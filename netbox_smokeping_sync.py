#!/usr/bin/env python3
"""
# Copyright (c) 2026 git.com/itsjustbrianyo
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org>.


netbox_smokeping_sync.py

One-way sync: NetBox -> SmokePing.

Usage:
  netbox_smokeping_sync.py --dry-run      # show diff, change nothing
  netbox_smokeping_sync.py                # apply
  netbox_smokeping_sync.py --force        # apply even past the change threshold

Requires: pynetbox
"""

from __future__ import annotations

import argparse
import difflib
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pynetbox

log = logging.getLogger("netbox_smokeping_sync")

# SmokePing section names: letters, digits, dash, underscore.
VALID_NAME = re.compile(r"^[-_0-9A-Za-z]+$")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    netbox_url: str
    netbox_token: str
    netbox_verify_ssl: bool
    url_field: str
    section: str
    section_menu: str
    section_title: str
    role_slug: str
    manufacturer_slug: str
    warm_spare_tag: str
    include_file: Path
    check_cmd: str
    reload_cmd: str
    max_change_pct: float
    min_targets_for_threshold: int

    @classmethod
    def from_env(cls) -> "Config":
        def req(name: str) -> str:
            val = os.environ.get(name)
            if not val:
                sys.exit(f"Missing required environment variable: {name}")
            return val

        env = os.environ.get
        return cls(
            netbox_url=req("NETBOX_URL"),
            netbox_token=req("NETBOX_TOKEN"),
            netbox_verify_ssl=env("NETBOX_VERIFY_SSL", "true").lower() != "false",
            url_field=env("SMOKEPING_URL_FIELD", "url_smokeping_meraki"),
            section=env("SMOKEPING_SECTION", "Meraki"),
            section_menu=env("SMOKEPING_SECTION_MENU", "Meraki Sites"),
            section_title=env("SMOKEPING_SECTION_TITLE", "Meraki Sites"),
            role_slug=env("MX_ROLE_SLUG", "firewall"),
            manufacturer_slug=env("MX_MANUFACTURER_SLUG", "cisco-meraki"),
            warm_spare_tag=env("WARM_SPARE_TAG", "warm-spare"),
            include_file=Path(req("SMOKEPING_INCLUDE_FILE")),
            check_cmd=env("SMOKEPING_CHECK_CMD", "docker exec smokeping smokeping --check"),
            reload_cmd=env("SMOKEPING_RELOAD_CMD", "docker restart smokeping"),
            max_change_pct=float(env("MAX_CHANGE_PCT", "25")),
            min_targets_for_threshold=int(env("MIN_TARGETS_FOR_THRESHOLD", "5")),
        )


def load_env_file(path: Path) -> None:
    """Minimal KEY=VALUE loader. Real environment variables take precedence."""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


# --------------------------------------------------------------------------- #
# Existing file
# --------------------------------------------------------------------------- #
def parse_existing_hosts(path: Path) -> dict[str, str]:
    """Return {target_name: host} for ++ entries in the current include file."""
    hosts: dict[str, str] = {}
    if not path.exists():
        return hosts
    current = None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line.startswith("++ "):
            current = line[3:].strip()
        elif line.startswith("+ "):
            current = None
        elif current and line.startswith("host"):
            _, _, value = line.partition("=")
            hosts[current] = value.strip()
    return hosts


# --------------------------------------------------------------------------- #
# NetBox
# --------------------------------------------------------------------------- #
def target_from_url(url: str, section: str) -> str | None:
    """'...?target=Meraki.Site_Name' -> 'Site_name' (None if not in our section)."""
    target = parse_qs(urlparse(url).query).get("target", [""])[0]
    sect, _, leaf = target.partition(".")
    if sect != section or not leaf or "." in leaf or not VALID_NAME.match(leaf):
        return None
    return leaf


def device_tag_slugs(device) -> set[str]:
    return {t.slug for t in (device.tags or [])}


def resolve_mx_ip(nb, site, cfg: Config) -> tuple[str | None, str]:
    """Return (ip, reason). ip is None when the site can't be resolved."""
    candidates = list(
        nb.dcim.devices.filter(
            site_id=site.id,
            role=cfg.role_slug,
            manufacturer=cfg.manufacturer_slug,
            status="active",
            has_primary_ip=True,
        )
    )
    candidates = [d for d in candidates if d.primary_ip4]

    if cfg.warm_spare_tag:
        spares = [d for d in candidates if cfg.warm_spare_tag in device_tag_slugs(d)]
        if spares and len(spares) < len(candidates):
            candidates = [d for d in candidates if d not in spares]

    if not candidates:
        return None, "no active MX with a primary IPv4"

    ips = {d.primary_ip4.address.split("/")[0] for d in candidates}
    if len(ips) == 1:
        ip = ips.pop()
        reason = candidates[0].name if len(candidates) == 1 else f"{len(candidates)} MXs sharing {ip}"
        return ip, reason

    names = ", ".join(sorted(d.name for d in candidates))
    return None, f"ambiguous: {len(candidates)} MXs with different IPs ({names}); tag the spare '{cfg.warm_spare_tag}'"


def build_targets(nb, cfg: Config, existing: dict[str, str]) -> dict[str, str]:
    """Return {target_name: host} for the new file."""
    targets: dict[str, str] = {}
    owners: dict[str, str] = {}

    for site in nb.dcim.sites.all():
        url = (site.custom_fields or {}).get(cfg.url_field)
        if not url:
            continue

        leaf = target_from_url(url, cfg.section)
        if not leaf:
            log.warning("%s: %s is not a valid '%s.<name>' target URL - skipping",
                        site.name, url, cfg.section)
            continue

        if leaf in owners:
            log.error("%s: target %s already claimed by site %s - skipping",
                      site.name, leaf, owners[leaf])
            continue

        ip, reason = resolve_mx_ip(nb, site, cfg)
        if ip:
            targets[leaf] = ip
            owners[leaf] = site.name
            log.debug("%s -> %s = %s (%s)", site.name, leaf, ip, reason)
        elif leaf in existing:
            targets[leaf] = existing[leaf]
            owners[leaf] = site.name
            log.warning("%s: %s - keeping previous host %s", site.name, reason, existing[leaf])
        else:
            log.warning("%s: %s - no previous host, target not created", site.name, reason)

    return targets


# --------------------------------------------------------------------------- #
# Render / diff / write
# --------------------------------------------------------------------------- #
def render(targets: dict[str, str], cfg: Config) -> str:
    lines = [
        f"# Managed by netbox_smokeping_sync.py from NetBox field '{cfg.url_field}'.",
        "# Manual edits will be overwritten.",
        "",
        f"+ {cfg.section}",
        f"menu = {cfg.section_menu}",
        f"title = {cfg.section_title}",
        "",
    ]
    for leaf in sorted(targets, key=str.lower):
        lines += [f"++ {leaf}", f"menu = {leaf}", f"title = {leaf}", f"host = {targets[leaf]}", ""]
    return "\n".join(lines)


def summarize(old: dict[str, str], new: dict[str, str]) -> tuple[list, list, list]:
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(k for k in set(old) & set(new) if old[k] != new[k])
    return added, removed, changed


def atomic_write(path: Path, content: str) -> None:
    """Write via temp file in the same directory, keeping mode/ownership of the original."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        if path.exists():
            st = path.stat()
            os.chmod(tmp, st.st_mode)
            try:
                os.chown(tmp, st.st_uid, st.st_gid)
            except PermissionError:
                pass
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def run(cmd: str) -> subprocess.CompletedProcess:
    log.info("Running: %s", cmd)
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser(description="Sync Meraki MX IPs from NetBox into SmokePing targets.")
    ap.add_argument("--dry-run", action="store_true", help="show the diff, change nothing")
    ap.add_argument("--force", action="store_true", help="apply even if the change threshold is exceeded")
    ap.add_argument("--env-file", type=Path,
                    default=Path(__file__).with_name("netbox_smokeping_sync.env"),
                    help="KEY=VALUE config file (default: netbox_smokeping_sync.env next to the script)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.env_file.exists():
        load_env_file(args.env_file)
    cfg = Config.from_env()

    nb = pynetbox.api(cfg.netbox_url, token=cfg.netbox_token)
    nb.http_session.verify = cfg.netbox_verify_ssl

    old_text = cfg.include_file.read_text() if cfg.include_file.exists() else ""
    existing = parse_existing_hosts(cfg.include_file)
    targets = build_targets(nb, cfg, existing)
    new_text = render(targets, cfg)

    added, removed, changed = summarize(existing, targets)
    for t in added:
        log.info("ADD     %s = %s", t, targets[t])
    for t in removed:
        log.info("REMOVE  %s (was %s)", t, existing[t])
    for t in changed:
        log.info("CHANGE  %s: %s -> %s", t, existing[t], targets[t])

    if new_text == old_text:
        log.info("No changes (%d targets).", len(targets))
        return 0

    if args.dry_run:
        sys.stdout.writelines(difflib.unified_diff(
            old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
            fromfile=str(cfg.include_file), tofile="(generated)"))
        log.info("Dry run: nothing written.")
        return 0

    disruptive = len(removed) + len(changed)
    if len(existing) >= cfg.min_targets_for_threshold and not args.force:
        pct = 100 * disruptive / len(existing)
        if pct > cfg.max_change_pct:
            log.error("Aborting: %d of %d existing targets would be removed or re-IP'd (%.0f%% > %.0f%%). "
                      "Check NetBox, then re-run with --force if this is expected.",
                      disruptive, len(existing), pct, cfg.max_change_pct)
            return 2

    backup = cfg.include_file.with_name(cfg.include_file.name + ".bak")
    if cfg.include_file.exists():
        shutil.copy2(cfg.include_file, backup)
    atomic_write(cfg.include_file, new_text)
    log.info("Wrote %s (%d targets).", cfg.include_file, len(targets))

    check = run(cfg.check_cmd)
    if check.returncode != 0:
        log.error("SmokePing config check failed:\n%s%s", check.stdout, check.stderr)
        if backup.exists():
            shutil.copy2(backup, cfg.include_file)
            log.error("Restored previous %s. SmokePing was not reloaded.", cfg.include_file)
        else:
            cfg.include_file.unlink(missing_ok=True)
        return 3

    reload_ = run(cfg.reload_cmd)
    if reload_.returncode != 0:
        log.error("Reload failed:\n%s%s", reload_.stdout, reload_.stderr)
        return 4

    log.info("SmokePing reloaded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
