#!/usr/bin/env python3
"""FreeDNS subdomain rotation script.

Maintains up to 60 active A-record subdomains pointing to mitch.pro's IP,
rotating 10x/day on weekdays and 5x/day on weekends (with configurable speed
multiplier for testing), tracking active replacement times and retired domains.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
import time
from typing import Any

from diceware import generate_diceware_label
from freedns_client import (
    AuthenticationError,
    BaseFreeDNSClient,
    CaptchaRequiredError,
    FreeDNSClient,
    FreeDNSError,
    RegistryDomain,
    SubdomainTakenError,
)

ROTATION_MODES: dict[str, tuple[int, int]] = {
    "weekly": (10, 5),  # ~6.4 days (~1 week) for 55 domains
    "2day": (28, 27),   # ~2.0 days for 55 domains
}


def apply_rotation_mode(config: dict[str, Any], mode: str | None = None) -> None:
    """Apply preset weekday/weekend rotation counts for 'weekly' or '2day' mode."""
    selected = (mode or config.get("rotation_mode") or "weekly").lower().strip()
    config["rotation_mode"] = selected
    if selected in ROTATION_MODES:
        wkday, wkend = ROTATION_MODES[selected]
        config["weekday_rotations_per_day"] = wkday
        config["weekend_rotations_per_day"] = wkend


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(ts: str) -> datetime:
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_duration(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if mins:
        parts.append(f"{mins}m")
    if secs or not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def resolve_target_ip(target_domain: str) -> str:
    """Resolve the IPv4 A record of target_domain."""
    infos = socket.getaddrinfo(target_domain, None, socket.AF_INET, socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError(f"Could not resolve IPv4 address for {target_domain}")
    return str(infos[0][4][0])


def resolve_fqdn_ips(fqdn: str) -> set[str]:
    """Return all IPv4 addresses fqdn currently resolves to, or empty set."""
    try:
        infos = socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)
        return {str(info[4][0]) for info in infos}
    except socket.gaierror:
        return set()


def fqdn_exists_in_dns(fqdn: str) -> bool:
    """Return True if fqdn already resolves in DNS (likely already taken)."""
    return bool(resolve_fqdn_ips(fqdn))


def get_interval_seconds(dt: datetime, config: dict[str, Any]) -> float:
    is_weekend = dt.weekday() >= 5
    rotations = (
        float(config["weekend_rotations_per_day"])
        if is_weekend
        else float(config["weekday_rotations_per_day"])
    )
    rotations = max(1.0, rotations)
    speed = max(0.001, float(config.get("speed_multiplier", 1.0)))
    return (86400.0 / rotations) / speed


def compute_replacement_times(
    active_domains: list[dict[str, Any]],
    next_rotation_at: datetime,
    config: dict[str, Any],
) -> list[datetime]:
    """Compute scheduled replacement UTC timestamps for active_domains (oldest-first)."""
    max_domains = int(config["max_domains"])
    count = len(active_domains)
    if count == 0:
        return []

    cursor = next_rotation_at
    # If below max_domains, fill ticks happen before the oldest domain is deleted.
    fill_ticks = max(0, max_domains - count)
    for _ in range(fill_ticks):
        cursor = cursor + timedelta(seconds=get_interval_seconds(cursor, config))

    schedule: list[datetime] = []
    for _ in range(count):
        schedule.append(cursor)
        cursor = cursor + timedelta(seconds=get_interval_seconds(cursor, config))
    return schedule


def _load_dotenv(env_path: Path) -> None:
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def load_config(path: Path) -> dict[str, Any]:
    _load_dotenv(path.parent / ".env")
    with path.open("r", encoding="utf-8") as f:
        cfg = json.load(f)
    # Allow environment variable overrides for credentials.
    if os.environ.get("FREEDNS_USERNAME"):
        cfg["username"] = os.environ["FREEDNS_USERNAME"]
    if os.environ.get("FREEDNS_PASSWORD"):
        cfg["password"] = os.environ["FREEDNS_PASSWORD"]
    if os.environ.get("FREEDNS_COOKIE"):
        cfg["dns_cookie"] = os.environ["FREEDNS_COOKIE"]
    apply_rotation_mode(cfg)
    return cfg


def load_state(state_path: Path) -> dict[str, Any]:
    if state_path.exists():
        with state_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "active_domains": [],
        "old_domains": [],
        "used_prefixes": [],
        "next_rotation_at": None,
    }


def save_state(state_path: Path, state: dict[str, Any]) -> None:
    tmp = state_path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    tmp.replace(state_path)


def write_old_domains_file(old_path: Path, old_domains: list[dict[str, Any]]) -> None:
    lines = [
        "# Retired / previously used FreeDNS subdomains (never reused)",
        "# FQDN | Retired At (UTC) | Former Target IP",
        "",
    ]
    for entry in old_domains:
        lines.append(
            f"{entry['fqdn']} | {entry.get('retired_at', 'unknown')} | {entry.get('address', '')}"
        )
    old_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_active_domains_file(
    active_path: Path,
    state: dict[str, Any],
    next_rotation_at: datetime,
    target_ip: str,
    config: dict[str, Any],
) -> None:
    now = utc_now()
    active = sorted(state["active_domains"], key=lambda d: d["created_at"])
    replacements = compute_replacement_times(active, next_rotation_at, config)
    speed = float(config.get("speed_multiplier", 1.0))

    lines = [
        "# FreeDNS Active Domains",
        f"# Updated:       {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"# Target A IP:   {target_ip} ({config['target_domain']})",
        f"# Active Count:  {len(active)} / {config['max_domains']}",
        f"# Schedule:      {config.get('rotation_mode', 'weekly')} "
        f"({config['weekday_rotations_per_day']}/day weekdays, "
        f"{config['weekend_rotations_per_day']}/day weekends, speed: {speed:g}x)",
        f"# Next Rotation: {next_rotation_at.strftime('%Y-%m-%d %H:%M:%S UTC')} "
        f"(in {format_duration((next_rotation_at - now).total_seconds())})",
        "",
        f"{'#':<4} {'FQDN':<38} {'Type':<5} {'Target IP':<16} "
        f"{'Created At (UTC)':<21} {'Replace At (UTC)':<21} {'Replace In'}",
        "-" * 124,
    ]
    for idx, (entry, replace_at) in enumerate(zip(active, replacements), start=1):
        created_str = parse_iso(entry["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        replace_str = replace_at.strftime("%Y-%m-%d %H:%M:%S")
        delta = format_duration((replace_at - now).total_seconds())
        lines.append(
            f"{idx:<4} {entry['fqdn']:<38} {entry.get('record_type', 'A'):<5} "
            f"{entry['address']:<16} {created_str:<21} {replace_str:<21} {delta}"
        )

    active_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def refresh_working_domains(
    state: dict[str, Any],
    target_ip: str,
    config: dict[str, Any],
) -> None:
    """Check active domains in parallel and mark them working once DNS resolves properly."""
    active = state["active_domains"]
    if not active:
        return

    now = utc_now()

    def _check(entry: dict[str, Any]) -> tuple[dict[str, Any], str, bool]:
        expected_ip = entry.get("address") or target_ip
        resolved_ips = resolve_fqdn_ips(entry["fqdn"])
        return entry, expected_ip, (expected_ip in resolved_ips)

    with ThreadPoolExecutor(max_workers=10) as pool:
        for entry, expected_ip, ok in pool.map(_check, active):
            if ok:
                if not entry.get("working"):
                    entry["working"] = True
                    entry["verified_at"] = now.isoformat()
                    entry["resolved_ip"] = expected_ip
                    print(f"[working] {entry['fqdn']} now resolves to {expected_ip}")
            else:
                entry["working"] = False


def write_working_domains_file(
    working_path: Path,
    state: dict[str, Any],
    next_rotation_at: datetime,
    target_ip: str,
    config: dict[str, Any],
) -> None:
    """Write separate list of active domains that currently resolve properly."""
    now = utc_now()
    active = sorted(state["active_domains"], key=lambda d: d["created_at"])
    replacements = compute_replacement_times(active, next_rotation_at, config)
    working_pairs = [
        (entry, rep) for entry, rep in zip(active, replacements) if entry.get("working")
    ]

    lines = [
        "# FreeDNS Verified Working Domains",
        f"# Updated:        {now.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"# Target A IP:    {target_ip} ({config['target_domain']})",
        f"# Working Count:  {len(working_pairs)} / {len(active)} active",
        "",
        f"{'#':<4} {'FQDN':<38} {'Resolved IP':<16} "
        f"{'Verified At (UTC)':<21} {'Replace At (UTC)':<21} {'Replace In'}",
        "-" * 118,
    ]
    for idx, (entry, replace_at) in enumerate(working_pairs, start=1):
        verified_str = (
            parse_iso(entry["verified_at"]).strftime("%Y-%m-%d %H:%M:%S")
            if entry.get("verified_at")
            else "unknown"
        )
        replace_str = replace_at.strftime("%Y-%m-%d %H:%M:%S")
        delta = format_duration((replace_at - now).total_seconds())
        lines.append(
            f"{idx:<4} {entry['fqdn']:<38} {entry.get('resolved_ip', entry['address']):<16} "
            f"{verified_str:<21} {replace_str:<21} {delta}"
        )

    working_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_client(config: dict[str, Any]) -> FreeDNSClient:
    client = FreeDNSClient()
    if config.get("dns_cookie"):
        client.set_cookie(config["dns_cookie"])
        return client

    cookie_cache = Path(__file__).resolve().parent / ".freedns_cookie"
    if cookie_cache.exists():
        cached = cookie_cache.read_text(encoding="utf-8").strip()
        if cached:
            client.set_cookie(cached)
            try:
                client.list_subdomains()
                return client
            except Exception:
                client = FreeDNSClient()

    client.login(config.get("username", ""), config.get("password", ""))
    cookie_val = client.session.cookies.get("dns_cookie")
    if cookie_val:
        cookie_cache.write_text(cookie_val, encoding="utf-8")
    return client


def reauth_client(config: dict[str, Any]) -> FreeDNSClient:
    """Clear cached cookie and re-login when the session expires."""
    cookie_cache = Path(__file__).resolve().parent / ".freedns_cookie"
    if cookie_cache.exists():
        cookie_cache.unlink()
    return build_client(config)


def sync_state_with_account(client: BaseFreeDNSClient, state: dict[str, Any]) -> None:
    """Reconcile local state with actual subdomains on the FreeDNS account."""
    remote_records = client.list_subdomains()
    remote_by_id = {r.data_id: r for r in remote_records}
    local_by_id = {str(d["data_id"]): d for d in state["active_domains"]}

    now_iso = utc_now().isoformat()
    synced: list[dict[str, Any]] = []
    for data_id, rec in remote_by_id.items():
        if data_id in local_by_id:
            entry = dict(local_by_id[data_id])
            entry["address"] = rec.address
            synced.append(entry)
        else:
            synced.append(
                {
                    "data_id": rec.data_id,
                    "subdomain": rec.subdomain,
                    "domain": rec.domain,
                    "fqdn": rec.fqdn,
                    "record_type": rec.record_type,
                    "address": rec.address,
                    "created_at": now_iso,
                }
            )
    synced.sort(key=lambda d: d["created_at"])
    state["active_domains"] = synced


def choose_parent_domains(
    client: BaseFreeDNSClient, config: dict[str, Any], cache_dir: Path | None = None
) -> list[RegistryDomain]:
    cache_path = (cache_dir or Path(__file__).resolve().parent) / "registry_cache.json"
    all_registry: list[RegistryDomain] = []

    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            age = (utc_now() - parse_iso(cached["fetched_at"])).total_seconds()
            if age < 86400 and cached.get("domains"):
                all_registry = [
                    RegistryDomain(domain_id=d["domain_id"], domain=d["domain"])
                    for d in cached["domains"]
                ]
        except Exception:
            all_registry = []

    if not all_registry:
        print("[registry] Fetching all public domains from FreeDNS registry...")
        all_registry = client.get_registry_domains(pages=None, public_only=True)
        try:
            cache_path.write_text(
                json.dumps(
                    {
                        "fetched_at": utc_now().isoformat(),
                        "domains": [
                            {"domain_id": d.domain_id, "domain": d.domain}
                            for d in all_registry
                        ],
                    }
                ),
                encoding="utf-8",
            )
        except Exception:
            pass

    configured = [d.lower().strip() for d in config.get("parent_domains", []) if d.strip()]
    if configured:
        filtered = [r for r in all_registry if r.domain in configured or r.domain_id in configured]
        if filtered:
            return filtered
    return all_registry


def create_unique_subdomain(
    client: BaseFreeDNSClient,
    state: dict[str, Any],
    config: dict[str, Any],
    target_ip: str,
    registry_domains: list[RegistryDomain],
) -> dict[str, Any]:
    """Pick a unique prefix (word_list first, then 1-2 word diceware) and create it."""
    if not registry_domains:
        raise FreeDNSError("No parent registry domains available.")

    active_fqdns = {d["fqdn"].lower() for d in state["active_domains"]}
    old_fqdns = {d["fqdn"].lower() for d in state["old_domains"]}
    taken_fqdns = {f.lower() for f in state.get("taken_fqdns", [])}
    blocked_fqdns = active_fqdns | old_fqdns | taken_fqdns

    word_list = [w.strip().lower() for w in config.get("word_list", []) if w.strip()]
    word_candidates = [
        (w, parent)
        for w in word_list
        for parent in registry_domains
        if f"{w}.{parent.domain}".lower() not in blocked_fqdns
    ]
    secrets.SystemRandom().shuffle(word_candidates)

    word_tries = 0
    max_word_tries = 25
    attempts = 0
    max_attempts = 60
    while attempts < max_attempts:
        attempts += 1
        if word_candidates and word_tries < max_word_tries:
            prefix, parent = word_candidates.pop(0)
            word_tries += 1
            source_kind = "word_list"
        else:
            prefix = generate_diceware_label()
            parent = secrets.choice(registry_domains)
            source_kind = "diceware"

        candidate_fqdn = f"{prefix}.{parent.domain}".lower()
        if candidate_fqdn in blocked_fqdns:
            continue

        try:
            rec = client.create_subdomain(
                subdomain=prefix,
                domain_id=parent.domain_id,
                domain_name=parent.domain,
                ip_address=target_ip,
                record_type="A",
            )
            state["taken_fqdns"] = sorted(taken_fqdns)[-2000:]
            entry = {
                "data_id": rec.data_id,
                "subdomain": rec.subdomain,
                "domain": rec.domain,
                "fqdn": rec.fqdn,
                "record_type": rec.record_type,
                "address": rec.address,
                "created_at": utc_now().isoformat(),
                "source": source_kind,
            }
            print(f"[created:{source_kind}] {rec.fqdn} -> {rec.address} (id={rec.data_id})")
            return entry
        except SubdomainTakenError:
            print(f"[taken] {candidate_fqdn}, trying another...")
            blocked_fqdns.add(candidate_fqdn)
            taken_fqdns.add(candidate_fqdn)
            continue

    state["taken_fqdns"] = sorted(taken_fqdns)[-2000:]
    raise FreeDNSError(f"Failed to create a unique subdomain after {max_attempts} attempts.")


def rotate_once(
    client: BaseFreeDNSClient,
    state: dict[str, Any],
    config: dict[str, Any],
    registry_domains: list[RegistryDomain],
) -> str:
    """Delete oldest subdomain if at max_domains, then create one unique subdomain."""
    target_ip = resolve_target_ip(config["target_domain"])
    sync_state_with_account(client, state)

    max_domains = int(config["max_domains"])
    active = sorted(state["active_domains"], key=lambda d: d["created_at"])

    while len(active) >= max_domains:
        oldest = active.pop(0)
        client.delete_subdomain(oldest["data_id"])
        retired = dict(oldest)
        retired["retired_at"] = utc_now().isoformat()
        state["old_domains"].append(retired)
        print(f"[deleted] {oldest['fqdn']} (id={oldest['data_id']})")

    new_entry = create_unique_subdomain(client, state, config, target_ip, registry_domains)
    active.append(new_entry)
    state["active_domains"] = active
    refresh_working_domains(state, target_ip, config)
    return target_ip


def persist_all_files(
    state_path: Path,
    active_path: Path,
    working_path: Path,
    old_path: Path,
    state: dict[str, Any],
    next_rot: datetime,
    target_ip: str,
    config: dict[str, Any],
) -> None:
    save_state(state_path, state)
    write_active_domains_file(active_path, state, next_rot, target_ip, config)
    write_working_domains_file(working_path, state, next_rot, target_ip, config)
    write_old_domains_file(old_path, state["old_domains"])


def clear_all_domains(
    client: BaseFreeDNSClient,
    state: dict[str, Any],
    config: dict[str, Any],
) -> int:
    """Literally delete every subdomain on the FreeDNS account, no matter what."""
    deleted_count = 0
    seen_ids: set[str] = set()

    for _ in range(20):
        records = client.list_subdomains()
        if not records:
            break
        progress = False
        for rec in records:
            if rec.data_id in seen_ids:
                continue
            seen_ids.add(rec.data_id)
            client.delete_subdomain(rec.data_id)
            deleted_count += 1
            progress = True
            state["old_domains"].append(
                {
                    "data_id": rec.data_id,
                    "subdomain": rec.subdomain,
                    "domain": rec.domain,
                    "fqdn": rec.fqdn,
                    "record_type": rec.record_type,
                    "address": rec.address,
                    "retired_at": utc_now().isoformat(),
                }
            )
            print(f"[cleared] {rec.fqdn} (id={rec.data_id})")
        if not progress:
            break

    state["active_domains"] = []
    state["next_rotation_at"] = None
    return deleted_count


def import_account_domains(
    client: BaseFreeDNSClient,
    state: dict[str, Any],
    config: dict[str, Any],
) -> tuple[int, int]:
    """Scrape all subdomains from the FreeDNS account and add missing ones to state."""
    remote_records = client.list_subdomains()
    existing_ids = {str(d["data_id"]) for d in state["active_domains"]}
    existing_fqdns = {d["fqdn"].lower() for d in state["active_domains"]}
    now_iso = utc_now().isoformat()

    added = 0
    for rec in remote_records:
        if rec.data_id in existing_ids or rec.fqdn.lower() in existing_fqdns:
            continue
        state["active_domains"].append(
            {
                "data_id": rec.data_id,
                "subdomain": rec.subdomain,
                "domain": rec.domain,
                "fqdn": rec.fqdn,
                "record_type": rec.record_type,
                "address": rec.address,
                "created_at": now_iso,
                "source": "imported",
            }
        )
        existing_ids.add(rec.data_id)
        existing_fqdns.add(rec.fqdn.lower())
        added += 1
        print(f"[imported] {rec.fqdn} -> {rec.address} (id={rec.data_id})")

    state["active_domains"].sort(key=lambda d: d["created_at"])
    target_ip = resolve_target_ip(config["target_domain"])
    refresh_working_domains(state, target_ip, config)
    return added, len(remote_records)


def main() -> int:
    parser = argparse.ArgumentParser(description="FreeDNS subdomain rotation script")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--speed", type=float, default=None, help="Override speed_multiplier (1 = real-time)")
    parser.add_argument(
        "--mode",
        choices=["weekly", "2day", "custom"],
        default=None,
        help="Rotation retention mode: weekly (10/day wkday, 5/day wkend) or 2day (28/day wkday, 27/day wkend)",
    )
    parser.add_argument("--max-domains", type=int, default=None, help="Override max_domains (default 55)")
    parser.add_argument("--once", action="store_true", help="Run one rotation step and exit")
    parser.add_argument("--bootstrap", type=int, default=0, help="Create N subdomains immediately before rotating")
    parser.add_argument("--status", action="store_true", help="Refresh/show active & working domain lists and exit")
    parser.add_argument("--import-account", action="store_true", help="Scrape all domains from FreeDNS account and add them")
    parser.add_argument("--clear-all", action="store_true", help="Delete ALL subdomains from FreeDNS and exit")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = base_dir / config_path

    config = load_config(config_path)
    if args.mode is not None:
        apply_rotation_mode(config, args.mode)
    if args.speed is not None:
        config["speed_multiplier"] = args.speed
    if args.max_domains is not None:
        config["max_domains"] = args.max_domains

    state_path = base_dir / config["state_file"]
    active_path = base_dir / config["active_domains_file"]
    working_path = base_dir / config.get("working_domains_file", "working_domains.txt")
    old_path = base_dir / config["old_domains_file"]

    state = load_state(state_path)
    now = utc_now()
    next_rot = (
        parse_iso(state["next_rotation_at"])
        if state.get("next_rotation_at")
        else now + timedelta(seconds=get_interval_seconds(now, config))
    )

    if args.status:
        target_ip = resolve_target_ip(config["target_domain"])
        refresh_working_domains(state, target_ip, config)
        persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)
        print(active_path.read_text(encoding="utf-8"))
        print(working_path.read_text(encoding="utf-8"))
        return 0

    client = build_client(config)

    if args.clear_all:
        target_ip = resolve_target_ip(config["target_domain"])
        deleted = clear_all_domains(client, state, config)
        persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)
        print(f"[clear-all] Deleted {deleted} subdomain(s) from FreeDNS.")
        return 0

    if args.import_account:
        target_ip = resolve_target_ip(config["target_domain"])
        added, total = import_account_domains(client, state, config)
        persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)
        print(f"[import] Added {added} new domain(s) ({total} total on FreeDNS account).")
        return 0

    registry_domains = choose_parent_domains(client, config)

    running = True

    def _handle_signal(_sig: int, _frame: Any) -> None:
        nonlocal running
        running = False
        print("\n[stop] Shutting down cleanly...")

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        if args.bootstrap > 0:
            target_count = min(args.bootstrap, int(config["max_domains"]))
            while running and len(state["active_domains"]) < target_count:
                target_ip = rotate_once(client, state, config, registry_domains)
                persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)

        if args.once:
            target_ip = rotate_once(client, state, config, registry_domains)
            next_rot = utc_now() + timedelta(seconds=get_interval_seconds(utc_now(), config))
            state["next_rotation_at"] = next_rot.isoformat()
            persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)
            return 0

        print(
            f"[start] max={config['max_domains']} speed={config.get('speed_multiplier', 1)}x "
            f"target={config['target_domain']}"
        )
        while running:
            now = utc_now()
            try:
                target_ip = rotate_once(client, state, config, registry_domains)
            except AuthenticationError:
                print("[auth] Session cookie expired, re-logging in...")
                client = reauth_client(config)
                target_ip = rotate_once(client, state, config, registry_domains)
            interval = get_interval_seconds(now, config)
            next_rot = now + timedelta(seconds=interval)
            state["next_rotation_at"] = next_rot.isoformat()
            persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)

            working_count = sum(1 for d in state["active_domains"] if d.get("working"))
            print(
                f"[wait] active={len(state['active_domains'])}/{config['max_domains']} "
                f"working={working_count} old={len(state['old_domains'])} "
                f"next_rotation={format_duration(interval)}"
            )
            sleep_end = time.monotonic() + interval
            while running and time.monotonic() < sleep_end:
                time.sleep(min(0.5, max(0.0, sleep_end - time.monotonic())))

    except CaptchaRequiredError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    except FreeDNSError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
