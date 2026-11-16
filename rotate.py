#!/usr/bin/env python3
"""FreeDNS subdomain rotation script.

Maintains up to DOMAIN_COUNT (default 55) active A-record subdomains pointing to
mitch.pro's IP. Weekly mode rotates DOMAIN_COUNT times per week (each domain lives
~1 week); daily mode replaces each domain ~every 2 days. Speed multiplier for testing.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
import re
from pathlib import Path
import secrets
import signal
import socket
import ssl
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import subprocess
import sys
import time
from typing import Any, Callable

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

# Number of active domains to keep, and the weekly rotation volume (one full turnover
# per week). Change this one constant; `max_domains` in config.json overrides it, and
# the rotation volume always follows the effective max_domains so the two stay matched.
DOMAIN_COUNT = 55


def sync_rotation_rates(config: dict[str, Any]) -> tuple[float, float]:
    """Compute effective (weekday, weekend) rotations/day from weekly_enabled + daily_enabled.

    weekly: max_domains rotations per week, weekdays weighted 2:1 over weekend days.
    daily:  every domain replaced ~every 2 days (max_domains / 2 per day, every day).
    """
    count = max(1, int(config.get("max_domains", DOMAIN_COUNT)))
    weekly = bool(config.get("weekly_enabled", True))
    daily = bool(config.get("daily_enabled", False))
    if not weekly and not daily:
        weekly = True
    wkday = wkend = 0.0
    if weekly:
        wkday += count * 2 / 12  # 5 weekdays * 2 + 2 weekend days * 1 = 12 weight units
        wkend += count / 12
    if daily:
        wkday += count / 2
        wkend += count / 2
    config["weekday_rotations_per_day"] = round(wkday, 2)
    config["weekend_rotations_per_day"] = round(wkend, 2)
    return wkday, wkend


def _parse_hhmm(value: str) -> tuple[int, int]:
    hh, mm = value.strip().split(":", 1)
    return int(hh), int(mm)


def resolve_timezone(config: dict[str, Any]) -> ZoneInfo | None:
    """tzinfo for the configured `timezone` (e.g. 'America/Los_Angeles'), or None for system local."""
    name = str(config.get("timezone", "")).strip()
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def _to_local(dt: datetime, config: dict[str, Any]) -> datetime:
    """Convert an aware datetime to the configured active-hours timezone (system local if unset/invalid)."""
    return dt.astimezone(resolve_timezone(config))


def is_in_active_hours(dt: datetime, config: dict[str, Any]) -> bool:
    """Return True if rotation is allowed at dt (respecting active_hours_only & weekends)."""
    if not config.get("active_hours_only", False):
        return True
    local_dt = _to_local(dt, config)
    if local_dt.weekday() >= 5:
        return False
    sh, sm = _parse_hhmm(str(config.get("active_hours_start", "08:30")))
    eh, em = _parse_hhmm(str(config.get("active_hours_end", "15:20")))
    start_t = local_dt.replace(hour=sh, minute=sm, second=0, microsecond=0)
    end_t = local_dt.replace(hour=eh, minute=em, second=0, microsecond=0)
    return start_t <= local_dt < end_t


def next_active_window_start(dt: datetime, config: dict[str, Any]) -> datetime:
    """Return the next UTC timestamp where active hours allow rotation."""
    if not config.get("active_hours_only", False):
        return dt
    local_dt = _to_local(dt, config)
    sh, sm = _parse_hhmm(str(config.get("active_hours_start", "08:30")))
    eh, em = _parse_hhmm(str(config.get("active_hours_end", "15:20")))

    candidate = local_dt
    for _ in range(8):
        start_t = candidate.replace(hour=sh, minute=sm, second=0, microsecond=0)
        end_t = candidate.replace(hour=eh, minute=em, second=0, microsecond=0)
        if candidate.weekday() < 5:
            if candidate < start_t:
                return start_t.astimezone(timezone.utc)
            if start_t <= candidate < end_t:
                return candidate.astimezone(timezone.utc)
        candidate = (candidate + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return dt


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
    wkday, wkend = sync_rotation_rates(config)
    local_dt = _to_local(dt, config)
    is_weekend = local_dt.weekday() >= 5
    rotations = float(wkend if is_weekend else wkday)
    rotations = max(0.01, rotations)
    speed = max(0.001, float(config.get("speed_multiplier", 1.0)))
    if config.get("active_hours_only", False):
        # Same weekly volume as normal mode, squeezed into the weekday windows:
        # weekend rotations are redistributed across the 5 active weekdays.
        sh, sm = _parse_hhmm(str(config.get("active_hours_start", "08:30")))
        eh, em = _parse_hhmm(str(config.get("active_hours_end", "15:20")))
        window_secs = max(60.0, ((eh * 60 + em) - (sh * 60 + sm)) * 60.0)
        per_active_day = max(0.01, (5 * wkday + 2 * wkend) / 5.0)
        return (window_secs / per_active_day) / speed
    return (86400.0 / rotations) / speed


def _advance_active_time(dt: datetime, seconds: float, config: dict[str, Any]) -> datetime:
    """Move forward by `seconds` of *active* time, skipping time outside active windows.
    Leftover time carries into the next window, so fractional per-day rates stay exact."""
    eh, em = _parse_hhmm(str(config.get("active_hours_end", "15:20")))
    t = next_active_window_start(dt, config)
    remaining = seconds
    for _ in range(10000):
        local = _to_local(t, config)
        window_end = local.replace(hour=eh, minute=em, second=0, microsecond=0).astimezone(timezone.utc)
        available = (window_end - t).total_seconds()
        if remaining < available:
            return t + timedelta(seconds=remaining)
        remaining -= max(0.0, available)
        t = next_active_window_start(window_end, config)
    return t


def advance_rotation_time(dt: datetime, config: dict[str, Any]) -> datetime:
    if config.get("active_hours_only", False):
        return _advance_active_time(dt, get_interval_seconds(dt, config), config)
    return dt + timedelta(seconds=get_interval_seconds(dt, config))


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

    cursor = next_active_window_start(next_rotation_at, config)
    # If below max_domains, fill ticks happen before the oldest domain is deleted.
    fill_ticks = max(0, max_domains - count)
    for _ in range(fill_ticks):
        cursor = advance_rotation_time(cursor, config)

    schedule: list[datetime] = []
    for _ in range(count):
        schedule.append(cursor)
        cursor = advance_rotation_time(cursor, config)
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
    cfg.setdefault("max_domains", DOMAIN_COUNT)
    sync_rotation_rates(cfg)
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


def prune_unverified_domains(
    client: BaseFreeDNSClient,
    state: dict[str, Any],
    config: dict[str, Any],
    max_age_hours: float | None = None,
) -> list[str]:
    """Delete active domains that never became working within max_age_hours (default 24h)."""
    hours = float(config.get("unverified_max_age_hours", 24) if max_age_hours is None else max_age_hours)
    cutoff = timedelta(hours=max(0.1, hours))
    now = utc_now()
    deleted: list[str] = []
    remaining: list[dict[str, Any]] = []

    for entry in state.get("active_domains", []):
        if entry.get("working") or entry.get("verified_at") or not entry.get("created_at"):
            remaining.append(entry)
            continue
        age = now - parse_iso(entry["created_at"])
        if age < cutoff:
            remaining.append(entry)
            continue
        client.delete_subdomain(entry["data_id"])
        retired = dict(entry)
        retired["retired_at"] = now.isoformat()
        retired["retired_reason"] = "unverified_expired"
        state["old_domains"].append(retired)
        deleted.append(entry["fqdn"])
        print(f"[deleted:unverified] {entry['fqdn']} (age={format_duration(age.total_seconds())}, id={entry['data_id']})")

    state["active_domains"] = remaining
    return deleted


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


BANNED_NAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9-]{2,63}$")


def normalize_banned_domains(raw: Any) -> list[str]:
    """Parse a comma/whitespace-separated string or list into clean domain names."""
    items = re.split(r"[,\s]+", raw) if isinstance(raw, str) else [str(x) for x in raw or []]
    out: list[str] = []
    for item in items:
        name = item.strip().lower().rstrip(".")
        name = name.removeprefix("*.").lstrip(".")
        if name and BANNED_NAME_RE.match(name) and name not in out:
            out.append(name)
    return out


def is_banned(name: str, config: dict[str, Any]) -> bool:
    """True if name equals a banned domain or is a subdomain of one (groups.id bans x.groups.id)."""
    name = name.lower().rstrip(".")
    return any(
        name == b or name.endswith("." + b)
        for b in normalize_banned_domains(config.get("banned_domains", []))
    )


ALLOWED_WORD_RE = re.compile(r"^\*([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\*$")


def extract_allowed_word_prefixes(allowed_patterns: list[str]) -> list[str]:
    """Extract *word* entries from allowed_sites (no dots/slashes) as subdomain prefixes."""
    words: list[str] = []
    for raw in allowed_patterns:
        m = ALLOWED_WORD_RE.match(raw.strip().lower())
        if m:
            w = m.group(1)
            if w not in words:
                words.append(w)
    return words


def compile_site_patterns(patterns: list[str]) -> list[tuple[str, re.Pattern[str]]]:
    """Compile GoGuardian site wildcard patterns into regexes."""
    compiled: list[tuple[str, re.Pattern[str]]] = []
    for raw in patterns:
        pat = raw.strip().lower().rstrip("/")
        if not pat:
            continue
        if pat.startswith("*."):
            rest = pat[2:]
            regex_str = r"^(?:.*\.)?" + r".*".join(re.escape(part) for part in rest.split("*")) + r"$"
        else:
            regex_str = r"^" + r".*".join(re.escape(part) for part in pat.split("*")) + r"$"
        compiled.append((raw.strip(), re.compile(regex_str)))
    return compiled


compile_block_patterns = compile_site_patterns


def is_fqdn_blocked(
    fqdn: str,
    compiled_blocks: list[tuple[str, re.Pattern[str]]],
    compiled_allows: list[tuple[str, re.Pattern[str]]] | None = None,
) -> str | None:
    """Return matching block pattern if fqdn is blocked and NOT overridden by an allow rule."""
    clean = fqdn.strip().lower().rstrip(".")
    if compiled_allows:
        for _raw, rx in compiled_allows:
            if rx.match(clean):
                return None
    for raw, rx in compiled_blocks:
        if rx.match(clean):
            return raw
    return None


def load_compiled_rules(
    base_dir: Path,
) -> tuple[list[tuple[str, re.Pattern[str]]], list[tuple[str, re.Pattern[str]]]]:
    allowed_path = base_dir / "allowed_sites.txt"
    blocked_path = base_dir / "blocked_sites.txt"
    allows = (
        compile_site_patterns([l.strip() for l in allowed_path.read_text(encoding="utf-8").splitlines() if l.strip()])
        if allowed_path.exists()
        else []
    )
    blocks = (
        compile_site_patterns([l.strip() for l in blocked_path.read_text(encoding="utf-8").splitlines() if l.strip()])
        if blocked_path.exists()
        else []
    )
    return allows, blocks


def sync_goguardian_rules(
    base_dir: Path,
    config: dict[str, Any],
) -> tuple[list[str], list[tuple[str, re.Pattern[str]]], list[tuple[str, re.Pattern[str]]]]:
    """Fetch GoGuardian policy rules, update word_list with *word* allow entries, return (words, allows, blocks)."""
    if str(base_dir) not in sys.path:
        sys.path.insert(0, str(base_dir))
    import goguardian

    auth_cache = str(base_dir / "goguardian_auth_cache.json")
    rules_out = base_dir / "goguardian_rules.json"
    blocked_out = base_dir / "blocked_sites.txt"
    allowed_out = base_dir / "allowed_sites.txt"

    auth_overrides = config.get("goguardian_auth")
    auth_state = (
        goguardian.load_auth_state(auth_cache, overrides=auth_overrides)
        if isinstance(auth_overrides, dict) and any(auth_overrides.values())
        else goguardian.load_auth_state(auth_cache)
    )
    interface = str(config.get("goguardian_interface", "")).strip() or None
    res = goguardian.fetch_policy(
        auth_state,
        auth_cache,
        **({"interface": interface} if interface else {}),
    )
    policy_data = {"value": res["policy"], "hash": res.get("policyHash")}
    rules_out.write_text(json.dumps(policy_data, indent=2), encoding="utf-8")

    sites = policy_data["value"].get("adminSettings", {}).get("sites", {})
    blocked = sorted(p for p, info in sites.items() if not info.get("isAllowAction"))
    allowed = sorted(p for p, info in sites.items() if info.get("isAllowAction"))

    blocked_out.write_text("\n".join(blocked) + "\n", encoding="utf-8")
    allowed_out.write_text("\n".join(allowed) + "\n", encoding="utf-8")

    word_prefixes = extract_allowed_word_prefixes(allowed)
    if word_prefixes:
        config["word_list"] = word_prefixes

    return word_prefixes, compile_site_patterns(allowed), compile_site_patterns(blocked)


def rotate_blocked_domains(
    client: BaseFreeDNSClient,
    state: dict[str, Any],
    config: dict[str, Any],
    registry_domains: list[RegistryDomain],
    compiled_blocks: list[tuple[str, re.Pattern[str]]],
    compiled_allows: list[tuple[str, re.Pattern[str]]] | None = None,
) -> list[tuple[str, str]]:
    """Rotate out any active domain matching blocked_sites (unless allowed) and replace with a unique one."""
    if not compiled_blocks:
        return []

    target_ip = resolve_target_ip(config["target_domain"])
    rotated: list[tuple[str, str]] = []
    remaining: list[dict[str, Any]] = []

    for entry in state["active_domains"]:
        matched = is_fqdn_blocked(entry["fqdn"], compiled_blocks, compiled_allows)
        if not matched:
            remaining.append(entry)
            continue

        print(f"[blocked] {entry['fqdn']} matched rule {matched!r}; rotating...")
        client.delete_subdomain(entry["data_id"])
        retired = dict(entry)
        retired["retired_at"] = utc_now().isoformat()
        retired["retired_reason"] = f"blocked:{matched}"
        state["old_domains"].append(retired)

        state["active_domains"] = remaining
        new_entry = create_unique_subdomain(client, state, config, target_ip, registry_domains)
        remaining.append(new_entry)
        rotated.append((entry["fqdn"], new_entry["fqdn"]))

    state["active_domains"] = remaining
    if rotated:
        refresh_working_domains(state, target_ip, config)
    return rotated


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
    registry_domains = [r for r in registry_domains if not is_banned(r.domain, config)]
    if not registry_domains:
        raise FreeDNSError("No parent registry domains available (all banned?).")

    active_fqdns = {d["fqdn"].lower() for d in state["active_domains"]}
    old_fqdns = {d["fqdn"].lower() for d in state["old_domains"]}
    taken_fqdns = {f.lower() for f in state.get("taken_fqdns", [])}
    blocked_fqdns = active_fqdns | old_fqdns | taken_fqdns
    compiled_allows, compiled_blocks = load_compiled_rules(Path(__file__).resolve().parent)

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
        if compiled_blocks and is_fqdn_blocked(candidate_fqdn, compiled_blocks, compiled_allows):
            blocked_fqdns.add(candidate_fqdn)
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

    # Retire anything under a banned domain first.
    for banned in [d for d in active if is_banned(d["fqdn"], config)]:
        client.delete_subdomain(banned["data_id"])
        active.remove(banned)
        retired = dict(banned)
        retired["retired_at"] = utc_now().isoformat()
        retired["retired_reason"] = "banned"
        state["old_domains"].append(retired)
        print(f"[deleted:banned] {banned['fqdn']} (id={banned['data_id']})")

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
    prune_unverified_domains(client, state, config)
    return target_ip


def fill_to_max_domains(
    client: BaseFreeDNSClient,
    state: dict[str, Any],
    config: dict[str, Any],
    registry_domains: list[RegistryDomain],
) -> tuple[str, int]:
    """Create unique subdomains until active_domains reaches max_domains."""
    target_ip = resolve_target_ip(config["target_domain"])
    sync_state_with_account(client, state)

    max_domains = int(config["max_domains"])
    active = sorted(state["active_domains"], key=lambda d: d["created_at"])

    for banned in [d for d in active if is_banned(d["fqdn"], config)]:
        client.delete_subdomain(banned["data_id"])
        active.remove(banned)
        retired = dict(banned)
        retired["retired_at"] = utc_now().isoformat()
        retired["retired_reason"] = "banned"
        state["old_domains"].append(retired)
        print(f"[deleted:banned] {banned['fqdn']} (id={banned['data_id']})")

    state["active_domains"] = active
    created = 0
    while len(state["active_domains"]) < max_domains:
        new_entry = create_unique_subdomain(client, state, config, target_ip, registry_domains)
        state["active_domains"].append(new_entry)
        created += 1

    refresh_working_domains(state, target_ip, config)
    return target_ip, created


def syncable_fqdns(state: dict[str, Any], config: dict[str, Any]) -> list[str]:
    """Verified-working, non-banned FQDNs that should be served by nginx."""
    return sorted(
        d["fqdn"].lower()
        for d in state.get("active_domains", [])
        if d.get("working") and not is_banned(d["fqdn"], config)
    )


def check_https(fqdn: str, host: str, timeout: float = 8.0) -> str | None:
    """Connect to host:443 with SNI=fqdn and fully verify the cert. None if OK, else the error."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=fqdn):
                return None
    except ssl.SSLCertVerificationError as exc:
        return f"certificate: {exc.verify_message or exc}"
    except (OSError, ssl.SSLError) as exc:
        return f"connection: {exc}"


def check_nginx_sync(fqdns: list[str], config: dict[str, Any]) -> dict[str, str]:
    """Return {fqdn: error} for every fqdn that the nginx server doesn't serve with a valid cert."""
    if not fqdns:
        return {}
    host = (
        str(config.get("nginx_check_host", "")).strip()
        or str(config.get("nginx_ssh_host", "")).strip()
        or resolve_target_ip(config["target_domain"])
    )
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = pool.map(lambda f: (f, check_https(f, host)), fqdns)
    return {f: err for f, err in results if err}


CERTBOT_NOISE = (
    "Saving debug log",
    "Ask for help or search",
    "See the logfile",
    "Some challenges have failed",
    "- - - -",
)


def parse_sync_failures(output: str) -> dict[str, str]:
    """Extract per-domain reasons from sync_nginx.py output:
    "[certbot] Failed for <fqdn>: <multi-line stderr>" and "[nginx-sync] Refusing ... <fqdn>..."."""
    reasons: dict[str, list[str]] = {}
    current: str | None = None
    for raw in output.splitlines():
        line = raw.strip()
        m = re.match(r"^\[certbot\] Failed for (\S+?):\s*(.*)$", line)
        if m:
            current = m.group(1).lower()
            reasons[current] = [m.group(2)] if m.group(2) else []
            continue
        m = re.match(r"^\[nginx-sync\] Refusing (?:protected/externally configured name: )?(\S+?):?\s*(.*)$", line)
        if m:
            current = None
            reasons[m.group(1).lower()] = [line.removeprefix("[nginx-sync] ")]
            continue
        if line.startswith("["):
            current = None
        elif current and line and not any(line.startswith(n) for n in CERTBOT_NOISE):
            reasons[current].append(line)
    return {f: (" ".join(parts) or "certbot failed (no details)")[:600] for f, parts in reasons.items()}


def trigger_nginx_sync(
    state: dict[str, Any],
    config: dict[str, Any],
    _base_dir: Path,
    force: bool = False,
    log: Callable[[str], None] | None = None,
) -> bool:
    """Sync verified working domains to main server nginx + certbot over SSH."""
    if not force and not config.get("nginx_sync_enabled", False):
        return False

    working_fqdns = syncable_fqdns(state, config)
    if not force and working_fqdns == state.get("last_synced_working", []):
        return False

    user = str(config.get("nginx_ssh_user", "root")).strip() or "root"
    host = str(config.get("nginx_ssh_host", "")).strip()
    port = int(config.get("nginx_ssh_port", 22))
    if not host:
        raise RuntimeError("nginx_ssh_host is required for SSH nginx sync")

    cmd = ["ssh", "-T", "-o", "BatchMode=yes", "-p", str(port)]
    ssh_key = str(config.get("nginx_ssh_key", "")).strip()
    if ssh_key:
        cmd.extend(["-i", ssh_key])
    cmd.append(f"{user}@{host}")

    res = subprocess.run(
        cmd,
        input=json.dumps({"working_fqdns": working_fqdns}),
        capture_output=True,
        text=True,
    )

    output = "\n".join(part for part in (res.stdout.strip(), res.stderr.strip()) if part)
    if res.returncode != 0:
        raise RuntimeError(f"nginx sync failed: {output}")
    # Surface everything (incl. per-domain certbot failures on stderr), not just stdout.
    emit = log or print
    for line in output.splitlines():
        if line.strip():
            emit(f"[sync] {line.rstrip()}")
    state["last_synced_working"] = working_fqdns
    return True


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
    if config.get("nginx_sync_enabled", False):
        try:
            trigger_nginx_sync(state, config, state_path.parent)
        except Exception as exc:
            print(f"[nginx-sync] error: {exc}", file=sys.stderr)
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
    parser.add_argument("--weekly", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable weekly schedule (10/5)")
    parser.add_argument("--daily", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable daily 2-day schedule (28/27)")
    parser.add_argument("--active-hours", action=argparse.BooleanOptionalAction, default=None, help="Only rotate 08:30-15:20 on weekdays")
    parser.add_argument("--max-domains", type=int, default=None, help=f"Override max_domains (default {DOMAIN_COUNT})")
    parser.add_argument("--once", action="store_true", help="Run one rotation step and exit")
    parser.add_argument("--bootstrap", type=int, default=0, help="Create N subdomains immediately before rotating")
    parser.add_argument("--status", action="store_true", help="Refresh/show active & working domain lists and exit")
    parser.add_argument("--import-account", action="store_true", help="Scrape all domains from FreeDNS account and add them")
    parser.add_argument("--sync-rules", action="store_true", help="Download GoGuardian rules, update word_list, and rotate blocked domains")
    parser.add_argument("--clear-all", action="store_true", help="Delete ALL subdomains from FreeDNS and exit")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = base_dir / config_path

    config = load_config(config_path)
    if args.weekly is not None:
        config["weekly_enabled"] = args.weekly
    if args.daily is not None:
        config["daily_enabled"] = args.daily
    if args.active_hours is not None:
        config["active_hours_only"] = args.active_hours
    sync_rotation_rates(config)
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

    registry_domains = choose_parent_domains(client, config, cache_dir=base_dir)
    last_registry_check = time.monotonic()

    if args.sync_rules:
        words, compiled_allows, compiled_blocks = sync_goguardian_rules(base_dir, config)
        rotated = rotate_blocked_domains(
            client, state, config, registry_domains, compiled_blocks, compiled_allows
        )
        target_ip = resolve_target_ip(config["target_domain"])
        persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)
        print(f"[rules] Loaded {len(words)} *word* prefixes, rotated {len(rotated)} blocked domain(s).")
        return 0

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
        last_rules_check = 0.0
        rules_interval = float(config.get("rules_check_interval_seconds", 300))
        while running:
            now = utc_now()
            if (time.monotonic() - last_registry_check) >= 86400.0:
                registry_domains = choose_parent_domains(client, config, cache_dir=base_dir)
                last_registry_check = time.monotonic()
            if config.get("rules_sync_enabled", True) and (time.monotonic() - last_rules_check) >= rules_interval:
                last_rules_check = time.monotonic()
                try:
                    words, compiled_allows, compiled_blocks = sync_goguardian_rules(base_dir, config)
                    rotated = rotate_blocked_domains(
                        client, state, config, registry_domains, compiled_blocks, compiled_allows
                    )
                    if rotated:
                        target_ip = resolve_target_ip(config["target_domain"])
                        persist_all_files(state_path, active_path, working_path, old_path, state, next_rot, target_ip, config)
                    print(f"[rules] Synced {len(words)} *word* prefixes; rotated {len(rotated)} blocked domain(s).")
                except Exception as exc:
                    print(f"[rules] Sync error: {exc}", file=sys.stderr)

            if not is_in_active_hours(now, config):
                next_rot = next_active_window_start(now, config)
                wait_secs = max(1.0, (next_rot - now).total_seconds())
                print(f"[active-hours] Outside 08:30-15:20 or weekend; sleeping {format_duration(wait_secs)}")
                sleep_end = time.monotonic() + min(wait_secs, 60.0)
                while running and time.monotonic() < sleep_end:
                    time.sleep(min(0.5, max(0.0, sleep_end - time.monotonic())))
                continue

            try:
                target_ip = rotate_once(client, state, config, registry_domains)
            except AuthenticationError:
                print("[auth] Session cookie expired, re-logging in...")
                client = reauth_client(config)
                target_ip = rotate_once(client, state, config, registry_domains)
            next_rot = advance_rotation_time(now, config)
            interval = max(1.0, (next_rot - now).total_seconds())
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
