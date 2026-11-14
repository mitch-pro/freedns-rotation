#!/usr/bin/env python3
"""Web UI and controller for the FreeDNS subdomain rotation script."""

from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

from freedns_client import AuthenticationError, FreeDNSClient
from rotate import (
    advance_rotation_time,
    build_client,
    check_nginx_sync,
    choose_parent_domains,
    clear_all_domains,
    compute_replacement_times,
    format_duration,
    get_interval_seconds,
    import_account_domains,
    is_in_active_hours,
    load_config,
    load_state,
    next_active_window_start,
    normalize_banned_domains,
    parse_iso,
    persist_all_files,
    reauth_client,
    refresh_working_domains,
    resolve_fqdn_ips,
    resolve_target_ip,
    rotate_once,
    sync_rotation_rates,
    syncable_fqdns,
    trigger_nginx_sync,
    utc_now,
)


class AuthManager:
    """Self-hosted open-source warped SVG CAPTCHA and session cookie manager."""

    ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    COLORS = ("#93c5fd", "#6ee7b7", "#fcd34d", "#f9a8d4", "#c4b5fd")

    def __init__(self, password: str) -> None:
        self._password = password
        self._lock = threading.Lock()
        self._captchas: dict[str, tuple[str, float]] = {}
        self._sessions: dict[str, float] = {}

    def generate_captcha(self) -> tuple[str, str]:
        code = "".join(secrets.choice(self.ALPHABET) for _ in range(5))
        captcha_id = secrets.token_urlsafe(16)
        now = time.monotonic()

        with self._lock:
            self._captchas = {k: v for k, v in self._captchas.items() if v[1] > now}
            self._captchas[captcha_id] = (code, now + 300.0)

        svg = self._render_svg(code)
        return captcha_id, svg

    def _render_svg(self, code: str) -> str:
        rng = secrets.SystemRandom()
        seed = rng.randint(1, 99999)
        freq_x = rng.uniform(0.025, 0.045)
        freq_y = rng.uniform(0.05, 0.08)
        scale = rng.uniform(5.5, 8.5)

        parts = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="240" height="80" viewBox="0 0 240 80">',
            "<defs>",
            f'<filter id="warp_{seed}" x="-10%" y="-10%" width="120%" height="120%">',
            f'<feTurbulence type="fractalNoise" baseFrequency="{freq_x:.3f} {freq_y:.3f}" '
            f'numOctaves="2" seed="{seed}" result="noise"/>',
            f'<feDisplacementMap in="SourceGraphic" in2="noise" scale="{scale:.1f}" '
            'xChannelSelector="R" yChannelSelector="G"/>',
            "</filter>",
            "</defs>",
            '<rect width="240" height="80" rx="8" fill="#0b0f17" stroke="#232d42"/>',
            f'<g filter="url(#warp_{seed})">',
        ]

        # Background interference curves
        for _ in range(6):
            x1, y1 = rng.randint(0, 50), rng.randint(8, 72)
            cx, cy = rng.randint(60, 180), rng.randint(0, 80)
            x2, y2 = rng.randint(190, 240), rng.randint(8, 72)
            col = rng.choice(self.COLORS)
            parts.append(
                f'<path d="M{x1},{y1} Q{cx},{cy} {x2},{y2}" '
                f'stroke="{col}" stroke-opacity="0.4" stroke-width="1.8" fill="none"/>'
            )

        # Warped, skewed, rotated characters
        for idx, ch in enumerate(code):
            x = 24 + idx * 41 + rng.randint(-4, 4)
            y = 52 + rng.randint(-6, 6)
            rot = rng.randint(-25, 25)
            skew = rng.randint(-18, 18)
            fsize = rng.randint(30, 36)
            col = rng.choice(self.COLORS)
            parts.append(
                f'<text x="{x}" y="{y}" fill="{col}" '
                f'font-family="Georgia, \'Times New Roman\', serif" '
                f'font-size="{fsize}" font-weight="900" '
                f'transform="rotate({rot} {x} {y}) skewX({skew})">{ch}</text>'
            )

        # Noise speckles
        for _ in range(40):
            dx, dy = rng.randint(6, 234), rng.randint(6, 74)
            r = rng.uniform(0.9, 2.0)
            parts.append(f'<circle cx="{dx}" cy="{dy}" r="{r:.1f}" fill="#94a3b8" opacity="0.4"/>')

        parts.append("</g></svg>")
        return "".join(parts)

    def login(self, password: str, captcha_id: str, captcha_answer: str) -> tuple[bool, str, str | None]:
        now = time.monotonic()
        with self._lock:
            entry = self._captchas.pop(captcha_id, None)
        if not entry or entry[1] < now:
            return False, "CAPTCHA expired or invalid. Please try again.", None

        expected_code = entry[0]
        if not secrets.compare_digest(captcha_answer.strip().upper(), expected_code):
            return False, "Incorrect CAPTCHA.", None

        if not self._password or not secrets.compare_digest(password, self._password):
            return False, "Invalid password.", None

        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions = {k: v for k, v in self._sessions.items() if v > now}
            self._sessions[token] = now + 86400.0
        return True, "OK", token

    def is_authenticated(self, cookie_header: str | None) -> bool:
        if not cookie_header:
            return False
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            return False
        morsel = cookie.get("freedns_session")
        if not morsel:
            return False
        token = morsel.value
        now = time.monotonic()
        with self._lock:
            exp = self._sessions.get(token)
            if exp and exp > now:
                return True
            self._sessions.pop(token, None)
            return False

    def logout(self, cookie_header: str | None) -> None:
        if not cookie_header:
            return
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            return
        morsel = cookie.get("freedns_session")
        if morsel:
            with self._lock:
                self._sessions.pop(morsel.value, None)


class RotatorController:
    """Thread-safe controller managing rotation state, background loop, and logs."""

    def __init__(self, config_path: Path) -> None:
        self.base_dir = config_path.parent
        self.config_path = config_path
        self.config = load_config(config_path)
        self.state_path = self.base_dir / self.config["state_file"]
        self.active_path = self.base_dir / self.config["active_domains_file"]
        self.working_path = self.base_dir / self.config.get("working_domains_file", "working_domains.txt")
        self.old_path = self.base_dir / self.config["old_domains_file"]

        self.state = load_state(self.state_path)
        self.lock = threading.RLock()
        self.running = False
        self.logs: deque[str] = deque(maxlen=200)
        self._client: FreeDNSClient | None = None
        self._registry = None
        self._last_error: str | None = None
        self._cached_target_ip: str = "unresolved"
        self._cached_target_ip_at: float = 0.0

        now = utc_now()
        self.next_rot = (
            parse_iso(self.state["next_rotation_at"])
            if self.state.get("next_rotation_at")
            else now + timedelta(seconds=get_interval_seconds(now, self.config))
        )
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def log(self, msg: str) -> None:
        ts = utc_now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self.logs.append(line)
        print(line, flush=True)

    def _ensure_client(self) -> FreeDNSClient:
        if self._client is None:
            self._client = build_client(self.config)
            self.log("Authenticated with FreeDNS.")
        if self._registry is None:
            self._registry = choose_parent_domains(self._client, self.config)
            self.log(f"Loaded {len(self._registry)} public registry domain(s).")
        return self._client

    def _persist(self, target_ip: str) -> None:
        persist_all_files(
            self.state_path,
            self.active_path,
            self.working_path,
            self.old_path,
            self.state,
            self.next_rot,
            target_ip,
            self.config,
        )

    def _loop(self) -> None:
        last_dns_check = 0.0
        while True:
            with self.lock:
                should_run = self.running
                has_pending_dns = any(not d.get("working") for d in self.state["active_domains"])

            now_mono = time.monotonic()
            if has_pending_dns and (now_mono - last_dns_check) >= 30.0:
                last_dns_check = now_mono
                try:
                    self.refresh_dns()
                except Exception:
                    pass

            if should_run:
                now = utc_now()
                if now >= self.next_rot:
                    with self.lock:
                        allowed = is_in_active_hours(now, self.config)
                        if not allowed:
                            self.next_rot = next_active_window_start(now, self.config)
                    if allowed:
                        try:
                            self.rotate_now()
                            last_dns_check = time.monotonic()
                        except Exception as exc:
                            with self.lock:
                                self._last_error = str(exc)
                                self.running = False
                            self.log(f"ERROR (paused): {exc}")
            time.sleep(0.5)

    def start(self) -> None:
        with self.lock:
            self._last_error = None
            now = utc_now()
            if self.next_rot < now:
                self.next_rot = now
            self.running = True
            self.log("Rotation started.")

    def pause(self) -> None:
        with self.lock:
            self.running = False
            self.log("Rotation paused.")

    def rotate_now(self) -> None:
        with self.lock:
            client = self._ensure_client()
            now = utc_now()
            try:
                target_ip = rotate_once(client, self.state, self.config, self._registry)
            except AuthenticationError:
                self.log("Session cookie expired; re-logging in...")
                self._client = reauth_client(self.config)
                target_ip = rotate_once(self._client, self.state, self.config, self._registry)
            self.next_rot = advance_rotation_time(now, self.config)
            interval = max(1.0, (self.next_rot - now).total_seconds())
            self.state["next_rotation_at"] = self.next_rot.isoformat()
            self._persist(target_ip)
            self._last_error = None
            working_cnt = sum(1 for d in self.state["active_domains"] if d.get("working"))
            self.log(
                f"Rotated: active={len(self.state['active_domains'])}/{self.config['max_domains']}, "
                f"working={working_cnt}, next in {format_duration(interval)}"
            )

    def refresh_dns(self) -> None:
        with self.lock:
            target_domain = self.config["target_domain"]
            snapshot = [
                (d["fqdn"], d.get("address") or "")
                for d in self.state["active_domains"]
            ]

        target_ip = resolve_target_ip(target_domain)
        results: dict[str, tuple[str, bool]] = {}
        if snapshot:
            def _check(item: tuple[str, str]) -> tuple[str, str, bool]:
                fqdn, addr = item
                expected = addr or target_ip
                return fqdn, expected, (expected in resolve_fqdn_ips(fqdn))

            with ThreadPoolExecutor(max_workers=10) as pool:
                for fqdn, expected, ok in pool.map(_check, snapshot):
                    results[fqdn] = (expected, ok)

        now = utc_now()
        with self.lock:
            self._cached_target_ip = target_ip
            self._cached_target_ip_at = time.monotonic()
            for entry in self.state["active_domains"]:
                res = results.get(entry["fqdn"])
                if not res:
                    continue
                expected, ok = res
                if ok:
                    if not entry.get("working"):
                        entry["working"] = True
                        entry["verified_at"] = now.isoformat()
                        entry["resolved_ip"] = expected
                        self.log(f"{entry['fqdn']} now resolves to {expected}")
                else:
                    entry["working"] = False
            self._persist(target_ip)
            working_cnt = sum(1 for d in self.state["active_domains"] if d.get("working"))
            self.log(f"DNS check complete: {working_cnt}/{len(self.state['active_domains'])} working.")

    def clear_all(self) -> int:
        with self.lock:
            self.running = False
            client = self._ensure_client()
            target_ip = resolve_target_ip(self.config["target_domain"])
            try:
                deleted = clear_all_domains(client, self.state, self.config)
            except AuthenticationError:
                self.log("Session cookie expired; re-logging in...")
                self._client = reauth_client(self.config)
                deleted = clear_all_domains(self._client, self.state, self.config)
            self._persist(target_ip)
            self._last_error = None
            self.log(f"Cleared ALL domains from FreeDNS ({deleted} deleted).")
            return deleted

    def import_account(self) -> tuple[int, int]:
        with self.lock:
            client = self._ensure_client()
            target_ip = resolve_target_ip(self.config["target_domain"])
            try:
                added, total = import_account_domains(client, self.state, self.config)
            except AuthenticationError:
                self.log("Session cookie expired; re-logging in...")
                self._client = reauth_client(self.config)
                added, total = import_account_domains(self._client, self.state, self.config)
            self._persist(target_ip)
            self._last_error = None
            self.log(f"Imported {added} new domain(s) from FreeDNS ({total} total on account).")
            return added, total

    def sync_nginx(self) -> None:
        with self.lock:
            trigger_nginx_sync(self.state, self.config, self.base_dir, force=True)
            target_ip = resolve_target_ip(self.config["target_domain"])
            self._persist(target_ip)
            self.log("Synced working domains to Nginx & Certbot.")

    def verify_sync(self) -> dict[str, Any]:
        """Check every verified-working domain serves valid HTTPS; sync if any don't."""
        with self.lock:
            fqdns = syncable_fqdns(self.state, self.config)
        failing = check_nginx_sync(fqdns, self.config)  # network checks run outside the lock
        result: dict[str, Any] = {"checked": len(fqdns), "failing": sorted(failing), "synced": False}
        if not failing:
            self.log(f"Sync check: all {len(fqdns)} working domain(s) serve valid HTTPS.")
            result["still_failing"] = {}
            return result

        self.log(f"Sync check: {len(failing)}/{len(fqdns)} not serving valid HTTPS; syncing...")
        self.sync_nginx()
        result["synced"] = True
        still = check_nginx_sync(sorted(failing), self.config)
        result["still_failing"] = still
        if still:
            for fqdn, err in sorted(still.items()):
                self.log(f"Sync check: still failing {fqdn}: {err}")
        else:
            self.log(f"Sync check: fixed all {len(failing)} domain(s).")
        return result

    def update_config(self, updates: dict[str, Any]) -> None:
        with self.lock:
            if "weekly_enabled" in updates:
                self.config["weekly_enabled"] = bool(updates["weekly_enabled"])
            if "daily_enabled" in updates:
                self.config["daily_enabled"] = bool(updates["daily_enabled"])
            if "active_hours_only" in updates:
                self.config["active_hours_only"] = bool(updates["active_hours_only"])
            if "nginx_sync_enabled" in updates:
                self.config["nginx_sync_enabled"] = bool(updates["nginx_sync_enabled"])
            if "nginx_ssh_user" in updates:
                self.config["nginx_ssh_user"] = str(updates["nginx_ssh_user"]).strip() or "root"
            if "nginx_ssh_host" in updates:
                self.config["nginx_ssh_host"] = str(updates["nginx_ssh_host"]).strip()
            if "nginx_ssh_port" in updates:
                self.config["nginx_ssh_port"] = max(1, min(65535, int(updates["nginx_ssh_port"])))
            sync_rotation_rates(self.config)
            if "speed_multiplier" in updates:
                self.config["speed_multiplier"] = max(0.01, float(updates["speed_multiplier"]))
            if "max_domains" in updates:
                self.config["max_domains"] = max(1, int(updates["max_domains"]))
            if "target_domain" in updates and str(updates["target_domain"]).strip():
                self.config["target_domain"] = str(updates["target_domain"]).strip()
            if "word_list" in updates:
                raw = updates["word_list"]
                if isinstance(raw, str):
                    words = [w.strip().lower() for w in raw.split(",") if w.strip()]
                else:
                    words = [str(w).strip().lower() for w in raw if str(w).strip()]
                self.config["word_list"] = words
            if "banned_domains" in updates:
                self.config["banned_domains"] = normalize_banned_domains(updates["banned_domains"])

            # Persist config without overwriting env-only secrets if empty.
            with self.config_path.open("w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=2)

            now = utc_now()
            self.next_rot = advance_rotation_time(now, self.config)
            self.state["next_rotation_at"] = self.next_rot.isoformat()
            target_ip = resolve_target_ip(self.config["target_domain"])
            self._persist(target_ip)
            self.log("Configuration updated.")

    def get_status(self) -> dict[str, Any]:
        with self.lock:
            now = utc_now()
            now_mono = time.monotonic()
            if (now_mono - self._cached_target_ip_at) >= 60.0 or self._cached_target_ip == "unresolved":
                try:
                    self._cached_target_ip = resolve_target_ip(self.config["target_domain"])
                    self._cached_target_ip_at = now_mono
                except Exception:
                    pass
            target_ip = self._cached_target_ip

            active = sorted(self.state["active_domains"], key=lambda d: d["created_at"])
            replacements = compute_replacement_times(active, self.next_rot, self.config)

            active_rows = []
            working_rows = []
            for entry, rep in zip(active, replacements):
                delta = format_duration((rep - now).total_seconds())
                row = {
                    "fqdn": entry["fqdn"],
                    "data_id": entry.get("data_id", ""),
                    "address": entry.get("address", ""),
                    "created_at": parse_iso(entry["created_at"]).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "replace_at": rep.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "replace_in": delta,
                    "working": bool(entry.get("working")),
                    "verified_at": (
                        parse_iso(entry["verified_at"]).strftime("%Y-%m-%d %H:%M:%S UTC")
                        if entry.get("verified_at")
                        else ""
                    ),
                }
                active_rows.append(row)
                if row["working"]:
                    working_rows.append(row)

            old_rows = [
                {
                    "fqdn": o["fqdn"],
                    "address": o.get("address", ""),
                    "retired_at": (
                        parse_iso(o["retired_at"]).strftime("%Y-%m-%d %H:%M:%S UTC")
                        if o.get("retired_at")
                        else ""
                    ),
                }
                for o in reversed(self.state["old_domains"][-100:])
            ]

            return {
                "running": self.running,
                "last_error": self._last_error,
                "target_domain": self.config["target_domain"],
                "target_ip": target_ip,
                "max_domains": int(self.config["max_domains"]),
                "weekly_enabled": bool(self.config.get("weekly_enabled", True)),
                "daily_enabled": bool(self.config.get("daily_enabled", False)),
                "active_hours_only": bool(self.config.get("active_hours_only", False)),
                "nginx_sync_enabled": bool(self.config.get("nginx_sync_enabled", False)),
                "nginx_ssh_user": str(self.config.get("nginx_ssh_user", "root")),
                "nginx_ssh_host": str(self.config.get("nginx_ssh_host", "")),
                "nginx_ssh_port": int(self.config.get("nginx_ssh_port", 22)),
                "speed_multiplier": float(self.config.get("speed_multiplier", 1)),
                "weekday_rotations_per_day": float(self.config["weekday_rotations_per_day"]),
                "weekend_rotations_per_day": float(self.config["weekend_rotations_per_day"]),
                "word_list": self.config.get("word_list", []),
                "banned_domains": normalize_banned_domains(self.config.get("banned_domains", [])),
                "next_rotation_at": self.next_rot.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "next_rotation_in": format_duration((self.next_rot - now).total_seconds()),
                "active_count": len(active_rows),
                "working_count": len(working_rows),
                "old_count": len(self.state["old_domains"]),
                "active_domains": active_rows,
                "working_domains": working_rows,
                "old_domains": old_rows,
                "logs": list(self.logs),
            }

    def get_public_status(self) -> dict[str, Any]:
        """Read-only public status of all domains (no logs, secrets, or controls)."""
        full = self.get_status()
        return {
            "running": full["running"],
            "target_domain": full["target_domain"],
            "target_ip": full["target_ip"],
            "max_domains": full["max_domains"],
            "weekly_enabled": full["weekly_enabled"],
            "daily_enabled": full["daily_enabled"],
            "active_hours_only": full["active_hours_only"],
            "next_rotation_at": full["next_rotation_at"],
            "next_rotation_in": full["next_rotation_in"],
            "active_count": full["active_count"],
            "working_count": full["working_count"],
            "old_count": full["old_count"],
            "working_domains": full["working_domains"],
            "active_domains": full["active_domains"],
            "old_domains": full["old_domains"],
        }


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FreeDNS Rotator Control</title>
<style>
  :root {
    --bg: #0b0f17; --card: #131a26; --border: #232d42;
    --text: #e6edf7; --muted: #8b9bb4; --accent: #3b82f6;
    --green: #10b981; --amber: #f59e0b; --red: #ef4444;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: var(--bg); color: var(--text); padding: 24px;
  }
  .wrap { max-width: 1200px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }
  h1 { margin: 0; font-size: 22px; font-weight: 700; }
  .badge { padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge.run { background: rgba(16,185,129,.15); color: var(--green); border: 1px solid rgba(16,185,129,.4); }
  .badge.pause { background: rgba(245,158,11,.15); color: var(--amber); border: 1px solid rgba(245,158,11,.4); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .label { font-size: 12px; color: var(--muted); margin-bottom: 6px; }
  .val { font-size: 20px; font-weight: 700; }
  .sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .controls { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 20px; }
  button {
    border: 1px solid var(--border); background: #1c2536; color: var(--text);
    padding: 9px 15px; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 13px;
  }
  button:hover { filter: brightness(1.15); }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button.green { background: var(--green); border-color: var(--green); color: #052e16; }
  button.danger { background: rgba(239,68,68,.15); border-color: rgba(239,68,68,.5); color: #fca5a5; }
  .settings { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 20px; }
  .settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; align-items: end; }
  input, select {
    width: 100%; background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 8px 10px; font-size: 13px; margin-top: 4px;
  }
  .tabs { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .tab { background: var(--card); }
  .tab.active { background: var(--accent); border-color: var(--accent); color: #fff; }
  .panel { background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; background: rgba(255,255,255,.02); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .err { background: rgba(239,68,68,.15); border: 1px solid rgba(239,68,68,.4); color: #fecaca; padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; display: none; }
  pre { margin: 0; padding: 14px; max-height: 360px; overflow: auto; font-size: 12px; line-height: 1.5; color: #cbd5e1; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>FreeDNS Subdomain Rotator</h1>
    <div style="display:flex;gap:10px;align-items:center;">
      <span id="statusBadge" class="badge pause">PAUSED</span>
      <button onclick="logout()">Logout</button>
    </div>
  </header>

  <div id="errBox" class="err"></div>

  <div class="grid">
    <div class="card"><div class="label">Target A Record</div><div class="val mono" id="targetIp">-</div><div class="sub" id="targetDomain">-</div></div>
    <div class="card"><div class="label">Active Domains</div><div class="val" id="activeCount">-</div><div class="sub">Max cap enforced</div></div>
    <div class="card"><div class="label">Verified Working</div><div class="val" id="workingCount">0</div><div class="sub">DNS resolves to target</div></div>
    <div class="card"><div class="label">Retired Domains</div><div class="val" id="oldCount">0</div><div class="sub">Never reused</div></div>
    <div class="card"><div class="label">Next Rotation</div><div class="val" id="nextIn">-</div><div class="sub" id="nextAt">-</div></div>
  </div>

  <div class="controls">
    <button class="green" onclick="api('/api/start')">Start Rotation</button>
    <button onclick="api('/api/pause')">Pause</button>
    <button class="primary" onclick="api('/api/rotate-now')">Rotate Now</button>
    <button onclick="api('/api/import-account')">Import Account Domains</button>
    <button onclick="api('/api/refresh-dns')">Check Working DNS</button>
    <button onclick="api('/api/sync-nginx')">Sync Nginx &amp; Certbot</button>
    <button id="verifySyncBtn" onclick="verifySync()">Verify Nginx &amp; Certbot</button>
    <button class="danger" onclick="clearAll()">Clear ALL Domains</button>
  </div>

  <div class="settings">
    <div style="display:flex;flex-wrap:wrap;gap:18px;margin-bottom:14px;">
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input id="cfgWeekly" type="checkbox" style="width:auto;margin:0;"> Weekly (10/day wkday, 5/day wkend)
      </label>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input id="cfgDaily" type="checkbox" style="width:auto;margin:0;"> Daily / 2-Day (28/day wkday, 27/day wkend)
      </label>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input id="cfgActiveHours" type="checkbox" style="width:auto;margin:0;"> Active Hours Only (08:30–15:20, no weekends)
      </label>
      <label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;">
        <input id="cfgNginxSync" type="checkbox" style="width:auto;margin:0;"> Auto-Sync Nginx &amp; Certbot (SSH)
      </label>
    </div>
    <div class="settings-grid">
      <div><label class="label">Speed Multiplier (1 = real-time)<input id="cfgSpeed" type="number" step="any"></label></div>
      <div><label class="label">Max Domains<input id="cfgMax" type="number"></label></div>
      <div><label class="label">SSH User<input id="cfgSshUser" type="text" placeholder="root"></label></div>
      <div><label class="label">SSH Host<input id="cfgSshHost" type="text" placeholder="mitch.pro"></label></div>
      <div><label class="label">SSH Port<input id="cfgSshPort" type="number" placeholder="22"></label></div>
      <div style="grid-column: span 2;"><label class="label">Word List (comma-separated)<input id="cfgWords" type="text"></label></div>
      <div style="grid-column: span 2;"><label class="label">Banned Domains (comma-separated; also bans subdomains)<input id="cfgBanned" type="text" placeholder="groups.id, example.com"></label></div>
      <div><button class="primary" style="width:100%" onclick="saveConfig()">Save Settings</button></div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="showTab('working', this)">Working Domains</button>
    <button class="tab" onclick="showTab('active', this)">All Active Domains</button>
    <button class="tab" onclick="showTab('old', this)">Old / Retired</button>
    <button class="tab" onclick="showTab('logs', this)">Logs</button>
  </div>

  <div class="panel" id="tab-working"></div>
  <div class="panel" id="tab-active" style="display:none"></div>
  <div class="panel" id="tab-old" style="display:none"></div>
  <div class="panel" id="tab-logs" style="display:none"><pre id="logPre"></pre></div>
</div>

<script>
let currentTab = 'working';
let cfgLoaded = false;

function showTab(name, btn) {
  currentTab = name;
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  ['working','active','old','logs'].forEach(t => {
    document.getElementById('tab-' + t).style.display = (t === name) ? 'block' : 'none';
  });
}

async function api(url, body) {
  const res = await fetch(url, {
    method: body ? 'POST' : (url === '/api/status' ? 'GET' : 'POST'),
    headers: {'Content-Type': 'application/json'},
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json();
  if (!res.ok) alert(data.error || 'Request failed');
  if (url !== '/api/status') refresh();
  return data;
}

async function verifySync() {
  const btn = document.getElementById('verifySyncBtn');
  btn.disabled = true; const label = btn.textContent; btn.textContent = 'Verifying...';
  try {
    const d = await api('/api/verify-sync');
    if (d.error) return;
    const still = Object.entries(d.still_failing || {});
    let msg = `Checked ${d.checked} working domain(s).\n`;
    if (!d.failing.length) msg += 'All serve valid HTTPS. Nothing to sync.';
    else {
      msg += `${d.failing.length} were not serving valid HTTPS; ran a sync.\n`;
      msg += still.length ? `Still failing (${still.length}):\n` + still.map(([f, e]) => `- ${f}: ${e}`).join('\n')
                          : 'All fixed.';
    }
    alert(msg);
  } finally { btn.disabled = false; btn.textContent = label; }
}

async function clearAll() {
  if (!confirm('Delete EVERY subdomain on your FreeDNS account? This cannot be undone.')) return;
  await api('/api/clear-all');
}

async function saveConfig() {
  await api('/api/config', {
    weekly_enabled: document.getElementById('cfgWeekly').checked,
    daily_enabled: document.getElementById('cfgDaily').checked,
    active_hours_only: document.getElementById('cfgActiveHours').checked,
    nginx_sync_enabled: document.getElementById('cfgNginxSync').checked,
    nginx_ssh_user: document.getElementById('cfgSshUser').value,
    nginx_ssh_host: document.getElementById('cfgSshHost').value,
    nginx_ssh_port: parseInt(document.getElementById('cfgSshPort').value || '22', 10),
    speed_multiplier: parseFloat(document.getElementById('cfgSpeed').value),
    max_domains: parseInt(document.getElementById('cfgMax').value, 10),
    word_list: document.getElementById('cfgWords').value,
    banned_domains: document.getElementById('cfgBanned').value
  });
  cfgLoaded = false;
}

function renderTable(cols, rows) {
  if (!rows.length) return '<div style="padding:18px;color:#8b9bb4">No domains yet.</div>';
  let h = '<table><thead><tr>' + cols.map(c => `<th>${c.label}</th>`).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    h += '<tr>' + cols.map(c => `<td class="${c.mono ? 'mono' : ''}">${r[c.key] ?? ''}</td>`).join('') + '</tr>';
  }
  return h + '</tbody></table>';
}

async function refresh() {
  const d = await (await fetch('/api/status')).json();
  const badge = document.getElementById('statusBadge');
  badge.textContent = d.running ? 'RUNNING' : 'PAUSED';
  badge.className = 'badge ' + (d.running ? 'run' : 'pause');

  const errBox = document.getElementById('errBox');
  if (d.last_error) { errBox.textContent = d.last_error; errBox.style.display = 'block'; }
  else { errBox.style.display = 'none'; }

  document.getElementById('targetIp').textContent = d.target_ip;
  document.getElementById('targetDomain').textContent = d.target_domain;
  document.getElementById('activeCount').textContent = `${d.active_count} / ${d.max_domains}`;
  document.getElementById('workingCount').textContent = d.working_count;
  document.getElementById('oldCount').textContent = d.old_count;
  document.getElementById('nextIn').textContent = d.next_rotation_in;
  document.getElementById('nextAt').textContent = d.next_rotation_at;

  if (!cfgLoaded) {
    document.getElementById('cfgWeekly').checked = !!d.weekly_enabled;
    document.getElementById('cfgDaily').checked = !!d.daily_enabled;
    document.getElementById('cfgActiveHours').checked = !!d.active_hours_only;
    document.getElementById('cfgNginxSync').checked = !!d.nginx_sync_enabled;
    document.getElementById('cfgSshUser').value = d.nginx_ssh_user || 'root';
    document.getElementById('cfgSshHost').value = d.nginx_ssh_host || '';
    document.getElementById('cfgSshPort').value = d.nginx_ssh_port || 22;
    document.getElementById('cfgSpeed').value = d.speed_multiplier;
    document.getElementById('cfgMax').value = d.max_domains;
    document.getElementById('cfgWords').value = d.word_list.join(', ');
    document.getElementById('cfgBanned').value = (d.banned_domains || []).join(', ');
    cfgLoaded = true;
  }

  document.getElementById('tab-working').innerHTML = renderTable([
    {key:'fqdn', label:'FQDN', mono:true},
    {key:'address', label:'Resolved IP', mono:true},
    {key:'verified_at', label:'Verified Working'},
    {key:'replace_at', label:'Replace At'},
    {key:'replace_in', label:'Replace In'}
  ], d.working_domains);

  document.getElementById('tab-active').innerHTML = renderTable([
    {key:'fqdn', label:'FQDN', mono:true},
    {key:'address', label:'Target IP', mono:true},
    {key:'working', label:'DNS OK'},
    {key:'created_at', label:'Created At'},
    {key:'replace_at', label:'Replace At'},
    {key:'replace_in', label:'Replace In'}
  ], d.active_domains);

  document.getElementById('tab-old').innerHTML = renderTable([
    {key:'fqdn', label:'FQDN', mono:true},
    {key:'address', label:'Former IP', mono:true},
    {key:'retired_at', label:'Retired At'}
  ], d.old_domains);

  document.getElementById('logPre').textContent = d.logs.join('\\n');
}

async function logout() {
  await fetch('/api/logout', {method: 'POST'});
  location.reload();
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login - FreeDNS Rotator</title>
<style>
  :root { --bg:#0b0f17; --card:#131a26; --border:#232d42; --text:#e6edf7; --muted:#8b9bb4; --accent:#3b82f6; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    background: var(--bg); color: var(--text);
    font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  .card {
    width: 100%; max-width: 380px; background: var(--card);
    border: 1px solid var(--border); border-radius: 12px; padding: 24px;
  }
  h1 { margin: 0 0 6px; font-size: 20px; }
  p { margin: 0 0 18px; color: var(--muted); font-size: 13px; }
  label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 12px; }
  input {
    width: 100%; margin-top: 5px; background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 7px; padding: 9px 11px; font-size: 14px;
  }
  .captcha-row { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
  .captcha-box { line-height: 0; }
  button {
    border: 1px solid var(--border); background: #1c2536; color: var(--text);
    padding: 9px 12px; border-radius: 7px; font-weight: 600; cursor: pointer; font-size: 13px;
  }
  button.primary { width: 100%; background: var(--accent); border-color: var(--accent); color: #fff; margin-top: 4px; }
  .err { color: #fca5a5; background: rgba(239,68,68,.15); border: 1px solid rgba(239,68,68,.4); border-radius: 7px; padding: 8px 10px; font-size: 13px; margin-bottom: 12px; display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>FreeDNS Rotator</h1>
  <p>Enter your password and solve the CAPTCHA to continue.</p>
  <div id="err" class="err"></div>
  <form onsubmit="submitLogin(event)">
    <label>Password
      <input id="pw" type="password" required autocomplete="current-password">
    </label>
    <div class="captcha-row">
      <div id="captchaBox" class="captcha-box"></div>
      <button type="button" onclick="loadCaptcha()" title="New CAPTCHA">&#x21bb;</button>
    </div>
    <label>CAPTCHA Code
      <input id="cap" type="text" required autocomplete="off" placeholder="Enter characters above">
    </label>
    <button class="primary" type="submit">Sign In</button>
  </form>
</div>
<script>
let captchaId = '';
async function loadCaptcha() {
  const r = await (await fetch('/api/captcha')).json();
  captchaId = r.captcha_id;
  document.getElementById('captchaBox').innerHTML = r.svg;
  document.getElementById('cap').value = '';
}
async function submitLogin(e) {
  e.preventDefault();
  const errEl = document.getElementById('err');
  errEl.style.display = 'none';
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      password: document.getElementById('pw').value,
      captcha_id: captchaId,
      captcha_answer: document.getElementById('cap').value
    })
  });
  const data = await res.json();
  if (res.ok) { location.reload(); return; }
  errEl.textContent = data.error || 'Login failed';
  errEl.style.display = 'block';
  await loadCaptcha();
}
loadCaptcha();
</script>
</body>
</html>
"""


STATUS_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FreeDNS Domain Status</title>
<style>
  :root {
    --bg: #0b0f17; --card: #131a26; --border: #232d42;
    --text: #e6edf7; --muted: #8b9bb4; --accent: #3b82f6;
    --green: #10b981; --amber: #f59e0b;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--text); padding: 24px; }
  .wrap { max-width: 1150px; margin: 0 auto; }
  header { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; }
  h1 { margin: 0; font-size: 22px; }
  .badge { padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
  .badge.run { background: rgba(16,185,129,.15); color: var(--green); border: 1px solid rgba(16,185,129,.4); }
  .badge.pause { background: rgba(245,158,11,.15); color: var(--amber); border: 1px solid rgba(245,158,11,.4); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .label { font-size: 12px; color: var(--muted); margin-bottom: 6px; }
  .val { font-size: 20px; font-weight: 700; }
  .sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
  .tabs { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  button { border: 1px solid var(--border); background: var(--card); color: var(--text); padding: 9px 15px; border-radius: 8px; font-weight: 600; cursor: pointer; font-size: 13px; }
  button.active { background: var(--accent); border-color: var(--accent); color: #fff; }
  .panel { background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; background: rgba(255,255,255,.02); }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>FreeDNS Domain Status</h1>
    <div style="display:flex;gap:10px;align-items:center;">
      <span id="statusBadge" class="badge pause">PAUSED</span>
      <a href="/" style="color:#93c5fd;font-size:13px;text-decoration:none;">Admin</a>
    </div>
  </header>

  <div class="grid">
    <div class="card"><div class="label">Target A Record</div><div class="val mono" id="targetIp">-</div><div class="sub" id="targetDomain">-</div></div>
    <div class="card"><div class="label">Active Domains</div><div class="val" id="activeCount">-</div><div class="sub" id="modeText">-</div></div>
    <div class="card"><div class="label">Verified Working</div><div class="val" id="workingCount">0</div><div class="sub">DNS resolves properly</div></div>
    <div class="card"><div class="label">Retired Domains</div><div class="val" id="oldCount">0</div><div class="sub">Never reused</div></div>
    <div class="card"><div class="label">Next Rotation</div><div class="val" id="nextIn">-</div><div class="sub" id="nextAt">-</div></div>
  </div>

  <div class="tabs">
    <button class="active" onclick="showTab('working', this)">Working Domains</button>
    <button onclick="showTab('active', this)">All Active Domains</button>
    <button onclick="showTab('old', this)">Old / Retired</button>
  </div>

  <div class="panel" id="tab-working"></div>
  <div class="panel" id="tab-active" style="display:none"></div>
  <div class="panel" id="tab-old" style="display:none"></div>
</div>
<script>
function showTab(name, btn) {
  document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  ['working','active','old'].forEach(t => {
    document.getElementById('tab-' + t).style.display = (t === name) ? 'block' : 'none';
  });
}
function renderTable(cols, rows) {
  if (!rows.length) return '<div style="padding:18px;color:#8b9bb4">No domains yet.</div>';
  let h = '<table><thead><tr>' + cols.map(c => `<th>${c.label}</th>`).join('') + '</tr></thead><tbody>';
  for (const r of rows) {
    h += '<tr>' + cols.map(c => `<td class="${c.mono ? 'mono' : ''}">${r[c.key] ?? ''}</td>`).join('') + '</tr>';
  }
  return h + '</tbody></table>';
}
async function refresh() {
  const d = await (await fetch('/api/public-status')).json();
  const badge = document.getElementById('statusBadge');
  badge.textContent = d.running ? 'RUNNING' : 'PAUSED';
  badge.className = 'badge ' + (d.running ? 'run' : 'pause');
  document.getElementById('targetIp').textContent = d.target_ip;
  document.getElementById('targetDomain').textContent = d.target_domain;
  document.getElementById('activeCount').textContent = `${d.active_count} / ${d.max_domains}`;
  const modes = [];
  if (d.weekly_enabled) modes.push('Weekly');
  if (d.daily_enabled) modes.push('Daily');
  if (d.active_hours_only) modes.push('Active Hours');
  document.getElementById('modeText').textContent = modes.length ? modes.join(' + ') : 'Default';
  document.getElementById('workingCount').textContent = d.working_count;
  document.getElementById('oldCount').textContent = d.old_count;
  document.getElementById('nextIn').textContent = d.next_rotation_in;
  document.getElementById('nextAt').textContent = d.next_rotation_at;

  document.getElementById('tab-working').innerHTML = renderTable([
    {key:'fqdn', label:'FQDN', mono:true},
    {key:'address', label:'Resolved IP', mono:true},
    {key:'verified_at', label:'Verified Working'},
    {key:'replace_at', label:'Replace At'},
    {key:'replace_in', label:'Replace In'}
  ], d.working_domains);

  document.getElementById('tab-active').innerHTML = renderTable([
    {key:'fqdn', label:'FQDN', mono:true},
    {key:'address', label:'Target IP', mono:true},
    {key:'working', label:'DNS OK'},
    {key:'created_at', label:'Created At'},
    {key:'replace_at', label:'Replace At'},
    {key:'replace_in', label:'Replace In'}
  ], d.active_domains);

  document.getElementById('tab-old').innerHTML = renderTable([
    {key:'fqdn', label:'FQDN', mono:true},
    {key:'address', label:'Former IP', mono:true},
    {key:'retired_at', label:'Retired At'}
  ], d.old_domains);
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


MAX_POST_BYTES = 64 * 1024


def make_handler(controller: RotatorController, auth: AuthManager) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, code: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _is_authed(self) -> bool:
            return auth.is_authenticated(self.headers.get("Cookie"))

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if path == "/":
                page = HTML_PAGE if self._is_authed() else LOGIN_PAGE
                body = page.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "/status":
                if query.get("format") == ["json"]:
                    self._send_json(HTTPStatus.OK, controller.get_public_status())
                    return
                body = STATUS_PAGE.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "/api/public-status":
                self._send_json(HTTPStatus.OK, controller.get_public_status())
            elif path == "/api/captcha":
                captcha_id, svg = auth.generate_captcha()
                self._send_json(HTTPStatus.OK, {"captcha_id": captcha_id, "svg": svg})
            elif path == "/api/status":
                if not self._is_authed():
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
                    return
                self._send_json(HTTPStatus.OK, controller.get_status())
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length"})
                return
            if length > MAX_POST_BYTES:
                self.close_connection = True
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Request body too large"})
                return
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON"})
                return
            if not isinstance(body, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "JSON body must be an object"})
                return

            if path == "/api/login":
                ok, msg, token = auth.login(
                    str(body.get("password", "")),
                    str(body.get("captcha_id", "")),
                    str(body.get("captcha_answer", "")),
                )
                if not ok or not token:
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": msg})
                    return
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True},
                    extra_headers={
                        "Set-Cookie": f"freedns_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"
                    },
                )
                return

            if path == "/api/logout":
                auth.logout(self.headers.get("Cookie"))
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True},
                    extra_headers={"Set-Cookie": "freedns_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"},
                )
                return

            if not self._is_authed():
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
                return

            try:
                if path == "/api/start":
                    controller.start()
                    self._send_json(HTTPStatus.OK, {"ok": True})
                elif path == "/api/pause":
                    controller.pause()
                    self._send_json(HTTPStatus.OK, {"ok": True})
                elif path == "/api/rotate-now":
                    controller.rotate_now()
                    self._send_json(HTTPStatus.OK, {"ok": True})
                elif path == "/api/refresh-dns":
                    controller.refresh_dns()
                    self._send_json(HTTPStatus.OK, {"ok": True})
                elif path == "/api/clear-all":
                    deleted = controller.clear_all()
                    self._send_json(HTTPStatus.OK, {"ok": True, "deleted": deleted})
                elif path == "/api/import-account":
                    added, total = controller.import_account()
                    self._send_json(HTTPStatus.OK, {"ok": True, "added": added, "total": total})
                elif path == "/api/verify-sync":
                    self._send_json(HTTPStatus.OK, {"ok": True, **controller.verify_sync()})
                elif path == "/api/sync-nginx":
                    controller.sync_nginx()
                    self._send_json(HTTPStatus.OK, {"ok": True})
                elif path == "/api/config":
                    controller.update_config(body)
                    self._send_json(HTTPStatus.OK, {"ok": True})
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="FreeDNS Rotator Web UI")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--host", default=None, help="Bind host (default from config.json)")
    parser.add_argument("--port", type=int, default=None, help="Bind port (default from config.json)")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = base_dir / config_path

    controller = RotatorController(config_path)
    web_password = os.environ.get("FREEDNS_WEB_PASSWORD") or controller.config.get("web_password", "")
    if not web_password:
        raise SystemExit("web_password (or FREEDNS_WEB_PASSWORD) must be set in config.json.")
    auth = AuthManager(web_password)

    host = args.host or controller.config.get("web_host", "127.0.0.1")
    port = args.port or int(controller.config.get("web_port", 8080))

    server = ThreadingHTTPServer((host, port), make_handler(controller, auth))
    print(f"FreeDNS Rotator Web UI running at http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Web UI...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
