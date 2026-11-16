#!/usr/bin/env python3
"""Publish the current working FreeDNS domains (and their expiry times) to a
Google Doc via a Google Apps Script web app (see google_doc_publisher.gs).

The Apps Script creates a brand-new Google Doc each time, shares it with a list
of emails, records it as the "current" doc, and trashes the docs it created
before. Rotating the doc this way gives a fresh, shareable URL on every publish.

Nothing here is FreeDNS-specific beyond the payload shape: the controller hands
us a list of {"fqdn", "expires_at", "expires_in"} dicts plus the config, and we
POST a JSON body to the web app:

    {"password": "<shared secret>",
     "emails": ["a@example.com", ...],
     "title":  "...",
     "text":   "...human-readable body...",
     "domains":[{"fqdn": "...", "expires_at": "...", "expires_in": "..."}]}
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_emails(raw: Any) -> list[str]:
    """Parse a comma/space/newline-separated string (or list) into unique, valid emails."""
    items = re.split(r"[,\s]+", raw) if isinstance(raw, str) else [str(x) for x in (raw or [])]
    out: list[str] = []
    for item in items:
        addr = item.strip().lower()
        if addr and EMAIL_RE.match(addr) and addr not in out:
            out.append(addr)
    return out


def render_document_text(domains: list[dict[str, Any]], target_domain: str = "") -> str:
    """Build the human-readable document body: one line per domain with its expiry."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = ["FreeDNS Working Domains", f"Updated: {now}"]
    if target_domain:
        lines.append(f"Target: {target_domain}")
    lines.append("")
    if not domains:
        lines.append("(no working domains right now)")
        return "\n".join(lines)

    lines.append("These links work until the listed expiry time:")
    lines.append("")
    width = max(len(d.get("fqdn", "")) for d in domains)
    for d in domains:
        fqdn = d.get("fqdn", "")
        at = d.get("expires_at", "")
        rem = d.get("expires_in", "")
        suffix = f"expires {at}" if at else ""
        if rem:
            suffix += f"  (in {rem})"
        lines.append(f"https://{fqdn.ljust(width)}   {suffix}".rstrip())
    return "\n".join(lines)


def build_payload(config: dict[str, Any], domains: list[dict[str, Any]]) -> dict[str, Any]:
    target = str(config.get("target_domain", "")).strip()
    title = str(config.get("doc_title_prefix", "Working Domains")).strip() or "Working Domains"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return {
        "password": str(config.get("doc_auth_password", "")),
        "emails": normalize_emails(config.get("doc_emails", [])),
        "title": f"{title} — {stamp}",
        "text": render_document_text(domains, target),
        "domains": domains,
    }


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    # Apps Script /exec answers with a 302 to script.googleusercontent.com; urllib
    # follows it as a GET and fetches the ContentService result, which is what we want.
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500] if exc.fp else ""
        raise RuntimeError(f"HTTP {exc.code} from web app: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach web app: {exc.reason}") from exc

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        snippet = body.strip()[:500]
        raise RuntimeError(
            "Web app did not return JSON (check the deployment is public and the URL ends in /exec): "
            + snippet
        )
    if isinstance(parsed, dict) and parsed.get("ok") is False:
        raise RuntimeError(f"Web app error: {parsed.get('error', 'unknown')}")
    return parsed if isinstance(parsed, dict) else {"result": parsed}


def publish_domains(
    config: dict[str, Any],
    domains: list[dict[str, Any]],
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """POST the domains to the web app. Returns the parsed response (with 'url', 'id')."""
    url = str(config.get("doc_webapp_url", "")).strip()
    if not url:
        raise RuntimeError("doc_webapp_url is not configured")
    if not str(config.get("doc_auth_password", "")):
        raise RuntimeError("doc_auth_password is not configured")
    return _post_json(url, build_payload(config, domains), timeout)


def get_current_url(config: dict[str, Any], *, timeout: float = 20.0) -> str:
    """Fetch the URL of the current published doc (uses the web app's doGet)."""
    url = str(config.get("doc_webapp_url", "")).strip()
    if not url:
        return ""
    sep = "&" if "?" in url else "?"
    full = f"{url}{sep}password={urllib.parse.quote(str(config.get('doc_auth_password', '')))}"
    try:
        with urllib.request.urlopen(full, timeout=timeout) as resp:
            parsed = json.loads(resp.read().decode("utf-8", "replace"))
        return str(parsed.get("url", "")) if isinstance(parsed, dict) else ""
    except Exception:
        return ""
