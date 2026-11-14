#!/usr/bin/env python3
"""Privileged helper to sync verified working FreeDNS domains into nginx.conf and Certbot.

Designed to be invoked either:
  1. Locally via a locked-down sudoers rule:
       mitch ALL=(root) NOPASSWD: /usr/bin/python3 /home/mitch/freedns/sync_nginx.py
  2. Remotely over SSH via a forced-command in authorized_keys:
       command="/usr/bin/python3 /opt/freedns/sync_nginx.py --stdin",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 ...
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any


BEGIN_MARKER = "# BEGIN FREEDNS MANAGED DOMAINS"
END_MARKER = "# END FREEDNS MANAGED DOMAINS"
FQDN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def validate_fqdn(name: str) -> str:
    clean = name.strip().lower()
    if not FQDN_RE.match(clean):
        raise ValueError(f"Invalid FQDN rejected: {name!r}")
    return clean


def load_sync_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        return {}
    return json.loads(config_path.read_text(encoding="utf-8"))


def cert_exists(fqdn: str, letsencrypt_dir: Path) -> bool:
    live = letsencrypt_dir / "live" / fqdn
    return (live / "fullchain.pem").is_file() and (live / "privkey.pem").is_file()


def render_server_blocks(
    fqdns: list[str],
    proxy_pass: str,
    letsencrypt_dir: Path,
) -> str:
    blocks: list[str] = []
    for fqdn in fqdns:
        if cert_exists(fqdn, letsencrypt_dir):
            fullchain = letsencrypt_dir / "live" / fqdn / "fullchain.pem"
            privkey = letsencrypt_dir / "live" / fqdn / "privkey.pem"
            blocks.append(
                f"server {{\n"
                f"    listen 80;\n"
                f"    server_name {fqdn};\n"
                f"    return 301 https://$host$request_uri;\n"
                f"}}\n"
                f"server {{\n"
                f"    listen 443 ssl;\n"
                f"    server_name {fqdn};\n"
                f"    ssl_certificate {fullchain};\n"
                f"    ssl_certificate_key {privkey};\n"
                f"    location / {{\n"
                f"        proxy_pass {proxy_pass};\n"
                f"        proxy_set_header Host $host;\n"
                f"        proxy_set_header X-Real-IP $remote_addr;\n"
                f"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                f"        proxy_set_header X-Forwarded-Proto $scheme;\n"
                f"    }}\n"
                f"}}"
            )
        else:
            blocks.append(
                f"server {{\n"
                f"    listen 80;\n"
                f"    server_name {fqdn};\n"
                f"    location / {{\n"
                f"        proxy_pass {proxy_pass};\n"
                f"        proxy_set_header Host $host;\n"
                f"        proxy_set_header X-Real-IP $remote_addr;\n"
                f"        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
                f"        proxy_set_header X-Forwarded-Proto $scheme;\n"
                f"    }}\n"
                f"}}"
            )
    return "\n\n".join(blocks)


def update_nginx_conf(nginx_conf: Path, managed_body: str) -> None:
    content = nginx_conf.read_text(encoding="utf-8")
    section = f"{BEGIN_MARKER}\n{managed_body}\n{END_MARKER}" if managed_body else f"{BEGIN_MARKER}\n{END_MARKER}"

    pattern = re.compile(
        re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER),
        re.S,
    )
    if pattern.search(content):
        new_content = pattern.sub(lambda _m: section, content, count=1)
    else:
        # Insert before the last closing brace of http { ... } if present.
        last_brace = content.rfind("}")
        if last_brace != -1 and re.search(r"\bhttp\s*\{", content):
            new_content = (
                content[:last_brace].rstrip()
                + "\n\n    "
                + section.replace("\n", "\n    ")
                + "\n}\n"
            )
        else:
            new_content = content.rstrip() + "\n\n" + section + "\n"

    backup = nginx_conf.with_suffix(".conf.freedns.bak")
    shutil.copy2(nginx_conf, backup)
    try:
        nginx_conf.write_text(new_content, encoding="utf-8")
        subprocess.run(["nginx", "-t"], check=True, capture_output=True, text=True)
    except Exception:
        shutil.copy2(backup, nginx_conf)
        raise


def reload_nginx() -> None:
    subprocess.run(["systemctl", "reload", "nginx"], check=True)


def obtain_cert(
    fqdn: str,
    email: str,
    method: str,
    webroot: str,
) -> bool:
    cmd = [
        "certbot",
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--keep-until-expiring",
    ]
    if email:
        cmd.extend(["--email", email])
    else:
        cmd.append("--register-unsafely-without-email")

    if method == "webroot":
        cmd.extend(["--webroot", "-w", webroot])
    else:
        cmd.append("--nginx")

    cmd.extend(["-d", fqdn])
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[certbot] Failed for {fqdn}: {res.stderr.strip()}", file=sys.stderr)
        return False
    print(f"[certbot] Obtained certificate for {fqdn}")
    return True


def delete_cert(fqdn: str) -> None:
    subprocess.run(
        ["certbot", "delete", "--cert-name", fqdn, "--non-interactive"],
        capture_output=True,
        text=True,
    )
    print(f"[certbot] Deleted retired certificate for {fqdn}")


def sync(
    working_fqdns: list[str],
    config: dict[str, Any],
    base_dir: Path,
) -> None:
    fqdns = sorted({validate_fqdn(d) for d in working_fqdns})
    nginx_conf = Path(config.get("nginx_conf_path", "/etc/nginx/nginx.conf"))
    proxy_pass = str(config.get("nginx_proxy_pass", "http://127.0.0.1:8080"))
    letsencrypt_dir = Path(config.get("letsencrypt_dir", "/etc/letsencrypt"))
    certbot_email = str(config.get("certbot_email", "")).strip()
    certbot_method = str(config.get("certbot_method", "nginx")).strip()
    certbot_webroot = str(config.get("certbot_webroot", "/var/www/html")).strip()
    managed_certs_path = Path(
        config.get("managed_certs_file", str(base_dir / "managed_certs.json"))
    )

    previously_managed: set[str] = set()
    if managed_certs_path.exists():
        try:
            previously_managed = {
                validate_fqdn(x)
                for x in json.loads(managed_certs_path.read_text(encoding="utf-8"))
            }
        except Exception:
            previously_managed = set()

    # 1. Write initial HTTP blocks for any new domains so Certbot HTTP-01 can verify them.
    initial_blocks = render_server_blocks(fqdns, proxy_pass, letsencrypt_dir)
    update_nginx_conf(nginx_conf, initial_blocks)
    reload_nginx()

    # 2. Obtain Certbot certs for any working domain missing one.
    newly_certified = False
    for fqdn in fqdns:
        if not cert_exists(fqdn, letsencrypt_dir):
            if obtain_cert(fqdn, certbot_email, certbot_method, certbot_webroot):
                newly_certified = True
                previously_managed.add(fqdn)
        else:
            previously_managed.add(fqdn)

    # 3. Clean up certs for domains we previously certified that are no longer working/active.
    retired = previously_managed - set(fqdns)
    for old_fqdn in sorted(retired):
        if cert_exists(old_fqdn, letsencrypt_dir):
            delete_cert(old_fqdn)
        previously_managed.discard(old_fqdn)

    managed_certs_path.write_text(
        json.dumps(sorted(previously_managed), indent=2),
        encoding="utf-8",
    )

    # 4. Re-render nginx.conf with HTTPS blocks if new certs were issued.
    if newly_certified:
        final_blocks = render_server_blocks(fqdns, proxy_pass, letsencrypt_dir)
        update_nginx_conf(nginx_conf, final_blocks)
        reload_nginx()

    print(f"[nginx-sync] Synced {len(fqdns)} working domain(s) to {nginx_conf}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync working FreeDNS domains to nginx.conf and Certbot")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--stdin", action="store_true", help="Read JSON {\"working_fqdns\": [...]} from stdin")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = base_dir / config_path
    config = load_sync_config(config_path)

    if args.stdin:
        payload = json.loads(sys.stdin.read() or "{}")
        working_fqdns = [str(x) for x in payload.get("working_fqdns", [])]
    else:
        state_path = base_dir / config.get("state_file", "state.json")
        if not state_path.exists():
            working_fqdns = []
        else:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            working_fqdns = [
                d["fqdn"] for d in state.get("active_domains", []) if d.get("working")
            ]

    sync(working_fqdns, config, base_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
