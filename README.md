# FreeDNS Rotation

Automated FreeDNS (`freedns.afraid.org`) subdomain rotator with a password- and CAPTCHA-protected Web UI.

## Features
- Maintains up to **55** active `A` record subdomains pointing to the current IP of `mitch.pro` (configurable).
- Separate schedule toggles (can be combined):
  - **`weekly_enabled`**: 10 rotations/day on weekdays, 5/day on weekends (~1 week lifetime).
  - **`daily_enabled`**: 28 rotations/day on weekdays, 27/day on weekends (~2 day lifetime).
  - **`active_hours_only`**: only rotates during local hours **08:30–15:20** on weekdays (no rotations on weekends).
- Draws from **all public domains** in the FreeDNS registry (cached in `registry_cache.json`).
- Picks subdomain prefixes randomly from `word_list` across public domains, falling back to 1- or 2-word diceware labels when exhausted.
- Tracks:
  - `active_domains.txt` — all active domains and their scheduled replacement times
  - `working_domains.txt` — only active domains verified to resolve to the target IP
  - `old_domains.txt` — retired domains (never reused)
- `--clear-all` / **Clear ALL Domains** button to delete every subdomain on the account.
- Self-hosted Web UI protected by password + open-source SVG CAPTCHA.

## Setup
```bash
cp config.example.json config.json
# Edit config.json with your FreeDNS credentials and web_password
# (or set FREEDNS_USERNAME, FREEDNS_PASSWORD, FREEDNS_COOKIE, FREEDNS_WEB_PASSWORD)
```

## Run
```bash
# Web UI (default http://127.0.0.1:8080)
python3 web.py

# CLI daemon
python3 rotate.py --mode 2day --speed 1
```

## 24/7 User-Level Systemd (`/home/mitch/freedns`)
```bash
mkdir -p ~/.config/systemd/user
cp freedns-rotation.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now freedns-rotation.service
sudo loginctl enable-linger mitch
```

## Secure Nginx + Certbot Sync (`sync_nginx.py`, SSH-Only)
`sync_nginx.py` automatically syncs whenever a new working domain starts resolving (or is removed). It only edits `# --- BEGIN DOMAIN: <fqdn> ---` ... `# --- END DOMAIN: <fqdn> ---` blocks in `nginx.conf`, strictly validates every FQDN, backs up `nginx.conf` and rolls back automatically if `nginx -t` fails, runs `certbot --nginx certonly -d <fqdn>`, and deletes certs only for domains it previously managed.

1. Copy `sync_nginx.py` to `/opt/freedns/sync_nginx.py` on your main server.
2. Generate a dedicated SSH key (`ssh-keygen -t ed25519 -f ~/.ssh/freedns_sync_ed25519 -N ""`).
3. Restrict the key on the main server's `/root/.ssh/authorized_keys` with a forced command:
   ```text
   command="/usr/bin/python3 /opt/freedns/sync_nginx.py --stdin",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty ssh-ed25519 AAAA...
   ```
4. Set `"nginx_sync_enabled": true`, `"nginx_ssh_user"`, `"nginx_ssh_host"`, `"nginx_ssh_port"`, `"nginx_ssh_key"`, and `"certbot_email"` in `config.json` (or via the Web UI).

