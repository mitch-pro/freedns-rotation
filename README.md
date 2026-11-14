# FreeDNS Rotation

Automated FreeDNS (`freedns.afraid.org`) subdomain rotator with a password- and CAPTCHA-protected Web UI.

## Features
- Maintains up to **55** active `A` record subdomains pointing to the current IP of `mitch.pro` (`DOMAIN_COUNT` in `rotate.py`; `max_domains` in `config.json` overrides it).
- Separate schedule toggles (can be combined):
  - **`weekly_enabled`**: `max_domains` rotations per week (55 → ~9.2/day weekdays, ~4.6/day weekends; ~1 week lifetime).
  - **`daily_enabled`**: `max_domains / 2` rotations per day (55 → 27.5/day; ~2 day lifetime).
  - **`active_hours_only`**: same weekly volume, squeezed into the weekday active-hours window.
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

1. Copy `sync_nginx.py` to `/opt/freedns/sync_nginx.py` on your main server. `/opt/freedns` and everything in it must be `root:root` and not group/world-writable (root runs it and writes `managed_certs.json` / `sync.lock` there).
2. Create `/opt/freedns/config.json` (root-owned) on the main server, e.g.:
   ```json
   {
     "nginx_conf_path": "/etc/nginx/conf.d/1-freedns-rotation.conf",
     "nginx_locations_snippet": "/etc/nginx/snippets/mitch-main-locations.conf",
     "certbot_email": "",
     "protected_domains": ["mitch.pro"],
     "max_fqdns": 100,
     "max_retire_per_run": 20
   }
   ```
   - `nginx_conf_path`: use a dedicated file inside `http {}` (e.g. `conf.d/`), not `nginx.conf` or your main site config. Create it empty first (`touch`), owned by root.
   - `protected_domains`: names (and all their subdomains) the sync will never serve or delete certs for. Every `server_name` already in nginx outside the managed `BEGIN/END DOMAIN` blocks (from `nginx -T`) is protected automatically.
   - Only certs this script issued itself are ever deleted; a requested name with a pre-existing cert is refused.
   - `max_fqdns` caps one request; `max_retire_per_run` caps cert deletions per run (the rest are deferred to later runs).
3. Generate a dedicated SSH key on the rotator (`ssh-keygen -t ed25519 -f ~/.ssh/freedns_sync_ed25519 -N ""`) and install it for a dedicated, unprivileged user (e.g. `freedns-sync`) on the main server with a forced command:
   ```text
   # ~freedns-sync/.ssh/authorized_keys
   restrict,from="<rotator-ip>",command="sudo -n /usr/bin/python3 -I /opt/freedns/sync_nginx.py --stdin" ssh-ed25519 AAAA...
   ```
   ```text
   # /etc/sudoers.d/freedns-sync  (arguments listed => sudo allows exactly these, nothing else)
   freedns-sync ALL=(root) NOPASSWD: /usr/bin/python3 -I /opt/freedns/sync_nginx.py --stdin
   ```
   `-I` stops Python from importing modules from the script directory or `PYTHON*` env vars. Concurrent runs are serialized with a lock file.
4. Set `"nginx_sync_enabled": true`, `"nginx_ssh_user"`, `"nginx_ssh_host"`, `"nginx_ssh_port"`, `"nginx_ssh_key"`, and `"certbot_email"` in `config.json` (or via the Web UI).

### Verify Nginx & Certbot
The **Verify Nginx & Certbot** button opens an HTTPS connection to the nginx server for every verified-working domain (SNI = the domain) and fully validates the certificate (trusted chain, hostname, expiry). If any fail it runs a sync, then re-checks those and reports what is still broken. Checks go to `nginx_check_host` if set, else `nginx_ssh_host`, else the IP of `target_domain` (set `nginx_check_host` to the server's LAN IP if your router doesn't do hairpin NAT).

