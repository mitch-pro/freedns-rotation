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

## No Target A Record (FreeDNS Update Script)
Untick **Use Target A Record** (or set `"target_enabled": false`) when the rotator runs on a different server and the main server has no fixed A record. Then:
- Run a FreeDNS dynamic-update script on the main server that updates **every** A record on the account (e.g. one driven by `https://freedns.afraid.org/api/?action=getdyndns&v=2&sha=...`, so newly created subdomains are picked up too).
- New subdomains are created with a placeholder IP: `placeholder_ip` if set, otherwise FreeDNS's default (the rotator's own public IP). The update script then moves them to the server's IP.
- A domain counts as working as soon as DNS returns any IP other than its placeholder. The IP most working domains resolve to is shown as the target IP.
- Verify Nginx & Certbot uses `nginx_check_host` / `nginx_ssh_host`, falling back to the learned IP.

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


## Google Doc Publisher (`doc.py` + `google_doc_publisher.gs`)
Publishes the current working domains and their expiry times to a Google Doc.
- **Routine publishes** (auto-publish interval, **Update Google Doc** button) rewrite the current doc in place: same URL, no sharing, so nobody gets emailed.
- **A new doc is created and shared** (emailing the list), and the old docs trashed, only when there is no current doc yet, when GoGuardian blocks the current doc, or when you click **New Google Doc + Reshare**.
- With **Active Hours Only** on, automatic new docs and shares wait until the next active-hours window. A manual **New Google Doc + Reshare** click goes out immediately.

1. In `script.google.com`, create a project and paste `google_doc_publisher.gs`. After updating the file, paste it again and redeploy a new version (Manage deployments → edit → New version), or the old script keeps creating and sharing a new doc on every publish.
2. Deploy → New deployment → **Web app**, *Execute as* Me, *Who has access* **Anyone**. Copy the `/exec` URL.
3. In the web UI settings set **Doc Web App URL**, **Doc Auth Password** (shared secret; the first request sets it on the script if unset), **Doc Share Emails**, optionally **Doc Publish Interval**, and tick **Auto-Publish** (or use the **Update Google Doc** button).

Secrets (`doc_auth_password`) live in `config.json` and are never returned by the UI; the password field stays blank and only overwrites when you type a new value. Note: a school/Workspace Google account may block "Anyone" web-app access or external link-sharing — deploy from an account whose admin allows it.
