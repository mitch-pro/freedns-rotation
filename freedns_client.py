"""FreeDNS (freedns.afraid.org) HTTP client."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import html
import re
from typing import Protocol
import requests


BASE_URL = "https://freedns.afraid.org"


class FreeDNSError(Exception):
    """Base error for FreeDNS operations."""


class AuthenticationError(FreeDNSError):
    """Raised when FreeDNS login fails."""


class SubdomainTakenError(FreeDNSError):
    """Raised when the requested subdomain is already taken."""


class CaptchaRequiredError(FreeDNSError):
    """Raised when FreeDNS presents a CAPTCHA challenge."""


@dataclass
class SubdomainRecord:
    data_id: str
    subdomain: str
    domain: str
    fqdn: str
    record_type: str
    address: str


@dataclass
class RegistryDomain:
    domain_id: str
    domain: str


class BaseFreeDNSClient(Protocol):
    def list_subdomains(self) -> list[SubdomainRecord]: ...
    def get_registry_domains(self, pages: int | None = None, public_only: bool = True) -> list[RegistryDomain]: ...
    def create_subdomain(
        self,
        subdomain: str,
        domain_id: str,
        domain_name: str,
        ip_address: str,
        record_type: str = "A",
    ) -> SubdomainRecord: ...
    def delete_subdomain(self, data_id: str) -> None: ...


class FreeDNSClient:
    """Live HTTP client for freedns.afraid.org."""

    def __init__(self, timeout: int = 20) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            }
        )
        self.timeout = timeout

    def set_cookie(self, dns_cookie: str) -> None:
        self.session.cookies.set("dns_cookie", dns_cookie, domain="freedns.afraid.org")

    def login(self, username: str, password: str) -> None:
        if not username or not password:
            raise AuthenticationError("FreeDNS username and password are required for live mode.")
        resp = self.session.post(
            f"{BASE_URL}/zc.php?step=2",
            data={
                "username": username,
                "password": password,
                "remember": "1",
                "submit": "Login",
                "remote": "",
                "from": "",
                "action": "auth",
            },
            timeout=self.timeout,
            allow_redirects=True,
        )
        resp.raise_for_status()
        text_lower = resp.text.lower()
        if (
            "invalid userid/pass" in text_lower
            or "dns_cookie" not in self.session.cookies
        ):
            raise AuthenticationError(
                "Login to FreeDNS failed (Invalid UserID/Pass or missing dns_cookie). "
                "Check username/password or set dns_cookie in config.json / .env."
            )

    def list_subdomains(self) -> list[SubdomainRecord]:
        resp = self.session.get(f"{BASE_URL}/subdomain/", timeout=self.timeout)
        resp.raise_for_status()
        if "zc.php" in resp.url or "action=auth" in resp.text:
            raise AuthenticationError("Session is not authenticated with FreeDNS (redirected to login).")

        records: list[SubdomainRecord] = []
        # Each subdomain row links to edit.php?data_id=<id> with the FQDN as link text,
        # followed by record type and destination IP in table cells.
        row_pattern = re.compile(
            r"<tr[^>]*>.*?edit\.php\?data_id=(\d+)[^>]*>([^<]+)</a>.*?"
            r"<td[^>]*>\s*([A-Z]+)\s*</td>\s*<td[^>]*>\s*([^<\s]+)\s*</td>.*?</tr>",
            re.S | re.I,
        )
        for match in row_pattern.finditer(resp.text):
            data_id = match.group(1).strip()
            fqdn = html.unescape(match.group(2)).strip().lower()
            record_type = html.unescape(match.group(3)).strip().upper()
            address = html.unescape(match.group(4)).strip()
            if "." in fqdn:
                sub, dom = fqdn.split(".", 1)
            else:
                sub, dom = fqdn, ""
            records.append(
                SubdomainRecord(
                    data_id=data_id,
                    subdomain=sub,
                    domain=dom,
                    fqdn=fqdn,
                    record_type=record_type,
                    address=address,
                )
            )
        return records

    def get_registry_domains(
        self, pages: int | None = None, public_only: bool = True
    ) -> list[RegistryDomain]:
        row_re = re.compile(
            r'<tr[^>]*class=["\']?tr[ld]["\']?[^>]*>.*?'
            r"subdomain/edit\.php\?edit_domain_id=(\d+)[^>]*>([^<]+)</a>.*?"
            r"<td>\s*(public|private)\s*</td>.*?</tr>",
            re.S | re.I,
        )

        def _parse_page(page_num: int) -> tuple[str, list[RegistryDomain]]:
            url = (
                f"{BASE_URL}/domain/registry/"
                if page_num == 1
                else f"{BASE_URL}/domain/registry/page-{page_num}.html"
            )
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            found: list[RegistryDomain] = []
            for domain_id, name, status in row_re.findall(resp.text):
                if public_only and status.strip().lower() != "public":
                    continue
                clean_name = html.unescape(name).strip().lower()
                if clean_name:
                    found.append(RegistryDomain(domain_id=domain_id, domain=clean_name))
            return resp.text, found

        first_html, first_domains = _parse_page(1)
        domains: dict[str, RegistryDomain] = {d.domain_id: d for d in first_domains}

        m = re.search(r"Page\s+\d+\s+of\s+(\d+)", first_html, re.I)
        total_pages = int(m.group(1)) if m else 1
        target_pages = total_pages if pages is None else min(pages, total_pages)

        if target_pages > 1:
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = [pool.submit(_parse_page, p) for p in range(2, target_pages + 1)]
                for fut in as_completed(futures):
                    try:
                        _, page_domains = fut.result()
                        for d in page_domains:
                            if d.domain_id not in domains:
                                domains[d.domain_id] = d
                    except Exception:
                        continue

        return list(domains.values())

    def create_subdomain(
        self,
        subdomain: str,
        domain_id: str,
        domain_name: str,
        ip_address: str,
        record_type: str = "A",
    ) -> SubdomainRecord:
        edit_url = f"{BASE_URL}/subdomain/edit.php?edit_domain_id={domain_id}"
        edit_resp = self.session.get(edit_url, timeout=self.timeout)
        edit_resp.raise_for_status()
        if "zc.php" in edit_resp.url or "action=auth" in edit_resp.text:
            raise AuthenticationError("Session expired (redirected to login).")

        if self._has_captcha(edit_resp.text):
            raise CaptchaRequiredError(
                "FreeDNS presented a CAPTCHA on subdomain creation; manual intervention required."
            )

        if not ip_address:
            # No target IP known (dynamic mode before the update script has run): use the
            # address FreeDNS pre-fills (the requester's IP); the update script replaces it.
            ip_address = self._form_default_address(edit_resp.text)
            if not ip_address:
                raise FreeDNSError("No target IP and FreeDNS form had no default address to use.")

        payload: dict[str, str] = {
            "domain_id": str(domain_id),
            "subdomain": subdomain,
            "type": record_type,
            "address": ip_address,
            "ttl": "",
            "send": "Save!",
        }
        # Preserve any hidden fields (such as 'ref' or CSRF tokens) from the form.
        for name, val in re.findall(
            r'<input[^>]*type=["\']?hidden["\']?[^>]*name=["\']?([^"\'\s>]+)["\']?[^>]*value=["\']?([^"\'>]*)["\']?',
            edit_resp.text,
            re.I,
        ):
            if name not in payload:
                payload[name] = html.unescape(val)

        save_resp = self.session.post(
            f"{BASE_URL}/subdomain/save.php?step=2",
            data=payload,
            headers={"Referer": edit_url},
            timeout=self.timeout,
            allow_redirects=True,
        )
        save_resp.raise_for_status()

        if self._has_captcha(save_resp.text):
            raise CaptchaRequiredError(
                "FreeDNS presented a CAPTCHA after submitting subdomain; manual intervention required."
            )

        body_lower = save_resp.text.lower()
        if any(
            phrase in body_lower
            for phrase in (
                "already exists",
                "already taken",
                "is already in use",
                "not available",
                "host already",
                "pending approval",
                "pending",
            )
        ):
            raise SubdomainTakenError(f"{subdomain}.{domain_name} is unavailable or pending on FreeDNS.")

        target_fqdn = f"{subdomain}.{domain_name}".lower()
        for rec in self.list_subdomains():
            if rec.fqdn == target_fqdn:
                return rec

        raise FreeDNSError(f"Subdomain {target_fqdn} did not appear in account list after creation.")

    def delete_subdomain(self, data_id: str) -> None:
        resp = self.session.get(
            f"{BASE_URL}/subdomain/delete2.php",
            params={"data_id[]": str(data_id), "submit": "delete selected"},
            headers={"Referer": f"{BASE_URL}/subdomain/"},
            timeout=self.timeout,
            allow_redirects=True,
        )
        resp.raise_for_status()
        if "zc.php" in resp.url or "action=auth" in resp.text:
            raise AuthenticationError("Session expired (redirected to login).")

    @staticmethod
    def _form_default_address(page_html: str) -> str:
        for tag in re.findall(r"<input[^>]*>", page_html, re.I):
            if re.search(r'name=["\']?address["\'\s>/]', tag, re.I):
                m = re.search(r'value=["\']?([^"\'\s>]*)', tag, re.I)
                return html.unescape(m.group(1)).strip() if m else ""
        return ""

    @staticmethod
    def _has_captcha(page_html: str) -> bool:
        lower = page_html.lower()
        return any(marker in lower for marker in ("securimage", "cap.php", "g-recaptcha", "hcaptcha", "captcha"))
