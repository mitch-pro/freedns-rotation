#!/usr/bin/env python3
"""GoGuardian policy downloader (reads auth from config.json's goguardian_auth + cache)."""

from __future__ import annotations

import http.client
import http.cookies
import json
import os
import socket
from typing import Any
import urllib.error
import urllib.request

GATEWAY = "https://prod-ext-gateway.goguardian.com"
EXT_VERSION = "4.1.246"

EMPTY_AUTH: dict[str, Any] = {
    "license_tag": "",
    "device_id": "",
    "device_id_type": "SelfGenerated",
    "email": "",
    "profile_id": "",
    "identity_source": "ChromeIdentity",
    "refresh_token": "",
    "auth_token": None,
}


class _BoundHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that binds its socket to a specific network interface via SO_BINDTODEVICE."""

    def __init__(self, *args: Any, interface: str | None = None, **kwargs: Any) -> None:
        self._interface = interface
        super().__init__(*args, **kwargs)
        if interface:
            self._create_connection = self._bind_create_connection  # type: ignore[method-assign]

    def _bind_create_connection(
        self,
        address: tuple[str, int],
        timeout: float | None = socket._GLOBAL_DEFAULT_TIMEOUT,  # type: ignore[attr-defined]
        source_address: tuple[str, int] | None = None,
    ) -> socket.socket:
        if not hasattr(socket, "SO_BINDTODEVICE"):
            raise OSError("SO_BINDTODEVICE is not supported on this platform")

        host, port = address
        err: OSError | None = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, _, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    (self._interface + "\0").encode("utf-8"),  # type: ignore[operator]
                )
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:  # type: ignore[attr-defined]
                    sock.settimeout(timeout)
                if source_address:
                    sock.bind(source_address)
                sock.connect(sa)
                return sock
            except OSError as exc:
                err = exc
                if sock is not None:
                    sock.close()
        if err is not None:
            raise err
        raise OSError("getaddrinfo returns an empty list")


class _BoundHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPSHandler that routes requests through a specific network interface."""

    def __init__(self, interface: str) -> None:
        super().__init__()
        self._interface = interface

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(
            lambda host, **kwargs: _BoundHTTPSConnection(host, interface=self._interface, **kwargs),
            req,
            context=self._context,
        )


def load_auth_state(cache_path: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    state = dict(EMPTY_AUTH)
    if isinstance(overrides, dict):
        state.update({k: v for k, v in overrides.items() if v})
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
                same_identity = all(
                    not state.get(k) or not saved.get(k) or saved.get(k) == state.get(k)
                    for k in ("license_tag", "device_id", "email", "profile_id")
                )
                if same_identity:
                    state.update({k: v for k, v in saved.items() if v})
        except Exception:
            pass
    return state


def save_auth_state(cache_path: str, state: dict[str, Any]) -> None:
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def api_call(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    token: str | None = None,
    refresh_token: str | None = None,
    interface: str | None = None,
) -> tuple[int, Any, str | None]:
    url = f"{GATEWAY}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Extension-Version": EXT_VERSION,
        "User-Agent": (
            "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if refresh_token:
        headers["Cookie"] = f"refreshToken={refresh_token}"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    iface = (interface or "").strip()
    opener = urllib.request.build_opener(_BoundHTTPSHandler(iface)) if iface else None
    try:
        resp_ctx = opener.open(req, timeout=15) if opener else urllib.request.urlopen(req, timeout=15)
        with resp_ctx as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            new_rt = None
            for hdr_val in resp.headers.get_all("Set-Cookie") or []:
                c = http.cookies.SimpleCookie()
                c.load(hdr_val)
                if "refreshToken" in c and c["refreshToken"].value:
                    new_rt = c["refreshToken"].value
            return resp.status, (json.loads(raw) if raw else {}), new_rt
    except urllib.error.HTTPError as e:
        err_raw = e.read().decode("utf-8", errors="replace")
        return e.code, err_raw, None


def obtain_session(state: dict[str, Any], cache_path: str, interface: str | None = None) -> str:
    if state.get("refresh_token"):
        refresh_payload = {
            "licenseTag": state["license_tag"],
            "deviceId": state["device_id"],
            "deviceIdType": state["device_id_type"],
        }
        status, res, new_rt = api_call(
            "POST",
            "/v1/auth/refresh-session",
            body=refresh_payload,
            refresh_token=state["refresh_token"],
            interface=interface,
        )
        if status == 200 and isinstance(res, dict) and "authToken" in res:
            state["auth_token"] = res["authToken"]
            if new_rt:
                state["refresh_token"] = new_rt
            save_auth_state(cache_path, state)
            return state["auth_token"]

    if not state.get("email") or not state.get("device_id") or not state.get("license_tag"):
        raise RuntimeError(
            "GoGuardian credentials are not configured. Set goguardian_auth in config.json."
        )

    signin_payloads = [
        {
            "licenseTag": state["license_tag"],
            "deviceId": state["device_id"],
            "deviceIdType": state["device_id_type"],
            "identity": {
                "source": state["identity_source"],
                "email": state["email"],
                "profileId": state["profile_id"],
            },
            "oauth": {"googleAccessTokenError": "OAuth2 not granted or revoked."},
        },
        {
            "licenseTag": state["license_tag"],
            "deviceId": state["device_id"],
            "deviceIdType": state["device_id_type"],
            "identity": {
                "source": state["identity_source"],
                "email": state["email"],
                "profileId": state["profile_id"],
            },
        },
    ]
    last_status, last_res = None, None
    for path in ("/v2/auth/sign-in", "/v1/auth/sign-in"):
        for payload in signin_payloads:
            status, res, new_rt = api_call("POST", path, body=payload, interface=interface)
            last_status, last_res = status, res
            if status == 200 and isinstance(res, dict) and "authToken" in res:
                state["auth_token"] = res["authToken"]
                if new_rt:
                    state["refresh_token"] = new_rt
                save_auth_state(cache_path, state)
                return state["auth_token"]

    raise RuntimeError(f"Failed to authenticate with GoGuardian (HTTP {last_status}): {last_res}")


def fetch_policy(
    state: dict[str, Any],
    cache_path: str,
    timezone: str = "America%2FLos_Angeles",
    interface: str | None = None,
) -> dict[str, Any]:
    token = state.get("auth_token")
    if token:
        status, res, _ = api_call(
            "GET", f"/v1/policy?clientTimezoneLocale={timezone}", token=token, interface=interface
        )
        if status == 200 and isinstance(res, dict) and "policy" in res:
            return res

    token = obtain_session(state, cache_path, interface=interface)
    status, res, _ = api_call(
        "GET", f"/v1/policy?clientTimezoneLocale={timezone}", token=token, interface=interface
    )
    if status != 200 or not isinstance(res, dict) or "policy" not in res:
        raise RuntimeError(f"Failed to fetch GoGuardian policy (HTTP {status}): {res}")
    return res
