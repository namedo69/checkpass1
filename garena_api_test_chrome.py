from __future__ import annotations

import argparse
import csv
import hashlib
import json
import secrets
import socket
import ssl
import threading
import time
import traceback
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.cookiejar import Cookie, CookieJar
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import garena_tcp_login_chrome as tcp_ui


MAX_BODY = 8 * 1024
TEST_LOCK = threading.Lock()
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36"
)
SSO_LOGIN_URL = (
    "https://sso.garena.com/universal/login?"
    "app_id=10100&redirect_uri=https%3A%2F%2Faccount.garena.com%2F&locale=vi-VN"
)

SECRET_KEYS = {
    "access_token",
    "refresh_token",
    "authtoken",
    "ssokey",
    "sso_key",
    "session_key",
    "sessionkey",
    "oauth_code",
    "authorization_code",
    "code",
    "encodeparam",
    "authorization",
    "cookie",
    "client_secret",
}
PII_PARTS = ("phone", "mobile", "email", "identity", "passport", "cmnd", "cccd", "id_card")
ACCOUNT_VISIBLE_PII = frozenset({"email", "email_v", "email_verified", "email_verify"})
MAX_BATCH_BODY = 10 * 1024 * 1024
MAX_BATCH_ACCOUNTS = 2000


def resilient_tcp_client_type(tcp_module: Any) -> type:
    """Accept server-push frames while waiting for the requested command response."""

    base = tcp_module.GarenaTcpClient

    class ResilientGarenaTcpClient(base):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.ignored_server_commands: list[int] = []

        def _request(self, command: int, payload: bytes, key: bytes | None = None) -> bytes:
            if self.socket is None:
                raise tcp_module.GarenaError("Kết nối Garena chưa được mở")

            request_id = self._next_id()
            try:
                self.socket.sendall(tcp_module._encode_packet(request_id, command, payload, key))
            except OSError as exc:
                raise tcp_module.GarenaError("Không gửi được yêu cầu tới Garena") from exc

            deadline = time.monotonic() + float(self.timeout)
            previous_timeout = self.socket.gettimeout()
            try:
                for _ in range(16):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self.socket.settimeout(max(0.1, remaining))
                    size = tcp_module.struct.unpack("<I", self._receive_exact(4))[0]
                    if size <= 0 or size > 4 * 1024 * 1024:
                        raise tcp_module.GarenaError("Kích thước phản hồi Garena không hợp lệ")
                    header, reply = tcp_module._decode_packet(self._receive_exact(size), key)
                    reply_command = tcp_module._first_int(header, 4)
                    result = tcp_module._first_int(header, 5)
                    if reply_command != command:
                        self.ignored_server_commands.append(reply_command)
                        continue
                    if result != 0:
                        command_name = {
                            0x100: "LOGIN_PREPARE",
                            0x101: "LOGIN",
                            0x1BA: "SSO_KEY_GET",
                        }.get(command, "UNKNOWN")
                        raise tcp_module.GarenaError(
                            f"Garena từ chối ở bước {command_name} "
                            f"(lệnh 0x{command:X}), mã {result}"
                        )
                    return reply
            finally:
                self.socket.settimeout(previous_timeout)

            ignored = ", ".join(f"0x{item:X}" for item in self.ignored_server_commands[-8:])
            raise tcp_module.GarenaError(
                f"Không nhận được phản hồi 0x{command:X}; server-push đã bỏ qua: {ignored or 'không có'}"
            )

    ResilientGarenaTcpClient.__name__ = "ResilientGarenaTcpClient"
    return ResilientGarenaTcpClient


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def redact_value(key: str, value: Any, visible_pii: frozenset[str] = frozenset()) -> Any:
    folded = key.casefold().replace("-", "_")
    compact = folded.replace("_", "")
    if folded in SECRET_KEYS or compact in SECRET_KEYS:
        text = str(value or "")
        return f"<redacted sha256:{fingerprint(text)}>" if text else "<redacted>"
    if (
        folded not in visible_pii
        and any(part in folded for part in PII_PARTS)
        and isinstance(value, str)
        and value
    ):
        if len(value) <= 4:
            return "****"
        return value[:2] + "***" + value[-2:]
    return value


def redact_tree(
    value: Any,
    key: str = "",
    visible_pii: frozenset[str] = frozenset(),
) -> Any:
    value = redact_value(key, value, visible_pii)
    if isinstance(value, dict):
        return {
            str(k): redact_tree(v, str(k), visible_pii)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_tree(item, key, visible_pii) for item in value]
    return value


def safe_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def query_values(url: str) -> dict[str, str]:
    parsed = urllib.parse.urlsplit(url)
    values: dict[str, str] = {}
    for encoded in (parsed.query, parsed.fragment):
        for key, items in urllib.parse.parse_qs(encoded, keep_blank_values=True).items():
            if items:
                values[key] = items[-1]
    return values


def callback_matches(url: str, expected: str) -> bool:
    actual_parts = urllib.parse.urlsplit(url)
    expected_parts = urllib.parse.urlsplit(expected)
    return (
        actual_parts.scheme == "https"
        and actual_parts.scheme == expected_parts.scheme
        and actual_parts.netloc.casefold() == expected_parts.netloc.casefold()
        and actual_parts.path == expected_parts.path
    )


def normalized_label(value: Any) -> str:
    text = unicodedata.normalize("NFD", str(value or ""))
    return " ".join(
        "".join(char for char in text if unicodedata.category(char) != "Mn")
        .casefold()
        .split()
    )


def latest_lien_quan_login(logs: Any) -> dict[str, Any] | None:
    """Return the newest Account Center login whose source is Liên Quân Mobile."""

    if not isinstance(logs, list):
        return None
    matches = [
        item
        for item in logs
        if isinstance(item, dict)
        and "lien quan mobile" in normalized_label(item.get("source"))
    ]
    if not matches:
        return None

    def timestamp(item: dict[str, Any]) -> float:
        try:
            return float(item.get("timestamp") or 0)
        except (TypeError, ValueError):
            return 0.0

    return max(matches, key=timestamp)


def format_login_timestamp(value: Any) -> str:
    try:
        timestamp = float(value)
    except (TypeError, ValueError):
        return "không rõ"
    if timestamp <= 0:
        return "không rõ"
    vietnam_time = datetime.fromtimestamp(
        timestamp, tz=timezone(timedelta(hours=7))
    )
    return vietnam_time.strftime("%Y-%m-%d %H:%M:%S GMT+7")


def garena_web_password(password: str, v1: str, v2: str) -> str:
    """Match the password transform used by Garena's current Universal Login page."""

    md5_digest = hashlib.md5(password.encode("utf-8"), usedforsecurity=False).digest()
    md5_hex = md5_digest.hex()
    inner_hex = hashlib.sha256((md5_hex + v1).encode("utf-8")).hexdigest()
    aes_key = hashlib.sha256((inner_hex + v2).encode("utf-8")).digest()
    encryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    return (encryptor.update(md5_digest) + encryptor.finalize()).hex()


class WebSession:
    def __init__(self, timeout: float) -> None:
        self.cookies = CookieJar()
        self.timeout = timeout
        tls_context = ssl.create_default_context()
        # Python 3.14 enables OpenSSL X509_STRICT. Some certificates in the
        # Windows trust chain on this machine predate that RFC requirement.
        # Clearing only STRICT keeps CA, hostname, expiry and signature checks.
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            tls_context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=tls_context),
        )

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: Any | None = None,
        form_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, str, Any]:
        data = None
        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "vi-VN,vi;q=0.9,en;q=0.7",
        }
        if headers:
            request_headers.update(headers)
        if json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        elif form_body is not None:
            data = urllib.parse.urlencode(form_body).encode("utf-8")
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            response = exc

        raw = response.read(2 * 1024 * 1024)
        status = int(response.status)
        final_url = response.geturl()
        content_type = response.headers.get("Content-Type", "")
        text = raw.decode("utf-8", "replace")
        try:
            body: Any = json.loads(text)
        except json.JSONDecodeError:
            body = {"text_preview": text[:2000]}
        return status, final_url, content_type, body

    def api_result(
        self,
        url: str,
        *,
        method: str = "GET",
        json_body: Any | None = None,
        form_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        visible_pii: frozenset[str] = frozenset(),
    ) -> dict[str, Any]:
        started = time.monotonic()
        try:
            status, final_url, content_type, body = self.request(
                url, method=method, json_body=json_body, form_body=form_body, headers=headers
            )
            http_ok = 200 <= status < 300
            application_ok = not (
                isinstance(body, dict)
                and (body.get("error") not in (None, "", 0, False) or bool(body.get("errors")))
            )
            return {
                "ok": http_ok and application_ok,
                "http_ok": http_ok,
                "status": status,
                "url": safe_url(final_url),
                "content_type": content_type,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "body": redact_tree(body, visible_pii=visible_pii),
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": 0,
                "url": safe_url(url),
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "error": (str(exc).strip() or type(exc).__name__)[:500],
            }

    @staticmethod
    def _api_url(host: str, path: str, params: dict[str, Any]) -> str:
        values = {k: v for k, v in params.items() if v is not None}
        values["format"] = "json"
        values["id"] = str(int(time.time() * 1000))
        return f"https://{host}{path}?" + urllib.parse.urlencode(values)

    def _credential_login(
        self,
        host: str,
        app_id: str,
        account: str,
        password: str,
        redirect_uri: str,
        *,
        login_secondary: str | None = None,
    ) -> dict[str, Any]:
        started = time.monotonic()
        common = {"app_id": app_id, "account": account}
        prelogin: Any = None
        status = 0
        for attempt in range(3):
            try:
                status, _, _, prelogin = self.request(
                    self._api_url(host, "/api/prelogin", common),
                    headers={"Referer": f"https://{host}/universal/"},
                )
            except Exception:
                status, prelogin = 0, None
            if status == 200 and isinstance(prelogin, dict) and not prelogin.get("error"):
                break
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
        if status != 200 or not isinstance(prelogin, dict) or prelogin.get("error"):
            return {
                "ok": False,
                "stage": "prelogin",
                "status": status,
                "error": str(prelogin.get("error", "invalid_prelogin_response"))
                if isinstance(prelogin, dict)
                else f"invalid_prelogin_response (http {status})",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        if not isinstance(prelogin.get("v1"), str) or not isinstance(prelogin.get("v2"), str):
            return {
                "ok": False,
                "stage": "prelogin",
                "status": status,
                "error": "missing_password_challenge",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }

        transformed = garena_web_password(password, prelogin["v1"], prelogin["v2"])
        login_params: dict[str, Any] = {
            "app_id": app_id,
            "account": account,
            "password": transformed,
            "redirect_uri": redirect_uri,
        }
        if login_secondary is not None:
            login_params["login_secondary"] = login_secondary
        status, _, _, login = self.request(
            self._api_url(host, "/api/login", login_params),
            headers={"Referer": f"https://{host}/universal/"},
        )
        transformed = ""
        if status != 200 or not isinstance(login, dict) or login.get("error"):
            return {
                "ok": False,
                "stage": "login",
                "status": status,
                "error": str(login.get("error", "invalid_login_response"))
                if isinstance(login, dict)
                else "invalid_login_response",
                "challenge_required": bool(
                    isinstance(login, dict)
                    and any(word in str(login.get("error", "")) for word in ("captcha", "security", "otp"))
                ),
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        return {
            "ok": True,
            "stage": "login",
            "status": status,
            "redirect_uri": str(login.get("redirect_uri", "")),
            "session_key": str(login.get("session_key", "")),
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }

    def oauth_callback(
        self,
        account: str,
        password: str,
        params: dict[str, Any],
        *,
        ensure_login: bool,
    ) -> tuple[dict[str, Any], bool]:
        started = time.monotonic()
        init_url = self._api_url("auth.garena.com", "/api/universal/oauth", params)
        init: Any = None
        status = 0
        for attempt in range(3):
            try:
                status, _, _, init = self.request(init_url)
            except Exception:
                status, init = 0, None
            if status == 200 and isinstance(init, dict) and not init.get("error"):
                break
            if attempt < 2:
                time.sleep(1.5 * (attempt + 1))
        if status != 200 or not isinstance(init, dict) or init.get("error"):
            return ({
                "ok": False,
                "stage": "oauth_init",
                "status": status,
                "error": str(init.get("error", "invalid_oauth_init")) if isinstance(init, dict) else f"invalid_oauth_init (http {status})",
            }, ensure_login)

        logged_in = bool((init.get("sso_session") or {}).get("login"))
        login_result: dict[str, Any] | None = None
        if not logged_in and not ensure_login:
            login_result = self._credential_login(
                "auth.garena.com",
                str(params["client_id"]),
                account,
                password,
                str(params["redirect_uri"]),
            )
            if not login_result.get("ok"):
                return (login_result, False)
            ensure_login = True
        elif logged_in:
            ensure_login = True

        grant = {k: v for k, v in params.items() if k not in {"platform", "locale", "all_platforms", "prompt"}}
        grant["format"] = "json"
        grant["id"] = str(int(time.time() * 1000))
        status, _, _, body = self.request(
            "https://auth.garena.com/oauth/token/grant",
            method="POST",
            form_body=grant,
            headers={"Referer": "https://auth.garena.com/universal/"},
        )
        if status != 200 or not isinstance(body, dict) or body.get("error") or not body.get("redirect_uri"):
            return ({
                "ok": False,
                "stage": "oauth_grant",
                "status": status,
                "error": str(body.get("error", "missing_callback")) if isinstance(body, dict) else "invalid_grant_response",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }, ensure_login)

        callback_url = str(body["redirect_uri"])
        if not callback_matches(callback_url, str(params["redirect_uri"])):
            return ({
                "ok": False,
                "stage": "callback_validation",
                "status": status,
                "error": "unexpected_callback_origin",
                "callback_url": safe_url(callback_url),
            }, ensure_login)
        callback_status, final_url, content_type, _ = self.request(callback_url)
        callback_values = query_values(callback_url)
        return ({
            "ok": 200 <= callback_status < 400,
            "stage": "callback",
            "status": callback_status,
            "final_url": safe_url(final_url),
            "content_type": content_type,
            "callback_values": redact_tree(callback_values),
            "_callback_values": callback_values,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }, ensure_login)

    def bootstrap(self, url: str) -> dict[str, Any]:
        started = time.monotonic()
        try:
            status, final_url, content_type, body = self.request(url)
            return {
                "ok": 200 <= status < 400,
                "status": status,
                "final_url": safe_url(final_url),
                "content_type": content_type,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "query": query_values(final_url),
                "body_kind": "json" if not (isinstance(body, dict) and "text_preview" in body) else "html/text",
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": 0,
                "final_url": safe_url(url),
                "elapsed_ms": round((time.monotonic() - started) * 1000),
                "query": {},
                "error": (str(exc).strip() or type(exc).__name__)[:500],
            }


def fetch_latest_lien_quan_login(
    session: WebSession, account_init: dict[str, Any], max_pages: int = 5
) -> dict[str, Any]:
    """Search recent Account Center login pages for the newest Liên Quân entry."""

    current_result = account_init
    seen_cursors: set[tuple[str, str]] = set()
    pages_checked = 0
    exhausted = False

    while pages_checked < max_pages:
        body = current_result.get("body") or {}
        if not current_result.get("ok") or not isinstance(body, dict):
            break
        pages_checked += 1
        match = latest_lien_quan_login(body.get("login_history"))
        if match:
            return {
                "found": True,
                "entry": match,
                "pages_checked": pages_checked,
                "history_exhausted": False,
            }

        last_login_ts = body.get("last_login_ts")
        last_im_ts = body.get("last_im_ts")
        params = {
            key: value
            for key, value in (
                ("last_login_ts", last_login_ts),
                ("last_im_ts", last_im_ts),
            )
            if value not in (None, "", 0, "0")
        }
        cursor = (str(last_login_ts or ""), str(last_im_ts or ""))
        if not params or cursor in seen_cursors:
            exhausted = True
            break
        seen_cursors.add(cursor)
        current_result = session.api_result(
            "https://account.garena.com/api/account/login_logs/get",
            method="POST",
            json_body=params,
            headers={"Referer": "https://account.garena.com/login-history"},
        )

    return {
        "found": False,
        "entry": None,
        "pages_checked": pages_checked,
        "history_exhausted": exhausted,
    }


def public_sso_diagnostics(timeout: float) -> dict[str, Any]:
    """Check the public SSO route without sending account or session credentials."""

    host = "sso.garena.com"
    started = time.monotonic()
    result: dict[str, Any] = {
        "ok": False,
        "target": safe_url(SSO_LOGIN_URL),
        "credentials_sent": False,
    }
    try:
        result["dns_addresses"] = sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            }
        )

        tls_context = ssl.create_default_context()
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            tls_context.verify_flags &= ~ssl.VERIFY_X509_STRICT

        tcp_started = time.monotonic()
        with socket.create_connection((host, 443), timeout=timeout) as tcp_socket:
            result["tcp_connect_ms"] = round((time.monotonic() - tcp_started) * 1000)
            remote_host, remote_port = tcp_socket.getpeername()[:2]
            result["remote_endpoint"] = f"{remote_host}:{remote_port}"

            tls_started = time.monotonic()
            with tls_context.wrap_socket(tcp_socket, server_hostname=host) as tls_socket:
                result["tls_handshake_ms"] = round((time.monotonic() - tls_started) * 1000)
                result["tls_version"] = tls_socket.version()
                cipher = tls_socket.cipher()
                result["cipher"] = cipher[0] if cipher else None
                certificate = tls_socket.getpeercert()
                result["certificate_subject"] = certificate.get("subject", ())
                result["certificate_issuer"] = certificate.get("issuer", ())
                result["certificate_expires"] = certificate.get("notAfter")

        result["http"] = WebSession(timeout).bootstrap(SSO_LOGIN_URL)
        result["ok"] = bool(result["http"].get("ok"))
    except Exception as exc:
        result["error"] = (str(exc).strip() or type(exc).__name__)[:500]
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def web_account_center_login(
    session: WebSession,
    account: str,
    password: str,
) -> dict[str, Any]:
    """Log in through the Account Center's current app_id=10100 SSO route."""

    started = time.monotonic()
    result: dict[str, Any] = {
        "ok": False,
        "stage": "bootstrap",
        "login_url": safe_url(SSO_LOGIN_URL),
    }
    bootstrap = session.bootstrap(SSO_LOGIN_URL)
    if not bootstrap.get("ok"):
        result.update(
            {
                "status": bootstrap.get("status", 0),
                "error": bootstrap.get("error") or "account_sso_bootstrap_failed",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        )
        return result

    login = session._credential_login(
        "sso.garena.com",
        "10100",
        account,
        password,
        "https://account.garena.com/",
    )
    result.update(
        {
            "stage": login.get("stage") or "login",
            "status": login.get("status", 0),
            "session_key": str(login.get("session_key", "") or ""),
        }
    )
    if not login.get("ok"):
        result.update(
            {
                "error": login.get("error") or "account_sso_login_failed",
                "challenge_required": bool(login.get("challenge_required")),
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        )
        return result

    redirect_uri = str(login.get("redirect_uri") or "")
    if not redirect_uri:
        result.update(
            {
                "stage": "callback",
                "error": "missing_account_callback",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        )
        return result
    if not callback_matches(redirect_uri, "https://account.garena.com/"):
        result.update(
            {
                "stage": "callback_validation",
                "error": "unexpected_account_callback",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        )
        return result

    callback_status, final_url, _, _ = session.request(redirect_uri)
    result.update(
        {
            "stage": "account_init",
            "callback_status": callback_status,
            "final_url": safe_url(final_url),
        }
    )
    account_init = session.api_result(
        "https://account.garena.com/api/account/init",
        visible_pii=ACCOUNT_VISIBLE_PII,
    )
    result["account_init"] = account_init
    result["ok"] = bool(200 <= callback_status < 400 and account_init.get("ok"))
    if account_init.get("ok"):
        result["latest_lien_quan_login"] = fetch_latest_lien_quan_login(
            session, account_init
        )
    if not result["ok"]:
        result["error"] = account_init.get("error") or "account_init_failed"
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def legacy_account_sso_probe(sso_key: str, sso_expiry: int, timeout: float) -> dict[str, Any]:
    """Test the only plausible TCP-to-web bridge without putting secrets in a URL."""

    started = time.monotonic()
    session = WebSession(timeout)
    session.cookies.set_cookie(
        Cookie(
            version=0,
            name="sso_key",
            value=sso_key,
            port=None,
            port_specified=False,
            domain="sso.garena.com",
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=True,
            expires=sso_expiry,
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        )
    )
    params = {
        "app_id": "10100",
        "redirect_uri": "https://account.garena.com/",
        "locale": "vi-VN",
    }
    try:
        status, _, content_type, body = session.request(
            session._api_url("sso.garena.com", "/api/universal/login", params),
            headers={"Referer": "https://sso.garena.com/universal/login"},
        )
        if not isinstance(body, dict):
            return {
                "ok": False,
                "accepted": False,
                "status": status,
                "error": "invalid_sso_response",
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        logged_in = bool((body.get("sso_session") or {}).get("login"))
        redirect_uri = str(body.get("redirect_uri") or "")
        accepted = logged_in or bool(redirect_uri)
        result: dict[str, Any] = {
            "ok": 200 <= status < 300 and accepted,
            "accepted": accepted,
            "status": status,
            "content_type": content_type,
            "sso_session_login": logged_in,
            "redirect_received": bool(redirect_uri),
            "error": str(body.get("error") or "") or None,
            "credential_used": "tcp_sso_key_cookie",
            "tcp_session_key_sent": False,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
        if redirect_uri:
            if not callback_matches(redirect_uri, "https://account.garena.com/"):
                result.update({"ok": False, "accepted": False, "error": "unexpected_redirect_origin"})
            else:
                redirect_status, final_url, _, _ = session.request(redirect_uri)
                result["redirect_status"] = redirect_status
                result["final_url"] = safe_url(final_url)
        if result["accepted"]:
            result["account_init"] = session.api_result(
                "https://account.garena.com/api/account/init",
                visible_pii=ACCOUNT_VISIBLE_PII,
            )
            result["latest_lien_quan_login"] = fetch_latest_lien_quan_login(
                session, result["account_init"]
            )
            oauth_params = {
                "client_id": "100054",
                "redirect_uri": "https://kientuong.lienquan.garena.vn/auth/login/callback",
                "response_type": "code",
                "platform": "1",
                "locale": "vi-VN",
            }
            oauth_started = time.monotonic()
            oauth_status, _, oauth_type, oauth_body = session.request(
                session._api_url("auth.garena.com", "/api/universal/oauth", oauth_params),
                headers={"Referer": "https://auth.garena.com/universal/oauth"},
            )
            oauth_result: dict[str, Any] = {
                "ok": False,
                "status": oauth_status,
                "content_type": oauth_type,
                "account_session_reused": True,
                "credential_login_called": False,
                "sso_session_login": False,
                "callback_received": False,
            }
            if isinstance(oauth_body, dict):
                oauth_result["sso_session_login"] = bool(
                    (oauth_body.get("sso_session") or {}).get("login")
                )
                oauth_result["error"] = str(oauth_body.get("error") or "") or None
                callback_url = str(oauth_body.get("redirect_uri") or "")

                if oauth_result["sso_session_login"] and not callback_url:
                    grant = {
                        "client_id": "100054",
                        "response_type": "code",
                        "redirect_uri": oauth_params["redirect_uri"],
                        "format": "json",
                        "id": str(int(time.time() * 1000)),
                    }
                    grant_status, _, _, grant_body = session.request(
                        "https://auth.garena.com/oauth/token/grant",
                        method="POST",
                        form_body=grant,
                        headers={"Referer": "https://auth.garena.com/universal/oauth"},
                    )
                    oauth_result["grant_status"] = grant_status
                    if isinstance(grant_body, dict):
                        oauth_result["grant_error"] = str(grant_body.get("error") or "") or None
                        callback_url = str(grant_body.get("redirect_uri") or "")

                if callback_url:
                    oauth_result["callback_received"] = True
                    if callback_matches(callback_url, oauth_params["redirect_uri"]):
                        callback_status, final_url, _, _ = session.request(callback_url)
                        oauth_result["callback_status"] = callback_status
                        oauth_result["final_url"] = safe_url(final_url)
                        oauth_result["player_api"] = session.api_result(
                            "https://kientuong.lienquan.garena.vn/api/player/get",
                            headers={"Referer": "https://kientuong.lienquan.garena.vn/"},
                        )
                        oauth_result["ok"] = bool(oauth_result["player_api"].get("ok"))
                    else:
                        oauth_result["error"] = "unexpected_callback_origin"
            else:
                oauth_result["error"] = "invalid_oauth_response"
            oauth_result["elapsed_ms"] = round((time.monotonic() - oauth_started) * 1000)
            result["account_to_kientuong_oauth"] = oauth_result
        return result
    except Exception as exc:
        return {
            "ok": False,
            "accepted": False,
            "status": 0,
            "error": (str(exc).strip() or type(exc).__name__)[:500],
            "credential_used": "tcp_sso_key_cookie",
            "tcp_session_key_sent": False,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
def run_api_tests(tcp_module: Any, account: str, password: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    results: dict[str, Any] = {
        "tcp": {"ok": False, "account": account},
        "apis": {},
        "web_auth": {},
    }

    sso: Any = None
    try:
        client_type = resilient_tcp_client_type(tcp_module)
        with client_type(timeout=timeout) as client:
            uid = int(client.login(account, password))
            sso = client.get_sso_key()
            ignored_commands = list(client.ignored_server_commands)
        results["tcp"] = {
            "ok": True,
            "account": account,
            "uid": uid,
            "session_key_bytes": 16,
            "sso_key": f"<redacted sha256:{fingerprint(str(sso.sso_key))}>",
            "sso_expiry_time": int(sso.expiry_time),
            "web_sso_key": str(sso.sso_key),
            "ignored_server_commands": [f"0x{item:X}" for item in ignored_commands],
        }
    except Exception as exc:
        results["tcp"]["error"] = (str(exc).strip() or type(exc).__name__)[:500]

    tcp_ok = bool(results["tcp"].get("ok"))
    account_init: dict[str, Any] = {}
    player_api: dict[str, Any] = {}
    if tcp_ok:
        try:
            probe = legacy_account_sso_probe(str(sso.sso_key), int(sso.expiry_time), timeout)
        except Exception as exc:
            probe = {
                "ok": False,
                "accepted": False,
                "error": (str(exc).strip() or type(exc).__name__)[:500],
            }
        results["tcp_to_web_probe"] = probe
        candidate = probe.get("account_init")
        account_init = candidate if isinstance(candidate, dict) else {}
        results["apis"]["account_init"] = account_init or {
            "ok": False,
            "status": probe.get("status", 0),
            "error": str(probe.get("error") or "sso_key_probe_rejected"),
        }
        oauth_chain = probe.get("account_to_kientuong_oauth")
        oauth_chain = oauth_chain if isinstance(oauth_chain, dict) else {}
        candidate = oauth_chain.get("player_api")
        player_api = candidate if isinstance(candidate, dict) else {}
        results["apis"]["kientuong_player"] = player_api or {
            "ok": False,
            "error": str(oauth_chain.get("error") or "kientuong_probe_failed"),
        }
        results["web_auth"]["account_center"] = {
            "ok": bool(account_init.get("ok")),
            "stage": "tcp_sso_probe",
            "error": None if account_init.get("ok") else str(probe.get("error") or "sso_key_probe_rejected"),
        }
        results["web_auth"]["kientuong"] = {
            "ok": bool(player_api.get("ok")),
            "stage": "tcp_sso_probe_oauth",
            "error": None if player_api.get("ok") else str(oauth_chain.get("error") or "kientuong_probe_failed"),
        }

    account_ok = bool(account_init.get("ok"))
    kientuong_ok = bool(player_api.get("ok"))
    if not tcp_ok or not account_ok or not kientuong_ok:
        account_session = WebSession(timeout)
        try:
            account_auth = web_account_center_login(account_session, account, password)
        except Exception as exc:
            account_auth = {
                "ok": False,
                "stage": "account_sso",
                "error": (str(exc).strip() or type(exc).__name__)[:500],
            }
        results["web_auth"]["account_center"] = account_auth
        if not account_ok:
            results["apis"]["account_init"] = account_auth.get("account_init") or {
                "ok": False,
                "status": account_auth.get("status", 0),
                "error": account_auth.get("error") or "account_sso_login_failed",
            }

        session = WebSession(timeout)
        kientuong_params = {
            "client_id": "100054",
            "redirect_uri": "https://kientuong.lienquan.garena.vn/auth/login/callback",
            "response_type": "code",
            "platform": "3",
            "locale": "vi-VN",
        }
        try:
            kientuong_auth, _ = session.oauth_callback(
                account, password, kientuong_params, ensure_login=False
            )
        except Exception as exc:
            kientuong_auth = {
                "ok": False,
                "stage": "kientuong_oauth",
                "error": (str(exc).strip() or type(exc).__name__)[:500],
            }
        kientuong_auth.pop("_callback_values", None)
        results["web_auth"]["kientuong"] = kientuong_auth
        web_player = session.api_result(
            "https://kientuong.lienquan.garena.vn/api/player/get",
            headers={"Referer": "https://kientuong.lienquan.garena.vn/"},
        )
        if not kientuong_ok:
            results["apis"]["kientuong_player"] = web_player

    password = ""
    results["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return results


def format_user_output(result: dict[str, Any]) -> str:
    """Return only account and Kiện Tướng data on one ``||``-delimited line."""

    tcp = result.get("tcp") or {}
    apis = result.get("apis") or {}
    web_auth = result.get("web_auth") or {}
    probe = result.get("tcp_to_web_probe") or {}
    account_body = (apis.get("account_init") or {}).get("body") or {}
    if not isinstance(account_body, dict) or not isinstance(account_body.get("user_info"), dict):
        account_body = (probe.get("account_init") or {}).get("body") or {}
    user_info = account_body.get("user_info") or {}
    if not isinstance(user_info, dict):
        user_info = {}

    def clean(value: Any, fallback: str = "không có") -> str:
        if value is None or value == "":
            return fallback
        return " ".join(str(value).replace("||", "｜｜").split())

    def yes_no(value: Any) -> str:
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"1", "true", "yes", "on", "verified"}:
                return "Có"
            if normalized in {"0", "false", "no", "off", "unverified", ""}:
                return "Không"
        return "Có" if bool(value) else "Không"

    email = user_info.get("email")
    if not email:
        email_status = "Chưa liên kết"
    else:
        email_verified = next(
            (
                user_info[key]
                for key in ("email_v", "email_verified", "email_verify")
                if key in user_info
            ),
            None,
        )
        email_status = "Không rõ" if email_verified is None else (
            "Đã xác thực" if yes_no(email_verified) == "Có" else "Chưa xác thực"
        )

    def player_from(api_result: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        body = api_result.get("body") if isinstance(api_result, dict) else {}
        if not isinstance(body, dict):
            return {}, {}
        payload = body.get("data") if isinstance(body.get("data"), dict) else body
        player = payload.get("player") if isinstance(payload, dict) else {}
        return (
            payload if isinstance(payload, dict) else {},
            player if isinstance(player, dict) else {},
        )

    oauth_chain = probe.get("account_to_kientuong_oauth") or {}
    kientuong_payload, kientuong_player = player_from(apis.get("kientuong_player") or {})
    if not kientuong_player:
        kientuong_payload, kientuong_player = player_from(oauth_chain.get("player_api") or {})

    account_auth = web_auth.get("account_center") or {}
    session_key_display: Any = mask_secret_text(
        account_auth.get("session_key") or tcp.get("web_sso_key")
    )
    login_search = account_auth.get("latest_lien_quan_login") or {}
    if not login_search:
        login_search = probe.get("latest_lien_quan_login") or {}
    latest_game_login = (
        login_search.get("entry")
        if isinstance(login_search, dict)
        and isinstance(login_search.get("entry"), dict)
        else None
    )

    fields: list[tuple[str, Any, str]] = [
        ("Tài khoản", user_info.get("username") or tcp.get("account"), "không có"),
        ("UID Garena", user_info.get("uid") or tcp.get("uid"), "không có"),
        ("Email", email, "chưa liên kết"),
        ("Xác thực email", email_status, "Không rõ"),
        ("Số điện thoại", user_info.get("mobile_no"), "chưa liên kết"),
        ("Quốc gia", user_info.get("acc_country"), "không rõ"),
        ("Xác thực 2 bước", yes_no(user_info.get("two_step_verify_enable")), "Không"),
        ("Authenticator", yes_no(user_info.get("authenticator_enable")), "Không"),
        ("Session Key SSO", session_key_display, "không lấy được"),
    ]

    if latest_game_login:
        fields.extend(
            [
                (
                    "Đăng nhập Liên Quân gần nhất",
                    format_login_timestamp(latest_game_login.get("timestamp")),
                    "không rõ",
                ),
                ("IP đăng nhập", latest_game_login.get("ip"), "không có"),
                ("Khu vực đăng nhập", latest_game_login.get("country"), "không rõ"),
            ]
        )
    else:
        fields.append(("Đăng nhập Liên Quân gần nhất", "Không tìm thấy", "Không tìm thấy"))

    if kientuong_player:
        game_id = (
            kientuong_player.get("id")
            or kientuong_player.get("uid")
            or kientuong_player.get("openId")
        )
        game_uid = kientuong_player.get("uid") or kientuong_player.get("openId")
        fields.extend(
            [
                ("Tên Kiện Tướng", kientuong_player.get("name"), "không có"),
                ("ID Kiện Tướng", game_id, "không có"),
                ("Cấp độ", kientuong_player.get("level"), "không có"),
                (
                    "Trạng thái Kiện Tướng",
                    "Bị khóa" if bool(kientuong_player.get("banInfo")) else "Bình thường",
                    "không rõ",
                ),
            ]
        )
        if game_uid is not None and str(game_uid) != str(game_id):
            fields.append(("UID/OpenID game", game_uid, "không có"))
        deletion_status = kientuong_payload.get("playerStatus")
        if deletion_status:
            deletion_labels = {
                "NO_DELETION_REQUEST": "Không có yêu cầu xóa",
                "DELETION_REQUESTED": "Đang chờ xóa",
                "DELETION_COMPLETED": "Đã xóa",
            }
            fields.append(
                (
                    "Yêu cầu xóa Kiện Tướng",
                    deletion_labels.get(str(deletion_status), deletion_status),
                    "không rõ",
                )
            )
    else:
        fields.append(("Kiện Tướng", "Không lấy được thông tin", "Không lấy được thông tin"))

    return " || ".join(
        f"{label}: {clean(value, fallback)}" for label, value, fallback in fields
    )


@dataclass(slots=True)
class BatchAccount:
    index: int
    account: str
    password: str


def parse_credentials_text(text: str) -> list[BatchAccount]:
    accounts: list[BatchAccount] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            account, password = line.split("|", 1)
        elif line.count(":") == 1:
            account, password = line.split(":", 1)
        else:
            raise ValueError(f"Dòng {line_number}: cần định dạng user|pass hoặc user:pass")
        account = account.strip()
        if not account or not password or len(account) > 128 or len(password) > 1024:
            raise ValueError(f"Dòng {line_number}: tài khoản/mật khẩu không hợp lệ")
        accounts.append(BatchAccount(len(accounts) + 1, account, password))
        if len(accounts) >= MAX_BATCH_ACCOUNTS:
            break
    if not accounts:
        raise ValueError("Danh sách trống hoặc không có dòng hợp lệ")
    return accounts


def yes_no_text(value: Any) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"1", "true", "yes", "on", "verified"}:
            return "Có"
        if normalized in {"0", "false", "no", "off", "unverified"}:
            return "Không"
    return "Có" if bool(value) else "Không"


def email_verification_text(user_info: dict[str, Any]) -> str:
    if not str(user_info.get("email") or ""):
        return "chưa liên kết"
    verified = next(
        (
            user_info[key]
            for key in ("email_v", "email_verified", "email_verify")
            if key in user_info
        ),
        None,
    )
    if verified is None:
        return "không rõ"
    return "đã xác thực" if yes_no_text(verified) == "Có" else "chưa xác thực"


def identity_docs_text(user_info: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in user_info.items():
        folded = str(key).casefold().replace("-", "_").replace(" ", "_")
        if value in (None, "", {}, []):
            continue
        if any(part in folded for part in ("identity", "passport", "cmnd", "cccd", "id_card")):
            parts.append(f"{key}: {value}")
    return "; ".join(parts)[:160]


def latest_lqm_text(account_auth: dict[str, Any], probe: dict[str, Any]) -> str:
    search = account_auth.get("latest_lien_quan_login") or probe.get("latest_lien_quan_login") or {}
    entry = search.get("entry") if isinstance(search, dict) else None
    if not isinstance(entry, dict):
        return ""
    try:
        timestamp = float(entry.get("timestamp") or 0)
    except (TypeError, ValueError):
        timestamp = 0.0
    if timestamp <= 0:
        return ""
    return datetime.fromtimestamp(timestamp, tz=timezone(timedelta(hours=7))).strftime(
        "%Y-%m-%d %H:%M"
    )


def mask_secret_text(value: Any) -> str:
    text = str(value or "")
    if len(text) <= 12:
        return text
    return f"{text[:8]}...{text[-4:]}"


def batch_check_one(
    credential: Any,
    tcp_module: Any,
    timeout: float,
    gate: Any,
    stop_event: threading.Event,
) -> dict[str, str]:
    started = time.monotonic()
    row = {
        "stt": str(getattr(credential, "index", "")),
        "account": getattr(credential, "account", ""),
        "status": "FAIL",
        "uid": "",
        "email": "",
        "email_status": "",
        "phone": "",
        "country": "",
        "twofa": "",
        "auth": "",
        "id_docs": "",
        "lqm_login": "",
        "name": "",
        "level": "",
        "kt_status": "",
        "session_key": "",
        "session_key_masked": "",
        "elapsed_ms": "0",
        "error": "",
    }
    if not gate.wait(stop_event):
        row["error"] = "đã dừng trước khi gửi"
        credential.password = ""
        return row
    try:
        result = run_api_tests(tcp_module, credential.account, credential.password, timeout)
    except Exception as exc:
        row["error"] = (str(exc).strip() or type(exc).__name__)[:300]
    else:
        apis = result.get("apis") or {}
        web_auth = result.get("web_auth") or {}
        tcp_info = result.get("tcp") or {}
        account_auth = web_auth.get("account_center") or {}
        init_api = apis.get("account_init") or {}
        kientuong_api = apis.get("kientuong_player") or {}
        probe = result.get("tcp_to_web_probe") or {}
        oauth_chain = probe.get("account_to_kientuong_oauth") or {}

        init_body = init_api.get("body") if isinstance(init_api.get("body"), dict) else {}
        user_info = init_body.get("user_info") if isinstance(init_body.get("user_info"), dict) else {}
        probe_init_result = probe.get("account_init") or {}
        probe_init_body = (
            probe_init_result.get("body")
            if isinstance(probe_init_result.get("body"), dict)
            else {}
        )
        if not user_info and isinstance(probe_init_body.get("user_info"), dict):
            user_info = probe_init_body.get("user_info") or {}

        probe_player = (
            oauth_chain.get("player_api")
            if isinstance(oauth_chain.get("player_api"), dict)
            else {}
        )
        player_source = kientuong_api
        if not player_source.get("ok") and probe_player.get("ok"):
            player_source = probe_player
        kientuong_body = (
            player_source.get("body") if isinstance(player_source.get("body"), dict) else {}
        )
        payload = (
            kientuong_body.get("data")
            if isinstance(kientuong_body.get("data"), dict)
            else kientuong_body
        )
        player = payload.get("player") if isinstance(payload.get("player"), dict) else {}

        row["uid"] = str(user_info.get("uid") or tcp_info.get("uid") or "")
        row["name"] = str(player.get("name") or "")
        row["level"] = str(player.get("level") or "")
        row["kt_status"] = (
            ("Bị khóa" if player.get("banInfo") else "Bình thường") if player else ""
        )
        row["email"] = str(user_info.get("email") or "")
        row["email_status"] = email_verification_text(user_info)
        row["phone"] = str(user_info.get("mobile_no") or "")
        row["country"] = str(user_info.get("acc_country") or "")
        row["twofa"] = yes_no_text(user_info.get("two_step_verify_enable"))
        row["auth"] = yes_no_text(user_info.get("authenticator_enable"))
        row["id_docs"] = identity_docs_text(user_info)
        row["lqm_login"] = latest_lqm_text(account_auth, probe)
        row["session_key"] = (
            str(account_auth.get("session_key") or "")
            or str(tcp_info.get("web_sso_key") or "")
        )
        row["session_key_masked"] = mask_secret_text(row["session_key"])

        kientuong_ok = bool(kientuong_api.get("ok") or probe_player.get("ok"))
        errors: list[str] = []
        if not account_auth.get("ok"):
            errors.append(str(account_auth.get("error") or "sso_login_failed"))
        if not kientuong_ok:
            errors.append(str(kientuong_api.get("error") or "kientuong_failed"))
        if tcp_info.get("error"):
            errors.append(str(tcp_info.get("error")))
        row["error"] = "; ".join(dict.fromkeys(e for e in errors if e and e != "None"))[:300]
        succeeded = bool(
            account_auth.get("ok") or kientuong_ok or tcp_info.get("ok")
        )
        row["status"] = "OK" if succeeded else "FAIL"
    row["elapsed_ms"] = str(round((time.monotonic() - started) * 1000))
    credential.password = ""
    return row


def run_batch_core(
    credentials: list[Any],
    tcp_module: Any,
    workers: int,
    gap: float,
    timeout: float,
    *,
    stop_event: threading.Event | None = None,
    on_result: Any = None,
) -> list[dict[str, str]]:
    import garena_tcp_rate_limit_probe as batch_helpers

    gate = batch_helpers.StartGate(max(0.0, gap))
    if stop_event is None:
        stop_event = threading.Event()
    rows: list[dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, int(workers)), thread_name_prefix="sso-batch") as executor:
        futures = [
            executor.submit(batch_check_one, credential, tcp_module, timeout, gate, stop_event)
            for credential in credentials
        ]
        for future in as_completed(futures):
            row = future.result()
            rows.append(row)
            if on_result is not None:
                on_result(row)
    return rows


def _batch_worker(
    server: ApiTestServer,
    credentials: list[BatchAccount],
    workers: int,
    gap: float,
) -> None:
    def on_result(row: dict[str, str]) -> None:
        with server.batch_lock:
            server.batch_rows.append(row)

    try:
        run_batch_core(
            credentials,
            server.tcp_module,
            workers,
            gap,
            server.tcp_timeout,
            stop_event=server.batch_stopped,
            on_result=on_result,
        )
    except Exception:
        traceback.print_exc()
        with server.batch_lock:
            server.batch_rows.append({
                "stt": "-", "account": "-", "status": "FAIL", "uid": "", "name": "",
                "level": "", "session_key": "", "elapsed_ms": "",
                "error": "lỗi batch không mong muốn, xem console",
            })
    finally:
        for credential in credentials:
            credential.password = ""
        server.batch_running = False


def run_batch(args: argparse.Namespace) -> int:
    import garena_tcp_rate_limit_probe as batch_helpers

    credentials = batch_helpers.load_credentials(args.file.resolve(), limit=999999999999)
    tcp_module = tcp_ui.load_verified_tcp_module()

    print(
        f"Batch SSO: {len(credentials)} tài khoản | workers={args.workers} | "
        f"start_gap={max(0.0, args.start_gap):g}s | timeout={args.timeout:g}s"
    )
    print(
        "STT|ACCOUNT|STATUS|UID|EMAIL|PHONE|COUNTRY|NAME|LEVEL|KT_STATUS|SESSION_KEY|ELAPSED_MS|ERROR"
    )

    def on_result(row: dict[str, str]) -> None:
        def pipe_safe(key: str) -> str:
            return row[key].replace("|", "/").replace("\r", " ").replace("\n", " ")

        print(
            f"{row['stt']}|{row['account']}|{row['status']}|{row['uid']}|"
            f"{pipe_safe('email')}|{pipe_safe('phone')}|{pipe_safe('country')}|"
            f"{pipe_safe('name')}|{row['level']}|{row['kt_status']}|"
            f"{row['session_key']}|{row['elapsed_ms']}|{pipe_safe('error')}",
            flush=True,
        )

    rows = run_batch_core(
        credentials, tcp_module, args.workers, args.start_gap, args.timeout,
        on_result=on_result,
    )

    ok_count = sum(1 for row in rows if row["status"] == "OK")
    print(
        f"SUMMARY|total={len(credentials)}|done={len(rows)}"
        f"|ok={ok_count}|fail={len(rows) - ok_count}"
    )

    if args.csv:
        fieldnames = [
            "stt", "account", "status", "uid", "email", "email_status",
            "phone", "country", "twofa", "auth", "id_docs", "lqm_login",
            "name", "level", "kt_status", "session_key", "elapsed_ms", "error",
        ]
        with args.csv.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sorted(rows, key=lambda item: int(item["stt"])))
        print(f"Đã ghi kết quả: {args.csv}")
    return 0 if len(rows) == len(credentials) else 1


PAGE_TEMPLATE = r'''<!doctype html>
<html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kiểm tra tài khoản Garena + Kiện Tướng</title><style>
:root{color-scheme:dark;font-family:Segoe UI,system-ui,sans-serif}body{margin:0;background:#0d1117;color:#e6edf3}
main{width:min(1100px,calc(100vw - 32px));margin:28px auto;display:grid;gap:22px}
.card{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:22px}
h1{margin:0 0 8px;font-size:20px}h2{margin:0 0 10px;font-size:16px;color:#58a6ff}
p,small,label{color:#9da7b3;line-height:1.5}
input,textarea{box-sizing:border-box;width:100%;padding:11px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;outline:none}
input:focus,textarea:focus{border-color:#2f81f7}
textarea{min-height:140px;resize:vertical;font-family:Consolas,monospace}
button{margin-top:12px;padding:11px 18px;border:0;border-radius:8px;background:#238636;color:#fff;font-weight:750;cursor:pointer}
button:disabled{opacity:.5;cursor:not-allowed}
button.warnb{background:#9e6a03}button.ghost{background:#30363d}
.btnfile{display:inline-block;margin-top:12px;padding:11px 18px;border-radius:8px;background:#30363d;color:#fff;font-weight:750;cursor:pointer}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-top:12px}.row>div{flex:1;min-width:140px}
#batchStatus{font-weight:650;margin-top:10px}#batchStatus.bad,#result.bad{color:#ff7b72}#result.ok{color:#56d364}
.wrap{max-height:430px;overflow:auto;border:1px solid #21262d;border-radius:8px;margin-top:10px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{border-bottom:1px solid #21262d;padding:6px 8px;text-align:left;word-break:break-all;vertical-align:top}
th{color:#8b949e;position:sticky;top:0;background:#161b22}
tr.ok td:nth-child(3){color:#56d364}tr.fail td:nth-child(3){color:#ff7b72}
#out{white-space:pre-wrap;overflow-wrap:anywhere;background:#010409;border:1px solid #30363d;border-radius:8px;padding:14px;min-height:60px;margin-top:14px}
</style></head><body><main>

<div class="card">
<h2>Kiểm tra hàng loạt (SSO web)</h2>
<p>Dán danh sách <code>user|pass</code> hoặc <code>user:pass</code>, mỗi dòng một tài khoản. Dòng trống hoặc bắt đầu bằng <code>#</code> bị bỏ qua.</p>
<textarea id="batchAccounts" placeholder="user1|pass1&#10;user2|pass2&#10;user3:pass3"></textarea>
<div class="row">
<div><label>Số luồng (1–8)</label><input id="batchWorkers" type="number" min="1" max="8" value="2"></div>
<div><label>Gap giữa 2 lần đăng nhập (giây, 0–60)</label><input id="batchGap" type="number" min="0" max="60" step="0.5" value="3"></div>
</div>
<button id="batchStart" type="button">Chạy batch</button>
<button id="batchStop" type="button" class="warnb">Dừng</button>
<button id="batchExport" type="button" class="ghost">Xuất CSV</button>
<label class="btnfile">Nhập file<input id="batchImport" type="file" accept=".txt,.csv,text/plain" hidden></label>
<div id="batchStatus">Chưa chạy.</div>
<div class="wrap"><table><thead><tr><th>STT</th><th>Tài khoản</th><th>Trạng thái</th><th>UID</th><th>Email</th><th>Xác thực email</th><th>SĐT</th><th>Quốc gia</th><th>2FA</th><th>Authenticator</th><th>Giấy tờ</th><th>LQM gần nhất</th><th>Tên KT</th><th>Cấp</th><th>Trạng thái KT</th><th>Session Key</th><th>ms</th><th>Lỗi</th></tr></thead>
<tbody id="batchBody"></tbody></table></div>
<small>Kết quả hiển thị trực tiếp khi từng tài khoản xong. Session Key trong bảng chỉ hiện rút gọn (8 ký tự đầu + 4 cuối); file CSV xuất đầy đủ. "Nhập file" nạp list từ .txt/.csv.</small>
</div>

<div class="card">
<h2>Kiểm tra lẻ</h2>
<form id="f" autocomplete="off"><input id="credential" type="password" maxlength="1200" autocomplete="off" placeholder="user|pass" required>
<button id="b" type="submit">Chạy kiểm tra API</button></form>
<pre id="out">Chưa thực hiện.</pre>
<small class="warn">Không vượt CAPTCHA/2FA. Email được hiển thị theo yêu cầu; SĐT, giấy tờ vẫn được che. Session Key SSO hiển thị khi đăng nhập thành công. Chỉ chạy tại 127.0.0.1.</small>
</div>

</main>
<script>
const token=__TOKEN__;
const $=id=>document.getElementById(id);
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function postJson(url,body){try{const r=await fetch(url,{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json','X-API-Test-Token':token},body:JSON.stringify(body)});return await r.json();}catch(e){return{ok:false,error:'Lỗi localhost: '+e}}}
async function getState(){const r=await fetch('/api/batch/state',{cache:'no-store',credentials:'same-origin',headers:{'X-API-Test-Token':token}});return r.json();}
let pollTimer=null,rendered=0,lastRows=[];
function setStatus(t,bad){const el=$('batchStatus');el.textContent=t;el.className=bad?'bad':'';}
function renderRows(rows){const tb=$('batchBody');for(let i=rendered;i<rows.length;i++){const r=rows[i],tr=document.createElement('tr');tr.className=r.status==='OK'?'ok':'fail';tr.innerHTML='<td>'+[r.stt,r.account,r.status,r.uid,r.email,r.email_status,r.phone,r.country,r.twofa,r.auth,r.id_docs,r.lqm_login,r.name,r.level,r.kt_status,r.session_key_masked,r.elapsed_ms,r.error].map(esc).join('</td><td>')+'</td>';tb.appendChild(tr);}rendered=rows.length;lastRows=rows;}
async function poll(){try{const s=await getState();if(!s||!s.ok)return;renderRows(s.rows);const done=s.rows.length;setStatus(s.running?('Đang chạy: '+done+'/'+s.total+'...'):('Xong: '+done+'/'+s.total+(s.stopped?' (đã dừng sớm)':'')),false);if(!s.running&&pollTimer){clearInterval(pollTimer);pollTimer=null;$('batchStart').disabled=false;}}catch(e){}}
$('batchStart').addEventListener('click',async()=>{
 const res=await postJson('/api/batch/start',{accounts:$('batchAccounts').value,workers:parseInt($('batchWorkers').value,10)||2,gap:parseFloat($('batchGap').value)||0});
 if(!res.ok){setStatus(res.error||'Không bắt đầu được',true);return;}
 $('batchBody').innerHTML='';rendered=0;lastRows=[];$('batchStart').disabled=true;setStatus('Đang chạy...',false);
 if(pollTimer)clearInterval(pollTimer);pollTimer=setInterval(poll,900);poll();});
$('batchStop').addEventListener('click',()=>{postJson('/api/batch/stop',{});setStatus('Đang dừng sau các acc đang xử lý...',false);});
$('batchImport').addEventListener('change',ev=>{const f=ev.target.files&&ev.target.files[0];if(!f)return;const rd=new FileReader();rd.onload=()=>{$('batchAccounts').value=String(rd.result||'');setStatus('Đã nạp file: '+f.name,false);};rd.readAsText(f,'utf-8');ev.target.value='';});
$('batchExport').addEventListener('click',()=>{
 if(!lastRows.length){setStatus('Chưa có kết quả để xuất',true);return;}
 const cols=['stt','account','status','uid','email','email_status','phone','country','twofa','auth','id_docs','lqm_login','name','level','kt_status','session_key','elapsed_ms','error'];
 const q=v=>{v=String(v==null?'':v);return /[",\n\r]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
 const csv='\ufeff'+cols.join(',')+'\n'+lastRows.map(r=>cols.map(c=>q(r[c])).join(',')).join('\r\n');
 const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));a.download='ketqua_batch.csv';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),2000);});
$('f').addEventListener('submit',async ev=>{ev.preventDefault();const b=$('b'),out=$('out'),input=$('credential');
 b.disabled=true;out.className='';out.textContent='Đang kiểm tra tài khoản Garena và hồ sơ Kiện Tướng...';
 const data=await postJson('/api/test',{credential:input.value});
 out.className=data.ok?'ok':'bad';out.textContent=data.display||data.error||'Không có kết quả';
 input.value='';b.disabled=false;});
(async function resume(){try{const s=await getState();if(!s||!s.ok)return;if(s.running||s.rows.length){renderRows(s.rows);setStatus(s.running?('Đang chạy: '+s.rows.length+'/'+s.total+'...'):('Lần trước: '+s.rows.length+'/'+s.total+(s.stopped?' (đã dừng sớm)':'')),false);$('batchStart').disabled=!!s.running;if(s.running&&!pollTimer)pollTimer=setInterval(poll,900);}}catch(e){}})();
</script></body></html>'''


def page_html(csrf_token: str) -> bytes:
    token_js = json.dumps(csrf_token)
    return PAGE_TEMPLATE.replace("__TOKEN__", token_js).encode("utf-8")


class ApiTestServer(tcp_ui.LoginTestServer):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.batch_lock = threading.Lock()
        self.batch_running = False
        self.batch_stopped = threading.Event()
        self.batch_total = 0
        self.batch_rows: list[dict[str, str]] = []


class Handler(BaseHTTPRequestHandler):
    server: ApiTestServer

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none';style-src 'unsafe-inline';script-src 'unsafe-inline';connect-src 'self';frame-ancestors 'none';form-action 'self'")

    def send_json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status);self.security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)));self.end_headers();self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT);self.end_headers();return
        if self.path == "/api/batch/state":
            if self.headers.get("X-API-Test-Token", "") != self.server.csrf_token:
                self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "CSRF token không hợp lệ"});return
            with self.server.batch_lock:
                payload = {
                    "ok": True,
                    "running": self.server.batch_running,
                    "stopped": self.server.batch_stopped.is_set(),
                    "total": self.server.batch_total,
                    "rows": [dict(row) for row in self.server.batch_rows],
                }
            self.send_json(HTTPStatus.OK, payload);return
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND);return
        body = page_html(self.server.csrf_token)
        self.send_response(HTTPStatus.OK);self.security_headers("text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)));self.end_headers();self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path == "/api/batch/start":
            if self.headers.get("X-API-Test-Token", "") != self.server.csrf_token:
                self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "CSRF token không hợp lệ"});return
            try:length=int(self.headers.get("Content-Length", "0"))
            except ValueError:length=0
            if length <= 0 or length > MAX_BATCH_BODY:
                if length>0:
                    try:
                        rem=length
                        while rem>0:
                            chunk=self.rfile.read(min(rem, 64*1024))
                            if not chunk: break
                            rem-=len(chunk)
                    except: pass
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Kích thước request không hợp lệ"});return
            try:
                body=json.loads(self.rfile.read(length).decode("utf-8"))
                accounts_text=str(body.get("accounts", ""))
                workers=int(body.get("workers", 2))
                gap=float(body.get("gap", 3.0))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "JSON không hợp lệ"});return
            if not 1 <= workers <= 8:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Số luồng phải trong khoảng 1..8"});return
            if not 0 <= gap <= 60:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Gap phải trong khoảng 0..60 giây"});return
            try:
                credentials = parse_credentials_text(accounts_text)
            except ValueError as exc:
                self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)});return
            with self.server.batch_lock:
                if self.server.batch_running:
                    self.send_json(HTTPStatus.CONFLICT, {"ok": False, "error": "Đang có batch chạy; hãy Dừng hoặc chờ xong"});return
                self.server.batch_rows = []
                self.server.batch_total = len(credentials)
                self.server.batch_stopped.clear()
                self.server.batch_running = True
            threading.Thread(
                target=_batch_worker,
                args=(self.server, credentials, workers, gap),
                daemon=True,
                name="sso-batch-runner",
            ).start()
            self.send_json(HTTPStatus.OK, {"ok": True, "total": len(credentials)});return

        if self.path == "/api/batch/stop":
            if self.headers.get("X-API-Test-Token", "") != self.server.csrf_token:
                self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "CSRF token không hợp lệ"});return
            self.server.batch_stopped.set()
            self.send_json(HTTPStatus.OK, {"ok": True});return

        if self.path != "/api/test":
            self.send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Endpoint không tồn tại"});return
        if self.headers.get("X-API-Test-Token", "") != self.server.csrf_token:
            self.send_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "CSRF token không hợp lệ"});return
        try:length=int(self.headers.get("Content-Length", "0"))
        except ValueError:length=0
        if length <= 0 or length > MAX_BODY:
            if length>0:
                try:
                    rem=length
                    while rem>0:
                        chunk=self.rfile.read(min(rem, 64*1024))
                        if not chunk: break
                        rem-=len(chunk)
                except: pass
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Kích thước request không hợp lệ"});return
        try:
            body=json.loads(self.rfile.read(length).decode("utf-8"));credential=str(body.get("credential", ""))
            account,password=credential.split("|",1);account=account.strip()
        except (UnicodeDecodeError,json.JSONDecodeError,AttributeError,ValueError):
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Nhập đúng định dạng user|pass"});return
        if not account or not password or len(account)>128 or len(password)>1024:
            self.send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Tài khoản/mật khẩu trống hoặc quá dài"});return
        if not TEST_LOCK.acquire(blocking=False):
            self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"ok": False, "error": "Đang có lần kiểm tra khác"});return
        try:
            result=run_api_tests(self.server.tcp_module,account,password,self.server.tcp_timeout)
            self.send_json(HTTPStatus.OK, {"ok": True, "display": format_user_output(result)})
        except Exception as exc:
            self.send_json(HTTPStatus.OK, {"ok": False, "error": (str(exc).strip() or type(exc).__name__)[:500]})
        finally:
            credential=account=password="";TEST_LOCK.release()


def parse_args() -> argparse.Namespace:
    parser=argparse.ArgumentParser(description="Kiểm tra tài khoản Garena và hồ sơ Kiện Tướng")
    parser.add_argument("--port",type=int,default=8766,help="Cổng localhost (mặc định: 8766)")
    parser.add_argument("--timeout",type=float,default=20.0,help="Timeout mỗi request, 1..60 giây")
    parser.add_argument("--no-browser",action="store_true",help="Không tự mở Chrome")
    parser.add_argument("--self-test",action="store_true",help="Kiểm tra source/hash, không đăng nhập")
    parser.add_argument(
        "--sso-diagnostics",
        action="store_true",
        help="Check SSO DNS/TCP/TLS/HTTP without sending credentials or tokens",
    )
    parser.add_argument("--file",type=Path,default=None,help="Chạy batch: file UTF-8 dạng user|pass hoặc user:pass, mỗi dòng một tài khoản")
    parser.add_argument("--workers",type=int,default=2,help="Số luồng song song khi batch, 1..8 (mặc định 2)")
    parser.add_argument("--start-gap",type=float,default=3.0,help="Giãn cách tối thiểu giữa hai lần bắt đầu đăng nhập SSO, giây (mặc định 3)")
    parser.add_argument("--csv",type=Path,default=None,help="Ghi kết quả batch ra file CSV này (mã hóa utf-8-sig)")
    return parser.parse_args()


def main() -> int:
    tcp_ui.configure_console_encoding();args=parse_args()
    if args.file:
        if not 1<=args.workers<=8:raise SystemExit("--workers phải trong khoảng 1..8")
        if not 0<=args.start_gap<=60:raise SystemExit("--start-gap phải trong khoảng 0..60 giây")
        return run_batch(args)
    if not 1024<=args.port<=65535:raise SystemExit("Port phải trong khoảng 1024..65535")
    if not 1.0<=args.timeout<=60.0:raise SystemExit("Timeout phải trong khoảng 1..60 giây")
    if args.sso_diagnostics:
        result = public_sso_diagnostics(args.timeout)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        if not args.no_browser:
            tcp_ui.open_chrome_or_default(SSO_LOGIN_URL)
        return 0 if result.get("ok") else 1
    tcp_module=tcp_ui.load_verified_tcp_module()
    if args.self_test:
        expected = "b0494ef53b7b15eebbefd763d56dbf5f"
        actual = garena_web_password("test-password", "v1-example", "v2-example")
        if actual != expected:
            raise SystemExit("SELF-TEST FAIL: Garena web password transform")
        if redact_tree({"code": "secret"})["code"] == "secret":
            raise SystemExit("SELF-TEST FAIL: OAuth code redaction")
        print("SELF-TEST OK: TCP module và localhost handler đã nạp.");return 0
    csrf=secrets.token_urlsafe(32);server=ApiTestServer(("127.0.0.1",args.port),Handler,tcp_module,csrf,args.timeout)
    url=f"http://127.0.0.1:{server.server_port}/";print(f"Kiểm tra Garena + Kiện Tướng: {url}");print("Ctrl+C để dừng; credential/token không được ghi log.")
    if not args.no_browser:threading.Timer(.25,tcp_ui.open_chrome_or_default,args=(url,)).start()
    try:server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:print("\nĐã dừng server test.")
    finally:server.server_close()
    return 0


if __name__=="__main__":raise SystemExit(main())
