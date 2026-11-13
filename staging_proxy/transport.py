"""Explicit, fail-closed transport for the local staging lab."""
from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit
import uuid


class RoutingError(Exception):
    def __init__(self, category, status=None):
        self.category, self.status = category, status
        super().__init__(category + (f" ({status})" if status else ""))


def loopback(host):
    # Numeric literals only: no DNS, DNS rebinding, or external destinations.
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError
    except ValueError:
        raise RoutingError("staging_destination_denied") from None
    return host


@dataclass(frozen=True)
class ProxyConfig:
    host: str
    port: int
    protocol: str = "http"
    enabled: bool = True
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    timeout: float = 1.0
    retries: int = 1

    def __post_init__(self):
        loopback(self.host)
        if (type(self.port) is not int or not 0 < self.port < 65536
                or self.protocol not in {"http", "https", "socks5"}
                or type(self.enabled) is not bool
                or not 0.02 <= self.timeout <= 30
                or type(self.retries) is not int or not 0 <= self.retries <= 3):
            raise RoutingError("invalid_proxy_config")
        if self.protocol == "socks5":
            try:
                import socks  # noqa: F401
            except ImportError:
                raise RoutingError("socks5_unavailable") from None


class Audit:
    def __init__(self):
        self.lock = threading.Lock()
        self.events = []

    def add(self, **event):
        # Callers supply IDs/status only, never URL, body, headers, credentials.
        with self.lock:
            self.events.append(event)

    def snapshot(self):
        with self.lock:
            return list(self.events)


class ProxyManager:
    def __init__(self, audit=None, tls_context=None):
        self.audit = audit or Audit()
        self.tls_context = tls_context or ssl.create_default_context()
        self._lock = threading.Lock()
        self.states = {}

    def request(self, config, url, payload=None, *, headers=None, identity=None):
        if not config.enabled:
            raise RoutingError("proxy_disabled")
        target = urlsplit(url)
        loopback(target.hostname)
        if (target.scheme != "http" or target.username or target.password
                or target.fragment or not target.port):
            raise RoutingError("staging_destination_denied")
        data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
        for attempt in range(config.retries + 1):
            request_id = uuid.uuid4().hex
            tags = {k: str((identity or {}).get(k, "")) for k in ("task", "worker", "satellite")}
            metadata = dict(request_id=request_id, attempt=attempt, **tags)
            request_headers = dict(headers or {})
            request_headers.update({"Content-Type": "application/json", "Connection": "close",
                                    "X-Staging-Request": request_id,
                                    **{f"X-Staging-{k}": v for k, v in tags.items()}})
            connection = None
            self.audit.add(event="attempt", **metadata)
            try:
                if config.protocol == "https":
                    connection = http.client.HTTPSConnection(config.host, config.port,
                        timeout=config.timeout, context=self.tls_context)
                else:
                    connection = http.client.HTTPConnection(config.host, config.port, timeout=config.timeout)
                path = url
                if config.protocol == "socks5":
                    import socks
                    sock = socks.socksocket()
                    connection.sock = sock
                    sock.set_proxy(socks.SOCKS5, config.host, config.port, rdns=False,
                                   username=config.username or None, password=config.password or None)
                    sock.settimeout(config.timeout)
                    sock.connect((target.hostname, target.port))
                    path = target.path or "/"
                    if target.query:
                        path += "?" + target.query
                elif config.username or config.password:
                    basic = base64.b64encode(f"{config.username}:{config.password}".encode()).decode()
                    request_headers["Proxy-Authorization"] = "Basic " + basic
                connection.request("POST" if payload is not None else "GET", path, data, request_headers)
                response = connection.getresponse()
                raw = response.read(1024 * 1024 + 1)
                if response.status == 407:
                    raise RoutingError("proxy_auth", 407)
                if response.getheader("X-Staging-Proxy-Error") == "1":
                    raise RoutingError("proxy_response", response.status)
                if not 200 <= response.status < 300:
                    raise RoutingError("service_response", response.status)
                if len(raw) > 1024 * 1024:
                    raise RoutingError("service_invalid_response")
                try:
                    result = json.loads(raw)
                except (ValueError, UnicodeError):
                    raise RoutingError("service_invalid_response") from None
                self.audit.add(event="success", **metadata)
                with self._lock:
                    self.states[(config.host, config.port)] = "ready"
                return result
            except RoutingError as exc:
                error = exc
            except (socket.timeout, TimeoutError):
                error = RoutingError("proxy_timeout")
            except ssl.SSLError:
                error = RoutingError("proxy_tls")
            except (OSError, http.client.HTTPException):
                error = RoutingError("proxy_connection")
            finally:
                if connection is not None:
                    connection.close()
            self.audit.add(event="error", category=error.category, **metadata)
            with self._lock:
                self.states[(config.host, config.port)] = error.category
            transient = error.category in {"proxy_timeout", "proxy_connection"}
            if not transient or attempt == config.retries:
                raise error from None
            time.sleep(0.02 * (attempt + 1))

    def check(self, config, health_url, **kwargs):
        """Protocol + proxy authentication + upstream health, using the same route."""
        return self.request(config, health_url, **kwargs)

    @staticmethod
    def serialize(config):
        return asdict(config)
