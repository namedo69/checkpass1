"""Instrumented loopback HTTP proxy and synthetic authentication server."""
from __future__ import annotations

import base64
from contextlib import closing, contextmanager
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import socketserver
import threading
import time
from urllib.parse import urlsplit

from .transport import Audit, loopback


def proof(secret, request_id, path, body):
    return hmac.new(secret, request_id.encode() + path.encode() + body, hashlib.sha256).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, value, headers=None):
        raw = json.dumps(value).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for key, val in (headers or {}).items():
                self.send_header(key, val)
            self.end_headers()
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 <= length <= 1024 * 1024:
            raise ValueError("body_limit")
        return self.rfile.read(length)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


@contextmanager
def serve(handler, port=0):
    server = Server(("127.0.0.1", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server.url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class MockProxy:
    def __init__(self, username="", password="", audit=None):
        self.username, self.password = username, password
        self.audit = audit or Audit()
        self.secret = secrets.token_bytes(32)
        self.allowed = set()
        self.mode = "ok"
        self.delay = 0.2
        self.failures_left = 0
        self.lock = threading.Lock()

    def handler(self):
        proxy = self

        class ProxyHandler(Handler):
            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                rid = self.headers.get("X-Staging-Request", "")
                tags = {k: self.headers.get(f"X-Staging-{k}", "") for k in ("task", "worker", "satellite")}
                proxy.audit.add(event="received", request_id=rid, **tags)
                expected = "Basic " + base64.b64encode(f"{proxy.username}:{proxy.password}".encode()).decode()
                if (proxy.username or proxy.password) and not hmac.compare_digest(
                        self.headers.get("Proxy-Authorization", ""), expected):
                    self.reply(407, {"error": "proxy_auth"})
                    return
                with proxy.lock:
                    mode = proxy.mode
                    if proxy.failures_left:
                        proxy.failures_left -= 1
                        mode = "disconnect"
                if mode == "disconnect":
                    self.close_connection = True
                    return
                if mode == "timeout":
                    time.sleep(proxy.delay)
                    # Never forward a timed-out mock request later.
                    self.close_connection = True
                    return
                if mode == "error":
                    self.reply(502, {"error": "proxy_response"}, {"X-Staging-Proxy-Error": "1"})
                    return
                target = urlsplit(self.path)
                try:
                    loopback(target.hostname)
                    if target.scheme != "http" or (target.hostname, target.port) not in proxy.allowed:
                        raise ValueError
                    body = self.body()
                    path = target.path or "/"
                    if target.query:
                        path += "?" + target.query
                    headers = {k: v for k, v in self.headers.items()
                               if k.lower() not in {"proxy-authorization", "host", "connection", "x-staging-proof"}}
                    headers["X-Staging-Proof"] = proof(proxy.secret, rid, path, body)
                    with closing(http.client.HTTPConnection(target.hostname, target.port, timeout=1)) as conn:
                        conn.request(self.command, path, body, headers)
                        res = conn.getresponse()
                        raw = res.read(1024 * 1024)
                        proxy.audit.add(event="forwarded", request_id=rid, **tags)
                        self.reply(res.status, json.loads(raw))
                except Exception:
                    self.reply(502, {"error": "proxy_upstream"}, {"X-Staging-Proxy-Error": "1"})

        return ProxyHandler


class MockAuth:
    def __init__(self, proxy_secrets, audit=None):
        self.proxy_secrets = proxy_secrets
        self.audit = audit or Audit()
        self.mode = "ok"
        self.after_auth = None

    def handler(self):
        auth = self

        class AuthHandler(Handler):
            def do_GET(self):
                self.do_POST()

            def do_POST(self):
                body = self.body()
                rid = self.headers.get("X-Staging-Request", "")
                supplied = self.headers.get("X-Staging-Proof", "")
                verified = any(hmac.compare_digest(supplied, proof(key, rid, self.path, body))
                               for key in auth.proxy_secrets)
                tags = {k: self.headers.get(f"X-Staging-{k}", "") for k in ("task", "worker", "satellite")}
                auth.audit.add(event="received", request_id=rid, via_proxy=verified, **tags)
                if not verified:
                    self.reply(403, {"error": "direct_denied"})
                elif auth.mode == "error":
                    self.reply(503, {"error": "mock_unavailable"})
                elif self.path == "/health":
                    self.reply(200, {"ok": True})
                elif self.path in {"/authenticate", "/profile"}:
                    item = json.loads(body)
                    if not str(item.get("synthetic_id", "")).startswith("fixture-"):
                        self.reply(400, {"error": "synthetic_only"})
                        return
                    if self.path == "/authenticate" and auth.after_auth:
                        auth.after_auth()
                    self.reply(200, {"ok": True, "synthetic": True})
                else:
                    self.reply(404, {"error": "unknown_endpoint"})

        return AuthHandler


@contextmanager
def serve_socks(proxy, username, password):
    """Minimal RFC1928/1929 mock gateway, loopback/allowlist only."""
    base = proxy.handler()

    class SocksHandler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            sock.settimeout(2)

            def exact(size):
                result = b""
                while len(result) < size:
                    chunk = sock.recv(size - len(result))
                    if not chunk:
                        raise OSError("closed")
                    result += chunk
                return result

            try:
                version, count = exact(2)
                methods = exact(count)
                if version != 5 or 2 not in methods:
                    sock.sendall(b"\x05\xff")
                    return
                sock.sendall(b"\x05\x02")
                version, size = exact(2)
                user = exact(size).decode()
                size = exact(1)[0]
                secret = exact(size).decode()
                valid = version == 1 and hmac.compare_digest(user, username) and hmac.compare_digest(secret, password)
                sock.sendall(b"\x01\x00" if valid else b"\x01\x01")
                if not valid:
                    return
                version, command, reserved, kind = exact(4)
                if version != 5 or command != 1 or kind != 1:
                    return
                host = ".".join(str(b) for b in exact(4))
                port = int.from_bytes(exact(2), "big")
                if (host, port) not in proxy.allowed:
                    sock.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
                    return
                sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + port.to_bytes(2, "big"))

                class OriginHandler(base):
                    def forward(self):
                        self.path = f"http://{host}:{port}" + self.path
                        super().forward()

                OriginHandler(sock, self.client_address, self.server)
            except (OSError, ValueError):
                pass

    class SocksServer(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = SocksServer(("127.0.0.1", 0), SocksHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
