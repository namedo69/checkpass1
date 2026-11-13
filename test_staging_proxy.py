"""All network tests use loopback, generated tokens, and synthetic fixtures."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

from staging_proxy.cluster import Master, Store
from staging_proxy.lab import Lab
from staging_proxy.transport import ProxyConfig, RoutingError


class ConfigTests(unittest.TestCase):
    def test_reject_external_and_invalid(self):
        for host in ("example.com", "8.8.8.8", "localhost", "127.0.0.1.example.com"):
            with self.assertRaises(RoutingError):
                ProxyConfig(host, 8080)
        for changes in ({"port": 0}, {"protocol": "ftp"}, {"retries": 99}, {"timeout": 0}):
            with self.assertRaises(RoutingError):
                ProxyConfig(**dict({"host": "127.0.0.1", "port": 8080}, **changes))

    def test_credentials_not_in_repr(self):
        config = ProxyConfig("127.0.0.1", 8080, username="secret-user", password="secret-password")
        self.assertNotIn("secret", repr(config))


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.lab = Lab(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.lab.close)

    def call(self, config=None):
        return self.lab.manager.check(config or self.lab.config, self.lab.auth_server.url + "/health",
                                      identity={"task": "probe", "worker": "one", "satellite": "sat-1"})

    def assert_evidence(self, equality=True):
        ev = self.lab.evidence()
        self.assertEqual(ev["direct_requests"], 0)
        self.assertEqual(ev["auth_without_proxy_receipt"], 0)
        self.assertEqual(ev["successful_without_forward"], 0)
        if equality:
            self.assertEqual(ev["total_outbound_attempts"], ev["requests_through_proxy"])
        return ev

    def error(self, category, config=None):
        with self.assertRaises(RoutingError) as caught:
            self.call(config)
        self.assertEqual(caught.exception.category, category)
        self.assertNotIn(self.lab.config.password, str(caught.exception))

    def test_one_worker_and_authentication(self):
        self.lab.store.add("one")
        self.lab.master.check()
        self.assertEqual(self.lab.satellite().run(1), ["done"])
        ev = self.assert_evidence()
        self.assertEqual(ev["auth_requests"], 4)  # master health + 3 dependent requests

    def test_concurrent_satellites_and_service_routes(self):
        self.lab.store.configure("vvip", self.lab.config2)
        for i in range(24):
            self.lab.store.add(f"task-{i:02}", "normal" if i % 2 else "vvip")
        sats = [self.lab.satellite(name) for name in self.lab.tokens]
        claims = [sat.rpc("/claim", {}) for sat in sats]
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda pair: pair[0].process(pair[1], "initial"), zip(sats, claims)))
            list(pool.map(lambda sat: sat.run(4), sats))
        ev = self.assert_evidence()
        self.assertTrue(all(r["state"] == "done" for r in ev["tasks"]))
        self.assertEqual(ev["auth_requests"], 72)
        self.assertGreater(ev["satellites"]["sat-1"], 0)
        self.assertGreater(ev["satellites"]["sat-2"], 0)
        self.assertGreater(len(ev["workers"]), 2)
        second = {e["task"] for e in self.lab.proxy2.audit.snapshot() if e["event"] == "forwarded"}
        self.assertEqual(second, {f"task-{i:02}" for i in range(0, 24, 2)})

    def test_wrong_proxy_auth(self):
        self.error("proxy_auth", replace(self.lab.config, password="invalid"))
        self.assertEqual(len(self.lab.audit.snapshot()), 2)  # no authentication retries
        self.assertEqual(self.assert_evidence()["auth_requests"], 0)

    def test_disconnect_never_falls_back(self):
        self.lab.proxy.mode = "disconnect"
        self.error("proxy_connection")
        ev = self.assert_evidence()
        self.assertEqual(ev["total_outbound_attempts"], 2)
        self.assertEqual(ev["auth_requests"], 0)

    def test_unreachable_proxy(self):
        # Closed listener: the endpoint has no accepting proxy.
        import socket
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        with self.assertRaises(RoutingError) as caught:
            self.call(replace(self.lab.config, port=port, timeout=0.04))
        self.assertIn(caught.exception.category, {"proxy_connection", "proxy_timeout"})
        ev = self.assert_evidence(equality=False)
        self.assertEqual(ev["requests_through_proxy"], 0)
        self.assertEqual(ev["auth_requests"], 0)
        self.assertEqual(ev["total_outbound_attempts"], 2)

    def test_timeout(self):
        self.lab.proxy.mode = "timeout"
        self.error("proxy_timeout", replace(self.lab.config, timeout=0.04))
        self.assertEqual(self.assert_evidence()["auth_requests"], 0)

    def test_proxy_response_error(self):
        self.lab.proxy.mode = "error"
        self.error("proxy_response")
        self.assertEqual(self.assert_evidence()["total_outbound_attempts"], 1)

    def test_service_error_is_distinct(self):
        self.lab.auth.mode = "error"
        self.error("service_response")
        self.assertEqual(self.assert_evidence()["auth_requests"], 1)

    def test_transient_retry_keeps_route(self):
        self.lab.proxy.failures_left = 1
        self.assertTrue(self.call()["ok"])
        ev = self.assert_evidence()
        self.assertEqual(ev["total_outbound_attempts"], 2)
        self.assertEqual(ev["auth_requests"], 1)

    def test_disable_mid_task_then_recover(self):
        self.lab.store.add("disable")
        self.lab.auth.after_auth = lambda: self.lab.store.configure("shared", replace(self.lab.config, enabled=False))
        self.assertEqual(self.lab.satellite().run(1), ["connection_error"])
        self.assertEqual(self.lab.store.rows()[0]["error"], "proxy_disabled")
        self.assertEqual(self.assert_evidence()["auth_requests"], 2)  # profile not sent
        self.lab.auth.after_auth = None
        self.lab.store.configure("shared", self.lab.config2)
        self.lab.store.recover()
        self.assertEqual(self.lab.satellite().run(1), ["done"])
        self.assert_evidence()

    def test_control_proxy_outage_preserves_lease_and_recovers(self):
        self.lab.store.add("control-outage")
        self.lab.auth.after_auth = lambda: setattr(self.lab.proxy, "mode", "disconnect")
        self.assertEqual(self.lab.satellite().run(1), ["connection_error"])
        self.assertEqual(self.lab.store.rows()[0]["state"], "running")
        self.lab.proxy.mode = "ok"
        self.lab.auth.after_auth = None
        with self.lab.store.connect() as db:
            db.execute("UPDATE tasks SET lease=0")
        self.assertEqual(self.lab.satellite("sat-2").run(1), ["done"])
        self.assert_evidence()

    def test_master_restart_persists_config_and_tasks(self):
        self.lab.store.add("restart")
        reopened = Store(self.lab.store.path, self.lab.key)
        master = Master(reopened, self.lab.tokens, self.lab.grant_key, self.lab.manager,
                        self.lab.config, self.lab.auth_server.url)
        # Restart HTTP server on the same address and re-open SQLite.
        from staging_proxy.mocks import serve
        old = self.lab.master_server
        port = old.server_port
        old.shutdown()
        old.server_close()
        restarted = self.lab.stack.enter_context(serve(master.handler(), port))
        self.assertEqual(restarted.url, old.url)
        self.assertEqual(self.lab.satellite().run(1), ["done"])
        self.assertEqual(reopened.rows()[0]["state"], "done")
        self.assert_evidence()

    def test_satellite_restart_expired_lease(self):
        self.lab.store.add("restart-sat")
        sat = self.lab.satellite()
        claim = sat.rpc("/claim", {})
        self.assertIsNotNone(claim["task"])
        del sat
        with self.lab.store.connect() as db:
            db.execute("UPDATE tasks SET lease=0 WHERE id=?", (claim["task"],))
        self.assertEqual(self.lab.satellite("sat-2").run(2), ["done"])
        self.assertEqual(self.lab.store.rows()[0]["satellite"], "sat-2")
        self.assert_evidence()

    def test_encrypted_config_and_scoped_grant(self):
        self.lab.store.add("scope")
        sat = self.lab.satellite()
        claim = sat.rpc("/claim", {})
        grant = sat.rpc("/config", {"task": claim["task"]})["grant"]
        self.assertNotIn(self.lab.config.password, grant)
        with self.lab.store.connect() as db:
            encrypted = db.execute("SELECT value FROM configs").fetchone()[0]
        self.assertNotIn(self.lab.config.password.encode(), encrypted)
        # A valid token for another satellite cannot read someone else's task.
        with self.assertRaises(RoutingError):
            self.lab.satellite("sat-2").rpc("/config", {"task": claim["task"]})
        sat.grants = Fernet(Fernet.generate_key())
        with self.assertRaises(RoutingError) as caught:
            sat.config(claim["task"], "one")
        self.assertEqual(caught.exception.category, "config_invalid")
        self.assert_evidence()

    def test_external_target_and_redirect_never_sent(self):
        with self.assertRaises(RoutingError):
            self.lab.manager.request(self.lab.config, "http://example.com:80/authenticate")
        self.assertEqual(self.lab.audit.snapshot(), [])

    def test_socket_connections_only_to_proxy_even_on_failure(self):
        # Independent socket destination observer: server forwarding threads are
        # distinguished from the client thread, without trusting client counters.
        import socket
        original = socket.create_connection
        client_thread = threading.get_ident()
        destinations = []

        def observed(address, *args, **kwargs):
            if threading.get_ident() == client_thread:
                destinations.append(address)
            return original(address, *args, **kwargs)

        with patch("socket.create_connection", side_effect=observed):
            self.call()
            self.lab.proxy.mode = "disconnect"
            self.error("proxy_connection")
        self.assertEqual(len(destinations), 3)
        self.assertEqual(set(destinations), {("127.0.0.1", self.lab.config.port)})
        self.assert_evidence()

    def test_https_proxy_with_verified_certificate(self):
        import datetime
        import ipaddress
        from pathlib import Path
        import ssl
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from staging_proxy.mocks import Server
        from staging_proxy.transport import ProxyManager

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "staging-loopback")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                .sign(key, hashes.SHA256()))
        cert_path, key_path = Path(self.temp.name) / "cert.pem", Path(self.temp.name) / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server = Server(("127.0.0.1", 0), self.lab.proxy.handler())
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            config = replace(self.lab.config, port=server.server_port, protocol="https")
            trusted = ssl.create_default_context(cafile=str(cert_path))
            manager = ProxyManager(self.lab.audit, tls_context=trusted)
            self.assertTrue(manager.check(config, self.lab.auth_server.url + "/health")["ok"])
            with self.assertRaises(RoutingError) as caught:
                self.call(config)  # Default trust rejects the untrusted fixture CA.
            self.assertEqual(caught.exception.category, "proxy_tls")
            self.assert_evidence(equality=False)  # TLS rejection never reaches HTTP handler.
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_socks5_authenticated(self):
        import importlib.util
        if importlib.util.find_spec("socks") is None:
            self.skipTest("PySocks not installed")
        from staging_proxy.mocks import MockProxy, serve_socks
        gateway = MockProxy(audit=self.lab.proxy.audit)
        gateway.secret = self.lab.proxy.secret
        gateway.allowed.update(self.lab.allowed)
        with serve_socks(gateway, "fixture-user", "fixture-secret") as server:
            config = ProxyConfig("127.0.0.1", server.server_address[1], protocol="socks5",
                                 username="fixture-user", password="fixture-secret", retries=0)
            self.assertTrue(self.call(config)["ok"])
            self.assert_evidence()

    def test_detector_rejects_actual_direct_request(self):
        # Negative control proves detector works (excluded from acceptance run).
        with closing(http.client.HTTPConnection("127.0.0.1", self.lab.auth_server.server_port)) as conn:
            conn.request("GET", "/health", headers={"X-Staging-Proof": "forged"})
            self.assertEqual(conn.getresponse().status, 403)
        self.assertEqual(self.lab.evidence()["direct_requests"], 1)


if __name__ == "__main__":
    unittest.main()
