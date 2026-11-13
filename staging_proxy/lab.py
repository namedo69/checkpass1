"""Runnable multi-satellite lab: python -m staging_proxy.lab."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import tempfile

from cryptography.fernet import Fernet

from .cluster import Master, Satellite, Store
from .mocks import MockAuth, MockProxy, serve
from .transport import Audit, ProxyConfig, ProxyManager


class Lab:
    def __init__(self, directory):
        self.stack = ExitStack()
        self.directory = Path(directory)
        self.audit = Audit()
        self.manager = ProxyManager(self.audit)
        self.key = os.environ.get("STAGING_STORAGE_KEY", "").encode() or Fernet.generate_key()
        self.grant_key = os.environ.get("STAGING_GRANT_KEY", "").encode() or Fernet.generate_key()
        self.tokens = {name: secrets.token_urlsafe(24) for name in ("sat-1", "sat-2")}
        self.proxy = MockProxy("lab-user", secrets.token_urlsafe(24))
        self.proxy2 = MockProxy("lab-user-2", secrets.token_urlsafe(24))
        self.proxy_server = self.stack.enter_context(serve(self.proxy.handler()))
        self.proxy_server2 = self.stack.enter_context(serve(self.proxy2.handler()))
        self.config = ProxyConfig("127.0.0.1", self.proxy_server.server_port,
                                  username=self.proxy.username, password=self.proxy.password)
        self.config2 = ProxyConfig("127.0.0.1", self.proxy_server2.server_port,
                                   username=self.proxy2.username, password=self.proxy2.password)
        self.auth = MockAuth([self.proxy.secret, self.proxy2.secret])
        self.auth_server = self.stack.enter_context(serve(self.auth.handler()))
        self.store = Store(self.directory / "staging.db", self.key)
        self.store.configure("shared", self.config)
        self.master = Master(self.store, self.tokens, self.grant_key, self.manager,
                             self.config, self.auth_server.url)
        self.master_server = self.stack.enter_context(serve(self.master.handler()))
        self.allowed = {("127.0.0.1", self.auth_server.server_port),
                        ("127.0.0.1", self.master_server.server_port)}
        self.proxy.allowed.update(self.allowed)
        self.proxy2.allowed.update(self.allowed)

    def satellite(self, name="sat-1"):
        return Satellite(name, self.tokens[name], self.grant_key, self.manager,
                         self.config, self.master_server.url, self.auth_server.url)

    def close(self):
        self.stack.close()

    def evidence(self):
        clients = self.audit.snapshot()
        proxies = self.proxy.audit.snapshot() + self.proxy2.audit.snapshot()
        auth = self.auth.audit.snapshot()
        attempted = {e["request_id"] for e in clients if e["event"] == "attempt"}
        received = {e["request_id"] for e in proxies if e["event"] == "received"}
        forwarded = {e["request_id"] for e in proxies if e["event"] == "forwarded"}
        successes = {e["request_id"] for e in clients if e["event"] == "success"}
        return {
            "total_outbound_attempts": len(attempted),
            "requests_through_proxy": len(received),
            "unreceived_attempts": len(attempted - received),
            "auth_requests": len(auth),
            "auth_requests_through_proxy": sum(e["via_proxy"] for e in auth),
            "direct_requests": sum(not e["via_proxy"] for e in auth),
            "auth_without_proxy_receipt": sum(e["request_id"] not in received for e in auth),
            "successful_without_forward": len(successes - forwarded),
            "satellites": {name: sum(e["satellite"] == name for e in auth)
                           for name in ["master", *self.tokens]},
            "workers": sorted({e["satellite"] + "/" + e["worker"] for e in auth}),
            "tasks": self.store.rows(),
            "client_events": clients, "proxy_events": proxies, "auth_events": auth,
        }


def main():
    # Config persistence is encrypted; keys come from environment in deployments.
    with tempfile.TemporaryDirectory(prefix="checkpass-staging-") as directory:
        lab = Lab(directory)
        try:
            for i in range(24):
                lab.store.add(f"task-{i:03}", "normal" if i % 2 else "vvip")
            lab.store.configure("vvip", lab.config2)
            lab.master.check()
            # Assign initial claims to both satellites before starting workers,
            # guaranteeing evidence for both even under uneven scheduling.
            satellites = [lab.satellite(name) for name in lab.tokens]
            claims = [sat.rpc("/claim", {}) for sat in satellites]
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda pair: pair[0].process(pair[1], "initial"), zip(satellites, claims)))
                list(pool.map(lambda sat: sat.run(workers=4), satellites))
            evidence = lab.evidence()
            assert evidence["direct_requests"] == 0
            assert evidence["requests_through_proxy"] == evidence["total_outbound_attempts"]
            assert evidence["successful_without_forward"] == 0
            assert evidence["auth_without_proxy_receipt"] == 0
            assert all(row["state"] == "done" for row in evidence["tasks"])
            # Requested evidence artifact; path supplied explicitly by operator.
            output = os.environ.get("STAGING_REPORT")
            if output:
                Path(output).write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            print(json.dumps({key: value for key, value in evidence.items()
                              if not key.endswith("events") and key != "tasks"}, indent=2))
        finally:
            lab.close()


if __name__ == "__main__":
    main()
