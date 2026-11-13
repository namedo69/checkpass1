"""Durable staging claim/report protocol with encrypted, scoped proxy grants."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import secrets
import sqlite3
import threading
import time

from cryptography.fernet import Fernet, InvalidToken

from .mocks import Handler
from .transport import ProxyConfig, RoutingError


class Store:
    def __init__(self, path, key):
        self.path, self.cipher = str(path), Fernet(key)
        self.lock = threading.RLock()
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS configs(service TEXT PRIMARY KEY, version INTEGER, value BLOB);
                CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY, service TEXT, synthetic TEXT,
                    state TEXT, satellite TEXT, lease REAL, error TEXT);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def configure(self, service, config):
        with self.lock, self.connect() as db:
            old = db.execute("SELECT version FROM configs WHERE service=?", (service,)).fetchone()
            version = old[0] + 1 if old else 1
            value = self.cipher.encrypt(json.dumps(config.__dict__).encode())
            db.execute("INSERT OR REPLACE INTO configs VALUES(?,?,?)", (service, version, value))

    def config(self, service):
        with self.connect() as db:
            row = db.execute("SELECT version,value FROM configs WHERE service=?", (service,)).fetchone()
            if row is None:
                row = db.execute("SELECT version,value FROM configs WHERE service='shared'").fetchone()
        if row is None:
            raise RoutingError("config_missing")
        return row[0], json.loads(self.cipher.decrypt(row[1]))

    def add(self, task, service="normal"):
        with self.connect() as db:
            db.execute("INSERT INTO tasks VALUES(?,?,?,'pending','',0,'')", (task, service, "fixture-" + task))

    def rows(self):
        with self.connect() as db:
            return [dict(zip(("id", "service", "synthetic", "state", "satellite", "lease", "error"), row))
                    for row in db.execute("SELECT * FROM tasks ORDER BY id")]

    def recover(self):
        with self.connect() as db:
            db.execute("UPDATE tasks SET state='pending',satellite='',lease=0 WHERE state='connection_error'")


class Master:
    def __init__(self, store, tokens, grants_key, manager, bootstrap, auth_url):
        self.store, self.tokens = store, tokens
        self.grants = Fernet(grants_key)
        self.manager, self.bootstrap, self.auth_url = manager, bootstrap, auth_url

    def check(self):
        return self.manager.check(self.bootstrap, self.auth_url + "/health",
                                  identity={"satellite": "master", "worker": "master", "task": "health"})

    def dispatch(self, path, body, satellite):
        with self.store.lock, self.store.connect() as db:
            if path == "/claim":
                row = db.execute("SELECT id,service,synthetic FROM tasks WHERE state='pending' OR "
                                 "(state='running' AND lease<?) ORDER BY id LIMIT 1", (time.time(),)).fetchone()
                if not row:
                    return {"task": None}
                task, service, synthetic = row
                db.execute("UPDATE tasks SET state='running',satellite=?,lease=? WHERE id=?",
                           (satellite, time.time() + 180, task))
                return {"task": task, "service": service, "synthetic_id": synthetic}
            task = body.get("task", "")
            row = db.execute("SELECT service FROM tasks WHERE id=? AND satellite=? AND state='running'",
                             (task, satellite)).fetchone()
            if not row:
                raise RoutingError("task_not_owned")
            if path == "/config":
                version, config = self.store.config(row[0])
                envelope = {"task": task, "satellite": satellite, "version": version, "config": config}
                return {"grant": self.grants.encrypt(json.dumps(envelope).encode()).decode()}
            if path == "/report":
                state = body.get("state")
                error = body.get("error", "")
                if state not in {"done", "connection_error"} or error not in {
                    "", "proxy_disabled", "proxy_timeout", "proxy_auth", "proxy_connection", "proxy_tls",
                    "proxy_response", "service_response", "service_invalid_response", "config_invalid"}:
                    raise RoutingError("invalid_report")
                db.execute("UPDATE tasks SET state=?,error=?,lease=0 WHERE id=?", (state, error, task))
                return {"ok": True}
            raise RoutingError("unknown_endpoint")

    def handler(self):
        master = self

        class MasterHandler(Handler):
            def do_POST(self):
                auth = self.headers.get("Authorization", "")
                satellite = next((name for name, token in master.tokens.items()
                                  if secrets.compare_digest(auth, "Bearer " + token)), None)
                if satellite is None:
                    self.reply(401, {"error": "unauthorized"})
                    return
                try:
                    self.reply(200, master.dispatch(self.path, json.loads(self.body()), satellite))
                except (RoutingError, ValueError):
                    self.reply(400, {"error": "invalid_operation"})

        return MasterHandler


class Satellite:
    def __init__(self, name, token, grants_key, manager, bootstrap, master_url, auth_url):
        self.name, self.token, self.grants = name, token, Fernet(grants_key)
        self.manager, self.bootstrap = manager, bootstrap
        self.master_url, self.auth_url = master_url, auth_url

    def rpc(self, path, body, task="control", worker="control"):
        return self.manager.request(self.bootstrap, self.master_url + path, body,
            headers={"Authorization": "Bearer " + self.token},
            identity={"task": task, "worker": worker, "satellite": self.name})

    def config(self, task, worker):
        response = self.rpc("/config", {"task": task}, task, worker)
        try:
            envelope = json.loads(self.grants.decrypt(response["grant"].encode(), ttl=60))
            if envelope["satellite"] != self.name or envelope["task"] != task:
                raise ValueError
            return ProxyConfig(**envelope["config"])
        except (InvalidToken, ValueError, KeyError, TypeError):
            raise RoutingError("config_invalid") from None

    def process(self, claim, worker):
        task = claim["task"]
        identity = {"task": task, "worker": worker, "satellite": self.name}
        try:
            # Refresh before every dependent request: configuration changes take
            # effect on the next request; in-flight requests retain their snapshot.
            for endpoint in ("/health", "/authenticate", "/profile"):
                config = self.config(task, worker)
                self.manager.request(config, self.auth_url + endpoint,
                    {"synthetic_id": claim["synthetic_id"]}, identity=identity)
            state, error = "done", ""
        except RoutingError as exc:
            state, error = "connection_error", exc.category
        # If control proxy is unavailable the lease persists and expires for
        # reassignment. Never mark a task done until report is acknowledged.
        self.rpc("/report", {"task": task, "state": state, "error": error}, task, worker)
        return state

    def run(self, workers=3):
        def loop(index):
            results = []
            while True:
                try:
                    claim = self.rpc("/claim", {}, worker=str(index))
                    if claim["task"] is None:
                        return results
                    results.append(self.process(claim, str(index)))
                except RoutingError as exc:
                    # Control-plane outage: preserve the lease for recovery and
                    # stop this worker after the transport's bounded retries.
                    self.manager.audit.add(event="worker_stopped", category=exc.category,
                                           satellite=self.name, worker=str(index))
                    results.append("connection_error")
                    return results
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return [result for rows in pool.map(loop, range(workers)) for result in rows]
