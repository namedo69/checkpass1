"""Small HTTPS-pull worker; max 15 sessions, no database access or Qt."""
import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import json
import os
from pathlib import Path
import re
import signal
import threading
import time
import urllib.request
from urllib.parse import urlsplit
import uuid

VERSION = 'buff-like-render-1.0'
MAX_ACCOUNTS = 15  # Render build; VPS build uses a separate fixed constant.


class Client:
    def __init__(self, url, token):
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('BUFF_MASTER_URL must be HTTPS without credentials/query')
        if len(token) < 32:
            raise ValueError('Set dedicated BUFF_WORKER_TOKEN (at least 32 characters)')
        self.url, self.token = url.rstrip('/'), token

    def post(self, action, body):
        request = urllib.request.Request(self.url + '/v1/render-workers/' + action,
            json.dumps(body).encode(), {'Content-Type': 'application/json',
                                       'User-Agent': 'Mozilla/5.0 (compatible; AutoBuffWorker/1.0)',
                                       'Authorization': 'Bearer ' + self.token})
        # Never follow redirects carrying account-control credentials.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        with urllib.request.build_opener(NoRedirect).open(request, timeout=15) as response:
            return json.load(response)


def auth_code(exc):
    code = getattr(exc, 'code', None)
    if type(code) is int:
        return code
    match = re.search(r'\bcode\s*=\s*(-?\d+)\b', str(exc))
    return int(match.group(1)) if match else None


class Worker:
    def __init__(self, client, identity, capacity=15, session_factory=None):
        self.client, self.identity = client, identity
        self.capacity = max(1, min(MAX_ACCOUNTS, int(capacity)))
        self.session_factory = session_factory
        self.shutdown = threading.Event()
        self.login_lock = threading.Lock()
        self.next_login = 0
        self.loop_seen = time.monotonic()

    def status(self):
        age = time.monotonic() - self.loop_seen
        return {'worker_loop_ok': age < 180, 'loop_age_seconds': round(age),
                'capacity': self.capacity, 'service_type': 'buff-like', 'id': self.identity}

    def execute(self, task, deadline):
        from backend_native.lobby_session import LobbySession
        factory = self.session_factory or LobbySession
        base = {'worker_id': self.identity, 'lease': task['lease']}
        outcome, code = 'interrupted', None
        logged_in = False
        stop = threading.Event()
        # Closing the socket is required before returning the account lease.
        def expire():
            stop.set()
        timer = threading.Timer(max(0, deadline-time.monotonic()), expire)
        timer.daemon = True
        timer.start()
        try:
            for attempt in range(3):
                if self.shutdown.is_set() or stop.is_set():
                    return
                try:
                    with factory(task['username'], task['password'], stop=stop) as session:
                        with self.login_lock:
                            delay = max(0, self.next_login-time.monotonic())
                            if stop.wait(delay):
                                return
                            self.next_login = time.monotonic()+0.6
                        session.authenticate()
                        session.connect_lobby()
                        logged_in = True
                        code = None
                        for post in task['posts']:
                            if self.shutdown.is_set() or stop.is_set():
                                return
                            started = time.monotonic()
                            permission = self.client.post('permit', {**base, 'post': post['post']})
                            if not permission.get('allowed'):
                                continue
                            # Slow responses never grant a delayed send.
                            if time.monotonic()-started >= 4 or stop.is_set() or self.shutdown.is_set():
                                return
                            session.send_like_feed_12958(int(post['uid']), int(post['world']), int(post['feed']))
                            if stop.wait(1.05):
                                return
                        outcome = 'finished'
                        return
                except Exception as exc:
                    code = auth_code(exc)
                    # Retry login only, never replay any attempted like. 91551
                    # is treated as retryable operationally, not as a known cause.
                    if logged_in or code != 91551 or attempt == 2:
                        outcome = 'interrupted' if logged_in else 'auth_failed'
                        print(json.dumps({'event': outcome, 'auth_code': code,
                                          'error_type': type(exc).__name__}), flush=True)
                        return
                    print(json.dumps({'event': 'login_retry', 'auth_code': code, 'attempt': attempt+1}), flush=True)
                    if stop.wait(5*(attempt+1)):
                        return
        finally:
            timer.cancel()
            task.pop('password', None)
            try:
                self.client.post('report', {**base, 'outcome': outcome, 'auth_code': code})
            except Exception as exc:
                # Lost reports are safe: the host expires the original lease.
                print(json.dumps({'event': 'report_failed', 'error_type': type(exc).__name__}), flush=True)

    def run(self):
        pending_request = None
        with ThreadPoolExecutor(max_workers=self.capacity) as pool:
            active = set()
            while not self.shutdown.is_set():
                self.loop_seen = time.monotonic()
                done = {future for future in active if future.done()}
                for future in done:
                    try:
                        future.result()
                    except Exception as exc:
                        print(json.dumps({'event': 'task_failed', 'error_type': type(exc).__name__}), flush=True)
                active -= done
                if len(active) >= self.capacity:
                    wait(active, timeout=1, return_when=FIRST_COMPLETED)
                    continue
                pending_request = pending_request or str(uuid.uuid4())
                started = time.monotonic()
                try:
                    response = self.client.post('claim', {'worker_id': self.identity, 'request_id': pending_request})
                    pending_request = None
                    task = response.get('task')
                    if task:
                        # Subtract the entire request round trip and safety margin.
                        deadline = started + min(300, max(0, float(task['seconds_left']))) - 30
                        active.add(pool.submit(self.execute, task, deadline))
                    else:
                        self.shutdown.wait(10)
                except Exception as exc:
                    print(json.dumps({'event': 'control_unavailable', 'error_type': type(exc).__name__,
                                      'http_status': getattr(exc, 'code', None)}), flush=True)
                    self.shutdown.wait(10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-runtime', action='store_true')
    args = parser.parse_args()
    from backend_native.lobby_protocol import build_login_request
    from backend_native.lobby_session import LobbySession
    body = build_login_request('a'*32, 'b'*32, 123456789)
    if body[4:8] != bytes.fromhex('0300008d'):
        raise RuntimeError('Login version mismatch')
    if args.check_runtime:
        print(json.dumps({'ok': True, 'version': VERSION, 'network_used': False, 'login_version': 50331789}))
        return
    from fleet_config import BUFF_MASTER_URL, BUFF_WORKER_TOKEN
    token = os.environ.get('BUFF_WORKER_TOKEN') or BUFF_WORKER_TOKEN
    client = Client(os.environ.get('BUFF_MASTER_URL') or BUFF_MASTER_URL, token)
    identity = os.environ.get('BUFF_WORKER_ID') or os.environ.get('SATELLITE_ID') or os.environ.get('RENDER_SERVICE_ID')
    if not identity:
        raise RuntimeError('Set BUFF_WORKER_ID or RENDER_SERVICE_ID')
    worker = Worker(client, identity, os.environ.get('BUFF_MAX_ACCOUNTS', '15'))
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: worker.shutdown.set())
    health = None
    if os.environ.get('PORT') or os.environ.get('HEALTH_PORT'):
        from uplv_health import start_health
        health = start_health('0.0.0.0', int(os.environ.get('PORT') or os.environ['HEALTH_PORT']),
                              worker.shutdown, VERSION, status=worker.status)
    print(json.dumps({'event': 'started', 'version': VERSION, 'capacity': worker.capacity}), flush=True)
    try:
        worker.run()
    finally:
        if health:
            health.shutdown()
            health.server_close()


if __name__ == '__main__':
    main()
