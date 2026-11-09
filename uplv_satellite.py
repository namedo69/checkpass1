"""One-room headless satellite; stdlib control plane, lazy game imports."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
import uplv_config as config

VERSION = 'uplv-satellite-0.3.0'


class Client:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip('/'), token

    def post(self, action, body):
        request = urllib.request.Request(self.url + '/api/uplv/' + action,
                                         json.dumps(body).encode(),
                                         {'Authorization': 'Bearer ' + self.token,
                                          'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.load(response)
        if not data.get('ok'):
            raise RuntimeError('Master rejected request')
        return data


class Metrics:
    def __init__(self):
        self.started = self.last_wall = time.monotonic()
        self.last_cpu = time.process_time()

    def snapshot(self):
        now, cpu = time.monotonic(), time.process_time()
        percent = 100 * (cpu - self.last_cpu) / max(.001, now - self.last_wall)
        self.last_wall, self.last_cpu = now, cpu
        rss = 0
        if sys.platform.startswith('linux'):
            rss = int(Path('/proc/self/statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE') / 1048576
        else:
            try:
                import psutil
                rss = psutil.Process().memory_info().rss / 1048576
            except ImportError:
                pass
        return {'rss_mb': round(rss, 2), 'cpu_percent': round(percent, 2),
                'threads': threading.active_count(), 'uptime_seconds': int(now - self.started)}


class Satellite:
    def __init__(self, client, engine, state_dir, satellite_id):
        self.client, self.engine = client, engine
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.id = satellite_id
        self.shutdown = threading.Event()
        self.metrics = Metrics()

    def run_room(self, room):
        stop = threading.Event()
        done = threading.Event()
        lock = threading.Lock()
        progress, results = {}, {}
        versions = list(room.get('versions', [0] * 5))
        checkpoint = self.state_dir / 'pending_report.json'
        base = {'satellite_id': self.id, 'room_id': room['id'], 'lease_token': room['lease_token']}

        def status(index, message):
            with lock:
                row = progress.setdefault(str(index), {})
                stage = re.search(r'\[(STACK\d(?:_DONE)?|BUFF|REGROUP|WAIT|RECONNECT|DEFERRED)\]', message)
                level = re.search(r'\[LEVEL\]\s*Lv(\d+)', message)
                elapsed = re.search(r'\[TIMER\]\s*(\d+)', message)
                if stage:
                    row['stage'] = stage.group(1)
                if level:
                    row['level'] = int(level.group(1))
                if elapsed:
                    row['elapsed'] = int(elapsed.group(1))
                if any(marker in message for marker in ('[ERROR]', '[DEFERRED]', 'timeout', 'Timeout')):
                    safe = message
                    for account in room['accounts']:
                        for secret in account:
                            if secret:
                                safe = safe.replace(secret, '[REDACTED]')
                    row['detail'] = safe[:400]
                    print(f'room={room["id"]} slot={index} {safe[:400]}', flush=True)

        def completed(index, row):
            ok, before, after, _ = row
            with lock:
                if (not ok and progress.get(str(index), {}).get('stage') == 'WAIT_REPLACEMENT'
                        and results.get(str(index), {}).get('status') == 'failed'):
                    return  # The failed original is not merely pending on stop.
                results[str(index)] = {'status': 'success' if ok else 'pending' if stop.is_set() else 'failed',
                                       'level_before': before, 'level_after': after}

        def snapshot():
            with lock:
                return {**base, 'progress': {k: dict(v) for k, v in progress.items()},
                        'versions': list(versions),
                        'results': {k: dict(v) for k, v in results.items()}, 'metrics': self.metrics.snapshot()}

        def replacement(index, row):
            request = {**base, 'request_id': uuid.uuid4().hex, 'slot': index,
                       'generation': versions[index], 'phase': 'preparation',
                       'result': {'status': 'failed', 'level_before': row[1], 'level_after': row[2]}}
            while not stop.is_set() and not self.shutdown.is_set():
                try:
                    # Serialize with heartbeat snapshot+send. A stale heartbeat
                    # must never write the previous occupant's result to a new slot.
                    with lock:
                        reply = self.client.post('replace', request)
                        if reply.get('stop'):
                            stop.set()
                            return None
                        if reply.get('account'):
                            room['accounts'][index] = reply['account']
                            versions[index] = reply['generation']
                            progress.pop(str(index), None)
                            results.pop(str(index), None)
                            return reply['account']
                        progress[str(index)] = {'stage': 'WAIT_REPLACEMENT', 'level': row[2]}
                        results[str(index)] = dict(request['result'])
                except (OSError, ValueError, RuntimeError):
                    pass
                stop.wait(15)
            return None

        def heartbeat():
            # Stop locally before the acknowledged lease expires. Never resume
            # a room after losing ownership or after shutdown is requested.
            lease_deadline = time.monotonic() + max(0, room['lease_until'] - time.time()) - 30
            while not done.is_set():
                if self.shutdown.is_set() or time.monotonic() >= lease_deadline:
                    stop.set()
                try:
                    payload = snapshot()
                    with lock:
                        payload['versions'] = list(versions)
                        payload['progress'] = {k: dict(v) for k, v in progress.items()}
                        payload['results'] = {k: dict(v) for k, v in results.items()}
                        reply = self.client.post('heartbeat', payload)
                    if reply.get('stop'):
                        stop.set()
                    lease_deadline = time.monotonic() + max(0, reply['lease_until'] - time.time()) - 30
                except (OSError, ValueError, RuntimeError):
                    pass
                done.wait(config.HEARTBEAT_SECONDS)

        thread = threading.Thread(target=heartbeat, name='uplv-heartbeat', daemon=True)
        thread.start()
        try:
            rows = self.engine.run(room, stop, status, completed, replacement=replacement)
            for index, row in rows.items():
                completed(index, row)
        except Exception as exc:
            # Exceptions can contain auth payloads: log class only.
            print(f'Room interrupted: {type(exc).__name__}', flush=True)
        finally:
            done.set()
            thread.join(timeout=12)
        with lock:
            for index in range(5):
                key = str(index)
                if key not in results:
                    level = progress.get(key, {}).get('level', 0)
                    results[key] = {'status': 'pending', 'level_before': level, 'level_after': level}
        report = {**snapshot(), 'stopped': stop.is_set() or self.shutdown.is_set()}
        temporary = checkpoint.with_suffix('.tmp')
        temporary.write_text(json.dumps(report), encoding='utf-8')
        temporary.replace(checkpoint)
        return self.flush_report()

    def flush_report(self):
        checkpoint = self.state_dir / 'pending_report.json'
        if not checkpoint.exists():
            return True
        try:
            report = json.loads(checkpoint.read_text(encoding='utf-8'))
            self.client.post('report', report)
            checkpoint.unlink()
            return True
        except (OSError, ValueError, RuntimeError):
            return False

    def run(self):
        while not self.shutdown.is_set():
            try:
                if not self.flush_report():
                    self.shutdown.wait(config.POLL_SECONDS)
                    continue
                reply = self.client.post('claim', {'satellite_id': self.id, 'metrics': self.metrics.snapshot()})
                if reply.get('room'):
                    self.run_room(reply['room'])
                else:
                    self.shutdown.wait(config.POLL_SECONDS)
            except (OSError, ValueError, RuntimeError) as exc:
                print(f'Master unavailable: {type(exc).__name__}', flush=True)
                self.shutdown.wait(config.POLL_SECONDS)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-runtime', action='store_true')
    parser.add_argument('--measure-idle', type=int, default=0, metavar='SECONDS')
    args = parser.parse_args()
    from uplv_engine import Engine
    state = os.environ.get('UPLV_STATE_DIR', config.STATE_DIR)
    metrics = Metrics()
    engine = Engine(state)
    if args.measure_idle:
        metrics.snapshot()  # Exclude cold imports from the idle CPU interval.
        time.sleep(max(1, min(300, args.measure_idle)))
        print(json.dumps({'ok': True, 'kind': 'idle_only', 'metrics': metrics.snapshot(), 'network_used': False}))
        return
    if args.check_runtime:
        print(json.dumps({'ok': True, 'version': VERSION, 'qt_loaded': any(n.startswith('PySide') for n in sys.modules),
                          'metrics': metrics.snapshot(), 'network_used': False}))
        return
    token = os.environ.get('MASTER_TOKEN', '')
    if not token:
        secret = Path(config.SECRET_FILE)
        token = secret.read_text(encoding='utf-8').strip() if secret.is_file() else config.MASTER_TOKEN
    if not token:
        raise RuntimeError('Set MASTER_TOKEN or mount the master token secret file')
    client = Client(os.environ.get('MASTER_URL', config.MASTER_URL), token)
    identity = Path(state) / 'satellite-id'
    if not identity.exists():
        identity.write_text('uplv-' + uuid.uuid4().hex[:16], encoding='utf-8')
    satellite = Satellite(client, engine, state, os.environ.get('SATELLITE_ID') or
                          os.environ.get('RENDER_SERVICE_ID') or identity.read_text().strip())
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: satellite.shutdown.set())
    health = None
    port = os.environ.get('PORT') or os.environ.get('HEALTH_PORT')
    if port:
        from uplv_health import start_health
        health = start_health('0.0.0.0', int(port), satellite.shutdown, VERSION)
    print(f'{VERSION} started; satellite={satellite.id}; health={bool(health)}', flush=True)
    try:
        satellite.run()
    finally:
        if health:
            health.shutdown()
            health.server_close()


if __name__ == '__main__':
    main()
