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
from concurrent.futures import ThreadPoolExecutor
import uplv_config as config
from uplv_logs import RoomLogs

VERSION = 'uplv-satellite-0.6.0'


class RevokedLease(RuntimeError):
    pass


class Client:
    def __init__(self, url, token):
        self.url, self.token = url.rstrip('/'), token

    def post(self, action, body):
        request = urllib.request.Request(self.url + '/api/uplv/' + action,
                                         json.dumps(body).encode(),
                                         {'Authorization': 'Bearer ' + self.token,
                                          'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                data = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 400:
                payload = json.loads(exc.read().decode('utf-8'))
                message = str(payload.get('error', ''))
                if 'Lease không hợp lệ' in message or 'Stale slot versions' in message:
                    raise RevokedLease('Lease revoked') from None
            raise
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
                 'threads': threading.active_count(), 'uptime_seconds': int(now - self.started),
                 'capacity': max(1, min(4, int(getattr(config, 'MAX_ROOMS', 4))))}


class Satellite:
    def __init__(self, client, engine, state_dir, satellite_id):
        self.client, self.engine = client, engine
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.id = satellite_id
        self.shutdown = threading.Event()
        self.metrics = Metrics()
        self.logs = RoomLogs()
        self.room_logs = {}
        self.logging_active = set()
        self.room_logs_lock = threading.Lock()
        self.report_lock = threading.Lock()

    def view_logs(self):
        with self.room_logs_lock:
            return sorted([item for logs in self.room_logs.values() for item in logs.view()],
                          key=lambda item: item['at'])[-300:]

    def run_room(self, room):
        stop = threading.Event()
        done = threading.Event()
        lock = threading.Lock()
        progress, results = {}, {}
        logs = RoomLogs(room['id'])
        self.logs = logs
        with self.room_logs_lock:
            self.room_logs[room['id']] = logs
            self.logging_active.add(room['id'])
            # Keep four active/recent rooms; bounded even over a long run.
            while len(self.room_logs) > 4:
                old = next((key for key in self.room_logs if key not in self.logging_active), None)
                if old is None:
                    break
                del self.room_logs[old]
        logs.protect(room['accounts'])
        logs.add(-1, '[ROOM_START] Nhận phòng')
        versions = list(room.get('versions', [0] * 5))
        checkpoint = self.state_dir / ('pending_report_' + room['id'] + '.json')
        base = {'satellite_id': self.id, 'room_id': room['id'], 'lease_token': room['lease_token']}

        def status(index, message):
            logs.add(index, message)
            with lock:
                row = progress.setdefault(str(index), {})
                stage = re.search(r'\[(STACK\d(?:_DONE)?|BUFF|REGROUP|WAIT|RECONNECT|DEFERRED|VERIFYING|POOL_READY)\]', message)
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
            ok, before, after, error = row
            logs.add(index, f'[RESULT] {"success" if ok else "pending" if stop.is_set() or error in ('pool_ready', 'pool_verifying') else "failed"} Lv{after}')
            with lock:
                if (not ok and progress.get(str(index), {}).get('stage') == 'WAIT_REPLACEMENT'
                        and results.get(str(index), {}).get('status') == 'failed'):
                    return  # The failed original is not merely pending on stop.
                failure_kind = ('login' if error.startswith('terminal_login:') else
                                'create_character' if error.startswith('terminal_create_character:') else '')
                pending = stop.is_set() or (not ok and not failure_kind)
                if error:
                    diagnostic = str(error)
                    for account in room['accounts']:
                        for secret in account:
                            if secret:
                                diagnostic = diagnostic.replace(secret, '[REDACTED]')
                    diagnostic = re.sub(r'(?i)(bearer\s+|(?:password|token|sso_key|access_token)\s*[=:]\s*)\S+', r'\1[REDACTED]', diagnostic)
                    item = progress.setdefault(str(index), {})
                    item.setdefault('stage', 'VERIFYING' if pending else 'FAILED')
                    if not item.get('detail'):
                        item['detail'] = diagnostic[:400]
                results[str(index)] = {'status': 'success' if ok else 'pending' if pending else 'failed',
                                        'level_before': before, 'level_after': after, 'failure_kind': failure_kind,
                                        'verified': ok or error in ('pool_ready', 'screen_ready'),
                                        'idle': error in ('pool_ready', 'screen_ready'), 'screened': error == 'screen_ready'}

        def snapshot():
            with lock:
                return {**base, 'progress': {k: dict(v) for k, v in progress.items()},
                        'versions': list(versions),
                        'results': {k: dict(v) for k, v in results.items()},
                        'metrics': self.metrics.snapshot()}

        def replacement(index, row):
            request = {**base, 'request_id': uuid.uuid4().hex, 'slot': index,
                       'generation': versions[index], 'phase': 'preparation',
                       'result': {'status': 'failed', 'level_before': row[1], 'level_after': row[2],
                                  'failure_kind': 'login' if row[3].startswith('terminal_login:') else 'create_character' if row[3].startswith('terminal_create_character:') else ''}}
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
                            logs.protect([reply['account']])
                            logs.add(index, '[REPLACEMENT] Đã nhận acc bù')
                            room['accounts'][index] = reply['account']
                            if 'target' in reply:
                                room.setdefault('targets', [room['target']] * 5)[index] = reply['target']
                                room.setdefault('levels', [0] * 5)[index] = reply['level']
                            versions[index] = reply['generation']
                            progress.pop(str(index), None)
                            results.pop(str(index), None)
                            return reply['account']
                        progress[str(index)] = {'stage': 'WAIT_REPLACEMENT', 'level': row[2]}
                        results[str(index)] = dict(request['result'])
                except RevokedLease:
                    stop.set()
                    return
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
                except RevokedLease:
                    stop.set()
                    break
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
            logs.add(-1, f'[ERROR] Engine {type(exc).__name__}')
        finally:
            done.set()
            thread.join(timeout=12)
        with lock:
            for index in range(len(room['accounts'])):
                key = str(index)
                if key not in results:
                    level = progress.get(key, {}).get('level', 0)
                    results[key] = {'status': 'pending', 'level_before': level, 'level_after': level}
        logs.add(-1, '[ROOM_END] Kết thúc xử lý phòng')
        with self.room_logs_lock:
            self.logging_active.discard(room['id'])
        report = {**snapshot(), 'stopped': stop.is_set() or self.shutdown.is_set()}
        temporary = checkpoint.with_suffix('.tmp')
        temporary.write_text(json.dumps(report), encoding='utf-8')
        temporary.replace(checkpoint)
        return self.flush_report()

    def flush_report(self):
        with self.report_lock:
            paths = list(self.state_dir.glob('pending_report_*.json'))
            legacy = self.state_dir / 'pending_report.json'
            if legacy.exists():
                paths.append(legacy)
            ok = True
            for checkpoint in paths:
                try:
                    report = json.loads(checkpoint.read_text(encoding='utf-8'))
                    self.client.post('report', report)
                    checkpoint.unlink()
                except RevokedLease:
                    # Retired ownership must never block every future claim.
                    checkpoint.unlink()
                except (OSError, ValueError, RuntimeError):
                    ok = False
            return ok

    def run(self):
        capacity = max(1, min(4, int(config.MAX_ROOMS)))
        with ThreadPoolExecutor(max_workers=capacity, thread_name_prefix='uplv-room') as pool:
            active = set()
            while not self.shutdown.is_set():
                try:
                    for future in list(active):
                        if future.done():
                            active.remove(future)
                            try:
                                future.result()
                            except Exception as exc:
                                # A failed finished task must not poison every
                                # subsequent claim iteration. Its expired lease
                                # is recovered by the master inspection queue.
                                print(f'Room task failed: {type(exc).__name__}; continuing claims', flush=True)
                    if not self.flush_report() or len(active) >= capacity:
                        self.shutdown.wait(1 if active else config.POLL_SECONDS)
                        continue
                    reply = self.client.post('claim', {'satellite_id': self.id, 'capacity': capacity,
                                                       'pool_protocol': 1,
                                                       'verify_protocol': 1,
                                                       'screen_protocol': 1,
                                                       'metrics': self.metrics.snapshot()})
                    if reply.get('room'):
                        active.add(pool.submit(self.run_room, reply['room']))
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
        health = start_health('0.0.0.0', int(port), satellite.shutdown, VERSION,
                              token=token, logs=satellite.view_logs)
    print(f'{VERSION} started; satellite={satellite.id}; health={bool(health)}', flush=True)
    try:
        satellite.run()
    finally:
        if health:
            health.shutdown()
            health.server_close()


if __name__ == '__main__':
    main()
