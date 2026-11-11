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

VERSION = 'uplv-satellite-0.6.3'


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

    def checkpass_claim(self, body):
        """Claim a checkpass chunk from the master (UPLV checkpass mode)."""
        request = urllib.request.Request(
            self.url + '/api/uplv/checkpass/claim',
            json.dumps(body).encode(),
            {'Authorization': 'Bearer ' + self.token,
             'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def checkpass_report(self, body):
        """Report checkpass results to the master via standard report endpoint."""
        request = urllib.request.Request(
            self.url + '/api/report',
            json.dumps(body).encode(),
            {'Authorization': 'Bearer ' + self.token,
             'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def checkpass_heartbeat(self, body):
        """Extend lease on active checkpass chunks."""
        request = urllib.request.Request(
            self.url + '/api/heartbeat',
            json.dumps(body).encode(),
            {'Authorization': 'Bearer ' + self.token,
             'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)


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
                 'capacity': max(1, min(5, int(getattr(config, 'MAX_ROOMS', 5))))}


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
        self.loop_seen = time.monotonic()
        self.master_seen = 0
        self.last_control_error = ''

    def health_status(self):
        age = time.monotonic() - self.loop_seen
        return {'id': self.id, 'commit': os.environ.get('RENDER_GIT_COMMIT', 'local'),
                'worker_loop_ok': age < 180, 'loop_age_seconds': round(age),
                'master_age_seconds': round(time.monotonic() - self.master_seen) if self.master_seen else None,
                'last_control_error': self.last_control_error}

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
                                'restricted' if error.startswith('terminal_restricted:') else
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

    def _load_checkpass_engine(self):
        """Lazy-load the checkpass engine modules; returns (api_test, tcp_module) or None."""
        if hasattr(self, '_checkpass_engine'):
            return self._checkpass_engine
        try:
            import garena_api_test_chrome1 as api_test
            import garena_tcp_login_chrome as tcp_ui
            tcp_module = tcp_ui.load_verified_tcp_module()
            self._checkpass_engine = (api_test, tcp_module)
            print('[checkpass] Engine loaded successfully', flush=True)
            return self._checkpass_engine
        except Exception as exc:
            print(f'[checkpass] Engine not available: {type(exc).__name__}: {exc}', flush=True)
            self._checkpass_engine = None
            return None

    def run_checkpass_chunk(self, claim):
        """Process a single checkpass chunk using the garena checker engine."""
        engine = self._load_checkpass_engine()
        if engine is None:
            print('[checkpass] Engine not available, skipping chunk', flush=True)
            return
        api_test, tcp_module = engine
        chunk_id = int(claim['chunk_id'])
        job_id = int(claim['job_id'])
        accounts = list(claim.get('accounts') or [])
        print(f'[checkpass] {self.id}: chunk {chunk_id} job {job_id} ({len(accounts)} acc)', flush=True)

        credentials = []
        for index, raw in enumerate(accounts, 1):
            raw_str = str(raw).strip()
            parts = re.split(r'[|:]', raw_str)
            account = parts[0].strip() if parts else ''
            password = parts[1].strip() if len(parts) >= 2 else ''
            credentials.append(api_test.BatchAccount(index, account, password))

        workers = getattr(config, 'WORKERS', 8)
        start_gap = getattr(config, 'START_GAP', 0.5)
        timeout = getattr(config, 'TIMEOUT', 20.0)

        buffer = []
        buffer_lock = threading.Lock()
        FLUSH_SIZE = 5

        def flush_buffer(done=False):
            with buffer_lock:
                if not buffer and not done:
                    return
                rows_to_send = list(buffer)
                buffer.clear()
            if rows_to_send or done:
                for attempt in range(3):
                    try:
                        self.client.checkpass_report({
                            'chunk_id': chunk_id,
                            'rows': [api_test.public_batch_row(r) for r in rows_to_send],
                            'done': done,
                        })
                        break
                    except Exception:
                        if attempt == 2:
                            print(f'[checkpass] Report failed for chunk {chunk_id}', flush=True)
                        time.sleep(1)

        def on_result(row):
            need_flush = False
            with buffer_lock:
                buffer.append(row)
                if len(buffer) >= FLUSH_SIZE:
                    need_flush = True
            if need_flush:
                flush_buffer()

        # Heartbeat thread to keep the chunk lease alive
        heartbeat_stop = threading.Event()
        def heartbeat_loop():
            while not heartbeat_stop.is_set():
                heartbeat_stop.wait(60)
                if heartbeat_stop.is_set():
                    break
                try:
                    self.client.checkpass_heartbeat({
                        'satellite_id': self.id,
                        'chunk_ids': [chunk_id],
                        'lease_minutes': 5,
                    })
                except Exception:
                    pass

        hb_thread = threading.Thread(target=heartbeat_loop, daemon=True, name='cp-heartbeat')
        hb_thread.start()

        try:
            api_test.run_batch_core(
                credentials, tcp_module, workers, start_gap, timeout,
                stop_event=self.shutdown, on_result=on_result)
            # Final flush
            flush_buffer(done=True)
        except Exception as exc:
            print(f'[checkpass] Chunk {chunk_id} error: {type(exc).__name__}', flush=True)
            flush_buffer(done=True)
        finally:
            heartbeat_stop.set()
            hb_thread.join(timeout=5)
            for cred in credentials:
                cred.password = ''

        print(f'[checkpass] Chunk {chunk_id} completed', flush=True)

    def run(self):
        capacity = max(1, min(5, int(config.MAX_ROOMS)))
        request_id = uuid.uuid4().hex
        wake = threading.Event()
        last_presence = 0
        last_checkpass_poll = 0
        CHECKPASS_POLL_INTERVAL = 5  # seconds between checkpass claim attempts when idle
        def pause(seconds):
            wake.wait(seconds)
        with ThreadPoolExecutor(max_workers=capacity + 2, thread_name_prefix='uplv-room') as pool:
            active = set()
            checkpass_active = set()
            while not self.shutdown.is_set():
                wake.clear()
                self.loop_seen = time.monotonic()
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
                    for future in list(checkpass_active):
                        if future.done():
                            checkpass_active.remove(future)
                            try:
                                future.result()
                            except Exception as exc:
                                print(f'CheckPass task failed: {type(exc).__name__}; continuing', flush=True)

                    # Try checkpass claim (throttled)
                    now_mono = time.monotonic()
                    if len(checkpass_active) < 2 and now_mono - last_checkpass_poll >= CHECKPASS_POLL_INTERVAL:
                        last_checkpass_poll = now_mono
                        try:
                            cp_reply = self.client.checkpass_claim({
                                'satellite_id': self.id,
                                'lease_minutes': 5,
                            })
                            cp_claim = cp_reply.get('claim')
                            if cp_claim:
                                future = pool.submit(self.run_checkpass_chunk, cp_claim)
                                checkpass_active.add(future)
                                future.add_done_callback(lambda _: wake.set())
                                last_checkpass_poll = 0  # Reset to claim again immediately
                                continue
                        except Exception:
                            pass

                    # Presence is independent of report spool/game threads.
                    # A failed pending report must remain visible to master.
                    if time.monotonic() - last_presence >= 15:
                        self.client.post('presence', {'satellite_id': self.id, 'metrics': self.metrics.snapshot(),
                                                      'worker_url': os.environ.get('RENDER_EXTERNAL_URL', '')})
                        self.master_seen = time.monotonic()
                        last_presence = self.master_seen
                        self.last_control_error = ''
                    if not self.flush_report() or len(active) >= capacity:
                        pause(1)
                        continue
                    # Normal UPLV room claim
                    reply = self.client.post('claim', {'satellite_id': self.id, 'capacity': capacity,
                                                       'request_id': request_id,
                                                       'pool_protocol': 1,
                                                       'verify_protocol': 1,
                                                       'screen_protocol': 1,
                                                       'metrics': self.metrics.snapshot()})
                    request_id = uuid.uuid4().hex
                    if reply.get('room'):
                        future = pool.submit(self.run_room, reply['room'])
                        active.add(future)
                        future.add_done_callback(lambda _: wake.set())
                    else:
                        pause(1)
                except (OSError, ValueError, RuntimeError) as exc:
                    self.last_control_error = type(exc).__name__
                    print(f'Master unavailable: {type(exc).__name__}', flush=True)
                    pause(2)


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
                              token=token, logs=satellite.view_logs, status=satellite.health_status)
    print(f'{VERSION} started; satellite={satellite.id}; health={bool(health)}', flush=True)
    try:
        satellite.run()
    finally:
        if health:
            health.shutdown()
            health.server_close()


if __name__ == '__main__':
    main()
