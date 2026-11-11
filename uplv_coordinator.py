"""Persistent one-room leases, independent of CheckPass billing/chunks."""
import json
import re
import secrets
import threading
import time
import uuid
import math
import urllib.request
import urllib.parse
import copy
from uplv_account_pool import AccountPool


class UpLvCoordinator(AccountPool):
    LEASE_SECONDS = 180

    def worker_snapshot(self):
        rows = self.store.fetch('SELECT id,last_seen,paused,metrics_json FROM uplv_satellites ORDER BY id')
        return {'ok': True, 'satellites': [{'id': r[0], 'last_seen': r[1],
                'online': time.time() - r[1] < 90, 'paused': bool(r[2]),
                'metrics': json.loads(r[3]), 'service_type': 'uplv'} for r in rows]}

    def dashboard_snapshot(self):
        # UI polling shares a short-lived snapshot; control-plane callers and
        # tests can still request an uncached authoritative snapshot.
        # Own lock: dashboard viewers must not hold the coordinator lock that
        # worker claim/heartbeat/report calls need.
        with self._dashboard_lock:
            now = time.monotonic()
            cached = getattr(self, '_dashboard_cache', None)
            if cached and now - cached[0] < 2:
                return copy.deepcopy(cached[1])
            result = self.snapshot()
            self._dashboard_cache = (now, result)
            return copy.deepcopy(result)

    def saved_targets(self):
        row = self.store.fetchone("SELECT setting_value FROM app_settings WHERE setting_key='uplv_satellite_targets'")
        return str(row[0]) if row else ''

    def save_targets(self, body):
        from satellite_keepawake import parse_satellite_targets
        text = str(body.get('targets', ''))
        if len(text) > 20000:
            raise ValueError('Danh sách tối đa 20.000 ký tự')
        targets = parse_satellite_targets(text)
        if text.strip() and not targets:
            raise ValueError('Cần URL http/https hợp lệ')
        value = '\n'.join(f"[{t['label']}] {t['url']}" for t in targets)
        self.store.batch([{'sql': "INSERT INTO app_settings (setting_key,setting_value) VALUES ('uplv_satellite_targets',?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value", 'args': [value]}])
        return {'ok': True, 'targets': value}

    def target_health(self, body):
        from satellite_keepawake import parse_satellite_targets
        from master_server import fetch_satellite_health
        from concurrent.futures import ThreadPoolExecutor
        targets = [{**t, 'expected_service_type': 'uplv'} for t in parse_satellite_targets(self.saved_targets())]
        requested = str(body.get('url', '')).rstrip('/')
        if requested:
            targets = [t for t in targets if t['url'].rstrip('/') == requested]
            if not targets:
                raise ValueError('URL không thuộc danh sách UpLv đã lưu')
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as pool:
            results = list(pool.map(fetch_satellite_health, targets))
        for result in results:
            health = result.get('health') or {}
            result['type_mismatch'] = bool(result.get('online') and health.get('service_type') != 'uplv')
        return {'ok': True, 'satellites': results, 'checked_at': time.time()}

    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self._dashboard_lock = threading.Lock()
        self.clear_state = {'running': False, 'state': 'idle', 'message': ''}
        for sql in (
            "CREATE TABLE IF NOT EXISTS uplv_jobs (id TEXT PRIMARY KEY, created_at DOUBLE PRECISION NOT NULL, target INTEGER NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_rooms (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, ordinal INTEGER NOT NULL, accounts_json TEXT NOT NULL, status TEXT NOT NULL, satellite_id TEXT NOT NULL DEFAULT '', lease_token TEXT NOT NULL DEFAULT '', lease_until DOUBLE PRECISION NOT NULL DEFAULT 0, progress_json TEXT NOT NULL DEFAULT '{}', results_json TEXT NOT NULL DEFAULT '{}', stop_requested INTEGER NOT NULL DEFAULT 0)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_room_status ON uplv_rooms(status,lease_until)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_room_job ON uplv_rooms(job_id,ordinal)",
            "CREATE TABLE IF NOT EXISTS uplv_satellites (id TEXT PRIMARY KEY, last_seen DOUBLE PRECISION NOT NULL, paused INTEGER NOT NULL DEFAULT 0, metrics_json TEXT NOT NULL DEFAULT '{}')",
            "CREATE TABLE IF NOT EXISTS uplv_reserves (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, account_json TEXT NOT NULL, status TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_room_versions (room_id TEXT PRIMARY KEY, versions_json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_replacements (request_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, slot INTEGER NOT NULL, old_account_json TEXT NOT NULL, result_json TEXT NOT NULL, response_json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_logs (id TEXT PRIMARY KEY, satellite_id TEXT NOT NULL, room_id TEXT NOT NULL, received_at DOUBLE PRECISION NOT NULL, event_at DOUBLE PRECISION NOT NULL, slot INTEGER NOT NULL, message TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_logs_satellite ON uplv_logs(satellite_id,received_at,id)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_jobs_created ON uplv_jobs(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_room_satellite ON uplv_rooms(satellite_id,status)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_replacements_room ON uplv_replacements(room_id)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_reserves_job ON uplv_reserves(job_id,status)",
        ):
            store.exec(sql)
        self.init_pool()

    def clear_data(self, body):
        with self.lock:
            if self.clear_state['running']:
                return {'ok': True, 'clear': dict(self.clear_state)}
            self.clear_state = {'running': True, 'state': 'stopping',
                                'message': 'Đang dừng các phòng trước khi xóa dữ liệu UpLv'}
            try:
                self.store.batch([
                    {'sql': "UPDATE uplv_jobs SET status='stopped' WHERE status='open'", 'args': []},
                    {'sql': 'UPDATE uplv_rooms SET stop_requested=1', 'args': []},
                ])
            except Exception:
                self.clear_state = {'running': False, 'state': 'error', 'message': 'Không gửi được yêu cầu dừng'}
                raise
            threading.Thread(target=self._clear_data_worker, daemon=True, name='uplv-clear-data').start()
            return {'ok': True, 'clear': dict(self.clear_state)}

    def _clear_data_worker(self):
        tables = ('uplv_check_members', 'uplv_job_owners', 'uplv_check_chunks', 'uplv_claim_requests', 'uplv_logs', 'uplv_replacements', 'uplv_room_versions', 'uplv_reserves',
                  'uplv_check_leases', 'uplv_verify_attempts', 'uplv_verify_rooms',
                  'uplv_screen_rooms', 'uplv_room_history', 'uplv_task_details',
                  'uplv_tasks', 'uplv_pool_jobs', 'uplv_rooms', 'uplv_jobs')
        try:
            deadline = time.monotonic() + 240
            while True:
                with self.lock:
                    active = self.store.fetchone("SELECT COUNT(*) FROM uplv_rooms WHERE status IN ('running','interrupted') AND lease_until>?", (time.time(),))[0]
                    if not active:
                        counts = {table: self.store.fetchone(f'SELECT COUNT(*) FROM {table}')[0] for table in tables}
                        self.store.batch([{'sql': f'DELETE FROM {table}', 'args': []} for table in tables])
                        self.clear_state = {'running': False, 'state': 'done',
                            'message': 'Đã xóa dữ liệu UpLv; giữ nguyên cấu hình và vệ tinh', 'deleted': counts}
                        return
                    if time.monotonic() >= deadline:
                        self.clear_state = {'running': False, 'state': 'error',
                            'message': 'Phòng chưa dừng sau 240 giây. Chưa xóa dữ liệu; có thể thử lại.'}
                        return
                time.sleep(1)
        except Exception:
            with self.lock:
                self.clear_state = {'running': False, 'state': 'error',
                                    'message': 'Không thể hoàn tất clear dữ liệu UpLv'}

    @staticmethod
    def parse_accounts(text):
        accounts = []
        seen = set()
        for number, line in enumerate(str(text).splitlines(), 1):
            line = line.strip().lstrip('\ufeff')
            if not line or line.startswith('#'):
                continue
            fields = line.split('|' if '|' in line else ':')
            if len(fields) < 2 or not fields[0].strip() or not fields[1].strip():
                raise ValueError(f'Dòng {number}: cần user|pass')
            user, password = fields[0].strip(), fields[1].strip()
            if user.casefold() in seen:
                raise ValueError(f'Dòng {number}: tài khoản trùng')
            seen.add(user.casefold())
            accounts.append([user, password])
        return accounts

    def create(self, body):
        return self.pool_create(body)
        # Legacy room records remain readable; new jobs use account ownership.
        target = int(body.get('target', 12))
        mode = str(body.get('mode', 'victory'))
        if not 6 <= target <= 30 or mode not in ('victory', 'defeat', 'surrender'):
            raise ValueError('Mục tiêu Lv6–30; mode victory/defeat/surrender')
        accounts = self.parse_accounts(body.get('accounts', ''))
        reserves = self.parse_accounts(body.get('reserves', ''))
        seen = [u.casefold() for u, _ in accounts + reserves]
        if len(set(seen)) != len(seen) or len(accounts) + len(reserves) > 5000:
            raise ValueError('Tài khoản trùng hoặc tổng vượt 5.000')
        if not accounts or len(accounts) % 5 or len(accounts) > 5000:
            raise ValueError('Mỗi job cần bội số của 5 tài khoản, tối đa 5.000')
        job = uuid.uuid4().hex
        statements = [{'sql': 'INSERT INTO uplv_jobs VALUES (?,?,?,?,?)',
                       'args': [job, time.time(), target, mode, 'open']}]
        for offset in range(0, len(accounts), 5):
            statements.append({'sql': 'INSERT INTO uplv_rooms (id,job_id,ordinal,accounts_json,status) VALUES (?,?,?,?,?)',
                               'args': [uuid.uuid4().hex, job, offset // 5 + 1,
                                         json.dumps(accounts[offset:offset + 5]), 'pending']})
        for account in reserves:
            statements.append({'sql': 'INSERT INTO uplv_reserves VALUES (?,?,?,?)',
                               'args': [uuid.uuid4().hex, job, json.dumps(account), 'pending']})
        with self.lock:
            active = self.store.fetch("SELECT accounts_json FROM uplv_rooms WHERE status IN ('pending','running','interrupted')")
            reserved = {user.casefold() for row in active for user, _ in json.loads(row[0])}
            reserved.update(json.loads(r[0])[0].casefold() for r in self.store.fetch(
                "SELECT account_json FROM uplv_reserves WHERE status='pending'"))
            if reserved.intersection(seen):
                raise ValueError('Có tài khoản đang thuộc phòng UpLv khác')
            self.store.batch(statements)
        return {'ok': True, 'job_id': job, 'rooms': len(accounts) // 5}

    @staticmethod
    def satellite_id(body):
        value = str(body.get('satellite_id', ''))
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', value):
            raise ValueError('satellite_id không hợp lệ')
        return value

    def touch(self, body):
        satellite = self.satellite_id(body)
        # Store resource telemetry only, never arbitrary credentials/logs.
        metrics = {}
        for key in ('rss_mb', 'cpu_percent', 'threads', 'uptime_seconds', 'capacity'):
            value = body.get('metrics', {}).get(key)
            if isinstance(value, (int, float)) and 0 <= value < 1e12:
                metrics[key] = value
        # Store.exec on PostgreSQL auto-returns an integer id; these IDs are
        # text, so use the portable batch interface for the upsert.
        self.store.batch([{'sql':
            'INSERT INTO uplv_satellites (id,last_seen,metrics_json) VALUES (?,?,?) '
            'ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,metrics_json=excluded.metrics_json',
            'args': [satellite, time.time(), json.dumps(metrics)]}])
        return satellite

    def presence(self, body):
        with self.lock:
            self.touch(body)
            return {'ok': True}

    def expire(self, throttled=False):
        now = time.monotonic()
        if throttled and now - getattr(self, '_last_expire', 0) < 5:
            return
        self._last_expire = now
        # A lost worker may still be in a game: do not assign its accounts to
        # another VPS automatically. Late results remain accepted by its token.
        self.store.exec("UPDATE uplv_rooms SET status='interrupted' WHERE status='running' AND lease_until<?",
                        (time.time(),))
        # Workers stop at their local lease deadline. Keep another 120 seconds
        # for cleanup/late reports, then inspect instead of blindly replaying.
        for (room,) in self.store.fetch("SELECT id FROM uplv_rooms WHERE status='interrupted' AND lease_until<?", (time.time() - 120,)):
            tasks = self.room_tasks(room)
            if not tasks:
                continue
            progress = json.loads(self.store.fetchone('SELECT progress_json FROM uplv_rooms WHERE id=?', (room,))[0])
            changes = []
            for task, job, _, _, level, slot, _ in tasks:
                state = self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (job,))[0]
                observed = int(progress.get(str(slot), {}).get('level', 0) or 0)
                changes += [
                    {'sql': "UPDATE uplv_tasks SET status=?,level=?,room_id='',slot=-1 WHERE id=?", 'args': ['stopped' if state == 'stopped' else 'verifying', max(level, observed), task]},
                    {'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, time.time(), json.dumps({'stage': 'VERIFYING', 'detail': 'Mất heartbeat/worker restart; thu hồi lease cũ, đối soát cấp và trận cũ trước khi chạy tiếp'})]},
                    {'sql': 'DELETE FROM uplv_verify_attempts WHERE task_id=?', 'args': [task]},
                ]
            changes.append({'sql': "UPDATE uplv_rooms SET status='incomplete',lease_token='',lease_until=0,stop_requested=1 WHERE id=?", 'args': [room]})
            self.store.batch(changes)

    def claim(self, body):
        with self.lock:
            if self.clear_state['running']:
                return {'ok': True, 'room': None, 'reason': 'clearing_data'}
            satellite = self.touch(body)
            self.expire(throttled=True)
            request_id = str(body.get('request_id', ''))
            if request_id:
                if not re.fullmatch(r'[a-f0-9]{32}', request_id):
                    raise ValueError('request_id không hợp lệ')
                previous = self.store.fetchone('SELECT satellite_id,room_id,token,response_json FROM uplv_claim_requests WHERE id=?', (request_id,))
                if previous:
                    if previous[0] != satellite:
                        raise ValueError('request_id thuộc vệ tinh khác')
                    lease = self.store.fetchone('SELECT lease_token,lease_until,status FROM uplv_rooms WHERE id=?', (previous[1],))
                    if not lease or lease[0] != previous[2] or lease[1] <= time.time() or lease[2] != 'running':
                        return {'ok': True, 'room': None, 'reason': 'claim_expired'}
                    return json.loads(previous[3])
            active = self.store.fetchone("SELECT COUNT(*) FROM uplv_rooms WHERE satellite_id=? AND status IN ('running','interrupted')", (satellite,))[0]
            capacity = max(1, min(5, int(body.get('capacity', 1))))
            if active >= capacity:
                return {'ok': True, 'room': None, 'reason': 'already_running'}
            paused = self.store.fetchone('SELECT paused FROM uplv_satellites WHERE id=?', (satellite,))
            if paused[0]:
                return {'ok': True, 'room': None, 'reason': 'paused'}
            occupied = self.store.fetchone("SELECT COUNT(*) FROM uplv_rooms WHERE status IN ('running','interrupted')")[0]
            if occupied >= self.pool_limit():
                return {'ok': True, 'room': None, 'reason': 'system_room_limit'}
            pending = self.store.fetchone("SELECT id FROM uplv_rooms WHERE status='pending' LIMIT 1")
            if not pending:
                self.pool_form_room()
            row = self.store.fetchone(
                "SELECT r.id,r.accounts_json,j.target,j.mode FROM uplv_rooms r JOIN uplv_jobs j ON j.id=r.job_id "
                "WHERE r.status='pending' AND j.status='open' ORDER BY j.created_at,r.ordinal LIMIT 1")
            if not row:
                return {'ok': True, 'room': None}
            token = secrets.token_urlsafe(32)
            until = time.time() + self.LEASE_SECONDS
            self.store.exec("UPDATE uplv_rooms SET status='running',satellite_id=?,lease_token=?,lease_until=? WHERE id=?",
                            (satellite, token, until, row[0]))
            tasks = self.room_tasks(row[0])
            verify_only = self.store.fetchone('SELECT room_id FROM uplv_verify_rooms WHERE room_id=?', (row[0],)) is not None
            screen_only = self.store.fetchone('SELECT room_id FROM uplv_screen_rooms WHERE room_id=?', (row[0],)) is not None
            if (verify_only and not body.get('verify_protocol')) or (screen_only and not body.get('screen_protocol')):
                # Older workers cannot safely process verification-only leases.
                self.store.exec("UPDATE uplv_rooms SET status='pending',satellite_id='',lease_token='',lease_until=0 WHERE id=?", (row[0],))
                return {'ok': True, 'room': None, 'reason': 'worker_upgrade_required'}
            response = {'ok': True, 'room': {'id': row[0], 'accounts': json.loads(row[1]),
                    'verify_only': verify_only,
                    'screen_only': screen_only,
                    'target': row[2], 'targets': [r[3] for r in tasks] if tasks else [row[2]] * 5,
                    'levels': [r[4] for r in tasks] if tasks else [0] * 5,
                    'pool_protocol': 1 if tasks else 0,
                    'mode': row[3], 'lease_token': token, 'lease_until': until}}
            if request_id:
                self.store.batch([{'sql': 'INSERT INTO uplv_claim_requests VALUES (?,?,?,?,?)', 'args': [request_id, satellite, row[0], token, json.dumps(response)]}])
            return response

    def owned(self, body):
        satellite = self.satellite_id(body)
        row = self.store.fetchone('SELECT satellite_id,lease_token,status,stop_requested,accounts_json,results_json FROM uplv_rooms WHERE id=?',
                                 (str(body.get('room_id', '')),))
        if not row or row[0] != satellite or not secrets.compare_digest(row[1], str(body.get('lease_token', ''))):
            raise ValueError('Lease không hợp lệ hoặc phòng không thuộc vệ tinh này')
        return row

    def versions(self, room_id):
        row = self.store.fetchone('SELECT versions_json FROM uplv_room_versions WHERE room_id=?', (room_id,))
        return json.loads(row[0]) if row else [0] * 5

    def check_versions(self, body):
        if body.get('versions', [0] * 5) != self.versions(body['room_id']):
            raise ValueError('Stale slot versions; discard old heartbeat/report')

    def add_reserves(self, body):
        if self.pool_job(str(body.get('job_id', ''))):
            return self.pool_add(body)
        accounts = self.parse_accounts(body.get('accounts', ''))
        job = str(body.get('job_id', ''))
        if not accounts or len(accounts) > 5000:
            raise ValueError('Cần 1–5.000 acc dự phòng')
        with self.lock:
            row = self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (job,))
            if not row or row[0] != 'open':
                raise ValueError('Job không còn mở')
            # Include historical attempts: never recycle an already failed acc
            # into the same job, or an account currently owned by another job.
            reserved = {u.casefold() for r in self.store.fetch(
                "SELECT accounts_json FROM uplv_rooms WHERE job_id=? OR status IN ('pending','running','interrupted')", (job,))
                for u, _ in json.loads(r[0])}
            reserved.update(json.loads(r[0])[0].casefold() for r in self.store.fetch(
                "SELECT account_json FROM uplv_reserves WHERE job_id=? OR status='pending'", (job,)))
            reserved.update(json.loads(r[0])[0].casefold() for r in self.store.fetch(
                'SELECT p.old_account_json FROM uplv_replacements p JOIN uplv_rooms r ON r.id=p.room_id WHERE r.job_id=?', (job,)))
            if reserved.intersection(u.casefold() for u, _ in accounts):
                raise ValueError('Có acc trùng/đã dùng/đang thuộc phòng khác')
            self.store.batch([{'sql': 'INSERT INTO uplv_reserves VALUES (?,?,?,?)',
                              'args': [uuid.uuid4().hex, job, json.dumps(a), 'pending']} for a in accounts])
        return {'ok': True, 'added': len(accounts)}

    def replace(self, body):
        with self.lock:
            row = self.owned(body)
            request = str(body.get('request_id', ''))
            if not re.fullmatch(r'[a-f0-9]{32}', request):
                raise ValueError('request_id không hợp lệ')
            slot = int(body.get('slot', -1))
            if not 0 <= slot < 5:
                raise ValueError('slot không hợp lệ')
            previous = self.store.fetchone('SELECT room_id,slot,response_json FROM uplv_replacements WHERE request_id=?', (request,))
            if previous:
                if previous[:2] != (body['room_id'], slot):
                    raise ValueError('request_id đã thuộc yêu cầu khác')
                return json.loads(previous[2])
            if row[2] != 'running' or row[3]:
                return {'ok': True, 'stop': True}
            lease = self.store.fetchone('SELECT lease_until,job_id FROM uplv_rooms WHERE id=?', (body['room_id'],))
            if lease[0] <= time.time():
                return {'ok': True, 'stop': True}
            versions = self.versions(body['room_id'])
            if body.get('generation') != versions[slot] or body.get('phase') != 'preparation':
                raise ValueError('Chỉ bù acc chuẩn bị với generation hiện tại')
            progress = self.store.fetchone('SELECT progress_json FROM uplv_rooms WHERE id=?', (body['room_id'],))
            stage = json.loads(progress[0]).get(str(slot), {}).get('stage', '')
            if stage in ('STACK2', 'STACK2_DONE', 'STACK3', 'STACK3_DONE', 'STACK4', 'STACK4_DONE', 'BUFF'):
                raise ValueError('Không thay acc đã mở phiên buff/trận')
            result = self.clean_rows({str(slot): body.get('result')})[str(slot)]
            if result['status'] != 'failed':
                raise ValueError('Cần kết quả lỗi chuẩn bị')
            reserve = self.store.fetchone("SELECT id,account_json FROM uplv_reserves WHERE job_id=? AND status='pending' ORDER BY id LIMIT 1", (lease[1],))
            task = self.store.fetchone('SELECT id,job_id,mode FROM uplv_tasks WHERE room_id=? AND slot=?', (body['room_id'], slot))
            candidate = None
            if task:
                candidate = self.store.fetchone("SELECT t.id,t.account_json,t.target,t.level FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE j.status='open' AND t.mode=? AND (t.status='waiting' OR (t.status='ready' AND t.level=?)) ORDER BY CASE WHEN t.status='ready' THEN 0 ELSE 1 END,CASE WHEN t.job_id=? THEN 0 ELSE 1 END,t.created_at LIMIT 1", (task[2], result['level_after'], task[1]))
                reserve = candidate
            if not reserve:
                results = json.loads(row[5]); results[str(slot)] = result
                waiting = json.loads(progress[0])
                waiting[str(slot)] = {'stage': 'WAIT_REPLACEMENT', 'level': result['level_after'], 'elapsed': 0}
                self.store.exec('UPDATE uplv_rooms SET results_json=?,progress_json=? WHERE id=?',
                                (json.dumps(results), json.dumps(waiting), body['room_id']))
                return {'ok': True, 'waiting': True, 'retry_after': 15}
            accounts = json.loads(row[4])
            old_account = accounts[slot]
            accounts[slot] = json.loads(reserve[1])
            versions[slot] += 1
            response = {'ok': True, 'account': accounts[slot], 'generation': versions[slot]}
            if candidate:
                response.update(target=candidate[2], level=candidate[3])
            results = json.loads(row[5]); results.pop(str(slot), None)
            progress = json.loads(progress[0]); progress.pop(str(slot), None)
            changes = [
                {'sql': 'UPDATE uplv_rooms SET accounts_json=?,results_json=?,progress_json=? WHERE id=?',
                 'args': [json.dumps(accounts), json.dumps(results), json.dumps(progress), body['room_id']]},
                {'sql': 'INSERT INTO uplv_room_versions VALUES (?,?) ON CONFLICT(room_id) DO UPDATE SET versions_json=excluded.versions_json',
                 'args': [body['room_id'], json.dumps(versions)]},
                {'sql': 'INSERT INTO uplv_replacements VALUES (?,?,?,?,?,?)',
                 'args': [request, body['room_id'], slot, json.dumps(old_account), json.dumps(result), json.dumps(response)]},
            ]
            if task:
                changes += [
                    {'sql': "UPDATE uplv_tasks SET status='failed',level=? WHERE id=?", 'args': [result['level_after'], task[0]]},
                    {'sql': "UPDATE uplv_tasks SET status='assigned',room_id=?,slot=? WHERE id=?", 'args': [body['room_id'], slot, candidate[0]]},
                ]
                # Historical failed task retains room reference but no active slot.
                changes.append({'sql': 'UPDATE uplv_tasks SET slot=-1 WHERE id=?', 'args': [task[0]]})
            else:
                changes.append({'sql': "UPDATE uplv_reserves SET status='assigned' WHERE id=?", 'args': [reserve[0]]})
            self.store.batch(changes)
            return response

    @staticmethod
    def clean_rows(rows):
        if not isinstance(rows, dict) or len(rows) > 5:
            raise ValueError('Tối đa 5 kết quả/phòng')
        clean = {}
        for key, value in rows.items():
            if str(key) not in ('0', '1', '2', '3', '4') or not isinstance(value, dict):
                raise ValueError('Kết quả không hợp lệ')
            status = value.get('status')
            if status not in ('success', 'failed', 'pending'):
                raise ValueError('Trạng thái kết quả không hợp lệ')
            clean[str(key)] = {'status': status, 'level_before': max(0, min(30, int(value.get('level_before', 0)))),
                               'level_after': max(0, min(30, int(value.get('level_after', 0)))),
                               'verified': value.get('verified') is True, 'idle': value.get('idle') is True,
                               'screened': value.get('screened') is True,
                               'failure_kind': value.get('failure_kind') if value.get('failure_kind') in ('login', 'create_character', 'restricted') else ''}
        return clean

    def heartbeat(self, body):
        with self.lock:
            row = self.owned(body)
            self.check_versions(body)
            self.touch(body)
            if row[2] not in ('running', 'interrupted'):
                return {'ok': True, 'stop': True, 'lease_until': 0}
            # Progress is bounded, structured data; no password/error text.
            progress = {}
            for key, value in (body.get('progress') or {}).items():
                if str(key) not in ('0', '1', '2', '3', '4') or not isinstance(value, dict):
                    raise ValueError('Tiến độ không hợp lệ')
                progress[str(key)] = {
                    'stage': str(value.get('stage', ''))[:32],
                    'level': max(0, min(30, int(value.get('level', 0)))),
                    'elapsed': max(0, min(86400, int(value.get('elapsed', 0)))),
                    'detail': str(value.get('detail', ''))[:400]}
            results = json.loads(row[5])
            results.update(self.clean_rows(body.get('results', {})))
            until = time.time() + self.LEASE_SECONDS
            self.store.exec("UPDATE uplv_rooms SET status='running',lease_until=?,progress_json=?,results_json=? WHERE id=?",
                            (until, json.dumps(progress), json.dumps(results), body['room_id']))
            self.save_task_details(body['room_id'], progress, results)
            return {'ok': True, 'stop': bool(row[3]), 'lease_until': until}

    def report(self, body):
        with self.lock:
            row = self.owned(body)
            self.check_versions(body)
            if row[2] in ('done', 'stopped', 'failed', 'incomplete'):
                return {'ok': True, 'duplicate': True}
            results = json.loads(row[5])
            results.update(self.clean_rows(body.get('results', {})))
            for i in range(len(json.loads(row[4]))):
                results.setdefault(str(i), {'status': 'pending', 'level_before': 0, 'level_after': 0})
            pool_room = bool(self.room_tasks(body['room_id']))
            progress_row = self.store.fetchone('SELECT progress_json FROM uplv_rooms WHERE id=?', (body['room_id'],))
            self.save_task_details(body['room_id'], json.loads(progress_row[0]), results)
            # A worker shutdown is not an operator stop of the owning job.
            # Mixed-owner rooms can also be interrupted by a different job.
            job_state = self.store.fetchone('SELECT j.status FROM uplv_jobs j JOIN uplv_rooms r ON r.job_id=j.id WHERE r.id=?', (body['room_id'],))[0]
            state = ('stopped' if job_state == 'stopped' else
                     'incomplete' if row[3] or body.get('stopped') else 'done')
            if state == 'done' and any(r['status'] == 'pending' for r in results.values()):
                state = 'incomplete'
            elif state == 'done' and any(r['status'] == 'failed' for r in results.values()):
                state = 'failed'
            self.store.exec('UPDATE uplv_rooms SET status=?,results_json=?,lease_until=0 WHERE id=?',
                            (state, json.dumps(results), body['room_id']))
            self.pool_finish(body, results, bool(row[3] or body.get('stopped')))
            self.store.exec("UPDATE uplv_jobs SET status='done' WHERE id=(SELECT job_id FROM uplv_rooms WHERE id=?) "
                            "AND NOT EXISTS (SELECT 1 FROM uplv_rooms r WHERE r.job_id=uplv_jobs.id AND r.status IN ('pending','running','interrupted'))",
                             (body['room_id'],)) if not pool_room else None
            return {'ok': True}

    def save_logs(self, body):
        items = body.get('logs', [])
        if not isinstance(items, list) or len(items) > 300:
            raise ValueError('Tối đa 300 log/request')
        # Defense in depth: also redact credentials held in room/history.
        credentials = self.store.fetchone('SELECT accounts_json FROM uplv_rooms WHERE id=?', (body['room_id'],))
        secrets_to_hide = [s for a in json.loads(credentials[0]) for s in a if s]
        secrets_to_hide += [s for r in self.store.fetch('SELECT old_account_json FROM uplv_replacements WHERE room_id=?', (body['room_id'],)) for s in json.loads(r[0]) if s]
        statements = []
        now = time.time()
        for item in items:
            if not isinstance(item, dict) or not re.fullmatch(r'[a-f0-9]{32}', str(item.get('id', ''))):
                raise ValueError('Log id không hợp lệ')
            slot = int(item.get('slot', -1))
            if not -1 <= slot < 5:
                raise ValueError('Log slot không hợp lệ')
            message = str(item.get('text', ''))[:500]
            event_at = float(item.get('at', now))
            if not math.isfinite(event_at) or not now - 86400 <= event_at <= now + 300:
                event_at = now
            for secret in sorted(secrets_to_hide, key=len, reverse=True):
                message = message.replace(secret, '[REDACTED]')
            message = re.sub(r'(?i)(bearer\s+|(?:password|token|sso_key|access_token)\s*[=:]\s*)\S+', r'\1[REDACTED]', message)
            statements.append({'sql': 'INSERT INTO uplv_logs VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING',
                'args': [item['id'], body['satellite_id'], body['room_id'], event_at, event_at, slot, message]})
        if statements:
            self.store.batch(statements)
            self.store.exec('DELETE FROM uplv_logs WHERE satellite_id=? AND id NOT IN '
                '(SELECT id FROM uplv_logs WHERE satellite_id=? ORDER BY received_at DESC,id DESC LIMIT 1500)',
                (body['satellite_id'], body['satellite_id']))

    def discover_log_url(self, satellite):
        from satellite_keepawake import parse_satellite_targets
        from concurrent.futures import ThreadPoolExecutor
        targets = parse_satellite_targets(self.saved_targets())
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None
        def inspect(target):
            url = target['url'].rstrip('/')
            try:
                # Public health probes never carry the master token.
                with urllib.request.build_opener(NoRedirect).open(url + '/healthz', timeout=5) as response:
                    data = json.loads(response.read(16384))
                identity = str(data.get('id') or '')
                if data.get('service_type') == 'uplv' and re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', identity):
                    return identity, url
            except (OSError, ValueError):
                pass
            return None
        mappings = []
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(targets)))) as pool:
            mappings = [item for item in pool.map(inspect, targets) if item]
        if mappings:
            self.store.batch([{'sql': 'INSERT INTO app_settings (setting_key,setting_value) VALUES (?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value',
                              'args': ['uplv_log_url:' + identity, url]} for identity, url in mappings])
        return next((url for identity, url in mappings if identity == satellite), None)

    def logs(self, body, token=''):
        satellite = self.satellite_id(body)
        key = 'uplv_log_url:' + satellite
        if body.get('worker_url'):
            url = str(body['worker_url']).strip().rstrip('/')
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError('URL worker không hợp lệ')
            self.store.batch([{'sql': 'INSERT INTO app_settings (setting_key,setting_value) VALUES (?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value',
                               'args': [key, url]}])
        row = self.store.fetchone('SELECT setting_value FROM app_settings WHERE setting_key=?', (key,))
        if not row:
            discovered = self.discover_log_url(satellite)
            if not discovered:
                return {'ok': True, 'needs_url': True, 'logs': [], 'message': 'Không tìm thấy service trả đúng Worker ID trong danh sách URL UpLv; kiểm tra service offline hoặc URL chưa được lưu tại /admin.'}
            row = (discovered,)
        request = urllib.request.Request(row[0] + '/api/logs', headers={'Authorization': 'Bearer ' + token})
        # Never forward a master token through redirects to another origin.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args):
                return None
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=8) as response:
                payload = response.read(512001)
            if len(payload) > 512000:
                raise ValueError('Log response quá lớn')
            data = json.loads(payload)
            if data.get('satellite_id') and data['satellite_id'] != satellite:
                discovered = self.discover_log_url(satellite)
                if discovered and discovered != row[0]:
                    return self.logs({'satellite_id': satellite}, token)
                raise ValueError('URL log không khớp Worker ID')
            return {'ok': True, 'logs': data.get('logs', [])[:300]}
        except (OSError, ValueError) as exc:
            raise ValueError('Không lấy được log worker: ' + type(exc).__name__) from None

    def control(self, body):
        with self.lock:
            action = body.get('action')
            if action in ('pause', 'resume'):
                self.store.exec('UPDATE uplv_satellites SET paused=? WHERE id=?',
                                (int(action == 'pause'), self.satellite_id(body)))
            elif action == 'stop_job':
                job = str(body.get('job_id', ''))
                self.store.batch([
                    {'sql': "UPDATE uplv_jobs SET status='stopped' WHERE id=?", 'args': [job]},
                    {'sql': "UPDATE uplv_rooms SET stop_requested=1,status=CASE WHEN status='pending' THEN 'stopped' ELSE status END WHERE job_id=?", 'args': [job]},
                ])
                self.store.exec("UPDATE uplv_tasks SET status='stopped' WHERE job_id=? AND status IN ('screening','waiting','ready','verifying')", (job,))
                self.store.exec("UPDATE uplv_rooms SET stop_requested=1 WHERE id IN (SELECT room_id FROM uplv_tasks WHERE job_id=? AND status='assigned')", (job,))
            else:
                raise ValueError('action: pause/resume/stop_job')
            return {'ok': True}

    # ------------------------------------------------------------------
    # CheckPass mode: let UPLV satellites work as checkpass satellites
    # for a specific job chosen by the admin.
    # ------------------------------------------------------------------

    def checkpass_mode_status(self):
        """Return the current checkpass-mode setting for the UPLV group."""
        row = self.store.fetchone(
            "SELECT setting_value FROM app_settings WHERE setting_key='uplv_checkpass_job_id'")
        job_id_str = str(row[0]).strip() if row and row[0] else ''
        if not job_id_str:
            return {'ok': True, 'active': False, 'job_id': None}
        try:
            job_id = int(job_id_str)
        except (TypeError, ValueError):
            return {'ok': True, 'active': False, 'job_id': None}
        # Verify the job still exists and is open
        job_row = self.store.fetchone(
            "SELECT id, status, total FROM jobs WHERE id=?", (job_id,))
        if not job_row:
            return {'ok': True, 'active': True, 'job_id': job_id, 'job_status': 'not_found'}
        return {'ok': True, 'active': True, 'job_id': job_id,
                'job_status': job_row[1], 'job_total': job_row[2]}

    def checkpass_mode_set(self, body):
        """Admin sets or clears a checkpass job_id for the UPLV satellite group."""
        job_id = body.get('job_id')
        if job_id is None or job_id == '' or job_id is False:
            # Clear checkpass mode
            self.store.batch([{
                'sql': ("INSERT INTO app_settings (setting_key, setting_value) "
                        "VALUES ('uplv_checkpass_job_id', '') "
                        "ON CONFLICT(setting_key) DO UPDATE SET setting_value=''"),
                'args': [],
            }])
            return {'ok': True, 'active': False, 'job_id': None,
                    'message': 'Đã tắt chế độ CheckPass cho nhóm vệ tinh UpLv'}
        try:
            job_id = int(job_id)
        except (TypeError, ValueError):
            raise ValueError('job_id phải là số nguyên')
        if job_id <= 0:
            raise ValueError('job_id phải lớn hơn 0')
        # Verify the job exists
        job_row = self.store.fetchone(
            "SELECT id, status, total FROM jobs WHERE id=?", (job_id,))
        if not job_row:
            raise ValueError(f'Không tìm thấy job #{job_id}')
        if job_row[1] not in ('open', 'creating'):
            raise ValueError(f'Job #{job_id} có trạng thái "{job_row[1]}", cần trạng thái "open"')
        self.store.batch([{
            'sql': ("INSERT INTO app_settings (setting_key, setting_value) "
                    "VALUES ('uplv_checkpass_job_id', ?) "
                    "ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value"),
            'args': [str(job_id)],
        }])
        return {'ok': True, 'active': True, 'job_id': job_id,
                'job_status': job_row[1], 'job_total': job_row[2],
                'message': f'Đã bật chế độ CheckPass cho nhóm vệ tinh UpLv — job #{job_id} ({job_row[2]} acc)'}

    def checkpass_mode_claim(self, body):
        """UPLV satellite claims a checkpass chunk from the pinned job.

        Returns a chunk dict compatible with the normal checkpass claim format,
        or None if no work is available (or mode is off).
        """
        row = self.store.fetchone(
            "SELECT setting_value FROM app_settings WHERE setting_key='uplv_checkpass_job_id'")
        job_id_str = str(row[0]).strip() if row and row[0] else ''
        if not job_id_str:
            return {'ok': True, 'claim': None, 'reason': 'checkpass_mode_off'}
        try:
            job_id = int(job_id_str)
        except (TypeError, ValueError):
            return {'ok': True, 'claim': None, 'reason': 'invalid_job_id'}
        # Check job is still open
        job_row = self.store.fetchone(
            "SELECT status FROM jobs WHERE id=?", (job_id,))
        if not job_row or job_row[0] != 'open':
            return {'ok': True, 'claim': None, 'reason': 'job_not_open'}

        satellite_id = str(body.get('satellite_id', ''))
        if not satellite_id:
            raise ValueError('cần satellite_id')
        lease_minutes = 5.0
        try:
            lease_minutes = float(body.get('lease_minutes', 5))
        except (TypeError, ValueError):
            pass
        lease_minutes = min(max(lease_minutes, 1), 15)
        now = time.time()
        # Find a pending or expired-lease chunk from the specific job
        chunk = self.store.fetchone(
            "SELECT id, account FROM chunks "
            "WHERE job_id=? AND (status='pending' OR (status='claimed' AND lease_until < ?)) "
            "ORDER BY id LIMIT 1",
            (job_id, now))
        if not chunk:
            return {'ok': True, 'claim': None, 'reason': 'no_pending_chunks'}
        chunk_id, account_data = chunk
        # Atomic claim
        self.store.exec(
            "UPDATE chunks SET status='claimed', satellite_id=?, claimed_at=?, lease_until=? "
            "WHERE id=? AND (status='pending' OR (status='claimed' AND lease_until < ?))",
            (satellite_id, now, now + lease_minutes * 60, chunk_id, now))
        verify = self.store.fetchone("SELECT satellite_id FROM chunks WHERE id=?", (chunk_id,))
        if not verify or verify[0] != satellite_id:
            return {'ok': True, 'claim': None, 'reason': 'claim_race_lost'}
        try:
            accounts = json.loads(account_data)
        except (json.JSONDecodeError, TypeError):
            accounts = [account_data] if account_data else []
        return {'ok': True, 'claim': {
            'chunk_id': chunk_id,
            'job_id': job_id,
            'queue_type': 'uplv_checkpass',
            'lease_until': now + lease_minutes * 60,
            'accounts': accounts,
        }}

    def snapshot(self):
        with self.lock:
            self.expire(throttled=True)
        # Read-only queries run outside the coordinator lock so worker
        # heartbeats are not blocked while a dashboard renders.
        job_rows = self.store.fetch('SELECT id,created_at,target,mode,status FROM uplv_jobs ORDER BY created_at DESC LIMIT 50')
        # Aggregate only over the 50 listed jobs; history grows without bound.
        job_ids = tuple(job[0] for job in job_rows)
        marks = ','.join('?' for _ in job_ids)
        replacements, reserves_by_job, owners, counts_by_job, room_rows = {}, {}, {}, {}, []
        if job_ids:
            replacements = dict(self.store.fetch(
                f'SELECT p.room_id,COUNT(*) FROM uplv_replacements p JOIN uplv_rooms r ON r.id=p.room_id WHERE r.job_id IN ({marks}) GROUP BY p.room_id', job_ids))
            reserves_by_job = dict(self.store.fetch(
                f"SELECT job_id,COUNT(*) FROM uplv_reserves WHERE status='pending' AND job_id IN ({marks}) GROUP BY job_id", job_ids))
            owners = dict(self.store.fetch(f'SELECT job_id,user_id FROM uplv_job_owners WHERE job_id IN ({marks})', job_ids))
            for job_id, status, count in self.store.fetch(
                    f'SELECT job_id,status,COUNT(*) FROM uplv_tasks WHERE job_id IN ({marks}) GROUP BY job_id,status', job_ids):
                counts_by_job.setdefault(job_id, {})[status] = count
            room_rows = self.store.fetch(
                'SELECT id,ordinal,accounts_json,status,satellite_id,lease_until,progress_json,results_json,job_id '
                f'FROM uplv_rooms WHERE job_id IN ({marks}) ORDER BY ordinal', job_ids)
        rooms_by_job = {}
        for r in room_rows:
            rooms_by_job.setdefault(r[8], []).append({'id': r[0], 'ordinal': r[1],
                'users': [a[0] for a in json.loads(r[2])], 'status': r[3],
                'satellite_id': r[4], 'lease_until': r[5], 'progress': json.loads(r[6]),
                'results': json.loads(r[7]), 'replaced_failed': replacements.get(r[0], 0)})
        satellites = [{'id': r[0], 'last_seen': r[1], 'online': time.time() - r[1] < 90,
                       'paused': bool(r[2]), 'metrics': json.loads(r[3]), 'service_type': 'uplv'}
                      for r in self.store.fetch('SELECT id,last_seen,paused,metrics_json FROM uplv_satellites ORDER BY id')]
        jobs = []
        for job in job_rows:
            rooms = rooms_by_job.get(job[0], [])
            reserves = reserves_by_job.get(job[0], 0)
            jobs.append({'id': job[0], 'created_at': job[1], 'target': job[2], 'mode': job[3], 'status': job[4], 'rooms': rooms, 'reserves': reserves})
        for job in jobs:
            job['task_counts'] = counts_by_job.get(job['id'], {})
            job['owner_user_id'] = owners.get(job['id'])
        return {'ok': True, 'satellites': satellites, 'jobs': jobs, 'pool': self.pool_snapshot(), 'targets': self.saved_targets(), 'clear': dict(self.clear_state), 'user_limits': self.user_limits(), 'checkpass_mode': self.checkpass_mode_status()}

    def export(self, job):
        if self.pool_job(job):
            groups = {'success': [], 'failed': [], 'pending': []}
            for account, state in self.store.fetch('SELECT account_json,status FROM uplv_tasks WHERE job_id=? ORDER BY created_at', (job,)):
                user, password = json.loads(account)
                groups[state if state in ('success', 'failed') else 'pending'].append(f'{user}|{password}')
            return {'ok': True, **{key: '\n'.join(value) for key, value in groups.items()}}
        rows = self.store.fetch('SELECT accounts_json,results_json FROM uplv_rooms WHERE job_id=? ORDER BY ordinal', (job,))
        groups = {'success': [], 'failed': [], 'pending': []}
        for account, result in self.store.fetch('SELECT p.old_account_json,p.result_json FROM uplv_replacements p JOIN uplv_rooms r ON r.id=p.room_id WHERE r.job_id=?', (job,)):
            user, password = json.loads(account)
            groups[json.loads(result)['status']].append(f'{user}|{password}')
        for account, in self.store.fetch("SELECT account_json FROM uplv_reserves WHERE job_id=? AND status='pending'", (job,)):
            user, password = json.loads(account)
            groups['pending'].append(f'{user}|{password}')
        for accounts, results in rows:
            results = json.loads(results)
            for i, (user, password) in enumerate(json.loads(accounts)):
                result = results.get(str(i), {})
                groups[result.get('status', 'pending')].append(f'{user}|{password}')
        return {'ok': True, **{key: '\n'.join(value) for key, value in groups.items()}}
