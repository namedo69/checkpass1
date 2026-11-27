"""Account-owned work queue; rooms are temporary leases of five tasks."""
import json
import time
import uuid
import re
from uplv_failure_policy import terminal_account_failure


class AccountPool:
    RATE_LIMIT_DELAY = 30
    VERIFY_DELAY = 30
    # Conservative scheduling policy, not a claimed game-server session TTL.
    SESSION_WAIT_DELAYS = (30,)
    SESSION_WAIT_MAX_CHECKS = 6
    SESSION_WAIT_MAX_SECONDS = 2 * 60 * 60

    @staticmethod
    def screening_evidence(result, legacy=False):
        """Separate unreadable profiles from missing roles and explicit bans."""
        status = str(result.get('check_status' if legacy else 'status', '')).strip().casefold()
        kind = str(result.get('check_result' if legacy else 'result_type', '')).strip().casefold()
        player = str(result.get('check_player_status' if legacy else 'player_status', '')).strip().casefold()
        banned = (player in ('bị khóa', 'banned', 'ban')
                  or status in ('ban', 'banned')
                  or bool(result.get('banTime') or result.get('unbanTime')))
        raw = result.get('level')
        value = '' if raw is None else str(raw).strip()
        level = int(value) if type(raw) is not bool and value.isdigit() and 1 <= int(value) <= 30 else None
        unknown = (status == 'ok' and kind == 'lỗi ctnv'
                   and not value and not banned
                   and str(result.get('tcp_login_ok', '')).strip() not in ('0', 'False', 'false'))
        return level, unknown, banned

    def init_pool(self):
        for sql in (
            "CREATE TABLE IF NOT EXISTS uplv_tasks (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, username_key TEXT NOT NULL, account_json TEXT NOT NULL, target INTEGER NOT NULL, mode TEXT NOT NULL, level INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, room_id TEXT NOT NULL DEFAULT '', slot INTEGER NOT NULL DEFAULT -1, created_at DOUBLE PRECISION NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_tasks_queue ON uplv_tasks(status,level,mode,created_at)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_tasks_room ON uplv_tasks(room_id,slot)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_tasks_job_status ON uplv_tasks(job_id,status)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_tasks_fifo ON uplv_tasks(status,created_at,id)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_tasks_mode_fifo ON uplv_tasks(status,mode,created_at,id)",
            "CREATE TABLE IF NOT EXISTS uplv_pool_jobs (job_id TEXT PRIMARY KEY)",
            "CREATE TABLE IF NOT EXISTS uplv_job_owners (job_id TEXT PRIMARY KEY, user_id BIGINT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_job_owner ON uplv_job_owners(user_id)",
            "CREATE TABLE IF NOT EXISTS uplv_verify_attempts (task_id TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, next_at DOUBLE PRECISION NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS uplv_session_wait (task_id TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, started_at DOUBLE PRECISION NOT NULL, next_at DOUBLE PRECISION NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_session_wait_due ON uplv_session_wait(next_at)",
            "CREATE TABLE IF NOT EXISTS uplv_rate_limit_wait (task_id TEXT PRIMARY KEY, attempts INTEGER NOT NULL, started_at DOUBLE PRECISION NOT NULL, next_at DOUBLE PRECISION NOT NULL, resume_state TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_rate_limit_due ON uplv_rate_limit_wait(next_at)",
            "CREATE TABLE IF NOT EXISTS uplv_retry_wait (task_id TEXT PRIMARY KEY, attempts INTEGER NOT NULL, next_at DOUBLE PRECISION NOT NULL, resume_state TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_retry_due ON uplv_retry_wait(next_at)",
            "CREATE TABLE IF NOT EXISTS uplv_auth_cooldown (id TEXT PRIMARY KEY, until_at DOUBLE PRECISION NOT NULL, pace_until DOUBLE PRECISION NOT NULL, next_admit DOUBLE PRECISION NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_verify_rooms (room_id TEXT PRIMARY KEY)",
            "CREATE TABLE IF NOT EXISTS uplv_screen_rooms (room_id TEXT PRIMARY KEY)",
            "CREATE TABLE IF NOT EXISTS uplv_room_history (id TEXT PRIMARY KEY, room_id TEXT NOT NULL, finished_at DOUBLE PRECISION NOT NULL, snapshot_json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_task_details (task_id TEXT PRIMARY KEY, updated_at DOUBLE PRECISION NOT NULL, detail_json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_check_leases (task_id TEXT PRIMARY KEY, satellite_id TEXT NOT NULL, token TEXT NOT NULL, lease_until DOUBLE PRECISION NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS uplv_claim_requests (id TEXT PRIMARY KEY, satellite_id TEXT NOT NULL, room_id TEXT NOT NULL, token TEXT NOT NULL, response_json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS uplv_check_chunks (id TEXT PRIMARY KEY, job_id TEXT NOT NULL, tasks_json TEXT NOT NULL, status TEXT NOT NULL, satellite_id TEXT NOT NULL DEFAULT '', token TEXT NOT NULL DEFAULT '', lease_until DOUBLE PRECISION NOT NULL DEFAULT 0)",
            "CREATE TABLE IF NOT EXISTS uplv_check_members (task_id TEXT PRIMARY KEY, chunk_id TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_check_members_chunk ON uplv_check_members(chunk_id)",
            "CREATE INDEX IF NOT EXISTS idx_uplv_check_chunk_status_lease ON uplv_check_chunks(status,lease_until)",
        ):
            self.store.exec(sql)
        migration = []
        for chunk, raw in self.store.fetch("SELECT id,tasks_json FROM uplv_check_chunks WHERE status='claimed'"):
            for item in json.loads(raw):
                migration.append({'sql': 'INSERT INTO uplv_check_members VALUES (?,?) ON CONFLICT(task_id) DO UPDATE SET chunk_id=excluded.chunk_id', 'args': [item['task_id'], chunk]})
        if migration:
            self.store.batch(migration)

    def pool_job(self, job):
        return self.store.fetchone('SELECT job_id FROM uplv_pool_jobs WHERE job_id=?', (job,)) is not None

    def user_limits(self):
        defaults = {'max_accounts_per_job': 1000, 'max_jobs_per_user': 1, 'max_system_jobs': 20}
        for key in defaults:
            row = self.store.fetchone('SELECT setting_value FROM app_settings WHERE setting_key=?', ('uplv_user_' + key,))
            if row:
                defaults[key] = int(row[0])
        return defaults

    def save_user_limits(self, body):
        limits = self.user_limits()
        for key in limits:
            value = int(body.get(key, limits[key]))
            if not 1 <= value <= 100000:
                raise ValueError('Hạn mức phải từ 1 đến 100.000')
            limits[key] = value
        with self.lock:
            self.store.batch([{'sql': 'INSERT INTO app_settings (setting_key,setting_value) VALUES (?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value', 'args': ['uplv_user_' + k, str(v)]} for k, v in limits.items()])
        return {'ok': True, 'limits': limits}

    def user_action(self, action, body, auth):
        user = int(auth.get('user_id') or 0)
        if user <= 0:
            raise ValueError('Vui lòng đăng nhập tài khoản SP1S')
        with self.lock:
            if action == 'jobs':
                jobs = []
                for job in self.store.fetch('SELECT j.id,j.created_at,j.target,j.mode,j.status FROM uplv_jobs j JOIN uplv_job_owners o ON o.job_id=j.id WHERE o.user_id=? ORDER BY j.created_at DESC LIMIT 100', (user,)):
                    counts = dict(self.store.fetch('SELECT status,COUNT(*) FROM uplv_tasks WHERE job_id=? GROUP BY status', (job[0],)))
                    jobs.append(dict(zip(('id','created_at','target','mode','status'), job), task_counts=counts))
                return {'ok': True, 'jobs': jobs, 'limits': self.user_limits(), 'user': {'name': auth.get('name', '')}}
            if action == 'create':
                limits = self.user_limits()
                accounts = self.parse_accounts(body.get('accounts', ''))
                if not auth.get('is_admin') and len(accounts) > limits['max_accounts_per_job']:
                    raise ValueError('Vượt số tài khoản tối đa mỗi job')
                active = self.store.fetchone("SELECT COUNT(*) FROM uplv_jobs j JOIN uplv_job_owners o ON o.job_id=j.id WHERE o.user_id=? AND j.status='open'", (user,))[0]
                if not auth.get('is_admin') and active >= limits['max_jobs_per_user']:
                    raise ValueError('Đã đạt số job đang mở tối đa của bạn')
                if not auth.get('is_admin') and self.store.fetchone("SELECT COUNT(*) FROM uplv_jobs WHERE status='open'")[0] >= limits['max_system_jobs']:
                    raise ValueError('Hệ thống đã đủ số job đang mở; vui lòng chờ')
                result = self.pool_create({'accounts': body.get('accounts', ''), 'target': body.get('target', 12), 'mode': body.get('mode', 'victory'), '_owner_user_id': user})
                return result
            job = str(body.get('job_id', ''))
            owner = self.store.fetchone('SELECT user_id FROM uplv_job_owners WHERE job_id=?', (job,))
            if not owner or int(owner[0]) != user:
                raise ValueError('Không tìm thấy job của bạn')
            if action == 'accounts':
                result = self.account_details(body)
                allowed = ('id','username','status','level','target','mode','attempts','next_retry_at',
                           'session_wait_attempts','session_wait_deadline','session_wait_active','rate_limit_attempts','retry_attempts')
                result['accounts'] = [{k: row[k] for k in allowed} for row in result['accounts']]
                return result
            if action == 'export':
                return self.export(job)
            if action == 'stop':
                # Cross-user rooms are temporary teams; stop only this owner's
                # jobs. Other occupants are requeued for continued processing.
                return self.control({'action': 'stop_job', 'job_id': job})
            raise ValueError('Thao tác không hợp lệ')

    def hidden_check_claim(self, body):
        # Compatibility for old CheckPass workers: finish existing reports,
        # but never take new UpLv accounts away from game workers.
        self.satellite_id(body)
        return None

    def hidden_check_report(self, body):
        with self.lock:
            chunk = self.store.fetchone('SELECT tasks_json,satellite_id,token,status FROM uplv_check_chunks WHERE id=?', (str(body.get('chunk_id', '')),))
            if not chunk or chunk[1] != self.satellite_id(body) or chunk[2] != str(body.get('lease_token', '')):
                raise ValueError('Screening chunk lease không hợp lệ')
            if chunk[3] == 'done':
                return {'ok': True, 'duplicate': True}
            items = json.loads(chunk[0])
            changes = []
            if not body.get('done'):
                changes.append({'sql': 'UPDATE uplv_check_chunks SET lease_until=? WHERE id=?', 'args': [time.time() + 300, body['chunk_id']]})
            for result in body.get('rows', []):
                try:
                    index = int(result.get('stt', 0)) - 1
                except (TypeError, ValueError):
                    continue
                if not 0 <= index < len(items):
                    continue
                item = items[index]
                value = str(result.get('level', '')).strip()
                level, unknown, banned = self.screening_evidence(result)
                missing = value.casefold() == 'ctnv' and result.get('player_status') == 'Chưa tạo nhân vật'
                task = self.store.fetchone('SELECT status,target,job_id FROM uplv_tasks WHERE id=?', (item['task_id'],))
                if not task or task[0] != 'screening':
                    continue
                job = self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (task[2],))
                if not job or job[0] != 'open':
                    continue
                if banned:
                    changes.append({'sql': "UPDATE uplv_tasks SET status='failed' WHERE id=?", 'args': [item['task_id']]})
                elif unknown:
                    # Keep the unconfirmed level untouched. UpLv must read the
                    # live profile; creating still requires server csid 1007.
                    changes.append({'sql': "UPDATE uplv_tasks SET status='waiting' WHERE id=?", 'args': [item['task_id']]})
                elif level is not None or missing:
                    level = level or 0
                    state = 'success' if level >= task[1] else 'waiting' if level < 5 else 'ready'
                    changes.append({'sql': 'UPDATE uplv_tasks SET status=?,level=? WHERE id=?', 'args': [state, level, item['task_id']]})
                detail = ({'stage': 'CHECKPASS_BANNED', 'detail': 'CheckPass có bằng chứng khóa; không chuyển UpLv'} if banned else
                          {'stage': 'UPLV_PROFILE_PENDING', 'detail': 'OK / Lỗi CTNV: chuyển UpLv đọc profile và OAuth V2; chưa xác nhận cấp hoặc thiếu nhân vật', 'level_confirmed': False} if unknown else
                          {'stage': 'CHECKPASS_DONE' if level is not None or missing else 'CHECKPASS_RETRY', 'detail': 'CheckPass trả kết quả qua chunk nội bộ' if level is not None or missing else 'Chưa đọc được cấp; chờ chunk kiểm tra tiếp'})
                changes.append({'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [item['task_id'], time.time(), json.dumps(detail)]})
            if body.get('done'):
                changes.append({'sql': "UPDATE uplv_check_chunks SET status='done',lease_until=0 WHERE id=?", 'args': [body['chunk_id']]})
            self.store.batch(changes)
            self.store.exec("UPDATE uplv_jobs SET status='done' WHERE status='open' AND id IN (SELECT job_id FROM uplv_pool_jobs) AND NOT EXISTS (SELECT 1 FROM uplv_tasks t WHERE t.job_id=uplv_jobs.id AND t.status NOT IN ('success','failed','stopped'))")
            return {'ok': True}

    def checkpass_claim(self, body):
        self.satellite_id(body)
        return {'ok': True, 'check': None}

    def checkpass_report(self, body):
        import secrets
        satellite = self.satellite_id(body)
        rows = body.get('rows', [])
        if not isinstance(rows, list) or len(rows) > 5:
            raise ValueError('Tối đa 5 kết quả screening')
        with self.lock:
            changes = []
            for result in rows:
                task = str(result.get('task_id', ''))
                owned = self.store.fetchone('SELECT c.satellite_id,c.token,t.status,t.target,t.job_id FROM uplv_check_leases c JOIN uplv_tasks t ON t.id=c.task_id WHERE c.task_id=?', (task,))
                if not owned or owned[0] != satellite or not secrets.compare_digest(owned[1], str(body.get('token', ''))):
                    raise ValueError('Screening lease không hợp lệ')
                if owned[2] != 'screening':
                    continue
                job = self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (owned[4],))
                if job[0] != 'open':
                    continue
                level, unknown, banned = self.screening_evidence(result, legacy=True)
                valid = type(level) is int and 1 <= level <= 30
                missing = result.get('no_character') is True
                if banned or unknown:
                    state = 'failed' if banned else 'waiting'
                    detail = ({'stage': 'CHECKPASS_BANNED', 'detail': 'CheckPass có bằng chứng khóa; không chuyển UpLv'} if banned else
                              {'stage': 'UPLV_PROFILE_PENDING', 'detail': 'OK / Lỗi CTNV: chuyển UpLv đọc profile và OAuth V2; chưa xác nhận cấp hoặc thiếu nhân vật', 'level_confirmed': False})
                    changes += [
                        {'sql': 'UPDATE uplv_tasks SET status=? WHERE id=?', 'args': [state, task]},
                        {'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, time.time(), json.dumps(detail)]},
                    ]
                    continue
                if not valid and not missing:
                    diagnostic = 'CheckPass chưa trả cấp hợp lệ; chờ 1 giây trước khi kiểm tra lại'
                    for field in ('check_status', 'check_result', 'check_stage', 'check_code'):
                        value = str(result.get(field, ''))[:80]
                        # Diagnostics are redacted against this task's credentials.
                        credentials = self.store.fetchone('SELECT account_json FROM uplv_tasks WHERE id=?', (task,))
                        for secret in json.loads(credentials[0]):
                            if secret:
                                value = value.replace(secret, '[REDACTED]')
                        if value:
                            diagnostic += ' · ' + value
                    changes.append({'sql': 'UPDATE uplv_check_leases SET lease_until=? WHERE task_id=?', 'args': [time.time() + 1, task]})
                    changes.append({'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, time.time(), json.dumps({'stage': 'CHECKPASS_RETRY', 'detail': diagnostic})]})
                    continue
                level = level if valid else 0
                state = 'success' if level >= owned[3] else 'waiting' if level < 5 else 'ready'
                # This is a candidate team, not proof of idle. The UpLv engine
                # must check game state before starting any new match.
                changes += [
                    {'sql': 'UPDATE uplv_tasks SET status=?,level=? WHERE id=?', 'args': [state, level, task]},
                    {'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, time.time(), json.dumps({'stage': 'CHECKPASS_DONE', 'detail': 'CheckPass xác nhận chưa có nhân vật' if missing and not valid else 'CheckPass đã xác minh cấp Kiện Tướng'})]},
                ]
            self.store.batch(changes)
            self.store.exec("UPDATE uplv_jobs SET status='done' WHERE status='open' AND id IN (SELECT job_id FROM uplv_pool_jobs) AND NOT EXISTS (SELECT 1 FROM uplv_tasks t WHERE t.job_id=uplv_jobs.id AND t.status NOT IN ('success','failed','stopped'))")
            return {'ok': True}

    def account_details(self, body):
        job = str(body.get('job_id', ''))
        page = max(1, int(body.get('page', 1)))
        size = max(1, min(100, int(body.get('page_size', 50))))
        state = str(body.get('status', ''))
        query = str(body.get('search', '')).casefold()[:100]
        with self.lock:
            if not self.pool_job(job):
                raise ValueError('Job không có dữ liệu tài khoản pool')
            where, params = 't.job_id=?', [job]
            if state:
                where += ' AND t.status=?'
                params.append(state)
            if query:
                where += ' AND t.username_key LIKE ?'
                params.append('%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
                # Explicit escape is portable to SQLite/PostgreSQL.
                where += " ESCAPE '\\'"
            total = self.store.fetchone('SELECT COUNT(*) FROM uplv_tasks t WHERE ' + where, tuple(params))[0]
            page = min(page, max(1, (total + size - 1) // size))
            rows = self.store.fetch('SELECT t.id,t.account_json,t.status,t.level,t.target,t.mode,t.room_id,t.slot,d.updated_at,d.detail_json,v.attempts,v.next_at,w.attempts,w.started_at,w.next_at,r.attempts,r.next_at,q.attempts,q.next_at FROM uplv_tasks t LEFT JOIN uplv_task_details d ON d.task_id=t.id LEFT JOIN uplv_verify_attempts v ON v.task_id=t.id LEFT JOIN uplv_session_wait w ON w.task_id=t.id LEFT JOIN uplv_rate_limit_wait r ON r.task_id=t.id LEFT JOIN uplv_retry_wait q ON q.task_id=t.id WHERE ' + where + ' ORDER BY t.created_at,t.id LIMIT ? OFFSET ?', tuple(params + [size, (page - 1) * size]))
            rooms = {r[0]: r for r in self.store.fetch('SELECT id,ordinal,satellite_id,status,progress_json FROM uplv_rooms')}
            accounts = []
            for task, credentials, status, level, target, mode, room, slot, updated, detail, attempts, next_at, wait_attempts, wait_started, wait_next, rate_attempts, rate_next, retry_attempts, retry_next in rows:
                user = json.loads(credentials)[0]
                saved = json.loads(detail) if detail else {}
                current = rooms.get(room) if status == 'assigned' else None
                progress = json.loads(current[4]).get(str(slot), {}) if current else {}
                accounts.append({'id': task, 'username': user, 'status': status,
                    'level': max(level, int(progress.get('level', 0))), 'target': target, 'mode': mode,
                    'stage': progress.get('stage') or saved.get('stage', ''),
                    'detail': saved.get('detail', ''),
                    'elapsed': progress.get('elapsed', 0) if current else 0,
                    'room': current[1] if current else None, 'room_status': current[3] if current else '',
                    'satellite_id': current[2] if current else '', 'updated_at': updated,
                    'attempts': attempts or 0, 'next_retry_at': (retry_next if status == 'retry_wait' else rate_next if status == 'rate_limit_wait' else wait_next if status == 'session_wait' else next_at) or 0,
                    'rate_limit_attempts': rate_attempts or 0,
                    'retry_attempts': retry_attempts or 0,
                    'session_wait_active': wait_started is not None and status not in ('success','failed','stopped'),
                    'session_wait_attempts': wait_attempts or 0,
                    'session_wait_deadline': 0})
            return {'ok': True, 'accounts': accounts, 'total': total, 'page': page, 'page_size': size}

    def save_task_details(self, room, progress, results=None, defer=False):
        changes = []
        previous = dict(self.store.fetch('SELECT d.task_id,d.detail_json FROM uplv_task_details d JOIN uplv_tasks t ON t.id=d.task_id WHERE t.room_id=? AND t.slot>=0', (room,)))
        for task, _, credentials, _, _, slot, _ in self.room_tasks(room):
            old = previous.get(task)
            data = json.loads(old) if old else {}
            incoming = progress.get(str(slot), {})
            data.update({k: v for k, v in incoming.items() if v != '' and k != 'elapsed'})
            if results and str(slot) in results:
                result = results[str(slot)]
                data['result'] = result['status']
                data['last_check'] = {'verified': result.get('verified') is True,
                                      'idle': result.get('idle') is True,
                                      'failure_kind': result.get('failure_kind', '')}
                if result.get('final_error'):
                    data.update(detail=result['final_error'], final_error=result['final_error'],
                                failure_kind=result.get('failure_kind', ''),
                                error_stage=result.get('error_stage', ''))
                elif 'failure_kind' in result:
                    if data.get('final_error'):
                        data['previous_error'] = data['final_error']
                        if data.get('detail') == data['final_error']:
                            data['detail'] = 'Lượt đọc mới không có mã từ chối; xem last_check để biết kết quả đối soát'
                    data.update(final_error='', failure_kind='',
                                error_stage=result.get('error_stage', ''))
                if result.get('root_cause'):
                    data['root_cause'] = result['root_cause']
            # Structured diagnostics only; redact this occupant's credentials.
            for key in ('detail', 'final_error', 'previous_error', 'root_cause', 'error_stage'):
                if key not in data:
                    continue
                text = str(data[key])
                for secret in sorted(json.loads(credentials), key=len, reverse=True):
                    if secret:
                        text = text.replace(secret, '[REDACTED]')
                text = re.sub(r'(?i)(bearer\s+|(?:password|token|sso_key|access_token)\s*[=:]\s*)\S+', r'\1[REDACTED]', text)
                data[key] = text[:400]
            if old and json.loads(old) == data:
                continue
            changes.append({'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, time.time(), json.dumps(data)]})
        if changes and not defer:
            self.store.batch(changes)
        return changes

    def room_tasks(self, room):
        return self.store.fetch('SELECT id,job_id,account_json,target,level,slot,status FROM uplv_tasks WHERE room_id=? AND slot>=0 ORDER BY slot', (room,))

    def pool_create(self, body):
        target, mode = int(body.get('target', 12)), str(body.get('mode', 'victory'))
        if not 6 <= target <= 30 or mode not in ('victory', 'defeat', 'surrender'):
            raise ValueError('Mục tiêu Lv6–30; mode victory/defeat/surrender')
        accounts = self.parse_accounts(body.get('accounts', '')) + self.parse_accounts(body.get('reserves', ''))
        if not accounts or len({a[0].casefold() for a in accounts}) != len(accounts):
            raise ValueError('Cần ít nhất 1 acc, không trùng')
        job = uuid.uuid4().hex
        with self.lock:
            if self.clear_state['running']:
                raise ValueError('Đang clear dữ liệu UpLv; chờ hoàn tất trước khi tạo job')
            self.assert_accounts_available(accounts)
            statements = [
                {'sql': 'INSERT INTO uplv_jobs VALUES (?,?,?,?,?)', 'args': [job, time.time(), target, mode, 'open']},
                {'sql': 'INSERT INTO uplv_pool_jobs VALUES (?)', 'args': [job]},
            ]
            statements += self.task_inserts(job, accounts, target, mode)
            if body.get('_owner_user_id'):
                statements.append({'sql': 'INSERT INTO uplv_job_owners VALUES (?,?)', 'args': [job, int(body['_owner_user_id'])]})
            self.store.batch(statements)
        return {'ok': True, 'job_id': job, 'rooms': 0, 'screening_accounts': 0,
                'waiting_accounts': len(accounts), 'profile_source': 'game'}

    def assert_accounts_available(self, accounts, job=None):
        keys = {a[0].casefold() for a in accounts}
        occupied = {r[0] for r in self.store.fetch("SELECT username_key FROM uplv_tasks WHERE status NOT IN ('success','failed','stopped')")}
        occupied.update(a[0].casefold() for r in self.store.fetch("SELECT accounts_json FROM uplv_rooms WHERE status IN ('pending','running','interrupted')") for a in json.loads(r[0]))
        occupied.update(json.loads(r[0])[0].casefold() for r in self.store.fetch("SELECT account_json FROM uplv_reserves WHERE status='pending'"))
        if job:
            occupied.update(r[0] for r in self.store.fetch('SELECT username_key FROM uplv_tasks WHERE job_id=?', (job,)))
        if keys.intersection(occupied):
            raise ValueError('Acc đã dùng trong job hoặc đang thuộc công việc khác')

    @staticmethod
    def task_inserts(job, accounts, target, mode):
        now = time.time()
        return [{'sql': 'INSERT INTO uplv_tasks (id,job_id,username_key,account_json,target,mode,status,created_at) VALUES (?,?,?,?,?,?,?,?)',
                 'args': [uuid.uuid4().hex, job, a[0].casefold(), json.dumps(a), target, mode, 'waiting', now + i * .000001]}
                for i, a in enumerate(accounts)]

    def pool_add(self, body):
        job = str(body.get('job_id', ''))
        accounts = self.parse_accounts(body.get('accounts', ''))
        if not accounts:
            raise ValueError('Cần ít nhất 1 acc')
        with self.lock:
            row = self.store.fetchone('SELECT target,mode,status FROM uplv_jobs WHERE id=?', (job,))
            if not row or row[2] != 'open':
                raise ValueError('Job không còn mở')
            self.assert_accounts_available(accounts, job)
            self.store.batch(self.task_inserts(job, accounts, row[0], row[1]))
        return {'ok': True, 'added': len(accounts)}

    def pool_limit(self):
        row = self.store.fetchone("SELECT setting_value FROM app_settings WHERE setting_key='uplv_max_rooms'")
        return int(row[0]) if row else 10

    def pool_settings(self, body):
        value = int(body.get('max_rooms', 10))
        if not 0 <= value <= 1000:
            raise ValueError('Giới hạn phòng: 0–1.000')
        with self.lock:
            active = self.store.fetchone("SELECT COUNT(*) FROM uplv_rooms WHERE status IN ('pending','running','interrupted')")[0]
            if value and active > value:
                raise ValueError('Cần chờ số phòng đang xử lý giảm trước khi thu gọn ô phòng')
            # Compact completed pool-only records left by the old append-only
            # scheduler. Account results stay in tasks; legacy jobs retain their
            # room records until explicitly migrated to account-owned results.
            if value:
                rooms = self.store.fetch("SELECT r.id,r.job_id,r.ordinal,r.accounts_json,r.status,r.results_json FROM uplv_rooms r JOIN uplv_pool_jobs p ON p.job_id=r.job_id WHERE r.status NOT IN ('pending','running','interrupted') ORDER BY r.ordinal")
                for room, job, ordinal, accounts, state, results in rooms:
                    self.store.batch([
                        {'sql': 'INSERT INTO uplv_room_history VALUES (?,?,?,?)', 'args': [uuid.uuid4().hex, room, time.time(), json.dumps({'job_id': job, 'ordinal': ordinal, 'users': [a[0] for a in json.loads(accounts)], 'status': state, 'results': json.loads(results)})]},
                        {'sql': "UPDATE uplv_tasks SET room_id='',slot=-1 WHERE room_id=?", 'args': [room]},
                        *[{'sql': f'DELETE FROM {table} WHERE room_id=?', 'args': [room]} for table in ('uplv_verify_rooms', 'uplv_screen_rooms', 'uplv_room_versions', 'uplv_replacements')],
                        {'sql': 'DELETE FROM uplv_rooms WHERE id=?', 'args': [room]},
                    ])
                # Ordinals are global slot numbers, including migrated active
                # rooms. Changing the label does not change ownership or token.
                active_rooms = self.store.fetch("SELECT id FROM uplv_rooms ORDER BY ordinal,id")
                for number, (room,) in enumerate(active_rooms, 1):
                    self.store.exec('UPDATE uplv_rooms SET ordinal=? WHERE id=?', (number, room))
            self.store.batch([{'sql': "INSERT INTO app_settings VALUES ('uplv_max_rooms',?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value", 'args': [str(value)]}])
        return {'ok': True, 'max_rooms': value}

    def pool_form_room(self):
        if self.auth_admission_blocked():
            return None
        self.release_rate_limit_wait()
        self.release_retry_wait()
        self.release_legacy_screening()
        # Give due inspection work a turn before new battles; otherwise a
        # large ready pool can starve interrupted accounts indefinitely.
        if time.monotonic() - getattr(self, '_verification_turn', 0) >= 5:
            verification = self.pool_verification_room()
            if verification:
                self._verification_turn = time.monotonic()
                return verification
        # Prioritize five idle, previously-run accounts of the same level/mode.
        group = self.store.fetchone("SELECT t.level,t.mode FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status='ready' AND j.status='open' GROUP BY t.level,t.mode HAVING COUNT(*)>=5 ORDER BY MIN(t.created_at) LIMIT 1")
        if group:
            selected = self.store.fetch("SELECT t.id,t.job_id,t.account_json FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status='ready' AND t.level=? AND t.mode=? AND j.status='open' ORDER BY t.created_at LIMIT 5", group)
        else:
            # Prefer same-level teams, but do not idle the fleet solely because
            # confirmed-idle unfinished accounts are split across levels.
            mixed = self.store.fetchone("SELECT t.mode FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status='ready' AND j.status='open' GROUP BY t.mode HAVING COUNT(*)>=5 ORDER BY MIN(t.created_at) LIMIT 1")
            if mixed:
                selected = self.store.fetch("SELECT t.id,t.job_id,t.account_json FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status='ready' AND t.mode=? AND j.status='open' ORDER BY t.level DESC,t.created_at LIMIT 5", mixed)
                room, statements = self.room_assignment(selected)
                if room is None:
                    return None
                statements += [{'sql': "UPDATE uplv_tasks SET status='assigned',room_id=?,slot=? WHERE id=?", 'args': [room, i, r[0]]} for i, r in enumerate(selected)]
                self.store.batch(statements)
                return room
            group = self.store.fetchone("SELECT t.mode FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status='waiting' AND j.status='open' GROUP BY t.mode HAVING COUNT(*)>=5 ORDER BY MIN(t.created_at) LIMIT 1")
            if not group:
                # A partial continuation group can be completed by new,
                # uploaded accounts; the game reads their actual level.
                combined = self.store.fetchone("SELECT t.mode FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status IN ('ready','waiting') AND j.status='open' GROUP BY t.mode HAVING COUNT(*)>=5 ORDER BY MIN(t.created_at) LIMIT 1")
                if combined:
                    selected = self.store.fetch("SELECT t.id,t.job_id,t.account_json FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status IN ('ready','waiting') AND t.mode=? AND j.status='open' ORDER BY CASE WHEN t.status='ready' THEN 0 ELSE 1 END,t.created_at LIMIT 5", combined)
                    room, statements = self.room_assignment(selected)
                    if room is None:
                        return None
                    statements += [{'sql': "UPDATE uplv_tasks SET status='assigned',room_id=?,slot=? WHERE id=?", 'args': [room, i, r[0]]} for i, r in enumerate(selected)]
                    self.store.batch(statements)
                    return room
                verification = self.pool_verification_room()
                if verification:
                    return verification
                self.finish_unfillable_tail()
                return None
            selected = self.store.fetch("SELECT t.id,t.job_id,t.account_json FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status='waiting' AND t.mode=? AND j.status='open' ORDER BY t.created_at LIMIT 5", group)
        room, statements = self.room_assignment(selected)
        if room is None:
            return None
        statements += [{'sql': "UPDATE uplv_tasks SET status='assigned',room_id=?,slot=? WHERE id=?",
                        'args': [room, i, r[0]]} for i, r in enumerate(selected)]
        self.store.batch(statements)
        return room

    def release_legacy_screening(self):
        """Drain the old precheck queue without stealing any checker session.

        No fresh CheckPass claims are issued. Allow expired owners 120 seconds
        to finish/close before UpLv takes over; terminal tasks stay untouched.
        Zero is unconfirmed metadata, never evidence of a missing character.
        """
        cutoff = time.time() - 120
        rows = self.store.fetch("SELECT t.id FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id WHERE t.status='screening' AND j.status='open' AND NOT EXISTS (SELECT 1 FROM uplv_check_leases l WHERE l.task_id=t.id AND l.lease_until>=?) AND NOT EXISTS (SELECT 1 FROM uplv_check_members m JOIN uplv_check_chunks c ON c.id=m.chunk_id WHERE m.task_id=t.id AND c.status='claimed' AND c.lease_until>=?) ORDER BY t.created_at,t.id LIMIT 5", (cutoff, cutoff))
        changes = []
        for task, in rows:
            changes.extend([
                {'sql': "UPDATE uplv_tasks SET status='waiting' WHERE id=? AND status='screening'", 'args': [task]},
                {'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json',
                 'args': [task, time.time(), json.dumps({'stage': 'UPLV_GAME_PENDING', 'detail': 'Vệ tinh UpLv tự đăng nhập game và đọc cấp; không chờ CheckPass/Kiện Tướng', 'level_confirmed': False})]},
            ])
        if changes:
            self.store.batch(changes)

    def finish_unfillable_tail(self):
        """A partial team is waiting for teammates, not an account failure."""
        return

    def room_assignment(self, selected):
        """Reuse a global physical slot; per-account results/history outlive it."""
        limit = self.pool_limit()
        reusable = self.store.fetchone("SELECT id,ordinal FROM uplv_rooms WHERE status NOT IN ('pending','running','interrupted') AND ordinal<=? ORDER BY ordinal LIMIT 1", (limit,))
        if reusable:
            room, ordinal = reusable
            old = self.store.fetchone('SELECT job_id,accounts_json,status,results_json FROM uplv_rooms WHERE id=?', (room,))
            snapshot = {'job_id': old[0], 'users': [a[0] for a in json.loads(old[1])], 'status': old[2], 'results': json.loads(old[3]), 'ordinal': ordinal}
            changes = [
                {'sql': 'INSERT INTO uplv_room_history VALUES (?,?,?,?)', 'args': [uuid.uuid4().hex, room, time.time(), json.dumps(snapshot)]},
                {'sql': "UPDATE uplv_tasks SET room_id='',slot=-1 WHERE room_id=?", 'args': [room]},
            ]
            for table in ('uplv_verify_rooms', 'uplv_screen_rooms', 'uplv_room_versions', 'uplv_replacements'):
                changes.append({'sql': f'DELETE FROM {table} WHERE room_id=?', 'args': [room]})
            changes.append({'sql': "UPDATE uplv_rooms SET job_id=?,accounts_json=?,status='pending',satellite_id='',lease_token='',lease_until=0,progress_json='{}',results_json='{}',stop_requested=0 WHERE id=?",
                            'args': [selected[0][1], json.dumps([json.loads(r[2]) for r in selected]), room]})
            return room, changes
        used = {r[0] for r in self.store.fetch('SELECT ordinal FROM uplv_rooms')}
        ordinal = next((n for n in range(1, limit + 1) if n not in used), None)
        if ordinal is None:
            return None, []
        room = uuid.uuid4().hex
        return room, [{'sql': 'INSERT INTO uplv_rooms (id,job_id,ordinal,accounts_json,status) VALUES (?,?,?,?,?)',
                       'args': [room, selected[0][1], ordinal, json.dumps([json.loads(r[2]) for r in selected]), 'pending']}]

    def pool_screening_room(self):
        selected = self.store.fetch("SELECT t.id,t.job_id,t.account_json FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id LEFT JOIN uplv_verify_attempts v ON v.task_id=t.id WHERE t.status='screening' AND j.status='open' AND COALESCE(v.next_at,0)<=? ORDER BY t.created_at LIMIT 5", (time.time(),))
        if not selected:
            return None
        return self.inspection_assignment(selected, screen=True)

    def inspection_assignment(self, selected, screen=False):
        room, statements = self.room_assignment(selected)
        if room is None:
            return None
        statements.append({'sql': 'INSERT INTO ' + ('uplv_screen_rooms' if screen else 'uplv_verify_rooms') + ' VALUES (?)', 'args': [room]})
        for slot, row in enumerate(selected):
            waiting = self.store.fetchone('SELECT task_id FROM uplv_session_wait WHERE task_id=?', (row[0],))
            if waiting:
                # Separate budget: never spend/reset the match inspection count.
                statements += [
                    {'sql': "UPDATE uplv_tasks SET status='assigned',room_id=?,slot=? WHERE id=?", 'args': [room, slot, row[0]]},
                    {'sql': 'UPDATE uplv_session_wait SET attempts=attempts+1 WHERE task_id=?', 'args': [row[0]]},
                ]
                continue
            attempt = self.store.fetchone('SELECT attempts FROM uplv_verify_attempts WHERE task_id=?', (row[0],))
            delay = self.VERIFY_DELAY
            statements += [
                {'sql': "UPDATE uplv_tasks SET status='assigned',room_id=?,slot=? WHERE id=?", 'args': [room, slot, row[0]]},
                {'sql': 'INSERT INTO uplv_verify_attempts (task_id,attempts,next_at) VALUES (?,1,?) ON CONFLICT(task_id) DO UPDATE SET attempts=uplv_verify_attempts.attempts+1,next_at=excluded.next_at', 'args': [row[0], time.time() + delay]},
            ]
        self.store.batch(statements)
        return room

    def pool_verification_room(self):
        # Counts are telemetry, not evidence for stopping an account.
        self.expire_session_wait()
        now = time.time()
        selected = self.store.fetch("SELECT t.id,t.job_id,t.account_json FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id LEFT JOIN uplv_verify_attempts v ON v.task_id=t.id LEFT JOIN uplv_session_wait w ON w.task_id=t.id WHERE j.status='open' AND ((t.status='verifying' AND w.task_id IS NULL AND COALESCE(v.next_at,0)<=?) OR (t.status='session_wait' AND w.next_at<=?)) ORDER BY CASE WHEN w.task_id IS NOT NULL THEN w.next_at ELSE COALESCE(v.next_at,0) END,t.created_at,t.id LIMIT 5", (now, now))
        if not selected:
            return None
        return self.inspection_assignment(selected)

    def session_wait_result(self, task, observed_detail=None):
        """Plan one durable wait after completion/lease revocation, never login."""
        now = time.time()
        row = self.store.fetchone('SELECT attempts,started_at FROM uplv_session_wait WHERE task_id=?', (task,))
        count, started = row if row else (0, now)
        due = now + self.VERIFY_DELAY
        saved = self.store.fetchone('SELECT detail_json FROM uplv_task_details WHERE task_id=?', (task,))
        detail = json.loads(saved[0]) if saved else {}
        if observed_detail:
            detail.update(observed_detail)
        detail.update(stage='WAIT_SESSION_RELEASE', pause_reason='',
                      session_wait_attempts=count, session_wait_deadline=0)
        return 'session_wait', [
            {'sql': 'INSERT INTO uplv_session_wait VALUES (?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET next_at=excluded.next_at', 'args': [task, count, started, due]},
            {'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, now, json.dumps(detail)]},
        ]

    def auth_admission_blocked(self):
        # Only a fresh 429 starts a fleet quiet interval. Old retry metadata
        # must never serialize every healthy worker to one room per 30 seconds.
        row = self.store.fetchone("SELECT until_at FROM uplv_auth_cooldown WHERE id='fleet'")
        return bool(row and time.time() < row[0])

    def auth_cooldown_changes(self):
        now = time.time()
        return [{'sql': "INSERT INTO uplv_auth_cooldown VALUES ('fleet',?,?,?) ON CONFLICT(id) DO UPDATE SET until_at=excluded.until_at,pace_until=excluded.pace_until,next_admit=excluded.next_admit",
                 'args': [now + self.RATE_LIMIT_DELAY, now + self.RATE_LIMIT_DELAY + 60, now + self.RATE_LIMIT_DELAY]}]

    def rate_limit_result(self, task, room, observed_detail=None):
        """End this lease, not this account. A throttle spends no read budget."""
        now = time.time()
        prior = self.store.fetchone('SELECT attempts,resume_state FROM uplv_rate_limit_wait WHERE task_id=?', (task,))
        inspection = self.store.fetchone('SELECT room_id FROM uplv_verify_rooms WHERE room_id=?', (room,))
        session = self.store.fetchone('SELECT task_id FROM uplv_session_wait WHERE task_id=?', (task,))
        resume = 'session_wait' if session else 'verifying' if inspection else 'waiting'
        changes = []
        if inspection:
            table = 'uplv_session_wait' if session else 'uplv_verify_attempts'
            changes.append({'sql': f'UPDATE {table} SET attempts=CASE WHEN attempts>0 THEN attempts-1 ELSE 0 END WHERE task_id=?', 'args': [task]})
        saved = self.store.fetchone('SELECT detail_json FROM uplv_task_details WHERE task_id=?', (task,))
        detail = json.loads(saved[0]) if saved else {}
        if observed_detail:
            detail.update(observed_detail)
        detail.update(stage='WAIT_RATE_LIMIT', pause_reason='', detail='Giới hạn tần suất (429); chờ 30 giây rồi thử lại',
                      next_retry_at=now+self.RATE_LIMIT_DELAY)
        changes.extend([
            {'sql': 'INSERT INTO uplv_rate_limit_wait VALUES (?,?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET attempts=excluded.attempts,started_at=excluded.started_at,next_at=excluded.next_at,resume_state=excluded.resume_state',
             'args': [task, (prior[0] if prior else 0)+1, now, now+self.RATE_LIMIT_DELAY, resume]},
            {'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, now, json.dumps(detail)]},
        ])
        return changes

    def release_rate_limit_wait(self):
        """Only release due nonterminal tasks of open jobs; never migrate stops."""
        now = time.time()
        rows = self.store.fetch("SELECT t.id,r.resume_state,r.started_at FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id JOIN uplv_rate_limit_wait r ON r.task_id=t.id WHERE t.status='rate_limit_wait' AND j.status='open' AND r.next_at<=?", (now,))
        changes = []
        for task, resume, started in rows:
            changes.append({'sql': 'UPDATE uplv_tasks SET status=? WHERE id=?', 'args': [resume, task]})
            if resume == 'session_wait':
                # Time lost to auth throttling is not evidence of a stuck session.
                changes.append({'sql': 'UPDATE uplv_session_wait SET started_at=started_at+?,next_at=? WHERE task_id=?', 'args': [max(0, now-started), now, task]})
            elif resume == 'verifying':
                changes.append({'sql': 'UPDATE uplv_verify_attempts SET next_at=? WHERE task_id=?', 'args': [now, task]})
        if changes:
            self.store.batch(changes)

    def expire_session_wait(self):
        # Elapsed time is not a ban/name rejection. Keep historical terminal
        # rows untouched, but never terminate a queued task on a clock budget.
        return

    def retry_result(self, task, room, result, observed_detail=None):
        """Durable 30s retry, without reopening a possibly unresolved match."""
        now = time.time()
        prior = self.store.fetchone('SELECT attempts FROM uplv_retry_wait WHERE task_id=?', (task,))
        inspection = self.store.fetchone('SELECT room_id FROM uplv_verify_rooms WHERE room_id=?', (room,))
        saved = self.store.fetchone('SELECT detail_json FROM uplv_task_details WHERE task_id=?', (task,))
        detail = json.loads(saved[0]) if saved else {}
        detail.update(observed_detail or {})
        # Only a failure known to precede game login may return directly to
        # preparation. Unknown/missing level/state remains read-only inspection.
        text = str(result.get('final_error') or '')
        auth_only = ('SsoLoginError' in text or 'Auth V2 thất bại' in text)
        # Explicit registration rejection precedes any match. Retry preparation
        # rather than trapping an uncreated character in read-only inspection.
        import re
        registration_rejected = bool(re.search(
            r'server_error_csid_(?:1009|1190)_code_(?:91103|91123)\b', text))
        session = self.store.fetchone('SELECT task_id FROM uplv_session_wait WHERE task_id=?', (task,))
        resume = ('session_wait' if session else 'waiting' if registration_rejected
                  or (auth_only and not inspection) else 'verifying')
        detail.update(stage='WAIT_RETRY', pause_reason='', next_retry_at=now+self.VERIFY_DELAY)
        return [
            {'sql': 'INSERT INTO uplv_retry_wait VALUES (?,?,?,?) ON CONFLICT(task_id) DO UPDATE SET attempts=excluded.attempts,next_at=excluded.next_at,resume_state=excluded.resume_state',
             'args': [task, (prior[0] if prior else 0)+1, now+self.VERIFY_DELAY, resume]},
            {'sql': 'INSERT INTO uplv_task_details VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET updated_at=excluded.updated_at,detail_json=excluded.detail_json', 'args': [task, now, json.dumps(detail)]},
        ]

    def release_retry_wait(self):
        rows = self.store.fetch("SELECT t.id,q.resume_state FROM uplv_tasks t JOIN uplv_jobs j ON j.id=t.job_id JOIN uplv_retry_wait q ON q.task_id=t.id WHERE t.status='retry_wait' AND j.status='open' AND q.next_at<=?", (time.time(),))
        changes = []
        for task, resume in rows:
            changes.append({'sql': 'UPDATE uplv_tasks SET status=? WHERE id=?', 'args': [resume, task]})
            changes.append({'sql': 'UPDATE uplv_verify_attempts SET next_at=? WHERE task_id=?', 'args': [time.time(), task]})
            if resume == 'session_wait':
                changes.append({'sql': 'UPDATE uplv_session_wait SET next_at=? WHERE task_id=?', 'args': [time.time(), task]})
        if changes:
            self.store.batch(changes)

    def recovery_candidates(self, job):
        return self.store.fetch("SELECT t.id,t.status,t.level,t.room_id,t.slot FROM uplv_tasks t JOIN uplv_rooms r ON r.id=t.room_id WHERE t.job_id=? AND t.status='failed' AND t.slot>=0 AND t.level>=5 AND r.status IN ('failed','incomplete','done')", (job,))

    def recover_pending(self, body):
        job = str(body.get('job_id', ''))
        with self.lock:
            if not self.pool_job(job):
                raise ValueError('Cần pool job hợp lệ')
            row = self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (job,))
            if not row or row[0] == 'stopped':
                raise ValueError('Không khôi phục job đã dừng')
            candidates = self.recovery_candidates(job)
            changes = [{'sql': "UPDATE uplv_jobs SET status='open' WHERE id=?", 'args': [job]}]
            for task, _, _, _, _ in candidates:
                changes.append({'sql': "UPDATE uplv_tasks SET status='verifying',room_id='',slot=-1 WHERE id=?", 'args': [task]})
            self.store.batch(changes)
            return {'ok': True, 'rechecking_failed_lv5': len(candidates)}

    def pool_finish(self, body, results, stopped, defer=False, observed_details=None):
        tasks = self.room_tasks(body['room_id'])
        if not tasks:
            return
        statements = []
        for task, job, _, target, level, slot, _ in tasks:
            result = results[str(slot)]
            after = max(level, result['level_after'])
            # Only explicit verified+idle results enter the ready queue. Unknown
            # sessions remain blocked, never automatically replayed in a game.
            success = result['status'] == 'success' and after >= target
            job_state = self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (job,))[0]
            screening = self.store.fetchone('SELECT room_id FROM uplv_screen_rooms WHERE room_id=?', (body['room_id'],)) is not None
            state = ('success' if success else 'stopped' if job_state == 'stopped'
                     else 'verifying' if stopped
                     else 'waiting' if screening and result.get('screened') and after < 5
                     else ('waiting' if after < 5 else 'ready') if result.get('verified') and result.get('idle')
                      else 'screening' if screening and result['status'] != 'failed'
                      else 'verifying')
            terminal = terminal_account_failure(result)
            # 429 ends only the current operation, never the account's queue.
            rate_limited = not success and result.get('failure_kind') == 'rate_limit' and job_state != 'stopped'
            if rate_limited:
                state = 'rate_limit_wait'
                statements.extend(self.rate_limit_result(task, body['room_id'], (observed_details or {}).get(task)))
            elif not success and job_state != 'stopped' and terminal:
                state = 'failed'
            elif not success and job_state != 'stopped' and result.get('failure_kind') in ('login','restricted','create_character','server_error'):
                state = 'retry_wait'
                statements.extend(self.retry_result(task, body['room_id'], result, (observed_details or {}).get(task)))
            waiting = self.store.fetchone('SELECT task_id FROM uplv_session_wait WHERE task_id=?', (task,))
            conflict = result.get('failure_kind') == 'session_conflict'
            if not terminal and not rate_limited and not success and job_state != 'stopped' and (conflict or (waiting and state == 'verifying')):
                state, changes = self.session_wait_result(task, (observed_details or {}).get(task))
                statements.extend(changes)
            if state == 'verifying':
                attempt = self.store.fetchone('SELECT attempts FROM uplv_verify_attempts WHERE task_id=?', (task,))
                count = attempt[0] if attempt else 0
                # Counts remain diagnostic only. No terminal conversion on an
                # inconclusive read, including after the former three passes.
                statements.append({'sql': 'INSERT INTO uplv_verify_attempts VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET next_at=excluded.next_at', 'args': [task, count, time.time() + self.VERIFY_DELAY]})
            statements.append({'sql': 'UPDATE uplv_tasks SET status=?,level=?,room_id=?,slot=? WHERE id=?',
                'args': [state, after, '' if state in ('ready', 'verifying', 'screening', 'waiting', 'session_wait','rate_limit_wait','retry_wait') else body['room_id'], -1 if state in ('ready', 'verifying', 'screening', 'waiting', 'session_wait','rate_limit_wait','retry_wait') else slot, task]})
            if state != 'rate_limit_wait':
                statements.append({'sql': 'DELETE FROM uplv_rate_limit_wait WHERE task_id=?', 'args': [task]})
            if state != 'retry_wait':
                statements.append({'sql': 'DELETE FROM uplv_retry_wait WHERE task_id=?', 'args': [task]})
            if state in ('ready', 'waiting', 'success'):
                statements.append({'sql': 'DELETE FROM uplv_verify_attempts WHERE task_id=?', 'args': [task]})
                statements.append({'sql': 'DELETE FROM uplv_session_wait WHERE task_id=?', 'args': [task]})
        for job in {r[1] for r in tasks}:
            statements.append({'sql': "UPDATE uplv_jobs SET status='done' WHERE id=? AND status='open' AND NOT EXISTS (SELECT 1 FROM uplv_tasks WHERE job_id=? AND status NOT IN ('success','failed','stopped'))", 'args': [job, job]})
        if not defer:
            self.store.batch(statements)
        return statements

    def pool_snapshot(self):
        groups = [{'level': r[0], 'mode': r[1], 'status': r[2], 'count': r[3]} for r in self.store.fetch(
            "SELECT level,mode,status,COUNT(*) FROM uplv_tasks WHERE status IN ('screening','waiting','ready','verifying','session_wait','rate_limit_wait','retry_wait') GROUP BY level,mode,status ORDER BY level DESC")]
        return {'max_rooms': self.pool_limit(), 'room_count': self.store.fetchone('SELECT COUNT(*) FROM uplv_rooms')[0],
                'occupied_rooms': self.store.fetchone("SELECT COUNT(*) FROM uplv_rooms WHERE status IN ('running','interrupted')")[0], 'groups': groups}
