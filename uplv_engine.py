"""Lazy-loaded Qt-free adapter for the production PvE runtime bundle."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import uplv_config as config


def load_runtime():
    root = Path(os.environ.get('UPLV_RUNTIME_DIR', Path(__file__).parent / 'uplv_runtime')).resolve()
    if sys.version_info[:2] != (3, 14):
        raise RuntimeError('UpLv runtime requires CPython 3.14')
    if not (root / 'pve_runtime' / 'vendor' / 'manifest.json').is_file():
        raise RuntimeError('Missing UpLv runtime; run package_uplv_runtime.py first')
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / 'pve_backend'))
    from pve_runtime.loader import load
    from pve_runtime.rooms import run_rooms
    from purepc.purepc_run import run
    from token_login import login_and_exchange
    from aov_device_identity import get_device_for_account
    from pve_runtime.novice_retry import prepare_with_retry
    from pve_runtime.checkpoints import RewardCheckpoints
    # Load and hash-check all modules used by the match before claiming work.
    for name in ('lever_session', 'five_runtime'):
        load(name)
    return run_rooms, run, login_and_exchange, get_device_for_account, prepare_with_retry, RewardCheckpoints


class Engine:
    def __init__(self, state_dir):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.environ['AOV_DEVICE_CACHE'] = str(self.state_dir / 'devices')
        self.runtime = load_runtime()
        self.login_lock = threading.Lock()
        self.last_login = 0

    def run(self, room, stop, progress, completed, replacement=None):
        """Own transient recovery while the lease/heartbeat remains valid."""
        if not room.get('pool_protocol') and not room.get('verify_only'):
            return self._run_once(room, stop, progress, completed, replacement)
        published = set()
        def publish(index, row):
            # Pending is progress, not a finished result. Publish only terminal
            # outcomes early; the final return carries regroup/stop outcomes.
            if row[0] or str(row[3]).startswith('terminal_'):
                if index not in published:
                    published.add(index)
                    if completed:
                        completed(index, row)
        results = self._run_once(room, stop, progress, publish, replacement)
        attempts = {}
        recovery_started = time.monotonic()
        max_recovery_attempts = 3
        recovery_budget = 180
        while not stop.is_set():
            unresolved = [i for i, row in results.items()
                          if not row[0] and not str(row[3]).startswith('terminal_')
                           and row[3] not in ('pool_ready', 'screen_ready')]
            if unresolved and (
                time.monotonic() - recovery_started >= recovery_budget
                or all(attempts.get(i, 0) >= max_recovery_attempts for i in unresolved)
            ):
                for index in unresolved:
                    progress(index, '[VERIFYING] Hết lượt kiểm tra tại worker; trả về hàng kiểm tra và giải phóng phòng')
                break
            for index in unresolved:
                if stop.is_set():
                    break
                if attempts.get(index, 0) >= max_recovery_attempts or time.monotonic() - recovery_started >= recovery_budget:
                    continue
                attempts[index] = attempts.get(index, 0) + 1
                delay = min(30, 2 ** min(attempts[index], 5))
                progress(index, f'[VERIFYING] Worker tự đối soát lượt {attempts[index]}; thử lại sau {delay}s, giữ quyền xử lý')
                if stop.wait(delay):
                    break
                check = {'accounts': [room['accounts'][index]],
                         'levels': [results[index][2]],
                         'targets': [room.get('targets', [room.get('target', 12)] * len(room['accounts']))[index]],
                         'verify_only': True}
                recovered = self._run_once(check, stop,
                    lambda _, message, i=index: progress(i, message),
                    lambda _, row, i=index: publish(i, row))
                if 0 in recovered:
                    results[index] = recovered[0]
                    publish(index, recovered[0])
            if stop.is_set():
                break
            if any(not row[0] and not str(row[3]).startswith('terminal_')
                   and row[3] not in ('pool_ready', 'screen_ready') for row in results.values()):
                continue
            # A recovery-only lease returns confirmed state to the scheduler.
            # A full battle team can continue without a new master allocation.
            if room.get('verify_only') or len(results) != 5 or any(row[0] or str(row[3]).startswith('terminal_') for row in results.values()):
                break
            for i, row in results.items():
                room.setdefault('levels', [0] * len(room['accounts']))[i] = row[2]
            progress(0, '[STACK3] Đối soát xong cả đội; worker tiếp tục up trong cùng lượt phòng')
            results = self._run_once(room, stop, progress, publish, replacement)
        for index, row in results.items():
            publish(index, row)
        return results

    def _run_once(self, room, stop, progress, completed, replacement=None):
        run_rooms, run_cs, login, device, retry, checkpoints = self.runtime
        bundles = {}
        bundle_lock = threading.Lock()

        def authenticate(user, password):
            with bundle_lock:
                cached = bundles.get(user.casefold())
            if cached is not None:
                return cached
            for attempt in range(3):
                with self.login_lock:
                    delay = max(0, self.last_login + 0.6 - time.monotonic())
                    if stop.wait(delay):
                        raise RuntimeError('Stopped')
                    self.last_login = time.monotonic()
                try:
                    # UpLv now reads levels in-game; requesting web SSO here
                    # adds a failure point (0x1BA) unrelated to game login.
                    bundle = login(user, password, device(user)['device_id'], timeout=20, with_sso_key=False)
                    break
                except Exception as exc:
                    # Code 3 is an unclassified request rejection, not proof
                    # of an invalid password. Keep retries bounded and spaced.
                    code = getattr(exc, 'code', None)
                    transient = code == 3 or any(word in str(exc).lower() for word in
                        ('mã 3', 'timeout', 'timed out', 'connection', '429'))
                    if not transient or attempt == 2:
                        raise
                    if stop.wait(3 * (attempt + 1)):
                        raise RuntimeError('Stopped')
            with bundle_lock:
                bundles[user.casefold()] = bundle
            return bundle

        def execute(user, password, target_level=5, progress_cb=None, debug_log=None, character_name=None):
            # Read actual CS profile; skip the optional web-profile request.
            if stop.is_set():
                return False, 0, 0, 'Đã dừng'
            bundle = authenticate(user, password)
            with tempfile.TemporaryDirectory(prefix='uplv-') as temp:
                token = Path(temp) / 'token.json'
                token.write_text(json.dumps({'authToken': bundle.access_token, 'openId': bundle.open_id}), encoding='utf-8')
                def log(message):
                    import re
                    level = re.search(r'\[level\] level=(\d+)', message)
                    if level:
                        progress_cb(f'[LEVEL] Lv{level.group(1)}')
                row = run_cs(token, user, role_cs='resolve', create=True,
                             replay_1v1='1v1_setwin_seq.json', log=log,
                             target=target_level, max_rounds=8,
                             **({'character_name': character_name} if character_name else {}))
            before = row.get('level_before') or 0
            after = row.get('level_after') or before
            return bool(row.get('ok') and after >= target_level), before, after, str(row.get('reject') or '')

        def prepare(index, user, password):
            while not stop.is_set():
                if room.get('pool_protocol') and room.get('levels', [0] * 5)[index] >= 5:
                    level = room['levels'][index]
                    progress(index, f'[LEVEL] Lv{level}')
                    return True, level, level, ''
                row = retry(execute, user, password, 5, stop, lambda message: progress(index, message))
                if not row[0] and not stop.is_set():
                    text = row[3].lower()
                    login_failed = any(word in text for word in ('sai mật khẩu', '50004', 'bị khóa', 'banned'))
                    creation_failed = row[2] == 0 and any(word in text for word in ('create-role', 'create_role', '_code_91103', '_code_91123'))
                    if not (login_failed or creation_failed):
                        progress(index, '[VERIFYING] Chuẩn bị chưa xong; giữ acc để tiếp tục: ' + row[3])
                        return False, row[1], row[2], 'pool_verifying'
                    row = (False, row[1], row[2], ('terminal_login: ' if login_failed else 'terminal_create_character: ') + row[3])
                if row[0] or stop.is_set() or replacement is None:
                    return row
                # execute/run_cs has returned and closed the preparation
                # session. No buff/battle session has been opened at this point.
                account = replacement(index, row)
                if account is None:
                    return False, row[1], row[2], 'Đã dừng chờ acc bù'
                user, password = account
            return False, 0, 0, 'Đã dừng'

        if room.get('verify_only') or room.get('screen_only'):
            from concurrent.futures import ThreadPoolExecutor
            from pve_runtime.loader import load
            from pve_runtime.deadlines import session_deadline
            from pve_runtime.web_finish import idle_on_current_session
            def verify_account(index):
                level = room['levels'][index]
                target = room['targets'][index]
                row = (False, level, level, 'pool_verifying')
                session = web = None
                bundle = None
                try:
                    progress(index, '[VERIFYING] Đối soát cấp/trạng thái cũ; không mở trận')
                    bundle = authenticate(*room['accounts'][index])
                    # Initial web screening belongs to CheckPass. Recovery and
                    # post-match verification use the authenticated game profile.
                    verified = None
                    if verified is not None:
                        level = verified
                        progress(index, f'[LEVEL] Lv{level}')
                    if room.get('screen_only') and verified is not None and level < 5:
                        row = (False, room['levels'][index], level, 'screen_ready')
                    elif verified is not None and level >= target:
                        row = (True, room['levels'][index], level, '')
                    else:
                        session = load('lever_session').LeverSession(stop)
                        session.authenticate_garena_session(bundle.access_token, bundle.open_id)
                        with session_deadline(session, 35, 'Đối soát phiên cũ'):
                            session.connect()
                            idle = idle_on_current_session(session, stop)
                        # Readback on a fresh authenticated game session is also
                        # valid level evidence; silence never means idle.
                        actual = getattr(session, 'level', None)
                        if type(actual) is int and 1 <= actual <= 30:
                            level = actual
                            progress(index, f'[LEVEL] Lv{level}')
                            row = (level >= target, room['levels'][index], level,
                                   '' if level >= target else 'screen_ready' if idle and room.get('screen_only') else 'pool_ready' if idle else 'pool_verifying')
                    progress(index, '[POOL_READY] Đã xác nhận rảnh; chờ ghép cùng cấp' if row[3] == 'pool_ready'
                             else '[STACK4_DONE] Đã đạt mục tiêu' if row[0] else '[VERIFYING] Chưa xác nhận rảnh; retry có giới hạn')
                except Exception as exc:
                    from pve_runtime.failure_policy import restricted_account
                    diagnostic = str(exc) or type(exc).__name__
                    for account in room['accounts']:
                        for secret in account:
                            if secret:
                                diagnostic = diagnostic.replace(secret, '[REDACTED]')
                    create_rejected = 'tạo nhân vật bị từ chối' in str(exc).casefold()
                    if create_rejected:
                        row = (False, room['levels'][index], level, 'terminal_create_character: ' + diagnostic)
                    elif restricted_account(exc):
                        row = (False, room['levels'][index], level, 'terminal_restricted: ' + diagnostic)
                    elif room.get('screen_only'):
                        row = (False, room['levels'][index], level, 'screen_wait')
                    progress(index, '[ERROR] Tài khoản bị hạn chế: ' + diagnostic if restricted_account(exc)
                             else '[VERIFYING] Đối soát chưa xong: ' + type(exc).__name__ + ': ' + diagnostic)
                    if not create_rejected and not restricted_account(exc) and not stop.is_set():
                        try:
                            from uplv_kientuong import PlayerSession
                            progress(index, '[VERIFYING] Không đọc được game; kiểm tra cấp Kiện Tướng dự phòng')
                            if bundle is None:
                                user, password = room['accounts'][index]
                                bundle = login(user, password, device(user)['device_id'], timeout=15, with_sso_key=True)
                            key = getattr(bundle, 'sso_key', '') if bundle is not None else ''
                            if not key:
                                from token_login import login_sso_key
                                key = login_sso_key(*room['accounts'][index], timeout=15)
                                key = key.sso_key if hasattr(key, 'sso_key') else str(key)
                            # OAuth/game namespace is bound only when a bundle
                            # was obtained. Never accept an unbound web player.
                            if bundle is None:
                                raise RuntimeError('Chưa có OAuth identity để đối chiếu Kiện Tướng')
                            web = PlayerSession(key, bundle.open_id, stop)
                            actual = web.read(time.monotonic() + 20)
                            level = actual
                            progress(index, f'[LEVEL] Lv{level}')
                            if level >= target:
                                row = (True, room['levels'][index], level, '')
                                progress(index, '[STACK4_DONE] Kiện Tướng dự phòng xác nhận đạt mục tiêu')
                            else:
                                row = (False, room['levels'][index], level, 'pool_verifying')
                                progress(index, '[VERIFYING] Kiện Tướng đã xác nhận cấp; còn chờ trạng thái trận trong game')
                        except Exception as fallback:
                            progress(index, '[VERIFYING] Kiện Tướng dự phòng chưa xong: ' + type(fallback).__name__)
                finally:
                    if session is not None:
                        session.close()
                    if web is not None:
                        web.close()
                completed(index, row)
                return index, row
            with ThreadPoolExecutor(max_workers=min(5, len(room['accounts']))) as executor:
                return dict(executor.map(verify_account, range(len(room['accounts']))))

        # One room, up to five concurrent preparations; battle waits for all.
        concurrency = max(1, min(5, int(config.PREPARE_WORKERS)))
        if room.get('pool_protocol'):
            from pve_runtime.uplv import run_five_batch
            return run_five_batch(room['accounts'], room['target'], concurrency, stop,
                prepare, authenticate, progress, mode=room['mode'], prepare_cards=True,
                checkpoint_store=checkpoints(self.state_dir / 'rewards'), completed=completed,
                require_idle={i for i, level in enumerate(room.get('levels', [])) if level >= 5},
                targets=room.get('targets'))
        return run_rooms(room['accounts'], room['target'], 1, concurrency, stop,
                         prepare, authenticate, progress, mode=room['mode'],
                         checkpoint_store=checkpoints(self.state_dir / 'rewards'), completed=completed)
