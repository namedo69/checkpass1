"""Lazy-loaded Qt-free adapter for the production PvE runtime bundle."""
import json
import hashlib
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
    manifest = json.loads((root/'bundle_manifest.json').read_text(encoding='utf8'))
    for name, expected in manifest.items():
        path = (root/name).resolve()
        if not path.is_relative_to(root) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('UpLv runtime integrity mismatch: ' + name)
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / 'pve_backend'))
    from pve_runtime.loader import load
    from pve_runtime.rooms import run_rooms
    from purepc.purepc_run import run
    from token_login import login_and_exchange
    from aov_device_identity import get_device_for_account
    from pve_runtime.novice_retry import prepare_with_retry
    from pve_runtime.checkpoints import RewardCheckpoints
    from purepc.login_v2 import login_body
    import base64
    protocol = json.loads((root/'pve_runtime/vendor/protocol_config.json').read_bytes())
    versions = bytes.fromhex('030000870300008e')
    if (login_body('a'*32, 'b'*32, 123)[:8] != versions
            or base64.b64decode(protocol['login_body'])[:8] != versions
            or base64.b64decode(protocol['reconnect_body'])[4:12] != versions):
        raise RuntimeError('UpLv V2 resource candidate mismatch')
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
        # One account-bound OAuth cache for this owned operation, including its
        # verification passes. Never persist tokens or share across leases.
        room['_auth_context'] = ({}, threading.RLock())
        try:
            return self._run_owned(room, stop, progress, completed, replacement)
        finally:
            room.pop('_auth_context', None)

    def _run_owned(self, room, stop, progress, completed, replacement=None):
        """Own transient recovery while the lease/heartbeat remains valid."""
        if not room.get('pool_protocol') and not room.get('verify_only'):
            return self._run_once(room, stop, progress, completed, replacement)
        published = set()
        def publish(index, row):
            from pve_runtime.failure_policy import terminal_result
            row = terminal_result(row)
            # Pending is progress, not a finished result. Publish only terminal
            # outcomes early; the final return carries regroup/stop outcomes.
            if row[0] or str(row[3]).startswith('terminal_'):
                if index not in published:
                    published.add(index)
                    if completed:
                        completed(index, row)
        results = self._run_once(room, stop, progress, publish, replacement)
        from pve_runtime.failure_policy import terminal_result
        results = {i: terminal_result(row) for i, row in results.items()}
        # Never layer fresh game logins over an inconclusive match/readback.
        # The master persists a quiet interval and a bounded inspection budget.
        # Ready accounts can only be regrouped by the existing verified+idle gate.
        for index, row in results.items():
            if not row[0] and not str(row[3]).startswith('terminal_') and row[3] not in ('pool_ready', 'screen_ready'):
                progress(index, '[DEFERRED] Chưa rõ kết quả; nhả phòng, chờ lịch đối soát tại master; không mở lại phiên ngay')
        for index, row in results.items():
            publish(index, row)
        return results

    def _run_once(self, room, stop, progress, completed, replacement=None):
        run_rooms, run_cs, login, device, retry, checkpoints = self.runtime
        bundles, bundle_lock = room.get('_auth_context') or ({}, threading.RLock())

        def authenticate(user, password):
            with bundle_lock:
                cached = bundles.get(user.casefold())
            if cached is not None:
                return cached
            with self.login_lock:
                delay = max(0, self.last_login + 0.6 - time.monotonic())
                if stop.wait(delay):
                    raise RuntimeError('Stopped')
                self.last_login = time.monotonic()
            try:
                def auth_progress(message):
                    for index, account in enumerate(room['accounts']):
                        if account[0].casefold() == user.casefold():
                            progress(index, message)
                # V2 handles conditional OAuth 141 TCP/SSO/HTTP grant on this
                # single credential session. Never restart login on 3/429/deny.
                bundle = login(user, password, device(user)['device_id'], timeout=20,
                               with_sso_key=False,
                               progress=auth_progress)
            except Exception as exc:
                code = getattr(exc, 'code', None)
                status = getattr(exc, 'http_status', None)
                details = type(exc).__name__
                if type(code) is int:
                    details += f' code={code}'
                if type(status) is int:
                    details += f' HTTP={status}'
                raise RuntimeError('terminal_login: Auth V2 thất bại; đã dừng ('
                                   + details + ')') from None
            with bundle_lock:
                bundles[user.casefold()] = bundle
            return bundle

        def execute(user, password, target_level=5, progress_cb=None, debug_log=None, character_name=None):
            # Read actual CS profile; skip the optional web-profile request.
            if stop.is_set():
                return False, 0, 0, 'Đã dừng'
            try:
                bundle = authenticate(user, password)
            except Exception as exc:
                return False, 0, 0, str(exc)
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
                              target=target_level, max_rounds=8, stop_event=stop,
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
                # Creation has its own bounded in-session V2 state machine.
                # Do not reset its send budget by invoking novice retries.
                row = execute(user, password, target_level=min(room.get('target', 5), 5),
                              progress_cb=lambda message: progress(index, message))
                from pve_runtime.failure_policy import terminal_result
                row = terminal_result(row)
                if row[3].startswith('terminal_'):
                    return row
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
                    from uplv_profile_v2 import read_profile
                    level, idle = read_profile(run_cs, bundle, room['accounts'][index][0], stop)
                    progress(index, f'[LEVEL] Lv{level}')
                    row = (level >= target, room['levels'][index], level,
                           '' if level >= target else 'screen_ready' if idle and room.get('screen_only') else 'pool_ready' if idle else 'pool_verifying')
                    progress(index, '[POOL_READY] Đã xác nhận rảnh; chờ ghép cùng cấp' if row[3] == 'pool_ready'
                             else '[STACK4_DONE] Đã đạt mục tiêu' if row[0] else '[VERIFY_WAIT] Đọc được cấp nhưng chưa xác nhận phiên rảnh; không mở trận')
                except Exception as exc:
                    from pve_runtime.failure_policy import restricted_account, stop_on_denial
                    diagnostic = str(exc) or type(exc).__name__
                    for account in room['accounts']:
                        for secret in account:
                            if secret:
                                diagnostic = diagnostic.replace(secret, '[REDACTED]')
                    create_rejected = 'tạo nhân vật bị từ chối' in str(exc).casefold()
                    if create_rejected:
                        row = (False, room['levels'][index], level, 'terminal_create_character: ' + diagnostic)
                    elif stop_on_denial(exc):
                        row = (False, room['levels'][index], level, 'terminal_restricted: ' + diagnostic)
                    elif room.get('screen_only'):
                        row = (False, room['levels'][index], level, 'screen_wait')
                    progress(index, '[ERROR] Tài khoản bị hạn chế: ' + diagnostic if restricted_account(exc)
                             else '[VERIFY_WAIT] Đối soát chưa xong: ' + type(exc).__name__ + ': ' + diagnostic)
                    if not create_rejected and not stop_on_denial(exc) and not stop.is_set():
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
