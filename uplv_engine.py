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
        run_rooms, run_cs, login, device, retry, checkpoints = self.runtime
        bundles = {}
        bundle_lock = threading.Lock()

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
            # Serialize start times, not the entire network exchange.
            bundle = login(user, password, device(user)['device_id'], timeout=20)
            with bundle_lock:
                bundles[user.casefold()] = bundle
            return bundle

        def execute(user, password, target_level=5, progress_cb=None, debug_log=None, character_name=None):
            # Read actual CS profile; skip the optional web-profile request.
            bundle = None
            for attempt in range(3):
                if stop.is_set():
                    return False, 0, 0, 'Đã dừng'
                try:
                    bundle = authenticate(user, password)
                    break
                except Exception:
                    if attempt == 2:
                        raise
                    stop.wait(2)
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
                if row[0] or stop.is_set() or replacement is None:
                    return row
                # execute/run_cs has returned and closed the preparation
                # session. No buff/battle session has been opened at this point.
                account = replacement(index, row)
                if account is None:
                    return False, row[1], row[2], 'Đã dừng chờ acc bù'
                user, password = account
            return False, 0, 0, 'Đã dừng'

        if room.get('verify_only'):
            from concurrent.futures import ThreadPoolExecutor
            from pve_runtime.loader import load
            from pve_runtime.deadlines import session_deadline
            from pve_runtime.web_finish import idle_on_current_session
            from uplv_kientuong import PlayerSession
            def verify_account(index):
                level = room['levels'][index]
                target = room['targets'][index]
                row = (False, level, level, 'pool_verifying')
                session = web = None
                try:
                    progress(index, '[VERIFYING] Đối soát cấp/trạng thái cũ; không mở trận')
                    bundle = authenticate(*room['accounts'][index])
                    web = PlayerSession(bundle.sso_key, bundle.open_id, stop)
                    verified = web.verify(level, target, budget=15)
                    if verified is not None:
                        level = verified
                        progress(index, f'[LEVEL] Lv{level}')
                    if verified is not None and level >= target:
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
                                   '' if level >= target else 'pool_ready' if idle else 'pool_verifying')
                    progress(index, '[POOL_READY] Đã xác nhận rảnh; chờ ghép cùng cấp' if row[3] == 'pool_ready'
                             else '[STACK4_DONE] Đã đạt mục tiêu' if row[0] else '[VERIFYING] Chưa xác nhận rảnh; retry có giới hạn')
                except Exception as exc:
                    progress(index, '[VERIFYING] Đối soát chưa xong: ' + type(exc).__name__)
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
            from uplv_kientuong import PlayerSession
            return run_five_batch(room['accounts'], room['target'], concurrency, stop,
                prepare, authenticate, progress, mode=room['mode'], prepare_cards=True,
                checkpoint_store=checkpoints(self.state_dir / 'rewards'), completed=completed,
                web_verify=(lambda bundle, stop: PlayerSession(bundle.sso_key, bundle.open_id, stop))
                    if room['mode'] == 'victory' else None,
                targets=room.get('targets'))
        return run_rooms(room['accounts'], room['target'], 1, concurrency, stop,
                         prepare, authenticate, progress, mode=room['mode'],
                         checkpoint_store=checkpoints(self.state_dir / 'rewards'), completed=completed)
