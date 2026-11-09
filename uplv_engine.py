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

        def authenticate(user, password):
            with self.login_lock:
                delay = max(0, self.last_login + 0.6 - time.monotonic())
                if stop.wait(delay):
                    raise RuntimeError('Stopped')
                self.last_login = time.monotonic()
            # Serialize start times, not the entire network exchange.
            return login(user, password, device(user)['device_id'], timeout=20)

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

        # One room, up to five concurrent preparations; battle waits for all.
        concurrency = max(1, min(5, int(config.PREPARE_WORKERS)))
        return run_rooms(room['accounts'], room['target'], 1, concurrency, stop,
                         prepare, authenticate, progress, mode=room['mode'],
                         checkpoint_store=checkpoints(self.state_dir / 'rewards'), completed=completed)
