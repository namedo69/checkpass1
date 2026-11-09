"""Durable reward checkpoints, excluding auth identity and credentials."""
import hashlib
import json
import os
from pathlib import Path
import threading

_LOCK = threading.RLock()


class RewardCheckpoints:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, account):
        key = hashlib.sha256(account.casefold().encode()).hexdigest()[:24]
        return self.root / (key + '.json')

    def load(self, account):
        with _LOCK:
            path = self.path(account)
            if not path.exists():
                return {}
            return json.loads(path.read_text(encoding='utf-8'))

    def update(self, account, **fields):
        # Original profile store receives many fields; retain reward decisions
        # only. No token, password or SDK device tuple is persisted here.
        safe = {key: value for key, value in fields.items()
                if key.startswith(('exp_', 'reward_', 'starter_')) or key == 'ruby_balance'}
        if not safe:
            return
        with _LOCK:
            data = self.load(account)
            data.update(safe)
            path = self.path(account)
            temp = path.with_suffix('.tmp')
            temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
            os.replace(temp, path)
