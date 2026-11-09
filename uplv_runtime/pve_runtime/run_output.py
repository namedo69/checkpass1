"""Per-run, incrementally saved results; metadata contains no passwords."""
from datetime import datetime
import json
import os
from pathlib import Path
import threading
import uuid


class RunOutput:
    def __init__(self, root, accounts, target, mode, rooms, version=None):
        self.root = Path(root)
        self.folder = self.root / (datetime.now().strftime('run_%Y%m%d_%H%M%S_') + uuid.uuid4().hex[:8])
        self.folder.mkdir(parents=True)
        self.lock = threading.RLock()
        self.data = dict(started_at=datetime.now().isoformat(), state='running',
                         target=target, mode=mode, rooms=rooms, total=len(accounts), results={})
        self.data['app_version'] = version
        self.accounts = list(accounts)
        for name in ('thanh_cong.txt', 'that_bai.txt', 'chua_xong.txt', 'debug.log'):
            (self.folder / name).touch()
        self.save()

    def save(self):
        with self.lock:
            rows = self.data['results']
            self.data['processed'] = len(rows)
            self.data['success'] = sum(r['ok'] for r in rows.values())
            self.data['failed'] = len(rows) - self.data['success']
            path = self.folder / 'summary.json'
            tmp = path.with_suffix('.tmp')
            tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding='utf-8')
            os.replace(tmp, path)
            pending = [f'{u}|{p}' for i, (u, p) in enumerate(self.accounts) if str(i) not in rows]
            path = self.folder / 'chua_xong.txt'
            tmp = path.with_suffix('.tmp')
            tmp.write_text('\n'.join(pending) + ('\n' if pending else ''), encoding='utf-8')
            os.replace(tmp, path)

    def record(self, result, ok):
        with self.lock:
            self.data['results'][str(result.index)] = dict(
                account=result.account, ok=ok, level_before=result.level_before,
                level_after=result.level_after, error=result.error, duration=result.duration,
                finished_at=datetime.now().isoformat())
            self.save()

    def finish(self, stopped=False):
        with self.lock:
            self.data.update(state='stopped' if stopped else 'finished',
                             ended_at=datetime.now().isoformat())
            self.save()
