"""Bounded room log spool; replay-safe IDs, no raw auth payloads."""
from collections import deque
import re
import threading
import time
import uuid


class RoomLogs:
    def __init__(self, room_id=''):
        self.items = deque(maxlen=300)
        self.lock = threading.Lock()
        self.secrets = set()
        self.timers = {}
        self.room_id = room_id

    def protect(self, accounts):
        with self.lock:
            self.secrets.update(str(s) for a in accounts for s in a if s)

    def add(self, slot, message):
        with self.lock:
            timer = re.search(r'\[TIMER\]\s*(\d+)', message)
            if timer:
                bucket = int(timer.group(1)) // 30
                if self.timers.get(slot) == bucket:
                    return
                self.timers[slot] = bucket
            for secret in sorted(self.secrets, key=len, reverse=True):
                message = message.replace(secret, '[REDACTED]')
            message = re.sub(r'(?i)(bearer\s+|(?:password|token|sso_key|access_token)\s*[=:]\s*)\S+',
                             r'\1[REDACTED]', message)
            self.items.append({'id': uuid.uuid4().hex, 'at': time.time(), 'room_id': self.room_id, 'slot': slot, 'text': message[:500]})

    def view(self):
        with self.lock:
            return list(self.items)

    def batch(self):
        with self.lock:
            return list(self.items)[:100]

    def ack(self, items):
        ids = {item['id'] for item in items}
        with self.lock:
            self.items = deque((item for item in self.items if item['id'] not in ids), maxlen=300)
