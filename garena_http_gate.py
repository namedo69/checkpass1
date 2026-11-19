"""Process-wide host pacing and circuit breaker for upstream HTTP throttling."""
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import random
import threading
import time
from urllib.parse import urlsplit


class HostGate:
    def __init__(self, interval=0.0, concurrency=2):
        self.interval = interval
        self.slots = threading.BoundedSemaphore(concurrency)
        self.lock = threading.Lock()
        self.next_request = 0.0
        self.blocked_until = 0.0
        self.strikes = 0

    @contextmanager
    def admission(self):
        self.slots.acquire()
        try:
            while True:
                with self.lock:
                    now = time.monotonic()
                    delay = max(self.next_request, self.blocked_until) - now
                    if delay <= 0:
                        self.next_request = now + self.interval
                        admitted = True
                        break
                time.sleep(delay)
            yield admitted
        finally:
            self.slots.release()

    def throttle(self, retry_after=None):
        delay = 0.0
        try:
            delay = max(0.0, float(retry_after))
        except (TypeError, ValueError):
            try:
                delay = max(0.0, (parsedate_to_datetime(retry_after) - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                pass
        with self.lock:
            self.strikes = min(self.strikes + 1, 5)
            delay = max(delay, min(300.0, 15.0 * 2 ** (self.strikes - 1)) + random.uniform(0, 3))
            self.blocked_until = max(self.blocked_until, time.monotonic() + delay)
            self.interval = max(self.interval, 1.0)
        return delay

    def success(self):
        with self.lock:
            self.strikes = max(0, self.strikes - 1)


_gates = {}
_lock = threading.Lock()


def host_gate(url):
    host = urlsplit(url).hostname or ''
    with _lock:
        if host not in _gates:
            _gates[host] = HostGate(interval=0.5 if host == 'auth.garena.com' else 0.0,
                                    concurrency=2 if host == 'auth.garena.com' else 45)
        return _gates[host]
