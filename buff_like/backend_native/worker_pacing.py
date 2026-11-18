"""Process-local scheduling reconstructed in WORKER_REPORT.md.

These are client pacing intervals, not guarantees about server rate limits.
"""
import threading
import time

GARENA_SLOTS = threading.BoundedSemaphore(20)
LOBBY_SLOTS = threading.BoundedSemaphore(256)
_lock = threading.Lock()
_next = {}


def pace(key, gap):
    with _lock:
        now = time.monotonic()
        slot = max(now, _next.get(key, now))
        _next[key] = slot + gap
    if slot > now:
        time.sleep(slot-now)
