"""Aggregate coordinator lock timings; never collect request/account data."""
import json
from collections import deque
import sys
import threading
import time


class CoordinatorLock:
    def __init__(self, interval=30):
        self._lock = threading.RLock()
        self._local = threading.local()
        self._stats_lock = threading.Lock()
        self._stats = {}
        self._logged_at = time.monotonic()
        self._interval = interval
        self._admission = threading.Condition()
        self._priority_waiters = 0
        self._tickets = deque()

    def acquire(self, blocking=True, timeout=-1):
        started = time.monotonic()
        priority = blocking and not getattr(self._local, 'depth', 0)
        if priority:
            with self._admission:
                self._priority_waiters += 1
        try:
            acquired = self._lock.acquire(blocking, timeout)
        finally:
            if priority:
                with self._admission:
                    self._priority_waiters -= 1
                    self._admission.notify_all()
        if acquired:
            depth = getattr(self._local, 'depth', 0)
            if not depth:
                self._local.started = time.monotonic()
                self._local.wait_ms = (self._local.started - started) * 1000
                caller = sys._getframe(1)
                if caller.f_code.co_name in ('__enter__', 'acquire_admission'):
                    caller = caller.f_back
                self._local.operation = caller.f_code.co_name
            self._local.depth = depth + 1
        return acquired

    def acquire_admission(self, timeout=.25):
        """Brief FIFO handoff, never ahead of queued renewals/reports/STOP.

        Waiting consumes no DB connection, request id or lease. A bounded wait
        avoids discarding every free-slot request during a short critical section.
        """
        ticket = object()
        deadline = time.monotonic() + timeout
        with self._admission:
            self._tickets.append(ticket)
            try:
                while True:
                    if (self._tickets[0] is ticket and not self._priority_waiters
                            and self.acquire(False)):
                        return True
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._admission.wait(remaining)
            finally:
                self._tickets.remove(ticket)
                self._admission.notify_all()

    def release(self):
        depth = getattr(self._local, 'depth', 0)
        if depth != 1:
            self._lock.release()
            self._local.depth = max(0, depth - 1)
            return
        elapsed = (time.monotonic() - self._local.started) * 1000
        operation, wait_ms = self._local.operation, self._local.wait_ms
        self._lock.release()
        self._local.depth = 0
        with self._admission:
            self._admission.notify_all()
        # Printing and aggregation never extend the coordinator critical section.
        payload = None
        with self._stats_lock:
            row = self._stats.setdefault(operation, dict(count=0, hold_ms=0, max_hold_ms=0, wait_ms=0))
            row['count'] += 1
            row['hold_ms'] += elapsed
            row['max_hold_ms'] = max(row['max_hold_ms'], elapsed)
            row['wait_ms'] += wait_ms
            now = time.monotonic()
            if now - self._logged_at >= self._interval:
                payload = {name: {key: round(value, 2) for key, value in values.items()}
                           for name, values in self._stats.items()}
                self._stats = {}
                self._logged_at = now
        if payload is not None:
            print('[uplv-lock] ' + json.dumps(payload), flush=True)

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *exc):
        self.release()
