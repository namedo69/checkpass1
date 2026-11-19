"""A shared bounded worker count across independently leased chunks."""
import threading
from concurrent.futures import ThreadPoolExecutor


class AccountPool(ThreadPoolExecutor):
    def __init__(self, capacity):
        super().__init__(max_workers=capacity, thread_name_prefix='account')
        self.capacity = capacity
        self._pending_lock = threading.Lock()
        self._pending_accounts = 0
        self.changed = threading.Event()

    @property
    def pending_accounts(self):
        with self._pending_lock:
            return self._pending_accounts

    def _finished(self, future):
        with self._pending_lock:
            self._pending_accounts -= 1
        self.changed.set()

    def submit(self, fn, /, *args, **kwargs):
        with self._pending_lock:
            self._pending_accounts += 1
        try:
            future = super().submit(fn, *args, **kwargs)
        except BaseException:
            self._finished(None)
            raise
        future.add_done_callback(self._finished)
        return future
