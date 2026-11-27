import json
import threading
import time
import unittest
from unittest.mock import patch

from uplv_lock import CoordinatorLock


class CoordinatorLockTests(unittest.TestCase):
    def test_nested_acquisition_counts_outer_operation_once(self):
        lock = CoordinatorLock(interval=0)
        with patch('builtins.print') as output:
            with lock:
                self.assertTrue(lock.acquire(False))
                lock.release()
        payload = json.loads(output.call_args.args[0].split('] ', 1)[1])
        self.assertEqual(payload[self._testMethodName]['count'], 1)

    def test_busy_attempt_does_not_change_owner_or_allow_other_thread(self):
        lock = CoordinatorLock()
        attempts = []
        with lock:
            thread = threading.Thread(target=lambda: attempts.append(lock.acquire(False)))
            thread.start()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(attempts, [False])
        self.assertTrue(lock.acquire(False))
        lock.release()

    def test_exception_releases_lock(self):
        lock = CoordinatorLock()
        with self.assertRaises(ValueError):
            with lock:
                raise ValueError('fixture')
        self.assertTrue(lock.acquire(False))
        lock.release()

    def test_admission_handoff_follows_queued_priority_operation(self):
        lock = CoordinatorLock()
        order = []
        with lock:
            def priority():
                with lock:
                    order.append('report')
            report = threading.Thread(target=priority)
            report.start()
            deadline = time.monotonic()+2
            while not lock._priority_waiters and time.monotonic()<deadline:
                time.sleep(.001)
            self.assertEqual(lock._priority_waiters,1)
            def admission():
                if lock.acquire_admission(timeout=2):
                    order.append('claim')
                    lock.release()
            claim = threading.Thread(target=admission)
            claim.start()
        report.join(3);claim.join(3)
        self.assertFalse(report.is_alive())
        self.assertFalse(claim.is_alive())
        self.assertEqual(order,['report','claim'])

    def test_timed_out_admission_does_not_leave_ticket_or_consume_lock(self):
        lock = CoordinatorLock()
        replies = []
        with lock:
            worker=threading.Thread(target=lambda:replies.append(lock.acquire_admission(timeout=.01)))
            worker.start();worker.join(2)
            self.assertEqual(replies,[False])
            self.assertEqual(len(lock._tickets),0)
        self.assertTrue(lock.acquire_admission())
        lock.release()
