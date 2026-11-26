"""Offline 40-room publication pressure, no credentials or network."""
from concurrent.futures import ThreadPoolExecutor
import threading
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent/'uplv_runtime'))
from pve_runtime.rooms import run_rooms


class RoomPublicationTests(unittest.TestCase):
    def run_pool(self, count, battle, completed, stop=None):
        with patch('pve_runtime.rooms.run_five_batch', side_effect=battle):
            return run_rooms(
                [(f'synthetic-{i}', 'unused') for i in range(count)],
                12, 40, 8, stop or threading.Event(),
                lambda *args: (True, 5, 5, ''), lambda *args: None,
                lambda *args: None, completed=completed)

    def test_40_rooms_finish_battle_while_writer_is_blocked_and_drain_before_return(self):
        rendezvous = threading.Barrier(40, timeout=10)
        battles_done = threading.Event()
        release_writer = threading.Event()
        writer_started = threading.Event()
        lock = threading.Lock()
        finished = 0
        saved = []
        owners = set()

        def battle(accounts, *args, completed, **kwargs):
            nonlocal finished
            rendezvous.wait()
            rows = {i: (True, 5, 12, '') for i in range(5)}
            for i, row in rows.items():
                completed(i, row)
                completed(i, row)  # Duplicate completion cannot duplicate exports.
            with lock:
                finished += 1
                if finished == 40:
                    battles_done.set()
            return rows

        def persist(index, row):
            owners.add(threading.get_ident())
            writer_started.set()
            if not release_writer.wait(10):
                raise TimeoutError('Synthetic writer not released')
            saved.append(index)

        with ThreadPoolExecutor(max_workers=1) as caller:
            run = caller.submit(self.run_pool, 200, battle, persist)
            try:
                self.assertTrue(writer_started.wait(10))
                self.assertTrue(battles_done.wait(10), 'Disk blocked battle threads')
                self.assertFalse(run.done(), 'Run finished before exports drained')
            finally:
                release_writer.set()
            rows = run.result(timeout=10)
        self.assertEqual(len(rows), 200)
        self.assertEqual(sorted(saved), list(range(200)))
        self.assertEqual(len(owners), 1)

    def test_stop_still_drains_already_confirmed_results(self):
        stop = threading.Event()
        saved = []

        def battle(accounts, *args, completed, **kwargs):
            rows = {i: (True, 5, 12, '') for i in range(5)}
            for i, row in rows.items():
                completed(i, row)
            stop.set()
            return rows

        rows = self.run_pool(5, battle, lambda i, row: saved.append(i), stop)
        self.assertEqual(len(rows), 5)
        self.assertEqual(sorted(saved), list(range(5)))

    def test_writer_error_is_not_silently_ignored(self):
        def battle(accounts, *args, **kwargs):
            return {i: (True, 5, 12, '') for i in range(5)}

        def persist(*args):
            raise OSError('Synthetic disk failure')

        with self.assertRaisesRegex(OSError, 'Synthetic disk failure'):
            self.run_pool(5, battle, persist)

    def test_persistence_is_drained_when_scheduler_raises(self):
        saved = []
        calls = 0

        def persist(index, row):
            saved.append(index)

        def progress(index, message):
            nonlocal calls
            if '[STACK1]' in message:
                calls += 1
                if calls == 2:
                    raise RuntimeError('Synthetic scheduler error')

        # One already-target account is published before the next preparation.
        with self.assertRaisesRegex(RuntimeError, 'Synthetic scheduler error'):
            run_rooms([('one', 'unused'), ('two', 'unused')], 12, 1, 1,
                      threading.Event(), lambda *args: (True, 12, 12, ''),
                      None, progress, completed=persist)
        self.assertEqual(saved, [0])


if __name__ == '__main__':
    unittest.main()
