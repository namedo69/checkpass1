"""Offline scheduling/spool regressions: synthetic accounts, no game network."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from uplv_satellite import Satellite, RevokedLease
import test_uplv_screening_handoff as handoff


class TurnoverTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.client = Mock()
        self.worker = Satellite(self.client, Mock(), directory.name, 'synthetic-worker')

    def spool(self, name):
        path = self.worker.state_dir / ('pending_report_' + name + '.json')
        path.write_text(json.dumps({'room_id': name}), encoding='utf8')
        return path

    def test_failed_report_retained_other_report_delivered_and_backoff_independent(self):
        bad, good = self.spool('a'), self.spool('b')
        def post(action, body):
            if body['room_id'] == 'a':
                raise TimeoutError('synthetic transport failure')
        self.client.post.side_effect = post
        self.assertFalse(self.worker.flush_report())
        self.assertTrue(bad.exists())
        self.assertFalse(good.exists())
        self.assertEqual(self.client.post.call_count, 2)
        self.spool('c')
        self.worker.flush_report()
        self.assertEqual(self.client.post.call_count, 3)
        self.assertTrue(bad.exists())

    def test_revoked_report_dropped_but_not_transient_failure(self):
        path = self.spool('old')
        self.client.post.side_effect = RevokedLease()
        self.assertTrue(self.worker.flush_report())
        self.assertFalse(path.exists())

    def test_spool_lock_never_blocks_caller_and_batch_is_bounded(self):
        for i in range(7):
            self.spool(str(i))
        self.worker.report_lock.acquire()
        try:
            self.assertFalse(self.worker.flush_report())
        finally:
            self.worker.report_lock.release()
        self.assertFalse(self.worker.flush_report(max_reports=2))
        self.assertEqual(self.client.post.call_count, 2)
        self.assertEqual(len(list(self.worker.state_dir.glob('*.json'))), 5)

    def test_room_returns_after_durable_checkpoint_without_network_report(self):
        room = dict(id='synthetic', lease_token='unused', lease_until=time.time()+180,
                    accounts=[['synthetic'+str(i), 'unused'] for i in range(5)])
        self.client.post.return_value = {'lease_until': time.time()+180}
        self.worker.engine.run.return_value = {i: (True, 5, 12, '') for i in range(5)}
        self.assertTrue(self.worker.run_room(room))
        path, = self.worker.state_dir.glob('pending_report_synthetic_*.json')
        data = json.loads(path.read_text())
        self.assertEqual(len(data['results']), 5)
        self.assertEqual(data['versions'], [0]*5)
        self.assertTrue(self.worker.report_wake.is_set())
        self.assertNotIn('report', [c.args[0] for c in self.client.post.call_args_list])

        # Reusing a pool room slot must not overwrite its previous lease spool.
        self.worker.run_room(dict(room, lease_token='next-lease'))
        paths = list(self.worker.state_dir.glob('pending_report_synthetic_*.json'))
        self.assertEqual(len(paths), 2)
        self.assertEqual({json.loads(p.read_text())['lease_token'] for p in paths},
                         {'unused', 'next-lease'})

    def test_pending_report_and_blocked_auxiliary_claim_do_not_block_refill(self):
        self.spool('old')
        auxiliary_started = threading.Event()
        release = threading.Event()
        second_claim = threading.Event()
        order = []
        def auxiliary(body):
            order.append('checkpass')
            auxiliary_started.set()
            release.wait(5)
            return {}
        def post(action, body):
            order.append(action)
            if action == 'report':
                raise TimeoutError('synthetic report failure')
            if action == 'claim':
                if order.count('claim') == 1:
                    return {'room': {'id': 'new'}}
                second_claim.set()
                self.worker.shutdown.set()
            return {}
        self.client.checkpass_claim.side_effect = auxiliary
        self.client.post.side_effect = post
        def room(_):
            self.assertTrue(auxiliary_started.wait(3))
        self.worker.run_room = room
        with patch('uplv_satellite.config.MAX_ROOMS', 1, create=True):
            thread = threading.Thread(target=self.worker.run)
            thread.start()
            try:
                self.assertTrue(second_claim.wait(4), 'Refill waited on report or CheckPass')
                self.assertLess(order.index('claim'), order.index('checkpass'))
            finally:
                release.set()
                self.worker.shutdown.set()
                thread.join(5)
            self.assertFalse(thread.is_alive())


class ScreeningAdmissionTests(unittest.TestCase):
    setUp = handoff.ScreeningHandoffTests.setUp

    def test_room_admission_returns_busy_without_queuing_or_consuming_work(self):
        held, release = threading.Event(), threading.Event()
        def hold():
            with self.pool.lock:
                held.set()
                release.wait(4)
        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(held.wait(2))
        try:
            start = time.monotonic()
            self.assertEqual(self.pool.claim({'satellite_id': 'test'})['reason'], 'coordinator_busy')
            self.assertTrue(self.pool.presence({'satellite_id': 'test'})['busy'])
            self.assertLess(time.monotonic()-start, .5)
            self.assertEqual(self.store.fetchone('SELECT COUNT(*) FROM uplv_claim_requests')[0], 0)
        finally:
            release.set()
            thread.join(3)

    def test_heartbeat_one_atomic_batch_and_stale_generation_no_write(self):
        self.store.exec("UPDATE uplv_tasks SET status='waiting'")
        room = self.pool.claim({'satellite_id': 'test', 'capacity': 1,
                               'verify_protocol': 1, 'screen_protocol': 1, 'direct_game_protocol': 1})['room']
        body = dict(satellite_id='test', room_id=room['id'], lease_token=room['lease_token'],
                    versions=[0]*5, progress={'0': {'stage': 'VERIFYING', 'level': 3}})
        with patch.object(self.store, 'batch', wraps=self.store.batch) as batch:
            with patch.object(self.store, 'exec', wraps=self.store.exec) as execute:
                self.assertGreater(self.pool.heartbeat(body)['lease_until'], time.time())
                self.assertEqual(batch.call_count, 1)
                self.assertEqual(execute.call_count, 0)
                with self.assertRaises(ValueError):
                    self.pool.heartbeat(dict(body, versions=[1]*5))
                self.assertEqual(batch.call_count, 1)

    def test_screening_skips_busy_coordinator(self):
        held, release = threading.Event(), threading.Event()
        def hold():
            with self.pool.lock:
                held.set()
                release.wait(4)
        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(held.wait(2))
        try:
            start = time.monotonic()
            self.assertIsNone(self.pool.hidden_check_claim({'satellite_id': 'test'}))
            self.assertLess(time.monotonic()-start, .5)
        finally:
            release.set()
            thread.join(3)

    def test_no_new_checkpass_claims_after_direct_game_switch(self):
        tasks = [r[0] for r in self.store.fetch('SELECT id FROM uplv_tasks ORDER BY created_at')]
        self.store.exec('INSERT INTO uplv_check_leases VALUES (?,?,?,?,?)',
                        (tasks[0], 'other', 'unused', time.time()+300, 0))
        self.assertIsNone(self.pool.hidden_check_claim({'satellite_id': 'test'}))
        self.assertIsNone(self.pool.hidden_check_claim({'satellite_id': 'other'}))
        self.store.exec('UPDATE uplv_check_leases SET lease_until=0')
        self.assertIsNone(self.pool.hidden_check_claim({'satellite_id': 'other'}))
        self.assertIsNone(self.pool.checkpass_claim({'satellite_id': 'other'})['check'])

    def test_delayed_report_keeps_capacity_until_ack_then_immediate_refill(self):
        self.store.exec("UPDATE uplv_tasks SET status='waiting'")
        body = {'satellite_id': 'test', 'capacity': 1, 'pool_protocol': 1,
                'verify_protocol': 1, 'screen_protocol': 1, 'direct_game_protocol': 1}
        room = self.pool.claim(body)['room']
        self.assertIsNotNone(room)
        self.assertEqual(self.pool.claim(body)['reason'], 'already_running')
        # More synthetic work is available while the old final report is late.
        self.pool.pool_add({'job_id': self.job, 'accounts': '\n'.join('new%d|unused' % i for i in range(5))})
        self.store.exec("UPDATE uplv_tasks SET status='waiting' WHERE status='screening'")
        report = dict(satellite_id='test', room_id=room['id'], lease_token=room['lease_token'],
                      versions=[0]*5, results={str(i): {'status': 'pending', 'level_after': 3} for i in range(5)})
        # Ownership and generations are still checked before any release.
        with self.assertRaises(ValueError):
            self.pool.report(dict(report, lease_token='wrong'))
        with self.assertRaises(ValueError):
            self.pool.report(dict(report, versions=[1]*5))
        self.pool.report(report)
        self.assertEqual(self.store.fetchone("SELECT COUNT(*) FROM uplv_tasks WHERE status='verifying'")[0], 5)
        # Old tasks may only receive inspection leases; defer their synthetic
        # next inspection so this assertion specifically exercises fresh work.
        for task, in self.store.fetch("SELECT id FROM uplv_tasks WHERE status='verifying'"):
            self.store.exec('INSERT INTO uplv_verify_attempts VALUES (?,?,?) ON CONFLICT(task_id) DO UPDATE SET next_at=excluded.next_at',
                            (task, 1, time.time()+300))
        next_room = self.pool.claim(body)['room']
        self.assertIsNotNone(next_room)
        self.assertTrue(set(a[0] for a in room['accounts']).isdisjoint(a[0] for a in next_room['accounts']))


if __name__ == '__main__':
    unittest.main()
