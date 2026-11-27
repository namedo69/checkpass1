"""Durable 91117 queue regressions. Synthetic accounts, no network/real DB."""
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uplv_coordinator import UpLvCoordinator
from test_uplv_screening_handoff import Store


class SessionWaitTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000000.0
        clock = patch('uplv_account_pool.time.time', side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.store = Store()
        self.addCleanup(self.store.db.close)
        self.store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT)')
        self.pool = UpLvCoordinator(self.store)
        self.accounts = '\n'.join(f'offline_wait_{i}|unused' for i in range(5))
        self.job = self.pool.pool_create({'accounts': self.accounts})['job_id']
        self.store.exec("UPDATE uplv_tasks SET status='waiting'")
        self.room = self.claim()

    def claim(self, worker='offline'):
        return self.pool.claim(dict(satellite_id=worker, capacity=1, pool_protocol=1,
                                    verify_protocol=1, screen_protocol=1, direct_game_protocol=1))['room']

    def report(self, room=None, kind='session_conflict', **extra):
        room = room or self.room
        result = dict(status='pending', level_after=10, failure_kind=kind)
        if kind == 'session_conflict':
            result['final_error'] = 'terminal_session_conflict: server_error_csid_1190_code_91117'
        result.update(extra)
        return self.pool.report(dict(satellite_id='offline', room_id=room['id'],
            lease_token=room['lease_token'], versions=[0]*5,
            results={str(i): dict(result) for i in range(5)}))

    def states(self):
        return self.store.fetch('SELECT DISTINCT status FROM uplv_tasks')

    def due_claim(self):
        self.now = self.store.fetchone('SELECT max(next_at) FROM uplv_session_wait')[0]
        return self.claim()

    def test_initial_conflict_releases_room_but_not_account_or_job(self):
        self.report()
        self.assertEqual(self.states(), [('session_wait',)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT room_id,slot FROM uplv_tasks'), [('', -1)])
        self.assertEqual(self.store.fetch('SELECT attempts,started_at,next_at FROM uplv_session_wait'), [(0, self.now, self.now+30)]*5)
        self.assertIsNone(self.claim())
        self.assertIsNone(self.claim('other-worker'))
        self.assertEqual(self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (self.job,)), ('open',))
        with self.assertRaises(ValueError):
            self.pool.pool_create({'accounts': self.accounts})

    def test_due_lease_is_verify_only_and_uses_separate_budget(self):
        for task, in self.store.fetch('SELECT id FROM uplv_tasks'):
            self.store.exec('INSERT INTO uplv_verify_attempts VALUES (?,?,?)', (task, 3, 0))
        self.report()
        room = self.due_claim()
        self.assertTrue(room['verify_only'])
        self.assertFalse(room['screen_only'])
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_session_wait'), [(1,)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_verify_attempts'), [(3,)])
        self.assertIsNone(self.claim('other-worker'))
        self.report(room, kind='')
        self.assertEqual(self.states(), [('session_wait',)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_verify_attempts'), [(3,)])

    def test_backoff_starts_at_completion_with_no_room_held(self):
        self.report()
        started = self.now
        for n, delay in ((1, 30), (2, 30), (3, 30), (4, 30), (5, 30)):
            room = self.due_claim()
            self.now += 45  # A slow read must not consume its own quiet interval.
            self.report(room)
            self.assertEqual(self.states(), [('session_wait',)])
            self.assertEqual(self.store.fetch('SELECT DISTINCT attempts,started_at,next_at FROM uplv_session_wait'), [(n, started, self.now+delay)])
            self.assertIsNone(self.claim())

    def test_sixth_inconclusive_check_pauses_without_infinite_retry(self):
        self.report()
        for _ in range(6):
            room = self.due_claim()
            self.report(room)
        self.assertEqual(self.states(), [('stopped',)])
        self.assertIsNone(self.claim())
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            d = json.loads(raw)
            self.assertEqual(d['stage'], 'PAUSED_SESSION_WAIT_LIMIT')
            self.assertIn('91117', d['final_error'])

    def test_absolute_deadline_expires_even_when_no_worker_checked(self):
        self.report()
        self.now += self.pool.SESSION_WAIT_MAX_SECONDS
        self.assertIsNone(self.claim())
        self.assertEqual(self.states(), [('stopped',)])
        self.assertEqual(self.store.fetchone('SELECT status FROM uplv_jobs WHERE id=?', (self.job,)), ('done',))

    def test_nonidle_profile_below_target_never_enters_battle_queue(self):
        self.report()
        room = self.due_claim()
        self.report(room, kind='', verified=True, idle=False)
        self.assertEqual(self.states(), [('session_wait',)])
        self.assertIsNone(self.pool.pool_form_room())

    def test_verified_idle_continues_without_stale_wait_budget(self):
        self.report()
        room = self.due_claim()
        self.report(room, kind='', verified=True, idle=True)
        self.assertEqual(self.states(), [('ready',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_session_wait'), (0,))
        self.assertFalse(self.claim()['verify_only'])

    def test_verified_idle_novice_returns_to_preparation_not_five_battle(self):
        self.report(level_after=3)
        room = self.due_claim()
        self.report(room, kind='', level_after=3, verified=True, idle=True)
        self.assertEqual(self.states(), [('waiting',)])

    def test_confirmed_target_can_finish_without_inventing_idle(self):
        self.report()
        room = self.due_claim()
        self.report(room, kind='', status='success', level_after=12, verified=True, idle=False)
        self.assertEqual(self.states(), [('success',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_session_wait'), (0,))

    def test_operator_stop_is_never_reopened(self):
        self.report()
        self.pool.control({'action': 'stop_job', 'job_id': self.job})
        self.now += 1000
        self.assertEqual(self.states(), [('stopped',)])
        self.assertIsNone(self.claim())

    def test_old_stopped_and_failed_tasks_with_91117_are_never_reopened(self):
        self.report()
        self.store.exec("UPDATE uplv_tasks SET status='stopped'")
        self.now += 1000
        self.pool = UpLvCoordinator(self.store)
        self.assertIsNone(self.claim())
        self.assertEqual(self.states(), [('stopped',)])
        self.store.exec("UPDATE uplv_tasks SET status='failed'")
        self.assertIsNone(self.claim())
        self.assertEqual(self.states(), [('failed',)])

    def test_conflict_report_after_operator_stop_does_not_queue(self):
        self.pool.control({'action': 'stop_job', 'job_id': self.job})
        self.report()
        self.assertEqual(self.states(), [('stopped',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_session_wait'), (0,))

    def test_new_ban_rate_limit_or_server_error_still_stops_operation(self):
        for kind in ('restricted', 'rate_limit', 'server_error', 'login', 'create_character'):
            with self.subTest(kind=kind):
                # Use one independent synthetic task group per case.
                self.store.exec("UPDATE uplv_tasks SET status='assigned',room_id=?", (self.room['id'],))
                self.store.exec('DELETE FROM uplv_session_wait')
                self.store.exec("UPDATE uplv_rooms SET status='running' WHERE id=?", (self.room['id'],))
                self.store.exec("UPDATE uplv_jobs SET status='open' WHERE id=?", (self.job,))
                self.report(kind=kind, status='failed')
                self.assertNotIn(('session_wait',), self.states())

    def test_rate_limit_during_release_check_is_not_retried_as_91117(self):
        self.report()
        room = self.due_claim()
        self.report(room, kind='rate_limit', final_error='HTTP=429')
        self.assertEqual(self.states(), [('rate_limit_wait',)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_session_wait'), [(0,)])
        self.now += 30
        self.assertTrue(self.claim()['verify_only'])

    def test_duplicate_report_does_not_reset_deadline(self):
        self.report()
        before = self.store.fetch('SELECT * FROM uplv_session_wait ORDER BY task_id')
        self.now += 30
        self.assertTrue(self.report()['duplicate'])
        self.assertEqual(self.store.fetch('SELECT * FROM uplv_session_wait ORDER BY task_id'), before)

    def test_wait_survives_coordinator_restart_without_reopening_terminal_tasks(self):
        self.report()
        before = self.store.fetch('SELECT * FROM uplv_session_wait ORDER BY task_id')
        self.pool = UpLvCoordinator(self.store)
        self.assertEqual(self.store.fetch('SELECT * FROM uplv_session_wait ORDER BY task_id'), before)
        self.assertIsNone(self.claim())
        self.assertTrue(self.due_claim()['verify_only'])

    def test_lost_inspection_preserves_budget_and_revokes_late_report(self):
        self.report()
        room = self.due_claim()
        self.now = room['lease_until'] + 121
        self.pool.expire()
        self.assertEqual(self.states(), [('session_wait',)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_session_wait'), [(1,)])
        with self.assertRaises(ValueError):
            self.report(room)
        self.assertIsNone(self.claim())

    def test_deadline_does_not_revoke_an_inflight_lease(self):
        self.report()
        self.now += self.pool.SESSION_WAIT_MAX_SECONDS - 10
        room = self.claim()
        self.now += 11
        self.pool.expire_session_wait()
        self.assertEqual(self.states(), [('assigned',)])
        self.report(room, kind='')
        self.assertEqual(self.states(), [('stopped',)])

    def test_stale_generation_cannot_finish_a_wait_inspection(self):
        self.report()
        room = self.due_claim()
        before = self.store.fetch('SELECT * FROM uplv_session_wait ORDER BY task_id')
        with self.assertRaisesRegex(ValueError, 'Stale slot'):
            self.pool.report(dict(satellite_id='offline', room_id=room['id'],
                lease_token=room['lease_token'], versions=[1]*5, results={}))
        self.assertEqual(self.states(), [('assigned',)])
        self.assertEqual(self.store.fetch('SELECT * FROM uplv_session_wait ORDER BY task_id'), before)

    def test_duplicate_report_after_room_reuse_rejected_by_old_token(self):
        self.report()
        room = self.due_claim()
        with self.assertRaises(ValueError):
            self.report(self.room)
        self.assertEqual(self.states(), [('assigned',)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_session_wait'), [(1,)])

    def test_heartbeat_conflict_survives_lost_final_report(self):
        self.pool.heartbeat(dict(satellite_id='offline', room_id=self.room['id'],
            lease_token=self.room['lease_token'], versions=[0]*5,
            results={str(i):dict(status='pending', failure_kind='session_conflict',
                final_error='server_error_csid_1190_code_91117') for i in range(5)}))
        self.now = self.room['lease_until'] + 121
        self.pool.expire()
        self.assertEqual(self.states(), [('session_wait',)])
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            self.assertIn('91117', json.loads(raw)['final_error'])
        self.assertIsNone(self.claim())

    def test_details_show_separate_budget_and_due_time(self):
        self.report()
        d = self.pool.account_details({'job_id': self.job, 'status': 'session_wait'})
        self.assertEqual(d['total'], 5)
        for a in d['accounts']:
            self.assertEqual(a['attempts'], 0)
            self.assertTrue(a['session_wait_active'])
            self.assertEqual(a['session_wait_attempts'], 0)
            self.assertEqual(a['next_retry_at'], self.now+30)
            self.assertEqual(a['session_wait_deadline'], self.now+7200)

    def test_pending_wait_prevents_unfillable_tail_failure(self):
        self.report()
        task, = self.store.fetchone('SELECT id FROM uplv_tasks LIMIT 1')
        self.store.exec("UPDATE uplv_tasks SET status='ready' WHERE id=?", (task,))
        self.store.exec('DELETE FROM uplv_session_wait WHERE task_id=?', (task,))
        self.pool.finish_unfillable_tail()
        self.assertEqual(self.store.fetchone('SELECT status FROM uplv_tasks WHERE id=?', (task,)), ('ready',))


class WaitWorkerTests(unittest.TestCase):
    def engine(self):
        from uplv_engine import Engine
        engine = Engine.__new__(Engine)
        engine.login_lock = threading.Lock()
        engine.last_login = 0
        login = Mock(return_value=SimpleNamespace(access_token='fixture', open_id='fixture'))
        run_cs = Mock()
        engine.runtime = (Mock(), run_cs, login, lambda _: {'device_id': 'fixture'}, None, None)
        return engine, login, run_cs

    def test_wait_inspection_reads_once_without_preparation_battle_or_second_auth(self):
        engine, login, run_cs = self.engine()
        progress = Mock()
        room = dict(accounts=[['offline_wait', 'unused']], levels=[3], targets=[12], verify_only=True)
        with patch('uplv_profile_v2.read_profile', return_value=(3, False)) as read:
            rows = engine.run(room, threading.Event(), progress, Mock())
        self.assertEqual(rows[0], (False, 3, 3, 'pool_verifying'))
        read.assert_called_once()
        login.assert_called_once()
        run_cs.assert_not_called()
        engine.runtime[0].assert_not_called()
        self.assertTrue(any('[VERIFY_WAIT]' in c.args[1] for c in progress.call_args_list))

    def test_repeat_conflict_stops_worker_once_and_skips_fallback(self):
        engine, login, run_cs = self.engine()
        room = dict(accounts=[['offline_wait', 'unused']], levels=[10], targets=[12], verify_only=True)
        with patch('uplv_profile_v2.read_profile', side_effect=RuntimeError('server_error_csid_1190_code_91117')) as read:
            rows = engine.run(room, threading.Event(), Mock(), Mock())
        self.assertIn('terminal_session_conflict:', rows[0][3])
        read.assert_called_once()
        login.assert_called_once()
        run_cs.assert_not_called()

    def test_auth_429_in_read_only_inspection_is_rate_limit_not_restricted(self):
        engine, login, run_cs = self.engine()
        error = RuntimeError('HTTP=429')
        error.code = 429
        error.http_status = 429
        login.side_effect = error
        room = dict(accounts=[['offline_wait', 'unused']], levels=[10], targets=[12], verify_only=True)
        with patch('uplv_profile_v2.read_profile') as read:
            rows = engine.run(room, threading.Event(), Mock(), Mock())
        self.assertIn('terminal_rate_limit:', rows[0][3])
        self.assertNotIn('terminal_restricted:', rows[0][3])
        login.assert_called_once()
        read.assert_not_called()
        run_cs.assert_not_called()

    def test_wait_diagnostic_survives_durable_worker_report(self):
        from uplv_satellite import Satellite
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.post.return_value = {'lease_until': time.time()+180}
            engine = Mock()
            def run(room, stop, progress, completed, **kwargs):
                progress(0, '[VERIFY_WAIT] Đọc được cấp nhưng chưa xác nhận phiên rảnh; không mở trận')
                progress(0, '[DEFERRED] Chờ master')
                return {0: (False, 3, 3, 'pool_verifying')}
            engine.run.side_effect = run
            worker = Satellite(client, engine, directory, 'offline')
            with patch('builtins.print'):
                worker.run_room(dict(id='fixture', lease_token='unused', lease_until=time.time()+180,
                    accounts=[['offline_wait', 'unused']]))
            report = json.loads(next(Path(directory).glob('pending_report_*.json')).read_text())
            self.assertIn('chưa xác nhận phiên rảnh', report['results']['0']['root_cause'])
            self.assertFalse(report['results']['0']['verified'])
            self.assertFalse(report['results']['0']['idle'])


if __name__ == '__main__':
    unittest.main()
