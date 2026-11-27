"""429 queue policy: synthetic SQLite, mocked clock, no account logins."""
import json
import unittest
from unittest.mock import patch

from uplv_coordinator import UpLvCoordinator
from test_uplv_screening_handoff import Store


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000000.0
        clock = patch('uplv_account_pool.time.time', side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.store = Store()
        self.addCleanup(self.store.db.close)
        self.store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT)')
        self.pool = UpLvCoordinator(self.store)
        self.accounts = '\n'.join(f'offline_rate_{i}|unused' for i in range(5))
        self.job = self.pool.pool_create({'accounts': self.accounts})['job_id']
        self.room = self.claim()

    def claim(self, worker='offline', **extra):
        return self.pool.claim(dict(satellite_id=worker, capacity=5, direct_game_protocol=1,
                                    verify_protocol=1, screen_protocol=1, **extra))['room']

    def body(self, room=None, kind='rate_limit', **extra):
        room = room or self.room
        return dict(satellite_id='offline', room_id=room['id'], lease_token=room['lease_token'],
                    versions=[0]*5, results={str(i): dict(status='failed', failure_kind=kind,
                        final_error='terminal_rate_limit: HTTP=429' if kind == 'rate_limit' else '',
                        level_after=0, **extra) for i in range(5)})

    def states(self):
        return self.store.fetch('SELECT DISTINCT status FROM uplv_tasks')

    def report(self, room=None, **extra):
        return self.pool.report(self.body(room, **extra))

    def test_initial_429_is_durable_wait_and_due_retry_is_game_not_profile(self):
        self.report()
        self.assertEqual(self.states(), [('rate_limit_wait',)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT room_id,slot FROM uplv_tasks'), [('', -1)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts,next_at,resume_state FROM uplv_rate_limit_wait'), [(1, self.now+30, 'waiting')])
        self.assertEqual(self.store.fetchone('SELECT status FROM uplv_jobs'), ('open',))
        for a in self.pool.account_details({'job_id': self.job})['accounts']:
            self.assertEqual(a['next_retry_at'], self.now+30)
            self.assertEqual(a['rate_limit_attempts'], 1)
        self.pool = UpLvCoordinator(self.store)
        self.now += 29
        self.assertIsNone(self.claim())
        self.now += 1
        retry = self.claim()
        self.assertFalse(retry['verify_only'])
        self.assertFalse(retry['screen_only'])

    def test_repeated_429_always_waits_30_seconds_never_exhausts_budget(self):
        room = self.room
        for count in range(1, 12):
            self.report(room)
            self.assertEqual(self.states(), [('rate_limit_wait',)])
            self.assertEqual(self.store.fetch('SELECT DISTINCT attempts,next_at FROM uplv_rate_limit_wait'), [(count, self.now+30)])
            self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_verify_attempts'), (0,))
            self.now += 30
            room = self.claim()
            self.assertIsNotNone(room)

    def test_duplicate_and_stale_reports_cannot_extend_wait(self):
        self.report()
        before = self.store.fetch('SELECT * FROM uplv_rate_limit_wait ORDER BY task_id')
        self.now += 5
        self.assertTrue(self.report()['duplicate'])
        self.assertEqual(self.store.fetch('SELECT * FROM uplv_rate_limit_wait ORDER BY task_id'), before)
        self.now += 25
        self.claim()
        with self.assertRaises(ValueError):
            self.report()

    def test_stop_while_waiting_and_stop_before_report_are_respected(self):
        self.report()
        self.pool.control(dict(action='stop_job', job_id=self.job))
        self.now += 300
        self.pool = UpLvCoordinator(self.store)
        self.assertIsNone(self.claim())
        self.assertEqual(self.states(), [('stopped',)])

    def test_operator_stop_before_429_report_does_not_queue(self):
        self.pool.control(dict(action='stop_job', job_id=self.job))
        self.report()
        self.assertEqual(self.states(), [('stopped',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_rate_limit_wait'), (0,))

    def test_terminal_history_is_never_migrated(self):
        self.report()
        self.store.exec("UPDATE uplv_tasks SET status='stopped'")
        self.now += 1000
        self.pool = UpLvCoordinator(self.store)
        self.assertIsNone(self.claim())
        self.assertEqual(self.states(), [('stopped',)])
        self.store.exec("UPDATE uplv_tasks SET status='failed'")
        self.assertIsNone(self.claim())
        self.assertEqual(self.states(), [('failed',)])

    def test_fleet_cooldown_blocks_new_accounts_but_not_renewal_or_report(self):
        job = self.pool.pool_create({'accounts': '\n'.join(f'offline_new_{i}|unused' for i in range(20))})['job_id']
        heartbeat = self.body()
        self.pool.heartbeat(heartbeat)
        before = self.store.fetchone("SELECT until_at FROM uplv_auth_cooldown")[0]
        self.now += 5
        self.assertIsNone(self.claim('other'))
        self.assertIsNone(self.pool.pool_form_room())
        renewed = self.pool.heartbeat(heartbeat)
        self.assertGreater(renewed['lease_until'], self.now)
        self.assertEqual(self.store.fetchone('SELECT until_at FROM uplv_auth_cooldown')[0], before)
        self.report()
        self.assertEqual(self.store.fetchone("SELECT count(*) FROM uplv_tasks WHERE job_id=? AND status='waiting'", (job,)), (20,))
        self.now = before
        self.assertIsNotNone(self.claim('probe'))
        self.assertIsNotNone(self.claim('other'))

    def test_verify_429_refunds_read_attempt_and_retries_read_only(self):
        self.report(kind='')
        self.now += 30
        room = self.claim()
        self.assertTrue(room['verify_only'])
        self.report(room)
        self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_verify_attempts'), [(0,)])
        self.now += 30
        self.assertTrue(self.claim()['verify_only'])

    def test_stale_pacing_fields_never_limit_healthy_admission(self):
        self.report()
        self.store.exec("UPDATE uplv_tasks SET status='stopped'")
        self.pool.pool_create({'accounts': '\n'.join(f'offline_tail_{i}|unused' for i in range(20))})
        self.now += 30
        self.store.exec('UPDATE uplv_auth_cooldown SET pace_until=?,next_admit=?', (self.now+99999,self.now+99999))
        self.assertIsNotNone(self.claim('one'))
        self.assertIsNotNone(self.claim('two'))
        self.assertIsNotNone(self.claim('three'))
        self.assertIsNotNone(self.claim('four'))

    def test_expired_429_quiet_interval_allows_all_42_workers_not_one_probe(self):
        self.report()
        self.pool.pool_settings({'max_rooms': 250})
        self.pool.pool_create({'accounts': '\n'.join(f'offline_fleet_{i}|unused' for i in range(210))})
        self.now += 30
        self.store.exec('UPDATE uplv_auth_cooldown SET pace_until=?,next_admit=?', (self.now+99999,self.now+99999))
        for i in range(42):
            self.assertIsNotNone(self.claim(f'worker_{i}'))
        self.assertEqual(self.store.fetchone("SELECT count(*) FROM uplv_rooms WHERE status='running'"), (42,))

    def test_heartbeat_429_with_lost_report_is_queued_after_lease_cleanup(self):
        self.pool.heartbeat(self.body())
        self.now = self.room['lease_until'] + 121
        self.pool.expire()
        self.assertEqual(self.states(), [('rate_limit_wait',)])
        with self.assertRaises(ValueError):
            self.report()
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            self.assertIn('429', json.loads(raw)['final_error'])

    def test_wait_prevents_tail_failure_and_keeps_exclusive_account_ownership(self):
        self.report()
        task = self.store.fetchone('SELECT id FROM uplv_tasks LIMIT 1')[0]
        self.store.exec("UPDATE uplv_tasks SET status='ready' WHERE id=?", (task,))
        self.pool.finish_unfillable_tail()
        self.assertEqual(self.store.fetchone('SELECT status FROM uplv_tasks WHERE id=?', (task,)), ('ready',))
        with self.assertRaises(ValueError):
            self.pool.pool_create({'accounts': self.accounts})

    def test_failed_batch_is_atomic_and_report_can_be_retried(self):
        with patch.object(self.store, 'batch', side_effect=RuntimeError('synthetic commit failure')):
            with self.assertRaises(RuntimeError):
                self.report()
        self.assertEqual(self.states(), [('assigned',)])
        self.assertEqual(self.store.fetchone('SELECT status FROM uplv_rooms'), ('running',))
        self.report()
        self.assertEqual(self.states(), [('rate_limit_wait',)])

    def test_repeated_session_auth_throttles_preserve_session_budget_and_deadline(self):
        self.report(kind='session_conflict')
        started = self.now
        for _ in range(8):
            self.now += 30
            room = self.claim()
            self.assertTrue(room['verify_only'])
            self.report(room)
            self.assertEqual(self.store.fetch('SELECT DISTINCT attempts FROM uplv_session_wait'), [(0,)])
            self.now += 30
            self.pool.release_rate_limit_wait()
            self.assertEqual(self.states(), [('session_wait',)])
        self.assertEqual(self.store.fetch('SELECT DISTINCT started_at FROM uplv_session_wait'), [(started+8*30,)])

    def test_replacement_429_never_substitutes_another_account(self):
        result = self.body()['results']['0']
        response = self.pool.replace(dict(satellite_id='offline', room_id=self.room['id'],
            lease_token=self.room['lease_token'], request_id='a'*32, slot=0,
            generation=0, phase='preparation', result=result))
        self.assertTrue(response['stop'])
        self.assertEqual(self.states(), [('assigned',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_replacements'), (0,))
        self.report()
        self.assertEqual(self.states(), [('rate_limit_wait',)])

    def test_429_remains_pending_in_export_not_failed(self):
        self.report()
        result = self.pool.export(self.job)
        self.assertFalse(result['failed'])
        self.assertEqual(len(result['pending'].splitlines()), 5)

    def test_partial_retry_group_waits_for_more_accounts_instead_of_failing(self):
        self.report()
        tasks = self.store.fetch('SELECT id FROM uplv_tasks LIMIT 4')
        for task, in tasks:
            self.store.exec("UPDATE uplv_tasks SET status='failed' WHERE id=?", (task,))
        self.now += 30
        self.assertIsNone(self.claim())
        self.assertEqual(self.store.fetchone("SELECT count(*) FROM uplv_tasks WHERE status='waiting'"), (1,))

    def test_user_details_expose_retry_time_but_no_diagnostics_or_password(self):
        self.store.exec('INSERT INTO uplv_job_owners VALUES (?,?)', (self.job, 123))
        self.report()
        data = self.pool.user_action('accounts', {'job_id': self.job}, {'user_id': 123})
        for row in data['accounts']:
            self.assertEqual(row['next_retry_at'], self.now+30)
            self.assertEqual(row['rate_limit_attempts'], 1)
            self.assertNotIn('detail', row)
            self.assertNotIn('unused', json.dumps(row))
    def test_stale_generation_cannot_queue_or_trigger_cooldown(self):
        body = self.body()
        body['versions'] = [1]*5
        with self.assertRaises(ValueError):
            self.pool.report(body)
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_auth_cooldown'), (0,))
        self.assertEqual(self.states(), [('assigned',)])


if __name__ == '__main__':
    unittest.main()
