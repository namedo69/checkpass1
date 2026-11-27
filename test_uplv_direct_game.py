"""Direct upload -> UpLv login regressions, synthetic accounts/in-memory DB."""
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_uplv_screening_handoff import Store
from uplv_coordinator import UpLvCoordinator
from uplv_engine import Engine
from uplv_satellite import Satellite


class DirectGameTests(unittest.TestCase):
    def setUp(self):
        for target in ('socket.create_connection', 'socket.socket.connect', 'urllib.request.urlopen'):
            guard = patch(target, side_effect=AssertionError('network forbidden'))
            guard.start(); self.addCleanup(guard.stop)
        self.store = Store(); self.addCleanup(self.store.db.close)
        self.store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT)')
        self.pool = UpLvCoordinator(self.store)
        self.created = self.pool.pool_create({'accounts':'\n'.join(f'direct{i}|unused' for i in range(5))})
        self.job = self.created['job_id']

    def claim(self):
        return self.pool.claim(dict(satellite_id='offline', capacity=5, pool_protocol=1,
                                    verify_protocol=1, screen_protocol=1, direct_game_protocol=1))['room']

    def test_old_worker_cannot_take_new_work_or_create_assignment(self):
        reply = self.pool.claim(dict(satellite_id='old',capacity=5,pool_protocol=1,
                                    verify_protocol=1,screen_protocol=1))
        self.assertEqual(reply['reason'], 'worker_upgrade_required')
        self.assertIsNone(reply['room'])
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('waiting',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_rooms')[0], 0)

    def test_presence_preserves_only_valid_direct_game_telemetry(self):
        for value in (1, None, 0, 2, '1', True, {}, float('nan')):
            with self.subTest(protocol=value):
                self.pool.presence(dict(satellite_id='telemetry', metrics={
                    'direct_game_protocol': value, 'capacity': 5,
                    'access_token': 'must-not-be-stored'}))
                metrics = json.loads(self.store.fetchone(
                    'SELECT metrics_json FROM uplv_satellites WHERE id=?', ('telemetry',))[0])
                expected = {'capacity': 5}
                if type(value) is int and value == 1:
                    expected['direct_game_protocol'] = 1
                self.assertEqual(metrics, expected)

    def test_presence_records_bounded_version_and_exact_capabilities(self):
        from uplv_satellite import VERSION
        self.pool.presence(dict(satellite_id='telemetry', metrics={
            'worker_version': VERSION, 'auth_web_session': 1,
            'ban_only_failure': 1, 'password': 'must-not-be-stored'}))
        metrics = json.loads(self.store.fetchone(
            'SELECT metrics_json FROM uplv_satellites WHERE id=?', ('telemetry',))[0])
        self.assertEqual(metrics, dict(worker_version=VERSION, auth_web_session=1, ban_only_failure=1))
        for value in (None, 1, {}, 'secret\nvalue', 'uplv-satellite-' + 'x'*81):
            self.pool.presence(dict(satellite_id='telemetry', metrics={
                'worker_version': value, 'auth_web_session': True, 'ban_only_failure': '1'}))
            self.assertEqual(json.loads(self.store.fetchone(
                'SELECT metrics_json FROM uplv_satellites WHERE id=?', ('telemetry',))[0]), {})

    def test_upload_and_add_go_straight_to_game_queue_without_level_claim(self):
        self.pool.pool_add(dict(job_id=self.job, accounts='extra|unused'))
        self.assertEqual(self.created['screening_accounts'], 0)
        self.assertEqual(self.created['profile_source'], 'game')
        self.assertEqual(self.store.fetch('SELECT DISTINCT status,level FROM uplv_tasks'), [('waiting',0)])
        room = self.claim()
        self.assertIsNotNone(room)
        self.assertFalse(room['verify_only'])
        self.assertFalse(room['screen_only'])
        self.assertEqual(room['levels'], [0]*5)
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_check_chunks')[0], 0)

    def test_checkpass_cannot_claim_even_legacy_screening_backlog(self):
        self.store.exec("UPDATE uplv_tasks SET status='screening'")
        self.assertIsNone(self.pool.hidden_check_claim(dict(satellite_id='checker')))
        self.assertIsNone(self.pool.checkpass_claim(dict(satellite_id='checker'))['check'])
        self.assertIsNotNone(self.claim())

    def old_chunk(self, until):
        self.store.exec("UPDATE uplv_tasks SET status='screening'")
        tasks = self.store.fetch('SELECT id,account_json FROM uplv_tasks ORDER BY created_at')
        items = [{'task_id':t, 'account':json.loads(a)} for t,a in tasks]
        self.store.exec('INSERT INTO uplv_check_chunks VALUES (?,?,?,?,?,?,?)',
            ('old', self.job, json.dumps(items), 'claimed', 'checker', 'old-token', until))
        for task, _ in tasks:
            self.store.exec('INSERT INTO uplv_check_members VALUES (?,?)', (task, 'old'))

    def test_legacy_owner_and_cleanup_grace_are_not_stolen(self):
        self.old_chunk(time.time()+300)
        self.assertIsNone(self.claim())
        self.store.exec('UPDATE uplv_check_chunks SET lease_until=?', (time.time()-60,))
        self.assertIsNone(self.claim())
        self.store.exec('UPDATE uplv_check_chunks SET lease_until=?', (time.time()-121,))
        self.assertIsNotNone(self.claim())
        self.pool.hidden_check_report(dict(satellite_id='checker',chunk_id='old',lease_token='old-token',
            rows=[dict(stt='1', level='30')],done=True))
        self.assertEqual(self.store.fetch('SELECT DISTINCT status,level FROM uplv_tasks'), [('assigned',0)])

    def test_legacy_direct_lease_blocks_until_grace_passes(self):
        self.store.exec("UPDATE uplv_tasks SET status='screening'")
        for task, in self.store.fetch('SELECT id FROM uplv_tasks'):
            self.store.exec('INSERT INTO uplv_check_leases VALUES (?,?,?,?,?)',
                            (task,'checker','old',time.time()-60,1))
        self.assertIsNone(self.claim())
        self.store.exec('UPDATE uplv_check_leases SET lease_until=0')
        self.assertIsNotNone(self.claim())

    def test_stopped_failed_and_stopped_jobs_untouched(self):
        tasks = [r[0] for r in self.store.fetch('SELECT id FROM uplv_tasks')]
        self.store.exec("UPDATE uplv_tasks SET status='stopped' WHERE id=?", (tasks[0],))
        self.store.exec("UPDATE uplv_tasks SET status='failed' WHERE id=?", (tasks[1],))
        self.store.exec("UPDATE uplv_tasks SET status='screening' WHERE status='waiting'")
        before = self.store.fetch('SELECT id,status FROM uplv_tasks ORDER BY id')
        self.store.exec("UPDATE uplv_jobs SET status='stopped'")
        self.pool.release_legacy_screening()
        self.assertEqual(self.store.fetch('SELECT id,status FROM uplv_tasks ORDER BY id'), before)

    def test_duplicate_upload_still_rejected(self):
        with self.assertRaises(ValueError):
            self.pool.pool_create(dict(accounts='direct0|unused'))

    def engine(self, run_cs):
        engine = Engine.__new__(Engine)
        engine.state_dir = Path('offline-unused-state')
        engine.login_lock, engine.last_login = threading.Lock(), 0
        login = Mock(return_value=SimpleNamespace(access_token='unused', open_id='a'*32))
        engine.runtime = (Mock(), run_cs, login, lambda _:dict(device_id='unused'), Mock(), Mock())
        return engine, login

    def test_initial_game_login_uses_actual_level_and_per_account_targets(self):
        room = self.claim()
        run_cs = Mock(return_value=dict(ok=True, level_before=12, level_after=12))
        engine, login = self.engine(run_cs)
        def batch(accounts, target, concurrency, stop, prepare, authenticate, progress, **kwargs):
            self.assertEqual(kwargs['require_idle'], set(range(5)))
            self.assertEqual(kwargs['targets'], [12]*5)
            self.assertNotIn('web_verify', kwargs)
            return {i: prepare(i,*account) for i,account in enumerate(accounts)}
        with patch('pve_runtime.uplv.run_five_batch', side_effect=batch), \
                patch('uplv_engine.time.monotonic', return_value=100), \
                patch('uplv_kientuong.PlayerSession', side_effect=AssertionError('no web')):
            rows = engine.run(room, threading.Event(), Mock(), Mock())
        self.assertTrue(all(row[0] and row[2] == 12 for row in rows.values()))
        self.assertEqual(run_cs.call_count, 5)
        self.assertEqual(login.call_count, 5)
        self.assertTrue(all(not c.kwargs['with_sso_key'] for c in login.call_args_list))

    def test_direct_worker_reports_target_and_denials_to_master_without_precheck(self):
        self.pool.pool_add(dict(job_id=self.job, accounts='\n'.join(f'leftover{i}|unused' for i in range(5))))
        room = self.claim()
        outcomes = [dict(ok=True, level_before=12, level_after=12),
                    dict(ok=False, reject='server_error_csid_1190_code_91126'),
                    dict(ok=False, reject='server_error_csid_1190_code_91117'),
                    dict(ok=False, reject='role_level_not_received_after_create'),
                    dict(ok=False, reject='HTTP 429')]
        run_cs = Mock(side_effect=outcomes)
        engine, _ = self.engine(run_cs)
        def batch(accounts, target, concurrency, stop, prepare, authenticate, progress, **kwargs):
            return {i: prepare(i,*account) for i,account in enumerate(accounts)}
        with tempfile.TemporaryDirectory() as folder:
            client = Mock(); client.post.return_value = dict(lease_until=time.time()+180)
            worker = Satellite(client, engine, folder, 'offline')
            with patch('pve_runtime.uplv.run_five_batch', side_effect=batch), \
                    patch('uplv_engine.time.monotonic', return_value=100), \
                    patch('uplv_kientuong.PlayerSession', side_effect=AssertionError('no web')):
                worker.run_room(room)
            report = json.loads(next(Path(folder).glob('pending_report_*.json')).read_text())
        self.pool.report(report)
        self.assertEqual(self.store.fetch('SELECT status FROM uplv_tasks WHERE room_id=? ORDER BY slot', (room['id'],)),
                         [('success',), ('failed',)])
        self.assertEqual(self.store.fetchone("SELECT count(*) FROM uplv_tasks WHERE status='retry_wait' AND room_id='' AND slot=-1")[0], 1)
        self.assertEqual(self.store.fetchone("SELECT count(*) FROM uplv_tasks WHERE status='rate_limit_wait'")[0], 1)
        self.assertEqual(self.store.fetchone("SELECT count(*) FROM uplv_tasks WHERE status='session_wait'")[0], 1)
        self.assertEqual(report['results']['1']['failure_kind'], 'restricted')
        self.assertEqual(report['results']['2']['failure_kind'], 'session_conflict')
        self.assertEqual(run_cs.call_count, 5)
        client.checkpass_claim.assert_not_called()

    def test_ban_conflict_and_unknown_error_are_not_confused(self):
        from pve_runtime.failure_policy import terminal_result
        for code, kind in ((91126,'restricted'), (91117,'session_conflict'), (91123,'create_character'), (99999,'server_error')):
            with self.subTest(code=code):
                row = terminal_result((False,0,0,f'server_error_csid_1190_code_{code}'))
                self.assertTrue(row[3].startswith('terminal_'+kind+':'))

    def test_worker_no_checkpass_engine_loaded_for_uplv_uploads(self):
        with tempfile.TemporaryDirectory() as folder:
            client = Mock(); client.checkpass_claim.return_value = {'claim':None}
            worker = Satellite(client, Mock(), folder, 'offline')
            worker._load_checkpass_engine = Mock(side_effect=AssertionError('no precheck'))
            worker.claim_checkpass_chunk()
            worker._load_checkpass_engine.assert_not_called()
            client.post.assert_not_called()


if __name__ == '__main__':
    unittest.main()
