"""Offline session/denial/diagnostic regressions; no real account or network."""
from contextlib import nullcontext
import json
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent / 'uplv_runtime'))
sys.path.insert(0, str(Path(__file__).parent / 'uplv_runtime/pve_backend'))
from pve_runtime.failure_policy import terminal_result
from pve_runtime.reconnect import recover_battle
from purepc.registration_v2 import role_name, CreationState
from uplv_coordinator import UpLvCoordinator
from uplv_satellite import Satellite
from test_uplv_screening_handoff import ScreeningHandoffTests


class RecoveryTests(unittest.TestCase):
    def session(self):
        return SimpleNamespace(character_uid=123, level=10, experience=808,
            stop=SimpleNamespace(wait=lambda _: False), check_stop=Mock(), close=Mock(),
            connect=Mock(), send_game=Mock(), receive_game=Mock(return_value=(1061, b'\0', None)))

    def test_idle_unchanged_profile_connects_once_and_remains_unconfirmed(self):
        session = self.session()
        with patch('pve_runtime.reconnect.load', return_value=SimpleNamespace(wait_lobby=Mock())), \
             patch('pve_runtime.reconnect.session_deadline', side_effect=lambda *a: nullcontext()):
            result = recover_battle(session, dict(uid=123, level=10, exp=808))
        self.assertFalse(result['reward_confirmed'])
        session.connect.assert_called_once()

    def test_denial_is_not_swallowed_or_retried(self):
        session = self.session()
        session.connect.side_effect = RuntimeError('server_error_csid_1190_code_91117')
        with patch('pve_runtime.reconnect.session_deadline', side_effect=lambda *a: nullcontext()):
            with self.assertRaisesRegex(RuntimeError, '91117'):
                recover_battle(session, dict(uid=123, level=10, exp=808))
        session.connect.assert_called_once()

    def test_uid_mismatch_never_confirms_reward(self):
        session = self.session()
        with patch('pve_runtime.reconnect.session_deadline', side_effect=lambda *a: nullcontext()):
            with self.assertRaisesRegex(ValueError, 'UID'):
                recover_battle(session, dict(uid=999, level=5, exp=0))

    def test_stop_during_release_wait_never_connects(self):
        session = self.session()
        session.stop = SimpleNamespace(wait=Mock(return_value=True))
        result = recover_battle(session, dict(uid=123, level=10, exp=808))
        session.stop.wait.assert_called_once_with(30)
        session.connect.assert_not_called()
        self.assertFalse(result['reward_confirmed'])

    def test_transport_failure_does_not_spin_even_with_legacy_attempts_argument(self):
        session = self.session()
        session.stop = SimpleNamespace(wait=Mock(return_value=False))
        session.connect.side_effect = TimeoutError('fixture transport')
        with patch('pve_runtime.reconnect.session_deadline', side_effect=lambda *a: nullcontext()):
            result = recover_battle(session, dict(uid=123, level=10, exp=808), attempts=3)
        session.connect.assert_called_once()
        session.stop.wait.assert_called_once_with(30)
        self.assertEqual(len(result['attempts']), 1)
        self.assertFalse(result['reward_confirmed'])

    def test_unknown_state_cannot_start_relay_or_confirm_reward(self):
        session = self.session()
        session.receive_game.side_effect = TimeoutError('no state')
        vendor = SimpleNamespace(wait_lobby=Mock(), RelayBattle=Mock())
        with patch('pve_runtime.reconnect.load', return_value=vendor), \
             patch('pve_runtime.reconnect.session_deadline', side_effect=lambda *a: nullcontext()):
            result = recover_battle(session, dict(uid=123, level=10, exp=808))
        vendor.RelayBattle.assert_not_called()
        self.assertFalse(result['reward_confirmed'])
        session.connect.assert_called_once()

    def test_readback_signal_reads_reward_once_without_recovering_again(self):
        class ProfileReadbackRequired(ConnectionError):
            pass
        session = self.session()
        session.receive_game.return_value = (1061, b'\1', None)
        relay = Mock()
        relay.run.side_effect = ProfileReadbackRequired()
        def connect():
            if session.connect.call_count == 2:
                session.level = 12
        session.connect.side_effect = connect
        vendor = SimpleNamespace(wait_lobby=Mock(), RelayBattle=Mock(return_value=relay))
        with patch('pve_runtime.reconnect.load', return_value=vendor), \
             patch('pve_runtime.reconnect.session_deadline', side_effect=lambda *a: nullcontext()):
            result = recover_battle(session, dict(uid=123, level=10, exp=808))
        self.assertTrue(result['reward_confirmed'])
        self.assertEqual(session.connect.call_count, 2)
        relay.run.assert_called_once_with(recover=True)

    def test_policy_reclassifies_catch_all_without_retry_permission(self):
        for code, kind in ((91117, 'session_conflict'), (91123, 'create_character'),
                           (91126, 'restricted'), (91121, 'server_error')):
            row = terminal_result((False, 5, 10, f'terminal_restricted: server_error_csid_1190_code_{code}'))
            self.assertTrue(row[3].startswith('terminal_' + kind + ':'))
        self.assertTrue(terminal_result((False, 0, 0, 'terminal_login: HTTP=429'))[3].startswith('terminal_rate_limit:'))

    def test_short_names_and_no_retry_on_1190(self):
        for _ in range(20):
            name = role_name()
            self.assertEqual(len(name), 10)
            self.assertTrue(name.isascii())
        state = CreationState()
        state.mark_sent()
        self.assertEqual(state.reply(1190, 91123), 'reject')
        self.assertFalse(state.pending)

    def test_inconclusive_verification_does_not_reopen_game_or_auth(self):
        from uplv_engine import Engine
        engine = Engine.__new__(Engine)
        engine.login_lock = threading.Lock()
        engine.last_login = 0
        login = Mock(return_value=SimpleNamespace(access_token='fixture', open_id='fixture'))
        engine.runtime = (None, None, login, lambda _: {'device_id': 'fixture'}, None, None)
        stop = Mock()
        stop.is_set.return_value = False
        stop.wait.return_value = False
        room = dict(accounts=[['synthetic', 'unused']], levels=[10], targets=[12], verify_only=True)
        with patch('uplv_profile_v2.read_profile', side_effect=[(10, False), (12, True)]):
            rows = engine.run(room, stop, Mock(), Mock())
        self.assertFalse(rows[0][0])
        self.assertEqual(rows[0][3], 'pool_verifying')
        login.assert_called_once()
        self.assertNotIn('_auth_context', room)

    def test_satellite_final_error_replaces_stale_detail_and_is_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            client.post.return_value = {'lease_until': time.time()+180}
            engine = Mock()
            def run(room, stop, progress, completed, **kwargs):
                progress(0, '[ERROR] old recovery detail')
                progress(0, '[VERIFYING] server_error_csid_1190_code_91117')
                return {0: (False, 5, 10, 'terminal_restricted: server_error_csid_1190_code_91117')}
            engine.run.side_effect = run
            worker = Satellite(client, engine, directory, 'offline')
            worker.run_room(dict(id='fixture', lease_token='unused', lease_until=time.time()+180,
                                 accounts=[['synthetic-user', 'unused']]))
            data = json.loads(next(Path(directory).glob('pending_report_*.json')).read_text())
            self.assertIn('91117', data['progress']['0']['detail'])
            self.assertIn('old recovery', data['results']['0']['root_cause'])
            self.assertEqual(data['results']['0']['failure_kind'], 'session_conflict')
            self.assertEqual(data['results']['0']['status'], 'pending')

    def test_clean_rows_retains_and_redacts_final_error(self):
        rows = UpLvCoordinator.clean_rows({'0': dict(status='pending', failure_kind='session_conflict',
            final_error='91117 fixture-password token=secret', root_cause='fixture-password')}, ['fixture-password'])
        self.assertIn('91117', rows['0']['final_error'])
        self.assertNotIn('secret', rows['0']['final_error'])
        self.assertNotIn('fixture-password', json.dumps(rows))


class QuarantineTests(unittest.TestCase):
    setUp = ScreeningHandoffTests.setUp

    def test_conflict_is_queued_not_failed_and_cannot_be_immediately_claimed(self):
        self.store.exec("UPDATE uplv_tasks SET status='waiting'")
        room = self.pool.claim(dict(satellite_id='offline', capacity=1, pool_protocol=1,
                                    verify_protocol=1, screen_protocol=1, direct_game_protocol=1))['room']
        results = {str(i): dict(status='pending', level_after=10, failure_kind='session_conflict',
                   final_error='terminal_session_conflict: server_error_csid_1190_code_91117') for i in range(5)}
        self.pool.report(dict(satellite_id='offline', room_id=room['id'], lease_token=room['lease_token'],
                              versions=[0]*5, results=results))
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('session_wait',)])
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            self.assertIn('91117', json.loads(raw)['detail'])
        self.assertIsNone(self.pool.pool_form_room())

    def assign(self):
        self.store.exec("UPDATE uplv_tasks SET status='waiting'")
        return self.pool.claim(dict(satellite_id='offline', capacity=1, pool_protocol=1,
                                    verify_protocol=1, screen_protocol=1, direct_game_protocol=1))['room']

    def pending_report(self, room):
        self.pool.report(dict(satellite_id='offline', room_id=room['id'], lease_token=room['lease_token'],
            versions=[0]*5, results={str(i): dict(status='pending', level_after=10) for i in range(5)}))

    def test_inconclusive_battle_persists_cooldown_from_completion(self):
        room = self.assign()
        start = time.time()
        self.pending_report(room)
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('verifying',)])
        for count, due in self.store.fetch('SELECT attempts,next_at FROM uplv_verify_attempts'):
            self.assertEqual(count, 0)
            self.assertGreaterEqual(due, start+30)
        self.assertIsNone(self.pool.pool_verification_room())

    def test_third_inconclusive_inspection_pauses_without_new_battle(self):
        room = self.assign()
        for task, in self.store.fetch('SELECT id FROM uplv_tasks'):
            self.store.exec('INSERT INTO uplv_verify_attempts VALUES (?,?,?)', (task,3,0))
        self.pending_report(room)
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('stopped',)])
        self.assertIsNone(self.pool.pool_form_room())
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            self.assertEqual(json.loads(raw)['stage'], 'PAUSED_VERIFY_LIMIT')

    def test_unresolved_inspection_uses_backoff_not_immediate_reclaim(self):
        room = self.assign()
        for task, in self.store.fetch('SELECT id FROM uplv_tasks'):
            self.store.exec('INSERT INTO uplv_verify_attempts VALUES (?,?,?)', (task,1,0))
        start = time.time()
        self.pending_report(room)
        for count, due in self.store.fetch('SELECT attempts,next_at FROM uplv_verify_attempts'):
            self.assertEqual(count, 1)
            self.assertGreaterEqual(due, start+30)
        self.assertIsNone(self.pool.pool_verification_room())

    def test_verified_idle_account_still_enters_ready_and_clears_budget(self):
        room = self.assign()
        for task, in self.store.fetch('SELECT id FROM uplv_tasks'):
            self.store.exec('INSERT INTO uplv_verify_attempts VALUES (?,?,?)', (task,2,0))
        self.pool.report(dict(satellite_id='offline', room_id=room['id'], lease_token=room['lease_token'],
            versions=[0]*5, results={str(i): dict(status='pending', level_after=10,
                                                verified=True, idle=True) for i in range(5)}))
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('ready',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_verify_attempts')[0], 0)

    def test_existing_stopped_and_failed_accounts_are_not_inspection_candidates(self):
        self.store.exec("UPDATE uplv_tasks SET status='stopped'")
        self.assertIsNone(self.pool.pool_verification_room())
        self.assertIsNone(self.pool.pool_form_room())
        self.store.exec("UPDATE uplv_tasks SET status='failed'")
        self.assertIsNone(self.pool.pool_verification_room())
        self.assertIsNone(self.pool.pool_form_room())


if __name__ == '__main__':
    unittest.main()
