"""Synthetic restoration checks. No live login, match, or deployment."""
import base64
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'uplv_runtime'))
sys.path.insert(0, str(HERE/'uplv_runtime/pve_backend'))


class RestoreTests(unittest.TestCase):
    def test_default_entry_and_docker_are_uplv(self):
        self.assertIn('ENV WORKER_MODE=uplv', (HERE/'Dockerfile.uplv').read_text())
        self.assertIn("os.environ.get('WORKER_MODE', 'uplv')", (HERE/'uplv_satellite.py').read_text(encoding='utf8'))
        self.assertIn('value: uplv', (HERE/'render_uplv.yaml').read_text())

    def test_all_login_resource_paths_match_candidate(self):
        from purepc.login_v2 import login_body
        from purepc.purepc_run import build_devreg_fresh
        from purepc.cs import unpack_lz4_payload
        versions = bytes.fromhex('030000870300008e')
        config = json.loads((HERE/'uplv_runtime/pve_runtime/vendor/protocol_config.json').read_bytes())
        self.assertEqual(login_body('a'*32, 'b'*32, 123)[:8], versions)
        self.assertEqual(base64.b64decode(config['login_body'])[:8], versions)
        self.assertEqual(base64.b64decode(config['reconnect_body'])[4:12], versions)
        packet, _ = build_devreg_fresh('synthetic', seq=7, live_handle=123)
        self.assertEqual(unpack_lz4_payload(packet[4:])[16:24], versions)
        self.assertIs(config['verified_runtime']['server_login_verified'], False)

    def test_server_rejection_is_not_recovered_as_new_login(self):
        from uplv_engine import Engine
        for error in ('server_error_csid_1190_code_91121',
                      'server_error_csid_1190_code_91117',
                      'V2 direct-token Garena OAuth 141',
                      'role_level_not_received_after_create'):
            with self.subTest(error=error):
                engine = Engine.__new__(Engine)
                engine._run_once = Mock(return_value={0: (False, 0, 0, error)})
                completed = Mock()
                result = engine.run({'accounts': [['synthetic', 'unused']],
                                     'levels': [0], 'targets': [12], 'verify_only': True},
                                    threading.Event(), Mock(), completed)
                self.assertEqual(engine._run_once.call_count, 1)
                self.assertTrue(result[0][3].startswith('terminal_'))
                completed.assert_called_once_with(0, result[0])

    def test_auth_rate_limit_stops_without_web_or_second_login(self):
        from uplv_engine import Engine
        engine = Engine.__new__(Engine)
        engine.login_lock = threading.Lock()
        engine.last_login = 0
        error = RuntimeError('private response must not be logged')
        error.code = 429
        login = Mock(side_effect=error)
        engine.runtime = (None, None, login, lambda user: {'device_id': 'unused'}, None, None)
        with patch('uplv_kientuong.PlayerSession', side_effect=AssertionError('no fallback')):
            rows = engine.run({'accounts': [['synthetic', 'unused']], 'levels': [0],
                               'targets': [12], 'screen_only': True},
                              threading.Event(), Mock(), Mock())
        login.assert_called_once()
        self.assertIn('code=429', rows[0][3])
        self.assertNotIn('private response', rows[0][3])

    def test_read_profile_never_creates_grants_or_plays_and_closes_socket(self):
        from uplv_profile_v2 import read_profile
        sock = Mock()
        session = dict(ok=True, stage='session', sock=sock, key1=b'x'*16, rd=Mock(),
                       seq=3, last_c1=1, level=8)
        run = Mock(return_value=session)
        bundle = SimpleNamespace(access_token='synthetic', open_id='a'*32)
        with patch('purepc.uplevel_stateful.read_frames', return_value=[{'csid': 1061, 'body': '00'}]):
            self.assertEqual(read_profile(run, bundle, 'synthetic', threading.Event()), (8, True))
        options = run.call_args.kwargs
        self.assertIs(options['create'], False)
        self.assertIs(options['verify_only'], True)
        self.assertIsNone(options['replay_1v1'])
        sock.close.assert_called_once()

    def test_read_profile_missing_evidence_is_not_level_zero(self):
        from uplv_profile_v2 import read_profile
        run = Mock(return_value=dict(ok=False, reject='initial_role_level_not_received'))
        with self.assertRaisesRegex(RuntimeError, 'initial_role_level_not_received'):
            read_profile(run, SimpleNamespace(access_token='synthetic', open_id='a'*32),
                         'synthetic', threading.Event())

    def test_server_rejection_during_profile_skips_web_fallback(self):
        from uplv_engine import Engine
        engine = Engine.__new__(Engine)
        engine.login_lock = threading.Lock()
        engine.last_login = 0
        login = Mock(return_value=SimpleNamespace(access_token='synthetic', open_id='a'*32))
        engine.runtime = (None, None, login, lambda user: {'device_id': 'unused'}, None, None)
        with patch('uplv_profile_v2.read_profile', side_effect=RuntimeError('server_error_csid_1190_code_91121')), \
                patch('uplv_kientuong.PlayerSession', side_effect=AssertionError('no fallback')):
            rows = engine.run({'accounts': [['synthetic', 'unused']], 'levels': [0],
                               'targets': [12], 'verify_only': True},
                              threading.Event(), Mock(), Mock())
        login.assert_called_once()
        self.assertTrue(rows[0][3].startswith('terminal_'))

    def test_oauth_141_grant_stays_on_same_session_without_third_oauth(self):
        import io
        from bridge.core._core_data import garena_tcp as tcp
        client = tcp.GarenaTcpClient()
        client.uid, client.socket, client.session_key = 123, Mock(), b'x'*16
        client.socket.gettimeout.return_value = 15.
        client._request_response = Mock(side_effect=[
            ({4: [439], 5: [141]}, b''), ({4: [439], 5: [141]}, b''),
            ({4: [442], 5: [0]}, tcp._field_string(1, 'synthetic-sso'))])
        response = io.BytesIO(b'{"access_token":"synthetic-token","open_id":"synthetic-open"}')
        response.status, response.headers = 200, {}
        response.getcode = lambda: 200
        client.http_grant_opener = Mock(return_value=response)
        result = client.oauth_token_login()
        self.assertEqual(result.response_data, 'synthetic-token')
        self.assertEqual([c.args[0] for c in client._request_response.call_args_list], [439, 439, 442])
        client.http_grant_opener.assert_called_once()

    def test_prepare_server_denial_never_repeats_creator_or_replaces_account(self):
        from uplv_engine import Engine
        engine = Engine.__new__(Engine)
        engine.state_dir = HERE/'backups/before_restore_uplv_20261126_101558/synthetic'
        engine.login_lock, engine.last_login = threading.Lock(), 0
        bundle = SimpleNamespace(access_token='synthetic', open_id='a'*32)
        run_cs = Mock(return_value=dict(ok=False, reject='server_error_csid_1190_code_91121'))
        login = Mock(return_value=bundle)
        def rooms(accounts, target, count, concurrency, stop, prepare, *args, **kwargs):
            return {0: prepare(0, *accounts[0])}
        engine.runtime = (rooms, run_cs, login, lambda user: {'device_id':'unused'},
                          Mock(side_effect=AssertionError('no novice retry')), lambda path: None)
        replace = Mock(side_effect=AssertionError('do not replace on server deny'))
        result = engine.run({'accounts': [['synthetic', 'unused']], 'target': 12, 'mode':'victory'},
                            threading.Event(), Mock(), Mock(), replacement=replace)
        run_cs.assert_called_once()
        login.assert_called_once()
        self.assertTrue(result[0][3].startswith('terminal_'))

    def test_match_denial_never_reconnects_or_recovers_old_match(self):
        from pve_runtime.uplv import run_five_batch
        sessions = []
        class Session:
            def __init__(self, *args, **kwargs):
                self.level, self.experience, self.character_uid = 5, 0, len(sessions)+1
                self.connect, self.close = Mock(), Mock()
                sessions.append(self)
            def check_stop(self): pass
            def authenticate_garena_session(self, *args): pass
        class Match:
            def __init__(self, *args, **kwargs):
                self.surrender = SimpleNamespace(seconds=375)
                self.outcomes = SimpleNamespace(mode='victory', seconds=190)
            def play(self, session):
                raise RuntimeError('server_error_csid_1190_code_91117')
        with patch('pve_runtime.uplv.load', return_value=SimpleNamespace(LeverSession=Session, FiveMatch=Match)), \
                patch('pve_runtime.tutorial.wait_lobby_or_rescue'), \
                patch('pve_runtime.uplv.recover_battle', side_effect=AssertionError('no recovery')):
            results = run_five_batch([(f'synthetic{i}', 'unused') for i in range(5)], 12, 5,
                threading.Event(), lambda *args: (True, 5, 5, ''),
                lambda *args: SimpleNamespace(access_token='synthetic', open_id='a'*32),
                Mock(), allow_regroup=True)
        self.assertTrue(all(row[3].startswith('terminal_') for row in results.values()))
        self.assertTrue(all(s.connect.call_count == 1 and s.close.called for s in sessions))

    def test_readonly_parser_rejects_login_code_without_role_fallback(self):
        from purepc.purepc_run import _pump_state
        state = dict(read_only_v2=True, received_csids=set(), csids=set(), level=None)
        reply = dict(csid=1003, body='000163f1', body_full='000163f1')
        with patch('purepc.uplevel_stateful.read_frames', return_value=[reply]), \
                patch('purepc.dr_role_decode.decode_login_role', side_effect=AssertionError('no decode on deny')):
            _pump_state(Mock(), Mock(), 1, state)
        self.assertEqual(state['reject'], 'server_error_csid_1003_code_91121')
        self.assertIsNone(state['level'])

    def test_prepare_publishes_bounded_oauth_fallback_before_cs_creation(self):
        from uplv_engine import Engine
        engine = Engine.__new__(Engine)
        engine.state_dir = HERE/'backups/synthetic-unused'
        engine.login_lock, engine.last_login = threading.Lock(), 0
        events = []
        def login(*args, **kwargs):
            for message in ('[oauth-v2] app_id=100054 action=fallback',
                            '[oauth-v2] app_id=100055 action=success next=msdk-vn'):
                kwargs['progress'](message)
            events.append('authenticated')
            return SimpleNamespace(access_token='synthetic', open_id='a'*32)
        def cs(*args, **kwargs):
            self.assertEqual(events[-1], 'authenticated')
            self.assertIs(kwargs['create'], True)
            return dict(ok=True, level_before=1, level_after=5)
        def rooms(accounts, target, count, concurrency, stop, prepare, *args, **kwargs):
            return {0: prepare(0, *accounts[0])}
        engine.runtime = (rooms, cs, login, lambda user: {'device_id': 'unused'}, None, lambda path: None)
        notify = Mock()
        rows = engine._run_once({'accounts': [['synthetic', 'unused']], 'target': 5, 'mode': 'victory'},
                                threading.Event(), notify, Mock())
        self.assertTrue(rows[0][0])
        messages = [call.args[1] for call in notify.call_args_list]
        self.assertTrue(any('app_id=100054' in message for message in messages))
        self.assertTrue(any('app_id=100055' in message for message in messages))


if __name__ == '__main__':
    unittest.main()
