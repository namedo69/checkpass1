"""Offline game-profile framing/recovery; no real account or network."""
import json
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent/'uplv_runtime'))
sys.path.insert(0, str(Path(__file__).parent/'uplv_runtime/pve_backend'))
import test_uplv_session_wait as session_wait
from uplv_profile_v2 import read_profile, reply_packets
from uplv_satellite import Satellite


class NoNetwork(unittest.TestCase):
    def setUp(self):
        for target in ('socket.create_connection', 'socket.socket.connect', 'urllib.request.urlopen'):
            guard = patch(target, side_effect=AssertionError('network forbidden'))
            guard.start()
            self.addCleanup(guard.stop)


class ProfileFramingTests(NoNetwork):
    def frame(self, state=b'\0', csid=1061, padding=b'\x83\x17\x92\x00'):
        plain = struct.pack('>IIII', csid, 5510, 11, 3) + state
        padding += b'tsf4g' + bytes([len(padding)+6])
        return {'dec_body': (plain+padding).hex()}

    def read(self, frames, level=3):
        sock = Mock()
        run = Mock(return_value=dict(ok=True, stage='session', sock=sock,
                   key1=b'x'*16, rd=Mock(), seq=3, last_c1=1, level=level))
        with patch('purepc.uplevel_stateful.read_frames', return_value=frames):
            result = read_profile(run, SimpleNamespace(access_token='unused', open_id='a'*32),
                                  'synthetic', threading.Event())
        sock.close.assert_called_once()
        sock.sendall.assert_called_once()
        self.assertFalse(run.call_args.kwargs['create'])
        self.assertTrue(run.call_args.kwargs['verify_only'])
        self.assertIsNone(run.call_args.kwargs['replay_1v1'])
        return result

    def test_padded_idle_decodes_without_changing_capture_parser(self):
        from purepc.cs import parse_cspkgs
        frame = self.frame()
        generic = parse_cspkgs(bytes.fromhex(frame['dec_body']))[0]
        self.assertNotEqual(generic['body_full'], b'\0')
        self.assertEqual(self.read([frame, dict(csid=1061, body_full=generic['body_full'].hex())]), (3, True))

    def test_busy_is_never_idle(self):
        self.assertEqual(self.read([self.frame(b'\1')]), (3, False))

    def test_unknown_payload_is_not_idle_even_if_first_byte_zero(self):
        clock = iter([0, 0, 0, 0, 9])
        with patch('uplv_profile_v2.time.monotonic', side_effect=lambda: next(clock, 9)):
            self.assertEqual(self.read([self.frame(b'\0\x02')]), (3, False))

    def test_malformed_trailer_never_guesses_payload(self):
        for raw in ('00', self.frame()['dec_body'][:-2]+'ff'):
            with self.assertRaises(ValueError):
                list(reply_packets([dict(dec_body=raw), dict(csid=1061, body='00')]))

    def test_denial_after_idle_wins(self):
        with self.assertRaisesRegex(RuntimeError, '91117'):
            self.read([self.frame(), self.frame(struct.pack('>I', 91117), csid=1190)])

    def test_busy_wins_over_idle_in_same_batch(self):
        self.assertEqual(self.read([self.frame(), self.frame(b'\1')]), (3, False))

    def test_closed_transport_never_confirms_idle(self):
        with self.assertRaises(ConnectionError):
            self.read([self.frame(), {'closed': True}])

    def test_stop_never_opens_socket(self):
        stop = threading.Event(); stop.set()
        run = Mock()
        with self.assertRaisesRegex(RuntimeError, 'Stopped'):
            read_profile(run, Mock(), 'synthetic', stop)
        run.assert_not_called()

    def test_silence_times_out_without_idle_or_another_probe(self):
        clock = iter([0, 0, 0, 0, 9])
        with patch('uplv_profile_v2.time.monotonic', side_effect=lambda: next(clock, 9)):
            self.assertEqual(self.read([]), (3, False))

    def test_stop_during_read_closes_socket_and_never_confirms_idle(self):
        stop = threading.Event()
        sock = Mock()
        run = Mock(return_value=dict(ok=True, stage='session', sock=sock,
                   key1=b'x'*16, rd=Mock(), seq=3, last_c1=1, level=3))
        def receive(*args, **kwargs):
            stop.set()
            return [self.frame()]
        with patch('purepc.uplevel_stateful.read_frames', side_effect=receive):
            with self.assertRaisesRegex(RuntimeError, 'Stopped'):
                read_profile(run, SimpleNamespace(access_token='unused', open_id='a'*32),
                             'synthetic', stop)
        sock.close.assert_called_once()
        sock.sendall.assert_called_once()


class FreshDiagnosticTests(NoNetwork):
    claim = session_wait.SessionWaitTests.claim

    def setUp(self):
        super().setUp()
        session_wait.SessionWaitTests.setUp(self)

    def test_fresh_read_clears_current_denial_preserves_history(self):
        session_wait.SessionWaitTests.report(self)
        self.now = self.store.fetchone('SELECT max(next_at) FROM uplv_session_wait')[0]
        room = self.claim()
        session_wait.SessionWaitTests.report(self, room, kind='')
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            detail = json.loads(raw)
            self.assertEqual(detail['final_error'], '')
            self.assertEqual(detail['last_check']['failure_kind'], '')
            self.assertIn('91117', detail['previous_error'])

    def test_padded_idle_lv3_returns_to_preparation_not_another_inspection(self):
        from uplv_engine import Engine
        session_wait.SessionWaitTests.report(self)
        self.now = self.store.fetchone('SELECT max(next_at) FROM uplv_session_wait')[0]
        self.store.exec('UPDATE uplv_tasks SET level=3')
        room = self.claim()
        engine = Engine.__new__(Engine)
        engine.login_lock, engine.last_login = threading.Lock(), 0
        bundle = SimpleNamespace(access_token='unused', open_id='a'*32)
        run_cs = Mock(side_effect=lambda *a, **kw: dict(ok=True, stage='session', sock=Mock(),
                       key1=b'x'*16, rd=Mock(), seq=3, last_c1=1, level=3))
        engine.runtime = (Mock(), run_cs, Mock(return_value=bundle), lambda _: dict(device_id='unused'), None, None)
        with tempfile.TemporaryDirectory() as directory:
            client = Mock(); client.post.return_value = dict(lease_until=self.now+180)
            worker = Satellite(client, engine, directory, 'offline')
            with patch('purepc.uplevel_stateful.read_frames', return_value=[ProfileFramingTests.frame(self)]):
                worker.run_room(room)
            report = json.loads(next(Path(directory).glob('pending_report_*.json')).read_text())
        self.pool.report(report)
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('waiting',)])
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_session_wait')[0], 0)
        next_room = self.claim()
        self.assertFalse(next_room['verify_only'])
        self.assertEqual(next_room['levels'], [3]*5)
        self.assertEqual(run_cs.call_count, 5)
        self.assertTrue(all(c.kwargs['verify_only'] and not c.kwargs['create'] for c in run_cs.call_args_list))
        engine.runtime[0].assert_not_called()


if __name__ == '__main__':
    unittest.main()
