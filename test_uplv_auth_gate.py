"""Offline worker-local auth admission; synthetic results are not level proof."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
import sys
import json
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / 'uplv_runtime'))
sys.path.insert(0, str(ROOT / 'uplv_runtime/pve_backend'))
from uplv_engine import AuthGate, Engine


class ClockStop:
    def __init__(self):
        self.now = 100.0
        self.stopped = False
        self.on_wait = None

    def is_set(self):
        return self.stopped

    def wait(self, delay):
        self.now += delay
        if self.on_wait:
            self.on_wait()
        return self.stopped


class AuthGateTests(unittest.TestCase):
    def test_capped_policy_and_server_wait_take_maximum(self):
        gate, clock = AuthGate(), ClockStop()
        throttle = SimpleNamespace(reason='rate_limited', retry_after=0)
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now)), patch('uplv_auth_policy.random.uniform', return_value=0):
            for delay in (10, 20, 40, 80):
                self.assertEqual(gate.rejected(throttle), (True, delay, False))
                self.assertEqual(gate.retry_until, clock.now + delay)
                clock.now += delay
            throttle.retry_after = 1200
            self.assertEqual(gate.rejected(throttle), (True, 1200, True))

    def test_no_burst_after_shared_deadline_and_start_spacing(self):
        gate, clock = AuthGate(), ClockStop()
        gate.retry_until = 117
        starts = []
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now)):
            for _ in range(5):
                gate.enter(clock, Mock())
                starts.append(clock.now)
                gate.last_start = clock.now
                gate.lock.release()
        self.assertGreaterEqual(starts[0], 117)
        self.assertTrue(all(b - a >= 2.5 - 1e-9 for a, b in zip(starts, starts[1:])))

    def test_stop_during_cooldown_releases_gate_without_admission(self):
        gate, clock = AuthGate(), ClockStop()
        gate.retry_until = 200
        clock.on_wait = lambda: setattr(clock, 'stopped', True)
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now)):
            with self.assertRaisesRegex(RuntimeError, '^Stopped$'):
                gate.enter(clock, Mock())
        self.assertTrue(gate.lock.acquire(blocking=False))
        gate.lock.release()
        self.assertEqual(gate.last_start, 0)

    def test_stop_while_queued_does_not_release_another_owner(self):
        gate, stop, messages = AuthGate(), threading.Event(), []
        gate.lock.acquire()
        def progress(message):
            messages.append(message)
            stop.set()
        with self.assertRaisesRegex(RuntimeError, '^Stopped$'):
            gate.enter(stop, progress)
        self.assertFalse(gate.lock.acquire(blocking=False))
        gate.lock.release()
        self.assertEqual(len(messages), 1)

    def test_denials_are_not_rate_limits_and_invalid_wait_is_ignored(self):
        for reason in ('web_http_rejected', 'captcha', 'otp', 'require_grant'):
            for delay in (float('nan'), float('inf'), -1, '17', None, True):
                with self.subTest(reason=reason, delay=delay):
                    gate = AuthGate()
                    self.assertEqual(gate.rejected(SimpleNamespace(reason=reason, http_status=403,
                                                                  code=3, retry_after=delay)),
                                     (False, 0, False))
                    self.assertEqual(gate.retry_until, 0)

    def test_503_explicit_wait_is_not_mislabeled_rate_limit(self):
        gate = AuthGate()
        self.assertEqual(gate.rejected(SimpleNamespace(http_status=503, retry_after=12)),
                         (False, 12, True))
        self.assertEqual(gate.streak, 0)


class AuthEngineTests(unittest.TestCase):
    def setUp(self):
        for target in ('socket.create_connection', 'socket.socket.connect',
                       'urllib.request.OpenerDirector.open', 'requests.sessions.Session.request'):
            guard = patch(target, side_effect=AssertionError('offline test forbids network'))
            guard.start()
            self.addCleanup(guard.stop)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.stop, self.progress = threading.Event(), Mock()
        self.bundle = SimpleNamespace(access_token='synthetic', open_id='a' * 32)
        self.login = Mock(return_value=self.bundle)
        self.run_cs = Mock(return_value=dict(ok=True, level_before=5, level_after=5))
        self.engine = Engine.__new__(Engine)
        self.engine.state_dir = Path(self.folder.name)
        self.engine.login_lock = threading.Lock()
        self.engine.auth_gate = AuthGate()
        self.rooms = Mock()
        self.engine.runtime = (self.rooms, self.run_cs, self.login,
                               lambda _: dict(device_id='synthetic'), None, Mock())
        self.room = dict(accounts=[('fixture' + str(i), 'unused') for i in range(5)],
                         target=5, mode='synthetic')

    def run_auth(self, callback):
        def rooms(accounts, target, count, concurrency, stop, prepare, authenticate, progress, **kwargs):
            return callback(prepare, authenticate)
        self.rooms.side_effect = rooms
        return self.engine.run(self.room, self.stop, self.progress, Mock())

    def test_complete_flows_serialized_and_stop_event_forwarded(self):
        lock, active, peak, starts = threading.Lock(), 0, 0, []
        def login(*args, **kwargs):
            nonlocal active, peak
            self.assertIs(kwargs['stop_event'], self.stop)
            with lock:
                active += 1
                peak = max(peak, active)
                starts.append(time.monotonic())
            time.sleep(0.03)
            with lock:
                active -= 1
            return self.bundle
        self.login.side_effect = login
        def batch(prepare, authenticate):
            with ThreadPoolExecutor(max_workers=5) as executor:
                return list(executor.map(lambda account: authenticate(*account), self.room['accounts']))
        self.assertEqual(len(self.run_auth(batch)), 5)
        self.assertEqual(peak, 1)
        self.assertTrue(all(b - a >= 2.49 for a, b in zip(starts, starts[1:])))

    def test_same_lease_single_flight_but_new_lease_authenticates_fresh(self):
        def batch(prepare, authenticate):
            with ThreadPoolExecutor(max_workers=5) as executor:
                rows = list(executor.map(lambda _: authenticate('fixture0', 'unused'), range(5)))
            self.assertTrue(all(row is self.bundle for row in rows))
            return rows
        self.run_auth(batch)
        self.assertEqual(self.login.call_count, 1)
        self.run_auth(batch)
        self.assertEqual(self.login.call_count, 2)
        self.assertNotIn('_auth_context', self.room)

    def test_throttle_classification_no_same_account_retry_and_redaction(self):
        for attrs in (dict(reason='rate_limited', code=3), dict(http_status=429), dict(code=429)):
            with self.subTest(attrs=attrs):
                exc = RuntimeError('secret-server-body')
                for key, value in attrs.items():
                    setattr(exc, key, value)
                self.login.side_effect = exc
                self.login.reset_mock()
                self.engine.auth_gate = AuthGate()
                row = self.run_auth(lambda prepare, auth: prepare(0, 'fixture0', 'unused'))
                self.assertTrue(row[3].startswith('terminal_rate_limit:'))
                self.assertNotIn('secret-server-body', row[3])
                self.login.assert_called_once()
                self.assertEqual(self.engine.auth_gate.streak, 1)
                self.assertGreater(self.engine.auth_gate.retry_until, time.monotonic())
                self.assertFalse(self.engine.auth_gate.lock.locked())

    def test_other_denials_no_retry_no_ban_label(self):
        for reason in ('web_http_rejected', 'captcha', 'otp'):
            with self.subTest(reason=reason):
                exc = RuntimeError('untrusted-body')
                exc.reason, exc.http_status = reason, 403
                self.login.side_effect = exc
                self.login.reset_mock()
                self.engine.auth_gate = AuthGate()
                row = self.run_auth(lambda prepare, auth: prepare(0, 'fixture0', 'unused'))
                self.assertTrue(row[3].startswith('terminal_login:'))
                self.assertNotIn('banned', row[3])
                self.login.assert_called_once()
                self.assertEqual(self.engine.auth_gate.streak, 0)

    def test_stop_after_auth_prevents_game_and_discards_cache(self):
        def login(*args, **kwargs):
            self.stop.set()
            return self.bundle
        self.login.side_effect = login
        row = self.run_auth(lambda prepare, auth: prepare(0, 'fixture0', 'unused'))
        self.assertFalse(row[0])
        self.run_cs.assert_not_called()
        self.assertNotIn('_auth_context', self.room)
        self.assertFalse(self.engine.auth_gate.lock.locked())

    def test_stop_prevents_even_cached_auth_return(self):
        def batch(prepare, authenticate):
            authenticate('fixture0', 'unused')
            self.stop.set()
            with self.assertRaisesRegex(RuntimeError, '^Stopped$'):
                authenticate('fixture0', 'unused')
            return {}
        self.run_auth(batch)
        self.login.assert_called_once()

    def test_success_resets_streak_not_explicit_future_deadline(self):
        self.engine.auth_gate.streak = 3
        self.run_auth(lambda prepare, auth: auth('fixture0', 'unused'))
        self.assertEqual(self.engine.auth_gate.streak, 0)

    def test_real_runtime_signature_accepts_engine_stop_keyword(self):
        from token_login import login_and_exchange
        import inspect
        inspect.signature(login_and_exchange).bind('fixture0', 'unused', 'synthetic',
                                                  timeout=20, with_sso_key=False,
                                                  progress=Mock(), stop_event=self.stop)


class AuthSatelliteTests(unittest.TestCase):
    def test_heartbeat_retains_lease_during_auth_wait_and_unread_level_is_unknown(self):
        from uplv_satellite import Satellite
        renewed = threading.Event()
        client = Mock()
        def post(action, payload):
            if action == 'heartbeat':
                renewed.set()
            return dict(lease_until=time.time() + 180)
        client.post.side_effect = post
        engine = Mock()
        def run(room, stop, progress, completed, **kwargs):
            progress(0, '[AUTH] phase=login level=unconfirmed')
            progress(0, '[AUTH_WAIT] worker_local remaining=10s')
            self.assertTrue(renewed.wait(2), 'heartbeat must be independent of auth gate')
            self.assertFalse(stop.is_set())
            return {0: (False, 0, 0, 'terminal_rate_limit: HTTP 429')}
        engine.run.side_effect = run
        room = dict(id='synthetic-auth-wait', lease_token='synthetic', accounts=[('fixture', 'unused')],
                    levels=[0], targets=[5], target=5, mode='synthetic', lease_until=time.time() + 180)
        with tempfile.TemporaryDirectory() as directory, patch('builtins.print') as printed:
            worker = Satellite(client, engine, directory, 'offline')
            worker.run_room(room)
            report = json.loads(next(Path(directory).glob('pending_report_*.json')).read_text())
        self.assertFalse(report['results']['0']['level_confirmed'])
        self.assertEqual(report['results']['0']['status'], 'pending')
        self.assertEqual(report['results']['0']['failure_kind'], 'rate_limit')
        self.assertTrue(any('Lv? -> Lv?' in str(call) for call in printed.call_args_list))
        client.checkpass_claim.assert_not_called()


if __name__ == '__main__':
    unittest.main()
