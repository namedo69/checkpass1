"""Web denial retry history is account-owned; explicit server waits stay shared."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_uplv_auth_gate import AuthEngineTests, ClockStop
from uplv_engine import AuthGate
from uplv_auth_policy import auth_delay


def denial(**kwargs):
    return SimpleNamespace(http_status=403, stage='tcp-token-v2',
                           diagnostics={'phase': 'web-prelogin'}, **kwargs)


class ScopedWebBackoffTests(unittest.TestCase):
    def test_web_policy_has_no_attempt_escalation_or_jitter(self):
        with patch('uplv_auth_policy.random.uniform', side_effect=AssertionError('no web jitter')):
            for attempt in (0, 1, 2, 5, 16, 1000000):
                self.assertEqual(auth_delay('web_denied', attempt), 10)

    def test_short_server_wait_cannot_shorten_local_ten_seconds(self):
        gate, clock = AuthGate(), ClockStop()
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda:clock.now)):
            self.assertEqual(gate.rejected(denial(retry_after=3), 12), (False, 10, True))
            self.assertEqual(gate.retry_until, 110)

    def test_master_fallback_uses_same_fixed_policy(self):
        from uplv_account_pool import AccountPool
        detail = dict(auth_attempt=99, auth_retry_until=0)
        AccountPool.plan_auth_wait(detail, 1000, 'web_denied')
        self.assertEqual(detail['auth_retry_until'], 1010)
        self.assertEqual(detail['auth_attempt'], 100)

    def test_high_account_attempt_keeps_fixed_ten_seconds(self):
        gate, clock = AuthGate(), ClockStop()
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now)), patch('uplv_auth_policy.random.uniform', return_value=0):
            self.assertEqual(gate.rejected(denial(), prior_attempt=12), (False, 10, False))
            self.assertEqual(gate.retry_until, clock.now + 10)
            messages = []
            gate.enter(clock, messages.append)
            self.assertEqual(clock.now, 110)
            gate.lock.release()
        self.assertTrue(any('reason=worker_backoff' in m for m in messages))

    def test_many_distinct_denials_do_not_inherit_worker_attempts(self):
        gate, clock = AuthGate(), ClockStop()
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now)), patch('uplv_auth_policy.random.uniform', return_value=0):
            for _ in range(20):
                self.assertEqual(gate.rejected(denial()), (False, 10, False))
                self.assertEqual(gate.retry_until, clock.now + 10)
                clock.now += 10
        self.assertEqual(gate.streak, 0)

    def test_server_retry_after_stays_shared_even_when_longer_than_policy(self):
        gate, clock = AuthGate(), ClockStop()
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now)), patch('uplv_auth_policy.random.uniform', return_value=0):
            self.assertEqual(gate.rejected(denial(retry_after=1800), 12), (False, 1800, True))
            self.assertEqual(gate.retry_until, 1900)
            clock.now += 1
            gate.rejected(denial())
            self.assertEqual(gate.retry_until, 1900, 'new denial must not shorten server wait')

    def test_429_exponential_worker_backoff_is_unchanged(self):
        gate, clock = AuthGate(), ClockStop()
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now)), patch('uplv_auth_policy.random.uniform', return_value=0):
            self.assertEqual(gate.rejected(SimpleNamespace(http_status=429), 12), (True, 300, False))
            self.assertEqual(gate.retry_until, 400)

    def test_account_long_deadline_is_not_shortened_by_short_worker_wait(self):
        gate, clock = AuthGate(), ClockStop()
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now, time=lambda:1000)), patch('uplv_auth_policy.random.uniform', return_value=0):
            gate.rejected(denial(), 12)
            gate.enter(clock, Mock(), not_before=1900)
            self.assertEqual(clock.now, 1000)
            gate.lock.release()


class ScopedWebEngineTests(AuthEngineTests):
    def test_engine_reports_distinct_account_and_worker_wait_without_retry(self):
        exc = RuntimeError('untrusted-body')
        exc.http_status, exc.stage, exc.diagnostics = 403, 'tcp-token-v2', {'phase':'web-prelogin'}
        self.login.side_effect = exc
        self.room['auth_waits'] = [dict(auth_attempt=8, auth_retry_until=0)] * 5
        with patch('uplv_auth_policy.random.uniform', return_value=0):
            row = self.run_auth(lambda prepare, auth: prepare(0, 'fixture0', 'unused'))
        self.assertTrue(row[3].startswith('terminal_login:'))
        self.login.assert_called_once()
        messages = [call.args[1] for call in self.progress.call_args_list]
        backoff = next(m for m in messages if '[AUTH_BACKOFF]' in m)
        self.assertIn('worker_local=10s', backoff)
        self.assertIn('account_local=10s', backoff)
        self.assertIn('attempt=9', backoff)
        self.assertNotIn('untrusted-body', ' '.join(messages))


if __name__ == '__main__':
    unittest.main()
