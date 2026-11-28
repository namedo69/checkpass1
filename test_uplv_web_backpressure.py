"""Offline cross-worker wait propagation and server-denial regressions."""
import json
from pathlib import Path
import tempfile
import time
import uuid
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_uplv_rate_limit as rate_tests
import test_uplv_web_session as web_tests
import test_uplv_auth_gate as gate_tests
from test_uplv_auth_gate import AuthGate, ClockStop
from bridge.core._core_data.garena_tcp import GarenaError
from bridge.core._core_data import garena_web_session as web
from uplv_auth_policy import auth_delay, clean_auth_wait


class TransferredWaitTests(rate_tests.RateLimitTests):
    # Inherit existing STOP/ownership/master-admission invariants too.
    def test_report_then_other_worker_claim_preserves_deadline(self):
        deadline = self.now + 123
        body = self.body()
        body['progress'] = {str(i): dict(stage='AUTH_BACKOFF', auth_retry_until=deadline,
                                        auth_attempt=4) for i in range(5)}
        self.pool.heartbeat(body)
        self.pool.report(body)
        room = self.claim('other-worker')
        self.assertEqual(room['auth_waits'], [dict(auth_retry_until=deadline, auth_attempt=4)] * 5)
        self.assertEqual(self.store.fetchone('SELECT count(*) FROM uplv_auth_cooldown'), (0,))

    def test_old_worker_report_generates_wait_without_blocking_dispatch(self):
        self.report()
        room = self.claim('new-worker')
        self.assertIsNotNone(room)
        self.assertTrue(all(s['auth_retry_until'] > self.now for s in room['auth_waits']))
        self.assertTrue(all(s['auth_attempt'] == 1 for s in room['auth_waits']))

    def test_final_report_carries_deadline_without_intermediate_heartbeat(self):
        body = self.body()
        for result in body['results'].values():
            result.update(auth_retry_until=self.now+999, auth_attempt=7)
        self.pool.report(body)
        room = self.claim('different')
        self.assertTrue(all(s == dict(auth_retry_until=self.now+999, auth_attempt=7) for s in room['auth_waits']))

    def test_success_clears_prior_wait_in_saved_details(self):
        self.report()
        room = self.claim()
        body = self.body(room, kind='')
        body['progress'] = {str(i): dict(stage='AUTH_OK', auth_retry_until=0, auth_attempt=0) for i in range(5)}
        self.pool.heartbeat(body)
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            self.assertEqual(json.loads(raw)['auth_attempt'], 0)

    def test_replacement_receives_its_own_wait(self):
        job = self.pool.pool_create({'accounts': 'replacement_fixture|unused'})['job_id']
        task = self.store.fetchone('SELECT id FROM uplv_tasks WHERE job_id=?', (job,))[0]
        state = dict(auth_retry_until=self.now+432, auth_attempt=6)
        self.store.exec('INSERT INTO uplv_task_details VALUES (?,?,?)', (task, self.now, json.dumps(state)))
        reply = self.pool.replace(dict(satellite_id='offline', room_id=self.room['id'],
            lease_token=self.room['lease_token'], request_id=uuid.uuid4().hex,
            slot=0, generation=0, phase='preparation',
            result=dict(status='failed', level_after=0, final_error='server_error_csid_1_code_91126')))
        self.assertEqual(reply['account'][0], 'replacement_fixture')
        self.assertEqual(reply['auth_wait'], state)


class WorkerWaitTests(unittest.TestCase):
    def test_transferred_wait_enforced_monotonically(self):
        gate, clock, messages = AuthGate(), ClockStop(), []
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now, time=lambda: 1000)):
            gate.enter(clock, messages.append, not_before=1040)
        self.assertGreaterEqual(clock.now, 140)
        gate.lock.release()
        self.assertTrue(messages)

    def test_stop_during_transferred_wait(self):
        gate, clock = AuthGate(), ClockStop()
        clock.on_wait = lambda: setattr(clock, 'stopped', True)
        with patch('uplv_engine.time', SimpleNamespace(monotonic=lambda: clock.now, time=lambda: 1000)):
            with self.assertRaisesRegex(RuntimeError, '^Stopped$'):
                gate.enter(clock, Mock(), not_before=2000)
        self.assertFalse(gate.lock.locked())

    def test_policy_jitter_caps_and_finite_metadata(self):
        for kind, cap in [('rate_limit', 300), ('web_denied', 900)]:
            for attempt in range(1, 30):
                self.assertLessEqual(auth_delay(kind, attempt), cap * 1.1)
        for value in (float('nan'), float('inf'), '123', True, -1, 10**10000):
            self.assertEqual(clean_auth_wait(dict(auth_retry_until=value))['auth_retry_until'], 0)

    def test_web403_has_backoff_but_is_not429(self):
        exc = SimpleNamespace(http_status=403, stage='tcp-token-v2', diagnostics={'phase':'web-prelogin'})
        gate = AuthGate()
        with patch('uplv_auth_policy.random.uniform', return_value=0):
            self.assertEqual(gate.rejected(exc, prior_attempt=2), (False, 10, False))
        self.assertEqual(gate.streak, 0)

    def test_long_server_wait_is_not_capped(self):
        gate = AuthGate()
        exc = SimpleNamespace(http_status=429, retry_after=86400)
        self.assertEqual(gate.rejected(exc), (True, 86400, True))


class EngineWaitTests(gate_tests.AuthEngineTests):
    def test_replaced_account_uses_current_wait_not_previous_slot_wait(self):
        original = dict(auth_retry_until=time.time()+1000, auth_attempt=8)
        self.room['auth_waits'] = [original] * 5
        def batch(prepare, authenticate):
            self.room['accounts'][0] = ('replacement', 'unused')
            self.room['auth_waits'] = [dict(auth_retry_until=0, auth_attempt=0)] * 5
            return authenticate('replacement', 'unused')
        self.assertIs(self.run_auth(batch), self.bundle)
        self.login.assert_called_once()


class SatelliteMetadataTests(unittest.TestCase):
    def test_final_report_preserves_wait_on_interruption_without_completed_callback(self):
        from uplv_satellite import Satellite
        for emit in (False, True):
            with self.subTest(emit=emit), tempfile.TemporaryDirectory() as directory, patch('builtins.print'):
                deadline = time.time() + 777
                state = dict(auth_retry_until=deadline, auth_attempt=5)
                client = Mock()
                client.post.return_value = dict(lease_until=time.time()+180)
                engine = Mock()
                def run(room, stop, progress, completed, **kwargs):
                    if emit:
                        progress(0, f'[AUTH_BACKOFF] retry_at={deadline} attempt=5')
                    raise RuntimeError('synthetic interruption')
                engine.run.side_effect = run
                room = dict(id='synthetic', lease_token='unused', accounts=[('fixture', 'unused')],
                            target=5, mode='synthetic', lease_until=time.time()+180,
                            auth_waits=[{} if emit else state])
                Satellite(client, engine, directory, 'offline').run_room(room)
                report = json.loads(next(Path(directory).glob('pending_report_*.json')).read_text())
                self.assertEqual(report['results']['0']['auth_retry_until'], deadline)
                self.assertEqual(report['results']['0']['auth_attempt'], 5)

    def test_success_reset_survives_final_report_without_heartbeat(self):
        from uplv_satellite import Satellite
        with tempfile.TemporaryDirectory() as directory, patch('builtins.print'):
            client, engine = Mock(), Mock()
            client.post.return_value = dict(lease_until=time.time()+180)
            def run(room, stop, progress, completed, **kwargs):
                progress(0, '[AUTH_OK] synthetic token only')
                return {}
            engine.run.side_effect = run
            room = dict(id='synthetic', lease_token='unused', accounts=[('fixture', 'unused')],
                        target=5, mode='synthetic', lease_until=time.time()+180,
                        auth_waits=[dict(auth_retry_until=time.time()+777, auth_attempt=5)])
            Satellite(client, engine, directory, 'offline').run_room(room)
            report = json.loads(next(Path(directory).glob('pending_report_*.json')).read_text())
            self.assertEqual(report['results']['0']['auth_retry_until'], 0)
            self.assertEqual(report['results']['0']['auth_attempt'], 0)


class WebDenialTests(web_tests.WebSessionTests):
    def test_html403_remains_http_denial_and_preserves_retry_after(self):
        session, replies = self.session([{}])
        replies[0].status_code = 403
        replies[0].headers = {'Retry-After':'77'}
        replies[0].raw.read.return_value = b'<html>Forbidden</html>'
        with self.assertRaises(GarenaError) as caught:
            web.web_login_grant('fixture', 'unused', session_factory=lambda:session)
        self.assertEqual(caught.exception.reason, 'web_http_rejected')
        self.assertEqual(caught.exception.retry_after, 77)
        replies[0].raw.read.assert_not_called()
        session.request.assert_called_once()
        session.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
