"""Evidence-based outcomes and durable retries using synthetic accounts only."""
import unittest

from uplv_failure_policy import terminal_account_failure
import test_uplv_session_wait as fixtures


class EvidenceTests(unittest.TestCase):
    def test_current_explicit_denial_only(self):
        for code, expected in ((91126, 'restricted'), (91123, ''),
                               (91117, ''), (91121, ''), (99999, '')):
            self.assertEqual(terminal_account_failure(dict(
                final_error=f'server_error_csid_1190_code_{code}')), expected)
        for error in ('SsoLoginError HTTP=200', 'SsoLoginError code=3',
                      'initial_role_level_not_received', 'role_level_not_received_after_create',
                      'Profile state trailer invalid', ''):
            self.assertEqual(terminal_account_failure(dict(final_error=error,
                failure_kind='restricted', root_cause='server_error_csid_1190_code_91126')), '')


class RetryTests(unittest.TestCase):
    setUp = fixtures.SessionWaitTests.setUp
    claim = fixtures.SessionWaitTests.claim
    report = fixtures.SessionWaitTests.report
    states = fixtures.SessionWaitTests.states
    due_claim = fixtures.SessionWaitTests.due_claim
    def test_name_rejection_never_fails_or_stops_account(self):
        self.report(kind='create_character', status='failed',
                    final_error='server_error_csid_1009_code_91123')
        self.assertEqual(self.states(), [('retry_wait',)])
        self.now += 29
        self.assertIsNone(self.claim())
        self.now += 1
        self.assertFalse(self.claim()['verify_only'])

    def test_auth_retry_survives_restart_and_waits_exactly_30_seconds(self):
        self.report(kind='restricted', status='failed', final_error='SsoLoginError HTTP=200')
        self.assertEqual(self.states(), [('retry_wait',)])
        self.pool = type(self.pool)(self.store)
        self.now += 29
        self.assertIsNone(self.claim())
        self.now += 1
        self.assertFalse(self.claim()['verify_only'])

    def test_auth_error_during_session_check_never_strands_account(self):
        self.report()
        room = self.due_claim()
        self.report(room, kind='login', final_error='SsoLoginError HTTP=200')
        self.assertEqual(self.states(), [('retry_wait',)])
        self.now += 30
        self.assertTrue(self.claim()['verify_only'])

    def test_unknown_server_denial_keeps_read_only_retrying(self):
        room = self.room
        for _ in range(10):
            self.report(room, kind='server_error', status='failed',
                        final_error='server_error_csid_1190_code_99999')
            self.assertEqual(self.states(), [('retry_wait',)])
            self.assertIsNone(self.claim())
            self.now += 30
            room = self.claim()
            self.assertTrue(room['verify_only'])

    def test_explicit_ban_overrides_mislabeled_session_conflict(self):
        self.report(final_error='server_error_csid_1190_code_91126')
        self.assertEqual(self.states(), [('failed',)])

    def test_operator_stop_during_generic_retry_is_final(self):
        self.report(kind='login', final_error='SsoLoginError HTTP=200')
        self.pool.control(dict(action='stop_job', job_id=self.job))
        self.now += 30
        self.assertIsNone(self.claim())
        self.assertEqual(self.states(), [('stopped',)])
