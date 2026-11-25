"""Uncertain TCP refusals must never consume a valid account as a failed login."""
import unittest
from unittest.mock import Mock, patch

import garena_api_test_chrome1 as api


def refused(command=0x101, code=1, **extra):
    return {'tcp': {'ok': False, 'credential_rejected': True,
                    'rejection_command': command, 'rejection_result': code, **extra}}


class LoginClassificationTests(unittest.TestCase):
    def run_account(self, results):
        stop = Mock()
        stop.wait.return_value = False
        gate = Mock()
        gate.wait.return_value = True
        with patch.object(api, 'run_api_tests', side_effect=results) as check:
            row = api.batch_check_one(api.BatchAccount(1, 'test-user', 'dummy-password'),
                                      None, 8, gate, stop)
        return row, check.call_count

    def test_generic_refusals_remain_uncheckable_after_four_attempts(self):
        for command in (0x100, 0x101):
            for code in ((1, 3, 105) if command == 0x100 else (1, 5)):
                with self.subTest(command=command, code=code):
                    row, count = self.run_account([refused(command, code)] * 4)
                    self.assertEqual(count, 4)
                    self.assertEqual(row['status'], 'CHƯA THỂ CHECK')
                    self.assertEqual(row['result_type'], 'Chưa thể check')

    def test_grant_error_is_final_without_retry(self):
        for evidence in (
            {'web_auth': {'kientuong': {'error': 'error_require_grant'}}},
            {'tcp_to_web_probe': {'account_to_kientuong_oauth':
                                 {'grant_error': 'error_require_grant'}}},
            {'tcp_to_web_probe': {'account_to_kientuong_oauth':
                                 {'player_api': {'body': {'error': 'error_require_grant'}}}}},
        ):
            for tcp_ok in (True, False):
                with self.subTest(evidence=evidence, tcp_ok=tcp_ok):
                    result = {'tcp': {'ok': tcp_ok}, 'apis': {'other': {'status': 429}},
                              **evidence}
                    row, count = self.run_account([result])
                    self.assertEqual(count, 1)
                    self.assertEqual(row['status'], 'OK')
                    self.assertEqual(row['result_type'], 'Lỗi CTNV')
                    self.assertEqual(row['player_status'], 'Lỗi CTNV')
                    self.assertNotEqual(row['level'].casefold(), 'ctnv')

    def test_valid_account_recovers_after_two_identical_refusals(self):
        success = {'tcp': {'ok': True, 'uid': '123'},
                   'apis': {'kientuong_player': {'ok': True, 'body': {'player': {'level': 12}}}}}
        for command in (0x100, 0x101):
            with self.subTest(command=command):
                row, count = self.run_account([refused(command), refused(command), success])
                self.assertEqual(count, 3)
                self.assertEqual(row['status'], 'OK')
                self.assertEqual(row['level'], '12')

    def test_prepare_rate_limit_and_success_are_not_invalid_login(self):
        for result in (refused(0x100, credential_invalid_confirmed=True),
                       refused(credential_invalid_confirmed=True, rate_limit_suspected=True),
                       refused(credential_invalid_confirmed=True, ok=True)):
            self.assertFalse(api.batch_login_rejected_permanently(result))

    def test_exception_breaks_confirmation_sequence(self):
        result = refused(code=3)
        row, count = self.run_account([result, TimeoutError('test timeout'), result, result])
        self.assertEqual(count, 4)
        self.assertEqual(row['status'], 'FAIL')
        self.assertEqual(row['login_rejection_confirmations'], '2')

    def test_login_code_three_is_confirmed_even_when_fast(self):
        result = refused(code=3, retryable_fast_rejection=True)
        row, count = self.run_account([result, result])
        self.assertEqual(count, 2)
        self.assertEqual(row['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
