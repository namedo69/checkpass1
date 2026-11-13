import unittest
from unittest.mock import Mock, patch
import garena_api_test_chrome1 as api

class GrantErrorTests(unittest.TestCase):
    def run_account(self, results):
        stop = Mock()
        stop.wait.return_value = False
        gate = Mock()
        gate.wait.return_value = True
        with patch.object(api, 'run_api_tests', side_effect=results) as check:
            row = api.batch_check_one(api.BatchAccount(1, 'test-user', 'dummy-password'),
                                      None, 8, gate, stop)
        return row, check.call_count

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
                    self.assertEqual(row['player_status'], 'Lỗi CTNV (error_require_grant)')
                    self.assertNotEqual(row['level'].casefold(), 'ctnv')

