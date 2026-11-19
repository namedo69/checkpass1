"""Account completion must refill a slot before its sibling chunk completes."""
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import garena_api_test_chrome1 as api
from satellite_account_pool import AccountPool


class AccountPoolTests(unittest.TestCase):
    def test_refills_while_old_chunk_is_still_running(self):
        slow_started = threading.Event()
        release_slow = threading.Event()
        replacement_started = threading.Event()

        def check(credential, *args):
            if credential == 'slow':
                slow_started.set()
                if not release_slow.wait(5):
                    raise RuntimeError('test timeout')
            elif credential == 'fast':
                self.assertTrue(slow_started.wait(2))
            else:
                replacement_started.set()
            return {'account': credential}

        with patch.object(api, 'batch_check_one', side_effect=check):
            with AccountPool(2) as accounts, ThreadPoolExecutor(2) as chunks:
                first = chunks.submit(api.run_batch_core, ['slow', 'fast'], None, 2, 0, 1,
                                      account_executor=accounts)
                try:
                    self.assertTrue(slow_started.wait(2))
                    second = chunks.submit(api.run_batch_core, ['replacement'], None, 2, 0, 1,
                                           account_executor=accounts)
                    self.assertTrue(replacement_started.wait(2))
                    self.assertFalse(first.done())
                    self.assertEqual(second.result(timeout=2), [{'account': 'replacement'}])
                finally:
                    release_slow.set()
                self.assertEqual(len(first.result(timeout=2)), 2)
            self.assertEqual(accounts.pending_accounts, 0)


if __name__ == '__main__':
    unittest.main()
