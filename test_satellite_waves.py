"""Polling no longer waits for chunk waves or their cooldown."""
import unittest
from unittest.mock import Mock, patch
import satellite_worker as worker


class EndLoop(BaseException):
    pass


class StreamingTests(unittest.TestCase):
    def test_claims_more_without_wave_cooldown(self):
        client = Mock()
        claims = [{'claim': {'chunk_id': i, 'accounts': ['dummy|unused']}}
                  for i in range(1, 5)]
        client.claim.side_effect = claims + [EndLoop()]

        def process(*args, account_executor=None, on_submitted=None):
            on_submitted()

        with patch.object(worker.tcp_ui, 'load_verified_tcp_module'), \
             patch.object(worker, '_Client', return_value=client), \
             patch.object(worker.threading, 'Thread', wraps=worker.threading.Thread) as threads, \
             patch.object(worker, '_lease_heartbeat_loop'), \
             patch.object(worker, '_status_log_loop'), \
             patch.object(worker, '_process_chunk', side_effect=process), \
             patch.object(worker.time, 'sleep') as sleep, \
             patch.object(worker, 'RUNTIME_STATUS'), patch('builtins.print'):
            with self.assertRaises(EndLoop):
                worker._worker_loop()
        self.assertEqual(client.claim.call_count, 5)
        sleep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
