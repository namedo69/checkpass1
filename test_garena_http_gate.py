import unittest
from unittest.mock import patch
from garena_http_gate import HostGate
import garena_api_test_chrome1 as api


class HttpGateTests(unittest.TestCase):
    def test_retry_after_and_shared_cooldown(self):
        gate = HostGate()
        clock = [100.0]
        with patch('garena_http_gate.time.monotonic', side_effect=lambda: clock[0]), \
             patch('garena_http_gate.random.uniform', return_value=0), \
             patch('garena_http_gate.time.sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            self.assertEqual(gate.throttle('60'), 60)
            with gate.admission() as admitted:
                self.assertTrue(admitted)
                self.assertGreaterEqual(clock[0], 160)

    def test_plain_http_429_does_not_retry_ten_times(self):
        session = api.WebSession(1)
        gate = HostGate()
        response = (429, 'https://auth.garena.com/test', 'text/html', {'text_preview': 'limited'})
        with patch('garena_http_gate.host_gate', return_value=gate), \
             patch.object(session, '_request_once', return_value=response) as request:
            self.assertEqual(session.request(response[1]), response)
            request.assert_called_once()
            self.assertGreater(gate.blocked_until, 0)


if __name__ == '__main__':
    unittest.main()
