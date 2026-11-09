import json
import threading
import unittest
import urllib.error
import urllib.request

from uplv_health import start_health


class HealthTests(unittest.TestCase):
    def test_health_and_shutdown_without_sensitive_data(self):
        stop = threading.Event()
        server = start_health('127.0.0.1', 0, stop, 'test')
        url = f'http://127.0.0.1:{server.server_port}/healthz'
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                data = json.load(response)
            self.assertEqual(data, {'ok': True, 'role': 'satellite', 'service_type': 'uplv', 'version': 'test'})
            stop.set()
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(url, timeout=3)
            self.assertEqual(error.exception.code, 503)
            error.exception.close()
        finally:
            server.shutdown()
            server.server_close()
