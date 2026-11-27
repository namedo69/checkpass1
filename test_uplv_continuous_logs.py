"""Safe continuous progress views/stdout, without credentials or game traffic."""
import unittest
from uplv_logs import RoomLogs


class ContinuousLogsTests(unittest.TestCase):
    def test_progress_redaction_and_five_second_timer_cadence(self):
        logs = RoomLogs('synthetic')
        logs.protect([['synthetic-user', 'synthetic-password']])
        safe = logs.add(0, '[LEVEL] Lv8 synthetic-user synthetic-password token=secret')
        self.assertNotIn('synthetic-user', safe)
        self.assertNotIn('synthetic-password', safe)
        self.assertNotIn('token=secret', safe)
        self.assertEqual(safe, logs.view()[-1]['text'])
        self.assertIsNotNone(logs.add(0, '[TIMER] 0'))
        self.assertIsNone(logs.add(0, '[TIMER] 4'))
        self.assertIsNotNone(logs.add(0, '[TIMER] 5'))
        self.assertIsNotNone(logs.add(0, '[TIMER] 10'))


if __name__ == '__main__':
    unittest.main()
