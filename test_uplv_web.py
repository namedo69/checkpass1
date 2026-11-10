"""Offline evidence gates for web verification; no live requests."""
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).parent / 'uplv_runtime'))
from pve_runtime.uplv import run_five_batch
from pve_runtime.web_finish import OutcomeSent, outcome_sent_status
from uplv_kientuong import PlayerSession


class WebTests(unittest.TestCase):
    def run_batch(self, behavior='sent', level=12, idle=True):
        sessions, clients, published = [], [], {}
        class Session:
            def __init__(self, stop, notify):
                self.notify, self.level, self.experience = notify, 5, 0
                self.character_uid = len(sessions) + 1
                self.closed = False
                sessions.append(self)
            def authenticate_garena_session(self, *args): pass
            def check_stop(self): pass
            def connect(self): pass
            def close(self): self.closed = True
        class Match:
            def __init__(self, *args, **kwargs):
                self.surrender = SimpleNamespace(seconds=375)
                self.outcomes = SimpleNamespace(mode='victory', seconds=190)
            def play(self, session):
                if behavior == 'error': raise OSError('send failed')
                if behavior == 'sent':
                    session.notify('status', text='Cả đội gửi WIN; chờ server xác nhận và đọc Exp')
        def web(*args):
            client = Mock()
            client.verify.return_value = level
            clients.append(client)
            return client
        with patch('pve_runtime.uplv.load', return_value=SimpleNamespace(LeverSession=Session, FiveMatch=Match)), \
             patch('pve_runtime.tutorial.wait_lobby_or_rescue'), \
             patch('pve_runtime.web_finish.idle_on_current_session', return_value=idle):
            rows = run_five_batch([(f'u{i}', 'unused') for i in range(5)], 12, 5,
                threading.Event(), lambda *a: (True, 1, 5, ''),
                lambda *a: SimpleNamespace(access_token='unused', open_id='unused'),
                lambda *a: None, mode='victory', web_verify=web,
                completed=lambda i, row: published.update({i: row}))
        self.assertTrue(all(s.closed for s in sessions))
        self.assertTrue(all(c.close.called for c in clients))
        return rows, clients

    def test_only_post_send_status_allows_verification(self):
        for behavior in ('return', 'error'):
            rows, clients = self.run_batch(behavior)
            self.assertTrue(all(r[3] == 'pool_verifying' and not r[0] for r in rows.values()))
            self.assertFalse(any(c.verify.called for c in clients))
        rows, clients = self.run_batch()
        self.assertTrue(all(r[0] for r in rows.values()))
        self.assertTrue(all(c.verify.called for c in clients))

    def test_stale_or_busy_results_cannot_reenter_ready_pool(self):
        for level, idle, marker in ((5, True, 'pool_verifying'), (8, False, 'pool_verifying'),
                                     (8, True, 'pool_ready'), (None, True, 'pool_verifying')):
            rows, _ = self.run_batch(level=level, idle=idle)
            self.assertTrue(all(r[3] == marker and not r[0] for r in rows.values()))

    def test_identity_validation_and_expired_session(self):
        http = Mock()
        http.get.return_value.status_code = 200
        http.get.return_value.json.return_value = {'player': {'tencentOpenId': 'other', 'level': 12}}
        session = PlayerSession('unused', 'expected', threading.Event(), session=http)
        session.authorized = True
        import time
        with self.assertRaises(ValueError): session.read(time.monotonic() + 5)
        http.get.return_value.status_code = 401
        http.get.return_value.raise_for_status.side_effect = __import__('requests').HTTPError()
        with self.assertRaises(__import__('requests').HTTPError): session.read(time.monotonic() + 5)
        self.assertFalse(session.authorized)

    def test_outcome_gate_is_win_only(self):
        text = 'Cả đội gửi WIN; chờ server xác nhận và đọc Exp'
        self.assertTrue(outcome_sent_status(text, 'victory'))
        self.assertFalse(outcome_sent_status(text, 'defeat'))
        self.assertFalse(outcome_sent_status('outcome_report_sent', 'victory'))


if __name__ == '__main__':
    unittest.main()
