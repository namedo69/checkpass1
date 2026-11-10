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
    def test_preflight_routes_existing_and_missing_characters_without_tutorial(self):
        from uplv_engine import Engine
        for level in (0, 3, 5, 8, 12):
            with self.subTest(level=level):
                engine = Engine.__new__(Engine)
                engine.login_lock = threading.Lock()
                engine.last_login = 0
                login = Mock(return_value=SimpleNamespace(sso_key='unused', open_id='unused', access_token='unused'))
                engine.runtime = (None, None, login, lambda u: {'device_id': 'unused'},
                                  Mock(side_effect=AssertionError('Preflight must not run tutorial')), None)
                web = Mock()
                web.read.return_value = level
                session = SimpleNamespace(level=level, check_stop=lambda: None,
                    authenticate_garena_session=lambda *a: None, connect=lambda: None, close=Mock())
                with patch('uplv_kientuong.PlayerSession', return_value=web), \
                     patch('pve_runtime.loader.load', return_value=SimpleNamespace(LeverSession=lambda *a: session)), \
                     patch('pve_runtime.web_finish.idle_on_current_session', return_value=True):
                    rows = engine.run({'accounts': [['u', 'p']], 'levels': [0], 'targets': [12],
                        'screen_only': True}, threading.Event(), lambda *a: None, lambda *a: None)
                self.assertEqual(rows[0][0], level >= 12)
                self.assertEqual(rows[0][2], level)
                self.assertEqual(rows[0][3], '' if level >= 12 else 'screen_ready')
                web.read.assert_called_once()
                web.close.assert_called_once()

    def test_optional_cards_attempt_both_types_despite_failures(self):
        from pve_runtime.rewards import prepare_optional
        helper = Mock()
        helper.request.side_effect = TimeoutError()
        helper.prepare_exp.side_effect = RuntimeError('no ruby')
        helper.prepare_win_exp.side_effect = RuntimeError('rejected')
        rewards = SimpleNamespace(AutomaticRewards=Mock(return_value=helper),
                                  collect_starter_checkin=lambda: b'')
        session = SimpleNamespace(check_stop=lambda: None,
                                  reward_state=SimpleNamespace(checkins=[]))
        with patch('pve_runtime.rewards.load', return_value=rewards):
            result = prepare_optional(session)
        helper.prepare_exp.assert_called_once()
        helper.prepare_win_exp.assert_called_once()
        self.assertTrue(result['warnings'])

    def run_batch(self, behavior='sent', level=12, idle=True, cards=False):
        sessions, clients, published = [], [], {}
        class Session:
            def __init__(self, stop, notify):
                self.notify, self.level, self.experience = notify, 5, 0
                self.character_uid = len(sessions) + 1
                self.closed = False
                self.reward_state = SimpleNamespace(exp_active=lambda: False, win_exp_active=lambda: False)
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
             patch('pve_runtime.rewards.install_resource_decoder'), \
             patch('pve_runtime.rewards.prepare_optional', side_effect=RuntimeError('cards unavailable')), \
             patch('pve_runtime.web_finish.idle_on_current_session', return_value=idle):
            rows = run_five_batch([(f'u{i}', 'unused') for i in range(5)], 12, 5,
                threading.Event(), lambda *a: (True, 1, 5, ''),
                lambda *a: SimpleNamespace(access_token='unused', open_id='unused'),
                lambda *a: None, mode='victory', web_verify=web, prepare_cards=cards,
                completed=lambda i, row: published.update({i: row}))
        self.assertTrue(all(s.closed for s in sessions))
        self.assertTrue(all(c.close.called for c in clients))
        return rows, clients

    def test_missing_cards_and_unconfirmed_buffs_still_play(self):
        rows, clients = self.run_batch(cards=True)
        self.assertTrue(all(row[0] for row in rows.values()))
        self.assertTrue(all(client.verify.called for client in clients))

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
        http.get.return_value.json.return_value = {'player': {'gopOpenId': 'other', 'level': 12}}
        session = PlayerSession('unused', 'expected', threading.Event(), session=http)
        session.authorized = True
        import time
        with self.assertRaises(ValueError): session.read(time.monotonic() + 5)
        http.get.return_value.json.return_value = {'player': {'gopOpenId': 'expected', 'tencentOpenId': 'different-game-id', 'level': 8}}
        self.assertEqual(session.read(time.monotonic() + 5), 8)
        http.get.return_value.status_code = 422
        self.assertEqual(session.read(time.monotonic() + 5, allow_no_player=True), 0)
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
