"""Offline CheckPass -> UpLv handoff; synthetic accounts, in-memory DB only."""
import json
import sqlite3
import unittest

from uplv_coordinator import UpLvCoordinator


class Store:
    def __init__(self):
        self.db = sqlite3.connect(':memory:')
    def exec(self, sql, args=()):
        self.db.execute(sql, args)
    def fetch(self, sql, args=()):
        return self.db.execute(sql, args).fetchall()
    def fetchone(self, sql, args=()):
        return self.db.execute(sql, args).fetchone()
    def batch(self, statements):
        with self.db:
            for row in statements:
                self.db.execute(row['sql'], row.get('args', ()))


class ScreeningHandoffTests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.db.close)
        self.store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT)')
        self.pool = UpLvCoordinator(self.store)
        self.job = self.pool.pool_create({'accounts': '\n'.join(f'synthetic{i}|unused' for i in range(5))})['job_id']

    def report(self, row, legacy=False):
        if legacy:
            claim = self.pool.checkpass_claim({'satellite_id': 'test'})['check']
            rows = [dict(task_id=item['task_id'], level=None, check_status=row.get('status', ''),
                         check_result=row.get('result_type', ''),
                         check_player_status=row.get('player_status', ''),
                         tcp_login_ok=row.get('tcp_login_ok', ''),
                         no_character=False) for item in claim['accounts']]
            self.pool.checkpass_report({'satellite_id': 'test', 'token': claim['token'], 'rows': rows})
        else:
            claim = self.pool.hidden_check_claim({'satellite_id': 'test'})
            self.pool.hidden_check_report(dict(satellite_id='test', chunk_id=claim['chunk_id'],
                lease_token=claim['lease_token'], done=True,
                rows=[dict(row, stt=str(i)) for i in range(1, 6)]))

    def test_authenticated_unreadable_ctnv_enters_uplv_without_missing_role_claim(self):
        self.report({'status': 'OK', 'result_type': 'Lỗi CTNV', 'player_status': 'Lỗi CTNV',
                     'level': '', 'tcp_login_ok': '1'})
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('waiting',)])
        for raw, in self.store.fetch('SELECT detail_json FROM uplv_task_details'):
            detail = json.loads(raw)
            self.assertEqual(detail['stage'], 'UPLV_PROFILE_PENDING')
            self.assertIs(detail['level_confirmed'], False)
        self.assertIsNone(self.pool.hidden_check_claim({'satellite_id': 'test'}))
        self.assertIsNotNone(self.pool.pool_form_room())
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('assigned',)])

    def test_legacy_report_also_hands_off_unreadable_ctnv(self):
        self.report({'status': 'OK', 'result_type': 'Lỗi CTNV', 'player_status': 'Lỗi CTNV'}, legacy=True)
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('waiting',)])

    def test_explicit_ban_never_enters_uplv_even_with_valid_level(self):
        self.report({'status': 'OK', 'result_type': 'Lỗi CTNV', 'player_status': 'Bị khóa', 'level': '12'})
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('failed',)])
        self.assertIsNone(self.pool.pool_form_room())

    def test_unclassified_failure_is_not_sent_to_creation(self):
        self.report({'status': 'CHƯA THỂ CHECK', 'result_type': 'Chưa thể check', 'level': ''})
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('screening',)])

    def test_ctnv_does_not_overwrite_existing_level(self):
        self.store.exec('UPDATE uplv_tasks SET level=8')
        self.report({'status': 'OK', 'result_type': 'Lỗi CTNV', 'level': ''})
        self.assertEqual(self.store.fetch('SELECT DISTINCT level FROM uplv_tasks'), [(8,)])

    def test_explicit_failed_tcp_does_not_get_unknown_profile_handoff(self):
        self.report({'status': 'OK', 'result_type': 'Lỗi CTNV', 'level': '', 'tcp_login_ok': '0'})
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('screening',)])

    def test_legacy_ban_never_enters_uplv(self):
        self.report({'status': 'OK', 'result_type': 'Lỗi CTNV', 'player_status': 'Bị khóa'}, legacy=True)
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('failed',)])

    def test_old_chunk_cannot_overwrite_assigned_tasks(self):
        claim = self.pool.hidden_check_claim({'satellite_id': 'test'})
        body = dict(satellite_id='test', chunk_id=claim['chunk_id'], lease_token=claim['lease_token'],
                    done=False, rows=[dict(stt=str(i), status='OK', result_type='Lỗi CTNV', level='') for i in range(1, 6)])
        self.pool.hidden_check_report(body)
        self.pool.pool_form_room()
        self.pool.hidden_check_report(body)
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('assigned',)])

    def test_invalid_chunk_lease_rejected_without_changes(self):
        claim = self.pool.hidden_check_claim({'satellite_id': 'test'})
        with self.assertRaises(ValueError):
            self.pool.hidden_check_report(dict(satellite_id='test', chunk_id=claim['chunk_id'],
                lease_token='wrong', done=True, rows=[dict(stt='1', status='OK', result_type='Lỗi CTNV', level='')]))
        self.assertEqual(self.store.fetch('SELECT DISTINCT status FROM uplv_tasks'), [('screening',)])


if __name__ == '__main__':
    unittest.main()
