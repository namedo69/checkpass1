"""Explicit single-room clients remain safe under the four-room master cap."""
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import uplv_config
from uplv_coordinator import UpLvCoordinator
from uplv_satellite import Metrics, Satellite
from test_uplv_screening_handoff import Store


class SingleRoomTests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.db.close)
        self.store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY,setting_value TEXT)')
        self.pool = UpLvCoordinator(self.store)
        self.pool.pool_create({'accounts': '\n'.join(f'fixture_{i}|unused' for i in range(20))})
        self.body = dict(satellite_id='fixture', capacity=1, direct_game_protocol=1, verify_protocol=1)

    def test_old_worker_cannot_claim_second_room_but_can_replay_owned_request(self):
        body = dict(self.body, request_id='a'*32)
        first = self.pool.claim(body)
        self.assertIsNotNone(first['room'])
        self.assertEqual(self.pool.claim(body), first)
        self.assertEqual(self.pool.claim(dict(body, request_id='b'*32))['reason'], 'already_running')
        self.assertIsNotNone(self.pool.claim(dict(self.body, satellite_id='other'))['room'])

    def test_legacy_extra_rooms_are_not_revoked_and_must_all_drain_before_refill(self):
        first = self.pool.claim(self.body)['room']
        second = self.pool.claim(dict(self.body, satellite_id='other'))['room']
        # Represent two already-owned leases from the former five-room policy.
        self.store.exec('UPDATE uplv_rooms SET satellite_id=? WHERE id=?', ('fixture', second['id']))
        before = self.store.fetch('SELECT id,status,lease_token,lease_until FROM uplv_rooms ORDER BY id')
        self.assertEqual(self.pool.claim(self.body)['reason'], 'already_running')
        self.assertEqual(self.store.fetch('SELECT id,status,lease_token,lease_until FROM uplv_rooms ORDER BY id'), before)
        for index, room in enumerate((first, second)):
            owned = dict(satellite_id='fixture', room_id=room['id'], lease_token=room['lease_token'])
            self.assertGreater(self.pool.heartbeat(owned)['lease_until'], time.time())
            self.pool.report(dict(owned, results={str(i): dict(status='success', level_after=12) for i in range(5)}))
            if index == 0:
                self.assertEqual(self.pool.claim(self.body)['reason'], 'already_running')
        self.assertIsNotNone(self.pool.claim(self.body)['room'])

    def test_interrupted_room_still_occupies_the_only_slot(self):
        room = self.pool.claim(self.body)['room']
        self.store.exec("UPDATE uplv_rooms SET status='interrupted' WHERE id=?", (room['id'],))
        self.assertEqual(self.pool.claim(self.body)['reason'], 'already_running')

    def test_worker_advertises_and_schedules_four_even_with_stale_config(self):
        self.assertEqual(uplv_config.MAX_ROOMS, 4)
        with tempfile.TemporaryDirectory() as directory, patch('uplv_satellite.config.MAX_ROOMS', 5):
            worker = Satellite(Mock(), Mock(), directory, 'fixture')
            self.assertEqual(Metrics().snapshot()['capacity'], 4)
            worker._run_scheduler = Mock()
            worker.report_loop = Mock()
            worker.run()
            self.assertEqual(worker._run_scheduler.call_args.args[0], 4)


if __name__ == '__main__':
    unittest.main()
