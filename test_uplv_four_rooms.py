"""Four-room limits, ownership and per-worker auth serialization; offline."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from test_uplv_screening_handoff import Store
from uplv_coordinator import UpLvCoordinator
from uplv_engine import AuthGate, Engine
from uplv_satellite import Satellite


class FourRoomMasterTests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.db.close)
        self.store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY,setting_value TEXT)')
        self.pool = UpLvCoordinator(self.store)
        self.pool.pool_settings({'max_rooms':1000})
        self.job = self.pool.pool_create({'accounts':'\n'.join(f'four_fixture_{i}|unused' for i in range(60))})['job_id']
        self.body = dict(satellite_id='offline',capacity=4,direct_game_protocol=1,verify_protocol=1)

    def test_four_owned_rooms_replay_and_fifth_blocked_even_when_advertising_five(self):
        rooms = []
        for index in range(4):
            body = dict(self.body,capacity=99,request_id=f'{index:032x}')
            reply = self.pool.claim(body)
            self.assertEqual(self.pool.claim(body), reply)
            rooms.append(reply['room'])
        self.assertEqual(len({a[0] for room in rooms for a in room['accounts']}),20)
        self.assertEqual(self.pool.claim(self.body)['reason'],'already_running')
        self.assertIsNotNone(self.pool.claim(dict(self.body,satellite_id='other'))['room'])
        for room in rooms:
            self.assertGreater(self.pool.heartbeat(dict(satellite_id='offline',room_id=room['id'],
                lease_token=room['lease_token']))['lease_until'],time.time())

    def test_one_finished_room_refills_without_revoking_three_peers(self):
        rooms = [self.pool.claim(self.body)['room'] for _ in range(4)]
        peers = self.store.fetch("SELECT id,lease_token,lease_until FROM uplv_rooms WHERE id!=? AND satellite_id='offline' ORDER BY id", (rooms[0]['id'],))
        self.pool.report(dict(satellite_id='offline',room_id=rooms[0]['id'],lease_token=rooms[0]['lease_token'],
            results={str(i):dict(status='success',level_after=12) for i in range(5)}))
        self.assertEqual(self.store.fetch("SELECT id,lease_token,lease_until FROM uplv_rooms WHERE id!=? AND satellite_id='offline' ORDER BY id", (rooms[0]['id'],)),peers)
        self.assertIsNotNone(self.pool.claim(self.body)['room'])
        self.assertEqual(self.pool.claim(self.body)['reason'],'already_running')

    def test_interrupted_counts_toward_four_and_stop_does_not_reopen(self):
        rooms = [self.pool.claim(self.body)['room'] for _ in range(4)]
        self.store.exec("UPDATE uplv_rooms SET status='interrupted' WHERE id=?", (rooms[0]['id'],))
        self.assertEqual(self.pool.claim(self.body)['reason'],'already_running')
        self.pool.control(dict(action='stop_job',job_id=self.job))
        self.assertIsNone(self.pool.claim(dict(self.body,satellite_id='other'))['room'])
        for room in rooms:
            self.assertTrue(self.pool.heartbeat(dict(satellite_id='offline',room_id=room['id'],
                lease_token=room['lease_token']))['stop'])


class FourRoomAuthTests(unittest.TestCase):
    def test_scheduler_runs_four_rooms_and_never_claims_fifth_while_full(self):
        with tempfile.TemporaryDirectory() as directory:
            client = Mock()
            worker = Satellite(client,Mock(),directory,'offline')
            release, full = threading.Event(), threading.Event()
            seen = []
            guard = threading.Lock()
            claims = []
            def post(action, body):
                if action == 'claim':
                    claims.append(body)
                    return dict(room=dict(id=str(len(claims))))
                return {}
            def room(value):
                with guard:
                    seen.append(value['id'])
                    if len(seen) == 4:
                        full.set()
                release.wait(5)
            client.post.side_effect = post
            worker.run_room = room
            worker.claim_checkpass_chunk = Mock()
            thread = threading.Thread(target=worker.run)
            thread.start()
            try:
                self.assertTrue(full.wait(3))
                time.sleep(.1)
                self.assertEqual(len(claims),4)
                self.assertTrue(all(body['capacity']==4 for body in claims))
            finally:
                worker.shutdown.set()
                release.set()
                thread.join(4)
            self.assertFalse(thread.is_alive())

    def test_four_rooms_share_one_serialized_gate_but_not_token_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = Engine.__new__(Engine)
            engine.state_dir = Path(directory)
            engine.login_lock = threading.Lock()
            engine.auth_gate = AuthGate()
            starts, active, peak = [], 0, 0
            guard = threading.Lock()
            def login(*args, **kwargs):
                nonlocal active, peak
                with guard:
                    active += 1
                    peak = max(peak,active)
                    starts.append(time.monotonic())
                time.sleep(.01)
                with guard:
                    active -= 1
                return object()
            def rooms(accounts,target,count,concurrency,stop,prepare,authenticate,progress,**kwargs):
                authenticate(*accounts[0])
                return {}
            authenticate = Mock(side_effect=login)
            engine.runtime = (rooms,Mock(),authenticate,lambda _:dict(device_id='synthetic'),None,Mock())
            def run(index):
                room = dict(id=str(index),accounts=[('same_fixture','unused')],target=5,mode='synthetic')
                engine.run(room,threading.Event(),Mock(),Mock())
                self.assertNotIn('_auth_context',room)
            with ThreadPoolExecutor(max_workers=4) as executor:
                list(executor.map(run,range(4)))
            self.assertEqual(authenticate.call_count,4)
            self.assertEqual(peak,1)
            self.assertTrue(all(b-a >= 2.49 for a,b in zip(starts,starts[1:])))


if __name__ == '__main__':
    unittest.main()
