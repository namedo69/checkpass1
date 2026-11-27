"""42 concurrent schedulers, delayed SQLite reads; no production/network work."""
import sqlite3
import threading
import time
import unittest

from test_uplv_screening_handoff import Store
from uplv_coordinator import UpLvCoordinator


class ConcurrentStore(Store):
    def __init__(self):
        self.db = sqlite3.connect(':memory:', check_same_thread=False)
        self.delay = 0

    def fetch(self, sql, args=()):
        if self.delay:
            time.sleep(self.delay)
        return super().fetch(sql,args)

    def fetchone(self, sql, args=()):
        if self.delay:
            time.sleep(self.delay)
        return super().fetchone(sql,args)


class ConcurrentRefillTests(unittest.TestCase):
    def test_42_schedulers_fill_slots_without_duplicate_accounts_or_request_leases(self):
        store=ConcurrentStore();self.addCleanup(store.db.close)
        store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY,setting_value TEXT)')
        pool=UpLvCoordinator(store)
        pool.pool_settings({'max_rooms':1000})
        job=pool.pool_create({'accounts':'\n'.join(f'fixture_{i}|unused' for i in range(1100))})['job_id']
        store.delay=.0005
        start=threading.Barrier(42)
        errors=[];rooms=[];guard=threading.Lock()
        def scheduler(worker):
            try:
                start.wait(5)
                count=0
                deadline=time.monotonic()+15
                while count<5 and time.monotonic()<deadline:
                    reply=pool.claim(dict(satellite_id=f'fixture_{worker}',capacity=5,direct_game_protocol=1,
                                         verify_protocol=1,request_id=f'{worker*5+count:032x}'))
                    if reply.get('room'):
                        with guard:rooms.append(reply['room'])
                        count+=1
                if count!=5:
                    raise AssertionError(f'worker {worker} only got {count} slots')
            except Exception as exc:
                with guard:errors.append(exc)
        threads=[threading.Thread(target=scheduler,args=(i,)) for i in range(42)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(20)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors,[])
        self.assertEqual(len(rooms),210)
        self.assertEqual(len({room['id'] for room in rooms}),210)
        self.assertEqual(len({a[0] for room in rooms for a in room['accounts']}),1050)
        self.assertEqual(store.fetchone('SELECT count(*) FROM uplv_claim_requests'),(210,))
        self.assertEqual(store.fetchone("SELECT count(*) FROM uplv_tasks WHERE status='assigned'"),(1050,))
        pool.control(dict(action='stop_job',job_id=job))
        self.assertFalse(pool.claim(dict(satellite_id='extra',capacity=5,direct_game_protocol=1)).get('room'))
        self.assertEqual(store.fetchone("SELECT count(*) FROM uplv_tasks WHERE status='stopped'"),(50,))
