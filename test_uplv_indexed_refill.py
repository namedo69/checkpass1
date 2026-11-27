"""Production-sized synthetic queue regression: bounded, indexed selection."""
import unittest
from unittest.mock import patch
from test_uplv_screening_handoff import Store
from uplv_coordinator import UpLvCoordinator


class IndexedRefillTests(unittest.TestCase):
    def test_27k_queue_fills_210_slots_and_rotates_without_full_sort(self):
        store=Store();self.addCleanup(store.db.close)
        store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY,setting_value TEXT)')
        pool=UpLvCoordinator(store);pool.pool_settings({'max_rooms':1000})
        # Skip API upload limits; populate only this isolated in-memory DB.
        store.exec("INSERT INTO uplv_jobs VALUES ('synthetic',1,12,'normal','open')")
        store.exec("INSERT INTO uplv_pool_jobs VALUES ('synthetic')")
        store.db.executemany("INSERT INTO uplv_tasks (id,job_id,username_key,account_json,target,mode,status,created_at,dispatch_at) VALUES (?,'synthetic',?,?,12,'normal','waiting',?,0)",
            [(str(i),f'fixture_{i}',f'["fixture_{i}","unused"]',i) for i in range(27000)])
        traces=[];store.db.set_trace_callback(traces.append)
        rooms=[]
        for worker in range(42):
            for _ in range(5):
                reply=pool.claim(dict(satellite_id=f'offline_{worker}',capacity=5,direct_game_protocol=1,verify_protocol=1))
                self.assertIsNotNone(reply['room'])
                rooms.append(reply['room'])
        self.assertEqual(store.fetchone("SELECT count(*) FROM uplv_tasks WHERE status='assigned'"),(1050,))
        selectors=[sql for sql in traces if 'ORDER BY t.dispatch_at' in sql]
        self.assertEqual(len(selectors),210)
        self.assertTrue(all('LEFT JOIN uplv_retry_wait' not in sql for sql in selectors))
        plan=store.fetch('EXPLAIN QUERY PLAN '+selectors[0])
        self.assertTrue(any('idx_uplv_tasks_dispatch' in str(row) for row in plan))
        self.assertFalse(any('TEMP B-TREE' in str(row) for row in plan))
        self.assertEqual(store.fetchone("SELECT count(DISTINCT username_key) FROM uplv_tasks WHERE status='assigned'"),(1050,))

    def test_busy_admission_is_observable_without_database_access(self):
        pool=object.__new__(UpLvCoordinator)
        import threading
        pool.lock=threading.Lock();pool.lock.acquire()
        self.addCleanup(pool.lock.release)
        with patch.object(pool,'touch',side_effect=AssertionError('must not access DB')):
            reply=pool.claim({'satellite_id':'synthetic'})
        self.assertEqual(reply['reason'],'coordinator_busy')
        self.assertEqual(pool._admission_counts,{'coordinator_busy':1})


if __name__=='__main__':unittest.main()
