"""Report planning equivalence and round-trip regression, offline fixtures."""
import ast
import json
from pathlib import Path
import subprocess
import time
import unittest
from unittest.mock import patch

import uplv_account_pool
from uplv_coordinator import UpLvCoordinator
from test_uplv_screening_handoff import Store


class ReportReadsTests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.addCleanup(self.store.db.close)
        self.store.exec('CREATE TABLE app_settings (setting_key TEXT PRIMARY KEY,setting_value TEXT)')
        self.pool = UpLvCoordinator(self.store)
        self.job = self.pool.pool_create({'accounts': '\n'.join(f'fixture_{i}|unused' for i in range(5))})['job_id']
        self.room = self.pool.claim(dict(satellite_id='fixture',capacity=5,direct_game_protocol=1,verify_protocol=1))['room']
        self.body = dict(satellite_id='fixture',room_id=self.room['id'],lease_token=self.room['lease_token'])

    def legacy(self):
        # Frozen pre-optimization implementations from the existing commit.
        source = subprocess.check_output(['git','show','010ce1f:uplv_account_pool.py'],cwd=Path(__file__).parent).decode()
        cls = next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef))
        methods = [n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name in ('pool_finish','rate_limit_result','retry_result')]
        namespace = dict(vars(uplv_account_pool))
        exec(compile(ast.fix_missing_locations(ast.Module(body=methods,type_ignores=[])),'legacy','exec'),namespace)
        legacy = type('LegacyPlanner',(UpLvCoordinator,),{n.name:namespace[n.name] for n in methods})
        pool = object.__new__(legacy)
        pool.store = self.store
        return pool

    def test_identical_plans_for_mixed_stop_429_login_and_unknown_results(self):
        old = self.legacy()
        for stopped in (False, True):
            for job_state in ('open','stopped'):
                self.store.exec('UPDATE uplv_jobs SET status=?',(job_state,))
                results = {str(i):dict(status='pending',level_after=0,failure_kind=kind,
                    final_error='Auth V2 thất bại: SsoLoginError') for i,kind in enumerate(('rate_limit','login','','session_conflict','server_error'))}
                with patch('uplv_account_pool.time.time',return_value=1000000):
                    before = old.pool_finish(self.body,results,stopped,defer=True)
                    after = self.pool.pool_finish(self.body,results,stopped,defer=True)
                self.assertEqual(before,after)

    def test_429_report_bounded_reads_with_simulated_database_latency(self):
        results = {str(i):dict(status='pending',level_after=0,failure_kind='rate_limit') for i in range(5)}
        counts = []
        timings = []
        for pool in (self.legacy(),self.pool):
            calls = []
            fetch,fetchone = self.store.fetch,self.store.fetchone
            def slow(method):
                def query(sql,args=()):
                    calls.append(sql)
                    time.sleep(.002)
                    return method(sql,args)
                return query
            with patch.object(self.store,'fetch',side_effect=slow(fetch)),patch.object(self.store,'fetchone',side_effect=slow(fetchone)):
                start = time.monotonic()
                pool.pool_finish(self.body,results,False,defer=True)
                timings.append(time.monotonic()-start)
            counts.append(len(calls))
        self.assertEqual(counts,[36,2])
        self.assertLess(timings[1],timings[0]/3)

    def test_heartbeat_task_details_need_one_read_and_report_reuses_same_rows(self):
        heartbeat=dict(self.body,progress={'0':dict(stage='VERIFYING',level=0)})
        queries=[]
        self.store.db.set_trace_callback(queries.append)
        self.pool.heartbeat(heartbeat)
        reads=[sql for sql in queries if sql.startswith('SELECT') and 'uplv_tasks' in sql]
        self.assertEqual(len(reads),1)
        self.assertIn('LEFT JOIN uplv_task_details',reads[0])
        queries.clear()
        results={str(i):dict(status='pending',level_after=0,failure_kind='rate_limit') for i in range(5)}
        self.pool.report(dict(self.body,results=results))
        reads=[sql for sql in queries if sql.startswith('SELECT') and 'uplv_tasks' in sql]
        self.assertEqual(len(reads),2)
        self.assertTrue(all('WHERE t.room_id=' in sql for sql in reads))
