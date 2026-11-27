"""Exercise exact production batch method without importing master startup."""
import ast
import contextlib
from pathlib import Path
import unittest
from unittest.mock import Mock


class PipelineTests(unittest.TestCase):
    def store(self):
        tree=ast.parse(Path(__file__).with_name('master_server.py').read_text(encoding='utf8'))
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='PostgreSQLStore')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='batch')
        namespace={'contextlib':contextlib}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[])),'batch','exec'),namespace)
        store=Mock();store.batch=namespace['batch'].__get__(store)
        store._sql.side_effect=lambda sql:sql
        store._uplv_only_write.side_effect=lambda sql:'uplv_' in sql
        conn=Mock();cursor=Mock();events=[]
        @contextlib.contextmanager
        def scope(name,value):
            events.append(name+' enter')
            try:yield value
            except Exception:
                events.append(name+' rollback');raise
            else:events.append(name+' commit')
        store._write_connection.side_effect=lambda flag:scope('connection',conn)
        conn.transaction.side_effect=lambda:scope('transaction',None)
        conn.pipeline.side_effect=lambda:scope('pipeline',None)
        conn.cursor.side_effect=lambda:scope('cursor',cursor)
        return store,conn,cursor,events

    def test_uplv_pipeline_flushes_before_transaction_commit(self):
        store,conn,cursor,events=self.store()
        store.batch([{'sql':'UPDATE uplv_rooms SET status=?','args':['running']},
                     {'sql':'UPDATE uplv_tasks SET status=?','args':['assigned']}])
        conn.pipeline.assert_called_once()
        self.assertEqual(cursor.execute.call_count,2)
        self.assertLess(events.index('pipeline commit'),events.index('transaction commit'))

    def test_other_services_are_not_pipelined(self):
        store,conn,cursor,events=self.store()
        store.batch([{'sql':'UPDATE chunks SET status=?','args':['done']}])
        conn.pipeline.assert_not_called()

    def test_statement_failure_rolls_back_whole_batch(self):
        store,conn,cursor,events=self.store()
        cursor.execute.side_effect=RuntimeError('synthetic')
        with self.assertRaises(RuntimeError):store.batch([{'sql':'UPDATE uplv_rooms SET status=?','args':['running']}])
        self.assertIn('transaction rollback',events)
        self.assertNotIn('transaction commit',events)


if __name__=='__main__':unittest.main()
