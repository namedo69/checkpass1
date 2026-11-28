"""Account-only waits cannot block eligible peers; no network/game accounts."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from uplv_engine import AuthGate
from test_uplv_auth_gate import ClockStop


class AuthWaitFairnessTests(unittest.TestCase):
    def test_future_account_deadline_leaves_gate_available_for_other_room(self):
        gate = AuthGate()
        waiting, stopped, entered = threading.Event(), threading.Event(), threading.Event()
        errors = []
        def waiter():
            try:
                gate.enter(stopped,lambda message: waiting.set(),not_before=time.time()+600)
                errors.append('future account was admitted')
                gate.lock.release()
            except RuntimeError as exc:
                if str(exc) != 'Stopped':
                    errors.append(type(exc).__name__)
        thread = threading.Thread(target=waiter)
        thread.start()
        try:
            self.assertTrue(waiting.wait(2))
            self.assertTrue(gate.lock.acquire(False),'account wait held auth mutex')
            gate.lock.release()
            peer_stop = threading.Event()
            def peer():
                try:
                    gate.enter(peer_stop,Mock())
                    entered.set()
                    gate.lock.release()
                except RuntimeError:
                    pass
            peer_thread = threading.Thread(target=peer)
            peer_thread.start()
            try:
                self.assertTrue(entered.wait(2),'eligible peer blocked by unrelated account')
                self.assertFalse(stopped.is_set())
            finally:
                peer_stop.set()
                peer_thread.join(2)
        finally:
            stopped.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])

    def test_shared_worker_wait_is_still_enforced_without_holding_mutex(self):
        gate, clock, messages = AuthGate(), ClockStop(), []
        gate.retry_until = 112
        def on_wait():
            self.assertTrue(gate.lock.acquire(False))
            gate.lock.release()
            if clock.now < 102:
                gate.retry_until = 120
        clock.on_wait = on_wait
        with patch('uplv_engine.time',SimpleNamespace(monotonic=lambda:clock.now)):
            gate.enter(clock,messages.append)
        self.assertGreaterEqual(clock.now,120)
        self.assertTrue(gate.lock.locked())
        gate.lock.release()
        self.assertTrue(any('reason=worker_backoff' in m for m in messages))

    def test_account_wait_is_converted_once_and_stop_releases_no_other_owner(self):
        gate, clock, messages = AuthGate(), ClockStop(), []
        gate.lock.acquire()
        clock.on_wait = lambda: setattr(clock,'stopped',True)
        with patch('uplv_engine.time',SimpleNamespace(monotonic=lambda:clock.now,time=lambda:1000)):
            with self.assertRaisesRegex(RuntimeError,'^Stopped$'):
                gate.enter(clock,messages.append,not_before=1200)
        self.assertTrue(gate.lock.locked())
        self.assertIn('reason=account_backoff',messages[0])
        gate.lock.release()

    def test_progress_exception_never_leaks_acquired_gate(self):
        gate = AuthGate()
        gate.retry_until = time.monotonic()+600
        with self.assertRaisesRegex(ValueError,'synthetic'):
            gate.enter(threading.Event(),Mock(side_effect=ValueError('synthetic')))
        self.assertTrue(gate.lock.acquire(False))
        gate.lock.release()


class DashboardAuthWaitTests(unittest.TestCase):
    def test_unknown_levels_and_specific_wait_survive_pending_status(self):
        node = shutil.which('node')
        if not node:
            self.skipTest('Node unavailable for dashboard JavaScript regression')
        source = (Path(__file__).parent/'uplv_admin.html').read_text(encoding='utf8')
        helper = source[source.index('function roomSlotDisplay('):source.index('\nfunction renderRooms(')]
        fixtures = [
            [dict(stage='AUTH_WAIT',level=0,detail='[AUTH_WAIT] reason=account_backoff remaining=123s'),dict(status='pending',level_after=0)],
            [dict(stage='STACK3',level=8),dict(status='pending',level_after=0)],
            [dict(stage='AUTH_WAIT'),dict(status='success',level_after=12)],
            [dict(level=0,level_confirmed=True),{}],
            [dict(stage='AUTH_WAIT',detail='reason=worker_backoff remaining=900s'),{}],
            [dict(stage='AUTH_WAIT',detail='reason=auth_queue'),{}]]
        script = helper+'\nconsole.log(JSON.stringify('+json.dumps(fixtures)+'.map(([p,z])=>roomSlotDisplay(p,z))));'
        result = subprocess.run([node,'-e',script],capture_output=True,text=True,encoding='utf8',check=True)
        rows = json.loads(result.stdout)
        self.assertEqual(rows[0]['level'],'?')
        self.assertIn('chờ riêng acc',rows[0]['stage'])
        self.assertIn('123s',rows[0]['stage'])
        self.assertEqual(rows[1],dict(level=8,stage='STACK3'))
        self.assertEqual(rows[2],dict(level=12,stage='success'))
        self.assertEqual(rows[3]['level'],0)
        self.assertIn('backoff chung',rows[4]['stage'])
        self.assertIn('chờ lượt',rows[5]['stage'])

    def test_wait_reason_is_sent_in_heartbeat_detail(self):
        from uplv_satellite import Satellite
        client, engine = Mock(), Mock()
        heartbeat = []
        def post(action,body):
            if action=='heartbeat':
                heartbeat.append(body)
            return dict(lease_until=time.time()+180)
        client.post.side_effect = post
        def run(room,stop,progress,completed,**kwargs):
            progress(0,'[AUTH_WAIT] reason=account_backoff remaining=123s; no secret')
            return {}
        engine.run.side_effect = run
        with tempfile.TemporaryDirectory() as directory,patch('builtins.print'):
            room = dict(id='synthetic-wait',accounts=[('fixture','unused')],lease_token='unused',
                lease_until=time.time()+180,target=12,mode='synthetic')
            Satellite(client,engine,directory,'offline').run_room(room)
            report = json.loads(next(Path(directory).glob('pending_report_*.json')).read_text(encoding='utf8'))
        self.assertIn('reason=account_backoff',report['progress']['0']['detail'])
        self.assertEqual(report['progress']['0']['stage'],'AUTH_WAIT')


if __name__=='__main__':
    unittest.main()
