"""Bounded opt-in tutorial rescue, invoked on lobby timeout only."""
import struct
import time
from .loader import load
from .deadlines import session_deadline

STEPS = (168,105,0,106,107,108,110,111,112,192,193)
MARKERS = ('NewbieStep_Start_453_1','NewbieStepCompleted_453_1','NewbieStep_Start_453_2')


def wait_lobby_or_rescue(session, notify, stack, timeout=8):
    flow = load('team_flow')
    try:
        flow.wait_lobby(session, timeout=timeout)
        return
    except TimeoutError:
        notify(f'[{stack}] [STUCK] Chờ lobby quá {timeout}s; thử khắc phục tutorial một lần')
    if getattr(session, '_uplv_tutorial_attempted', False):
        raise TimeoutError(f'{stack}: lobby vẫn kẹt sau lượt thử tutorial')
    session._uplv_tutorial_attempted = True
    uid = getattr(session, 'character_uid', None)
    with session_deadline(session, 35, f'{stack} / tutorial rescue', notify):
        session.send_game(2608,b'\3')
        for step in STEPS:
            session.check_stop()
            session.send_game(1193,struct.pack('>I',step))
        for marker in MARKERS:
            raw=marker.encode()+b'\0'
            session.send_game(12170,struct.pack('>I',len(raw))+raw)
        # Drain only a bounded burst; sending telemetry is not confirmation.
        deadline=time.monotonic()+1
        while time.monotonic()<deadline:
            try:
                session.receive_game(deadline)
            except TimeoutError:
                break
        session.connect()
        if uid is not None and session.character_uid!=uid:
            raise ValueError(f'{stack}: UID thay đổi sau tutorial')
        flow.wait_lobby(session, timeout=8)
    notify(f'[{stack}] [TUTORIAL_OK] Đăng nhập lại xác nhận đã vào lobby')
