"""Explicit server-idle gate before an interrupted account may rejoin a team."""
import time
from .loader import load
from .deadlines import session_deadline

REGROUP = 'regroup_ready'
UNRESOLVED = 'regroup_unresolved'


def inspect_for_regroup(session, uid, target, notify=lambda msg: None):
    with session_deadline(session, 35, 'Kiểm tra trước tái ghép', notify):
        session.connect()
        if session.character_uid != uid:
            raise ValueError('UID không khớp khi tái ghép')
        if type(session.level) is not int or type(session.experience) is not int:
            raise ValueError('Thiếu snapshot trước tái ghép')
        if session.level >= target:
            return 'done'
        load('team_flow').wait_lobby(session, timeout=8, allow_battle=True)
        session.send_game(1060, b'\0')
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                msg, body, _ = session.receive_game(deadline)
            except TimeoutError:
                break
            if msg == 1061:
                if body == b'\0':
                    session.pending_battle = None
                    return REGROUP
                if body == b'\1':
                    return UNRESOLVED
    # Silence is NOT evidence of an idle account.
    return UNRESOLVED
