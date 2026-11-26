"""Read profile/idle through V2 without vendor's implicit character creation."""
import json
from pathlib import Path
import tempfile


def read_profile(run_cs, bundle, user, stop):
    from purepc.login_v2 import game_ack_packet
    from purepc.cs import enc_frame_raw
    from purepc.uplevel_stateful import read_frames
    if stop.is_set():
        raise RuntimeError('Stopped')
    session = None
    try:
        with tempfile.TemporaryDirectory(prefix='uplv-readonly-') as temp:
            token = Path(temp)/'token.json'
            token.write_text(json.dumps({'authToken': bundle.access_token,
                                        'openId': bundle.open_id}), encoding='utf8')
            session = run_cs(token, user, role_cs='resolve', create=False,
                             verify_only=True, return_session=True, target=1,
                             replay_1v1=None, stop_event=stop, log=lambda message: None)
        if not session.get('ok') or session.get('stage') != 'session' or 'sock' not in session:
            raise RuntimeError(session.get('reject') or 'initial_role_level_not_received')
        level = session.get('level')
        if type(level) is not int or not 1 <= level <= 30:
            raise ValueError('Thiếu cấp server xác nhận; không coi là Lv0')
        if stop.is_set():
            raise RuntimeError('Stopped')
        packet = game_ack_packet(session['seq'], session['last_c1'], 1060, b'\0')
        session['sock'].sendall(enc_frame_raw(session['key1'], session['seq'], packet,
                                            compression=False))
        replies = read_frames(session['sock'], session['rd'], 8, stop_csids=(1061, 1190, 1009))
        idle = False
        for row in replies:
            if row.get('reject'):
                raise RuntimeError('terminal_restricted: Gateway từ chối đối soát; đã dừng')
            if row.get('csid') in (1190, 1009):
                raw = bytes.fromhex(row.get('body_full') or row.get('body') or '')
                if len(raw) >= 4 and int.from_bytes(raw[:4], 'big'):
                    raise RuntimeError(f"server_error_csid_{row['csid']}_code_{int.from_bytes(raw[:4], 'big')}")
            if row.get('csid') == 1061:
                idle = bytes.fromhex(row.get('body_full') or row.get('body') or '') == b'\0'
        return level, idle
    finally:
        if session is not None and session.get('sock') is not None:
            session['sock'].close()
