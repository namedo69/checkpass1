"""Read profile/idle through V2 without vendor's implicit character creation."""
import json
from pathlib import Path
import tempfile
import time


def reply_packets(replies):
    """Decode full CS frames after removing only a validated tsf4g trailer.

    The generic capture parser's body_full includes randomized padding before
    tsf4g. Comparing that field with a one-byte 1061 state never confirms idle.
    Work from the decrypted envelope, not a guessed prefix of padded bytes.
    """
    from purepc.cs import parse_cspkgs
    envelope = False
    for row in replies:
        if row.get('reject') or row.get('closed') or row.get('transport_error'):
            yield row
        if 'dec_body' in row:
            envelope = True
            plain = bytes.fromhex(row['dec_body'])
            if len(plain) < 6:
                raise ValueError('Profile state frame too short')
            padding = plain[-1]
            if not (6 <= padding <= 32 and padding <= len(plain)
                    and plain[-6:-1] == b'tsf4g'):
                # No trustworthy payload boundary: never guess state from byte0.
                raise ValueError('Profile state trailer invalid')
            plain = plain[:-padding]
            packets = parse_cspkgs(plain)
            for index, packet in enumerate(packets):
                end = packets[index+1]['off'] if index+1 < len(packets) else len(plain)
                yield dict(packet, body_full=plain[packet['off']+16:end].hex())
        elif row.get('csid') is not None and not envelope:
            # Already-normalized packet sources and synthetic test adapters.
            yield row


def read_profile(run_cs, bundle, user, stop, progress=None):
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
        deadline = time.monotonic() + 8
        state = None
        while time.monotonic() < deadline and not stop.is_set():
            replies = read_frames(session['sock'], session['rd'],
                                  min(.6, max(0, deadline-time.monotonic())), stop_csids=())
            for row in reply_packets(replies):
                if row.get('reject'):
                    raise RuntimeError('terminal_restricted: Gateway từ chối đối soát; đã dừng')
                if row.get('closed') or row.get('transport_error'):
                    raise ConnectionError('Profile state transport closed')
                if row.get('csid') in (1190, 1009):
                    raw = bytes.fromhex(row.get('body_full') or row.get('body') or '')
                    if len(raw) >= 4 and int.from_bytes(raw[:4], 'big'):
                        raise RuntimeError(f"server_error_csid_{row['csid']}_code_{int.from_bytes(raw[:4], 'big')}")
                if row.get('csid') == 1061:
                    raw = bytes.fromhex(row.get('body_full') or row.get('body') or '')
                    if raw in (b'\0', b'\1'):
                        # Busy wins over contradictory state in the same batch.
                        state = raw if state != b'\1' else state
            if state is not None:
                break
        if stop.is_set():
            raise RuntimeError('Stopped')
        if progress:
            progress('[PROFILE_STATE] ' + ('idle' if state == b'\0' else 'busy' if state == b'\1' else 'unknown'))
        return level, state == b'\0'
    finally:
        if session is not None and session.get('sock') is not None:
            session['sock'].close()
