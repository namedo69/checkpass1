"""Offline-testable VN registration variant inferred from the supplied TLT PE.

No engine is imported/executed. Unknown fields are kept as observed constants.
This is not a server-ban workaround and never treats an ACK as role evidence.
"""
import secrets
import struct


def role_name():
    # Independent names avoid exposing the account login in a public character.
    # Conservative short ASCII identity; do not resend on unrelated denials.
    return 'KT' + secrets.token_hex(4)


def _string(value):
    raw = str(value).encode('utf-8')
    if not raw or b'\0' in raw or len(raw) > 63:
        raise ValueError('V2 identity must contain 1..63 UTF-8 bytes, without NUL')
    return struct.pack('>I', len(raw) + 1) + raw + b'\0'


def register_body(name, garena_token):
    """Reconstruction of main.buildRegisterCharacter at VA 0x1402cf300.

    The second string comes from session +0x68/+0x70: Garena open_id,
    NOT access_token or GUID. Corrected using newer engine return-value tracing.
    Parameter name is retained only for source compatibility.
    """
    empty = bytes.fromhex('0000000100')
    return (struct.pack('>I', 1) + _string(name) + empty
            + struct.pack('>II', 10, 1) + _string(garena_token)
            + empty * 2 + bytes(4) + empty * 2 + b'\x03'
            + struct.pack('>I', 5) + b'0000\0' + bytes(4))


def register_packet(seq, c1, name, garena_token):
    import lz4.block
    from .cs import pad_trailer
    if int(seq) < 2:
        raise ValueError('V2 sequence must be >= 2')
    game = struct.pack('>IIII', 1008, 5510, int(c1), int(seq)-2)
    game += register_body(name, garena_token)
    return pad_trailer(struct.pack('>I', seq) + lz4.block.compress(game, store_size=False))


class CreationState:
    """Bounded create state; scoped to a single account/socket, not global."""
    max_sends = 3

    def __init__(self):
        self.sent = 0
        self.retry_code = None
        self.pending = False
        self.events = []

    def reply(self, csid, code):
        self.events.append({'csid': csid, 'code': code, 'sent': self.sent})
        if code == 0:
            return 'wait'
        if csid == 1190 and code == 91103 and self.sent:
            return 'wait'
        if csid == 1009 and code in (91103, 91123) and self.sent:
            if self.sent < self.max_sends:
                self.pending = True
                self.retry_code = code
                return 'retry'
        return 'reject'

    def mark_sent(self):
        if self.sent >= self.max_sends:
            raise ValueError('V2 registration send limit reached')
        self.sent += 1
        self.pending = False


def create_character(sock, key, seq, reader, state, garena_token, pump,
                     log=None, name=None, stop_event=None):
    from .uplevel_stateful import enc_frame_raw
    creation = state['creation_v2']
    if state.get('level_evidence'):
        return seq
    if 1007 not in state.get('received_csids', ()):
        pump(sock, reader, 4.0, state)
    if state.get('level_evidence'):
        return seq
    if state.get('reject') or state.get('server_closed') or state.get('transport_error'):
        return seq
    if 1007 not in state.get('received_csids', ()):
        state['reject'] = 'v2_create_requires_server_1007'
        if log: log('[create-role-v2] STOP: server chưa yêu cầu tạo nhân vật (1007)')
        return seq
    while creation.sent < creation.max_sends:
        if stop_event is not None and stop_event.is_set():
            state['reject'] = 'stopped_before_create'
            break
        selected = name if creation.sent == 0 and name else role_name()
        from .login_v2 import game_ack_packet, identity32
        identity32(garena_token, 'Garena open_id')
        packet = game_ack_packet(seq, state.get('last_c1', 0), 1008,
                                 register_body(selected, garena_token))
        sock.sendall(enc_frame_raw(key, seq, packet, compression=False))
        seq += 1
        creation.mark_sent()
        if log:
            log(f'[create-role-v2] profile=tlt-vn send={creation.sent}/3 csid=1008 name={selected}')
        pump(sock, reader, 6.0, state)
        if state.get('reject') or state.get('transport_error') or state.get('server_closed'):
            break
        if state.get('level_evidence'):
            if log: log('[create-role-v2] role data received; ACK alone is not success')
            break
        if not creation.pending:
            # A zero ACK (or ignored 1190) is not permission to resend.
            pump(sock, reader, 4.0, state)
            if (state.get('reject') or state.get('transport_error')
                    or state.get('server_closed') or state.get('level_evidence')
                    or not creation.pending):
                break
        if log: log(f'[create-role-v2] đổi tên theo csid=1009 code={creation.retry_code}')
    return seq
