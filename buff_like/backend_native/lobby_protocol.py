"""Lobby entry/world handshake, game packet framing, and payload compression; no implicit network calls."""
import base64
from dataclasses import dataclass
import zlib
from .framing import Packet
from .lobby_cipher import LobbyCipher
from .reader import DecodeError, Reader

# Slice descriptor at 0x14075beb0 (8 endpoints).
LOBBY_ENTRY_ENDPOINTS = (
    '148.222.93.33:6670',
    '148.222.93.34:6670',
    '148.222.93.35:6670',
    '148.222.93.36:6670',
    '148.222.93.38:6670',
    '148.222.93.46:6670',
    '148.222.93.47:6670',
    '148.222.93.48:6670',
)

# Slice descriptor at 0x14075bed0 (14 endpoints).
WORLD_SERVER_POOL_ENDPOINTS = (
    '148.222.90.51:6629',
    '148.222.90.51:6630',
    '148.222.90.68:6629',
    '148.222.90.68:6630',
    '148.222.90.135:6629',
    '148.222.90.135:6630',
    '148.222.90.173:6629',
    '148.222.90.173:6630',
    '148.222.90.193:6629',
    '148.222.90.193:6630',
    '148.222.90.196:6629',
    '148.222.90.196:6630',
    '148.222.90.222:6629',
    '148.222.90.222:6630',
)

# Embedded base64 templates at 0x1403a0613 (len 0x304) and 0x14039fdf5 (len 0x88).
LOGIN_REQUEST_B64 = (
    'AwAAhwMAAIwAAAAwQW5kcm9pZCBPUyA5IC8gQVBJLTI4IChQUTNBLjE5MDYwNS4wMDMvMzc5MzI2NSkAAAAA'
    'EXNhbXN1bmcgU00tRzk2ME4AAAAABU5VTEwAAAAACldpLUZpL0xBTgAAAAAAAAAACTEuNjQuMS43AAAABdUA'
    'AAAFMDAwMAAAAAAIMTc2ODU3NwD//////////wAAAAEAAAAACVNNLUc5NjBOAAAAAAtWaWV0bmFtZXNlAAAA'
    'AAEAAAAAAQAAAAPAAAACHAAAAA5wbGFjZWhvbGRlciwzAAAAAAMAAAAlOWE3MjFkNmYtY2IxYi00YTRmLTg1'
    'YWMtYzU1NDNiOWE3MmI3AAAAAAEAAAAAITE3OTI4Mjg2NjA4OTctMzY0NzQ4MTA5ODM5NzExMzMyAAAACzEA'
    'AGwEAABLJAAAgwUAAD7zAAAAAAAAAAAAAAAAAAAD8wEBAAEAAAAwQVBRVC1QQy1SRVFVRVNULUNMSUVOVDAw'
    'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAvwV9QAAAAhMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'
    'MDAAAAAAAAAAAAEAAAAAITAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAAAAAAQAAGvyBAAAA'
    'AAEAAAAAAQAAAAAHZ29vZ2xlAAAAABUtNzQ1NTM5ODg5NjIxMjAzMTQwMQAAAAABAAAAAAAAAAABAQAAAAth'
    'bmhwaGE1NTYyAA=='
)
RESTART_REQUEST_B64 = (
    'AAAD8wMAAIcDAACMAAAAMEFQUVQtUEMtUkVRVUVTVC1DTElFTlQwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'
    'AAAAC/BX1AAa/IEAAAAAABUtNzQ1NTM5ODg5NjIxMjAzMTQwMQA='
)

GAME_INNER_MAGIC = bytes.fromhex('00001586')
RESTART_PRE_BODY = bytes.fromhex('000000000000001f')

MSG_WORLD_REDIRECT = 0x3E5
MSG_LOGIN_REQUEST = 0x3EA
MSG_LOGIN_RESULT = 0x3EB
MSG_REGISTER_REQUIRED = 0x3EF
MSG_REGISTER_CHARACTER = 0x3F0
MSG_REGISTER_RESULT = 0x3F1
MSG_LOBBY_READY = 0x3F5
MSG_LOGIN_PROMPT = 0x3F6
MSG_LEVEL_EXP = 0x3F7
MSG_RESTART_PROMPT = 0x410
MSG_RESTART_REQUEST = 0x411
MSG_SESSION_KICK = 0x412
MSG_ENTER_WORLD_OK = 0x4D7
MSG_RESTART_PRE = 0x4ED
MSG_PING_14BA = 0x14BA
MSG_PONG_14BB = 0x14BB


@dataclass(frozen=True)
class GameMessage:
    msg_id: int
    server_seq: int
    sub_id: int
    body: bytes


@dataclass(frozen=True)
class LoginSuccessInfo:
    world_id: int
    role_uid: int
    level: int
    experience: int


class CharacterCreationRequiredError(DecodeError):
    """Raised when the game server requests character registration (0x3ef/0x3f1)."""


def zlib_decompress_bytes(data: bytes, *, max_output: int = 0x1000000) -> bytes:
    """Reconstructed from main.zlibDecompressBytes (0x140303d40) with output size bound."""
    try:
        decomp = zlib.decompressobj()
        out = decomp.decompress(bytes(data), max_output + 1)
        if decomp.unconsumed_tail or len(out) > max_output:
            raise DecodeError('zlib decompressed payload exceeds limit')
        out += decomp.flush()
        if len(out) > max_output:
            raise DecodeError('zlib decompressed payload exceeds limit')
        return out
    except DecodeError:
        raise
    except Exception as exc:
        raise DecodeError(f'zlib decompression failed: {exc}') from exc


def lz4_block_decompress(data: bytes, *, max_output: int = 0x1000000) -> bytes:
    """Reconstructed from main.lz4BlockDecompress (0x140303f80) with output size bound."""
    src = bytes(data)
    n = len(src)
    pos = 0
    out = bytearray()
    while pos < n:
        token = src[pos]
        pos += 1
        lit_len = token >> 4
        if lit_len == 0x0F:
            while True:
                if pos >= n:
                    raise DecodeError('lz4 literal length overflow')
                b = src[pos]
                pos += 1
                lit_len += b
                if b != 0xFF:
                    break
        if pos + lit_len > n:
            raise DecodeError('lz4 literal overrun')
        if len(out) + lit_len > max_output:
            raise DecodeError('lz4 decompressed payload exceeds limit')
        out.extend(src[pos:pos + lit_len])
        pos += lit_len
        if pos == n:
            break
        if pos + 2 > n:
            raise DecodeError('lz4 match offset truncated')
        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        if offset <= 0 or offset > len(out):
            raise DecodeError('lz4 invalid match offset')
        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 0x0F:
            while True:
                if pos >= n:
                    raise DecodeError('lz4 match length overflow')
                b = src[pos]
                pos += 1
                match_len += b
                if b != 0xFF:
                    break
        if len(out) + match_len > max_output:
            raise DecodeError('lz4 decompressed payload exceeds limit')
        for _ in range(match_len):
            out.append(out[-offset])
    return bytes(out)


def build_entry_auth_packet(msdk_token: str, cipher: LobbyCipher, *, sequence: int = 2) -> Packet:
    """Reconstructed from connectLobbyFromEntry (0x14030f040) 0x2001 packet assembly."""
    if not msdk_token:
        raise ValueError('msdk_token must be non-empty')
    tok = b'J' + msdk_token.encode('ascii')
    plain = (
        b'\xff\xff\x00\x041137\x00\x3f\x01'
        + len(tok).to_bytes(2, 'big')
        + tok
        + b'\x00' * 19
    )
    return Packet(0x2001, 0, sequence, b'', cipher.encrypt(plain))


def parse_world_redirect_body(body: bytes) -> str:
    """Reconstructed from connectLobbyFromEntry (0x14030f040) 0x3e5 world redirect branch."""
    if len(body) < 6:
        raise DecodeError('world redirect body too short')
    host_len = int.from_bytes(body[:4], 'big')
    if not 2 <= host_len <= 64 or len(body) < 6 + host_len:
        raise DecodeError('invalid world redirect host length')
    host_bytes = body[4:4 + host_len].rstrip(b'\x00')
    try:
        host = host_bytes.decode('ascii')
    except UnicodeDecodeError as exc:
        raise DecodeError('invalid world redirect host encoding') from exc
    if not host:
        raise DecodeError('empty world redirect host')
    port = int.from_bytes(body[4 + host_len:6 + host_len], 'big')
    if not 1 <= port <= 65535:
        raise DecodeError('invalid world redirect port')
    if ':' in host:
        return f'[{host}]:{port}'
    return f'{host}:{port}'


def build_login_request(garena_open_id: str, msdk_uid: str, numeric_uid: int) -> bytes:
    """Reconstructed from main.(*LobbySession).buildLoginRequest (0x14030d400)."""
    open_id_bytes = garena_open_id.encode('ascii')
    msdk_uid_bytes = msdk_uid.encode('ascii')
    if len(open_id_bytes) != 32 or len(msdk_uid_bytes) != 32:
        raise ValueError('Garena open_id and MSDK uid must each be 32 ASCII bytes')
    if not isinstance(numeric_uid, int) or not 0 < numeric_uid < 2**64:
        raise ValueError('numeric_uid must be a positive uint64')
    raw = bytearray(base64.b64decode(LOGIN_REQUEST_B64))
    if len(raw) < 0x230:
        raise DecodeError('login template too short')
    raw[:4] = (50331783).to_bytes(4, 'big')
    raw[4:8] = (50331789).to_bytes(4, 'big')
    raw[0x19B:0x1BB] = open_id_bytes
    raw[0x1C9:0x1E9] = msdk_uid_bytes
    raw[0x228:0x230] = numeric_uid.to_bytes(8, 'big')
    expected_tail = b'\x00\x00\x00\x0banhpha5562\x00'
    if bytes(raw[-15:]) != expected_tail:
        raise DecodeError('unexpected login template tail')
    nick = f'Vua{numeric_uid % 100000:05d}'.encode('ascii')
    tail = (len(nick) + 1).to_bytes(4, 'big') + nick + b'\x00'
    return bytes(raw[:-15]) + tail


def build_restart_request() -> bytes:
    """Reconstructed from main.(*LobbySession).buildRestartRequest (0x14030da00)."""
    raw = bytearray(base64.b64decode(RESTART_REQUEST_B64))
    if len(raw) < 16:
        raise DecodeError('restart template too short')
    n = int.from_bytes(raw[12:16], 'big')
    if n <= 0 or len(raw) <= 17 + n:
        raise DecodeError('restart template offset out of range')
    raw[4:8] = (50331783).to_bytes(4, 'big')
    raw[8:12] = (50331789).to_bytes(4, 'big')
    raw[17 + n] = 1
    return bytes(raw)


def build_game_packet(
    msg_id: int,
    body: bytes,
    cipher: LobbyCipher,
    *,
    client_seq: int,
    logical_seq: int,
    ack_seq: int = 0,
) -> Packet:
    """Reconstructed from main.(*LobbySession).SendGameAck (0x14030e200)."""
    inner = (
        int(client_seq).to_bytes(4, 'big')
        + int(msg_id).to_bytes(4, 'big')
        + GAME_INNER_MAGIC
        + int(ack_seq).to_bytes(4, 'big')
        + int(logical_seq).to_bytes(4, 'big')
        + bytes(body)
    )
    return Packet(0x4013, 0, int(client_seq), b'\x00', cipher.encrypt(inner))


def decode_game_packet(packet: Packet, cipher: LobbyCipher) -> GameMessage:
    """Reconstructed from main.(*LobbySession).ReceiveGame (0x14030e5a0)."""
    if packet.kind == 0x5002:
        raise DecodeError('server disconnected (0x5002)')
    if packet.kind != 0x4013:
        raise ValueError(f'non-game packet kind 0x{packet.kind:x}')
    plain = cipher.decrypt(packet.payload)
    if packet.extra:
        flags = packet.extra[0]
        if flags & 2:
            plain = zlib_decompress_bytes(plain)
        if flags & 1:
            plain = lz4_block_decompress(plain)
    if len(plain) < 16:
        raise DecodeError('game packet inner payload shorter than 16-byte header')
    msg_id = int.from_bytes(plain[0:4], 'big')
    server_seq = int.from_bytes(plain[8:12], 'big')
    sub_id = int.from_bytes(plain[12:16], 'big')
    return GameMessage(
        msg_id=msg_id,
        server_seq=server_seq,
        sub_id=sub_id,
        body=plain[16:],
    )


def parse_login_result_1003(body: bytes) -> LoginSuccessInfo:
    """Reconstructed from connectLobbyFromEntry 0x3eb (1003) handler (0x140310040)."""
    if len(body) < 5:
        raise DecodeError('login result 1003 body shorter than 5 bytes')
    code = int.from_bytes(body[:4], 'big', signed=True)
    if code != 0 or body[4] != 0:
        from .account_health import AccountAuthError
        error = AccountAuthError('lobby_1003', code)
        error.args = (f'game rejected login 1003 (code={code}, flag={body[4]})',)
        raise error
    if len(body) >= 32:
        world_id = int.from_bytes(body[4:8], 'big')
        role_uid = int.from_bytes(body[8:16], 'big')
        level = int.from_bytes(body[24:28], 'big')
        experience = int.from_bytes(body[28:32], 'big')
        return LoginSuccessInfo(
            world_id=world_id,
            role_uid=role_uid,
            level=level,
            experience=experience,
        )
    return LoginSuccessInfo(world_id=0, role_uid=0, level=0, experience=0)
