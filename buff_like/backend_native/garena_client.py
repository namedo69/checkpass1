"""Garena TCP login session and MSDK HTTP exchange runner; no implicit side effects on import."""
from dataclasses import dataclass
import gzip
import hashlib
import secrets
import socket
import threading
import time
import urllib.request
from .garena_framing import (
    MAX_FRAME,
    MIN_ENC_FRAME,
    build_encrypted_frame,
    build_frame,
    parse_encrypted_frame,
    parse_frame,
)
from .garena_login_body import (
    CMD_LOGIN_BODY,
    CMD_LOGIN_PREPARE,
    CMD_OAUTH_TOKEN,
    OAuthGrant,
    build_login_body,
    build_oauth_request_payload,
    parse_login_body_payload,
    parse_login_prepare_payload,
    parse_oauth_response_payload,
)
from .garena_prepare import build_prepare
from .msdk_exchange import (
    MSDKIdentity,
    build_msdk_login_request,
    format_uuid_from_bytes,
    parse_msdk_login_response,
)
from .reader import DecodeError
from .account_health import AccountAuthError
from .transport import read_exact

# Slice descriptor at 0x14075bdf0 (10 endpoints).
GARENA_GATEWAY_ENDPOINTS = (
    '103.247.205.14:19000',
    '103.247.205.15:19000',
    '103.247.205.16:19000',
    '103.247.205.17:19000',
    '103.247.205.18:19000',
    '103.247.205.19:19000',
    '103.247.205.20:19000',
    '103.247.205.21:19000',
    '103.247.205.22:19000',
    '103.247.205.23:19000',
)

DEVICE_KEY_PREFIX = b'vua_truyenlua_dev:'


class GarenaAuthError(AccountAuthError):
    def __init__(self, stage: str, code: int, message: str = ''):
        super().__init__(stage, code, message)
        detail = f'Garena {stage} failed with code {self.code}'
        if message:
            detail = f'{detail}: {message}'
        self.args = (detail,)


@dataclass(frozen=True)
class DeviceIdentity:
    device_key: bytes
    device_uuid: str


def derive_device_identity(account: str) -> DeviceIdentity:
    """Reconstructed from main.NewLobbySession (0x14030c280)."""
    normalized = account.lower().encode('utf-8')
    digest = hashlib.sha256(DEVICE_KEY_PREFIX + normalized).digest()
    raw = bytearray(digest[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    device_key = bytes(raw)
    return DeviceIdentity(
        device_key=device_key,
        device_uuid=format_uuid_from_bytes(device_key),
    )


def next_garena_sequence(counter: int) -> tuple[int, int]:
    """Reconstructed from GarenaTCPLoginOnce sequence formula."""
    next_counter = int(counter) + 1
    seq = (next_counter & 0x7FFFFFFF) | 0x1102
    return seq, next_counter


def _header_ints(header_fields) -> dict[int, int]:
    ints = {}
    for field in header_fields:
        if field.wire == 0:
            ints[field.number] = field.value
    return ints


def read_garena_frame(sock, *, deadline, stop):
    raw_len = read_exact(sock, 4, deadline=deadline, stop=stop, max_bytes=4)
    body_len = int.from_bytes(raw_len, 'little')
    if not 2 <= body_len <= MAX_FRAME:
        raise DecodeError('invalid Garena frame length')
    body = read_exact(sock, body_len, deadline=deadline, stop=stop, max_bytes=MAX_FRAME)
    return parse_frame(raw_len + body)


def read_encrypted_garena_frame(sock, key: bytes, *, deadline, stop):
    raw_len = read_exact(sock, 4, deadline=deadline, stop=stop, max_bytes=4)
    body_len = int.from_bytes(raw_len, 'little')
    if not MIN_ENC_FRAME <= body_len <= MAX_FRAME or body_len % 8:
        raise DecodeError('invalid encrypted Garena frame length')
    body = read_exact(sock, body_len, deadline=deadline, stop=stop, max_bytes=MAX_FRAME)
    return parse_encrypted_frame(raw_len + body, key)


def _recv_matching_frame(sock, expected_cmd: int, expected_seq: int, *, deadline, stop, encrypted_key=None):
    for _ in range(5):
        if encrypted_key is None:
            frame = read_garena_frame(sock, deadline=deadline, stop=stop)
        else:
            frame = read_encrypted_garena_frame(sock, encrypted_key, deadline=deadline, stop=stop)
        ints = _header_ints(frame.header)
        if (ints.get(4) == expected_cmd
                and ints.get(2) == expected_seq
                and ints.get(3) == 3):
            return frame, ints
    raise DecodeError(f'Garena response command 0x{expected_cmd:x} not received within 5 frames')


def garena_login_on_socket(
    sock,
    account: str,
    password: str,
    device_key: bytes,
    *,
    deadline: float,
    stop=None,
    seq_counter: int = 0,
    now_fn=time.time,
    temp_key: bytes | None = None,
) -> tuple[OAuthGrant, int]:
    """Execute one 0x100 -> 0x101 -> 0x1b7 Garena authentication exchange on an open socket."""
    if stop is None:
        stop = threading.Event()
    if len(device_key) != 16:
        raise ValueError('device_key must be 16 bytes')
    if temp_key is None:
        temp_key = secrets.token_bytes(16)
    elif len(temp_key) != 16:
        raise ValueError('temp_key must be 16 bytes')

    seq1, seq_counter = next_garena_sequence(seq_counter)
    prep_payload = build_prepare(account, temp_key)
    prep_frame = build_frame(
        CMD_LOGIN_PREPARE,
        prep_payload,
        sequence=seq1,
        unix_seconds=int(now_fn()),
    )
    sock.sendall(prep_frame)

    resp1, ints1 = _recv_matching_frame(
        sock, CMD_LOGIN_PREPARE, seq1, deadline=deadline, stop=stop
    )
    rc1 = ints1.get(5, 0)
    if rc1 != 0:
        raise GarenaAuthError('prepare', rc1)
    salts = parse_login_prepare_payload(resp1.payload)

    seq2, seq_counter = next_garena_sequence(seq_counter)
    login_payload, login_key = build_login_body(
        password, salts.salt1, salts.salt2, device_key
    )
    login_frame = build_frame(
        CMD_LOGIN_BODY,
        login_payload,
        sequence=seq2,
        unix_seconds=int(now_fn()),
    )
    sock.sendall(login_frame)

    resp2, ints2 = _recv_matching_frame(
        sock, CMD_LOGIN_BODY, seq2, deadline=deadline, stop=stop
    )
    rc2 = ints2.get(5, 0)
    if rc2 != 0:
        raise GarenaAuthError('login', rc2)
    session_key = parse_login_body_payload(resp2.payload, login_key)

    seq3, seq_counter = next_garena_sequence(seq_counter)
    oauth_payload = build_oauth_request_payload()
    oauth_frame = build_encrypted_frame(
        CMD_OAUTH_TOKEN,
        oauth_payload,
        session_key,
        sequence=seq3,
        unix_seconds=int(now_fn()),
    )
    sock.sendall(oauth_frame)

    resp3, _ = _recv_matching_frame(
        sock,
        CMD_OAUTH_TOKEN,
        seq3,
        deadline=deadline,
        stop=stop,
        encrypted_key=session_key,
    )
    grant = parse_oauth_response_payload(resp3.header, resp3.payload)
    return grant, seq_counter


def parse_host_port(endpoint: str) -> tuple[str, int]:
    host, sep, port_str = endpoint.rpartition(':')
    if not sep or not host:
        raise ValueError(f'invalid endpoint: {endpoint}')
    return host, int(port_str, 10)


def garena_authenticate(
    account: str,
    password: str,
    device_key: bytes | None = None,
    *,
    endpoints=GARENA_GATEWAY_ENDPOINTS,
    connect_timeout: float = 3.5,
    session_timeout: float = 8.0,
    stop=None,
    now_fn=time.time,
) -> OAuthGrant:
    """Connect to a Garena gateway endpoint and perform a single authentication flow."""
    if stop is None:
        stop = threading.Event()
    if device_key is None:
        device_key = derive_device_identity(account).device_key
    last_error = None
    seq_counter = 0
    for endpoint in endpoints:
        host, port = parse_host_port(endpoint)
        try:
            from .worker_pacing import GARENA_SLOTS, pace
            with GARENA_SLOTS:
                pace('garena_direct', 0.110)
                pace('garena_'+endpoint, 0.380)
                grant, seq_counter = _login_endpoint(host, port, account, password, device_key, connect_timeout, session_timeout, stop, seq_counter, now_fn)
                return grant
        except GarenaAuthError:
            raise
        except Exception as exc:
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    raise RuntimeError('no Garena gateway endpoints configured')


def _login_endpoint(host, port, account, password, device_key, connect_timeout, session_timeout, stop, seq_counter, now_fn):
    with socket.create_connection((host, port), timeout=connect_timeout) as sock:
        deadline = time.monotonic() + session_timeout
        grant, seq_counter = garena_login_on_socket(
            sock, account, password, device_key, deadline=deadline,
            stop=stop, seq_counter=seq_counter, now_fn=now_fn,
        )
        return grant, seq_counter


def exchange_msdk_session(
    garena_token: str,
    garena_open_id: str,
    device_uuid: str,
    *,
    timeout: float = 10.0,
    now_fn=time.time,
    opener=None,
) -> MSDKIdentity:
    """Execute the HTTPS MSDK session exchange."""
    url, headers, body = build_msdk_login_request(
        garena_token,
        garena_open_id,
        device_uuid,
        unix_seconds=int(now_fn()),
    )
    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    open_fn = opener.open if opener is not None else urllib.request.urlopen
    from .worker_pacing import pace
    pace('msdk_http', 0.002)
    with open_fn(req, timeout=timeout) as resp:
        raw = resp.read()
        encoding = (resp.headers.get('Content-Encoding') or '').lower() if hasattr(resp, 'headers') else ''
        if encoding == 'gzip' or raw[:2] == b'\x1f\x8b':
            raw = gzip.decompress(raw)
    return parse_msdk_login_response(raw)
