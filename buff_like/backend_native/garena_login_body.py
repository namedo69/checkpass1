"""Garena login body and OAuth token payload assembly; no sockets or implicit retries."""
from dataclasses import dataclass
from .garena_cipher import GarenaCipher
from .garena_login_key import derive_login_key
from .protobuf_wire import bytes_field, decode, uint_field
from .reader import DecodeError

CMD_LOGIN_PREPARE = 0x100
CMD_LOGIN_BODY = 0x101
CMD_OAUTH_TOKEN = 0x1B7
GARENA_APP_ID = 0x186D6


@dataclass(frozen=True)
class PrepareSalts:
    salt1: str
    salt2: str


@dataclass(frozen=True)
class OAuthGrant:
    access_token: str
    open_id: str


def _field_map(fields):
    ints = {}
    blobs = {}
    for field in fields:
        if field.wire == 0:
            ints[field.number] = field.value
        elif field.wire == 2:
            blobs[field.number] = field.value
    return ints, blobs


def parse_login_prepare_payload(payload):
    _, outer = _field_map(decode(payload))
    server_key = outer.get(1, b'')
    ciphertext = outer.get(2, b'')
    if not server_key or not ciphertext:
        raise DecodeError('missing prepare key or ciphertext')
    _, inner = _field_map(decode(GarenaCipher(server_key).decrypt(ciphertext)))
    salt1 = inner.get(1, b'').decode('utf-8')
    salt2 = inner.get(2, b'').decode('utf-8')
    return PrepareSalts(salt1=salt1, salt2=salt2)


def build_login_body(password, salt1, salt2, device_key):
    if len(device_key) != 16:
        raise ValueError('device_key must be 16 bytes')
    s1 = salt1.encode('utf-8') if isinstance(salt1, str) else bytes(salt1)
    s2 = salt2.encode('utf-8') if isinstance(salt2, str) else bytes(salt2)
    key, password_digest = derive_login_key(password, s1, s2)
    nested = uint_field(2, 0x1200)
    inner = (bytes_field(1, password_digest)
             + uint_field(2, 0)
             + bytes_field(3, nested)
             + bytes_field(4, bytes(device_key)))
    ciphertext = GarenaCipher(key).encrypt(inner)
    return bytes_field(1, ciphertext), key


def parse_login_body_payload(payload, login_key):
    _, outer = _field_map(decode(payload))
    ciphertext = outer.get(1, b'')
    if not ciphertext:
        raise DecodeError('missing login response ciphertext')
    _, inner = _field_map(decode(GarenaCipher(login_key).decrypt(ciphertext)))
    session_key = inner.get(2, b'')
    if len(session_key) != 16:
        raise DecodeError('invalid Garena session encryption key length')
    return session_key


def build_oauth_request_payload():
    return (uint_field(1, GARENA_APP_ID)
            + bytes_field(2, b'')
            + uint_field(3, 2)
            + bytes_field(4, b'')
            + uint_field(5, 0)
            + uint_field(6, 0x11))


def parse_oauth_response_payload(header_fields, payload):
    header_ints, _ = _field_map(header_fields)
    if header_ints.get(4) != CMD_OAUTH_TOKEN:
        raise DecodeError('unexpected OAuth response command')
    _, body_blobs = _field_map(decode(payload))
    err_bytes = body_blobs.get(5, b'')
    if err_bytes:
        err_text = err_bytes.decode('utf-8', 'replace')
        rc = header_ints.get(5, 0)
        raise DecodeError(f'Garena OAuth error: {err_text} (rc={rc})')
    if header_ints.get(5, 0) != 0:
        raise DecodeError(f'Garena OAuth token rejected (rc={header_ints.get(5, 0)})')
    access_token = body_blobs.get(1, b'').decode('utf-8').strip()
    open_id = body_blobs.get(4, b'').decode('utf-8').strip()
    if not access_token or not open_id:
        raise DecodeError('missing OAuth access_token or open_id')
    return OAuthGrant(access_token=access_token, open_id=open_id)
