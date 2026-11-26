"""TLT VN live-session 1002 body; offsets verified against the newer engine.

Garena open_id != MSDK uid != numerical MSDK openid != MSDK token.
This builder never uses a captured account credential or follows a guessed ID.
"""
import base64
import secrets
import struct


LOGIN_TEMPLATE_B64 = (
    'AwAAhwMAAI4AAAAwQW5kcm9pZCBPUyA5IC8gQVBJLTI4IChQUTNBLjE5MDYwNS4wMDMvMzc5MzI2NSkAAAAAEXNhbXN1bmcgU00tRzk2ME4AAAAABU5VTEwAAAAACldpLUZpL0xBTgAAAAAAAAAACTEuNjQuMS43AAAABdUAAAAFMDAwMAAAAAAIMTc2ODU3NwD//////////wAAAAEAAAAACVNNLUc5NjBOAAAAAAtWaWV0bmFtZXNlAAAAAAEAAAAAAQAAAAPAAAACHAAAAA5wbGFjZWhvbGRlciwzAAAAAAMAAAAlOWE3MjFkNmYtY2IxYi00YTRmLTg1YWMtYzU1NDNiOWE3MmI3AAAAAAEAAAAAITE3OTI4Mjg2NjA4OTctMzY0NzQ4MTA5ODM5NzExMzMyAAAACzEAAGwEAABLJAAAgwUAAD7zAAAAAAAAAAAAAAAAAAAD8wEBAAEAAAAwQVBRVC1QQy1SRVFVRVNULUNMSUVOVDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAvwV9QAAAAhMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAAAAAAAAAAAAEAAAAAITAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAAAAAAQAAGvyBAAAAAAEAAAAAAQAAAAAHZ29vZ2xlAAAAABUtNzQ1NTM5ODg5NjIxMjAzMTQwMQAAAAABAAAAAAAAAAABAQAAAAthbmhwaGE1NTYyAA=='
)
LOGIN_TEMPLATE = base64.b64decode(LOGIN_TEMPLATE_B64, validate=True)
NAME_SUFFIX = struct.pack('>I', 11) + b'anhpha5562\0'


def identity32(value, label):
    if not isinstance(value, str):
        raise ValueError(f'V2 {label} must be a 32-byte string')
    raw = value.encode('utf8')
    if len(raw) != 32 or b'\0' in raw:
        raise ValueError(f'V2 {label} must be a 32-byte string')
    return raw


def login_body(garena_open_id, msdk_uid, numerical_openid, name=None, *, template=LOGIN_TEMPLATE):
    body = bytearray(template)
    if len(body) < 0x230 or not body.endswith(NAME_SUFFIX):
        raise ValueError('V2 login template mismatch')
    if type(numerical_openid) is not int or not 0 < numerical_openid < 2**64:
        raise ValueError('V2 numerical MSDK openid invalid')
    body[0x19b:0x1bb] = identity32(garena_open_id, 'Garena open_id')
    body[0x1c9:0x1e9] = identity32(msdk_uid, 'MSDK uid')
    struct.pack_into('>Q', body, 0x228, numerical_openid)
    selected = (name or f'lv{numerical_openid % 100000000:08d}').encode('utf8')
    if b'\0' in selected:
        raise ValueError('V2 planned name contains NUL')
    selected = selected[:63]  # TLT byte cap, not Unicode codepoint count.
    return bytes(body[:-len(NAME_SUFFIX)]) + struct.pack('>I', len(selected) + 1) + selected + b'\0'


def game_ack_packet(seq, c1, csid, body):
    """SendGameAck: raw seq/csid/5510/server-counter/client-counter + body.

    No LZ4, compression flag must be false. TLT randomizes padding before tsf4g.
    seq starts at3 following transport login seq2; client counter starts at1.
    """
    if not 3 <= int(seq) < 2**32 or not 0 <= int(c1) < 2**32:
        raise ValueError('V2 game sequence/counter invalid')
    plain = struct.pack('>IIIII', int(seq), int(csid), 5510, int(c1), int(seq) - 2) + bytes(body)
    padding = 16 - len(plain) % 16
    if padding < 6:
        padding += 16
    return plain + secrets.token_bytes(padding - 6) + b'tsf4g' + bytes([padding])
