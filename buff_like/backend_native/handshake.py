"""Static reconstruction of lobby hello packets; no network side effects."""
from .framing import Packet
from .reader import DecodeError

# BuildClientHello slice descriptors at 0x14075be70 and 0x14075be90.
HELLO_PREFIX = bytes.fromhex('02030000271000000065803103')
HELLO_SUFFIX = bytes.fromhex('000000000000000000000300000000')


def build_client_hello(uid: int) -> Packet:
    if type(uid) is not int or not 0 <= uid <= 0xffffffffffffffff:
        raise ValueError('UID must be uint64')
    identity = str(uid).encode('ascii') + b'\x00'
    extra = HELLO_PREFIX + len(identity).to_bytes(4, 'big') + identity + HELLO_SUFFIX
    return Packet(0x1001, 0, 1, extra, b'')


def read_server_hello_key(packet: Packet) -> bytes:
    if (packet.kind, packet.direction, packet.sequence) != (0x1002, 1, 1):
        raise DecodeError('unexpected server hello')
    if len(packet.extra) < 18 or packet.extra[:2] != b'\x02\x10':
        raise DecodeError('unsupported key negotiation')
    if len(packet.payload) != 16:
        raise DecodeError('unexpected hello challenge size')
    return bytes(packet.extra[2:18])
