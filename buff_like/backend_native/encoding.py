"""Standard-frame serialization; caller separately owns all network actions."""
import struct
from .framing import HEADER_SIZE, MAGIC, MAX_FRAME, Packet


def encode_packet(packet: Packet) -> bytes:
    for value, maximum in ((packet.kind, 0xffff), (packet.direction, 1),
                           (packet.sequence, 0xffffffff)):
        if type(value) is not int or not 0 <= value <= maximum:
            raise ValueError('packet field outside supported range')
    if not isinstance(packet.extra, bytes) or not isinstance(packet.payload, bytes):
        raise TypeError('packet contents must be immutable bytes')
    header = HEADER_SIZE + len(packet.extra)
    if header > 65536 or header + len(packet.payload) > MAX_FRAME:
        raise ValueError('packet exceeds frame limits')
    return (MAGIC + struct.pack('>HBIII', packet.kind, packet.direction,
                              packet.sequence, header, len(packet.payload))
            + packet.extra + packet.payload)
