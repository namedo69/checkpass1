"""Receive-only framing reconstructed from static evidence, not live validated."""
from dataclasses import dataclass
from .reader import DecodeError

MAGIC = bytes.fromhex('336600080008')
HEADER_SIZE = 21
MAX_FRAME = 0x1000000


@dataclass(frozen=True)
class Packet:
    kind: int
    direction: int
    sequence: int
    extra: bytes
    payload: bytes


class FrameReader:
    """Single-owner parser, terminal failure on malformed input.

    Deliberately rejects integer-overflow lengths rather than reproducing a
    possible uint32 wrap in the original. Input chunk bounded to 64 KiB.
    """
    def __init__(self):
        self._buffer = bytearray()
        self._failed = False

    @property
    def buffered_bytes(self):
        return len(self._buffer)

    def feed(self, chunk: bytes) -> list[Packet]:
        if self._failed:
            raise DecodeError('parser failed; discard connection')
        if len(chunk) > 65536:
            raise DecodeError('input chunk exceeds limit')
        self._buffer.extend(chunk)
        packets = []
        consumed = 0
        try:
            while len(self._buffer) - consumed >= HEADER_SIZE:
                b = self._buffer
                start = consumed
                if b[start:start + 6] != MAGIC:
                    raise DecodeError('unsupported protocol/version')
                direction = b[start + 8]
                header = int.from_bytes(b[start + 13:start + 17], 'big')
                payload_size = int.from_bytes(b[start + 17:start + 21], 'big')
                total = header + payload_size
                if not HEADER_SIZE <= header <= 65536 or total > MAX_FRAME or direction not in (0, 1):
                    raise DecodeError('invalid packet header')
                if len(b) - start < total:
                    break
                packets.append(Packet(
                    int.from_bytes(b[start + 6:start + 8], 'big'), direction,
                    int.from_bytes(b[start + 9:start + 13], 'big'),
                    bytes(b[start + HEADER_SIZE:start + header]),
                    bytes(b[start + header:start + total]),
                ))
                consumed += total
        except DecodeError:
            self._failed = True
            self._buffer.clear()
            raise
        if consumed:
            del self._buffer[:consumed]
        return packets

    def finish(self):
        if self._failed or self._buffer:
            raise DecodeError('incomplete or failed stream')
