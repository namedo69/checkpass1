"""Offline byte reader. See RECONSTRUCTION.md for provenance and limits."""


class DecodeError(ValueError):
    """Malformed or truncated input; messages never include payload bytes."""


class Reader:
    def __init__(self, data: bytes):
        self._data = bytes(data)
        self.position = 0

    @property
    def remaining(self):
        return len(self._data) - self.position

    def take(self, size: int) -> bytes:
        if size < 0 or size > self.remaining:
            raise DecodeError("invalid or truncated field")
        start = self.position
        self.position += size
        return self._data[start:self.position]

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")

    def moments_string_bytes(self) -> bytes:
        """u32 length includes terminal NUL; return raw bytes, not assumed UTF-8."""
        length = self.u32()
        if not 1 <= length <= 0x100000 or length > self.remaining:
            raise DecodeError("invalid moments string length")
        raw = self.take(length)
        if raw[-1] != 0:
            raise DecodeError("unterminated moments string")
        return raw[:-1]
