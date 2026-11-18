"""Garena legacy XTEA framing reconstructed from static assembly.

Not authenticated encryption. Decryption deliberately rejects malformed padding
where the original can return unstripped data. Trailer checksum is not verified.
"""
import secrets
import struct
from .reader import DecodeError

MASK = 0xffffffff
DELTA = 0x9e3779b9


def _block(block, key, decrypt=False):
    a, b = struct.unpack('<II', block)
    words = struct.unpack('<4I', key)
    total = (DELTA * 32) & MASK if decrypt else 0
    for _ in range(32):
        if decrypt:
            b = (b - ((((a << 4) ^ (a >> 5)) + a) ^ (total + words[(total >> 11) & 3]))) & MASK
            total = (total - DELTA) & MASK
            a = (a - ((((b << 4) ^ (b >> 5)) + b) ^ (total + words[total & 3]))) & MASK
        else:
            a = (a + ((((b << 4) ^ (b >> 5)) + b) ^ (total + words[total & 3]))) & MASK
            total = (total + DELTA) & MASK
            b = (b + ((((a << 4) ^ (a >> 5)) + a) ^ (total + words[(total >> 11) & 3]))) & MASK
    return struct.pack('<II', a, b)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class GarenaCipher:
    def __init__(self, key):
        if not isinstance(key, bytes) or len(key) != 16:
            raise ValueError('expected 16-byte Garena session key')
        self._key = key

    def encrypt(self, plaintext):
        padding = 8 - len(plaintext) % 8
        padded = plaintext + bytes([padding]) * padding
        seed = secrets.token_bytes(8)
        previous = _block(seed, self._key)
        checksum = int.from_bytes(seed, 'little')
        result = bytearray(previous)
        for offset in range(0, len(padded), 8):
            block = padded[offset:offset + 8]
            checksum = (checksum + int.from_bytes(block, 'little')) & 0xffffffffffffffff
            previous = _block(_xor(block, previous), self._key)
            result.extend(previous)
        result.extend(_block(_xor(previous, checksum.to_bytes(8, 'little')), self._key))
        return bytes(result)

    def decrypt(self, ciphertext):
        if len(ciphertext) < 24 or len(ciphertext) % 8:
            raise DecodeError('invalid Garena ciphertext length')
        result = bytearray()
        for offset in range(8, len(ciphertext) - 8, 8):
            result.extend(_xor(_block(ciphertext[offset:offset + 8], self._key, True),
                               ciphertext[offset - 8:offset]))
        padding = result[-1]
        if not 1 <= padding <= 8 or result[-padding:] != bytes([padding]) * padding:
            raise DecodeError('invalid Garena cipher padding')
        return bytes(result[:-padding])
