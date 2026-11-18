"""Legacy lobby wire compatibility, not a recommended new encryption design.

Uses a negotiated per-session key. CBC/footer provides no authentication.
"""
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .reader import DecodeError

IV = bytes(range(16))
FOOTER = b'tsf4g'


class LobbyCipher:
    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != 16:
            raise ValueError('expected 16-byte negotiated key')
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        padding = 16 - len(plaintext) % 16
        if padding < 6:
            padding += 16
        padded = plaintext + secrets.token_bytes(padding - 6) + FOOTER + bytes([padding])
        enc = Cipher(algorithms.AES(self._key), modes.CBC(IV)).encryptor()
        return enc.update(padded) + enc.finalize()

    def decrypt(self, ciphertext: bytes) -> bytes:
        if not ciphertext or len(ciphertext) % 16:
            raise DecodeError('invalid encrypted block length')
        dec = Cipher(algorithms.AES(self._key), modes.CBC(IV)).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        padding = padded[-1]
        if not 6 <= padding <= 21 or padding > len(padded):
            raise DecodeError('invalid lobby cipher padding length')
        if padded[-6:-1] != FOOTER:
            raise DecodeError('invalid lobby cipher footer')
        return padded[:-padding]
