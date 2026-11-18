"""Garena gateway frame layout; no connections or implicit requests."""
from dataclasses import dataclass
from .garena_cipher import GarenaCipher
from .protobuf_wire import decode, uint_field
from .reader import DecodeError

MAX_FRAME = 2**21
MIN_ENC_FRAME = 24


@dataclass(frozen=True)
class GarenaFrame:
    header: tuple
    payload: bytes


def _build_inner(command, payload, *, sequence, unix_seconds):
    header = (uint_field(1, 0x1100011b) + uint_field(2, sequence)
              + uint_field(3, 2) + uint_field(4, command)
              + uint_field(6, unix_seconds))
    return len(header).to_bytes(2, 'big') + header + payload


def build_frame(command, payload, *, sequence, unix_seconds):
    body = _build_inner(command, payload, sequence=sequence, unix_seconds=unix_seconds)
    if len(body) > MAX_FRAME:
        raise ValueError('Garena frame exceeds limit')
    return len(body).to_bytes(4, 'little') + body


def build_encrypted_frame(command, payload, key, *, sequence, unix_seconds):
    inner = _build_inner(command, payload, sequence=sequence, unix_seconds=unix_seconds)
    ciphertext = GarenaCipher(key).encrypt(inner)
    if not MIN_ENC_FRAME <= len(ciphertext) <= MAX_FRAME:
        raise ValueError('invalid encrypted garena frame size')
    return len(ciphertext).to_bytes(4, 'little') + ciphertext


def parse_frame(raw):
    if len(raw) < 6:
        raise DecodeError('truncated Garena frame')
    size = int.from_bytes(raw[:4], 'little')
    if not 2 <= size <= MAX_FRAME or len(raw) != size + 4:
        raise DecodeError('invalid Garena frame size')
    header_size = int.from_bytes(raw[4:6], 'big')
    if header_size > size - 2:
        raise DecodeError('invalid Garena header length')
    end = 6 + header_size
    return GarenaFrame(tuple(decode(raw[6:end])), raw[end:])


def parse_encrypted_frame(raw, key):
    if len(raw) < 4:
        raise DecodeError('truncated Garena frame')
    size = int.from_bytes(raw[:4], 'little')
    if not MIN_ENC_FRAME <= size <= MAX_FRAME or len(raw) != size + 4:
        raise DecodeError('invalid encrypted garena frame size')
    plain = GarenaCipher(key).decrypt(raw[4:])
    if len(plain) < 2:
        raise DecodeError('decrypted payload too short')
    header_size = int.from_bytes(plain[:2], 'big')
    if len(plain) < 2 + header_size:
        raise DecodeError('invalid decrypted header length')
    end = 2 + header_size
    return GarenaFrame(tuple(decode(plain[2:end])), plain[end:])
