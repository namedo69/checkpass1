"""Reconstructed gateway prepare body, without endpoint or login side effects."""
import re
from .garena_cipher import GarenaCipher
from .protobuf_wire import bytes_field, uint_field


def account_type(account):
    if '@' in account:
        return 2
    if re.fullmatch(r'[+-]?[0-9]+', account):
        number = int(account)
        if -(2**63) <= number < 2**63:
            return 3
    return 1


def build_prepare(account: str, temporary_key: bytes) -> bytes:
    cipher = GarenaCipher(temporary_key)
    inner = (uint_field(1, 0) + uint_field(2, account_type(account))
             + bytes_field(3, account.encode('utf-8')) + uint_field(4, 0x1100)
             + uint_field(5, 0x11b))
    return bytes_field(1, temporary_key) + bytes_field(2, cipher.encrypt(inner))
