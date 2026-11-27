"""Strict 1042 decoder matching the existing reconstructed game boundary."""
import struct


def decode_login_limit_evidence(body):
    """Read only the validated prefix; never claim unknown suffix is decoded."""
    if len(body) < 13:
        raise ValueError('truncated_1042')
    code, args, until, size = struct.unpack_from('>IBII', body)
    if args != 0 or not 1 <= size <= 1048576 or 13 + size > len(body):
        raise ValueError('invalid_1042_string')
    text = body[13:13 + size]
    if text[-1] != 0 or b'\0' in text[:-1]:
        raise ValueError('invalid_1042_string')
    return dict(code=code, until=until, reason=text[:-1].decode('utf8'),
                unparsed_tail_bytes=len(body) - 13 - size)


def decode_login_limit(body):
    if len(body) < 13:
        raise ValueError('truncated_1042')
    code, args, until, size = struct.unpack_from('>IBII', body)
    if args != 0:
        raise ValueError('unsupported_1042_arguments')
    if not 1 <= size <= 1048576 or len(body) != 13 + size or body[-1] != 0:
        raise ValueError('invalid_1042_string')
    return dict(code=code, until=until, reason=body[13:-1].decode('utf8'))
