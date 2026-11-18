"""Bounded protobuf wire primitives for authentication messages, no schema guesses."""
import struct
from dataclasses import dataclass
from .reader import DecodeError, Reader


def varint(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('expected uint64')
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _read_varint(reader):
    result = 0
    for index in range(10):
        byte = reader.take(1)[0]
        if index == 9 and byte > 1:
            raise DecodeError('protobuf varint overflow')
        result |= (byte & 127) << (index * 7)
        if not byte & 128:
            return result
    raise DecodeError('unterminated protobuf varint')


def _tag(number, wire):
    if type(number) is not int or not 1 <= number < 2**29:
        raise ValueError('invalid protobuf field number')
    return varint(number << 3 | wire)


def uint_field(number, value):
    return _tag(number, 0) + varint(value)


def bytes_field(number, value):
    if not isinstance(value, bytes):
        raise TypeError('field must be bytes')
    return _tag(number, 2) + varint(len(value)) + value


@dataclass(frozen=True)
class Field:
    number: int
    wire: int
    value: int | bytes


def decode(data, *, max_bytes=2**21, max_fields=4096):
    """Preserve order and duplicates; reject groups and malformed wire types."""
    if len(data) > max_bytes:
        raise DecodeError('protobuf message exceeds limit')
    reader = Reader(data)
    fields = []
    while reader.remaining:
        if len(fields) >= max_fields:
            raise DecodeError('protobuf field count exceeds limit')
        tag = _read_varint(reader)
        number, wire = tag >> 3, tag & 7
        if not 1 <= number < 2**29:
            raise DecodeError('invalid protobuf field number')
        if wire == 0:
            value = _read_varint(reader)
        elif wire == 1:
            value = struct.unpack('<Q', reader.take(8))[0]
        elif wire == 2:
            value = reader.take(_read_varint(reader))
        elif wire == 5:
            value = struct.unpack('<I', reader.take(4))[0]
        else:
            raise DecodeError('unsupported protobuf wire type')
        fields.append(Field(number, wire, value))
    return fields
