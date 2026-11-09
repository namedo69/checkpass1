"""Persist CS wire chunks and decoded response frames for one account run."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()
_seq = 0


def record(kind, data, **metadata):
    folder = os.environ.get('AOV_TRACE_DIR')
    if not folder:
        return None
    global _seq
    with _lock:
        root = Path(folder)
        root.mkdir(parents=True, exist_ok=True)
        _seq += 1
        name = f'{_seq:06d}_{kind}.bin'
        raw = bytes(data)
        (root / name).write_bytes(raw)
        row = dict(time=datetime.now(timezone.utc).isoformat(), kind=kind,
                   file=name, length=len(raw), **metadata)
        with (root / 'frames.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + '\n')
        return name


class TraceSocket:
    def __init__(self, sock, endpoint):
        self.sock = sock
        self.endpoint = str(endpoint)

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def sendall(self, data, *args):
        # A separate kind makes an attempted send distinguishable from a reply.
        record('send_attempt', data, endpoint=self.endpoint)
        return self.sock.sendall(data, *args)

    def recv(self, size, *args):
        data = self.sock.recv(size, *args)
        record('recv_chunk', data, endpoint=self.endpoint, closed=not data)
        return data


def receive_hello(sock):
    """Wait for a complete TConnd hello; TCP recv() is not a frame boundary."""
    from purepc.cs import parse_server_hello
    buf = bytearray()
    while len(buf) < 1024 * 1024:
        data = sock.recv(65536)
        if not data:
            raise ConnectionError('server closed before complete hello')
        buf.extend(data)
        if len(buf) < 21:
            continue
        header_end = int.from_bytes(buf[13:17], 'big')
        body_length = int.from_bytes(buf[17:21], 'big')
        total = header_end + body_length
        if not 21 <= header_end <= total <= 1024 * 1024:
            raise ValueError('invalid server hello frame length')
        if len(buf) < total:
            continue
        command = int.from_bytes(buf[6:8], 'big')
        if command != 0x1002:
            body = bytes(buf[header_end:total])
            record('hello_reject', body, command=command,
                   server_status=int.from_bytes(body[:4], 'big') if len(body) >= 4 else None)
            raise ValueError(f'expected hello 0x1002, received 0x{command:04x}: {body.hex()}')
        result = parse_server_hello(bytes(buf[:total]))
        result['tail'] = bytes(buf[total:])
        return result
    raise ValueError('server hello exceeds capture limit')
