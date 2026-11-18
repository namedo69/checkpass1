"""Bounded native socket reads; no endpoint, authentication or game actions."""
import socket
import time


class CancelledError(Exception):
    pass


def read_exact(sock, size, *, deadline, stop, max_bytes=65536):
    """Read size bytes using an absolute monotonic deadline.

    Caller must exclusively own the socket during this call. A failure can
    consume bytes: caller must close the connection, not retry the same read.
    """
    if not isinstance(size, int) or not 0 <= size <= max_bytes:
        raise ValueError("read size outside configured limit")
    old_timeout = sock.gettimeout()
    result = bytearray()
    try:
        while len(result) < size:
            if stop.is_set():
                raise CancelledError("read cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("read deadline exceeded")
            sock.settimeout(min(0.2, remaining))
            try:
                chunk = sock.recv(size - len(result))
            except socket.timeout:
                continue
            if not chunk:
                raise EOFError("connection closed before field completed")
            result.extend(chunk)
        return bytes(result)
    finally:
        sock.settimeout(old_timeout)
