"""Single-owner receive pipeline; no game endpoint or authentication."""
from collections import deque
import socket
import time
from .framing import FrameReader
from .transport import CancelledError


class Receiver:
    def __init__(self, sock):
        self.sock = sock
        self.frames = FrameReader()
        self.pending = deque()
        self.failed = False

    def receive(self, *, deadline, stop):
        """Return one frame, retaining complete trailing frames for later calls.

        A deadline timeout preserves the connection and buffered partial frame.
        Other failures are terminal. Caller owns closing socket.
        Not thread-safe; only one owner may access receiver and socket.
        """
        if self.failed:
            raise RuntimeError('receiver failed; discard connection')
        old_timeout = self.sock.gettimeout()
        try:
            while True:
                if stop.is_set():
                    raise CancelledError('receive cancelled')
                if self.pending:
                    return self.pending.popleft()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('receive deadline exceeded')
                self.sock.settimeout(min(0.2, remaining))
                try:
                    chunk = self.sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    self.frames.finish()
                    raise EOFError('connection closed')
                self.pending.extend(self.frames.feed(chunk))
        except TimeoutError:
            raise
        except Exception:
            self.failed = True
            self.pending.clear()
            raise
        finally:
            self.sock.settimeout(old_timeout)
