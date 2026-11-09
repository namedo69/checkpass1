"""Cooperative session deadline plus socket interruption on blocked I/O.

No detached task is launched: operation stays on its owning thread. Timer
closes current TCP socket; receive/check_stop wrappers bound packet loops.
"""
from contextlib import contextmanager
import socket
import threading
import time


@contextmanager
def session_deadline(session, seconds, label, notify=lambda message: None):
    deadline = time.monotonic() + seconds
    expired = threading.Event()
    saved = {name: session.__dict__.get(name) for name in ('check_stop', 'receive_game', 'receive_packet')}
    owned = {name: name in session.__dict__ for name in saved}
    original_check = session.check_stop

    def guard():
        original_check()
        if expired.is_set() or time.monotonic() >= deadline:
            raise TimeoutError(f'{label}: quá {seconds:g}s, đã dừng phiên để kiểm tra lại')

    def interrupt():
        expired.set()
        notify(f'[TIMEOUT] {label}: quá {seconds:g}s; ngắt socket đang chờ')
        sock = getattr(session, 'sock', None)
        if sock is not None:
            try:
                shutdown = getattr(sock, 'shutdown', None)
                if callable(shutdown):
                    shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    wrappers = {}
    for name in ('receive_game', 'receive_packet'):
        original = getattr(session, name, None)
        if callable(original):
            def receive(until, *args, _original=original, **kwargs):
                guard()
                value = _original(min(until, deadline), *args, **kwargs)
                guard()
                return value
            wrappers[name] = receive
    session.check_stop = guard
    for name, wrapped in wrappers.items():
        setattr(session, name, wrapped)
    timer = threading.Timer(seconds, interrupt)
    timer.daemon = True
    timer.start()
    try:
        guard()
        yield
        guard()
    finally:
        timer.cancel()
        timer.join()
        for name in ('check_stop', *wrappers):
            if owned[name]:
                setattr(session, name, saved[name])
            else:
                session.__dict__.pop(name, None)
