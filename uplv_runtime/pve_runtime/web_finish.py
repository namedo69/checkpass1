"""Exit vendor reward-wait only AFTER its WIN send returned successfully."""
import time


class OutcomeSent(BaseException):
    """Control-flow sentinel, deliberately bypasses vendor recovery handlers."""


def outcome_sent_status(text, mode):
    # relay_battle.run calls this status immediately AFTER relay.send_game(1080)
    # returns. Do not use the earlier outcome_report_sent profile notification.
    return mode == 'victory' and text.startswith('Cả đội gửi ') and 'chờ server xác nhận và đọc Exp' in text


def idle_on_current_session(session, stop, budget=12):
    """No reconnect/profile login. Silence is never treated as server-idle."""
    deadline = time.monotonic() + budget
    session.send_game(1060, b'\0')
    while time.monotonic() < deadline and not stop.is_set():
        try:
            msg, body, _ = session.receive_game(deadline)
        except TimeoutError:
            return False
        if msg == 1061:
            return body == b'\0'
    return False
