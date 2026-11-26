"""Recover the existing battle only; never creates a room or a new match."""
import time

from .loader import load
from .deadlines import session_deadline
from .failure_policy import stop_on_denial


def recover_battle(session, before, notify=lambda message: None, team=None, attempts=3):
    uid = before["uid"]
    evidence = {"attempts": [], "reward_confirmed": False}
    for attempt in range(1, attempts + 1):
        session.check_stop()
        row = {"attempt": attempt}
        evidence["attempts"].append(row)
        try:
            notify(f"Reconnect trận cũ {attempt}/{attempts}")
            session.close()
            with session_deadline(session, 35, 'Reconnect / đọc profile', notify):
                session.connect()
            if session.character_uid != uid:
                raise ValueError("UID sau reconnect không khớp nhân vật ban đầu")
            row["profile"] = dict(uid=uid, level=session.level, exp=session.experience)
            if (session.level, session.experience) > (before["level"], before["exp"]):
                evidence["reward_confirmed"] = True
                evidence["status"] = "profile_increased"
                return evidence
            load("team_flow").wait_lobby(session, timeout=8, allow_battle=True)
            session.send_game(1060, b"\x00")
            deadline = time.monotonic() + 8
            active = None
            while time.monotonic() < deadline:
                try:
                    msg, body, _ = session.receive_game(deadline)
                except TimeoutError:
                    break
                if msg == 1061 and body in (b"\x00", b"\x01"):
                    active = body == b"\x01"
                    break
            row["active_battle"] = active
            if active is None:
                row["status"] = "battle_state_unknown"
                break  # Silence does not authorize another immediate login.
            elif active:
                notify("Server còn giữ trận cũ; khôi phục relay/kết toán")
                try:
                    with session_deadline(session, 90, 'Khôi phục / chờ kết toán', notify):
                        load("relay_battle").RelayBattle(session, map_id=20011,
                                                          player_count=10, team=team).run(recover=True)
                except ConnectionError as exc:
                    if type(exc).__name__ != 'ProfileReadbackRequired':
                        raise
                    # Normal readback signal: fall through to one UID-bound
                    # reward read, rather than retrying active relay recovery.
                    row['profile_readback_required'] = True
                row["recovery_returned"] = True
            else:
                row["status"] = "server_no_active_battle"
                # This connection already supplied a fresh UID-bound profile.
                # Unchanged EXP + idle is unresolved reward, not permission for
                # another login loop or another match.
                notify("Server đã về sảnh; profile mới chưa tăng EXP, giữ đối soát, không đăng nhập dồn")
                break
            session.close()
            with session_deadline(session, 35, 'Đọc lại phần thưởng', notify):
                session.connect()
            if session.character_uid != uid:
                raise ValueError("UID kiểm tra thưởng không khớp")
            row["after"] = dict(uid=uid, level=session.level, exp=session.experience)
            if (session.level, session.experience) > (before["level"], before["exp"]):
                evidence["reward_confirmed"] = True
                evidence["status"] = "profile_increased"
                return evidence
        except ValueError:
            raise
        except Exception as exc:
            if stop_on_denial(exc):
                raise
            row["error"] = str(exc) or type(exc).__name__
            notify(f"Reconnect chưa hoàn tất: {row['error']}")
        if attempt < attempts and session.stop.wait(2):
            break
    evidence["status"] = "reward_not_confirmed"
    notify(f"[ERROR] Kết thúc reconnect sau {len(evidence['attempts'])}/{attempts} lượt: "
           f"Lv{session.level}, EXP {session.experience}; chưa xác nhận thưởng trận cũ")
    return evidence
