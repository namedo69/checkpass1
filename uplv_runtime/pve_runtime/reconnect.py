"""Recover the existing battle only; never creates a room or a new match."""
import time

from .loader import load
from .deadlines import session_deadline


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
            elif active:
                notify("Server còn giữ trận cũ; khôi phục relay/kết toán")
                with session_deadline(session, 90, 'Khôi phục / chờ kết toán', notify):
                    load("relay_battle").RelayBattle(session, map_id=20011,
                                                      player_count=10, team=team).run(recover=True)
                row["recovery_returned"] = True
            else:
                row["status"] = "server_no_active_battle"
                notify("Server đã về sảnh; đọc lại profile để kiểm tra thưởng")
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
            row["error"] = str(exc)
            notify(f"Reconnect chưa hoàn tất: {exc}")
        if attempt < attempts and session.stop.wait(2):
            break
    evidence["status"] = "reward_not_confirmed"
    notify(f"[ERROR] Kết thúc reconnect sau {len(evidence['attempts'])}/{attempts} lượt: "
           f"Lv{session.level}, EXP {session.experience}; chưa xác nhận thưởng trận cũ")
    return evidence
