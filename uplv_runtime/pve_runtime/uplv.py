"""Five-account PvE orchestration with server profile readback."""
from concurrent.futures import ThreadPoolExecutor, as_completed

from .loader import load
from .modes import configure_match
from .reconnect import recover_battle
from .deadlines import session_deadline
from .regroup import inspect_for_regroup, REGROUP, UNRESOLVED


def run_five_batch(accounts, target, concurrency, stop, prepare, authenticate, progress,
                   max_rounds=100, mode="surrender", prepare_cards=False, checkpoint_store=None,
                   completed=None, allow_regroup=False, require_idle=(), web_verify=None, targets=None):
    """Return index -> (ok, initial level, latest confirmed level, error).

    Completed accounts may support the last incomplete team. Every live session
    belongs to only one team at a time; no worker waits for queued teammates.
    """
    results = {}
    sessions = {}
    initial = {}
    progress_evidence = {}
    session_uids = {}
    web_clients = {}
    def goal(index):
        return targets[index] if targets else target
    if prepare_cards:
        from .rewards import install_resource_decoder
        install_resource_decoder()
    session_type = load("lever_session").LeverSession
    match_type = load("five_runtime").FiveMatch

    def open_session(index):
        user, password = accounts[index]
        try:
            ok, before, after, error = prepare(index, user, password)
        except Exception as exc:
            results[index] = (False, 0, 0, str(exc))
            if completed:
                completed(index, results[index])
            return
        initial[index] = before
        # Preparation may have replaced this slot. Never authenticate the old
        # occupant using the credentials captured before the replacement.
        user, password = accounts[index]
        results[index] = (False, before, after, error)
        if ok and after >= goal(index):
            results[index] = (True, before, after, "")
            progress(index, f"[LEVEL] Lv{after}")
            progress(index, "[ALREADY_DONE] Đã đạt mục tiêu; bỏ qua các stack còn lại")
            if completed:
                completed(index, results[index])
            return
        if not ok or stop.is_set():
            if ok:
                results[index] = (False, before, after, "Đã dừng")
            if completed:
                completed(index, results[index])
            return

        last_timer = -1
        def notify(kind, **fields):
            nonlocal last_timer
            if kind == "status" and fields.get("text"):
                progress(index, fields["text"])
                if web_verify is not None:
                    from .web_finish import OutcomeSent, outcome_sent_status
                    if outcome_sent_status(fields['text'], mode):
                        raise OutcomeSent()
            elif kind == "profile" and type(fields.get("level")) is int:
                progress(index, f"5v5: Cấp {fields['level']} / {target}")
            elif kind == "level" and type(fields.get("level")) is int:
                progress(index, f"[LEVEL] Lv{fields['level']} EXP {fields.get('experience', 0)}")
            elif kind == "battle_progress":
                seconds = int(fields.get('elapsed_seconds', 0))
                if seconds != last_timer:
                    last_timer = seconds
                    progress(index, f"[TIMER] {seconds}")

        session = session_type(stop, notify=notify)
        try:
            progress(index, "Đang mở phiên 5v5 PvE...")
            bundle = authenticate(user, password)
            if web_verify is not None:
                web_clients[index] = web_verify(bundle, stop)
            session.authenticate_garena_session(bundle.access_token, bundle.open_id)
            session.planned_name = user
            session.request_battle_mode = "5vs5"
            session.strict_ai_map = 20011
            session.strict_ai_five = True
            session.request_outcome_mode = mode if mode in ("victory", "defeat") else "off"
            session.connect()
            if checkpoint_store is not None:
                # Attach after initial auth/login so only reward decisions
                # are restored, not an old login identity/device binding.
                session.login_profile = checkpoint_store.load(user)
                session.progress_store = checkpoint_store
                session.progress_username = user
            if type(session.level) is not int or session.level < 5:
                raise RuntimeError("Chưa xác nhận nhân vật đạt Lv5 trong phiên 5v5")
            progress(index, f"[LEVEL] Lv{session.level} EXP {session.experience}")
            if session.level >= goal(index):
                results[index] = (True, before, session.level, "")
                progress(index, "[ALREADY_DONE] Server xác nhận đã đạt mục tiêu")
                session.close()
                if completed:
                    completed(index, results[index])
                return
            if index in require_idle:
                progress(index, '[REGROUP_CHECK] Kiểm tra rõ trạng thái trận cũ trước khi vào đội')
                status = inspect_for_regroup(session, session.character_uid, goal(index),
                                            lambda msg: progress(index, msg))
                if status != REGROUP:
                    results[index] = (status == 'done', before, session.level,
                                      '' if status == 'done' else UNRESOLVED)
                    session.close()
                    if status == 'done' and completed:
                        completed(index, results[index])
                    return
            if session.level < goal(index) and prepare_cards:
                from .rewards import prepare_optional
                from .tutorial import wait_lobby_or_rescue
                progress(index, "[STACK2] Nhận quà tân thủ / thẻ EXP")
                wait_lobby_or_rescue(session, lambda msg: progress(index,msg), 'STACK2')
                # Missing ruby/cards or rejected purchase/use must not reject
                # an otherwise valid Lv5+ account or skip the other card type.
                try:
                    with session_deadline(session, 85, 'Thử thẻ EXP', lambda msg: progress(index, msg)):
                        prepare_optional(session, lambda msg: progress(index, msg))
                except Exception:
                    session.check_stop()
                    progress(index, '[EXP_OPTIONAL] Bước thẻ EXP chưa hoàn tất; mở lại phiên và tiếp tục')
                uid = session.character_uid
                session.connect()
                wait_lobby_or_rescue(session, lambda msg: progress(index,msg), 'STACK2')
                if session.character_uid != uid:
                    raise RuntimeError("UID thay đổi khi kiểm tra buff")
                day = session.reward_state.exp_active() is True
                wins = session.reward_state.win_exp_active() is True
                progress(index, f"[BUFF] Ngày: {'ON' if day else 'chưa xác nhận'} | Trận thắng: {'ON' if wins else 'chưa xác nhận'}")
                if not (day and wins):
                    progress(index, '[EXP_OPTIONAL] Thiếu buff EXP; vẫn tiếp tục vào trận')
            progress(index, "[STACK2_DONE] Hoàn tất chuẩn bị")
            sessions[index] = session
            session_uids[index] = session.character_uid
            results[index] = (session.level >= goal(index), before, session.level, "")
            progress_evidence[index] = (session.level, session.experience)
        except Exception as exc:
            session.close()
            results[index] = (False, before, after, str(exc))
            progress(index, f"[ERROR] Chuẩn bị thất bại: {exc}")
            from .failure_policy import restricted_account
            if restricted_account(exc):
                results[index] = (False, before, max(after, getattr(session, 'level', 0) or 0),
                                  'terminal_restricted: ' + str(exc))
                if completed:
                    completed(index, results[index])
                return
            if allow_regroup and not stop.is_set():
                results[index] = (False, before, max(after, getattr(session, 'level', 0) or 0),
                                  UNRESOLVED + ': ' + str(exc))
                progress(index, '[REGROUP] Lỗi phiên chuẩn bị; chờ kiểm tra lại từ pool chung')
            elif completed:
                if targets and after >= 5:
                    results[index] = (False, before, after, 'pool_verifying')
                completed(index, results[index])

    try:
        if len(accounts) < 5 or len({u.casefold() for u, _ in accounts}) != len(accounts):
            raise ValueError("5v5 cần ít nhất 5 tài khoản khác nhau")
        with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
            futures = [executor.submit(open_session, i) for i in range(len(accounts))]
            for future in as_completed(futures):
                future.result()
        if len(sessions) < 5:
            for i, session in sessions.items():
                if not results[i][0]:
                    if targets:
                        from .web_finish import idle_on_current_session
                        try:
                            idle = idle_on_current_session(session, stop)
                        except Exception:
                            idle = False
                        results[i] = (False, initial[i], session.level, 'pool_ready' if idle else 'pool_verifying')
                        progress(i, '[POOL_READY] Đội thiếu người; trả acc rảnh về pool' if idle else '[VERIFYING] Đội thiếu người; chờ đối soát phiên')
                        if completed:
                            completed(i, results[i])
                        continue
                    results[i] = (False, initial[i], session.level,
                                  REGROUP if allow_regroup else f"Không đủ 5 phiên hợp lệ để lập đội ({len(sessions)}/5)")
                    progress(i, f"[ERROR] Không đủ đội ({len(sessions)}/5); dừng phòng")
                    if completed and not allow_regroup:
                        completed(i, results[i])
            return results

        stalled = 0
        for round_no in range(1, max_rounds + 1):
            pending = [i for i in sessions if not results[i][0]]
            if not pending or stop.is_set():
                break
            for i in pending:
                progress(i, f"[STACK3] Trận {round_no} / mục tiêu Lv{target}")
            team = pending[:5]
            team += [i for i in sessions if i not in team][:5 - len(team)]
            match = match_type([{"session": sessions[i]} for i in team],
                               team_size=5, map_id=20011)
            configure_match(match, mode)
            round_errors = {}

            def play(index):
                session = sessions[index]
                previous = progress_evidence[index]
                uid = session.character_uid
                recovered_reward = False
                session.last_settlement = None
                try:
                    from .tutorial import wait_lobby_or_rescue
                    wait_lobby_or_rescue(session, lambda msg: progress(index,msg), 'STACK3')
                    progress(index, f"5v5 PvE: trận {round_no}, đủ 5 tài khoản")
                    if web_verify is not None:
                        from .web_finish import OutcomeSent, idle_on_current_session
                        try:
                            with session_deadline(session, 720, '5v5 WIN', lambda msg: progress(index, msg)):
                                match.play(session)
                        except OutcomeSent:
                            progress(index, '[STACK4] Kiện Tướng: xác minh cấp, không login game lại')
                        else:
                            # A normal return is not evidence that the WIN send
                            # completed; only the post-send sentinel authorizes
                            # web verification of this round.
                            results[index] = (False, initial[index], previous[0], 'pool_verifying')
                            progress(index, '[VERIFYING] Chưa có bằng chứng gửi WIN thành công')
                            if completed:
                                completed(index, results[index])
                            return False
                        progress(index, '[VERIFYING] Đọc cấp Kiện Tướng')
                        level = web_clients[index].verify(previous[0], goal(index))
                        if level is None:
                            progress(index, '[VERIFYING] Kiện Tướng: ' + str(getattr(web_clients[index], 'last_error', '') or 'chưa đọc được cấp hợp lệ'))
                        idle = False
                        if level is not None:
                            progress(index, f'[LEVEL] Lv{level}')
                            try:
                                idle = idle_on_current_session(session, stop)
                            except Exception:
                                idle = False
                        ok = level is not None and level >= goal(index)
                        after = level if level is not None else previous[0]
                        marker = 'pool_ready' if level is not None and level > previous[0] and idle else 'pool_verifying'
                        results[index] = (ok, initial[index], after, '' if ok else marker)
                        progress(index, '[STACK4_DONE] Kiện Tướng xác nhận đạt mục tiêu' if ok else '[POOL_READY] Chờ up tiếp' if marker == 'pool_ready' else '[VERIFYING] Chờ xác minh/trận cũ')
                        if completed:
                            completed(index, results[index])
                        return False
                    try:
                        with session_deadline(session, 720, '5v5 / kết toán',
                                              lambda msg: progress(index, msg)):
                            match.play(session)
                    except Exception:
                        recovered = recover_battle(
                            session, dict(uid=uid, level=previous[0], exp=previous[1]),
                            lambda msg: progress(index, msg), team=match)
                        if not recovered["reward_confirmed"]:
                            raise RuntimeError("Reconnect trận cũ chưa xác nhận nhận thưởng")
                        recovered_reward = True
                    settlement = session.last_settlement
                    if (settlement is None or settlement.map_id != 20011) and not recovered_reward:
                        raise RuntimeError("Chưa nhận kết toán 5v5 từ server")
                    # A settlement alone is not proof the profile was saved.
                    progress(index, '[STACK4] Đăng nhập lại / đối chiếu cấp (tối đa 35s)')
                    with session_deadline(session, 35, 'Xác minh profile sau trận',
                                          lambda msg: progress(index, msg)):
                        session.connect()
                    # Fresh 1003 already binds UID/level to persisted server
                    # data. The vendor helper can wait for an old battle status
                    # even after a valid settlement; query only on recovery.
                    current = (session.level, session.experience)
                    if (type(current[0]) is not int or type(current[1]) is not int
                            or session.character_uid != uid):
                        raise RuntimeError("Thiếu snapshot nhân vật sau trận")
                    progress_evidence[index] = current
                    progress(index, f"[LEVEL] Lv{current[0]} EXP {current[1]}")
                    progress(index, f"[ROUND_DONE] {round_no}")
                    results[index] = (current[0] >= goal(index), initial[index], current[0], "")
                    if current[0] >= goal(index):
                        progress(index, "[STACK4_DONE] Đăng nhập lại xác nhận đạt mục tiêu")
                        if completed:
                            completed(index, results[index])
                    elif targets:
                        from .web_finish import idle_on_current_session
                        idle = idle_on_current_session(session, stop)
                        results[index] = (False, initial[index], current[0],
                                          'pool_ready' if idle else 'pool_verifying')
                    return current > previous
                except Exception as exc:
                    round_errors[index] = str(exc) or type(exc).__name__
                    progress(index, f'[ERROR] Trận {round_no} kết thúc lỗi: {round_errors[index]}; đóng phiên, không chờ thêm')
                    session.close()
                    if not results[index][0]:
                        results[index] = (False, initial[index], results[index][2],
                                          'pool_verifying' if web_verify is not None or targets else str(exc))
                        if completed and not allow_regroup:
                            completed(index, results[index])
                    return False

            with ThreadPoolExecutor(max_workers=5) as executor:
                changed = list(executor.map(play, team))
            if web_verify is not None or (targets and any(r[0] for r in results.values())):
                break  # Close this temporary team; master owns continuation.
            if targets:
                if round_errors or any(results[i][3] == 'pool_verifying' for i in team):
                    break
                # All five still need levels and are confirmed idle: retain
                # their sessions and keep running rather than reassign stacks.
                for i in team:
                    if results[i][3] == 'pool_ready':
                        results[i] = (False, initial[i], results[i][2], '')
            if round_errors:
                for i in pending:
                    if allow_regroup and not stop.is_set() and not results[i][0]:
                        try:
                            progress(i, '[REGROUP_CHECK] Đội cũ gián đoạn; kiểm tra riêng UID/cấp/trận')
                            status = inspect_for_regroup(sessions[i], session_uids[i], target,
                                                        lambda msg, idx=i: progress(idx, msg))
                            level = sessions[i].level
                            if status == 'done':
                                results[i] = (True, initial[i], level, '')
                                progress(i, '[STACK4_DONE] Đã đạt mục tiêu khi kiểm tra lại')
                                if completed:
                                    completed(i, results[i])
                            elif status == REGROUP:
                                results[i] = (False, initial[i], level, REGROUP)
                                progress(i, '[REGROUP] Server xác nhận rảnh; đưa về hàng chờ bù đội')
                            else:
                                results[i] = (False, initial[i], level, UNRESOLVED)
                                progress(i, '[DEFERRED] Trận cũ chưa rõ/đang giữ; tách khỏi ghép mới')
                        except Exception as exc:
                            results[i] = (False, initial[i], results[i][2], UNRESOLVED + ': ' + str(exc))
                            progress(i, '[DEFERRED] Không xác minh được phiên cũ; lưu Chưa xong')
                    elif not results[i][0] and not results[i][3]:
                        results[i] = (False, initial[i], results[i][2],
                                      "Đội bị gián đoạn; cần mở lại phiên để xác minh và tiếp tục")
                break
            stalled = 0 if any(changed) else stalled + 1
            if stalled >= 3:
                break
        if targets:
            from .web_finish import idle_on_current_session
            for i, session in sessions.items():
                if not results[i][0] and not results[i][3]:
                    try:
                        idle = idle_on_current_session(session, stop)
                    except Exception:
                        idle = False
                    results[i] = (False, initial[i], results[i][2], 'pool_ready' if idle else 'pool_verifying')
        for i in sessions:
            ok, before, after, error = results[i]
            if not ok and not error:
                error = "Đã dừng" if stop.is_set() else "Chưa đạt mục tiêu sau giới hạn trận / EXP chưa tăng"
                results[i] = (False, before, after, error)
        return results
    finally:
        for session in sessions.values():
            session.close()
        for client in web_clients.values():
            client.close()
