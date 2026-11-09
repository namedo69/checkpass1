"""Bounded stage-1 retry, rereading server role/level each attempt."""
import secrets


def new_character_name():
    # Short ASCII name, independently generated from the login username.
    return 'A' + secrets.token_hex(5)


def prepare_with_retry(execute, account, password, target, stop, progress,
                       *, debug=None, attempts=3):
    first_before = None
    latest = (False, 0, 0, 'Chưa thực hiện')
    character_name = None
    for attempt in range(1, attempts + 1):
        if stop.is_set():
            return False, first_before or 0, latest[2], 'Đã dừng'
        progress(f'[STACK1] Đăng nhập / đọc lại cấp ({attempt}/{attempts})')
        try:
            options = dict(target_level=target, progress_cb=progress, debug_log=debug)
            if character_name is not None:
                options['character_name'] = character_name
            latest = execute(account, password, **options)
        except Exception as exc:
            latest = (False, 0, latest[2], str(exc))
        ok, before, after, error = latest
        if first_before is None and before:
            first_before = before
        if ok and after >= target:
            return True, first_before or before, after, ''
        lower = error.lower()
        if any(code in lower for code in ('_code_91103', '_code_91123')):
            character_name = new_character_name()
            progress(f'[RETRY_NAME] Server từ chối tên ({error}); thử tên ngắn {character_name} sau khi đăng nhập lại')
        if any(word in lower for word in ('sai mật khẩu', 'bị khóa', 'banned', 'captcha')):
            break
        if attempt < attempts:
            progress(f'[RETRY] Stack1: {error}. Đăng nhập lại kiểm tra role/cấp ({attempt + 1}/{attempts})')
            if stop.wait(2):
                return False, first_before or before, after, 'Đã dừng'
    return False, first_before or latest[1], latest[2], f'Stack1 dừng sau {attempt} lượt: {latest[3]}'
