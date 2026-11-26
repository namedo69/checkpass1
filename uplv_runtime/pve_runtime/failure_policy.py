"""Server/auth denials stop this lease; silence is never a missing role."""
import re


def restricted_account(message):
    text = str(message).casefold()
    return ('tài khoản khởi tạo có dấu hiệu bất thường' in text
             or 'tài khoản game bị khóa / hạn chế' in text)


def stop_on_denial(message):
    text = str(message).casefold()
    return (restricted_account(message)
            or bool(re.search(r'server_error_csid_\d+_code_-?\d+', text))
            or any(marker in text for marker in (
                'v2 direct-token', 'terminal_login:', 'terminal_restricted:',
                'v2_create_', 'role_level_not_received_after_create',
                'initial_role_level_not_received', 'oauth', 'captcha',
                'sai mật khẩu', '50004', 'banned', 'bị khóa',
                'giới hạn yêu cầu', 'giới hạn tần suất', '429')))


def terminal_result(row):
    ok, before, after, error = row
    if not ok and stop_on_denial(error):
        # A denial stops this operation, not necessarily the account forever.
        # Reclassify legacy catch-all prefixes too, without retrying the denial.
        text = str(error)
        code = re.search(r'server_error_csid_\d+_code_(-?\d+)', text)
        value = int(code.group(1)) if code else None
        if restricted_account(text) or value == 91126:
            kind = 'restricted'
        elif value == 91117:
            kind = 'session_conflict'
        elif value == 91123:
            kind = 'create_character'
        elif '429' in text or 'giới hạn yêu cầu' in text.casefold() or 'giới hạn tần suất' in text.casefold():
            kind = 'rate_limit'
        elif value is not None:
            kind = 'server_error'
        elif text.startswith('terminal_'):
            return row
        else:
            kind = 'login' if any(t in text.casefold() for t in ('oauth', 'sai mật khẩu', '50004', 'captcha')) else 'server_error'
        text = re.sub(r'^terminal_[a-z_]+:\s*', '', text)
        return False, before, after, 'terminal_' + kind + ': ' + text
    return row
