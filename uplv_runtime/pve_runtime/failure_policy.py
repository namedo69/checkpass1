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
    if not ok and not error.startswith('terminal_') and stop_on_denial(error):
        return False, before, after, 'terminal_restricted: ' + error
    return row
