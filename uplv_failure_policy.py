"""Account terminal evidence, distinct from ending a worker's current operation."""
import re


def terminal_account_failure(result):
    """Never trust a worker's catch-all label or a stale historical root cause.

    Only the current denial is evidence. HTTP200/login/absence/timeouts do not
    establish a ban. Registration/name rejection is retryable too.
    """
    text = str(result.get('final_error') or '').casefold()
    code = re.search(r'server_error_csid_\d+_code_(-?\d+)\b', text)
    value = int(code.group(1)) if code else None
    if value == 91126 or any(marker in text for marker in (
            'tài khoản game bị khóa / hạn chế',
            'tài khoản khởi tạo có dấu hiệu bất thường',
            'apk đã chỉnh sửa')):
        return 'restricted'
    return ''
