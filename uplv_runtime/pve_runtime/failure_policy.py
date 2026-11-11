"""Explicit terminal game restrictions; transport failures stay retryable."""
def restricted_account(message):
    text = str(message).casefold()
    return ('tài khoản khởi tạo có dấu hiệu bất thường' in text
            or 'tài khoản game bị khóa / hạn chế' in text)
