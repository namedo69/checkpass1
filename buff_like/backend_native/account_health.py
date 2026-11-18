"""Conservative classification: never guess the meaning of numeric auth codes."""
import json
import os
import re
from .reader import DecodeError


class AccountAuthError(DecodeError):
    def __init__(self, stage, code, message=''):
        self.stage = stage
        self.code = int(code)
        self.server_message = message
        super().__init__(f'{stage} rejected login (code={code}, msg={message})')


def restriction_reason(exc):
    if not isinstance(exc, AccountAuthError):
        return None
    # Only examine an explicit server message, never arbitrary exception text.
    message = exc.server_message.strip().lower()
    if re.search(r'\b(?:account|user|tài khoản)\s+(?:(?:has been|is|was|đã|bị)\s+)*(?:banned|suspended|locked|khóa)\b', message) or message in ('account_banned', 'account_locked', 'account_suspended'):
        return f'{exc.stage}:account_restricted:{exc.code}'
    # Optional deployment-specific codes must be independently verified first.
    try:
        codes = json.loads(os.environ.get('AUTOBUFF_RESTRICTED_AUTH_CODES', '{}'))
        if exc.code in codes.get(exc.stage, []):
            return f'{exc.stage}:account_restricted:{exc.code}'
    except (ValueError, TypeError, AttributeError):
        pass
    return None
