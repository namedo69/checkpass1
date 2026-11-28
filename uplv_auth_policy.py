"""Small shared auth-wait policy. Dispatch never sleeps; workers own waits."""
import math
import random


def nonnegative_number(value):
    if type(value) not in (int, float) or value <= 0:
        return 0
    try:
        return value if math.isfinite(value) else 0
    except OverflowError:
        return 0


def auth_delay(kind, attempt):
    """Bounded exponential backoff plus positive jitter, not a server TTL."""
    base, cap = (60, 900) if kind == 'web_denied' else (10, 300)
    attempt = min(16, max(1, int(attempt)))
    delay = min(cap, base * 2 ** (attempt - 1))
    return delay + random.uniform(0, delay * .1)


def clean_auth_wait(value):
    """Only bounded numeric scheduling metadata can cross the control plane."""
    value = value if isinstance(value, dict) else {}
    attempt = value.get('auth_attempt')
    return {'auth_retry_until': nonnegative_number(value.get('auth_retry_until')),
            'auth_attempt': min(1000000, attempt) if type(attempt) is int and attempt > 0 else 0}
