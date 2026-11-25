"""Bounded Kiện Tướng code grant; game tokens are not web sessions."""
import time
import urllib.parse
import urllib.request

CALLBACK = 'https://kientuong.lienquan.garena.vn/auth/login/callback'
GRANT = 'https://auth.garena.com/oauth/token/grant'
PATHS = ('body', 'kientuong', 'kientuong_player', 'account_to_kientuong_oauth',
         'web_auth', 'apis', 'tcp_to_web_probe', 'player_api')


def terminal_authorization(result):
    if not isinstance(result, dict):
        return False
    if result.get('terminal_authorization') or result.get('challenge_required'):
        return True
    if any(result.get(k) in (401, 403, 429) for k in ('status', 'grant_status', 'callback_status')):
        return True
    for key in ('error', 'grant_error'):
        error = str(result.get(key) or '').casefold()
        if error in ('error_require_grant', 'require_grant', 'error_access_denied',
                     'access_denied', 'error_too_many_requests'):
            return True
        if any(word in error for word in ('captcha', 'security', 'otp')):
            return True
    return any(terminal_authorization(result.get(key)) for key in PATHS)


def safe_error(body, fallback):
    """Server error text may echo credentials; expose only known error codes."""
    value = body.get('error') if isinstance(body, dict) else None
    allowed = {'error_require_grant', 'require_grant', 'error_access_denied',
               'access_denied', 'error_too_many_requests', 'error_captcha',
               'error_security', 'error_otp', 'error_not_logged_in'}
    if isinstance(value, str) and value in allowed:
        return value
    if isinstance(value, str) and any(w in value.casefold() for w in ('captcha', 'security', 'otp')):
        return 'error_security'
    return fallback


class OAuthRedirectGuard(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        source = urllib.parse.urlsplit(req.full_url)
        target = urllib.parse.urlsplit(newurl)
        if source.path == '/oauth/token/grant':
            return None  # No automatic POST replay or unvalidated code redirect.
        if (source.hostname == 'kientuong.lienquan.garena.vn'
                and source.path == '/auth/login/callback'
                and (target.scheme != 'https' or target.netloc != source.netloc
                     or target.username or target.password)):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def valid_code_callback(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        target = urllib.parse.urlsplit(CALLBACK)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        codes = query.get('code', [])
        return (parsed.scheme == 'https' and parsed.netloc == target.netloc
                and parsed.path == target.path and not parsed.fragment
                and not parsed.username and not parsed.password
                and not any(ord(c) < 32 or c == '\\' for c in url)
                and not query.get('error') and len(codes) == 1 and bool(codes[0].strip()))
    except (ValueError, TypeError):
        return False


def code_grant(session, params):
    """One explicit-consent POST per account-owned session, including failures."""
    if str(params.get('client_id')) != '100054' or params.get('redirect_uri') != CALLBACK:
        return (0, GRANT, 'application/json', {'error': 'invalid_grant_target'})
    cache = getattr(session, '_code_grants', None)
    if cache is None:
        cache = session._code_grants = {}
    key = ('100054', CALLBACK)
    if key in cache:
        return cache[key]
    cache[key] = (0, GRANT, 'application/json', {'error': 'grant_already_attempted'})
    form = dict(client_id='100054', response_type='code', redirect_uri=CALLBACK,
                create_grant='true', format='json', id=str(time.time_ns() // 1000000))
    try:
        response = session.request(GRANT, method='POST', form_body=form,
                                   headers={'Referer': 'https://auth.garena.com/universal/oauth'})
        status, _, _, body = response
        if status != 200 or not isinstance(body, dict) or body.get('error'):
            response = (status, GRANT, 'application/json',
                        {'error': safe_error(body, 'grant_rejected')})
        cache[key] = response
    except Exception:
        cache[key] = (0, GRANT, 'application/json', {'error': 'grant_transport_failed'})
    return cache[key]
