"""One bounded web-session login, only after explicit HTTP error_no_session.

No retries, redirect execution, shared cookie jar, or raw response/URL logging.
"""
from __future__ import annotations

import hashlib
import json
import time

from .garena_http_grant import (
    APP_ID, BODY_LIMIT, CONNECT_BASE, HTTP_TIMEOUT, _failure,
    extract_token_open_id, response_diagnostics, transport_diagnostics,
)
from .garena_tcp import GarenaError


def needs_web_session(exc):
    return (isinstance(exc, GarenaError) and exc.stage == 'http-grant'
            and exc.app_id == APP_ID and exc.http_status == 200
            and exc.reason == 'http_rejected'
            and getattr(exc, 'diagnostics', {}).get('error_name') == 'error_no_session')


def transform_password(password, v1, v2):
    from Crypto.Cipher import AES
    digest = hashlib.md5(password.encode('utf8')).digest()
    inner = hashlib.sha256((digest.hex() + v1).encode('utf8')).hexdigest()
    key = hashlib.sha256((inner + v2).encode('utf8')).digest()
    return AES.new(key, AES.MODE_ECB).encrypt(digest).hex()


def web_login_grant(account, password, *, session_factory=None, progress=None):
    """Fresh session per call; at most prelogin/login/OAuth/grant requests."""
    if session_factory is None:
        from requests import Session
        session_factory = Session
    session = None
    phase = 'web-prelogin'
    status = None
    redirect = f'gop{APP_ID}://'

    def fail(reason, obj=None, code=None):
        error = _failure(reason, status=status, code=code,
                         diagnostics=response_diagnostics(obj))
        error.diagnostics['phase'] = phase
        return error

    def request(path, *, params=None, data=None):
        nonlocal status
        status = None
        response = session.request('POST' if data is not None else 'GET',
            CONNECT_BASE + path, params=params, data=data, timeout=HTTP_TIMEOUT,
            allow_redirects=False, stream=True, verify=True)
        try:
            status = response.status_code
            if status == 429:
                raise fail('rate_limited', code=429)
            raw = response.raw.read(BODY_LIMIT + 1, decode_content=True)
            if len(raw) > BODY_LIMIT:
                raise fail('response_too_large')
            try:
                obj = json.loads(raw)
            except (ValueError, UnicodeError):
                raise fail('web_invalid_response') from None
            if not isinstance(obj, dict):
                raise fail('web_invalid_response')
            if obj.get('error') == 'error_too_many_requests':
                raise fail('rate_limited', obj, code=429)
            if obj.get('error'):
                raise fail('web_auth_rejected', obj)
            if any(obj.get(key) for key in ('captcha', 'captcha_key', 'captcha_url',
                    'otp', 'otp_required', 'require_otp', 'require_captcha',
                    'login_secondary', 'verification_required')):
                raise fail('web_verification_required', obj)
            # Never follow signed or external redirects. This helper accepts
            # credentials only from the final grant's JSON body.
            if status != 200:
                raise fail('web_http_rejected', obj)
            if progress:
                progress(f'[web-session] app_id={APP_ID} phase={phase} http={status} action=accepted')
            return obj
        except GarenaError as exc:
            if status in (429, 503):
                from .garena_http_grant import retry_after_seconds
                exc.retry_after = retry_after_seconds(response.headers.get('Retry-After'))
            raise
        finally:
            response.close()

    try:
        session = session_factory()
        session.headers.update({
            'User-Agent': 'GarenaMSDK/5.12.1(SM-S918B ;Android 13;vi;vn;)',
            'Accept': 'application/json, text/plain, */*',
            'Origin': CONNECT_BASE,
            'Referer': CONNECT_BASE + '/universal/oauth?locale=vi-VN&platform=1'
                       f'&response_type=token&login_scenario=normal&client_id={APP_ID}'
                       f'&redirect_uri=gop{APP_ID}%3A%2F%2F',
        })
        challenge = request('/api/prelogin', params=dict(app_id=str(APP_ID), account=account))
        if not all(isinstance(challenge.get(k), str) and 0 < len(challenge[k]) <= 4096
                   for k in ('v1', 'v2')):
            raise fail('web_missing_challenge', challenge)
        phase = 'web-login'
        login = request('/api/login', params=dict(app_id=str(APP_ID), account=account,
            password=transform_password(password, challenge['v1'], challenge['v2']),
            redirect_uri=redirect))
        if not any(isinstance(login.get(k), str) and login[k] for k in ('session_key', 'redirect_uri')):
            raise fail('web_missing_session', login)
        phase = 'web-oauth-init'
        params = dict(client_id=str(APP_ID), redirect_uri=redirect, response_type='token',
                      platform='1', locale='vi-VN', login_scenario='normal')
        oauth = request('/api/universal/oauth', params=params)
        if isinstance(oauth.get('sso_session'), dict) and oauth['sso_session'].get('login') is False:
            raise fail('web_session_not_established', oauth)
        phase = 'web-token-grant'
        form = {k: v for k, v in params.items() if k not in ('platform', 'locale')}
        form.update(create_grant='true', format='json', id=str(time.time_ns() // 1_000_000))
        grant = request('/oauth/token/grant', data=form)
        if any(grant.get(k) is not None and not isinstance(grant[k], str)
               for k in ('access_token', 'open_id', 'openid', 'redirect_uri')):
            raise fail('web_invalid_response', grant)
        token = (grant.get('access_token') or '').strip()
        open_id = (grant.get('open_id') or grant.get('openid') or '').strip()
        uri = grant.get('redirect_uri') or ''
        if uri.startswith(redirect):
            uri_token, uri_id = extract_token_open_id(uri)
            token, open_id = token or uri_token, open_id or uri_id
        if not token or not open_id:
            raise fail('missing_token', grant)
        return token, open_id
    except GarenaError:
        raise
    except Exception as exc:
        error = _failure('web_transport', status=status, diagnostics=transport_diagnostics(exc))
        error.diagnostics['phase'] = phase
        raise error from None
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
