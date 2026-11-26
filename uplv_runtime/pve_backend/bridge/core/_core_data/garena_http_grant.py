"""Bounded token grant reconstructed from the newly supplied TLT engine.

No authorization-code exchange, redirect execution, or raw response logging.
"""
from __future__ import annotations

import gzip
import io
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from .garena_tcp import GarenaError


CONNECT_BASE = 'https://100055.connect.garena.com'
APP_ID = 100055
BODY_LIMIT = 1024 * 1024
HTTP_TIMEOUT = 10.0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def extract_token_open_id(uri: str) -> tuple[str, str]:
    try:
        parsed = urllib.parse.urlsplit(uri.strip())
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        fragment = urllib.parse.parse_qs(parsed.fragment.removeprefix('?'), keep_blank_values=True)
    except (ValueError, UnicodeError):
        return '', ''

    def first(values, name):
        return values.get(name, [''])[0]

    token = first(query, 'access_token')
    open_id = first(query, 'openid') or first(query, 'open_id')
    return (token or first(fragment, 'access_token'),
            open_id or first(fragment, 'openid') or first(fragment, 'open_id'))


def _failure(reason, *, status=None, code=None):
    # Never interpolate response bodies, URLs, Location, cookies or exceptions.
    return GarenaError('Garena HTTP token grant thất bại', code=code,
                       stage='http-grant', app_id=APP_ID, reason=reason,
                       http_status=status)


def grant_token(sso_key: str, *, opener=None) -> tuple[str, str]:
    if not isinstance(sso_key, str) or not sso_key.strip() or any(
            char in sso_key for char in ('\r', '\n', ';', '\0')):
        raise _failure('invalid_sso_key')
    redirect = 'gop100055://'
    form = dict(client_id='100055', response_type='token', redirect_uri=redirect,
                create_grant='true', login_scenario='normal', format='json',
                id=str(time.time_ns() // 1_000_000))
    referer = (CONNECT_BASE + '/universal/oauth?locale=vi-VN&platform=1&response_type=token'
               '&login_scenario=normal&client_id=100055&redirect_uri='
               + urllib.parse.quote_plus(redirect, safe=''))
    request = urllib.request.Request(
        CONNECT_BASE + '/oauth/token/grant',
        data=urllib.parse.urlencode(form).encode('ascii'), method='POST', headers={
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'Accept': 'application/json, text/plain, */*',
            'User-Agent': 'GarenaMSDK/5.12.1(SM-S918B ;Android 13;vi;vn;)',
            'Origin': CONNECT_BASE, 'Referer': referer,
            'Cookie': 'sso_key=' + sso_key.strip(),
        })
    # Default TLS verification stays enabled. urllib's redirect handler is
    # disabled for all status codes, including codes not parsed below.
    send = opener if opener is not None else urllib.request.build_opener(NoRedirect()).open
    response = None
    status = None
    try:
        try:
            response = send(request, timeout=HTTP_TIMEOUT)
        except urllib.error.HTTPError as exc:
            response = exc  # Redirects and non-2xx still have a parseable body.
        status = response.getcode()
        if status in (301, 302, 303, 307):
            token, open_id = extract_token_open_id(response.headers.get('Location', ''))
            if token and open_id:
                return token, open_id
        raw = response.read(BODY_LIMIT + 1)
        if len(raw) > BODY_LIMIT:
            raise _failure('response_too_large', status=status,
                           code=429 if status == 429 else None)
        if response.headers.get('Content-Encoding', '').lower().strip() == 'gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
                raw = compressed.read(BODY_LIMIT + 1)
            if len(raw) > BODY_LIMIT:
                raise _failure('response_too_large', status=status,
                               code=429 if status == 429 else None)
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict) or any(
                    obj.get(name) is not None and not isinstance(obj[name], str)
                    for name in ('access_token', 'open_id', 'openid', 'redirect_uri', 'error')):
                obj = {}
        except (ValueError, UnicodeError):
            obj = {}
        token = (obj.get('access_token') or '').strip()
        open_id = (obj.get('open_id') or '').strip() or (obj.get('openid') or '').strip()
        if not token or not open_id:
            uri_token, uri_open_id = extract_token_open_id(obj.get('redirect_uri') or '')
            token, open_id = token or uri_token, open_id or uri_open_id
        # Match the binary's ordering: complete credentials precede error/status
        # classification, not an invented requirement for HTTP 200 alone.
        if token and open_id:
            return token, open_id
        error = (obj.get('error') or '').strip()
        if status == 429 or error == 'error_too_many_requests':
            raise _failure('rate_limited', status=status, code=429)
        if error == 'error_require_grant':
            raise _failure('require_grant', status=status, code=141)
        raise _failure('http_rejected' if error or status != 200 else 'missing_token', status=status)
    except GarenaError:
        raise
    except Exception:
        raise _failure('http_transport', status=status,
                       code=429 if status == 429 else None) from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
