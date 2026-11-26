"""VN MSDK request reconstructed from TLT main.MSDKExchangeSession (static).

No target engine is executed. These constants do not establish server acceptance.
"""
import gzip
import hashlib
import json
import time
import urllib.error
import urllib.request
import uuid

ITOP_HOST = 'https://itop.kg.garena.vn'
GAME_ID = '1137'
CHANNEL_ID = '10'
MSDK_SIGN_KEY = '4dfd535a3a2ef92644301c3e3ce87c9f'


def tlt_device_uuid(account):
    # NewLeverSession 0x1402ce96a..0x1402ce9f8, for normal ASCII Garena usernames.
    raw = bytearray(hashlib.sha256(('vua_uplv_dev:' + str(account).lower()).encode()).digest()[:16])
    raw[6] = (raw[6] & 15) | 64
    raw[8] = (raw[8] & 63) | 128
    return str(uuid.UUID(bytes=bytes(raw)))


def sign_query(path, query, body_plaintext):
    # VA 0x1402c86fc..0x1402c8959: path?query + key + actual JSON bytes; hex + "1".
    raw = body_plaintext.encode('utf-8') if isinstance(body_plaintext, str) else bytes(body_plaintext)
    prefix = (path + '?' + query + MSDK_SIGN_KEY).encode('utf-8')
    return hashlib.md5(prefix + raw).hexdigest() + '1'


def _go_json(obj):
    # encoding/json.Marshal sorts string-map keys and escapes HTML/U+2028/U+2029.
    text = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    for char, escaped in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                          ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        text = text.replace(char, escaped)
    return text.encode('utf-8')


def build_login_url_and_body(garena_token, open_id, device, ts=None, seq=None):
    """Keep the Lite four-value call shape; seq/key are unused, not sent."""
    ts = int(time.time() if ts is None else ts)
    query = f'channelid=10&gameid=1137&lang=vi&os=1&ts={ts}&version=5.12.1'
    device_uuid = device.get('uuid') or device.get('install_id') or str(uuid.uuid4())
    info = dict(uuid=device_uuid, device_language='vi', app_version='1.64.1.7.176857764',
                screen_dpi='1.5', resolution='960*540', trade_mark='disable',
                manufacturer='disable', model='disable', apn='disable',
                ram_info='1566527488', rom_info='28995375104', cpu_info='-1',
                imei='', qimei='', oaid='', xid='', qimei36='')
    obj = dict(device_info=info, channel_dis='00000000', scenes=1, scenes_version=2,
               region=['', '', ''], channel_info=dict(token=garena_token, uid=str(open_id),
                                                      login_type=0, cgToken=''))
    body = _go_json(obj)
    sig = sign_query('/v2/auth/login', query, body)
    return ITOP_HOST + '/v2/auth/login?' + query + '&sig=' + sig, body, None, None


def itop_login(garena_token, open_id, device, timeout=20, diagnostics=None):
    url, body, _, _ = build_login_url_and_body(garena_token, open_id, device)
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'Content-Type': 'application/json', 'Accept-Encoding': 'gzip',
        'User-Agent': 'Go-http-client/1.1'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            encoding = response.headers.get('Content-Encoding', '')
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'iTop login HTTP rejected (status={exc.code})') from None
    except Exception:
        # Do not expose signed URL, token, or raw server errors in debug logs.
        raise RuntimeError('iTop login transport failed') from None
    try:
        if encoding.lower() == 'gzip' or raw.startswith(b'\x1f\x8b'):
            raw = gzip.decompress(raw)
        out = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeError, OSError, EOFError):
        raise RuntimeError('iTop response JSON/gzip không hợp lệ') from None
    if not isinstance(out, dict):
        raise RuntimeError('iTop response must be an object')
    if diagnostics is not None:
        # Structural facts only. Never emit response values or arbitrary keys.
        diagnostics(dict(ret=out.get('ret') if type(out.get('ret')) is int else None, fields={key: dict(type=type(out.get(key)).__name__,
                               bytes=len(out[key].encode('utf8')) if isinstance(out.get(key),str) else None)
                     for key in ('ret','openid','uid','token','pf')}))
    ret = out.get('ret')
    if type(ret) is not int or ret != 0:
        status = str(ret) if type(ret) is int else 'invalid'
        raise RuntimeError(f'iTop login rejected request (ret={status})')
    # main.MSDKIdentity metadata 0x140754620 and checks 0x1402c8e9c..0x1402c8fe3.
    openid, token = out.get('openid'), out.get('token')
    if not isinstance(openid, str) or not openid or not isinstance(token, str) or not token:
        raise RuntimeError('iTop response thiếu token/openid')
    if not openid.isascii() or not openid.isdecimal() or not 0 < int(openid) < 2**64:
        raise RuntimeError('iTop numerical openid không hợp lệ')
    uid = out.get('uid')
    if not isinstance(uid, str) or len(uid.encode('utf8')) != 32 or '\0' in uid:
        raise RuntimeError('iTop MSDK uid phải có đúng 32 byte')
    return out


def login_account_no_phone(account, garena_token, open_id):
    from aov_device_identity import get_device_for_account
    device = dict(get_device_for_account(account))
    # Only MSDK's UUID follows TLT here; leave Lite's persisted transport identity intact.
    device['uuid'] = tlt_device_uuid(account)
    response = itop_login(garena_token, open_id, device)
    return dict(ok=True, game_token=response.get('token'), openid=response.get('openid'),
                msdk_uid=response.get('uid'),
                aov_token=response.get('aov_token'), device=device, raw=response)
