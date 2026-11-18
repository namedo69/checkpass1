"""MSDK session exchange request signing and response parsing; no implicit network calls."""
from dataclasses import dataclass
import hashlib
import json
from .reader import DecodeError

MSDK_LOGIN_URL = 'https://itop.kg.garena.vn/v2/auth/login?'
MSDK_LOGIN_PATH = '/v2/auth/login?'
MSDK_SIG_SECRET = '4dfd535a3a2ef92644301c3e3ce87c9f'
MSDK_SIG_SUFFIX = '1'


@dataclass(frozen=True)
class MSDKIdentity:
    ret: int
    msg: str
    openid: str
    uid: str
    token: str
    pf: str
    numeric_uid: int


def format_uuid_from_bytes(raw):
    if len(raw) < 16:
        raise ValueError('UUID source must be at least 16 bytes')
    b = bytes(raw[:16])
    return f'{b[0:4].hex()}-{b[4:6].hex()}-{b[6:8].hex()}-{b[8:10].hex()}-{b[10:16].hex()}'


def build_msdk_login_request(garena_token, garena_open_id, device_uuid, *, unix_seconds):
    if not device_uuid:
        raise ValueError('device_uuid must be non-empty')
    device_info = {
        'apn': 'disable',
        'app_version': '1.64.1.7.176857764',
        'cpu_info': '-1',
        'device_language': 'vi',
        'imei': '',
        'manufacturer': 'disable',
        'model': 'disable',
        'oaid': '',
        'qimei': '',
        'qimei36': '',
        'ram_info': '1566527488',
        'resolution': '960*540',
        'rom_info': '28995375104',
        'screen_dpi': '1.5',
        'trade_mark': 'disable',
        'uuid': device_uuid,
        'xid': '',
    }
    channel_info = {
        'cgToken': '',
        'login_type': 0,
        'token': garena_token,
        'uid': garena_open_id,
    }
    payload = {
        'channel_dis': '00000000',
        'channel_info': channel_info,
        'device_info': device_info,
        'region': ['', '', ''],
        'scenes': 1,
        'scenes_version': 2,
    }
    body = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    query = f'channelid=10&gameid=1137&lang=vi&os=1&ts={int(unix_seconds)}&version=5.12.1'
    sig_input = (MSDK_LOGIN_PATH + query + MSDK_SIG_SECRET).encode('utf-8') + body
    sig = hashlib.md5(sig_input).hexdigest() + MSDK_SIG_SUFFIX
    url = f'{MSDK_LOGIN_URL}{query}&sig={sig}'
    headers = {
        'Content-Type': 'application/json',
        'Accept-Encoding': 'gzip',
    }
    return url, headers, body


def parse_msdk_login_response(raw_json):
    try:
        obj = json.loads(raw_json.decode('utf-8') if isinstance(raw_json, (bytes, bytearray)) else raw_json)
    except Exception as exc:
        raise DecodeError(f'invalid MSDK JSON: {exc}') from exc
    if not isinstance(obj, dict):
        raise DecodeError('MSDK response must be a JSON object')
    ret = int(obj.get('ret', 0) or 0)
    msg = str(obj.get('msg', '') or '')
    openid = str(obj.get('openid', '') or '')
    uid = str(obj.get('uid', '') or '')
    token = str(obj.get('token', '') or '')
    pf = str(obj.get('pf', '') or '')
    if ret != 0 or not openid or not token:
        from .account_health import AccountAuthError
        raise AccountAuthError('msdk', ret, msg)
    try:
        numeric_uid = int(openid, 10)
    except ValueError as exc:
        raise DecodeError('invalid MSDK numerical openid') from exc
    if numeric_uid <= 0 or numeric_uid >= 2**64:
        raise DecodeError('invalid MSDK numerical openid')
    return MSDKIdentity(
        ret=ret,
        msg=msg,
        openid=openid,
        uid=uid,
        token=token,
        pf=pf,
        numeric_uid=numeric_uid,
    )
