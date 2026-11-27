from __future__ import annotations
import hashlib,os,ssl,socket,time,urllib.parse,urllib.request,urllib.error,json
from dataclasses import dataclass
class SsoLoginError(RuntimeError):
 def __init__(self,message,code=None,stage=None,http_status=None): super().__init__(message); self.code=code; self.stage=stage; self.http_status=http_status
@dataclass
class TokenBundle:
 uid:int; access_token:str; refresh_token:str; open_id:str; device_id:str; expiry_time:int; refresh_expiry_time:int; sso_key:str=''
 def __repr__(self): return f"TokenBundle(uid={self.uid}, access_token=<redacted>, refresh_token=<redacted>, open_id=<redacted>, device_id={self.device_id!r}, expiry_time={self.expiry_time}, refresh_expiry_time={self.refresh_expiry_time})"
def stable_device_id(serial,android_id,account): return '01-'+hashlib.sha256(f'{serial}|{android_id}|{account}'.encode()).hexdigest()[:32]
def preflight_device_id(account):
 from aov_device_identity import get_device_for_account
 return get_device_for_account(account).get('device_id')
class GarenaConnectClient:
 def __init__(self,client_secret=None,connect_base='https://100054.connect.garena.com',timeout=20,opener=None): self.client_secret=client_secret or os.environ.get('APP_SECRET'); self.connect_base=connect_base.rstrip('/'); self.timeout=timeout; self.opener=opener or urllib.request.urlopen
 def _post_form(self,path,form,cookie=None):
  headers={'Content-Type':'application/x-www-form-urlencoded','Connection':'close','User-Agent':'AutoUPLV/1.0'}
  if cookie: headers['Cookie']=cookie
  req=urllib.request.Request(self.connect_base+path,data=urllib.parse.urlencode(form).encode(),headers=headers)
  last=None
  for attempt in range(5):
   try:
    response=self.opener(req,timeout=self.timeout)
    try:
     return json.loads(response.read())
    finally:
     close=getattr(response,'close',None)
     if close: close()
   except urllib.error.HTTPError as exc:
    # Garena occasionally answers a burst of otherwise valid logins with
    # HTTP 429. Treat this as a transient transport response for the bounded
    # worker retry instead of converting it immediately into a bad-password
    # result. Keep the retry interval fixed at one second as requested.
    if exc.code == 429 and attempt < 4:
     try: exc.close()
     except Exception: pass
     time.sleep(1.0)
     continue
    raise
   except (urllib.error.URLError,TimeoutError,socket.timeout,ssl.SSLError) as exc:
    last=exc
    reason=getattr(exc,'reason',exc)
    text=str(reason).lower()
    transient=isinstance(reason,(TimeoutError,socket.timeout,ssl.SSLError)) or 'timed out' in text or 'timeout' in text
    if not transient or attempt >= 4:
     raise
    time.sleep(1.0)
  raise last
 def grant_code(self,sso_key):
  import time as _t
  form={'client_id':'100054','response_type':'code','redirect_uri':'gop100054://auth/','create_grant':'true','login_scenario':'normal','format':'json','id':str(int(_t.time()*1000))}
  resp=self._post_form('/oauth/token/grant',form,cookie=f'sso_key={sso_key}')
  return resp.get('code')
 def exchange_token(self,code,device_id):
  secret=self.client_secret or '027709b12673a3e18de16bf9b85723a2d55e9bffd3364aea67f176e533f69515'
  form={'grant_type':'authorization_code','code':code,'device_id':device_id,'redirect_uri':'gop100054://auth/','source':'2','client_id':'100054','client_secret':secret}
  d=self._post_form('/oauth/token/exchange',form); return TokenBundle(int(d.get('uid',0)),d['access_token'],d['refresh_token'],d['open_id'],device_id,int(d.get('expiry_time',0)),int(d.get('refresh_expiry_time',0)),sso_key=getattr(self,'_current_sso_key',''))

def login_sso_key(account,password,tcp_source_path=None,timeout=20,tcp_client_factory=None):
    """Obtain an SSO key through an injected Garena TCP client.

    The dependency is injected so the complete control flow can be tested with a
    local client while production deployments can load their verified transport.
    """
    if not account or not password: raise SsoLoginError('Garena account and password are required',stage='tcp')
    if tcp_client_factory is None:
        # The original application used the Garena TCP wire client directly.
        # Keep injection for deterministic tests, but make live mode use the
        # recovered implementation instead of failing before any request.
        try:
            from bridge.core._core_data.garena_tcp import GarenaTcpClient
            tcp_client_factory = GarenaTcpClient
        except ImportError as exc:
            raise SsoLoginError('Garena TCP client is not configured',stage='tcp') from exc
    try:
        client=tcp_client_factory(timeout=timeout)
        with client if hasattr(client,'__enter__') else _Context(client) as c:
            result=c.login(account,password)
            key=c.get_sso_key() if hasattr(c,'get_sso_key') else result
        if not key: raise SsoLoginError('Garena returned an empty SSO key',stage='tcp')
        return key
    except SsoLoginError: raise
    except Exception as exc: raise SsoLoginError(str(exc),stage='tcp') from exc

class _Context:
    def __init__(self,obj): self.obj=obj
    def __enter__(self): return self.obj
    def __exit__(self,*args):
        if hasattr(self.obj,'close'): self.obj.close()

def _direct_or_web(client, account, password, session_factory, progress):
    from bridge.core._core_data.garena_web_session import needs_web_session, web_login_grant
    from bridge.core._core_data.garena_tcp import OAuthResult
    try:
        return client.oauth_token_login()
    except Exception as exc:
        if not needs_web_session(exc):
            raise
    if progress:
        progress('[web-session] app_id=100055 trigger=error_no_session action=start')
    token, open_id = web_login_grant(account, password, session_factory=session_factory, progress=progress)
    return OAuthResult(client.uid, open_id, token, '', ())


def login_and_exchange(account,password,device_id,tcp_source_path=None,login_api_pyc_path=None,connect_base='https://100054.connect.garena.com',timeout=20,tcp_client_factory=None,opener=None,with_sso_key=True,progress=None,web_session_factory=None):
    if not account or not password: raise SsoLoginError('Garena account and password are required',stage='tcp')
    if tcp_client_factory is None:
        try:
            from bridge.core._core_data.garena_tcp import GarenaTcpClient
            tcp_client_factory = GarenaTcpClient
        except ImportError as exc:
            raise SsoLoginError('Garena TCP client is not configured',stage='tcp') from exc

    client_obj = tcp_client_factory(timeout=timeout)
    with client_obj if hasattr(client_obj,'__enter__') else _Context(client_obj) as c:
        c.login(account, password)
        # New TLT same-session TCP pair + conditional SSO/HTTP token grant.
        c.oauth_log = progress
        if opener is not None:
            c.http_grant_opener = opener
        try:
            direct = _direct_or_web(c, account, password, web_session_factory, progress)
        except Exception as exc:
            # Do not include a raw server body/token in diagnostics.
            code = getattr(exc, 'code', None)
            code = code if type(code) is int else None
            app_id = getattr(exc, 'app_id', None)
            reason = getattr(exc, 'reason', None)
            message = 'V2 direct-token Garena thất bại'
            if code == 141 or reason == 'require_grant':
                code = 141
                message += ': cần cấp quyền Liên Quân lần đầu (141)'
            elif reason in ('missing_token', 'invalid_token_encoding'):
                message += ': thiếu hoặc sai định dạng token/open ID (không phải lỗi grant 141)'
            elif reason == 'malformed_body':
                message += ': OAuth body không hợp lệ'
            elif reason == 'body_error':
                message += f': OAuth body báo lỗi (rc={code})'
            elif reason == 'rate_limited':
                message += f': OAuth/grant bị giới hạn tần suất (mã {code}); dừng, không tự thử lại'
            elif getattr(exc, 'stage', None) == 'http-grant':
                message += ': HTTP token grant thất bại'
                status = getattr(exc, 'http_status', None)
                if type(status) is int:
                    message += f' (HTTP {status})'
            elif code is not None:
                message += f' (mã {code})'
            else:
                message += f' ({type(exc).__name__})'
            if type(app_id) is int:
                message += f' [app_id={app_id}]'
            error = SsoLoginError(message, code=code, stage='tcp-token-v2',
                                  http_status=getattr(exc, 'http_status', None))
            error.app_id = app_id if type(app_id) is int else None
            error.reason = reason
            error.diagnostics = getattr(exc, 'diagnostics', {})
            raise error from None
        if not direct.open_id or not direct.response_data:
            raise SsoLoginError('V2 direct-token thiếu token/open ID', stage='tcp-token-v2')
        return TokenBundle(c.uid, direct.response_data, '', direct.open_id,
                           device_id, 0, 0, sso_key='')
