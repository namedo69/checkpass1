import base64,hashlib,json,time,uuid,urllib.request
ITOP_HOST="https://itop.kg.garena.vn"; GAME_ID="1137"; CHANNEL_ID="10"; MSDK_SIGN_KEY="4dfd535a3a2ef92644301c3e3ce87c9f"
def _md5(s): return hashlib.md5(s.encode() if isinstance(s,str) else s).hexdigest()
def make_seq(ts=None,counter=0): return f"{GAME_ID}-{uuid.uuid4()}-{int(time.time() if ts is None else ts)}-{counter}"
def sign_query(path,query,body_plaintext): return _md5(path+"?"+query+body_plaintext+MSDK_SIGN_KEY)
def _xor(data,key_ascii):
 k=key_ascii.encode('ascii') if isinstance(key_ascii,str) else key_ascii
 return bytes(data[i]^k[i%len(k)] for i in range(len(data)))
def _derive_xor_key(sig): return _md5('MSDK_ENCRYPT'+MSDK_SIGN_KEY+sig)
def build_login_url_and_body(garena_token,open_id,device,ts=None,seq=None):
 ts=int(time.time()) if not ts else int(ts); seq=seq or make_seq(ts); q=f"channelid={CHANNEL_ID}&encrypt=1&gameid={GAME_ID}&lang=&os={device.get('os','1')}&seq={seq}&ts={ts}&version=null"; obj={'channel_info':{'token':garena_token,'uid':str(open_id),'cgToken':'','login_type':0},'channel_dis':'1','uid':str(open_id)}; plain=json.dumps(obj,separators=(',',':')).encode(); sig=sign_query('/v2/auth/login',q,plain.decode()); key=_derive_xor_key(sig); return ITOP_HOST+'/v2/auth/login?'+q+'&sig='+sig,base64.b64encode(_xor(plain,key)),seq,key
def itop_login(garena_token,open_id,device,timeout=20):
 url,body,seq,key=build_login_url_and_body(garena_token,open_id,device); req=urllib.request.Request(url,data=body,method='POST',headers={'Content-Type':'application/json','User-Agent':device.get('user_agent','okhttp/3.12.1')})
 try:
  with urllib.request.urlopen(req,timeout=timeout) as r: raw=r.read()
 except Exception as exc: raise RuntimeError(f'iTop login request failed: {exc}') from exc
 try: out=json.loads(_xor(base64.b64decode(raw),key).decode('utf-8'))
 except Exception:
  try: out=json.loads(raw.decode('utf-8'))
  except Exception: out={'_raw':raw[:400].decode('latin1','replace')}
 if not isinstance(out,dict): raise ValueError('iTop response must be an object')
 ret=out.get('ret',out.get('code',0))
 if isinstance(ret,int) and ret not in (0,1): raise RuntimeError(f'iTop login rejected request (ret={ret})')
 return out
def login_account_no_phone(account,garena_token,open_id):
 from aov_device_identity import get_device_for_account
 device=get_device_for_account(account); resp=itop_login(garena_token,open_id,device)
 if resp.get('ret')==0: return {'ok':True,'game_token':resp.get('token'),'openid':resp.get('openid'),'aov_token':resp.get('aov_token'),'device':device,'raw':resp}
 return {'ok':False,'error':resp.get('msg'),'ret':resp.get('ret'),'raw':resp}
