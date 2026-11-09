import re,struct

def decode_login_role(body, known_uid=None):
 """SCPKG_CMD_GAMELOGINRSP fixed prefix from recovered tdr_metalib.json.

 Offsets: result 0, account object 4, UID 8, level 16, exp 20,
 PvP level 24, PvP exp 28, max/current action points 32/36.
 Only invoke for CSID 1003, never by scanning unrelated packet bytes.
 """
 b=bytes(body)
 if len(b)<40:return None
 result,object_id,uid,level,exp,pvp_level,pvp_exp,max_ap,cur_ap=struct.unpack_from('>iIQ6I',b)
 if result != 0 or uid <= 0 or not 1<=pvp_level<=200:return None
 if known_uid is not None and uid != int(known_uid):return None
 return dict(uid=str(uid),object_id=object_id,level=level,exp=exp,
             pvp_level=pvp_level,pvp_exp=pvp_exp,max_action_point=max_ap,
             cur_action_point=cur_ap,level_offset=24)

def decode_level_update(body):
 """CSID 1015 observed after grant/PvE: u32 level, u32 EXP, type 2."""
 b=bytes(body)
 if len(b)<12 or b[8:12] != bytes.fromhex('00020000'):return None
 level,exp=struct.unpack_from('>II',b)
 if not 1<=level<=200:return None
 return dict(pvp_level=level,pvp_exp=exp)
_COIN_ANCHOR=b'\x01\x05\x00\x04'; _TOK1=re.compile(b'[\\x0c-\\x14]\\x00[\\x00-\\x40]\\x02\\x00'); _TOK2=re.compile(b'[\\x0c-\\x14]\\x00'); _PREUID=re.compile(b'\\x00\\x01\\x00\\x01\\x00'); _MAXAP=b'\x00\x00\x00\xc9'
def _find_coin_tok1(blob):
 start=0
 while True:
  a=blob.find(_COIN_ANCHOR,start)
  if a<0:return None
  m=_TOK1.search(blob,a,a+48)
  if m and m.start()-a>=6:return m.start()
  start=a+1
def _decode_currency(blob):
 out={'gold':None,'diamond':None,'symbol':None}; t1=_find_coin_tok1(blob)
 if t1 is None or t1<2:return out
 out['gold']=struct.unpack_from('>H',blob,t1-2)[0]; c2=t1+6; m2=_TOK2.search(blob,c2+1,c2+16)
 if not m2:return out
 t2=m2.start()
 if t2>=4:
  ruby=struct.unpack_from('>I',blob,t2-4)[0]
  if ruby<=2000000: out['diamond']=ruby
 sym_bytes=blob[c2:t2-4]
 if 0<len(sym_bytes)<=4:
  sym=int.from_bytes(sym_bytes,'big')
  if sym<=50000000: out['symbol']=sym
 return out
def _decode_level(blob):
 out={'pvp_level':None,'pvp_exp':None,'max_action_point':None}; m=_PREUID.search(blob,26000,27700) or _PREUID.search(blob)
 if not m:return out
 base=m.start(); mp=blob.find(_MAXAP,base,base+160)
 if mp<0:return out
 out['max_action_point']=struct.unpack_from('>I',blob,mp)[0]
 if mp>=4:out['pvp_exp']=struct.unpack_from('>I',blob,mp-4)[0]
 if mp>=5:out['pvp_level']=blob[mp-5]
 return out
def _decode_experimental(blob):
 exp={}; lo=27000; hi=min(len(blob),30000); cands=[i for i in range(lo,hi-3) if blob[i:i+4]==b'\0\0\0c']
 if len(cands)==1:exp['credit_score']=99
 for p in range(lo,max(lo,hi-10)):
  if blob[p+8:p+10]!=b'z\0':continue
  c,e=struct.unpack_from('>II',blob,p)
  if 1<=c<=999 and 0<=e<=6000: exp.update(country_id=c,five_camp_elo=e); break
 return exp
def decode_role(blob,include_experimental=False):
 if not isinstance(blob,(bytes,bytearray)): raise TypeError('blob must be bytes')
 b=bytes(blob); out={}; out.update(_decode_currency(b)); out.update(_decode_level(b))
 # Preserve the original decoder's optional tagged fallback for synthetic fixtures.
 for name in ('pvp_level','pvp_exp','gold','diamond','ruby','symbol','max_action_point','credit_score','country_id','five_camp_elo'):
  tag=name.encode()+b'='; i=b.find(tag)
  if i>=0:
   v=b[i+len(tag):].split(b'\0',1)[0].split(b';',1)[0]
   try: out[name]=int(v)
   except ValueError: pass
 out={k:v for k,v in out.items() if v is not None}
 if 'diamond' in out:out['ruby']=out['diamond']
 if include_experimental:
  exp=_decode_experimental(b)
  if exp:out['experimental']=exp
 return out
def decode(blob): return decode_role(blob)
