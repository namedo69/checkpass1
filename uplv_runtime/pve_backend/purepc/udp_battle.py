import os,socket,struct,time,random
# Constants recovered from the shipped CPython 3.12 udp_battle module.
TUNNEL_HDR_C2S=bytes.fromhex('010200009abcdef000011a3b'); TYPE_S2C_CTRL=0x20000; TYPE_S2C_FLOW=0x30000; SUBTYPE_SYN=0; SUBTYPE_ACK=0x40000; SUBTYPE_DATA=0x50000; HDR_LEN_5=0x5000; F_SYN=2; F_ACK=16; FLAGS_SYN=0xa2; FLAGS_SYN_ACK=0xb2; FLAGS_ACK=F_ACK; FLAGS_PSH_ACK=F_ACK|8; WIN_FFFF=0xffff; WIN_SYN_ACK=0x5544
def crc32c(data):
 crc=0xffffffff; poly=0x82f63b78
 for b in data:
  crc^=b
  for _ in range(8): crc=(crc>>1)^poly if crc&1 else crc>>1
 return crc^0xffffffff

def validate_crc32c(data, expected):
    """Validate a TGCP CRC field (integer or four-byte big endian value)."""
    if isinstance(expected, (bytes, bytearray)):
        if len(expected) != 4: return False
        expected = struct.unpack('>I', expected)[0]
    return crc32c(bytes(data)) == int(expected) & 0xffffffff

def parse_tgcp_packet(raw, *, min_header=32):
    """Perform conservative envelope validation and expose packet metadata.

    Proprietary payloads are returned unchanged.  Invalid/truncated packets
    raise ValueError so callers can trigger retransmission or reconnect.
    """
    raw = bytes(raw)
    if len(raw) < 4: raise ValueError('TGCP packet is truncated')
    ptype = struct.unpack('>I', raw[:4])[0]
    if ptype in (TYPE_S2C_CTRL, TYPE_S2C_FLOW):
        if len(raw) < min_header: raise ValueError('TGCP control packet is truncated')
        return {'type':ptype, 'payload':raw[4:], 'raw':raw}
    if len(raw) < 16: raise ValueError('TGCP envelope is truncated')
    return {'type':ptype, 'payload':raw[4:], 'raw':raw}
class TGCPConn:
 def __init__(self,host,port,log=print,tunnel_header=None):
  self.tunnel_header=bytes(tunnel_header) if tunnel_header is not None else TUNNEL_HDR_C2S
  if len(self.tunnel_header)!=12 or self.tunnel_header[:8]!=TUNNEL_HDR_C2S[:8]:
   raise ValueError('invalid TGCP tunnel header')
  self.host,self.port=host,int(port); self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); self.sock.settimeout(5); self.sock.connect((host,port)); self.log=log; self.state='CLOSED'; self.counter=random.randint(160,239); self.session_token=bytes.fromhex('1cd46a'); self.server_cookie1=self.server_cookie2=self.server_cookie3=self.server_cookie4=b'\0'*4; self.server_win=WIN_FFFF; self.client_seq=random.randint(1308622848,1325400063); self.server_seq=0; self.last_payload_csum=b'\0'*4; self.state2=self.state3=0
 def _counter_token(self): c=self.counter&255; self.counter=(self.counter+1)&255; return bytes([c])+self.session_token
 def _crc_chain(self,seq_u32_le): self.state3=crc32c(struct.pack('<I',(self.state2^self.state3^seq_u32_le)&0xffffffff)); return struct.pack('>I',self.state3)
 def _build_envelope(self,subtype,flags,payload_csum,payload):
  ct=self._counter_token(); seq=struct.unpack('<I',ct)[0]; return self.tunnel_header+self._crc_chain(seq)+ct+struct.pack('>I',subtype)+self.server_cookie1+self.server_cookie2+self.server_cookie3+self.server_cookie4+struct.pack('>H',HDR_LEN_5|flags)+struct.pack('>H',WIN_FFFF)+payload_csum+payload
 def build_syn(self):
  if __import__('os').environ.get('AOV_UDP_EXACT_CAPTURE_SYN')=='1':
   # Diagnostic wire sample from the owner-authorized .36 capture.  This
   # branch is deliberately opt-in: it is used only to distinguish a bad
   # reconstructed SYN layout from an endpoint/routing failure.  The normal
   # path below still generates an independent packet.
   # The following stream state is the one inferred from the two following
   # client envelopes in the same capture.  It makes the CRC chain emit the
   # observed 0x0749f96a and 0x2b92bd85 for counters e7/e8.
   self.session_token=bytes.fromhex('fae56a')
   # The captured SYN carries counter 0xe6.  The first DATA envelope sent
   # after its SYN-ACK carries 0xe7 and the CS hello carries 0xe8.  Do not
   # consume a counter here: this branch returns a literal SYN rather than
   # using ``ct`` below, so advancing it would shift every subsequent CRC by
   # one and the gateway would silently discard the hello.
   self.counter=0xe7
   self.state2=0x1647ff5c
   self.state3=0x669ba8d4
   return bytes.fromhex(
    '010200009abcdef000011a3b'
    'bfe3bcb7e6fae56a93ce1a0124b83730'
    '0000000050a2ffff0000e20eff998c6a')
  if __import__('os').environ.get('AOV_UDP_CAPTURE_SYN')=='1':
   # The phone capture uses a compact 44-byte SYN.  The old reconstruction
   # inserted four zero cookie fields and emitted 48 bytes, which cannot be
   # accepted by the live TGCP listener.  Captured layout is:
   # tunnel, chain CRC, counter token, client cookie, client sequence,
   # subtype, flags/window, payload checksum, random tail.
   # These prefixes/suffixes are stable across the five owner-authorized
   # phone captures. They are selected only by this diagnostic mode; the
   # default reconstruction keeps its independent generator.
   self.session_token=bytes.fromhex('fae56a'); self.counter=0xe7
   # These chain seeds and the e6/e7/e8 counter sequence are stable across
   # all five phone captures.  The old branch used a different token (90) and
   # seeds from an unrelated probe, which produced a SYN-ACK followed by a
   # discarded DATA packet.
   self.state2=0x1647ff5c; self.state3=0x669ba8d4
   # The SYN itself carries e6; keep e7 pending for the post-SYN DATA packet.
   ct=bytes.fromhex('e6fae56a')
   self.client_cookie=(random.randrange(0, 0x10000) << 16) | 0x1a01
   self.client_seq=0x24b83700 | random.randrange(0x100)
   self._syn_client_cookie=self.client_cookie
   # The first SYN CRC is a fixed TGCP session marker in the owner capture;
   # deriving it from the four byte counter token produces 0caba727 and is
   # silently discarded by the live listener.
   syn_crc=bytes.fromhex('bfe3bcb7')
   self._syn_packet=(self.tunnel_header+syn_crc+ct+
                     struct.pack('>I',self.client_cookie)+
                     struct.pack('>I',self.client_seq)+
                     struct.pack('>I',SUBTYPE_SYN)+
                     struct.pack('>H',HDR_LEN_5|FLAGS_SYN)+
                     struct.pack('>H',WIN_FFFF)+
                     bytes.fromhex('0000e20e')+
                     random.randbytes(4))
   return self._syn_packet
  # Shipped send_syn: 40-byte prefix + two uint16 fields + one uint32.
  # Construct once so diagnostics and the session send identical layouts.
  self.server_cookie1=self.server_cookie2=self.server_cookie3=self.server_cookie4=b'\0'*4
  return self._build_envelope(SUBTYPE_SYN,FLAGS_SYN,b'\0'*4,b'')[:40]+struct.pack('>HH',HDR_LEN_5|FLAGS_SYN,WIN_FFFF)+struct.pack('>I',random.getrandbits(32))
 def send_syn(self, *, retransmit=False):
  if not retransmit:
   self._syn_packet=self.build_syn()
  elif self.state!='SYN_SENT' or not getattr(self,'_syn_packet',None):
   raise RuntimeError('no pending SYN to retransmit')
  if os.environ.get('AOV_UDP_TRACE') == '1':
   try: self.log('[udp-send] SYN bytes=%d prefix=%s' % (len(self._syn_packet), self._syn_packet.hex()))
   except Exception: pass
  sent=self.sock.send(self._syn_packet); self.state='SYN_SENT'; return sent
 def send_ack(self):
  # ACK-only envelopes are sent for each 0x00030000 flow burst before the
  # gateway releases the encrypted server hello.  The final four bytes are a
  # client nonce, stable across the burst but different per session.
  if not hasattr(self, '_client_ack_csum'):
   override=os.environ.get('AOV_UDP_ACK_CSUM','').strip()
   try: value=bytes.fromhex(override) if override else os.urandom(4)
   except ValueError: value=os.urandom(4)
   self._client_ack_csum=value if len(value)==4 else os.urandom(4)
  ct=self._counter_token()
  wire=(self.tunnel_header+self._crc_chain(struct.unpack('<I',ct)[0])+ct+
        struct.pack('>I',SUBTYPE_ACK)+self.server_cookie1+
        struct.pack('>I',1946484736)+self._client_ack_csum)
  if os.environ.get('AOV_UDP_TRACE') == '1':
   try: self.log('[udp-send] ACK bytes=%d prefix=%s' % (len(wire),wire.hex()))
   except Exception: pass
  self.sock.send(wire)
 def send_post_syn_data_ack(self):
  """Send the first client envelope observed after a TGCP SYN-ACK.

  The phone capture does not send ``SUBTYPE_ACK`` here.  It sends a 52-byte
  DATA envelope (subtype 0x00050000, ACK-only flags 0x5010) with a four-byte
  opaque tail, then sends the normal client hello.  Keeping this separate from
  ``send_ack`` makes the wire-order experiment explicit and preserves the old
  path behind the environment switch below.
  """
  # The server advances its fourth cookie by one for the first DATA envelope.
  # This is visible in all five captured sessions; use the parsed value when
  # available and leave it unchanged for older endpoints that omit it.
  if len(self.server_cookie4) == 4:
   value=(int.from_bytes(self.server_cookie4,'big')+1)&0xffffffff
   self.server_cookie4=struct.pack('>I',value)
  if os.environ.get('AOV_UDP_CAPTURE_CHECKSUM') == '1':
   # The first two bytes of this field are echoed from the current
   # SYN-ACK's payload checksum.  They are not a constant: the five phone
   # captures had f b0e / fc0e / fa0f / f00e / fc0e respectively, while the
   # server may return a different value on every fresh BattleAssign.
   # Keeping the old fixed vector here made the server retransmit SYN-ACK
   # forever, because the DATA envelope did not belong to that session.
   # The trailing two bytes are still an inferred field; callers can override
   # them with AOV_UDP_POST_CSUM_TAIL while we collect another phone vector.
   tail_hex = os.environ.get('AOV_UDP_POST_CSUM_TAIL', '050f').strip()
   try:
    tail = bytes.fromhex(tail_hex)
   except ValueError:
    tail = bytes.fromhex('050f')
   if len(tail) != 2:
    tail = bytes.fromhex('050f')
   prior = bytes(self.last_payload_csum or b'')
   prefix = prior[2:4] if len(prior) == 4 else bytes.fromhex('f00e')
   payload_csum = prefix + tail
   self.log('[udp] post-syn checksum server=%s selected=%s'
            % (prior.hex(), payload_csum.hex()))
   # The four bytes after the transport header are a per-packet nonce.  They
   # differ in every phone session (including sessions from the same device),
   # so replaying the .36 capture literal makes the gateway discard the DATA
   # packet.  An explicit override remains useful for byte-for-byte replay.
   tail_hex = os.environ.get('AOV_UDP_POST_SYN_TAIL', '').strip()
   try:
    opaque_tail = bytes.fromhex(tail_hex) if tail_hex else os.urandom(4)
   except ValueError:
    opaque_tail = os.urandom(4)
   if len(opaque_tail) != 4:
    opaque_tail = os.urandom(4)
   self.send_data(opaque_tail, flags=FLAGS_ACK, payload_csum=payload_csum)
  else:
   self.send_data(os.urandom(4), flags=FLAGS_ACK)
 def send_data(self,payload,flags=FLAGS_PSH_ACK,payload_csum=None):
  csum=self.last_payload_csum if payload_csum is None else bytes(payload_csum)
  wire=self._build_envelope(SUBTYPE_DATA,flags,csum,payload)
  if os.environ.get('AOV_UDP_TRACE') == '1':
   try: self.log('[udp-send] DATA bytes=%d prefix=%s' % (len(wire), wire[:96].hex()))
   except Exception: pass
  self.sock.send(wire)
 def recv(self,timeout=5):
  self.sock.settimeout(timeout)
  try: raw=self.sock.recv(2048)
  except socket.timeout:return (None,None)
  if os.environ.get('AOV_UDP_TRACE') == '1':
   try: self.log('[udp-recv] bytes=%d prefix=%s' % (len(raw), raw[:40].hex()))
   except Exception: pass
  if len(raw)<4:return (None,None)
  try: parse_tgcp_packet(raw)
  except ValueError: return ('malformed',raw)
  tp=struct.unpack('>I',raw[:4])[0]
  if tp==TYPE_S2C_CTRL and len(raw)==32:
   # The first DATA packet echoes the client's sequence (wire bytes 16..20)
   # in cookie slot 3 and advances the server sequence (wire bytes 12..16)
   # by one in slot 4. Bytes 8..12 are stored in the wire's rotated order;
   # the phone sends the two-byte rotation in the DATA envelope.
   self.server_cookie1=raw[4:8]
   sc2=raw[8:12]
   self.server_cookie2=sc2[2:]+sc2[:2]
   self.server_cookie3=raw[16:20]
   self.server_cookie4=raw[12:16]
   self.last_payload_csum=raw[24:28]
   if os.environ.get('AOV_UDP_TRACE') == '1':
    try:
     self.log('[udp] SYN-ACK cookies c1=%s c2=%s c3=%s c4=%s csum=%s' % (
      self.server_cookie1.hex(), self.server_cookie2.hex(),
      self.server_cookie3.hex(), self.server_cookie4.hex(),
      self.last_payload_csum.hex()))
    except Exception:
     pass
   self.state='ESTABLISHED'; return ('syn_ack',raw)
  if tp==TYPE_S2C_FLOW:return ('flow',raw)
  # TGCP DATA envelopes carry a CS frame after a 24-byte transport prefix.
  # The old probe searched for ``3f 00 08`` (a typo from an unrelated frame),
  # so a valid server hello (magic ``33 66 00 08``) was classified as
  # ``unknown`` and connect() eventually reported a false hello timeout.
  from purepc.cs import MAGIC as CS_MAGIC
  pos=raw.find(CS_MAGIC)
  return ('data',raw[pos:] if pos>=0 else raw) if len(raw)>48 and pos>=0 else ('unknown',raw)
 def close(self):
  try:self.sock.close()
  except Exception:pass

 def reconnect(self):
  """Reset the UDP socket and perform a fresh SYN handshake."""
  self.close(); self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); self.sock.settimeout(5)
  self.sock.connect((self.host,self.port))
  self.state='CLOSED'; self.counter=random.randint(160,239); self.send_syn(); return self.state
class UDPBattleSession:
 def __init__(self,host,port,openid,game_token,log=print):
  self.host,self.port,self.openid,self.game_token,self.log=host,port,openid,game_token,log
  self.conn=None; self.key1=None; self.tx=None; self.rx=None; self.cs_counter=1; self.state='CLOSED'
  self.handshake_verified=False; self.server_hello_received=False; self.login_sent=False
  self.syn_bytes_sent=0
  self.syn_attempts=0
  self.syn_hex=''
  self.tunnel_header=None
 @classmethod
 def from_battle_assign(cls,battle_token_hex,ip,port,openid,game_token,log=print):
  session=cls(ip,port,openid,game_token,log)
  # The original constructor ignores this token. Its actual wire use remains
  # unknown; retain the recovered prefix unless explicitly experimenting.
  # BattleAssign carries the per-session TGCP routing prefix.  Using the
  # frozen header makes the SYN reach the wrong session on current shards;
  # retain an explicit opt-out only for legacy captures.
  use_token = __import__('os').environ.get('AOV_UDP_USE_TOKEN_PREFIX', '1') != '0'
  if battle_token_hex and use_token:
   token=bytes.fromhex(battle_token_hex)
   if len(token)<12 or token[:8]!=TUNNEL_HDR_C2S[:8]: raise ValueError('invalid battle routing token')
   session.tunnel_header=token[:12]
  return session
 def connect(self):
  from purepc.cs import build_client_hello,parse_server_hello,build_login_plaintext,build_data_frame
  from purepc.crypto import AES128CBCStream
  self.conn=TGCPConn(self.host,self.port,log=self.log,tunnel_header=self.tunnel_header)
  self.sock=self.conn.sock
  try:
   self.state='SYN_SENT'
   for attempt in range(3):
    self.syn_bytes_sent+=self.conn.send_syn(retransmit=attempt>0)
    self.syn_hex=getattr(self.conn,'_syn_packet',b'').hex()
    self.syn_attempts=attempt+1
    kind,raw=self.conn.recv(timeout=3.0)
    # Retransmit the exact pending SYN only on silence. A response, including
    # an unrecognized one, must be diagnosed rather than blindly retried.
    if kind is not None: break
   # Some current shards reject newly generated cookie/sequence pairs even
   # though they still accept the 44-byte layout used by the phone client.
   # Retry once with the captured fixed vector so this remains diagnosable
   # without requiring an operator to set an environment flag.  The fallback
   # is opt-out because it is only a transport probe; it does not bypass the
   # subsequent session authentication.
   if kind != 'syn_ack' and os.environ.get('AOV_UDP_EXACT_FALLBACK', '1') != '0':
    old_exact=os.environ.get('AOV_UDP_EXACT_CAPTURE_SYN')
    try:
     os.environ['AOV_UDP_EXACT_CAPTURE_SYN']='1'
     self.syn_bytes_sent += self.conn.send_syn(retransmit=False)
     self.syn_attempts += 1
     self.syn_hex=getattr(self.conn,'_syn_packet',b'').hex()
     kind,raw=self.conn.recv(timeout=3.0)
    finally:
     if old_exact is None: os.environ.pop('AOV_UDP_EXACT_CAPTURE_SYN',None)
     else: os.environ['AOV_UDP_EXACT_CAPTURE_SYN']=old_exact
   if kind!='syn_ack': raise RuntimeError('UDP handshake failed: response=%s bytes=%d' % (kind,len(raw or b'')))
   self.handshake_verified=True
   # Captured clients send DATA/ACK immediately after SYN-ACK.  The legacy
   # ACK-only envelope is retained for controlled comparison only.
   if os.environ.get('AOV_UDP_LEGACY_ACK_ORDER') == '1':
    self.conn.send_ack()
   else:
    self.conn.send_post_syn_data_ack()
   self.state='HELLO_SENT'
   hello_payload = build_client_hello(self.openid)
   # The live phone envelope carries a four-byte TGCP payload tail after the
   # CS hello.  Older reconstruction omitted it, causing the gateway to
   # accept SYN but silently discard the hello.  Keep it opt-in until the
   # checksum stream is fully validated.
   if os.environ.get('AOV_UDP_EXACT_PAYLOAD') == '1':
    hello_payload += (bytes.fromhex('c6e89c2a')
                      if os.environ.get('AOV_UDP_CAPTURE_TAILS') == '1'
                      else os.urandom(4))
   hello_csum = None
   if os.environ.get('AOV_UDP_CAPTURE_CHECKSUM') == '1':
    # The five captures use different hello checksum/nonce words.  A single
    # .36 literal breaks the other four sessions.  Keep that literal only for
    # the exact replay vector; live capture mode inherits the server word
    # unless an operator supplies a fresh value explicitly.
    raw_csum = os.environ.get('AOV_UDP_HELLO_CSUM', '').strip()
    if raw_csum:
     try:
      candidate = bytes.fromhex(raw_csum)
      if len(candidate) == 4: hello_csum = candidate
     except ValueError:
      pass
    elif os.environ.get('AOV_UDP_EXACT_CAPTURE_SYN') == '1':
     hello_csum = bytes.fromhex('f60e0b0f')
    elif os.environ.get('AOV_UDP_CAPTURE_CHECKSUM') == '1':
     # The hello checksum is another client nonce.  It is unrelated to the
     # SYN-ACK checksum; reusing the server word causes the gateway to hold
     # the hello until timeout.  Keep an explicit override for replay tests.
     hello_csum = os.urandom(4)
   self.conn.send_data(hello_payload, payload_csum=hello_csum)
   deadline=time.monotonic()+4.0
   hello=None
   while time.monotonic()<deadline:
    kind,body=self.conn.recv(timeout=min(1.0,max(0.01,deadline-time.monotonic())))
    if kind == 'flow':
     # A flow burst is the server's invitation to acknowledge the transport
     # window.  The phone emits one 36-byte ACK per burst before the gateway
     # sends 0x1002 server hello.
     self.conn.send_ack()
     continue
    if kind=='data' and body and body[4:8]==bytes.fromhex('00081002'):
     hello=parse_server_hello(body); break
   if hello is None: raise RuntimeError('UDP server hello timed out after verified SYN-ACK')
   self.server_hello_received=True; self.key1=hello['key1']; self.tx=AES128CBCStream(self.key1); self.rx=AES128CBCStream(self.key1)
   self.conn.send_data(build_data_frame('00082001',2,self.tx.encrypt(build_login_plaintext(self.game_token)),21))
   self.cs_counter=2; self.login_sent=True; self.state='LOGIN_SENT'
   return self
  except Exception:
   self.close()
   raise
 def _send(self,payload):
  if not getattr(self,'sock',None): raise RuntimeError('UDP battle session is not connected')
  self.sock.sendto(bytes(payload),(self.host,int(self.port))); return len(payload)
 def _battle_pt(self, inner_csid, variant_6bytes):
  self.cs_counter += 1
  pt=bytearray(32)
  struct.pack_into('>I',pt,0,self.cs_counter)
  struct.pack_into('>I',pt,4,int(inner_csid))
  pt[8:12]=b'\x00\x00\x15\x86'
  value=bytes(variant_6bytes or b'')[:6]
  pt[20:20+len(value)]=value
  pt[26:32]=b'tsf4g'+bytes([random.randrange(16)])
  return bytes(pt)
 def _send_battle_cs(self, inner_csid, variant_6bytes):
  from Crypto.Cipher import AES
  if not self.conn or not self.key1: raise RuntimeError('UDP battle session is not connected')
  pt=self._battle_pt(inner_csid,variant_6bytes)
  enc=AES.new(self.key1,AES.MODE_CBC,iv=bytes(range(16))).encrypt(pt)
  from purepc.cs import frame_header
  frame=frame_header(self.cs_counter,len(enc),type_hex='00084013')+enc
  return self.conn.send_data(frame,flags=FLAGS_PSH_ACK)
 def send_cs(self,cs_type_hex,body=b'',metalen=0):
  return self.conn.send_data(bytes.fromhex(cs_type_hex)+bytes(body),flags=FLAGS_PSH_ACK)
 def send_heartbeat(self,hb_body=b''):
  return self.conn.send_data(bytes(hb_body),flags=FLAGS_ACK)
 def send_settlement(self): return self.send_battle_settlement()
 def send_relay_init(self,slot_id=None):
  slot_id=random.randrange(1,6) if slot_id is None else int(slot_id)
  return self._send_battle_cs(3103,struct.pack('>I',slot_id)+os.urandom(2))
 def send_relay_ready(self): return self._send_battle_cs(4850,b'\x01\x02\x93\x00'+os.urandom(2))
 def send_pick(self,hero_id):
  value=bytearray(6); struct.pack_into('<H',value,4,int(hero_id)&0xffff)
  return self._send_battle_cs(1240,bytes(value))
 def send_confirm(self): return self._send_battle_cs(1242,b'\x00'+os.urandom(5))
 def observe_s2c_tick(self):
  from Crypto.Cipher import AES
  if not self.conn: return None
  self.conn.sock.settimeout(0.1)
  try: raw=self.conn.sock.recv(2048)
  except Exception: return None
  idx=raw.find(b'\x33\x66\x00\x08')
  if idx<0 or idx+24>len(raw): return None
  if struct.unpack_from('>I',raw,idx+4)[0]!=540691: return None
  metalen=struct.unpack_from('<I',raw,idx+16)[0]; bl_w=metalen-20
  if not 1<=bl_w<=4: return None
  bodylen=int.from_bytes(raw[idx+20:idx+20+bl_w],'little'); start=idx+20+bl_w
  body=raw[start:start+bodylen]
  if len(body)!=bodylen or len(body)%16: return None
  try:
   pt=AES.new(self.key1,AES.MODE_CBC,iv=bytes(range(16))).decrypt(body)
   if struct.unpack_from('>I',pt,4)[0]!=1084: return None
   tick=struct.unpack_from('>H',pt,20)[0]
   self.world_tick=max(getattr(self,'world_tick',0),tick)
   return tick
  except Exception: return None
 def send_move(self,tick=None):
  if tick is None:
   self.observe_s2c_tick()
   if getattr(self,'world_tick',0)>0:
    tick=self.world_tick+1; self.world_tick=tick
   else:
    tick=getattr(self,'_move_tick',2); self._move_tick=tick+1
  return self._send_battle_cs(1083,struct.pack('>H',int(tick)&0xffff)+os.urandom(4))
 def send_battle_settlement(self):
  from Crypto.Cipher import AES
  if not self.conn or not self.key1: raise RuntimeError('UDP battle session is not connected')
  self.cs_counter+=1; pt=bytearray(48)
  struct.pack_into('>I',pt,0,self.cs_counter); struct.pack_into('>I',pt,4,20700)
  pt[8:12]=b'\x00\x00\x15\x86'; pt[20:24]=b'\x00\x00\x00\x01'; pt[24:28]=b'\x00\x00\x00\x04'
  pt[28:40]=os.urandom(12); pt[40:46]=b'tsf4g'+bytes([20]); pt[46:48]=os.urandom(2)
  enc=AES.new(self.key1,AES.MODE_CBC,iv=bytes(range(16))).encrypt(bytes(pt))
  # 0x85001 is the legacy 21-byte control-frame header (no compression flag).
  frame=(bytes.fromhex('33660008')+struct.pack('>I',0x85001)+b'\x00\x00\x00\x00'+
         struct.pack('<I',self.cs_counter)+struct.pack('<I',21)+bytes([len(enc)])+enc)
  return self.conn.send_data(frame,flags=FLAGS_PSH_ACK)
 def close(self):
  if self.conn: self.conn.close(); self.conn=None
  elif getattr(self,'sock',None): self.sock.close()
  self.sock=None
  self.state='CLOSED'
 def hold(self,duration,hb_body=b'',hb_interval=5,on_tick=None):
  if not getattr(self,'sock',None): raise RuntimeError('UDP battle session is not connected')
  end=time.monotonic()+max(0,duration); next_hb=0
  while time.monotonic()<end:
   if time.monotonic()>=next_hb: self.sock.sendto(bytes(hb_body),(self.host,int(self.port))); next_hb=time.monotonic()+hb_interval
   if on_tick: on_tick(end-time.monotonic())
   time.sleep(.05)
  return {'state':getattr(self,'state','CONNECTED'),'duration':duration}
 def play_battle(self,duration=119,hero_id=1,on_tick=None,move_interval=1):
  self.send_relay_init(); time.sleep(.5); self.send_pick(hero_id); time.sleep(.3)
  self.send_relay_ready(); time.sleep(.5); self.send_confirm(); time.sleep(.5)
  t0=time.monotonic(); last=0.0
  while time.monotonic()-t0 < max(0,float(duration)):
   now=time.monotonic()
   if now-last >= max(.05,float(move_interval)):
    self.send_move(); last=now
   self.observe_s2c_tick()
   if on_tick: on_tick(max(0,float(duration)-(time.monotonic()-t0)))
   time.sleep(.05)
  self.send_battle_settlement(); return True
