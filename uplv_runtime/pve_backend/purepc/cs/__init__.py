from __future__ import annotations
import os,struct,socket
from purepc.crypto import AES128CBCStream, aes_cbc_once, IV16
MAGIC=bytes.fromhex('33660008'); GAME_ID='1137'; META_VER=5402
TS=b'tsf4g'

def build_client_hello(openid):
 oid=str(openid).encode(); body=bytes.fromhex('0002030000271000000065803103000000')+bytes([len(oid)+1])+oid+bytes.fromhex('00000000000000000000000300000000')
 return MAGIC+bytes.fromhex('00081001')+b'\0'*4+b'\1\0\0\0'+struct.pack('<I',20+len(body))+body
def parse_server_hello(frame):
 b=bytes(frame); i=b.find(bytes.fromhex("100210"))
 if i<0: raise ValueError("no 1002-10 tag in server-hello")
 # Some gateways coalesce the first encrypted CS frame with the hello. Keep
 # bytes beginning at the next CS magic so the caller can feed them to its
 # normal frame reader instead of silently dropping the 1014 handle packet.
 next_magic=b.find(MAGIC,i+19)
 return {"key1":b[i+3:i+19],"raw":b,
         "tail":(b[next_magic:] if next_magic >= 0 else b'')}
def build_login_plaintext(game_token,game_id=GAME_ID,sep=None):
 """Build the CS login body from the recovered wire captures.

 The final byte is the trailer length marker (``07``), not seven zero
 bytes.  The separator is route-specific: the game CS capture uses ``0x40``
 while the directory gateway capture uses ``0x2c``.  Callers can override it
 explicitly or with ``AOV_LOGIN_SEP``.
 """
 explicit_sep = sep is not None
 if sep is None:
  raw=os.environ.get('AOV_LOGIN_SEP',
                     os.environ.get('PVE1V1_LOGIN_SEP','0x40')).strip()
  try: sep=int(raw,0)
  except ValueError: sep=0x40
 if not 0 <= int(sep) <= 255:
  raise ValueError('login separator must fit in one byte')
 gt=str(game_token).encode()
 # 0xcf was the pre-capture helper's sentinel.  Keep its old padding shape
 # for callers that explicitly request it; the live defaults and the recovered
 # 0x2c/0x40 routes use the single 0x07 trailer byte above.
 trailer = bytes(7) if explicit_sep and int(sep) == 207 else bytes([7])
 return (bytes.fromhex('ffff0004') + str(game_id).encode() +
         bytes.fromhex('003f010029') + b'J' + gt + bytes(19) +
         bytes([int(sep)]) + b'tsf4g' + trailer)
def build_data_frame(ftype_hex,seq,body,metalen=21):
 body=bytes(body); bl_w=metalen-20; hdr=MAGIC+bytes.fromhex(ftype_hex)+b'\0'*4+struct.pack('<I',int(seq))+struct.pack('<I',int(metalen)); hdr+=len(body).to_bytes(bl_w,'little'); return hdr+body

def pad_trailer(payload):
    """Apply the original CS trailer/padding rule recovered from bytecode."""
    payload=bytes(payload); r4=len(payload)&15
    # Original bytecode slices P[aligned:] and calls bytes([padding]),
    # not P[:aligned] and bytes(padding). Preserve every payload byte.
    pad = 16-r4 if r4 <= 10 else 32-r4
    return payload + b'\0'*(pad-6) + TS + bytes([pad])


def unpack_lz4_payload(padded):
    """Decode a captured CS LZ4 block after removing its AES trailer."""
    import lz4.block
    padded = bytes(padded)
    if len(padded) < 6 or padded[-6:-1] != TS:
        raise ValueError('compressed CS body has no tsf4g trailer')
    padding = padded[-1]
    if not 6 <= padding <= 21 or padding > len(padded):
        raise ValueError('compressed CS body has invalid trailer length')
    return lz4.block.decompress(padded[:-padding], uncompressed_size=4 * 1024 * 1024)

def frame_header(seq, n, type_hex='00084013', compression=None):
    """Build the captured CS encrypted-frame header."""
    n=int(n)
    flag = int(bool(compression)) if compression is not None else (1 if n>=128 else 0)
    return MAGIC+bytes.fromhex(type_hex)+b'\0'*4+struct.pack('<I',int(seq))+bytes((22,0,0,(n>>8)&255,n&255,flag))

def _meta_override(payload):
    value=__import__('os').environ.get('AOV_SEND_META')
    if not value: return bytes(payload)
    try:
        target=bytes.fromhex('0000'+value[-4:])
        return bytes(payload).replace(b'\0\0\x15\x1a',target)
    except Exception:
        return bytes(payload)

def enc_frame_raw(key1, seq, plaintext_padded, *, compression=None):
    body=aes_cbc_once(key1,_meta_override(plaintext_padded),encrypt=True,iv=IV16)
    return frame_header(seq,len(body), compression=compression)+body

def enc_frame(key1, seq, cspkt):
    body=aes_cbc_once(key1,_meta_override(pad_trailer(cspkt)),encrypt=True,iv=IV16)
    return frame_header(seq,len(body))+body

class WireReader:
    """Incremental reader for the CS header/body framing."""
    def __init__(self): self.buf=bytearray()
    def feed(self,data):
        self.buf.extend(data); out=[]
        while len(self.buf)>=22:
            if self.buf[:4]!=MAGIC:
                i=self.buf.find(MAGIC,1)
                if i<0: self.buf.clear(); break
                del self.buf[:i]; continue
            # Reject frames (00085002) emitted by the current gateway have a
            # 21-byte header; normal encrypted frames use 22 bytes.
            header_len=int(self.buf[16])
            if header_len not in (21,22): header_len=22
            n=(self.buf[19]<<8)|self.buf[20]
            total=header_len+n
            if len(self.buf)<total: break
            out.append(bytes(self.buf[:total])); del self.buf[:total]
        return out

def parse_cspkgs(plain):
    """Parse the fixed CS package layout recovered from the original client.

    Packages are identified by the metadata marker at ``offset + 4``. The
    first sixteen bytes are ``csid, marker, c1, c2``; the captured protocol
    does not contain a generic total/meta/subcmd envelope here. Keeping the
    original offsets is required for the 1014 handle and role counters.
    """
    plain = bytes(plain); out = []; i = 0
    markers = (bytes.fromhex('0000151a'), bytes.fromhex('00001586'))
    while i + 16 <= len(plain):
        if plain[i + 4:i + 8] in markers:
            try:
                csid = struct.unpack_from('>I', plain, i)[0]
                c1 = struct.unpack_from('>I', plain, i + 8)[0]
                c2 = struct.unpack_from('>I', plain, i + 12)[0]
            except struct.error:
                break
            out.append({
                'csid': csid, 'c1': c1, 'c2': c2, 'off': i,
                # The original decoder keeps a short body view for grant
                # status and handle fields. ``body_full`` below preserves the
                # complete captured payload for role/profile decoding.
                'payload': plain[i + 16:i + 56],
            })
            i += 16
        else:
            i += 1
    # Preserve the complete body for device/role packets. The next package
    # marker or the protocol trailer bounds each payload.
    for n, packet in enumerate(out):
        start = packet['off'] + 16
        if n + 1 < len(out):
            end = out[n + 1]['off']
        else:
            end = plain.find(b'tsf4g', start)
            if end < start:
                end = len(plain)
        packet['body_full'] = plain[start:end]
    return out

def grant_response_status(blob):
    """Extract the confirmed grant status field from a response blob."""
    b=bytes(blob)
    for marker in (b'\x00\x00\x03\xeb',b'\x00\x00\x03\xef'):
        i=b.find(marker)
        if i>=0 and i+8<=len(b): return struct.unpack_from('>I',b,i+4)[0]
    return None
def build_cspkg(csid,payload,subcmd=4352):
 inner=struct.pack('>III',int(csid),META_VER,int(subcmd))+struct.pack('>I',len(payload))+bytes(payload); return struct.pack('>I',len(inner)+4)+inner
def iter_cspkgs(plain):
 off=0
 while off+20<=len(plain):
  total,csid,meta,sub,n=struct.unpack_from('>5I',plain,off)
  if meta!=META_VER or off+20+n>len(plain): off+=4; continue
  yield {"csid":csid,"subcmd":sub,"payload":plain[off+20:off+20+n]}; off+=4+total
def parse_cspkg(plain,off=0):
 total,csid,meta,sub,n=struct.unpack_from('>5I',plain,off); return csid,sub,plain[off+20:off+20+n],off+4+total
def parse_role_profile(plain):
 i=bytes(plain).find(bytes.fromhex('00001520'))
 if i<0:return None
 p=i+16; out={}
 try:
  out['level']=struct.unpack_from('>I',plain,p)[0]; p+=4; nlen=struct.unpack_from('>I',plain,p)[0]; p+=4; out['name']=bytes(plain[p:p+nlen]).rstrip(b'\0').decode('utf-8','replace'); p+=nlen; ulen=struct.unpack_from('>I',plain,p)[0]
  if 0<ulen<4096: out['avatar_url']=bytes(plain[p+4:p+4+ulen]).rstrip(b'\0').decode('utf-8','replace')
 except (struct.error,UnicodeError): pass
 return out
def parse_role_profile_level(plain):
 i=bytes(plain).find(bytes.fromhex('00001520'))
 if i<0:return None
 try:
  v=struct.unpack_from('>I',plain,i+16)[0]; return v if 1<=v<=200 else None
 except struct.error:return None
class CSClient:
 def __init__(self,host,port,openid,game_token,timeout=20,proxy=None): self.host,self.port,self.openid,self.game_token,self.timeout,self.proxy=host,port,openid,game_token,timeout,proxy; self.sock=None; self.key1=None; self.reader=None; self.seq=1
 def _recv_some(self,n=4096):
  if not self.sock: raise RuntimeError('CS session is not connected')
  self.sock.settimeout(self.timeout); data=self.sock.recv(n)
  if not data: raise ConnectionError('CS server closed during handshake')
  return data
 def connect(self):
  import socket
  self.sock=socket.create_connection((self.host,self.port),self.timeout)
  self.sock.sendall(build_client_hello(self.openid))
  buf=bytearray();
  while len(buf)<64:
   data=self._recv_some(); buf.extend(data)
   try: self.key1=parse_server_hello(buf)['key1']; break
   except ValueError: continue
  if not self.key1: raise ValueError('CS server hello did not contain key1')
  # Login is a normal encrypted 00082001 data frame.  Sending the plaintext
  # body directly (the old helper did this) skips the CS framing header and
  # makes the server answer with the generic login reject.
  self.seq=2
  tx=AES128CBCStream(self.key1)
  self.sock.sendall(build_data_frame('00082001',self.seq,
                                     tx.encrypt(build_login_plaintext(self.game_token)),21))
  self.seq+=1
  self.reader=WireReader(); return self
 def send_command(self,csid,payload,subcmd=0):
  if not self.sock: raise RuntimeError('CS session is not connected')
  packet=build_cspkg(csid,payload,subcmd)
  if self.key1:
   frame=enc_frame(self.key1,self.seq,packet); self.seq=(self.seq+1)&0xffffffff
  else: frame=struct.pack('>I',len(packet))+packet
  self.sock.sendall(frame); return len(frame)
 def poll(self,max_frames=32):
  if not self.sock: raise RuntimeError('CS session is not connected')
  if self.key1:
   self.sock.settimeout(self.timeout); out=[]; reader=self.reader or WireReader(); self.reader=reader
   for _ in range(max_frames):
    try: data=self.sock.recv(65536)
    except socket.timeout: break
    if not data: break
    for fr in reader.feed(data): out.append(fr)
   return out
  self.sock.settimeout(self.timeout); out=[]
  for _ in range(max_frames):
   try: h=self.sock.recv(4)
   except TimeoutError: break
   if not h: break
   if len(h)<4: raise ValueError('truncated CS frame header')
   n=struct.unpack('>I',h)[0]; body=b''
   while len(body)<n:
    chunk=self.sock.recv(n-len(body))
    if not chunk: raise ValueError('truncated CS frame body')
    body+=chunk
   out.append(body)
  return out
 def close(self):
  if self.sock:self.sock.close(); self.sock=None
