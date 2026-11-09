"""Resolve account shards through the recovered binary 6670 gateway.

An HTTP resolver remains supported when AOV_SHARD_URL is configured, which
keeps the local fixture boundary compatible with the earlier rebuild.
"""
from __future__ import annotations
import ipaddress, json, os, re, socket, struct, time, urllib.request
from pathlib import Path

GATEWAY_HOST = 'vn-dirsvr.aovmoba.com'
GATEWAY_PORT = 6670
_ROOT = Path(__file__).resolve().parent.parent / '_internal' / 'rt' / 'purepc'
_GUID_TEMPLATE = '5edeef444a83c2fc099c2e6d78bde941'
_USER_TEMPLATE = 'cmq.s3452'

def _parse_3e5_full(payload):
    m = re.search(rb'(\d{1,3}(?:\.\d{1,3}){3})\x00', bytes(payload))
    if not m: return None
    off = m.end()
    if off + 2 > len(payload): return None
    try: address = str(ipaddress.IPv4Address(m.group(1).decode('ascii')))
    except ValueError: return None
    port = struct.unpack_from('>H', payload, off)[0]
    return (address, port) if port else None

def _parse_3e5(packet):
    # parse_cspkgs returns bytes in body_full/payload. The legacy read_frames
    # wrapper also supplies a hex string named body; it is not always present.
    packet = packet or {}
    for field in ('body_full', 'payload', 'body'):
        value = packet.get(field)
        if not isinstance(value, (str, bytes, bytearray, memoryview)): continue
        try: raw = bytes.fromhex(value) if isinstance(value, str) else bytes(value)
        except ValueError: continue
        shard = _parse_3e5_full(raw)
        if shard: return shard
    return None


def _directory_frames(frames, state, log):
    """Inspect every frame, including a status coalesced with a redirect."""
    from .cs import parse_cspkgs
    for typ, seq, _raw, plain in frames:
        if typ == '00085002':
            words = [struct.unpack_from('>I', plain, off)[0]
                     for off in range(0, len(plain) - 3, 4)]
            status = dict(frame_type=typ, seq=seq, body_hex=plain.hex(),
                          server_status=words[0] if words else None, words=words)
            state['server_responses'].append(status)
            if log:
                log(f'[shard] SERVER type={typ} seq={seq} '
                    f'words={words} body_hex={plain.hex()}')
            continue
        for packet in parse_cspkgs(plain):
            csid = packet.get('csid')
            state['received_csids'].add(csid)
            if csid == 997:
                shard = _parse_3e5(packet)
                state['server_responses'].append(dict(
                    frame_type=typ, seq=seq, csid=csid,
                    body_hex=plain.hex(), shard=shard))
                if shard: state['shard'] = shard
                if log:
                    log(f'[shard] SERVER csid=997 (0x03e5) seq={seq} '
                        f'shard={shard} body_hex={plain.hex()}')

def _http_resolve(openid,gt,guid,username,base):
    payload=json.dumps({'openid':openid,'game_token':gt,'guid':guid,'username':username}).encode()
    req=urllib.request.Request(str(base).rstrip('/')+'/resolve',data=payload,headers={'Content-Type':'application/json'},method='POST')
    with urllib.request.urlopen(req,timeout=15) as r: out=json.loads(r.read().decode())
    if not isinstance(out,dict) or not out.get('host'): raise ValueError('shard response has no host')
    return out

def resolve_shard(openid,gt,guid,username,host=None,log=print,keep_open=False):
    configured=host or os.environ.get('AOV_SHARD_URL')
    if configured and str(configured).lower().startswith(('http://','https://')):
        return _http_resolve(openid,gt,guid,username,configured)
    from .cs import build_client_hello,parse_server_hello,build_login_plaintext,build_data_frame,parse_cspkgs
    from .crypto import AES128CBCStream
    from .uplevel_stateful import FrameReader,HS,build_cmd,enc_frame,enc_frame_raw
    gateway=str(host or configured or GATEWAY_HOST)
    if log: log(f'[shard] connecting gateway={gateway}:{GATEWAY_PORT}')
    from pve_trace import TraceSocket, receive_hello
    sock=TraceSocket(socket.create_connection((gateway,GATEWAY_PORT),timeout=10), f'{gateway}:{GATEWAY_PORT}'); close_socket=True
    try:
        sock.settimeout(5); sock.sendall(build_client_hello(str(openid))); hello=receive_hello(sock); key1=hello['key1']; tx=AES128CBCStream(key1); reader=FrameReader(key1); seq=2
        devreg=bytes.fromhex((_ROOT/'devreg_6670_dev11270.hex').read_text(encoding='ascii').strip())
        if guid and len(str(guid))==len(_GUID_TEMPLATE) and str(guid)!=_GUID_TEMPLATE: devreg=devreg.replace(_GUID_TEMPLATE.encode(),str(guid).encode(),1)
        if username and len(str(username))==len(_USER_TEMPLATE) and str(username)!=_USER_TEMPLATE: devreg=devreg.replace(_USER_TEMPLATE.encode(),str(username).encode(),1)
        # The 6670 gateway capture uses separator 0x2c; game-CS uses 0x40.
        # Keep it independently configurable because these are distinct
        # protocol routes.
        gateway_sep = os.environ.get('AOV_GATEWAY_LOGIN_SEP', '0x2c')
        try: gateway_sep = int(gateway_sep, 0)
        except ValueError: gateway_sep = 0x2c
        batch=bytearray(build_data_frame('00082001',seq,
                                         tx.encrypt(build_login_plaintext(str(gt), sep=gateway_sep)),21)); seq+=1
        for ph in HS: batch+=enc_frame(key1,seq,bytes.fromhex(ph)); seq+=1
        sock.sendall(bytes(batch)); handle=None; recv_bytes=0; recv_frames=0; recv_csids=set(); reject_hex=''; last_head=''; last_wire=''; deadline=time.time()+3.0
        while time.time()<deadline and handle is None:
            try: data=sock.recv(65536)
            except socket.timeout: continue
            if not data: break
            recv_bytes += len(data)
            if not last_head: last_head=data[:16].hex()
            if len(data) <= 64: last_wire=data.hex()
            for _typ,_sq,_raw,plain in reader.feed(data):
                recv_frames += 1
                if _typ == '00085002': reject_hex = plain.hex()
                for pk in parse_cspkgs(plain):
                    recv_csids.add(int(pk.get('csid')))
                    if pk.get('csid')==1014 and pk.get('c1'): handle=int(pk['c1']); break
                if handle is not None: break
        if not handle:
            if log: log(f'[shard] no handle bytes={recv_bytes} frames={recv_frames} '
                        f'csids={sorted(recv_csids)[:12]} head={last_head} wire={last_wire}')
            if log and reject_hex:
                detail = ''
                try:
                    raw = bytes.fromhex(reject_hex)
                    if len(raw) >= 8:
                        words = struct.unpack_from('>II', raw, 0)
                        detail = f' words={words[0]},{words[1]}'
                except (TypeError, ValueError, struct.error):
                    pass
                log(f'[shard] gateway reject_plain={reject_hex}{detail}')
            return {'ok':False,'err':'no handle','gateway':f'{gateway}:{GATEWAY_PORT}',
                    'reject': reject_hex or None}
        dr_seq=seq; patched=struct.pack('>I',dr_seq)+devreg[4:14]+struct.pack('>I',handle)+devreg[18:]; out=enc_frame_raw(key1,dr_seq,patched); seq+=1; out+=enc_frame_raw(key1,seq,build_cmd('0x4ed',handle,seq-2,seq)); seq+=1; sock.sendall(out)
        if log: log(f'[shard] gateway={gateway}:{GATEWAY_PORT} handle={handle} devreg+0x4ed sent')
        state = dict(shard=None, received_csids=set(), server_responses=[])
        server_closed = False; transport_error = None
        deadline=time.time()+4.0
        while time.time()<deadline and state['shard'] is None:
            try: data=sock.recv(65536)
            except socket.timeout: continue
            except OSError as exc:
                transport_error = str(exc)
                if log: log(f'[shard] gateway socket reset: {exc}')
                break
            if not data:
                server_closed = True
                break
            _directory_frames(reader.feed(data), state, log)
            if any(row['frame_type'] == '00085002' for row in state['server_responses']):
                break
        shard = state['shard']
        result={'ok':bool(shard),'shard':shard,'handle':handle,'gateway':f'{gateway}:{GATEWAY_PORT}',
                'received_csids': sorted(state['received_csids']),
                'server_responses': state['server_responses'],
                'server_closed': server_closed, 'transport_error': transport_error}
        statuses = [row for row in state['server_responses'] if row['frame_type'] == '00085002']
        if not shard:
            if statuses:
                last = statuses[-1]
                result['reject'] = (f"directory server frame=0x5002 status={last['server_status']} "
                                    f"body_hex={last['body_hex']}; no shard decoded")
            else:
                result['err'] = transport_error or ('directory closed without shard' if server_closed
                                                    else 'directory timed out without shard')
            if log: log(f"[shard] {result.get('reject') or result.get('err')}")
        # A redirect can precede a terminal status on the directory connection.
        # Retain both as evidence; use the returned address with a new socket.
        if shard and keep_open and not statuses:
            result['sock']=sock; close_socket=False
        return result
    finally:
        if close_socket:
            try: sock.close()
            except OSError: pass
