"""Production transport boundary recovered from the original ``purepc_run``.

The packet builders and CS handshake are reused from the rebuilt modules.  The
proprietary create/replay command bodies are intentionally not synthesized;
when they are unavailable the result reports the exact blocked stage.
"""
from __future__ import annotations
import json, os, re, random, uuid, hashlib, time
from pathlib import Path

_ASSET_ROOT=Path(__file__).resolve().parent.parent/'_internal'/'rt'/'purepc'/'room_assets'
_RT_ROOT=_ASSET_ROOT.parent

# These values and replacement rules are recovered from the original
# purepc_run.pyc.  They describe the captured device-registration payload;
# they do not emulate an Android operating system.
_CAP_USER = 'cmq.s3790'
_CAP_GUID = '2886e41bc59624d4011344502fdf7efb'
_CAP_STOK = '1792047101920-125420161613820929'
_CAP_CR_USER = 'cmq.s3790'
_CAP_CR_GUID = '2886e41bc59624d4011344502fdf7efb'
_SEQ_FILE = _RT_ROOT/'seq6670.json'

# Successful phone .36 CSID 1002 capture, 2026-10-30 (resources 1.64.1.11).
# Offsets refer to the decompressed CS packet, excluding its wire sequence.
CURRENT_REGISTRATION_VERSIONS = bytes.fromhex('030000870300008c')

# Addresses found in the recovered client.  They are only a fallback when the
# account-specific shard resolver is not configured; a resolver result always
# takes precedence.  Keep this list in one place so a deployment can override
# it with AOV_ROLE_CS_POOL without changing the protocol code.
DEFAULT_ROLE_CS = '148.222.90.198'
SHARD_POOL = (
    '148.222.90.198', '148.222.90.234', '148.222.90.122',
    '148.222.90.124', '148.222.90.2', '148.222.90.109',
    '148.222.90.156', '148.222.91.2', '148.222.93.33',
)


def _endpoint_candidates(role_cs, port):
    """Return configured CS endpoints in deterministic order.

    ``role_cs`` is normally the resolved account shard.  The pool is opt-in
    through ``AOV_ROLE_CS_POOL`` so an absent resolver does not silently send
    an account to an arbitrary shard.  Values may be ``host`` or ``host:port``.
    """
    raw = str(role_cs or '').strip()
    if raw and raw != 'resolve':
        return [raw]
    configured = os.environ.get('AOV_ROLE_CS')
    if configured:
        return [x.strip() for x in configured.split(',') if x.strip()]
    pool = os.environ.get('AOV_ROLE_CS_POOL')
    if pool:
        return [x.strip() for x in pool.split(',') if x.strip()]
    return [DEFAULT_ROLE_CS]


def _split_endpoint(endpoint, default_port):
    raw = str(endpoint).strip()
    if raw.startswith('[') and ']' in raw:  # tolerate an IPv6-style value
        host, _, suffix = raw[1:].partition(']')
        suffix = suffix[1:] if suffix.startswith(':') else suffix
        return host, int(suffix or default_port)
    host, sep, p = raw.rpartition(':')
    if sep and p.isdigit() and host:
        return host, int(p)
    return raw, int(default_port)

def _devreg_full_plain():
    """Load the original captured device-registration plaintext and handle."""
    obj = json.loads(_SEQ_FILE.read_text(encoding='utf-8'))
    handle = obj.get('cap_handle')
    frames = [f for f in obj.get('frames', []) if f.get('csid') == 1002]
    if not frames:
        raise ValueError('device-registration frame (csid=1002) is unavailable')
    return bytes.fromhex(frames[0]['hex']), int(handle or 0)

def _find_qimei(body):
    """Return the captured QIMEI-like field, when present."""
    for hit in re.findall(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', bytes(body)):
        try:
            value = hit.decode()
        except UnicodeDecodeError:
            continue
        if value != _CAP_GUID and len(value) in (31, 32):
            return value
    return None

def _rand_device_fields(body, username=''):
    """Apply the bytecode's deterministic-per-account identity randomization.

    Only fields whose formats are evidenced in the captured payload are
    replaced: UUID, K0.. MAC and a standalone 19-digit identifier.
    """
    seed = int(hashlib.md5(('aovdev:' + str(username)).encode()).hexdigest()[:16], 16)
    rng = random.Random(seed)
    b = bytes(body)
    m = re.search(rb'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', b)
    if m:
        replacement = str(uuid.UUID(int=rng.getrandbits(128))).encode()
        b = b[:m.start()] + replacement + b[m.end():]
    m = re.search(rb'K0[0-9A-F]{2}(?:-[0-9A-F]{2}){15}', b)
    if m:
        raw = [rng.randrange(256) for _ in range(16)]
        replacement = ('K0%02X' % raw[0]) + ''.join('-%02X' % x for x in raw[1:])
        b = b[:m.start()] + replacement.encode() + b[m.end():]
    m = re.search(rb'(?<![0-9])[0-9]{19}(?![0-9])', b)
    if m:
        replacement = str(rng.randrange(10**18, 10**19)).encode()
        b = b[:m.start()] + replacement + b[m.end():]
    return b

def build_devreg(username='', guid='', qimei=''):
    """Build the original (stale capture) device-registration plaintext.

    Replacement is length-preserving, matching the original implementation;
    invalid-length values are deliberately ignored rather than corrupting the
    binary structure.
    """
    body, handle = _devreg_full_plain()
    captured_qimei = _find_qimei(body)
    if guid and len(str(guid)) == len(_CAP_GUID):
        body = body.replace(_CAP_GUID.encode(), str(guid).encode(), 1)
    if username and len(str(username)) == len(_CAP_USER):
        body = body.replace(_CAP_USER.encode(), str(username).encode(), 1)
    if qimei and captured_qimei and len(str(qimei)) == len(captured_qimei) \
            and os.environ.get('AOV_DEVREG_KEEP_QIMEI') != '1':
        body = body.replace(captured_qimei.encode(), str(qimei).encode(), 1)
    if os.environ.get('AOV_DEVREG_RANDOM', '1') != '0':
        body = _rand_device_fields(body, username)
    return body, handle

def build_devreg_fresh(username='', guid='', qimei='', *, seq=None, live_handle=None):
    """Patch fields in the decompressed registration, then compress again."""
    import struct
    import lz4.block
    from .cs import unpack_lz4_payload, pad_trailer
    obj=json.loads((_ASSET_ROOT/'devreg_fresh.json').read_text(encoding='utf-8'))
    capture = bytes.fromhex(obj['pt'])
    plain = bytearray(unpack_lz4_payload(capture[4:]))
    if plain[:8] != bytes.fromhex('000003ea00001586'):
        raise ValueError('unexpected fresh registration header')
    if plain[16:24] not in (
            bytes.fromhex('030000870300008a'),
            bytes.fromhex('030000870300008b'), CURRENT_REGISTRATION_VERSIONS):
        raise ValueError('unexpected fresh registration version layout')
    plain[16:24] = CURRENT_REGISTRATION_VERSIONS
    handle = int.from_bytes(plain[8:12], 'big')
    # The final field in the verified capture is a big-endian length followed
    # by the account name and its NUL. Patch the length as well as the value.
    marker = struct.pack('>I', 10) + b'cmq.s3813\0'
    if not plain.endswith(marker):
        raise ValueError('fresh registration account field is not recognized')
    if username:
        raw = str(username).encode('utf-8')
        if b'\0' in raw or len(raw) > 255:
            raise ValueError('invalid registration account name')
        plain[-len(marker):] = struct.pack('>I', len(raw) + 1) + raw + b'\0'
    if live_handle is not None:
        plain[8:12] = struct.pack('>I', int(live_handle))
    sequence = int.from_bytes(capture[:4], 'big') if seq is None else int(seq)
    compressed = lz4.block.compress(bytes(plain), store_size=False)
    # Sequence is outside the compressed block in client-to-server packets.
    return pad_trailer(struct.pack('>I', sequence) + compressed), handle

def build_device_registration(identity, username='', *, fresh=True):
    """Return ``(payload, handle, source)`` for a device identity record.

    ``fresh`` follows the original run path.  The fresh capture has a fixed
    Android metadata block and only its fixed-width account marker is patched;
    the legacy capture is the path that supports GUID/QIMEI replacement.
    """
    identity = identity or {}
    if fresh:
        payload, handle = build_devreg_fresh(username, identity.get('guid', ''), identity.get('qimei', ''))
        return payload, handle, 'fresh-capture'
    payload, handle = build_devreg(username, identity.get('guid', ''), identity.get('qimei', ''))
    return payload, handle, 'legacy-capture'


def _fresh_stoken():
    """Create the same fixed-width stoken shape used by the original runner."""
    prefix = str(int(time.time() * 1000))
    suffix_len = max(1, len(_CAP_STOK) - len(prefix) - 1)
    return f'{prefix}-{random.randint(0, 10 ** suffix_len - 1):0{suffix_len}d}'


def _patch_raw_capture(frame, seq, *, handle_old=None, handle_new=None,
                       stok=True):
    """Patch only fields the original capture path patched for raw frames.

    Device-registration and the following 1261 frame are raw captured
    packets. Their command counters are part of the capture and must not be
    rewritten as generic live command counters.
    """
    import struct
    pl = bytearray.fromhex(frame.get('hex', ''))
    if len(pl) < 4:
        raise ValueError('captured CS frame is shorter than its sequence field')
    pl[:4] = struct.pack('>I', int(seq) & 0xffffffff)
    if handle_old and handle_new is not None:
        pl = bytearray(bytes(pl).replace(
            struct.pack('>I', int(handle_old) & 0xffffffff),
            struct.pack('>I', int(handle_new) & 0xffffffff), 1))
    if stok:
        fresh = _fresh_stoken()
        pl = bytearray(bytes(pl).replace(_CAP_STOK.encode(), fresh.encode(), 1))
    return bytes(pl)


def _patch_create_capture(frame, seq, *, username='', msdk_oid=''):
    """Patch create-role capture exactly as the recovered ``_patchf`` does."""
    import struct
    pl = bytearray.fromhex(frame.get('hex', ''))
    if len(pl) < 4:
        raise ValueError('captured create frame is shorter than its sequence field')
    pl[:4] = struct.pack('>I', int(seq) & 0xffffffff)
    body = bytes(pl)
    if username:
        raw = str(username).encode()
        if len(raw) < len(_CAP_CR_USER):
            raw = raw + _CAP_CR_USER.encode()[len(raw):]
        elif len(raw) > len(_CAP_CR_USER):
            raw = raw[:len(_CAP_CR_USER)]
        if raw != _CAP_CR_USER.encode():
            body = body.replace(_CAP_CR_USER.encode(), raw, 1)
    if msdk_oid and len(str(msdk_oid)) == len(_CAP_CR_GUID):
        body = body.replace(_CAP_CR_GUID.encode(), str(msdk_oid).encode(), 1)
    return body

def _build_1520(seq, username, c1):
    """Patch the role/profile 0x1520 template from bundled room assets."""
    candidates=sorted(_ASSET_ROOT.glob('*1520*.json'))
    if not candidates: raise FileNotFoundError('1520 template asset is unavailable')
    obj=json.loads(candidates[0].read_text(encoding='utf-8')); b=bytearray.fromhex(obj.get('pt',''))
    marker=b'cmq.s3813'; nm=str(username or '').encode()[:len(marker)].ljust(len(marker),b' ')
    if marker in b: b=bytearray(bytes(b).replace(marker,nm,1))
    if len(b)>=20:
        import struct
        struct.pack_into('>I',b,0,int(seq)&0xffffffff); struct.pack_into('>I',b,12,int(c1)&0xffffffff)
    return bytes(b)


def build_create_role(frame, seq, username, guid, c1):
    """Rebuild captured 1008 fields inside LZ4; preserve unknown fields."""
    import struct
    import lz4.block
    from .cs import unpack_lz4_payload, pad_trailer
    capture = bytes.fromhex(frame['hex'])
    plain = bytearray(unpack_lz4_payload(capture[4:]))
    if plain[:8] != bytes.fromhex('000003f000001586'):
        raise ValueError('unexpected create-role command')
    for old, new in ((_CAP_CR_USER, username), (_CAP_CR_GUID, guid)):
        value = str(new).encode('utf-8')
        if not value or b'\0' in value or len(value) > 255:
            raise ValueError('invalid create-role identity field')
        captured = old.encode() + b'\0'
        marker = struct.pack('>I', len(captured)) + captured
        if bytes(plain).count(marker) != 1:
            raise ValueError('create-role identity field not found uniquely')
        plain = bytearray(bytes(plain).replace(marker, struct.pack('>I', len(value)+1)+value+b'\0', 1))
    struct.pack_into('>II', plain, 8, int(c1), int(seq)-2)
    return pad_trailer(struct.pack('>I', seq) + lz4.block.compress(bytes(plain), store_size=False))

def scan(blob, known_uid=None):
    from .runtime_decoder import decode_purepc
    return decode_purepc(bytes(blob), known_uid=known_uid)

def _record_level(state, level, source, seq=None):
    if type(level) is int and 1 <= level <= 200:
        state['level'] = level
        state.setdefault('level_evidence', []).append({
            'level': level, 'source': source, 'seq': seq,
            'time': time.time(),
        })
        if state.get('progress_log'):
            state['progress_log'](f'[level] level={level} source={source} seq={seq}')


def _level_result(state, target, before, stage, endpoint, rounds=0):
    level = state.get('level')
    confirmed = bool(state.get('level_evidence')) and type(level) is int
    reached = confirmed and level >= target
    exp_rows = [row for row in state.get('level_evidence', [])
                if row.get('csid') in (1003, 1015)
                and type(row.get('pvp_exp')) is int]
    exp_before = exp_rows[0]['pvp_exp'] if exp_rows else None
    exp_after = exp_rows[-1]['pvp_exp'] if exp_rows else None
    same_level = bool(exp_rows and exp_rows[0].get('level') == exp_rows[-1].get('level'))
    same_uid = bool(exp_rows and exp_rows[0].get('uid')
                    and exp_rows[0].get('uid') == exp_rows[-1].get('uid'))
    exp_delta = exp_after - exp_before if len(exp_rows) >= 2 and same_level and same_uid else None
    return {
        'ok': bool(reached and not state.get('reject') and not state.get('transport_error')),
        'stage': stage, 'target': target, 'level_before': before,
        'level_after': level, 'level_evidence': state.get('level_evidence', []),
        'exp_before': exp_before, 'exp_after': exp_after,
        'exp_delta_same_level': exp_delta,
        'exp_increase_observed': exp_delta is not None and exp_delta > 0,
        'reject': state.get('reject') or state.get('transport_error') or (None if reached else 'target_level_not_confirmed'),
        'grant_status': state.get('grant_status'), 'rounds': rounds,
        'role_cs': endpoint, 'frames_received': state.get('frames_seen', 0),
        'received_csids': sorted(state.get('received_csids', ())),
        'server_closed': state.get('server_closed', False),
        'transport_error': state.get('transport_error'),
        'identity_responses': state.get('identity_responses', []),
    }


def _pump_state(sock, reader, seconds, state, initial=b''):
    """Read encrypted CS frames and update the state used by the original run."""
    from .uplevel_stateful import read_frames
    rows = []
    if initial:
        # parse_server_hello may have consumed the first encrypted frame in
        # the same recv() call.  Decode that buffered tail before blocking on
        # the socket again.
        rows.extend(reader.feed(bytes(initial)))
        decoded = []
        for typ, seq, raw, plain in rows:
            decoded.append({'reject': typ == '00085002', 'seq': seq,
                            'raw_body': raw.hex(), 'dec_body': plain.hex()})
            from .cs import parse_cspkgs, parse_role_profile
            for pk in parse_cspkgs(plain):
                entry = dict(pk); entry['body'] = entry.pop('payload').hex()
                if isinstance(entry.get('body_full'), (bytes, bytearray)):
                    entry['body_full'] = bytes(entry['body_full']).hex()
                decoded.append(entry)
                profile = parse_role_profile(plain)
                if profile and profile.get('level') is not None:
                    decoded.append({'role_profile': profile,
                                    'role_profile_level': profile['level']})
        rows = decoded
    rows.extend(read_frames(sock, reader, seconds, stop_csids=()))
    if os.environ.get('AOV_DEBUG_FRAMES') == '1' and rows:
        for _row in rows:
            if _row.get('closed'):
                print('[frame] closed')
            elif _row.get('transport_error'):
                print(f"[frame] transport={_row.get('transport_error')}")
            elif _row.get('reject'):
                print(f"[frame] reject type seq={_row.get('seq')} raw={str(_row.get('raw_body',''))[:32]} dec={str(_row.get('dec_body',''))[:32]}")
            elif _row.get('csid') is not None:
                print(f"[frame] csid={_row.get('csid')} c1={_row.get('c1')} c2={_row.get('c2')} body_len={len(_row.get('body',''))//2}")
            else:
                print(f"[frame] type seq={_row.get('seq')} body_len={len(_row.get('dec_body',''))//2}")
    state['frames_seen'] = state.get('frames_seen', 0) + sum(1 for row in rows if 'raw_body' in row)
    state.setdefault('received_csids', set()).update(
        int(row['csid']) for row in rows if row.get('csid') is not None
    )
    if any(row.get('closed') for row in rows):
        state['server_closed'] = True
    for row in rows:
        if row.get('transport_error'):
            state['transport_error'] = row['transport_error']
    for row in rows:
        if row.get('reject'):
            srv_code = row.get('server_status')
            if srv_code is None and len(row.get('dec_body', '')) >= 8:
                try: srv_code = int.from_bytes(bytes.fromhex(row['dec_body'][:8]), 'big')
                except Exception: pass
            if srv_code == 7 and (state.get('handle') or state.get('level_evidence') or state.get('received_csids')):
                # Status 7 is the server's lobby end-of-burst signal, not a fatal rejection!
                state['lobby_burst_done'] = True
            else:
                state['reject'] = row.get('dec_body') or row.get('raw_body')
                state['reject_status'] = srv_code
        if row.get('role_profile'):
            _record_level(state, row['role_profile'].get('level'), 'role_profile', row.get('seq'))
        if row.get('csid') is None:
            continue
        csid = int(row['csid']); state['csids'].add(csid)
        if csid == 997:
            from .shard_resolve import _parse_3e5
            redirect = _parse_3e5(row)
            if redirect:
                state['redirect'] = redirect
                state['redirect_evidence'] = dict(csid=997, seq=row.get('seq'),
                    body_hex=row.get('body_full') or row.get('body'), endpoint=list(redirect))
        body = bytes.fromhex(row.get('body','')) if row.get('body') else b''
        c1 = row.get('c1')
        if isinstance(c1, int) and 0 < c1 < 0x10000000:
            state['last_c1'] = max(int(state.get('last_c1') or 0), c1)
        if csid == 1014 and len(body) >= 4:
            # The server handle is the package c1 counter. Older rebuilds
            # incorrectly read the first four payload bytes, leaving the
            # handle unset and causing the next 1261 frame to be rejected.
            state['handle'] = int(c1) if isinstance(c1, int) else int.from_bytes(body[:4], 'big')
        if csid == 22351 and len(body) >= 4:
            state['grant_status'] = int.from_bytes(body[:4], 'big')
        if csid in (1190, 1009):
            full = bytes.fromhex(row.get('body_full') or row.get('body', ''))
            if len(full) >= 4:
                code = int.from_bytes(full[:4], 'big', signed=True)
                if code:
                    state['reject'] = f'server_error_csid_{csid}_code_{code}'
                    if state.get('progress_log'):
                        state['progress_log'](f'[server-error] csid={csid} code={code}')
        if csid == 1003:
            from .dr_role_decode import decode_login_role
            full = bytes.fromhex(row.get('body_full') or row.get('body', ''))
            profile = decode_login_role(full, state.get('openid'))
            if profile:
                _record_level(state, profile['pvp_level'], 'role_login_rsp', row.get('seq'))
                state['level_evidence'][-1].update(csid=1003, uid=profile['uid'],
                    pvp_exp=profile['pvp_exp'], offset=24, body_prefix_hex=full[:40].hex())
                state['pvp_exp'] = profile['pvp_exp']
        if csid == 1015 and state.get('level_evidence'):
            from .dr_role_decode import decode_level_update
            full = bytes.fromhex(row.get('body_full') or row.get('body', ''))
            profile = decode_level_update(full)
            if profile:
                _record_level(state, profile['pvp_level'], 'role_level_update', row.get('seq'))
                state['level_evidence'][-1].update(csid=1015, pvp_exp=profile['pvp_exp'],
                    offset=0, body_hex=full.hex(), uid=state.get('openid'))
                state['pvp_exp'] = profile['pvp_exp']
        if csid in (1007, 1009, 4103):
            state.setdefault('identity_responses', []).append({
                'csid': csid, 'seq': row.get('seq'),
                'body_hex': row.get('body_full') or row.get('body', ''),
            })
        if csid in (4318, 2011, 2023, 2022, 4110, 4401, 1007, 4103):
            role_body = bytes.fromhex(row.get('body_full','')) if row.get('body_full') else body
            state['role_blob'] = (state.get('role_blob', b'') + role_body)[-1048576:]
            try:
                from .dr_role_decode import _decode_level
                decoded=_decode_level(state['role_blob'])
                level = decoded.get('pvp_level')
                if type(level) is int and 1 <= level <= 200:
                    _record_level(state, level, 'role_binary_anchor', row.get('seq'))
                    # Do not repeatedly decode the first, now stale snapshot.
                    state['role_blob'] = b''
            except Exception:
                pass
    return rows

def _send_capture_frames(sock, key1, seq, frames, *, role=False):
    from .uplevel_stateful import enc_frame_raw
    import struct
    batch=bytearray(); sent=0
    for f in frames:
        if f.get('typ') not in ('data','00084013',None): continue
        raw=f.get('hex')
        if not raw: continue
        pl=bytearray.fromhex(raw); pl[:4]=struct.pack('>I',seq)
        batch += enc_frame_raw(key1,seq,bytes(pl)); seq += 1; sent += len(pl)
    if batch: sock.sendall(bytes(batch))
    return seq,sent

def _send_plain_capture_frames(sock, key1, seq, frames, *, c1=None, replace=None):
    """Encrypt captured plaintext CS packets after patching sequence/counter."""
    from .uplevel_stateful import enc_frame_raw
    from .cs import unpack_lz4_payload, pad_trailer
    import lz4.block
    import struct
    batch=bytearray(); sent=0
    for f in frames:
        raw=f.get('plain_hex') or f.get('hex')
        if not raw: continue
        pl=bytearray.fromhex(raw)
        compressed = int.from_bytes(pl[4:8], 'big') != int(f['csid'])
        if compressed:
            pl = bytearray(pl[:4] + unpack_lz4_payload(pl[4:]))
        pl[:4]=struct.pack('>I',seq)
        if c1 is not None and len(pl)>=16:
            # Captured commands carry the live counter pair immediately after
            # the 0x1586 metadata marker. The second counter must track the
            # previous wire sequence; leaving the captured value in place
            # causes the game server to silently ignore the command.
            mp=bytes(pl).find(b'\x00\x00\x15\x86')
            if mp >= 0 and len(pl) >= mp + 12:
                pl[mp+4:mp+8]=struct.pack('>I',int(c1)&0xffffffff)
                pl[mp+8:mp+12]=struct.pack('>I',(int(seq)-2)&0xffffffff)
            else:
                pl[12:16]=struct.pack('>I',int(c1)&0xffffffff)
        if replace:
            for old,new in replace:
                if old and new and len(old)==len(new): pl=bytearray(bytes(pl).replace(old,new))
        if compressed:
            pl = pad_trailer(bytes(pl[:4]) + lz4.block.compress(bytes(pl[4:]), store_size=False))
        batch += enc_frame_raw(key1,seq,bytes(pl),compression=compressed); seq += 1; sent += len(pl)
    if batch: sock.sendall(bytes(batch))
    return seq,sent


def build_grant_request(seq, c1):
    """Build the recovered CSID 22352 level grant request."""
    import struct
    gseq = int(seq) & 0xffffffff
    return (struct.pack('>I', gseq) + struct.pack('>I', 22352) + b'\x00\x00\x15\x86' +
            struct.pack('>I', int(c1) & 0xffffffff) +
            struct.pack('>I', (gseq - 2) & 0xffffffff) + b'\x01')

def run(devtoken_path, username, role_cs=None, port=6630, log=print,
        create=False, pve1v1=False, replay_1v1=None, return_session=False,
        lobby_entry=False, target=5, max_rounds=8, verify_only=False, force_pve=False,
        _game_session=None, _redirect_history=(), _prev_handle=None, character_name=None):
    resolved_role_cs = role_cs
    if os.environ.get('AOV_RUNNER_OFFLINE','').lower() in ('1','true','yes'):
        return {'ok':True,'stage':'fixture','level':1,'level_before':1,
                'level_after':1,'openid':username,'role_cs':role_cs,
                'grant_status':0,'grant_statuses':[],'matches':0}
    try:
        token=json.loads(Path(devtoken_path).read_text(encoding='utf-8'))
    except Exception as exc:
        return {'ok':False,'stage':'token','reject':str(exc)}
    required=('authToken','openId')
    if any(not token.get(k) for k in required):
        return {'ok':False,'stage':'token','reject':'token file requires authToken and openId'}
    if not role_cs:
        return {'ok':False,'stage':'resolve','reject':'role_cs endpoint is required'}
    try:
        # Build the exact protocol payload before opening the socket.
        from aov_device_identity import get_device_for_account
        identity = get_device_for_account(username)
        devreg, handle, source = build_device_registration(identity, username, fresh=True)
        # Exchange the Garena token through iTop before opening CS, matching
        # the original run order.
        try:
            from aov_itop_login import login_account_no_phone
            game=_game_session if _game_session is not None else login_account_no_phone(username,str(token['authToken']),str(token['openId']))
        except Exception as exc:
            return {'ok':False,'stage':'itop','reject':str(exc)}
        if not isinstance(game,dict) or not game.get('ok'):
            return {'ok':False,'stage':'itop','reject':(game or {}).get('error','iTop login failed')}
        openid=str(game.get('openid') or token['openId']); game_token=str(game.get('game_token') or '')
        if not game_token: return {'ok':False,'stage':'itop','reject':'iTop response has no game token'}
        if log:
            # Lengths are safe diagnostics; never print the token or openid.
            log(f'[auth] iTop session fields openid_len={len(openid)} game_token_len={len(game_token)}')
        # Resolve the account shard when the caller passed the original
        # sentinel.  A configured shard service is account-specific; the
        # static address is retained only as a compatibility fallback.
        if role_cs == 'resolve':
            shard_url = os.environ.get('AOV_SHARD_URL')
            try:
                from .shard_resolve import resolve_shard
                # Directory status=1/no-shard is transient during gateway
                # bursts. Retry the account-specific resolve once per second
                # before reporting a real resolve failure.
                shard = None
                for resolve_attempt in range(3):
                    shard = resolve_shard(openid, game_token,
                                          str(identity.get('guid') or openid),
                                          username, host=shard_url, log=log)
                    if isinstance(shard, dict) and (shard.get('shard') or shard.get('host')):
                        break
                    reject_text = str((shard or {}).get('reject') or (shard or {}).get('err') or '')
                    transient_resolve = 'status=1' in reject_text or 'no shard' in reject_text.lower()
                    if not transient_resolve or resolve_attempt >= 2:
                        break
                    if log: log(f'[resolve] transient directory response; retry {resolve_attempt + 2}/3 in 1s')
                    time.sleep(1.0)
                resolved = shard.get('shard') if isinstance(shard, dict) else None
                if not resolved and isinstance(shard, dict) and shard.get('host'):
                    resolved = (shard.get('host'), shard.get('port') or port)
                if resolved:
                    role_cs = f'{resolved[0]}:{int(resolved[1])}'
                    if log: log(f'[resolve] shard={role_cs} source=directory-gateway')
                else:
                    return {'ok': False, 'stage': 'resolve',
                            'reject': (shard or {}).get('reject') or (shard or {}).get('err') or 'directory returned no shard',
                            'directory_response': shard}
            except Exception as exc:
                return {'ok': False, 'stage': 'resolve', 'reject': str(exc)}
            if role_cs == 'resolve':
                candidates = _endpoint_candidates(role_cs, port)
                role_cs = candidates[0]
                if log: log(f'[resolve] shard={role_cs} source=static-fallback')
        host, gs_port = _split_endpoint(role_cs, port)
        resolved_role_cs = f'{host}:{gs_port}'
        role_cs = resolved_role_cs
        if log: log(f'[cs] connecting {resolved_role_cs}')
        import socket, struct
        from .cs import build_client_hello, parse_server_hello, build_data_frame, build_login_plaintext
        from .crypto import AES128CBCStream
        from .uplevel_stateful import FrameReader, enc_frame_raw, enc_frame, build_1v1, build_logout
        try:
            from pve_trace import TraceSocket, receive_hello
            sock=TraceSocket(socket.create_connection((host,gs_port),10), resolved_role_cs)
        except OSError as exc:
            return {'ok':False,'stage':'connect','reject':str(exc),
                    'role_cs':resolved_role_cs,'host':host,'port':gs_port,
                    'transport_error':str(exc),'frames_received':0,
                    'received_csids':[],'server_closed':False}
        sock.settimeout(5)
        sock.sendall(build_client_hello(openid))
        _sh=receive_hello(sock); key1=_sh['key1']; reader=FrameReader(key1); tx=AES128CBCStream(key1); seq=2
        if log: log(f'[cs] server hello bytes={len(_sh.get("raw", b""))} buffered_tail={len(_sh.get("tail", b""))}')
        login_plain = build_login_plaintext(game_token)
        # Keep this diagnostic structural only; never print the token itself.
        if log:
            sep_off = 14 + len(game_token.encode()) + 19
            log(f'[cs] login payload bytes={len(login_plain)} '
                f'separator=0x{login_plain[sep_off]:02x} trailer={login_plain[-1]:02x}')
        sock.sendall(build_data_frame('00082001',seq,tx.encrypt(login_plain),21)); seq+=1
        state={'progress_log':log,'openid':openid,'handle':_prev_handle,'last_c1':0,'level':None,'reject':None,'grant_status':None,'csids':set(),'role_blob':b'',
               'frames_seen':0,'received_csids':set(),'server_closed':False}
        _pump_state(sock,reader,2.5,state,initial=_sh.get('tail', b''))
        if log:
            log(f'[cs] after login frames={state.get("frames_seen", 0)} '
                f'csids={sorted(state.get("received_csids", ()))[:12]} '
                f'handle={state.get("handle")} c1={state.get("last_c1")} '
                f'transport={state.get("transport_error") or "none"}')
        if 1040 in state['received_csids'] and not state.get('reject'):
            caps = json.loads((_RT_ROOT/'1v1_setwin_seq.json').read_text(encoding='utf-8'))['frames']
            enter = next(f for f in caps if f.get('csid') == 1041)
            # Match the protocol version pair in the current registration
            # capture (the older replay starts with 0x03000088).
            from .cs import unpack_lz4_payload
            current_versions = unpack_lz4_payload(devreg[4:])[16:24]
            seq, _ = _send_plain_capture_frames(sock, key1, seq, [enter],
                replace=[(bytes.fromhex('0300008703000088'), current_versions)])
            if log: log('[cs] SERVER csid=1040; sent captured lobby entry 1041')
            _pump_state(sock, reader, 6.0, state)
            if log: log(f"[cs] after lobby entry level={state.get('level')} c1={state.get('last_c1')} reject={state.get('reject')}")
        # The original path sends the role bootstrap burst only for an
        # existing role/replay session. Create-role starts directly with the
        # captured registration sequence.
        seqdata=json.loads((_RT_ROOT/'seq6670.json').read_text(encoding='utf8'))['frames']
        hs=[f for f in seqdata if f.get('typ')=='data' and f.get('csid') in (5530,5114) and f.get('c1')==0]
        burst_bytes=0
        if not create and (not replay_1v1 or os.environ.get('AOV_SEND_HS') == '1'):
            seq,burst_bytes=_send_capture_frames(sock,key1,seq,hs)
        _pump_state(sock,reader,2.5,state)
        if not state.get('level_evidence'):
            # The recovered client does not send device registration until the
            # server has issued the 1014 handle.  Sending the captured 1002/1261
            # frames with a missing handle makes the server abort the socket and
            # hides the actual CS-login failure behind WSAECONNABORTED.
            if state.get('handle') is None:
                if log:
                    log('[cs] STOP before device/grant: server did not issue 1014 handle')
                try: sock.close()
                except OSError: pass
                return {
                    'ok': False, 'stage': 'cs-login',
                    'reject': state.get('reject') or state.get('transport_error') or 'cs_handle_not_received',
                    'role_cs': resolved_role_cs, 'host': host, 'port': gs_port,
                    'frames_received': state.get('frames_seen', 0),
                    'received_csids': sorted(state.get('received_csids', ())),
                    'server_closed': state.get('server_closed', False),
                    'transport_error': state.get('transport_error'),
                }
            # Patch the captured registration sequence, handle and stoken, then
            # send it as a raw captured frame. The server's 1014 response handle
            # is required by the following 1261 frame.
            if source == 'fresh-capture':
                dv, _ = build_devreg_fresh(username, seq=seq, live_handle=state['handle'])
            else:
                dv=bytearray(devreg); dv[:4]=struct.pack('>I',seq)
                dv=bytearray(bytes(dv).replace(_CAP_STOK.encode(),_fresh_stoken().encode(),1))
                if handle and state.get('handle') is not None:
                    dv=bytearray(bytes(dv).replace(struct.pack('>I',handle),struct.pack('>I',state['handle'])))
            sock.sendall(enc_frame_raw(key1,seq,bytes(dv), compression=True if source == 'fresh-capture' else None)); seq+=1
            if log: log(f'[device-reg] sent handle={state.get("handle")} bytes={len(dv)}')
            # 1261 is a separate raw packet in the original sequence. It must be
            # sent with sequence/handle patching only; applying live c1/c2
            # counters here makes the endpoint abort the session.
            try:
                p4f=next(f for f in seqdata if f.get('csid') == 1261)
                p4=_patch_raw_capture(p4f,seq,
                                      handle_old=handle,
                                      handle_new=state.get('handle'), stok=False)
                sock.sendall(enc_frame_raw(key1,seq,p4)); seq+=1
                if log: log(f'[device-reg] follow-up 1261 sent bytes={len(p4)}')
            except StopIteration:
                return {'ok':False,'stage':'device-reg','reject':'device-registration follow-up (1261) is unavailable','role_cs':role_cs}
            _pump_state(sock,reader,1.0 if create else 6.0,state)
            if log:
                log(f'[cs] after device frames={state.get("frames_seen", 0)} '
                    f'csids={sorted(state.get("received_csids", ()))[:12]} '
                    f'handle={state.get("handle")} c1={state.get("last_c1")} '
                    f'transport={state.get("transport_error") or "none"}')
                for reply in state.get('identity_responses', []):
                    log(f"[cs] SERVER csid={reply['csid']} seq={reply['seq']} body_hex={reply['body_hex']}")
        if state.get('redirect'):
            redirect_host, redirect_port = state['redirect']
            destination = f'{redirect_host}:{redirect_port}'
            evidence = dict(state['redirect_evidence'], from_endpoint=role_cs,
                            terminal_body_hex=state.get('reject'))
            history = (*_redirect_history, evidence)
            sock.close()
            if destination == role_cs or len(history) > 3 or any(
                    row['from_endpoint'] == destination for row in _redirect_history):
                return dict(ok=False, stage='cs-redirect', reject='redirect_loop_or_limit',
                            role_cs=role_cs, redirect_history=list(history))
            if log: log(f'[cs] SERVER redirect csid=997 -> {destination}; reconnect {len(history)}/3')
            time.sleep(1.5)
            result = run(devtoken_path, username, role_cs=destination, port=port, log=log,
                         create=create, pve1v1=pve1v1, replay_1v1=replay_1v1,
                         return_session=return_session, lobby_entry=lobby_entry,
                         target=target, max_rounds=max_rounds, verify_only=verify_only,
                         _game_session=game, _redirect_history=history, _prev_handle=state.get('handle'),
                         character_name=character_name)
            result.setdefault('redirect_history', list(history))
            return result
        if state.get('reject'):
            sock.close(); return {'ok':False,'stage':'device-reg','reject':state['reject'],'device_registration_source':source,'burst_bytes':burst_bytes,'role_cs':role_cs}
        if create and not state.get('level_evidence') and not state.get('server_closed') and not state.get('transport_error'):
            # 1002 and 1261 have already been sent. The bundled capture then
            # contains two 5530 preamble packets followed by create CSID 1008.
            # The previous slice ended at 1261 and never sent 1008 at all.
            try:
                cf=json.loads((_RT_ROOT/'createseq.json').read_text(encoding='utf8')).get('frames',[])
                follow_idx=next(i for i,f in enumerate(cf) if f.get('csid') == 1261)
                create_idx=next(i for i,f in enumerate(cf) if f.get('csid') == 1008)
                pre=cf[follow_idx + 1:create_idx]
                if any(f.get('csid') != 5530 for f in pre):
                    raise ValueError('unrecognized create-role preamble')
                seq, _ = _send_plain_capture_frames(sock,key1,seq,pre,c1=state.get('last_c1'))
                role_name = character_name or username
                plain=build_create_role(cf[create_idx],seq,role_name,identity['guid'],state['last_c1'])
                sock.sendall(enc_frame_raw(key1,seq,plain,compression=True)); seq+=1
                if log: log(f'[create-role] sent csid=1008 name={role_name}; waiting for server role data')
                _pump_state(sock,reader,6.0,state)
                if log:
                    log(f'[create-role] received_csids={sorted(state.get("received_csids", ()))} level={state.get("level")} reject={state.get("reject")}')
                    for reply in state.get('identity_responses', []):
                        log(f"[create-role] SERVER csid={reply['csid']} seq={reply['seq']} body_hex={reply['body_hex']}")
            except Exception as exc:
                sock.close(); return {'ok':False,'stage':'create-role','reject':str(exc),'role_cs':role_cs}

        if (return_session and not state.get('level_evidence')
                and not state.get('reject') and not state.get('server_closed')
                and not state.get('transport_error')):
            if log: log('[role] waiting up to 10s for initial role; no packet resend')
            _pump_state(sock, reader, 10.0, state)
        before = state.get('level')
        if return_session and not state.get('reject') and state.get('level_evidence'):
            session_handed_off = True
            return {'ok': True, 'stage': 'session', 'sock': sock, 'key1': key1,
                    'rd': reader, 'tx': tx, 'seq': seq, 'last_c1': state['last_c1'],
                    'handle': state.get('handle'), 'level': before, 'exp': state.get('pvp_exp'),
                    'openid': openid, 'game_token': game_token, 'reject': None,
                    'received_csids': sorted(state.get('received_csids', ())),
                    'frames_received': state.get('frames_seen', 0), 'role_cs': role_cs}
        if not state.get('level_evidence'):
            # Nếu chưa có level evidence nhưng CSID 1007 và 4103 đã trả về (server đã gán tên nhân vật), thử gửi grant 22352
            if not create and not state.get('reject') and 1007 in state.get('received_csids', ()) and 4103 in state.get('received_csids', ()):
                if log: log('[cs] initial 1003 absent but 1007/4103 present; attempting direct grant 22352...')
                gseq = seq
                grant = build_grant_request(gseq, state.get('last_c1', 0))
                try:
                    sock.sendall(enc_frame(key1, gseq, grant)); seq += 1
                    _pump_state(sock, reader, 4.0, state)
                    if log: log(f'[cs] post-grant csids={sorted(state.get("received_csids", ()))} level={state.get("level")}')
                except Exception:
                    pass
            if not state.get('level_evidence'):
                state['reject'] = state.get('reject') or ('role_level_not_received_after_create' if create else 'initial_role_level_not_received')
                return _level_result(state, target, before, 'read-level', role_cs)
        if verify_only or (before >= target and not force_pve) or state.get('reject'):
            return _level_result(state, target, before, 'read-level', role_cs)

        # The grant request is a distinct CSID (22352) and must be sent before
        # the optional 1v1 replay. The old runner skipped this frame, which
        # produced a clean session with no level change and no server error.
        grant_status = None
        if before >= 3 and log:
            log(f'[grant] level={before}; resume PvE without repeating initial grant')
        for attempt in range(0 if before >= 3 else 1):
            gseq = seq
            grant = build_grant_request(gseq, state.get('last_c1', 0))
            try:
                sock.sendall(enc_frame(key1, gseq, grant)); seq += 1
            except OSError as exc:
                state['transport_error'] = str(exc)
                state['reject'] = str(exc)
                break
            state['grant_status'] = None
            _pump_state(sock, reader, 3.0, state)
            if state.get('grant_status') is None and not state.get('reject') and not state.get('server_closed') and not state.get('transport_error'):
                if log: log('[grant] no response yet; waiting 8s more without resending')
                _pump_state(sock, reader, 8.0, state)
            grant_status = state.get('grant_status')
            if log: log(f'[grant] attempt {attempt + 1}/1 seq={gseq} '
                        f'c1={state.get("last_c1", 0)} status={grant_status!r}')
            if grant_status in (0, 0xffffffff):
                break
            time.sleep(0.4)
        grant_ok = before >= 3 or grant_status in (0, 0xffffffff) or (state.get('level') or 0) >= 3
        if not grant_ok:
            try: sock.sendall(build_logout(key1, seq))
            except OSError: pass
            sock.close()
            state['reject'] = state.get('reject') or 'grant_not_confirmed'
            return _level_result(state, target, before, 'grant', role_cs)

        if (state.get('level') or 0) >= target:
            try: sock.sendall(build_logout(key1, seq))
            except OSError: pass
            sock.close()
            return _level_result(state, target, before, 'grant', role_cs)

        if replay_1v1 and not pve1v1:
            try:
                p=Path(replay_1v1)
                if not p.is_file(): p=_RT_ROOT/replay_1v1
                caps=json.loads(p.read_text(encoding='utf8')).get('frames',[])
                idxs=os.environ.get('REPLAY_IDXS')
                if idxs:
                    want={int(x) for x in idxs.split(',') if x.strip().isdigit()}; caps=[f for f in caps if f.get('i') in want]
                else:
                    start=os.environ.get('REPLAY_FROM')
                    if start is not None:
                        caps=caps[int(start):]
                    else:
                        want={105,106,108,124}
                        caps=[f for f in caps if f.get('i') in want]
                if not caps:
                    raise ValueError('PvE replay template selection is empty')
                current = state.get('level')
                loops = max_rounds
                role_old = int(os.environ.get('REPLAY_ROLE_OLD', '0') or 0)
                role_new = state.get('role_id')
                replacements = None
                if role_old and isinstance(role_new, int) and role_new != role_old:
                    replacements = [(struct.pack('>H', role_old & 0xffff), struct.pack('>H', role_new & 0xffff))]
                if log: log(f'[replay1v1] level={current} target={target or "?"} loops={loops} frames={[f.get("i") for f in caps]} role_new={role_new!r}')
                sent = 0
                rounds = 0
                for loop in range(loops):
                    if ((state.get('level') >= target and not force_pve)
                            or state.get('reject') or state.get('transport_error')):
                        break
                    observations = len(state.get('level_evidence', []))
                    seq, sent_now = _send_plain_capture_frames(sock,key1,seq,caps,c1=state.get('last_c1'),replace=replacements)
                    sent += sent_now
                    rounds += 1
                    _pump_state(sock,reader,6.0,state)
                    if log: log(f'[replay1v1] loop={loop + 1}/{loops} level={state.get("level")} reject={state.get("reject")}')
                    if state.get('reject'): break
                    if len(state.get('level_evidence', [])) == observations:
                        state['reject'] = 'role_level_update_not_received_after_pve'
                        break
                sock.sendall(build_logout(key1,seq)); sock.close()
                return _level_result(state, target, before, 'replay1v1', role_cs, rounds)
            except Exception as exc:
                sock.close(); return {'ok':False,'stage':'replay1v1','reject':str(exc),
                                     'role_cs':resolved_role_cs,
                                     'transport_error':str(exc)}
        if return_session:
            session_handed_off = True
            return {'ok':True,'stage':'session','sock':sock,'key1':key1,'rd':reader,'tx':tx,'seq':seq,'last_c1':state['last_c1'],'handle':state.get('handle'),'level':state.get('level'),'openid':openid,'game_token':game_token,'reject':None}
        # Execute the byte-for-byte PvE templates when requested.
        if pve1v1:
            before=state.get('level'); role_new=state.get('role_id'); role_old=20001
            steps=os.environ.get('PVE1V1_STEPS','create_team,team_oper_start,start_single,fin_single').split(',')
            for st in steps:
                st=st.strip()
                if not st: continue
                pkt=build_1v1('c2s_'+st,state['last_c1'],seq,seq,role_old=role_old if role_new else None,role_new=role_new)
                sock.sendall(enc_frame(key1,seq,pkt)); seq+=1; _pump_state(sock,reader,2.5,state)
                if state.get('reject'): break
            after=state.get('level'); sock.sendall(build_logout(key1,seq)); sock.close()
            return {'ok':state.get('reject') is None,'stage':'1v1','level_before':before,'level_after':after,'role_id':role_new,'role_cs':role_cs,'reject':state.get('reject')}
        sock.sendall(build_logout(key1,seq)); sock.close()
        return {'ok':state.get('reject') is None,'stage':'session','openid':openid,'role_cs':role_cs,'level':state.get('level'),'last_c1':state.get('last_c1'),'burst_bytes':burst_bytes,'reject':state.get('reject')}
    except Exception as exc:
        # Preserve the selected endpoint on every exception.  Previously a
        # send-side WSAECONNABORTED escaped here and the batch result reported
        # host=null, which made it impossible to tell routing from protocol
        # failure in the terminal log.
        return {'ok':False,'stage':'session','reject':str(exc),
                'openid':str(token['openId']), 'role_cs':resolved_role_cs,
                'transport_error':str(exc)}
    finally:
        if 'sock' in locals() and not locals().get('session_handed_off', False):
            try: sock.close()
            except OSError: pass
