"""Evidence based CS state-machine primitives recovered from bytecode.

This module intentionally contains only structures present in the bundled
``newbie_seq.hex`` and ``1v1_templates.hex`` captures.  It does not invent
commands when a capture is unavailable.
"""
from __future__ import annotations

import os
import socket
import struct
import time
from pathlib import Path
from typing import Iterable

from .cs import MAGIC, IV16, aes_cbc_once, pad_trailer, parse_cspkgs, parse_role_profile, enc_frame, enc_frame_raw

ROOT = Path(__file__).resolve().parent.parent / "_internal" / "rt" / "purepc"
_NEWBIE: dict[str, bytes] | None = None
_1V1TPL: dict[str, bytes] | None = None

# Bootstrap frames used by the original directory/shard gateway on TCP 6670.
# They are kept as plaintext captures and encrypted with the negotiated key at
# send time, just like the recovered client.
HS = (
    '000000030000159a0000151a0000000000000001000027840000011000000000000000000000000100',
    '000000040000159a0000151a00000000000000020000289608a500000d2b000000030000000000000006302e302e3100000000010000000001000000000100',
    '000000050000159a0000151a00000000000000030000289608a500000bc0000000040000000000000006312e302e3500000000010000000001000000000100',
    '000000060000159a0000151a00000000000000040000289608a500000cd1000000050000000000000006302e302e3500000000010000000001000000000100',
)


def _load_hex_table(name: str, *, require_tab: bool = True) -> dict[str, bytes]:
    path = ROOT / name
    if not path.is_file():
        raise FileNotFoundError(f"protocol asset is unavailable: {path}")
    out: dict[str, bytes] = {}
    for raw in path.read_text(encoding="ascii").splitlines():
        line = raw.strip()
        if not line or (require_tab and "\t" not in line):
            continue
        key, value = line.split("\t", 1)
        out[key] = bytes.fromhex(value.strip())
    if not out:
        raise ValueError(f"protocol asset is empty: {path}")
    return out


def _load_newbie() -> dict[str, bytes]:
    global _NEWBIE
    if _NEWBIE is None:
        _NEWBIE = _load_hex_table("newbie_seq.hex")
    return _NEWBIE


def _load_1v1() -> dict[str, bytes]:
    global _1V1TPL
    if _1V1TPL is None:
        _1V1TPL = _load_hex_table("1v1_templates.hex")
    return _1V1TPL


def build_cmd(key: str, c1: int, c2: int, seq: int) -> bytes:
    """Build a captured newbie command with sequence and counters patched."""
    pl = _load_newbie()[key]
    if len(pl) < 20:
        raise ValueError(f"template {key!r} is shorter than CS header")
    return struct.pack(">I", int(seq) & 0xffffffff) + pl[4:12] + struct.pack(">I", int(c1) & 0xffffffff) + struct.pack(">I", int(c2) & 0xffffffff) + pl[20:]


def build_1v1(key: str, c1: int, c2: int, seq: int, role_old: int | None = None, role_new: int | None = None) -> bytes:
    """Build a captured PvE 1v1 command.

    The role replacement is performed only when both values are supplied and
    differ, matching the original ``bytes.replace(struct.pack('>H', ...))``
    operation.
    """
    pl = _load_1v1()[key]
    if len(pl) < 20:
        raise ValueError(f"template {key!r} is shorter than CS header")
    csid, body = pl[:4], pl[16:]
    if role_old is not None and role_new is not None and role_old != role_new:
        body = body.replace(struct.pack(">H", int(role_old) & 0xffff), struct.pack(">H", int(role_new) & 0xffff))
    meta = bytes.fromhex("0000" + os.environ.get("AOV_SEND_META", "1586")[-4:])
    return struct.pack(">I", int(seq) & 0xffffffff) + csid + meta + struct.pack(">I", int(c1) & 0xffffffff) + struct.pack(">I", int(c2) & 0xffffffff) + body


def build_logout(key1: bytes, seq: int) -> bytes:
    body = aes_cbc_once(key1, pad_trailer(b"\0\0\0\0"), encrypt=True, iv=IV16)
    n = len(body)
    return MAGIC + bytes.fromhex("00085001") + b"\0" * 4 + struct.pack("<I", int(seq)) + bytes((21, 0, 0, 0, n & 0xff)) + body


def grant_response_status(packet: dict) -> int | None:
    """Decode the status field from the confirmed grant CSID (22351)."""
    if not isinstance(packet, dict) or packet.get("csid") != 22351:
        return None
    try:
        body = bytes.fromhex(packet.get("body", ""))
    except (TypeError, ValueError):
        return None
    return struct.unpack_from(">I", body, 0)[0] if len(body) >= 4 else None


class FrameReader:
    """Incremental CS frame reader used by the original response pump."""
    def __init__(self, key1: bytes):
        self.key1 = bytes(key1)
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[tuple[str, int, bytes, bytes]]:
        self.buf.extend(data)
        out = []
        while True:
            if len(self.buf) < 22:
                break
            if self.buf[:4] != MAGIC:
                pos = self.buf.find(MAGIC, 1)
                if pos < 0:
                    self.buf.clear(); break
                del self.buf[:pos]; continue
            # Normal encrypted frames have a 22-byte header.  The gateway's
            # reject frame (00085002) uses the same length fields but sets
            # the header-size byte to 21, so its body starts one byte earlier
            # (21 + 8 bytes in the observed response).  A fixed 22-byte
            # offset would leave that frame buffered and hide its code.
            header_len = int(self.buf[16])
            if header_len not in (21, 22):
                header_len = 22
            n = (self.buf[19] << 8) | self.buf[20]
            if len(self.buf) < header_len + n:
                break
            frame = bytes(self.buf[:header_len+n]); del self.buf[:header_len+n]
            typ = frame[4:8].hex(); seq = struct.unpack_from("<I", frame, 12)[0]
            body = frame[header_len:]
            # CS response bodies are one-shot AES-CBC blocks with the
            # negotiated key and protocol IV.  The old rebuild only decoded
            # reject frames, so normal login/role packets stayed ciphertext
            # and no CSID/handle could ever be observed.
            plain = (aes_cbc_once(self.key1, body, encrypt=False, iv=IV16)
                     if body and len(body) % 16 == 0 else body)
            from pve_trace import record
            record('response_frame', frame, frame_type=typ, seq=seq,
                   header_length=header_len, body_length=len(body))
            record('response_body', plain, frame_type=typ, seq=seq,
                   server_status=(int.from_bytes(plain[:4], 'big')
                                  if typ == '00085002' and len(plain) >= 4 else None))
            # Byte 21 is the compression flag, not a size threshold. Captured
            # large server bodies are LZ4 blocks after AES and trailer removal.
            if typ == '00084013' and header_len == 22 and frame[21] & 1:
                from .cs import unpack_lz4_payload
                plain = unpack_lz4_payload(plain)
                record('response_uncompressed', plain, frame_type=typ, seq=seq,
                       compression='lz4')
            out.append((typ, seq, body, plain))
        return out


def read_frames(sock, reader: FrameReader, until: float, stop_csids: Iterable[int] = ()) -> list[dict]:
    """Read and decode frames until timeout or a requested CSID appears."""
    stop = set(stop_csids); out: list[dict] = []; sock.settimeout(0.6)
    deadline = time.time() + max(0.0, float(until))
    while time.time() < deadline:
        try: data = sock.recv(65536)
        except socket.timeout: continue
        except OSError as exc:
            # Windows reports a peer close as WSAECONNABORTED (10053) on
            # some CS endpoints. Preserve the transport reason for the
            # caller instead of turning it into an unrelated send failure.
            out.append({"closed": True, "transport_error": str(exc)})
            return out
        if not data: out.append({"closed": True}); return out
        for typ, seq, raw, plain in reader.feed(data):
            status = (int.from_bytes(plain[:4], "big")
                      if typ == "00085002" and len(plain) >= 4 else None)
            item = {"reject": typ == "00085002", "seq": seq,
                    "raw_body": raw.hex(), "dec_body": plain.hex(),
                    "server_status": status}
            out.append(item)
            for pk in parse_cspkgs(plain):
                entry = dict(pk)
                entry['seq'] = seq
                entry["body"] = entry.pop("payload").hex()
                if isinstance(entry.get("body_full"), (bytes, bytearray)):
                    entry["body_full"] = bytes(entry["body_full"]).hex()
                out.append(entry)
                profile = parse_role_profile(plain)
                if profile and profile.get("level") is not None: out.append({"role_profile": profile, "role_profile_level": profile["level"], "seq": seq})
                if pk.get("csid") in stop: return out
    return out
