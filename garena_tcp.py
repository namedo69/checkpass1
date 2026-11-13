from __future__ import annotations

import hashlib
import json
import os
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


GARENA_HOST = "mconnect.gxx.garenanow.com"
GARENA_PORT = 19000
GARENA_IPV4_FALLBACKS = tuple(f"103.247.205.{last}" for last in (14, 15, 16, 17, 18, 19, 20, 22))
CLIENT_VERSION = 283
CLIENT_PLATFORM_ANDROID = 0x11
CLIENT_ANDROID_GOOGLE_PLAY = 0x1100
CLIENT_ANDROID_INTERNAL = 0x1102
COMMAND_LOGIN_PREPARE = 0x100
COMMAND_LOGIN = 0x101
COMMAND_LOGIN_TOKEN_GET = 0x115
COMMAND_APP_OAUTH_LOGIN = 0x1B7
COMMAND_SSO_KEY_GET = 0x1BA
APP_ID = 100054
REDIRECT_URI = "gop100054://auth/"


class GarenaError(RuntimeError):
    pass


def _varint(value: int) -> bytes:
    value &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _field_varint(tag: int, value: int) -> bytes:
    return _varint(tag << 3) + _varint(value)


def _field_bytes(tag: int, value: bytes) -> bytes:
    return _varint((tag << 3) | 2) + _varint(len(value)) + value


def _field_string(tag: int, value: str) -> bytes:
    return _field_bytes(tag, value.encode("utf-8"))


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if not current & 0x80:
            return value, offset
        shift += 7
    raise GarenaError("Gói protobuf không hợp lệ")


def _parse_message(data: bytes) -> dict[int, list[int | bytes]]:
    fields: dict[int, list[int | bytes]] = {}
    offset = 0
    while offset < len(data):
        key, offset = _read_varint(data, offset)
        tag, wire_type = key >> 3, key & 7
        if wire_type == 0:
            value, offset = _read_varint(data, offset)
        elif wire_type == 1:
            if offset + 8 > len(data):
                raise GarenaError("Gói protobuf bị cắt")
            value = data[offset : offset + 8]
            offset += 8
        elif wire_type == 2:
            size, offset = _read_varint(data, offset)
            if offset + size > len(data):
                raise GarenaError("Gói protobuf bị cắt")
            value = data[offset : offset + size]
            offset += size
        elif wire_type == 5:
            if offset + 4 > len(data):
                raise GarenaError("Gói protobuf bị cắt")
            value = data[offset : offset + 4]
            offset += 4
        else:
            raise GarenaError(f"Kiểu protobuf chưa hỗ trợ: {wire_type}")
        fields.setdefault(tag, []).append(value)
    return fields


def _first_int(fields: dict[int, list[int | bytes]], tag: int, default: int = 0) -> int:
    values = fields.get(tag)
    return int(values[0]) if values and isinstance(values[0], int) else default


def _first_bytes(fields: dict[int, list[int | bytes]], tag: int) -> bytes:
    values = fields.get(tag)
    return bytes(values[0]) if values and isinstance(values[0], bytes) else b""


def _xtea_encrypt_block(block: bytes, key_words: tuple[int, int, int, int]) -> bytes:
    left, right = struct.unpack("<2I", block)
    total = 0
    delta = 0x9E3779B9
    for _ in range(32):
        left = (
            left
            + ((((right << 4) ^ (right >> 5)) + right) ^ (total + key_words[total & 3]))
        ) & 0xFFFFFFFF
        total = (total + delta) & 0xFFFFFFFF
        right = (
            right
            + ((((left << 4) ^ (left >> 5)) + left) ^ (total + key_words[(total >> 11) & 3]))
        ) & 0xFFFFFFFF
    return struct.pack("<2I", left, right)


def _xtea_decrypt_block(block: bytes, key_words: tuple[int, int, int, int]) -> bytes:
    left, right = struct.unpack("<2I", block)
    delta = 0x9E3779B9
    total = (delta * 32) & 0xFFFFFFFF
    for _ in range(32):
        right = (
            right
            - ((((left << 4) ^ (left >> 5)) + left) ^ (total + key_words[(total >> 11) & 3]))
        ) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
        left = (
            left
            - ((((right << 4) ^ (right >> 5)) + right) ^ (total + key_words[total & 3]))
        ) & 0xFFFFFFFF
    return struct.pack("<2I", left, right)


def _xtea_cbc_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != 16 or len(plaintext) % 8:
        raise GarenaError("Dữ liệu mã hóa XTEA không hợp lệ")
    key_words = struct.unpack("<4I", key)
    previous = bytes(8)
    result = bytearray()
    for offset in range(0, len(plaintext), 8):
        block = bytes(a ^ b for a, b in zip(plaintext[offset : offset + 8], previous))
        previous = _xtea_encrypt_block(block, key_words)
        result.extend(previous)
    return bytes(result)


def _xtea_cbc_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 16 or not ciphertext or len(ciphertext) % 8:
        raise GarenaError("Dữ liệu giải mã XTEA không hợp lệ")
    key_words = struct.unpack("<4I", key)
    previous = bytes(8)
    result = bytearray()
    for offset in range(0, len(ciphertext), 8):
        block = ciphertext[offset : offset + 8]
        decrypted = _xtea_decrypt_block(block, key_words)
        result.extend(a ^ b for a, b in zip(decrypted, previous))
        previous = block
    return bytes(result)


def _encrypt_payload(data: bytes, key: bytes) -> bytes:
    pad_size = 8 - (len(data) % 8)
    protected = os.urandom(8) + data + bytes([pad_size]) * pad_size
    # Khối cuối là tổng kiểm tra uint64 của toàn bộ khối rõ, đúng với libcrypt.so.
    checksum = 0
    for offset in range(0, len(protected), 8):
        checksum = (
            checksum + int.from_bytes(protected[offset : offset + 8], "little")
        ) & 0xFFFFFFFFFFFFFFFF
    wrapped = protected + checksum.to_bytes(8, "little")
    return _xtea_cbc_encrypt(wrapped, key)


def _decrypt_payload(data: bytes, key: bytes) -> bytes:
    wrapped = _xtea_cbc_decrypt(data, key)
    if len(wrapped) < 24:
        raise GarenaError("Phản hồi mã hóa quá ngắn")
    checksum = 0
    for offset in range(0, len(wrapped) - 8, 8):
        checksum = (
            checksum + int.from_bytes(wrapped[offset : offset + 8], "little")
        ) & 0xFFFFFFFFFFFFFFFF
    if checksum.to_bytes(8, "little") != wrapped[-8:]:
        raise GarenaError("Tổng kiểm tra mã hóa không hợp lệ")
    middle = wrapped[8:-8]
    pad_size = middle[-1]
    if not 1 <= pad_size <= 8 or middle[-pad_size:] != bytes([pad_size]) * pad_size:
        raise GarenaError("Lớp đệm mã hóa không hợp lệ")
    return middle[:-pad_size]


def _encode_header(request_id: int, command: int) -> bytes:
    version = (CLIENT_PLATFORM_ANDROID << 24) | CLIENT_VERSION
    return b"".join(
        (
            _field_varint(1, version),
            _field_varint(2, request_id),
            _field_varint(3, 2),
            _field_varint(4, command),
            _field_varint(6, int(time.time())),
        )
    )


def _encode_packet(request_id: int, command: int, payload: bytes, key: bytes | None = None) -> bytes:
    header = _encode_header(request_id, command)
    body = struct.pack(">H", len(header)) + header + payload
    if key is not None:
        body = _encrypt_payload(body, key)
    return struct.pack("<I", len(body)) + body


def _decode_packet(body: bytes, key: bytes | None = None) -> tuple[dict[int, list[int | bytes]], bytes]:
    if key is not None:
        body = _decrypt_payload(body, key)
    if len(body) < 2:
        raise GarenaError("Phản hồi Garena quá ngắn")
    header_size = struct.unpack(">H", body[:2])[0]
    if 2 + header_size > len(body):
        raise GarenaError("Header Garena không hợp lệ")
    return _parse_message(body[2 : 2 + header_size]), body[2 + header_size :]


@dataclass(slots=True)
class OAuthResult:
    uid: int
    open_id: str
    response_data: str = field(repr=False)
    redirect_uri: str
    granted_scopes: tuple[str, ...]

    @property
    def masked_account(self) -> str:
        tail = self.open_id[-4:] if self.open_id else str(self.uid)[-4:]
        return f"•••• {tail}"


@dataclass(slots=True)
class SsoSession:
    uid: int
    sso_key: str = field(repr=False)
    expiry_time: int


class GarenaTcpClient:
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.socket: socket.socket | None = None
        self.session_key: bytes | None = None
        self.uid = 0
        # Ứng dụng Android khởi tạo phần thấp của request-id bằng số dương 31 bit.
        self._sequence = random.getrandbits(31)

    def __enter__(self) -> "GarenaTcpClient":
        self.connect()
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def connect(self) -> None:
        self.close()
        candidates: list[str] = []
        try:
            candidates.extend(
                address[4][0]
                for address in socket.getaddrinfo(
                    GARENA_HOST, GARENA_PORT, socket.AF_INET, socket.SOCK_STREAM
                )
            )
        except OSError:
            pass
        candidates.extend(GARENA_IPV4_FALLBACKS)
        last_error: OSError | None = None
        for host in dict.fromkeys(candidates):
            # Bỏ qua server bị blacklist (giống markDiamondServerFailed)
            if not is_server_available(host):
                continue
            try:
                self.socket = socket.create_connection(
                    (host, GARENA_PORT), min(self.timeout, 3.5)
                )
                self.socket.settimeout(self.timeout)
                return
            except OSError as exc:
                # Đánh dấu server lỗi kết nối — blacklist 45s
                mark_server_failed(host, _FAIL_CONNECT_SECONDS)
                last_error = exc
        raise GarenaError("Không kết nối được máy chủ đăng nhập Garena") from last_error

    def close(self) -> None:
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
        self.socket = None
        self.session_key = None

    def _next_id(self) -> int:
        self._sequence = (self._sequence + 1) & 0xFFFFFFFF
        return (CLIENT_ANDROID_INTERNAL << 32) | self._sequence

    def _receive_exact(self, size: int) -> bytes:
        if self.socket is None:
            raise GarenaError("Kết nối Garena chưa được mở")
        result = bytearray()
        while len(result) < size:
            try:
                chunk = self.socket.recv(size - len(result))
            except OSError as exc:
                raise GarenaError("Mất kết nối với máy chủ Garena") from exc
            if not chunk:
                raise GarenaError("Máy chủ Garena đã đóng kết nối")
            result.extend(chunk)
        return bytes(result)

    def _request(self, command: int, payload: bytes, key: bytes | None = None) -> bytes:
        if self.socket is None:
            raise GarenaError("Kết nối Garena chưa được mở")
        request_id = self._next_id()
        try:
            self.socket.sendall(_encode_packet(request_id, command, payload, key))
        except OSError as exc:
            raise GarenaError("Không gửi được yêu cầu tới Garena") from exc
        size = struct.unpack("<I", self._receive_exact(4))[0]
        if size <= 0 or size > 4 * 1024 * 1024:
            raise GarenaError("Kích thước phản hồi Garena không hợp lệ")
        header, reply = _decode_packet(self._receive_exact(size), key)
        reply_command = _first_int(header, 4)
        result = _first_int(header, 5)
        if reply_command != command:
            raise GarenaError(f"Sai lệnh phản hồi Garena: {reply_command}")
        if result != 0:
            raise GarenaError(f"Garena từ chối yêu cầu, mã {result}")
        return reply

    def login(self, account: str, password: str) -> int:
        account = account.strip()
        if not account or not password:
            raise GarenaError("Tài khoản hoặc mật khẩu trống")
        if self.socket is None:
            self.connect()

        prepare_key = os.urandom(16)
        prepare_data = b"".join(
            (
                _field_varint(1, 0),
                _field_varint(2, 1),
                _field_string(3, account),
                _field_varint(4, CLIENT_ANDROID_GOOGLE_PLAY),
                _field_varint(5, CLIENT_VERSION),
            )
        )
        prepare_request = _field_bytes(1, prepare_key) + _field_bytes(
            2, _encrypt_payload(prepare_data, prepare_key)
        )
        prepare_reply = _parse_message(
            self._request(COMMAND_LOGIN_PREPARE, prepare_request)
        )
        reply_key = _first_bytes(prepare_reply, 1)
        reply_data = _first_bytes(prepare_reply, 2)
        if len(reply_key) != 16 or not reply_data:
            raise GarenaError("Garena không trả về dữ liệu chuẩn bị đăng nhập")
        prepared = _parse_message(_decrypt_payload(reply_data, reply_key))
        salt = _first_bytes(prepared, 1).decode("utf-8", "strict")
        verify_code = _first_bytes(prepared, 2).decode("utf-8", "strict")

        password_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
        salted_hash = hashlib.sha256((password_md5 + salt).encode("utf-8")).hexdigest()
        login_key = hashlib.sha256((salted_hash + verify_code).encode("utf-8")).digest()[:16]
        device_id = os.urandom(8).hex().encode("ascii")
        user_status = _field_varint(2, 0x1200)
        login_data = b"".join(
            (
                _field_bytes(1, password_md5.encode("ascii")),
                _field_varint(2, 0),
                _field_bytes(3, user_status),
                _field_bytes(4, device_id),
            )
        )
        login_request = _field_bytes(1, _encrypt_payload(login_data, login_key))
        login_envelope = _parse_message(
            self._request(COMMAND_LOGIN, login_request)
        )
        encrypted_login_reply = _first_bytes(login_envelope, 1)
        if not encrypted_login_reply:
            raise GarenaError("Garena không trả về kết quả đăng nhập")
        login_reply = _parse_message(
            _decrypt_payload(encrypted_login_reply, login_key)
        )
        self.uid = _first_int(login_reply, 1)
        self.session_key = _first_bytes(login_reply, 2)
        if not self.uid or len(self.session_key) != 16:
            raise GarenaError("Không nhận được phiên đăng nhập Garena")
        return self.uid

    def oauth_login(self) -> OAuthResult:
        if not self.session_key or not self.uid:
            raise GarenaError("Chưa đăng nhập Garena")
        oauth_request = b"".join(
            (
                _field_varint(1, APP_ID),
                _field_string(2, REDIRECT_URI),
                _field_varint(3, 1),
                _field_varint(6, CLIENT_PLATFORM_ANDROID),
            )
        )
        reply = _parse_message(
            self._request(COMMAND_APP_OAUTH_LOGIN, oauth_request, self.session_key)
        )
        error = _first_bytes(reply, 5).decode("utf-8", "replace")
        if error:
            raise GarenaError(error)
        response_data = _first_bytes(reply, 1).decode("utf-8", "strict")
        redirect_uri = _first_bytes(reply, 2).decode("utf-8", "strict")
        open_id = _first_bytes(reply, 4).decode("utf-8", "strict")
        scopes = tuple(
            bytes(item).decode("utf-8", "replace")
            for item in reply.get(3, [])
            if isinstance(item, bytes)
        )
        if not response_data or not open_id:
            raise GarenaError("Garena không trả về dữ liệu cấp quyền cho Liên Quân")
        return OAuthResult(
            uid=self.uid,
            open_id=open_id,
            response_data=response_data,
            redirect_uri=redirect_uri,
            granted_scopes=scopes,
        )


    def get_sso_key(self) -> SsoSession:
        """Return the Garena web SSO cookie used by the official grant flow."""
        if not self.session_key or not self.uid:
            raise GarenaError("Chưa đăng nhập Garena")
        fields = _parse_message(
            self._request(COMMAND_SSO_KEY_GET, b"", self.session_key)
        )
        sso_key = _first_bytes(fields, 1).decode("ascii", "strict")
        expiry_time = _first_int(fields, 2)
        if len(sso_key) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in sso_key
        ):
            raise GarenaError("Garena không trả về SSO key hợp lệ")
        if expiry_time <= int(time.time()):
            raise GarenaError("SSO key Garena đã hết hạn")
        return SsoSession(uid=self.uid, sso_key=sso_key, expiry_time=expiry_time)


# ---------------------------------------------------------------------------
# GarenaAuthError — phân loại lỗi đăng nhập (mô phỏng Go engine)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class GarenaAuthError(GarenaError):
    """Lỗi đăng nhập Garena với phân loại theo Go engine."""

    message: str = ""
    stage: str = ""           # "prepare" | "login" | "oauth"
    code: int = 0
    is_captcha: bool = False
    is_banned: bool = False
    is_invalid_creds: bool = False
    retryable: bool = False

    def __init__(
        self,
        message: str = "",
        *,
        stage: str = "",
        code: int = 0,
        is_captcha: bool = False,
        is_banned: bool = False,
        is_invalid_creds: bool = False,
        retryable: bool = False,
    ) -> None:
        self.message = message
        self.stage = stage
        self.code = code
        self.is_captcha = is_captcha
        self.is_banned = is_banned
        self.is_invalid_creds = is_invalid_creds
        self.retryable = retryable
        super().__init__(message)


def _classify_login_error(stage: str, code: int) -> GarenaAuthError:
    """Tạo GarenaAuthError phân loại từ stage + error code, giống Go engine."""
    # Mã 0x69 (105) hoặc 3 = rate-limit / captcha (ở phase prepare)
    is_captcha = code in (0x69, 3) and stage == "prepare"
    # Mã phổ biến cho tài khoản bị khóa
    is_banned = code in (0x0B, 11)  # BANNED
    # Mã phổ biến cho sai mật khẩu
    is_invalid_creds = code in (0x02, 2, 0x03, 0x09, 9)  # INVALID_PASSWORD, ACCOUNT_NOT_FOUND
    # Retryable: captcha hoặc lỗi tạm thời không phải banned/invalid
    retryable = is_captcha or (not is_banned and not is_invalid_creds and code not in (0,))

    stage_label = {"prepare": "LOGIN_PREPARE", "login": "LOGIN", "oauth": "OAUTH"}.get(stage, stage)
    return GarenaAuthError(
        f"Garena từ chối ở bước {stage_label} (mã {code})",
        stage=stage,
        code=code,
        is_captcha=is_captcha,
        is_banned=is_banned,
        is_invalid_creds=is_invalid_creds,
        retryable=retryable,
    )


# ---------------------------------------------------------------------------
# Diamond server failure marking (mô phỏng markDiamondServerFailed)
# ---------------------------------------------------------------------------

_failed_servers: dict[str, float] = {}
_failed_servers_lock = threading.Lock()

# Thời gian blacklist (giây) — giống Go engine
_FAIL_CONNECT_SECONDS = 45.0       # connect failure (no proxy)
_FAIL_IO_SECONDS = 30.0            # write/recv failure
_FAIL_RATELIMIT_SECONDS = 20.0     # error code 0x69 or 3


def mark_server_failed(host: str, duration: float) -> None:
    """Đánh dấu server không khả dụng trong khoảng thời gian cho trước."""
    with _failed_servers_lock:
        until = time.monotonic() + duration
        _failed_servers[host] = max(_failed_servers.get(host, 0), until)


def is_server_available(host: str) -> bool:
    """Kiểm tra server có đang bị blacklist không."""
    with _failed_servers_lock:
        until = _failed_servers.get(host, 0)
        if until <= time.monotonic():
            _failed_servers.pop(host, None)
            return True
        return False


# ---------------------------------------------------------------------------
# Login semaphore — 16 concurrent slots (giống Go engine channel capacity 0x10)
# ---------------------------------------------------------------------------

_LOGIN_SEMAPHORE = threading.Semaphore(16)

# ---------------------------------------------------------------------------
# Gateway pacing — slot-based global scheduler (giống paceGarenaGateway)
# ---------------------------------------------------------------------------

_gateway_lock = threading.Lock()
_gateway_next: dict[str, float] = {}
_GATEWAY_GAP_NO_PROXY = 0.0    # tắt pacing — probe 40w/gap0 không rate limit
_GATEWAY_GAP_WITH_PROXY = 0.0  # tắt pacing
_GLOBAL_FLOOR_NO_PROXY = 0.0   # tắt pacing

# OAuth cooldown
_oauth_cooldown_until = 0.0
_oauth_cooldown_lock = threading.Lock()
_OAUTH_RETRY_COOLDOWN = 1.5    # giây
_OAUTH_RC3_COOLDOWN = 2.5      # giây cho error code 3
_OAUTH_RC3_GATEWAY_QUARANTINE = 10.0  # giây


def _pace_gateway(
    key: str = "default",
    gap: float | None = None,
    stop_event: threading.Event | None = None,
) -> bool:
    """Chờ đến slot tiếp theo. Trả False nếu bị dừng."""
    if gap is None:
        gap = _GATEWAY_GAP_NO_PROXY
    with _gateway_lock:
        now = time.monotonic()
        slot = max(now, _gateway_next.get(key, 0))
        _gateway_next[key] = slot + gap
    delay = slot - time.monotonic()
    if delay > 0:
        if stop_event is not None:
            return not stop_event.wait(delay)
        time.sleep(delay)
    return True


def mark_oauth_rate_limited(duration: float = _OAUTH_RETRY_COOLDOWN) -> None:
    """Đánh dấu OAuth bị rate-limit."""
    global _oauth_cooldown_until
    with _oauth_cooldown_lock:
        until = time.monotonic() + duration
        _oauth_cooldown_until = max(_oauth_cooldown_until, until)


def _wait_oauth_cooldown(stop_event: threading.Event | None = None) -> bool:
    """Chờ hết cooldown OAuth. Trả False nếu bị dừng."""
    with _oauth_cooldown_lock:
        until = _oauth_cooldown_until
    delay = until - time.monotonic()
    if delay > 0:
        if stop_event is not None:
            return not stop_event.wait(delay)
        time.sleep(delay)
    return True


# ---------------------------------------------------------------------------
# Session cache — lưu kết quả đăng nhập vào JSON (giống buff_hot_sessions.json)
# ---------------------------------------------------------------------------

@dataclass
class CachedAuthSession:
    """Phiên đăng nhập đã cache, giống struct CachedAuthSession của Go engine."""
    garena_token: str = ""       # 64-hex SSO key
    garena_open_id: str = ""     # 32-hex open_id
    uid: int = 0
    updated_at: int = 0         # Unix timestamp

    def is_valid(self, max_age_seconds: int = 86400 * 365) -> bool:
        """Kiểm tra cache còn hạn (mặc định 365 ngày, giống Go engine)."""
        if self.updated_at <= 0:
            return True  # không có timestamp = luôn hợp lệ
        return (int(time.time()) - self.updated_at) < max_age_seconds

    def has_zero_hop(self) -> bool:
        """Kiểm tra có đủ dữ liệu để bỏ qua login (giống HasZeroHopAuthSession)."""
        return bool(
            self.garena_token
            and len(self.garena_open_id) == 32
            and self.uid > 0
        )

    def to_dict(self) -> dict:
        return {
            "garena_token": self.garena_token,
            "garena_open_id": self.garena_open_id,
            "uid": self.uid,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CachedAuthSession:
        return cls(
            garena_token=str(data.get("garena_token") or ""),
            garena_open_id=str(data.get("garena_open_id") or ""),
            uid=int(data.get("uid") or 0),
            updated_at=int(data.get("updated_at") or 0),
        )


class SessionCache:
    """Cache phiên đăng nhập Garena giống Go engine.

    - Thread-safe (RWLock)
    - Flush tự động mỗi 12 giây (nếu dirty)
    - Atomic write (tmp + rename)
    """

    _FLUSH_INTERVAL = 12.0  # giây, giống Go engine 0x2CB417800 ns

    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            path = Path("data") / "garena_tcp_sessions.json"
        self._path = Path(path)
        self._lock = threading.RLock()
        self._cache: dict[str, CachedAuthSession] = {}
        self._dirty = False
        self._flush_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._load()
        self._start_flush_thread()

    def _normalize_key(self, username: str) -> str:
        return username.strip().lower()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for key, value in raw.items():
                    if isinstance(value, dict):
                        self._cache[self._normalize_key(key)] = CachedAuthSession.from_dict(value)
        except Exception:
            pass

    def _start_flush_thread(self) -> None:
        def flusher() -> None:
            while not self._stop.wait(self._FLUSH_INTERVAL):
                self.flush()

        self._flush_thread = threading.Thread(target=flusher, daemon=True, name="session-cache-flush")
        self._flush_thread.start()

    def get(self, username: str) -> CachedAuthSession | None:
        """Lấy session đã cache (giống GetCachedAuthSession)."""
        key = self._normalize_key(username)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if not entry.is_valid():
                del self._cache[key]
                self._dirty = True
                return None
            return entry

    def save(
        self,
        username: str,
        *,
        garena_token: str = "",
        garena_open_id: str = "",
        uid: int = 0,
    ) -> None:
        """Lưu session (giống SaveCachedAuthSession)."""
        key = self._normalize_key(username)
        entry = CachedAuthSession(
            garena_token=garena_token,
            garena_open_id=garena_open_id,
            uid=uid,
            updated_at=int(time.time()),
        )
        with self._lock:
            self._cache[key] = entry
            self._dirty = True

    def invalidate(self, username: str) -> None:
        """Xóa session cache (giống InvalidateCachedAuthSession)."""
        key = self._normalize_key(username)
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._dirty = True

    def flush(self) -> None:
        """Ghi cache ra đĩa (giống flushSessionCacheToDisk)."""
        with self._lock:
            if not self._dirty:
                return
            self._dirty = False
            data = {key: entry.to_dict() for key, entry in self._cache.items()}
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            tmp.replace(self._path)
        except Exception:
            # Đánh dấu lại dirty nếu ghi thất bại
            with self._lock:
                self._dirty = True

    def close(self) -> None:
        """Dừng flush thread và ghi lần cuối."""
        self._stop.set()
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=5.0)
        self.flush()

    def prioritize_accounts(
        self, accounts: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        """Sắp xếp tài khoản: zero-hop first, cached second, no-cache last.

        Giống ReloadClonePool trong Go engine.
        Mỗi phần tử: (account, password)
        """
        zero_hop: list[tuple[str, str]] = []
        cached: list[tuple[str, str]] = []
        no_cache: list[tuple[str, str]] = []
        for account, password in accounts:
            entry = self.get(account)
            if entry is not None and entry.has_zero_hop():
                zero_hop.append((account, password))
            elif entry is not None:
                cached.append((account, password))
            else:
                no_cache.append((account, password))
        return zero_hop + cached + no_cache

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)


# Singleton global session cache — khởi tạo lười
_session_cache: SessionCache | None = None
_session_cache_lock = threading.Lock()


def get_session_cache(path: str | Path | None = None) -> SessionCache:
    """Lấy hoặc tạo singleton SessionCache."""
    global _session_cache
    if _session_cache is None:
        with _session_cache_lock:
            if _session_cache is None:
                _session_cache = SessionCache(path)
    return _session_cache


# ---------------------------------------------------------------------------
# garena_authenticate — retry wrapper giống Go engine GarenaAuthenticate
# ---------------------------------------------------------------------------

_MAX_AUTH_RETRIES = 3
_CAPTCHA_SLEEP = 12.0  # giây, giống Go engine
_RETRY_BACKOFF_STEP = 0.300  # 300ms per attempt, giống 0x11E1A300 ns


def garena_authenticate(
    account: str,
    password: str,
    *,
    timeout: float = 15.0,
    stop_event: threading.Event | None = None,
    use_cache: bool = True,
    cache: SessionCache | None = None,
) -> tuple[int, SsoSession | None]:
    """Đăng nhập Garena với retry logic giống Go engine.

    Trả về (uid, SsoSession hoặc None).
    Sử dụng:
    - Semaphore 16 slots
    - Gateway pacing
    - Session cache (nếu use_cache=True)
    - Retry với error classification (captcha 12s sleep, retryable backoff)
    - Diamond server failure marking
    """
    if cache is None and use_cache:
        cache = get_session_cache()

    # Kiểm tra cache trước
    if use_cache and cache is not None:
        cached = cache.get(account)
        if cached is not None and cached.has_zero_hop():
            # Có cache đầy đủ — trả về ngay
            return cached.uid, SsoSession(
                uid=cached.uid,
                sso_key=cached.garena_token,
                expiry_time=int(time.time()) + 86400,  # giả định 1 ngày
            )

    # Lấy semaphore slot (giống channel send trong Go engine)
    acquired = _LOGIN_SEMAPHORE.acquire(timeout=timeout)
    if not acquired:
        raise GarenaError("Quá nhiều kết nối đăng nhập đồng thời (tối đa 16)")
    try:
        return _garena_authenticate_inner(
            account, password, timeout=timeout, stop_event=stop_event,
            use_cache=use_cache, cache=cache,
        )
    finally:
        _LOGIN_SEMAPHORE.release()


def _garena_authenticate_inner(
    account: str,
    password: str,
    *,
    timeout: float,
    stop_event: threading.Event | None,
    use_cache: bool,
    cache: SessionCache | None,
) -> tuple[int, SsoSession | None]:
    last_error: GarenaAuthError | GarenaError | None = None

    for attempt in range(1, _MAX_AUTH_RETRIES + 1):
        # Kiểm tra dừng
        if stop_event is not None and stop_event.is_set():
            raise GarenaError("Đã dừng")

        # Gateway pacing
        if not _pace_gateway(stop_event=stop_event):
            raise GarenaError("Đã dừng")

        try:
            uid, sso = _garena_tcp_login_once(account, password, timeout=timeout)

            # Lưu cache nếu thành công
            if use_cache and cache is not None and sso is not None:
                cache.save(
                    account,
                    garena_token=sso.sso_key,
                    garena_open_id="",  # sẽ được điền bởi layer cao hơn nếu cần
                    uid=uid,
                )

            return uid, sso

        except GarenaAuthError as exc:
            last_error = exc

            if exc.is_banned or exc.is_invalid_creds:
                # Không retry — lỗi vĩnh viễn
                if use_cache and cache is not None:
                    cache.invalidate(account)
                raise

            if exc.is_captcha and exc.stage == "prepare":
                # Captcha ở phase prepare — sleep 12s rồi retry
                if attempt >= _MAX_AUTH_RETRIES:
                    raise
                delay = _CAPTCHA_SLEEP
                if stop_event is not None:
                    if stop_event.wait(delay):
                        raise GarenaError("Đã dừng") from exc
                else:
                    time.sleep(delay)
                continue

            if exc.retryable:
                if attempt >= _MAX_AUTH_RETRIES:
                    raise
                # Backoff tăng dần: attempt * 300ms
                delay = attempt * _RETRY_BACKOFF_STEP
                if stop_event is not None:
                    if stop_event.wait(delay):
                        raise GarenaError("Đã dừng") from exc
                else:
                    time.sleep(delay)
                continue

            # Lỗi không phân loại — không retry
            raise

        except GarenaError as exc:
            last_error = exc
            if attempt >= _MAX_AUTH_RETRIES:
                raise
            delay = attempt * _RETRY_BACKOFF_STEP
            if stop_event is not None:
                if stop_event.wait(delay):
                    raise GarenaError("Đã dừng") from exc
            else:
                time.sleep(delay)

    if last_error is not None:
        raise last_error
    raise GarenaError("Đăng nhập Garena thất bại sau tất cả các lần thử")


def _garena_tcp_login_once(
    account: str, password: str, *, timeout: float = 15.0
) -> tuple[int, SsoSession | None]:
    """Thực hiện 1 lần login TCP đầy đủ (giống GarenaTCPLoginOnce).

    Trả về (uid, SsoSession hoặc None).
    """
    with GarenaTcpClient(timeout=timeout) as client:
        try:
            uid = client.login(account, password)
        except GarenaError as exc:
            # Phân loại lỗi dựa trên thuộc tính garena_command/garena_result
            command = getattr(exc, "garena_command", 0)
            code = getattr(exc, "garena_result", 0)
            if command == COMMAND_LOGIN_PREPARE:
                raise _classify_login_error("prepare", code) from exc
            elif command == COMMAND_LOGIN:
                raise _classify_login_error("login", code) from exc
            # Lỗi kết nối — đánh dấu server failed
            if client.socket is not None:
                try:
                    host = client.socket.getpeername()[0]
                    mark_server_failed(host, _FAIL_IO_SECONDS)
                except Exception:
                    pass
            raise

        # Login thành công — lấy SSO key
        sso: SsoSession | None = None
        try:
            sso = client.get_sso_key()
        except GarenaError as exc:
            # SSO key thất bại nhưng login vẫn OK — không raise
            command = getattr(exc, "garena_command", 0)
            code = getattr(exc, "garena_result", 0)
            if (command, code) == (COMMAND_SSO_KEY_GET, 3):
                mark_oauth_rate_limited(_OAUTH_RC3_COOLDOWN)
            pass

        return uid, sso


def login_and_authorize(account: str, password: str) -> OAuthResult:
    with GarenaTcpClient() as client:
        client.login(account, password)
        return client.oauth_login()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Kiểm tra đăng nhập Garena trực tiếp trên PC")
    parser.add_argument("account")
    parser.add_argument("password")
    args = parser.parse_args()
    started = time.monotonic()
    result = login_and_authorize(args.account, args.password)
    # Chỉ in thông tin đã che, không ghi mật khẩu hoặc token ra đĩa.
    print(
        {
            "success": True,
            "account": result.masked_account,
            "oauth_length": len(result.response_data),
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
    )
