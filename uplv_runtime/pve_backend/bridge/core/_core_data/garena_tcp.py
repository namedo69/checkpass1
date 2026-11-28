from __future__ import annotations

import hashlib
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field


GARENA_HOST = "mconnect.gxx.garenanow.com"
GARENA_PORT = 19000
GARENA_IPV4_FALLBACKS = tuple(f"103.247.205.{last}" for last in range(14, 24))
_REQUEST_SEQUENCE = 0
_REQUEST_SEQUENCE_LOCK = threading.Lock()
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


class AuthStopped(RuntimeError):
    def __init__(self):
        super().__init__('Stopped')


def check_auth_stop(stop_event):
    """Cooperative boundary check; never interrupts an in-flight OS request."""
    if stop_event is not None and stop_event.is_set():
        raise AuthStopped()


class GarenaError(RuntimeError):
    def __init__(self, message, *, code=None, stage=None, app_id=None, reason=None, http_status=None):
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.app_id = app_id
        self.reason = reason
        self.http_status = http_status


def _account_type(account: str) -> int:
    # TLT garenaAccountType 0x1402be740: contains @, then ParseInt(base10,64).
    if '@' in account:
        return 2
    digits = account[1:] if account[:1] in ('+', '-') else account
    if digits and all('0' <= c <= '9' for c in digits):
        value = int(account)
        if -(1 << 63) <= value < (1 << 63):
            return 3
    return 1


def _device_bytes(account: str) -> bytes:
    # NewLeverSession 0x1402ce96a..0x1402ce9ee, raw slice passed to login.
    raw = bytearray(hashlib.sha256(('vua_uplv_dev:' + account.lower()).encode('utf-8')).digest()[:16])
    raw[6] = (raw[6] & 15) | 64
    raw[8] = (raw[8] & 63) | 128
    return bytes(raw)


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
        self.stop_event = None
        self.socket: socket.socket | None = None
        self.session_key: bytes | None = None
        self.uid = 0

    def __enter__(self) -> "GarenaTcpClient":
        self.connect()
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def connect(self) -> None:
        self.close()
        # TLT's static Go slice at 0x1407b2a20 has these ten direct endpoints.
        # Pool pacing/cooldown is not reconstructed here; do not retry OAuth
        # denials by rotating gateways.
        candidates = list(GARENA_IPV4_FALLBACKS)
        last_error: OSError | None = None
        for host in dict.fromkeys(candidates):
            check_auth_stop(self.stop_event)
            try:
                self.socket = socket.create_connection(
                    (host, GARENA_PORT), min(self.timeout, 3.0)
                )
                self.socket.settimeout(self.timeout)
                check_auth_stop(self.stop_event)
                return
            except AuthStopped:
                # __exit__ is not called when __enter__/connect raises.
                self.close()
                raise
            except OSError as exc:
                check_auth_stop(self.stop_event)
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
        # TLT 0x1402fc11e..0x1402fc141: process-wide atomic increment,
        # mask to 31 bits, then OR 0x1102 (not shifted into the high word).
        global _REQUEST_SEQUENCE
        with _REQUEST_SEQUENCE_LOCK:
            _REQUEST_SEQUENCE = (_REQUEST_SEQUENCE + 1) & 0xFFFFFFFFFFFFFFFF
            return (_REQUEST_SEQUENCE & 0x7FFFFFFF) | CLIENT_ANDROID_INTERNAL

    def _receive_exact(self, size: int, *, deadline=None) -> bytes:
        if self.socket is None:
            raise GarenaError("Kết nối Garena chưa được mở")
        result = bytearray()
        while len(result) < size:
            check_auth_stop(self.stop_event)
            try:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('SSO deadline')
                    self.socket.settimeout(remaining)
                chunk = self.socket.recv(size - len(result))
            except OSError as exc:
                check_auth_stop(self.stop_event)
                raise GarenaError("Mất kết nối với máy chủ Garena") from exc
            check_auth_stop(self.stop_event)
            if not chunk:
                raise GarenaError("Máy chủ Garena đã đóng kết nối")
            result.extend(chunk)
        return bytes(result)

    def _request_response(self, command: int, payload: bytes, key: bytes | None = None, *, deadline=None):
        """Preserve header status and body for the bounded OAuth policy."""
        if self.socket is None:
            raise GarenaError("Kết nối Garena chưa được mở")
        request_id = self._next_id()
        def receive(size):
            return (self._receive_exact(size) if deadline is None else
                    self._receive_exact(size, deadline=deadline))
        try:
            check_auth_stop(self.stop_event)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('SSO deadline')
                self.socket.settimeout(remaining)
            self.socket.sendall(_encode_packet(request_id, command, payload, key))
        except OSError as exc:
            check_auth_stop(self.stop_event)
            raise GarenaError("Không gửi được yêu cầu tới Garena") from exc
        check_auth_stop(self.stop_event)
        # TLT waits for a matching command/request-id/type, up to five frames.
        # Unrelated pushes must not drive OAuth fallback or token validation.
        for _ in range(5):
            size = struct.unpack("<I", receive(4))[0]
            if size <= 0 or size > 4 * 1024 * 1024:
                raise GarenaError("Kích thước phản hồi Garena không hợp lệ")
            header, reply = _decode_packet(receive(size), key)
            if (_first_int(header, 4) == command and
                    _first_int(header, 2) == request_id and
                    _first_int(header, 3) == 3):
                return header, reply
        raise GarenaError("Không nhận được phản hồi Garena khớp sau 5 gói",
                          stage='tcp-match', reason='unmatched_response')

    def _request(self, command: int, payload: bytes, key: bytes | None = None) -> bytes:
        header, reply = self._request_response(command, payload, key)
        reply_command = _first_int(header, 4)
        result = _first_int(header, 5)
        if reply_command != command:
            raise GarenaError(f"Sai lệnh phản hồi Garena: {reply_command}")
        if result != 0:
            raise GarenaError(f"Garena từ chối yêu cầu, mã {result}", code=result,
                              stage='tcp-header', reason='header_rejected')
        return reply

    def login(self, account: str, password: str) -> int:
        check_auth_stop(self.stop_event)
        account = account.strip()
        if not account or not password:
            raise GarenaError("Tài khoản hoặc mật khẩu trống")
        if self.socket is None:
            self.connect()

        prepare_key = os.urandom(16)
        prepare_data = b"".join(
            (
                _field_varint(1, 0),
                _field_varint(2, _account_type(account)),
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
        salt = _first_bytes(prepared, 1)
        verify_code = _first_bytes(prepared, 2)

        password_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
        salted_hash = hashlib.sha256(password_md5.encode('ascii') + salt).hexdigest()
        login_key = hashlib.sha256(salted_hash.encode('ascii') + verify_code).digest()[:16]
        device_id = _device_bytes(account)
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

    def oauth_token_login(self) -> OAuthResult:
        """New TLT: bounded TCP pair, then SSO + HTTP token grant if denied."""
        check_auth_stop(self.stop_event)
        if not self.session_key or not self.uid:
            raise GarenaError("Chưa đăng nhập Garena")
        self.oauth_diagnostics = []
        for attempt, app_id in enumerate((100054, 100055), 1):
            check_auth_stop(self.stop_event)
            request = b"".join((
                _field_varint(1, app_id), _field_string(2, ""),
                _field_varint(3, 2), _field_string(4, ""),
                _field_varint(5, 0), _field_varint(6, 17),
            ))
            header, raw = self._request_response(COMMAND_APP_OAUTH_LOGIN, request, self.session_key)
            check_auth_stop(self.stop_event)
            rc = _first_int(header, 5)
            try:
                reply = _parse_message(raw)
            except (GarenaError, ValueError, IndexError, struct.error):
                raise GarenaError('OAuth body không hợp lệ', code=rc, stage='oauth-decode',
                                  app_id=app_id, reason='malformed_body') from None
            error = _first_bytes(reply, 5)
            grant = error == b'error_require_grant'
            fallback = attempt == 1 and (grant or rc == 141)
            http_grant = attempt == 2 and (grant or rc == 141)
            action = 'fallback' if fallback else ('sso-http-grant' if http_grant else ('reject' if error or rc or
                      _first_int(header, 4) != COMMAND_APP_OAUTH_LOGIN else 'validate-token'))
            event = dict(app_id=app_id, attempt=attempt, rc=rc,
                         body_error='require_grant' if grant else ('present' if error else 'none'),
                         action=action)
            self.oauth_diagnostics.append(event)
            callback = getattr(self, 'oauth_log', None)
            if callback:
                callback(f'[oauth-v2] app_id={app_id} attempt={attempt}/2 rc={rc} '
                         f'body_error={event["body_error"]} action={action}')
            if fallback:
                continue
            if http_grant:
                check_auth_stop(self.stop_event)
                try:
                    sso_key = self.request_sso_key_for_grant()
                except GarenaError:
                    # TLT retains the original grant denial if SSO fails.
                    if callback:
                        callback('[sso-v2] command=442 action=reject next=stop')
                else:
                    if callback:
                        callback('[sso-v2] command=442 action=success next=http-grant')
                    try:
                        from .garena_http_grant import grant_token
                        check_auth_stop(self.stop_event)
                        token, open_id = grant_token(sso_key, opener=getattr(self, 'http_grant_opener', None),
                                                    stop_event=self.stop_event)
                        check_auth_stop(self.stop_event)
                    except GarenaError as exc:
                        if callback:
                            callback(f'[http-grant-v2] app_id=100055 http={exc.http_status} '
                                      f'reason={exc.reason} action=reject next=stop')
                            if getattr(exc, 'diagnostics', None):
                                import json
                                callback('[http-grant-diagnostics] '+json.dumps(exc.diagnostics, sort_keys=True))
                        if exc.reason != 'require_grant':
                            raise
                    else:
                        if callback:
                            callback('[http-grant-v2] app_id=100055 action=success next=msdk-vn')
                        return OAuthResult(self.uid, open_id, token, '', ())
            # TLT checks body field 5 before command/status validation.
            if error or rc == 141:
                reason = 'require_grant' if grant or rc == 141 else 'body_error'
                raise GarenaError('OAuth cần cấp quyền' if reason == 'require_grant' else 'OAuth body báo lỗi',
                                  code=141 if reason == 'require_grant' else rc,
                                  stage='oauth-body' if error else 'oauth-header', app_id=app_id, reason=reason)
            if _first_int(header, 4) != COMMAND_APP_OAUTH_LOGIN or rc:
                raise GarenaError('OAuth header từ chối', code=rc, stage='oauth-header',
                                  app_id=app_id, reason='rate_limited' if rc == 3 else 'header_rejected')
            try:
                # Go return tracing 0x1402c7231..0x1402c738b:
                # field1 -> first returned string (access token),
                # field4 -> second returned string (32-byte Garena open_id).
                token = _first_bytes(reply, 1).decode('utf-8', 'strict').strip()
                open_id = _first_bytes(reply, 4).decode('utf-8', 'strict').strip()
            except UnicodeError:
                raise GarenaError('OAuth token/open ID không hợp lệ', stage='oauth-token',
                                  app_id=app_id, reason='invalid_token_encoding') from None
            if not open_id or not token:
                raise GarenaError('OAuth thiếu token/open ID', stage='oauth-token',
                                  app_id=app_id, reason='missing_token')
            if callback:
                callback(f'[oauth-v2] app_id={app_id} action=success next=msdk-vn')
            return OAuthResult(self.uid, open_id, token, '', ())

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


    def request_sso_key_for_grant(self) -> str:
        """New TLT command442: eight-second deadline; nonempty field1 only."""
        check_auth_stop(self.stop_event)
        if self.socket is None or not self.session_key or not self.uid:
            raise GarenaError('Chưa đăng nhập Garena', stage='tcp-sso', reason='no_session')
        previous_timeout = self.socket.gettimeout()
        try:
            header, raw = self._request_response(COMMAND_SSO_KEY_GET, b'', self.session_key,
                                                 deadline=time.monotonic() + 8.0)
            check_auth_stop(self.stop_event)
            if _first_int(header, 5):
                raise GarenaError('Garena từ chối SSO', stage='tcp-sso', reason='sso_rejected')
            key = _first_bytes(_parse_message(raw), 1).decode('utf-8', 'strict').strip()
            if not key:
                raise GarenaError('Garena trả SSO rỗng', stage='tcp-sso', reason='empty_sso')
            return key
        except (AuthStopped, GarenaError):
            raise
        except Exception:
            raise GarenaError('Không nhận được SSO', stage='tcp-sso', reason='invalid_sso') from None
        finally:
            self.socket.settimeout(previous_timeout)

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
