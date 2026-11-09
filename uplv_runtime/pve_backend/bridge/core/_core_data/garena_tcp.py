from __future__ import annotations

import hashlib
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field


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
            try:
                self.socket = socket.create_connection(
                    (host, GARENA_PORT), min(self.timeout, 3.0)
                )
                self.socket.settimeout(self.timeout)
                return
            except OSError as exc:
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
