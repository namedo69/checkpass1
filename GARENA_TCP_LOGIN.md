# Tài liệu cơ chế đăng nhập Garena TCP trong dự án

## 1. Phạm vi và nguồn tài liệu

Tài liệu này mô tả cơ chế được khôi phục từ mã đang đóng gói trong dự án, chủ yếu từ:

- `TOOL AUTO UP LEVEL/_internal/apk_analysis/api_system_v1/device_192.168.1.22_56625/billow_tool/runtime_snapshot/garena_tcp.py`
- `_security_audit_extract/billow_sso.pyc`
- `_security_audit_extract/login_worker.pyc`
- `_security_audit_extract/garena_auth.pyc`

Đây là tài liệu kỹ thuật nội bộ dựa trên mã của dự án, không phải đặc tả giao thức chính thức do Garena công bố. Giao thức riêng trên cổng TCP 19000 có thể thay đổi mà không báo trước.

## 2. Ứng dụng nhận được gì từ TCP?

Đăng nhập TCP không trả trực tiếp access token và refresh token trong luồng đang sử dụng. Nó tạo ra hai cấp kết quả:

### Sau command LOGIN (`0x101`)

Ứng dụng nhận được:

- `uid`: định danh số của tài khoản Garena.
- `session_key`: khóa phiên 16 byte dùng để mã hóa các command TCP sau khi đăng nhập.

Trong API Python, `GarenaTcpClient.login()` chỉ trả về `uid`, còn `session_key` được giữ trong đối tượng client.

### Sau command SSO_KEY_GET (`0x1BA`)

Ứng dụng nhận được:

- `uid`.
- `sso_key`: chuỗi 64 ký tự hexadecimal, hoạt động như cookie/bearer credential tạm thời.
- `expiry_time`: thời điểm SSO key hết hạn.

`sso_key` sau đó được gửi qua HTTPS tới Garena Connect để nhận authorization code và đổi thành:

- `access_token`.
- `refresh_token`.
- `open_id`.
- `expiry_time` của access token.
- `refresh_expiry_time` của refresh token.

Tóm tắt:

```text
username + password
        |
        v
Garena TCP LOGIN
        |
        +--> uid
        +--> session_key
                 |
                 v
          TCP SSO_KEY_GET
                 |
                 +--> sso_key + expiry_time
                              |
                              v
                     HTTPS OAuth grant/exchange
                              |
                              +--> access_token
                              +--> refresh_token
                              +--> open_id
```

## 3. Máy chủ và thông số client

```text
Host: mconnect.gxx.garenanow.com
Port: 19000/TCP
Client version: 283
Platform: Android (0x11)
Android Google Play: 0x1100
Android internal request namespace: 0x1102
App ID AOV: 100054
Redirect URI: gop100054://auth/
```

Nếu DNS không hoạt động, mã hiện tại lần lượt thử các IP:

```text
103.247.205.14
103.247.205.15
103.247.205.16
103.247.205.17
103.247.205.18
103.247.205.19
103.247.205.20
103.247.205.22
```

## 4. Danh sách command

| Command | Giá trị | Vai trò | Luồng hiện tại dùng? |
|---|---:|---|---|
| `LOGIN_PREPARE` | `0x100` | Gửi account, nhận `salt` và `verify_code` | Có |
| `LOGIN` | `0x101` | Xác thực password hash, nhận `uid` và `session_key` | Có |
| `LOGIN_TOKEN_GET` | `0x115` | Được khai báo nhưng chưa triển khai trong file khôi phục | Không |
| `APP_OAUTH_LOGIN` | `0x1B7` | Lấy OAuth response data trực tiếp qua TCP | Có code nhưng luồng chính không gọi |
| `SSO_KEY_GET` | `0x1BA` | Lấy SSO cookie tạm thời | Có |

## 5. Định dạng frame TCP

Khi chưa có session key:

```text
+----------------------+------------------------------------------+
| 4 byte little-endian | Độ dài body                              |
+----------------------+------------------------------------------+
| 2 byte big-endian    | Độ dài protobuf header                   |
+----------------------+------------------------------------------+
| N byte               | Protobuf-like header                     |
+----------------------+------------------------------------------+
| còn lại              | Payload                                  |
+----------------------+------------------------------------------+
```

Khi đã có session key, toàn bộ phần từ `header-length` đến hết payload được mã hóa trước khi thêm trường body-length.

Header protobuf-like:

| Tag | Giá trị |
|---:|---|
| 1 | `(0x11 << 24) | 283` |
| 2 | `(0x1102 << 32) | sequence` |
| 3 | `2` |
| 4 | Command ID |
| 6 | Unix timestamp |

Response được kiểm tra `command` ở tag 4 và mã kết quả ở tag 5. Mã hiện tại chưa đối chiếu request ID của response với request vừa gửi.

## 6. Mã hóa payload

Mã sử dụng XTEA 32 vòng, block 8 byte, khóa 16 byte, chế độ CBC.

Trước khi mã hóa, plaintext được bọc như sau:

```text
[8 byte ngẫu nhiên]
[payload thật]
[padding 1..8 byte]
[checksum uint64]
```

`checksum` là tổng các block 64-bit little-endian modulo `2^64`. CBC dùng IV bằng 8 byte zero; block ngẫu nhiên ở đầu làm ciphertext thay đổi giữa các lần gửi.

Checksum này chỉ giúp phát hiện lỗi dữ liệu thông thường. Nó không phải MAC/HMAC và không cung cấp tính toàn vẹn mật mã.

## 7. Trình tự LOGIN_PREPARE

Client tạo khóa ngẫu nhiên:

```python
prepare_key = os.urandom(16)
```

`prepare_data`:

| Tag | Giá trị |
|---:|---|
| 1 | `0` |
| 2 | `1` |
| 3 | Account dạng UTF-8 |
| 4 | `0x1100` |
| 5 | `283` |

Payload command `0x100`:

| Tag | Giá trị |
|---:|---|
| 1 | `prepare_key` |
| 2 | `XTEA-CBC(prepare_data, prepare_key)` |

Packet ngoài không được mã hóa bằng một khóa phiên. Do `prepare_key` nằm ngay trong payload, đây không phải cơ chế giữ bí mật account trước người quan sát mạng.

Response chứa:

| Tag | Giá trị |
|---:|---|
| 1 | `reply_key` 16 byte |
| 2 | Dữ liệu chuẩn bị được mã hóa bằng `reply_key` |

Sau giải mã, dữ liệu chuẩn bị chứa:

| Tag | Giá trị |
|---:|---|
| 1 | `salt` |
| 2 | `verify_code` |

## 8. Trình tự LOGIN

Khóa đăng nhập được tạo như sau:

```python
password_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
salted_hash = hashlib.sha256((password_md5 + salt).encode("utf-8")).hexdigest()
login_key = hashlib.sha256((salted_hash + verify_code).encode("utf-8")).digest()[:16]
```

Client đồng thời tạo một device ID ngẫu nhiên cho phiên TCP:

```python
device_id = os.urandom(8).hex()
```

`login_data`:

| Tag | Giá trị |
|---:|---|
| 1 | Chuỗi hex `password_md5` |
| 2 | `0` |
| 3 | Message con chứa user status `0x1200` |
| 4 | Device ID ngẫu nhiên |

Client mã hóa `login_data` bằng `login_key`, đặt ciphertext vào tag 1 và gửi command `0x101`.

Response sau khi giải mã bằng cùng `login_key`:

| Tag | Giá trị |
|---:|---|
| 1 | `uid` |
| 2 | `session_key` 16 byte |

Từ thời điểm này, client coi phiên TCP là đã đăng nhập.

## 9. Lấy SSO key

Client gửi command `0x1BA` với payload rỗng. Toàn bộ body được mã hóa bằng `session_key`.

Response:

| Tag | Giá trị |
|---:|---|
| 1 | `sso_key` 64 ký tự hex |
| 2 | Unix expiry time |

Client từ chối SSO key nếu sai độ dài, chứa ký tự ngoài hexadecimal hoặc đã hết hạn.

## 10. Đổi SSO thành OAuth token

Đây là phần HTTPS, không còn nằm trong kết nối TCP 19000.

### Grant authorization code

```http
POST https://100054.connect.garena.com/oauth/token/grant
Cookie: sso_key=<64-hex-sso-key>
Content-Type: application/x-www-form-urlencoded
```

Các trường form chính:

```text
client_id=100054
response_type=code
redirect_uri=gop100054://auth/
create_grant=true
login_scenario=normal
format=json
id=<timestamp milliseconds>
```

### Exchange token

```http
POST https://100054.connect.garena.com/oauth/token/exchange
Content-Type: application/x-www-form-urlencoded
```

Các trường form:

```text
grant_type=authorization_code
code=<authorization-code>
device_id=<stable-device-id>
redirect_uri=gop100054://auth/
source=2
client_id=100054
client_secret=<được lấy từ cấu hình bytecode cục bộ>
```

Không ghi giá trị `client_secret` vào tài liệu hoặc log.

## 11. Đưa kết quả vào game

`login_worker.pyc` nhận `TokenBundle` rồi tạo token cache MSDK gồm:

```json
{
  "authToken": "<access_token>",
  "expiryTimestamp": 0,
  "refreshToken": "<refresh_token>",
  "openId": "<open_id>",
  "lastInspectTime": 0,
  "mainPlatform": 1,
  "main_active_platform": 1,
  "login_platform": 1,
  "refresh_expiry_time": 0
}
```

Các số thời gian trong file thật được lấy từ token và thời gian hiện hành; ví dụ trên chỉ minh họa cấu trúc.

JSON được escape vào:

```text
/data/data/com.garena.game.kgvn32/shared_prefs/com.garena.msdk.token_cache.xml
```

Sau khi khởi chạy game, desktop gửi `MSDK_AUTO_LOGIN` tới bridge cục bộ của APK qua ADB-forward/TCP 27625. Bridge này chỉ kích hoạt MSDK đọc token cache; nó không thực hiện xác thực username/password với Garena.

## 12. Thuộc tính bảo mật và giới hạn

1. TCP 19000 không dùng TLS hoặc certificate pinning.
2. `prepare_key` và `reply_key` xuất hiện trong packet chưa có bảo vệ phiên.
3. Người quan sát có thể thu account, salt, verify code và ciphertext login, từ đó có khả năng thử mật khẩu ngoại tuyến.
4. XTEA-CBC kèm checksum cộng không cung cấp xác thực dữ liệu như AEAD/HMAC.
5. Client không đối chiếu request ID của response.
6. SSO key là bearer credential và phải được bảo vệ tương đương mật khẩu trong thời gian còn hạn.
7. OAuth client secret nhúng trong ứng dụng desktop không thể được coi là bí mật lâu dài.
8. Hash SHA-256 kiểm tra file `garena_tcp.py` chỉ là kiểm tra tính toàn vẹn cục bộ, không phải ranh giới chống sửa đổi khi kẻ tấn công kiểm soát toàn bộ client.

## 13. Khuyến nghị sử dụng

- Ưu tiên SDK/authorization flow chính thức thay vì nhận mật khẩu Garena trong tool PC.
- Không ghi account/password nguyên dòng vào các file kết quả.
- Không log password, MD5 password, login key, session key, SSO key hoặc OAuth token.
- Không gửi các credential trên qua bridge TCP 27625.
- Bổ sung HMAC, nonce và secret ngẫu nhiên theo phiên cho bridge cục bộ.
- Nếu buộc phải giữ client TCP, cần thêm kiểm tra request ID, giới hạn kích thước, timeout và xóa credential khỏi bộ nhớ sớm nhất có thể.
- Xem `sso_key`, `access_token` và `refresh_token` là dữ liệu nhạy cảm có khả năng chiếm quyền tài khoản.

## 14. Pseudocode luồng đang sử dụng

```python
with GarenaTcpClient() as tcp:
    uid = tcp.login(account, password)
    sso = tcp.get_sso_key()

authorization_code = garena_connect.grant_code(sso.sso_key)
bundle = garena_connect.exchange_token(authorization_code, stable_device_id)

token_vault.save(account, bundle)       # Windows DPAPI
install_msdk_token_cache(device, bundle) # ADB + root
launch_game(device)
bridge.send("MSDK_AUTO_LOGIN")
```

Kết quả cuối cùng mà phần còn lại của chương trình sử dụng là `TokenBundle`, không phải password hoặc session TCP.

## 15. Công cụ test login-only trên Chrome

Dự án có kèm `garena_tcp_login_chrome.py`. Chrome không hỗ trợ raw TCP, vì vậy trang web chỉ chạy trên `127.0.0.1`; Python localhost thực hiện kết nối TCP 19000.

Chạy bằng một trong hai cách:

```text
CHAY_TEST_GARENA_TCP_CHROME.cmd
```

hoặc:

```powershell
python garena_tcp_login_chrome.py
```

Mặc định Chrome mở địa chỉ:

```text
http://127.0.0.1:8765/
```

Bản test chỉ thực hiện `LOGIN_PREPARE` và `LOGIN`, rồi hiển thị `uid`, kích thước session key và thời gian phản hồi. Nó không gọi `SSO_KEY_GET`, không đổi OAuth token và không ghi mật khẩu xuống file/log.

Kiểm tra mã và SHA-256 mà không kết nối Garena:

```powershell
python garena_tcp_login_chrome.py --self-test
```

## 16. Công cụ test các API read-only

Chạy `CHAY_TEST_GARENA_APIS_CHROME.cmd` hoặc:

```powershell
python garena_api_test_chrome.py
```

Chrome mở `http://127.0.0.1:5555/`. Có thể mở thêm nhiều cổng dùng chung trạng thái bằng cách lặp tham số, ví dụ `--port 5555 --port 5556`. Nhập một dòng `user|pass`. Công cụ thực hiện TCP login, lấy SSO key trong bộ nhớ và thử tuần tự:

- `account.garena.com/api/account/init`
- OAuth Kiện Tướng và `api/player/get`
- OAuth Sale và GraphQL operation `getUser`
- GOP/NapThe session exchange và `api/shop/history?app_id=100054`

Mỗi API trả kết quả độc lập gồm HTTP status, thời gian và JSON body. Token, cookie, SĐT, email và giấy tờ định danh được che trước khi đưa về Chrome. Công cụ không ghi credential hoặc token xuống file/log và không gọi API thay đổi tài khoản, giao dịch hoặc mua hàng.

Garena có thể gửi server-push xen giữa request và response (đã quan sát command `0x126` sau login). Bản API test bỏ qua tối đa 16 command không khớp trong cùng timeout và tiếp tục chờ đúng response `0x1BA`. Danh sách command đã bỏ qua xuất hiện tại `tcp.ignored_server_commands`; payload server-push không được log.

## 17. Ranh giới giữa TCP SSO và Web OAuth

`sso_key` lấy từ command TCP `0x1BA` dùng được với cổng Connect của ứng dụng game, nhưng không tự tạo `sso_session` cho `auth.garena.com/universal`. Không được gắn khóa này thành cookie dùng chung cho `.garena.com`: cổng OAuth vẫn trả trang đăng nhập và các service tiếp tục báo `NOT_LOGIN`.

Bản API test hiện làm rõ hai bước độc lập:

1. TCP login xác nhận credential và lấy UID/session/SSO của client game.
2. Universal Login gọi `/api/prelogin`, `/api/login`, rồi `/oauth/token/grant` để nhận callback và cookie riêng của từng web service.

Nếu Garena trả CAPTCHA, OTP, `error_security_ban` hoặc `error_suspicious_ip`, công cụ dừng ở stage tương ứng và không thử vượt cơ chế đó. Trường `web_auth` trong JSON cho biết lỗi xảy ra ở `prelogin`, `login`, `oauth_grant` hay `callback`; trường `apis.*.http_ok` phân biệt HTTP thành công với lỗi nghiệp vụ nằm trong JSON body.
