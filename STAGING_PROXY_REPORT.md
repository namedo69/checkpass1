# Báo cáo nghiệm thu Proxy staging

## Kết quả thực chạy

Môi trường: Windows, CPython 3.14, HTTP server và TCP socket thực trên loopback.

```text
python -m unittest test_staging_proxy -v
Ran 21 tests in 34.754s
OK
```

Đợt chạy độc lập `python -m staging_proxy.lab`:

| Chỉ số | Kết quả |
|---|---:|
| Tác vụ giả lập hoàn tất | 24/24 |
| Satellite | 2 |
| Worker đồng thời mỗi Satellite | 4 |
| Tổng request logic do Master/Satellite tạo | 201 |
| Request được Mock Proxy tiếp nhận | 201 |
| Lượt gửi không được proxy tiếp nhận | 0 |
| Request tới Mock Authentication Server | 73 |
| Request Mock Auth xác minh HMAC proxy hợp lệ | 73 |
| Direct Requests | **0** |
| Request tới Mock Auth thiếu receipt proxy | 0 |
| Client thành công nhưng proxy không forward | 0 |

Theo thành phần, request tới Mock Auth: master **1**, sat-1 **39**, sat-2 **33**.
Cả 4 worker trên từng Satellite đều có request trong evidence. Phân bố tác vụ có thể thay đổi theo lịch thread.

`staging_proxy_evidence.json` là artifact thực chạy, chứa ID request/task/worker/Satellite
và các event độc lập phía client, proxy, Mock Auth. Không chứa password, token, grant,
body hay URL. Số 201 bao gồm claim/config/report, health và các bước mock authentication/profile.
Đây là số request logic ở phía client, không cộng thêm lần proxy chuyển tiếp cùng request.

**Điều kiện nghiệm thu của đợt chạy thành công:**

```text
Direct Requests = 0
Requests Through Proxy = Total Outbound Requests = 201
```

Khi proxy không lắng nghe hoặc TLS bị từ chối, attempt có thể chưa tới HTTP handler của
proxy. Trong những test lỗi này, không thể yêu cầu receipt bằng attempt; kiểm thử yêu cầu
Mock Auth nhận 0 request và không xuất hiện kết nối socket trực tiếp thay thế.

## Kiến trúc

```text
Master staging --ProxyManager--> Mock Proxy A/B --> Mock Auth /health
Satellite control --ProxyManager--> Mock Proxy A --> Master claim/config/report
Satellite workers --ProxyManager--> Proxy theo service --> Mock Auth
                                                       /health
                                                       /authenticate
                                                       /profile
Master --> SQLite: tasks, leases, cấu hình Fernet mã hóa
Master --grant Fernet gắn task/Satellite--> Satellite được cấp quyền
```

- `ProxyManager` kết nối tường minh tới proxy bằng `http.client`, không dùng
  cấu hình proxy môi trường và không có nhánh direct fallback. Không tự theo redirect.
- HTTP proxy, TLS tới HTTPS proxy có kiểm tra chứng chỉ và SOCKS5/PySocks.
  Mục tiêu của lab là HTTP loopback; không triển khai HTTPS origin/CONNECT.
- Chỉ chấp nhận IP literal loopback. Mock Proxy có allowlist chính xác host/port.
  Không import module đăng nhập bên thứ ba.
- Cấu hình gồm host, port, protocol, enabled, username/password, timeout, retries.
  Timeout 0.02–30 giây; retry 0–3, chỉ lỗi kết nối/timeout, không retry lỗi HTTP/xác thực.
- Mỗi request có ID mới; retry giữ nguyên task/worker/Satellite và chính sách định tuyến.
- Master lưu cấu hình theo service; fallback cấu hình `shared` khi chưa có override.
- Worker lấy grant mới trước **từng** request phụ thuộc. Thay đổi áp dụng từ request kế tiếp;
  request đang chạy dùng snapshot cũ. Tắt proxy làm tác vụ lỗi, không cho phép direct.
- Bearer token riêng từng Satellite xác thực API control. Grant mã hóa và xác thực bằng
  Fernet, TTL 60 giây, ràng buộc task/Satellite. API chỉ cấp grant cho chủ lease đang chạy.
- SQLite giữ trạng thái pending/running/done/connection_error và nguyên nhân đã chuẩn hóa.
  Lease 180 giây; mất control proxy thì worker dừng sau retry giới hạn, lease còn lưu để
  cấp lại khi hết hạn. `Store.recover()` đưa tác vụ connection_error về pending khi vận hành phục hồi.
- Mock Proxy ký HMAC request ID + path + body bằng bí mật chỉ mock server/proxy biết.
  Mock Auth kiểm chứng độc lập, ghi nhận và từ chối request thiếu bằng chứng.

## Phân tích source hiện hữu

| Thành phần | Vai trò và kết nối hiện tại |
|---|---|
| `service-litesel.py` | Đặt loại service normal, gọi `satellite_worker.main` |
| `service-liteselVVIP.py` | Đặt loại service vvip, gọi cùng worker |
| `satellite_worker.py` | `_Client` dùng `urllib.request.urlopen`, bearer MASTER_TOKEN, timeout control 120s; claim/heartbeat/report/release; thread pool, lease và xử lý chunk |
| `garena_api_test_chrome1.py` | `run_batch_core`/`batch_check_one`/`run_api_tests`; HTTP opener/cookie jar, urllib, thread pool, retry phân loại; một số chẩn đoán tạo socket/TLS trực tiếp |
| `garena_tcp.py` | `GarenaTcpClient.connect`: DNS, IP dự phòng, `socket.create_connection`, timeout từng lần kết nối tối đa 3s rồi socket timeout; không có proxy transport trong class này |

Luồng production: master nhận tác vụ → Satellite claim chunk → engine kiểm tra từng hàng
→ callback/report → master lưu kết quả; heartbeat giữ lease và release xử lý lỗi.
Staging tái sử dụng **mô hình** claim/report, bearer, SQLite và thread pool, với endpoint,
database và transport riêng. Không nối staging vào production login engine.

## Kết quả kiểm thử

| Yêu cầu | Kết quả |
|---|---|
| 1. Một worker qua proxy | PASS; full health/authenticate/profile |
| 2. Nhiều worker đồng thời | PASS; 24 tác vụ, 8 worker cấu hình |
| 3. Nhiều Satellite | PASS; cả sat-1 và sat-2 có evidence |
| 4. Proxy có xác thực | PASS; HTTP Basic và SOCKS5 user/password |
| 5. Sai thông tin xác thực | PASS; proxy_auth, không retry, Mock Auth nhận 0 |
| 6. Proxy mất kết nối | PASS; disconnect/refused, không fallback |
| 7. Proxy timeout | PASS; proxy_timeout, retry giới hạn, Mock Auth nhận 0 |
| 8. Proxy trả lỗi | PASS; proxy_response tách biệt service_response |
| 9. Retry lỗi tạm thời | PASS; hai receipt proxy, một request tới Mock Auth |
| 10. Tắt proxy khi đang chạy | PASS; không gửi profile, giữ lỗi, phục hồi qua proxy mới |
| 11. Master restart | PASS; đóng/mở HTTP server cùng port, mở lại SQLite/config |
| 12. Satellite restart | PASS; hủy instance, hết lease, Satellite khác nhận lại |
| 13. Không direct request | PASS; receipt/HMAC và quan sát địa chỉ socket độc lập |

Các kiểm thử bổ sung: validation IP/cấu hình, che credentials trong repr, mã hóa SQLite,
grant sai khóa/chủ sở hữu, service normal/vvip đi đúng proxy, HTTPS proxy với chứng chỉ
tin cậy và từ chối chứng chỉ không tin cậy, SOCKS5 thật, control proxy outage và phục hồi.
Negative control cố ý gửi **một** request trực tiếp tới Mock Auth trong test riêng:
detector ghi nhận direct=1 và trả 403. Request cố ý này không thuộc đợt nghiệm thu 201 request.

## File mới

- `staging_proxy/__init__.py`
- `staging_proxy/transport.py`
- `staging_proxy/mocks.py`
- `staging_proxy/cluster.py`
- `staging_proxy/lab.py`
- `test_staging_proxy.py`
- `staging_proxy_evidence.json` (artifact chạy thực tế)
- `STAGING_PROXY_REPORT.md`

Không chỉnh sửa file production hiện hữu.

## Chạy lại và cấu hình

Các dependency `cryptography` và `PySocks` đã có trong `requirements.txt`.

```powershell
python -m unittest test_staging_proxy -v
$env:STAGING_REPORT = 'D:\checkpass\staging_proxy_evidence.json'
python -m staging_proxy.lab
```

Lab tự tạo port, mật khẩu, token và khóa ngẫu nhiên mỗi lần chạy. Không cần tài khoản.
Cấu hình tùy chỉnh qua API Python cho staging:

```python
from staging_proxy.transport import ProxyConfig

# operator_config được nạp từ secret/config của môi trường staging.
config = ProxyConfig(**operator_config)
store.configure('shared', config)
store.configure('vvip', override_config)
```

`Store(path, key)` nhận khóa Fernet từ bên ngoài; không lưu khóa trong DB.
Lab hỗ trợ `STAGING_STORAGE_KEY`, `STAGING_GRANT_KEY`; nếu không đặt, tạo khóa tạm.
Khi cần giữ database qua restart, ứng dụng staging phải giữ nguyên khóa và bearer token
trong secret store của môi trường. Runner demo dùng DB tạm và xóa sau mỗi lượt.

## Giới hạn còn tồn tại

- Đây là nghiệm thu local staging với nhiều đối tượng Satellite/thread qua HTTP socket thật,
  không phải deploy nhiều VPS/process. Restart được mô phỏng bằng tái tạo thành phần và
  server; test hết lease chủ động đặt thời hạn về 0 để không chờ 180 giây.
- Control bootstrap proxy/token được cấp lúc khởi tạo; hot reload áp dụng cho proxy tác vụ,
  đổi bootstrap control cần tái tạo Satellite. Bootstrap chỉ cấp cấu hình control cần thiết.
- Claim/report không có idempotency key chống mất response sau commit. Lease giữ trạng thái
  và cho cấp lại; tác vụ mock có thể chạy lại (at-least-once), không cam kết exactly-once.
- Lab HTTP loopback không cung cấp bảo vệ kênh control khỏi tiến trình đặc quyền cục bộ;
  grant/config được mã hóa, nhưng bearer control dùng HTTP trong môi trường local này.
- Không có UI staging; cấu hình bằng module/API Python. Không có firewall cấp hệ điều hành:
  bảo đảm và bằng chứng áp dụng cho các đường mạng do luồng staging này tạo ra.
