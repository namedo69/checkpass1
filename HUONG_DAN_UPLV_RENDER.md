# Deploy vệ tinh UpLv lên Render — 0.5.1

## Bàn giao CheckPass → UpLv cho `OK / Lỗi CTNV` — 26/11/2026

- `OK / Lỗi CTNV`, cấp trống không phải ban, không phải xác nhận thiếu nhân vật,
  cũng không phải UpLv đã thất bại. Hai endpoint screening chuyển trường hợp
  này sang hàng chờ UpLv đọc profile, không lặp chunk CheckPass vô hạn.
- Giữ cấp chưa xác nhận, ghi `UPLV_PROFILE_PENDING`, `level_confirmed=false`;
  không ghi đè cấp đã biết. Có bằng chứng khóa thì dừng trước UpLv.
- UpLv vẫn dùng OAuth V2 có điều kiện: `100054 → 100055` chỉ khi nhận
  `141/error_require_grant`, sau đó SSO/HTTP grant nếu cần trên cùng phiên.
  Log `[oauth-v2]`/`[http-grant-v2]` nay được chuyển ra log phòng.
- Không đổi app ID tùy ý sau lỗi CS hoặc ban. Chỉ gửi tạo nhân vật khi server
  yêu cầu `1007`; hết ngân sách hoặc bị từ chối cuối cùng thì dừng.
- Cần cập nhật **master** (`uplv_account_pool.py`) và vệ tinh CheckPass
  (`satellite_worker.py`) cho cả hai đường report; chỉ deploy worker UpLv
  không cập nhật logic bàn giao của master. Không tự sửa trạng thái job cũ
  đã failed; bản vá áp dụng khi nhận screening report mới hợp lệ.
- Thay đổi này được kiểm tra offline; không chứng minh hết lỗi tạo nhân vật
  trên server. Backup: `backups/before_ctnv_handoff_20261126_104813/source.zip`.

## Khôi phục UpLv — 26/11/2026 (0.6.4-v208-experimental)

- Phạm vi lần này: **chỉ `D:\checkpass1`**. Báo cáo kiểm chứng được ghi trước
  commit/push; trạng thái triển khai không được suy ra từ báo cáo đó. Không
  thay `buff_like/` hoặc các chỉnh sửa checker có sẵn. Các mục bên dưới là
  lịch sử; cấu hình thực tế hiện là **5 phòng/vệ tinh**,5 acc/phòng.
- Docker, Blueprint `render_uplv.yaml` và entry Python mặc định `WORKER_MODE=uplv`.
  Render dashboard nếu còn override `WORKER_MODE=buff-like` phải đổi sang `uplv`;
  cập nhật local không thay môi trường đã deploy. Giữ nguyên master URL, ID,
  state và token; source không chứa token, phải dùng env/secret.
- Backend đăng nhập đồng bộ từ V2 **2.0.8-experimental**: live identities,
  OAuth TCP100054/100055 có điều kiện; khi cả hai yêu cầu grant141 mới lấy
  SSO và gửi HTTP token grant trên cùng phiên. Không có credential-login lần
  hai. Nếu vẫn từ chối/429/HTTP403 hoặc lỗi server thì dừng, không đổi version,
  token hay lặp login để vượt chặn. Tạo role tối đa3 lần gửi trong phiên theo
  state machine V2, không reset bằng novice retry.
- Tài nguyên điện thoại `1.64.1.14`; mã packed `0x0300008E` là ứng viên suy
  luận giống V2, **chưa wire/server xác nhận**, chưa tuyên bố hết91121.
- Nhánh đọc profile dùng V2 `create=False, verify_only=True`: không gọi
  vendor connector có auto-create, không grant/chạy trận. Không đọc được cấp
  không phải Lv0 hay không có nhân vật; không xác nhận rảnh từ im lặng.
- Giữ lease/heartbeat, targets riêng từng acc, thay slot có generation,
  kiểm tra UID/kết toán và chặn ghép trận cũ chưa rõ. Thêm deadline connect
  35s, log RECOVERY/SETTLEMENT và writer kết quả riêng trong scheduler rooms.
  Không chép đè service bằng GUI/Qt. Runtime smoke bắt buộc `qt_loaded=false`.
- Giữ web fallback đối soát cho lỗi vận chuyển, nhưng **không fallback sau
  server/auth từ chối**. Điều này không đảm bảo Kiện Tướng hết HTTP403.
- Drain hết phòng và đối soát lease cũ trước redeploy; không chạy hàng loạt
  trước một lượt kiểm chứng tài khoản được ủy quyền. Chưa thử tài khoản thật,
  chưa nghiệm thu Render/relay hoặc độ ổn định5 phòng live.
- Backup: `backups/before_restore_uplv_20261126_101558/source.zip`,94 file
  đã kiểm SHA256. Kết quả offline: `UPLV_RESTORE_VERIFICATION.json`.
- `.gitattributes` giữ nguyên byte trong `uplv_runtime/`, không chuyển đổi
  LF/CRLF khi commit/checkout vì bundle kiểm SHA256 trước khi khởi động.
- Kiểm chứng:67 tests chọn lọc đạt; bộ restore/writer lặp5 lượt đều đạt.
  Full discovery102 tests còn6 failures (subtests nhãn CTNV cũ) và1 error
  (thiếu `job_excel_export`); tái hiện đúng trên baseline trước sửa. Runtime
  smoke không dùng mạng, không Qt;90 file bundle kiểm hash,38 vendor bytecode
  giữ nguyên. Chưa build Docker vì máy không có Docker CLI, chưa deploy thật.

Kiểm tra offline (CPython3.14):

```sh
python -B -m unittest test_uplv_restore test_uplv_oauth_v2 test_uplv_publication test_uplv_web test_uplv_health test_kientuong_grant -v
python -B uplv_satellite.py --check-runtime
```

Lệnh thứ hai mặc định tạo thư mục state theo `UPLV_STATE_DIR`; khi test local
hãy đặt một thư mục tạm riêng. `--check-runtime` không nhận job hay đăng nhập.

## Source 0.6.0 — 4 phòng/vệ tinh

`MAX_ROOMS = 4`; master chặn tối đa 4 lease mỗi vệ tinh. Giới hạn ô phòng
toàn hệ thống vẫn ưu tiên: ví dụ tổng 10 ô thì mọi vệ tinh chia sẻ 10 ô đó.
Mỗi phòng tối đa 5 acc, tối đa 20 acc/vệ tinh. Cần cập nhật cả master và
worker để nhận đủ 4 phòng; chưa đo tải live cấu hình này.

## Source local trên ổ D — 2026-11-10

- Master/source chuẩn: `D:\checkpass`; vệ tinh: `D:\checkpass1`–`D:\checkpass5`.
- `python sync_uplv_satellites.py --update-worker --dry-run` kiểm tra trước;
  bỏ `--dry-run` để đồng bộ payload worker, kiểm SHA256 và backup file khác
  trong `D:\checkpass\uplv_state\sync_backup_*`.
- Payload gồm `uplv_kientuong.py` cả trong Docker để tránh lỗi import khi WIN.
- Scheduler nhận acc lẻ, giới hạn phòng toàn master, ưu tiên nhóm up tiếp.
  `max_rooms=0` ngừng cấp mới. Chờ xác minh không được ghép trận tự động.
- Cập nhật source local không tự deploy/restart VPS hoặc Render. Đọc kết quả
  kiểm thử trong `D:\UpLv_AOV_Standalone\PLAN_NEXT_UPLV.md`, mục 8.

Heartbeat phòng đang xử lý: **5 giây/phòng** (`HEARTBEAT_SECONDS`). Khi rảnh,
claim poll vẫn 15 giây. Lease master vẫn 180 giây. Log không gửi kèm heartbeat;
master chỉ lấy log khi admin yêu cầu. Restart vẫn cần đối soát phòng cũ.

## 0.4.0 — log theo yêu cầu

Giới hạn thử nghiệm mới: `MAX_ROOMS = 2`. Worker chạy hai phòng độc lập,
mỗi phòng tối đa năm acc chuẩn bị song song, report/checkpoint và heartbeat
riêng. Master chặn quá hai lease/phòng-vệ-tinh; worker cũ không gửi capacity
vẫn chỉ được một phòng. Cần cập nhật master trước worker. Chưa đo tải hai
phòng live trên Render; drain phòng trước khi redeploy.

Thiết kế hiện tại dùng pull: worker không gửi log trong heartbeat/report.
Master chỉ gọi endpoint worker `/api/logs` khi admin bấm Lấy log hoặc bật
Tự làm mới mỗi 5s (mặc định tắt). Đóng viewer/tắt checkbox dừng polling;
tab ẩn cũng không poll. Nhập URL worker lần đầu, master lưu mapping theo ID.
Worker giữ tối đa 300 dòng trong RAM của phòng gần nhất, timer lấy mẫu 30s.
Endpoint yêu cầu Bearer token, không public log. Không lưu log mới trong DB
master; restart worker làm mất buffer. Các mô tả gửi batch/lưu DB bên dưới
là thiết kế cũ đã được thay bằng pull.

Trang master `/admin/uplv` có nút **Xem log** cho từng vệ tinh. Hiển thị 500
dòng gần nhất với thời gian/phòng/slot, tự refresh 5s, có tùy chọn theo dõi
cuối log hoặc giữ vị trí đọc. Master lưu tối đa 1.500 dòng/vệ tinh.
Worker gửi batch tối đa 100 dòng/heartbeat 15s; timer chỉ ghi mỗi 30s/acc.
Buffer worker tối đa 300 dòng, có thể mất dòng cũ khi sự kiện dồn quá nhanh.
Report cuối mang log chưa ack (tối đa 300), replay dedup theo event ID.
Username/password và các mẫu token được che trước khi gửi, master che thêm
lần nữa. Endpoint log yêu cầu quyền admin. Log cũ trước bản 0.4.0 không được
truy hồi từ Render. Cần cập nhật cả master và worker; chờ hết phòng đang chạy
trước khi redeploy worker để tránh ngắt trận.

## Các file đã bổ sung

- `render_uplv.yaml`: Blueprint Web Service Docker, plan free để thử nghiệm.
- `Dockerfile.uplv`: Python 3.14, chỉ copy worker và runtime game, không Qt.
- `uplv_health.py`: bind `0.0.0.0:$PORT`, GET `/healthz` trả role/version.
  Endpoint chỉ cho biết tiến trình đang phục vụ, không chứng minh relay game
  hoặc master đang kết nối tốt. Không trả credentials/lease/job.
- `uplv_runtime/`: code/assets production, bỏ ignore thư mục này để Git build
  trên Render có đủ runtime; chỉ cho phép vendor `.pyc` đã đóng gói.

## Triển khai

1. Đưa các file UpLv và `uplv_runtime/` vào repository Git dùng để deploy.
   Không đưa `uplv_state`, env riêng tư hoặc cache thiết bị vào repo. Các thay
   đổi hiện mới ở local, chưa commit/push tự động.
2. Render → New Blueprint → chọn repo, chỉ định `render_uplv.yaml` nếu UI hỗ
   trợ đường dẫn blueprint; hoặc tạo Web Service Docker thủ công, chọn
   Dockerfile `Dockerfile.uplv`, health check `/healthz`.
3. URL/token mặc định lấy từ `uplv_config.py` theo cấu hình người vận hành.
   Có thể override bằng `MASTER_URL`/`MASTER_TOKEN` trong Render khi cần.
   Token được dùng nguyên văn; nếu master trả 401 cần kiểm tra khớp token.
4. Không cần tự đặt SATELLITE_ID: worker lấy RENDER_SERVICE_ID, ổn định theo
   service và khác nhau giữa các service. Có thể override SATELLITE_ID.
5. Đợi health check OK và kiểm tra vệ tinh online tại `/admin/uplv` trên master.
6. Giao một phòng thử và theo dõi kết toán/cấp thực tế, RAM/CPU và relay.

`PORT` do Render cấp. Không publish UDP port để nhận traffic công khai; worker
chủ động mở UDP đến relay và cần nhận được phản hồi qua socket đó.

## Cấu hình cập nhật hàng loạt

`PREPARE_WORKERS = 5` trong `uplv_config.py`: chuẩn bị tối đa năm acc song
song trong một phòng. Login giãn thời điểm bắt đầu 0,6s, không giữ khóa suốt
request mạng. Giai đoạn mở phiên/buff cũng dùng tối đa năm worker; trận chỉ
bắt đầu khi đủ năm phiên hợp lệ. Số phòng mỗi vệ tinh vẫn là một.

Các mặc định URL/token/poll/heartbeat nằm trong `uplv_config.py`, cập nhật
source và redeploy sẽ cập nhật worker. Env Render nếu đã đặt sẽ ưu tiên hơn
source, nên xóa override nếu muốn dùng mặc định mới. File secret mount có
ưu tiên hơn token trong source. Cấu hình source hiện chứa token theo yêu cầu
người vận hành. Các giá trị WORKERS/CONCURRENT_CHUNKS của CheckPass được lưu
để đối chiếu, không tăng số phòng/luồng xử lý game của UpLv.
ID từng service phải riêng. Blueprint không cấu hình quota CPU tùy ý; mức
CPU/RAM do plan Render quyết định, khác quota cgroup thử nghiệm trên VPS.

## Giới hạn hiện tại

- Chưa có phiên Render thật hoàn thành 5v5. VPS đang thử không nhận phản hồi
  relay, trong khi cùng SYN gửi từ local có phản hồi; chưa biết đường Render.
- Free Web Service có thể sleep/restart và filesystem không bền vững. Health
  check không đảm bảo dịch vụ luôn thức. `/state` trong free container sẽ mất
  khi recreate/redeploy: checkpoint/report chưa gửi có thể mất.
- Service ID ổn định không khôi phục một phòng sau kill cứng. Master giữ lease
  cũ thành interrupted để tránh hai worker dùng chung acc; cần đối soát.
- Khi cần chạy liên tục và state bền vững, dùng plan phù hợp có persistent
  disk mount `/state`. Drain phòng trước khi redeploy.
- Chưa thêm proxy/tunnel hoặc sửa giao thức relay. Blueprint này chuẩn bị
  môi trường test đúng Render, không phải bản sửa Relay SYN timeout.

## Kiểm tra local

```sh
python -B -m unittest test_uplv test_uplv_health -q
```
# Tối ưu chuyển lượt phòng (0.6.5-turnover)

- Worker ưu tiên claim UpLv; claim/xử lý CheckPass phụ chạy ngoài vòng điều phối.
- Báo cáo cuối được lưu atomically theo từng lease rồi gửi ở thread riêng, tối đa
  5 báo cáo/lượt quét. Lỗi tạm giữ file và retry backoff 2–30 giây; không chặn
  các slot khác. Chỉ xóa khi master xác nhận hoặc lease/generation bị thu hồi.
- Master vẫn đếm lease đang chạy: báo cáo chưa nhận không tự giải phóng capacity.
  Token, generation, target từng acc và đối soát trận cũ không thay đổi.
- Index `idx_uplv_tasks_fifo` và `idx_uplv_tasks_mode_fifo` hỗ trợ lấy đầu hàng
  đợi. Với PostgreSQL production, tạo bằng `CREATE INDEX CONCURRENTLY` trước
  khi nạp source để tránh giữ khóa ghi khi khởi động.
- `ROOM_END` nghĩa là đã lưu báo cáo, không phải master đã xác nhận trả lease.
  Theo dõi `last_report_error` trong health để phân biệt lỗi gửi báo cáo.
