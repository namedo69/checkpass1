# Deploy vệ tinh UpLv lên Render — 0.5.1

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
