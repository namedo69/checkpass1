# Render: chuyển vệ tinh uplv thành buff like

Giữ Dockerfile.uplv và lệnh `python -B uplv_satellite.py`. Mặc định chạy buff
like; đặt WORKER_MODE=uplv để quay lại chương trình uplv. Không đổi master uplv.
Không chạy hai loại worker trên cùng instance. Drain công việc cũ trước deploy.

## Host buff like — cần chuẩn bị trước khi push worker

1. Backup DB/source production. Thêm `backend_native/render_workers.py` và
   hook `/v1/render-workers/` trong Handler.do_POST của api.py. Không chép đè
   toàn bộ api.py local lên production vì có thể khác bản đang chạy.
2. Apply `backend_native/render_workers_schema.sql` trong DB autobuff_native
   bằng role sở hữu bảng. Đây là migration tách riêng, không tự chạy khi import.
3. Tạo token ngẫu nhiên ít nhất 32 ký tự; đặt AUTOBUFF_RENDER_TOKEN trong env
   của API host. Không dùng lại MASTER_TOKEN uplv hoặc token admin/native API.
4. Kiểm tra HTTPS domain/reverse proxy chuyển /v1/render-workers/ tới API native.
   Domain mặc định https://hot.sp1s.shop cần được xác minh trước live rollout.
5. Reload/restart API có kiểm soát; không cần restart các worker VPS hiện có.

## Render — dùng deployment uplv hiện tại

- URL và token fleet đã nhúng trong `buff_like/fleet_config.py`, khớp token
  trên host. Không cần đặt BUFF_MASTER_URL/BUFF_WORKER_TOKEN trên Render.
  Env nếu đã đặt và không rỗng vẫn ưu tiên hơn source.
- Theo yêu cầu vận hành, token nằm trong source và sẽ vào lịch sử Git nếu push.
  Chỉ sử dụng repo private, giới hạn người có quyền đọc repo/build log/image.
  Ai lấy được token có thể nhận pack chứa thông tin đăng nhập account.
- BUFF_MAX_ACCOUNTS=15 (clamp cứng tối đa 15 mỗi process).
- WORKER_MODE=buff-like.
- RENDER_SERVICE_ID tự nhận dạng; local phải đặt BUFF_WORKER_ID riêng.
- MASTER_URL/MASTER_TOKEN cũ không dùng cho buff like, tránh gọi nhầm master uplv.
- Build check `python -B uplv_satellite.py --check-runtime` không gọi mạng/game.
- GET /healthz: service_type=buff-like. Health OK không chứng minh host/game OK.

Commit/push phải gồm `buff_like/`, `uplv_satellite.py`, `Dockerfile.uplv` và tài
liệu này. Script push_uplv_repos.py cũ chỉ stage allowlist uplv, chưa hỗ trợ
payload mới và thiếu checkpass6: không dùng nguyên script cũ để push buff like.
Không commit DB, accounts, state, log hoặc file env riêng. Token fleet trong
fleet_config.py là ngoại lệ được người vận hành yêu cầu. Không tự commit/push trong
bước chuẩn bị local.

## An toàn và giới hạn

Host cấp lease account dùng chung với worker native, trần dự phòng 400 lease mỗi
worker ID; bản Render hardcode tối đa 15 phiên. Request claim có UUID chống cấp trùng khi mất response. Worker đóng
phiên trước expiry với margin 30s, không hoạt động offline. Mỗi post yêu cầu
permit một lần từ host, kiểm tra đơn/account vẫn hợp lệ. Permit mất response
không được gửi lại; gửi like lỗi không replay. Dừng đơn vẫn có cửa sổ request
đã được cấp permit đang bay (tối đa khoảng 5 giây), không thu hồi được gói đã gửi.
Chỉ observer game hiện tại kết luận đơn hoàn tất, không tính permit là like.

91551 tại bước login: tối đa ba lần tổng cộng, nghỉ 5s rồi 10s; không thử lại
like. Đây là chính sách retry giới hạn, không khẳng định ý nghĩa mã. Report lỗi
auth được ghi ở render_worker_leases, account nghỉ ít nhất 60s, không tự ban.
Worker không giữ plaintext password trên disk; log chỉ error_type/mã lỗi.
Token fleet là credential tin cậy có thể nhận account; chỉ cấp cho Render của
chính bạn. Chưa có quota toàn fleet, thu hồi token từng worker hoặc retention
tự động cho bảng lease/permit: cần theo dõi DB và bổ sung trước scale lớn.

Chỉ là bản chuẩn bị local + unit tests, chưa chứng minh tải 15 account trên
Render 0.1 core/500MB. Rollout một instance trước, đo RSS/CPU/lỗi/lease và xác
minh tăng like bằng observer; sau đó mới chuyển toàn fleet.
