# Kiện Tướng: cấp quyền code flow — 25/11/2026

## Phạm vi

Áp dụng checker chính `garena_api_test_chrome1.py` trong checkpass và checkpass1–6.
Không đổi App ID của Kiện Tướng sang100055: token game100055 không thay cho phiên web100054.
Không sửa EXE V2, dữ liệu tài khoản/database, deploy hay restart dịch vụ.
Adapter cũ `uplv_kientuong.PlayerSession` của luồng up-level không nằm trong bản vá này.

## Luồng mới

SSO của đúng tài khoản → OAuth web100054 → một POST grant có `create_grant=true`,
`response_type=code`, callback Kiện Tướng cố định → cookie Kiện Tướng → `/api/player/get`.
Giữ CookieJar riêng cho từng tài khoản; không đưa token game vào API player.
Một grant POST cho mỗi phiên, kể cả timeout/từ chối. Callback phải HTTPS, đúng host/path,
có đúng một code không rỗng, không có lỗi/fragment. Không replay POST qua redirect và không
cho callback redirect sang host khác. Không mở phiên mới sau403/429/CAPTCHA hoặc grant thất bại.
Player chưa đồng bộ có thể được đọc lại trong giới hạn sẵn có; không mở grant/session mới
khi đã đọc hết giới hạn mà vẫn chưa xác nhận cấp. Không thay đổi host pacing/cooldown.

## Tag xuất kết quả theo yêu cầu người vận hành

- Đọc cấp hợp lệ1–30: xuất cấp thật.
- Đã xác thực đăng nhập nhưng không đọc được nhân vật sau nhánh mới: **OK / Lỗi CTNV**,
  `player_status=Lỗi CTNV`, cấp để trống; giữ tương thích tag require-grant cũ.
- Tag OK trong trường hợp trên KHÔNG khẳng định đọc nhân vật thành công hoặc chưa có nhân vật.
- Không đổi HTTP422 rỗng/HTTP200 thiếu player thành Lv0 hay `Ctnv`.
- TCP đăng nhập bị từ chối/chưa xác minh vẫn theo phân loại đăng nhập hiện có.

Không ghi mật khẩu/token/code/cookie trong báo cáo kiểm chứng. Dòng hiển thị SSO được che.
Kiểm thử offline dùng dữ liệu giả; không phải bằng chứng server live chấp nhận grant của mọi tài khoản.

## Backup / kiểm tra

Mỗi thư mục có `backups/before_kientuong_grant_20261125_171851/source.zip` và manifest SHA256
đã xác minh trước khi sửa. Backup chỉ gồm source liên quan, không database/list/cookie.
Chạy `python -m unittest test_kientuong_grant test_login_classification test_garena_http_gate`.
Kết quả/hashes sau khi áp dụng nằm ở `kientuong_grant_verification.json`.
Các tiến trình đã nạp module cũ cần được khởi động lại trong lịch vận hành; bản vá không tự restart.
