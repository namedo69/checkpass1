# checkpass

Master gọi `GET /healthz` của mỗi vệ tinh trong danh sách đã lưu ở trang quản trị mỗi 2 phút. Danh sách được đọc lại từ khóa `satellite_targets` trong bảng `app_settings` ở mỗi lượt, nên thay đổi danh sách không cần khởi động lại master. Danh sách trống sẽ không gọi vệ tinh nào. Cần lưu URL công khai của vệ tinh, ví dụ `[checkpass3] https://checkpass3-wt3z.onrender.com`.
