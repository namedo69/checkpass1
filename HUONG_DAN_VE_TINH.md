# 🛰️ Hướng dẫn cài đặt Vệ tinh (Satellite Worker)

## Tổng quan kiến trúc

```
                    ┌──────────────────────────┐
                    │   Master Server (Render)  │
                    │   Web Service - 24/7      │
   Gửi acc check → │   URL: https://xxx.onrender.com
                    └──────┬───────┬───────┬───┘
                           │       │       │
                    claim/report  claim   claim
                           │       │       │
                    ┌──────▼──┐ ┌──▼────┐ ┌▼──────────┐
                    │ PC Local│ │ A51   │ │ Render    │
                    │ Windows │ │Termux │ │ BG Worker │
                    └─────────┘ └───────┘ └───────────┘
                       Vệ tinh 1  Vệ tinh 2  Vệ tinh 3
```

**Vệ tinh chủ động gọi lên Master lấy việc** (pull model):
1. Gọi `POST /api/claim` → nhận chunk accounts
2. Check từng acc qua Garena TCP
3. Gọi `POST /api/report` → trả kết quả
4. Lặp lại

---

## Biến môi trường chung (tất cả vệ tinh)

| Biến | Bắt buộc | Mô tả | Mặc định |
|------|----------|-------|----------|
| `MASTER_URL` | ✅ | URL master server | `http://127.0.0.1:8761` |
| `MASTER_TOKEN` | ✅ | Token xác thực (giống master) | (trống) |
| `SATELLITE_ID` | ❌ | Tên định danh vệ tinh | `hostname-pid` |
| `WORKERS` | ❌ | Số luồng check song song trong 1 chunk | `8` |
| `CONCURRENT_CHUNKS` | ❌ | Số chunk xử lý đồng thời | `3` |
| `START_GAP` | ❌ | Giãn cách (giây) giữa mỗi login TCP | `3.0` |
| `TIMEOUT` | ❌ | Timeout (giây) mỗi lần login | `20.0` |
| `LEASE_MINUTES` | ❌ | Thời gian giữ chunk (phút); vệ tinh còn hoạt động sẽ tự gia hạn | `3` |
| `POLL_INTERVAL` | ❌ | Khoảng cách poll khi hết việc (giây) | `15` |
| `HEALTH_PORT` | ❌ | Port health check | `8765` |

### Công thức tính hiệu suất:
```
Tổng luồng = WORKERS × CONCURRENT_CHUNKS
Ví dụ: 15 workers × 3 chunks = 45 acc check đồng thời
```

### Khuyến nghị theo phần cứng:

| Thiết bị | WORKERS | CONCURRENT_CHUNKS | START_GAP | Tổng luồng |
|----------|---------|-------------------|-----------|------------|
| Điện thoại cũ | 4 | 1 | 3.0 | 4 |
| A51 (6GB RAM) | 8-15 | 2-3 | 2.0 | 16-45 |
| PC trung bình | 15 | 3 | 2.0 | 45 |
| PC mạnh / VPS | 20 | 5 | 1.5 | 100 |
| Render Free (Web) | 1 | 15 | 0 | 15 |

---

## Môi trường 1: PC Local (Windows)

### Yêu cầu
- Python 3.10+
- Git

### Cài đặt (1 lần)

```powershell
# Clone repo
git clone https://github.com/HoangVanLuong2207/checkpass F:\checkpass
cd F:\checkpass

# Cài dependencies
pip install -r requirements.txt
```

### Chạy vệ tinh

**PowerShell (1 dòng):**
```powershell
$env:MASTER_URL="https://checkpass-4grp.onrender.com"; $env:MASTER_TOKEN="Zocl00zonx."; $env:SATELLITE_ID="pc-local"; $env:WORKERS="15"; $env:CONCURRENT_CHUNKS="3"; $env:START_GAP="2.0"; $env:TIMEOUT="20.0"; $env:POLL_INTERVAL="10"; python satellite_worker.py
```

**Hoặc tạo file `run_satellite.bat`:**
```bat
@echo off
set MASTER_URL=https://checkpass-4grp.onrender.com
set MASTER_TOKEN=Zocl00zonx.
set SATELLITE_ID=pc-local
set WORKERS=15
set CONCURRENT_CHUNKS=3
set START_GAP=2.0
set TIMEOUT=20.0
set POLL_INTERVAL=10
python satellite_worker.py
```
Double-click file `.bat` để chạy.

**Hoặc tạo file `run_satellite.ps1`:**
```powershell
$env:MASTER_URL = "https://checkpass-4grp.onrender.com"
$env:MASTER_TOKEN = "Zocl00zonx."
$env:SATELLITE_ID = "pc-local"
$env:WORKERS = "15"
$env:CONCURRENT_CHUNKS = "3"
$env:START_GAP = "2.0"
$env:TIMEOUT = "20.0"
$env:POLL_INTERVAL = "10"
python satellite_worker.py
```

### Cập nhật code
```powershell
cd F:\checkpass
git pull
```

### Dừng
Nhấn `Ctrl+C`

---

## Môi trường 2: Termux (Android - Samsung A51, etc.)

### Yêu cầu
- Termux từ **F-Droid** (không dùng bản Play Store)
- Termux:API (tùy chọn, để giữ chạy nền)

### Cài đặt (1 lần)

```bash
# Cập nhật Termux
pkg update -y && pkg upgrade -y

# Cài Python + tools
pkg install -y python python-pip git openssl libffi clang build-essential

# Cài Python packages
pip install cryptography openpyxl

# Clone repo
git clone https://github.com/HoangVanLuong2207/checkpass ~/checkpass
```

> **Lỗi cài cryptography?** Thử: `pkg install -y python-cryptography`
> hoặc `pkg install -y rust && pip install cryptography`

### Chạy vệ tinh (1 dòng)

```bash
echo 'cd "$HOME/checkpass"' > ~/checkpass/s.sh && echo 'export MASTER_URL="https://checkpass-4grp.onrender.com"' >> ~/checkpass/s.sh && echo 'export MASTER_TOKEN="Zocl00zonx."' >> ~/checkpass/s.sh && echo 'export SATELLITE_ID="a51-local"' >> ~/checkpass/s.sh && echo 'export WORKERS=15' >> ~/checkpass/s.sh && echo 'export CONCURRENT_CHUNKS=3' >> ~/checkpass/s.sh && echo 'export START_GAP=2.0' >> ~/checkpass/s.sh && echo 'export TIMEOUT=20.0' >> ~/checkpass/s.sh && echo 'export POLL_INTERVAL=10' >> ~/checkpass/s.sh && echo 'python satellite_worker.py' >> ~/checkpass/s.sh && bash ~/checkpass/s.sh
```

### Chạy nền (không bị tắt khi tắt màn hình)

```bash
# Cài tmux
pkg install tmux

# Tạo session
tmux new -s sat

# Chạy trong tmux
bash ~/checkpass/s.sh

# Tách ra: nhấn Ctrl+B rồi D
# Tắt màn hình, vẫn chạy!

# Quay lại xem:
tmux attach -t sat
```

### Giữ Termux không bị Android kill

1. **Cài đặt Android:**
   - Cài đặt → Ứng dụng → Termux → Pin → **Không giới hạn**
   - Cài đặt → Pin → Tối ưu hóa pin → Termux → **Không tối ưu hóa**

2. **Trong Termux:**
   ```bash
   termux-wake-lock    # Giữ CPU khi tắt màn hình
   ```

3. **Samsung đặc biệt:**
   - Cài đặt → Chăm sóc pin và thiết bị → Pin → Giới hạn nền → **Bỏ Termux ra**

### Cập nhật code
```bash
cd ~/checkpass && git pull
```

### Dừng
Nhấn `Ctrl+C` hoặc kill tmux session: `tmux kill-session -t sat`

---

## Môi trường 3: Render Web Service (Free)

> ⚠️ **Render KHÔNG có gói Free cho Background Worker**, chỉ có **Web Service** mới có free plan.
> Satellite worker được thiết kế để chạy như Web Service: bind port HTTP (Render truyền qua env `PORT`),
> phục vụ `/healthz`, đồng thời chạy worker loop ở background thread.
> Có cơ chế **tự ping mỗi 5 phút** để tránh Render spin down do không có traffic.

### Ưu điểm
- Gói Free, không mất tiền
- Không cần quản lý server
- Tự deploy khi push code
- Tự ping giữ cho service không bị ngủ

### Giới hạn Free Plan
- **750 giờ/tháng** (chia cho tất cả free services)
- **512 MB RAM**, CPU giới hạn
- Nên để WORKERS vừa phải, CONCURRENT_CHUNKS nhỏ

### Cài đặt

1. Vào **https://dashboard.render.com**
2. **New** → **Web Service**
3. Kết nối repo **GitHub**: `HoangVanLuong2207/checkpass`
4. Cấu hình:

| Mục | Giá trị |
|-----|--------|
| Name | `garena-satellite-1` |
| Runtime | Python |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `python satellite_worker.py` |
| Plan | Free |
| Health Check Path | `/healthz` |

5. **Environment Variables:**

| Key | Value |
|-----|-------|
| `MASTER_URL` | `https://checkpass-4grp.onrender.com` |
| `MASTER_TOKEN` | `Zocl00zonx.` |
| `SATELLITE_ID` | `render-sat-1` |
| `WORKERS` | `1` |
| `CONCURRENT_CHUNKS` | `15` |
| `START_GAP` | `0` |
| `TIMEOUT` | `20.0` |
| `POLL_INTERVAL` | `10` |
| `PYTHON_VERSION` | `3.13.4` |

> **Lưu ý:** Không cần set `PORT` — Render tự truyền. Code tự đọc `PORT` từ env.

6. Bấm **Create Web Service**

### Cơ chế chống ngủ (self-ping)
Satellite worker có thread tự gửi HTTP request đến chính mình (`http://127.0.0.1:{PORT}/healthz`)
mỗi **5 phút** để Render không spin down service. Không cần cài thêm gì.

### Thêm vệ tinh Render thứ 2

Lặp lại bước trên, chỉ đổi:
- **Name**: `garena-satellite-2`
- **SATELLITE_ID**: `render-sat-2`

### Cập nhật code
Push lên GitHub → Render tự deploy:
```powershell
cd F:\checkpass
git add -A && git commit -m "update" && git push
```

### Dừng
Vào Render Dashboard → chọn service → **Suspend**

---

## Quản lý nhiều vệ tinh

### Ví dụ cấu hình 4 vệ tinh:

| Vệ tinh | Môi trường | SATELLITE_ID | WORKERS | CHUNKS | Tổng luồng |
|----------|-----------|--------------|---------|--------|------------|
| PC nhà | Windows | `pc-home` | 15 | 3 | 45 |
| A51 | Termux | `a51-local` | 8 | 2 | 16 |
| Render #1 | Web Service | `render-sat-1` | 1 | 15 | 15 |
| Render #2 | Web Service | `render-sat-2` | 1 | 15 | 15 |
| | | | | **Tổng** | **91** |

### Xem vệ tinh nào đang hoạt động

Gửi acc check rồi xem job detail → cột kết quả sẽ thấy acc được check từ các vệ tinh khác nhau.

### Thêm vệ tinh bất kỳ lúc nào

Chỉ cần:
1. Có code (`git clone`)
2. Đặt đúng `MASTER_URL` + `MASTER_TOKEN`
3. Chạy `python satellite_worker.py`

**Không cần đăng ký** với master, không cần restart master. Vệ tinh tự gọi lên nhận việc!

### Gỡ vệ tinh

Tắt đi là xong. Chunk đang xử lý sẽ **tự động** được giao lại cho vệ tinh khác sau khi hết lease (60 phút).

---

## Troubleshooting

### ❌ `ModuleNotFoundError: No module named 'cryptography'`
```bash
pip install cryptography
# Termux: pkg install python-cryptography
```

### ❌ `không kết nối được tổng bộ`
- Kiểm tra `MASTER_URL` đúng chưa
- Master trên Render có đang chạy không
- Thử: `curl https://checkpass-4grp.onrender.com/healthz`

### ❌ Vệ tinh chạy nhưng không nhận chunk
- Kiểm tra `MASTER_TOKEN` giống master
- Kiểm tra đã gửi acc (tạo job) trên master chưa

### ⚠️ LOGIN phản hồi nhanh < 600ms
- Chưa đủ căn cứ kết luận rate limit hoặc không thể đăng nhập → code sẽ chờ rồi check lại.
- Rate limit chỉ được ghi nhận khi có tín hiệu rõ như HTTP 429 hoặc thông báo rate limit/throttling.
- Mỗi tài khoản được thử lại trong giới hạn tối đa 100 lần hoặc 300 giây.
- Nếu xuất hiện nhiều phản hồi nhanh: tăng `START_GAP` lên 3-5s và giảm `WORKERS`.

### ❌ Termux bị Android kill
- Xem mục **Giữ Termux không bị Android kill** ở trên
- Dùng `tmux` + `termux-wake-lock`

### ❌ Render hết giờ free
- 750 giờ/tháng chia cho tất cả services
- Tắt vệ tinh không dùng: Dashboard → Suspend
- Hoặc nâng plan

---

## Tóm tắt lệnh nhanh

### PC (PowerShell):
```powershell
$env:MASTER_URL="https://checkpass-4grp.onrender.com"; $env:MASTER_TOKEN="Zocl00zonx."; $env:SATELLITE_ID="pc-local"; $env:WORKERS="15"; $env:CONCURRENT_CHUNKS="3"; $env:START_GAP="2.0"; $env:TIMEOUT="20.0"; $env:POLL_INTERVAL="10"; python satellite_worker.py
```

### Termux (1 dòng):
```bash
echo 'cd "$HOME/checkpass"' > ~/checkpass/s.sh && echo 'export MASTER_URL="https://checkpass-4grp.onrender.com"' >> ~/checkpass/s.sh && echo 'export MASTER_TOKEN="Zocl00zonx."' >> ~/checkpass/s.sh && echo 'export SATELLITE_ID="a51-local"' >> ~/checkpass/s.sh && echo 'export WORKERS=15' >> ~/checkpass/s.sh && echo 'export CONCURRENT_CHUNKS=3' >> ~/checkpass/s.sh && echo 'export START_GAP=2.0' >> ~/checkpass/s.sh && echo 'export TIMEOUT=20.0' >> ~/checkpass/s.sh && echo 'export POLL_INTERVAL=10' >> ~/checkpass/s.sh && echo 'python satellite_worker.py' >> ~/checkpass/s.sh && bash ~/checkpass/s.sh
```

### Render:
Deploy qua Dashboard, không cần lệnh.
