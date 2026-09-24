from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parent
_TCP_NESTED = ROOT / (
    "TOOL AUTO UP LEVEL/_internal/apk_analysis/api_system_v1/"
    "device_192.168.1.22_56625/billow_tool/runtime_snapshot/garena_tcp.py"
)
_TCP_SIBLING = ROOT / "garena_tcp.py"
TCP_SOURCES = (_TCP_NESTED, _TCP_SIBLING)
TCP_SOURCE = _TCP_NESTED
TCP_SOURCE_SHA256 = "12d75635092e5f2f75a26ce6a773c6aeea46af036df099aa22d7cb4f90c5897a"
MAX_BODY = 8 * 1024
LOGIN_LOCK = threading.Lock()


def load_verified_tcp_module() -> ModuleType:
    source = next((path for path in TCP_SOURCES if path.is_file()), None)
    if source is None:
        raise RuntimeError(
            "Không tìm thấy Garena TCP source (garena_tcp.py); đã thử: "
            + "; ".join(str(path) for path in TCP_SOURCES)
        )

    # Git may check text files out as CRLF on Windows and LF on Linux/Render.
    # Hash canonical LF bytes so the integrity check is platform-independent.
    canonical_source = source.read_bytes().replace(b"\r\n", b"\n")
    digest = hashlib.sha256(canonical_source).hexdigest()
    if digest != TCP_SOURCE_SHA256:
        raise RuntimeError(
            f"{source.name} không đúng SHA-256 đã kiểm tra; dừng để tránh chạy mã bị thay đổi"
        )

    module_name = "_garena_tcp_login_chrome_verified"
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError("Không tạo được module loader cho garena_tcp.py")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise

    if not hasattr(module, "GarenaTcpClient"):
        raise RuntimeError("garena_tcp.py không có GarenaTcpClient")
    return module


def page_html(csrf_token: str) -> bytes:
    token_js = json.dumps(csrf_token)
    page = f"""<!doctype html>
<html lang="vi">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Garena TCP Login Test</title>
  <style>
    :root {{ color-scheme: dark; font-family: Segoe UI, system-ui, sans-serif; }}
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:#0e1117; color:#e6edf3; }}
    main {{ width:min(440px,calc(100vw - 36px)); background:#161b22; border:1px solid #30363d;
            border-radius:14px; padding:24px; box-shadow:0 18px 60px #0008; }}
    h1 {{ margin:0 0 8px; font-size:22px; }}
    p {{ color:#9da7b3; line-height:1.5; }}
    label {{ display:block; margin:15px 0 6px; font-weight:650; }}
    input {{ box-sizing:border-box; width:100%; padding:11px 12px; color:#e6edf3; background:#0d1117;
             border:1px solid #30363d; border-radius:8px; outline:none; }}
    input:focus {{ border-color:#2f81f7; }}
    button {{ width:100%; margin-top:18px; padding:11px; border:0; border-radius:8px;
              background:#238636; color:white; font-weight:750; cursor:pointer; }}
    button:disabled {{ opacity:.55; cursor:wait; }}
    #result {{ margin-top:16px; padding:12px; min-height:23px; border-radius:8px; background:#0d1117;
               white-space:pre-wrap; overflow-wrap:anywhere; }}
    .ok {{ color:#56d364; }} .bad {{ color:#ff7b72; }}
    small {{ display:block; margin-top:14px; color:#7d8590; line-height:1.45; }}
  </style>
</head>
<body>
<main>
  <h1>Garena TCP login-only test</h1>
  <p>Kiểm tra command <code>0x100 → 0x101</code>. Công cụ chỉ trả UID và trạng thái
     session; không lấy SSO/access token và không lưu mật khẩu.</p>
  <form id="loginForm" autocomplete="off">
    <label for="account">Tài khoản Garena</label>
    <input id="account" name="tcp_test_account" maxlength="128" required autocomplete="off">
    <label for="password">Mật khẩu</label>
    <input id="password" name="tcp_test_password" type="password" maxlength="1024" required autocomplete="off">
    <button id="submit" type="submit">Kiểm tra đăng nhập TCP</button>
  </form>
  <div id="result">Chưa thực hiện.</div>
  <small>Trang chỉ chạy tại 127.0.0.1. Không dùng tài khoản quan trọng nếu máy tính hoặc mạng đang bị giám sát.</small>
</main>
<script>
const csrfToken = {token_js};
const form = document.getElementById('loginForm');
const button = document.getElementById('submit');
const result = document.getElementById('result');
form.addEventListener('submit', async (event) => {{
  event.preventDefault();
  button.disabled = true;
  result.className = '';
  result.textContent = 'Đang kết nối Garena TCP...';
  const passwordInput = document.getElementById('password');
  const payload = {{
    account: document.getElementById('account').value,
    password: passwordInput.value
  }};
  try {{
    const response = await fetch('/api/login', {{
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {{'Content-Type':'application/json','X-Login-Test-Token':csrfToken}},
      body: JSON.stringify(payload)
    }});
    const data = await response.json();
    if (data.ok) {{
      result.className = 'ok';
      result.textContent = `Đăng nhập TCP thành công\nUID: ${{data.uid}}\nSession key: đã nhận (${{data.session_key_bytes}} byte)\nThời gian: ${{data.elapsed_ms}} ms`;
    }} else {{
      result.className = 'bad';
      result.textContent = `Thất bại: ${{data.error}}`;
    }}
  }} catch (error) {{
    result.className = 'bad';
    result.textContent = `Lỗi giao diện localhost: ${{error}}`;
  }} finally {{
    payload.password = '';
    passwordInput.value = '';
    button.disabled = false;
  }}
}});
</script>
</body>
</html>"""
    return page.encode("utf-8")


class LoginTestServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        tcp_module: ModuleType,
        csrf_token: str,
        tcp_timeout: float,
    ) -> None:
        super().__init__(address, handler)
        self.tcp_module = tcp_module
        self.csrf_token = csrf_token
        self.tcp_timeout = tcp_timeout


class Handler(BaseHTTPRequestHandler):
    server: LoginTestServer

    def log_message(self, _format: str, *args: Any) -> None:
        # Không để HTTP server ghi request chứa dữ liệu đăng nhập vào console.
        return

    def _security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; frame-ancestors 'none'; form-action 'self'",
        )

    def _json(self, status: HTTPStatus, data: dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        if self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = page_html(self.server.csrf_token)
        self.send_response(HTTPStatus.OK)
        self._security_headers("text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/api/login":
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Endpoint không tồn tại"})
            return

        if self.headers.get("X-Login-Test-Token", "") != self.server.csrf_token:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "CSRF token không hợp lệ"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            if length > 0:
                try:
                    rem = length
                    while rem > 0:
                        chunk = self.rfile.read(min(rem, 64 * 1024))
                        if not chunk:
                            break
                        rem -= len(chunk)
                except Exception:
                    pass
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Kích thước request không hợp lệ"})
            return

        try:
            request = json.loads(self.rfile.read(length).decode("utf-8"))
            account = str(request.get("account", "")).strip()
            password = str(request.get("password", ""))
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "JSON không hợp lệ"})
            return

        if not account or not password or len(account) > 128 or len(password) > 1024:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Thiếu hoặc sai độ dài tài khoản/mật khẩu"})
            return

        if not LOGIN_LOCK.acquire(blocking=False):
            self._json(HTTPStatus.TOO_MANY_REQUESTS, {"ok": False, "error": "Đang có một lần kiểm tra khác"})
            return

        started = time.monotonic()
        try:
            client_type = self.server.tcp_module.GarenaTcpClient
            with client_type(timeout=self.server.tcp_timeout) as client:
                uid = int(client.login(account, password))
                session_size = len(client.session_key or b"")
            elapsed_ms = round((time.monotonic() - started) * 1000)
            self._json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "uid": uid,
                    "session_key_bytes": session_size,
                    "elapsed_ms": elapsed_ms,
                },
            )
        except Exception as exc:
            # Chỉ trả mô tả lỗi; tuyệt đối không kèm account, password hoặc packet.
            message = str(exc).strip() or type(exc).__name__
            self._json(HTTPStatus.OK, {"ok": False, "error": message[:500]})
        finally:
            password = ""
            LOGIN_LOCK.release()


def open_chrome_or_default(url: str) -> None:
    candidates: list[Path] = []
    for env_name in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        base = os.environ.get(env_name)
        if base:
            candidates.append(Path(base) / "Google/Chrome/Application/chrome.exe")
    for chrome in candidates:
        if chrome.is_file():
            subprocess.Popen([str(chrome), "--new-window", url])
            return
    webbrowser.open_new(url)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Giao diện Chrome localhost để test Garena TCP LOGIN")
    parser.add_argument("--port", type=int, default=8765, help="Cổng localhost (mặc định: 8765)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Timeout TCP giây (mặc định: 15)")
    parser.add_argument("--no-browser", action="store_true", help="Không tự mở Chrome/trình duyệt")
    parser.add_argument("--self-test", action="store_true", help="Chỉ kiểm tra source/hash, không mở TCP")
    return parser.parse_args()


def configure_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    configure_console_encoding()
    args = parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit("Port phải nằm trong khoảng 1024..65535")
    if not 1.0 <= args.timeout <= 60.0:
        raise SystemExit("Timeout phải nằm trong khoảng 1..60 giây")

    tcp_module = load_verified_tcp_module()
    if args.self_test:
        print("SELF-TEST OK: source tồn tại, SHA-256 đúng và GarenaTcpClient nạp thành công.")
        return 0

    csrf_token = secrets.token_urlsafe(32)
    server = LoginTestServer(
        ("127.0.0.1", args.port), Handler, tcp_module, csrf_token, args.timeout
    )
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Garena TCP login test đang chạy tại: {url}")
    print("Chỉ bind 127.0.0.1; nhấn Ctrl+C để dừng. Mật khẩu không được ghi xuống file/log.")
    if not args.no_browser:
        threading.Timer(0.25, open_chrome_or_default, args=(url,)).start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nĐã dừng server test.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
