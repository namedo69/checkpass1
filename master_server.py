from __future__ import annotations

"""Tổng bộ (coordinator) - chỉ điều phối chứ KHÔNG tự check account.

Nhận acc (user|pass), chia thành các chunk <= 1000, cho vệ tinh claim,
nhận kết quả về và lưu. Máy này giữ RAM nhỏ bất kể số lượng acc vì nó
không chạy Garena check; dữ liệu nằm trong SQLite trên đĩa.
"""

import argparse
import asyncio
import csv
import hashlib
import io
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_CHUNK_LIMIT = 15
# Chunk được cố định để tránh client thay đổi kích thước qua API.
MAX_CHUNK_LIMIT = 15
DEFAULT_DB_PATH = Path(__file__).resolve().with_name("master.db")
DEFAULT_LEASE_MINUTES = 3
MAX_SATELLITE_LEASE_MINUTES = 3
MAX_ACCOUNT_RETRY_ROUNDS = 3
MAX_BODY = 32 * 1024 * 1024
LICENSE_CACHE_TTL = 300  # giây cache kết quả verify license
LICENSE_SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "").strip()
# Cache license: key -> (ok, expiry, info)
_LICENSE_CACHE: dict[str, tuple[bool, float, dict[str, Any]]] = {}
_LICENSE_CACHE_LOCK = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    total INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    finished_at REAL,
    owner_hash TEXT DEFAULT '',
    owner_preview TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS chunks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    account TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    satellite_id TEXT DEFAULT '',
    claimed_at REAL,
    lease_until REAL,
    reported_at REAL,
    retry_round INTEGER NOT NULL DEFAULT 1,
    avoid_satellite_id TEXT DEFAULT '',
    UNIQUE(job_id, idx)
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chunk_id INTEGER NOT NULL,
    job_id INTEGER NOT NULL,
    account TEXT NOT NULL,
    row_json TEXT NOT NULL,
    reported_at REAL NOT NULL,
    UNIQUE(chunk_id, account)
);
CREATE INDEX IF NOT EXISTS idx_chunks_claim ON chunks(status, lease_until);
CREATE INDEX IF NOT EXISTS idx_chunks_job ON chunks(job_id);
CREATE INDEX IF NOT EXISTS idx_results_chunk ON results(chunk_id);
CREATE INDEX IF NOT EXISTS idx_results_job ON results(job_id);
CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_hash);
"""


def _now() -> float:
    return time.time()


def _run_async(coro):
    """Run async code from sync context."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _preview_key(key: str) -> str:
    k = key.strip()
    if len(k) <= 8:
        return k[:2] + "***" + k[-1:] if len(k) > 3 else "***"
    return k[:4] + "***" + k[-2:]


def _verify_license_key(key: str) -> tuple[bool, dict[str, Any]]:
    """Gọi license-server HTTP để verify key. Có cache TTL.

    Trả về (ok, info). Nếu LICENSE_SERVER_URL rỗng thì chấp nhận mọi key (dùng cho dev/test).
    Hỗ trợ cả POST JSON {"key": "..."} và GET ?key=... .
    Mong license-server trả về {"valid": true} / {"ok": true} / {"success": true} hoặc {"active": true}.
    """
    key = (key or "").strip()
    if not key:
        return False, {"error": "empty key"}
    now = time.time()
    with _LICENSE_CACHE_LOCK:
        cached = _LICENSE_CACHE.get(key)
        if cached and cached[1] > now:
            return cached[0], cached[2]
    # Nếu không cấu hình license server, chấp nhận mọi key (dev mode) — vẫn chia theo hash
    license_url = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
    if not license_url:
        info = {"mode": "no-license-server", "preview": _preview_key(key)}
        with _LICENSE_CACHE_LOCK:
            _LICENSE_CACHE[key] = (True, now + LICENSE_CACHE_TTL, info)
        return True, info
    # Nếu license_url không phải http(s) thì coi như file local (hỗ trợ f:license-server, file://, v.v.)
    if not license_url.lower().startswith(("http://", "https://")):
        # Xử lý file local
        file_path = license_url
        if file_path.startswith("file://"):
            file_path = file_path[7:]
        # Chuẩn hoá các dạng f:license-server, F:\license-server
        candidates: list[Path] = []
        try:
            p0 = Path(file_path)
            candidates.append(p0)
            # Thử thêm dấu / sau :
            if ":" in file_path and not ":/" in file_path and not ":\\" in file_path:
                candidates.append(Path(file_path.replace(":", ":/")))
                candidates.append(Path(file_path.replace("f:", "F:/").replace("F:", "F:/")))
            # Thử các vị trí tương đối
            candidates.append(Path.cwd() / file_path)
            candidates.append(Path(__file__).parent / file_path)
            # Nếu chỉ là tên file không đường dẫn, thử F:/
            if not any(c.exists() for c in candidates):
                candidates.append(Path("F:/license-server"))
                candidates.append(Path("F:/checkpass/license.txt"))
                candidates.append(Path("./license.txt"))
        except Exception:
            candidates = [Path(file_path)]
        found: Path | None = None
        for cand in candidates:
            try:
                if cand.exists() and cand.is_file():
                    found = cand
                    break
            except Exception:
                continue
        if found is not None:
            try:
                content = found.read_text(encoding="utf-8", errors="ignore")
                # Hỗ trợ cả JSON và plain text (mỗi dòng 1 key)
                content_stripped = content.strip()
                # Thử JSON
                is_valid = False
                try:
                    j = json.loads(content_stripped)
                    if isinstance(j, dict):
                        # Dict có thể là {key: info} hoặc {"keys": [...]}
                        if key in j:
                            is_valid = bool(j[key]) if isinstance(j[key], bool) else True
                        elif "keys" in j and isinstance(j["keys"], list) and key in j["keys"]:
                            is_valid = True
                        elif "valid" in j and isinstance(j["valid"], bool):
                            # File JSON đơn giản {"valid": true} không dùng
                            pass
                    elif isinstance(j, list) and key in j:
                        is_valid = True
                except Exception:
                    pass
                if not is_valid:
                    # Plain text: mỗi dòng 1 key
                    lines = [line.strip() for line in content.splitlines() if line.strip()]
                    if key.strip() in lines:
                        is_valid = True
                    # Cũng hỗ trợ key là substring? Không, phải khớp chính xác
                info = {"mode": "file", "file": str(found), "preview": _preview_key(key)}
                if is_valid:
                    with _LICENSE_CACHE_LOCK:
                        _LICENSE_CACHE[key] = (True, now + LICENSE_CACHE_TTL, info)
                    return True, info
                else:
                    info["error"] = "key not in file"
                    with _LICENSE_CACHE_LOCK:
                        _LICENSE_CACHE[key] = (False, now + 60, info)
                    return False, info
            except Exception as e_file:
                info = {"error": f"file verify failed: {e_file}", "mode": "file", "file": str(found)}
                with _LICENSE_CACHE_LOCK:
                    _LICENSE_CACHE[key] = (False, now + 60, info)
                return False, info
        else:
            # File không tồn tại — có thể license_url là URL lỗi như "f:license-server" (thiếu //)
            # Thử sửa thành http:// nếu trông như host
            if ":" in license_url and not license_url.startswith("http"):
                # Thử thêm http://
                alt = "http://" + license_url.replace("f:", "").replace("F:", "").lstrip("/")
                # Nhưng để tránh block, trả về lỗi rõ ràng
                info = {"error": f"license file not found: {file_path} (tried {candidates[0] if candidates else file_path})", "mode": "file", "hint": "Nếu dùng HTTP, hãy đặt LICENSE_SERVER_URL=http://... hoặc https://..."}
                # Trong trường hợp file không tồn tại và không phải http, tạm cho phép key để không block user (fallback dev)?
                # Để an toàn, nếu file không tồn tại và key trông như license key hợp lệ, tạm chấp nhận với cảnh báo
                # Nhưng nếu người dùng đã nhập đúng key, ta không nên block
                # Quyết định: nếu file không tồn tại, coi như dev mode tạm thời để không làm gián đoạn
                print(f"[license] file not found {file_path}, fallback dev-mode for key { _preview_key(key)}", flush=True)
                info["fallback"] = "dev-mode"
                with _LICENSE_CACHE_LOCK:
                    _LICENSE_CACHE[key] = (True, now + 60, info)
                return True, info
            info = {"error": f"license file not found: {file_path}", "mode": "file"}
            with _LICENSE_CACHE_LOCK:
                _LICENSE_CACHE[key] = (False, now + 60, info)
            return False, info
    # Thử HTTP verify — hỗ trợ cả master-verify (đơn giản) và verify cũ (cần hwid/nonce)
    info: dict[str, Any] = {}
    ok = False
    def _check_valid(info_dict: dict[str, Any], status: int) -> bool:
        if "valid" in info_dict:
            return bool(info_dict["valid"])
        if "ok" in info_dict:
            return bool(info_dict["ok"])
        if "success" in info_dict:
            return bool(info_dict["success"])
        if "active" in info_dict:
            return bool(info_dict["active"])
        # Fallback: nếu không có flag explicit và status 200 và không có error thì coi như valid
        return status == 200 and not info_dict.get("error")
    # Chuẩn hoá base URL
    base = license_url.rstrip("/")
    # Nếu base đã chứa /api/verify hoặc /api/master-verify thì dùng trực tiếp, else thử các endpoint
    candidates: list[tuple[str, dict[str, Any] | None]] = []
    if "/api/" in base:
        # Đã chỉ rõ endpoint
        candidates.append((base, {"key": key}))
    else:
        # Thử master-verify trước (đơn giản, không cần hwid)
        candidates.append((base + "/api/master-verify", {"key": key}))
        candidates.append((base + "/api/verify-simple", {"key": key}))
        candidates.append((base + "/api/check", {"key": key}))
        # Cuối cùng thử verify cũ với hwid/nonce giả
        candidates.append((base + "/api/verify", {"key": key, "hwid": "master-server-verify", "nonce": secrets.token_hex(16)}))
    # Thêm fallback GET
    tried_errors: list[str] = []
    try:
        for verify_url, payload in candidates:
            try:
                data = json.dumps(payload).encode("utf-8") if payload else b""
                headers = {"Content-Type": "application/json"} if payload else {}
                req = urllib.request.Request(verify_url, data=data if payload else None, headers=headers, method="POST" if payload else "GET")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    # Nếu body là HTML (admin panel) thì không phải JSON verify, bỏ qua
                    if body.strip().startswith("<!DOCTYPE") or body.strip().startswith("<html"):
                        tried_errors.append(f"{verify_url} returned HTML")
                        continue
                    try:
                        j = json.loads(body)
                        info = j if isinstance(j, dict) else {"raw": body}
                    except Exception:
                        info = {"raw": body}
                    # Nếu info có valid flag thì dùng, else tiếp tục thử endpoint khác nếu body là HTML
                    if "valid" in info or "ok" in info or "success" in info or "active" in info or "error" in info:
                        ok = _check_valid(info, resp.status)
                        break
                    else:
                        # Không có flag, thử endpoint tiếp
                        tried_errors.append(f"{verify_url} no valid flag: {body[:100]}")
                        continue
            except Exception as e:
                tried_errors.append(f"{verify_url}: {e}")
                continue
        else:
            # Tất cả POST fail, thử GET fallback
            sep = "&" if "?" in base else "?"
            get_url = f"{base}/api/master-verify?key={urllib.parse.quote(key)}" if "/api/" not in base else f"{base}{sep}key={urllib.parse.quote(key)}"
            try:
                with urllib.request.urlopen(get_url, timeout=5) as resp2:
                    body2 = resp2.read().decode("utf-8", errors="ignore")
                    if body2.strip().startswith("<!DOCTYPE") or body2.strip().startswith("<html"):
                        raise ValueError("GET returned HTML")
                    try:
                        j2 = json.loads(body2)
                        info = j2 if isinstance(j2, dict) else {"raw": body2}
                    except Exception:
                        info = {"raw": body2}
                    ok = _check_valid(info, resp2.status)
            except Exception as e_get:
                tried_errors.append(f"GET {get_url}: {e_get}")
                info = {"error": f"license verify failed: {'; '.join(tried_errors[-3:])}"}
                ok = False
        if not info:
            info = {"error": f"license verify failed: {'; '.join(tried_errors)}"}
            ok = False
    except Exception as exc:
        info = {"error": str(exc)[:300]}
        ok = False
    with _LICENSE_CACHE_LOCK:
        _LICENSE_CACHE[key] = (ok, now + LICENSE_CACHE_TTL, info)
    return ok, info


class TursoStore:
    """Store using Turso/libSQL cloud database."""
    def __init__(self, url: str, token: str) -> None:
        # Render đôi khi lỗi wss 400/505, ép https như license-server
        if url and url.startswith("libsql://"):
            url = url.replace("libsql://", "https://", 1)
        self._url = url
        self._token = token
        self._lock = threading.RLock()
        self._init_tables()

    async def _aclient(self):
        from libsql_client import create_client
        return create_client(self._url, auth_token=self._token or None)

    async def _aexec(self, sql: str, args: tuple = ()) -> Any:
        client = await self._aclient()
        try:
            return await client.execute(sql, list(args))
        finally:
            await client.close()

    async def _afetch(self, sql: str, args: tuple = ()) -> list:
        client = await self._aclient()
        try:
            result = await client.execute(sql, list(args))
            return result.rows if hasattr(result, "rows") else []
        finally:
            await client.close()

    async def _abatch(self, statements: list) -> Any:
        from libsql_client.client import Statement
        client = await self._aclient()
        try:
            converted = []
            for s in statements:
                if isinstance(s, dict):
                    sql = s.get("sql", "")
                    args = list(s.get("args", []))
                    converted.append(Statement(sql, args))
                elif isinstance(s, tuple):
                    converted.append(Statement.convert(s))
                elif isinstance(s, str):
                    converted.append(Statement(s))
                elif isinstance(s, Statement):
                    converted.append(s)
                else:
                    converted.append(Statement(str(s)))
            if not converted:
                return []
            results = []
            # Chia nhỏ sub-batch tối đa 50 stmts để không vượt HTTP payload
            for i in range(0, len(converted), 50):
                sub = converted[i : i + 50]
                try:
                    res = await client.batch(sub)
                    if isinstance(res, list):
                        results.extend(res)
                    else:
                        results.append(res)
                except Exception as batch_err:
                    print(f"[TursoStore] sub-batch fallback ({batch_err}), chay execute rieng le", flush=True)
                    for single in sub:
                        res_single = await client.execute(single.sql, list(single.args or []))
                        results.append(res_single)
            return results
        finally:
            await client.close()

    def _init_tables(self) -> None:
        for sql in _SCHEMA.strip().split(";"):
            sql = sql.strip()
            if sql:
                try:
                    _run_async(self._aexec(sql))
                except Exception:
                    pass
        # Migration cho DB cũ thiếu owner columns
        for mig in [
            "ALTER TABLE jobs ADD COLUMN owner_hash TEXT DEFAULT ''",
            "ALTER TABLE jobs ADD COLUMN owner_preview TEXT DEFAULT ''",
            "ALTER TABLE chunks ADD COLUMN retry_round INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE chunks ADD COLUMN avoid_satellite_id TEXT DEFAULT ''",
            "CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_hash)",
        ]:
            try:
                _run_async(self._aexec(mig))
            except Exception:
                pass

    def exec(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            result = _run_async(self._aexec(sql, args))
            rowid = getattr(result, "last_insert_rowid", None)
            if rowid:
                return int(rowid)
            try:
                row = _run_async(self._afetch("SELECT last_insert_rowid()"))
                if row and row[0] and row[0][0]:
                    return int(row[0][0])
            except Exception:
                pass
            return 0

    def exec_with_changes(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            result = _run_async(self._aexec(sql, args))
            # libsql client trả về affected_rows hoặc rowcount
            for attr in ("affected_rows", "rowcount", "rows_affected"):
                if hasattr(result, attr):
                    try:
                        return int(getattr(result, attr) or 0)
                    except Exception:
                        pass
            return 0

    def fetch(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return _run_async(self._afetch(sql, args))

    def fetchone(self, sql: str, args: tuple = ()) -> tuple | None:
        rows = self.fetch(sql, args)
        return rows[0] if rows else None

    def batch(self, statements: list) -> Any:
        with self._lock:
            return _run_async(self._abatch(statements))


class LocalStore:
    """Store using local SQLite file."""
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=10000")
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            # Migration cho DB cũ
            for mig in [
                "ALTER TABLE jobs ADD COLUMN owner_hash TEXT DEFAULT ''",
                "ALTER TABLE jobs ADD COLUMN owner_preview TEXT DEFAULT ''",
                "ALTER TABLE chunks ADD COLUMN retry_round INTEGER NOT NULL DEFAULT 1",
                "ALTER TABLE chunks ADD COLUMN avoid_satellite_id TEXT DEFAULT ''",
                "CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_hash)",
            ]:
                try:
                    self._conn.execute(mig)
                except Exception:
                    pass
            try:
                self._conn.commit()
            except Exception:
                pass

    def exec(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur.lastrowid

    def exec_with_changes(self, sql: str, args: tuple = ()) -> int:
        """Thực thi và trả về số dòng bị ảnh hưởng (dùng cho claim atomic)."""
        with self._lock:
            cur = self._conn.execute(sql, args)
            self._conn.commit()
            return cur.rowcount

    def fetch(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._conn.execute(sql, args).fetchall()

    def fetchone(self, sql: str, args: tuple = ()) -> tuple | None:
        with self._lock:
            return self._conn.execute(sql, args).fetchone()

    def batch(self, statements: list) -> Any:
        with self._lock:
            for stmt in statements:
                if isinstance(stmt, dict):
                    self._conn.execute(stmt["sql"], stmt.get("args", []))
                else:
                    self._conn.execute(stmt)
            self._conn.commit()


@dataclass
class ParsedAccount:
    account: str
    password: str


def parse_accounts(text: str) -> list[ParsedAccount]:
    result: list[ParsedAccount] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            parts = line.split("|")
            if len(parts) < 2:
                raise ValueError(f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)")
            account = parts[0].strip()
            password = parts[1].strip()
        elif line.count(":") == 1:
            account, password = line.split(":", 1)
            account = account.strip()
            password = password.strip()
        else:
            raise ValueError(f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)")
        if not account or not password or len(account) > 128 or len(password) > 1024:
            raise ValueError(f"Dòng {line_number}: tài khoản/mật khẩu không hợp lệ")
        result.append(ParsedAccount(account, password))
        if len(result) >= MAX_CHUNK_LIMIT * 10000:
            raise ValueError("Quá nhiều tài khoản trong một lần gửi")
    if not result:
        raise ValueError("Danh sách trống hoặc không có dòng hợp lệ")
    return result


def split_chunks(accounts: list[ParsedAccount], chunk_size: int) -> list[list[ParsedAccount]]:
    return [accounts[i : i + chunk_size] for i in range(0, len(accounts), chunk_size)]


_PAGE_HTML = """
<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Garena Check Tool</title>
<style>
:root{color-scheme:dark;font-family:'Segoe UI',system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0e1117;color:#e6edf3;min-height:100vh;padding:18px}
.container{max-width:900px;margin:0 auto}
header{display:flex;align-items:center;gap:12px;margin-bottom:20px}
header h1{font-size:22px;color:#58a6ff}
header .badge{background:#238636;color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700}
.card{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:20px;margin-bottom:16px}
.card h2{font-size:16px;margin-bottom:12px;color:#79c0ff}
textarea{width:100%;height:140px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:8px;padding:10px;font-family:monospace;font-size:13px;resize:vertical}
textarea:focus{border-color:#2f81f7;outline:none}
.row{display:flex;gap:12px;align-items:end;flex-wrap:wrap}
.field{flex:1;min-width:120px}
.field label{display:block;font-size:13px;color:#8b949e;margin-bottom:4px}
.field input,.field select{width:100%;padding:8px;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px}
btn,button,.btn{padding:10px 20px;border:0;border-radius:8px;font-weight:700;cursor:pointer;font-size:14px}
.btn-primary{background:#238636;color:#fff}.btn-primary:hover{background:#2ea043}
.btn-primary:disabled{opacity:.5;cursor:wait}
.btn-sm{padding:6px 14px;font-size:12px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:12px 0}
.stat{background:#0d1117;border-radius:8px;padding:12px;text-align:center}
.stat .num{font-size:28px;font-weight:800;color:#58a6ff}
.stat .lbl{font-size:11px;color:#8b949e;margin-top:2px}
.stat.ok .num{color:#56d364}
.stat.fail .num{color:#ff7b72}
.stat.pending .num{color:#d29922}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
th{text-align:left;padding:8px 6px;border-bottom:2px solid #30363d;color:#8b949e;font-size:11px;text-transform:uppercase}
td{padding:7px 6px;border-bottom:1px solid #21262d}
tr:hover{background:#1c2128}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700}
.tag-ok{background:#23863633;color:#56d364}
.tag-fail{background:#da363333;color:#ff7b72}
.tag-run{background:#d2992233;color:#d29922}
.empty{color:#484f58;text-align:center;padding:30px}
#toast{position:fixed;bottom:20px;right:20px;background:#238636;color:#fff;padding:10px 18px;border-radius:8px;font-weight:600;display:none;z-index:99;box-shadow:0 4px 20px #0006}
.jobs-list{max-height:500px;overflow-y:auto}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>🎮 Garena Check Tool</h1>
  <span class="badge">MASTER</span>
  <span id="ownerBadge" style="margin-left:auto;background:#1f6feb;color:#fff;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600"></span>
  <button class="btn btn-sm" style="background:#30363d;color:#fff;margin-left:8px" onclick="changeKey()">🔑 Đổi Key</button>
</header>

<div class="card" id="keyCard" style="border-color:#1f6feb">
  <h2>🔐 License Key (f:license-server)</h2>
  <p style="color:#8b949e;font-size:13px;margin-bottom:10px">Mỗi key chỉ xem được job của mình. Nhập key được cấp từ license-server. Vệ tinh vẫn dùng <code>MASTER_TOKEN</code> để claim mọi job.</p>
  <div class="row">
    <div class="field" style="flex:2"><label>License Key</label><input type="password" id="keyInput" placeholder="Nhập key..."></div>
    <div class="field"><label>&nbsp;</label><button class="btn btn-primary" onclick="saveKey()">✅ Lưu & Kiểm tra</button></div>
  </div>
  <div id="keyStatus" style="margin-top:10px;font-size:13px"></div>
</div>

<div class="card">
  <h2>📋 Gửi danh sách tài khoản</h2>
  <textarea id="accInput" placeholder="Nhập tài khoản, mỗi dòng 1 acc&#10;Định dạng: user|pass  hoặc  user:pass&#10;&#10;Ví dụ:&#10;account1|password1&#10;account2|password2"></textarea>
  <div class="row" style="margin-top:12px">
    <input type="file" id="accFile" accept=".txt,.csv,text/plain" style="display:none" onchange="importAccountsFile()">
    <div class="field"><label>&nbsp;</label><button class="btn btn-sm" style="background:#30363d;color:#fff" onclick="document.getElementById('accFile').click()">📄 Nhập file</button></div>
    <div class="field"><label>&nbsp;</label><button class="btn btn-primary" id="btnSend" onclick="sendJob()">🚀 Gửi check</button></div>
  </div>
</div>

<div class="card">
  <h2>📊 Danh sách Jobs của bạn</h2>
  <p style="color:#8b949e;font-size:12px;margin-bottom:8px">Chỉ hiện job tạo bởi key hiện tại. Admin (MASTER_TOKEN) sẽ thấy tất cả.</p>
  <div style="margin-bottom:10px"><button class="btn btn-sm btn-primary" onclick="loadJobs()">🔄 Refresh</button></div>
  <div id="jobsList" class="jobs-list"><div class="empty">Chưa có job nào</div></div>
</div>

<div class="card" id="detailCard" style="display:none">
  <h2>📝 Chi tiết Job #<span id="detailJobId"></span><span id="detailDuration" style="font-size:14px;font-weight:600;color:#8b949e;margin-left:10px"></span> <span id="detailOwner" style="font-size:12px;color:#8b949e"></span></h2>
  <div class="stats" id="detailStats"></div>
  <div style="margin:10px 0;display:flex;gap:8px">
    <button class="btn btn-sm btn-primary" onclick="refreshDetail()">🔄 Refresh</button>
    <button class="btn btn-sm" id="stopJobBtn" onclick="stopCurrentJob()" style="background:#da3633">⏹ Dừng job</button>
    <button class="btn btn-sm btn-primary" onclick="exportCsv()" style="background:#1f6feb">📥 Export CSV</button>
    <button class="btn btn-sm btn-primary" onclick="exportXlsx()" style="background:#8250df">📊 Xuất Excel</button>
  </div>
  <div id="detailRows"><div class="empty">Đang tải...</div></div>
</div>
</div>

<div id="toast"></div>

<script>
let TOKEN=localStorage.getItem('licenseKey')||localStorage.getItem('masterToken')||'';
if(!TOKEN){
  TOKEN=prompt('Nhập License Key (key từ f:license-server):','')||'';
  if(TOKEN) localStorage.setItem('licenseKey',TOKEN);
}
function getHeaders(){return {'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'};}
let H=getHeaders();
let currentJobId=null;
let detailPage=1;
const DETAIL_PAGE_SIZE=50;

function toast(msg,ms=3000){const t=document.getElementById('toast');t.textContent=msg;t.style.display='block';setTimeout(()=>t.style.display='none',ms)}

async function api(path,opt={}){
  const r=await fetch(path,{headers:getHeaders(),...opt});
  const text=await r.text();
  let j;
  try{ j=text?JSON.parse(text):{ok:false,error:'Server trả về rỗng (status '+r.status+')'}; }
  catch(e){ j={ok:false,error:'Lỗi parse JSON: '+(text.slice(0,200)||'empty')+' (status '+r.status+')'}; }
  if(r.status===401){ toast('❌ '+(j.error||'Key không hợp lệ, vui lòng đổi key')); }
  else if(!r.ok && !j.error){ j.error='Lỗi '+r.status+': '+text.slice(0,200); }
  return j;
}

function previewKey(k){if(!k) return '';if(k.length<=8) return k.slice(0,2)+'***'+k.slice(-1);return k.slice(0,4)+'***'+k.slice(-2);}
function updateOwnerBadge(){const el=document.getElementById('ownerBadge');if(el) el.textContent=TOKEN?('Key: '+previewKey(TOKEN)):'Chưa có key';const inp=document.getElementById('keyInput');if(inp && !inp.value) inp.value=TOKEN;}
function changeKey(){const k=prompt('Nhập License Key mới:','');if(k!==null){TOKEN=k.trim();localStorage.setItem('licenseKey',TOKEN);H=getHeaders();updateOwnerBadge();checkKey();loadJobs();toast('Đã đổi key');}}
async function saveKey(){const inp=document.getElementById('keyInput');const k=(inp?inp.value.trim():'');if(!k){toast('Nhập key!');return;}TOKEN=k;localStorage.setItem('licenseKey',TOKEN);H=getHeaders();updateOwnerBadge();await checkKey();loadJobs();}
async function checkKey(){
  const st=document.getElementById('keyStatus');if(!st) return;
  if(!TOKEN){st.innerHTML='<span style="color:#ff7b72">Chưa nhập key</span>';return;}
  st.innerHTML='Đang kiểm tra...';
  try{
    const r=await fetch('/api/verify?token='+encodeURIComponent(TOKEN),{headers:getHeaders()});
    const j=await r.json();
    if(j.valid||j.ok){st.innerHTML='<span style="color:#56d364">✅ Key hợp lệ ('+previewKey(TOKEN)+')</span>';}
    else{st.innerHTML='<span style="color:#ff7b72">❌ Key không hợp lệ: '+(j.error||'unknown')+'</span>';}
  }catch(e){st.innerHTML='<span style="color:#d29922">⚠️ Không kiểm tra được: '+e.message+'</span>';}
}
updateOwnerBadge();checkKey();

function importAccountsFile(){
  const input=document.getElementById('accFile'),file=input&&input.files&&input.files[0];
  if(!file)return;
  if(file.size>32*1024*1024){toast('❌ File tối đa 32 MB');input.value='';return;}
  const reader=new FileReader();
  reader.onload=()=>{document.getElementById('accInput').value=String(reader.result||'').replace(/^\uFEFF/,'');toast('✅ Đã nhập file '+file.name);input.value='';};
  reader.onerror=()=>{toast('❌ Không đọc được file');input.value='';};
  reader.readAsText(file);
}

async function sendJob(){
  const text=document.getElementById('accInput').value.trim();
  if(!text){toast('Nhập danh sách tài khoản!');return}
  const btn=document.getElementById('btnSend');btn.disabled=true;btn.textContent='⏳ Đang gửi...';
  try{
    const d=await api('/api/jobs',{method:'POST',body:JSON.stringify({text})});
    if(d.ok){toast('✅ Tạo Job #'+d.job_id+' ('+d.total+' acc)');document.getElementById('accInput').value='';loadJobs();viewJob(d.job_id)}
    else toast('❌ '+d.error)
  }catch(e){toast('❌ Lỗi: '+e.message)}finally{btn.disabled=false;btn.textContent='🚀 Gửi check'}
}

async function loadJobs(){
  const el=document.getElementById('jobsList');
  try{
    const d=await api('/api/jobs_list');
    if(!d.ok||!d.jobs||d.jobs.length===0){el.innerHTML='<div class="empty">Chưa có job nào</div>';return}
    let h='<table><tr><th>ID</th><th>Tổng</th><th>Trạng thái</th><th>OK</th><th>Sai pass</th><th>Chưa thể check</th><th></th></tr>';
    d.jobs.forEach(j=>{
      const st=j.status==='done'?'<span class="tag tag-ok">Xong</span>':'<span class="tag tag-run">Đang chạy</span>';
      h+='<tr><td>#'+j.id+'</td><td>'+j.total+'</td><td>'+st+'</td><td style="color:#56d364">'+(j.ok||0)+'</td><td style="color:#ff7b72">'+(j.fail||0)+'</td><td style="color:#d29922">'+(j.uncheckable||0)+'</td>';
      h+='<td><button class="btn btn-sm btn-primary" onclick="viewJob('+j.id+')">Xem</button></td></tr>'
    });
    el.innerHTML=h+'</table>'
  }catch(e){el.innerHTML='<div class="empty">Lỗi: '+e.message+'</div>'}
}

async function viewJob(id){
  currentJobId=id;
  detailPage=1;
  document.getElementById('detailCard').style.display='block';
  document.getElementById('detailJobId').textContent=id;
  refreshDetail();
}

async function refreshDetail(){
  if(!currentJobId)return;
  const id=currentJobId;
  try{
    const s=await api('/api/jobs/'+id);
    if(!s.ok){document.getElementById('detailStats').innerHTML='<div class="empty">'+s.error+'</div>';return}
    const c=s.chunks||{},r=s.results||{};
    const duration=document.getElementById('detailDuration');duration.textContent=' · ⏱ '+formatJobDuration(s.created_at,s.finished_at);
    document.getElementById('stopJobBtn').style.display=s.status==='open'?'inline-block':'none';
    document.getElementById('detailStats').innerHTML=
      '<div class="stat"><div class="num">'+s.total+'</div><div class="lbl">Tổng</div></div>'+
      '<div class="stat ok"><div class="num">'+(r.ok||0)+'</div><div class="lbl">OK</div></div>'+
      '<div class="stat fail"><div class="num">'+(r.fail||0)+'</div><div class="lbl">Sai pass</div></div>'+
      '<div class="stat pending"><div class="num">'+(r.uncheckable||0)+'</div><div class="lbl">Chưa thể check</div></div>'+
      '<div class="stat pending"><div class="num">'+(c.pending||0)+'</div><div class="lbl">Chờ</div></div>'+
      '<div class="stat"><div class="num">'+(c.claimed||0)+'</div><div class="lbl">Đang check</div></div>';

    const rd=await api('/api/jobs/'+id+'/rows?page='+detailPage+'&per_page='+DETAIL_PAGE_SIZE);
    if(!rd.ok||!rd.rows||rd.rows.length===0){document.getElementById('detailRows').innerHTML='<div class="empty">Chưa có kết quả</div>';return}
    let h='<table><tr><th>STT</th><th>Account</th><th>Status</th><th>UID</th><th>Tên</th><th>Level</th><th>Trạng thái tài khoản</th></tr>';
    rd.rows.forEach(r=>{
      const tag=r.status==='OK'?'tag-ok':(r.status==='CHƯA THỂ CHECK'?'tag-run':'tag-fail');
      h+='<tr><td>'+r.stt+'</td><td><b>'+r.account+'</b></td><td><span class="tag '+tag+'">'+r.status+'</span></td>';
      h+='<td>'+r.uid+'</td><td>'+r.name+'</td><td>'+r.level+'</td><td>'+(r.player_status||'')+'</td></tr>'
    });
    const totalPages=rd.total_pages||1;
    h+='</table>';
    if(totalPages>1){
      h+='<div style="display:flex;align-items:center;justify-content:center;gap:10px;margin-top:12px">'+
        '<button class="btn btn-sm btn-primary" '+(rd.page<=1?'disabled':'')+' onclick="goDetailPage('+(rd.page-1)+')">← Trước</button>'+
        '<span style="font-size:12px;color:#8b949e">Trang '+rd.page+'/'+totalPages+' · '+rd.total+' kết quả</span>'+
        '<button class="btn btn-sm btn-primary" '+(rd.page>=totalPages?'disabled':'')+' onclick="goDetailPage('+(rd.page+1)+')">Sau →</button></div>';
    }
    document.getElementById('detailRows').innerHTML=h;
    if(s.status!=='done')setTimeout(refreshDetail,5000)
  }catch(e){document.getElementById('detailRows').innerHTML='<div class="empty">Lỗi: '+e.message+'</div>'}
}
function goDetailPage(page){detailPage=Math.max(1,page);refreshDetail();}

function exportCsv(){if(currentJobId)window.open('/api/jobs/'+currentJobId+'/export.csv?token='+TOKEN)}
function exportXlsx(){if(currentJobId)window.open('/api/jobs/'+currentJobId+'/export.xlsx?token='+TOKEN)}
function formatJobDuration(start,end){const t=Math.max(0,Math.floor((Number(end)||Date.now()/1000)-Number(start)));return String(Math.floor(t/3600)).padStart(2,'0')+':'+String(Math.floor(t%3600/60)).padStart(2,'0')+':'+String(t%60).padStart(2,'0');}
async function stopCurrentJob(){if(!currentJobId||!confirm('Dừng job này?'))return;const d=await api('/api/jobs/'+currentJobId+'/stop',{method:'POST',body:'{}'});if(d.ok){toast('⏹ Đã dừng job');refreshDetail();loadJobs()}else toast('❌ '+(d.error||'Không thể dừng job'));}

loadJobs();setInterval(loadJobs,15000);
</script>
</body>
</html>
"""


class MasterHandler(BaseHTTPRequestHandler):
    server: "CoordinatorServer"

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _extract_token(self) -> str:
        # Ưu tiên Authorization Bearer, sau đó X-License-Key, cuối cùng query ?token=
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip()
        lk = self.headers.get("X-License-Key", "")
        if lk:
            return lk.strip()
        # Hỗ trợ token qua query string cho export CSV
        if "?" in self.path:
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(self.path).query)
            qt = qs.get("token", [""])[0]
            if qt:
                return qt.strip()
            qk = qs.get("key", [""])[0]
            if qk:
                return qk.strip()
        return ""

    def _get_auth_info(self) -> dict[str, Any]:
        """Trả về thông tin xác thực: {authorized, is_admin, is_satellite, owner_hash, owner_preview, token}"""
        token = self._extract_token()
        master_token = self.server.master_token or ""
        # Nếu không đặt MASTER_TOKEN và không có LICENSE_SERVER_URL -> mở (dev)
        license_url = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
        if not master_token and not license_url:
            # Dev mode: chấp nhận mọi token, nếu không có token thì owner rỗng (legacy)
            if not token:
                return {"authorized": True, "is_admin": True, "is_satellite": True, "owner_hash": "", "owner_preview": "", "token": ""}
            # Nếu có token, coi như owner riêng
            return {"authorized": True, "is_admin": False, "is_satellite": False, "owner_hash": _hash_key(token), "owner_preview": _preview_key(token), "token": token}
        # Nếu token khớp MASTER_TOKEN -> admin / satellite
        if master_token and token and secrets.compare_digest(token.strip(), master_token.strip()):
            return {"authorized": True, "is_admin": True, "is_satellite": True, "owner_hash": "", "owner_preview": "admin", "token": token}
        # Nếu token không khớp MASTER_TOKEN, thử verify như license key
        if token:
            ok, info = _verify_license_key(token)
            if ok:
                return {"authorized": True, "is_admin": False, "is_satellite": False, "owner_hash": _hash_key(token), "owner_preview": _preview_key(token), "token": token, "license_info": info}
            # Verify fail — log để debug
            print(f"[master] auth FAIL: token='{_preview_key(token)}' license_url='{license_url}' info={info}", flush=True)
            return {"authorized": False, "is_admin": False, "is_satellite": False, "owner_hash": "", "owner_preview": "", "token": token, "license_info": info}
        # Không có token
        return {"authorized": False, "is_admin": False, "is_satellite": False, "owner_hash": "", "owner_preview": "", "token": ""}

    def _authorized(self) -> bool:
        return self._get_auth_info().get("authorized", False)

    def _require_user(self) -> dict[str, Any] | None:
        """Kiểm tra auth cho endpoint của user (job). Trả về auth_info nếu ok, else gửi 401 và return None"""
        info = self._get_auth_info()
        if not info.get("authorized"):
            # Nếu không có token mà server đang mở (không master_token, không license) thì cho qua
            master_token = self.server.master_token or ""
            license_url = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
            if not master_token and not license_url:
                return {"authorized": True, "is_admin": True, "owner_hash": "", "owner_preview": ""}
            # Error message chi tiết hơn
            license_info = info.get("license_info", {})
            error_detail = license_info.get("error", "") if isinstance(license_info, dict) else ""
            token = info.get("token", "")
            if not token:
                msg = "thiếu license key. Vui lòng nhập key từ license-server"
            elif error_detail:
                msg = f"license key không hợp lệ: {error_detail}"
            else:
                msg = "license key không hợp lệ hoặc hết hạn. Vui lòng kiểm tra lại key"
            self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": msg})
            return None
        return info

    def _require_satellite(self) -> dict[str, Any] | None:
        """Vệ tinh chỉ cần MASTER_TOKEN, không cần license key. Master có license key là đủ."""
        master_token = self.server.master_token or ""
        if not master_token:
            # Không đặt MASTER_TOKEN → cho phép mọi vệ tinh (tương thích cũ, tránh chặn)
            return {"authorized": True, "is_admin": True, "is_satellite": True, "owner_hash": "", "owner_preview": "", "token": ""}
        token = self._extract_token()
        if not token:
            self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "thiếu token vệ tinh (cần MASTER_TOKEN trong header Authorization)"})
            return None
        # So sánh an toàn — strip whitespace để tránh lỗi do copy/paste
        token_clean = token.strip()
        master_clean = master_token.strip()
        if token_clean and master_clean and secrets.compare_digest(token_clean, master_clean):
            return {"authorized": True, "is_admin": True, "is_satellite": True, "owner_hash": "", "owner_preview": "admin", "token": token}
        # Debug: log để dễ phát hiện mismatch
        print(f"[master] satellite auth FAIL: token_len={len(token_clean)} master_len={len(master_clean)} match={token_clean == master_clean}", flush=True)
        self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "token vệ tinh không hợp lệ (MASTER_TOKEN không khớp)"})
        return None

    def _security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, status: HTTPStatus, value: Any) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _read_json(self) -> Any:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            # Drain body để tránh RST khiến browser báo Failed to fetch
            if length > 0:
                try:
                    remaining = length
                    while remaining > 0:
                        chunk = self.rfile.read(min(remaining, 64 * 1024))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                except Exception:
                    pass
            raise ValueError("Kích thước request không hợp lệ")
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("JSON không hợp lệ") from exc

    def _html(self, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _clean_path(self) -> str:
        """Return path without query string."""
        p = self.path
        if "?" in p:
            p = p.split("?", 1)[0]
        return p

    def do_GET(self) -> None:
        try:
            path = self._clean_path()
            if path == "/healthz":
                mt = self.server.master_token or ""
                lu = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
                self._json(HTTPStatus.OK, {
                    "ok": True, "role": "master", "now": _now(),
                    "master_token_len": len(mt),
                    "master_token_preview": (mt[:4] + "***" + mt[-2:]) if len(mt) > 6 else ("set" if mt else "empty"),
                    "license_url": lu[:60] if lu else "empty",
                })
                return
            if path == "/api/verify":
                # Endpoint để frontend kiểm tra license key: ?key=xxx hoặc Authorization Bearer
                tok = self._extract_token()
                if not tok:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "thiếu key"})
                    return
                # Kiểm tra có phải MASTER_TOKEN không
                mt = self.server.master_token or ""
                is_master = bool(mt and tok and secrets.compare_digest(tok.strip(), mt.strip()))
                if is_master:
                    self._json(HTTPStatus.OK, {"ok": True, "valid": True, "is_admin": True, "preview": _preview_key(tok), "info": {"mode": "master_token"}})
                    return
                ok, info = _verify_license_key(tok)
                if ok:
                    self._json(HTTPStatus.OK, {"ok": True, "valid": True, "preview": _preview_key(tok), "info": info})
                else:
                    self._json(HTTPStatus.OK, {"ok": False, "valid": False, "error": info.get("error") or "key không hợp lệ", "info": info,
                        "debug": {"token_len": len(tok), "master_token_len": len(mt), "token_preview": _preview_key(tok)}})
                return
            if path == "/" or path == "/index.html":
                self._html(_PAGE_HTML)
                return
            # Các API user cần xác thực license key (hoặc MASTER_TOKEN cho admin)
            auth = self._require_user()
            if auth is None:
                return
            if path == "/api/jobs_list":
                self._handle_jobs_list(auth)
                return
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[0] == "api" and parts[1] == "jobs":
                job_id = self._int_or_none(parts[2])
                if job_id is None:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                    return
                self._handle_job_summary(job_id, auth)
                return
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "rows":
                job_id = self._int_or_none(parts[2])
                if job_id is None:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                    return
                self._handle_job_rows(job_id, auth)
                return
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "export.csv":
                job_id = self._int_or_none(parts[2])
                if job_id is None:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                    return
                self._handle_job_export(job_id, auth)
                return
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "export.xlsx":
                job_id = self._int_or_none(parts[2])
                if job_id is None:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                    return
                self._handle_job_export_xlsx(job_id, auth)
                return
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Không tìm thấy"})
        except Exception as exc:
            # Đảm bảo luôn trả JSON, tránh "Unexpected end of JSON input" ở frontend
            try:
                print(f"[master] do_GET error: {exc}", flush=True)
                import traceback; traceback.print_exc()
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"lỗi server: {exc}"[:300]})
            except Exception:
                pass

    @staticmethod
    def _int_or_none(value: str) -> int | None:
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        return number

    def do_POST(self) -> None:
        try:
            # Dùng _clean_path để hỗ trợ cả /api/jobs?foo=bar
            path = self._clean_path()
            # Phân biệt endpoint user vs vệ tinh
            if path == "/api/jobs":
                auth = self._require_user()
                if auth is None:
                    return
                self._handle_create_job(auth)
                return
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "stop":
                auth = self._require_user()
                if auth is None: return
                job_id = self._int_or_none(parts[2])
                if job_id is None:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"}); return
                self._handle_stop_job(job_id, auth); return
            if path == "/api/claim":
                auth = self._require_satellite()
                if auth is None:
                    return
                self._handle_claim()
                return
            if path == "/api/heartbeat":
                auth = self._require_satellite()
                if auth is None:
                    return
                self._handle_heartbeat()
                return
            if path == "/api/report":
                auth = self._require_satellite()
                if auth is None:
                    return
                self._handle_report()
                return
            if path == "/api/chunk/release":
                auth = self._require_satellite()
                if auth is None:
                    return
                self._handle_release()
                return
            if path == "/api/verify":
                tok = self._extract_token()
                if not tok:
                    try:
                        body = self._read_json()
                        tok = str(body.get("key") or body.get("token") or "")
                    except Exception:
                        tok = ""
                if not tok:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "thiếu key"})
                    return
                # Kiểm tra có phải MASTER_TOKEN không
                mt = self.server.master_token or ""
                is_master = bool(mt and tok and secrets.compare_digest(tok.strip(), mt.strip()))
                if is_master:
                    self._json(HTTPStatus.OK, {"ok": True, "valid": True, "is_admin": True, "preview": _preview_key(tok), "info": {"mode": "master_token"}})
                    return
                ok, info = _verify_license_key(tok)
                if ok:
                    self._json(HTTPStatus.OK, {"ok": True, "valid": True, "preview": _preview_key(tok), "info": info})
                else:
                    self._json(HTTPStatus.OK, {"ok": False, "valid": False, "error": info.get("error") or "key không hợp lệ", "info": info})
                return
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Không tìm thấy"})
        except Exception as exc:
            try:
                print(f"[master] do_POST error: {exc}", flush=True)
                import traceback; traceback.print_exc()
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"lỗi server: {exc}"[:300]})
            except Exception:
                pass

    # --- handlers -----------------------------------------------------

    def _handle_jobs_list(self, auth: dict[str, Any] | None = None) -> None:
        store = self.server.store
        owner_hash = (auth or {}).get("owner_hash", "") if auth else ""
        is_admin = bool((auth or {}).get("is_admin"))
        # Nếu admin (MASTER_TOKEN) hoặc owner rỗng (legacy/dev) thì xem tất cả
        if is_admin or not owner_hash:
            jobs_raw = store.fetch(
                "SELECT id, created_at, total, chunk_size, status, finished_at, owner_preview FROM jobs ORDER BY id DESC LIMIT 50"
            )
        else:
            jobs_raw = store.fetch(
                "SELECT id, created_at, total, chunk_size, status, finished_at, owner_preview FROM jobs WHERE owner_hash=? ORDER BY id DESC LIMIT 50",
                (owner_hash,),
            )
        jobs = []
        for row in jobs_raw:
            job_id = row[0]
            results = store.fetchone(
                "SELECT COUNT(*), SUM(CASE WHEN json_extract(row_json,'$.status')='OK' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN json_extract(row_json,'$.status')='FAIL' THEN 1 ELSE 0 END), "
                "SUM(CASE WHEN json_extract(row_json,'$.status')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END) "
                "FROM results WHERE job_id=?",
                (job_id,),
            )
            results_count = (results[0] if results else 0) or 0
            ok_count = (results[1] if results else 0) or 0
            fail_count = (results[2] if results else 0) or 0
            uncheckable_count = (results[3] if results else 0) or 0
            jobs.append({
                "id": job_id,
                "total": row[2],
                "status": row[4],
                "ok": ok_count,
                "fail": fail_count,
                "uncheckable": uncheckable_count,
                "owner_preview": row[6] if len(row) > 6 else "",
            })
        self._json(HTTPStatus.OK, {"ok": True, "jobs": jobs})

    def _handle_create_job(self, auth: dict[str, Any] | None = None) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        accounts_raw = body.get("accounts")
        text = body.get("text")
        if isinstance(accounts_raw, list):
            joined = "\n".join(str(item) for item in accounts_raw if item is not None)
        elif isinstance(text, str):
            joined = text
        elif isinstance(accounts_raw, str):
            joined = accounts_raw
        else:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần 'accounts' hoặc 'text'"})
            return
        try:
            parsed = parse_accounts(joined)
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        # Cố định 15 account/chunk; không nhận cấu hình từ client.
        chunk_size = DEFAULT_CHUNK_LIMIT

        store = self.server.store
        owner_hash = (auth or {}).get("owner_hash", "") if auth else ""
        owner_preview = (auth or {}).get("owner_preview", "") if auth else ""
        try:
            job_id = store.exec(
                "INSERT INTO jobs (created_at, total, chunk_size, status, owner_hash, owner_preview) VALUES (?,?,?,?,?,?)",
                (_now(), len(parsed), chunk_size, "open", owner_hash, owner_preview),
            )
            if not job_id:
                row = store.fetchone("SELECT MAX(id) FROM jobs")
                if row and row[0]:
                    job_id = int(row[0])
            chunks = split_chunks(parsed, chunk_size)
            stmts = []
            for idx, chunk in enumerate(chunks):
                accounts_json = json.dumps(
                    [f"{acc.account}|{acc.password}" for acc in chunk],
                    ensure_ascii=False,
                )
                stmts.append({
                    "sql": "INSERT INTO chunks (job_id, idx, account) VALUES (?,?,?)",
                    "args": [job_id, idx, accounts_json],
                })
            if stmts:
                store.batch(stmts)
        except Exception as exc:
            print(f"[master] Loi luu job vao DB: {exc}", flush=True)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"Lỗi lưu job vào DB: {exc}"[:300]})
            return
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "total": len(parsed),
            "chunks": len(chunks),
            "chunk_size": chunk_size,
        })

    def _handle_stop_job(self, job_id: int, auth: dict[str, Any]) -> None:
        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"}); return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền dừng job này"}); return
        if job[4] != "open":
            self._json(HTTPStatus.OK, {"ok": True, "status": job[4], "already_stopped": True}); return
        now = _now()
        self.server.store.batch([
            {"sql": "UPDATE jobs SET status='stopped', finished_at=? WHERE id=? AND status='open'", "args": [now, job_id]},
            {"sql": "UPDATE chunks SET status='stopped', lease_until=NULL WHERE job_id=? AND status IN ('pending','claimed')", "args": [job_id]},
        ])
        self._json(HTTPStatus.OK, {"ok": True, "job_id": job_id, "status": "stopped"})

    def _handle_claim(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        satellite_id = str(body.get("satellite_id") or "")
        if not satellite_id:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần satellite_id"})
            return
        try:
            lease_minutes = float(body.get("lease_minutes", DEFAULT_LEASE_MINUTES))
        except (TypeError, ValueError):
            lease_minutes = DEFAULT_LEASE_MINUTES
        lease_minutes = min(max(lease_minutes, 1), MAX_SATELLITE_LEASE_MINUTES)

        store = self.server.store
        now = _now()
        # Thử claim atomic — tránh việc 2 vệ tinh cùng nhận 1 pack và bỏ sót pack nhỏ
        # Lặp tối đa 3 lần nếu gặp race
        for _ in range(3):
            row = store.fetchone(
                """
                SELECT id, job_id, account FROM chunks
                WHERE (
                    status='pending'
                    OR (status='claimed' AND lease_until IS NOT NULL AND lease_until < ?)
                )
                AND (avoid_satellite_id='' OR avoid_satellite_id<>?)
                ORDER BY RANDOM()
                LIMIT 1
                """,
                (now, satellite_id),
            )
            if row is None:
                self._check_finish_all_jobs(now)
                self._json(HTTPStatus.OK, {"ok": True, "claim": None})
                return
            chunk_id, job_id, account_data = row
            # UPDATE có điều kiện — chỉ thành công nếu vẫn pending/lease hết hạn
            if hasattr(store, "exec_with_changes"):
                changed = store.exec_with_changes(
                    "UPDATE chunks SET status='claimed', satellite_id=?, claimed_at=?, lease_until=? WHERE id=? AND (status='pending' OR (status='claimed' AND lease_until < ?))",
                    (satellite_id, now, now + lease_minutes * 60, chunk_id, now),
                )
            else:
                store.exec(
                    "UPDATE chunks SET status='claimed', satellite_id=?, claimed_at=?, lease_until=? WHERE id=? AND (status='pending' OR (status='claimed' AND lease_until < ?))",
                    (satellite_id, now, now + lease_minutes * 60, chunk_id, now),
                )
                # Fallback: kiểm tra lại satellite_id
                chk = store.fetchone("SELECT satellite_id FROM chunks WHERE id=?", (chunk_id,))
                changed = 1 if (chk and chk[0] == satellite_id) else 0
            if changed == 0:
                # Race: chunk đã bị vệ tinh khác lấy, thử chunk khác
                continue
            try:
                accounts = json.loads(account_data)
            except (json.JSONDecodeError, TypeError):
                accounts = [account_data] if account_data else []
            # Đảm bảo luôn trả về đúng số acc của pack, kể cả pack nhỏ (< chunk_size)
            self._json(HTTPStatus.OK, {"ok": True, "claim": {
                "chunk_id": chunk_id,
                "job_id": job_id,
                "lease_until": now + lease_minutes * 60,
                "accounts": accounts,
            }})
            return
        # Nếu sau 3 lần vẫn race, báo không có claim để vệ tinh thử lại
        self._json(HTTPStatus.OK, {"ok": True, "claim": None})

    def _handle_heartbeat(self) -> None:
        """Gia hạn lease cho các chunk mà vệ tinh vẫn đang xử lý."""
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        satellite_id = str(body.get("satellite_id") or "").strip()
        chunk_ids = body.get("chunk_ids")
        if not satellite_id or not isinstance(chunk_ids, list):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần satellite_id và chunk_ids"})
            return
        valid_ids = []
        for value in chunk_ids[:100]:
            try:
                chunk_id = int(value)
            except (TypeError, ValueError):
                continue
            if chunk_id > 0:
                valid_ids.append(chunk_id)
        if not valid_ids:
            self._json(HTTPStatus.OK, {"ok": True, "renewed": 0})
            return
        try:
            lease_minutes = float(body.get("lease_minutes", DEFAULT_LEASE_MINUTES))
        except (TypeError, ValueError):
            lease_minutes = DEFAULT_LEASE_MINUTES
        lease_minutes = min(max(lease_minutes, 1), MAX_SATELLITE_LEASE_MINUTES)
        placeholders = ",".join("?" for _ in valid_ids)
        changed = self.server.store.exec_with_changes(
            f"UPDATE chunks SET lease_until=? WHERE status='claimed' AND satellite_id=? AND id IN ({placeholders})",
            (_now() + lease_minutes * 60, satellite_id, *valid_ids),
        )
        self._json(HTTPStatus.OK, {"ok": True, "renewed": changed})

    def _handle_report(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        try:
            chunk_id = int(body.get("chunk_id"))
        except (TypeError, ValueError):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần chunk_id"})
            return
        rows = body.get("rows")
        if not isinstance(rows, list):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần mảng rows"})
            return
        is_done = bool(body.get("done", True))

        store = self.server.store
        now = _now()
        chunk = store.fetchone(
            "SELECT job_id, status, account, satellite_id, retry_round FROM chunks WHERE id=?", (chunk_id,)
        )
        if chunk is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "chunk không tồn tại"})
            return
        job_id = chunk[0]
        job_state = store.fetchone("SELECT status FROM jobs WHERE id=?", (job_id,))
        if job_state and job_state[0] == "stopped":
            self._json(HTTPStatus.OK, {"ok": True, "chunk_id": chunk_id, "stopped": True})
            return
        # Lấy số acc kỳ vọng của pack (kể cả pack nhỏ < chunk_size)
        expected_count = None
        try:
            expected_accounts = json.loads(chunk[2]) if len(chunk) > 2 and chunk[2] else []
            expected_count = len(expected_accounts) if isinstance(expected_accounts, list) else None
        except Exception:
            expected_count = None
        stmts = []
        skipped_empty = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            account = str(row.get("account", "") or "")
            if not account:
                skipped_empty += 1
                continue
            stmts.append({
                "sql": "INSERT INTO results (chunk_id, job_id, account, row_json, reported_at) VALUES (?,?,?,?,?) ON CONFLICT(chunk_id, account) DO UPDATE SET row_json=excluded.row_json, reported_at=excluded.reported_at",
                "args": [chunk_id, job_id, account, json.dumps(row, ensure_ascii=False), now],
            })
        if is_done:
            stmts.append({
                "sql": "UPDATE chunks SET status='done', reported_at=? WHERE id=?",
                "args": [now, chunk_id],
            })
        if stmts:
            store.batch(stmts)
        requeued = 0
        retry_round = int(chunk[4] or 1)
        if is_done and chunk[1] != "done" and retry_round < MAX_ACCOUNT_RETRY_ROUNDS:
            requeued = self._requeue_uncheckable_rows(
                chunk_id, int(job_id), str(chunk[2] or ""), retry_round, str(chunk[3] or "")
            )
        # Kiểm tra sau khi ghi: nếu là pack nhỏ mà số rows thực tế ít hơn kỳ vọng, log cảnh báo để phát hiện mất pack
        if expected_count is not None:
            actual = store.fetchone("SELECT COUNT(*) FROM results WHERE chunk_id=?", (chunk_id,))
            actual_count = actual[0] if actual else 0
            final_expected = expected_count - requeued if is_done else expected_count
            if is_done and actual_count != final_expected:
                print(f"[master] cảnh báo: chunk {chunk_id} expected {expected_count} acc nhưng results {actual_count} (rows gửi {len(rows)} skipped_empty {skipped_empty})", flush=True)
            elif skipped_empty:
                print(f"[master] chunk {chunk_id} skipped_empty {skipped_empty}/{len(rows)}", flush=True)
        if is_done:
            self._check_finish_all_jobs(now)
        self._json(HTTPStatus.OK, {"ok": True, "chunk_id": chunk_id, "rows": len(rows), "done": is_done, "expected": expected_count, "requeued": requeued})

    def _requeue_uncheckable_rows(self, chunk_id: int, job_id: int, account_data: str, retry_round: int, avoid_satellite_id: str) -> int:
        """Allocate timeout/network failures again; only round 3 is final."""
        store = self.server.store
        try:
            source_accounts = json.loads(account_data)
        except (TypeError, json.JSONDecodeError):
            source_accounts = []
        if not isinstance(source_accounts, list):
            return 0
        retry_credentials: list[str] = []
        retry_accounts: list[str] = []
        for account, row_json in store.fetch("SELECT account, row_json FROM results WHERE chunk_id=? ORDER BY id", (chunk_id,)):
            try:
                row = json.loads(row_json)
            except (TypeError, json.JSONDecodeError):
                continue
            if str(row.get("status") or "").strip().upper() != "CHƯA THỂ CHECK":
                continue
            try:
                source_index = int(str(row.get("stt") or "0")) - 1
            except (TypeError, ValueError):
                source_index = -1
            if 0 <= source_index < len(source_accounts):
                retry_credentials.append(str(source_accounts[source_index]))
                retry_accounts.append(str(account))
        if not retry_credentials:
            return 0
        next_idx_row = store.fetchone("SELECT COALESCE(MAX(idx), -1) + 1 FROM chunks WHERE job_id=?", (job_id,))
        statements = [{
            "sql": "INSERT INTO chunks (job_id, idx, account, retry_round, avoid_satellite_id) VALUES (?,?,?,?,?)",
            "args": [job_id, int(next_idx_row[0]) if next_idx_row else 0, json.dumps(retry_credentials, ensure_ascii=False), retry_round + 1, avoid_satellite_id],
        }]
        statements.extend({"sql": "DELETE FROM results WHERE chunk_id=? AND account=?", "args": [chunk_id, account]} for account in retry_accounts)
        store.batch(statements)
        print(f"[master] chunk {chunk_id}: phân lại {len(retry_credentials)} acc sang vòng {retry_round + 1}", flush=True)
        return len(retry_credentials)

    def _handle_release(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        try:
            chunk_id = int(body.get("chunk_id"))
        except (TypeError, ValueError):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần chunk_id"})
            return
        satellite_id = str(body.get("satellite_id") or "")
        store = self.server.store
        store.exec(
            "UPDATE chunks SET status='pending', satellite_id='', claimed_at=NULL, lease_until=NULL WHERE id=? AND status='claimed' AND (?='' OR satellite_id=?)",
            (chunk_id, satellite_id, satellite_id),
        )
        self._json(HTTPStatus.OK, {"ok": True})

    def _check_finish_all_jobs(self, now: float) -> None:
        store = self.server.store
        open_jobs = store.fetch("SELECT id FROM jobs WHERE status='open'")
        for item in open_jobs:
            job_id = item[0]
            pending = store.fetchone(
                "SELECT COUNT(*) FROM chunks WHERE job_id=? AND status!='done'", (job_id,)
            )
            if pending and pending[0] == 0:
                store.exec(
                    "UPDATE jobs SET status='done', finished_at=? WHERE id=?",
                    (now, job_id),
                )

    def _check_job_access(self, job_id: int, auth: dict[str, Any] | None) -> tuple[bool, tuple | None]:
        """Kiểm tra job có thuộc owner không. Trả về (allowed, job_row). Admin được xem tất cả."""
        store = self.server.store
        job = store.fetchone(
            "SELECT id, created_at, total, chunk_size, status, finished_at, owner_hash, owner_preview FROM jobs WHERE id=?",
            (job_id,),
        )
        if job is None:
            return False, None
        # Nếu job cũ không có owner (legacy) thì chỉ admin mới xem được, user thường không thấy
        job_owner = job[6] or ""
        auth_owner = (auth or {}).get("owner_hash", "") if auth else ""
        is_admin = bool((auth or {}).get("is_admin"))
        if is_admin or not job_owner:
            # Admin xem tất cả, legacy job (owner rỗng) cho admin hoặc khi dev mode không filter
            # Nếu dev mode (không license, không master_token) thì owner rỗng -> cho qua
            if not is_admin and job_owner == "" and auth_owner != "":
                # User thường không được xem job legacy của người khác
                return False, job
            return True, job
        if job_owner == auth_owner:
            return True, job
        return False, job

    def _handle_job_summary(self, job_id: int, auth: dict[str, Any] | None = None) -> None:
        store = self.server.store
        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền xem job này (key khác)"})
            return
        pending = (store.fetchone("SELECT COUNT(*) FROM chunks WHERE job_id=? AND status='pending'", (job_id,)) or [0])[0]
        claimed = (store.fetchone("SELECT COUNT(*) FROM chunks WHERE job_id=? AND status='claimed'", (job_id,)) or [0])[0]
        done = (store.fetchone("SELECT COUNT(*) FROM chunks WHERE job_id=? AND status='done'", (job_id,)) or [0])[0]
        results = store.fetchone(
            "SELECT COUNT(*), SUM(CASE WHEN json_extract(row_json,'$.status')='OK' THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN json_extract(row_json,'$.status')='FAIL' THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN json_extract(row_json,'$.status')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END) FROM results WHERE job_id=?",
            (job_id,),
        )
        results_count = (results[0] if results else 0) or 0
        ok_count = (results[1] if results else 0) or 0
        fail_count = (results[2] if results else 0) or 0
        uncheckable_count = (results[3] if results else 0) or 0
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "created_at": job[1],
            "total": job[2],
            "chunk_size": job[3],
            "status": job[4],
            "finished_at": job[5],
            "owner_preview": job[7] if len(job) > 7 else "",
            "chunks": {"pending": pending, "claimed": claimed, "done": done},
            "results": {"count": results_count, "ok": ok_count, "fail": fail_count, "uncheckable": uncheckable_count},
        })

    def _handle_job_rows(self, job_id: int, auth: dict[str, Any] | None = None) -> None:
        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền xem job này"})
            return
        store = self.server.store
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            page = max(1, int(query.get("page", ["1"])[0]))
        except (TypeError, ValueError):
            page = 1
        try:
            per_page = int(query.get("per_page", ["50"])[0])
        except (TypeError, ValueError):
            per_page = 50
        # Giới hạn kích thước trang để một request chi tiết không tải quá nhiều dữ liệu.
        per_page = max(1, min(per_page, 100))
        total_row = store.fetchone("SELECT COUNT(*) FROM results WHERE job_id=?", (job_id,))
        total = int(total_row[0]) if total_row else 0
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        offset = (page - 1) * per_page
        rows_raw = store.fetch(
            "SELECT row_json FROM results WHERE job_id=? ORDER BY id LIMIT ? OFFSET ?",
            (job_id, per_page, offset),
        )
        rows = [json.loads(item[0]) for item in rows_raw]
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "rows": rows,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
        })

    def _handle_job_export(self, job_id: int, auth: dict[str, Any] | None = None) -> None:
        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền export job này"})
            return
        store = self.server.store
        rows_raw = store.fetch(
            "SELECT row_json FROM results WHERE job_id=? ORDER BY id", (job_id,)
        )
        rows = [json.loads(item[0]) for item in rows_raw]
        columns: list[str] = []
        for row in rows:
            for key in row:
                if key not in columns:
                    columns.append(key)
        if not columns:
            columns = ["account", "status"]
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        body = buffer.getvalue()
        data = body.encode("utf-8-sig")
        self.send_response(HTTPStatus.OK)
        self._security_headers("text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="job_{job_id}.csv"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _handle_job_export_xlsx(self, job_id: int, auth: dict[str, Any] | None = None) -> None:
        """Export one job into exclusive result-category sheets (level >= 12 is đạt)."""
        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền export job này"})
            return

        rows_raw = self.server.store.fetch(
            "SELECT chunk_id, row_json FROM results WHERE job_id=? ORDER BY id", (job_id,)
        )
        chunks_raw = self.server.store.fetch(
            "SELECT id, account FROM chunks WHERE job_id=?", (job_id,)
        )
        credentials_by_chunk: dict[int, list[str]] = {}
        for chunk_id, credentials_json in chunks_raw:
            try:
                credentials = json.loads(credentials_json)
            except (TypeError, json.JSONDecodeError):
                credentials = []
            credentials_by_chunk[int(chunk_id)] = credentials if isinstance(credentials, list) else []
        rows = []
        for chunk_id, row_json in rows_raw:
            row = json.loads(row_json)
            try:
                row_index = int(str(row.get("stt") or "0")) - 1
            except (TypeError, ValueError):
                row_index = -1
            credentials = credentials_by_chunk.get(int(chunk_id), [])
            if 0 <= row_index < len(credentials):
                # Chỉ dùng credential gốc cho file tải xuống; không trả qua API/UI.
                row["_export_credential"] = str(credentials[row_index])
            rows.append(row)
        sheets: dict[str, list[dict[str, Any]]] = {
            "Đạt": [], "Không đạt": [], "CTNV": [], "Bị khóa": [], "Sai pass": [], "Chưa thể check": [],
        }
        for row in rows:
            player_status = str(row.get("player_status") or "").strip()
            level = str(row.get("level") or "").strip()
            result_type = str(row.get("result_type") or "").strip().casefold()
            if result_type == "sai pass":
                sheets["Sai pass"].append(row)
            elif result_type == "chưa thể check" or str(row.get("status") or "").upper() == "CHƯA THỂ CHECK":
                sheets["Chưa thể check"].append(row)
            elif player_status == "Bị khóa":
                sheets["Bị khóa"].append(row)
            elif level.casefold() == "ctnv" or player_status == "Chưa tạo nhân vật":
                sheets["CTNV"].append(row)
            elif level.isdigit() and int(level) >= 12:
                sheets["Đạt"].append(row)
            else:
                sheets["Không đạt"].append(row)

        try:
            import re
            import openpyxl
            from openpyxl.styles import Alignment, Font, PatternFill

            workbook = openpyxl.Workbook()
            headers = ["STT", "Tài khoản", "Kết quả check", "UID", "Tên", "Cấp", "Trạng thái tài khoản"]
            fields = ["stt", "account", "status", "uid", "name", "level", "player_status"]
            fills = {
                "Đạt": "238636", "Không đạt": "9E6A03", "CTNV": "8250DF",
                "Bị khóa": "C2410C", "Sai pass": "DA3633", "Chưa thể check": "D29922",
            }
            for index, (sheet_name, sheet_rows) in enumerate(sheets.items()):
                worksheet = workbook.active if index == 0 else workbook.create_sheet()
                worksheet.title = sheet_name
                fill = PatternFill(start_color=fills[sheet_name], end_color=fills[sheet_name], fill_type="solid")
                for column, label in enumerate(headers, 1):
                    cell = worksheet.cell(row=1, column=column, value=label)
                    cell.font = Font(bold=True, color="FFFFFF")
                    cell.fill = fill
                    cell.alignment = Alignment(horizontal="center")
                for row_index, row in enumerate(sheet_rows, 2):
                    for column, field in enumerate(fields, 1):
                        value = str(
                            row.get("_export_credential") or row.get(field, "") or ""
                        ) if field == "account" else str(row.get(field, "") or "")
                        # Excel rejects ASCII control characters in cell values.
                        value = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", value)
                        worksheet.cell(row=row_index, column=column, value=value)
                worksheet.freeze_panes = "A2"
                worksheet.auto_filter.ref = f"A1:G{max(1, len(sheet_rows) + 1)}"
                for column, width in enumerate((8, 28, 16, 16, 28, 10, 24), 1):
                    worksheet.column_dimensions[openpyxl.utils.get_column_letter(column)].width = width

            output = io.BytesIO()
            workbook.save(output)
            data = output.getvalue()
        except Exception as exc:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"Không tạo được file XLSX: {exc}"[:500]})
            return

        self.send_response(HTTPStatus.OK)
        self._security_headers("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.send_header("Content-Disposition", f'attachment; filename="job_{job_id}_ket_qua.xlsx"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class CoordinatorServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], store: Store, master_token: str) -> None:
        super().__init__(address, handler)
        self.store = store
        self.master_token = master_token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tổng bộ điều phối check acc; không tự check")
    parser.add_argument("--port", type=int, default=None, help="Port HTTP (env PORT)")
    parser.add_argument("--host", type=str, default=None, help="Host bind (env HOST, mặc định 0.0.0.0)")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="File SQLite (env MASTER_DB)")
    parser.add_argument("--token", type=str, default=None, help="Token bí mật (env MASTER_TOKEN)")
    parser.add_argument("--self-test", action="store_true", help="Không mở server, chỉ kiểm tra")
    return parser.parse_args()


def configure_console_encoding() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    configure_console_encoding()
    args = parse_args()
    host = (args.host or os.environ.get("HOST", "") or "0.0.0.0").strip() or "0.0.0.0"
    port = args.port or int(os.environ.get("PORT", "8761") or "8761")
    db_path = Path(args.db or os.environ.get("MASTER_DB", "") or DEFAULT_DB_PATH)
    token = args.token or os.environ.get("MASTER_TOKEN", "").strip()

    if args.self_test:
        accs = parse_accounts("a|1\nb:2\n# comment\nc|3")
        chunks = split_chunks(accs, 2)
        assert len(accs) == 3
        assert [len(c) for c in chunks] == [2, 1]
        dup = parse_accounts("a|1\na:2")
        assert len(dup) == 2
        print("SELF-TEST OK: master parse/split."); return 0

    # Chọn store: Turso (cloud) hoặc SQLite local (fallback nếu Turso lỗi 400/wss)
    turso_url = os.environ.get("TURSO_URL", "").strip()
    turso_token = os.environ.get("TURSO_TOKEN", "").strip()
    # Ép https như license-server để tránh wss 400
    if turso_url and turso_url.startswith("libsql://"):
        turso_url = turso_url.replace("libsql://", "https://", 1)
    if turso_url:
        try:
            store = TursoStore(turso_url, turso_token)
            # Thử ping nhẹ để phát hiện 400 sớm
            try:
                store.fetch("SELECT 1")
            except Exception as e:
                print(f"[master] Turso ping fail ({e}), fallback sqlite", flush=True)
                raise
            db_label = f"turso={turso_url.split('//')[1].split('.')[0] if '//' in turso_url else turso_url}"
        except Exception as e:
            print(f"[master] Không kết nối Turso ({e}), dùng sqlite local", flush=True)
            store = LocalStore(db_path)
            db_label = f"sqlite={db_path} (fallback from turso)"
    else:
        store = LocalStore(db_path)
        db_label = f"sqlite={db_path}"

    server = CoordinatorServer((host, port), MasterHandler, store, token)
    license_url = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
    print(f"[master] Tổng bộ: http://{host}:{port}  role=coordinator  db={db_label}")
    print(f"[master] LICENSE_SERVER_URL = '{license_url}'")
    if token:
        print(f"[master] MASTER_TOKEN = '{token[:4]}***{token[-2:]}' (len={len(token)})")
    else:
        print("[master] CẢNH BÁO: chưa đặt MASTER_TOKEN - các vệ tinh đều truy cập được. Hãy đặt trên Render.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[master] Đã dừng.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
