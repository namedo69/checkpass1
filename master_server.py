from __future__ import annotations

"""Tổng bộ (coordinator) - chỉ điều phối chứ KHÔNG tự check account.

Nhận acc (user|pass), chia thành các chunk <= 1000, cho vệ tinh claim,
nhận kết quả về và lưu. Máy này giữ RAM nhỏ bất kể số lượng acc vì nó
không chạy Garena check; dữ liệu nằm trong SQLite trên đĩa.
"""

import argparse
from export_dates import registration_date
import asyncio
import contextlib
import csv
import functools
from datetime import datetime, timedelta, timezone
import hashlib
import html
import io
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import uuid
from http.cookies import SimpleCookie
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo
from satellite_keepawake import keepawake_loop
import garena_api_test_chrome1 as kientuong_api_test
import garena_tcp_login_chrome as kientuong_tcp_ui

DEFAULT_CHUNK_LIMIT = 15
# Chunk được cố định để tránh client thay đổi kích thước qua API.
MAX_CHUNK_LIMIT = 15
DEFAULT_MAX_RUNNING_JOBS = 10
MAX_CONFIGURED_RUNNING_JOBS = 10_000
DEFAULT_MIN_ACCOUNTS_PER_JOB = 1
DEFAULT_MAX_ACCOUNTS_PER_JOB = 999_999_999_999
MAX_CONFIGURED_ACCOUNTS_PER_JOB = 999_999_999_999
DEFAULT_MAX_VVIP_RUNNING_JOBS = 10
DEFAULT_MIN_VVIP_ACCOUNTS_PER_JOB = 1
DEFAULT_MAX_VVIP_ACCOUNTS_PER_JOB = 999_999_999_999
DEFAULT_DB_PATH = Path(__file__).resolve().with_name("master.db")
DEFAULT_LEASE_MINUTES = 3
MAX_SATELLITE_LEASE_MINUTES = 3
MAX_ACCOUNT_RETRY_ROUNDS = 3
QUANTITY_FAIL_PRICE_TENTHS = 1
TIME_BLOCK_PRICE_TENTHS = 50_000
VVIP_BLOCK_PRICE_TENTHS = 100_000
MAX_BODY = 32 * 1024 * 1024
SATELLITE_HEALTH_TIMEOUT = 20
KIENTUONG_REQUEST_TIMEOUT = 20.0
try:
    KIENTUONG_MONITOR_INTERVAL_SECONDS = max(30, int(os.environ.get("KIENTUONG_MONITOR_INTERVAL", "120")))
except ValueError:
    KIENTUONG_MONITOR_INTERVAL_SECONDS = 120
KIENTUONG_MONITOR_ACCOUNT = os.environ.get("KIENTUONG_MONITOR_ACCOUNT", "regcsuc1").strip() or "regcsuc1"
KIENTUONG_MONITOR_PASSWORD = os.environ.get("KIENTUONG_MONITOR_PASSWORD", "Zocl00zonx.").strip() or "Zocl00zonx."
STOP_FINALIZE_BATCH_SIZE = 250
RETENTION_RESULT_BATCH_SIZE = 1_000
RETENTION_CHUNK_BATCH_SIZE = 250
RETENTION_BATCH_GAP_SECONDS = 0.25
CHECKPASS_SESSION_SECONDS = 7 * 24 * 60 * 60
try:
    MAX_CHECKPASS_TIME_BLOCKS = int(os.environ.get("CHECKPASS_MAX_BLOCKS", "48"))
except ValueError:
    MAX_CHECKPASS_TIME_BLOCKS = 48
if MAX_CHECKPASS_TIME_BLOCKS < 1:
    MAX_CHECKPASS_TIME_BLOCKS = 48
AOVSHOP_API_URL = os.environ.get("AOVSHOP_API_URL", "").strip().rstrip("/")
CHECKPASS_SERVICE_TOKEN = os.environ.get("CHECKPASS_SERVICE_TOKEN", "").strip()
SP1S_FRONTEND_URL = os.environ.get("SP1S_FRONTEND_URL", "https://sp1s.shop").strip().rstrip("/")
CHECKPASS_PUBLIC_URL = os.environ.get("CHECKPASS_PUBLIC_URL", "").strip().rstrip("/")
LICENSE_CACHE_TTL = 300  # giây cache kết quả verify license
LICENSE_SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "").strip()
MASTER_TIMEZONE = os.environ.get("MASTER_TIMEZONE", "Asia/Ho_Chi_Minh").strip() or "Asia/Ho_Chi_Minh"
# Cache license: key -> (ok, expiry, info)
_LICENSE_CACHE: dict[str, tuple[bool, float, dict[str, Any]]] = {}
_LICENSE_CACHE_LOCK = threading.RLock()
_KIENTUONG_TCP_MODULE: Any = None
_KIENTUONG_TCP_MODULE_LOCK = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    total INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    finished_at REAL,
    owner_hash TEXT DEFAULT '',
    owner_preview TEXT DEFAULT '',
    owner_user_id INTEGER,
    owner_email TEXT DEFAULT '',
    owner_name TEXT DEFAULT '',
    billing_mode TEXT DEFAULT '',
    queue_type TEXT NOT NULL DEFAULT 'normal',
    billing_state TEXT DEFAULT 'none',
    external_job_reference TEXT DEFAULT '',
    unit_price_tenths INTEGER DEFAULT 0,
    estimated_amount_tenths INTEGER DEFAULT 0,
    final_amount_tenths INTEGER DEFAULT 0,
    hold_reference TEXT DEFAULT '',
    entitlement_id INTEGER,
    access_until REAL,
    billing_order_id INTEGER,
    billing_error TEXT DEFAULT ''
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
CREATE TABLE IF NOT EXISTS invalid_usernames (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    line_number INTEGER NOT NULL,
    username TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS junk_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    line_number INTEGER NOT NULL,
    username TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS job_stats (
    job_id INTEGER PRIMARY KEY,
    total_accounts INTEGER NOT NULL DEFAULT 0,
    job_status TEXT NOT NULL DEFAULT 'creating',
    pending_chunks INTEGER NOT NULL DEFAULT 0,
    claimed_chunks INTEGER NOT NULL DEFAULT 0,
    done_chunks INTEGER NOT NULL DEFAULT 0,
    result_count INTEGER NOT NULL DEFAULT 0,
    ok_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    uncheckable_count INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS job_result_stats (
    job_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 0,
    result_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (job_id, category, level)
);
CREATE TABLE IF NOT EXISTS web_sessions (
    session_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    expires_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS billing_outbox (
    job_id INTEGER PRIMARY KEY,
    operation TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at REAL NOT NULL DEFAULT 0,
    last_error TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_chunks_claim ON chunks(status, lease_until);
CREATE INDEX IF NOT EXISTS idx_chunks_job ON chunks(job_id);
CREATE INDEX IF NOT EXISTS idx_chunks_job_status ON chunks(job_id, status, id);
CREATE INDEX IF NOT EXISTS idx_chunks_available_job ON chunks(job_id, id) WHERE status IN ('pending','claimed');
CREATE INDEX IF NOT EXISTS idx_results_chunk ON results(chunk_id);
CREATE INDEX IF NOT EXISTS idx_results_job ON results(job_id);
CREATE INDEX IF NOT EXISTS idx_results_job_id ON results(job_id, id);
CREATE INDEX IF NOT EXISTS idx_invalid_usernames_job ON invalid_usernames(job_id, id);
CREATE INDEX IF NOT EXISTS idx_junk_accounts_job ON junk_accounts(job_id, id);
CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_hash);
CREATE INDEX IF NOT EXISTS idx_jobs_owner_user ON jobs(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_jobs_queue_status ON jobs(queue_type,status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_external_reference ON jobs(external_job_reference) WHERE external_job_reference<>'';
CREATE INDEX IF NOT EXISTS idx_web_sessions_expiry ON web_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_billing_outbox_retry ON billing_outbox(status,next_retry_at);
CREATE INDEX IF NOT EXISTS idx_job_stats_status ON job_stats(job_status);
"""

_POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    created_at DOUBLE PRECISION NOT NULL,
    total INTEGER NOT NULL,
    chunk_size INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    finished_at DOUBLE PRECISION,
    owner_hash TEXT DEFAULT '',
    owner_preview TEXT DEFAULT '',
    owner_user_id BIGINT,
    owner_email TEXT DEFAULT '',
    owner_name TEXT DEFAULT '',
    billing_mode TEXT DEFAULT '',
    queue_type TEXT NOT NULL DEFAULT 'normal',
    billing_state TEXT DEFAULT 'none',
    external_job_reference TEXT DEFAULT '',
    unit_price_tenths INTEGER DEFAULT 0,
    estimated_amount_tenths BIGINT DEFAULT 0,
    final_amount_tenths BIGINT DEFAULT 0,
    hold_reference TEXT DEFAULT '',
    entitlement_id BIGINT,
    access_until DOUBLE PRECISION,
    billing_order_id BIGINT,
    billing_error TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS chunks (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL,
    idx INTEGER NOT NULL,
    account TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    satellite_id TEXT DEFAULT '',
    claimed_at DOUBLE PRECISION,
    lease_until DOUBLE PRECISION,
    reported_at DOUBLE PRECISION,
    retry_round INTEGER NOT NULL DEFAULT 1,
    avoid_satellite_id TEXT DEFAULT '',
    UNIQUE(job_id, idx)
);
CREATE TABLE IF NOT EXISTS results (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    chunk_id BIGINT NOT NULL,
    job_id BIGINT NOT NULL,
    account TEXT NOT NULL,
    row_json TEXT NOT NULL,
    reported_at DOUBLE PRECISION NOT NULL,
    UNIQUE(chunk_id, account)
);
CREATE TABLE IF NOT EXISTS invalid_usernames (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL,
    line_number INTEGER NOT NULL,
    username TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS junk_accounts (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL,
    line_number INTEGER NOT NULL,
    username TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS job_stats (
    job_id BIGINT PRIMARY KEY,
    total_accounts INTEGER NOT NULL DEFAULT 0,
    job_status TEXT NOT NULL DEFAULT 'creating',
    pending_chunks INTEGER NOT NULL DEFAULT 0,
    claimed_chunks INTEGER NOT NULL DEFAULT 0,
    done_chunks INTEGER NOT NULL DEFAULT 0,
    result_count INTEGER NOT NULL DEFAULT 0,
    ok_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    uncheckable_count INTEGER NOT NULL DEFAULT 0,
    updated_at DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS job_result_stats (
    job_id BIGINT NOT NULL,
    category TEXT NOT NULL,
    level INTEGER NOT NULL DEFAULT 0,
    result_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (job_id, category, level)
);
CREATE TABLE IF NOT EXISTS web_sessions (
    session_hash TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at DOUBLE PRECISION NOT NULL,
    last_seen_at DOUBLE PRECISION NOT NULL,
    created_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS billing_outbox (
    job_id BIGINT PRIMARY KEY,
    operation TEXT NOT NULL,
    payload TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_error TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_chunks_claim ON chunks(status, lease_until);
CREATE INDEX IF NOT EXISTS idx_chunks_job ON chunks(job_id);
CREATE INDEX IF NOT EXISTS idx_chunks_job_status ON chunks(job_id, status, id);
CREATE INDEX IF NOT EXISTS idx_chunks_available_job ON chunks(job_id, id) WHERE status IN ('pending','claimed');
CREATE INDEX IF NOT EXISTS idx_results_chunk ON results(chunk_id);
CREATE INDEX IF NOT EXISTS idx_results_job ON results(job_id);
CREATE INDEX IF NOT EXISTS idx_results_job_id ON results(job_id, id);
CREATE INDEX IF NOT EXISTS idx_invalid_usernames_job ON invalid_usernames(job_id, id);
CREATE INDEX IF NOT EXISTS idx_junk_accounts_job ON junk_accounts(job_id, id);
CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_hash);
CREATE INDEX IF NOT EXISTS idx_jobs_owner_user ON jobs(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_jobs_queue_status ON jobs(queue_type,status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_external_reference ON jobs(external_job_reference) WHERE external_job_reference<>'';
CREATE INDEX IF NOT EXISTS idx_web_sessions_expiry ON web_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_billing_outbox_retry ON billing_outbox(status,next_retry_at);
CREATE INDEX IF NOT EXISTS idx_job_stats_status ON job_stats(job_status);
"""

_SQLITE_JOB_BILLING_MIGRATIONS = (
    "ALTER TABLE jobs ADD COLUMN owner_user_id INTEGER",
    "ALTER TABLE jobs ADD COLUMN owner_email TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN owner_name TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN billing_mode TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN queue_type TEXT NOT NULL DEFAULT 'normal'",
    "ALTER TABLE jobs ADD COLUMN billing_state TEXT DEFAULT 'none'",
    "ALTER TABLE jobs ADD COLUMN external_job_reference TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN unit_price_tenths INTEGER DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN estimated_amount_tenths INTEGER DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN final_amount_tenths INTEGER DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN hold_reference TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN entitlement_id INTEGER",
    "ALTER TABLE jobs ADD COLUMN access_until REAL",
    "ALTER TABLE jobs ADD COLUMN billing_order_id INTEGER",
    "ALTER TABLE jobs ADD COLUMN billing_error TEXT DEFAULT ''",
    "ALTER TABLE web_sessions ADD COLUMN is_admin INTEGER DEFAULT 0",
    "CREATE INDEX IF NOT EXISTS idx_jobs_owner_user ON jobs(owner_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_queue_status ON jobs(queue_type,status)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_external_reference ON jobs(external_job_reference) WHERE external_job_reference<>''",
)

_POSTGRES_JOB_BILLING_MIGRATIONS = (
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS owner_user_id BIGINT",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS owner_email TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS owner_name TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS billing_mode TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS queue_type TEXT NOT NULL DEFAULT 'normal'",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS billing_state TEXT DEFAULT 'none'",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS external_job_reference TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS unit_price_tenths INTEGER DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS estimated_amount_tenths BIGINT DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS final_amount_tenths BIGINT DEFAULT 0",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS hold_reference TEXT DEFAULT ''",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS entitlement_id BIGINT",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS access_until DOUBLE PRECISION",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS billing_order_id BIGINT",
    "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS billing_error TEXT DEFAULT ''",
    "ALTER TABLE web_sessions ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE",
    "CREATE INDEX IF NOT EXISTS idx_jobs_owner_user ON jobs(owner_user_id)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_queue_status ON jobs(queue_type,status)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_external_reference ON jobs(external_job_reference) WHERE external_job_reference<>''",
)


def _postgres_schema_phases() -> tuple[list[str], list[str]]:
    """Defer indexes until additive migrations have upgraded legacy tables."""
    table_statements: list[str] = []
    index_statements: list[str] = []
    for statement in _POSTGRES_SCHEMA.strip().split(";"):
        statement = statement.strip()
        if not statement:
            continue
        normalized = statement.upper()
        if normalized.startswith("CREATE INDEX") or normalized.startswith("CREATE UNIQUE INDEX"):
            index_statements.append(statement)
        else:
            table_statements.append(statement)
    return table_statements, index_statements


_SQLITE_JOB_STATS_TRIGGERS = (
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_jobs_insert
    AFTER INSERT ON jobs BEGIN
        INSERT INTO job_stats (job_id, total_accounts, job_status, updated_at)
        VALUES (NEW.id, NEW.total, NEW.status, CAST(strftime('%s','now') AS REAL))
        ON CONFLICT(job_id) DO UPDATE SET
            total_accounts=excluded.total_accounts,
            job_status=excluded.job_status,
            updated_at=excluded.updated_at;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_jobs_update
    AFTER UPDATE OF total, status ON jobs BEGIN
        UPDATE job_stats SET
            total_accounts=NEW.total,
            job_status=NEW.status,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=NEW.id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_jobs_delete
    AFTER DELETE ON jobs BEGIN
        DELETE FROM job_stats WHERE job_id=OLD.id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_chunks_insert
    AFTER INSERT ON chunks BEGIN
        UPDATE job_stats SET
            pending_chunks=pending_chunks + CASE WHEN NEW.status='pending' THEN 1 ELSE 0 END,
            claimed_chunks=claimed_chunks + CASE WHEN NEW.status='claimed' THEN 1 ELSE 0 END,
            done_chunks=done_chunks + CASE WHEN NEW.status='done' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=NEW.job_id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_chunks_update
    AFTER UPDATE OF job_id, status ON chunks BEGIN
        UPDATE job_stats SET
            pending_chunks=pending_chunks - CASE WHEN OLD.status='pending' THEN 1 ELSE 0 END,
            claimed_chunks=claimed_chunks - CASE WHEN OLD.status='claimed' THEN 1 ELSE 0 END,
            done_chunks=done_chunks - CASE WHEN OLD.status='done' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=OLD.job_id;
        UPDATE job_stats SET
            pending_chunks=pending_chunks + CASE WHEN NEW.status='pending' THEN 1 ELSE 0 END,
            claimed_chunks=claimed_chunks + CASE WHEN NEW.status='claimed' THEN 1 ELSE 0 END,
            done_chunks=done_chunks + CASE WHEN NEW.status='done' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=NEW.job_id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_chunks_delete
    AFTER DELETE ON chunks BEGIN
        UPDATE job_stats SET
            pending_chunks=pending_chunks - CASE WHEN OLD.status='pending' THEN 1 ELSE 0 END,
            claimed_chunks=claimed_chunks - CASE WHEN OLD.status='claimed' THEN 1 ELSE 0 END,
            done_chunks=done_chunks - CASE WHEN OLD.status='done' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=OLD.job_id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_results_insert
    AFTER INSERT ON results BEGIN
        UPDATE job_stats SET
            result_count=result_count + 1,
            ok_count=ok_count + CASE WHEN json_extract(NEW.row_json,'$.status')='OK' THEN 1 ELSE 0 END,
            fail_count=fail_count + CASE WHEN json_extract(NEW.row_json,'$.status')='FAIL' THEN 1 ELSE 0 END,
            uncheckable_count=uncheckable_count + CASE WHEN json_extract(NEW.row_json,'$.status')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=NEW.job_id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_results_update
    AFTER UPDATE OF job_id, row_json ON results BEGIN
        UPDATE job_stats SET
            result_count=result_count - 1,
            ok_count=ok_count - CASE WHEN json_extract(OLD.row_json,'$.status')='OK' THEN 1 ELSE 0 END,
            fail_count=fail_count - CASE WHEN json_extract(OLD.row_json,'$.status')='FAIL' THEN 1 ELSE 0 END,
            uncheckable_count=uncheckable_count - CASE WHEN json_extract(OLD.row_json,'$.status')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=OLD.job_id;
        UPDATE job_stats SET
            result_count=result_count + 1,
            ok_count=ok_count + CASE WHEN json_extract(NEW.row_json,'$.status')='OK' THEN 1 ELSE 0 END,
            fail_count=fail_count + CASE WHEN json_extract(NEW.row_json,'$.status')='FAIL' THEN 1 ELSE 0 END,
            uncheckable_count=uncheckable_count + CASE WHEN json_extract(NEW.row_json,'$.status')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=NEW.job_id;
    END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS trg_job_stats_results_delete
    AFTER DELETE ON results BEGIN
        UPDATE job_stats SET
            result_count=result_count - 1,
            ok_count=ok_count - CASE WHEN json_extract(OLD.row_json,'$.status')='OK' THEN 1 ELSE 0 END,
            fail_count=fail_count - CASE WHEN json_extract(OLD.row_json,'$.status')='FAIL' THEN 1 ELSE 0 END,
            uncheckable_count=uncheckable_count - CASE WHEN json_extract(OLD.row_json,'$.status')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END,
            updated_at=CAST(strftime('%s','now') AS REAL)
        WHERE job_id=OLD.job_id;
    END
    """,
)


def _sqlite_result_bucket_values(row_alias: str) -> tuple[str, str]:
    status = f"COALESCE(json_extract({row_alias}.row_json,'$.status'),'')"
    result_type = f"LOWER(COALESCE(json_extract({row_alias}.row_json,'$.result_type'),''))"
    player_status = f"LOWER(COALESCE(json_extract({row_alias}.row_json,'$.player_status'),''))"
    level_text = f"LOWER(COALESCE(json_extract({row_alias}.row_json,'$.level'),''))"
    category = (
        "CASE "
        f"WHEN {status}='CHƯA THỂ CHECK' OR {result_type}='chưa thể check' THEN 'PENDING' "
        f"WHEN UPPER({status})!='OK' OR {result_type} IN ('sai pass','không thể log') THEN 'FAIL' "
        f"WHEN {result_type}='lỗi ctnv' THEN 'GRANT_ERROR' "
        f"WHEN {player_status} LIKE '%khóa%' OR {player_status} LIKE '%ban%' "
        f"OR {player_status} LIKE '%cấm%' THEN 'LOCKED' "
        f"WHEN {level_text}='ctnv' OR {player_status} LIKE '%chưa tạo nhân vật%' THEN 'CTNV' "
        "ELSE 'LEVEL' END"
    )
    level = f"CASE WHEN ({category})='LEVEL' THEN CAST({level_text} AS INTEGER) ELSE 0 END"
    return category, level


_SQLITE_NEW_RESULT_CATEGORY, _SQLITE_NEW_RESULT_LEVEL = _sqlite_result_bucket_values("NEW")
_SQLITE_OLD_RESULT_CATEGORY, _SQLITE_OLD_RESULT_LEVEL = _sqlite_result_bucket_values("OLD")

_SQLITE_RESULT_STATS_TRIGGERS = (
    "DROP TRIGGER IF EXISTS trg_job_result_stats_insert",
    "DROP TRIGGER IF EXISTS trg_job_result_stats_update",
    "DROP TRIGGER IF EXISTS trg_job_result_stats_delete",
    f"""
    CREATE TRIGGER IF NOT EXISTS trg_job_result_stats_insert
    AFTER INSERT ON results BEGIN
        INSERT INTO job_result_stats (job_id, category, level, result_count)
        VALUES (NEW.job_id, {_SQLITE_NEW_RESULT_CATEGORY}, {_SQLITE_NEW_RESULT_LEVEL}, 1)
        ON CONFLICT(job_id, category, level) DO UPDATE SET result_count=result_count+1;
    END
    """,
    f"""
    CREATE TRIGGER IF NOT EXISTS trg_job_result_stats_update
    AFTER UPDATE OF job_id, row_json ON results BEGIN
        UPDATE job_result_stats SET result_count=result_count-1
        WHERE job_id=OLD.job_id AND category=({_SQLITE_OLD_RESULT_CATEGORY})
          AND level=({_SQLITE_OLD_RESULT_LEVEL});
        DELETE FROM job_result_stats WHERE job_id=OLD.job_id AND result_count<=0;
        INSERT INTO job_result_stats (job_id, category, level, result_count)
        VALUES (NEW.job_id, {_SQLITE_NEW_RESULT_CATEGORY}, {_SQLITE_NEW_RESULT_LEVEL}, 1)
        ON CONFLICT(job_id, category, level) DO UPDATE SET result_count=result_count+1;
    END
    """,
    f"""
    CREATE TRIGGER IF NOT EXISTS trg_job_result_stats_delete
    AFTER DELETE ON results BEGIN
        UPDATE job_result_stats SET result_count=result_count-1
        WHERE job_id=OLD.job_id AND category=({_SQLITE_OLD_RESULT_CATEGORY})
          AND level=({_SQLITE_OLD_RESULT_LEVEL});
        DELETE FROM job_result_stats WHERE job_id=OLD.job_id AND result_count<=0;
    END
    """,
)


_POSTGRES_JOB_STATS_TRIGGER_SQL = (
    """
    CREATE OR REPLACE FUNCTION maintain_job_stats_from_jobs() RETURNS TRIGGER AS $$
    BEGIN
        IF TG_OP = 'DELETE' THEN
            DELETE FROM job_stats WHERE job_id=OLD.id;
            RETURN OLD;
        END IF;
        INSERT INTO job_stats (job_id, total_accounts, job_status, updated_at)
        VALUES (NEW.id, NEW.total, NEW.status, EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))
        ON CONFLICT(job_id) DO UPDATE SET
            total_accounts=EXCLUDED.total_accounts,
            job_status=EXCLUDED.job_status,
            updated_at=EXCLUDED.updated_at;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS trg_job_stats_jobs ON jobs",
    "CREATE TRIGGER trg_job_stats_jobs AFTER INSERT OR UPDATE OF total, status OR DELETE ON jobs FOR EACH ROW EXECUTE FUNCTION maintain_job_stats_from_jobs()",
    """
    CREATE OR REPLACE FUNCTION maintain_job_stats_from_chunks() RETURNS TRIGGER AS $$
    BEGIN
        IF TG_OP IN ('UPDATE', 'DELETE') THEN
            UPDATE job_stats SET
                pending_chunks=pending_chunks - CASE WHEN OLD.status='pending' THEN 1 ELSE 0 END,
                claimed_chunks=claimed_chunks - CASE WHEN OLD.status='claimed' THEN 1 ELSE 0 END,
                done_chunks=done_chunks - CASE WHEN OLD.status='done' THEN 1 ELSE 0 END,
                updated_at=EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
            WHERE job_id=OLD.job_id;
        END IF;
        IF TG_OP IN ('INSERT', 'UPDATE') THEN
            UPDATE job_stats SET
                pending_chunks=pending_chunks + CASE WHEN NEW.status='pending' THEN 1 ELSE 0 END,
                claimed_chunks=claimed_chunks + CASE WHEN NEW.status='claimed' THEN 1 ELSE 0 END,
                done_chunks=done_chunks + CASE WHEN NEW.status='done' THEN 1 ELSE 0 END,
                updated_at=EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
            WHERE job_id=NEW.job_id;
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS trg_job_stats_chunks ON chunks",
    "CREATE TRIGGER trg_job_stats_chunks AFTER INSERT OR UPDATE OF job_id, status OR DELETE ON chunks FOR EACH ROW EXECUTE FUNCTION maintain_job_stats_from_chunks()",
    """
    CREATE OR REPLACE FUNCTION maintain_job_stats_from_results() RETURNS TRIGGER AS $$
    BEGIN
        IF TG_OP IN ('UPDATE', 'DELETE') THEN
            UPDATE job_stats SET
                result_count=result_count - 1,
                ok_count=ok_count - CASE WHEN COALESCE(OLD.row_json::jsonb ->> 'status','')='OK' THEN 1 ELSE 0 END,
                fail_count=fail_count - CASE WHEN COALESCE(OLD.row_json::jsonb ->> 'status','')='FAIL' THEN 1 ELSE 0 END,
                uncheckable_count=uncheckable_count - CASE WHEN COALESCE(OLD.row_json::jsonb ->> 'status','')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END,
                updated_at=EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
            WHERE job_id=OLD.job_id;
        END IF;
        IF TG_OP IN ('INSERT', 'UPDATE') THEN
            UPDATE job_stats SET
                result_count=result_count + 1,
                ok_count=ok_count + CASE WHEN COALESCE(NEW.row_json::jsonb ->> 'status','')='OK' THEN 1 ELSE 0 END,
                fail_count=fail_count + CASE WHEN COALESCE(NEW.row_json::jsonb ->> 'status','')='FAIL' THEN 1 ELSE 0 END,
                uncheckable_count=uncheckable_count + CASE WHEN COALESCE(NEW.row_json::jsonb ->> 'status','')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END,
                updated_at=EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)
            WHERE job_id=NEW.job_id;
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS trg_job_stats_results ON results",
    "CREATE TRIGGER trg_job_stats_results AFTER INSERT OR UPDATE OF job_id, row_json OR DELETE ON results FOR EACH ROW EXECUTE FUNCTION maintain_job_stats_from_results()",
    """
    CREATE OR REPLACE FUNCTION aggregate_result_category(value TEXT) RETURNS TEXT AS $$
        SELECT CASE
            WHEN COALESCE(value::jsonb ->> 'status','')='CHƯA THỂ CHECK'
              OR LOWER(COALESCE(value::jsonb ->> 'result_type',''))='chưa thể check' THEN 'PENDING'
            WHEN UPPER(COALESCE(value::jsonb ->> 'status',''))!='OK'
              OR LOWER(COALESCE(value::jsonb ->> 'result_type','')) IN ('sai pass','không thể log') THEN 'FAIL'
            WHEN LOWER(COALESCE(value::jsonb ->> 'result_type',''))='lỗi ctnv' THEN 'GRANT_ERROR'
            WHEN POSITION('khóa' IN LOWER(COALESCE(value::jsonb ->> 'player_status',''))) > 0
              OR POSITION('ban' IN LOWER(COALESCE(value::jsonb ->> 'player_status',''))) > 0
              OR POSITION('cấm' IN LOWER(COALESCE(value::jsonb ->> 'player_status',''))) > 0 THEN 'LOCKED'
            WHEN LOWER(COALESCE(value::jsonb ->> 'level',''))='ctnv'
              OR POSITION('chưa tạo nhân vật' IN LOWER(COALESCE(value::jsonb ->> 'player_status',''))) > 0 THEN 'CTNV'
            ELSE 'LEVEL'
        END
    $$ LANGUAGE SQL IMMUTABLE
    """,
    """
    CREATE OR REPLACE FUNCTION aggregate_result_level(value TEXT) RETURNS INTEGER AS $$
        SELECT CASE
            WHEN aggregate_result_category(value)='LEVEL'
             AND COALESCE(value::jsonb ->> 'level','') ~ '^[0-9]+$'
            THEN CAST(value::jsonb ->> 'level' AS INTEGER)
            ELSE 0
        END
    $$ LANGUAGE SQL IMMUTABLE
    """,
    """
    CREATE OR REPLACE FUNCTION maintain_job_result_stats() RETURNS TRIGGER AS $$
    BEGIN
        IF TG_OP IN ('UPDATE', 'DELETE') THEN
            UPDATE job_result_stats SET result_count=result_count-1
            WHERE job_id=OLD.job_id
              AND category=aggregate_result_category(OLD.row_json)
              AND level=aggregate_result_level(OLD.row_json);
            DELETE FROM job_result_stats WHERE job_id=OLD.job_id AND result_count<=0;
        END IF;
        IF TG_OP IN ('INSERT', 'UPDATE') THEN
            INSERT INTO job_result_stats (job_id, category, level, result_count)
            VALUES (NEW.job_id, aggregate_result_category(NEW.row_json), aggregate_result_level(NEW.row_json), 1)
            ON CONFLICT(job_id, category, level) DO UPDATE SET result_count=job_result_stats.result_count+1;
        END IF;
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql
    """,
    "DROP TRIGGER IF EXISTS trg_job_result_stats ON results",
    "CREATE TRIGGER trg_job_result_stats AFTER INSERT OR UPDATE OF job_id, row_json OR DELETE ON results FOR EACH ROW EXECUTE FUNCTION maintain_job_result_stats()",
)


def _backfill_job_stats_if_needed(store: Any) -> None:
    """Build aggregate rows once for an existing database during migration."""
    marker = store.fetchone(
        "SELECT setting_value FROM app_settings WHERE setting_key='job_stats_version'"
    )
    if marker and str(marker[0]) == "2":
        return
    now = _now()
    status = "COALESCE(json_extract(row_json,'$.status'),'')"
    result_type = "LOWER(COALESCE(json_extract(row_json,'$.result_type'),''))"
    player_status = "LOWER(COALESCE(json_extract(row_json,'$.player_status'),''))"
    level_text = "LOWER(COALESCE(json_extract(row_json,'$.level'),''))"
    if store.__class__.__name__ == "PostgreSQLStore":
        locked = (
            f"POSITION('khóa' IN {player_status}) > 0 OR POSITION('ban' IN {player_status}) > 0 "
            f"OR POSITION('cấm' IN {player_status}) > 0"
        )
        ctnv = f"{level_text}='ctnv' OR POSITION('chưa tạo nhân vật' IN {player_status}) > 0"
        numeric_level = (
            f"CASE WHEN {level_text} ~ '^[0-9]+$' THEN CAST({level_text} AS INTEGER) ELSE 0 END"
        )
    else:
        locked = (
            f"INSTR({player_status},'khóa') > 0 OR INSTR({player_status},'ban') > 0 "
            f"OR INSTR({player_status},'cấm') > 0"
        )
        ctnv = f"{level_text}='ctnv' OR INSTR({player_status},'chưa tạo nhân vật') > 0"
        numeric_level = f"CAST({level_text} AS INTEGER)"
    category = (
        "CASE "
        f"WHEN {status}='CHƯA THỂ CHECK' OR {result_type}='chưa thể check' THEN 'PENDING' "
        f"WHEN UPPER({status})!='OK' OR {result_type} IN ('sai pass','không thể log') THEN 'FAIL' "
        f"WHEN {result_type}='lỗi ctnv' THEN 'GRANT_ERROR' "
        f"WHEN {locked} THEN 'LOCKED' "
        f"WHEN {ctnv} THEN 'CTNV' "
        "ELSE 'LEVEL' END"
    )
    bucket_backfill_sql = (
        "INSERT INTO job_result_stats (job_id, category, level, result_count) "
        "SELECT job_id, category, level, COUNT(*) FROM ("
        f"SELECT job_id, {category} AS category, "
        f"CASE WHEN ({category})='LEVEL' THEN {numeric_level} ELSE 0 END AS level FROM results"
        ") categorized GROUP BY job_id, category, level"
    )
    store.batch([
        {"sql": "DELETE FROM job_stats"},
        {"sql": "DELETE FROM job_result_stats"},
        {
            "sql": (
                "INSERT INTO job_stats ("
                "job_id, total_accounts, job_status, pending_chunks, claimed_chunks, done_chunks, "
                "result_count, ok_count, fail_count, uncheckable_count, updated_at"
                ") SELECT j.id, j.total, j.status, "
                "COALESCE(c.pending,0), COALESCE(c.claimed,0), COALESCE(c.done,0), "
                "COALESCE(r.result_count,0), COALESCE(r.ok_count,0), "
                "COALESCE(r.fail_count,0), COALESCE(r.uncheckable_count,0), ? "
                "FROM jobs j LEFT JOIN ("
                "SELECT job_id, "
                "SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) AS pending, "
                "SUM(CASE WHEN status='claimed' THEN 1 ELSE 0 END) AS claimed, "
                "SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) AS done "
                "FROM chunks GROUP BY job_id"
                ") c ON c.job_id=j.id LEFT JOIN ("
                "SELECT job_id, COUNT(*) AS result_count, "
                "SUM(CASE WHEN json_extract(row_json,'$.status')='OK' THEN 1 ELSE 0 END) AS ok_count, "
                "SUM(CASE WHEN json_extract(row_json,'$.status')='FAIL' THEN 1 ELSE 0 END) AS fail_count, "
                "SUM(CASE WHEN json_extract(row_json,'$.status')='CHƯA THỂ CHECK' THEN 1 ELSE 0 END) AS uncheckable_count "
                "FROM results GROUP BY job_id"
                ") r ON r.job_id=j.id"
            ),
            "args": [now],
        },
        {"sql": bucket_backfill_sql},
        {
            "sql": (
                "INSERT INTO app_settings (setting_key, setting_value) VALUES ('job_stats_version','2') "
                "ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value"
            )
        },
    ])


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


def _aovshop_configured() -> bool:
    return bool(AOVSHOP_API_URL and CHECKPASS_SERVICE_TOKEN)


def _aovshop_requested() -> bool:
    return bool(AOVSHOP_API_URL or CHECKPASS_SERVICE_TOKEN)


def _aovshop_request(path: str, payload: dict[str, Any] | None = None, method: str = "POST") -> dict[str, Any]:
    if not _aovshop_configured():
        raise RuntimeError("AOVSHOP_API_URL/CHECKPASS_SERVICE_TOKEN chưa được cấu hình")
    url = AOVSHOP_API_URL + "/" + path.lstrip("/")
    data = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8") if method != "GET" else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {CHECKPASS_SERVICE_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            body = response.read().decode("utf-8", errors="replace")
            result = json.loads(body) if body else {}
            if not isinstance(result, dict):
                raise RuntimeError("AOVshop trả dữ liệu không hợp lệ")
            return result
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
            error_data = json.loads(error_body)
            message = str(error_data.get("error") or error_data.get("message") or f"HTTP {exc.code}")
            code = str(error_data.get("code") or "")
        except Exception:
            message, code = f"HTTP {exc.code}", ""
        error = RuntimeError(message[:300])
        setattr(error, "status", int(exc.code))
        setattr(error, "code", code)
        raise error from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("Không kết nối được hệ thống tài khoản SP1S") from exc


def _session_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _money_from_tenths(value: Any) -> float:
    return int(value or 0) / 10


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
            *_SQLITE_JOB_BILLING_MIGRATIONS,
        ]:
            try:
                _run_async(self._aexec(mig))
            except Exception:
                pass
        for trigger_sql in (*_SQLITE_JOB_STATS_TRIGGERS, *_SQLITE_RESULT_STATS_TRIGGERS):
            try:
                _run_async(self._aexec(trigger_sql))
            except Exception as exc:
                print(f"[TursoStore] cannot install aggregate trigger: {exc}", flush=True)
                raise
        _backfill_job_stats_if_needed(self)

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
            # Tạo các bảng cơ bản trước
            for statement in _SCHEMA.strip().split(";"):
                stmt = statement.strip()
                if stmt:
                    try:
                        self._conn.execute(stmt)
                    except Exception:
                        pass
            self._conn.commit()
            # Migration cho DB cũ
            for mig in [
                "ALTER TABLE jobs ADD COLUMN owner_hash TEXT DEFAULT ''",
                "ALTER TABLE jobs ADD COLUMN owner_preview TEXT DEFAULT ''",
                "ALTER TABLE chunks ADD COLUMN retry_round INTEGER NOT NULL DEFAULT 1",
                "ALTER TABLE chunks ADD COLUMN avoid_satellite_id TEXT DEFAULT ''",
                "CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_hash)",
                *_SQLITE_JOB_BILLING_MIGRATIONS,
            ]:
                try:
                    self._conn.execute(mig)
                except Exception:
                    pass
            try:
                self._conn.commit()
            except Exception:
                pass
            for trigger_sql in (*_SQLITE_JOB_STATS_TRIGGERS, *_SQLITE_RESULT_STATS_TRIGGERS):
                self._conn.execute(trigger_sql)
            self._conn.commit()
        _backfill_job_stats_if_needed(self)

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


@functools.lru_cache(maxsize=4096)
def _postgres_sql(sql: str) -> str:
    # Master dùng SQLite-style placeholders. Chuyển tại đây để các handler dùng chung.
    # Cache vì cùng một câu SQL được dịch lại ở mỗi request của vệ tinh.
    prepared = sql.replace("?", "%s")
    for field in ("status", "result_type", "player_status", "level"):
        prepared = prepared.replace(
            f"json_extract(row_json,'$.{field}')",
            f"(row_json::jsonb ->> '{field}')",
        )
    return prepared


class PostgreSQLStore:
    """PostgreSQL store for a dedicated VPS database.

    Dùng connection pool để các request HTTP (claim/heartbeat/report của vệ tinh,
    dashboard, UpLv) chạy song song thay vì xếp hàng sau một kết nối duy nhất.
    Nếu thiếu psycopg_pool thì quay về chế độ một kết nối + khóa như trước.
    """

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("thiếu psycopg; chạy pip install -r requirements_master.txt") from exc
        self._lock = threading.RLock()
        self._write_lock = threading.RLock()
        self._pool = None
        self._conn = None
        pool_size = max(1, int(os.environ.get("MASTER_PG_POOL_SIZE", "12") or 12))
        try:
            from psycopg_pool import ConnectionPool
        except ImportError:
            ConnectionPool = None
            print("[master] thiếu psycopg_pool; PostgreSQL chạy 1 kết nối (chậm hơn). "
                  "Cài: pip install 'psycopg[binary,pool]'", flush=True)
        if ConnectionPool is not None and pool_size > 1:
            # Read requests should not keep a PostgreSQL transaction open between calls.
            self._pool = ConnectionPool(
                dsn,
                min_size=min(2, pool_size),
                max_size=pool_size,
                kwargs={"autocommit": True},
                timeout=30,
                max_idle=300,
                open=True,
                name="checkpass-master",
            )
            self._pool.wait(timeout=30)
        else:
            self._conn = psycopg.connect(dsn, autocommit=True)
        self._init_tables()

    @contextlib.contextmanager
    def _connection(self):
        if self._pool is not None:
            with self._pool.connection() as conn:
                yield conn
        else:
            with self._lock:
                yield self._conn

    @staticmethod
    def _sql(sql: str) -> str:
        return _postgres_sql(sql)

    @contextlib.contextmanager
    def _write_connection(self):
        # Result/chunk triggers update shared aggregate rows in different orders.
        # Serialize writes BEFORE borrowing a pooled connection: queued reports
        # must not exhaust the pool needed by sessions and dashboard reads.
        with self._write_lock:
            with self._connection() as conn:
                yield conn

    def close(self) -> None:
        if self._pool is not None:
            self._pool.close()
        elif self._conn is not None:
            self._conn.close()

    def _init_tables(self) -> None:
        with self._connection() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    table_statements, index_statements = _postgres_schema_phases()
                    for sql in table_statements:
                        cur.execute(sql)
                    for migration in [
                        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS owner_hash TEXT DEFAULT ''",
                        "ALTER TABLE jobs ADD COLUMN IF NOT EXISTS owner_preview TEXT DEFAULT ''",
                        "ALTER TABLE chunks ADD COLUMN IF NOT EXISTS retry_round INTEGER NOT NULL DEFAULT 1",
                        "ALTER TABLE chunks ADD COLUMN IF NOT EXISTS avoid_satellite_id TEXT DEFAULT ''",
                        *_POSTGRES_JOB_BILLING_MIGRATIONS,
                    ]:
                        cur.execute(migration)
                    for sql in index_statements:
                        cur.execute(sql)
                    for trigger_sql in _POSTGRES_JOB_STATS_TRIGGER_SQL:
                        cur.execute(trigger_sql)
        _backfill_job_stats_if_needed(self)

    def exec(self, sql: str, args: tuple = ()) -> int:
        prepared = self._sql(sql)
        is_insert = prepared.lstrip().upper().startswith("INSERT")
        if is_insert and " RETURNING " not in prepared.upper():
            prepared += " RETURNING id"
        with self._write_connection() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(prepared, args)
                    if is_insert:
                        row = cur.fetchone()
                        return int(row[0]) if row else 0
                    return cur.rowcount

    def exec_with_changes(self, sql: str, args: tuple = ()) -> int:
        with self._write_connection() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(self._sql(sql), args)
                    return cur.rowcount

    def fetch(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(self._sql(sql), args)
                return cur.fetchall()

    def fetchone(self, sql: str, args: tuple = ()) -> tuple | None:
        with self._connection() as conn:
            with conn.cursor() as cur:
                cur.execute(self._sql(sql), args)
                return cur.fetchone()

    def batch(self, statements: list) -> None:
        with self._write_connection() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    for statement in statements:
                        if isinstance(statement, dict):
                            cur.execute(self._sql(statement["sql"]), statement.get("args", ()))
                        else:
                            cur.execute(self._sql(str(statement)))


@dataclass
class ParsedAccount:
    account: str
    password: str
    raw_line: str = ""
    line_number: int = 0


@dataclass
class InvalidUsername:
    line_number: int
    username: str
    raw_line: str
    reason: str


USERNAME_PATTERN = re.compile(
    r"^(?=.{6,18}$)(?=.*[A-Za-z])[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$"
)


def username_validation_reason(username: str) -> str:
    if not 6 <= len(username) <= 18:
        return "Tên đăng nhập phải có từ 6 đến 18 ký tự"
    if not re.fullmatch(r"[A-Za-z0-9._-]+", username):
        return "Chỉ được dùng chữ cái, chữ số, dấu gạch dưới, gạch ngang và dấu chấm"
    if not username[0].isalnum() or not username[-1].isalnum():
        return "Phải bắt đầu và kết thúc bằng chữ cái hoặc chữ số"
    if not re.search(r"[A-Za-z]", username):
        return "Phải chứa ít nhất một chữ cái"
    return "Tên đăng nhập không hợp lệ"


def partition_accounts_by_username(
    accounts: list[ParsedAccount],
) -> tuple[list[ParsedAccount], list[InvalidUsername]]:
    valid: list[ParsedAccount] = []
    invalid: list[InvalidUsername] = []
    for account in accounts:
        if USERNAME_PATTERN.fullmatch(account.account):
            valid.append(account)
        else:
            invalid.append(InvalidUsername(
                line_number=account.line_number,
                username=account.account,
                raw_line=account.raw_line or f"{account.account}|{account.password}",
                reason=username_validation_reason(account.account),
            ))
    return valid, invalid


@dataclass
class JunkAccount:
    line_number: int
    username: str
    raw_line: str
    reason: str


DOMAIN_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?\.){2,}"
    r"[A-Za-z]{2,24}(?::\d{1,5})?(?:[/#?].*)?$"
)
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
PROFILE_PATTERN = re.compile(r"^Google_\[Chrome\]_Profile\d*$", re.IGNORECASE)
SYSTEM_PLACEHOLDERS = {
    "unknown", "none", "null", "missing", "missingpass", "notsaved",
    "fail", "failed", "decryption", "decrypt", "decryptionfailed",
}
PROTOCOL_PLACEHOLDERS = {"http", "https", "ttp", "ttps", "ftp", "sso"}


def _normalized_marker(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def junk_account_reason(account: ParsedAccount) -> str | None:
    username = account.account.strip()
    password = account.password.strip()
    username_folded = username.casefold()
    password_folded = password.casefold()

    if (
        _normalized_marker(username) in SYSTEM_PLACEHOLDERS
        or _normalized_marker(password) in SYSTEM_PLACEHOLDERS
    ):
        return "Placeholder/trạng thái hệ thống, không phải thông tin đăng nhập thực"
    if password_folded in PROTOCOL_PLACEHOLDERS or password_folded.startswith(("http://", "https://")):
        return "Password là giao thức hoặc URL chuyển hướng"
    if DOMAIN_PATTERN.fullmatch(username):
        return "Username là domain hoặc endpoint web"
    if re.search(r"\.(?:html?|php\d?|aspx?|jsp)$", username, re.IGNORECASE):
        return "Username là tên file/endpoint web"
    if username_folded in {"direct", "redirect", "callback"} and password_folded in {
        "link", "url", "callback", "redirect",
    }:
        return "Dữ liệu endpoint/callback, không phải tài khoản"
    if PROFILE_PATTERN.fullmatch(password):
        return "Password là tên Chrome profile"
    if UUID_PATTERN.fullmatch(password):
        return "Password là UUID/token phiên"
    if len(password) >= 40 and (
        re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){1,2}", password)
        or re.fullmatch(r"[A-Za-z0-9_+/=-]{48,}", password)
    ):
        return "Password có dạng token/session dài"
    if (
        any(marker in username for marker in ("\ufffd", "ï¿½", "Ã", "Â", "Ð", "аё"))
        or re.search(r"[\u0400-\u04FF]", username)
    ):
        return "Username bị lỗi mã hóa bảng mã (mojibake)"
    if len(password) < 6:
        return "Mật khẩu ngắn hơn 6 ký tự"
    return None


def partition_accounts_for_job(
    accounts: list[ParsedAccount],
) -> tuple[list[ParsedAccount], list[InvalidUsername], list[JunkAccount]]:
    valid: list[ParsedAccount] = []
    invalid: list[InvalidUsername] = []
    junk: list[JunkAccount] = []

    for account in accounts:
        reason = junk_account_reason(account)
        raw_line = account.raw_line or f"{account.account}|{account.password}"
        if reason:
            junk.append(JunkAccount(account.line_number, account.account, raw_line, reason))
        elif not USERNAME_PATTERN.fullmatch(account.account):
            invalid.append(InvalidUsername(
                account.line_number,
                account.account,
                raw_line,
                username_validation_reason(account.account),
            ))
        else:
            valid.append(account)

    junk.sort(key=lambda item: item.line_number)
    return valid, invalid, junk


def _account_line_error(line_number: int, raw_line: str, reason: str) -> ValueError:
    rendered_line = json.dumps(raw_line, ensure_ascii=False)
    return ValueError(f"Dòng {line_number}: {reason}. Nội dung dòng: {rendered_line}")


def parse_accounts(text: str) -> list[ParsedAccount]:
    result: list[ParsedAccount] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[|:]", line)
        if len(parts) < 2:
            raise _account_line_error(
                line_number,
                raw,
                (
                    "cần định dạng user|pass, user|pass|mail hoặc "
                    "user|pass|mail|passmail (hoặc user:pass)"
                ),
            )
        account = parts[0].strip()
        password = parts[1].strip()
        if not account or not password or len(account) > 128 or len(password) > 1024:
            raise _account_line_error(
                line_number,
                raw,
                "tài khoản/mật khẩu không hợp lệ",
            )
        result.append(ParsedAccount(account, password, raw_line=line, line_number=line_number))
    if not result:
        raise ValueError("Danh sách trống hoặc không có dòng hợp lệ")
    return result


def split_chunks(accounts: list[ParsedAccount], chunk_size: int) -> list[list[ParsedAccount]]:
    return [accounts[i : i + chunk_size] for i in range(0, len(accounts), chunk_size)]


def _result_storage_key(account: str, row: dict[str, Any]) -> str:
    """Identify a result by its position so one USER may be tested with many passwords."""
    try:
        row_index = int(str(row.get("stt") or "0"))
    except (TypeError, ValueError):
        row_index = 0
    return f"{row_index}:{account}" if row_index > 0 else account


def select_fair_claim_candidate(
    store: Any,
    now: float,
    satellite_id: str,
    queue_type: str = "normal",
    allow_overflow: bool = False,
) -> tuple | None:
    """Select one eligible chunk from the open job with the fewest active chunks.

    Choosing a chunk globally would make a job's claim probability proportional
    to its remaining chunk count.  Selecting the least-active job first prevents
    a large job from starving smaller jobs. Normal jobs stay entirely in the
    normal pool. VVIP jobs assign 30% of chunks to VVIP and 70% to normal.
    Spread VVIP chunks across each group of ten (indices 0, 3, 6), rounding
    its share up for incomplete groups. Once a service pool has no preferred
    chunk left, it may claim available chunks from the other VVIP job share.
    """

    # Integer arithmetic works on SQLite/libSQL and PostgreSQL without optional
    # SQL math functions or percent signs conflicting with psycopg placeholders.
    vvip_share = "(c.idx - (c.idx / 10) * 10) IN (0,3,6)"
    normal_share = "(c.idx - (c.idx / 10) * 10) NOT IN (0,3,6)"
    if queue_type == "vvip":
        preferred_filter = f"COALESCE(j.queue_type,'normal')='vvip' AND {vvip_share}"
        overflow_filter = f"COALESCE(j.queue_type,'normal')='vvip' AND {normal_share}"
    else:
        preferred_filter = f"""(
            COALESCE(j.queue_type,'normal')='normal'
            OR (COALESCE(j.queue_type,'normal')='vvip' AND {normal_share})
        )"""
        overflow_filter = f"COALESCE(j.queue_type,'normal')='vvip' AND {vvip_share}"
    route_filter = overflow_filter if allow_overflow else preferred_filter

    selected_job = store.fetchone(
        f"""
        SELECT available.job_id
        FROM (
            SELECT j.id AS job_id
            FROM jobs AS j
            WHERE j.status='open'
              AND EXISTS (
                SELECT 1 FROM chunks AS c
                WHERE c.job_id=j.id
              AND c.status IN ('pending','claimed')
              AND ({route_filter})
              AND (
                  c.status='pending'
                  OR (c.status='claimed' AND c.lease_until IS NOT NULL AND c.lease_until < ?)
              )
              AND (c.avoid_satellite_id='' OR c.avoid_satellite_id<>?)
              )
        ) AS available
        LEFT JOIN (
            SELECT job_id, COUNT(*) AS active_count
            FROM chunks
            WHERE status='claimed'
              AND (lease_until IS NULL OR lease_until >= ?)
            GROUP BY job_id
        ) AS active ON active.job_id=available.job_id
        ORDER BY COALESCE(active.active_count, 0) ASC, available.job_id ASC
        LIMIT 1
        """,
        (now, satellite_id, now),
    )
    if selected_job is None:
        return None

    return store.fetchone(
        f"""
        SELECT c.id, c.job_id, c.account
        FROM chunks AS c
        JOIN jobs AS j ON j.id=c.job_id
        WHERE c.job_id=?
          AND c.status IN ('pending','claimed')
          AND ({route_filter})
          AND (
              c.status='pending'
              OR (c.status='claimed' AND c.lease_until IS NOT NULL AND c.lease_until < ?)
          )
          AND (c.avoid_satellite_id='' OR c.avoid_satellite_id<>?)
        ORDER BY c.job_id, c.id
        LIMIT 1
        """,
        (selected_job[0], now, satellite_id),
    )


_UI_FILE = Path(__file__).parent / "master_ui.html"
_ADMIN_UI_FILE = Path(__file__).parent / "master_admin.html"

DEFAULT_NOTICE_TITLE = "⚠️ CHÍNH SÁCH HỆ THỐNG & LƯU Ý CHECK:"
DEFAULT_NOTICE_BODY = (
    "Dữ liệu job và kết quả chỉ được lưu trong ngày hiện tại. Sang ngày mới, job đã hoàn thành "
    "sẽ tự xóa; job đang chạy được giữ lại đến khi hoàn thành rồi mới xóa.\n"
    "• Tool check không sử dụng proxy: chỉ khuyến khích check thông tin xấu và mailxt. "
    "Nếu TTT sau khi check mà lpass, Admin không chịu trách nhiệm.\n"
    "• Nếu gặp tài khoản bị treo quá lâu không trả kết quả, hãy bấm nút Dừng đơn và tạo đơn mới "
    "để tránh nghẽn tiến trình."
)
DEFAULT_SATELLITE_TARGETS = "[checkpass3] https://checkpass3-wt3z.onrender.com/\n"
DEFAULT_VVIP_SATELLITE_TARGETS = ""
DEFAULT_MODAL_NOTICE_TITLE = "THÔNG BÁO TỪ HỆ THỐNG"
DEFAULT_MODAL_NOTICE_HTML = (
    '<div style="text-align:center;padding:10px 0">'
    '<p style="font-size:16px;line-height:1.7;color:#e2e8f0;margin:0 0 10px 0">'
    'Hệ thống đang tạm bảo trì để nâng cấp dịch vụ.<br>'
    '<strong style="color:#f59e0b">Trang web tạm thời bị khóa.</strong> Vui lòng quay lại sau ít phút!'
    '</p>'
    '</div>'
)


def _setting(store: Any, key: str, default: str = "") -> str:
    row = store.fetchone("SELECT setting_value FROM app_settings WHERE setting_key=?", (key,))
    return str(row[0]) if row and row[0] is not None else default


def _master_tzinfo():
    try:
        return ZoneInfo(MASTER_TIMEZONE)
    except Exception:
        if MASTER_TIMEZONE in {"Asia/Ho_Chi_Minh", "Asia/Saigon"}:
            return timezone(timedelta(hours=7), name="ICT")
        raise ValueError(f"MASTER_TIMEZONE không hợp lệ: {MASTER_TIMEZONE}")


def _today_start_timestamp(now_timestamp: float | None = None) -> float:
    tz_info = _master_tzinfo()
    now = datetime.now(tz_info) if now_timestamp is None else datetime.fromtimestamp(now_timestamp, tz_info)
    return now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()


def _maintenance_window(now_timestamp: float | None = None) -> dict[str, Any]:
    tz_info = _master_tzinfo()
    now = datetime.now(tz_info) if now_timestamp is None else datetime.fromtimestamp(now_timestamp, tz_info)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(minutes=30)
    active = start <= now < end
    return {
        "active": active,
        "timezone": MASTER_TIMEZONE,
        "starts_at": start.isoformat(),
        "ends_at": end.isoformat(),
        "retry_after_seconds": max(0, int((end - now).total_seconds())) if active else 0,
        "message": "Hệ thống đang thực hiện dọn dẹp dữ liệu hôm trước, vui lòng quay lại sau 0h30.",
    }


def _prune_completed_jobs_batch(store: Any, cutoff: float | None = None) -> dict[str, Any]:
    """Delete one bounded slice of expired data and yield the database quickly."""
    cutoff = _today_start_timestamp() if cutoff is None else float(cutoff)
    target = store.fetchone(
        "SELECT id FROM jobs WHERE created_at < ? AND status='done' AND "
        "COALESCE(billing_state,'none') NOT IN ('reserved','settlement_pending') "
        "ORDER BY id LIMIT 1",
        (cutoff,),
    )
    if target is None:
        return {"complete": True, "jobs": 0, "chunks": 0, "results": 0}

    job_id = int(target[0])
    # Remove aggregates first. Their delete triggers would otherwise update the
    # same counter row once for every result in a very large expired job.
    store.exec("DELETE FROM job_result_stats WHERE job_id=?", (job_id,))
    store.exec("DELETE FROM job_stats WHERE job_id=?", (job_id,))
    store.exec("DELETE FROM invalid_usernames WHERE job_id=?", (job_id,))
    store.exec("DELETE FROM junk_accounts WHERE job_id=?", (job_id,))

    deleted_results = store.exec_with_changes(
        "DELETE FROM results WHERE id IN (SELECT id FROM results WHERE job_id=? ORDER BY id LIMIT ?)",
        (job_id, RETENTION_RESULT_BATCH_SIZE),
    )
    if store.fetchone("SELECT 1 FROM results WHERE job_id=? LIMIT 1", (job_id,)) is not None:
        return {"complete": False, "jobs": 0, "chunks": 0, "results": max(0, int(deleted_results or 0))}

    deleted_chunks = store.exec_with_changes(
        "DELETE FROM chunks WHERE id IN (SELECT id FROM chunks WHERE job_id=? ORDER BY id LIMIT ?)",
        (job_id, RETENTION_CHUNK_BATCH_SIZE),
    )
    if store.fetchone("SELECT 1 FROM chunks WHERE job_id=? LIMIT 1", (job_id,)) is not None:
        return {
            "complete": False, "jobs": 0,
            "chunks": max(0, int(deleted_chunks or 0)),
            "results": max(0, int(deleted_results or 0)),
        }

    store.exec("DELETE FROM billing_outbox WHERE job_id=?", (job_id,))
    deleted_jobs = store.exec_with_changes("DELETE FROM jobs WHERE id=?", (job_id,))
    return {
        "complete": False,
        "jobs": max(0, int(deleted_jobs or 0)),
        "chunks": max(0, int(deleted_chunks or 0)),
        "results": max(0, int(deleted_results or 0)),
    }


def _prune_completed_jobs_before_today(store: Any, cutoff: float | None = None) -> dict[str, Any]:
    """Compatibility entrypoint; intentionally performs only one bounded batch."""
    return _prune_completed_jobs_batch(store, cutoff)


def _finalize_unresolved_job_accounts(store: Any, job_id: int, now: float) -> int:
    """Persist placeholders for unfinished accounts without one huge DB batch."""

    statements: list[dict[str, Any]] = []
    marked = 0

    def flush() -> None:
        if statements:
            store.batch(list(statements))
            statements.clear()

    for chunk_id, account_data in store.fetch(
        "SELECT id, account FROM chunks WHERE job_id=? AND status IN ('pending','claimed')",
        (job_id,),
    ):
        try:
            credentials = json.loads(account_data)
        except (TypeError, json.JSONDecodeError):
            credentials = []
        if not isinstance(credentials, list):
            continue

        completed_indexes: set[int] = set()
        for (row_json,) in store.fetch(
            "SELECT row_json FROM results WHERE chunk_id=?", (chunk_id,)
        ):
            try:
                row = json.loads(row_json)
                completed_indexes.add(int(str(row.get("stt") or "0")) - 1)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue

        for index, credential in enumerate(credentials):
            if index in completed_indexes:
                continue
            account = str(credential).split("|", 1)[0].split(":", 1)[0].strip()
            if not account:
                continue
            row = {
                "stt": str(index + 1),
                "account": account,
                "status": "CHƯA THỂ CHECK",
                "result_type": "Chưa thể check",
                "uid": "",
                "name": "",
                "level": "",
                "player_status": "",
                "elapsed_ms": "0",
            }
            statements.append({
                "sql": "INSERT INTO results (chunk_id, job_id, account, row_json, reported_at) VALUES (?,?,?,?,?) ON CONFLICT(chunk_id, account) DO UPDATE SET row_json=excluded.row_json, reported_at=excluded.reported_at",
                "args": [
                    chunk_id,
                    job_id,
                    _result_storage_key(account, row),
                    json.dumps(row, ensure_ascii=False),
                    now,
                ],
            })
            marked += 1
            if len(statements) >= STOP_FINALIZE_BATCH_SIZE:
                flush()
    flush()
    return marked


def _retention_cleanup_loop(server: Any, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        if _maintenance_window().get("active"):
            server.schedule_retention_cleanup()
        try:
            server.store.exec("DELETE FROM web_sessions WHERE expires_at<=?", (_now(),))
        except Exception as exc:
            print(f"[master] expired session cleanup error: {exc}", flush=True)
        stop_event.wait(30)


def _max_running_jobs(store: Any) -> int:
    """Read the admission limit, falling back safely if stored data is invalid."""
    try:
        value = int(_setting(store, "max_running_jobs", str(DEFAULT_MAX_RUNNING_JOBS)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_RUNNING_JOBS
    if not 1 <= value <= MAX_CONFIGURED_RUNNING_JOBS:
        return DEFAULT_MAX_RUNNING_JOBS
    return value


def _max_accounts_per_job(store: Any) -> int:
    """Read the per-job account limit, falling back safely if it is invalid."""
    try:
        value = int(_setting(store, "max_accounts_per_job", str(DEFAULT_MAX_ACCOUNTS_PER_JOB)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_ACCOUNTS_PER_JOB
    if not 1 <= value <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
        return DEFAULT_MAX_ACCOUNTS_PER_JOB
    return value


def _min_accounts_per_job(store: Any) -> int:
    try:
        value = int(_setting(store, "min_accounts_per_job", str(DEFAULT_MIN_ACCOUNTS_PER_JOB)))
    except (TypeError, ValueError):
        return DEFAULT_MIN_ACCOUNTS_PER_JOB
    if not 1 <= value <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
        return DEFAULT_MIN_ACCOUNTS_PER_JOB
    return value


def _max_vvip_running_jobs(store: Any) -> int:
    try:
        value = int(_setting(store, "max_vvip_running_jobs", str(DEFAULT_MAX_VVIP_RUNNING_JOBS)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_VVIP_RUNNING_JOBS
    if not 1 <= value <= MAX_CONFIGURED_RUNNING_JOBS:
        return DEFAULT_MAX_VVIP_RUNNING_JOBS
    return value


def _max_vvip_accounts_per_job(store: Any) -> int:
    try:
        value = int(_setting(store, "max_vvip_accounts_per_job", str(DEFAULT_MAX_VVIP_ACCOUNTS_PER_JOB)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_VVIP_ACCOUNTS_PER_JOB
    if not 1 <= value <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
        return DEFAULT_MAX_VVIP_ACCOUNTS_PER_JOB
    return value


def _min_vvip_accounts_per_job(store: Any) -> int:
    try:
        value = int(_setting(store, "min_vvip_accounts_per_job", str(DEFAULT_MIN_VVIP_ACCOUNTS_PER_JOB)))
    except (TypeError, ValueError):
        return DEFAULT_MIN_VVIP_ACCOUNTS_PER_JOB
    if not 1 <= value <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
        return DEFAULT_MIN_VVIP_ACCOUNTS_PER_JOB
    return value


def _running_job_count(store: Any, queue_type: str = "normal") -> int:
    # "creating" reserves a slot until all chunks are committed and the job opens.
    row = store.fetchone(
        "SELECT COUNT(*) FROM jobs WHERE status IN ('creating','open') AND COALESCE(queue_type,'normal')=?",
        (queue_type,),
    )
    return int(row[0] or 0) if row else 0


def _notice_payload(store: Any, kientuong_status: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return editable HTML/CSS, falling back to the old title/body settings."""
    title = _setting(store, "notice_title", DEFAULT_NOTICE_TITLE)
    body = _setting(store, "notice_body", DEFAULT_NOTICE_BODY)
    body = body.replace(
        "Dữ liệu job và kết quả được lưu tối đa 2 ngày (hôm nay & hôm qua). Sau thời gian này hệ thống tự dọn dẹp sạch, kể cả Admin cũng không thể khôi phục.",
        "Dữ liệu job và kết quả chỉ được lưu trong ngày hiện tại. Sang ngày mới, job đã hoàn thành sẽ tự xóa; job đang chạy được giữ lại đến khi hoàn thành rồi mới xóa.",
    )
    notice_html = _setting(store, "notice_html", "").strip()
    notice_html = notice_html.replace(
        "Dữ liệu job và kết quả được lưu tối đa 2 ngày (hôm nay & hôm qua). Sau thời gian này hệ thống tự dọn dẹp sạch, kể cả Admin cũng không thể khôi phục.",
        "Dữ liệu job và kết quả chỉ được lưu trong ngày hiện tại. Sang ngày mới, job đã hoàn thành sẽ tự xóa; job đang chạy được giữ lại đến khi hoàn thành rồi mới xóa.",
    ).replace(
        "Dữ liệu job và kết quả được lưu tối đa 2 ngày (hôm nay &amp; hôm qua). Sau thời gian này hệ thống tự dọn dẹp sạch, kể cả Admin cũng không thể khôi phục.",
        "Dữ liệu job và kết quả chỉ được lưu trong ngày hiện tại. Sang ngày mới, job đã hoàn thành sẽ tự xóa; job đang chạy được giữ lại đến khi hoàn thành rồi mới xóa.",
    ).replace("Lưu trữ: 48h", "Lưu trữ: Trong ngày")
    if not notice_html:
        notice_html = (
            '<div><div class="notice-title">' + html.escape(title) + '</div>'
            '<div class="notice-body">' + html.escape(body) + '</div></div>'
            '<div class="notice-badges">'
            '<span class="notice-tag"><i class="fa-regular fa-clock"></i> Lưu trữ: Trong ngày</span>'
            '<span class="notice-tag"><i class="fa-solid fa-bolt"></i> Siêu tốc độ TCP</span>'
            '<span class="notice-tag"><i class="fa-solid fa-shield"></i> Mã hóa an toàn</span>'
            '</div>'
        )
    modal_enabled = _setting(store, "modal_notice_enabled", "0") == "1"
    modal_title = _setting(store, "modal_notice_title", DEFAULT_MODAL_NOTICE_TITLE)
    modal_html = _setting(store, "modal_notice_html", DEFAULT_MODAL_NOTICE_HTML)
    return {
        "enabled": _setting(store, "notice_enabled", "1") != "0",
        "title": title,
        "body": body,
        "html": notice_html,
        "css": _setting(store, "notice_css", ""),
        "modal_notice_enabled": modal_enabled,
        "modal_notice_title": modal_title,
        "modal_notice_html": modal_html,
        "modal_notice": {
            "enabled": modal_enabled,
            "title": modal_title,
            "html": modal_html,
        },
        "kientuong": dict(kientuong_status or {
            "state": "checking", "available": None, "http_status": 0,
            "checked_at": None, "error": "",
        }),
    }


def _save_settings(store: Any, values: dict[str, str]) -> None:
    store.batch([
        {
            "sql": (
                "INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?) "
                "ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value"
            ),
            "args": (key, value),
        }
        for key, value in values.items()
    ])


def parse_satellite_targets(text: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen_urls: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        # Dừng trước ký tự đóng Markdown để hỗ trợ cả [URL](URL).
        match = re.search(r"https?://[^\s\]\)>]+", line, flags=re.IGNORECASE)
        if not match:
            continue
        url = match.group(0).rstrip("/.,;)")
        try:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
                continue
            # URL cấu hình không được chứa user/password.
            if parsed.username or parsed.password:
                continue
            _ = parsed.port
        except ValueError:
            continue
        normalized_url = url.lower().rstrip("/")
        if normalized_url in seen_urls:
            continue
        seen_urls.add(normalized_url)
        named = re.search(r"\[([^]]+)\]", line)
        label = (named.group(1).strip() if named else "") or parsed.hostname or f"satellite-{number:02}"
        result.append({"label": label[:80], "url": url[:2048]})
    return result


def fetch_satellite_health(target: dict[str, str]) -> dict[str, Any]:
    started = time.monotonic()
    base_url = target["url"].rstrip("/")
    parsed = urllib.parse.urlsplit(base_url)
    base_path = parsed.path.rstrip("/")
    health_path = base_path if base_path.endswith("/healthz") else base_path + "/healthz"
    health_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, health_path or "/healthz", "", ""))
    request = urllib.request.Request(
        health_url,
        headers={"User-Agent": "Mozilla/5.0 CheckpassMasterHealthMonitor/1.0", "Accept": "application/json"},
    )
    result: dict[str, Any] = {**target, "health_url": health_url, "checked_at": _now()}
    try:
        with urllib.request.urlopen(request, timeout=SATELLITE_HEALTH_TIMEOUT) as response:
            raw = response.read(1024 * 1024).decode("utf-8", "replace")
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Health không trả JSON object")
        expected_type = str(target.get("expected_service_type") or "normal")
        actual_type = str(data.get("service_type") or "normal").lower()
        type_mismatch = actual_type != expected_type
        result.update({
            "online": bool(data.get("ok")),
            "health": data,
            "actual_service_type": actual_type,
            "type_mismatch": type_mismatch,
            "error": f"Service trả loại {actual_type}, cấu hình là {expected_type}" if type_mismatch else "",
        })
    except urllib.error.HTTPError as exc:
        body = exc.read(300).decode("utf-8", "replace")
        result.update({"online": False, "health": {}, "error": f"HTTP {exc.code}: {body}"[:300]})
    except Exception as exc:
        result.update({"online": False, "health": {}, "error": str(exc)[:300]})
    result["latency_ms"] = round((time.monotonic() - started) * 1000)
    return result


def restart_satellite(target: dict[str, str], control_token: str) -> dict[str, Any]:
    base_url = target["url"].rstrip("/")
    parsed = urllib.parse.urlsplit(base_url)
    base_path = parsed.path.rstrip("/")
    if base_path.endswith("/healthz"):
        base_path = base_path[:-8].rstrip("/")
    restart_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, base_path + "/restart", "", ""))
    request = urllib.request.Request(
        restart_url,
        data=b"{}",
        method="POST",
        headers={
            "Authorization": f"Bearer {control_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "CheckpassMasterControl/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=SATELLITE_HEALTH_TIMEOUT) as response:
            raw = response.read(64 * 1024).decode("utf-8", "replace")
            data = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read(500).decode("utf-8", "replace")
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
        raise RuntimeError(str(data.get("error") or f"Vệ tinh trả HTTP {exc.code}")) from exc
    except Exception as exc:
        raise RuntimeError(f"Không gửi được lệnh restart: {exc}") from exc
    if not isinstance(data, dict) or not data.get("ok"):
        raise RuntimeError(str(data.get("error") if isinstance(data, dict) else "Phản hồi restart không hợp lệ"))
    return {**data, "restart_url": restart_url}


def _kientuong_probe_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Extract only service-health fields from the direct master probe."""
    apis = result.get("apis") if isinstance(result.get("apis"), dict) else {}
    player = apis.get("kientuong_player") if isinstance(apis.get("kientuong_player"), dict) else {}
    try:
        status = int(player.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    available: bool | None = None
    if status == 404:
        available = False
    elif 200 <= status < 400:
        available = True
    return {
        "probe_succeeded": status > 0,
        "http_status": status,
        "available": available,
        "elapsed_ms": int(result.get("elapsed_ms") or 0),
    }


def run_kientuong_probe(account: str, password: str) -> dict[str, Any]:
    """Run the authenticated Kiện Tướng check inside the master process."""
    global _KIENTUONG_TCP_MODULE
    with _KIENTUONG_TCP_MODULE_LOCK:
        if _KIENTUONG_TCP_MODULE is None:
            _KIENTUONG_TCP_MODULE = kientuong_tcp_ui.load_verified_tcp_module()
        tcp_module = _KIENTUONG_TCP_MODULE
    result = kientuong_api_test.run_api_tests(
        tcp_module,
        account,
        password,
        KIENTUONG_REQUEST_TIMEOUT,
    )
    return _kientuong_probe_summary(result)


def _get_page_html() -> str:
    if _UI_FILE.is_file():
        try:
            return _UI_FILE.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"[master] Lỗi đọc master_ui.html: {exc}", flush=True)
    return """<!doctype html><html><body><h1>CHECK.SP1S.SHOP</h1><p>Vui lòng kiểm tra file master_ui.html</p></body></html>"""


def _get_admin_page_html() -> str:
    if _ADMIN_UI_FILE.is_file():
        try:
            return _ADMIN_UI_FILE.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"[master] Lỗi đọc master_admin.html: {exc}", flush=True)
    return """<!doctype html><html><body><h1>Quản trị CHECK.SP1S.SHOP</h1><p>Vui lòng kiểm tra file master_admin.html</p></body></html>"""


_PAGE_HTML = _get_page_html()


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

    def _extract_session(self) -> str:
        return self._cookie_value("checkpass_session")

    def _cookie_value(self, name: str) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
            item = cookie.get(name)
            return str(item.value).strip() if item else ""
        except Exception:
            return ""

    def _session_auth(self) -> dict[str, Any] | None:
        session = self._extract_session()
        if not session:
            return None
        now = _now()
        row = self.server.store.fetchone(
            "SELECT user_id,email,name,expires_at,is_admin FROM web_sessions WHERE session_hash=?",
            (_session_hash(session),),
        )
        if not row or float(row[3] or 0) <= now:
            if row:
                self.server.store.exec("DELETE FROM web_sessions WHERE session_hash=? ", (_session_hash(session),))
            return None
        self.server.store.exec(
            "UPDATE web_sessions SET last_seen_at=? WHERE session_hash=?",
            (now, _session_hash(session)),
        )
        is_admin = bool(row[4]) if len(row) > 4 and row[4] else False
        return {
            "authorized": True,
            "is_admin": is_admin,
            "is_satellite": False,
            "user_id": int(row[0]),
            "email": str(row[1] or ""),
            "name": str(row[2] or ""),
            "owner_hash": "",
            "owner_preview": "admin" if is_admin else str(row[1] or row[2] or f"user-{row[0]}"),
            "token": "",
        }

    def _public_base_url(self) -> str:
        if CHECKPASS_PUBLIC_URL:
            return CHECKPASS_PUBLIC_URL
        proto = self.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0].strip() or "http"
        host = self.headers.get("X-Forwarded-Host", "").split(",", 1)[0].strip() or self.headers.get("Host", "localhost")
        return f"{proto}://{host}".rstrip("/")

    def _redirect(self, location: str, cookies: list[str] | None = None) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _session_cookie(self, value: str, max_age: int = CHECKPASS_SESSION_SECONDS) -> str:
        secure = "; Secure" if self._public_base_url().startswith("https://") else ""
        return f"checkpass_session={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"

    def _sso_state_cookie(self, value: str, max_age: int = 300) -> str:
        secure = "; Secure" if self._public_base_url().startswith("https://") else ""
        return f"checkpass_sso_state={value}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"

    def _get_auth_info(self) -> dict[str, Any]:
        """Trả về thông tin xác thực: {authorized, is_admin, is_satellite, owner_hash, owner_preview, token}"""
        token = self._extract_token()
        master_token = self.server.master_token or ""
        # MASTER_TOKEN remains reserved for administration/satellites.
        if master_token and token and secrets.compare_digest(token.strip(), master_token.strip()):
            return {"authorized": True, "is_admin": True, "is_satellite": True, "owner_hash": "", "owner_preview": "admin", "token": token}

        # Production user authentication is the SP1S SSO session only. License
        # keys are deliberately not accepted once this integration is enabled.
        if _aovshop_configured():
            session_auth = self._session_auth()
            if session_auth:
                return session_auth
            return {"authorized": False, "is_admin": False, "is_satellite": False, "owner_hash": "", "owner_preview": "", "token": ""}
        if _aovshop_requested():
            return {
                "authorized": False, "is_admin": False, "is_satellite": False,
                "owner_hash": "", "owner_preview": "", "token": "",
                "config_error": "Thiếu AOVSHOP_API_URL hoặc CHECKPASS_SERVICE_TOKEN",
            }

        # Local tests/development retain the old open behavior when SP1S is not configured.
        license_url = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
        if not master_token and not license_url:
            # Dev mode: chấp nhận mọi token, nếu không có token thì owner rỗng (legacy)
            if not token:
                return {"authorized": True, "is_admin": True, "is_satellite": True, "owner_hash": "", "owner_preview": "", "token": ""}
            # Nếu có token, coi như owner riêng
            return {"authorized": True, "is_admin": False, "is_satellite": False, "owner_hash": _hash_key(token), "owner_preview": _preview_key(token), "token": token}
        # Nếu token không khớp MASTER_TOKEN, thử verify như license key
        if token:
            ok, info = _verify_license_key(token)
            if ok:
                return {"authorized": True, "is_admin": False, "is_satellite": False, "owner_hash": _hash_key(token), "owner_preview": _preview_key(token), "token": token, "license_info": info}
            # Verify fail — log để debug
            print(f"[master] auth FAIL: token='{_preview_key(token)}' license_url='{license_url}' info={info}", flush=True)
            # Preserve the deterministic owner identity even after expiry.
            # Possession of the original key may unlock only that key's stored
            # jobs; creating new work still requires a valid license.
            return {"authorized": False, "is_admin": False, "is_satellite": False, "owner_hash": _hash_key(token), "owner_preview": _preview_key(token), "token": token, "license_info": info}
        # Không có token
        return {"authorized": False, "is_admin": False, "is_satellite": False, "owner_hash": "", "owner_preview": "", "token": ""}

    def _authorized(self) -> bool:
        return self._get_auth_info().get("authorized", False)

    def _require_user(self) -> dict[str, Any] | None:
        """Kiểm tra auth cho endpoint của user (job). Trả về auth_info nếu ok, else gửi 401 và return None"""
        info = self._get_auth_info()
        if not info.get("authorized"):
            if _aovshop_requested() and not _aovshop_configured():
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": info.get("config_error") or "SP1S SSO chưa được cấu hình đầy đủ"})
                return None
            if _aovshop_configured():
                self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Vui lòng đăng nhập bằng tài khoản SP1S", "login_url": "/auth/login"})
                return None
            # Nếu không có token mà server đang mở (không master_token, không license) thì cho qua
            master_token = self.server.master_token or ""
            license_url = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
            if not master_token and not license_url:
                return {"authorized": True, "is_admin": True, "owner_hash": "", "owner_preview": ""}
            # Legacy local-development error message.
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

    def _require_job_owner(self) -> dict[str, Any] | None:
        """Require the current SP1S session (or local legacy test identity)."""
        info = self._get_auth_info()
        if info.get("authorized"):
            return info
        if _aovshop_requested() and not _aovshop_configured():
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": info.get("config_error") or "SP1S SSO chưa được cấu hình đầy đủ"})
            return None
        if not _aovshop_configured() and info.get("token") and info.get("owner_hash"):
            info["history_only"] = True
            return info
        self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "Vui lòng đăng nhập bằng tài khoản SP1S", "login_url": "/auth/login"})
        return None

    def _require_satellite(self, expected_queue: str | None = None) -> dict[str, Any] | None:
        """Authenticate a satellite with the shared token and bind its endpoint to a queue."""
        master_token = (self.server.master_token or "").strip()
        if not master_token:
            if _aovshop_requested() or _aovshop_configured():
                self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": "MASTER_TOKEN chưa được cấu hình"})
                return None
            # Không đặt MASTER_TOKEN → cho phép mọi vệ tinh (tương thích cũ, tránh chặn)
            queue_type = expected_queue or "normal"
            return {"authorized": True, "is_admin": True, "is_satellite": True, "queue_type": queue_type, "owner_hash": "", "owner_preview": queue_type, "token": ""}
        token = self._extract_token()
        if not token:
            self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "thiếu token vệ tinh trong header Authorization"})
            return None
        token_clean = token.strip()
        if token_clean and secrets.compare_digest(token_clean, master_token):
            queue_type = expected_queue or "normal"
            return {"authorized": True, "is_admin": True, "is_satellite": True, "queue_type": queue_type, "owner_hash": "", "owner_preview": queue_type, "token": token}
        print(f"[master] satellite auth FAIL: expected={expected_queue or 'any'} token_len={len(token_clean)}", flush=True)
        self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "error": "MASTER_TOKEN vệ tinh không hợp lệ"})
        return None

    def _require_admin(self) -> dict[str, Any] | None:
        """Chỉ chấp nhận MASTER_TOKEN thật cho các chức năng quản trị."""
        master_token = (self.server.master_token or "").strip()
        auth = self._get_auth_info()
        if not master_token or not auth.get("is_admin"):
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "chỉ MASTER_TOKEN mới được truy cập trang quản trị"})
            return None
        return auth

    def _security_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, status: HTTPStatus, value: Any, cookies: list[str] | None = None) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8")
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
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
            if path == '/uplv':
                if self._session_auth() is None:
                    self._redirect('/auth/login')
                    return
                self._html((Path(__file__).parent / 'uplv_user.html').read_text(encoding='utf-8'))
                return
            if path == '/admin/uplv':
                self._html((Path(__file__).parent / 'uplv_admin.html').read_text(encoding='utf-8'))
                return
            if path == '/api/admin/uplv/workers':
                if self._require_admin() is None:
                    return
                self._json(HTTPStatus.OK, self.server.uplv.worker_snapshot())
                return
            if path == '/api/admin/uplv':
                if self._require_admin() is None:
                    return
                self._json(HTTPStatus.OK, self.server.uplv.dashboard_snapshot())
                return
            if path == '/api/admin/uplv/checkpass-mode':
                if self._require_admin() is None:
                    return
                self._json(HTTPStatus.OK, self.server.uplv.checkpass_mode_status())
                return
            if path == "/favicon.svg":
                body = (Path(__file__).parent / "favicon.svg").read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "image/svg+xml")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(body)
                return
            if path == "/healthz":
                mt = self.server.master_token or ""
                lu = os.environ.get("LICENSE_SERVER_URL", "").strip() or LICENSE_SERVER_URL
                maintenance = _maintenance_window()
                self._json(HTTPStatus.OK, {
                    "ok": True, "role": "master", "now": _now(),
                    "master_token_configured": bool(mt),
                    "satellite_token_shared": True,
                    "license_url": lu[:60] if lu and not _aovshop_configured() else "disabled",
                    "sp1s_sso": _aovshop_configured(),
                    "maintenance": maintenance,
                })
                return
            if path == "/api/public/maintenance":
                maintenance = _maintenance_window()
                maintenance["cleanup"] = self.server.retention_cleanup_status()
                self._json(HTTPStatus.OK, {"ok": True, "maintenance": maintenance})
                return
            if path in {"/auth/login", "/auth/register"}:
                if not _aovshop_configured():
                    self._redirect("/?login_error=" + urllib.parse.quote("SP1S SSO chưa được cấu hình"))
                    return
                state = secrets.token_urlsafe(32)
                callback = self._public_base_url() + "/auth/callback?state=" + urllib.parse.quote(state, safe="")
                connect_path = "/checkpass/connect?return_url=" + urllib.parse.quote(callback, safe="")
                if path == "/auth/register":
                    target = SP1S_FRONTEND_URL + "/register?redirect=" + urllib.parse.quote(connect_path, safe="")
                else:
                    target = SP1S_FRONTEND_URL + "/login?redirect=" + urllib.parse.quote(connect_path, safe="")
                self._redirect(target, [self._sso_state_cookie(state)])
                return
            if path == "/auth/callback":
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                code = str(query.get("code", [""])[0] or "")
                state = str(query.get("state", [""])[0] or "")
                expected_state = self._cookie_value("checkpass_sso_state")
                clear_state = self._sso_state_cookie("", 0)
                if not code or not state or not expected_state or not secrets.compare_digest(state, expected_state):
                    self._redirect("/?login_error=" + urllib.parse.quote("Phiên đăng nhập SP1S không hợp lệ"), [clear_state])
                    return
                try:
                    result = _aovshop_request("/api/integrations/checkpass/sso/exchange", {"code": code})
                    user = result.get("user") if isinstance(result.get("user"), dict) else {}
                    user_id = int(user.get("id") or 0)
                    if not result.get("ok") or user_id <= 0:
                        raise RuntimeError(str(result.get("error") or "Không xác thực được tài khoản SP1S"))
                    is_admin = bool(result.get("is_admin") or user.get("role") == "admin")
                    session = secrets.token_urlsafe(48)
                    now = _now()
                    self.server.store.exec_with_changes(
                        "INSERT INTO web_sessions (session_hash,user_id,email,name,is_admin,expires_at,last_seen_at,created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            _session_hash(session), user_id, str(user.get("email") or ""),
                            str(user.get("name") or ""), bool(is_admin), now + CHECKPASS_SESSION_SECONDS, now, now,
                        ),
                    )
                    self._redirect("/?login=success", [self._session_cookie(session), clear_state])
                except Exception as exc:
                    self._redirect("/?login_error=" + urllib.parse.quote(str(exc)[:200]), [clear_state])
                return
            if path == "/api/session":
                auth = self._require_user()
                if auth is None:
                    return
                if auth.get("is_admin") or not _aovshop_configured():
                    self._json(HTTPStatus.OK, {
                        "ok": True,
                        "authenticated": True,
                        "user": {"id": auth.get("user_id", 0), "name": auth.get("name", "Admin"), "email": auth.get("email", "")},
                        "is_admin": True,
                        "role": "admin",
                        "min_accounts_per_job": _min_accounts_per_job(self.server.store),
                        "max_accounts_per_job": None,
                        "min_vvip_accounts_per_job": _min_vvip_accounts_per_job(self.server.store),
                        "max_vvip_accounts_per_job": _max_vvip_accounts_per_job(self.server.store),
                    })
                    return
                result = _aovshop_request(f"/api/integrations/checkpass/account/{int(auth['user_id'])}", method="GET")
                self._json(HTTPStatus.OK, {
                    "ok": True, "authenticated": True,
                    "min_accounts_per_job": _min_accounts_per_job(self.server.store),
                    "max_accounts_per_job": _max_accounts_per_job(self.server.store),
                    "min_vvip_accounts_per_job": _min_vvip_accounts_per_job(self.server.store),
                    "max_vvip_accounts_per_job": _max_vvip_accounts_per_job(self.server.store),
                    **result,
                })
                return
            if path == "/api/public/notice":
                self._json(HTTPStatus.OK, {
                    "ok": True,
                    "notice": _notice_payload(self.server.store, self.server.kientuong_status()),
                })
                return
            if path == "/api/verify":
                if _aovshop_configured():
                    auth = self._require_user()
                    if auth is None:
                        return
                    self._json(HTTPStatus.OK, {
                        "ok": True, "valid": True, "can_create_job": True,
                        "is_admin": bool(auth.get("is_admin")),
                        "max_accounts_per_job": _max_accounts_per_job(self.server.store),
                        "max_vvip_accounts_per_job": _max_vvip_accounts_per_job(self.server.store),
                        "user": {"id": auth.get("user_id"), "name": auth.get("name"), "email": auth.get("email")},
                    })
                    return
                # Endpoint để frontend kiểm tra license key: ?key=xxx hoặc Authorization Bearer
                tok = self._extract_token()
                if not tok:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "thiếu key"})
                    return
                # Kiểm tra có phải MASTER_TOKEN không
                mt = self.server.master_token or ""
                is_master = bool(mt and tok and secrets.compare_digest(tok.strip(), mt.strip()))
                if is_master:
                    self._json(HTTPStatus.OK, {
                        "ok": True,
                        "valid": True,
                        "history_access": True,
                        "can_create_job": True,
                        "is_admin": True,
                        "preview": _preview_key(tok),
                        "max_accounts_per_job": _max_accounts_per_job(self.server.store),
                        "max_vvip_accounts_per_job": _max_vvip_accounts_per_job(self.server.store),
                        "info": {"mode": "master_token"},
                    })
                    return
                ok, info = _verify_license_key(tok)
                if ok:
                    self._json(HTTPStatus.OK, {
                        "ok": True,
                        "valid": True,
                        "history_access": True,
                        "can_create_job": True,
                        "is_admin": False,
                        "preview": _preview_key(tok),
                        "max_accounts_per_job": _max_accounts_per_job(self.server.store),
                        "max_vvip_accounts_per_job": _max_vvip_accounts_per_job(self.server.store),
                        "info": info,
                    })
                else:
                    self._json(HTTPStatus.OK, {"ok": False, "valid": False, "history_access": True, "can_create_job": False, "error": info.get("error") or "key không hợp lệ", "info": info,
                        "debug": {"token_len": len(tok), "master_token_len": len(mt), "token_preview": _preview_key(tok)}})
                return
            if path == "/" or path == "/index.html":
                self._html(_get_page_html())
                return
            if path == "/admin" or path == "/admin.html":
                self._html(_get_admin_page_html())
                return
            if path == "/api/admin/settings":
                if self._require_admin() is None:
                    return
                self._handle_admin_settings_get()
                return
            if path == "/api/admin/prune_before_today":
                self._handle_prune_before_today()
                return
            if path == "/api/deposit/config":
                auth = self._require_user()
                if auth is None:
                    return
                try:
                    res = _aovshop_request("/api/integrations/checkpass/deposit/config", method="GET")
                    self._json(HTTPStatus.OK, res)
                except Exception as exc:
                    self._json(HTTPStatus.BAD_GATEWAY, {"ok": False, "error": str(exc)})
                return
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "deposit" and parts[2] == "status":
                auth = self._require_user()
                if auth is None:
                    return
                ref = parts[3]
                try:
                    res = _aovshop_request(f"/api/integrations/checkpass/deposit/status/{urllib.parse.quote(ref)}", method="GET")
                    self._json(HTTPStatus.OK, res)
                except Exception as exc:
                    self._json(HTTPStatus.BAD_GATEWAY, {"ok": False, "error": str(exc)})
                return
            # Các API user cần xác thực license key (hoặc MASTER_TOKEN cho admin)
            auth = self._require_job_owner()
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
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "export.txt":
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
            if self._clean_path().startswith('/api/user/uplv/'):
                auth = self._session_auth()
                if not auth:
                    self._json(HTTPStatus.UNAUTHORIZED, {'ok': False, 'error': 'Vui lòng đăng nhập SP1S', 'login_url': '/auth/login'})
                    return
                origin = self.headers.get('Origin', '')
                if origin and urllib.parse.urlsplit(origin).netloc != urllib.parse.urlsplit(self._public_base_url()).netloc:
                    self._json(HTTPStatus.FORBIDDEN, {'ok': False, 'error': 'Origin không hợp lệ'})
                    return
                try:
                    self._json(HTTPStatus.OK, self.server.uplv.user_action(self._clean_path().rsplit('/', 1)[-1], self._read_json(), auth))
                except (ValueError, TypeError, KeyError) as exc:
                    self._json(HTTPStatus.BAD_REQUEST, {'ok': False, 'error': str(exc)})
                return
            if self._clean_path() in ('/api/checkpass/uplv/claim', '/api/checkpass/uplv/report'):
                if self._require_satellite('normal') is None:
                    return
                try:
                    action = self.server.uplv.checkpass_claim if self._clean_path().endswith('/claim') else self.server.uplv.checkpass_report
                    self._json(HTTPStatus.OK, action(self._read_json()))
                except (ValueError, TypeError, KeyError) as exc:
                    self._json(HTTPStatus.BAD_REQUEST, {'ok': False, 'error': str(exc)})
                return
            # Dùng _clean_path để hỗ trợ cả /api/jobs?foo=bar
            path = self._clean_path()
            if path.startswith('/api/uplv/') or path.startswith('/api/admin/uplv/'):
                admin = path.startswith('/api/admin/')
                auth = self._require_admin() if admin else self._require_satellite('uplv')
                if auth is None:
                    return
                actions = {'/api/admin/uplv/jobs': self.server.uplv.create,
                           '/api/admin/uplv/reserves': self.server.uplv.add_reserves,
                           '/api/admin/uplv/settings': self.server.uplv.pool_settings,
                           '/api/admin/uplv/user-limits': self.server.uplv.save_user_limits,
                           '/api/admin/uplv/targets': self.server.uplv.save_targets,
                           '/api/admin/uplv/health': self.server.uplv.target_health,
                           '/api/admin/uplv/recover': self.server.uplv.recover_pending,
                           '/api/admin/uplv/accounts': self.server.uplv.account_details,
                           '/api/admin/uplv/clear': self.server.uplv.clear_data,
                           '/api/admin/uplv/logs': lambda b: self.server.uplv.logs(b, self.server.master_token),
                           '/api/admin/uplv/control': self.server.uplv.control,
                           '/api/admin/uplv/export': lambda b: self.server.uplv.export(str(b.get('job_id', ''))),
                           '/api/admin/uplv/checkpass-mode': self.server.uplv.checkpass_mode_set,
                           '/api/uplv/claim': self.server.uplv.claim,
                           '/api/uplv/presence': self.server.uplv.presence,
                           '/api/uplv/replace': self.server.uplv.replace,
                           '/api/uplv/heartbeat': self.server.uplv.heartbeat,
                           '/api/uplv/report': self.server.uplv.report,
                           '/api/uplv/checkpass/claim': self.server.uplv.checkpass_mode_claim}
                action = actions.get(path)
                if action is None:
                    self._json(HTTPStatus.NOT_FOUND, {'ok': False, 'error': 'Không tìm thấy'})
                    return
                try:
                    self._json(HTTPStatus.OK, action(self._read_json()))
                except (ValueError, TypeError, KeyError) as exc:
                    self._json(HTTPStatus.BAD_REQUEST, {'ok': False, 'error': str(exc)})
                return
            # Phân biệt endpoint user vs vệ tinh
            if path == "/api/admin/clear_all":
                self._handle_clear_all_data()
                return
            if path == "/api/admin/settings":
                if self._require_admin() is None:
                    return
                self._handle_admin_settings_save()
                return
            if path == "/api/admin/satellites/health":
                if self._require_admin() is None:
                    return
                self._handle_satellite_health()
                return
            if path == "/api/admin/satellites/restart":
                if self._require_admin() is None:
                    return
                self._handle_satellite_restart()
                return
            if path == "/api/admin/satellites/restart-all":
                if self._require_admin() is None:
                    return
                self._handle_satellites_restart_all()
                return
            if path == "/api/deposit/create":
                auth = self._require_user()
                if auth is None:
                    return
                try:
                    body = self._read_json()
                    user_id = int(auth.get("user_id") or 0)
                    if user_id <= 0:
                        raise ValueError("Tài khoản không hợp lệ")
                    amount = int(body.get("amount") or 0)
                    res = _aovshop_request("/api/integrations/checkpass/deposit/create", {
                        "user_id": user_id,
                        "amount": amount,
                    })
                    self._json(HTTPStatus.OK, res)
                except Exception as exc:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
                return
            if path == "/api/jobs":
                maintenance = _maintenance_window()
                if maintenance.get("active"):
                    self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                        "ok": False,
                        "code": "DAILY_MAINTENANCE",
                        "error": maintenance["message"],
                        "maintenance": maintenance,
                    })
                    return
                auth = self._require_user()
                if auth is None:
                    return
                self._handle_create_job(auth)
                return
            if path == "/api/quote":
                auth = self._require_user()
                if auth is None:
                    return
                self._handle_billing_quote(auth)
                return
            if path == "/auth/logout":
                session = self._extract_session()
                if session:
                    self.server.store.exec("DELETE FROM web_sessions WHERE session_hash=?", (_session_hash(session),))
                self._json(
                    HTTPStatus.OK,
                    {"ok": True, "logged_out": True},
                    [self._session_cookie("", 0)],
                )
                return
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "jobs" and parts[3] == "stop":
                auth = self._require_job_owner()
                if auth is None:
                    return
                job_id = self._int_or_none(parts[2])
                if job_id is None:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "job_id không hợp lệ"})
                    return
                self._handle_stop_job(job_id, auth)
                return
            if path == "/api/claim":
                auth = self._require_satellite("normal")
                if auth is None:
                    return
                self._handle_claim("normal")
                return
            if path == "/api/vvip/claim":
                auth = self._require_satellite("vvip")
                if auth is None:
                    return
                self._handle_claim("vvip")
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
            if path == '/api/checkpass/uplv/chunk-report':
                if self._require_satellite('normal') is None:
                    return
                try:
                    self._json(HTTPStatus.OK, self.server.uplv.hidden_check_report(self._read_json()))
                except (ValueError, TypeError, KeyError) as exc:
                    self._json(HTTPStatus.BAD_REQUEST, {'ok': False, 'error': str(exc)})
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
                    self._json(HTTPStatus.OK, {
                        "ok": True,
                        "valid": True,
                        "is_admin": True,
                        "preview": _preview_key(tok),
                        "max_accounts_per_job": _max_accounts_per_job(self.server.store),
                        "max_vvip_accounts_per_job": _max_vvip_accounts_per_job(self.server.store),
                        "info": {"mode": "master_token"},
                    })
                    return
                ok, info = _verify_license_key(tok)
                if ok:
                    self._json(HTTPStatus.OK, {
                        "ok": True,
                        "valid": True,
                        "is_admin": False,
                        "preview": _preview_key(tok),
                        "max_accounts_per_job": _max_accounts_per_job(self.server.store),
                        "max_vvip_accounts_per_job": _max_vvip_accounts_per_job(self.server.store),
                        "info": info,
                    })
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

    def _handle_admin_settings_get(self) -> None:
        store = self.server.store
        targets_text = _setting(store, "satellite_targets", DEFAULT_SATELLITE_TARGETS)
        vvip_targets_text = _setting(store, "vvip_satellite_targets", DEFAULT_VVIP_SATELLITE_TARGETS)
        max_running_jobs = _max_running_jobs(store)
        min_accounts_per_job = _min_accounts_per_job(store)
        max_accounts_per_job = _max_accounts_per_job(store)
        max_vvip_running_jobs = _max_vvip_running_jobs(store)
        min_vvip_accounts_per_job = _min_vvip_accounts_per_job(store)
        max_vvip_accounts_per_job = _max_vvip_accounts_per_job(store)
        running_jobs = _running_job_count(store, "normal")
        vvip_running_jobs = _running_job_count(store, "vvip")
        n_payload = _notice_payload(store, self.server.kientuong_status())
        self._json(HTTPStatus.OK, {
            "ok": True,
            "notice": n_payload,
            "modal_notice": n_payload["modal_notice"],
            "satellite_targets": targets_text,
            "satellite_count": len(parse_satellite_targets(targets_text)),
            "vvip_satellite_targets": vvip_targets_text,
            "vvip_satellite_count": len(parse_satellite_targets(vvip_targets_text)),
            "max_running_jobs": max_running_jobs,
            "min_accounts_per_job": min_accounts_per_job,
            "max_accounts_per_job": max_accounts_per_job,
            "running_jobs": running_jobs,
            "available_job_slots": max(0, max_running_jobs - running_jobs),
            "max_vvip_running_jobs": max_vvip_running_jobs,
            "min_vvip_accounts_per_job": min_vvip_accounts_per_job,
            "max_vvip_accounts_per_job": max_vvip_accounts_per_job,
            "vvip_running_jobs": vvip_running_jobs,
            "vvip_available_job_slots": max(0, max_vvip_running_jobs - vvip_running_jobs),
        })

    def _handle_admin_settings_save(self) -> None:
        body = self._read_json()
        if not isinstance(body, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "JSON phải là object"})
            return
        notice = body.get("notice")
        modal_notice = body.get("modal_notice")
        targets_value = body.get("satellite_targets")
        vvip_targets_value = body.get("vvip_satellite_targets")
        max_running_value = body.get("max_running_jobs")
        min_accounts_value = body.get("min_accounts_per_job")
        max_accounts_value = body.get("max_accounts_per_job")
        max_vvip_running_value = body.get("max_vvip_running_jobs")
        min_vvip_accounts_value = body.get("min_vvip_accounts_per_job")
        max_vvip_accounts_value = body.get("max_vvip_accounts_per_job")
        values: dict[str, str] = {}
        if modal_notice is not None:
            if not isinstance(modal_notice, dict):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "modal_notice không hợp lệ"})
                return
            m_title = str(modal_notice.get("title") or "").strip()
            m_html = str(modal_notice.get("html") or "").strip()
            if len(m_title) > 200:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "tiêu đề modal tối đa 200 ký tự"})
                return
            if len(m_html) > 50000:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "HTML modal tối đa 50.000 ký tự"})
                return
            values.update({
                "modal_notice_enabled": "1" if bool(modal_notice.get("enabled")) else "0",
                "modal_notice_title": m_title or DEFAULT_MODAL_NOTICE_TITLE,
                "modal_notice_html": m_html or DEFAULT_MODAL_NOTICE_HTML,
            })
        if notice is not None:
            if not isinstance(notice, dict):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "notice không hợp lệ"})
                return
            if isinstance(notice.get("modal_notice"), dict):
                mn = notice["modal_notice"]
                values.update({
                    "modal_notice_enabled": "1" if bool(mn.get("enabled")) else "0",
                    "modal_notice_title": str(mn.get("title") or "").strip() or DEFAULT_MODAL_NOTICE_TITLE,
                    "modal_notice_html": str(mn.get("html") or "").strip() or DEFAULT_MODAL_NOTICE_HTML,
                })
            elif "modal_notice_enabled" in notice:
                values["modal_notice_enabled"] = "1" if bool(notice.get("modal_notice_enabled")) else "0"
            if "html" in notice or "css" in notice:
                notice_html = str(notice.get("html") or "").strip()
                notice_css = str(notice.get("css") or "").strip()
                if not notice_html or len(notice_html) > 20000:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "HTML thông báo cần 1-20.000 ký tự"})
                    return
                if len(notice_css) > 20000:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "CSS thông báo tối đa 20.000 ký tự"})
                    return
                values.update({
                    "notice_enabled": "1" if bool(notice.get("enabled", True)) else "0",
                    "notice_html": notice_html,
                    "notice_css": notice_css,
                })
            else:
                # Giữ tương thích với giao diện/API cũ trong lúc các bản deploy chuyển tiếp.
                title = str(notice.get("title") or "").strip()
                content = str(notice.get("body") or "").strip()
                if not title or len(title) > 200:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "tiêu đề thông báo cần 1-200 ký tự"})
                    return
                if not content or len(content) > 5000:
                    self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "nội dung thông báo cần 1-5000 ký tự"})
                    return
                values.update({
                    "notice_enabled": "1" if bool(notice.get("enabled", True)) else "0",
                    "notice_title": title,
                    "notice_body": content,
                })
        if targets_value is not None:
            targets_text = str(targets_value).strip()
            targets = parse_satellite_targets(targets_text)
            if targets_text and not targets:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "không tìm thấy URL http/https hợp lệ"})
                return
            normalized = "\n".join(f"[{target['label']}] {target['url']}" for target in targets)
            values["satellite_targets"] = normalized + ("\n" if normalized else "")
        if vvip_targets_value is not None:
            targets_text = str(vvip_targets_value).strip()
            targets = parse_satellite_targets(targets_text)
            if targets_text and not targets:
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "không tìm thấy URL VVIP http/https hợp lệ"})
                return
            normalized = "\n".join(f"[{target['label']}] {target['url']}" for target in targets)
            values["vvip_satellite_targets"] = normalized + ("\n" if normalized else "")
        if max_running_value is not None:
            try:
                if isinstance(max_running_value, bool):
                    raise ValueError
                if isinstance(max_running_value, float) and not max_running_value.is_integer():
                    raise ValueError
                max_running_jobs = int(max_running_value)
            except (TypeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "giới hạn job phải là số nguyên"})
                return
            if not 1 <= max_running_jobs <= MAX_CONFIGURED_RUNNING_JOBS:
                self._json(HTTPStatus.BAD_REQUEST, {
                    "ok": False,
                    "error": f"giới hạn job phải từ 1 đến {MAX_CONFIGURED_RUNNING_JOBS:,}",
                })
                return
            values["max_running_jobs"] = str(max_running_jobs)
        if min_accounts_value is not None:
            try:
                if isinstance(min_accounts_value, bool):
                    raise ValueError
                if isinstance(min_accounts_value, float) and not min_accounts_value.is_integer():
                    raise ValueError
                min_accounts_per_job = int(min_accounts_value)
            except (TypeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "số tài khoản tối thiểu/job phải là số nguyên"})
                return
            if not 1 <= min_accounts_per_job <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
                self._json(HTTPStatus.BAD_REQUEST, {
                    "ok": False,
                    "error": f"số tài khoản tối thiểu/job phải từ 1 đến {MAX_CONFIGURED_ACCOUNTS_PER_JOB:,}",
                })
                return
            values["min_accounts_per_job"] = str(min_accounts_per_job)
        if max_accounts_value is not None:
            try:
                if isinstance(max_accounts_value, bool):
                    raise ValueError
                if isinstance(max_accounts_value, float) and not max_accounts_value.is_integer():
                    raise ValueError
                max_accounts_per_job = int(max_accounts_value)
            except (TypeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "giới hạn tài khoản/job phải là số nguyên"})
                return
            if not 1 <= max_accounts_per_job <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
                self._json(HTTPStatus.BAD_REQUEST, {
                    "ok": False,
                    "error": f"giới hạn tài khoản/job phải từ 1 đến {MAX_CONFIGURED_ACCOUNTS_PER_JOB:,}",
                })
                return
            values["max_accounts_per_job"] = str(max_accounts_per_job)
        if max_vvip_running_value is not None:
            try:
                if isinstance(max_vvip_running_value, bool):
                    raise ValueError
                if isinstance(max_vvip_running_value, float) and not max_vvip_running_value.is_integer():
                    raise ValueError
                max_vvip_running_jobs = int(max_vvip_running_value)
            except (TypeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "giới hạn job VVIP phải là số nguyên"})
                return
            if not 1 <= max_vvip_running_jobs <= MAX_CONFIGURED_RUNNING_JOBS:
                self._json(HTTPStatus.BAD_REQUEST, {
                    "ok": False,
                    "error": f"giới hạn job VVIP phải từ 1 đến {MAX_CONFIGURED_RUNNING_JOBS:,}",
                })
                return
            values["max_vvip_running_jobs"] = str(max_vvip_running_jobs)
        if min_vvip_accounts_value is not None:
            try:
                if isinstance(min_vvip_accounts_value, bool):
                    raise ValueError
                if isinstance(min_vvip_accounts_value, float) and not min_vvip_accounts_value.is_integer():
                    raise ValueError
                min_vvip_accounts_per_job = int(min_vvip_accounts_value)
            except (TypeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "số tài khoản tối thiểu/job VVIP phải là số nguyên"})
                return
            if not 1 <= min_vvip_accounts_per_job <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
                self._json(HTTPStatus.BAD_REQUEST, {
                    "ok": False,
                    "error": f"số tài khoản tối thiểu/job VVIP phải từ 1 đến {MAX_CONFIGURED_ACCOUNTS_PER_JOB:,}",
                })
                return
            values["min_vvip_accounts_per_job"] = str(min_vvip_accounts_per_job)
        if max_vvip_accounts_value is not None:
            try:
                if isinstance(max_vvip_accounts_value, bool):
                    raise ValueError
                if isinstance(max_vvip_accounts_value, float) and not max_vvip_accounts_value.is_integer():
                    raise ValueError
                max_vvip_accounts_per_job = int(max_vvip_accounts_value)
            except (TypeError, ValueError):
                self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "giới hạn tài khoản/job VVIP phải là số nguyên"})
                return
            if not 1 <= max_vvip_accounts_per_job <= MAX_CONFIGURED_ACCOUNTS_PER_JOB:
                self._json(HTTPStatus.BAD_REQUEST, {
                    "ok": False,
                    "error": f"giới hạn tài khoản/job VVIP phải từ 1 đến {MAX_CONFIGURED_ACCOUNTS_PER_JOB:,}",
                })
                return
            values["max_vvip_accounts_per_job"] = str(max_vvip_accounts_per_job)
        effective_min = int(values.get("min_accounts_per_job", _min_accounts_per_job(self.server.store)))
        effective_max = int(values.get("max_accounts_per_job", _max_accounts_per_job(self.server.store)))
        if effective_min > effective_max:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "số tài khoản tối thiểu/job thường không được lớn hơn số tối đa"})
            return
        effective_vvip_min = int(values.get("min_vvip_accounts_per_job", _min_vvip_accounts_per_job(self.server.store)))
        effective_vvip_max = int(values.get("max_vvip_accounts_per_job", _max_vvip_accounts_per_job(self.server.store)))
        if effective_vvip_min > effective_vvip_max:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "số tài khoản tối thiểu/job VVIP không được lớn hơn số tối đa"})
            return
        if not values:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "không có cấu hình để lưu"})
            return
        _save_settings(self.server.store, values)
        self._json(HTTPStatus.OK, {"ok": True, "saved": list(values)})

    def _handle_satellite_health(self) -> None:
        body = self._read_json()
        if not isinstance(body, dict):
            body = {}
        targets_text = str(body.get("satellite_targets") or "").strip()
        if not targets_text:
            targets_text = _setting(self.server.store, "satellite_targets", DEFAULT_SATELLITE_TARGETS)
        vvip_targets_text = str(body.get("vvip_satellite_targets") or "").strip()
        if not vvip_targets_text:
            vvip_targets_text = _setting(self.server.store, "vvip_satellite_targets", DEFAULT_VVIP_SATELLITE_TARGETS)
        targets = [
            {**target, "expected_service_type": "normal"}
            for target in parse_satellite_targets(targets_text)
        ] + [
            {**target, "expected_service_type": "vvip"}
            for target in parse_satellite_targets(vvip_targets_text)
        ]
        indexed_results: dict[int, dict[str, Any]] = {}
        if targets:
            with ThreadPoolExecutor(max_workers=min(12, len(targets))) as pool:
                futures = {pool.submit(fetch_satellite_health, target): index for index, target in enumerate(targets)}
                for future in as_completed(futures):
                    index = futures[future]
                    try:
                        indexed_results[index] = future.result()
                    except Exception as exc:
                        indexed_results[index] = {**targets[index], "online": False, "health": {}, "error": str(exc)[:300]}
        results = [indexed_results[index] for index in range(len(targets))]
        def active_chunks(item: dict[str, Any]) -> int:
            try:
                return max(0, int((item.get("health") or {}).get("chunks_active") or 0))
            except (TypeError, ValueError):
                return 0

        self._json(HTTPStatus.OK, {
            "ok": True,
            "checked_at": _now(),
            "online": sum(1 for item in results if item.get("online")),
            "total": len(results),
            "normal_total": sum(1 for item in results if item.get("expected_service_type") == "normal"),
            "vvip_total": sum(1 for item in results if item.get("expected_service_type") == "vvip"),
            "normal_online": sum(1 for item in results if item.get("online") and item.get("expected_service_type") == "normal"),
            "vvip_online": sum(1 for item in results if item.get("online") and item.get("expected_service_type") == "vvip"),
            "normal_active": sum(active_chunks(item) for item in results if item.get("expected_service_type") == "normal"),
            "vvip_active": sum(active_chunks(item) for item in results if item.get("expected_service_type") == "vvip"),
            "satellites": results,
        })

    def _handle_satellite_restart(self) -> None:
        body = self._read_json()
        if not isinstance(body, dict):
            body = {}
        requested_url = str(body.get("url") or "").strip().rstrip("/")
        if not requested_url:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Thiếu URL vệ tinh"})
            return
        configured_targets = [
            {**target, "expected_service_type": "normal"}
            for target in parse_satellite_targets(_setting(self.server.store, "satellite_targets", DEFAULT_SATELLITE_TARGETS))
        ] + [
            {**target, "expected_service_type": "vvip"}
            for target in parse_satellite_targets(_setting(self.server.store, "vvip_satellite_targets", DEFAULT_VVIP_SATELLITE_TARGETS))
        ]
        target = next((item for item in configured_targets if item["url"].rstrip("/").lower() == requested_url.lower()), None)
        if target is None:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "VPS chưa có trong danh sách đã lưu"})
            return
        control_token = os.environ.get("SATELLITE_CONTROL_TOKEN", "").strip() or (self.server.master_token or "").strip()
        if not control_token:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": "Chưa cấu hình token điều khiển vệ tinh"})
            return
        try:
            result = restart_satellite(target, control_token)
        except RuntimeError as exc:
            self._json(HTTPStatus.BAD_GATEWAY, {"ok": False, "error": str(exc)[:300]})
            return
        self._json(HTTPStatus.ACCEPTED, {
            "ok": True,
            "message": f"Đã gửi lệnh restart tới {target['label']}",
            "satellite": target,
            "control": result,
        })

    def _handle_satellites_restart_all(self) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        if not isinstance(body, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Dữ liệu không hợp lệ"})
            return
        configured_targets = [
            {**target, "expected_service_type": "normal"}
            for target in parse_satellite_targets(_setting(self.server.store, "satellite_targets", DEFAULT_SATELLITE_TARGETS))
        ] + [
            {**target, "expected_service_type": "vvip"}
            for target in parse_satellite_targets(_setting(self.server.store, "vvip_satellite_targets", DEFAULT_VVIP_SATELLITE_TARGETS))
        ]
        targets: list[dict[str, str]] = []
        seen_urls: set[str] = set()
        for target in configured_targets:
            normalized = target["url"].rstrip("/").lower()
            if normalized in seen_urls:
                continue
            seen_urls.add(normalized)
            targets.append(target)
        if not targets:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Danh sách VPS đang trống"})
            return
        control_token = os.environ.get("SATELLITE_CONTROL_TOKEN", "").strip() or (self.server.master_token or "").strip()
        if not control_token:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "error": "Chưa cấu hình token điều khiển vệ tinh"})
            return
        results: list[dict[str, Any] | None] = [None] * len(targets)
        with ThreadPoolExecutor(max_workers=min(12, len(targets))) as pool:
            futures = {pool.submit(restart_satellite, target, control_token): index for index, target in enumerate(targets)}
            for future in as_completed(futures):
                index = futures[future]
                target = targets[index]
                try:
                    result = future.result()
                    results[index] = {**target, "ok": True, "control": result}
                except Exception as exc:
                    results[index] = {**target, "ok": False, "error": str(exc)[:300]}
        completed = [result for result in results if result is not None]
        succeeded = sum(1 for result in completed if result.get("ok"))
        failed = len(completed) - succeeded
        self._json(HTTPStatus.ACCEPTED, {
            "ok": True,
            "message": f"Đã gửi lệnh restart tới {succeeded}/{len(targets)} service",
            "total": len(targets),
            "succeeded": succeeded,
            "failed": failed,
            "results": completed,
        })

    def _handle_clear_all_data(self) -> None:
        """Xóa toàn bộ dữ liệu điều phối; chỉ MASTER_TOKEN mới được phép gọi."""
        master_token = self.server.master_token or ""
        auth = self._get_auth_info()
        if not master_token or not auth.get("is_admin"):
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "chỉ MASTER_TOKEN mới được xóa toàn bộ dữ liệu"})
            return

        store = self.server.store
        unsettled = store.fetchone(
            "SELECT COUNT(*) FROM jobs WHERE billing_state IN ('reserved','settlement_pending')"
        )
        if int(unsettled[0] if unsettled else 0) > 0:
            self._json(HTTPStatus.CONFLICT, {
                "ok": False,
                "code": "UNSETTLED_BILLING_EXISTS",
                "error": "Không thể xóa dữ liệu khi còn job chưa quyết toán với SP1S.",
                "unsettled_jobs": int(unsettled[0]),
            })
            return
        totals = store.fetchone(
            "SELECT COUNT(*), COALESCE(SUM(pending_chunks+claimed_chunks+done_chunks),0), "
            "COALESCE(SUM(result_count),0) FROM job_stats"
        )
        try:
            # Xóa bảng con trước để dùng được với cả SQLite lẫn Turso.
            store.batch([
                {"sql": "DELETE FROM billing_outbox"},
                {"sql": "DELETE FROM job_stats"},
                {"sql": "DELETE FROM job_result_stats"},
                {"sql": "DELETE FROM invalid_usernames"},
                {"sql": "DELETE FROM junk_accounts"},
                {"sql": "DELETE FROM results"},
                {"sql": "DELETE FROM chunks"},
                {"sql": "DELETE FROM jobs"},
            ])
        except Exception as exc:
            print(f"[master] clear all data error: {exc}", flush=True)
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"không thể xóa dữ liệu: {exc}"[:300]})
            return
        self._json(HTTPStatus.OK, {
            "ok": True,
            "jobs": int(totals[0] if totals else 0),
            "chunks": int(totals[1] if totals else 0),
            "results": int(totals[2] if totals else 0),
        })

    def _handle_prune_before_today(self) -> None:
        """Queue bounded cleanup and return immediately instead of blocking the DB."""
        master_token = self.server.master_token or ""
        auth = self._get_auth_info()
        if not master_token or not auth.get("is_admin"):
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "chỉ MASTER_TOKEN mới được phép dọn dữ liệu cũ"})
            return

        tz_info = _master_tzinfo()
        cutoff = _today_start_timestamp()
        started = self.server.schedule_retention_cleanup(cutoff)
        self._json(HTTPStatus.ACCEPTED, {
            "ok": True,
            "accepted": True,
            "started": started,
            "timezone": MASTER_TIMEZONE,
            "cutoff": cutoff,
            "cutoff_local": datetime.fromtimestamp(cutoff, tz_info).strftime("%Y-%m-%d 00:00:00 %Z"),
            "cleanup": self.server.retention_cleanup_status(),
        })

    def _handle_jobs_list(self, auth: dict[str, Any] | None = None) -> None:
        store = self.server.store
        owner_hash = (auth or {}).get("owner_hash", "") if auth else ""
        owner_user_id = int((auth or {}).get("user_id") or 0)
        is_admin = bool((auth or {}).get("is_admin"))
        # Phần tổng quan luôn phản ánh toàn hệ thống để mọi key đều biết tải hiện tại.
        # Danh sách/chi tiết job bên dưới vẫn giới hạn theo owner để không lộ dữ liệu.
        # The overview scans one compact row per job, never the account results.
        overview_row = store.fetchone(
            "SELECT COUNT(*), "
            "SUM(CASE WHEN job_status IN ('creating','open','stopping') THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN job_status='done' THEN 1 ELSE 0 END), "
            "SUM(total_accounts), SUM(result_count), "
            "SUM(CASE "
            "WHEN job_status IN ('creating','open','stopping') AND total_accounts>result_count "
            "THEN total_accounts-result_count ELSE 0 END), "
            "SUM(CASE WHEN job_status IN ('creating','open','stopping') "
            "AND COALESCE(j.queue_type,'normal')='normal' THEN 1 ELSE 0 END), "
            "SUM(CASE WHEN job_status IN ('creating','open','stopping') "
            "AND j.queue_type='vvip' THEN 1 ELSE 0 END) "
            "FROM job_stats s JOIN jobs j ON j.id=s.job_id"
        )
        overview = {
            "total_jobs": int((overview_row[0] if overview_row else 0) or 0),
            "running_jobs": int((overview_row[1] if overview_row else 0) or 0),
            "done_jobs": int((overview_row[2] if overview_row else 0) or 0),
            "total_accounts": int((overview_row[3] if overview_row else 0) or 0),
            "processed_accounts": int((overview_row[4] if overview_row else 0) or 0),
            "pending_accounts": int((overview_row[5] if overview_row else 0) or 0),
            "normal_running_jobs": int((overview_row[6] if overview_row else 0) or 0),
            "vvip_running_jobs": int((overview_row[7] if overview_row else 0) or 0),
        }
        select_sql = (
            "SELECT j.id,j.created_at,j.total,j.chunk_size,j.status,j.finished_at,j.owner_preview,"
            "COALESCE(s.result_count,0),COALESCE(s.ok_count,0),COALESCE(s.fail_count,0),"
            "COALESCE(s.uncheckable_count,0),j.billing_mode,j.billing_state,j.estimated_amount_tenths,"
            "j.final_amount_tenths,j.access_until,j.billing_order_id,j.owner_email,j.queue_type "
            "FROM jobs j LEFT JOIN job_stats s ON s.job_id=j.id "
        )
        if is_admin:
            jobs_raw = store.fetch(
                select_sql + "ORDER BY j.id DESC LIMIT 50"
            )
        elif owner_user_id:
            jobs_raw = store.fetch(
                select_sql + "WHERE j.owner_user_id=? ORDER BY j.id DESC LIMIT 50",
                (owner_user_id,),
            )
        elif owner_hash:
            jobs_raw = store.fetch(
                select_sql + "WHERE j.owner_hash=? ORDER BY j.id DESC LIMIT 50",
                (owner_hash,),
            )
        else:
            jobs_raw = []
        jobs = []
        for row in jobs_raw:
            job_id = row[0]
            jobs.append({
                "id": job_id,
                "created_at": row[1],
                "finished_at": row[5],
                "total": row[2],
                "status": row[4],
                "processed": int(row[7] or 0),
                "ok": int(row[8] or 0),
                "fail": int(row[9] or 0),
                "uncheckable": int(row[10] or 0),
                "owner_preview": row[17] or row[6] or "",
                "billing_mode": row[11] or "",
                "billing_state": row[12] or "none",
                "estimated_amount": _money_from_tenths(row[13]),
                "final_amount": _money_from_tenths(row[14]),
                "access_until": row[15],
                "billing_order_id": row[16],
                "queue_type": row[18] or "normal",
            })
        self._json(HTTPStatus.OK, {"ok": True, "jobs": jobs, "overview": overview})

    def _handle_billing_quote(self, auth: dict[str, Any]) -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        if not _aovshop_configured():
            self._json(HTTPStatus.OK, {"ok": True, "mode": "development", "amount": 0, "affordable": True})
            return
        if auth.get("is_admin"):
            self._json(HTTPStatus.OK, {"ok": True, "mode": "admin", "amount": 0, "affordable": True})
            return
        user_id = int(auth.get("user_id") or 0)
        mode = str(body.get("billing_mode") or body.get("mode") or "quantity").strip().lower()
        try:
            if mode == "quantity":
                source = body.get("text") if isinstance(body.get("text"), str) else ""
                if source.strip():
                    submitted = len(partition_accounts_for_job(parse_accounts(source))[0])
                    if submitted < 1:
                        raise ValueError("Không có USER hợp lệ để tính chi phí")
                else:
                    submitted = int(body.get("submitted_count") or 0)
                    if submitted < 1 or submitted > _max_accounts_per_job(self.server.store):
                        raise ValueError("Số lượng tài khoản không hợp lệ")
                payload = {"mode": "quantity", "user_id": user_id, "submitted_count": submitted}
            elif mode in {"time", "vvip"}:
                raw_blocks = body.get("block_count", 1)
                if isinstance(raw_blocks, bool) or not isinstance(raw_blocks, int):
                    raise ValueError("Số block phải là số nguyên")
                blocks = raw_blocks
                if not 1 <= blocks <= MAX_CHECKPASS_TIME_BLOCKS:
                    raise ValueError(f"Số block phải từ 1 đến {MAX_CHECKPASS_TIME_BLOCKS}")
                payload = {"mode": mode, "user_id": user_id, "block_count": blocks}
            else:
                raise ValueError("Chế độ thanh toán không hợp lệ")
            result = _aovshop_request("/api/integrations/checkpass/quote", payload)
            self._json(HTTPStatus.OK, {"ok": True, **result})
        except (TypeError, ValueError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
        except RuntimeError as exc:
            self._json(HTTPStatus(getattr(exc, "status", 503)), {"ok": False, "code": getattr(exc, "code", ""), "error": str(exc)})

    def _handle_create_job(self, auth: dict[str, Any] | None = None) -> None:
        maintenance = _maintenance_window()
        if maintenance.get("active"):
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                "ok": False,
                "code": "DAILY_MAINTENANCE",
                "error": maintenance["message"],
                "maintenance": maintenance,
            })
            return
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
        parsed, invalid_usernames, junk_accounts = partition_accounts_for_job(parsed)
        confirmed_filtered_accounts = (
            body.get("confirm_filtered_accounts") is True
            or body.get("confirm_invalid_usernames") is True
        )
        if (invalid_usernames or junk_accounts) and not confirmed_filtered_accounts:
            self._json(HTTPStatus.CONFLICT, {
                "ok": False,
                "code": "FILTERED_ACCOUNTS_REQUIRE_CONFIRMATION",
                "error": (
                    f"Phát hiện {len(invalid_usernames):,} USER không hợp lệ và "
                    f"{len(junk_accounts):,} dòng DATA rác. Nếu tiếp tục, các tài khoản "
                    "này sẽ bị loại khỏi lượt check."
                ),
                "valid_accounts": len(parsed),
                "invalid_accounts": len(invalid_usernames),
                "junk_accounts_count": len(junk_accounts),
                "invalid_usernames": [
                    {
                        "line_number": item.line_number,
                        "username": item.username,
                        "reason": item.reason,
                    }
                    for item in invalid_usernames[:100]
                ],
                "invalid_usernames_truncated": len(invalid_usernames) > 100,
                "junk_accounts": [
                    {
                        "line_number": item.line_number,
                        "username": item.username,
                        "reason": item.reason,
                    }
                    for item in junk_accounts[:100]
                ],
                "junk_accounts_truncated": len(junk_accounts) > 100,
            })
            return
        if not parsed:
            self._json(HTTPStatus.BAD_REQUEST, {
                "ok": False,
                "code": "NO_VALID_USERNAMES",
                "error": "Không còn tài khoản hợp lệ để tạo job sau khi lọc USER và DATA rác.",
                "invalid_accounts": len(invalid_usernames),
                "junk_accounts_count": len(junk_accounts),
            })
            return
        store = self.server.store
        is_admin = bool((auth or {}).get("is_admin"))
        # Resolve the queue before admission checks so normal and VVIP limits
        # remain completely independent. Admin defaults to the VVIP queue.
        default_billing_mode = "vvip" if is_admin else "quantity"
        billing_mode = str(body.get("billing_mode") or default_billing_mode).strip().lower()
        if billing_mode not in {"quantity", "time", "vvip"}:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "billing_mode phải là quantity, time hoặc vvip"})
            return
        requested_billing_mode = billing_mode
        queue_type = "vvip" if requested_billing_mode == "vvip" else "normal"
        max_accounts_per_job = (
            _max_vvip_accounts_per_job(store)
            if queue_type == "vvip"
            else _max_accounts_per_job(store)
        )
        min_accounts_per_job = (
            _min_vvip_accounts_per_job(store)
            if queue_type == "vvip"
            else _min_accounts_per_job(store)
        )
        if len(parsed) < min_accounts_per_job:
            self._json(HTTPStatus.BAD_REQUEST, {
                "ok": False,
                "code": "VVIP_ACCOUNT_MINIMUM_NOT_REACHED" if queue_type == "vvip" else "ACCOUNT_MINIMUM_NOT_REACHED",
                "error": (
                    f"Mỗi job {'VVIP ' if queue_type == 'vvip' else ''}cần tối thiểu {min_accounts_per_job:,} tài khoản. "
                    f"Danh sách hiện có {len(parsed):,} tài khoản."
                ),
                "submitted_accounts": len(parsed),
                "min_accounts_per_job": min_accounts_per_job,
                "queue_type": queue_type,
            })
            return
        account_limit_applies = queue_type == "vvip" or not is_admin
        if account_limit_applies and len(parsed) > max_accounts_per_job:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {
                "ok": False,
                "code": "VVIP_ACCOUNT_LIMIT_REACHED" if queue_type == "vvip" else "ACCOUNT_LIMIT_REACHED",
                "error": (
                    f"Mỗi job {'VVIP ' if queue_type == 'vvip' else ''}được gửi tối đa {max_accounts_per_job:,} tài khoản. "
                    f"Danh sách hiện có {len(parsed):,} tài khoản."
                ),
                "submitted_accounts": len(parsed),
                "max_accounts_per_job": max_accounts_per_job,
                "queue_type": queue_type,
            })
            return
        # Cố định 15 account/chunk; không nhận cấu hình từ client.
        chunk_size = DEFAULT_CHUNK_LIMIT
        chunks = split_chunks(parsed, chunk_size)
        chunk_payloads = [
            json.dumps(
                [acc.raw_line or f"{acc.account}|{acc.password}" for acc in chunk],
                ensure_ascii=False,
            )
            for chunk in chunks
        ]

        owner_hash = (auth or {}).get("owner_hash", "") if auth else ""
        auth_token = str((auth or {}).get("token") or "")
        if not owner_hash and auth_token:
            # Master Token cũng là một key và phải tuân theo giới hạn 1 job đang chạy/key.
            owner_hash = _hash_key(auth_token)
        owner_preview = (auth or {}).get("owner_preview", "") if auth else ""
        owner_user_id = int((auth or {}).get("user_id") or 0)
        owner_email = str((auth or {}).get("email") or "")
        owner_name = str((auth or {}).get("name") or "")
        block_count = 1
        raw_block_count = body.get("block_count", 1)
        if isinstance(raw_block_count, bool) or not isinstance(raw_block_count, int):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Số block không hợp lệ"})
            return
        block_count = raw_block_count
        if not 1 <= block_count <= MAX_CHECKPASS_TIME_BLOCKS:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": f"Số block phải từ 1 đến {MAX_CHECKPASS_TIME_BLOCKS}"})
            return
        external_reference = f"cp_{uuid.uuid4().hex}"
        billing_state = "none"
        unit_price_tenths = 0
        estimated_amount_tenths = 0
        hold_reference = ""
        entitlement_id: int | None = None
        access_until: float | None = None
        billing_result: dict[str, Any] = {}
        job_id = 0
        # Serialize admission and creation so simultaneous requests cannot all pass
        # the count check before any of them reserves a slot.
        with self.server.job_creation_lock:
            active_key_job = None
            if owner_user_id and not is_admin:
                active_key_job = store.fetchone(
                    "SELECT id FROM jobs WHERE owner_user_id=? AND status IN ('creating','open','stopping') ORDER BY id DESC LIMIT 1",
                    (owner_user_id,),
                )
            elif owner_hash and not is_admin:
                active_key_job = store.fetchone(
                    "SELECT id FROM jobs WHERE owner_hash=? AND status IN ('creating','open','stopping') ORDER BY id DESC LIMIT 1",
                    (owner_hash,),
                )
            if active_key_job is not None:
                limit_code = "USER_RUNNING_JOB_LIMIT_REACHED" if owner_user_id else "KEY_RUNNING_JOB_LIMIT_REACHED"
                self._json(HTTPStatus.CONFLICT, {
                    "ok": False,
                    "code": limit_code,
                    "error": "Mỗi tài khoản chỉ được có 1 job đang chạy. Vui lòng chờ job hiện tại hoàn tất hoặc dừng job đó trước.",
                    "active_job_id": int(active_key_job[0]),
                    "max_running_jobs_per_user": 1,
                })
                return
            max_running_jobs = (
                _max_vvip_running_jobs(store)
                if queue_type == "vvip"
                else _max_running_jobs(store)
            )
            running_jobs = _running_job_count(store, queue_type)
            if running_jobs >= max_running_jobs:
                self._json(HTTPStatus.TOO_MANY_REQUESTS, {
                    "ok": False,
                    "code": "VVIP_JOB_LIMIT_REACHED" if queue_type == "vvip" else "JOB_LIMIT_REACHED",
                    "error": (
                        f"Hàng đợi {'VVIP' if queue_type == 'vvip' else 'thường'} đang chạy tối đa {max_running_jobs} job. "
                        "Vui lòng chờ một job hoàn tất hoặc dừng bớt job rồi thử lại."
                    ),
                    "running_jobs": running_jobs,
                    "max_running_jobs": max_running_jobs,
                    "queue_type": queue_type,
                })
                return
            try:
                if _aovshop_configured() and not is_admin:
                    if owner_user_id <= 0:
                        raise RuntimeError("Phiên SP1S không có user_id hợp lệ")
                    if billing_mode == "quantity":
                        quote = _aovshop_request("/api/integrations/checkpass/quote", {
                            "mode": "quantity", "user_id": owner_user_id, "submitted_count": len(parsed),
                        })
                        if quote.get("entitlement") and body.get("confirm_quantity_while_timed") is not True:
                            self._json(HTTPStatus.CONFLICT, {
                                "ok": False,
                                "code": "TIME_ACCESS_ACTIVE",
                                "error": "Tài khoản đang có quyền chạy theo thời gian. Hãy chọn chế độ thời gian để tối ưu chi phí hoặc xác nhận vẫn chạy theo số lượng.",
                                "entitlement": quote.get("entitlement"),
                            })
                            return
                        billing_result = _aovshop_request("/api/integrations/checkpass/quantity/reserve", {
                            "user_id": owner_user_id,
                            "external_job_reference": external_reference,
                            "submitted_count": len(parsed),
                            "idempotency_key": f"reserve:{external_reference}",
                        })
                        billing_state = "reserved"
                        unit_price_tenths = 3
                        estimated_amount_tenths = int(
                            billing_result.get("estimated_amount_tenths")
                            if billing_result.get("estimated_amount_tenths") is not None
                            else round(float(billing_result.get("estimated_amount") or 0) * 10)
                        )
                        hold_reference = external_reference
                    else:
                        service_tier = "vvip" if billing_mode == "vvip" else "normal"
                        billing_result = _aovshop_request("/api/integrations/checkpass/time/activate", {
                            "user_id": owner_user_id,
                            "external_job_reference": external_reference,
                            "block_count": block_count,
                            "idempotency_key": f"time:{external_reference}",
                            "extend": False,
                            "service_tier": service_tier,
                        })
                        billing_state = "settled" if billing_result.get("charged") else "covered_by_time"
                        unit_price_tenths = VVIP_BLOCK_PRICE_TENTHS if service_tier == "vvip" else TIME_BLOCK_PRICE_TENTHS
                        estimated_amount_tenths = int(
                            billing_result.get("amount_tenths")
                            if billing_result.get("amount_tenths") is not None
                            else round(float(billing_result.get("amount") or 0) * 10)
                        )
                        entitlement = billing_result.get("entitlement") if isinstance(billing_result.get("entitlement"), dict) else {}
                        entitlement_id = int(entitlement.get("id") or 0) or None
                        expires_at = str(entitlement.get("expires_at") or "")
                        if not expires_at:
                            raise RuntimeError("SP1S không trả thời hạn quyền Checkpass")
                        access_until = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
                elif is_admin:
                    billing_mode = "admin"
                # Giữ job ở trạng thái trung gian cho tới khi toàn bộ chunk đã lưu.
                # Vệ tinh và _check_finish_all_jobs chỉ xử lý job "open".
                job_id = store.exec(
                    "INSERT INTO jobs (created_at,total,chunk_size,status,owner_hash,owner_preview,owner_user_id,owner_email,owner_name,billing_mode,queue_type,billing_state,external_job_reference,unit_price_tenths,estimated_amount_tenths,hold_reference,entitlement_id,access_until) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        _now(), len(parsed), chunk_size, "creating", owner_hash, owner_preview,
                        owner_user_id or None, owner_email, owner_name, billing_mode, queue_type, billing_state,
                        external_reference, unit_price_tenths, estimated_amount_tenths,
                        hold_reference, entitlement_id, access_until,
                    ),
                )
                if not job_id:
                    row = store.fetchone("SELECT MAX(id) FROM jobs")
                    if row and row[0]:
                        job_id = int(row[0])
                if not job_id:
                    raise RuntimeError("không lấy được job_id sau khi tạo")
                self.server._satellite_idle_since = None
                self.server._satellite_idle_restarted = False
                stmts = []
                for idx, accounts_json in enumerate(chunk_payloads):
                    stmts.append({
                        "sql": "INSERT INTO chunks (job_id, idx, account) VALUES (?,?,?)",
                        "args": [job_id, idx, accounts_json],
                    })
                for item in invalid_usernames:
                    stmts.append({
                        "sql": (
                            "INSERT INTO invalid_usernames "
                            "(job_id,line_number,username,raw_line,reason) VALUES (?,?,?,?,?)"
                        ),
                        "args": [job_id, item.line_number, item.username, item.raw_line, item.reason],
                    })
                for item in junk_accounts:
                    stmts.append({
                        "sql": (
                            "INSERT INTO junk_accounts "
                            "(job_id,line_number,username,raw_line,reason) VALUES (?,?,?,?,?)"
                        ),
                        "args": [job_id, item.line_number, item.username, item.raw_line, item.reason],
                    })
                # UPDATE cuối cùng nằm trong cùng batch/transaction với chunks.
                stmts.append({
                    "sql": "UPDATE jobs SET status='open' WHERE id=? AND status='creating'",
                    "args": [job_id],
                })
                store.batch(stmts)
            except Exception as exc:
                print(f"[master] Loi luu job vao DB: {exc}", flush=True)
                if job_id:
                    try:
                        store.batch([
                            {"sql": "DELETE FROM invalid_usernames WHERE job_id=?", "args": [job_id]},
                            {"sql": "DELETE FROM junk_accounts WHERE job_id=?", "args": [job_id]},
                            {"sql": "DELETE FROM chunks WHERE job_id=?", "args": [job_id]},
                            {"sql": "DELETE FROM jobs WHERE id=? AND status='creating'", "args": [job_id]},
                        ])
                    except Exception as cleanup_exc:
                        print(f"[master] Loi don job dang tao {job_id}: {cleanup_exc}", flush=True)
                # Release by reference even when the reserve response was lost:
                # SP1S may have committed the hold immediately before a timeout.
                if _aovshop_configured() and billing_mode == "quantity" and owner_user_id:
                    try:
                        _aovshop_request("/api/integrations/checkpass/quantity/release", {
                            "user_id": owner_user_id, "external_job_reference": external_reference,
                        })
                    except Exception as release_exc:
                        print(f"[master] failed to release hold {external_reference}: {release_exc}", flush=True)
                status = getattr(exc, "status", HTTPStatus.INTERNAL_SERVER_ERROR)
                self._json(HTTPStatus(status), {"ok": False, "code": getattr(exc, "code", ""), "error": str(exc)[:300]})
                return
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "total": len(parsed),
            "chunks": len(chunks),
            "chunk_size": chunk_size,
            "billing_mode": billing_mode,
            "queue_type": queue_type,
            "billing_state": billing_state,
            "estimated_amount": _money_from_tenths(estimated_amount_tenths),
            "access_until": access_until,
            "charged": bool(billing_result.get("charged")),
            "invalid_accounts": len(invalid_usernames),
            "junk_accounts_count": len(junk_accounts),
        })

    def _handle_stop_job(self, job_id: int, auth: dict[str, Any]) -> None:
        """Accept a stop immediately; finalize unfinished rows in background."""

        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền dừng job này"})
            return

        status = str(job[4] or "")
        store = self.server.store
        if status == "open":
            store.exec_with_changes(
                "UPDATE jobs SET status='stopping' WHERE id=? AND status='open'",
                (job_id,),
            )
            current = store.fetchone("SELECT status FROM jobs WHERE id=?", (job_id,))
            status = str(current[0] if current else "done")

        if status == "stopping":
            self.server.schedule_stop_finalization(
                job_id, self._finalize_unresolved_accounts
            )
            self._json(HTTPStatus.ACCEPTED, {
                "ok": True,
                "job_id": job_id,
                "status": "stopping",
                "accepted": True,
            })
            return

        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "status": status or "done",
            "already_stopped": True,
        })

    def _finalize_unresolved_accounts(self, job_id: int, now: float) -> int:
        """Persist a terminal result for accounts in chunks interrupted by Stop."""
        return _finalize_unresolved_job_accounts(self.server.store, job_id, now)

    def _handle_claim(self, queue_type: str = "normal") -> None:
        try:
            body = self._read_json()
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)})
            return
        satellite_id = str(body.get("satellite_id") or "")
        if not satellite_id:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "cần satellite_id"})
            return
        if queue_type == 'normal' and body.get('uplv_chunk_protocol'):
            hidden = self.server.uplv.hidden_check_claim(body)
            if hidden:
                self._json(HTTPStatus.OK, {'ok': True, 'claim': hidden})
                return
        try:
            lease_minutes = float(body.get("lease_minutes", DEFAULT_LEASE_MINUTES))
        except (TypeError, ValueError):
            lease_minutes = DEFAULT_LEASE_MINUTES
        lease_minutes = min(max(lease_minutes, 1), MAX_SATELLITE_LEASE_MINUTES)

        store = self.server.store
        now = _now()
        claim_payload: dict[str, Any] | None = None
        # Serialize the short select/update section so simultaneous pull requests
        # see the active-count change before choosing their job.  The conditional
        # UPDATE remains as protection when multiple master processes share a DB.
        with self.server.claim_lock:
            for _ in range(3):
                row = select_fair_claim_candidate(store, now, satellite_id, queue_type)
                if row is None:
                    row = select_fair_claim_candidate(
                        store, now, satellite_id, queue_type, allow_overflow=True
                    )
                if row is None:
                    break
                chunk_id, job_id, account_data = row
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
                    chk = store.fetchone("SELECT satellite_id FROM chunks WHERE id=?", (chunk_id,))
                    changed = 1 if (chk and chk[0] == satellite_id) else 0
                if changed == 0:
                    continue
                try:
                    accounts = json.loads(account_data)
                except (json.JSONDecodeError, TypeError):
                    accounts = [account_data] if account_data else []
                claim_payload = {
                    "chunk_id": chunk_id,
                    "job_id": job_id,
                    "queue_type": queue_type,
                    "lease_until": now + lease_minutes * 60,
                    "accounts": accounts,
                }
                break

        if claim_payload is None and self.server.should_run_idle_finish_check():
            # Vệ tinh rảnh poll liên tục; report cuối đã tự chốt job nên ở đây
            # chỉ cần quét dự phòng theo nhịp thay vì mỗi lần claim rỗng.
            self._check_finish_all_jobs(now)
        self._json(HTTPStatus.OK, {"ok": True, "claim": claim_payload})

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
        stopped_rows = self.server.store.fetch(
            f"SELECT c.id FROM chunks c JOIN jobs j ON j.id=c.job_id "
            f"WHERE c.satellite_id=? AND c.id IN ({placeholders}) AND j.status!='open'",
            (satellite_id, *valid_ids),
        )
        self._json(HTTPStatus.OK, {
            "ok": True,
            "renewed": changed,
            "stopped_chunk_ids": [int(row[0]) for row in stopped_rows],
        })

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
        if job_state and job_state[0] != "open":
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
                "args": [
                    chunk_id,
                    job_id,
                    _result_storage_key(account, row),
                    json.dumps(row, ensure_ascii=False),
                    now,
                ],
            })
        if is_done:
            stmts.append({
                "sql": "UPDATE chunks SET status='done', reported_at=? WHERE id=?",
                "args": [now, chunk_id],
            })
        if stmts:
            store.batch(stmts)
        # A timeout/network failure is not a final result until three different
        # allocation rounds have had a chance to check it.  On rounds 1 and 2
        # take only those accounts back out of this chunk's interim results and
        # create a fresh pending chunk.  `avoid_satellite_id` makes the worker
        # that just failed ineligible for that next allocation.
        requeued = 0
        retry_round = int(chunk[4] or 1) if len(chunk) > 4 else 1
        if is_done and chunk[1] != "done" and retry_round < MAX_ACCOUNT_RETRY_ROUNDS:
            requeued = self._requeue_uncheckable_rows(
                chunk_id=chunk_id,
                job_id=int(job_id),
                account_data=str(chunk[2] or ""),
                retry_round=retry_round,
                avoid_satellite_id=str(chunk[3] or ""),
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

    def _requeue_uncheckable_rows(
        self,
        *,
        chunk_id: int,
        job_id: int,
        account_data: str,
        retry_round: int,
        avoid_satellite_id: str,
    ) -> int:
        # Keep MAX(idx)+1 and the insert/delete batch in one write critical
        # section. Concurrent final reports otherwise allocate the same idx.
        lock = getattr(self.server.store, "_write_lock", None)
        with lock if lock is not None else contextlib.nullcontext():
            return self._requeue_uncheckable_rows_locked(
                chunk_id=chunk_id, job_id=job_id, account_data=account_data,
                retry_round=retry_round, avoid_satellite_id=avoid_satellite_id,
            )

    def _requeue_uncheckable_rows_locked(
        self,
        *,
        chunk_id: int,
        job_id: int,
        account_data: str,
        retry_round: int,
        avoid_satellite_id: str,
    ) -> int:
        """Move non-final rows into the next allocation round.

        Results are streamed while a chunk runs, so this deliberately reads the
        persisted rows after its final report rather than trusting only that
        final report's payload.
        """
        store = self.server.store
        try:
            source_accounts = json.loads(account_data)
        except (TypeError, json.JSONDecodeError):
            source_accounts = []
        if not isinstance(source_accounts, list):
            return 0

        retry_credentials: list[str] = []
        retry_accounts: list[str] = []
        for account, row_json in store.fetch(
            "SELECT account, row_json FROM results WHERE chunk_id=? ORDER BY id", (chunk_id,)
        ):
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
            if not 0 <= source_index < len(source_accounts):
                print(f"[master] chunk {chunk_id}: không map được acc retry {account!r}", flush=True)
                continue
            retry_credentials.append(str(source_accounts[source_index]))
            retry_accounts.append(str(account))
        if not retry_credentials:
            return 0

        # The original temporary outcome must not enter UI/export totals.  The
        # new chunk retains the credentials only in the coordinator database.
        next_idx_row = store.fetchone("SELECT COALESCE(MAX(idx), -1) + 1 FROM chunks WHERE job_id=?", (job_id,))
        next_idx = int(next_idx_row[0]) if next_idx_row else 0
        statements = [{
            "sql": "INSERT INTO chunks (job_id, idx, account, retry_round, avoid_satellite_id) VALUES (?,?,?,?,?)",
            "args": [job_id, next_idx, json.dumps(retry_credentials, ensure_ascii=False), retry_round + 1, avoid_satellite_id],
        }]
        statements.extend(
            {
                "sql": "DELETE FROM results WHERE chunk_id=? AND account=?",
                "args": [chunk_id, account],
            }
            for account in retry_accounts
        )
        store.batch(statements)
        print(
            f"[master] chunk {chunk_id}: phân lại {len(retry_credentials)} acc chưa thể check "
            f"sang vòng {retry_round + 1}; tránh vệ tinh {avoid_satellite_id or 'vừa chạy'}",
            flush=True,
        )
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
        open_jobs = store.fetch(
            "SELECT job_id, pending_chunks+claimed_chunks+done_chunks AS total_chunks, "
            "pending_chunks+claimed_chunks AS unfinished_chunks "
            "FROM job_stats WHERE job_status='open'"
        )
        finished_any = False
        for item in open_jobs:
            job_id = item[0]
            total_chunks = int(item[1] or 0)
            unfinished_chunks = int(item[2] or 0)
            # Job không có chunk là job chưa tạo xong/lỗi; tuyệt đối không tự đánh done.
            if total_chunks > 0 and unfinished_chunks == 0:
                store.exec(
                    "UPDATE jobs SET status='done', finished_at=? WHERE id=? AND status='open'",
                    (now, job_id),
                )
                self.server.schedule_billing(int(job_id))
                finished_any = True
        if finished_any:
            self.server.schedule_retention_cleanup()

    @staticmethod
    def _is_job_access_allowed(job: tuple, auth: dict[str, Any] | None) -> bool:
        """Check access for a job row that has already been fetched."""
        job_owner = job[6] or ""
        job_user_id = int(job[8] or 0) if len(job) > 8 else 0
        auth_owner = (auth or {}).get("owner_hash", "") if auth else ""
        auth_user_id = int((auth or {}).get("user_id") or 0)
        is_admin = bool((auth or {}).get("is_admin"))
        if is_admin:
            return True
        if auth_user_id:
            return bool(job_user_id and job_user_id == auth_user_id)
        if job_owner == auth_owner:
            return True
        return False

    def _check_job_access(self, job_id: int, auth: dict[str, Any] | None) -> tuple[bool, tuple | None]:
        """Kiểm tra job có thuộc owner không. Trả về (allowed, job_row). Admin được xem tất cả."""
        store = self.server.store
        job = store.fetchone(
            "SELECT id,created_at,total,chunk_size,status,finished_at,owner_hash,owner_preview,owner_user_id FROM jobs WHERE id=?",
            (job_id,),
        )
        if job is None:
            return False, None
        return self._is_job_access_allowed(job, auth), job

    def _handle_job_summary(self, job_id: int, auth: dict[str, Any] | None = None) -> None:
        store = self.server.store
        # Read only the per-job aggregate row; this remains constant-time even
        # when the job has millions of result records.
        summary = store.fetchone(
            "SELECT j.id, j.created_at, j.total, j.chunk_size, j.status, j.finished_at, "
            "j.owner_hash,j.owner_preview,j.owner_user_id, "
            "COALESCE(s.pending_chunks,0), COALESCE(s.claimed_chunks,0), COALESCE(s.done_chunks,0), "
            "COALESCE(s.result_count,0), COALESCE(s.ok_count,0), "
            "COALESCE(s.fail_count,0),COALESCE(s.uncheckable_count,0),"
            "j.billing_mode,j.billing_state,j.estimated_amount_tenths,j.final_amount_tenths,"
            "j.access_until,j.billing_order_id,j.owner_email,j.queue_type,"
            "(SELECT COUNT(*) FROM invalid_usernames iu WHERE iu.job_id=j.id),"
            "(SELECT COUNT(*) FROM junk_accounts ja WHERE ja.job_id=j.id) "
            "FROM jobs j LEFT JOIN job_stats s ON s.job_id=j.id WHERE j.id=?",
            (job_id,),
        )
        if summary is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        job = summary[:9]
        if not self._is_job_access_allowed(job, auth):
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền xem job này (key khác)"})
            return
        pending, claimed, done = summary[9:12]
        results_count, ok_count, fail_count, uncheckable_count = summary[12:16]
        invalid_count = int(summary[24] or 0)
        junk_count = int(summary[25] or 0)
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "created_at": job[1],
            "total": job[2],
            "chunk_size": job[3],
            "status": job[4],
            "finished_at": job[5],
            "owner_preview": job[7] if len(job) > 7 else "",
            "billing_mode": summary[16] or "",
            "billing_state": summary[17] or "none",
            "estimated_amount": _money_from_tenths(summary[18]),
            "final_amount": _money_from_tenths(summary[19]),
            "access_until": summary[20],
            "billing_order_id": summary[21],
            "owner_email": summary[22] or "",
            "queue_type": summary[23] or "normal",
            "chunks": {"pending": pending, "claimed": claimed, "done": done},
            "results": {
                "count": results_count,
                "ok": ok_count,
                "fail": fail_count,
                "uncheckable": uncheckable_count,
                "invalid": invalid_count,
                "junk": junk_count,
            },
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
        try:
            min_level = max(1, min(1000, int(query.get("min_level", ["12"])[0])))
        except (TypeError, ValueError):
            min_level = 12
        result_filter = str(query.get("filter", ["all"])[0] or "all").upper()
        if result_filter not in {
            "ALL", "OK", "NOT_MET", "CTNV", "GRANT_ERROR", "LOCKED", "FAIL", "PENDING", "INVALID", "JUNK",
        }:
            result_filter = "ALL"

        # Giới hạn kích thước trang để một request chi tiết không tải quá nhiều dữ liệu.
        per_page = max(1, min(per_page, 100))

        status_sql = "COALESCE(json_extract(row_json,'$.status'),'')"
        result_type_sql = "LOWER(COALESCE(json_extract(row_json,'$.result_type'),''))"
        player_status_sql = "LOWER(COALESCE(json_extract(row_json,'$.player_status'),''))"
        level_text_sql = "COALESCE(json_extract(row_json,'$.level'),'')"
        if isinstance(store, PostgreSQLStore):
            like_any = "%%"
            numeric_level_sql = (
                f"CASE WHEN {level_text_sql} ~ '^[0-9]+$' "
                f"THEN CAST({level_text_sql} AS INTEGER) ELSE 0 END"
            )
        else:
            like_any = "%"
            numeric_level_sql = f"CAST({level_text_sql} AS INTEGER)"
        category_sql = (
            "CASE "
            f"WHEN {status_sql}='CHƯA THỂ CHECK' OR {result_type_sql}='chưa thể check' THEN 'PENDING' "
            f"WHEN UPPER({status_sql})!='OK' OR {result_type_sql} IN ('sai pass','không thể log') THEN 'FAIL' "
            f"WHEN {result_type_sql}='lỗi ctnv' THEN 'GRANT_ERROR' "
            f"WHEN {player_status_sql} LIKE '{like_any}khóa{like_any}' "
            f"OR {player_status_sql} LIKE '{like_any}ban{like_any}' "
            f"OR {player_status_sql} LIKE '{like_any}cấm{like_any}' THEN 'LOCKED' "
            f"WHEN LOWER({level_text_sql})='ctnv' "
            f"OR {player_status_sql} LIKE '{like_any}chưa tạo nhân vật{like_any}' THEN 'CTNV' "
            f"WHEN {numeric_level_sql}>=? THEN 'OK' "
            "ELSE 'NOT_MET' END"
        )

        # Category/level buckets are maintained with each result write. Reading
        # filter totals touches at most a small set of buckets, not every result.
        category_rows = store.fetch(
            "SELECT category, level, result_count FROM job_result_stats WHERE job_id=?",
            (job_id,),
        )
        category_counts = {"OK": 0, "NOT_MET": 0, "CTNV": 0, "GRANT_ERROR": 0, "LOCKED": 0, "FAIL": 0, "PENDING": 0}
        for category, level, count in category_rows:
            key = str(category or "")
            if key == "LEVEL":
                key = "OK" if int(level or 0) >= min_level else "NOT_MET"
            if key in category_counts:
                category_counts[key] += int(count or 0)
        results_total = sum(category_counts.values())
        invalid_count_row = store.fetchone(
            "SELECT COUNT(*) FROM invalid_usernames WHERE job_id=?", (job_id,)
        )
        invalid_count = int(invalid_count_row[0] or 0) if invalid_count_row else 0
        junk_count_row = store.fetchone(
            "SELECT COUNT(*) FROM junk_accounts WHERE job_id=?", (job_id,)
        )
        junk_count = int(junk_count_row[0] or 0) if junk_count_row else 0
        category_counts["INVALID"] = invalid_count
        category_counts["JUNK"] = junk_count
        total_all = results_total + invalid_count + junk_count

        filter_sql = ""
        filter_args: tuple[Any, ...] = ()
        if result_filter not in {"ALL", "INVALID", "JUNK"}:
            filter_sql = f" AND ({category_sql})=?"
            filter_args = (min_level, result_filter)
        total = total_all if result_filter == "ALL" else category_counts[result_filter]
        total_pages = max(1, (total + per_page - 1) // per_page)
        page = min(page, total_pages)
        offset = (page - 1) * per_page
        rows_raw: list[tuple] = []
        invalid_rows_raw: list[tuple] = []
        junk_rows_raw: list[tuple] = []
        if result_filter == "INVALID":
            invalid_rows_raw = store.fetch(
                "SELECT line_number,username,raw_line,reason FROM invalid_usernames "
                "WHERE job_id=? ORDER BY id LIMIT ? OFFSET ?",
                (job_id, per_page, offset),
            )
        elif result_filter == "JUNK":
            junk_rows_raw = store.fetch(
                "SELECT line_number,username,raw_line,reason FROM junk_accounts "
                "WHERE job_id=? ORDER BY id LIMIT ? OFFSET ?",
                (job_id, per_page, offset),
            )
        else:
            result_offset = offset if result_filter == "ALL" else offset
            result_limit = (
                min(per_page, max(0, results_total - offset))
                if result_filter == "ALL" else per_page
            )
            if result_limit > 0:
                rows_raw = store.fetch(
                    "SELECT r.chunk_id, r.row_json, c.account FROM results r "
                    "JOIN chunks c ON c.id=r.chunk_id "
                    f"WHERE r.job_id=?{filter_sql} ORDER BY r.id LIMIT ? OFFSET ?",
                    (job_id, *filter_args, result_limit, result_offset),
                )
            remaining = per_page - len(rows_raw)
            if result_filter == "ALL" and remaining > 0:
                invalid_offset = max(0, offset - results_total)
                invalid_rows_raw = store.fetch(
                    "SELECT line_number,username,raw_line,reason FROM invalid_usernames "
                    "WHERE job_id=? ORDER BY id LIMIT ? OFFSET ?",
                    (job_id, remaining, invalid_offset),
                )
                remaining -= len(invalid_rows_raw)
            if result_filter == "ALL" and remaining > 0:
                junk_offset = max(0, offset - results_total - invalid_count)
                junk_rows_raw = store.fetch(
                    "SELECT line_number,username,raw_line,reason FROM junk_accounts "
                    "WHERE job_id=? ORDER BY id LIMIT ? OFFSET ?",
                    (job_id, remaining, junk_offset),
                )

        rows = []
        for _chunk_id_res, item_json, credentials_json in rows_raw:
            row = json.loads(item_json)
            try:
                row_index = int(str(row.get("stt") or "0")) - 1
            except (TypeError, ValueError):
                row_index = -1
            try:
                creds = json.loads(credentials_json)
            except (TypeError, json.JSONDecodeError):
                creds = []
            if not isinstance(creds, list):
                creds = []
            if 0 <= row_index < len(creds):
                row["full_credential"] = str(creds[row_index])
            else:
                row["full_credential"] = str(row.get("account") or "")
            rows.append(row)
        for line_number, username, raw_line, reason in invalid_rows_raw:
            rows.append({
                "stt": line_number,
                "account": username,
                "full_credential": raw_line,
                "status": "USER không hợp lệ",
                "result_type": "invalid username",
                "player_status": reason,
                "invalid_reason": reason,
            })
        for line_number, username, raw_line, reason in junk_rows_raw:
            rows.append({
                "stt": line_number,
                "account": username,
                "full_credential": raw_line,
                "status": "DATA rác",
                "result_type": "junk data",
                "player_status": reason,
                "invalid_reason": reason,
            })
        self._json(HTTPStatus.OK, {
            "ok": True,
            "job_id": job_id,
            "rows": rows,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_all": total_all,
            "total_pages": total_pages,
            "filter": result_filter,
            "min_level": min_level,
            "category_counts": category_counts,
        })

    def _handle_job_export(self, job_id: int, auth: dict[str, Any] | None = None) -> None:
        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền export job này"})
            return
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        category_filter = str(query.get("category", ["all"])[0] or "all").upper()
        VALID_CATEGORIES = {"ALL", "OK", "NOT_MET", "CTNV", "GRANT_ERROR", "LOCKED", "FAIL", "PENDING"}
        if category_filter not in VALID_CATEGORIES:
            category_filter = "ALL"
        try:
            min_level = max(1, min(1000, int(query.get("min_level", ["12"])[0])))
        except (TypeError, ValueError):
            min_level = 12
        # Map category filter to internal group names
        CATEGORY_TO_GROUP = {
            "OK": "Đạt", "NOT_MET": "Không đạt", "CTNV": "CTNV",
            "GRANT_ERROR": "Lỗi CTNV", "LOCKED": "Bị khóa",
            "FAIL": "Không thể log", "PENDING": "Chưa thể check",
        }
        store = self.server.store
        rows_raw = store.fetch(
            "SELECT chunk_id, row_json FROM results WHERE job_id=? ORDER BY id", (job_id,)
        )
        chunks_raw = store.fetch(
            "SELECT id, account FROM chunks WHERE job_id=?", (job_id,)
        )
        credentials_by_chunk: dict[int, list[str]] = {}
        for chunk_id, credentials_json in chunks_raw:
            try:
                credentials = json.loads(credentials_json)
            except (TypeError, json.JSONDecodeError):
                credentials = []
            credentials_by_chunk[int(chunk_id)] = credentials if isinstance(credentials, list) else []
        grouped_rows: dict[str, list[dict[str, Any]]] = {
            "Đạt": [], "Không đạt": [], "CTNV": [], "Lỗi CTNV": [], "Chưa thể check": [], "Bị khóa": [], "Không thể log": [],
        }
        for chunk_id, row_json in rows_raw:
            row = json.loads(row_json)
            try:
                row_index = int(str(row.get("stt") or "0")) - 1
            except (TypeError, ValueError):
                row_index = -1
            credentials = credentials_by_chunk.get(int(chunk_id), [])
            if 0 <= row_index < len(credentials):
                row["_export_credential"] = str(credentials[row_index])
            level = str(row.get("level") or "").strip()
            player_status = str(row.get("player_status") or "").strip()
            is_ctnv = level.casefold() == "ctnv" or player_status.casefold() == "chưa tạo nhân vật"
            result_type = str(row.get("result_type") or "").strip().casefold()
            if result_type in {"sai pass", "không thể log"} or str(row.get("status") or "").strip().upper() == "FAIL":
                grouped_rows["Không thể log"].append(row)
            elif result_type == "chưa thể check" or str(row.get("status") or "").strip().upper() == "CHƯA THỂ CHECK":
                grouped_rows["Chưa thể check"].append(row)
            elif player_status == "Bị khóa":
                grouped_rows["Bị khóa"].append(row)
            elif result_type == "lỗi ctnv":
                grouped_rows["Lỗi CTNV"].append(row)
            elif is_ctnv:
                grouped_rows["CTNV"].append(row)
            elif level.isdigit() and int(level) >= min_level:
                grouped_rows["Đạt"].append(row)
            else:
                grouped_rows["Không đạt"].append(row)
        all_categories = ("Đạt", "Không đạt", "CTNV", "Lỗi CTNV", "Chưa thể check", "Bị khóa", "Không thể log")
        if category_filter != "ALL":
            export_categories = (CATEGORY_TO_GROUP[category_filter],)
        else:
            export_categories = all_categories
        lines: list[str] = []
        for category in export_categories:
            for row in grouped_rows[category]:
                level = str(row.get("level") or "").strip()
                player_status = str(row.get("player_status") or "").strip()
                is_ctnv = level.casefold() == "ctnv" or player_status.casefold() == "chưa tạo nhân vật"
                name = "CTNV" if is_ctnv else str(row.get("name") or "").strip()
                status = player_status or str(row.get("status") or "").strip()
                values = [
                    str(row.get("_export_credential") or row.get("account") or "").strip(),
                    str(row.get("uid") or "").strip(),
                    name,
                    level,
                    status,
                ]
                if player_status == "Bị khóa":
                    values.extend((
                        f"Ban: {str(row.get('banTime') or '').strip()}",
                        f"Mở ban: {str(row.get('unbanTime') or '').strip()}",
                    ))
                lines.append(" || ".join(values))
        body = "\n".join(lines) + ("\n" if lines else "")
        data = body.encode("utf-8-sig")
        category_suffix = "" if category_filter == "ALL" else f"_{category_filter.lower()}"
        self.send_response(HTTPStatus.OK)
        self._security_headers("text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="job_{job_id}{category_suffix}.txt"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _handle_job_export_xlsx(self, job_id: int, auth: dict[str, Any] | None = None) -> None:
        """Export one job into exclusive result-category sheets with configurable pass level."""
        allowed, job = self._check_job_access(job_id, auth)
        if job is None:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "job không tồn tại"})
            return
        if not allowed:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "không có quyền export job này"})
            return

        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        min_level_raw = query.get("min_level", ["12"])[0]
        try:
            min_level = int(min_level_raw)
        except (TypeError, ValueError):
            min_level = 0
        if not 1 <= min_level <= 1000:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "min_level phải là số nguyên từ 1 đến 1000"})
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
        invalid_export_rows = []
        for line_number, username, raw_line, reason in self.server.store.fetch(
            "SELECT line_number,username,raw_line,reason FROM invalid_usernames "
            "WHERE job_id=? ORDER BY id",
            (job_id,),
        ):
            invalid_export_rows.append({
                "stt": line_number,
                "account": username,
                "_export_credential": raw_line,
                "status": "USER không hợp lệ",
                "player_status": reason,
            })
        junk_export_rows = []
        for line_number, username, raw_line, reason in self.server.store.fetch(
            "SELECT line_number,username,raw_line,reason FROM junk_accounts "
            "WHERE job_id=? ORDER BY id",
            (job_id,),
        ):
            junk_export_rows.append({
                "stt": line_number,
                "account": username,
                "_export_credential": raw_line,
                "status": "DATA rác",
                "player_status": reason,
            })
        sheets: dict[str, list[dict[str, Any]]] = {
            "Đạt": [], "Không đạt": [], "CTNV": [], "Lỗi CTNV": [], "Bị khóa": [], "Không thể log": [],
            "Chưa thể check": [], "USER không hợp lệ": invalid_export_rows,
            "DATA rác": junk_export_rows,
        }
        for row in rows:
            player_status = str(row.get("player_status") or "").strip()
            level = str(row.get("level") or "").strip()
            result_type = str(row.get("result_type") or "").strip().casefold()
            if result_type in {"sai pass", "không thể log"} or str(row.get("status") or "").strip().upper() == "FAIL":
                sheets["Không thể log"].append(row)
            elif result_type == "chưa thể check" or str(row.get("status") or "").upper() == "CHƯA THỂ CHECK":
                sheets["Chưa thể check"].append(row)
            elif player_status == "Bị khóa":
                sheets["Bị khóa"].append(row)
            elif result_type == "lỗi ctnv":
                sheets["Lỗi CTNV"].append(row)
            elif level.casefold() == "ctnv" or player_status == "Chưa tạo nhân vật":
                sheets["CTNV"].append(row)
            elif level.isdigit() and int(level) >= min_level:
                sheets["Đạt"].append(row)
            else:
                sheets["Không đạt"].append(row)

        try:
            import re
            import openpyxl
            from openpyxl.styles import Alignment, Font, PatternFill

            workbook = openpyxl.Workbook()
            headers = ["STT", "Tài khoản", "Kết quả check", "UID", "Tên", "Cấp", "Ngày tạo", "Trạng thái tài khoản"]
            fields = ["stt", "account", "status", "uid", "name", "level", "registerDate", "player_status"]
            widths = [8, 28, 16, 16, 28, 10, 16, 24]
            fills = {
                "Đạt": "238636", "Không đạt": "9E6A03", "CTNV": "8250DF",
                "Lỗi CTNV": "D97706",
                "Bị khóa": "C2410C", "Không thể log": "DA3633", "Chưa thể check": "D29922",
                "USER không hợp lệ": "B91C1C", "DATA rác": "7F1D1D",
            }
            for index, (sheet_name, sheet_rows) in enumerate(sheets.items()):
                worksheet = workbook.active if index == 0 else workbook.create_sheet()
                worksheet.title = f"Đạt từ LV {min_level}" if sheet_name == "Đạt" else sheet_name
                fill = PatternFill(start_color=fills[sheet_name], end_color=fills[sheet_name], fill_type="solid")
                sheet_headers = list(headers)
                sheet_fields = list(fields)
                sheet_widths = list(widths)
                if sheet_name == "Bị khóa":
                    sheet_headers.extend(("Thời gian ban", "Thời gian mở ban"))
                    sheet_fields.extend(("banTime", "unbanTime"))
                    sheet_widths.extend((28, 28))
                for column, label in enumerate(sheet_headers, 1):
                    cell = worksheet.cell(row=1, column=column, value=label)
                    cell.font = Font(bold=True, color="FFFFFF")
                    cell.fill = fill
                    cell.alignment = Alignment(horizontal="center")
                for row_index, row in enumerate(sheet_rows, 2):
                    for column, field in enumerate(sheet_fields, 1):
                        value = str(
                            row.get("_export_credential") or row.get(field, "") or ""
                        ) if field == "account" else str(row.get(field, "") or "")
                        if field == "registerDate":
                            cell = worksheet.cell(row=row_index, column=column, value=registration_date(value))
                            cell.number_format = "dd/mm/yyyy"
                            continue
                        # Excel rejects ASCII control characters in cell values.
                        value = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", value)
                        worksheet.cell(row=row_index, column=column, value=value)
                worksheet.freeze_panes = "A2"
                last_column = openpyxl.utils.get_column_letter(len(sheet_headers))
                worksheet.auto_filter.ref = f"A1:{last_column}{max(1, len(sheet_rows) + 1)}"
                for column, width in enumerate(sheet_widths, 1):
                    worksheet.column_dimensions[openpyxl.utils.get_column_letter(column)].width = width

            output = io.BytesIO()
            workbook.save(output)
            data = output.getvalue()
        except Exception as exc:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": f"Không tạo được file XLSX: {exc}"[:500]})
            return

        self.send_response(HTTPStatus.OK)
        self._security_headers("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        self.send_header("Content-Disposition", f'attachment; filename="job_{job_id}_tu_lv_{min_level}.xlsx"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class CoordinatorServer(ThreadingHTTPServer):
    daemon_threads = True
    # Mặc định socketserver chỉ cho hàng đợi accept = 5; khi nhiều vệ tinh +
    # trình duyệt poll cùng lúc, kết nối bị rớt/thử lại gây cảm giác lag.
    request_queue_size = 256

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], store: Store, master_token: str) -> None:
        super().__init__(address, handler)
        self.store = store
        self.master_token = master_token
        from uplv_coordinator import UpLvCoordinator
        self.uplv = UpLvCoordinator(store)
        self.claim_lock = threading.Lock()
        self.job_creation_lock = threading.Lock()
        self._idle_finish_check_lock = threading.Lock()
        self._idle_finish_check_at = 0.0
        self._satellite_idle_since: float | None = None
        self._satellite_idle_restarted = False
        self.stop_lock = threading.Lock()
        self._stopping_jobs_lock = threading.Lock()
        self._stopping_jobs: set[int] = set()
        self._billing_jobs_lock = threading.Lock()
        self._billing_jobs: set[int] = set()
        self._retention_lock = threading.Lock()
        self._retention_running = False
        self._retention_status: dict[str, Any] = {
            "running": False,
            "started_at": None,
            "finished_at": None,
            "cutoff": None,
            "jobs": 0,
            "chunks": 0,
            "results": 0,
            "error": "",
        }
        self._kientuong_lock = threading.Lock()
        self._kientuong_status: dict[str, Any] = {
            "state": "checking",
            "available": None,
            "http_status": 0,
            "checked_at": None,
            "satellite": "",
            "error": "",
        }

    IDLE_FINISH_CHECK_SECONDS = 3.0

    def should_run_idle_finish_check(self) -> bool:
        now = time.monotonic()
        with self._idle_finish_check_lock:
            if now - self._idle_finish_check_at < self.IDLE_FINISH_CHECK_SECONDS:
                return False
            self._idle_finish_check_at = now
            return True

    def kientuong_status(self) -> dict[str, Any]:
        with self._kientuong_lock:
            return dict(self._kientuong_status)

    def refresh_kientuong_status(self) -> bool:
        errors: list[str] = []
        try:
            result = run_kientuong_probe(
                KIENTUONG_MONITOR_ACCOUNT,
                KIENTUONG_MONITOR_PASSWORD,
            )
            status = int(result.get("http_status") or 0)
            if not result.get("probe_succeeded") or status <= 0:
                raise RuntimeError(str(result.get("error") or "Probe không trả HTTP status"))
            available_value = result.get("available")
            if status == 404:
                available = False
            elif available_value is True and 200 <= status < 400:
                available = True
            else:
                raise RuntimeError(f"Probe trả HTTP {status}, chưa thể xác nhận sẵn sàng")
            with self._kientuong_lock:
                self._kientuong_status = {
                    "state": "ready" if available else "down",
                    "available": available,
                    "http_status": status,
                    "checked_at": _now(),
                    "satellite": "master",
                    "error": "",
                }
            print(
                f"[master] Kien Tuong {'ready' if available else 'down'} (HTTP {status})",
                flush=True,
            )
            return True
        except Exception as exc:
            errors.append(str(exc)[:300])
        with self._kientuong_lock:
            previous = dict(self._kientuong_status)
            # Only a confirmed nested HTTP 404 may turn the public badge red.
            # Transient satellite/network failures retain the last confirmed state.
            if previous.get("available") is None:
                previous["state"] = "checking"
            previous["error"] = "; ".join(errors)[:500]
            self._kientuong_status = previous
        print(f"[master] Kien Tuong probe unknown: {'; '.join(errors)[:300]}", flush=True)
        return False

    def kientuong_monitor_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.refresh_kientuong_status()
            except Exception as exc:
                print(f"[master] Kien Tuong monitor error: {exc}", flush=True)
            stop_event.wait(KIENTUONG_MONITOR_INTERVAL_SECONDS)

    def retention_cleanup_status(self) -> dict[str, Any]:
        with self._retention_lock:
            return dict(self._retention_status)

    def schedule_retention_cleanup(self, cutoff: float | None = None) -> bool:
        cutoff = _today_start_timestamp() if cutoff is None else float(cutoff)
        with self._retention_lock:
            if self._retention_running:
                return False
            self._retention_running = True
            self._retention_status = {
                "running": True,
                "started_at": _now(),
                "finished_at": None,
                "cutoff": cutoff,
                "jobs": 0,
                "chunks": 0,
                "results": 0,
                "error": "",
            }
        threading.Thread(
            target=self._run_retention_cleanup,
            args=(cutoff,),
            name="master-retention-batches",
            daemon=True,
        ).start()
        return True

    def _run_retention_cleanup(self, cutoff: float) -> None:
        try:
            while True:
                batch = _prune_completed_jobs_batch(self.store, cutoff)
                with self._retention_lock:
                    for key in ("jobs", "chunks", "results"):
                        self._retention_status[key] += int(batch.get(key) or 0)
                if batch.get("complete"):
                    break
                time.sleep(RETENTION_BATCH_GAP_SECONDS)
        except Exception as exc:
            with self._retention_lock:
                self._retention_status["error"] = str(exc)[:300]
            print(f"[master] retention cleanup stopped: {exc}", flush=True)
        finally:
            with self._retention_lock:
                self._retention_running = False
                self._retention_status["running"] = False
                self._retention_status["finished_at"] = _now()
            status = self.retention_cleanup_status()
            print(
                f"[master] retention cleanup finished: jobs={status['jobs']} "
                f"chunks={status['chunks']} results={status['results']} "
                f"error={status['error'] or 'none'}",
                flush=True,
            )

    def schedule_stop_finalization(self, job_id: int, finalizer: Any = None) -> bool:
        """Run slow stop finalization once per job without blocking its HTTP request."""

        job_id = int(job_id)
        with self._stopping_jobs_lock:
            if job_id in self._stopping_jobs:
                return False
            self._stopping_jobs.add(job_id)

        if finalizer is None:
            finalizer = lambda current_job_id, now: _finalize_unresolved_job_accounts(
                self.store, current_job_id, now
            )
        thread = threading.Thread(
            target=self._finish_stopping_job,
            args=(job_id, finalizer),
            name=f"master-stop-job-{job_id}",
            daemon=True,
        )
        thread.start()
        return True

    def _finish_stopping_job(self, job_id: int, finalizer: Any) -> None:
        try:
            # Keep database-heavy stop jobs serialized while HTTP requests stay responsive.
            with self.stop_lock:
                current = self.store.fetchone(
                    "SELECT status FROM jobs WHERE id=?", (job_id,)
                )
                if current is None or str(current[0]) != "stopping":
                    return
                now = _now()
                try:
                    marked_uncheckable = int(finalizer(job_id, now) or 0)
                    self.store.batch([
                        {
                            "sql": "UPDATE chunks SET status='done', lease_until=NULL, reported_at=? WHERE job_id=? AND status IN ('pending','claimed')",
                            "args": [now, job_id],
                        },
                        {
                            "sql": "UPDATE jobs SET status='done', finished_at=? WHERE id=? AND status='stopping'",
                            "args": [now, job_id],
                        },
                    ])
                except Exception as exc:
                    # Placeholder upserts are idempotent, so returning to open
                    # makes a retry safe even after a partial batch succeeded.
                    self.store.exec(
                        "UPDATE jobs SET status='open' WHERE id=? AND status='stopping'",
                        (job_id,),
                    )
                    print(f"[master] failed to stop job {job_id}: {exc}", flush=True)
                    return
                print(
                    f"[master] stopped job {job_id}; "
                    f"marked {marked_uncheckable} unresolved accounts",
                    flush=True,
                )
                self.schedule_billing(job_id)
                self.schedule_retention_cleanup()
        finally:
            with self._stopping_jobs_lock:
                self._stopping_jobs.discard(job_id)

    def resume_stopping_jobs(self) -> int:
        """Resume stop requests left in progress by a previous process."""

        jobs = self.store.fetch("SELECT id FROM jobs WHERE status='stopping'")
        for (job_id,) in jobs:
            self.schedule_stop_finalization(int(job_id))
        return len(jobs)

    def schedule_billing(self, job_id: int) -> bool:
        """Settle one completed quantity job without blocking an HTTP worker."""

        job_id = int(job_id)
        with self._billing_jobs_lock:
            if job_id in self._billing_jobs:
                return False
            self._billing_jobs.add(job_id)
        threading.Thread(
            target=self._settle_billing_job,
            args=(job_id,),
            name=f"master-billing-job-{job_id}",
            daemon=True,
        ).start()
        return True

    def _settle_billing_job(self, job_id: int) -> None:
        try:
            row = self.store.fetchone(
                "SELECT j.owner_user_id,j.external_job_reference,j.billing_mode,j.billing_state,"
                "COALESCE(s.ok_count,0),COALESCE(s.fail_count,0),COALESCE(s.uncheckable_count,0),"
                "j.unit_price_tenths,j.status FROM jobs j LEFT JOIN job_stats s ON s.job_id=j.id WHERE j.id=?",
                (job_id,),
            )
            if row is None:
                return
            user_id, reference, mode, state, ok_count, fail_count, uncheckable_count, unit_price, status = row
            if str(mode or "") != "quantity" or str(status or "") != "done" or str(state or "") == "settled":
                return
            if not _aovshop_configured() or not user_id or not reference:
                return

            payload = {
                "user_id": int(user_id),
                "external_job_reference": str(reference),
                "ok_count": int(ok_count or 0),
                "fail_count": int(fail_count or 0),
                "uncheckable_count": int(uncheckable_count or 0),
                "idempotency_key": f"settle:{reference}",
                "master_job_id": job_id,
            }
            self.store.exec(
                "UPDATE jobs SET billing_state='settlement_pending',billing_error='' "
                "WHERE id=? AND billing_state<>'settled'",
                (job_id,),
            )
            result = _aovshop_request("/api/integrations/checkpass/quantity/settle", payload)
            if not result.get("ok") or str(result.get("status") or "") != "settled":
                raise RuntimeError(str(result.get("error") or "SP1S chưa xác nhận quyết toán"))
            final_tenths = result.get("final_amount_tenths")
            if final_tenths is None:
                final_tenths = (
                    int(ok_count or 0) * int(unit_price or 3)
                    + int(fail_count or 0) * QUANTITY_FAIL_PRICE_TENTHS
                )
            self.store.batch([
                {
                    "sql": "UPDATE jobs SET billing_state='settled',final_amount_tenths=?,"
                           "billing_order_id=?,billing_error='' WHERE id=?",
                    "args": [int(final_tenths), result.get("order_id"), job_id],
                },
                {"sql": "DELETE FROM billing_outbox WHERE job_id=?", "args": [job_id]},
            ])
            print(
                f"[master] settled job {job_id}: {int(ok_count or 0)} OK, "
                f"{int(fail_count or 0)} failed login, "
                f"{_money_from_tenths(final_tenths)} VND",
                flush=True,
            )
            self.schedule_retention_cleanup()
        except Exception as exc:
            error_message = str(exc)[:500]
            current = self.store.fetchone(
                "SELECT attempt_count FROM billing_outbox WHERE job_id=?", (job_id,)
            )
            attempts = int(current[0] if current else 0) + 1
            retry_at = _now() + min(300, 5 * (2 ** min(attempts - 1, 6)))
            payload_json = json.dumps({"job_id": job_id}, ensure_ascii=False)
            self.store.batch([
                {
                    "sql": "UPDATE jobs SET billing_state='settlement_pending',billing_error=? WHERE id=?",
                    "args": [error_message, job_id],
                },
                {
                    "sql": "INSERT INTO billing_outbox "
                           "(job_id,operation,payload,attempt_count,next_retry_at,last_error,status) "
                           "VALUES (?,?,?,?,?,?,'pending') ON CONFLICT(job_id) DO UPDATE SET "
                           "attempt_count=excluded.attempt_count,next_retry_at=excluded.next_retry_at,"
                           "last_error=excluded.last_error,status='pending'",
                    "args": [job_id, "quantity_settle", payload_json, attempts, retry_at, error_message],
                },
            ])
            print(f"[master] billing retry scheduled for job {job_id}: {error_message}", flush=True)
        finally:
            with self._billing_jobs_lock:
                self._billing_jobs.discard(job_id)

    def resume_billing_jobs(self) -> int:
        rows = self.store.fetch(
            "SELECT id FROM jobs WHERE status='done' AND billing_mode='quantity' "
            "AND billing_state IN ('reserved','settlement_pending')"
        )
        for (job_id,) in rows:
            self.schedule_billing(int(job_id))
        return len(rows)

    def restart_idle_satellites(self) -> None:
        """Restart configured satellites once after one continuous idle hour."""
        # Serialize with job admission so a job cannot open during dispatch.
        with self.job_creation_lock:
            now = time.monotonic()
            active = self.store.fetchone(
                "SELECT id FROM jobs WHERE status IN ('creating','open','stopping') LIMIT 1"
            )
            if active is not None:
                self._satellite_idle_since = None
                self._satellite_idle_restarted = False
                return
            if self._satellite_idle_since is None:
                self._satellite_idle_since = now
                return
            if self._satellite_idle_restarted or now - self._satellite_idle_since < 3600:
                return
            control_token = os.environ.get("SATELLITE_CONTROL_TOKEN", "").strip() or self.master_token.strip()
            targets = parse_satellite_targets(
                _setting(self.store, "satellite_targets", DEFAULT_SATELLITE_TARGETS)
            ) + parse_satellite_targets(
                _setting(self.store, "vvip_satellite_targets", DEFAULT_VVIP_SATELLITE_TARGETS)
            )
            unique = {target["url"].rstrip("/").lower(): target for target in targets}
            if not control_token or not unique:
                return
            # Failed targets are logged, without repeatedly restarting healthy ones.
            self._satellite_idle_restarted = True
            with ThreadPoolExecutor(max_workers=min(12, len(unique))) as pool:
                futures = {
                    pool.submit(restart_satellite, target, control_token): target
                    for target in unique.values()
                }
                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        future.result()
                        print(f"[master] idle 1h: restart sent to {target['label']}", flush=True)
                    except Exception as exc:
                        print(f"[master] idle restart failed for {target['label']}: {exc}", flush=True)

    def satellite_idle_maintenance_loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.restart_idle_satellites()
            except Exception as exc:
                # An unobserved interval cannot establish continuous idleness.
                self._satellite_idle_since = None
                print(f"[master] satellite idle maintenance error: {exc}", flush=True)
            stop_event.wait(5)

    def billing_maintenance_loop(self, stop_event: threading.Event) -> None:
        """Retry settlements; rental expiry does not stop accepted jobs."""

        while not stop_event.is_set():
            try:
                now = _now()
                pending = self.store.fetch(
                    "SELECT job_id FROM billing_outbox WHERE status='pending' AND next_retry_at<=? "
                    "ORDER BY next_retry_at LIMIT 20",
                    (now,),
                )
                for (job_id,) in pending:
                    self.schedule_billing(int(job_id))
            except Exception as exc:
                print(f"[master] billing maintenance error: {exc}", flush=True)
            stop_event.wait(2)


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
        targets = parse_satellite_targets("[one] https://one.example/\nhttps://two.example\nhttps://ONE.example")
        assert [(target["label"], target["url"]) for target in targets] == [
            ("one", "https://one.example"), ("two.example", "https://two.example")
        ]
        markdown_target = parse_satellite_targets(
            "[Checkpass 1] ([https://checkpass3-wt3z.onrender.com/](https://checkpass3-wt3z.onrender.com/))"
        )
        assert markdown_target == [{"label": "Checkpass 1", "url": "https://checkpass3-wt3z.onrender.com"}]
        print("SELF-TEST OK: master parse/split."); return 0

    if _aovshop_requested() and not _aovshop_configured():
        raise RuntimeError("Phải cấu hình đồng thời AOVSHOP_API_URL và CHECKPASS_SERVICE_TOKEN")

    # Chọn store: PostgreSQL VPS, Turso cloud, hoặc SQLite local.
    postgres_url = os.environ.get("DATABASE_URL", "").strip() or os.environ.get("POSTGRES_URL", "").strip()
    turso_url = os.environ.get("TURSO_URL", "").strip()
    turso_token = os.environ.get("TURSO_TOKEN", "").strip()
    if postgres_url:
        try:
            store = PostgreSQLStore(postgres_url)
            db_label = "postgresql"
        except Exception as exc:
            print(f"[master] Không kết nối PostgreSQL ({exc})", flush=True)
            raise
    else:
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
                    print(f"[master] Turso ping fail ({e}), chay SQLite", flush=True)
                    raise
                db_label = f"turso={turso_url.split('//')[1].split('.')[0] if '//' in turso_url else turso_url}"
            except Exception as e:
                print(f"[master] Không kết nối Turso ({e}), dùng SQLite", flush=True)
                store = LocalStore(db_path)
                db_label = f"sqlite={db_path} (fallback from turso)"
        else:
            store = LocalStore(db_path)
            db_label = f"sqlite={db_path}"

    server = CoordinatorServer((host, port), MasterHandler, store, token)
    # Resume an interrupted previous-day cleanup after any process restart. The
    # worker exits immediately when no eligible data remains.
    server.schedule_retention_cleanup()
    resumed_stops = server.resume_stopping_jobs()
    if resumed_stops:
        print(f"[master] resuming {resumed_stops} unfinished stop request(s)", flush=True)
    resumed_billing = server.resume_billing_jobs()
    if resumed_billing:
        print(f"[master] resuming {resumed_billing} unfinished billing operation(s)", flush=True)
    billing_stop = threading.Event()
    billing_thread = threading.Thread(
        target=server.billing_maintenance_loop,
        args=(billing_stop,),
        name="master-billing-maintenance",
        daemon=True,
    )
    billing_thread.start()
    satellite_idle_stop = threading.Event()
    satellite_idle_thread = threading.Thread(
        target=server.satellite_idle_maintenance_loop,
        args=(satellite_idle_stop,),
        name="master-satellite-idle-maintenance",
        daemon=True,
    )
    satellite_idle_thread.start()
    retention_stop = threading.Event()
    retention_thread = threading.Thread(
        target=_retention_cleanup_loop,
        args=(server, retention_stop),
        name="master-retention-cleanup",
        daemon=True,
    )
    retention_thread.start()
    kientuong_stop = threading.Event()
    kientuong_thread = threading.Thread(
        target=server.kientuong_monitor_loop,
        args=(kientuong_stop,),
        name="master-kientuong-monitor",
        daemon=True,
    )
    kientuong_thread.start()
    keepawake_stop = threading.Event()
    keepawake_thread = threading.Thread(
        target=keepawake_loop,
        args=(store, keepawake_stop, DEFAULT_SATELLITE_TARGETS, parse_satellite_targets),
        name="master-satellite-keepawake", daemon=True,
    )
    keepawake_thread.start()
    print(f"[master] Tổng bộ: http://{host}:{port}  role=coordinator  db={db_label}")
    if _aovshop_configured():
        print(f"[master] SP1S SSO/billing = '{AOVSHOP_API_URL}'")
    else:
        print("[master] CẢNH BÁO: chưa cấu hình SP1S SSO/billing; chỉ nên dùng chế độ local/test.")
    if token:
        print(f"[master] MASTER_TOKEN = '{token[:4]}***{token[-2:]}' (len={len(token)})")
    else:
        print("[master] CẢNH BÁO: chưa đặt MASTER_TOKEN - các vệ tinh đều truy cập được. Hãy đặt trên Render.")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n[master] Đã dừng.")
    finally:
        satellite_idle_stop.set()
        satellite_idle_thread.join(timeout=2)
        billing_stop.set()
        billing_thread.join(timeout=3)
        keepawake_stop.set()
        keepawake_thread.join(timeout=2)
        retention_stop.set()
        retention_thread.join(timeout=2)
        kientuong_stop.set()
        kientuong_thread.join(timeout=2)
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
