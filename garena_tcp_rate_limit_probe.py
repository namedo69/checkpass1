"""Bounded 3-phase Garena rate-limit probe for accounts owned by the operator.

Phase 1 – TCP LOGIN:       account + password  →  uid + session_key
Phase 2 – SSO Token:       session_key         →  sso_key (TCP cmd 0x1BA)
Phase 3 – Web Session:     sso_key cookie       →  Account Center + Kiện Tướng

Each phase is tested independently so that rate-limit boundaries per endpoint
are visible.  No secrets are saved to disk.
"""

from __future__ import annotations

import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import garena_api_test_chrome as api_test
import garena_tcp_login_chrome as tcp_ui


MAX_ACCOUNTS = 999999999999
MAX_WORKERS = 9999999
MIN_START_GAP_SECONDS = 0.0
DEFAULT_CREDENTIALS_FILE = Path(__file__).resolve().with_name("accounts_probe.txt")

PHASE_TCP = "tcp_login"
PHASE_SSO = "sso_token"
PHASE_WEB = "web_session"
ALL_PHASES = (PHASE_TCP, PHASE_SSO, PHASE_WEB)


@dataclass(slots=True)
class Credential:
    index: int
    account: str
    password: str


@dataclass(slots=True)
class PhaseResult:
    """Result of a single probe phase."""
    phase: str
    ok: bool
    elapsed_ms: int = 0
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ProbeResult:
    index: int
    masked_account: str
    uid: int = 0
    session_key_bytes: int = 0
    phases: list[PhaseResult] = field(default_factory=list)
    total_elapsed_ms: int = 0
    should_stop: bool = False
    skipped: bool = False

    @property
    def all_ok(self) -> bool:
        return bool(self.phases) and all(p.ok for p in self.phases)

    @property
    def last_error(self) -> str:
        for p in reversed(self.phases):
            if p.error:
                return p.error
        return ""

    def phase_status(self, phase_name: str) -> str:
        for p in self.phases:
            if p.phase == phase_name:
                return "OK" if p.ok else "FAIL"
        return "-"

    def phase_elapsed(self, phase_name: str) -> int:
        for p in self.phases:
            if p.phase == phase_name:
                return p.elapsed_ms
        return 0

    def phase_error(self, phase_name: str) -> str:
        for p in self.phases:
            if p.phase == phase_name:
                return p.error
        return ""


class StartGate:
    """Space LOGIN starts globally even when two requests overlap."""

    def __init__(self, gap_seconds: float) -> None:
        self.gap_seconds = gap_seconds
        self._lock = threading.Lock()
        self._next_start = 0.0

    def wait(self, stop_event: threading.Event) -> bool:
        with self._lock:
            while not stop_event.is_set():
                delay = self._next_start - time.monotonic()
                if delay <= 0:
                    self._next_start = time.monotonic() + self.gap_seconds
                    return True
                stop_event.wait(min(delay, 0.25))
        return False


def mask_account(account: str) -> str:
    if len(account) <= 2:
        return "*" * len(account)
    if len(account) <= 6:
        return account[0] + "*" * (len(account) - 2) + account[-1]
    return account[:2] + "*" * (len(account) - 4) + account[-2:]


def load_credentials(path: Path, limit: int) -> list[Credential]:
    if not path.is_file():
        raise ValueError(f"Không tìm thấy file: {path}")
    credentials: list[Credential] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            parts = line.split("|")
            if len(parts) < 2:
                raise ValueError(
                    f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)"
                )
            account = parts[0].strip()
            password = parts[1].strip()
        elif line.count(":") == 1:
            account, password = line.split(":", 1)
            account = account.strip()
            password = password.strip()
        else:
            raise ValueError(
                f"Dòng {line_number}: cần định dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass)"
            )
        if not account or not password or len(account) > 128 or len(password) > 1024:
            raise ValueError(f"Dòng {line_number}: tài khoản/mật khẩu không hợp lệ")
        credentials.append(Credential(len(credentials) + 1, account, password))
        if len(credentials) >= limit:
            break
    if not credentials:
        raise ValueError("File không có tài khoản hợp lệ")
    return credentials


def _safe(text: str) -> str:
    """Sanitize a string for pipe-delimited output."""
    return text.replace("|", "/").replace("\r", " ").replace("\n", " ")


def probe_one(
    tcp_module,
    credential: Credential,
    timeout: float,
    phases: tuple[str, ...],
    gate: StartGate,
    stop_event: threading.Event,
) -> ProbeResult:
    masked = mask_account(credential.account)
    if not gate.wait(stop_event):
        return ProbeResult(index=credential.index, masked_account=masked, skipped=True)

    result = ProbeResult(index=credential.index, masked_account=masked)
    total_started = time.monotonic()

    # ── Phase 1: TCP LOGIN ──────────────────────────────────────────────
    sso_key: str | None = None
    sso_expiry: int = 0
    phase1_started = time.monotonic()
    try:
        client_type = api_test.resilient_tcp_client_type(tcp_module)
        client = client_type(timeout=timeout)
        client.__enter__()
        try:
            uid = int(client.login(credential.account, credential.password))
            key_size = len(client.session_key or b"")
        except Exception:
            client.__exit__(None, None, None)
            raise
        phase1_ms = round((time.monotonic() - phase1_started) * 1000)
        if key_size != 16:
            client.__exit__(None, None, None)
            result.phases.append(PhaseResult(
                phase=PHASE_TCP, ok=False, elapsed_ms=phase1_ms,
                error="LOGIN OK nhưng session key không đúng 16 byte",
            ))
            result.should_stop = True
            stop_event.set()
            result.total_elapsed_ms = round((time.monotonic() - total_started) * 1000)
            return result
        result.uid = uid
        result.session_key_bytes = key_size
        result.phases.append(PhaseResult(
            phase=PHASE_TCP, ok=True, elapsed_ms=phase1_ms,
            details={"uid": uid, "session_key_bytes": key_size},
        ))
    except Exception as exc:
        phase1_ms = round((time.monotonic() - phase1_started) * 1000)
        message = (str(exc).strip() or type(exc).__name__)[:300]
        result.phases.append(PhaseResult(
            phase=PHASE_TCP, ok=False, elapsed_ms=phase1_ms, error=message,
        ))
        result.should_stop = True
        stop_event.set()
        result.total_elapsed_ms = round((time.monotonic() - total_started) * 1000)
        return result

    # ── Phase 2: SSO Token (get_sso_key) ────────────────────────────────
    if PHASE_SSO in phases:
        phase2_started = time.monotonic()
        try:
            sso = client.get_sso_key()
            sso_key = str(sso.sso_key)
            sso_expiry = int(sso.expiry_time)
            phase2_ms = round((time.monotonic() - phase2_started) * 1000)
            result.phases.append(PhaseResult(
                phase=PHASE_SSO, ok=True, elapsed_ms=phase2_ms,
                details={
                    "sso_key_length": len(sso_key),
                    "sso_expiry_time": sso_expiry,
                },
            ))
        except Exception as exc:
            phase2_ms = round((time.monotonic() - phase2_started) * 1000)
            message = (str(exc).strip() or type(exc).__name__)[:300]
            result.phases.append(PhaseResult(
                phase=PHASE_SSO, ok=False, elapsed_ms=phase2_ms, error=message,
            ))
            result.should_stop = True
            stop_event.set()

    # Close TCP connection – no longer needed
    try:
        client.__exit__(None, None, None)
    except Exception:
        pass

    if stop_event.is_set() and not result.all_ok:
        result.total_elapsed_ms = round((time.monotonic() - total_started) * 1000)
        return result

    # ── Phase 3: Web Session (SSO key → Account Center) ─────────────────
    if PHASE_WEB in phases and sso_key:
        phase3_started = time.monotonic()
        try:
            probe = api_test.legacy_account_sso_probe(sso_key, sso_expiry, timeout)
            phase3_ms = round((time.monotonic() - phase3_started) * 1000)
            probe_ok = bool(probe.get("ok"))
            accepted = bool(probe.get("accepted"))
            account_init_ok = bool(
                isinstance(probe.get("account_init"), dict)
                and probe["account_init"].get("ok")
            )
            oauth_chain = probe.get("account_to_kientuong_oauth") or {}
            kientuong_ok = bool(
                isinstance(oauth_chain, dict) and oauth_chain.get("ok")
            )
            error = ""
            if not probe_ok:
                error = str(probe.get("error") or "web_session_failed")[:300]
            result.phases.append(PhaseResult(
                phase=PHASE_WEB, ok=probe_ok, elapsed_ms=phase3_ms,
                error=error,
                details={
                    "sso_accepted": accepted,
                    "sso_login": bool(probe.get("sso_session_login")),
                    "redirect_received": bool(probe.get("redirect_received")),
                    "account_init_ok": account_init_ok,
                    "kientuong_ok": kientuong_ok,
                    "http_status": probe.get("status", 0),
                },
            ))
            if not probe_ok:
                result.should_stop = True
                stop_event.set()
        except Exception as exc:
            phase3_ms = round((time.monotonic() - phase3_started) * 1000)
            message = (str(exc).strip() or type(exc).__name__)[:300]
            result.phases.append(PhaseResult(
                phase=PHASE_WEB, ok=False, elapsed_ms=phase3_ms, error=message,
            ))
            result.should_stop = True
            stop_event.set()
    elif PHASE_WEB in phases and not sso_key:
        result.phases.append(PhaseResult(
            phase=PHASE_WEB, ok=False, elapsed_ms=0,
            error="bỏ qua vì không có SSO key",
        ))

    result.total_elapsed_ms = round((time.monotonic() - total_started) * 1000)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Probe rate-limit 3 pha: TCP LOGIN → SSO Token → Web Session.  "
            "Không lưu session/token ra đĩa."
        ),
    )
    parser.add_argument(
        "credentials",
        type=Path,
        nargs="?",
        default=DEFAULT_CREDENTIALS_FILE,
        help="File UTF-8 dạng user|pass, user|pass|mail hoặc user|pass|mail|passmail (hoặc user:pass) (mặc định: accounts_probe.txt cạnh chương trình)",
    )
    parser.add_argument("--limit", type=int, default=5, help="Số tài khoản, 1..999999999999 (mặc định 5)")
    parser.add_argument("--workers", type=int, choices=(20, 40), default=20)
    parser.add_argument(
        "--start-gap",
        type=float,
        default=5.0,
        help="Khoảng cách giữa hai lần bắt đầu, tối thiểu 0 giây (mặc định 5)",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="Timeout mỗi pha, 5..60 giây")
    parser.add_argument(
        "--phases",
        type=str,
        default="tcp,sso,web",
        help=(
            "Chọn các pha cần test, phân cách bằng dấu phẩy.  "
            "Giá trị: tcp, sso, web  (mặc định: tcp,sso,web)"
        ),
    )
    return parser.parse_args()


def _parse_phases(raw: str) -> tuple[str, ...]:
    """Parse the --phases flag into validated phase constants."""
    mapping = {"tcp": PHASE_TCP, "sso": PHASE_SSO, "web": PHASE_WEB}
    phases: list[str] = []
    for token in raw.lower().replace(" ", "").split(","):
        token = token.strip()
        if not token:
            continue
        if token not in mapping:
            raise SystemExit(
                f"Pha không hợp lệ: '{token}'.  Chọn từ: tcp, sso, web"
            )
        constant = mapping[token]
        if constant not in phases:
            phases.append(constant)
    if not phases:
        raise SystemExit("Cần ít nhất một pha (tcp, sso, web)")
    # sso & web both require tcp
    if PHASE_SSO in phases and PHASE_TCP not in phases:
        phases.insert(0, PHASE_TCP)
    if PHASE_WEB in phases and PHASE_SSO not in phases:
        # web needs sso_key, which needs tcp
        if PHASE_TCP not in phases:
            phases.insert(0, PHASE_TCP)
        phases.insert(phases.index(PHASE_WEB), PHASE_SSO)
    return tuple(phases)


def main() -> int:
    tcp_ui.configure_console_encoding()
    args = parse_args()
    if not 1 <= args.limit <= MAX_ACCOUNTS:
        raise SystemExit(f"--limit phải trong khoảng 1..{MAX_ACCOUNTS}")
    if not MIN_START_GAP_SECONDS <= args.start_gap <= 60:
        raise SystemExit("--start-gap phải trong khoảng 0..60 giây")
    if not 5 <= args.timeout <= 60:
        raise SystemExit("--timeout phải trong khoảng 5..60 giây")

    phases = _parse_phases(args.phases)
    phase_labels = [p.replace("_", " ").upper() for p in phases]

    credentials = load_credentials(args.credentials.resolve(), args.limit)
    tcp_module = tcp_ui.load_verified_tcp_module()
    gate = StartGate(args.start_gap)
    stop_event = threading.Event()

    print(
        f"Probe {len(credentials)} tài khoản | workers={args.workers} | "
        f"start_gap={args.start_gap:g}s | phases={','.join(phase_labels)} | "
        f"không lưu session/token"
    )
    # Header
    header_parts = ["STT", "ACCOUNT", "UID"]
    for phase in phases:
        short = phase.split("_")[-1].upper()
        header_parts.extend([f"{short}_STATUS", f"{short}_MS"])
    header_parts.extend(["TOTAL_MS", "ERROR"])
    print("|".join(header_parts))

    results: list[ProbeResult] = []
    try:
        with ThreadPoolExecutor(max_workers=args.workers, thread_name_prefix="probe") as executor:
            futures = [
                executor.submit(
                    probe_one,
                    tcp_module,
                    credential,
                    args.timeout,
                    phases,
                    gate,
                    stop_event,
                )
                for credential in credentials
            ]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                if result.skipped:
                    print(f"{result.index}|{result.masked_account}|SKIPPED|đã dừng trước khi gửi")
                    continue

                row_parts: list[str] = [
                    str(result.index),
                    result.masked_account,
                    str(result.uid) if result.uid else "",
                ]
                for phase in phases:
                    row_parts.append(result.phase_status(phase))
                    row_parts.append(str(result.phase_elapsed(phase)))
                row_parts.append(str(result.total_elapsed_ms))
                # Collect all phase errors
                errors = [
                    f"[{p.phase.split('_')[-1]}] {p.error}"
                    for p in result.phases if p.error
                ]
                row_parts.append(_safe("; ".join(errors)) if errors else "")
                print("|".join(row_parts))

                if result.should_stop:
                    print(
                        "STOP|Phát hiện lỗi/giới hạn; không gửi thêm request mới.  "
                        f"Pha lỗi: {result.last_error[:120]}"
                    )
    finally:
        for credential in credentials:
            credential.password = ""

    attempted = [r for r in results if not r.skipped]
    all_ok = sum(r.all_ok for r in attempted)
    partial = sum(1 for r in attempted if r.phases and not r.all_ok)

    # Per-phase summary
    print()
    for phase in phases:
        short = phase.split("_")[-1].upper()
        ok_count = sum(1 for r in attempted for p in r.phases if p.phase == phase and p.ok)
        fail_count = sum(1 for r in attempted for p in r.phases if p.phase == phase and not p.ok)
        avg_ms = 0
        phase_times = [p.elapsed_ms for r in attempted for p in r.phases if p.phase == phase and p.ok]
        if phase_times:
            avg_ms = round(sum(phase_times) / len(phase_times))
        print(f"PHASE_{short}|ok={ok_count}|fail={fail_count}|avg_ms={avg_ms}")

    print(
        f"SUMMARY|attempted={len(attempted)}|all_ok={all_ok}|"
        f"partial_fail={partial}|stopped={stop_event.is_set()}"
    )
    return 0 if partial == 0 and not stop_event.is_set() else 1


if __name__ == "__main__":
    raise SystemExit(main())
