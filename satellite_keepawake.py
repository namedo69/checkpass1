"""Periodically send inbound health requests to saved satellite services."""

from __future__ import annotations

import concurrent.futures
import re
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Callable


KEEPAWAKE_INTERVAL = 120
KEEPAWAKE_TIMEOUT = 15


def parse_satellite_targets(text: str) -> list[dict[str, str]]:
    """Accept the same one-URL-per-line format as the master admin settings."""
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r"https?://[^\s\]\)>]+", line, re.IGNORECASE)
        if not match:
            continue
        url = match.group(0).rstrip("/.,;)")
        try:
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                continue
            if parsed.username or parsed.password:
                continue
            _ = parsed.port
        except ValueError:
            continue
        normalized = url.lower().rstrip("/")
        if normalized in seen:
            continue
        seen.add(normalized)
        named = re.search(r"\[([^]]+)\]", line)
        label = (named.group(1).strip() if named else "") or parsed.hostname or f"satellite-{number:02}"
        targets.append({"label": label[:80], "url": url[:2048]})
    return targets


def saved_satellite_targets(
    store: Any, default_targets: str, parser: Callable[[str], list[dict[str, str]]]
) -> list[dict[str, str]]:
    row = store.fetchone(
        "SELECT setting_value FROM app_settings WHERE setting_key=?", ("satellite_targets",)
    )
    text = str(row[0]) if row and row[0] is not None else default_targets
    return parser(text)


def save_satellite_targets(store: Any, text: str) -> str:
    if len(text) > 20_000:
        raise ValueError("danh sách vệ tinh tối đa 20.000 ký tự")
    targets = parse_satellite_targets(text.strip())
    if text.strip() and not targets:
        raise ValueError("không tìm thấy URL http/https hợp lệ")
    normalized = "\n".join(f"[{target['label']}] {target['url']}" for target in targets)
    value = normalized + ("\n" if normalized else "")
    store.batch([{
        "sql": (
            "INSERT INTO app_settings (setting_key, setting_value) VALUES (?,?) "
            "ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value"
        ),
        "args": ("satellite_targets", value),
    }])
    return value


def ping_satellite(target: dict[str, str]) -> None:
    parsed = urllib.parse.urlsplit(target["url"].rstrip("/"))
    path = parsed.path.rstrip("/")
    if not path.endswith("/healthz"):
        path += "/healthz"
    url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
    request = urllib.request.Request(
        url, headers={"User-Agent": "CheckpassMasterKeepAwake/1.0"}
    )
    with urllib.request.urlopen(request, timeout=KEEPAWAKE_TIMEOUT):
        pass


def keepawake_loop(
    store: Any,
    stop_event: threading.Event,
    default_targets: str = "",
    parser: Callable[[str], list[dict[str, str]]] = parse_satellite_targets,
    interval: float = KEEPAWAKE_INTERVAL,
) -> None:
    """Read the saved list afresh on every round, starting when master starts."""
    while not stop_event.is_set():
        started = time.monotonic()
        try:
            targets = saved_satellite_targets(store, default_targets, parser)
            if targets:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
                    futures = {pool.submit(ping_satellite, target): target for target in targets}
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            future.result()
                        except Exception as exc:
                            target = futures[future]
                            print(f"[master] keepawake {target['label']}: {exc}", flush=True)
        except Exception as exc:
            print(f"[master] keepawake list error: {exc}", flush=True)
        stop_event.wait(max(0, started + interval - time.monotonic()))
