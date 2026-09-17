"""Read Weekly Report using a code issued for its own web redirect URI.

The caller supplies an authenticated Garena WebSession. TCP login responses
and codes issued for other sites are not Weekly Report credentials.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit


WEEKLY_URL = "https://weeklyreport.moba.garena.vn/"
PROFILE_URL = WEEKLY_URL + "api/profile"
OAUTH_PARAMS = {
    "client_id": "100054",
    "redirect_uri": WEEKLY_URL,
    "response_type": "code",
    "platform": "1",
    "locale": "vn-VN",
}


def _failure(stage: str, status: int, body: Any, fallback: str) -> dict[str, Any]:
    error = body.get("error") if isinstance(body, dict) else None
    # Do not expose arbitrary response text, callback URLs, or credentials.
    if not isinstance(error, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:-]{0,79}", error):
        error = fallback
    return {"ok": False, "stage": stage, "status": status, "error": error}


def fetch_weekly_profile(session: Any) -> dict[str, Any]:
    """Reuse Garena web SSO, grant a fresh Weekly code, and GET profile once."""
    stage = "oauth_init"
    try:
        status, _, _, body = session.request(
            session._api_url("auth.garena.com", "/api/universal/oauth", OAUTH_PARAMS),
            headers={"Referer": "https://auth.garena.com/universal/oauth"},
        )
        if status != 200 or not isinstance(body, dict) or body.get("error"):
            return _failure(stage, status, body, "invalid_oauth_init")
        sso = body.get("sso_session")
        if not isinstance(sso, dict) or not sso.get("login"):
            return _failure(stage, status, body, "web_login_required")

        stage = "oauth_grant"
        status, _, _, body = session.request(
            "https://auth.garena.com/oauth/token/grant",
            method="POST",
            form_body={
                "client_id": OAUTH_PARAMS["client_id"],
                "redirect_uri": WEEKLY_URL,
                "response_type": "code",
                "format": "json",
                "id": str(int(time.time() * 1000)),
            },
            headers={"Referer": "https://auth.garena.com/universal/oauth"},
        )
        if status != 200 or not isinstance(body, dict) or body.get("error"):
            return _failure(stage, status, body, "oauth_grant_failed")

        stage = "callback_validation"
        callback = urlsplit(str(body.get("redirect_uri") or ""))
        expected = urlsplit(WEEKLY_URL)
        if (
            callback.scheme != expected.scheme
            or callback.netloc != expected.netloc
            or callback.path != expected.path
        ):
            return _failure(stage, status, None, "unexpected_callback_origin")
        values = parse_qs(callback.query)
        codes = values.get("code", [])
        if len(codes) != 1 or not codes[0]:
            return _failure(stage, status, None, "missing_oauth_code")

        # The site reads its code in JavaScript and sends it in this header.
        # Keep the same cookie jar so the backend can establish its web session.
        stage = "profile"
        result = session.api_result(
            PROFILE_URL,
            headers={"Code": codes[0], "Partition": "1011", "Referer": WEEKLY_URL},
        )
        result["stage"] = stage
        return result
    except Exception as exc:
        return {"ok": False, "stage": stage, "status": 0, "error": type(exc).__name__}
