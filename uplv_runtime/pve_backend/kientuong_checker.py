"""
Adapter kiểm tra cấp độ và trạng thái nhân vật qua API Kiện Tướng (f:checkpass).
Sử dụng chính sso_key qua TCP đăng nhập Garena, không qua giao diện web.
"""
from __future__ import annotations
import time
import requests
from typing import Any, Optional

KIENTUONG_CALLBACK = "https://kientuong.lienquan.garena.vn/auth/login/callback"
KIENTUONG_PLAYER_API = "https://kientuong.lienquan.garena.vn/api/player/get"
GRANT_API = "https://100054.connect.garena.com/oauth/token/grant"
WEB_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def check_kientuong_player(sso_key: str, timeout: float = 10.0) -> dict[str, Any]:
    """
    Trả về:
    - has_role: True/False (True nếu đã tạo nhân vật và có cấp độ)
    - level: int (cấp độ nhân vật, 0 nếu chưa tạo)
    - name: str (tên ingame, rỗng nếu chưa tạo)
    - openid: str (tencentOpenId)
    - status: 'OK' | 'NO_PLAYER' | 'ERROR'
    - error: str (thông báo lỗi nếu có)
    """
    if not sso_key:
        return {"has_role": False, "level": 0, "name": "", "status": "ERROR", "error": "Thiếu sso_key"}

    sess = requests.Session()
    sess.headers.update({
        "User-Agent": WEB_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Referer": "https://kientuong.lienquan.garena.vn/"
    })

    # 1. Lấy grant code cho kientuong
    grant_data = {
        "client_id": "100054",
        "response_type": "code",
        "redirect_uri": KIENTUONG_CALLBACK,
        "format": "json",
        "id": str(int(time.time() * 1000))
    }
    try:
        r_grant = sess.post(GRANT_API, data=grant_data, cookies={"sso_key": sso_key}, timeout=timeout)
        if r_grant.status_code != 200:
            return {"has_role": False, "level": 0, "name": "", "status": "ERROR", "error": f"Grant HTTP {r_grant.status_code}"}
        grant_json = r_grant.json()
        code = grant_json.get("code")
        if not code:
            return {"has_role": False, "level": 0, "name": "", "status": "ERROR", "error": f"Grant rejected: {grant_json.get('error')}"}
    except Exception as exc:
        return {"has_role": False, "level": 0, "name": "", "status": "ERROR", "error": f"Grant request error: {exc}"}

    # 2. Callback thiết lập session kientuong
    try:
        cb_url = f"{KIENTUONG_CALLBACK}?code={code}"
        sess.get(cb_url, allow_redirects=True, timeout=timeout)
    except Exception as exc:
        pass

    # 3. Gọi player/get
    for attempt in range(3):
        if attempt > 0:
            time.sleep(0.5 * attempt)
        try:
            r_player = sess.get(KIENTUONG_PLAYER_API, timeout=timeout)
            if r_player.status_code == 422:
                # 422 Unprocessable Entity = CHƯA TẠO NHÂN VẬT!
                return {
                    "has_role": False,
                    "level": 0,
                    "name": "",
                    "status": "NO_PLAYER",
                    "error": ""
                }
            elif r_player.status_code == 200:
                data = r_player.json()
                player = data.get("player") or {}
                lvl = int(player.get("level") or player.get("role_level") or 0)
                name = player.get("name") or ""
                openid = player.get("tencentOpenId") or ""
                return {
                    "has_role": True,
                    "level": lvl,
                    "name": name,
                    "openid": openid,
                    "status": "OK",
                    "error": ""
                }
        except Exception:
            continue

    return {"has_role": False, "level": 0, "name": "", "status": "ERROR", "error": "player/get timeout"}
