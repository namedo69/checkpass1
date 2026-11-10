"""Reusable web session from the original Garena SSO, no game re-login."""
import time
import requests


class PlayerSession:
    def __init__(self, sso_key, open_id, stop, session=None):
        self.sso_key, self.open_id, self.stop = sso_key, str(open_id), stop
        self.http = session or requests.Session()
        self.authorized = False
        self.last_error = ''
        self.http.headers.update({'Referer': 'https://kientuong.lienquan.garena.vn/'})

    def read(self, deadline, allow_no_player=False):
        def timeout():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self.stop.is_set():
                raise TimeoutError('Kiện Tướng deadline')
            return min(5, remaining)
        if not self.authorized:
            if not self.sso_key:
                raise ValueError('Thiếu SSO từ phiên đăng nhập ban đầu')
            reply = self.http.post('https://100054.connect.garena.com/oauth/token/grant',
                data={'client_id': '100054', 'response_type': 'code', 'redirect_uri': 'https://kientuong.lienquan.garena.vn/auth/login/callback', 'format': 'json'},
                cookies={'sso_key': self.sso_key}, timeout=timeout())
            reply.raise_for_status()
            code = reply.json().get('code')
            if not code:
                raise ValueError('Kiện Tướng grant rejected')
            self.http.get('https://kientuong.lienquan.garena.vn/auth/login/callback', params={'code': code}, timeout=timeout()).raise_for_status()
            self.authorized = True
        reply = self.http.get('https://kientuong.lienquan.garena.vn/api/player/get', timeout=timeout(), headers={'Cache-Control': 'no-cache'})
        if allow_no_player and reply.status_code == 422:
            return 0
        if reply.status_code in (401, 403):
            self.authorized = False
        reply.raise_for_status()
        player = reply.json().get('player') or {}
        # Garena OAuth open_id is gopOpenId. tencentOpenId belongs to the
        # game-side identity namespace and is different on live accounts.
        identity = str(player.get('gopOpenId') or '')
        if not identity or identity != self.open_id:
            raise ValueError('Kiện Tướng identity mismatch/missing')
        level = int(player.get('level') or player.get('role_level') or 0)
        if not 1 <= level <= 30:
            raise ValueError('Kiện Tướng level invalid')
        return level

    def verify(self, previous, target, budget=30):
        deadline = time.monotonic() + budget
        latest = None
        while time.monotonic() < deadline and not self.stop.is_set():
            try:
                level = self.read(deadline)
                if level >= previous:
                    latest = level
                    if level > previous or level >= target:
                        return level
            except (requests.RequestException, ValueError, TimeoutError) as exc:
                response = getattr(exc, 'response', None)
                self.last_error = ('HTTP ' + str(response.status_code) if response is not None
                                   else str(exc) if isinstance(exc, (ValueError, TimeoutError)) else type(exc).__name__)
            self.stop.wait(min(5, max(0, deadline - time.monotonic())))
        return latest

    def close(self):
        self.http.close()
