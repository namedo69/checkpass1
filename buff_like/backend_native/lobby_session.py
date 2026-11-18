"""Stateful lobby session runner reconstructed from go_buff_hot_engine.exe."""
import socket
import threading
import time
from .encoding import encode_packet
from .garena_client import (
    GARENA_GATEWAY_ENDPOINTS,
    derive_device_identity,
    exchange_msdk_session,
    garena_authenticate,
    parse_host_port,
)
from .handshake import build_client_hello, read_server_hello_key
from .lobby_cipher import LobbyCipher
from .lobby_protocol import (
    CharacterCreationRequiredError,
    GameMessage,
    LOBBY_ENTRY_ENDPOINTS,
    LoginSuccessInfo,
    MSG_ENTER_WORLD_OK,
    MSG_LEVEL_EXP,
    MSG_LOBBY_READY,
    MSG_LOGIN_PROMPT,
    MSG_LOGIN_REQUEST,
    MSG_LOGIN_RESULT,
    MSG_PING_14BA,
    MSG_PONG_14BB,
    MSG_REGISTER_REQUIRED,
    MSG_REGISTER_RESULT,
    MSG_RESTART_PRE,
    MSG_RESTART_PROMPT,
    MSG_RESTART_REQUEST,
    MSG_SESSION_KICK,
    MSG_WORLD_REDIRECT,
    RESTART_PRE_BODY,
    build_entry_auth_packet,
    build_game_packet,
    build_login_request,
    build_restart_request,
    decode_game_packet,
    parse_login_result_1003,
    parse_world_redirect_body,
)
from .moments_protocol import (
    MSG_LIKE_FEED_REQ,
    MSG_LIKE_FEED_RESP,
    MSG_QUERY_FEEDS_REQ,
    MSG_QUERY_FEEDS_RESP,
    MSG_RESOLVE_PROFILE_REQ,
    MSG_RESOLVE_PROFILE_RESP,
    MomentsFeedPage,
    PlayerProfile,
    build_like_feed_request,
    build_query_user_feeds_request,
    build_resolve_profile_request,
    parse_like_feed_response,
    parse_query_user_feeds_response,
    parse_resolve_profile_response,
)
from .reader import DecodeError
from .receiver import Receiver


class PermanentLobbyAuthError(DecodeError):
    """Non-retryable lobby authentication error."""


class LobbyDisconnectError(DecodeError):
    """Server disconnect retaining a preceding notice, without guessing meaning."""
    def __init__(self, endpoint, notice=None):
        super().__init__('server disconnected (0x5002)')
        self.endpoint = endpoint
        self.notice = notice


def is_permanent_lobby_auth_error(exc: BaseException) -> bool:
    """Reconstructed from main.isPermanentLobbyAuthError (0x14030ea60)."""
    if isinstance(exc, (PermanentLobbyAuthError, CharacterCreationRequiredError)):
        return True
    text = str(exc).lower()
    for marker in (
        'game rejected login 1003',
        'register result 1009 failed',
        'character registration required',
        'token expired',
        'invalid token',
        'auth failed',
    ):
        if marker in text:
            return True
    return False


class LobbySession:
    """Single-owner stateful game lobby session."""

    def __init__(
        self,
        account: str,
        password: str = '',
        *,
        stop: threading.Event | None = None,
        socket_factory=socket.create_connection,
    ):
        self.account = account
        self.password = password
        self.identity = derive_device_identity(account)
        self.stop = stop if stop is not None else threading.Event()
        self._socket_factory = socket_factory

        self.garena_open_id = ''
        self.garena_token = ''
        self.msdk_uid = ''
        self.msdk_token = ''
        self.numeric_uid = 0

        self.world_id = 0
        self.role_uid = 0
        self.level = 0
        self.experience = 0
        self.lobby_ready = False

        self.client_seq = 0
        self.logical_seq = 0
        self.server_seq = 0

        self.sock = None
        self.receiver: Receiver | None = None
        self.cipher: LobbyCipher | None = None
        self.connected_endpoint = ''
        self.home_endpoint = ''
        self.last_login_notice = None

    def close(self) -> None:
        sock = self.sock
        self.sock = None
        self.receiver = None
        self.cipher = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def authenticate(
        self,
        *,
        garena_endpoints=GARENA_GATEWAY_ENDPOINTS,
        connect_timeout: float = 3.5,
        session_timeout: float = 8.0,
        msdk_timeout: float = 10.0,
        opener=None,
        now_fn=time.time,
    ) -> None:
        """Execute Garena TCP login + MSDK HTTP exchange (ConnectAndAuth auth half)."""
        grant = garena_authenticate(
            self.account,
            self.password,
            self.identity.device_key,
            endpoints=garena_endpoints,
            connect_timeout=connect_timeout,
            session_timeout=session_timeout,
            stop=self.stop,
            now_fn=now_fn,
        )
        msdk = exchange_msdk_session(
            grant.access_token,
            grant.open_id,
            self.identity.device_uuid,
            timeout=msdk_timeout,
            now_fn=now_fn,
            opener=opener,
        )
        self.garena_open_id = grant.open_id
        self.garena_token = grant.access_token
        self.msdk_uid = msdk.uid
        self.msdk_token = msdk.token
        self.numeric_uid = msdk.numeric_uid

    def _dial_and_hello(self, endpoint: str, *, connect_timeout: float, deadline: float) -> None:
        self.close()
        self.last_login_notice = None
        host, port = parse_host_port(endpoint)
        from .worker_pacing import pace
        pace('lobby_'+host, 0.006)
        sock = self._socket_factory((host, port), timeout=connect_timeout)
        self.sock = sock
        self.receiver = Receiver(sock)
        self.connected_endpoint = endpoint

        hello_pkt = build_client_hello(self.numeric_uid)
        sock.sendall(encode_packet(hello_pkt))

        srv_pkt = self.receiver.receive(deadline=deadline, stop=self.stop)
        key = read_server_hello_key(srv_pkt)
        self.cipher = LobbyCipher(key)
        self.client_seq = 2
        self.logical_seq = 0
        self.server_seq = 0

    def send_game_ack(
        self,
        msg_id: int,
        body: bytes,
        ack_seq: int | None = None,
    ) -> int:
        """Reconstructed from main.(*LobbySession).SendGameAck (0x14030e200)."""
        if self.sock is None or self.cipher is None:
            raise RuntimeError('lobby session is not connected')
        self.client_seq += 1
        self.logical_seq += 1
        effective_ack = self.server_seq if ack_seq is None else int(ack_seq)
        pkt = build_game_packet(
            msg_id,
            body,
            self.cipher,
            client_seq=self.client_seq,
            logical_seq=self.logical_seq,
            ack_seq=effective_ack,
        )
        self.sock.sendall(encode_packet(pkt))
        return self.client_seq

    def _handle_received_packet(self, pkt) -> GameMessage | None:
        if self.cipher is None:
            raise RuntimeError('lobby session cipher not initialized')
        if pkt.kind != 0x4013 and pkt.kind != 0x5002:
            return None
        if pkt.kind == 0x5002:
            raise LobbyDisconnectError(self.connected_endpoint, self.last_login_notice)
        msg = decode_game_packet(pkt, self.cipher)
        self.server_seq = msg.server_seq
        if msg.msg_id == 0x4a6:
            # Exact observed notice shape only. No token/payload logging and no
            # claim that the first word is a documented rejection code.
            self.last_login_notice = (0x4a6, int.from_bytes(msg.body[:4], 'big')) if len(msg.body) == 10 else (0x4a6, None)

        if msg.msg_id == MSG_PING_14BA:
            if len(msg.body) == 1 and self.sock is not None:
                self.send_game_ack(MSG_PONG_14BB, msg.body, None)
            return None

        if msg.msg_id == MSG_SESSION_KICK:
            code = int.from_bytes(msg.body[:4], 'big', signed=True) if len(msg.body) >= 4 else 0
            raise DecodeError(f'session kicked by server (0x412, code={code})')

        if msg.msg_id == MSG_LOBBY_READY:
            self.lobby_ready = True
        elif msg.msg_id == MSG_LEVEL_EXP and len(msg.body) >= 8:
            self.level = int.from_bytes(msg.body[:4], 'big')
            self.experience = int.from_bytes(msg.body[4:8], 'big')

        return msg

    def receive_game(
        self,
        *,
        timeout: float = 6.0,
        deadline: float | None = None,
    ) -> GameMessage:
        """Reconstructed from main.(*LobbySession).ReceiveGame (0x14030e5a0)."""
        if self.receiver is None or self.cipher is None:
            raise RuntimeError('lobby session is not connected')
        effective_deadline = (time.monotonic() + timeout) if deadline is None else deadline
        while True:
            pkt = self.receiver.receive(deadline=effective_deadline, stop=self.stop)
            msg = self._handle_received_packet(pkt)
            if msg is not None:
                return msg

    def connect_from_entry(
        self,
        entry_endpoint: str,
        *,
        connect_timeout: float = 6.0,
        handshake_timeout: float = 18.0,
    ) -> LoginSuccessInfo:
        """Reconstructed from main.(*LobbySession).connectLobbyFromEntry (0x14030f040)."""
        if not self.msdk_token or not self.garena_open_id or not self.msdk_uid or not self.numeric_uid:
            raise ValueError('session must have MSDK and Garena auth fields before lobby connect')

        deadline = time.monotonic() + handshake_timeout
        current_endpoint = entry_endpoint
        try:
            for hop in range(2):
                self._dial_and_hello(
                    current_endpoint,
                    connect_timeout=connect_timeout,
                    deadline=deadline,
                )
                assert self.sock is not None and self.cipher is not None
                auth_pkt = build_entry_auth_packet(self.msdk_token, self.cipher, sequence=2)
                self.sock.sendall(encode_packet(auth_pkt))

                redirected = False
                for _ in range(80):
                    msg = self.receive_game(deadline=deadline)
                    if msg.msg_id == MSG_WORLD_REDIRECT:
                        if hop >= 1:
                            raise DecodeError('unexpected second world redirect (0x3e5)')
                        current_endpoint = parse_world_redirect_body(msg.body)
                        redirected = True
                        break

                    if msg.msg_id == MSG_LOGIN_PROMPT:
                        login_req = build_login_request(
                            self.garena_open_id,
                            self.msdk_uid,
                            self.numeric_uid,
                        )
                        self.send_game_ack(MSG_LOGIN_REQUEST, login_req, None)
                        continue

                    if msg.msg_id == MSG_RESTART_PROMPT:
                        self.logical_seq = msg.sub_id
                        ack = max(0, self.server_seq - 1)
                        self.send_game_ack(MSG_RESTART_PRE, RESTART_PRE_BODY, ack)
                        self.send_game_ack(MSG_RESTART_REQUEST, build_restart_request(), ack)
                        continue

                    if msg.msg_id == MSG_LOGIN_RESULT:
                        info = parse_login_result_1003(msg.body)
                        if len(msg.body) >= 32:
                            self.world_id = info.world_id
                            self.role_uid = info.role_uid
                            self.level = info.level
                            self.experience = info.experience
                        if not self.connected_endpoint.endswith(':6670'):
                            self.home_endpoint = self.connected_endpoint
                        return info

                    if msg.msg_id == MSG_ENTER_WORLD_OK and len(msg.body) > 1:
                        if not self.connected_endpoint.endswith(':6670'):
                            self.home_endpoint = self.connected_endpoint
                        return LoginSuccessInfo(
                            world_id=self.world_id,
                            role_uid=self.role_uid,
                            level=self.level,
                            experience=self.experience,
                        )

                    if msg.msg_id == MSG_REGISTER_REQUIRED:
                        raise CharacterCreationRequiredError(
                            'character registration required (0x3ef); refusing to auto-create character'
                        )

                    if msg.msg_id == MSG_REGISTER_RESULT:
                        code = int.from_bytes(msg.body[:4], 'big', signed=True) if len(msg.body) >= 4 else -1
                        if code == 0:
                            if not self.connected_endpoint.endswith(':6670'):
                                self.home_endpoint = self.connected_endpoint
                            return LoginSuccessInfo(
                                world_id=self.world_id,
                                role_uid=self.role_uid,
                                level=self.level,
                                experience=self.experience,
                            )
                        raise CharacterCreationRequiredError(
                            f'register result 1009 failed (code={code}); refusing character creation'
                        )

                if not redirected:
                    break

            raise DecodeError('lobby handshake exceeded 80 messages without login completion')
        except Exception:
            self.close()
            raise

    def connect_lobby(
        self,
        *,
        entry_endpoints=LOBBY_ENTRY_ENDPOINTS,
        max_attempts: int = 3,
        connect_timeout: float = 6.0,
        handshake_timeout: float = 18.0,
    ) -> LoginSuccessInfo:
        """Reconstructed from main.(*LobbySession).ConnectLobby (0x14030eb40)."""
        self.lobby_ready = False
        candidates = []
        if self.home_endpoint:
            candidates.append(self.home_endpoint)
        for ep in entry_endpoints:
            if ep and ep not in candidates:
                candidates.append(ep)
        last_error = None
        attempts = 0
        for endpoint in candidates:
            if attempts >= max_attempts:
                break
            attempts += 1
            try:
                return self.connect_from_entry(
                    endpoint,
                    connect_timeout=connect_timeout,
                    handshake_timeout=handshake_timeout,
                )
            except Exception as exc:
                last_error = exc
                if is_permanent_lobby_auth_error(exc):
                    raise
                continue
        if last_error is not None:
            raise last_error
        raise RuntimeError('no lobby entry endpoints configured')

    def resolve_player_profile_1205(
        self,
        name: str,
        *,
        timeout: float = 6.0,
    ) -> PlayerProfile:
        """Reconstructed from main.(*LobbySession).ResolvePlayerProfile1205 (0x140310640)."""
        req = build_resolve_profile_request(name)
        self.send_game_ack(MSG_RESOLVE_PROFILE_REQ, req, None)
        deadline = time.monotonic() + timeout
        while True:
            msg = self.receive_game(deadline=deadline)
            if msg.msg_id == MSG_RESOLVE_PROFILE_RESP:
                return parse_resolve_profile_response(msg.body, name)

    def query_user_feeds_12956(
        self,
        target_uid: int,
        world_id: int,
        start_index: int = 0,
        end_index: int = 15,
        *,
        timeout: float = 6.0,
    ) -> MomentsFeedPage:
        """Reconstructed from main.(*LobbySession).QueryUserFeeds12956 (0x140310fc0)."""
        req = build_query_user_feeds_request(
            target_uid,
            world_id,
            start_index=start_index,
            end_index=end_index,
        )
        self.send_game_ack(MSG_QUERY_FEEDS_REQ, req, None)
        deadline = time.monotonic() + timeout
        items, accounts = [], []
        while True:
            msg = self.receive_game(deadline=deadline)
            if msg.msg_id == MSG_QUERY_FEEDS_RESP:
                page = parse_query_user_feeds_response(msg.body)
                items.extend(page.items)
                accounts.extend(page.accounts)
                if page.done:
                    return MomentsFeedPage(tuple(items), tuple(accounts), True)

    def query_latest_feeds(self, target_uid: int, world_id: int, *, max_pages=100, on_page=None, page_timeout=6.0):
        """Stop pagination once 100 distinct posts have been collected."""
        if type(max_pages) is not int or not 1 <= max_pages <= 1000:
            raise ValueError('invalid page limit')
        items = {}
        for page_index in range(max_pages):
            if page_index:
                time.sleep(2.0)
            start = page_index * 15
            page = self.query_user_feeds_12956(target_uid, world_id, start, start + 15, timeout=page_timeout)
            new_items = 0
            for feed in page.items:
                if feed.owner_uid != target_uid or feed.world_id != world_id:
                    raise DecodeError('feed identity mismatch')
                if feed.feed_id not in items:
                    new_items += 1
                elif items[feed.feed_id].timeline != feed.timeline:
                    raise DecodeError('feed timeline changed during pagination')
                items[feed.feed_id] = feed
            if on_page is not None and page.items:
                if on_page(page.items) is False:
                    return tuple(sorted(items.values(), key=lambda f: (f.timeline, f.feed_id), reverse=True)[:100])
            if len(items) >= 100:
                return tuple(sorted(items.values(), key=lambda f: (f.timeline, f.feed_id), reverse=True)[:100])
            # Some responses mark a full 15-item page done. Probe the next
            # range instead of silently treating that first page as all posts.
            if not page.items or (page.done and len(page.items) < 15):
                return tuple(sorted(items.values(), key=lambda f: (f.timeline, f.feed_id), reverse=True)[:100])
            if not new_items:
                raise DecodeError('feed pagination did not advance')
        raise DecodeError('feed pagination limit reached; latest snapshot unverified')

    def drain_stale_12959(self) -> int:
        """Reconstructed from main.(*LobbySession).drainStale12959 (0x140312840)."""
        if self.receiver is None or self.cipher is None:
            return 0
        drained = 0
        while self.receiver.pending:
            try:
                self.receive_game(timeout=0.005)
                drained += 1
            except (DecodeError, TimeoutError, EOFError):
                break
        return drained

    def send_like_feed_12958(self, target_uid: int, world_id: int, feed_id: int) -> None:
        """Send once without reading or interpreting a like response."""
        req = build_like_feed_request(target_uid, world_id, feed_id)
        self.send_game_ack(MSG_LIKE_FEED_REQ, req, None)

    def like_feed_12958(
        self,
        target_uid: int,
        world_id: int,
        feed_id: int,
        *,
        timeout: float = 3.5,
    ) -> int:
        """Single-attempt Moments feed like reconstructed from LikeFeed12958 (0x1403128c0).

        Deliberately executes at most one request without automatic retry so callers
        have exact single-like control during live validation.
        """
        self.drain_stale_12959()
        req = build_like_feed_request(target_uid, world_id, feed_id)
        self.send_game_ack(MSG_LIKE_FEED_REQ, req, None)
        deadline = time.monotonic() + timeout
        while True:
            msg = self.receive_game(deadline=deadline)
            if msg.msg_id == MSG_LIKE_FEED_RESP:
                return parse_like_feed_response(msg.body)
