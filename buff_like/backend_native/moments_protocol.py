"""Moments profile resolution, feed query, and single-like payload encoding/decoding; no network calls."""
from dataclasses import dataclass
from .reader import DecodeError, Reader

MSG_RESOLVE_PROFILE_REQ = 0x4B4
MSG_RESOLVE_PROFILE_RESP = 0x4B5
MSG_QUERY_FEEDS_REQ = 0x329C
MSG_QUERY_FEEDS_RESP = 0x329D
MSG_LIKE_FEED_REQ = 0x329E
MSG_LIKE_FEED_RESP = 0x329F

MAX_SECTION_ITEMS = 10000


@dataclass(frozen=True)
class PlayerProfile:
    target_uid: int
    world_id: int
    name: str
    likes: int = 0
    hot: int = 0
    level: int = 0
    vip: int = 0
    likes_available: bool = False


@dataclass(frozen=True)
class MomentsFeedItem:
    owner_uid: int
    world_id: int
    feed_id: int
    text_bytes: bytes
    timeline: int
    like_count: int
    comments: int

    @property
    def text(self) -> str:
        return self.text_bytes.decode('utf-8', 'replace')


@dataclass(frozen=True)
class MomentsAccountEntry:
    uid: int
    world_id: int
    nickname_bytes: bytes
    avatar_bytes: bytes

    @property
    def nickname(self) -> str:
        return self.nickname_bytes.decode('utf-8', 'replace')

    @property
    def avatar(self) -> str:
        return self.avatar_bytes.decode('utf-8', 'replace')


@dataclass(frozen=True)
class MomentsFeedPage:
    items: tuple[MomentsFeedItem, ...]
    accounts: tuple[MomentsAccountEntry, ...]
    done: bool


def build_resolve_profile_request(name: str) -> bytes:
    """Reconstructed from main.(*LobbySession).ResolvePlayerProfile1205 (0x140310640)."""
    trimmed = name.strip()
    raw = trimmed.encode('utf-8')
    if not 1 <= len(raw) <= 64:
        raise ValueError('character name UTF-8 length must be 1..64 bytes')
    if any(ord(ch) < 0x20 for ch in trimmed):
        raise ValueError('character name must not contain control characters')
    return b'\x00' + (len(raw) + 1).to_bytes(4, 'big') + raw + b'\x00'


def parse_resolve_profile_response(body: bytes, requested_name: str) -> PlayerProfile:
    """Reconstructed from main.(*LobbySession).ResolvePlayerProfile1205 (0x140310640)."""
    r = Reader(body)
    status = int.from_bytes(r.take(4), 'big', signed=True)
    flag = r.take(1)[0]
    if status != 0 or flag != 0:
        raise DecodeError(f'profile lookup 1205 rejected (status={status}, flag={flag})')
    target_uid = r.u64()
    world_id = r.u32()
    resolved_raw = r.moments_string_bytes()
    expected_name = requested_name.strip()
    if resolved_raw != expected_name.encode('utf-8') or target_uid == 0 or world_id == 0:
        raise DecodeError('resolved profile does not match requested character name')

    hot = 0
    likes = 0
    level = 0
    vip = 0
    likes_available = False
    try:
        r.moments_string_bytes()  # avatar URL
        r.take(13)
        hot = r.u32()
        r.take(8)
        r.moments_string_bytes()  # signature
        if r.remaining >= 0x64:
            tail = r.take(0x64)
            level = int.from_bytes(tail[0x18:0x1C], 'big')
            vip = int.from_bytes(tail[0x1C:0x20], 'big')
            likes = int.from_bytes(tail[0x60:0x64], 'big')
            likes_available = True
    except DecodeError:
        pass

    return PlayerProfile(
        likes_available=likes_available,
        target_uid=target_uid,
        world_id=world_id,
        name=expected_name,
        likes=likes,
        hot=hot,
        level=level,
        vip=vip,
    )


def build_query_user_feeds_request(
    target_uid: int,
    world_id: int,
    start_index: int = 0,
    end_index: int = 15,
) -> bytes:
    """Reconstructed from main.(*LobbySession).QueryUserFeeds12956 (0x140310fc0)."""
    if not 0 < int(target_uid) < 2**64:
        raise ValueError('target_uid must be a positive uint64')
    if not 0 <= int(world_id) < 2**32:
        raise ValueError('world_id must be uint32')
    if not (0 <= int(start_index) < 2**32 and 0 <= int(end_index) < 2**32):
        raise ValueError('start_index and end_index must be uint32')
    return (
        int(target_uid).to_bytes(8, 'big')
        + int(world_id).to_bytes(4, 'big')
        + int(start_index).to_bytes(4, 'big')
        + int(end_index).to_bytes(4, 'big')
    )


def parse_query_user_feeds_response(body: bytes) -> MomentsFeedPage:
    """Reconstructed from main.(*LobbySession).QueryUserFeeds12956 (0x140310fc0)."""
    r = Reader(body)
    status = int.from_bytes(r.take(4), 'big', signed=True)
    flag = r.take(1)[0]
    if status != 0 or flag != 0:
        raise DecodeError(f'Moments query 12957 rejected: code={status} flag={flag}')

    feed_count = r.u32()
    if feed_count > MAX_SECTION_ITEMS:
        raise DecodeError('Moments feed count exceeds limit')

    items = []
    for _ in range(feed_count):
        owner_uid = r.u64()
        world_id = r.u32()
        feed_id = r.u64()
        text_bytes = r.moments_string_bytes()
        media_count = r.u32()
        if media_count > MAX_SECTION_ITEMS:
            raise DecodeError('Moments media count exceeds limit')
        for _ in range(media_count):
            r.moments_string_bytes()
            r.moments_string_bytes()
        timeline = r.u32()
        like_count = r.u32()
        r.take(2)
        comments = r.u32()
        r.take(13)
        items.append(
            MomentsFeedItem(
                owner_uid=owner_uid,
                world_id=world_id,
                feed_id=feed_id,
                text_bytes=text_bytes,
                timeline=timeline,
                like_count=like_count,
                comments=comments,
            )
        )

    unk_count = r.u32()
    if unk_count > MAX_SECTION_ITEMS:
        raise DecodeError('Moments secondary count exceeds limit')
    r.take(unk_count * 28)

    acct_count = r.u32()
    if acct_count > MAX_SECTION_ITEMS:
        raise DecodeError('Moments account count exceeds limit')
    accounts = []
    for _ in range(acct_count):
        uid = r.u64()
        world_id = r.u32()
        nickname_bytes = r.moments_string_bytes()
        avatar_bytes = r.moments_string_bytes()
        r.take(9)
        accounts.append(
            MomentsAccountEntry(
                uid=uid,
                world_id=world_id,
                nickname_bytes=nickname_bytes,
                avatar_bytes=avatar_bytes,
            )
        )

    done_flag = r.u32()
    return MomentsFeedPage(
        items=tuple(items),
        accounts=tuple(accounts),
        done=(done_flag == 1),
    )


def build_like_feed_request(target_uid: int, world_id: int, feed_id: int) -> bytes:
    """Reconstructed from main.(*LobbySession).LikeFeed12958 (0x1403128c0) 40-byte payload."""
    if not 0 < int(target_uid) < 2**64:
        raise ValueError('target_uid must be a positive uint64')
    if not 0 <= int(world_id) < 2**32:
        raise ValueError('world_id must be uint32')
    if not 0 < int(feed_id) < 2**64:
        raise ValueError('feed_id must be a positive uint64')
    return (
        int(target_uid).to_bytes(8, 'big')
        + int(world_id).to_bytes(4, 'big')
        + int(feed_id).to_bytes(8, 'big')
        + (1).to_bytes(4, 'big')
        + b'\x00' * 16
    )


def parse_like_feed_response(body: bytes) -> int:
    """Reconstructed from main.(*LobbySession).LikeFeed12958 (0x1403128c0) 0x329f check."""
    if len(body) < 4:
        raise DecodeError('like response 12959 shorter than 4 bytes')
    return int.from_bytes(body[:4], 'big', signed=True)
