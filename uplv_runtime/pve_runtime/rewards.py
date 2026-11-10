"""Focused starter/EXP preparation; no unrelated gifts or purchases."""
import struct

from .loader import load


def install_resource_decoder():
    rewards = load("automatic_rewards")
    original = load("reward_codec").read_login_resources

    def decode(body):
        try:
            return original(body)
        except load("reward_codec").RewardPacketError:
            candidates = []
            marker = struct.pack(">I", 10)
            for at in range(max(0, len(body) - 48)):
                if body[at:at+4] != marker:
                    continue
                n = struct.unpack_from(">I", body, at+44)[0]
                tail = at + 48 + n
                if not 2 <= n <= 1024 or tail + 408 > len(body):
                    continue
                url = body[at+48:tail]
                if not url.startswith((b"http://", b"https://")) or url[-1:] != b"\0":
                    continue
                count = struct.unpack_from(">H", body, tail+406)[0]
                end = tail + 408 + count * 10
                if count > 4 or end > len(body):
                    continue
                try:
                    candidates.append(original(body[at:end]))
                except load("reward_codec").RewardPacketError:
                    continue
            if len(candidates) != 1:
                raise ValueError("Không xác định duy nhất số dư ruby/buff đăng nhập")
            return candidates[0]

    rewards.read_login_resources = decode


def prepare(session):
    rewards = load("automatic_rewards")
    rewards.wait_lobby(session, timeout=8)
    helper = rewards.AutomaticRewards(session, budget=70)
    helper.request(2507, b"\x01", 2508, timeout=5)
    state = session.reward_state
    starter = next((r for r in state.checkins if r.get("weal_id") == 161116001), {})
    if starter.get("rewarded") != 1:
        response = helper.request(2503, rewards.collect_starter_checkin(), 2504, timeout=6)
        if response is None or rewards.response_result(response) != 0:
            raise RuntimeError("Server chưa xác nhận nhận quà tân thủ")
    helper.request(1108, b"\x00", 1109, timeout=5)
    day_ids = set(helper.data["exp_day_inventory_ids"])
    day_cards = [r for r in state.inventory.values() if r["item_id"] in day_ids and r["count"] > 0]
    if not state.inventory_known or (not day_cards and state.exp_active() is not True):
        raise RuntimeError("Chưa thấy thẻ EXP ngày hoặc buff tương ứng sau nhận quà")
    if type(state.ruby) is not int:
        raise RuntimeError("Chưa đọc được ruby; không mua thẻ")
    helper.prepare_exp()
    helper.prepare_win_exp()
    helper.request(1108, b"\x00", 1109, timeout=5)
    return {"ruby": state.ruby, "inventory": list(state.inventory.values()),
            "multipliers": state.multipliers, "day_active": state.exp_active(),
            "wins_active": state.win_exp_active()}


def prepare_optional(session, notify=lambda message: None):
    """Try every EXP preparation stage independently; card failure is optional."""
    rewards = load('automatic_rewards')
    helper = rewards.AutomaticRewards(session, budget=70)
    warnings = []

    def attempt(label, action):
        session.check_stop()
        try:
            return action()
        except Exception:
            session.check_stop()
            warnings.append(label)
            notify(f'[EXP_OPTIONAL] {label} chưa thành công; tiếp tục bước kế tiếp')

    attempt('Đọc quà tân thủ', lambda: helper.request(2507, b'\x01', 2508, timeout=5))
    state = session.reward_state
    starter = next((r for r in state.checkins if r.get('weal_id') == 161116001), {})
    if starter.get('rewarded') != 1:
        def claim():
            reply = helper.request(2503, rewards.collect_starter_checkin(), 2504, timeout=6)
            if reply is None or rewards.response_result(reply) != 0:
                raise RuntimeError('Starter reward not confirmed')
        attempt('Nhận quà tân thủ', claim)
    attempt('Đọc túi đồ', lambda: helper.request(1108, b'\x00', 1109, timeout=5))
    attempt('Mua/dùng thẻ EXP ngày', helper.prepare_exp)
    attempt('Mua/dùng thẻ EXP trận thắng', helper.prepare_win_exp)
    attempt('Đọc lại túi đồ', lambda: helper.request(1108, b'\x00', 1109, timeout=5))
    return {'warnings': warnings}
