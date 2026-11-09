"""Per-match timing; vendor defaults and original bytecode stay intact."""
MODES = {"surrender": ("Đầu hàng sau 6 phút", 360),
         "victory": ("Yêu cầu WIN sau 3 phút 10 giây", 190),
         "defeat": ("Yêu cầu LOST sau 3 phút 10 giây", 190)}


def configure_match(match, mode):
    if mode not in MODES:
        raise ValueError("Chế độ 5v5 không hợp lệ")
    match.surrender.seconds = 360
    if mode in ("victory", "defeat"):
        if match.outcomes.mode != mode:
            raise ValueError("Các session phải cùng chế độ kết quả trước khi lập đội")
        match.outcomes.seconds = 190
    return match
