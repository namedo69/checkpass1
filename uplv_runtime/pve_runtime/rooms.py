"""Global ready pool: preparation and battle jobs never retain partial teams."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from .uplv import run_five_batch
from .regroup import REGROUP, UNRESOLVED


def run_rooms(accounts, target, rooms, concurrency, stop, prepare, authenticate, progress,
              *, mode='victory', max_rounds=100, checkpoint_store=None, completed=None):
    if len({u.casefold() for u, _ in accounts}) != len(accounts):
        raise ValueError('Danh sách có tài khoản trùng')
    waiting = deque(range(len(accounts)))
    ready = deque()
    checking = deque()
    results = {}
    terminal = set()
    retries = {}
    cached = {}
    idle_check = set()
    slots = deque(range(1, max(1, min(int(rooms), 100)) + 1))
    preparations = {}
    battles = {}

    def publish(index, row):
        # Invoked by battle threads as well as scheduler.
        with publication_lock:
            if index in terminal:
                return
            terminal.add(index)
            results[index] = row
            if completed:
                completed(index, row)

    import threading
    publication_lock = threading.RLock()

    def run_team(room, indexes):
        def status(local, message):
            progress(indexes[local], f'[ROOM {room}] {message}')
        try:
            return run_five_batch(
                [accounts[i] for i in indexes], target, concurrency, stop,
                lambda local, u, p: cached[indexes[local]], authenticate, status,
                mode=mode, max_rounds=max_rounds, prepare_cards=True,
                checkpoint_store=checkpoint_store, allow_regroup=True,
                require_idle={k for k, i in enumerate(indexes) if i in idle_check},
                completed=lambda k, row: publish(indexes[k], row)
                if not stop.is_set() or row[0] else None)
        except Exception as exc:
            return {k: (False, cached[i][1], cached[i][2], UNRESOLVED + ': ' + str(exc))
                    for k, i in enumerate(indexes)}

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as prep_pool, \
            ThreadPoolExecutor(max_workers=len(slots)) as battle_pool:
        while True:
            if not stop.is_set():
                # Bound preparation ahead of available battle capacity.
                capacity = max(5, (len(slots) + 1) * 5)
                while waiting and len(preparations) < max(1, concurrency) and len(ready) + len(preparations) < capacity:
                    index = waiting.popleft()
                    progress(index, '[STACK1] Chuẩn bị vào pool chung')
                    preparations[prep_pool.submit(prepare, index, *accounts[index])] = index
                # Prefer verified-idle members and new replacements. Recheck
                # unresolved sessions only once ordinary work cannot fill a team.
                if not waiting and not preparations and not battles and len(ready) < 5 and checking:
                    while checking and len(ready) < 5:
                        ready.append(checking.popleft())
                while slots and len(ready) >= 5:
                    indexes = [ready.popleft() for _ in range(5)]
                    room = slots.popleft()
                    for i in indexes:
                        progress(i, f'[ROOM {room}] [REGROUP] Ghép đủ 5 từ pool sẵn sàng')
                    battles[battle_pool.submit(run_team, room, indexes)] = (room, indexes)
            active = list(preparations) + list(battles)
            if not active:
                if not stop.is_set() and waiting:
                    continue
                break
            done, _ = wait(active, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in done:
                if future in preparations:
                    index = preparations.pop(future)
                    try:
                        row = future.result()
                    except Exception as exc:
                        row = (False, 0, 0, str(exc))
                    if stop.is_set():
                        continue
                    if row[0] and row[2] >= target:
                        publish(index, row)
                    elif row[0]:
                        cached[index] = row
                        ready.append(index)
                        progress(index, '[REGROUP] Sẵn sàng · chờ đủ 5 trong pool chung')
                    else:
                        publish(index, row)
                else:
                    room, indexes = battles.pop(future)
                    slots.append(room)
                    for local, row in future.result().items():
                        index = indexes[local]
                        if index in terminal:
                            continue
                        if stop.is_set() and not row[0]:
                            continue
                        if row[0]:
                            publish(index, row)
                        elif row[3] == REGROUP or row[3].startswith(UNRESOLVED):
                            retries[index] = retries.get(index, 0) + 1
                            if retries[index] <= 3:
                                cached[index] = (True, row[1], row[2], '')
                                idle_check.add(index)
                                (ready if row[3] == REGROUP else checking).append(index)
                                progress(index, f'[REGROUP] Kiểm tra lại / tái ghép {retries[index]}/3; giữ Lv{row[2]}')
                            else:
                                progress(index, '[DEFERRED] Hết 3 lượt kiểm tra/tái ghép; lưu Chưa xong')
                        else:
                            progress(index, '[STUCK] Phiên chuẩn bị/trận lỗi: ' + row[3])
                            publish(index, row)
        for index in ready:
            progress(index, '[DEFERRED] Pool còn thiếu người hoặc đã dừng; lưu Chưa xong')
        for index in checking:
            progress(index, '[DEFERRED] Phiên cũ chưa rõ; chưa đủ đội kiểm tra tiếp, lưu Chưa xong')
    return results
