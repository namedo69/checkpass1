# UpLv 0.6.6 — session recovery update

## 0.6.7 follow-up — deployment authorized

- Remove the worker's outer 2/4/8-second fresh-login verification loop. One
  inspection per lease; inconclusive results return to master without a second
  game login in that operation. Normal battle rounds still use existing gates.
- Battle recovery has one pass, with cooperative30-second quiet intervals after
  closing a socket before reopening. Denials still propagate without retry.
  These intervals are conservative scheduling defaults, not a proven server TTL.
- Master persists verification cooldown **from completion**:60s after a battle
  deferral, then120/240s after inconclusive inspection1/2. At inspection3 without
  a conclusive result, pause for manual review instead of looping indefinitely.
- Only existing verified+idle evidence can return an account to the battle pool.
  Unknown/active state remains blocked. Existing failed/stopped tasks are not
  reopened; denial quarantine behavior remains unchanged.
- Preserve the triggering diagnostic separately from the deferral notice.
- VPS customizations require a targeted merge of the new verification budget/
  completion-cooldown logic before any future deployment. Do not overwrite the
  customized master with the repository file.

## Changed
- Server denials still stop the current operation. Duplicate login91117, rate limits and unknown numeric errors are not blanket ban evidence.
- New worker reports distinguish session_conflict, rate_limit, server_error, create_character, login and restricted. Master quarantines the first three as stopped, with a final diagnostic; no automatic re-login or fresh match. This does not count them as success or reopen existing failed tasks.
- Recovery propagates denials immediately, stops reconnect churn on idle/unknown server state, handles ProfileReadbackRequired as a reward-read signal, and skips redundant verification reconnect after UID-bound recovery already confirmed increased profile.
- OAuth bundles are reused only within the same owned room operation, including its verification passes, and removed afterwards. No persisted token cache, app-ID/version rotation or retry429.
- Default generated role names are ten ASCII characters instead of seventeen. Server1007 creation gate, bounded send budget and denial channel policy remain unchanged. Current server name policy is not claimed proven.
- Final sanitized error/stage/root cause survive worker report, coordinator validation, per-task detail and room history. Final error takes precedence over stale CTNV/recovery detail.

## Preserved
Lease/heartbeat ownership and generations, per-account targets, UID/reward checks, unresolved replay guard, Render auto-deploy, CheckPass/VVIP processes, existing production data and failed/stopped account states.

## Validation
Offline tests only; no real account login or test job. Runtime integrity/startup check without game network. Production improvement in settlement success rate is not established by these checks and must be observed on user-submitted work.

VPS master receives a targeted merge preserving its custom queue/recovery and admission limits. Repository main does not overwrite those files wholesale.
