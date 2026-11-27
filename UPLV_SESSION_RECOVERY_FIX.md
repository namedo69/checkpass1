# UpLv 0.6.6 — session recovery update

## 0.6.10 — 429 durable retry / fixed 30-second waits

- 2026-11-27 19:50 VN admission hotfix: production snapshot showed only
  30 battle accounts plus3 inspections with26929 waiting and42 live workers.
  A1-room/30s fleet pacing tail was perpetually renewed by old retry rows,
  even without recent429. Remove claim-time pacing writes and ignore legacy
  pace_until/next_admit fields; only until_at from a fresh429 blocks admission
  for30s. Per-account30s retry, leases and unresolved-match gates unchanged.
  169 offline tests pass, including42 workers admitted in one clock instant
  after cooldown despite stale pacing fields. Two-file targeted VPS install,
  backup `/home/sp1s/uplv-rate-speed-backup-20261127_195013`, health in1.738s,
  all3 active-room ownership tokens and251510 terminal statuses preserved;
  sibling CheckPass/VVIP PIDs unchanged. First read-only snapshot after install:
  49 assigned across10 rooms, not proof of sustained throughput or auth health.
- User correction: 429 must queue, not stop an account. Subsequent correction:
  use a fixed 30 seconds, not increasing minute-scale delays. Applies to 429,
  generic post-match verification and 91117 session-release checks. Existing
  verification/session check limits remain unchanged for non-throttled reads.
- Separate `uplv_rate_limit_wait` records retain attempts, due time and resume
  path. Initial-game throttles return to game preparation (with existing idle
  guards), while read-only throttles return to read-only inspection. A 429
  refunds that inspection's check count; its queued time does not spend the
  session-release deadline. Repeated 429 alone never exhausts a terminal budget.
- Durable fleet admission cooldown starts on a new 429 checkpoint or report.
  Heartbeat renewals and reports continue; identical heartbeat checkpoints do
  not keep extending cooldown. After the admission hotfix, all available workers
  can resume after30s; no fleet pacing tail remains. Existing leased rooms
  are not revoked. Claims replayed by request ID remain idempotent.
- Account details expose status/due time/429 count; admin/user filters label
  the wait. Pending exports, exclusive ownership, incomplete-tail protection,
  stop/clear and expired-lease cleanup include this queue. Final room, account
  queue and due-time changes commit together so a failed report can be retried.
- Read-only worker auth 429 is classified as rate_limit, not restricted. No
  runtime asset changes or extra inline credential retries. Profile trailer
  failures and HTTP200 auth diagnostic loss remain separate, unresolved issues.
- User authorized push/deploy. No historical terminal tasks/jobs are reopened
  and no real-account tests are permitted. VPS rollout must preserve custom admission/priority/recovery capacity and use
  backups plus guarded targeted merges; it is not an HTML-only deployment.
- Master deployed 2026-11-27 19:28 VN: four targeted files installed after
  168 offline candidate tests and 10 UI tests. Backup:
  `/home/sp1s/uplv-rate-limit-backup-20261127_192818`. Health ready in 1.22s;
  CheckPass/VVIP PIDs unchanged, dependencies restored. All 251294 historical
  terminal task IDs/statuses and all job statuses unchanged across cutover.
  Worker release is `uplv-satellite-0.6.10-rate-limit-queue`; confirm Render
  auto-deploy health separately after push, not from local test success.

## 0.6.9 direct-game/profile follow-up — PUSH/DEPLOY AUTHORIZED

- Rollout verification follow-up: the master's resource telemetry allowlist
  initially discarded `direct_game_protocol` even though fresh claims used it.
  Preserve only integer protocol `1` from heartbeat metrics; do not infer an
  upgrade from liveness alone. 20 configured health endpoints reported the new
  version; full fleet coverage must be verified after this telemetry correction.
  149 offline regressions include invalid-protocol and credential-filter tests.
- Deployment verified 2026-11-27: master active; 42/42 fresh live satellite
  heartbeats advertise direct_game_protocol=1, and 20/20 configured health URLs
  are healthy on uplv-satellite-0.6.9-direct-game. 45 synthetic tests passed
  against installed master imports. No real-account tests were performed.
  Job statuses and terminal task counts stayed unchanged; CheckPass/VVIP PIDs
  remained unchanged. Targeted VPS customizations and auto-deploy were retained.

- Reproduced an idle-decoding defect with synthetic encrypted-frame payloads:
  the bundled capture parser leaves pre-tsf4g padding in body_full. Comparing
  that entire value with one-byte1061 `00` rejects valid idle replies. The V2
  profile adapter now validates/removes the full trailer before extracting CS
  bodies. Unknown, malformed, busy, closed and denied replies never imply idle.
  Reads remain create=False/verify_only; one1060 probe, no match/re-login loop.
- A synthetic end-to-end worker-report/master test confirms idleLv3 returns to
  waiting/preparation, with wait budget cleared, rather than another inspection.
  This establishes a code defect/fix, NOT the cause of every liveLv3 stop or a
  measured production recovery rate. No claim that all historical waits recover.
- Supersedes the UNDEPLOYED auxiliary-feeder proposal at user request: no3x
  precheck tuning. New uploads/additions enter waiting directly, not screening.
  Level0 in the database means unconfirmed metadata, NOT a confirmed missing
  role. The existing game preparation/login reads actual level; a confirmed
  target account finishes, lower levels use existing preparation and PvE flow.
- Stop issuing hidden/direct CheckPass claims for UpLv accounts. Keep old report
  endpoints compatible for already-running owners; do not change ordinary or
  explicitly pinned CheckPass jobs. UpLv no longer loads the checker for uploads.
- Drain at most5 old screening tasks per room-formation call, only for open jobs
  and after any claimed hidden chunk/direct lease expires plus120s cleanup grace.
  Still-live owners are not stolen. Late reports cannot overwrite assigned or
  terminal tasks. No bulk migration or production DB edit has been run locally.
- Remove Kiện Tướng fallback from read-only recovery too: a failed/unknown game
  read stays unresolved, without another web/SSO profile login. Game-only match
  confirmation remains in use; optional web client utilities remain unused by
  the UpLv engine. OAuth exchange is still required for game authentication.
- Require the existing UID/idle/old-match gate for every member entering5v5,
  including fresh uploads with unknown level. Do not remove reward validation.
- Game denial classification is preserved:91126 restricted/ban code,91117
  session conflict (not ban),91123 registration-name rejection; unknown server
  errors/429 stop their operation and do not imply ban or trigger bypass/retry.
- Durable diagnostics separate previous_error from the current last_check; a
  later no-denial result no longer appears as six repeated91117 errors merely
  because the original error was retained. Historical room snapshots stay intact.
- Do NOT increase room limits/check budgets, reopen terminal tasks, change the
  missing-profile-after-create policy or edit runtime bundle assets.
  Backups: backups/before_screening_recovery_20261127_141001/ and
  backups/before_direct_game_login_20261127_153448/.
- Deployment requires game-only workers for new claims: direct_game_protocol=1
  is mandatory on master admission, and is advertised in worker metrics/claims.
  Old workers can finish/report existing leases but cannot claim fresh work.
  Push workers then switch master with this guard during the rolling update;
  use a targeted VPS merge preserving admission/priority/live recovery capacity;
  do not overwrite customized master/account-pool/coordinator files wholesale.
- Validation:148 offline regressions, including upload/add -> direct claim,
  legacy ownership/grace, game-level reads, target completion,91126/91117/429,
  missing-profile stops and padded-idleLv3 recovery. No live-account test,
  production throughput measurement. User authorized push/deploy afterwards.
- Final integrity checks:9 changed/new Python files compile, git diff --check
  clean, all90 runtime manifest entries unchanged/verified, both backup manifests
  verified (9 and12 files), runtime self-check network-free and Qt-free.

## 0.6.8 session-wait follow-up — push/deployment authorized

- New `session_wait` state retains account exclusivity and keeps the owning job
  open, but frees the physical room after the worker has closed its operation.
  Fresh `91117/session_conflict` results enter this queue, not immediate stop.
- Durable `uplv_session_wait` stores a separate check count, start and next time.
  Quiet intervals start at completion:120s initially, then240/480/900s (900s
  capped). Maximum6 read-only inspections and2 hours per unresolved wait cycle.
  These are conservative defaults, NOT a proven server TTL or success guarantee.
- Due work uses existing verify-only leases; no novice preparation/battle is run
  during a release check. Unknown/active state stays queued, even if a profile
  was read. Only verified+idle re-enters preparation (belowLv5) or ready (Lv5+).
  A confirmed target result can finish; silence cannot manufacture idle/reward.
- The match-verification three-pass budget is neither consumed nor reset by
  session-release checks. Verified+idle/target completion clears wait metadata.
  Expired wait/check limits pause for manual review with91117 diagnostics.
- Lost workers retain wait deadline/count after normal lease+120s cleanup.
  A91117 result persisted in heartbeat also enters the wait queue if the final
  report is lost. Late revoked-token/generation reports are still rejected.
- Explicit job stop wins; no migration or reopening of old stopped/failed tasks,
  including job f85e5d61.429/unknown server errors keep their previous quarantine.
- Admin/user pages show the wait state; admin details show its own budget, due
  time and deadline. Keep nonterminal waits out of unfillable-tail finalization.
- Preserve verification-wait diagnostics instead of retaining only old CTNV text.
- This does NOT fix the separate noviceLv3 continuation dead end, registration
  error91123, auth429 throughput, or prove the source of91117 session conflicts.
- Future VPS deployment requires an exact-hash guarded targeted merge preserving
  its custom admission/queue/recovery-capacity settings; do not copy the local
  coordinator/account-pool wholesale. Existing database is not touched locally.
- Local validation:125 offline tests passed (26 new session-wait regressions),
  runtime startup/integrity check passed without game network, both page scripts
  passed JavaScript syntax checks. VPS-targeted candidate:67 offline tests passed;
  customized admission, queue priority, recovery capacity and nonblocking reads
  preserved. No real-account login or production test job used for validation.

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
