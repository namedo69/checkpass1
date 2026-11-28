# UpLv 0.6.15 — auth backpressure and evidence

## Outcome / acceptance boundary

This release fixes worker-side overlapping authentication and throttle
classification. It does **not** establish successful live authentication,
reduced server 429s, or level progression. All regression results below use
synthetic accounts and mocked transports.

At read-only VPS audit timestamp `1795827148.6880598`:

- 42 fresh workers reported `0.6.14-single-room`, all advertising capacity 1.
- Master authoritative capacity 1 was installed; zero owned rooms.
- No tasks belonged to open jobs. No stopped job was reopened or test job created.

## Exact EXE and static findings

User-selected `TLT_UpLevel_Khach.exe (2)/TLT_UpLevel_Khach.exe`:

- Size: 54,148,134 bytes.
- SHA-256: `bf79501a08973c75ac82ce414094ff1def202574b5a5c3a2cd6e594016599c84`.
- Embedded Go engine SHA-256:
  `756be45e7603209cab7f107f22555fb5ca45646c6ec4d95c5303e65b4a87c35a`.
- Canonical REA 6.0.0 artifact identity evidence:
  `ev_d4991443990ee62e82afb9abb8a0b32085593a1e475d5ccc520ea9ed78387d2a`.

REA's artifact result identifies the PE root. Native decompilation returned
`provider_unavailable`: local Ghidra lacks `support/analyzeHeadless.bat`.
Consequently the following code findings come from separate, retained
Capstone/pefile/Go-pclntab static analysis, **not successful REA decompilation
or runtime observation**. The EXE was never run or modified.

| Finding | Static anchor / scope |
| --- | --- |
| Progressive 10/20/30-second throttle wait | `main.recordOAuthRateLimitCooldown`, VA `0x1402be4e0`; instructions `0x1402be55a`–`0x1402be5a0` compute `min(10*(old_streak+1),30)*1e9`, then add to `time.Now`. Later code keeps the later existing deadline. |
| OAuth rc3 triggers cooldown | `main.GarenaTCPLoginOnce`: compare rc to 3 at `0x1402c71cd`, call cooldown at `0x1402c71d7`. |
| HTTP-grant throttle handling | `main.GarenaTCPLoginOnce`: HTTP grant call `0x1402c6cc6`, comparison with 429 at `0x1402c6da5`; cooldown branch at `0x1402c76c0`. |
| Reset after successful token parsing | Calls `main.resetOAuthRateLimitStreak` at `0x1402c6d09` and `0x1402c762e`; reset writes zero to the shared streak. |
| Pacing before network login | `main.GarenaTCPLoginOnce` calls `main.paceGarenaGateway` at `0x1402c5cf5`. Pacing reads shared deadlines under a mutex and uses a timer/context wait. This is in-process state, not proof of fleet-wide coordination. |
| Wrapper defaults, not adaptive feedback | One native child process; GUI passes `-login-gap-ms 2500`, `-login-node-gap-ms 8000`, `-msdk-gap-ms 200`, `-login-concurrency 0`, `-workers 2000`. These are arguments, not 2000 Python processes. Native effective concurrency remains incompletely established. |
| No new Python anti-429 policy | Entry module and PYZ match previous retained extraction; 143/143 PYZ modules identical. No adaptive wrapper retry loop was found in inspected application methods. |

These findings establish backpressure code, not an ability to override a
server denial. Proxy/gateway rotation and CAPTCHA/OTP bypass are not copied.
Full local disassembly, identity JSON, wrapper report and provider diagnostics
are retained under the investigation directory `tlt-analysis`.

## Worker changes

- A single worker-local gate now spans each complete uncached auth flow,
  failure/deadline updates, and lease-local cache insertion.
- Existing minimum 0.6-second start spacing is retained. It is **not** claimed
  to reproduce the EXE's 2.5-second GUI default or its gateway-selection policy.
- Structured rate limits and HTTP 429 cause local 10/20/30-second backpressure.
  Explicit positive finite `Retry-After` wins when longer; a later existing
  deadline is never shortened. One admitted flow at a time avoids a release burst.
- The gate persists across room turnover within the same engine process.
  Credentials are not retried internally after denial; token cache does not
  survive a lease. A process restart does not preserve this local cooldown.
- `stop_event` is passed through TCP, HTTP grant and web-session boundaries.
  STOP prevents subsequent stages and game login, but does not interrupt an
  already-running OS/network request; existing transport timeouts still apply.
- Auth logs distinguish waiting/token success from confirmed game level.
  Unread results display `Lv?`, not a claimed `Lv0` reading.
- No master auth cooldown, room-admission change, CheckPass/VVIP change,
  historical-result migration, or unresolved-match retry change is introduced.

## Validation

- Full root `test_uplv*.py` discovery: **240 tests passed**, genuine child
  process exit code 0. This includes new gate/cancellation tests and existing
  one-room, stopped-job, ownership, failure-policy and match-recovery tests.
- New tests cover maximum one in-flight auth, start spacing, shared deadline,
  10/20/30 cap, explicit server wait, rc3/429, 403/CAPTCHA/OTP no internal retry,
  cache single-flight and lease isolation, STOP boundaries/resource cleanup,
  independent heartbeat during auth wait, and unknown-level reporting.
- `python -B uplv_satellite.py --check-runtime`: `ok=true`, capacity 1,
  Qt absent, network unused, `server_login_verified=false`.
- Only four changed runtime file hashes were refreshed in the bundle manifest.

Live acceptance still requires an authorized open job and observed
profile → match → settlement/readback with an actual level increase. Health,
allocation, token success and synthetic Lv5 fixtures do not meet that criterion.
