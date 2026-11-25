# Kovo Hunter security re-audit (adversarial, read-only)

- Date: 2026-11-22
- Repo: `/home/omarchy/kovo-hunter`
- HEAD: `3c0a547` (merge of `probe-split` + compat audit)
- Fix commits in scope (all confirmed ancestors of HEAD): `6350a4f` (Tier-3 approvals), `ad853ab`/`fec9df8` (session/IdP/browser), `dbcc773` (repo/worker/lab).
- Method: trace real call paths, then try to refute each claim with targeted `node --test` runs and small throw-away probes under `/tmp` (no repo/source edits, no benchmarks, no commits).
- Tests run: `node --test tests/v5-security-approvals.test.ts tests/v5-security-repo.test.ts tests/v5-security-authbrowser.test.ts` → **33/33 pass**.

Framing: defensive authorization/scope re-audit of a local, authorized security-testing tool. “Probe” below means an in-scope defensive verification request; no exploit payloads are reproduced here.

---

## Verdict table

| # | Finding | Verdict | One-line basis |
|---|---------|---------|----------------|
| 1 | HIGH Tier-3 approval reuse | **PARTIAL** | Fingerprint/single-use/scope binding is real, but two pre-approval gates and 307/308 redirects still bypass the exact-path grant; operator patterns over-match and can cover RCE when context is omitted. |
| 2 | HIGH symlink escape | **PARTIAL** | Repo-content escape is closed; the “deepest existing parent” containment primitive still accepts a *dangling* symlink, and a create-file patch writes through it (latent, not repo-reachable today). |
| 3 | MED bootstrap session | **FIXED** | Only an exact 64-hex `?bootstrap=` GET mints a cookie, single-use with no await in the check/set window, 401 otherwise; no other route issues the cookie. |
| 4 | MED Clerk/provider host scope | **PARTIAL** | “PSL-aware” is a hardcoded partial list; private/multi-tenant suffixes (`github.io`, `vercel.app`, `com.co`, `s3.amazonaws.com`, …) collapse to the suffix and authorize attacker-controlled sibling tenants. Form login never validates its login URL. |
| 5 | MED credential redirects + SSRF | **PARTIAL** | Redirects are manual and fail closed; address classification is sound, but checked addresses are **not pinned**, zero-address resolutions and `unknown` browser results are accepted, and the browser re-resolves at connect. |
| 6 | MED browser egress (`scoped-browser.ts`) | **FIXED** | All listed controls are present and fail closed; residual egress via WebTransport/IP literal and a fail-open `routeWebSocket` fallback remain (see residuals). The bigger gap is that the same guards were not applied to the persona form-login browser. |
| 7 | MED lab container | **PARTIAL** | Non-root/read-only/cap-drop/no-socket are present, but `KOVO_LAB_USER=00:00` passes the root check, and the IAST telemetry bind mount is RW and shared across runs. |
| 8 | MED approval fast paths | **PARTIAL** | GraphQL envelope/multipart/rationale fixes hold, but the older idempotent-POST gate bypasses the whole approval pipeline, duplicate JSON keys are parity-unsafe, and >64 KiB or gzip bodies evade the keyword scan. |
| 9 | MED worker output bounds | **FIXED** | 64 KiB/line + 4 MiB/session enforced with terminate-on-overrun; stderr bounded separately; no buffered/before-check allocation found. |

---

## 1. HIGH — approval reuse / exact single-use fingerprint

**What the fix actually does (verified):**
- `buildStateChangeFingerprint` binds `runId, origin, method, exact pathAndQuery, persona, body/parts hash, scopeRevision, multipart/race/rce flags` (`src/server/approval-judge.ts:296-311`).
- Grant TTL is 60 s (`approval-judge.ts:319`); `consume()` deletes the key first and then checks expiry (`approval-judge.ts:341-347`).
- Persisted rows are audit-only, documented and not read for authorization (`src/server/store.ts:2172-2213`; the old DB/prefix lookup was removed from `buildGrant`).
- The broker passes real context: persona, body bytes, multipart/race flags (`src/server/broker.ts:2381-2393`), and the race path marks every request as a burst (`broker.ts:3109`).
- Scope changes invalidate: `decideApproval` cancels on a revision mismatch (`store.ts:2244-2251`), and consumption uses `fresh.scopeRevision` (`src/server/execution.ts:1183-1193`).

**Attempts to refute:**
- Replay same fingerprint: `consume()` is synchronous and deletes on first match; a second call fails (test `tests/v5-security-approvals.test.ts:420-422`).
- Different persona/body/flags/path: covered by the test at `:414-418`.
- Forged by a missing context: callers without context cannot consume a one-shot grant at all (`approval-judge.ts:408`), so this fails **closed**.
- Run/scope change survival: runId and scope revision are in the key; fail closed.
- Local-lab path: `localLabAutoApproval` is evaluated before patterns/ledger and returns `approved` for every request at that origin (`approval-judge.ts:394-396`), but it requires `environment=local-lab`, `KOVO_ALLOW_LOCAL_LAB=1`, tier ≥ 3, non-strict policy, and `isLocalLabAutoApprovalOrigin` (`execution.ts:1171-1176`). Metadata/link-local hosts are rejected there (`approval-judge.ts:192-197`) and independently by the broker’s unconditional link-local resolver check (`broker.ts:2140-2153`). I could not bypass the origin binding. This is intentional per-run lab behavior, not a grant reuse.

**Remaining bypasses (why PARTIAL):**

1. **307/308 redirect re-sends an already-approved state change to a different path with no re-approval.** `prepareHttpRequest` is called once; the redirect loop only re-runs `check()` (origin scope) and re-sends `activeBody` for 307/308 (`broker.ts:2957-2976`). Verified with a fake transport: a POST approved for `/safe-update` was re-sent as `POST /dangerous-delete` with only one approval callback. The returned exchange even records the original `req.pathAndQuery` (`broker.ts:3016`), so the audit/evidence path does not show the redirect target. This directly defeats “exact path+query” approval for any agent/browser request with `followRedirects: true` (browser path passes `true` at `scoped-browser.ts:829`; `request_http` honours the caller flag at `execution.ts:5158`).

2. **The pre-approval idempotent-POST gate bypasses the entire approval system.** `execution.ts:749-753` allows any Tier-2+ POST whose path contains `graphql|search|query|introspect` and whose raw body does not contain the literal word `mutation`. The broker consults this before the Tier-3 block (`broker.ts:2364-2372`), so `isStateChangeApproved` is never called. Verified: a state-changing POST to `/api/query` executed at Tier 2 with **zero** approval checks.

3. **Operator patterns over-match.** `matchesApprovedEndpointPattern` wildcards target segments that merely *look* like IDs when normalizing the pattern (`approval-judge.ts:122-140`), then matches `*` against **any** literal segment and lets a trailing `*` match arbitrary depth (`approval-judge.ts:220-228`). Verified: a pattern derived from `POST /api/items/123` matches `POST /api/items/delete` and `POST /api/items/123/settings`, and pattern matching happens before hard escalation (`approval-judge.ts:693-730`). An operator who approved an item-update endpoint can therefore pre-approve a destructive verb at the same depth.

4. **Operator patterns can cover RCE proofs when context is omitted.** `authorizeStateChange` only excludes patterns when `context.isRceProof` is truthy (`approval-judge.ts:400`). The replay verifier and the SQL-time differential probe call the hook **without context** (`src/server/replay-verifier.ts:627-633`, `src/server/probes/injection.ts:205`), so a matching operator pattern authorizes an `rce_proof`/upload replay even though `evaluateTier3Approval` would have refused it. This also means judge/operator grants registered for those specs are unusable (see “New risks”).

---

## 2. HIGH — symlink escape (repo copy, recon walkers, patch workflow)

**Fixed and verified:**
- CLI mount copy uses `lstat` filtering, `dereference:false`, and a post-copy link sweep that fails closed and removes the copy (`scripts/cli.ts:383-437`).
- Recon walkers use `lstat`, refuse to traverse links, canonicalise the root, and read final files with `O_NOFOLLOW` (`src/server/phase0-recon.ts:253-330`, `631-680`).
- Patch work copies are link-free and re-verified (`src/server/patch-workflow.ts:198-220`); mounted repo roots that are links are rejected (`patch-workflow.ts:178-187`).
- Tests cover file/dir links, manifest links and traversal (`tests/v5-security-repo.test.ts:76-199`).
- Hardlinks: not reachable as an escape here. `cpSync`/`copyFileSync` create new inodes, so the writable patch/lab trees do not preserve attacker hardlinks.
- Tar/zip entries: no tar/zip import exists in the patch path, so that vector is not present.
- Case/unicode: containment is `resolve`/`relative`-based on a case-sensitive filesystem; no normalization or case-folding bypass found.

**Refutation (latent but real): the containment primitive accepts a dangling symlink, and the create path writes through it.**
`safeResolveUnderRoot` uses `existsSync` both to find the deepest existing parent and to walk components (`src/server/lab-runner.ts:692-716`). `existsSync` follows links, so a symlink whose target does **not** exist returns false: the loop `break`s and the link is never `lstat`ed. `applyUnifiedDiffToDirectory` treats the target as non-existent, and for a create-file hunk (`--- /dev/null`) writes normally (`lab-runner.ts:913-918`, `976-983`). Verified under `/tmp`: a create-file diff targeting `dangling.ts` created the file at the link’s outside target and reported success.

Preconditions: a writable tree containing a dangling link at the moment the patch is applied. Today the two call sites use (a) a freshly copied, link-free mkdtemp tree and (b) `sanitizedRepoDir`, which is copied link-free and bind-mounted **read-only** into the lab (`lab-runner.ts:1293,1298`). So this is not reachable from repo content today, but the primitive is not sound and will fail if any later code path makes the tree writable. Residual TOCTOU on intermediate directories also remains in the recon walkers and in `safeResolveUnderRoot`, but it requires a concurrent same-uid writer, which is already outside the remote threat model.

---

## 3. MED — bootstrap session issuance

**Verified:**
- A session cookie is set in exactly one place: the bootstrap branch (`scripts/serve.ts:173-186`). No other route sets `kovo_local`; the app response’s `set-cookie` is only forwarded after an authorized request (`serve.ts:188-224`).
- Only `GET` with a `bootstrap` search param is accepted; `HEAD` falls through to 401. `isBootstrapAuthorized` requires exactly 64 lowercase hex chars and uses `timingSafeEqual` after a length check (`serve.ts:74-83`).
- Single use is safe against a race: `bootstrapConsumed` is checked and set synchronously with no `await` in between, then the 0600 file is removed (`serve.ts:176-181`). A second attempt gets 401 (`tests/v5-security-authbrowser.test.ts:107-108`).
- The 303 strips the secret from `Location` (`serve.ts:182-184`), and `Referrer-Policy: no-referrer` is set.
- `/health` returns only `ok`; static assets are a strict filename allowlist under `build/client/assets` and are public (`serve.ts:154-171`) — no session/token material.
- Cookie is `HttpOnly; SameSite=Strict`, with `Secure` on HTTPS (`serve.ts:85-87`).
- Duplicate/encoded params: `searchParams.get` returns the first value and the candidate is re-validated as strict hex; neither form opens a bypass without knowing the 256-bit secret.

**Caveats (not bypasses):** the secret is accepted on any GET path, not only `/`; the bootstrap branch has no `Sec-Fetch-Site` check (possession of the secret is the credential); the URL is printed to stdout and written to `bootstrap-url` (0600; that file is not deleted on consumption); a reverse proxy in front of `KOVO_PUBLIC_ORIGIN` may log the request line containing `?bootstrap=`. The long-lived session token is port-agnostic under browser cookie rules, so another service on `localhost` can receive it on a same-site top-level navigation (it cannot read the HttpOnly value, but its server sees the header).

---

## 4. MED — Clerk / provider host binding and registrable domain

**Fixed:** `isOriginInScope` gating on the publishable-key-derived host and on the `clerk.` FAPI match (`src/server/persona-auth.ts:483-494`), manual redirects for discovery (`:471-480`), and an explicit allowlist check on operator-supplied Clerk login URLs (`:705-713`). Publisher-key decoding rejects non-host shapes (no userinfo/port) (`:140-150`). IDN input is normalized by `URL` on both sides, so homograph/trailing-dot tricks did not produce a match.

**Refutation: “PSL-aware” is a hardcoded partial suffix list, and it fails open for platform/private suffixes.**
`registrableDomain` only special-cases the ~90 suffixes in `multiLabelPublicSuffixes` (`persona-auth.ts:158-202`). For any other multi-label public **or private** suffix, `lastTwo` is treated as the suffix, so the “registrable domain” becomes the suffix itself. Verified against the real module:

```
https://app.example.github.io  -> registrable "github.io"
https://app.example.vercel.app -> registrable "vercel.app"
https://a.b.example.com.co     -> registrable "com.co"
https://app.example.s3.amazonaws.com -> registrable "amazonaws.com"
isHostInScope("evil.github.io", ["https://app.example.github.io"]) === true
```

Consequences: for a persona whose target is a tenant on a shared platform (GitHub Pages, Vercel, Netlify, S3, many ccTLD second-level registries), **any attacker-controlled sibling tenant is “in scope”**. A target document containing a publishable key/fapi string for such a host (or the `clerk.<registrable>` fallback at `:722-730`) passes `isOriginInScope`, and `assertCredentialTarget` then only checks scheme/host/DNS — so persona credentials can be POSTed to the attacker’s tenant. The same widened scope is used for form-login read-only subresources (`:1335,1352`).

**Second bypass (same finding): form login does not enforce the allowlist at all.**
`authenticateForm` builds `loginOrigin` and adds it to `allowedOrigins` unconditionally (`persona-auth.ts:1261-1264`); there is no `assertCredentialTarget` and no HTTPS check, unlike Clerk/Supabase/JSON (`:747,937,1103`). A `loginUrl` outside the persona allowlist (or plain HTTP) causes the browser to type the password into that origin. The route interceptor treats it as “exact allowed” (`:1351-1353`) and DNS-checks only that it is public (`:1359`).

`isOriginInScope` also ignores ports and userinfo (it checks `parsed.hostname` only, `:233-241`), so `https://<in-scope-host>:<any-port>` and a userinfo-bearing config URL are accepted. Low impact on its own, but it widens the destination set.

---

## 5. MED — credential POST redirects and SSRF

**Fixed:** `fetchWithTimeout` forces `redirect: 'manual'` after spreading caller init (`persona-auth.ts:444`), so the CSRF prefetch’s `redirect: 'follow'` cannot take effect. Every credential-bearing call site rejects 3xx before parsing (`:771, 854, 954, 1012, 1117, 1161`), and provider discovery turns a 3xx into “no Clerk detected” (`:478-480`). `assertCredentialTarget` enforces HTTPS except explicitly allowlisted loopback, and rejects a resolved address that is private/loopback-not-exact/link-local/metadata (`:547-582`). `classifyAddress` uses `ipaddr.process`, which collapses IPv4-mapped IPv6 (`::ffff:127.0.0.1` → loopback) and does not treat NAT64/6to4/Teredo as public (`:251-259`). HTTP→HTTPS downgrade via redirect is impossible because redirects are not followed.

**Refutation (why PARTIAL): the validated address is not the connected address.**
- `assertCredentialTarget` resolves, classifies, then returns the URL; the later `fetch` resolves again (`:574-581`). Nothing pins the IP, so a DNS answer of “public” at check time and “loopback/LAN” at connect time passes. This is the exact rebinding window the fix was meant to close; the request broker pins the address (`broker.ts:2907`), persona-auth does not.
- **Zero addresses are accepted**: `resolveHost` returns `[]` on lookup failure (`:531-537`) and the loop at `:574-580` performs no check for an empty list, so an NXDOMAIN-then-rebind answer sequence bypasses classification entirely (the comment “the ensuing fetch fails closed” is not true when the second lookup succeeds).
- `hostIsSafeForBrowser` classifies an empty resolution as `unknown` and treats `unknown` as safe, then caches the verdict for 60 s (`:585-606`). The browser then `route.continue()`s (`:1363`), so Chromium resolves independently: check-to-connect rebinding is open for the whole cache window.
- If Node runs with an environment proxy (`NODE_USE_ENV_PROXY`/`--use-env-proxy`), DNS and egress move to the proxy, so the post-check addresses do not describe the actual connection.
- `classifyAddress('localhost')` is `blocked`, while `127.0.0.1` and `[::1]` are accepted. That is fail-closed but breaks an explicitly allowlisted `http://localhost:<port>` lab login (see New risks).
- The CSRF prefetch will read `Set-Cookie` from a 3xx response because it does not reject redirects (`:1072-1082`); the URL is operator config, so this is low risk.

---

## 6. MED — scoped browser egress

**Verified as fixed in `src/server/scoped-browser.ts`:**
- Sandbox on by default; `--no-sandbox` only with `KOVO_INSECURE_NO_SANDBOX=1` plus a warning (`:295-305`, `:358-363`).
- `--host-resolver-rules=MAP * ~NOTFOUND` + `--disable-background-networking` (`:296-302`), and every request is fulfilled through the broker — no `route.continue` in this file.
- Non-proxied UDP/WebRTC flags plus constructor neutralisation (`:300-313`, `:739-740`).
- `serviceWorkers: 'block'` (`:736`, and `:1579`).
- WebSocket guard routes `wss` (and `ws` only for an explicitly enabled local lab) and requires `grant.canRead(origin)` (`:325-356`, `:741-745`).
- `about:/data:/blob:` are fulfilled empty; `file:` and non-http(s) schemes are aborted (`:758-780`).
- `route()` covers documents, iframes, scripts, XHR/fetch, images and pings, so `<a ping>` (POST) and `sendBeacon` go through the broker and the Tier-2/3 rules.

**Residuals (not refutations of the listed controls):**
- `installWebSocketGuard` returns silently when `context.routeWebSocket` is absent (`:333`) — fail-open on older Playwright. An IP-literal `ws(s)://` target bypasses the resolver rules, so this matters if the API ever disappears.
- **WebTransport (HTTP/3 over UDP) is not disabled or intercepted.** Hostname targets fail because of the resolver rules, but an IP-literal `https://<ip>:443/` is a direct UDP egress channel not covered by the WebRTC flags.
- Downloads are not disabled (`acceptDownloads` defaults on). Content is still brokered, so this is disk-write/DoS surface rather than egress.
- The persona form-login browser does **not** reuse these guards: no `serviceWorkers: 'block'`, no host-resolver rules, and `route.continue()` for allowed requests (`persona-auth.ts:1316,1336-1369`). That browser is the higher-risk one (it types credentials).

---

## 7. MED — lab container confinement

**Verified:**
- `docker run` includes `--user <non-root>`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, `/tmp` tmpfs, memory/CPU/pids limits, and per-run labels (`src/server/lab-runner.ts:779-802`).
- `/app` is a read-only bind mount; IAST hooks are read-only; the only RW mount is the telemetry dir (`:1293,1298,1303,1306`). No Docker socket, no `--privileged`.
- The lab network is `--internal` with `inhibit_ipv4=true` (`:1443-1455`).
- Telemetry dir is created/chmod 0700, and chowned to the container user only when Kovo Hunter is root (`:751-759`).
- Compose parsing does not carry `volumes` through to `docker run`; explicit service objects are whitelisted (`:324-460`).

**Refutation:**
- **`KOVO_LAB_USER` root check is textual.** `resolveLabContainerUser` rejects only `candidate.split(':')[0] === '0'` (`:738-743`). Verified: `00:00` and `000:1000` are accepted. Docker’s numeric user parsing accepts leading zeros, so `00:00` resolves to uid 0 — the exact condition the function claims to forbid. Impact is mitigated by cap-drop/no-new-privileges/read-only rootfs, but container root can still chown/write the RW telemetry bind mount and any future RW mount.
- The telemetry mount is RW (`:1303`) and, when the data-dir path is used (`execution.ts:2452`), is **shared across runs** (`<data>/evidence/lab-telemetry`). One lab app can read/overwrite another run’s telemetry, and there is no quota on the bind mount (disk-fill DoS). I found no host reader that follows links placed there today, so this is cross-run integrity/DoS rather than a direct host escape.
- When Kovo Hunter is non-root and the operator sets a non-root `KOVO_LAB_USER` different from Kovo Hunter’s uid, the 0700 telemetry dir is not writable by the container and IAST silently produces nothing (fail-closed functional regression).

---

## 8. MED — approval fast paths

**Fixed and verified:**
- GraphQL fast path parses JSON and requires an exact top-level `query` key with only envelope keys, a string document, and no `mutation`/`subscription` (`approval-judge.ts:480-517`). Nested/array `query`, `notquery`, and non-string values are rejected.
- Multipart is detected from `Content-Type`, a malformed boundary, or boundary-looking body, not just a caller flag (`:463-478`), and multipart/malformed/DELETE always hard-escalate (`:526-547`).
- Keyword scan covers up to 64 KiB (`:95`, `:554-556`) and the agent rationale is no longer sent to the judge (`:817-829`); tests at `tests/v5-security-approvals.test.ts:163-296` pass.
- Case-insensitive keywords are used throughout.

**Remaining bypasses (why PARTIAL):**
- **The older idempotent-POST gate short-circuits all of this** (see finding 1, item 2): path-name + “no literal mutation” is the only test, and it runs before `evaluateTier3Approval`.
- **Duplicate top-level JSON keys.** `parseJsonObjectBody` uses `JSON.parse` (last-wins, `:480-490`). Verified: a body with the same `query` key twice — first a mutation, then a read-only document — is auto-approved as `benign_fast_path`. Kovo Hunter forwards the body unchanged, so a target parser that takes the first occurrence executes the mutation. Parity-unsafe even if most popular parsers are last-wins.
- **No outbound body-size cap.** `textBody` is capped, but `jsonBody` is `z.unknown()` (`src/replay-spec.ts:393-394`); a body larger than 64 KiB can place a destructive keyword past `MAX_KEYWORD_SCAN_CHARS`, and the judge preview is only 1,200 chars (`:825`). The 64 KiB scan therefore has a truncation gap.
- **Compressed bodies.** A request with `Content-Encoding: gzip` is scanned as compressed bytes, so the keyword hard-escalation never sees the plaintext and the judge receives a gibberish preview. The broker does not decompress request bodies for classification.
- `isReadOnlySearchPost` trusts the path name (`search|query|filter|lookup|introspect|validate|check|health|ping`) plus the absence of a small mutation keyword set (`:87-91`, `519-524`); a state-changing POST on any such path that avoids those words is auto-approved at `benign_fast_path`.

---

## 9. MED — worker output bounds

**Verified fixed:**
- `MAX_WORKER_LINE_BYTES = 64 KiB`, `MAX_WORKER_OUTPUT_BYTES = 4 MiB` (`src/server/worker-backend.ts:314-316`).
- The cumulative limit is checked **before** `Buffer.concat`, so a huge chunk cannot allocate past the cap (`:341-347`); the pending buffer is bounded before and after splitting (`:349-375`).
- On overflow, `failAll` rejects pending operations, `close()` kills the attach CLI and removes the container, and the data listener is removed (`:720-731`, `:749-766`).
- stderr is separately bounded at 8 KiB, and the per-call docker stderr path is also bounded (`:685-693`, `:391-406`).
- Tests cover normal chunking, a single flood line, and the total cap (`tests/v5-security-repo.test.ts:259-289`).

**Attempts to refute:** buffered frames cannot accumulate beyond the pending cap; multiple streams (stdout/stderr) are bounded separately; base64 growth is just bytes counted against the same caps; post-error data events keep throwing without growing memory (the total already exceeds the cap) and listeners are removed when close completes. No bypass found. Nit: `total` is not reset until a new decoder, which is the intended per-session semantics.

---

## New risks introduced by these fixes

1. **Tier-3 RCE/upload/timing verification is now un-consumable after a decision (fail-closed dead end).** `replay-verifier.ts:627-633` and `:2106-2108` call `isStateChangeApproved(origin, method, path)` with **no context**; `authorizeStateChange` then ignores the ledger (`approval-judge.ts:408`) and only operator patterns can pass. The `: localLab` fallback at `replay-verifier.ts:630` is dead because `buildGrant` always defines the hook (`execution.ts:1169`). Result: a judge/operator approval for `rce_proof`, `upload_probe` or public `sql_time_diff` cannot authorize the retry, so those verifications stay inconclusive even after explicit approval. `probes/injection.ts:205` has the same shape and can re-raise `BrokerApprovalRequired` after approval.
2. **Identical-request Tier-3 race bursts cannot be approved.** `registerStateChangeApproval` registers one grant per **unique** fingerprint, and identical burst requests collapse to one key (`execution.ts:1898-1922`, `5296-5306`). `executeRaceBurst` prepares every request before sending (`broker.ts:3109`), so the second identical request throws. Verified with the real ledger/broker: a 3× identical burst is rejected after one grant. In `executeRaceBurstTool` this lands back in `waitForTier3Approval`, which can loop through new approval cards (and judge calls/spend) until the budget or timeout stops it.
3. **Tier-3 state-change batches now hard-fail.** `request_http_batch` calls `executeBatch` with no `BrokerApprovalRequired` catch (`execution.ts:5400-5420`), so once the first grant is consumed any further batch item fails the whole tool.
4. **Local-lab `localhost` persona login is always rejected.** `classifyAddress('localhost')` is `blocked` (`persona-auth.ts:251-259`), so an explicitly allowlisted `http://localhost:<port>` credential target fails at `:574-580`; only `127.0.0.1`/`[::1]` work.
5. **Bootstrap operational/leak surface.** The one-time URL is printed to stdout and stored in `bootstrap-url` (0600) and can appear in a reverse proxy’s request log. The `bootstrap-url` file is not removed when the secret is consumed. Headless/UI automation must now read the 0600 file (the Playwright fixture does).
6. **Sandbox-by-default can break browser probes inside containers where user namespaces are unavailable**, forcing the explicit `KOVO_INSECURE_NO_SANDBOX=1` opt-in (with reduced isolation).
7. **Read-only rootfs + non-root user + cap-drop can break images that expect to write outside `/tmp`** (e.g. package managers/entrypoints), turning some lab targets into start failures. This is the intended trade-off, but it should be surfaced in the lab error path.
8. **`KOVO_LAB_USER=00:00` is accepted as root** (finding 7), which is a validation regression relative to the stated invariant.

---

## Top 3 residual risks (ranked) and next actions

### 1. Idempotent-POST pre-approval bypass — HIGH
Any Tier-2/3 POST with a path containing `graphql|search|query|introspect` and without the literal `mutation` keyword skips the entire Tier-3 gate (`execution.ts:749-753`, `broker.ts:2364-2372`). Verified: zero approval callbacks.
**Action:** delete/replace `isSafeIdempotentPost` with the exact `isGraphqlReadOnlyQuery`/`isReadOnlySearchPost` checks **and** require a real GraphQL envelope (or an operator opt-in) before skipping approvals; never infer “read-only” from a path substring alone. Add a broker regression that asserts `isStateChangeApproved` is invoked for every non-GET, including `/api/query` with a state-changing JSON body.

### 2. Approved state change re-sent through a 307/308 redirect — HIGH
`broker.ts:2957-2976` follows 307/308 and re-sends `activeBody` with no new authorization; the exchange even reports the original path (`:3016`).
**Action:** before following a 3xx for a state-changing method, require a fresh exact-fingerprint approval for `(final origin, method, pathname+search, body)` (or refuse to auto-follow 307/308 for non-GET/HEAD and re-escalate); record the redirect path(s), not just the origin, in the exchange. Add a test with a 307 from the approved path to a distinct path.

### 3. Registrable-domain widening to shared/private suffixes — HIGH
The hardcoded suffix list treats `github.io`, `vercel.app`, `com.co`, `s3.amazonaws.com`, etc. as registrable domains, so any sibling tenant is in scope for Clerk discovery and credential POSTs (verified). Form login additionally accepts any `config.loginUrl` and even plain HTTP.
**Action:** use a real PSL (e.g. `tldts`) and **reject** allowlist targets whose registrable domain is a public/private suffix; require exact-host (or explicit operator confirmation) for IdP/Clerk hosts, and derive `clerk.<apex>` only for non-multi-tenant apexes. Add `assertCredentialTarget` + HTTPS enforcement to `authenticateForm` (including `loginUrl`) and add tests for private suffixes and out-of-allowlist login URLs.

### Then, in priority order
4. **Pin credential connections**: deny `addresses.length === 0`; connect to the validated IP (custom lookup/dispatcher) or fail; drop the `unknown → safe` browser branch; reduce/remove the 60 s DNS safety cache; document `NODE_USE_ENV_PROXY` as unsupported for credential flows.
5. **Fix the dangling-symlink containment bug**: `lstat` every existing component (including broken links) and reject links unconditionally before returning from `safeResolveUnderRoot`; write patch files with `O_NOFOLLOW | O_CREAT | O_EXCL` and verify the parent realpath at write time.
6. **Restore legitimate Tier-3 flows**: pass the full `StateChangeApprovalContext` from `replay-verifier`/`probes` (including `isRceProof`, body hash, persona), or add a spec-scoped grant that the verifier consumes; register one grant per **request instance** (or dedupe burst requests before preparation) so identical race bursts work; add a catch/approval path for `request_http_batch`.
7. **Tighten patterns**: wildcard only ID-like target segments, not arbitrary literals; consider removing the trailing-`*` arbitrary-depth prefix match or requiring an explicit operator confirmation for it; never allow patterns to cover `rce_proof` regardless of context availability.
8. **Lab hardening**: compare the numeric uid parsed from `KOVO_LAB_USER` (`Number(...) !== 0`), make the telemetry mount per-run (or `readonly` unless IAST is enabled), and add quota/cleanup; consider `--userns-remap`/rootless docs.
9. **Fast-path parity**: reject duplicate top-level JSON keys (parse with a strict/duplicate-aware parser or scan the raw body for repeated `"query"` keys), cap outbound body size, and classify compressed bodies by rejecting `Content-Encoding` on Tier-3 state changes.
10. **Bootstrap hygiene**: strip/avoid logging the bootstrap URL at the proxy, remove `bootstrap-url` on consumption, and consider a session token bound to the issuing origin/port where possible.

---

## Appendix — reproduction notes (structural, no secrets)

- Approval tests: `node --test tests/v5-security-approvals.test.ts tests/v5-security-repo.test.ts tests/v5-security-authbrowser.test.ts` → 33 pass.
- Redirect bypass: fake transport, approve only the first path, observe a second wire request with the original method/body to the redirect path; only one approval callback fired.
- Idempotent-POST bypass: broker grant with the production-style `isIdempotentPostAllowed` predicate, public origin, Tier 2; a state-changing POST to a `query`-named path is sent with zero approval callbacks.
- Pattern over-match: real `matchesApprovedEndpointPattern`/`evaluateTier3Approval`; a pattern derived from an item-ID path matches a destructive verb at the same depth and is auto-approved as `approved_pattern`.
- Registrable domain: real `registrableDomain`/`isHostInScope`; `app.example.github.io` → `github.io`, and a sibling host is in scope.
- Dangling symlink: under `/tmp`, a create-file unified diff through a dangling link wrote the target outside the root; `safeResolveUnderRoot` accepted the path.
- Race burst: real `StateChangeApprovalLedger` + `RequestBroker.executeRaceBurst`; one grant, three identical requests → `BrokerApprovalRequired` on the second.
- Lab user: `resolveLabContainerUser({KOVO_LAB_USER:'00:00'})` returns `00:00` (accepted).
- Localhost: `classifyAddress('localhost') === 'blocked'`; `127.0.0.1` and `::1` are `loopback`.
