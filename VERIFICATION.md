# Guardian v2 Verification

Verified on November 20, 2026 against the clean-slate Guardian v2 implementation ([SPEC-v2.md](SPEC-v2.md)) using the real TanStack Start production build, Playwright Chromium, Node.js SQLite (`node:sqlite` + FTS5 trigram), and the local air-gapped Linux Docker worker image (`guardian-worker:local`).

## Summary of Verification Gates

| Gate | Command | Result |
| :--- | :--- | :--- |
| **Worker Image Build** | `npm run worker:build` | Passed. Built `guardian-worker:local` with `worker/bridge.ts`, `worker/analyzers.ts`, and `just-bash` running as UID `10001:10001`. |
| **TypeScript Check** | `npm run check` | Passed with **0 errors** across the entire repository (`src/`, `worker/`, `tests/`, `scripts/`). |
| **Production Build** | `npm run build` | Passed cleanly (Vite client bundle in 0.77s, TanStack Start SSR server bundle in 0.42s). |
| **Boundary & Security Suite** | `npm run test:boundaries` | **27 / 27 passed** (`tests/boundaries.test.ts`: 9/9, `tests/provider-stream.test.ts`: 8/8, `tests/report-comparison.test.ts`: 10/10). |
| **Production Browser E2E Suite** | `npm run test:e2e` | **4 / 4 passed** in 25.1s against the real production server (`scripts/serve.ts`) and real Docker containers (`tests/guardian-v2.spec.ts`). |
| **Deep Live v2 Smoke (`dyad.sh`)** | `node scripts/live-smoke-v2.ts` | **Passed** (`status: complete`, `reportPartial: false`, 714s). Synced 6 authorized `dyad-sh` repos read-only (99 files, 1,734 dependencies, 11 specs), assessed all 30 approved `dyad.sh` subdomains at Tier 1 (409 turns, 573 brokered requests, $5.80 / $25.00 USD), confirmed **29 findings** (22 baseline + **7 Zero-LLM deterministically confirmed multi-step chain findings**), verified **0 out-of-scope requests**, **0 mutating HTTP methods**, **0 secret leaks**, and executed live one-click **Verify Fix** retest (`reproduced`). |

---

## 1. Boundary, Security & Failover Suite (`npm run test:boundaries`)

### `tests/boundaries.test.ts` (9 / 9 passed)
1. **DNS Rebinding, Private-IP Blocking, 8-Hop Redirects & `local-lab` Opt-In Gate:** Verified private/loopback IPs are blocked before dialing; `local-lab` private targets require **both** `grant.allowLocalLab === true` and `GUARDIAN_ALLOW_LOCAL_LAB=1`; aborting while DNS is unresolved never dials; 8-hop in-scope redirects succeed while 9th hop or cross-scope redirect hops are rejected; paths > 8 KiB and direct caller `Authorization`/`Cookie` headers are denied.
2. **Tier 0–3 Capability Matrix & Tier 3 HITL Approval Lifecycle:** Verified Tier 0 blocks all live HTTP/DNS/TLS; Tier 1 permits GET/HEAD/OPTIONS and blocks mutating methods and `executeBatch`; Tier 2 permits opaque personas, synchronized `executeBatch` (`2..10`), and allowlisted idempotent POSTs while blocking state-changing methods; Tier 3 throws `BrokerApprovalRequired` until `isStateChangeApproved` passes; verified SQLite `approval_requests` creation, approval, and denial commands.
3. **Persona Vault Isolation & Zero Secret Leakage:** Verified `createProjectPersona` writes `0600` credential files outside SQLite and omits raw secrets from `listProjectPersonas`; egress injects credentials only on origins in both `run.approved` and `persona.originAllowlist`; cross-origin redirects inject on hop 1 and **strip** auth headers on hop 2; server-echoed secrets are scrubbed to `[persona:<handle>:secret]` across `BrokerExchangeResult`, `broker_exchanges` + FTS5 trigram search, `facts`, artifacts, and Markdown exports.
4. **Sliding-Window `5xx` / `429` Defensive Circuit Breaker:** Verified `>= 5` HTTP `5xx` or `>= 8` HTTP `429` responses within 30s open `BrokerCircuitOpen`, emit `circuit_open` audit events, and fail fast without touching transport.
5. **Persistent `--network none` Intent Container, Offline Analyzers, Abort Kill & Orphan Cleanup:** Verified non-Unix `DOCKER_HOST` rejection; inspected real Docker container `HostConfig` (`NetworkMode: none`, `Privileged: false`, `ReadonlyRootfs: true`, `512m` RAM, `1.0` CPU, `96` PIDs, `64m` `/tmp`, `Binds: null`), confirmed UID `10001`, absence of `/var/run/docker.sock` and host env vars, and blocked reachability to the Docker bridge gateway; verified NDJSON staging (`/evidence`), read-only `/evidence` rejection (`EROFS`), `just-bash` execution in `/work`, all offline analyzers (`js-harvest`, `secret-scan`, `tech-fingerprint`, `jwt-inspect`, `graphql-parse`, `diff-response`, `dns-takeover`), instant container kill on `AbortSignal`, and `reclaimInactive()` workspace-scoped orphan cleanup preserving foreign workspace containers.
6. **Runtime Tech Fingerprinting + `cve-broker` (`CVE-2025-29927`) & SPA Catch-All Immunity:** Verified curated `CVE-2025-29927` lookup for `next@14.2.20`; verified Zero-LLM `http_chain` replay with `spaCatchallControl: true` confirms the vulnerable fixture (`confirmed`), rules out the edge-blocked fixture (`dismissed`), rejects an HTTP `200 index.html` SPA catch-all (`inconclusive` even under permissive `jq`), and verifies `retestReplaySpec` transitions from `reproduced` → `fixed` after patching.
7. **`dns_takeover`, `tls_audit`, and 100%-Brokered Playwright `browser_dom`:** Verified dangling GitHub Pages CNAME takeover (`confirmed` vs. `dismissed`), deprecated `TLSv1.1` / expired certificate detection (`confirmed` vs. `dismissed`), and real Chromium `ScopedBrowser` routing 100% of approved requests through `RequestBroker` while aborting unapproved third-party scripts (`0` hits on third-party trap server), capturing DOM/XHR/unchecked `postMessage` listeners and storage key names without leaking storage values.
8. **Zero-LLM Non-Destructive `rce_proof` (`dynamic_math`, `split_echo`, `oob_canary`):** Verified schema and broker reject destructive/reverse-shell/metadata payloads (`rm -rf`, `/dev/tcp/`, `nc -e`, `/etc/shadow`, `169.254.169.254`); verified hard Tier 3 + HITL approval gates; confirmed executing fixtures pass while **raw input reflection fails confirmation (`dismissed`)** for both `dynamic_math` and `split_echo`; confirmed adjacent non-concatenated `split_echo` templates are rejected (`inconclusive`); confirmed local `CanaryBroker` OOB callbacks confirm only when the probe canary triggers and control stays silent.
9. **Transitive Scope-Revocation Tainting, Cold-Graph Digest Compaction & `budget_paused` → Resume:** Verified revoking Step 1's origin transitively taints downstream `facts` and `chain_steps` on another origin along `graph_edges` while keeping independent facts untainted and earlier report exports byte-for-byte immutable; verified `ColdGraphCompactor` stamps `coldSinceRound` after 4 idle rounds, runs minor compaction into `graph_digests`, and restores facts via `expandDigest`; verified `checkBudgetExceeded` transitions to `budget_paused`, blocks `resume` while over budget, and resumes cleanly after `raise_budget`.

### `tests/provider-stream.test.ts` (8 / 8 passed)
- Verified cross-chunk SSE redaction for both **OpenAI Responses** and **Anthropic Messages** protocols scrubbing both API keys and registered `NamedSecret[]` **persona secrets** split across deltas, preserving valid tool-call JSON and event order, and leaving zero secret fragments in recorded calls or Pi Durable `.sqlite` sessions.
- Verified terminal-event flush, v2 16 MiB default `responseLimit` and custom size-limit enforcement, `429 → 402` quota-body vs. transient RPM rate-limit classification, `providerPool` priority ordering + context-window filtering + circuit-breaker state transitions (`open` on hard failure) + safe-window-only failover (no duplicate failover after emitting stream deltas), and `onUsage` cost reporting.

### `tests/report-comparison.test.ts` (10 / 10 passed)
- Verified matched report scorecard precision/recall, severity grading, coverage overclaim rejection, scope-revision binding, and artifact integrity checks.

---

## 2. Production Browser E2E Suite (`npm run test:e2e` — 4 / 4 passed in 25.1s)

Executed against the compiled TanStack Start server (`scripts/serve.ts`), real Docker worker containers, and a local deterministic OpenAI Responses + HTTPS target fixture server (`tests/v2-fixture-server.ts`, `tests/guardian-v2.spec.ts`):

1. **Multi-Profile Model Settings, Persona Vault, Lockfile Spec Import, Multi-Step Chain + CVE-2025-29927 Zero-LLM Replay, One-Click Verify Fix Retest, Workflow Trace DAG & Portable Markdown Export (8.1s):** Configured and verified model profile in `/settings`, registered opaque persona `tenant_a` (confirming raw secret never appears in DOM), imported `package.json` (`next@14.2.20`), executed full Threat Model → multi-turn JS-harvest investigation → Zero-LLM replay confirmation of `CVE-2025-29927`, clicked **Verify Fix** (`Still reproducible`), patched the fixture and clicked **Verify Fix** again (`Verified fixed`), inspected the Workflow Trace DAG, and exported portable Markdown verifying zero leaks of API key, synthetic cookie, or persona secret.
2. **Tier 3 Blocking HITL Approval Card (4.7s):** Confirmed a Tier 3 `POST /api/state-eval` probe is blocked (0 `POST` requests sent) while surfacing the live **Tier 3 approval required** card via SSE; clicking **Approve probe** unblocked execution (1 `POST` sent) and completed the report.
3. **Crash (`SIGKILL`) & Explicit Resume Without Duplicate Requests (6.4s):** Killed the production server with `SIGKILL` mid-investigation after baseline `GET /` completed; restarted on the same SQLite directory; confirmed recovery into `paused` with **Resume** visible and zero requests before resuming; clicked **Resume** and completed the report with exactly 1 baseline `GET /` read.
4. **Mid-Chain Scope Revocation (5.1s):** Revoked `northstar.example` from a running two-host engagement via Scope Review (`Revision 2`), let `api.northstar.example` finish, and verified the completed report and exported Markdown completely omitted the revoked origin and its findings.

---

## 3. Deep Live v2 Smoke Test (`scripts/live-smoke-v2.ts` against `dyad.sh`)

Executed live on November 20, 2026 using `~/.config/guardian-fixtures/openrouter.key` (`deepseek/deepseek-v4.1-flash-1017`, Responses protocol) and read-only `~/.config/guardian-fixtures/github.pat` (never logged, stored in SQLite, or exported).

- **Capability Tier & Guardrails:** **Tier 1 (Deep Read-Only + Safe Benign Probes)**, `budgetUsd: $25`, `budgetRequests: 2,500`, `maxRpsPerOrigin: 5`, `workerConcurrency: 6`, `workerMaxTurns: 25`, zero state mutations, zero RCE payloads.
- **Grey-Box Read-Only GitHub Repo Sync:** Synced all 6 authorized `dyad-sh` repositories (`dyad-cloud`, `dyad-llm-engine`, `dyad-billingz`, `dyad-chat-uploader`, `dyad-image-uploader`, `sandpack-bundler`) — **99 high-signal files**, **1,734 dependencies** extracted for CVE correlation, **11 project specs** imported with zero warnings.
- **Scope & Execution Metrics:**
  - Approved hosts: **30** `dyad.sh` subdomains (all 30 ranked in Round-0 Threat Model).
  - Completion: `status: complete`, `phase: complete`, `reportVersion: 1`, `reportPartial: false`, elapsed **714s** (~11.9 min).
  - Usage: **15 planner rounds**, **409 turns**, **573 / 2,500 brokered requests**, **$5.80 / $25.00 USD** (`21,454,961` tokens).
  - Structured exploration: **32 chain steps planned (20 completed)**, **146 structured facts**, **23 `cve_hypothesis` correlations**, **113 OWASP / API Top 10 coverage entries**, **14 Declarative Replay Specs proposed**.
- **Security Invariants Verified Live:**
  - Out-of-scope broker requests: **0** (every `broker.allowed` event strictly within the 30 approved `dyad.sh` origins).
  - Mutating HTTP requests (`POST`/`PUT`/`PATCH`/`DELETE`): **0**.
  - `rce_proof` executions at Tier 1: **0**.
  - Defensive circuit breaker verified live: `upload-image.dyad.sh` tripped the per-origin 5xx circuit breaker cleanly, protecting that host while the remaining 29 approved hosts completed uninterrupted with zero container leaks (`0` orphaned Docker containers remaining).
  - Secret hygiene: Verified neither the OpenRouter API key nor the GitHub PAT appeared anywhere in `guardian.sqlite` or the exported Markdown report.
- **Confirmed Findings (29 total — 2 medium, 19 low, 8 informational):**
  - **22 baseline response-control findings** across live 200 HTML hosts (missing CSP, frame protection, `X-Content-Type-Options`, server disclosure).
  - **7 Zero-LLM deterministically confirmed multi-step chain findings** (each linked to its saved `replay_specs` record and SHA-256 verification artifact):
    1. **Medium** (`accounts.dyad.sh`) — Account-portal edge reflects arbitrary and `null` `Origin` with `Access-Control-Allow-Credentials: true` on `/v1/*` responses.
    2. **Medium** (`bulletin.dyad.sh`) — Credentialed CORS reflection on `better-auth` `/api/auth/*` (`ACAO` mirrors arbitrary `Origin` with `Access-Control-Allow-Credentials: true`).
    3. **Low** (`accounts.dyad.sh`) — Arbitrary-origin reflection with credentials on `/v1/*` vs. clean control paths.
    4. **Low** (`bulletin.dyad.sh`) — Credentialed CORS reflection on `better-auth` session endpoints.
    5. **Low** (`upload-logs.dyad.sh`) — Verbose Express stack-trace disclosure when a cross-origin request is rejected (CORS denial surfaced as HTTP 500).
    6. **Low** (`login.dyad.sh`) — Authentication hostname dead-ended at Cloudflare edge by Error 1014 (cross-account CNAME target).
    7. **Low** (`helpchat.dyad.sh`) — Missing CSP, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy` on HTML responses alongside wildcard ACAO.
- **Live One-Click Verify Fix Retest:** Re-ran the saved Declarative Replay Spec for the confirmed `helpchat.dyad.sh` finding via `retest_finding` (Zero-LLM) → returned verdict **`reproduced`** cleanly.
- **Exported Artifacts (local `0700`/`0600`, uncommitted):**
  - `.guardian/dyad-v2-smoke/guardian-dyad-v2.md` (1,662,362 bytes, portable Markdown with Threat Model, chain timelines, OWASP coverage matrix, and SHA-256 redacted exchange & replay appendices).
  - `.guardian/dyad-v2-smoke/summary.json` and `.guardian/dyad-v2-smoke/github-sync.json`.

---

## 4. Real Defects Caught & Fixed During Verification

Verification uncovered and resolved 7 real defects across the stack prior to final green pass:
1. **`worker/.dockerignore`** — Missing `!analyzers.ts` broke `npm run worker:build` (fixed by `@llm-skills`, #8/#15).
2. **`src/server/provider.ts`** — Double `onProfileFailure` invocation during safe-window failover caused single transient errors to double-increment failure streaks (fixed by `@llm-skills`, #11/#15).
3. **`src/server/personas.ts`** — Unreferenced legacy draft file broke global `tsc --noEmit` (removed by `@broker-sec`, #13/#14).
4. **`src/server/store.ts` & `src/server/execution.ts`** — Nested `BEGIN IMMEDIATE` transactions threw SQLite errors when saving Round-0 Threat Model steps and operator hints (fixed with re-entrant `SAVEPOINT` `Store.transaction<T>()` by `@core-engine`, #19/#20).
5. **`src/routes/settings.tsx`, `projects.$projectId.tsx`, `run-overview.tsx`, `run-workspace.tsx`** — Four HTML5 `<input type="number">` `stepMismatch` constraints silently blocked default form submissions in Chromium (fixed by `@ui-frontend`, #21/#24).
6. **`src/server/worker-backend.ts` & `src/server/execution.ts`** — Concurrent `onAbort` + `finally` `session.close()` threw unhandled `ERR_STREAM_WRITE_AFTER_END`, and a single host's `5xx` circuit breaker paused unrelated healthy hosts in a 30-host run (fixed by `@broker-sec` & `@core-engine`, #22/#25/#26).
7. **`src/server/replay-verifier.ts` & `src/server/agent-session.ts`** — Live `http_chain` replay assertions failed schema validation when `jq` emitted structured objects for `observed`/`expected` or accessed `[.steps[] | select(.id == ...)]` / `.control` / `.probe` (fixed with deterministic string coercion, step `id` + top-level aliases, and explicit tool schema docs by `@broker-sec` & `@llm-skills`, #30/#31/#32).
