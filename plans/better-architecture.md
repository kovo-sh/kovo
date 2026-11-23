# Guardian Real-World Architecture Assessment & Redesign Plan

> **Date:** 2026-11-22
> **Scope:** End-to-end architectural audit of Guardian (`src/server/`, `worker/`, `src/templates/`, `src/replay-spec.ts`, `plans/`, `VERIFICATION-v5.md`, `HANDOVER-v5.md`) evaluating structural ceilings that limit real-world vulnerability detection, verification, and operational scale.
> **Framing:** Defensive QA / authorized security verification architecture.

---

## 1. Executive Summary

Guardian achieves strong recall on local benchmark harnesses (~65–67% on realistic-bench dev and salted held-out suites), yet faces a steep drop-off when pointed at real-world staging or production applications. That gap is driven less by missing individual probe signatures and more by **seven interlocking architectural assumptions** inherited from single-origin, loopback, disposable local-lab benchmarks:

1. **Mutually exclusive deterministic vs. agentic execution lanes**, leaving the deterministic differential floor unwired from LLM specialist runs.
2. **Single-origin, single-header, redirect-hostile auth**, which breaks federated SSO/OIDC/SAML, MFA, hybrid cookie+JWT SPAs, and concurrent session refreshes.
3. **Asset-starved, non-interactive `ScopedBrowser` crawling**, which fails to hydrate CDN-backed SPAs or pass auth to split `app.`/`api.` origins.
4. **HTTP/1.1-only normalized transport & loopback 1.5s OOB canaries**, blinding Guardian to HTTP/2/gRPC, WAN races, WAF-fronted apps, external blind callbacks, and async queues.
5. **Noise-intolerant, JSON-only, siloed verification & coarse dedupe**, which reject valid real-world findings (already >70% of harness misses are `replay_spec_miss`) and collapse distinct bugs on multi-field or RPC endpoints.
6. **Binary local-lab vs. public approval cliff**, causing synchronous HITL approval storms that starve worker pools and leases without providing test-entity isolation or cleanup.
7. **Truncated stateless planning, English-REST heuristic gates, and single-process synchronous SQLite persistence**, which silently drop surface area, clobber multi-resource IDs, and stall on large targets.

This document catalogs every verified structural limitation with code locations and defines a phased architectural redesign to close the local-lab-to-real-world chasm.

---

## 2. Structural Limitations Audit

### Tier 1 — Critical Architectural Ceilings

#### 1. Dual-Pipeline Split & Mutually Exclusive Deterministic vs. Agentic Lanes
* **Locations:**
  * `src/server/execution.ts:3169-3357, 3921-3928, 4742-4980, 5923-5927, 7739-7770`
  * `src/server/assignment-brief.ts:345-452`
  * `src/server/agent-session.ts:92-107, 1744-1790`
  * `VERIFICATION-v5.md:15-56, 89-168`; `plans/ENGINE-PORT-COMPAT.md:50-122, 208`
* **Mechanism:**
  * In `driveInvestigation()` (`execution.ts:3922-3928`), `driveEngineInvestigation()` / `driveDeterministicInvestigation()` execute **only when `!profiles.length`**, and the in-product deterministic engine remains behind a default-off feature flag (`ENGINE-PORT-COMPAT.md:208`).
  * Whenever a model profile is configured, Guardian skips the deterministic differential floor completely (even emitting a `post-floor` checkpoint at `execution.ts:3354` without having run the floor) and launches LLM specialists from an initial 12-step threat model (`execution.ts:3297`).
  * Handoff scaffolding already built for v5.1—`buildAssignmentBrief` (`assignment-brief.ts:345`), `resolveAgenticTurnBudget` / `AGENTIC_SPECIALIST_WALL_CLOCK_MS` (`agent-session.ts:92-107`), and `alreadyConfirmed` / `detLeads` prompt slots (`agent-session.ts:1744-1790`)—is not wired into `execution.ts`. `startInvestigationStep` (`5923-5927`) forces a 25–35 turn minimum with no `wallClockMs` cap below the 25.5-minute lease (`7739-7770`).
* **Real-World Impact:** Agentic runs burn wall-clock budget (historically 2–4 assignments per 600s, with 34/52 misses in `budget_exhausted`) rediscovering baseline differential classes instead of investigating business logic and multi-step chains, while routes outside the 12-step cap receive no systematic coverage.

---

#### 2. Enterprise Identity, Multi-Origin Auth & Concurrent Session Lifecycle Ceiling
* **Locations:**
  * `src/domain.ts:493-526`
  * `src/server/persona-auth.ts:121-130, 402-411, 622, 629-637, 685, 806-830, 888-916, 1558-1622, 1696-1706, 1789-1823, 1910-1915`
  * `src/server/persona-vault.ts:33-47, 136-187, 362, 461-474`
  * `src/server/broker.ts:2792-2794, 2855-2905`
  * `src/server/phase0-recon.ts:2204-2245`
* **Mechanism:**
  * **No federated SSO/OIDC/SAML or MFA:** Auth adapters are restricted to `clerk | supabase | json | form` (`domain.ts:496`). HTTP login adapters abort on any `3xx` (`persona-auth.ts:622, 629-637`), `assertCredentialTarget` rejects origins outside `originAllowlist` or on shared PaaS suffixes (`*.vercel.app`, `*.github.io`, `806-830`), and `authenticateForm` DNS-pins Chromium (`MAP * ~NOTFOUND`, `402-411, 1558-1573`) and aborts cross-origin navigations/POSTs (`1696-1706`). External IdP flows (Okta, Auth0, Entra ID, Cognito, Google/GitHub OAuth, SAML ACS) are structurally blocked. MFA/TOTP hard-aborts (`121-130, 1581-1622`), and any passive CAPTCHA script tag aborts login even when not enforced for test accounts (`1606-1610, 1668-1672`).
  * **Single-header credential abstraction:** `MintedPersonaSession` (`persona-vault.ts:33-47, 461-474`) stores a single `Cookie` **or** `Bearer` **or** custom header. Form login discards harvested Bearer JWTs whenever *any* cookie is set (`persona-auth.ts:1789-1823`), breaking hybrid cookie+Bearer SPAs and multi-tenant headers (`X-Tenant-Id` / `X-Org-Id`). Cross-origin redirects strip persona credentials unconditionally (`broker.ts:2794`).
  * **Shared mutable session + 60s re-auth throttle:** Concurrent workers share one `.session` file (`persona-vault.ts:136-187, 362`) and one per-handle re-auth slot throttled to `<=1/60s` (`persona-auth.ts:685, 888-916`, not reset in `stopRunRefreshers:1910-1915`), with no proactive refresher for cookie/form sessions (`1818-1823`). One session-invalidating probe or token rotation causes a 60s cascade of `401`s across sibling workers; Phase-0 permanently disables `discoveryPersona` on the first `BrokerDenied` (`phase0-recon.ts:2239-2245`). Rotating CSRF (`broker.ts:2855-2905`) requires explicit `session` + `csrfBind`, neither of which Phase-0 or `crawlStateGraph` passes.
* **Real-World Impact:** Blinds Guardian to authenticated attack surfaces on enterprise SSO/OIDC/SAML/MFA apps, PaaS-hosted apps, hybrid SPAs, multi-tenant org-switching flows, and CSRF-protected state machines.

---

#### 3. ScopedBrowser & SPA Crawler Cannot Hydrate or Traverse Real Modern SPAs
* **Locations:**
  * `src/server/scoped-browser.ts:254, 295-308, 358-383, 590-628, 742-841, 888-893, 1608`
  * `src/server/broker.ts:1853-1884, 2381-2385`
  * `src/server/phase0-recon.ts:2022-2025, 2160, 2328, 2427, 2550, 2699, 2881, 2902, 3004, 3055-3132, 3300-3446`
  * `src/server/surface-engine.ts:25-27, 145-147, 243-287, 376-384, 428-472, 538`
* **Mechanism:**
  * **CDN/asset starvation:** Chromium launches with `MAP * ~NOTFOUND`, `serviceWorkers: 'block'`, and aborts every subresource request outside `grant.canRead` (`scoped-browser.ts:299, 764, 802-808`). Apps serving JS chunks from CDNs (`cdn.*`, `*.cloudfront.net`, `assets.*`) fail to boot and render blank shells.
  * **Broken browser auth & split-origin APIs:** `ScopedBrowser` strips `Authorization`/`Cookie` and `sec-fetch-*`/`sec-ch-*` (`254, 822-826`), strips `Set-Cookie` on fulfill (`594`), never seeds `localStorage`/`sessionStorage`, mirrors only non-`HttpOnly` cookies (`broker.ts:1867`, returning `[]` when `req.session` is omitted as in `crawlStateGraph`), and attaches persona headers only to `initialOrigin` (`scoped-browser.ts:830-841`)—never to sibling allowlisted API origins (`app.example.com` → `api.example.com`).
  * **Non-interactive, heavily capped crawl:** `crawlStateGraph` (`phase0-recon.ts:3300-3358`) starts and kills a full Chromium process per page (`scoped-browser.ts:742, 752`), settles only `120ms` after `domcontentloaded` (`phase0-recon.ts:3340`), never clicks SPA UI controls, caps Phase-0 at `min(0.15 * budget, 250)` requests / `<=10` crawl pages / `32` JS chunks, runs HTTP discovery only as `personas[0]` (`2160, 2427`, missing role-exclusive admin routes), and blocks non-allowlisted `POST`s (e.g., GraphQL/RPC bootstraps).
  * **Protocol/encoding blind spots:** `ParamLocation` (`domain.ts:161`) omits `multipart`, binary/protobuf, gRPC, WebSocket, and SSE. `ScopedBrowser` WebSockets bypass `context.route` without frame capture (`scoped-browser.ts:358-383`, making `phase0-recon.ts:3444` dead code). GraphQL discovery depends solely on live `__schema` introspection (`phase0-recon.ts:3055-3097`), and `surface-engine.ts` skips `/` completely (`145-147, 376-384`) and calibrates soft-404s only at `/` (`243-287`).
* **Real-World Impact:** Modern React/Next/Vue/Angular SPAs with CDN bundles, `app.`/`api.` splits, `localStorage` tokens, interactive routing, multi-role APIs, production GraphQL (introspection off), or multipart/WebSocket/gRPC surfaces yield minimal discovered endpoints.

---

#### 4. HTTP/1.1-Only Normalized Transport & Loopback-First 1.5s OOB Canaries
* **Locations:**
  * `src/server/broker.ts:3-9, 346, 892-899, 1012-1280, 1350-1481, 2141-2165, 2413-2424, 3149-3248`
  * `src/server/canary-broker.ts:177-178, 642-809, 948-964`
  * `src/server/replay-verifier.ts:741-810, 1191-1197, 1894-1901, 2325-2331`
  * `HANDOVER-v5.md:151`; `VERIFICATION-v5.md:343`
* **Mechanism:**
  * **Transport ceiling:** `defaultTransport` (`broker.ts:1350-1481`) uses `node:http`/`node:https` with `agent: false` (fresh TCP+TLS handshake per request), enforces normalized HTTP/1.1 with computed `Content-Length`, hardcodes `User-Agent: Guardian/2...` + default OpenSSL TLS stack, and blocks caller-supplied `Host`, `Content-Length`, `Transfer-Encoding`, `Cookie`, and `Authorization` (`forbiddenCallerHeaders`, `346, 2415`). No HTTP/2, HTTP/3, gRPC, mTLS client certificates, or corporate egress proxy support exists. `executeRaceBurst` (`3208-3216`) executes `Promise.all` across independent HTTP/1.1 sockets (no H2 single-packet or last-byte TCP sync). `defaultWsTransport` (`1012-1280`) blasts all `sendMessages` immediately without awaiting server turns, caps idle wait at 1200ms, and lacks continuation-frame reassembly.
  * **Local-only, synchronous 1.5s OOB canaries:** `CanaryBroker` defaults to plain `node:http` on `127.0.0.1:0` (`canary-broker.ts:732-735, 808`) with DNS off by default (`723-729`), `udp4`-only (`654`), no built-in TLS termination, no TCP DNS/SMTP/LDAP/ICMP listeners, and no managed public relay. Furthermore, all OOB verification paths (`replay-verifier.ts:1193-1196, 1896-1900, 2327-2330`) poll synchronously for only `10 × 150ms = 1.5s` before finalizing `dismissed`/`inconclusive`.
* **Real-World Impact:** Blinds Guardian to HTTP desync/request smuggling, Host-header routing attacks, gRPC/H2-only APIs, sub-10ms WAN race conditions, WAF/bot-managed origins (trivial JA3/JA4 + UA blocking), mTLS/proxy-gated staging targets, blind SSRF/XXE/RCE/JWKS on public internet targets without custom ops relays, and any async/queued callback slower than 1.5s (webhook workers, PDF/email/cron pipelines).

---

#### 5. Rigid Verification, Proof-Compiler & Deduplication False-Negative Traps
* **Locations:**
  * `src/server/replay-verifier.ts:184-254, 440-655, 1381-1475, 1980-2025, 2698-2750, 2870-2925`
  * `src/server/proof-tools.ts:176, 360-366, 450-454, 756-758, 1174-1185`
  * `src/replay-spec.ts:238-380, 633-683, 705, 722-737`
  * `src/server/dedupe.ts:142-172, 257-350, 554-583, 620-641`
  * `VERIFICATION-v5.md:143-145`
* **Mechanism:**
  * Over **70% of realistic-bench misses are `replay_spec_miss`** (41/57 dev, 46/60 held-out), and internet targets amplify these failure modes:
  * **Noise-intolerant statistical checks:** `sql_time_diff` caps delay at 1500–3000ms over 3 rounds and requires strict non-overlap (`minProbeMs > maxBaselineMs`) plus `deltaMedianMs >= 0.85 * delayMs` (`replay-verifier.ts:2737-2745`); a single WAN jitter spike fails verification. `sql_boolean_diff` requires `>=0.90` baseline similarity and `<=0.75` true-vs-false (`2008-2010`), failing on dynamic nonces/timestamps or small diffs inside large HTML shells.
  * **JSON-only, same-path, same-origin proof constraints:** All `proof-tools.ts` compilers bind strictly to dotted JSON keys (`JSON_PATH_RE`, `176, 756-758`—no array indexing, HTML/XML/CSV/binary/header extraction), require `beforeRead.pathAndQuery === afterRead.pathAndQuery` (`452`), and lack general `setup/cleanup` isolation for one-shot tokens or non-idempotent state transitions. `assessHttpChainEndpointBinding` (`replay-verifier.ts:626-633`) rejects probes whose `finalOrigin` differs from `spec.origin`; `assessBflaImpact` (`234-253`) drops compact (`<64B`) or single-persona/unauthenticated BFLA; `cache_differential` mandates `?_gcb=<hex>` (`replay-spec.ts:633-683`), failing on CDNs that ignore query keys or only cache queryless URLs.
  * **HTTP vs. Browser verification silo:** `http_chain` and `browser_chain`/`browser_dom` are mutually exclusive (`replay-spec.ts:722-737`). `browser_chain` caps at 8 steps and 6 built-in DOM checks; `stored_xss` compiles to an `http_chain` raw-body substring match (`proof-tools.ts:1174-1185`) without verifying browser execution or CSP bypass. Second-order tracking (`canary-broker.ts:501-564`) scans raw HTTP bodies for literal `gn2o_` markers and emits an advisory fact without launching cross-persona verification.
  * **First-key parameter dedupe collisions:** `primaryParamForRequest` (`dedupe.ts:302-314`) extracts `Object.keys(jsonBody)[0]` or the first query parameter rather than the mutated parameter, colliding distinct vulnerabilities on endpoints starting with boilerplate fields (`tenantId`, `action`). `extractGraphqlRootField` (`165-172`) only regex-matches the first root field; single-URL RPC frameworks (tRPC, JSON-RPC, Next.js Server Actions) collapse onto `/`; `ORIGIN_WIDE_CWES` (`142-153, 620-628`) merges distinct microservices sharing a reverse proxy.
* **Real-World Impact:** Valid real-world blind SQLi, HTML/binary IDORs, non-idempotent workflow bugs, cross-subdomain authz flaws, SPA stored/DOM XSS, and distinct bugs on multi-field/RPC endpoints are downgraded to `inconclusive`/`dismissed` or silently deduplicated away.

---

#### 6. Staging/Production State-Safety Chasm & Synchronous Approval-Storm Deadlocks
* **Locations:**
  * `src/server/approval-judge.ts:94-99, 343-395, 451-486, 649-715, 813-864`
  * `src/server/execution.ts:2281-2518, 3945, 6132-6161, 7770, 8074, 8414`
  * `src/server/store.ts:2130-2226, 2265-2393`; `src/server/schema.ts:48, 52, 104-106`
  * `VERIFICATION-v5.md:171-184`; `plans/ROADMAP-v5.md:139, 155, 165, 203`
* **Mechanism:**
  * Outside `local-lab` (`approval-judge.ts:813`), `detectHardEscalationReason` (`649-715`) executes **before** operator-approved endpoint patterns (`451-466, 827-864`). Any `DELETE`, `multipart/*`, `Content-Encoding`, body >64 KiB, or common substring anywhere in path or body (`role`, `permission`, `password`, `reset`, `revoke`, `admin`, `delete`, `remove`, `cancel`, `transfer`, `invoice`, `subscription`, `webhook`, `trial`; `94-99`) forces human escalation even when pre-approved.
  * Approval grants are single-use, exact-body-hash, 60s-TTL, and strictly in-memory (`343-395, 468-483`), so probe iteration and Phase-3 replay verification (`execution.ts:8074, 8414`) re-escalate. While waiting, `waitForTier3Approval` (`2441-2483`) blocks the worker coroutine synchronously, occupying a `workerConcurrency` slot (`3945`), keeping the Docker container alive, and burning the worker lease (`7770`).
  * Conversely, Guardian lacks **test-entity prefix isolation, idempotency tracking, or automatic cleanup hooks** for shared live databases.
* **Real-World Impact:** On real staging/production apps, write-BOLA, BFLA, account recovery, file upload, mass assignment, CSRF, and billing/workflow checks either deadlock behind HITL approval storms or (in `yolo` mode) risk irreversible state pollution, outbound emails/webhooks, and cross-probe interference.

---

#### 7. Stateless Truncated Planning, Heuristic-Gated Detection & Single-Process SQLite Scale Limits
* **Locations:**
  * `src/server/execution.ts:192-223, 3963-3990, 5390-5425, 5572-5894`; `src/server/agent-session.ts:3785-3821`; `src/server/compactor.ts:53, 138-141, 268-358`
  * `src/server/deterministic-engine.ts:33-37, 148-221, 546-770, 1556-1687`
  * `src/server/store.ts:477-494, 802-817, 874-884, 1435-1528, 1571-1612, 1655-1740, 2018-2042, 4209-4234, 4384-4535`
* **Mechanism:**
  * **Truncated stateless planner & chaining ceiling (1/6 on chains):** `runChainPlanner` (`execution.ts:5809-5821`) invokes `agentTurn` with **no tools**, a fresh `sessionId` per round, and a 16 KB output cap over a truncated graph snapshot (max 80 active facts, 30 findings, 30 suspects, 25 uncovered endpoints). `ColdGraphCompactor` (`compactor.ts:138-141, 268, 303`) lossily summarizes facts idle for 4 rounds without an `expand_digest` tool. Any planner JSON parse error sets `plannerDoneRound` (`5826-5839`), and 6 consecutive dry steps globally halt investigation (`192-223, 3963-3973`).
  * **English-REST heuristic-gated detection:** `deterministic-engine.ts` caps at 120 endpoints / 120 hypotheses (`35-36`) and gates SSRF, XXE, path traversal, SSTI, command injection, open redirect, and workflow hypotheses behind English REST naming regexes (`162-193, 547, 711`), probes `?reveal=0` (`1659`), and embeds realistic-bench token regexes (`1557`). `workflow_invariant` (`708-746`) only models a 1-step repeat transition on `POST /<collection>/:id/<actionVerb>`. Opaque/non-English routes, RPC APIs, and multi-step business-logic invariants never generate hypotheses.
  * **Single-process SQLite bottlenecks & data-model clobbering:** `process-lock.sqlite` holds `BEGIN EXCLUSIVE` for process lifetime (`store.ts:477-483`). `DatabaseSync` runs on the main thread with `PRAGMA synchronous = FULL` (`492-493`); every HTTP exchange synchronously calls `writeFileSync(..., { flush: true })` into an unsharded `artifacts/` dir (`1603-1606`) and updates an FTS5 **trigram** index (`874-884, 1717-1723`) with zero GC/retention. `listEndpoints()` hard-truncates at 500 (max 2,000; `4209-4234`), `runDetail()` hydrates unbounded rows across ~20 tables (`1435-1528`), and `resource_samples` defines `UNIQUE(run_id, owner_persona, resource_key, origin)` keyed by JSON field name (`id`, `816, 4384, 4495`)—causing `/invoices`, `/orders`, and `/tickets` on one origin to overwrite each other's entity IDs.
* **Real-World Impact:** Enterprise targets (>500 endpoints, multi-hour runs, 10k+ exchanges) suffer main-thread stalls, disk/FTS5 bloat, OOM on report generation, silent endpoint truncation, BOLA ID clobbering, lossy chain context, and missed vulnerabilities on non-conventional routes.

---

### Tier 2 — High-Impact Secondary Limitations

| # | Limitation | Exact Locations | Mechanism & Real-World Impact |
|---|---|---|---|
| **8** | **Rigid specialist tool silos & dropped board handoffs** | `agent-session.ts:658-757, 867-939, 1321-1322`; `execution.ts:1658-1748, 5429-5570`; `board-tools.ts:44-47, 538-555, 879-1042` | Regex routing hard-strips tools per specialist (`bola-bfla` lacks browser/scripts/race; `injection-parser` lacks `request_http_batch`; `dom` lacks SAST/scripts). `wakeBoardMember` silently drops wakes when target is busy; warm sessions retire on any failure and accumulate token counts additively toward the 60% ceiling. Multi-channel chains stall or drop. |
| **9** | **Air-gapped scripting & fragile NDJSON pipe** | `worker-backend.ts:274-280, 315-378, 574-603, 720-809`; `worker/bridge.ts:122-123, 1442-1527`; `worker/Dockerfile:62`; `agent-session.ts:3602` | Workers run `--network none` with only `PyJWT`/`cryptography`, decoupled from host HTTP/browser; any >64 KiB NDJSON line or >4 MiB cumulative session stdout kills the container; `execCommand` timeout calls `process.exit(124)` wiping `/tmp`; `toolExecution` is forced `'sequential'`. Blocks HMAC/request-signing, protobuf/encrypted APIs, and large SAST outputs. |
| **10** | **White-box ingestion & thin CVE correlation** | `github-connector.ts:76-78, 651, 810, 829`; `semantic-audit.ts:620-671, 861-864, 1213, 1332-1391, 1448-1460, 1656-1661, 2066`; `phase0-recon.ts:289-618, 2058-2065`; `cve-broker.ts:449-453, 514-516` | `cloneGithubRepos` clones `--depth 1` and deletes `.git`, making Stage-3 `mineGitSecurityHistory` permanently dead. Static route regexes lose mount prefixes (`app.use('/v2', ...)`), `resolveSuspectEntrypoint` traverses <=1 reverse call-graph hop, multi-origin repos bind to `origins[0]`, `pom.xml` parsing misaligns `<artifactId>`/`<version>`, and `CVE_TEMPLATE_IDS` maps only 1 CVE (`CVE-2025-29927`). |
| **11** | **Brittle `LabRunner` containerization** | `lab-runner.ts:70, 162, 331-464, 1054-1077, 1310-1407, 1576, 1614-1620`; `plans/SECURITY-REAUDIT-2026-11-22.md:202` | Hard cap of 6 containers, regex Compose parser, `docker build --network none`, forced `--read-only` + 64MB `/tmp` (breaks DBs), `docker exec ... node -e` readiness checks (breaks Postgres/Redis/Go/Python), and per-TCP-connection `docker exec` proxying (fails distroless/compiled images, risks `pidsLimit: 128` exhaustion). Breaks local-lab white-box & Patch Gate 6 on real stacks. |
| **12** | **Coarse origin provenance & aggressive 5xx/WAF circuit breakers** | `store.ts:3394-3533, 3727-3800`; `broker.ts:1966-1997, 2042, 2463-2707`; `execution.ts:1282-1314`; `response-checks.ts:139-176` | Exact-origin provenance drops findings touching third-party IdP/CDN redirect hops (`writeReport`). Non-JWT auth tokens cannot be mutated (`broker.ts:2463-2707`). Five `5xx` responses in 30s trip a route circuit breaker, and origin circuit trips permanently pause runs with no cooldown recovery—causing error-inducing probes to self-block verification. |
| **13** | **Incomplete crash recovery & ephemeral runtime state** | `store.ts:961-973, 2173-2177, 3351-3363`; `execution.ts:956-999, 7887-7928`; `lab-runner.ts:1523` | `Store.recover()` leaves `board_members` stuck `working`, orphans `LabRunner` containers/tmpdirs, loses in-memory refinement queues, approval ledgers, session/CSRF jars, and canary bindings, and unconditionally re-queues permanently `failed` assignments on resume. |

---

## 3. Target Architecture & Redesign Blueprint

To close the real-world gap without sacrificing Guardian's core safety invariants (strict scope enforcement, non-destructive verification, zero-hallucination evidence), refactor along **five decoupled workstreams**.

### Workstream A — Unified Floor + Tool-Augmented Graph Planner (Fixes #1, #7, #8, #9)

1. **Always-On Bounded Deterministic Floor (`execution.ts`, `assignment-brief.ts`, `agent-session.ts`):**
   * Remove the `!profiles.length` gate in `driveInvestigation()`. Run a bounded deterministic floor (configurable budget, e.g., 15–25% of run request budget, non-blocking via progressive streaming of `EngineConfirmed` and `EngineLead` records to the store) *before* or *concurrently with* agentic lanes.
   * Wire `buildAssignmentBrief()`, `alreadyConfirmed`, `detLeads`, and `resolveAgenticTurnBudget()` + explicit `wallClockMs` caps into `startInvestigationStep()` so LLM specialists never waste turns re-probing confirmed findings and prioritize unresolved high-signal leads and business-logic/chaining hypotheses.
2. **Stateful Tool-Equipped Chain Planner (`execution.ts`, `compactor.ts`):**
   * Replace the tool-less single-shot `runChainPlanner` prompt with a compact, persistent planner session equipped with read-only graph tools: `query_endpoints`, `query_facts`, `query_findings`, `expand_digest(digestId)`, and `list_uncovered_routes(cursor, limit)`.
   * Never terminate investigation on a single malformed planner JSON response (retry with schema feedback) or on parallel dry steps (count dry *rounds* with zero new coverage rather than raw step completions).
3. **Capability-Based Specialist Profiles & Reliable Board Delivery (`agent-session.ts`, `execution.ts`, `board-tools.ts`):**
   * Replace rigid regex-stripped tool silos with additive capability bundles (every specialist retains read-only graph/SAST query + `request_http_batch`, with browser/race/canary/script capabilities granted when the hypothesis or peer handoff demands them).
   * Persist board wakeups in a durable per-member queue in SQLite (delivered when the member transitions `working -> waiting`) instead of dropping wakes in memory; separate per-step context tokens from lifetime cumulative tokens.
4. **Resilient Worker Bridge & Networked Helper Proxy (`worker-backend.ts`, `worker/bridge.ts`):**
   * Raise NDJSON transport framing to chunked/file-backed IPC (spill tool payloads >64 KiB to mounted tmpfs with pointer passing instead of killing the container) and handle command timeouts via child-process cancellation rather than `process.exit(124)`.
   * Enable parallel execution for pure read-only tool calls and expose a scoped host-mediated `broker_rpc` bridge inside `run_offline_script` (strictly routed through `Broker` scope/tier/rate-limit enforcement) so custom Python/Node scripts can perform dynamic request signing, HMAC/protobuf serialization, and multi-step challenge-response without breaking `--network none` isolation.

---

### Workstream B — Enterprise Auth, Modern SPA Hydration & Three-Tier Origin Scope (Fixes #2, #3, #12)

1. **Three-Tier Scope Model (`schema.ts`, `broker.ts`, `scoped-browser.ts`, `store.ts`):**
   * Separate origins into three explicit classes on every engagement:
     * `targetOrigins` (active probing & verification allowed up to `capabilityTier`)
     * `authOrigins` (read/form/OAuth redirect traversal allowed strictly for persona authentication; active probing forbidden)
     * `assetOrigins` (passive `GET` allowed for JS/CSS/font/map hydration in `ScopedBrowser`; active probing forbidden)
   * Update `writeReport()` and transitive revocation so benign redirect hops through `authOrigins` / `assetOrigins` never suppress valid findings on `targetOrigins`.
2. **Composite Per-Worker Session Vault & OIDC/MFA Support (`persona-vault.ts`, `persona-auth.ts`, `broker.ts`):**
   * Upgrade `MintedPersonaSession` to a composite credential bundle (`cookies[]` including `HttpOnly` + `headers: Record<string, string>` + `storage: { localStorage, sessionStorage }` + `originBindings`) so hybrid Cookie + Bearer + `X-Tenant-Id` apps work seamlessly across `app.` and `api.` origins.
   * Add: (a) standard OIDC/OAuth2/SAML interactive Playwright login flow permitting `authOrigins` redirects, (b) optional TOTP seed support and interactive cookie/storage-state import for MFA/passkey/SSO apps, and (c) **per-worker isolated session clones** with coordinated single-flight refresh (replacing the global 60s re-auth lockout and preventing one destructive/logout probe from poisoning sibling workers).
   * Only treat CAPTCHA as blocking when an interactive challenge actually prevents login submission, not when a script tag is merely present in DOM.
3. **Interactive Pooled SPA Crawler & Multi-Persona Discovery (`scoped-browser.ts`, `phase0-recon.ts`, `surface-engine.ts`):**
   * Reuse a pooled Playwright browser context per persona (instead of cold-booting Chromium per URL), seed `HttpOnly` cookies + `localStorage`/`sessionStorage`, attach persona headers to all allowlisted sibling API origins, and wait on network-idle / DOM-stability heuristics rather than `120ms`.
   * Add safe interactive state exploration (clicking nav items, tabs, pagination, read-only dropdowns/filters) and allow read-only GraphQL/RPC `POST` queries (`operationType === 'query'`) below Tier 3.
   * Run Phase-0 discovery across **all distinct role personas** (unioning role-exclusive endpoints and tagging `visibleToPersonas`), capture WebSocket handshakes/frames via Playwright CDP `Network.webSocket*` events, support `multipart/form-data` & per-prefix soft-404 calibration, and stop skipping `/` in `surface-engine.ts`.

---

### Workstream C — Modern Transport, Public Async OOB & Noise-Tolerant Verification (Fixes #4, #5)

1. **HTTP/2-Capable Transport & Configurable Egress (`broker.ts`):**
   * Add an `undici` / `node:http2` transport backend supporting HTTP/2 multiplexing, **single-packet / last-byte synchronized `executeRaceBurst`**, optional corporate HTTP/SOCKS egress proxy, mTLS client certificates, configurable realistic `User-Agent` / header profiles for authorized WAF-fronted targets, and turn-aware stateful WebSocket sessions (awaiting server frames + continuation reassembly).
   * Add a controlled Tier-3 raw-framing capability (explicitly opt-in for authorized targets) for Host-header and HTTP desync/smuggling verification without weakening scope pinning.
   * Distinguish target `5xx` responses triggered by active injection/parser probes from transport failures/429s so error-based probing does not trip its own verification circuit breaker; add exponential-backoff cooldown recovery instead of permanently halting runs.
2. **Externally Routable Async OOB Relay (`canary-broker.ts`, `replay-verifier.ts`, `execution.ts`):**
   * Support a lightweight deployable/managed public OOB relay mode (HTTP + automated ACME/TLS HTTPS + authoritative UDP/TCP DNS, with optional SMTP listener) alongside local loopback mode, configured via a single engagement relay profile.
   * Replace the synchronous `1.5s` poll loop with **two-stage async OOB correlation**: a short immediate check (e.g., 2–3s) followed by durable `pending_oob` state that stays subscribed to the relay for the remainder of the run (or configurable delay window, e.g., 5–30 minutes) and automatically promotes matching late callbacks into verified findings.
3. **Flexible, Noise-Tolerant Verification & Accurate Deduplication (`replay-verifier.ts`, `proof-tools.ts`, `replay-spec.ts`, `dedupe.ts`):**
   * **Hybrid `http_browser_chain` specs:** Allow a single declarative spec to mutate/seed state via HTTP (or persona A) and verify DOM execution/CSP bypass or cross-persona UI rendering in Playwright (with full `HttpOnly` cookie bridging).
   * **Rich extractors & jitter-resilient statistics:** Extend `proof-tools.ts` extractors beyond flat dotted JSON keys to JSONPath/array indices, regex/CSS-selector HTML/XML extraction, and response headers. Replace brittle 3-round `minProbe > maxBaseline` checks in `sql_time_diff` with adaptive baseline sampling (e.g., 5–7 interleaved control/probe pairs using Mann-Whitney U / median-MAD separation) and structural DOM/token-diffing (stripping dynamic nonces/timestamps) in `sql_boolean_diff`.
   * **Mutated-parameter dedupe:** Derive dedupe fingerprints from the **explicitly mutated parameter/header/GraphQL operation/RPC procedure** recorded in the replay spec rather than `Object.keys(jsonBody)[0]`, and scope `ORIGIN_WIDE_CWES` by service path prefix when distinct backend headers/cookies indicate reverse-proxied microservices.

---

### Workstream D — Production-Safe Mutations & Non-Blocking Scoped Approvals (Fixes #6)

1. **Non-Blocking Approval Queue & Scoped Policy Grants (`approval-judge.ts`, `execution.ts`, `store.ts`):**
   * Evaluate explicit operator-approved endpoint/method/class policies **before** keyword heuristics, reserving unconditional hard escalation strictly for genuinely destructive/out-of-policy operations.
   * Support **scoped durable approval leases** (e.g., `(runId, origin, normalizedRoute, method, vulnClass)` valid across probe iterations and Phase-3 replay verification) persisted in SQLite instead of single-use 60s exact-body-hash in-memory grants.
   * Decouple HITL waiting from worker execution: when a step requires human approval, park the step in `awaiting_approval`, release the `workerConcurrency` slot and container immediately, pause its lease timer, and re-enqueue on approval.
2. **Test-Entity Isolation & Teardown Contract (`replay-spec.ts`, `proof-tools.ts`, `execution.ts`):**
   * Add first-class `setup` / `cleanup` steps and a run-scoped entity prefix (`guardian-qa-<runShortId>-`) to `http_chain` and `workflow_invariant` specs so stateful verification creates, mutates, verifies, and deletes its own test records instead of colliding with shared staging data or burning one-shot records.

---

### Workstream E — Scalable Persistence, Behavior-Driven Detection & White-Box Repair (Fixes #7, #10, #11, #13)

1. **Scalable Store & Relational Entity Model (`store.ts`, `schema.ts`):**
   * Move SQLite to `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;`, batch exchange writes asynchronously off the hot HTTP path, shard `artifacts/<runId>/<bucket>/`, replace full-body FTS5 trigram indexing on every exchange with opt-in/bounded indexing + TTL/retention cleanup, and paginate `listEndpoints`, `listFacts`, and `runDetail` (removing the silent 500/2,000 endpoint truncation).
   * Fix `resource_samples` uniqueness from `UNIQUE(run_id, owner_persona, resource_key, origin)` to `UNIQUE(run_id, owner_persona, origin, collection_path, resource_key)` so distinct collections (`/invoices`, `/orders`, `/tickets`) never clobber each other's IDs.
   * Harden `Store.recover()` to reset stuck `board_members`, persist refinement queues and approval leases, track active `LabRunner` container IDs in SQLite for orphan reaping on startup, and distinguish retryable failures from permanent failures on resume.
2. **Schema- & Response-Driven Hypothesis Generation (`deterministic-engine.ts`, `cve-broker.ts`):**
   * Decouple hypothesis planning from English URL regexes (`pathHasUrlHint`, `pathHasXmlHint`, etc.) by prioritizing **observed OpenAPI/GraphQL/HAR/runtime parameter types and response shapes** (e.g., any parameter observed holding a URL/UUID/XML/template/file-like value or triggering backend parser errors), while keeping path hints only as tie-breaking priority boosts. Remove benchmark-specific regexes (`rb[cst]_`, `?reveal=0` assumptions) from core engine code.
   * Expand CVE-to-verification coverage by indexing compiled templates dynamically by CVE ID (replacing the 1-entry `CVE_TEMPLATE_IDS` map) and fixing `pom.xml` dependency block parsing to parse per-`<dependency>` XML element rather than parallel global regexes.
3. **White-Box & `LabRunner` Productionization (`github-connector.ts`, `semantic-audit.ts`, `lab-runner.ts`):**
   * Preserve shallow git history (e.g., `--depth 100` without deleting `.git`, or fetch security-relevant commit logs via API before cleanup) so Stage-3 `mineGitSecurityHistory` actually runs.
   * Replace single-file static route regexes with AST/router-mount-aware extraction (preserving `app.use` / `APIRouter` / `include()` prefixes), extend `resolveSuspectEntrypoint` to multi-hop reverse call-graph traversal (depth 5–8), and bind monorepo services to their matching origin via service config / Dockerfile / ingress mapping instead of `origins[0]`.
   * Replace `LabRunner`'s regex Compose parser and per-TCP `docker exec` proxy with a proper YAML Compose parser, configurable build/writable-mount overlays for DB sidecars, native TCP health probes from a shared Docker network, and a persistent lightweight forwarder (removing the `node`/`python3` requirement inside target containers).

---

## 4. Prioritized Rollout Order & Realism Verification Gates

Execute in four phases so every merge delivers measurable real-world gains on shipped `Execution` (never harness-only):

| Phase | Workstreams | Concrete Exit / Realism Gate |
|---|---|---|
| **Phase 1: Core Product Unification & Data Integrity** | A1 (unified deterministic floor + `buildAssignmentBrief`), E1 (`resource_samples` key fix, pagination >500 endpoints, WAL/async writes, `Store.recover`), C3 (mutated-param dedupe) | `Execution` agentic recall >= `Execution --no-llm` + significant chain/logic lift on both dev and salted held-out; 2,500-endpoint synthetic scale run completes with zero truncation and <50ms p99 main-thread store stall. |
| **Phase 2: Enterprise Auth, SPA & Scope** | B1 (3-tier origin model), B2 (OIDC/SAML/MFA + composite per-worker session vault), B3 (pooled interactive SPA crawler + multi-persona discovery) | New realistic integration fixture: CDN-hosted React SPA + split `app.`/`api.` origins + external OIDC IdP + hybrid Cookie+Bearer + `HttpOnly` admin view achieves >=80% endpoint discovery and authenticated verification. |
| **Phase 3: Modern Transport, Public OOB & Noise-Tolerant Proofs** | C1 (HTTP/2 + single-packet race + proxy/mTLS + error-safe circuit breaker), C2 (public HTTPS/DNS OOB relay + async late-callback promotion), C3 (hybrid HTTP+browser specs, rich extractors, jitter-tolerant timing/diff) | WAN-jitter (50–300ms injected latency) and delayed-callback (10–60s async webhook/worker) integration tests verify blind SQLi, blind SSRF/XXE, HTTP/2 race, and SPA stored XSS with <5% false negatives. |
| **Phase 4: Production Safety, Behavior-Driven Detection & White-Box** | D1–D2 (non-blocking scoped approvals + entity setup/cleanup), A2–A4 (tool-equipped planner, durable board wakes, chunked IPC + broker RPC), E2–E3 (schema-driven hypotheses, live git-history + multi-hop SAST binding, `LabRunner` network proxy) | Staging-mode (`environment: 'public'`) run verifies stateful write-BOLA/workflow/CSRF classes without deadlocking worker slots or leaking test entities; multi-hop monorepo white-box run confirms SAST suspects against live endpoints. |
