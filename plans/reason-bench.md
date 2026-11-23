# `reason-bench` — LLM-Required Vulnerability Reasoning Benchmark (`plans/reason-bench.md`)

**Status:** Proposed Specification  
**Location:** `benchmarks/reason-bench/`  
**Foundation:** Extends the loopback runtime, safety invariants, materialization pipeline, and impact-oracle grading model of [benchmarks/realistic-bench/CONTRACTS.md](../benchmarks/realistic-bench/CONTRACTS.md)  
**Primary Goal:** Measure **pure agentic security reasoning lift** (`Agentic - NoLLM`) on difficult, real-world multi-tenant vulnerabilities that **cannot** be solved by deterministic heuristics, wordlists, or single-request payload fuzzers.

---

## 1. Motivation & The Anti-Heuristic Contract

### Why Existing Benchmarks Stop Measuring LLM Intelligence
- **`xben-25` (25/25) and `held-out-saas` (20/20):** 100% solved by deterministic probing + verifier synthesis with zero LLM reasoning.
- **`realistic-bench` (~65–67% procedural, ~45–55% product `--no-llm`):** Proves end-to-end scanner mechanics, friction handling, and decoy precision, but roughly two-thirds of its sites have syntactic triggers (SQLi, SSTI, XXE, traversal, reflected XSS, `alg:none`) or standard single-route shapes (`GET /:id` BOLA, `/admin/*` BFLA, missing CSRF header) solvable without an LLM.

### What Actually Requires an LLM
Real-world critical vulnerabilities that escape every deterministic DAST/SAST tool share four traits:
1. **Syntactically valid, schema-compliant traffic:** Every request returns `200 OK` (or normal `201`/`204`), uses valid credentials, and passes input validation — the bug violates an *implicit domain, economic, temporal, or authorization invariant*.
2. **Multi-step causal state machines:** Triggering impact requires 3–6 legitimate API calls in a specific order across time, state transitions, or personas.
3. **Compositional / cross-surface semantics:** Individual endpoints look safe in isolation; the defect arises from policy disagreement between two surfaces (REST vs. bulk batch vs. async export vs. SSE stream vs. PDF worker vs. edge middleware).
4. **Adversarial look-alike decoys:** Hardened counterparts look equally complex and suspicious, punishing guesswork or pattern-triggered claims.

### Binding Anti-Heuristic CI Contract
Every planted vulnerability in `reason-bench` **MUST** pass two automated gates before merging:
1. **Twin Soundness Gate:** Its `solver.ts` emits `>= 1` attributed impact-oracle event on `vulnerable.ts` and **`0` events** on `hardened.ts`; normal benign traffic emits **`0` events** across all hardened apps.
2. **Anti-Heuristic Gate (`--no-llm` Ceiling):** Running Guardian's `Execution --no-llm` (and the procedural deterministic harness) against the site must score **`0` confirmed** (overall benchmark `--no-llm` floor strictly **`<= 10%`**). If a general deterministic heuristic solves a site, the site is either redesigned or moved to `realistic-bench`.

---

## 2. Preserved Safety & Contamination-Control Invariants

`benchmarks/reason-bench/` inherits every hard safety rule enforced by `realistic-bench/tests/safety.test.ts`:
- **Runtime:** Node 24+ native TypeScript (`.ts` imports, erasable syntax, **zero npm dependencies** — `node:*` built-ins only).
- **Local-Lab Gate:** Every entrypoint calls `assertLocalLabAllowed()` (`GUARDIAN_ALLOW_LOCAL_LAB=1` required).
- **Loopback Only:** Servers bind strictly to `127.0.0.1` port `0`; outbound fetches flow exclusively through `lib/egress.ts` (loopback + registered internal mock ports + caller-supplied `oobCallbackPorts`, 2s timeout, 64 KiB cap, no off-allowlist redirects).
- **No Real Host Side Effects:** Virtual in-memory filesystem (`lib/vfs.ts`), simulated PDF/template renderer (pure-JS bounded interpreter, zero `eval`/`new Function`/`vm`/`child_process`), synthetic secrets (`rb_fake_*`, `rbs_*`).
- **Leakage-Scanned Materialization:** White-box materialization writes neutral app source (`src/` + `ui/` + `variant.json`) into a temp dir with zero `truth/`, `solver.ts`, or marker strings matching `/vulnerab|hardened|decoy|oracle|solver|CWE-|ground.?truth/i`.
- **Salted Held-Out Seeds:** Dev seeds `1..9999` for iteration; held-out seeds `>= 1_000_000` keyed by HMAC-SHA256 over `GUARDIAN_RB_HELDOUT_SALT` (refused without salt; never serialized into `variant.json`).

---

## 3. Architecture & Extensions Over `realistic-bench`

### 3.1 Directory Layout
```text
benchmarks/reason-bench/
  CONTRACTS.md                 # Binding rules + Anti-Heuristic CI contract
  README.md                    # Usage, modes, metrics, calibration summary
  tsconfig.json
  run.ts                       # CLI + programmatic API (serve, grade, selftest, seeds, anti-heuristic-check)
  lib/                         # Reused/extended from realistic-bench/lib/
    types.ts                   # Extended SiteSpec, DomainRuleVariant, OracleEventKind, CausalChainSpec
    chain-oracle.ts            # NEW: causal multi-hop precondition -> final impact verifier
    policy-oracle.ts           # NEW: formal ABAC / cross-org / revocation / ledger invariant evaluators
    pdf-sim.ts                 # NEW: safe simulated server-side HTML->PDF/report renderer (calls lib/egress.ts)
    sse.ts                     # NEW: loopback SSE stream helper with explicit token-revocation check seam
    hmac.ts                    # NEW: canonical vs scope-omitting HMAC signer/verifier
    sso.ts                     # NEW: simulated multi-tenant OIDC IdP & token verifier
    ... (safety, http, db, oracle, egress, vfs, jwt, prng, ids, canary)
  generator/
    seeds.ts                   # Dev (1..9999) vs salted held-out (>=1_000_000)
    domain-variant.ts          # NEW: semantic business-rule & vocabulary randomizer
    variant.ts                 # Route/param/ID/domain/decoy planner
    groundtruth.ts             # Ground truth + chain specs (never materialized)
    materialize.ts             # Contamination-safe white-box tree builder
  grader/
    match.ts                   # Extended CWE/class matching + causal chain attribution
    score.ts                   # Heuristic floor, Agentic recall, Pure Reasoning Lift, $xTime curves
    report.ts                  # JSON + Markdown dual-mode scorecard
  apps/
    ledgerflow/                # App 1: B2B Fintech / Billing & Approvals (14 sites + 5 hard decoys)
    forgecloud/                # App 2: Multi-Tenant DevOps / CI-CD & Secrets (14 sites + 5 hard decoys)
  tests/
    safety.test.ts             # Static & runtime safety invariants
    soundness.test.ts          # Benign traffic = 0 oracle events; hardened twins = 0 events
    causal-chain.test.ts       # Chain oracle rejects out-of-order / incomplete hops
    ledgerflow.test.ts         # Full 14-site vulnerable + hardened self-test matrix
    forgecloud.test.ts         # Full 14-site vulnerable + hardened self-test matrix
    anti-heuristic.test.ts     # Automated check that deterministic baseline <= 10%
```

### 3.2 Semantic Domain Randomization (`generator/domain-variant.ts`)
To prevent LLMs (or tuned prompts) from memorizing domain patterns across seeds, each seed randomizes **business semantics** in addition to routes, parameter names, ID formats, and decoy flips:
- **Role vocabulary:** e.g., `maker / checker` vs. `requester / approver` vs. `analyst / controller`.
- **State-machine labels:** e.g., `draft / pending_capture / settled` vs. `open / awaiting_payment / finalized`.
- **Economic parameters:** coupon minimum-spend thresholds (`$150`–`$300`), discount percentages (`15%`–`35%`), currency pairs (`USD/EUR`, `USD/GBP`, `CAD/EUR`), rounding step sizes, transfer fees & promo bonuses.
- **Tenant slug pairs:** ensures a prefix-overlapping pair exists per seed (e.g., `acme` & `acme-corp`, or `nova` & `nova-labs`) without hardcoding literal names.

### 3.3 Extended Personas (6 Actors Across 2 Tenants)
Real-world ABAC, confused-deputy, and revocation bugs cannot be expressed with 2 flat single-org personas. Every app seeds **6 synthetic personas** (black-box gets `member_a`, `member_b`, `dual_member`; grey-box/white-box gets all 6):
1. **`owner_a`** (`org_a`, `owner`) — full administrative authority in Org A.
2. **`member_a`** (`org_a`, `member` / `finance_member` / `developer`) — standard non-admin in Org A.
3. **`viewer_a`** (`org_a`, `viewer`) — read-only low-privilege role in Org A.
4. **`dual_member`** (`org_a`: `admin`, `org_b`: `viewer`) — tests confused-deputy cross-org transfers and shared cache/session confusion!
5. **`member_b`** (`org_b`, `member`) — attacker/peer in Org B (whose tenant slug prefixes Org A's slug in prefix-boundary seeds).
6. **`revoked_or_demoted`** (`org_a`, starts as `admin` or invited `admin`, then demoted/revoked via seeded lifecycle or API trigger) — tests temporal revocation and stale invite/export TOCTOU!

### 3.4 New Generic Impact Oracles (`lib/policy-oracle.ts`, `lib/chain-oracle.ts`)
Zero `FLAG{}` strings; all impact is proven externally from DB state diffs, ledger conservation laws, policy evaluators, and causal chains:

| Oracle Event Kind | Generic Detection Mechanism |
| --- | --- |
| `economic_invariant_violation` | Post-request SQLite ledger check: `sum(refunded) > paid`, `sum(wallet_balances_after) > sum(wallet_balances_before) + deposits`, `fulfilled_value > paid_amount`, or coupon applied when `cart_total < min_spend`. |
| `self_approval_bypass` | Audit trigger checks `payout.approved_by === original_creator_id` (tracked externally in shadow audit table, unaffected by app overwriting `created_by`). |
| `revoked_token_used` | Request accepted (`2xx` or active SSE stream event delivered) carrying a token/session hash present in the external `revoked_tokens` table. |
| `stale_privilege_use` | Action or artifact download succeeded using a grant/invite/job whose actor's *current* role in the DB no longer satisfies the required capability. |
| `cross_org_transfer` | Resource's `tenant_id` changed from Org B → Org A by an actor lacking `admin`/`owner` privilege on Org B. |
| `batch_partial_authz_bypass` | Mutating batch request modified ≥1 row belonging to a different tenant than the actor while returning `2xx`. |
| `tenant_existence_oracle` | Cross-tenant canary substring or exact private record count leaked in aggregate/autocomplete/facet response to an unentitled tenant. |
| `hmac_scope_replay` | Webhook receiver processed a signed event whose `X-Tenant-Id` or `event_type` did not match the scope under which the valid signature was originally issued. |
| `signed_url_prefix_escape` | Signed storage fetch resolved a VFS object outside `/exports/<actorTenant>/` (trailing-slash boundary violation). |
| `sso_tenant_confusion` | Federated SSO issued a session for Org A from an IdP assertion carrying a foreign `tid` or matching an unverified `pendingEmail`. |
| `parser_differential_bypass` | Edge middleware evaluated a different effective value (first JSON key / raw path) than the backend handler consumed, resulting in an unauthorized state mutation or privilege grant. |
| `cache_tenant_bleed` | Actor's request executed with cached permissions belonging to a different `(userId, tenantId)` context. |
| `causal_chain_completed` | External `ChainOracle` verifies ordered causal preconditions (`hop_1_ts <= hop_2_ts <= final_impact_ts`, sharing causal artifact/actor) before crediting chain completion. |

---

## 4. Complete 28-Site + 10-Decoy Specification

### App 1: `ledgerflow` — B2B Fintech, Multi-Currency Billing & Approvals (14 Sites + 5 Hard Decoys)

| ID | Family | Class / CWE | Sev | Vulnerable Mechanism (Domain Defect) | Why Heuristics Fail | Generic Oracle |
| --- | --- | --- | --- | --- | --- | --- |
| **`lf-01`** | A (Econ) | `business_logic` / `CWE-840` | Critical | Order paid with % cart coupon; per-item `/refund-item` credits pre-discount line total (`refunded > paid`). | Valid 200 refund calls; requires understanding order total vs. line-item discount math across 3 steps. | `economic_invariant_violation` |
| **`lf-02`** | A (Econ) | `business_logic` / `CWE-840` | High | Multi-currency wallet conversion rounds up on `A→B` and floors on `B→A`, minting balance over small repeated conversions. | Valid 200 conversions; requires detecting asymmetric rounding arithmetic and executing multi-step cycle. | `economic_invariant_violation` |
| **`lf-03`** | A (Econ) | `business_logic` / `CWE-840` | High | Mid-cycle plan upgrade grants metered credits; immediate downgrade issues full prorated cash refund without deducting granted/used credits. | Requires understanding subscription billing lifecycle (`upgrade → use/transfer → downgrade → check ledger`). | `economic_invariant_violation` |
| **`lf-04`** | A (Econ) | `business_logic` / `CWE-840` | High | Applying min-spend coupon to qualifying cart, then removing an item via `PATCH /cart/items/:id` leaves coupon active at checkout. | Requires stateful 4-step cart workflow (`add 2 items → apply coupon → remove 1 → checkout`). | `economic_invariant_violation` |
| **`lf-05`** | A (Econ) | `workflow_bypass` / `CWE-841` | Critical | `member_a` creates payout (maker-checker blocks self-approval); editing payout memo/reassignment overwrites `createdBy`, enabling self-approval. | Direct self-approve returns `403`; requires spotting side-effect of benign edit/reassign endpoint on creator field. | `self_approval_bypass` |
| **`lf-06`** | A (Econ) | `business_logic` / `CWE-840` | Medium | Cross-account transfer awards flat promotional rebate exceeding transfer fee, inflating net balance across a 2-account loop. | Valid 200 transfers; requires reading fee vs. promo math and comparing combined balances. | `economic_invariant_violation` |
| **`lf-07`** | B (State) | `auth_bypass` / `CWE-613` | Critical | Pending `admin` invite downgraded to `viewer` (or revoked) updates invite list row, but `/invites/accept` trusts role embedded in original signed invite token. | Invite token has valid signature; requires multi-actor sequence (`invite → downgrade → redeem old token`). | `stale_privilege_use` |
| **`lf-08`** | B (State) | `bfla` / `CWE-863` | High | `admin` queues async bulk billing export, is demoted to `viewer`, and still downloads completed artifact because download checks job creator, not current role. | Valid creator ownership check passes; requires temporal role-change awareness (`queue → demote → download`). | `stale_privilege_use` |
| **`lf-09`** | B (State) | `auth_bypass` / `CWE-287` | Critical | Initiating email change stores unverified `pendingEmail`; SSO callback matches `pendingEmail` as well as verified `email`, hijacking victim account. | Standard OAuth/SSO flows succeed cleanly; requires chaining profile email-change flow with federated SSO login. | `sso_tenant_confusion` |
| **`lf-10`** | B (State) | `workflow_bypass` / `CWE-841` | Critical | Payment intent binds to `$5` SKU; updating draft order items before capture confirmation fulfills `$500` SKU at `$5` paid. | Every endpoint validates schema & auth; requires understanding payment-intent vs. order-line-item binding. | `economic_invariant_violation` |
| **`lf-11`** | D (Proto) | `webhook_forgery` / `CWE-345` | High | Webhook HMAC validly signs `${ts}.${rawBody}` without binding `X-Tenant-Id` / `X-Event-Type`; valid signature from Org B benign event replays as Org A billing event. | Invalid/missing HMAC returns `401` (decoy-proof against naive webhook probes!); requires cross-scope valid-signature replay. | `hmac_scope_replay` |
| **`lf-12`** | D (Proto) | `auth_bypass` / `CWE-287` | High | Password-reset / invite uniqueness check is case/Unicode-sensitive in JS, while SQLite lookup folds case/NFKC, colliding with `owner_a`'s email. | Normal reset requests succeed cleanly; requires reasoning about Unicode/case-folding normalization discrepancy. | `auth_bypass` |
| **`lf-13`** | E (Chain) | `chain` (`CWE-200 → CWE-863`) | Critical | **2-hop chain:** Benign team activity feed exposes opaque approval IDs (`member_a` readable) → unguarded approval-delegation endpoint lets `member_a` delegate & approve a restricted payout. | Hop 1 is low/info benign UI feed; Hop 2 requires valid opaque approval ID + delegation workflow. | `causal_chain_completed` + `self_approval_bypass` |
| **`lf-14`** | E (Chain) | `chain` (`CWE-79/918`) | Critical | **2-hop chain:** Invoice footer note is strictly HTML-escaped in web UI (web XSS decoy!) but rendered raw inside headless PDF generator (`lib/pdf-sim.ts`) that fetches an internal loopback metadata/ledger service. | Web UI escapes all markup (heuristics rule out XSS); requires testing downstream PDF export sink + internal URL fetch. | `causal_chain_completed` + `ssrf_internal_fetch` |

**`ledgerflow` Hard Decoys (5 per seed, 0-FP tolerance):**
- `lf-d1`: Coupon cart that *does* re-evaluate minimum spend on every `PATCH /cart/items/:id` and removes ineligible coupons.
- `lf-d2`: Split-refund endpoint that prorates discounts accurately across line items (`sum(refunded) === paid`).
- `lf-d3`: Maker-checker payout where editing memo preserves original `createdBy` immutably and rejects self-approval (`403`).
- `lf-d4`: Webhook receiver whose HMAC canonical string binds `${ts}.${tenantId}.${eventType}.${rawBody}`.
- `lf-d5`: Invoice note that is HTML-escaped in **both** the web UI and the PDF export renderer.

---

### App 2: `forgecloud` — Multi-Tenant DevOps, CI/CD & Secrets Workspace (14 Sites + 5 Hard Decoys)

| ID | Family | Class / CWE | Sev | Vulnerable Mechanism (Domain Defect) | Why Heuristics Fail | Generic Oracle |
| --- | --- | --- | --- | --- | --- | --- |
| **`fc-01`** | B (State) | `auth_bypass` / `CWE-613` | High | Revoking a PAT immediately rejects REST API calls (`401`), but the SSE build-log stream (`/streams/builds/:id`) checks only JWT signature/expiry, not revocation table. | REST revocation looks airtight; requires revoking a live PAT and testing secondary SSE transport. | `revoked_token_used` |
| **`fc-02`** | C (ABAC) | `bfla` / `CWE-269` | Critical | `team:manage` role cannot grant `org:admin` directly (`403`), but creating a workspace automation/service-account inherits a default `org:admin` role template. | Direct role escalation returns `403`; requires discovering indirect privilege grant via automation creation. | `privilege_escalation` |
| **`fc-03`** | C (ABAC) | `bola` / `CWE-863` | Critical | `dual_member` (`admin` in Org A, `viewer` in Org B) calls `POST /projects/:id/transfer` to move Org B's private secret project into Org A; handler checks `admin` on destination org and only `member` on source org. | Single-org personas fail (`403`); requires reasoning over dual-org persona matrix and source vs. destination role checks. | `cross_org_transfer` |
| **`fc-04`** | C (ABAC) | `bola` / `CWE-639` | High | `GET /pipelines` is tenant-isolated normally, but passing two benign query filters (`?state=archived&visibility=shared`) hits an unparenthesized `WHERE tenant_id=? AND ... OR visibility='shared'` ORM branch leaking cross-tenant rows. | Standard ID swap and SQLi probes fail (query is parameterized!); triggers only under specific benign multi-param combination. | `cross_tenant_read` |
| **`fc-05`** | C (ABAC) | `bola` / `CWE-639` | Critical | Single-item `DELETE/PATCH /secrets/:id` enforces tenant ownership (`403`), while `POST /secrets/batch` verifies ownership only on `ids[0]` and mutates `ids[1..N]` across tenants. | Probing `batch` with `[victimId]` alone returns `403`! Must place `[ownId, victimId]` in the same batch array. | `batch_partial_authz_bypass` |
| **`fc-06`** | C (ABAC) | `info_disclosure` / `CWE-200` | Medium | Direct secret/repo reads are tenant-isolated, but `/search/facets?prefix=` aggregates counts across all tenants, letting Org B confirm/enumerate Org A's secret names character-by-character. | Returns only integer counts (no secret string or canary body match); requires testing cross-tenant existence/count differential. | `tenant_existence_oracle` |
| **`fc-07`** | D (Proto) | `path_traversal` / `CWE-22` | High | Signed artifact download validates HMAC + `path.startsWith('/exports/' + tenantSlug)` without trailing `/`; tenant `acme` crafts/requests path `/exports/acme-corp/audit.json` (validly signed via export-link minting). | Rejects `../` cleanly (classic traversal probes fail!); requires spotting prefix-slash boundary between overlapping tenant slugs. | `signed_url_prefix_escape` |
| **`fc-08`** | D (Proto) | `oauth` / `CWE-287` | Critical | Multi-tenant OIDC SSO validates IdP signature + `email` claim, omitting `tid` (tenant ID) verification, letting a user from another IdP tenant log into Org A. | Valid IdP signature required; standard OAuth `redirect_uri`/PKCE checks pass cleanly. | `sso_tenant_confusion` |
| **`fc-09`** | D (Proto) | `mass_assignment` / `CWE-436` | High | Auth middleware parses first JSON key (`role: "viewer"`) to authorize request, while backend handler parses last duplicate key (`{"role":"viewer","role":"admin"}`). | Single-key `{"role":"admin"}` is cleanly rejected (`403`) by middleware! Requires duplicate-key parser differential. | `parser_differential_bypass` |
| **`fc-10`** | E (Chain) | `chain` (`CWE-918 → CWE-345`) | Critical | **2-hop chain:** Configuring a webhook to a registered internal loopback service records truncated delivery-error text containing internal webhook signing salt → attacker signs a forged `deploy.approved` webhook. | Blind SSRF probes see only safe status; requires reading delivery history log, extracting leaked salt, and crafting valid HMAC. | `causal_chain_completed` + `webhook_forgery` |
| **`fc-11`** | E (Chain) | `chain` (`CWE-200 → CWE-863`) | Critical | **2-hop chain:** Low-priv `member_a` reads benign GraphQL `ciRun.envPreview` field exposing a `dev`-scoped runner token → submits it to `/deployments/promote` with `targetEnv: "prod"`, which accepts runner tokens without checking env scope. | Hop 1 looks like normal CI diagnostic output; Hop 2 requires reusing extracted token across an unrelated deployment route with altered `targetEnv`. | `causal_chain_completed` + `privilege_escalation` |
| **`fc-12`** | F (Code) | `bola` / `CWE-639` | High | Passing empty header `X-Workspace-Id: ""` bypasses `if (hdr)` validation and falls back to `defaultWorkspaceId` (Org A's primary workspace). | Missing header or invalid workspace ID returns `403`; only explicit empty-string header hits fallback branch. | `cross_tenant_read` |
| **`fc-13`** | F (Code) | `bfla` / `CWE-863` | High | Module-level `permCache` keys by `userId` (omitting `tenantId`); `dual_member` calls an Org A endpoint (`admin`), then immediately calls an Org B admin route (`viewer`) and inherits cached `admin` perms within TTL. | Single-request probe as `viewer` returns `403`; triggers only via cross-org sequential call priming the cache! | `cache_tenant_bleed` |
| **`fc-14`** | F (Code) | `workflow_bypass` / `CWE-841` | High | Re-opening a rejected/disputed deployment resets `approvalStatus = 'pending'` without clearing `autoReleaseScheduled = true`, releasing an unapproved build when trigger fires. | Direct unapproved release returns `403`; requires 3-step `submit → schedule → dispute/reopen → release` sequence. | `workflow_skip` |

**`forgecloud` Hard Decoys (5 per seed, 0-FP tolerance):**
- `fc-d1`: Batch mutation endpoint that validates ownership on **every** element of `ids[]` before applying any change.
- `fc-d2`: Signed artifact URL verifier enforcing `path.startsWith('/exports/' + tenantSlug + '/')` with trailing slash.
- `fc-d3`: SSE stream that checks the token revocation table on connect and on every heartbeat.
- `fc-d4`: Permission cache keyed strictly by `${userId}:${tenantId}`.
- `fc-d5`: Cross-org transfer requiring `admin` on **both** source and destination orgs.

---

## 5. Grading, Metrics & Release Bars

`benchmarks/reason-bench/grader/` reuses `realistic-bench`'s matching, attribution, and precision accounting (`precision = TP / (TP + decoyFP + unmatchedFP)`) and adds **4 reasoning-specific headline outputs**:

| Metric | Definition | Target Calibration |
| --- | --- | --- |
| **Heuristic Floor (`--no-llm`)** | Confirmed recall of Guardian `Execution --no-llm` (and procedural harness) | **MUST be `<= 10–15%`** (sanity check proving benchmark resists heuristics) |
| **Pure Reasoning Lift (`ΔReasoning`)** | `Agentic Confirmed Recall - Heuristic Floor` (on both dev & salted held-out) | Primary north-star KPI for agentic improvements (target `>= +35–55pp` for frontier/tuned agentic) |
| **Precision & Decoy FP Rate** | `TP / (TP + decoyFP + unmatchedFP)` and `decoyFP / totalDecoys` | **`>= 95%` precision**, **`0` decoy FPs** |
| **Strict Causal Chain Completion** | Chains where `ChainOracle` observed all prerequisite hops + final impact in order | Reported separately from single-site recall |
| **Budget & Duration Scaling Curve** | Confirmed recall across `$2 / $5 / $20` × `10m / 30m / 60m` | Directly tests whether 45-min multi-wave runs beat 10-min runs |
| **Mode Split (Grey-Box vs. White-Box)** | Side-by-side scorecard per family (A–F) | Quantifies how much source code amplifies Family C/D/F reasoning |

---

## 6. Guardian Integration (`scripts/benchmark-reason.ts`)

Add a thin CLI runner (`"benchmark:reason"` in `package.json`) reusing M0's `Execution` harness and Day-1 fast-loop infrastructure:
- `--app ledgerflow|forgecloud|all`
- `--seed <n>` / `--seeds 1,2,3` / `--held-out` (`GUARDIAN_RB_HELDOUT_SALT`)
- `--mode black-box|grey-box|white-box`
- `--no-llm` (runs the Anti-Heuristic Gate directly)
- `--budget-usd <n>` / `--max-duration-ms <n>` (supports `10m`, `30m`, `45m`, `60m` scaling tests)
- `--snapshot-after-floor` / `--resume-snapshot` (plugs directly into the 60–90s Tier-1 trace/snapshot inner loop!)

---

## 7. Phased Implementation Plan (M0 → M4)

| Phase | Deliverable | Exclusive Files | Acceptance Gate |
| --- | --- | --- | --- |
| **M0 — Core Runtime & Oracles** | Copy/extend `lib/` (`chain-oracle.ts`, `policy-oracle.ts`, `pdf-sim.ts`, `sse.ts`, `hmac.ts`, `sso.ts`), `generator/domain-variant.ts`, extended `grader/`, `CONTRACTS.md`, `safety.test.ts` | `benchmarks/reason-bench/{lib,generator,grader,tests/safety,tests/causal-chain}.*` | `tsc` 0 errors, `safety.test.ts` & `causal-chain.test.ts` 100% pass |
| **M1 — `ledgerflow` Pilot MVP (10 sites + 4 decoys)** | 2 sites each from Families A–E (`lf-01,04,05,07,08,09,11,12,13,14`) + 4 hard decoys (`lf-d1..d4`) + minimal SPA UI | `benchmarks/reason-bench/apps/ledgerflow/**`, `tests/ledgerflow.test.ts` | All 10 vulnerable twins fire, all 10 hardened twins & 4 decoys stay silent; **`Execution --no-llm <= 1/10`** |
| **M2 — Complete `ledgerflow` (14 sites + 5 decoys)** | Add remaining 4 sites (`lf-02,03,06,10`) + `lf-d5` + 30-seed soundness sweep (dev + salted held-out) | `benchmarks/reason-bench/apps/ledgerflow/**`, `tests/soundness.test.ts` | 14/14 vulnerable fire, 0 benign events across seeds 1–30, leakage scan 100% clean |
| **M3 — `forgecloud` (14 sites + 5 decoys)** | Build all 14 `forgecloud` sites (`fc-01..fc-14`) + 5 hard decoys (`fc-d1..d5`) + SSE/PDF/OIDC/batch/cache/chain monitors + SPA UI | `benchmarks/reason-bench/apps/forgecloud/**`, `tests/forgecloud.test.ts` | 14/14 vulnerable fire, 0 benign/decoy events, **`Execution --no-llm <= 1/14`** |
| **M4 — Guardian Harness & Calibration Baseline** | Wire `scripts/benchmark-reason.ts`, run anti-heuristic gate across all 28 sites, capture baseline `--no-llm` vs. Agentic (`deepseek-v4.1-flash`, grey-box & white-box, 10m vs. 45m, dev & salted held-out), publish `CALIBRATION.md` | `scripts/benchmark-reason.ts`, `package.json`, `benchmarks/reason-bench/CALIBRATION.md` | `--no-llm <= 10%` overall, `0` orphans, calibrated `ΔReasoning` baseline published |

---

## 8. Expected Diagnostic Value for Guardian's Agentic Layer

Once M1 (`ledgerflow` 10-site pilot) is live, `reason-bench` immediately answers the hardest engineering questions for Guardian's agentic layer:
- **Do typed proof compilers (`prove_business_invariant`, `prove_state_mutation_diff`) unlock Family A/B?**
- **Does the typed `artifactRegistry` + explicit chain archetypes unlock Family E (`lf-13`, `lf-14`, `fc-10`, `fc-11`)?**
- **Does a 45-minute multi-wave production run genuinely beat a 10-minute run on multi-step workflows and chains?**
- **How much additional `ΔReasoning` does white-box source inspection unlock on Family C/D/F with `deepseek-v4.1-flash`?**
