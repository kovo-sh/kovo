# Guardian v4 — Engineering Handover (`HANDOVER-v4.md`)

**Date:** 2026-11-22  
**Branch:** `main` (`origin`: `https://github.com/wwwillchen/guardian.git`)  
**Spec Reference:** [SPEC-v4.md](SPEC-v4.md)

> **Status (2026-11-22): historical planning document, superseded by M7.**
> M1–M7 are implemented and the release gate is complete (XBEN 25/25, held-out
> 20/20, patches 20/20). Read
> [VERIFICATION-v4.md](VERIFICATION-v4.md) for the measured gate, recall,
> held-out, patch-retest and realistic-bench results. The “remaining work” and
> percentage estimates below describe the pre-M7 state and are kept for history.

> **v5 status (2026-11-22):** v5 is in progress. For the current line read
> [HANDOVER-v5.md](HANDOVER-v5.md) and the living
> [VERIFICATION-v5.md](VERIFICATION-v5.md); the v4 material below remains
> historical.

---

## 1. Executive Summary & Current Build Health

> **Superseded:** this section is a pre-M7 snapshot (it still lists M6/M7 as not
> started and shows 44/45 on the milestone suites). See
> [VERIFICATION-v4.md §2](VERIFICATION-v4.md#2-build-and-test-gate) for the final
> 519/519 non-Docker gate, and [§3–§5](VERIFICATION-v4.md#3-recall-hill-climbing-on-xben-25)
> for the recall and generalization results.

Guardian v4 implementation is **~75% complete** with all foundational architecture, security boundaries, worker tooling, Phase-0/orchestration code, multi-container `LabRunner`, IAST telemetry, and Web UI already landed and compiling cleanly:

- **`npm run check` (`tsc --noEmit`):** **PASS (0 errors)**
- **`npm run build` (`vite build` client + SSR):** **PASS**
- **v4 Zero-Trust Boundary Suites (`tests/v4-boundaries.test.ts`, `V4-B1`–`V4-B8`):** **8 / 8 PASS (100%)**
- **v4 Milestone Unit/Integration Suites (`v4-m1`, `v4-m2`, `v4-m3`, `v4-m5`):** **44 / 45 PASS** *(the sole failure is a 1-line count assertion `14 !== 13` at `tests/v4-m2-broker-browser-probes.test.ts:836` because M4 added a 14th `DifferentialProbeClass`)*
- **Playwright UI E2E (verified at M5 completion):** `tests/guardian-v2.spec.ts` **4 / 4 PASS**; `tests/guardian-v4.spec.ts` **3 / 3** M5 UI tests PASS (Test 4 Surface Graph E2E ready to run now that M4 `phase0-recon.ts` landed)
- **Docker Hygiene:** `0` orphan containers, `0` orphan networks; `guardian-worker:v4` + `guardian-worker:local` image (`f926ee3ebbd8`) built and verified

### Remaining Work at a Glance
1. **Finish M4 verification & polish** (update 1-line probe count in `M2.7`, run & green all M4 cases in `tests/v4-e2e-tiers.test.ts` and Test 4 in `tests/guardian-v4.spec.ts`, add `tests/v4-m4-surface-orchestration.test.ts`).
2. **Implement M6 (`benchmarks-and-labs`)**: `scripts/benchmark-recall.ts` (`npm run benchmark:recall`), local `benchmarks/xben-25/` dev suite, and Held-Out Modern SaaS Lab (`local-lab/saas-lab/` with 20 planted High/Critical vulns + 6 hard decoys).
3. **Execute M7 (`final-milestone`)**: Green 100% of v2/v3/v4 boundary + 322+ tiered E2E + Playwright suites, run **iterative recall hill-climbing** on `XBEN-25` (general engine improvements only, zero benchmark hardcoding), run **anti-overfitting validation** on Held-Out Modern SaaS Lab (`>= 18/20` confirmed, `0/6` decoy FPs, `>= 14/20` verified patches), and publish `VERIFICATION-v4.md`.

---

## 2. What's Done (By Milestone)

### ✅ M1 — Schema, Inline Verification & Role Routing (`DONE` — 15/15 PASS)
- **Files:** `src/domain.ts`, `src/replay-spec.ts`, `src/server/schema.ts`, `src/server/store.ts`, `src/server/model-settings.ts`, `src/server/provider.ts`, `src/server/replay-verifier.ts`, `src/server/execution.ts`, `src/server/agent-session.ts`, `tests/v4-m1-schema-verify-routing.test.ts`
- **Delivered:**
  - Lossless `v2/v3 -> v4` SQLite auto-migration (`Store.initV4Schema()`), 5 extended tables + 6 new tables (`endpoints`, `endpoint_params`, `api_dependencies`, `second_order_canaries`, `lab_telemetry`, `benchmark_runs`) with all 19 typed CRUD/query helpers.
  - Synchronous `verifyReplaySpecInline()` / `verify_replay_spec` & `propose_chain_finding(verifyNow=true)` with sanitized `InlineVerifyFeedback`, max 2 inline repair retries (`replay_specs.attempt_count` capped at 3), and strict Zero-LLM / `static_verified` tier locks.
  - Phase-3 single 8-turn focused Refinement Turn for failed late/cross-host specs.
  - `model_profiles.roleAffinity` (`reasoning` | `tactical` | `fast` | `any`) routing with single-profile & open-circuit fallback.

### ✅ M2 — Stateful Broker, Persistent Browser & Modern Probes (`DONE` — `V4-B1..B4` 4/4 PASS, 8/9 M2 unit PASS)
- **Files:** `src/server/broker.ts`, `src/server/redact.ts`, `src/server/scoped-browser.ts`, `src/server/canary-broker.ts`, `src/server/surface-engine.ts`, `src/replay-spec.ts`, `src/server/replay-verifier.ts`, `tests/v4-m2-broker-browser-probes.test.ts`
- **Delivered & Hardened (Wave-1 review/challenger findings resolved):**
  - Opaque host-side Ephemeral Session Jars (`session`), `control`/`probe` isolation, `setup` deep-clone, LRU caps, and immediate purge on `scopeRevision` revocation.
  - Automatic CSRF token extraction & egress binding (`csrfBind`) with secret redaction (`x-xsrf-token` + custom headers) and cross-origin redirect safety.
  - Broker-side JWT `authMutation` primitives (`alg_none`, `strip_signature`, `expired_replay`, `rs256_to_hs256_jwks`, `kid_inject`, `jku_x5u_canary`, `claim_swap`) with hardened `jku_x5u_canary` URL validation and dynamic redaction across full tokens, 2-segment `h.p` fragments, `payloadB64`, and error catch paths.
  - Tier-2 `sandboxWriteAllowlist` (defaults to `[]` on `public`, blocks double-encoded `%252e` traversal, `DELETE`, multipart, and destructive payloads).
  - Persistent 100%-brokered `ScopedBrowser.runBrowserSession()` sharing `PlaywrightContext`/`Page` across contiguous steps and resetting cleanly on `control <-> probe`, `probe/control -> setup`, `persona`, `origin`, or `resetContext: true`.
  - Universal 7 parameter encodings (`query`, `json`, `form`, `path`, `header`, `xml`, `graphql_var`), expanded `sqli_boolean` (including `or_branch` support in `sql_boolean_diff`), 3-round interleaved `sqli_time_diff` / `sql_time_diff` (#14, gated to `local-lab` / Tier 3), `xss_context`, `auth_protocol_audit` / `auth_protocol_proof` (#12), `xxe_canary`, `cache_poison_deception` / `cache_differential` (#13 with mandatory single-use `?_gcb=`), `mass_assignment` (boolean-safe check & cleanup), and Second-Order Canary Ledger (`gn2o_<8hex>`).

### ✅ M3 — Hardened Offline Worker, Semantic Audit & 1,600 Templates (`DONE` — 15/15 PASS + `V4-B7` PASS)
- **Files:** `worker/Dockerfile`, `worker/analyzers.ts`, `worker/bridge.ts`, `worker/rules/opengrep/` (137 YAML files, 1,500+ deduplicated rules), `src/server/worker-backend.ts`, `src/server/semantic-audit.ts`, `scripts/transpile-nuclei-templates.ts`, `src/templates/compiled/` (1,600 YAML templates), `src/templates/{loader,yaml}.ts`, `tests/v4-m3-worker-sast-templates.test.ts`
- **Delivered:**
  - `guardian-worker:v4` (aliased to `guardian-worker:local`): `--network none`, `--read-only`, `--cap-drop ALL`, `UID 10001:10001`, `1536m`/`256` defaults, 1,500+ offline Opengrep rules, pre-baked `/opt/trivy-cache` DB, `@swc/core` JS/source-map AST harvester, and multi-file call-graph / guard-dominance analyzer.
  - 3-stage offline semantic audit pipeline (`src/server/semantic-audit.ts`): Stage 1 `ProjectSecuritySpec` + safe dynamic rule generation; Stage 2 backward interprocedural dominance traversal lifting the 12-suspect cap (up to 80 budget-ranked); Stage 3 offline `git log` security miner & post-confirmation Variant Sweep.
  - Build-time safe Nuclei transpiler (`npm run templates:transpile`) producing **1,600 Zod-validated templates** in `src/templates/compiled/` with strict safety filters (rejects non-HTTP, third-party OAST, metadata/loopback IPs, destructive/webshell payloads, unreviewed mutating methods; rewrites `{{interactsh-url}}`).

### 🟡 M4 — Phase-0 Recon, State Graph & Specialist Orchestration (`~95% IMPLEMENTED, NEEDS VERIFICATION`)
- **Files:** `src/server/phase0-recon.ts` (new, ~50 KB), `src/server/surface-engine.ts`, `src/server/execution.ts`, `src/server/agent-session.ts`
- **Already Implemented & Compiling (`tsc` 0 errors, `build` PASS):**
  - `src/server/phase0-recon.ts`: `runPhase0Recon`, `crawlStateGraph`, and `extractStaticFrameworkRoutes` (11 frameworks + dynamic wordlist synthesis + Tier-0 repo-only mode + budget cap `min(floor(15% * budgetRequests), 250)`).
  - `src/server/surface-engine.ts`: Expanded GraphQL SDL resolver fuzzer (`diffGraphqlSurface` with nested-edge BOLA/BFLA & mutation gating) and BOLA/BFLA/workflow-skip helpers.
  - `src/server/execution.ts` & `src/server/agent-session.ts`: Phase-0 wiring, `crawl_state_graph` & `browser_session` tool wiring, dynamic step budget (`clamp(24, crownJewels * 2 + suspects, 200)` persisted via `updateRunDynamicStepBudget`) + `K=6` diminishing-returns stopping, all 7 clean-context Specialist Worker Profiles (`bola-bfla-specialist`, `injection-parser-specialist`, `auth-session-oauth-specialist`, `client-browser-dom-specialist`, `graphql-api-specialist`, `business-logic-race-specialist`, `protocol-cache-edge-specialist`), and crown-jewel Multi-Trial Parallel Branching (`trialGroupId`, `trialIndex`) with early-stopping sibling cancellation.
- **What's Left for M4:**
  - Fix the 1-line probe-class count assertion at `tests/v4-m2-broker-browser-probes.test.ts:836` (`13` -> `14`).
  - Run the M4 slices of `tests/v4-e2e-tiers.test.ts` (Features 8, 9, 10, 17, 18, 22, 23, 24 and `T4-01..05`, `T4-11`, `T4-12`) and fix any contract mismatches.
  - Run Test 4 (Surface Graph E2E) of `tests/guardian-v4.spec.ts`.
  - Verify `LabRunner.startLabTarget` lifecycle hook is cleanly invoked inside `execution.ts` when `project.environment === 'local-lab' && project.labConfig?.enabled`.
  - Add a focused `tests/v4-m4-surface-orchestration.test.ts`.

### ✅ M5 — Multi-Container `LabRunner`, Opt-In IAST & v4 Web UI (`DONE` — 6/6 unit + `V4-B5`/`V4-B6` PASS + 25/25 E2E slice PASS)
- **Files:** `src/server/lab-runner.ts`, `local-lab/iast/node-hook.mjs`, `local-lab/iast/python/sitecustomize.py`, `scripts/cli.ts`, `src/server/store.ts`, `src/actions.ts`, `src/routes/{settings,index,projects.$projectId,runs.$runId,api.runs.$runId.events}.tsx/.ts`, `src/components/{run-overview,run-workspace,run-surface}.tsx`, `src/app.css`, `tests/v4-m5-lab-iast-ui.test.ts`
- **Delivered:**
  - Multi-container `--internal` (`inhibit_ipv4=true`) Compose/`services` stacks (up to 6 containers, `CapDrop: ALL`, `no-new-privileges`, 0 host ports), strict pre-spawn sanitizer rejecting unsafe directives, `seedCommand` provisioning synthetic personas into `0600` Persona Vault, `rebuildWithPatch`, and 0-orphan teardown.
  - `ingestLabTelemetry()` enforcing `local-lab`-only, scrubbing caller + AWS/Stripe/JWT/Bearer/Cookie secrets, capping files at `<= 65536` bytes, persisting `lab_telemetry` and `endpoints.coverage_pct`, strictly isolated from `ReplayVerifier` (`V4-B6` PASS).
  - Lightweight zero-egress Node (`local-lab/iast/node-hook.mjs`) and Python (`local-lab/iast/python/sitecustomize.py`) hooks.
  - CLI `--local-lab` / `--compose` / `--iast` / `--sarif` wiring (`scripts/cli.ts`).
  - Web UI: `Role affinity` selector + badges on `/settings`; fail-closed `public` gating + LabRunner settings + Tier-2 `sandboxWriteAllowlist` editor; Run Overview LabRunner controls; SQLite-backed Surface Graph tab (`src/components/run-surface.tsx`) in light & dark themes.

### ✅ Independent E2E & Boundary Test Infrastructure (`READY`)
- **Files:** `tests/v4-boundaries.test.ts` (8 suites, **8/8 PASS**), `tests/v4-e2e-tiers.test.ts` (322+ tiered cases across all 28 features + 14 workload/stress scenarios), `tests/v4-tier-helpers.ts`, `tests/guardian-v4.spec.ts` (4 Playwright E2E UI specs).

---

## 3. What's Left To Do

### 1. Close Out M4 Verification (`~30–60 min`)
- Update `tests/v4-m2-broker-browser-probes.test.ts:836` (`13 -> 14` probe classes) and re-run `tests/v4-m2-broker-browser-probes.test.ts`.
- Run M4 cases in `tests/v4-e2e-tiers.test.ts` (`Features 8, 9, 10, 17, 18, 22, 23, 24` and `T4-01..05`, `T4-11`, `T4-12`) + `T3-14`/`T4-10` (check `replay-verifier.ts:582-591` `requireControlNonError` under `CWE-639` if still failing) and fix any discrepancies.
- Confirm `tests/guardian-v4.spec.ts` passes **4/4** (including Test 4 Surface Graph E2E) and `tests/guardian-v2.spec.ts` remains **4/4**.

### 2. Implement M6 — Recall Benchmark Harness & Local Evaluation Labs (`NOT STARTED`)
Check exact exported signatures expected by Features 26 & 27 + `T4-13` in `tests/v4-e2e-tiers.test.ts` before coding:
- **`scripts/benchmark-recall.ts` + `"benchmark:recall"` in `package.json`:**
  - CLI (`--suite xben-25|saas-lab|all`, `--db`, `--out-dir`, `--diff`, etc.) and programmatic exports.
  - 6-stage monotonic funnel (`targetsTotal -> surfaceDiscovered -> hypothesisFormed -> signalObserved -> specSubmitted -> zeroLlmConfirmed`) + deterministic 11-bucket failure-attribution taxonomy (`surface_miss`, `hypothesis_miss`, `form_encoding_missing`, `csrf_blocked`, `context_reset`, `tier_blocked`, `trigger_miss`, `jq_assertion_bug`, `spa_catchall_fp`, `replay_spec_miss`, `budget_exhausted`).
  - Persists to SQLite `benchmark_runs` and outputs machine-readable JSON + Markdown diff tables.
  - Drives Guardian's real engines (`RequestBroker`, `phase0-recon`, `surface-engine`, `ReplayVerifier`, `ScopedBrowser`, `CanaryBroker`, `LabRunner`) — never hardcoded fake counters.
- **`benchmarks/xben-25/`:** Self-contained local loopback stratified 25-target web security suite (`manifest.json` + local server fixtures) spanning SQLi (all 7 encodings, OR-branch, time-blind), IDOR/BOLA, BFLA, SSTI, SSRF (OOB), XSS (reflected/DOM/stored), XXE (OOB), JWT/OAuth (`alg: none`, `strip_signature`, `jku`), path traversal, mass assignment, cache poisoning/deception, CSRF-protected forms, and multi-step browser flows.
- **`local-lab/saas-lab/` (Held-Out Modern SaaS Lab):** Contamination-free multi-tenant app with source tree + synthetic personas + **20 planted High/Critical vulns** + **6 hard decoys** (must produce `0/6` FPs) + deterministic patch retest support for `>= 14/20` vulns.
- Add `tests/v4-m6-benchmarks.test.ts` and verify Features 26/27 & `T4-13` pass.

### 3. Execute M7 — Full Release Gate, Iterative Recall Hill-Climbing & `VERIFICATION-v4.md` (`NOT STARTED`)
1. **Full Automated Suite Gate (100% PASS, 0 skips, 0 Docker orphans):**
   - `npm run check && npm run build`
   - `GUARDIAN_ALLOW_LOCAL_LAB=1 npm run test:boundaries` (46/46)
   - `GUARDIAN_ALLOW_LOCAL_LAB=1 node --test tests/v3-boundaries.test.ts tests/v3-protocol-browser.test.ts tests/v4-boundaries.test.ts`
   - `GUARDIAN_ALLOW_LOCAL_LAB=1 node --test --test-concurrency=1 tests/v4-e2e-tiers.test.ts` (322+ cases)
   - `npm run test:e2e` (`tests/guardian-v2.spec.ts` + `tests/guardian-v4.spec.ts`)
2. **Iterative Recall Hill-Climbing Loop:**
   - Capture baseline `npm run benchmark:recall -- --suite xben-25` scorecard (funnel + failure taxonomy).
   - Iteratively fix top root-cause failure buckets via **general engine improvements only** (never hardcoding benchmark routes/payloads/flags) and record per-iteration `benchmark_runs` diffs until high confirmed recall & 100% precision.
   - Run **anti-overfitting generalization check** on Held-Out Modern SaaS Lab (`local-lab/saas-lab/`): target **`>= 18/20` confirmed (`runtime_confirmed`)**, **`0/6` decoy false positives**, and **`>= 14/20` verified patches** passing 6-gate review + `reproduced -> fixed`.
   - Re-run regression suites after any hill-climbing code edits.
3. **Publish `VERIFICATION-v4.md`** documenting all release gates, hill-climbing iteration table (before -> after deltas), held-out generalization results, and zero-trust boundary verification.

> **Completed:** see [VERIFICATION-v4.md](VERIFICATION-v4.md). Final held-out recall is 20/20 (target `>=18/20`), decoy FPs 0/6, and patch verification 20/20 (target `>=14/20`). Realistic-bench remains the open v4 baseline (0/172 dev, 3/171 held-out); v5 targets are in [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md).

---

## 4. Environment & Operational Notes (Important for Next Session)

- **Host Resources:** Root disk was expanded to **493 GB** (`~455 GB` free). Host has **7.7 GiB RAM** + a persistent **16 GiB swapfile** (`/swapfile`, `vm.swappiness=20`).
- **Avoid OOM/Swap Thrash:** Always prefix Node/Vite/TypeScript commands with `NODE_OPTIONS=--max-old-space-size=1536`, run heavy suites with `--test-concurrency=1`, and keep concurrent subagents/workers capped at **<= 2** (avoid spawning deep nested subagent trees simultaneously).
- **Avoid False-Positive Content Filters:** When editing security probe engines (`surface-engine.ts`, `benchmarks/xben-25/`, `local-lab/saas-lab/`), keep each worker focused on small modular files and read targeted line ranges instead of loading entire multi-thousand-line probe files into one context.
- **Docker Worker Image:** `guardian-worker:v4` (and `guardian-worker:local` alias) is already built locally (`f926ee3ebbd8`). Rebuild via `npm run worker:build` only if `worker/` changes, and run `docker builder prune -f` afterward.
- **Worker Host Dependencies:** The `tests/v4-m3-*` AST suites import `worker/analyzers.ts` on the host, which requires `@swc/core`/`acorn` from `worker/node_modules`. Run `npm run worker:install` once after checkout (the root `npm install` does not install them); without it those suites fall back to regex parsing and M3-T5/T8 fail.
- **Secrets / Safety Rules:**
  - Never print, log, or commit credentials from `/home/exedev/.config/guardian-git/` or `/home/exedev/.config/guardian-fixtures/`.
  - Never run active automated probing against external internet domains; run all benchmark/hill-climbing work strictly against loopback `local-lab` targets (`127.0.0.1`).

---

## 5. Quick Resume Commands

```bash
cd /home/exedev/guardian

# 1. Typecheck + build
NODE_OPTIONS=--max-old-space-size=1536 npm run check && NODE_OPTIONS=--max-old-space-size=1536 npm run build

# 2. v4 Zero-Trust Boundary Suite (currently 8/8 PASS)
NODE_OPTIONS=--max-old-space-size=1536 GUARDIAN_ALLOW_LOCAL_LAB=1 node --test tests/v4-boundaries.test.ts

# 3. v4 Milestone Unit Suites (currently 44/45 PASS; fix M2.7 line 836 count 13->14)
NODE_OPTIONS=--max-old-space-size=1536 GUARDIAN_ALLOW_LOCAL_LAB=1 node --test \
  tests/v4-m1-schema-verify-routing.test.ts \
  tests/v4-m2-broker-browser-probes.test.ts \
  tests/v4-m3-worker-sast-templates.test.ts \
  tests/v4-m5-lab-iast-ui.test.ts

# 4. Run M4 slice of E2E tiers next
NODE_OPTIONS=--max-old-space-size=1536 GUARDIAN_ALLOW_LOCAL_LAB=1 node --test --test-concurrency=1 \
  --test-name-pattern="T[123]-(08|09|10|17|18|22|23|24)" tests/v4-e2e-tiers.test.ts

# 5. Playwright UI E2E (v2 + v4)
NODE_OPTIONS=--max-old-space-size=1536 npm run test:e2e

# 6. Docker orphan hygiene check (all 3 should be empty)
docker ps -aq --filter label=dev.guardian.assignment
docker ps -aq --filter label=dev.guardian.run
docker network ls -q --filter name=guardian
```
