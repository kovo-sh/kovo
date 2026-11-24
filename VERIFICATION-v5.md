# Guardian v5 — Freeze Verification (`VERIFICATION-v5.md`)

**Status:** **v5.0 FREEZE CANDIDATE.** The deterministic engine harness meets G4/G9; the shipped production runtime has **no deterministic floor** in v5.0. The ported engine exists on `agents/engine-port` but was reverted from `main` because it regressed 25 existing Execution/E2E tests. Final release gate: **992/992 PASS** (0 failures, 0 skips, 0 orphans; `/tmp/guardian-reverify-v5.5in05x`).

**Snapshot:** 2026-11-22, `main` @ `d26cd01` (engine-port revert `a73f07e` + workflow-synthesis restore `d26cd01`), docs branch `agents/docs-v5`.
**Plan:** [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md) · [plans/v5.md](plans/v5.md)
**Prior release:** [VERIFICATION-v4.md](VERIFICATION-v4.md)
**Handover:** [HANDOVER-v5.md](HANDOVER-v5.md)
**v5.1 integration:** in progress behind a default-off flag — see [§0](#0-v51-integration-in-progress). The v5.0 scorecards in §2–§3 are unchanged and remain the shipped numbers.
**v7 planning snapshot:** current measured state and the smoke battery — see [§V7](#v7-planning-snapshot-2026-11-23--not-a-release-claim). It is a **planning record**, not a release claim.

> The two scorecards are not interchangeable. Scorecard B is the deterministic engine harness. Scorecard A is the shipped `Execution` runtime. The 25/59 and 28/59 runtime numbers are a **v5.1 candidate**, not v5.0.
>
> Everything in §0–§11 is **historical** (v5.0 freeze + v5.1 integration record). The current line is v7 planning; its numbers live only in §V7 and are labelled with their measurement scope.

---

## v7 planning snapshot (2026-11-23) — not a release claim

> **This section is new and supersedes nothing.** The v5.0 freeze record (§2–§3, §6) and the v5.1 integration record (§0) stay intact and historical. Nothing below is a release gate result, a certification, or a shipped number. It records what the v6 line measured, what it did not, and the battery/protocol v7 will use to turn a measurement into a claim.

**Status:** v7 **M0-interim** (2026-11-24). Recorded: floor + legacy regression + realism wiring milestone (see V7.2). **Not certified for agentic lift** — held-out lift is 0 and 2 unmatched FPs remain. v6 remains the shipped baseline. Floor + realism numbers below supersede V7.1 from the 2026-11-23 snapshot.

### V7.1 Current measured numbers

All product rows are real `Execution` on the 3-app realistic dev cells (acme-saas, shopflow, opsportal), seed 1, grey-box, Tier-3 local-lab, Docker verifier, wordlists off, serial unless noted.

| Measure | Result | Scope / caveat |
| :--- | :--- | :--- |
| Product floor (`Execution --no-llm`) | **36 / 59 (61.0%)**, **100%** precision, 0 decoy/unmatched | acme **14**, shopflow 12, opsportal 10; 3 runs, 0 spread, identical site-set hash |
| Floor determinism | **0 spread**, 3 repeats identical (site sets included, `driftApps=0`) | Re-gated on the current tree |
| Salted held-out product floor (seed 1000042) | **28 / 58 (48.3%)**, **100%** precision | acme **11**, shopflow **10**, opsportal 7; 2 runs, identical per-app; gains from inferred-param discovery and an evidence-based quota reservation, each confirmed through the normal proof path |
| Agentic, 600 s generous, 3 apps dev | **35 / 59 (59.3%)**, **100%** precision, 0 unmatched, **+2 net** | acme 13 (+1), shopflow 12 (+1), opsportal 10 (**+0**); ~$1.0 total |
| Agentic, 600 s generous, 3 apps salted held-out | **25 / 58**, **+1 net**, **100%** precision | acme 10, shopflow 8, opsportal 7; 19–23 investigations/app; pre-hardening run had 2 unmatched FPs |
| Agentic rotation (shopflow, resumed, 300 s) | **3 / 19**, **100%** precision, p50 **77.5 s** | After injection-class precedence fix |
| XBEN-25 | **25 / 25**, 100% precision | Hard regression gate |
| held-out-saas | **20 / 20** + **20 / 20 patches** (`allPatches=fixed`) | Hard regression gate |
| Realism #2 (`wan-oob`, no-llm) | **2 TP / 0 FP**; async **SSRF ✅**, async **XXE ✅**; gate still fails on blind-SQLi, blended async FNR 33.3%, chain 2/3 | Gate denominator split in flight |
| Realism #3 (`staging-concurrency`) | **capability PASS** — write-BOLA, h2 single-packet race (2 ms spread, 4 acks / 1 debit), checkout tampering; 0 leaks; 100% precision | |
| Realism #4 (`monorepo-whitebox`) | wiring PASS; 4-hop confirmations **0 / 3** | capability gap, not wiring |
| `execution.ts` size | ~**11.5K LOC** | Grew with brief slices; Cut 3a target < 8.5K |

**Scope rule carried forward:** product capability is always reported as `Execution --no-llm` (deterministic floor) **and** agentic (increment over that floor), on dev **and** salted held-out. Harness/procedural numbers are secondary evidence, never the product score.

### V7.2 Certification status

**TWO CLAIMS, TWO STATUSES.** "Floor + realism wiring" is recordable now; **"agentic lift" is not certifiable** (dev +2, held-out +0).

| Gate | Target | Measured | Status |
| :--- | :--- | :--- | :--- |
| **Floor** dev | 0 spread, 100% precision | 33/59, 3 identical repeats, 100% | **PASS** |
| **Floor** salted held-out | 100% precision, no regression | **28/58**, 100%, 2 identical runs; invariant-clean | **PASS** |
| Legacy regression | xben 25/25, held-out 20/20 + 20/20 | both hold | **PASS** |
| Realism wiring | #2–#4 wiring pass | #2 PASS, #3 PASS, #4 PASS | **PASS** |
| Realism capability | ≥75% on #1–#4 | #3 PASS (3/3 confirms); #2 2/4 planted; #4 0/3 | **PARTIAL** |
| Worst-run precision (agentic) | 100% on every lift cell | dev 100%; **held-out 2 unmatched FPs** | **FAIL** |
| Agentic lift | ≥ +6–8 pp dev / ≥ +6 pp held-out | dev **+2** over the 33/59 tree (superseded by the 34/59 tree, remeasuring); held-out **+1 (+1.7 pp)** | **FAIL (bar held red)** |
| Dispatch coverage | ready steps are not stranded | fixed: opsportal 6→**19–25** distinct steps, acme 7→**14**; stranded only at wall-clock; invariant live in worker-gate | **PASS** |
| Proof submission | route-hit targets produce a spec or an explicit proof gap | was **19 of 23** no-spec; after the 18-turn/120 s raise + settlement gate: **5/10 (50%)** spec-on-route in the measured cell | **IMPROVING (P0)** |
| Confirmation integrity | no confirmed finding may carry a non-confirming diff | store-level `InvariantError` now enforces it; 0 violations on dev+held-out floor re-runs | **PASS (forward)** |
| Chains | ≥ 4/6 | #2 chain 2/3; not re-measured elsewhere | **PARTIAL** |

**M0-interim milestone (recorded 2026-11-24, pre-Cut3):** the floor (33/59 dev, 24/58 held-out, 0-spread, 100% precision), legacy regression gates, realism wiring, Realism #3 capability, and Realism #2 async SSRF+XXE are citable **with the explicit provenance "pre-Cut3: floor still confirms via declarative specs in `replay-verifier.ts`; receipts are shadow/convert for the agent path."** Cut 3a retires six of those spec families; the milestone must be re-gated after it lands.

Two claims that must not be made: (a) "agentic lift is proven" — held-out is exactly the floor, and the dev +2 sits inside a dispatch defect that left 13 of 14 planned acme steps and 6 of 7 opsportal steps undispatched; (b) "realism is done" — #4 has 0 confirmations and #2 misses blind SQLi plus one chain leg.

### V7.3 Smoke battery (adopted design)

The fast battery answers one question: **did this change break the funnel, the precision boundary, or the floor?** It does not attempt to certify. Decoupled deliberately from "a smaller 45-minute scan".

| Tier | Budget | Contents | Catches |
| :--- | :--- | :--- | :--- |
| **Tier 0** | < 90 s, $0 | `scripts/worker-gate.sh` (typecheck + fast contract invariants + targeted slice) and deterministic replay of past FP/over-claim archetypes through verifier → dedupe → scheduler | Type/contract breakage and regressions in previously-fixed over-claims, with no LLM and no Docker-heavy run |
| **Tier 1** | ~6 min, ~$1, 4 parallel cells | Paired lift from post-floor snapshots (acme); one rotating second app (shopflow or opsportal); the **pre-exhausted precision trap**; one realism conversion micro-slice (async OOB / staging race / 4-hop) | Floor preservation, net-new lift shape, precision boundary, one live realism path |
| **Tier 2** | 30–45 min | Cold 3-app dev n=3, salted held-out n=2, one 45-min endurance cell, realism suite, xben + held-out-saas | Cold Phase-A→B integration and multi-hour DB drift — the two known Tier-0/1 blind spots |

**The precision trap.** A pre-exhausted cell whose correct answer is *zero* findings (all budget spent before the target is reachable). It must confirm **0**. Any confirmation from the trap is a precision failure regardless of recall. This is the cheapest guard against the reward-hacking and cross-talk failure modes already seen (control-denial pairing, `before != after` cross-worker reads, SDK helper bypass of host transcripts).

**Tier-1 pass gates (all must hold):**

1. **100% precision** on every lift cell, and **0** on the trap.
2. **Paired net-new non-regression** versus the post-floor snapshot: no lost confirmed targets (a −1 is allowed only with a conversion gain and a clean rerun).
3. **Conversion drop ≤ 10 pp** on the realism micro-slice.
4. **0 crashes / 0 worker failures / 0 orphan containers or networks.**
5. **Throughput floor:** p50 assignment ≤ 75 s and ≥ 12 completions per 300 s of Phase B.
6. **Cost ceiling:** ≤ $0.80 per cell.

**Anti-gaming rules:** rotate the second app every batch; fix general invariants, never trap-specific names or fixtures; a green smoke is *not* evidence of capability — only of non-regression.

**Calibration (accepted, ~$22–24, deferred until M0 lands):** 8 deliberately-varied builds measured against a full reference run. Trust the battery only if Spearman ≥ 0.75 against the reference, 100% directional agreement for Δ ≥ 2 targets, and the trap catches every variant below 95% precision. Until that study is run, Tier 1 is a **regression tripwire**, not a predictive estimate.

**Rejected techniques:** bootstrap confidence intervals on 22-target cells (4/10 — too noisy to gate on); frozen LLM-turn VCR replay (plumbing-only; never a recall signal).

### V7.4 Known regressions fixed this cycle

| Regression | Fix | Result |
| :--- | :--- | :--- |
| XBEN-25 fell to **24/25** after the verifier required pre/post readback (`xben-12` became `replay_spec_miss`) | Spec-side readback for `synthAuthz`; no gate weakening | **25/25** restored |
| held-out-saas BFLA lost during floor hardening | Role-exclusive function-surface delta counts as vertical impact (restored held-out BFLA) | **20/20** + **20/20 patches** |
| Floor fell **26/59** after hardening took it off its pre-hardening level (shopflow 7, opsportal 8) | All-occurrence XSS canary scan picking the strongest executable context (opsportal reflected XSS +1) | **31/59 (52.5%)** at 100% |
| Floor repeat spread **29 / 30 / 33** | Canonical endpoint/probe/ID/persona ordering, state-clobber isolation, request-first termination with wall margin | **0 spread**, 3 identical repeats and site sets (26/59 tree), idle *and* loaded |
| 3 unmatched FPs in the K=6 cell: a planted mass-assignment target labelled BOLA; two fixture XSS escape defects | Evidence-first impact classification (CWE-915) and fixture escaping | **100%** precision on K=6 |
| Stored 2FA over-claim and `/api/admin/activity` false charge | Universal default-deny boundary + real MFA gate; `misclassifiedFindingIds` grader bucket (neither TP nor FP) | Over-claim dismissed; acme samples 100% precision |
| **Open:** 45-min "invoice amount accepts negative values" claim | Triage in flight (genuine invariant bug vs echo/clamp) | **Unresolved** — reason the 45-min worst-run precision is not 100% |

### V7.5 Honest limitations

1. **The agentic increment is currently ~0.** Dev +2 and held-out +0, with the dev +2 produced while 13 of 14 planned acme steps and 6 of 7 opsportal steps were never dispatched. Treat every prior "+2 net" as unproven until the dispatch funnel is fixed and re-measured.
2. **Longer horizon trades precision for recall.** 15/22 at 88.2% is not better than 13/22 at 100% until the unmatched claims are triaged. Worst-run precision at the horizon is the gate, not budget.
3. **Budgets are not the constraint.** The binding limits are dispatch coverage, hypothesis/proof quality, and (on randomized held-out surfaces) structural assumptions in the deterministic layer. 45 min produced 0 marginal recall over 10 min.
4. **Realism capability is partial, not complete.** #3 passes end-to-end. #2 confirms async SSRF and XXE (2 TP / 0 FP) but misses blind SQLi and one chain leg; the 33.3% "async FNR" blended an unrelated capability miss into the OOB denominator and is being split into `oob_wiring_fnr` and `fixture_capability_recall`. #4 has 0 of 3 4-hop confirmations despite 600 B slices attached.
5. **The deterministic floor is re-gated and green** (33/59 dev, 0 spread, 24/58 held-out, 100% precision).
6. **Held-out surfaces lag dev by 14.5 pp** on the floor (55.9% vs 41.4%). That is residual Layer-2 structure on randomized routes; it must be closed by Layer 3 (agents + white-box), not by more deterministic regexes.
7. **Chains, white-box conversion, and reason-bench remain M1/M2 gates.** #2's chain is at 2/3; #4's 4-hop conversion is at 0/3.
8. **The smoke battery is not yet calibrated.** Tier 1 is a tripwire until the 8-variant study lands; Tier 2 blind spots (cold integration, DB drift) are real.
9. **DSL retirement is partially started.** Cut 1–2 landed (agent path on ProofReceipt; floor receipts in shadow) and six typed floor recipes exist, but the production caller is not wired, so `execution.ts` is ~11.5K LOC and `replay-verifier.ts` still confirms the floor. Cut 3a is in flight with a no-fallback assertion.

### V7.6 Reporting rule

- §2–§3 and §6 are the **v5.0 freeze record**. §0 is the **v5.1 integration record**. Both are historical; do not update their numbers to match the current line.
- Nothing in §V7 is a release claim. A v7 number becomes citable only when it is produced by the protocol in [plans/v7.md](plans/v7.md#certification-protocol-adopted) and the M0 gates are green.
- Never cite a harness/procedural number as the product score; never cite a wiring pass as a capability result; never cite a per-app lift as an aggregate.

---

## 0. v5.1 integration (in progress)

> This section is **new in v5.1**. It does not revise the v5.0 freeze record. v5.0 is frozen at the scorecards in §2–§3 (deterministic dev **115/172**, held-out **111/171**, runtime agentic **7/59**, `--no-llm` **0/59**). Nothing below changes those numbers until the integration flag is flipped on `main` and the pre-flip gates in §0.3 pass.

### 0.1 Status

- **v5.0 is frozen.** Release gate **992/992 PASS**, 0 failures, 0 skips, 0 orphans; deterministic floors and Scorecards A/B stand as recorded in §2–§3.
- **The engine-port was reverted** from `main` (`a73f07e`). It delivered 25/59 `--no-llm` and 28/59 agentic at 100% precision, but regressed **25 existing Execution/E2E tests**: planner budgets, specialist tools, multi-trial, and M1 fallback. It remains preserved on `agents/engine-port` for reference only.
- **Integration restarted in five slices** rather than re-merging the branch. The integration lands behind a **default-off** flag so `main` stays at v5.0 behavior until parity is proven. Slices **1–2 are in progress**; slices 3–5 are gated on their results.

### 0.2 The five slices

| # | Slice | Scope | Status |
| :--- | :--- | :--- | :--- |
| 1 | Standalone engine modules + structural dedupe | Extract the engine out of the request path into testable modules; structural dedupe key `(origin, endpoint, method, param/resolver, cwe)` so distinct same-class endpoints are not collapsed | **IN PROGRESS** |
| 2 | Deterministic-only path | Explicit `deterministicOnly` path outside the M1 fallback; persist verified findings only; emit `det_lead` facts for unconfirmed leads | **IN PROGRESS** |
| 3 | Non-blocking agentic lane | Concurrent lane behind a **default-off** flag; seeded-step guard, 30% / 180 s cap, K=6 and per-lane budget isolation, **no step cancellation** | **NOT STARTED** (gated on 1–2) |
| 4 | Verifier proof strength | Replace the specialist deterministic-pair scope guard with `ReplayVerifier` proof-strength + endpoint binding | **NOT STARTED** |
| 5 | Flip default + parity | Port remaining parity gaps, run the pre-flip gate, then flip the default on `main` | **NOT STARTED** |

### 0.3 Pre-flip gates

All of these must pass **with the integration flag forced ON** before slice 5 flips the default:

1. **Full suite green** with the flag ON — 0 failures, 0 skips, 0 orphans (`docs/reverify-v5.sh --full`).
2. **Budget invariants:** `dynamicStepBudget` / **K=6** / M1 fallback behavior unchanged; per-lane budget isolation holds.
3. **Deterministic floor:** `Execution --no-llm` **≥ 25/59 at 100% precision** on the 3-app grey-box dev cells.
4. **Agentic is strictly additive:** **≥ 95% precision** and **≤ 10 pp held-out gap**, with no loss of already-confirmed findings versus the flag-off control.
5. **Legacy floors hold:** XBEN **25/25**, held-out-saas **20/20** + **20/20 patches**, deterministic dev **115/172**, deterministic held-out **111/171**, and **0 orphans**.

A slice result that misses a gate is recorded as a failed candidate, not a shipped number. v5.1 figures are **not shipped until the flag flips**.

### 0.4 Chain-safety rules

The integration must preserve chained and white-box findings. These rules are release-blocking:

- **No step cancellation.** The deterministic pass never cancels a specialist step, and never hides a confirmed route from the agentic lane — either would break multi-step chains.
- **Read-only “Already Confirmed” context.** Specialists receive confirmed findings as read-only context for chaining, not as a signal to skip work.
- **Preserve white-box findings.** `static_verified` findings survive the integration; the deterministic lane must not overwrite or suppress them.
- **Persist unconfirmed leads.** Unconfirmed deterministic candidates are stored as `det_lead` facts rather than silently dropped, so later steps can promote them.
- **Per-endpoint structural dedupe.** Dedupe on `(origin, endpoint, method, param/resolver, cwe)`; origin+CWE-only dedupe is rejected because it discards distinct endpoints.

### 0.5 Reporting rule

Scorecards in §2 (runtime) and §3 (deterministic harness) are **v5.0 history and stay unchanged**. The 25/59 and 28/59 candidate results and any slice measurements are **reference only**; they are not v5.1 shipped numbers until the flag is on by default and §0.3 is green.

### 0.6 Security hardening (v5.1, merged)

An independent audit produced 2 high, 3 medium and 6 medium/low findings against Guardian itself. All were fixed on `main` with regression tests; nothing here changes the v5.0 scorecards, and the deterministic capability harness was re-measured after the merge (**39/56, 100% precision, 0 decoys/unmatched** on seed 42).

| # | Severity | Finding | Fix | Evidence |
| :--- | :--- | :--- | :--- | :--- |
| 1 | High | One automatic approval authorized every later state change on the origin (path-prefix match; query/persona/body/flags ignored; 15-minute reuse) | Exact single-use approval ledger bound to run, origin, method, exact path+query, persona, body/parts hash, multipart/race/rce flags and scope revision (60 s TTL, consumed on first use). Persisted DB rows are audit-only. Broker passes real context; operator patterns are segment-aware only (`/api/*` matches `/api/x`, not `/apix`) | `tests/v5-security-approvals.test.ts` 11/11 |
| 2 | High | `--repo` copied symlinks; recon read through them and patches could write outside the repo | Link-free copy with `lstat` filtering, `O_NOFOLLOW` manifest reads, link-free patch work tree, `safeResolveUnderRoot` realpaths the deepest existing parent and rejects symlinked components | `tests/v5-security-repo.test.ts` 10/10 |
| 3 | Medium | Any local process received the owner session cookie on a plain HTML GET | Bootstrap-only issuance: printed one-time `?bootstrap=` URL plus owner-only `<data>/bootstrap` (0600); secret consumed on use; `HttpOnly; SameSite=Strict`; unauthenticated requests get `401` and never reach the app handler | `tests/v5-security-authbrowser.test.ts` 12/12 |
| 4 | Medium | Clerk/provider host taken from target HTML with a last-two-labels fallback (`co.uk` bug) and no allowlist check | PSL-aware registrable-domain check, provider discovery ignores redirects, publishable-key hosts must be in the allowlisted registrable domain | same suite |
| 5 | Medium | Credential POSTs followed redirects, replaying passwords to arbitrary/internal hosts outside the broker's IP checks | `redirect: 'manual'` everywhere; 3xx on credential/CSRF flows fails closed; `assertCredentialTarget` enforces scheme, allowlist and public-IP DNS classification | same suite |
| 6 | Medium | Scoped browser intercepted only HTTP; WebSocket/WebRTC egress reached loopback/LAN/metadata | `routeWebSocket` scope guard, non-proxied UDP disabled, `RTCPeerConnection` removed, host-resolver rules pin DNS | same suite |
| 7 | Medium | Form-login browser allowed self-resolved DNS (rebinding) and cross-origin subresources to any host | Cross-origin subresources limited to target/allowlisted eTLD+1; every request re-checks DNS before `route.continue()`; documents limited to exact allowed origins | same suite |
| 8 | Medium | Chromium ran with `--no-sandbox` while rendering target pages | Sandbox on by default; `--no-sandbox` only behind `GUARDIAN_INSECURE_NO_SANDBOX=1` with a warning | same suite |
| 9 | Medium | IAST telemetry directory was `0777` and mounted read-write into a root-capable container | `0700` directory, explicit non-root `--user` (root rejected), read-only `/app` | `tests/v5-security-repo.test.ts` |
| 10 | Medium | Approval fast paths were spoofable (`"query"` substring, hand-written multipart, 4 KiB scan, agent-controlled rationale) | Exact JSON `query` envelope, multipart derived from `Content-Type`/boundary, full-body scan capped at 64 KiB, rationale removed from the judge prompt | `tests/v5-security-approvals.test.ts` |
| 11 | Medium | Worker output read without line limits; LLM-written scripts shared the bridge uid | `BoundedLineDecoder` (64 KiB/line, 4 MiB/session) terminates the session on overrun | `tests/v5-security-repo.test.ts` |

**Intentional behavior changes**

- Public-target `rce_proof` / `upload_probe` / `sql_time_diff` replay gates now fail closed unless the request is local-lab auto-approved or operator-pattern authorized; they no longer ride the context-free fast path.
- Headless UI is opened through the bootstrap URL; `tests/app.ts` exposes `app.open(page)` and the README documents the handshake.
- Lab containers default to the invoking uid:gid (non-root) and reject `GUARDIAN_LAB_USER=0:*`.

**Gate wiring:** the three security suites run in the fast release gate (`docs/reverify-v5.sh`) and in the `v5-*` group of the full gate.

---

## 1. Two surfaces, two scorecards

| Surface | What it measures | v5.0 result | Role |
| :--- | :--- | :--- | :--- |
| **A — Production runtime (`Execution`)** | Real orchestrator, Docker verifier, Tier-3 local-lab | agentic **7/59 (11.9%)**; `--no-llm` **0/59** | Primary product surface; no deterministic floor in v5.0 |
| **B — Deterministic engine harness (procedural)** | `scripts/benchmark-*` hypothesis → probe → spec → `ReplayVerifier` | dev **115/172 (66.9%)**; held-out **111/171 (64.9%)** | Capability engine + hill-climb harness; G4 met here |
| **v5.1 candidate (not shipped)** | Ported deterministic engine inside `Execution` on `agents/engine-port` | `--no-llm` 25/59; agentic 28/59 | Deferred: regressed 25 existing Execution/E2E tests |

The shipped runtime and the procedural harness are ~55 pp apart in v5.0. The candidate port narrows that to ~19 pp but is not in `main`.

---

## 2. Scorecard A — Production Runtime (`Execution`), actual v5.0

Scope: 3 apps, grey-box, dev seed 1, $2/600 s per cell, Tier-3 local-lab, Docker verifier, concurrency 3.

| Mode | Confirmed | Recall | Precision | Decoy / unmatched | Worker failures | Cost | Wall |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `--no-llm` | **0 / 59** | **0%** | 0 confirmed; 2 unmatched FPs | 0 / 2 | 0 | $0.00 | 81.5 s total |
| agentic (post race-fix) | **7 / 59** | **11.9%** | **100%** (7/7) | 0 / 0 | 0 | $0.4844 total; $0.069/finding | 1,800 s total |

Per-cell agentic:

| App | Confirmed | Wall | Notes |
| :--- | ---: | ---: | :--- |
| acme-saas | 2 / 22 | 600.1 s | hit wall |
| opsportal | 4 / 18 | 600.1 s | hit wall |
| shopflow | 1 / 19 | 600.1 s | hit wall |
| **Total** | **7 / 59** | 1,800 s | 7 assignments completed, 0 failed |

Agentic funnel: 59 → **25 surface** → 13 hypothesis → 13 signal → 7 spec → **7 confirmed**. Buckets: `budget_exhausted` 34, `hypothesis_miss` 16, `replay_spec_miss` 1, `form_encoding_missing` 1.

`--no-llm` funnel: 59 → 21 surface → 10 hypothesis → 2 signal → 1 spec → **0 confirmed**. Buckets: `surface_miss` 38, `hypothesis_miss` 12, `replay_spec_miss` 6, `trigger_miss` 2, `form_encoding_missing` 1.

**v5.1 candidate (branch `agents/engine-port`, NOT shipped):** `--no-llm` 25/59 (42.4%), agentic 28/59 (47.5%), 100% precision, 0 decoy/unmatched, 0 worker failures, $0.140 total / $0.005 per finding. Two of three cells hit 600 s after the deterministic pass; opsportal exited at 137 s. This candidate is preserved on the branch and deferred because it regressed 25 existing tests (planner budgets, specialist tools, multi-trial, fallback); it must not be cited as v5.0.

---

## 3. Scorecard B — Deterministic Engine Harness (procedural)

Final completed matrix on the freeze tree. Values below are the freeze floors.

| Suite | Confirmed | Recall | Precision | Decoy / unmatched | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: |
| realistic dev | **115 / 172** | **66.9%** | **100%** | 0 / 0 | 1 / 6 |
| salted held-out | **111 / 171** | **64.9%** | **100%** | 0 / 0 | 1 / 6 |
| XBEN-25 | **25 / 25** | 100% | 100% | 0 / 0 | — |
| held-out-saas | **20 / 20** | 100% | 100% | 0/6 decoys | — |
| held-out-saas patches | **20 / 20 fixed** | — | — | `allPatches=fixed` | — |

- Dev → held-out gap: **−2.0 pp** (64.9% vs 66.9%), within 10 pp.
- **G4 MET** on this surface: all-severity 66.9%; H/C **83/117 = 70.9%**.
- **G8 still open:** chains **1/6 dev, 1/6 held-out**.

Dev funnel: 172 → 162 surface → 162 hypothesis → 131 signal → 117 spec → **115 confirmed**. Buckets: `replay_spec_miss` 41, `budget_exhausted` 10, `form_encoding_missing` 3, `csrf_blocked` 3.

Held-out funnel: 171 → 162 surface → 162 hypothesis → 132 signal → 112 spec → **111 confirmed**. Buckets: `replay_spec_miss` 46, `budget_exhausted` 7, `form_encoding_missing` 2, `csrf_blocked` 3, `surface_miss` 2.

Class highlights (dev / held-out): BOLA 17/19 / 17/18; SQLi 4/7 / 3/10; stored XSS 6/6 / 4/6; path traversal 6/6 / 9/9; XXE 7/7 / 5/5; SSRF 11/12 / 11/12; CSRF 7/7 / 4/5; command injection 5/5 / 5/5; info disclosure 7/9 / 11/13; mass assignment 6/11 / 5/9; JWT 1/6 / 2/4; business logic 5/12 / 5/11; workflow 5/10 / 3/5.

---

## 4. Convergence gap: B → A

**v5.0 framing: the product has no deterministic floor.** Real `Execution` is 7/59 agentic and 0/59 `--no-llm`; the procedural harness is 115/172. The ported engine that closed this loop was reverted because it broke 25 existing tests.

| Cause | Evidence | Impact | v5.1 action |
| :--- | :--- | :--- | :--- |
| Engine-port was reverted | `a73f07e`; 25 existing Execution/E2E tests regressed (planner budgets, specialist tools, multi-trial, fallback) | Shipped runtime has no deterministic closed loop | Rebuild the port without regressing planner/tool/trial behavior |
| Latest JWT/mass converters not ported into `src/server/deterministic-engine.ts` | Candidate still used an older converter set | Missing runtime class coverage | Port remaining converters |
| `Execution` surface ingestion is incomplete | v5.0 agentic surface 25 endpoints / 59 targets; candidate 45 / 59 | Targets never reach the runtime loop | Full surface ingestion + evidence-derived discovery |
| 600 s wall consumed by deterministic pass (candidate) | Candidate: 2/3 cells at 600 s, opsportal 137 s | Specialists get little wall clock | Reallocate deterministic vs specialist budgets; document early stop |
| Specialist deterministic-pair scope guard (candidate) | Only engine-triaged `(endpoint, class family)` pairs accepted | Fail-safe precision, but blinds novel logic/workflow/chain/white-box recall | Replace with ReplayVerifier proof-strength + endpoint binding |

**Gap size:** v5.0 **66.9% − 11.9% = 55.0 pp**. The v5.1 candidate narrows it to **19.4 pp** (66.9% − 47.5%), but is not shipped.

### 4.1 v5.1 candidate guardrail (not in v5.0)

The candidate carries a specialist deterministic-pair scope guard: local-lab LLM specs are accepted only when the normalized `(endpoint, class family)` pair was triaged by the deterministic engine, or the family is already confirmed. It is fail-safe and precision-preserving, but deliberately blinds novel logic, workflow, chain, and white-box recall. It is scheduled for replacement in v5.1 by `ReplayVerifier` proof-strength and endpoint-binding guards. This guard is on `agents/engine-port`, not in the v5.0 runtime.

---

## 5. Tier-3 safety and containment (shipped)

Five invariants, covered by `tests/v5-tier3-safety.test.ts` (**8/8**) and together with `tests/approval-judge.test.ts` (**15/15**):

| # | Invariant | Enforcement |
| :--- | :--- | :--- |
| 1 | Environment isolation | Tier-3 auto-approval only for `environment === 'local-lab'`; public/unspecified always escalates; `GUARDIAN_ALLOW_LOCAL_LAB=1` alone never relaxes public rules |
| 2 | Origin binding | Only loopback, RFC1918 lab/container subnets, and single-label Docker/LabRunner aliases auto-approve; external/mislabeled origins fall back to public hard escalation |
| 3 | Strict precedence | Explicit `strict` always escalates before any auto-approval |
| 4 | Broker guards survive | Destructive/webshell denylists, metadata/link-local SSRF denial (`169.254/16`, `fe80::/10`), RPS caps remain fail-closed |
| 5 | Audit attribution | Auto-approvals attributed `auto-review:local-lab` and persisted before the state change leaves the broker |

**Containment fix** (`343bf16`, confirmation `0fd6127`): auto-approved local-lab writes no longer follow redirects to external hosts. Redirect hops are checked against lab containment, not just `canRead`; external hops are denied and audited, while relative/same-loopback/container-alias redirects still work. The project schema default `environment` is **public** and fails closed; a loopback seed does not become local-lab implicitly.

---

## 6. Release gates

**Release gate status: PASS — 992/992, 0 failed, 0 skipped, 0 orphans.** Freeze run: `/tmp/guardian-reverify-v5.5in05x`. This includes 234 v5 tests (full glob), 322 tiered E2E, 198 v4 M1–M7, 46+32 boundaries, 142 realistic-harness, 9 Playwright, and orphan hygiene.

| # | Gate | Target | Current evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| G1 | XBEN-25 | ≥ 23/25 | **25/25**, 0 FP | **MET** |
| G2 | Held-out SaaS | ≥ 18/20 | **20/20**, 6/6 decoys clean | **MET** |
| G3 | Held-out patches | ≥ 14/20 | **20/20 fixed**; `allPatches=fixed` | **MET, with caveat** |
| G4 | Realistic H/C recall — grey-box | ≥ 65% | deterministic H/C **70.9%**; all-severity **66.9%** | **MET** (deterministic surface) |
| G5 | Realistic H/C recall — white-box | ≥ 80% | not measured | **NOT MEASURED** |
| G6 | Precision | ≥ 95% | deterministic **100%** (115/115, 111/111); agentic **100%** (7/7); `--no-llm` 0 confirmed + 2 unmatched FPs | **PARTIAL** |
| G7 | Decoy FP | ≤ 5% | 0/62 dev, 0/63 held-out; runtime 0/19 | **MET** |
| G8 | Chain completion | ≥ 50% | **1/6 dev, 1/6 held-out** | **NOT MET** |
| G9 | Held-out within 10 pp | ≤ 10 pp absolute | **−2.0 pp** all-severity; H/C −3.2 pp | **MET** |
| G10 | Full release gate | 100% pass, 0 skips | **992/992 PASS**, 0 skips, 0 orphans | **MET** |
| G11 | Orphan containers/networks | 0 / 0 | direct check **0** stale `Created`, **0** networks | **PASS** (gate pending) |

**Scorecard:** 6 met, 1 met-with-caveat, 1 partial (G6), 1 not met (G8), 1 not measured (G5), 1 pending (G10). **G4 is met on the deterministic surface, not on production `Execution`.**

---

## 7. Milestones

| # | Status | Notes |
| :--- | :--- | :--- |
| M0 | **DONE** | E2E realistic harness, per-cell isolation, inert-run preflight |
| M1 | **DONE** | Wiring, canaries, dedupe, routing, guard/sanitizer, CVE semver, recon halt fix |
| M2 | **DONE** | State graph, recon, auth/session, coverage, ID harvest, BOLA queue |
| M3 | **DONE** | Probes/verifiers, SSRF/XXE realism, probes3/contracts |
| M4 | **DONE** | Templates/AST/bridge/Gate 6; 1,724 templates, 492 modern CVE-named (493 unique IDs) |
| M5 | **DONE** | Board UI, board tools, deterministic posters, warm specialists/handoffs |
| M6 | **PARTIAL** | Deterministic matrix measured; runtime has no floor; final gate, white-box/salted Execution matrices, chains, engine-port rebuild remain |

Commits: Tier-3 safety `76a4903`, containment `343bf16`, engine-port candidate `abcbd29` (branch), revert `a73f07e`, workflow restore `d26cd01`.

---

## 8. Before / after

| Metric | Pre-freeze v5 | Freeze v5.0 | Delta |
| :--- | ---: | ---: | ---: |
| Deterministic dev | 86/172 (50.0%) | **115/172 (66.9%)** | **+16.9 pp** |
| Deterministic held-out | 87/171 (50.9%) | **111/171 (64.9%)** | **+14.0 pp** |
| Deterministic H/C dev | 54.7% | **70.9%** | +16.2 pp |
| Deterministic chains | 0/6 | **1/6** | +1 |
| XBEN | 25/25 | **25/25** | 0 |
| Held-out SaaS / patches | 20/20 / 20/20 | **20/20 / 20/20** | 0 |
| Runtime `--no-llm` | 0/59 | **0/59** | 0 (engine-port reverted) |
| Runtime agentic | 12/117 stale | **7/59 (11.9%)** | new scope |
| Runtime precision | 66.7% stale | **100%** (7/7) | +33.3 pp |
| Runtime worker failures | 39.3% stale | **0** | fixed |

The 25/59 and 28/59 numbers are **not** in this table because they are not shipped. They are the v5.1 candidate.

---

## 9. Known limitations / v5.1 priorities

### 9.1 v5.0 limitations (frozen record)

1. **No deterministic floor in shipped `Execution`.** The port exists on `agents/engine-port`; rebuild it without the 25 regressions.
2. **Port regressions to fix:** planner budgets, specialist tools, multi-trial, fallback.
3. **Surface ingestion:** v5.0 runtime sees 25/59; full ingestion is required.
4. **Specialist scope guard:** candidate-only; blinds novel logic/workflow/chain/white-box recall; replace with proof-strength + endpoint binding.
5. **Wall-clock:** candidate behavior (2/3 at 600 s, opsportal 137 s) needs budget allocation.
6. **White-box and salted Execution matrices** are v5.1.
7. **Chains remain 1/6 (16.7%)**, below 50%.
8. Release gate is **PASS (992/992)** on the freeze tree.
9. **Patch evidence** includes 2 inconclusive-after retests and a replay-based all-patches pass.
10. **No external targets, secrets, or salts.**

### 9.2 v5.1 integration limitations (current, in progress)

1. **Flag is default-off.** `main` still behaves as v5.0; the deterministic floor only exists on integration branches until slice 5.
2. **Slices 1–2 are in progress.** Modules/dedupe and the `deterministicOnly` path are not yet merged; slices 3–5 have not started.
3. **No v5.1 numbers are shipped.** Candidate 25/59 / 28/59 remain reference results; slice measurements are not release claims.
4. **Scope guard is still in the candidate.** Until slice 4 lands, deterministic-pair scoping can blind novel logic, workflow, chain, and white-box recall.
5. **Chain safety is unverified end-to-end.** The no-cancellation, read-only confirmed context, `static_verified` preservation, and `det_lead` rules must be proven by the flag-ON suite.
6. **Wall-clock split is unresolved.** Slice 3's 30% / 180 s lane cap and K=6 isolation are design targets, not measured behavior.
7. **Held-out parity is unmeasured for the integration.** The ≤ 10 pp gap gate is a pre-flip requirement, not a result.
8. **Release gate still applies to v5.0.** Any integration run that is not flag-ON and 0-skip is not a release gate.

---

## 10. Reproduction

### 10.1 Shipped runtime (Scorecard A)

```bash
# Agentic, 3 apps, seed 1, Tier-3 local-lab, $2 / 600 s cells.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 \
         GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \
         NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v5-runtime-agentic
'

# No-LLM baseline (0/59 expected on v5.0 main).
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box --no-llm \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v5-runtime-no-llm
'
```

### 10.2 Deterministic harness (Scorecard B)

Entrypoint map — the two files are *not* interchangeable:

- `scripts/benchmark-realistic.ts` = **product runtime** harness (drives real `Execution`; Scorecard A).
- `benchmarks/realistic-bench/benchmark-realistic.ts` = **deterministic capability** harness
  (procedural probes/spec synthesis; Scorecard B). `scripts/benchmark-realistic-matrix.ts`
  parallelizes this one across app × seed cells.

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 node scripts/benchmark-realistic-matrix.ts \
  --apps acme-saas,shopflow,opsportal --seeds 1,2,42 --split dev \
  --mode grey-box --concurrency 9 --out-dir /tmp/v5-dev

# Salt lives at ~/.config/guardian-bench/heldout.salt (mode 600); never echo it.
export GUARDIAN_ALLOW_LOCAL_LAB=1
export GUARDIAN_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"
node scripts/benchmark-realistic-matrix.ts \
  --apps acme-saas,shopflow,opsportal --seeds 1000001,1000002,1000042 --split heldout \
  --mode grey-box --concurrency 9 --out-dir /tmp/v5-held
unset GUARDIAN_RB_HELDOUT_SALT
```

### 10.3 v5.1 candidate (branch only, historical)

```bash
git switch agents/engine-port
# Same Scorecard A commands; the candidate reports 25/59 no-LLM and 28/59 agentic.
# Do not merge: this branch regressed 25 Execution/E2E tests. Integration now proceeds
# in slices behind a default-off flag — see §10.5.
```

### 10.4 Freeze gate, Tier-3 safety, OOB, secrets

```bash
newgrp docker -c 'bash docs/reverify-v5.sh --full'          # v5.0 release gate: 992/992 PASS

GUARDIAN_ALLOW_LOCAL_LAB=1 \
  node --test tests/v5-tier3-safety.test.ts tests/approval-judge.test.ts   # 15/15
```

OOB callbacks bind one **loopback** canary listener; the harness passes that exact port to the app allowlist. Pin with loopback-only `GUARDIAN_CANARY_PORT` / `GUARDIAN_CANARY_DNS_PORT`; never bind off-loopback. `secretMatches` is `{kind, sha256Prefix, fieldPath?, count}` only; correlate against a locally held secret, never log the raw value.

### 10.5 v5.1 integration loop and pre-flip gate

```bash
# Between tweaks: smoke tier (realistic seed 42 + agentic --smoke + typecheck, parallel).
newgrp docker -c 'bash scripts/hillclimb-loop.sh'

# Once per batch: validation tier (3 dev seeds + 600 s agentic matrix).
newgrp docker -c 'bash scripts/hillclimb-loop.sh --full'

# Pre-flip release gate. Slice 3 introduces the opt-in flag; force it ON for the
# whole run so the flag-ON suite, 0-skip, and orphan checks are meaningful.
# The flag is default-off; its name is pinned by slice 3 (do not guess it here).
newgrp docker -c 'bash docs/reverify-v5.sh --full'

# Deterministic floor on the flag-ON tree: expect >= 25/59 at 100% precision.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box --no-llm \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v51-no-llm
'

# Agentic parity: control (flag off) vs variant (same cells, flag on).
# Pass condition: >= 95% precision, <= 10 pp held-out gap, no confirmed findings lost.
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 \
         GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \
         NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 2 --max-duration-ms 600000 \
    --out-dir /tmp/v51-parity-control
'
# Repeat the same command with the slice-3 flag exported and --out-dir /tmp/v51-parity-variant.
```

Until the flag flips, a v5.1 run is a **candidate measurement**, not a release result. Keep v5.0 scorecards in §2–§3 as the shipped numbers.

---

## 11. Provenance and remaining discrepancies

| Claim | Source | Status |
| :--- | :--- | :--- |
| Runtime agentic 7/59, $0.4844 | `/tmp/m6-postrace/matrix.json` | re-derived |
| Runtime no-LLM 0/59, 2 unmatched | `/tmp/engine-port-baseline/matrix.json` | re-derived |
| v5.1 candidate 25/59, 28/59, $0.140 | `/tmp/engine-port-final-no-llm`, `/tmp/tier3-agentic` | re-derived, **not shipped** |
| Deterministic dev 115/172, held-out 111/171 | `/tmp/v5-final2/dev`, `/tmp/v5-final2/held` | re-derived, final rerun |
| XBEN 25/25, held-out 20/20 + patches | `/tmp/guardian-m7-bench/final-dev.json`, `final-held.json` | re-derived |
| Tier-3 safety 8/8 and 15/15 | test runs | re-derived |
| Freeze gate | `5in05x` log | **PASS 992/992** |

**Discrepancies:**

1. **Engine-port is not shipped.** `a73f07e` reverted the merge; 25 existing Execution/E2E tests regressed. The 25/59 and 28/59 results are v5.1 candidate only.
2. **Shipped runtime has no deterministic floor:** agentic 7/59 (11.9%), no-LLM 0/59.
3. **Scorecard B is deterministic-only:** 66.9% dev / 64.9% held-out; do not present it as the product runtime.
4. **G4 is met on the deterministic surface only.**
5. **G9 is all-severity (−2.0 pp); H/C is −3.2 pp** (70.9% dev vs 67.7% held-out). Both are within 10 pp.
6. **Chains are 1/6**, below 50%; G8 open.
7. Freeze gate is **PASS (992/992)**; the earlier `GtumGa` failures were mid-change and are superseded.
8. **Final deterministic rerun:** dev holds at 115/172; held-out is 111/171, one below the earlier 112. The document uses the final rerun values.
9. **v5.1 integration is sliced, not a re-merge.** Slices 1–2 are in progress behind a default-off flag; the reverted branch is reference only. See §0.
10. **No v5.1 number is shipped.** The 25/59 / 28/59 candidate and any slice measurement become citable only after the flag flips and §0.3 is green.
