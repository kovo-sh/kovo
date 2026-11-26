# Kovo Hunter v7 — swarm handover (2026-11-24 11:45 PT)

> Read this first, then `plans/ROADMAP-v5.md` (the decision log, 1,013 lines), `VERIFICATION-v5.md` §V7 (the certificate and its erratum), and `plans/STREAM-BACKLOG.md` (the queue).
> This file is written for a **new agent with no context**. It states what is true, what is provable, what is broken, and what to do next — in that order.

---

## 0. Mission

Kovo Hunter is a **defensive** web-app security scanner (authorized local benchmarks + fixtures only). It has three layers:

1. **Layer 2 — deterministic floor** (`Execution --no-llm`): recon → hypotheses → probes → proofs. No model.
2. **Layer 3 — agentic** (DeepSeek V4.1 Flash via the OpenRouter profile): investigations on top of the floor.
3. **Verification** — every confirmation must satisfy a class-specific oracle over host-signed transcripts (`oracle-invariants.ts`, `proof-receipt.ts`).

**v7 thesis:** real-world conversion + white-box-first verification. The DSL ("spec VM") is being retired; ProofReceipts are the confirmation primitive. Continuous scanning/PR-diff is deferred to v8.

---

## 1. Current measured state (docker verifier, dev seed 1 / salted held-out 1000042, 600 s cells, K=6)

| Surface | Floor (`--no-llm`) | Unified (agentic) | Precision |
|---|---|---|---|
| Dev seed 1 | **36/59 (61.0%)**, 0 spread, 3 identical runs | **36/59** (lift **+0**) | **100%** (0 decoy, 0 unmatched) |
| Salted held-out 1000042 | **26/58 (44.8%)** — 11/8/7 | **29/58** measured at `f86757c` (lift **+1**, shopflow only) | **100%** |

**Certified (reviewer-ratified, `VERIFICATION-v5.md` §V7.2):** Floor + Realism wiring + **100% worst-run precision** (dev) + legacy gates (xben 25/25, held-out-saas 20/20 + 20/20 patches) + confirmation integrity (store-level invariant).
**NOT certified:** agentic lift (67 investigations converted 1 target = 1.5%), Total Product Recall (needs ≥40/59 dev and ≥32/58 held-out), anti-inert guard (needs ≥+4 net-new over the frozen floor).
**Erratum open:** the certificate's held-out 28/58 is **not reproducible**; three independent streams + a clean audit say **26/58**. The two extra targets were produced by a **persona-scope bleed** (a `viewer` request served another tenant's store). Fix with `persona-binding`, then re-issue either 28 (if the viewer legitimately owns that store) or **26 with an erratum**.

### Realism suites
| Fixture | Status |
|---|---|
| #2 `wan-oob` | wiring PASS, `oob_wiring_fnr` **0%**, async **SSRF ✅ + XXE ✅** (2 TP / 0 FP); `fixture_capability_recall` 50% (blind SQLi + exfil chain 2/3 missing) |
| #3 `staging-concurrency` | **capability PASS** — write-BOLA, HTTP/2 single-packet race (2 ms, 4 acks / 1 debit), checkout tampering, 0 leaks, 100% precision |
| #4 `monorepo-whitebox` | **capability PASS — 3/3 4-hop confirmed at 100%**, chain `mono-tenant-takeover` 2/2, canonical (no fallbacks) |

---

## 2. What was fixed most recently (context for the current numbers)

| Fix | Effect |
|---|---|
| Probe-class carried across the broker (payload 5xx is evidence, not an outage) | held-out floor 17 → 24 |
| Identity-assumption probes strip scope selectors; self-state proof restores baseline (`w3`) | recovered 2 shopflow targets (later found persona-bleed-tainted) |
| Phase-0 crawl paging (1,000/page, stable order) | no 500-row truncation on 6k-route surfaces |
| Injection impact class from machine-readable labels only | fixed a real label bug (SQLi rebranded CWE-200 → unmatched FP) |
| Recon param discovery with provenance (`observed` / `inferred_bundle|html|ast`, `:sensitive` only after a paired check) | held-out +1, then +2 more via quota |
| `pathHasSearchHint` token-boundary + evidence-based quota reservation | dev 34→36, held-out 25→28 (pre-bleed) |
| Universal status-only ban + per-class oracles (injection fingerprints, publicness, anon-401-is-not-a-peer-control) | precision 50% → 100% on a full held-out matrix |
| **Per-route proof obligation** (one gap no longer discharges every route) | route-hit → verify_called **12.5% → 69.2%** |
| Gap validation against the transcript | 4/4 unearned gaps rejected in the measured cell |
| Realism #4: Tier-A lead priority + identifier targets + mandatory Round-1 seeding + `dry_rounds` may only stop speculative work | 4-hop **0/3 → 3/3** |
| Stall watchdog (28 s no-token, 1 retry) + warm pool K=6 (77% reuse) | acme p50 154 s → **104.4 s**, completed-only 72.8 s |
| Cut 3a/3b receipt rules (`boolean`, `status_differential`, authz readback) | one family migrated; VM **not** deletable yet (see §4) |

---

## 3. Architecture map (line counts today)

| File | LOC | Role |
|---|---:|---|
| `src/server/execution.ts` | 13,039 | Orchestration: budgets, planner/dispatch, Phase A/B, settlement, finding persistence. **The hot file.** |
| `src/server/agent-session.ts` | 5,837 | Tool loop, settlement, proof obligations, gap validation, early exit. |
| `src/server/replay-verifier.ts` | 3,953 | The legacy spec VM. Still load-bearing (see §4). |
| `src/server/deterministic-engine.ts` | — | Hypothesis selection, quota, probes scheduling. |
| `src/server/deterministic-specs.ts` | — | Canonical spec synthesis (authz jq, SQL error chain, boolean). |
| `src/server/oracle-invariants.ts` | 2,518 | **All confirmation gates.** Never weaken. |
| `src/server/proof-receipt.ts` | 631 | Receipt primitive + `verifyReceipt()`. |
| `src/server/floor-recipes.ts` (+engine) | 1,396 | Typed recipes; production caller for the boolean family. |
| `src/replay-spec.ts` | 852 | Declarative spec schema (+ recipe envelope). |
| `scripts/benchmark-realistic.ts` | — | **Product** harness (`Execution`). Emits `--out` JSON + FP evidence. |
| `scripts/smoke-agentic.ts` | — | Tier 0/1/2 smoke battery (gates incl. precision trap). |
| `scripts/worker-gate.sh` | — | Mandatory pre-handoff gate (typecheck + invariants + lease guard). |

---

## 4. The one blocking architectural fact (read before touching the VM)

`replay-verifier.ts` cannot shrink because the **agent** proof path never persists a script:
- production does not wire `handlers.kovo_verify` into `AgentSession`;
- there is **no storage table** for a verified agent script/receipt;
- therefore agent findings are still declarative `replay_spec` rows covering any of 14 kinds (`execution.ts` ~12298), and patch retest historically replayed them.

`retest-receipts` (merged) moved **floor** retest onto recipes and the harness onto the product entrypoint, but explicitly reported that deleting the VM requires the agent half. `agent-script-proofs` (WIP, §7) is that work.

**Do not "delete the VM" by branch deletion.** Retest and the harness were the first dependencies; the agent spec path is the last. Prove equivalence after each step.

---

## 5. Invariants — never break these

1. **Precision first.** Any confirmed finding whose persisted evidence does not satisfy its class oracle is a defect. `Store.assertConfirmationEvidence()` throws `InvariantError('invariant.confirmation_evidence')`; SQLite triggers back it up.
2. **No gate weakening to gain recall.** If a target cannot be proved, the answer is better evidence, not a looser oracle.
3. **No benchmark literals** (no app/route/seed names in `src/`). Ordering must be deterministic and evidence-derived.
4. **No truth inflation.** A fixture may only be *hardened* for genuinely unintended, non-planted behavior, with an entry in `benchmarks/CHANGELOG.md`. Adding a target to `truth.json` requires an explicit, versioned denominator bump and operator sign-off.
5. **Inference is not proof.** Inferred params may seed a hypothesis; confirmation still needs the full receipt.
6. **Status-only divergence never confirms** any class. Injection needs a fingerprint/boolean/timing/OOB; authz reads need non-public data (`variantBody !== anonBody`); writes need a post-GET delta; redirects need an off-origin `Location` no control reaches.
7. **`anon = 401` is not a peer control** for an authenticated cross-tenant write.
8. **Same production model.** The operator requires `deepseek/deepseek-v4.1-flash-1017`. A different-model control run needs explicit operator approval.
9. **`dry_rounds` may only stop speculative re-investigation** — never abandon first-pass routes/classes or Tier-A slices.
10. **`worker-gate.sh` must pass before handoff**, and it fails when the **main checkout is dirty** (subagents must work in their worktrees; coordinator override `WORKER_GATE_ALLOW_DIRTY_MAIN=1`).

---

## 6. Ranked backlog (do in this order)

1. **`persona-binding` (P0, in flight):** transport-level per-request scope — `Map<workerId, Map<personaHandle, IsolatedSession>>`, cookies resolved only from that key, `Set-Cookie` rotations scoped back. It is both a recall loss (`viewer` served another store) and a **precision** hazard (a same-tenant claim mis-attributed to a cross-tenant decoy: 88.9% cell). Then re-issue the certificate erratum.
2. **`agent-script-proofs` (P0, in flight):** persist the verified agent proof (script + receipt), wire the handler in production, make `verify_replay_spec`/`propose_chain_finding` receipt-first, then delete legacy branches. **This is the M0 closer.**
3. **`capability-misses` (in flight):** `api-jwt-alg-none`, `giftcard-race`, `coupon-reuse`, `inventory-oversell` — one JWT boundary + three stateful race/workflow classes. Worth ~+4–5 held-out, i.e. the difference between +1 and a real lift. (Check its result before duplicating.)
4. **`execution.ts` engine-lane follow-ups** (beside/after 2): profile-aware no-token watchdog (28 s aborted 45 streams → 552 turns), demote unstarted trial duplicates (287 turns), planner coverage assert for discovered high-risk routes (6 targets), wire `onGapValidation`/`onProofObligation`/`onEarlyExit` stat forwarding.
5. **Realism #2 remainder:** blind SQLi + exfil chain leg 3/3 (needs `probes/injection.ts` + engine).
6. **Retire the VM** once (2) lands: parity gate = xben 25/25, held-out-saas 20/20 + 20/20 patches, dev 36/59 0-spread, held-out exact total at 100%.
7. **Hygiene:** pre-existing red/hanging tests (`tests/v5-engine-coverage.test.ts` 2 failures, `tests/v5-verifier-guards.test.ts` publicness dismissal, `tests/v4-m4-surface-orchestration.test.ts` teardown hang) — these are known-red on main, not caused by recent work.
8. **Smoke calibration** (8 varied builds vs reference) only after the above; Tier 1 is a tripwire until then.

---

## 7. Active WIP branches — exact state (all committed, clean, NOT pushed)

### 7.1 `agents/persona-binding` @ `c2ce1ce` — **the erratum resolver. Highest priority.**
**Root cause bisected and proven:** the persona bleed was introduced by **`0df720d` (Cut 3b)**. Identity-assumption routes (`/admin/impersonate`) were routed through the `persisted_mutation` recipe, which emits `state_reset → baseline_read → mutation_probe → post_mutation_read` and **no post-restore**; the legacy `http_chain` it replaced carried the `w3` restore (`deterministic-specs.ts:601`). Result: the viewer's session stayed pinned to `actAsStore=6ea2e7` for the rest of the run. Clean commits `98480cc…bd01209` measure 10/19; `0df720d` measures 8/19.

| persona | `2621bab` | defect `0df720d` | after fix |
|---|---|---|---|
| persona_a | 9ca676 | 9ca676 | 9ca676 |
| persona_b | 6ea2e7 | 6ea2e7 | 6ea2e7 |
| admin | 9ca676 | 9ca676 | 9ca676 |
| viewer | 9ca676 | **6ea2e7** | **9ca676** |

Done: broker jars keyed `(run, assignment, role, persona, session)`; mismatch detector on the shared login-session cookie **fails closed** (`BrokerDenied`, nothing sent) + `broker.persona_scope_mismatch` event + `getPersonaScopeMismatches()`; per-persona plumbing in `surface-engine.ts` / `scoped-browser.ts` / `canary-broker.ts`; **post-observation `state_restore` cleanup** in `floor-recipes.ts` `persistedMutation` (~15 LOC); 7 tests incl. A/B/A/B interleaving and restore-before-next-read.

**Measured:** dev **36/59 ×2, 0 spread, 100%**; salted held-out **28/58 @100%** (11/10/7); shopflow cell 10/19 @100%; xben+held-out-saas 45/45; patches 20/20 fixed.

**Before merging:** (a) the `floor-recipes.ts` restore hunk needs owner sign-off — as coordinator I approve it, since it restores behavior `0df720d` dropped; (b) run **one repeat** of the salted held-out floor and the shopflow agentic cell to confirm 28/58 and 100% precision with the fix, and to catch the decoy FP direction (unit-tested only so far); (c) note the `deterministic-engine.ts` credential-scan path (~3630) calls `broker.executeHttp` directly and relies on the broker refusing mismatches.

**If it validates, the certificate erratum resolves to 28/58 (the viewer legitimately owns `9ca676`), not 26.**

### 7.2 `agents/agent-script-proofs` @ `16726df` — M0 closer, **code only, unvalidated**
Done (typecheck clean): `agentScriptProofEnvelopeSchema` + `agentScript` on `replayBase`; schema v8→v9 additive migration with `replay_specs` proof columns (`proof_kind/verdict/runtime/script_sha256/artifact_id/receipt`) + accessors; `buildAgentScriptReceipt()`; `runAgentScriptProof()` (real worker session + `VerifyRpcServer`, fresh nonce, transcript → `verifyReceipt`); production `kovo_verify` handler registered **only** for `LinuxWorkerBackend`; `persistAgentScriptProof()` (owner-only artifact, synthesized attribution-only spec, finding upserted with a `ProofReceipt…` verification string so the confirmation guard holds); receipt-first short-circuit at the top of `executeInlineVerification` for `verify_replay_spec` / `propose_chain_finding` / `update_proposed_finding`; `retestPersistedAgentScript()` wired into `retestReplaySpec`.

**Not done:** no `tests/v7-agent-script-proofs.test.ts`, no `worker-gate.sh`, **no benchmark of any kind**, **zero deletions**. The next step is exactly: write the test (receipt persistence + retest through a fake backend/attempt factory), run `npm run check` + `worker-gate.sh`, then parity (xben 25/25, held-out-saas 20/20 + 20/20 patches, dev 36/59, salted held-out exact total), then one agentic cell to prove agent findings cite receipts, then delete only provably-unreachable branches.

Known coverage gaps (documented, not blockers to running): receipts cover **impact / structural_diff / timing** claims only — boundary-only, OOB, race, browser proofs stay script-only; there is **no `VerifyBrowserDriver` adapter** (`verify-rpc.ts ~1857`) so `ctx.browser` calls fail by design; `scriptPath` reads only from `reposDir` (`execution.ts ~12230`).

### 7.3 `agents/capability-misses` @ `e5027f1` — diagnosis done, **no recall gain yet**
Done but unvalidated end-to-end: JWT hypothesis for reporting/integration reads even when cookie auth is rejected; `probes/jwt.ts` scope-bearing claim candidate with a **data-bearing JSON body** requirement (status-only rejected) + `payload`/`dataFields`/`declaredAlg`; forged-token replay emits `tokenMints` (HS256-empty-signature control vs `alg:none` probe) with field-bound jq; `replay-spec.ts` allows `Authorization` only as `Bearer {{mintName}}`; `broker.ts` allows caller `Authorization` only for 3-segment JWTs with an **empty signature** (`isSelfMintedBearer`).

**Confirmed root causes from kept dirs (this is the valuable part):**
- `api-jwt-alg-none`: `property_hypothesis_miss` — `/api/v1/reports/sales` returns 401 to cookie auth and the route noun is not in `credentialSurface`, so no hypothesis; header-transport forge was impossible because the broker forbade caller `Authorization`.
- `giftcard-race` + `inventory-oversell`: **race hypotheses are gated on `environmentMode === 'staging_isolated'`** (`deterministic-engine.ts:2051`) but the bench runs `ephemeral_lab`, so `race_burst` never forms. Secondary: `probeRaceDoubleSpend` (~3932) POSTs `{}` expecting 2xx (giftcard returns 409), resolves no `{{id}}`, and bursts `amount=1`, which cannot drive the balance/stock negative — the actual oracle condition.
- `coupon-reuse`: `surface_miss` — `actionVerb` (~2008) excludes `coupons/redeem/apply`; and `applyCoupon` has **no persisted readback** (only inserts `coupon_uses`; the cart GET never shows it), so a one-shot-reuse proof has no observable delta on this app.

**Next:** re-run shopflow dev floor and grep probes for `reports/sales`; if still absent, inspect the `auth_protocol` cap/rank (~4620) and `add()` risk ordering. Then widen race to `ephemeral_lab`, resolve `{{id}}` with a GET readback and a full-conserved-value burst — that is the expected +2.

## 8. Runbook (copy-paste)

```bash
# Pre-handoff gate (must pass; fails on a dirty main checkout)
bash scripts/worker-gate.sh

# Dev floor (no model, cheap)
newgrp docker -c 'cd <repo-root> && KOVO_ALLOW_LOCAL_LAB=1 \
  node scripts/benchmark-realistic.ts --app all --seeds 1 --mode grey-box --no-llm \
  --verifier docker --no-conventional-wordlist --isolate-data-dir --concurrency 1 \
  --budget-usd 2 --max-duration-ms 600000 --out-dir /tmp/floor-x'

# Salted held-out floor (never print the salt)
newgrp docker -c 'cd <repo-root> && KOVO_ALLOW_LOCAL_LAB=1 \
  KOVO_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")" \
  node scripts/benchmark-realistic.ts --app all --seeds 1000042 --held-out --mode grey-box \
  --no-llm --verifier docker --isolate-data-dir --concurrency 1 --budget-usd 2 \
  --max-duration-ms 600000 --out-dir /tmp/heldout-x'

# Agentic cell (SERIALIZED: --data-dir takes an exclusive lock)
newgrp docker -c 'cd <repo-root> && KOVO_ALLOW_LOCAL_LAB=1 \
  KOVO_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")" \
  node scripts/benchmark-realistic.ts --app shopflow --seeds 1000042 --held-out --mode grey-box \
  --verifier docker --isolate-data-dir --keep-data-dirs --concurrency 1 --worker-concurrency 6 \
  --budget-usd 5 --max-duration-ms 600000 --data-dir "$HOME/guardian-data" \
  --out-dir /tmp/agentic-x'

# Realism suites
newgrp docker -c 'cd <repo-root> && KOVO_ALLOW_LOCAL_LAB=1 \
  node scripts/benchmark-realism.ts --fixture wan-oob --no-llm --verifier docker --out-dir /tmp/r2'
node scripts/smoke-agentic.ts --tier 1 --out-dir /tmp/smoke   # ~6 min, ~$1.30, includes the precision trap

# Confirmation-integrity audit on any kept cell
node scripts/audit-confirmation-consistency.ts --data-dir /tmp/x/data/<cell>
```

**Environment gotchas that cost real runs:**
- `/tmp` is a **15 GB tmpfs**. Keep data dirs only for cells under triage; `EDQUOT` looks like a benchmark failure.
- `--data-dir` holds an **exclusive SQLite lock** (model profile) ⇒ **agentic runs are globally serialized**. Floor runs don't need it.
- 29 GB RAM; concurrent benchmark cells cause SIGTERMs and hung cells. One benchmark at a time.
- Docker needs `newgrp docker -c '…'`.
- Model profile: `KOVO_DATA_DIR="$HOME/guardian-data"` (OpenRouter DeepSeek V4.1 Flash). Credentials live outside the repo; never print or commit them.

---

## 9. Definition of done for the next milestone

1. `persona-binding` merged: served-store table proves per-persona isolation; interleaved-persona test passes; precision 100% with no bleed.
2. Certificate erratum issued (26 or 28) with the reason.
3. `agent-script-proofs` merged with receipt-first agent findings, and the legacy branches deleted **only** where provably unreachable.
4. Total Product Recall ≥ **40/59 dev** and ≥ **32/58 held-out** at 100% worst-run precision, **and** ≥ **+4 net-new** over the frozen floor (36/59, 26/58).
5. Tier-1 smoke green (including the precision trap = 0).

Report every number with its provenance (which tree, which seed, which budgets) and never quote a harness/procedural number as the product score.
