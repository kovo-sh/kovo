# `reason-bench` — LLM-required vulnerability reasoning benchmark

`reason-bench` measures **pure agentic security reasoning lift** (`Agentic − NoLLM`) on multi-tenant
business-logic, authorization, temporal, economic and cross-surface vulnerabilities that deterministic
DAST/SAST heuristics cannot solve. It extends
[`../realistic-bench`](../realistic-bench/CONTRACTS.md)'s loopback runtime, materialization pipeline
and impact-oracle grading model, and keeps every safety invariant.

Binding spec: [`plans/reason-bench.md`](../../plans/reason-bench.md). Build contract:
[`CONTRACTS.md`](./CONTRACTS.md). **M0 status:** core runtime, oracles, generator, grader, CLI and
safety/causal-chain tests are implemented. App shells (`apps/ledgerflow`, `apps/forgecloud`) land in
M1–M3 and are discovered dynamically; `run.ts` compiles and its `seeds` CLI works with no apps present.

---

## Why this benchmark exists

Syntactic scanners already score ~100% on `xben-25`/`held-out-saas` and ~45–55% `--no-llm` on
`realistic-bench`. `reason-bench` sites are designed to defeat them:

1. **Schema-valid traffic** — every request returns `200/201/204` with valid credentials and passes
   input validation; the bug violates an implicit domain/economic/temporal/authorization invariant.
2. **Multi-step causal state machines** — 3–6 legitimate calls in a specific order, often across
   personas or time.
3. **Compositional surfaces** — REST vs. batch vs. export vs. SSE vs. PDF vs. edge middleware
   disagree about policy.
4. **Adversarial hardened twins** — equally complex look-alikes punish guesswork and pattern triggers.

### Binding anti-heuristic gate

Every planted vulnerability must pass:

- **Twin soundness:** its solver emits ≥1 attributed impact event on `vulnerable.ts` and **0** on
  `hardened.ts`; benign traffic emits **0** events on every hardened app.
- **Anti-heuristic ceiling:** `Execution --no-llm` (and the procedural deterministic harness) scores
  **0 confirmed** for the site; overall `--no-llm` floor **≤ 10–15%**. Otherwise the site is
  redesigned or moved to `realistic-bench`.

---

## Apps & sites (target)

| App | Domain | Sites |
| --- | --- | --- |
| `ledgerflow` | B2B fintech — multi-currency billing, approvals, payouts, invoices | 14 sites (families A–E) + 5 hard decoys |
| `forgecloud` | multi-tenant DevOps — CI/CD, secrets, pipelines, deployments | 14 sites (families B–F) + 5 hard decoys |

Families: **A** economic/ledger, **B** temporal/state, **C** ABAC/cross-tenant, **D** protocol/parser,
**E** causal chains, **F** code/framework semantics. See `plans/reason-bench.md` §4 for the full table.

---

## Modes & briefings

| Mode | Scanner sees |
| --- | --- |
| `black-box` | origin + `member_a` + `member_b` credentials |
| `grey-box` | all 6 personas + API reference (method/path/path-params) |
| `white-box` | grey-box + materialized `sourceDir` (neutral source, no truth) |

Six seeded personas: `owner_a`, `member_a`, `viewer_a`, `dual_member` (admin orgA / viewer orgB),
`member_b` (orgB), `revoked_or_demoted`.

---

## Usage

```bash
# dev seeds are 1..9999; held-out seeds need KOVO_RB_HELDOUT_SALT (never committed)
node benchmarks/reason-bench/run.ts seeds --set dev --n 5
KOVO_RB_HELDOUT_SALT=... node benchmarks/reason-bench/run.ts seeds --set held-out --n 5

# boot a lab (prints the mode briefing JSON; artifacts written on Ctrl-C)
KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/reason-bench/run.ts serve --app ledgerflow --seed 1 --mode grey-box

# grade a run
node benchmarks/reason-bench/run.ts grade --truth t.json --findings f.json --events e.json \
  --requests r.json --egress g.json --telemetry tel.json --mode grey-box --md out.md --json out.json

# anti-heuristic gate (fails with exit 2 when --no-llm recall > 15%)
node benchmarks/reason-bench/run.ts anti-heuristic-check --scorecard card.json --max-recall 0.15

# app self-tests once the shells exist
KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/reason-bench/run.ts selftest --app all --seeds 1,2,3
```

Programmatic API (`run.ts`): `startReasonApp`, `gradeRun`, `renderScorecard`, `briefingFor`,
`listSeeds`. Apps are imported lazily from `apps/<app>/index.ts`.

---

## Metrics

| Metric | Definition | Target |
| --- | --- | --- |
| **Heuristic Floor** | confirmed recall of `Execution --no-llm` / procedural harness | **≤ 10–15%** |
| **Pure Reasoning Lift (`ΔReasoning`)** | `Agentic confirmed recall − Heuristic Floor` (dev + salted held-out) | **≥ +35–55pp** frontier |
| **Precision** | `TP / (TP + decoyFP + unmatchedFP)` | **≥ 95%** |
| **Decoy FP rate** | `decoyFP / totalDecoys` | **0** decoy FPs |
| **Causal chain completion** | chains where every ordered hop + final impact was observed by `ChainOracle` under one causal artifact | tracked separately from single-site recall |
| **Budget/duration curve** | confirmed recall at `$2/$5/$20` × `10m/30m/60m` | tests multi-wave value |
| **Mode split** | scorecard per family A–F, grey-box vs. white-box | measures source-code lift |

---

## M0 runtime modules

- `lib/types.ts` — additive realistic-bench types: `ReasonOracleEventKind`, `CausalChainSpec`,
  `DomainVariant`, 6 personas, `AppModuleStartOpts`, `SolverCtx`.
- `lib/chain-oracle.ts` — ordered multi-hop completion tied to one causal artifact.
- `lib/policy-oracle.ts` — 12 pure invariant evaluators returning `{ violated, detail }`:
  economic conservation, self-approval, revocation, stale privilege, cross-org transfer, batch
  partial authz, tenant existence, HMAC scope, signed-URL prefix, SSO tenant confusion, parser
  differential, cache tenant bleed.
- `lib/pdf-sim.ts` — bounded pure-JS HTML→PDF text extraction + egress fetch seam.
- `lib/sse.ts` — SSE writer with revocation check on connect/write/heartbeat.
- `lib/hmac.ts` — canonical signer vs. scope-omitting signer/verifier (`hmac_scope_replay`).
- `lib/sso.ts` — simulated multi-tenant OIDC IdP/verifier with `tid`-omission and pending-email seams.
- `generator/` — dev/salted-held-out seeds, semantic domain randomization, route/param/id/decoy
  planner, dynamic site discovery, ground truth (incl. causal chains), leakage-scanned
  materialization.
- `grader/` — matching, funnel/attribution, precision & decoy FP, causal-chain completion, family
  breakdown, JSON + Markdown scorecards.
- `tests/` — safety invariants and chain-oracle ordering/soundness.

---

## Safety

Everything runs offline on `127.0.0.1:0`, requires `KOVO_ALLOW_LOCAL_LAB=1`, uses only `node:*`
built-ins, confines outbound traffic to `lib/egress.ts`, confines file features to `lib/vfs.ts`,
simulates shell execution, emits only synthetic `rb_fake_*`/`rbc_*`/`rbs_*` secrets, and scans
materialized app trees for truth/solver/mode leakage. See `tests/safety.test.ts`.

Typecheck: `node_modules/.bin/tsc -p benchmarks/reason-bench/tsconfig.json`
Tests: `KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/reason-bench/tests/`
