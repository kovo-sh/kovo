# Realism exit-gate calibration

This document defines how the four `benchmarks/realism-suite` fixtures become measured
**exit gates** for the product pipeline. Every number is produced by the real
`Execution` orchestrator (`scripts/benchmark-realism.ts`) and graded offline against
`benchmarks/realism-suite/fixtures/<fixture>/truth.json`. The harness never imports or
serves `truth.json` to `Execution`.

> Defensive QA context: the fixtures are loopback-only authorized lab targets. They
> measure whether Kovo's discovery, auth, replay and evidence pipeline works under
> realistic enterprise, WAN, staging and monorepo conditions — not an attack tool.

## Safety and evidence rules

- `KOVO_ALLOW_LOCAL_LAB=1` is mandatory; fixtures bind only `127.0.0.1:0`.
- Fixture credentials are synthetic and per-run. Artifacts are written `0600` in a `0700`
  directory and scanned for known fixture secrets, `KOVO_RB_HELDOUT_SALT` when set,
  private keys, provider keys, JWTs and AWS-shaped keys. A dirty scan exits `4`.
- `--no-llm` is the deterministic floor. It never inherits a model-enabled data dir.
- Agentic runs need an enabled model profile (`--data-dir` / `KOVO_DATA_DIR`) **and**
  a worker-session-capable verifier (`--verifier docker`). `local-jq` plus a model profile
  exits `2` instead of producing an inert run.
- A fixture that `Execution` cannot reach is recorded with its exact failure stage
  (`fixture_start`, `execution_preflight`, `execution_failed`, `timeout`, `discovery`,
  `investigation`, `verification_or_attribution`, `gate_incomplete`, `interrupted`).
  A missing measurement is never written as a pass.
- Default exit code is `0` for a completed measurement even when a gate is unmet.
  `--fail-on-gate` exits `3` when any required criterion is false (CI use).

## Commands

```bash
# Deterministic floor per fixture (no model profile, no Docker required)
KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
  --fixture enterprise-spa --no-llm --out-dir .kovo/realism-gate

# Agentic lane per fixture (needs a model profile + Docker worker sessions)
KOVO_ALLOW_LOCAL_LAB=1 KOVO_DATA_DIR=/path/to/kovo-data \
  newgrp docker -c 'npm run benchmark:realism -- --fixture enterprise-spa --verifier docker \
    --mode grey-box --out-dir .kovo/realism-gate-agentic'

# CI form: fail the build when a required gate criterion is not met
KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
  --fixture all --no-llm --fail-on-gate --out-dir .kovo/realism-gate

# Cross-check the persisted findings with the suite's own grader
KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/realism-suite/run.ts grade \
  --fixture enterprise-spa --findings .kovo/realism-gate/enterprise-spa-grey-box-no-llm.findings.json
```

Artifacts per fixture (`<slug> = <fixture>-<mode>[-no-llm]`):

| Artifact | Contents |
| --- | --- |
| `<slug>.json` | gate criteria, metrics, grade, meta, failure stage |
| `<slug>.md` | rendered gate report |
| `<slug>.meta.json` | model/verifier/budget/terminal/shutdown/orphan metadata |
| `<slug>.findings.json` | submitted findings (re-gradeable by the suite grader) |
| `summary.json` / `summary.md` | aggregate over all fixtures + artifact scan result |

## Grading model

Submitted findings are `{ origin, method, endpoint, vulnClass?, status? }`. `origin` is
mapped from the fixture origin URL back to its fixture label (`app`, `api`, `proxy`,
`idp`, `h2`). Endpoints come from persisted replay specs, falling back to the finding's
persisted broker exchanges. Baseline hygiene checks, dismissed and superseded findings
are excluded. `TP = distinct matched truth findings`; `FP = decoy matches + unmatched
claims`; `precision = TP/(TP+FP)`; `recall = TP/truth findings`. Chain completion is
`covered/total` from `truth.json` chains.

Known attribution caveat: two truth findings may share one endpoint (for example a
monorepo BOLA and its git-history regression, or the blind-SQLi/GraphQL POST route and
an introspection decoy). The suite grader treats a single submitted claim as a match for
one truth entry and reports the second as a duplicate TP; decoys are checked first. Gate
criteria therefore use explicit truth IDs rather than raw recall.

## Wiring health vs capability

Every cell reports two verdicts:

- **wiring** — was the product mechanism actually exercised, and did its safety invariants hold?
- **capability** — did the product confirm the fixture's ground-truth vulnerabilities?

The printed report puts `## Wiring health (separate from capability)` beside the capability
criteria, and every artifact carries `metrics.wiring.status` plus `capabilityPassed` /
`wiringPassed`. A cell passes overall only when both verdicts pass. A wiring failure therefore
cannot be softened by a capability pass, and a capability miss is still reported as a wiring
PASS when the mechanism ran safely (the useful "real product gap" shape).

Missing measurements are `unmeasured`, never coerced to zero or pass. Wiring status is `fail` if
any check fails, else `unmeasured` if any check is unmeasured, else `pass`.

### Metric sources

| Metric | Source | Notes |
| --- | --- | --- |
| `pendingOobRegistered` | `<data-dir>/oob-relay.sqlite` → `pending_oob` rows for the run | durable subscriptions, not just in-memory tokens |
| `lateCallbacksMatched` | same table: `status='promoted'` and `promoted_at - created_at > immediate_ms` | promotions after the immediate correlation window |
| `oobDrainWaitedMs` | latest `oob.drain_complete` run-event meta (`oobDrainMs`) | produced by the engine's bounded pre-report drain |
| `latePromotions` | same event meta (`promotedLate`) | `null` when the drain never ran |
| `approvalBlocks` | `approval_requests` rows that are pending/undecided or not `auto-review:*` | auto-review audit rows are not blocks; the raw row count is reported as `approvalRequestsCreated` |
| `brokerDeniedMutations` | harness-instrumented real `RequestBroker`: `BrokerDenied` for POST/PUT/PATCH/DELETE | `brokerDeniedTotal` and payload-free reason classes are reported for context |
| `parkedWorkers` | `assignments` with `approval_parked_at` set | current awaiting-approval assignments |
| `h2SinglePacketBursts` | instrumented race barrier: burst completed with every participant arriving and none skipping | `http1FallbackBursts` / `raceBursts` give the fallback context; staging runs with HTTP/2 enabled because the fixture's h2c endpoint is the object under test |
| `storedEndpoints` | `endpoints` rows for the run | `null` if the count query failed |
| `declaredEndpoints` | fixture `routes.length` | fixture-declared surface |
| `storeWriteP99Ms` | harness timing of real `Store.upsertEndpoint` calls during the run | nearest-rank p99; `null` with fewer than 20 writes |
| `siblingDerivationSuppressed` | `phase0.siblings_suppressed` event with `KOVO_RECON_SIBLINGS=1` | `false` when Phase-0 ran without suppressing; `null` when no Phase-0 evidence exists |
| `tierA4HopSinks` | truth 4-hop IDs matched to Program-Graph code→runtime lead facts (`source=program_graph`) | Tier A is the hypothesis-linked priority set; `null` without ranking evidence |
| `leakedEntities` | staging `orphans()` after `cleanup(runId)` | unchanged from the staging safety gate |

Harness instrumentation observes the real `RequestBroker` and real `Store`; it does not
reimplement or bypass broker policy. The instrumentation lives only in
`scripts/benchmark-realism.ts`.

### Wiring criteria

| Fixture | Wiring check | Rule |
| --- | --- | --- |
| #2 `wan-oob` | durable OOB registration | `pendingOobRegistered > 0` |
| #2 `wan-oob` | pre-report drain window | fail when `lateCallbacksMatched > 0` and `oobDrainWaitedMs < 15,000` (a missing drain measurement also fails close) |
| #3 `staging-concurrency` | no blocking approvals | `approvalBlocks == 0` |
| #3 `staging-concurrency` | no denied mutations | `brokerDeniedMutations == 0` |
| #3 `staging-concurrency` | cleanup | `leakedEntities == 0` |
| #3 `staging-concurrency` | race transport (capability criterion) | the race criterion additionally requires `h2SinglePacketBursts >= 1` |
| #4 `monorepo-whitebox` | lossless store scale | `storedEndpoints >= 2,500` |
| #4 `monorepo-whitebox` | store latency | `storeWriteP99Ms < 50` |
| #4 `monorepo-whitebox` | sibling suppression | `siblingDerivationSuppressed == true` |
| #4 `monorepo-whitebox` | Tier A ranking | `tierA4HopSinks >= 2` |

## Gate #1 — enterprise SPA (`enterprise-spa`)

Gate: **route discovery ≥ 80%**, **cross-origin/tenant authz confirmed**, **browser-executed
stored XSS confirmed**, and chain `spa-admin-compromise` complete.

| Measurement | Definition | `--no-llm` result | agentic result |
| --- | --- | --- | --- |
| Route discovery | matched declared application routes / total declared application routes (`fixture.routes`, excluding liveness, CORS preflight, catch-all handlers and fixture test hooks) | — | — |
| Cross-origin authz | TP for `spa-graphql-bola` **or** `spa-admin-export-bfla` | — | — |
| Stored XSS matched | TP for `spa-stored-xss-admin` | — | — |
| Browser-executed stored XSS | stored-XSS TP whose finding evidence reports browser/DOM/Playwright/rendered-script execution | — | — |
| Chain completion | `spa-admin-compromise` covered/total | — | — |
| Grade | TP / FP / precision / recall | — | — |

```bash
KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- --fixture enterprise-spa --no-llm
```

## Gate #2 — WAN + async OOB (`wan-oob`)

Two orthogonal gates (never blended):

- **`oob_wiring_fnr` ≤ 5%** (target 0%) — async-OOB wiring reliability. Denominator = minted
  async-OOB canaries whose callback fired (SSRF/XXE), falling back to all minted async canaries
  when nothing fired; unmeasured (`null`) when no async canary was minted. Blind SQLi and the
  exfil chain are **never** in this denominator.
- **`fixture_capability_recall` ≥ 75%** — product capability over all planted #2 targets:
  async SSRF, async XXE, blind SQLi, and chain `wan-oob-exfil` complete. 2 of 4 is 50% and fails;
  3 of 4 (75%) passes.

The legacy blended async false-negative rate is still printed as an informational row but is no
longer a gate. Wiring is additionally judged separately: at least one durable `pending_oob`
subscription must be registered, and any late callback must be allowed the full ≥ 15 s drain
window (see “Wiring health vs capability”).

| Measurement | Definition | `--no-llm` result | agentic result |
| --- | --- | --- | --- |
| OOB wiring FNR | fired async canary targets without a confirmation / fired async canary targets (SSRF, XXE) | — | — |
| Capability recall | confirmed planted targets / 4 `{wan-ssrf-async, wan-xxe-async, wan-blind-sqli, wan-oob-exfil chain}` | — | — |
| Blind SQLi | TP for `wan-blind-sqli` (capability member) | — | — |
| Async SSRF / XXE | TP for `wan-ssrf-async` / `wan-xxe-async` (capability and wiring members) | — | — |
| Async canary evidence | `canaries` rows by purpose (`ssrf*` / `xxe*`): minted vs fired (`triggered` or `hit_count > 0`) | — | — |
| Legacy blended async FNR | missed `{wan-blind-sqli, wan-ssrf-async, wan-xxe-async}` / 3 — **informational only** | — | — |
| Fixture callback evidence | fixture-side collector observed `sqli` / `ssrf` / `xxe` / `webhook` after the HTTP response | — | — |
| Chain completion | `wan-oob-exfil` covered/total (capability member) | — | — |
| Grade | TP / FP / precision / recall | — | — |

```bash
KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- --fixture wan-oob --no-llm
```

Flag: `--callback-delay-ms` exists for smoke runs only; the default `15000,30000` is the gate configuration.

## Gate #3 — staging safety (`staging-concurrency`)

Gate: **write-BOLA confirmed**, **HTTP/2 race confirmed**, **checkout price tampering
confirmed**, and **zero leaked `kovo-qa-` entities after cleanup**. Chain
`stg-tenant-takeover` is reported informationally (the explicit staging gate above is
authoritative). Wiring is judged separately: zero blocking approvals, zero broker-denied
mutating requests, and zero leaked entities. The race capability criterion additionally
requires at least one HTTP/2 single-packet burst.

The harness runs the fixture in `staging_isolated`, then after `Execution` stops calls the
fixture's `cleanup(runId)` and re-reads `orphans()` before fixture teardown. Zero orphans is
only meaningful alongside the three positive criteria: a run that performs no tagged
mutations reports `0 leaked` but still fails the write/race/checkout gate.

| Measurement | Definition | `--no-llm` result | agentic result |
| --- | --- | --- | --- |
| Write-BOLA | TP for `stg-write-bola` | — | — |
| HTTP/2 race | TP for `stg-race-double-spend` | — | — |
| Checkout tampering | TP for `stg-price-tampering` | — | — |
| Leaked entities | `fixture.orphans()` length after `cleanup(runId)` (prefix `kovo-qa-`) | — | — |
| Cleanup effect | records removed / tenant mutations restored | — | — |
| Grade | TP / FP / precision / recall | — | — |

```bash
KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- --fixture staging-concurrency --no-llm
```

## Gate #4 — monorepo white-box (`monorepo-whitebox`)

Gate: **SAST-suspect → live-endpoint link ≥ 85%**, **2,500-route scale without endpoint
truncation**, **at least two 4-hop sinks confirmed**, and chain `mono-tenant-takeover`
complete. Run with `--mode white-box` so the preserved `.git` tree is mounted read-only.
Wiring is judged separately: at least 2,500 persisted endpoints, endpoint-write p99 < 50 ms,
sibling derivation suppressed by the AST/declared surface, and at least two truth 4-hop sinks
ranked Tier A.

| Measurement | Definition | `--no-llm` result | agentic result |
| --- | --- | --- | --- |
| SAST link rate | findings with `codeLocations` that also carry a concrete live endpoint / all findings with `codeLocations` | — | — |
| Route scale | declared catalog vs harness OpenAPI operations (`specOps`) vs persisted rows/distinct canonical identities vs retrieved rows; **truncated** when retrieved < persisted; gate requires declared ≥ 2,500 and `declaredMatched` ≥ 2,500 | — | — |
| Code leads | Program-Graph `det_lead` facts; `fourHopLeads` counts route→sink chains of at least four hops | — | — |
| Probe plan | Phase-0 ranked plan: Tier A (`priority`), schema-typed, clustered probe subset, total routes | — | — |
| 4-hop confirmations | TP count among `{mono-billing-bola, mono-report-sqli, mono-admin-bfla}` (0–3) | — | — |
| Per-slice funnel | per Tier-A 4-hop slice: `dispatched_count` (assignments attributed via fact link / brief target / route hit), `target_route_hit` (broker exchange on the exact mounted method+route), `verify_called` (replay specs whose requests hit that route), `oracle_rejected_by` (structural rejection-code histogram) | — | — |
| Chain completion | `mono-tenant-takeover` covered/total | — | — |
| Grade | TP / FP / precision / recall | — | — |

```bash
KOVO_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
  --fixture monorepo-whitebox --mode white-box --no-llm
```

## Result log (real runs only)

Add rows only from an executed harness artifact. Include the commit SHA and artifact path;
do not transcribe expected or simulated numbers.

| Date | Commit | Fixture | Mode / lane | Gate | Stage | Key measurements | Artifact |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-11-23 | `91a4be1` | `enterprise-spa` | grey-box / `--no-llm` | FAIL | `investigation` | route 16/24 (66.7%); authz no; stored XSS no; chain 0/2; TP 0 / FP 0 / submitted 0; 79 endpoints; 822 engine requests, 0 confirmed / 0 leads; 108.7 s | `realism-gate-1-final` (local out-dir) |
| 2026-11-23 | `91a4be1` | `staging-concurrency` | grey-box / `--no-llm`, `staging_isolated` | FAIL | `investigation` | write-BOLA no; h2 race no; checkout no; leaked 0 (no tagged mutations; cleanup removed 0 / restored 0); TP 0 / FP 0; 32 endpoints; 539 engine requests, 0 confirmed / 0 leads; 49.1 s | `realism-gate-3-final` (local out-dir) |
| 2026-11-23 | `91a4be1` | `wan-oob` | grey-box / `--no-llm`, **smoke** (`--callback-delay-ms 1000,2000`) | FAIL | `timeout` | blind SQLi / async SSRF / async XXE: no product confirmations; async FN 100%; fixture-side `sqli` callback observed, `ssrf`/`xxe` not; TP 0 / FP 0; 36 endpoints; 120 s cap | `realism-gate-2-smoke` (local out-dir) |
| 2026-11-23 | `91a4be1` | `monorepo-whitebox` | white-box / `--no-llm`, **smoke** (120 s cap) | FAIL | `investigation` | SAST suspects 0 (link n/a); persisted 62 / retrieved 62 / declared 2,565 (under 2,500); 4-hop 0/3; chain 0/2; TP 0 / FP 0; 611 engine requests, 2 rejected / 1 lead; 88.3 s | `realism-gate-4-smoke` (local out-dir) |
| 2026-11-23 | `b62401c` | `wan-oob` | grey-box / `--no-llm`, 300 s cap, default callback delays (15/30 s) | FAIL | `investigation` | **wiring FAIL**: pending_oob registered 0; drain n/a (no late callbacks); approvals 0 blocking / 176 auto-review rows; denied mutations 0; 33 endpoints; p99 1.24 ms; **capability FAIL**: blind SQLi / async SSRF / async XXE not confirmed, async FN 100%; fixture callbacks `sqli` only; TP 0 / FP 0; 467 engine requests | `realism-gate-2-final` (local out-dir) |
| 2026-11-23 | `b62401c` | `staging-concurrency` | grey-box / `--no-llm`, 180 s cap, `staging_isolated`, HTTP/2 transport enabled | FAIL | `investigation` | **wiring FAIL**: approvals 0 blocking; **denied mutations 15 (all `staging_contract`)**; parked workers 0; leaked 0; **h2 single-packet bursts 0**, HTTP/1.1 fallback 0; 18 endpoints; p99 1.23 ms; **capability FAIL**: write-BOLA / race / checkout not confirmed; TP 0 / FP 0; 396 engine requests | `realism-gate-3-final` (local out-dir) |
| 2026-11-23 | `b62401c` | `monorepo-whitebox` | white-box / `--no-llm`, 300 s cap, `KOVO_RECON_SIBLINGS=1` | FAIL | `investigation` | **wiring FAIL**: stored 62 / declared 2,565 (< 2,500); p99 1.06 ms (pass); sibling derivation suppressed true (pass); Tier A 4-hop sinks 3/3 (pass); **capability FAIL**: SAST suspects 0, 4-hop 0/3, chain 0/2; TP 0 / FP 0; 62 endpoints; 571 engine requests, 2 rejected / 1 lead | `realism-gate-4-final` (local out-dir) |
| 2026-11-23 | `5f0aea8` | `wan-oob` | grey-box / `--no-llm`, 300 s cap, default callback delays, merged main | FAIL | `investigation` | **wiring FAIL**: pending_oob registered 0; drain n/a; approvals 0 blocking / 176 auto-review rows; denied mutations 0; 33 endpoints; p99 1.37 ms; **capability FAIL**: blind SQLi / async SSRF / async XXE not confirmed, async FN 100%; fixture callbacks `sqli` only; TP 0 / FP 0; 467 engine requests | `realism-merged-2` (local out-dir) |
| 2026-11-23 | `5f0aea8` | `staging-concurrency` | grey-box / `--no-llm`, 180 s cap, `staging_isolated`, HTTP/2 enabled, merged main | FAIL | `investigation` | **wiring FAIL**: approvals 0 blocking; **denied mutations 15 (all `staging_contract`)**; parked 0; leaked 0; h2 single-packet bursts 0 / fallback 0; 18 endpoints; p99 0.97 ms; **capability FAIL**: write-BOLA / race / checkout not confirmed; TP 0 / FP 0; 396 engine requests | `realism-merged-3` (local out-dir) |
| 2026-11-23 | `5f0aea8` | `monorepo-whitebox` | white-box / `--no-llm`, 300 s cap, `KOVO_RECON_SIBLINGS=1`, merged main | FAIL | `investigation` | **wiring PASS**: declared 2,565 / spec ops 2,565 / matched 2,565; persisted 5,130 rows (2,568 distinct); retrieved 5,130; truncated no; p99 0.39 ms; sibling suppression true; Tier A 4-hop 3/3; code leads 4 (3 four-hop); probe plan Tier A 3, subset 1,444/2,563. **capability FAIL**: SAST suspects 0, 4-hop 0/3, chain 0/2; TP 0 / FP 0; 5,130 endpoints; 373 engine requests | `realism-merged-4` (local out-dir) |
| 2026-11-24 | `42ff918` | `wan-oob` | grey-box / `--no-llm` | FAIL | `gate_incomplete` | **split gates**: `oob_wiring_fnr` **0.0% PASS** (0/2 fired async canary targets unconfirmed; basis `fired_canaries`; SSRF 14 minted/1 fired, XXE 15 minted/3 fired); `fixture_capability_recall` **50.0% FAIL** (2/4 — missing blind SQLi and the exfil chain); legacy blended async FNR 33.3% informational only. **wiring PASS**: 29 pending_oob registered, 45 s drain, 4 late promotions. TP 2 / FP 0 / precision 100%; 34 endpoints; 393 broker exchanges; 166 s | `/tmp/realism-gates-wan-final` |
| 2026-11-24 | `42ff918` | `staging-concurrency` | grey-box / `--no-llm`, `staging_isolated` | **PASS** | `passed` | **wiring PASS**; **capability PASS**: write-BOLA / HTTP/2 double-spend (2 single-packet bursts, 0 HTTP/1.1 fallback) / checkout tampering confirmed; 0 leaked `kovo-qa-` entities; chain 1/2 informational. TP 3 / FP 0 / precision 100%; 51 endpoints; 276 broker exchanges; 108 s | `/tmp/realism-gates-staging` |
| 2026-11-24 | `42ff918` | `monorepo-whitebox` | white-box / `--no-llm` | FAIL | `investigation` | **wiring PASS** (declared 2,565 / matched 2,565; persisted 5,130 rows / 2,568 distinct; Tier A 4-hop 3/3; code leads 4 with 3 four-hop). **capability FAIL**: TP 0 / FP 0; 0 vulnerability findings; 5,130 endpoints; 373 engine requests. **#4 funnel**: billing 0 dispatched / 0 route hit / 0 verify; reports 0/0/0; admin 1/1/0 — confirmations lost before verification, not at brief truncation | `/tmp/realism-gates-mono-final` |

Smoke rows (`91a4be1`) are harness-validation runs, not gate evidence: the WAN smoke row uses a
shortened callback delay and the monorepo smoke row uses a shortened wall-clock cap. The
`b62401c` rows are the pre-merge wiring baseline; the `5f0aea8` rows are the merged-tree
measurement. The `5f0aea8` #4 row is the useful shape: wiring PASS with capability FAIL.
