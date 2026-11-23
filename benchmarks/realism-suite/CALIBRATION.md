# Realism exit-gate calibration

This document defines how the four `benchmarks/realism-suite` fixtures become measured
**exit gates** for the product pipeline. Every number is produced by the real
`Execution` orchestrator (`scripts/benchmark-realism.ts`) and graded offline against
`benchmarks/realism-suite/fixtures/<fixture>/truth.json`. The harness never imports or
serves `truth.json` to `Execution`.

> Defensive QA context: the fixtures are loopback-only authorized lab targets. They
> measure whether Guardian's discovery, auth, replay and evidence pipeline works under
> realistic enterprise, WAN, staging and monorepo conditions — not an attack tool.

## Safety and evidence rules

- `GUARDIAN_ALLOW_LOCAL_LAB=1` is mandatory; fixtures bind only `127.0.0.1:0`.
- Fixture credentials are synthetic and per-run. Artifacts are written `0600` in a `0700`
  directory and scanned for known fixture secrets, `GUARDIAN_RB_HELDOUT_SALT` when set,
  private keys, provider keys, JWTs and AWS-shaped keys. A dirty scan exits `4`.
- `--no-llm` is the deterministic floor. It never inherits a model-enabled data dir.
- Agentic runs need an enabled model profile (`--data-dir` / `GUARDIAN_DATA_DIR`) **and**
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
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
  --fixture enterprise-spa --no-llm --out-dir .guardian/realism-gate

# Agentic lane per fixture (needs a model profile + Docker worker sessions)
GUARDIAN_ALLOW_LOCAL_LAB=1 GUARDIAN_DATA_DIR=/path/to/guardian-data \
  newgrp docker -c 'npm run benchmark:realism -- --fixture enterprise-spa --verifier docker \
    --mode grey-box --out-dir .guardian/realism-gate-agentic'

# CI form: fail the build when a required gate criterion is not met
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
  --fixture all --no-llm --fail-on-gate --out-dir .guardian/realism-gate

# Cross-check the persisted findings with the suite's own grader
GUARDIAN_ALLOW_LOCAL_LAB=1 node benchmarks/realism-suite/run.ts grade \
  --fixture enterprise-spa --findings .guardian/realism-gate/enterprise-spa-grey-box-no-llm.findings.json
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
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- --fixture enterprise-spa --no-llm
```

## Gate #2 — WAN + async OOB (`wan-oob`)

Gate: **blind SQLi confirmed**, **async SSRF confirmed**, **async XXE confirmed**, and
**async false-negative rate < 5%**, with chain `wan-oob-exfil` complete.

| Measurement | Definition | `--no-llm` result | agentic result |
| --- | --- | --- | --- |
| Blind SQLi | TP for `wan-blind-sqli` | — | — |
| Async SSRF | TP for `wan-ssrf-async` | — | — |
| Async XXE | TP for `wan-xxe-async` | — | — |
| Async false-negative rate | missed `{wan-blind-sqli, wan-ssrf-async, wan-xxe-async}` / 3 | — | — |
| Fixture callback evidence | fixture-side collector observed `sqli` / `ssrf` / `xxe` / `webhook` after the HTTP response | — | — |
| Chain completion | `wan-oob-exfil` covered/total | — | — |
| Grade | TP / FP / precision / recall | — | — |

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- --fixture wan-oob --no-llm
```

Flag: `--callback-delay-ms` exists for smoke runs only; the default `15000,30000` is the gate configuration.

## Gate #3 — staging safety (`staging-concurrency`)

Gate: **write-BOLA confirmed**, **HTTP/2 race confirmed**, **checkout price tampering
confirmed**, and **zero leaked `guardian-qa-` entities after cleanup**. Chain
`stg-tenant-takeover` is reported informationally (the explicit staging gate above is
authoritative).

The harness runs the fixture in `staging_isolated`, then after `Execution` stops calls the
fixture's `cleanup(runId)` and re-reads `orphans()` before fixture teardown. Zero orphans is
only meaningful alongside the three positive criteria: a run that performs no tagged
mutations reports `0 leaked` but still fails the write/race/checkout gate.

| Measurement | Definition | `--no-llm` result | agentic result |
| --- | --- | --- | --- |
| Write-BOLA | TP for `stg-write-bola` | — | — |
| HTTP/2 race | TP for `stg-race-double-spend` | — | — |
| Checkout tampering | TP for `stg-price-tampering` | — | — |
| Leaked entities | `fixture.orphans()` length after `cleanup(runId)` (prefix `guardian-qa-`) | — | — |
| Cleanup effect | records removed / tenant mutations restored | — | — |
| Grade | TP / FP / precision / recall | — | — |

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- --fixture staging-concurrency --no-llm
```

## Gate #4 — monorepo white-box (`monorepo-whitebox`)

Gate: **SAST-suspect → live-endpoint link ≥ 85%**, **2,500-route scale without endpoint
truncation**, **at least two 4-hop sinks confirmed**, and chain `mono-tenant-takeover`
complete. Run with `--mode white-box` so the preserved `.git` tree is mounted read-only.

| Measurement | Definition | `--no-llm` result | agentic result |
| --- | --- | --- | --- |
| SAST link rate | findings with `codeLocations` that also carry a concrete live endpoint / all findings with `codeLocations` | — | — |
| Route scale | persisted endpoints vs retrieved endpoints vs declared routes; **truncated** when retrieved < persisted; gate requires declared ≥ 2,500 **and** persisted ≥ 2,500 | — | — |
| 4-hop confirmations | TP count among `{mono-billing-bola, mono-report-sqli, mono-admin-bfla}` (0–3) | — | — |
| Chain completion | `mono-tenant-takeover` covered/total | — | — |
| Grade | TP / FP / precision / recall | — | — |

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realism -- \
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

Smoke rows are harness-validation runs, not gate evidence: the WAN row uses a shortened
callback delay and the monorepo row uses a shortened wall-clock cap. The #1 and #3 rows use
the gate configuration (`--no-llm`, grey-box, 180 s cap, default WAN settings where applicable).
