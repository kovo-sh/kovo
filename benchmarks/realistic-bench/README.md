# realistic-bench

An offline, loopback-only benchmark for measuring a defensive scanner's **High/Critical recall and
precision** against realistic, multi-tenant web applications — a more faithful alternative to
single-bug CTF suites like XBOW/XBEN. Built to score Guardian, but scanner-agnostic.

Everything runs on `127.0.0.1` behind `GUARDIAN_ALLOW_LOCAL_LAB=1`; all data is synthetic and every
dangerous sink (SSRF, XXE, path traversal, command execution, SSTI) is a safe, instrumented
stand-in. No real network, filesystem, or shell is ever touched.

## Why this is more realistic than XBOW/XBEN

| | XBOW/XBEN style | realistic-bench |
|---|---|---|
| Target | ~100 tiny single-bug apps | 3 full multi-tenant apps, 55–90 routes each, SPA + personas + webhooks |
| Bugs | 1 per app, often hinted by route/name | 24–28 planted bugs per app, unevenly spread, incl. second-order and chained |
| Decoys | none | 6–8 **hard decoys** per seed: code that looks exploitable but isn't; graded as strictly as bugs |
| Grading | capture a `FLAG{}` string | **impact oracle** — a finding counts only if a side-channel saw the real impact (cross-tenant row read, tainted sink reached, privilege changed) |
| Contamination | static, public | **per-seed variants** randomize routes, param names, id formats, and which sites are vulnerable; a **held-out** seed set keyed by an uncommitted salt resists overfitting |
| Metrics | % solved | recall by severity/class, **precision (decoy FP rate)**, chain completion, funnel, failure taxonomy, **budget curves ($1/$5/$20)** |
| Friction | minimal | real login + sessions + CSRF, bearer/JWT, rate limits, pagination, opaque ids, SPA route discovery |

## Layout

```
lib/          generic runtime + impact sinks (router, sqlite+SQLi sink, canary/SSRF/XXE/SSTI/
              traversal/command/JWT/webhook detectors, virtual FS, seeded PRNG) — materialized into each app
generator/    seeded variants (dev vs held-out), blueprint validation, ground truth, contamination-safe materialization
grader/       finding↔truth matching, oracle attribution, funnel, budget curves, scorecard + Markdown
apps/<app>/   src/ (neutral, materialized app code) · ui/ (SPA) · sites/<id>/ (spec + vulnerable/hardened twins + solver) ·
              truth/ (blueprint, monitors, catalog, selftest) — truth/ and solvers are never materialized
run.ts        CLI + programmatic API
tests/        node:test self-tests (lib detectors, grader, generator, per-app matrices, soundness, e2e grading, safety)
```

Three apps: **acme-saas** (B2B SaaS — 28 sites), **shopflow** (e-commerce/payments — 26 sites,
emphasis on workflow bypass, races, XXE, webhook forgery), **opsportal** (internal ops tool — 24
sites, emphasis on GraphQL nested BOLA, SSTI, second-order XSS/SSRF, cache poisoning, jailed
traversal, simulated command injection).

## Quick start

```sh
export GUARDIAN_ALLOW_LOCAL_LAB=1

# Boot a lab instance (prints a per-mode briefing; writes ground truth + oracle/request logs to --out-dir on Ctrl-C)
node benchmarks/realistic-bench/run.ts serve --app acme-saas --seed 3 --mode grey-box

# Run the built-in site self-test matrix (every vulnerable twin fires; every hard decoy stays silent)
node benchmarks/realistic-bench/run.ts selftest --app all --seeds 1,2,3

# Grade a scanner's output
node benchmarks/realistic-bench/run.ts grade --truth gt.json --findings f.json \
  --events ev.json --requests req.json --telemetry tel.json --md scorecard.md

# List reproducible seeds (held-out needs GUARDIAN_RB_HELDOUT_SALT, >=16 chars)
node benchmarks/realistic-bench/run.ts seeds --set dev --n 5
```

Typecheck: `node_modules/.bin/tsc -p benchmarks/realistic-bench/tsconfig.json`
Tests: `GUARDIAN_ALLOW_LOCAL_LAB=1 node --test --test-concurrency=1 benchmarks/realistic-bench/tests/`

## Modes

`briefingFor(app, mode)` controls what the scanner under test may see:
- **black-box** — origin + `persona_a`/`persona_b` credentials only.
- **grey-box** — all four personas + an API reference (method/path/params of every route; no site info).
- **white-box** — additionally the materialized source tree (`app.sourceDir`), which contains **no**
  truth/solver/decoy markers (leakage-scanned at materialization).

## Seeds (dev vs held-out)

- **dev** seeds (`1..9999`): freely reproducible; use for development and recall hill-climbing.
- **held-out** seeds (`>= 1_000_000`): the plan is keyed by HMAC over `GUARDIAN_RB_HELDOUT_SALT`
  (never committed). Without the salt they are refused and their numbers aren't derivable from the
  repo — use them for the anti-overfitting generalization check.

Each seed randomizes api prefix, route nouns, param names, id format (`int`/`uuid`/`prefixed`/`hashid`),
persona credentials, canary salt, and which sites are vulnerable vs hardened (decoy count in
`[min,max]`; chain members share a mode; keystone sites are never decoys).

## Grading (summary)

A finding is **confirmed** only when it matches a planted vuln (by endpoint + class/CWE family) **and**
the impact oracle recorded an attributed event with `ts <= submittedAtMs`. A finding matching a decoy
is a false positive regardless of how confident it is; a finding matching nothing is an unmatched FP.
`precision = TP / (TP + decoyFP + unmatchedFP)`. The scorecard also reports recall by severity/class,
chain completion, the 6-stage monotonic funnel, the 11-bucket failure taxonomy, budget curves at
$1/$5/$20, and blocked-egress counts. See `CONTRACTS.md` for the exact rules.

## Impact oracle

Impact is detected **generically** (not via per-site flags), so app source carries no tells:
- cross-tenant reads via tenant **canary** tokens seeded into records; DB mutations judged against an
  authorization policy via runtime audit triggers; SQLi via structural tokenization of raw SQL;
  SSRF/XXE/traversal/command/SSTI/JWT/webhook/cache/redirect each via their instrumented `lib/` sink.
- The oracle, its logs, and the ground truth live **outside** the app's HTTP surface and are never fed
  to the scanner under test. On a clean (hardened) app, benign traffic produces **zero** events
  (`tests/soundness.test.ts`).

## Safety guarantees

Enforced by `tests/safety.test.ts` over the whole tree: no `child_process`/`eval`/`new Function`/`vm`;
sockets bind `127.0.0.1` only; outbound requests go through `lib/egress.ts` (loopback + registered
ports only); file access for app features goes through the in-memory `lib/vfs.ts`; command execution
is a pure simulator (`lib/simshell.ts`); `node:fs` is confined to the jailed static server and
build-time tooling; secrets are synthetic (`rb_fake_*`, `rbs_*`). Nothing starts without
`GUARDIAN_ALLOW_LOCAL_LAB=1`.

## Integrating a scanner (e.g. Guardian)

```ts
import { startRealisticApp, briefingFor, gradeRun, renderScorecard } from './run.ts'

const app = await startRealisticApp({ app: 'acme-saas', seed: 3 })
const briefing = briefingFor(app, 'grey-box')   // hand this to the scanner
// ... run the scanner against app.origin, collecting its findings ...
const scorecard = gradeRun({
  groundTruth: app.groundTruth,
  findings,                       // adapter: map scanner findings -> SubmittedFinding (lib/types.ts)
  oracleEvents: app.oracle.events(),
  requestLog: app.oracle.requests(),
  egressLog: app.oracle.egress(),
  telemetry: { startedAtMs, endedAtMs, totalCostUsd },
  mode: 'grey-box',
})
console.log(renderScorecard(scorecard, 'md'))
await app.stop()
```

Map the scanner's verified/static statuses onto `SubmittedFinding.status`
(`runtime_confirmed`/`confirmed` count toward recall; `static_verified` counts only toward the
white-box `staticRecall`).

## Adding a site or an app

- **Site:** add `apps/<app>/sites/<id>/{spec.ts,vulnerable.ts,hardened.ts,solver.ts}` (twins export the
  same `register(app)` and must be free of leakage markers), add its id to the app's implemented set,
  and verify both twins with the app's self-test matrix. `(oracle.kind, routeKey)` pairs and entry
  routeKeys must be unique across sites (enforced by `validateBlueprint`).
- **App:** default-export an `AppModule` from `apps/<app>/index.ts` (see the three apps), add it to
  `lib/types.ts` `appNames`, and provide `truth/blueprint.ts` + `truth/monitors.ts` + a selftest.
