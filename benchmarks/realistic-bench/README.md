# realistic-bench

An offline, loopback-only benchmark for measuring a defensive scanner's **High/Critical recall and
precision** against realistic, multi-tenant web applications — a more faithful alternative to
single-bug CTF suites like XBOW/XBEN. Built to score Kovo Hunter, but scanner-agnostic.

Everything runs on `127.0.0.1` behind `KOVO_ALLOW_LOCAL_LAB=1`; all data is synthetic and every
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
tests/        node:test self-tests (lib detectors, grader + grader-soundness, generator, held-out
              integrity, decoy audit, per-app matrices, soundness matrix, e2e grading, safety)
```

Three apps: **acme-saas** (B2B SaaS — 28 sites), **shopflow** (e-commerce/payments — 26 sites,
emphasis on workflow bypass, races, XXE, webhook forgery), **opsportal** (internal ops tool — 24
sites, emphasis on GraphQL nested BOLA, SSTI, second-order XSS/SSRF, cache poisoning, jailed
traversal, simulated command injection).

## Quick start

```sh
export KOVO_ALLOW_LOCAL_LAB=1

# Boot a lab instance (prints a per-mode briefing; writes ground truth + oracle/request logs to --out-dir on Ctrl-C)
node benchmarks/realistic-bench/run.ts serve --app acme-saas --seed 3 --mode grey-box

# Run the built-in site self-test matrix (every vulnerable twin fires; every hard decoy stays silent)
node benchmarks/realistic-bench/run.ts selftest --app all --seeds 1,2,3

# Grade a scanner's output
node benchmarks/realistic-bench/run.ts grade --truth gt.json --findings f.json \
  --events ev.json --requests req.json --telemetry tel.json --md scorecard.md

# List reproducible seeds (held-out needs KOVO_RB_HELDOUT_SALT, >=16 chars)
node benchmarks/realistic-bench/run.ts seeds --set dev --n 5
```

Typecheck: `node_modules/.bin/tsc -p benchmarks/realistic-bench/tsconfig.json`
Tests: `KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/realistic-bench/tests/` (142 tests)

## Scoring commands (dev and held-out)

Run from the repo root. Everything is loopback-only and refuses to start unless
`KOVO_ALLOW_LOCAL_LAB=1` is set.

```sh
export KOVO_ALLOW_LOCAL_LAB=1

# Dev seed: reproducible, no salt. --split dev rejects seeds >= 1_000_000.
node benchmarks/realistic-bench/benchmark-realistic.ts \
  --app acme-saas --seed 1 --split dev \
  --profile-mode v4-full --mode grey-box --verifier auto \
  --out-json benchmarks/realistic-bench/out/dev-acme-1.score.json \
  --out-md   benchmarks/realistic-bench/out/dev-acme-1.score.md \
  --out-findings benchmarks/realistic-bench/out/dev-acme-1.findings.json

# Held-out seed: the salt comes from the environment only (>=16 chars, never committed).
# --split heldout rejects seeds < 1_000_000 and refuses to run without the salt.
KOVO_ALLOW_LOCAL_LAB=1 KOVO_RB_HELDOUT_SALT="$KOVO_RB_HELDOUT_SALT" \
  node benchmarks/realistic-bench/benchmark-realistic.ts \
  --app acme-saas --seed 1000001 --split heldout \
  --profile-mode v4-full --mode grey-box --verifier auto \
  --out-json benchmarks/realistic-bench/out/heldout-acme-1000001.score.json \
  --out-md   benchmarks/realistic-bench/out/heldout-acme-1000001.score.md

# Full dev sweep (all apps, seeds 1-3). Stop on the first failure.
for app in acme-saas shopflow opsportal; do
  for seed in 1 2 3; do
    node benchmarks/realistic-bench/benchmark-realistic.ts \
      --app "$app" --seed "$seed" --split dev \
      --out-json "benchmarks/realistic-bench/out/dev-$app-$seed.score.json" || exit 1
  done
done
```

The same scorecard can be produced from externally captured artifacts with
`node benchmarks/realistic-bench/run.ts grade --truth gt.json --findings f.json --events ev.json
--requests req.json --telemetry tel.json --md scorecard.md`.

## Parallel agentic matrix (real `Execution` harness)

`scripts/benchmark-realistic.ts` drives Kovo Hunter's real `Execution` loop. A parallel
agentic matrix must not share one Kovo Hunter data dir (the second Store would fail with
`Another Kovo Hunter server is using this data directory`). With `--concurrency > 1`,
per-cell isolation is on by default:

```sh
# Run from the repo root. The key stays in the source data dir; only profile metadata
# is copied and credentials/ is symlinked into each cell.
KOVO_ALLOW_LOCAL_LAB=1 KOVO_DATA_DIR=<kovo-data-dir> \
newgrp docker -c 'cd <repo> && node scripts/benchmark-realistic.ts \
  --app all --seeds 1 --mode grey-box --verifier docker \
  --concurrency 3 --isolate-data-dir --budget-usd 3 \
  --out-dir /tmp/rb-agentic-matrix'
```

Each cell creates `<out-dir>/data/<app>-seed<seed>-<mode>/`, initializes a fresh Kovo Hunter
Store, copies only the enabled `model_profiles` rows (+ workspace identity), and symlinks
`credentials/` to the source data dir. The key is never copied into the out-dir. Isolated
dirs are removed after grading unless `--keep-data-dirs` is passed; `--isolate-data-dir`
can also be forced for a single cell.

**Current engine gap (do not misread as a benchmark bug):** as of repo `c345f46` / engine
`ca992f6`, the full Kovo Hunter pipeline confirmed **0 vulnerabilities on every dev seed tried**
(acme 0/22, 0/22, 0/20; shopflow 0/18, 0/19, 0/20; opsportal 0/16, 0/18, 0/17 for seeds
42/1/2). Precision was 100% on shopflow, 0% on acme/opsportal (a few unmatched findings).
The gap is engine-side (recon stops at the SPA shell; query/body-driven classes are never
probed; some authz signals bind sibling/self-service routes). See `ADAPTER.md` for the
per-finding attribution diagnosis. Treat the recall columns as an engine TODO, not as evidence
that the planted sites are unreachable — `run.ts selftest` proves every site is exploitable
when vulnerable and silent when hardened.

## Held-out salt rule

- Held-out seeds (`>= 1_000_000`) are derived with `HMAC-SHA256(KOVO_RB_HELDOUT_SALT, ...)`;
  the same seed with a different salt produces a different plan. The salt lives only in the
  environment (or an explicit `{ salt }` argument in tests) and must be **>= 16 characters**.
- Never commit the salt, echo it into logs, pass it on a command line, or write it next to results.
  The materialized `variant.json` contains only `app`, `apiPrefix`, `routes`, `params` and
  `idFormat`; it never contains the salt, the seed set, personas or site modes. Briefings omit
  the salt and all site/truth fields, and ground truth is never mounted into the app tree.
- Rotate the salt if it is ever exposed. Tests use a clearly fake fixed salt; that value is not
  a usable held-out key.


## Modes

`briefingFor(app, mode)` controls what the scanner under test may see:
- **black-box** — origin + `persona_a`/`persona_b` credentials only.
- **grey-box** — all four personas + an API reference (method/path/params of every route; no site info).
- **white-box** — additionally the materialized source tree (`app.sourceDir`), which contains **no**
  truth/solver/decoy markers (leakage-scanned at materialization).

## Seeds (dev vs held-out)

- **dev** seeds (`1..9999`): freely reproducible; use for development and recall hill-climbing.
- **held-out** seeds (`>= 1_000_000`): the plan is keyed by HMAC over `KOVO_RB_HELDOUT_SALT`
  (never committed). Without the salt they are refused and their numbers aren't derivable from the
  repo — use them for the anti-overfitting generalization check. See "Held-out salt rule" above for
  artifact and rotation requirements.

Each seed randomizes api prefix, route nouns, param names, id format (`int`/`uuid`/`prefixed`/`hashid`),
persona credentials, canary salt, and which sites are vulnerable vs hardened (decoy count in
`[min,max]`; chain members share a mode; keystone sites are never decoys).

## Grading (summary)

A finding is **confirmed** only when it matches a planted vuln (by endpoint + class/CWE family) **and**
the impact oracle recorded an attributed event whose kind **and** routeKey both belong to that site,
with `ts <= submittedAtMs`. A finding matching a decoy is a false positive regardless of how
confident it is; a finding matching nothing is an unmatched FP. `precision = TP / (TP + decoyFP +
unmatchedFP)`.

Accounting details worth knowing before comparing runs:
- `decoyFalsePositives` counts **decoy sites with at least one active claim**, not claims, so a
  duplicate pile on one decoy costs one FP. A multi-endpoint finding is credited to at most one
  vulnerable site but is charged for **every** decoy site it names, so bundling cannot hide decoy
  claims behind a real finding. `duplicateFindings` counts extra claims on a *vulnerable* site.
- Claims on a vulnerable site that lack oracle impact are `claimed_without_impact`; they are
  reported per vuln and counted in the funnel/failure taxonomy, but are **not** in the precision
  denominator. Precision here is "confirmed-site precision", not "finding precision" — do not read
  100% as "no false claims on vulnerable routes".
- `chainsTotal` includes only chains whose members are all vulnerable. A chain unit selected as a
  decoy is fully hardened and is not an unachievable scoring target.

The scorecard also reports recall by severity/class, chain completion, the 6-stage monotonic funnel,
the 11-bucket failure taxonomy, budget curves at $1/$5/$20, and blocked-egress counts. See
`CONTRACTS.md` for the exact rules.

## Decoy audit

`tests/decoy-audit.test.ts` treats decoys as an adversarial control, not just a count:
- every twin pair is non-trivial and size-comparable (no stub/one-line tell), and neither twin
  contains its site id, lure, solver marker or classification marker;
- across seeds 1–30, decoy counts stay in range, keystone sites are never hardened, chain units never
  split modes, and every selectable site is chosen as a decoy at least once;
- benign per-persona browsing plus each decoy's own exploit solver produce **zero** oracle events on
  decoy routes (seeds 1–3);
- open-redirect decoys are probed with absolute, protocol-relative and origin-relative backslash
  targets; hardened twins must stay same-origin and silent, while vulnerable twins must redirect
  off-origin **and** be attributed by the oracle;
- materialized trees are scanned for site ids, lures, mode strings and hidden plan fields, and each
  planted file is byte-compared with the chosen twin.

The redirect probes caught a real weak-decoy class: `startsWith('//')` guards alone let `/\host`
targets through (browsers fold `\` to `/`), and `offOrigin()` previously treated them as local.
`lib/http-util.ts` now resolves targets with browser semantics, and the affected hardened twins
reject backslashes/whitespace/scheme-like local paths.


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
`KOVO_ALLOW_LOCAL_LAB=1`.

## Integrating a scanner (e.g. Kovo Hunter)

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
