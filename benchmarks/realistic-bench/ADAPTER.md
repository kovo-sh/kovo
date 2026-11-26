# Kovo Hunter integration adapter (`realistic-bench`)

Pane 3's contract (`run.ts`) owns materialization, the impact oracle and grading, but it stops
at "what the scanner may see" (`briefingFor`). Kovo Hunter's engines need more: authenticated
personas, a benchmark-server handle for `EngineEnv`, and finding objects in the grader schema.
This adapter is that missing layer.

All code here is benchmark scope: nothing under `src/` or `scripts/` was modified.

## Files

| File | Purpose |
| --- | --- |
| `kovo-adapter.ts` | `runKovoAgainstMaterialized()` — discovery → hypotheses → probes → replay-spec synthesis → Zero-LLM verification, emitted as `SubmittedFinding[]` + `RunTelemetry`. Also `startOobCanaryBroker()`, `readMaterializedSurface()`, `loadKovoEngine()`, and a manifest-mode `runKovoLivePipelineAgainstMaterialized()`. |
| `kovo-login.ts` | Derives the login route from `variant.json` routes and exchanges briefing email/password for cookie/bearer credentials per persona. |
| `benchmark-realistic.ts` | Thin CLI: materialize → run Kovo Hunter → `gradeRun()` → recall/precision by class + decoy FP count. |

The engine itself is imported from the repo (never copied): `scripts/benchmark-env.ts`
(`createEngineEnv`, `discoverEndpoints`), `scripts/benchmark-probes.ts`
(`profileCaps`, `formHypotheses`, `runHypothesis`), `scripts/benchmark-specs.ts`
(`synthesizeSpec`), `scripts/benchmark-backend.ts` (`selectVerifierBackend`),
`src/server/replay-verifier.ts` (`verifyReplaySpec`/`verifyReplaySpecInline`) and
`scripts/benchmark-live.ts` (`runLivePipeline`). Imports use non-literal dynamic specifiers so
this `tsconfig.json` does not have to typecheck `scripts/` + `src/`.

## API

```ts
import { runKovoAgainstMaterialized } from './kovo-adapter.ts'

const run = await runKovoAgainstMaterialized({
  treeDir: started.sourceDir,        // materialized src/ (contains variant.json)
  seed: 42,
  app: 'acme-saas',
  profileMode: 'v4-full',            // or 'v3-baseline' | 'full' | 'baseline'
  verifierBackend: 'auto',           // 'auto' | 'docker' | 'local-jq'
  benchMode: 'grey-box',             // black-box | grey-box | white-box (default grey-box)
  started,                           // optional: reuse an app the caller already started
  oobCanary,                         // optional: broker started before `started` (see below)
  // emitUnconfirmedFindings: false  // default: only confirmed/static-verified findings
})

run.findings      // SubmittedFinding[] — grader/schema.ts shape; validateFindings() clean
run.telemetry     // RunTelemetry for gradeRun()
run.notes         // login/discovery/verification notes
run.surface       // routes/params read from variant.json
run.verifierBackend, endpointsDiscovered, hypothesesFormed, signalsObserved,
run.proofGaps, duplicateSignals
```

Behavior:

- `assertLocalLabAllowed()` runs before anything else (also inside `startRealisticApp`).
- `treeDir` must be the **same** directory as the started app's `sourceDir` (realpath check), so
  the surface we read and the origin we probe cannot diverge.
- The only inputs are `variant.json` (routes/params/apiPrefix/idFormat), the briefing
  (origin, personas, optional `apiReference`) and the app's HTTP responses. `groundTruth` and
  `plan.sites` are not part of the adapter's started-app type, so truth is not reachable.
- Discovery = real Phase-0 recon, then merged with `variant.json` routes that recon missed
  (path params only). Class/impact evidence comes from the probes + verifier, never from a
  manifest.
- Findings are deduped by `path|param|cwe`; a submitted TP requires verifier verdict
  `confirmed`, matching the grader's "confirmed" rule. `static_verified` is counted as a proof
  gap: it has no `codeLocation` here, so the grader would otherwise score it as an unmatched FP.
- Out-of-band SSRF/XXE wiring: the app's contained egress permits loopback HTTP only to the
  internal mock services plus the exact `oobCallbackPorts` it was started with. The CLI therefore
  calls `startOobCanaryBroker()` **before** `startRealisticApp()`, passes that loopback port to the
  app, and forwards the same broker as `oobCanary`; `createEngineEnv` reuses it (instead of minting
  a second listener) so probes, replay verification and the app all agree on one callback port.
  When the adapter starts the app itself it performs the same ordering. Only the registered port
  is reachable; every other loopback port remains `port_blocked`.
- Login: prefers a non-legacy `POST` route whose key/path contains `login|signin|session`, tries
  JSON → form → JSON+tenant, and accepts either a `Set-Cookie` session or a bearer token field.
  All non-deletion cookies are kept (labs use prefixed names like `acme_sid`, not just `sid`).
  Failures become notes, not exceptions (partial personas still allow anonymous probing).

### Manifest mode (diagnostic only)

`runKovoLivePipelineAgainstMaterialized({ started, treeDir, manifest, ... })` wraps
`runLivePipeline` with the shared launcher contract
(`{ origin, port, personas: {cookie|token}, close }`). It exists for parity/diagnostic runs where
a caller already owns a manifest; the truth-free path above never uses it.

## CLI

```bash
cd <repo-root>            # repo root
export KOVO_ALLOW_LOCAL_LAB=1

node benchmarks/realistic-bench/benchmark-realistic.ts \
  --app acme-saas --seed 42 --split dev \
  --profile-mode v4-full --mode grey-box --verifier auto \
  --out-json benchmarks/realistic-bench/out/acme-42.score.json \
  --out-md   benchmarks/realistic-bench/out/acme-42.score.md \
  --out-findings benchmarks/realistic-bench/out/acme-42.findings.json
```

Flags: `--app` (acme-saas|shopflow|opsportal), `--seed`, `--split dev|heldout`,
`--profile-mode v4-full|v3-baseline`, `--mode black-box|grey-box|white-box`,
`--verifier auto|docker|local-jq`, `--out-json`, `--out-md`, `--out-findings`.
Output is the scorecard plus this summary:

```
recall      3/20 (15.0%)
precision   100.0%  (tp=3 decoyFP=0 unmatchedFP=0)
decoys      0/6 false positives
funnel      surface 12/20 -> hypotheses 34 -> signal 5 -> spec 5 -> confirmed 3
engine      34 hypotheses, 5 signals, 2 proof gaps, verifier=local-jq
by vuln class:
  bola                 1/3 (33.3%)
  sqli                 2/2 (100.0%)
```

## Commands once the apps land

Dev seed (reproducible, no salt):

```bash
cd <repo-root>
KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/realistic-bench/benchmark-realistic.ts \
  --app acme-saas --seed 42 --split dev --profile-mode v4-full --mode grey-box \
  --out-json benchmarks/realistic-bench/out/dev-acme-42.score.json \
  --out-md benchmarks/realistic-bench/out/dev-acme-42.score.md
```

Held-out seed (salt never committed; `>= 16` chars):

```bash
cd <repo-root>
KOVO_ALLOW_LOCAL_LAB=1 KOVO_RB_HELDOUT_SALT="$KOVO_RB_HELDOUT_SALT" \
  node benchmarks/realistic-bench/benchmark-realistic.ts \
  --app acme-saas --seed 1000042 --split heldout --profile-mode v4-full --mode grey-box \
  --out-json benchmarks/realistic-bench/out/heldout-acme-1000042.score.json \
  --out-md benchmarks/realistic-bench/out/heldout-acme-1000042.score.md
```

All three apps, dev seed sweep:

```bash
for app in acme-saas shopflow opsportal; do
  for seed in 1 2 3; do
    KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/realistic-bench/benchmark-realistic.ts \
      --app "$app" --seed "$seed" --split dev \
      --out-json "benchmarks/realistic-bench/out/dev-$app-$seed.score.json" || exit 1
  done
done
```

## Validation

```bash
KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/realistic-bench/tests/
node_modules/.bin/tsc -p benchmarks/realistic-bench/tsconfig.json
```

Adapter tests cover: grader-schema validity, CWE→vulnClass mapping, dedupe, telemetry,
`KOVO_ALLOW_LOCAL_LAB` refusal, treeDir/sourceDir mismatch refusal, cookie+form+bearer login,
loopback-only login, and — via throwing getters — that `groundTruth`/`plan.sites` are never read.

## Baseline after merging engine `ca992f6` (native, no shims)

Apps snapshot synced read-only at 2026-11-21 23:28 PT; Kovo Hunter engine at `ca992f6`
(23/25 xben-25, 0 FP). Adapter now consumes `synthesizeSpecs` (multiple specs per signal).
Nine runs, `KOVO_ALLOW_LOCAL_LAB=1`, `v4-full`, grey-box:

| app | seed | recall | precision | decoy FP | unmatched FP | findings | runtime |
| --- | --- | --- | --- | --- | --- | --- | --- |
| acme-saas | 42 | 0/22 | 0.0% | 0/6 | 1 | 1 | 75s |
| acme-saas | 1 | 0/22 | 0.0% | 0/6 | 1 | 1 | 76s |
| acme-saas | 2 | 0/20 | 0.0% | 0/8 | 1 | 1 | 76s |
| shopflow | 42 | 0/18 | 100.0% | 0/8 | 0 | 0 | 102s |
| shopflow | 1 | 0/19 | 100.0% | 0/7 | 0 | 0 | 97s |
| shopflow | 2 | 0/20 | 100.0% | 0/6 | 0 | 0 | 97s |
| opsportal | 42 | 0/16 | 0.0% | 0/8 | 3 | 3 | 90s |
| opsportal | 1 | 0/18 | 0.0% | 0/6 | 3 | 3 | 91s |
| opsportal | 2 | 0/17 | 0.0% | 0/7 | 3 | 3 | 93s |

Per-class recall remains 0/N for every class/app/seed. Decoy FPs dropped from 1/8 and 1/6
(pre-merge opsportal) to **0 everywhere**.

### Attribution diagnosis (why findings do not match)

Every finding was checked against ground truth with `matchFindingToEntries` plus a
path-shape comparison. **No trailing-slash/query/param-name normalization mismatch exists**:

| finding | engine evidence | nearest GT | verdict |
| --- | --- | --- | --- |
| acme seed 42 `POST /rest/alerts/:alertId/read` | cross-actor, CWE-639 | `acme.notification-idor` is `GET /rest/alerts/:alertId` | sibling action route; site's `vulnerable.ts` only registers `getNotification`, so the finding is out of scope (not a mis-mapping) |
| acme seeds 1/2 (`POST /api/inbox/:id/read`, `POST /api/v1/notifications/:id/read`) | same | same sibling-route pattern | out of scope |
| ops seeds 42/1/2 `GET .../issues/:ticketRef/view` | cross-actor, CWE-639 | decoy `og.ticket-note-xss` trigger (xss_stored) | class-mismatched; route is not an authz site |
| ops seeds 42/1/2 `POST .../issues/:ticketRef/notes` | cross-actor, CWE-639 | decoy `og.ticket-note-xss` entry (xss_stored) | class-mismatched |
| ops seeds 42/1/2 `PATCH .../staff/:userId` (or members/:uid) | cross-actor, CWE-639 | vuln `og.user-mass-assignment` (CWE-915) same endpoint | class-mismatched: the app ignores the path id and updates the session user, so the authz spec proves a self-service write, not the planted role overpost |

No adapter-side remapping was applied: matching these would either relabel a cross-actor
finding as mass assignment or bind a sibling action route to a handler that does not implement
the site. Path normalization is already handled by `grader/match.ts`; findings are emitted with
the materialized route template, not a concrete id.

### Decoy false positives

- Pre-merge engine: opsportal seed 42 `GET /api/v1/issues/:ticketRef` (CWE-639/idor) matched
  decoy `og.ticket-bola-read` (bola) on the same route; seed 1 `GET /api/switches/:toggleKey`
  matched decoy `og.flag-bola`. Both were real decoy hits.
- Merged engine: those confirmations no longer occur; decoy FP = 0 in all 9 runs. The findings
  that still touch decoy routes (`/issues/:ticketRef/view`, `/notes`) are class-mismatched and
  therefore counted as unmatched, not as decoy hits.

### Engine-side gaps (not fixable in the adapter without fabricating surface)

- Recon finds only 5 endpoints on opsportal despite a 69-route materialized surface. The SPA's
  `/app-config.json` route map is fetched (`js_ast`) but not expanded into routes/params, and
  the crawl stays on the SPA shell; the adapter's surface merge adds routes but only path
  params, so query/body-driven classes (sqli/ssrf/xxe/xss/ssti) are never probed.
- 25–33 signals per run are `path_traversal_benign`, for which no spec builder exists; they are
  proof gaps by design.
- `synthAuthz` reliably confirms 200-equality on routes that ignore the path id (self-service
  PATCH /staff/:userId) or expose sibling action routes (`/read`); that is an engine precision
  issue, not an attribution bug.
- The real mass-assignment site (`og.user-mass-assignment`, CWE-915) receives no
  `mass_assignment` probe signal in these runs, so the planted role-overpost bug is not reached.

## Snapshot state / notes for pane 3

- This snapshot boots natively for all three apps. `node --test` is 109/110: the only failure is
  pane 3's `tests/opsportal.test.ts` implemented-site matrix (expected 16 oracle events, saw 96);
  all adapter/login/lib/grader/generator tests pass, and `tsc` is clean.
- Both apps and the pane-3 tree are mid-write. Earlier snapshots failed on
  `Unknown named parameter '0'` (`lib/db.ts` does not spread array bindings) and a missing
  shopflow `hardened.ts`; the current wiring routes around the former. A future site module
  calling `db.run(sql, [..])` directly would still hit it.
- `tests/safety.test.ts` passes; its `FS_ALLOWED` list includes `kovo-adapter.ts` and
  `benchmark-realistic.ts` (benchmark tooling). Re-apply that one-line-list change if pane 3's
  safety test is re-synced over this tree.
- The merged engine exports `synthesizeSpecs` (array). The adapter prefers it and falls back to
  `synthesizeSpec` for older engines.
- `static_verified` is treated as a proof gap (no `codeLocations` are derived here), so it does
  not count toward `static_only` / `staticRecall` and cannot inflate precision.
- `runLivePipelineAgainstMaterialized` uses `suite: 'xben-25'` purely as the pipeline's suite
  label; the caller supplies the manifest and no suite scoring is performed.
- `tests/safety.test.ts`'s `FS_ALLOWED` list gained `kovo-adapter.ts` and
  `benchmark-realistic.ts` (benchmark tooling: variant.json read + artifact writes). Re-apply that
  one-line-list change if pane 3's safety test is re-synced over this tree.
