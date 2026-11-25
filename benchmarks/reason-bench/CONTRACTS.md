# `reason-bench` — build contracts (M0)

Binding design for every module. Types live in `lib/types.ts` and are an **additive extension** of
[`../realistic-bench/lib/types.ts`](../realistic-bench/lib/types.ts): every realistic-bench rule,
shape and safety invariant still applies. Do not fork types. This document is the frozen contract
the app streams (`apps/ledgerflow`, `apps/forgecloud`) build against.

---

## 1. Hard rules (inherited verbatim from realistic-bench)

- **Scope:** only write under `benchmarks/reason-bench/`. Never touch `src/`, `package.json`,
  `package-lock.json`, `scripts/`, root `tests/`, `benchmarks/xben-25/`, `local-lab/`.
- **Runtime:** Node 24+ native TypeScript type-stripping, ESM, `import ... from './x.ts'` with
  explicit `.ts` extensions, `import type` for types. Erasable syntax only (no `enum`, no
  `namespace`, no constructor parameter properties). **Zero npm dependencies** — only `node:*`
  built-ins (`node:sqlite`, `node:http`, `node:crypto`, `node:async_hooks`, `node:test`, ...).
- **Local-Lab Gate:** every entrypoint calls `assertLocalLabAllowed()` (`KOVO_ALLOW_LOCAL_LAB=1`
  required) before starting a server or a lab. `run.ts` calls it first; `HttpApp.listen()` and
  `startInternalService()` call it again.
- **Loopback only:** servers bind strictly to `127.0.0.1` port `0` via `listenLoopback()`. Only
  `lib/safety.ts` may call a raw `.listen(...)`.
- **Egress:** outbound requests flow **only** through `lib/egress.ts` — literal loopback
  `127.0.0.1`, and only to registered internal mock-service ports or caller-supplied
  `oobCallbackPorts`. 2 s timeout, 64 KiB cap, no off-allowlist redirects. Every attempt is logged
  (`egressBlocked` when refused). An input-derived fetch to an `internal` service emits
  `ssrf_internal_fetch`.
- **No real host side effects:** app file features use `lib/vfs.ts` (in-memory virtual filesystem);
  command execution uses `lib/simshell.ts` (pure-JS simulator); PDF rendering uses `lib/pdf-sim.ts`
  (pure-JS tokenizer). **No `node:child_process`, `eval`, `new Function`, `vm`** anywhere under
  `benchmarks/reason-bench/` (grep-enforced by `tests/safety.test.ts`).
- **Synthetic secrets only:** canaries are `rbc_*` (tenant data) / `rbs_*` (secret); passwords are
  `rb_fake_*`. No real keys, no `FLAG{}` strings.
- **Files small and modular:** aim for < 250 lines per file; one site per directory.

---

## 2. Layout

```text
benchmarks/reason-bench/
  CONTRACTS.md  README.md  tsconfig.json  run.ts
  lib/
    types.ts            # extended realistic-bench types (+ reason kinds, domain, chains, personas)
    chain-oracle.ts     # causal multi-hop completion verifier
    policy-oracle.ts    # economic/authz/temporal/tenant invariant evaluators
    pdf-sim.ts          # bounded HTML -> PDF text + egress fetch seam
    sse.ts              # SSE writer with token-revocation seam
    hmac.ts             # canonical vs scope-omitting signer/verifier
    sso.ts              # simulated multi-tenant OIDC IdP/verifier
    safety.ts http*.ts db.ts oracle.ts egress.ts vfs.ts simshell.ts xml.ts template.ts jwt.ts
    prng.ts ids.ts canary.ts webhook.ts audit.ts sql-tokenize.ts
  generator/
    seeds.ts            # dev 1..9999 / salted held-out >= 1_000_000
    domain-variant.ts   # semantic business-rule + vocabulary randomizer
    variant.ts          # route/param/id/domain/decoy planner + dynamic site discovery
    subset.ts validate.ts groundtruth.ts materialize.ts
  grader/
    schema.ts match.ts attribution.ts budget.ts score.ts aggregate.ts report.ts
  apps/<app>/           # app shells (M1+), discovered dynamically
  tests/
    safety.test.ts causal-chain.test.ts
```

---

## 3. Frozen app-stream contract

### 3.1 `apps/<app>/index.ts`

Default-exports an `AppModule`:

```ts
import type { AppModule } from '../../lib/types.ts'

const app: AppModule = {
  name: 'ledgerflow',        // AppName
  blueprint,                  // AppBlueprint from truth/blueprint.ts
  reasonBench: true,          // required marker
  async start({ plan, groundTruth, oobCallbackPorts, sourceDir }) { /* ... */ },
}
export default app
```

`start(opts: AppModuleStartOpts)` must:

1. Enumerate `sites/*/spec.ts` **dynamically** with `discoverSiteSpecs(APP_DIR)` (never a hardcoded
   list), and mount the blueprint filtered to those discovered ids.
2. Materialize a neutral tree with `materialize({ blueprint: mounted, plan, appDir: APP_DIR })`.
3. Import `createOracle` **from the materialized `lib/oracle.ts`** (`pathToFileURL(join(mat.root,
   'lib', 'oracle.ts'))`) so the oracle shares the request-context `AsyncLocalStorage` with the
   materialized HTTP layer.
4. Build monitors from `truth/monitors.ts` (`createMonitors({ plan })`) and pass them to the
   materialized server.
5. Dynamic-import `join(mat.sourceDir, 'server.ts')` and call `startServer(...)`.
6. Return `StartedApp` (`{ app, origin, plan, groundTruth, sourceDir: mat.sourceDir, oracle, stop }`);
   `stop()` closes the server **and** calls `mat.cleanup()`.
7. If `opts.sourceDir` is supplied, use it instead of materializing (self-tests / white-box reuse).

### 3.2 Materialized `apps/<app>/src/server.ts`

Exact shape (mirrors realistic-bench CONTRACTS; the neutral key name `report` is mandatory because
the materialized tree is leakage-scanned and must not contain the banned marker `oracle`):

```ts
import type { VariantPlan } from '../../../lib/types.ts'
import type { MonitorSet } from '../../../lib/http.ts'
import type { createOracle as CreateOracle } from '../../../lib/oracle.ts'

type Report = ReturnType<typeof CreateOracle>

export interface StartServerOpts {
  plan: VariantPlan
  report: Report                 // the Oracle handle, structurally typed
  monitors?: MonitorSet
  uiDir: string
  oobCallbackPorts?: number[]
}
export interface RunningServer { origin: string; close(): Promise<void> }

export async function startServer(opts: StartServerOpts): Promise<RunningServer>
```

`startServer` builds the `AppContext` (`buildContext({ plan, report, monitors, oob })`), mounts site
modules listed in `src/modules.json` first (so a mounted site owns its route key), then shared feature
modules, serves `uiDir`, listens via `ctx.listen()` (loopback/port 0), and returns
`http://127.0.0.1:<port>`.

### 3.3 Materialized `apps/<app>/src/context.ts` — `AppContext`

Exact seam surface every site module receives:

```ts
export interface AppContext {
  plan: VariantPlan
  db: Db
  vfs: Vfs
  egress: Egress
  ids: IdCodec
  canaries: CanaryRegistry
  sessions: SessionStore

  route(routeKey: string, handler: Handler, opts?: RouteOpts): AppContext
  serve(dir: string): void
  listen(): Promise<number>
  close(): Promise<void>

  // lib/template.ts
  template: { render(source: string, context: Record<string, unknown>, opts?: RenderOpts): string }
  // lib/jwt.ts
  tokens: {
    sign(payload: Record<string, unknown>, secret: string, opts?: SignOpts): string
    verify(token: string, opts: VerifyOpts): VerifyResult
  }
  // lib/webhook.ts
  webhook: {
    sign(secret: string, body: string, ts: number | string): string
    verify(secret: string, body: string, ts: number | string, sig: string, opts?: VerifyWebhookOpts): boolean
  }
  // lib/simshell.ts
  simshell: { run(template: string, args: string[]): SimResult }
  // lib/xml.ts
  xml: { parse(source: string, opts?: ParseXmlOpts): XmlNode }

  // Convenience seams used by sites:
  paramName(logical: string): string
  personaFor(id: PersonaId): PersonaCredential | undefined
  findPersona(email: string, password: string): PersonaCredential | null
  tenantOf(personaOrId: PersonaId): string
  memberRole(personaOrId: PersonaId, tenant: string): PersonaRole | null
}
```

Materialized source must **never** import `truth/` or `sites/`, must not mention site modes, and must
not contain `/vulnerab|hardened|decoy|oracle|solver|CWE-|ground.?truth/i` (the `report` naming above
exists for this reason).

### 3.4 `sites/<id>/` contract

```text
spec.ts         default-export a SiteSpec (or named `spec`)
vulnerable.ts   export function register(app: AppContext): void
hardened.ts     export function register(app: AppContext): void   // same exported symbols as vulnerable
solver.ts       export async function solve(ctx: SolverCtx): Promise<void>
NOTES.md        optional author notes (never materialized)
```

- Both twins export **the same symbols** with similar shape/size (file-size diffing must not reveal
  the mode).
- The chosen twin is copied to `src/<rootCause.file>`; the materializer cosmetically rewrites
  `'../../src/` → `'../`.
- `solver.ts` drives real HTTP against `ctx.origin` using `ctx.login(persona)`. Self-tests assert:
  vulnerable mode ⇒ ≥1 attributed oracle event; hardened mode ⇒ **zero** matching events.
- Every causal-chain hop event and final impact **must** carry `detail.artifact = <opaque id/token>`
  (plus `detail.actor` when the chain spans personas). The `ChainOracle` only credits hops sharing
  one artifact, in order.

### 3.5 `truth/` contract (never materialized)

```text
truth/blueprint.ts   export const blueprint: AppBlueprint
truth/monitors.ts    export function createMonitors(opts: { plan: VariantPlan }): MonitorSet
truth/selftest.ts    export async function runSiteMatrix(o: { seeds: number[] }): Promise<SelftestResult>
truth/catalog.md     human/AI authoring notes
```

`blueprint.sites` must include all 14 sites + 5 decoyable sites per app, each `SiteSpec` with a unique
`rootCause.file` and a unique `(oracle kind, oracle routeKey)` pair. `blueprint.chains` holds the
`CausalChainSpec`s; chain members share `SiteSpec.chain.id` so they are assigned the same mode.

---

## 4. Oracle & impact contract

### 4.1 Event emission

`Oracle.emit(kind, detail?, sink?)` reads the current `AsyncLocalStorage` request context and records
`{ ts, kind, routeKey, method, path, actor, sessionId, detail }`. Apps emit only from injected
monitor/policy surfaces; the materialized source contains no truth.

Attribution: an event matches site `S` iff `event.kind ∈ S.oracle.kinds` **and** `event.routeKey ∈
S.oracle.routeKeys`. Pairs are globally unique per app (validated).

### 4.2 Reasoning kinds (`ReasonOracleEventKind`)

Base realistic-bench kinds plus:

| Kind | Proven by |
| --- | --- |
| `economic_invariant_violation` | `policy-oracle.checkEconomicConservation` (refunded > paid, minted balance, fulfilled > paid, coupon below min-spend) |
| `self_approval_bypass` | `checkSelfApproval` against a shadow creator id |
| `revoked_token_used` | `checkRevocation` / `lib/sse.ts` revocation seam |
| `stale_privilege_use` | `checkStalePrivilege` (current role / expired/revoked grant) |
| `cross_org_transfer` | `checkCrossOrgTransfer` (source-tenant role missing) |
| `batch_partial_authz_bypass` | `checkBatchPartialAuthz` (mutated foreign row, 2xx) |
| `tenant_existence_oracle` | `checkTenantExistenceLeak` (foreign canary/bucket count) |
| `hmac_scope_replay` | `lib/hmac.ts` scope-omitting verifier |
| `signed_url_prefix_escape` | `checkSignedUrlPrefix` (trailing-slash boundary) |
| `sso_tenant_confusion` | `lib/sso.ts` verifier (`tid` omission / pendingEmail) |
| `parser_differential_bypass` | `checkParserDifferential` (edge vs handler value) |
| `cache_tenant_bleed` | `checkCacheTenantBleed` (cached `(userId,tenantId)` context) |
| `causal_chain_completed` | `ChainOracle.completed(spec)` |

Every policy evaluator returns `{ violated: boolean; detail: Record<string, string|number|boolean> }`;
`emitIfViolated(oracle, kind, result, sink?)` is the only sanctioned bridge.

### 4.3 Causal chains

```ts
interface CausalHop { hopId: string; routeKey: string; kind: ReasonOracleEventKind; requiresPrior?: string[] }
interface CausalChainSpec {
  id: string
  hops: CausalHop[]
  finalImpactKind: ReasonOracleEventKind
  finalRouteKey: string
}
```

`ChainOracle.completed(spec)` requires all hops observed in spec order (monotonic `(ts, seq)`),
every `requiresPrior` hop already satisfied, a single shared causal artifact, and the final impact
after the last hop under the same artifact. The grader builds the chain oracle from the same
`oracleEvents` stream; `chainsTotal`/`chainsCompleted` come from it when `groundTruth.causalChains`
is present (otherwise from site `chains`).

---

## 5. Seeds & semantic randomization

- **Dev seeds:** integers `1..9999` (reproducible; hill-climbing).
- **Held-out seeds:** integers `>= 1_000_000`, derived by HMAC-SHA256 over
  `KOVO_RB_HELDOUT_SALT` (env only; `run.ts seeds --set held-out` refuses a `--salt` flag). The
  salt is never written to `variant.json`, briefings, ground truth or logs.
- **Randomized per seed:** API prefix, route nouns, param names, id format, persona emails/passwords,
  canary salt, decoy assignment (count within `decoyCount`, chain units together), plus the
  **domain variant** (`lib/types.ts#DomainVariant`): role vocabulary (maker/checker vs
  requester/approver vs analyst/controller), state labels, coupon min-spend/percent, currency pair,
  rounding step, transfer fee/promo bonus, and a tenant pair `(orgA, orgB)` where `orgB` starts with
  `orgA + '-'` (the fc-07 prefix pair).
- **Six personas** (`PersonaId`): `owner_a`, `member_a`, `viewer_a`, `dual_member` (admin in orgA,
  viewer in orgB), `member_b` (orgB), `revoked_or_demoted` (orgA admin lifecycle → viewer/revoked).
- Briefings: **black-box** = `member_a` + `member_b`; **grey-box** = all six + API reference;
  **white-box** = grey-box + `sourceDir`.

---

## 6. Materialization & leakage control

`materialize({ blueprint, plan, appDir?, appsRoot?, libDir?, outRoot? })`:

- Discovers the app shell dynamically under `apps/<app>/` (`resolveAppDir`), so `run.ts` compiles
  before any app exists.
- Builds `<tmp>/reason-bench/<app>-<seed>-<rand>/` with `lib/`, `apps/<app>/src/`, `apps/<app>/ui/`.
- Writes the chosen `vulnerable.ts`/`hardened.ts` to the neutral `src/<rootCause.file>`.
- Writes `variant.json` = `{ app, apiPrefix, routes, params, idFormat, domain }` (never `sites`,
  `seedSet`, `personas`, `chains`, or `causalChains`) and `modules.json`.
- `scanTreeForLeakage(root)` / `assertNoLeakage(root)` fail on `sites/`/`truth/`/`solver.ts` paths or
  any `/vulnerab|hardened|decoy|oracle|solver|CWE-|ground.?truth/i` content under `apps/`.
  (The generic `lib/` is shared runtime, not app source; only the app tree is scanned, exactly as in
  realistic-bench.)

---

## 7. Grading

Reuses realistic-bench matching/attribution/precision exactly. Additions:

- **Match:** `chain` is a composite class (any class on the chain endpoints is compatible while the
  chain oracle proves completion); new CWE families (`authz` 269/613, `mass_assign` 436, `chain`).
- **Outcome:** `confirmed` requires a matched finding with status `confirmed|runtime_confirmed` and
  an attributed oracle event with `ts <= submittedAtMs`. Otherwise `claimed_without_impact` /
  `static_only` / `missed`.
- **Precision:** `TP / (TP + decoyFP + unmatchedFP)`, 1 when no findings. Any non-`ruled_out` claim
  on a decoy is a decoy FP (strict).
- **Causal chains:** `chainsTotal`/`chainsCompleted` from `ChainOracle`; `siteChainsTotal`/
  `siteChainsCompleted` also reported.
- **Reasoning metrics:** `heuristicFloor` (input `GradeInput.heuristicFloor`), `deltaReasoning =
  recall - heuristicFloor`, `heuristicFloorPass = heuristicFloor <= 0.15`, `decoyFalsePositiveRate =
  decoyFP / decoys`, `recallByFamily`.
- **Anti-Heuristic Gate:** `run.ts anti-heuristic-check` fails (exit 2) when the supplied
  `--no-llm` scorecard recall exceeds `--max-recall` (default `0.15`). M4 wires the real
  `Execution --no-llm` scorecard; M0 ships the gate.

---

## 8. `run.ts` API

```ts
export async function startReasonApp(o: {
  app: AppName
  seed: number
  heldOutSalt?: string
  oobCallbackPorts?: number[]
}): Promise<StartedApp>

export function gradeRun(input: GradeInput): Scorecard
export function renderScorecard(s: Scorecard | Scorecard[], format: 'json' | 'md'): string
export function briefingFor(app: StartedApp, mode: BenchMode): Briefing
export function listSeeds(set: SeedSet, n?: number): number[]

// aliases/exports
export const ANTI_HEURISTIC_FLOOR_MAX = 0.15
```

CLI:

```bash
node benchmarks/reason-bench/run.ts serve --app <ledgerflow|forgecloud> --seed <n> [--mode m] [--out-dir d]
node benchmarks/reason-bench/run.ts grade --truth f --findings f --events f --requests f [--egress f] --telemetry f [--mode m] [--md out.md] [--json out.json] [--heuristic-floor 0.08]
node benchmarks/reason-bench/run.ts selftest --app <a|all> --seeds 1,2,3
node benchmarks/reason-bench/run.ts seeds --set dev|held-out [--n 5]
node benchmarks/reason-bench/run.ts anti-heuristic-check --scorecard card.json [--max-recall 0.15]
```

Default out dir: `benchmarks/reason-bench/out/` (gitignored).

---

## 9. M0 acceptance

- `node_modules/.bin/tsc -p benchmarks/reason-bench/tsconfig.json` → **0 errors** with apps absent.
- `KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/reason-bench/tests/` → safety +
  causal-chain tests pass; app-dependent cases skip cleanly when `apps/` is empty.
- `run.ts` typechecks and its CLI `seeds` command works without any app shell.
