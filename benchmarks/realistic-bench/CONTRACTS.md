# realistic-bench — build contracts

Binding design for every module. Types live in `lib/types.ts` (do not fork them).

## Hard rules
- **Scope:** only write under `benchmarks/realistic-bench/`. Never touch `src/`, `package.json`, `package-lock.json`, `scripts/`, root `tests/`, `benchmarks/xben-25/`, `local-lab/`. Never `git commit`.
- **Runtime:** Node 24+ native TypeScript type-stripping, ESM, `import ... from './x.ts'` with explicit `.ts` extensions, `import type` for types. Erasable syntax only (no `enum`, no `namespace`, no constructor parameter properties). **Zero npm dependencies** — only `node:*` built-ins (`node:sqlite`, `node:http`, `node:crypto`, `node:async_hooks`, `node:test`, ...). No zod.
- **Safety (enforced by `tests/safety.test.ts`):**
  - Everything calls `assertLocalLabAllowed()` (throws unless `KOVO_ALLOW_LOCAL_LAB=1`) before starting.
  - Servers listen only on `127.0.0.1` port `0`.
  - Outbound requests only via `lib/egress.ts` — loopback `127.0.0.1` only, and only to ports registered as the app's internal mock services or the caller-supplied `oobCallbackPorts`. Everything else is blocked and logged (`egressBlocked`). No redirects followed off the allowlist, 2 s timeout, 64 KiB cap.
  - File access for app features (downloads, XXE `file://`, templates, exports) only via `lib/vfs.ts` — an in-memory virtual filesystem with synthetic files. The real filesystem is never read from user input.
  - Command execution only via `lib/simshell.ts` — a pure-JS parser/simulator. **No `node:child_process`, no `eval`, no `new Function`, no `vm`** anywhere under `realistic-bench/` (grep-enforced).
  - All secrets are synthetic and per-seed derived (`canarySalt`), clearly fake (`rb_fake_...`). Never real keys.
- **Files small and modular:** aim for < 250 lines per file; one site per directory.

## Layout
```
lib/            generic runtime shared by all apps (copied into each materialized tree)
  types.ts  safety.ts  http.ts (router, ALS request ctx, cookies, body parsing json/form/multipart/xml, CSRF helper, sessions, static/SPA serving)
  db.ts (node:sqlite wrapper + SQL-injection sink detection)  oracle.ts (event bus + logs + canary scanner + hooks)
  egress.ts  vfs.ts  simshell.ts  xml.ts  template.ts  jwt.ts  prng.ts  ids.ts  canary.ts
generator/      seeds.ts (dev vs held-out)  variant.ts (blueprint+seed -> VariantPlan)  groundtruth.ts  materialize.ts
grader/         schema.ts (hand-written validators)  match.ts  attribution.ts (funnel + taxonomy)  budget.ts  score.ts  report.ts (JSON + Markdown)
apps/<app>/
  index.ts      default export AppModule (wires blueprint + start)
  src/          app code that is materialized for white-box (neutral names, NO mention of vuln/decoy/oracle/CWE/solver/hardened)
  sites/<site-id>/  spec.ts (SiteSpec)  vulnerable.ts  hardened.ts  solver.ts   (never mounted)
  truth/        blueprint.ts (AppBlueprint incl. all SiteSpecs)  monitors.ts (authz policy + invariants + response inspectors)  catalog.md
  ui/           static SPA (index.html, app.js, styles.css)
  Dockerfile  docker-compose.yml   (optional, internal network only, no ports/binds/privileged)
run.ts          CLI + programmatic API
tests/          node:test self-tests
```

## Materialization (contamination + white-box leakage control)
`generator/materialize.ts` builds a per-seed tree in `os.tmpdir()/realistic-bench/<app>-<seed>-<rand>/`:
copies `lib/` (minus nothing — it is generic) and `apps/<app>/src/` and `ui/`, then for each site copies
`sites/<id>/vulnerable.ts` **or** `sites/<id>/hardened.ts` (per `plan.sites[id]`) to the neutral
path `src/<rootCause.file>`. It writes `variant.json` containing only routes/params/idFormat/apiPrefix
(no site modes, no truth). `app.start()` dynamically imports the materialized `src/server.ts`.
The materialized tree must contain no string matching `/vulnerab|hardened|decoy|oracle|solver|CWE-|ground.?truth/i`
except inside `lib/oracle.ts` and the hooks file (tests check this). Both variants of a site export the same
symbols and have similar shape/size so diffing file sizes doesn't reveal mode.

## Impact oracle (generic sinks + external invariants — not per-site flags)
Impact is detected generically so source code contains no per-vuln tells:
- **Request context:** `lib/http.ts` wraps each request in `AsyncLocalStorage` with `{routeKey, actor, tenant, sessionId, inputs[]}`; `oracle.emit(kind, detail, sink)` reads it.
- **Canaries:** each tenant's seeded records contain tokens `rbc_<tenantTag>_<hex>` (from `lib/canary.ts`). The response scanner emits `cross_tenant_read` when a response to an actor of tenant X contains a canary of tenant Y ≠ X — unless that exact token previously appeared in a request *input* from that actor (prevents laundering). Secret canaries (`rbs_...` for API keys/config secrets) → `secret_disclosed` when served to an actor not entitled (policy in `truth/monitors.ts`).
- **DB diffs:** `oracle` installs SQLite triggers (created at runtime from `truth/monitors.ts` config, not present in `src/`) into an audit table; after each request `monitors.ts`' policy checks diffs → `cross_tenant_write`, `privilege_escalation`, `mass_assignment`, `invariant_violation`, `race_double_spend`, `workflow_skip`.
- **SQLi:** `lib/db.ts` `db.raw(sql)` / `db.all(sql, params)` — if any request input value (len≥2) occurs verbatim inside the SQL text and tokenizing the SQL shows the input spans more than a single literal/identifier token (quote break, comment, keyword, operator) → `sql_structure_change`.
- **SSRF:** `lib/egress.ts` — fetch to a registered internal mock (marked `internal`) where the URL (or host/port) derives from request input → `ssrf_internal_fetch`.
- **XXE:** `lib/xml.ts` resolving an external entity → `xxe_entity_resolved`. **Path traversal:** `lib/vfs.ts` `vfs.readWithin(jailDir, userPath)` resolving outside `jailDir` → `path_escape` (still inside the virtual root). **Command injection:** `lib/simshell.ts` running more than the intended single command / substitution → `command_injection_simulated`.
- **SSTI:** `lib/template.ts` (safe mini-engine, own expression interpreter, no eval) rendering a template *source* that contains request input with an expression → `template_code_exec`.
- **JWT:** `lib/jwt.ts` keeps a set of issued token hashes; a token accepted by verify that was never issued → `token_forgery`.
- **XSS:** response inspectors registered per trigger routeKey (in `monitors.ts`) detect active markup (`<script`, `on*=`, `javascript:`) originating from another request's input, unescaped in an HTML or rich-HTML JSON field → `stored_xss_rendered` / `reflected_xss_rendered`.
- **Cache:** `lib/http.ts` cache layer; a cached response containing one actor's canary/attacker-controlled host served to a different actor → `cache_poisoned`.
- **Redirect/CSRF/webhook/auth:** emitted via generic helpers (`redirect()` to off-origin from input → `open_redirect`; state change on a cookie-auth request whose `Origin`/`Referer` is foreign or absent with no CSRF token → `csrf_state_change` *only if the change succeeds*; webhook signature checks in lib → `webhook_forgery`; `auth_bypass` from session/auth monitor in monitors.ts).

Attribution: an event matches site S iff `event.kind ∈ S.oracle.kinds` and `event.routeKey ∈ S.oracle.routeKeys`.
The `(kind, routeKey)` pairs must be unique across sites in an app (blueprint validator enforces).
**Hardened variants must never emit their site's oracle events** under the site solver's decoy probe.

## Sites & solvers (self-test ground truth)
Each `sites/<id>/solver.ts` exports `async function solve(ctx: SolverCtx): Promise<void>` that performs a
realistic exploit over HTTP against `ctx.origin` using `ctx.plan` (runtime routes/params/personas) and
`ctx.login(persona)`. Self-tests assert: vulnerable mode → ≥1 matching oracle event; hardened mode → the
same attempts produce **zero** matching events. Solvers live outside the materialized tree.

## Seeds
- Dev seeds: integers `1..9999` (hill-climbing; freely reproducible).
- Held-out seeds: integers `>= 1_000_000`; plan derivation mixes HMAC-SHA256 over `KOVO_RB_HELDOUT_SALT` (env, ≥16 chars, never committed). Without the salt, held-out seeds are refused. The salt is never written into `variant.json`, briefings, ground truth or any other artifact; only routes/params/idFormat/apiPrefix are scanner-visible.
- Randomized per seed: api prefix, route nouns (vocab synonyms), param names, id format, persona emails/passwords, canary salt, which sites are hardened (count within `decoyCount`, chain members together, `canBeDecoy:false` respected).

## Grading
- A finding **matches** an entry if one of its endpoints matches an entry endpoint or trigger endpoint (method optional; runtime path compared against route pattern with `:param` wildcards; concrete IDs allowed) AND its class is compatible (same `vulnClass`, or CWE in the same family per `grader/match.ts` table; missing class/CWE → endpoint+param match only).
- **confirmed** = matched vuln + finding status `runtime_confirmed|confirmed` + ≥1 attributed oracle event whose `kind` and `routeKey` both belong to that entry, with `ts <= submittedAtMs`. Matched w/o impact → `claimed_without_impact` (not TP, not FP). `static_verified` with matching `codeLocations` rootCause → `static_only` (counts only in `staticRecall`).
- Any non-`ruled_out` finding matching a decoy → decoy FP (strict, regardless of status). A finding whose endpoints hit a **planted vulnerable** entry but which matches no entry class-compatibly is *class-incompatible with the target* and increments `incompatibleClassCount`. It is left uncharged (listed in `misclassifiedFindingIds`) **only** when it is `runtime_confirmed|confirmed` **and** the two labels are one of the documented close-sibling pairs (`bola ↔ idor ↔ bfla ↔ graphql_bola`, `mass_assignment ↔ bfla`, `mass_assignment ↔ business_logic`, `business_logic ↔ race_condition`, `info_disclosure ↔ bfla`); otherwise it is an unmatched FP. Unverified claims (`static_verified`, `proposed`, `open_proof_gap`) are always charged — an unproven leak is a contract leak. Findings matching nothing → unmatched FP. Multiple findings on one vulnerable site → 1 TP + duplicates; multiple findings on one decoy site → 1 decoy FP. A multi-endpoint finding binds to at most one vulnerable site but is charged for every decoy site it names.
- Precision = confirmed TPs / (confirmed TPs + decoy sites with ≥1 claim + unmatched findings). Claims on vulnerable sites that lack impact are `claimed_without_impact` and do not enter this denominator. `strictPrecision` = confirmed TPs / (confirmed TPs + decoy sites with ≥1 claim + unmatched findings + uncharged misclassifications) — the sibling tolerance is never free. Phase-1 gates use `strictPrecision` and require `incompatibleClassCount === 0`.
- Chains: `chainsTotal` counts only chains whose members are all vulnerable (a chain unit selected as a decoy is fully hardened); `chainsCompleted` requires every member confirmed.
- Funnel per vuln: surfaceDiscovered (request log hit an entry route), hypothesisFormed (suspicious input to an entry route, or telemetry hypothesis), signalObserved (attributed oracle event), specSubmitted (matching finding), zeroLlmConfirmed (confirmed). Monotonic: each stage counts only vulns that passed the previous stage.
- Failure bucket per non-confirmed vuln (first rule that applies): budget_exhausted (telemetry exhausted & no matching finding & surface not reached) → surface_miss → tier_blocked → csrf_blocked → form_encoding_missing → context_reset → hypothesis_miss → trigger_miss (second-order: payload stored but trigger route never requested after) → replay_spec_miss (signal observed, no confirmed finding) → jq_assertion_bug (telemetry assertion failure on matched finding). `spa_catchall_fp` is counted for unmatched FPs whose endpoint only ever hit SPA fallback.
- Budget curve: confirmed count/recall with `costUsdAtSubmit <= usd` for each of $1/$5/$20.

## Materialized layout & import rule (no import rewriting needed)
The materialized tree mirrors repo layout: `<tmp>/lib/`, `<tmp>/apps/<app>/src/`, `<tmp>/apps/<app>/ui/`.
Every `SiteSpec.rootCause.file` is exactly two levels inside src: `<subdir>/<name>.ts` (e.g. `billing/invoices.ts`),
and is copied to `apps/<app>/src/<subdir>/<name>.ts`. Because `apps/<app>/sites/<id>/` and `apps/<app>/src/<subdir>/`
have the same depth, site files import with `'../../src/<...>.ts'` and `'../../../../lib/<...>.ts'` and resolve
identically in both places. (Materializer may cosmetically rewrite `'../../src/` → `'../` in copied site files.)
The materializer also writes `apps/<app>/src/variant.json` (routes/params/idFormat/apiPrefix only) and
`apps/<app>/src/modules.json` (list of the site module files). `src/server.ts` dynamically imports those modules,
each exporting `register(app: AppContext): void` (AppContext type defined by the app in `src/context.ts`).
`src/server.ts` exports `startServer(opts: { plan: VariantPlan; oracle: Oracle; monitors: MonitorSet; uiDir: string; oobCallbackPorts?: number[] })`.
The Oracle + monitors are created by `apps/<app>/index.ts` (repo side) and injected; the materialized tree never imports truth/.

## run.ts API
```ts
export async function startRealisticApp(o: { app: AppName; seed: number; heldOutSalt?: string; oobCallbackPorts?: number[] }): Promise<StartedApp>
export function gradeRun(input: GradeInput): Scorecard
export function renderScorecard(s: Scorecard | Scorecard[], format: 'json' | 'md'): string
export function briefingFor(app: StartedApp, mode: BenchMode): Briefing // what the scanner under test may see
//   black-box: origin + persona_a & persona_b credentials
//   grey-box:  + all 4 personas + API reference (method/path/params of every route; no site info)
//   white-box: + sourceDir (materialized tree)
export function listSeeds(set: SeedSet, n?: number): number[]
```
CLI: `node benchmarks/realistic-bench/run.ts serve --app <a> --seed <n> [--mode m] [--out-dir d]` (prints briefing JSON to stdout, writes
ground truth + oracle/request/egress logs to out-dir on SIGINT/SIGTERM), `grade --truth f --findings f --events f --requests f [--egress f] --telemetry f [--mode m] [--md out.md] [--json out.json]`,
`selftest --app <a|all> --seeds 1,2,3` (runs every site solver in both modes), `seeds --set dev|held-out [--n 5]`.
Default out dir: `benchmarks/realistic-bench/out/` (gitignored).
Self-tests: `KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/realistic-bench/tests/` ; typecheck: `node_modules/.bin/tsc -p benchmarks/realistic-bench/tsconfig.json`.
