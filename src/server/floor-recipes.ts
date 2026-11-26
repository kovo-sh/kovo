/**
 * Floor recipes — typed, deterministic proof scripts for the deterministic floor.
 *
 * M0 (v7) replaces declarative replay-spec synthesis with *recipes*: a recipe owns the exact
 * request sequence a confirmation needs, cites the host-recorded exchange ids, and builds a
 * `ProofReceipt` that `verifyReceipt()` re-derives from the transcript with the shared
 * `oracle-invariants` model. The motivation is Cut 3: once every floor confirmation is a recipe over
 * receipts, the spec VM (`DeclarativeReplaySpec` + `verifyReplaySpec`) can be deleted.
 *
 * Design constraints (load-bearing):
 *  - **Layer-1 boundary.** Recipes never speak HTTP. They send through the injected
 *    `FloorRecipeDeps.request`, which is the same boundary the broker/verifier uses. Tests supply
 *    fake deps; the migration stream supplies a broker adapter.
 *  - **Deterministic.** No `Date.now`, no randomness, no timers. Durations, OOB timestamps and
 *    exchange ids come from the host recorder. The same fixtures produce byte-identical runs.
 *  - **Bounded.** A run may not exceed `MAX_FLOOR_RECIPE_STEPS` exchanges; burst length and sampling
 *    are clamped. A budget overflow is a named failure, never a partially credited proof.
 *  - **Minimum evidence, no "trust me".** Recipes assert the preconditions of the oracle they
 *    target (`ctx.require`) and then the receipt gate decides. Missing evidence is reported as the
 *    *role* the proof lacked (`denied_control`, `post_mutation_read`, `delivered_callback`, ...).
 *
 * Mapping from the legacy deterministic spec kinds this module replaces 1:1:
 *
 * | Legacy spec kind       | Legacy vulnClass                          | Recipe               | Note |
 * |------------------------|-------------------------------------------|----------------------|------|
 * | `http_chain`           | bola / idor / bfla / authorization        | `access_boundary`    | peer denied + lower-privilege probe served |
 * | `http_chain`           | mass_assignment                           | `persisted_mutation` | request body field persisted through a separate GET |
 * | `http_chain`           | workflow_bypass / price_tampering         | `persisted_mutation` | before/write/after chain |
 * | `http_chain`           | csrf                                      | `persisted_mutation` | ambient cookie + foreign Origin header + csrf_state_change oracle |
 * | `http_chain`           | info_disclosure / secret_disclosure       | `disclosure`         | owner-scoped non-public field + denied peer |
 * | `http_chain`           | xxe / ssrf / webhook_forgery              | `oob_callback`       | delivered durable callback carrying the injected token |
 * | `sql_boolean_diff`     | sqli                                      | `boolean_or_timing`  | boolean rule: >=2 paired rounds, stable structural change |
 * | `sql_time_diff`        | sqli                                      | `boolean_or_timing`  | timing rule, >3x separation |
 * | `race_burst`           | race_double_spend                         | `race_burst`         | repeated terminal transition + divergent burst outcomes |
 * | `browser_chain`        | xss_* / dom_* (navigate/fill/click)       | `browser_sink`       | browser rule: host-recorded trace with the canary in an executable sink |
 * | `browser_chain`        | protocol (postMessage/fetch/builtin)      | — (no recipe)        | claim is not expressible as a sink trace |
 * | `rce_proof`            | ssti / command_injection                  | — (no recipe)        | not expressible by the receipt impact model |
 * | `auth_protocol_proof`  | jwt / oauth / webhook_forgery             | — (no recipe)        | proof-script path stays for protocol forgery |
 * | `cache_differential`   | cache_poisoning                           | — (no recipe)        | no receipt rule |
 * | `http_chain`           | path_traversal / open_redirect / xss_*    | — (no recipe)        | no receipt rule |
 *
 * Boolean-only SQLi confirms through the `boolean_differential` receipt rule: the recipe sends at
 * least two paired control/probe rounds with an identical request shape apart from the injected
 * predicate, and `verifyReceipt()` requires a stable structural response difference after token
 * stripping, a stable control baseline, and no 5xx. Echo/nonce-only changes are rejected.
 *
 * Cut 3a wired `sql_boolean_diff`; Cut 3b adds the authorization families (`http_chain` +
 * object/function access) with a bogus-id/peer denial control and a pre-read + post-read mutation
 * readback. The other rows above stay on the legacy verifier and are listed in
 * `LEGACY_UNWIRED_SPECKINDS` with the measured blocking reason; `wiredRecipeForSpecKind` is the
 * single source of truth for the guard.
 */
import { createHash } from 'node:crypto'
import { matchInjectionFingerprint } from './oracle-invariants.ts'
import type { AmbientAuth, ImpactStep, InjectionFamily, RoleName } from './oracle-invariants.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import { buildProofReceipt, verifyReceipt } from './proof-receipt.ts'
import type {
  ProofReceipt,
  ReceiptBrowserTrace,
  ReceiptOobEvent,
  ReceiptTranscript,
  ReceiptTranscriptEntry,
  ReceiptVerification,
} from './proof-receipt.ts'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type FloorRecipeId =
  | 'access_boundary'
  | 'persisted_mutation'
  | 'boolean_or_timing'
  | 'oob_callback'
  | 'race_burst'
  | 'disclosure'

export const FLOOR_RECIPE_IDS: readonly FloorRecipeId[] = [
  'access_boundary',
  'persisted_mutation',
  'boolean_or_timing',
  'oob_callback',
  'race_burst',
  'disclosure',
]

/**
 * Cut 3c/3d recipe ids. They are intentionally **not** in `FloorRecipeId` yet: the persisted
 * envelope enum (`src/replay-spec.ts`) and the retest title table (`floor-recipe-engine.ts`) own that
 * set, and both are outside this stream's lease. These recipes are complete and independently
 * runnable/testable; registering them for persistence is a one-line follow-up in each of those two
 * files (reported in the handoff).
 */
export type Cut3FloorRecipeId = 'redirect' | 'browser_sink' | 'injection_fingerprint' | 'conserved_balance'
export const CUT3_FLOOR_RECIPE_IDS: readonly Cut3FloorRecipeId[] = [
  'redirect',
  'browser_sink',
  'injection_fingerprint',
  'conserved_balance',
]

/** A persona the recipe sends as. Host-resolved in production; explicit in fixtures. */
export interface FloorActor {
  handle: string
  role?: RoleName | null
  tenant?: string | null
  auth?: AmbientAuth
  sameSite?: string | null
}

export type FloorArm = 'control' | 'probe' | 'setup' | 'cleanup'

/** One request the recipe asks Layer 1 to perform. */
export interface FloorRequestSpec {
  arm: FloorArm
  /** Evidence role, reported when the proof lacks this step (`denied_control`, ...). */
  role: string
  method: string
  pathAndQuery: string
  actor: FloorActor
  jsonBody?: unknown
  textBody?: string
  headers?: Record<string, string>
  /** Opaque browser-session jar handle (cookie/CSRF state) for form carriers. */
  session?: string
  /** Bind the route's CSRF token (hidden field + cookie) on this arm. */
  csrfBind?: boolean
}

/** One host-recorded exchange. Ids/timings are the host's, never the recipe's. */
export interface FloorExchange {
  /** Host exchange id. Defaults to a per-run deterministic `fr-N` when omitted. */
  exchangeId?: string
  status: number | null
  json?: unknown
  body?: string
  /** Host-measured wall-clock duration (timing receipts). */
  durationMs?: number
  carrierText?: string
  route?: string
  responseHeaders?: Record<string, string> | null
  /** Pre-redaction credential fingerprints observed by the broker (never raw values). */
  secretMatches?: readonly string[]
}

export interface FloorOobQuery {
  token: string
  injectedAtMs?: number
}

/** The Layer-1 seam. Production supplies a broker adapter; tests supply fixtures. */
export interface FloorBrowserInput {
  origin: string
  url: string
  actor: FloorActor
  marker?: string
}

export interface FloorRecipeDeps {
  request(spec: FloorRequestSpec): Promise<FloorExchange> | FloorExchange
  /** Optional synchronized concurrent burst execution (production wires `broker.executeRaceBurst`). */
  burst?(specs: readonly FloorRequestSpec[]): Promise<FloorExchange[]> | FloorExchange[]
  /** Durable callback lookup for the token the injection exchange carried. */
  oob?(query: FloorOobQuery): Promise<ReceiptOobEvent | null> | ReceiptOobEvent | null
  /**
   * Host-recorded browser trace for a Layer-3 sink proof. Optional: a recipe that needs it fails
   * closed (`browser_trace`) rather than inventing trace ids.
   */
  browserTrace?(input: FloorBrowserInput): Promise<ReceiptBrowserTrace | null> | ReceiptBrowserTrace | null
  /**
   * Execute an ordered browser session (navigate/fill/click) and return the canary-bearing traces.
   * Optional: a recipe that needs it fails closed (`browser_trace`).
   */
  browserSession?(input: {
    origin: string
    steps: readonly FloorBrowserStep[]
    canaryToken: string
    actor: FloorActor
  }): Promise<FloorBrowserSessionResult | null> | FloorBrowserSessionResult | null
  /** Stable id source; defaults to a per-run counter. */
  nextExchangeId?(): string
}

interface FloorRecipeBaseArgs {
  origin: string
  method: string
  pathAndQuery: string
  /** Receipt class (`bola`, `bfla`, `mass_assignment`, `business_logic`, `blind_sqli`, `ssrf`, ...). */
  vulnClass: string
  param?: string
  /** Headers applied to the probe/mutating request (e.g. a foreign `Origin` for CSRF). */
  headers?: Record<string, string>
}

export interface AccessBoundaryArgs extends FloorRecipeBaseArgs {
  owner: FloorActor
  probe: FloorActor
  /** Same-route control that must be denied; defaults to a peer of `probe`. */
  denied?: FloorActor
  /**
   * Control path the denied actor requests. Defaults to `pathAndQuery` (a same-route sibling arm).
   * When a route only denies nonexistent identifiers, this is the bogus-id variant: the denial is
   * still an authenticated negative control, and the impact oracle decides whether it is boundary
   * evidence or merely selectivity.
   */
  deniedPathAndQuery?: string
  deniedMethod?: string
  /**
   * What the negative control proves. `denial` (default) requires a 4xx. `denial_or_distinct`
   * accepts the legacy collection-reference shape: a bogus identifier returns 2xx but a body
   * different from the entitled read, so the route is selective without a denial. The impact
   * oracle still decides confirmation; this only keeps the recipe from discarding a valid control.
   */
  controlEvidence?: 'denial' | 'denial_or_distinct'
  requiredRole?: RoleName
  resourceTenant?: string
  expectControlDenied?: boolean
  oracleEvents?: string[]
}

export interface PersistedMutationArgs extends FloorRecipeBaseArgs {
  actor: FloorActor
  /** Request body whose persisted fields are the claimed impact. */
  body: Record<string, unknown>
  baselinePathAndQuery?: string
  baselineMethod?: string
  readbackPathAndQuery?: string
  readbackMethod?: string
  readbackActor?: FloorActor
  /**
   * Control write that puts the mutated field in a known-different state before the pre-read, so
   * the probe's body is a genuine delta instead of re-sending the value the record already holds.
   * Reuses the existing persistence oracle (`findPersistence`): the write is a control arm and its
   * resulting value must differ from the probe's post-read.
   */
  baselineWrite?: { body: Record<string, unknown>; actor?: FloorActor; method?: string }
  /**
   * Control write restoring the probe actor's own state before the proof. Self-service function
   * state (identity assumption) is a persistent session mutation, so without a reset the pre-read
   * may already carry the target value and the replay looks like an idempotent no-op.
   */
  reset?: { body: Record<string, unknown>; actor?: FloorActor; method?: string }
  requiredRole?: RoleName
  resourceTenant?: string
  expectControlDenied?: boolean
  oracleEvents?: string[]
  proofPatterns?: string[]
}

export interface BooleanOrTimingArgs extends FloorRecipeBaseArgs {
  /**
   * `boolean` = control-vs-variant structural differential; `timing` = conditional delay;
   * `status` = the paired status-boolean triangle (benign 2xx baseline, 2xx tautology, <500
   * contradiction) for sinks whose rows do not separate structurally.
   */
  mode: 'boolean' | 'timing' | 'status'
  actor?: FloorActor
  /** Path with the baseline (true) predicate; defaults to `pathAndQuery`. */
  controlPathAndQuery?: string
  /** Path with the injected/false predicate; defaults to `pathAndQuery`. */
  probePathAndQuery?: string
  /** Status mode: path of the failing contradiction arm (defaults to `probePathAndQuery`). */
  contradictionPathAndQuery?: string
  /** JSON body carrying the baseline value (JSON-located parameters cannot move a query string). */
  controlJsonBody?: unknown
  /** JSON body carrying the injected predicate. */
  probeJsonBody?: unknown
  /** Status mode: JSON body of the contradiction arm. */
  contradictionJsonBody?: unknown
  /** Paired rounds for the boolean/status rules (clamped to 2..4; timing ignores it). */
  rounds?: number
  /** Receipt class; defaults to `sqli` (boolean/timing) or `sqli_status` (status mode). */
  receiptClass?: string
  /**
   * Operand the probe proved the predicate with. A response-grounded value (or the empty term of the
   * tautology pair) must travel onto the recorded spec so a patch retest replays the same pair
   * instead of rotating back to a seed literal the target's data does not contain.
   */
  baselineValue?: string
  /** Shape of the proven predicate; carried for the recorded spec's replay. */
  quoteStyle?: 'single' | 'double' | 'numeric'
  /** Exact proven single-template shape (`{{baseline}}` / `{{sql_expr}}` placeholders). */
  valueTemplate?: string
  /**
   * Full per-arm request overrides. Needed for carriers the path/body shortcuts cannot express:
   * a header parameter, a path segment, an XML document, or a GraphQL variable envelope.
   */
  controlRequest?: FloorArmRequest
  probeRequest?: FloorArmRequest
  contradictionRequest?: FloorArmRequest
  /** Opaque session jar and CSRF binding applied to every arm (form carriers). */
  session?: string
  csrfBind?: boolean
  /** Same-origin page fetched first so the jar obtains cookies + a CSRF token. */
  primePath?: string
}

/** Per-arm request override used by the boolean/status/timing modes. */
export interface FloorArmRequest {
  pathAndQuery?: string
  headers?: Record<string, string>
  jsonBody?: unknown
  textBody?: string
  session?: string
  csrfBind?: boolean
}

export interface OobCallbackArgs extends FloorRecipeBaseArgs {
  actor?: FloorActor
  /** Canary token that must appear in the injection exchange and the callback. */
  token: string
  injectPathAndQuery?: string
  injectJsonBody?: unknown
  injectTextBody?: string
  injectHeaders?: Record<string, string>
  oracleEvents?: string[]
}

export interface ConservedBalanceStepSpec {
  method: string
  pathAndQuery: string
  jsonBody?: unknown
  headers?: Record<string, string>
  actor?: FloorActor
  /** Optional JSON dot-path extractions stored into `{{varName}}` for downstream steps. */
  extract?: ReadonlyArray<{ varName: string; selector: string }>
}

export interface RaceBurstArgs extends FloorRecipeBaseArgs {
  actor: FloorActor
  /** Identical body for every burst request (the terminal transition). */
  body: Record<string, unknown>
  /** Number of synchronized requests, clamped to 2..8. */
  burst: number
  /** Optional ordered prerequisite steps (e.g. minting a single-use token) run before the burst. */
  setupSteps?: readonly ConservedBalanceStepSpec[]
  /** Optional cleanup steps run in `finally` (never cited in the receipt). */
  cleanupSteps?: readonly ConservedBalanceStepSpec[]
  oracleEvents?: string[]
}

export interface ConservedBalanceArgs extends FloorRecipeBaseArgs {
  actor: FloorActor
  /** Body for each concurrent burst mutation (supports `{{var}}` from `setupSteps`). */
  body: Record<string, unknown>
  /** Number of synchronized burst requests, clamped to 2..8. */
  burst: number
  /** Request used to read the conserved numeric field before and after the burst. */
  readback: ConservedBalanceStepSpec
  /** Optional override for post-burst and post-serial readbacks if distinct from `readback`. */
  postReadback?: ConservedBalanceStepSpec
  /** Optional ordered prerequisite steps (e.g. minting a token) run before the baseline read. */
  setupSteps?: readonly ConservedBalanceStepSpec[]
  /** Optional serial control mutation override (defaults to the burst method/path/body). */
  serialControl?: ConservedBalanceStepSpec
  /** Optional cleanup steps run in `finally` (never cited as proof evidence). */
  cleanupSteps?: readonly ConservedBalanceStepSpec[]
  /** Explicit numeric conserved field name for `verifyConservedBalanceReceipt`. */
  balanceField?: string
  /** Explicit cap/limit field name for `verifyConservedBalanceReceipt`. */
  capField?: string
  /** Expected unit debit per acknowledged mutation when the request body omits an amount field. */
  unitDebit?: number
  oracleEvents?: string[]
}

export interface DisclosureArgs extends FloorRecipeBaseArgs {
  /** Entitled reader of the victim record (control). */
  owner: FloorActor
  /** Unauthorized reader (probe). */
  probe: FloorActor
  /** Peer whose same-route read must be denied; defaults to a peer of `probe`. */
  denied?: FloorActor
  /** The probe actor's own record, used as the disclosure baseline. */
  baselinePathAndQuery?: string
  requiredRole?: RoleName
  resourceTenant?: string
  proofPatterns?: string[]
  oracleEvents?: string[]
}

export interface RedirectArgs extends FloorRecipeBaseArgs {
  actor: FloorActor
  /** Same-origin control request; defaults to `pathAndQuery`. */
  controlPathAndQuery?: string
  /** Probe request carrying the attacker-controlled destination; defaults to `pathAndQuery`. */
  probePathAndQuery?: string
  /** Optional canary host the `Location` must match (a regex is derived from it). */
  canaryHost?: string
}

export interface FloorBrowserStep {
  role: 'control' | 'probe'
  action: 'navigate' | 'fill' | 'click'
  pathAndQuery?: string
  selector?: string
  value?: string
  waitAfterLoadMs?: number
  reusePage?: boolean
  persona?: string
}

export interface FloorBrowserSessionResult {
  traces: ReceiptBrowserTrace[]
  /** True when a cited probe trace recorded the canary reaching an executable sink. */
  sinkHit: boolean
}

export interface BrowserSinkArgs extends FloorRecipeBaseArgs {
  actor: FloorActor
  /** URL the browser session loads; defaults to `origin + pathAndQuery`. */
  url?: string
  /** Sink names the host trace must contain (e.g. `dom_xss`, `postmessage`). */
  expectSinks?: readonly string[]
  /** Marker the driver looks for in the trace (never a payload). */
  marker?: string
  /** Ordered browser steps (navigate / fill / click); `{{canary_token}}` is interpolated. */
  steps?: readonly FloorBrowserStep[]
  /** Verifier-minted canary substituted into the steps and required in the probe sink. */
  canaryToken?: string
}

export interface InjectionFingerprintArgs extends FloorRecipeBaseArgs {
  actor: FloorActor
  /** The injected value (the payload itself; sent only to the target). */
  payload: string
  /** Benign value for the control arm; defaults to `kovo-benign`. */
  controlValue?: string
  /** Injection family used to select the fingerprint vocabulary. */
  family?: InjectionFamily
  /** JSON body template; `param` is replaced per arm. */
  jsonBody?: unknown
}

export interface FloorRecipeArgsMap {
  access_boundary: AccessBoundaryArgs
  persisted_mutation: PersistedMutationArgs
  boolean_or_timing: BooleanOrTimingArgs
  oob_callback: OobCallbackArgs
  race_burst: RaceBurstArgs
  disclosure: DisclosureArgs
}

export interface Cut3FloorRecipeArgsMap {
  redirect: RedirectArgs
  browser_sink: BrowserSinkArgs
  injection_fingerprint: InjectionFingerprintArgs
  conserved_balance: ConservedBalanceArgs
}

export type Cut3FloorRecipeArgs = Cut3FloorRecipeArgsMap[Cut3FloorRecipeId]

export type FloorRecipeArgs = FloorRecipeArgsMap[FloorRecipeId]

export interface FloorRecipeStep {
  exchangeId: string
  role: string
  arm: FloorArm
  request: FloorRequestSpec
  exchange: FloorExchange
  step: ImpactStep
}

/** A recipe is `{ id, args, run(ctx) }`; `run` only talks to Layer 1 through `ctx`. */
export interface FloorRecipe {
  readonly id: FloorRecipeId
  readonly args: FloorRecipeArgs
  run(ctx: FloorRecipeContext): Promise<ProofReceipt>
}

export type FloorRequireSide = 'control' | 'probe' | 'harness'

export interface FloorRecipeRequireFailure {
  role: string
  side: FloorRequireSide
  message: string
}

export interface FloorRecipeContext {
  readonly args: FloorRecipeArgs
  /** Exchanges recorded so far (bounded). */
  readonly steps: readonly FloorRecipeStep[]
  /** Host exchange ids recorded so far, in order. */
  readonly exchangeIds: readonly string[]
  send(spec: FloorRequestSpec): Promise<FloorRecipeStep>
  /** Execute 2..8 requests concurrently (via `deps.burst` when wired, else `Promise.all`). */
  sendBurst(specs: readonly FloorRequestSpec[]): Promise<FloorRecipeStep[]>
  oob(query: FloorOobQuery): Promise<ReceiptOobEvent | null>
  /** Record (and cite) a host-recorded browser trace; null when the host produced none. */
  browser(input: FloorBrowserInput): Promise<ReceiptBrowserTrace | null>
  /** Run an ordered browser session through the host seam. */
  browserSession(input: {
    origin: string
    steps: readonly FloorBrowserStep[]
    canaryToken: string
    actor: FloorActor
  }): Promise<FloorBrowserSessionResult | null>
  /**
   * Record a preconditions the oracle needs that the receipt gate alone cannot name. Returns the
   * condition so a recipe can continue gathering the rest of the minimum evidence.
   */
  require(condition: boolean, role: string, message: string, side?: FloorRequireSide): boolean
}

export interface FloorRecipeStepRecord {
  exchangeId: string
  role: string
  arm: FloorArm
  method: string
  pathAndQuery: string
  status: number | null
  durationMs: number | null
}

export interface FloorRecipeRunResult {
  recipeId: FloorRecipeId
  confirmed: boolean
  steps: FloorRecipeStepRecord[]
  exchangeIds: string[]
  oobEventIds: string[]
  transcript: ReceiptTranscript
  verification: ReceiptVerification
}

export type FloorRecipeFailureCode =
  | 'receipt_rejected'
  | 'precondition_unsatisfied'
  | 'step_budget_exceeded'
  | 'recipe_error'

export interface FloorRecipeFailure {
  code: FloorRecipeFailureCode
  message: string
  /** Evidence roles the proof lacked, named so a repair can add exactly those. */
  missingRoles: string[]
  /** Side-tagged failed `ctx.require` preconditions (R2-H-15 / H-19 retest health). */
  requireFailures?: FloorRecipeRequireFailure[]
}

export interface FloorRecipeExecution {
  result: FloorRecipeRunResult
  receipt: ProofReceipt
  failure?: FloorRecipeFailure
}

/** Hard bound: no recipe may exceed this many exchanges in one run. */
export const MAX_FLOOR_RECIPE_STEPS = 16
/** Race bursts are clamped: a wider burst is not more evidence, only more traffic. */
export const MAX_RACE_BURST = 8
export const MIN_RACE_BURST = 2

// ---------------------------------------------------------------------------
// Context implementation
// ---------------------------------------------------------------------------

class FloorRecipeAbort extends Error {
  readonly code: FloorRecipeFailureCode
  readonly missingRoles: string[]

  constructor(code: FloorRecipeFailureCode, message: string, missingRoles: string[]) {
    super(message)
    this.name = 'FloorRecipeAbort'
    this.code = code
    this.missingRoles = missingRoles
  }
}

interface RecordedMissing {
  roles: string[]
  side: FloorRequireSide
  message: string
}

function inferRequireSide(role: string): FloorRequireSide {
  if (/control|baseline|entitled|reset/i.test(role)) return 'control'
  if (/probe|tautology|contradiction|burst|sink|callback/i.test(role)) return 'probe'
  return 'harness'
}

class RecipeContext implements FloorRecipeContext {
  readonly args: FloorRecipeArgs
  readonly steps: FloorRecipeStep[] = []
  readonly missing: RecordedMissing[] = []
  private readonly deps: FloorRecipeDeps
  private readonly entries: ReceiptTranscriptEntry[] = []
  private readonly oobEvents: ReceiptOobEvent[] = []
  private readonly traces: ReceiptBrowserTrace[] = []
  private exchangeCount = 0

  constructor(args: FloorRecipeArgs, deps: FloorRecipeDeps) {
    this.args = args
    this.deps = deps
  }

  get exchangeIds(): string[] {
    return this.steps.map(step => step.exchangeId)
  }

  get oobEventIds(): string[] {
    return this.oobEvents.map(event => event.id)
  }

  transcript(): ReceiptTranscript {
    return {
      entries: [...this.entries],
      oobEvents: [...this.oobEvents],
      ...(this.traces.length > 0 ? { browserTraces: [...this.traces] } : {}),
    }
  }

  private recordExchange(spec: FloorRequestSpec, exchange: FloorExchange, index: number, measuredDurationMs?: number): FloorRecipeStep {
    const exchangeId = exchange.exchangeId
      ?? this.deps.nextExchangeId?.()
      ?? `fr-${index}`
    const route = exchange.route ?? pathOnly(spec.pathAndQuery)
    const step: ImpactStep = {
      id: `s${index}:${spec.role}`,
      arm: spec.arm,
      method: spec.method.toUpperCase(),
      route,
      pathAndQuery: spec.pathAndQuery,
      status: exchange.status,
      actor: {
        handle: ANONYMOUS_ACTOR_HANDLES.has(spec.actor.handle.trim().toLowerCase()) ? null : spec.actor.handle,
        role: spec.actor.role ?? null,
        tenant: spec.actor.tenant ?? null,
        auth: spec.actor.auth ?? 'unknown',
        sameSite: spec.actor.sameSite ?? null,
      },
      ...(exchange.json !== undefined ? { json: exchange.json } : {}),
      ...(exchange.body !== undefined
        ? { body: exchange.body }
        : exchange.json !== undefined
          ? { body: JSON.stringify(exchange.json) }
          : {}),
      ...(spec.jsonBody !== undefined ? { requestJson: spec.jsonBody } : {}),
      ...(spec.headers ? { requestHeaders: spec.headers } : {}),
      ...(exchange.responseHeaders ? { responseHeaders: exchange.responseHeaders } : {}),
      ...(exchange.secretMatches?.length ? { secretMatches: exchange.secretMatches.slice(0, 16) } : {}),
      evidenceRole: spec.role,
    }
    const recorded: FloorRecipeStep = {
      exchangeId,
      role: spec.role,
      arm: spec.arm,
      request: spec,
      exchange,
      step,
    }
    this.steps.push(recorded)
    this.entries.push({
      exchangeId,
      step,
      durationMs: exchange.durationMs ?? measuredDurationMs ?? 0,
      carrierText: exchange.carrierText ?? carrierTextOf(spec),
      evidenceRole: spec.role,
    })
    return recorded
  }

  async send(spec: FloorRequestSpec): Promise<FloorRecipeStep> {
    if (this.exchangeCount >= MAX_FLOOR_RECIPE_STEPS) {
      throw new FloorRecipeAbort(
        'step_budget_exceeded',
        `Recipe exceeded the ${MAX_FLOOR_RECIPE_STEPS}-exchange budget.`,
        ['step_budget'],
      )
    }
    if (!spec.pathAndQuery.trim()) {
      throw new FloorRecipeAbort('recipe_error', `Recipe sent an empty path for role ${spec.role}.`, [spec.role])
    }
    this.exchangeCount += 1
    const index = this.exchangeCount
    const startedAt = Date.now()
    const exchange = await this.deps.request(spec)
    return this.recordExchange(spec, exchange, index, Math.max(0, Date.now() - startedAt))
  }

  async sendBurst(specs: readonly FloorRequestSpec[]): Promise<FloorRecipeStep[]> {
    if (specs.length === 0) return []
    if (this.exchangeCount + specs.length > MAX_FLOOR_RECIPE_STEPS) {
      throw new FloorRecipeAbort(
        'step_budget_exceeded',
        `Recipe exceeded the ${MAX_FLOOR_RECIPE_STEPS}-exchange budget.`,
        ['step_budget'],
      )
    }
    for (const spec of specs) {
      if (!spec.pathAndQuery.trim()) {
        throw new FloorRecipeAbort('recipe_error', `Recipe sent an empty path for role ${spec.role}.`, [spec.role])
      }
    }
    const startIndex = this.exchangeCount + 1
    this.exchangeCount += specs.length
    const exchanges = this.deps.burst
      ? await this.deps.burst(specs)
      : await Promise.all(specs.map(spec => Promise.resolve(this.deps.request(spec))))
    return specs.map((spec, idx) => this.recordExchange(spec, exchanges[idx]!, startIndex + idx))
  }

  async oob(query: FloorOobQuery): Promise<ReceiptOobEvent | null> {
    const event = this.deps.oob ? await this.deps.oob(query) : null
    if (event && !this.oobEvents.some(existing => existing.id === event.id)) this.oobEvents.push(event)
    return event
  }

  async browser(input: FloorBrowserInput): Promise<ReceiptBrowserTrace | null> {
    const trace = this.deps.browserTrace ? await this.deps.browserTrace(input) : null
    if (trace && !this.traces.some(existing => existing.id === trace.id)) this.traces.push(trace)
    return trace
  }

  async browserSession(input: {
    origin: string
    steps: readonly FloorBrowserStep[]
    canaryToken: string
    actor: FloorActor
  }): Promise<FloorBrowserSessionResult | null> {
    const result = this.deps.browserSession ? await this.deps.browserSession(input) : null
    if (result) for (const trace of result.traces) {
      if (!this.traces.some(existing => existing.id === trace.id)) this.traces.push(trace)
    }
    return result
  }

  require(condition: boolean, role: string, message: string, side?: FloorRequireSide): boolean {
    if (!condition) this.missing.push({ roles: [role], side: side ?? inferRequireSide(role), message })
    return condition
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function deriveDifferingParam(controlPath: string, probePath: string): string | null {
  try {
    const control = new URL(controlPath, 'http://kovo.invalid').searchParams
    const probe = new URL(probePath, 'http://kovo.invalid').searchParams
    const keys = new Set([...control.keys(), ...probe.keys()])
    for (const key of keys) {
      if (control.get(key) !== probe.get(key)) return key
    }
  } catch { /* not URL-shaped */ }
  return null
}

function pathOnly(pathAndQuery: string): string {
  return pathAndQuery.split('?')[0]!.split('#')[0]!.replace(/\/+$/, '') || '/'
}

function carrierTextOf(spec: FloorRequestSpec): string {
  const parts = [`${spec.method.toUpperCase()} ${spec.pathAndQuery}`]
  if (spec.headers && Object.keys(spec.headers).length > 0) {
    parts.push(Object.entries(spec.headers).map(([name, value]) => `${name}: ${value}`).join('\n'))
  }
  if (spec.jsonBody !== undefined) parts.push(JSON.stringify(spec.jsonBody))
  if (spec.textBody !== undefined) parts.push(spec.textBody)
  return parts.join('\n')
}

function isSuccess(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300
}

function isDenied(status: number | null): boolean {
  return status === 401 || status === 403 || status === 404
}

function peerOf(actor: FloorActor, suffix = 'peer'): FloorActor {
  return { ...actor, handle: `${actor.handle}-${suffix}` }
}

function uniqueRoles(values: readonly string[]): string[] {
  return [...new Set(values.filter(value => value.length > 0))]
}

function assertBoundedText(label: string, value: string, max: number): string {
  if (!value.trim() || value.length > max) {
    throw new FloorRecipeAbort('recipe_error', `${label} must be 1..${max} characters.`, [label])
  }
  return value
}

/** The probe/control actor is a fixture in tests; real runs resolve it at Layer 1. */
const ANONYMOUS: FloorActor = { handle: 'anon' }

function targetOf(args: FloorRecipeBaseArgs): ProofReceipt['target'] {
  return {
    origin: args.origin,
    method: args.method.toUpperCase(),
    pathAndQuery: assertBoundedText('pathAndQuery', args.pathAndQuery, 4096),
    ...(args.param ? { param: args.param } : {}),
  }
}

// ---------------------------------------------------------------------------
// Recipe definitions
// ---------------------------------------------------------------------------

interface FloorRecipeDefinition<A extends FloorRecipeBaseArgs> {
  readonly id: FloorRecipeId
  run(args: A, ctx: FloorRecipeContext): Promise<ProofReceipt>
}

function defineRecipe<A extends FloorRecipeBaseArgs>(
  id: string,
  run: (args: A, ctx: FloorRecipeContext) => Promise<ProofReceipt>,
): FloorRecipeDefinition<A> {
  return { id: id as FloorRecipeId, run }
}

/**
 * Vertical/object access boundary: the entitled control is served, a peer control is denied on the
 * same route, and the lower-privileged probe is served. The impact oracle needs the denied sibling
 * (or a role/tenant differential); the recipe asserts the boundary before the receipt gate sees it.
 */
const accessBoundary = defineRecipe<AccessBoundaryArgs>('access_boundary', async (args, ctx) => {
  const deniedActor = args.denied ?? peerOf(args.probe)
  const deniedMethod = (args.deniedMethod ?? args.method).toUpperCase()
  const deniedPath = args.deniedPathAndQuery ?? args.pathAndQuery
  // H-17: Never allow the denied control arm to be the owner re-reading the exact same method & path.
  if (
    deniedActor.handle === args.owner.handle
    && deniedMethod === args.method.toUpperCase()
    && deniedPath === args.pathAndQuery
  ) {
    throw new FloorRecipeAbort(
      'recipe_error',
      'access_boundary denied control actor cannot equal owner on the same method and path.',
      ['denied_control'],
    )
  }
  const entitled = await ctx.send({
    arm: 'control',
    role: 'entitled_read',
    method: args.method,
    pathAndQuery: args.pathAndQuery,
    actor: args.owner,
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const denied = await ctx.send({
    arm: 'control',
    role: 'denied_control',
    method: args.deniedMethod ?? args.method,
    pathAndQuery: deniedPath,
    actor: deniedActor,
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const probe = await ctx.send({
    arm: 'probe',
    role: 'probe_request',
    method: args.method,
    pathAndQuery: args.pathAndQuery,
    actor: args.probe,
    ...(args.headers ? { headers: args.headers } : {}),
  })

  ctx.require(isSuccess(entitled.exchange.status), 'entitled_read', 'The entitled control was not served the resource.', 'control')
  const deniedBody = denied.exchange.body ?? ''
  const distinctControl = isSuccess(denied.exchange.status) && deniedBody.length > 2 && deniedBody !== (entitled.exchange.body ?? '')
  const controlOk = isDenied(denied.exchange.status) || (args.controlEvidence === 'denial_or_distinct' && distinctControl)
  ctx.require(controlOk, 'denied_control', `The control arm returned ${denied.exchange.status ?? 'no status'} without a denial or a distinct selective body.`, 'control')
  ctx.require(isSuccess(probe.exchange.status), 'probe_request', `The probe actor was not served the resource (${probe.exchange.status ?? 'no status'}).`, 'probe')

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [entitled.exchangeId, denied.exchangeId, probe.exchangeId],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: `${args.probe.handle} was served ${args.method.toUpperCase()} ${pathOnly(args.pathAndQuery)} while an authenticated control arm on the same ${args.deniedPathAndQuery ? 'resource family' : 'route'} was denied.`,
    ...(args.requiredRole ? { requiredRole: args.requiredRole } : {}),
    ...(args.resourceTenant ? { resourceTenant: args.resourceTenant } : {}),
    ...(args.expectControlDenied !== undefined ? { expectControlDenied: args.expectControlDenied } : {}),
    ...(args.oracleEvents ? { oracleEvents: args.oracleEvents } : {}),
  })
})

/**
 * Persisted mutation: baseline read, mutating probe carrying the candidate body, and a separate
 * post-mutation readback. The readback (not the mutation echo) is what the impact oracle accepts.
 */
const persistedMutation = defineRecipe<PersistedMutationArgs>('persisted_mutation', async (args, ctx) => {
  const baselinePath = args.baselinePathAndQuery ?? args.pathAndQuery
  const baselineMethod = args.baselineMethod ?? 'GET'
  const readbackPath = args.readbackPathAndQuery ?? baselinePath
  const readbackMethod = args.readbackMethod ?? baselineMethod
  const readbackActor = args.readbackActor ?? args.actor
  const bodyKeys = Object.keys(args.body).slice(0, 8)

  // A self-service function state persists on the caller's own session, so a stale target value
  // from the probe phase would make a correct mutation look like an idempotent no-op. The reset is
  // a control write that restores the actor's own baseline before the pre-read.
  if (args.reset) {
    const reset = await ctx.send({
      arm: 'control',
      role: 'state_reset',
      method: args.reset.method ?? args.method,
      pathAndQuery: args.pathAndQuery,
      actor: args.reset.actor ?? args.actor,
      jsonBody: args.reset.body,
      ...(args.headers ? { headers: args.headers } : {}),
    })
    ctx.require(isSuccess(reset.exchange.status), 'state_reset', `The state reset was not accepted (${reset.exchange.status ?? 'no status'}).`, 'control')
  }
  // A baseline write makes the probe body a genuine delta: the pre-read then holds a known
  // different value, and the persistence oracle can attribute the post-read change to the probe.
  if (args.baselineWrite) {
    const baselineWrite = await ctx.send({
      arm: 'control',
      role: 'baseline_write',
      method: args.baselineWrite.method ?? args.method,
      pathAndQuery: args.pathAndQuery,
      actor: args.baselineWrite.actor ?? args.actor,
      jsonBody: args.baselineWrite.body,
      ...(args.headers ? { headers: args.headers } : {}),
    })
    ctx.require(isSuccess(baselineWrite.exchange.status), 'baseline_write', `The baseline write was not accepted (${baselineWrite.exchange.status ?? 'no status'}).`, 'control')
  }

  const baseline = await ctx.send({
    arm: 'control',
    role: 'baseline_read',
    method: baselineMethod,
    pathAndQuery: baselinePath,
    actor: readbackActor,
  })
  const probe = await ctx.send({
    arm: 'probe',
    role: 'mutation_probe',
    method: args.method,
    pathAndQuery: args.pathAndQuery,
    actor: args.actor,
    jsonBody: args.body,
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const after = await ctx.send({
    arm: 'control',
    role: 'post_mutation_read',
    method: readbackMethod,
    pathAndQuery: readbackPath,
    actor: readbackActor,
  })

  ctx.require(baseline.exchange.json !== undefined, 'baseline_read', 'The pre-mutation baseline read recorded no JSON body.', 'control')
  ctx.require(isSuccess(probe.exchange.status), 'mutation_probe', `The mutating probe was not accepted (${probe.exchange.status ?? 'no status'}).`, 'probe')
  // A DELETE's separate readback proves persistence by reporting the resource gone; a 404/410
  // tombstone need not carry a JSON body (the persistence oracle handles that case).
  const tombstone = args.method.toUpperCase() === 'DELETE' &&
    (after.exchange.status === 404 || after.exchange.status === 410)
  ctx.require(after.exchange.json !== undefined || tombstone, 'post_mutation_read', 'The separate post-mutation GET recorded no JSON body.', 'control')

  // An identity-assumption route (impersonate / act-as / tenant switch) pins the acting scope on
  // the caller's *session*. The reset above re-establishes the actor's own baseline before the
  // proof; the mutation itself then leaves the caller acting as the target tenant, so every later
  // read by that persona would be served another tenant's data — the scope bleed. Restore the
  // baseline again after the observation and before control returns to the run, so no later probe
  // (by this persona or the next one) is served the wrong tenant.
  if (args.reset) {
    await ctx.send({
      arm: 'cleanup',
      role: 'state_restore',
      method: args.reset.method ?? args.method,
      pathAndQuery: args.pathAndQuery,
      actor: args.reset.actor ?? args.actor,
      jsonBody: args.reset.body,
      ...(args.headers ? { headers: args.headers } : {}),
    })
  }

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [...ctx.exchangeIds],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: `The probe persisted request field(s) ${bodyKeys.join(', ') || '(none)'} and a separate readback observed the change.`,
    ...(args.requiredRole ? { requiredRole: args.requiredRole } : {}),
    ...(args.resourceTenant ? { resourceTenant: args.resourceTenant } : {}),
    ...(args.expectControlDenied !== undefined ? { expectControlDenied: args.expectControlDenied } : {}),
    ...(args.oracleEvents ? { oracleEvents: args.oracleEvents } : {}),
    ...(args.proofPatterns ? { proofPatterns: args.proofPatterns } : {}),
  })
})

/**
 * Boolean-or-timing SQL injection. Timing uses host-recorded durations (>3x separation); boolean
 * uses paired rounds whose structural response difference must reproduce with a stable control.
 */
/** Build one arm, honouring a full per-arm override when the carrier is not path/JSON. */
function armRequest(
  args: BooleanOrTimingArgs,
  arm: 'control' | 'probe',
  fallbackPath: string,
  fallbackJson: unknown,
  actor: FloorActor,
  role?: string,
): FloorRequestSpec {
  const override = arm === 'control' ? args.controlRequest : args.probeRequest
  const jsonBody = override?.jsonBody !== undefined ? override.jsonBody : fallbackJson
  return {
    arm,
    role: role ?? (arm === 'control' ? 'boolean_control' : 'boolean_probe'),
    method: args.method,
    pathAndQuery: override?.pathAndQuery ?? fallbackPath,
    actor,
    ...(override?.headers ?? args.headers ? { headers: { ...(args.headers ?? {}), ...(override?.headers ?? {}) } } : {}),
    ...(jsonBody !== undefined ? { jsonBody } : {}),
    ...(override?.textBody !== undefined ? { textBody: override.textBody } : {}),
    ...(override?.session ?? args.session ? { session: override?.session ?? args.session } : {}),
    ...((override?.csrfBind ?? args.csrfBind) ? { csrfBind: true } : {}),
  }
}

const booleanOrTiming = defineRecipe<BooleanOrTimingArgs>('boolean_or_timing', async (args, ctx) => {
  const actor = args.actor ?? ANONYMOUS
  const controlPath = args.controlPathAndQuery ?? args.pathAndQuery
  const probePath = args.probePathAndQuery ?? args.pathAndQuery
  if (args.session && args.primePath) {
    // Prime the jar (cookies + hidden CSRF token) before any arm; not part of the receipt.
    await ctx.send({
      arm: 'setup',
      role: 'session_prime',
      method: 'GET',
      pathAndQuery: args.primePath,
      actor,
      ...(args.headers ? { headers: args.headers } : {}),
    })
  }

  if (args.mode === 'boolean') {
    const param = args.param ?? deriveDifferingParam(controlPath, probePath)
    ctx.require(
      Boolean(param),
      'injected_parameter',
      'A boolean SQL injection proof must name the injected parameter (or vary exactly one query key).',
      'harness',
    )
    const rounds = Math.max(2, Math.min(4, Math.floor(args.rounds ?? 2)))
    const exchangeIds: string[] = []
    let serverError = false
    for (let round = 0; round < rounds; round += 1) {
      const control = await ctx.send(armRequest(args, 'control', controlPath, args.controlJsonBody, actor))
      const probe = await ctx.send(armRequest(args, 'probe', probePath, args.probeJsonBody, actor))
      exchangeIds.push(control.exchangeId, probe.exchangeId)
      if ((control.exchange.status ?? 0) >= 500 || (probe.exchange.status ?? 0) >= 500) serverError = true
    }
    ctx.require(!serverError, 'non_error_arm', 'A boolean differential arm returned a server error (5xx).', 'harness')
    return buildProofReceipt({
      vulnClass: args.receiptClass ?? 'sqli',
      target: { ...targetOf(args), ...(param ? { param } : {}) },
      exchangeIds,
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: `The boolean SQL predicate changed the response structure across ${rounds} paired rounds while the baseline predicate stayed stable.`,
    })
  }

  if (args.mode === 'status') {
    const param = args.param ?? deriveDifferingParam(controlPath, probePath)
    ctx.require(
      Boolean(param),
      'injected_parameter',
      'A status-only boolean proof must name the injected parameter (or vary exactly one query key).',
      'harness',
    )
    const rounds = Math.max(2, Math.min(4, Math.floor(args.rounds ?? 2)))
    const contradictionPath = args.contradictionPathAndQuery ?? probePath
    const exchangeIds: string[] = []
    for (let round = 0; round < rounds; round += 1) {
      // The benign baseline is what separates a predicate contrast from a single malformed request:
      // it is the same request without the boolean operator and must answer 2xx.
      const benign = await ctx.send(armRequest(args, 'control', controlPath, args.controlJsonBody, actor, 'benign_baseline'))
      const tautology = await ctx.send(armRequest(args, 'probe', probePath, args.probeJsonBody, actor, 'tautology'))
      const contradiction = await ctx.send(armRequest(args, 'probe', contradictionPath, args.contradictionJsonBody, actor, 'contradiction'))
      exchangeIds.push(benign.exchangeId, tautology.exchangeId, contradiction.exchangeId)
      ctx.require(isSuccess(benign.exchange.status), 'benign_baseline', `The benign baseline returned ${benign.exchange.status ?? 'no status'} instead of a 2xx.`, 'control')
      ctx.require(isSuccess(tautology.exchange.status), 'tautology', `The tautology arm returned ${tautology.exchange.status ?? 'no status'} instead of a 2xx.`, 'probe')
      ctx.require(
        contradiction.exchange.status !== null && contradiction.exchange.status >= 400 && contradiction.exchange.status < 500,
        'contradiction',
        `The contradiction arm returned ${contradiction.exchange.status ?? 'no status'}; only a 4xx predicate failure is the paired status shape (a 5xx is a malformed request).`,
        'probe',
      )
    }
    return buildProofReceipt({
      vulnClass: args.receiptClass ?? 'sqli_status',
      target: { ...targetOf(args), ...(param ? { param } : {}) },
      exchangeIds,
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: `The tautology predicate kept the benign status across ${rounds} rounds while the contradiction predicate failed on the same request shape.`,
    })
  }

  const control = await ctx.send(armRequest(args, 'control', controlPath, args.controlJsonBody, actor, 'timing_control'))
  const probe = await ctx.send(armRequest(args, 'probe', probePath, args.probeJsonBody, actor, 'timing_probe'))

  return buildProofReceipt({
    vulnClass: args.receiptClass ?? args.vulnClass,
    target: targetOf(args),
    exchangeIds: [control.exchangeId, probe.exchangeId],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'The conditional SQL payload produced a stable >3x response delay against the control arm.',
  })
})

/**
 * Out-of-band callback: one probe exchange must carry the injected canary token, and the host must
 * have a delivered durable callback for that same token, after the injection.
 */
const oobCallback = defineRecipe<OobCallbackArgs>('oob_callback', async (args, ctx) => {
  const inject = await ctx.send({
    arm: 'probe',
    role: 'injection_exchange',
    method: args.method,
    pathAndQuery: args.injectPathAndQuery ?? args.pathAndQuery,
    actor: args.actor ?? ANONYMOUS,
    ...(args.injectJsonBody !== undefined ? { jsonBody: args.injectJsonBody } : {}),
    ...(args.injectTextBody !== undefined ? { textBody: args.injectTextBody } : {}),
    ...((args.injectHeaders ?? args.headers) ? { headers: args.injectHeaders ?? args.headers } : {}),
  })
  const event = await ctx.oob({ token: args.token })

  ctx.require(event !== null, 'delivered_callback', 'No durable OOB event was delivered for the injected canary token.', 'probe')
  if (event) {
    ctx.require(event.delivered, 'delivered_callback', `OOB event ${event.id} was recorded but not delivered.`, 'probe')
    const injectedAt = event.injectedAtMs
    if (injectedAt !== undefined) {
      ctx.require(event.receivedAtMs >= injectedAt, 'callback_causality', `OOB event ${event.id} arrived before the canary was injected.`, 'harness')
    }
  }

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [inject.exchangeId],
    oobEventIds: event ? [event.id] : [],
    browserTraceIds: [],
    claimedDelta: `The injected canary ${args.token} was fetched out of band after the probe exchange carried it.`,
    ...(event?.injectedAtMs !== undefined ? { injectedAtMs: event.injectedAtMs } : {}),
    ...(args.oracleEvents ? { oracleEvents: args.oracleEvents } : {}),
  })
})

/** Distinct outcome signature for a burst request (status + stable body). */
function outcomeOf(step: FloorRecipeStep): string {
  return `${step.exchange.status ?? 'none'}:${JSON.stringify(step.exchange.json ?? step.exchange.body ?? null)}`
}

/**
 * Synchronized race burst: identical terminal transitions sent together. The receipt confirms the
 * repeated terminal transition (business-logic impact); the recipe separately requires a divergent
 * outcome set, because a burst where everything succeeded/failed uniformly proves no race.
 */
function interpolateVarString(template: string, vars: Readonly<Record<string, string>>): string {
  return template.replace(/\{\{([A-Za-z0-9_.-]+)\}\}/g, (match, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? vars[name]! : match)
}

function interpolateVarValue(value: unknown, vars: Readonly<Record<string, string>>): unknown {
  if (typeof value === 'string') return interpolateVarString(value, vars)
  if (Array.isArray(value)) return value.map(item => interpolateVarValue(item, vars))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = interpolateVarValue(v, vars)
    }
    return out
  }
  return value
}

function extractVarPath(json: unknown, selector: string): string | null {
  if (!json || typeof json !== 'object') return null
  let cur: unknown = json
  for (const seg of selector.split('.')) {
    if (!cur || typeof cur !== 'object') return null
    cur = (cur as Record<string, unknown>)[seg]
  }
  if (typeof cur === 'string' && cur.length > 0) return cur
  if (typeof cur === 'number' && Number.isFinite(cur)) return String(cur)
  return null
}

function buildStepRequest(
  step: ConservedBalanceStepSpec,
  arm: FloorArm,
  role: string,
  defaultActor: FloorActor,
  defaultHeaders: Record<string, string> | undefined,
  vars: Readonly<Record<string, string>>,
): FloorRequestSpec {
  const mergedHeaders = { ...(defaultHeaders ?? {}), ...(step.headers ?? {}) }
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(mergedHeaders)) headers[k] = interpolateVarString(v, vars)
  return {
    arm,
    role,
    method: step.method,
    pathAndQuery: interpolateVarString(step.pathAndQuery, vars),
    actor: step.actor ?? defaultActor,
    ...(step.jsonBody !== undefined ? { jsonBody: interpolateVarValue(step.jsonBody, vars) } : {}),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
}

async function runSetupSequence(
  ctx: FloorRecipeContext,
  setupSteps: readonly ConservedBalanceStepSpec[] | undefined,
  defaultActor: FloorActor,
  defaultHeaders: Record<string, string> | undefined,
  vars: Record<string, string>,
): Promise<void> {
  for (let i = 0; i < (setupSteps?.length ?? 0); i += 1) {
    const spec = setupSteps![i]!
    const res = await ctx.send(buildStepRequest(spec, 'setup', `setup_${i + 1}`, defaultActor, defaultHeaders, vars))
    for (const ex of spec.extract ?? []) {
      const parsed = res.exchange.json ?? (typeof res.exchange.body === 'string' ? (() => { try { return JSON.parse(res.exchange.body) } catch { return undefined } })() : undefined)
      const val = extractVarPath(parsed, ex.selector)
      if (val !== null) vars[ex.varName] = val
    }
  }
}

async function runCleanupSequence(
  ctx: FloorRecipeContext,
  cleanupSteps: readonly ConservedBalanceStepSpec[] | undefined,
  defaultActor: FloorActor,
  defaultHeaders: Record<string, string> | undefined,
  vars: Readonly<Record<string, string>>,
): Promise<void> {
  for (let i = 0; i < (cleanupSteps?.length ?? 0); i += 1) {
    try {
      await ctx.send(buildStepRequest(cleanupSteps![i]!, 'cleanup', `cleanup_${i + 1}`, defaultActor, defaultHeaders, vars))
    } catch {
      // Cleanup is best-effort and must never mask the primary verdict.
    }
  }
}

function buildBurstSpecs(
  args: { method: string; pathAndQuery: string; actor: FloorActor; body: unknown; headers?: Record<string, string> },
  count: number,
  vars: Readonly<Record<string, string>>,
): FloorRequestSpec[] {
  const burstPath = interpolateVarString(args.pathAndQuery, vars)
  const burstBody = interpolateVarValue(args.body, vars)
  return Array.from({ length: count }, (_, index) => ({
    arm: 'probe' as const,
    role: `burst_${index + 1}`,
    method: args.method,
    pathAndQuery: burstPath,
    actor: args.actor,
    jsonBody: burstBody,
    ...(args.headers ? { headers: args.headers } : {}),
  }))
}

const raceBurst = defineRecipe<RaceBurstArgs>('race_burst', async (args, ctx) => {
  const count = Math.min(MAX_RACE_BURST, Math.max(MIN_RACE_BURST, Math.trunc(args.burst)))
  const vars: Record<string, string> = {}
  await runSetupSequence(ctx, args.setupSteps, args.actor, args.headers, vars)
  let steps: FloorRecipeStep[] = []
  try {
    steps = await ctx.sendBurst(buildBurstSpecs(args, count, vars))
  } finally {
    await runCleanupSequence(ctx, args.cleanupSteps, args.actor, args.headers, vars)
  }
  const successes = steps.filter(step => isSuccess(step.exchange.status))
  const distinct = new Set(steps.map(outcomeOf)).size

  ctx.require(successes.length >= 2, 'burst_repeat', `Only ${successes.length} of ${count} burst requests were accepted; a race needs the terminal transition accepted twice.`, 'probe')
  ctx.require(distinct >= 2, 'burst_divergence', `The burst produced ${distinct} distinct outcome(s); a uniform burst is not race evidence.`, 'probe')

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: steps.map(step => step.exchangeId),
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: `A synchronized burst of ${count} identical ${args.method.toUpperCase()} ${pathOnly(args.pathAndQuery)} requests was accepted ${successes.length} times with ${distinct} distinct outcomes.`,
    ...(args.oracleEvents ? { oracleEvents: args.oracleEvents } : { oracleEvents: ['invariant_violation', 'state_delta'] }),
  })
})

/**
 * Read disclosure: an entitled control serves the victim record, a peer is denied on the same
 * route, and the probe receives an owner-scoped non-public attribute bound to the victim. The
 * probe's own record is the baseline so a body difference alone cannot satisfy the oracle.
 */
const disclosure = defineRecipe<DisclosureArgs>('disclosure', async (args, ctx) => {
  const baseline = await ctx.send({
    arm: 'control',
    role: 'probe_baseline',
    method: 'GET',
    pathAndQuery: args.baselinePathAndQuery ?? `${pathOnly(args.pathAndQuery)}/self`,
    actor: args.probe,
  })
  const entitled = await ctx.send({
    arm: 'control',
    role: 'entitled_read',
    method: args.method,
    pathAndQuery: args.pathAndQuery,
    actor: args.owner,
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const denied = await ctx.send({
    arm: 'control',
    role: 'denied_control',
    method: args.method,
    pathAndQuery: args.pathAndQuery,
    actor: args.denied ?? peerOf(args.probe),
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const probe = await ctx.send({
    arm: 'probe',
    role: 'probe_request',
    method: args.method,
    pathAndQuery: args.pathAndQuery,
    actor: args.probe,
    ...(args.headers ? { headers: args.headers } : {}),
  })

  ctx.require(baseline.exchange.json !== undefined, 'probe_baseline', 'The probe actor\'s own baseline read recorded no JSON body.', 'control')
  ctx.require(isSuccess(entitled.exchange.status), 'entitled_read', 'The entitled control was not served the victim record.', 'control')
  ctx.require(isDenied(denied.exchange.status), 'denied_control', `The peer control returned ${denied.exchange.status ?? 'no status'} instead of a denial.`, 'control')
  ctx.require(isSuccess(probe.exchange.status), 'probe_request', `The probe actor was not served the victim record (${probe.exchange.status ?? 'no status'}).`, 'probe')

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [baseline.exchangeId, entitled.exchangeId, denied.exchangeId, probe.exchangeId],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: `The probe read ${pathOnly(args.pathAndQuery)} and received owner-scoped non-public data while a same-route peer control was denied.`,
    ...(args.requiredRole ? { requiredRole: args.requiredRole } : {}),
    ...(args.resourceTenant ? { resourceTenant: args.resourceTenant } : {}),
    ...(args.proofPatterns ? { proofPatterns: args.proofPatterns } : {}),
    ...(args.oracleEvents ? { oracleEvents: args.oracleEvents } : {}),
  })
})


// ---------------------------------------------------------------------------
// Cut 3c/3d — redirect, browser sink, injection fingerprint
// ---------------------------------------------------------------------------

function headerValue(headers: Record<string, string> | null | undefined, name: string): string | null {
  if (!headers) return null
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name.toLowerCase() && typeof value === 'string' && value.length > 0) return value
  }
  return null
}

function hostOfLocation(location: string | null, origin: string): string | null {
  if (!location) return null
  try { return new URL(location, origin).host.toLowerCase() } catch { return null }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function isRedirectStatus(status: number | null): boolean {
  return status !== null && status >= 300 && status < 400
}

/** `http_chain` open_redirect / url_redirect → receipt `redirect` rule (off-origin Location). */
const redirect = defineRecipe<RedirectArgs>('redirect', async (args, ctx) => {
  const controlPath = args.controlPathAndQuery ?? args.pathAndQuery
  const probePath = args.probePathAndQuery ?? args.pathAndQuery
  const control = await ctx.send({
    arm: 'control',
    role: 'same_origin_control',
    method: args.method,
    pathAndQuery: controlPath,
    actor: args.actor,
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const probe = await ctx.send({
    arm: 'probe',
    role: 'redirect_probe',
    method: args.method,
    pathAndQuery: probePath,
    actor: args.actor,
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const probeLocation = headerValue(probe.exchange.responseHeaders, 'location')
  const controlLocation = headerValue(control.exchange.responseHeaders, 'location')
  const targetHost = hostOfLocation(args.origin, args.origin)
  const probeHost = hostOfLocation(probeLocation, args.origin)
  ctx.require(isRedirectStatus(probe.exchange.status), 'redirect_probe', `The probe returned ${probe.exchange.status ?? 'no status'} instead of a 3xx redirect.`, 'probe')
  ctx.require(Boolean(probeLocation), 'redirect_probe', 'The probe response carried no Location header; a 3xx status alone is not an open redirect.', 'probe')
  ctx.require(Boolean(probeHost) && probeHost !== targetHost, 'redirect_probe', `The Location ${probeLocation ?? '(none)'} stays on the target origin.`, 'probe')
  ctx.require(controlLocation !== probeLocation, 'same_origin_control', 'The same-origin control redirects to the same destination, so the destination is not attacker-controlled.', 'probe')
  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [control.exchangeId, probe.exchangeId],
    browserTraceIds: [],
    claimedDelta: `The probe redirected to ${probeLocation ?? 'no destination'} (off-origin) while the same-origin control ${controlLocation ? `redirected to ${controlLocation}` : 'stayed on origin'}.`,
    ...(args.canaryHost ? { proofPatterns: [escapeRegex(args.canaryHost)] } : {}),
  })
})

function requireExpectedSinks(ctx: FloorRecipeContext, sinks: readonly string[], expectSinks?: readonly string[]): void {
  if (!expectSinks || expectSinks.length === 0) return
  ctx.require(
    expectSinks.some(sink => sinks.includes(sink)),
    'browser_sink',
    `The trace recorded ${sinks.join(', ') || 'no sinks'}; expected one of ${expectSinks.join(', ')}.`,
    'probe',
  )
}

/** `browser_chain` / DOM sink → receipt `browser` rule over a host-recorded trace. */
const browserSink = defineRecipe<BrowserSinkArgs>('browser_sink', async (args, ctx) => {
  const browserClass = /^(?:browser_|dom_|postmessage|xss(?:_(?:reflected|stored))?$)/i.test(args.vulnClass)
  ctx.require(
    browserClass,
    'receipt_class',
    `browser_sink needs a browser-class label (dom_*/browser_*/postmessage*/xss*); ${args.vulnClass} maps to a different receipt rule.`,
    'harness',
  )
  const canaryToken = args.canaryToken
    ?? `kovo-dom-${createHash('sha256').update(`${args.origin}|${args.pathAndQuery}|${args.vulnClass}`).digest('hex').slice(0, 10)}`
  const interpolate = (value: string | undefined): string | undefined => value?.replaceAll('{{canary_token}}', canaryToken)
  const receiptVulnClass = /^(?:xss|xss_reflected|xss_stored|dom_xss)$/i.test(args.vulnClass)
    ? 'dom_xss'
    : args.vulnClass

  if (!args.steps || args.steps.length === 0) {
    const url = args.url ?? `${args.origin.replace(/\/+$/, '')}${args.pathAndQuery}`
    const trace = await ctx.browser({ origin: args.origin, url, actor: args.actor, ...(args.marker ? { marker: args.marker } : {}) })
    ctx.require(trace !== null, 'browser_trace', 'No host-recorded browser trace was produced for this origin.', 'harness')
    const sinks = trace?.sinks ?? []
    ctx.require(sinks.length > 0, 'browser_sink', 'The browser trace recorded no sink execution (DOM XSS, postMessage, storage write).', 'probe')
    requireExpectedSinks(ctx, sinks, args.expectSinks)
    return buildProofReceipt({
      vulnClass: receiptVulnClass,
      target: targetOf(args),
      exchangeIds: [],
      browserTraceIds: trace ? [trace.id] : [],
      claimedDelta: `The recorded browser trace executed ${sinks.join(', ') || 'no sink'} on ${url}.`,
    })
  }

  const normalized = args.steps.map(step => ({
    ...step,
    ...(step.pathAndQuery !== undefined ? { pathAndQuery: interpolate(step.pathAndQuery) } : {}),
    ...(step.value !== undefined ? { value: interpolate(step.value) } : {}),
  }))
  const controlSteps = normalized.filter(step => step.role === 'control')
  const probeSteps = normalized.filter(step => step.role !== 'control')
  if (controlSteps.length > 0) {
    const control = await ctx.browserSession({ origin: args.origin, steps: controlSteps, canaryToken, actor: args.actor })
    ctx.require(control !== null, 'browser_control', 'The control browser session produced no trace.', 'control')
    ctx.require(control?.sinkHit !== true, 'browser_control', 'The control session recorded the canary in an executable sink, so the payload is not the cause.', 'control')
  }
  const result = await ctx.browserSession({ origin: args.origin, steps: probeSteps, canaryToken, actor: args.actor })
  ctx.require(result !== null, 'browser_trace', 'No host-recorded browser session trace was produced for this origin.', 'harness')
  ctx.require(result?.sinkHit === true, 'browser_sink', 'The probe session did not record the canary reaching an executable DOM sink.', 'probe')
  const sinks = [...new Set((result?.traces ?? []).flatMap(trace => trace.sinks ?? []))]
  requireExpectedSinks(ctx, sinks, args.expectSinks)
  return buildProofReceipt({
    vulnClass: receiptVulnClass,
    target: targetOf(args),
    exchangeIds: [],
    browserTraceIds: (result?.traces ?? []).map(trace => trace.id),
    claimedDelta: `The probe browser session recorded ${sinks.join(', ') || 'the canary'} reaching an executable sink after ${probeSteps.length} step(s).`,
  })
})

const SIMPLE_BROWSER_ACTIONS = new Set(['navigate', 'fill', 'click', 'dom_xss_sink_hook'])

/**
 * True when a browser spec carries a protocol proof (postMessage origin check, credentialed
 * cross-origin fetch, built-in DOM/storage assertion). Those stay on the framework verifier; only
 * navigate/fill/click DOM-sink proofs map onto the `browser_sink` recipe.
 */
export function isProtocolBrowserSpec(steps: ReadonlyArray<Record<string, unknown>> | undefined): boolean {
  if (!steps || steps.length === 0) return false
  return steps.some(step => {
    const action = typeof step.action === 'string' ? step.action : 'navigate'
    if (!SIMPLE_BROWSER_ACTIONS.has(action)) return true
    return step.builtinCheck !== undefined ||
      step.fetchTarget !== undefined ||
      step.postMessagePayload !== undefined ||
      step.postMessageOrigin !== undefined
  })
}

/** Map a navigate/fill/click `browser_chain` spec onto the browser_sink recipe envelope. */
export function browserSinkEnvelopeFromSteps(input: {
  origin: string
  vulnClass: string
  steps: ReadonlyArray<Record<string, unknown>>
  canaryToken?: string
}): { recipeId: 'browser_sink'; args: BrowserSinkArgs } | null {
  // A protocol proof must never be flattened into a DOM-sink recipe: its assertion (origin check,
  // credentialed fetch, built-in result) is not expressible here, so the caller stays on the
  // framework verifier instead of silently dropping the claim.
  if (isProtocolBrowserSpec(input.steps)) return null
  const mapped: FloorBrowserStep[] = []
  for (const step of input.steps) {
    const action = typeof step.action === 'string' ? step.action : 'navigate'
    if (!SIMPLE_BROWSER_ACTIONS.has(action)) return null
    const role = step.role === 'control' ? 'control' : 'probe'
    const pathAndQuery = typeof step.pathAndQuery === 'string' && step.pathAndQuery.startsWith('/') ? step.pathAndQuery : undefined
    const selector = typeof step.selector === 'string' && step.selector.length > 0 ? step.selector : undefined
    const value = typeof step.value === 'string' ? step.value : undefined
    const waitAfterLoadMs = typeof step.waitAfterLoadMs === 'number' ? step.waitAfterLoadMs : undefined
    const reusePage = step.reusePage === true ? true : undefined
    const persona = typeof step.persona === 'string' && step.persona.length > 0 ? step.persona : undefined
    // `dom_xss_sink_hook` is a snapshot when a prior step for the same role already visited that
    // path; when it targets a new path (or is the first step for that role), keep it as a
    // `navigate` step so the armed sink hook still loads the target page.
    if (action === 'dom_xss_sink_hook') {
      const priorForRole = [...mapped].reverse().find(prev => prev.role === role)
      if (!pathAndQuery || (priorForRole && priorForRole.pathAndQuery === pathAndQuery)) continue
      mapped.push({
        role,
        action: 'navigate',
        pathAndQuery,
        ...(waitAfterLoadMs !== undefined ? { waitAfterLoadMs } : {}),
        ...(reusePage ? { reusePage } : {}),
        ...(persona ? { persona } : {}),
      })
      continue
    }
    if (action !== 'navigate' && !selector) return null
    mapped.push({
      role,
      action: action as FloorBrowserStep['action'],
      ...(pathAndQuery ? { pathAndQuery } : {}),
      ...(selector ? { selector } : {}),
      ...(value !== undefined ? { value } : {}),
      ...(waitAfterLoadMs !== undefined ? { waitAfterLoadMs } : {}),
      ...(reusePage ? { reusePage } : {}),
      ...(persona ? { persona } : {}),
    })
  }
  const firstProbe = mapped.find(step => step.role === 'probe')
  if (!firstProbe) return null
  const actorHandle = typeof input.steps[0]?.persona === 'string' ? String(input.steps[0].persona) : 'anonymous'
  return {
    recipeId: 'browser_sink',
    args: {
      origin: input.origin,
      method: 'GET',
      pathAndQuery: firstProbe.pathAndQuery ?? '/',
      vulnClass: input.vulnClass,
      actor: { handle: actorHandle },
      steps: mapped,
      ...(input.canaryToken ? { canaryToken: input.canaryToken } : {}),
    },
  }
}

/** Fingerprinted SQL error / traversal / command injection → receipt `impact` rule (never status). */
const injectionFingerprint = defineRecipe<InjectionFingerprintArgs>('injection_fingerprint', async (args, ctx) => {
  const controlValue = args.controlValue ?? 'kovo-benign'
  // The recipe owns the arm shapes: a query-located parameter is substituted in the query string,
  // a JSON-located one in the body. An unmovable carrier fails closed rather than sending the same
  // value twice (which would make a control/fingerprint comparison meaningless).
  const armFor = (value: string): { pathAndQuery: string; jsonBody?: Record<string, unknown> } | null => {
    if (args.jsonBody !== undefined) {
      const base = args.jsonBody !== null && typeof args.jsonBody === 'object' && !Array.isArray(args.jsonBody)
        ? { ...(args.jsonBody as Record<string, unknown>) }
        : {}
      if (args.param) base[args.param] = value
      return { pathAndQuery: args.pathAndQuery, jsonBody: base }
    }
    if (!args.param) return null
    try {
      const url = new URL(args.pathAndQuery, 'http://kovo.invalid')
      if (!url.searchParams.has(args.param)) return null
      url.searchParams.set(args.param, value)
      return { pathAndQuery: `${url.pathname}${url.search}` }
    } catch {
      return null
    }
  }
  const controlArm = armFor(controlValue)
  const probeArm = armFor(args.payload)
  ctx.require(controlArm !== null && probeArm !== null, 'injection_probe', 'The injected parameter could not be moved (a query key or JSON body field is required).', 'harness')
  const control = await ctx.send({
    arm: 'control',
    role: 'benign_control',
    method: args.method,
    pathAndQuery: controlArm?.pathAndQuery ?? args.pathAndQuery,
    actor: args.actor,
    ...(controlArm?.jsonBody ? { jsonBody: controlArm.jsonBody } : {}),
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const probe = await ctx.send({
    arm: 'probe',
    role: 'injection_probe',
    method: args.method,
    pathAndQuery: probeArm?.pathAndQuery ?? args.pathAndQuery,
    actor: args.actor,
    ...(probeArm?.jsonBody ? { jsonBody: probeArm.jsonBody } : {}),
    ...(args.headers ? { headers: args.headers } : {}),
  })
  const textOf = (step: FloorRecipeStep): string => {
    const exchange = step.exchange
    const parts = [exchange.body ?? '']
    if (exchange.json !== undefined) parts.push(JSON.stringify(exchange.json))
    if (exchange.carrierText) parts.push(exchange.carrierText)
    return parts.join('\n')
  }
  const fingerprint = matchInjectionFingerprint(textOf(probe), args.family)
  ctx.require(fingerprint !== null, 'injection_probe', 'The probe response carried no engine/parser error fingerprint; a status change alone is not injection.', 'probe')
  ctx.require(
    fingerprint === null || !matchInjectionFingerprint(textOf(control), fingerprint.family),
    'benign_control',
    'The benign control produced the same engine error, so the fingerprint is infrastructure noise, not injection.',
    'control',
  )
  if (fingerprint === null) {
    return buildProofReceipt({
      vulnClass: args.vulnClass,
      target: targetOf(args),
      exchangeIds: [control.exchangeId, probe.exchangeId],
      browserTraceIds: [],
      claimedDelta: 'The injection probe produced no engine/parser fingerprint, so no semantic oracle exists.',
    })
  }
  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [control.exchangeId, probe.exchangeId],
    browserTraceIds: [],
    claimedDelta: `The ${args.family ?? 'injection'} payload produced a ${fingerprint.family}/${fingerprint.label} fingerprint (${fingerprint.text}) that the benign control did not.`,
  })
})

/**
 * Cut 3d conserved-balance concurrency recipe:
 *  1. Optional prerequisite setup steps (e.g. minting a resource or token),
 *  2. Baseline numeric readback (`baseline_read`),
 *  3. Synchronized concurrent burst (`burst_1..N`) via `ctx.sendBurst`,
 *  4. Post-burst numeric readback (`post_read`),
 *  5. Serial control mutation (`serial_control_1`) + conditional post-serial readback
 *     (`serial_post_read`) when the serial mutation returns 2xx,
 *  6. Best-effort cleanup in `finally`.
 * Confirmation is owned solely by `verifyConservedBalanceReceipt` in `proof-receipt.ts`.
 */
const conservedBalance = defineRecipe<ConservedBalanceArgs>('conserved_balance', async (args, ctx) => {
  const count = Math.min(MAX_RACE_BURST, Math.max(MIN_RACE_BURST, Math.trunc(args.burst)))
  const vars: Record<string, string> = {}
  await runSetupSequence(ctx, args.setupSteps, args.actor, args.headers, vars)

  const postReadSpec = args.postReadback ?? args.readback
  let baseline: FloorRecipeStep
  let burstSteps: FloorRecipeStep[]
  let postRead: FloorRecipeStep
  let serialMutation: FloorRecipeStep
  let serialPostRead: FloorRecipeStep | null = null

  try {
    baseline = await ctx.send(buildStepRequest(args.readback, 'setup', 'baseline_read', args.actor, args.headers, vars))
    burstSteps = await ctx.sendBurst(buildBurstSpecs(args, count, vars))
    postRead = await ctx.send(buildStepRequest(postReadSpec, 'control', 'post_read', args.actor, args.headers, vars))

    const serialSpec: ConservedBalanceStepSpec = args.serialControl ?? {
      method: args.method,
      pathAndQuery: args.pathAndQuery,
      jsonBody: args.body,
      actor: args.actor,
      ...(args.headers ? { headers: args.headers } : {}),
    }
    serialMutation = await ctx.send(buildStepRequest(serialSpec, 'control', 'serial_control_1', args.actor, args.headers, vars))
    if (isSuccess(serialMutation.exchange.status)) {
      serialPostRead = await ctx.send(buildStepRequest(postReadSpec, 'control', 'serial_post_read', args.actor, args.headers, vars))
    }
  } finally {
    await runCleanupSequence(ctx, args.cleanupSteps, args.actor, args.headers, vars)
  }

  const exchangeIds = [
    baseline.exchangeId,
    ...burstSteps.map(step => step.exchangeId),
    postRead.exchangeId,
    serialMutation.exchangeId,
    ...(serialPostRead ? [serialPostRead.exchangeId] : []),
  ]
  const ackedCount = burstSteps.filter(step => isSuccess(step.exchange.status)).length
  const conservedBalanceMeta = {
    ...(args.balanceField ? { balanceField: args.balanceField } : {}),
    ...(args.capField ? { capField: args.capField } : {}),
    ...(args.unitDebit !== undefined ? { unitDebit: args.unitDebit } : {}),
  }
  return buildProofReceipt({
    vulnClass: args.vulnClass || 'race_double_spend',
    target: targetOf(args),
    exchangeIds,
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: `A synchronized burst of ${count} ${args.method.toUpperCase()} ${pathOnly(args.pathAndQuery)} requests acknowledged ${ackedCount} mutations with conserved-balance readbacks and serial control.`,
    ...(Object.keys(conservedBalanceMeta).length > 0 ? { conservedBalance: conservedBalanceMeta } : {}),
    ...(args.oracleEvents ? { oracleEvents: args.oracleEvents } : { oracleEvents: ['invariant_violation', 'state_delta'] }),
  })
})

const CUT3_DEFINITIONS: { readonly [K in Cut3FloorRecipeId]: FloorRecipeDefinition<Cut3FloorRecipeArgsMap[K]> } = {
  redirect,
  browser_sink: browserSink,
  injection_fingerprint: injectionFingerprint,
  conserved_balance: conservedBalance,
}

export interface Cut3FloorRecipe {
  readonly id: Cut3FloorRecipeId
  readonly args: Cut3FloorRecipeArgs
  run(ctx: FloorRecipeContext): Promise<ProofReceipt>
}

/** Build a typed Cut 3c/3d recipe instance (not yet registered for persistence; see the id note). */
export function cut3FloorRecipe<K extends Cut3FloorRecipeId>(
  id: K,
  args: Cut3FloorRecipeArgsMap[K],
): Cut3FloorRecipe {
  const definition = CUT3_DEFINITIONS[id] as FloorRecipeDefinition<Cut3FloorRecipeArgsMap[K]>
  return { id, args, run: ctx => definition.run(args, ctx) }
}

/** Run a Cut 3c/3d recipe through the same runner, receipt gate and failure vocabulary. */
export async function runCut3Recipe(recipe: Cut3FloorRecipe, deps: FloorRecipeDeps): Promise<FloorRecipeExecution> {
  return runFloorRecipe(
    {
      id: recipe.id as unknown as FloorRecipeId,
      args: recipe.args as unknown as FloorRecipeArgs,
      run: recipe.run,
    },
    deps,
  )
}

const DEFINITIONS: { readonly [K in FloorRecipeId]: FloorRecipeDefinition<FloorRecipeArgsMap[K]> } = {
  access_boundary: accessBoundary,
  persisted_mutation: persistedMutation,
  boolean_or_timing: booleanOrTiming,
  oob_callback: oobCallback,
  race_burst: raceBurst,
  disclosure,
}

/** Build a typed recipe instance. */
export function floorRecipe<K extends FloorRecipeId>(id: K, args: FloorRecipeArgsMap[K]): FloorRecipe {
  const definition = DEFINITIONS[id] as FloorRecipeDefinition<FloorRecipeArgsMap[K]>
  return { id, args, run: ctx => definition.run(args, ctx) }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * Execute one recipe against Layer 1, build the receipt, and validate it with `verifyReceipt`.
 * A recipe precondition the receipt gate cannot name (e.g. race divergence) is folded into
 * `failure.missingRoles`; nothing is confirmed unless both agree.
 */
export async function runFloorRecipe(recipe: FloorRecipe, deps: FloorRecipeDeps): Promise<FloorRecipeExecution> {
  const ctx = new RecipeContext(recipe.args, deps)
  let receipt: ProofReceipt
  let abortFailure: FloorRecipeFailure | undefined
  try {
    receipt = await recipe.run(ctx)
  } catch (error) {
    const abort = error instanceof FloorRecipeAbort ? error : null
    abortFailure = {
      code: abort?.code ?? 'recipe_error',
      message: abort?.message ?? `Recipe threw: ${error instanceof Error ? error.message.slice(0, 300) : String(error).slice(0, 300)}`,
      missingRoles: uniqueRoles(abort?.missingRoles ?? []),
    }
    receipt = fallbackReceipt(recipe.args, ctx.exchangeIds, ctx.oobEventIds)
  }

  const transcript = ctx.transcript()
  const verification = verifyReceipt(receipt, transcript)
  const missing = uniqueRoles([
    ...ctx.missing.flatMap(item => item.roles),
    ...(verification.confirmed ? [] : inferMissingRoles(recipe, receipt, transcript, verification)),
  ])
  const requireFailures: FloorRecipeRequireFailure[] = ctx.missing.map(item => ({
    role: item.roles[0] ?? 'unknown',
    side: item.side,
    message: item.message,
  }))
  const failure: FloorRecipeFailure | undefined = abortFailure
    ?? (ctx.missing.length > 0
      ? {
          code: 'precondition_unsatisfied',
          message: ctx.missing.map(item => item.message).join('; '),
          missingRoles: missing,
          requireFailures,
        }
      : verification.confirmed
        ? undefined
        : {
            code: 'receipt_rejected',
            message: verification.reason,
            missingRoles: missing,
          })

  const result: FloorRecipeRunResult = {
    recipeId: recipe.id,
    confirmed: failure === undefined,
    steps: ctx.steps.map(step => ({
      exchangeId: step.exchangeId,
      role: step.role,
      arm: step.arm,
      method: step.request.method.toUpperCase(),
      pathAndQuery: step.request.pathAndQuery,
      status: step.exchange.status,
      durationMs: step.exchange.durationMs ?? null,
    })),
    exchangeIds: ctx.exchangeIds,
    oobEventIds: ctx.oobEventIds,
    transcript,
    verification,
  }
  return {
    result,
    receipt,
    ...(failure ? { failure } : {}),
  }
}

function fallbackReceipt(args: FloorRecipeArgs, exchangeIds: readonly string[], oobEventIds: readonly string[]): ProofReceipt {
  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [...exchangeIds],
    oobEventIds: [...oobEventIds],
    browserTraceIds: [],
    claimedDelta: 'The recipe aborted before it could produce confirmation evidence.',
  })
}

/**
 * Name the evidence role a rejected receipt lacked. The receipt gate already says *why*; this maps
 * that reason back to the step role a repair must add, so the migration has one vocabulary.
 */
const MISSING_ROLE_RULES: Readonly<Record<string, ReadonlyArray<readonly [RegExp, readonly string[]]>>> = {
  boolean: [
    [/benign 2xx baseline|benign_baseline|complete benign/, ['benign_baseline']],
    [/paired control\/probe rounds|equal number/, ['paired_rounds']],
    [/name the injected parameter/, ['injected_parameter']],
    [/request shape/, ['request_shape']],
    [/server error|5xx/, ['non_error_arm']],
    [/only difference was the injected predicate|rotating nonce|no structural response change/, ['structural_delta']],
    [/unstable|moving baseline/, ['stable_differential']],
  ],
  oob: [
    [/not delivered|durable OOB event/, ['delivered_callback']],
    [/carried the delivered canary/, ['injection_exchange']],
    [/before the canary was injected/, ['callback_causality']],
    [/different target origin/, ['callback_target']],
  ],
  conserved_balance: [
    [/baseline numeric readback/, ['baseline_read']],
    [/post-burst numeric readback/, ['post_read']],
    [/concurrent mutation|no 2xx acknowledged|Only \d+ concurrent/, ['burst_mutation']],
    [/post-serial numeric readback/, ['serial_post_read']],
    [/serial control/i, ['serial_control']],
    [/shared numeric conserved field/, ['conserved_field']],
  ],
  impact: [
    [/pre-mutation readback/, ['baseline_read']],
    [/separate post-mutation GET/, ['post_mutation_read']],
    [/identical to the baseline|state echo|not impact|idempotent|removed|no persisted impact/, ['persisted_delta']],
    [/not a protected field/, ['protected_field']],
    [/request body/, ['mutation_request_body']],
    [/owner-scoped|disclosure/, ['disclosed_field']],
    [/not served|no probe step/, ['probe_request']],
    [/role|tenant|differential/, ['role_or_tenant_differential']],
  ],
}

function matchMissingRole(rules: ReadonlyArray<readonly [RegExp, readonly string[]]>, reason: string): string[] | null {
  const hit = rules.find(([re]) => re.test(reason))
  return hit ? [...hit[1]] : null
}

function inferMissingRoles(
  recipe: FloorRecipe,
  receipt: ProofReceipt,
  transcript: ReceiptTranscript,
  verification: ReceiptVerification,
): string[] {
  const reason = verification.reason
  const cited = (transcript.entries ?? []).filter(entry => receipt.exchangeIds.includes(entry.exchangeId))

  if (verification.rule === 'boolean' || verification.rule === 'status_differential') {
    return matchMissingRole(MISSING_ROLE_RULES.boolean!, reason)
      ?? [verification.rule === 'status_differential' ? 'contradiction' : 'boolean_arm']
  }
  if (verification.rule === 'timing') {
    if (/control and a probe/.test(reason)) return ['timing_control', 'timing_probe']
    if (/wall-clock duration/.test(reason)) {
      const roles: string[] = []
      if (cited.some(entry => entry.step.arm === 'control' && (entry.durationMs ?? 0) <= 0)) roles.push('control_duration')
      if (cited.some(entry => entry.step.arm === 'probe' && (entry.durationMs ?? 0) <= 0)) roles.push('probe_duration')
      return roles.length > 0 ? roles : ['timing_duration']
    }
    return [/not distinguishable|stable separation/.test(reason) ? 'probe_delay' : 'timing_arm']
  }
  if (verification.rule === 'oob') {
    return matchMissingRole(MISSING_ROLE_RULES.oob!, reason) ?? ['oob_callback']
  }
  if (verification.rule === 'conserved_balance') {
    return matchMissingRole(MISSING_ROLE_RULES.conserved_balance!, reason) ?? ['conservation_violation']
  }
  return matchMissingRole(MISSING_ROLE_RULES.impact!, reason)
    ?? [recipe.id === 'disclosure' ? 'disclosed_field' : 'impact_evidence']
}

// ---------------------------------------------------------------------------
// Layer-1 broker adapter (production `FloorRecipeDeps`)
// ---------------------------------------------------------------------------

/** Persona handles the broker treats as unauthenticated. */
const ANONYMOUS_ACTOR_HANDLES = new Set(['', 'anon', 'anonymous', 'guest', 'public', 'unauthenticated'])

const BROKER_HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])

export interface FloorRecipeBrokerOptions {
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  /** Assignment origin every recipe exchange is sent to. */
  origin: string
  runId?: string
  assignmentId?: string
  /**
   * Probe class carried on every brokered request. The broker uses it for the same policy,
   * evidence and telemetry it applies to a probe exchange (`5xx` evidence, tracer tags, logs).
   */
  probeClass?: string
  /** Run-scoped headers (staging tenant/run tag) every exchange inherits. */
  headers?: Record<string, string>
  /** Host recorder; its return value is the persisted exchange id the receipt cites. */
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
  /** Reflection canary header for probes that prove in-band execution. */
  traceId?: string
  /** Durable callback lookup (Layer-2 relay) for `oob_callback` recipes. */
  oob?: FloorRecipeDeps['oob']
  /** Brokers authenticate by persona handle; recipes name their actors by handle. */
  personaFor?: (actor: FloorActor) => string | null
  /** Test seam: override the exchange projection (never used in production). */
  mapExchange?: (exchange: BrokerExchangeResult, spec: FloorRequestSpec) => Omit<FloorExchange, 'exchangeId'>
}

/**
 * Map one host-recorded broker exchange onto the recipe's Layer-1 view. JSON is parsed only when the
 * broker says the wire body was JSON, so an HTML error page is never mistaken for a record.
 */
export function exchangeToFloorExchange(
  exchange: BrokerExchangeResult,
  spec: FloorRequestSpec,
): Omit<FloorExchange, 'exchangeId'> {
  let json: unknown
  if (exchange.mediaType.includes('json')) {
    try { json = JSON.parse(exchange.body) } catch { json = undefined }
  }
  return {
    status: exchange.status,
    ...(json !== undefined ? { json } : {}),
    body: exchange.body,
    durationMs: exchange.durationMs,
    carrierText: carrierTextOf(spec),
    route: exchange.finalPathAndQuery ?? exchange.pathAndQuery,
    responseHeaders: exchange.respHeaders,
    ...(exchange.secretMatches?.length
      ? { secretMatches: exchange.secretMatches.slice(0, 16).map(match => match.sha256Prefix) }
      : {}),
  }
}

/**
 * The production `FloorRecipeDeps`: every recipe exchange goes through the existing
 * `RequestBroker.executeHttp` path with the run's grant/scope/rate/destructive guards, the same
 * staging headers and probe class as the differential probe, and the run's exchange recorder so the
 * receipt cites persisted exchange ids.
 */
export function brokerFloorRecipeDeps(options: FloorRecipeBrokerOptions): FloorRecipeDeps {
  const personaFor = options.personaFor
    ?? ((actor: FloorActor) => (ANONYMOUS_ACTOR_HANDLES.has(actor.handle.trim().toLowerCase()) ? null : actor.handle))
  const toBrokerRequest = (spec: FloorRequestSpec): BrokerHttpRequest => {
    const method = spec.method.toUpperCase()
    if (!BROKER_HTTP_METHODS.has(method)) {
      throw new FloorRecipeAbort('recipe_error', `Recipe asked for unsupported method ${method}.`, [spec.role])
    }
    const persona = personaFor(spec.actor)
    const body = spec.textBody ?? (spec.jsonBody !== undefined ? JSON.stringify(spec.jsonBody) : undefined)
    const headers = { ...(options.headers ?? {}), ...(spec.headers ?? {}) }
    return {
      origin: options.origin,
      method: method as BrokerHttpRequest['method'],
      pathAndQuery: spec.pathAndQuery,
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
      ...(persona ? { persona } : {}),
      ...(body !== undefined ? { body } : {}),
      ...(options.probeClass ? { probeClass: options.probeClass } : {}),
      ...(options.runId ? { runId: options.runId } : {}),
      ...(options.assignmentId ? { assignmentId: options.assignmentId } : {}),
      ...(options.traceId ? { traceId: options.traceId } : {}),
      ...(spec.session ? { session: spec.session } : {}),
      ...(spec.csrfBind ? { csrfBind: true as never } : {}),
      followRedirects: false,
    }
  }
  const project = (exchange: BrokerExchangeResult, spec: FloorRequestSpec): FloorExchange => {
    const exchangeId = options.recordExchange?.(exchange)
    const projected = options.mapExchange
      ? options.mapExchange(exchange, spec)
      : exchangeToFloorExchange(exchange, spec)
    return {
      ...projected,
      ...(typeof exchangeId === 'string' && exchangeId ? { exchangeId } : {}),
    }
  }
  return {
    async request(spec: FloorRequestSpec): Promise<FloorExchange> {
      const exchange = await options.broker.executeHttp(toBrokerRequest(spec), options.grant, options.signal)
      return project(exchange, spec)
    },
    async burst(specs: readonly FloorRequestSpec[]): Promise<FloorExchange[]> {
      const brokerReqs = specs.map(toBrokerRequest)
      const burstResult = await options.broker.executeRaceBurst(brokerReqs, options.grant, options.signal)
      return specs.map((spec, idx) => project(burstResult.results[idx]!, spec))
    },
    ...(options.oob ? { oob: options.oob } : {}),
  }
}

// ---------------------------------------------------------------------------
// Legacy spec-kind -> recipe mapping (Cut 3 migration table)
// ---------------------------------------------------------------------------

export interface SpecKindRecipeMapping {
  /** Outer/inner spec kind the legacy synthesizer emits. */
  specKind: string
  /** Legacy `vulnClass` values this row applies to (empty = the kind itself is the key). */
  vulnClasses: readonly string[]
  /** Replacement recipe, or null when the receipt model cannot express the evidence yet. */
  recipe: FloorRecipeId | Cut3FloorRecipeId | null
  note: string
}

export const SPEC_KIND_RECIPES: readonly SpecKindRecipeMapping[] = [
  {
    specKind: 'http_chain',
    vulnClasses: ['bola', 'idor', 'bfla', 'authorization', 'cross_tenant_read', 'cross_tenant_write'],
    recipe: 'access_boundary',
    note: 'Entitled control served + peer denied + probe served; requiredRole/resourceTenant carried on the receipt.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['mass_assignment'],
    recipe: 'persisted_mutation',
    note: 'Baseline GET + body-carrying mutation + separate readback; protected-field delta is the impact.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['workflow_bypass', 'business_logic', 'price_tampering'],
    recipe: 'persisted_mutation',
    note: 'Same before/write/after chain; invariant_violation/state_delta oracle events preserved.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['csrf'],
    recipe: 'persisted_mutation',
    note: 'Probe carries a foreign Origin header and an ambient cookie actor; csrf_state_change oracle required.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['info_disclosure', 'secret_disclosure', 'disclosure'],
    recipe: 'disclosure',
    note: 'Probe baseline + entitled read + denied peer + probe read; owner-scoped non-public field is required.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['xxe', 'ssrf', 'webhook_forgery'],
    recipe: 'oob_callback',
    note: 'Injection exchange must carry the durable canary token; delivered callback must post-date it.',
  },
  {
    specKind: 'sql_boolean_diff',
    vulnClasses: ['sqli'],
    recipe: 'boolean_or_timing',
    note: 'Boolean rule: >=2 paired rounds, identical request shape apart from the predicate, stable structural delta after token stripping, no 5xx.',
  },
  {
    specKind: 'sql_time_diff',
    vulnClasses: ['sqli'],
    recipe: 'boolean_or_timing',
    note: 'Timing rule: control <1000 ms and probe >max(1000 ms, 3x control).',
  },
  {
    specKind: 'race_burst',
    vulnClasses: ['race_double_spend'],
    recipe: 'race_burst',
    note: 'Identical terminal transitions accepted twice plus a divergent outcome set; business-logic receipt rule.',
  },
  { specKind: 'browser_chain', vulnClasses: [], recipe: null, note: 'Navigate/fill/click DOM-sink proofs are wired to `browser_sink` (see WIRED_SPECKIND_RECIPES); protocol proofs (postMessage/fetch/builtin) keep the browser spec path.' },
  { specKind: 'rce_proof', vulnClasses: [], recipe: null, note: 'No receipt rule for command execution/template evaluation.' },
  { specKind: 'auth_protocol_proof', vulnClasses: [], recipe: null, note: 'Token/protocol forgery proof scripts stay on the proof-script path.' },
  { specKind: 'cache_differential', vulnClasses: [], recipe: null, note: 'No receipt rule for cache poisoning.' },
  { specKind: 'http_chain', vulnClasses: ['path_traversal', 'open_redirect', 'xss_reflected', 'xss_stored', 'ssti', 'command_injection'], recipe: null, note: 'No receipt rule in the current oracle model; not a 1:1 recipe yet.' },
]

/** Resolve the replacement recipe for a legacy spec, or null when it has no receipt shape yet. */
export function recipeForSpecKind(specKind: string, vulnClass?: string | null): FloorRecipeId | Cut3FloorRecipeId | null {
  for (const row of SPEC_KIND_RECIPES) {
    if (row.specKind !== specKind) continue
    if (row.vulnClasses.length === 0 || (vulnClass && row.vulnClasses.includes(vulnClass))) return row.recipe
  }
  return null
}

/**
 * The rows that are **wired**: `deterministic-engine.ts` runs the recipe instead of evaluating a
 * `DeclarativeReplaySpec`, and `verifyReplaySpec()` hard-refuses the kind/class combination.
 *
 * This is deliberately narrower than `SPEC_KIND_RECIPES` (the target table). A row graduates here
 * only after the recipe reproduces the legacy confirmation set on the dev floor. Rows that are
 * still on the legacy path are listed in `LEGACY_UNWIRED_SPECKINDS` with the blocking reason, so
 * the gap is explicit instead of looking like an oversight.
 */
export const WIRED_SPECKIND_RECIPES: readonly SpecKindRecipeMapping[] = [
  {
    specKind: 'race_burst',
    vulnClasses: ['race_double_spend'],
    recipe: 'conserved_balance',
    note: 'Cut 3d: the conserved-balance recipe reads the value before and after a synchronized burst, requires the serial control to debit every acknowledgement, and confirms only an under-debit / oversell / cap overshoot. The legacy race VM branch is retired.',
  },
  {
    specKind: 'sql_time_diff',
    vulnClasses: ['sqli'],
    recipe: 'boolean_or_timing',
    note: 'Time-based blind SQLi: the engine schedules this probe only after a response-identical boolean arm, and the recipe carries the delay payload. Confirmation is the `timing` receipt rule (vulnClass blind_sqli, >3x separation), never a status.',
  },
  {
    specKind: 'sql_boolean_diff',
    vulnClasses: ['sqli'],
    recipe: 'boolean_or_timing',
    note: 'Product floor: paired true/false predicate rounds confirmed by the boolean receipt rule. The legacy verifier branch is retained only for the capability harness (scripts/) and patch retest; the live probe deliberately never emits a status-only signal, so the status_differential receipt rule is available for callers that do (xben harness migration), not selected by the floor.',
  },
  {
    specKind: 'browser_chain',
    vulnClasses: ['xss', 'xss_reflected', 'xss_stored', 'dom_xss'],
    recipe: 'browser_sink',
    note: 'Cut 3d: navigate/fill/click DOM-sink proofs run the browser_sink recipe, which requires a host-recorded trace with the verifier canary in an executable sink. Protocol proofs (postMessage origin check, credentialed cross-origin fetch, built-in DOM/storage assertions) keep the framework verifier branch and are deliberately not wired here.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['bola', 'idor', 'bfla', 'authorization', 'cross_tenant_read', 'cross_tenant_write'],
    recipe: 'access_boundary',
    note: 'Reads: entitled read + probe read + authenticated denial control (same-route peer, or the bogus-id variant when the route only denies nonexistent ids). Mutations: baseline write/reset + pre-mutation readback + probe mutation + separate post-read, confirmed by the shared authorization oracle (persisted delta / cross-tenant entitlement).',
  },
]

/** Rows whose recipe exists but that stay on the legacy verifier for a measured reason. */
export const LEGACY_UNWIRED_SPECKINDS: readonly { specKind: string; vulnClasses: readonly string[]; recipe: FloorRecipeId | Cut3FloorRecipeId; reason: string }[] = [
  {
    specKind: 'http_chain',
    vulnClasses: ['mass_assignment', 'workflow_bypass', 'business_logic', 'price_tampering', 'csrf'],
    recipe: 'persisted_mutation',
    reason: 'Legacy chain binds the mutated field value and staging tag into the readback assertion; the recipe readback is a plain before/after pair, which is weaker on self-service writes.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['info_disclosure', 'secret_disclosure', 'disclosure'],
    recipe: 'disclosure',
    reason: 'Credential/audit reads confirm on pre-redaction secret fingerprints; the disclosure recipe requires a probe-owned baseline read that API-key/audit routes do not expose.',
  },
  {
    specKind: 'http_chain',
    vulnClasses: ['xxe', 'ssrf', 'webhook_forgery'],
    recipe: 'oob_callback',
    reason: 'The legacy OOB proof mints and waits on a durable canary subscription inside the verifier; the recipe adapter needs that relay seam (canary session + late promotion) before moving.',
  },
]

/**
 * Resolve the **wired** recipe for a legacy spec kind/class pair. This is the function the verifier
 * uses for its no-fallback assertion, so a wired pair can never silently reach the legacy path.
 */
export function wiredRecipeForSpecKind(specKind: string, vulnClass?: string | null): FloorRecipeId | Cut3FloorRecipeId | null {
  for (const row of WIRED_SPECKIND_RECIPES) {
    if (row.specKind !== specKind) continue
    if (row.vulnClasses.length === 0 || (vulnClass && row.vulnClasses.includes(vulnClass))) return row.recipe
  }
  return null
}

