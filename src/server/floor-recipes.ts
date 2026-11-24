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
 * | `sql_boolean_diff`     | sqli                                      | `boolean_or_timing`  | **exception**: boolean-only has no receipt rule yet (see below) |
 * | `sql_time_diff`        | sqli                                      | `boolean_or_timing`  | timing rule, >3x separation |
 * | `race_burst`           | race_double_spend                         | `race_burst`         | repeated terminal transition + divergent burst outcomes |
 * | `browser_chain`        | xss_* / dom_*                             | — (no recipe)        | browser-trace receipts are a separate cut |
 * | `rce_proof`            | ssti / command_injection                  | — (no recipe)        | not expressible by the receipt impact model |
 * | `auth_protocol_proof`  | jwt / oauth / webhook_forgery             | — (no recipe)        | proof-script path stays for protocol forgery |
 * | `cache_differential`   | cache_poisoning                           | — (no recipe)        | no receipt rule |
 * | `http_chain`           | path_traversal / open_redirect / xss_*    | — (no recipe)        | no receipt rule |
 *
 * The one migration blocker is documented rather than faked: `verifyReceipt()` has no boolean-
 * differential rule (a `sqli` class returns `rule: 'none'`). `boolean_or_timing` therefore confirms
 * only timing evidence today and refuses a boolean-only run naming `timing_arm`. Cut 3 can retire
 * every other spec kind; boolean-only SQLi needs either a receipt rule (proof-receipt stream) or
 * must keep its spec shape.
 */
import type { AmbientAuth, ImpactStep, RoleName } from './oracle-invariants.ts'
import { buildProofReceipt, verifyReceipt } from './proof-receipt.ts'
import type {
  ProofReceipt,
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
}

export interface FloorOobQuery {
  token: string
  injectedAtMs?: number
}

/** The Layer-1 seam. Production supplies a broker adapter; tests supply fixtures. */
export interface FloorRecipeDeps {
  request(spec: FloorRequestSpec): Promise<FloorExchange> | FloorExchange
  /** Durable callback lookup for the token the injection exchange carried. */
  oob?(query: FloorOobQuery): Promise<ReceiptOobEvent | null> | ReceiptOobEvent | null
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
  requiredRole?: RoleName
  resourceTenant?: string
  expectControlDenied?: boolean
  oracleEvents?: string[]
  proofPatterns?: string[]
}

export interface BooleanOrTimingArgs extends FloorRecipeBaseArgs {
  /** `boolean` = control-vs-variant body differential; `timing` = conditional delay. */
  mode: 'boolean' | 'timing'
  actor?: FloorActor
  controlPathAndQuery?: string
  probePathAndQuery?: string
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

export interface RaceBurstArgs extends FloorRecipeBaseArgs {
  actor: FloorActor
  /** Identical body for every burst request (the terminal transition). */
  body: Record<string, unknown>
  /** Number of synchronized requests, clamped to 2..8. */
  burst: number
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

export interface FloorRecipeArgsMap {
  access_boundary: AccessBoundaryArgs
  persisted_mutation: PersistedMutationArgs
  boolean_or_timing: BooleanOrTimingArgs
  oob_callback: OobCallbackArgs
  race_burst: RaceBurstArgs
  disclosure: DisclosureArgs
}

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

export interface FloorRecipeContext {
  readonly args: FloorRecipeArgs
  /** Exchanges recorded so far (bounded). */
  readonly steps: readonly FloorRecipeStep[]
  send(spec: FloorRequestSpec): Promise<FloorRecipeStep>
  oob(query: FloorOobQuery): Promise<ReceiptOobEvent | null>
  /**
   * Record a preconditions the oracle needs that the receipt gate alone cannot name. Returns the
   * condition so a recipe can continue gathering the rest of the minimum evidence.
   */
  require(condition: boolean, role: string, message: string): boolean
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
  message: string
}

class RecipeContext implements FloorRecipeContext {
  readonly args: FloorRecipeArgs
  readonly steps: FloorRecipeStep[] = []
  readonly missing: RecordedMissing[] = []
  private readonly deps: FloorRecipeDeps
  private readonly entries: ReceiptTranscriptEntry[] = []
  private readonly oobEvents: ReceiptOobEvent[] = []
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
    return { entries: [...this.entries], oobEvents: [...this.oobEvents] }
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
    const exchange = await this.deps.request(spec)
    const exchangeId = exchange.exchangeId
      ?? this.deps.nextExchangeId?.()
      ?? `fr-${this.exchangeCount}`
    const route = exchange.route ?? pathOnly(spec.pathAndQuery)
    const step: ImpactStep = {
      id: `s${this.exchangeCount}:${spec.role}`,
      arm: spec.arm,
      method: spec.method.toUpperCase(),
      route,
      pathAndQuery: spec.pathAndQuery,
      status: exchange.status,
      actor: {
        handle: spec.actor.handle,
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
      ...(exchange.durationMs !== undefined ? { durationMs: exchange.durationMs } : {}),
      carrierText: exchange.carrierText ?? carrierTextOf(spec),
    })
    return recorded
  }

  async oob(query: FloorOobQuery): Promise<ReceiptOobEvent | null> {
    const event = this.deps.oob ? await this.deps.oob(query) : null
    if (event && !this.oobEvents.some(existing => existing.id === event.id)) this.oobEvents.push(event)
    return event
  }

  require(condition: boolean, role: string, message: string): boolean {
    if (!condition) this.missing.push({ roles: [role], message })
    return condition
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

interface FloorRecipeDefinition<A extends FloorRecipeArgs> {
  readonly id: FloorRecipeId
  run(args: A, ctx: FloorRecipeContext): Promise<ProofReceipt>
}

function defineRecipe<A extends FloorRecipeArgs>(
  id: FloorRecipeId,
  run: (args: A, ctx: FloorRecipeContext) => Promise<ProofReceipt>,
): FloorRecipeDefinition<A> {
  return { id, run }
}

/**
 * Vertical/object access boundary: the entitled control is served, a peer control is denied on the
 * same route, and the lower-privileged probe is served. The impact oracle needs the denied sibling
 * (or a role/tenant differential); the recipe asserts the boundary before the receipt gate sees it.
 */
const accessBoundary = defineRecipe<AccessBoundaryArgs>('access_boundary', async (args, ctx) => {
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

  ctx.require(isSuccess(entitled.exchange.status), 'entitled_read', 'The entitled control was not served the resource.')
  ctx.require(isDenied(denied.exchange.status), 'denied_control', `The peer control returned ${denied.exchange.status ?? 'no status'} instead of a denial.`)
  ctx.require(isSuccess(probe.exchange.status), 'probe_request', `The probe actor was not served the resource (${probe.exchange.status ?? 'no status'}).`)

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [entitled.exchangeId, denied.exchangeId, probe.exchangeId],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: `${args.probe.handle} was served ${args.method.toUpperCase()} ${pathOnly(args.pathAndQuery)} while a same-route peer control was denied.`,
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

  ctx.require(baseline.exchange.json !== undefined, 'baseline_read', 'The pre-mutation baseline read recorded no JSON body.')
  ctx.require(isSuccess(probe.exchange.status), 'mutation_probe', `The mutating probe was not accepted (${probe.exchange.status ?? 'no status'}).`)
  ctx.require(after.exchange.json !== undefined, 'post_mutation_read', 'The separate post-mutation GET recorded no JSON body.')

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [baseline.exchangeId, probe.exchangeId, after.exchangeId],
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
 * Boolean-or-timing SQL injection. Only the timing shape is receipt-confirmable today: the control
 * and probe durations are host-recorded by Layer 1. A boolean-only run is refused with `timing_arm`
 * instead of being credited through a rule the receipt model does not have.
 */
const booleanOrTiming = defineRecipe<BooleanOrTimingArgs>('boolean_or_timing', async (args, ctx) => {
  const control = await ctx.send({
    arm: 'control',
    role: 'timing_control',
    method: args.method,
    pathAndQuery: args.controlPathAndQuery ?? args.pathAndQuery,
    actor: args.actor ?? ANONYMOUS,
  })
  const probe = await ctx.send({
    arm: 'probe',
    role: 'timing_probe',
    method: args.method,
    pathAndQuery: args.probePathAndQuery ?? args.pathAndQuery,
    actor: args.actor ?? ANONYMOUS,
  })

  if (args.mode === 'boolean') {
    ctx.require(
      false,
      'timing_arm',
      'Boolean-only SQL injection has no verifyReceipt rule yet; a control/probe timing arm is required for receipt confirmation.',
    )
  }

  return buildProofReceipt({
    vulnClass: args.vulnClass,
    target: targetOf(args),
    exchangeIds: [control.exchangeId, probe.exchangeId],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: args.mode === 'timing'
      ? 'The conditional SQL payload produced a stable >3x response delay against the control arm.'
      : 'The boolean SQL payload changed the response independently of the baseline value.',
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

  ctx.require(event !== null, 'delivered_callback', 'No durable OOB event was delivered for the injected canary token.')
  if (event) {
    ctx.require(event.delivered, 'delivered_callback', `OOB event ${event.id} was recorded but not delivered.`)
    const injectedAt = event.injectedAtMs
    if (injectedAt !== undefined) {
      ctx.require(event.receivedAtMs >= injectedAt, 'callback_causality', `OOB event ${event.id} arrived before the canary was injected.`)
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
const raceBurst = defineRecipe<RaceBurstArgs>('race_burst', async (args, ctx) => {
  const count = Math.min(MAX_RACE_BURST, Math.max(MIN_RACE_BURST, Math.trunc(args.burst)))
  const steps: FloorRecipeStep[] = []
  for (let index = 0; index < count; index += 1) {
    steps.push(await ctx.send({
      arm: 'probe',
      role: `burst_${index + 1}`,
      method: args.method,
      pathAndQuery: args.pathAndQuery,
      actor: args.actor,
      jsonBody: args.body,
      ...(args.headers ? { headers: args.headers } : {}),
    }))
  }
  const successes = steps.filter(step => isSuccess(step.exchange.status))
  const distinct = new Set(steps.map(outcomeOf)).size

  ctx.require(successes.length >= 2, 'burst_repeat', `Only ${successes.length} of ${count} burst requests were accepted; a race needs the terminal transition accepted twice.`)
  ctx.require(distinct >= 2, 'burst_divergence', `The burst produced ${distinct} distinct outcome(s); a uniform burst is not race evidence.`)

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

  ctx.require(baseline.exchange.json !== undefined, 'probe_baseline', 'The probe actor\'s own baseline read recorded no JSON body.')
  ctx.require(isSuccess(entitled.exchange.status), 'entitled_read', 'The entitled control was not served the victim record.')
  ctx.require(isDenied(denied.exchange.status), 'denied_control', `The peer control returned ${denied.exchange.status ?? 'no status'} instead of a denial.`)
  ctx.require(isSuccess(probe.exchange.status), 'probe_request', `The probe actor was not served the victim record (${probe.exchange.status ?? 'no status'}).`)

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
  const failure: FloorRecipeFailure | undefined = abortFailure
    ?? (ctx.missing.length > 0
      ? {
          code: 'precondition_unsatisfied',
          message: ctx.missing.map(item => item.message).join('; '),
          missingRoles: missing,
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
function inferMissingRoles(
  recipe: FloorRecipe,
  receipt: ProofReceipt,
  transcript: ReceiptTranscript,
  verification: ReceiptVerification,
): string[] {
  const reason = verification.reason
  const cited = (transcript.entries ?? []).filter(entry => receipt.exchangeIds.includes(entry.exchangeId))

  if (verification.rule === 'timing') {
    if (/control and a probe/.test(reason)) return ['timing_control', 'timing_probe']
    if (/wall-clock duration/.test(reason)) {
      const roles: string[] = []
      if (cited.some(entry => entry.step.arm === 'control' && (entry.durationMs ?? 0) <= 0)) roles.push('control_duration')
      if (cited.some(entry => entry.step.arm === 'probe' && (entry.durationMs ?? 0) <= 0)) roles.push('probe_duration')
      return roles.length > 0 ? roles : ['timing_duration']
    }
    if (/not distinguishable|stable separation/.test(reason)) return ['probe_delay']
    return ['timing_arm']
  }

  if (verification.rule === 'oob') {
    if (/not delivered|durable OOB event/.test(reason)) return ['delivered_callback']
    if (/carried the delivered canary/.test(reason)) return ['injection_exchange']
    if (/before the canary was injected/.test(reason)) return ['callback_causality']
    if (/different target origin/.test(reason)) return ['callback_target']
    return ['oob_callback']
  }

  if (/pre-mutation readback/.test(reason)) return ['baseline_read']
  if (/separate post-mutation GET/.test(reason)) return ['post_mutation_read']
  if (/identical to the baseline|state echo|not impact|idempotent|removed|no persisted impact/.test(reason)) return ['persisted_delta']
  if (/not a protected field/.test(reason)) return ['protected_field']
  if (/request body/.test(reason)) return ['mutation_request_body']
  if (/owner-scoped|disclosure/.test(reason)) return ['disclosed_field']
  if (/not served|no probe step/.test(reason)) return ['probe_request']
  if (/role|tenant|differential/.test(reason)) return ['role_or_tenant_differential']
  if (recipe.id === 'disclosure') return ['disclosed_field']
  return ['impact_evidence']
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
  recipe: FloorRecipeId | null
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
    note: 'EXCEPTION: boolean-only evidence has no receipt rule yet; the recipe refuses with missing timing_arm.',
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
  { specKind: 'browser_chain', vulnClasses: [], recipe: null, note: 'Browser-trace receipts (dom_*/xss_*) are a separate cut; keep the browser spec path.' },
  { specKind: 'rce_proof', vulnClasses: [], recipe: null, note: 'No receipt rule for command execution/template evaluation.' },
  { specKind: 'auth_protocol_proof', vulnClasses: [], recipe: null, note: 'Token/protocol forgery proof scripts stay on the proof-script path.' },
  { specKind: 'cache_differential', vulnClasses: [], recipe: null, note: 'No receipt rule for cache poisoning.' },
  { specKind: 'http_chain', vulnClasses: ['path_traversal', 'open_redirect', 'xss_reflected', 'xss_stored', 'ssti', 'command_injection'], recipe: null, note: 'No receipt rule in the current oracle model; not a 1:1 recipe yet.' },
]

/** Resolve the replacement recipe for a legacy spec, or null when it has no receipt shape yet. */
export function recipeForSpecKind(specKind: string, vulnClass?: string | null): FloorRecipeId | null {
  for (const row of SPEC_KIND_RECIPES) {
    if (row.specKind !== specKind) continue
    if (row.vulnClasses.length === 0 || (vulnClass && row.vulnClasses.includes(vulnClass))) return row.recipe
  }
  return null
}
