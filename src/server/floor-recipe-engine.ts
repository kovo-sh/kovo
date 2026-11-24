/**
 * Floor recipe planner (Cut 3a) — the production bridge between the deterministic floor's legacy
 * hypothesis/spec vocabulary and the typed recipe library in `floor-recipes.ts`.
 *
 * The floor forms a hypothesis, runs its benign differential probe, and gets a signal. For a
 * **wired** spec kind/class pair this module:
 *   1. derives the recipe arguments from the hypothesis, probe evidence and approved personas,
 *   2. runs the recipe through `runFloorRecipe` with the broker-backed deps
 *      (`brokerFloorRecipeDeps`), so every exchange is a real brokered request with the run's
 *      grant, staging headers, probe class and persisted exchange id,
 *   3. records a `SynthesizedEngineSpec` whose steps are the recipe's own host-recorded exchanges and
 *      whose assertion re-checks the receipt's claim on a later retest replay.
 *
 * Confirmation itself is the recipe's `ProofReceipt` verified by `verifyReceipt` — never a
 * declarative-spec assertion. A wired pair must not fall back to `verifyReplaySpec`; the verifier
 * throws if it is called for one (`assertRecipeWiredKind`).
 */
import { createHash } from 'node:crypto'
import { baseFields } from './deterministic-specs.ts'
import type { EngineHypothesis, Severity, SynthesizedEngineSpec } from './deterministic-specs.ts'
import type { EnginePersona } from './deterministic-engine.ts'
import type { DifferentialResult } from './surface-engine.ts'
import { injectUniversalParam } from './probes/context.ts'
import { floorRecipe, runFloorRecipe, wiredRecipeForSpecKind } from './floor-recipes.ts'
import type {
  BooleanOrTimingArgs,
  FloorActor,
  FloorRecipeArgs,
  FloorRecipeExecution,
  FloorRecipeId,
  FloorRequestSpec,
  RaceBurstArgs,
} from './floor-recipes.ts'
import type { ImpactStep, RoleName } from './oracle-invariants.ts'
import type { ReplayVerificationResult } from './replay-verifier.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import { brokerFloorRecipeDeps } from './floor-recipes.ts'

/** The exact target a wired recipe confirmed; the record spec re-uses it. */
export interface FloorRecipePlan {
  recipeId: FloorRecipeId
  /** Legacy spec kind this plan replaces (used for attribution and the no-fallback assertion). */
  specKind: string
  vulnClass: string
  endpoint: string
  args: FloorRecipeArgs
  /** Injection location of the parameter the recipe drives (record-spec metadata). */
  paramLocation?: string
  /** Machine-readable reason the plan could not be expressed, when `args` is absent. */
  skipReason?: string
}

export interface FloorRecipePlanInput {
  hypothesis: EngineHypothesis
  probe: DifferentialResult
  /** Legacy candidate kind/class the synthesizer would have emitted. */
  specKind: string
  vulnClass: string
  personas: readonly EnginePersona[]
  /** Run-scoped headers (staging tenant/run tag) applied to every recipe exchange. */
  headers?: Record<string, string>
}

const ANONYMOUS_HANDLE = 'anon'

function roleOf(persona: EnginePersona | undefined): RoleName | null {
  if (!persona) return null
  if (persona.privilege === 'admin') return 'admin'
  if (persona.privilege === 'viewer') return 'viewer'
  return 'member'
}

function personaOf(handle: string | null | undefined, personas: readonly EnginePersona[]): EnginePersona | undefined {
  if (!handle) return undefined
  return personas.find(persona => persona.handle === handle)
}

/** Build the recipe actor for a persona handle (or the unauthenticated actor for a null handle). */
export function floorActorFor(handle: string | null | undefined, personas: readonly EnginePersona[]): FloorActor {
  if (!handle) return { handle: ANONYMOUS_HANDLE, role: null, tenant: null, auth: 'unknown' }
  const persona = personaOf(handle, personas)
  return {
    handle,
    role: roleOf(persona),
    tenant: persona?.tenant ?? null,
    auth: 'cookie',
  }
}

// ---------------------------------------------------------------------------------------------
// Boolean / timing SQL injection
// ---------------------------------------------------------------------------------------------

type BooleanStyle = 'single' | 'double' | 'numeric' | 'or'

function booleanStyleOf(raw: unknown): BooleanStyle {
  const style = String(raw ?? '')
  if (style === 'double_quote' || style === 'double') return 'double'
  if (style === 'numeric') return 'numeric'
  if (style === 'or_branch' || style === 'or') return 'or'
  return 'single'
}

function booleanExpression(style: BooleanStyle, baseline: string, key: number, arm: 'true' | 'false'): string {
  const expr = arm === 'true' ? `${key}=${key}` : `${key}=${key + 1}`
  switch (style) {
    case 'numeric': return `${baseline} AND ${expr}`
    case 'double': return `${baseline}" AND ${expr}-- -`
    case 'or': return `${baseline}' OR ${expr}-- -`
    default: return `${baseline}' AND ${expr}-- -`
  }
}

/**
 * Build one arm of the boolean pair. The probe reports the exact operand and a single replay
 * template for the shape that passed; replaying that pair keeps the differential grounded in the
 * target's own data instead of a dev fixture literal that may not exist in this catalog. A template
 * is preferred because the proven shape may not be one of the four legacy style branches.
 */
function booleanArm(input: {
  template: string | null
  style: BooleanStyle
  baseline: string
  key: number
  arm: 'true' | 'false'
}): string {
  const expr = `${input.key}=${input.arm === 'true' ? input.key : input.key + 1}`
  if (input.template) {
    return input.template.replaceAll('{{baseline}}', input.baseline).replaceAll('{{sql_expr}}', expr)
  }
  return booleanExpression(input.style, input.baseline, input.key, input.arm)
}

function requestFromInjection(input: {
  hyp: EngineHypothesis
  value: string
}): Pick<FloorRequestSpec, 'method' | 'pathAndQuery' | 'jsonBody' | 'textBody' | 'headers'> | null {
  const hyp = input.hyp
  const location = hyp.location ?? hyp.param?.location
  if (!hyp.param || !location) return null
  const injected = injectUniversalParam({
    pathAndQuery: hyp.pathAndQuery,
    param: hyp.param.name,
    paramLocation: location,
    value: input.value,
    method: hyp.method === 'DELETE' ? 'POST' : hyp.method,
    ...(hyp.headers ? { headers: hyp.headers } : {}),
    ...(hyp.jsonBody ? { jsonBody: hyp.jsonBody } : {}),
    ...(hyp.formBody ? { formBody: hyp.formBody } : {}),
    ...(hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate } : {}),
    ...(hyp.graphqlQuery ? { graphqlQuery: hyp.graphqlQuery } : {}),
    ...(hyp.session ? { session: hyp.session } : {}),
  })
  let jsonBody: unknown
  let textBody: string | undefined
  if (typeof injected.body === 'string' && injected.body.length > 0) {
    const contentType = Object.entries(injected.headers ?? {})
      .find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? ''
    if (contentType.includes('json') || /^[{[]/.test(injected.body.trim())) {
      try { jsonBody = JSON.parse(injected.body) } catch { jsonBody = undefined }
    }
    if (jsonBody === undefined) textBody = injected.body
  }
  return {
    method: injected.method ?? hyp.method,
    pathAndQuery: injected.pathAndQuery,
    ...(jsonBody !== undefined ? { jsonBody } : {}),
    ...(textBody !== undefined ? { textBody } : {}),
    ...(injected.headers ? { headers: injected.headers } : {}),
  }
}

function planBooleanRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const sketch: FloorRecipePlan = {
    recipeId: 'boolean_or_timing',
    specKind: input.specKind,
    vulnClass: 'sqli',
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  if (!hyp.param) return { ...sketch, skipReason: 'sqli hypothesis has no injected parameter' }
  const hit = input.probe.anomalies.find(anomaly => anomaly.type === 'boolean_differential')
  // Prefer the operand the probe actually grounded (a literal from the target's own rows, or the
  // empty term of the tautology pair). A hypothesis default such as `1` is only the last resort.
  const grounded = typeof hit?.baselineValue === 'string' ? hit.baselineValue : null
  const baseline = grounded ?? hyp.baselineValue ?? '1'
  const key = 7_919
  const style = booleanStyleOf(hit?.style)
  const rawTemplate = typeof hit?.valueTemplate === 'string' && hit.valueTemplate.includes('{{sql_expr}}')
    ? hit.valueTemplate
    : null
  const rawQuote = typeof hit?.quoteStyle === 'string' ? hit.quoteStyle : ''
  const quoteStyle: 'single' | 'double' | 'numeric' = rawQuote === 'double' || rawQuote === 'numeric' ? rawQuote : 'single'
  // The receipt's boolean rule pairs a *true* predicate (control arm) with a *false* predicate
  // (probe arm): the structural difference between them is the differential. A benign baseline vs a
  // true predicate is structurally identical by construction, so it can never be the pair.
  const control = requestFromInjection({ hyp, value: booleanArm({ template: rawTemplate, style, baseline, key, arm: 'true' }) })
  const probe = requestFromInjection({ hyp, value: booleanArm({ template: rawTemplate, style, baseline, key, arm: 'false' }) })
  if (!control || !probe) return { ...sketch, skipReason: 'sqli injection point could not be expressed as a recipe request' }
  const args: BooleanOrTimingArgs = {
    mode: 'boolean',
    origin: hyp.endpoint.origin,
    method: probe.method,
    pathAndQuery: probe.pathAndQuery,
    controlPathAndQuery: control.pathAndQuery,
    probePathAndQuery: probe.pathAndQuery,
    param: hyp.param.name,
    vulnClass: 'sqli',
    actor: floorActorFor(hyp.ownerPersona ?? null, input.personas),
    rounds: 2,
    baselineValue: baseline,
    ...(rawTemplate ? { valueTemplate: rawTemplate, quoteStyle } : { quoteStyle }),
    ...(control.jsonBody !== undefined ? { controlJsonBody: control.jsonBody } : {}),
    ...(probe.jsonBody !== undefined ? { probeJsonBody: probe.jsonBody } : {}),
    ...(input.headers ?? hyp.headers ? { headers: { ...(hyp.headers ?? {}), ...(input.headers ?? {}) } } : {}),
  }
  return { ...sketch, args, paramLocation: hyp.location ?? hyp.param.location }
}

// ---------------------------------------------------------------------------------------------
// Race burst
// ---------------------------------------------------------------------------------------------

function planRaceRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const hit = input.probe.anomalies.find(anomaly => anomaly.type === 'race_double_spend')
  const sketch: FloorRecipePlan = {
    recipeId: 'race_burst',
    specKind: input.specKind,
    vulnClass: 'race_double_spend',
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  if (!hit) return { ...sketch, skipReason: 'no race_double_spend evidence on the probe result' }
  const amountField = typeof hit.amountField === 'string' ? hit.amountField : ''
  const amount = Number(hit.amount)
  const burst = Number(hit.burstSize)
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(amountField) || !Number.isFinite(amount) || amount <= 0) {
    return { ...sketch, skipReason: 'race evidence did not name a positive amount field' }
  }
  if (!Number.isFinite(burst) || burst < 2 || burst > 10) {
    return { ...sketch, skipReason: 'race evidence did not name a usable burst size' }
  }
  const path = typeof hit.path === 'string' && hit.path.startsWith('/')
    ? hit.path.split('?')[0]!
    : hyp.pathAndQuery.split('?')[0]!
  const idempotencyKey = typeof hit.idempotencyKey === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(hit.idempotencyKey)
    ? hit.idempotencyKey
    : null
  const body: Record<string, unknown> = { [amountField]: amount, ...(idempotencyKey ? { idempotencyKey } : {}) }
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }
  const args: RaceBurstArgs = {
    origin: hyp.endpoint.origin,
    method: 'POST',
    pathAndQuery: path,
    vulnClass: 'race_double_spend',
    actor: floorActorFor(hyp.ownerPersona ?? null, input.personas),
    body,
    burst: Math.trunc(burst),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args }
}

// ---------------------------------------------------------------------------------------------
// Planning entrypoint
// ---------------------------------------------------------------------------------------------

/**
 * Resolve a wired recipe plan for one legacy candidate, or null when the pair is not wired. A wired
 * pair that cannot be expressed returns a plan with `skipReason` so the engine records a named
 * rejection instead of silently taking the legacy path.
 */
export function planFloorRecipe(input: FloorRecipePlanInput): FloorRecipePlan | null {
  const recipe = wiredRecipeForSpecKind(input.specKind, input.vulnClass)
  if (!recipe) return null
  switch (recipe) {
    case 'boolean_or_timing': return planBooleanRecipe(input)
    case 'race_burst': return planRaceRecipe(input)
    default: return {
      recipeId: recipe,
      specKind: input.specKind,
      vulnClass: input.vulnClass,
      endpoint: input.hypothesis.endpoint.pathTemplate,
      args: {} as FloorRecipeArgs,
      skipReason: `${recipe} is wired but has no planner for ${input.specKind}/${input.vulnClass}`,
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Recipe execution through the broker
// ---------------------------------------------------------------------------------------------

export interface RunPlannedRecipeInput {
  plan: FloorRecipePlan
  hypothesis: EngineHypothesis
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  assignmentId?: string
  runId?: string
  headers?: Record<string, string>
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
}

/** Run a plan through the broker-backed Layer-1 adapter. Never falls back to the legacy verifier. */
export async function runPlannedRecipe(input: RunPlannedRecipeInput): Promise<FloorRecipeExecution> {
  const deps = brokerFloorRecipeDeps({
    broker: input.broker,
    grant: input.grant,
    signal: input.signal,
    origin: input.hypothesis.endpoint.origin,
    probeClass: input.hypothesis.probeClass,
    ...(input.runId ? { runId: input.runId } : {}),
    ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
    ...(input.headers ? { headers: input.headers } : {}),
    ...(input.recordExchange ? { recordExchange: input.recordExchange } : {}),
  })
  return runFloorRecipe(floorRecipe(input.plan.recipeId, input.plan.args), deps)
}

// ---------------------------------------------------------------------------------------------
// Persisted record spec + verification result
// ---------------------------------------------------------------------------------------------

const SEVERITY_BY_CLASS: Readonly<Record<string, Severity>> = {
  bola: 'high',
  idor: 'high',
  bfla: 'high',
  cross_tenant_read: 'high',
  cross_tenant_write: 'critical',
  mass_assignment: 'high',
  workflow_bypass: 'high',
  business_logic: 'high',
  price_tampering: 'high',
  csrf: 'high',
  info_disclosure: 'high',
  secret_disclosure: 'high',
  xxe: 'high',
  ssrf: 'high',
  webhook_forgery: 'high',
  sqli: 'high',
  race_double_spend: 'critical',
}

const CWE_BY_CLASS: Readonly<Record<string, string>> = {
  bola: 'CWE-639',
  idor: 'CWE-639',
  bfla: 'CWE-285',
  authorization: 'CWE-285',
  cross_tenant_read: 'CWE-639',
  cross_tenant_write: 'CWE-639',
  mass_assignment: 'CWE-915',
  workflow_bypass: 'CWE-840',
  business_logic: 'CWE-840',
  price_tampering: 'CWE-472',
  csrf: 'CWE-352',
  info_disclosure: 'CWE-200',
  secret_disclosure: 'CWE-200',
  xxe: 'CWE-611',
  ssrf: 'CWE-918',
  webhook_forgery: 'CWE-345',
  sqli: 'CWE-89',
  race_double_spend: 'CWE-362',
}

const TITLE_BY_RECIPE: Readonly<Record<FloorRecipeId, string>> = {
  access_boundary: 'Cross-actor object or function access',
  persisted_mutation: 'Persisted unauthorized state change',
  boolean_or_timing: 'SQL injection differential',
  oob_callback: 'Out-of-band callback from injected payload',
  race_burst: 'Synchronized burst double-spend',
  disclosure: 'Unauthorized record disclosure',
}

const is2xxJq = (id: string) => `(.steps.${id}.status >= 200 and .steps.${id}.status < 300)`
const isDeniedJq = (id: string) =>
  `(.steps.${id}.status == 401 or .steps.${id}.status == 403 or .steps.${id}.status == 404)`

/**
 * Replay assertion for a receipt-confirmed spec. This is the *retest* re-check of an already
 * persisted proof (reproduced vs fixed), not the confirmation path: it restates the receipt's
 * structural precondition over the recorded steps so a hardened fixture cannot replay as reproduced.
 */
function retestAssertion(recipe: FloorRecipeId, steps: readonly { id: string; role: string }[]): string {
  const ids = (role: string) => steps.filter(step => step.role === role).map(step => step.id)
  const first = (role: string) => ids(role)[0] ?? null
  const all = (predicate: (id: string) => string) => {
    const parts = steps.map(step => predicate(step.id))
    return parts.length > 0 ? `(${parts.join(' and ')})` : 'true'
  }
  switch (recipe) {
    case 'access_boundary': {
      const entitled = first('entitled_read') ?? first('probe_baseline')
      const denied = first('denied_control')
      const probe = first('probe_request')
      const confirmed = [probe, denied].filter((id): id is string => Boolean(id))
      return `{ controlPassed: (${entitled ? is2xxJq(entitled) : 'true'}), `
        + `confirmed: (${confirmed.length ? confirmed.map(id => (id === denied ? isDeniedJq(id) : is2xxJq(id))).join(' and ') : 'true'}), `
        + 'observed: "recipe replay: boundary arms re-observed", expected: "the denied control is refused while the probe is served" }'
    }
    case 'disclosure': {
      const probe = first('probe_request')
      const denied = first('denied_control')
      const confirmed = [probe, denied].filter((id): id is string => Boolean(id))
      return `{ controlPassed: (${first('probe_baseline') ? is2xxJq(first('probe_baseline')!) : 'true'}), `
        + `confirmed: (${confirmed.length ? confirmed.map(id => (id === denied ? isDeniedJq(id) : is2xxJq(id))).join(' and ') : 'true'}), `
        + 'observed: "recipe replay: disclosure arms re-observed", expected: "a peer is denied while the probe reads owner-scoped data" }'
    }
    case 'persisted_mutation': {
      const baseline = first('baseline_read')
      const probe = first('mutation_probe')
      const after = first('post_mutation_read')
      const diff = baseline && after ? `(.steps.${after}.body != .steps.${baseline}.body)` : 'true'
      return `{ controlPassed: (${baseline ? is2xxJq(baseline) : 'true'}), `
        + `confirmed: (${probe ? is2xxJq(probe) : 'true'} and ${diff}), `
        + 'observed: "recipe replay: mutation and readback re-observed", expected: "the readback shows no persisted change" }'
    }
    case 'boolean_or_timing': {
      const controls = ids('boolean_control')
      const probes = ids('boolean_probe')
      const pairs = probes.map((probe, index) => {
        const control = controls[index] ?? controls[0]
        return control ? `(.steps.${probe}.body != .steps.${control}.body)` : 'true'
      })
      return `{ controlPassed: (${all(is2xxJq)}), `
        + `confirmed: (${all(is2xxJq)} and (${pairs.length ? pairs.join(' and ') : 'true'})), `
        + 'observed: "recipe replay: paired boolean rounds re-observed", expected: "the boolean predicate separates every pair" }'
    }
    case 'race_burst': {
      const burst = steps.filter(step => step.role.startsWith('burst_')).map(step => step.id)
      const successes = burst.length >= 2
        ? burst.map(id => is2xxJq(id)).slice(0, 2).join(' and ')
        : 'true'
      const divergence = burst.slice(1)
        .map((id, index) => `(.steps.${id}.body != .steps.${burst[index]}.body)`)
        .join(' or ') || 'true'
      return `{ controlPassed: true, `
        + `confirmed: ((${successes}) and (${divergence})), `
        + 'observed: "recipe replay: burst re-observed", expected: "a repeated terminal transition never produces divergent outcomes" }'
    }
    default:
      return '{ controlPassed: true, confirmed: true, observed: "recipe replay", expected: "recipe evidence reproduced" }'
  }
}

function recordSteps(
  origin: string,
  execution: FloorRecipeExecution,
): Array<{ id: string; role: 'setup' | 'control' | 'probe' | 'cleanup'; description: string; request: Record<string, unknown> }> {
  const entries = execution.result.transcript.entries ?? []
  return entries.map((entry, index) => {
    const step: ImpactStep = entry.step
    const persona = step.actor.handle && step.actor.handle !== ANONYMOUS_HANDLE ? step.actor.handle : null
    return {
      id: `s${index + 1}`,
      role: step.arm,
      description: execution.result.steps[index]?.role ?? step.arm,
      request: {
        origin,
        method: step.method,
        pathAndQuery: step.pathAndQuery ?? step.route ?? '/',
        ...(persona ? { persona } : {}),
        ...(step.requestJson !== undefined ? { jsonBody: step.requestJson } : {}),
        ...(step.requestHeaders ? { headers: step.requestHeaders } : {}),
        followRedirects: false,
      },
    }
  })
}

function recordSpecFor(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  origin: string,
): Record<string, unknown> {
  const severity = SEVERITY_BY_CLASS[plan.vulnClass] ?? 'high'
  const cwe = CWE_BY_CLASS[plan.vulnClass] ?? 'CWE-639'
  const title = TITLE_BY_RECIPE[plan.recipeId]
  const steps = recordSteps(origin, execution)
  const jq = retestAssertion(plan.recipeId, steps)
  const base = baseFields(origin, title, cwe, plan.vulnClass, severity, jq)
  if (plan.specKind === 'sql_boolean_diff') {
    const args = plan.args as BooleanOrTimingArgs
    return {
      ...base,
      kind: 'sql_boolean_diff',
      targetOrigin: origin,
      method: args.method.toUpperCase(),
      pathAndQuery: args.pathAndQuery,
      paramName: args.param ?? 'q',
      paramLocation: plan.paramLocation ?? 'query',
      baselineValue: args.baselineValue ?? '1',
      quoteStyle: args.quoteStyle ?? 'single',
      ...(args.valueTemplate ? { valueTemplate: args.valueTemplate } : {}),
      ...(args.probeJsonBody !== undefined ? { jsonBody: args.probeJsonBody } : {}),
      ...(args.headers ? { headers: args.headers } : {}),
    }
  }
  if (plan.specKind === 'race_burst') {
    const args = plan.args as RaceBurstArgs
    const burst = steps
      .filter(step => step.role === 'probe')
      .map(step => ({
        origin,
        method: step.request.method,
        pathAndQuery: step.request.pathAndQuery,
        ...(step.request.persona ? { persona: step.request.persona } : {}),
        ...(step.request.jsonBody !== undefined ? { jsonBody: step.request.jsonBody } : {}),
        ...(step.request.headers ? { headers: step.request.headers } : {}),
        followRedirects: false,
      }))
    return {
      ...base,
      kind: 'race_burst',
      burst: burst.length >= 2 ? burst : [
        { origin, method: args.method, pathAndQuery: args.pathAndQuery, jsonBody: args.body, followRedirects: false },
        { origin, method: args.method, pathAndQuery: args.pathAndQuery, jsonBody: args.body, followRedirects: false },
      ],
    }
  }
  return { ...base, kind: 'http_chain', steps }
}

/** Build the persisted spec record for a recipe confirmation (steps = host-recorded exchanges). */
export function recipeSpecRecord(plan: FloorRecipePlan, execution: FloorRecipeExecution): SynthesizedEngineSpec {
  return {
    kind: plan.specKind,
    vulnClass: plan.vulnClass,
    endpoint: plan.endpoint,
    spec: recordSpecFor(plan, execution, plan.args.origin),
  }
}

/**
 * Project the receipt execution onto the verifier's result shape so the finding pipeline stores the
 * same artifact (exchange ids, transcript, evidence payload) it stores for a legacy confirmation.
 */
export function recipeVerificationResult(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  exchangeIds: readonly string[],
): ReplayVerificationResult {
  return recipeResult(plan, execution, exchangeIds, true)
}

/** Retest projection: `reproduced` keeps the confirmation shape, a rejected receipt is `dismissed`. */
export function recipeRetestResult(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  exchangeIds: readonly string[],
): ReplayVerificationResult {
  return recipeResult(plan, execution, exchangeIds, execution.result.confirmed)
}

function recipeResult(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  exchangeIds: readonly string[],
  confirmed: boolean,
): ReplayVerificationResult {
  const verification = execution.result.verification
  const steps = recordSteps(plan.args.origin, execution)
  const evidencePayload: Record<string, unknown> = {
    kind: plan.specKind,
    origin: plan.args.origin,
    replayedAt: null,
    confirmation: 'proof_receipt',
    recipe: plan.recipeId,
    receipt: execution.receipt,
    verification,
    steps: Object.fromEntries(steps.map((step, index) => [step.id, {
      role: step.role,
      status: execution.result.steps[index]?.status ?? null,
      method: step.request.method,
      pathAndQuery: step.request.pathAndQuery,
    }])),
    exchangeIds: [...execution.result.exchangeIds],
  }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
  return {
    verdict: confirmed ? 'confirmed' : 'dismissed',
    ...(confirmed ? { verificationTier: 'runtime_confirmed' as const } : {}),
    outcome: {
      confirmed,
      controlPassed: confirmed,
      observed: verification.observed.slice(0, 1200),
      expected: verification.expected.slice(0, 1200),
      reason: verification.reason.slice(0, 1200),
    },
    exchangeIds: [...exchangeIds],
    exchanges: [],
    evidencePayload,
    evidenceSha256,
    receipt: { receipt: execution.receipt, verification, mode: 'strict' },
  }
}
