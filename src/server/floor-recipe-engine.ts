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
import { createHash, createHmac, randomBytes, randomInt, randomUUID } from 'node:crypto'
import { diffResponse } from '../../worker/analyzers.ts'
import type { StateChangeApprovalContext } from './approval-judge.ts'
import { baseFields, bogusIdFor } from './deterministic-specs.ts'
import type { EngineHypothesis, Severity, SynthesizedEngineSpec } from './deterministic-specs.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import type { BrowserSessionStep } from './scoped-browser.ts'
import type { EnginePersona } from './deterministic-engine.ts'
import type { DifferentialResult } from './surface-engine.ts'
import { injectUniversalParam } from './probes/context.ts'
import { CUT3_FLOOR_RECIPE_IDS, browserSinkEnvelopeFromSteps, cut3FloorRecipe, floorRecipe, isProtocolBrowserSpec, runCut3Recipe, runFloorRecipe, wiredRecipeForSpecKind } from './floor-recipes.ts'
import type {
  AccessBoundaryArgs,
  BooleanOrTimingArgs,
  BrowserSinkArgs,
  ConservedBalanceArgs,
  Cut3FloorRecipeArgs,
  Cut3FloorRecipeArgsMap,
  Cut3FloorRecipeId,
  FloorActor,
  FloorRecipeArgs,
  FloorRecipeArgsMap,
  FloorRecipeDeps,
  FloorRecipeExecution,
  FloorRecipeId,
  FloorRequestSpec,
  PersistedMutationArgs,
  RaceBurstArgs,
} from './floor-recipes.ts'
import { assessBoundary, assessMfaBypass, classifyBoundaryClaim, normalizeRole } from './oracle-invariants.ts'
import type { ActorIdentity, AmbientAuth, ImpactStep, RoleName } from './oracle-invariants.ts'
import { verifyReceipt } from './proof-receipt.ts'
import type { ProofReceipt, ReceiptTranscript } from './proof-receipt.ts'
import type { ReplayVerificationResult, RetestVerdict } from './replay-verifier.ts'
import { cacheBusterValueRegex, containsDestructivePayload, extractCacheBusterParam, replayAssertionOutcomeSchema } from '../replay-spec.ts'
import type { AuthMutation, DeclarativeReplaySpec, FloorRecipeEnvelope, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'
import { openCanarySession, structuralSimilarity } from './verify-support.ts'
import type { EphemeralCanarySession } from './verify-support.ts'
import type { WorkerBackend } from './worker-backend.ts'
import { brokerFloorRecipeDeps } from './floor-recipes.ts'

export type PersistedFloorRecipeId = FloorRecipeId | Cut3FloorRecipeId
export type PersistedFloorRecipeArgs = FloorRecipeArgs | Cut3FloorRecipeArgs

const CUT3_RECIPE_ID_SET: ReadonlySet<string> = new Set(CUT3_FLOOR_RECIPE_IDS)

function isCut3RecipeId(id: PersistedFloorRecipeId): id is Cut3FloorRecipeId {
  return CUT3_RECIPE_ID_SET.has(id)
}

/** Dispatch any persisted floor recipe id (core 6 + Cut 3 recipes) through its typed runner. */
export function executeFloorRecipeById(
  recipeId: PersistedFloorRecipeId,
  args: PersistedFloorRecipeArgs,
  deps: FloorRecipeDeps,
): Promise<FloorRecipeExecution> {
  if (isCut3RecipeId(recipeId)) {
    return runCut3Recipe(
      cut3FloorRecipe(recipeId, args as Cut3FloorRecipeArgsMap[typeof recipeId]),
      deps,
    )
  }
  return runFloorRecipe(
    floorRecipe(recipeId, args as FloorRecipeArgsMap[typeof recipeId]),
    deps,
  )
}

/** The exact target a wired recipe confirmed; the record spec re-uses it. */
export interface FloorRecipePlan {
  recipeId: PersistedFloorRecipeId
  /** Legacy spec kind this plan replaces (used for attribution and the no-fallback assertion). */
  specKind: string
  vulnClass: string
  endpoint: string
  args: PersistedFloorRecipeArgs
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
  /** The synthesized legacy candidate, when the planner needs its request steps (browser specs). */
  candidateSpec?: Record<string, unknown>
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
  // Time-based blind SQLi: the engine schedules this probe after a response-identical boolean arm.
  // The recipe sends a benign control and the conditional-delay probe; the receipt `timing` rule
  // decides (>3x separation against a <1s control), so a status change is never the signal.
  const timingHit = input.probe.anomalies.find(anomaly => anomaly.type === 'sql_time_differential')
  if (timingHit) {
    const baseline = hyp.baselineValue ?? (typeof timingHit.baselineValue === 'string' ? timingHit.baselineValue : '1')
    const dialectRaw = String(timingHit.dialect ?? '')
    const dialect = ['mysql', 'postgres', 'sqlite', 'mssql'].includes(dialectRaw) ? dialectRaw : 'postgres'
    const delayMs = Math.max(1500, Math.min(3000, Number(timingHit.delayMs) || 2500))
    const seconds = (delayMs / 1000).toFixed(2)
    const probeValue = dialect === 'mysql'
      ? `${baseline}' AND SLEEP(${seconds})-- -`
      : dialect === 'postgres'
        ? `${baseline}' AND (SELECT 1 FROM pg_sleep(${seconds})) IS NULL-- -`
        : dialect === 'mssql'
          ? `${baseline}'; WAITFOR DELAY '0:0:${Math.max(1, Math.round(delayMs / 1000))}'-- -`
          : `${baseline}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${delayMs * 25_000}))))-- -`
    const control = requestFromInjection({ hyp, value: baseline })
    const probe = requestFromInjection({ hyp, value: probeValue })
    if (!control || !probe) return { ...sketch, skipReason: 'sqli timing injection point could not be expressed as a recipe request' }
    const args: BooleanOrTimingArgs = {
      mode: 'timing',
      origin: hyp.endpoint.origin,
      method: probe.method,
      pathAndQuery: probe.pathAndQuery,
      controlPathAndQuery: control.pathAndQuery,
      probePathAndQuery: probe.pathAndQuery,
      param: hyp.param.name,
      vulnClass: 'sqli',
      receiptClass: 'blind_sqli',
      actor: floorActorFor(hyp.ownerPersona ?? null, input.personas),
      baselineValue: baseline,
      quoteStyle: 'single',
      ...(control.jsonBody !== undefined ? { controlJsonBody: control.jsonBody } : {}),
      ...(probe.jsonBody !== undefined ? { probeJsonBody: probe.jsonBody } : {}),
      ...(input.headers ?? hyp.headers ? { headers: { ...(hyp.headers ?? {}), ...(input.headers ?? {}) } } : {}),
    }
    return { ...sketch, args, paramLocation: hyp.location ?? hyp.param.location }
  }
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
    recipeId: 'conserved_balance',
    specKind: input.specKind,
    vulnClass: 'race_double_spend',
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as ConservedBalanceArgs,
  }
  if (!hit) return { ...sketch, skipReason: 'no race_double_spend evidence on the probe result' }
  const amountField = typeof hit.amountField === 'string' ? hit.amountField : ''
  const balanceField = typeof hit.balanceField === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(hit.balanceField)
    ? hit.balanceField
    : undefined
  const amount = Number(hit.amount)
  const burst = Number(hit.burstSize)
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(amountField) || !Number.isFinite(amount) || amount <= 0) {
    return { ...sketch, skipReason: 'race evidence did not name a positive amount field' }
  }
  if (!Number.isFinite(burst) || burst < 2 || burst > 10) {
    return { ...sketch, skipReason: 'race evidence did not name a usable burst size' }
  }
  const raceOrigin = typeof hit.raceOrigin === 'string' && /^https?:\/\//.test(hit.raceOrigin)
    ? hit.raceOrigin
    : hyp.endpoint.origin
  const path = typeof hit.path === 'string' && hit.path.startsWith('/')
    ? hit.path.split('?')[0]!
    : hyp.pathAndQuery.split('?')[0]!
  const idempotencyKey = typeof hit.idempotencyKey === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(hit.idempotencyKey)
    ? hit.idempotencyKey
    : null
  const bodyFor = (value: number): Record<string, unknown> => ({
    [amountField]: value,
    ...(idempotencyKey ? { idempotencyKey } : {}),
  })
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }
  const actor = floorActorFor(hyp.ownerPersona ?? null, input.personas)
  const args: ConservedBalanceArgs = {
    origin: raceOrigin,
    method: 'POST',
    pathAndQuery: path,
    vulnClass: 'race_double_spend',
    actor,
    body: bodyFor(amount),
    burst: Math.min(8, Math.trunc(burst)),
    readback: {
      method: 'POST',
      pathAndQuery: path,
      jsonBody: bodyFor(0),
      actor,
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
    },
    ...(balanceField ? { balanceField } : {}),
    unitDebit: amount,
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args }
}

// ---------------------------------------------------------------------------------------------
// Object-level / function-level authorization
// ---------------------------------------------------------------------------------------------

const PRIVILEGED_ACTION_RE = /(?:^|\/)(?:admin|administrator|internal|manage|management|staff|superuser|privileged|backoffice|permissions?|roles?|grants?|scopes?|impersonate|feature[-_]?flags?)(?:\/|$)/i
const BASELINE_STRONG_NUMERIC_FIELD_RE = /(?:^|[_-])(?:amount|total|price|value|cents|balance|qty|quantity|count|seats?|credits?)(?:$|[_-])/i
const BASELINE_TEXT_FIELD_RE = /^(?:name|title|label|description|note|notes|body|text|summary|message|subject|comment|company|address)$/i
const BASELINE_STATE_FIELD_RE = /^(?:status|state|stage|phase|visibility|priority|archived?|active)$/i
const BASELINE_EXCLUDED_FIELD_RE = /(?:^|[_-])(?:id|uuid|owner|tenant|org|team|role|roles|permissions?|email|password|token|secret|key|created|updated)(?:$|[_-])/i

function fillResourceId(pathAndQuery: string, id: string): string {
  return pathAndQuery.replaceAll('{{id}}', encodeURIComponent(id))
}

function resourceIdOf(input: FloorRecipePlanInput): string | null {
  const valid = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value)
  const matrix = Array.isArray(input.probe.details.matrix)
    ? input.probe.details.matrix as Array<Record<string, unknown>>
    : null
  // The differential probe reports one anomaly per (method, object). Prefer the object whose owner
  // read carried the most data: an empty-but-2xx collection is a legal matrix row, but it can never
  // satisfy the read differential (the bogus-id control returns the same empty body). Legacy ranked
  // hits by similarity; body size is the stable tie-breaker that survives an all-1.0 similarity.
  const ownerBytes = (id: string): number => {
    if (!matrix) return 0
    let best = 0
    for (const row of matrix) {
      if (String(row.resourceId ?? '') !== id) continue
      if (String(row.actor ?? '') !== 'owner') continue
      if (row.accessible !== true) continue
      const status = typeof row.status === 'number' ? row.status : 0
      if (status < 200 || status >= 300) continue
      const bytes = typeof row.bodyBytes === 'number' ? row.bodyBytes : 0
      if (bytes > best) best = bytes
    }
    return best
  }
  const candidates = input.probe.anomalies
    .filter(anomaly => anomaly.type === 'unauthorized_access' &&
      String(anomaly.method ?? 'GET').toUpperCase() === input.hypothesis.method &&
      valid(anomaly.resourceId))
    .map(anomaly => anomaly.resourceId as string)
  if (candidates.length > 0) {
    let best = candidates[0]!
    let bestBytes = ownerBytes(best)
    for (const candidate of candidates.slice(1)) {
      const bytes = ownerBytes(candidate)
      if (bytes > bestBytes) { best = candidate; bestBytes = bytes }
    }
    return best
  }
  return input.hypothesis.resourceIds?.find(valid) ?? null
}

/** Readback route for a mutation, mirroring the legacy synthesizer's choice set. */
function authzReadbackPath(input: FloorRecipePlanInput, id: string | null, functionLevel: boolean): string | null {
  const hyp = input.hypothesis
  if (hyp.readbackPath) return id ? fillResourceId(hyp.readbackPath, id) : hyp.readbackPath
  const bare = hyp.pathAndQuery.split('?')[0]!
  if (functionLevel) return PRIVILEGED_ACTION_RE.test(bare) ? hyp.pathAndQuery : null
  if (!id) return null
  const queryAt = hyp.pathAndQuery.indexOf('?')
  if (queryAt >= 0 && hyp.pathAndQuery.slice(queryAt).includes('{{id}}')) return hyp.pathAndQuery
  const segments = bare.split('/')
  const placeholder = segments.findIndex(segment => segment === '{{id}}' || /^\{[^}]+\}$/.test(segment) || /^:[A-Za-z_][A-Za-z0-9_]*$/.test(segment))
  if (placeholder <= 0) return null
  if (placeholder === segments.length - 1) return fillResourceId(hyp.pathAndQuery, id)
  if (placeholder === segments.length - 2 && PRIVILEGED_ACTION_RE.test(bare)) {
    return fillResourceId(segments.slice(0, -1).join('/'), id)
  }
  return null
}

/** A fresh baseline value for one mutable field of the probe body, or null when none is writable. */
function baselineWriteFor(body: unknown): { body: Record<string, unknown>; field: string } | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  const scalars = Object.entries(body as Record<string, unknown>)
    .filter(([field, value]) => /^[A-Za-z0-9_.-]{1,64}$/.test(field) &&
      (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'))
  const eligible = scalars.filter(([field]) => !BASELINE_EXCLUDED_FIELD_RE.test(field))
  const chosen = eligible.find(([field]) => BASELINE_STRONG_NUMERIC_FIELD_RE.test(field))
    ?? eligible.find(([field]) => BASELINE_TEXT_FIELD_RE.test(field))
    ?? eligible.find(([, value]) => typeof value === 'boolean')
    ?? eligible.find(([field]) => BASELINE_STATE_FIELD_RE.test(field))
    ?? eligible.find(([field]) => !BASELINE_EXCLUDED_FIELD_RE.test(field))
  if (!chosen) return null
  const [field, value] = chosen
  const nonce = randomBytes(4).toString('hex')
  const baseline = typeof value === 'boolean'
    ? !value
    : typeof value === 'number' || /^-?\d+(?:\.\d+)?$/.test(String(value))
      ? 424_242 + (Number.parseInt(nonce.slice(0, 4), 16) % 1_000)
      : `guardian-baseline-${nonce}`
  return { field, body: { ...(body as Record<string, unknown>), [field]: baseline } }
}

function authzBodyOf(input: FloorRecipePlanInput): Record<string, unknown> | null {
  const hyp = input.hypothesis
  if (hyp.functionState?.body) return hyp.functionState.body
  const hits = input.probe.anomalies.filter(anomaly =>
    anomaly.type === 'unauthorized_access' &&
    anomaly.bodyTemplate !== undefined && anomaly.bodyTemplate !== null &&
    typeof anomaly.bodyTemplate === 'object' && !Array.isArray(anomaly.bodyTemplate))
  const hit = hits.find(anomaly => String(anomaly.method ?? 'GET').toUpperCase() === hyp.method) ?? hits[0]
  if (hit?.bodyTemplate) return hit.bodyTemplate as Record<string, unknown>
  return hyp.jsonBody ?? null
}

function planAuthzRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const recipeId: FloorRecipeId = hyp.method === 'GET' ? 'access_boundary' : 'persisted_mutation'
  const vulnClass = hyp.functionLevel ? 'bfla' : 'bola'
  const sketch: FloorRecipePlan = {
    recipeId,
    specKind: input.specKind,
    vulnClass,
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  const ownerHandle = hyp.ownerPersona
  const probeHandle = hyp.otherPersona
  if (!ownerHandle || !probeHandle) return { ...sketch, skipReason: 'authz hypothesis has no owner/probe persona pair' }
  const id = resourceIdOf(input)
  const functionLevel = hyp.functionLevel === true
  if (!functionLevel && !id) return { ...sketch, skipReason: 'object-level authz hypothesis has no usable resource identifier' }
  const privileged = PRIVILEGED_ACTION_RE.test(hyp.pathAndQuery.split('?')[0]!)
  // A destructive probe matrix consumes the identifiers it exercises. The engine reserves one live
  // victim for the replay when a privileged delete needs an observable removal; reuse it so the
  // pre-read, mutation and post-read all address a real object.
  const reserved = hyp.method === 'DELETE' && !functionLevel && privileged && hyp.reservedVictimId
    ? hyp.reservedVictimId
    : null
  const resolvedId = reserved && /^[A-Za-z0-9_.:-]{1,128}$/.test(reserved) ? reserved : id
  const realPath = resolvedId ? fillResourceId(hyp.pathAndQuery, resolvedId) : hyp.pathAndQuery
  const owner = floorActorFor(ownerHandle, input.personas)
  const probe = floorActorFor(probeHandle, input.personas)
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }

  if (hyp.method === 'GET') {
    // The legacy read proof is an entitled read plus a cross-actor read, with an authenticated
    // bogus-id control where the route only denies nonexistent identifiers. The shared
    // authorization oracle decides whether the denial is boundary evidence or merely selectivity,
    // and confirms a cross-tenant disclosure from the entitled/probe pair.
    const deniedPath = id && !functionLevel ? fillResourceId(hyp.pathAndQuery, bogusIdFor(id)) : realPath
    const idInPath = /\/\{\{id\}\}(?:\/|$|\?)/.test(hyp.pathAndQuery) || /\/:\w+(?:\/|$|\?)/.test(hyp.pathAndQuery)
    const args: AccessBoundaryArgs = {
      origin: hyp.endpoint.origin,
      method: 'GET',
      pathAndQuery: realPath,
      vulnClass,
      owner,
      probe,
      denied: owner,
      ...(deniedPath !== realPath ? { deniedPathAndQuery: deniedPath } : {}),
      ...(!idInPath ? { controlEvidence: 'denial_or_distinct' as const } : {}),
      ...(Object.keys(headers).length > 0 ? { headers } : {}),
    }
    return { ...sketch, args, paramLocation: 'path' }
  }

  // A mutation proves impact only through a separate readback. The legacy shape needs both a
  // pre-mutation readback and a post-mutation delta, plus a control that keeps the delta
  // attributable (a fresh baseline write, or a reset for self-service session state).
  const body = authzBodyOf(input)
  if (!body) return { ...sketch, skipReason: 'authz mutation hypothesis has no request body template' }
  const readbackPath = authzReadbackPath(input, resolvedId, functionLevel)
  if (!readbackPath) return { ...sketch, skipReason: 'authz mutation hypothesis has no separate readback route' }
  const readbackActor = floorActorFor(hyp.readbackPersona ?? ownerHandle, input.personas)
  const selfState = Boolean(hyp.functionState?.bindings?.length)
  const baselineWrite = !functionLevel && !selfState && hyp.method !== 'DELETE' ? baselineWriteFor(body) : null
  const resetBody = selfState && hyp.functionState?.reset?.length
    ? { ...body, ...Object.fromEntries(hyp.functionState.reset.map(item => [item.field, item.value])) }
    : null
  const args: PersistedMutationArgs = {
    origin: hyp.endpoint.origin,
    method: hyp.method,
    pathAndQuery: realPath,
    vulnClass,
    actor: probe,
    body,
    baselineMethod: 'GET',
    baselinePathAndQuery: readbackPath,
    readbackMethod: 'GET',
    readbackPathAndQuery: readbackPath,
    readbackActor,
    ...(baselineWrite ? { baselineWrite: { body: baselineWrite.body, actor: owner, method: hyp.method } } : {}),
    ...(resetBody ? { reset: { body: resetBody, actor: probe, method: hyp.method } } : {}),
    ...(hyp.authzRequiredRole ? { requiredRole: hyp.authzRequiredRole } : {}),
    ...(functionLevel && privileged && hyp.authzRequiredRole ? { oracleEvents: ['privilege_escalation'] } : {}),
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
  }
  return { ...sketch, args, paramLocation: 'path' }
}

// ---------------------------------------------------------------------------------------------
// Planning entrypoint
// ---------------------------------------------------------------------------------------------

/**
 * Resolve a wired recipe plan for one legacy candidate, or null when the pair is not wired. A wired
 * pair that cannot be expressed returns a plan with `skipReason` so the engine records a named
 * rejection instead of silently taking the legacy path.
 */
function planBrowserRecipe(input: FloorRecipePlanInput): FloorRecipePlan {
  const hyp = input.hypothesis
  const sketch: FloorRecipePlan = {
    recipeId: 'browser_sink',
    specKind: input.specKind,
    vulnClass: input.vulnClass || 'dom_xss',
    endpoint: hyp.endpoint.pathTemplate,
    args: {} as FloorRecipeArgs,
  }
  const spec = input.candidateSpec
  const steps = Array.isArray(spec?.steps) ? spec!.steps as Array<Record<string, unknown>> : null
  if (!steps || steps.length === 0) return { ...sketch, skipReason: 'browser spec carried no steps to replay' }
  // Protocol browser proofs (postMessage/fetch/builtin) have no recipe model yet and stay on the
  // framework verifier; only navigate/fill/click DOM proofs migrate.
  if (isProtocolBrowserSpec(steps)) return { ...sketch, skipReason: 'protocol browser proof (postMessage/fetch/builtin) stays on the framework verifier' }
  const origin = typeof steps[0]?.origin === 'string' ? String(steps[0].origin) : hyp.endpoint.origin
  const envelope = browserSinkEnvelopeFromSteps({ origin, vulnClass: 'dom_xss', steps })
  if (!envelope) return { ...sketch, skipReason: 'browser spec steps could not be expressed as a browser_sink recipe' }
  return { ...sketch, vulnClass: input.vulnClass || envelope.args.vulnClass, args: envelope.args }
}

export function planFloorRecipe(input: FloorRecipePlanInput): FloorRecipePlan | null {
  const recipe = wiredRecipeForSpecKind(input.specKind, input.vulnClass)
  if (!recipe) return null
  switch (recipe) {
    case 'boolean_or_timing': return planBooleanRecipe(input)
    case 'race_burst':
    case 'conserved_balance': return planRaceRecipe(input)
    case 'browser_sink': return planBrowserRecipe(input)
    case 'access_boundary':
    case 'persisted_mutation': return planAuthzRecipe(input)
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

/**
 * Host seam for browser recipes: run an ordered navigate/fill/click session through the same
 * `ScopedBrowser` the framework verifier uses and return only the traces whose canary reached an
 * executable sink. The recipe still owns the confirmation rule; this only records evidence.
 */
export function browserSessionSeam(input: {
  browser: ScopedBrowser
  grant: Grant
  signal: AbortSignal
  origin: string
  runId?: string
  assignmentId?: string
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
}): NonNullable<FloorRecipeDeps['browserSession']> {
  return async session => {
    if (typeof input.browser.runBrowserSession !== 'function') return null
    const defaultPersona = session.actor?.handle &&
      session.actor.handle !== 'anonymous' &&
      session.actor.handle !== ANONYMOUS_HANDLE
      ? session.actor.handle
      : undefined
    const sessionSteps: BrowserSessionStep[] = session.steps.map((step, index) => {
      const persona = step.persona ?? defaultPersona
      return {
        id: `b${index + 1}`,
        role: step.role,
        origin: input.origin,
        ...(step.pathAndQuery !== undefined ? { pathAndQuery: step.pathAndQuery } : {}),
        ...(step.reusePage ? { reusePage: true } : {}),
        ...(persona ? { persona } : {}),
        action: step.action,
        ...(step.selector !== undefined ? { selector: step.selector } : {}),
        ...(step.value !== undefined ? { value: step.value } : {}),
        ...(step.waitAfterLoadMs !== undefined ? { waitAfterLoadMs: step.waitAfterLoadMs } : {}),
        canaryToken: session.canaryToken,
        checkKind: 'dom_xss' as const,
        enableSinkHook: true,
        ...(input.runId ? { runId: input.runId } : {}),
        ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
        ...(input.recordExchange ? { onExchange: input.recordExchange } : {}),
      }
    })
    const visits = await input.browser.runBrowserSession(sessionSteps, input.grant, input.signal)
    const traces: Array<{ id: string; origin: string; sinks: string[] }> = []
    let sinkHit = false
    visits.forEach((visit, index) => {
      if (!visit) return
      const hits = visit.domSinkTraces.filter(trace => trace.containsCanary)
      // Two non-sink execution channels the legacy verifier already accepted: the driver's canary
      // flag, and an exact document-title match. The title is compared by equality (never
      // containment) so a server-side reflection of the payload into `<title>` cannot satisfy it;
      // only a handler that assigned the canary to `document.title` can.
      const titleHit = visit.title === session.canaryToken
      if (!hits.length && !visit.canaryCheck.triggered && !titleHit) return
      sinkHit = true
      traces.push({
        id: `browser-${index + 1}`,
        origin: input.origin,
        sinks: hits.length > 0
          ? [...new Set(hits.map(trace => `dom_xss:${trace.sink}`))]
          : titleHit ? ['canary:title'] : ['canary:executed'],
      })
    })
    return { traces, sinkHit }
  }
}

export interface RunPlannedRecipeInput {
  plan: FloorRecipePlan
  hypothesis: EngineHypothesis
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  assignmentId?: string
  runId?: string
  headers?: Record<string, string>
  /** Scoped browser used by browser recipes; omitted by callers that never plan one. */
  browser?: ScopedBrowser
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
}

/** Run a plan through the broker-backed Layer-1 adapter. Never falls back to the legacy verifier. */
export async function runPlannedRecipe(input: RunPlannedRecipeInput): Promise<FloorRecipeExecution> {
  const deps = brokerFloorRecipeDeps({
    broker: input.broker,
    grant: input.grant,
    signal: input.signal,
    origin: input.plan.args.origin || input.hypothesis.endpoint.origin,
    probeClass: input.hypothesis.probeClass,
    ...(input.runId ? { runId: input.runId } : {}),
    ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
    ...(input.headers ? { headers: input.headers } : {}),
    ...(input.recordExchange ? { recordExchange: input.recordExchange } : {}),
  })
  const browser = input.browser ?? new ScopedBrowser(input.broker)
  const withBrowser: FloorRecipeDeps = input.plan.recipeId === 'browser_sink'
    ? {
        ...deps,
        browserSession: browserSessionSeam({
          browser,
          grant: input.grant,
          signal: input.signal,
          origin: input.plan.args.origin || input.hypothesis.endpoint.origin,
          ...(input.runId ? { runId: input.runId } : {}),
          ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
          ...(input.recordExchange ? { recordExchange: input.recordExchange } : {}),
        }),
      }
    : deps
  return executeFloorRecipeById(input.plan.recipeId, input.plan.args, withBrowser)
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
  open_redirect: 'medium',
  url_redirect: 'medium',
  dom_xss: 'high',
  xss: 'high',
  xss_reflected: 'high',
  xss_stored: 'high',
  injection: 'high',
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
  open_redirect: 'CWE-601',
  url_redirect: 'CWE-601',
  dom_xss: 'CWE-79',
  xss: 'CWE-79',
  xss_reflected: 'CWE-79',
  xss_stored: 'CWE-79',
  injection: 'CWE-89',
}

const TITLE_BY_RECIPE: Readonly<Record<PersistedFloorRecipeId, string>> = {
  access_boundary: 'Cross-actor object or function access',
  persisted_mutation: 'Persisted unauthorized state change',
  boolean_or_timing: 'SQL injection differential',
  oob_callback: 'Out-of-band callback from injected payload',
  race_burst: 'Synchronized burst double-spend',
  disclosure: 'Unauthorized record disclosure',
  redirect: 'Open redirect to off-origin destination',
  browser_sink: 'Client-side browser sink execution',
  injection_fingerprint: 'Parser or engine injection fingerprint',
  conserved_balance: 'Conserved-balance concurrency violation',
}

const is2xxJq = (id: string) => `(.steps.${id}.status >= 200 and .steps.${id}.status < 300)`
const isDeniedJq = (id: string) =>
  `(.steps.${id}.status == 401 or .steps.${id}.status == 403 or .steps.${id}.status == 404)`

/**
 * Replay assertion for a receipt-confirmed spec. This is the *retest* re-check of an already
 * persisted proof (reproduced vs fixed), not the confirmation path: it restates the receipt's
 * structural precondition over the recorded steps so a hardened fixture cannot replay as reproduced.
 */
function retestAssertion(recipe: PersistedFloorRecipeId, steps: readonly { id: string; role: string; description?: string }[], args?: PersistedFloorRecipeArgs): string {
  // Evidence roles (`entitled_read`, `baseline_read`, ...) are carried in the step description: the
  // persisted http_chain schema only allows arm roles. Match the description first so a replay
  // assertion never silently references a step it does not have.
  const ids = (role: string) => steps
    .filter(step => step.description === role || (step.description === undefined && step.role === role))
    .map(step => step.id)
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
      // A collection-reference negative control is selective through a different 2xx body, not a
      // denial; the retest must assert the same predicate the proof used.
      const distinctControl = (args as AccessBoundaryArgs | undefined)?.controlEvidence === 'denial_or_distinct'
      const deniedJq = denied
        ? distinctControl && entitled
          ? `(${is2xxJq(denied)} and (.steps.${denied}.body != .steps.${entitled}.body))`
          : isDeniedJq(denied)
        : 'true'
      const confirmed = [probe, denied].filter((id): id is string => Boolean(id))
      return `{ controlPassed: (${entitled ? is2xxJq(entitled) : 'true'}), `
        + `confirmed: (${confirmed.length ? confirmed.map(id => (id === denied ? deniedJq : is2xxJq(id))).join(' and ') : 'true'}), `
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
      const reset = first('state_reset')
      const baselineWrite = first('baseline_write')
      const diff = baseline && after ? `(.steps.${after}.body != .steps.${baseline}.body)` : 'true'
      const controls = [baseline, reset, baselineWrite].filter((id): id is string => Boolean(id))
      return `{ controlPassed: (${controls.length ? controls.map(is2xxJq).join(' and ') : 'true'}), `
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
    case 'race_burst':
    case 'conserved_balance': {
      const burst = steps.filter(step => (step.description ?? step.role).startsWith('burst_')).map(step => step.id)
      const successes = burst.length >= 2
        ? burst.map(id => is2xxJq(id)).slice(0, 2).join(' and ')
        : 'true'
      const baseline = first('baseline_read')
      const post = first('post_read')
      if (recipe === 'conserved_balance') {
        const readOk = [baseline, post].filter((id): id is string => Boolean(id)).map(is2xxJq).join(' and ') || 'true'
        return `{ controlPassed: (${readOk}), `
          + `confirmed: ((${readOk}) and (${successes})), `
          + 'observed: "recipe replay: conserved-balance burst re-observed", expected: "concurrent mutations preserve conservation identically to serial execution" }'
      }
      const divergence = burst.slice(1)
        .map((id, index) => `(.steps.${id}.body != .steps.${burst[index]}.body)`)
        .join(' or ') || 'true'
      return `{ controlPassed: true, `
        + `confirmed: ((${successes}) and (${divergence})), `
        + 'observed: "recipe replay: burst re-observed", expected: "a repeated terminal transition never produces divergent outcomes" }'
    }
    case 'redirect': {
      const probe = first('redirect_probe')
      const control = first('same_origin_control')
      const is3xx = (id: string) => `(.steps.${id}.status >= 300 and .steps.${id}.status < 400)`
      return `{ controlPassed: (${control ? `(.steps.${control}.status >= 200 and .steps.${control}.status < 400)` : 'true'}), `
        + `confirmed: (${probe ? is3xx(probe) : 'true'}), `
        + 'observed: "recipe replay: off-origin redirect re-observed", expected: "redirect stays on origin" }'
    }
    case 'browser_sink': {
      return '{ controlPassed: true, confirmed: true, observed: "recipe replay: browser sink re-observed", expected: "no untrusted browser sink execution" }'
    }
    case 'injection_fingerprint': {
      const control = first('benign_control')
      const probe = first('injection_probe')
      const diff = control && probe ? `(.steps.${probe}.body != .steps.${control}.body)` : 'true'
      return `{ controlPassed: (${control ? is2xxJq(control) : 'true'}), `
        + `confirmed: (${diff}), `
        + 'observed: "recipe replay: injection fingerprint re-observed", expected: "no parser/engine error fingerprint on probe" }'
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
  const jq = retestAssertion(plan.recipeId, steps, plan.args)
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
  if (plan.recipeId === 'browser_sink' || plan.specKind === 'browser_chain') {
    const args = plan.args as BrowserSinkArgs
    const defaultPersona = args.actor?.handle && args.actor.handle !== 'anonymous' && args.actor.handle !== ANONYMOUS_HANDLE
      ? args.actor.handle
      : undefined
    const browserSteps = (args.steps && args.steps.length > 0)
      ? args.steps.map((step, index) => ({
          id: `${step.role === 'control' ? 'c' : 'p'}${index + 1}`,
          role: step.role,
          description: `${step.role} ${step.action}`,
          origin,
          ...(step.pathAndQuery !== undefined ? { pathAndQuery: step.pathAndQuery } : index === 0 ? { pathAndQuery: args.pathAndQuery || '/' } : {}),
          ...(step.reusePage ? { reusePage: true } : {}),
          ...(step.persona ?? defaultPersona ? { persona: step.persona ?? defaultPersona } : {}),
          action: step.action,
          ...(step.selector ? { selector: step.selector } : {}),
          ...(step.value !== undefined ? { value: step.value } : {}),
          ...(step.waitAfterLoadMs !== undefined ? { waitAfterLoadMs: step.waitAfterLoadMs } : {}),
          checkKind: 'dom_xss' as const,
          enableSinkHook: true,
        }))
      : [
          { id: 'c1', role: 'control' as const, description: 'Control view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const, checkKind: 'dom_xss' as const, enableSinkHook: true },
          { id: 'p1', role: 'probe' as const, description: 'Probe view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const, checkKind: 'dom_xss' as const, enableSinkHook: true },
        ]
    // Ensure schema invariants: at least one control and one probe step, and step 1 has pathAndQuery.
    const hasControl = browserSteps.some(s => s.role === 'control')
    const hasProbe = browserSteps.some(s => s.role === 'probe')
    const validSteps = [
      ...(hasControl ? [] : [{ id: 'c0', role: 'control' as const, description: 'Control view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const }]),
      ...browserSteps,
      ...(hasProbe ? [] : [{ id: 'p0', role: 'probe' as const, description: 'Probe view', origin, pathAndQuery: args.pathAndQuery || '/', ...(defaultPersona ? { persona: defaultPersona } : {}), action: 'navigate' as const }]),
    ]
    return { ...base, kind: 'browser_chain', steps: validSteps }
  }
  return { ...base, kind: 'http_chain', steps }
}

/** Build the persisted spec record for a recipe confirmation (steps = host-recorded exchanges). */
export function recipeSpecRecord(plan: FloorRecipePlan, execution: FloorRecipeExecution): SynthesizedEngineSpec {
  return {
    kind: plan.specKind,
    vulnClass: plan.vulnClass,
    endpoint: plan.endpoint,
    // The receipt owns the retest: persist the exact recipe that confirmed so a retest re-runs it and
    // validates a fresh ProofReceipt instead of re-interpreting the legacy declarative shape.
    spec: { ...recordSpecFor(plan, execution, plan.args.origin), recipe: { recipeId: plan.recipeId, args: plan.args } },
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

/**
 * Receipt-based retest of a persisted recipe (Cut 3 retest migration).
 *
 * Re-runs the exact `recipeId` + args the confirmation recorded, through the same broker seam, and
 * lets `runFloorRecipe` → `verifyReceipt()` decide. The legacy declarative verifier is never called
 * for a recipe-owned proof, so the persisted spec's shape is not the retest contract.
 *
 * Verdict mapping keeps the patch gate's semantics:
 *   - the receipt confirms again → `reproduced`
 *   - the receipt is rejected, or a precondition no longer holds (e.g. the vulnerable route now
 *     refuses the actor) → `fixed`
 *   - the recipe could not finish (aborted / schema error / timeout) → `inconclusive`
 */
export async function retestPersistedRecipe(input: {
  envelope: FloorRecipeEnvelope
  specKind: string
  vulnClass: string
  endpoint: string
  /** Target origin for every exchange; callers rebase it when a rebuilt lab moves ports. */
  origin: string
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  runId?: string
  assignmentId?: string
  probeClass?: string
  recordExchange?: (exchange: BrokerExchangeResult) => string | void
  browserTrace?: FloorRecipeDeps['browserTrace']
  browserSession?: FloorRecipeDeps['browserSession']
}): Promise<{ verdict: RetestVerdict; execution: FloorRecipeExecution | null; replay: ReplayVerificationResult }> {
  const args = input.envelope.args as unknown as PersistedFloorRecipeArgs
  const plan: FloorRecipePlan = {
    recipeId: input.envelope.recipeId,
    specKind: input.specKind,
    vulnClass: input.vulnClass,
    endpoint: input.endpoint,
    args,
  }
  let execution: FloorRecipeExecution
  try {
    const baseDeps = brokerFloorRecipeDeps({
      broker: input.broker,
      grant: input.grant,
      signal: input.signal,
      origin: input.origin,
      ...(input.probeClass ? { probeClass: input.probeClass } : {}),
      ...(input.runId ? { runId: input.runId } : {}),
      ...(input.assignmentId ? { assignmentId: input.assignmentId } : {}),
      ...(input.recordExchange ? { recordExchange: input.recordExchange } : {}),
    })
    const deps: FloorRecipeDeps = {
      ...baseDeps,
      ...(input.browserTrace ? { browserTrace: input.browserTrace } : {}),
      ...(input.browserSession ? { browserSession: input.browserSession } : {}),
    }
    execution = await executeFloorRecipeById(input.envelope.recipeId, args, deps)
  } catch (error) {
    // A recipe that cannot execute at all is not evidence the vulnerability is gone.
    const reason = `recipe retest could not run: ${error instanceof Error ? error.message.slice(0, 300) : String(error).slice(0, 300)}`
    return {
      verdict: 'inconclusive',
      execution: null,
      replay: {
        verdict: 'inconclusive',
        outcome: { confirmed: false, controlPassed: false, observed: reason, expected: 'the persisted recipe re-executes', reason },
        exchangeIds: [],
        exchanges: [],
        evidencePayload: { kind: plan.specKind, recipe: plan.recipeId, confirmation: 'proof_receipt' },
        evidenceSha256: createHash('sha256').update(reason).digest('hex'),
      },
    }
  }
  const exchangeIds = [...execution.result.exchangeIds]
  const replay = recipeRetestResult(plan, execution, exchangeIds)
  const verdict: RetestVerdict = execution.result.confirmed
    ? 'reproduced'
    : execution.failure?.code === 'recipe_error'
      ? 'inconclusive'
      : 'fixed'
  return { verdict, execution, replay }
}

function recipeResult(
  plan: FloorRecipePlan,
  execution: FloorRecipeExecution,
  exchangeIds: readonly string[],
  confirmed: boolean,
): ReplayVerificationResult {
  const verification = execution.result.verification
  const steps = recordSteps(plan.args.origin, execution)
  const burstResults = plan.specKind === 'race_burst'
    ? execution.result.steps
      .filter(step => step.role.startsWith('burst_'))
      .map(step => ({ status: step.status, method: step.method, pathAndQuery: step.pathAndQuery, durationMs: step.durationMs }))
    : null
  const evidencePayload: Record<string, unknown> = {
    kind: plan.specKind,
    origin: plan.args.origin,
    replayedAt: null,
    confirmation: 'proof_receipt',
    recipe: plan.recipeId,
    receipt: execution.receipt,
    verification,
    ...(burstResults && burstResults.length > 0 ? { burst: { results: burstResults } } : {}),
    steps: Object.fromEntries(steps.map((step, index) => [step.id, {
      role: step.role,
      status: execution.result.steps[index]?.status ?? null,
      method: step.request.method,
      pathAndQuery: step.request.pathAndQuery,
    }])),
    exchangeIds: [...execution.result.exchangeIds],
  }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
  const isRecipeError = !confirmed && execution.failure?.code === 'recipe_error'
  const reason = isRecipeError
    ? (execution.failure?.message ?? verification.reason)
    : !confirmed && execution.failure?.code === 'precondition_unsatisfied'
      ? execution.failure.message
      : verification.reason
  return {
    verdict: confirmed ? 'confirmed' : isRecipeError ? 'inconclusive' : 'dismissed',
    ...(confirmed ? { verificationTier: 'runtime_confirmed' as const } : {}),
    outcome: {
      confirmed,
      controlPassed: confirmed,
      observed: verification.observed.slice(0, 1200),
      expected: verification.expected.slice(0, 1200),
      reason: reason.slice(0, 1200),
    },
    exchangeIds: [...exchangeIds],
    exchanges: [],
    evidencePayload,
    evidenceSha256,
    receipt: { receipt: execution.receipt, verification, mode: 'strict' },
  }
}


// ---------------------------------------------------------------------------------------------
// Cut 3e: Typed runners retiring legacy VM branches from replay-verifier.ts
// ---------------------------------------------------------------------------------------------

export interface LegacySpecRunnerContext {
  broker: RequestBroker
  canaryBroker?: CanaryBroker
  backend: WorkerBackend
  reposDir?: string
  grant: Grant
  signal: AbortSignal
  storage?: Store
  runId?: string
  assignmentId: string
  onExchange?: (exchange: BrokerExchangeResult) => string | void
}

function runnerSecrets(grant: Grant, broker: RequestBroker): NamedSecret[] {
  return [
    ...(grant.secrets ?? []),
    ...(grant.personas ? personaSecrets(grant.personas) : []),
    ...(broker.getRegisteredSecrets?.() ?? []),
  ]
}

function runnerInconclusive(
  reason: string,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
  evidencePayload: Record<string, unknown>,
): ReplayVerificationResult {
  const payload = { ...evidencePayload, error: reason }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(payload)).digest('hex')
  return {
    verdict: 'inconclusive',
    outcome: {
      confirmed: false,
      controlPassed: false,
      observed: reason.slice(0, 1200),
      expected: 'Clean replay execution passing control and deterministic assertions.',
      reason: reason.slice(0, 1200),
    },
    exchangeIds,
    exchanges,
    evidencePayload: payload,
    evidenceSha256,
  }
}

function runnerSummarizeExchange(ex: BrokerExchangeResult) {
  let json: unknown = null
  if (ex.mediaType.includes('json')) {
    try { json = JSON.parse(ex.body) } catch { json = null }
  }
  return {
    origin: ex.origin,
    finalOrigin: ex.finalOrigin,
    redirectOrigins: ex.redirectOrigins,
    method: ex.method,
    pathAndQuery: ex.pathAndQuery,
    personaHandle: ex.personaHandle,
    status: ex.status,
    mediaType: ex.mediaType,
    headers: ex.respHeaders,
    setCookies: ex.setCookies,
    body: ex.body.slice(0, 64 * 1024),
    bodyPreview: ex.bodyPreview,
    bodyBytes: ex.bodyBytes,
    bodySha256: ex.bodySha256,
    durationMs: ex.durationMs,
    ...(ex.secretMatches?.length
      ? {
          secretMatches: ex.secretMatches.slice(0, 16).map(m => ({
            kind: m.kind,
            sha256Prefix: m.sha256Prefix,
            ...(m.fieldPath ? { fieldPath: m.fieldPath } : {}),
            count: m.count,
          })),
        }
      : {}),
    ...(json !== null ? { json } : {}),
  }
}

function runnerInterpolateString(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g, (full, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? vars[name] : full)
}

function runnerInterpolateValue(value: unknown, vars: Record<string, string>): unknown {
  if (typeof value === 'string') return runnerInterpolateString(value, vars)
  if (Array.isArray(value)) return value.map(v => runnerInterpolateValue(v, vars))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = runnerInterpolateValue(v, vars)
    }
    return out
  }
  return value
}

function runnerApplyBodySignature(interpolated: unknown, signable: NonNullable<ReplayStep['request']['bodySignature']>): unknown {
  const input = interpolated && typeof interpolated === 'object' && !Array.isArray(interpolated)
    ? { ...(interpolated as Record<string, unknown>) }
    : {}
  const key = `guardian_whk_${randomBytes(8).toString('hex')}`
  const ts = String(Math.floor(Date.now() / 1000))
  if (signable.timestampField) input[signable.timestampField] = ts
  input[signable.keyField] = key
  const withoutSig = { ...input }
  delete withoutSig[signable.signatureField]
  const event = signable.eventField
    ? withoutSig[signable.eventField]
    : (withoutSig.event ?? withoutSig.payload ?? withoutSig.data ?? withoutSig)
  const asText = (value: unknown): string => (typeof value === 'string' ? value : JSON.stringify(value))
  const canonical = signable.canonical === 'ts_event'
    ? `${ts}.${asText(event)}`
    : signable.canonical === 'ts_body'
      ? `${ts}.${JSON.stringify(withoutSig)}`
      : signable.canonical === 'event'
        ? asText(event)
        : JSON.stringify(withoutSig)
  input[signable.signatureField] = createHmac('sha256', key).update(canonical).digest(signable.encoding)
  return input
}

function runnerStepToBrokerRequest(
  step: ReplayStep,
  vars: Record<string, string>,
  opts?: { replayJarPrefix?: string; runId?: string; assignmentId?: string },
): BrokerHttpRequest {
  const req = step.request
  let sessionId: string | undefined
  if (req.session) {
    if (opts?.replayJarPrefix) {
      const candidate = `rv-${opts.replayJarPrefix}-${req.session}`
      sessionId = candidate.length <= 32
        ? candidate
        : `rv-${opts.replayJarPrefix}-${createHash('sha256').update(req.session).digest('hex').slice(0, 12)}`.slice(0, 32)
    } else {
      sessionId = req.session
    }
  }
  const pathAndQuery = runnerInterpolateString(req.pathAndQuery, vars)
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    headers[k] = runnerInterpolateString(v, vars)
  }
  let body: string | undefined
  if (req.textBody !== undefined) {
    body = runnerInterpolateString(req.textBody, vars)
  } else if (req.jsonBody !== undefined) {
    const interpolated = runnerInterpolateValue(req.jsonBody, vars)
    const signed = req.bodySignature ? runnerApplyBodySignature(interpolated, req.bodySignature) : interpolated
    body = JSON.stringify(signed)
    if (!headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json'
    }
  }
  let authMutation: AuthMutation | undefined = req.authMutation
  if (authMutation && authMutation.kind === 'jku_x5u_canary') {
    const rawUrl = authMutation.url ?? authMutation.value
    const interpUrl = rawUrl !== undefined ? runnerInterpolateString(rawUrl, vars) : undefined
    authMutation = {
      ...authMutation,
      ...(authMutation.url !== undefined && interpUrl !== undefined ? { url: interpUrl } : {}),
      ...(authMutation.value !== undefined && interpUrl !== undefined ? { value: interpUrl } : {}),
    }
  }
  return {
    origin: req.origin,
    method: req.method,
    pathAndQuery,
    headers,
    body,
    persona: req.persona,
    ...(sessionId ? { session: sessionId } : {}),
    sessionGroupRole: step.role,
    ...(req.csrfBind !== undefined ? { csrfBind: req.csrfBind } : {}),
    ...(authMutation ? { authMutation } : {}),
    ...(req.traceId ? { traceId: req.traceId } : {}),
    ...(opts?.runId ? { runId: opts.runId } : {}),
    ...(opts?.assignmentId ? { assignmentId: opts.assignmentId } : {}),
    followRedirects: req.followRedirects,
  }
}

function runnerHasDestructiveContent(text: string): boolean {
  if (containsDestructivePayload(text)) return true
  try {
    const decoded = decodeURIComponent(text.replaceAll('+', ' '))
    if (decoded !== text && containsDestructivePayload(decoded)) return true
  } catch {
    const plusDecoded = text.replaceAll('+', ' ')
    if (plusDecoded !== text && containsDestructivePayload(plusDecoded)) return true
  }
  return false
}

function runnerIsPrime(n: number): boolean {
  if (n < 2) return false
  if (n % 2 === 0) return n === 2
  const limit = Math.floor(Math.sqrt(n))
  for (let i = 3; i <= limit; i += 2) {
    if (n % i === 0) return false
  }
  return true
}

function runnerFiveDigitPrime(exclude?: number): number {
  for (;;) {
    const candidate = randomInt(10_007, 99_991) | 1
    if (candidate !== exclude && runnerIsPrime(candidate)) return candidate
  }
}

function runnerAlphaToken(len = 7): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789'
  const bytes = randomBytes(len)
  let out = ''
  for (let i = 0; i < len; i += 1) out += alphabet[bytes[i] % alphabet.length]
  return out
}

function runnerBase64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
}

async function runnerSleepAbortable(ms: number, signal: AbortSignal) {
  if (signal.aborted) throw signal.reason
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason)
    }
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

function runnerStatusMatchesExpected(expected: number | number[] | undefined, status: number): boolean {
  if (expected === undefined) return false
  return Array.isArray(expected) ? expected.includes(status) : expected === status
}

function runnerIsUnexpectedErrorStatus(status: number, ...expected: Array<number | number[] | undefined>): boolean {
  if (status !== 404 && status < 500) return false
  return !expected.some(e => runnerStatusMatchesExpected(e, status))
}

const RUNNER_POSTURE_CWES = new Set([
  'CWE-16', 'CWE-200', 'CWE-209', 'CWE-284', 'CWE-285', 'CWE-287', 'CWE-288', 'CWE-306', 'CWE-319', 'CWE-326',
  'CWE-346', 'CWE-523', 'CWE-538', 'CWE-540', 'CWE-614', 'CWE-639', 'CWE-693', 'CWE-862', 'CWE-863', 'CWE-942',
  'CWE-1004', 'CWE-1021',
])
const RUNNER_POSTURE_CATEGORY_RE = /access|auth|bypass|cors|header|posture|misconfig|exposure|session|cookie|transport|tls|csp|policy|idor|bola|bfla/i

function runnerDefaultRequireControlNonError(spec: DeclarativeReplaySpec): boolean {
  if (spec.kind === 'static_ast_proof') return false
  return RUNNER_POSTURE_CWES.has(spec.cwe) || RUNNER_POSTURE_CATEGORY_RE.test(spec.category)
}

function runnerReadJsonPath(obj: unknown, path: string): string | null {
  const clean = path.replace(/^\$\.?/, '')
  const segments = clean.split('.').filter(Boolean)
  let cur: unknown = obj
  for (const seg of segments) {
    if (cur === null || cur === undefined) return null
    const arrayMatch = seg.match(/^([a-zA-Z0-9_-]*)\[(\d+)\]$/)
    if (arrayMatch) {
      const [, key, idxStr] = arrayMatch
      if (key) cur = (cur as Record<string, unknown>)[key]
      if (!Array.isArray(cur)) return null
      cur = cur[Number(idxStr)]
    } else if (typeof cur === 'object') {
      cur = (cur as Record<string, unknown>)[seg]
    } else {
      return null
    }
  }
  if (cur === null || cur === undefined) return null
  return typeof cur === 'string' ? cur : JSON.stringify(cur)
}

function runnerExtractVariables(step: ReplayStep, exchange: BrokerExchangeResult, vars: Record<string, string>) {
  for (const rule of step.extract ?? []) {
    let extracted: string | null = null
    if (rule.from === 'status') {
      extracted = String(exchange.status)
    } else if (rule.from === 'header') {
      extracted = exchange.respHeaders[rule.selector.toLowerCase()] ?? null
    } else if (rule.from === 'json') {
      try { extracted = runnerReadJsonPath(JSON.parse(exchange.body), rule.selector) } catch { extracted = null }
    } else if (rule.from === 'regex') {
      try {
        const m = exchange.body.match(new RegExp(rule.selector))
        extracted = m ? (m[1] ?? m[0] ?? null) : null
      } catch {
        extracted = null
      }
    }
    if (extracted !== null) vars[rule.varName] = extracted.slice(0, 512)
  }
}

function runnerHandleError(
  err: unknown,
  ctx: LegacySpecRunnerContext,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
  evidencePayload: Record<string, unknown>,
): ReplayVerificationResult {
  const secrets = runnerSecrets(ctx.grant, ctx.broker)
  const safePayload = redactJsonValue(evidencePayload, secrets)
  if (err instanceof BrokerDenied || err instanceof BrokerCircuitOpen || err instanceof BrokerApprovalRequired) {
    return runnerInconclusive(redact(err.message, secrets), exchanges, exchangeIds, safePayload)
  }
  const message = redact(err instanceof Error ? err.message : String(err), secrets)
  return runnerInconclusive(`Replay execution failed: ${message}`, exchanges, exchangeIds, safePayload)
}

/**
 * Cut 3e typed runner for `static_ast_proof` (zero-jq).
 * Enforces strict tier separation: can only ever emit `static_verified`, `dismissed`, or `inconclusive`.
 */
export async function runStaticAstProofRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'static_ast_proof' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  if (!ctx.reposDir) {
    return runnerInconclusive('static_ast_proof requires the read-only /repos mount (reposDir).', [], [], { kind: spec.kind })
  }
  const basePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  try {
    const astResult = await ctx.backend.verifyStaticAst(ctx.assignmentId, {
      repo: spec.repo,
      file: spec.file,
      startLine: spec.startLine,
      endLine: spec.endLine,
      engine: spec.engine,
      ruleOrPattern: spec.ruleOrPattern,
    }, ctx.signal, { reposDir: ctx.reposDir })
    const evidencePayload = redactJsonValue({
      ...basePayload,
      repo: spec.repo,
      file: spec.file,
      startLine: spec.startLine,
      endLine: spec.endLine,
      engine: spec.engine,
      ruleOrPattern: spec.ruleOrPattern,
      sourceToSinkTrace: spec.sourceToSinkTrace ?? null,
      runtimeProofGap: spec.runtimeProofGap,
      verificationTier: 'static_verified',
      astVerify: astResult,
      static: {
        verified: astResult.verified,
        matchCount: astResult.matchCount,
        matchedLines: astResult.matchedLines,
        controlPassed: astResult.verified,
      },
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
    if (astResult.verified) {
      return {
        verdict: 'static_verified',
        verificationTier: 'static_verified',
        outcome: {
          confirmed: true,
          controlPassed: true,
          observed: `Static AST matched ${astResult.matchCount} line(s) in ${spec.repo}/${spec.file}:${spec.startLine}-${spec.endLine}.`,
          expected: `Pattern ${spec.ruleOrPattern} verified in cited source range.`,
        },
        exchangeIds: [],
        exchanges: [],
        evidencePayload,
        evidenceSha256,
      }
    }
    const reason = `Static AST re-verification failed: ${astResult.reason ?? 'pattern not found in the cited range.'}`
    return {
      verdict: 'dismissed',
      outcome: {
        confirmed: false,
        controlPassed: true,
        observed: reason.slice(0, 1200),
        expected: `Pattern ${spec.ruleOrPattern} verified in cited source range.`,
        reason: reason.slice(0, 1200),
      },
      exchangeIds: [],
      exchanges: [],
      evidencePayload,
      evidenceSha256,
    }
  } catch (err) {
    return runnerHandleError(err, ctx, [], [], basePayload)
  }
}

/**
 * Cut 3e typed runner for `rce_proof` (zero-jq; Tier-3 + HITL gate, non-reflectable math/split_echo,
 * and ProofReceipt-verified OOB callbacks).
 */
export async function runRceProofRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'rce_proof' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult): string => {
    exchanges.push(ex)
    const id = ctx.onExchange?.(ex)
    if (typeof id === 'string' && id) {
      exchangeIds.push(id)
      return id
    }
    return `rce-${exchanges.length}`
  }

  // Hard Tier 3 + HITL approval gate
  const tier = ctx.grant.tier ?? 1
  const gateRequest = spec.probeStep.request
  if (tier < 3) {
    ctx.grant.audit('denied', gateRequest.origin)
    return runnerInconclusive(`${spec.kind} replay specs are blocked below Tier 3.`, exchanges, exchangeIds, { kind: spec.kind })
  }
  const localLab = Boolean(ctx.grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  const approvalContext: StateChangeApprovalContext = {
    personaHandle: gateRequest.persona ?? null,
    body: gateRequest.textBody ?? (gateRequest.jsonBody !== undefined ? JSON.stringify(gateRequest.jsonBody) : null),
    hasMultipart: false,
    isRaceBurst: false,
    isRceProof: true,
  }
  const approved = ctx.grant.isStateChangeApproved
    ? ctx.grant.isStateChangeApproved(gateRequest.origin, gateRequest.method, gateRequest.pathAndQuery, approvalContext)
    : localLab
  if (!approved) {
    ctx.grant.audit('denied', gateRequest.origin)
    return runnerInconclusive(`${spec.kind} requires explicit Tier 3 HITL operator approval.`, exchanges, exchangeIds, { kind: spec.kind })
  }

  const basePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  const controlVars: Record<string, string> = {}
  const probeVars: Record<string, string> = {}
  const proofMeta: Record<string, unknown> = { mode: spec.proofMode }

  let canarySession: EphemeralCanarySession | undefined
  let controlCanaryToken: string | undefined
  let probeCanaryToken: string | undefined
  let expectedNonceProduct: string | undefined
  let expectedSplitAssembled: string | undefined

  try {
    if (spec.proofMode === 'dynamic_math') {
      const a = runnerFiveDigitPrime()
      const b = runnerFiveDigitPrime(a)
      expectedNonceProduct = String(a * b)
      probeVars.nonce_a = String(a)
      probeVars.nonce_b = String(b)
      proofMeta.nonceA = a
      proofMeta.nonceB = b
      proofMeta.expectedProduct = expectedNonceProduct
    } else if (spec.proofMode === 'split_echo') {
      const part1 = runnerAlphaToken(7)
      const part2 = runnerAlphaToken(7)
      expectedSplitAssembled = part1 + part2
      probeVars.nonce_part1 = part1
      probeVars.nonce_part2 = part2
      proofMeta.expectedAssembled = expectedSplitAssembled
    } else {
      canarySession = await openCanarySession(ctx.canaryBroker, ctx.storage, ctx.runId, ctx.assignmentId, spec.origin)
      const controlCanary = canarySession.mint(`rce_proof:control:${spec.title}`)
      const probeCanary = canarySession.mint(`rce_proof:probe:${spec.title}`)
      controlCanaryToken = controlCanary.token
      probeCanaryToken = probeCanary.token
      controlVars.canary_token = controlCanary.token
      controlVars.canary_url = controlCanary.url
      controlVars.canary_dns_host = controlCanary.dnsHost
      probeVars.canary_token = probeCanary.token
      probeVars.canary_url = probeCanary.url
      probeVars.canary_dns_host = probeCanary.dnsHost
      proofMeta.controlCanaryToken = controlCanary.token
      proofMeta.probeCanaryToken = probeCanary.token
    }

    const controlReq = runnerStepToBrokerRequest(spec.controlStep, controlVars, { runId: ctx.runId, assignmentId: ctx.assignmentId })
    const probeReq = runnerStepToBrokerRequest(spec.probeStep, probeVars, { runId: ctx.runId, assignmentId: ctx.assignmentId })
    const serializedProbeReq = JSON.stringify(probeReq)

    if (runnerHasDestructiveContent(JSON.stringify(controlReq)) || runnerHasDestructiveContent(serializedProbeReq)) {
      return runnerInconclusive('Interpolated rce_proof request matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (spec.proofMode === 'split_echo' && expectedSplitAssembled && serializedProbeReq.includes(expectedSplitAssembled)) {
      return runnerInconclusive('Invalid split_echo template: nonce_part1 and nonce_part2 must be separated by execution concatenation syntax.', exchanges, exchangeIds, { kind: spec.kind })
    }

    const controlEx = await ctx.broker.executeHttp(controlReq, ctx.grant, ctx.signal)
    recordExchange(controlEx)
    const injectedAtMs = Date.now()
    const probeEx = await ctx.broker.executeHttp(probeReq, ctx.grant, ctx.signal)
    const probeExchangeId = recordExchange(probeEx)

    let deterministicProofPassed = false
    let receiptCheck: ReplayVerificationResult['receipt']
    let observed = probeEx.bodyPreview.slice(0, 400) || `status=${probeEx.status}`

    if (spec.proofMode === 'dynamic_math' && expectedNonceProduct) {
      const inProbe = probeEx.body.includes(expectedNonceProduct)
      const inControl = controlEx.body.includes(expectedNonceProduct)
      const inOutbound = serializedProbeReq.includes(expectedNonceProduct)
      deterministicProofPassed = inProbe && !inControl && !inOutbound
      proofMeta.mathVerified = deterministicProofPassed
      proofMeta.productInProbe = inProbe
      proofMeta.productInControl = inControl
      observed = deterministicProofPassed
        ? `Evaluated dynamic_math product ${expectedNonceProduct} observed exclusively in probe.`
        : `dynamic_math product not evaluated (inProbe=${inProbe}, inControl=${inControl}).`
    } else if (spec.proofMode === 'split_echo' && expectedSplitAssembled) {
      const inProbe = probeEx.body.includes(expectedSplitAssembled)
      const inControl = controlEx.body.includes(expectedSplitAssembled)
      const inOutbound = serializedProbeReq.includes(expectedSplitAssembled)
      deterministicProofPassed = inProbe && !inControl && !inOutbound
      proofMeta.splitEchoVerified = deterministicProofPassed
      proofMeta.assembledInProbe = inProbe
      proofMeta.assembledInControl = inControl
      observed = deterministicProofPassed
        ? `Concatenated split_echo token observed exclusively in probe.`
        : `split_echo concatenation not observed (inProbe=${inProbe}, inControl=${inControl}).`
    } else if (spec.proofMode === 'oob_canary' && canarySession && controlCanaryToken && probeCanaryToken) {
      const probeWait = await canarySession.waitForCallback(probeCanaryToken, ctx.signal)
      const controlCheck = canarySession.check(controlCanaryToken)
      proofMeta.canaryProbeTriggered = probeWait.triggered
      proofMeta.canaryProbeStage = probeWait.stage
      proofMeta.canaryProbePromoted = probeWait.promoted
      proofMeta.canaryProbeDetail = probeWait.detail
      proofMeta.canaryControlTriggered = controlCheck.triggered
      proofMeta.canaryControlDetail = controlCheck.detail
      const receipt: ProofReceipt = {
        vulnClass: 'oob',
        target: { origin: spec.origin, method: probeEx.method.toUpperCase(), pathAndQuery: probeEx.pathAndQuery },
        exchangeIds: [probeExchangeId],
        oobEventIds: ['rce-oob-canary'],
        browserTraceIds: [],
        claimedDelta: 'Probe triggered an out-of-band execution callback that control did not.',
        injectedAtMs,
      }
      const transcript: ReceiptTranscript = {
        entries: [{
          exchangeId: probeExchangeId,
          step: {
            id: spec.probeStep.id,
            arm: 'probe',
            method: probeEx.method.toUpperCase(),
            route: probeEx.pathAndQuery.split('?')[0] || '/',
            pathAndQuery: probeEx.pathAndQuery,
            status: probeEx.status,
            actor: { handle: probeEx.personaHandle, role: null, tenant: null, auth: 'unknown', sameSite: null },
            json: null,
            body: probeEx.body,
          },
          carrierText: `${probeReq.pathAndQuery}\n${JSON.stringify(probeReq.headers ?? {})}\n${probeReq.body ?? ''}`,
        }],
        oobEvents: [{
          id: 'rce-oob-canary',
          callbackId: probeWait.subscriptionId ?? `rce:${probeExchangeId}`,
          token: probeCanaryToken,
          targetOrigin: spec.origin,
          delivered: probeWait.triggered && !controlCheck.triggered,
          stage: probeWait.stage === 'late' ? 'late' : 'immediate',
          receivedAtMs: Date.now(),
          injectedAtMs,
        }],
      }
      const verification = verifyReceipt(receipt, transcript)
      receiptCheck = { receipt, verification, mode: 'strict' }
      deterministicProofPassed = probeWait.triggered && !controlCheck.triggered && verification.confirmed
      observed = `probeCanary=${probeWait.triggered}, controlCanary=${controlCheck.triggered}`
    }

    proofMeta.cryptographicProofPassed = deterministicProofPassed
    const evidencePayload = redactJsonValue({
      ...basePayload,
      proofMode: spec.proofMode,
      control: runnerSummarizeExchange(controlEx),
      probe: runnerSummarizeExchange(probeEx),
      proof: proofMeta,
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')

    const controlPassed = !runnerIsUnexpectedErrorStatus(controlEx.status, spec.controlStep.expectedStatus, spec.expectedStatus) &&
      controlEx.status >= 200 && controlEx.status < 500
    if (deterministicProofPassed && controlPassed) {
      return {
        verdict: 'confirmed',
        verificationTier: 'runtime_confirmed',
        outcome: {
          confirmed: true,
          controlPassed: true,
          observed: observed.slice(0, 1200),
          expected: 'Untrusted input is never evaluated as template or command code.',
        },
        exchangeIds,
        exchanges,
        evidencePayload,
        evidenceSha256,
        ...(receiptCheck ? { receipt: receiptCheck } : {}),
      }
    }
    return {
      verdict: controlPassed ? 'dismissed' : 'inconclusive',
      outcome: {
        confirmed: false,
        controlPassed,
        observed: observed.slice(0, 1200),
        expected: 'Untrusted input is never evaluated as template or command code.',
        reason: deterministicProofPassed
          ? `Control step returned unexpected HTTP ${controlEx.status}.`
          : 'Cryptographic non-destructive proof-of-execution check did not pass (possible reflection or unexecuted payload).',
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
      ...(receiptCheck ? { receipt: receiptCheck } : {}),
    }
  } catch (err) {
    return runnerHandleError(err, ctx, exchanges, exchangeIds, basePayload)
  } finally {
    await canarySession?.close()
  }
}

/**
 * Cut 3e typed runner for `cache_differential` (zero-jq).
 * Enforces unique ?_gcb= isolation, header-hit / body_repeat persistence, requireControlNonError,
 * and optional SPA catch-all control.
 */
export async function runCacheDifferentialRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'cache_differential' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult) => {
    exchanges.push(ex)
    const id = ctx.onExchange?.(ex)
    if (typeof id === 'string' && id) exchangeIds.push(id)
  }
  const basePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }

  try {
    const controlGcb = randomUUID()
    const probeGcb = randomUUID()
    const repeatGcb = randomUUID()
    const resolveCachePath = (raw: string, token: string): string =>
      raw.replaceAll('{{control_gcb}}', controlGcb)
        .replaceAll('{{probe_gcb}}', probeGcb)
        .replaceAll('{{repeat_gcb}}', repeatGcb)
        .replaceAll('{{cache_buster}}', token)

    const controlPath = resolveCachePath(spec.controlPath, controlGcb)
    const probePath = resolveCachePath(spec.probePath, probeGcb)
    const verifyPath = spec.verifyPath ? resolveCachePath(spec.verifyPath, probeGcb) : probePath
    const repeatPath = spec.repeatPath ? resolveCachePath(spec.repeatPath, repeatGcb) : null

    const actualCtrlGcb = extractCacheBusterParam(controlPath)
    const actualProbeGcb = extractCacheBusterParam(probePath)
    if (!actualCtrlGcb || !cacheBusterValueRegex.test(actualCtrlGcb) ||
        !actualProbeGcb || !cacheBusterValueRegex.test(actualProbeGcb)) {
      return runnerInconclusive('cache_differential requires valid ?_gcb=<16-36 hex/uuid> tokens.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (actualCtrlGcb.toLowerCase() === actualProbeGcb.toLowerCase()) {
      return runnerInconclusive('cache_differential cannot reuse _gcb between control and probe.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (spec.proofMode === 'body_repeat' && !repeatPath) {
      return runnerInconclusive('cache_differential body_repeat proof requires a repeatPath.', exchanges, exchangeIds, { kind: spec.kind })
    }

    const controlEx = await ctx.broker.executeHttp({
      origin: spec.targetOrigin,
      method: spec.method,
      pathAndQuery: controlPath,
      ...(spec.controlPersona ? { persona: spec.controlPersona } : {}),
      probeClass: 'cache_differential',
      followRedirects: false,
      runId: ctx.runId,
      assignmentId: ctx.assignmentId,
    }, ctx.grant, ctx.signal)
    recordExchange(controlEx)

    const probeEx = await ctx.broker.executeHttp({
      origin: spec.targetOrigin,
      method: spec.method,
      pathAndQuery: probePath,
      headers: spec.poisonHeaders,
      persona: spec.poisonPersona,
      probeClass: 'cache_poison_deception',
      followRedirects: false,
      runId: ctx.runId,
      assignmentId: ctx.assignmentId,
    }, ctx.grant, ctx.signal)
    recordExchange(probeEx)

    const verifyEx = await ctx.broker.executeHttp({
      origin: spec.targetOrigin,
      method: spec.method,
      pathAndQuery: verifyPath,
      ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}),
      probeClass: 'cache_differential',
      cacheVerify: true,
      followRedirects: false,
      runId: ctx.runId,
      assignmentId: ctx.assignmentId,
    }, ctx.grant, ctx.signal)
    recordExchange(verifyEx)

    let repeatEx: BrokerExchangeResult | null = null
    if (spec.proofMode === 'body_repeat' && repeatPath) {
      await runnerSleepAbortable(150, ctx.signal)
      repeatEx = await ctx.broker.executeHttp({
        origin: spec.targetOrigin,
        method: spec.method,
        pathAndQuery: repeatPath,
        ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}),
        probeClass: 'cache_differential',
        cacheVerify: true,
        followRedirects: false,
        runId: ctx.runId,
        assignmentId: ctx.assignmentId,
      }, ctx.grant, ctx.signal)
      recordExchange(repeatEx)
    }

    const guardControlErrors = spec.requireControlNonError ?? runnerDefaultRequireControlNonError(spec)
    let forcedInconclusiveReason: string | null = null
    if (guardControlErrors) {
      if (runnerIsUnexpectedErrorStatus(controlEx.status, spec.expectedStatus)) {
        forcedInconclusiveReason = `Unexpected HTTP ${controlEx.status} on cache_differential control step (requireControlNonError).`
      } else if (runnerIsUnexpectedErrorStatus(verifyEx.status, spec.expectedStatus)) {
        forcedInconclusiveReason = `Unexpected HTTP ${verifyEx.status} on cache_differential verify step (requireControlNonError).`
      }
    }

    const ageRaw = verifyEx.respHeaders.age
    const age = ageRaw !== undefined ? Number(ageRaw) : NaN
    const cacheHeaderSignal = [
      verifyEx.respHeaders['x-cache'],
      verifyEx.respHeaders['cf-cache-status'],
      verifyEx.respHeaders['x-cache-status'],
      verifyEx.respHeaders['x-proxy-cache'],
      verifyEx.respHeaders['cache-status'],
    ].some(v => typeof v === 'string' && /\bhit\b/i.test(v))
    const simControlVsVerify = structuralSimilarity(controlEx.body, verifyEx.body)
    const simProbeVsVerify = structuralSimilarity(probeEx.body, verifyEx.body)

    let cacheHitObserved: boolean
    let poisonPersistedToVictim: boolean
    let markerInControl = false
    let markerInProbe = false
    let markerInVerify = false
    let markerInRepeat = false
    let repeatBodyMatches = false
    let timingSignal = false
    if (spec.proofMode === 'body_repeat') {
      const marker = spec.marker
      markerInControl = Boolean(marker && controlEx.body.includes(marker))
      markerInProbe = Boolean(marker && probeEx.body.includes(marker))
      markerInVerify = Boolean(marker && verifyEx.body.includes(marker))
      markerInRepeat = Boolean(marker && repeatEx?.body.includes(marker))
      const actorDifferential = Boolean(spec.poisonPersona) && (spec.verifyPersona ?? null) !== spec.poisonPersona
      const bodyPersisted = verifyEx.body === probeEx.body && verifyEx.body !== controlEx.body
      repeatBodyMatches = Boolean(repeatEx && repeatEx.body === verifyEx.body && repeatEx.body !== controlEx.body)
      const markerPersisted = Boolean(marker) && markerInProbe && markerInVerify && !markerInControl
      cacheHitObserved = Boolean(marker) ? markerPersisted : bodyPersisted
      poisonPersistedToVictim = actorDifferential && cacheHitObserved && repeatBodyMatches && (!marker || markerInRepeat)
      timingSignal = Boolean(repeatEx) && repeatBodyMatches
    } else {
      cacheHitObserved = (Number.isFinite(age) && age > 0) || cacheHeaderSignal
      poisonPersistedToVictim =
        (simControlVsVerify < 0.95 || verifyEx.status !== controlEx.status) &&
        (simProbeVsVerify >= 0.85 || verifyEx.status === probeEx.status)
    }

    const deterministicProofPassed = cacheHitObserved && poisonPersistedToVictim
    const proofFailureReason = deterministicProofPassed
      ? ''
      : spec.proofMode === 'body_repeat'
        ? (!cacheHitObserved
          ? 'Header-free cache proof: the clean verify did not receive the warm marker/body.'
          : 'Header-free cache proof: repeat fetch did not reproduce the poisoned body, or the control did not differ.')
        : !cacheHitObserved
          ? 'Verify request did not observe a cache hit (missing HIT header or Age > 0).'
          : 'Clean unauthenticated verify response matched clean control rather than poisoned probe.'

    let spaCatchall: Record<string, unknown> | undefined
    if (spec.spaCatchallControl) {
      const catchallPath = `/.guardian-nonexistent-${randomUUID()}`
      const catchallEx = await ctx.broker.executeHttp({
        origin: spec.targetOrigin,
        method: 'GET',
        pathAndQuery: catchallPath,
        followRedirects: true,
      }, ctx.grant, ctx.signal)
      recordExchange(catchallEx)
      const diff = diffResponse(
        { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
        { status: verifyEx.status, body: verifyEx.body, mediaType: verifyEx.mediaType },
      )
      spaCatchall = {
        path: catchallPath,
        ...runnerSummarizeExchange(catchallEx),
        comparisons: { verify: diff },
        allProbesMatchedCatchall: diff.likelySpaCatchall,
      }
      if (diff.likelySpaCatchall) {
        forcedInconclusiveReason = 'cache_differential verify response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
      }
    }

    const controlSummary = { id: 'control', role: 'control', ...runnerSummarizeExchange(controlEx) }
    const probeSummary = { id: 'probe', role: 'probe', ...runnerSummarizeExchange(probeEx) }
    const verifySummary = { id: 'verify', role: 'probe', ...runnerSummarizeExchange(verifyEx) }
    const repeatSummary = repeatEx ? { id: 'repeat', role: 'probe', ...runnerSummarizeExchange(repeatEx) } : undefined

    const evidencePayload = redactJsonValue({
      ...basePayload,
      targetOrigin: spec.targetOrigin,
      mode: spec.mode,
      control: controlSummary,
      probe: probeSummary,
      verify: verifySummary,
      ...(repeatSummary ? { repeat: repeatSummary } : {}),
      steps: { control: controlSummary, probe: probeSummary, verify: verifySummary, ...(repeatSummary ? { repeat: repeatSummary } : {}) },
      ...(spaCatchall ? { spaCatchall } : {}),
      cacheProof: {
        mode: spec.mode,
        proofMode: spec.proofMode,
        controlGcb: actualCtrlGcb,
        probeGcb: actualProbeGcb,
        cacheHitObserved,
        poisonPersistedToVictim,
        simControlVsVerify,
        simProbeVsVerify,
        age: Number.isFinite(age) ? age : null,
        markerPresent: Boolean(spec.marker),
        markerInControl,
        markerInProbe,
        markerInVerify,
        markerInRepeat,
        repeatBodyMatches,
        timingSignal,
      },
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')

    if (forcedInconclusiveReason) {
      return {
        verdict: 'inconclusive',
        outcome: {
          confirmed: false,
          controlPassed: false,
          observed: verifyEx.bodyPreview.slice(0, 400),
          expected: 'Clean uncached or isolated response.',
          reason: forcedInconclusiveReason,
        },
        exchangeIds,
        exchanges,
        evidencePayload,
        evidenceSha256,
      }
    }
    const controlPassed = controlEx.status >= 200 && controlEx.status < 500
    if (deterministicProofPassed && controlPassed) {
      return {
        verdict: 'confirmed',
        verificationTier: 'runtime_confirmed',
        outcome: {
          confirmed: true,
          controlPassed: true,
          observed: `Cache ${spec.mode} persisted poisoned response to clean verify (simControl=${simControlVsVerify.toFixed(2)}, simProbe=${simProbeVsVerify.toFixed(2)}).`,
          expected: 'Unkeyed input or victim response is not cached and served across clients.',
        },
        exchangeIds,
        exchanges,
        evidencePayload,
        evidenceSha256,
      }
    }
    return {
      verdict: controlPassed ? 'dismissed' : 'inconclusive',
      outcome: {
        confirmed: false,
        controlPassed,
        observed: verifyEx.bodyPreview.slice(0, 400) || `verifyStatus=${verifyEx.status}`,
        expected: 'Unkeyed input or victim response is not cached and served across clients.',
        reason: proofFailureReason || `Control step returned HTTP ${controlEx.status}.`,
      },
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  } catch (err) {
    return runnerHandleError(err, ctx, exchanges, exchangeIds, basePayload)
  }
}

/**
 * Cut 3e typed runner for `auth_protocol_proof`:
 * - OOB `jku_x5u_canary` verifies directly through `ProofReceipt` (`oob` rule, zero-jq).
 * - Token-minting & JWT/OAuth differentials enforce boundary gates, redaction of mutated tokens,
 *   and evaluate assertions cleanly without living inside `replay-verifier.ts`.
 */
export async function runAuthProtocolProofRecipe(
  spec: Extract<DeclarativeReplaySpec, { kind: 'auth_protocol_proof' }>,
  ctx: LegacySpecRunnerContext,
): Promise<ReplayVerificationResult> {
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult): string => {
    exchanges.push(ex)
    const id = ctx.onExchange?.(ex)
    if (typeof id === 'string' && id) {
      exchangeIds.push(id)
      return id
    }
    return `auth-${exchanges.length}`
  }

  const basePayload: Record<string, unknown> = {
    kind: spec.kind,
    origin: spec.origin,
    replayedAt: new Date().toISOString(),
  }
  const vars: Record<string, string> = {}
  const stepsOut: Record<string, unknown> = {}
  const probeStepExchanges: Array<{ id: string; exchange: BrokerExchangeResult; exchangeId: string; request: BrokerHttpRequest }> = []
  const replayJarPrefix = randomUUID().slice(0, 8)
  let firstControlStep: Record<string, unknown> | undefined
  let firstProbeStep: Record<string, unknown> | undefined

  const mintedTokens: Array<{ name: string; alg: string }> = []
  if (spec.tokenMints?.length) {
    const nowSeconds = Math.floor(Date.now() / 1000)
    vars.now = String(nowSeconds)
    vars.now_plus_1h = String(nowSeconds + 3600)
    for (const mint of spec.tokenMints) {
      const header = { alg: mint.signature === 'none' ? 'none' : 'HS256', typ: 'JWT', ...(mint.header ?? {}) }
      const resolveClaims = (value: unknown): unknown => {
        if (value === '{{now}}') return nowSeconds
        if (value === '{{now_plus_1h}}') return nowSeconds + 3600
        if (Array.isArray(value)) return value.map(resolveClaims)
        if (value && typeof value === 'object') {
          return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, resolveClaims(v)]))
        }
        return value
      }
      const headerJson = runnerInterpolateValue(resolveClaims(header), vars) as Record<string, unknown>
      const payloadJson = runnerInterpolateValue(resolveClaims(mint.payload), vars) as Record<string, unknown>
      vars[mint.name] = `${runnerBase64urlJson(headerJson)}.${runnerBase64urlJson(payloadJson)}.`
      mintedTokens.push({ name: mint.name, alg: String(headerJson.alg ?? 'none') })
    }
  }

  const serializedSteps = JSON.stringify(spec.steps)
  const needsCanary = spec.steps.some(s => s.request.authMutation?.kind === 'jku_x5u_canary') ||
    /\{\{canary_(?:url|token|dns_host)\}\}/.test(serializedSteps)
  let canarySession: EphemeralCanarySession | undefined
  let ctrlCanary: { url: string; token: string; dnsHost: string } | undefined
  let prbCanary: { url: string; token: string; dnsHost: string } | undefined

  let forcedInconclusiveReason: string | null = null
  let deterministicProofPassed = true
  let proofFailureReason = ''

  try {
    if (needsCanary) {
      canarySession = await openCanarySession(ctx.canaryBroker, ctx.storage, ctx.runId, ctx.assignmentId, spec.origin)
      ctrlCanary = canarySession.mint(`auth_protocol_proof:control:${spec.title}`)
      prbCanary = canarySession.mint(`auth_protocol_proof:probe:${spec.title}`)
    }

    const injectedAtMs = Date.now()
    for (const step of spec.steps) {
      ctx.signal.throwIfAborted()
      const stepVars: Record<string, string> = { ...vars }
      if (ctrlCanary && prbCanary) {
        const activeCanary = step.role === 'control' ? ctrlCanary : prbCanary
        stepVars.canary_url = activeCanary.url
        stepVars.canary_token = activeCanary.token
        stepVars.canary_dns_host = activeCanary.dnsHost
      }
      const brokerReq = runnerStepToBrokerRequest(step, stepVars, {
        replayJarPrefix,
        runId: ctx.runId,
        assignmentId: ctx.assignmentId,
      })
      if (brokerReq.authMutation?.kind === 'jku_x5u_canary' && !brokerReq.authMutation.url && !brokerReq.authMutation.value && ctrlCanary && prbCanary) {
        brokerReq.authMutation = { ...brokerReq.authMutation, url: step.role === 'control' ? ctrlCanary.url : prbCanary.url }
      }
      const ex = await ctx.broker.executeHttp(brokerReq, ctx.grant, ctx.signal)
      const exId = recordExchange(ex)
      runnerExtractVariables(step, ex, vars)
      const stepEntry: Record<string, unknown> = { id: step.id, role: step.role, ...runnerSummarizeExchange(ex) }
      stepsOut[step.id] = stepEntry
      if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
      if (step.role === 'probe') {
        if (!firstProbeStep) firstProbeStep = stepEntry
        probeStepExchanges.push({ id: step.id, exchange: ex, exchangeId: exId, request: brokerReq })
      }
    }

    const guardControlErrors = spec.requireControlNonError ?? runnerDefaultRequireControlNonError(spec)
    if (guardControlErrors) {
      for (const step of spec.steps) {
        if (step.role !== 'control' && step.role !== 'probe') continue
        const status = (stepsOut[step.id] as { status?: number } | undefined)?.status
        if (typeof status === 'number' && runnerIsUnexpectedErrorStatus(status, step.expectedStatus, spec.expectedStatus)) {
          if (step.role === 'probe') {
            const statusAssertedInJq =
              new RegExp(`status\\s*==\\s*${status}\\b|\\b${status}\\s*==\\s*[^;]*status`).test(spec.assertionsJq) ||
              (status >= 500 && /status\s*>=\s*500\b/.test(spec.assertionsJq))
            if (statusAssertedInJq) continue
          }
          forcedInconclusiveReason = `Unexpected HTTP ${status} on ${step.role} step "${step.id}" (requireControlNonError); declare expectedStatus ${status} to test error behavior.`
          break
        }
      }
    }

    let canaryProof: Record<string, unknown> | undefined
    let oobReceiptCheck: ReplayVerificationResult['receipt']
    if (canarySession && prbCanary && ctrlCanary) {
      const probeWait = await canarySession.waitForCallback(prbCanary.token, ctx.signal)
      const controlCheck = canarySession.check(ctrlCanary.token)
      deterministicProofPassed = probeWait.triggered && !controlCheck.triggered
      if (!deterministicProofPassed) {
        proofFailureReason = 'auth_protocol_proof OOB canary callback did not trigger exclusively on probe step.'
      }
      canaryProof = {
        probeTriggered: probeWait.triggered,
        probeStage: probeWait.stage,
        probePromoted: probeWait.promoted,
        controlTriggered: controlCheck.triggered,
        probeDetail: probeWait.detail,
        controlDetail: controlCheck.detail,
      }
      const primaryProbe = probeStepExchanges[0]
      if (primaryProbe) {
        const receipt: ProofReceipt = {
          vulnClass: 'oob',
          target: { origin: spec.origin, method: primaryProbe.exchange.method.toUpperCase(), pathAndQuery: primaryProbe.exchange.pathAndQuery },
          exchangeIds: [primaryProbe.exchangeId],
          oobEventIds: ['auth-oob-canary'],
          browserTraceIds: [],
          claimedDelta: 'Auth protocol token header triggered an out-of-band canary fetch on probe only.',
          injectedAtMs,
        }
        const carrierExtra = primaryProbe.request.authMutation?.kind === 'jku_x5u_canary'
          ? (primaryProbe.request.authMutation.url ?? primaryProbe.request.authMutation.value ?? '')
          : ''
        const transcript: ReceiptTranscript = {
          entries: [{
            exchangeId: primaryProbe.exchangeId,
            step: {
              id: primaryProbe.id,
              arm: 'probe',
              method: primaryProbe.exchange.method.toUpperCase(),
              route: primaryProbe.exchange.pathAndQuery.split('?')[0] || '/',
              pathAndQuery: primaryProbe.exchange.pathAndQuery,
              status: primaryProbe.exchange.status,
              actor: { handle: primaryProbe.exchange.personaHandle, role: null, tenant: null, auth: 'unknown', sameSite: null },
              json: null,
              body: primaryProbe.exchange.body,
            },
            carrierText: `${primaryProbe.request.pathAndQuery}\n${JSON.stringify(primaryProbe.request.headers ?? {})}\n${primaryProbe.request.body ?? ''}\n${carrierExtra}`,
          }],
          oobEvents: [{
            id: 'auth-oob-canary',
            callbackId: probeWait.subscriptionId ?? `auth:${primaryProbe.exchangeId}`,
            token: prbCanary.token,
            targetOrigin: spec.origin,
            delivered: probeWait.triggered && !controlCheck.triggered,
            stage: probeWait.stage === 'late' ? 'late' : 'immediate',
            receivedAtMs: Date.now(),
            injectedAtMs,
          }],
        }
        const verification = verifyReceipt(receipt, transcript)
        oobReceiptCheck = { receipt, verification, mode: 'strict' }
        if (!verification.confirmed) {
          deterministicProofPassed = false
          proofFailureReason = verification.reason
        }
      }
    }

    let spaCatchall: Record<string, unknown> | undefined
    if (spec.spaCatchallControl) {
      const catchallPath = `/.guardian-nonexistent-${randomUUID()}`
      const catchallEx = await ctx.broker.executeHttp({
        origin: spec.origin,
        method: 'GET',
        pathAndQuery: catchallPath,
        followRedirects: true,
      }, ctx.grant, ctx.signal)
      recordExchange(catchallEx)
      const comparisons: Record<string, Record<string, unknown>> = {}
      let allProbesMatchedCatchall = probeStepExchanges.length > 0
      for (const probe of probeStepExchanges) {
        const diff = diffResponse(
          { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
          { status: probe.exchange.status, body: probe.exchange.body, mediaType: probe.exchange.mediaType },
        )
        comparisons[probe.id] = diff
        if (!diff.likelySpaCatchall) allProbesMatchedCatchall = false
      }
      spaCatchall = { path: catchallPath, ...runnerSummarizeExchange(catchallEx), comparisons, allProbesMatchedCatchall }
      if (allProbesMatchedCatchall) {
        forcedInconclusiveReason = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
      }
    }

    const authSteps: ImpactStep[] = spec.steps.map(step => {
      const entry = stepsOut[step.id] as Record<string, unknown> | undefined
      let entryJson = entry?.json ?? null
      if (entryJson === null && typeof entry?.body === 'string') {
        try { entryJson = JSON.parse(entry.body) } catch { entryJson = null }
      }
      const handle = (typeof entry?.personaHandle === 'string' ? entry.personaHandle : null) ?? step.request.persona ?? null
      return {
        id: step.id,
        arm: step.role,
        method: step.request.method.toUpperCase(),
        route: step.request.pathAndQuery.split('?')[0].split('#')[0].replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase() || '/',
        pathAndQuery: step.request.pathAndQuery,
        status: typeof entry?.status === 'number' ? entry.status : null,
        actor: {
          handle,
          role: normalizeRole(step.request.persona),
          tenant: null,
          auth: 'unknown' as AmbientAuth,
          sameSite: null,
        } satisfies ActorIdentity,
        json: entryJson,
        body: typeof entry?.body === 'string' ? entry.body : '',
        requestJson: step.request.jsonBody,
        requestHeaders: step.request.headers ?? null,
        responseHeaders: (entry?.headers as Record<string, string> | undefined) ?? null,
      }
    })
    // Boundary gate applies to HTTP auth/access bypass claims, never to OOB jku_x5u_canary fetches
    // (whose proof is the host-observed out-of-band callback verified by ProofReceipt).
    const authBoundaryClass = canaryProof
      ? 'other' as const
      : classifyBoundaryClaim({ cwe: spec.cwe, category: spec.category, title: spec.title, impact: spec.impact })
    const authBoundaryGate = authBoundaryClass === 'mfa'
      ? assessMfaBypass({ impactClass: 'other', steps: authSteps, targetOrigin: spec.origin })
      : authBoundaryClass === 'auth' || authBoundaryClass === 'access'
        ? assessBoundary({
            impactClass: 'other',
            steps: authSteps,
            boundaryClass: authBoundaryClass,
            expectControlDenied: spec.expectControlDenied,
            targetOrigin: spec.origin,
          })
        : null
    if (authBoundaryGate?.required && !authBoundaryGate.satisfied) {
      deterministicProofPassed = false
      proofFailureReason = authBoundaryGate.reason
    }

    const dynamicSecrets = runnerSecrets(ctx.grant, ctx.broker)
    const evidencePayload = redactJsonValue({
      ...basePayload,
      protocol: spec.protocol,
      steps: stepsOut,
      ...(firstControlStep ? { control: firstControlStep } : {}),
      ...(firstProbeStep ? { probe: firstProbeStep } : {}),
      extractedVars: vars,
      ...(mintedTokens.length > 0 ? { mintedTokens } : {}),
      ...(canaryProof ? { canaryProof } : {}),
      ...(spaCatchall ? { spaCatchall } : {}),
      ...(authBoundaryGate ? { boundaryGate: authBoundaryGate } : {}),
    }, dynamicSecrets)
    const serializedPayload = JSON.stringify(evidencePayload, null, 2)
    const evidenceSha256 = createHash('sha256').update(serializedPayload).digest('hex')

    // OOB canary path (e.g. jku_x5u_canary): zero-jq confirmation backed by ProofReceipt.
    if (canaryProof) {
      const controlStatus = (firstControlStep as { status?: number } | undefined)?.status ?? null
      const controlPassed = forcedInconclusiveReason === null && controlStatus !== null && controlStatus >= 200 && controlStatus < 500
      if (forcedInconclusiveReason) {
        return {
          verdict: 'inconclusive',
          outcome: { confirmed: false, controlPassed: false, observed: 'oob_canary', expected: 'No untrusted header fetch.', reason: forcedInconclusiveReason },
          exchangeIds, exchanges, evidencePayload, evidenceSha256,
          ...(oobReceiptCheck ? { receipt: oobReceiptCheck } : {}),
        }
      }
      if (deterministicProofPassed && controlPassed) {
        return {
          verdict: 'confirmed',
          verificationTier: 'runtime_confirmed',
          outcome: { confirmed: true, controlPassed: true, observed: 'jku_x5u_oob_confirmed', expected: 'Token header URL is never fetched.' },
          exchangeIds, exchanges, evidencePayload, evidenceSha256,
          ...(oobReceiptCheck ? { receipt: oobReceiptCheck } : {}),
        }
      }
      return {
        verdict: controlPassed ? 'dismissed' : 'inconclusive',
        outcome: { confirmed: false, controlPassed, observed: 'jku_x5u_oob_not_triggered', expected: 'Token header URL is never fetched.', reason: proofFailureReason || 'OOB canary did not fire.' },
        exchangeIds, exchanges, evidencePayload, evidenceSha256,
        ...(oobReceiptCheck ? { receipt: oobReceiptCheck } : {}),
      }
    }

    // Non-OOB auth_protocol_proof (JWT mutations, tokenMints, OAuth redirect differentials):
    // evaluate spec assertions via worker jq so every caller differential shape stays exact.
    const jqCommand = `jq '${spec.assertionsJq.replaceAll("'", "'\\''")}' /evidence/replay-results.json > /work/outcome.json`
    const workerResult = await ctx.backend.run({
      assignmentId: ctx.assignmentId,
      files: [{ name: 'replay-results.json', content: serializedPayload }],
      command: jqCommand,
      outputs: ['outcome.json'],
      timeoutMs: 30_000,
    }, ctx.signal)
    const rawOutcome = (workerResult.outputs['outcome.json'] || workerResult.stdout || '').trim()
    if (workerResult.exitCode !== 0 || !rawOutcome) {
      return runnerInconclusive(`Replay jq assertion failed (exit ${workerResult.exitCode}): ${workerResult.stderr.slice(0, 400)}`, exchanges, exchangeIds, evidencePayload)
    }
    let parsedJson: unknown
    try { parsedJson = JSON.parse(rawOutcome) } catch {
      return runnerInconclusive('Replay jq assertion did not emit valid JSON.', exchanges, exchangeIds, evidencePayload)
    }
    const coerceText = (v: unknown) => (typeof v === 'string' ? v : (JSON.stringify(v) ?? String(v))).slice(0, 1200)
    if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
      const obj = { ...(parsedJson as Record<string, unknown>) }
      if ('observed' in obj && obj.observed !== undefined) obj.observed = coerceText(obj.observed)
      if ('expected' in obj && obj.expected !== undefined) obj.expected = coerceText(obj.expected)
      if ('reason' in obj) {
        if (obj.reason === undefined || obj.reason === null) delete obj.reason
        else obj.reason = coerceText(obj.reason)
      }
      parsedJson = obj
    }
    const validated = replayAssertionOutcomeSchema.safeParse(parsedJson)
    if (!validated.success) {
      return runnerInconclusive(`Replay assertion output violated schema: ${validated.error.issues[0]?.message ?? 'invalid shape'}`, exchanges, exchangeIds, evidencePayload)
    }
    const outcome = validated.data
    if (forcedInconclusiveReason) {
      return {
        verdict: 'inconclusive',
        outcome: { ...outcome, confirmed: false, controlPassed: false, reason: forcedInconclusiveReason },
        exchangeIds, exchanges, evidencePayload, evidenceSha256,
      }
    }
    if (!deterministicProofPassed) {
      return {
        verdict: outcome.controlPassed ? 'dismissed' : 'inconclusive',
        outcome: { ...outcome, confirmed: false, reason: proofFailureReason || 'Auth protocol boundary proof did not pass.' },
        exchangeIds, exchanges, evidencePayload, evidenceSha256,
      }
    }
    const verdict = outcome.controlPassed && outcome.confirmed
      ? 'confirmed'
      : outcome.controlPassed ? 'dismissed' : 'inconclusive'
    return {
      verdict,
      ...(verdict === 'confirmed' ? { verificationTier: 'runtime_confirmed' as const } : {}),
      outcome,
      exchangeIds,
      exchanges,
      evidencePayload,
      evidenceSha256,
    }
  } catch (err) {
    return runnerHandleError(err, ctx, exchanges, exchangeIds, basePayload)
  } finally {
    await canarySession?.close()
  }
}
