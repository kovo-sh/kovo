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
import { baseFields } from './deterministic-specs.ts'
import type { EngineHypothesis, Severity, SynthesizedEngineSpec } from './deterministic-specs.ts'
import {
  POSTURE_CATEGORY_RE,
  POSTURE_CWES,
  PRIVILEGED_ACTION_RE,
  bogusIdFor,
  fillResourceId,
  isSafeFieldName,
  isSafeResourceId,
  pickBaselineWrite,
  resolveAuthzReadbackTemplate,
  rolePrivilegeRank,
} from './floor-heuristics.ts'
import { ScopedBrowser } from './scoped-browser.ts'
import type { BrowserSessionStep } from './scoped-browser.ts'
import type { EnginePersona } from './deterministic-engine.ts'
import type { DifferentialResult } from './surface-engine.ts'
import { injectUniversalParam } from './probes/context.ts'
import { CUT3_FLOOR_RECIPE_IDS, brokerFloorRecipeDeps, browserSinkEnvelopeFromSteps, cut3FloorRecipe, floorRecipe, isProtocolBrowserSpec, runCut3Recipe, runFloorRecipe, wiredRecipeForSpecKind } from './floor-recipes.ts'
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
import { actorFromPersona, assessBoundary, assessImpactEvidence, assessMassAssignmentImpact, assessMfaBypass, assessStatusOnlyDivergence, classifyBoundaryClaim, classifyImpactDescriptor, normalizeRole, parseRoleLabel } from './oracle-invariants.ts'
import type { ActorIdentity, AmbientAuth, ImpactStep, PersonaCredentialSource, RoleName } from './oracle-invariants.ts'
import { classifyRetestHealth } from './retest-health.ts'
import type { RetestHealthAssessment } from './retest-health.ts'
import { HostFactLog } from './host-fact-log.ts'
import { isPureJobOrHandleStubChain, proofReceiptMode } from './proof-receipt.ts'
import type { ProofReceipt, ReceiptTranscript, ReceiptTranscriptEntry, ReceiptVerification } from './proof-receipt.ts'
import { defaultTerminalOracleRegistry } from './terminal-oracle-registry.ts'
import type { ProofReceiptMode, ReplayReceiptCheck, ReplayVerdict, ReplayVerificationResult, RetestVerdict } from './replay-verifier.ts'

export { proofReceiptMode }
import { cacheBusterValueRegex, containsDestructivePayload, extractCacheBusterParam, replayAssertionOutcomeSchema } from '../replay-spec.ts'
import type { AuthMutation, DeclarativeReplaySpec, FloorRecipeEnvelope, ReplayAssertionOutcome, ReplayStep } from '../replay-spec.ts'
import { BrokerApprovalRequired, BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant, RequestBroker } from './broker.ts'
import type { CanaryBroker } from './canary-broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'
import { normalizeStructuralTokens, openCanarySession, structuralDiffNormalized } from './verify-support.ts'
import type { EphemeralCanarySession } from './verify-support.ts'
import type { WorkerBackend } from './worker-backend.ts'

export type PersistedFloorRecipeId = FloorRecipeId | Cut3FloorRecipeId
export type PersistedFloorRecipeArgs = FloorRecipeArgs | Cut3FloorRecipeArgs

const CUT3_RECIPE_ID_SET: ReadonlySet<string> = new Set(CUT3_FLOOR_RECIPE_IDS)

function isCut3RecipeId(id: PersistedFloorRecipeId): id is Cut3FloorRecipeId {
  return CUT3_RECIPE_ID_SET.has(id)
}

/** Dispatch any persisted floor recipe id (core 6 + Cut 3 recipes) through its typed runner and TerminalOracleRegistry. */
export async function executeFloorRecipeById(
  recipeId: PersistedFloorRecipeId,
  args: PersistedFloorRecipeArgs,
  deps: FloorRecipeDeps,
): Promise<FloorRecipeExecution> {
  const exec = isCut3RecipeId(recipeId)
    ? await runCut3Recipe(
        cut3FloorRecipe(recipeId, args as Cut3FloorRecipeArgsMap[typeof recipeId]),
        deps,
      )
    : await runFloorRecipe(
        floorRecipe(recipeId, args as FloorRecipeArgsMap[typeof recipeId]),
        deps,
      )
  if (!exec.result.confirmed) return exec
  const factLog = HostFactLog.fromTranscript(exec.result.transcript)
  const oracle = defaultTerminalOracleRegistry.evaluate(
    factLog,
    { kind: 'single_hop', receipt: exec.receipt },
    { strictHostDerivation: false },
  )
  if (oracle.confirmed) return exec
  const verification: ReceiptVerification = oracle.singleHop ?? {
    confirmed: false,
    vulnClass: exec.receipt.vulnClass,
    rule: exec.result.verification.rule,
    reason: oracle.reason,
    observed: exec.receipt.claimedDelta,
    expected: 'host-custody verified floor receipt',
  }
  return {
    ...exec,
    result: { ...exec.result, confirmed: false, verification },
    failure: {
      code: 'receipt_rejected',
      message: verification.reason,
      missingRoles: ['impact_evidence'],
    },
  }
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
  const parsed = parseRoleLabel(persona?.roleLabel ?? null)
  return {
    handle,
    role: parsed.role ?? roleOf(persona),
    tenant: persona?.tenant?.toLowerCase() ?? parsed.tenant ?? null,
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
    ...(hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate.replaceAll('{{value}}', '{{val}}') } : {}),
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

function armOverrideOf(req: Pick<FloorRequestSpec, 'pathAndQuery' | 'jsonBody' | 'textBody' | 'headers'>) {
  if (req.textBody === undefined && !req.headers) return undefined
  return {
    pathAndQuery: req.pathAndQuery,
    ...(req.jsonBody !== undefined ? { jsonBody: req.jsonBody } : {}),
    ...(req.textBody !== undefined ? { textBody: req.textBody } : {}),
    ...(req.headers ? { headers: req.headers } : {}),
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
  const buildArgs = (
    mode: 'boolean' | 'timing',
    control: NonNullable<ReturnType<typeof requestFromInjection>>,
    probe: NonNullable<ReturnType<typeof requestFromInjection>>,
    extra: Partial<BooleanOrTimingArgs>,
  ): FloorRecipePlan => {
    const controlReq = armOverrideOf(control)
    const probeReq = armOverrideOf(probe)
    const args: BooleanOrTimingArgs = {
      mode,
      origin: hyp.endpoint.origin,
      method: probe.method,
      pathAndQuery: probe.pathAndQuery,
      controlPathAndQuery: control.pathAndQuery,
      probePathAndQuery: probe.pathAndQuery,
      param: hyp.param!.name,
      vulnClass: 'sqli',
      actor: floorActorFor(hyp.ownerPersona ?? null, input.personas),
      ...(control.jsonBody !== undefined ? { controlJsonBody: control.jsonBody } : {}),
      ...(probe.jsonBody !== undefined ? { probeJsonBody: probe.jsonBody } : {}),
      ...(controlReq ? { controlRequest: controlReq } : {}),
      ...(probeReq ? { probeRequest: probeReq } : {}),
      ...(input.headers ?? hyp.headers ? { headers: { ...(hyp.headers ?? {}), ...(input.headers ?? {}) } } : {}),
      ...extra,
    }
    return { ...sketch, args, paramLocation: hyp.location ?? hyp.param!.location }
  }
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
    return buildArgs('timing', control, probe, { receiptClass: 'blind_sqli', baselineValue: baseline, quoteStyle: 'single' })
  }
  const hit = input.probe.anomalies.find(anomaly => anomaly.type === 'boolean_differential')
  const baseline = (typeof hit?.baselineValue === 'string' ? hit.baselineValue : null) ?? hyp.baselineValue ?? '1'
  const key = 7_919
  const style = booleanStyleOf(hit?.style)
  const rawTemplate = typeof hit?.valueTemplate === 'string' && hit.valueTemplate.includes('{{sql_expr}}') ? hit.valueTemplate : null
  const rawQuote = typeof hit?.quoteStyle === 'string' ? hit.quoteStyle : ''
  const quoteStyle: 'single' | 'double' | 'numeric' = rawQuote === 'double' || rawQuote === 'numeric' ? rawQuote : 'single'
  const control = requestFromInjection({ hyp, value: booleanArm({ template: rawTemplate, style, baseline, key, arm: 'true' }) })
  const probe = requestFromInjection({ hyp, value: booleanArm({ template: rawTemplate, style, baseline, key, arm: 'false' }) })
  if (!control || !probe) return { ...sketch, skipReason: 'sqli injection point could not be expressed as a recipe request' }
  return buildArgs('boolean', control, probe, {
    rounds: 2,
    baselineValue: baseline,
    quoteStyle,
    ...(rawTemplate ? { valueTemplate: rawTemplate } : {}),
  })
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
  const amountField = isSafeFieldName(hit.amountField) ? hit.amountField : ''
  const balanceField = isSafeFieldName(hit.balanceField) ? hit.balanceField : undefined
  const amount = Number(hit.amount)
  const burst = Number(hit.burstSize)
  if (!amountField || !Number.isFinite(amount) || amount <= 0) {
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

function resourceIdOf(input: FloorRecipePlanInput): string | null {
  const matrix = Array.isArray(input.probe.details.matrix)
    ? input.probe.details.matrix as Array<Record<string, unknown>>
    : null
  const ownerBytes = (id: string): number => {
    if (!matrix) return 0
    let best = 0
    for (const row of matrix) {
      if (String(row.resourceId ?? '') !== id || String(row.actor ?? '') !== 'owner' || row.accessible !== true) continue
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
      isSafeResourceId(anomaly.resourceId))
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
  return input.hypothesis.resourceIds?.find(isSafeResourceId) ?? null
}

function authzReadbackPath(input: FloorRecipePlanInput, id: string | null, functionLevel: boolean): string | null {
  const resolved = resolveAuthzReadbackTemplate(input.hypothesis, functionLevel)
  if (!resolved) return null
  if (!functionLevel && !id) return null
  return id ? fillResourceId(resolved.template, id) : resolved.template
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

function selectLowerRoleDeniedPeer(
  owner: FloorActor,
  probe: FloorActor,
  personas: readonly EnginePersona[],
): FloorActor | null {
  const ownerRank = rolePrivilegeRank(owner.role)
  const candidates = personas
    .filter(p => p.handle !== owner.handle && p.handle !== probe.handle)
    .map(p => floorActorFor(p.handle, personas))
    .filter(actor => {
      const rank = rolePrivilegeRank(actor.role)
      if (ownerRank !== null && rank !== null) return rank < ownerRank
      return actor.role !== owner.role || actor.tenant !== owner.tenant
    })
  if (candidates.length === 0) return null
  candidates.sort((a, b) => (rolePrivilegeRank(a.role) ?? 0) - (rolePrivilegeRank(b.role) ?? 0))
  return candidates[0]!
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
  const resolvedId = reserved && isSafeResourceId(reserved) ? reserved : id
  const realPath = resolvedId ? fillResourceId(hyp.pathAndQuery, resolvedId) : hyp.pathAndQuery
  const owner = floorActorFor(ownerHandle, input.personas)
  const probe = floorActorFor(probeHandle, input.personas)
  const headers = { ...(hyp.headers ?? {}), ...(input.headers ?? {}) }

  if (hyp.method === 'GET') {
    // The legacy read proof is an entitled read plus a cross-actor read, with an authenticated
    // bogus-id control where the route only denies nonexistent identifiers. For same-path / BFLA
    // reads (H-17), never reuse `owner` as the denied control arm — require a distinct lower-role peer.
    const deniedPath = id && !functionLevel ? fillResourceId(hyp.pathAndQuery, bogusIdFor(id)) : realPath
    const samePath = deniedPath === realPath
    let deniedActor: FloorActor
    if (samePath) {
      const peer = selectLowerRoleDeniedPeer(owner, probe, input.personas)
      if (!peer) {
        return {
          ...sketch,
          skipReason: 'function-level authz read requires a distinct lower-role peer persona for the denied control arm',
        }
      }
      deniedActor = peer
    } else {
      deniedActor = owner
    }
    const idInPath = /\/\{\{id\}\}(?:\/|$|\?)/.test(hyp.pathAndQuery) || /\/:\w+(?:\/|$|\?)/.test(hyp.pathAndQuery)
    const args: AccessBoundaryArgs = {
      origin: hyp.endpoint.origin,
      method: 'GET',
      pathAndQuery: realPath,
      vulnClass,
      owner,
      probe,
      denied: deniedActor,
      ...(deniedPath !== realPath ? { deniedPathAndQuery: deniedPath } : {}),
      ...(!idInPath && !functionLevel ? { controlEvidence: 'denial_or_distinct' as const } : {}),
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
  const baselineWrite = !functionLevel && !selfState && hyp.method !== 'DELETE' ? pickBaselineWrite(body) : null
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
    ...(baselineWrite ? { baselineWrite: { body: baselineWrite.baselineBody, actor: owner, method: hyp.method } } : {}),
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
  let steps = Array.isArray(spec?.steps) ? spec!.steps as Array<Record<string, unknown>> : null
  if (!steps || steps.length === 0) {
    // Direct floor-recipe planning for reflected xss_context without throwaway browser_chain jq synthesis.
    const hit = input.probe.anomalies.find(a => a.type === 'xss_context')
    const context = String(hit?.context ?? 'html_body')
    const chars = Array.isArray(hit?.unencodedChars) ? hit!.unencodedChars.map(String) : []
    if (!hit || !hyp.param || hyp.location !== 'query' || context !== 'html_body' || !chars.includes('<') || !chars.includes('"')) {
      return { ...sketch, skipReason: 'browser spec carried no steps to replay' }
    }
    const sep = hyp.pathAndQuery.includes('?') ? '&' : '?'
    const key = encodeURIComponent(hyp.param.name)
    const controlPath = `${hyp.pathAndQuery}${sep}${key}=kovo`
    const payload = `<img src=x onerror="document.title='{{canary_token}}'">`
    const encodedPayload = payload.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
    const probePath = `${hyp.pathAndQuery}${sep}${key}=${encodedPayload}`
    const persona = hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}
    steps = [
      { id: 'c1', role: 'control', origin: hyp.endpoint.origin, ...persona, pathAndQuery: controlPath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 300 },
      { id: 'p1', role: 'probe', origin: hyp.endpoint.origin, ...persona, pathAndQuery: probePath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 800 },
    ]
  }
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
      // A sink trace proves only that a canary-bearing value reached a setter; the value itself may
      // be inert. Likewise, the driver's generic canary flag also fires for a surviving marker
      // attribute. Require an execution effect: the verifier-owned window flag, or a title change
      // that was not already rendered by the server.
      const globalFlag = visit.canaryCheck.triggered === true &&
        visit.canaryCheck.token === session.canaryToken &&
        visit.canaryCheck.detail === 'DOM execution canary flag observed on window.'
      const serverRenderedTitle = (visit.exchanges ?? []).some(exchange =>
        [...String(exchange.body ?? '').matchAll(/<title\b[^>]*>([\s\S]*?)<\/title>/gi)]
          .some(match => match[1]!.trim() === session.canaryToken))
      const titleHit = visit.title === session.canaryToken && !serverRenderedTitle
      if (!globalFlag && !titleHit) return
      sinkHit = true
      const sinks = [
        ...new Set(hits.map(trace => `dom_xss:${trace.sink}`)),
        ...(titleHit ? ['canary:title'] : []),
        ...(globalFlag ? ['canary:executed'] : []),
      ]
      traces.push({
        id: `browser-${index + 1}`,
        origin: input.origin,
        sinks,
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
  if (input.plan.recipeId === 'boolean_or_timing' &&
      (input.plan.args as BooleanOrTimingArgs).mode === 'timing' && (input.grant.tier ?? 1) < 3) {
    input.grant.audit('denied', input.plan.args.origin || input.hypothesis.endpoint.origin)
    throw new BrokerDenied('Timing differential recipes require Tier 3 verification scope.')
  }
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

export { assessRetestHealth, classifyRetestHealth } from './retest-health.ts'
export type { RetestFailureReason, RetestHealthAssessment, RetestHealthCode } from './retest-health.ts'

/**
 * Receipt-based retest of a persisted recipe (Cut 3 retest migration).
 *
 * Re-runs the exact `recipeId` + args the confirmation recorded, through the same broker seam, and
 * lets `runFloorRecipe` → `verifyReceipt()` decide. The legacy declarative verifier is never called
 * for a recipe-owned proof, so the persisted spec's shape is not the retest contract.
 *
 * Verdict mapping keeps the patch gate's semantics:
 *   - the receipt confirms again → `reproduced`
 *   - `classifyRetestHealth` confirms positive baseline + probe health → `fixed`
 *   - any unhealthy control/probe, missing control, budget overflow, or oracle disagreement → `inconclusive`
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
    const health: RetestHealthAssessment = { healthy: false, code: 'recipe_error', failureReason: 'baseline_unhealthy', reason }
    return {
      verdict: 'inconclusive',
      execution: null,
      replay: {
        verdict: 'inconclusive',
        outcome: { confirmed: false, controlPassed: false, observed: reason, expected: 'the persisted recipe re-executes', reason },
        exchangeIds: [],
        exchanges: [],
        evidencePayload: { kind: plan.specKind, recipe: plan.recipeId, confirmation: 'proof_receipt', retestHealth: health },
        evidenceSha256: createHash('sha256').update(reason).digest('hex'),
      },
    }
  }
  const exchangeIds = [...execution.result.exchangeIds]
  const baseReplay = recipeRetestResult(plan, execution, exchangeIds)
  const health = classifyRetestHealth(execution)
  const replay: ReplayVerificationResult = {
    ...baseReplay,
    evidencePayload: { ...baseReplay.evidencePayload, retestHealth: health },
  }
  const verdict: RetestVerdict = execution.result.confirmed
    ? 'reproduced'
    : health.healthy && health.failureReason === 'claim_not_reproduced'
      ? 'fixed'
      : 'inconclusive'
  if (verdict === 'inconclusive') {
    const reason = health.reason ?? execution.failure?.message ?? replay.outcome.reason ?? 'The persisted recipe could not establish retest health.'
    return {
      verdict,
      execution,
      replay: {
        ...replay,
        verdict: 'inconclusive',
        outcome: { ...replay.outcome, confirmed: false, controlPassed: false, reason },
      },
    }
  }
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

function makeRunnerRecorder(ctx: LegacySpecRunnerContext, fallbackPrefix: string) {
  const exchanges: BrokerExchangeResult[] = []
  const exchangeIds: string[] = []
  const recordExchange = (ex: BrokerExchangeResult): string => {
    exchanges.push(ex)
    const id = ctx.onExchange?.(ex)
    if (typeof id === 'string' && id) {
      exchangeIds.push(id)
      return id
    }
    return `${fallbackPrefix}-${exchanges.length}`
  }
  return { exchanges, exchangeIds, recordExchange }
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

function evaluateRunnerOobReceipt(input: {
  origin: string
  stepId: string
  exchange: BrokerExchangeResult
  exchangeId: string
  request: BrokerHttpRequest
  oobEventId: string
  callbackPrefix: string
  token: string
  probeWait: { triggered: boolean; stage?: string; subscriptionId?: string | null }
  controlTriggered: boolean
  claimedDelta: string
  injectedAtMs: number
  carrierExtra?: string
}): ReplayReceiptCheck {
  const receipt: ProofReceipt = {
    vulnClass: 'oob',
    target: { origin: input.origin, method: input.exchange.method.toUpperCase(), pathAndQuery: input.exchange.pathAndQuery },
    exchangeIds: [input.exchangeId],
    oobEventIds: [input.oobEventId],
    browserTraceIds: [],
    claimedDelta: input.claimedDelta,
    injectedAtMs: input.injectedAtMs,
  }
  const carrierBase = `${input.request.pathAndQuery}\n${JSON.stringify(input.request.headers ?? {})}\n${input.request.body ?? ''}`
  const transcript: ReceiptTranscript = {
    entries: [{
      exchangeId: input.exchangeId,
      step: {
        id: input.stepId,
        arm: 'probe',
        method: input.exchange.method.toUpperCase(),
        route: input.exchange.pathAndQuery.split('?')[0] || '/',
        pathAndQuery: input.exchange.pathAndQuery,
        status: input.exchange.status,
        actor: { handle: input.exchange.personaHandle, role: null, tenant: null, auth: 'unknown', sameSite: null },
        json: null,
        body: input.exchange.body,
      },
      carrierText: input.carrierExtra ? `${carrierBase}\n${input.carrierExtra}` : carrierBase,
    }],
    oobEvents: [{
      id: input.oobEventId,
      callbackId: input.probeWait.subscriptionId ?? `${input.callbackPrefix}:${input.exchangeId}`,
      token: input.token,
      targetOrigin: input.origin,
      delivered: input.probeWait.triggered && !input.controlTriggered,
      stage: input.probeWait.stage === 'late' ? 'late' : 'immediate',
      receivedAtMs: Date.now(),
      injectedAtMs: input.injectedAtMs,
    }],
  }
  const verification = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript(transcript),
    { kind: 'single_hop', receipt },
    { strictHostDerivation: true },
  ).singleHop!
  return { receipt, verification, mode: 'strict' }
}

async function runRunnerSpaCatchall(input: {
  origin: string
  ctx: LegacySpecRunnerContext
  recordExchange: (ex: BrokerExchangeResult) => string
  targets: readonly { id: string; exchange: BrokerExchangeResult }[]
}): Promise<{ summary: Record<string, unknown>; allProbesMatchedCatchall: boolean }> {
  const catchallPath = `/.kovo-nonexistent-${randomUUID()}`
  const catchallEx = await input.ctx.broker.executeHttp({
    origin: input.origin,
    method: 'GET',
    pathAndQuery: catchallPath,
    followRedirects: true,
  }, input.ctx.grant, input.ctx.signal)
  input.recordExchange(catchallEx)
  const comparisons: Record<string, Record<string, unknown>> = {}
  let allProbesMatchedCatchall = input.targets.length > 0
  for (const target of input.targets) {
    const diff = diffResponse(
      { status: catchallEx.status, body: catchallEx.body, mediaType: catchallEx.mediaType },
      { status: target.exchange.status, body: target.exchange.body, mediaType: target.exchange.mediaType },
    )
    comparisons[target.id] = diff
    if (!diff.likelySpaCatchall) allProbesMatchedCatchall = false
  }
  return {
    summary: { path: catchallPath, ...summarizeExchange(catchallEx), comparisons, allProbesMatchedCatchall },
    allProbesMatchedCatchall,
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
    return inconclusiveResult(redact(err.message, secrets), exchanges, exchangeIds, safePayload)
  }
  const message = redact(err instanceof Error ? err.message : String(err), secrets)
  return inconclusiveResult(`Replay execution failed: ${message}`, exchanges, exchangeIds, safePayload)
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
    return inconclusiveResult('static_ast_proof requires the read-only /repos mount (reposDir).', [], [], { kind: spec.kind })
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
  const { exchanges, exchangeIds, recordExchange } = makeRunnerRecorder(ctx, 'rce')

  // Hard Tier 3 + HITL approval gate
  const tier = ctx.grant.tier ?? 1
  const gateRequest = spec.probeStep.request
  if (tier < 3) {
    ctx.grant.audit('denied', gateRequest.origin)
    return inconclusiveResult(`${spec.kind} replay specs are blocked below Tier 3.`, exchanges, exchangeIds, { kind: spec.kind })
  }
  const localLab = Boolean(ctx.grant.allowLocalLab && process.env.KOVO_ALLOW_LOCAL_LAB === '1')
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
    return inconclusiveResult(`${spec.kind} requires explicit Tier 3 HITL operator approval.`, exchanges, exchangeIds, { kind: spec.kind })
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

    const controlReq = stepToBrokerRequest(spec.controlStep, controlVars, { runId: ctx.runId, assignmentId: ctx.assignmentId })
    const probeReq = stepToBrokerRequest(spec.probeStep, probeVars, { runId: ctx.runId, assignmentId: ctx.assignmentId })
    const serializedProbeReq = JSON.stringify(probeReq)

    if (hasDestructiveContent(JSON.stringify(controlReq)) || hasDestructiveContent(serializedProbeReq)) {
      return inconclusiveResult('Interpolated rce_proof request matched destructive-payload denylist.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (spec.proofMode === 'split_echo' && expectedSplitAssembled && serializedProbeReq.includes(expectedSplitAssembled)) {
      return inconclusiveResult('Invalid split_echo template: nonce_part1 and nonce_part2 must be separated by execution concatenation syntax.', exchanges, exchangeIds, { kind: spec.kind })
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
      deterministicProofPassed = inProbe && !inControl && !serializedProbeReq.includes(expectedNonceProduct)
      proofMeta.mathVerified = deterministicProofPassed
      proofMeta.productInProbe = inProbe
      proofMeta.productInControl = inControl
      observed = deterministicProofPassed
        ? `Evaluated dynamic_math product ${expectedNonceProduct} observed exclusively in probe.`
        : `dynamic_math product not evaluated (inProbe=${inProbe}, inControl=${inControl}).`
    } else if (spec.proofMode === 'split_echo' && expectedSplitAssembled) {
      const inProbe = probeEx.body.includes(expectedSplitAssembled)
      const inControl = controlEx.body.includes(expectedSplitAssembled)
      deterministicProofPassed = inProbe && !inControl && !serializedProbeReq.includes(expectedSplitAssembled)
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
      receiptCheck = evaluateRunnerOobReceipt({
        origin: spec.origin,
        stepId: spec.probeStep.id,
        exchange: probeEx,
        exchangeId: probeExchangeId,
        request: probeReq,
        oobEventId: 'rce-oob-canary',
        callbackPrefix: 'rce',
        token: probeCanaryToken,
        probeWait,
        controlTriggered: controlCheck.triggered,
        claimedDelta: 'Probe triggered an out-of-band execution callback that control did not.',
        injectedAtMs,
      })
      deterministicProofPassed = probeWait.triggered && !controlCheck.triggered && receiptCheck.verification.confirmed
      observed = `probeCanary=${probeWait.triggered}, controlCanary=${controlCheck.triggered}`
    }

    proofMeta.cryptographicProofPassed = deterministicProofPassed
    const evidencePayload = redactJsonValue({
      ...basePayload,
      proofMode: spec.proofMode,
      control: summarizeExchange(controlEx),
      probe: summarizeExchange(probeEx),
      proof: proofMeta,
    }, runnerSecrets(ctx.grant, ctx.broker))
    const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')

    const controlPassed = !isUnexpectedErrorStatus(controlEx.status, spec.controlStep.expectedStatus, spec.expectedStatus) &&
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
  const { exchanges, exchangeIds, recordExchange } = makeRunnerRecorder(ctx, 'cache')
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
      return inconclusiveResult('cache_differential requires valid ?_gcb=<16-36 hex/uuid> tokens.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (actualCtrlGcb.toLowerCase() === actualProbeGcb.toLowerCase()) {
      return inconclusiveResult('cache_differential cannot reuse _gcb between control and probe.', exchanges, exchangeIds, { kind: spec.kind })
    }
    if (spec.proofMode === 'body_repeat' && !repeatPath) {
      return inconclusiveResult('cache_differential body_repeat proof requires a repeatPath.', exchanges, exchangeIds, { kind: spec.kind })
    }

    const executeCacheReq = (pathAndQuery: string, extra: Partial<BrokerHttpRequest>) =>
      ctx.broker.executeHttp({
        origin: spec.targetOrigin,
        method: spec.method,
        pathAndQuery,
        followRedirects: false,
        runId: ctx.runId,
        assignmentId: ctx.assignmentId,
        ...extra,
      }, ctx.grant, ctx.signal)

    const controlEx = await executeCacheReq(controlPath, {
      ...(spec.controlPersona ? { persona: spec.controlPersona } : {}),
      probeClass: 'cache_differential',
    })
    recordExchange(controlEx)

    const probeEx = await executeCacheReq(probePath, {
      headers: spec.poisonHeaders,
      persona: spec.poisonPersona,
      probeClass: 'cache_poison_deception',
    })
    recordExchange(probeEx)

    const verifyEx = await executeCacheReq(verifyPath, {
      ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}),
      probeClass: 'cache_differential',
      cacheVerify: true,
    })
    recordExchange(verifyEx)

    let repeatEx: BrokerExchangeResult | null = null
    if (spec.proofMode === 'body_repeat' && repeatPath) {
      await runnerSleepAbortable(150, ctx.signal)
      repeatEx = await executeCacheReq(repeatPath, {
        ...(spec.verifyPersona ? { persona: spec.verifyPersona } : {}),
        probeClass: 'cache_differential',
        cacheVerify: true,
      })
      recordExchange(repeatEx)
    }

    const guardControlErrors = spec.requireControlNonError ?? defaultRequireControlNonError(spec)
    let forcedInconclusiveReason: string | null = null
    if (guardControlErrors) {
      if (isUnexpectedErrorStatus(controlEx.status, spec.expectedStatus)) {
        forcedInconclusiveReason = `Unexpected HTTP ${controlEx.status} on cache_differential control step (requireControlNonError).`
      } else if (isUnexpectedErrorStatus(verifyEx.status, spec.expectedStatus)) {
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
    const normVerifyBody = normalizeStructuralTokens(verifyEx.body)
    const simControlVsVerify = structuralDiffNormalized(normalizeStructuralTokens(controlEx.body), normVerifyBody).similarity
    const simProbeVsVerify = structuralDiffNormalized(normalizeStructuralTokens(probeEx.body), normVerifyBody).similarity

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
      const catchall = await runRunnerSpaCatchall({
        origin: spec.targetOrigin,
        ctx,
        recordExchange,
        targets: [{ id: 'verify', exchange: verifyEx }],
      })
      spaCatchall = catchall.summary
      if (catchall.allProbesMatchedCatchall) {
        forcedInconclusiveReason = 'cache_differential verify response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
      }
    }

    const controlSummary = { id: 'control', role: 'control', ...summarizeExchange(controlEx) }
    const probeSummary = { id: 'probe', role: 'probe', ...summarizeExchange(probeEx) }
    const verifySummary = { id: 'verify', role: 'probe', ...summarizeExchange(verifyEx) }
    const repeatSummary = repeatEx ? { id: 'repeat', role: 'probe', ...summarizeExchange(repeatEx) } : undefined

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
  const { exchanges, exchangeIds, recordExchange } = makeRunnerRecorder(ctx, 'auth')
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
      const headerJson = interpolateValue(resolveClaims(header), vars) as Record<string, unknown>
      const payloadJson = interpolateValue(resolveClaims(mint.payload), vars) as Record<string, unknown>
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
      const brokerReq = stepToBrokerRequest(step, stepVars, {
        replayJarPrefix,
        runId: ctx.runId,
        assignmentId: ctx.assignmentId,
      })
      if (brokerReq.authMutation?.kind === 'jku_x5u_canary' && !brokerReq.authMutation.url && !brokerReq.authMutation.value && ctrlCanary && prbCanary) {
        brokerReq.authMutation = { ...brokerReq.authMutation, url: step.role === 'control' ? ctrlCanary.url : prbCanary.url }
      }
      const ex = await ctx.broker.executeHttp(brokerReq, ctx.grant, ctx.signal)
      const exId = recordExchange(ex)
      extractVariables(step, ex, vars)
      const stepEntry: Record<string, unknown> = { id: step.id, role: step.role, ...summarizeExchange(ex) }
      stepsOut[step.id] = stepEntry
      if (step.role === 'control' && !firstControlStep) firstControlStep = stepEntry
      if (step.role === 'probe') {
        if (!firstProbeStep) firstProbeStep = stepEntry
        probeStepExchanges.push({ id: step.id, exchange: ex, exchangeId: exId, request: brokerReq })
      }
    }

    const guardControlErrors = spec.requireControlNonError ?? defaultRequireControlNonError(spec)
    if (guardControlErrors) {
      for (const step of spec.steps) {
        if (step.role !== 'control' && step.role !== 'probe') continue
        const status = (stepsOut[step.id] as { status?: number } | undefined)?.status
        if (typeof status === 'number' && isUnexpectedErrorStatus(status, step.expectedStatus, spec.expectedStatus)) {
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
        const carrierExtra = primaryProbe.request.authMutation?.kind === 'jku_x5u_canary'
          ? (primaryProbe.request.authMutation.url ?? primaryProbe.request.authMutation.value ?? '')
          : ''
        oobReceiptCheck = evaluateRunnerOobReceipt({
          origin: spec.origin,
          stepId: primaryProbe.id,
          exchange: primaryProbe.exchange,
          exchangeId: primaryProbe.exchangeId,
          request: primaryProbe.request,
          oobEventId: 'auth-oob-canary',
          callbackPrefix: 'auth',
          token: prbCanary.token,
          probeWait,
          controlTriggered: controlCheck.triggered,
          claimedDelta: 'Auth protocol token header triggered an out-of-band canary fetch on probe only.',
          injectedAtMs,
          carrierExtra,
        })
        if (!oobReceiptCheck.verification.confirmed) {
          deterministicProofPassed = false
          proofFailureReason = oobReceiptCheck.verification.reason
        }
      }
    }

    let spaCatchall: Record<string, unknown> | undefined
    if (spec.spaCatchallControl) {
      const catchall = await runRunnerSpaCatchall({
        origin: spec.origin,
        ctx,
        recordExchange,
        targets: probeStepExchanges,
      })
      spaCatchall = catchall.summary
      if (catchall.allProbesMatchedCatchall) {
        forcedInconclusiveReason = 'Probe response is structurally indistinguishable from an HTTP 200 SPA catch-all route.'
      }
    }

    const authSteps = impactStepsFromStepsOut(spec, stepsOut)
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
    const jqCommand = `jq '${singleQuoteEscape(spec.assertionsJq)}' /evidence/replay-results.json > /work/outcome.json`
    const workerResult = await ctx.backend.run({
      assignmentId: ctx.assignmentId,
      files: [{ name: 'replay-results.json', content: serializedPayload }],
      command: jqCommand,
      outputs: ['outcome.json'],
      timeoutMs: 30_000,
    }, ctx.signal)
    const rawOutcome = (workerResult.outputs['outcome.json'] || workerResult.stdout || '').trim()
    if (workerResult.exitCode !== 0 || !rawOutcome) {
      return inconclusiveResult(`Replay jq assertion failed (exit ${workerResult.exitCode}): ${workerResult.stderr.slice(0, 400)}`, exchanges, exchangeIds, evidencePayload)
    }
    let parsedJson: unknown
    try { parsedJson = JSON.parse(rawOutcome) } catch {
      return inconclusiveResult('Replay jq assertion did not emit valid JSON.', exchanges, exchangeIds, evidencePayload)
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
      return inconclusiveResult(`Replay assertion output violated schema: ${validated.error.issues[0]?.message ?? 'invalid shape'}`, exchanges, exchangeIds, evidencePayload)
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

// ---------------------------------------------------------------------------------------------
// Verification assessment + receipt helpers (moved from replay-verifier.ts, Cut 3f)
//
// These helpers implement the legacy declarative VM's impact/proof-strength gates and the receipt
// gate. They live with the recipe engine so `replay-verifier.ts` stays a thin validation/dispatch
// module; every public symbol is re-exported from the verifier.
// ---------------------------------------------------------------------------------------------

function interpolateString(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}/g, (full, name: string) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? vars[name] : full)
}

function interpolateValue(value: unknown, vars: Record<string, string>): unknown {
  if (typeof value === 'string') return interpolateString(value, vars)
  if (Array.isArray(value)) return value.map(v => interpolateValue(v, vars))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = interpolateValue(v, vars)
    }
    return out
  }
  return value
}

function readJsonPath(obj: unknown, path: string): string | null {
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

export function extractVariables(step: ReplayStep, exchange: BrokerExchangeResult, vars: Record<string, string>) {
  for (const rule of step.extract ?? []) {
    let extracted: string | null = null
    if (rule.from === 'status') {
      extracted = String(exchange.status)
    } else if (rule.from === 'header') {
      extracted = exchange.respHeaders[rule.selector.toLowerCase()] ?? null
    } else if (rule.from === 'json') {
      try {
        const parsed = JSON.parse(exchange.body) as unknown
        extracted = readJsonPath(parsed, rule.selector)
      } catch {
        extracted = null
      }
    } else if (rule.from === 'regex') {
      try {
        const re = new RegExp(rule.selector)
        const m = exchange.body.match(re)
        extracted = m ? (m[1] ?? m[0] ?? null) : null
      } catch {
        extracted = null
      }
    }
    if (extracted !== null) vars[rule.varName] = extracted.slice(0, 512)
  }
}

const BFLA_CWE_RE = /^CWE-(?:285|269|862|863)$/i
const BFLA_TEXT_RE = /\b(?:bfla|broken function[- ]level|function[- ]level|privilege escalation|vertical access)\b/i
const READ_ONLY_REPLAY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const MUTATING_REPLAY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export interface BflaImpactAssessment {
  required: boolean
  satisfied: boolean
  reason: string
  evidence?: Record<string, unknown>
}

function normalizedReplayPath(value: string | undefined): string {
  if (!value) return ''
  return value.split('?')[0].split('#')[0].replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase() || '/'
}

/** Parse the body the host actually sent, including form/XML carriers, for shared impact oracles. */
function recordedRequestJson(entry: Record<string, unknown> | undefined, request: ReplayStep['request']): unknown {
  const raw = typeof entry?.requestBody === 'string' ? entry.requestBody : request.textBody
  if (raw === undefined) return request.jsonBody
  const contentType = String(entry?.requestHeaders && typeof entry.requestHeaders === 'object'
    ? Object.entries(entry.requestHeaders as Record<string, unknown>).find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? ''
    : Object.entries(request.headers ?? {}).find(([name]) => name.toLowerCase() === 'content-type')?.[1] ?? '')
  if (/application\/x-www-form-urlencoded/i.test(contentType)) {
    return Object.fromEntries(new URLSearchParams(raw).entries())
  }
  if (/json/i.test(contentType) || /^(?:\{|\[)/.test(raw.trim())) {
    try { return JSON.parse(raw) } catch { return raw }
  }
  return raw
}

/**
 * Map recorded replay steps onto the shared evidence model. Role/tenant/auth metadata is enriched
 * into each step summary at record time (see `personaActorFields`), so the same validators can run
 * on a spec whose persona handles are opaque.
 */
export function impactStepsFromStepsOut(
  spec: DeclarativeReplaySpec,
  stepsOut: Record<string, unknown>,
): ImpactStep[] {
  if (spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') return []
  return spec.steps.map(step => {
    const entry = stepsOut[step.id] as Record<string, unknown> | undefined
    const handle = (typeof entry?.personaHandle === 'string' ? entry.personaHandle : null) ?? step.request.persona ?? null
    const declaredRole = typeof entry?.actorRole === 'string' ? normalizeRole(entry.actorRole) : null
    let entryJson = entry?.json ?? null
    if (entryJson === null && typeof entry?.body === 'string') {
      // Unit-level callers may provide only the recorded body; parse it so the shared validators
      // see the same shape the wire recorder produces.
      try { entryJson = JSON.parse(entry.body) } catch { entryJson = null }
    }
    return {
      id: step.id,
      arm: step.role,
      method: step.request.method.toUpperCase(),
      route: normalizedReplayPath(typeof entry?.pathAndQuery === 'string' ? entry.pathAndQuery : step.request.pathAndQuery),
      pathAndQuery: typeof entry?.pathAndQuery === 'string' ? entry.pathAndQuery : step.request.pathAndQuery,
      status: typeof entry?.status === 'number' ? entry.status : null,
      actor: {
        handle,
        role: declaredRole ?? normalizeRole(step.request.persona),
        tenant: typeof entry?.actorTenant === 'string' ? entry.actorTenant : null,
        auth: (typeof entry?.ambientAuth === 'string' ? entry.ambientAuth : 'unknown') as AmbientAuth,
        sameSite: typeof entry?.sessionSameSite === 'string' ? entry.sessionSameSite : null,
      } satisfies ActorIdentity,
      json: entryJson,
      body: typeof entry?.body === 'string' ? entry.body : '',
      ...(Array.isArray(entry?.secretMatches)
        ? { secretMatches: (entry.secretMatches as Array<Record<string, unknown>>).map(match => String(match.sha256Prefix ?? '')).filter(Boolean) }
        : {}),
      requestJson: recordedRequestJson(entry, step.request),
      requestHeaders: (entry?.requestHeaders as Record<string, string> | undefined) ?? step.request.headers ?? null,
      responseHeaders: (entry?.headers as Record<string, string> | undefined) ?? null,
    }
  })
}

/**
 * Vertical (function-level) BFLA needs *impact*, not just a 2xx from a lower-privileged actor.
 * A read-only route that every authenticated role may legitimately read must never confirm as
 * privilege escalation: the replay must show a role/tenant differential *and* a real side effect
 * (or an owner-scoped disclosure for reads). Object-level BOLA (CWE-639) is handled by the shared
 * impact gate, not here.
 */
export function assessBflaImpact(
  spec: DeclarativeReplaySpec,
  stepsOut: Record<string, unknown>,
): BflaImpactAssessment {
  if (spec.kind !== 'http_chain') {
    return { required: false, satisfied: true, reason: 'Not an HTTP chain replay spec.' }
  }
  const descriptor = `${spec.cwe} ${spec.category} ${spec.title} ${spec.impact} ${spec.severityRationale}`
  const vertical = BFLA_CWE_RE.test(spec.cwe) || BFLA_TEXT_RE.test(descriptor)
  if (!vertical || spec.steps.length < 2) {
    return { required: false, satisfied: true, reason: 'Not a function-level BFLA proof.' }
  }
  const assessment = assessImpactEvidence({
    impactClass: 'bfla',
    steps: impactStepsFromStepsOut(spec, stepsOut),
    requiredRole: spec.requiredRole ?? null,
    resourceTenant: spec.resourceTenant ?? null,
    expectControlDenied: spec.expectControlDenied,
    oracleEvents: spec.expectedImpactEvents,
    targetOrigin: spec.origin,
  })
  return {
    required: true,
    satisfied: assessment.satisfied,
    reason: assessment.reason,
    ...(assessment.evidence ? { evidence: assessment.evidence } : {}),
  }
}

// ---------------------------------------------------------------------------
// v5.1 Slice 4 — proof-strength + endpoint-binding guards for LLM-authored
// http_chain specs. These guards are strictly additive: they can only turn a
// would-be confirmation into `inconclusive`, never the other way around.
// ---------------------------------------------------------------------------

type HttpChainSpec = Extract<DeclarativeReplaySpec, { kind: 'http_chain' }>

/** Vertical/horizontal authorization claims, identified by CWE or category only (never free text). */
const AUTHZ_CWE_RE = /^CWE-(?:269|284|285|566|639|862|863|1220)$/i
const AUTHZ_CATEGORY_RE = /(?:^|[-_\s])(?:broken[-_\s]?access[-_\s]?control|access[-_\s]?control|idor|bola|bfla|authori[sz]ation|privilege[-_\s]?escalation|tenant[-_\s]?isolation)(?:$|[-_\s])/i

function isAuthorizationClaim(spec: HttpChainSpec): boolean {
  return AUTHZ_CWE_RE.test(spec.cwe) || AUTHZ_CATEGORY_RE.test(spec.category)
}

export type HttpChainAssertionEvidence = 'status_only' | 'unbound_content' | 'content_bound'

/**
 * Classify what the jq assertion actually proves. `status_only` inspects nothing but status codes;
 * `unbound_content` reads a body/header without binding it to an identifier, extracted variable or
 * field comparison (a dynamic page differs on every request); `content_bound` compares structured
 * fields, extracted identifiers, canary/canary-fingerprint evidence or secret fingerprints.
 */
export function classifyHttpChainAssertion(program: string): HttpChainAssertionEvidence {
  const fields = new Set<string>()
  for (const match of program.matchAll(/\.steps\.[A-Za-z0-9_-]+\.([A-Za-z0-9_]+)/g)) {
    fields.add(match[1].toLowerCase())
  }
  const contentFields = [...fields].filter(field =>
    field !== 'status' && field !== 'statuses' && field !== 'id' && field !== 'role' && field !== 'batchcount')
  const topLevelProof = /\.(?:proofMatches|extractedVars|secretMatches|canary|cacheProof|uploadProof|cryptographicProofPassed)\b/.test(program)
  if (contentFields.length === 0) return topLevelProof ? 'content_bound' : 'status_only'
  if (fields.has('json') || fields.has('secretmatches')) return 'content_bound'
  const identifierBound = topLevelProof ||
    /\$[A-Za-z_][A-Za-z0-9_]*/.test(program) ||
    /\.(?:body|bodyPreview)\s*\|\s*(?:index|contains|startswith|endswith|test|match|capture|split|ltrimstr|rtrimstr)\s*\(/.test(program) ||
    /\b(?:index|contains|startswith|endswith)\s*\(\s*(?:"[^"]*"|\$[A-Za-z_])/.test(program)
  if (identifierBound) return 'content_bound'
  // A body/header byte-length differential is structural (a masked value cannot be longer than the
  // value it masks); any other unbound body/header read is only a "different body" observation.
  if (fields.has('bodybytes')) return 'content_bound'
  return 'unbound_content'
}

interface JsonFieldRef {
  stepId: string
  path: string[]
}

/** Extract `.steps.<id>.json.<field>` / `.json["field"]` references (bounded, no array indexes). */
function referencedJsonPaths(program: string): JsonFieldRef[] {
  const out: JsonFieldRef[] = []
  const seen = new Set<string>()
  const refPattern = /\.steps\.([A-Za-z0-9_-]+)\.json((?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:"[^"]{1,64}"|\d{1,3})\])+)/g
  for (const match of program.matchAll(refPattern)) {
    const segments = [...match[2].matchAll(/\[(?:"([^"]{1,64})"|\d{1,3})\]|\.([A-Za-z_][A-Za-z0-9_]*)/g)]
    if (segments.some(seg => seg[1] === undefined && seg[2] === undefined)) continue
    if (/\[\d{1,3}\]/.test(match[2])) continue
    const path = segments.map(seg => seg[1] ?? seg[2]).filter((seg): seg is string => Boolean(seg))
    if (path.length === 0) continue
    const key = `${match[1]}|${path.join('.')}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push({ stepId: match[1], path })
    if (out.length >= 24) break
  }
  return out
}

function readJsonField(json: unknown, path: readonly string[]): string | null {
  let cur: unknown = json
  for (const segment of path) {
    if (!cur || typeof cur !== 'object' || Array.isArray(cur)) return null
    cur = (cur as Record<string, unknown>)[segment]
  }
  if (cur === undefined || cur === null) return null
  return typeof cur === 'string' ? cur : JSON.stringify(cur)
}

/** Non-secret quoted literals used by the assertion, for identifier-bound marker disclosure checks. */
function jqStringLiterals(program: string): string[] {
  const out = new Set<string>()
  for (const match of program.matchAll(/"((?:[^"\\]|\\.){8,120})"/g)) {
    const value = match[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\')
    if (!value || /[\r\n\0]/.test(value)) continue
    if (/^(?:application\/json|content-type|content-security-policy)$/i.test(value)) continue
    out.add(value)
    if (out.size >= 8) break
  }
  return [...out]
}

function normalizeOriginValue(value: string | undefined): string {
  if (!value) return ''
  try {
    const url = new URL(value)
    return `${url.protocol}//${url.host.toLowerCase()}`
  } catch {
    return value.trim().toLowerCase().replace(/\/+$/, '')
  }
}

function originHost(value: string | undefined): string {
  try {
    return value ? new URL(value).host.toLowerCase() : ''
  } catch {
    return ''
  }
}

/** Route family: path only, lower-cased, trailing slash trimmed (query is compared separately). */
export function routeKey(pathAndQuery: string | undefined): string {
  if (!pathAndQuery) return ''
  const pathOnly = pathAndQuery.split('?')[0].split('#')[0]
  const collapsed = pathOnly.replace(/\/{2,}/g, '/').replace(/\/+$/, '')
  return (collapsed || '/').toLowerCase()
}

interface HttpChainStepSnapshot {
  index: number
  id: string
  role: string
  method: string
  route: string
  pathAndQuery: string
  actor: string
  status: number | null
  body: string
  bodyBytes: number
  mediaType: string
  json: unknown
  requestJson?: unknown
  requestBody?: string
  requestHeaders?: Record<string, string> | null
  secretMatches: number
}

export function isSuccessStatus(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300
}

export function snapshotHttpChainSteps(
  spec: HttpChainSpec,
  stepsOut: Record<string, unknown>,
  stepExchanges: ReadonlyMap<string, BrokerExchangeResult[]>,
): HttpChainStepSnapshot[] {
  return spec.steps.map((step, index) => {
    const entry = (stepsOut[step.id] ?? {}) as Record<string, unknown>
    const exchange = stepExchanges.get(step.id)?.[0]
    const body = typeof entry.body === 'string' ? entry.body : ''
    const persona = step.request.persona ?? null
    const session = step.request.session ?? null
    return {
      index,
      id: step.id,
      role: step.role,
      method: step.request.method.toUpperCase(),
      route: routeKey(exchange?.pathAndQuery ?? step.request.pathAndQuery),
      pathAndQuery: exchange?.pathAndQuery ?? step.request.pathAndQuery,
      actor: persona ? `persona:${persona}` : session ? `session:${session}` : 'anonymous',
      status: typeof entry.status === 'number' ? entry.status : null,
      body,
      bodyBytes: typeof entry.bodyBytes === 'number' ? entry.bodyBytes : Buffer.byteLength(body, 'utf8'),
      mediaType: typeof entry.mediaType === 'string' ? entry.mediaType : '',
      json: entry.json ?? null,
      ...(step.request.jsonBody !== undefined ? { requestJson: step.request.jsonBody } : {}),
      ...(typeof step.request.textBody === 'string' ? { requestBody: step.request.textBody } : {}),
      ...(step.request.headers ? { requestHeaders: step.request.headers } : {}),
      secretMatches: exchange?.secretMatches?.length ?? 0,
    }
  })
}

export type HttpChainDifferential =
  | 'denied_then_allowed'
  | 'cross_actor_access'
  | 'field_bound'
  | 'state_delta'
  | 'identifier_proof'
  | null

export interface HttpChainProofStrength {
  claim: 'authorization' | 'other'
  assertionEvidence: HttpChainAssertionEvidence
  differential: HttpChainDifferential
  satisfied: boolean
  reason: string
}

function detectHttpChainDifferential(
  spec: HttpChainSpec,
  snapshots: readonly HttpChainStepSnapshot[],
): HttpChainDifferential {
  const controls = snapshots.filter(step => step.role === 'control')
  const probes = snapshots.filter(step => step.role === 'probe')
  const dataBearing = (step: HttpChainStepSnapshot) => isSuccessStatus(step.status) && step.bodyBytes >= 8
  const sameRoute = (a: HttpChainStepSnapshot, b: HttpChainStepSnapshot) =>
    a.method === b.method && a.route === b.route && a.route !== ''
  const denied = (step: HttpChainStepSnapshot) => step.status === 401 || step.status === 403
  // A control that is bounced (login/SSO redirect) did not receive the resource either.
  const bounced = (step: HttpChainStepSnapshot) =>
    step.status !== null && step.status >= 300 && step.status < 400

  // 1. The same endpoint is denied to the control caller and served to the probe caller.
  if (probes.some(probe => dataBearing(probe) && controls.some(control => sameRoute(control, probe) && (denied(control) || bounced(control))))) {
    return 'denied_then_allowed'
  }

  // 2. A different actor reaches the exact endpoint the control actor reached.
  if (probes.some(probe => dataBearing(probe) && controls.some(control =>
    sameRoute(control, probe) && control.actor !== probe.actor && (isSuccessStatus(control.status) || denied(control))))) {
    return 'cross_actor_access'
  }

  // 3. A declared response field carries a different value for the probe than for the control.
  for (const ref of referencedJsonPaths(spec.assertionsJq)) {
    const probe = probes.find(step => step.id === ref.stepId && isSuccessStatus(step.status))
    if (!probe) continue
    const probeValue = readJsonField(probe.json, ref.path)
    if (probeValue === null) continue
    if (controls.some(control => control.status !== null && readJsonField(control.json, ref.path) !== probeValue)) {
      return 'field_bound'
    }
  }

  // 4. A privileged mutation succeeds and a later read observes the mutated state (or its removal).
  const mutatingProbe = probes.find(step => MUTATING_REPLAY_METHODS.has(step.method) && isSuccessStatus(step.status))
  if (mutatingProbe) {
    const reads = snapshots.filter(step => READ_ONLY_REPLAY_METHODS.has(step.method) && step.index !== mutatingProbe.index)
    const before = [...reads].reverse().find(step => step.index < mutatingProbe.index && isSuccessStatus(step.status) && step.bodyBytes > 0)
    const after = reads.find(step => step.index > mutatingProbe.index)
    if (before && after) {
      if ((after.status !== null && after.status >= 400) || (after.bodyBytes > 0 && after.body !== before.body)) {
        return 'state_delta'
      }
    }
  }

  // 5. Identifier-bound proof: pre-redaction secret fingerprints or an asserted marker observed only
  //    in the probe response.
  if (probes.some(step => isSuccessStatus(step.status) && step.secretMatches > 0)) return 'identifier_proof'
  const controlBodies = controls.map(step => step.body)
  for (const literal of jqStringLiterals(spec.assertionsJq)) {
    if (probes.some(step => step.body !== '' && step.body.includes(literal)) &&
        !controlBodies.some(body => body.includes(literal))) {
      return 'identifier_proof'
    }
  }

  return null
}

/**
 * Proof-strength gate for authorization `http_chain` specs. A status-only claim (or a bare
 * "the body differs" claim) is never a control-vs-probe differential, and a content assertion must
 * be backed by an observable differential in the recorded exchanges (denied-then-allowed,
 * cross-actor access, field-bound value change, state delta, or identifier-bound proof).
 */
export function assessHttpChainProofStrength(
  spec: HttpChainSpec,
  snapshots: readonly HttpChainStepSnapshot[],
): HttpChainProofStrength {
  const assertionEvidence = classifyHttpChainAssertion(spec.assertionsJq)
  // Universal status-only ban: a bare 2xx -> 4xx/5xx divergence can never confirm ANY class. The
  // injection/authz/redirect oracles still run afterwards; this is a floor, not a substitute.
  if (assertionEvidence === 'status_only') {
    const statusOnly = assessStatusOnlyDivergence(
      snapshots.map(snapshot => ({
        id: snapshot.id,
        arm: snapshot.role === 'probe'
          ? 'probe' as const
          : snapshot.role === 'control'
            ? 'control' as const
            : snapshot.role === 'cleanup'
              ? 'cleanup' as const
              : 'setup' as const,
        method: snapshot.method,
        route: snapshot.route,
        pathAndQuery: snapshot.pathAndQuery,
        status: snapshot.status,
        actor: actorFromPersona(snapshot.actor, []),
        json: snapshot.json,
        body: snapshot.body,
        ...(snapshot.requestJson !== undefined ? { requestJson: snapshot.requestJson } : {}),
        ...(snapshot.requestBody !== undefined ? { requestBody: snapshot.requestBody } : {}),
        ...(snapshot.requestHeaders ? { requestHeaders: snapshot.requestHeaders } : {}),
      })),
    )
    if (statusOnly.statusOnly) {
      return {
        claim: isAuthorizationClaim(spec) ? 'authorization' : 'other',
        assertionEvidence,
        differential: null,
        satisfied: false,
        reason: statusOnly.reason,
      }
    }
  }
  if (!isAuthorizationClaim(spec)) {
    return { claim: 'other', assertionEvidence, differential: null, satisfied: true, reason: 'Not an authorization claim.' }
  }
  if (assertionEvidence === 'status_only') {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential: null,
      satisfied: false,
      reason: 'Authorization claim is status-only: a 2xx status (or status equality) is not an access-control differential. Assert a cross-actor resource read, a field/identifier bound to the victim object, or a state delta.',
    }
  }
  // Canary / cryptographic proof is produced by the verifier itself (distinct control vs probe
  // tokens, non-destructive math), so it is already an identifier-bound execution differential.
  if (/\.(?:canary|proof)\b/.test(spec.assertionsJq)) {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential: 'identifier_proof',
      satisfied: true,
      reason: 'Authorization claim is bound to verifier-minted canary/cryptographic proof.',
    }
  }
  const differential = detectHttpChainDifferential(spec, snapshots)
  if (assertionEvidence === 'unbound_content' && differential !== 'state_delta' && differential !== 'field_bound') {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential,
      satisfied: false,
      reason: 'Authorization claim rests on a different-body observation without identifier binding; assert a field-bound value, extracted victim identifier, secret fingerprint, or state delta.',
    }
  }
  if (differential === null) {
    return {
      claim: 'authorization',
      assertionEvidence,
      differential,
      satisfied: false,
      reason: 'Authorization claim has no genuine control-vs-probe differential in the recorded exchanges (no denied-then-allowed route, cross-actor access, field-bound change, or state delta).',
    }
  }
  return {
    claim: 'authorization',
    assertionEvidence,
    differential,
    satisfied: true,
    reason: `Authorization differential proven: ${differential}.`,
  }
}

export interface HttpChainEndpointBinding {
  bound: boolean
  verifiedEndpoint: { stepId: string; role: string; origin: string; method: string; pathAndQuery: string } | null
  declaredEndpoint: { stepId: string; origin: string; method: string; pathAndQuery: string } | null
  mismatches: Array<{ stepId: string; field: 'origin' | 'method' | 'redirectHost' | 'specOrigin'; declared: string; actual: string }>
  reason: string
}

/**
 * Mechanical endpoint/method binding: the verified endpoint is the *actual* probe exchange, not the
 * spec's claim. Any disagreement between the declared step request and the wire exchange, a redirect
 * that leaves the declared host, or a primary probe step targeting a different origin than the
 * finding origin, invalidates the confirmation.
 */
export function assessHttpChainEndpointBinding(
  spec: HttpChainSpec,
  stepRequests: ReadonlyMap<string, readonly BrokerHttpRequest[]>,
  stepExchanges: ReadonlyMap<string, readonly BrokerExchangeResult[]>,
): HttpChainEndpointBinding {
  const mismatches: HttpChainEndpointBinding['mismatches'] = []
  for (const step of spec.steps) {
    const requests = stepRequests.get(step.id) ?? []
    const exchanges = stepExchanges.get(step.id) ?? []
    for (const [idx, exchange] of exchanges.entries()) {
      const request = requests[Math.min(idx, Math.max(0, requests.length - 1))]
      if (!request) continue
      if (exchange.method.toUpperCase() !== request.method.toUpperCase()) {
        mismatches.push({ stepId: step.id, field: 'method', declared: request.method.toUpperCase(), actual: exchange.method.toUpperCase() })
      }
      if (normalizeOriginValue(exchange.origin) !== normalizeOriginValue(request.origin)) {
        mismatches.push({ stepId: step.id, field: 'origin', declared: normalizeOriginValue(request.origin), actual: normalizeOriginValue(exchange.origin) })
      }
    }
  }

  const primaryProbe = spec.steps.find(step => step.role === 'probe' && (stepExchanges.get(step.id)?.length ?? 0) > 0)
  const primaryExchange = primaryProbe ? stepExchanges.get(primaryProbe.id)?.[0] : undefined
  if (!primaryProbe || !primaryExchange) {
    return {
      bound: false,
      verifiedEndpoint: null,
      declaredEndpoint: null,
      mismatches,
      reason: 'No executed probe exchange is available to bind the finding endpoint.',
    }
  }

  const declaredEndpoint = {
    stepId: primaryProbe.id,
    origin: normalizeOriginValue(primaryProbe.request.origin),
    method: primaryProbe.request.method.toUpperCase(),
    pathAndQuery: primaryProbe.request.pathAndQuery,
  }
  const verifiedEndpoint = {
    stepId: primaryProbe.id,
    role: primaryProbe.role,
    origin: normalizeOriginValue(primaryExchange.origin),
    method: primaryExchange.method.toUpperCase(),
    pathAndQuery: primaryExchange.pathAndQuery,
  }

  if (normalizeOriginValue(spec.origin) !== declaredEndpoint.origin) {
    mismatches.push({ stepId: primaryProbe.id, field: 'specOrigin', declared: declaredEndpoint.origin, actual: normalizeOriginValue(spec.origin) })
  }
  const declaredHost = originHost(primaryProbe.request.origin)
  const finalHost = originHost(primaryExchange.finalOrigin)
  if (declaredHost && finalHost && declaredHost !== finalHost) {
    mismatches.push({ stepId: primaryProbe.id, field: 'redirectHost', declared: declaredHost, actual: finalHost })
  }

  if (mismatches.length > 0) {
    const first = mismatches[0]
    return {
      bound: false,
      verifiedEndpoint,
      declaredEndpoint,
      mismatches: mismatches.slice(0, 8),
      reason: first.field === 'specOrigin'
        ? `Finding origin ${normalizeOriginValue(spec.origin)} does not match the probe endpoint origin ${declaredEndpoint.origin} (step "${first.stepId}"); the verified exchange came from a different asset than the finding claims.`
        : first.field === 'redirectHost'
          ? `Probe step "${first.stepId}" redirected from ${first.declared} to ${first.actual}; the verified endpoint is not the declared asset.`
          : `Probe step "${first.stepId}" ${first.field} mismatch: declared ${first.declared}, exchanged ${first.actual}.`,
    }
  }

  return {
    bound: true,
    verifiedEndpoint,
    declaredEndpoint,
    mismatches: [],
    reason: `Verified ${verifiedEndpoint.method} ${verifiedEndpoint.origin}${verifiedEndpoint.pathAndQuery} from step "${verifiedEndpoint.stepId}".`,
  }
}

export function summarizeExchange(ex: BrokerExchangeResult) {  let json: unknown = null
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
    // Pre-redaction structural proof: fingerprints only (never the raw value), so an assertion can
    // prove a disclosed secret matched the entitled view even after the body was scrubbed.
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

export function hasDestructiveContent(text: string): boolean {
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

export function singleQuoteEscape(value: string): string {
  return value.replaceAll("'", "'\\''")
}

export const RETIRED_LEGACY_SPEC_KINDS: ReadonlySet<string> = new Set([
  'dns_takeover', 'tls_audit', 'browser_dom', 'ws_chain', 'upload_probe',
  'sql_boolean_diff', 'sql_time_diff', 'race_burst', 'browser_chain',
])
export const RETIRED_LEGACY_SPEC_REASON = 'retired_legacy_spec_kind: use kovo_verify'

export function retiredLegacyResult(
  kind: string,
  exchanges: BrokerExchangeResult[],
  exchangeIds: string[],
): ReplayVerificationResult {
  const evidencePayload = { kind, retired: true, reason: RETIRED_LEGACY_SPEC_REASON }
  const evidenceSha256 = createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex')
  return {
    verdict: 'dismissed',
    outcome: {
      confirmed: false,
      controlPassed: false,
      observed: RETIRED_LEGACY_SPEC_REASON,
      expected: 'Proof submitted via kovo_verify or a wired floor recipe.',
      reason: RETIRED_LEGACY_SPEC_REASON,
    },
    exchangeIds,
    exchanges,
    evidencePayload,
    evidenceSha256,
  }
}

export function inconclusiveResult(
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

/**
 * Mint a throw-away signing key and a fresh timestamp, then compute the HMAC over the documented
 * canonical form. Used only for self-signed webhook proof (no real secret ever enters the spec).
 */

function applyBodySignature(interpolated: unknown, signable: NonNullable<ReplayStep['request']['bodySignature']>): unknown {
  const input = interpolated && typeof interpolated === 'object' && !Array.isArray(interpolated)
    ? { ...(interpolated as Record<string, unknown>) }
    : {}
  const key = `kovo_whk_${randomBytes(8).toString('hex')}`
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

function requestShapeToBrokerRequest(
  req: ReplayStep['request'],
  vars: Record<string, string>,
  opts?: {
    sessionId?: string
    sessionGroupRole?: 'setup' | 'control' | 'probe' | 'cleanup'
    runId?: string
    assignmentId?: string
  },
): BrokerHttpRequest {
  const pathAndQuery = interpolateString(req.pathAndQuery, vars)
  const headers: Record<string, string> = {}
  for (const [k, v] of Object.entries(req.headers ?? {})) {
    headers[k] = interpolateString(v, vars)
  }
  let body: string | undefined
  if (req.textBody !== undefined) {
    body = interpolateString(req.textBody, vars)
  } else if (req.jsonBody !== undefined) {
    const interpolated = interpolateValue(req.jsonBody, vars)
    const signable = (req as ReplayStep['request']).bodySignature
    const signed = signable ? applyBodySignature(interpolated, signable) : interpolated
    body = JSON.stringify(signed)
    if (!headers['Content-Type'] && !headers['content-type']) {
      headers['Content-Type'] = 'application/json'
    }
  }
  const maybeReq = req as ReplayStep['request']
  let authMutation: AuthMutation | undefined = maybeReq.authMutation
  if (authMutation && authMutation.kind === 'jku_x5u_canary') {
    const rawUrl = authMutation.url ?? authMutation.value
    const interpUrl = rawUrl !== undefined ? interpolateString(rawUrl, vars) : undefined
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
    ...(opts?.sessionId ?? req.session ? { session: opts?.sessionId ?? req.session } : {}),
    ...(opts?.sessionGroupRole ? { sessionGroupRole: opts.sessionGroupRole } : {}),
    ...(req.csrfBind !== undefined ? { csrfBind: req.csrfBind } : {}),
    ...(authMutation ? { authMutation } : {}),
    ...(maybeReq.traceId ? { traceId: maybeReq.traceId } : {}),
    ...(opts?.runId ? { runId: opts.runId } : {}),
    ...(opts?.assignmentId ? { assignmentId: opts.assignmentId } : {}),
    followRedirects: req.followRedirects,
  }
}

export function stepToBrokerRequest(
  step: ReplayStep,
  vars: Record<string, string>,
  opts?: { replayJarPrefix?: string; runId?: string; assignmentId?: string },
): BrokerHttpRequest {
  let sessionId: string | undefined
  if (step.request.session) {
    if (opts?.replayJarPrefix) {
      const candidate = `rv-${opts.replayJarPrefix}-${step.request.session}`
      sessionId = candidate.length <= 32
        ? candidate
        : `rv-${opts.replayJarPrefix}-${createHash('sha256').update(step.request.session).digest('hex').slice(0, 12)}`.slice(0, 32)
    } else {
      sessionId = step.request.session
    }
  }
  return requestShapeToBrokerRequest(step.request, vars, {
    sessionId,
    sessionGroupRole: step.role,
    runId: opts?.runId,
    assignmentId: opts?.assignmentId,
  })
}

/** requireControlNonError defaults to true for posture / auth-bypass style specs. */
export function defaultRequireControlNonError(spec: DeclarativeReplaySpec): boolean {
  if (spec.kind === 'static_ast_proof') return false
  return POSTURE_CWES.has(spec.cwe) || POSTURE_CATEGORY_RE.test(spec.category)
}

function statusMatchesExpected(expected: number | number[] | undefined, status: number): boolean {
  if (expected === undefined) return false
  return Array.isArray(expected) ? expected.includes(status) : expected === status
}

export function isUnexpectedErrorStatus(status: number, ...expected: Array<number | number[] | undefined>): boolean {
  if (status !== 404 && status < 500) return false
  return !expected.some(e => statusMatchesExpected(e, status))
}

/**
 * Map a replay spec onto a receipt class. Only classes whose evidence the receipt model can
 * re-derive in-process are returned; everything else stays on the legacy verdict (no invented
 * receipt rule keeps a confirmation alive).
 */

const CWE_NUMBER_RE = /\bCWE-(\d{1,5})\b/i

const CWE_TO_RECEIPT_CLASS: Record<number, string> = {
  918: 'ssrf',
  611: 'xxe',
  601: 'open_redirect',
  345: 'webhook_forgery',
  287: 'auth_bypass',
  288: 'auth_bypass',
  290: 'auth_bypass',
  306: 'auth_bypass',
  307: 'auth_bypass',
  347: 'auth_bypass',
  384: 'auth_bypass',
  613: 'auth_bypass',
  798: 'auth_bypass',
  352: 'csrf',
  915: 'mass_assignment',
  79: 'xss_stored',
  80: 'xss_stored',
  83: 'xss_stored',
  89: 'injection',
  564: 'injection',
  943: 'injection',
  269: 'bfla',
  285: 'bfla',
  862: 'bfla',
  863: 'bfla',
  284: 'bola',
  362: 'bola',
  566: 'bola',
  639: 'bola',
  1021: 'bola',
  1220: 'bola',
  840: 'business_logic',
  841: 'business_logic',
  472: 'business_logic',
  1284: 'business_logic',
  200: 'info_disclosure',
  359: 'info_disclosure',
  522: 'info_disclosure',
  532: 'info_disclosure',
}

const DEDICATED_RECEIPT_CLASSES = new Set(['ssrf', 'xxe', 'open_redirect', 'webhook_forgery'])

const EXPLICIT_KEYWORD_CLASS_MATCHERS: ReadonlyArray<{ receiptClass: string; pattern: RegExp }> = [
  { receiptClass: 'ssrf', pattern: /\bssrf\b|server[- ]side request/i },
  { receiptClass: 'xxe', pattern: /\bxxe\b|external entit/i },
  { receiptClass: 'open_redirect', pattern: /\bopen[-_ ]?redirect\b|unvalidated[- ]redirect/i },
  { receiptClass: 'webhook_forgery', pattern: /webhook[^.]{0,80}(?:signature|forger|tamper)|(?:signature|forger)[^.]{0,80}webhook/i },
  { receiptClass: 'csrf', pattern: /\bcsrf\b|cross[- ]site\s+request\s+forgery/i },
  { receiptClass: 'xss_stored', pattern: /\b(?:xss|cross[- ]site\s+scripting)\b/i },
  { receiptClass: 'injection', pattern: /\b(?:sqli|sql[-_ ]?injection|nosql[-_ ]?injection)\b/i },
  { receiptClass: 'mass_assignment', pattern: /\bmass[- ]?assign|over[- ]?post/i },
  { receiptClass: 'auth_bypass', pattern: /\b(?:auth(?:entication)?[- ]bypass|jwt[- ]forgery|oauth[- ]bypass|mfa[- ]bypass)\b/i },
]

function explicitKeywordReceiptClasses(labelText: string): string[] {
  const matched: string[] = []
  for (const { receiptClass, pattern } of EXPLICIT_KEYWORD_CLASS_MATCHERS) {
    if (pattern.test(labelText)) matched.push(receiptClass)
  }
  return matched
}

/**
 * R2-H-14 / H-18: Map a replay spec onto a receipt class strictly CWE-first.
 *
 * When `spec.cwe` names a CWE identifier:
 *   - Unmodelled CWEs (e.g. CWE-22) fail closed (`null`) regardless of keywords in title/impact;
 *   - Conflicting explicit class keywords in model-authored labels fail closed (`null`).
 * Only when no CWE identifier is present does classification fall back to label keywords (still
 * failing closed if two distinct explicit keyword classes conflict).
 */
export function receiptVulnClassFor(spec: DeclarativeReplaySpec): string | null {
  const labelText = `${spec.category ?? ''} ${spec.title ?? ''} ${spec.impact ?? ''}`
  const keywordClasses = explicitKeywordReceiptClasses(labelText)
  const cweMatch = CWE_NUMBER_RE.exec(spec.cwe ?? '')
  if (cweMatch) {
    const cweNum = Number(cweMatch[1])
    const cweClass = Object.prototype.hasOwnProperty.call(CWE_TO_RECEIPT_CLASS, cweNum)
      ? CWE_TO_RECEIPT_CLASS[cweNum]!
      : null
    if (!cweClass) return null
    if (!DEDICATED_RECEIPT_CLASSES.has(cweClass) && spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') {
      return null
    }
    // Fail closed whenever model-authored label keywords name a different receipt class than the CWE.
    if (keywordClasses.some(cls => cls !== cweClass)) return null
    return cweClass
  }

  // No CWE present: fall back to label keywords, failing closed on multi-class ambiguity.
  if (keywordClasses.length > 1) return null
  if (keywordClasses.length === 1) {
    const only = keywordClasses[0]!
    if (DEDICATED_RECEIPT_CLASSES.has(only)) return only
  }
  if (spec.kind !== 'http_chain' && spec.kind !== 'auth_protocol_proof') return null
  if (classifyBoundaryClaim({
    cwe: spec.cwe,
    category: spec.category,
    title: spec.title,
    impact: spec.impact,
  }) === 'auth') {
    return 'auth_bypass'
  }
  return vulnClassForImpactClass(classifyImpactDescriptor({
    cwe: spec.cwe,
    category: spec.category,
    title: spec.title,
    impact: spec.impact,
  }))
}

function vulnClassForImpactClass(impactClass: string | null | undefined): string | null {
  switch (impactClass) {
    case 'authorization':
    case 'bola':
      return 'bola'
    case 'bfla': return 'bfla'
    case 'mass_assignment': return 'mass_assignment'
    case 'csrf': return 'csrf'
    case 'business_logic': return 'business_logic'
    case 'markup': return 'xss_stored'
    case 'disclosure': return 'info_disclosure'
    case 'injection': return 'injection'
    default: return null
  }
}

const replayCanaryTokenRe = /kovo-canary-[a-f0-9]{24}/i

/**
 * Build a ProofReceipt + transcript from a completed replay. The transcript is the host-recorded
 * evidence the verifier already produced (`stepsOut` + exchange ids); nothing is re-executed.
 * Returns null when the spec has no receipt representation.
 */
export function buildReplayReceipt(input: {
  spec: DeclarativeReplaySpec
  evidencePayload: Record<string, unknown>
  exchangeIds: readonly string[]
  exchanges: readonly BrokerExchangeResult[]
  canaryBroker?: Pick<CanaryBroker, 'checkCanary'>
  canaryRunId?: string
  canaryStorage?: Store
}): { receipt: ProofReceipt; transcript: ReceiptTranscript; factLog: HostFactLog; trustedOracleEvents: string[] } | null {
  const impactGate = input.evidencePayload.impactGate as { required?: boolean } | undefined
  const bflaImpact = input.evidencePayload.bflaImpact as { required?: boolean } | undefined
  const boundaryGate = input.evidencePayload.boundaryGate as { required?: boolean; satisfied?: boolean; boundaryClass?: string } | undefined
  const evidenceClass = typeof input.evidencePayload.evidenceClass === 'string'
    ? input.evidencePayload.evidenceClass
    : null
  const specClass = receiptVulnClassFor(input.spec)
  // R2-H-14: When the spec carries an explicit CWE that failed closed (unmodelled or keyword conflict),
  // never let evidenceClass override the CWE-first rejection.
  if (CWE_NUMBER_RE.test(input.spec.cwe ?? '') && specClass === null) return null
  const baseVulnClass = vulnClassForImpactClass(evidenceClass) ?? specClass
  const isBoundaryAuth = (baseVulnClass === null || baseVulnClass === 'auth_bypass') &&
    boundaryGate?.required === true && boundaryGate.satisfied === true && boundaryGate.boundaryClass === 'auth'
  const vulnClass = baseVulnClass ?? (isBoundaryAuth ? 'auth_bypass' : null)
  if (!vulnClass) return null
  const canary = input.evidencePayload.canary as {
    triggered?: boolean
    probeTriggered?: boolean
    controlTriggered?: boolean
    token?: string
    callbackId?: string
    stage?: 'immediate' | 'late'
    receivedAtMs?: number
  } | undefined
  const isOob = vulnClass === 'ssrf' || vulnClass === 'xxe' ||
    (vulnClass === 'webhook_forgery' && canary?.triggered === true)
  const isRedirect = vulnClass === 'open_redirect'
  const isWebhook = vulnClass === 'webhook_forgery' && !isOob
  // Require a gated class (impactGate, bflaImpact, OOB, redirect, webhook differential, or boundaryGate auth
  // bypass) to emit a receipt. Dedicated rules re-derive their evidence from the host transcript.
  if (!isOob && !isRedirect && !isWebhook && !isBoundaryAuth && impactGate?.required !== true && bflaImpact?.required !== true) return null
  const stepsOut = (input.evidencePayload.steps ?? {}) as Record<string, unknown>
  const steps = impactStepsFromStepsOut(input.spec, stepsOut)
  if (steps.length === 0 && vulnClass !== 'ssrf' && vulnClass !== 'xxe') return null
  const exchangeById = new Map<string, BrokerExchangeResult>()
  input.exchangeIds.forEach((id, index) => {
    const exchange = input.exchanges[index]
    if (exchange) exchangeById.set(id, exchange)
  })
  const entries: ReceiptTranscriptEntry[] = []
  const orderedIds: string[] = []
  for (const [index, step] of steps.entries()) {
    const recorded = stepsOut[step.id] as { exchangeId?: unknown; durationMs?: unknown; requestBody?: unknown } | undefined
    const id = typeof recorded?.exchangeId === 'string'
      ? recorded.exchangeId
      : input.exchangeIds[index] ?? `exchange-${index}`
    if (!id) continue
    const exchange = exchangeById.get(id) ?? (input.exchangeIds.length === 0 ? input.exchanges[index] : undefined)
    const durationMs = typeof recorded?.durationMs === 'number' ? recorded.durationMs : exchange?.durationMs
    const requestBody = typeof recorded?.requestBody === 'string' ? recorded.requestBody : ''
    entries.push({
      exchangeId: id,
      step,
      seq: index + 1,
      origin: exchange?.origin || input.spec.origin,
      ...(typeof durationMs === 'number' ? { durationMs } : {}),
      ...(exchange || requestBody
        ? { carrierText: `${exchange?.pathAndQuery ?? step.pathAndQuery ?? ''}\n${JSON.stringify(step.requestHeaders ?? {})}\n${requestBody}` }
        : {}),
    })
    orderedIds.push(id)
  }

  if (isOob) {
    // C-3 & R2-H-14: Require canary.triggered === true AND an independently checked host CanaryBroker hit.
    const token = canary?.token
    if (canary?.triggered !== true || !token || !replayCanaryTokenRe.test(token) || !canary.callbackId || canary.controlTriggered === true) return null
    const hostCheck = input.canaryBroker?.checkCanary(token, {
      ...(input.canaryStorage ? { storage: input.canaryStorage } : {}),
      ...(input.canaryRunId ? { runId: input.canaryRunId } : {}),
    })
    if (!hostCheck?.hit || !hostCheck.hits.some(hit => hit.token === token)) return null
    const detail = hostCheck.detail ?? {}
    const receivedAtMs = typeof detail.timestamp === 'number' && Number.isFinite(detail.timestamp)
      ? detail.timestamp
      : typeof detail.receivedAt === 'string' ? Date.parse(detail.receivedAt) : Number.NaN
    if (!Number.isFinite(receivedAtMs)) return null
    const carrying = entries.find(entry => (entry.carrierText ?? '').includes(token))
    if (!carrying) return null
    const receipt = {
      vulnClass,
      target: {
        origin: input.spec.origin,
        method: carrying.step.method.toUpperCase(),
        ...(carrying.step.pathAndQuery ? { pathAndQuery: carrying.step.pathAndQuery } : {}),
      },
      exchangeIds: [carrying.exchangeId],
      oobEventIds: ['replay-canary'],
      browserTraceIds: [],
      claimedDelta: `The target fetched the injected out-of-band canary after the ${vulnClass.toUpperCase()} probe.`,
    }
    const transcript: ReceiptTranscript = {
      entries: [carrying],
      oobEvents: [{
        id: 'replay-canary',
        callbackId: canary.callbackId,
        token,
        targetOrigin: input.spec.origin,
        delivered: true,
        stage: canary.stage === 'late' ? 'late' : 'immediate',
        receivedAtMs,
      }],
      browserTraces: [],
    }
    return { receipt: receipt as ProofReceipt, transcript, factLog: HostFactLog.fromTranscript(transcript), trustedOracleEvents: [] }
  }

  if (orderedIds.length === 0) return null
  const targetExchangeStep = steps.find(step => step.arm === 'probe') ?? steps[0]
  const targetEntry = entries.find(entry => entry.step === targetExchangeStep) ?? entries[0]
  // H-1: Only derive trustedOracleEvents from host-observed controls (csrfBind verified against
  // host cookie-authenticated probe headers), NEVER from raw model-authored spec.expectedImpactEvents.
  const csrfModelled = vulnClass === 'csrf' && 'steps' in input.spec && Array.isArray(input.spec.steps) &&
    input.spec.steps.some(s => Boolean((s as { request?: { csrfBind?: unknown } }).request?.csrfBind))
  const hasHostCookieProbe = entries.some(entry =>
    entry.step.arm === 'probe' && (
      entry.step.actor.auth === 'cookie' ||
      Object.entries(entry.step.requestHeaders ?? {}).some(([k, v]) => k.toLowerCase() === 'cookie' && Boolean(v?.trim()))
    ),
  )
  const trustedOracleEvents = csrfModelled && hasHostCookieProbe ? ['csrf_state_change'] : []
  const receipt = {
    vulnClass,
    target: {
      origin: input.spec.origin,
      method: targetEntry.step.method.toUpperCase(),
      ...(targetEntry.step.pathAndQuery ? { pathAndQuery: targetEntry.step.pathAndQuery } : {}),
    },
    exchangeIds: orderedIds,
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: (input.spec.expectedImpactEvents ?? []).length
      ? `Replay observed the declared impact: ${(input.spec.expectedImpactEvents ?? []).join(', ')}.`
      : `Replay moved state across the ${vulnClass} boundary described by "${input.spec.title.slice(0, 120)}".`,
    ...(trustedOracleEvents.length ? { oracleEvents: trustedOracleEvents } : {}),
    ...('proofPatterns' in input.spec && Array.isArray(input.spec.proofPatterns) && input.spec.proofPatterns.length
      ? { proofPatterns: input.spec.proofPatterns as string[] }
      : {}),
    ...('requiredRole' in input.spec && input.spec.requiredRole ? { requiredRole: input.spec.requiredRole } : {}),
    ...('resourceTenant' in input.spec && input.spec.resourceTenant ? { resourceTenant: input.spec.resourceTenant } : {}),
    ...('expectControlDenied' in input.spec && input.spec.expectControlDenied ? { expectControlDenied: true } : {}),
  }
  const transcript: ReceiptTranscript = { entries }
  return { receipt: receipt as ProofReceipt, transcript, factLog: HostFactLog.fromTranscript(transcript), trustedOracleEvents }
}

/**
 * Apply the receipt to a verdict. Shadow mode only annotates; strict mode can only downgrade a
 * confirmation (never promote one), so precision is monotonic.
 */
export function applyReceiptGate(input: {
  mode: ProofReceiptMode
  verdict: ReplayVerdict
  outcome: ReplayAssertionOutcome
  receipt: ProofReceipt
  verification: ReceiptVerification
}): { verdict: ReplayVerdict; outcome: ReplayAssertionOutcome; check?: ReplayReceiptCheck } {
  if (input.mode === 'off') return { verdict: input.verdict, outcome: input.outcome }
  const check: ReplayReceiptCheck = { receipt: input.receipt, verification: input.verification, mode: input.mode }
  if (input.mode === 'strict' && input.verdict === 'confirmed' && !input.verification.confirmed) {
    return {
      verdict: 'inconclusive',
      outcome: {
        ...input.outcome,
        confirmed: false,
        reason: `ProofReceipt rejected the confirmation: ${input.verification.reason}`.slice(0, 1200),
      },
      check,
    }
  }
  return { verdict: input.verdict, outcome: input.outcome, check }
}

/**
 * Explicit, bounded allowlist of host-persisted deterministic floor spec kinds that do not yet
 * construct a dedicated ProofReceipt. Untrusted/inline specs and all other kinds (including
 * `http_chain`, `sql_*`, `browser_chain`, `race_burst`, `rce_proof`, `agent_script`) ALWAYS fail
 * closed in strict mode when no ProofReceipt can be built.
 */
export const RECEIPT_EXEMPT_HOST_SPEC_KINDS: ReadonlySet<DeclarativeReplaySpec['kind']> = new Set([
  'cache_differential',
  'auth_protocol_proof',
  'upload_probe',
  'ws_chain',
])

export function isReceiptExemptHostSpec(
  spec: Pick<DeclarativeReplaySpec, 'kind'>,
  envelopeTrust?: 'host_persisted' | 'untrusted',
): boolean {
  return envelopeTrust === 'host_persisted' && RECEIPT_EXEMPT_HOST_SPEC_KINDS.has(spec.kind)
}

export function receiptCheckForResult(input: {
  mode: ProofReceiptMode
  verdict: ReplayVerdict
  outcome: ReplayAssertionOutcome
  spec: DeclarativeReplaySpec
  evidencePayload: Record<string, unknown>
  exchangeIds: readonly string[]
  exchanges: readonly BrokerExchangeResult[]
  envelopeTrust?: 'host_persisted' | 'untrusted'
  canaryBroker?: Pick<CanaryBroker, 'checkCanary'>
  canaryRunId?: string
  canaryStorage?: Store
}): { verdict: ReplayVerdict; outcome: ReplayAssertionOutcome; check?: ReplayReceiptCheck } {
  if (input.mode === 'off' || input.verdict !== 'confirmed') return { verdict: input.verdict, outcome: input.outcome }
  // Floor-path intermediate job/handle stub guard: even before receipt construction (or on exempt
  // host-persisted kinds), a pure job/handle/ack stub chain with no substantive post-probe readback
  // never confirms in strict mode.
  if (input.mode === 'strict' && (input.spec.kind === 'http_chain' || input.spec.kind === 'auth_protocol_proof')) {
    const stepsOut = (input.evidencePayload.steps ?? {}) as Record<string, unknown>
    const floorSteps = impactStepsFromStepsOut(input.spec, stepsOut)
    const specClass = receiptVulnClassFor(input.spec)
    const isStubGuardedClass = specClass === null ||
      (specClass !== 'ssrf' && specClass !== 'xxe' && specClass !== 'injection' &&
        specClass !== 'open_redirect' && specClass !== 'webhook_forgery' &&
        !specClass.startsWith('xss') && !specClass.startsWith('dom_'))
    if (isStubGuardedClass && isPureJobOrHandleStubChain(floorSteps)) {
      return {
        verdict: 'inconclusive',
        outcome: {
          ...input.outcome,
          confirmed: false,
          reason: 'terminal_impact_unproven: floor probe returned only an intermediate job/handle/ack stub without substantive post-probe terminal impact.',
        },
      }
    }
  }
  const built = buildReplayReceipt({
    spec: input.spec,
    evidencePayload: input.evidencePayload,
    exchangeIds: input.exchangeIds,
    exchanges: input.exchanges,
    ...(input.canaryBroker ? { canaryBroker: input.canaryBroker } : {}),
    ...(input.canaryRunId ? { canaryRunId: input.canaryRunId } : {}),
    ...(input.canaryStorage ? { canaryStorage: input.canaryStorage } : {}),
  })
  // Fail closed in strict mode whenever a confirmed replay cannot construct a host-verified ProofReceipt,
  // preserving only the explicit host-persisted allowlist (`RECEIPT_EXEMPT_HOST_SPEC_KINDS`).
  if (!built) {
    if (input.mode === 'strict' && !isReceiptExemptHostSpec(input.spec, input.envelopeTrust)) {
      return {
        verdict: 'inconclusive',
        outcome: {
          ...input.outcome,
          confirmed: false,
          reason: 'ProofReceipt could not be built from host-recorded replay exchanges (fail-closed strict mode).',
        },
      }
    }
    return { verdict: input.verdict, outcome: input.outcome }
  }
  const strictHostDerivation = input.envelopeTrust !== 'host_persisted'
  const oracleRes = defaultTerminalOracleRegistry.evaluate(
    built.factLog,
    { kind: 'single_hop', receipt: built.receipt },
    {
      // H-6 / R2-H-9: Enforce strictHostDerivation on untrusted/inline specs and NEVER pass
      // spec-derived trustedOracleEvents under strict host derivation.
      strictHostDerivation,
      ...(!strictHostDerivation && built.trustedOracleEvents.length ? { trustedOracleEvents: built.trustedOracleEvents } : {}),
    },
  )
  const verification: ReceiptVerification = oracleRes.singleHop ?? {
    confirmed: oracleRes.confirmed,
    vulnClass: built.receipt.vulnClass,
    rule: 'none',
    reason: oracleRes.reason,
    observed: built.receipt.claimedDelta,
    expected: 'host-custody verified floor receipt',
  }
  return applyReceiptGate({
    mode: input.mode,
    verdict: input.verdict,
    outcome: input.outcome,
    receipt: built.receipt,
    verification,
  })
}
