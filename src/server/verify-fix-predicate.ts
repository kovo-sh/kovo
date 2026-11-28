/**
 * Track A3 — 0-LLM `Verify Fix` predicate compiler.
 *
 * A confirmed Tier-1 receipt (or a Tier-2 confirmation backed by a host-verified refusal control)
 * is compiled into a secret-free, canonical-hashed predicate derived strictly from the host-signed
 * transcript. Retest replays the compiled steps through the `RequestBroker` (host-injected persona
 * credentials), signs the fresh transcript, gates it with `assessRetestHealth`, and re-runs the
 * SAME universal primitive. `fixed` requires a healthy retest whose probe is cleanly refused;
 * every tampered / unsigned / drifted / ambiguous retest is `inconclusive`, never `fixed`.
 */
import { randomBytes } from 'node:crypto'
import { z } from 'zod'
import type { HttpMethod } from '../domain.ts'
import type { BrokerExchangeResult, BrokerHttpRequest } from './broker.ts'
import { sha256Hex, signHostRecord, verifyHostRecordSignature, type CompositeProofReceipt, type HostSignedTranscript, type HostTranscriptEntry } from './composite-receipt.ts'
import type { ImpactStep } from './oracle-invariants.ts'
import type { PolicyJudgeDecision } from './policy-judge.ts'
import type { ProofReceipt } from './proof-receipt.ts'
import type { RetestVerdict, VerifyReplaySpecParams } from './replay-verifier.ts'
import { assessRetestHealth, type RetestArmObservation, type RetestHealthAssessment } from './retest-health.ts'
import { UNIVERSAL_EVIDENCE_PRIMITIVES, evaluateUniversalPrimitive, resolveUniversalPrimitive, type HostSignedRecord, type UniversalEvidencePrimitive, type UniversalPrimitiveDecision, type UniversalPrimitiveInputMap } from './v8-oracle-families.ts'

const STEP_ROLES = ['setup', 'control', 'probe', 'readback', 'prime', 'refusal_control'] as const
export type CompiledVerifyFixStepRole = (typeof STEP_ROLES)[number]
const DEFAULT_PATCHED_STATUSES = [400, 401, 403, 404, 409, 422] as const
const SERIAL_PATCHED_STATUSES = [400, 409, 422] as const
const ACCESS_AUTH_PATCHED_STATUSES = [403, 404] as const
const ACCESS_UNAUTH_PATCHED_STATUSES = [401, 403, 404] as const
/** Non-secret request headers that may be replayed; credentials are always host-injected by persona. */
const REPLAYABLE_HEADER_RE = /^(?:accept|accept-language|content-type|x-requested-with|if-match|if-none-match|x-http-method-override|origin|referer)$/i
const SECRET_KEY_RE = /authorization|cookie|api[-_]?key|token|secret|session|csrf|xsrf|signature|password|passwd|credential|bearer|jwt|private[-_]?key/i
const SECRET_VALUE_RE = /\b(?:bearer|basic)\s+\S{8,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}/i

export type VerifyFixJsonValue = string | number | boolean | null | VerifyFixJsonValue[] | { [key: string]: VerifyFixJsonValue }
const jsonValueSchema: z.ZodType<VerifyFixJsonValue> = z.lazy(() => z.union([z.string(), z.number(), z.boolean(), z.null(), z.array(jsonValueSchema), z.record(z.string(), jsonValueSchema)]))
const stepIdSchema = z.string().min(1).max(128)
/** Non-secret structural expectations needed to rebuild the `evaluateUniversalPrimitive` call. */
const primitiveConfigSchema = z.object({
  controlStepId: stepIdSchema, variantStepId: stepIdSchema, readbackStepId: stepIdSchema, primeStepId: stepIdSchema, probeStepId: stepIdSchema,
  baselineReadbackStepId: stepIdSchema, finalReadbackStepId: stepIdSchema, actionStepIds: z.array(stepIdSchema).max(32),
  quantitySelector: z.string().max(256), authorizedDelta: z.number(), structuralOnly: z.boolean(), property: z.string().max(64),
  refusalControlKind: z.enum(['serial_4xx', 'clean_session_403', 'boundary_flip_403_200']),
}).partial()
const compiledStepSchema = z.object({
  id: z.string().min(1).max(128),
  role: z.enum(STEP_ROLES),
  method: z.string().regex(/^[A-Z]{3,10}$/),
  origin: z.string().min(1).max(512),
  pathAndQuery: z.string().min(1).max(4096),
  actorPersona: z.string().max(128).nullable(),
  headers: z.record(z.string(), z.string().max(1024)),
  requestJson: jsonValueSchema.optional(),
  baselineStatus: z.number().int().nullable(),
  expectDenied: z.boolean(),
  allowDenied: z.boolean(),
})
const compiledVerifyFixPredicateSchema = z.object({
  version: z.literal(1),
  predicateSha256: z.string().regex(/^[0-9a-f]{64}$/),
  sourceKind: z.enum(['tier1_primitive', 'tier2_refusal_control']),
  primitive: z.enum(UNIVERSAL_EVIDENCE_PRIMITIVES),
  vulnClass: z.string().min(1).max(128),
  stepRoles: z.record(z.string(), z.enum(STEP_ROLES)),
  steps: z.array(compiledStepSchema).min(2).max(32),
  expectedPatchedStatuses: z.array(z.number().int().min(100).max(599)).min(1).max(16),
  primitiveConfig: primitiveConfigSchema.optional(),
})
export type CompiledVerifyFixStep = z.output<typeof compiledStepSchema>
export type CompiledVerifyFixPredicate = z.output<typeof compiledVerifyFixPredicateSchema>

export interface VerifyFixCompileDecision {
  confirmed: boolean
  vulnClass?: string
  /** Host signing key of the confirming session; every cited exchange must verify against it. */
  signingKey: string
  /** Tier-1 terminal evidence (`quantitySelector`, `ceiling`, `property`, ...). */
  evidence?: Record<string, unknown>
  policyJudgeDecision?: PolicyJudgeDecision
}

export interface VerifyFixEvaluation {
  verdict: RetestVerdict
  reason: string
  predicateSha256: string
  health: RetestHealthAssessment | null
  primitiveDecision?: UniversalPrimitiveDecision
}

/* ───────────────────────────── Compilation ───────────────────────────── */

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  return `{${Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`
}
const predicateDigest = (p: Omit<CompiledVerifyFixPredicate, 'predicateSha256'>): string => sha256Hex(canonical(p))

function safeHeaders(raw: Readonly<Record<string, string>> | null | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, rawVal] of Object.entries(raw ?? {})) {
    if (!REPLAYABLE_HEADER_RE.test(k) || SECRET_KEY_RE.test(k)) continue
    const lower = k.toLowerCase()
    const val = (lower === 'referer' ? String(rawVal).split(/[?#]/)[0] ?? '' : String(rawVal)).slice(0, 1024)
    if (!val || SECRET_VALUE_RE.test(val)) continue
    out[lower] = val
  }
  return out
}

function hasSecretQuery(pathAndQuery: string): boolean {
  const qIdx = pathAndQuery.indexOf('?')
  if (qIdx < 0) return false
  const params = new URLSearchParams(pathAndQuery.slice(qIdx + 1))
  for (const [k, v] of params) {
    if (SECRET_KEY_RE.test(k) || SECRET_VALUE_RE.test(v)) return true
  }
  return false
}

function hasSecretJson(value: unknown, depth = 0): boolean {
  if (depth > 16 || value === null || value === undefined) return false
  if (typeof value === 'string') return SECRET_VALUE_RE.test(value)
  if (typeof value !== 'object') return false
  if (Array.isArray(value)) return value.some(v => hasSecretJson(v, depth + 1))
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (SECRET_KEY_RE.test(k) || hasSecretJson(v, depth + 1)) return true
  }
  return false
}

function compileStep(entry: HostTranscriptEntry, role: CompiledVerifyFixStepRole): CompiledVerifyFixStep | null {
  const origin = entry.origin?.trim(), pathAndQuery = entry.step.pathAndQuery ?? entry.step.route
  if (!origin || !pathAndQuery || hasSecretQuery(pathAndQuery)) return null
  if (entry.step.requestJson !== undefined && hasSecretJson(entry.step.requestJson)) return null
  const status = typeof entry.step.status === 'number' ? entry.step.status : null
  const denied = status === 401 || status === 403 || status === 404
  return {
    id: entry.exchangeId, role, method: (entry.step.method || 'GET').toUpperCase(), origin, pathAndQuery,
    actorPersona: entry.actorPersona ?? entry.step.actor?.handle ?? null, headers: safeHeaders(entry.step.requestHeaders),
    ...(entry.step.requestJson !== undefined ? { requestJson: JSON.parse(JSON.stringify(entry.step.requestJson)) as VerifyFixJsonValue } : {}),
    baselineStatus: status, expectDenied: (role === 'control' || role === 'refusal_control') && denied, allowDenied: role === 'readback' || role === 'setup' || role === 'prime',
  }
}

function isCompositeReceipt(r: CompositeProofReceipt | ProofReceipt): r is CompositeProofReceipt { return Array.isArray((r as CompositeProofReceipt).hops) }

/** Role assignment over cited exchange IDs (host-signed arm/evidence role wins over receipt position). */
function tier1Roles(receipt: CompositeProofReceipt | ProofReceipt, byId: ReadonlyMap<string, HostTranscriptEntry>): Map<string, CompiledVerifyFixStepRole> {
  const roles = new Map<string, CompiledVerifyFixStepRole>()
  const assign = (id: string, fallback: CompiledVerifyFixStepRole): void => {
    const e = byId.get(id); if (!e || roles.has(id)) return
    const evRole = (e.step.evidenceRole ?? '').toLowerCase()
    roles.set(id, /prime/.test(evRole) ? 'prime' : /readback/.test(evRole) ? 'readback' : /control/.test(evRole) || e.step.arm === 'control' ? 'control' : e.step.arm === 'setup' ? 'setup' : fallback)
  }
  if (isCompositeReceipt(receipt)) {
    receipt.terminalImpact.preChainControlExchangeIds.forEach(id => assign(id, 'control'))
    for (const hop of receipt.hops) hop.exchangeIds.forEach(id => assign(id, hop.hopId === receipt.terminalImpact.terminalHopId ? 'probe' : 'setup'))
    receipt.terminalImpact.postChainReadbackExchangeIds.forEach(id => assign(id, 'readback'))
  } else receipt.exchangeIds.forEach(id => assign(id, 'probe'))
  return roles
}

type PrimitiveConfig = NonNullable<CompiledVerifyFixPredicate['primitiveConfig']>
function tier1PrimitiveConfig(primitive: UniversalEvidencePrimitive, steps: readonly CompiledVerifyFixStep[], evidence: Record<string, unknown> | undefined): PrimitiveConfig | null {
  const first = (role: CompiledVerifyFixStepRole, pred: (s: CompiledVerifyFixStep) => boolean = () => true) => steps.find(s => s.role === role && pred(s))?.id
  const probes = steps.filter(s => s.role === 'probe'), variantStepId = probes[probes.length - 1]?.id
  const controlStepId = first('control', s => s.expectDenied)
  if (primitive === 'access_differential') return controlStepId && variantStepId ? { controlStepId, variantStepId, ...(first('readback') ? { readbackStepId: first('readback') } : {}) } : null
  if (primitive === 'state_delta_and_conservation') {
    const baselineReadbackStepId = first('setup') ?? first('control'), finalReadbackStepId = first('readback')
    if (!baselineReadbackStepId || !finalReadbackStepId || !probes.length) return null
    const sel = typeof evidence?.quantitySelector === 'string' ? evidence.quantitySelector : null, ceiling = typeof evidence?.ceiling === 'number' ? evidence.ceiling : null
    return { baselineReadbackStepId, actionStepIds: probes.map(p => p.id), finalReadbackStepId, ...(sel && ceiling !== null ? { quantitySelector: sel, authorizedDelta: ceiling } : { structuralOnly: true }) }
  }
  if (primitive === 'wire_framing_and_cache_differential') {
    const property = typeof evidence?.property === 'string' ? evidence.property : null
    const primeStepId = first('prime'), cache = property === 'cache_priming'
    if (!property || !variantStepId || !(controlStepId ?? first('control')) || (cache && !primeStepId)) return null
    return { property, controlStepId: controlStepId ?? first('control'), variantStepId, ...(primeStepId ? { primeStepId } : {}) }
  }
  return null // causal_dag / oob witnesses need freshly minted capabilities: legacy replay handles them.
}

function refusalSteps(decision: PolicyJudgeDecision, byId: ReadonlyMap<string, HostTranscriptEntry>): CompiledVerifyFixStep[] | null {
  const rc = decision.verifiedRefusalControl; if (!rc) return null
  const steps = [...rc.controlExchangeIds.map(id => [id, 'refusal_control'] as const), [rc.probeExchangeId, 'probe'] as const].map(([id, role]) => { const e = byId.get(id); return e ? compileStep(e, role) : null })
  return steps.every(Boolean) ? steps as CompiledVerifyFixStep[] : null
}

function finalizePredicate(body: Omit<CompiledVerifyFixPredicate, 'predicateSha256' | 'stepRoles' | 'version'>): CompiledVerifyFixPredicate {
  const payload = { version: 1 as const, ...body, stepRoles: Object.fromEntries(body.steps.map(s => [s.id, s.role])) }
  return compiledVerifyFixPredicateSchema.parse({ ...payload, predicateSha256: predicateDigest(payload) })
}

/**
 * Compile a confirmed verification outcome into a deterministic, secret-free Verify Fix predicate.
 * Returns `null` (legacy replay retest) when the outcome is not confirmed, any cited exchange fails
 * host-signature verification, or the primitive cannot be re-evaluated without fresh capabilities.
 */
function expectedPatchedStatusesFor(
  sourceKind: 'tier1_primitive' | 'tier2_refusal_control',
  primitive: UniversalEvidencePrimitive,
  steps: readonly CompiledVerifyFixStep[],
  refusalKind?: string,
): number[] {
  const probes = steps.filter(s => s.role === 'probe')
  const anyUnauthProbe = probes.some(p => !p.actorPersona)
  if (sourceKind === 'tier2_refusal_control') {
    if (refusalKind === 'serial_4xx') return [...SERIAL_PATCHED_STATUSES]
    return anyUnauthProbe ? [...ACCESS_UNAUTH_PATCHED_STATUSES] : [...ACCESS_AUTH_PATCHED_STATUSES]
  }
  if (primitive === 'access_differential') {
    return anyUnauthProbe ? [...ACCESS_UNAUTH_PATCHED_STATUSES] : [...ACCESS_AUTH_PATCHED_STATUSES]
  }
  return [...DEFAULT_PATCHED_STATUSES]
}

export function compileVerifyFixPredicate(receipt: CompositeProofReceipt | ProofReceipt, transcript: HostSignedTranscript, decision: VerifyFixCompileDecision): CompiledVerifyFixPredicate | null {
  if (!decision.confirmed || !decision.signingKey) return null
  const byId = new Map((transcript.entries ?? []).filter(e => verifyHostRecordSignature(e, decision.signingKey)).map(e => [e.exchangeId, e] as const))
  const vulnClass = (decision.vulnClass ?? (isCompositeReceipt(receipt) ? receipt.terminalVulnClass : receipt.vulnClass)).trim().toLowerCase().slice(0, 128) || 'unknown'
  if (decision.policyJudgeDecision) {
    if (decision.policyJudgeDecision.verdict !== 'confirmed' || !decision.policyJudgeDecision.confirmed || !decision.policyJudgeDecision.signaturesVerified) return null
    const steps = refusalSteps(decision.policyJudgeDecision, byId)
    const rc = decision.policyJudgeDecision.verifiedRefusalControl
    const primitive = resolveUniversalPrimitive(vulnClass)
    return steps && rc
      ? finalizePredicate({ sourceKind: 'tier2_refusal_control', primitive, vulnClass, steps, expectedPatchedStatuses: expectedPatchedStatusesFor('tier2_refusal_control', primitive, steps, rc.kind), primitiveConfig: { refusalControlKind: rc.kind, probeStepId: rc.probeExchangeId } })
      : null
  }
  const roles = tier1Roles(receipt, byId)
  const cited = isCompositeReceipt(receipt) ? [...receipt.hops.flatMap(h => h.exchangeIds), ...receipt.terminalImpact.preChainControlExchangeIds, ...receipt.terminalImpact.postChainReadbackExchangeIds] : receipt.exchangeIds
  if (!cited.length || cited.some(id => !byId.has(id))) return null
  const steps = [...roles.entries()].map(([id, role]) => compileStep(byId.get(id)!, role))
  if (steps.some(s => !s) || steps.length < 2) return null
  const compiledSteps = steps as CompiledVerifyFixStep[]
  const primitive = resolveUniversalPrimitive(vulnClass)
  const primitiveConfig = tier1PrimitiveConfig(primitive, compiledSteps, decision.evidence)
  return primitiveConfig
    ? finalizePredicate({ sourceKind: 'tier1_primitive', primitive, vulnClass, steps: compiledSteps, expectedPatchedStatuses: expectedPatchedStatusesFor('tier1_primitive', primitive, compiledSteps), primitiveConfig })
    : null
}

/** Parse a persisted predicate (from `replay_specs.proof_receipt` JSON); invalid/absent → `null`. */
export function readCompiledVerifyFixPredicate(proofReceipt: unknown): CompiledVerifyFixPredicate | null {
  const raw = proofReceipt && typeof proofReceipt === 'object' ? (proofReceipt as { compiledPredicate?: unknown }).compiledPredicate : undefined
  const parsed = raw ? compiledVerifyFixPredicateSchema.safeParse(raw) : null
  return parsed?.success ? parsed.data : null
}

/* ─────────────────────────────── Evaluation ─────────────────────────────── */

const toRecord = (e: HostTranscriptEntry): HostSignedRecord => ({
  id: e.exchangeId, hostSignature: e.hostSignature ?? '', timestampMs: e.timestampMs ?? 0, status: e.step.status, method: e.step.method,
  route: e.step.route ?? e.step.pathAndQuery, pathAndQuery: e.step.pathAndQuery, actorId: e.actorPersona ?? e.step.actor?.handle ?? null,
  tenantId: e.actorTenant ?? e.step.actor?.tenant ?? null, body: e.step.body, json: e.step.json, requestHeaders: e.step.requestHeaders ?? null, responseHeaders: e.step.responseHeaders ?? null,
})

function armOf(step: CompiledVerifyFixStep, entry: HostTranscriptEntry, refusalKind: unknown): RetestArmObservation {
  const role = step.role === 'refusal_control' && refusalKind === 'serial_4xx' ? 'serial_control_1' : step.role
  return { role, status: typeof entry.step.status === 'number' ? entry.step.status : null, authenticated: Boolean(step.actorPersona), expectDenied: step.expectDenied, allowDenied: step.allowDenied, method: step.method }
}

function assessCompiledHealth(predicate: CompiledVerifyFixPredicate, entryOf: (id: string) => HostTranscriptEntry): RetestHealthAssessment {
  const kind = predicate.primitiveConfig?.refusalControlKind
  const arms = predicate.steps.map(s => ({ step: s, arm: armOf(s, entryOf(s.id), kind) }))
  return assessRetestHealth(
    { deniedRequirePassed: false, setupArms: arms.filter(a => a.step.role === 'setup' || a.step.role === 'prime' || a.step.role === 'readback').map(a => a.arm), controlArms: arms.filter(a => a.step.role === 'control' || a.step.role === 'refusal_control').map(a => a.arm) },
    { arms: arms.filter(a => a.step.role === 'probe').map(a => a.arm) },
    {},
  )
}

function buildPrimitiveInput(predicate: CompiledVerifyFixPredicate, recOf: (id: unknown) => HostSignedRecord | undefined, verifySignature: (r: HostSignedRecord) => boolean): UniversalPrimitiveInputMap[UniversalEvidencePrimitive] | null {
  const c = predicate.primitiveConfig ?? {}
  if (predicate.primitive === 'access_differential') {
    const control = recOf(c.controlStepId), variant = recOf(c.variantStepId)
    if (!control || !variant) return null
    const readback = c.readbackStepId ? recOf(c.readbackStepId) : undefined
    if (c.readbackStepId && !readback) return null
    return { control, variant, ...(readback ? { readback } : {}), bindRoute: true, verifySignature }
  }
  if (predicate.primitive === 'state_delta_and_conservation') {
    const baselineReadback = recOf(c.baselineReadbackStepId), finalReadback = recOf(c.finalReadbackStepId)
    const actionIds = Array.isArray(c.actionStepIds) ? c.actionStepIds : []
    const actions = actionIds.map(recOf).filter((r): r is HostSignedRecord => Boolean(r))
    if (!baselineReadback || !finalReadback || !actions.length || actions.length !== actionIds.length) return null
    return { baselineReadback, actions, finalReadback, ...(typeof c.quantitySelector === 'string' && Number.isFinite(c.authorizedDelta) ? { quantitySelector: c.quantitySelector, authorizedDelta: Number(c.authorizedDelta) } : { structuralOnly: true }), verifySignature }
  }
  if (predicate.primitive === 'wire_framing_and_cache_differential') {
    const control = recOf(c.controlStepId), variant = recOf(c.variantStepId), prime = c.primeStepId ? recOf(c.primeStepId) : undefined
    if (!c.property || !control || !variant || (c.primeStepId && !prime) || (c.property === 'cache_priming' && !prime)) return null
    const step = (id: unknown) => predicate.steps.find(s => s.id === id)
    const wire = (s: CompiledVerifyFixStep | undefined) => s ? sha256Hex(canonical({ p: s.pathAndQuery, h: s.headers, b: s.requestJson ?? null })) : undefined
    return { property: c.property as never, control, variant, ...(prime ? { prime } : {}), controlWireValue: wire(step(c.controlStepId)), variantWireValue: wire(step(c.variantStepId)), isolatedControl: true, verifySignature }
  }
  return null
}

function stepBindingMismatch(step: CompiledVerifyFixStep, entry: HostTranscriptEntry): boolean {
  const entryOrigin = (entry.origin ?? '').trim()
  const entryMethod = (entry.step.method || '').trim().toUpperCase()
  const entryPath = entry.step.pathAndQuery ?? entry.step.route ?? ''
  const entryActor = entry.actorPersona ?? entry.step.actor?.handle ?? null
  return entryOrigin !== step.origin || entryMethod !== step.method || entryPath !== step.pathAndQuery || entryActor !== step.actorPersona
}

function validatePredicateIntegrity(predicate: CompiledVerifyFixPredicate): string | null {
  const parsed = compiledVerifyFixPredicateSchema.safeParse(predicate)
  if (!parsed.success) return 'predicate_schema_invalid'
  const { predicateSha256: claimed, ...payload } = parsed.data
  return predicateDigest(payload) === claimed ? null : 'predicate_integrity_mismatch'
}

/**
 * 0-LLM deterministic retest over a host-signed retest transcript. Integrity (predicate digest +
 * every entry signature), step binding, and `assessRetestHealth` gate BEFORE any primitive runs;
 * only a healthy retest whose probe arms are refused with an `expectedPatchedStatuses` status is `fixed`.
 */
export function evaluateCompiledVerifyFixPredicate(predicate: CompiledVerifyFixPredicate, retestTranscript: HostSignedTranscript, signingKey: string): VerifyFixEvaluation {
  const predicateSha256 = typeof predicate?.predicateSha256 === 'string' ? predicate.predicateSha256 : ''
  const inconclusive = (reason: string, health: RetestHealthAssessment | null = null, primitiveDecision?: UniversalPrimitiveDecision): VerifyFixEvaluation => ({ verdict: 'inconclusive', reason, predicateSha256, health, ...(primitiveDecision ? { primitiveDecision } : {}) })
  const integrityErr = validatePredicateIntegrity(predicate)
  if (integrityErr) return inconclusive(integrityErr)
  const entries = retestTranscript?.entries ?? []
  if (!signingKey || entries.some(e => !verifyHostRecordSignature(e, signingKey))) return inconclusive('retest_transcript_signature_invalid')
  const byStep = new Map(entries.map(e => [e.step.id, e] as const))
  const missing = predicate.steps.find(s => !byStep.has(s.id))
  if (missing) return inconclusive(`retest_step_missing:${missing.role}`)
  const entryOf = (id: string): HostTranscriptEntry => byStep.get(id)!
  const unbound = predicate.steps.find(s => stepBindingMismatch(s, entryOf(s.id)))
  if (unbound) return inconclusive(`retest_step_binding_mismatch:${unbound.role}`)
  const health = assessCompiledHealth(predicate, entryOf)
  if (!health.healthy) return inconclusive(health.reason ?? health.code, health)
  const probes = predicate.steps.filter(s => s.role === 'probe').map(s => entryOf(s.id).step.status)
  const probeBypassed = probes.some(s => typeof s === 'number' && s >= 200 && s < 300)
  const probeRefused = probes.length > 0 && probes.every(s => typeof s === 'number' && predicate.expectedPatchedStatuses.includes(s))
  if (predicate.sourceKind === 'tier2_refusal_control') {
    if (predicate.primitiveConfig?.refusalControlKind === 'serial_4xx') {
      const serialControls = predicate.steps.filter(s => s.role === 'refusal_control').map(s => entryOf(s.id).step.status)
      if (!serialControls.length || !serialControls.every(s => s === 400 || s === 409)) return inconclusive('serial_control_not_refused', health)
    }
    return probeBypassed ? { verdict: 'reproduced', reason: 'refusal_boundary_still_bypassed', predicateSha256, health }
      : probeRefused ? { verdict: 'fixed', reason: 'refusal_boundary_enforced_on_probe', predicateSha256, health } : inconclusive('refusal_boundary_ambiguous', health)
  }
  const recs = new Map(predicate.steps.map(s => [s.id, toRecord(entryOf(s.id))] as const))
  const recOf = (id: unknown): HostSignedRecord | undefined => (typeof id === 'string' ? recs.get(id) : undefined)
  const input = buildPrimitiveInput(predicate, recOf, r => { const e = entries.find(x => x.exchangeId === r.id); return Boolean(e && verifyHostRecordSignature(e, signingKey)) })
  if (!input) return inconclusive('primitive_not_retestable', health)
  const primitiveDecision = evaluateUniversalPrimitive(predicate.primitive, input)
  if (primitiveDecision.satisfied) return { verdict: 'reproduced', reason: `primitive_still_confirms:${primitiveDecision.reason}`, predicateSha256, health, primitiveDecision }
  return probeRefused ? { verdict: 'fixed', reason: `primitive_mitigated:${primitiveDecision.reason}`, predicateSha256, health, primitiveDecision } : inconclusive(`primitive_shape_drift:${primitiveDecision.reason}`, health, primitiveDecision)
}

/* ─────────────────────────────── Execution ─────────────────────────────── */

export interface CompiledVerifyFixRetestResult {
  verdict: RetestVerdict
  evaluation: VerifyFixEvaluation
  replay: { outcome: { observed: string; expected: string; reason: string; predicateSha256: string; healthCode: string | null }; exchangeIds: string[]; evidenceSha256: string }
}

async function replayCompiledStep(step: CompiledVerifyFixStep, params: Pick<VerifyReplaySpecParams, 'broker' | 'grant' | 'signal' | 'runId' | 'assignmentId'>): Promise<BrokerExchangeResult | null> {
  const req: BrokerHttpRequest = {
    origin: step.origin, method: step.method as HttpMethod, pathAndQuery: step.pathAndQuery, headers: { ...step.headers },
    ...(step.requestJson !== undefined ? { body: JSON.stringify(step.requestJson), headers: { 'content-type': 'application/json', ...step.headers } } : {}),
    ...(step.actorPersona ? { persona: step.actorPersona } : {}),
    sessionGroupRole: step.role === 'probe' ? 'probe' : step.role === 'setup' || step.role === 'prime' ? 'setup' : 'control',
    ...(params.runId ? { runId: params.runId } : {}), ...(params.assignmentId ? { assignmentId: params.assignmentId } : {}),
  }
  try { return await params.broker.executeHttp(req, params.grant, params.signal) } catch (err) { if (params.signal.aborted) throw err; return null }
}

function retestEntry(step: CompiledVerifyFixStep, ex: BrokerExchangeResult | null, exchangeId: string, signingKey: string): HostTranscriptEntry {
  let json: unknown
  if (ex?.body && /json/i.test(ex.mediaType)) { try { json = JSON.parse(ex.body) } catch { json = undefined } }
  const arm: ImpactStep['arm'] = step.role === 'probe' ? 'probe' : step.role === 'setup' || step.role === 'prime' ? 'setup' : 'control'
  const base: HostTranscriptEntry = {
    exchangeId, origin: step.origin, timestampMs: Date.now(), actorPersona: step.actorPersona,
    step: { id: step.id, arm, method: step.method, pathAndQuery: step.pathAndQuery, status: ex ? ex.status : null, actor: { handle: step.actorPersona, role: null, tenant: null, auth: 'unknown', sameSite: null }, ...(json !== undefined ? { json } : {}), ...(ex ? { body: ex.body, responseHeaders: ex.respHeaders } : {}), ...(step.requestJson !== undefined ? { requestJson: step.requestJson } : {}) },
  }
  return { ...base, hostSignature: signHostRecord(base, signingKey) }
}

/** Replay a compiled predicate through the broker (host-injected personas), sign, and evaluate (0-LLM). */
export async function executeCompiledVerifyFixPredicate(predicate: CompiledVerifyFixPredicate, params: Pick<VerifyReplaySpecParams, 'broker' | 'grant' | 'signal' | 'runId' | 'assignmentId' | 'onExchange'>): Promise<CompiledVerifyFixRetestResult> {
  const integrityErr = validatePredicateIntegrity(predicate)
  if (integrityErr) {
    const sha = typeof predicate?.predicateSha256 === 'string' ? predicate.predicateSha256 : ''
    const evaluation: VerifyFixEvaluation = { verdict: 'inconclusive', reason: integrityErr, predicateSha256: sha, health: null }
    return {
      verdict: 'inconclusive', evaluation,
      replay: { outcome: { observed: `0-LLM compiled predicate rejected before replay: ${integrityErr}`, expected: 'valid predicate digest prior to replay', reason: integrityErr, predicateSha256: sha, healthCode: null }, exchangeIds: [], evidenceSha256: sha256Hex(integrityErr) },
    }
  }
  const signingKey = randomBytes(32).toString('hex'), entries: HostTranscriptEntry[] = [], exchangeIds: string[] = []
  for (const [i, step] of predicate.steps.entries()) {
    const ex = await replayCompiledStep(step, params)
    const recorded = ex ? params.onExchange?.(ex) : undefined
    if (typeof recorded === 'string' && recorded) exchangeIds.push(recorded)
    entries.push(retestEntry(step, ex, typeof recorded === 'string' && recorded ? recorded : `vf-${predicate.predicateSha256.slice(0, 12)}-${i}`, signingKey))
  }
  const evaluation = evaluateCompiledVerifyFixPredicate(predicate, { entries }, signingKey)
  const observed = `0-LLM compiled predicate (${predicate.sourceKind}/${predicate.primitive}): ${evaluation.reason}; statuses ${entries.map(e => `${e.step.id.slice(0, 12)}=${e.step.status ?? 'none'}`).join(', ')}`
  return {
    verdict: evaluation.verdict, evaluation,
    replay: { outcome: { observed, expected: `probe refused with one of ${predicate.expectedPatchedStatuses.join('/')} while control arms stay healthy`, reason: evaluation.reason, predicateSha256: predicate.predicateSha256, healthCode: evaluation.health?.code ?? null }, exchangeIds, evidenceSha256: sha256Hex(canonical(entries.map(e => ({ id: e.step.id, status: e.step.status, sig: e.hostSignature })))) },
  }
}
