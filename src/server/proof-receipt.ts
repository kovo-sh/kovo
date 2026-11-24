/**
 * ProofReceipt — the single confirmation primitive.
 *
 * A finding is `runtime_confirmed` only when a receipt names the vulnerability class, the exact
 * target, the host-recorded exchanges/Signed OOB events that carry the proof, and the behavioural
 * delta it claims. `verifyReceipt()` re-derives that claim from the transcript with the shared
 * `oracle-invariants` model in-process (~1 ms): it never trusts a model-authored summary, a
 * declarative spec, nor a receipt field by itself.
 *
 * The receipt is deliberately transport-agnostic. The floor replays (HTTP), the async path
 * promotes a durable `pending_oob` callback, and the browser path records traces — all three
 * produce the same artifact, so promotion, patch retest, and reporting share one confirmation
 * path instead of three.
 */
import { z } from 'zod'
import { scopedAssetOrigin } from '../domain.ts'
import {
  assessBooleanDifferential,
  assessImpactEvidence,
  assessInjectionImpact,
  assessStatusOnlyDivergence,
  knownOracleEvent,
  routeFamily,
  stepMutatesState,
} from './oracle-invariants.ts'
import type { BooleanDifferentialArm, BooleanDifferentialRound, ImpactClass, ImpactInput, ImpactStep, RoleName } from './oracle-invariants.ts'

export const receiptIdSchema = z.string().trim().min(1).max(128)

export const proofReceiptSchema = z.object({
  /** Machine-readable class (bola, ssrf, xxe, blind_sqli, xss_stored, ...). */
  vulnClass: z.string().trim().min(1).max(64),
  target: z.object({
    origin: scopedAssetOrigin,
    method: z.string().trim().regex(/^[A-Z]{1,10}$/).optional(),
    pathAndQuery: z.string().trim().min(1).max(4096).optional(),
    param: z.string().trim().min(1).max(128).optional(),
  }),
  exchangeIds: z.array(receiptIdSchema).max(32).default([]),
  oobEventIds: z.array(receiptIdSchema).max(16).default([]),
  browserTraceIds: z.array(receiptIdSchema).max(16).default([]),
  claimedDelta: z.string().trim().min(1).max(1200),
  /** Declared impact-oracle events, checked against the known set (never evidence by itself). */
  oracleEvents: z.array(z.string().trim().min(1).max(48)).max(8).optional(),
  requiredRole: z.enum(['viewer', 'member', 'admin', 'owner']).optional(),
  resourceTenant: z.string().trim().min(1).max(64).optional(),
  expectControlDenied: z.boolean().optional(),
  /** Non-secret credential value shapes asserted by the proof (re-tested against the bodies). */
  proofPatterns: z.array(z.string().trim().min(4).max(200)).max(4).optional(),
  /** When the injected value reached the target; a callback before this is not causal. */
  injectedAtMs: z.number().int().nonnegative().optional(),
})
export type ProofReceipt = z.output<typeof proofReceiptSchema>

/** One host-recorded exchange, already mapped onto the shared impact model. */
export interface ReceiptTranscriptEntry {
  exchangeId: string
  step: ImpactStep
  /** Wall-clock duration of the exchange (timing-differential receipts). */
  durationMs?: number
  /**
   * Text the target actually received (path, request headers, body). Used only to prove the
   * injected canary token reached the target — never to re-run a request.
   */
  carrierText?: string
  /**
   * Evidence role the recipe asked the exchange to fill (`benign_baseline`, `tautology`,
   * `contradiction`, `denied_control`, ...). The status-differential rule uses it to pair arms;
   * without it the rule falls back to inferring the triangle from status and request shape.
   */
  evidenceRole?: string
}

/** One durable OOB delivery promoted by the relay (host-observed, not model-supplied). */
export interface ReceiptOobEvent {
  /** Durable `pending_oob` subscription id. */
  id: string
  callbackId?: string
  canaryId?: string
  token?: string
  targetOrigin?: string | null
  delivered: boolean
  stage?: 'immediate' | 'late'
  receivedAtMs: number
  injectedAtMs?: number
  latencyMs?: number
}

export interface ReceiptBrowserTrace {
  id: string
  origin: string
  /** Observed sink/behaviour names (dom_xss, postmessage, storage_write, ...). */
  sinks?: readonly string[]
}

export interface ReceiptTranscript {
  entries?: readonly ReceiptTranscriptEntry[]
  oobEvents?: readonly ReceiptOobEvent[]
  browserTraces?: readonly ReceiptBrowserTrace[]
}

export interface ReceiptVerification {
  confirmed: boolean
  vulnClass: string
  /** Rule family used to validate the receipt. */
  rule: 'impact' | 'oob' | 'timing' | 'boolean' | 'status_differential' | 'browser' | 'redirect' | 'none'
  reason: string
  observed: string
  expected: string
  evidence?: Record<string, unknown>
}

const OOB_CLASS_RE = /^(?:ssrf|xxe|blind_ssrf|blind_xxe|oob|webhook_forgery)$/i
const TIMING_CLASS_RE = /^(?:blind_sqli|sqli_time|sql_time|timing|race)$/i
const BOOLEAN_CLASS_RE = /^(?:sqli|sql_boolean|sql_boolean_diff|boolean_sqli|boolean_differential)$/i
/**
 * The paired status-boolean shape: a benign 2xx baseline, a 2xx tautology arm and a <500
 * contradiction arm on the same request shape. This is deliberately a separate class from `sqli`
 * (which selects the structural differential rule) so a caller can never obtain the weaker status
 * rule by accident.
 */
const STATUS_DIFF_CLASS_RE = /^(?:sqli_status|sql_status|sql_status_diff|status_sqli|status_boolean)$/i
const REDIRECT_CLASS_RE = /^(?:open_redirect|redirect|url_redirect|unvalidated_redirect)$/i

const IMPACT_CLASS_BY_VULN: Readonly<Record<string, ImpactClass>> = {
  bola: 'authorization',
  idor: 'authorization',
  authorization: 'authorization',
  'broken-access-control': 'authorization',
  access_control: 'authorization',
  cross_tenant: 'authorization',
  cross_tenant_read: 'authorization',
  cross_tenant_write: 'authorization',
  bfla: 'bfla',
  privilege_escalation: 'bfla',
  mass_assignment: 'mass_assignment',
  csrf: 'csrf',
  business_logic: 'business_logic',
  invariant_violation: 'business_logic',
  workflow_skip: 'business_logic',
  xss: 'markup',
  xss_stored: 'markup',
  xss_reflected: 'markup',
  markup: 'markup',
  html_injection: 'markup',
  disclosure: 'disclosure',
  info_disclosure: 'disclosure',
  secret_disclosed: 'disclosure',
  // Injection family: the oracle needs an engine fingerprint, a paired boolean/timing arm or OOB
  // evidence. A bare 2xx -> 4xx/5xx transition is rejected like every other class.
  injection: 'injection',
  'injection-input': 'injection',
  injection_input: 'injection',
  nosqli: 'injection',
  nosql_injection: 'injection',
  ssti: 'injection',
  template_injection: 'injection',
  command_injection: 'injection',
  cmdi: 'injection',
  path_traversal: 'injection',
  directory_traversal: 'injection',
}

/** Classify a receipt's vulnerability label into the shared impact model (or a non-impact rule). */
export function receiptRuleFor(vulnClass: string): { rule: ReceiptVerification['rule']; impactClass?: ImpactClass } {
  if (OOB_CLASS_RE.test(vulnClass)) return { rule: 'oob' }
  if (STATUS_DIFF_CLASS_RE.test(vulnClass)) return { rule: 'status_differential' }
  if (BOOLEAN_CLASS_RE.test(vulnClass)) return { rule: 'boolean' }
  if (TIMING_CLASS_RE.test(vulnClass)) return { rule: 'timing' }
  if (REDIRECT_CLASS_RE.test(vulnClass)) return { rule: 'redirect' }
  const impactClass = IMPACT_CLASS_BY_VULN[vulnClass.toLowerCase()]
  if (impactClass) return { rule: 'impact', impactClass }
  if (/^browser_|^dom_|^postmessage/i.test(vulnClass)) return { rule: 'browser' }
  return { rule: 'none' }
}

function reject(receipt: ProofReceipt, rule: ReceiptVerification['rule'], reason: string): ReceiptVerification {
  return {
    confirmed: false,
    vulnClass: receipt.vulnClass,
    rule,
    reason,
    observed: receipt.claimedDelta,
    expected: 'host-recorded evidence that substantiates the claimed delta',
  }
}

function normalizePath(value: string | undefined): string {
  return (value ?? '').split('?')[0].split('#')[0].replace(/\/+$/, '').toLowerCase()
}

function routeOf(step: ImpactStep): string {
  return normalizePath(step.route ?? step.pathAndQuery ?? '')
}

function headerValue(headers: Record<string, string> | null | undefined, name: string): string | null {
  if (!headers) return null
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name.toLowerCase() && typeof value === 'string' && value.length > 0) return value
  }
  return null
}

function locationOf(step: ImpactStep): string | null {
  return headerValue(step.responseHeaders, 'location')
}

function hostOf(value: string | null, base?: string | null): string | null {
  if (!value) return null
  try { return new URL(value, base ?? 'http://guardian.invalid').host.toLowerCase() } catch { return null }
}

/**
 * Validate one receipt against the transcript. A receipt with a missing exchange, a missing OOB
 * event, a mismatched target, or an impact claim the oracle model cannot substantiate is rejected —
 * there is no "trust me" branch.
 */
export function verifyReceipt(rawReceipt: unknown, transcript: ReceiptTranscript): ReceiptVerification {
  const parsed = proofReceiptSchema.safeParse(rawReceipt)
  if (!parsed.success) {
    const issue = parsed.error.issues[0]
    return {
      confirmed: false,
      vulnClass: 'invalid',
      rule: 'none',
      reason: `Receipt failed schema validation: ${issue?.path.join('.') || 'receipt'} ${issue?.message ?? ''}`.slice(0, 400),
      observed: 'invalid receipt',
      expected: 'a well-formed ProofReceipt',
    }
  }
  const receipt = parsed.data
  const { rule, impactClass } = receiptRuleFor(receipt.vulnClass)
  if (rule === 'none') {
    return reject(receipt, rule, `No confirmation rule for vulnerability class "${receipt.vulnClass}".`)
  }

  const entries = transcript.entries ?? []
  const entriesById = new Map(entries.map(entry => [entry.exchangeId, entry]))
  const oobById = new Map((transcript.oobEvents ?? []).map(event => [event.id, event]))
  const tracesById = new Map((transcript.browserTraces ?? []).map(trace => [trace.id, trace]))

  // Boundary: every id the receipt cites must exist in the host transcript.
  const missingExchange = receipt.exchangeIds.find(id => !entriesById.has(id))
  if (missingExchange) return reject(receipt, rule, `Receipt cites exchange ${missingExchange}, which is absent from the transcript.`)
  const missingOob = receipt.oobEventIds.find(id => !oobById.has(id))
  if (missingOob) return reject(receipt, rule, `Receipt cites OOB event ${missingOob}, which is absent from the transcript.`)
  const missingTrace = receipt.browserTraceIds.find(id => !tracesById.has(id))
  if (missingTrace) return reject(receipt, rule, `Receipt cites browser trace ${missingTrace}, which is absent from the transcript.`)

  if (rule === 'oob') {
    if (receipt.oobEventIds.length === 0) return reject(receipt, rule, 'An out-of-band class needs at least one durable OOB event.')
    const events = receipt.oobEventIds.map(id => oobById.get(id)!)
    for (const event of events) {
      if (!event.delivered) return reject(receipt, rule, `OOB event ${event.id} was not delivered.`)
      if (event.targetOrigin && normalizeOrigin(event.targetOrigin) !== normalizeOrigin(receipt.target.origin)) {
        return reject(receipt, rule, `OOB event ${event.id} belongs to a different target origin.`)
      }
      const injectedAt = receipt.injectedAtMs ?? event.injectedAtMs
      if (injectedAt !== undefined && event.receivedAtMs < injectedAt) {
        return reject(receipt, rule, `OOB event ${event.id} arrived before the canary was injected.`)
      }
      if (!event.token) return reject(receipt, rule, `OOB event ${event.id} does not name the canary token that was delivered.`)
    }
    const token = events.find(event => event.token)!.token!
    // The injection must be visible in the host-recorded request the receipt names; a callback
    // alone proves the relay was reached, not that this target was the one that reached it.
    if (receipt.exchangeIds.length === 0) {
      return reject(receipt, rule, 'An OOB receipt must cite the exchange that carried the injected canary.')
    }
    const carrying = receipt.exchangeIds
      .map(id => entriesById.get(id)!)
      .filter(entry => (entry.carrierText ?? entry.step.body ?? '').includes(token) ||
        stepCarries(entry.step, token))
    if (carrying.length === 0) {
      return reject(receipt, rule, 'None of the cited exchanges carried the delivered canary token.')
    }
    if (receipt.target.method && carrying.every(entry => entry.step.method.toUpperCase() !== receipt.target.method)) {
      return reject(receipt, rule, 'The cited exchange method does not match the receipt target.')
    }
    if (receipt.target.pathAndQuery) {
      const wanted = normalizePath(receipt.target.pathAndQuery)
      if (carrying.every(entry => routeOf(entry.step) !== wanted)) {
        return reject(receipt, rule, 'The cited exchange route does not match the receipt target.')
      }
    }
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: `A durable out-of-band callback for canary ${events[0]!.canaryId ?? events[0]!.id} was delivered ${events[0]!.stage ? `(${events[0]!.stage}) ` : ''}after the injection exchange carried it to the target.`,
      observed: receipt.claimedDelta,
      expected: 'no out-of-band fetch of the injected canary',
      evidence: { exchangeIds: receipt.exchangeIds, oobEventIds: receipt.oobEventIds, latencyMs: events[0]!.latencyMs ?? null },
    }
  }

  if (rule === 'boolean') {
    if (receipt.exchangeIds.length < 4) {
      return reject(receipt, rule, 'A boolean differential needs at least two paired control/probe rounds.')
    }
    const arms = receipt.exchangeIds.map(id => entriesById.get(id)!)
    const controls = arms.filter(arm => arm.step.arm === 'control')
    const probes = arms.filter(arm => arm.step.arm === 'probe')
    if (controls.length !== probes.length || controls.length < 2) {
      return reject(receipt, rule, 'A boolean differential needs an equal number (>=2) of control and probe arms.')
    }
    const param = receipt.target.param ?? deriveDifferingParam(controls[0]!, probes[0]!)
    if (!param) return reject(receipt, rule, 'A boolean differential must name the injected parameter.')
    const toArm = (entry: ReceiptTranscriptEntry): BooleanDifferentialArm => ({
      status: entry.step.status,
      method: entry.step.method,
      pathAndQuery: entry.step.pathAndQuery,
      ...(entry.step.requestJson !== undefined ? { requestJson: entry.step.requestJson } : {}),
      requestHeaders: entry.step.requestHeaders ?? null,
      ...(entry.step.json !== undefined ? { json: entry.step.json } : {}),
      ...(entry.step.body !== undefined ? { body: entry.step.body } : {}),
    })
    const rounds: BooleanDifferentialRound[] = controls.map((control, index) => ({
      control: toArm(control),
      probe: toArm(probes[index]!),
    }))
    const assessment = assessBooleanDifferential({ rounds, param })
    if (!assessment.satisfied) {
      return {
        confirmed: false,
        vulnClass: receipt.vulnClass,
        rule,
        reason: assessment.reason,
        observed: receipt.claimedDelta,
        expected: 'a stable structural response difference between the two predicates',
        evidence: assessment.evidence,
      }
    }
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: assessment.reason,
      observed: receipt.claimedDelta,
      expected: 'identical responses for equivalent boolean predicates',
      evidence: assessment.evidence,
    }
  }

  if (rule === 'status_differential') {
    const arms = receipt.exchangeIds.map(id => entriesById.get(id)!.step)
    const triangle = statusDifferentialRounds(arms)
    if (!triangle) {
      return reject(receipt, rule, 'A status differential needs a benign 2xx baseline, a 2xx tautology arm and a <500 contradiction arm on the same request shape, in every round.')
    }
    if (triangle.rounds.length < 2) {
      return reject(receipt, rule, 'A status differential needs at least two complete benign/tautology/contradiction rounds.')
    }
    for (const [index, round] of triangle.rounds.entries()) {
      const assessment = assessInjectionImpact({
        impactClass: 'injection',
        steps: [round.benign, round.tautology, round.contradiction],
        injection: { family: 'sqli', statusBoolean: round },
      })
      if (!assessment.satisfied) {
        return {
          confirmed: false,
          vulnClass: receipt.vulnClass,
          rule,
          reason: `Status differential round ${index + 1} was rejected: ${assessment.reason}`,
          observed: receipt.claimedDelta,
          expected: 'a benign 2xx baseline and a tautology-vs-contradiction predicate contrast',
          evidence: assessment.evidence,
        }
      }
    }
    const stable = new Set(triangle.rounds.map(round => `${round.tautology.status}/${round.contradiction.status}`)).size === 1
    if (!stable) {
      return reject(receipt, rule, 'The tautology/contradiction status pair was unstable across rounds; a status differential must reproduce identically.')
    }
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: `Paired status-only boolean exception reproduced across ${triangle.rounds.length} rounds: the benign baseline (${triangle.rounds[0]!.benign.status}) and tautology arm (${triangle.rounds[0]!.tautology.status}) are 2xx while the contradiction arm fails (${triangle.rounds[0]!.contradiction.status}) on the same request shape. A single malformed request that turns 200 into 500 is not this shape.`,
      observed: receipt.claimedDelta,
      expected: 'identical status for equivalent boolean predicates',
      evidence: { rounds: triangle.rounds.length, statuses: triangle.rounds.map(round => ({
        benign: round.benign.status, tautology: round.tautology.status, contradiction: round.contradiction.status,
      })) },
    }
  }

  if (rule === 'timing') {
    if (receipt.exchangeIds.length < 2) return reject(receipt, rule, 'A timing receipt needs a control and a probe exchange.')
    const timed = receipt.exchangeIds.map(id => entriesById.get(id)!)
    const controls = timed.filter(entry => entry.step.arm === 'control')
    const probes = timed.filter(entry => entry.step.arm === 'probe')
    if (controls.length === 0 || probes.length === 0) {
      return reject(receipt, rule, 'A timing receipt needs at least one control arm and one probe arm.')
    }
    const controlMs = Math.max(...controls.map(entry => entry.durationMs ?? entry.step.durationMs ?? 0))
    const probeMs = Math.max(...probes.map(entry => entry.durationMs ?? entry.step.durationMs ?? 0))
    if (controlMs <= 0 || probeMs <= 0) return reject(receipt, rule, 'Timing receipt exchanges must record their wall-clock duration.')
    if (controlMs >= 1_000) return reject(receipt, rule, `The control took ${controlMs} ms, so a delay is not distinguishable from normal latency.`)
    if (probeMs < Math.max(1_000, controlMs * 3)) {
      return reject(receipt, rule, `Probe ${probeMs} ms is not a stable separation from the ${controlMs} ms control.`)
    }
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: `The probe arm took ${probeMs} ms against a ${controlMs} ms control (>3x separation).`,
      observed: receipt.claimedDelta,
      expected: 'comparable latency between control and probe',
      evidence: { controlMs, probeMs },
    }
  }

  if (rule === 'browser') {
    if (receipt.browserTraceIds.length === 0) return reject(receipt, rule, 'A browser receipt needs at least one host-recorded browser trace.')
    const traces = receipt.browserTraceIds.map(id => tracesById.get(id)!)
    if (traces.every(trace => (trace.sinks ?? []).length === 0)) {
      return reject(receipt, rule, 'No cited browser trace recorded a sink or security-relevant behaviour.')
    }
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: `Browser trace(s) ${receipt.browserTraceIds.join(', ')} recorded the claimed sink behaviour.`,
      observed: receipt.claimedDelta,
      expected: 'no sink execution in the recorded browser trace',
      evidence: { browserTraceIds: receipt.browserTraceIds },
    }
  }

  if (rule === 'redirect') {
    if (receipt.exchangeIds.length === 0) return reject(receipt, rule, 'A redirect receipt needs at least one recorded exchange.')
    const entries = receipt.exchangeIds.map(id => entriesById.get(id)!)
    const probe = entries.find(entry => entry.step.arm === 'probe') ?? entries[entries.length - 1]!
    const location = locationOf(probe.step)
    if (!location) return reject(receipt, rule, 'The cited exchange carries no Location header; a 3xx status alone is not an open redirect.')
    const targetHost = hostOf(receipt.target.origin)
    const locationHost = hostOf(location, receipt.target.origin)
    if (!locationHost || locationHost === targetHost) {
      return reject(receipt, rule, 'The redirect stays on the target origin (or has no host); a local 3xx is not an open redirect.')
    }
    const controlLocations = entries
      .filter(entry => entry !== probe)
      .map(entry => locationOf(entry.step))
      .filter((value): value is string => Boolean(value))
    if (controlLocations.includes(location)) {
      return reject(receipt, rule, 'The control arm redirects to the same off-origin destination, so the destination is not attacker-controlled.')
    }
    const canaryPattern = (receipt.proofPatterns ?? []).find(pattern => {
      try { return new RegExp(pattern).test(location) } catch { return false }
    })
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: `The probe response redirects to an off-origin host (${locationHost}) that no control arm reaches${canaryPattern ? ' and the Location matches the proof-declared canary host' : ''}; the 3xx is backed by a destination change, not status alone.`,
      observed: receipt.claimedDelta,
      expected: 'the marker-bearing request stays local',
      evidence: { locationHost, canaryPattern: canaryPattern ?? null },
    }
  }

  // Impact rules: re-run the shared oracle model over the recorded steps.
  if (receipt.exchangeIds.length === 0) return reject(receipt, rule, 'An impact receipt needs at least one recorded exchange.')
  const steps = receipt.exchangeIds.map(id => entriesById.get(id)!.step)
  const statusOnly = assessStatusOnlyDivergence(steps)
  if (statusOnly.statusOnly) {
    return reject(receipt, rule, `Bare status-only divergence (${statusOnly.controlStatus ?? 'no control'} -> ${statusOnly.probeStatus}): ${statusOnly.reason} A 4xx/5xx probe is only supporting evidence; confirmation needs a fingerprint, structural differential, timing arm, state delta or OOB callback.`)
  }
  // Bind the receipt target to the mutating exchange the claim actually made: a GET used as a
  // readback baseline must never become the finding's route for a write.
  const mutatingProbe = steps.find(step =>
    step.arm === 'probe' && stepMutatesState(step) && step.status !== null && step.status >= 200 && step.status < 300)
  if (mutatingProbe && receipt.target.pathAndQuery) {
    const targetRoute = normalizePath(receipt.target.pathAndQuery)
    const probeRoute = routeOf(mutatingProbe)
    if (targetRoute && probeRoute && probeRoute !== targetRoute) {
      return reject(receipt, rule, `The receipt target (${targetRoute}) is not the mutating probe exchange (${probeRoute}); a readback/GET used as evidence must not become the finding route.`)
    }
    if (receipt.target.method && receipt.target.method.toUpperCase() !== mutatingProbe.method.toUpperCase()) {
      return reject(receipt, rule, `The receipt target method (${receipt.target.method}) is not the mutating probe method (${mutatingProbe.method}); a read used as evidence must not become the write's finding method.`)
    }
  }
  const oracleEvents = (receipt.oracleEvents ?? []).filter(knownOracleEvent)
  const input: ImpactInput = {
    impactClass: impactClass!,
    steps,
    requiredRole: receipt.requiredRole ?? null,
    resourceTenant: receipt.resourceTenant ?? null,
    expectControlDenied: receipt.expectControlDenied,
    oracleEvents,
    targetOrigin: receipt.target.origin,
    credentialPatterns: receipt.proofPatterns ?? null,
  }
  const assessment = assessImpactEvidence(input)
  if (!assessment.required) {
    return reject(receipt, rule, `The ${impactClass} oracle has no requirement this receipt can satisfy.`)
  }
  if (!assessment.satisfied) {
    return {
      confirmed: false,
      vulnClass: receipt.vulnClass,
      rule,
      reason: assessment.reason,
      observed: receipt.claimedDelta,
      expected: 'persisted/observable impact that the recorded exchanges substantiate',
      evidence: assessment.evidence,
    }
  }
  return {
    confirmed: true,
    vulnClass: receipt.vulnClass,
    rule,
    reason: assessment.reason,
    observed: receipt.claimedDelta,
    expected: 'an authorized actor or control shows the boundary the probe crossed',
    evidence: assessment.evidence,
  }
}

/**
 * Reconstruct the benign / tautology / contradiction triangle from the cited arms.
 *
 * The recipe records an `evidenceRole` per exchange, so the normal case is an exact role match.
 * Transcripts built by other producers (async promotion, unit callers) may not carry roles; the
 * fallback infers the triangle from the universal shape — a 2xx baseline without a boolean
 * operator, a 2xx arm with one, and a <500 failing arm with one. A 5xx contradiction is never
 * accepted, so a single malformed request cannot be mistaken for a predicate contrast.
 */
function statusDifferentialRounds(arms: readonly ImpactStep[]): { rounds: Array<{ benign: ImpactStep; tautology: ImpactStep; contradiction: ImpactStep }> } | null {
  const entries = arms as Array<ImpactStep & { evidenceRole?: string }>
  const byRole = (role: string): ImpactStep[] => entries.filter(arm => arm.evidenceRole === role)
  const roleBenign = byRole('benign_baseline')
  const roleTautology = byRole('tautology')
  const roleContradiction = byRole('contradiction')
  const booleanRequest = (step: ImpactStep): boolean => {
    const raw = `${step.pathAndQuery ?? ''}${step.requestJson === undefined ? '' : JSON.stringify(step.requestJson)}`
    let text = raw
    try { text = decodeURIComponent(raw) } catch { /* keep raw */ }
    return /\b(?:AND|OR)\b/i.test(text)
  }
  const success = (status: number | null): boolean => status !== null && status >= 200 && status < 300
  const finishing = (status: number | null): boolean => status !== null && status >= 400 && status < 500
  const benign = roleBenign.length > 0
    ? roleBenign
    : entries.filter(step => step.arm === 'control' && success(step.status) && !booleanRequest(step))
  const tautology = roleTautology.length > 0
    ? roleTautology
    : entries.filter(step => success(step.status) && booleanRequest(step))
  const contradiction = roleContradiction.length > 0
    ? roleContradiction
    : entries.filter(step => finishing(step.status) && booleanRequest(step))
  if (benign.length === 0 || tautology.length === 0 || contradiction.length === 0) return null
  const rounds = Math.min(tautology.length, contradiction.length)
  if (rounds === 0) return null
  // Every arm of the triangle must be a well-formed member: the baseline is a 2xx without a
  // predicate, the two predicate arms are one 2xx and one <500 failure. Anything else means the
  // caller assembled the triangle from unrelated exchanges.
  if (benign.some(step => !success(step.status) || booleanRequest(step))) return null
  if (tautology.some(step => !success(step.status))) return null
  if (contradiction.some(step => !finishing(step.status))) return null
  return { rounds: Array.from({ length: rounds }, (_, index) => ({
    benign: benign[index] ?? benign[benign.length - 1]!,
    tautology: tautology[index]!,
    contradiction: contradiction[index]!,
  })) }
}

function deriveDifferingParam(control: ReceiptTranscriptEntry, probe: ReceiptTranscriptEntry): string | null {
  try {
    const controlUrl = new URL(control.step.pathAndQuery ?? '', 'http://guardian.invalid')
    const probeUrl = new URL(probe.step.pathAndQuery ?? '', 'http://guardian.invalid')
    for (const [key, value] of probeUrl.searchParams.entries()) {
      if (controlUrl.searchParams.get(key) !== value) return key
    }
  } catch { /* not a URL-shaped request */ }
  return null
}

function normalizeOrigin(origin: string): string {
  try {
    return new URL(origin).origin.toLowerCase()
  } catch {
    return origin.trim().toLowerCase()
  }
}

function stepCarries(step: ImpactStep, token: string): boolean {
  if ((step.pathAndQuery ?? '').includes(token)) return true
  if ((step.body ?? '').includes(token)) return true
  if (step.requestHeaders) {
    if (Object.values(step.requestHeaders).some(value => value.includes(token))) return true
  }
  return step.requestJson !== undefined && JSON.stringify(step.requestJson).includes(token)
}

/** Typed builder used by the floor/verifier so receipts are always schema-checked before use. */
export function buildProofReceipt(input: z.input<typeof proofReceiptSchema>): ProofReceipt {
  return proofReceiptSchema.parse(input)
}

/** Convenience for the async promotion path: one durable event, one carrying exchange. */
export function buildOobReceipt(input: {
  vulnClass: string
  origin: string
  method?: string
  pathAndQuery?: string
  param?: string
  exchangeIds: readonly string[]
  oobEventId: string
  claimedDelta: string
  injectedAtMs?: number
}): ProofReceipt {
  return buildProofReceipt({
    vulnClass: input.vulnClass,
    target: {
      origin: input.origin,
      ...(input.method ? { method: input.method.toUpperCase() } : {}),
      ...(input.pathAndQuery ? { pathAndQuery: input.pathAndQuery } : {}),
      ...(input.param ? { param: input.param } : {}),
    },
    exchangeIds: [...new Set(input.exchangeIds)],
    oobEventIds: [input.oobEventId],
    browserTraceIds: [],
    claimedDelta: input.claimedDelta,
    ...(input.injectedAtMs !== undefined ? { injectedAtMs: input.injectedAtMs } : {}),
  })
}

export type { ImpactClass, ImpactStep, RoleName }
