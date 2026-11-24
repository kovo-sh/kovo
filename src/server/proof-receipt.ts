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
  parseRoleLabel,
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
  /** Optional conserved-balance hints for `conserved_balance` receipts (always verified against host JSON). */
  conservedBalance: z.object({
    balanceField: z.string().trim().min(1).max(64).optional(),
    capField: z.string().trim().min(1).max(64).optional(),
    unitDebit: z.number().positive().optional(),
  }).optional(),
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
  rule: 'impact' | 'oob' | 'timing' | 'boolean' | 'status_differential' | 'browser' | 'redirect' | 'conserved_balance' | 'none'
  reason: string
  observed: string
  expected: string
  evidence?: Record<string, unknown>
}

const OOB_CLASS_RE = /^(?:ssrf|xxe|blind_ssrf|blind_xxe|oob|webhook_forgery)$/i
const TIMING_CLASS_RE = /^(?:blind_sqli|sqli_time|sql_time|timing)$/i
const BOOLEAN_CLASS_RE = /^(?:sqli|sql_boolean|sql_boolean_diff|boolean_sqli|boolean_differential)$/i
/**
 * The paired status-boolean shape: a benign 2xx baseline, a 2xx tautology arm and a <500
 * contradiction arm on the same request shape. This is deliberately a separate class from `sqli`
 * (which selects the structural differential rule) so a caller can never obtain the weaker status
 * rule by accident.
 */
const STATUS_DIFF_CLASS_RE = /^(?:sqli_status|sql_status|sql_status_diff|status_sqli|status_boolean)$/i
const REDIRECT_CLASS_RE = /^(?:open_redirect|redirect|url_redirect|unvalidated_redirect)$/i
const CONSERVED_BALANCE_CLASS_RE = /^(?:race|race_double_spend|race_condition|race_burst|double_spend|oversell|inventory_oversell|conserved_balance|toctou)$/i

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
  if (CONSERVED_BALANCE_CLASS_RE.test(vulnClass)) return { rule: 'conserved_balance' }
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

  if (rule === 'conserved_balance') {
    return verifyConservedBalanceReceipt(receipt, entriesById)
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

const CONSERVED_FIELD_RE = /(?:balance|credit|stock|inventory|quantity|qty|remaining|available|quota|seat|used|count|redeem|funds|points|tokens|amount)/i
const CONSERVED_CAP_FIELD_RE = /(?:limit|max|cap|quota|seat_limit|max_redemptions|max_uses|capacity)/i
const CONSERVED_IGNORE_FIELD_RE = /^(?:id|status|code|version|timestamp|created_at|updated_at|http_status|ok|error)$/i
const REQUEST_DEBIT_FIELD_RE = /^(?:amount|quantity|qty|debit|delta|value|count|seats|points|credits|transfer_amount|redeem_amount)$/i

const BASELINE_READ_ROLES = new Set(['baseline_read', 'pre_read', 'baseline_balance', 'balance_before', 'pre_burst_read'])
const POST_READ_ROLES = new Set(['post_read', 'post_burst_read', 'after_read', 'balance_after'])
const SERIAL_PRE_ROLES = new Set(['serial_pre_read', 'serial_baseline_read', 'serial_before_read'])
const SERIAL_POST_ROLES = new Set(['serial_post_read', 'serial_after_read', 'serial_read', 'serial_balance_after'])
const BURST_ROLE_RE = /^(?:burst|race_burst|concurrent)(?:[_-].*)?$/i
const SERIAL_MUTATION_ROLE_RE = /^serial(?:_(?:control|mutation|probe|step|request|debit))?(?:_\d+)?$/i

const is2xxStatus = (status: number | null): boolean => status !== null && status >= 200 && status < 300
const is4xxRejection = (status: number | null): boolean =>
  status !== null && (status === 400 || status === 403 || status === 404 || status === 409 || status === 410 || status === 422)

function parseStepJson(step: ImpactStep): unknown {
  if (step.json !== undefined) return step.json
  if (typeof step.body === 'string' && step.body.trim()) {
    try { return JSON.parse(step.body) } catch { return undefined }
  }
  return undefined
}

/** Collect finite numeric leaf fields up to depth 2 (e.g. `balance`, `wallet.balance`, `seats_used`). */
function extractNumericFields(value: unknown, prefix = '', depth = 0, out = new Map<string, number>()): Map<string, number> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || depth > 2) return out
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key
    if (typeof entry === 'number' && Number.isFinite(entry)) {
      if (!out.has(path)) out.set(path, entry)
      if (prefix && !out.has(key)) out.set(key, entry)
    } else if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
      extractNumericFields(entry, path, depth + 1, out)
    }
  }
  return out
}

function numericFieldFrom(step: ImpactStep, fieldName: string): number | null {
  const fields = extractNumericFields(parseStepJson(step))
  const direct = fields.get(fieldName)
  if (direct !== undefined) return direct
  const lowered = fieldName.toLowerCase()
  for (const [key, val] of fields.entries()) {
    if (key.toLowerCase() === lowered) return val
  }
  return null
}

function sharedConservedField(
  baseline: ImpactStep,
  post: ImpactStep,
  explicitField?: string,
): { field: string; pre: number; post: number } | null {
  if (explicitField) {
    const pre = numericFieldFrom(baseline, explicitField)
    const after = numericFieldFrom(post, explicitField)
    return pre !== null && after !== null ? { field: explicitField, pre, post: after } : null
  }
  const preFields = extractNumericFields(parseStepJson(baseline))
  const postFields = extractNumericFields(parseStepJson(post))
  const candidates: Array<{ field: string; pre: number; post: number; priority: number }> = []
  for (const [field, pre] of preFields.entries()) {
    const leaf = field.split('.').pop() ?? field
    if (CONSERVED_IGNORE_FIELD_RE.test(leaf)) continue
    const after = postFields.get(field)
    if (after === undefined) continue
    if (!CONSERVED_FIELD_RE.test(leaf)) continue
    // Prefer conserved balance/stock/remaining/used fields over cap/limit fields.
    const isCap = CONSERVED_CAP_FIELD_RE.test(leaf) && !/(?:used|remaining|available|balance|stock|credit)/i.test(leaf)
    const priority = (isCap ? 0 : 2) + (pre !== after ? 1 : 0)
    candidates.push({ field, pre, post: after, priority })
  }
  candidates.sort((a, b) => b.priority - a.priority || a.field.length - b.field.length || a.field.localeCompare(b.field))
  return candidates[0] ? { field: candidates[0].field, pre: candidates[0].pre, post: candidates[0].post } : null
}

function findCapValue(baseline: ImpactStep, post: ImpactStep, balanceField: string, explicitCapField?: string): { field: string; value: number } | null {
  if (explicitCapField) {
    const val = numericFieldFrom(post, explicitCapField) ?? numericFieldFrom(baseline, explicitCapField)
    return val !== null ? { field: explicitCapField, value: val } : null
  }
  const combined = new Map([...extractNumericFields(parseStepJson(baseline)), ...extractNumericFields(parseStepJson(post))])
  for (const [field, value] of combined.entries()) {
    if (field === balanceField) continue
    const leaf = field.split('.').pop() ?? field
    if (CONSERVED_CAP_FIELD_RE.test(leaf) && value > 0) return { field, value }
  }
  return null
}

function requestDebitOf(step: ImpactStep, fallbackUnitDebit: number): number {
  if (step.requestJson && typeof step.requestJson === 'object' && !Array.isArray(step.requestJson)) {
    const fields = extractNumericFields(step.requestJson)
    for (const [field, value] of fields.entries()) {
      const leaf = field.split('.').pop() ?? field
      if (REQUEST_DEBIT_FIELD_RE.test(leaf) && value > 0) return value
    }
  }
  return fallbackUnitDebit
}

/**
 * Fail-closed `conserved_balance` receipt rule for race / double-spend / inventory-oversell proofs.
 * Requires host-recorded transcript evidence of:
 *   1. A 2xx baseline numeric readback before the burst,
 *   2. >=2 acknowledged (2xx) concurrent burst mutations (rejecting 5xx/4xx-only bursts),
 *   3. A 2xx post-burst numeric readback on the same conserved field proving a conservation
 *      violation (under-debit, negative balance/stock, or cap/quota overshoot — never status-only),
 *   4. A passing serial control exchange proving the conservation boundary holds serially (either
 *      serial debit matches expected debit without going negative, or serial mutation is rejected
 *      with 4xx once depleted/used).
 */
function verifyConservedBalanceReceipt(
  receipt: ProofReceipt,
  entriesById: ReadonlyMap<string, ReceiptTranscriptEntry>,
): ReceiptVerification {
  const rule = 'conserved_balance' as const
  if (receipt.exchangeIds.length < 4) {
    return reject(
      receipt,
      rule,
      'A conserved_balance receipt requires baseline readback, >=2 burst mutations, post-burst readback, and a serial control.',
    )
  }
  const cited = receipt.exchangeIds.map(id => entriesById.get(id)!)
  const roleOf = (entry: ReceiptTranscriptEntry): string => (entry.evidenceRole ?? '').trim().toLowerCase()

  const burstIndices: number[] = []
  cited.forEach((entry, index) => {
    const role = roleOf(entry)
    if (BURST_ROLE_RE.test(role) || (!role && entry.step.arm === 'probe' && stepMutatesState(entry.step))) {
      burstIndices.push(index)
    }
  })
  if (burstIndices.length < 2) {
    return reject(receipt, rule, 'A conserved_balance receipt requires at least 2 concurrent mutation exchanges.')
  }
  const firstBurstIdx = burstIndices[0]!
  const lastBurstIdx = burstIndices[burstIndices.length - 1]!
  const burstEntries = burstIndices.map(i => cited[i]!)

  if (receipt.target.method && burstEntries.every(entry => entry.step.method.toUpperCase() !== receipt.target.method)) {
    return reject(receipt, rule, 'The cited burst exchange method does not match the receipt target.')
  }
  if (receipt.target.pathAndQuery) {
    const wanted = normalizePath(receipt.target.pathAndQuery)
    if (burstEntries.every(entry => routeOf(entry.step) !== wanted)) {
      return reject(receipt, rule, 'The cited burst exchange route does not match the receipt target.')
    }
  }

  const ackedBurst = burstEntries.filter(entry => is2xxStatus(entry.step.status))
  if (ackedBurst.length === 0) {
    return reject(receipt, rule, 'The concurrent burst produced no 2xx acknowledged mutations (5xx/4xx-only bursts never prove a race).')
  }
  if (ackedBurst.length < 2) {
    return reject(receipt, rule, `Only ${ackedBurst.length} concurrent mutation was acknowledged; a conserved_balance proof requires >=2 acknowledged concurrent mutations.`)
  }

  // Locate baseline readback (before the burst).
  let baselineIdx = cited.findIndex((entry, index) => index < firstBurstIdx && BASELINE_READ_ROLES.has(roleOf(entry)))
  if (baselineIdx < 0) {
    baselineIdx = cited.findIndex((entry, index) =>
      index < firstBurstIdx && (entry.step.arm === 'setup' || entry.step.arm === 'control') && is2xxStatus(entry.step.status))
  }
  if (baselineIdx < 0 || !is2xxStatus(cited[baselineIdx]!.step.status)) {
    return reject(receipt, rule, 'A conserved_balance receipt requires a 2xx baseline numeric readback before the burst.')
  }
  const baselineEntry = cited[baselineIdx]!

  // Locate post-burst readback (after the burst, before any serial post-read).
  let postIdx = cited.findIndex((entry, index) => index > lastBurstIdx && POST_READ_ROLES.has(roleOf(entry)))
  if (postIdx < 0) {
    postIdx = cited.findIndex((entry, index) =>
      index > lastBurstIdx &&
      !SERIAL_MUTATION_ROLE_RE.test(roleOf(entry)) &&
      !SERIAL_POST_ROLES.has(roleOf(entry)) &&
      !SERIAL_PRE_ROLES.has(roleOf(entry)) &&
      (entry.step.arm === 'control' || entry.step.arm === 'cleanup' || entry.step.arm === 'setup') &&
      is2xxStatus(entry.step.status))
  }
  if (postIdx < 0 || !is2xxStatus(cited[postIdx]!.step.status)) {
    return reject(receipt, rule, 'A conserved_balance receipt requires a 2xx post-burst numeric readback after the burst.')
  }
  const postEntry = cited[postIdx]!

  const conserved = sharedConservedField(baselineEntry.step, postEntry.step, receipt.conservedBalance?.balanceField)
  if (!conserved) {
    return reject(
      receipt,
      rule,
      'Baseline and post-burst readbacks lack a shared numeric conserved field (status-only differential without numeric delta is rejected).',
    )
  }

  const unitDebit = receipt.conservedBalance?.unitDebit ?? 1
  const expectedBurstDebit = ackedBurst.reduce((sum, entry) => sum + requestDebitOf(entry.step, unitDebit), 0)
  const actualBurstDebit = conserved.pre - conserved.post
  const cap = findCapValue(baselineEntry.step, postEntry.step, conserved.field, receipt.conservedBalance?.capField)

  // Locate serial control exchanges (must prove conservation holds serially).
  const serialMutations = cited.filter((entry, index) => {
    if (index === baselineIdx || index === postIdx || burstIndices.includes(index)) return false
    const role = roleOf(entry)
    if (SERIAL_PRE_ROLES.has(role) || SERIAL_POST_ROLES.has(role)) return false
    return SERIAL_MUTATION_ROLE_RE.test(role) || (entry.step.arm === 'control' && stepMutatesState(entry.step))
  })
  const serialPreEntry = cited.find(entry => SERIAL_PRE_ROLES.has(roleOf(entry)))
  const serialPostEntry = cited.find((entry, index) =>
    index !== baselineIdx && index !== postIdx && !burstIndices.includes(index) && SERIAL_POST_ROLES.has(roleOf(entry)))

  if (serialMutations.length === 0) {
    return reject(receipt, rule, 'A conserved_balance receipt requires a serial control exchange proving the conservation boundary holds serially.')
  }
  const serial5xx = serialMutations.filter(entry => entry.step.status !== null && entry.step.status >= 500)
  const serial2xx = serialMutations.filter(entry => is2xxStatus(entry.step.status))
  const serial4xx = serialMutations.filter(entry => is4xxRejection(entry.step.status))

  if (serial2xx.length === 0 && serial4xx.length === 0) {
    return reject(
      receipt,
      rule,
      serial5xx.length > 0
        ? 'Serial control returned 5xx; cannot prove the conservation boundary holds serially.'
        : 'Serial control produced neither a verified serial debit nor a 4xx conservation rejection.',
    )
  }

  let serialControlKind: 'serial_debit_exact' | 'serial_rejection' | null = null
  let serialDebitObserved: number | null = null
  if (serial2xx.length > 0) {
    if (!serialPostEntry || !is2xxStatus(serialPostEntry.step.status)) {
      return reject(receipt, rule, 'Serial control mutations succeeded without a 2xx post-serial numeric readback proving exact serial debit.')
    }
    const serialPreVal = serialPreEntry && is2xxStatus(serialPreEntry.step.status)
      ? numericFieldFrom(serialPreEntry.step, conserved.field)
      : conserved.post
    const serialPostVal = numericFieldFrom(serialPostEntry.step, conserved.field)
    if (serialPreVal === null || serialPostVal === null) {
      return reject(receipt, rule, `Serial control readback is missing numeric field "${conserved.field}".`)
    }
    const expectedSerialDebit = serial2xx.reduce((sum, entry) => sum + requestDebitOf(entry.step, unitDebit), 0)
    const decreasing = conserved.post <= conserved.pre && !cap
    const serialDelta = decreasing ? serialPreVal - serialPostVal : serialPostVal - serialPreVal
    if (decreasing && serialPostVal < 0) {
      return reject(receipt, rule, 'Serial control itself drove the conserved balance negative (not a concurrency/race boundary).')
    }
    if (cap && serialPostVal > cap.value) {
      return reject(receipt, rule, `Serial control itself exceeded cap "${cap.field}" (${serialPostVal} > ${cap.value}); not a concurrency boundary.`)
    }
    if (serialDelta < expectedSerialDebit - 1e-6) {
      return reject(
        receipt,
        rule,
        `Serial control under-debited (${serialDelta} vs expected ${expectedSerialDebit}); conservation does not hold serially.`,
      )
    }
    serialControlKind = 'serial_debit_exact'
    serialDebitObserved = serialDelta
  } else {
    // Pure serial rejection (4xx once depleted/already-redeemed): verify serialPost (if given) did not violate further.
    if (serialPostEntry && is2xxStatus(serialPostEntry.step.status)) {
      const afterSerial = numericFieldFrom(serialPostEntry.step, conserved.field)
      if (afterSerial !== null && Math.abs(afterSerial - conserved.post) > 1e-6) {
        return reject(receipt, rule, 'Rejected serial control still mutated the conserved field; serial boundary did not hold.')
      }
    }
    serialControlKind = 'serial_rejection'
  }

  // Evaluate conservation violation on the concurrent burst.
  let violationKind: 'under_debit' | 'negative_balance' | 'cap_overshoot' | null = null
  if (conserved.pre >= 0 && conserved.post < 0) {
    violationKind = 'negative_balance'
  } else if (cap && conserved.pre <= cap.value && conserved.post > cap.value) {
    violationKind = 'cap_overshoot'
  } else if (conserved.pre >= 0 && conserved.post >= 0 && actualBurstDebit < expectedBurstDebit - 1e-6) {
    // Require concrete movement (either burst debited >0 but <expected, OR serial control proved a
    // single serial mutation debits >0 while the concurrent burst debited less than expected).
    const provedMutating = actualBurstDebit > 1e-6 || (serialDebitObserved !== null && serialDebitObserved > 1e-6)
    if (provedMutating) violationKind = 'under_debit'
  }

  if (!violationKind) {
    return reject(
      receipt,
      rule,
      `Numeric readbacks on "${conserved.field}" (${conserved.pre} -> ${conserved.post} across ${ackedBurst.length} acked burst mutations, expected debit ${expectedBurstDebit}) show no conservation violation (no under-debit, negative balance, or cap overshoot).`,
    )
  }

  return {
    confirmed: true,
    vulnClass: receipt.vulnClass,
    rule,
    reason: `Conserved-balance violation (${violationKind}) on "${conserved.field}": ${ackedBurst.length} concurrent mutations acknowledged (${conserved.pre} -> ${conserved.post}, expected debit ${expectedBurstDebit}, actual debit ${actualBurstDebit}) while serial control (${serialControlKind}) preserved the conservation boundary.`,
    observed: receipt.claimedDelta,
    expected: `concurrent mutations preserve "${conserved.field}" conservation identically to serial execution`,
    evidence: {
      balanceField: conserved.field,
      preBalance: conserved.pre,
      postBalance: conserved.post,
      ackedBurstCount: ackedBurst.length,
      totalBurstCount: burstEntries.length,
      expectedBurstDebit,
      actualBurstDebit,
      violationKind,
      serialControlKind,
      ...(serialDebitObserved !== null ? { serialDebitObserved } : {}),
      ...(cap ? { capField: cap.field, capValue: cap.value } : {}),
    },
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

// ---------------------------------------------------------------------------
// Agent-script receipts (v7 M5): turn a host-recorded Layer-3 transcript + the script's own claim
// set into the same `ProofReceipt` the floor uses, so a script proof is re-checkable by
// `verifyReceipt()` instead of by script stdout. The builder is deliberately conservative: it
// returns null for any class it cannot map onto a receipt rule, and the caller then keeps the
// script verdict alone (never a declarative re-interpretation).
// ---------------------------------------------------------------------------

/** One host-recorded Layer-3 exchange, reduced to what a receipt needs. */
export interface ScriptProofExchange {
  exchangeId: string
  op?: string
  method: string
  pathAndQuery: string
  origin: string
  status: number | null
  durationMs?: number
  personaHandle?: string | null
  /** Session-group role the script declared (`control`, `probe`, `setup`, `cleanup`). */
  sessionRole?: string | null
  /** Host-resolved persona role label (e.g. "owner (acme)"); never script-supplied. */
  actorRoleLabel?: string | null
  body?: string
  requestHeaders?: Record<string, string> | null
  responseHeaders?: Record<string, string> | null
}

const IMPACT_CLASS_TO_VULN_CLASS: Readonly<Record<string, string>> = {
  authorization: 'authorization',
  bfla: 'bfla',
  mass_assignment: 'mass_assignment',
  csrf: 'csrf',
  business_logic: 'business_logic',
  markup: 'markup',
  disclosure: 'disclosure',
  injection: 'injection',
}

function recordField(record: Record<string, unknown>, key: string): unknown {
  return record[key]
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string' && item.length > 0) : []
}

function impactStepOf(
  exchange: ScriptProofExchange,
  overrides?: {
    arm?: ImpactStep['arm']
    requestJson?: unknown
    ambientAuth?: ImpactStep['actor']['auth']
    sameSite?: string | null
  },
): ImpactStep {
  const roleLabel = exchange.actorRoleLabel ?? null
  const parsed = parseRoleLabel(roleLabel ?? exchange.personaHandle ?? null)
  const arm = overrides?.arm ?? (exchange.sessionRole === 'control' || exchange.sessionRole === 'probe' ||
    exchange.sessionRole === 'cleanup' || exchange.sessionRole === 'setup'
    ? exchange.sessionRole
    : 'setup')
  let json: unknown
  if (exchange.body !== undefined) {
    try { json = JSON.parse(exchange.body) } catch { json = undefined }
  }
  return {
    id: exchange.exchangeId,
    arm,
    method: (exchange.method || 'GET').toUpperCase(),
    route: (exchange.pathAndQuery || '/').split('?')[0],
    pathAndQuery: exchange.pathAndQuery || '/',
    status: exchange.status,
    actor: {
      handle: exchange.personaHandle ?? null,
      role: parsed.role,
      tenant: parsed.tenant,
      auth: overrides?.ambientAuth ?? 'unknown',
      sameSite: overrides?.sameSite ?? null,
    },
    ...(json !== undefined ? { json } : {}),
    ...(exchange.body !== undefined ? { body: exchange.body } : {}),
    ...(overrides?.requestJson !== undefined ? { requestJson: overrides.requestJson } : {}),
    ...(exchange.requestHeaders ? { requestHeaders: exchange.requestHeaders } : {}),
    ...(exchange.responseHeaders ? { responseHeaders: exchange.responseHeaders } : {}),
    ...(exchange.durationMs !== undefined ? { durationMs: exchange.durationMs } : {}),
  }
}

/**
 * Derive a receipt from a confirmed script run. `claims` are the oracle-checked claim objects the
 * SDK returned (already re-evaluated against the signed transcript); they are used only to name the
 * class, the target and the exchange set. Every cited id must exist in `exchanges`.
 */
export function buildAgentScriptReceipt(input: {
  claims: readonly Record<string, unknown>[]
  exchanges: readonly ScriptProofExchange[]
  origin: string
  title: string
}): { receipt: ProofReceipt; transcript: ReceiptTranscript } | null {
  const byId = new Map(input.exchanges.map(exchange => [exchange.exchangeId, exchange]))
  const orderById = new Map(input.exchanges.map((exchange, index) => [exchange.exchangeId, index]))
  const buildTranscript = (
    armOverrides: ReadonlyMap<string, ImpactStep['arm']>,
    extra?: {
      requestJson?: unknown
      ambientAuth?: ImpactStep['actor']['auth']
      sameSite?: string | null
      evidenceRoleOverrides?: ReadonlyMap<string, string>
    },
  ): ReceiptTranscript => ({
    entries: input.exchanges.map(exchange => ({
      exchangeId: exchange.exchangeId,
      step: impactStepOf(exchange, {
        ...(armOverrides.has(exchange.exchangeId) ? { arm: armOverrides.get(exchange.exchangeId)! } : {}),
        ...(extra?.requestJson !== undefined ? { requestJson: extra.requestJson } : {}),
        ...(extra?.ambientAuth ? { ambientAuth: extra.ambientAuth } : {}),
        ...(extra?.sameSite !== undefined ? { sameSite: extra.sameSite } : {}),
      }),
      ...(exchange.durationMs !== undefined ? { durationMs: exchange.durationMs } : {}),
      ...(exchange.body !== undefined
        ? { carrierText: `${exchange.pathAndQuery}\n${JSON.stringify(exchange.requestHeaders ?? {})}\n${exchange.body}` }
        : {}),
      ...(extra?.evidenceRoleOverrides?.has(exchange.exchangeId)
        ? { evidenceRole: extra.evidenceRoleOverrides.get(exchange.exchangeId)! }
        : exchange.sessionRole ? { evidenceRole: exchange.sessionRole } : {}),
    })),
  })
  const cited = (ids: readonly string[]) => ids.filter(id => byId.has(id))

  for (const claim of input.claims) {
    if (recordField(claim, 'kind') !== 'impact') continue
    const impactClass = recordField(claim, 'impactClass')
    if (typeof impactClass !== 'string') continue
    const vulnClass = IMPACT_CLASS_TO_VULN_CLASS[impactClass]
    if (!vulnClass) continue
    const probeId = recordField(claim, 'probeExchangeId')
    if (typeof probeId !== 'string') continue
    const probe = byId.get(probeId)
    if (!probe) continue
    const controlIds = cited(stringArray(recordField(claim, 'controlExchangeIds')))
    const beforeId = typeof recordField(claim, 'beforeExchangeId') === 'string' && byId.has(recordField(claim, 'beforeExchangeId') as string)
      ? recordField(claim, 'beforeExchangeId') as string
      : null
    const afterId = typeof recordField(claim, 'afterExchangeId') === 'string' && byId.has(recordField(claim, 'afterExchangeId') as string)
      ? recordField(claim, 'afterExchangeId') as string
      : null
    // Deduplicate and preserve host-transcript chronological order so pre/post mutation readbacks
    // stay strictly before/after the mutating probe in `findPersistence()`.
    const exchangeIds = [...new Set([
      ...(beforeId ? [beforeId] : []),
      ...controlIds,
      probeId,
      ...(afterId ? [afterId] : []),
    ])].sort((a, b) => (orderById.get(a) ?? 0) - (orderById.get(b) ?? 0))
    if (exchangeIds.length === 0) continue
    const armOverrides = new Map<string, ImpactStep['arm']>()
    for (const id of controlIds) armOverrides.set(id, 'control')
    if (beforeId) armOverrides.set(beforeId, 'control')
    if (afterId) armOverrides.set(afterId, 'control')
    armOverrides.set(probeId, 'probe')
    const rawAmbient = recordField(claim, 'ambient')
    const ambient = rawAmbient && typeof rawAmbient === 'object' && !Array.isArray(rawAmbient)
      ? rawAmbient as { kind?: unknown; sameSite?: unknown }
      : null
    const ambientAuth = ambient?.kind === 'cookie' || ambient?.kind === 'bearer' || ambient?.kind === 'header' || ambient?.kind === 'unknown'
      ? ambient.kind
      : undefined
    const sameSite = typeof ambient?.sameSite === 'string' ? ambient.sameSite : null
    const transcript = buildTranscript(armOverrides, {
      ...(recordField(claim, 'requestBody') !== undefined ? { requestJson: recordField(claim, 'requestBody') } : {}),
      ...(ambientAuth ? { ambientAuth } : {}),
      ...(sameSite !== null ? { sameSite } : {}),
    })
    const requiredRole = recordField(claim, 'requiredRole')
    const resourceTenant = recordField(claim, 'resourceTenant')
    const oracleEvents = stringArray(recordField(claim, 'oracleEvents'))
    const proofPatterns = stringArray(recordField(claim, 'proofPatterns')).filter(p => p.length >= 4 && p.length <= 200).slice(0, 4)
    return {
      receipt: buildProofReceipt({
        vulnClass,
        target: {
          origin: probe.origin || input.origin,
          method: probe.method.toUpperCase(),
          pathAndQuery: probe.pathAndQuery,
        },
        exchangeIds,
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `${input.title} — script claims ${impactClass} impact over ${exchangeIds.length} host-recorded exchange(s).`.slice(0, 1200),
        ...(requiredRole === 'viewer' || requiredRole === 'member' || requiredRole === 'admin' || requiredRole === 'owner'
          ? { requiredRole }
          : {}),
        ...(typeof resourceTenant === 'string' && resourceTenant ? { resourceTenant } : {}),
        ...(recordField(claim, 'expectControlDenied') === true ? { expectControlDenied: true } : {}),
        ...(oracleEvents.length ? { oracleEvents: [...new Set(oracleEvents)].slice(0, 8) } : {}),
        ...(proofPatterns.length ? { proofPatterns } : {}),
      }),
      transcript,
    }
  }

  for (const claim of input.claims) {
    const kind = recordField(claim, 'kind')
    if (kind === 'structural_diff') {
      const controls = cited(stringArray(recordField(claim, 'controlIds')))
      const variants = cited(stringArray(recordField(claim, 'variantIds')))
      if (controls.length < 2 || controls.length !== variants.length) continue
      const armOverrides = new Map<string, ImpactStep['arm']>()
      for (const id of controls) armOverrides.set(id, 'control')
      for (const id of variants) armOverrides.set(id, 'probe')
      const transcript = buildTranscript(armOverrides)
      const controlEntry = transcript.entries!.find(entry => entry.exchangeId === controls[0])
      const probeEntry = transcript.entries!.find(entry => entry.exchangeId === variants[0])
      if (!controlEntry || !probeEntry) continue
      const param = deriveDifferingParam(controlEntry, probeEntry)
      if (!param) continue
      const variantExchange = byId.get(variants[0]!)
      return {
        receipt: buildProofReceipt({
          vulnClass: 'sqli',
          target: {
            origin: variantExchange?.origin || input.origin,
            ...(probeEntry.step.method ? { method: probeEntry.step.method.toUpperCase() } : {}),
            ...(probeEntry.step.pathAndQuery ? { pathAndQuery: probeEntry.step.pathAndQuery } : {}),
            param,
          },
          exchangeIds: [...controls, ...variants],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: `${input.title} — paired boolean differential over ${controls.length} recorded round(s).`.slice(0, 1200),
        }),
        transcript,
      }
    }
    if (kind === 'timing') {
      const controls = cited(stringArray(recordField(claim, 'controlIds')))
      const variants = cited(stringArray(recordField(claim, 'variantIds')))
      if (controls.length < 5 || variants.length < 5) continue
      const probe = byId.get(variants[0]!)
      if (!probe) continue
      const armOverrides = new Map<string, ImpactStep['arm']>()
      for (const id of controls) armOverrides.set(id, 'control')
      for (const id of variants) armOverrides.set(id, 'probe')
      const transcript = buildTranscript(armOverrides)
      return {
        receipt: buildProofReceipt({
          vulnClass: 'blind_sqli',
          target: {
            origin: probe.origin || input.origin,
            method: probe.method.toUpperCase(),
            pathAndQuery: probe.pathAndQuery,
          },
          exchangeIds: [...controls, ...variants],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: `${input.title} — timing separation over ${controls.length}/${variants.length} recorded arms.`.slice(0, 1200),
        }),
        transcript,
      }
    }
    if (kind === 'conserved_balance' || kind === 'race') {
      const rawBaseline = recordField(claim, 'baselineExchangeId') ?? recordField(claim, 'beforeExchangeId')
      const baselineId = typeof rawBaseline === 'string' && byId.has(rawBaseline) ? rawBaseline : null
      const rawPost = recordField(claim, 'postExchangeId') ?? recordField(claim, 'afterExchangeId')
      const postId = typeof rawPost === 'string' && byId.has(rawPost) ? rawPost : null
      const burstIds = cited(stringArray(recordField(claim, 'burstExchangeIds') ?? recordField(claim, 'exchangeIds')))
      const serialIds = cited(stringArray(recordField(claim, 'serialExchangeIds') ?? recordField(claim, 'controlExchangeIds')))
      const rawSerialPre = recordField(claim, 'serialPreExchangeId')
      const serialPreId = typeof rawSerialPre === 'string' && byId.has(rawSerialPre) ? rawSerialPre : null
      const rawSerialPost = recordField(claim, 'serialPostExchangeId')
      const serialPostId = typeof rawSerialPost === 'string' && byId.has(rawSerialPost) ? rawSerialPost : null
      if (!baselineId || !postId || burstIds.length < 2 || serialIds.length === 0) continue
      const firstBurst = byId.get(burstIds[0]!)
      if (!firstBurst) continue
      const armOverrides = new Map<string, ImpactStep['arm']>()
      const evidenceRoleOverrides = new Map<string, string>()
      armOverrides.set(baselineId, 'setup')
      evidenceRoleOverrides.set(baselineId, 'baseline_read')
      burstIds.forEach((id, index) => {
        armOverrides.set(id, 'probe')
        evidenceRoleOverrides.set(id, `burst_${index + 1}`)
      })
      armOverrides.set(postId, 'control')
      evidenceRoleOverrides.set(postId, 'post_read')
      if (serialPreId) {
        armOverrides.set(serialPreId, 'control')
        evidenceRoleOverrides.set(serialPreId, 'serial_pre_read')
      }
      serialIds.forEach((id, index) => {
        armOverrides.set(id, 'control')
        evidenceRoleOverrides.set(id, `serial_control_${index + 1}`)
      })
      if (serialPostId) {
        armOverrides.set(serialPostId, 'control')
        evidenceRoleOverrides.set(serialPostId, 'serial_post_read')
      }
      const exchangeIds = [...new Set([
        baselineId,
        ...burstIds,
        postId,
        ...(serialPreId ? [serialPreId] : []),
        ...serialIds,
        ...(serialPostId ? [serialPostId] : []),
      ])]
      const transcript = buildTranscript(armOverrides, {
        ...(recordField(claim, 'requestBody') !== undefined ? { requestJson: recordField(claim, 'requestBody') } : {}),
        evidenceRoleOverrides,
      })
      const rawClass = recordField(claim, 'vulnClass')
      const vulnClass = typeof rawClass === 'string' && CONSERVED_BALANCE_CLASS_RE.test(rawClass.trim())
        ? rawClass.trim()
        : 'race_double_spend'
      const balanceField = typeof recordField(claim, 'balanceField') === 'string' ? (recordField(claim, 'balanceField') as string).trim() : ''
      const capField = typeof recordField(claim, 'capField') === 'string' ? (recordField(claim, 'capField') as string).trim() : ''
      const unitDebitRaw = recordField(claim, 'unitDebit')
      const unitDebit = typeof unitDebitRaw === 'number' && Number.isFinite(unitDebitRaw) && unitDebitRaw > 0 ? unitDebitRaw : undefined
      return {
        receipt: buildProofReceipt({
          vulnClass,
          target: {
            origin: firstBurst.origin || input.origin,
            method: firstBurst.method.toUpperCase(),
            pathAndQuery: firstBurst.pathAndQuery,
          },
          exchangeIds,
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: `${input.title} — conserved-balance race over ${burstIds.length} burst + ${serialIds.length} serial control exchange(s).`.slice(0, 1200),
          ...(balanceField || capField || unitDebit !== undefined
            ? {
                conservedBalance: {
                  ...(balanceField ? { balanceField } : {}),
                  ...(capField ? { capField } : {}),
                  ...(unitDebit !== undefined ? { unitDebit } : {}),
                },
              }
            : {}),
        }),
        transcript,
      }
    }
  }
  return null
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
