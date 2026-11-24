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
import { assessImpactEvidence, knownOracleEvent } from './oracle-invariants.ts'
import type { ImpactClass, ImpactInput, ImpactStep, RoleName } from './oracle-invariants.ts'

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
  rule: 'impact' | 'oob' | 'timing' | 'browser' | 'none'
  reason: string
  observed: string
  expected: string
  evidence?: Record<string, unknown>
}

const OOB_CLASS_RE = /^(?:ssrf|xxe|blind_ssrf|blind_xxe|oob|webhook_forgery)$/i
const TIMING_CLASS_RE = /^(?:blind_sqli|sqli_time|sql_time|timing|race)$/i

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
}

/** Classify a receipt's vulnerability label into the shared impact model (or a non-impact rule). */
export function receiptRuleFor(vulnClass: string): { rule: ReceiptVerification['rule']; impactClass?: ImpactClass } {
  if (OOB_CLASS_RE.test(vulnClass)) return { rule: 'oob' }
  if (TIMING_CLASS_RE.test(vulnClass)) return { rule: 'timing' }
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

  if (rule === 'timing') {
    if (receipt.exchangeIds.length < 2) return reject(receipt, rule, 'A timing receipt needs a control and a probe exchange.')
    const timed = receipt.exchangeIds.map(id => entriesById.get(id)!)
    const controls = timed.filter(entry => entry.step.arm === 'control')
    const probes = timed.filter(entry => entry.step.arm === 'probe')
    if (controls.length === 0 || probes.length === 0) {
      return reject(receipt, rule, 'A timing receipt needs at least one control arm and one probe arm.')
    }
    const controlMs = Math.max(...controls.map(entry => entry.durationMs ?? 0))
    const probeMs = Math.max(...probes.map(entry => entry.durationMs ?? 0))
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

  // Impact rules: re-run the shared oracle model over the recorded steps.
  if (receipt.exchangeIds.length === 0) return reject(receipt, rule, 'An impact receipt needs at least one recorded exchange.')
  const steps = receipt.exchangeIds.map(id => entriesById.get(id)!.step)
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
