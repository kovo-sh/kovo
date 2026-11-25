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
import { createHmac } from 'node:crypto'
import { z } from 'zod'
import { scopedAssetOrigin } from '../domain.ts'
import { HostFactLog } from './host-fact-log.ts'
import {
  assessBooleanDifferential,
  assessImpactEvidence,
  assessInjectionImpact,
  assessStatusOnlyDivergence,
  hasForeignTenantOrOwnerDisclosure,
  isObjectScopedRequest,
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
  /** Host-recorded operation type (`http`, `http2`, `race`, `oob`, `browser`). */
  op?: string
  /** Host-recorded monotonic transcript sequence index (never worker-ordered). */
  seq?: number
  /** Host-recorded request start timestamp (epoch ms). */
  startedAt?: number
  /** Host-recorded request end timestamp (epoch ms). */
  endedAt?: number
  /** Host-recorded target origin of this exchange. */
  origin?: string
  /** Host-recorded primary sealed capability consumed by this exchange (if any). */
  consumedCapabilityId?: string | null
  /** Host-recorded sealed capabilities consumed by this exchange (if any). */
  consumedCapabilities?: readonly string[]
  /** Host-recorded session jar identifier (if any). */
  sessionId?: string | null
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
  rule: 'impact' | 'oob' | 'timing' | 'boolean' | 'status_differential' | 'browser' | 'redirect' | 'conserved_balance' | 'auth_bypass' | 'webhook' | 'none'
  reason: string
  observed: string
  expected: string
  evidence?: Record<string, unknown>
}

const OOB_CLASS_RE = /^(?:ssrf|xxe|blind_ssrf|blind_xxe|oob)$/i
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
const AUTH_BYPASS_CLASS_RE = /^(?:auth_bypass|jwt_forgery|broken_auth|auth_protocol|token_forgery|authentication_bypass)$/i

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
  sqli_error: 'injection',
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
export function receiptRuleFor(vulnClass: string, receipt?: Pick<ProofReceipt, 'oobEventIds'>): { rule: ReceiptVerification['rule']; impactClass?: ImpactClass } {
  if (OOB_CLASS_RE.test(vulnClass)) return { rule: 'oob' }
  // Webhook forgery has two evidence models: a durable callback remains OOB, while an inline-key
  // self-signed delivery must prove the signature/control differential over host-recorded requests.
  if (/^webhook_forgery$/i.test(vulnClass)) {
    return receipt && receipt.oobEventIds.length === 0 ? { rule: 'webhook' } : { rule: 'oob' }
  }
  if (STATUS_DIFF_CLASS_RE.test(vulnClass)) return { rule: 'status_differential' }
  if (BOOLEAN_CLASS_RE.test(vulnClass)) return { rule: 'boolean' }
  if (TIMING_CLASS_RE.test(vulnClass)) return { rule: 'timing' }
  if (CONSERVED_BALANCE_CLASS_RE.test(vulnClass)) return { rule: 'conserved_balance' }
  if (AUTH_BYPASS_CLASS_RE.test(vulnClass)) return { rule: 'auth_bypass' }
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
  try { return new URL(value, base ?? 'http://kovo.invalid').host.toLowerCase() } catch { return null }
}

interface InlineWebhookSignature {
  valid: boolean
  delivery: string
  keyField: string
  signatureField: string
}

/** Recompute an inline-key webhook HMAC strictly from the host-recorded request body. */
function inlineWebhookSignature(step: ImpactStep): InlineWebhookSignature | null {
  const body = step.requestJson
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null
  const record = body as Record<string, unknown>
  const entries = Object.entries(record)
  const keyField = entries.find(([key, value]) => typeof value === 'string' && value.length > 0 &&
    /(?:^|_)(?:key|secret)$|^(?:signing|webhook|hmac)(?:key|secret)$/i.test(key))?.[0]
  const signatureField = entries.find(([key, value]) => typeof value === 'string' && value.length > 0 &&
    /(?:^|_)(?:signature|sig)$|signature$/i.test(key))?.[0]
  if (!keyField || !signatureField) return null
  const key = String(record[keyField])
  const signature = String(record[signatureField])
  const timestampField = entries.find(([name]) => /(?:^|_)(?:ts|timestamp)$/i.test(name))?.[0]
  const eventField = entries.find(([name]) => /^(?:event|payload|data)$/i.test(name))?.[0]
  const withoutSignature: Record<string, unknown> = { ...record }
  delete withoutSignature[signatureField]
  const event = eventField ? withoutSignature[eventField] : withoutSignature
  const asText = (value: unknown): string => typeof value === 'string' ? value : (JSON.stringify(value) ?? String(value))
  const comparable = eventField ? event : Object.fromEntries(Object.entries(withoutSignature).filter(([name]) =>
    name !== keyField && name !== timestampField))
  const result: InlineWebhookSignature = {
    valid: false,
    delivery: JSON.stringify(comparable),
    keyField,
    signatureField,
  }
  const candidates: string[] = []
  if (timestampField && withoutSignature[timestampField] !== undefined) {
    candidates.push(`${String(withoutSignature[timestampField])}.${asText(event)}`)
    candidates.push(`${String(withoutSignature[timestampField])}.${JSON.stringify(withoutSignature)}`)
  }
  candidates.push(asText(event), JSON.stringify(withoutSignature))
  for (const canonical of candidates) {
    const hex = createHmac('sha256', key).update(canonical).digest('hex')
    const base64 = createHmac('sha256', key).update(canonical).digest('base64')
    if (signature === hex || signature === base64) return { ...result, valid: true }
  }
  return result
}

function webhookAcknowledged(step: ImpactStep): boolean {
  const visit = (value: unknown, depth: number): boolean => {
    if (depth > 4 || !value || typeof value !== 'object') return false
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (/^(?:ok|received|processed|accepted|success)$/i.test(key) &&
          (child === true || (typeof child === 'string' && /^(?:true|processed|accepted|received)$/i.test(child)))) return true
      if (visit(child, depth + 1)) return true
    }
    return false
  }
  return visit(step.json, 0)
}

function webhookReadbackBound(steps: readonly ImpactStep[], probeIndex: number, request: ImpactStep['requestJson']): boolean {
  const ids = new Set<string>()
  const visit = (value: unknown, depth: number): void => {
    if (depth > 4 || !value || typeof value !== 'object') return
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (/(?:^|_)(?:id|uuid)$/i.test(key) && typeof child === 'string' && child.length <= 128) ids.add(child)
      visit(child, depth + 1)
    }
  }
  visit(request, 0)
  return ids.size > 0 && steps.slice(probeIndex + 1).some(step => {
    if (!/^(?:GET|HEAD|OPTIONS)$/i.test(step.method ?? '') || !is2xxStatus(step.status)) return false
    const response = step.body ?? (step.json !== undefined ? JSON.stringify(step.json) : '')
    return [...ids].some(id => response.includes(id))
  })
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
  const { rule, impactClass } = receiptRuleFor(receipt.vulnClass, receipt)
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
    const extractCarrierRequestBody = (entry: ReceiptTranscriptEntry): string | undefined => {
      if (typeof entry.step.requestJson === 'string' && entry.step.requestJson.length > 0) return entry.step.requestJson
      if (entry.step.requestJson !== undefined || !entry.carrierText) return undefined
      const lines = entry.carrierText.split('\n').map(l => l.trim()).filter(Boolean)
      for (let i = lines.length - 1; i >= 0; i -= 1) {
        const line = lines[i]!
        if (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\//i.test(line)) continue
        if (/^[A-Za-z0-9-]+:\s/.test(line)) continue
        return line
      }
      return undefined
    }
    const toArm = (entry: ReceiptTranscriptEntry): BooleanDifferentialArm => {
      const requestBody = extractCarrierRequestBody(entry)
      return {
        status: entry.step.status,
        method: entry.step.method,
        pathAndQuery: entry.step.pathAndQuery,
        ...(entry.step.requestJson !== undefined ? { requestJson: entry.step.requestJson } : {}),
        ...(requestBody !== undefined ? { requestBody } : {}),
        requestHeaders: entry.step.requestHeaders ?? null,
        ...(entry.step.json !== undefined ? { json: entry.step.json } : {}),
        ...(entry.step.body !== undefined ? { body: entry.step.body } : {}),
      }
    }
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
    const uniqueIds = new Set(receipt.exchangeIds)
    if (uniqueIds.size !== receipt.exchangeIds.length) {
      return reject(receipt, rule, 'A timing receipt must not cite duplicate exchange IDs across control and probe arms.')
    }
    const timed = receipt.exchangeIds.map(id => entriesById.get(id)!)
    const controls = timed.filter(entry => entry.step.arm === 'control')
    const probes = timed.filter(entry => entry.step.arm === 'probe')
    if (controls.length === 0 || probes.length === 0) {
      return reject(receipt, rule, 'A timing receipt needs at least one control arm and one probe arm.')
    }
    // H-15: Every control and probe exchange MUST target the exact same normalized origin,
    // HTTP method, route path, and persona so a fast route or different persona cannot be paired
    // against a legitimately slow route/persona to forge a blind_sqli timing confirmation.
    const normalizedActorOf = (entry: ReceiptTranscriptEntry): string => (entry.step.actor.handle ?? '').trim().toLowerCase()
    const baseMethod = controls[0]!.step.method.toUpperCase()
    const baseRoute = routeOf(controls[0]!.step)
    const basePersona = normalizedActorOf(controls[0]!)
    const baseOrigin = controls[0]!.origin ? normalizeOrigin(controls[0]!.origin) : null
    const targetOrigin = normalizeOrigin(receipt.target.origin)
    const targetRoute = receipt.target.pathAndQuery ? normalizePath(receipt.target.pathAndQuery) : null
    for (const entry of [...controls, ...probes]) {
      const method = entry.step.method.toUpperCase()
      if (method !== baseMethod) {
        return reject(receipt, rule, `Timing arms must use the exact same HTTP method (${baseMethod} vs ${method}).`)
      }
      if (receipt.target.method && method !== receipt.target.method) {
        return reject(receipt, rule, `Timing exchange method (${method}) does not match receipt target (${receipt.target.method}).`)
      }
      const route = routeOf(entry.step)
      if (route !== baseRoute) {
        return reject(receipt, rule, `Timing arms must target the exact same route (${baseRoute || '/'} vs ${route || '/'}).`)
      }
      if (targetRoute && route && route !== targetRoute) {
        return reject(receipt, rule, `Timing exchange route (${route}) does not match receipt target (${targetRoute}).`)
      }
      const persona = normalizedActorOf(entry)
      if (persona !== basePersona) {
        return reject(receipt, rule, `Timing arms must execute under the exact same persona (${basePersona || 'anonymous'} vs ${persona || 'anonymous'}).`)
      }
      if (entry.origin) {
        const entryOrigin = normalizeOrigin(entry.origin)
        if (baseOrigin && entryOrigin !== baseOrigin) {
          return reject(receipt, rule, `Timing arms must target the exact same origin (${baseOrigin} vs ${entryOrigin}).`)
        }
        if (entryOrigin !== targetOrigin) {
          return reject(receipt, rule, `Timing exchange origin (${entryOrigin}) does not match receipt target (${targetOrigin}).`)
        }
      }
    }
    const controlDurations = controls.map(entry => entry.durationMs ?? entry.step.durationMs ?? 0)
    const probeDurations = probes.map(entry => entry.durationMs ?? entry.step.durationMs ?? 0)
    if (controlDurations.some(d => d <= 0) || probeDurations.some(d => d <= 0)) {
      return reject(receipt, rule, 'Timing receipt exchanges must record their wall-clock duration.')
    }
    const sortedProbes = [...probeDurations].sort((a, b) => a - b)
    const mid = Math.floor(sortedProbes.length / 2)
    const probeMs = sortedProbes.length % 2 === 1
      ? sortedProbes[mid]!
      : (sortedProbes[mid - 1]! + sortedProbes[mid]!) / 2
    const controlMs = Math.max(...controlDurations)
    if (controlMs >= 1_000) return reject(receipt, rule, `The control took ${controlMs} ms, so a delay is not distinguishable from normal latency.`)
    if (probeMs < Math.max(1_000, controlMs * 3)) {
      return reject(receipt, rule, `Probe ${probeMs} ms is not a stable separation from the ${controlMs} ms control.`)
    }
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: `The probe arm took ${probeMs} ms (median) against a ${controlMs} ms control (>3x separation) on ${baseMethod} ${baseRoute || targetRoute || '/'}.`,
      observed: receipt.claimedDelta,
      expected: 'comparable latency between control and probe',
      evidence: { controlMs, probeMs, method: baseMethod, route: baseRoute || targetRoute || '/', persona: basePersona || null },
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
    const canaryPattern = (receipt.proofPatterns ?? []).find(pattern => safeRegexTest(pattern, location))
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

  if (rule === 'webhook') {
    if (receipt.exchangeIds.length < 2) return reject(receipt, rule, 'An inline-key webhook receipt needs a rejected control and an accepted probe delivery.')
    const entries = receipt.exchangeIds.map(id => entriesById.get(id)!)
    const control = entries.find(entry => entry.step.arm === 'control' && entry.step.status !== null &&
      entry.step.status >= 400 && entry.step.status < 500)
    const probe = entries.find(entry => entry.step.arm === 'probe' && is2xxStatus(entry.step.status))
    if (!control || !probe) return reject(receipt, rule, 'An inline-key webhook receipt needs a 4xx control and a 2xx probe on the recorded receiver route.')
    if (control.step.method.toUpperCase() !== probe.step.method.toUpperCase() || routeOf(control.step) !== routeOf(probe.step)) {
      return reject(receipt, rule, 'The webhook control and probe deliveries do not target the same method and route.')
    }
    if ((control.step.actor.handle ?? null) !== (probe.step.actor.handle ?? null)) {
      return reject(receipt, rule, 'The webhook control and probe deliveries use different actors.')
    }
    if (receipt.target.method && receipt.target.method.toUpperCase() !== probe.step.method.toUpperCase()) {
      return reject(receipt, rule, 'The webhook receipt target method does not match the accepted delivery.')
    }
    if (receipt.target.pathAndQuery && normalizePath(receipt.target.pathAndQuery) !== routeOf(probe.step)) {
      return reject(receipt, rule, 'The webhook receipt target route does not match the accepted delivery.')
    }
    if ((control.origin && normalizeOrigin(control.origin) !== normalizeOrigin(receipt.target.origin)) ||
        (probe.origin && normalizeOrigin(probe.origin) !== normalizeOrigin(receipt.target.origin))) {
      return reject(receipt, rule, 'The webhook delivery origin does not match the receipt target.')
    }
    const controlSignature = inlineWebhookSignature(control.step)
    const probeSignature = inlineWebhookSignature(probe.step)
    if (!controlSignature || !probeSignature) return reject(receipt, rule, 'The host-recorded webhook bodies do not carry inline key/signature fields.')
    if (controlSignature.valid) return reject(receipt, rule, 'The webhook control signature is valid; it is not a tampered-signature control.')
    if (!probeSignature.valid) return reject(receipt, rule, 'The accepted webhook probe body does not carry a valid signature under its inline key.')
    if (controlSignature.keyField !== probeSignature.keyField || controlSignature.signatureField !== probeSignature.signatureField) {
      return reject(receipt, rule, 'The webhook control and probe use different inline key/signature fields.')
    }
    if (controlSignature.delivery !== probeSignature.delivery) {
      return reject(receipt, rule, 'The webhook control and probe differ beyond their key, timestamp, and signature fields.')
    }
    const steps = entries.map(entry => entry.step)
    const probeIndex = steps.indexOf(probe.step)
    if (!webhookAcknowledged(probe.step) && !webhookReadbackBound(steps, probeIndex, probe.step.requestJson)) {
      return reject(receipt, rule, 'The accepted webhook delivery has neither a processing acknowledgement nor an identifier-bound readback.')
    }
    return {
      confirmed: true,
      vulnClass: receipt.vulnClass,
      rule,
      reason: 'A tampered inline signature was rejected while the same delivery signed with an attacker-supplied inline key was accepted and acknowledged.',
      observed: receipt.claimedDelta,
      expected: 'webhook deliveries signed with an attacker-supplied key are rejected',
      evidence: { controlExchangeId: control.exchangeId, probeExchangeId: probe.exchangeId },
    }
  }

  if (rule === 'conserved_balance') {
    const transcriptOrder = new Map(entries.map((entry, idx) => [entry.exchangeId, idx]))
    return verifyConservedBalanceReceipt(receipt, entriesById, transcriptOrder)
  }

  if (rule === 'auth_bypass') {
    return verifyAuthBypassReceipt(receipt, entriesById, entries)
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
    if (impactClass === 'injection') {
      const evaluated = verifyEvaluatedExpression(receipt, entriesById)
      if (evaluated) return evaluated
    }
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
  // Defense-in-depth precision guard for read-only object-level BOLA/IDOR (CWE-639): a bare
  // collection GET without an object identifier must carry explicit cross-tenant or foreign-owner
  // disclosure evidence (never an inverted higher-role 401/403 vs lower-role own-collection 200).
  if (!mutatingProbe && /^(?:bola|idor|cross_tenant|cross_tenant_read)$/i.test(receipt.vulnClass)) {
    const readProbe = steps.find(step => step.arm === 'probe' && is2xxStatus(step.status))
    if (readProbe && !isObjectScopedRequest(readProbe)) {
      const evidence = assessment.evidence as { crossTenant?: boolean } | undefined
      const hasForeign = evidence?.crossTenant === true ||
        hasForeignTenantOrOwnerDisclosure(steps, readProbe, receipt.resourceTenant ?? null)
      if (!hasForeign) {
        return reject(
          receipt,
          rule,
          `Bare collection GET (${readProbe.route ?? readProbe.pathAndQuery ?? '/'}) without an object identifier cannot confirm ${receipt.vulnClass} without explicit cross-tenant or foreign-owner data disclosure.`,
        )
      }
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

function hostRequestDebitOf(step: ImpactStep): number | null {
  if (step.requestJson && typeof step.requestJson === 'object' && !Array.isArray(step.requestJson)) {
    const fields = extractNumericFields(step.requestJson)
    for (const [field, value] of fields.entries()) {
      const leaf = field.split('.').pop() ?? field
      if (REQUEST_DEBIT_FIELD_RE.test(leaf) && value > 0) return value
    }
  }
  return null
}

function entryHostOrder(entry: ReceiptTranscriptEntry, transcriptOrder: ReadonlyMap<string, number>): number {
  if (typeof entry.seq === 'number' && Number.isFinite(entry.seq)) return entry.seq
  return transcriptOrder.get(entry.exchangeId) ?? 0
}

function entryWindow(entry: ReceiptTranscriptEntry): { start: number; end: number } | null {
  if (typeof entry.startedAt !== 'number' || !Number.isFinite(entry.startedAt)) return null
  const start = entry.startedAt
  const end = typeof entry.endedAt === 'number' && Number.isFinite(entry.endedAt)
    ? Math.max(start, entry.endedAt)
    : start + Math.max(0, entry.durationMs ?? entry.step.durationMs ?? 0)
  return { start, end }
}

/**
 * Fail-closed `conserved_balance` receipt rule for race / double-spend / inventory-oversell proofs.
 * Requires host-recorded transcript evidence of:
 *   1. A 2xx baseline numeric readback strictly before the burst in host transcript order,
 *   2. >=2 acknowledged (2xx) concurrent burst mutations with genuine temporal overlap when
 *      host timestamps are recorded (rejecting 5xx/4xx-only or strictly sequential bursts),
 *   3. A 2xx post-burst numeric readback strictly after the burst in host transcript order on the
 *      same conserved field proving a conservation violation (under-debit, negative balance/stock,
 *      or cap/quota overshoot — never status-only),
 *   4. A passing serial control exchange proving the conservation boundary holds serially, with
 *      per-mutation debit derived/bounded strictly from host-recorded exchanges.
 */
function verifyConservedBalanceReceipt(
  receipt: ProofReceipt,
  entriesById: ReadonlyMap<string, ReceiptTranscriptEntry>,
  transcriptOrder: ReadonlyMap<string, number>,
): ReceiptVerification {
  const rule = 'conserved_balance' as const
  if (receipt.exchangeIds.length < 4) {
    return reject(
      receipt,
      rule,
      'A conserved_balance receipt requires baseline readback, >=2 burst mutations, post-burst readback, and a serial control.',
    )
  }
  // C-5: Never trust worker-supplied `receipt.exchangeIds` array order. Deduplicate and sort
  // deterministically by host transcript sequence/order (with host `startedAt` as tie-breaker).
  const uniqueIds = [...new Set(receipt.exchangeIds)]
  if (uniqueIds.length !== receipt.exchangeIds.length) {
    return reject(receipt, rule, 'A conserved_balance receipt must not reuse the same exchange ID across roles.')
  }
  const cited = uniqueIds
    .map(id => entriesById.get(id)!)
    .sort((a, b) => {
      const orderDiff = entryHostOrder(a, transcriptOrder) - entryHostOrder(b, transcriptOrder)
      if (orderDiff !== 0) return orderDiff
      const startA = typeof a.startedAt === 'number' ? a.startedAt : 0
      const startB = typeof b.startedAt === 'number' ? b.startedAt : 0
      return startA - startB
    })
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

  // C-5: Verify genuine temporal concurrency overlap across acknowledged burst exchanges whenever
  // host timestamps are present. Strictly sequential HTTP requests cannot prove a race condition.
  const ackedWindows = ackedBurst.map(entryWindow).filter((w): w is { start: number; end: number } => w !== null)
  if (ackedWindows.length >= 2) {
    let hasOverlap = false
    for (let i = 0; i < ackedWindows.length && !hasOverlap; i += 1) {
      for (let j = i + 1; j < ackedWindows.length; j += 1) {
        const a = ackedWindows[i]!
        const b = ackedWindows[j]!
        if (a.start <= b.end && b.start <= a.end) {
          hasOverlap = true
          break
        }
      }
    }
    if (!hasOverlap) {
      return reject(
        receipt,
        rule,
        'Burst exchanges did not overlap in time in the host transcript; strictly sequential requests cannot prove a race condition.',
      )
    }
  }

  // C-5: Enforce strict host chronological ordering for baseline and post-burst readbacks.
  const misplacedBaseline = cited.findIndex((entry, index) => index >= firstBurstIdx && BASELINE_READ_ROLES.has(roleOf(entry)))
  if (misplacedBaseline >= 0) {
    return reject(receipt, rule, 'Baseline readback must occur chronologically before the concurrent burst in the host transcript.')
  }
  const misplacedPost = cited.findIndex((entry, index) => index <= lastBurstIdx && POST_READ_ROLES.has(roleOf(entry)))
  if (misplacedPost >= 0) {
    return reject(receipt, rule, 'Post-burst readback must occur chronologically after the concurrent burst in the host transcript.')
  }

  // Locate baseline readback (strictly before the burst in host order).
  let baselineIdx = cited.findIndex((entry, index) => index < firstBurstIdx && BASELINE_READ_ROLES.has(roleOf(entry)))
  if (baselineIdx < 0) {
    baselineIdx = cited.findIndex((entry, index) => {
      if (index >= firstBurstIdx) return false
      const r = roleOf(entry)
      if (POST_READ_ROLES.has(r) || SERIAL_PRE_ROLES.has(r) || SERIAL_POST_ROLES.has(r) || SERIAL_MUTATION_ROLE_RE.test(r) || BURST_ROLE_RE.test(r)) {
        return false
      }
      return (entry.step.arm === 'setup' || entry.step.arm === 'control') && is2xxStatus(entry.step.status)
    })
  }
  if (baselineIdx < 0 || !is2xxStatus(cited[baselineIdx]!.step.status)) {
    return reject(receipt, rule, 'A conserved_balance receipt requires a 2xx baseline numeric readback before the burst.')
  }
  const baselineEntry = cited[baselineIdx]!

  // Locate post-burst readback (strictly after the burst in host order, before any serial post-read).
  let postIdx = cited.findIndex((entry, index) => index > lastBurstIdx && POST_READ_ROLES.has(roleOf(entry)))
  if (postIdx < 0) {
    postIdx = cited.findIndex((entry, index) =>
      index > lastBurstIdx &&
      !BASELINE_READ_ROLES.has(roleOf(entry)) &&
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

  // Timestamp sanity check when host timestamps are recorded: baseline cannot start after burst,
  // and post-burst readback cannot start before burst.
  if (ackedWindows.length > 0) {
    const minBurstStart = Math.min(...ackedWindows.map(w => w.start))
    const maxBurstEnd = Math.max(...ackedWindows.map(w => w.end))
    const baseWin = entryWindow(baselineEntry)
    const postWin = entryWindow(postEntry)
    if (baseWin && baseWin.start > maxBurstEnd) {
      return reject(receipt, rule, 'Baseline readback timestamp is after the concurrent burst in the host transcript.')
    }
    if (postWin && postWin.start < minBurstStart) {
      return reject(receipt, rule, 'Post-burst readback timestamp precedes the concurrent burst in the host transcript.')
    }
  }

  const conserved = sharedConservedField(baselineEntry.step, postEntry.step, receipt.conservedBalance?.balanceField)
  if (!conserved) {
    return reject(
      receipt,
      rule,
      'Baseline and post-burst readbacks lack a shared numeric conserved field (status-only differential without numeric delta is rejected).',
    )
  }

  const actualBurstDebit = conserved.pre - conserved.post
  const cap = findCapValue(baselineEntry.step, postEntry.step, conserved.field, receipt.conservedBalance?.capField)

  // Locate serial control exchanges (must not be interleaved inside the burst).
  const serialIndices: number[] = []
  cited.forEach((entry, index) => {
    if (index === baselineIdx || index === postIdx || burstIndices.includes(index)) return
    const role = roleOf(entry)
    if (SERIAL_PRE_ROLES.has(role) || SERIAL_POST_ROLES.has(role)) return
    if (SERIAL_MUTATION_ROLE_RE.test(role) || (entry.step.arm === 'control' && stepMutatesState(entry.step))) {
      serialIndices.push(index)
    }
  })
  if (serialIndices.some(idx => idx > firstBurstIdx && idx < lastBurstIdx)) {
    return reject(receipt, rule, 'Serial control exchanges must not be interleaved inside the concurrent burst.')
  }
  const serialMutations = serialIndices.map(i => cited[i]!)
  const serialPreIdx = cited.findIndex(entry => SERIAL_PRE_ROLES.has(roleOf(entry)))
  const serialPreEntry = serialPreIdx >= 0 ? cited[serialPreIdx] : undefined
  const serialPostIdx = cited.findIndex((entry, index) =>
    index !== baselineIdx && index !== postIdx && !burstIndices.includes(index) && SERIAL_POST_ROLES.has(roleOf(entry)))
  const serialPostEntry = serialPostIdx >= 0 ? cited[serialPostIdx] : undefined

  if (serialMutations.length === 0) {
    return reject(receipt, rule, 'A conserved_balance receipt requires a serial control exchange proving the conservation boundary holds serially.')
  }
  const lastSerialIdx = serialIndices[serialIndices.length - 1]!
  if (serialPostIdx >= 0 && serialPostIdx < lastSerialIdx) {
    return reject(receipt, rule, 'Serial post-readback must occur chronologically after the serial control mutation in the host transcript.')
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
  const declaredUnitDebit = receipt.conservedBalance?.unitDebit
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
    const serialHostDebits = serial2xx.map(entry => hostRequestDebitOf(entry.step))
    const allSerialHostDebits = serialHostDebits.every((d): d is number => d !== null)
    const expectedSerialDebit = allSerialHostDebits
      ? serialHostDebits.reduce((sum, d) => sum + d, 0)
      : serial2xx.length * (declaredUnitDebit ?? 1)
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

  // C-5: Derive/bound expectedBurstDebit strictly from host-recorded exchanges — NEVER trust an
  // uncorroborated worker-supplied `unitDebit` to fabricate an `under_debit` violation!
  const burstHostDebits = ackedBurst.map(entry => hostRequestDebitOf(entry.step))
  const allBurstHostDebits = burstHostDebits.every((d): d is number => d !== null)
  let expectedBurstDebit: number
  let hasHostDerivedDebit = false
  if (allBurstHostDebits) {
    expectedBurstDebit = burstHostDebits.reduce((sum, d) => sum + d, 0)
    hasHostDerivedDebit = true
  } else if (serialControlKind === 'serial_debit_exact' && serialDebitObserved !== null && serialDebitObserved > 1e-6) {
    const derivedHostUnitDebit = serialDebitObserved / serial2xx.length
    // Bound any declared unitDebit to never exceed the host-observed serial per-mutation debit.
    const effectiveUnitDebit = declaredUnitDebit !== undefined
      ? Math.min(declaredUnitDebit, derivedHostUnitDebit)
      : derivedHostUnitDebit
    expectedBurstDebit = ackedBurst.length * effectiveUnitDebit
    hasHostDerivedDebit = true
  } else {
    // No host request body debit and no 2xx serial debit: worker-supplied unitDebit is untrusted.
    expectedBurstDebit = ackedBurst.length
    hasHostDerivedDebit = false
  }

  // Evaluate conservation violation on the concurrent burst.
  let violationKind: 'under_debit' | 'negative_balance' | 'cap_overshoot' | 'over_credit' | null = null
  if (conserved.pre >= 0 && conserved.post < 0) {
    violationKind = 'negative_balance'
  } else if (cap && conserved.pre <= cap.value && conserved.post > cap.value) {
    violationKind = 'cap_overshoot'
  } else if (conserved.pre >= 0 && conserved.post >= 0 && actualBurstDebit < expectedBurstDebit - 1e-6) {
    // Require host-derived debit AND concrete movement (under_debit cannot rely on worker unitDebit).
    const provedMutating = actualBurstDebit > 1e-6 || (serialDebitObserved !== null && serialDebitObserved > 1e-6)
    if (hasHostDerivedDebit && provedMutating) {
      violationKind = 'under_debit'
    } else if (serialControlKind === 'serial_rejection' && conserved.post > conserved.pre + 1e-6) {
      // Single-use credit/coupon race: >=2 concurrent redemptions credited the balance while a
      // subsequent serial redemption was rejected with 4xx.
      violationKind = 'over_credit'
    }
  } else if (serialControlKind === 'serial_rejection' && conserved.pre >= 0 && conserved.post > conserved.pre + 1e-6) {
    violationKind = 'over_credit'
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

const AUTH_BYPASS_BOILERPLATE_KEY_RE = /^(?:ok|status|success|message|msg|error|errors|detail|details|code|timestamp|time|date|version|health|healthy|alive|ping|pong|request_?id|trace_?id|correlation_?id|nonce)$/i
const AUTH_BYPASS_VOLATILE_HEADER_RE = /^(?:host|content-length|connection|user-agent|accept|accept-encoding|x-request-id|x-correlation-id|x-trace-id|traceparent|tracestate|date)$/i
const AUTH_BYPASS_SECURITY_HEADER_RE = /^(?:authorization|proxy-authorization|x-forwarded-(?:for|host|proto|user|email|groups|roles|uri|url)|x-original-(?:url|uri|forwarded-for)|x-rewrite-url|x-real-ip|x-client-ip|x-remote-(?:user|addr|ip)|x-custom-ip-authorization|x-user(?:name|-id|-role)?|x-auth(?:[-_].+)?|x-admin(?:[-_].+)?|x-role(?:s)?|x-api-key|x-token(?:[-_].+)?|x-bypass(?:[-_].+)?|x-internal(?:[-_].+)?|forwarded|client-ip|true-client-ip|cf-connecting-ip|x-impersonate(?:[-_].+)?|x-tenant(?:[-_].+)?)$/i
const SEALED_OR_VAULT_MARKER_RE = /(?:\[redacted:(?:cap:)?|cap:hop_[A-Za-z0-9._-]+:|\[persona:)/i
const ANON_HANDLE_RE = /^(?:anon|anonymous|guest|unauthenticated)$/i
const AUTH_ROLE_RANK: Readonly<Record<string, number>> = { viewer: 1, member: 2, admin: 3, owner: 4 }

function normalizedAuthHandle(handle: string | null | undefined): string | null {
  if (!handle) return null
  const trimmed = handle.trim().toLowerCase()
  if (!trimmed || ANON_HANDLE_RE.test(trimmed)) return null
  return trimmed
}

function authRoleRank(role: RoleName | null | undefined): number {
  return role ? (AUTH_ROLE_RANK[role] ?? 0) : 0
}

function queryPartOf(pathAndQuery: string | undefined): string {
  if (!pathAndQuery) return ''
  const idx = pathAndQuery.indexOf('?')
  return idx >= 0 ? pathAndQuery.slice(idx + 1).trim() : ''
}

function canonicalRequestHeaderMap(headers: Record<string, string> | null | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!headers) return out
  for (const [k, v] of Object.entries(headers)) {
    const lower = k.trim().toLowerCase()
    if (!lower || AUTH_BYPASS_VOLATILE_HEADER_RE.test(lower)) continue
    out[lower] = String(v)
  }
  return out
}

function authBypassRequestDifferential(
  control: ImpactStep,
  probe: ImpactStep,
): 'header' | 'query' | 'body' | null {
  const controlHeaders = canonicalRequestHeaderMap(control.requestHeaders)
  const probeHeaders = canonicalRequestHeaderMap(probe.requestHeaders)
  const headerKeys = new Set([...Object.keys(controlHeaders), ...Object.keys(probeHeaders)])
  for (const key of headerKeys) {
    if (key === 'cookie') continue
    if (!AUTH_BYPASS_SECURITY_HEADER_RE.test(key)) continue
    if (controlHeaders[key] !== probeHeaders[key]) return 'header'
  }
  if (queryPartOf(control.pathAndQuery) !== queryPartOf(probe.pathAndQuery)) return 'query'
  if (JSON.stringify(control.requestJson ?? null) !== JSON.stringify(probe.requestJson ?? null)) return 'body'
  return null
}

function probeCarriedHostCredentialControlLacked(
  control: ReceiptTranscriptEntry,
  probe: ReceiptTranscriptEntry,
  allEntries: readonly ReceiptTranscriptEntry[],
): string | null {
  const ctlHandle = normalizedAuthHandle(control.step.actor.handle)
  const prbHandle = normalizedAuthHandle(probe.step.actor.handle)
  if (prbHandle !== null && prbHandle !== ctlHandle) {
    if (ctlHandle === null) {
      return `Normal authenticated persona "${probe.step.actor.handle}" crossing an unauthenticated 401 is standard login, not an authentication bypass.`
    }
    return `Auth bypass rejected: probe used a different authenticated persona ("${probe.step.actor.handle}" vs control "${control.step.actor.handle}"); switching personas is not an authentication bypass.`
  }
  if (authRoleRank(probe.step.actor.role) > authRoleRank(control.step.actor.role)) {
    return `Auth bypass rejected: probe carried higher role privileges ("${probe.step.actor.role}" vs control "${control.step.actor.role ?? 'none'}"); normal RBAC is not an authentication bypass.`
  }

  // Sealed capability check: reject if probe consumed any host-sealed capability that control lacked.
  const ctlCaps = new Set<string>([
    ...(control.consumedCapabilityId ? [control.consumedCapabilityId] : []),
    ...(control.consumedCapabilities ?? []),
  ])
  const prbCaps = [
    ...(probe.consumedCapabilityId ? [probe.consumedCapabilityId] : []),
    ...(probe.consumedCapabilities ?? []),
  ]
  if (prbCaps.some(cap => !ctlCaps.has(cap))) {
    return 'Auth bypass rejected: probe carried a host-sealed capability that the control lacked (authenticated session reuse is not an authentication bypass).'
  }
  const ctlHeaders = canonicalRequestHeaderMap(control.step.requestHeaders)
  const prbHeaders = canonicalRequestHeaderMap(probe.step.requestHeaders)
  for (const [k, v] of Object.entries(prbHeaders)) {
    if (SEALED_OR_VAULT_MARKER_RE.test(v) && ctlHeaders[k] !== v) {
      return 'Auth bypass rejected: probe carried a sealed capability or vault credential header that the control lacked.'
    }
  }

  // Session jar / cookie check: reject if probe carried a cookie or distinct session jar that control lacked.
  if (prbHeaders.cookie && prbHeaders.cookie !== ctlHeaders.cookie) {
    return 'Auth bypass rejected: probe carried a session cookie that the control lacked (session-jar authentication is not an authentication bypass).'
  }
  if (probe.sessionId && probe.sessionId !== control.sessionId) {
    return 'Auth bypass rejected: probe used an authenticated session jar that the control lacked.'
  }

  // Login-issued token check: if probe sent an Authorization token that matches a token returned by
  // an earlier 2xx response in the host transcript, it is a real login credential, not a forgery.
  const prbAuth = prbHeaders.authorization
  if (prbAuth && prbAuth !== ctlHeaders.authorization) {
    const rawToken = prbAuth.replace(/^(?:Bearer|Token|Basic)\s+/i, '').trim()
    if (rawToken.length >= 12) {
      for (const prior of allEntries) {
        if (prior.exchangeId === probe.exchangeId || prior.exchangeId === control.exchangeId) continue
        if (!is2xxStatus(prior.step.status)) continue
        const priorBody = typeof prior.step.body === 'string'
          ? prior.step.body
          : prior.step.json !== undefined ? JSON.stringify(prior.step.json) : ''
        const priorSetCookie = headerValue(prior.step.responseHeaders, 'set-cookie') ?? ''
        if (priorBody.includes(rawToken) || priorSetCookie.includes(rawToken)) {
          return 'Auth bypass rejected: probe used a credential issued by a prior 2xx login/token exchange in the host transcript (normal authentication, not a bypass).'
        }
      }
    }
  }
  return null
}

function collectSubstantiveAuthDataFields(value: unknown, prefix = '', depth = 0, out: string[] = []): string[] {
  if (depth > 4 || out.length >= 16 || value === null || value === undefined) return out
  if (Array.isArray(value)) {
    if (value.length === 0) return out
    for (let i = 0; i < Math.min(value.length, 4); i += 1) {
      const item = value[i]
      if (item && typeof item === 'object') {
        collectSubstantiveAuthDataFields(item, `${prefix}[${i}]`, depth + 1, out)
      } else if (typeof item === 'string' ? item.trim().length > 0 : item !== null && item !== undefined) {
        const leaf = prefix.split('.').pop()?.replace(/\[\d+\]$/, '') ?? ''
        if (leaf && !AUTH_BYPASS_BOILERPLATE_KEY_RE.test(leaf)) out.push(prefix)
        break
      }
    }
    return out
  }
  if (typeof value !== 'object') return out
  const entries = Object.entries(value as Record<string, unknown>)
  // Error-only envelopes (`{ error: "..." }`) never prove protected account data was returned.
  const nonErrorKeys = entries.filter(([k]) => !/^(?:error|errors|message|msg|detail|details|status|code|ok|success)$/i.test(k))
  if (depth === 0 && nonErrorKeys.length === 0) return out
  for (const [key, child] of entries) {
    const path = prefix ? `${prefix}.${key}` : key
    if (child && typeof child === 'object') {
      collectSubstantiveAuthDataFields(child, path, depth + 1, out)
    } else if (!AUTH_BYPASS_BOILERPLATE_KEY_RE.test(key)) {
      const nonEmpty = typeof child === 'string'
        ? child.trim().length > 0
        : child !== null && child !== undefined
      if (nonEmpty) out.push(path)
    }
  }
  return out
}

/**
 * Fail-closed `auth_bypass` receipt rule (`CWE-287` / `CWE-347`):
 * Proves authentication bypass or forged-token access on a protected route.
 * Requires:
 *  1. A 401/403 control on the exact same route & HTTP method (proving the route IS gated, never public),
 *  2. A 2xx probe on the same route & method carrying a distinct auth header/token, bypass query param,
 *     or request body differential (never a normal Layer-1 vault-persona login crossing an anon-401!),
 *  3. Substantive structured private/account data in the probe response distinct from the control
 *     (rejecting status-only, empty, boilerplate `{ok:true}`, error-only, and HTML shell responses).
 */
function verifyAuthBypassReceipt(
  receipt: ProofReceipt,
  entriesById: ReadonlyMap<string, ReceiptTranscriptEntry>,
  allEntries: readonly ReceiptTranscriptEntry[] = [...entriesById.values()],
): ReceiptVerification {
  const rule = 'auth_bypass' as const
  if (receipt.exchangeIds.length < 2) {
    return reject(receipt, rule, 'An auth_bypass receipt requires a denied (401/403) control and a bypassing 2xx probe exchange.')
  }
  const cited = receipt.exchangeIds.map(id => entriesById.get(id)!)
  const controls = cited.filter(entry => entry.step.arm === 'control')
  const probes = cited.filter(entry => entry.step.arm === 'probe')
  if (controls.length === 0 || probes.length === 0) {
    return reject(receipt, rule, 'An auth_bypass receipt requires at least one control arm and one probe arm.')
  }

  const deniedControls = controls.filter(entry => entry.step.status === 401 || entry.step.status === 403)
  if (deniedControls.length === 0) {
    return reject(
      receipt,
      rule,
      'Auth bypass rejected: no control exchange was denied with 401 or 403 on the target route (a public or ungated endpoint is not an authentication bypass).',
    )
  }

  const okProbes = probes.filter(entry => is2xxStatus(entry.step.status))
  if (okProbes.length === 0) {
    return reject(receipt, rule, 'Auth bypass rejected: no probe exchange succeeded with a 2xx status.')
  }

  let matchedPair: {
    control: ReceiptTranscriptEntry
    probe: ReceiptTranscriptEntry
    differential: 'header' | 'query' | 'body'
    dataFields: string[]
  } | null = null
  let lastRejection = 'No control/probe pair on the same protected route demonstrated a valid authentication bypass.'

  for (const probe of okProbes) {
    const probeRoute = routeOf(probe.step)
    const probeMethod = probe.step.method.toUpperCase()
    if (receipt.target.method && probeMethod !== receipt.target.method) {
      lastRejection = `The probe method (${probeMethod}) does not match the receipt target (${receipt.target.method}).`
      continue
    }
    if (receipt.target.pathAndQuery && probeRoute !== normalizePath(receipt.target.pathAndQuery)) {
      lastRejection = `The probe route (${probeRoute}) does not match the receipt target (${normalizePath(receipt.target.pathAndQuery)}).`
      continue
    }
    const sameRouteControls = deniedControls.filter(
      control => routeOf(control.step) === probeRoute && control.step.method.toUpperCase() === probeMethod,
    )
    if (sameRouteControls.length === 0) {
      lastRejection = `No 401/403 control exists on the exact same route and method (${probeMethod} ${probeRoute}).`
      continue
    }
    for (const control of sameRouteControls) {
      // H-14: Reject if probe carried ANY host credential (vault persona, higher role/admin,
      // sealed capability, session cookie/jar, or login-issued token) that the control lacked.
      const credRejection = probeCarriedHostCredentialControlLacked(control, probe, allEntries)
      if (credRejection) {
        lastRejection = credRejection
        continue
      }
      const differential = authBypassRequestDifferential(control.step, probe.step)
      if (!differential) {
        lastRejection = 'Control and probe requests carry no distinct auth header, forged token, bypass parameter, or request body differential.'
        continue
      }
      const probeBodyRaw = typeof probe.step.body === 'string'
        ? probe.step.body
        : probe.step.json !== undefined ? JSON.stringify(probe.step.json) : ''
      const controlBodyRaw = typeof control.step.body === 'string'
        ? control.step.body
        : control.step.json !== undefined ? JSON.stringify(control.step.json) : ''
      const probeTrim = probeBodyRaw.trim()
      if (probeTrim.length < 12) {
        lastRejection = 'Auth bypass rejected: probe returned an empty or trivially short body (status-only 2xx is never proof).'
        continue
      }
      if (probeTrim === controlBodyRaw.trim()) {
        lastRejection = 'Auth bypass rejected: probe response body is identical to the denied control response.'
        continue
      }
      const parsedJson = parseStepJson(probe.step)
      if (parsedJson !== undefined) {
        const fields = collectSubstantiveAuthDataFields(parsedJson)
        if (fields.length === 0) {
          lastRejection = 'Auth bypass rejected: probe JSON contains only generic status/boilerplate/error keys and no structured private or account data.'
          continue
        }
        matchedPair = { control, probe, differential, dataFields: fields }
        break
      }
      // Non-JSON response: reject HTML shells/login pages and trivial text; require substantive data.
      if (/^(?:<!doctype\s+html|<html\b)/i.test(probeTrim)) {
        lastRejection = 'Auth bypass rejected: probe returned an HTML document/shell rather than structured protected data.'
        continue
      }
      if (probeTrim.length < 24 || /^(?:ok|success|true|done|accepted|pong)$/i.test(probeTrim)) {
        lastRejection = 'Auth bypass rejected: probe response lacks substantive protected data (status-only/trivial text).'
        continue
      }
      matchedPair = { control, probe, differential, dataFields: ['text_body'] }
      break
    }
    if (matchedPair) break
  }

  if (!matchedPair) {
    return reject(receipt, rule, lastRejection)
  }

  return {
    confirmed: true,
    vulnClass: receipt.vulnClass,
    rule,
    reason: `Authentication bypass confirmed on ${matchedPair.probe.step.method.toUpperCase()} ${routeOf(matchedPair.probe.step)}: control denied (${matchedPair.control.step.status}) while probe with distinct ${matchedPair.differential} bypass returned ${matchedPair.probe.step.status} with structured protected data (${matchedPair.dataFields.slice(0, 6).join(', ')}).`,
    observed: receipt.claimedDelta,
    expected: 'forged tokens, bypass headers, or unauthenticated bypass parameters are rejected identically to the 401/403 control',
    evidence: {
      controlStatus: matchedPair.control.step.status,
      probeStatus: matchedPair.probe.step.status,
      route: routeOf(matchedPair.probe.step),
      differentialKind: matchedPair.differential,
      dataFields: matchedPair.dataFields.slice(0, 8),
    },
  }
}

/**
 * Fail-closed evaluated-expression oracle for SSTI / server-side expression evaluation (`CWE-1336`).
 * Requires:
 *  1. Same route family across a 2xx control and 2xx probe with distinct request inputs,
 *  2. An explicit non-trivial expected marker (`proofPatterns`, length >= 4),
 *  3. Strict anti-reflection: the marker appears in the probe response body, is ABSENT from every
 *     control response body, AND is ABSENT from the probe request itself (path, headers, body).
 */
function verifyEvaluatedExpression(
  receipt: ProofReceipt,
  entriesById: ReadonlyMap<string, ReceiptTranscriptEntry>,
): ReceiptVerification | null {
  const patterns = (receipt.proofPatterns ?? []).filter(p => p.length >= 4)
  if (patterns.length === 0) return null
  const cited = receipt.exchangeIds.map(id => entriesById.get(id)!)
  const controls = cited.filter(entry => entry.step.arm === 'control' && is2xxStatus(entry.step.status))
  const probes = cited.filter(entry => entry.step.arm === 'probe' && is2xxStatus(entry.step.status))
  if (controls.length === 0 || probes.length === 0) return null
  const bodyOf = (step: ImpactStep): string =>
    typeof step.body === 'string' ? step.body : step.json !== undefined ? JSON.stringify(step.json) : ''
  const requestTextOf = (entry: ReceiptTranscriptEntry): string => {
    const parts = [
      entry.step.pathAndQuery ?? '',
      entry.step.requestJson !== undefined ? JSON.stringify(entry.step.requestJson) : '',
      entry.step.requestHeaders ? JSON.stringify(entry.step.requestHeaders) : '',
    ]
    const raw = parts.join('\n')
    try { return `${raw}\n${decodeURIComponent(raw)}` } catch { return raw }
  }
  const controlBodies = controls.map(c => bodyOf(c.step)).join('\n')
  for (const probe of probes) {
    const probeRoute = routeOf(probe.step)
    const matchingControl = controls.find(control => {
      if (routeOf(control.step) !== probeRoute) return false
      const samePath = (control.step.pathAndQuery ?? '') === (probe.step.pathAndQuery ?? '')
      const sameBody = JSON.stringify(control.step.requestJson ?? null) === JSON.stringify(probe.step.requestJson ?? null)
      return !(samePath && sameBody)
    })
    if (!matchingControl) continue
    const probeBody = bodyOf(probe.step)
    const probeReqText = requestTextOf(probe)
    for (const marker of patterns) {
      if (!probeBody.includes(marker)) continue
      if (controlBodies.includes(marker)) continue
      // Anti-reflection: a marker present verbatim in the request is reflection, not evaluation.
      if (probeReqText.includes(marker)) continue
      return {
        confirmed: true,
        vulnClass: receipt.vulnClass,
        rule: 'impact',
        reason: `Server-side expression evaluation confirmed: computed marker "${marker}" appeared in the probe response while absent from both the control response and the probe request (non-reflected).`,
        observed: receipt.claimedDelta,
        expected: 'user input is rendered literally without server-side expression evaluation',
        evidence: { evaluatedMarker: marker, route: probeRoute, antiReflectionPassed: true },
      }
    }
  }
  return null
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
    const controlUrl = new URL(control.step.pathAndQuery ?? '', 'http://kovo.invalid')
    const probeUrl = new URL(probe.step.pathAndQuery ?? '', 'http://kovo.invalid')
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
  /** Host-recorded monotonic transcript sequence index (never worker-ordered). */
  seq?: number
  /** Host-recorded request start timestamp (epoch ms). */
  startedAt?: number
  /** Host-recorded request end timestamp (epoch ms). */
  endedAt?: number
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
  /** Host-resolved ambient credential placement (`cookie`, `bearer`, `header`, `unknown`). */
  ambientAuth?: ImpactStep['actor']['auth']
  /** Host-observed SameSite attribute on the session cookie (`Strict`, `Lax`, `None`, or null). */
  sessionSameSite?: string | null
  /** Host-recorded primary sealed capability consumed by this exchange (if any). */
  consumedCapabilityId?: string | null
  /** Host-recorded sealed capabilities consumed by this exchange (if any). */
  consumedCapabilities?: readonly string[]
  /** Host-recorded session jar identifier (if any). */
  sessionId?: string | null
  /** Host-recorded OOB or structured artifact (for `op: 'oob'` mint/wait/check records). */
  artifact?: {
    kind?: string
    token?: string
    url?: string
    dnsHost?: string
    hit?: boolean
    subscriptionId?: string
    canaryId?: string
    receivedAtMs?: number
  } | null
  body?: string
  requestBody?: string | null
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

/**
 * Derive a receipt from a confirmed script run. `claims` are used only to select the class,
 * target, and exchange IDs; all request bodies, actor roles/tenants, ambient auth, SameSite,
 * and exchange ordering are derived strictly from the immutable `HostFactLog`.
 */
export function buildAgentScriptReceipt(input: {
  claims: readonly Record<string, unknown>[]
  exchanges: readonly ScriptProofExchange[]
  /** Optional pre-populated immutable HostFactLog (takes precedence over `exchanges`). */
  factLog?: HostFactLog
  /** Host-recorded OOB callback events (for `kind === 'oob'` claims). */
  oobEvents?: readonly ReceiptOobEvent[]
  origin: string
  title: string
}): {
  receipt: ProofReceipt
  transcript: ReceiptTranscript
  factLog: HostFactLog
  armOverrides: Map<string, ImpactStep['arm']>
  evidenceRoleOverrides?: Map<string, string>
} | null {
  const factLog = input.factLog ?? HostFactLog.fromScriptExchanges(input.exchanges, input.oobEvents)
  const byId = new Map(input.exchanges.map(exchange => [exchange.exchangeId, exchange]))
  const hasExchange = (id: string): boolean => Boolean(factLog.getExchange(id) || byId.has(id))
  const sortByHostOrder = (ids: readonly string[]): string[] =>
    factLog.orderedExchanges(ids).map(fact => fact.exchangeId)
  const buildTranscript = (
    armOverrides: ReadonlyMap<string, ImpactStep['arm']>,
    extra?: {
      evidenceRoleOverrides?: ReadonlyMap<string, string>
    },
  ): ReceiptTranscript => factLog.toReceiptTranscript({
    armOverrides,
    ...(extra?.evidenceRoleOverrides ? { evidenceRoleOverrides: extra.evidenceRoleOverrides } : {}),
  })
  const cited = (ids: readonly string[]) => ids.filter(hasExchange)

  for (const claim of input.claims) {
    if (recordField(claim, 'kind') !== 'impact') continue
    const impactClass = recordField(claim, 'impactClass')
    if (typeof impactClass !== 'string') continue
    const rawVulnClass = recordField(claim, 'vulnClass')
    const explicitVuln = typeof rawVulnClass === 'string' ? rawVulnClass.trim().toLowerCase() : ''
    const vulnClass = explicitVuln && AUTH_BYPASS_CLASS_RE.test(explicitVuln)
      ? explicitVuln
      : impactClass === 'injection' && /^(?:sqli|sql_injection)$/i.test(explicitVuln)
        ? 'sqli_error'
        : explicitVuln && IMPACT_CLASS_BY_VULN[explicitVuln] === impactClass
          ? explicitVuln
          : IMPACT_CLASS_TO_VULN_CLASS[impactClass]
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
    const exchangeIds = sortByHostOrder([
      ...(beforeId ? [beforeId] : []),
      ...controlIds,
      probeId,
      ...(afterId ? [afterId] : []),
    ])
    if (exchangeIds.length === 0) continue
    const armOverrides = new Map<string, ImpactStep['arm']>()
    for (const id of controlIds) armOverrides.set(id, 'control')
    if (beforeId) armOverrides.set(beforeId, 'control')
    if (afterId) armOverrides.set(afterId, 'control')
    armOverrides.set(probeId, 'probe')
    // H-13: Never trust script-declared `requestBody`, `ambient`, `sameSite`, or `oracleEvents`.
    // Request bodies, ambient auth kind, SameSite, and host-observed oracle events are derived
    // strictly from host-recorded TranscriptStore exchanges and headers.
    const transcript = buildTranscript(armOverrides)
    const hostOracleEvents: string[] = []
    if (impactClass === 'csrf' && beforeId && afterId) {
      const probeEntry = transcript.entries?.find(e => e.exchangeId === probeId)
      const probeStep = probeEntry?.step
      if (probeStep && is2xxStatus(probeStep.status) && stepMutatesState(probeStep) && probeStep.actor.auth === 'cookie') {
        const ss = (probeStep.actor.sameSite ?? '').toLowerCase()
        const originHdr = headerValue(probeStep.requestHeaders, 'origin') ?? headerValue(probeStep.requestHeaders, 'referer')
        const targetHost = hostOf(probe.origin || input.origin)
        const reqHost = hostOf(originHdr)
        if (ss !== 'strict' && ss !== 'lax' && targetHost && reqHost && reqHost !== targetHost) {
          hostOracleEvents.push('csrf_state_change')
        }
      }
    }
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
        ...(recordField(claim, 'expectControlDenied') === true ? { expectControlDenied: true } : {}),
        ...(hostOracleEvents.length ? { oracleEvents: hostOracleEvents } : {}),
        ...(proofPatterns.length ? { proofPatterns } : {}),
      }),
      transcript,
      factLog,
      armOverrides,
    }
  }

  for (const claim of input.claims) {
    if (recordField(claim, 'kind') !== 'boundary') continue
    const rawBoundaryClass = recordField(claim, 'boundaryClass')
    if (typeof rawBoundaryClass !== 'string') continue
    const boundaryClass = rawBoundaryClass.toLowerCase()
    if (boundaryClass !== 'access' && boundaryClass !== 'auth') continue
    const controlId = recordField(claim, 'controlExchangeId')
    const probeId = recordField(claim, 'probeExchangeId')
    if (typeof controlId !== 'string' || typeof probeId !== 'string') continue
    const control = byId.get(controlId)
    const probe = byId.get(probeId)
    if (!control || !probe) continue
    const rawVuln = typeof recordField(claim, 'vulnClass') === 'string'
      ? (recordField(claim, 'vulnClass') as string).trim().toLowerCase()
      : ''
    // H-14: A probe carrying a persona, sealed capability, session jar, or cookie that the control
    // lacked cannot auto-classify as an unauthenticated auth_bypass.
    const probeHasHostCredential = Boolean(
      normalizedAuthHandle(probe.personaHandle) ||
      probe.consumedCapabilityId ||
      (probe.consumedCapabilities && probe.consumedCapabilities.length > 0) ||
      (probe.sessionId && probe.sessionId !== control.sessionId) ||
      (headerValue(probe.requestHeaders, 'cookie') && headerValue(probe.requestHeaders, 'cookie') !== headerValue(control.requestHeaders, 'cookie')),
    )
    const isAuthBypass = AUTH_BYPASS_CLASS_RE.test(rawVuln) ||
      (boundaryClass === 'auth' && !rawVuln && !normalizedAuthHandle(control.personaHandle) && !probeHasHostCredential)
    const probeMethod = probe.method.toUpperCase()
    // Mutating BOLA/BFLA boundary claims require persisted before/after readbacks (`impact` claim);
    // only non-mutating read boundaries map directly onto `bola`/`bfla`. Auth bypass / forged-token
    // proofs on protected endpoints may use GET/HEAD/POST when control is 401/403 and probe returns
    // structured protected data.
    if (isAuthBypass) {
      if (probeMethod !== 'GET' && probeMethod !== 'HEAD' && probeMethod !== 'POST') continue
    } else if (probeMethod !== 'GET' && probeMethod !== 'HEAD') {
      continue
    }
    const vulnClass = rawVuln && (AUTH_BYPASS_CLASS_RE.test(rawVuln) || IMPACT_CLASS_BY_VULN[rawVuln])
      ? rawVuln
      : isAuthBypass
        ? 'auth_bypass'
        : boundaryClass === 'auth'
          ? 'bfla'
          : 'bola'
    const exchangeIds = sortByHostOrder([controlId, probeId])
    const armOverrides = new Map<string, ImpactStep['arm']>([
      [controlId, 'control'],
      [probeId, 'probe'],
    ])
    const transcript = buildTranscript(armOverrides)
    const expectControlDenied = recordField(claim, 'expectControlDenied') !== false
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
        claimedDelta: `${input.title} — ${isAuthBypass ? 'authentication' : 'access'} boundary crossed (${control.status ?? 'n/a'} control vs ${probe.status ?? 'n/a'} probe).`.slice(0, 1200),
        expectControlDenied,
      }),
      transcript,
      factLog,
      armOverrides,
    }
  }

  // Paired non-reflected evaluated-expression claims (`body_contains` absent on control + present
  // on probe for the same >=4-char marker, emitted by `ctx.prove_injection_differential`).
  // Checked BEFORE `structural_diff` because `prove_injection_differential` also emits a 2-round
  // `structural_diff` claim for the Layer-3 injection semantic oracle.
  const bodyClaims = input.claims.filter(claim =>
    recordField(claim, 'kind') === 'body_contains' &&
    typeof recordField(claim, 'exchangeId') === 'string' &&
    typeof recordField(claim, 'text') === 'string' &&
    (recordField(claim, 'text') as string).length >= 4)
  for (const present of bodyClaims) {
    if (recordField(present, 'absent') === true) continue
    const marker = recordField(present, 'text') as string
    const probeId = recordField(present, 'exchangeId') as string
    const probe = byId.get(probeId)
    if (!probe) continue
    const absent = bodyClaims.find(c =>
      recordField(c, 'absent') === true &&
      recordField(c, 'text') === marker &&
      typeof recordField(c, 'exchangeId') === 'string' &&
      recordField(c, 'exchangeId') !== probeId &&
      hasExchange(recordField(c, 'exchangeId') as string))
    if (!absent) continue
    const controlId = recordField(absent, 'exchangeId') as string
    const exchangeIds = sortByHostOrder([controlId, probeId])
    const armOverrides = new Map<string, ImpactStep['arm']>([
      [controlId, 'control'],
      [probeId, 'probe'],
    ])
    // Request bodies come strictly from immutable HostFactLog — never from worker claim scalars.
    const transcript = buildTranscript(armOverrides)
    const rawExplicit = typeof recordField(present, 'vulnClass') === 'string'
      ? (recordField(present, 'vulnClass') as string).trim().toLowerCase()
      : ''
    const msg = `${input.title} ${String(recordField(present, 'message') ?? '')}`.toLowerCase()
    const vulnClass = rawExplicit && IMPACT_CLASS_BY_VULN[rawExplicit] === 'injection'
      ? rawExplicit
      : /^(?:sqli|sql_injection)$/i.test(rawExplicit)
        ? 'sqli_error'
        : /command|cmdi|os.command|rce/.test(msg)
          ? 'command_injection'
          : /ssti|template/.test(msg)
            ? 'ssti'
            : 'injection'
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
        claimedDelta: `${input.title} — evaluated marker "${marker}" observed only in probe response.`.slice(0, 1200),
        proofPatterns: [marker],
      }),
      transcript,
      factLog,
      armOverrides,
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
        factLog,
        armOverrides,
      }
    }
    if (kind === 'timing') {
      const controls = [...new Set(cited(stringArray(recordField(claim, 'controlIds'))))]
      const variants = [...new Set(cited(stringArray(recordField(claim, 'variantIds'))))]
      if (controls.length < 5 || variants.length < 5) continue
      const controlSet = new Set(controls)
      if (variants.some(id => controlSet.has(id))) continue
      const probe = byId.get(variants[0]!)
      const baseline = byId.get(controls[0]!)
      if (!probe || !baseline) continue
      // H-15: Every control and variant exchange MUST target the exact same normalized origin,
      // HTTP method, route path, and persona.
      const baseOrigin = normalizeOrigin(baseline.origin || input.origin)
      const baseMethod = baseline.method.toUpperCase()
      const baseRoute = normalizePath(baseline.pathAndQuery)
      const basePersona = (baseline.personaHandle ?? '').trim().toLowerCase()
      const allConsistent = [...controls, ...variants].every(id => {
        const ex = byId.get(id)!
        return normalizeOrigin(ex.origin || input.origin) === baseOrigin
          && ex.method.toUpperCase() === baseMethod
          && normalizePath(ex.pathAndQuery) === baseRoute
          && (ex.personaHandle ?? '').trim().toLowerCase() === basePersona
      })
      if (!allConsistent) continue
      const armOverrides = new Map<string, ImpactStep['arm']>()
      for (const id of controls) armOverrides.set(id, 'control')
      for (const id of variants) armOverrides.set(id, 'probe')
      const transcript = buildTranscript(armOverrides)
      const controlEntry = transcript.entries!.find(entry => entry.exchangeId === controls[0])
      const probeEntry = transcript.entries!.find(entry => entry.exchangeId === variants[0])
      const param = controlEntry && probeEntry ? deriveDifferingParam(controlEntry, probeEntry) : null
      return {
        receipt: buildProofReceipt({
          vulnClass: 'blind_sqli',
          target: {
            origin: probe.origin || input.origin,
            method: probe.method.toUpperCase(),
            pathAndQuery: probe.pathAndQuery,
            ...(param ? { param } : {}),
          },
          exchangeIds: sortByHostOrder([...controls, ...variants]),
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: `${input.title} — timing separation over ${controls.length}/${variants.length} recorded arms.`.slice(0, 1200),
        }),
        transcript,
        factLog,
        armOverrides,
      }
    }
    if (kind === 'conserved_balance' || kind === 'race') {
      const rawBaseline = recordField(claim, 'baselineExchangeId') ?? recordField(claim, 'beforeExchangeId')
      const baselineId = typeof rawBaseline === 'string' && byId.has(rawBaseline) ? rawBaseline : null
      const rawPost = recordField(claim, 'postExchangeId') ?? recordField(claim, 'afterExchangeId')
      const postId = typeof rawPost === 'string' && byId.has(rawPost) ? rawPost : null
      const burstIds = [...new Set(cited(stringArray(recordField(claim, 'burstExchangeIds') ?? recordField(claim, 'exchangeIds'))))]
      const serialIds = [...new Set(cited(stringArray(recordField(claim, 'serialExchangeIds') ?? recordField(claim, 'controlExchangeIds'))))]
      const rawSerialPre = recordField(claim, 'serialPreExchangeId')
      const serialPreId = typeof rawSerialPre === 'string' && byId.has(rawSerialPre) ? rawSerialPre : null
      const rawSerialPost = recordField(claim, 'serialPostExchangeId')
      const serialPostId = typeof rawSerialPost === 'string' && byId.has(rawSerialPost) ? rawSerialPost : null
      if (!baselineId || !postId || burstIds.length < 2 || serialIds.length === 0) continue
      // C-5: Every role must refer to a disjoint host exchange ID (no role aliasing).
      const roleIdList = [
        baselineId,
        ...burstIds,
        postId,
        ...(serialPreId ? [serialPreId] : []),
        ...serialIds,
        ...(serialPostId ? [serialPostId] : []),
      ]
      if (new Set(roleIdList).size !== roleIdList.length) continue
      const sortedBurstIds = sortByHostOrder(burstIds)
      const sortedSerialIds = sortByHostOrder(serialIds)
      const firstBurst = byId.get(sortedBurstIds[0]!)
      if (!firstBurst) continue
      const armOverrides = new Map<string, ImpactStep['arm']>()
      const evidenceRoleOverrides = new Map<string, string>()
      armOverrides.set(baselineId, 'setup')
      evidenceRoleOverrides.set(baselineId, 'baseline_read')
      sortedBurstIds.forEach((id, index) => {
        armOverrides.set(id, 'probe')
        evidenceRoleOverrides.set(id, `burst_${index + 1}`)
      })
      armOverrides.set(postId, 'control')
      evidenceRoleOverrides.set(postId, 'post_read')
      if (serialPreId) {
        armOverrides.set(serialPreId, 'control')
        evidenceRoleOverrides.set(serialPreId, 'serial_pre_read')
      }
      sortedSerialIds.forEach((id, index) => {
        armOverrides.set(id, 'control')
        evidenceRoleOverrides.set(id, `serial_control_${index + 1}`)
      })
      if (serialPostId) {
        armOverrides.set(serialPostId, 'control')
        evidenceRoleOverrides.set(serialPostId, 'serial_post_read')
      }
      // C-5: Always sort exchangeIds deterministically by host transcript order — NEVER trust
      // worker-supplied array order, claim `requestBody`, or uncorroborated `unitDebit`.
      const exchangeIds = sortByHostOrder(roleIdList)
      const transcript = buildTranscript(armOverrides, {
        evidenceRoleOverrides,
      })
      const rawClass = recordField(claim, 'vulnClass')
      const vulnClass = typeof rawClass === 'string' && CONSERVED_BALANCE_CLASS_RE.test(rawClass.trim())
        ? rawClass.trim()
        : 'race_double_spend'
      const balanceField = typeof recordField(claim, 'balanceField') === 'string' ? (recordField(claim, 'balanceField') as string).trim() : ''
      const capField = typeof recordField(claim, 'capField') === 'string' ? (recordField(claim, 'capField') as string).trim() : ''
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
          claimedDelta: `${input.title} — conserved-balance race over ${sortedBurstIds.length} burst + ${sortedSerialIds.length} serial control exchange(s).`.slice(0, 1200),
          ...(balanceField || capField
            ? {
                conservedBalance: {
                  ...(balanceField ? { balanceField } : {}),
                  ...(capField ? { capField } : {}),
                },
              }
            : {}),
        }),
        transcript,
        factLog,
        armOverrides,
        evidenceRoleOverrides,
      }
    }
  }

  // H-20: Out-of-band (`prove.oob`) receipt branch — converts a host-verified OOB callback into a
  // standard `ProofReceipt` via `buildOobReceipt` using host OOB events + mint/injection/wait IDs.
  for (const claim of input.claims) {
    if (recordField(claim, 'kind') !== 'oob') continue
    if (recordField(claim, 'expectHit') === false) continue
    const rawMintId = recordField(claim, 'exchangeId') ?? recordField(claim, 'mintExchangeId')
    const mintId = typeof rawMintId === 'string' && byId.has(rawMintId) ? rawMintId : null
    const mintExchange = mintId ? byId.get(mintId) : undefined
    const rawWaitId = recordField(claim, 'waitExchangeId')
    const explicitWaitId = typeof rawWaitId === 'string' && byId.has(rawWaitId) ? rawWaitId : null
    const rawInjectId = recordField(claim, 'injectionExchangeId') ?? recordField(claim, 'carrierExchangeId')
    const explicitInjectId = typeof rawInjectId === 'string' && byId.has(rawInjectId) ? rawInjectId : null
    const rawOobEventId = recordField(claim, 'oobEventId') ?? recordField(claim, 'subscriptionId')
    const explicitOobEventId = typeof rawOobEventId === 'string' && rawOobEventId.trim() ? rawOobEventId.trim() : null

    const mintToken = mintExchange?.artifact?.token?.trim() || null
    const hostOobEvents = input.oobEvents ?? []
    let oobEvent: ReceiptOobEvent | null = null
    if (hostOobEvents.length > 0) {
      oobEvent = hostOobEvents.find(ev =>
        ev.delivered && Boolean(ev.token) &&
        ((explicitOobEventId && ev.id === explicitOobEventId) ||
          (mintToken && ev.token?.toLowerCase() === mintToken.toLowerCase()) ||
          (!explicitOobEventId && !mintToken)),
      ) ?? null
    }
    let derivedWaitId: string | null = explicitWaitId
    if (!oobEvent) {
      const waitRecord = (explicitWaitId ? byId.get(explicitWaitId) : undefined)
        ?? input.exchanges.find(ex =>
          ex.op === 'oob' &&
          ex.artifact?.hit === true &&
          Boolean(ex.artifact?.token) &&
          (!mintToken || ex.artifact!.token!.toLowerCase() === mintToken.toLowerCase()),
        )
      if (waitRecord?.artifact?.hit === true && waitRecord.artifact.token) {
        derivedWaitId = waitRecord.exchangeId
        const subMatch = /^\/oob\/pending\/([^/?#]+)/.exec(waitRecord.pathAndQuery ?? '')
        const derivedId = explicitOobEventId
          ?? waitRecord.artifact.subscriptionId
          ?? subMatch?.[1]
          ?? waitRecord.exchangeId
        oobEvent = {
          id: derivedId,
          ...(waitRecord.artifact.canaryId ? { canaryId: waitRecord.artifact.canaryId } : {}),
          token: waitRecord.artifact.token,
          targetOrigin: input.origin,
          delivered: true,
          stage: 'immediate',
          receivedAtMs: waitRecord.artifact.receivedAtMs ?? waitRecord.endedAt ?? waitRecord.startedAt ?? Date.now(),
        }
      }
    }
    if (!oobEvent || !oobEvent.delivered || !oobEvent.token) continue

    const token = oobEvent.token
    const carriesToken = (ex: ScriptProofExchange): boolean => {
      if (ex.op === 'oob') return false
      if ((ex.pathAndQuery ?? '').includes(token)) return true
      if ((ex.requestBody ?? '').includes(token)) return true
      if ((ex.body ?? '').includes(token)) return true
      if (ex.requestHeaders && Object.values(ex.requestHeaders).some(v => String(v).includes(token))) return true
      return false
    }
    const explicitCarrier = explicitInjectId ? byId.get(explicitInjectId) : undefined
    const carryingExchanges = explicitCarrier && carriesToken(explicitCarrier)
      ? [explicitCarrier]
      : input.exchanges.filter(carriesToken)
    const primaryCarrier = carryingExchanges[0] ?? explicitCarrier ?? null
    const exchangeIds = sortByHostOrder([
      ...(mintId ? [mintId] : []),
      ...carryingExchanges.map(ex => ex.exchangeId),
      ...(explicitCarrier ? [explicitCarrier.exchangeId] : []),
      ...(derivedWaitId ? [derivedWaitId] : []),
    ])
    if (exchangeIds.length === 0) continue

    const armOverrides = new Map<string, ImpactStep['arm']>()
    for (const ex of carryingExchanges) armOverrides.set(ex.exchangeId, 'probe')
    if (mintId && !armOverrides.has(mintId)) armOverrides.set(mintId, 'setup')
    if (derivedWaitId && !armOverrides.has(derivedWaitId)) armOverrides.set(derivedWaitId, 'control')
    const baseTranscript = buildTranscript(armOverrides)
    const rawVuln = typeof recordField(claim, 'vulnClass') === 'string'
      ? (recordField(claim, 'vulnClass') as string).trim().toLowerCase()
      : ''
    const msg = `${input.title} ${String(recordField(claim, 'message') ?? '')}`.toLowerCase()
    const vulnClass = rawVuln && OOB_CLASS_RE.test(rawVuln)
      ? rawVuln
      : /\bxxe\b|xml external/.test(msg)
        ? 'xxe'
        : /\bssrf\b|server-side request/.test(msg)
          ? 'ssrf'
          : /webhook/.test(msg)
            ? 'webhook_forgery'
            : 'oob'
    const injectedAtMs = primaryCarrier?.startedAt ?? oobEvent.injectedAtMs
    const normalizedOobEvent: ReceiptOobEvent = {
      ...oobEvent,
      ...(oobEvent.targetOrigin ? {} : { targetOrigin: primaryCarrier?.origin || input.origin }),
      ...(injectedAtMs !== undefined && oobEvent.injectedAtMs === undefined ? { injectedAtMs } : {}),
    }
    factLog.recordOobEvent(normalizedOobEvent)
    return {
      receipt: buildOobReceipt({
        vulnClass,
        origin: primaryCarrier?.origin || input.origin,
        ...(primaryCarrier?.method ? { method: primaryCarrier.method.toUpperCase() } : {}),
        ...(primaryCarrier?.pathAndQuery ? { pathAndQuery: primaryCarrier.pathAndQuery } : {}),
        exchangeIds,
        oobEventId: normalizedOobEvent.id,
        claimedDelta: `${input.title} — host-verified out-of-band callback (${normalizedOobEvent.id}) delivered after canary injection.`.slice(0, 1200),
        ...(injectedAtMs !== undefined ? { injectedAtMs } : {}),
      }),
      transcript: {
        ...baseTranscript,
        oobEvents: [normalizedOobEvent],
      },
      factLog,
      armOverrides,
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

export type ProofReceiptMode = 'off' | 'shadow' | 'strict'

/**
 * Confirmation gate mode for legacy declarative replay specs:
 *  - `strict` (default): `verifyReceipt()` is the final confirmation gate and vetoes any
 *    unsubstantiated DSL confirmation (never widens a non-confirming verdict).
 *  - `shadow` / `advisory`: records the receipt without changing the DSL verdict (explicit env
 *    override for parity/regression tests).
 *  - `off` / `0` / `false` / `no`: disables receipt evaluation on legacy DSL replays.
 */
export function proofReceiptMode(env: NodeJS.ProcessEnv = process.env): ProofReceiptMode {
  const raw = (env.KOVO_PROOF_RECEIPT ?? '').trim().toLowerCase()
  if (raw === '0' || raw === 'off' || raw === 'false' || raw === 'no') return 'off'
  if (raw === 'shadow' || raw === 'advisory') return 'shadow'
  return 'strict'
}

export const MAX_REPLAY_REGEX_PATTERN_LENGTH = 256
export const MAX_REPLAY_REGEX_HAYSTACK_LENGTH = 16 * 1024

/**
 * H-32: Structural ReDoS guard for worker- and model-supplied regexes running on the host event
 * loop. Rejects overly long patterns (> 256 chars), control chars, backreferences, lookbehinds,
 * nested quantifiers (including `{m,n}` and nested groups), quantified alternations, stacked
 * quantifiers, unbounded chained wildcards, and huge explicit repetition bounds.
 */
export function isSafeRegexPattern(pattern: string, maxLength = MAX_REPLAY_REGEX_PATTERN_LENGTH): boolean {
  if (typeof pattern !== 'string' || pattern.length === 0 || pattern.length > maxLength) return false
  if (/[\0\r\n]/.test(pattern)) return false
  if (/\\[1-9]|\\k</.test(pattern)) return false
  if (/\(\?<[=!]/.test(pattern)) return false
  if (/(?:\.\*|\.\+){2,}/.test(pattern)) return false
  if (/(\\[wsdWSD])[*+]\s*\1[*+]/.test(pattern)) return false

  type Frame = { hasQuantifier: boolean; hasAlternation: boolean; isLookahead: boolean }
  const stack: Frame[] = [{ hasQuantifier: false, hasAlternation: false, isLookahead: false }]
  let inClass = false
  let prevWasQuantifier = false
  let prevTokenKind: 'none' | 'atom' | 'group' | 'lookahead' = 'none'
  let lastClosedGroup: Frame | null = null

  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i]!
    if (ch === '\\') {
      i += 1
      if (i >= pattern.length) return false
      if (!inClass) { prevWasQuantifier = false; prevTokenKind = 'atom'; lastClosedGroup = null }
      continue
    }
    if (inClass) {
      if (ch === ']') { inClass = false; prevWasQuantifier = false; prevTokenKind = 'atom'; lastClosedGroup = null }
      continue
    }
    if (ch === '[') { inClass = true; continue }
    if (ch === '(') {
      const isLookahead = pattern[i + 1] === '?' && (pattern[i + 2] === '=' || pattern[i + 2] === '!')
      stack.push({ hasQuantifier: false, hasAlternation: false, isLookahead })
      prevWasQuantifier = false; prevTokenKind = 'none'; lastClosedGroup = null
      continue
    }
    if (ch === ')') {
      if (stack.length <= 1) return false
      const closed = stack.pop()!
      if (closed.hasQuantifier) stack[stack.length - 1]!.hasQuantifier = true
      lastClosedGroup = closed
      prevWasQuantifier = false
      prevTokenKind = closed.isLookahead ? 'lookahead' : 'group'
      continue
    }
    if (ch === '|') {
      stack[stack.length - 1]!.hasAlternation = true
      prevWasQuantifier = false; prevTokenKind = 'none'; lastClosedGroup = null
      continue
    }
    const isStarPlus = ch === '*' || ch === '+'
    const isBrace = ch === '{'
    if (isStarPlus || isBrace) {
      let repeatsAtLeastTwo = isStarPlus
      if (isBrace) {
        const endBrace = pattern.indexOf('}', i + 1)
        if (endBrace === -1) return false
        const m = /^(\d+)(?:,(\d*))?$/.exec(pattern.slice(i + 1, endBrace))
        if (!m) { prevWasQuantifier = false; prevTokenKind = 'atom'; lastClosedGroup = null; continue }
        const min = Number(m[1])
        const max = m[2] === undefined ? min : (m[2] === '' ? Infinity : Number(m[2]))
        if (min > 64 || (Number.isFinite(max) && max > 64) || max < min) return false
        repeatsAtLeastTwo = max >= 2
        i = endBrace
      }
      if (pattern[i + 1] === '?') i += 1
      if (prevWasQuantifier || prevTokenKind === 'lookahead') return false
      if (repeatsAtLeastTwo && prevTokenKind === 'group' && lastClosedGroup && (lastClosedGroup.hasQuantifier || lastClosedGroup.hasAlternation)) return false
      if (repeatsAtLeastTwo) stack[stack.length - 1]!.hasQuantifier = true
      prevWasQuantifier = true; lastClosedGroup = null
      continue
    }
    if (ch === '?') {
      if (prevWasQuantifier) return false
      prevWasQuantifier = true
      continue
    }
    prevWasQuantifier = false; prevTokenKind = 'atom'; lastClosedGroup = null
  }
  if (inClass || stack.length !== 1) return false
  try { new RegExp(pattern); return true } catch { return false }
}

export function safeRegexTest(
  pattern: string,
  haystack: string,
  opts?: { maxPatternLength?: number; maxHaystackLength?: number },
): boolean {
  if (!isSafeRegexPattern(pattern, opts?.maxPatternLength ?? MAX_REPLAY_REGEX_PATTERN_LENGTH)) return false
  const capped = typeof haystack === 'string'
    ? haystack.slice(0, opts?.maxHaystackLength ?? MAX_REPLAY_REGEX_HAYSTACK_LENGTH)
    : ''
  try { return new RegExp(pattern).test(capped) } catch { return false }
}

const ALLOWED_RECIPES_BY_SPEC_KIND: Readonly<Record<string, ReadonlySet<string>>> = {
  browser_chain: new Set(['browser_sink']),
  sql_boolean_diff: new Set(['boolean_or_timing']),
  sql_time_diff: new Set(['boolean_or_timing']),
  race_burst: new Set(['conserved_balance', 'race_burst']),
  http_chain: new Set([
    'access_boundary', 'persisted_mutation', 'boolean_or_timing', 'oob_callback',
    'race_burst', 'disclosure', 'redirect', 'injection_fingerprint', 'conserved_balance',
  ]),
}

/**
 * H-5: Strict provenance, scope, Tier-0, denylist, and allowlist gate for `recipe` envelopes.
 */
export function validateReplayRecipeEnvelope(input: {
  specKind: string
  specOrigin: string
  recipeId: string
  recipeArgs: Record<string, unknown>
  recipeOrigin: string
  envelopeTrust?: 'host_persisted' | 'untrusted'
  tier: number
  canRead: (origin: string) => boolean
  hasDestructive: (serialized: string) => boolean
  hasStoredMatch?: () => boolean
}): { ok: true } | { ok: false; reason: string } {
  if (input.envelopeTrust === 'untrusted') {
    return { ok: false, reason: 'Untrusted model-supplied recipe envelope rejected by verification kernel.' }
  }
  if (input.specKind === 'static_ast_proof') {
    return { ok: false, reason: 'static_ast_proof cannot carry or execute a live floor recipe envelope.' }
  }
  if (input.tier === 0) {
    return { ok: false, reason: 'Live recipe execution is disabled in Tier 0.' }
  }
  const allowed = ALLOWED_RECIPES_BY_SPEC_KIND[input.specKind]
  if (!allowed || !allowed.has(input.recipeId)) {
    return { ok: false, reason: `Recipe "${input.recipeId}" is not allowlisted for spec kind "${input.specKind}".` }
  }
  if (input.hasDestructive(JSON.stringify({ recipeId: input.recipeId, args: input.recipeArgs }))) {
    return { ok: false, reason: 'Recipe envelope rejected by destructive-payload denylist.' }
  }
  const specOriginNorm = normalizeOrigin(input.specOrigin)
  const origins = new Set<string>()
  if (input.recipeOrigin) origins.add(input.recipeOrigin)
  for (const key of ['origin', 'targetOrigin'] as const) {
    const val = input.recipeArgs[key]
    if (typeof val === 'string' && val.trim()) origins.add(val.trim())
  }
  if (Array.isArray(input.recipeArgs.steps)) {
    for (const s of input.recipeArgs.steps) {
      if (s && typeof s === 'object' && typeof (s as { origin?: unknown }).origin === 'string') {
        const o = (s as { origin: string }).origin.trim()
        if (o) origins.add(o)
      }
    }
  }
  for (const origin of origins) {
    if (!input.canRead(origin)) return { ok: false, reason: `Recipe envelope origin ${origin} is not in approved scope.` }
    if (specOriginNorm && normalizeOrigin(origin) !== specOriginNorm) {
      return { ok: false, reason: `Recipe envelope origin (${origin}) does not match spec origin (${input.specOrigin}).` }
    }
  }
  if (input.recipeId === 'boolean_or_timing') {
    const ctlPath = typeof input.recipeArgs.controlPathAndQuery === 'string' ? input.recipeArgs.controlPathAndQuery : null
    const prbPath = typeof input.recipeArgs.probePathAndQuery === 'string' ? input.recipeArgs.probePathAndQuery : null
    if (ctlPath && prbPath && normalizePath(ctlPath) !== normalizePath(prbPath)) {
      return { ok: false, reason: `boolean_or_timing recipe control route (${normalizePath(ctlPath)}) does not match probe route (${normalizePath(prbPath)}).` }
    }
  }
  if (input.hasStoredMatch && input.envelopeTrust !== 'host_persisted' && !input.hasStoredMatch()) {
    return { ok: false, reason: 'Recipe envelope has no matching host-persisted floor record in run storage.' }
  }
  return { ok: true }
}

export function validateReplayAgentScriptEnvelope(input: {
  specKind?: unknown
  origin: string
  verdict: string
  envelopeTrust?: 'host_persisted' | 'untrusted'
  tier: number
  canRead: (origin: string) => boolean
  hasStoredMatch?: () => boolean
}): { ok: true } | { ok: false; reason: string } {
  if (input.envelopeTrust === 'untrusted') {
    return { ok: false, reason: 'Untrusted model-supplied agentScript envelope rejected by verification kernel.' }
  }
  if (input.specKind === 'static_ast_proof') {
    return { ok: false, reason: 'static_ast_proof cannot carry or execute a live agentScript envelope.' }
  }
  if (input.tier === 0) {
    return { ok: false, reason: 'Live agentScript retest is disabled in Tier 0.' }
  }
  if (!input.origin || !input.canRead(input.origin)) {
    return { ok: false, reason: `agentScript envelope origin ${input.origin || '(missing)'} is not in approved scope.` }
  }
  if (input.verdict !== 'confirmed') {
    return { ok: false, reason: `agentScript envelope verdict must be "confirmed" to retest (got "${input.verdict}").` }
  }
  if (input.hasStoredMatch && input.envelopeTrust !== 'host_persisted' && !input.hasStoredMatch()) {
    return { ok: false, reason: 'agentScript envelope has no matching host-confirmed proof record in run storage.' }
  }
  return { ok: true }
}

export type { ImpactClass, ImpactStep, RoleName }
