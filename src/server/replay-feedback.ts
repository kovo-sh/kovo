/**
 * Inline replay-verification feedback formatting.
 *
 * Turns a `ReplayVerificationResult` into the bounded, redacted, actionable
 * `InlineVerifyFeedback` an agent uses to repair a spec, plus the `verifyReplaySpecInline`
 * entrypoint that runs one attempt and formats it. Extracted from `replay-verifier.ts` (Cut 3f)
 * so the verifier module only owns the legacy declarative VM. Every public symbol is re-exported
 * from `replay-verifier.ts`, so caller imports are unchanged.
 */
import { maxInlineVerifyRetries } from '../domain.ts'
import type { InlineVerifyFeedback } from '../domain.ts'
import type { DeclarativeReplaySpec } from '../replay-spec.ts'
import type { BrokerExchangeResult } from './broker.ts'
import { personaSecrets } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { inconclusiveResult, verifyReplaySpec } from './replay-verifier.ts'
import type { ReplayVerificationResult, VerifyReplaySpecParams } from './replay-verifier.ts'

export interface VerifyReplaySpecInlineParams extends VerifyReplaySpecParams {
  findingId?: string
  attemptCount?: number
  maxRetries?: number
  secrets?: readonly NamedSecret[]
}

export interface InlineReplayVerificationResult {
  feedback: InlineVerifyFeedback
  replay: ReplayVerificationResult
}

function toStepStatusItem(
  id: string,
  role: string,
  entry: Record<string, unknown>,
): InlineVerifyFeedback['stepStatuses'][number] {
  const status = typeof entry.status === 'number' && Number.isFinite(entry.status) ? entry.status : null
  const mediaType = typeof entry.mediaType === 'string' && entry.mediaType ? entry.mediaType : undefined
  const bodyLen = typeof entry.bodyBytes === 'number' && Number.isFinite(entry.bodyBytes)
    ? Math.max(0, Math.round(entry.bodyBytes))
    : typeof entry.body === 'string'
      ? Buffer.byteLength(entry.body, 'utf8')
      : 0
  return {
    id,
    role,
    status,
    ...(mediaType ? { mediaType } : {}),
    bodyLen,
  }
}

export interface InlineExchangeHeaderSummary {
  stepId: string
  status: number
  contentType?: string
  location?: string
  cacheControl?: string
  xCache?: string
  age?: string
  vary?: string
  accessControl?: string
  setCookie?: Array<{ name: string; secure: boolean; httpOnly: boolean; sameSite: string | null }>
}

export interface InlineStepBodyPreview {
  stepId: string
  status: number
  mediaType?: string
  preview: string
  truncated: boolean
}

/**
 * Enriched inline verification feedback. Extra fields are additive on top of the persisted
 * `InlineVerifyFeedback` contract (the domain schema strips nothing on read), so older consumers
 * and stored rows keep working while the repairing agent gets actionable evidence.
 */
export interface EnrichedInlineVerifyFeedback extends InlineVerifyFeedback {
  replayExchangeIds?: string[]
  keyResponseHeaders?: InlineExchangeHeaderSummary[]
  stepBodyPreviews?: InlineStepBodyPreview[]
  extractedVars?: Array<{ key: string; preview: string }>
  verificationKind?: string
  /** True when a vertical BFLA (function-level) proof lacked impact evidence. */
  bflaImpactRequired?: boolean
  impactEvidenceMissing?: boolean
  /** False when a status-only / unbound authorization claim was rejected for lacking a differential. */
  proofStrengthSatisfied?: boolean
  proofStrengthReason?: string
  /** True when the executed probe exchange did not match the spec's declared endpoint/method. */
  endpointBindingFailed?: boolean
  /** Method + origin + path of the endpoint the verifier actually observed. */
  verifiedEndpoint?: string
  /** True when a catch-all baseline matched and the spec must opt in to spaCatchallControl. */
  spaCatchallRequired?: boolean
}

const inlinePreviewBytes = 512
const maxInlineExchanges = 8
const maxInlineExtractedVars = 12

function sanitizeInlinePreview(text: string, secrets: readonly NamedSecret[]): { preview: string; truncated: boolean } {
  const redacted = redact(text, secrets)
  const cleaned = redacted
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (Buffer.byteLength(cleaned, 'utf8') <= inlinePreviewBytes) return { preview: cleaned, truncated: false }
  const sliced = Buffer.from(cleaned, 'utf8').subarray(0, inlinePreviewBytes).toString('utf8').replace(/\uFFFD+$/, '')
  return { preview: `${sliced}…`, truncated: true }
}

function headerValue(headers: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(headers).find(k => k.toLowerCase() === name)
  return key ? headers[key] : undefined
}

function summarizeKeyResponseHeaders(
  exchanges: readonly BrokerExchangeResult[],
  stepIds: readonly string[],
  secrets: readonly NamedSecret[],
): InlineExchangeHeaderSummary[] {
  const out: InlineExchangeHeaderSummary[] = []
  for (const [idx, ex] of exchanges.slice(0, maxInlineExchanges).entries()) {
    const headers = ex.respHeaders ?? {}
    const accessControl = Object.entries(headers)
      .filter(([k]) => k.toLowerCase().startsWith('access-control-'))
      .map(([k, v]) => `${k.toLowerCase()}: ${redact(v, secrets).slice(0, 120)}`)
      .sort()
      .join('; ')
    const setCookie = (ex.setCookies ?? []).slice(0, 8).map(c => ({
      name: c.name,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
    }))
    out.push({
      stepId: stepIds[idx] ?? `exchange-${idx + 1}`,
      status: ex.status,
      ...(headerValue(headers, 'content-type') ? { contentType: redact(headerValue(headers, 'content-type')!, secrets).slice(0, 120) } : {}),
      ...(headerValue(headers, 'location') ? { location: redact(headerValue(headers, 'location')!, secrets).slice(0, 240) } : {}),
      ...(headerValue(headers, 'cache-control') ? { cacheControl: redact(headerValue(headers, 'cache-control')!, secrets).slice(0, 160) } : {}),
      ...(headerValue(headers, 'x-cache') ? { xCache: redact(headerValue(headers, 'x-cache')!, secrets).slice(0, 80) } : {}),
      ...(headerValue(headers, 'age') ? { age: redact(headerValue(headers, 'age')!, secrets).slice(0, 40) } : {}),
      ...(headerValue(headers, 'vary') ? { vary: redact(headerValue(headers, 'vary')!, secrets).slice(0, 160) } : {}),
      ...(accessControl ? { accessControl } : {}),
      ...(setCookie.length ? { setCookie } : {}),
    })
  }
  return out
}

export function buildInlineVerifyFeedback(
  spec: DeclarativeReplaySpec | unknown,
  replay: ReplayVerificationResult,
  attemptCount: number,
  maxRetries = maxInlineVerifyRetries,
  secrets: readonly NamedSecret[] = [],
): EnrichedInlineVerifyFeedback {
  const maxAttempts = 1 + Math.max(0, maxRetries)
  const retriesRemaining = Math.max(0, maxAttempts - attemptCount)
  const payload = replay.evidencePayload ?? {}
  const kind = spec && typeof spec === 'object' && 'kind' in spec && typeof (spec as { kind?: unknown }).kind === 'string'
    ? (spec as { kind: string }).kind
    : (typeof payload.kind === 'string' ? payload.kind : '')

  // Retired legacy DSL kinds fail closed immediately: skip dead step/SPA/header/body enrichment
  // and report retriesRemaining=0 so agents switch to kovo_verify instead of retrying DSL.
  if (payload.retired === true) {
    const retiredReason = replay.outcome.reason ?? (typeof payload.reason === 'string' ? payload.reason : '')
    return redactJsonValue({
      verdict: replay.verdict,
      ...(replay.verificationTier ? { verificationTier: replay.verificationTier } : {}),
      controlPassed: false,
      assertionSummary: {
        observed: redact(replay.outcome.observed, secrets).slice(0, 400),
        expected: redact(replay.outcome.expected, secrets).slice(0, 400),
        ...(retiredReason ? { reason: redact(retiredReason, secrets).slice(0, 400) } : {}),
      },
      stepStatuses: [],
      retriesRemaining: 0,
      ...(kind ? { verificationKind: kind } : {}),
    } satisfies EnrichedInlineVerifyFeedback, secrets)
  }

  const stepStatuses: InlineVerifyFeedback['stepStatuses'] = []
  if (payload.steps && typeof payload.steps === 'object' && !Array.isArray(payload.steps)) {
    for (const [key, val] of Object.entries(payload.steps as Record<string, unknown>)) {
      if (!val || typeof val !== 'object') continue
      const entry = val as Record<string, unknown>
      const id = typeof entry.id === 'string' ? entry.id : key
      const role = typeof entry.role === 'string' ? entry.role : 'probe'
      stepStatuses.push(toStepStatusItem(id, role, entry))
    }
  } else if (kind === 'rce_proof') {
    if (payload.control && typeof payload.control === 'object') {
      stepStatuses.push(toStepStatusItem('control', 'control', payload.control as Record<string, unknown>))
    }
    if (payload.probe && typeof payload.probe === 'object') {
      stepStatuses.push(toStepStatusItem('probe', 'probe', payload.probe as Record<string, unknown>))
    }
  } else if (kind === 'cache_differential') {
    if (payload.control && typeof payload.control === 'object') {
      stepStatuses.push(toStepStatusItem('control', 'control', payload.control as Record<string, unknown>))
    }
    if (payload.probe && typeof payload.probe === 'object') {
      stepStatuses.push(toStepStatusItem('probe', 'probe', payload.probe as Record<string, unknown>))
    }
    if (payload.verify && typeof payload.verify === 'object') {
      stepStatuses.push(toStepStatusItem('verify', 'probe', payload.verify as Record<string, unknown>))
    }
  }

  const reason = replay.outcome.reason ?? ''
  const requireControlNonErrorTriggered = /requireControlNonError/i.test(reason) ? true : undefined

  let failedStepId: string | undefined
  if (replay.verdict === 'dismissed' || replay.verdict === 'inconclusive') {
    const stepMatch = /step\s+"([^"]+)"/i.exec(reason)
    if (stepMatch) {
      failedStepId = stepMatch[1]
    } else {
      const errStep = stepStatuses.find(s => s.status === null || s.status === 0 || s.status === 404 || s.status >= 500)
      if (errStep) {
        failedStepId = errStep.id
      } else if (!replay.outcome.controlPassed) {
        failedStepId = stepStatuses.find(s => s.role === 'control')?.id ?? stepStatuses[0]?.id
      } else {
        failedStepId = stepStatuses.find(s => s.role === 'probe')?.id ?? stepStatuses[0]?.id
      }
    }
  }

  let spaCatchallMatched: boolean | undefined
  let spaSimilarityScore: number | undefined
  if (payload.spaCatchall && typeof payload.spaCatchall === 'object') {
    const spa = payload.spaCatchall as { allProbesMatchedCatchall?: unknown; comparisons?: Record<string, { tokenSimilarity?: unknown }> }
    spaCatchallMatched = Boolean(spa.allProbesMatchedCatchall)
    if (spa.comparisons && typeof spa.comparisons === 'object') {
      const scores = Object.values(spa.comparisons)
        .map(c => (c && typeof c.tokenSimilarity === 'number' && Number.isFinite(c.tokenSimilarity) ? c.tokenSimilarity : null))
        .filter((v): v is number => v !== null)
      if (scores.length) spaSimilarityScore = Math.max(...scores)
    }
  }

  let spaCatchallRequired: boolean | undefined
  if (payload.spaCatchallAuto && typeof payload.spaCatchallAuto === 'object') {
    const auto = payload.spaCatchallAuto as { requiresControl?: unknown; matchedProbes?: unknown; probeCount?: unknown }
    if (auto.requiresControl === true && typeof auto.matchedProbes === 'number' &&
        typeof auto.probeCount === 'number' && auto.matchedProbes === auto.probeCount) {
      spaCatchallRequired = true
    }
  }

  let canaryTriggered: boolean | undefined
  const proofObj = payload.proof as { canaryProbeTriggered?: unknown } | undefined
  const probeObj = payload.probe as { canaryCheck?: { triggered?: unknown } } | undefined
  if (typeof proofObj?.canaryProbeTriggered === 'boolean') {
    canaryTriggered = proofObj.canaryProbeTriggered
  } else if (typeof probeObj?.canaryCheck?.triggered === 'boolean') {
    canaryTriggered = probeObj.canaryCheck.triggered
  }

  const jqError = /^(?:Replay jq assertion|Replay assertion output violated schema|Verification container failed)/i.test(reason)
    ? redact(reason, secrets).slice(0, 400)
    : undefined

  const assertionSummary: InlineVerifyFeedback['assertionSummary'] = {
    observed: redact(replay.outcome.observed, secrets).slice(0, 400),
    expected: redact(replay.outcome.expected, secrets).slice(0, 400),
    ...(reason ? { reason: redact(reason, secrets).slice(0, 400) } : {}),
  }

  // --- M1.5 enrichment: actionable, bounded, redacted evidence for the repairing agent ---
  const enrichedHeaders = summarizeKeyResponseHeaders(replay.exchanges ?? [], stepStatuses.map(s => s.id), secrets)
  const bodyPreviews: InlineStepBodyPreview[] = []
  if (replay.verdict !== 'confirmed' && replay.verdict !== 'static_verified') {
    const failedIds = new Set<string>()
    if (failedStepId) failedIds.add(failedStepId)
    for (const step of stepStatuses) {
      if (step.id === failedStepId || step.status === null || step.status === 0 || step.status >= 400) failedIds.add(step.id)
    }
    for (const [idx, ex] of (replay.exchanges ?? []).slice(0, maxInlineExchanges).entries()) {
      const stepId = stepStatuses[idx]?.id ?? `exchange-${idx + 1}`
      if (failedIds.size && !failedIds.has(stepId)) continue
      if (!ex.body) continue
      const { preview, truncated } = sanitizeInlinePreview(ex.body, secrets)
      if (!preview) continue
      bodyPreviews.push({
        stepId,
        status: ex.status,
        ...(ex.mediaType ? { mediaType: ex.mediaType } : {}),
        preview,
        truncated,
      })
      if (bodyPreviews.length >= 4) break
    }
  }

  const extractedVarSummaries: Array<{ key: string; preview: string }> = []
  const rawExtractedVars = payload.extractedVars
  if (rawExtractedVars && typeof rawExtractedVars === 'object' && !Array.isArray(rawExtractedVars)) {
    for (const [key, value] of Object.entries(rawExtractedVars as Record<string, unknown>).slice(0, maxInlineExtractedVars)) {
      const { preview } = sanitizeInlinePreview(String(value ?? ''), secrets)
      extractedVarSummaries.push({ key, preview })
    }
  }

  const bflaImpact = payload.bflaImpact as { required?: unknown; satisfied?: unknown; reason?: unknown } | undefined
  const bflaImpactRequired = bflaImpact?.required === true ? true : undefined
  const impactEvidenceMissing = bflaImpact?.required === true && bflaImpact?.satisfied === false ? true : undefined
  const proofStrengthPayload = payload.proofStrength as { claim?: unknown; satisfied?: unknown; reason?: unknown } | undefined
  const proofStrengthSatisfied = proofStrengthPayload && typeof proofStrengthPayload.satisfied === 'boolean'
    ? proofStrengthPayload.satisfied
    : undefined
  const proofStrengthReason = proofStrengthPayload && proofStrengthPayload.satisfied === false && typeof proofStrengthPayload.reason === 'string'
    ? redact(proofStrengthPayload.reason, secrets).slice(0, 320)
    : undefined
  const endpointBindingPayload = payload.endpointBinding as {
    bound?: unknown
    reason?: unknown
    verifiedEndpoint?: { origin?: unknown; method?: unknown; pathAndQuery?: unknown } | null
  } | undefined
  const endpointBindingFailed = endpointBindingPayload && endpointBindingPayload.bound === false ? true : undefined
  const verifiedEndpoint = endpointBindingPayload?.verifiedEndpoint &&
    typeof endpointBindingPayload.verifiedEndpoint.method === 'string' &&
    typeof endpointBindingPayload.verifiedEndpoint.origin === 'string' &&
    typeof endpointBindingPayload.verifiedEndpoint.pathAndQuery === 'string'
    ? redact(`${endpointBindingPayload.verifiedEndpoint.method} ${endpointBindingPayload.verifiedEndpoint.origin}${endpointBindingPayload.verifiedEndpoint.pathAndQuery}`, secrets).slice(0, 320)
    : undefined

  const rawFeedback: EnrichedInlineVerifyFeedback = {
    verdict: replay.verdict,
    ...(replay.verificationTier ? { verificationTier: replay.verificationTier } : {}),
    ...(failedStepId ? { failedStepId: redact(failedStepId, secrets) } : {}),
    controlPassed: replay.outcome.controlPassed,
    ...(requireControlNonErrorTriggered ? { requireControlNonErrorTriggered } : {}),
    ...(spaCatchallMatched !== undefined ? { spaCatchallMatched } : {}),
    ...(spaCatchallRequired ? { spaCatchallRequired } : {}),
    ...(spaSimilarityScore !== undefined ? { spaSimilarityScore } : {}),
    ...(canaryTriggered !== undefined ? { canaryTriggered } : {}),
    ...(jqError ? { jqError } : {}),
    assertionSummary,
    stepStatuses,
    retriesRemaining,
    ...(replay.exchangeIds?.length ? { replayExchangeIds: replay.exchangeIds.slice(0, maxInlineExchanges) } : {}),
    ...(enrichedHeaders.length ? { keyResponseHeaders: enrichedHeaders } : {}),
    ...(bodyPreviews.length ? { stepBodyPreviews: bodyPreviews } : {}),
    ...(extractedVarSummaries.length ? { extractedVars: extractedVarSummaries } : {}),
    ...(kind ? { verificationKind: kind } : {}),
    ...(bflaImpactRequired ? { bflaImpactRequired } : {}),
    ...(impactEvidenceMissing ? { impactEvidenceMissing } : {}),
    ...(proofStrengthSatisfied !== undefined ? { proofStrengthSatisfied } : {}),
    ...(proofStrengthReason ? { proofStrengthReason } : {}),
    ...(endpointBindingFailed ? { endpointBindingFailed } : {}),
    ...(verifiedEndpoint ? { verifiedEndpoint } : {}),
  }

  // Enrichment is built from already-redacted exchanges; this final pass catches anything that
  // slipped through and guarantees the persisted feedback never carries live credentials.
  return redactJsonValue(rawFeedback, secrets)
}

export async function verifyReplaySpecInline(
  params: VerifyReplaySpecInlineParams,
): Promise<InlineReplayVerificationResult> {
  const maxRetries = Math.max(0, params.maxRetries ?? maxInlineVerifyRetries)
  const maxAttempts = 1 + maxRetries
  const attemptCount = Math.max(1, params.attemptCount ?? 1)
  const allSecrets: NamedSecret[] = [
    ...(params.secrets ?? []),
    ...(params.grant.secrets ?? []),
    ...(params.grant.personas ? personaSecrets(params.grant.personas) : []),
  ]

  if (attemptCount > maxAttempts) {
    const reason = `Inline verification retry limit reached (maxInlineVerifyRetries=${maxRetries}).`
    const emptyReplay = inconclusiveResult(reason, [], [], { retryLimitExceeded: true })
    const feedback = redactJsonValue({
      verdict: 'inconclusive',
      controlPassed: false,
      assertionSummary: {
        observed: 'retry_limit_exceeded',
        expected: `<= ${maxAttempts} verification attempts`,
        reason,
      },
      stepStatuses: [],
      retriesRemaining: 0,
    } satisfies InlineVerifyFeedback, allSecrets)
    return { feedback, replay: emptyReplay }
  }

  const replay = await verifyReplaySpec(params)
  const finalSecrets: NamedSecret[] = [
    ...allSecrets,
    ...(params.broker.getRegisteredSecrets?.() ?? []),
  ]
  const feedback = buildInlineVerifyFeedback(params.spec, replay, attemptCount, maxRetries, finalSecrets)
  return { feedback, replay }
}

