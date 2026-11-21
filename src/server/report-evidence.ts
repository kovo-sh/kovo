import { z } from 'zod'
import { accessCaseLabel, accessPolicySnapshot, maxAccessPolicyCases } from '../access-policy.ts'
import { assessmentCheckIds, assetOrigin, id, preparedObservation, referrerPolicies, responseCheckIds } from '../domain.ts'
import type { EvidenceSummary } from '../domain.ts'
import { accessPolicyReviews } from './access-policy-checks.ts'
import { checkCoverage } from './evidence-checks.ts'

export const responseCapture = z.object({
  observation: preparedObservation.extend({
    origin: assetOrigin,
    finalOrigin: assetOrigin,
    mediaType: z.union([preparedObservation.shape.mediaType, z.literal('unknown')]),
    source: z.enum(['public response', 'fixture response', 'supplied observation']),
  }).nullable(),
  reusedFrom: z.object({
    artifactId: id,
    capturedAt: z.iso.datetime(),
    scopeRevision: z.number().int().positive(),
  }).optional(),
})
const accessRecord = z.object({ origin: assetOrigin, snapshot: accessPolicySnapshot.nullable() })
const interpreter = z.string().regex(/^just-bash \d+\.\d+\.\d+$/)
const receipt = z.object({
  inputEvidence: z.array(id).max(16),
  interpreter: interpreter.optional(),
  exitStatus: z.number().int().min(0).max(255).optional(),
})
const minimum = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)
const values = z.enum([
  'absent', 'unrecognized', 'nosniff', 'allow', 'deny', ...referrerPolicies,
  'enforced', 'report-only', 'x-frame-options', 'csp-frame-ancestors', 'both',
  'generic', 'technology', 'restricted', 'wildcard', 'reflected-origin',
  'reflected-origin-with-credentials', 'none', 'internal-details', 'stack-trace',
  'secure-httponly', 'secure-only', 'insecure',
])
const maxComparisons = maxAccessPolicyCases + responseCheckIds.length
const comparison = z.object({
  id: z.string().refine(value => responseCheckIds.some(cid => cid === value) ||
    (value.startsWith('access-policy:') && accessCaseLabel.safeParse(value.slice('access-policy:'.length)).success)),
  observed: z.union([minimum, values, z.null()]),
  baseline: z.union([z.object({ minimum }), z.object({ allowed: z.array(values).min(1).max(values.options.length) })]),
})
const verification = receipt.extend({
  origin: assetOrigin,
  verifiedAt: z.iso.datetime().optional(),
  checks: z.array(z.object({
    id: z.enum(assessmentCheckIds),
    caseId: accessCaseLabel.optional(),
    status: z.enum(['met', 'gap', 'inconclusive', 'not-applicable']),
  })).max(maxComparisons),
  comparisons: z.array(comparison).max(maxComparisons),
})
const replayReceipt = z.object({
  replaySpecId: id.optional(),
  specSha256: z.string().optional(),
  kind: z.string().optional(),
  origin: assetOrigin.optional(),
  verdict: z.enum(['confirmed', 'dismissed', 'inconclusive', 'reproduced', 'fixed']).optional(),
  outcome: z.object({
    confirmed: z.boolean(),
    controlPassed: z.boolean(),
    observed: z.string(),
    expected: z.string(),
    reason: z.string().optional(),
  }).optional(),
  exchangeIds: z.array(z.string()).optional(),
  sourceOrigins: z.array(assetOrigin).optional(),
}).passthrough()
const genericRecord = z.record(z.string(), z.unknown())

function parseEvidence(content: string): unknown {
  try {
    return JSON.parse(content)
  } catch {
    return undefined
  }
}

export function restrictAccessVerification(content: string, source: { id: string; content: string }, origin: string) {
  const saved = verification.safeParse(parseEvidence(content))
  const access = accessRecord.safeParse(parseEvidence(source.content))
  if (!saved.success || saved.data.origin !== origin || !saved.data.inputEvidence.includes(source.id) ||
    !access.success || access.data.origin !== origin || (access.data.snapshot && access.data.snapshot.origin !== origin)) return

  const accessChecks = saved.data.checks.filter(check => check.id === 'access-policy')
  const savedChecks = new Map(accessChecks.map(check => [check.caseId, check.status]))
  const savedComparisons = new Map(saved.data.comparisons.map(item => [item.id, item]))
  if (savedChecks.size !== accessChecks.length || savedComparisons.size !== saved.data.comparisons.length) return

  const reviews = accessPolicyReviews(access.data.snapshot ?? undefined).filter(review => savedChecks.has(review.coverage.caseId))
  const outcomes = new Map<string, 'met' | 'gap'>()
  const comparisons = reviews.flatMap(({ coverage, comparison: comp }) => {
    if (!comp || !('allowed' in comp.baseline)) return []
    const recorded = savedComparisons.get(comp.id)
    if (!recorded || recorded.observed !== comp.observed || !('allowed' in recorded.baseline) ||
      recorded.baseline.allowed.length !== 1 || recorded.baseline.allowed[0] !== comp.baseline.allowed[0]) return []
    const outcome = savedChecks.get(coverage.caseId)
    if (saved.data.exitStatus === 0 && (outcome === 'met' || outcome === 'gap')) outcomes.set(recorded.id, outcome)
    return [recorded]
  })
  const checks = reviews.map(review => checkCoverage(review, outcomes))
  if (!checks.length) return
  return {
    recordedAt: access.data.snapshot?.recordedAt,
    receipt: {
      origin, inputEvidence: [source.id], checks, comparisons,
      interpreter: saved.data.interpreter, exitStatus: saved.data.exitStatus,
    },
  }
}

export function isReportSource(kind: EvidenceSummary['kind']) {
  return kind === 'observation' || kind === 'access-policy' || kind === 'exchange' || kind === 'dns' || kind === 'tls' || kind === 'browser'
}

export function projectReportEvidence(
  kind: EvidenceSummary['kind'],
  content: string,
  origin: string,
  approved: ReadonlySet<string>,
): { data: object; sources?: string[] } | undefined {
  const input = parseEvidence(content)
  switch (kind) {
    case 'observation': {
      const parsed = responseCapture.safeParse(input)
      if (!parsed.success) return
      const observed = parsed.data.observation
      if (observed && (observed.origin !== origin || !approved.has(observed.finalOrigin))) return
      const source = parsed.data.reusedFrom
      return { data: source ? { ...parsed.data, capturedAt: source.capturedAt } : parsed.data }
    }
    case 'access-policy': {
      const parsed = accessRecord.safeParse(input)
      if (!parsed.success || parsed.data.origin !== origin || (parsed.data.snapshot && parsed.data.snapshot.origin !== origin)) return
      return { data: parsed.data }
    }
    case 'verification': {
      const parsed = verification.safeParse(input)
      if (parsed.success) {
        const { inputEvidence, ...data } = parsed.data
        if (data.origin && data.origin !== origin) return
        return { data, sources: inputEvidence }
      }
      const replay = replayReceipt.safeParse(input)
      if (replay.success) {
        if (replay.data.origin && !approved.has(replay.data.origin)) return
        if (replay.data.sourceOrigins?.some(o => !approved.has(o))) return
        return { data: replay.data }
      }
      return
    }
    case 'replay': {
      const replay = replayReceipt.safeParse(input)
      if (!replay.success) return
      if (replay.data.origin && !approved.has(replay.data.origin)) return
      if (replay.data.sourceOrigins?.some(o => !approved.has(o))) return
      return { data: replay.data }
    }
    case 'analysis':
    case 'exchange':
    case 'dns':
    case 'tls':
    case 'browser':
    case 'threat-model':
    case 'digest': {
      const parsed = genericRecord.safeParse(input)
      if (!parsed.success) return
      const rawOrigin = typeof parsed.data.origin === 'string' ? parsed.data.origin : undefined
      if (rawOrigin && !approved.has(rawOrigin)) return
      const redirectOrigins = Array.isArray(parsed.data.redirectOrigins) ? parsed.data.redirectOrigins : []
      if (redirectOrigins.some(item => typeof item === 'string' && !approved.has(item))) return
      const inputEvidence = Array.isArray(parsed.data.inputEvidence)
        ? parsed.data.inputEvidence.filter((item): item is string => typeof item === 'string' && id.safeParse(item).success)
        : undefined
      return { data: parsed.data, ...(inputEvidence?.length ? { sources: inputEvidence } : {}) }
    }
  }
}
