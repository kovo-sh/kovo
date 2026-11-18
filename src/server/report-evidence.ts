import { z } from 'zod'
import { accessCaseLabel, accessPolicySnapshot, maxAccessPolicyCases } from '../access-policy.ts'
import { assessmentCheckIds, assetOrigin, id, preparedObservation, referrerPolicies, responseCheckIds } from '../domain.ts'
import type { EvidenceSummary } from '../domain.ts'

const observation = z.object({
  observation: preparedObservation.extend({
    origin: assetOrigin,
    finalOrigin: assetOrigin,
    mediaType: z.union([preparedObservation.shape.mediaType, z.literal('unknown')]),
    source: z.enum(['public response', 'fixture response', 'supplied observation']),
  }).nullable(),
})
const accessRecord = z.object({ origin: assetOrigin, snapshot: accessPolicySnapshot.nullable() })
const interpreter = z.string().regex(/^just-bash \d+\.\d+\.\d+$/)
const receipt = z.object({
  inputEvidence: z.array(id).max(2),
  interpreter: interpreter.optional(),
  exitStatus: z.number().int().min(0).max(255).optional(),
})
const minimum = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER)
const values = z.enum(['absent', 'unrecognized', 'nosniff', 'allow', 'deny', ...referrerPolicies])
const maxComparisons = maxAccessPolicyCases + responseCheckIds.length
const comparison = z.object({
  id: z.string().refine(value => responseCheckIds.some(id => id === value) ||
    (value.startsWith('access-policy:') && accessCaseLabel.safeParse(value.slice('access-policy:'.length)).success)),
  observed: z.union([minimum, values, z.null()]),
  baseline: z.union([z.object({ minimum }), z.object({ allowed: z.array(values).min(1).max(values.options.length) })]),
})
const verification = receipt.extend({
  origin: assetOrigin,
  checks: z.array(z.object({
    id: z.enum(assessmentCheckIds),
    caseId: accessCaseLabel.optional(),
    status: z.enum(['met', 'gap', 'inconclusive', 'not-applicable']),
  })).max(maxComparisons),
  comparisons: z.array(comparison).max(maxComparisons),
})
const legacyVerification = receipt.extend({
  expected: z.literal('positive HSTS max-age'),
  observed: minimum.nullable(),
  result: z.enum(['present', 'missing', 'inconclusive']),
  origin: assetOrigin.optional(),
  finalOrigin: assetOrigin.optional(),
})
const verificationReceipt = z.union([verification, legacyVerification])
const analysisReceipt = receipt.extend({ inputEvidence: z.array(id).length(1) })

export function isReportSource(kind: EvidenceSummary['kind']) {
  return kind === 'observation' || kind === 'access-policy'
}

export function projectReportEvidence(
  kind: EvidenceSummary['kind'],
  content: string,
  origin: string,
  approved: ReadonlySet<string>,
): { data: object; sources?: string[] } | undefined {
  let input: unknown
  try {
    input = JSON.parse(content)
  } catch {
    return
  }
  switch (kind) {
    case 'observation': {
      const parsed = observation.safeParse(input)
      if (!parsed.success) return
      const observed = parsed.data.observation
      if (observed && (observed.origin !== origin || !approved.has(observed.finalOrigin))) return
      return { data: parsed.data }
    }
    case 'access-policy': {
      const parsed = accessRecord.safeParse(input)
      if (!parsed.success || parsed.data.origin !== origin || (parsed.data.snapshot && parsed.data.snapshot.origin !== origin)) return
      return { data: parsed.data }
    }
    case 'verification': {
      const parsed = verificationReceipt.safeParse(input)
      if (!parsed.success) return
      const { inputEvidence, ...data } = parsed.data
      if (data.origin && data.origin !== origin) return
      if ('finalOrigin' in data && data.finalOrigin && !approved.has(data.finalOrigin)) return
      return { data, sources: inputEvidence }
    }
    case 'analysis': {
      const parsed = analysisReceipt.safeParse(input)
      if (!parsed.success) return
      const { inputEvidence, ...data } = parsed.data
      return { data, sources: inputEvidence }
    }
  }
}
