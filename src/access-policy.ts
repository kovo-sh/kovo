import { z } from 'zod'
import { assetOrigin, id } from './domain.ts'

export const maxAccessPolicyBytes = 512 * 1024
export const maxAccessPolicyCases = 512

export const accessCaseLabel = z.string().trim().regex(/^[a-z0-9][a-z0-9_.-]{0,59}$/i)
const decision = z.object({ caseId: accessCaseLabel, decision: z.enum(['allow', 'deny']) })
const expectedDecision = decision.extend({
  role: accessCaseLabel,
  capability: accessCaseLabel,
  impactIfAllowed: z.enum(['sensitive-records', 'organization-admin']).optional(),
}).refine(item => item.decision === 'deny' || item.impactIfAllowed === undefined, {
  message: 'Supply the impact of an unintended grant only for an expected deny.',
  path: ['impactIfAllowed'],
})

export const accessPolicySnapshot = z.object({
  origin: assetOrigin,
  recordedAt: z.iso.datetime(),
  expected: z.array(expectedDecision).min(1).max(maxAccessPolicyCases),
  observed: z.array(decision).max(maxAccessPolicyCases),
}).superRefine(({ expected, observed }, context) => {
  const cases = new Set(expected.map(item => item.caseId))
  if (cases.size !== expected.length || new Set(observed.map(item => item.caseId)).size !== observed.length) {
    context.addIssue({ code: 'custom', message: 'Use each case identifier once in each list.' })
  }
  if (observed.some(item => !cases.has(item.caseId))) {
    context.addIssue({ code: 'custom', message: 'Every recorded decision needs a matching expected case.' })
  }
})

export type AccessPolicySnapshot = z.output<typeof accessPolicySnapshot>

export const importAccessPolicy = z.object({
  requestId: id,
  projectId: id,
  snapshot: accessPolicySnapshot,
})
