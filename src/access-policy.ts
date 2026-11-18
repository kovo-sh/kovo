import { z } from 'zod'
import { assetOrigin, id } from './domain.ts'

export const maxAccessPolicyBytes = 64 * 1024
export const maxAccessPolicyCases = 64

export const accessCaseLabel = z.string().trim().regex(/^[a-z0-9][a-z0-9_.-]{0,59}$/i)
const decision = z.object({ caseId: accessCaseLabel, decision: z.enum(['allow', 'deny']) })

export const accessPolicySnapshot = z.object({
  origin: assetOrigin,
  recordedAt: z.iso.datetime(),
  expected: z.array(decision.extend({ role: accessCaseLabel, capability: accessCaseLabel })).min(1).max(maxAccessPolicyCases),
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
