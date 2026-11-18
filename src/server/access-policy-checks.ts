import type { AccessPolicySnapshot } from '../access-policy.ts'
import { assessmentCheckTitles } from '../domain.ts'
import type { EvidenceReview, FindingRule } from './evidence-checks.ts'

const baseRule: FindingRule = {
  id: 'access-policy',
  title: assessmentCheckTitles['access-policy'],
  findingTitle: 'Access decision differs from the expected policy',
  severity: 'low',
  impact: 'The recorded role and capability resolve to a different decision than the supplied policy specifies.',
  remediation: 'Review this role and capability in the application’s server-side authorization policy and align the decision with the intended rule.',
  recheck: 'Rerun the owner’s authorization test for this case and import the new decision.',
}

export function accessPolicyReviews(snapshot: AccessPolicySnapshot | undefined): EvidenceReview[] {
  if (!snapshot) return [{
    rule: baseRule,
    coverage: {
      id: 'access-policy', title: baseRule.title, status: 'inconclusive',
      expected: 'Expected policy and recorded access decisions', observed: null,
      reason: 'Supply access records for this approved host to verify its policy.',
    },
  }]
  const observed = new Map(snapshot.observed.map(item => [item.caseId, item.decision]))
  return snapshot.expected.map(policy => {
    const actual = observed.get(policy.caseId)
    const rule: FindingRule = {
      ...baseRule,
      title: `Access policy · ${policy.caseId}`,
      findingTitle: policy.decision === 'deny'
        ? `Recorded access exceeds policy for ${policy.caseId}`
        : `Recorded access falls short of policy for ${policy.caseId}`,
      severity: policy.decision === 'deny' ? 'medium' : 'low',
      impact: policy.decision === 'deny'
        ? `The recorded decision grants ${policy.capability} to ${policy.role} beyond the supplied policy.`
        : `The recorded decision denies ${policy.capability} to ${policy.role}, although the supplied policy permits it.`,
    }
    return {
      rule,
      coverage: {
        id: 'access-policy', caseId: policy.caseId, title: rule.title,
        status: 'inconclusive',
        expected: `${policy.decision === 'deny' ? 'Deny' : 'Allow'} ${policy.capability} for ${policy.role}.`,
        observed: actual === undefined ? null : actual === 'allow' ? 'Allowed' : 'Denied',
        reason: actual === undefined ? `The supplied records omit a decision for ${policy.caseId}.` : 'Verification is pending.',
      },
      ...(actual === undefined ? {} : {
        comparison: { id: 'access-policy:' + policy.caseId, observed: actual, baseline: { allowed: [policy.decision] } },
      }),
    }
  })
}
