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

const policyImpacts = {
  'sensitive-records': {
    severity: 'high',
    description: 'The supplied policy identifies this capability as access to sensitive records.',
  },
  'organization-admin': {
    severity: 'critical',
    description: 'The supplied policy identifies this capability as organization-wide administration.',
  },
} as const

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
    const expectedDeny = policy.decision === 'deny'
    const expected = `${expectedDeny ? 'Deny' : 'Allow'} ${policy.capability} for ${policy.role}`
    const consequence = policy.impactIfAllowed ? policyImpacts[policy.impactIfAllowed] : undefined
    const impact = expectedDeny
      ? `The recorded decision grants ${policy.capability} to ${policy.role} beyond the supplied policy.`
      : `The recorded decision denies ${policy.capability} to ${policy.role}, although the supplied policy permits it.`
    const rule: FindingRule = {
      ...baseRule,
      title: `Access policy · ${policy.caseId}`,
      findingTitle: expectedDeny
        ? `Recorded access exceeds policy for ${policy.caseId}`
        : `Recorded access falls short of policy for ${policy.caseId}`,
      severity: consequence?.severity ?? (expectedDeny ? 'medium' : 'low'),
      impact: consequence ? impact + ' ' + consequence.description : impact,
      remediation: expected + ' in this host’s server-side authorization policy.',
      recheck: 'Rerun the owner’s authorization test for this case. The expected decision is ' + policy.decision + '.',
    }
    return {
      rule,
      coverage: {
        id: 'access-policy', caseId: policy.caseId, title: rule.title,
        status: 'inconclusive',
        expected: expected + '.',
        observed: actual === undefined ? null : actual === 'allow' ? 'Allowed' : 'Denied',
        reason: actual === undefined ? `The supplied records omit a decision for ${policy.caseId}.` : 'Verification is pending.',
      },
      ...(actual === undefined ? {} : {
        comparison: { id: 'access-policy:' + policy.caseId, observed: actual, baseline: { allowed: [policy.decision] } },
      }),
    }
  })
}
