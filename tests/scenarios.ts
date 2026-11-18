import type { PublicObservation } from '../src/server/broker.ts'
import type { AccessPolicySnapshot } from '../src/access-policy.ts'

export const fixtureCredential = 'guardian-replay-fixture-key'
export const primaryOrigin = 'https://northstar.example'
export const unavailableOrigin = 'https://docs.northstar.example'
export const healthyOrigin = 'https://healthy.northstar.example'
export const excludedOrigin = 'https://help.vendor.example'
export const mainGoal = 'Review the public transport policy for our selected Northstar hosts.'
export const healthyGoal = 'Review the transport policy for the healthy Northstar fixture.'
export const allChecksGoal = 'Review all supported security headers on the approved responses.'
export const referrerGoal = 'Review only the Referrer-Policy header on the approved responses.'
export const statusQuestion = 'What is the current progress of this review?'
export const accessPolicyGoal = 'Compare only the recorded access decisions with the supplied authorization policy.'
export const combinedGoal = 'Review all available response headers and compare the recorded access decisions with the supplied authorization policy.'

export const accessPolicy: AccessPolicySnapshot = {
  origin: primaryOrigin,
  recordedAt: '2026-11-17T15:45:00Z',
  expected: [
    { caseId: 'billing-export', role: 'billing-viewer', capability: 'export-statements', decision: 'deny' },
    { caseId: 'audit-summary', role: 'team-auditor', capability: 'read-audit-summary', decision: 'allow' },
    { caseId: 'read-summary', role: 'team-viewer', capability: 'read-summary', decision: 'allow' },
    { caseId: 'modify-schedule', role: 'schedule-viewer', capability: 'modify-schedule', decision: 'deny' },
  ],
  observed: [
    { caseId: 'billing-export', decision: 'allow' },
    { caseId: 'audit-summary', decision: 'deny' },
    { caseId: 'read-summary', decision: 'allow' },
  ],
}

export const secondaryAccessPolicy: AccessPolicySnapshot = {
  ...accessPolicy,
  origin: unavailableOrigin,
  recordedAt: '2026-11-17T16:10:00Z',
  observed: [
    { caseId: 'billing-export', decision: 'allow' },
    { caseId: 'audit-summary', decision: 'allow' },
    { caseId: 'modify-schedule', decision: 'deny' },
  ],
}

export const severeAccessPolicy: AccessPolicySnapshot = {
  origin: primaryOrigin,
  recordedAt: '2026-11-17T16:30:00Z',
  expected: [
    { caseId: 'customer-history', role: 'support-viewer', capability: 'read-customer-history', decision: 'deny',
      impactIfAllowed: 'sensitive-records' },
    { caseId: 'workspace-ownership', role: 'team-viewer', capability: 'manage-organization-owners', decision: 'deny',
      impactIfAllowed: 'organization-admin' },
    { caseId: 'security-administration', role: 'audit-viewer', capability: 'manage-security-settings', decision: 'deny',
      impactIfAllowed: 'organization-admin' },
    { caseId: 'payroll-records', role: 'team-viewer', capability: 'read-payroll', decision: 'deny',
      impactIfAllowed: 'sensitive-records' },
  ],
  observed: [
    { caseId: 'customer-history', decision: 'allow' },
    { caseId: 'workspace-ownership', decision: 'allow' },
    { caseId: 'security-administration', decision: 'deny' },
  ],
}

export function observation(origin: string, status: number, transportMaxAge: number | null): PublicObservation {
  return {
    origin, finalOrigin: origin, status, mediaType: 'text/html',
    transportMaxAge, includeSubDomains: false, source: 'fixture response',
  }
}

export const primary: PublicObservation = {
  ...observation(primaryOrigin, 200, null), contentTypeOptions: 'absent', referrerPolicy: 'unsafe-url',
}
export const unavailable: PublicObservation = {
  ...observation(unavailableOrigin, 503, null), contentTypeOptions: 'absent', referrerPolicy: 'absent',
}
export const healthy: PublicObservation = {
  ...observation(healthyOrigin, 200, 31_536_000), contentTypeOptions: 'nosniff', referrerPolicy: 'strict-origin-when-cross-origin',
}
