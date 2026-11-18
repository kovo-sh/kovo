import type { Verdict } from '../scripts/report-metrics.ts'
import type { AccessPolicySnapshot } from '../src/access-policy.ts'
import { publicResponseCheckIds } from '../src/domain.ts'
import type { AssessmentCheckId, Finding, ResponseCheckId } from '../src/domain.ts'
import type { PublicObservation } from '../src/server/broker.ts'
import {
  accessPolicy, accessPolicyGoal, allChecksGoal, deepPrimary, healthy, healthyOrigin, primary, primaryOrigin,
  secondaryAccessPolicy, severeAccessPolicy, unavailable, unavailableOrigin,
} from './scenarios.ts'

export const benchmarkSuite = 'northstar-report-v1'
export { scoreReportCases, verdictSchema } from '../scripts/report-metrics.ts'
export type { Verdict } from '../scripts/report-metrics.ts'

type ExpectedOutcome = { expected: 'confirmed'; severity: Finding['severity'] }
  | { expected: Exclude<Verdict, 'confirmed'> }

export type ExpectedCase = ExpectedOutcome & {
  origin: string
  check: AssessmentCheckId
  caseId?: string
}

export type BenchmarkInput = {
  goal: string
  scope: string[]
  stoppingPoint: 'complete' | 'interrupted'
  overlappingObservations?: boolean
  stoppingCondition?: string
  capturedEvidence: {
    responseObservations?: PublicObservation[]
    accessDecisions?: AccessPolicySnapshot[]
  }
}

type ReportScenario = { version: number; partial: boolean; basis: string; input: BenchmarkInput; cases: ExpectedCase[] }

function responseCases(origin: string, expected: Verdict, checks: readonly ResponseCheckId[] = publicResponseCheckIds): ExpectedCase[] {
  const severities: Record<ResponseCheckId, Finding['severity']> = {
    hsts: 'low', nosniff: 'informational', 'referrer-policy': 'low',
    'content-security-policy': 'low', 'frame-protection': 'low', 'server-disclosure': 'informational',
    'cors-policy': 'high', 'error-exposure': 'low', 'session-cookie': 'medium',
  }
  return checks.map(check => {
    const severity = severities[check]
    return expected === 'confirmed' ? { origin, check, expected, severity } : { origin, check, expected }
  })
}

function accessCases(origin: string, outcomes: Record<string, ExpectedOutcome>): ExpectedCase[] {
  return Object.entries(outcomes).map(([caseId, outcome]) => ({ origin, check: 'access-policy', caseId, ...outcome }))
}

const firstPolicyCases = accessCases(primaryOrigin, {
  'billing-export': { expected: 'confirmed', severity: 'medium' },
  'audit-summary': { expected: 'confirmed', severity: 'low' },
  'read-summary': { expected: 'met' },
  'modify-schedule': { expected: 'inconclusive' },
})

const responseInput = {
  goal: allChecksGoal, scope: [primaryOrigin, unavailableOrigin],
  capturedEvidence: { responseObservations: [primary, unavailable] },
}

// These labels come from the controlled inputs, independently of the report and check implementation.
export const benchmarkScenarios = {
  'response-multi-host': {
    version: 2, partial: false,
    basis: 'The main response omits HSTS and nosniff and uses unsafe-url. The other host returns HTTP 503.',
    input: { ...responseInput, stoppingPoint: 'complete' },
    cases: [...responseCases(primaryOrigin, 'confirmed'), ...responseCases(unavailableOrigin, 'inconclusive')],
  },
  'response-interrupted': {
    version: 1, partial: true,
    basis: 'The operator stops the same run before verification while the second response remains unavailable.',
    input: {
      ...responseInput, stoppingPoint: 'interrupted',
      stoppingCondition: 'Stop after analysis of northstar.example while the docs response is pending, before verification starts.',
    },
    cases: [...responseCases(primaryOrigin, 'untested'), ...responseCases(unavailableOrigin, 'untested')],
  },
  'response-healthy': {
    version: 1, partial: false,
    basis: 'The response has positive HSTS max-age, nosniff, and strict-origin-when-cross-origin.',
    input: {
      goal: allChecksGoal, scope: [healthyOrigin], stoppingPoint: 'complete',
      capturedEvidence: { responseObservations: [healthy] },
    },
    cases: responseCases(healthyOrigin, 'met'),
  },
  'response-deep-prepared': {
    version: 1, partial: false,
    basis: 'The supplied snapshot records six response-policy gaps plus arbitrary credentialed CORS, a stack trace, and an insecure session-cookie classification.',
    input: {
      goal: allChecksGoal, scope: [primaryOrigin], stoppingPoint: 'complete',
      capturedEvidence: { responseObservations: [deepPrimary] },
    },
    cases: responseCases(primaryOrigin, 'confirmed', [
      'hsts', 'nosniff', 'referrer-policy', 'content-security-policy', 'frame-protection', 'server-disclosure',
      'cors-policy', 'error-exposure', 'session-cookie',
    ]),
  },
  'access-policy': {
    version: 1, partial: false,
    basis: 'Billing export is incorrectly allowed. Audit summary is incorrectly denied. Read summary is correctly allowed. Modify schedule has no recorded decision.',
    input: {
      goal: accessPolicyGoal, scope: [primaryOrigin], stoppingPoint: 'complete',
      capturedEvidence: { accessDecisions: [accessPolicy] },
    },
    cases: firstPolicyCases,
  },
  'policy-multi-host': {
    version: 1, partial: false,
    basis: 'Both approved hosts allow billing export against policy. Only the primary host denies the required audit summary. Each host has one missing decision.',
    input: {
      goal: accessPolicyGoal, scope: [primaryOrigin, unavailableOrigin], stoppingPoint: 'complete', overlappingObservations: true,
      capturedEvidence: { accessDecisions: [accessPolicy, secondaryAccessPolicy] },
    },
    cases: [...firstPolicyCases, ...accessCases(unavailableOrigin, {
      'billing-export': { expected: 'confirmed', severity: 'medium' },
      'audit-summary': { expected: 'met' },
      'read-summary': { expected: 'inconclusive' },
      'modify-schedule': { expected: 'met' },
    })],
  },
  'policy-serious-impact': {
    version: 1, partial: false,
    basis: 'A read-only role can manage organization owners and a support viewer can read sensitive records. A separate administration check correctly denies access, and payroll has no recorded decision.',
    input: {
      goal: accessPolicyGoal, scope: [primaryOrigin], stoppingPoint: 'complete',
      capturedEvidence: { accessDecisions: [severeAccessPolicy] },
    },
    cases: accessCases(primaryOrigin, {
      'workspace-ownership': { expected: 'confirmed', severity: 'critical' },
      'customer-history': { expected: 'confirmed', severity: 'high' },
      'security-administration': { expected: 'met' },
      'payroll-records': { expected: 'inconclusive' },
    }),
  },
} satisfies Record<string, ReportScenario>

export type ScenarioId = keyof typeof benchmarkScenarios
export const benchmarkAttachment = 'report-benchmark-'

export function benchmarkCaseId(scenario: ScenarioId, check: ExpectedCase) {
  return [scenario, new URL(check.origin).hostname, check.check, check.caseId].filter(Boolean).join('/')
}

export type CaseResult = {
  id: string
  reported: Verdict
  visible: boolean
  reportedSeverity?: Finding['severity']
  linkedEvidence?: boolean
  fixGuidance?: boolean
}

export type ReportResult = {
  scenario: ScenarioId
  cases: CaseResult[]
  unmatchedConfirmations: number
  recording: {
    runId: string
    reportId: string
    reportVersion: number
    createdAt: number
    scopeRevision: number
    goalRevision: number
    approval: { eventId: number; scope: string[] }
    phase: string
    status: string
    events: {
      id: number
      kind: string
      createdAt: number
      origin: string | null
      assignmentId: string | null
      artifactId: string | null
      reportId: string | null
      reportVersion: number | null
      scope?: string[]
    }[]
  }
}
