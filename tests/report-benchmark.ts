import type { Verdict } from '../scripts/report-metrics.ts'
import type { AssessmentCheckId } from '../src/domain.ts'
import { healthyOrigin, primaryOrigin, unavailableOrigin } from './scenarios.ts'

export const benchmarkSuite = 'northstar-report-v1'
export { scoreReportCases, verdictSchema } from '../scripts/report-metrics.ts'
export type { Verdict } from '../scripts/report-metrics.ts'

export type ExpectedCase = {
  origin: string
  check: AssessmentCheckId
  caseId?: string
  expected: Verdict
}

type ReportScenario = { version: number; partial: boolean; basis: string; cases: ExpectedCase[] }

function responseCases(origin: string, expected: Verdict): ExpectedCase[] {
  const checks = ['hsts', 'nosniff', 'referrer-policy'] as const
  return checks.map(check => ({ origin, check, expected }))
}

function accessCase(caseId: string, expected: Verdict): ExpectedCase {
  return { origin: primaryOrigin, check: 'access-policy', caseId, expected }
}

// These labels come from the controlled inputs, independently of the report and check implementation.
export const benchmarkScenarios = {
  'response-multi-host': {
    version: 2, partial: false,
    basis: 'The main response omits HSTS and nosniff and uses unsafe-url. The other host returns HTTP 503.',
    cases: [...responseCases(primaryOrigin, 'confirmed'), ...responseCases(unavailableOrigin, 'inconclusive')],
  },
  'response-interrupted': {
    version: 1, partial: true,
    basis: 'The operator stops the same run before verification while the second response remains unavailable.',
    cases: [...responseCases(primaryOrigin, 'untested'), ...responseCases(unavailableOrigin, 'untested')],
  },
  'response-healthy': {
    version: 1, partial: false,
    basis: 'The response has positive HSTS max-age, nosniff, and strict-origin-when-cross-origin.',
    cases: responseCases(healthyOrigin, 'met'),
  },
  'access-policy': {
    version: 1, partial: false,
    basis: 'Billing export is incorrectly allowed. Audit summary is incorrectly denied. Read summary is correctly allowed. Modify schedule has no recorded decision.',
    cases: [accessCase('billing-export', 'confirmed'), accessCase('audit-summary', 'confirmed'),
      accessCase('read-summary', 'met'), accessCase('modify-schedule', 'inconclusive')],
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
  linkedEvidence?: boolean
  fixGuidance?: boolean
}

export type ReportResult = { scenario: ScenarioId; cases: CaseResult[]; unmatchedConfirmations: number }
