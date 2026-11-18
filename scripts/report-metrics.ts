import { z } from 'zod'

export const verdictSchema = z.enum(['confirmed', 'met', 'inconclusive', 'untested'])
export type Verdict = z.infer<typeof verdictSchema>

export function scoreReportCases(cases: { expected: Verdict; reported: Verdict }[], unmatchedConfirmations: number) {
  const expected = cases.filter(row => row.expected === 'confirmed').length
  const confirmed = cases.filter(row => row.reported === 'confirmed').length + unmatchedConfirmations
  const correct = cases.filter(row => row.expected === 'confirmed' && row.reported === 'confirmed').length
  return {
    cases: cases.length,
    agreeingVerdicts: cases.filter(row => row.expected === row.reported).length,
    expectedConfirmations: expected,
    reportedConfirmations: confirmed,
    correctConfirmations: correct,
    falseConfirmations: confirmed - correct,
    missedConfirmations: expected - correct,
    precision: confirmed ? correct / confirmed : null,
    recall: expected ? correct / expected : null,
    met: cases.filter(row => row.reported === 'met').length,
    inconclusive: cases.filter(row => row.reported === 'inconclusive').length,
    untested: cases.filter(row => row.reported === 'untested').length,
  }
}
