import { z } from 'zod'
import { maxAccessPolicyCases } from '../access-policy.ts'
import { responseCheckIds } from '../domain.ts'
import type { AssessmentCheckId, CheckCoverage, Finding } from '../domain.ts'

export type Baseline = { minimum: number } | { allowed: readonly string[] }
export type CheckValue = number | string | null
export type Comparison = { id: string; observed: CheckValue; baseline: Baseline }
export type FindingRule = {
  id: AssessmentCheckId
  title: string
  findingTitle: string
  severity: Finding['severity']
  impact: string
  remediation: string
  recheck: string
  category?: string
  cwe?: string
  verification?: string
}

export type EvidenceReview = {
  rule: FindingRule
  coverage: CheckCoverage
  comparison?: Comparison
}

export function meetsBaseline({ observed, baseline }: Comparison) {
  if ('minimum' in baseline) return typeof observed === 'number' && observed >= baseline.minimum
  return typeof observed === 'string' && baseline.allowed.includes(observed)
}

export const verificationCommand = [
  "jq 'def access_comparisons:",
  '  if .access == null then [] else',
  '    .access as $policy',
  '    | ($policy.observed | map({key: .caseId, value: .decision}) | from_entries) as $recorded',
  '    | [$policy.expected[] | . as $case | $recorded[$case.caseId] as $actual',
  '       | select($actual != null)',
  '       | {id: ("access-policy:" + $case.caseId), observed: $actual, baseline: {allowed: [$case.decision]}}]',
  '  end;',
  '(.response + access_comparisons) | map({id, outcome: (',
  '  if .baseline.minimum != null then',
  '    if (.observed | type) == "number" and .observed >= .baseline.minimum then "met" else "gap" end',
  '  else',
  '    if (.observed as $value | .baseline.allowed | index($value)) != null then "met" else "gap" end',
  '  end',
  ")})' /evidence/verification-input.json > /work/verification.json",
].join('\n')

const outcomes = z.array(z.strictObject({
  id: z.string(),
  outcome: z.enum(['met', 'gap']),
})).max(maxAccessPolicyCases + responseCheckIds.length)

export function readComparisons(output: string | undefined, comparisons: Comparison[]) {
  if (!output) return new Map<string, 'met' | 'gap'>()
  try {
    const results = outcomes.parse(JSON.parse(output))
    const allowed = new Set(comparisons.map(comparison => comparison.id))
    const map = new Map(results.map(result => [result.id, result.outcome]))
    if (map.size === results.length && results.every(result => allowed.has(result.id))) return map
  } catch {
    // An incomplete worker result is handled as inconclusive.
  }
  return new Map<string, 'met' | 'gap'>()
}

export function checkCoverage(review: EvidenceReview, outcomes: ReadonlyMap<string, 'met' | 'gap'>): CheckCoverage {
  const { coverage, comparison } = review
  if (!comparison) return coverage
  const result = outcomes.get(comparison.id)
  if (!result || (result === 'met') !== meetsBaseline(comparison)) {
    return { ...coverage, reason: 'The worker did not return a valid comparison for this observation.' }
  }
  const baseline = review.rule.id === 'access-policy' ? 'supplied policy' : 'response baseline'
  return { ...coverage, status: result, reason: result === 'met'
    ? `The recorded value meets the ${baseline}.`
    : `The recorded value falls outside the ${baseline}.` }
}
