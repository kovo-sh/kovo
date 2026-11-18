import { z } from 'zod'
import { referrerPolicies } from '../domain.ts'
import type { CheckCoverage, Finding, PreparedObservation, ResponseCheckId } from '../domain.ts'
import type { PublicObservation } from './broker.ts'

type Baseline = { minimum: number } | { allowed: readonly string[] }
type CheckValue = number | string | null
type Control = {
  id: ResponseCheckId
  field: keyof Pick<PreparedObservation, 'transportMaxAge' | 'contentTypeOptions' | 'referrerPolicy'>
  title: string
  findingTitle: string
  severity: Finding['severity']
  expected: string
  baseline: Baseline
  impact: string
  remediation: string
  recheck: string
}

const controls: readonly Control[] = [
  {
    id: 'hsts', field: 'transportMaxAge', title: 'HSTS policy',
    findingTitle: 'HSTS max-age missing or disabled', severity: 'low',
    expected: 'A positive Strict-Transport-Security max-age.',
    baseline: { minimum: 1 },
    impact: 'A browser without a stored, preloaded, or parent-domain HSTS policy can still attempt an HTTP connection on a later visit.',
    remediation: 'Set Strict-Transport-Security with a positive max-age at the HTTPS server or edge after confirming HTTPS readiness.',
    recheck: 'Review a fresh authorized HTTPS response for this host and confirm the max-age is positive.',
  },
  {
    id: 'nosniff', field: 'contentTypeOptions', title: 'MIME sniffing protection',
    findingTitle: 'MIME sniffing protection missing', severity: 'informational',
    expected: 'X-Content-Type-Options set to nosniff.',
    baseline: { allowed: ['nosniff'] },
    impact: 'The response lacks the explicit safeguard that enforces declared MIME types for script and stylesheet loads.',
    remediation: 'Set X-Content-Type-Options to nosniff at the server or edge. Confirm that scripts and stylesheets have the intended Content-Type.',
    recheck: 'Review a fresh authorized response for nosniff and check that scripts and stylesheets in a controlled browser session still load.',
  },
  {
    id: 'referrer-policy', field: 'referrerPolicy', title: 'Referrer policy',
    findingTitle: 'Referrer policy permits full cross-origin URLs', severity: 'low',
    expected: 'No explicit header policy that sends full URLs to other HTTPS origins.',
    baseline: {
      allowed: ['absent', ...referrerPolicies.filter(policy => policy !== 'unsafe-url' && policy !== 'no-referrer-when-downgrade')],
    },
    impact: 'Under this response policy, cross-origin HTTPS requests can carry the page path and query. Document and link policy can affect individual requests.',
    remediation: 'Set Referrer-Policy to strict-origin-when-cross-origin or a more restrictive policy that meets the application’s needs.',
    recheck: 'Review a fresh authorized response and confirm the last recognized Referrer-Policy value is restrictive.',
  },
]

type Comparison = { id: ResponseCheckId; observed: CheckValue; baseline: Baseline }

export type ResponseReview = {
  rule: Control
  coverage: CheckCoverage
  comparison?: Comparison
}

function displayValue(value: CheckValue) {
  if (typeof value === 'number') return value + ' seconds'
  if (value === null) return 'No usable max-age recorded'
  if (value === 'absent') return 'Header absent'
  if (value === 'unrecognized') return 'Header value unrecognized'
  return value
}

export function responseReview(observation: PublicObservation | null | undefined, readNote?: string): ResponseReview[] {
  // A successful final response on a different host cannot establish the policy of the initiating host.
  const blocked = !observation
    ? readNote ?? 'A response under the current approval was unavailable.'
    : observation.origin !== observation.finalOrigin
      ? 'The final response came from ' + new URL(observation.finalOrigin).hostname + '.'
      : observation.status < 200 || observation.status >= 300
        ? 'The recorded response returned HTTP ' + observation.status + '.'
        : null
  return controls.map(rule => {
    const coverage: CheckCoverage = {
      id: rule.id, title: rule.title, expected: rule.expected,
      observed: null, status: 'inconclusive', reason: blocked ?? 'Verification is pending.',
    }
    if (blocked || !observation) return { rule, coverage }
    if (rule.id === 'referrer-policy') {
      if (observation.mediaType === 'unknown') {
        return { rule, coverage: { ...coverage, reason: 'The response media type could not be determined.' } }
      }
      if (observation.status === 204 || observation.status === 205 ||
          !['text/html', 'application/xhtml+xml'].includes(observation.mediaType)) {
        return { rule, coverage: { ...coverage, status: 'not-applicable', reason: 'This check applies to HTML documents.' } }
      }
    }
    const observed = observation[rule.field]
    if (observed === undefined) {
      return { rule, coverage: { ...coverage, reason: 'This header was outside the recorded observation.' } }
    }
    coverage.observed = displayValue(observed)
    if (rule.id === 'referrer-policy' && observed === 'unrecognized') {
      return { rule, coverage: { ...coverage, reason: 'The header could not be interpreted as a recognized referrer policy.' } }
    }
    return { rule, coverage, comparison: { id: rule.id, observed, baseline: rule.baseline } }
  })
}

export function meetsBaseline({ observed, baseline }: Comparison) {
  if ('minimum' in baseline) return typeof observed === 'number' && observed >= baseline.minimum
  return typeof observed === 'string' && baseline.allowed.includes(observed)
}

export const responseVerificationCommand = [
  "jq 'map({id, outcome: (",
  '  if .baseline.minimum != null then',
  '    if (.observed | type) == "number" and .observed >= .baseline.minimum then "met" else "gap" end',
  '  else',
  '    if (.observed as $value | .baseline.allowed | index($value)) != null then "met" else "gap" end',
  '  end',
  ")})' /evidence/checks.json > /work/verification.json",
].join('\n')

const outcomes = z.array(z.object({
  id: z.enum(['hsts', 'nosniff', 'referrer-policy']),
  outcome: z.enum(['met', 'gap']),
})).max(controls.length)

export function readComparisons(output: string | undefined) {
  if (!output) return new Map<ResponseCheckId, 'met' | 'gap'>()
  try {
    const results = outcomes.parse(JSON.parse(output))
    const map = new Map(results.map(result => [result.id, result.outcome]))
    if (map.size === results.length) return map
  } catch {
    // An incomplete worker result is handled as inconclusive.
  }
  return new Map<ResponseCheckId, 'met' | 'gap'>()
}

export function checkCoverage(review: ResponseReview, result: 'met' | 'gap' | undefined): CheckCoverage {
  const { coverage, comparison } = review
  if (!comparison) return coverage
  if (!result || (result === 'met') !== meetsBaseline(comparison)) {
    return { ...coverage, reason: 'The worker did not return a valid comparison for this observation.' }
  }
  return { ...coverage, status: result, reason: result === 'met'
    ? 'The recorded value meets the response baseline.'
    : 'The recorded value falls outside the response baseline.' }
}
