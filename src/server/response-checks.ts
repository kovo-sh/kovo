import { assessmentCheckTitles, referrerPolicies, responseCheckIds } from '../domain.ts'
import type { CheckCoverage, PreparedObservation, ResponseCheckId } from '../domain.ts'
import type { PublicObservation } from './broker.ts'
import type { Baseline, CheckValue, EvidenceReview, FindingRule } from './evidence-checks.ts'

type Control = FindingRule & {
  id: ResponseCheckId
  field: keyof Pick<PreparedObservation, 'transportMaxAge' | 'contentTypeOptions' | 'referrerPolicy'>
  expected: string
  baseline: Baseline
}

const controls: readonly Control[] = [
  {
    id: 'hsts', field: 'transportMaxAge', title: assessmentCheckTitles.hsts,
    findingTitle: 'HSTS max-age missing or disabled', severity: 'low',
    expected: 'A positive Strict-Transport-Security max-age.',
    baseline: { minimum: 1 },
    impact: 'A browser without a stored, preloaded, or parent-domain HSTS policy can still attempt an HTTP connection on a later visit.',
    remediation: 'Set Strict-Transport-Security with a positive max-age at the HTTPS server or edge after confirming HTTPS readiness.',
    recheck: 'Review a fresh authorized HTTPS response for this host and confirm the max-age is positive.',
  },
  {
    id: 'nosniff', field: 'contentTypeOptions', title: assessmentCheckTitles.nosniff,
    findingTitle: 'MIME sniffing protection missing', severity: 'informational',
    expected: 'X-Content-Type-Options set to nosniff.',
    baseline: { allowed: ['nosniff'] },
    impact: 'The response lacks the explicit safeguard that enforces declared MIME types for script and stylesheet loads.',
    remediation: 'Set X-Content-Type-Options to nosniff at the server or edge. Confirm that scripts and stylesheets have the intended Content-Type.',
    recheck: 'Review a fresh authorized response for nosniff and check that scripts and stylesheets in a controlled browser session still load.',
  },
  {
    id: 'referrer-policy', field: 'referrerPolicy', title: assessmentCheckTitles['referrer-policy'],
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

export function responseEvidence(observation: PublicObservation, checks: readonly ResponseCheckId[]) {
  const { origin, finalOrigin, status, mediaType, source } = observation
  const selected = controls.filter(rule => checks.includes(rule.id) && observation[rule.field] !== undefined)
  return {
    origin, finalOrigin, status, mediaType, source,
    ...Object.fromEntries(selected.map(rule => [rule.field, observation[rule.field]])),
    ...(checks.includes('hsts') ? { includeSubDomains: observation.includeSubDomains } : {}),
  }
}

function displayValue(value: CheckValue) {
  if (typeof value === 'number') return value + ' seconds'
  if (value === null) return 'No usable max-age recorded'
  if (value === 'absent') return 'Header absent'
  if (value === 'unrecognized') return 'Header value unrecognized'
  return value
}

export function responseReview(observation: PublicObservation | null | undefined, readNote?: string,
  checks: readonly ResponseCheckId[] = responseCheckIds): EvidenceReview[] {
  // A successful final response on a different host cannot establish the policy of the initiating host.
  const blocked = !observation
    ? readNote ?? 'A response under the current approval was unavailable.'
    : observation.origin !== observation.finalOrigin
      ? 'The final response came from ' + new URL(observation.finalOrigin).hostname + '.'
      : observation.status < 200 || observation.status >= 300
        ? 'The recorded response returned HTTP ' + observation.status + '.'
        : null
  return controls.filter(rule => checks.includes(rule.id)).map(rule => {
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
