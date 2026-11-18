import { assessmentCheckTitles, referrerPolicies, responseCheckIds } from '../domain.ts'
import type { CheckCoverage, PreparedObservation, ResponseCheckId } from '../domain.ts'
import type { PublicObservation } from './broker.ts'
import type { Baseline, CheckValue, EvidenceReview, FindingRule } from './evidence-checks.ts'

type Control = FindingRule & {
  id: ResponseCheckId
  field: keyof Pick<PreparedObservation,
    'transportMaxAge' | 'contentTypeOptions' | 'referrerPolicy' | 'contentSecurityPolicy' |
    'frameProtection' | 'serverDisclosure' | 'corsPolicy' | 'errorExposure' | 'sessionCookiePolicy'>
  expected: string
  baseline: Baseline
  htmlOnly?: boolean
  notApplicable?: readonly string[]
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
    category: 'Transport security', cwe: 'CWE-319',
    verification: 'Compared the recorded Strict-Transport-Security max-age with a positive-duration baseline.',
  },
  {
    id: 'nosniff', field: 'contentTypeOptions', title: assessmentCheckTitles.nosniff,
    findingTitle: 'MIME sniffing protection missing', severity: 'informational',
    expected: 'X-Content-Type-Options set to nosniff.',
    baseline: { allowed: ['nosniff'] },
    impact: 'The response lacks the explicit safeguard that enforces declared MIME types for script and stylesheet loads.',
    remediation: 'Set X-Content-Type-Options to nosniff at the server or edge. Confirm that scripts and stylesheets have the intended Content-Type.',
    recheck: 'Review a fresh authorized response for nosniff and check that scripts and stylesheets in a controlled browser session still load.',
    category: 'Browser hardening', cwe: 'CWE-16',
    verification: 'Compared the normalized X-Content-Type-Options value with nosniff.',
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
    category: 'Information exposure', cwe: 'CWE-200', htmlOnly: true,
    verification: 'Parsed the effective Referrer-Policy token and compared it with policies that do not send full URLs cross-origin.',
  },
  {
    id: 'content-security-policy', field: 'contentSecurityPolicy', title: assessmentCheckTitles['content-security-policy'],
    findingTitle: 'Content Security Policy is not enforced', severity: 'low',
    expected: 'An enforced Content-Security-Policy header on HTML documents.',
    baseline: { allowed: ['enforced'] }, htmlOnly: true,
    impact: 'Without an enforced policy, the browser has no response-level restriction on where scripts and other active content may load from. This increases the impact of a separate injection defect; it is not proof of injection by itself.',
    remediation: 'Deploy an enforced Content-Security-Policy tailored to the application. Start from report-only telemetry, remove unsafe allowances where practical, then enforce the tested policy.',
    recheck: 'Load representative application routes and confirm an enforced Content-Security-Policy is present without blocking required resources.',
    category: 'Browser hardening', cwe: 'CWE-693',
    verification: 'Distinguished an enforced Content-Security-Policy from report-only, absent, and malformed values.',
  },
  {
    id: 'frame-protection', field: 'frameProtection', title: assessmentCheckTitles['frame-protection'],
    findingTitle: 'HTML response can be embedded without a recorded frame restriction', severity: 'low',
    expected: 'A valid frame-ancestors directive or X-Frame-Options DENY/SAMEORIGIN.',
    baseline: { allowed: ['x-frame-options', 'csp-frame-ancestors', 'both'] }, htmlOnly: true,
    impact: 'An attacker-controlled site may be able to frame the page and visually trick a user into interacting with it. Exploitability depends on the page actions and browser behavior.',
    remediation: "Set Content-Security-Policy frame-ancestors to the application’s intended embedding policy. Retain X-Frame-Options for older clients when needed.",
    recheck: 'Attempt to frame representative sensitive routes from an unapproved origin and confirm the browser blocks the load.',
    category: 'UI redress protection', cwe: 'CWE-1021',
    verification: 'Checked both CSP frame-ancestors and valid X-Frame-Options values.',
  },
  {
    id: 'server-disclosure', field: 'serverDisclosure', title: assessmentCheckTitles['server-disclosure'],
    findingTitle: 'Response discloses server technology details', severity: 'informational',
    expected: 'No product, framework, or version disclosure in response headers.',
    baseline: { allowed: ['absent', 'generic'] },
    impact: 'Product and framework hints reduce reconnaissance effort, but do not establish that a vulnerable version is running.',
    remediation: 'Remove or generalize unnecessary Server and X-Powered-By details at the application or edge. Do not rely on header suppression as a substitute for patching.',
    recheck: 'Review a fresh response and confirm product, framework, and version details are absent from response headers.',
    category: 'Information exposure', cwe: 'CWE-200',
    verification: 'Classified normalized Server and X-Powered-By metadata without treating a generic edge identifier as a vulnerability.',
  },
  {
    id: 'cors-policy', field: 'corsPolicy', title: assessmentCheckTitles['cors-policy'],
    findingTitle: 'Arbitrary cross-origin credentialed reads are permitted', severity: 'high',
    expected: 'No reflection of an arbitrary Origin together with credentialed cross-origin access.',
    baseline: { allowed: ['absent', 'restricted', 'wildcard', 'reflected-origin'] },
    impact: 'A malicious website could issue credentialed browser requests and read responses in a victim’s session when the affected endpoint uses ambient credentials.',
    remediation: 'Use an exact allowlist of trusted origins, reject unknown origins, and enable Access-Control-Allow-Credentials only for endpoints that require it. Send Vary: Origin for dynamic decisions.',
    recheck: 'Repeat preflight and actual requests from an untrusted origin with credentials and confirm the response does not grant readable cross-origin access.',
    category: 'Cross-origin access control', cwe: 'CWE-942',
    verification: 'Compared a supplied arbitrary-origin probe with the credentialed CORS safety baseline.',
  },
  {
    id: 'error-exposure', field: 'errorExposure', title: assessmentCheckTitles['error-exposure'],
    findingTitle: 'Error response exposes internal implementation details', severity: 'low',
    expected: 'No stack trace, internal path, or implementation detail in externally visible errors.',
    baseline: { allowed: ['none'] },
    impact: 'Internal paths and stack frames can reveal implementation structure that helps an attacker focus later testing. The disclosure is not code execution by itself.',
    remediation: 'Return a stable public error envelope and log detailed exceptions only to protected server-side telemetry.',
    recheck: 'Repeat the recorded malformed request and confirm the public response contains no stack frames, source paths, secrets, or internal identifiers.',
    category: 'Error handling', cwe: 'CWE-209',
    verification: 'Compared the supplied error-response classification with a no-internal-details baseline.',
  },
  {
    id: 'session-cookie', field: 'sessionCookiePolicy', title: assessmentCheckTitles['session-cookie'],
    findingTitle: 'Session cookie is missing required browser protections', severity: 'medium',
    expected: 'Session cookies set with both Secure and HttpOnly.',
    baseline: { allowed: ['secure-httponly'] }, notApplicable: ['none'],
    impact: 'A session cookie without Secure can traverse a cleartext request path; without HttpOnly it is accessible to injected script. The recorded classification does not by itself prove session theft.',
    remediation: 'Set Secure and HttpOnly on every session-bearing cookie, choose a SameSite policy that matches the login flow, and keep cookie scope as narrow as practical.',
    recheck: 'Authenticate through the approved test flow and confirm every session-bearing Set-Cookie value includes Secure and HttpOnly with the intended SameSite and scope.',
    category: 'Session management', cwe: 'CWE-614 / CWE-1004',
    verification: 'Compared the supplied session-cookie classification with the Secure plus HttpOnly baseline.',
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
    if (rule.htmlOnly) {
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
    if (typeof observed === 'string' && rule.notApplicable?.includes(observed)) {
      return { rule, coverage: { ...coverage, status: 'not-applicable', reason: 'No session-bearing cookie was present in the supplied observation.' } }
    }
    if (rule.id === 'referrer-policy' && observed === 'unrecognized') {
      return { rule, coverage: { ...coverage, reason: 'The header could not be interpreted as a recognized referrer policy.' } }
    }
    return { rule, coverage, comparison: { id: rule.id, observed, baseline: rule.baseline } }
  })
}
