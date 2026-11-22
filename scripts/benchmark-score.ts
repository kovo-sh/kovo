/**
 * Scoring: maps what the live pipeline observed back onto manifest entries.
 * The manifest is the answer key and is consulted ONLY here, after probing has finished.
 */
import type { ManifestChallenge, TargetTrace } from './benchmark-core.ts'

export interface ScoredOutcome {
  /** Discovered endpoint path the hypothesis ran against. */
  path: string
  probeClass: string
  signal: boolean
  specSubmitted: boolean
  confirmed: boolean
  csrfRejected: boolean
  contextReset: boolean
  tierBlocked: boolean
  jqError: boolean
  spaCatchall: boolean
  skippedForBudget: boolean
}

export interface ScoringInput {
  discoveredPaths: string[]
  outcomes: ScoredOutcome[]
  encodingSkipPaths: string[]
  /** Paths for which hypotheses were formed but never executed (run budget/deadline reached). */
  budgetSkippedPaths: string[]
}

const classCompat: Array<[RegExp, string[]]> = [
  [/sqli_time|time/i, ['sqli_time_diff']],
  [/sqli|sql/i, ['sqli_boolean', 'sqli_time_diff']],
  [/idor|bola|bfla|authz|access/i, ['authz_matrix']],
  [/ssti|template/i, ['ssti_math']],
  [/ssrf/i, ['ssrf_canary']],
  [/xxe/i, ['xxe_canary']],
  [/xss|browser|dom/i, ['xss_context']],
  [/jwt|oauth|auth/i, ['auth_protocol_audit']],
  [/path|traversal/i, ['path_traversal_benign']],
  [/mass/i, ['mass_assignment']],
  [/cache/i, ['cache_poison_deception']],
  [/graphql/i, ['graphql_audit', 'sqli_boolean', 'authz_matrix']],
  [/second_order|stored/i, ['xss_context', 'ssrf_canary']],
  [/workflow|race|business/i, ['workflow_invariant']],
  [/csrf/i, ['sqli_boolean', 'authz_matrix', 'xss_context']],
]

export function compatibleClasses(vulnClass: string): string[] | null {
  const out = new Set<string>()
  for (const [re, classes] of classCompat) if (re.test(vulnClass)) for (const c of classes) out.add(c)
  return out.size ? [...out] : null
}

function templateToRegex(template: string): RegExp {
  const pathOnly = template.split('?')[0].split('#')[0]
  const body = pathOnly.split('/').map(seg => (/^(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])$/.test(seg) ? '[^/]+' : seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))).join('/')
  return new RegExp(`^${body}/?$`)
}

export function endpointMatches(manifestEndpoint: string, foundPath: string): boolean {
  const found = foundPath.split('?')[0].split('#')[0]
  const norm = (p: string) => p.replace(/(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])/g, ':id').replace(/\/+$/, '') || '/'
  if (norm(manifestEndpoint) === norm(found)) return true
  return templateToRegex(manifestEndpoint).test(found.replace(/\/+$/, '') || '/')
}

export function scoreChallenge(c: ManifestChallenge, input: ScoringInput): TargetTrace {
  const compat = compatibleClasses(c.vulnClass)
  const surfaceDiscovered = input.discoveredPaths.some(p => endpointMatches(c.endpoint, p))
  const onEndpoint = input.outcomes.filter(o => endpointMatches(c.endpoint, o.path))
  const relevant = onEndpoint.filter(o => !compat || compat.includes(o.probeClass))
  const trace: TargetTrace = {
    id: c.id,
    isDecoy: Boolean(c.isDecoy),
    vulnClass: c.vulnClass,
    surfaceDiscovered,
    hypothesisFormed: relevant.length > 0,
    signalObserved: relevant.some(o => o.signal),
    specSubmitted: relevant.some(o => o.specSubmitted),
    confirmed: relevant.some(o => o.confirmed),
    probeClass: relevant.find(o => o.confirmed)?.probeClass ?? relevant.find(o => o.signal)?.probeClass ?? relevant[0]?.probeClass ?? null,
    encodingUnsupported: relevant.length === 0 && input.encodingSkipPaths.some(p => endpointMatches(c.endpoint, p)),
    csrfRejected: onEndpoint.some(o => o.csrfRejected),
    contextReset: onEndpoint.some(o => o.contextReset),
    tierBlocked: onEndpoint.some(o => o.tierBlocked),
    jqError: relevant.some(o => o.jqError),
    spaCatchall: relevant.some(o => o.spaCatchall),
    budgetExhausted: input.budgetSkippedPaths.some(p => endpointMatches(c.endpoint, p)) || onEndpoint.some(o => o.skippedForBudget),
  }
  return trace
}

export function scoreManifest(challenges: readonly ManifestChallenge[], input: ScoringInput): TargetTrace[] {
  return challenges.map(c => scoreChallenge(c, input))
}
