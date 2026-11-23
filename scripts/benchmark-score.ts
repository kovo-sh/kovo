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
  /** Shape of the confirming spec's mutated input, used to attribute shared-endpoint evidence. */
  specSubject?: SpecSubject
}

/**
 * What a replay spec actually mutated/read. Used only for attribution: when several targets share
 * one endpoint (e.g. two flaws behind `/graphql`), a spec whose mutated parameter is demonstrably a
 * different input cannot be credited to a target that declares one.
 */
export interface SpecSubject {
  /** Named parameter the proof varied (`paramName` on SQLi-shaped specs). */
  paramName?: string
  /** Recorded GraphQL operation, whose selection-set identifiers bind the resolver path. */
  query?: string
}

export function specSubjectOf(spec: Record<string, unknown> | undefined): SpecSubject | undefined {
  if (!spec) return undefined
  const paramName = typeof spec.paramName === 'string' ? spec.paramName.trim() : ''
  const query = typeof spec.graphqlQuery === 'string' ? spec.graphqlQuery : ''
  if (!paramName && !query) return undefined
  return { ...(paramName ? { paramName } : {}), ...(query ? { query } : {}) }
}

/**
 * True unless the spec explicitly binds a *different* input than the target declares. Absence of an
 * explicit subject (authz chains, introspection proofs) is not evidence against the target, so it
 * stays attributable; only a contradictory, observable binding disqualifies the pairing.
 */
export function specBindsParam(subject: SpecSubject | undefined, param: string | undefined): boolean {
  if (!subject || !param) return true
  const wanted = param.split('.').map(part => part.trim().toLowerCase()).filter(part => part.length > 0)
  if (wanted.length === 0) return true
  if (subject.paramName) {
    const named = subject.paramName.toLowerCase()
    return named === wanted.join('.') || wanted.includes(named) || named.split('.').every(part => wanted.includes(part))
  }
  if (subject.query) {
    const identifiers = new Set((subject.query.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []).map(token => token.toLowerCase()))
    const meaningful = wanted.filter(part => !/^\d+$/.test(part))
    return meaningful.length > 0 && meaningful.every(part => identifiers.has(part))
  }
  return true
}

/** Stable key for an endpoint template, so two targets on the same route are detectable. */
export function endpointKey(template: string): string {
  const path = template.split('?')[0].split('#')[0].replace(/\/+$/, '')
  return (path || '/').replace(/(:[A-Za-z0-9_]+|\{[^}]+\}|\[[^\]]+\])/g, ':id')
}

/** Endpoints declared by more than one non-decoy target. */
export function sharedEndpointKeys(challenges: ReadonlyArray<{ endpoint: string; isDecoy?: boolean }>): Set<string> {
  const counts = new Map<string, number>()
  for (const challenge of challenges) {
    if (challenge.isDecoy) continue
    const key = endpointKey(challenge.endpoint)
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return new Set([...counts].filter(([, count]) => count > 1).map(([key]) => key))
}

export interface ScoringInput {
  discoveredPaths: string[]
  outcomes: ScoredOutcome[]
  encodingSkipPaths: string[]
  /** Paths for which hypotheses were formed but never executed (run budget/deadline reached). */
  budgetSkippedPaths: string[]
  /**
   * Endpoints shared by more than one target: here a confirming spec must not bind a different
   * declared input, otherwise one finding is credited to two vulnerabilities (or the wrong one).
   */
  sharedEndpointKeys?: ReadonlySet<string>
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
  [/race/i, ['race_burst', 'workflow_invariant']],
  [/workflow|business/i, ['workflow_invariant', 'race_burst']],
  [/command|os_command|rce/i, ['command_injection']],
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
  // A shared endpoint can host several distinct flaws. Confirm against a spec whose observed input
  // is not explicitly a different parameter than this target declares.
  const strictBinding = Boolean(input.sharedEndpointKeys?.has(endpointKey(c.endpoint)))
  const attributed = strictBinding ? relevant.filter(o => specBindsParam(o.specSubject, c.param)) : relevant
  const trace: TargetTrace = {
    id: c.id,
    isDecoy: Boolean(c.isDecoy),
    vulnClass: c.vulnClass,
    surfaceDiscovered,
    hypothesisFormed: relevant.length > 0,
    signalObserved: relevant.some(o => o.signal),
    specSubmitted: relevant.some(o => o.specSubmitted),
    confirmed: attributed.some(o => o.confirmed),
    probeClass: attributed.find(o => o.confirmed)?.probeClass ?? attributed.find(o => o.signal)?.probeClass ?? attributed[0]?.probeClass ?? relevant[0]?.probeClass ?? null,
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
