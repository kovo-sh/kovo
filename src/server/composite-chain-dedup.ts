/**
 * Pure multi-step composite chain DAG deduplication & upstream-overlap helpers shared by
 * `src/server/store-findings.ts` and `src/server/exec-verify.ts`.
 *
 * Extracted from the oversized repository/verifier files to satisfy the monotone size ratchet
 * (`R3-10`) without altering any confirmation semantics or introducing import cycles.
 */
import type { Finding } from '../domain.ts'
import { mergeChainFindings } from '../report-summary.ts'
import { normalizeEndpointTemplate, normalizeOrigin } from './finding-fingerprint.ts'

const SHARED_AUTH_UTILITY_ROUTE_RE =
  /^(?:\/(?:api|v\d+)(?:\/v\d+)?)?(?:\/(?:login|logout|me|health|healthz|token|session)|\/oauth\/token|\/auth(?:\/(?:login|logout|callback|token|session|me|refresh))?)$/i
const LEADING_VERB_RE = /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE)\s+(.+)$/i
const MUTATING_HTTP_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

export function isGenericSharedAuthOrUtilityEndpoint(normalizedEndpoint: string): boolean {
  const trimmed = normalizedEndpoint.trim()
  if (!trimmed) return false
  const clean = trimmed.length > 1 ? trimmed.replace(/\/+$/, '') : trimmed
  return SHARED_AUTH_UTILITY_ROUTE_RE.test(clean)
}

function normalizeCompositeMethod(raw: unknown): string | null {
  if (typeof raw !== 'string') return null
  const upper = raw.trim().toUpperCase()
  return upper && upper !== 'ANY' ? upper : null
}

function parseCompositeEndpoint(raw: unknown): { endpoint: string; method: string | null } | null {
  if (typeof raw !== 'string') return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  const match = LEADING_VERB_RE.exec(trimmed)
  if (match?.[1] && match[2]?.trim()) {
    return { endpoint: match[2].trim(), method: match[1].toUpperCase() }
  }
  return { endpoint: trimmed, method: null }
}

function compositeMethodsCompatible(a: string | null | undefined, b: string | null | undefined): boolean {
  const ma = normalizeCompositeMethod(a)
  const mb = normalizeCompositeMethod(b)
  return !ma || !mb || ma === mb
}

function isLoopbackHostname(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]'
}

function effectiveUrlPort(u: URL): string {
  if (u.port) return u.port
  return u.protocol === 'https:' ? '443' : '80'
}

/**
 * Exact scheme + port match; allows loopback hostname aliasing (`127.0.0.1` <-> `localhost` <-> `::1`)
 * ONLY on the exact same port so distinct local apps/twins on different ports never collapse.
 */
export function compositeChainOriginsEquivalent(
  originA: string | null | undefined,
  originB: string | null | undefined,
): boolean {
  const a = originA ? normalizeOrigin(originA) : ''
  const b = originB ? normalizeOrigin(originB) : ''
  if (!a || !b) return false
  if (a === b) return true
  try {
    const uA = new URL(a)
    const uB = new URL(b)
    if (uA.protocol !== uB.protocol || effectiveUrlPort(uA) !== effectiveUrlPort(uB)) return false
    return isLoopbackHostname(uA.hostname.toLowerCase()) && isLoopbackHostname(uB.hostname.toLowerCase())
  } catch {
    return false
  }
}

export interface CompositeChainDedupSignature {
  chainId: string | null
  hopCount: number
  verifiedEdgeCount: number
  isModeA: boolean
  origin: string | null
  terminalMethod: string | null
  terminalNormalizedEndpoint: string | null
  terminalKey: string | null
  effectiveActionTerminalKey: string | null
  nonGenericHopKeys: ReadonlySet<string>
  upstreamNonGenericKeys: ReadonlySet<string>
}

interface RawCompositeHopLike {
  hopId?: unknown
  target?: { origin?: unknown; method?: unknown; pathAndQuery?: unknown } | null
  exchangeIds?: unknown
}

interface RawCompositeReceiptLike {
  chainId?: unknown
  replayMode?: unknown
  hops?: RawCompositeHopLike[]
  causalEdges?: unknown[]
  terminalImpact?: { terminalHopId?: unknown; terminalExchangeId?: unknown } | null
}

export function extractCompositeChainDedupSignature(input: {
  origin?: string | null
  evidence?: Record<string, unknown> | null
  compositeReceipt?: unknown
  compositeVerification?: unknown
  hostExchanges?: ReadonlyMap<string, { origin?: string; method?: string | null; pathAndQuery?: string }>
}): CompositeChainDedupSignature | null {
  const ev = input.evidence && typeof input.evidence === 'object' ? input.evidence : undefined
  const receipt = (input.compositeReceipt ?? ev?.compositeReceipt) as RawCompositeReceiptLike | undefined
  if (!receipt || typeof receipt !== 'object' || !Array.isArray(receipt.hops) || !receipt.hops.length) return null
  const ver = (input.compositeVerification ?? ev?.compositeVerification) as
    | { terminalEndpoint?: unknown; verifiedEdges?: unknown[] }
    | undefined
  const chainId = typeof receipt.chainId === 'string' && receipt.chainId.trim() ? receipt.chainId.trim() : null
  const hopCount = receipt.hops.length
  const verifiedEdgeCount = Array.isArray(ver?.verifiedEdges)
    ? ver.verifiedEdges.length
    : (Array.isArray(receipt.causalEdges) ? receipt.causalEdges.length : 0)

  const resolvedHops: Array<{ method: string | null; normalizedEndpoint: string; key: string; generic: boolean }> = []
  const nonGenericHopKeys = new Set<string>()
  for (const hop of receipt.hops) {
    let rawPath: unknown = hop?.target?.pathAndQuery
    let rawMethod: unknown = hop?.target?.method
    if (input.hostExchanges && Array.isArray(hop?.exchangeIds)) {
      for (const exId of hop.exchangeIds) {
        const ex = typeof exId === 'string' ? input.hostExchanges.get(exId) : undefined
        if (ex?.pathAndQuery) {
          rawPath = ex.pathAndQuery
          rawMethod = ex.method ?? rawMethod
          break
        }
      }
    }
    const parsed = parseCompositeEndpoint(rawPath)
    if (!parsed) continue
    const normalizedEndpoint = normalizeEndpointTemplate(parsed.endpoint)
    const method = parsed.method ?? normalizeCompositeMethod(rawMethod)
    const key = `${method ?? '*'} ${normalizedEndpoint}`
    const generic = isGenericSharedAuthOrUtilityEndpoint(normalizedEndpoint)
    resolvedHops.push({ method, normalizedEndpoint, key, generic })
    if (!generic) nonGenericHopKeys.add(key)
  }

  const termHopId = typeof receipt.terminalImpact?.terminalHopId === 'string'
    ? receipt.terminalImpact.terminalHopId
    : null
  const termHop = (termHopId ? receipt.hops.find(h => h?.hopId === termHopId) : undefined)
    ?? receipt.hops[receipt.hops.length - 1]
  const termEx = typeof receipt.terminalImpact?.terminalExchangeId === 'string' && input.hostExchanges
    ? input.hostExchanges.get(receipt.terminalImpact.terminalExchangeId)
    : undefined
  const termParsed = parseCompositeEndpoint(ver?.terminalEndpoint)
    ?? parseCompositeEndpoint(ev?.terminalEndpoint)
    ?? parseCompositeEndpoint(termEx?.pathAndQuery)
    ?? parseCompositeEndpoint(termHop?.target?.pathAndQuery)
  const terminalNormalizedEndpoint = termParsed ? normalizeEndpointTemplate(termParsed.endpoint) : null
  const terminalMethod = termParsed?.method
    ?? normalizeCompositeMethod(termEx?.method)
    ?? normalizeCompositeMethod(termHop?.target?.method)
    ?? null
  const terminalKey = terminalNormalizedEndpoint ? `${terminalMethod ?? '*'} ${terminalNormalizedEndpoint}` : null
  if (terminalKey && terminalNormalizedEndpoint && !isGenericSharedAuthOrUtilityEndpoint(terminalNormalizedEndpoint)) {
    nonGenericHopKeys.add(terminalKey)
  }
  const upstreamNonGenericKeys = new Set<string>([...nonGenericHopKeys].filter(k => k !== terminalKey))

  let effectiveActionTerminalKey = terminalKey
  if (resolvedHops.length >= 2) {
    const pen = resolvedHops[resolvedHops.length - 2]
    if (
      resolvedHops.length >= 3
      && terminalMethod === 'GET'
      && pen && !pen.generic
      && pen.method && MUTATING_HTTP_METHODS.has(pen.method)
    ) {
      effectiveActionTerminalKey = pen.key
    } else if (terminalNormalizedEndpoint && isGenericSharedAuthOrUtilityEndpoint(terminalNormalizedEndpoint)) {
      const lastNonGen = [...resolvedHops].reverse().find(h => !h.generic)
      if (lastNonGen) effectiveActionTerminalKey = lastNonGen.key
    } else if (!terminalKey) {
      effectiveActionTerminalKey = resolvedHops[resolvedHops.length - 1]?.key ?? null
    }
  }

  return {
    chainId,
    hopCount,
    verifiedEdgeCount,
    isModeA: receipt.replayMode === 'fresh_clean_replay',
    origin: input.origin?.trim() || null,
    terminalMethod,
    terminalNormalizedEndpoint,
    terminalKey,
    effectiveActionTerminalKey,
    nonGenericHopKeys,
    upstreamNonGenericKeys,
  }
}

export function compositeChainRichnessScore(sig: CompositeChainDedupSignature | null | undefined): number {
  return sig ? (sig.hopCount * 100) + (sig.verifiedEdgeCount * 10) + (sig.isModeA ? 5 : 0) : 0
}

function setIntersectionCount(a: ReadonlySet<string>, b: ReadonlySet<string>): number {
  let count = 0
  const [sm, lg] = a.size <= b.size ? [a, b] : [b, a]
  for (const item of sm) if (lg.has(item)) count += 1
  return count
}

export type CompositeChainOverlapDecision = 'none' | 'collapse_in_place' | 'defer_to_supersession'

export function classifyCompositeChainOverlap(
  incoming: CompositeChainDedupSignature,
  existing: CompositeChainDedupSignature,
  options: { originsEquivalent: boolean; vulnClassesEquivalent: boolean },
): CompositeChainOverlapDecision {
  if (!options.originsEquivalent || incoming.hopCount < 2 || existing.hopCount < 2) return 'none'

  const sameTerminal = Boolean(
    incoming.terminalNormalizedEndpoint
    && existing.terminalNormalizedEndpoint
    && incoming.terminalNormalizedEndpoint === existing.terminalNormalizedEndpoint
    && compositeMethodsCompatible(incoming.terminalMethod, existing.terminalMethod),
  )
  const sameChainId = Boolean(incoming.chainId && existing.chainId && incoming.chainId === existing.chainId)
  if (sameTerminal) {
    if (options.vulnClassesEquivalent || sameChainId) return 'collapse_in_place'
    const upOverlap = setIntersectionCount(incoming.upstreamNonGenericKeys, existing.upstreamNonGenericKeys)
    return upOverlap >= 1 ? 'collapse_in_place' : 'none'
  }

  const inHops = incoming.nonGenericHopKeys
  const exHops = existing.nonGenericHopKeys
  const overlap = setIntersectionCount(inHops, exHops)
  if (
    incoming.effectiveActionTerminalKey
    && existing.effectiveActionTerminalKey
    && incoming.effectiveActionTerminalKey === existing.effectiveActionTerminalKey
    && overlap >= 1
  ) {
    return 'collapse_in_place'
  }
  if (!inHops.size || !exHops.size || !overlap) return 'none'

  const inSub = overlap === inHops.size
  const exSub = overlap === exHops.size
  const substantial = overlap >= 2 || overlap * 2 >= Math.min(inHops.size, exHops.size)
  const inTermInEx = Boolean(incoming.terminalKey && exHops.has(incoming.terminalKey))
  const exTermInIn = Boolean(existing.terminalKey && inHops.has(existing.terminalKey))

  if (incoming.hopCount > existing.hopCount && exSub && exTermInIn) return 'defer_to_supersession'
  if (inSub && incoming.hopCount <= existing.hopCount) return 'collapse_in_place'
  if (substantial && (inTermInEx || exTermInIn)) {
    return (incoming.hopCount > existing.hopCount && exTermInIn && !inTermInEx)
      ? 'defer_to_supersession'
      : 'collapse_in_place'
  }
  return 'none'
}

export function extractRowCompositeSignature(
  row: { finding: Finding },
  specRow?: { proofReceipt?: unknown; spec?: unknown } | null,
): CompositeChainDedupSignature | null {
  const ev = (row.finding as Finding & { evidence?: Record<string, unknown> }).evidence
  const pr = specRow?.proofReceipt && typeof specRow.proofReceipt === 'object'
    ? specRow.proofReceipt as Record<string, unknown>
    : undefined
  const specObj = specRow?.spec && typeof specRow.spec === 'object'
    ? specRow.spec as Record<string, unknown>
    : undefined
  return extractCompositeChainDedupSignature({
    origin: row.finding.origin,
    evidence: ev,
    compositeReceipt: ev?.compositeReceipt ?? pr?.compositeReceipt ?? specObj?.compositeReceipt,
    compositeVerification: ev?.compositeVerification ?? pr?.compositeVerification ?? specObj?.compositeVerification,
  })
}

export function mergeChainFindingWithCompositeUpgrade(existing: Finding, incoming: Finding): Finding {
  const merged = mergeChainFindings(existing, incoming)
  if (existing.status !== 'confirmed' || incoming.status !== 'confirmed') return merged
  const inEv = (incoming as Finding & { evidence?: Record<string, unknown> }).evidence
  const exEv = (existing as Finding & { evidence?: Record<string, unknown> }).evidence
  const inScore = compositeChainRichnessScore(extractCompositeChainDedupSignature({ origin: incoming.origin, evidence: inEv }))
  const exScore = compositeChainRichnessScore(extractCompositeChainDedupSignature({ origin: existing.origin, evidence: exEv }))
  if (inScore <= exScore) return merged
  return {
    ...merged,
    replaySpecId: incoming.replaySpecId ?? merged.replaySpecId,
    verification: incoming.verification,
    reason: incoming.reason,
    impact: incoming.impact,
    ...(inEv ? { evidence: inEv } : {}),
  } as Finding
}

export function matchesSameClassCompositeDuplicateRow(
  candidateOrigin: string,
  candidateSig: CompositeChainDedupSignature | null,
  row: { finding: Finding; sourceOrigins?: readonly string[] | null },
): { matched: boolean; rowSig: CompositeChainDedupSignature | null } {
  if (!candidateSig || candidateSig.hopCount < 2) return { matched: false, rowSig: null }
  const rowSig = extractRowCompositeSignature(row)
  if (!rowSig || rowSig.hopCount < 2) return { matched: false, rowSig }
  const originsEquivalent = [row.finding.origin, ...(row.sourceOrigins ?? [])]
    .some(o => compositeChainOriginsEquivalent(candidateOrigin, o))
  const decision = classifyCompositeChainOverlap(candidateSig, rowSig, {
    originsEquivalent,
    vulnClassesEquivalent: true,
  })
  return { matched: decision === 'collapse_in_place', rowSig }
}

export function sortChainDuplicateRows<T extends { id: string; finding: Finding }>(
  matches: T[],
  statusOrder: Readonly<Record<Finding['status'], number>>,
  sigLookup: (row: T) => CompositeChainDedupSignature | null,
): T[] {
  return matches.sort((a, b) =>
    (statusOrder[a.finding.status] - statusOrder[b.finding.status])
    || (compositeChainRichnessScore(sigLookup(b)) - compositeChainRichnessScore(sigLookup(a))),
  )
}

export interface UpstreamSupersessionEndpointLike {
  origin: string
  method: string | null
  normalizedEndpoint: string
  preconditionVulnClass?: string | null
}

/**
 * Substantial host-signed UPSTREAM overlap for shallower >=2-hop composite chains:
 * requires the earlier composite's terminal endpoint to appear in the deeper chain's non-generic
 * host-signed UPSTREAM set (exact origin + exact HTTP method), plus >=2 or >=50% hop overlap.
 */
export function matchSubstantialUpstreamCompositeOverlap<T extends UpstreamSupersessionEndpointLike>(input: {
  earlierCompReceipt: RawCompositeReceiptLike | undefined
  incomingHopCount: number
  earlierOrigin: string
  earlierEndpoints: readonly T[]
  upstreamNonGeneric: readonly T[]
  endpointsMatchExact: (earlier: T, upstream: T) => boolean
}): T[] {
  const { earlierCompReceipt, incomingHopCount, earlierOrigin, earlierEndpoints, upstreamNonGeneric, endpointsMatchExact } = input
  if (
    !earlierCompReceipt
    || !Array.isArray(earlierCompReceipt.hops)
    || earlierCompReceipt.hops.length < 2
    || incomingHopCount <= earlierCompReceipt.hops.length
    || earlierEndpoints.length < 2
    || !upstreamNonGeneric.length
  ) {
    return []
  }
  const earlierNonGeneric = earlierEndpoints.filter(ep => !isGenericSharedAuthOrUtilityEndpoint(ep.normalizedEndpoint))
  if (!earlierNonGeneric.length) return []
  const termHopId = typeof earlierCompReceipt.terminalImpact?.terminalHopId === 'string'
    ? earlierCompReceipt.terminalImpact.terminalHopId
    : null
  const termHop = (termHopId ? earlierCompReceipt.hops.find(h => h?.hopId === termHopId) : undefined)
    ?? earlierCompReceipt.hops[earlierCompReceipt.hops.length - 1]
  const parsedTerm = parseCompositeEndpoint(termHop?.target?.pathAndQuery)
  if (!parsedTerm) return []
  const termSpec = {
    origin: (typeof termHop?.target?.origin === 'string' && termHop.target.origin.trim()) || earlierOrigin,
    method: parsedTerm.method ?? normalizeCompositeMethod(termHop?.target?.method),
    normalizedEndpoint: normalizeEndpointTemplate(parsedTerm.endpoint),
  } as T
  if (isGenericSharedAuthOrUtilityEndpoint(termSpec.normalizedEndpoint)) return []
  if (!upstreamNonGeneric.some(up => endpointsMatchExact(termSpec, up))) return []

  const overlapSpecs: T[] = []
  let matchedCount = 0
  for (const ep of earlierNonGeneric) {
    const hits = upstreamNonGeneric.filter(up => endpointsMatchExact(ep, up))
    if (hits.length > 0) {
      matchedCount += 1
      overlapSpecs.push(...hits)
    }
  }
  return (matchedCount >= 2 || matchedCount * 2 >= earlierNonGeneric.length) ? overlapSpecs : []
}

const AUTHZ_PRIVESC_CWE_SET = new Set([
  'CWE-269', 'CWE-284', 'CWE-285', 'CWE-287', 'CWE-639', 'CWE-862', 'CWE-863',
])
const AUTHZ_PRIVESC_CLASS_SET = new Set([
  'broken_access_control', 'bola', 'bfla', 'idor', 'privilege_escalation', 'privesc',
  'auth_bypass', 'authentication_bypass', 'broken_auth', 'cross_tenant_read',
  'cross_tenant_write', 'cross_tenant_export', 'cross_tenant_exfiltration',
  'dual_tenant_abac', 'self_approved_payout', 'stale_privilege_use', 'temporal_revocation',
])
const VERSION_SEG_RE = /^(?:api|rest|v\d+)$/i
const TENANT_SCOPE_SEG_RE = /^(?:orgs?|organizations?|tenants?|workspaces?)$/i
const PARAM_SEG_RE = /^(?::[a-z0-9_]+|<[^>]+>|\{[^}]+\})$/i

/**
 * R6: Compatible authz / privilege-escalation / access-control class check for causal-prefix
 * supersession. Strictly excludes injection/XSS/SSRF/economic classes so distinct-class findings
 * are never hidden behind a deeper chain.
 */
export function isAuthzPrivescClassSupersessionCompatible(
  earlier: { cwe: string; vulnClass: string },
  composite: { vulnClasses: readonly string[] },
): boolean {
  const norm = (s: string) => s.trim().toLowerCase().replace(/[\s-]+/g, '_')
  const hasConcreteEarlierCwe = /^CWE-\d{1,5}$/.test(earlier.cwe)
  if (hasConcreteEarlierCwe && !AUTHZ_PRIVESC_CWE_SET.has(earlier.cwe)) return false
  const earlierInFamily = (hasConcreteEarlierCwe && AUTHZ_PRIVESC_CWE_SET.has(earlier.cwe))
    || (Boolean(earlier.vulnClass) && AUTHZ_PRIVESC_CLASS_SET.has(norm(earlier.vulnClass)))
  if (!earlierInFamily) return false
  return composite.vulnClasses.some(cls => AUTHZ_PRIVESC_CLASS_SET.has(norm(cls)))
}

function normalizedResourceFamilyRoot(normalizedEndpoint: string): string | null {
  const raw = normalizedEndpoint.split('?', 1)[0] ?? ''
  const segs = raw.split('/').filter(Boolean).map(s => s.toLowerCase())
  let i = 0
  while (i < segs.length && VERSION_SEG_RE.test(segs[i]!)) i += 1
  if (i + 1 < segs.length && TENANT_SCOPE_SEG_RE.test(segs[i]!) && PARAM_SEG_RE.test(segs[i + 1]!)) i += 2
  const root: string[] = []
  while (i < segs.length && !PARAM_SEG_RE.test(segs[i]!) && root.length < 2) {
    root.push(segs[i]!)
    i += 1
  }
  return root.length > 0 ? root.join('/') : null
}

function extractCompositeTerminalSpec<T extends UpstreamSupersessionEndpointLike>(
  receipt: RawCompositeReceiptLike | undefined,
  fallbackOrigin: string,
  overrideEndpoint?: string | null,
): T | null {
  if (!receipt || !Array.isArray(receipt.hops) || receipt.hops.length === 0) return null
  const termHopId = typeof receipt.terminalImpact?.terminalHopId === 'string'
    ? receipt.terminalImpact.terminalHopId
    : null
  const termHop = (termHopId ? receipt.hops.find(h => h?.hopId === termHopId) : undefined)
    ?? receipt.hops[receipt.hops.length - 1]
  const parsedTerm = parseCompositeEndpoint(overrideEndpoint) ?? parseCompositeEndpoint(termHop?.target?.pathAndQuery)
  if (!parsedTerm) return null
  const method = parsedTerm.method ?? normalizeCompositeMethod(termHop?.target?.method)
  const origin = (typeof termHop?.target?.origin === 'string' && termHop.target.origin.trim()) || fallbackOrigin
  if (!method || !origin) return null
  return {
    origin,
    method,
    normalizedEndpoint: normalizeEndpointTemplate(parsedTerm.endpoint),
  } as T
}

function extractCompositeNonGenericUpstreamFromReceipt<T extends UpstreamSupersessionEndpointLike>(
  receipt: RawCompositeReceiptLike | undefined,
  fallbackOrigin: string,
): T[] {
  if (!receipt || !Array.isArray(receipt.hops) || receipt.hops.length < 2) return []
  const termHopId = typeof receipt.terminalImpact?.terminalHopId === 'string'
    ? receipt.terminalImpact.terminalHopId
    : null
  const termHop = (termHopId ? receipt.hops.find(h => h?.hopId === termHopId) : undefined)
    ?? receipt.hops[receipt.hops.length - 1]
  const out: T[] = []
  for (const hop of receipt.hops) {
    if (hop === termHop) continue
    const parsed = parseCompositeEndpoint(hop?.target?.pathAndQuery)
    if (!parsed) continue
    const method = parsed.method ?? normalizeCompositeMethod(hop?.target?.method)
    const origin = (typeof hop?.target?.origin === 'string' && hop.target.origin.trim()) || fallbackOrigin
    const normalizedEndpoint = normalizeEndpointTemplate(parsed.endpoint)
    if (!method || !origin || isGenericSharedAuthOrUtilityEndpoint(normalizedEndpoint)) continue
    out.push({ origin, method, normalizedEndpoint } as T)
  }
  return out
}

/**
 * R6: Generic causal-prefix partial-chain supersession.
 * Returns matched upstream specs when `winner` strictly dominates `partial` on the exact same
 * origin: both are >=2-hop composite chains sharing >=1 non-generic upstream causal hop AND the
 * same terminal resource family root, where `winner` executes a mutating terminal action while
 * `partial` stops at either a read-only terminal action or a strictly shallower intermediate hop.
 */
export function matchCausalPrefixPartialChainSupersession<T extends UpstreamSupersessionEndpointLike>(input: {
  winnerReceipt: RawCompositeReceiptLike | undefined
  winnerOrigin: string
  winnerUpstreamNonGeneric: readonly T[]
  winnerTerminalEndpoint?: string | null
  partialReceipt: RawCompositeReceiptLike | undefined
  partialOrigin: string
  partialUpstreamNonGeneric?: readonly T[]
  partialTerminalEndpoint?: string | null
  endpointsMatchExact: (a: T, b: T) => boolean
}): T[] {
  const {
    winnerReceipt, winnerOrigin, winnerUpstreamNonGeneric, winnerTerminalEndpoint,
    partialReceipt, partialOrigin, partialUpstreamNonGeneric, partialTerminalEndpoint,
    endpointsMatchExact,
  } = input
  if (
    !winnerReceipt || !partialReceipt
    || !Array.isArray(winnerReceipt.hops) || winnerReceipt.hops.length < 2
    || !Array.isArray(partialReceipt.hops) || partialReceipt.hops.length < 2
    || !winnerUpstreamNonGeneric.length
  ) {
    return []
  }
  if (normalizeOrigin(winnerOrigin) !== normalizeOrigin(partialOrigin)) return []
  const winnerTerm = extractCompositeTerminalSpec<T>(winnerReceipt, winnerOrigin, winnerTerminalEndpoint)
  const partialTerm = extractCompositeTerminalSpec<T>(partialReceipt, partialOrigin, partialTerminalEndpoint)
  if (!winnerTerm || !partialTerm) return []
  if (
    isGenericSharedAuthOrUtilityEndpoint(winnerTerm.normalizedEndpoint)
    || isGenericSharedAuthOrUtilityEndpoint(partialTerm.normalizedEndpoint)
  ) {
    return []
  }
  if (endpointsMatchExact(winnerTerm, partialTerm)) return []

  const winnerMut = Boolean(winnerTerm.method && MUTATING_HTTP_METHODS.has(winnerTerm.method))
  if (!winnerMut) return []
  const partialReadOnly = partialTerm.method === 'GET' || partialTerm.method === 'HEAD'
  const winnerStrictlyDeeper = winnerReceipt.hops.length > partialReceipt.hops.length
  if (!partialReadOnly && !winnerStrictlyDeeper) return []

  const winnerRoot = normalizedResourceFamilyRoot(winnerTerm.normalizedEndpoint)
  const partialRoot = normalizedResourceFamilyRoot(partialTerm.normalizedEndpoint)
  if (!winnerRoot || !partialRoot || winnerRoot !== partialRoot) return []

  const partialUpstream = (partialUpstreamNonGeneric && partialUpstreamNonGeneric.length > 0)
    ? partialUpstreamNonGeneric
    : extractCompositeNonGenericUpstreamFromReceipt<T>(partialReceipt, partialOrigin)
  if (!partialUpstream.length) return []

  const shared: T[] = []
  for (const pup of partialUpstream) {
    for (const wup of winnerUpstreamNonGeneric) {
      if (endpointsMatchExact(pup, wup)) shared.push(wup)
    }
  }
  return shared
}

/**
 * R6: Resolve bidirectional causal-prefix / upstream composite supersession between a newly
 * persisted composite receipt and an existing confirmed finding row.
 */
export function resolveCompositeSupersessionMatch<T extends UpstreamSupersessionEndpointLike>(input: {
  incomingReceipt: RawCompositeReceiptLike
  incomingOrigin: string
  incomingTerminalEndpoint?: string | null
  incomingUpstreamNonGeneric: readonly T[]
  earlierCompReceipt: RawCompositeReceiptLike | undefined
  earlierOrigin: string
  earlierEndpoints: readonly T[]
  endpointsMatchExact: (a: T, b: T) => boolean
}): { direction: 'none' | 'incoming_supersedes_earlier' | 'earlier_supersedes_incoming'; matched: T[] } {
  const sub = matchSubstantialUpstreamCompositeOverlap({
    earlierCompReceipt: input.earlierCompReceipt,
    incomingHopCount: input.incomingReceipt.hops?.length ?? 0,
    earlierOrigin: input.earlierOrigin,
    earlierEndpoints: input.earlierEndpoints,
    upstreamNonGeneric: input.incomingUpstreamNonGeneric,
    endpointsMatchExact: input.endpointsMatchExact,
  })
  if (sub.length > 0) return { direction: 'incoming_supersedes_earlier', matched: sub }

  const fwd = matchCausalPrefixPartialChainSupersession({
    winnerReceipt: input.incomingReceipt,
    winnerOrigin: input.incomingOrigin,
    winnerUpstreamNonGeneric: input.incomingUpstreamNonGeneric,
    winnerTerminalEndpoint: input.incomingTerminalEndpoint,
    partialReceipt: input.earlierCompReceipt,
    partialOrigin: input.earlierOrigin,
    endpointsMatchExact: input.endpointsMatchExact,
  })
  if (fwd.length > 0) return { direction: 'incoming_supersedes_earlier', matched: fwd }

  const earlierUpstream = extractCompositeNonGenericUpstreamFromReceipt<T>(input.earlierCompReceipt, input.earlierOrigin)
  const rev = matchCausalPrefixPartialChainSupersession({
    winnerReceipt: input.earlierCompReceipt,
    winnerOrigin: input.earlierOrigin,
    winnerUpstreamNonGeneric: earlierUpstream,
    partialReceipt: input.incomingReceipt,
    partialOrigin: input.incomingOrigin,
    partialUpstreamNonGeneric: input.incomingUpstreamNonGeneric,
    partialTerminalEndpoint: input.incomingTerminalEndpoint,
    endpointsMatchExact: input.endpointsMatchExact,
  })
  if (rev.length > 0) return { direction: 'earlier_supersedes_incoming', matched: rev }

  return { direction: 'none', matched: [] }
}
