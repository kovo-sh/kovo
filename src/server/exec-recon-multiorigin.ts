import type { ThreatModelSummary } from '../domain.ts'
import type { HostTier } from './agent-session.ts'
import { materializeGreyBoxDataflowWave1Steps, synthesizeGreyBoxDataflowStepsFromStore } from './gb-dataflow-synthesizer.ts'
import type { ChainStep, Run, Store } from './store.ts'

export { materializeGreyBoxDataflowWave1Steps }

export interface Wave1OriginFallbackEndpoint {
  origin: string
  pathTemplate: string
  riskScore?: number
  source?: string
}

export interface Wave1OriginFallbackInput {
  hypEntity: string
  candidateRouteRefs: readonly string[]
  approvedList: readonly string[]
  activeOrigins: ReadonlySet<string>
  storedEndpoints: readonly Wave1OriginFallbackEndpoint[]
  staticOnlySources: ReadonlySet<string>
  /** True only when a white-box hypothesis comes from an explicitly unmapped repo in a multi-repo mount. */
  explicitlyUnmappedMountedRepo: boolean
  normalizeRoute: (raw: string) => string | null
  classifyTier: (origin: string) => HostTier
}

export interface Wave1OriginFallbackResult {
  origins: string[]
  unmapped: boolean
}

export interface BalancedRepoCandidate {
  full: string
  relPath: string
  depth: number
}

export interface Wave1SeededStepDraft {
  title: string
  hypothesis: string
  category: string
  priority: number
  origins: string[]
  skills: string[]
}

export interface Wave1UncoveredFallbackInput {
  reachableFinalEntries: readonly ThreatModelSummary[]
  seededSteps: readonly Wave1SeededStepDraft[]
  existingSteps: readonly Pick<ChainStep, 'status' | 'sourceOrigins'>[]
  discoveredEndpointOrigins: ReadonlySet<string>
  finalHostTiers: Record<string, HostTier>
  sourceMounted: boolean
  codeAuditStepsCreated: number
  capabilityTier: number
  whiteBoxCapPriority: number
  classifyTier: (origin: string, tags?: readonly string[]) => HostTier
  storage?: Store
  run?: Run
  activeOrigins?: ReadonlySet<string>
}

export interface Wave1UncoveredFallbackResult {
  seededSteps: Wave1SeededStepDraft[]
  uncoveredAddedCount: number
}

const GENERIC_ROUTE_PREFIX_SEGMENTS = new Set([
  'api', 'v1', 'v2', 'v3', 'v4', 'rest', 'public', 'internal', 'service', 'services', 'app',
])

const GENERIC_ENTITY_TOKENS = new Set([
  'service', 'boundary', 'item', 'resource', 'entity', 'endpoint', 'api', 'app', 'data', 'object', 'record', 'default',
])

const HOST_TIER_RANK: Record<HostTier, number> = {
  crown_jewel: 0,
  standard: 1,
  low_value_static: 2,
}

const PRIORITY_RUNTIME_DIRS = new Set([
  'src', 'server', 'api', 'routes', 'route', 'handlers', 'handler', 'services', 'service',
  'controllers', 'controller', 'app', 'apps', 'backend', 'cmd', 'internal', 'pkg',
  'middleware', 'middlewares', 'endpoints', 'graphql', 'resolvers', 'workers', 'gateway',
  'packages', 'modules', 'core', 'lib',
])

const DEPRIORITIZED_REPO_DIRS = new Set([
  'docs', 'doc', 'test', 'tests', '__tests__', '__mocks__', 'spec', 'specs',
  'fixtures', 'fixture', '__fixtures__', 'migrations', 'migration', 'seeds', 'seed',
  'examples', 'example', 'samples', 'sample', 'benchmarks', 'benchmark',
  'e2e', 'cypress', 'playwright', 'storybook', '.storybook',
  'scripts', 'tools', 'infra', 'k8s', 'helm', 'terraform', 'deploy', 'charts',
  'assets', 'static', 'public', 'locales', 'i18n',
])

const SERVICE_CONTAINER_DIRS = new Set([
  'services', 'apps', 'packages', 'modules', 'microservices', 'backends', 'workers', 'cmd', 'internal', 'pkg', 'src',
])

const TEST_OR_FIXTURE_FILE_RE = /(?:^|\/)(?:test_[^/]+|[^/]+\.(?:test|spec|mock|fixture)\.[^./]+|[^/]+_test\.go)$/i
const RUNTIME_ENTRYPOINT_SEGMENT_RE = /(?:^|\/)(?:routes?|handlers?|controllers?|middlewares?|auth|server|index|app|main|graphql|resolvers?)(?:\.|\/|$)/i
const PARAM_SEGMENT_RE = /^(?::[^/]+|\{[^}]+\}|\[[^\]]+\]|<[^>]+>|\*|\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i

function extractNormalizedSegments(raw: string, normalizeRoute: (r: string) => string | null): string[] {
  const norm = normalizeRoute(raw)
  const cleaned = norm ?? (raw.trim().replace(/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s+/i, '').split(/[?#]/, 1)[0] ?? '')
  if (!cleaned.startsWith('/')) return []
  return cleaned
    .split('/')
    .map(s => s.trim().toLowerCase())
    .filter(Boolean)
    .map(s => (PARAM_SEGMENT_RE.test(s) ? ':param' : s))
}

function stripLeadingGenericSegments(segs: readonly string[]): string[] {
  let idx = 0
  while (idx < segs.length && GENERIC_ROUTE_PREFIX_SEGMENTS.has(segs[idx]!)) idx += 1
  return segs.slice(idx)
}

function scoreSegmentPrefixMatch(cand: readonly string[], ep: readonly string[]): number {
  if (!cand.length || !ep.length) return 0
  const maxLen = Math.min(cand.length, ep.length)
  let lcp = 0
  let distinctive = 0
  while (lcp < maxLen && cand[lcp] === ep[lcp]) {
    const seg = cand[lcp]!
    if (seg !== ':param' && !GENERIC_ROUTE_PREFIX_SEGMENTS.has(seg)) distinctive += 1
    lcp += 1
  }
  let score = 0
  if (lcp > 0 && (distinctive > 0 || (lcp === cand.length && lcp === ep.length))) {
    score = lcp === cand.length && lcp === ep.length ? lcp * 4 : distinctive * 3 + lcp
  }
  const candTail = stripLeadingGenericSegments(cand)
  const epTail = stripLeadingGenericSegments(ep)
  if (candTail.length && epTail.length) {
    const tailMax = Math.min(candTail.length, epTail.length)
    let tailLcp = 0
    let tailDistinctive = 0
    while (tailLcp < tailMax && candTail[tailLcp] === epTail[tailLcp]) {
      const seg = candTail[tailLcp]!
      if (seg !== ':param' && !GENERIC_ROUTE_PREFIX_SEGMENTS.has(seg)) tailDistinctive += 1
      tailLcp += 1
    }
    if (tailDistinctive > 0) {
      score = Math.max(score, tailDistinctive * 2 + (tailLcp === candTail.length ? 1 : 0))
    }
  }
  return score
}

/**
 * Fallback origin resolution for Wave-1 invariant hypotheses when explicit `serviceOrigin`,
 * repo-origin affinity, exact host mention, and exact live-route overlap did not resolve an origin.
 *
 * 1. Fuzzy path-prefix matching across all discovered endpoints on `approvedList`.
 * 2. If still ambiguous on multi-origin runs, preserves Grey-Box / single-monorepo hypotheses by
 *    attaching them to the highest-risk approved active origin plus sibling active origins (so
 *    `publicOrigins` covers all approved origins), while keeping explicitly unmapped repos in
 *    multi-repo mounts skipped.
 */
export function resolveWave1MultiOriginFallback(input: Wave1OriginFallbackInput): Wave1OriginFallbackResult {
  const { approvedList, activeOrigins, storedEndpoints, staticOnlySources, normalizeRoute, classifyTier } = input
  if (!approvedList.length) return { origins: [], unmapped: true }
  if (approvedList.length === 1) return { origins: [approvedList[0]!], unmapped: false }

  const approvedSet = new Set(approvedList)
  const liveEndpoints = storedEndpoints.filter(
    ep => approvedSet.has(ep.origin) && !(ep.source && staticOnlySources.has(ep.source.toLowerCase())),
  )
  const endpointsForMatch = liveEndpoints.length > 0
    ? liveEndpoints
    : storedEndpoints.filter(ep => approvedSet.has(ep.origin))

  const statsByOrigin = new Map<string, { epCount: number; maxRisk: number; tierRank: number }>()
  for (const origin of approvedList) {
    statsByOrigin.set(origin, { epCount: 0, maxRisk: 0, tierRank: HOST_TIER_RANK[classifyTier(origin)] })
  }
  for (const ep of endpointsForMatch) {
    const st = statsByOrigin.get(ep.origin)
    if (!st) continue
    st.epCount += 1
    if (typeof ep.riskScore === 'number' && ep.riskScore > st.maxRisk) st.maxRisk = ep.riskScore
  }

  const compareOriginsByRisk = (a: string, b: string): number => {
    const activeDiff = Number(activeOrigins.has(b)) - Number(activeOrigins.has(a))
    if (activeDiff !== 0) return activeDiff
    const stA = statsByOrigin.get(a)!
    const stB = statsByOrigin.get(b)!
    return (
      Number(stB.epCount > 0) - Number(stA.epCount > 0)
      || stB.maxRisk - stA.maxRisk
      || stB.epCount - stA.epCount
      || stA.tierRank - stB.tierRank
      || a.localeCompare(b)
    )
  }

  const parsedEndpoints = endpointsForMatch
    .map(ep => ({ origin: ep.origin, segs: extractNormalizedSegments(ep.pathTemplate, normalizeRoute) }))
    .filter(ep => ep.segs.length > 0)

  const originScores = new Map<string, number>()
  for (const ref of input.candidateRouteRefs) {
    const candSegs = extractNormalizedSegments(ref, normalizeRoute)
    if (!candSegs.length) continue
    const bestPerOrigin = new Map<string, number>()
    for (const ep of parsedEndpoints) {
      const s = scoreSegmentPrefixMatch(candSegs, ep.segs)
      if (s > (bestPerOrigin.get(ep.origin) ?? 0)) bestPerOrigin.set(ep.origin, s)
    }
    for (const [origin, score] of bestPerOrigin.entries()) {
      originScores.set(origin, (originScores.get(origin) ?? 0) + score)
    }
  }

  if (originScores.size === 0 && parsedEndpoints.length > 0) {
    const entityToken = input.hypEntity.toLowerCase().replace(/[^a-z0-9]/g, '')
    if (entityToken.length >= 3 && !GENERIC_ENTITY_TOKENS.has(entityToken)) {
      const matchedOrigins = new Set<string>()
      for (const ep of parsedEndpoints) {
        if (ep.segs.some(seg => seg !== ':param' && (seg === entityToken || seg.includes(entityToken)))) {
          matchedOrigins.add(ep.origin)
        }
      }
      if (matchedOrigins.size > 0 && matchedOrigins.size < approvedList.length) {
        for (const origin of matchedOrigins) originScores.set(origin, 2)
      }
    }
  }

  if (originScores.size > 0) {
    const ranked = [...originScores.entries()].sort((a, b) => b[1] - a[1] || compareOriginsByRisk(a[0], b[0]))
    const topScore = ranked[0]![1]
    const topOrigins = ranked.filter(([, score]) => score === topScore).map(([origin]) => origin)
    return { origins: topOrigins, unmapped: false }
  }

  if (input.explicitlyUnmappedMountedRepo) {
    return { origins: [], unmapped: true }
  }

  const activeRanked = approvedList.filter(o => activeOrigins.has(o)).sort(compareOriginsByRisk)
  if (!activeRanked.length) return { origins: [...approvedList], unmapped: false }
  return { origins: activeRanked, unmapped: false }
}

/** Classify a directory name into BFS traversal priority: 0=runtime, 1=normal, 2=deprioritized. */
export function classifyRepoDirTier(dirName: string, parentTier: 0 | 1 | 2): 0 | 1 | 2 {
  const lower = dirName.toLowerCase()
  if (parentTier === 2 || DEPRIORITIZED_REPO_DIRS.has(lower)) return 2
  if (PRIORITY_RUNTIME_DIRS.has(lower)) return 0
  return parentTier === 0 ? 0 : 1
}

function classifySourceFileTier(relPath: string): 0 | 1 | 2 {
  const lower = relPath.toLowerCase()
  const segs = lower.split('/').filter(Boolean)
  const dirSegs = segs.slice(0, -1)
  if (dirSegs.some(seg => DEPRIORITIZED_REPO_DIRS.has(seg)) || TEST_OR_FIXTURE_FILE_RE.test(lower)) return 2
  if (dirSegs.some(seg => PRIORITY_RUNTIME_DIRS.has(seg)) || RUNTIME_ENTRYPOINT_SEGMENT_RE.test(lower)) return 0
  return 1
}

function deriveServiceBranchKey(relPath: string): string {
  const segs = relPath.split('/').filter(Boolean)
  if (segs.length <= 1) return '.'
  if (SERVICE_CONTAINER_DIRS.has(segs[0]!.toLowerCase()) && segs.length >= 3) {
    return `${segs[0]!}/${segs[1]!}`
  }
  return segs[0]!
}

/**
 * Select up to `cap` repo source files using priority tiers (runtime source -> normal source ->
 * docs/tests/fixtures/migrations) and round-robin across sibling service/subtree branches so no
 * early directory starves later services in a multi-service repository.
 */
export function selectBalancedRepoSourceCandidates<T extends BalancedRepoCandidate>(
  candidates: readonly T[],
  cap: number,
): T[] {
  if (cap <= 0 || !candidates.length) return []
  const byTier: Array<Map<string, T[]>> = [new Map(), new Map(), new Map()]
  for (const cand of candidates) {
    const tier = classifySourceFileTier(cand.relPath)
    const branch = deriveServiceBranchKey(cand.relPath)
    const map = byTier[tier]!
    let bucket = map.get(branch)
    if (!bucket) {
      bucket = []
      map.set(branch, bucket)
    }
    bucket.push(cand)
  }

  const selected: T[] = []
  for (const tierMap of byTier) {
    if (selected.length >= cap) break
    const branches = [...tierMap.keys()].sort((a, b) => a.localeCompare(b))
    const queues = branches.map(branch => {
      const list = tierMap.get(branch)!
      list.sort((a, b) =>
        a.depth - b.depth
        || Number(RUNTIME_ENTRYPOINT_SEGMENT_RE.test(b.relPath)) - Number(RUNTIME_ENTRYPOINT_SEGMENT_RE.test(a.relPath))
        || a.relPath.localeCompare(b.relPath),
      )
      return { list, cursor: 0 }
    })
    let progressed = true
    while (selected.length < cap && progressed) {
      progressed = false
      for (const q of queues) {
        if (selected.length >= cap) break
        if (q.cursor < q.list.length) {
          selected.push(q.list[q.cursor++]!)
          progressed = true
        }
      }
    }
  }
  return selected
}

function parseOriginHostLabel(origin: string): string {
  if (URL.canParse(origin)) return new URL(origin).host
  return origin.replace(/^https?:\/\//i, '').replace(/\/.*$/, '') || origin
}

/**
 * Guarantee every reachable approved origin with discovered endpoints receives Wave-1 coverage
 * even when `codeAuditStepsCreated > 0` or the LLM threat model only seeded steps for a subset
 * of origins. Non-static fallback steps include sibling reachable origins for cross-origin chains.
 */
export function buildWave1UncoveredOriginFallbackSteps(
  input: Wave1UncoveredFallbackInput,
): Wave1UncoveredFallbackResult {
  const {
    reachableFinalEntries,
    seededSteps,
    existingSteps,
    discoveredEndpointOrigins,
    finalHostTiers,
    sourceMounted,
    codeAuditStepsCreated,
    capabilityTier,
    whiteBoxCapPriority,
    classifyTier,
  } = input
  if (capabilityTier <= 0 || !reachableFinalEntries.length) {
    return { seededSteps: [...seededSteps], uncoveredAddedCount: 0 }
  }

  const reachableOriginSet = new Set(reachableFinalEntries.map(e => e.origin))
  const nonStaticReachableOrigins = reachableFinalEntries
    .filter(e => (finalHostTiers[e.origin] ?? classifyTier(e.origin, e.surfaceTags)) !== 'low_value_static')
    .map(e => e.origin)

  let gbDataflowSteps: Wave1SeededStepDraft[] = []
  if (!sourceMounted && input.storage && input.run) {
    const existingSeedTitles = new Set(seededSteps.map(s => s.title.trim().toLowerCase()))
    gbDataflowSteps = synthesizeGreyBoxDataflowStepsFromStore(input.storage, input.run, {
      activeOrigins: input.activeOrigins ?? reachableOriginSet,
      sourceMounted,
      maxSteps: 6,
    }).filter(s => !existingSeedTitles.has(s.title.trim().toLowerCase()))
  }
  const combinedSeededSteps: Wave1SeededStepDraft[] = [...gbDataflowSteps, ...seededSteps]

  const makeFallbackStep = (entry: ThreatModelSummary, idx: number): Wave1SeededStepDraft => {
    const tier = finalHostTiers[entry.origin] ?? classifyTier(entry.origin, entry.surfaceTags)
    const basePriority = tier === 'low_value_static' ? 30 : Math.max(55, 95 - idx * 6)
    const stepOrigins = tier === 'low_value_static'
      ? [entry.origin]
      : [entry.origin, ...nonStaticReachableOrigins.filter(o => o !== entry.origin)]
    const hostLabel = parseOriginHostLabel(entry.origin)
    const siblingNote = stepOrigins.length > 1
      ? ` Cross-origin siblings in scope: ${stepOrigins.slice(1).join(', ')}.`
      : ''
    return {
      title: `Surface & chain investigation · ${hostLabel}`,
      hypothesis: `Harvest JS/API routes, inspect DNS/TLS/CORS/auth headers, fingerprint stack & CVEs, and verify any candidate vulnerabilities on ${entry.origin} (${entry.surfaceTags.join(', ')}).${siblingNote}`,
      category: entry.surfaceTags.includes('auth') ? 'auth-identity'
        : entry.surfaceTags.includes('api') ? 'broken-access-control'
          : entry.surfaceTags.includes('upload') ? 'upload-storage'
            : entry.surfaceTags.includes('llm-proxy') ? 'llm-ai-security'
              : 'misconfig-exposure',
      priority: sourceMounted ? Math.min(basePriority, whiteBoxCapPriority - 5) : basePriority,
      origins: stepOrigins,
      skills: ['recon-modern-spa', 'cve-runtime-correlation', 'false-positive-elimination'],
    }
  }

  const coveredPrimaryOrigins = new Set<string>()
  for (const step of existingSteps) {
    if (step.status === 'canceled' || step.status === 'tainted') continue
    const primary = step.sourceOrigins[0]
    if (primary && reachableOriginSet.has(primary)) coveredPrimaryOrigins.add(primary)
  }
  for (const step of combinedSeededSteps) {
    const primary = step.origins.find(o => reachableOriginSet.has(o))
    if (primary) coveredPrimaryOrigins.add(primary)
  }

  if (!combinedSeededSteps.length && (!sourceMounted || codeAuditStepsCreated === 0)) {
    const topHosts = reachableFinalEntries.slice(0, Math.min(8, reachableFinalEntries.length))
    const built = topHosts.map((entry, idx) => makeFallbackStep(entry, idx))
    const uncoveredCount = topHosts.filter(e => discoveredEndpointOrigins.has(e.origin) && !coveredPrimaryOrigins.has(e.origin)).length
    return { seededSteps: built, uncoveredAddedCount: uncoveredCount }
  }

  const uncoveredEntries = reachableFinalEntries
    .filter(entry => discoveredEndpointOrigins.has(entry.origin) && !coveredPrimaryOrigins.has(entry.origin))
    .slice(0, 8)
  if (!uncoveredEntries.length) {
    return { seededSteps: combinedSeededSteps, uncoveredAddedCount: gbDataflowSteps.length }
  }
  const appended = uncoveredEntries.map((entry, idx) => makeFallbackStep(entry, idx))
  return {
    seededSteps: [...combinedSeededSteps, ...appended],
    uncoveredAddedCount: gbDataflowSteps.length + appended.length,
  }
}
