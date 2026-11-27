import { createHash } from 'node:crypto'
import { BrokerCircuitOpen, BrokerDenied } from './broker.ts'
import type { BrokerExchangeResult, Grant, RequestBroker } from './broker.ts'
import { normalizeRouteTemplate } from './route-template.ts'
import type { EndpointRow, Store } from './store.ts'

export interface SiblingVerbEndpointInput {
  origin: string
  method?: string
  /** Concrete path (e.g. `/api/items/123/action`) or templated path (e.g. `/api/items/:id/action`). */
  path: string
}

export interface SiblingVerbOriginIds {
  [collectionPath: string]: readonly string[]
}

export interface ExtractSiblingVerbOptions {
  /** Already-discovered endpoints across all approved origins. */
  endpoints: readonly SiblingVerbEndpointInput[]
  /**
   * Optional concrete paths observed during crawling/navigation/probing (per origin),
   * used to recover concrete IDs when stored endpoints were already normalized to `:id`.
   */
  observedConcretePathsByOrigin?: ReadonlyMap<string, Iterable<string>> | Readonly<Record<string, readonly string[]>>
  /**
   * Optional concrete IDs harvested from JSON collection responses, keyed by origin -> collectionPath -> ids.
   */
  idsByOrigin?: ReadonlyMap<string, ReadonlyMap<string, readonly string[]>> | Readonly<Record<string, SiblingVerbOriginIds>>
  /** Optional allowlist of approved origins; endpoints/origins outside it are ignored. */
  approvedOrigins?: readonly string[]
  /** Maximum candidates generated per origin (default 24). */
  maxCandidatesPerOrigin?: number
  /** Maximum total candidates generated across all origins (default 48). */
  maxTotalCandidates?: number
}

export interface SiblingVerbCandidate {
  origin: string
  /** API prefix preceding the resource segment (e.g. `/v1`, `/api`, or `''`). */
  prefix: string
  /** Target sibling resource segment (e.g. `widgets`). */
  resource: string
  /** Concrete harvested ID substituted into the candidate path (e.g. `456`). */
  concreteId: string
  /** Target-derived verb segment observed on another resource family (e.g. `action`). */
  verb: string
  /** Concrete request path to probe (e.g. `/api/widgets/456/action`). */
  concretePath: string
  /** Normalized route template to register if discovered (e.g. `/api/widgets/:id/action`). */
  templatePath: string
  /** Whether the verb was observed on the same origin or a sibling origin sharing `prefix`. */
  sourceScope: 'same_origin' | 'sibling_origin'
  /** HTTP methods observed on the source route(s) that contributed this verb (uppercase). */
  observedMethods: string[]
}

export interface SiblingVerbOriginState {
  requestsUsed: number
  perOriginCap: number
  halted?: boolean
  isSoftNotFound?: (ex: BrokerExchangeResult) => boolean
  persona?: string
}

export interface SiblingVerbOriginSnapshot extends SiblingVerbOriginState {
  idsByCollection: ReadonlyMap<string, readonly string[]>
  observedConcretePaths: readonly string[]
  probedKeys?: ReadonlySet<string>
}

export interface ProbeSiblingVerbParams {
  storage: Store
  runId: string
  scopeRevision: number
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  candidates: readonly SiblingVerbCandidate[]
  /** Approved candidate personas; prober strictly selects a low-privilege persona (NEVER elevated/admin). */
  personas?: readonly string[]
  originStates?: ReadonlyMap<string, SiblingVerbOriginState> | Readonly<Record<string, SiblingVerbOriginState>>
  defaultOriginBudget?: number
  maxTotalRequests?: number
  requestTimeoutMs?: number
  assignmentId?: string
  onExchange?: (ex: BrokerExchangeResult) => string | void
}

export interface DiscoveredSiblingVerbEndpoint {
  origin: string
  method: string
  pathTemplate: string
  concretePath: string
  status: number
  discoveredVia: 'options_allow' | 'options_status' | 'get_allow' | 'get_405_inferred' | 'get_status'
  endpointId: string
}

export interface ProbeSiblingVerbResult {
  candidatesConsidered: number
  candidatesProbed: number
  requestsSent: number
  endpointsDiscovered: number
  paramsDiscovered: number
  skippedOutOfScope: number
  skippedBudget: number
  soft404Rejected: number
  discovered: DiscoveredSiblingVerbEndpoint[]
}

export interface Phase0SiblingVerbPassParams {
  storage: Store
  runId: string
  scopeRevision: number
  broker: RequestBroker
  grant: Grant
  signal: AbortSignal
  approvedOrigins: readonly string[]
  personas?: readonly string[]
  originSnapshots: ReadonlyMap<string, SiblingVerbOriginSnapshot>
  requestTimeoutMs?: number
  assignmentId?: string
  onExchange?: (ex: BrokerExchangeResult) => string | void
}

const DEFAULT_MAX_CANDIDATES_PER_ORIGIN = 24
const DEFAULT_MAX_TOTAL_CANDIDATES = 48
const DEFAULT_ORIGIN_BUDGET = 48
const DEFAULT_MAX_TOTAL_REQUESTS = 96

const PARAM_TOKEN_RE = /^(?::[A-Za-z_][A-Za-z0-9_-]*|\{[^}]+\}|\[[^\]]+\]|<[^>]+>)$/
const VERB_SEGMENT_RE = /^[a-z][a-z_-]{0,30}[a-z]$/
const RESOURCE_SEGMENT_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/
const PREFIX_SEGMENT_RE = /^[A-Za-z0-9_-]{1,64}$/
const VERSION_ONLY_RE = /^v\d+$/i
const ALLOWED_RECORDED_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
const DISCOVERY_STATUSES = new Set([200, 204, 400, 401, 403, 405, 422])
const ELEVATED_PERSONA_RE = /\b(?:owner|super\s*(?:user|admin)|superuser|superadmin|root|privileged|victim|admin|administrator)\b/i
const LOW_PRIV_READONLY_RE = /\b(?:read\s*only|viewer|guest|readonly|anon|anonymous|unauthenticated|observer)\b/i
const MID_PRIV_ROLE_RE = /\b(?:manager|editor|moderator|approver|maintainer|operator)\b/i

interface ResourceFamilyRecord {
  prefix: string
  resource: string
  familyPath: string
  concreteIds: string[]
  existingVerbs: Set<string>
}

interface ParsedObservedRoute {
  kind: 'verb' | 'detail'
  prefix: string
  resource: string
  familyPath: string
  concreteId: string | null
  verb?: string
  templatePath: string
}

interface ObservedVerbState {
  knownTemplatesByOrigin: Map<string, Set<string>>
  familiesByOrigin: Map<string, Map<string, ResourceFamilyRecord>>
  verbsByOriginPrefix: Map<string, Map<string, Set<string>>>
  verbsBySharedPrefix: Map<string, Map<string, { origins: Set<string>; methods: Set<string> }>>
}

interface ProbeRuntimeContext {
  params: ProbeSiblingVerbParams
  result: ProbeSiblingVerbResult
  defaultBudget: number
  maxTotalRequests: number
  timeoutMs: number
  remainingByOrigin: Map<string, number>
  haltedOrigins: Set<string>
  producersByOrigin: Map<string, Map<string, EndpointRow>>
}

function normalizeOriginSafe(raw: string): string | null {
  try {
    return new URL(raw).origin
  } catch {
    return null
  }
}

function stripPathExtras(rawPath: string): string {
  const trimmed = rawPath.trim()
  if (!trimmed) return '/'
  let pathname = trimmed
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      pathname = new URL(trimmed).pathname || '/'
    } catch {
      pathname = trimmed
    }
  }
  const qIdx = pathname.indexOf('?')
  if (qIdx >= 0) pathname = pathname.slice(0, qIdx)
  const hIdx = pathname.indexOf('#')
  if (hIdx >= 0) pathname = pathname.slice(0, hIdx)
  if (!pathname.startsWith('/')) pathname = `/${pathname}`
  const clean = pathname.replace(/\/{2,}/g, '/').replace(/\/+$/, '')
  return clean || '/'
}

function normalizeConcreteId(rawSegment: string): string | null {
  let value = rawSegment.trim()
  if (value.includes('%')) {
    try { value = decodeURIComponent(value).trim() } catch { value = rawSegment.trim() }
  }
  if (!value || value.length > 128) return null
  if (PARAM_TOKEN_RE.test(value)) return null
  if (value === '.' || value === '..' || value.includes('..')) return null
  if (/[/\\?#\s\r\n\0]/.test(value)) return null
  return value
}

function isValidPrefix(segments: readonly string[]): boolean {
  return segments.every(seg => seg !== ':id' && !PARAM_TOKEN_RE.test(seg) && PREFIX_SEGMENT_RE.test(seg))
}

function isValidResource(segment: string): boolean {
  return segment !== ':id' && !PARAM_TOKEN_RE.test(segment) && RESOURCE_SEGMENT_RE.test(segment) && !VERSION_ONLY_RE.test(segment)
}

function canonicalTemplate(rawPath: string): string {
  return normalizeRouteTemplate(rawPath, {
    preserveCase: true,
    preserveParamNames: false,
    collapseConcreteIds: true,
  })
}

function parseObservedRoute(rawPath: string): {
  parsed: ParsedObservedRoute | null
  concretePairs: Array<{ familyPath: string; prefix: string; resource: string; concreteId: string }>
} {
  const bare = stripPathExtras(rawPath)
  const rawSegs = bare.split('/').filter(Boolean)
  const normPath = canonicalTemplate(bare)
  const normSegs = normPath.split('/').filter(Boolean)
  const concretePairs: Array<{ familyPath: string; prefix: string; resource: string; concreteId: string }> = []

  if (rawSegs.length === normSegs.length) {
    for (let i = 1; i < normSegs.length; i += 1) {
      if (normSegs[i] !== ':id') continue
      const prefixSegs = normSegs.slice(0, i - 1)
      const resourceSeg = normSegs[i - 1]!
      const concreteId = normalizeConcreteId(rawSegs[i]!)
      if (!isValidPrefix(prefixSegs) || !isValidResource(resourceSeg) || !concreteId) continue
      const prefix = prefixSegs.length > 0 ? `/${prefixSegs.join('/')}` : ''
      concretePairs.push({ familyPath: `${prefix}/${resourceSeg}`, prefix, resource: resourceSeg, concreteId })
    }
  }

  const n = normSegs.length
  if (n >= 3 && rawSegs.length === n && normSegs[n - 2] === ':id' && normSegs[n - 1] !== ':id') {
    const prefixSegs = normSegs.slice(0, n - 3)
    const resourceSeg = normSegs[n - 3]!
    const verbSeg = rawSegs[n - 1]!
    if (isValidPrefix(prefixSegs) && isValidResource(resourceSeg) && VERB_SEGMENT_RE.test(verbSeg)) {
      const prefix = prefixSegs.length > 0 ? `/${prefixSegs.join('/')}` : ''
      const familyPath = `${prefix}/${resourceSeg}`
      const concreteId = normalizeConcreteId(rawSegs[n - 2]!)
      return {
        parsed: {
          kind: 'verb',
          prefix,
          resource: resourceSeg,
          familyPath,
          concreteId,
          verb: verbSeg,
          templatePath: `${familyPath}/:id/${verbSeg}`,
        },
        concretePairs,
      }
    }
  }

  if (n >= 2 && rawSegs.length === n && normSegs[n - 1] === ':id') {
    const prefixSegs = normSegs.slice(0, n - 2)
    const resourceSeg = normSegs[n - 2]!
    if (isValidPrefix(prefixSegs) && isValidResource(resourceSeg)) {
      const prefix = prefixSegs.length > 0 ? `/${prefixSegs.join('/')}` : ''
      const familyPath = `${prefix}/${resourceSeg}`
      const concreteId = normalizeConcreteId(rawSegs[n - 1]!)
      return {
        parsed: {
          kind: 'detail',
          prefix,
          resource: resourceSeg,
          familyPath,
          concreteId,
          templatePath: `${familyPath}/:id`,
        },
        concretePairs,
      }
    }
  }

  return { parsed: null, concretePairs }
}

function ensureFamily(
  familiesByOrigin: Map<string, Map<string, ResourceFamilyRecord>>,
  origin: string,
  prefix: string,
  resource: string,
  familyPath: string,
): ResourceFamilyRecord {
  let byFamily = familiesByOrigin.get(origin)
  if (!byFamily) {
    byFamily = new Map<string, ResourceFamilyRecord>()
    familiesByOrigin.set(origin, byFamily)
  }
  let rec = byFamily.get(familyPath)
  if (!rec) {
    rec = { prefix, resource, familyPath, concreteIds: [], existingVerbs: new Set<string>() }
    byFamily.set(familyPath, rec)
  }
  return rec
}

function appendUniqueId(ids: string[], candidateId: string): void {
  if (ids.length >= 8 || ids.includes(candidateId)) return
  ids.push(candidateId)
}

function iterateEntries<V>(source: ReadonlyMap<string, V> | Readonly<Record<string, V>> | undefined): Array<[string, V]> {
  if (!source) return []
  return source instanceof Map
    ? [...source.entries()]
    : Object.entries(source as Readonly<Record<string, V>>)
}

function collectObservedVerbState(
  options: ExtractSiblingVerbOptions,
  allowedOrigins: ReadonlySet<string> | null,
): ObservedVerbState {
  const knownTemplatesByOrigin = new Map<string, Set<string>>()
  const familiesByOrigin = new Map<string, Map<string, ResourceFamilyRecord>>()
  const verbsByOriginPrefix = new Map<string, Map<string, Set<string>>>()
  const verbsBySharedPrefix = new Map<string, Map<string, { origins: Set<string>; methods: Set<string> }>>()

  for (const ep of options.endpoints) {
    const origin = normalizeOriginSafe(ep.origin)
    if (!origin || (allowedOrigins && !allowedOrigins.has(origin))) continue
    const normTemplate = canonicalTemplate(ep.path)
    let known = knownTemplatesByOrigin.get(origin)
    if (!known) {
      known = new Set<string>()
      knownTemplatesByOrigin.set(origin, known)
    }
    known.add(normTemplate)

    const { parsed, concretePairs } = parseObservedRoute(ep.path)
    for (const pair of concretePairs) {
      const fam = ensureFamily(familiesByOrigin, origin, pair.prefix, pair.resource, pair.familyPath)
      appendUniqueId(fam.concreteIds, pair.concreteId)
    }
    if (!parsed) continue
    const family = ensureFamily(familiesByOrigin, origin, parsed.prefix, parsed.resource, parsed.familyPath)
    if (parsed.concreteId) appendUniqueId(family.concreteIds, parsed.concreteId)
    if (parsed.kind !== 'verb' || !parsed.verb) continue

    family.existingVerbs.add(parsed.verb)
    const upperMethod = (ep.method ?? '').trim().toUpperCase()
    const validMethod = ALLOWED_RECORDED_METHODS.has(upperMethod) ? upperMethod : null

    const opKey = `${origin}|${parsed.prefix}`
    let localVerbs = verbsByOriginPrefix.get(opKey)
    if (!localVerbs) {
      localVerbs = new Map<string, Set<string>>()
      verbsByOriginPrefix.set(opKey, localVerbs)
    }
    let methodSet = localVerbs.get(parsed.verb)
    if (!methodSet) {
      methodSet = new Set<string>()
      localVerbs.set(parsed.verb, methodSet)
    }
    if (validMethod) methodSet.add(validMethod)

    if (parsed.prefix.length > 0) {
      let sharedVerbs = verbsBySharedPrefix.get(parsed.prefix)
      if (!sharedVerbs) {
        sharedVerbs = new Map<string, { origins: Set<string>; methods: Set<string> }>()
        verbsBySharedPrefix.set(parsed.prefix, sharedVerbs)
      }
      let sharedEntry = sharedVerbs.get(parsed.verb)
      if (!sharedEntry) {
        sharedEntry = { origins: new Set<string>(), methods: new Set<string>() }
        sharedVerbs.set(parsed.verb, sharedEntry)
      }
      sharedEntry.origins.add(origin)
      if (validMethod) sharedEntry.methods.add(validMethod)
    }
  }

  for (const [rawOrigin, paths] of iterateEntries(options.observedConcretePathsByOrigin)) {
    const origin = normalizeOriginSafe(rawOrigin)
    if (!origin || (allowedOrigins && !allowedOrigins.has(origin))) continue
    const originFamilies = familiesByOrigin.get(origin)
    if (!originFamilies) continue
    for (const rawPath of paths) {
      const { concretePairs } = parseObservedRoute(rawPath)
      for (const pair of concretePairs) {
        const existing = originFamilies.get(pair.familyPath)
        if (existing) appendUniqueId(existing.concreteIds, pair.concreteId)
      }
    }
  }

  const idsOriginEntries: Array<[string, ReadonlyMap<string, readonly string[]> | SiblingVerbOriginIds]> =
    options.idsByOrigin instanceof Map
      ? [...options.idsByOrigin.entries()]
      : options.idsByOrigin
        ? Object.entries(options.idsByOrigin)
        : []
  for (const [rawOrigin, collections] of idsOriginEntries) {
    const origin = normalizeOriginSafe(rawOrigin)
    if (!origin || (allowedOrigins && !allowedOrigins.has(origin))) continue
    for (const [rawCollectionPath, rawIds] of iterateEntries(collections)) {
      const safeIds = rawIds.map(normalizeConcreteId).filter((id): id is string => Boolean(id))
      if (safeIds.length === 0) continue
      const normCollection = canonicalTemplate(rawCollectionPath)
      const segs = normCollection.split('/').filter(Boolean)
      if (segs.length === 0) continue
      const prefixSegs = segs.slice(0, -1)
      const resourceSeg = segs[segs.length - 1]!
      if (!isValidPrefix(prefixSegs) || !isValidResource(resourceSeg)) continue
      const prefix = prefixSegs.length > 0 ? `/${prefixSegs.join('/')}` : ''
      const familyPath = `${prefix}/${resourceSeg}`
      const fam = ensureFamily(familiesByOrigin, origin, prefix, resourceSeg, familyPath)
      for (const id of safeIds) appendUniqueId(fam.concreteIds, id)
    }
  }

  return { knownTemplatesByOrigin, familiesByOrigin, verbsByOriginPrefix, verbsBySharedPrefix }
}

function buildPriorityBuckets(
  state: ObservedVerbState,
  sortedOrigins: readonly string[],
): {
  sameOriginBuckets: Map<string, SiblingVerbCandidate[]>
  siblingOriginBuckets: Map<string, SiblingVerbCandidate[]>
} {
  const sameOriginBuckets = new Map<string, SiblingVerbCandidate[]>()
  const siblingOriginBuckets = new Map<string, SiblingVerbCandidate[]>()

  for (const origin of sortedOrigins) {
    const families = [...(state.familiesByOrigin.get(origin)?.values() ?? [])].sort((a, b) =>
      a.familyPath.localeCompare(b.familyPath),
    )
    const knownTemplates = state.knownTemplatesByOrigin.get(origin) ?? new Set<string>()
    const emittedTemplates = new Set<string>()
    const sameList: SiblingVerbCandidate[] = []
    const siblingList: SiblingVerbCandidate[] = []

    for (const family of families) {
      if (family.concreteIds.length === 0) continue
      const concreteId = family.concreteIds[0]!
      const encodedId = encodeURIComponent(concreteId)

      const localVerbs = state.verbsByOriginPrefix.get(`${origin}|${family.prefix}`)
      if (localVerbs) {
        for (const verb of [...localVerbs.keys()].sort((a, b) => a.localeCompare(b))) {
          if (family.existingVerbs.has(verb) || verb.toLowerCase() === family.resource.toLowerCase()) continue
          const templatePath = `${family.familyPath}/:id/${verb}`
          if (knownTemplates.has(templatePath) || emittedTemplates.has(templatePath)) continue
          emittedTemplates.add(templatePath)
          sameList.push({
            origin,
            prefix: family.prefix,
            resource: family.resource,
            concreteId,
            verb,
            concretePath: `${family.familyPath}/${encodedId}/${verb}`,
            templatePath,
            sourceScope: 'same_origin',
            observedMethods: [...(localVerbs.get(verb) ?? [])].sort(),
          })
        }
      }

      if (family.prefix.length > 0) {
        const sharedVerbs = state.verbsBySharedPrefix.get(family.prefix)
        if (sharedVerbs) {
          for (const verb of [...sharedVerbs.keys()].sort((a, b) => a.localeCompare(b))) {
            if (family.existingVerbs.has(verb) || verb.toLowerCase() === family.resource.toLowerCase()) continue
            const sharedInfo = sharedVerbs.get(verb)!
            if (![...sharedInfo.origins].some(o => o !== origin)) continue
            const templatePath = `${family.familyPath}/:id/${verb}`
            if (knownTemplates.has(templatePath) || emittedTemplates.has(templatePath)) continue
            emittedTemplates.add(templatePath)
            siblingList.push({
              origin,
              prefix: family.prefix,
              resource: family.resource,
              concreteId,
              verb,
              concretePath: `${family.familyPath}/${encodedId}/${verb}`,
              templatePath,
              sourceScope: 'sibling_origin',
              observedMethods: [...sharedInfo.methods].sort(),
            })
          }
        }
      }
    }

    if (sameList.length > 0) sameOriginBuckets.set(origin, sameList)
    if (siblingList.length > 0) siblingOriginBuckets.set(origin, siblingList)
  }

  return { sameOriginBuckets, siblingOriginBuckets }
}

function drainRoundRobin(
  bucketsByOrigin: Map<string, SiblingVerbCandidate[]>,
  sortedOrigins: readonly string[],
  perOriginCounts: Map<string, number>,
  selected: SiblingVerbCandidate[],
  maxPerOrigin: number,
  maxTotal: number,
): void {
  const cursors = new Map<string, number>()
  let advanced = true
  while (advanced && selected.length < maxTotal) {
    advanced = false
    for (const origin of sortedOrigins) {
      if (selected.length >= maxTotal) break
      const bucket = bucketsByOrigin.get(origin)
      if (!bucket || bucket.length === 0) continue
      const used = perOriginCounts.get(origin) ?? 0
      if (used >= maxPerOrigin) continue
      const idx = cursors.get(origin) ?? 0
      if (idx >= bucket.length) continue
      selected.push(bucket[idx]!)
      cursors.set(origin, idx + 1)
      perOriginCounts.set(origin, used + 1)
      advanced = true
    }
  }
}

/**
 * Pure target-derived sibling-verb candidate extractor.
 * Derives sub-resource `<verb>` vocabulary strictly from the target's own observed
 * `<prefix>/<resource>/<id-or-param>/<verb>` routes (zero hardcoded verb wordlists) and
 * transfers those verbs to sibling `<prefix>/<siblingResource>/<concreteId>` families.
 */
export function extractSiblingVerbCandidates(options: ExtractSiblingVerbOptions): SiblingVerbCandidate[] {
  const maxPerOrigin = Math.max(0, Math.floor(options.maxCandidatesPerOrigin ?? DEFAULT_MAX_CANDIDATES_PER_ORIGIN))
  const maxTotal = Math.max(0, Math.floor(options.maxTotalCandidates ?? DEFAULT_MAX_TOTAL_CANDIDATES))
  if (maxPerOrigin === 0 || maxTotal === 0) return []

  const allowedOrigins = options.approvedOrigins
    ? new Set(options.approvedOrigins.map(normalizeOriginSafe).filter((o): o is string => Boolean(o)))
    : null

  const state = collectObservedVerbState(options, allowedOrigins)
  const sortedOrigins = [...state.familiesByOrigin.keys()].sort((a, b) => a.localeCompare(b))
  const { sameOriginBuckets, siblingOriginBuckets } = buildPriorityBuckets(state, sortedOrigins)

  const selected: SiblingVerbCandidate[] = []
  const perOriginCounts = new Map<string, number>()
  drainRoundRobin(sameOriginBuckets, sortedOrigins, perOriginCounts, selected, maxPerOrigin, maxTotal)
  drainRoundRobin(siblingOriginBuckets, sortedOrigins, perOriginCounts, selected, maxPerOrigin, maxTotal)
  return selected
}

function personaPrivilegeRank(handle: string, roleLabel?: string | null, privilege?: string | null): number {
  const norm = `${handle} ${roleLabel ?? ''} ${privilege ?? ''}`
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .toLowerCase()
  if (ELEVATED_PERSONA_RE.test(norm)) return 3
  if (LOW_PRIV_READONLY_RE.test(norm)) return 0
  return MID_PRIV_ROLE_RE.test(norm) ? 2 : 1
}

function selectLowPrivilegePersona(
  personas: readonly string[] | undefined,
  grant: Grant,
  origin: string,
  preferredPersona?: string,
): string | undefined {
  if ((grant.tier ?? 0) < 2) return undefined
  const isAllowedLowPriv = (handle: string | undefined): handle is string => {
    if (!handle) return false
    const entry = grant.personas?.get(handle)
    if (!entry || !entry.originAllowlist.includes(origin)) return false
    return personaPrivilegeRank(handle, entry.roleLabel, entry.privilege) < 3
  }
  if (isAllowedLowPriv(preferredPersona)) return preferredPersona
  const eligible = [...new Set(personas ?? [])]
    .filter(isAllowedLowPriv)
    .sort((a, b) => {
      const aEntry = grant.personas?.get(a)
      const bEntry = grant.personas?.get(b)
      const rankDiff = personaPrivilegeRank(a, aEntry?.roleLabel, aEntry?.privilege)
        - personaPrivilegeRank(b, bEntry?.roleLabel, bEntry?.privilege)
      return rankDiff !== 0 ? rankDiff : a.localeCompare(b)
    })
  return eligible[0]
}

function parseAllowHeaderMethods(respHeaders: Record<string, string> | undefined | null): string[] {
  if (!respHeaders) return []
  let raw = ''
  for (const [k, v] of Object.entries(respHeaders)) {
    if (k.toLowerCase() === 'allow') {
      raw = v
      break
    }
  }
  if (!raw) return []
  const out: string[] = []
  for (const token of raw.split(',')) {
    const m = token.trim().toUpperCase()
    if (ALLOWED_RECORDED_METHODS.has(m) && !out.includes(m)) {
      out.push(m)
      if (out.length >= 6) break
    }
  }
  return out
}

function scoreSiblingVerbRisk(method: string, pathTemplate: string): number {
  let score = 58
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') score += 14
  if (/\/:(?:[a-zA-Z0-9_]+)/.test(pathTemplate)) score += 8
  return Math.min(100, score)
}

function lookupOriginState(
  originStates: ProbeSiblingVerbParams['originStates'],
  origin: string,
): SiblingVerbOriginState | undefined {
  if (!originStates) return undefined
  if (originStates instanceof Map) return originStates.get(origin)
  return (originStates as Readonly<Record<string, SiblingVerbOriginState>>)[origin]
}

function listAllEndpointsForOrigin(storage: Store, runId: string, origin: string): EndpointRow[] {
  const rows: EndpointRow[] = []
  const pageSize = 500
  for (let offset = 0; offset < 50_000; offset += pageSize) {
    const page = storage.listEndpoints(runId, { origin, limit: pageSize, offset })
    for (const row of page) rows.push(row)
    if (page.length < pageSize) break
  }
  return rows
}

function extractPathFromProbedKey(key: string): string | null {
  const firstSpace = key.indexOf(' ')
  if (firstSpace < 0) return null
  const secondSpace = key.indexOf(' ', firstSpace + 1)
  if (secondSpace < 0) return null
  const raw = key.slice(secondSpace + 1).trim()
  return raw.startsWith('/') ? raw : null
}

function getOriginRemaining(ctx: ProbeRuntimeContext, origin: string): number {
  const cached = ctx.remainingByOrigin.get(origin)
  if (cached !== undefined) return cached
  const state = lookupOriginState(ctx.params.originStates, origin)
  if (state?.halted) ctx.haltedOrigins.add(origin)
  const remaining = state
    ? Math.max(0, state.perOriginCap - state.requestsUsed)
    : ctx.defaultBudget
  ctx.remainingByOrigin.set(origin, remaining)
  return remaining
}

function getProducerForCollection(ctx: ProbeRuntimeContext, origin: string, familyPath: string): EndpointRow | undefined {
  let map = ctx.producersByOrigin.get(origin)
  if (!map) {
    map = new Map<string, EndpointRow>()
    for (const ep of listAllEndpointsForOrigin(ctx.params.storage, ctx.params.runId, origin)) {
      const clean = stripPathExtras(ep.pathTemplate)
      if (/[:{}[\]]/.test(clean)) continue
      const existing = map.get(clean)
      if (!existing || (existing.method !== 'POST' && ep.method === 'POST')) {
        map.set(clean, ep)
      }
    }
    ctx.producersByOrigin.set(origin, map)
  }
  return map.get(familyPath)
}

async function sendReadOnlyProbe(
  ctx: ProbeRuntimeContext,
  origin: string,
  method: 'OPTIONS' | 'GET',
  pathAndQuery: string,
  persona: string | undefined,
): Promise<{ exchange: BrokerExchangeResult | null; fatal: 'none' | 'circuit' | 'denied' | 'aborted' }> {
  const remaining = getOriginRemaining(ctx, origin)
  if (remaining <= 0 || ctx.result.requestsSent >= ctx.maxTotalRequests) {
    return { exchange: null, fatal: 'none' }
  }
  ctx.remainingByOrigin.set(origin, remaining - 1)
  ctx.result.requestsSent += 1
  try {
    const ex = await ctx.params.broker.executeHttp({
      origin,
      method,
      pathAndQuery,
      ...(persona ? { persona } : {}),
      followRedirects: false,
      timeoutMs: ctx.timeoutMs,
      runId: ctx.params.runId,
      assignmentId: ctx.params.assignmentId,
    }, ctx.params.grant, ctx.params.signal)
    ctx.params.onExchange?.(ex)
    return { exchange: ex, fatal: 'none' }
  } catch (err) {
    if (err instanceof BrokerCircuitOpen) {
      ctx.haltedOrigins.add(origin)
      return { exchange: null, fatal: 'circuit' }
    }
    if (err instanceof BrokerDenied) return { exchange: null, fatal: 'denied' }
    if (ctx.params.signal.aborted) return { exchange: null, fatal: 'aborted' }
    return { exchange: null, fatal: 'none' }
  }
}

function registerSiblingVerbMethods(
  ctx: ProbeRuntimeContext,
  candidate: SiblingVerbCandidate,
  methods: readonly string[],
  status: number,
  discoveredVia: DiscoveredSiblingVerbEndpoint['discoveredVia'],
  persona: string | undefined,
): void {
  const { storage, runId, scopeRevision } = ctx.params
  const familyPath = `${candidate.prefix}/${candidate.resource}`
  const producer = getProducerForCollection(ctx, candidate.origin, familyPath)

  for (const method of methods) {
    const upper = method.toUpperCase()
    if (!ALLOWED_RECORDED_METHODS.has(upper)) continue
    const ep = storage.upsertEndpoint({
      runId,
      scopeRevision,
      origin: candidate.origin,
      method: upper,
      pathTemplate: candidate.templatePath,
      source: 'surface_probe',
      authRequirement: persona ? `persona:${persona}` : null,
      riskScore: scoreSiblingVerbRisk(upper, candidate.templatePath),
    })
    storage.upsertEndpointParam({
      runId,
      endpointId: ep.id,
      name: 'id',
      location: 'path',
      isObjectId: true,
      isCsrf: false,
      source: 'phase0_sibling_verb',
    })
    ctx.result.endpointsDiscovered += 1
    ctx.result.paramsDiscovered += 1
    ctx.result.discovered.push({
      origin: candidate.origin,
      method: upper,
      pathTemplate: candidate.templatePath,
      concretePath: candidate.concretePath,
      status,
      discoveredVia,
      endpointId: ep.id,
    })
    if (producer && producer.id !== ep.id) {
      const sampleHash = `sha256:${createHash('sha256').update(`${candidate.origin}:${familyPath}:id:${candidate.verb}`).digest('hex').slice(0, 16)}`
      storage.recordApiDependency({
        runId,
        producerEndpointId: producer.id,
        consumerEndpointId: ep.id,
        resourceKey: 'id',
        sampleResourceIdHash: sampleHash,
        personaHandle: persona ?? null,
      })
    }
  }
}

async function probeSingleCandidate(
  ctx: ProbeRuntimeContext,
  candidate: SiblingVerbCandidate,
  normOrigin: string,
  originState: SiblingVerbOriginState | undefined,
  persona: string | undefined,
): Promise<'continue' | 'break'> {
  const optRes = await sendReadOnlyProbe(ctx, normOrigin, 'OPTIONS', candidate.concretePath, persona)
  if (optRes.fatal === 'aborted') return 'break'
  if (optRes.fatal === 'denied') {
    ctx.result.skippedOutOfScope += 1
    return 'continue'
  }
  if (optRes.fatal === 'circuit' || !optRes.exchange) return 'continue'

  ctx.result.candidatesProbed += 1
  const optEx = optRes.exchange
  const optAllow = parseAllowHeaderMethods(optEx.respHeaders)
  const optSoft404 = optEx.status >= 200
    && optEx.status < 300
    && optEx.body.length > 0
    && Boolean(originState?.isSoftNotFound?.(optEx))

  if (optAllow.length > 0 && optEx.status !== 404 && optEx.status !== 410 && optEx.status < 500 && !optSoft404) {
    registerSiblingVerbMethods(ctx, candidate, optAllow, optEx.status, 'options_allow', persona)
    return 'continue'
  }
  if (optEx.status === 400 || optEx.status === 401 || optEx.status === 403 || optEx.status === 422) {
    registerSiblingVerbMethods(ctx, candidate, ['GET'], optEx.status, 'options_status', persona)
    return 'continue'
  }
  const shouldFallbackGet = optEx.status === 404
    || optEx.status === 405
    || optEx.status === 501
    || optEx.status === 200
    || optEx.status === 204
  if (!shouldFallbackGet) return 'continue'
  if (getOriginRemaining(ctx, normOrigin) <= 0 || ctx.result.requestsSent >= ctx.maxTotalRequests || ctx.params.signal.aborted) {
    return 'continue'
  }

  const getRes = await sendReadOnlyProbe(ctx, normOrigin, 'GET', candidate.concretePath, persona)
  if (getRes.fatal === 'aborted') return 'break'
  if (getRes.fatal === 'denied') {
    ctx.result.skippedOutOfScope += 1
    return 'continue'
  }
  if (getRes.fatal === 'circuit' || !getRes.exchange) return 'continue'

  const getEx = getRes.exchange
  if (originState?.isSoftNotFound?.(getEx)) {
    ctx.result.soft404Rejected += 1
    return 'continue'
  }
  if (!DISCOVERY_STATUSES.has(getEx.status)) return 'continue'

  const getAllow = parseAllowHeaderMethods(getEx.respHeaders)
  if (getEx.status === 405) {
    if (getAllow.length > 0) {
      registerSiblingVerbMethods(ctx, candidate, getAllow, getEx.status, 'get_allow', persona)
    } else {
      const writeMethods = candidate.observedMethods.filter(m => m !== 'GET' && ALLOWED_RECORDED_METHODS.has(m))
      registerSiblingVerbMethods(
        ctx,
        candidate,
        writeMethods.length > 0 ? writeMethods : ['POST'],
        getEx.status,
        'get_405_inferred',
        persona,
      )
    }
    return 'continue'
  }
  if (getAllow.length > 0) {
    registerSiblingVerbMethods(ctx, candidate, [...new Set(['GET', ...getAllow])], getEx.status, 'get_allow', persona)
  } else {
    registerSiblingVerbMethods(ctx, candidate, ['GET'], getEx.status, 'get_status', persona)
  }
  return 'continue'
}

/**
 * Safely probes target-derived sibling-verb candidates using strictly read-only methods
 * (`OPTIONS`, with a single `GET` fallback when `OPTIONS` returns `404`/`405`/`501` or an
 * Allow-less `200`/`204`). Never sends mutating HTTP verbs (`POST`/`PATCH`/`PUT`/`DELETE`).
 */
export async function probeSiblingVerbCandidates(params: ProbeSiblingVerbParams): Promise<ProbeSiblingVerbResult> {
  const defaultBudget = Math.max(0, Math.floor(params.defaultOriginBudget ?? DEFAULT_ORIGIN_BUDGET))
  const maxTotalRequests = Math.max(0, Math.floor(params.maxTotalRequests ?? DEFAULT_MAX_TOTAL_REQUESTS))
  const timeoutMs = Math.max(250, Math.min(Math.floor(params.requestTimeoutMs ?? 6_000), 10_000))

  const result: ProbeSiblingVerbResult = {
    candidatesConsidered: params.candidates.length,
    candidatesProbed: 0,
    requestsSent: 0,
    endpointsDiscovered: 0,
    paramsDiscovered: 0,
    skippedOutOfScope: 0,
    skippedBudget: 0,
    soft404Rejected: 0,
    discovered: [],
  }
  if (params.candidates.length === 0 || maxTotalRequests === 0) return result

  const ctx: ProbeRuntimeContext = {
    params,
    result,
    defaultBudget,
    maxTotalRequests,
    timeoutMs,
    remainingByOrigin: new Map<string, number>(),
    haltedOrigins: new Set<string>(),
    producersByOrigin: new Map<string, Map<string, EndpointRow>>(),
  }

  for (const candidate of params.candidates) {
    if (params.signal.aborted) break
    const normOrigin = normalizeOriginSafe(candidate.origin)
    if (!normOrigin || !params.grant.canRead(normOrigin)) {
      result.skippedOutOfScope += 1
      continue
    }
    const remaining = getOriginRemaining(ctx, normOrigin)
    if (ctx.haltedOrigins.has(normOrigin) || remaining <= 0 || result.requestsSent >= maxTotalRequests) {
      result.skippedBudget += 1
      continue
    }
    const originState = lookupOriginState(params.originStates, normOrigin)
    const persona = selectLowPrivilegePersona(params.personas, params.grant, normOrigin, originState?.persona)
    const flow = await probeSingleCandidate(ctx, candidate, normOrigin, originState, persona)
    if (flow === 'break') break
  }

  if (result.candidatesProbed > 0 || result.endpointsDiscovered > 0) {
    params.storage.event(
      params.runId,
      'phase0.sibling_verbs',
      `Sibling-verb transfer probed ${result.candidatesProbed}/${result.candidatesConsidered} candidate(s) (${result.requestsSent} read-only req(s)) and registered ${result.endpointsDiscovered} endpoint(s).`,
      {
        candidatesConsidered: result.candidatesConsidered,
        candidatesProbed: result.candidatesProbed,
        requestsSent: result.requestsSent,
        endpointsDiscovered: result.endpointsDiscovered,
        paramsDiscovered: result.paramsDiscovered,
        skippedOutOfScope: result.skippedOutOfScope,
        skippedBudget: result.skippedBudget,
        soft404Rejected: result.soft404Rejected,
      },
    )
  }

  return result
}

/**
 * Phase-0 post-discovery pass: collects discovered endpoints and harvested IDs across all
 * approved live origins, generates bounded sibling-verb candidates, and runs safe read-only probing.
 */
export async function runPhase0SiblingVerbPass(params: Phase0SiblingVerbPassParams): Promise<ProbeSiblingVerbResult> {
  const endpoints: SiblingVerbEndpointInput[] = []
  const idsByOrigin = new Map<string, ReadonlyMap<string, readonly string[]>>()
  const observedConcretePathsByOrigin = new Map<string, string[]>()
  const activeOrigins: string[] = []

  for (const rawOrigin of params.approvedOrigins) {
    const origin = normalizeOriginSafe(rawOrigin)
    if (!origin) continue
    const snapshot = params.originSnapshots.get(origin)
    if (!snapshot || snapshot.halted || !params.grant.canRead(origin)) continue
    activeOrigins.push(origin)
    idsByOrigin.set(origin, snapshot.idsByCollection)
    const concretePaths = [...snapshot.observedConcretePaths]
    if (snapshot.probedKeys) {
      for (const key of snapshot.probedKeys) {
        const extracted = extractPathFromProbedKey(key)
        if (extracted) concretePaths.push(extracted)
      }
    }
    observedConcretePathsByOrigin.set(origin, concretePaths)
    for (const row of listAllEndpointsForOrigin(params.storage, params.runId, origin)) {
      endpoints.push({ origin, method: row.method, path: row.pathTemplate })
    }
  }

  const candidates = extractSiblingVerbCandidates({
    endpoints,
    idsByOrigin,
    observedConcretePathsByOrigin,
    approvedOrigins: activeOrigins,
  })
  if (candidates.length === 0) {
    return {
      candidatesConsidered: 0,
      candidatesProbed: 0,
      requestsSent: 0,
      endpointsDiscovered: 0,
      paramsDiscovered: 0,
      skippedOutOfScope: 0,
      skippedBudget: 0,
      soft404Rejected: 0,
      discovered: [],
    }
  }

  return probeSiblingVerbCandidates({
    storage: params.storage,
    runId: params.runId,
    scopeRevision: params.scopeRevision,
    broker: params.broker,
    grant: params.grant,
    signal: params.signal,
    candidates,
    personas: params.personas,
    originStates: params.originSnapshots,
    requestTimeoutMs: params.requestTimeoutMs,
    assignmentId: params.assignmentId,
    onExchange: params.onExchange,
  })
}
