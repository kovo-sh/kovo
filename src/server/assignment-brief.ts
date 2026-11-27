/**
 * Assignment evidence brief (v5.1 agentic throughput).
 *
 * The agentic layer is throughput-starved: a specialist that spends its first turns rediscovering
 * routes/personas/baselines cannot spend them probing. This module renders a deliberately tiny,
 * deterministic packet (<= 1.5 KB; <= 4 KB when the caller expands a code slice) from data the
 * session already has, so turn 1 can probe.
 *
 * v7 M1 adds an optional white-box `code` slice: mounts, input schema, auth chain and a 4–8 hop
 * sink path with exact file:line. The slice is built by `buildCodeDataflowSlice` (program graph)
 * and always re-fitted here to {@link ASSIGNMENT_BRIEF_CODE_MAX_BYTES}; `codeExpansion: 'full'`
 * raises the slice and brief budgets for a coordinator-requested expansion.
 *
 * Invariants:
 *  - Pure: no I/O, no clock, no randomness.
 *  - Deterministic ordering: highest-signal material first, stable tie-breakers.
 *  - Hard byte cap: the returned text is always valid JSON and never exceeds
 *    {@link ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE} (4 KB); reduction is a fixed ladder, not a
 *    blind slice.
 *  - No secrets or response bodies: only names, status codes, top-level keys, and short scalar
 *    state/numeric samples. Secret-shaped keys/values and body-like fields are dropped.
 */

import { buildRecordCoverageBriefGuidance } from './coverage-category.ts'
import { renderCodeDataflowSlice, type CodeDataflowSlice } from './program-graph.ts'
import { redact } from './redact.ts'

export const ASSIGNMENT_BRIEF_MAX_BYTES = 1536
/** Hard ceiling for any brief (compact or expanded with a code slice / hop checkpoint). */
export const ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE = 4096
/** Default budget for the rendered dataflow slice inside a brief. */
export const ASSIGNMENT_BRIEF_CODE_MAX_BYTES = 600
/** Budget when the coordinator asks for the expanded slice (`codeExpansion: 'full'`). */
export const ASSIGNMENT_BRIEF_CODE_EXPANDED_BYTES = 1600
/** Hard ceiling for an embedded v8 hop-checkpoint brief inside an assignment brief. */
export const ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES = 2048
export const HOP_CHECKPOINT_SCHEMA_V1 = 'v8.hop_checkpoint.v1' as const

export type MissionKind =
  | 'det_lead_upgrade'
  | 'workflow_skip'
  | 'business_logic'
  | 'chain_step_2'
  | 'multihop_chain'
  | 'second_order'
  | 'class_scan'

export interface AssignmentBriefRoute {
  /** Optional origin URL when routes span multiple approved public origins. */
  origin?: string
  method: string
  /** Path template only; any query string or fragment is stripped before rendering. */
  path: string
  /** Parameter NAMES only. Values are never rendered. */
  params?: readonly string[]
  /** Query | json | form | path | header | xml | graphql_var | ... */
  encoding?: string
  csrfRequired?: boolean
  /** Optional deterministic risk score (0-100) used for ordering. */
  riskScore?: number
}

export interface AssignmentBriefPersona {
  handle: string
  role?: string
  /** Resource IDs harvested for this persona (never tokens/cookies). */
  harvestedIds?: readonly string[]
}

export interface AssignmentBriefBaseline {
  status?: number
  topLevelKeys?: readonly string[]
  /** Short numeric/state fields only (counts, quantities, flags, enum states). */
  sampleNumericOrStateFields?: Record<string, string | number | boolean>
}

export interface AssignmentBriefConfirmedRef {
  method: string
  path: string
  param?: string | null
  cwe?: string | null
  origin?: string | null
  /** Read-only finding id so a worker can cite a confirmed floor finding as a chain primitive. */
  findingId?: string | null
}

export interface AssignmentBriefDetLead {
  probeClass: string
  exchangeId?: string | null
  signalSummary: string
  verifyFailureReason?: string | null
}

/**
 * Explicit settlement proof obligation for a hypothesis route: the exact mounted route, the
 * declared input names, the authorization context and the sink expression. Names only — never
 * values, bodies or secrets — so a specialist can build the replay spec without re-reading the
 * graph or guessing the route shape.
 */
export interface AssignmentBriefProofObligation {
  /** `METHOD /mounted/path` (as extracted), or a bare path. */
  route: string
  method?: string
  /** Parameter NAMES only. */
  params?: readonly string[]
  /** `guarded` / `unguarded` from the mounted middleware chain. */
  auth?: string
  /** `sinkKind@file:line` of the dataflow terminus. */
  sink?: string
  /** `route -> ... -> sink` hop locations, already bounded by the caller. */
  chain?: string
  /** Exact control actor for the differential (persona handle). */
  controlPersona?: string
  /** Exact variant actor for the differential (persona handle). */
  variantPersona?: string
  /** Explicit deliverable: invoke kovo_verify(<tool>) or record a coded proofGapReason. */
  deliverable?: string
}

export interface AssignmentBriefCheckpointHop {
  hop: number
  receiptId: string
  /** Opaque `cap:...` handle only; raw secret values are scrubbed/replaced. */
  capId: string
  kind?: string
  surface?: string
  service?: string
  tenant?: string
  actor?: string
  role?: string
  at?: string
  binding?: string
}

export interface AssignmentBriefCheckpointNextGoal {
  targetSurfaceKey?: string
  surface?: string
  service?: string
  endpoint: string
  method?: string
  hypothesisClass?: string
  expectedBinding?: string
  targetTenant?: string
  targetRole?: string
  goal: string
}

export interface AssignmentBriefPrunedBranch {
  surface: string
  hypothesis?: string
  reason: string
}

export interface AssignmentBriefWorkflowNotebook {
  discoveredRoutes?: readonly string[]
  verifiedHypotheses?: readonly string[]
  triedRecipes?: readonly string[]
  openHypotheses?: readonly string[]
}

export interface AssignmentBriefHopCheckpoint {
  schema?: string
  branchKey: string
  depth: number
  targetHop?: number
  mode?: 'pivot' | 'fuse' | 'discover' | 'sweep'
  evi?: number
  verifiedHops?: readonly AssignmentBriefCheckpointHop[]
  omittedEarlierHops?: number
  /** Opaque `cap:...` handles only; raw secrets are scrubbed. */
  capabilityHandles?: readonly string[]
  fuseWithBranchKey?: string
  nextGoal: AssignmentBriefCheckpointNextGoal
  prunedBranches?: readonly AssignmentBriefPrunedBranch[]
  workflowNotebook?: AssignmentBriefWorkflowNotebook
  /** Always rendered as `true` so specialists continue from parent hops instead of rediscovering Hop 1. */
  doNotRediscover?: true
}

export interface RenderedHopCheckpoint {
  schema: string
  branchKey: string
  depth: number
  targetHop: number
  mode: 'pivot' | 'fuse' | 'discover' | 'sweep'
  evi?: number
  verifiedHops: AssignmentBriefCheckpointHop[]
  omittedEarlierHops?: number
  capabilityHandles: string[]
  fuseWithBranchKey?: string
  nextGoal: AssignmentBriefCheckpointNextGoal
  prunedBranches?: AssignmentBriefPrunedBranch[]
  workflowNotebook?: {
    discoveredRoutes?: string[]
    verifiedHypotheses?: string[]
    triedRecipes?: string[]
    openHypotheses?: string[]
  }
  doNotRediscover: true
}

export interface FittedHopCheckpointResult {
  checkpoint: RenderedHopCheckpoint
  bytes: number
  truncated: boolean
}

export interface AssignmentBriefInput {
  missionKind: MissionKind
  origin: string
  routes?: readonly AssignmentBriefRoute[]
  linkedRoutes?: readonly AssignmentBriefRoute[]
  personas?: readonly AssignmentBriefPersona[]
  baseline?: AssignmentBriefBaseline
  alreadyConfirmedOnOrigin?: readonly AssignmentBriefConfirmedRef[]
  detLead?: AssignmentBriefDetLead
  /**
   * Compact white-box dataflow slice for the hypothesis route (built with
   * `buildCodeDataflowSlice`). Always hard-truncated before rendering.
   */
  codeSlice?: CodeDataflowSlice
  /**
   * Bounded v8 multi-hop checkpoint (`<= 2 KB`, opaque `cap:...` handles, verified parent hops,
   * next-hop pivot target, `doNotRediscover: true`). Always scrubbed and fitted before rendering.
   */
  hopCheckpoint?: AssignmentBriefHopCheckpoint
  /** One explicit proof obligation naming the route, auth context and sink chain. */
  proofObligation?: AssignmentBriefProofObligation
  /**
   * `compact` (default, 600 B slice, 1536 B brief) or `full` (1600 B slice, 4096 B brief) when
   * the planner/coordinator explicitly asks to expand the code evidence.
   */
  codeExpansion?: 'compact' | 'full'
  /** 1 hypothesis cluster (1-3 linked routes) or 1 det_lead, by default. */
  targetCount?: number
  turnBudget?: number
  /** Approved public origins for multi-service / cross-origin investigations. */
  publicOrigins?: readonly string[]
  /** Count of sealed capabilities already present in the run's CapabilityLedger. */
  sealedCapabilityCount?: number
  /** When true (or `KOVO_DECOUPLED_PROOF_PIPELINE=1`), omit `kovo_verify` boilerplate from the brief. */
  decoupledProofPipeline?: boolean
}

export interface AssignmentBriefResult {
  text: string
  bytes: number
  truncated: boolean
}

/**
 * Route evidence the settlement phase must name before a worker may conclude. `params` are
 * parameter NAMES only — values are never rendered, matching the brief's no-secret invariant.
 */
export interface SettlementSpecTarget {
  method: string
  /** Path template or observed request path; query string/fragment is stripped. */
  path: string
  params?: readonly string[]
  origin?: string
}

const SECRET_KEY_RE = /(?:secret|token|passw|pwd|api[_-]?key|authorization|cookie|session|jwt|bearer|credential|private[_-]?key|client[_-]?secret)/i
const BODY_KEY_RE = /(?:body|content|html|snippet|payload|response|raw|markup|text)/i
const SECRET_VALUE_RE =
  /^(?:bearer\s+)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$|^(?:sk|pk|ghp|gho|ghs|ghu|ghr|xox[baprs])_[A-Za-z0-9_-]{10,}$|^(?:sk-or-v1|sk-ant|sk-proj)-[A-Za-z0-9_-]{8,}$|^github_pat_[A-Za-z0-9_]{10,}$|^AKIA[0-9A-Z]{16}$/i
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g
const BEARER_RE = /(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi
const NAMED_SECRET_RE =
  /((?:secret|token|password|passwd|api[_-]?key|access[_-]?key|signing[_-]?salt|hmac[_-]?key|client[_-]?secret|session[_-]?(?:id|key|token)|cookie|sig(?:nature)?|auth)[ \t]*[:=][ \t]*)[^\s&"',;]+/gi
const KEY_PREFIX_RE =
  /\b(?:(?:sk|pk|ghp|gho|ghs|ghu|ghr|xox[baprs])_[A-Za-z0-9_-]{10,}|(?:sk-or-v1|sk-ant|sk-proj)-[A-Za-z0-9_-]{8,}|github_pat_[A-Za-z0-9_]{10,}|AKIA[0-9A-Z]{16})\b/g
const PEM_KEY_RE = /-----BEGIN [^-\n]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-\n]*PRIVATE KEY-----|$)/g
const RAW_HEX_SECRET_RE = /(?<![A-Za-z0-9_:-])[0-9a-fA-F]{40,}(?![A-Za-z0-9_:-])/g
const OPAQUE_CAP_HANDLE_RE =
  /^cap:(?:hop_[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._-]{0,63}|[A-Za-z0-9][A-Za-z0-9._-]{1,63}:[A-Za-z0-9][A-Za-z0-9._-]{1,63})$/
const OPAQUE_CAP_HANDLE_GLOBAL_RE =
  /\bcap:(?:hop_[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[A-Za-z0-9][A-Za-z0-9._-]{0,63}|[A-Za-z0-9][A-Za-z0-9._-]{1,63}:[A-Za-z0-9][A-Za-z0-9._-]{1,63})\b/g

function cleanText(value: unknown, maxBytes: number): string {
  if (typeof value !== 'string') return ''
  const flattened = value.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim()
  return truncateUtf8Head(flattened, maxBytes)
}

/** Validate an opaque v8 capability handle (`cap:hop_<id>:<slot>` or `cap:<ns>:<slot>`), rejecting raw secrets. */
export function sanitizeCapabilityHandle(value: unknown): string {
  if (typeof value !== 'string') return ''
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > 128) return ''
  if (!OPAQUE_CAP_HANDLE_RE.test(trimmed)) return ''
  if (isSecretValue(trimmed) || JWT_RE.test(trimmed) || KEY_PREFIX_RE.test(trimmed)) return ''
  // Reset stateful global regexes after `.test()`.
  JWT_RE.lastIndex = 0
  KEY_PREFIX_RE.lastIndex = 0
  return trimmed
}

/** Remove token-shaped fragments and body-like key/value pairs from free text while preserving valid opaque `cap:...` handles. */
export function redactBriefText(value: unknown, maxBytes = 200): string {
  let text = cleanText(value, maxBytes * 2)
  if (!text) return ''
  // Protect valid opaque `cap:...` handles from key:value redaction patterns before scrubbing.
  const preservedHandles: string[] = []
  text = text.replace(OPAQUE_CAP_HANDLE_GLOBAL_RE, match => {
    const clean = sanitizeCapabilityHandle(match)
    if (!clean) return '[redacted]'
    const idx = preservedHandles.push(clean) - 1
    return `\u0001CAP${idx}\u0002`
  })
  text = redact(text)
    .replace(PEM_KEY_RE, '[redacted-key]')
    .replace(JWT_RE, '[redacted-jwt]')
    .replace(BEARER_RE, '$1[redacted]')
    .replace(KEY_PREFIX_RE, '[redacted]')
    .replace(NAMED_SECRET_RE, '$1[redacted]')
    .replace(RAW_HEX_SECRET_RE, '[redacted-hex]')
    .replace(/\b(?:body|html|content)\s*[:=]\s*[^\s]+/gi, '[body omitted]')
  text = text.replace(/\u0001CAP(\d+)\u0002/g, (_m, idx) => preservedHandles[Number(idx)] ?? '')
  return truncateUtf8Head(text, maxBytes)
}

function truncateUtf8Head(text: string, maxBytes: number): string {
  if (maxBytes <= 0) return ''
  const buf = Buffer.from(text, 'utf8')
  if (buf.length <= maxBytes) return text
  let end = maxBytes
  while (end > 0 && (buf[end] & 0xc0) === 0x80) end--
  return buf.subarray(0, end).toString('utf8')
}

function isSecretValue(value: unknown): boolean {
  return typeof value === 'string' && SECRET_VALUE_RE.test(value.trim())
}

function cleanPath(value: unknown): string {
  if (typeof value !== 'string') return '/'
  const withoutQuery = value.split(/[?#]/, 1)[0] || '/'
  const normalized = withoutQuery.replace(/[\u0000-\u001f\u007f\s]+/g, '').slice(0, 160)
  return normalized.startsWith('/') ? normalized : `/${normalized}`
}

function cleanParamName(value: unknown): string {
  if (typeof value !== 'string') return ''
  return value.trim().split('=', 1)[0]!.replace(/[^A-Za-z0-9_.:[\]-]/g, '').slice(0, 48)
}

function cleanEncoding(value: unknown): string {
  if (typeof value !== 'string') return ''
  return value.trim().replace(/[^A-Za-z0-9_-]/g, '').slice(0, 24)
}

function cleanHarvestedId(value: unknown): string {
  if (typeof value !== 'string') return ''
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > 120) return ''
  if (/[\s\u0000-\u001f\u007f]/.test(trimmed)) return ''
  if (isSecretValue(trimmed)) return ''
  return trimmed
}

function routeSignal(route: AssignmentBriefRoute): number {
  const method = route.method.toUpperCase()
  const methodWeight = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE' ? 8 : 0
  const params = route.params?.length ?? 0
  return (route.riskScore ?? 0) + methodWeight + Math.min(params, 4)
}

function normalizeRoute(route: AssignmentBriefRoute): AssignmentBriefRoute {
  const origin = typeof route.origin === 'string' ? cleanText(route.origin.split(/[?#]/, 1)[0], 120) : ''
  const params = [...new Set((route.params ?? []).map(cleanParamName).filter(Boolean))].slice(0, 8)
  const encoding = cleanEncoding(route.encoding)
  return {
    ...(origin ? { origin } : {}),
    method: (route.method || 'GET').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10) || 'GET',
    path: cleanPath(route.path),
    ...(params.length ? { params } : {}),
    ...(encoding ? { encoding } : {}),
    ...(route.csrfRequired ? { csrfRequired: true } : {}),
    ...(typeof route.riskScore === 'number' && Number.isFinite(route.riskScore)
      ? { riskScore: Math.max(0, Math.min(100, Math.round(route.riskScore))) }
      : {}),
  }
}

function sortRoutes(routes: readonly AssignmentBriefRoute[]): AssignmentBriefRoute[] {
  const seen = new Set<string>()
  const normalized: AssignmentBriefRoute[] = []
  for (const route of routes) {
    const next = normalizeRoute(route)
    const key = `${next.origin ?? ''} ${next.method} ${next.path} ${(next.params ?? []).join(',')}`
    if (seen.has(key)) continue
    seen.add(key)
    normalized.push(next)
  }
  return normalized.sort((a, b) => {
    const signal = routeSignal(b) - routeSignal(a)
    if (signal !== 0) return signal
    if ((a.origin ?? '') !== (b.origin ?? '')) return (a.origin ?? '') < (b.origin ?? '') ? -1 : 1
    if (a.path !== b.path) return a.path < b.path ? -1 : 1
    return a.method < b.method ? -1 : a.method > b.method ? 1 : 0
  })
}

function interleaveMultiOriginRoutes(
  routes: readonly AssignmentBriefRoute[],
  publicOrigins: readonly string[],
  primaryOrigin: string,
  maxTotal: number,
): AssignmentBriefRoute[] {
  const sorted = sortRoutes(routes)
  const buckets = new Map<string, AssignmentBriefRoute[]>()
  for (const route of sorted) {
    const bucketOrigin = route.origin || primaryOrigin
    const list = buckets.get(bucketOrigin)
    if (list) list.push(route)
    else buckets.set(bucketOrigin, [route])
  }
  const orderedOrigins = [
    ...publicOrigins.filter(orig => buckets.has(orig)),
    ...[...buckets.keys()].filter(orig => !publicOrigins.includes(orig)).sort(),
  ]
  const interleaved: AssignmentBriefRoute[] = []
  let depth = 0
  while (interleaved.length < maxTotal) {
    let added = false
    for (const orig of orderedOrigins) {
      const bucket = buckets.get(orig)
      if (bucket && depth < bucket.length) {
        interleaved.push(bucket[depth]!)
        added = true
        if (interleaved.length >= maxTotal) break
      }
    }
    if (!added) break
    depth += 1
  }
  return interleaved
}

export function selectBriefRoutes(
  endpoints: readonly { origin: string; method: string; pathTemplate: string; riskScore: number }[],
  options: {
    publicOrigins: readonly string[]
    targetOrigins: readonly string[]
    confirmedPaths: ReadonlySet<string>
    confirmedOriginPaths: ReadonlySet<string>
    normalizePath: (path: string) => string
  },
): AssignmentBriefRoute[] {
  const { publicOrigins, targetOrigins, confirmedPaths, confirmedOriginPaths, normalizePath } = options
  if (publicOrigins.length <= 1) {
    const originEndpoints = endpoints.filter(ep => targetOrigins.includes(ep.origin))
    const unconfirmed = originEndpoints.filter(ep => !confirmedPaths.has(normalizePath(ep.pathTemplate)))
    return (unconfirmed.length > 0 ? unconfirmed : originEndpoints)
      .slice(0, 6)
      .map(ep => ({ method: ep.method, path: ep.pathTemplate, riskScore: ep.riskScore }))
  }
  const perOrigin = new Map<string, typeof endpoints[number][]>()
  for (const orig of publicOrigins) {
    const epsForOrigin = endpoints.filter(ep => ep.origin === orig)
    if (epsForOrigin.length === 0) continue
    const unconfirmed = epsForOrigin.filter(ep => !confirmedOriginPaths.has(`${orig} ${normalizePath(ep.pathTemplate)}`))
    perOrigin.set(orig, (unconfirmed.length > 0 ? unconfirmed : epsForOrigin).slice(0, 4))
  }
  const routes: AssignmentBriefRoute[] = []
  for (let slot = 0; slot < 4 && routes.length < 20; slot += 1) {
    for (const orig of publicOrigins) {
      const ep = perOrigin.get(orig)?.[slot]
      if (!ep) continue
      routes.push({ origin: ep.origin, method: ep.method, path: ep.pathTemplate, riskScore: ep.riskScore })
      if (routes.length >= 20) break
    }
  }
  return routes
}

function normalizeConfirmed(ref: AssignmentBriefConfirmedRef): Record<string, unknown> {
  const param = cleanParamName(ref.param ?? '')
  const cwe = typeof ref.cwe === 'string' ? ref.cwe.trim().replace(/[^A-Za-z0-9-]/g, '').slice(0, 24) : ''
  const findingId = typeof ref.findingId === 'string' ? cleanText(ref.findingId, 64) : ''
  return {
    method: (ref.method || 'GET').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10) || 'GET',
    path: cleanPath(ref.path),
    ...(param ? { param } : {}),
    ...(cwe ? { cwe } : {}),
    ...(findingId ? { findingId } : {}),
  }
}

function normalizeProofObligation(
  obligation: AssignmentBriefProofObligation,
): Record<string, unknown> | undefined {
  const raw = typeof obligation.route === 'string' ? obligation.route.trim().slice(0, 180) : ''
  if (!raw) return undefined
  const matched = /^([A-Za-z]{2,10})\s+(.*)$/.exec(raw)
  const routeMethod = (obligation.method || matched?.[1] || '')
    .toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10)
  const routePath = cleanPath(matched?.[2] ?? raw)
  const params = [...new Set((obligation.params ?? []).map(cleanParamName).filter(Boolean))].slice(0, 8)
  const auth = cleanText(obligation.auth, 16)
  const sink = redactBriefText(obligation.sink, 96)
  const chain = redactBriefText(obligation.chain, 200)
  const controlPersona = cleanText(obligation.controlPersona, 48)
  const variantPersona = cleanText(obligation.variantPersona, 48)
  const deliverable = redactBriefText(obligation.deliverable, 240)
  return {
    route: `${routeMethod || 'ANY'} ${routePath}`,
    ...(params.length ? { params } : {}),
    ...(auth ? { auth } : {}),
    ...(sink ? { sink } : {}),
    ...(chain ? { chain } : {}),
    ...(controlPersona ? { controlPersona } : {}),
    ...(variantPersona ? { variantPersona } : {}),
    ...(deliverable ? { deliverable } : {}),
  }
}

function normalizeDetLead(lead: AssignmentBriefDetLead): Record<string, unknown> {
  return {
    probeClass: cleanText(lead.probeClass, 40) || 'unknown',
    ...(lead.exchangeId ? { exchangeId: cleanText(lead.exchangeId, 64) } : {}),
    signalSummary: redactBriefText(lead.signalSummary, 180),
    ...(lead.verifyFailureReason
      ? { verifyFailureReason: redactBriefText(lead.verifyFailureReason, 120) }
      : {}),
  }
}

const VALID_CHECKPOINT_MODES = new Set(['pivot', 'fuse', 'discover', 'sweep'] as const)

function cleanCheckpointEndpoint(value: unknown, maxBytes = 120): string {
  if (typeof value !== 'string') return '/'
  const trimmed = value.trim()
  if (!trimmed) return '/'
  const methodMatch = /^([A-Za-z]{2,10})\s+(.*)$/.exec(trimmed)
  if (methodMatch) {
    const method = methodMatch[1]!.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10)
    const pathPart = redactBriefText(cleanPath(methodMatch[2]!), Math.max(16, maxBytes - method.length - 1))
    return truncateUtf8Head(`${method} ${pathPart || '/'}`, maxBytes)
  }
  const stripped = trimmed.split(/[?#]/, 1)[0] || '/'
  const scrubbed = redactBriefText(stripped, maxBytes).replace(/\s+/g, '')
  if (!scrubbed) return '/'
  return scrubbed.startsWith('/') ? scrubbed : `/${scrubbed}`
}

function normalizeCheckpointHop(hop: AssignmentBriefCheckpointHop, compact = false): AssignmentBriefCheckpointHop {
  const hopNum = Number.isFinite(hop.hop) ? Math.max(1, Math.min(8, Math.trunc(hop.hop))) : 1
  const receiptId = redactBriefText(hop.receiptId, 48) || `hop-${hopNum}`
  const capId = sanitizeCapabilityHandle(hop.capId) || `cap:redacted:hop_${hopNum}`
  const out: AssignmentBriefCheckpointHop = { hop: hopNum, receiptId, capId }
  const kind = redactBriefText(hop.kind, 32)
  const surface = redactBriefText(hop.surface, 24)
  const service = redactBriefText(hop.service, 48)
  const tenant = redactBriefText(hop.tenant, 36)
  const actor = redactBriefText(hop.actor, 36)
  if (kind) out.kind = kind
  if (surface) out.surface = surface
  if (service) out.service = service
  if (tenant) out.tenant = tenant
  if (actor) out.actor = actor
  if (!compact) {
    const role = redactBriefText(hop.role, 32)
    const at = hop.at ? cleanCheckpointEndpoint(hop.at, 72) : ''
    const binding = redactBriefText(hop.binding, 32)
    if (role) out.role = role
    if (at) out.at = at
    if (binding) out.binding = binding
  }
  return out
}

/**
 * Scrub and deterministically fit a v8 `hopCheckpoint` to `<= maxBytes` (hard cap `<= 2048 B`).
 * Preserves valid opaque `cap:...` handles, parent hops, next-hop pivot target, and `doNotRediscover: true`
 * while stripping all raw secrets and query-string credentials.
 */
export function fitHopCheckpointForBrief(
  input: AssignmentBriefHopCheckpoint,
  maxBytes = ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES,
): FittedHopCheckpointResult {
  const cap = Math.max(256, Math.min(Math.floor(maxBytes), ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES))
  const mode = input.mode && VALID_CHECKPOINT_MODES.has(input.mode) ? input.mode : 'pivot'
  const depth = Number.isFinite(input.depth) ? Math.max(0, Math.min(8, Math.trunc(input.depth))) : 0
  const targetHop = Number.isFinite(input.targetHop)
    ? Math.max(1, Math.min(8, Math.trunc(input.targetHop!)))
    : Math.max(1, Math.min(8, depth + 1))
  const branchKey = redactBriefText(input.branchKey, 64) || 'branch-0'
  const fuseWithBranchKey = input.fuseWithBranchKey ? redactBriefText(input.fuseWithBranchKey, 64) : ''
  const evi = typeof input.evi === 'number' && Number.isFinite(input.evi)
    ? Number(Math.max(0, input.evi).toFixed(6))
    : undefined

  const orderedInputHops = [...(input.verifiedHops ?? [])].sort((a, b) => (a.hop - b.hop) || a.receiptId.localeCompare(b.receiptId))
  const baseOmitted = typeof input.omittedEarlierHops === 'number' && Number.isFinite(input.omittedEarlierHops)
    ? Math.max(0, Math.trunc(input.omittedEarlierHops))
    : 0

  // Collect only valid opaque `cap:...` handles (from explicit list + verified hops).
  const handleSet = new Set<string>()
  for (const h of input.capabilityHandles ?? []) {
    const clean = sanitizeCapabilityHandle(h)
    if (clean) handleSet.add(clean)
  }
  for (const hop of orderedInputHops) {
    const clean = sanitizeCapabilityHandle(hop.capId)
    if (clean) handleSet.add(clean)
  }
  const allHandles = [...handleSet].slice(0, 16)

  const prunedBranches: AssignmentBriefPrunedBranch[] = (input.prunedBranches ?? [])
    .slice(0, 8)
    .map(b => ({
      surface: redactBriefText(b.surface, 72) || 'unknown',
      ...(b.hypothesis ? { hypothesis: redactBriefText(b.hypothesis, 48) } : {}),
      reason: redactBriefText(b.reason, 48) || 'invariant_enforced_hardened',
    }))

  const makeNextGoal = (goalBytes: number, endpointBytes: number, includeOptional: boolean): AssignmentBriefCheckpointNextGoal => {
    const ng = input.nextGoal
    const method = ng.method ? ng.method.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10) : ''
    const out: AssignmentBriefCheckpointNextGoal = {
      endpoint: cleanCheckpointEndpoint(ng.endpoint, endpointBytes),
      goal: redactBriefText(ng.goal, goalBytes) || 'Advance next hop',
    }
    if (method) out.method = method
    const surface = redactBriefText(ng.surface, 24)
    const service = redactBriefText(ng.service, 48)
    const hypothesisClass = redactBriefText(ng.hypothesisClass, 48)
    if (surface) out.surface = surface
    if (service) out.service = service
    if (hypothesisClass) out.hypothesisClass = hypothesisClass
    if (includeOptional) {
      const targetSurfaceKey = redactBriefText(ng.targetSurfaceKey, 80)
      const expectedBinding = redactBriefText(ng.expectedBinding, 32)
      const targetTenant = redactBriefText(ng.targetTenant, 36)
      const targetRole = redactBriefText(ng.targetRole, 32)
      if (targetSurfaceKey) out.targetSurfaceKey = targetSurfaceKey
      if (expectedBinding) out.expectedBinding = expectedBinding
      if (targetTenant) out.targetTenant = targetTenant
      if (targetRole) out.targetRole = targetRole
    }
    return out
  }

  const cleanNbList = (items: readonly string[] | undefined, maxItems: number, maxLen: number): string[] =>
    [...new Set((items ?? []).map(v => redactBriefText(v, maxLen)).filter(Boolean))].slice(0, maxItems)
  const rawNb = input.workflowNotebook
  const notebook: NonNullable<RenderedHopCheckpoint['workflowNotebook']> | undefined = rawNb
    ? (() => {
        const discoveredRoutes = cleanNbList(rawNb.discoveredRoutes, 10, 88)
        const verifiedHypotheses = cleanNbList(rawNb.verifiedHypotheses, 6, 110)
        const triedRecipes = cleanNbList(rawNb.triedRecipes, 10, 110)
        const openHypotheses = cleanNbList(rawNb.openHypotheses, 6, 110)
        if (!discoveredRoutes.length && !verifiedHypotheses.length && !triedRecipes.length && !openHypotheses.length) return undefined
        return {
          ...(discoveredRoutes.length ? { discoveredRoutes } : {}),
          ...(verifiedHypotheses.length ? { verifiedHypotheses } : {}),
          ...(triedRecipes.length ? { triedRecipes } : {}),
          ...(openHypotheses.length ? { openHypotheses } : {}),
        }
      })()
    : undefined

  const build = (
    hops: AssignmentBriefCheckpointHop[],
    omitted: number,
    handles: string[],
    pruned: AssignmentBriefPrunedBranch[],
    goalBytes: number,
    endpointBytes: number,
    includeOptional: boolean,
    nb?: RenderedHopCheckpoint['workflowNotebook'],
  ): RenderedHopCheckpoint => ({
    schema: HOP_CHECKPOINT_SCHEMA_V1,
    branchKey,
    depth,
    targetHop,
    mode,
    ...(includeOptional && evi !== undefined ? { evi } : {}),
    verifiedHops: hops,
    ...(omitted > 0 ? { omittedEarlierHops: omitted } : {}),
    capabilityHandles: handles,
    ...(includeOptional && fuseWithBranchKey ? { fuseWithBranchKey } : {}),
    nextGoal: makeNextGoal(goalBytes, endpointBytes, includeOptional),
    ...(pruned.length ? { prunedBranches: pruned } : {}),
    ...(nb && Object.keys(nb).length ? { workflowNotebook: nb } : {}),
    doNotRediscover: true,
  })

  const measure = (cp: RenderedHopCheckpoint) => Buffer.byteLength(JSON.stringify(cp), 'utf8')

  const fullHops = orderedInputHops.map(h => normalizeCheckpointHop(h, false))
  const full = build(fullHops, baseOmitted, allHandles, prunedBranches, 180, 96, true, notebook)
  const fullBytes = measure(full)
  if (fullBytes <= cap) return { checkpoint: full, bytes: fullBytes, truncated: false }

  if (notebook) {
    const trimmedNb: NonNullable<RenderedHopCheckpoint['workflowNotebook']> = {
      ...(notebook.discoveredRoutes ? { discoveredRoutes: [...notebook.discoveredRoutes] } : {}),
      ...(notebook.verifiedHypotheses ? { verifiedHypotheses: [...notebook.verifiedHypotheses] } : {}),
      ...(notebook.triedRecipes ? { triedRecipes: [...notebook.triedRecipes] } : {}),
      ...(notebook.openHypotheses ? { openHypotheses: [...notebook.openHypotheses] } : {}),
    }
    const trimOrder = ['triedRecipes', 'discoveredRoutes', 'openHypotheses', 'verifiedHypotheses'] as const
    for (const key of trimOrder) {
      while (trimmedNb[key]?.length) {
        trimmedNb[key]!.pop()
        if (!trimmedNb[key]!.length) delete trimmedNb[key]
        const candidate = build(fullHops, baseOmitted, allHandles, prunedBranches, 180, 96, true, Object.keys(trimmedNb).length ? trimmedNb : undefined)
        const bytes = measure(candidate)
        if (bytes <= cap) return { checkpoint: candidate, bytes, truncated: true }
      }
    }
  }

  const passes = [
    { compact: false, goalBytes: 180, endpointBytes: 96, opt: true, keepPruned: true },
    { compact: false, goalBytes: 160, endpointBytes: 88, opt: true, keepPruned: false },
    { compact: true, goalBytes: 110, endpointBytes: 64, opt: false, keepPruned: false },
    { compact: true, goalBytes: 64, endpointBytes: 48, opt: false, keepPruned: false },
  ] as const

  for (const pass of passes) {
    const hops = orderedInputHops.map(h => normalizeCheckpointHop(h, pass.compact))
    const pruned = pass.keepPruned ? prunedBranches.slice(0, 2) : []
    for (let keep = hops.length; keep >= 0; keep -= 1) {
      const slice = keep === 0 ? [] : hops.slice(hops.length - keep)
      const omitted = baseOmitted + (hops.length - slice.length)
      const handles = keep === 0 ? allHandles.slice(-Math.min(allHandles.length, 4)) : allHandles
      const candidate = build(slice, omitted, handles, pruned, pass.goalBytes, pass.endpointBytes, pass.opt)
      const bytes = measure(candidate)
      if (bytes <= cap) return { checkpoint: candidate, bytes, truncated: true }
    }
  }

  // Final guaranteed-under-cap fallback preserving opaque handle + target + doNotRediscover.
  const minimal: RenderedHopCheckpoint = {
    schema: HOP_CHECKPOINT_SCHEMA_V1,
    branchKey: truncateUtf8Head(branchKey, 24),
    depth,
    targetHop,
    mode,
    verifiedHops: [],
    ...(baseOmitted + orderedInputHops.length > 0 ? { omittedEarlierHops: baseOmitted + orderedInputHops.length } : {}),
    capabilityHandles: allHandles.slice(-1).map(h => truncateUtf8Head(h, 48)),
    nextGoal: {
      endpoint: cleanCheckpointEndpoint(input.nextGoal.endpoint, 32),
      goal: redactBriefText(input.nextGoal.goal, 28) || 'Advance hop',
    },
    doNotRediscover: true,
  }
  const minimalBytes = measure(minimal)
  if (minimalBytes <= cap) return { checkpoint: minimal, bytes: minimalBytes, truncated: true }
  minimal.capabilityHandles = []
  minimal.nextGoal = { endpoint: '/', goal: 'Pivot' }
  minimal.branchKey = truncateUtf8Head(branchKey, 12)
  return { checkpoint: minimal, bytes: measure(minimal), truncated: true }
}

export interface AssignmentBriefMultiHopContract {
  attackerOriginRule: string
  continueChainRule: string
  optionalHelpers?: string
  helperPatterns?: string[]
  modeATsRecipe: string
  hardenedTwinRule: string
}

export const MULTIHOP_ATTACKER_ORIGIN_RULE =
  'Run discovery & attack hops as low-privilege/attacker persona(s) ONLY — NEVER privileged victim/owner/admin shortcuts (negative control only, passing { arm: "control" }). Shared/dual-tenant persona crossing into non-admin tenant -> dual_tenant_abac (not broken_access_control). Ablation = SAME actor as toHop.'

export const MULTIHOP_CONTINUE_CHAIN_RULE =
  'Explore with http_request/kovo_http first; NEVER seal-only kovo_verify. Never submit a proof for reading your own tenant resource or stopping at an intermediate invite/token/metadata/job/export-handle/role-write mint — seal (ctx.seal_capability) and chain Hops 3-5 in ONE SAME script to cross-tenant/unauthorized victim impact on terminalHopId via ctx.chain(...).prove().'

export const RECORD_COVERAGE_BRIEF_GUIDANCE = buildRecordCoverageBriefGuidance()

export const MULTIHOP_HARDENED_TWIN_RULE =
  `If a terminal guard holds cleanly, do NOT file a standalone finding on benign Hop 1-2; call record_coverage(status="ruled_out", proofGapReason="invariant_enforced_hardened") with enforcingControl+exchangeIds (or needs_follow_up if no live exchange) and complete_intent.`

export const MULTIHOP_OPTIONAL_HELPERS_NOTE =
  'Crypto/async hops: ctx.hmac_sign({ secretHandle, payload, alg: "sha256", encoding: "hex" }) | ctx.jwt_sign({ secretHandle, claims, alg: "HS256", hopReceiptId, slot }) -> derived_crypto_binding; ctx.await_async({ pollRequest, matchPredicate, triggerExchangeId, correlationId, profile: "fast_lab" }) -> async_pivot_binding; state mutation -> state_transition_binding (entityId, ablationExchangeIds as SAME actor as toHop).'

export const MULTIHOP_HMAC_SIGN_PATTERN =
  'const sig = await ctx.hmac_sign({ secretHandle: cap.handle, payload: body, alg: "sha256", encoding: "hex" }) // send sig.signature -> derived_crypto_binding'

export const MULTIHOP_JWT_SIGN_PATTERN =
  'const minted = await ctx.jwt_sign({ secretHandle: cap.handle, claims: { sub: "svc", scope: "admin" }, alg: "HS256", hopReceiptId: "2", slot: "jwt" }) // use capability: minted.derivedHandle -> derived_crypto_binding'

export const MULTIHOP_AWAIT_ASYNC_PATTERN =
  'const pol = await ctx.await_async({ pollRequest: { path: "/api/jobs/" + id, as: "<attacker_persona>", role: "probe" }, matchPredicate: { status: 200, jsonPath: "$.status", equals: "completed" }, triggerExchangeId: h1.exchangeId, correlationId: id, profile: "fast_lab" }) // -> async_pivot_binding (pollRecordId: pol.pollRecordId)'

const CRYPTO_HELPER_SIGNAL_RE = /\b(?:webhook|hmac|sign(?:ing|ature|ed)?|secret|salt|jwt|jws|oidc|oauth|token|assertion|bearer|key|crypto|forge)\b/i
const ASYNC_HELPER_SIGNAL_RE = /\b(?:async|job|export|worker|queue|poll|pdf|render|ssrf|callback|webhook|batch|settlement|ledger|report|download|presign(?:ed)?|signed[_-]?url|storage|cdn)\b/i

function detectMultiHopHelperPatterns(input?: AssignmentBriefInput, compact = false): string[] {
  if (!input) return []
  const parts: string[] = []
  for (const r of [...(input.routes ?? []), ...(input.linkedRoutes ?? [])]) {
    parts.push(r.path, ...(r.params ?? []))
  }
  if (input.hopCheckpoint) {
    const ng = input.hopCheckpoint.nextGoal
    parts.push(ng.endpoint, ng.goal, ng.surface ?? '', ng.hypothesisClass ?? '', ng.expectedBinding ?? '')
    for (const vh of input.hopCheckpoint.verifiedHops ?? []) {
      parts.push(vh.kind ?? '', vh.surface ?? '', vh.at ?? '', vh.binding ?? '')
    }
  }
  if (input.proofObligation) {
    parts.push(input.proofObligation.route, input.proofObligation.sink ?? '', input.proofObligation.chain ?? '', input.proofObligation.deliverable ?? '')
  }
  if (input.detLead) parts.push(input.detLead.probeClass, input.detLead.signalSummary)
  if (input.codeSlice) parts.push(input.codeSlice.route ?? '', input.codeSlice.sink?.kind ?? '', input.codeSlice.sink?.at ?? '')
  const corpus = parts.join(' ')
  if (!corpus.trim()) return []
  const patterns: string[] = []
  if (CRYPTO_HELPER_SIGNAL_RE.test(corpus)) {
    patterns.push(
      compact ? 'ctx.hmac_sign({ secretHandle: cap.handle, payload: body, alg: "sha256", encoding: "hex" })' : MULTIHOP_HMAC_SIGN_PATTERN,
      compact ? 'ctx.jwt_sign({ secretHandle: cap.handle, claims, alg: "HS256", hopReceiptId: "2", slot: "jwt" })' : MULTIHOP_JWT_SIGN_PATTERN,
    )
  }
  if (ASYNC_HELPER_SIGNAL_RE.test(corpus)) {
    patterns.push(
      compact
        ? 'ctx.await_async({ pollRequest: { path, as: "<attacker_persona>", role: "probe" }, matchPredicate: { status: 200 }, triggerExchangeId: h1.exchangeId, correlationId: id, profile: "fast_lab" })'
        : MULTIHOP_AWAIT_ASYNC_PATTERN,
    )
  }
  return patterns
}

/** Exact Mode-A TypeScript kovo_verify recipe (<= 18 lines, live SDK parameter names). */
export const MULTIHOP_MODE_A_TS_RECIPE = [
  '// Explore via http_request/kovo_http first; NEVER seal-only kovo_verify. Run Hop 1..N + ctx.chain(...).prove() / ctx.prove_composite in ONE script.',
  'const actor = "<attacker_persona>" // low-priv attacker; negative control MUST pass { arm: "control" } as SAME actor as toHop',
  'const ctrl = await ctx.http("/api/target", { as: actor, arm: "control" })',
  'const h1 = await ctx.http_send("/api/hop1", { as: actor, role: "probe" })',
  'const cap = await ctx.seal_capability({ exchange: h1, hopReceiptId: "1", slot: "tok", jsonPath: "$.token" })',
  'const h2 = await ctx.http_send("/api/target", { capability: cap.handle, role: "probe" })',
  'await ctx.prove_composite({',
  '  // Match terminalVulnClass to actual impact: broken_access_control|privilege_escalation|stale_privilege_use|cross_tenant_export|ledger_overcredit|forged_settlement (dual_tenant_abac ONLY for cross-tenant ABAC w/denied terminal ctrl)',
  '  chainId: "chain-1", terminalVulnClass: "broken_access_control", replayMode: "fresh_clean_replay",',
  '  hops: [',
  '    { hopId: "hop_1", surface: "http", target: { origin: ctx.targetOrigin, method: "GET", pathAndQuery: "/api/hop1" }, exchangeIds: [h1.exchangeId], producedCapabilities: [cap.handle], claimedDelta: "Hop 1 capability obtained." },',
  '    { hopId: "hop_2", surface: "http", target: { origin: ctx.targetOrigin, method: "GET", pathAndQuery: "/api/target" }, exchangeIds: [h2.exchangeId], consumedCapabilities: [cap.handle], claimedDelta: "Hop 2 boundary crossed." },',
  '  ],',
  '  // causalEdges.kind: value_binding | derived_crypto_binding | state_transition_binding (ablation as SAME actor as toHop) | async_pivot_binding',
  '  causalEdges: [{ kind: "value_binding", fromHopId: "hop_1", toHopId: "hop_2", capabilityHandle: cap.handle }],',
  '  terminalImpact: { terminalHopId: "hop_2", claimedImpact: "Unauthorized cross-tenant/victim terminal impact confirmed.", preChainControlExchangeIds: [ctrl.exchangeId], postChainReadbackExchangeIds: [h2.exchangeId] },',
  '})',
  'return ctx.result({ title: "Multi-hop chain confirmed" })',
].join('\n')

const COMPACT_MULTIHOP_MODE_A_RECIPE =
  'a="<attacker_persona>"; ctx.http(t,{as:a,arm:"control"}); h1=http_send(hop1,{as:a,role:"probe"}); cap=seal_capability({exchange:h1,slot:"tok",jsonPath:"$.token"}); http_send(t,{capability:cap.handle,role:"probe"}); prove_composite({chainId,terminalVulnClass:"<broken_access_control|privilege_escalation|stale_privilege_use|cross_tenant_export|ledger_overcredit|forged_settlement;dual_tenant_abac w/ctrl>",hops,causalEdges:[value_binding|derived_crypto_binding|state_transition_binding|async_pivot_binding],terminalImpact,replayMode:"fresh_clean_replay"})'

function isExplicitMultiHopMission(input: Pick<AssignmentBriefInput, 'missionKind' | 'hopCheckpoint'>): boolean {
  return Boolean(input.hopCheckpoint)
    || input.missionKind === 'chain_step_2'
    || input.missionKind === 'multihop_chain'
    || input.missionKind === 'second_order'
}

export function isMultiHopBriefInput(
  input: Pick<
    AssignmentBriefInput,
    'missionKind' | 'hopCheckpoint' | 'codeSlice' | 'publicOrigins' | 'sealedCapabilityCount'
  >,
): boolean {
  return isExplicitMultiHopMission(input)
    || (input.codeSlice?.hops?.length ?? 0) >= 2
    || (input.codeSlice?.mounts?.length ?? 0) >= 2
    || (input.publicOrigins?.length ?? 0) >= 2
    || (input.sealedCapabilityCount ?? 0) > 0
}

function resolveBriefDefaultCap(input: AssignmentBriefInput): number {
  return input.codeExpansion === 'full'
    || isExplicitMultiHopMission(input)
    || (input.publicOrigins?.length ?? 0) >= 2
    || (input.sealedCapabilityCount ?? 0) > 0
    ? ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE
    : ASSIGNMENT_BRIEF_MAX_BYTES
}

export function buildMultiHopProofContract(compact = false, input?: AssignmentBriefInput): AssignmentBriefMultiHopContract {
  const helperPatterns = detectMultiHopHelperPatterns(input, compact)
  if (compact) {
    return {
      attackerOriginRule: 'Low-priv only (no victim/owner/admin); non-admin tenant->dual_tenant_abac; SAME actor; {arm:"control"}.',
      continueChainRule: 'kovo_http; no own-tenant/handle stubs; ctx.seal_capability Hops 3-5->terminalHopId+ctx.chain().prove() in SAME script.',
      ...(helperPatterns.length ? { helperPatterns } : {}),
      modeATsRecipe: COMPACT_MULTIHOP_MODE_A_RECIPE,
      hardenedTwinRule: 'Guard holds: no Hop1-2 finding; record_coverage(status="ruled_out", proofGapReason="invariant_enforced_hardened")+complete_intent.',
    }
  }
  return {
    attackerOriginRule: MULTIHOP_ATTACKER_ORIGIN_RULE,
    continueChainRule: MULTIHOP_CONTINUE_CHAIN_RULE,
    optionalHelpers: MULTIHOP_OPTIONAL_HELPERS_NOTE,
    ...(helperPatterns.length ? { helperPatterns } : {}),
    modeATsRecipe: MULTIHOP_MODE_A_TS_RECIPE,
    hardenedTwinRule: MULTIHOP_HARDENED_TWIN_RULE,
  }
}

interface WorkingState {
  publicOrigins: string[]
  routes: AssignmentBriefRoute[]
  linked: AssignmentBriefRoute[]
  personas: Array<{ handle: string; role?: string; harvestedIds: string[] }>
  baseline?: { status?: number; keys: string[]; sample: Array<[string, string | number | boolean]> }
  confirmed: Array<Record<string, unknown>>
  detLead?: Record<string, unknown>
  code?: CodeDataflowSlice
  codeBudget: number
  hopCheckpoint?: RenderedHopCheckpoint
  hopCheckpointBudget: number
  multiHopProofContract?: AssignmentBriefMultiHopContract
  multiHopContractCompacted: boolean
  proofObligation?: Record<string, unknown>
  coverageContract?: string
}

function renderPacket(input: AssignmentBriefInput, state: WorkingState): Record<string, unknown> {
  return {
    mission: input.missionKind,
    origin: cleanText(input.origin.split(/[?#]/, 1)[0], 180),
    ...(state.publicOrigins.length > 1 ? { publicOrigins: state.publicOrigins } : {}),
    ...(state.detLead ? { detLead: state.detLead } : {}),
    ...(state.hopCheckpoint ? { hopCheckpoint: state.hopCheckpoint } : {}),
    ...(state.multiHopProofContract ? { multiHopProofContract: state.multiHopProofContract } : {}),
    ...(state.proofObligation ? { proofObligation: state.proofObligation } : {}),
    ...(state.coverageContract ? { coverageContract: state.coverageContract } : {}),
    routes: state.routes,
    ...(state.code ? { code: state.code } : {}),
    ...(state.linked.length ? { linkedRoutes: state.linked } : {}),
    ...(state.personas.length
      ? {
          personas: state.personas.map(p => ({
            handle: p.handle,
            ...(p.role ? { role: p.role } : {}),
            ...(p.harvestedIds.length ? { harvestedIds: p.harvestedIds } : {}),
          })),
        }
      : {}),
    ...(state.baseline
      ? {
          baseline: {
            ...(state.baseline.status !== undefined ? { status: state.baseline.status } : {}),
            ...(state.baseline.keys.length ? { topLevelKeys: state.baseline.keys } : {}),
            ...(state.baseline.sample.length
              ? { sampleNumericOrStateFields: Object.fromEntries(state.baseline.sample) }
              : {}),
          },
        }
      : {}),
    ...(state.confirmed.length
      ? {
          alreadyConfirmedDirective: 'ALREADY CONFIRMED BY FLOOR — DO NOT RE-PROVE; investigate unconfirmed routes/classes instead.',
          alreadyConfirmedOnOrigin: state.confirmed,
        }
      : {}),
    targetCount: Math.max(1, Math.min(3, Math.floor(input.targetCount ?? 1))),
    ...(input.turnBudget ? { turnBudget: Math.max(1, Math.min(30, Math.floor(input.turnBudget))) } : {}),
  }
}

function buildWorkingState(input: AssignmentBriefInput): WorkingState {
  const primaryOrigin = cleanText(input.origin.split(/[?#]/, 1)[0], 180)
  const rawPublicOrigins = [...new Set(
    (input.publicOrigins ?? [])
      .map(o => cleanText(typeof o === 'string' ? o.split(/[?#]/, 1)[0] : '', 180))
      .filter(Boolean),
  )].slice(0, 8)
  const publicOrigins = rawPublicOrigins.length > 1 ? rawPublicOrigins : []
  const routes = publicOrigins.length > 1
    ? interleaveMultiOriginRoutes(input.routes ?? [], publicOrigins, primaryOrigin, 20)
    : sortRoutes(input.routes ?? []).slice(0, 12)
  const linked = sortRoutes(input.linkedRoutes ?? []).slice(0, 8)

  const personaSeen = new Set<string>()
  const personas = (input.personas ?? [])
    .map(p => {
      const handle = cleanText(p.handle, 48)
      const harvestedIds = [...new Set((p.harvestedIds ?? []).map(cleanHarvestedId).filter(Boolean))].slice(0, 6)
      return {
        handle,
        ...(p.role ? { role: cleanText(p.role, 32) } : {}),
        harvestedIds,
      }
    })
    .filter(p => {
      if (!p.handle || personaSeen.has(p.handle)) return false
      personaSeen.add(p.handle)
      return true
    })
    .sort((a, b) => {
      if (a.harvestedIds.length !== b.harvestedIds.length) return b.harvestedIds.length - a.harvestedIds.length
      return a.handle < b.handle ? -1 : a.handle > b.handle ? 1 : 0
    })
    .slice(0, 6)

  let baseline: WorkingState['baseline']
  if (input.baseline) {
    const status = typeof input.baseline.status === 'number' && Number.isFinite(input.baseline.status)
      ? Math.trunc(input.baseline.status)
      : undefined
    const keys = [...new Set((input.baseline.topLevelKeys ?? [])
      .map(key => cleanText(key, 48))
      .filter(key => key && !SECRET_KEY_RE.test(key) && !BODY_KEY_RE.test(key)))]
      .sort()
      .slice(0, 12)
    const sample: Array<[string, string | number | boolean]> = []
    for (const [key, value] of Object.entries(input.baseline.sampleNumericOrStateFields ?? {})) {
      if (sample.length >= 10) break
      if (!key || SECRET_KEY_RE.test(key) || BODY_KEY_RE.test(key)) continue
      if (typeof value === 'number' && Number.isFinite(value)) {
        sample.push([cleanText(key, 48), value])
      } else if (typeof value === 'boolean') {
        sample.push([cleanText(key, 48), value])
      } else if (typeof value === 'string') {
        const clean = cleanText(value, 40)
        if (!clean || isSecretValue(clean) || clean.length > 40) continue
        sample.push([cleanText(key, 48), clean])
      }
    }
    sample.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    if (status !== undefined || keys.length || sample.length) baseline = { status, keys, sample }
  }

  const confirmedSeen = new Set<string>()
  const confirmed = (input.alreadyConfirmedOnOrigin ?? [])
    .map(normalizeConfirmed)
    .filter(ref => {
      const key = `${ref.method} ${ref.path} ${ref.param ?? ''} ${ref.cwe ?? ''}`
      if (confirmedSeen.has(key)) return false
      confirmedSeen.add(key)
      return true
    })
    .sort((a, b) => {
      const left = `${a.path} ${a.method}`
      const right = `${b.path} ${b.method}`
      return left < right ? -1 : left > right ? 1 : 0
    })
    .slice(0, 30)

  const codeBudget = input.codeExpansion === 'full'
    ? ASSIGNMENT_BRIEF_CODE_EXPANDED_BYTES
    : ASSIGNMENT_BRIEF_CODE_MAX_BYTES
  const code = input.codeSlice
    ? renderCodeDataflowSlice(input.codeSlice, codeBudget).slice
    : undefined
  const decoupled = input.decoupledProofPipeline ?? (process.env.KOVO_DECOUPLED_PROOF_PIPELINE === '1')
  const hopCheckpointBudget = ASSIGNMENT_BRIEF_HOP_CHECKPOINT_MAX_BYTES
  const fittedCheckpoint = input.hopCheckpoint
    ? fitHopCheckpointForBrief(input.hopCheckpoint, hopCheckpointBudget)
    : undefined
  const proofObligation = !decoupled && input.proofObligation ? normalizeProofObligation(input.proofObligation) : undefined
  const explicitMultiHop = !decoupled && isExplicitMultiHopMission(input)
  const multiHopProofContract = !decoupled && isMultiHopBriefInput(input)
    ? buildMultiHopProofContract(!explicitMultiHop, input)
    : undefined

  return {
    publicOrigins,
    routes,
    linked,
    personas,
    ...(baseline ? { baseline } : {}),
    confirmed,
    ...(input.detLead ? { detLead: normalizeDetLead(input.detLead) } : {}),
    ...(code ? { code } : {}),
    ...(fittedCheckpoint ? { hopCheckpoint: fittedCheckpoint.checkpoint } : {}),
    ...(multiHopProofContract ? { multiHopProofContract } : {}),
    multiHopContractCompacted: Boolean(multiHopProofContract && !explicitMultiHop),
    ...(proofObligation ? { proofObligation } : {}),
    ...(!decoupled ? { coverageContract: RECORD_COVERAGE_BRIEF_GUIDANCE } : {}),
    codeBudget,
    hopCheckpointBudget,
  }
}

/**
 * Render the brief plus deterministic reduction metadata.
 *
 * The reduction ladder keeps the highest-signal material longest: det_lead, hopCheckpoint,
 * multiHopProofContract, then the top route(s), then personas/confirmed refs, then baseline
 * keys/samples, then linked routes.
 */
export function buildAssignmentBriefPacket(
  input: AssignmentBriefInput,
  maxBytes?: number,
): AssignmentBriefResult {
  const defaultCap = resolveBriefDefaultCap(input)
  const cap = Math.max(128, Math.min(Math.floor(maxBytes ?? defaultCap), ASSIGNMENT_BRIEF_MAX_BYTES_WITH_CODE))
  const state = buildWorkingState(input)
  let truncated = Boolean(input.hopCheckpoint && fitHopCheckpointForBrief(input.hopCheckpoint, state.hopCheckpointBudget).truncated)

  const render = () => JSON.stringify(renderPacket(input, state))
  const fits = (text: string) => Buffer.byteLength(text, 'utf8') <= cap

  for (let guard = 0; guard < 500; guard += 1) {
    const text = render()
    if (fits(text)) {
      const bytes = assertAssignmentBriefSize(text, cap)
      return { text, bytes, truncated }
    }
    truncated = true

    if (state.coverageContract) {
      state.coverageContract = undefined
      continue
    }
    // Compact the Mode-A multi-hop proof contract before dropping linkedRoutes or shrinking
    // secondary material so follow-on hop endpoints and chain lineage coexist inside the 4 KB budget.
    if (state.multiHopProofContract && !state.multiHopContractCompacted) {
      state.multiHopProofContract = buildMultiHopProofContract(true, input)
      state.multiHopContractCompacted = true
      continue
    }

    // Secondary material first: preserve up to 2 linked routes & 2 distinct personas before shedding bulk.
    if (state.linked.length > 2) { state.linked.pop(); continue }
    const minRoutes = state.publicOrigins.length > 1 ? Math.min(state.routes.length, state.publicOrigins.length) : 1
    if (state.routes.length > minRoutes) { state.routes.pop(); continue }
    if (state.personas.length > 2) { state.personas.pop(); continue }
    if (state.baseline?.keys.length) {
      state.baseline.keys.pop()
      continue
    }
    if (state.baseline?.sample.length) {
      state.baseline.sample.pop()
      continue
    }
    if (state.confirmed.length > 1) {
      state.confirmed.pop()
      continue
    }
    const personaWithIds = [...state.personas].reverse().find(p => p.harvestedIds.length)
    if (personaWithIds) {
      personaWithIds.harvestedIds.pop()
      continue
    }
    if (state.routes[0]?.params?.length) {
      state.routes[0] = { ...state.routes[0], params: state.routes[0].params.slice(0, -1) }
      if (!state.routes[0].params?.length) delete state.routes[0].params
      continue
    }
    // The obligation is a convenience wrapper over the code slice; drop it before any byte of the
    // file:line evidence or hopCheckpoint so a tight render can never lose chain continuity.
    if (state.proofObligation) {
      state.proofObligation = undefined
      continue
    }
    // Under tight caps, drop heuristic (non-explicit) multi-hop contract before shrinking code evidence.
    if (state.multiHopProofContract && !isExplicitMultiHopMission(input)) { state.multiHopProofContract = undefined; continue }
    if (state.code && state.codeBudget > 240) {
      const nextBudget = Math.max(240, Math.floor(state.codeBudget * 0.6))
      state.code = renderCodeDataflowSlice(state.code, nextBudget).slice
      state.codeBudget = nextBudget
      continue
    }
    if (state.hopCheckpoint && input.hopCheckpoint && state.hopCheckpointBudget > 384) {
      const nextHopBudget = Math.max(384, Math.floor(state.hopCheckpointBudget * 0.65))
      state.hopCheckpoint = fitHopCheckpointForBrief(input.hopCheckpoint, nextHopBudget).checkpoint
      state.hopCheckpointBudget = nextHopBudget
      continue
    }
    // Last-resort drop of remaining linked routes / second persona only if still over cap.
    if (state.linked.length) {
      state.linked.pop(); continue
    }
    if (state.personas.length > 1) {
      state.personas.pop(); continue
    }
    if (state.code) {
      state.code = undefined
      continue
    }
    if (state.hopCheckpoint && input.hopCheckpoint && state.hopCheckpointBudget > 256) {
      state.hopCheckpoint = fitHopCheckpointForBrief(input.hopCheckpoint, 256).checkpoint
      state.hopCheckpointBudget = 256
      continue
    }
    if (state.multiHopProofContract) {
      state.multiHopProofContract = undefined
      continue
    }
    if (state.detLead && typeof state.detLead.signalSummary === 'string' && state.detLead.signalSummary.length > 60) {
      state.detLead = {
        ...state.detLead,
        signalSummary: truncateUtf8Head(state.detLead.signalSummary, Math.max(60, Math.floor(state.detLead.signalSummary.length * 0.6))),
      }
      continue
    }
    if (state.detLead?.verifyFailureReason) {
      const { verifyFailureReason: _drop, ...rest } = state.detLead
      state.detLead = rest
      continue
    }
    if (state.baseline) {
      if (state.baseline.sample.length) {
        state.baseline.sample.pop()
      } else if (state.baseline.keys.length) {
        state.baseline.keys.pop()
      } else {
        state.baseline = undefined
      }
      continue
    }
    if (state.confirmed.length) {
      state.confirmed.pop()
      continue
    }
    if (state.personas.length) {
      state.personas.pop()
      continue
    }
    if (state.detLead) {
      state.detLead = undefined
      continue
    }
    if (state.routes.length) {
      state.routes.pop()
      continue
    }
    if (state.hopCheckpoint) {
      state.hopCheckpoint = undefined
      continue
    }
    if (state.publicOrigins.length) { state.publicOrigins = []; continue }

    // Guaranteed-under-cap fallback (mission + bounded origin only).
    const minimal = JSON.stringify({
      mission: input.missionKind,
      origin: cleanText(input.origin.split(/[?#]/, 1)[0], 120),
      targetCount: Math.max(1, Math.min(3, Math.floor(input.targetCount ?? 1))),
    })
    assertAssignmentBriefSize(minimal, cap)
    return { text: minimal, bytes: Buffer.byteLength(minimal, 'utf8'), truncated: true }
  }

  const minimal = JSON.stringify({ mission: input.missionKind, origin: cleanText(input.origin.split(/[?#]/, 1)[0], 120) })
  assertAssignmentBriefSize(minimal, cap)
  return { text: minimal, bytes: Buffer.byteLength(minimal, 'utf8'), truncated: true }
}

/** Render the compact packet as JSON text (always <= {@link ASSIGNMENT_BRIEF_MAX_BYTES} unless expanded). */
export function buildAssignmentBrief(input: AssignmentBriefInput, maxBytes?: number): string {
  return buildAssignmentBriefPacket(input, maxBytes).text
}

/** Measure a rendered brief in UTF-8 bytes. */
export function measureAssignmentBriefBytes(text: string): number {
  return Buffer.byteLength(text, 'utf8')
}

/**
 * Assert a rendered brief stays inside its byte cap. The reduction ladder already guarantees this;
 * the assertion turns a future rendering regression into a loud failure instead of silent bloat.
 */
export function assertAssignmentBriefSize(text: string, maxBytes = ASSIGNMENT_BRIEF_MAX_BYTES): number {
  const bytes = measureAssignmentBriefBytes(text)
  if (bytes > maxBytes) {
    throw new RangeError(`assignment brief exceeds ${maxBytes} bytes (rendered ${bytes} bytes)`)
  }
  return bytes
}

/**
 * One explicit settlement-phase proof line: the target route+method+param and the smallest valid
 * replay spec that would prove it. Appended to the settlement nudge/banner (never the byte-capped
 * assignment packet) so the reserved wrap-up turn has a concrete, copyable obligation.
 *
 * Pure: parameter names only, no values, no bodies, no secrets.
 */
export function renderSettlementSpecDirective(
  target: SettlementSpecTarget | undefined,
  specShape: string,
  proofGapCodes: readonly string[],
): string {
  const method = (target?.method || 'GET').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10) || 'GET'
  const path = cleanPath(target?.path ?? '/')
  const params = [...new Set((target?.params ?? []).map(cleanParamName).filter(Boolean))].slice(0, 4)
  const paramText = params.length ? ` param=${params.join('|')}` : ''
  const origin = target?.origin ? cleanText(target.origin.split(/[?#]/, 1)[0], 120) : ''
  const route = `${method} ${path}${paramText}${origin ? ` on ${origin}` : ''}`
  const codes = proofGapCodes.map(code => cleanText(code, 40)).filter(Boolean).slice(0, 8).join(', ')
  return [
    `[PROOF OBLIGATION — settlement] Your route evidence is ${route}.`,
    'This wrap-up turn is reserved: submit ONE kovo_verify inline script (ctx.prove_*) or replay spec for that route before complete_intent.',
    `Smallest valid spec: ${specShape}`,
    `If no valid spec can be built, call record_coverage(status="needs_follow_up", proofGapReason="<code>") with a machine-readable code (${codes}) instead of silently skipping. ${RECORD_COVERAGE_BRIEF_GUIDANCE}`,
  ].join(' ')
}

