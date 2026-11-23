/**
 * Assignment evidence brief (v5.1 agentic throughput).
 *
 * The agentic layer is throughput-starved: a specialist that spends its first turns rediscovering
 * routes/personas/baselines cannot spend them probing. This module renders a deliberately tiny,
 * deterministic packet (<= 1.5 KB) from data the session already has, so turn 1 can probe.
 *
 * Invariants:
 *  - Pure: no I/O, no clock, no randomness.
 *  - Deterministic ordering: highest-signal material first, stable tie-breakers.
 *  - Hard byte cap: the returned text is always valid JSON and never exceeds
 *    {@link ASSIGNMENT_BRIEF_MAX_BYTES}; reduction is a fixed ladder, not a blind slice.
 *  - No secrets or response bodies: only names, status codes, top-level keys, and short scalar
 *    state/numeric samples. Secret-shaped keys/values and body-like fields are dropped.
 */

export const ASSIGNMENT_BRIEF_MAX_BYTES = 1536

export type MissionKind =
  | 'det_lead_upgrade'
  | 'workflow_skip'
  | 'business_logic'
  | 'chain_step_2'
  | 'second_order'
  | 'class_scan'

export interface AssignmentBriefRoute {
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
}

export interface AssignmentBriefDetLead {
  probeClass: string
  exchangeId?: string | null
  signalSummary: string
  verifyFailureReason?: string | null
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
  /** 1 hypothesis cluster (1-3 linked routes) or 1 det_lead, by default. */
  targetCount?: number
  turnBudget?: number
}

export interface AssignmentBriefResult {
  text: string
  bytes: number
  truncated: boolean
}

const SECRET_KEY_RE = /(?:secret|token|passw|pwd|api[_-]?key|authorization|cookie|session|jwt|bearer|credential|private[_-]?key|client[_-]?secret)/i
const BODY_KEY_RE = /(?:body|content|html|snippet|payload|response|raw|markup|text)/i
const SECRET_VALUE_RE = /^(?:bearer\s+)?[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$|^(?:sk|pk|ghp|gho|ghs|xox[baprs])_[A-Za-z0-9_-]{10,}$/i
const JWT_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g
const BEARER_RE = /(bearer\s+)[A-Za-z0-9._~+/=-]{12,}/gi
const NAMED_SECRET_RE = /((?:secret|token|password|passwd|api[_-]?key|access[_-]?key)=)[^\s&"']+/gi
const KEY_PREFIX_RE = /\b(?:sk|pk|ghp|gho|ghs|xox[baprs])_[A-Za-z0-9_-]{10,}/g

function cleanText(value: unknown, maxBytes: number): string {
  if (typeof value !== 'string') return ''
  const flattened = value.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim()
  return truncateUtf8Head(flattened, maxBytes)
}

/** Remove token-shaped fragments and body-like key/value pairs from free text. */
export function redactBriefText(value: unknown, maxBytes = 200): string {
  let text = cleanText(value, maxBytes * 2)
  if (!text) return ''
  text = text
    .replace(JWT_RE, '[redacted-jwt]')
    .replace(BEARER_RE, '$1[redacted]')
    .replace(KEY_PREFIX_RE, '[redacted]')
    .replace(NAMED_SECRET_RE, '$1[redacted]')
    .replace(/\b(?:body|html|content)\s*[:=]\s*[^\s]+/gi, '[body omitted]')
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
  return value.trim().replace(/[^A-Za-z0-9_.:[\]-]/g, '').slice(0, 48)
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
  const params = [...new Set((route.params ?? []).map(cleanParamName).filter(Boolean))].slice(0, 8)
  const encoding = cleanEncoding(route.encoding)
  return {
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
    const key = `${next.method} ${next.path} ${(next.params ?? []).join(',')}`
    if (seen.has(key)) continue
    seen.add(key)
    normalized.push(next)
  }
  return normalized.sort((a, b) => {
    const signal = routeSignal(b) - routeSignal(a)
    if (signal !== 0) return signal
    if (a.path !== b.path) return a.path < b.path ? -1 : 1
    return a.method < b.method ? -1 : a.method > b.method ? 1 : 0
  })
}

function normalizeConfirmed(ref: AssignmentBriefConfirmedRef): Record<string, unknown> {
  const param = cleanParamName(ref.param ?? '')
  const cwe = typeof ref.cwe === 'string' ? ref.cwe.trim().replace(/[^A-Za-z0-9-]/g, '').slice(0, 24) : ''
  return {
    method: (ref.method || 'GET').toUpperCase().replace(/[^A-Z]/g, '').slice(0, 10) || 'GET',
    path: cleanPath(ref.path),
    ...(param ? { param } : {}),
    ...(cwe ? { cwe } : {}),
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

interface WorkingState {
  routes: AssignmentBriefRoute[]
  linked: AssignmentBriefRoute[]
  personas: Array<{ handle: string; role?: string; harvestedIds: string[] }>
  baseline?: { status?: number; keys: string[]; sample: Array<[string, string | number | boolean]> }
  confirmed: Array<Record<string, unknown>>
  detLead?: Record<string, unknown>
}

function renderPacket(input: AssignmentBriefInput, state: WorkingState): Record<string, unknown> {
  return {
    mission: input.missionKind,
    origin: cleanText(input.origin.split(/[?#]/, 1)[0], 180),
    ...(state.detLead ? { detLead: state.detLead } : {}),
    routes: state.routes,
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
    ...(state.confirmed.length ? { alreadyConfirmedOnOrigin: state.confirmed } : {}),
    targetCount: Math.max(1, Math.min(3, Math.floor(input.targetCount ?? 1))),
    ...(input.turnBudget ? { turnBudget: Math.max(1, Math.min(30, Math.floor(input.turnBudget))) } : {}),
  }
}

function buildWorkingState(input: AssignmentBriefInput): WorkingState {
  const routes = sortRoutes(input.routes ?? []).slice(0, 12)
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
    .slice(0, 10)

  return {
    routes,
    linked,
    personas,
    ...(baseline ? { baseline } : {}),
    confirmed,
    ...(input.detLead ? { detLead: normalizeDetLead(input.detLead) } : {}),
  }
}

/**
 * Render the brief plus deterministic reduction metadata.
 *
 * The reduction ladder keeps the highest-signal material longest: det_lead, then the top route(s),
 * then personas/confirmed refs, then baseline keys/samples, then linked routes (secondary).
 */
export function buildAssignmentBriefPacket(
  input: AssignmentBriefInput,
  maxBytes = ASSIGNMENT_BRIEF_MAX_BYTES,
): AssignmentBriefResult {
  const cap = Math.max(128, Math.floor(maxBytes))
  const state = buildWorkingState(input)
  let truncated = false

  const render = () => JSON.stringify(renderPacket(input, state))
  const fits = (text: string) => Buffer.byteLength(text, 'utf8') <= cap

  for (let guard = 0; guard < 500; guard += 1) {
    const text = render()
    if (fits(text)) {
      const bytes = assertAssignmentBriefSize(text, cap)
      return { text, bytes, truncated }
    }
    truncated = true

    // Secondary material first.
    if (state.linked.length) {
      state.linked.pop()
      continue
    }
    if (state.routes.length > 1) {
      state.routes.pop()
      continue
    }
    if (state.personas.length > 1) {
      state.personas.pop()
      continue
    }
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
    if (state.personas[0]?.harvestedIds.length) {
      state.personas[0].harvestedIds.pop()
      continue
    }
    if (state.routes[0]?.params?.length) {
      state.routes[0] = { ...state.routes[0], params: state.routes[0].params.slice(0, -1) }
      if (!state.routes[0].params?.length) delete state.routes[0].params
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

/** Render the compact packet as JSON text (always <= {@link ASSIGNMENT_BRIEF_MAX_BYTES}). */
export function buildAssignmentBrief(input: AssignmentBriefInput, maxBytes = ASSIGNMENT_BRIEF_MAX_BYTES): string {
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
