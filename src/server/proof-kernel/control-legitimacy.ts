/**
 * Proof Kernel — Single Control-Legitimacy Stage (`R3-17`, consolidating `R4-H-7` / `H-14` / `C-4`).
 *
 * Driven directly by each registered `OracleSpec`'s declarative control contract
 * (`{ role, differsOnlyIn, mustBe }`) so EVERY oracle declaring a denied control executes
 * `assertLegitimateControl()` before confirmation:
 *   - Rejects self-sabotaged controls (synthetic invalid credentials `kovo-synth-invalid-*` or
 *     `wireCredentialProvenance.authMutated`, control-only auth headers/cookies/persona/session jar).
 *   - Rejects host-credential escalation on `denied_unauthenticated` pairs (vault persona,
 *     higher role, sealed capabilities, session jar/cookies, login-issued prior tokens).
 *   - Enforces bare anonymous ablation checks on unauthenticated auth-bypass proofs.
 *   - Preserves legitimate temporal differences for `v8:temporal_revocation`
 *     (`differsOnlyIn: ['time_after_revocation']`) and legitimate signature tampering for
 *     `webhook` / `v8:cryptographic_scope_replay` (`role: 'denied_tampered'`).
 */

import type { OracleControlContract, OracleSpec, V8OracleFamilyId } from '../oracle-spec.ts'
import type { WireCredentialProvenance } from '../host-fact-log.ts'
import type { ImpactStep, RoleName } from '../oracle-invariants.ts'
import type { HydratableEntry, HydratableTranscriptIndex } from '../v8-oracle-hydrate.ts'
import { AUTH_OR_BYPASS_HEADER_RE, normalizeRequestCarrier } from './reflection.ts'

export interface ControlLegitimacyExchange {
  readonly id: string
  readonly method?: string | null
  readonly route?: string | null
  readonly pathAndQuery?: string | null
  readonly status?: number | null
  readonly actorHandle?: string | null
  readonly actorRole?: string | null
  readonly actorAuth?: string | null
  readonly sessionId?: string | null
  readonly consumedCapabilityId?: string | null
  readonly consumedCapabilities?: readonly string[]
  readonly requestHeaders?: Readonly<Record<string, string>> | null
  readonly responseHeaders?: Readonly<Record<string, string>> | null
  readonly requestJson?: unknown
  readonly body?: string | null
  readonly json?: unknown
  readonly timestampMs?: number
  readonly wireCredentialProvenance?: Readonly<WireCredentialProvenance> | null
}

export interface ControlLegitimacyInput {
  readonly spec: OracleSpec
  readonly control: ControlLegitimacyExchange
  readonly probe?: ControlLegitimacyExchange | null
  /** Optional full transcript entries for prior login-token and anonymous ablation checks. */
  readonly allEntries?: readonly ControlLegitimacyExchange[]
  /** Optional explicit boundary class override (e.g. `evaluateBoundaryClaim`). */
  readonly boundaryClass?: 'auth' | 'access' | 'mfa' | 'other'
  /** Whether to run the bare anonymous ablation requirement (default: true for `auth_bypass`). */
  readonly requireAnonymousAblation?: boolean
}

export interface ControlLegitimacyResult {
  readonly ok: boolean
  readonly executed: boolean
  readonly specId: string
  readonly contractRole: string | null
  readonly rejectedBy: string | null
  readonly reason: string
}

const BOUNDARY_CREDENTIAL_HEADER_RE = /^(?:authorization|proxy-authorization|cookie|x-api-key|x-auth.*)$/i
const AUTH_BYPASS_PARAM_KEY_RE = /^(?:token|jwt|auth|access_token|id_token|api_key|apikey|key|session|session_id|sid|role|admin|is_admin|user|user_id|uid|bypass|debug|impersonate|as_user|override)$/i
const TENANT_OR_PRINCIPAL_PARAM_RE = /^(?:tenant|tenant_?id|org|org_?id|account|account_?id|workspace|workspace_?id|user|user_?id|owner|owner_?id|actor|actor_?id|principal)$/i
const ROLE_PARAM_RE = /^(?:role|roles|scope)$/i
const SIG_OR_SCOPE_PARAM_RE = /^(?:sig|signature|hmac|mac|x-amz-signature|x-goog-signature|scope|aud|audience|exp|expires|token|jwt)$/i
const ROUTE_COLLECTION_SEGMENT_RE = /^(?:tenants|orgs|organizations|users|accounts|workspaces|projects|teams|buckets|repos|customers|clients|members)$/i
const ROUTE_STATIC_ACTION_RE = /^(?:admin|settings|me|public|health|status|list|search|export|import|batch|create|new|login|logout|auth)$/i
const SYNTH_INVALID_CRED_RE = /kovo-synth-invalid-/i
const SEALED_OR_VAULT_MARKER_RE = /\[(?:redacted:cap|persona:[^\]]+:secret)\]/i
const ROLE_RANK_MAP: Readonly<Record<string, number>> = {
  viewer: 0,
  member: 1,
  admin: 2,
  owner: 3,
}

function normalizedAuthHandle(handle: string | null | undefined): string | null {
  const trimmed = (handle ?? '').trim().toLowerCase()
  if (!trimmed || /^(?:anonymous|anon|unauthenticated|none|public)$/.test(trimmed)) return null
  return trimmed
}

function authRoleRank(role: string | null | undefined): number {
  const lower = (role ?? '').trim().toLowerCase()
  return lower in ROLE_RANK_MAP ? ROLE_RANK_MAP[lower]! : -1
}

function canonicalHeaderMap(headers: Readonly<Record<string, string>> | null | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers ?? {})) {
    const lk = k.trim().toLowerCase()
    if (lk && typeof v === 'string') out[lk] = v.trim()
  }
  return out
}

function normalizeRoutePath(value: string | null | undefined): string {
  return (value ?? '').split('?')[0]!.split('#')[0]!.replace(/\/+$/, '').toLowerCase()
}

function isDynamicPathSegment(seg: string, prevSeg: string): boolean {
  if (/^v\d+$/i.test(seg)) return false
  if (/^\d+$/.test(seg)) return true
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return true
  if (/^[0-9a-f]{16,}$/i.test(seg)) return true
  if (/^[a-z0-9]+(?:[-_][a-z0-9]+)+$/i.test(seg) && /\d/.test(seg)) return true
  if (/^[a-z]{1,8}\d+$/i.test(seg)) return true
  if (ROUTE_COLLECTION_SEGMENT_RE.test(prevSeg) && !ROUTE_STATIC_ACTION_RE.test(seg)) return true
  return false
}

function normalizeRouteTemplate(value: string | null | undefined): string {
  const path = normalizeRoutePath(value)
  if (!path) return ''
  const parts = path.split('/').filter(Boolean)
  const out: string[] = []
  for (let i = 0; i < parts.length; i += 1) {
    const seg = parts[i]!
    const prev = i > 0 ? parts[i - 1]! : ''
    out.push(isDynamicPathSegment(seg, prev) ? ':id' : seg)
  }
  return `/${out.join('/')}`
}

function extractRawQueryKeys(pathAndQuery: string | null | undefined): Set<string> {
  const keys = new Set<string>()
  if (!pathAndQuery) return keys
  const qIdx = pathAndQuery.indexOf('?')
  if (qIdx < 0) return keys
  const raw = pathAndQuery.slice(qIdx + 1).split('#')[0] ?? ''
  for (const pair of raw.split('&')) {
    if (!pair) continue
    const eq = pair.indexOf('=')
    const rawKey = (eq >= 0 ? pair.slice(0, eq) : pair).trim().toLowerCase()
    if (rawKey) keys.add(rawKey)
  }
  return keys
}

function extractTopLevelBodyKeys(requestJson: unknown): { hasBody: boolean; keys: Set<string> } {
  if (requestJson === undefined || requestJson === null || requestJson === '') {
    return { hasBody: false, keys: new Set() }
  }
  let parsed: unknown = requestJson
  if (typeof requestJson === 'string') {
    const trimmed = requestJson.trim()
    if (!trimmed) return { hasBody: false, keys: new Set() }
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      return { hasBody: true, keys: new Set() }
    }
  }
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const keys = new Set(Object.keys(parsed as Record<string, unknown>).map(k => k.trim().toLowerCase()))
    return { hasBody: keys.size > 0, keys }
  }
  return { hasBody: true, keys: new Set() }
}

function parseQueryMap(pathAndQuery: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!pathAndQuery) return out
  const qIdx = pathAndQuery.indexOf('?')
  if (qIdx < 0) return out
  const raw = pathAndQuery.slice(qIdx + 1).split('#')[0] ?? ''
  for (const [k, v] of new URLSearchParams(raw).entries()) {
    out[k.trim().toLowerCase()] = v
  }
  return out
}

function collectBodyEntries(value: unknown, prefix = '', depth = 0, out: Record<string, string> = {}): Record<string, string> {
  if (depth > 4 || value === null || value === undefined) return out
  if (typeof value === 'string') {
    if (prefix) out[prefix.toLowerCase()] = value
    return out
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    if (prefix) out[prefix.toLowerCase()] = String(value)
    return out
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < Math.min(value.length, 16); i += 1) {
      collectBodyEntries(value[i], `${prefix}[${i}]`, depth + 1, out)
    }
    return out
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      collectBodyEntries(v, prefix ? `${prefix}.${k}` : k, depth + 1, out)
    }
  }
  return out
}

function is2xxStatus(status: number | null | undefined): boolean {
  return typeof status === 'number' && status >= 200 && status < 300
}

/** Convert a host transcript entry (`ReceiptTranscriptEntry` / `HostSignedTranscriptEntry`) into a `ControlLegitimacyExchange`. */
export function transcriptEntryToControlExchange(entry: {
  exchangeId: string
  sessionId?: string | null
  consumedCapabilityId?: string | null
  consumedCapabilities?: readonly string[]
  wireCredentialProvenance?: Readonly<WireCredentialProvenance> | null
  timestampMs?: number
  step: {
    method: string
    route?: string
    pathAndQuery?: string
    status: number | null
    actor: { handle?: string | null; role?: string | null; auth?: string }
    requestHeaders?: Readonly<Record<string, string>> | null
    responseHeaders?: Readonly<Record<string, string>> | null
    requestJson?: unknown
    body?: string
    json?: unknown
  }
}): ControlLegitimacyExchange {
  return {
    id: entry.exchangeId,
    method: entry.step.method,
    route: entry.step.route ?? entry.step.pathAndQuery ?? null,
    pathAndQuery: entry.step.pathAndQuery ?? entry.step.route ?? null,
    status: entry.step.status,
    actorHandle: entry.step.actor.handle ?? null,
    actorRole: entry.step.actor.role ?? null,
    actorAuth: entry.step.actor.auth ?? null,
    sessionId: entry.sessionId ?? null,
    consumedCapabilityId: entry.consumedCapabilityId ?? null,
    consumedCapabilities: entry.consumedCapabilities,
    requestHeaders: entry.step.requestHeaders ?? null,
    responseHeaders: entry.step.responseHeaders ?? null,
    requestJson: entry.step.requestJson,
    body: entry.step.body ?? null,
    json: entry.step.json,
    ...(entry.timestampMs !== undefined ? { timestampMs: entry.timestampMs } : {}),
    wireCredentialProvenance: entry.wireCredentialProvenance ?? null,
  }
}

/** Convert an `ImpactStep` (with optional host wire credential provenance) into a `ControlLegitimacyExchange`. */
export function impactStepToControlExchange(
  step: {
    id: string
    method: string
    route?: string
    pathAndQuery?: string
    status: number | null
    actor: { handle: string | null; role: string | null; auth: string }
    requestHeaders?: Readonly<Record<string, string>> | null
    responseHeaders?: Readonly<Record<string, string>> | null
    requestJson?: unknown
    body?: string
    json?: unknown
  },
  wireCredentialProvenance?: Readonly<WireCredentialProvenance> | null,
): ControlLegitimacyExchange {
  return {
    id: step.id,
    method: step.method,
    route: step.route ?? step.pathAndQuery ?? null,
    pathAndQuery: step.pathAndQuery ?? step.route ?? null,
    status: step.status,
    actorHandle: step.actor.handle,
    actorRole: step.actor.role,
    actorAuth: step.actor.auth,
    requestHeaders: step.requestHeaders ?? null,
    responseHeaders: step.responseHeaders ?? null,
    requestJson: step.requestJson,
    body: step.body ?? null,
    json: step.json,
    wireCredentialProvenance: wireCredentialProvenance ?? null,
  }
}

/** Return the first denied-control contract declared on an `OracleSpec`, if any. */
export function selectDeniedControlContract(spec: OracleSpec): OracleControlContract | null {
  for (const ctl of spec.controls) {
    const c = ctl.contract
    if (c && (c.mustBe === 'denied_401_or_403' || c.mustBe === 'denied_4xx')) {
      return c
    }
  }
  return null
}

/** True when an `OracleSpec` declares a denied negative-control contract. */
export function specDeclaresDeniedControl(spec: OracleSpec): boolean {
  return selectDeniedControlContract(spec) !== null
}

/** True when `entry` is a bare unauthenticated request with zero auth headers, cookies, or bypass params on `method + route`. */
export function isBareAnonymousAblationExchange(
  entry: ControlLegitimacyExchange,
  targetMethod: string,
  targetRoute: string,
): boolean {
  if ((entry.method ?? '').toUpperCase() !== targetMethod.toUpperCase()) return false
  if (normalizeRoutePath(entry.route ?? entry.pathAndQuery) !== normalizeRoutePath(targetRoute)) return false
  if (normalizedAuthHandle(entry.actorHandle) !== null) return false
  if (entry.sessionId || entry.consumedCapabilityId || (entry.consumedCapabilities && entry.consumedCapabilities.length > 0)) {
    return false
  }
  const wp = entry.wireCredentialProvenance
  if (wp && (
    wp.authenticated ||
    wp.authMutated ||
    wp.session ||
    wp.sources.length > 0 ||
    wp.headerNames.length > 0 ||
    wp.callerAuthHeaderNames.length > 0 ||
    wp.vaultHeaderNames.length > 0 ||
    wp.cookieNames.length > 0
  )) {
    return false
  }
  const h = canonicalHeaderMap(entry.requestHeaders)
  if (h.cookie) return false
  for (const [k, v] of Object.entries(h)) {
    if (AUTH_OR_BYPASS_HEADER_RE.test(k) && v.length > 0) return false
  }
  for (const [k, v] of Object.entries(parseQueryMap(entry.pathAndQuery))) {
    if (AUTH_BYPASS_PARAM_KEY_RE.test(k) && v.trim().length > 0) return false
  }
  for (const [k, v] of Object.entries(collectBodyEntries(entry.requestJson))) {
    const leaf = k.split('.').pop()?.replace(/\[\d+\]$/, '') ?? ''
    if (AUTH_BYPASS_PARAM_KEY_RE.test(leaf) && v.trim().length > 0) return false
  }
  return true
}

function checkProbeHostCredentialEscalation(
  control: ControlLegitimacyExchange,
  probe: ControlLegitimacyExchange,
  allEntries: readonly ControlLegitimacyExchange[],
): string | null {
  const ctlHandle = normalizedAuthHandle(control.actorHandle)
  const prbHandle = normalizedAuthHandle(probe.actorHandle)
  if (prbHandle !== null && prbHandle !== ctlHandle) {
    if (ctlHandle === null) {
      return `Normal authenticated persona "${probe.actorHandle}" crossing an unauthenticated 401 is standard login, not an authentication bypass.`
    }
    return `Auth bypass rejected: probe used a different authenticated persona ("${probe.actorHandle}" vs control "${control.actorHandle}"); switching personas is not an authentication bypass.`
  }
  if (authRoleRank(probe.actorRole) > authRoleRank(control.actorRole)) {
    return `Auth bypass rejected: probe carried higher role privileges ("${probe.actorRole}" vs control "${control.actorRole ?? 'none'}"); normal RBAC is not an authentication bypass.`
  }
  const ctlCaps = new Set<string>([
    ...(control.consumedCapabilityId ? [control.consumedCapabilityId] : []),
    ...(control.consumedCapabilities ?? []),
  ])
  const prbCaps = [
    ...(probe.consumedCapabilityId ? [probe.consumedCapabilityId] : []),
    ...(probe.consumedCapabilities ?? []),
  ]
  if (prbCaps.some(cap => !ctlCaps.has(cap))) {
    return 'Auth bypass rejected: probe carried a host-sealed capability that the control lacked (authenticated session reuse is not an authentication bypass).'
  }
  const ctlHeaders = canonicalHeaderMap(control.requestHeaders)
  const prbHeaders = canonicalHeaderMap(probe.requestHeaders)
  for (const [k, v] of Object.entries(prbHeaders)) {
    if (SEALED_OR_VAULT_MARKER_RE.test(v) && ctlHeaders[k] !== v) {
      return 'Auth bypass rejected: probe carried a sealed capability or vault credential header that the control lacked.'
    }
  }
  if (prbHeaders.cookie && prbHeaders.cookie !== ctlHeaders.cookie) {
    return 'Auth bypass rejected: probe carried a session cookie that the control lacked (session-jar authentication is not an authentication bypass).'
  }
  const ctlSessionId = control.sessionId ?? control.wireCredentialProvenance?.session ?? null
  const prbSessionId = probe.sessionId ?? probe.wireCredentialProvenance?.session ?? null
  if (prbSessionId && prbSessionId !== ctlSessionId) {
    return 'Auth bypass rejected: probe used an authenticated session jar that the control lacked.'
  }

  const ctlWire = control.wireCredentialProvenance
  const prbWire = probe.wireCredentialProvenance
  if (prbWire) {
    const ctlSources = new Set(ctlWire?.sources ?? [])
    const ctlVaultHeaders = new Set((ctlWire?.vaultHeaderNames ?? []).map(h => h.toLowerCase()))
    const ctlVaultCookies = new Set((ctlWire?.vaultCookieNames ?? []).map(c => c.toLowerCase()))
    const ctlJarCookies = new Set((ctlWire?.jarCookieNames ?? []).map(c => c.toLowerCase()))
    const ctlWireCookies = new Set((ctlWire?.cookieNames ?? []).map(c => c.toLowerCase()))
    const prbWireHandle = normalizedAuthHandle(prbWire.personaHandle)
    const ctlWireHandle = normalizedAuthHandle(ctlWire?.personaHandle ?? control.actorHandle)
    if (prbWire.sources.includes('persona_vault') || prbWire.vaultHeaderNames.length > 0 || prbWire.vaultCookieNames.length > 0 || prbWireHandle !== null) {
      if (!ctlSources.has('persona_vault') || (prbWireHandle !== null && prbWireHandle !== ctlWireHandle) ||
          prbWire.vaultHeaderNames.some(h => !ctlVaultHeaders.has(h.toLowerCase())) ||
          prbWire.vaultCookieNames.some(c => !ctlVaultCookies.has(c.toLowerCase()))) {
        return 'Auth bypass rejected: wire credential provenance shows probe carried host persona-vault credentials that the control lacked (normal authentication is not an authentication bypass).'
      }
    }
    if (prbWire.sources.includes('session_jar') || prbWire.jarCookieNames.length > 0 || prbWire.session) {
      if ((prbWire.session && prbWire.session !== ctlSessionId) ||
          prbWire.jarCookieNames.some(c => !ctlJarCookies.has(c.toLowerCase())) ||
          (prbWire.sources.includes('session_jar') && !ctlSources.has('session_jar'))) {
        return 'Auth bypass rejected: wire credential provenance shows probe carried session-jar credentials that the control lacked (session-jar authentication is not an authentication bypass).'
      }
    }
    if (prbWire.sources.includes('ephemeral_observed') && !ctlSources.has('ephemeral_observed')) {
      return 'Auth bypass rejected: wire credential provenance shows probe replayed host-observed ephemeral credentials that the control lacked.'
    }
    if (prbWire.cookieNames.some(c => !ctlWireCookies.has(c.toLowerCase()))) {
      return 'Auth bypass rejected: wire credential provenance shows probe transmitted cookie(s) on the wire that the control lacked.'
    }
  }

  return checkPriorIssuedLoginToken(control, probe, ctlHeaders, prbHeaders, allEntries)
}

function checkPriorIssuedLoginToken(
  control: ControlLegitimacyExchange,
  probe: ControlLegitimacyExchange,
  ctlHeaders: Record<string, string>,
  prbHeaders: Record<string, string>,
  allEntries: readonly ControlLegitimacyExchange[],
): string | null {
  if (allEntries.length === 0) return null
  const candidateTokens = new Set<string>()
  const addCandidate = (raw: string | undefined) => {
    if (!raw) return
    const stripped = raw.replace(/^(?:Bearer|Token|Basic|ApiKey)\s+/i, '').trim()
    if (stripped.length >= 12) candidateTokens.add(stripped)
  }
  for (const [k, v] of Object.entries(prbHeaders)) {
    if (k === 'cookie' || !AUTH_OR_BYPASS_HEADER_RE.test(k)) continue
    if (v !== ctlHeaders[k]) addCandidate(v)
  }
  const ctlQuery = parseQueryMap(control.pathAndQuery)
  for (const [k, v] of Object.entries(parseQueryMap(probe.pathAndQuery))) {
    if (v !== ctlQuery[k]) addCandidate(v)
  }
  const ctlBody = collectBodyEntries(control.requestJson)
  for (const [k, v] of Object.entries(collectBodyEntries(probe.requestJson))) {
    if (v !== ctlBody[k]) addCandidate(v)
  }
  if (candidateTokens.size === 0) return null
  for (const prior of allEntries) {
    if (prior.id === probe.id || prior.id === control.id) continue
    if (!is2xxStatus(prior.status)) continue
    const priorBody = typeof prior.body === 'string'
      ? prior.body
      : prior.json !== undefined ? JSON.stringify(prior.json) : ''
    const priorRespHeaders = Object.values(prior.responseHeaders ?? {}).join('\n')
    for (const rawToken of candidateTokens) {
      if (priorBody.includes(rawToken) || priorRespHeaders.includes(rawToken)) {
        return 'Auth bypass rejected: probe used a credential issued by a prior 2xx login/token exchange in the host transcript (normal authentication, not a bypass).'
      }
    }
  }
  return null
}

function isAllowedExtraControlKey(key: string, allowed: ReadonlySet<string>): boolean {
  if (allowed.has('signature_or_scope') && SIG_OR_SCOPE_PARAM_RE.test(key)) return true
  if (allowed.has('persona_or_tenant') && TENANT_OR_PRINCIPAL_PARAM_RE.test(key)) return true
  if (allowed.has('role_privilege') && ROLE_PARAM_RE.test(key)) return true
  return false
}

/**
 * Enforce declarative `contract.differsOnlyIn` request-shape parity between a denied control
 * and the probe (`R3-17` B1): compares encoding validity, HTTP method, normalized route,
 * query keys, and body shape, allowing ONLY dimensions declared in `contract.differsOnlyIn`.
 */
function checkControlContractParity(
  control: ControlLegitimacyExchange,
  probe: ControlLegitimacyExchange | null | undefined,
  contract: OracleControlContract,
): string | null {
  const ctlCarrier = normalizeRequestCarrier({
    pathAndQuery: control.pathAndQuery ?? control.route ?? null,
    requestJson: control.requestJson,
    requestHeaders: control.requestHeaders ?? null,
  }, { strictJson: true })
  const prbCarrier = probe ? normalizeRequestCarrier({
    pathAndQuery: probe.pathAndQuery ?? probe.route ?? null,
    requestJson: probe.requestJson,
    requestHeaders: probe.requestHeaders ?? null,
  }, { strictJson: true }) : null
  if (ctlCarrier.malformedEscape && !(prbCarrier?.malformedEscape)) {
    return `Control legitimacy rejected (R3-17): control carries malformed request encoding/JSON (${ctlCarrier.malformedReason ?? 'malformed_carrier'}) absent from the probe (self-sabotaged control).`
  }

  const isDeniedStatus = typeof control.status === 'number' && control.status >= 400 && control.status < 500
  if (!probe || !isDeniedStatus) return null

  const allowed = new Set<string>(contract.differsOnlyIn)
  const allowsArbitraryShape = allowed.has('request_payload') || allowed.has('time_after_revocation')

  // 1. HTTP method parity
  //    On `denied_unauthorized` mutating write proofs (PATCH/POST/PUT/DELETE), a denied GET/HEAD
  //    read/publicness probe (401/403/404/405) on the same resource (or parent resource prefix) is
  //    legitimate pre-write / non-publicness evidence synthesized for mutating endpoints.
  const ctlMethod = (control.method ?? '').trim().toUpperCase()
  const prbMethod = (probe.method ?? '').trim().toUpperCase()
  const isLegitDeniedReadForMutatingProbe =
    contract.role === 'denied_unauthorized' &&
    (control.status === 401 || control.status === 403 || control.status === 404 || control.status === 405) &&
    (ctlMethod === 'GET' || ctlMethod === 'HEAD') &&
    (prbMethod === 'POST' || prbMethod === 'PUT' || prbMethod === 'PATCH' || prbMethod === 'DELETE')
  if (!allowsArbitraryShape && ctlMethod && prbMethod && ctlMethod !== prbMethod && !isLegitDeniedReadForMutatingProbe) {
    return `Control legitimacy rejected (R3-17): denied control method "${ctlMethod}" differs from probe method "${prbMethod}", which is outside contract.differsOnlyIn (${contract.differsOnlyIn.join(', ')}).`
  }

  // 2. Normalized route parity (exact route for denied_unauthenticated; template parity for denied_unauthorized/denied_tampered)
  const ctlRouteRaw = control.route ?? control.pathAndQuery
  const prbRouteRaw = probe.route ?? probe.pathAndQuery
  if (!allowsArbitraryShape && ctlRouteRaw && prbRouteRaw) {
    const ctlRoute = contract.role === 'denied_unauthenticated'
      ? normalizeRoutePath(ctlRouteRaw)
      : normalizeRouteTemplate(ctlRouteRaw)
    const prbRoute = contract.role === 'denied_unauthenticated'
      ? normalizeRoutePath(prbRouteRaw)
      : normalizeRouteTemplate(prbRouteRaw)
    const routeMatches = ctlRoute === prbRoute || (
      isLegitDeniedReadForMutatingProbe &&
      ctlRoute.length > 1 &&
      prbRoute.startsWith(`${ctlRoute}/`)
    )
    if (ctlRoute && prbRoute && !routeMatches) {
      return `Control legitimacy rejected (R3-17): denied control route "${ctlRoute}" does not match probe route "${prbRoute}" (outside contract.differsOnlyIn: ${contract.differsOnlyIn.join(', ')}).`
    }
  }

  // 3. Query-key parity: reject extraneous query keys added on the denied control absent from the probe
  if (!allowsArbitraryShape) {
    const prbQueryKeys = extractRawQueryKeys(probe.pathAndQuery ?? probe.route)
    const extraQueryKeys = [...extractRawQueryKeys(control.pathAndQuery ?? control.route)].filter(
      k => !prbQueryKeys.has(k) && !isAllowedExtraControlKey(k, allowed),
    )
    if (extraQueryKeys.length > 0) {
      return `Control legitimacy rejected (R3-17): denied control adds extraneous query parameter(s) [${extraQueryKeys.join(', ')}] absent from the probe (outside contract.differsOnlyIn: ${contract.differsOnlyIn.join(', ')}).`
    }
  }

  // 4. Body-shape parity: reject extraneous top-level body keys or control-only bodies absent from the probe
  if (!allowsArbitraryShape && !allowed.has('signature_or_scope')) {
    const ctlBody = extractTopLevelBodyKeys(control.requestJson)
    const prbBody = extractTopLevelBodyKeys(probe.requestJson)
    if (ctlBody.hasBody && !prbBody.hasBody) {
      return `Control legitimacy rejected (R3-17): denied control carries a request body absent from the probe (outside contract.differsOnlyIn: ${contract.differsOnlyIn.join(', ')}).`
    }
    if (ctlBody.keys.size > 0) {
      const extraBodyKeys = [...ctlBody.keys].filter(
        k => !prbBody.keys.has(k) && !isAllowedExtraControlKey(k, allowed),
      )
      if (extraBodyKeys.length > 0) {
        return `Control legitimacy rejected (R3-17): denied control adds extraneous request body field(s) [${extraBodyKeys.join(', ')}] absent from the probe (outside contract.differsOnlyIn: ${contract.differsOnlyIn.join(', ')}).`
      }
    }
  }

  return null
}

function checkControlSelfSabotage(
  control: ControlLegitimacyExchange,
  probe: ControlLegitimacyExchange | null | undefined,
  contract: OracleControlContract,
  boundaryClass?: 'auth' | 'access' | 'mfa' | 'other',
): string | null {
  const ctlHeaders = canonicalHeaderMap(control.requestHeaders)
  const prbHeaders = canonicalHeaderMap(probe?.requestHeaders)
  const ctlWire = control.wireCredentialProvenance
  const prbWire = probe?.wireCredentialProvenance

  // R4-H-7: Synthetic invalid credentials are NEVER allowed on a negative control arm.
  const hasSynthHeader = Object.values(ctlHeaders).some(v => SYNTH_INVALID_CRED_RE.test(v))
  const authMutatedSabotage = Boolean(ctlWire?.authMutated) && contract.role !== 'denied_tampered'
  if (hasSynthHeader || authMutatedSabotage) {
    return 'Auth bypass rejected (R4-H-7): synthetic invalid credentials are allowed strictly on the probe arm and never as a negative control (self-sabotaged control is not an authentication bypass).'
  }

  // R3-17 B1: Enforce declarative `contract.differsOnlyIn` parity across ALL denied-control specs.
  const parityErr = checkControlContractParity(control, probe, contract)
  if (parityErr) return parityErr

  // Only `denied_unauthenticated` (and auth/mfa boundary claims) enforce strict zero-extra-auth-on-control;
  // `denied_unauthorized` (BOLA/BFLA/dual-tenant) legitimately has an authenticated denied control,
  // `denied_revoked` (v8:temporal_revocation) legitimately differs in time after revocation, and
  // `denied_tampered` (webhook / crypto_scope_replay) legitimately carries a tampered signature.
  const enforceStrictUnauthControl =
    contract.role === 'denied_unauthenticated' ||
    boundaryClass === 'auth' ||
    boundaryClass === 'mfa'
  if (!enforceStrictUnauthControl || !probe) return null

  const headerRe = boundaryClass && boundaryClass !== 'access' ? BOUNDARY_CREDENTIAL_HEADER_RE : AUTH_OR_BYPASS_HEADER_RE
  for (const [k, v] of Object.entries(ctlHeaders)) {
    if (!v) continue
    if (k === 'cookie') {
      if (!(prbHeaders.cookie ?? '').trim()) {
        return 'Auth bypass rejected (R4-H-7): control carried a cookie absent from the probe (self-sabotaged control is not an authentication bypass).'
      }
      continue
    }
    if (headerRe.test(k) && !(prbHeaders[k] ?? '').trim()) {
      return 'Auth bypass rejected (R4-H-7): control carried an extra auth header absent from the probe (self-sabotaged control is not an authentication bypass).'
    }
  }
  if (ctlWire) {
    const prbCallerHeaders = new Set((prbWire?.callerAuthHeaderNames ?? []).map(h => h.toLowerCase()))
    const prbAllHeaderKeys = new Set(Object.keys(prbHeaders).filter(k => (prbHeaders[k] ?? '').length > 0))
    if (ctlWire.callerAuthHeaderNames.some(h => {
      const lh = h.toLowerCase()
      return lh !== 'cookie' && !prbCallerHeaders.has(lh) && !prbAllHeaderKeys.has(lh)
    })) {
      return 'Auth bypass rejected (R4-H-7): wire credential provenance shows control carried an extra caller auth header absent from the probe (self-sabotaged control is not an authentication bypass).'
    }
    const prbVaultHeaders = new Set((prbWire?.vaultHeaderNames ?? []).map(h => h.toLowerCase()))
    if (ctlWire.vaultHeaderNames.some(h => !prbVaultHeaders.has(h.toLowerCase()))) {
      return 'Auth bypass rejected (R4-H-7): wire credential provenance shows control carried a vault auth header absent from the probe (self-sabotaged control is not an authentication bypass).'
    }
    const prbWireCookies = new Set((prbWire?.cookieNames ?? []).map(c => c.toLowerCase()))
    if (ctlWire.cookieNames.some(c => !prbWireCookies.has(c.toLowerCase())) && !(prbHeaders.cookie ?? '').trim()) {
      return 'Auth bypass rejected (R4-H-7): wire credential provenance shows control carried a cookie absent from the probe (self-sabotaged control is not an authentication bypass).'
    }
  }
  if (normalizedAuthHandle(control.actorHandle) !== null && normalizedAuthHandle(probe.actorHandle) === null) {
    return 'Auth bypass rejected (R4-H-7): control carried an authenticated persona that the anonymous probe lacked (self-sabotaged control is not an authentication bypass).'
  }
  const ctlSessionId = control.sessionId ?? ctlWire?.session ?? null
  const prbSessionId = probe.sessionId ?? prbWire?.session ?? null
  if (ctlSessionId && !prbSessionId) {
    return 'Auth bypass rejected (R4-H-7): control carried a session jar that the probe lacked (self-sabotaged control is not an authentication bypass).'
  }
  return null
}

function checkAnonymousAblation(
  control: ControlLegitimacyExchange,
  probe: ControlLegitimacyExchange,
  allEntries: readonly ControlLegitimacyExchange[],
): string | null {
  const probeHeaders = canonicalHeaderMap(probe.requestHeaders)
  const probeHasHostBaseAuth = Boolean(
    normalizedAuthHandle(probe.actorHandle) !== null ||
    probeHeaders.cookie ||
    probe.sessionId ||
    probe.wireCredentialProvenance?.session ||
    probe.wireCredentialProvenance?.sources.some(s => s === 'persona_vault' || s === 'session_jar' || s === 'ephemeral_observed') ||
    (probe.wireCredentialProvenance?.vaultHeaderNames.length ?? 0) > 0 ||
    (probe.wireCredentialProvenance?.vaultCookieNames.length ?? 0) > 0 ||
    (probe.wireCredentialProvenance?.jarCookieNames.length ?? 0) > 0,
  )
  if (probeHasHostBaseAuth) return null
  const method = (probe.method ?? '').toUpperCase()
  const route = normalizeRoutePath(probe.route ?? probe.pathAndQuery)
  if (!method || !route) return null
  if (allEntries.some(e => isBareAnonymousAblationExchange(e, method, route) && is2xxStatus(e.status))) {
    return 'Auth bypass rejected (R4-H-7): a bare anonymous ablation request on the same route succeeded with 2xx (endpoint is permit-all/public, not an authentication bypass).'
  }
  const hasDeniedAblation = isBareAnonymousAblationExchange(control, method, route) ||
    allEntries.some(e => isBareAnonymousAblationExchange(e, method, route) && (e.status === 401 || e.status === 403))
  if (!hasDeniedAblation) {
    return 'Auth bypass rejected (R4-H-7): missing denied (401/403) bare anonymous ablation arm (the probe minus its bypass element must be denied without credentials).'
  }
  return null
}

/**
 * Single spec-driven control-legitimacy stage (`R3-17`).
 * Executes for every `OracleSpec` declaring a denied control (`mustBe === 'denied_401_or_403' | 'denied_4xx'`),
 * rejecting self-sabotaged controls, host-credential escalations, and missing anonymous ablations
 * while preserving legitimate temporal differences (`v8:temporal_revocation`) and tampered-signature controls.
 */
export function assertLegitimateControl(input: ControlLegitimacyInput): ControlLegitimacyResult {
  const contract = selectDeniedControlContract(input.spec)
  if (!contract) {
    return {
      ok: true,
      executed: true,
      specId: input.spec.id,
      contractRole: null,
      rejectedBy: null,
      reason: 'Spec does not declare a denied-control contract.',
    }
  }

  // 1. Self-sabotaged control check (applies across ALL denied-control specs, tailored by contract.role).
  const sabotageErr = checkControlSelfSabotage(input.control, input.probe, contract, input.boundaryClass)
  if (sabotageErr) {
    return {
      ok: false,
      executed: true,
      specId: input.spec.id,
      contractRole: contract.role,
      rejectedBy: 'self_sabotaged_control',
      reason: sabotageErr,
    }
  }

  // 2. For `denied_unauthenticated` specs (auth_bypass, signed_url_mint unauth write), reject
  //    probe host-credential escalations on denied controls and optionally enforce bare anonymous ablation.
  const controlIsDenied = typeof input.control.status !== 'number' || (input.control.status >= 400 && input.control.status < 500)
  if (contract.role === 'denied_unauthenticated' && input.probe && input.boundaryClass !== 'access' && controlIsDenied) {
    const escalationErr = checkProbeHostCredentialEscalation(
      input.control,
      input.probe,
      input.allEntries ?? [],
    )
    if (escalationErr) {
      return {
        ok: false,
        executed: true,
        specId: input.spec.id,
        contractRole: contract.role,
        rejectedBy: 'probe_host_credential_escalation',
        reason: escalationErr,
      }
    }
    if (input.requireAnonymousAblation && input.allEntries) {
      const ablationErr = checkAnonymousAblation(input.control, input.probe, input.allEntries)
      if (ablationErr) {
        return {
          ok: false,
          executed: true,
          specId: input.spec.id,
          contractRole: contract.role,
          rejectedBy: 'missing_anonymous_ablation',
          reason: ablationErr,
        }
      }
    }
  }

  return {
    ok: true,
    executed: true,
    specId: input.spec.id,
    contractRole: contract.role,
    rejectedBy: null,
    reason: 'Control satisfies spec control-legitimacy contract.',
  }
}

function normalizeRoleLocal(raw: string | null | undefined): RoleName | null {
  const lower = (raw ?? '').trim().toLowerCase()
  if (lower === 'owner' || lower === 'admin' || lower === 'member' || lower === 'viewer') return lower
  if (lower === 'administrator') return 'admin'
  if (lower === 'guest') return 'viewer'
  if (lower === 'user' || lower === 'editor') return 'member'
  return null
}

function hydratableEntryToImpactStep(e: HydratableEntry): ImpactStep {
  const rawAuth = e.step.actor.auth
  const auth = rawAuth === 'cookie' || rawAuth === 'bearer' || rawAuth === 'header' ? rawAuth : 'unknown'
  const rawArm = e.step.arm
  const arm: ImpactStep['arm'] = rawArm === 'control' || rawArm === 'probe' || rawArm === 'setup' || rawArm === 'cleanup' ? rawArm : 'probe'
  return {
    id: e.exchangeId,
    arm,
    method: e.step.method,
    route: e.step.route,
    pathAndQuery: e.step.pathAndQuery,
    status: e.step.status,
    actor: {
      handle: e.step.actor.handle ?? null,
      role: normalizeRoleLocal(e.step.actor.role ?? null),
      tenant: e.step.actor.tenant ?? null,
      auth,
      sameSite: null,
    },
    ...(e.step.json !== undefined ? { json: e.step.json } : {}),
    ...(e.step.body !== undefined ? { body: e.step.body } : {}),
    ...(e.step.requestJson !== undefined ? { requestJson: e.step.requestJson } : {}),
    requestHeaders: e.step.requestHeaders ?? null,
    responseHeaders: e.step.responseHeaders ?? null,
  }
}

/**
 * Extract the denied control exchange(s), primary probe exchange, and full transcript steps
 * for a hydrated v8 family input so `TerminalOracleRegistry` executes `assertLegitimateControl()`
 * and `evaluateMustBeNonPublicStage()` before `evaluateV8OracleFamily()` runs (`R3-17`).
 */
export function extractV8KernelStageContext(
  family: V8OracleFamilyId,
  hydrated: Record<string, unknown>,
  idx: HydratableTranscriptIndex,
): {
  controls: ControlLegitimacyExchange[]
  probe: ControlLegitimacyExchange | null
  probeStep: ImpactStep | null
  allSteps: ImpactStep[]
  allExchanges: ControlLegitimacyExchange[]
} {
  const entryFromField = (field: string): HydratableEntry | undefined => {
    const val = hydrated[field]
    if (!val || typeof val !== 'object' || Array.isArray(val)) return undefined
    const id = (val as { id?: unknown }).id
    return typeof id === 'string' ? idx.entriesById.get(id) : undefined
  }

  const controlEntries: HydratableEntry[] = []
  let probeEntry: HydratableEntry | undefined
  if (family === 'dual_tenant_abac') {
    for (const f of ['sourceControlDenied', 'baselineDeniedControl', 'singleForeignControlDenied']) {
      const e = entryFromField(f)
      if (e) controlEntries.push(e)
    }
    probeEntry = entryFromField('bledAccess') ?? entryFromField('postTransferReadback') ?? entryFromField('batchRequest') ?? entryFromField('transferRecord')
  } else if (family === 'temporal_revocation') {
    const c = entryFromField('primaryDeniedCheck')
    if (c) controlEntries.push(c)
    probeEntry = entryFromField('secondarySuccess')
  } else if (family === 'cryptographic_scope_replay') {
    const c = entryFromField('tamperedSignatureControl')
    if (c) controlEntries.push(c)
    probeEntry = entryFromField('replayedAcceptance')
  } else if (family === 'cross_surface_pivot') {
    const ti = hydrated.terminalImpact
    if (ti && typeof ti === 'object' && !Array.isArray(ti)) {
      const rb = (ti as Record<string, unknown>).postImpactReadback
      if (rb && typeof rb === 'object' && typeof (rb as { id?: unknown }).id === 'string') {
        probeEntry = idx.entriesById.get((rb as { id: string }).id)
      }
    }
    const hops = Array.isArray(hydrated.hops) ? hydrated.hops : []
    if (!probeEntry && hops.length > 0) {
      const last = hops[hops.length - 1]
      const rec = last && typeof last === 'object' ? (last as Record<string, unknown>).record : undefined
      if (rec && typeof rec === 'object' && typeof (rec as { id?: unknown }).id === 'string') {
        probeEntry = idx.entriesById.get((rec as { id: string }).id)
      }
    }
    const seenPivotControls = new Set<string>()
    const preChainCtrl = entryFromField('preChainControlDenied')
    if (preChainCtrl) {
      seenPivotControls.add(preChainCtrl.exchangeId)
      controlEntries.push(preChainCtrl)
    }
    for (const e of idx.entriesById.values()) {
      if (e.step.arm === 'control' && !seenPivotControls.has(e.exchangeId)) {
        seenPivotControls.add(e.exchangeId)
        controlEntries.push(e)
      }
    }
  }

  const allEntries = [...idx.entriesById.values()]
  return {
    controls: controlEntries.map(transcriptEntryToControlExchange),
    probe: probeEntry ? transcriptEntryToControlExchange(probeEntry) : null,
    probeStep: probeEntry ? hydratableEntryToImpactStep(probeEntry) : null,
    allSteps: allEntries.map(hydratableEntryToImpactStep),
    allExchanges: allEntries.map(transcriptEntryToControlExchange),
  }
}
