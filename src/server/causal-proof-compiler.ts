/**
 * Host-Side Causal Proof Compiler (Move 1 Foundation) & Grey-Box Precision Guards.
 *
 * Compiles causal DAG edges backwards from `HostSignedTranscript` / `HostFactLog`:
 *   - Rewires mis-anchored `value_binding (hop_k -> hop_m)` edges to the true chronological
 *     ancestor `hop_a` that emitted the capability handle (and infers valid mutating
 *     `state_transition_binding (hop_k -> hop_m)` when shared `entityId` + clean ablation exists).
 *   - Infers missing `derived_crypto_binding`, `value_binding` (capability + high-entropy digest),
 *     and mutating `state_transition_binding` edges strictly chronologically and acyclically.
 *   - Enforces generic grey-box precision guards: rejects read-only directory/roster/metadata GETs
 *     as `privilege_escalation`/`bfla`, strips request URL/query/body tokens from JSON & CSV tenant
 *     markers for positive foreign-tenant verification, rejects bogus `GET -> GET` state transitions,
 *     and deterministically infers or fails closed when `terminalImpact.oracleInput` omits `oracleFamily`.
 */
import { createHash } from 'node:crypto'
import type {
  CausalEdgeBinding,
  CompositeProofReceipt,
  HostSignedTranscript,
  HostTranscriptEntry,
} from './composite-receipt.ts'
import { HostFactLog, type HostExchangeFact } from './host-fact-log.ts'
import { isReadMethod, parseRoleMemberships, routeFamily, stepReadsState } from './oracle-invariants.ts'
import { extractTenantMarkers, type V8OracleFamily } from './v8-oracle-families.ts'
import { canonicalNonAuthQuery, cleanExactPath, entryMatchesEntity, isPrivilegedActorOrRole, type CapOriginIndex } from './v8-oracle-hydrate.ts'

const CAP_HANDLE_RE = /^cap:[A-Za-z0-9._:-]{1,180}$/
const SHA256_RE = /^[0-9a-f]{64}$/
const MAX_COMPOSITE_EDGES = 28
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}|$)/
const ABLATION_DENIED_STATUSES = new Set([401, 403, 404, 409, 412, 422])
const STATIC_VERSION_PREFIX_RE = /^(?:v\d+|api|oauth\d*|http\d*|sha\d+|aes\d+|cwe|cve|rfc|iso|utf\d+)$/i
const UUID_SEG_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const HEX_ID_SEG_RE = /^(?:(?=[0-9a-f]*\d)[0-9a-f]{8,}|[0-9a-f]{16,})$/i
const OPAQUE_ALNUM_ID_RE = /^(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{8,}$/i
const SKIP_HDR_NAMES = new Set([
  'date', 'server', 'content-type', 'content-length', 'cache-control', 'vary', 'connection',
  'keep-alive', 'accept', 'accept-encoding', 'accept-language', 'user-agent', 'host', 'origin',
  'referer', 'pragma', 'expires', 'transfer-encoding', 'strict-transport-security',
  'content-security-policy', 'x-powered-by', 'x-frame-options', 'x-content-type-options',
  'access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers',
  'access-control-allow-credentials',
])

const sha256Hex = (v: string): string => createHash('sha256').update(v, 'utf8').digest('hex')
const isFiniteTs = (ts: unknown): ts is number => typeof ts === 'number' && Number.isFinite(ts) && ts >= 0
const is2xx = (st: number | null | undefined): boolean => typeof st === 'number' && st >= 200 && st < 300
const isExecArm = (arm: string | undefined, isTerm: boolean): boolean => arm === 'probe' || (!isTerm && arm === 'setup')

/** True when a decoded URL path segment is a dynamic resource/job/export identifier rather than a static route noun. */
export function isDynamicResourceIdSegment(rawSegment: string): boolean {
  let seg = rawSegment.trim()
  if (!seg) return false
  if (seg.includes('%')) {
    try { seg = decodeURIComponent(seg) } catch { /* keep raw */ }
  }
  const lower = seg.toLowerCase()
  if (/^\d+$/.test(lower)) return true
  if (UUID_SEG_RE.test(lower) || HEX_ID_SEG_RE.test(lower)) return true
  if (CAP_HANDLE_RE.test(seg) || /^\[redacted(?::[^\]]+)?\]$/i.test(seg)) return true
  if (OPAQUE_ALNUM_ID_RE.test(lower) && !STATIC_VERSION_PREFIX_RE.test(lower)) return true
  if ((lower.includes('-') || lower.includes('_')) && /\d/.test(lower)) {
    const parts = lower.split(/[-_]/).filter(Boolean)
    if (parts.length >= 2 && !STATIC_VERSION_PREFIX_RE.test(parts[0]!)) return true
  }
  return false
}

/**
 * Normalize a composite terminal endpoint into a canonical route family so Mode-A dual runs
 * minting fresh per-run entity IDs (`/v1/orders/ord_16/settle` vs `/v1/orders/ord_17/settle`)
 * agree cleanly while distinct routes still disagree.
 */
export function normalizeCompositeTerminalEndpoint(endpoint: string | null | undefined, entityId?: string | null): string {
  const raw = (endpoint ?? '').trim()
  if (!raw) return ''
  const pathOnly = raw.split(/[?#]/, 1)[0]!.replace(/\/+$/, '')
  if (!pathOnly) return ''
  const eid = entityId?.trim().toLowerCase() || ''
  const normalized = pathOnly
    .split('/')
    .map(seg => {
      if (!seg) return ''
      let decoded = seg
      if (seg.includes('%')) {
        try { decoded = decodeURIComponent(seg) } catch { decoded = seg }
      }
      if ((eid && decoded.toLowerCase() === eid) || /^\d+$/.test(decoded) || isDynamicResourceIdSegment(decoded)) {
        return ':id'
      }
      return decoded
    })
    .join('/')
  return routeFamily(normalized)
}

// ---------------------------------------------------------------------------
// Generic Grey-Box Precision Guards
// ---------------------------------------------------------------------------

const PRIVILEGED_SENSITIVE_PATH_RE =
  /(?:^|\/)(?:vault|audit|secrets?|credentials?|keys?|tokens?|billing|payouts?|ledger|settlements?|treasury|backups?|exports?|downloads?|records?|admin|owner|internal|webhooks?|deployments?|releases?)(?:\/|$)/i
const READONLY_DIRECTORY_PATH_RE =
  /(?:^|\/)(?:members?|roster|directory|org_?directory|users|people|teams?|groups?|metadata|profiles?|orgs?|organizations?|workspaces?)(?:\/[^/]+)?(?:\/(?:members?|roster|directory|users|metadata|profile|info|summary))?$/i
const DIRECTORY_KEY_ALLOWLIST = new Set([
  'id', 'userid', 'user_id', 'memberid', 'member_id', 'email', 'pendingemail', 'pending_email',
  'name', 'displayname', 'display_name', 'username', 'handle', 'role', 'roles', 'slug', 'region',
  'plan', 'tier', 'org', 'orgid', 'org_id', 'organization', 'organizationid', 'organization_id',
  'tenant', 'tenantid', 'tenant_id', 'workspace', 'workspaceid', 'workspace_id', 'status',
  'active', 'createdat', 'created_at', 'updatedat', 'updated_at', 'count', 'total', 'members',
  'users', 'roster', 'directory', 'teams', 'groups', 'orgs', 'organizations', 'metadata', 'profile',
])
const DIRECTORY_MARKER_KEYS = new Set([
  'members', 'roster', 'directory', 'users', 'pendingemail', 'pending_email', 'email', 'role', 'roles', 'org', 'orgs', 'metadata', 'profile',
])
const SENSITIVE_PAYLOAD_KEY_RE =
  /secret|passw|private|credential|api_?key|vault|audit|ledger|balance|amount|payout|settlement|token|signing|canary|ssn|card|iban/i

/**
 * True when a read-only GET terminal exchange is a directory/roster/member/metadata listing
 * (never sufficient alone to confirm `privilege_escalation` or `bfla` without mutation + readback
 * or a verified v8 oracle family).
 */
export function isReadOnlyDirectoryOrMetadataImpact(termEx: HostTranscriptEntry | undefined): boolean {
  if (!termEx || !stepReadsState(termEx.step)) return false
  const cleanPath = cleanExactPath(termEx.step.route ?? termEx.step.pathAndQuery)
  if (cleanPath && PRIVILEGED_SENSITIVE_PATH_RE.test(cleanPath)) return false
  if (cleanPath && READONLY_DIRECTORY_PATH_RE.test(cleanPath)) return true
  let parsed = termEx.step.json
  if (parsed === undefined && typeof termEx.step.body === 'string' && /^[\[{]/.test(termEx.step.body.trim())) {
    try { parsed = JSON.parse(termEx.step.body) } catch { parsed = undefined }
  }
  if (!parsed || typeof parsed !== 'object') return false
  let hasDirMarker = false
  let allAllowed = true
  let visited = 0
  const walk = (node: unknown, depth: number): void => {
    if (!allAllowed || depth > 4 || visited > 128 || node == null || typeof node !== 'object') return
    if (Array.isArray(node)) { for (const x of node.slice(0, 32)) walk(x, depth + 1); return }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      visited += 1
      const lk = k.toLowerCase()
      if (SENSITIVE_PAYLOAD_KEY_RE.test(lk) || !DIRECTORY_KEY_ALLOWLIST.has(lk)) { allAllowed = false; return }
      if (DIRECTORY_MARKER_KEYS.has(lk)) hasDirMarker = true
      if (v && typeof v === 'object') walk(v, depth + 1)
    }
  }
  walk(parsed, 0)
  return hasDirMarker && allAllowed
}

const TENANT_TEXT_KEY_RE = /^(?:tenant|tenant_id|tenantid|org|org_id|orgid|organization|organization_id|workspace|workspace_id|owner_tenant|owner_tenant_id|merchant_id)$/i
const TENANT_HEADER_NOISE = new Set(['tenant', 'tenant_id', 'tenantid', 'org', 'org_id', 'orgid', 'value', 'field', 'key', 'id', 'slug', 'name'])

function collectRequestTokensBySource(entry: HostTranscriptEntry): { pathTokens: Set<string>; queryAndBodyTokens: Set<string> } {
  const pathTokens = new Set<string>(), queryAndBodyTokens = new Set<string>()
  const add = (target: Set<string>, raw: string | null | undefined): void => {
    const t = (raw ?? '').trim().toLowerCase()
    if (t.length >= 2 && t.length <= 256) target.add(t)
  }
  const pq = entry.step.pathAndQuery ?? entry.step.route ?? ''
  if (pq) {
    const [pathPart = '', queryPart = ''] = pq.split('?', 2)
    for (const seg of pathPart.split('/')) {
      if (!seg) continue
      add(pathTokens, seg)
      try { add(pathTokens, decodeURIComponent(seg)) } catch { /* ignore */ }
    }
    if (queryPart) {
      for (const v of new URLSearchParams(queryPart.split('#', 1)[0]!).values()) add(queryAndBodyTokens, v)
    }
  }
  const walk = (v: unknown, d: number): void => {
    if (d > 4 || queryAndBodyTokens.size > 128 || v == null) return
    if (typeof v === 'string') add(queryAndBodyTokens, v)
    else if (Array.isArray(v)) for (const x of v.slice(0, 32)) walk(x, d + 1)
    else if (typeof v === 'object') for (const x of Object.values(v as Record<string, unknown>)) walk(x, d + 1)
  }
  walk(entry.step.requestJson, 0)
  return { pathTokens, queryAndBodyTokens }
}

function hasSubstantiveJsonRecords(json: unknown): boolean {
  if (!json || typeof json !== 'object') return false
  if (Array.isArray(json)) return json.some(x => x && typeof x === 'object')
  for (const [k, v] of Object.entries(json as Record<string, unknown>)) {
    if (SENSITIVE_PAYLOAD_KEY_RE.test(k) && v !== null && v !== undefined && v !== '') return true
    if (Array.isArray(v) && v.some(x => x && typeof x === 'object' && Object.keys(x as Record<string, unknown>).length >= 2)) return true
  }
  return false
}

function extractCsvOrKvTenantMarkers(body: string | undefined): Set<string> {
  const out = new Set<string>()
  if (typeof body !== 'string' || !body.trim()) return out
  const lines = body.split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(0, 128)
  if (lines.length === 0) return out
  // 1. Key-value CSV or `key=val` / `key: val` rows (e.g. `tenant,acme` or `tenant_id=org_b`).
  for (const line of lines) {
    const m = /^([A-Za-z_][A-Za-z0-9_-]{1,32})\s*[,:=]\s*"?([A-Za-z0-9._-]{2,64})"?$/.exec(line)
    if (!m) continue
    const key = m[1]!.toLowerCase(), val = m[2]!.toLowerCase()
    if (TENANT_TEXT_KEY_RE.test(key) && !TENANT_HEADER_NOISE.has(val)) out.add(val)
  }
  // 2. Tabular CSV header row (`id,tenant,amount\n1,org_b,500`). Skip when Step 1 already parsed
  //    2-column `key,value` rows (e.g. `tenant,acme\ncanary,...`) so column-0 keys aren't misread as tenants.
  const hdrCols = lines[0]!.split(',').map(c => c.trim().replace(/^"|"$/g, '').toLowerCase())
  if (out.size > 0 && hdrCols.length === 2 && TENANT_TEXT_KEY_RE.test(hdrCols[0]!)) return out
  const tenantColIdxs = hdrCols.map((c, i) => (TENANT_TEXT_KEY_RE.test(c) ? i : -1)).filter(i => i >= 0)
  if (tenantColIdxs.length > 0 && lines.length >= 2) {
    for (const row of lines.slice(1, 64)) {
      const cells = row.split(',').map(c => c.trim().replace(/^"|"$/g, '').toLowerCase())
      for (const idx of tenantColIdxs) {
        const val = cells[idx]
        if (val && val.length >= 2 && val.length <= 64 && !TENANT_HEADER_NOISE.has(val)) out.add(val)
      }
    }
  }
  return out
}

function isCsvOrJsonEntry(entry: HostTranscriptEntry): boolean {
  if (entry.step.json !== undefined) return true
  const body = typeof entry.step.body === 'string' ? entry.step.body.trim() : ''
  if (body && /^[\[{]/.test(body)) return true
  const ct = Object.entries(entry.step.responseHeaders ?? {}).find(([k]) => k.toLowerCase() === 'content-type')?.[1]?.toLowerCase() ?? ''
  if (ct.includes('json') || ct.includes('csv')) return true
  if (body && /^[^\r\n,]+,[^\r\n,]+(?:\r?\n[^\r\n,]+,[^\r\n,]+)+/.test(body)) return true
  return false
}

export interface CrossTenantTerminalAnalysis {
  ownTenantOnly: boolean
  hasForeignTenantData: boolean
  reflectedTenantOnly: boolean
  crossTenantSatisfied: boolean
}

/**
 * Positive non-reflected cross-tenant evidence evaluator for `CROSS_TENANT_CLASS_RE`.
 * Strips attacker-supplied request URL path/query/body tokens from JSON and CSV tenant markers
 * so reflecting a path segment in `text/csv` or JSON can NEVER satisfy foreign-tenant impact.
 */
export function analyzeCrossTenantTerminalEvidence(
  termEx: HostTranscriptEntry | undefined,
  attackerTenants: ReadonlySet<string>,
  isStub: boolean,
  hasBody: boolean,
  upstreamEntries: readonly HostTranscriptEntry[],
  hasPostMutation: boolean,
  hasVerifiedMultiHopTermEdge: boolean,
): CrossTenantTerminalAnalysis {
  if (!termEx) {
    return { ownTenantOnly: false, hasForeignTenantData: false, reflectedTenantOnly: false, crossTenantSatisfied: hasPostMutation }
  }
  const jsonMarkers = extractTenantMarkers(termEx.step.json, termEx.step.body)
  const textMarkers = termEx.step.json === undefined ? extractCsvOrKvTenantMarkers(termEx.step.body) : new Set<string>()
  const allMarkers = new Set<string>([...jsonMarkers, ...textMarkers])
  const { pathTokens, queryAndBodyTokens } = collectRequestTokensBySource(termEx)
  const reqCitesOwnTenant = attackerTenants.size > 0
    && ([...pathTokens, ...queryAndBodyTokens].some(t => attackerTenants.has(t)))
  const stripPathTokens = termEx.step.json === undefined || reqCitesOwnTenant || !hasSubstantiveJsonRecords(termEx.step.json)
  const strippedTokens = stripPathTokens
    ? new Set<string>([...pathTokens, ...queryAndBodyTokens])
    : queryAndBodyTokens
  const nonReflected = new Set<string>([...allMarkers].filter(m => !strippedTokens.has(m)))

  const ownTenantOnly = allMarkers.size > 0 && attackerTenants.size > 0 && [...allMarkers].every(t => attackerTenants.has(t))
  const reflectedTenantOnly = allMarkers.size > 0 && nonReflected.size === 0
  const directForeign = Boolean(!isStub && hasBody && attackerTenants.size > 0 && [...nonReflected].some(t => !attackerTenants.has(t)))

  const upstreamNonReflectedForeign = Boolean(
    !isStub && hasBody && !ownTenantOnly && attackerTenants.size > 0
    && upstreamEntries.some(e => {
      const m = extractTenantMarkers(e.step.json, e.step.body, true)
      if (m.size === 0) return false
      const u = collectRequestTokensBySource(e)
      return [...m].some(t => !u.pathTokens.has(t) && !u.queryAndBodyTokens.has(t) && !attackerTenants.has(t))
    }),
  )

  const hasForeignTenantData = directForeign || upstreamNonReflectedForeign
  const opaquePlainTextMultiHop = Boolean(
    !isStub && hasBody && !ownTenantOnly && !reflectedTenantOnly && !isCsvOrJsonEntry(termEx) && hasVerifiedMultiHopTermEdge,
  )
  const crossTenantSatisfied = hasPostMutation || hasForeignTenantData || opaquePlainTextMultiHop

  return { ownTenantOnly, hasForeignTenantData, reflectedTenantOnly, crossTenantSatisfied }
}

const DUAL_ABAC_MODES = new Set(['cross_org_transfer', 'dual_org_cache_bleed', 'batch_partial_authz'])

/**
 * Deterministically infer a v8 oracle family from `terminalImpact.oracleInput` when
 * `terminalImpact.oracleFamily` was omitted so `oracleInput` is NEVER silently ignored.
 */
export function inferV8OracleFamilyFromInput(rawInput: Record<string, unknown>): V8OracleFamily | null {
  const mode = typeof rawInput.mode === 'string' ? rawInput.mode.trim().toLowerCase() : ''
  const has = (...keys: string[]) => keys.some(k => rawInput[k] !== undefined)
  if (
    DUAL_ABAC_MODES.has(mode)
    || has('transferRecord', 'transferExchangeId', 'postTransferReadback', 'bledAccess', 'primeAction', 'baselineDeniedControl', 'baselineControlExchangeId', 'batchRequest', 'singleForeignControlDenied', 'singleForeignControlExchangeId')
  ) {
    return 'dual_tenant_abac'
  }
  if (has('revocationEvent', 'preRevocationBaseline', 'primaryDeniedCheck', 'secondarySuccess', 'credentialKind')) {
    return 'temporal_revocation'
  }
  if (has('equation', 'beforeBalance', 'afterBalance', 'initialBalance', 'finalReadback', 'finalBalance', 'raceRequests', 'authorizedCap', 'deltaObserved')) {
    return 'economic_conservation'
  }
  if (has('tamperedSignatureControl', 'tamperedControlExchangeId', 'sourceValidIssuance', 'sourceIssuanceExchangeId', 'replayedAcceptance', 'replayedExchangeId')) {
    return 'cryptographic_scope_replay'
  }
  if (has('canonicalRequest', 'variantRequest', 'cachePrimeRequest', 'victimReadback', 'smuggledRequest', 'parserDiff', 'cacheBleed')) {
    return 'parser_cache_differential'
  }
  if (has('preChainControlDenied') && Array.isArray(rawInput.hops)) {
    return 'cross_surface_pivot'
  }
  return null
}

/**
 * Guard `state_transition_binding` against bogus read-only `GET -> GET` claims.
 * Requires `fromHop` to be state-mutating (`!stepReadsState(fromEx)`), allowing read-only
 * `fromEx` ONLY for (a) cache-priming `GET -> mutating POST/PUT/PATCH/DELETE`, OR (b) strict
 * parent-resource open `GET /r/:id -> GET /r/:id/<subresource>` with literal entityId match and
 * strictly pre-`fromEx` non-query-tampered ablation control.
 */
export function verifyReadOnlyStateTransitionGuard(
  pair: { from: HostTranscriptEntry; to: HostTranscriptEntry },
  entityId: string,
  validAblation: HostTranscriptEntry,
  logicalFallback: boolean,
): string | null {
  const fromReads = stepReadsState(pair.from.step)
  if (!fromReads) return null
  const toReads = stepReadsState(pair.to.step)
  if (!toReads) return null
  const fromPath = cleanExactPath(pair.from.step.route ?? pair.from.step.pathAndQuery)
  const toPath = cleanExactPath(pair.to.step.route ?? pair.to.step.pathAndQuery)
  const strictParentSubresource = Boolean(fromPath && toPath && toPath.startsWith(`${fromPath}/`))
  const literalBoth = !logicalFallback && entryMatchesEntity(pair.from, entityId) && entryMatchesEntity(pair.to, entityId)
  const abPreFrom = isFiniteTs(validAblation.timestampMs) && isFiniteTs(pair.from.timestampMs) && validAblation.timestampMs < pair.from.timestampMs
  const abSameQuery = canonicalNonAuthQuery(validAblation.step.pathAndQuery ?? validAblation.step.route) === canonicalNonAuthQuery(pair.to.step.pathAndQuery ?? pair.to.step.route)
  if (strictParentSubresource && literalBoth && abPreFrom && abSameQuery) return null
  return `state_transition_binding requires a state-mutating fromHop (read-only ${pair.from.step.method} -> ${pair.to.step.method} cannot establish a state transition).`
}

// ---------------------------------------------------------------------------
// Host-Side Backwards Causal DAG Compiler + Ancestor-Cap Rewire (Move 1)
// ---------------------------------------------------------------------------

function isHighEntropyBindingToken(raw: string): boolean {
  const t = raw.trim()
  if (t.length < 8 || t.length > 2048 || /\s/.test(t) || /\[redacted/i.test(t) || ISO_DATE_RE.test(t)) return false
  if (t.startsWith('/') || /^https?:\/\//i.test(t)) {
    const pathPart = (t.startsWith('/') ? t : t.replace(/^https?:\/\/[^/]*/i, '')).split(/[?#]/, 1)[0] ?? ''
    if (!t.includes('?') && !pathPart.split('/').filter(Boolean).some(isDynamicResourceIdSegment)) return false
  }
  const counts = new Map<string, number>()
  for (const ch of t) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let h = 0
  for (const c of counts.values()) { const p = c / t.length; h -= p * Math.log2(p) }
  return (/\d/.test(t) && /[a-z]/i.test(t) && counts.size >= 4 && h >= 2.0) || (t.length >= 16 && counts.size >= 8 && h >= 3.0)
}

function collectJsonTokens(raw: string | null | undefined, out: Set<string>): void {
  if (!raw?.trim()) return
  let parsed: unknown
  try { parsed = JSON.parse(raw) } catch { return }
  const walk = (v: unknown, d: number): void => {
    if (d > 5 || out.size > 256 || v == null) return
    if (typeof v === 'string') { const t = v.trim(); if (t.length >= 8 && t.length <= 2048) out.add(t) }
    else if (typeof v === 'object') for (const x of Array.isArray(v) ? v : Object.values(v as Record<string, unknown>)) walk(x, d + 1)
  }
  walk(parsed, 0)
}

function collectHdrTokens(headers: Readonly<Record<string, string>> | null | undefined, out: Set<string>): void {
  for (const [k, raw] of Object.entries(headers ?? {})) {
    if (SKIP_HDR_NAMES.has(k.toLowerCase())) continue
    const t = raw.trim(); if (!t) continue; out.add(t)
    const m = /^(?:Bearer|Basic|Token|ApiKey)\s+(.+)$/i.exec(t); if (m?.[1]) out.add(m[1].trim())
    if (t.includes('=')) for (const p of t.split(';')) { const eq = p.indexOf('='); if (eq > 0 && p.slice(eq + 1).trim()) out.add(p.slice(eq + 1).trim()) }
  }
}

function collectFactDigests(fact: Readonly<HostExchangeFact>, side: 'response' | 'request'): Set<string> {
  const digests = new Set<string>(), tokens = new Set<string>(), exclude = new Set<string>()
  for (const s of [fact.actor, fact.actorTenant, fact.origin]) if (s?.trim()) exclude.add(s.trim().toLowerCase())
  const collectReqToks = (target: Set<string>): void => {
    collectJsonTokens(fact.rawRequestBody, target); collectHdrTokens(fact.requestHeaders, target)
    const pq = fact.pathAndQuery ?? '', q = pq.indexOf('?')
    if (pq) { target.add(pq); if (fact.origin) target.add(`${fact.origin.trim().replace(/\/+$/, '')}${pq}`) }
    for (const seg of (q >= 0 ? pq.slice(0, q) : pq).split('/')) if (seg) { target.add(seg); try { const d = decodeURIComponent(seg); if (d !== seg) target.add(d) } catch {} }
    if (q >= 0) for (const v of new URLSearchParams(pq.slice(q + 1)).values()) if (v) target.add(v)
  }
  if (side === 'response') {
    for (const d of [...(fact.observedResponseDigests ?? []), ...(fact.secretMatches ?? [])]) {
      const ld = d.toLowerCase(); if (SHA256_RE.test(ld)) digests.add(ld)
    }
    if (fact.status != null && fact.status >= 200 && fact.status < 400) {
      const ownReq = new Set<string>(); collectReqToks(ownReq)
      collectJsonTokens(fact.rawResponseBody, tokens); collectHdrTokens(fact.responseHeaders, tokens)
      for (const tok of tokens) if (!ownReq.has(tok) && !exclude.has(tok.toLowerCase()) && isHighEntropyBindingToken(tok)) digests.add(sha256Hex(tok))
    }
  } else {
    for (const d of fact.injectedRequestDigests ?? []) { const ld = d.toLowerCase(); if (SHA256_RE.test(ld)) digests.add(ld) }
    collectReqToks(tokens)
    for (const tok of tokens) if (!exclude.has(tok.toLowerCase()) && isHighEntropyBindingToken(tok)) digests.add(sha256Hex(tok))
  }
  return digests
}

interface CanonicalCapEmission {
  hopId: string
  sourceId: string
  isExchange: boolean
  timestampMs: number
  seq: number
}

function canReach(adj: ReadonlyMap<string, readonly string[]>, start: string, goal: string): boolean {
  if (start === goal) return true
  const visited = new Set<string>([start]), queue = [start]
  while (queue.length > 0) {
    for (const next of adj.get(queue.shift()!) ?? []) {
      if (next === goal) return true
      if (!visited.has(next)) { visited.add(next); queue.push(next) }
    }
  }
  return false
}

function factMatchesEntityId(fact: Readonly<HostExchangeFact>, entityId: string): boolean {
  const lid = entityId.trim().toLowerCase()
  if (!lid) return false
  if (fact.entityId?.trim().toLowerCase() === lid) return true
  if (fact.correlationIds?.some(c => c.trim().toLowerCase() === lid)) return true
  const pq = fact.pathAndQuery ?? ''
  if (pq) {
    const [p = '', q = ''] = pq.split('?', 2)
    for (const seg of p.split('/')) {
      if (seg.toLowerCase() === lid) return true
      try { if (decodeURIComponent(seg).toLowerCase() === lid) return true } catch { /* ignore */ }
    }
    if (q) for (const v of new URLSearchParams(q).values()) if (v.trim().toLowerCase() === lid) return true
  }
  return false
}

function findMutatingStateTransitionEdge(
  fromHop: CompositeProofReceipt['hops'][number],
  toHop: CompositeProofReceipt['hops'][number],
  factLog: HostFactLog,
  termHopId: string,
  allHopExIds: ReadonlySet<string>,
): Extract<CausalEdgeBinding, { kind: 'state_transition_binding' }> | null {
  const fromFacts = fromHop.exchangeIds
    .map(id => factLog.getExchange(id))
    .filter((f): f is HostExchangeFact => Boolean(f && isExecArm(f.arm, fromHop.hopId === termHopId) && is2xx(f.status) && isFiniteTs(f.timestampMs) && !isReadMethod(f.method)))
  const toFacts = toHop.exchangeIds
    .map(id => factLog.getExchange(id))
    .filter((f): f is HostExchangeFact => Boolean(f && isExecArm(f.arm, toHop.hopId === termHopId) && is2xx(f.status) && isFiniteTs(f.timestampMs)))
  if (fromFacts.length === 0 || toFacts.length === 0) return null

  const candidateEids = new Set<string>()
  for (const eid of [fromHop.entityId, toHop.entityId, ...fromFacts.map(f => f.entityId), ...toFacts.map(f => f.entityId)]) {
    if (eid?.trim()) candidateEids.add(eid.trim())
  }
  if (candidateEids.size === 0) return null

  const pair = fromFacts.flatMap(f => toFacts.filter(t => f.timestampMs! <= t.timestampMs!).map(t => ({ f, t })))[0]
  if (!pair) return null

  const sharedEid = [...candidateEids].find(eid => factMatchesEntityId(pair.f, eid) && factMatchesEntityId(pair.t, eid))
  if (!sharedEid) return null

  const toFam = normalizeCompositeTerminalEndpoint(pair.t.pathAndQuery, sharedEid)
  const ablation = factLog.orderedExchanges().find(ab => {
    if (allHopExIds.has(ab.exchangeId)) return false
    if (ab.cleanSession === false) return false
    if (ab.arm !== 'control' && ab.replayAttempt !== 'ablation_control') return false
    if (ab.status == null || !ABLATION_DENIED_STATUSES.has(ab.status)) return false
    const sameFam = Boolean(toFam) && normalizeCompositeTerminalEndpoint(ab.pathAndQuery, ab.entityId ?? sharedEid) === toFam
    return factMatchesEntityId(ab, sharedEid) || sameFam
  })
  if (!ablation) return null

  return {
    kind: 'state_transition_binding',
    fromHopId: fromHop.hopId,
    toHopId: toHop.hopId,
    entityId: sharedEid,
    ablationExchangeIds: [ablation.exchangeId],
  }
}

export interface RewiredCausalEdge {
  edgeIndex: number
  fromHopId: string
  rewiredFromHopId: string
  toHopId: string
  capabilityHandle: string
}

export interface CompiledCausalChain {
  receipt: CompositeProofReceipt
  inferredEdges: CausalEdgeBinding[]
  rewiredEdges: RewiredCausalEdge[]
}

/**
 * Compile and repair a composite causal DAG backwards from a `HostSignedTranscript` or `HostFactLog`.
 *
 * Guarantees:
 * - Never weakens downstream `composite-receipt.ts` verification (signatures, chronology, provenance,
 *   replay mode, terminal impact).
 * - Automatically rebinds `value_binding (hop_k -> hop_m)` to the true emitting ancestor `hop_a`
 *   when `hop_k` did not emit the handle, and infers valid mutating `state_transition_binding` on
 *   shared `entityId` when a clean-session denied ablation exists.
 * - Walks backwards from `terminalHopId` to compile missing `derived_crypto_binding`, `value_binding`,
 *   and mutating `state_transition_binding` edges strictly chronologically and acyclically.
 */
export function compileCausalChainFromTranscript(
  receipt: CompositeProofReceipt,
  transcriptOrFactLog: HostSignedTranscript | HostFactLog,
): CompiledCausalChain {
  if (receipt.hops.length < 2) return { receipt, inferredEdges: [], rewiredEdges: [] }
  const factLog = transcriptOrFactLog instanceof HostFactLog
    ? transcriptOrFactLog
    : HostFactLog.fromTranscript(transcriptOrFactLog)

  const hopsById = new Map<string, CompositeProofReceipt['hops'][number]>()
  for (const hop of receipt.hops) {
    if (hopsById.has(hop.hopId)) return { receipt, inferredEdges: [], rewiredEdges: [] }
    hopsById.set(hop.hopId, hop)
  }
  const termHopId = receipt.terminalImpact.terminalHopId
  if (!hopsById.has(termHopId)) return { receipt, inferredEdges: [], rewiredEdges: [] }

  // 1. Build canonical single-owner emission maps across exchanges, OOB events, and browser traces.
  const ownerHopByEx = new Map<string, string>()
  const ownerHopByOob = new Map<string, string>()
  const ownerHopByTrace = new Map<string, string>()
  const emissionsByCap = new Map<string, CanonicalCapEmission[]>()
  const emissionsByDigest = new Map<string, CanonicalCapEmission[]>()
  const allHopExIds = new Set<string>(receipt.hops.flatMap(h => h.exchangeIds))

  const recordEmission = (cap: string, em: CanonicalCapEmission): void => {
    if (!CAP_HANDLE_RE.test(cap)) return
    let list = emissionsByCap.get(cap)
    if (!list) { list = []; emissionsByCap.set(cap, list) }
    list.push(em)
  }
  const recordDigestEmission = (dig: string, em: CanonicalCapEmission): void => {
    const ld = dig.toLowerCase()
    if (!SHA256_RE.test(ld)) return
    let list = emissionsByDigest.get(ld)
    if (!list) { list = []; emissionsByDigest.set(ld, list) }
    list.push(em)
  }

  for (const hop of receipt.hops) {
    const isTerm = hop.hopId === termHopId
    for (const exId of hop.exchangeIds) {
      if (ownerHopByEx.has(exId)) continue
      ownerHopByEx.set(exId, hop.hopId)
      const flow = factLog.getExchangeCapabilityFlow(exId)
      if (!flow || !isExecArm(flow.arm, isTerm) || !isFiniteTs(flow.timestampMs)) continue
      const emBase: CanonicalCapEmission = { hopId: hop.hopId, sourceId: exId, isExchange: true, timestampMs: flow.timestampMs, seq: flow.seq }
      for (const cap of flow.emitted) recordEmission(cap, emBase)
      const fact = factLog.getExchange(exId)
      if (fact) for (const dig of collectFactDigests(fact, 'response')) recordDigestEmission(dig, emBase)
    }
    for (const oobId of hop.oobEventIds) {
      if (ownerHopByOob.has(oobId)) continue
      ownerHopByOob.set(oobId, hop.hopId)
      const oob = factLog.getOobEvent(oobId)
      if (!oob?.delivered || !isFiniteTs(oob.receivedAtMs)) continue
      const emBase: CanonicalCapEmission = { hopId: hop.hopId, sourceId: oobId, isExchange: false, timestampMs: oob.receivedAtMs, seq: -1 }
      for (const cap of oob.emittedCapabilities ?? []) recordEmission(cap, emBase)
      for (const dig of oob.observedValueDigests ?? []) recordDigestEmission(dig, emBase)
      if (oob.token && isHighEntropyBindingToken(oob.token)) recordDigestEmission(sha256Hex(oob.token), emBase)
    }
    for (const trId of hop.browserTraceIds) {
      if (ownerHopByTrace.has(trId)) continue
      ownerHopByTrace.set(trId, hop.hopId)
      const tr = factLog.getBrowserTrace(trId)
      if (!tr || !isFiniteTs(tr.timestampMs)) continue
      const emBase: CanonicalCapEmission = { hopId: hop.hopId, sourceId: trId, isExchange: false, timestampMs: tr.timestampMs, seq: -1 }
      for (const cap of tr.emittedCapabilities ?? []) recordEmission(cap, emBase)
      for (const dig of tr.observedValueDigests ?? []) recordDigestEmission(dig, emBase)
    }
  }

  // 2. Pass 1: Ancestor-cap `value_binding` rewire (hop_k -> hop_m rebinds to true emitting ancestor hop_a -> hop_m).
  const baseEdges: CausalEdgeBinding[] = receipt.causalEdges.map(e => ({ ...e }))
  const rewiredEdges: RewiredCausalEdge[] = []
  const stateTransitionCandidates: Array<{ fromHopId: string; toHopId: string }> = []
  const explicitKeySet = new Set(baseEdges.map(e => `${e.fromHopId}->${e.toHopId}:${e.kind}`))

  for (let i = 0; i < baseEdges.length; i++) {
    const edge = baseEdges[i]!
    if (edge.kind !== 'value_binding' || !edge.capabilityHandle) continue
    const toHop = hopsById.get(edge.toHopId)
    if (!toHop || !hopsById.has(edge.fromHopId) || edge.fromHopId === edge.toHopId) continue
    const cap = edge.capabilityHandle
    const allCapEmissions = emissionsByCap.get(cap) ?? []
    if (allCapEmissions.length === 0) continue

    // Find a host-verified consuming exchange on `toHop`.
    const targetIds = edge.targetExchangeId ? [edge.targetExchangeId] : toHop.exchangeIds
    let consumer: { exId: string; timestampMs: number; seq: number } | undefined
    for (const exId of targetIds) {
      const flow = factLog.getExchangeCapabilityFlow(exId)
      const fact = factLog.getExchange(exId)
      if (!flow || !fact || !isFiniteTs(flow.timestampMs)) continue
      const consumes = flow.consumed.includes(cap)
        || fact.actor === cap
        || flow.cryptoAttestations.some(a => a.derivedFromCapabilityId === cap || a.derivedCapabilityId === cap)
      if (consumes) { consumer = { exId, timestampMs: flow.timestampMs, seq: flow.seq }; break }
    }
    if (!consumer) continue

    // If `edge.fromHopId` already emitted `cap` chronologically before `consumer`, keep as-is.
    const declaredEmitted = allCapEmissions.some(
      em => em.hopId === edge.fromHopId && em.timestampMs <= consumer!.timestampMs,
    )
    if (declaredEmitted) continue

    // Otherwise locate the earliest chronological ancestor `hop_a` emitting `cap`.
    const ancestor = allCapEmissions.find(
      em => em.hopId !== edge.toHopId
        && em.hopId !== edge.fromHopId
        && (em.timestampMs < consumer!.timestampMs || (em.timestampMs === consumer!.timestampMs && em.seq < consumer!.seq)),
    )
    if (!ancestor) continue

    const oldKey = `${edge.fromHopId}->${edge.toHopId}:value_binding`
    const newKey = `${ancestor.hopId}->${edge.toHopId}:value_binding`
    if (explicitKeySet.has(newKey)) continue

    // Ensure rebinding preserves acyclicity against the remaining edges.
    const tmpAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
    for (let j = 0; j < baseEdges.length; j++) {
      if (j === i) continue
      const oe = baseEdges[j]!
      if (hopsById.has(oe.fromHopId) && hopsById.has(oe.toHopId) && oe.fromHopId !== oe.toHopId) {
        tmpAdj.get(oe.fromHopId)!.push(oe.toHopId)
      }
    }
    if (canReach(tmpAdj, edge.toHopId, ancestor.hopId)) continue

    const oldFromHopId = edge.fromHopId
    const { sourceExchangeId: _oldSrc, ...restEdge } = edge
    baseEdges[i] = {
      ...restEdge,
      fromHopId: ancestor.hopId,
      ...(ancestor.isExchange ? { sourceExchangeId: ancestor.sourceId } : {}),
    }
    explicitKeySet.delete(oldKey)
    explicitKeySet.add(newKey)
    rewiredEdges.push({
      edgeIndex: i,
      fromHopId: oldFromHopId,
      rewiredFromHopId: ancestor.hopId,
      toHopId: edge.toHopId,
      capabilityHandle: cap,
    })
    stateTransitionCandidates.push({ fromHopId: oldFromHopId, toHopId: edge.toHopId })
  }

  // 3. Build working adjacency + bound-cap indexes from (possibly rewired) explicit edges.
  const existingKeys = new Set<string>()
  const outAdj = new Map<string, string[]>(receipt.hops.map(h => [h.hopId, []]))
  const boundValueCapsByHop = new Map<string, Set<string>>()
  const boundCryptoCapsByHop = new Map<string, Set<string>>()
  const explicitProducerByCap = new Map<string, string>()

  const markBound = (map: Map<string, Set<string>>, hopId: string, cap: string): void => {
    let set = map.get(hopId)
    if (!set) { set = new Set<string>(); map.set(hopId, set) }
    set.add(cap)
  }

  for (const edge of baseEdges) {
    existingKeys.add(`${edge.fromHopId}->${edge.toHopId}:${edge.kind}`)
    if (hopsById.has(edge.fromHopId) && hopsById.has(edge.toHopId) && edge.fromHopId !== edge.toHopId) {
      outAdj.get(edge.fromHopId)!.push(edge.toHopId)
    }
    if (edge.kind === 'value_binding' && edge.capabilityHandle) {
      markBound(boundValueCapsByHop, edge.toHopId, edge.capabilityHandle)
      if (!explicitProducerByCap.has(edge.capabilityHandle)) explicitProducerByCap.set(edge.capabilityHandle, edge.fromHopId)
    } else if (edge.kind === 'derived_crypto_binding') {
      markBound(boundCryptoCapsByHop, edge.toHopId, edge.sourceCapabilityId)
      if (!explicitProducerByCap.has(edge.sourceCapabilityId)) explicitProducerByCap.set(edge.sourceCapabilityId, edge.fromHopId)
    }
  }

  const pickEmitter = (cap: string, toHopId: string, targetTs: number, targetSeq: number, maxEmitTs = targetTs): CanonicalCapEmission | undefined => {
    const list = emissionsByCap.get(cap)
    if (!list?.length) return undefined
    const preferredHop = explicitProducerByCap.get(cap)
    const eligible = list.filter(em => em.hopId !== toHopId && em.timestampMs <= maxEmitTs && (em.timestampMs < targetTs || (em.timestampMs === targetTs && em.seq < targetSeq)))
    if (eligible.length === 0) return undefined
    return (preferredHop ? eligible.find(em => em.hopId === preferredHop) : undefined) ?? eligible[0]
  }

  const inferredEdges: CausalEdgeBinding[] = []
  const tryAppendEdge = (edge: CausalEdgeBinding): boolean => {
    if (baseEdges.length + inferredEdges.length >= MAX_COMPOSITE_EDGES) return false
    const key = `${edge.fromHopId}->${edge.toHopId}:${edge.kind}`
    if (existingKeys.has(key)) return false
    if (canReach(outAdj, edge.toHopId, edge.fromHopId)) return false
    existingKeys.add(key)
    outAdj.get(edge.fromHopId)!.push(edge.toHopId)
    inferredEdges.push(edge)
    return true
  }

  // 4. Infer valid mutating `state_transition_binding` for rewired hop pairs on shared entityId.
  for (const cand of stateTransitionCandidates) {
    const fromHop = hopsById.get(cand.fromHopId), toHop = hopsById.get(cand.toHopId)
    if (!fromHop || !toHop) continue
    const stEdge = findMutatingStateTransitionEdge(fromHop, toHop, factLog, termHopId, allHopExIds)
    if (stEdge) tryAppendEdge(stEdge)
  }

  // 5. Pass 2: Backwards transcript-first compilation from terminal hop to earlier hops.
  const backwardsHops = [
    hopsById.get(termHopId)!,
    ...[...receipt.hops].filter(h => h.hopId !== termHopId).reverse(),
  ]

  for (const hopB of backwardsHops) {
    const isTermB = hopB.hopId === termHopId
    for (const exId of hopB.exchangeIds) {
      if (ownerHopByEx.get(exId) !== hopB.hopId) continue
      const flow = factLog.getExchangeCapabilityFlow(exId)
      const fact = factLog.getExchange(exId)
      if (!flow || !isExecArm(flow.arm, isTermB) || !isFiniteTs(flow.timestampMs)) continue

      // 5a. Derived cryptographic bindings (`derivedFromCapabilityId` -> `derived_crypto_binding`)
      for (const att of flow.cryptoAttestations) {
        const srcCap = att.derivedFromCapabilityId
        if (!CAP_HANDLE_RE.test(srcCap) || !SHA256_RE.test(att.artifactDigest.toLowerCase())) continue
        if (!isFiniteTs(att.timestampMs) || att.timestampMs > flow.timestampMs) continue
        if (boundCryptoCapsByHop.get(hopB.hopId)?.has(srcCap)) continue
        const em = pickEmitter(srcCap, hopB.hopId, flow.timestampMs, flow.seq, att.timestampMs)
        if (!em) continue
        const edge: CausalEdgeBinding = {
          kind: 'derived_crypto_binding',
          fromHopId: em.hopId,
          toHopId: hopB.hopId,
          sourceCapabilityId: srcCap,
          ...(att.derivedCapabilityId && CAP_HANDLE_RE.test(att.derivedCapabilityId)
            ? { derivedCapabilityId: att.derivedCapabilityId }
            : {}),
          ...(att.alg.trim() ? { alg: att.alg.trim().slice(0, 32) } : {}),
        }
        if (tryAppendEdge(edge)) markBound(boundCryptoCapsByHop, hopB.hopId, srcCap)
      }

      // 5b. Direct capability value bindings (`consumedCapabilities` + cap actor -> `value_binding`)
      const consumedCaps = new Set<string>(flow.consumed)
      if (fact?.actor && CAP_HANDLE_RE.test(fact.actor)) consumedCaps.add(fact.actor)
      for (const cap of consumedCaps) {
        if (!CAP_HANDLE_RE.test(cap)) continue
        if (boundValueCapsByHop.get(hopB.hopId)?.has(cap)) continue
        const em = pickEmitter(cap, hopB.hopId, flow.timestampMs, flow.seq)
        if (!em || canReach(outAdj, em.hopId, hopB.hopId)) continue
        const edge: CausalEdgeBinding = {
          kind: 'value_binding',
          fromHopId: em.hopId,
          toHopId: hopB.hopId,
          capabilityHandle: cap,
          ...(em.isExchange ? { sourceExchangeId: em.sourceId } : {}),
          targetExchangeId: exId,
        }
        if (tryAppendEdge(edge)) markBound(boundValueCapsByHop, hopB.hopId, cap)
      }
    }
  }

  // 5c. Host-signed observedValueDigests -> chronological `value_binding` fallback.
  if (emissionsByDigest.size > 0) {
    for (const hopB of backwardsHops) {
      const isTermB = hopB.hopId === termHopId
      for (const exId of hopB.exchangeIds) {
        if (ownerHopByEx.get(exId) !== hopB.hopId) continue
        const flow = factLog.getExchangeCapabilityFlow(exId), fact = factLog.getExchange(exId)
        if (!flow || !fact || !isExecArm(flow.arm, isTermB) || !isFiniteTs(flow.timestampMs)) continue
        for (const dig of collectFactDigests(fact, 'request')) {
          const list = emissionsByDigest.get(dig)
          if (!list?.length) continue
          const eligible = list.filter(em =>
            em.hopId !== hopB.hopId
            && (em.timestampMs < flow.timestampMs! || (em.timestampMs === flow.timestampMs! && em.seq < flow.seq)),
          )
          const em = eligible.length > 0 ? eligible[eligible.length - 1] : undefined
          if (!em || canReach(outAdj, em.hopId, hopB.hopId)) continue
          tryAppendEdge({
            kind: 'value_binding', fromHopId: em.hopId, toHopId: hopB.hopId, valueDigest: dig,
            ...(em.isExchange ? { sourceExchangeId: em.sourceId } : {}), targetExchangeId: exId,
          })
        }
      }
    }
  }

  // 5d. Backwards mutating `state_transition_binding` for any remaining orphan mutating hop with shared entityId + clean ablation.
  for (const hopA of receipt.hops) {
    if (hopA.hopId === termHopId || canReach(outAdj, hopA.hopId, termHopId)) continue
    for (const hopB of backwardsHops) {
      if (hopB.hopId === hopA.hopId || !canReach(outAdj, hopB.hopId, termHopId)) continue
      const stEdge = findMutatingStateTransitionEdge(hopA, hopB, factLog, termHopId, allHopExIds)
      if (stEdge && tryAppendEdge(stEdge)) break
    }
  }

  if (inferredEdges.length === 0 && rewiredEdges.length === 0) {
    return { receipt, inferredEdges: [], rewiredEdges: [] }
  }
  return {
    receipt: { ...receipt, causalEdges: [...baseEdges, ...inferredEdges] },
    inferredEdges,
    rewiredEdges,
  }
}

// ---------------------------------------------------------------------------
// R4-C-5 Shared Cited-Records Collector & R4-H-6 Per-Exchange Tenant Privilege
// ---------------------------------------------------------------------------

export interface CitedProvenanceTarget {
  exchangeId: string
  label: string
  /** True for attacker-origin issuance/action roles that MUST be checked even if labeled `arm='control'`. */
  forceCheck: boolean
}

const ORACLE_ATTACKER_ACTION_KEYS = new Set([
  'sourcevalidissuance', 'sourceissuanceexchangeid', 'issuanceexchangeid',
  'replayedacceptance', 'replayedexchangeid', 'replayedacceptanceexchangeid',
  'transferrecord', 'transferexchangeid',
  'primeaction', 'primeactionexchangeid',
  'bledaccess', 'bledaccessexchangeid',
  'batchrequest', 'batchrequestexchangeid',
  'actions', 'actionexchangeids', 'actionsexchangeids', 'actionexchangeid',
  'differentialprobe', 'differentialprobeexchangeid',
  'attackerprobe', 'attackerprobeexchangeid',
  'secondarysuccess', 'secondarysuccessexchangeid',
  'prerevocationbaseline', 'prerevocationbaselineexchangeid',
  'record', 'exchangeid',
])

const ORACLE_READBACK_KEYS = new Set([
  'posttransferreadback', 'posttransferreadbackexchangeid',
  'postmutationreadback', 'postmutationreadbackexchangeid',
  'postimpactreadback', 'postimpactreadbackexchangeid',
  'baselinereadback', 'baselineexchangeid', 'baselinereadbackexchangeid',
  'finalreadback', 'finalexchangeid', 'finalreadbackexchangeid',
])

const ORACLE_CONTROL_OR_VICTIM_KEYS = new Set([
  'tamperedsignaturecontrol', 'tamperedcontrolexchangeid', 'tamperedsigdenialexchangeid',
  'sourcecontroldenied', 'sourcecontrolexchangeid',
  'baselinedeniedcontrol', 'baselinecontrolexchangeid',
  'singleforeigncontroldenied', 'singleforeigncontrolexchangeid',
  'revocationevent', 'revocationeventexchangeid',
  'primarydeniedcheck', 'primarydeniedcheckexchangeid',
  'cleancontrol', 'cleancontrolexchangeid',
  'victimorprimerequest', 'victimprimeexchangeid',
  'prechaincontroldenied', 'prechaincontrolexchangeid',
  'ablationcontroldenied', 'ablationexchangeid',
])

/**
 * R4-C-5: ONE shared cited-records collector across ALL receipt citations — hops, edges,
 * embedded proofReceipts, readbacks, Mode-A failures, AND every exchange ID referenced inside
 * `terminalImpact.oracleInput` / `options.v8OracleInput` — so uncited admin-issued exchanges
 * named only in `oracleInput` can NEVER bypass `verifyAttackerProvenance`.
 */
export function collectCitedReceiptExchanges(
  receipt: CompositeProofReceipt,
  v8OracleInput: Record<string, unknown> | undefined,
  entriesById: ReadonlyMap<string, HostTranscriptEntry>,
): { allIds: Set<string>; extraProvenanceTargets: CitedProvenanceTarget[] } {
  const allIds = new Set<string>()
  const targetsById = new Map<string, CitedProvenanceTarget>()

  const addTarget = (id: string, label: string, forceCheck: boolean): void => {
    const trimmed = id.trim()
    if (!trimmed) return
    allIds.add(trimmed)
    const prev = targetsById.get(trimmed)
    if (!prev || (forceCheck && !prev.forceCheck)) {
      targetsById.set(trimmed, { exchangeId: trimmed, label, forceCheck })
    }
  }

  for (const h of receipt.hops) {
    for (const id of h.exchangeIds) allIds.add(id)
    for (const id of h.proofReceipt?.exchangeIds ?? []) addTarget(id, `hop "${h.hopId}" proofReceipt`, false)
  }
  for (const e of receipt.causalEdges) {
    if (e.kind === 'value_binding') {
      if (e.sourceExchangeId) allIds.add(e.sourceExchangeId)
      if (e.targetExchangeId) allIds.add(e.targetExchangeId)
    } else if (e.kind === 'state_transition_binding') {
      for (const id of e.ablationExchangeIds) allIds.add(id)
    }
  }

  const ti = receipt.terminalImpact
  if (ti.terminalExchangeId) allIds.add(ti.terminalExchangeId)
  for (const id of ti.preChainControlExchangeIds) allIds.add(id)
  for (const id of ti.postChainReadbackExchangeIds) {
    allIds.add(id)
    const e = entriesById.get(id)
    if (e && !stepReadsState(e.step)) addTarget(id, 'cited non-control exchange', false)
  }
  if (ti.modeAFailureExchangeId) addTarget(ti.modeAFailureExchangeId, 'cited non-control exchange', false)
  for (const id of ti.proofReceipt?.exchangeIds ?? []) addTarget(id, 'cited non-control exchange', false)

  const recordOracleRef = (keyName: string, rawId: string): void => {
    const id = rawId.trim()
    if (!id || !entriesById.has(id)) return
    const entry = entriesById.get(id)!
    const lk = keyName.toLowerCase()
    if (ORACLE_ATTACKER_ACTION_KEYS.has(lk)) {
      addTarget(id, `oracleInput "${keyName}"`, true)
    } else if (ORACLE_READBACK_KEYS.has(lk)) {
      allIds.add(id)
      if (!stepReadsState(entry.step)) addTarget(id, `oracleInput "${keyName}"`, false)
    } else if (ORACLE_CONTROL_OR_VICTIM_KEYS.has(lk)) {
      allIds.add(id)
      if (entry.step.arm !== 'control') addTarget(id, `oracleInput "${keyName}"`, false)
    } else {
      addTarget(id, `oracleInput "${keyName}"`, false)
    }
  }

  const walkOracle = (node: unknown, keyName: string, depth: number): void => {
    if (depth > 5 || node == null) return
    if (typeof node === 'string') {
      recordOracleRef(keyName, node)
      return
    }
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 64)) walkOracle(item, keyName, depth + 1)
      return
    }
    if (typeof node === 'object') {
      const obj = node as Record<string, unknown>
      const objId = typeof obj.exchangeId === 'string' ? obj.exchangeId.trim()
        : typeof obj.id === 'string' ? obj.id.trim() : ''
      if (objId && entriesById.has(objId) && keyName) {
        recordOracleRef(keyName, objId)
      }
      for (const [k, v] of Object.entries(obj)) {
        walkOracle(v, k, depth + 1)
      }
    }
  }

  if (ti.oracleInput) walkOracle(ti.oracleInput, '', 0)
  if (v8OracleInput && v8OracleInput !== ti.oracleInput) walkOracle(v8OracleInput, '', 0)

  return { allIds, extraProvenanceTargets: [...targetsById.values()] }
}

const ROUTE_TENANT_SEG_RE = /(?:^|\/)(?:tenants?|orgs?|organizations?|workspaces?|accounts?|merchants?)\/([a-z0-9][a-z0-9._-]{1,63})(?:\/|$)/gi
const QUERY_TENANT_KEYS = new Set([
  'tenant', 'tenantid', 'tenant_id', 'org', 'orgid', 'org_id',
  'organization', 'organizationid', 'organization_id', 'workspace', 'workspaceid', 'workspace_id',
])

export interface PersonaPrivilegeProfile {
  alwaysForbidden: boolean
  isMixedDual: boolean
  adminTenants: ReadonlySet<string>
  lowPrivTenants: ReadonlySet<string>
  allTenants: ReadonlySet<string>
}

/**
 * R4-H-6: Classify a persona's privilege profile from handle, role, and full roleLabel.
 * - `alwaysForbidden`: owner, superadmin, privileged handle, single-tenant admin, dual-admin, or unknown role.
 * - `isMixedDual`: holds `admin` in >=1 tenant AND low-privilege (`member`/`viewer`) in >=1 distinct tenant.
 */
export function parsePersonaPrivilegeProfile(
  actor: string | null,
  role: string | null,
  roleLabel?: string | null,
): PersonaPrivilegeProfile {
  const memberships = roleLabel ? parseRoleMemberships(roleLabel) : []
  const adminTenants = new Set<string>(
    memberships.filter(m => (m.role === 'admin' || m.role === 'owner') && m.tenant).map(m => m.tenant!.toLowerCase()),
  )
  const lowPrivTenants = new Set<string>(
    memberships
      .filter(m => (m.role === 'member' || m.role === 'viewer') && m.tenant && !adminTenants.has(m.tenant.toLowerCase()))
      .map(m => m.tenant!.toLowerCase()),
  )
  const allTenants = new Set<string>([...adminTenants, ...lowPrivTenants])
  const alwaysForbidden = isPrivilegedActorOrRole(actor, role, roleLabel)
  const isMixedDual = !alwaysForbidden && adminTenants.size >= 1 && lowPrivTenants.size >= 1
  return { alwaysForbidden, isMixedDual, adminTenants, lowPrivTenants, allTenants }
}

/** Extract host-attested tenant identifiers from a request route/path and query parameters. */
function extractRouteTenantMarkers(
  rawPathOrRoute: string | null | undefined,
  knownTenants?: ReadonlySet<string>,
): Set<string> {
  const out = new Set<string>()
  const raw = (rawPathOrRoute ?? '').trim()
  if (!raw) return out
  const [pathPart = '', queryPart = ''] = raw.split('?', 2)
  const cleanPath = pathPart.split('#', 1)[0] ?? ''
  ROUTE_TENANT_SEG_RE.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = ROUTE_TENANT_SEG_RE.exec(cleanPath)) !== null) {
    let seg = m[1]!
    try { seg = decodeURIComponent(seg) } catch { /* keep raw */ }
    const norm = seg.trim().toLowerCase()
    if (norm && !isDynamicResourceIdSegment(norm)) out.add(norm)
    else if (norm && knownTenants?.has(norm)) out.add(norm)
  }
  if (knownTenants && knownTenants.size > 0) {
    for (const rawSeg of cleanPath.split('/')) {
      if (!rawSeg) continue
      let seg = rawSeg
      try { seg = decodeURIComponent(rawSeg) } catch { /* keep raw */ }
      const norm = seg.trim().toLowerCase()
      if (knownTenants.has(norm)) out.add(norm)
    }
  }
  if (queryPart) {
    for (const [k, v] of new URLSearchParams(queryPart.split('#', 1)[0]!).entries()) {
      if (QUERY_TENANT_KEYS.has(k.trim().toLowerCase()) && v.trim()) {
        out.add(v.trim().toLowerCase())
      }
    }
  }
  return out
}

export interface ExchangeTenantPrivilegeResult {
  forbidden: boolean
  reason?: string
  resolvedTenant: string | null
}

/**
 * R4-H-6: Resolve the acting tenant of an exec-arm exchange from host route, response markers,
 * and persona/capability tenant map; forbid any mixed-role persona acting in an admin/owner
 * tenant and fail closed whenever the acting tenant is ambiguous.
 */
export function evaluateExchangeTenantPrivilege(
  entry: HostTranscriptEntry,
  profile: PersonaPrivilegeProfile,
  capIdx: CapOriginIndex,
  opts: { isTermHop: boolean; isDualTenantAbac: boolean; allowDualAbacPrimeHop: boolean },
): ExchangeTenantPrivilegeResult {
  if (profile.alwaysForbidden) {
    return { forbidden: true, reason: 'privileged persona/role is forbidden', resolvedTenant: null }
  }
  if (!profile.isMixedDual) {
    return { forbidden: false, resolvedTenant: null }
  }

  const routeTenants = extractRouteTenantMarkers(entry.step.pathAndQuery ?? entry.step.route, profile.allTenants)
  const jsonMarkers = extractTenantMarkers(entry.step.json, entry.step.body)
  const textMarkers = entry.step.json === undefined ? extractCsvOrKvTenantMarkers(entry.step.body) : new Set<string>()
  const respTenants = new Set<string>([...jsonMarkers, ...textMarkers])
  const explicitTargetTenants = new Set<string>([...routeTenants, ...respTenants])

  const capLoginTenants = new Set<string>()
  const rawActor = entry.actorPersona !== undefined ? entry.actorPersona : (entry.step.actor.handle ?? null)
  for (const c of [...(rawActor?.startsWith('cap:') ? [rawActor] : []), ...(entry.consumedCapabilities ?? [])]) {
    const lt = capIdx.loginTenantOf(c)
    if (lt) capLoginTenants.add(lt.trim().toLowerCase())
  }
  const actorDeclaredTenant = entry.step.actor.tenant?.trim().toLowerCase() || null

  // 1. Any explicit route or response tenant matching an admin tenant -> FORBIDDEN (unless explicit dual_tenant_abac priming hop).
  const adminHits = [...explicitTargetTenants].filter(t => profile.adminTenants.has(t))
  if (adminHits.length > 0) {
    if (!opts.isTermHop && opts.allowDualAbacPrimeHop) {
      return { forbidden: false, resolvedTenant: adminHits[0]! }
    }
    return {
      forbidden: true,
      reason: `dual-membership persona holds admin/owner in acting tenant "${adminHits[0]}"`,
      resolvedTenant: adminHits[0]!,
    }
  }

  // 2. Resolve effective target tenant (response-attested markers beat attacker-supplied route/query
  //    params once Check 1 confirmed neither touches an admin tenant); multiple conflicting tenants fail closed.
  const effectiveTargetTenants = respTenants.size > 0 ? respTenants : routeTenants
  if (effectiveTargetTenants.size > 1) {
    return {
      forbidden: true,
      reason: `ambiguous acting tenant (${[...effectiveTargetTenants].sort().join(', ')}) for dual-membership persona`,
      resolvedTenant: null,
    }
  }

  // 3. Single unambiguous host-bound non-admin target tenant -> ALLOWED!
  if (effectiveTargetTenants.size === 1) {
    return { forbidden: false, resolvedTenant: [...effectiveTargetTenants][0]! }
  }

  // 4. Zero route/response tenants -> terminal hops and non-dual_tenant_abac hops ALWAYS fail closed (ambiguous).
  if (opts.isTermHop || !opts.isDualTenantAbac) {
    return {
      forbidden: true,
      reason: 'ambiguous acting tenant (no host-bound route or response tenant) for dual-membership persona',
      resolvedTenant: null,
    }
  }

  // Non-terminal hop of a dual_tenant_abac chain with no route/response tenant: check login/declared tenant.
  const fallbackTenants = capLoginTenants.size > 0
    ? [...capLoginTenants]
    : (actorDeclaredTenant ? [actorDeclaredTenant] : [])
  const fallbackAdminHit = fallbackTenants.find(t => profile.adminTenants.has(t))
  if (fallbackAdminHit) {
    if (opts.allowDualAbacPrimeHop) return { forbidden: false, resolvedTenant: fallbackAdminHit }
    return {
      forbidden: true,
      reason: `dual-membership persona holds admin/owner in acting tenant "${fallbackAdminHit}"`,
      resolvedTenant: fallbackAdminHit,
    }
  }
  const lowHit = fallbackTenants.find(t => profile.lowPrivTenants.has(t))
  if (fallbackTenants.length === 1 && lowHit) {
    return { forbidden: false, resolvedTenant: lowHit }
  }
  return {
    forbidden: true,
    reason: 'ambiguous acting tenant for dual-membership persona',
    resolvedTenant: null,
  }
}
