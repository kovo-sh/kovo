/**
 * Stage 2a: Deterministic Trace Compiler (`src/server/trace-proof-compiler.ts`).
 * Compiles a recorded HTTP trace + `ExploitTraceSubmission` into a Mode-A-compatible
 * TypeScript `kovo_verify` script (`<= 64 KiB`) using `ctx.chain()`. Zero app/route hardcoding.
 */
import { buildTerminalClassContractMap } from './oracle-spec.ts'
import { canonicalNonAuthQuery } from './v8-oracle-hydrate.ts'

export interface RecordedRequestExchange {
  exchangeId: string; origin: string; method: string; pathAndQuery: string; persona?: string
  requestHeaders?: Record<string, string>; requestBody?: string; requestJson?: unknown; followRedirects?: boolean
  status: number; mediaType?: string; responseHeaders?: Record<string, string>; setCookies?: string[]
  responseBody?: string; responseJson?: unknown; timestampMs: number
}
export interface ExploitTraceSubmission {
  title: string; vulnClass: string; oracleFamily?: string; exchangeIds: string[]
  terminalExchangeId?: string; controlExchangeId?: string; readbackExchangeId?: string
  reproNotes?: string; attackerPersona?: string
}
export interface CompiledTraceResult {
  ok: boolean; script?: string; chainId: string; terminalVulnClass: string
  inferredBindings: Array<{ fromStep: number; toStep: number; kind: 'seal' | 'var'; selector: string; target: string }>
  controlSynthesized: boolean; warnings: string[]; uncompilableReasons: string[]
}

type BindingRecord = CompiledTraceResult['inferredBindings'][number]
type SourceKind = 'jsonPath' | 'setCookie' | 'locationQuery' | 'header' | 'jsonUrlQuery'
type SealKind = 'bearer_token' | 'api_token' | 'cookie' | 'header_secret' | 'signed_url' | 'generic_secret'
interface ExtractedSource {
  stepIdx: number; kind: SourceKind; selector: string; value: string
  jsAccess?: string; cookieName?: string; headerName?: string; paramName?: string; fromHash?: boolean; isSecretKey?: boolean; isIdKey?: boolean; isUrlKey?: boolean
}
interface SealSpec { varName: string; slot: string; source: ExtractedSource; kind: SealKind; defaultHeaderName?: string; defaultCookieName?: string }
interface VarSpec { varName: string; source: ExtractedSource }
interface PrimaryCapSpec { capVar: string; target: 'bearer' | 'header' | 'cookie' | 'url'; headerName?: string; cookieName?: string; queryParam?: string }
type CompiledEdge =
  | { kind: 'value_binding'; fromStepIdx: number; toStepIdx: number; capVar?: string; digestVar?: string }
  | { kind: 'state_transition_binding'; fromStepIdx: number; toStepIdx: number; entityExpr: string }
interface StepPlan {
  exchange: RecordedRequestExchange; stepNumber: number; hopId: string
  seals: SealSpec[]; vars: VarSpec[]; primaryCapability?: PrimaryCapSpec; signedUrlCapVar?: string; entityIdExpr?: string
  omitPersona: boolean; forceNoFollowRedirects: boolean; pathExpr: string; deltaPath: string; headersExpr?: string; bodyExpr?: string
  usesDynamicUrlOrBody: boolean; dynamicDepSteps: Set<number>; boundVars: Set<string>; hasSealedUrlOrBodyDep: boolean
}
interface BindingState {
  plans: StepPlan[]; allowedSet: ReadonlySet<string> | undefined; blocked: ReadonlySet<string>; warnings: string[]
  inferredBindings: BindingRecord[]; sealMap: Map<string, SealSpec>; varMap: Map<string, VarSpec>
  valueIndex: Map<string, ExtractedSource>; shortValueIndex: Map<string, ExtractedSource>; sealedValues: Map<string, number>
  edges: CompiledEdge[]; edgeKeys: Map<string, number>; needsSha256: boolean; sealN: number; varN: number
}

const MAX_SCRIPT_BYTES = 64 * 1024
const TERMINAL_CONTRACTS = buildTerminalClassContractMap()
const VALID_ORACLE_FAMILIES = new Set('dual_tenant_abac temporal_revocation economic_conservation cryptographic_scope_replay parser_cache_differential cross_surface_pivot'.split(' '))
const VULN_ALIASES: Readonly<Record<string, string>> = Object.fromEntries(([
  ['dual_tenant_abac', 'cross_tenant_data_access cross_tenant_access tenant_isolation tenant_isolation_bypass multi_tenant_bypass abac_bypass'],
  ['privilege_escalation', 'privesc priv_esc role_escalation vertical_privesc vertical_escalation admin_escalation'],
  ['bola', 'horizontal_privesc horizontal_escalation broken_object_level_authorization'],
  ['bfla', 'broken_function_level_authorization'],
  ['broken_access_control', 'bac access_control_bypass unauthorized_access'],
  ['temporal_revocation', 'revoked_token revoked_session stale_token token_revocation_bypass session_revocation_bypass'],
  ['economic_conservation', 'balance_conservation overcredit double_credit negative_balance coupon_reuse over_refund'],
  ['cryptographic_scope_replay', 'token_replay hmac_forgery signature_forgery scope_replay scope_escalation jwt_confusion'],
  ['parser_cache_differential', 'cache_bleed web_cache_deception web_cache_poisoning request_smuggling path_confusion'],
  ['cross_surface_pivot', 'cross_surface internal_pivot ssrf_pivot'],
  ['forged_settlement', 'settlement_forgery'],
] as const).flatMap(([c, list]) => list.split(' ').map(a => [a, c])))
const HOP_BY_HOP = new Set('host content-length connection keep-alive proxy-connection transfer-encoding te trailer upgrade accept-encoding dnt'.split(' '))
const SKIP_TAINT_HDRS = new Set([...HOP_BY_HOP, ...'authorization cookie proxy-authorization content-type accept accept-language user-agent origin referer cache-control pragma'.split(' ')])
const GENERIC_VALUES = new Set('true false null undefined bearer application/json text/html text/plain utf-8 public private active inactive pending success failed status created updated deleted viewer member admin owner default localhost unknown anonymous system internal external enabled disabled approved rejected completed processing verified'.split(' '))
const SECRET_KEY_RE = /(?:token|secret|jwt|auth|session|cookie|api_?key|access_?key|code|sig|signature|hmac|nonce|ticket|assertion|credential|bearer)/i
const URL_KEY_RE = /(?:url|href|download|redirect|callback)/i
const ID_KEY_RE = /^(?:id|.*_id|.*Id|code|slug|ref|key|handle|job|order|export|invite|token)$/i
const SHORT_SKIP_RE = /^(?:v\d+|0+|1|2|3|ok|no|on|id|en)$/i
const ENTITY_SEG_RE = /^(?=.*\d)[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$/
const UUID_VAL_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const AUTH_HDR_RE = /^(?:authorization|proxy-authorization|cookie|x-api-key|x-auth-token|x-access-token|x-session-token|x-service-token|x-internal-token)$/i
const UNIQUE_KEY_RE = /^(?:email|e_?mail|username|user_?name|handle|slug|org_?slug|tenant_?slug|subdomain|account_?name)$/i
const EMAIL_VAL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/, SIMPLE_ENTITY_ID_RE = /^[a-zA-Z]{2,20}[_-]\d{2,16}$/
const REPEATED_CHAR_RE = /^(.)\1+$/, JS_IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/, READ_ONLY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])
const AUTH_QUERY_KEYS = new Set(['sig', 'signature', 'hmac', 'mac', 'token', 'access_token', 'code', 'state', 'nonce', 'ts', 'timestamp', 'expires', 'exp'])
const ECONOMIC_CONSERVATION_CLASSES = new Set(['economic_conservation', 'conserved_balance', 'ledger_overcredit', 'over_refund', 'double_spend', 'race_condition', 'race', 'race_double_spend', 'race_burst', 'split_refund_ledger_break'])
const RACE_MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH'])

const slugifyChainId = (title: string): string => { const s = title.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 42); return s ? `trace_${s}` : 'trace_chain' }
function normalizeVulnClass(raw: string, oracleFamily: string | undefined, hopCount: number, warnings: string[]) {
  const normOracle = (oracleFamily ?? '').trim().toLowerCase().replace(/[\s-]+/g, '_')
  const validOracleFamily = VALID_ORACLE_FAMILIES.has(normOracle) ? normOracle : undefined
  if (oracleFamily && !validOracleFamily) warnings.push(`Ignoring unrecognized oracleFamily "${oracleFamily}".`)
  const lower = (raw ?? '').trim().toLowerCase(), norm = lower.replace(/[\s-]+/g, '_')
  if (norm === 'cross_tenant_read' && (hopCount >= 2 || validOracleFamily === 'dual_tenant_abac')) return { terminalVulnClass: 'dual_tenant_abac', validOracleFamily }
  if (norm in VULN_ALIASES) return { terminalVulnClass: VULN_ALIASES[norm]!, validOracleFamily }
  if (norm && norm in TERMINAL_CONTRACTS) return { terminalVulnClass: norm, validOracleFamily }
  if (lower && lower in TERMINAL_CONTRACTS) return { terminalVulnClass: lower, validOracleFamily }
  if (validOracleFamily && validOracleFamily in TERMINAL_CONTRACTS) { warnings.push(`Unrecognized vulnClass "${raw}"; mapped to oracleFamily "${validOracleFamily}".`); return { terminalVulnClass: validOracleFamily, validOracleFamily } }
  warnings.push(`Unrecognized vulnClass "${raw}"; defaulted to "broken_access_control".`)
  return { terminalVulnClass: 'broken_access_control', validOracleFamily }
}
function shannonEntropy(v: string): number {
  const m = new Map<string, number>(); for (const c of v) m.set(c, (m.get(c) ?? 0) + 1)
  let h = 0; for (const n of m.values()) { const p = n / v.length; h -= p * Math.log2(p) }
  return h
}
function tryParseJson(raw?: string): unknown {
  if (typeof raw !== 'string') return undefined
  const t = raw.replace(/^\uFEFF/, '').trim()
  if (!t || (t[0] !== '{' && t[0] !== '[')) return undefined
  try { return JSON.parse(t) } catch { return undefined }
}
const getHeaderCI = (headers: Record<string, string> | undefined, name: string): string | undefined =>
  headers ? Object.entries(headers).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1] : undefined

function extractSources(ex: RecordedRequestExchange, stepIdx: number): ExtractedSource[] {
  const out: ExtractedSource[] = [], rawCookies: string[] = Array.isArray(ex.setCookies) ? [...ex.setCookies] : []
  const scHdr = getHeaderCI(ex.responseHeaders, 'set-cookie')
  if (scHdr) for (const ln of scHdr.split(/\r?\n/)) rawCookies.push(...ln.split(/,\s*(?=[!#$%&'*+\-.^_`|~0-9A-Za-z]+=)/))
  const seenCk = new Set<string>()
  for (const entry of rawCookies) {
    const pair = entry.split(';', 1)[0]?.trim() ?? '', eq = pair.indexOf('='), name = eq > 0 ? pair.slice(0, eq).trim() : '', value = eq > 0 ? pair.slice(eq + 1).trim() : ''
    if (name && value && !seenCk.has(`${name}=${value}`)) { seenCk.add(`${name}=${value}`); out.push({ stepIdx, kind: 'setCookie', selector: `setCookie:${name}`, value, cookieName: name, isSecretKey: true }) }
  }
  const loc = getHeaderCI(ex.responseHeaders, 'location')?.trim()
  if (loc) try {
    const u = new URL(loc, 'http://kovo-local.invalid')
    for (const [k, v] of [...u.searchParams.entries(), ...(u.hash.length > 1 ? [...new URLSearchParams(u.hash.slice(1)).entries()] : [])])
      if (v) out.push({ stepIdx, kind: 'locationQuery', selector: `locationQuery:${k}`, value: v, paramName: k, isSecretKey: true })
  } catch { /* ignore malformed Location */ }
  const walk = (node: unknown, jp: string, js: string, depth: number, lastKey: string): void => {
    if (depth > 4 || node === null || node === undefined) return
    if (typeof node === 'string' || typeof node === 'number') {
      const s = String(node).trim(); if (!s || !jp) return
      out.push({ stepIdx, kind: 'jsonPath', selector: jp, value: s, jsAccess: js, isSecretKey: SECRET_KEY_RE.test(lastKey) || SECRET_KEY_RE.test(jp), isIdKey: ID_KEY_RE.test(lastKey), isUrlKey: URL_KEY_RE.test(lastKey) })
      if (typeof node === 'string' && (/^https?:\/\//i.test(s) || (s.startsWith('/') && (s.includes('?') || s.includes('#'))))) {
        try {
          const u = new URL(s, 'http://kovo-local.invalid')
          for (const [k, v] of u.searchParams.entries()) if (v) out.push({ stepIdx, kind: 'jsonUrlQuery', selector: `${jp}?${k}`, value: v, jsAccess: js, paramName: k, fromHash: false, isSecretKey: true })
          if (u.hash.length > 1) for (const [k, v] of new URLSearchParams(u.hash.slice(1)).entries()) if (v) out.push({ stepIdx, kind: 'jsonUrlQuery', selector: `${jp}#${k}`, value: v, jsAccess: js, paramName: k, fromHash: true, isSecretKey: true })
        } catch { /* ignore malformed URL */ }
      }
    } else if (Array.isArray(node)) { for (let i = 0; i < Math.min(node.length, 25); i += 1) walk(node[i], `${jp}[${i}]`, `${js}?.[${i}]`, depth + 1, lastKey) }
    else if (typeof node === 'object') { for (const [k, v] of Object.entries(node as Record<string, unknown>)) walk(v, JS_IDENT_RE.test(k) ? (jp ? `${jp}.${k}` : k) : `${jp}[${JSON.stringify(k)}]`, JS_IDENT_RE.test(k) ? `${js}?.${k}` : `${js}?.[${JSON.stringify(k)}]`, depth + 1, k) }
  }
  const parsedJson = ex.responseJson !== undefined ? ex.responseJson : tryParseJson(ex.responseBody)
  if (parsedJson !== undefined) walk(parsedJson, '', 'ex.json', 0, '')
  for (const [k, rawVal] of Object.entries(ex.responseHeaders ?? {})) {
    const l = k.toLowerCase(), val = rawVal.trim()
    if (!val || (!l.startsWith('x-') && l !== 'authorization' && l !== 'location')) continue
    if (l === 'authorization' && /^bearer\s+/i.test(val)) { const tok = val.replace(/^bearer\s+/i, '').trim(); if (tok) out.push({ stepIdx, kind: 'header', selector: `header:${k}`, value: tok, headerName: k, isSecretKey: true }) }
    out.push({ stepIdx, kind: 'header', selector: `header:${k}`, value: val, headerName: k, isSecretKey: l !== 'location' })
  }
  return out
}

function buildBlockedValues(exchanges: RecordedRequestExchange[], allowed?: string[], attacker?: string, runOrigin?: string): Set<string> {
  const blocked = new Set<string>(GENERIC_VALUES)
  const add = (s?: string) => { const t = s?.trim().toLowerCase(); if (t) blocked.add(t) }
  const addOrig = (o?: string) => { if (!o) return; add(o); try { const u = new URL(o); add(u.host); add(u.hostname) } catch { /* ignore */ } }
  add(attacker); (allowed ?? []).forEach(add); addOrig(runOrigin); exchanges.forEach(e => { add(e.persona); addOrig(e.origin) })
  return blocked
}
const isEligible = (v: string, blocked: ReadonlySet<string>): boolean => { const t = v.trim(); return t.length >= 6 && !t.toLowerCase().includes('[redacted') && !blocked.has(t.toLowerCase()) && !REPEATED_CHAR_RE.test(t) && new Set(t).size >= 3 }
const canSeal = (v: string, blocked: ReadonlySet<string>): boolean => isEligible(v, blocked) && shannonEntropy(v.trim()) >= 1.2
const canSealSource = (src: ExtractedSource, blocked: ReadonlySet<string>): boolean =>
  src.kind === 'jsonUrlQuery' ? (src.value.trim().length >= 8 && isEligible(src.value, blocked) && shannonEntropy(src.value.trim()) >= 1.5) : canSeal(src.value, blocked)
const isShortDynamicId = (src: ExtractedSource, blocked: ReadonlySet<string>): boolean => {
  const t = src.value.trim()
  return src.kind === 'jsonPath' && Boolean(src.isIdKey) && t.length >= 2 && t.length <= 16 && !blocked.has(t.toLowerCase()) && !SHORT_SKIP_RE.test(t) && (/^\d{2,}$/.test(t) || (/[a-z]/i.test(t) && /\d/.test(t)))
}
const isOpaque = (v: string, src: ExtractedSource, blocked: ReadonlySet<string>, sinkKey?: string): boolean => {
  if (!canSealSource(src, blocked)) return false; if (src.kind !== 'jsonPath') return true
  const t = v.trim()
  return t.length >= 12 && (Boolean(src.isSecretKey) || Boolean(sinkKey && SECRET_KEY_RE.test(sinkKey)) || (t.length >= 16 && !SIMPLE_ENTITY_ID_RE.test(t) && shannonEntropy(t) >= 3.0))
}
const buildTemplate = (parts: Array<{ lit?: string; expr?: string }>): string =>
  parts.every(p => p.expr === undefined) ? JSON.stringify(parts.map(p => p.lit ?? '').join(''))
    : `\`${parts.map(p => p.expr !== undefined ? `\${${p.expr}}` : (p.lit ?? '').replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${')).join('')}\``
function renderJsonBindings(node: unknown, prefix: string, resolve: (val: string, path: string) => string | undefined): string {
  if (typeof node === 'string' || typeof node === 'number') return resolve(String(node), prefix) ?? JSON.stringify(node)
  if (node === null || typeof node !== 'object') return JSON.stringify(node)
  if (Array.isArray(node)) return `[${node.map((x, i) => renderJsonBindings(x, `${prefix}[${i}]`, resolve)).join(', ')}]`
  return `{ ${Object.entries(node as Record<string, unknown>).map(([k, v]) => `${JS_IDENT_RE.test(k) ? k : JSON.stringify(k)}: ${renderJsonBindings(v, prefix ? `${prefix}.${k}` : k, resolve)}`).join(', ')} }`
}
function detectUniqueFields(bodyJson: unknown, bound: ReadonlySet<string>): string[] {
  const out: string[] = []
  const walk = (n: unknown, pre: string, d: number): void => {
    if (d > 3 || !n || typeof n !== 'object' || Array.isArray(n)) return
    for (const [k, v] of Object.entries(n as Record<string, unknown>)) {
      const p = pre ? `${pre}.${k}` : k
      if (typeof v === 'string' && !bound.has(p) && (UNIQUE_KEY_RE.test(k) || EMAIL_VAL_RE.test(v.trim()))) out.push(p)
      else if (v && typeof v === 'object') walk(v, p, d + 1)
    }
  }
  walk(bodyJson, '', 0); return out
}
const isSignedUrlValue = (v: string): boolean => {
  const t = v.trim()
  return /^https?:\/\//i.test(t) || (t.startsWith('/') && !t.startsWith('//') && (t.includes('?') || /\/[a-zA-Z0-9._-]{16,}/.test(t)))
}
const isSignedUrlSource = (src: ExtractedSource): boolean =>
  isSignedUrlValue(src.value) || Boolean(src.kind === 'jsonPath' && src.isUrlKey)
const stepJsAccess = (jsAccess: string | undefined, stepVar: string): string =>
  jsAccess ? jsAccess.replace(/^ex\./, `${stepVar}.`) : 'undefined'
function formatSealCall(s: SealSpec, stepVar: string): string {
  const jsExpr = stepJsAccess(s.source.jsAccess, stepVar)
  const sel = s.source.kind === 'jsonPath' ? `jsonPath: ${JSON.stringify(s.source.selector)}`
    : s.source.kind === 'setCookie' ? `setCookie: ${JSON.stringify(s.source.cookieName!)}`
    : s.source.kind === 'locationQuery' ? `locationQuery: ${JSON.stringify(s.source.paramName!)}`
    : s.source.kind === 'jsonUrlQuery'
      ? (s.source.fromHash
          ? `value: new URLSearchParams(new URL(String(${jsExpr} ?? ""), "http://kovo-local.invalid").hash.slice(1)).get(${JSON.stringify(s.source.paramName!)}) ?? ""`
          : `value: new URL(String(${jsExpr} ?? ""), "http://kovo-local.invalid").searchParams.get(${JSON.stringify(s.source.paramName!)}) ?? ""`)
    : `header: ${JSON.stringify(s.source.headerName!)}`
  const f = [`slot: ${JSON.stringify(s.slot)}`, sel, `kind: ${JSON.stringify(s.kind)}`]
  if (s.defaultHeaderName) f.push(`defaultHeaderName: ${JSON.stringify(s.defaultHeaderName)}`)
  if (s.defaultCookieName && s.source.kind !== 'setCookie') f.push(`defaultCookieName: ${JSON.stringify(s.defaultCookieName)}`)
  return `const ${s.varName} = await ch.seal(${stepVar}, { ${f.join(', ')} })`
}
const formatTarget = (origin: string, pathExpr: string, runOrigin?: string, asPathObj = false): string =>
  origin.trim() && (!runOrigin || origin.trim() !== runOrigin.trim())
    ? `{ origin: ${JSON.stringify(origin.trim())}, path: ${pathExpr} }`
    : asPathObj ? `{ path: ${pathExpr} }` : pathExpr
function formatHttpOpts(o: { hopId?: string; method: string; persona?: string; headersExpr?: string; bodyExpr?: string; followRedirectsFalse?: boolean; capability?: PrimaryCapSpec; arm?: 'control'; role?: 'control' | 'setup'; session?: string; entityIdExpr?: string; claimedDelta?: string }): string {
  const f: string[] = []
  if (o.hopId) f.push(`hopId: ${JSON.stringify(o.hopId)}`)
  f.push(`method: ${JSON.stringify(o.method.toUpperCase())}`)
  if (o.persona) f.push(`as: ${JSON.stringify(o.persona)}`)
  if (o.capability) {
    const c = [`handle: ${o.capability.capVar}`, `target: ${JSON.stringify(o.capability.target)}`]
    if (o.capability.headerName) c.push(`headerName: ${JSON.stringify(o.capability.headerName)}`)
    if (o.capability.cookieName) c.push(`cookieName: ${JSON.stringify(o.capability.cookieName)}`)
    if (o.capability.queryParam) c.push(`queryParam: ${JSON.stringify(o.capability.queryParam)}`)
    f.push(`capability: { ${c.join(', ')} }`)
  }
  if (o.headersExpr) f.push(`headers: ${o.headersExpr}`); if (o.bodyExpr) f.push(`body: ${o.bodyExpr}`); if (o.followRedirectsFalse) f.push('followRedirects: false')
  if (o.arm) f.push(`arm: ${JSON.stringify(o.arm)}`); if (o.role) f.push(`role: ${JSON.stringify(o.role)}`); if (o.session) f.push(`session: ${JSON.stringify(o.session)}`)
  if (o.entityIdExpr) f.push(`entityId: ${o.entityIdExpr}`)
  if (o.claimedDelta) f.push(`claimedDelta: ${JSON.stringify(o.claimedDelta)}`)
  return `{ ${f.join(', ')} }`
}
const sanitizeControlHeaders = (headers?: Record<string, string>): string | undefined => {
  const safe = Object.entries(headers ?? {}).filter(([k]) => { const l = k.toLowerCase(); return !HOP_BY_HOP.has(l) && !l.startsWith('sec-fetch-') && !l.startsWith('sec-ch-') && !AUTH_HDR_RE.test(l) })
  return safe.length ? JSON.stringify(Object.fromEntries(safe)) : undefined
}
const normOrigin = (o?: string): string => {
  const t = (o ?? '').trim().replace(/\/+$/, '').toLowerCase()
  if (!t) return ''
  try { return new URL(t).origin.toLowerCase() } catch { return t }
}
const cleanControlPath = (p?: string): string => {
  const raw = (p ?? '').split(/[?#]/, 1)[0] ?? ''
  const withSlash = raw.startsWith('/') ? raw : `/${raw}`
  return withSlash.replace(/\/+$/, '').toLowerCase() || '/'
}
function matchesControlTarget(ctrlEx: RecordedRequestExchange, refEx: RecordedRequestExchange): boolean {
  const co = normOrigin(ctrlEx.origin), ro = normOrigin(refEx.origin)
  if (co && ro && co !== ro) return false
  if ((ctrlEx.method || 'GET').toUpperCase() !== (refEx.method || 'GET').toUpperCase()) return false
  if (cleanControlPath(ctrlEx.pathAndQuery) !== cleanControlPath(refEx.pathAndQuery)) return false
  return canonicalNonAuthQuery(ctrlEx.pathAndQuery) === canonicalNonAuthQuery(refEx.pathAndQuery)
}
function sanitizeControlPath(rawPq: string): string {
  const pq = rawPq?.startsWith('/') ? rawPq : `/${rawPq ?? ''}`, qIdx = pq.indexOf('?'); if (qIdx < 0) return pq
  const base = pq.slice(0, qIdx) || '/'
  const hashIdx = pq.indexOf('#', qIdx + 1)
  const rawQuery = hashIdx >= 0 ? pq.slice(qIdx + 1, hashIdx) : pq.slice(qIdx + 1)
  const kept = [...new URLSearchParams(rawQuery).entries()].filter(([k]) => !AUTH_QUERY_KEYS.has(k.trim().toLowerCase()))
  return kept.length ? `${base}?${new URLSearchParams(kept).toString()}` : base
}
const appendEncodedKv = (parts: Array<{ lit?: string; expr?: string }>, pairs: Array<{ k: string; expr?: string; raw?: string }>): void => {
  pairs.forEach((qp, i) => { if (i > 0) parts.push({ lit: '&' }); if (qp.expr !== undefined) parts.push({ lit: `${encodeURIComponent(qp.k)}=` }, { expr: qp.expr }); else parts.push({ lit: `${encodeURIComponent(qp.k)}=${encodeURIComponent(qp.raw ?? '')}` }) })
}

function getOrCreateSeal(st: BindingState, source: ExtractedSource, kind: SealKind, extra?: { defaultHeaderName?: string; defaultCookieName?: string }): SealSpec {
  const key = `${source.stepIdx}|${source.kind}|${source.selector}|${kind}`, hit = st.sealMap.get(key); if (hit) return hit
  const s: SealSpec = { varName: `cap_${++st.sealN}`, slot: `cap_${st.sealN}`, source, kind, ...extra }
  st.sealMap.set(key, s); st.plans[source.stepIdx]!.seals.push(s)
  if (!st.sealedValues.has(source.value)) st.sealedValues.set(source.value, source.stepIdx)
  if (source.kind === 'locationQuery') st.plans[source.stepIdx]!.forceNoFollowRedirects = true
  return s
}
function getOrCreateVar(st: BindingState, source: ExtractedSource): VarSpec {
  const key = `${source.stepIdx}|${source.kind}|${source.selector}`, hit = st.varMap.get(key); if (hit) return hit
  const v: VarSpec = { varName: `v_${++st.varN}`, source }; st.varMap.set(key, v); st.plans[source.stepIdx]!.vars.push(v); return v
}
function addCompiledEdge(st: BindingState, edge: CompiledEdge): void {
  if (edge.fromStepIdx < 0 || edge.toStepIdx >= st.plans.length || edge.fromStepIdx === edge.toStepIdx) return
  const key = `${edge.fromStepIdx}->${edge.toStepIdx}:${edge.kind}`, idx = st.edgeKeys.get(key)
  if (idx !== undefined) { const prev = st.edges[idx]!; if (edge.kind === 'value_binding' && edge.capVar && prev.kind === 'value_binding' && !prev.capVar) st.edges[idx] = edge; return }
  st.edgeKeys.set(key, st.edges.length); st.edges.push(edge)
}
function bindLeafValue(st: BindingState, plan: StepPlan, src: ExtractedSource, toStepIdx: number, target: string, encode: boolean, preferHandle: boolean): string | undefined {
  const toStep = toStepIdx + 1; plan.usesDynamicUrlOrBody = true; plan.dynamicDepSteps.add(src.stepIdx)
  if (canSealSource(src, st.blocked)) {
    const signedUrl = isSignedUrlSource(src)
    const prevSealStep = st.sealedValues.get(src.value), s = getOrCreateSeal(st, src, signedUrl ? 'signed_url' : 'generic_secret')
    addCompiledEdge(st, { kind: 'value_binding', fromStepIdx: src.stepIdx, toStepIdx, capVar: s.varName })
    if (preferHandle || signedUrl || src.kind !== 'jsonPath' || src.value.trim().length < 8 || (prevSealStep !== undefined && prevSealStep < src.stepIdx)) {
      plan.hasSealedUrlOrBodyDep = true; st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target }); return s.varName
    }
    const v = getOrCreateVar(st, src); plan.boundVars.add(v.varName); st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'var', selector: src.selector, target })
    return encode ? `encodeURIComponent(String(${v.varName}))` : v.varName
  }
  if (src.kind === 'jsonPath') {
    const v = getOrCreateVar(st, src); plan.boundVars.add(v.varName); st.needsSha256 = true
    addCompiledEdge(st, { kind: 'value_binding', fromStepIdx: src.stepIdx, toStepIdx, digestVar: v.varName })
    st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'var', selector: src.selector, target })
    return encode ? `encodeURIComponent(String(${v.varName}))` : v.varName
  }
  return undefined
}

function bindRequestHeaders(st: BindingState, plan: StepPlan, toStepIdx: number, lookup: (val: string) => ExtractedSource | undefined): void {
  const ex = plan.exchange, toStep = toStepIdx + 1, hdrEntries: Array<[string, string]> = [], handled = new Set<string>(), reqHdrs = Object.entries(ex.requestHeaders ?? {})
  for (const [k, v] of reqHdrs) {
    const l = k.toLowerCase()
    if (l === 'authorization') {
      const m = /^bearer\s+(.+)$/i.exec(v.trim()), src = lookup(m ? m[1]! : v) ?? (m ? lookup(v) : undefined)
      if (src && canSealSource(src, st.blocked)) {
        const s = getOrCreateSeal(st, src, 'bearer_token'); plan.primaryCapability = { capVar: s.varName, target: 'bearer' }; plan.omitPersona = true; handled.add('authorization')
        addCompiledEdge(st, { kind: 'value_binding', fromStepIdx: src.stepIdx, toStepIdx, capVar: s.varName })
        st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: 'header:authorization:bearer' })
      }
    } else if (l === 'cookie') {
      for (const seg of v.split(';')) {
        const eq = seg.indexOf('='); if (eq <= 0) continue
        const cName = seg.slice(0, eq).trim(), src = lookup(seg.slice(eq + 1))
        if (src && canSealSource(src, st.blocked)) {
          const s = getOrCreateSeal(st, src, 'cookie', { defaultCookieName: cName })
          if (!plan.primaryCapability) { plan.primaryCapability = { capVar: s.varName, target: 'cookie', cookieName: cName }; plan.omitPersona = true }
          else hdrEntries.push([k, `\`${cName}=\${${s.varName}}\``])
          handled.add('cookie'); addCompiledEdge(st, { kind: 'value_binding', fromStepIdx: src.stepIdx, toStepIdx, capVar: s.varName })
          st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: `cookie:${cName}` }); break
        }
      }
    }
  }
  for (const [k, v] of reqHdrs) {
    const l = k.toLowerCase()
    if (handled.has(l) || HOP_BY_HOP.has(l) || l.startsWith('sec-fetch-') || l.startsWith('sec-ch-')) continue
    if (l === 'authorization' || l === 'cookie' || l === 'proxy-authorization') { if (!ex.persona && !plan.primaryCapability) st.warnings.push(`Step ${plan.hopId} had unlinked literal "${k}" header; stripped for hygiene.`); continue }
    const src = SKIP_TAINT_HDRS.has(l) ? undefined : lookup(v)
    if (src && canSealSource(src, st.blocked)) {
      const s = getOrCreateSeal(st, src, 'header_secret', { defaultHeaderName: k })
      if (!plan.primaryCapability) { plan.primaryCapability = { capVar: s.varName, target: 'header', headerName: k }; if (AUTH_HDR_RE.test(l) || !ex.persona) plan.omitPersona = true }
      else hdrEntries.push([k, s.varName])
      addCompiledEdge(st, { kind: 'value_binding', fromStepIdx: src.stepIdx, toStepIdx, capVar: s.varName })
      st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: `header:${l}` })
    } else hdrEntries.push([k, JSON.stringify(v)])
  }
  if (hdrEntries.length) plan.headersExpr = `{ ${hdrEntries.map(([k, v]) => `${JSON.stringify(k)}: ${v}`).join(', ')} }`
}

function bindStepPlan(st: BindingState, plan: StepPlan, toStepIdx: number, maxProdIdx: number): void {
  const ex = plan.exchange, toStep = toStepIdx + 1
  if (ex.persona && st.allowedSet && !st.allowedSet.has(ex.persona)) st.warnings.push(`Step ${plan.hopId} references persona "${ex.persona}" outside allowedPersonas.`)
  const lookup = (val: string, allowShort = false) => { const t = val.trim(), h = st.valueIndex.get(t) ?? (allowShort ? st.shortValueIndex.get(t) : undefined); return h && h.stepIdx < maxProdIdx ? h : undefined }
  bindRequestHeaders(st, plan, toStepIdx, lookup)

  const rawPq = ex.pathAndQuery?.startsWith('/') ? ex.pathAndQuery : `/${ex.pathAndQuery ?? ''}`
  const qIdx = rawPq.indexOf('?'), rawPath = qIdx >= 0 ? rawPq.slice(0, qIdx) : rawPq, rawQuery = qIdx >= 0 ? rawPq.slice(qIdx + 1) : ''
  const fullUrl = ex.origin ? `${ex.origin.trim().replace(/\/+$/, '')}${rawPq}` : '', urlSrc = (fullUrl ? lookup(fullUrl) : undefined) ?? lookup(rawPq)
  let urlBound = false
  if (urlSrc && canSealSource(urlSrc, st.blocked) && (isSignedUrlSource(urlSrc) || urlSrc.value.startsWith('/'))) {
    const s = getOrCreateSeal(st, urlSrc, 'signed_url')
    plan.signedUrlCapVar = s.varName; plan.pathExpr = s.varName; plan.deltaPath = rawPath || '/'
    plan.usesDynamicUrlOrBody = true; plan.dynamicDepSteps.add(urlSrc.stepIdx); plan.hasSealedUrlOrBodyDep = true; urlBound = true
    addCompiledEdge(st, { kind: 'value_binding', fromStepIdx: urlSrc.stepIdx, toStepIdx, capVar: s.varName })
    st.inferredBindings.push({ fromStep: urlSrc.stepIdx + 1, toStep, kind: 'seal', selector: urlSrc.selector, target: 'url' })
  }
  if (!urlBound) {
    const pathParts: Array<{ lit?: string; expr?: string }> = [], deltaSegs: string[] = []
    rawPath.split('/').forEach((seg, sIdx) => {
      if (sIdx > 0) pathParts.push({ lit: '/' }); if (!seg) { deltaSegs.push(''); return }
      let dec = seg; try { dec = decodeURIComponent(seg) } catch { /* raw */ }
      const src = lookup(dec, sIdx > 1) ?? (dec !== seg ? lookup(seg, sIdx > 1) : undefined)
      const expr = src ? bindLeafValue(st, plan, src, toStepIdx, 'path', true, src.kind !== 'jsonPath' || (isOpaque(src.value, src, st.blocked) && Boolean(src.isSecretKey))) : undefined
      if (expr) { pathParts.push({ expr }); deltaSegs.push(':param') } else { pathParts.push({ lit: seg }); deltaSegs.push(seg) }
    })
    plan.deltaPath = deltaSegs.join('/') || '/'
    if (rawQuery) {
      const qEntries = [...new URLSearchParams(rawQuery).entries()], counts = new Map<string, number>(), kept: Array<{ k: string; expr?: string; raw?: string }> = []
      for (const [k] of qEntries) counts.set(k, (counts.get(k) ?? 0) + 1)
      for (const [k, v] of qEntries) {
        const src = lookup(v, true); if (!src) { kept.push({ k, raw: v }); continue }
        if (canSealSource(src, st.blocked) && (isOpaque(src.value, src, st.blocked, k) || src.kind === 'jsonUrlQuery' || isSignedUrlSource(src))) {
          plan.usesDynamicUrlOrBody = true; plan.dynamicDepSteps.add(src.stepIdx); plan.hasSealedUrlOrBodyDep = true
          const s = getOrCreateSeal(st, src, isSignedUrlSource(src) ? 'signed_url' : 'generic_secret')
          addCompiledEdge(st, { kind: 'value_binding', fromStepIdx: src.stepIdx, toStepIdx, capVar: s.varName })
          if (!plan.primaryCapability && counts.get(k) === 1) plan.primaryCapability = { capVar: s.varName, target: 'url', queryParam: k }
          else kept.push({ k, expr: s.varName })
          st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: `query:${k}` })
        } else { const expr = bindLeafValue(st, plan, src, toStepIdx, `query:${k}`, true, false); kept.push(expr ? { k, expr } : { k, raw: v }) }
      }
      if (kept.length) { pathParts.push({ lit: '?' }); appendEncodedKv(pathParts, kept) }
    }
    plan.pathExpr = buildTemplate(pathParts)
  }

  const bodyJson = ex.requestJson !== undefined ? ex.requestJson : tryParseJson(ex.requestBody), boundBody = new Set<string>()
  if (bodyJson !== undefined) {
    plan.bodyExpr = renderJsonBindings(bodyJson, '', (leaf, fp) => {
      const leafKey = fp.split('.').pop() ?? '', src = lookup(leaf, ID_KEY_RE.test(leafKey)); if (!src) return undefined
      boundBody.add(fp); return bindLeafValue(st, plan, src, toStepIdx, `body:${fp}`, false, src.kind !== 'jsonPath' || isOpaque(src.value, src, st.blocked, leafKey))
    })
    if (/^(?:POST|PUT|PATCH)$/i.test(ex.method)) { const uniq = detectUniqueFields(bodyJson, boundBody); if (uniq.length) st.warnings.push(`Step ${plan.hopId} ${ex.method.toUpperCase()} body has literal unique-creation field(s) [${uniq.join(', ')}]; replay may need fresh values.`) }
  } else if (typeof ex.requestBody === 'string' && ex.requestBody.length > 0) {
    if ((getHeaderCI(ex.requestHeaders, 'content-type') ?? '').toLowerCase().includes('application/x-www-form-urlencoded')) {
      const fp: Array<{ lit?: string; expr?: string }> = []
      const pairs = [...new URLSearchParams(ex.requestBody).entries()].map(([k, v]) => {
        const src = lookup(v, ID_KEY_RE.test(k)), expr = src ? bindLeafValue(st, plan, src, toStepIdx, `body:${k}`, true, src.kind !== 'jsonPath' || isOpaque(src.value, src, st.blocked, k)) : undefined
        return expr ? { k, expr } : { k, raw: v }
      })
      appendEncodedKv(fp, pairs); plan.bodyExpr = buildTemplate(fp)
    } else plan.bodyExpr = JSON.stringify(ex.requestBody)
  }
}

function extractRequestEntities(ex: RecordedRequestExchange, blocked: ReadonlySet<string>): string[] {
  const out: string[] = []
  const add = (v: string) => { const t = v.trim(); if (ENTITY_SEG_RE.test(t) && !blocked.has(t.toLowerCase()) && !SHORT_SKIP_RE.test(t) && !out.includes(t)) out.push(t) }
  const isStructuredId = (t: string): boolean => !/^\d+$/.test(t) && (SIMPLE_ENTITY_ID_RE.test(t) || UUID_VAL_RE.test(t) || /^[a-zA-Z]{2,16}[_-][a-zA-Z0-9_-]*\d[a-zA-Z0-9_-]*$/.test(t))
  const rawPq = ex.pathAndQuery || '/', qIdx = rawPq.indexOf('?')
  const rawPath = qIdx >= 0 ? rawPq.slice(0, qIdx) : rawPq, rawQuery = qIdx >= 0 ? rawPq.slice(qIdx + 1) : ''
  rawPath.split('/').forEach((seg, idx) => { if (idx >= 1 && seg) { try { add(decodeURIComponent(seg)) } catch { add(seg) } } })
  if (rawQuery) {
    for (const [k, v] of new URLSearchParams(rawQuery).entries()) {
      const t = v.trim(); if (ID_KEY_RE.test(k) || isStructuredId(t)) add(t)
    }
  }
  const walkBody = (node: unknown, depth: number, lastKey: string): void => {
    if (depth > 4 || node === null || node === undefined) return
    if (typeof node === 'string' || typeof node === 'number') {
      const t = String(node).trim()
      if (ID_KEY_RE.test(lastKey) || (typeof node === 'string' && isStructuredId(t))) add(t)
    } else if (Array.isArray(node)) {
      for (let i = 0; i < Math.min(node.length, 25); i += 1) walkBody(node[i], depth + 1, lastKey)
    } else if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) walkBody(v, depth + 1, k)
    }
  }
  const body = ex.requestJson !== undefined ? ex.requestJson : tryParseJson(ex.requestBody)
  if (body !== undefined) walkBody(body, 0, '')
  else if (typeof ex.requestBody === 'string' && (getHeaderCI(ex.requestHeaders, 'content-type') ?? '').toLowerCase().includes('application/x-www-form-urlencoded')) {
    for (const [k, v] of new URLSearchParams(ex.requestBody).entries()) {
      const t = v.trim(); if (ID_KEY_RE.test(k) || isStructuredId(t)) add(t)
    }
  }
  return out
}
function computeReachableToTerminal(edges: readonly CompiledEdge[], terminalIdx: number): Set<number> {
  const revAdj = new Map<number, number[]>()
  for (const e of edges) {
    const list = revAdj.get(e.toStepIdx)
    if (list) list.push(e.fromStepIdx)
    else revAdj.set(e.toStepIdx, [e.fromStepIdx])
  }
  const reachable = new Set<number>([terminalIdx]), queue = [terminalIdx]
  while (queue.length > 0) {
    for (const prev of revAdj.get(queue.shift()!) ?? []) {
      if (!reachable.has(prev)) { reachable.add(prev); queue.push(prev) }
    }
  }
  return reachable
}
function linkMutatingStateTransitions(st: BindingState, terminalIdx: number): void {
  const entByStep = st.plans.map(p => extractRequestEntities(p.exchange, st.blocked))
  let reachable = computeReachableToTerminal(st.edges, terminalIdx)
  for (let i = terminalIdx - 1; i >= 0; i -= 1) {
    if (READ_ONLY_METHODS.has(st.plans[i]!.exchange.method.toUpperCase()) || reachable.has(i)) continue
    for (let j = i + 1; j <= terminalIdx; j += 1) {
      if (!reachable.has(j)) continue
      const sharedVar = [...st.plans[i]!.boundVars].find(v => st.plans[j]!.boundVars.has(v))
      const sharedLit = sharedVar ? undefined : entByStep[i]!.find(ent => entByStep[j]!.includes(ent))
      const entityExpr = sharedVar ? `String(${sharedVar})` : sharedLit ? JSON.stringify(sharedLit) : undefined
      if (!entityExpr) continue
      addCompiledEdge(st, { kind: 'state_transition_binding', fromStepIdx: i, toStepIdx: j, entityExpr })
      st.plans[i]!.entityIdExpr ??= entityExpr; st.plans[j]!.entityIdExpr ??= entityExpr
      reachable = computeReachableToTerminal(st.edges, terminalIdx)
      break
    }
  }
}
const mkStepPlan = (ex: RecordedRequestExchange, stepNumber: number, hopId: string): StepPlan => ({
  exchange: ex, stepNumber, hopId, seals: [], vars: [], omitPersona: false,
  forceNoFollowRedirects: ex.followRedirects === false || (ex.status >= 300 && ex.status < 400 && Boolean(getHeaderCI(ex.responseHeaders, 'location'))),
  pathExpr: JSON.stringify(ex.pathAndQuery || '/'), deltaPath: (ex.pathAndQuery || '/').split('?')[0] || '/',
  usesDynamicUrlOrBody: false, dynamicDepSteps: new Set<number>(), boundVars: new Set<string>(), hasSealedUrlOrBodyDep: false,
})
function runBindingPass(causal: RecordedRequestExchange[], terminalIdx: number, explicitReadback: RecordedRequestExchange | undefined, allowedSet: ReadonlySet<string> | undefined, blocked: ReadonlySet<string>, warnings: string[]) {
  const plans = causal.map((ex, i) => mkStepPlan(ex, i + 1, `step_${i + 1}`))
  const st: BindingState = {
    plans, allowedSet, blocked, warnings, inferredBindings: [], sealMap: new Map(), varMap: new Map(),
    valueIndex: new Map(), shortValueIndex: new Map(), sealedValues: new Map(), edges: [], edgeKeys: new Map(), needsSha256: false, sealN: 0, varN: 0,
  }
  for (let i = 0; i < plans.length; i += 1) {
    bindStepPlan(st, plans[i]!, i, i)
    const okResp = causal[i]!.status >= 200 && causal[i]!.status < 400
    for (const src of extractSources(causal[i]!, i)) {
      if (canSealSource(src, blocked)) { if (!st.valueIndex.has(src.value) || (okResp && src.kind !== 'jsonUrlQuery')) st.valueIndex.set(src.value, src) }
      else if (isShortDynamicId(src, blocked) && !st.shortValueIndex.has(src.value)) st.shortValueIndex.set(src.value, src)
    }
  }
  linkMutatingStateTransitions(st, terminalIdx)
  const readbackPlan = explicitReadback ? mkStepPlan(explicitReadback, plans.length + 1, 'readback') : undefined
  if (readbackPlan) bindStepPlan(st, readbackPlan, plans.length, plans.length)
  return { st, readbackPlan }
}
function formatEdgeLine(e: CompiledEdge, plans: readonly StepPlan[]): string {
  const fromHopId = JSON.stringify(plans[e.fromStepIdx]!.hopId), toHopId = JSON.stringify(plans[e.toStepIdx]!.hopId)
  if (e.kind === 'state_transition_binding') return `  ch.stateTransition({ fromHopId: ${fromHopId}, toHopId: ${toHopId}, entityId: ${e.entityExpr}, ablationExchange: ctrl })`
  return e.capVar
    ? `  ch.edge({ kind: "value_binding", fromHopId: ${fromHopId}, toHopId: ${toHopId}, capabilityHandle: ${e.capVar} })`
    : `  ch.edge({ kind: "value_binding", fromHopId: ${fromHopId}, toHopId: ${toHopId}, valueDigest: await _sha256(${e.digestVar}) })`
}
function collapseTrailingRaceExchanges(
  causal: RecordedRequestExchange[], terminalIdx: number, explicitTerminal: RecordedRequestExchange | undefined,
  explicitReadback: RecordedRequestExchange | undefined, submission: ExploitTraceSubmission,
): { causal: RecordedRequestExchange[]; terminalIdx: number; explicitReadback: RecordedRequestExchange | undefined; raceConcurrency: number } {
  const prelim = normalizeVulnClass(submission.vulnClass, submission.oracleFamily, causal.length, [])
  if (prelim.validOracleFamily !== 'economic_conservation' && !ECONOMIC_CONSERVATION_CLASSES.has(prelim.terminalVulnClass)) {
    return { causal, terminalIdx, explicitReadback, raceConcurrency: 0 }
  }
  let list = causal, idx = terminalIdx, rb = explicitReadback
  if (!rb && !explicitTerminal && list.length >= 3) {
    const last = list[list.length - 1]!, prev = list[list.length - 2]!
    if (READ_ONLY_METHODS.has((last.method || 'GET').toUpperCase()) && last.status >= 200 && last.status < 300 && RACE_MUTATING_METHODS.has((prev.method || '').toUpperCase())) {
      let k = list.length - 2
      while (k > 0 && matchesControlTarget(list[k - 1]!, prev)) k -= 1
      if (list.length - 1 - k >= 2) { rb = last; list = list.slice(0, -1); idx = list.length - 1 }
    }
  }
  const term = list[idx]!
  if (!RACE_MUTATING_METHODS.has((term.method || '').toUpperCase())) return { causal: list, terminalIdx: idx, explicitReadback: rb, raceConcurrency: 0 }
  let start = idx, end = idx
  while (start > 0 && matchesControlTarget(list[start - 1]!, term)) start -= 1
  while (end + 1 < list.length && matchesControlTarget(list[end + 1]!, term)) end += 1
  const count = end - start + 1
  if (count < 2) return { causal: list, terminalIdx: idx, explicitReadback: rb, raceConcurrency: 0 }
  const group = list.slice(start, end + 1), rep = group.find(e => e.status >= 200 && e.status < 300) ?? group[0]!
  if (!rb && end + 1 < list.length) {
    const after = list.slice(end + 1).find(e => READ_ONLY_METHODS.has((e.method || 'GET').toUpperCase()) && e.status >= 200 && e.status < 300)
    if (after) rb = after
  }
  return {
    causal: [...list.slice(0, start), rep, ...list.slice(end + 1).filter(e => e.exchangeId !== rb?.exchangeId)],
    terminalIdx: start, explicitReadback: rb, raceConcurrency: Math.min(10, count),
  }
}
function formatRaceCall(p: StepPlan, concurrency: number, hasDynPreRb: boolean, runOrigin?: string): string {
  const reqFields: string[] = [], orig = p.exchange.origin.trim()
  if (orig && (!runOrigin || orig !== runOrigin.trim())) reqFields.push(`origin: ${JSON.stringify(orig)}`)
  reqFields.push(`path: ${p.pathExpr}`, `method: ${JSON.stringify((p.exchange.method || 'POST').toUpperCase())}`)
  if (!p.omitPersona && p.exchange.persona?.trim()) reqFields.push(`as: ${JSON.stringify(p.exchange.persona.trim())}`)
  if (p.primaryCapability) {
    const c = [`handle: ${p.primaryCapability.capVar}`, `target: ${JSON.stringify(p.primaryCapability.target)}`]
    if (p.primaryCapability.headerName) c.push(`headerName: ${JSON.stringify(p.primaryCapability.headerName)}`)
    if (p.primaryCapability.cookieName) c.push(`cookieName: ${JSON.stringify(p.primaryCapability.cookieName)}`)
    if (p.primaryCapability.queryParam) c.push(`queryParam: ${JSON.stringify(p.primaryCapability.queryParam)}`)
    reqFields.push(`capability: { ${c.join(', ')} }`)
  }
  if (p.headersExpr) reqFields.push(`headers: ${p.headersExpr}`)
  if (p.bodyExpr) reqFields.push(`body: ${p.bodyExpr}`)
  if (p.forceNoFollowRedirects) reqFields.push('followRedirects: false')
  const raceFields = [
    `hopId: ${JSON.stringify(p.hopId)}`, `request: { ${reqFields.join(', ')} }`, `concurrency: ${concurrency}`,
    ...(p.entityIdExpr ? [`entityId: ${p.entityIdExpr}`] : []), ...(hasDynPreRb ? ['baseline: preRb'] : []),
    `claimedDelta: ${JSON.stringify(`${p.exchange.method.toUpperCase()} ${p.deltaPath}`)}`,
  ]
  return `ch.race({ ${raceFields.join(', ')} })`
}

export function compileTraceToKovoVerifyScript(input: {
  submission: ExploitTraceSubmission; exchanges: RecordedRequestExchange[]; allowedPersonas?: string[]; runOrigin?: string
}): CompiledTraceResult {
  const { submission, exchanges, allowedPersonas, runOrigin } = input
  const warnings: string[] = [], uncompilableReasons: string[] = [], chainId = slugifyChainId(submission.title || 'trace')
  const fail = (reason: string, n = 0): CompiledTraceResult => ({
    ok: false, chainId, terminalVulnClass: normalizeVulnClass(submission.vulnClass, submission.oracleFamily, n, warnings).terminalVulnClass,
    inferredBindings: [], controlSynthesized: false, warnings, uncompilableReasons: [reason],
  })
  if (!Array.isArray(exchanges) || !exchanges.length) return fail('No recorded exchanges provided.')
  const byId = new Map(exchanges.map(e => [e.exchangeId, e]))
  const explicitControl = submission.controlExchangeId ? byId.get(submission.controlExchangeId) : undefined
  if (submission.controlExchangeId && !explicitControl) warnings.push(`controlExchangeId "${submission.controlExchangeId}" not found; synthesizing clean control.`)
  let explicitReadback = submission.readbackExchangeId ? byId.get(submission.readbackExchangeId) : undefined
  if (submission.readbackExchangeId && !explicitReadback) warnings.push(`readbackExchangeId "${submission.readbackExchangeId}" not found in exchanges.`)
  const explicitTerminal = submission.terminalExchangeId ? byId.get(submission.terminalExchangeId) : undefined
  if (submission.terminalExchangeId && !explicitTerminal) return fail(`Terminal exchange "${submission.terminalExchangeId}" not found in recorded exchanges.`, exchanges.length)

  const excluded = new Set([explicitControl, explicitReadback].filter((e): e is RecordedRequestExchange => Boolean(e && e.exchangeId !== explicitTerminal?.exchangeId)).map(e => e.exchangeId))
  let causal: RecordedRequestExchange[] = []
  const seen = new Set<string>()
  const ordered = submission.exchangeIds?.length
    ? submission.exchangeIds.map(id => { const ex = byId.get(id); if (!ex) warnings.push(`Exchange "${id}" in submission.exchangeIds was not found.`); return ex }).filter((e): e is RecordedRequestExchange => Boolean(e))
    : [...exchanges].sort((a, b) => a.timestampMs - b.timestampMs)
  for (const ex of ordered) if (!seen.has(ex.exchangeId) && !excluded.has(ex.exchangeId)) { seen.add(ex.exchangeId); causal.push(ex) }
  if (explicitTerminal && !seen.has(explicitTerminal.exchangeId)) causal.push(explicitTerminal)
  if (!causal.length) return fail('No causal exchanges remain to compile.')

  let terminalIdx = explicitTerminal ? causal.findIndex(e => e.exchangeId === explicitTerminal.exchangeId) : causal.length - 1
  const collapsed = collapseTrailingRaceExchanges(causal, terminalIdx, explicitTerminal, explicitReadback, submission)
  causal = collapsed.causal; terminalIdx = collapsed.terminalIdx; explicitReadback = collapsed.explicitReadback
  const terminalEx = causal[terminalIdx]!, raceConcurrency = collapsed.raceConcurrency
  const allowedSet = allowedPersonas?.length ? new Set(allowedPersonas) : undefined
  const attackerPersona = (submission.attackerPersona?.trim() || causal[0]?.persona?.trim() || causal.find(e => e.persona?.trim())?.persona?.trim()) || undefined
  if (attackerPersona && allowedSet && !allowedSet.has(attackerPersona)) warnings.push(`Base attackerPersona "${attackerPersona}" is not in allowedPersonas.`)
  const blocked = buildBlockedValues(exchanges, allowedPersonas, attackerPersona, runOrigin)

  const passWarnings: string[] = []
  let { st, readbackPlan } = runBindingPass(causal, terminalIdx, explicitReadback, allowedSet, blocked, passWarnings)
  const reachable = computeReachableToTerminal(st.edges, terminalIdx)
  const prunedPollsBy202Id = new Map<string, RecordedRequestExchange>()
  for (let i = 0; i < causal.length; i += 1) {
    if (!reachable.has(i)) {
      const ex = causal[i]!, m = ex.method.toUpperCase(), kind = READ_ONLY_METHODS.has(m) ? 'unlinked read-only recon' : 'unreachable'
      warnings.push(`pruned ${kind} exchange "${ex.exchangeId}" (${m} ${ex.pathAndQuery || '/'})`)
      if (m === 'GET' && ex.status === 200) {
        for (const depIdx of st.plans[i]!.dynamicDepSteps) {
          if (reachable.has(depIdx) && causal[depIdx]!.status === 202) prunedPollsBy202Id.set(causal[depIdx]!.exchangeId, ex)
        }
      }
    }
  }
  if (reachable.size < causal.length) {
    causal = causal.filter((_, i) => reachable.has(i)); terminalIdx = causal.findIndex(e => e.exchangeId === terminalEx.exchangeId)
    ;({ st, readbackPlan } = runBindingPass(causal, terminalIdx, explicitReadback, allowedSet, blocked, warnings))
  } else warnings.push(...passWarnings)

  const asyncPollsByStep = new Map<number, StepPlan>()
  for (let i = 0; i < st.plans.length; i += 1) {
    if (causal[i]!.status !== 202 || (i >= st.plans.length - 1 && !readbackPlan)) continue
    const pollEx = prunedPollsBy202Id.get(causal[i]!.exchangeId)
    if (!pollEx) continue
    const pollPlan = mkStepPlan(pollEx, st.plans.length + 1, `async_poll_${i + 1}`), prevBindLen = st.inferredBindings.length
    bindStepPlan(st, pollPlan, st.plans.length, i + 1)
    st.inferredBindings.length = prevBindLen
    asyncPollsByStep.set(i, pollPlan)
  }

  const { terminalVulnClass, validOracleFamily } = normalizeVulnClass(submission.vulnClass, submission.oracleFamily, causal.length, warnings)
  const { plans } = st, termPlan = plans[terminalIdx]!
  const isTerminalMutation = !READ_ONLY_METHODS.has((terminalEx.method || 'GET').toUpperCase())
  const explicitControlMatches = Boolean(
    explicitControl && (
      matchesControlTarget(explicitControl, terminalEx)
      || (isTerminalMutation && readbackPlan && matchesControlTarget(explicitControl, readbackPlan.exchange))
    ),
  )
  if (explicitControl && !explicitControlMatches) {
    warnings.push(`Ignoring mismatched controlExchangeId "${explicitControl.exchangeId}" (${explicitControl.method} ${explicitControl.pathAndQuery || '/'}); deriving clean control from terminal exchange.`)
  }
  const effectiveControl = explicitControlMatches ? explicitControl : undefined
  const isEconomicConservation = validOracleFamily === 'economic_conservation' || ECONOMIC_CONSERVATION_CLASSES.has(terminalVulnClass)
  const hasStateTransitionEdge = st.edges.some(e => e.kind === 'state_transition_binding')
  const emitBaselineReadback = Boolean(readbackPlan && isEconomicConservation)
  const skipSynthEconCtrl = Boolean(emitBaselineReadback && !effectiveControl && !hasStateTransitionEdge && isTerminalMutation)
  const controlSynthesized = !effectiveControl && !skipSynthEconCtrl
  let ctrlAfterIdx = -1, ctrlUsesDyn = false
  if (controlSynthesized && termPlan.usesDynamicUrlOrBody) {
    const deps = [...termPlan.dynamicDepSteps].sort((a, b) => a - b), maxDep = deps[deps.length - 1] ?? -1
    if (maxDep >= 0 && maxDep < terminalIdx && !termPlan.hasSealedUrlOrBodyDep && plans.slice(0, maxDep + 1).every(p => READ_ONLY_METHODS.has(p.exchange.method.toUpperCase()))) {
      ctrlAfterIdx = maxDep; ctrlUsesDyn = true
      warnings.push(`Synthesized clean control depends on dynamic value(s) from read-only hop(s) (${deps.map(d => `step_${d + 1}`).join(', ')}); placed after step_${maxDep + 1}.`)
    } else warnings.push('Synthesized clean control targets a terminal request with dynamic value(s) from mutating/sealed hop(s); verify control idempotency on replay.')
  }

  const lines: string[] = ['export default async function (ctx) {', `  const ch = ctx.chain(${JSON.stringify(chainId)}, ${JSON.stringify(terminalVulnClass)})`]
  if (st.needsSha256) lines.push('  const _sha256 = async (s) => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(s)))), b => b.toString(16).padStart(2, "0")).join("")')
  const emitCtrl = (): void => {
    const srcEx = effectiveControl ?? terminalEx, cBodyJson = srcEx.requestJson !== undefined ? srcEx.requestJson : tryParseJson(srcEx.requestBody)
    const cBody = (!effectiveControl && ctrlUsesDyn) ? termPlan.bodyExpr : (cBodyJson !== undefined ? JSON.stringify(cBodyJson) : (srcEx.requestBody ? JSON.stringify(srcEx.requestBody) : undefined))
    const cPath = (!effectiveControl && ctrlUsesDyn) ? termPlan.pathExpr : JSON.stringify(effectiveControl ? (srcEx.pathAndQuery || '/') : sanitizeControlPath(srcEx.pathAndQuery || '/'))
    lines.push(`  const ctrl = await ch.control(${formatTarget(srcEx.origin, cPath, runOrigin)}, ${formatHttpOpts({ method: srcEx.method || 'GET', persona: effectiveControl ? (effectiveControl.persona?.trim() || attackerPersona) : attackerPersona, headersExpr: sanitizeControlHeaders(srcEx.requestHeaders), bodyExpr: cBody, session: 'ctrl_clean' })})`)
  }
  const planOpts = (p: StepPlan, fallbackPersona?: string, stepMeta?: { hopId: string; claimedDelta: string }, role?: 'control' | 'setup') => formatHttpOpts({ ...(stepMeta ?? {}), method: p.exchange.method || 'GET', persona: p.omitPersona ? undefined : (p.exchange.persona?.trim() || fallbackPersona), headersExpr: p.headersExpr, bodyExpr: p.bodyExpr, followRedirectsFalse: p.forceNoFollowRedirects, capability: p.primaryCapability, ...(role ? { role } : {}), entityIdExpr: p.entityIdExpr })

  const dynPreRb = Boolean(emitBaselineReadback && readbackPlan && raceConcurrency >= 2 && readbackPlan.usesDynamicUrlOrBody)
  if (!skipSynthEconCtrl && ctrlAfterIdx < 0) emitCtrl()
  if (emitBaselineReadback && readbackPlan && !dynPreRb) {
    const rbEx = readbackPlan.exchange
    const rbTarget = formatTarget(rbEx.origin, JSON.stringify(sanitizeControlPath(rbEx.pathAndQuery || '/')), runOrigin)
    const rbOpts = formatHttpOpts({ method: rbEx.method || 'GET', persona: rbEx.persona?.trim() || attackerPersona, headersExpr: sanitizeControlHeaders(rbEx.requestHeaders) })
    lines.push(`  await ch.readback(${rbTarget}, ${rbOpts})`)
  }
  for (let i = 0; i < plans.length; i += 1) {
    const p = plans[i]!, stepVar = `step_${p.stepNumber}`, isRaceStep = i === terminalIdx && raceConcurrency >= 2
    if (isRaceStep && dynPreRb && readbackPlan) {
      lines.push(`  const preRb = await ctx.http_send(${formatTarget(readbackPlan.exchange.origin, readbackPlan.pathExpr, runOrigin, Boolean(readbackPlan.signedUrlCapVar))}, ${planOpts(readbackPlan, attackerPersona, undefined, 'control')})`)
    }
    lines.push(
      isRaceStep
        ? `  const ${stepVar} = await ${formatRaceCall(p, raceConcurrency, dynPreRb, runOrigin)}`
        : `  const ${stepVar} = await ch.step(${formatTarget(p.exchange.origin, p.pathExpr, runOrigin, Boolean(p.signedUrlCapVar))}, ${planOpts(p, undefined, { hopId: p.hopId, claimedDelta: `${p.exchange.method.toUpperCase()} ${p.deltaPath}` })})`,
      ...p.seals.map(s => `  ${formatSealCall(s, stepVar)}`),
      ...p.vars.map(v => `  const ${v.varName} = ${stepJsAccess(v.source.jsAccess, stepVar)}`),
      ...st.edges.filter(e => e.toStepIdx === i).map(e => formatEdgeLine(e, plans)),
    )
    if (!isRaceStep && p.exchange.status === 202 && (i < plans.length - 1 || Boolean(readbackPlan))) {
      lines.push(`  if (${stepVar}.status === 202) await new Promise((r) => setTimeout(r, 400))`)
      const pollPlan = asyncPollsByStep.get(i)
      if (pollPlan) lines.push(`  if (${stepVar}.status === 202) await ctx.http_send(${formatTarget(pollPlan.exchange.origin, pollPlan.pathExpr, runOrigin, Boolean(pollPlan.signedUrlCapVar))}, ${planOpts(pollPlan, attackerPersona, undefined, 'setup')})`)
    }
    if (!skipSynthEconCtrl && ctrlAfterIdx === i) emitCtrl()
  }
  if (readbackPlan) lines.push(`  const rb = await ch.readback(${formatTarget(readbackPlan.exchange.origin, readbackPlan.pathExpr, runOrigin, Boolean(readbackPlan.signedUrlCapVar))}, ${planOpts(readbackPlan, attackerPersona)})`)

  const prove = [
    `terminalHopId: ${JSON.stringify(termPlan.hopId)}`, `terminalExchange: ${raceConcurrency >= 2 ? `step_${termPlan.stepNumber}.results?.[0]` : `step_${termPlan.stepNumber}`}`,
    ...(!skipSynthEconCtrl ? ['control: ctrl'] : []),
    ...(readbackPlan ? ['readback: rb'] : []), ...(validOracleFamily ? [`oracleFamily: ${JSON.stringify(validOracleFamily)}`] : []),
    `claimedImpact: ${JSON.stringify((submission.reproNotes?.trim() || submission.title || terminalVulnClass).slice(0, 240))}`,
  ]
  lines.push(
    `  const proof = await ch.prove({ ${prove.join(', ')} })`,
    `  return ctx.result({ title: ${JSON.stringify((submission.title || 'Compiled trace proof').slice(0, 300))}, severity: "high", description: proof.reason || ${JSON.stringify((submission.reproNotes?.trim() || submission.title || 'Compiled trace verification').slice(0, 500))} })`,
    '}',
  )
  const script = `${lines.join('\n')}\n`, bytes = Buffer.byteLength(script, 'utf8')
  if (bytes > MAX_SCRIPT_BYTES) { uncompilableReasons.push(`Compiled script exceeds 64 KiB limit (${bytes} bytes).`); return { ok: false, chainId, terminalVulnClass, inferredBindings: st.inferredBindings, controlSynthesized, warnings, uncompilableReasons } }
  return { ok: true, script, chainId, terminalVulnClass, inferredBindings: st.inferredBindings, controlSynthesized, warnings, uncompilableReasons }
}
