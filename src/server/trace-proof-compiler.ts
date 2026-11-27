/**
 * Stage 2a: Deterministic Trace Compiler (`src/server/trace-proof-compiler.ts`).
 * Compiles a recorded HTTP trace + `ExploitTraceSubmission` into a Mode-A-compatible
 * TypeScript `kovo_verify` script (`<= 64 KiB`) using `ctx.chain()`. Zero app/route hardcoding.
 */
import { buildTerminalClassContractMap } from './oracle-spec.ts'

export interface RecordedRequestExchange {
  exchangeId: string
  origin: string
  method: string
  pathAndQuery: string
  persona?: string
  requestHeaders?: Record<string, string>
  requestBody?: string
  requestJson?: unknown
  followRedirects?: boolean
  status: number
  mediaType?: string
  responseHeaders?: Record<string, string>
  setCookies?: string[]
  responseBody?: string
  responseJson?: unknown
  timestampMs: number
}

export interface ExploitTraceSubmission {
  title: string
  vulnClass: string
  oracleFamily?: string
  exchangeIds: string[]
  terminalExchangeId?: string
  controlExchangeId?: string
  readbackExchangeId?: string
  reproNotes?: string
  attackerPersona?: string
}

export interface CompiledTraceResult {
  ok: boolean
  script?: string
  chainId: string
  terminalVulnClass: string
  inferredBindings: Array<{ fromStep: number; toStep: number; kind: 'seal' | 'var'; selector: string; target: string }>
  controlSynthesized: boolean
  warnings: string[]
  uncompilableReasons: string[]
}

type BindingRecord = CompiledTraceResult['inferredBindings'][number]
type SourceKind = 'jsonPath' | 'setCookie' | 'locationQuery' | 'header'
type SealKind = 'bearer_token' | 'api_token' | 'cookie' | 'header_secret' | 'generic_secret'
interface ExtractedSource {
  stepIdx: number; kind: SourceKind; selector: string; value: string
  jsAccess?: string; cookieName?: string; headerName?: string; paramName?: string; isSecretKey?: boolean
}
interface SealSpec {
  varName: string; slot: string; source: ExtractedSource; kind: SealKind
  defaultHeaderName?: string; defaultCookieName?: string
}
interface VarSpec { varName: string; source: ExtractedSource }
interface PrimaryCapSpec {
  capVar: string; target: 'bearer' | 'header' | 'cookie' | 'url'
  headerName?: string; cookieName?: string; queryParam?: string
}
interface StepPlan {
  exchange: RecordedRequestExchange; stepNumber: number; hopId: string
  seals: SealSpec[]; vars: VarSpec[]; primaryCapability?: PrimaryCapSpec
  omitPersona: boolean; forceNoFollowRedirects: boolean; pathExpr: string; deltaPath: string
  headersExpr?: string; bodyExpr?: string
  usesDynamicUrlOrBody: boolean; dynamicDepSteps: Set<number>; hasSealedUrlOrBodyDep: boolean
}

const MAX_SCRIPT_BYTES = 64 * 1024
const TERMINAL_CONTRACTS = buildTerminalClassContractMap()
const VALID_ORACLE_FAMILIES = new Set('dual_tenant_abac temporal_revocation economic_conservation cryptographic_scope_replay parser_cache_differential cross_surface_pivot'.split(' '))
const VULN_ALIASES: Readonly<Record<string, string>> = Object.fromEntries(
  ([
    ['dual_tenant_abac', 'cross_tenant_data_access cross_tenant_access tenant_isolation tenant_isolation_bypass multi_tenant_bypass abac_bypass'],
    ['privilege_escalation', 'privesc priv_esc role_escalation vertical_privesc vertical_escalation admin_escalation'],
    ['bola', 'horizontal_privesc horizontal_escalation broken_object_level_authorization'],
    ['bfla', 'broken_function_level_authorization'],
    ['broken_access_control', 'bac access_control_bypass unauthorized_access'],
    ['temporal_revocation', 'revoked_token revoked_session stale_token token_revocation_bypass session_revocation_bypass'],
    ['economic_conservation', 'balance_conservation overcredit double_credit negative_balance coupon_reuse'],
    ['cryptographic_scope_replay', 'token_replay hmac_forgery signature_forgery scope_replay scope_escalation jwt_confusion'],
    ['parser_cache_differential', 'cache_bleed web_cache_deception web_cache_poisoning request_smuggling path_confusion'],
    ['cross_surface_pivot', 'cross_surface internal_pivot ssrf_pivot'],
    ['forged_settlement', 'settlement_forgery'],
  ] as const).flatMap(([canonical, list]) => list.split(' ').map(alias => [alias, canonical])),
)
const HOP_BY_HOP = new Set('host content-length connection keep-alive proxy-connection transfer-encoding te trailer upgrade accept-encoding dnt'.split(' '))
const SKIP_TAINT_HDRS = new Set([...HOP_BY_HOP, ...'authorization cookie proxy-authorization content-type accept accept-language user-agent origin referer cache-control pragma'.split(' ')])
const GENERIC_VALUES = new Set('true false null undefined bearer application/json text/html text/plain utf-8 public private active inactive pending success failed status created updated deleted viewer member admin owner default localhost unknown anonymous system internal external enabled disabled approved rejected completed processing verified'.split(' '))
const SECRET_KEY_RE = /(?:token|secret|jwt|auth|session|cookie|api_?key|access_?key|code|sig|signature|hmac|nonce|ticket|assertion|credential|bearer)/i
const AUTH_HDR_RE = /^(?:authorization|proxy-authorization|cookie|x-api-key|x-auth-token|x-access-token|x-session-token|x-service-token|x-internal-token)$/i
const UNIQUE_KEY_RE = /^(?:email|e_?mail|username|user_?name|handle|slug|org_?slug|tenant_?slug|subdomain|account_?name)$/i
const EMAIL_VAL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/
const SIMPLE_ENTITY_ID_RE = /^[a-zA-Z]{2,20}[_-]\d{2,16}$/
const REPEATED_CHAR_RE = /^(.)\1+$/
const JS_IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/
const READ_ONLY_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

const slugifyChainId = (title: string): string => {
  const s = title.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 42)
  return s ? `trace_${s}` : 'trace_chain'
}
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
    const pair = entry.split(';', 1)[0]?.trim() ?? '', eq = pair.indexOf('=')
    const name = eq > 0 ? pair.slice(0, eq).trim() : '', value = eq > 0 ? pair.slice(eq + 1).trim() : ''
    if (name && value && !seenCk.has(`${name}=${value}`)) { seenCk.add(`${name}=${value}`); out.push({ stepIdx, kind: 'setCookie', selector: `setCookie:${name}`, value, cookieName: name, isSecretKey: true }) }
  }
  const loc = getHeaderCI(ex.responseHeaders, 'location')?.trim()
  if (loc) {
    try {
      const u = new URL(loc, 'http://kovo-local.invalid')
      const pairs = [...u.searchParams.entries(), ...(u.hash.length > 1 ? [...new URLSearchParams(u.hash.slice(1)).entries()] : [])]
      for (const [k, v] of pairs) if (v) out.push({ stepIdx, kind: 'locationQuery', selector: `locationQuery:${k}`, value: v, paramName: k, isSecretKey: true })
    } catch { /* ignore malformed Location */ }
  }
  const walk = (node: unknown, jp: string, js: string, depth: number, lastKey: string): void => {
    if (depth > 4 || node === null || node === undefined) return
    if (typeof node === 'string' || typeof node === 'number') {
      const s = String(node).trim()
      if (s && jp) out.push({ stepIdx, kind: 'jsonPath', selector: jp, value: s, jsAccess: js, isSecretKey: SECRET_KEY_RE.test(lastKey) || SECRET_KEY_RE.test(jp) })
    } else if (Array.isArray(node)) {
      for (let i = 0; i < Math.min(node.length, 25); i += 1) walk(node[i], `${jp}[${i}]`, `${js}?.[${i}]`, depth + 1, lastKey)
    } else if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
        walk(v, JS_IDENT_RE.test(k) ? (jp ? `${jp}.${k}` : k) : `${jp}[${JSON.stringify(k)}]`, JS_IDENT_RE.test(k) ? `${js}?.${k}` : `${js}?.[${JSON.stringify(k)}]`, depth + 1, k)
      }
    }
  }
  const parsedJson = ex.responseJson !== undefined ? ex.responseJson : tryParseJson(ex.responseBody)
  if (parsedJson !== undefined) walk(parsedJson, '', 'ex.json', 0, '')
  for (const [k, rawVal] of Object.entries(ex.responseHeaders ?? {})) {
    const l = k.toLowerCase(), val = rawVal.trim()
    if (!val || (!l.startsWith('x-') && l !== 'authorization' && l !== 'location')) continue
    if (l === 'authorization' && /^bearer\s+/i.test(val)) {
      const tok = val.replace(/^bearer\s+/i, '').trim()
      if (tok) out.push({ stepIdx, kind: 'header', selector: `header:${k}`, value: tok, headerName: k, isSecretKey: true })
    }
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
const isEligible = (v: string, blocked: ReadonlySet<string>): boolean => {
  const t = v.trim(); return t.length >= 6 && !t.toLowerCase().includes('[redacted') && !blocked.has(t.toLowerCase()) && !REPEATED_CHAR_RE.test(t) && new Set(t).size >= 3
}
const canSeal = (v: string, blocked: ReadonlySet<string>): boolean => isEligible(v, blocked) && shannonEntropy(v.trim()) >= 1.2
const isOpaque = (v: string, src: ExtractedSource, blocked: ReadonlySet<string>, sinkKey?: string): boolean => {
  if (!canSeal(v, blocked)) return false
  if (src.kind !== 'jsonPath') return true
  const t = v.trim()
  return t.length >= 12 && (Boolean(src.isSecretKey) || Boolean(sinkKey && SECRET_KEY_RE.test(sinkKey)) || (t.length >= 16 && !SIMPLE_ENTITY_ID_RE.test(t) && shannonEntropy(t) >= 3.0))
}
const buildTemplate = (parts: Array<{ lit?: string; expr?: string }>): string =>
  parts.every(p => p.expr === undefined) ? JSON.stringify(parts.map(p => p.lit ?? '').join(''))
    : `\`${parts.map(p => p.expr !== undefined ? `\${${p.expr}}` : (p.lit ?? '').replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$\{/g, '\\${')).join('')}\``
function renderJsonBindings(node: unknown, prefix: string, resolve: (val: string, path: string) => string | undefined): string {
  if (typeof node === 'string') return resolve(node, prefix) ?? JSON.stringify(node)
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
function formatSealCall(s: SealSpec): string {
  const sel = s.source.kind === 'jsonPath' ? `jsonPath: ${JSON.stringify(s.source.selector)}`
    : s.source.kind === 'setCookie' ? `setCookie: ${JSON.stringify(s.source.cookieName!)}`
    : s.source.kind === 'locationQuery' ? `locationQuery: ${JSON.stringify(s.source.paramName!)}` : `header: ${JSON.stringify(s.source.headerName!)}`
  const f = [`exchangeId: ex.exchangeId`, `slot: ${JSON.stringify(s.slot)}`, sel, `kind: ${JSON.stringify(s.kind)}`]
  if (s.defaultHeaderName) f.push(`defaultHeaderName: ${JSON.stringify(s.defaultHeaderName)}`)
  if (s.defaultCookieName && s.source.kind !== 'setCookie') f.push(`defaultCookieName: ${JSON.stringify(s.defaultCookieName)}`)
  return `${s.varName} = await ctx.seal_capability({ ${f.join(', ')} })`
}
const formatTarget = (origin: string, pathExpr: string, runOrigin?: string): string =>
  origin.trim() && (!runOrigin || origin.trim() !== runOrigin.trim()) ? `{ origin: ${JSON.stringify(origin.trim())}, path: ${pathExpr} }` : pathExpr
function formatHttpOpts(o: { method: string; persona?: string; headersExpr?: string; bodyExpr?: string; followRedirectsFalse?: boolean; capability?: PrimaryCapSpec; arm?: 'control'; session?: string }): string {
  const f = [`method: ${JSON.stringify(o.method.toUpperCase())}`]
  if (o.persona) f.push(`as: ${JSON.stringify(o.persona)}`)
  if (o.capability) {
    const c = [`handle: ${o.capability.capVar}.handle`, `target: ${JSON.stringify(o.capability.target)}`]
    if (o.capability.headerName) c.push(`headerName: ${JSON.stringify(o.capability.headerName)}`)
    if (o.capability.cookieName) c.push(`cookieName: ${JSON.stringify(o.capability.cookieName)}`)
    if (o.capability.queryParam) c.push(`queryParam: ${JSON.stringify(o.capability.queryParam)}`)
    f.push(`capability: { ${c.join(', ')} }`)
  }
  if (o.headersExpr) f.push(`headers: ${o.headersExpr}`)
  if (o.bodyExpr) f.push(`body: ${o.bodyExpr}`)
  if (o.followRedirectsFalse) f.push('followRedirects: false')
  if (o.arm) f.push(`arm: ${JSON.stringify(o.arm)}`)
  if (o.session) f.push(`session: ${JSON.stringify(o.session)}`)
  return `{ ${f.join(', ')} }`
}
const sanitizeControlHeaders = (headers?: Record<string, string>): string | undefined => {
  const safe = Object.entries(headers ?? {}).filter(([k]) => { const l = k.toLowerCase(); return !HOP_BY_HOP.has(l) && !l.startsWith('sec-fetch-') && !l.startsWith('sec-ch-') && !AUTH_HDR_RE.test(l) })
  return safe.length ? JSON.stringify(Object.fromEntries(safe)) : undefined
}
const appendEncodedKv = (parts: Array<{ lit?: string; expr?: string }>, pairs: Array<{ k: string; expr?: string; raw?: string }>): void => {
  pairs.forEach((qp, i) => {
    if (i > 0) parts.push({ lit: '&' })
    if (qp.expr !== undefined) parts.push({ lit: `${encodeURIComponent(qp.k)}=` }, { expr: qp.expr })
    else parts.push({ lit: `${encodeURIComponent(qp.k)}=${encodeURIComponent(qp.raw ?? '')}` })
  })
}

interface BindingState {
  plans: StepPlan[]
  allowedSet: ReadonlySet<string> | undefined
  blocked: ReadonlySet<string>
  warnings: string[]
  inferredBindings: BindingRecord[]
  sealMap: Map<string, SealSpec>
  varMap: Map<string, VarSpec>
  valueIndex: Map<string, ExtractedSource>
  sealN: number
  varN: number
}

function getOrCreateSeal(st: BindingState, source: ExtractedSource, kind: SealKind, extra?: { defaultHeaderName?: string; defaultCookieName?: string }): SealSpec {
  const key = `${source.stepIdx}|${source.kind}|${source.selector}|${kind}`, hit = st.sealMap.get(key)
  if (hit) return hit
  const s: SealSpec = { varName: `cap_${++st.sealN}`, slot: `cap_${st.sealN}`, source, kind, ...extra }
  st.sealMap.set(key, s); st.plans[source.stepIdx]!.seals.push(s)
  if (source.kind === 'locationQuery') st.plans[source.stepIdx]!.forceNoFollowRedirects = true
  return s
}

function getOrCreateVar(st: BindingState, source: ExtractedSource): VarSpec {
  const key = `${source.stepIdx}|${source.kind}|${source.selector}`, hit = st.varMap.get(key)
  if (hit) return hit
  const v: VarSpec = { varName: `v_${++st.varN}`, source }
  st.varMap.set(key, v); st.plans[source.stepIdx]!.vars.push(v); return v
}

function bindLeafValue(st: BindingState, plan: StepPlan, src: ExtractedSource, toStep: number, target: string, encode: boolean, sealIt: boolean): string | undefined {
  plan.usesDynamicUrlOrBody = true; plan.dynamicDepSteps.add(src.stepIdx)
  if (sealIt && canSeal(src.value, st.blocked)) {
    const s = getOrCreateSeal(st, src, 'generic_secret'); plan.hasSealedUrlOrBodyDep = true
    st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target }); return `${s.varName}.handle`
  }
  if (src.kind === 'jsonPath') {
    const v = getOrCreateVar(st, src)
    st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'var', selector: src.selector, target })
    return encode ? `encodeURIComponent(String(${v.varName}))` : v.varName
  }
  return undefined
}

function bindStepPlan(st: BindingState, plan: StepPlan, toStep: number, maxProdIdx: number): void {
  const ex = plan.exchange
  if (ex.persona && st.allowedSet && !st.allowedSet.has(ex.persona)) st.warnings.push(`Step ${plan.hopId} references persona "${ex.persona}" outside allowedPersonas.`)
  const lookup = (val: string) => { const h = st.valueIndex.get(val.trim()); return h && h.stepIdx < maxProdIdx ? h : undefined }
  const hdrEntries: Array<[string, string]> = [], handled = new Set<string>(), reqHdrs = Object.entries(ex.requestHeaders ?? {})

  for (const [k, v] of reqHdrs) {
    const l = k.toLowerCase()
    if (l === 'authorization') {
      const m = /^bearer\s+(.+)$/i.exec(v.trim()), src = lookup(m ? m[1]! : v) ?? (m ? lookup(v) : undefined)
      if (src && canSeal(src.value, st.blocked)) {
        const s = getOrCreateSeal(st, src, 'bearer_token'); plan.primaryCapability = { capVar: s.varName, target: 'bearer' }; plan.omitPersona = true; handled.add('authorization')
        st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: 'header:authorization:bearer' })
      }
    } else if (l === 'cookie') {
      for (const seg of v.split(';')) {
        const eq = seg.indexOf('='); if (eq <= 0) continue
        const cName = seg.slice(0, eq).trim(), src = lookup(seg.slice(eq + 1))
        if (src && canSeal(src.value, st.blocked)) {
          const s = getOrCreateSeal(st, src, 'cookie', { defaultCookieName: cName })
          if (!plan.primaryCapability) { plan.primaryCapability = { capVar: s.varName, target: 'cookie', cookieName: cName }; plan.omitPersona = true }
          else hdrEntries.push([k, `\`${cName}=\${${s.varName}.handle}\``])
          handled.add('cookie'); st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: `cookie:${cName}` }); break
        }
      }
    }
  }
  for (const [k, v] of reqHdrs) {
    const l = k.toLowerCase()
    if (handled.has(l) || HOP_BY_HOP.has(l) || l.startsWith('sec-fetch-') || l.startsWith('sec-ch-')) continue
    if (l === 'authorization' || l === 'cookie' || l === 'proxy-authorization') {
      if (!ex.persona && !plan.primaryCapability) st.warnings.push(`Step ${plan.hopId} had unlinked literal "${k}" header; stripped for hygiene.`)
      continue
    }
    const src = SKIP_TAINT_HDRS.has(l) ? undefined : lookup(v)
    if (src && canSeal(src.value, st.blocked)) {
      const s = getOrCreateSeal(st, src, 'header_secret', { defaultHeaderName: k })
      if (!plan.primaryCapability) { plan.primaryCapability = { capVar: s.varName, target: 'header', headerName: k }; if (AUTH_HDR_RE.test(l) || !ex.persona) plan.omitPersona = true }
      else hdrEntries.push([k, `${s.varName}.handle`])
      st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: `header:${l}` })
    } else hdrEntries.push([k, JSON.stringify(v)])
  }
  if (hdrEntries.length) plan.headersExpr = `{ ${hdrEntries.map(([k, v]) => `${JSON.stringify(k)}: ${v}`).join(', ')} }`

  const rawPq = ex.pathAndQuery?.startsWith('/') ? ex.pathAndQuery : `/${ex.pathAndQuery ?? ''}`
  const qIdx = rawPq.indexOf('?'), rawPath = qIdx >= 0 ? rawPq.slice(0, qIdx) : rawPq, rawQuery = qIdx >= 0 ? rawPq.slice(qIdx + 1) : ''
  const pathParts: Array<{ lit?: string; expr?: string }> = [], deltaSegs: string[] = []
  rawPath.split('/').forEach((seg, sIdx) => {
    if (sIdx > 0) pathParts.push({ lit: '/' })
    if (!seg) { deltaSegs.push(''); return }
    let dec = seg; try { dec = decodeURIComponent(seg) } catch { /* raw */ }
    const src = lookup(dec) ?? (dec !== seg ? lookup(seg) : undefined)
    const expr = src ? bindLeafValue(st, plan, src, toStep, 'path', true, src.kind !== 'jsonPath' || (isOpaque(src.value, src, st.blocked) && Boolean(src.isSecretKey))) : undefined
    if (expr) { pathParts.push({ expr }); deltaSegs.push(':param') } else { pathParts.push({ lit: seg }); deltaSegs.push(seg) }
  })
  plan.deltaPath = deltaSegs.join('/') || '/'

  if (rawQuery) {
    const qEntries = [...new URLSearchParams(rawQuery).entries()], counts = new Map<string, number>()
    for (const [k] of qEntries) counts.set(k, (counts.get(k) ?? 0) + 1)
    const kept: Array<{ k: string; expr?: string; raw?: string }> = []
    for (const [k, v] of qEntries) {
      const src = lookup(v)
      if (!src) { kept.push({ k, raw: v }); continue }
      if (isOpaque(src.value, src, st.blocked, k)) {
        plan.usesDynamicUrlOrBody = true; plan.dynamicDepSteps.add(src.stepIdx); plan.hasSealedUrlOrBodyDep = true
        const s = getOrCreateSeal(st, src, 'generic_secret')
        if (!plan.primaryCapability && counts.get(k) === 1) plan.primaryCapability = { capVar: s.varName, target: 'url', queryParam: k }
        else kept.push({ k, expr: `${s.varName}.handle` })
        st.inferredBindings.push({ fromStep: src.stepIdx + 1, toStep, kind: 'seal', selector: src.selector, target: `query:${k}` })
      } else { const expr = bindLeafValue(st, plan, src, toStep, `query:${k}`, true, false); kept.push(expr ? { k, expr } : { k, raw: v }) }
    }
    if (kept.length) { pathParts.push({ lit: '?' }); appendEncodedKv(pathParts, kept) }
  }
  plan.pathExpr = buildTemplate(pathParts)

  const bodyJson = ex.requestJson !== undefined ? ex.requestJson : tryParseJson(ex.requestBody), boundBody = new Set<string>()
  if (bodyJson !== undefined) {
    plan.bodyExpr = renderJsonBindings(bodyJson, '', (leaf, fp) => {
      const src = lookup(leaf); if (!src) return undefined
      boundBody.add(fp)
      return bindLeafValue(st, plan, src, toStep, `body:${fp}`, false, src.kind !== 'jsonPath' || isOpaque(src.value, src, st.blocked, fp.split('.').pop()))
    })
    if (/^(?:POST|PUT|PATCH)$/i.test(ex.method)) {
      const uniq = detectUniqueFields(bodyJson, boundBody)
      if (uniq.length) st.warnings.push(`Step ${plan.hopId} ${ex.method.toUpperCase()} body has literal unique-creation field(s) [${uniq.join(', ')}]; replay may need fresh values.`)
    }
  } else if (typeof ex.requestBody === 'string' && ex.requestBody.length > 0) {
    if ((getHeaderCI(ex.requestHeaders, 'content-type') ?? '').toLowerCase().includes('application/x-www-form-urlencoded')) {
      const fp: Array<{ lit?: string; expr?: string }> = []
      const pairs = [...new URLSearchParams(ex.requestBody).entries()].map(([k, v]) => {
        const src = lookup(v), expr = src ? bindLeafValue(st, plan, src, toStep, `body:${k}`, true, src.kind !== 'jsonPath' || isOpaque(src.value, src, st.blocked, k)) : undefined
        return expr ? { k, expr } : { k, raw: v }
      })
      appendEncodedKv(fp, pairs); plan.bodyExpr = buildTemplate(fp)
    } else plan.bodyExpr = JSON.stringify(ex.requestBody)
  }
}

export function compileTraceToKovoVerifyScript(input: {
  submission: ExploitTraceSubmission; exchanges: RecordedRequestExchange[]
  allowedPersonas?: string[]; runOrigin?: string
}): CompiledTraceResult {
  const { submission, exchanges, allowedPersonas, runOrigin } = input
  const warnings: string[] = [], uncompilableReasons: string[] = []
  const chainId = slugifyChainId(submission.title || 'trace')
  const fail = (reason: string, n = 0): CompiledTraceResult => ({
    ok: false, chainId, terminalVulnClass: normalizeVulnClass(submission.vulnClass, submission.oracleFamily, n, warnings).terminalVulnClass,
    inferredBindings: [], controlSynthesized: false, warnings, uncompilableReasons: [reason],
  })

  if (!Array.isArray(exchanges) || !exchanges.length) return fail('No recorded exchanges provided.')
  const byId = new Map(exchanges.map(e => [e.exchangeId, e]))
  const explicitControl = submission.controlExchangeId ? byId.get(submission.controlExchangeId) : undefined
  if (submission.controlExchangeId && !explicitControl) warnings.push(`controlExchangeId "${submission.controlExchangeId}" not found; synthesizing clean control.`)
  const explicitReadback = submission.readbackExchangeId ? byId.get(submission.readbackExchangeId) : undefined
  if (submission.readbackExchangeId && !explicitReadback) warnings.push(`readbackExchangeId "${submission.readbackExchangeId}" not found in exchanges.`)
  const explicitTerminal = submission.terminalExchangeId ? byId.get(submission.terminalExchangeId) : undefined
  if (submission.terminalExchangeId && !explicitTerminal) return fail(`Terminal exchange "${submission.terminalExchangeId}" not found in recorded exchanges.`, exchanges.length)

  const excluded = new Set([explicitControl, explicitReadback].filter((e): e is RecordedRequestExchange => Boolean(e && e.exchangeId !== explicitTerminal?.exchangeId)).map(e => e.exchangeId))
  const causal: RecordedRequestExchange[] = [], seen = new Set<string>()
  const ordered = submission.exchangeIds?.length
    ? submission.exchangeIds.map(id => { const ex = byId.get(id); if (!ex) warnings.push(`Exchange "${id}" in submission.exchangeIds was not found.`); return ex }).filter((e): e is RecordedRequestExchange => Boolean(e))
    : [...exchanges].sort((a, b) => a.timestampMs - b.timestampMs)
  for (const ex of ordered) if (!seen.has(ex.exchangeId) && !excluded.has(ex.exchangeId)) { seen.add(ex.exchangeId); causal.push(ex) }
  if (explicitTerminal && !seen.has(explicitTerminal.exchangeId)) causal.push(explicitTerminal)
  if (!causal.length) return fail('No causal exchanges remain to compile.')

  const terminalIdx = explicitTerminal ? causal.findIndex(e => e.exchangeId === explicitTerminal.exchangeId) : causal.length - 1
  const terminalEx = causal[terminalIdx]!
  const { terminalVulnClass, validOracleFamily } = normalizeVulnClass(submission.vulnClass, submission.oracleFamily, causal.length, warnings)
  const allowedSet = allowedPersonas?.length ? new Set(allowedPersonas) : undefined
  const attackerPersona = (submission.attackerPersona?.trim() || causal[0]?.persona?.trim() || causal.find(e => e.persona?.trim())?.persona?.trim()) || undefined
  if (attackerPersona && allowedSet && !allowedSet.has(attackerPersona)) warnings.push(`Base attackerPersona "${attackerPersona}" is not in allowedPersonas.`)

  const blocked = buildBlockedValues(exchanges, allowedPersonas, attackerPersona, runOrigin)
  const mkPlan = (ex: RecordedRequestExchange, stepNumber: number, hopId: string): StepPlan => ({
    exchange: ex, stepNumber, hopId, seals: [], vars: [], omitPersona: false,
    forceNoFollowRedirects: ex.followRedirects === false || (ex.status >= 300 && ex.status < 400 && Boolean(getHeaderCI(ex.responseHeaders, 'location'))),
    pathExpr: JSON.stringify(ex.pathAndQuery || '/'), deltaPath: (ex.pathAndQuery || '/').split('?')[0] || '/',
    usesDynamicUrlOrBody: false, dynamicDepSteps: new Set<number>(), hasSealedUrlOrBodyDep: false,
  })
  const plans = causal.map((ex, i) => mkPlan(ex, i + 1, `step_${i + 1}`))
  const st: BindingState = {
    plans, allowedSet, blocked, warnings, inferredBindings: [],
    sealMap: new Map(), varMap: new Map(), valueIndex: new Map(), sealN: 0, varN: 0,
  }
  for (let i = 0; i < plans.length; i += 1) {
    bindStepPlan(st, plans[i]!, i + 1, i)
    for (const src of extractSources(causal[i]!, i)) if (isEligible(src.value, blocked) && !st.valueIndex.has(src.value)) st.valueIndex.set(src.value, src)
  }
  const readbackPlan = explicitReadback ? mkPlan(explicitReadback, plans.length + 1, 'readback') : undefined
  if (readbackPlan) bindStepPlan(st, readbackPlan, plans.length + 1, plans.length)

  const termPlan = plans[terminalIdx]!, controlSynthesized = !explicitControl
  let ctrlAfterIdx = -1, ctrlUsesDyn = false
  if (controlSynthesized && termPlan.usesDynamicUrlOrBody) {
    const deps = [...termPlan.dynamicDepSteps].sort((a, b) => a - b), maxDep = deps[deps.length - 1] ?? -1
    if (maxDep >= 0 && maxDep < terminalIdx && !termPlan.hasSealedUrlOrBodyDep && plans.slice(0, maxDep + 1).every(p => READ_ONLY_METHODS.has(p.exchange.method.toUpperCase()))) {
      ctrlAfterIdx = maxDep; ctrlUsesDyn = true
      warnings.push(`Synthesized clean control depends on dynamic value(s) from read-only hop(s) (${deps.map(d => `step_${d + 1}`).join(', ')}); placed after step_${maxDep + 1}.`)
    } else warnings.push('Synthesized clean control targets a terminal request with dynamic value(s) from mutating/sealed hop(s); verify control idempotency on replay.')
  }

  const lines: string[] = ['export default async function (ctx) {', `  const ch = ctx.chain(${JSON.stringify(chainId)}, ${JSON.stringify(terminalVulnClass)})`]
  const emitCtrl = (): void => {
    const srcEx = explicitControl ?? terminalEx
    const cBodyJson = srcEx.requestJson !== undefined ? srcEx.requestJson : tryParseJson(srcEx.requestBody)
    const cBody = (!explicitControl && ctrlUsesDyn) ? termPlan.bodyExpr : (cBodyJson !== undefined ? JSON.stringify(cBodyJson) : (srcEx.requestBody ? JSON.stringify(srcEx.requestBody) : undefined))
    const cPath = (!explicitControl && ctrlUsesDyn) ? termPlan.pathExpr : JSON.stringify(srcEx.pathAndQuery || '/')
    lines.push(`  const ctrl = await ctx.http_send(${formatTarget(srcEx.origin, cPath, runOrigin)}, ${formatHttpOpts({ method: srcEx.method || 'GET', persona: explicitControl ? (explicitControl.persona?.trim() || attackerPersona) : attackerPersona, headersExpr: sanitizeControlHeaders(srcEx.requestHeaders), bodyExpr: cBody, arm: 'control', session: 'ctrl_clean' })})`, '  ch.control(ctrl)')
  }
  const planOpts = (p: StepPlan, fallbackPersona?: string) => formatHttpOpts({ method: p.exchange.method || 'GET', persona: p.omitPersona ? undefined : (p.exchange.persona?.trim() || fallbackPersona), headersExpr: p.headersExpr, bodyExpr: p.bodyExpr, followRedirectsFalse: p.forceNoFollowRedirects, capability: p.primaryCapability })

  if (ctrlAfterIdx < 0) emitCtrl()
  for (let i = 0; i < plans.length; i += 1) {
    const p = plans[i]!
    lines.push(
      ...p.seals.map(s => `  let ${s.varName}`), ...p.vars.map(v => `  let ${v.varName}`),
      `  const h_${p.stepNumber} = await ch.hop(${JSON.stringify(p.hopId)}, { claimedDelta: ${JSON.stringify(`${p.exchange.method.toUpperCase()} ${p.deltaPath}`)} }, async () => {`,
      `    const ex = await ctx.http_send(${formatTarget(p.exchange.origin, p.pathExpr, runOrigin)}, ${planOpts(p)})`,
      ...p.seals.map(s => `    ${formatSealCall(s)}`), ...p.vars.map(v => `    ${v.varName} = ${v.source.jsAccess ?? 'undefined'}`),
      '    return ex', '  })',
    )
    if (ctrlAfterIdx === i) emitCtrl()
  }
  if (readbackPlan) lines.push(`  const rb = await ctx.http_send(${formatTarget(readbackPlan.exchange.origin, readbackPlan.pathExpr, runOrigin)}, ${planOpts(readbackPlan, attackerPersona)})`, '  ch.readback(rb)')

  const prove = [
    `terminalHopId: ${JSON.stringify(termPlan.hopId)}`, `terminalExchange: h_${termPlan.stepNumber}`, 'control: ctrl',
    ...(readbackPlan ? ['readback: rb'] : []), ...(validOracleFamily ? [`oracleFamily: ${JSON.stringify(validOracleFamily)}`] : []),
    `claimedImpact: ${JSON.stringify((submission.reproNotes?.trim() || submission.title || terminalVulnClass).slice(0, 240))}`,
  ]
  lines.push(
    `  const proof = await ch.prove({ ${prove.join(', ')} })`,
    `  return ctx.result({ title: ${JSON.stringify((submission.title || 'Compiled trace proof').slice(0, 300))}, severity: "high", description: proof.reason || ${JSON.stringify((submission.reproNotes?.trim() || submission.title || 'Compiled trace verification').slice(0, 500))} })`,
    '}',
  )
  const script = `${lines.join('\n')}\n`, bytes = Buffer.byteLength(script, 'utf8')
  if (bytes > MAX_SCRIPT_BYTES) {
    uncompilableReasons.push(`Compiled script exceeds 64 KiB limit (${bytes} bytes).`)
    return { ok: false, chainId, terminalVulnClass, inferredBindings: st.inferredBindings, controlSynthesized, warnings, uncompilableReasons }
  }
  return { ok: true, script, chainId, terminalVulnClass, inferredBindings: st.inferredBindings, controlSynthesized, warnings, uncompilableReasons }
}
