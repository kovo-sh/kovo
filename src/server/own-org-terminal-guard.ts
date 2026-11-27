/**
 * R3-05 Confirmation-Kernel Own-Org Benign-Read / Create FP Guard & Class Normalization.
 *
 * Pure, deterministic, fail-closed helpers extracted from `v8-oracle-hydrate.ts` to keep
 * shared kernel modules within strict LOC ceilings.
 */
import { ROLE_RANK, normalizeRole, routeFamily, stepReadsState } from './oracle-invariants.ts'
import { resolveCompositeTerminalContract, type OracleTerminalContractKind } from './oracle-spec.ts'
export { resolveCompositeTerminalContract }
import type { HostSignedRecord } from './v8-oracle-families.ts'
import type { HydratableEntry } from './v8-oracle-hydrate.ts'

export const normalizeTerminalVulnClass = (cls: string): string => cls.trim().toLowerCase().replace(/[\s-]+/g, '_')

// Access-control contract exemptions: csrf (ambient-cookie cross-site write), mass_assignment (field persistence),
// and signed/presigned URL mint classes validate distinct invariants outside the own-org benign read/create guard.
const OWN_ORG_ACCESS_CONTRACT_EXEMPT_RE = /^(?:csrf|mass_assignment|signed_url_.*|.*_signed_url|presigned_url_.*|.*_presigned_url|azure_sas_mint)$/i
const OWN_ORG_AUTH_OR_LOGIC_RE = /^(?:auth_bypass|authentication_bypass|broken_auth|business_logic|workflow_bypass|workflow_skip|invariant_violation)$/i
const OWN_ORG_BUSINESS_LOGIC_RE = /^business_logic$/i
const OWN_ORG_SENSITIVE_READ_PATH_RE = /(?:^|\/)(?:vault|audit|secrets?|credentials?|keys?|tokens?|admin|owner|internal|treasury|backups?)(?:\/|$)/i
const OWN_ORG_PRIVILEGED_WRITE_PATH_RE = /(?:^|\/)(?:admin|owner|internal|vault|scim|webhooks?|roles?|permissions?|secrets?|credentials?|keys?|tokens?)(?:\/|$)/i
const OWN_ORG_INVITE_PATH_RE = /(?:^|\/)invites?(?:\/|$)/i
const OWN_ORG_SINGLE_ITEM_TAIL_RE = /^(?:content|download|raw|file|blob|body|secret|secrets|export|approve|reject|rebind|settle|settle-race|capture|refund|revoke|rotate|promote|demote|delete|cancel|sync|verify|redeem|resolve|callback|webhook|execute|run|trigger|commit|finalize|transfer|withdraw|deploy|publish|impersonate|escalate)$/i
const OWN_ORG_TENANT_SCOPE_PATH_RE = /(?:^|\/)(?:orgs?|organizations?|tenants?|workspaces?)\/([^/]+)/i
const OWN_ORG_PAGINATION_KEY_RE = /^(?:next_?(?:page_?)?token|prev(?:ious)?_?(?:page_?)?token|page_?token|continuation_?token|resume_?token|scroll_?token|sync_?token|cursor_?token|cursor|next_?cursor|prev_?cursor)$/i
const OWN_ORG_SENSITIVE_WORD_RE = /^(?:secret|secrets|password|passwd|private|credential|credentials|apikey|api_key|vault|audit|token|tokens|signing|canary|ssn|card|iban|private_key|access_token|refresh_token|auth_token|session_token|id_token|bearer_token)$/i
const OWN_ORG_SLUG_RE = /\bslug=([a-z0-9][a-z0-9._-]{0,63})/i
const OWN_ORG_DYNAMIC_SEG_RE = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|(?=[0-9a-f]*\d)[0-9a-f]{8,}|[0-9a-f]{16,}|(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{8,}|[a-z]+[_-][a-z0-9_-]*\d[a-z0-9_-]*|:id|<scrubbed>)$/i

const actorOfGuardEntry = (e: HydratableEntry): string | null =>
  e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)

function normalizeGuardPath(raw: string | null | undefined): string {
  const base = (raw ?? '').split(/[?#]/, 1)[0]!.replace(/\/+$/, '').toLowerCase()
  if (!base) return ''
  const stack: string[] = []
  for (const rawSeg of base.split('/')) {
    if (!rawSeg) continue
    let seg = rawSeg
    if (seg.includes('%')) { try { seg = decodeURIComponent(seg) } catch { /* keep raw */ } }
    seg = seg.split(';', 1)[0]!.trim().toLowerCase()
    if (!seg || seg === '.') continue
    if (seg === '..') { stack.pop(); continue }
    stack.push(seg)
  }
  return stack.length > 0 ? '/' + stack.join('/') : '/'
}

function isSensitivePayloadKey(key: string): boolean {
  const lk = key.trim().toLowerCase()
  if (!lk || OWN_ORG_PAGINATION_KEY_RE.test(lk)) return false
  const norm = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
  if (OWN_ORG_PAGINATION_KEY_RE.test(norm)) return false
  if (OWN_ORG_SENSITIVE_WORD_RE.test(norm)) return true
  return norm.split(/[^a-z0-9]+/).filter(Boolean).some(w => OWN_ORG_SENSITIVE_WORD_RE.test(w))
}

function isNonSensitiveCollectionPayload(parsed: unknown): boolean {
  if (Array.isArray(parsed)) return true
  if (!parsed || typeof parsed !== 'object') return false
  let hasArray = false, hasSensitive = false, visited = 0
  const walk = (node: unknown, depth: number): void => {
    if (hasSensitive || depth > 3 || visited > 128 || !node || typeof node !== 'object') return
    if (Array.isArray(node)) { hasArray = true; return }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      visited += 1
      if (isSensitivePayloadKey(k)) { hasSensitive = true; return }
      if (Array.isArray(v)) hasArray = true
      else if (v && typeof v === 'object' && depth < 3) walk(v, depth + 1)
    }
  }
  walk(parsed, 0)
  return hasArray && !hasSensitive
}

/** Generic fail-closed guard rejecting own-org directory/invite/collection GETs and plain own-org POST creates without verified impact. */
export function evaluateOwnOrgTerminalGuard(params: {
  normCls: string
  contract: OracleTerminalContractKind | null
  isPrivEscCls: boolean
  isCrossTenantCls: boolean
  termEx: HydratableEntry | undefined
  terminalCtrl: HydratableEntry | undefined
  attackerTenants: ReadonlySet<string>
  personaRoleLabels?: Readonly<Record<string, string>>
  ownTenantOnly: boolean
  hasForeignTenantData: boolean
  hasPostMutation: boolean
  hasV8Oracle: boolean
  isReadOnlyDir: boolean
  hasTermDerivedCrypto: boolean
  hasVerifiedTermStateTransition: boolean
  hasVerifiedTermValueBinding: boolean
}): string | null {
  if (params.hasV8Oracle || params.hasPostMutation || !params.termEx) return null
  const isAccessOrLogic = (params.contract === 'access_control' && !OWN_ORG_ACCESS_CONTRACT_EXEMPT_RE.test(params.normCls))
    || OWN_ORG_AUTH_OR_LOGIC_RE.test(params.normCls)
  if (!params.isPrivEscCls && !params.isCrossTenantCls && !isAccessOrLogic) return null
  if (params.isReadOnlyDir) {
    return 'terminal_impact_unproven: privilege_escalation/bfla/cross-tenant/access-control/business-logic cannot confirm on a read-only directory/roster/metadata listing GET without private payload content, a state-mutating terminal action + postChainReadbackExchangeIds, or a verified v8 oracle family.'
  }

  const cleanPath = normalizeGuardPath(params.termEx.step.route ?? params.termEx.step.pathAndQuery)
  const termActor = actorOfGuardEntry(params.termEx), ctrlActor = params.terminalCtrl ? actorOfGuardEntry(params.terminalCtrl) : null
  const ownTokens = new Set<string>(params.attackerTenants)
  for (const lbl of [params.termEx.actorRoleLabel, termActor ? params.personaRoleLabels?.[termActor] : undefined, ctrlActor ? params.personaRoleLabels?.[ctrlActor] : undefined]) {
    const sm = lbl ? OWN_ORG_SLUG_RE.exec(lbl) : null
    if (sm?.[1]) ownTokens.add(sm[1].toLowerCase())
  }
  const scopeMatch = cleanPath ? OWN_ORG_TENANT_SCOPE_PATH_RE.exec(cleanPath) : null
  const scopeTenant = scopeMatch?.[1]?.toLowerCase() ?? null
  const pathTargetsOwnTenant = Boolean(!params.hasForeignTenantData && scopeTenant && ownTokens.has(scopeTenant))
  const pathTargetsForeignTenant = Boolean(scopeTenant && ownTokens.size > 0 && !ownTokens.has(scopeTenant))
  const ownOrgScoped = params.ownTenantOnly || pathTargetsOwnTenant

  const ctrlStatus = params.terminalCtrl?.step.status ?? null
  const ctrlAuthzDenied = ctrlStatus === 401 || ctrlStatus === 403 || ctrlStatus === 409 || ctrlStatus === 412 || ctrlStatus === 422
  const hasEscalatedCapDelta = Boolean(
    params.hasVerifiedTermValueBinding && ctrlAuthzDenied
    && (Boolean(termActor?.startsWith('cap:')) || (params.termEx.consumedCapabilities?.length ?? 0) > 0)
    && termActor !== ctrlActor,
  )

  const segs = cleanPath.split('/').filter(Boolean)
  const lastSeg = segs[segs.length - 1] ?? ''
  if (stepReadsState(params.termEx.step) && !OWN_ORG_SENSITIVE_READ_PATH_RE.test(cleanPath)) {
    let parsed = params.termEx.step.json
    if (parsed === undefined && typeof params.termEx.step.body === 'string' && /^[\[{]/.test(params.termEx.step.body.trim())) {
      try { parsed = JSON.parse(params.termEx.step.body) } catch { parsed = undefined }
    }
    const isCollectionPayload = isNonSensitiveCollectionPayload(parsed)
    const isInvitePath = Boolean(cleanPath && OWN_ORG_INVITE_PATH_RE.test(cleanPath))
    const isCollectionPath = Boolean(lastSeg && !OWN_ORG_DYNAMIC_SEG_RE.test(lastSeg) && !OWN_ORG_SINGLE_ITEM_TAIL_RE.test(lastSeg))
    const unattributedOwnCollection = !params.hasForeignTenantData && !pathTargetsForeignTenant && params.attackerTenants.size > 0 && !hasEscalatedCapDelta && isCollectionPath && isCollectionPayload
    if ((ownOrgScoped && (isInvitePath || (isCollectionPath && isCollectionPayload))) || unattributedOwnCollection) {
      return 'terminal_impact_unproven: own-org directory/invite/collection GET listing is non-terminal impact without foreign-tenant exposure, a state-mutating terminal action + postChainReadbackExchangeIds, or a verified v8 oracle family.'
    }
  }

  const hasNonScopeDynamicSeg = segs.some((seg, i) => {
    const prev = i > 0 ? segs[i - 1]! : ''
    return !/^(?:orgs?|organizations?|tenants?|workspaces?)$/i.test(prev) && OWN_ORG_DYNAMIC_SEG_RE.test(seg)
  })
  const isPlainCollectionCreate = params.termEx.step.method.toUpperCase() === 'POST'
    && !OWN_ORG_PRIVILEGED_WRITE_PATH_RE.test(cleanPath)
    && !hasNonScopeDynamicSeg
    && !OWN_ORG_SINGLE_ITEM_TAIL_RE.test(lastSeg)
  const unattributedOwnCreate = ownOrgScoped || (!params.hasForeignTenantData && !pathTargetsForeignTenant && !params.isCrossTenantCls)
  if (unattributedOwnCreate && isPlainCollectionCreate && ((isAccessOrLogic && !params.hasTermDerivedCrypto && !params.hasVerifiedTermStateTransition) || (params.isPrivEscCls && !params.hasTermDerivedCrypto && !params.hasVerifiedTermStateTransition && !hasEscalatedCapDelta))) {
    return 'terminal_impact_unproven: plain own-org POST resource creation requires a verified v8 oracle family, postChainReadbackExchangeIds proving unauthorized persisted impact, forged cryptographic signature, or verified state_transition_binding.'
  }

  if (!ownOrgScoped) return null
  if (OWN_ORG_BUSINESS_LOGIC_RE.test(params.normCls)) {
    const hasExplicitDelta = !stepReadsState(params.termEx.step) && !isPlainCollectionCreate && ctrlAuthzDenied
      && (params.hasTermDerivedCrypto || params.hasVerifiedTermStateTransition || hasEscalatedCapDelta)
    if (!hasExplicitDelta) {
      return 'terminal_impact_unproven: own-org business_logic without postChainReadbackExchangeIds requires a verified v8 oracle family (e.g. economic_conservation) or an explicit forged-signature, state-transition, or escalated-credential mutation delta on the same resource.'
    }
  }
  return null
}

// --- R2 / R5 / R8 Kernel Guard & Hydration Helpers -------------------------

const LEDGER_ARRAY_KEYS = ['entries', 'transactions', 'ledger'] as const
const LEDGER_AMOUNT_KEYS = ['amount', 'amountcents', 'amount_cents', 'delta'] as const
const LEDGER_GROUP_KEYS = ['tenantid', 'tenant_id', 'tenant', 'orgid', 'org_id', 'accountid', 'account_id', 'walletid', 'wallet_id'] as const
const LEDGER_DIR_KEYS = ['type', 'direction', 'entrytype', 'entry_type', 'kind'] as const
const LEDGER_STATUS_KEYS = ['status', 'state'] as const
const LEDGER_CURRENCY_KEYS = ['currency', 'currencycode', 'currency_code', 'asset', 'unit', 'denom'] as const
const LEDGER_CREDIT_RE = /^(?:credit|deposit|inflow|topup|top_up|settlement|settlement_credit|payout_credit|adjustment_credit|income|mint)$/i
const LEDGER_DEBIT_RE = /^(?:debit|withdrawal|outflow|charge|purchase|payment|spend|fee|payout|transfer_out|refund|chargeback|debit_adjustment|expense)$/i
const LEDGER_NON_FINAL_STATUS_RE = /^(?:failed|fail|pending|processing|queued|reversed|void|voided|declined|cancelled|canceled|rejected|expired|draft|unconfirmed)$/i
const LEDGER_FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * R2: Sum numeric `amount`/`amountCents`/`delta` (negating debits/spends) across append-only
 * ledger/transaction arrays (`entries`, `transactions`, `ledger`), grouped by tenant/account
 * or `'default'`, abstaining (returning `undefined`) on unrecognized direction strings,
 * non-final entry statuses, mixed currencies/units, or non-finite amount values.
 */
export function extractLedgerBalanceMap(json: unknown): Record<string, number> | undefined {
  if (!json || typeof json !== 'object') return undefined
  let items: unknown[] | undefined
  if (Array.isArray(json)) {
    items = json
  } else {
    const obj = json as Record<string, unknown>
    for (const k of LEDGER_ARRAY_KEYS) {
      if (Array.isArray(obj[k])) { items = obj[k] as unknown[]; break }
    }
  }
  if (!items || items.length === 0) return undefined
  const totals = new Map<string, number>()
  const currencies = new Set<string>()
  let matched = 0
  for (const item of items.slice(0, 4096)) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) continue
    const rec = item as Record<string, unknown>
    let rawAmt: number | undefined
    let dir = ''
    let group = ''
    for (const [ek, ev] of Object.entries(rec)) {
      const lk = ek.toLowerCase()
      if ((LEDGER_AMOUNT_KEYS as readonly string[]).includes(lk)) {
        if (typeof ev !== 'number' || !Number.isFinite(ev)) return undefined
        if (rawAmt === undefined) rawAmt = ev
      } else if (!dir && (LEDGER_DIR_KEYS as readonly string[]).includes(lk) && typeof ev === 'string' && ev.trim()) {
        dir = ev.trim()
      } else if (!group && (LEDGER_GROUP_KEYS as readonly string[]).includes(lk) && typeof ev === 'string' && ev.trim()) {
        group = ev.trim()
      } else if ((LEDGER_STATUS_KEYS as readonly string[]).includes(lk) && typeof ev === 'string' && LEDGER_NON_FINAL_STATUS_RE.test(ev.trim())) {
        return undefined
      } else if ((LEDGER_CURRENCY_KEYS as readonly string[]).includes(lk) && typeof ev === 'string' && ev.trim()) {
        currencies.add(ev.trim().toLowerCase())
        if (currencies.size > 1) return undefined
      }
    }
    if (rawAmt === undefined) continue
    let signed = rawAmt
    if (dir) {
      if (LEDGER_DEBIT_RE.test(dir)) signed = rawAmt > 0 ? -rawAmt : rawAmt
      else if (LEDGER_CREDIT_RE.test(dir)) signed = rawAmt
      else return undefined
    }
    const key = group && !LEDGER_FORBIDDEN_KEYS.has(group) ? group : 'default'
    totals.set(key, (totals.get(key) ?? 0) + signed)
    matched += 1
  }
  if (matched === 0) return undefined
  const out: Record<string, number> = Object.create(null)
  for (const [k, v] of totals) out[k] = v
  return out
}

/**
 * R2: Filter `economic_conservation` `actions` to mutating probe entries whenever at least one
 * mutating action exists, so intermediate read-only `GET` hops do not trip `action_not_mutating`.
 */
export function filterEconomicActionRecords(
  actRecs: readonly HostSignedRecord[],
  entriesById: ReadonlyMap<string, HydratableEntry>,
): HostSignedRecord[] {
  const mutating = actRecs.filter(a => {
    const entry = entriesById.get(a.id)
    if (entry) return !stepReadsState(entry.step)
    return !(a.method && /^(?:GET|HEAD|OPTIONS)$/i.test(a.method))
  })
  return mutating.length > 0 ? mutating : [...actRecs]
}

const SIG_CARRIER_KEY_RE = /(?:^|[-_])(?:sig|signature|hmac|digest|mac|derivation)(?:$|[-_])|signature|hmac/i
const SIGNED_URL_QUERY_KEY_RE = /^(?:x-)?sign$|^sig(?:\[\]|\d+)$/i
const FORGED_WEBHOOK_DENIED_STATUSES = new Set([401, 403, 404])
const FORGED_WEBHOOK_ALWAYS_CLASS_RE = /^(?:webhook_forgery|webhook|forged_signature.*)$/i

export function hasSignedUrlOrHeaderSignature(entry: HydratableEntry | undefined): boolean {
  const hdrs = entry?.step.requestHeaders
  if (hdrs && typeof hdrs === 'object') {
    for (const [k, v] of Object.entries(hdrs)) {
      if (SIG_CARRIER_KEY_RE.test(k.trim()) && typeof v === 'string' && v.trim().length > 0) return true
    }
  }
  const rawPq = entry?.step.pathAndQuery ?? entry?.step.route ?? ''
  const qIdx = rawPq.indexOf('?')
  if (qIdx >= 0) {
    const query = rawPq.slice(qIdx + 1).split('#', 1)[0] ?? ''
    for (const [k, v] of new URLSearchParams(query).entries()) {
      if ((SIG_CARRIER_KEY_RE.test(k.trim()) || SIGNED_URL_QUERY_KEY_RE.test(k.trim())) && v.trim().length > 0) return true
    }
  }
  return false
}

export function hasWebhookSignatureHeader(entry: HydratableEntry | undefined): boolean {
  const hdrs = entry?.step.requestHeaders
  if (hdrs && typeof hdrs === 'object' && Object.keys(hdrs).some(k => SIG_CARRIER_KEY_RE.test(k.trim()))) return true
  const rawPq = entry?.step.pathAndQuery ?? ''
  const qIdx = rawPq.indexOf('?')
  if (qIdx >= 0) {
    const query = rawPq.slice(qIdx + 1).split('#', 1)[0] ?? ''
    for (const k of new URLSearchParams(query).keys()) {
      if (SIG_CARRIER_KEY_RE.test(k.trim())) return true
    }
  }
  const reqBody = entry?.step.requestJson
  if (reqBody && typeof reqBody === 'object' && !Array.isArray(reqBody)) {
    if (Object.keys(reqBody as Record<string, unknown>).some(k => SIG_CARRIER_KEY_RE.test(k.trim()))) return true
  }
  return false
}

/**
 * R2: Returns true when a mutating probe exchange was denied on the same route+method by a
 * pre-chain control (`403` for the same authenticated actor, or `401` on a signature-authenticated
 * webhook/settlement endpoint for the same actor) so unauthorized minting probes are NOT counted
 * as `authorizedDeposits`.
 */
export function isControlDeniedAction(
  entry: HydratableEntry,
  preChainControlIds: readonly string[] | undefined,
  entriesById: ReadonlyMap<string, HydratableEntry>,
): boolean {
  if (entry.step.arm !== 'probe' || stepReadsState(entry.step) || !preChainControlIds?.length) return false
  const eMeth = entry.step.method.toUpperCase()
  const eFam = routeFamily(entry.step.route ?? entry.step.pathAndQuery)
  const eActor = actorOfGuardEntry(entry)?.trim().toLowerCase() ?? ''
  if (!eFam) return false
  const isSigWebhook = hasWebhookSignatureHeader(entry)
  for (const cid of preChainControlIds) {
    const ctrl = entriesById.get(cid)
    if (!ctrl || ctrl.exchangeId === entry.exchangeId || ctrl.step.arm !== 'control') continue
    const st = ctrl.step.status
    if (st !== 403 && !(st === 401 && isSigWebhook)) continue
    if (ctrl.step.method.toUpperCase() !== eMeth) continue
    if (routeFamily(ctrl.step.route ?? ctrl.step.pathAndQuery) !== eFam) continue
    const cActor = actorOfGuardEntry(ctrl)?.trim().toLowerCase() ?? ''
    if (!eActor || !cActor || cActor !== eActor) continue
    return true
  }
  return false
}

const STATE_PRESERVE_KEY_RE = /^(?:role|roles|permission|permissions|scope|scopes|tenant|tenant_id|org|org_id|organization_id|workspace_id|user_id|account_id|wallet_id|owner|owner_id|balance|balance_cents|amount|amount_cents|credits|funds|status|state|verified|active|revoked|admin|is_admin|email|plan|tier|entitlements|members|entries|records|items|payouts|orders|secrets)$/
const VOLATILE_READBACK_KEY_RE = /(?:^|_)(?:ts|timestamp|time|date|now|seen|login|accessed|synced|checked|refreshed|issued|expires|expiry|exp|iat|nbf|ttl|age|uptime|latency|duration)(?:$|_)|(?:_at|_ms|_sec|_ts)$|^(?:jti|nonce|etag|e_tag|version|ver|rev|revision|build|sid|csrf|csrf_token|xsrf_token)$|(?:^|_)(?:request|req|trace|span|correlation|session|csrf|xsrf|nonce)_id$/
const MAX_READBACK_CANON_DEPTH = 32

function isVolatileReadbackKey(rawKey: string): boolean {
  const norm = rawKey.trim().replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[\s-]+/g, '_').toLowerCase()
  if (!norm || STATE_PRESERVE_KEY_RE.test(norm)) return false
  return VOLATILE_READBACK_KEY_RE.test(norm)
}

function canonicalizeReadbackState(node: unknown, depth = 0): unknown {
  if (node === null || node === undefined) return node
  if (depth >= MAX_READBACK_CANON_DEPTH) return '[max_depth]'
  if (Array.isArray(node)) return node.map(item => canonicalizeReadbackState(item, depth + 1))
  if (typeof node === 'object') {
    const out: Record<string, unknown> = {}
    for (const k of Object.keys(node as Record<string, unknown>).sort()) {
      if (isVolatileReadbackKey(k)) continue
      out[k] = canonicalizeReadbackState((node as Record<string, unknown>)[k], depth + 1)
    }
    return out
  }
  return node
}

function normalizedReadbackFingerprint(entry: HydratableEntry): string | null {
  let parsed = entry.step.json
  if (parsed === undefined && typeof entry.step.body === 'string' && /^[\[{]/.test(entry.step.body.trim())) {
    try { parsed = JSON.parse(entry.step.body) } catch { parsed = undefined }
  }
  if (parsed !== undefined) {
    try { return `json:${JSON.stringify(canonicalizeReadbackState(parsed))}` } catch { return null }
  }
  if (typeof entry.step.body === 'string' && entry.step.body.trim().length > 0) {
    return `text:${entry.step.body.trim()}`
  }
  return null
}

function normalizedReadbackRoute(entry: HydratableEntry): string {
  const raw = (entry.step.pathAndQuery ?? entry.step.route ?? '').trim()
  if (!raw) return ''
  const [p = '', qRaw = ''] = raw.split('?', 2)
  const cleanP = normalizeGuardPath(p)
  const qNoHash = qRaw.split('#', 1)[0] ?? ''
  if (!qNoHash) return cleanP
  const pairs: Array<[string, string]> = []
  for (const [k, v] of new URLSearchParams(qNoHash).entries()) {
    pairs.push([k.trim().toLowerCase(), v.trim().toLowerCase()])
  }
  pairs.sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]))
  return pairs.length > 0 ? `${cleanP}?${pairs.map(([k, v]) => `${k}=${v}`).join('&')}` : cleanP
}

/**
 * R5(a): Returns true when a post-mutation readback `rb` has an earlier 2xx readback on the
 * exact same route, HTTP method, and actor whose normalized state/role body is IDENTICAL to `rb`
 * (zero persisted state change, e.g., `owner -> owner`).
 */
export function isZeroDeltaPostMutationReadback(
  rb: HydratableEntry,
  termEx: HydratableEntry | undefined,
  entriesById: ReadonlyMap<string, HydratableEntry>,
): boolean {
  const rbFp = normalizedReadbackFingerprint(rb)
  const rbRoute = normalizedReadbackRoute(rb)
  if (!rbFp || !rbRoute) return false
  const rbMeth = rb.step.method.toUpperCase()
  const rbActor = actorOfGuardEntry(rb)?.trim().toLowerCase() ?? ''
  const cutoffTs = typeof termEx?.timestampMs === 'number' && Number.isFinite(termEx.timestampMs)
    ? termEx.timestampMs
    : (typeof rb.timestampMs === 'number' && Number.isFinite(rb.timestampMs) ? rb.timestampMs : null)
  for (const pre of entriesById.values()) {
    if (pre.exchangeId === rb.exchangeId || pre.exchangeId === termEx?.exchangeId) continue
    if (typeof pre.step.status !== 'number' || pre.step.status < 200 || pre.step.status >= 300) continue
    if (!stepReadsState(pre.step) || pre.step.method.toUpperCase() !== rbMeth) continue
    if (cutoffTs !== null && (typeof pre.timestampMs !== 'number' || !Number.isFinite(pre.timestampMs) || pre.timestampMs >= cutoffTs)) continue
    if (normalizedReadbackRoute(pre) !== rbRoute) continue
    const preActor = actorOfGuardEntry(pre)?.trim().toLowerCase() ?? ''
    if (rbActor !== preActor) continue
    if (normalizedReadbackFingerprint(pre) === rbFp) return true
  }
  return false
}

/**
 * R5(a): Select the first valid post-mutation readback that does NOT match an earlier
 * same-route, same-actor baseline readback with identical normalized state. When at least one
 * candidate readback was rejected solely due to zero state delta and no other readback proves
 * a state change, returns `rejectedZeroDelta: true` so the verifier fails closed.
 */
export function selectVerifiedPostMutationReadback<T extends HydratableEntry>(
  postChainIds: readonly string[],
  termEx: T | undefined,
  entriesById: ReadonlyMap<string, T>,
  isCrossTenantCls: boolean,
  isOwnTenantOnly: (e: T) => boolean,
  hasEntryBody: (e: T) => boolean,
  isStubEntry: (e: T) => boolean,
): { postMutRb: T | undefined; rejectedZeroDelta: boolean } {
  let sawZeroDelta = false
  for (const id of postChainIds) {
    const e = entriesById.get(id)
    if (!e || (termEx && e.exchangeId === termEx.exchangeId)) continue
    const st = e.step.status
    if (typeof st !== 'number' || st < 200 || st >= 300) continue
    const termTs = termEx?.timestampMs
    const mono = !termEx || typeof termTs !== 'number' || !Number.isFinite(termTs)
      || (typeof e.timestampMs === 'number' && Number.isFinite(e.timestampMs) && e.timestampMs >= termTs)
    if (!mono) continue
    if (!(stepReadsState(e.step) || e.step.arm === 'control' || e.step.evidenceRole === 'post_chain_readback')) continue
    if (!hasEntryBody(e) || (isCrossTenantCls && isOwnTenantOnly(e))) continue
    if (isZeroDeltaPostMutationReadback(e, termEx, entriesById)) {
      sawZeroDelta = true
      continue
    }
    if (isStubEntry(e)) continue
    return { postMutRb: e, rejectedZeroDelta: false }
  }
  return { postMutRb: undefined, rejectedZeroDelta: sawZeroDelta }
}

/**
 * R5(b) + R6-nx: Reject 1-hop (`hops < 2`, `verifiedEdges === 0`) forged-signature / webhook
 * POST/PUT receipts AND 1-hop signed-URL/header GET/HEAD receipts whose denied control failed
 * (`401`/`403`/`404`) and whose probe carries a cryptographic signature carrier without proving
 * in-DAG secret/capability provenance (`hops >= 2` with causal edge, `derived_crypto_binding`,
 * or host-attested `cryptoAttestations`).
 */
export function evaluateForgedWebhookProvenanceGuard(params: {
  normCls: string
  hopCount: number
  verifiedEdgeCount: number
  singleHopProofOk: boolean
  termEx: HydratableEntry | undefined
  terminalCtrl: HydratableEntry | undefined
  preChainControlIds: readonly string[]
  entriesById: ReadonlyMap<string, HydratableEntry>
  hasTermDerivedCrypto: boolean
  /** v8 crypto oracle (e.g. cryptographic_scope_replay) already verified the in-transcript minting exchange. */
  hostVerifiedCryptoOracle?: boolean
}): string | null {
  if (params.singleHopProofOk || params.hopCount >= 2 || params.verifiedEdgeCount > 0) return null
  const term = params.termEx
  if (!term) return null
  const meth = term.step.method.toUpperCase()
  const isRead = meth === 'GET' || meth === 'HEAD'
  if (isRead && params.hostVerifiedCryptoOracle) return null
  if (!isRead && (stepReadsState(term.step) || (meth !== 'POST' && meth !== 'PUT'))) return null
  if (params.hasTermDerivedCrypto || (term.cryptoAttestations?.length ?? 0) > 0) return null
  const hasSigCarrier = isRead ? hasSignedUrlOrHeaderSignature(term) : hasWebhookSignatureHeader(term)
  const isForgedClass = !isRead && (FORGED_WEBHOOK_ALWAYS_CLASS_RE.test(params.normCls)
    || (params.normCls === 'forged_settlement' && (hasSigCarrier || term.step.requestHeaders !== undefined || term.step.requestJson !== undefined)))
  if (!hasSigCarrier && !isForgedClass) return null
  const termFam = routeFamily(term.step.route ?? term.step.pathAndQuery)
  const hasDeniedCtrl = (typeof params.terminalCtrl?.step.status === 'number' && FORGED_WEBHOOK_DENIED_STATUSES.has(params.terminalCtrl.step.status))
    || params.preChainControlIds.some(cid => {
      const c = params.entriesById.get(cid)
      return Boolean(c && c.step.arm === 'control' && typeof c.step.status === 'number' && FORGED_WEBHOOK_DENIED_STATUSES.has(c.step.status) && c.step.method.toUpperCase() === meth && (!termFam || routeFamily(c.step.route ?? c.step.pathAndQuery) === termFam))
    })
  if (!hasDeniedCtrl) return null
  return isRead
    ? 'signed_url_unproven_capability_provenance: 1-hop signed-URL/header GET/HEAD request with denied control (401/403/404) requires >= 2 hops with a verified causal edge or host-attested derived_crypto_binding proving in-DAG signature/URL provenance.'
    : 'forged_signature_unproven_secret_provenance: 1-hop forged signature/webhook mutation with denied control (401/403/404) requires >= 2 hops with a verified causal edge or host-attested derived_crypto_binding proving in-DAG secret provenance.'
}

// --- R6-nx: Entity-Less Read State-Transition Edge + Pre-Mutation Control Selection ---

const PRIV_MUTATION_ROUTE_RE = /(?:^|\/)(?:users?|members?(?:hips?)?|roles?|permissions?|acls?|grants?|groups?|scim|iam|principals?|identit(?:y|ies)|accounts?|sessions?|policies|policy|entitlements?|privileges?|admins?)(?:\/|$)/i
const PRIV_MUTATION_PAYLOAD_KEY_RE = /^(?:role|roles|permission|permissions|privileges?|admin|is_admin|isAdmin|acl|entitlements?|membership|memberships|tier)$/i
const PRIV_MUTATION_BENIGN_TAIL_RE = /(?:^|\/)(?:comments?|notes?|preferences?|settings?|notifications?|messages?|likes?|favou?rites?|bookmarks?|feedback|reviews?|avatars?|profile)\/?$/i
const ENTITY_LESS_DENIED_CTRL_STATUSES = new Set([401, 403, 404])
const GUARD_ANON_ACTOR_RE = /^(?:anon(?:ymous)?|unauth(?:enticated)?|guest)$/i

type GuardChronoEntry = HydratableEntry & { origin?: string; cleanSession?: boolean; replayAttempt?: string }

function hasPrivilegeMutationPayloadKey(node: unknown, depth = 0): boolean {
  if (depth > 2 || !node || typeof node !== 'object') return false
  if (Array.isArray(node)) return node.slice(0, 16).some(item => hasPrivilegeMutationPayloadKey(item, depth + 1))
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (PRIV_MUTATION_PAYLOAD_KEY_RE.test(k.trim())) return true
    if (v && typeof v === 'object' && depth < 2 && hasPrivilegeMutationPayloadKey(v, depth + 1)) return true
  }
  return false
}

function isPrivilegeOrActorMutationEntry(entry: HydratableEntry): boolean {
  const meth = entry.step.method.toUpperCase()
  if (stepReadsState(entry.step) || (meth !== 'PATCH' && meth !== 'POST' && meth !== 'PUT')) return false
  const cleanPath = normalizeGuardPath(entry.step.route ?? entry.step.pathAndQuery)
  if (cleanPath && PRIV_MUTATION_ROUTE_RE.test(cleanPath) && !PRIV_MUTATION_BENIGN_TAIL_RE.test(cleanPath)) return true
  return hasPrivilegeMutationPayloadKey(entry.step.requestJson) || hasPrivilegeMutationPayloadKey(entry.step.json)
}

function extractMutationLogicalEntityId(fromEx: HydratableEntry, fromHopEntityId: string | undefined, actorKey: string): string {
  if (fromEx.entityId?.trim()) return fromEx.entityId.trim()
  if (fromHopEntityId?.trim()) return fromHopEntityId.trim()
  const rawBase = (fromEx.step.pathAndQuery ?? fromEx.step.route ?? '').split(/[?#]/, 1)[0] ?? ''
  const rawSegs = rawBase.split('/').filter(Boolean)
  for (let i = rawSegs.length - 1; i >= 0; i--) {
    const seg = rawSegs[i]!.trim()
    const low = seg.toLowerCase()
    if (!seg || low === ':id' || low === '<scrubbed>') continue
    if (OWN_ORG_DYNAMIC_SEG_RE.test(seg)) return seg
  }
  return `actor:${actorKey}`
}

function isChronoBefore(a: GuardChronoEntry, b: GuardChronoEntry): boolean {
  const aTs = a.timestampMs, bTs = b.timestampMs
  if (typeof aTs !== 'number' || !Number.isFinite(aTs) || typeof bTs !== 'number' || !Number.isFinite(bTs)) return false
  if (aTs < bTs) return true
  return aTs === bTs && typeof a.seq === 'number' && typeof b.seq === 'number' && Number.isFinite(a.seq) && Number.isFinite(b.seq) && a.seq < b.seq
}

function compareChronoAsc(a: GuardChronoEntry, b: GuardChronoEntry): number {
  const aTs = typeof a.timestampMs === 'number' && Number.isFinite(a.timestampMs) ? a.timestampMs : Number.MAX_SAFE_INTEGER
  const bTs = typeof b.timestampMs === 'number' && Number.isFinite(b.timestampMs) ? b.timestampMs : Number.MAX_SAFE_INTEGER
  if (aTs !== bTs) return aTs - bTs
  const aSeq = typeof a.seq === 'number' && Number.isFinite(a.seq) ? a.seq : Number.MAX_SAFE_INTEGER
  const bSeq = typeof b.seq === 'number' && Number.isFinite(b.seq) ? b.seq : Number.MAX_SAFE_INTEGER
  return aSeq - bSeq
}

function originsCompatible(a: string | undefined, b: string | undefined): boolean {
  const na = (a ?? '').trim().replace(/\/+$/, '').toLowerCase()
  const nb = (b ?? '').trim().replace(/\/+$/, '').toLowerCase()
  return !na || !nb || na === nb
}

/**
 * R6-nx: Host-completed `state_transition_binding` inference for entity-less privileged read
 * terminals (e.g. privileged-mutation hop followed by a privileged read hop). Fires ONLY when:
 *  - `toEx` is an entity-less terminal `GET`/`HEAD` read under an authenticated actor;
 *  - `fromEx` is a succeeding `PATCH`/`POST`/`PUT` privilege/role/ACL/session mutation under the
 *    same actor identity lineage;
 *  - a verified clean pre-mutation denied `arm: 'control'` (401/403/404, strictly before `fromEx`,
 *    same actor — never anonymous 401 on an auth'd route) exists on the terminal read route family.
 */
export function resolveEntityLessReadStateTransition<T extends GuardChronoEntry>(params: {
  fromEx: T
  fromHopEntityId?: string
  toEx: T
  isTerminalTo: boolean
  allEntries: readonly T[]
  pairExIds: ReadonlySet<string>
  allHopExIds: ReadonlySet<string>
  preCtrlIds: ReadonlySet<string>
  normRouteFam: (p: string | null | undefined, eid?: string) => string
  sameCredIdentity: (a: T, b: T) => boolean
  probeActorOf: (e: T) => string | null
  isLoginCap: (cap: string) => boolean
  canonicalNonAuthQuery: (p: string | null | undefined) => string
}): { entityId: string; ablationExchangeId: string } | null {
  const { fromEx, fromHopEntityId, toEx, isTerminalTo, allEntries, pairExIds, allHopExIds, preCtrlIds, normRouteFam, sameCredIdentity, probeActorOf, isLoginCap, canonicalNonAuthQuery } = params
  if (!isTerminalTo || !stepReadsState(toEx.step) || toEx.entityId?.trim()) return null
  if (!isPrivilegeOrActorMutationEntry(fromEx)) return null
  const toRaw = actorOfGuardEntry(toEx)
  if (!toRaw || GUARD_ANON_ACTOR_RE.test(toRaw)) return null
  const toActor = probeActorOf(toEx)
  const fromActor = probeActorOf(fromEx)
  if (!toActor || !fromActor || toActor !== fromActor) return null
  const toFam = normRouteFam(toEx.step.route ?? toEx.step.pathAndQuery)
  if (!toFam) return null
  const toMeth = toEx.step.method.toUpperCase()
  const toQuery = canonicalNonAuthQuery(toEx.step.pathAndQuery ?? toEx.step.route)
  const cands = allEntries.filter(ab => {
    if (pairExIds.has(ab.exchangeId) || (!preCtrlIds.has(ab.exchangeId) && allHopExIds.has(ab.exchangeId))) return false
    if (ab.cleanSession !== true || (ab.step.arm !== 'control' && ab.replayAttempt !== 'ablation_control')) return false
    if (typeof ab.step.status !== 'number' || !ENTITY_LESS_DENIED_CTRL_STATUSES.has(ab.step.status)) return false
    if (ab.step.method.toUpperCase() !== toMeth || !originsCompatible(ab.origin, toEx.origin)) return false
    if (!isChronoBefore(ab, fromEx) || canonicalNonAuthQuery(ab.step.pathAndQuery ?? ab.step.route) !== toQuery) return false
    const abRaw = actorOfGuardEntry(ab)
    if (!abRaw || GUARD_ANON_ACTOR_RE.test(abRaw)) return false
    if (abRaw.startsWith('cap:') && abRaw !== toRaw && !isLoginCap(abRaw)) return false
    if (!sameCredIdentity(ab, toEx)) return false
    return normRouteFam(ab.step.route ?? ab.step.pathAndQuery, ab.entityId) === toFam
  })
  if (cands.length === 0) return null
  cands.sort(compareChronoAsc)
  const chosen = cands.find(c => preCtrlIds.has(c.exchangeId)) ?? cands[0]!
  return {
    entityId: extractMutationLogicalEntityId(fromEx, fromHopEntityId, toActor),
    ablationExchangeId: chosen.exchangeId,
  }
}

/**
 * R6-nx: Auto-select the earliest clean pre-mutation denied control (`401`/`403`/`404`) when a
 * `state_transition_binding` receipt cited a post-mutation `2xx` control (e.g. persistent
 * user-level role escalation). Never accepts a `2xx` control, never accepts an anonymous `401` on
 * an authenticated route, and requires a real mutating exchange between the clean pre-mutation
 * denial and the cited `2xx` exchange.
 */
export function findPreMutationDeniedControl<T extends GuardChronoEntry>(params: {
  citedTwoXx: T
  mutationEx: T
  toEx: T
  entityId?: string
  entriesById: ReadonlyMap<string, T>
  excludedIds: ReadonlySet<string>
  toUsesNewCap: boolean
  normRouteFam: (p: string | null | undefined, eid?: string) => string
  sameCredIdentity: (a: T, b: T) => boolean
  isLoginCap: (cap: string) => boolean
  canonicalNonAuthQuery: (p: string | null | undefined) => string
}): T | null {
  const { citedTwoXx, mutationEx, toEx, entityId, entriesById, excludedIds, toUsesNewCap, normRouteFam, sameCredIdentity, isLoginCap, canonicalNonAuthQuery } = params
  if (stepReadsState(mutationEx.step) || (typeof mutationEx.step.status === 'number' && (mutationEx.step.status < 200 || mutationEx.step.status >= 300))) return null
  const toFam = normRouteFam(toEx.step.route ?? toEx.step.pathAndQuery, entityId)
  if (!toFam) return null
  const toMeth = toEx.step.method.toUpperCase()
  const toQuery = canonicalNonAuthQuery(toEx.step.pathAndQuery ?? toEx.step.route)
  const toRaw = actorOfGuardEntry(toEx)
  const toAuth = Boolean(toRaw && !GUARD_ANON_ACTOR_RE.test(toRaw))
  const citedAfterMutation = isChronoBefore(mutationEx, citedTwoXx)
  const mutFam = normRouteFam(mutationEx.step.route ?? mutationEx.step.pathAndQuery, entityId)
  const allEntries = [...entriesById.values()]
  const hasInterveningMutation = (cand: T): boolean => {
    if (citedAfterMutation) return true
    if (!mutFam) return false
    return allEntries.some(m =>
      m.exchangeId !== cand.exchangeId && m.exchangeId !== citedTwoXx.exchangeId
      && !stepReadsState(m.step) && typeof m.step.status === 'number' && m.step.status >= 200 && m.step.status < 300
      && isChronoBefore(cand, m) && isChronoBefore(m, citedTwoXx)
      && normRouteFam(m.step.route ?? m.step.pathAndQuery, m.entityId ?? entityId) === mutFam,
    )
  }
  const cands = allEntries.filter(c => {
    if (excludedIds.has(c.exchangeId) || c.exchangeId === citedTwoXx.exchangeId || c.exchangeId === toEx.exchangeId || c.exchangeId === mutationEx.exchangeId) return false
    if (c.cleanSession !== true || (c.step.arm !== 'control' && c.replayAttempt !== 'ablation_control')) return false
    if (typeof c.step.status !== 'number' || !ENTITY_LESS_DENIED_CTRL_STATUSES.has(c.step.status)) return false
    if (c.step.method.toUpperCase() !== toMeth || !originsCompatible(c.origin, toEx.origin)) return false
    if (normRouteFam(c.step.route ?? c.step.pathAndQuery, c.entityId ?? entityId) !== toFam) return false
    if (canonicalNonAuthQuery(c.step.pathAndQuery ?? c.step.route) !== toQuery) return false
    if (!isChronoBefore(c, mutationEx) || !isChronoBefore(c, citedTwoXx)) return false
    const cRaw = actorOfGuardEntry(c)
    if (cRaw?.startsWith('cap:') && cRaw !== toRaw && !isLoginCap(cRaw)) return false
    if (toAuth) {
      if (!cRaw || GUARD_ANON_ACTOR_RE.test(cRaw)) return false
      if (!toUsesNewCap && !sameCredIdentity(c, toEx)) return false
    }
    return hasInterveningMutation(c)
  })
  if (cands.length === 0) return null
  cands.sort((a, b) => {
    const aLab = (a.step.arm === 'control' || a.replayAttempt === 'ablation_control') ? 0 : 1
    const bLab = (b.step.arm === 'control' || b.replayAttempt === 'ablation_control') ? 0 : 1
    return (aLab - bLab) || compareChronoAsc(a, b)
  })
  return cands[0]!
}

function bodyMentionsTenantToken(body: string, tenant: string): boolean {
  const lowBody = body.toLowerCase()
  const lowTenant = tenant.trim().toLowerCase()
  if (lowTenant.length < 3) return false
  let pos = lowBody.indexOf(lowTenant)
  while (pos >= 0) {
    const before = pos === 0 ? '' : lowBody[pos - 1]!
    const after = pos + lowTenant.length >= lowBody.length ? '' : lowBody[pos + lowTenant.length]!
    if ((before === '' || !/[a-z0-9_-]/.test(before)) && (after === '' || !/[a-z0-9_-]/.test(after))) return true
    pos = lowBody.indexOf(lowTenant, pos + 1)
  }
  return false
}

/**
 * R8: When `bledAccess` is opaque plain-text (non-JSON body with zero structured tenant markers)
 * AND the actor genuinely holds mixed dual-tenant roles (elevated in one tenant, lower in another),
 * fall back ONLY to unique foreign upstream cited hop markers or a unique known foreign tenant
 * explicitly present as a bounded token inside the plain-text response body (never fabricating a
 * target tenant with zero upstream/body evidence).
 */
export function resolveOpaqueDualCacheBleedTarget(params: {
  bled: HostSignedRecord | undefined
  primeTenant: string | null
  bledMarkers: ReadonlySet<string>
  actor: { actorId: string; rolesByTenant: Readonly<Record<string, string | null | undefined>> } | undefined
  citedUpstreamMarkers: readonly ReadonlySet<string>[]
  hostKnownTenants: ReadonlySet<string>
}): string | undefined {
  const { bled, primeTenant, bledMarkers, actor, citedUpstreamMarkers, hostKnownTenants } = params
  if (!bled || bledMarkers.size > 0 || !actor) return undefined
  // Only apply to genuinely opaque plain-text responses (never structured JSON lacking tenant markers).
  if (bled.json !== undefined) return undefined
  const trimmedBody = typeof bled.body === 'string' ? bled.body.trim() : ''
  if (!trimmedBody || /^[\[{]/.test(trimmedBody)) return undefined
  const entries = Object.entries(actor.rolesByTenant ?? {})
    .map(([t, r]) => [t.trim().toLowerCase(), normalizeRole(r ?? undefined)] as const)
    .filter(([t, r]) => Boolean(t && r))
  const distinctTenants = new Set(entries.map(([t]) => t))
  const hasElevated = entries.some(([, r]) => r !== null && ROLE_RANK[r] >= ROLE_RANK.admin)
  const hasLower = entries.some(([, r]) => r !== null && ROLE_RANK[r] < ROLE_RANK.admin)
  if (distinctTenants.size < 2 || !hasElevated || !hasLower) return undefined
  const prime = primeTenant?.trim().toLowerCase() ?? ''
  const upstreamForeign = new Set<string>()
  for (const ms of citedUpstreamMarkers) for (const m of ms) if (m && m !== prime) upstreamForeign.add(m)
  if (upstreamForeign.size === 1) return [...upstreamForeign][0]
  const bodyForeign = [...hostKnownTenants].filter(t => t && t !== prime && bodyMentionsTenantToken(trimmedBody, t))
  if (bodyForeign.length === 1) return bodyForeign[0]
  return undefined
}
