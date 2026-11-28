/**
 * Track C1: Unified Principal + Capability Custody Store.
 *
 * Composes `DerivedCapabilityVault` (single cryptographic sealing/HMAC/JWT source of truth) with
 * run-scoped `Principal` records, transparent response/request value-to-handle auto-linking (O(1)
 * raw + normalized variant lookup), a `deriveMutatedCapability` escape hatch preserving
 * `derivedFromHandle` lineage, and deterministic run-scoped disposal.
 */
import { existsSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import type { PersonaAuthKind, PersonaPrivilege } from '../domain.ts'
import { classifyPersonaPrivilege, type PersonaPrivilegeClassification } from './assignment-brief.ts'
import {
  DerivedCapabilityVault, isDerivedCapabilityHandle, isScrubbableCapabilityValue, vaultScrubDescriptors,
  type CapabilitySourceProvenance, type DerivedCapabilityHandle, type DerivedCapabilityMeta,
  type DerivedCapabilityVaultOptions, type DerivedSecretKind,
} from './derived-custody.ts'
import { personaSecrets, type ResolvedPersona } from './persona-vault.ts'
import type { NamedSecret } from './redact.ts'
import { registerRunDisposer } from './run-disposers.ts'

export type PrincipalKind = 'configured_persona' | 'isolated_clone' | 'derived_capability' | 'anonymous'
export type CapabilityCarrier = 'header' | 'cookie' | 'query' | 'body' | 'url' | 'derived'
export type MatchedVariantKind = 'raw' | 'url_encoded' | 'json_escaped' | 'bearer_stripped'

export interface Principal {
  principalId: string; kind: PrincipalKind; runId: string; handle: string; roleLabel: string
  tenantRef: string | null; privilege: PersonaPrivilege | null; privilegeClass: PersonaPrivilegeClassification
  configIndex: number; authKind: PersonaAuthKind | 'none'; originAllowlist: string[]; canaryMarkers: string[]
  harvestedIds: string[]; parentPrincipalId?: string; sourceProvenance?: CapabilitySourceProvenance
  sessionGeneration: number; expiresAtMs: number | null; active: boolean
}
export interface CapabilityRecord {
  handle: DerivedCapabilityHandle; runId: string; principalId: string; kind: DerivedSecretKind
  carrier: CapabilityCarrier; hopReceiptId: string; slot: string; sha256: string; sha256Prefix: string
  createdAtMs: number; expiresAtMs: number | null; allowedOrigins: string[]
  defaultHeaderName?: string; defaultCookieName?: string; derivedFromHandle?: DerivedCapabilityHandle
  sourceProvenance?: CapabilitySourceProvenance; active: boolean
}
export interface PrincipalCustodyStoreOptions { runId: string; vault?: DerivedCapabilityVault; persistDir?: string; vaultOptions?: Omit<DerivedCapabilityVaultOptions, 'runId'>; now?: () => number }
export interface RegisterIsolatedSessionInput { sessionKey: string; personaHandle: string; origin: string; headers: Record<string, string>; mintedAt?: number; expiresAtMs?: number | null }
export interface RegisterClonedPersonaInput { assignmentId: string; persona: ResolvedPersona; cloneId: string; generation?: number; rotatedCookies?: readonly string[]; headersByOrigin?: Readonly<Record<string, Record<string, string>>> }
export interface IndexResponseExtraction { slot?: string; rawValue: string; kind?: DerivedSecretKind; carrier?: CapabilityCarrier; headerName?: string; cookieName?: string }
export interface IndexResponseInput { hopReceiptId: string; origin?: string; ownerPrincipalId?: string; ownerHandle?: string; sourceExchangeId?: string; headers?: Readonly<Record<string, string | readonly string[] | undefined>>; setCookie?: readonly string[]; location?: string; extractions?: readonly IndexResponseExtraction[] }
export interface MatchRequestValuesInput { origin?: string; headers?: Readonly<Record<string, string | readonly string[] | undefined>>; query?: string | Readonly<Record<string, string | readonly string[] | undefined>>; url?: string; body?: string; parts?: readonly string[] }
export interface RequestValueMatch { matchType: 'capability' | 'principal'; matchedVariant: MatchedVariantKind; principalId: string; handle: string; capabilityHandle?: DerivedCapabilityHandle; capability?: CapabilityRecord; principal?: Principal; sourceProvenance?: CapabilitySourceProvenance }
export interface DeriveMutatedCapabilityInput { slot: string; rawValue: string; hopReceiptId: string; kind?: DerivedSecretKind; carrier?: CapabilityCarrier; allowedOrigins?: readonly string[]; defaultHeaderName?: string; defaultCookieName?: string }

interface ReverseIndexEntry { matchType: 'capability' | 'principal'; principalId: string; capabilityHandle?: DerivedCapabilityHandle; indexedVariant: MatchedVariantKind }
interface ResponseCandidate { slot: string; rawValue: string; kind: DerivedSecretKind; carrier: CapabilityCarrier; headerName?: string; cookieName?: string; minEntropyLen: number }
interface CustodyInternals {
  readonly runId: string; readonly safeRunId: string; readonly persistPath?: string; readonly now: () => number; readonly vault: DerivedCapabilityVault
  readonly principals: Map<string, Principal>; readonly principalByHandle: Map<string, string>; readonly capabilities: Map<DerivedCapabilityHandle, CapabilityRecord>
  readonly rawSecretsByPrincipal: Map<string, Map<string, string>>; readonly scrubHistory: Map<string, NamedSecret>
  readonly valueIndex: Map<string, ReverseIndexEntry>; readonly knownRawValues: Map<string, ReverseIndexEntry>
  autoSlotSeq: number; disposed: boolean
}

const custodyInternals = new WeakMap<PrincipalCustodyStore, CustodyInternals>()
const custodyStoresByRun = new Map<string, PrincipalCustodyStore>()

const SAFE_ID_RE = /^[A-Za-z0-9._-]{1,128}$/
const JWT_SHAPE_RE = /^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*$/
const TOKEN_HEADER_RE = /^(?:authorization|proxy-authorization|x-api-key|api-key|x-auth-token|x-access-token|x-session-token|x-refresh-token|x-csrf-token|x-xsrf-token|x-reset-token|x-invite-token|private-token)$/i
const TOKEN_QUERY_PARAM_RE = /^(?:token|access_token|id_token|refresh_token|code|sig|signature|key|api_key|apikey|auth|session|session_id|ticket|invite|invite_token|reset|reset_token|jwt|nonce|secret|credential|assertion)$/i
const EXPLICIT_PRIVILEGE_RANK: Record<PersonaPrivilege, { rank: number; tier: PersonaPrivilegeClassification['tier']; elevated: boolean }> = {
  viewer: { rank: 0, tier: 'low', elevated: false }, member: { rank: 1, tier: 'standard', elevated: false },
  admin: { rank: 4, tier: 'elevated', elevated: true }, owner: { rank: 5, tier: 'elevated', elevated: true },
}
const safeCustodyRunId = (runId: string): string => SAFE_ID_RE.test(runId) ? runId : runId.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 128) || 'run'
const resolvePersistPath = (persistDir: string | undefined, safeId: string): string | undefined => persistDir && existsSync(persistDir) ? join(persistDir, 'capability-vaults', `${safeId}.json`) : undefined
const sanitizeSlot = (raw: string): string => raw.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 48) || 'tok'
const normalizeOriginSafe = (raw: string | undefined): string | null => {
  if (!raw) return null
  try { const u = new URL(raw); return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : null } catch { return null }
}
function shannonEntropy(value: string): number {
  if (!value.length) return 0
  const counts = new Map<string, number>()
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let h = 0
  for (const c of counts.values()) { const p = c / value.length; h -= p * Math.log2(p) }
  return h
}
const isHighEntropyCandidate = (rawValue: string, minLen = 8): boolean => {
  const t = rawValue.trim()
  return t.length >= minLen && isScrubbableCapabilityValue(t, Math.min(6, minLen)) && (JWT_SHAPE_RE.test(t) || (new Set(t).size >= 4 && shannonEntropy(t) >= 1.8))
}
function resolvePrivilegeClass(handle: string, roleLabel: string, explicit?: PersonaPrivilege | null, tenantRef?: string | null): PersonaPrivilegeClassification {
  const inferred = classifyPersonaPrivilege(handle, roleLabel, { privilege: explicit, tenantRef }), mapped = explicit ? EXPLICIT_PRIVILEGE_RANK[explicit] : undefined
  if (!mapped) return inferred
  return { ...inferred, rank: mapped.rank, elevated: mapped.elevated, tier: inferred.revokedStale || inferred.multiTenant ? inferred.tier : mapped.tier }
}
const clonePrincipal = (p: Principal): Principal => ({
  ...p, privilegeClass: { ...p.privilegeClass, tenants: [...p.privilegeClass.tenants] }, originAllowlist: [...p.originAllowlist], canaryMarkers: [...p.canaryMarkers], harvestedIds: [...p.harvestedIds],
  ...(p.sourceProvenance ? { sourceProvenance: { ...p.sourceProvenance } } : {}),
})
const cloneCapability = (c: CapabilityRecord): CapabilityRecord => ({ ...c, allowedOrigins: [...c.allowedOrigins], ...(c.sourceProvenance ? { sourceProvenance: { ...c.sourceProvenance } } : {}) })
const provenanceFromPrincipal = (p: Principal | undefined, sourceExchangeId?: string): CapabilitySourceProvenance | undefined =>
  !p && !sourceExchangeId ? undefined : { ...(sourceExchangeId ? { sourceExchangeId } : {}), sourcePersonaHandle: p?.handle ?? null, sourceActorRoleLabel: p?.roleLabel ?? null, sourceActorRole: p?.privilege ?? p?.privilegeClass.tier ?? null, sourceActorTenant: p?.tenantRef ?? null }
const buildCapabilityRecord = (
  runId: string, principalId: string, carrier: CapabilityCarrier, meta: DerivedCapabilityMeta,
  provenance?: CapabilitySourceProvenance, derivedFromHandle?: DerivedCapabilityHandle,
): CapabilityRecord => ({
  handle: meta.handle, runId, principalId, kind: meta.kind, carrier, hopReceiptId: meta.hopReceiptId, slot: meta.slot,
  sha256: meta.sha256, sha256Prefix: meta.sha256Prefix, createdAtMs: meta.createdAtMs, expiresAtMs: meta.expiresAtMs,
  allowedOrigins: meta.allowedOrigins ? [...meta.allowedOrigins] : [],
  ...(meta.defaultHeaderName ? { defaultHeaderName: meta.defaultHeaderName } : {}), ...(meta.defaultCookieName ? { defaultCookieName: meta.defaultCookieName } : {}),
  ...(derivedFromHandle ? { derivedFromHandle } : {}), ...(provenance ? { sourceProvenance: { ...provenance } } : {}), active: true,
})
const getState = (store: PrincipalCustodyStore): CustodyInternals => { const s = custodyInternals.get(store); if (!s) throw new Error('Invalid PrincipalCustodyStore instance.'); return s }

function indexSecretVariants(
  state: CustodyInternals, rawValue: string, entry: Omit<ReverseIndexEntry, 'indexedVariant'>, placeholder: string,
): void {
  const trimmed = rawValue.trim()
  if (trimmed.length < 6) return
  if (isScrubbableCapabilityValue(trimmed, 6) && !state.scrubHistory.has(trimmed)) {
    state.scrubHistory.set(trimmed, { value: trimmed, placeholder })
  }
  const isCap = entry.matchType === 'capability'
  const put = (key: string, indexedVariant: MatchedVariantKind) => {
    if (key.length >= 6 && (isCap || !state.valueIndex.has(key))) state.valueIndex.set(key, { ...entry, indexedVariant })
  }
  put(trimmed, 'raw')
  if (isCap || !state.knownRawValues.has(trimmed)) state.knownRawValues.set(trimmed, { ...entry, indexedVariant: 'raw' })
  const bare = /^Bearer\s+(.+)$/i.exec(trimmed)?.[1]?.trim()
  if (bare && bare.length >= 6) {
    put(bare, 'bearer_stripped')
    if (isCap || !state.knownRawValues.has(bare)) state.knownRawValues.set(bare, { ...entry, indexedVariant: 'bearer_stripped' })
    if (isScrubbableCapabilityValue(bare, 6) && !state.scrubHistory.has(bare)) state.scrubHistory.set(bare, { value: bare, placeholder })
  }
  for (const cand of bare && bare.length >= 6 ? [trimmed, bare] : [trimmed]) {
    const encoded = encodeURIComponent(cand)
    if (encoded !== cand) {
      put(encoded, 'url_encoded')
      const lower = encoded.replace(/%[0-9A-F]{2}/g, m => m.toLowerCase())
      if (lower !== encoded) put(lower, 'url_encoded')
      if (encoded.includes('%20')) put(encoded.replaceAll('%20', '+'), 'url_encoded')
    }
    const jsonEscaped = JSON.stringify(cand).slice(1, -1)
    if (jsonEscaped !== cand) put(jsonEscaped, 'json_escaped')
    if (cand.includes('/')) {
      put(cand.replaceAll('/', '\\/'), 'json_escaped')
      if (jsonEscaped !== cand) put(jsonEscaped.replaceAll('/', '\\/'), 'json_escaped')
    }
  }
  const eq = trimmed.indexOf('=')
  if (eq > 0 && eq < trimmed.length - 1 && !trimmed.includes(';')) {
    const cookieVal = trimmed.slice(eq + 1).trim()
    if (cookieVal.length >= 8 && !cookieVal.includes('=')) indexSecretVariants(state, cookieVal, entry, placeholder)
  }
}

function recordPrincipalSecret(state: CustodyInternals, principalId: string, rawValue: string, placeholder: string): void {
  const trimmed = rawValue.trim()
  if (trimmed.length < 6) return
  let map = state.rawSecretsByPrincipal.get(principalId)
  if (!map) { map = new Map(); state.rawSecretsByPrincipal.set(principalId, map) }
  map.set(trimmed, placeholder)
  indexSecretVariants(state, trimmed, { matchType: 'principal', principalId }, placeholder)
}

function indexHeaderMapForPrincipal(
  state: CustodyInternals, principalId: string, handle: string, headers: Readonly<Record<string, string>>,
): void {
  for (const [k, v] of Object.entries(headers)) {
    if (typeof v !== 'string' || !v.trim()) continue
    const lower = k.toLowerCase()
    if (TOKEN_HEADER_RE.test(lower)) recordPrincipalSecret(state, principalId, v, `[redacted:principal:${handle}:${lower}]`)
    else if (lower === 'cookie') {
      for (const pair of v.split(';')) {
        const eq = pair.indexOf('=')
        if (eq <= 0) continue
        const name = pair.slice(0, eq).trim(), val = pair.slice(eq + 1).trim()
        if (name && val.length >= 8) recordPrincipalSecret(state, principalId, val, `[redacted:principal:${handle}:cookie:${name}]`)
      }
    }
  }
}

function parseSetCookieLine(line: string): { name: string; value: string } | null {
  const seg = line.split(';', 1)[0]?.trim()
  const eq = seg ? seg.indexOf('=') : -1
  if (!seg || eq <= 0) return null
  const name = seg.slice(0, eq).trim(), value = seg.slice(eq + 1).trim()
  return name && value ? { name, value } : null
}

function collectResponseCandidates(input: IndexResponseInput): ResponseCandidate[] {
  const out: ResponseCandidate[] = [], setCookies: string[] = [...(input.setCookie ?? [])]
  let location = input.location
  for (const [rawKey, rawVal] of Object.entries(input.headers ?? {})) {
    if (rawVal === undefined) continue
    const lower = rawKey.toLowerCase(), vals = Array.isArray(rawVal) ? rawVal : [rawVal]
    if (lower === 'set-cookie') { for (const v of vals) if (typeof v === 'string') setCookies.push(v) }
    else if (lower === 'location' && !location) { const f = vals.find(v => typeof v === 'string' && v.trim()); if (typeof f === 'string') location = f }
    else if (TOKEN_HEADER_RE.test(lower)) {
      for (const v of vals) {
        if (typeof v !== 'string') continue
        const trimmed = v.trim(), bearer = /^Bearer\s+(.+)$/i.exec(trimmed), tok = bearer?.[1]?.trim() ?? trimmed
        out.push({ slot: `hdr_${sanitizeSlot(lower)}`, rawValue: tok, kind: JWT_SHAPE_RE.test(tok) ? 'jwt' : bearer ? 'bearer_token' : 'header_secret', carrier: 'header', headerName: rawKey, minEntropyLen: 8 })
      }
    }
  }
  for (const line of setCookies) {
    const p = parseSetCookieLine(line)
    if (p) out.push({ slot: `cookie_${sanitizeSlot(p.name)}`, rawValue: p.value, kind: JWT_SHAPE_RE.test(p.value) ? 'jwt' : 'cookie', carrier: 'cookie', cookieName: p.name, minEntropyLen: 8 })
  }
  if (location) {
    try {
      const u = new URL(location, input.origin ?? 'http://localhost')
      const pairs: Array<[string, string]> = [...u.searchParams.entries(), ...(u.hash.includes('=') ? [...new URLSearchParams(u.hash.slice(1)).entries()] : [])]
      for (const [k, v] of pairs) {
        const named = TOKEN_QUERY_PARAM_RE.test(k)
        if (named || (v.length >= 16 && shannonEntropy(v) >= 2.6)) {
          out.push({ slot: `query_${sanitizeSlot(k)}`, rawValue: v, kind: JWT_SHAPE_RE.test(v) ? 'jwt' : 'signed_url', carrier: 'query', minEntropyLen: named ? 8 : 16 })
        }
      }
    } catch { /* ignore malformed Location */ }
  }
  for (const ext of input.extractions ?? []) {
    if (!ext || typeof ext.rawValue !== 'string' || !ext.rawValue.trim()) continue
    const tok = ext.rawValue.trim()
    out.push({
      slot: sanitizeSlot(ext.slot ?? (ext.cookieName ? `cookie_${ext.cookieName}` : ext.headerName ? `hdr_${ext.headerName}` : 'extracted')),
      rawValue: tok, kind: ext.kind ?? (JWT_SHAPE_RE.test(tok) ? 'jwt' : 'generic_secret'), carrier: ext.carrier ?? 'body',
      ...(ext.headerName ? { headerName: ext.headerName } : {}), ...(ext.cookieName ? { cookieName: ext.cookieName } : {}), minEntropyLen: 6,
    })
  }
  return out
}

const safeDecodeURIComponent = (v: string): string | null => { try { return decodeURIComponent(v) } catch { return null } }
function safeJsonUnescape(value: string): string | null {
  try { return JSON.parse(`"${value.replace(/"/g, '\\"')}"`) as string } catch {
    try { return JSON.parse(`"${value}"`) as string } catch { return null }
  }
}
function collectJsonStringLeaves(value: unknown, out: string[], depth = 0): void {
  if (depth > 8 || out.length >= 256) return
  if (typeof value === 'string') { if (value.length >= 6) out.push(value); return }
  if (Array.isArray(value)) { for (const item of value) collectJsonStringLeaves(item, out, depth + 1); return }
  if (value && typeof value === 'object') { for (const v of Object.values(value as Record<string, unknown>)) collectJsonStringLeaves(v, out, depth + 1) }
}

function collectRequestCandidateStrings(input: MatchRequestValuesInput): string[] {
  const out: string[] = []
  const push = (val: string | undefined) => { const t = val?.trim(); if (t && t.length >= 6) out.push(t) }
  const pushQuery = (raw: string) => {
    const cleaned = raw.startsWith('?') ? raw.slice(1) : raw
    for (const pair of cleaned.split('&')) { const eq = pair.indexOf('='); if (eq >= 0) push(pair.slice(eq + 1)) }
    for (const v of new URLSearchParams(cleaned).values()) push(v)
  }
  for (const [k, rawVal] of Object.entries(input.headers ?? {})) {
    if (rawVal === undefined) continue
    const lower = k.toLowerCase()
    for (const v of Array.isArray(rawVal) ? rawVal : [rawVal]) {
      if (typeof v !== 'string') continue
      push(v)
      if (lower === 'cookie') {
        for (const pair of v.split(';')) { const t = pair.trim(); push(t); const eq = t.indexOf('='); if (eq > 0) push(t.slice(eq + 1)) }
      }
    }
  }
  if (input.url) {
    const q = input.url.indexOf('?')
    if (q >= 0) { const h = input.url.indexOf('#', q); pushQuery(h >= 0 ? input.url.slice(q + 1, h) : input.url.slice(q + 1)) }
  }
  if (typeof input.query === 'string') pushQuery(input.query)
  else if (input.query) {
    for (const rv of Object.values(input.query)) if (rv !== undefined) for (const v of Array.isArray(rv) ? rv : [rv]) if (typeof v === 'string') push(v)
  }
  if (typeof input.body === 'string' && input.body.length >= 6) {
    push(input.body)
    const trimmed = input.body.trim()
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      const literalRe = /"((?:\\.|[^"\\]){6,})"/g
      let m: RegExpExecArray | null, scanned = 0
      while ((m = literalRe.exec(trimmed)) !== null && scanned < 256) { if (m[1]) out.push(m[1]); scanned += 1 }
      try { collectJsonStringLeaves(JSON.parse(trimmed), out) } catch { /* non-JSON */ }
    } else if (trimmed.includes('=')) pushQuery(trimmed)
  }
  for (const part of input.parts ?? []) push(part)
  return out
}

function upsertClonePrincipal(
  state: CustodyInternals, principalId: string, handle: string,
  opts: { roleLabel?: string; tenantRef?: string | null; privilege?: PersonaPrivilege | null; authKind?: PersonaAuthKind; originAllowlist: readonly string[]; canaryMarkers?: readonly string[]; generation?: number; expiresAtMs?: number | null },
): Principal {
  const parentId = state.principalByHandle.get(handle)
  const parent = parentId ? state.principals.get(parentId) : undefined
  const existing = state.principals.get(principalId)
  const origins = new Set<string>([...(parent?.originAllowlist ?? []), ...(existing?.originAllowlist ?? []), ...opts.originAllowlist])
  const roleLabel = opts.roleLabel ?? parent?.roleLabel ?? handle
  const privilege = opts.privilege ?? parent?.privilege ?? null
  const principal: Principal = {
    principalId, kind: 'isolated_clone', runId: state.runId, handle, roleLabel,
    tenantRef: opts.tenantRef ?? parent?.tenantRef ?? null, privilege,
    privilegeClass: parent ? { ...parent.privilegeClass, tenants: [...parent.privilegeClass.tenants] } : resolvePrivilegeClass(handle, roleLabel, privilege, opts.tenantRef ?? null),
    configIndex: parent?.configIndex ?? state.principals.size, authKind: opts.authKind ?? parent?.authKind ?? 'header',
    originAllowlist: [...origins], canaryMarkers: [...(opts.canaryMarkers ?? parent?.canaryMarkers ?? [])],
    harvestedIds: existing ? [...existing.harvestedIds] : [], ...(parent ? { parentPrincipalId: parent.principalId } : {}),
    sessionGeneration: opts.generation ?? ((existing?.sessionGeneration ?? 0) + 1),
    expiresAtMs: opts.expiresAtMs ?? null, active: true,
  }
  state.principals.set(principalId, principal)
  return principal
}

export class PrincipalCustodyStore {
  readonly runId: string
  readonly vault: DerivedCapabilityVault

  constructor(options: PrincipalCustodyStoreOptions) {
    const safeRunId = safeCustodyRunId(options.runId)
    const persistPath = options.vaultOptions?.persistPath ?? resolvePersistPath(options.persistDir, safeRunId)
    const now = options.now ?? Date.now
    const vault = options.vault ?? new DerivedCapabilityVault({
      runId: safeRunId, now, ...(options.vaultOptions ?? {}), ...(persistPath ? { persistPath } : {}),
    })
    this.runId = options.runId
    this.vault = vault
    custodyInternals.set(this, {
      runId: options.runId, safeRunId, persistPath, now, vault,
      principals: new Map(), principalByHandle: new Map(), capabilities: new Map(),
      rawSecretsByPrincipal: new Map(), scrubHistory: new Map(), valueIndex: new Map(), knownRawValues: new Map(),
      autoSlotSeq: 0, disposed: false,
    })
  }

  registerPersona(persona: ResolvedPersona, configIndex?: number): Principal {
    const state = getState(this), principalId = `persona:${persona.handle}`, existing = state.principals.get(principalId)
    const principal: Principal = {
      principalId, kind: 'configured_persona', runId: state.runId, handle: persona.handle,
      roleLabel: persona.roleLabel, tenantRef: persona.tenantRef ?? null, privilege: persona.privilege ?? null,
      privilegeClass: resolvePrivilegeClass(persona.handle, persona.roleLabel, persona.privilege, persona.tenantRef),
      configIndex: configIndex ?? existing?.configIndex ?? state.principals.size, authKind: persona.authKind,
      originAllowlist: [...persona.originAllowlist], canaryMarkers: [...persona.canaryMarkers],
      harvestedIds: existing ? [...existing.harvestedIds] : [],
      sessionGeneration: persona.session?.generation ?? (existing ? existing.sessionGeneration + 1 : 1),
      expiresAtMs: persona.session?.expiresAt ?? null, active: true,
    }
    state.principals.set(principalId, principal)
    state.principalByHandle.set(persona.handle, principalId)
    for (const n of personaSecrets(new Map([[persona.handle, persona]]))) recordPrincipalSecret(state, principalId, n.value, n.placeholder)
    if (persona.secret) recordPrincipalSecret(state, principalId, persona.secret, `[redacted:persona:${persona.handle}]`)
    for (const prev of persona.secretHistory ?? []) recordPrincipalSecret(state, principalId, prev, `[redacted:persona:${persona.handle}:history]`)
    if (persona.session?.value) recordPrincipalSecret(state, principalId, persona.session.value, `[redacted:persona:${persona.handle}:session]`)
    for (const tok of persona.session?.scrubTokens ?? []) recordPrincipalSecret(state, principalId, tok, `[redacted:persona:${persona.handle}:scrub]`)
    return clonePrincipal(principal)
  }

  registerPersonas(resolved: ReadonlyMap<string, ResolvedPersona>): Principal[] {
    const out: Principal[] = []
    let idx = 0
    for (const persona of resolved.values()) { out.push(this.registerPersona(persona, idx)); idx += 1 }
    return out
  }

  registerIsolatedSession(input: RegisterIsolatedSessionInput): Principal {
    const state = getState(this), normOrigin = normalizeOriginSafe(input.origin)
    const principal = upsertClonePrincipal(state, `iso:${input.sessionKey}:${input.personaHandle}`, input.personaHandle, { originAllowlist: normOrigin ? [normOrigin] : [], expiresAtMs: input.expiresAtMs ?? null })
    indexHeaderMapForPrincipal(state, principal.principalId, input.personaHandle, input.headers)
    return clonePrincipal(principal)
  }
  registerClonedPersona(input: RegisterClonedPersonaInput): Principal {
    const state = getState(this), p = input.persona
    const principal = upsertClonePrincipal(state, `clone:${input.assignmentId}:${p.handle}`, p.handle, {
      roleLabel: p.roleLabel, tenantRef: p.tenantRef, privilege: p.privilege, authKind: p.authKind,
      originAllowlist: p.originAllowlist, canaryMarkers: p.canaryMarkers, generation: input.generation, expiresAtMs: p.session?.expiresAt ?? null,
    })
    for (const n of personaSecrets(new Map([[p.handle, p]]))) recordPrincipalSecret(state, principal.principalId, n.value, n.placeholder)
    for (const hdrs of Object.values(input.headersByOrigin ?? {})) indexHeaderMapForPrincipal(state, principal.principalId, p.handle, hdrs)
    for (const line of input.rotatedCookies ?? []) { const parsed = parseSetCookieLine(line); if (parsed) recordPrincipalSecret(state, principal.principalId, parsed.value, `[redacted:clone:${p.handle}:cookie:${parsed.name}]`) }
    return clonePrincipal(principal)
  }
  recordRotatedCloneCookies(input: { assignmentId: string; personaHandle: string; setCookieLines: readonly string[]; generation?: number }): void {
    const state = getState(this), principalId = `clone:${input.assignmentId}:${input.personaHandle}`, existing = state.principals.get(principalId)
    if (existing) existing.sessionGeneration = input.generation ?? existing.sessionGeneration + 1
    const ownerId = existing ? principalId : (state.principalByHandle.get(input.personaHandle) ?? principalId)
    for (const line of input.setCookieLines) { const parsed = parseSetCookieLine(line); if (parsed) recordPrincipalSecret(state, ownerId, parsed.value, `[redacted:clone:${input.personaHandle}:cookie:${parsed.name}]`) }
  }
  getPrincipal(principalIdOrHandle: string): Principal | null {
    const state = getState(this)
    const hit = state.principals.get(principalIdOrHandle) ?? state.principals.get(state.principalByHandle.get(principalIdOrHandle) ?? '')
    return hit ? clonePrincipal(hit) : null
  }
  getCapability(handle: string): CapabilityRecord | null {
    const rec = isDerivedCapabilityHandle(handle) ? getState(this).capabilities.get(handle) : undefined
    return rec ? cloneCapability(rec) : null
  }
  listLowPrivFirst(options: { includeClones?: boolean; includeInactive?: boolean; tenantRef?: string } = {}): Principal[] {
    const list: Principal[] = []
    for (const p of getState(this).principals.values()) {
      if ((!options.includeInactive && !p.active) || (!options.includeClones && p.kind !== 'configured_persona')) continue
      if (options.tenantRef !== undefined && p.tenantRef !== options.tenantRef) continue
      list.push(clonePrincipal(p))
    }
    return list.sort((a, b) => (a.privilegeClass.rank - b.privilegeClass.rank) || (a.configIndex - b.configIndex) || a.principalId.localeCompare(b.principalId))
  }

  indexResponse(input: IndexResponseInput): CapabilityRecord[] {
    const state = getState(this), owner = this.resolveOwnerPrincipal(state, input.ownerPrincipalId, input.ownerHandle, input.origin)
    const provenance = provenanceFromPrincipal(owner, input.sourceExchangeId)
    const normOrigin = normalizeOriginSafe(input.origin), allowedOrigins = normOrigin ? [normOrigin] : owner.originAllowlist.slice()
    const sealed: CapabilityRecord[] = []
    for (const cand of collectResponseCandidates(input)) {
      const trimmed = cand.rawValue.trim()
      if (!isHighEntropyCandidate(trimmed, cand.minEntropyLen) || state.knownRawValues.has(trimmed)) continue
      let slot = cand.slot
      if (this.vault.hasEverSealed(`cap:hop_${input.hopReceiptId}:${slot}`)) { state.autoSlotSeq += 1; slot = `${slot.slice(0, 48)}_${state.autoSlotSeq}` }
      const meta = this.vault.seal({
        hopReceiptId: input.hopReceiptId, slot, rawValue: trimmed, kind: cand.kind,
        ...(cand.headerName ? { defaultHeaderName: cand.headerName } : {}), ...(cand.cookieName ? { defaultCookieName: cand.cookieName } : {}),
        ...(allowedOrigins.length ? { allowedOrigins } : {}), ...(provenance ? { sourceProvenance: provenance } : {}),
      })
      const record = buildCapabilityRecord(state.runId, owner.principalId, cand.carrier, meta, provenance)
      state.capabilities.set(record.handle, record)
      indexSecretVariants(state, trimmed, { matchType: 'capability', principalId: owner.principalId, capabilityHandle: record.handle }, `[redacted:${record.handle}]`)
      sealed.push(cloneCapability(record))
    }
    return sealed
  }

  deriveMutatedCapability(baseHandleOrPrincipalId: string, mutation: DeriveMutatedCapabilityInput): CapabilityRecord {
    const state = getState(this)
    const baseCap = isDerivedCapabilityHandle(baseHandleOrPrincipalId) ? state.capabilities.get(baseHandleOrPrincipalId) : undefined
    const basePrincipal = baseCap
      ? state.principals.get(baseCap.principalId)
      : state.principals.get(baseHandleOrPrincipalId) ?? state.principals.get(state.principalByHandle.get(baseHandleOrPrincipalId) ?? '')
    if (!baseCap && !basePrincipal) throw new Error(`Unknown base handle or principal "${baseHandleOrPrincipalId}" for deriveMutatedCapability.`)
    const principalId = baseCap?.principalId ?? basePrincipal!.principalId
    const provenance = baseCap?.sourceProvenance ? { ...baseCap.sourceProvenance } : provenanceFromPrincipal(basePrincipal)
    const allowedOrigins = mutation.allowedOrigins ? [...mutation.allowedOrigins] : baseCap?.allowedOrigins.length ? [...baseCap.allowedOrigins] : basePrincipal?.originAllowlist.length ? [...basePrincipal.originAllowlist] : undefined
    const meta = this.vault.seal({
      hopReceiptId: mutation.hopReceiptId, slot: mutation.slot, rawValue: mutation.rawValue,
      kind: mutation.kind ?? baseCap?.kind ?? (JWT_SHAPE_RE.test(mutation.rawValue.trim()) ? 'jwt' : 'generic_secret'),
      ...(baseCap ? { derivedFromCapabilityId: baseCap.handle } : {}),
      ...(mutation.defaultHeaderName ?? baseCap?.defaultHeaderName ? { defaultHeaderName: mutation.defaultHeaderName ?? baseCap?.defaultHeaderName } : {}),
      ...(mutation.defaultCookieName ?? baseCap?.defaultCookieName ? { defaultCookieName: mutation.defaultCookieName ?? baseCap?.defaultCookieName } : {}),
      ...(allowedOrigins?.length ? { allowedOrigins } : {}), ...(provenance ? { sourceProvenance: provenance } : {}),
    })
    const record = buildCapabilityRecord(state.runId, principalId, mutation.carrier ?? 'derived', meta, provenance, baseCap?.handle)
    state.capabilities.set(record.handle, record)
    indexSecretVariants(state, mutation.rawValue, { matchType: 'capability', principalId, capabilityHandle: record.handle }, `[redacted:${record.handle}]`)
    return cloneCapability(record)
  }

  lookupHandleByRawValue(rawValue: string, targetOrigin?: string): RequestValueMatch | null {
    const state = getState(this)
    if (state.disposed || typeof rawValue !== 'string') return null
    const trimmed = rawValue.trim()
    if (trimmed.length < 6) return null
    const normOrigin = normalizeOriginSafe(targetOrigin)
    const resolve = (entry: ReverseIndexEntry | undefined, matchedVariant: MatchedVariantKind): RequestValueMatch | null => {
      if (!entry) return null
      const principal = state.principals.get(entry.principalId)
      if (entry.matchType === 'capability' && entry.capabilityHandle) {
        const cap = state.capabilities.get(entry.capabilityHandle)
        if (!cap || !cap.active || (cap.expiresAtMs !== null && state.now() >= cap.expiresAtMs)) return null
        if (normOrigin && cap.allowedOrigins.length && !cap.allowedOrigins.includes(normOrigin)) return null
        return {
          matchType: 'capability', matchedVariant, principalId: cap.principalId,
          handle: principal?.handle ?? cap.sourceProvenance?.sourcePersonaHandle ?? 'anonymous',
          capabilityHandle: cap.handle, capability: cloneCapability(cap),
          ...(principal ? { principal: clonePrincipal(principal) } : {}),
          ...(cap.sourceProvenance ? { sourceProvenance: { ...cap.sourceProvenance } } : {}),
        }
      }
      return !principal || !principal.active ? null : {
        matchType: 'principal', matchedVariant, principalId: principal.principalId, handle: principal.handle,
        principal: clonePrincipal(principal), sourceProvenance: provenanceFromPrincipal(principal),
      }
    }
    const direct = state.valueIndex.get(trimmed)
    if (direct) return resolve(direct, direct.indexedVariant)
    const bearer = /^Bearer\s+(.+)$/i.exec(trimmed)?.[1]?.trim()
    if (bearer) { const hit = state.valueIndex.get(bearer); if (hit) return resolve(hit, 'bearer_stripped') }
    if (trimmed.includes('%') || trimmed.includes('+')) {
      const dec = safeDecodeURIComponent(trimmed)
      if (dec && dec !== trimmed) { const hit = state.valueIndex.get(dec); if (hit) return resolve(hit, 'url_encoded') }
      if (trimmed.includes('+')) {
        const form = safeDecodeURIComponent(trimmed.replaceAll('+', '%20'))
        if (form && form !== trimmed) { const hit = state.valueIndex.get(form); if (hit) return resolve(hit, 'url_encoded') }
      }
    }
    if (trimmed.includes('\\')) {
      const unesc = safeJsonUnescape(trimmed)
      if (unesc && unesc !== trimmed) { const hit = state.valueIndex.get(unesc); if (hit) return resolve(hit, 'json_escaped') }
    }
    return null
  }

  matchRequestValues(input: MatchRequestValuesInput): RequestValueMatch[] {
    if (getState(this).disposed) return []
    const seen = new Set<string>(), matches: RequestValueMatch[] = []
    for (const cand of collectRequestCandidateStrings(input)) {
      const match = this.lookupHandleByRawValue(cand, input.origin)
      if (!match) continue
      const key = match.capabilityHandle ? `cap:${match.capabilityHandle}` : `principal:${match.principalId}`
      if (!seen.has(key)) { seen.add(key); matches.push(match) }
    }
    return matches
  }

  scrubDescriptors(minLength = 6): NamedSecret[] {
    const byValue = new Map<string, NamedSecret>()
    for (const item of vaultScrubDescriptors(this.vault, minLength)) byValue.set(item.value, item)
    for (const item of getState(this).scrubHistory.values()) if (!byValue.has(item.value) && isScrubbableCapabilityValue(item.value, minLength)) byValue.set(item.value, item)
    return [...byValue.values()]
  }
  dispose(): void {
    const state = getState(this)
    state.disposed = true
    for (const meta of this.vault.list()) this.vault.revoke(meta.handle)
    state.principals.clear(); state.principalByHandle.clear(); state.capabilities.clear()
    state.rawSecretsByPrincipal.clear(); state.scrubHistory.clear(); state.valueIndex.clear(); state.knownRawValues.clear()
    if (state.persistPath) { try { rmSync(state.persistPath, { force: true }) } catch { /* ignore */ } }
  }
  toJSON(): { runId: string; principalCount: number; capabilityCount: number; principals: Principal[]; capabilities: CapabilityRecord[] } {
    const s = getState(this)
    return { runId: s.runId, principalCount: s.principals.size, capabilityCount: s.capabilities.size, principals: [...s.principals.values()].map(clonePrincipal), capabilities: [...s.capabilities.values()].map(cloneCapability) }
  }
  [Symbol.for('nodejs.util.inspect.custom')](): string { const s = getState(this); return `PrincipalCustodyStore(runId=${s.runId}, principals=${s.principals.size}, capabilities=${s.capabilities.size})` }
  private resolveOwnerPrincipal(state: CustodyInternals, ownerPrincipalId?: string, ownerHandle?: string, origin?: string): Principal {
    if (ownerPrincipalId && state.principals.has(ownerPrincipalId)) return state.principals.get(ownerPrincipalId)!
    const byHandleId = ownerHandle ? state.principalByHandle.get(ownerHandle) : undefined
    if (byHandleId && state.principals.has(byHandleId)) return state.principals.get(byHandleId)!
    const anonId = 'anonymous:default'
    let anon = state.principals.get(anonId)
    if (!anon) {
      const normOrigin = normalizeOriginSafe(origin)
      anon = {
        principalId: anonId, kind: 'anonymous', runId: state.runId, handle: 'anonymous', roleLabel: 'anonymous',
        tenantRef: null, privilege: null, privilegeClass: classifyPersonaPrivilege('anonymous', 'anonymous'),
        configIndex: Number.MAX_SAFE_INTEGER, authKind: 'none', originAllowlist: normOrigin ? [normOrigin] : [],
        canaryMarkers: [], harvestedIds: [], sessionGeneration: 0, expiresAtMs: null, active: true,
      }
      state.principals.set(anonId, anon)
    }
    return anon
  }
}

export function getOrCreatePrincipalCustodyStore(runId: string, opts: Omit<PrincipalCustodyStoreOptions, 'runId'> = {}): PrincipalCustodyStore {
  const key = runId.trim() || '__default__'
  let store = custodyStoresByRun.get(key)
  if (!store) { store = new PrincipalCustodyStore({ ...opts, runId: key }); custodyStoresByRun.set(key, store) }
  return store
}
export function getPrincipalCustodyStore(runId: string): PrincipalCustodyStore | undefined { return custodyStoresByRun.get(runId.trim() || '__default__') }
export function disposePrincipalCustodyStore(runId: string, persistDir?: string): boolean {
  const key = runId.trim() || '__default__', store = custodyStoresByRun.get(key)
  custodyStoresByRun.delete(key)
  if (store) store.dispose()
  const diskPath = resolvePersistPath(persistDir, safeCustodyRunId(key))
  if (diskPath) { try { rmSync(diskPath, { force: true }) } catch { /* ignore */ } }
  return Boolean(store)
}
export function mergeRunSecretsWithCustody(target: NamedSecret[], latestPersonaSecrets: readonly NamedSecret[], custody?: PrincipalCustodyStore | null): NamedSecret[] {
  const seen = new Set(target.map(s => `${s.placeholder}\0${s.value}`))
  const addAll = (items: readonly NamedSecret[]) => { for (const item of items) { const k = `${item.placeholder}\0${item.value}`; if (!seen.has(k)) { seen.add(k); target.push(item) } } }
  addAll(latestPersonaSecrets); if (custody) addAll(custody.scrubDescriptors())
  return target
}
registerRunDisposer('principal-custody:run-stores', runId => { disposePrincipalCustodyStore(runId) })
