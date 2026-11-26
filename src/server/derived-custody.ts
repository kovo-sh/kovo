/** Layer-1 Derived Capability Custody (`cap:hop_<hopReceiptId>:<slot>`) & Bounded Async Poll-Convergence (v8 M0). */
import { createHash, createHmac, randomBytes } from 'node:crypto'
import { accessSync, chmodSync, constants, lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { buildSecretEncodingVariants, type NamedSecret } from './redact.ts'

export type DerivedCapabilityHandle = `cap:hop_${string}:${string}`
export type DerivedSecretKind =
  | 'bearer_token' | 'api_token' | 'cookie' | 'signed_url' | 'oidc_assertion'
  | 'signing_salt' | 'hmac_key' | 'jwt' | 'header_secret' | 'generic_secret'
export type DerivedCustodyErrorCode =
  | 'INVALID_HANDLE' | 'UNKNOWN_HANDLE' | 'EXPIRED_HANDLE' | 'RUN_MISMATCH'
  | 'ORIGIN_NOT_ALLOWED' | 'INVALID_INPUT' | 'UNSAFE_HEADER' | 'PERSISTENCE_ERROR'
  | 'CAPACITY_EXCEEDED' | 'MONOTONIC_VIOLATION' | 'HANDLE_IMMUTABLE'

export class DerivedCustodyError extends Error {
  readonly code: DerivedCustodyErrorCode
  constructor(code: DerivedCustodyErrorCode, message: string) {
    super(message); this.name = 'DerivedCustodyError'; this.code = code
  }
}

export interface DerivedCapabilityMeta {
  handle: DerivedCapabilityHandle; runId: string; hopReceiptId: string; slot: string
  kind: DerivedSecretKind; sha256: string; sha256Prefix: string; createdAtMs: number; expiresAtMs: number | null
  derivedFromCapabilityId?: DerivedCapabilityHandle; defaultHeaderName?: string; defaultCookieName?: string
  allowedOrigins?: readonly string[]
}
export interface DerivedCapabilityVaultOptions {
  runId: string; persistPath?: string; defaultTtlMs?: number | null; maxEntries?: number; maxSealAttempts?: number; now?: () => number
}
export interface SealDerivedCapabilityInput {
  hopReceiptId: string; slot: string; rawValue: string; kind?: DerivedSecretKind; ttlMs?: number | null
  derivedFromCapabilityId?: DerivedCapabilityHandle; defaultHeaderName?: string; defaultCookieName?: string
  allowedOrigins?: readonly string[]
}
export interface MatchedSealedHandle { handleId: DerivedCapabilityHandle; rawDigest: string }
export interface MatchSealedHandlesInput { runId?: string; targetOrigin?: string; parts: readonly string[]; minLength?: number }

const SAFE_ID_RE = /^[A-Za-z0-9._-]{1,128}$/
const SAFE_SLOT_RE = /^[A-Za-z0-9._-]{1,64}$/
const HANDLE_RE = /^cap:hop_([A-Za-z0-9._-]{1,128}):([A-Za-z0-9._-]{1,64})$/
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$/
const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,256}$/
const CRLF_RE = /[\r\n\0]/
const MAX_SECRET_BYTES = 32_768
const DEFAULT_MAX_ENTRIES = 512
const DEFAULT_MAX_SEAL_ATTEMPTS = 1_024
export const MIN_SCRUB_LENGTH = 6
const DEFAULT_AUTOBIND_MIN_LENGTH = 8
const TRIVIAL_AUTOBIND_VALUES = new Set([
  'undefined', 'approved', 'accepted', 'rejected', 'completed', 'complete', 'processing', 'succeeded', 'disabled', 'password',
  'username', 'anonymous', 'localhost', 'application/json', 'text/plain', 'text/html', 'authorization', 'content-type', 'connection',
  'keep-alive', 'transfer-encoding', 'not_found', 'internal_error', 'forbidden', 'unauthorized', 'bad_request', 'placeholder',
  'default_value', 'readonly', 'readwrite',
  // Common 6-7 char English/JSON/HTTP words safely excluded from exact-value scrubbing.
  'status', 'active', 'public', 'failed', 'errors', 'result', 'object', 'string', 'number', 'delete',
  'create', 'update', 'cancel', 'submit', 'search', 'header', 'cookie', 'bearer', 'tokens', 'secret',
  'health', 'method', 'origin', 'target', 'client', 'server', 'system', 'normal', 'medium', 'simple',
  'custom', 'strict', 'legacy', 'verify', 'access', 'denied', 'closed', 'opened', 'paused', 'queued',
  'pending', 'success', 'warning', 'message', 'payload', 'request', 'headers', 'cookies', 'session',
  'account', 'profile', 'default', 'enabled', 'unknown', 'invalid', 'missing', 'timeout', 'aborted',
  'allowed', 'blocked', 'content', 'charset', 'options', 'connect', 'upgrade', 'expires', 'max-age',
  'boolean', 'nullish', 'integer', 'version', 'headers', 'referer', 'refresh',
])

export function isScrubbableCapabilityValue(rawValue: string, minLength = MIN_SCRUB_LENGTH): boolean {
  const floor = Math.max(1, minLength)
  const trimmed = rawValue.trim()
  if (!trimmed || rawValue.length < floor || trimmed.length < floor) return false
  if (/^(.)\1+$/.test(trimmed)) return false
  if (TRIVIAL_AUTOBIND_VALUES.has(trimmed.toLowerCase())) return false
  // For short 6-7 char values, require at least 3 distinct characters so trivial low-entropy
  // patterns (like `ababab`) do not corrupt benign JSON/text while real 6-7 char tokens/OTPs do scrub.
  if (trimmed.length < 8 && new Set(trimmed).size < 3) return false
  return true
}
const UNSAFE_HEADERS = new Set(['host', 'content-length', 'connection', 'transfer-encoding', 'upgrade', 'keep-alive', 'te', 'trailer', 'proxy-connection'])

function assertCustody(cond: unknown, code: DerivedCustodyErrorCode, msg: string): asserts cond {
  if (!cond) throw new DerivedCustodyError(code, msg)
}
export function formatDerivedHandle(hopReceiptId: string, slot: string): DerivedCapabilityHandle {
  assertCustody(SAFE_ID_RE.test(hopReceiptId), 'INVALID_HANDLE', `Invalid hopReceiptId "${hopReceiptId}".`)
  assertCustody(SAFE_SLOT_RE.test(slot), 'INVALID_HANDLE', `Invalid capability slot "${slot}".`)
  return `cap:hop_${hopReceiptId}:${slot}`
}
export function parseDerivedHandle(handle: string): { hopReceiptId: string; slot: string } | null {
  const m = HANDLE_RE.exec(handle)
  return m ? { hopReceiptId: m[1]!, slot: m[2]! } : null
}
export function isDerivedCapabilityHandle(value: string): value is DerivedCapabilityHandle { return HANDLE_RE.test(value) }
function sha256Hex(value: string | Uint8Array): string { return createHash('sha256').update(value).digest('hex') }
function normalizeOrigin(raw: string): string {
  let parsed: URL
  try { parsed = new URL(raw) } catch { throw new DerivedCustodyError('INVALID_INPUT', `Invalid origin URL "${raw}".`) }
  assertCustody(parsed.protocol === 'http:' || parsed.protocol === 'https:', 'INVALID_INPUT', `Unsupported origin protocol in "${raw}".`)
  return parsed.origin
}
function cloneMeta(meta: DerivedCapabilityMeta): DerivedCapabilityMeta {
  return { ...meta, ...(meta.allowedOrigins ? { allowedOrigins: [...meta.allowedOrigins] } : {}) }
}

// --- Module-Private Custody Store & 0600 Persistence ---
interface SealedEntry { meta: DerivedCapabilityMeta; rawValue: string }
interface ScrubRecord { handle: DerivedCapabilityHandle; rawValue: string }
interface PersistedVaultPayload { v: 1; runId: string; entries: SealedEntry[]; scrubHistory: ScrubRecord[] }
interface VaultInternals {
  readonly runId: string; readonly persistPath?: string; readonly defaultTtlMs: number | null
  readonly maxEntries: number; readonly maxSealAttempts: number; sealAttempts: number; readonly now: () => number
  readonly entries: Map<DerivedCapabilityHandle, SealedEntry>; readonly scrubHistory: Map<string, ScrubRecord>
  readonly sealedDigests: Map<DerivedCapabilityHandle, string>
}
const vaultInternals = new WeakMap<DerivedCapabilityVault, VaultInternals>()
function getInternals(vault: DerivedCapabilityVault): VaultInternals {
  const state = vaultInternals.get(vault)
  assertCustody(state, 'INVALID_INPUT', 'Invalid DerivedCapabilityVault instance.')
  return state
}

function resolveActiveEntry(vault: DerivedCapabilityVault, handle: string, opts?: { runId?: string; targetOrigin?: string }): SealedEntry {
  const state = getInternals(vault)
  assertCustody(opts?.runId === undefined || opts.runId === state.runId, 'RUN_MISMATCH', `Vault runId "${state.runId}" != "${opts?.runId}".`)
  assertCustody(isDerivedCapabilityHandle(handle), 'INVALID_HANDLE', `Malformed derived capability handle "${handle}".`)
  const entry = state.entries.get(handle)
  assertCustody(entry, 'UNKNOWN_HANDLE', `Unknown or revoked capability "${handle}".`)
  assertCustody(entry.meta.runId === state.runId, 'RUN_MISMATCH', `Capability "${handle}" does not belong to run "${state.runId}".`)
  assertCustody(entry.meta.expiresAtMs === null || state.now() < entry.meta.expiresAtMs, 'EXPIRED_HANDLE', `Capability "${handle}" has expired.`)
  if (opts?.targetOrigin && entry.meta.allowedOrigins?.length) {
    const origin = normalizeOrigin(opts.targetOrigin)
    assertCustody(entry.meta.allowedOrigins.includes(origin), 'ORIGIN_NOT_ALLOWED', `Capability "${handle}" not allowed for origin "${origin}".`)
  }
  return entry
}

function readPersistedVault(path: string, expectedRunId: string): PersistedVaultPayload | null {
  let stat: ReturnType<typeof lstatSync>
  try { stat = lstatSync(path) } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw new DerivedCustodyError('PERSISTENCE_ERROR', `Failed to stat custody file: ${(err as Error).message}`)
  }
  assertCustody(!stat.isSymbolicLink(), 'PERSISTENCE_ERROR', 'Derived custody file must not be a symbolic link.')
  assertCustody((stat.mode & 0o077) === 0, 'PERSISTENCE_ERROR', 'Derived custody file must have owner-only (0600) permissions.')
  assertCustody(stat.isFile(), 'PERSISTENCE_ERROR', 'Derived custody path is not a regular file.')
  accessSync(path, constants.R_OK)
  const raw = readFileSync(path, 'utf8').trim()
  if (!raw) return null
  let parsed: Partial<PersistedVaultPayload>
  try { parsed = JSON.parse(raw) as Partial<PersistedVaultPayload> } catch { throw new DerivedCustodyError('PERSISTENCE_ERROR', 'Derived custody file contains invalid JSON.') }
  assertCustody(parsed.v === 1 && typeof parsed.runId === 'string', 'PERSISTENCE_ERROR', 'Derived custody file has unsupported schema.')
  assertCustody(parsed.runId === expectedRunId, 'RUN_MISMATCH', `Persisted runId "${parsed.runId}" != "${expectedRunId}".`)
  return { v: 1, runId: parsed.runId, entries: Array.isArray(parsed.entries) ? parsed.entries : [], scrubHistory: Array.isArray(parsed.scrubHistory) ? parsed.scrubHistory : [] }
}

function writePersistedVault(state: VaultInternals): void {
  if (!state.persistPath) return
  const dir = dirname(state.persistPath)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const payload: PersistedVaultPayload = { v: 1, runId: state.runId, entries: Array.from(state.entries.values()), scrubHistory: Array.from(state.scrubHistory.values()) }
  const tmpPath = `${state.persistPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  try {
    writeFileSync(tmpPath, JSON.stringify(payload), { mode: 0o600, encoding: 'utf8' })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, state.persistPath)
    chmodSync(state.persistPath, 0o600)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw new DerivedCustodyError('PERSISTENCE_ERROR', `Failed to persist custody file: ${(err as Error).message}`)
  }
}

export class DerivedCapabilityVault {
  readonly runId: string

  constructor(options: DerivedCapabilityVaultOptions) {
    assertCustody(SAFE_ID_RE.test(options.runId), 'INVALID_INPUT', `Invalid runId "${options.runId}".`)
    const maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES
    assertCustody(Number.isInteger(maxEntries) && maxEntries >= 1 && maxEntries <= 10_000, 'INVALID_INPUT', 'maxEntries must be 1..10000.')
    const maxSealAttempts = options.maxSealAttempts ?? DEFAULT_MAX_SEAL_ATTEMPTS
    assertCustody(Number.isInteger(maxSealAttempts) && maxSealAttempts >= 1 && maxSealAttempts <= 100_000, 'INVALID_INPUT', 'maxSealAttempts must be 1..100000.')
    assertCustody(options.defaultTtlMs === undefined || options.defaultTtlMs === null || (Number.isFinite(options.defaultTtlMs) && options.defaultTtlMs >= 0), 'INVALID_INPUT', 'defaultTtlMs must be a non-negative finite number or null.')
    this.runId = options.runId
    const state: VaultInternals = {
      runId: options.runId, persistPath: options.persistPath, defaultTtlMs: options.defaultTtlMs ?? null,
      maxEntries, maxSealAttempts, sealAttempts: 0, now: options.now ?? Date.now, entries: new Map(), scrubHistory: new Map(), sealedDigests: new Map(),
    }
    const loaded = options.persistPath ? readPersistedVault(options.persistPath, options.runId) : null
    if (loaded) {
      for (const e of loaded.entries) {
        if (e?.meta && isDerivedCapabilityHandle(e.meta.handle) && typeof e.rawValue === 'string') {
          state.entries.set(e.meta.handle, e); state.scrubHistory.set(e.rawValue, { handle: e.meta.handle, rawValue: e.rawValue })
          state.sealedDigests.set(e.meta.handle, e.meta.sha256)
        }
      }
      for (const rec of loaded.scrubHistory) {
        if (rec && isDerivedCapabilityHandle(rec.handle) && typeof rec.rawValue === 'string') {
          state.scrubHistory.set(rec.rawValue, rec)
          if (!state.sealedDigests.has(rec.handle)) state.sealedDigests.set(rec.handle, sha256Hex(rec.rawValue))
        }
      }
    }
    vaultInternals.set(this, state)
  }

  seal(input: SealDerivedCapabilityInput): DerivedCapabilityMeta {
    const state = getInternals(this)
    state.sealAttempts += 1
    assertCustody(state.sealAttempts <= state.maxSealAttempts, 'CAPACITY_EXCEEDED', `Vault seal attempt cap (${state.maxSealAttempts}) exceeded.`)
    assertCustody(typeof input.rawValue === 'string' && input.rawValue.length > 0, 'INVALID_INPUT', 'rawValue must be a non-empty string.')
    assertCustody(Buffer.byteLength(input.rawValue, 'utf8') <= MAX_SECRET_BYTES, 'INVALID_INPUT', `rawValue exceeds ${MAX_SECRET_BYTES} bytes.`)
    const handle = formatDerivedHandle(input.hopReceiptId, input.slot)
    assertCustody(!state.entries.has(handle) && !state.sealedDigests.has(handle), 'HANDLE_IMMUTABLE', `Capability handle "${handle}" is immutable and cannot be overwritten or re-sealed.`)
    assertCustody(state.entries.size < state.maxEntries, 'CAPACITY_EXCEEDED', `Vault capacity (${state.maxEntries}) reached.`)
    const ttl = input.ttlMs === undefined ? state.defaultTtlMs : input.ttlMs
    assertCustody(ttl === null || (Number.isFinite(ttl) && ttl >= 0), 'INVALID_INPUT', 'ttlMs must be a non-negative finite number or null.')
    assertCustody(input.derivedFromCapabilityId === undefined || isDerivedCapabilityHandle(input.derivedFromCapabilityId), 'INVALID_HANDLE', 'Invalid derivedFromCapabilityId.')
    const allowedOrigins = input.allowedOrigins?.map(normalizeOrigin)
    const createdAtMs = state.now()
    const digest = sha256Hex(input.rawValue)
    const meta: DerivedCapabilityMeta = {
      handle, runId: state.runId, hopReceiptId: input.hopReceiptId, slot: input.slot, kind: input.kind ?? 'generic_secret',
      sha256: digest, sha256Prefix: digest.slice(0, 12), createdAtMs, expiresAtMs: ttl === null ? null : createdAtMs + ttl,
      ...(input.derivedFromCapabilityId ? { derivedFromCapabilityId: input.derivedFromCapabilityId } : {}),
      ...(input.defaultHeaderName ? { defaultHeaderName: input.defaultHeaderName } : {}),
      ...(input.defaultCookieName ? { defaultCookieName: input.defaultCookieName } : {}),
      ...(allowedOrigins?.length ? { allowedOrigins } : {}),
    }
    state.entries.set(handle, { meta, rawValue: input.rawValue })
    state.sealedDigests.set(handle, digest)
    state.scrubHistory.set(input.rawValue, { handle, rawValue: input.rawValue })
    writePersistedVault(state)
    return cloneMeta(meta)
  }

  hasEverSealed(handle: string): boolean {
    const state = getInternals(this)
    return isDerivedCapabilityHandle(handle) && (state.entries.has(handle) || state.sealedDigests.has(handle))
  }

  getMeta(handle: string): DerivedCapabilityMeta | null {
    const entry = isDerivedCapabilityHandle(handle) ? getInternals(this).entries.get(handle) : undefined
    return entry ? cloneMeta(entry.meta) : null
  }
  isExpired(handle: string): boolean {
    const state = getInternals(this)
    const entry = isDerivedCapabilityHandle(handle) ? state.entries.get(handle) : undefined
    return Boolean(entry && entry.meta.expiresAtMs !== null && state.now() >= entry.meta.expiresAtMs)
  }
  hasActive(handle: string): boolean {
    const state = getInternals(this)
    const entry = isDerivedCapabilityHandle(handle) ? state.entries.get(handle) : undefined
    return Boolean(entry && (entry.meta.expiresAtMs === null || state.now() < entry.meta.expiresAtMs))
  }
  list(): DerivedCapabilityMeta[] { return Array.from(getInternals(this).entries.values(), e => cloneMeta(e.meta)) }
  revoke(handle: string): boolean {
    const state = getInternals(this)
    const removed = isDerivedCapabilityHandle(handle) && state.entries.delete(handle)
    if (removed) writePersistedVault(state)
    return removed
  }
  purgeExpired(): number {
    const state = getInternals(this)
    const nowMs = state.now()
    let removed = 0
    for (const [handle, entry] of state.entries) {
      if (entry.meta.expiresAtMs !== null && nowMs >= entry.meta.expiresAtMs) { state.entries.delete(handle); removed += 1 }
    }
    if (removed > 0) writePersistedVault(state)
    return removed
  }
  injectCapabilityIntoRequest(options: Omit<InjectCapabilityOptions, 'vault'>): InjectCapabilityResult { return injectCapabilityIntoRequest({ ...options, vault: this }) }
  hostHmacSign(options: Omit<HostHmacSignOptions, 'vault'>): HostHmacSignResult { return hostHmacSign({ ...options, vault: this }) }
  hostJwtSign(options: Omit<HostJwtSignOptions, 'vault'>): HostJwtSignResult { return hostJwtSign({ ...options, vault: this }) }
  matchSealedHandlesInRequest(input: MatchSealedHandlesInput): MatchedSealedHandle[] {
    const state = getInternals(this)
    if (input.runId !== undefined && input.runId !== state.runId) return []
    const parts = input.parts.filter((p): p is string => typeof p === 'string' && p.length > 0)
    if (!parts.length) return []
    const minLen = typeof input.minLength === 'number' && Number.isFinite(input.minLength) ? Math.max(1, Math.floor(input.minLength)) : DEFAULT_AUTOBIND_MIN_LENGTH
    let targetOrigin: string | null = null
    if (input.targetOrigin) { try { targetOrigin = normalizeOrigin(input.targetOrigin) } catch { /* invalid origin */ } }
    const nowMs = state.now()
    const matches: MatchedSealedHandle[] = []
    for (const entry of state.entries.values()) {
      if (entry.meta.runId !== state.runId || (entry.meta.expiresAtMs !== null && nowMs >= entry.meta.expiresAtMs)) continue
      if (entry.meta.allowedOrigins?.length && (!targetOrigin || !entry.meta.allowedOrigins.includes(targetOrigin))) continue
      const raw = entry.rawValue, trimmed = raw.trim()
      if (trimmed.length < minLen || /^(.)\1+$/.test(trimmed) || TRIVIAL_AUTOBIND_VALUES.has(trimmed.toLowerCase())) continue
      const needles = [raw]
      const encoded = encodeURIComponent(raw)
      if (encoded !== raw) {
        needles.push(encoded)
        const lower = encoded.replace(/%[0-9A-F]{2}/g, m => m.toLowerCase())
        if (lower !== encoded) needles.push(lower)
        if (encoded.includes('%20')) needles.push(encoded.replaceAll('%20', '+'))
      }
      if (/["\\\r\n\t\x00-\x1f]/.test(raw)) needles.push(JSON.stringify(raw).slice(1, -1))
      if (needles.some(n => parts.some(p => p.includes(n)))) matches.push({ handleId: entry.meta.handle, rawDigest: entry.meta.sha256 })
    }
    return matches
  }
  toJSON(): { runId: string; count: number; handles: DerivedCapabilityHandle[] } {
    const state = getInternals(this)
    return { runId: state.runId, count: state.entries.size, handles: Array.from(state.entries.keys()) }
  }
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    const state = getInternals(this)
    return `DerivedCapabilityVault(runId=${state.runId}, entries=${state.entries.size})`
  }
}

// --- Secret Scrubbing (Raw + URL/Form + Base64 / Unpadded / Base64URL + Hex + JSON/HTML Escapes) ---
export function scrubDerivedSecrets(text: string, vault: DerivedCapabilityVault | readonly DerivedCapabilityVault[], minLength = MIN_SCRUB_LENGTH): string {
  if (!text) return text
  const floor = Math.max(1, minLength)
  const vaults = Array.isArray(vault) ? vault : [vault]
  const replacements: Array<{ needle: string; placeholder: string }> = []
  for (const v of vaults) {
    for (const rec of getInternals(v).scrubHistory.values()) {
      if (!isScrubbableCapabilityValue(rec.rawValue, floor)) continue
      const placeholder = `[redacted:${rec.handle}]`
      for (const needle of buildSecretEncodingVariants(rec.rawValue, floor)) replacements.push({ needle, placeholder })
    }
  }
  if (!replacements.length) return text
  replacements.sort((a, b) => b.needle.length - a.needle.length)
  let out = text
  for (const { needle, placeholder } of replacements) if (out.includes(needle)) out = out.replaceAll(needle, () => placeholder)
  return out
}

export function vaultScrubDescriptors(vault: DerivedCapabilityVault, minLength = MIN_SCRUB_LENGTH): NamedSecret[] {
  const floor = Math.max(1, minLength)
  const list: NamedSecret[] = []
  for (const rec of getInternals(vault).scrubHistory.values()) {
    if (isScrubbableCapabilityValue(rec.rawValue, floor)) {
      list.push({ value: rec.rawValue, placeholder: `[redacted:${rec.handle}]` })
    }
  }
  return list
}

// --- Host-Side Injection & Cryptographic Derivation Helpers ---
export type InjectCapabilityTarget = 'bearer' | 'header' | 'cookie' | 'url'
export interface HostInjectableRequest { url: string; method?: string; headers?: Record<string, string>; body?: string | Uint8Array | null }
export interface InjectCapabilityOptions {
  vault?: DerivedCapabilityVault; handle: string; target: InjectCapabilityTarget
  headerName?: string; cookieName?: string; queryParam?: string; runId?: string; request: HostInjectableRequest
}
export interface CapabilityConsumptionAttestation {
  consumedCapabilityId: DerivedCapabilityHandle; digest: string; sha256Prefix: string
  target: InjectCapabilityTarget; runId: string; timestampMs: number
}
export interface InjectCapabilityResult { request: HostInjectableRequest; attestation: CapabilityConsumptionAttestation }

function setHeaderCI(headers: Record<string, string>, name: string, value: string): void {
  const lower = name.toLowerCase()
  for (const key of Object.keys(headers)) if (key.toLowerCase() === lower) delete headers[key]
  headers[name] = value
}
function getHeaderCI(headers: Record<string, string>, name: string): string | undefined {
  const lower = name.toLowerCase()
  return Object.entries(headers).find(([k]) => k.toLowerCase() === lower)?.[1]
}
function mergeCookieHeader(existing: string | undefined, cookieName: string, rawValue: string): string {
  const pairs: string[] = []
  let replaced = false
  for (const seg of (existing ?? '').split(';')) {
    const t = seg.trim()
    if (!t) continue
    const eq = t.indexOf('=')
    if (eq > 0 && t.slice(0, eq).trim() === cookieName) {
      if (!replaced) { pairs.push(`${cookieName}=${rawValue}`); replaced = true }
    } else pairs.push(t)
  }
  if (!replaced) pairs.push(`${cookieName}=${rawValue}`)
  return pairs.join('; ')
}
function resolveVault(optVault: DerivedCapabilityVault | undefined, argVault: DerivedCapabilityVault | undefined): DerivedCapabilityVault {
  const vault = optVault ?? argVault
  assertCustody(vault, 'INVALID_INPUT', 'A DerivedCapabilityVault instance is required.')
  return vault
}

export function injectCapabilityIntoRequest(options: InjectCapabilityOptions & { vault: DerivedCapabilityVault }): InjectCapabilityResult
export function injectCapabilityIntoRequest(options: InjectCapabilityOptions, vault: DerivedCapabilityVault): InjectCapabilityResult
export function injectCapabilityIntoRequest(options: InjectCapabilityOptions, vaultArg?: DerivedCapabilityVault): InjectCapabilityResult {
  const vault = resolveVault(options.vault, vaultArg)
  const state = getInternals(vault)
  const entry = resolveActiveEntry(vault, options.handle, { runId: options.runId, targetOrigin: normalizeOrigin(options.request.url) })
  const headers: Record<string, string> = { ...(options.request.headers ?? {}) }
  let url = options.request.url
  const raw = entry.rawValue
  if (options.target === 'bearer') {
    assertCustody(!CRLF_RE.test(raw), 'INVALID_INPUT', 'Bearer capability contains control characters.')
    setHeaderCI(headers, 'Authorization', `Bearer ${/^bearer\s+/i.test(raw) ? raw.replace(/^bearer\s+/i, '') : raw}`)
  } else if (options.target === 'header') {
    const name = (options.headerName ?? entry.meta.defaultHeaderName ?? '').trim()
    assertCustody(name && HEADER_NAME_RE.test(name), 'INVALID_INPUT', `Invalid headerName "${name}".`)
    assertCustody(!UNSAFE_HEADERS.has(name.toLowerCase()), 'UNSAFE_HEADER', `Refusing unsafe header "${name}".`)
    assertCustody(!CRLF_RE.test(raw), 'INVALID_INPUT', 'Header capability contains control characters.')
    setHeaderCI(headers, name, raw)
  } else if (options.target === 'cookie') {
    assertCustody(!CRLF_RE.test(raw), 'INVALID_INPUT', 'Cookie capability contains control characters.')
    const cookieName = options.cookieName ?? entry.meta.defaultCookieName
    const existing = getHeaderCI(headers, 'Cookie')
    if (cookieName) {
      assertCustody(COOKIE_NAME_RE.test(cookieName), 'INVALID_INPUT', `Invalid cookieName "${cookieName}".`)
      setHeaderCI(headers, 'Cookie', mergeCookieHeader(existing, cookieName, raw))
    } else {
      const eq = raw.indexOf('=')
      assertCustody(eq > 0 && COOKIE_NAME_RE.test(raw.slice(0, eq).trim()), 'INVALID_INPUT', 'Cookie without cookieName requires "name=value".')
      setHeaderCI(headers, 'Cookie', existing ? `${existing}; ${raw}` : raw)
    }
  } else if (options.target === 'url') {
    if (options.queryParam) {
      const parsed = new URL(url)
      parsed.searchParams.set(options.queryParam, raw)
      url = parsed.toString()
    } else {
      const signedOrigin = normalizeOrigin(raw)
      assertCustody(!entry.meta.allowedOrigins?.length || entry.meta.allowedOrigins.includes(signedOrigin), 'ORIGIN_NOT_ALLOWED', `Signed URL origin "${signedOrigin}" not allowed.`)
      url = raw
    }
  } else {
    throw new DerivedCustodyError('INVALID_INPUT', `Unsupported injection target "${String(options.target)}".`)
  }
  return {
    request: { ...options.request, url, headers },
    attestation: {
      consumedCapabilityId: entry.meta.handle, digest: entry.meta.sha256, sha256Prefix: entry.meta.sha256Prefix,
      target: options.target, runId: state.runId, timestampMs: state.now(),
    },
  }
}

export type HostHmacAlg = 'sha256' | 'sha384' | 'sha512'
export type HostHmacEncoding = 'hex' | 'base64' | 'base64url'
const ALLOWED_HMAC_ALGS = new Set<HostHmacAlg>(['sha256', 'sha384', 'sha512'])
const ALLOWED_HMAC_ENC = new Set<HostHmacEncoding>(['hex', 'base64', 'base64url'])

export interface HostHmacSignOptions {
  vault?: DerivedCapabilityVault; secretHandle: string; payload: string | Uint8Array
  alg: HostHmacAlg; encoding?: HostHmacEncoding; runId?: string
}
export interface HmacDerivationAttestation {
  derivedFromCapabilityId: DerivedCapabilityHandle; alg: HostHmacAlg; encoding: HostHmacEncoding
  payloadDigest: string; signatureDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number
}
export interface HostHmacSignResult { signature: string; attestation: HmacDerivationAttestation }

export function hostHmacSign(options: HostHmacSignOptions & { vault: DerivedCapabilityVault }): HostHmacSignResult
export function hostHmacSign(options: HostHmacSignOptions, vault: DerivedCapabilityVault): HostHmacSignResult
export function hostHmacSign(options: HostHmacSignOptions, vaultArg?: DerivedCapabilityVault): HostHmacSignResult {
  const vault = resolveVault(options.vault, vaultArg)
  const state = getInternals(vault)
  assertCustody(ALLOWED_HMAC_ALGS.has(options.alg), 'INVALID_INPUT', `Unsupported HMAC alg "${String(options.alg)}".`)
  const encoding: HostHmacEncoding = options.encoding ?? 'hex'
  assertCustody(ALLOWED_HMAC_ENC.has(encoding), 'INVALID_INPUT', `Unsupported HMAC encoding "${String(encoding)}".`)
  assertCustody(typeof options.payload === 'string' || options.payload instanceof Uint8Array, 'INVALID_INPUT', 'HMAC payload must be string or Uint8Array.')
  const entry = resolveActiveEntry(vault, options.secretHandle, { runId: options.runId })
  const signature = createHmac(options.alg, entry.rawValue).update(options.payload).digest(encoding)
  return {
    signature,
    attestation: {
      derivedFromCapabilityId: entry.meta.handle, alg: options.alg, encoding, payloadDigest: sha256Hex(options.payload),
      signatureDigest: sha256Hex(signature), sourceSecretDigest: entry.meta.sha256, runId: state.runId, timestampMs: state.now(),
    },
  }
}

export type HostJwtAlg = 'HS256' | 'HS384' | 'HS512'
const JWT_ALG_TO_NODE: Record<HostJwtAlg, HostHmacAlg> = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' }

export interface HostJwtSignOptions {
  vault?: DerivedCapabilityVault; secretHandle: string; claims: Record<string, unknown>
  header?: Record<string, unknown>; alg: HostJwtAlg; hopReceiptId?: string; slot?: string
  ttlMs?: number | null; allowedOrigins?: readonly string[]; runId?: string
}
export interface JwtDerivationAttestation {
  derivedFromCapabilityId: DerivedCapabilityHandle; derivedHandle: DerivedCapabilityHandle; alg: HostJwtAlg
  claimsDigest: string; tokenDigest: string; sourceSecretDigest: string; runId: string; timestampMs: number
}
export interface HostJwtSignResult { token: string; derivedHandle: DerivedCapabilityHandle; attestation: JwtDerivationAttestation }

export function hostJwtSign(options: HostJwtSignOptions & { vault: DerivedCapabilityVault }): HostJwtSignResult
export function hostJwtSign(options: HostJwtSignOptions, vault: DerivedCapabilityVault): HostJwtSignResult
export function hostJwtSign(options: HostJwtSignOptions, vaultArg?: DerivedCapabilityVault): HostJwtSignResult {
  const vault = resolveVault(options.vault, vaultArg)
  const state = getInternals(vault)
  const nodeAlg = JWT_ALG_TO_NODE[options.alg]
  assertCustody(nodeAlg, 'INVALID_INPUT', `Unsupported JWT HMAC alg "${String(options.alg)}".`)
  assertCustody(options.claims && typeof options.claims === 'object' && !Array.isArray(options.claims), 'INVALID_INPUT', 'JWT claims must be a plain object.')
  assertCustody(options.header === undefined || (options.header && typeof options.header === 'object' && !Array.isArray(options.header)), 'INVALID_INPUT', 'JWT header must be a plain object.')
  assertCustody(options.header?.alg === undefined || options.header.alg === options.alg, 'INVALID_INPUT', 'JWT header.alg must match options.alg.')
  const entry = resolveActiveEntry(vault, options.secretHandle, { runId: options.runId })
  let headerJson: string, claimsJson: string
  try {
    headerJson = JSON.stringify({ typ: 'JWT', ...(options.header ?? {}), alg: options.alg })
    claimsJson = JSON.stringify(options.claims)
  } catch (err) {
    throw new DerivedCustodyError('INVALID_INPUT', `JWT header/claims not JSON-serializable: ${(err as Error).message}`)
  }
  const signingInput = `${Buffer.from(headerJson, 'utf8').toString('base64url')}.${Buffer.from(claimsJson, 'utf8').toString('base64url')}`
  const token = `${signingInput}.${createHmac(nodeAlg, entry.rawValue).update(signingInput, 'utf8').digest('base64url')}`
  const timestampMs = state.now()
  const sealedMeta = vault.seal({
    hopReceiptId: options.hopReceiptId ?? entry.meta.hopReceiptId, slot: options.slot ?? `jwt_${sha256Hex(token).slice(0, 12)}`,
    rawValue: token, kind: 'jwt', ttlMs: options.ttlMs, derivedFromCapabilityId: entry.meta.handle,
    allowedOrigins: options.allowedOrigins ?? entry.meta.allowedOrigins,
  })
  return {
    token, derivedHandle: sealedMeta.handle,
    attestation: {
      derivedFromCapabilityId: entry.meta.handle, derivedHandle: sealedMeta.handle, alg: options.alg,
      claimsDigest: sha256Hex(claimsJson), tokenDigest: sealedMeta.sha256, sourceSecretDigest: entry.meta.sha256, runId: state.runId, timestampMs,
    },
  }
}

// --- Bounded Async Poll-Convergence ---
export type AsyncPollProfile = 'fast_lab' | 'wan'
export const ASYNC_CONVERGENCE_PROFILES: Record<AsyncPollProfile, { defaultTimeoutMs: number; maxTimeoutMs: number; defaultIntervalMs: number; defaultMaxAttempts: number }> = {
  fast_lab: { defaultTimeoutMs: 5_000, maxTimeoutMs: 5_000, defaultIntervalMs: 150, defaultMaxAttempts: 40 },
  wan: { defaultTimeoutMs: 30_000, maxTimeoutMs: 30_000, defaultIntervalMs: 500, defaultMaxAttempts: 120 },
}

export interface AsyncPollAttemptContext { attempt: number; elapsedMs: number; signal: AbortSignal }
export interface AsyncMatchContext { attempt: number; observedAtMs: number }
export interface AsyncConvergenceAttemptRecord {
  attempt: number; startedAtMs: number; completedAtMs: number; observedAtMs: number; matched: boolean
  error?: string; rejectedReason?: 'non_monotonic_observed_timestamp' | 'clock_before_trigger'
}
export interface AsyncConvergenceEvidence {
  profile: AsyncPollProfile; tTriggerMs: number; tObservedMs: number | null; elapsedMs: number
  attempts: number; timeoutMs: number; intervalMs: number; maxAttempts: number
  aborted: boolean; timedOut: boolean; attemptLog: AsyncConvergenceAttemptRecord[]
}
export type AsyncConvergenceStatus = 'converged' | 'timeout' | 'aborted' | 'max_attempts' | 'monotonic_violation'
export interface AsyncConvergenceResult<T> { converged: boolean; status: AsyncConvergenceStatus; value?: T; evidence: AsyncConvergenceEvidence }
export interface AwaitAsyncConvergenceOptions<T> {
  pollFn: (ctx: AsyncPollAttemptContext) => Promise<T> | T
  matchPredicate: (value: T, ctx: AsyncMatchContext) => boolean | Promise<boolean>
  profile?: AsyncPollProfile; timeoutMs?: number; intervalMs?: number; maxAttempts?: number
  signal?: AbortSignal; tTriggerMs?: number; extractObservedAtMs?: (value: T) => number | undefined; now?: () => number
}

function sleepAbortable(ms: number, signal: AbortSignal): Promise<void> {
  if (ms <= 0 || signal.aborted) return Promise.resolve()
  return new Promise<void>(resolve => {
    const onAbort = () => { clearTimeout(timer); resolve() }
    const timer = setTimeout(() => { signal.removeEventListener('abort', onAbort); resolve() }, ms)
    signal.addEventListener('abort', onAbort, { once: true })
  })
}

async function raceWithAbortAndDeadline<T>(work: () => Promise<T> | T, signal: AbortSignal, remainingMs: number): Promise<{ kind: 'ok'; value: T } | { kind: 'aborted' } | { kind: 'timeout' }> {
  if (signal.aborted) return { kind: 'aborted' }
  if (remainingMs <= 0) return { kind: 'timeout' }
  let timer: ReturnType<typeof setTimeout> | undefined
  let onAbort: (() => void) | undefined
  try {
    const workP = Promise.resolve().then(work).then(value => ({ kind: 'ok' as const, value }))
    const gateP = new Promise<{ kind: 'aborted' } | { kind: 'timeout' }>(resolve => {
      onAbort = () => resolve({ kind: 'aborted' })
      signal.addEventListener('abort', onAbort, { once: true })
      timer = setTimeout(() => resolve({ kind: 'timeout' }), remainingMs)
    })
    return await Promise.race([workP, gateP])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
    if (onAbort) signal.removeEventListener('abort', onAbort)
  }
}

export async function awaitAsyncConvergence<T>(options: AwaitAsyncConvergenceOptions<T>): Promise<AsyncConvergenceResult<T>> {
  const now = options.now ?? Date.now
  const profile: AsyncPollProfile = options.profile ?? (options.timeoutMs !== undefined && options.timeoutMs > 5_000 ? 'wan' : 'fast_lab')
  const bounds = ASYNC_CONVERGENCE_PROFILES[profile]
  const timeoutMs = options.timeoutMs ?? bounds.defaultTimeoutMs
  const intervalMs = options.intervalMs ?? bounds.defaultIntervalMs
  const maxAttempts = options.maxAttempts ?? bounds.defaultMaxAttempts
  assertCustody(Number.isFinite(timeoutMs) && timeoutMs > 0 && timeoutMs <= bounds.maxTimeoutMs, 'INVALID_INPUT', `timeoutMs (${timeoutMs}) must be in (0, ${bounds.maxTimeoutMs}] for "${profile}".`)
  assertCustody(Number.isFinite(intervalMs) && intervalMs >= 0 && intervalMs <= bounds.maxTimeoutMs, 'INVALID_INPUT', `intervalMs (${intervalMs}) is out of bounds.`)
  assertCustody(Number.isInteger(maxAttempts) && maxAttempts >= 1, 'INVALID_INPUT', 'maxAttempts must be a positive integer.')
  const startMs = now(), tTriggerMs = options.tTriggerMs ?? startMs
  assertCustody(Number.isFinite(tTriggerMs), 'INVALID_INPUT', 'tTriggerMs must be a finite timestamp.')
  const deadlineMs = startMs + timeoutMs
  const attemptLog: AsyncConvergenceAttemptRecord[] = []
  const controller = new AbortController()
  const onExternalAbort = () => controller.abort(options.signal?.reason)
  if (options.signal) {
    if (options.signal.aborted) controller.abort(options.signal.reason)
    else options.signal.addEventListener('abort', onExternalAbort, { once: true })
  }
  const finish = (status: AsyncConvergenceStatus, tObservedMs: number | null, value?: T): AsyncConvergenceResult<T> => ({
    converged: status === 'converged', status, ...(value !== undefined ? { value } : {}),
    evidence: {
      profile, tTriggerMs, tObservedMs, elapsedMs: Math.max(0, (tObservedMs ?? now()) - tTriggerMs),
      attempts: attemptLog.length, timeoutMs, intervalMs, maxAttempts,
      aborted: status === 'aborted', timedOut: status === 'timeout', attemptLog,
    },
  })
  try {
    if (controller.signal.aborted) return finish('aborted', null)
    let sawMonotonicRejection = false
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      if (controller.signal.aborted) return finish('aborted', null)
      const remainingMs = deadlineMs - now()
      if (remainingMs <= 0) return finish(sawMonotonicRejection ? 'monotonic_violation' : 'timeout', null)
      const startedAtMs = now()
      try {
        const raced = await raceWithAbortAndDeadline(() => options.pollFn({ attempt, elapsedMs: Math.max(0, startedAtMs - tTriggerMs), signal: controller.signal }), controller.signal, remainingMs)
        if (raced.kind === 'aborted') return finish('aborted', null)
        if (raced.kind === 'timeout') { controller.abort(new Error('convergence_timeout')); return finish(sawMonotonicRejection ? 'monotonic_violation' : 'timeout', null) }
        const completedAtMs = now()
        const extracted = options.extractObservedAtMs?.(raced.value)
        const observedAtMs = typeof extracted === 'number' && Number.isFinite(extracted) ? extracted : completedAtMs
        const matched = Boolean(await options.matchPredicate(raced.value, { attempt, observedAtMs }))
        if (matched && completedAtMs < tTriggerMs) {
          attemptLog.push({ attempt, startedAtMs, completedAtMs, observedAtMs, matched: true, rejectedReason: 'clock_before_trigger' })
          return finish('monotonic_violation', null)
        }
        if (matched && observedAtMs < tTriggerMs) {
          sawMonotonicRejection = true
          attemptLog.push({ attempt, startedAtMs, completedAtMs, observedAtMs, matched: true, rejectedReason: 'non_monotonic_observed_timestamp' })
        } else if (matched) {
          attemptLog.push({ attempt, startedAtMs, completedAtMs, observedAtMs, matched: true })
          return finish('converged', observedAtMs, raced.value)
        } else attemptLog.push({ attempt, startedAtMs, completedAtMs, observedAtMs, matched: false })
      } catch (err) {
        if (controller.signal.aborted) return finish('aborted', null)
        const completedAtMs = now()
        attemptLog.push({ attempt, startedAtMs, completedAtMs, observedAtMs: completedAtMs, matched: false, error: err instanceof Error ? err.message : String(err) })
      }
      if (attempt < maxAttempts) {
        const leftMs = deadlineMs - now()
        if (leftMs <= 0) return finish(sawMonotonicRejection ? 'monotonic_violation' : 'timeout', null)
        await sleepAbortable(Math.min(intervalMs, leftMs), controller.signal)
      }
    }
    return finish(sawMonotonicRejection ? 'monotonic_violation' : 'max_attempts', null)
  } finally {
    if (options.signal) options.signal.removeEventListener('abort', onExternalAbort)
  }
}
