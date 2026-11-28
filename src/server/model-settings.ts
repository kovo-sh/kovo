import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { accessSync, chmodSync, constants, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import type { Stats } from 'node:fs'
import { join, resolve } from 'node:path'
import { and, desc, eq } from 'drizzle-orm'
import type { z } from 'zod'
import { providerSettings } from '../domain.ts'
import type { ProviderSettings, PublicModelProfile, RoleAffinity } from '../domain.ts'
import {
  CONSERVATIVE_FALLBACK_PRICING,
  isDefaultFlashModel,
  resolveProfilePricing,
} from './provider-runtime-policy.ts'
import { classifyProviderFailure, testProvider } from './provider.ts'
import { consumeProfileCooldownHandoff } from './provider-stream.ts'
import { redact } from './redact.ts'
import {
  consumeLatestProviderFailureForProfile,
  isProviderFailureCode,
  type PersistedProviderFailureMeta,
  type ProviderFailureCode,
} from './retry-governor.ts'
import { modelProfiles } from './schema.ts'
import type { Store } from './store.ts'
import { store } from './store.ts'

export interface ResolvedModelProfile extends ProviderSettings {
  id: string
  healthState: 'closed' | 'open' | 'half_open'
  cooldownUntil: number | null
  lastError: string | null
  failureKind?: ProviderFailureCode | null
  failureHard?: boolean | null
  failureStatus?: number | null
}

interface PersistedProfileFailureRecord extends PersistedProviderFailureMeta {
  readonly retryAfterMs?: number | null
  readonly cooldownUntilMs?: number | null
}

let lastTest: { digest: string; expires: number } | undefined
let latestTestAttempt = 0
const transientFailures = new Map<string, number>()
const PROFILE_FAILURE_META_FILENAME = '.model-profile-failures.json'
const profileFailureCache = new Map<string, Record<string, PersistedProfileFailureRecord>>()

function profileFailureCacheKey(storage: Store): string {
  return `${storage.directory}\0${storage.workspace.id}`
}

function profileFailureMetaPath(storage: Store): string {
  return join(storage.directory, PROFILE_FAILURE_META_FILENAME)
}

function readWorkspaceProfileFailureMap(storage: Store): Record<string, PersistedProfileFailureRecord> {
  const cacheKey = profileFailureCacheKey(storage)
  const filePath = profileFailureMetaPath(storage)
  if (existsSync(filePath)) {
    try {
      const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as Record<string, Record<string, unknown>>
      const wsMap = parsed?.[storage.workspace.id]
      if (wsMap && typeof wsMap === 'object' && !Array.isArray(wsMap)) {
        const clean: Record<string, PersistedProfileFailureRecord> = {}
        for (const [id, raw] of Object.entries(wsMap)) {
          if (!raw || typeof raw !== 'object') continue
          const rec = raw as {
            kind?: unknown
            hard?: unknown
            status?: unknown
            retryAfterMs?: unknown
            cooldownUntilMs?: unknown
            recordedAt?: unknown
          }
          if (!isProviderFailureCode(rec.kind)) continue
          clean[id] = {
            kind: rec.kind,
            hard: Boolean(rec.hard),
            status: typeof rec.status === 'number' && Number.isFinite(rec.status) ? rec.status : null,
            retryAfterMs: typeof rec.retryAfterMs === 'number' && Number.isFinite(rec.retryAfterMs) ? rec.retryAfterMs : null,
            cooldownUntilMs: typeof rec.cooldownUntilMs === 'number' && Number.isFinite(rec.cooldownUntilMs) ? rec.cooldownUntilMs : null,
            recordedAt: typeof rec.recordedAt === 'number' && Number.isFinite(rec.recordedAt) ? rec.recordedAt : 0,
          }
        }
        profileFailureCache.set(cacheKey, clean)
        return clean
      }
    } catch {
      return profileFailureCache.get(cacheKey) ?? {}
    }
  }
  return profileFailureCache.get(cacheKey) ?? {}
}

function persistWorkspaceProfileFailureMeta(
  storage: Store,
  profileId: string,
  meta: PersistedProfileFailureRecord | null,
): void {
  const cacheKey = profileFailureCacheKey(storage)
  const current = { ...readWorkspaceProfileFailureMap(storage) }
  if (meta) current[profileId] = meta
  else delete current[profileId]
  profileFailureCache.set(cacheKey, current)
  if (!storage.directory || !existsSync(storage.directory)) return
  const filePath = profileFailureMetaPath(storage)
  let rootDoc: Record<string, Record<string, PersistedProfileFailureRecord>> = {}
  if (existsSync(filePath)) {
    try {
      const existing = JSON.parse(readFileSync(filePath, 'utf8')) as unknown
      if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
        rootDoc = existing as Record<string, Record<string, PersistedProfileFailureRecord>>
      }
    } catch {
      rootDoc = {}
    }
  }
  rootDoc[storage.workspace.id] = current
  const tmpPath = `${filePath}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`
  try {
    writeFileSync(tmpPath, JSON.stringify(rootDoc), { mode: 0o600 })
    renameSync(tmpPath, filePath)
  } catch {
    if (existsSync(tmpPath)) {
      try { unlinkSync(tmpPath) } catch { /* ignore temp cleanup failure */ }
    }
  }
}

const hash = (settings: Pick<ProviderSettings, 'endpoint' | 'model' | 'protocol' | 'key'>) =>
  createHash('sha256').update(JSON.stringify({
    endpoint: settings.endpoint,
    model: settings.model,
    protocol: settings.protocol,
    key: settings.key,
  })).digest('hex')

export function normalizeModelEndpoint(endpoint: string): string {
  const trimmed = endpoint.trim()
  try {
    const url = new URL(trimmed)
    return `${url.origin.toLowerCase()}${url.pathname.replace(/\/+$/, '')}`
  } catch {
    return trimmed.replace(/\/+$/, '')
  }
}

/**
 * Compute a SHA-256 binding pin for `(normalizedEndpoint, protocol)` so a stored
 * API key cannot be silently redirected to another host or protocol (M-15).
 */
export function computeCredentialEndpointPin(
  endpoint: string,
  protocol: ProviderSettings['protocol'],
): string {
  const normalizedEndpoint = normalizeModelEndpoint(endpoint)
  return createHash('sha256')
    .update(`kovo.model-credential-pin.v1\0${normalizedEndpoint}\0${protocol}`, 'utf8')
    .digest('hex')
}

function pinsEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a.toLowerCase(), 'utf8')
  const bb = Buffer.from(b.toLowerCase(), 'utf8')
  return ab.length === bb.length && timingSafeEqual(ab, bb)
}

const SAFE_CREDENTIAL_ID_RE = /^[A-Za-z0-9._-]{1,128}$/
const PIN_LEDGER_FILENAME = '.pin-ledger.json'
const PIN_HMAC_KEY_FILENAME = '.pin-hmac.key'
export const CREDENTIALS_DIR_ENV = 'KOVO_CREDENTIALS_DIR'

export interface ResolvedCredentialsDir {
  dir: string
  isOverride: boolean
}

function assertSafeCredentialId(credentialId: string): string {
  if (typeof credentialId !== 'string' || !SAFE_CREDENTIAL_ID_RE.test(credentialId) || credentialId === '.' || credentialId === '..') {
    throw new Error('The workspace credential identifier is invalid.')
  }
  return credentialId
}

function assertNotSymlinkIfExists(path: string, label: string): Stats | null {
  try {
    const st = lstatSync(path)
    if (st.isSymbolicLink()) {
      throw new Error(`The workspace ${label} must not be a symbolic link.`)
    }
    return st
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw err
  }
}

/**
 * Resolve the active credentials directory for reading model API keys and pins.
 *
 * When `KOVO_CREDENTIALS_DIR` is set, it acts as a strictly read-only host-side
 * credentials directory override (used by isolated benchmark cells so secrets are
 * neither copied nor symlinked). M-15 anti-symlink and owner-only permission
 * checks (mode 0700 or read-only 0500) are enforced identically and never weakened.
 */
export function resolveCredentialsDir(
  directory: string,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedCredentialsDir {
  const overrideRaw = env[CREDENTIALS_DIR_ENV]?.trim()
  if (overrideRaw) {
    const resolved = resolve(overrideRaw)
    const st = assertNotSymlinkIfExists(resolved, `${CREDENTIALS_DIR_ENV} credentials directory`)
    if (!st) {
      throw new Error(`The ${CREDENTIALS_DIR_ENV} credentials directory does not exist.`)
    }
    if (!st.isDirectory()) {
      throw new Error(`The ${CREDENTIALS_DIR_ENV} credentials path is not a directory.`)
    }
    const modeBits = st.mode & 0o7777
    if (modeBits !== 0o700 && modeBits !== 0o500) {
      throw new Error(`The ${CREDENTIALS_DIR_ENV} credentials directory must have owner-only permissions (mode 0700 or 0500).`)
    }
    accessSync(resolved, constants.R_OK | constants.X_OK)
    return { dir: resolved, isOverride: true }
  }
  const dir = join(directory, 'credentials')
  const st = assertNotSymlinkIfExists(dir, 'credentials directory')
  if (st && !st.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  return { dir, isOverride: false }
}

function ensureCredentialsDir(directory: string): string {
  const dir = join(directory, 'credentials')
  const existing = assertNotSymlinkIfExists(dir, 'credentials directory')
  if (existing && !existing.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  const st = lstatSync(dir)
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error('The workspace credentials directory is invalid.')
  }
  return dir
}

function readPinHmacKeyFromDir(credDir: string): Buffer | null {
  const keyPath = join(credDir, PIN_HMAC_KEY_FILENAME)
  const st = assertNotSymlinkIfExists(keyPath, 'credential pin key')
  if (!st) return null
  if (!st.isFile() || (st.mode & 0o077) !== 0) {
    throw new Error('The workspace credential pin key has invalid permissions.')
  }
  const raw = readFileSync(keyPath, 'utf8').trim()
  if (!/^[0-9a-f]{64}$/i.test(raw)) {
    throw new Error('The workspace credential pin key is malformed.')
  }
  return Buffer.from(raw, 'hex')
}

function loadOrCreatePinHmacKey(directory: string, createIfMissing: boolean): Buffer | null {
  const dir = join(directory, 'credentials')
  const existing = readPinHmacKeyFromDir(dir)
  if (existing) return existing
  if (!createIfMissing) return null
  ensureCredentialsDir(directory)
  const keyPath = join(dir, PIN_HMAC_KEY_FILENAME)
  const secret = randomBytes(32)
  const tmpPath = `${keyPath}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`
  try {
    writeFileSync(tmpPath, secret.toString('hex'), { mode: 0o600, flag: 'wx' })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, keyPath)
    chmodSync(keyPath, 0o600)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
  return secret
}

function computePinLedgerHmac(key: Buffer, pins: Record<string, string>): string {
  const sortedEntries = Object.keys(pins).sort().map(k => [k, pins[k]!.toLowerCase()])
  return createHmac('sha256', key)
    .update(`kovo.model-pin-ledger.v1\0${JSON.stringify(sortedEntries)}`, 'utf8')
    .digest('hex')
}

function readPinLedgerFromDir(credDir: string): Map<string, string> {
  const dirSt = assertNotSymlinkIfExists(credDir, 'credentials directory')
  if (dirSt && !dirSt.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  const ledgerPath = join(credDir, PIN_LEDGER_FILENAME)
  const st = assertNotSymlinkIfExists(ledgerPath, 'credential pin ledger')
  if (!st) {
    return new Map()
  }
  if (!st.isFile() || (st.mode & 0o077) !== 0) {
    throw new Error('The workspace credential pin ledger has invalid permissions.')
  }
  const key = readPinHmacKeyFromDir(credDir)
  if (!key) {
    throw new Error('The workspace credential pin key is missing.')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(ledgerPath, 'utf8'))
  } catch {
    throw new Error('The workspace credential pin ledger is unreadable.')
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('The workspace credential pin ledger is malformed.')
  }
  const rec = parsed as { version?: unknown; pins?: unknown; hmac?: unknown }
  if (rec.version !== 1 || !rec.pins || typeof rec.pins !== 'object' || Array.isArray(rec.pins) || typeof rec.hmac !== 'string' || !/^[0-9a-f]{64}$/i.test(rec.hmac)) {
    throw new Error('The workspace credential pin ledger is malformed.')
  }
  const pinsObj: Record<string, string> = {}
  for (const [k, v] of Object.entries(rec.pins as Record<string, unknown>)) {
    if (!SAFE_CREDENTIAL_ID_RE.test(k) || typeof v !== 'string' || !/^[0-9a-f]{64}$/i.test(v)) {
      throw new Error('The workspace credential pin ledger contains invalid entries.')
    }
    pinsObj[k] = v.toLowerCase()
  }
  const expectedHmac = computePinLedgerHmac(key, pinsObj)
  if (!pinsEqual(rec.hmac, expectedHmac)) {
    throw new Error('The workspace credential pin ledger integrity check failed.')
  }
  return new Map(Object.entries(pinsObj))
}

function updatePinLedger(
  directory: string,
  mutate: (pins: Map<string, string>) => void,
): void {
  const dir = ensureCredentialsDir(directory)
  const ledgerPath = join(dir, PIN_LEDGER_FILENAME)
  assertNotSymlinkIfExists(ledgerPath, 'credential pin ledger')
  const existing = readPinLedgerFromDir(dir)
  mutate(existing)
  const key = loadOrCreatePinHmacKey(directory, true)!
  const pinsObj: Record<string, string> = {}
  for (const [k, v] of existing.entries()) {
    pinsObj[k] = v.toLowerCase()
  }
  const payload = JSON.stringify({
    version: 1,
    pins: pinsObj,
    hmac: computePinLedgerHmac(key, pinsObj),
  })
  const tmpPath = `${ledgerPath}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`
  try {
    writeFileSync(tmpPath, payload, { mode: 0o600, flag: 'wx' })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, ledgerPath)
    chmodSync(ledgerPath, 0o600)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
}

function credentialPinPath(directory: string, credentialId: string): string {
  const safeId = assertSafeCredentialId(credentialId)
  return join(directory, 'credentials', `${safeId}.pin`)
}

function readCredentialPinFromDir(
  credDir: string,
  credentialId: string,
): { present: false; pinSha256: null } | { present: true; pinSha256: string } {
  const dirSt = assertNotSymlinkIfExists(credDir, 'credentials directory')
  if (dirSt && !dirSt.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  const safeId = assertSafeCredentialId(credentialId)
  const path = join(credDir, `${safeId}.pin`)
  const st = assertNotSymlinkIfExists(path, 'credential pin metadata')
  if (!st) {
    return { present: false, pinSha256: null }
  }
  if (!st.isFile() || (st.mode & 0o077) !== 0) {
    throw new Error('The workspace credential pin metadata has invalid permissions.')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    throw new Error('The workspace credential pin metadata is unreadable.')
  }
  const pinSha256 = (parsed && typeof parsed === 'object' ? (parsed as { pinSha256?: unknown }).pinSha256 : null)
  if (typeof pinSha256 !== 'string' || !/^[0-9a-f]{64}$/i.test(pinSha256)) {
    throw new Error('The workspace credential pin metadata is malformed.')
  }
  return { present: true, pinSha256: pinSha256.toLowerCase() }
}

function writeCredentialPin(
  directory: string,
  credentialId: string,
  endpoint: string,
  protocol: ProviderSettings['protocol'],
): string {
  ensureCredentialsDir(directory)
  const path = credentialPinPath(directory, credentialId)
  assertNotSymlinkIfExists(path, 'credential pin metadata')
  const pinSha256 = computeCredentialEndpointPin(endpoint, protocol)
  const payload = JSON.stringify({
    version: 1,
    pinSha256,
    pinnedAt: Date.now(),
  })
  const tmpPath = `${path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`
  try {
    writeFileSync(tmpPath, payload, { mode: 0o600, flag: 'wx' })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, path)
    chmodSync(path, 0o600)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
  updatePinLedger(directory, pins => {
    pins.set(assertSafeCredentialId(credentialId), pinSha256)
  })
  return path
}

function credentialPathInDir(credDir: string, credentialId: string): string {
  const safeId = assertSafeCredentialId(credentialId)
  const dirSt = assertNotSymlinkIfExists(credDir, 'credentials directory')
  if (dirSt && !dirSt.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  const path = join(credDir, safeId)
  const file = lstatSync(path)
  if (file.isSymbolicLink()) throw new Error('The workspace credential must not be a symbolic link.')
  if ((file.mode & 0o077) !== 0) throw new Error('The workspace credential must have owner-only permissions.')
  if (!file.isFile() || file.size === 0) throw new Error('The workspace credential is unavailable.')
  accessSync(path, constants.R_OK)
  return path
}

function toPublicProfile(row: typeof modelProfiles.$inferSelect): PublicModelProfile {
  const now = Date.now()
  const healthState: PublicModelProfile['healthState'] =
    row.healthState === 'open' && row.cooldownUntil !== null && row.cooldownUntil <= now
      ? 'half_open'
      : row.healthState
  return {
    id: row.id,
    name: row.name,
    endpoint: row.endpoint,
    model: row.model,
    protocol: row.protocol,
    priority: row.priority,
    enabled: row.enabled,
    contextWindow: row.contextWindow,
    maxTokens: row.maxTokens,
    thinkingLevel: row.thinkingLevel,
    roleAffinity: row.roleAffinity ?? 'any',
    inputCostPerMtok: row.inputCostPerMtok,
    cachedInputCostPerMtok: row.cachedInputCostPerMtok,
    outputCostPerMtok: row.outputCostPerMtok,
    healthState,
    cooldownUntil: healthState === 'half_open' && row.healthState === 'open' ? null : row.cooldownUntil,
    lastError: row.lastError,
    updatedAt: row.updatedAt,
  }
}

export function listModelProfiles(storage: Store = store()): PublicModelProfile[] {
  return storage.db.select().from(modelProfiles)
    .where(eq(modelProfiles.workspaceId, storage.workspace.id))
    .orderBy(desc(modelProfiles.priority), desc(modelProfiles.updatedAt))
    .all()
    .map(toPublicProfile)
}

export function publicModelSettings(storage: Store = store()) {
  const profiles = listModelProfiles(storage)
  const head = profiles.find(item => item.enabled) ?? profiles[0]
  return head ? { ...head, profiles } : null
}

export interface ModelProfileLoadResult {
  profiles: ResolvedModelProfile[]
  enabledRows: number
  errors: string[]
}

export function inspectModelProfileLoad(storage: Store = store()): ModelProfileLoadResult {
  const now = Date.now()
  const rows = storage.db.select().from(modelProfiles)
    .where(and(eq(modelProfiles.workspaceId, storage.workspace.id), eq(modelProfiles.enabled, true)))
    .orderBy(desc(modelProfiles.priority), desc(modelProfiles.updatedAt))
    .all()
  let credTarget: ResolvedCredentialsDir
  try {
    credTarget = resolveCredentialsDir(storage.directory)
  } catch (err) {
    // Fail closed if credentials dir or KOVO_CREDENTIALS_DIR is a symlink, mispermissioned, or missing.
    return {
      profiles: [],
      enabledRows: rows.length,
      errors: [err instanceof Error ? err.message : String(err)],
    }
  }
  let ledger: Map<string, string>
  try {
    ledger = readPinLedgerFromDir(credTarget.dir)
  } catch (err) {
    // Fail closed if the workspace pin ledger is a symlink, mispermissioned, or HMAC-tampered.
    return {
      profiles: [],
      enabledRows: rows.length,
      errors: [err instanceof Error ? err.message : String(err)],
    }
  }
  const localCredDir = resolve(join(storage.directory, 'credentials'))
  const useLocalFallbackLedger = credTarget.isOverride && localCredDir !== credTarget.dir
  let localLedger: Map<string, string> | null = null
  if (useLocalFallbackLedger) {
    try {
      localLedger = readPinLedgerFromDir(localCredDir)
    } catch (err) {
      return {
        profiles: [],
        enabledRows: rows.length,
        errors: [err instanceof Error ? err.message : String(err)],
      }
    }
  }
  const persistedFailures = readWorkspaceProfileFailureMap(storage)
  const resolved: ResolvedModelProfile[] = []
  const errors: string[] = []
  for (const row of rows) {
    try {
      const expectedPin = computeCredentialEndpointPin(row.endpoint, row.protocol)
      const safeId = assertSafeCredentialId(row.credentialId)
      const pin = readCredentialPinFromDir(credTarget.dir, safeId)
      if (pin.present) {
        if (!pinsEqual(pin.pinSha256, expectedPin)) {
          // Stored API key is pinned to a different (endpoint, protocol) pair; refuse to load.
          errors.push(`profile '${row.name}' credential pin mismatch`)
          continue
        }
      } else {
        const ledgerPin = ledger.get(safeId)
        if (ledgerPin !== undefined) {
          if (!pinsEqual(ledgerPin, expectedPin)) {
            // Sidecar .pin was removed and SQLite endpoint/protocol was altered; fail closed.
            errors.push(`profile '${row.name}' credential pin ledger mismatch`)
            continue
          }
        } else if (credTarget.isOverride) {
          // Read-only host-side KOVO_CREDENTIALS_DIR override: never write to credTarget.dir.
          // Validate the host credential strictly first, then bind legacy unpinned credentials
          // into this isolated workspace's own local pin ledger so per-workspace SQLite tampering
          // still fails closed without mutating or racing on the shared read-only host directory.
          const credFile = credentialPathInDir(credTarget.dir, safeId)
          void credFile
          if (useLocalFallbackLedger && localLedger) {
            const localPin = localLedger.get(safeId)
            if (localPin !== undefined) {
              if (!pinsEqual(localPin, expectedPin)) {
                errors.push(`profile '${row.name}' local workspace pin ledger mismatch`)
                continue
              }
            } else {
              updatePinLedger(storage.directory, pins => {
                if (!pins.has(safeId)) pins.set(safeId, expectedPin)
              })
              localLedger.set(safeId, expectedPin)
            }
          }
        } else {
          // Genuine pre-M-15 legacy profile with neither .pin nor ledger entry: bind its
          // current (endpoint, protocol) into the HMAC-authenticated ledger on first observation
          // so any subsequent tampering fails closed even without a sidecar .pin file.
          const credFile = credentialPathInDir(credTarget.dir, safeId)
          void credFile
          updatePinLedger(storage.directory, pins => {
            if (!pins.has(safeId)) pins.set(safeId, expectedPin)
          })
          ledger.set(safeId, expectedPin)
        }
      }
      const key = readFileSync(credentialPathInDir(credTarget.dir, safeId), 'utf8').trim()
      let healthState = row.healthState
      let cooldownUntil = row.cooldownUntil
      if (healthState === 'open' && cooldownUntil !== null && cooldownUntil <= now) {
        healthState = 'half_open'
        cooldownUntil = null
        storage.db.update(modelProfiles).set({ healthState: 'half_open', cooldownUntil: null })
          .where(and(eq(modelProfiles.id, row.id), eq(modelProfiles.workspaceId, storage.workspace.id))).run()
      }
      const resolvedPricing = resolveProfilePricing({
        model: row.model,
        inputCostPerMtok: row.inputCostPerMtok,
        cachedInputCostPerMtok: row.cachedInputCostPerMtok,
        outputCostPerMtok: row.outputCostPerMtok,
      })
      const persistedFailure = row.lastError ? (persistedFailures[row.id] ?? null) : null
      resolved.push({
        id: row.id,
        name: row.name,
        endpoint: row.endpoint,
        model: row.model,
        protocol: row.protocol,
        key,
        priority: row.priority,
        enabled: row.enabled,
        contextWindow: row.contextWindow,
        maxTokens: row.maxTokens,
        thinkingLevel: row.thinkingLevel,
        roleAffinity: row.roleAffinity ?? 'any',
        inputCostPerMtok: resolvedPricing.inputCostPerMtok,
        cachedInputCostPerMtok: resolvedPricing.cachedInputCostPerMtok,
        outputCostPerMtok: resolvedPricing.outputCostPerMtok,
        healthState,
        cooldownUntil,
        lastError: row.lastError,
        failureKind: persistedFailure?.kind ?? null,
        failureHard: persistedFailure?.hard ?? null,
        failureStatus: persistedFailure?.status ?? null,
      })
    } catch (err) {
      // Skip unreadable or improperly permissioned credentials.
      errors.push(`profile '${row.name}': ${err instanceof Error ? err.message : String(err)}`)
    }
  }
  return { profiles: resolved, enabledRows: rows.length, errors }
}

export function privateModelProfiles(storage: Store = store()): ResolvedModelProfile[] {
  return inspectModelProfileLoad(storage).profiles
}

export function privateModelSettings(storage: Store = store()): ResolvedModelProfile | null {
  return privateModelProfiles(storage)[0] ?? null
}

export function modelReady(storage: Store = store()): boolean {
  return privateModelProfiles(storage).length > 0
}

export function isProfileHealthy(p: ResolvedModelProfile, now = Date.now()): boolean {
  return !(p.healthState === 'open' && p.cooldownUntil !== null && p.cooldownUntil > now)
}

export function resolveProfilePoolForRole(
  role: RoleAffinity,
  source: readonly ResolvedModelProfile[] | Store = store(),
): ResolvedModelProfile[] {
  const all = 'db' in source
    ? privateModelProfiles(source)
    : source.filter(p => p.enabled)
  if (!all.length) return []

  const sortedAll = [...all].sort((a, b) => b.priority - a.priority)
  if (role === 'any') return sortedAll

  const exact = sortedAll.filter(p => p.roleAffinity === role)
  const generic = sortedAll.filter(p => (p.roleAffinity ?? 'any') === 'any')
  const primaryPool = [...exact, ...generic]

  if (!primaryPool.length) {
    return sortedAll
  }

  const now = Date.now()
  const isHealthy = (p: ResolvedModelProfile) => isProfileHealthy(p, now)

  if (!primaryPool.some(isHealthy)) {
    const restHealthy = sortedAll.filter(
      p => p.roleAffinity !== role && (p.roleAffinity ?? 'any') !== 'any' && isHealthy(p),
    )
    if (restHealthy.length) return [...restHealthy, ...primaryPool]
  }

  return primaryPool
}

export function recordProfileSuccess(profileId: string, storage: Store = store()): void {
  transientFailures.delete(profileId)
  persistWorkspaceProfileFailureMeta(storage, profileId, null)
  storage.db.update(modelProfiles).set({
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }).where(and(eq(modelProfiles.id, profileId), eq(modelProfiles.workspaceId, storage.workspace.id))).run()
}

const RATE_LIMIT_DEFAULT_COOLDOWN_MS = 15_000
const RATE_LIMIT_MIN_COOLDOWN_MS = 1_000
const RATE_LIMIT_MAX_COOLDOWN_MS = 300_000

function clampRateLimitCooldownMs(retryAfterMs: number | null | undefined): number {
  const raw = typeof retryAfterMs === 'number' && Number.isFinite(retryAfterMs)
    ? retryAfterMs
    : RATE_LIMIT_DEFAULT_COOLDOWN_MS
  return Math.max(RATE_LIMIT_MIN_COOLDOWN_MS, Math.min(RATE_LIMIT_MAX_COOLDOWN_MS, Math.floor(raw)))
}

export function recordProfileFailure(
  profileId: string,
  err: string | Error,
  hard: boolean,
  storage: Store = store(),
  meta?: {
    failureKind?: ProviderFailureCode | null
    status?: number | null
    retryAfterMs?: number | null
    cooldownUntilMs?: number | null
    burstExhausted?: boolean
  },
): void {
  const rawMessage = err instanceof Error ? err.message : String(err)
  const safeError = redact(rawMessage).slice(0, 300)
  const now = Date.now()
  const handedOff = consumeLatestProviderFailureForProfile(profileId, now)
  const handedOffCooldown = consumeProfileCooldownHandoff(profileId, now)
  const errKind = typeof err === 'object' && err !== null && 'kind' in err
    ? (err as { kind?: unknown; status?: unknown; retryAfterMs?: unknown })
    : null
  const classifiedAtOrigin = !meta?.failureKind && !(errKind && isProviderFailureCode(errKind.kind)) && !handedOff
    ? classifyProviderFailure(err, { profileId })
    : null
  const resolvedKind: ProviderFailureCode | null = isProviderFailureCode(meta?.failureKind)
    ? meta.failureKind
    : errKind && isProviderFailureCode(errKind.kind)
      ? errKind.kind
      : handedOff?.kind ?? classifiedAtOrigin?.kind ?? null
  const resolvedStatus: number | null = typeof meta?.status === 'number'
    ? meta.status
    : typeof errKind?.status === 'number'
      ? errKind.status
      : handedOff?.status ?? classifiedAtOrigin?.status ?? null
  const resolvedRetryAfterMs: number | null =
    typeof meta?.retryAfterMs === 'number' && Number.isFinite(meta.retryAfterMs)
      ? meta.retryAfterMs
      : typeof errKind?.retryAfterMs === 'number' && Number.isFinite(errKind.retryAfterMs)
        ? errKind.retryAfterMs
        : typeof handedOffCooldown?.retryAfterMs === 'number' && Number.isFinite(handedOffCooldown.retryAfterMs)
          ? handedOffCooldown.retryAfterMs
          : null
  const resolvedCooldownUntilMs: number | null =
    typeof meta?.cooldownUntilMs === 'number' && Number.isFinite(meta.cooldownUntilMs)
      ? meta.cooldownUntilMs
      : typeof handedOffCooldown?.cooldownUntilMs === 'number' && Number.isFinite(handedOffCooldown.cooldownUntilMs)
        ? handedOffCooldown.cooldownUntilMs
        : null
  const isBurstExhausted = Boolean(meta?.burstExhausted || handedOffCooldown?.burstExhausted)
  let healthState: 'open' | 'half_open'
  let cooldownUntil: number

  if (hard) {
    transientFailures.delete(profileId)
    healthState = 'open'
    cooldownUntil = now + 10 * 60_000
  } else if (resolvedKind === 'rate_limited' || isBurstExhausted) {
    const streak = (transientFailures.get(profileId) ?? 0) + 1
    transientFailures.set(profileId, streak)
    healthState = 'open'
    cooldownUntil = resolvedCooldownUntilMs !== null && resolvedCooldownUntilMs > now
      ? Math.max(now + RATE_LIMIT_MIN_COOLDOWN_MS, Math.min(now + RATE_LIMIT_MAX_COOLDOWN_MS, Math.floor(resolvedCooldownUntilMs)))
      : now + clampRateLimitCooldownMs(resolvedRetryAfterMs)
  } else {
    const streak = (transientFailures.get(profileId) ?? 0) + 1
    transientFailures.set(profileId, streak)
    if (streak === 1) {
      healthState = 'half_open'
      cooldownUntil = now + 15_000
    } else {
      healthState = 'open'
      cooldownUntil = now + Math.min(5 * 60_000, 30_000 * 2 ** (streak - 2))
    }
  }

  persistWorkspaceProfileFailureMeta(
    storage,
    profileId,
    resolvedKind
      ? {
          kind: resolvedKind,
          hard,
          status: resolvedStatus,
          retryAfterMs: resolvedRetryAfterMs,
          cooldownUntilMs: cooldownUntil,
          recordedAt: now,
        }
      : null,
  )
  storage.db.update(modelProfiles).set({
    healthState,
    cooldownUntil,
    lastError: safeError,
  }).where(and(eq(modelProfiles.id, profileId), eq(modelProfiles.workspaceId, storage.workspace.id))).run()
}

function findExistingProfile(
  storage: Store,
  settings: Pick<ProviderSettings, 'id'>,
) {
  if (!settings.id) return undefined
  return storage.db.select().from(modelProfiles).where(and(
    eq(modelProfiles.id, settings.id), eq(modelProfiles.workspaceId, storage.workspace.id),
  )).get()
}

function resolveUniqueProfileName(
  storage: Store,
  requestedName: string,
  excludeId?: string,
): string {
  const base = requestedName.trim()
  const existingNames = new Set(
    storage.db.select({ id: modelProfiles.id, name: modelProfiles.name })
      .from(modelProfiles)
      .where(eq(modelProfiles.workspaceId, storage.workspace.id))
      .all()
      .filter(row => row.id !== excludeId)
      .map(row => row.name.trim().toLowerCase()),
  )
  if (!existingNames.has(base.toLowerCase())) return base
  for (let n = 2; n < 10_000; n += 1) {
    const suffix = ` (${n})`
    const candidate = `${base.slice(0, 160 - suffix.length)}${suffix}`
    if (!existingNames.has(candidate.toLowerCase())) return candidate
  }
  const fallbackSuffix = ` (${randomUUID().slice(0, 6)})`
  return `${base.slice(0, 160 - fallbackSuffix.length)}${fallbackSuffix}`
}

function resolveEffectiveKey(
  storage: Store,
  settings: ProviderSettings,
  existing: typeof modelProfiles.$inferSelect | undefined,
): string {
  if (settings.key) return settings.key
  if (!existing) throw new Error('API key is required when adding a new model profile.')

  // M-15 / H-7: Bind stored API keys to (normalizedEndpoint, protocol). Never send a previously
  // stored key to a different endpoint or protocol without re-entering the API key — even for
  // legacy profiles whose sidecar .pin file is absent.
  const requestedPin = computeCredentialEndpointPin(settings.endpoint, settings.protocol)
  const existingPin = computeCredentialEndpointPin(existing.endpoint, existing.protocol)
  if (!pinsEqual(requestedPin, existingPin)) {
    throw new Error('Changing a model profile endpoint or protocol requires re-entering the API key.')
  }
  const credTarget = resolveCredentialsDir(storage.directory)
  const storedPin = readCredentialPinFromDir(credTarget.dir, existing.credentialId)
  if (storedPin.present && !pinsEqual(storedPin.pinSha256, requestedPin)) {
    throw new Error('Stored API key is pinned to a different endpoint or protocol. Re-enter the API key to continue.')
  }
  const ledger = readPinLedgerFromDir(credTarget.dir)
  const ledgerPin = ledger.get(assertSafeCredentialId(existing.credentialId))
  if (ledgerPin !== undefined && !pinsEqual(ledgerPin, requestedPin)) {
    throw new Error('Stored API key is pinned to a different endpoint or protocol. Re-enter the API key to continue.')
  }
  const localCredDir = resolve(join(storage.directory, 'credentials'))
  if (credTarget.isOverride && localCredDir !== credTarget.dir) {
    const localLedger = readPinLedgerFromDir(localCredDir)
    const localPin = localLedger.get(assertSafeCredentialId(existing.credentialId))
    if (localPin !== undefined && !pinsEqual(localPin, requestedPin)) {
      throw new Error('Stored API key is pinned to a different endpoint or protocol. Re-enter the API key to continue.')
    }
  }

  return readFileSync(credentialPathInDir(credTarget.dir, existing.credentialId), 'utf8').trim()
}

function assertNoNullOrNegativePricing(raw: Record<string, unknown>): void {
  for (const field of ['inputCostPerMtok', 'cachedInputCostPerMtok', 'outputCostPerMtok'] as const) {
    if (!Object.prototype.hasOwnProperty.call(raw, field)) continue
    const val = raw[field]
    if (val === undefined) continue
    if (val === null || typeof val !== 'number' || !Number.isFinite(val) || val < 0) {
      throw new Error(
        `Invalid ${field}: pricing must be a finite non-negative number (null pricing is forbidden because it would disable the hard USD cap).`,
      )
    }
  }
}

function normalizeModelProfilePricingInput(
  input: z.input<typeof providerSettings>,
  opts: {
    existing?: typeof modelProfiles.$inferSelect
    requireExplicitPricing?: boolean
  } = {},
): z.input<typeof providerSettings> {
  const raw = input as Record<string, unknown>
  assertNoNullOrNegativePricing(raw)

  const model = typeof input.model === 'string' ? input.model.trim() : ''
  if (isDefaultFlashModel(model)) {
    return input
  }

  const hasExplicitInput = typeof input.inputCostPerMtok === 'number'
  const hasExplicitOutput = typeof input.outputCostPerMtok === 'number'
  const hasExplicitCached = typeof input.cachedInputCostPerMtok === 'number'

  if (hasExplicitInput && hasExplicitOutput) {
    return {
      ...input,
      cachedInputCostPerMtok: hasExplicitCached ? input.cachedInputCostPerMtok : input.inputCostPerMtok,
    }
  }

  const sameModelUpdate = Boolean(
    opts.existing && opts.existing.model.trim().toLowerCase() === model.toLowerCase(),
  )
  if (sameModelUpdate && opts.existing) {
    const preserved = resolveProfilePricing(opts.existing)
    return {
      ...input,
      inputCostPerMtok: hasExplicitInput ? input.inputCostPerMtok : preserved.inputCostPerMtok,
      cachedInputCostPerMtok: hasExplicitCached ? input.cachedInputCostPerMtok : preserved.cachedInputCostPerMtok,
      outputCostPerMtok: hasExplicitOutput ? input.outputCostPerMtok : preserved.outputCostPerMtok,
    }
  }

  if (opts.requireExplicitPricing) {
    throw new Error(
      `Explicit inputCostPerMtok and outputCostPerMtok are required for non-default model profile '${model || 'unknown'}'.`,
    )
  }

  // Non-default model without explicit pricing: apply conservatively high fallback pricing
  // instead of silently inheriting cheap Flash defaults (and never disable the USD cap).
  const fallbackInput = hasExplicitInput ? input.inputCostPerMtok! : CONSERVATIVE_FALLBACK_PRICING.inputCostPerMtok
  const fallbackOutput = hasExplicitOutput ? input.outputCostPerMtok! : CONSERVATIVE_FALLBACK_PRICING.outputCostPerMtok
  const fallbackCached = hasExplicitCached
    ? input.cachedInputCostPerMtok!
    : Math.min(fallbackInput, CONSERVATIVE_FALLBACK_PRICING.cachedInputCostPerMtok)

  return {
    ...input,
    inputCostPerMtok: fallbackInput,
    cachedInputCostPerMtok: fallbackCached,
    outputCostPerMtok: fallbackOutput,
  }
}

export async function checkModelConnection(
  input: z.input<typeof providerSettings>,
  storage: Store = store(),
): Promise<{ ok: true }> {
  const existing = typeof input.id === 'string' ? findExistingProfile(storage, { id: input.id }) : undefined
  const normalizedInput = normalizeModelProfilePricingInput(input, { existing })
  const parsed = providerSettings.parse(normalizedInput)
  const resolvedKey = resolveEffectiveKey(storage, parsed, existing)
  const effective = { ...parsed, key: resolvedKey }
  const digest = hash(effective)
  const attempt = ++latestTestAttempt
  if (lastTest?.digest === digest) lastTest = undefined
  await testProvider(effective)
  if (attempt === latestTestAttempt) lastTest = { digest, expires: Date.now() + 5 * 60_000 }
  if (existing) {
    let matchesStoredKey = !parsed.key
    if (!matchesStoredKey) {
      try {
        const credTarget = resolveCredentialsDir(storage.directory)
        matchesStoredKey = resolvedKey === readFileSync(credentialPathInDir(credTarget.dir, existing.credentialId), 'utf8').trim()
      } catch {
        matchesStoredKey = false
      }
    }
    const matchesExistingConnection =
      existing.endpoint === parsed.endpoint &&
      existing.model === parsed.model &&
      existing.protocol === parsed.protocol &&
      matchesStoredKey
    if (matchesExistingConnection) {
      recordProfileSuccess(existing.id, storage)
    }
  }
  return { ok: true as const }
}

export async function saveModelProfile(
  input: z.input<typeof providerSettings>,
  storage: Store = store(),
  options: { skipConnectionCheck?: boolean; requireExplicitPricing?: boolean } = {},
): Promise<{ ok: true; id: string }> {
  const existingPreParse = typeof input.id === 'string' ? findExistingProfile(storage, { id: input.id }) : undefined
  const normalizedInput = normalizeModelProfilePricingInput(input, {
    existing: existingPreParse,
    requireExplicitPricing: options.requireExplicitPricing,
  })
  const settings = providerSettings.parse(normalizedInput)
  const existing = existingPreParse ?? findExistingProfile(storage, settings)
  const rotatingKey = Boolean(settings.key)
  const resolvedKey = resolveEffectiveKey(storage, settings, existing)
  const effective = { ...settings, key: resolvedKey }

  const connectionUnchanged = Boolean(
    existing &&
    !rotatingKey &&
    existing.endpoint === settings.endpoint &&
    existing.model === settings.model &&
    existing.protocol === settings.protocol,
  )

  if (!options.skipConnectionCheck && !connectionUnchanged && (!lastTest || lastTest.expires < Date.now() || lastTest.digest !== hash(effective))) {
    await checkModelConnection(effective, storage)
  }

  const directory = ensureCredentialsDir(storage.directory)

  let credentialId: string
  let newCredentialPath: string | null = null
  let newPinPath: string | null = null
  if (existing && !rotatingKey) {
    credentialId = assertSafeCredentialId(existing.credentialId)
    // M-15 lazy-pin: preserve legacy profiles without a pin file yet, and pin on first save/update.
    if (!existsSync(credentialPinPath(storage.directory, credentialId))) {
      writeCredentialPin(storage.directory, credentialId, settings.endpoint, settings.protocol)
    }
  } else {
    credentialId = 'model-' + randomUUID()
    newCredentialPath = join(directory, credentialId)
    assertNotSymlinkIfExists(newCredentialPath, 'credential')
    writeFileSync(newCredentialPath, resolvedKey, { mode: 0o600, flag: 'wx' })
    chmodSync(newCredentialPath, 0o600)
    newPinPath = writeCredentialPin(storage.directory, credentialId, settings.endpoint, settings.protocol)
  }
  const profileId = existing?.id ?? settings.id ?? randomUUID()
  const finalName = existing ? settings.name : resolveUniqueProfileName(storage, settings.name)

  try {
    const values = {
      name: finalName,
      endpoint: settings.endpoint,
      model: settings.model,
      protocol: settings.protocol,
      credentialId,
      priority: settings.priority,
      enabled: settings.enabled,
      contextWindow: settings.contextWindow,
      maxTokens: settings.maxTokens,
      thinkingLevel: settings.thinkingLevel,
      roleAffinity: settings.roleAffinity,
      inputCostPerMtok: settings.inputCostPerMtok,
      cachedInputCostPerMtok: settings.cachedInputCostPerMtok,
      outputCostPerMtok: settings.outputCostPerMtok,
      healthState: 'closed' as const,
      cooldownUntil: null,
      lastError: null,
      updatedAt: Date.now(),
    }
    if (existing) {
      storage.db.update(modelProfiles).set(values).where(eq(modelProfiles.id, existing.id)).run()
    } else {
      storage.db.insert(modelProfiles).values({
        ...values,
        id: profileId,
        workspaceId: storage.workspace.id,
      }).run()
    }
    transientFailures.delete(profileId)
    persistWorkspaceProfileFailureMeta(storage, profileId, null)
  } catch {
    if (newCredentialPath) {
      try { unlinkSync(newCredentialPath) } catch { /* ignore */ }
    }
    if (newPinPath) {
      try { unlinkSync(newPinPath) } catch { /* ignore */ }
    }
    throw new Error('Could not save the workspace model profile.')
  }

  if (existing && newCredentialPath && existing.credentialId !== credentialId) {
    try { unlinkSync(join(directory, existing.credentialId)) } catch { /* ignore */ }
    try { unlinkSync(credentialPinPath(storage.directory, existing.credentialId)) } catch { /* ignore */ }
    try {
      updatePinLedger(storage.directory, pins => { pins.delete(existing.credentialId) })
    } catch { /* ignore */ }
  }
  return { ok: true as const, id: profileId }
}

export const saveModelSettings = saveModelProfile

export function setModelProfileEnabled(
  profileId: string,
  enabled: boolean,
  storage: Store = store(),
): { ok: true; id: string; enabled: boolean } {
  const row = storage.db.select().from(modelProfiles).where(and(
    eq(modelProfiles.id, profileId), eq(modelProfiles.workspaceId, storage.workspace.id),
  )).get()
  if (!row) throw new Error('Model profile not found.')
  storage.db.update(modelProfiles).set({
    enabled,
    ...(enabled ? { healthState: 'closed' as const, cooldownUntil: null } : {}),
    updatedAt: Date.now(),
  }).where(eq(modelProfiles.id, row.id)).run()
  if (enabled) transientFailures.delete(row.id)
  return { ok: true as const, id: row.id, enabled }
}

export function deleteModelProfile(profileId: string, storage: Store = store()): { ok: true; id: string } {
  const row = storage.db.select().from(modelProfiles).where(and(
    eq(modelProfiles.id, profileId), eq(modelProfiles.workspaceId, storage.workspace.id),
  )).get()
  if (!row) throw new Error('Model profile not found.')
  storage.db.delete(modelProfiles).where(eq(modelProfiles.id, row.id)).run()
  transientFailures.delete(row.id)
  try { unlinkSync(join(storage.directory, 'credentials', row.credentialId)) } catch { /* ignore */ }
  try { unlinkSync(credentialPinPath(storage.directory, row.credentialId)) } catch { /* ignore */ }
  try {
    updatePinLedger(storage.directory, pins => { pins.delete(row.credentialId) })
  } catch { /* ignore */ }
  return { ok: true as const, id: row.id }
}
