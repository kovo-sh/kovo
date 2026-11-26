import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { accessSync, chmodSync, constants, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import type { Stats } from 'node:fs'
import { join } from 'node:path'
import { and, desc, eq } from 'drizzle-orm'
import type { z } from 'zod'
import { providerSettings } from '../domain.ts'
import type { ProviderSettings, PublicModelProfile, RoleAffinity } from '../domain.ts'
import { testProvider } from './provider.ts'
import { redact } from './redact.ts'
import { modelProfiles } from './schema.ts'
import type { Store } from './store.ts'
import { store } from './store.ts'

export interface ResolvedModelProfile extends ProviderSettings {
  id: string
  healthState: 'closed' | 'open' | 'half_open'
  cooldownUntil: number | null
  lastError: string | null
}

let lastTest: { digest: string; expires: number } | undefined
let latestTestAttempt = 0
const transientFailures = new Map<string, number>()

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

function loadOrCreatePinHmacKey(directory: string, createIfMissing: boolean): Buffer | null {
  const dir = join(directory, 'credentials')
  const keyPath = join(dir, PIN_HMAC_KEY_FILENAME)
  const st = assertNotSymlinkIfExists(keyPath, 'credential pin key')
  if (st) {
    if (!st.isFile() || (st.mode & 0o077) !== 0) {
      throw new Error('The workspace credential pin key has invalid permissions.')
    }
    const raw = readFileSync(keyPath, 'utf8').trim()
    if (!/^[0-9a-f]{64}$/i.test(raw)) {
      throw new Error('The workspace credential pin key is malformed.')
    }
    return Buffer.from(raw, 'hex')
  }
  if (!createIfMissing) return null
  ensureCredentialsDir(directory)
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

function readPinLedger(directory: string): Map<string, string> {
  const dir = join(directory, 'credentials')
  const dirSt = assertNotSymlinkIfExists(dir, 'credentials directory')
  if (dirSt && !dirSt.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  const ledgerPath = join(dir, PIN_LEDGER_FILENAME)
  const st = assertNotSymlinkIfExists(ledgerPath, 'credential pin ledger')
  if (!st) {
    return new Map()
  }
  if (!st.isFile() || (st.mode & 0o077) !== 0) {
    throw new Error('The workspace credential pin ledger has invalid permissions.')
  }
  const key = loadOrCreatePinHmacKey(directory, false)
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
  const existing = readPinLedger(directory)
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

function readCredentialPin(
  directory: string,
  credentialId: string,
): { present: false; pinSha256: null } | { present: true; pinSha256: string } {
  const dirSt = assertNotSymlinkIfExists(join(directory, 'credentials'), 'credentials directory')
  if (dirSt && !dirSt.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  const path = credentialPinPath(directory, credentialId)
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

function credentialPath(directory: string, credentialId: string): string {
  const safeId = assertSafeCredentialId(credentialId)
  const dirSt = assertNotSymlinkIfExists(join(directory, 'credentials'), 'credentials directory')
  if (dirSt && !dirSt.isDirectory()) {
    throw new Error('The workspace credentials path is not a directory.')
  }
  const path = join(directory, 'credentials', safeId)
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

export function privateModelProfiles(storage: Store = store()): ResolvedModelProfile[] {
  const now = Date.now()
  const rows = storage.db.select().from(modelProfiles)
    .where(and(eq(modelProfiles.workspaceId, storage.workspace.id), eq(modelProfiles.enabled, true)))
    .orderBy(desc(modelProfiles.priority), desc(modelProfiles.updatedAt))
    .all()
  let ledger: Map<string, string>
  try {
    ledger = readPinLedger(storage.directory)
  } catch {
    // Fail closed if the workspace pin ledger is a symlink, mispermissioned, or HMAC-tampered.
    return []
  }
  const resolved: ResolvedModelProfile[] = []
  for (const row of rows) {
    try {
      const expectedPin = computeCredentialEndpointPin(row.endpoint, row.protocol)
      const pin = readCredentialPin(storage.directory, row.credentialId)
      if (pin.present) {
        if (!pinsEqual(pin.pinSha256, expectedPin)) {
          // Stored API key is pinned to a different (endpoint, protocol) pair; refuse to load.
          continue
        }
      } else {
        const ledgerPin = ledger.get(assertSafeCredentialId(row.credentialId))
        if (ledgerPin !== undefined) {
          if (!pinsEqual(ledgerPin, expectedPin)) {
            // Sidecar .pin was removed and SQLite endpoint/protocol was altered; fail closed.
            continue
          }
        } else {
          // Genuine pre-M-15 legacy profile with neither .pin nor ledger entry: bind its
          // current (endpoint, protocol) into the HMAC-authenticated ledger on first observation
          // so any subsequent tampering fails closed even without a sidecar .pin file.
          const credFile = credentialPath(storage.directory, row.credentialId)
          void credFile
          updatePinLedger(storage.directory, pins => {
            if (!pins.has(row.credentialId)) pins.set(row.credentialId, expectedPin)
          })
          ledger.set(row.credentialId, expectedPin)
        }
      }
      const key = readFileSync(credentialPath(storage.directory, row.credentialId), 'utf8').trim()
      let healthState = row.healthState
      let cooldownUntil = row.cooldownUntil
      if (healthState === 'open' && cooldownUntil !== null && cooldownUntil <= now) {
        healthState = 'half_open'
        cooldownUntil = null
        storage.db.update(modelProfiles).set({ healthState: 'half_open', cooldownUntil: null })
          .where(and(eq(modelProfiles.id, row.id), eq(modelProfiles.workspaceId, storage.workspace.id))).run()
      }
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
        inputCostPerMtok: row.inputCostPerMtok,
        cachedInputCostPerMtok: row.cachedInputCostPerMtok,
        outputCostPerMtok: row.outputCostPerMtok,
        healthState,
        cooldownUntil,
        lastError: row.lastError,
      })
    } catch {
      // Skip unreadable or improperly permissioned credentials.
    }
  }
  return resolved
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
  storage.db.update(modelProfiles).set({
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }).where(and(eq(modelProfiles.id, profileId), eq(modelProfiles.workspaceId, storage.workspace.id))).run()
}

export function recordProfileFailure(
  profileId: string,
  err: string | Error,
  hard: boolean,
  storage: Store = store(),
): void {
  const rawMessage = err instanceof Error ? err.message : String(err)
  const safeError = redact(rawMessage).slice(0, 300)
  const now = Date.now()
  let healthState: 'open' | 'half_open'
  let cooldownUntil: number

  if (hard) {
    transientFailures.delete(profileId)
    healthState = 'open'
    cooldownUntil = now + 10 * 60_000
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
  const storedPin = readCredentialPin(storage.directory, existing.credentialId)
  if (storedPin.present && !pinsEqual(storedPin.pinSha256, requestedPin)) {
    throw new Error('Stored API key is pinned to a different endpoint or protocol. Re-enter the API key to continue.')
  }
  const ledger = readPinLedger(storage.directory)
  const ledgerPin = ledger.get(assertSafeCredentialId(existing.credentialId))
  if (ledgerPin !== undefined && !pinsEqual(ledgerPin, requestedPin)) {
    throw new Error('Stored API key is pinned to a different endpoint or protocol. Re-enter the API key to continue.')
  }

  return readFileSync(credentialPath(storage.directory, existing.credentialId), 'utf8').trim()
}

export async function checkModelConnection(
  input: z.input<typeof providerSettings>,
  storage: Store = store(),
): Promise<{ ok: true }> {
  const parsed = providerSettings.parse(input)
  const existing = findExistingProfile(storage, parsed)
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
        matchesStoredKey = resolvedKey === readFileSync(credentialPath(storage.directory, existing.credentialId), 'utf8').trim()
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
  options: { skipConnectionCheck?: boolean } = {},
): Promise<{ ok: true; id: string }> {
  const settings = providerSettings.parse(input)
  const existing = findExistingProfile(storage, settings)
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
