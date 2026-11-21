import { createHash, randomUUID } from 'node:crypto'
import { accessSync, chmodSync, constants, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { and, desc, eq } from 'drizzle-orm'
import type { z } from 'zod'
import { providerSettings } from '../domain.ts'
import type { ProviderSettings, PublicModelProfile } from '../domain.ts'
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

function credentialPath(directory: string, credentialId: string): string {
  const path = join(directory, 'credentials', credentialId)
  const file = statSync(path)
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
    inputCostPerMtok: row.inputCostPerMtok,
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
  const resolved: ResolvedModelProfile[] = []
  for (const row of rows) {
    try {
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
        inputCostPerMtok: row.inputCostPerMtok,
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

export async function checkModelConnection(input: z.input<typeof providerSettings>): Promise<{ ok: true }> {
  const parsed = providerSettings.parse(input)
  const digest = hash(parsed)
  const attempt = ++latestTestAttempt
  if (lastTest?.digest === digest) lastTest = undefined
  await testProvider(parsed)
  if (attempt === latestTestAttempt) lastTest = { digest, expires: Date.now() + 5 * 60_000 }
  return { ok: true as const }
}

export async function saveModelProfile(
  input: z.input<typeof providerSettings>,
  storage: Store = store(),
  options: { skipConnectionCheck?: boolean } = {},
): Promise<{ ok: true; id: string }> {
  const settings = providerSettings.parse(input)
  if (!options.skipConnectionCheck && (!lastTest || lastTest.expires < Date.now() || lastTest.digest !== hash(settings))) {
    await checkModelConnection(settings)
  }

  const directory = join(storage.directory, 'credentials')
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  chmodSync(directory, 0o700)

  const existing = settings.id
    ? storage.db.select().from(modelProfiles).where(and(
        eq(modelProfiles.id, settings.id), eq(modelProfiles.workspaceId, storage.workspace.id),
      )).get()
    : storage.db.select().from(modelProfiles).where(and(
        eq(modelProfiles.workspaceId, storage.workspace.id), eq(modelProfiles.name, settings.name),
      )).get()

  const credentialId = 'model-' + randomUUID()
  const path = join(directory, credentialId)
  writeFileSync(path, settings.key, { mode: 0o600, flag: 'wx' })
  const profileId = existing?.id ?? settings.id ?? randomUUID()

  try {
    const values = {
      name: settings.name,
      endpoint: settings.endpoint,
      model: settings.model,
      protocol: settings.protocol,
      credentialId,
      priority: settings.priority,
      enabled: settings.enabled,
      contextWindow: settings.contextWindow,
      maxTokens: settings.maxTokens,
      thinkingLevel: settings.thinkingLevel,
      inputCostPerMtok: settings.inputCostPerMtok,
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
    try { unlinkSync(path) } catch { /* ignore */ }
    throw new Error('Could not save the workspace model profile.')
  }

  if (existing) {
    try { unlinkSync(join(directory, existing.credentialId)) } catch { /* ignore */ }
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
  return { ok: true as const, id: row.id }
}
