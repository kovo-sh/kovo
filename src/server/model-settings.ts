import { createHash, randomUUID } from 'node:crypto'
import { chmodSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { eq } from 'drizzle-orm'
import type { ProviderSettings } from '../domain.ts'
import { testProvider } from './provider.ts'
import { modelConfig } from './schema.ts'
import { store } from './store.ts'

let lastTest: { digest: string; expires: number } | undefined
let latestTestAttempt = 0
const hash = (settings: ProviderSettings) => createHash('sha256').update(JSON.stringify(settings)).digest('hex')

function savedConfiguration() {
  const storage = store()
  return storage.db.select().from(modelConfig).where(eq(modelConfig.workspaceId, storage.workspace.id)).get()
}

export function publicModelSettings() {
  const saved = savedConfiguration()
  return saved ? { endpoint: saved.endpoint, model: saved.model, protocol: saved.protocol } : null
}

export function privateModelSettings(): ProviderSettings | null {
  const saved = savedConfiguration()
  if (!saved) return null
  const path = join(store().directory, 'credentials', saved.credentialId)
  if ((statSync(path).mode & 0o077) !== 0) throw new Error('The workspace credential must have owner-only permissions.')
  return { endpoint: saved.endpoint, model: saved.model, protocol: saved.protocol, key: readFileSync(path, 'utf8') }
}

export async function checkModelConnection(settings: ProviderSettings) {
  const digest = hash(settings)
  const attempt = ++latestTestAttempt
  if (lastTest?.digest === digest) lastTest = undefined
  await testProvider(settings)
  if (attempt === latestTestAttempt) lastTest = { digest, expires: Date.now() + 5 * 60_000 }
  return { ok: true as const }
}

export async function saveModelSettings(settings: ProviderSettings) {
  if (!lastTest || lastTest.expires < Date.now() || lastTest.digest !== hash(settings)) {
    await checkModelConnection(settings)
  }
  const storage = store()
  const directory = join(storage.directory, 'credentials')
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  chmodSync(directory, 0o700)
  const previous = savedConfiguration()
  const credentialId = randomUUID()
  const path = join(directory, credentialId)
  writeFileSync(path, settings.key, { mode: 0o600, flag: 'wx' })
  try {
    const values = {
      endpoint: settings.endpoint, model: settings.model, protocol: settings.protocol, credentialId, updatedAt: Date.now(),
    }
    storage.db.insert(modelConfig).values({ ...values, workspaceId: storage.workspace.id })
      .onConflictDoUpdate({ target: modelConfig.workspaceId, set: values }).run()
  } catch {
    unlinkSync(path)
    throw new Error('Could not save the workspace model.')
  }
  if (previous) {
    try { unlinkSync(join(directory, previous.credentialId)) } catch { /* The new credential is already active. */ }
  }
  return { ok: true as const }
}
