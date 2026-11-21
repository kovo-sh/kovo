import { randomUUID } from 'node:crypto'
import { accessSync, chmodSync, constants, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { and, eq } from 'drizzle-orm'
import type { z } from 'zod'
import type { PublicPersona, createPersona, deletePersona } from '../domain.ts'
import type { NamedSecret } from './redact.ts'
import { personas } from './schema.ts'
import type { Store } from './store.ts'

export interface ResolvedPersona {
  id: string
  handle: string
  roleLabel: string
  originAllowlist: string[]
  authKind: 'cookie' | 'bearer' | 'header'
  headerName: string | null
  secret: string
  canaryMarkers: string[]
}

function secretFile(storage: Store, credentialId: string) {
  const path = join(storage.directory, 'credentials', credentialId)
  const stat = statSync(path)
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona credential must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) throw new Error('Persona credential is unavailable.')
  accessSync(path, constants.R_OK)
  return path
}

export function listProjectPersonas(storage: Store, projectId: string): PublicPersona[] {
  storage.project(projectId)
  return storage.db.select().from(personas)
    .where(and(eq(personas.projectId, projectId), eq(personas.workspaceId, storage.workspace.id)))
    .all()
    .map(({ credentialId: _omit, workspaceId: _ws, ...pub }) => pub)
}

export function createProjectPersona(storage: Store, input: z.output<typeof createPersona>): { id: string; handle: string } {
  return storage.operate(input, () => {
    const project = storage.project(input.projectId)
    const dir = join(storage.directory, 'credentials')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    const credentialId = 'persona-' + randomUUID()
    const path = join(dir, credentialId)
    writeFileSync(path, input.secret, { mode: 0o600, flag: 'wx' })
    const personaId = randomUUID()
    try {
      storage.db.insert(personas).values({
        id: personaId,
        projectId: project.id,
        workspaceId: storage.workspace.id,
        handle: input.handle,
        roleLabel: input.roleLabel,
        originAllowlist: [...new Set(input.originAllowlist)],
        authKind: input.authKind,
        headerName: input.authKind === 'header' ? (input.headerName ?? 'X-Api-Key') : null,
        credentialId,
        canaryMarkers: input.canaryMarkers,
        createdAt: Date.now(),
      }).run()
    } catch (error) {
      try { unlinkSync(path) } catch { /* ignore */ }
      throw error
    }
    storage.event(null, 'persona.created', `Registered persona ${input.handle}.`, {
      projectId: project.id, personaId, handle: input.handle, origins: input.originAllowlist,
    })
    return { id: personaId, handle: input.handle }
  })
}

export function deleteProjectPersona(storage: Store, input: z.output<typeof deletePersona>): { id: string } {
  return storage.operate(input, () => {
    storage.project(input.projectId)
    const existing = storage.db.select().from(personas).where(and(
      eq(personas.id, input.personaId), eq(personas.projectId, input.projectId), eq(personas.workspaceId, storage.workspace.id),
    )).get()
    if (!existing) throw new Error('Persona not found.')
    storage.db.delete(personas).where(eq(personas.id, existing.id)).run()
    try { unlinkSync(join(storage.directory, 'credentials', existing.credentialId)) } catch { /* ignore */ }
    storage.event(null, 'persona.deleted', `Removed persona ${existing.handle}.`, { projectId: input.projectId, personaId: existing.id })
    return { id: existing.id }
  })
}

export function resolveRunPersonas(storage: Store, projectId: string, approvedPersonaIds: readonly string[]): Map<string, ResolvedPersona> {
  const allowed = new Set(approvedPersonaIds)
  const map = new Map<string, ResolvedPersona>()
  if (!allowed.size) return map
  const rows = storage.db.select().from(personas)
    .where(and(eq(personas.projectId, projectId), eq(personas.workspaceId, storage.workspace.id)))
    .all()
  for (const row of rows) {
    if (!allowed.has(row.id)) continue
    const secret = readFileSync(secretFile(storage, row.credentialId), 'utf8')
    map.set(row.handle, {
      id: row.id,
      handle: row.handle,
      roleLabel: row.roleLabel,
      originAllowlist: row.originAllowlist,
      authKind: row.authKind,
      headerName: row.headerName,
      secret,
      canaryMarkers: row.canaryMarkers,
    })
  }
  return map
}

export function personaSecrets(resolved: ReadonlyMap<string, ResolvedPersona>): NamedSecret[] {
  const out: NamedSecret[] = []
  for (const persona of resolved.values()) {
    out.push({ value: persona.secret, placeholder: `[persona:${persona.handle}:secret]` })
  }
  return out
}

export function buildPersonaHeader(persona: ResolvedPersona, origin: string): Record<string, string> | null {
  if (!persona.originAllowlist.includes(origin)) return null
  if (persona.authKind === 'bearer') return { Authorization: 'Bearer ' + persona.secret }
  if (persona.authKind === 'cookie') return { Cookie: persona.secret }
  return { [persona.headerName ?? 'X-Api-Key']: persona.secret }
}
