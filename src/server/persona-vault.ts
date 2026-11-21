import { randomUUID } from 'node:crypto'
import {
  accessSync,
  chmodSync,
  constants,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { and, eq } from 'drizzle-orm'
import type { z } from 'zod'
import type {
  PersonaAuthKind,
  PersonaLoginConfig,
  PublicPersona,
  createPersona,
  deletePersona,
} from '../domain.ts'
import type { NamedSecret } from './redact.ts'
import { personas } from './schema.ts'
import type { Store } from './store.ts'

export interface LoginCredentialFilePayload {
  v: 1
  email: string
  password: string
}

export interface MintedPersonaSession {
  headerType: 'cookie' | 'bearer' | 'header'
  headerName?: string
  value: string
  expiresAt?: number
  adapterUsed: string
  /**
   * Additional sensitive tokens associated with this persona's login session
   * (e.g., __client cookie, refresh tokens, and historical rotated JWTs) so
   * personaSecrets() always scrubs them even across fresh Store reads.
   * Stored ONLY in this 0600 host file, never in SQLite or PublicPersona.
   */
  scrubTokens?: string[]
  updatedAt?: number
}

export interface ResolvedPersona {
  id: string
  handle: string
  roleLabel: string
  originAllowlist: string[]
  authKind: PersonaAuthKind
  headerName: string | null
  loginConfig?: PersonaLoginConfig | null
  credentialId?: string
  secret: string
  canaryMarkers: string[]
  secretPath?: string
  secretMtimeMs?: number
  secretIno?: number
  secretHistory?: string[]
  sessionPath?: string
  sessionMtimeMs?: number
  sessionIno?: number
  session?: MintedPersonaSession | null
}

const maxScrubHistoryEntries = 64

function readVerifiedSecretFile(path: string): { secret: string; mtimeMs: number; ino: number } {
  const stat = statSync(path)
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona credential must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) throw new Error('Persona credential is unavailable.')
  accessSync(path, constants.R_OK)
  const secret = readFileSync(path, 'utf8').replace(/[\r\n]+$/, '')
  if (!secret) throw new Error('Persona credential is unavailable.')
  return { secret, mtimeMs: stat.mtimeMs, ino: stat.ino }
}

function readVerifiedSessionFile(path: string): { session: MintedPersonaSession; mtimeMs: number; ino: number } | null {
  let stat: ReturnType<typeof statSync>
  try {
    stat = statSync(path)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw err
  }
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona session file must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) return null
  accessSync(path, constants.R_OK)
  const raw = readFileSync(path, 'utf8').trim()
  if (!raw) return null
  const parsed = JSON.parse(raw) as Partial<MintedPersonaSession>
  if (
    (parsed.headerType !== 'cookie' && parsed.headerType !== 'bearer' && parsed.headerType !== 'header') ||
    typeof parsed.value !== 'string' ||
    !parsed.value
  ) {
    return null
  }
  const session: MintedPersonaSession = {
    headerType: parsed.headerType,
    headerName: typeof parsed.headerName === 'string' && parsed.headerName ? parsed.headerName : undefined,
    value: parsed.value,
    expiresAt: typeof parsed.expiresAt === 'number' ? parsed.expiresAt : undefined,
    adapterUsed: typeof parsed.adapterUsed === 'string' ? parsed.adapterUsed : 'login',
    scrubTokens: Array.isArray(parsed.scrubTokens)
      ? parsed.scrubTokens.filter((v): v is string => typeof v === 'string' && v.length > 0)
      : undefined,
    updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : undefined,
  }
  return { session, mtimeMs: stat.mtimeMs, ino: stat.ino }
}

export function readLoginCredentialFile(path: string): {
  email: string
  password: string
  mtimeMs: number
  ino: number
} {
  const { secret: raw, mtimeMs, ino } = readVerifiedSecretFile(path)
  let parsed: Partial<LoginCredentialFilePayload>
  try {
    parsed = JSON.parse(raw) as Partial<LoginCredentialFilePayload>
  } catch {
    throw new Error('Persona login credential file is corrupted.')
  }
  if (typeof parsed.email !== 'string' || !parsed.email || typeof parsed.password !== 'string' || !parsed.password) {
    throw new Error('Persona login credential file is missing email or password.')
  }
  return { email: parsed.email, password: parsed.password, mtimeMs, ino }
}

export function writePersonaSessionFile(
  sessionPath: string,
  session: MintedPersonaSession,
): MintedPersonaSession {
  const dir = dirname(sessionPath)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)

  // Preserve historical minted session values & extra scrub tokens (e.g. __client, prior JWTs)
  // so personaSecrets() always scrubs every prior & current token after rotation.
  const mergedScrub: string[] = []
  const seen = new Set<string>()
  const addToken = (tok: string | undefined) => {
    if (!tok || tok.length < 4 || seen.has(tok)) return
    seen.add(tok)
    mergedScrub.push(tok)
  }

  try {
    const existing = readVerifiedSessionFile(sessionPath)
    if (existing) {
      addToken(existing.session.value)
      for (const tok of existing.session.scrubTokens ?? []) addToken(tok)
    }
  } catch {
    // Ignore missing/unparseable prior session file.
  }

  addToken(session.value)
  for (const tok of session.scrubTokens ?? []) addToken(tok)

  const payload: MintedPersonaSession = {
    headerType: session.headerType,
    ...(session.headerName ? { headerName: session.headerName } : {}),
    value: session.value,
    ...(session.expiresAt !== undefined ? { expiresAt: session.expiresAt } : {}),
    adapterUsed: session.adapterUsed,
    scrubTokens: mergedScrub.slice(-maxScrubHistoryEntries),
    updatedAt: Date.now(),
  }

  const tmpPath = `${sessionPath}.${randomUUID()}.tmp`
  try {
    writeFileSync(tmpPath, JSON.stringify(payload), { mode: 0o600, flag: 'wx' })
    chmodSync(tmpPath, 0o600)
    renameSync(tmpPath, sessionPath)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
  return payload
}

function appendHistory(persona: ResolvedPersona, values: readonly (string | undefined)[]) {
  const history = persona.secretHistory ?? (persona.secret ? [persona.secret] : [])
  for (const val of values) {
    if (val && !history.includes(val)) history.push(val)
  }
  persona.secretHistory = history
}

export function refreshPersonaSecret(persona: ResolvedPersona): string {
  if (persona.authKind === 'login') {
    refreshPersonaSession(persona)
    return persona.secret
  }
  if (!persona.secretPath) return persona.secret
  let stat: ReturnType<typeof statSync>
  try {
    stat = statSync(persona.secretPath)
  } catch {
    return persona.secret
  }
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona credential must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) return persona.secret
  if (stat.mtimeMs !== persona.secretMtimeMs || stat.ino !== persona.secretIno) {
    accessSync(persona.secretPath, constants.R_OK)
    const fresh = readFileSync(persona.secretPath, 'utf8').replace(/[\r\n]+$/, '')
    if (fresh) {
      appendHistory(persona, [persona.secret, fresh])
      persona.secret = fresh
      persona.secretMtimeMs = stat.mtimeMs
      persona.secretIno = stat.ino
    }
  }
  return persona.secret
}

export function refreshPersonaSession(persona: ResolvedPersona): MintedPersonaSession | null {
  if (persona.authKind !== 'login') return null
  if (!persona.sessionPath) return persona.session ?? null
  let stat: ReturnType<typeof statSync>
  try {
    stat = statSync(persona.sessionPath)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return persona.session ?? null
    throw err
  }
  if ((stat.mode & 0o077) !== 0) throw new Error('Persona session file must have owner-only permissions.')
  if (!stat.isFile() || stat.size === 0) return persona.session ?? null
  if (stat.mtimeMs !== persona.sessionMtimeMs || stat.ino !== persona.sessionIno || !persona.session) {
    const read = readVerifiedSessionFile(persona.sessionPath)
    if (read) {
      appendHistory(persona, [
        persona.session?.value,
        ...(persona.session?.scrubTokens ?? []),
        read.session.value,
        ...(read.session.scrubTokens ?? []),
      ])
      persona.session = read.session
      persona.sessionMtimeMs = read.mtimeMs
      persona.sessionIno = read.ino
    }
  }
  return persona.session ?? null
}

export function listProjectPersonas(storage: Store, projectId: string): PublicPersona[] {
  storage.project(projectId)
  return storage.db.select().from(personas)
    .where(and(eq(personas.projectId, projectId), eq(personas.workspaceId, storage.workspace.id)))
    .all()
    .map(({ credentialId: _omit, workspaceId: _ws, loginConfig, ...pub }) => ({
      ...pub,
      loginConfig: loginConfig ?? null,
    }))
}

export function createProjectPersona(storage: Store, input: z.output<typeof createPersona>): { id: string; handle: string } {
  return storage.operate(input, () => {
    const project = storage.project(input.projectId)
    const dir = join(storage.directory, 'credentials')
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    chmodSync(dir, 0o700)
    const credentialId = 'persona-' + randomUUID()
    const path = join(dir, credentialId)

    const canaryMarkers = [...input.canaryMarkers]
    let fileBody: string
    let storedLoginConfig: PersonaLoginConfig | null = null

    if (input.authKind === 'login') {
      if (!input.loginConfig?.email) {
        throw new Error('Email and login configuration are required for Email + Password personas.')
      }
      const email = input.loginConfig.email.trim()
      storedLoginConfig = {
        ...input.loginConfig,
        email,
      }
      if (email && !canaryMarkers.some(m => m.toLowerCase() === email.toLowerCase()) && canaryMarkers.length < 16) {
        canaryMarkers.push(email)
      }
      const payload: LoginCredentialFilePayload = {
        v: 1,
        email,
        password: input.secret,
      }
      fileBody = JSON.stringify(payload)
    } else {
      fileBody = input.secret.trim()
    }

    writeFileSync(path, fileBody, { mode: 0o600, flag: 'wx' })
    chmodSync(path, 0o600)
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
        loginConfig: storedLoginConfig,
        credentialId,
        canaryMarkers,
        createdAt: Date.now(),
      }).run()
    } catch (error) {
      try { unlinkSync(path) } catch { /* ignore */ }
      throw error
    }
    storage.event(null, 'persona.created', `Registered persona ${input.handle}.`, {
      projectId: project.id,
      personaId,
      handle: input.handle,
      authKind: input.authKind,
      adapter: storedLoginConfig?.adapter ?? null,
      origins: input.originAllowlist,
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
    const basePath = join(storage.directory, 'credentials', existing.credentialId)
    try { unlinkSync(basePath) } catch { /* ignore */ }
    try { unlinkSync(basePath + '.session') } catch { /* ignore */ }
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
    const path = join(storage.directory, 'credentials', row.credentialId)

    if (row.authKind === 'login') {
      const { password, mtimeMs, ino } = readLoginCredentialFile(path)
      const sessionPath = path + '.session'
      const sessionRead = readVerifiedSessionFile(sessionPath)
      const history: string[] = [password]
      if (sessionRead) {
        if (sessionRead.session.value && !history.includes(sessionRead.session.value)) {
          history.push(sessionRead.session.value)
        }
        for (const tok of sessionRead.session.scrubTokens ?? []) {
          if (tok && !history.includes(tok)) history.push(tok)
        }
      }
      map.set(row.handle, {
        id: row.id,
        handle: row.handle,
        roleLabel: row.roleLabel,
        originAllowlist: row.originAllowlist,
        authKind: row.authKind,
        headerName: row.headerName,
        loginConfig: row.loginConfig ?? null,
        credentialId: row.credentialId,
        secret: password,
        canaryMarkers: row.canaryMarkers,
        secretPath: path,
        secretMtimeMs: mtimeMs,
        secretIno: ino,
        secretHistory: history,
        sessionPath,
        sessionMtimeMs: sessionRead?.mtimeMs,
        sessionIno: sessionRead?.ino,
        session: sessionRead?.session ?? null,
      })
      continue
    }

    const { secret, mtimeMs, ino } = readVerifiedSecretFile(path)
    map.set(row.handle, {
      id: row.id,
      handle: row.handle,
      roleLabel: row.roleLabel,
      originAllowlist: row.originAllowlist,
      authKind: row.authKind,
      headerName: row.headerName,
      loginConfig: row.loginConfig ?? null,
      credentialId: row.credentialId,
      secret,
      canaryMarkers: row.canaryMarkers,
      secretPath: path,
      secretMtimeMs: mtimeMs,
      secretIno: ino,
      secretHistory: [secret],
    })
  }
  return map
}

export function personaSecrets(resolved: ReadonlyMap<string, ResolvedPersona>): NamedSecret[] {
  const out: NamedSecret[] = []
  const seen = new Set<string>()
  const push = (placeholder: string, value: string) => {
    if (!value || value.length < 4) return
    const key = `${placeholder}\0${value}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ value, placeholder })
  }
  for (const persona of resolved.values()) {
    try {
      if (persona.authKind === 'login') {
        refreshPersonaSession(persona)
      } else {
        refreshPersonaSecret(persona)
      }
    } catch {
      /* keep cached history if file permissions changed */
    }
    const placeholder = `[persona:${persona.handle}:secret]`
    const values = new Set<string>([
      persona.secret,
      ...(persona.secretHistory ?? []),
      ...(persona.session?.value ? [persona.session.value] : []),
      ...(persona.session?.scrubTokens ?? []),
    ])
    for (const raw of values) {
      if (!raw) continue
      push(placeholder, raw)
      // Also scrub individual cookie values >= 16 chars (e.g., rotated JWT inside "__session=<jwt>; __client_uat=...")
      if (persona.authKind === 'cookie' || persona.authKind === 'login') {
        for (const pair of raw.split(';')) {
          const eq = pair.indexOf('=')
          if (eq <= 0) continue
          const cookieVal = pair.slice(eq + 1).trim()
          if (cookieVal.length >= 16) push(placeholder, cookieVal)
        }
      }
    }
  }
  return out
}

export function buildPersonaHeader(persona: ResolvedPersona, origin: string): Record<string, string> | null {
  if (!persona.originAllowlist.includes(origin)) return null
  if (persona.authKind === 'login') {
    const session = refreshPersonaSession(persona)
    if (!session || !session.value) return null
    if (session.headerType === 'bearer') return { Authorization: 'Bearer ' + session.value }
    if (session.headerType === 'cookie') return { Cookie: session.value }
    return { [session.headerName || persona.headerName || 'X-Api-Key']: session.value }
  }
  const secret = refreshPersonaSecret(persona)
  if (persona.authKind === 'bearer') return { Authorization: 'Bearer ' + secret }
  if (persona.authKind === 'cookie') return { Cookie: secret }
  return { [persona.headerName ?? 'X-Api-Key']: secret }
}
