import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { asc, eq } from 'drizzle-orm'
import { isLocalLabEnvEnabled } from '../domain.ts'
import type { RequestBroker } from './broker.ts'
import { listMountedRepos, projectReposDir } from './github-connector.ts'
import { PersonaAuthManager } from './persona-auth.ts'
import { personaSecrets, refreshPersonaSession, resolveRunPersonas } from './persona-vault.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import * as tables from './schema.ts'
import type { Store } from './store.ts'

export interface WorkerSessionToolCall {
  id: string
  name: string
  argsPreview: string
  status: 'ok' | 'error' | 'finding' | 'pending'
  durationMs?: number
  resultPreview?: string
}

export interface WorkerSessionTurn {
  turn: number
  timestamp?: number
  durationMs?: number
  thinking?: string
  text?: string
  tools: WorkerSessionToolCall[]
}

export interface WorkerShellArtifact {
  id: string
  kind: string
  title: string
  createdAt: number
  command?: string
  exitStatus?: number
  stdout?: string
  stderr?: string
  preview?: string
}

export interface WorkerSessionData {
  workerId: string
  sessionId: string
  turns: WorkerSessionTurn[]
  artifacts: WorkerShellArtifact[]
}

function summarizeArgs(args: unknown, secrets: readonly NamedSecret[]): string {
  if (args == null) return ''
  if (typeof args === 'string') return redact(args, secrets).slice(0, 320)
  if (typeof args === 'object' && !Array.isArray(args)) {
    const rec = args as Record<string, unknown>
    if (typeof rec.command === 'string') return redact(rec.command, secrets).slice(0, 320)
    if (typeof rec.method === 'string' && typeof rec.origin === 'string') {
      const path = typeof rec.pathAndQuery === 'string' ? rec.pathAndQuery : '/'
      const persona = typeof rec.persona === 'string' ? ` [persona:${rec.persona}]` : ''
      return redact(`${rec.method} ${rec.origin}${path}${persona}`, secrets).slice(0, 320)
    }
    if (typeof rec.title === 'string') {
      const sev = typeof rec.severity === 'string' ? ` severity=${rec.severity}` : ''
      return redact(`title="${rec.title}"${sev}`, secrets).slice(0, 320)
    }
    if (typeof rec.kind === 'string' && typeof rec.origin === 'string') {
      return redact(`kind=${rec.kind} origin=${rec.origin}`, secrets).slice(0, 320)
    }
    if (typeof rec.name === 'string') {
      return redact(`name=${rec.name}`, secrets).slice(0, 320)
    }
    try {
      return redact(JSON.stringify(rec), secrets).slice(0, 320)
    } catch {
      return ''
    }
  }
  return redact(String(args), secrets).slice(0, 320)
}

function extractResultText(content: unknown, secrets: readonly NamedSecret[]): string {
  if (typeof content === 'string') return redact(content, secrets).slice(0, 1200)
  if (Array.isArray(content)) {
    const joined = content
      .map(part => {
        if (typeof part === 'string') return part
        if (part && typeof part === 'object' && typeof (part as { text?: unknown }).text === 'string') {
          return (part as { text: string }).text
        }
        return ''
      })
      .filter(Boolean)
      .join('\n')
    return redact(joined, secrets).slice(0, 1200)
  }
  return ''
}

export function readWorkerSession(storage: Store, runId: string, workerId: string): WorkerSessionData {
  const run = storage.run(runId)
  const assignment = storage.db
    .select()
    .from(tables.assignments)
    .where(eq(tables.assignments.id, workerId))
    .get()
  if (!assignment || assignment.runId !== run.id) {
    throw new Error('Worker assignment not found.')
  }

  let secrets: NamedSecret[] = []
  try {
    const resolved = resolveRunPersonas(storage, run.projectId, run.approvedPersonaIds)
    secrets = personaSecrets(resolved)
  } catch {
    secrets = []
  }

  const turns: WorkerSessionTurn[] = []
  const sessionPath = join(storage.directory, 'agent-sessions', `${assignment.sessionId}.sqlite`)
  if (existsSync(sessionPath)) {
    let sessionDb: DatabaseSync | undefined
    try {
      sessionDb = new DatabaseSync(sessionPath, { readOnly: true })
      const rows = sessionDb
        .prepare('SELECT id, commit_seq, record FROM entries ORDER BY commit_seq ASC')
        .all() as Array<{ id: number; commit_seq: number; record: string }>

      const toolByCallId = new Map<string, WorkerSessionToolCall>()
      let turnNo = 0

      for (const row of rows) {
        let parsed: { model?: Array<Record<string, unknown>> } | null = null
        try {
          parsed = JSON.parse(row.record) as { model?: Array<Record<string, unknown>> }
        } catch {
          continue
        }
        const models = Array.isArray(parsed?.model) ? parsed.model : []
        for (const msg of models) {
          if (msg.role === 'assistant') {
            turnNo += 1
            const content = Array.isArray(msg.content) ? (msg.content as Array<Record<string, unknown>>) : []
            const thinkingParts: string[] = []
            const textParts: string[] = []
            const tools: WorkerSessionToolCall[] = []

            for (const block of content) {
              if (block.type === 'thinking' && typeof block.thinking === 'string' && block.thinking.trim()) {
                thinkingParts.push(redact(block.thinking.trim(), secrets))
              } else if (block.type === 'text' && typeof block.text === 'string' && block.text.trim()) {
                textParts.push(redact(block.text.trim(), secrets))
              } else if (block.type === 'toolCall' && typeof block.name === 'string') {
                const callId = typeof block.id === 'string' ? block.id : `tc-${turnNo}-${tools.length}`
                const tc: WorkerSessionToolCall = {
                  id: callId,
                  name: block.name,
                  argsPreview: summarizeArgs(block.arguments, secrets),
                  status: block.name === 'propose_chain_finding' ? 'finding' : 'pending',
                }
                tools.push(tc)
                toolByCallId.set(callId, tc)
              }
            }

            if (thinkingParts.length || textParts.length || tools.length) {
              turns.push({
                turn: turnNo,
                timestamp: typeof msg.timestamp === 'number' ? msg.timestamp : undefined,
                durationMs: typeof msg.durationMs === 'number' ? msg.durationMs : undefined,
                thinking: thinkingParts.length ? thinkingParts.join('\n').slice(0, 1400) : undefined,
                text: textParts.length ? textParts.join('\n').slice(0, 1400) : undefined,
                tools,
              })
            }
          } else if (msg.role === 'toolResult') {
            const callId = typeof msg.toolCallId === 'string' ? msg.toolCallId : ''
            const target = toolByCallId.get(callId)
            if (target) {
              const isErr = Boolean(msg.isError)
              if (isErr) target.status = 'error'
              else if (target.name !== 'propose_chain_finding') target.status = 'ok'
              if (typeof msg.durationMs === 'number') target.durationMs = msg.durationMs
              const preview = extractResultText(msg.content, secrets)
              if (preview) target.resultPreview = preview.slice(0, 600)
            }
          }
        }
      }
    } catch {
      // Fall back gracefully if session sqlite is locked or mid-write.
    } finally {
      try { sessionDb?.close() } catch { /* ignore */ }
    }
  }

  const evidenceRows = storage.db
    .select()
    .from(tables.evidence)
    .where(eq(tables.evidence.assignmentId, assignment.id))
    .orderBy(asc(tables.evidence.createdAt))
    .all()

  const artifacts: WorkerShellArtifact[] = []
  for (const ev of evidenceRows) {
    if (ev.operationId === 'assignment') continue
    let raw = ''
    try {
      raw = storage.artifact(run.id, ev.id).content
    } catch {
      raw = ''
    }
    const clean = redact(raw, secrets)
    let command: string | undefined
    let exitStatus: number | undefined
    let stdout: string | undefined
    let stderr: string | undefined
    if (clean.trim().startsWith('{')) {
      try {
        const obj = JSON.parse(clean) as Record<string, unknown>
        if (typeof obj.command === 'string') command = redact(obj.command, secrets)
        if (typeof obj.exitStatus === 'number') exitStatus = obj.exitStatus
        else if (typeof obj.exitCode === 'number') exitStatus = obj.exitCode
        if (typeof obj.stdout === 'string') stdout = redact(obj.stdout, secrets).slice(0, 4000)
        if (typeof obj.stderr === 'string' && obj.stderr.trim()) stderr = redact(obj.stderr, secrets).slice(0, 1500)
      } catch {
        // Non-JSON artifact; use preview fallback below.
      }
    }
    artifacts.push({
      id: ev.id,
      kind: ev.kind,
      title: ev.title,
      createdAt: ev.createdAt,
      command,
      exitStatus,
      stdout,
      stderr,
      preview: command ? undefined : clean.slice(0, 2400),
    })
  }

  return {
    workerId: assignment.id,
    sessionId: assignment.sessionId,
    turns,
    artifacts,
  }
}

/**
 * Resolve the primary synced repository directory (`<dataDir>/repos/<projectId>/<owner>/<repo>`)
 * for local-lab execution, honoring an optional `labConfig.repo` selector and falling back to
 * `<dataDir>/repos/<projectId>` when no synced `<owner>/<repo>` directory exists.
 */
export function resolvePrimaryLabRepoDir(dataDir: string, projectId: string, preferredRepo?: string): string {
  const baseDir = projectReposDir(dataDir, projectId)
  const mountedRepos = listMountedRepos(baseDir)
  if (!mountedRepos.length) return baseDir

  const normalizedWanted = preferredRepo?.trim().replace(/^\/?repos\//, '').replace(/^\/+|\/+$/g, '')
  if (normalizedWanted) {
    const wantedLower = normalizedWanted.toLowerCase()
    const exact = mountedRepos.find(m => m.replace(/^\/repos\//, '').toLowerCase() === wantedLower)
    if (exact) return join(baseDir, exact.replace(/^\/repos\//, ''))
    const byRepoName = mountedRepos.find(m => m.replace(/^\/repos\//, '').toLowerCase().endsWith(`/${wantedLower}`))
    if (byRepoName) return join(baseDir, byRepoName.replace(/^\/repos\//, ''))
  }

  const primaryRel = mountedRepos[0]!.replace(/^\/repos\//, '')
  return primaryRel ? join(baseDir, primaryRel) : baseDir
}

function lowercaseHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = v
  }
  return out
}

function normalizeBodyForAuthDiff(body: string): string {
  return body
    .replace(/\bnonce=["'][^"']{4,128}["']/gi, 'nonce="[norm]"')
    .replace(/\bcsrf[-_]?token["']?\s*[:=]\s*["'][^"']{4,128}["']/gi, 'csrf="[norm]"')
    .replace(/\s+/g, ' ')
    .trim()
}

function resolveSameOriginRedirectPath(origin: string, location: string): string | null {
  try {
    const resolved = new URL(location, origin)
    if (resolved.origin !== origin) return null
    return `${resolved.pathname}${resolved.search}`
  } catch {
    return null
  }
}

export async function testPersonaAuth(
  storage: Store,
  broker: RequestBroker,
  input: { projectId: string; personaId: string; origin?: string; path?: string },
  personaAuth?: PersonaAuthManager,
): Promise<{
  ok: boolean
  inconclusive?: boolean
  origin: string
  path: string
  status: number
  durationMs: number
  authHint: string
}> {
  const project = storage.project(input.projectId)
  const resolved = resolveRunPersonas(storage, project.id, [input.personaId])
  const persona = [...resolved.values()][0]
  if (!persona) throw new Error('Persona not found.')

  const origin = input.origin && persona.originAllowlist.includes(input.origin)
    ? input.origin
    : persona.originAllowlist[0]
  if (!origin) throw new Error('Persona has no allowlisted origin configured.')

  const initialPath = input.path && input.path.startsWith('/') && !input.path.startsWith('//')
    ? input.path.slice(0, 256)
    : '/'

  // Playwright / browser-form logins need more than 20 s for launch, hydration, and redirect.
  const timeoutMs = persona.authKind === 'login' ? 60_000 : 20_000
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    let loginAdapterHint: string | null = null
    if (persona.authKind === 'login') {
      const authManager = personaAuth ?? new PersonaAuthManager()
      try {
        const authRes = await authManager.authenticatePersona(storage, project.id, persona.id, controller.signal)
        refreshPersonaSession(persona)
        if (authRes.adapterUsed === 'clerk') {
          loginAdapterHint = `Clerk (auto-refresh ${authRes.refreshIntervalSec ?? 35}s)`
        } else if (authRes.adapterUsed === 'supabase') {
          loginAdapterHint = 'Supabase Auth'
        } else if (authRes.adapterUsed === 'json') {
          loginAdapterHint = 'JSON API'
        } else {
          loginAdapterHint = 'Browser Form'
        }
      } catch (err) {
        const safeSecrets = personaSecrets(resolved)
        const safeMsg = redact(err instanceof Error ? err.message : String(err), safeSecrets)
        throw new Error(safeMsg)
      }
    }

    const secrets = personaSecrets(resolved)
    const grant = {
      origin,
      tier: 2 as const,
      maxRpsPerOrigin: 6,
      allowLocalLab: project.environment === 'local-lab' && isLocalLabEnvEnabled(),
      personas: resolved,
      secrets,
      canRead: (target: string) => persona.originAllowlist.includes(target),
      audit: () => { /* health check only */ },
    }

    const firstAuthRes = await broker.executeHttp(
      {
        origin,
        method: 'GET',
        pathAndQuery: initialPath,
        persona: persona.handle,
        followRedirects: false,
      },
      grant,
      controller.signal,
    )

    let res = firstAuthRes
    let effectivePath = initialPath
    let authRedirectPath: string | null = null
    let totalDurationMs = firstAuthRes.durationMs
    let headersLower = lowercaseHeaders(res.respHeaders)

    // Follow at most 1 same-origin redirect (e.g. GET / -> 302 /dashboard).
    if (res.status >= 300 && res.status < 400 && headersLower['location']) {
      const sameOriginNext = resolveSameOriginRedirectPath(origin, headersLower['location'])
      if (sameOriginNext && sameOriginNext !== initialPath) {
        authRedirectPath = sameOriginNext
        effectivePath = sameOriginNext
        const hopped = await broker.executeHttp(
          {
            origin,
            method: 'GET',
            pathAndQuery: sameOriginNext,
            persona: persona.handle,
            followRedirects: false,
          },
          grant,
          controller.signal,
        )
        res = hopped
        totalDurationMs += hopped.durationMs
        headersLower = lowercaseHeaders(res.respHeaders)
      }
    }

    const hints: string[] = []
    if (authRedirectPath) {
      hints.push(`redirect -> ${redact(authRedirectPath, secrets).slice(0, 80)}`)
    }
    if (headersLower['x-clerk-auth-status']) {
      hints.push(redact(headersLower['x-clerk-auth-status'], secrets))
    }
    if (headersLower['x-clerk-auth-reason']) {
      hints.push(`reason: ${redact(headersLower['x-clerk-auth-reason'], secrets)}`)
    }
    if (headersLower['www-authenticate']) {
      hints.push(`www-authenticate: ${redact(headersLower['www-authenticate'], secrets).slice(0, 60)}`)
    }
    if (res.status >= 300 && res.status < 400 && headersLower['location']) {
      hints.push(`redirect -> ${redact(headersLower['location'], secrets).slice(0, 80)}`)
    }

    const explicitClerkSignedIn = headersLower['x-clerk-auth-status'] === 'signed-in'
    const explicitClerkSignedOut = headersLower['x-clerk-auth-status'] === 'signed-out'
    let ok = res.status >= 200 && res.status < 300 && !explicitClerkSignedOut
    let inconclusive = false

    // Diff authenticated vs anonymous GET so identical public 200 SPA shells are flagged
    // inconclusive instead of returning a false-green sign-in verification.
    if (ok && !explicitClerkSignedIn) {
      try {
        const firstAnonRes = await broker.executeHttp(
          {
            origin,
            method: 'GET',
            pathAndQuery: initialPath,
            followRedirects: false,
          },
          grant,
          controller.signal,
        )
        let anonRes = firstAnonRes
        let anonHeadersLower = lowercaseHeaders(anonRes.respHeaders)
        let anonRedirectPath: string | null = null

        if (anonRes.status >= 300 && anonRes.status < 400 && anonHeadersLower['location']) {
          const anonSameOriginNext = resolveSameOriginRedirectPath(origin, anonHeadersLower['location'])
          if (anonSameOriginNext) {
            anonRedirectPath = anonSameOriginNext
            if (anonSameOriginNext === authRedirectPath) {
              anonRes = await broker.executeHttp(
                {
                  origin,
                  method: 'GET',
                  pathAndQuery: anonSameOriginNext,
                  followRedirects: false,
                },
                grant,
                controller.signal,
              )
              anonHeadersLower = lowercaseHeaders(anonRes.respHeaders)
            }
          }
        }

        const redirectDiverged = authRedirectPath !== anonRedirectPath
        const statusDiverged = res.status !== anonRes.status
        const bodyIdentical =
          !redirectDiverged &&
          !statusDiverged &&
          (res.bodySha256 === anonRes.bodySha256 ||
            normalizeBodyForAuthDiff(res.body) === normalizeBodyForAuthDiff(anonRes.body))

        if (bodyIdentical) {
          ok = false
          inconclusive = true
          hints.push(
            `Inconclusive: authenticated and anonymous GET ${effectivePath} returned identical HTTP ${res.status} (${res.mediaType || 'response'}) — test against a protected path such as /api/me or /dashboard`,
          )
        } else if (statusDiverged) {
          hints.push(`diff vs anonymous (HTTP ${anonRes.status})`)
        } else if (redirectDiverged) {
          hints.push(
            anonRedirectPath
              ? `diff vs anonymous (redirect -> ${redact(anonRedirectPath, secrets).slice(0, 60)})`
              : `diff vs anonymous (HTTP ${anonRes.status} on ${initialPath})`,
          )
        } else {
          hints.push(loginAdapterHint ? 'signed-in (differs from anonymous)' : `Authenticated GET differs from anonymous (${res.mediaType || 'ok'})`)
        }
      } catch {
        // Anonymous comparison failed (e.g. transient error); fall back to authenticated response alone.
      }
    }

    if (!hints.length) {
      if (res.status >= 200 && res.status < 300) {
        hints.push(loginAdapterHint ? 'signed-in' : `Authenticated GET accepted (${res.mediaType || 'ok'})`)
      } else if (res.status === 401 || res.status === 403) {
        hints.push('Rejected with auth error — verify credentials or session freshness')
      } else {
        hints.push(`HTTP ${res.status} (${res.mediaType || 'response'})`)
      }
    }
    if (loginAdapterHint) {
      hints.push(loginAdapterHint)
    }

    return {
      ok,
      ...(inconclusive ? { inconclusive: true } : {}),
      origin,
      path: effectivePath,
      status: res.status,
      durationMs: totalDurationMs,
      authHint: redact(hints.join(' · '), secrets),
    }
  } finally {
    clearTimeout(timeout)
  }
}
