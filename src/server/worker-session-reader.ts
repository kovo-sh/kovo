import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { asc, eq } from 'drizzle-orm'
import { isLocalLabEnvEnabled } from '../domain.ts'
import type { RequestBroker } from './broker.ts'
import { personaSecrets, resolveRunPersonas } from './persona-vault.ts'
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

export async function testPersonaAuth(
  storage: Store,
  broker: RequestBroker,
  input: { projectId: string; personaId: string; origin?: string; path?: string },
): Promise<{
  ok: boolean
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

  const path = input.path && input.path.startsWith('/') && !input.path.startsWith('//')
    ? input.path.slice(0, 256)
    : '/'

  const secrets = personaSecrets(resolved)
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 12_000)
  try {
    const res = await broker.executeHttp(
      {
        origin,
        method: 'GET',
        pathAndQuery: path,
        persona: persona.handle,
        followRedirects: false,
      },
      {
        origin,
        tier: 2,
        maxRpsPerOrigin: 2,
        allowLocalLab: project.environment === 'local-lab' && isLocalLabEnvEnabled(),
        personas: resolved,
        secrets,
        canRead: target => persona.originAllowlist.includes(target),
        audit: () => { /* health check only */ },
      },
      controller.signal,
    )

    const headersLower: Record<string, string> = {}
    for (const [k, v] of Object.entries(res.respHeaders)) {
      headersLower[k.toLowerCase()] = v
    }

    const hints: string[] = []
    if (headersLower['x-clerk-auth-status']) {
      hints.push(`x-clerk-auth-status: ${redact(headersLower['x-clerk-auth-status'], secrets)}`)
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
    if (!hints.length) {
      if (res.status >= 200 && res.status < 300) {
        hints.push(`Authenticated GET accepted (${res.mediaType || 'ok'})`)
      } else if (res.status === 401 || res.status === 403) {
        hints.push('Rejected with auth error — verify cookie/token freshness')
      } else {
        hints.push(`HTTP ${res.status} (${res.mediaType || 'response'})`)
      }
    }

    const ok = res.status >= 200 && res.status < 300 &&
      headersLower['x-clerk-auth-status'] !== 'signed-out'

    return {
      ok,
      origin,
      path,
      status: res.status,
      durationMs: res.durationMs,
      authHint: redact(hints.join(' · '), secrets),
    }
  } finally {
    clearTimeout(timeout)
  }
}
