/**
 * Programmatic Tool Calling (PTC) host-side Unix-socket RPC bridge.
 *
 * Lets Exploiter workers execute async TypeScript snippets inside their warm `--network none`
 * container and invoke host-brokered `kovo.*` tools over a readonly `/kovo-ptc` Unix socket
 * with constant-time token auth, an op allowlist, per-exec call budget, and secret redaction.
 */
import { randomBytes } from 'node:crypto'
import {
  chmodSync, chownSync, existsSync, mkdirSync, mkdtempSync,
  readFileSync, realpathSync, statSync, unlinkSync, writeFileSync,
} from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, Server, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { redact } from './redact.ts'
import { constantTimeStringEqual } from './safety-primitives.ts'

export const PTC_CONTAINER_DIR = '/kovo-ptc'
export const PTC_SOCKET_NAME = 'ptc.sock'
export const PTC_TOKEN_NAME = 'token'
export const PTC_RPC_HEADER = 'x-kovo-rpc-token'
export const DEFAULT_PTC_MAX_CALLS_PER_EXEC = 40
export const MAX_PTC_RPC_BODY_BYTES = 256 * 1024
export const DEFAULT_PTC_CALL_TIMEOUT_MS = 60_000

export const DEFAULT_PTC_ALLOWED_OPS: ReadonlySet<string> = new Set([
  'http', 'race', 'browser', 'oob', 'probe',
  'analyze', 'searchRun', 'repo', 'recordFact', 'queryCves',
])

export type PtcDispatchFn = (op: string, args: Record<string, unknown>, signal: AbortSignal) => Promise<unknown>

export interface PtcRpcServerOptions {
  hostDir: string
  dispatch: PtcDispatchFn
  allowedOps?: ReadonlySet<string>
  maxCallsPerExec?: number
  maxBodyBytes?: number
  callTimeoutMs?: number
}

export const ptcExecRequestSchema = z.object({
  code: z.string().min(1).max(256 * 1024),
  timeoutMs: z.number().int().min(1_000).max(120_000).optional(),
  maxOutputBytes: z.number().int().min(1_024).max(256 * 1024).optional(),
})

export const ptcExecResultSchema = z.object({
  ok: z.boolean(),
  result: z.unknown(),
  stdout: z.string().max(256 * 1024),
  stderr: z.string().max(256 * 1024),
  exitCode: z.number().int(),
  durationMs: z.number().int().min(0),
  timedOut: z.boolean().optional(),
  error: z.string().optional(),
})

export type PtcExecRequest = z.input<typeof ptcExecRequestSchema>
export type PtcExecResult = z.output<typeof ptcExecResultSchema>

const SAFE_OP_RE = /^[a-zA-Z0-9._-]{1,64}$/

function resolvePtcModes() {
  const hostUid = typeof process.getuid === 'function' ? process.getuid() : -1
  const ownerOnly = hostUid === 10001 || hostUid === 0
  return {
    hostUid,
    dirMode: ownerOnly ? 0o700 : 0o750,
    fileMode: ownerOnly ? 0o600 : 0o640,
    sockMode: ownerOnly ? 0o600 : 0o660,
  }
}

function applyPtcOwnerAndMode(targetPath: string, mode: number, hostUid: number): void {
  chmodSync(targetPath, mode)
  if (hostUid === 0) {
    try { chownSync(targetPath, 10001, 10001) } catch { /* non-fatal */ }
  }
}

/** Create or harden a per-container PTC host directory for non-root container UID 10001. */
export function preparePtcHostDir(existingDir?: string): string {
  const { hostUid, dirMode } = resolvePtcModes()
  let targetDir: string
  if (existingDir) {
    if (/[\0,\r\n]/.test(existingDir)) throw new Error('Invalid PTC mount directory path.')
    mkdirSync(existingDir, { recursive: true, mode: dirMode })
    targetDir = realpathSync(existingDir)
  } else {
    const base = existsSync('/dev/shm') ? '/dev/shm' : tmpdir()
    let raw: string
    try { raw = mkdtempSync(join(base, 'kovo-ptc-')) } catch { raw = mkdtempSync(join(tmpdir(), 'kovo-ptc-')) }
    targetDir = realpathSync(raw)
  }
  applyPtcOwnerAndMode(targetDir, dirMode, hostUid)
  return targetDir
}

/** Read `worker/ptc_client.ts` from disk so SDK updates require no container image rebuild. */
export function readPtcClientSource(clientPath?: string): string {
  const resolved = clientPath
    ?? process.env.KOVO_PTC_CLIENT_PATH
    ?? join(dirname(fileURLToPath(import.meta.url)), '../../worker/ptc_client.ts')
  if (!existsSync(resolved)) throw new Error('PTC client SDK file is unavailable on this host.')
  if (statSync(resolved).size > 256 * 1024) throw new Error('PTC client SDK file exceeds 256 KiB limit.')
  return readFileSync(resolved, 'utf8')
}

export class PtcRpcServer {
  private readonly hostDirValue: string
  private readonly dispatch: PtcDispatchFn
  private readonly allowedOps: ReadonlySet<string>
  private readonly maxCallsPerExecValue: number
  private readonly maxBodyBytes: number
  private readonly callTimeoutMs: number
  private readonly socketPathValue: string
  private readonly tokenPathValue: string
  private server: Server | null = null
  private serverAbort = new AbortController()
  private tokenValue = ''
  private callsUsedValue = 0
  private started = false

  constructor(options: PtcRpcServerOptions) {
    if (!options.hostDir || /[\0,\r\n]/.test(options.hostDir)) {
      throw new Error('PtcRpcServer requires a valid hostDir.')
    }
    this.hostDirValue = options.hostDir
    this.dispatch = options.dispatch
    this.allowedOps = options.allowedOps ?? DEFAULT_PTC_ALLOWED_OPS
    const maxCalls = options.maxCallsPerExec ?? DEFAULT_PTC_MAX_CALLS_PER_EXEC
    this.maxCallsPerExecValue = Math.max(1, Math.floor(Number.isFinite(maxCalls) ? maxCalls : DEFAULT_PTC_MAX_CALLS_PER_EXEC))
    const maxBody = options.maxBodyBytes ?? MAX_PTC_RPC_BODY_BYTES
    this.maxBodyBytes = Math.max(1024, Math.min(Math.floor(Number.isFinite(maxBody) ? maxBody : MAX_PTC_RPC_BODY_BYTES), MAX_PTC_RPC_BODY_BYTES))
    const timeout = options.callTimeoutMs ?? DEFAULT_PTC_CALL_TIMEOUT_MS
    this.callTimeoutMs = Math.max(100, Math.min(Math.floor(Number.isFinite(timeout) ? timeout : DEFAULT_PTC_CALL_TIMEOUT_MS), 120_000))
    this.socketPathValue = join(this.hostDirValue, PTC_SOCKET_NAME)
    this.tokenPathValue = join(this.hostDirValue, PTC_TOKEN_NAME)
  }

  get hostDir(): string { return this.hostDirValue }
  get socketPath(): string { return this.socketPathValue }
  get tokenPath(): string { return this.tokenPathValue }
  get callsUsed(): number { return this.callsUsedValue }
  get maxCallsPerExec(): number { return this.maxCallsPerExecValue }

  async start(): Promise<this> {
    if (this.started) return this
    const { hostUid, dirMode, fileMode, sockMode } = resolvePtcModes()
    mkdirSync(this.hostDirValue, { recursive: true, mode: dirMode })
    applyPtcOwnerAndMode(this.hostDirValue, dirMode, hostUid)
    if (existsSync(this.socketPathValue)) {
      try { unlinkSync(this.socketPathValue) } catch { /* ignore stale socket */ }
    }
    this.tokenValue = randomBytes(32).toString('hex')
    writeFileSync(this.tokenPathValue, this.tokenValue + '\n', { mode: fileMode })
    applyPtcOwnerAndMode(this.tokenPathValue, fileMode, hostUid)
    this.serverAbort = new AbortController()
    const srv = createServer((req, res) => { void this.handleRequest(req, res) })
    srv.on('clientError', (_err, socket) => { try { socket.destroy() } catch { /* ignore */ } })
    await new Promise<void>((resolveListen, rejectListen) => {
      const onError = (err: Error) => { srv.off('listening', onListening); rejectListen(err) }
      const onListening = () => { srv.off('error', onError); resolveListen() }
      srv.once('error', onError)
      srv.once('listening', onListening)
      srv.listen(this.socketPathValue)
    })
    applyPtcOwnerAndMode(this.socketPathValue, sockMode, hostUid)
    this.server = srv
    this.started = true
    return this
  }

  resetCallBudget(): void { this.callsUsedValue = 0 }

  async close(): Promise<void> {
    const srv = this.server
    this.server = null
    this.started = false
    this.serverAbort.abort(new Error('PTC RPC server closed.'))
    if (srv) {
      srv.closeAllConnections?.()
      await new Promise<void>(resolveClose => srv.close(() => resolveClose()))
    }
    for (const artifact of [this.socketPathValue, this.tokenPathValue]) {
      try { unlinkSync(artifact) } catch { /* ignore missing */ }
    }
    this.tokenValue = ''
  }

  private scrubError(raw: unknown): string {
    const text = raw instanceof Error ? raw.message : typeof raw === 'string' ? raw : 'PTC RPC call failed.'
    const secrets = this.tokenValue ? [{ value: this.tokenValue, placeholder: '[redacted-ptc-token]' }] : []
    return redact(text, secrets).slice(0, 600)
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const reply = (status: number, body: unknown) => {
      if (res.writableEnded) return
      const json = JSON.stringify(body)
      res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(json) })
      res.end(json)
    }
    if (req.method !== 'POST' || (req.url ?? '') !== '/rpc') return reply(404, { ok: false, error: 'Unknown PTC RPC endpoint.' })
    const provided = typeof req.headers[PTC_RPC_HEADER] === 'string' ? req.headers[PTC_RPC_HEADER].trim() : ''
    if (!this.tokenValue || !constantTimeStringEqual(provided, this.tokenValue)) {
      return reply(401, { ok: false, error: 'Unauthorized PTC RPC token.' })
    }
    const chunks: Buffer[] = []
    let bodyBytes = 0
    try {
      for await (const chunk of req) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        bodyBytes += buf.length
        if (bodyBytes > this.maxBodyBytes) return reply(413, { ok: false, error: 'PTC RPC request body exceeds limit.' })
        chunks.push(buf)
      }
    } catch {
      return reply(400, { ok: false, error: 'PTC RPC request body could not be read.' })
    }
    let parsed: unknown
    try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch {
      return reply(400, { ok: false, error: 'Invalid JSON request body.' })
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return reply(400, { ok: false, error: 'PTC RPC payload must be a JSON object.' })
    }
    const record = parsed as Record<string, unknown>
    const op = typeof record.op === 'string' ? record.op.trim() : ''
    if (!op || !this.allowedOps.has(op)) {
      return reply(403, { ok: false, error: `Disallowed PTC RPC operation: ${SAFE_OP_RE.test(op) ? op : '<invalid>'}` })
    }
    if (record.args !== undefined && (!record.args || typeof record.args !== 'object' || Array.isArray(record.args))) {
      return reply(400, { ok: false, error: 'PTC RPC args must be a JSON object.' })
    }
    if (this.callsUsedValue >= this.maxCallsPerExecValue) {
      return reply(429, { ok: false, error: `PTC RPC call budget exceeded (${this.maxCallsPerExecValue} max calls per execution).` })
    }
    this.callsUsedValue += 1
    const callAbort = new AbortController()
    const onServerAbort = () => callAbort.abort(this.serverAbort.signal.reason)
    const onClose = () => { if (!res.writableEnded) callAbort.abort(new Error('PTC RPC client disconnected.')) }
    this.serverAbort.signal.addEventListener('abort', onServerAbort, { once: true })
    res.once('close', onClose)
    const timer = setTimeout(() => callAbort.abort(new Error('PTC RPC call timed out.')), this.callTimeoutMs)
    timer.unref?.()
    try {
      const result = await this.dispatch(op, (record.args as Record<string, unknown> | undefined) ?? {}, callAbort.signal)
      return reply(200, { ok: true, result })
    } catch (error) {
      return reply(200, { ok: false, error: this.scrubError(error) })
    } finally {
      clearTimeout(timer)
      this.serverAbort.signal.removeEventListener('abort', onServerAbort)
      res.off('close', onClose)
    }
  }
}
