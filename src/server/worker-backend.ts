import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs'
import { basename, dirname, join, relative, sep } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import type { AnalyzerName } from '../../worker/analyzers.ts'
import {
  VERIFY_RPC_CONTAINER_DIR,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_ENV,
  VERIFY_RPC_TOKEN_NAME,
  prepareVerifyScript,
} from './verify-rpc.ts'

const pathSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}(?:\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}){0,3}$/)
const outputNameSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/)
const repoIdentifierSchema = z.string().refine(
  v => v === '.' || (/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}(?:\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}){0,3}$/.test(v) && !v.split('/').includes('..')),
  'Invalid repository identifier.',
)
const repoRelativePathSchema = z.string().min(1).max(512).refine(
  v => !v.startsWith('/') && !v.startsWith('\\') && !/[\0\r\n]/.test(v) && !v.split(/[\\/]+/).includes('..'),
  'Invalid repository-relative path.',
)
const workerNamespace = 'dev.guardian.workspace'
// Attribution labels: a leaked container must identify its run/assignment/session.
const runNamespace = 'dev.guardian.run'
const assignmentNamespace = 'dev.guardian.assignment'
const sessionNamespace = 'dev.guardian.session'
const createdAtNamespace = 'dev.guardian.created-at'
/** Matrix cells label every container so the cell reaper can remove exactly its own. */
const cellNamespace = 'dev.guardian.cell'
const warmNamespace = 'dev.guardian.warm'
/** A container may legitimately sit in `created` only for the create→start instant. */
const DEFAULT_STALE_CREATED_MS = 120_000
const processSessionId = randomUUID()
const liveContainers = new Set<string>()
const liveStagedRepoDirs = new Set<string>()
/** Process-scoped label value carried by every worker container (test/diagnostic seam). */
export function workerProcessSessionId() {
  return processSessionId
}
let liveExitHookInstalled = false
function removeLiveStagedRepoDirs() {
  for (const dir of [...liveStagedRepoDirs]) {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* best-effort */ }
    liveStagedRepoDirs.delete(dir)
  }
}
function removeLiveContainers(budgetMs = 4_000) {
  const deadline = Date.now() + budgetMs
  for (const container of [...liveContainers]) {
    const remaining = deadline - Date.now()
    if (remaining <= 0) break
    try { spawnSync('docker', ['container', 'rm', '--force', container], { stdio: 'ignore', timeout: Math.min(5_000, remaining) }) } catch { /* best-effort */ }
    liveContainers.delete(container)
  }
  removeLiveStagedRepoDirs()
}
export interface LiveExitHookTarget {
  once(event: 'exit', listener: () => void): unknown
  prependOnceListener(event: 'SIGTERM' | 'SIGINT', listener: () => void): unknown
  listenerCount(event: 'SIGTERM' | 'SIGINT'): number
  removeListener(event: 'exit' | 'SIGTERM' | 'SIGINT', listener: () => void): unknown
}

export interface LiveExitHookOptions {
  /** Container/tempdir cleanup callback (defaults to `removeLiveContainers`). */
  cleanup?: (budgetMs: number) => void
  /** Terminal exit callback used ONLY when no sibling signal listener remains (defaults to `process.exit`). */
  exit?: (code: number) => void
  /** Signal emitter target (defaults to `process`). */
  target?: LiveExitHookTarget
}

export interface InstalledLiveExitHooks {
  dispose(): void
}

/** Explicit shutdown-coordinator hook to reap tracked worker containers & staged repo dirs. */
export function cleanupLiveWorkerResources(budgetMs = 2_000): void {
  removeLiveContainers(budgetMs)
}

/**
 * Install bounded container/tempdir cleanup hooks on `exit`, `SIGTERM`, and `SIGINT`.
 *
 * Uses `prependOnceListener` on signals and only terminates the process when no other sibling
 * listener remains registered for that signal, so graceful HTTP server, SQLite WAL, and LabRunner
 * shutdown handlers always run without preemption.
 */
export function installLiveExitHooks(options: LiveExitHookOptions = {}): InstalledLiveExitHooks {
  const cleanup = options.cleanup ?? removeLiveContainers
  const exit = options.exit ?? (code => process.exit(code))
  const target = options.target ?? process

  const onExit = () => cleanup(1_500)
  const makeSignalHandler = (signal: 'SIGTERM' | 'SIGINT', exitCode: number) => () => {
    cleanup(2_000)
    if (target.listenerCount(signal) === 0) {
      exit(exitCode)
    }
  }
  const onSigterm = makeSignalHandler('SIGTERM', 143)
  const onSigint = makeSignalHandler('SIGINT', 130)

  target.once('exit', onExit)
  target.prependOnceListener('SIGTERM', onSigterm)
  target.prependOnceListener('SIGINT', onSigint)

  return {
    dispose() {
      target.removeListener('exit', onExit)
      target.removeListener('SIGTERM', onSigterm)
      target.removeListener('SIGINT', onSigint)
    },
  }
}

function ensureLiveExitHooks() {
  if (liveExitHookInstalled) return
  liveExitHookInstalled = true
  // Remove any container this process created but did not get to start/close
  // (for example an aborted session between `docker create` and `docker start`,
  // or a Playwright-owned server terminated with SIGTERM). Shutdown cleanup is strictly bounded so
  // a slow/unreachable Docker daemon can never block process exit (and E2E teardown).
  installLiveExitHooks()
}
function trackLiveContainer(name: string) {
  liveContainers.add(name)
  ensureLiveExitHooks()
}
function trackLiveStagedRepoDir(dir: string) {
  liveStagedRepoDirs.add(dir)
  ensureLiveExitHooks()
}
const workerName = /^guardian-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/

const jobSchema = z.object({
  assignmentId: z.uuid(),
  files: z.array(z.object({ name: pathSchema, content: z.string().max(2 * 1024 * 1024) })).max(128),
  command: z.string().min(1).max(16 * 1024),
  outputs: z.array(outputNameSchema).max(16),
  timeoutMs: z.number().int().min(1_000).max(120_000).optional(),
})

const resultSchema = z.object({
  exitCode: z.number().int(),
  stdout: z.string().max(256 * 1024),
  stderr: z.string().max(256 * 1024),
  outputs: z.record(outputNameSchema, z.string().max(256 * 1024)),
  timedOut: z.boolean().optional(),
})

export const sastEngineSchema = z.enum(['opengrep', 'ast-grep', 'gitleaks', 'trufflehog', 'trivy-fs', 'bandit'])
export const sastSeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info'])

export const sastFindingSchema = z.object({
  engine: sastEngineSchema,
  ruleId: z.string().min(1).max(256),
  severity: sastSeveritySchema,
  file: z.string().max(512),
  line: z.number().int().min(0),
  endLine: z.number().int().min(0).optional(),
  message: z.string().max(1024),
  maskedPreview: z.string().max(1024),
  cwe: z.string().max(32).optional(),
})

export const sastScanRequestSchema = z.object({
  repo: repoIdentifierSchema,
  engines: z.array(sastEngineSchema).min(1).max(6),
  paths: z.array(repoRelativePathSchema).max(32).optional(),
  ruleFilter: z.string().min(1).max(128).optional(),
  timeoutMs: z.number().int().min(5_000).max(120_000).optional(),
})

export const sastScanResultSchema = z.object({
  repo: z.string(),
  enginesRun: z.array(sastEngineSchema),
  engineStatus: z.record(z.string(), z.object({
    ok: z.boolean(),
    count: z.number().int().min(0),
    durationMs: z.number().int().min(0),
    toolVersion: z.string().optional(),
    note: z.string().optional(),
  })),
  findings: z.array(sastFindingSchema),
  totalFindings: z.number().int().min(0),
  truncated: z.boolean(),
  evidencePath: z.string().optional(),
  durationMs: z.number().int().min(0),
})

export const offlineScriptRequestSchema = z.object({
  runtime: z.enum(['python', 'node']),
  code: z.string().min(1).max(256 * 1024),
  timeoutMs: z.number().int().min(1_000).max(60_000).optional(),
})

export const offlineScriptResultSchema = z.object({
  runtime: z.enum(['python', 'node']),
  exitCode: z.number().int(),
  stdout: z.string().max(256 * 1024),
  stderr: z.string().max(256 * 1024),
  durationMs: z.number().int().min(0),
  timedOut: z.boolean(),
})

export const verifyScriptRequestSchema = z.object({
  runtime: z.enum(['ts', 'python']),
  code: z.string().min(1).max(256 * 1024),
  nonce: z.string().regex(/^[a-f0-9]{16,128}$/i),
  title: z.string().max(300).optional(),
  timeoutMs: z.number().int().min(1_000).max(120_000).optional(),
})

export const verifyScriptResultSchema = z.object({
  runtime: z.enum(['ts', 'python']),
  exitCode: z.number().int(),
  result: z.unknown(),
  stdout: z.string().max(256 * 1024),
  stderr: z.string().max(256 * 1024),
  durationMs: z.number().int().min(0),
  timedOut: z.boolean(),
})

export const astVerifyRequestSchema = z.object({
  repo: repoIdentifierSchema,
  file: repoRelativePathSchema,
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  engine: z.enum(['opengrep', 'ast-grep']),
  ruleOrPattern: z.string().min(1).max(32 * 1024),
  timeoutMs: z.number().int().min(5_000).max(60_000).optional(),
}).refine(v => v.endLine >= v.startLine, 'endLine must be >= startLine.')

export const astVerifyResultSchema = z.object({
  verified: z.boolean(),
  engine: z.enum(['opengrep', 'ast-grep']),
  repo: z.string(),
  file: z.string(),
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  matchedLines: z.array(z.number().int().min(1)),
  codeExcerpt: z.string().max(4096),
  matchCount: z.number().int().min(0),
  durationMs: z.number().int().min(0),
  reason: z.string().optional(),
})

export const callGraphSinkKindSchema = z.enum([
  'api_route',
  'server_action',
  'webhook',
  'db_query',
  'outbound_fetch',
  'redirect',
  'postmessage_iframe',
  'upload_storage',
  'auth_config',
  'other',
])

export const callGraphRequestSchema = z.object({
  repo: repoIdentifierSchema,
  paths: z.array(repoRelativePathSchema).max(32).optional(),
  maxDepth: z.number().int().min(2).max(12).optional(),
  customGuardPatterns: z.array(z.string().min(1).max(200)).max(40).optional(),
  customSanitizerPatterns: z.array(z.string().min(1).max(200)).max(40).optional(),
  customSinkPatterns: z.array(z.object({
    pattern: z.string().min(1).max(200),
    sinkKind: callGraphSinkKindSchema,
  })).max(40).optional(),
  timeoutMs: z.number().int().min(5_000).max(120_000).optional(),
})

export const callGraphResultSchema = z.object({
  repo: z.string(),
  filesScanned: z.number().int().min(0),
  nodes: z.array(z.object({
    id: z.string(),
    file: z.string(),
    line: z.number().int().min(0),
    endLine: z.number().int().min(0).optional(),
    symbol: z.string(),
    kind: z.enum(['entrypoint', 'function', 'middleware', 'sink', 'guard', 'sanitizer']),
    httpMethod: z.string().optional(),
    routePath: z.string().optional(),
    sinkKind: callGraphSinkKindSchema.optional(),
    guards: z.array(z.string()),
    sanitizers: z.array(z.string()),
    calls: z.array(z.string()),
  })),
  edges: z.array(z.object({
    fromId: z.string(),
    toId: z.string(),
    file: z.string(),
    line: z.number().int().min(0),
  })),
  taintPaths: z.array(z.object({
    entrypointId: z.string(),
    entrypointSymbol: z.string(),
    entrypointFile: z.string(),
    entrypointLine: z.number().int().min(0),
    routeOrAction: z.string(),
    httpMethod: z.string().optional(),
    sinkId: z.string(),
    sinkSymbol: z.string(),
    sinkFile: z.string(),
    sinkLine: z.number().int().min(0),
    sinkKind: callGraphSinkKindSchema,
    callChain: z.array(z.object({
      file: z.string(),
      line: z.number().int().min(0),
      symbol: z.string(),
      role: z.enum(['entrypoint', 'intermediate', 'guard', 'sanitizer', 'sink']),
    })),
    dominatingGuards: z.array(z.string()),
    partialGuards: z.array(z.string()),
    dominatingSanitizers: z.array(z.string()),
    isUnguardedPath: z.boolean(),
    authCheck: z.string(),
    ownershipCheck: z.string(),
    severity: z.enum(['critical', 'high', 'medium', 'low']),
    maskedSnippet: z.string(),
  })),
  evidencePath: z.string().optional(),
  durationMs: z.number().int().min(0),
})

export type WorkerJob = z.input<typeof jobSchema>
export type WorkerResult = z.output<typeof resultSchema>
export type SastEngine = z.infer<typeof sastEngineSchema>
export type SastSeverity = z.infer<typeof sastSeveritySchema>
export type SastFinding = z.infer<typeof sastFindingSchema>
export type SastScanRequest = z.input<typeof sastScanRequestSchema>
export type SastScanResult = z.output<typeof sastScanResultSchema>
export type OfflineScriptRequest = z.input<typeof offlineScriptRequestSchema>
export type OfflineScriptResult = z.output<typeof offlineScriptResultSchema>
export type VerifyScriptRequest = z.input<typeof verifyScriptRequestSchema>
export type VerifyScriptResult = z.output<typeof verifyScriptResultSchema>
export type AstVerifyRequest = z.input<typeof astVerifyRequestSchema>
export type AstVerifyResult = z.output<typeof astVerifyResultSchema>
export type CallGraphRequest = z.input<typeof callGraphRequestSchema>
export type CallGraphResult = z.output<typeof callGraphResultSchema>

export interface WorkerSession {
  stage(name: string, content: string, signal: AbortSignal): Promise<string>
  exec(command: string, outputs: string[], signal: AbortSignal, timeoutMs?: number): Promise<WorkerResult>
  analyze(tool: AnalyzerName, args: Record<string, unknown>, signal: AbortSignal): Promise<Record<string, unknown>>
  sast(req: SastScanRequest, signal: AbortSignal): Promise<SastScanResult>
  runScript(req: OfflineScriptRequest, signal: AbortSignal): Promise<OfflineScriptResult>
  /** Layer-3 `guardian_verify` script; claims are oracle-checked host-side. */
  verifyScript?(req: VerifyScriptRequest, signal: AbortSignal): Promise<VerifyScriptResult>
  verifyStaticAst(req: AstVerifyRequest, signal: AbortSignal): Promise<AstVerifyResult>
  callGraph?(req: CallGraphRequest, signal: AbortSignal): Promise<CallGraphResult>
  close(): Promise<void>
}

export interface WorkerSessionOptions {
  reposDir?: string
  memoryMb?: number
  cpus?: number
  pidsLimit?: number
  tmpfsMb?: number
  /**
   * Host directory holding the Layer-1 verification RPC socket/token/context. Mounted read-only
   * at `/guardian-rpc`; the rest of the container filesystem stays read-only.
   */
  rpcMountDir?: string
}

/** Container-reuse counters for one backend/pool (diagnostic seam; no secrets). */
export interface WorkerContainerStats {
  /** `container create` round-trips that succeeded (cold creates + warm prewarm). */
  created: number
  /** Sessions served by a container that had already been used at least once. */
  reused: number
  /** Sessions served in total by this backend (warm or cold). */
  sessions: number
  /** Cold `container create` calls for sessions (warm-pool misses). */
  coldSessions: number
  /** Idle warm containers currently available for the next assignment. */
  idle: number
  capacity: number
}

export interface WorkerBackend {
  run(job: WorkerJob, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerResult>
  openSession(assignmentId: string, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession>
  verifyStaticAst(assignmentId: string, req: AstVerifyRequest, signal: AbortSignal, options?: WorkerSessionOptions): Promise<AstVerifyResult>
  /** Container-reuse counters (diagnostic seam; optional for test/fake backends). */
  containerStats?(): WorkerContainerStats | undefined
  /** Size the warm idle pool to the run's worker-slot count (one container per slot). */
  setWarmCapacity?(slots: number): void
  /**
   * Install the run's pool policy (run identity + credential generation). A changed policy
   * discards idle containers instead of reusing them across runs, tenants, or secret rotations.
   */
  setWarmPoolPolicy?(policy: string): void
  /** Remove idle warm containers on teardown instead of leaving them on the host. */
  closeWarmPool?(): Promise<void>
}

function clamp(val: number | undefined, fallback: number, min: number, max: number): number {
  if (val === undefined || !Number.isFinite(val)) return fallback
  return Math.max(min, Math.min(max, val))
}

function dockerHost() {
  const host = process.env.DOCKER_HOST || 'unix:///var/run/docker.sock'
  if (!/^unix:\/\/\/[^/?#\r\n][^?#\r\n]*$/.test(host)) {
    throw new Error('Guardian requires a local Docker Unix socket.')
  }
  return host
}

function dockerEnv() {
  return {
    PATH: process.env.PATH,
    DOCKER_HOST: dockerHost(),
    XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
  }
}

const workerFailureGuidance = 'Build the local worker image and check Docker availability.'

/**
 * Build an operator-actionable worker failure message. Docker CLI stderr holds the real cause
 * (missing image, daemon socket, OOM, conflict); the old generic message hid it and made worker
 * failures indistinguishable from a missing image.
 */
export function formatWorkerFailure(stderr: string, exitCode: number | null): string {
  const detail = stderr
    .replace(/\u001b\[[0-9;]*m/g, '')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .slice(0, 3)
    .join(' ')
    .slice(0, 400)
  const code = typeof exitCode === 'number' ? `exit ${exitCode}` : 'terminated'
  return detail
    ? `The isolated worker failed (${code}): ${detail}. ${workerFailureGuidance}`
    : `The isolated worker failed (${code}). ${workerFailureGuidance}`
}

const maxDockerStderrBytes = 8 * 1024

/** Per-line cap for worker NDJSON responses (a single flood line must not exhaust memory). */
export const MAX_WORKER_LINE_BYTES = 64 * 1024
/** Total stdout cap for a long-lived worker session. */
export const MAX_WORKER_OUTPUT_BYTES = 4 * 1024 * 1024
/** Cap for a spilled (file-pointer) worker payload; larger refs are rejected as hostile. */
export const MAX_WORKER_REF_BYTES = 8 * 1024 * 1024

const workerRefPath = /^\/tmp\/guardian-ipc\/[a-f0-9-]{36}\.json$/
const oneShotRefPath = /^\/guardian-ipc\/[a-f0-9-]{36}\.json$/
const resultRefSchema = z.object({
  path: z.string().regex(workerRefPath),
  bytes: z.number().int().positive().max(MAX_WORKER_REF_BYTES),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
})
const oneShotRefSchema = resultRefSchema.extend({ path: z.string().regex(oneShotRefPath) })

/** Per-one-shot tmpfs directory bind-mounted at `/guardian-ipc` (host-readable). */
function makeOneShotIpcDir(): string {
  const base = existsSync('/dev/shm') ? '/dev/shm' : tmpdir()
  const dir = mkdtempSync(join(base, 'guardian-ipc-'))
  chmodSync(dir, 0o777)
  return dir
}

function readOneShotRef(dir: string, rawRef: unknown): Record<string, unknown> {
  const ref = oneShotRefSchema.parse(rawRef)
  const path = join(dir, basename(ref.path))
  const file = readFileSync(path)
  if (file.length !== ref.bytes) throw new Error('Worker result pointer size mismatch.')
  const digest = createHash('sha256').update(file).digest('hex')
  if (digest !== ref.sha256) throw new Error('Worker result pointer checksum mismatch.')
  const parsed = JSON.parse(file.toString('utf8')) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Worker result pointer payload is invalid.')
  return parsed as Record<string, unknown>
}

const verifySdkFiles = ['guardian_verify.ts', 'guardian_verify.py'] as const
/**
 * The worker image predates the SDK, so the host stages it per call. This keeps the container
 * filesystem immutable and makes the SDK version auditable alongside the verifier that ran it.
 */
export function readVerifySdkFiles(): Array<{ name: string; content: string }> {
  const dir = process.env.GUARDIAN_VERIFY_SDK_DIR ?? join(dirname(fileURLToPath(import.meta.url)), '../../worker/guardian_verify')
  const files: Array<{ name: string; content: string }> = []
  for (const name of verifySdkFiles) {
    const path = join(dir, name)
    if (!existsSync(path)) continue
    if (statSync(path).size > 256 * 1024) throw new Error('guardian_verify SDK file exceeds the size limit.')
    files.push({ name, content: readFileSync(path, 'utf8') })
  }
  if (files.length === 0) throw new Error('guardian_verify SDK files are unavailable on this host.')
  return files
}

export class WorkerOutputStreamError extends Error {
  readonly limit: 'line' | 'total'
  constructor(limit: 'line' | 'total', message: string) {
    super(message)
    this.name = 'WorkerOutputStreamError'
    this.limit = limit
  }
}

/**
 * Bounded NDJSON line decoder for a worker container's stdout. Caps both an individual line and
 * the cumulative stream so a hostile/flooding worker cannot grow host memory without limit; the
 * session terminates on overflow instead of buffering the whole stream.
 */
export class BoundedLineDecoder {
  private pending: Buffer = Buffer.alloc(0)
  private total = 0
  private readonly maxLineBytes: number
  private readonly maxTotalBytes: number

  constructor(limits: { maxLineBytes?: number; maxTotalBytes?: number } = {}) {
    this.maxLineBytes = limits.maxLineBytes ?? MAX_WORKER_LINE_BYTES
    this.maxTotalBytes = limits.maxTotalBytes ?? MAX_WORKER_OUTPUT_BYTES
  }

  get totalBytes(): number {
    return this.total
  }

  get pendingBytes(): number {
    return this.pending.length
  }

  push(chunk: Buffer | string): string[] {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk
    this.total += buf.length
    if (this.total > this.maxTotalBytes) {
      throw new WorkerOutputStreamError('total', `Worker output exceeded the ${this.maxTotalBytes}-byte session limit.`)
    }
    const combined = this.pending.length === 0 ? buf : Buffer.concat([this.pending, buf])
    if (combined.indexOf(10) === -1 && combined.length > this.maxLineBytes) {
      throw new WorkerOutputStreamError('line', `Worker output line exceeded the ${this.maxLineBytes}-byte line limit.`)
    }
    const lines: string[] = []
    let start = 0
    for (let idx = combined.indexOf(10); idx !== -1; idx = combined.indexOf(10, start)) {
      const raw = combined.subarray(start, idx)
      if (raw.length > this.maxLineBytes) {
        throw new WorkerOutputStreamError('line', `Worker output line exceeded the ${this.maxLineBytes}-byte line limit.`)
      }
      const withoutCr = raw.length > 0 && raw[raw.length - 1] === 13 ? raw.subarray(0, raw.length - 1) : raw
      lines.push(withoutCr.toString('utf8'))
      start = idx + 1
    }
    this.pending = start === 0 ? combined : combined.subarray(start)
    if (this.pending.length > this.maxLineBytes) {
      throw new WorkerOutputStreamError('line', `Worker output line exceeded the ${this.maxLineBytes}-byte line limit.`)
    }
    return lines
  }
}

function docker(args: string[], signal: AbortSignal, input?: string) {
  signal.throwIfAborted()
  return new Promise<string>((resolve, reject) => {
    const cli = spawn('docker', args, {
      signal,
      env: dockerEnv(),
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    const chunks: Buffer[] = []
    let size = 0
    const stderrChunks: Buffer[] = []
    let stderrBytes = 0
    const limit = 16 * 1024 * 1024
    cli.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > limit) {
        cli.kill()
        reject(new Error('Worker output exceeded its limit.'))
      } else chunks.push(chunk)
    })
    cli.stderr.on('data', (chunk: Buffer) => {
      if (stderrBytes >= maxDockerStderrBytes) return
      const remaining = maxDockerStderrBytes - stderrBytes
      const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk
      stderrChunks.push(slice)
      stderrBytes += slice.length
    })
    cli.stdin.on('error', () => { /* Early exit closes stdin. */ })
    cli.stdin.end(input)
    cli.once('error', error => reject(signal.aborted ? signal.reason : error))
    cli.once('close', code => {
      if (code === 0) resolve(Buffer.concat(chunks).toString('utf8'))
      else {
        const stderr = Buffer.concat(stderrChunks).toString('utf8')
        if (process.env.GUARDIAN_WORKER_DEBUG === '1') {
          console.error('[worker-docker]', args.slice(0, 3).join(' '), 'exit', code, stderr.trim().split('\n').slice(0, 2).join(' | '))
        }
        reject(new Error(formatWorkerFailure(stderr, code)))
      }
    })
  })
}

export type DockerRunner = (args: string[], signal: AbortSignal, input?: string) => Promise<string>
/** The real CLI executor, exported so Docker-gated tests can wrap it (e.g. force a start failure). */
export const dockerCliRunner: DockerRunner = docker

/** Binary CLI executor used to stream `docker cp` archives out of a container. */

/** Fetch, size/checksum-validate and parse a tmpfs-spilled worker response from a running container. */
async function readResultRef(container: string, rawRef: unknown, signal: AbortSignal, run: DockerRunner): Promise<Record<string, unknown>> {
  const ref = resultRefSchema.parse(rawRef)
  const text = await run(['exec', container, 'cat', ref.path], signal)
  const file = Buffer.from(text, 'utf8')
  if (file.length !== ref.bytes) throw new Error('Worker result pointer size mismatch.')
  const digest = createHash('sha256').update(file).digest('hex')
  if (digest !== ref.sha256) throw new Error('Worker result pointer checksum mismatch.')
  const parsed = JSON.parse(text) as unknown
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Worker result pointer payload is invalid.')
  return parsed as Record<string, unknown>
}

/** Session options that change the container shape; warm containers only serve exact matches. */
export function workerOptionsSignature(options?: WorkerSessionOptions): string {
  return JSON.stringify({
    memoryMb: options?.memoryMb ?? null,
    cpus: options?.cpus ?? null,
    pidsLimit: options?.pidsLimit ?? null,
    tmpfsMb: options?.tmpfsMb ?? null,
    reposDir: options?.reposDir ?? null,
    rpcMountDir: options?.rpcMountDir ?? null,
  })
}

interface ContainerArgsInput {
  image: string
  name: string
  assignmentId: string
  extraArgs?: string[]
  runLabel: string
  owner?: string
  cell?: string
  warm?: boolean
  options?: WorkerSessionOptions
  /** One-shot only: host tmpfs dir bind-mounted at /guardian-ipc for large-output pointers. */
  ipcDir?: string
}

export interface PreparedReposMount {
  /** Host directory bind-mounted read-only at `/repos`. */
  mountDir: string
  /** True when Guardian staged a clean container-readable copy instead of binding `reposDir` directly. */
  staged: boolean
  /** Number of secret/sensitive or unsafe entries excluded while staging. */
  excludedCount: number
  /** Remove any temporary staged directory (idempotent no-op when `staged === false`). */
  cleanup(): void
}

const SENSITIVE_DOT_DIRS = new Set(['.ssh', '.aws', '.gnupg', '.kube', '.docker'])
const SENSITIVE_EXACT_FILES = new Set([
  '.git-credentials',
  '.netrc',
  '.npmrc',
  '.pypirc',
  '.htpasswd',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'github-app.json',
  'credentials.json',
  'service-account.json',
  'vault.json',
  'vault.key',
  'token.txt',
  'secrets.json',
])
const SENSITIVE_FILE_EXT_RE = /\.(?:pat|salt|pem|key|p12|pfx|jks|keystore|kdbx|token)$/i
const SAFE_ENV_TEMPLATE_RE = /^\.env\.(?:example|sample|template|dist|schema)$/i
const SOURCE_CODE_EXT_RE = /\.(?:ts|tsx|mts|cts|js|jsx|mjs|cjs|py|go|rs|java|kt|rb|php|cs|c|h|cc|cpp|hpp|swift|scala|sql|graphql|gql|md|html|css|scss|vue|svelte)$/i
const GIT_CREDENTIAL_FILE_RE = /(?:^|\/)\.git\/(?:config|credentials|fetch_head)$/i
const GIT_CONFIG_FILE_RE = /(?:^|\/)\.git\/config$/i
const GIT_CONFIG_SECRET_RE = /^\s*\[credential(?:\s|\])|extraheader|^\s*(?:username|password|token)\s*=|https?:\/\/[^/@\s]+@/im

function isSensitiveRepoEntry(relPosixPath: string, entryName: string, isDir: boolean): boolean {
  const relLower = relPosixPath.toLowerCase()
  const nameLower = entryName.toLowerCase()
  if (isDir) {
    if (SENSITIVE_DOT_DIRS.has(nameLower)) return true
    if (relLower === '.git/hooks' || relLower.endsWith('/.git/hooks')) return true
    return false
  }
  if (GIT_CREDENTIAL_FILE_RE.test(relLower)) return true
  if (SENSITIVE_EXACT_FILES.has(nameLower)) return true
  if (SENSITIVE_FILE_EXT_RE.test(nameLower)) return true
  if (nameLower === '.env' || (nameLower.startsWith('.env.') && !SAFE_ENV_TEMPLATE_RE.test(nameLower))) {
    return true
  }
  const parentSegments = relLower.split('/').slice(0, -1)
  if (parentSegments.includes('credentials') && !SOURCE_CODE_EXT_RE.test(nameLower)) {
    return true
  }
  return false
}

function gitConfigHasCredentials(filePath: string): boolean {
  try {
    const st = lstatSync(filePath)
    if (!st.isFile() || st.size > 256 * 1024) return true
    return GIT_CONFIG_SECRET_RE.test(readFileSync(filePath, 'utf8'))
  } catch {
    return true
  }
}

function reposTreeNeedsStaging(resolvedRoot: string): boolean {
  const rootStat = statSync(resolvedRoot)
  // Non-root worker container (UID 10001) needs o+rx on `/repos` and every subdirectory,
  // and o+r on every non-secret file inside it.
  if ((rootStat.mode & 0o005) !== 0o005) return true

  const inspect = (dir: string): boolean => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name)
      const st = lstatSync(fullPath)
      if (st.isSymbolicLink()) continue
      const relPosix = relative(resolvedRoot, fullPath).split(sep).join('/')
      if (st.isDirectory()) {
        if (isSensitiveRepoEntry(relPosix, entry.name, true)) {
          if ((st.mode & 0o005) !== 0) return true
          continue
        }
        if ((st.mode & 0o005) !== 0o005) return true
        if (inspect(fullPath)) return true
      } else if (st.isFile()) {
        if (isSensitiveRepoEntry(relPosix, entry.name, false)) {
          if (GIT_CONFIG_FILE_RE.test(relPosix)) {
            if ((st.mode & 0o004) !== 0 && gitConfigHasCredentials(fullPath)) return true
            continue
          }
          if ((st.mode & 0o004) !== 0) return true
          continue
        }
        if ((st.mode & 0o004) !== 0o004) return true
      }
    }
    return false
  }

  return inspect(resolvedRoot)
}

function stageReadableReposTree(resolvedRoot: string): { mountDir: string; excludedCount: number } {
  const rawStageDir = mkdtempSync(join(tmpdir(), 'guardian-repos-'))
  chmodSync(rawStageDir, 0o755)
  const mountDir = realpathSync(rawStageDir)
  let excludedCount = 0

  const copyDir = (srcDir: string, dstDir: string) => {
    for (const entry of readdirSync(srcDir, { withFileTypes: true })) {
      const srcChild = join(srcDir, entry.name)
      const st = lstatSync(srcChild)
      if (st.isSymbolicLink()) {
        excludedCount += 1
        continue
      }
      const relPosix = relative(resolvedRoot, srcChild).split(sep).join('/')
      if (st.isDirectory()) {
        if (isSensitiveRepoEntry(relPosix, entry.name, true)) {
          excludedCount += 1
          continue
        }
        const dstChild = join(dstDir, entry.name)
        mkdirSync(dstChild)
        chmodSync(dstChild, 0o755)
        copyDir(srcChild, dstChild)
      } else if (st.isFile()) {
        if (isSensitiveRepoEntry(relPosix, entry.name, false)) {
          excludedCount += 1
          continue
        }
        const dstChild = join(dstDir, entry.name)
        copyFileSync(srcChild, dstChild)
        chmodSync(dstChild, 0o644)
      }
    }
  }

  try {
    copyDir(resolvedRoot, mountDir)
  } catch (error) {
    try { rmSync(mountDir, { recursive: true, force: true }) } catch { /* ignore */ }
    throw error
  }
  return { mountDir, excludedCount }
}

/**
 * Validate and prepare a host `reposDir` for a read-only `/repos` bind mount into the non-root
 * Docker worker (`UID 10001`). When the host tree lacks `o+rx` on directories or `o+r` on
 * non-secret files (e.g. created under host `umask 0077` or `0o700`), stages a clean read-only
 * copy with explicit `0o755`/`0o644` permissions while excluding credential/token files and
 * leaving original host files (including `0600` secrets) completely unmodified.
 */
export function prepareReposMount(reposDir?: string): PreparedReposMount | null {
  if (!reposDir) return null
  if (/[\0,\r\n]/.test(reposDir)) {
    throw new Error('Invalid repository mount path.')
  }
  if (!existsSync(reposDir)) return null
  const st = statSync(reposDir)
  if (!st.isDirectory()) {
    throw new Error('Repository mount path must be an existing directory.')
  }
  const resolved = realpathSync(reposDir)
  if (/[\0,\r\n]/.test(resolved)) {
    throw new Error('Invalid resolved repository mount path.')
  }
  if (!reposTreeNeedsStaging(resolved)) {
    return {
      mountDir: resolved,
      staged: false,
      excludedCount: 0,
      cleanup() { /* direct mount: never remove caller's directory */ },
    }
  }
  const { mountDir, excludedCount } = stageReadableReposTree(resolved)
  trackLiveStagedRepoDir(mountDir)
  let cleaned = false
  return {
    mountDir,
    staged: true,
    excludedCount,
    cleanup() {
      if (cleaned) return
      cleaned = true
      liveStagedRepoDirs.delete(mountDir)
      try { rmSync(mountDir, { recursive: true, force: true }) } catch { /* best-effort */ }
    },
  }
}

function resolveReposMountArgs(reposDir?: string): string[] {
  if (!reposDir) return []
  if (/[\0,\r\n]/.test(reposDir)) {
    throw new Error('Invalid repository mount path.')
  }
  if (!existsSync(reposDir)) return []
  const st = statSync(reposDir)
  if (!st.isDirectory()) {
    throw new Error('Repository mount path must be an existing directory.')
  }
  const resolved = realpathSync(reposDir)
  if (/[\0,\r\n]/.test(resolved)) {
    throw new Error('Invalid resolved repository mount path.')
  }
  return ['--mount', `type=bind,source=${resolved},target=/repos,readonly`]
}

/**
 * Mount the per-session verification RPC directory read-only at `/guardian-rpc`. The socket is
 * the only egress a `--network none` verification script needs; the rest of the container stays
 * read-only and the script never receives a persona credential (Layer 1 injects it).
 */
function resolveRpcMountArgs(rpcDir?: string): string[] {
  if (!rpcDir) return []
  if (/[\0,\r\n]/.test(rpcDir)) throw new Error('Invalid verification RPC mount path.')
  if (!existsSync(rpcDir)) throw new Error('Verification RPC mount path does not exist.')
  const st = statSync(rpcDir)
  if (!st.isDirectory()) throw new Error('Verification RPC mount path must be a directory.')
  const resolved = realpathSync(rpcDir)
  if (/[\0,\r\n]/.test(resolved)) throw new Error('Invalid resolved verification RPC mount path.')
  return [
    '--mount', `type=bind,source=${resolved},target=${VERIFY_RPC_CONTAINER_DIR},readonly`,
    '--env', `${VERIFY_RPC_SOCKET_ENV}=${VERIFY_RPC_CONTAINER_DIR}/${VERIFY_RPC_SOCKET_NAME}`,
    '--env', `${VERIFY_RPC_TOKEN_ENV}=${VERIFY_RPC_CONTAINER_DIR}/${VERIFY_RPC_TOKEN_NAME}`,
    '--env', `${VERIFY_RPC_CONTEXT_ENV}=${VERIFY_RPC_CONTAINER_DIR}/${VERIFY_RPC_CONTEXT_NAME}`,
  ]
}

/**
 * The single container-create argument builder (cold and warm-pool containers share it, so
 * security flags can never drift between the two paths).
 */
export function workerContainerCreateArgs(input: ContainerArgsInput): string[] {
  // Default 1536m RAM, 2.0 CPU, 256 PIDs (ceiling: 4096m / 4.0 / 384)
  const options = input.options
  const memoryMb = Math.round(clamp(options?.memoryMb, 1536, 512, 4096))
  const cpus = Number(clamp(options?.cpus, 2.0, 0.5, 4.0).toFixed(2))
  const pidsLimit = Math.round(clamp(options?.pidsLimit, 256, 64, 384))
  const tmpfsMb = Math.round(clamp(options?.tmpfsMb, 128, 64, 512))
  return [
    // No `--rm`: Docker's automatic removal races the explicit `rm --force` below and the
    // daemon answers "removal of container ... is already in progress", which previously
    // surfaced as a failed worker session. Explicit removal is the single mechanism.
    'container', 'create', '--name', input.name, '--interactive', '--pull', 'never',
    '--network', 'none', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', String(pidsLimit),
    '--cpus', String(cpus),
    '--memory', `${memoryMb}m`, '--memory-swap', `${memoryMb}m`,
    '--tmpfs', `/tmp:rw,nosuid,nodev,noexec,size=${tmpfsMb}m,mode=1777`,
    ...resolveReposMountArgs(options?.reposDir),
    ...resolveRpcMountArgs(options?.rpcMountDir),
    ...(input.ipcDir
      ? [
          '--mount', `type=bind,source=${realpathSync(input.ipcDir)},target=/guardian-ipc`,
          '--env', 'GUARDIAN_IPC_DIR=/guardian-ipc',
        ]
      : []),
    '--label', `${assignmentNamespace}=` + input.assignmentId,
    '--label', `${runNamespace}=${input.runLabel}`,
    ...(input.owner ? ['--label', `${workerNamespace}=${input.owner}`] : []),
    ...(input.cell ? ['--label', `${cellNamespace}=${input.cell}`] : []),
    ...(input.warm ? ['--label', `${warmNamespace}=1`] : []),
    '--label', `${sessionNamespace}=${processSessionId}`,
    '--label', `${createdAtNamespace}=` + Date.now(),
    input.image,
    ...(input.extraArgs ?? []),
  ]
}

/** Warm-pool escape hatch: `GUARDIAN_WARM_WORKERS=0` (or false/off) disables pooling. */
export function warmWorkersEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env.GUARDIAN_WARM_WORKERS
  return value !== '0' && value !== 'false' && value !== 'off'
}

/** Idle warm containers kept per cell (one per worker slot); bounded 1..8. */
export function warmPoolCapacity(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.GUARDIAN_WARM_SLOTS)
  if (!Number.isFinite(raw) || raw <= 0) return 1
  return Math.max(1, Math.min(8, Math.floor(raw)))
}

/**
 * Scratch reset executed inside a pooled container before it is returned to the pool. `/tmp` is
 * the container tmpfs that backs `/evidence` and the scratch workspace, so clearing it gives the
 * next assignment a fresh filesystem without paying for a `container create` round-trip.
 */
export const WARM_SCRATCH_RESET_COMMAND = 'rm -rf /tmp/* /tmp/.[!.]* 2>/dev/null; true'

/**
 * One pool per (cell, image) per process: Execution may construct more than one backend, and a
 * cell must not accumulate one idle container per backend.
 */
const warmPools = new Map<string, WarmWorkerPool>()
function sharedWarmPool(input: {
  cell: string
  image: string
  dockerRunner: DockerRunner
  runLabel: string
  owner?: string
}): WarmWorkerPool {
  // Owner (tenant/workspace) is part of the key: two tenants that happen to share a cell id and
  // run label must never share an idle container.
  const key = `${input.cell}\0${input.image}\0${input.runLabel}\0${input.owner ?? ''}`
  const existing = warmPools.get(key)
  if (existing) return existing
  const pool = new WarmWorkerPool(input)
  warmPools.set(key, pool)
  return pool
}

/**
 * Best-effort warm session pool: pre-created `--session` containers, one per worker slot
 * (`setCapacity`), reused across assignments inside a run. A container is never started until a
 * session takes it; when the session ends cleanly the backend resets `/tmp` and returns the
 * stopped container to the pool, so the next assignment pays only a `container start` instead of
 * a cold `create`. Any create/reuse failure permanently disables the pool and callers fall back to
 * the cold create path unchanged.
 */
export class WarmWorkerPool {
  readonly cell: string
  private readonly image: string
  private readonly docker: DockerRunner
  private readonly runLabel: string
  private readonly owner?: string
  private readonly options: WorkerSessionOptions
  private readonly signature: string
  private capacity: number
  private readonly idle: string[] = []
  private readonly inflight = new Set<Promise<void>>()
  private readonly used = new Set<string>()
  /** Containers currently held by a session (excluding idle and in-flight creates). */
  private readonly outstanding = new Set<string>()
  private disabled = false
  private closed = false
  private created = 0
  private failures = 0
  private reused = 0
  private returned = 0
  private discarded = 0
  private removed = 0

  constructor(input: {
    cell: string
    image: string
    dockerRunner: DockerRunner
    runLabel: string
    owner?: string
    options?: WorkerSessionOptions
    capacity?: number
  }) {
    this.cell = input.cell
    this.image = input.image
    this.docker = input.dockerRunner
    this.runLabel = input.runLabel
    this.owner = input.owner
    this.options = { ...(input.options ?? {}) }
    delete this.options.reposDir
    this.signature = workerOptionsSignature(this.options)
    this.capacity = Math.max(1, Math.min(8, Math.floor(input.capacity ?? warmPoolCapacity())))
  }

  get enabled(): boolean { return !this.disabled && !this.closed }
  get state(): 'warming' | 'ready' | 'disabled' | 'closed' {
    if (this.closed) return 'closed'
    if (this.disabled) return 'disabled'
    return this.idle.length ? 'ready' : 'warming'
  }
  get stats(): {
    state: string
    capacity: number
    idle: number
    prewarmed: number
    failures: number
    created: number
    reused: number
    returned: number
    discarded: number
    removed: number
  } {
    return {
      state: this.state,
      capacity: this.capacity,
      idle: this.idle.length,
      prewarmed: this.created,
      failures: this.failures,
      created: this.created,
      reused: this.reused,
      returned: this.returned,
      discarded: this.discarded,
      removed: this.removed,
    }
  }

  /** Resize the idle pool to one container per worker slot; never shrinks below `idle.length`. */
  setCapacity(slots: number): void {
    const next = Math.max(1, Math.min(8, Math.floor(slots)))
    if (next === this.capacity) return
    this.capacity = next
    this.fill()
  }

  /** True when the pool currently owns an idle container with this name. */
  owns(name: string): boolean {
    return this.idle.includes(name)
  }

  /** A pooled container died or was removed mid-session: stop accounting for it and refill. */
  forget(name: string): void {
    this.outstanding.delete(name)
    this.used.delete(name)
    this.fill()
  }

  private fill(): void {
    if (!this.enabled) return
    // Total live pool containers (idle + in a session + being created) never exceeds capacity.
    // A container returning from a session therefore becomes the next assignment's spare, instead
    // of racing a speculative prewarm that would be discarded.
    while (this.idle.length + this.outstanding.size + this.inflight.size < this.capacity) {
      let pending: Promise<void>
      pending = this.create().finally(() => { this.inflight.delete(pending) })
      this.inflight.add(pending)
    }
  }

  private async create(): Promise<void> {
    const name = 'guardian-' + randomUUID()
    try {
      await this.docker(workerContainerCreateArgs({
        image: this.image,
        name,
        assignmentId: `warm-${randomUUID()}`,
        extraArgs: ['--session'],
        runLabel: this.runLabel,
        ...(this.owner ? { owner: this.owner } : {}),
        cell: this.cell,
        warm: true,
        options: this.options,
      }), AbortSignal.timeout(15_000))
      if (this.closed) {
        await this.docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
        this.removed += 1
        return
      }
      this.created += 1
      if (this.idle.length >= this.capacity) {
        this.discarded += 1
        await this.removeIdle(name)
        return
      }
      this.idle.push(name)
      trackLiveContainer(name)
    } catch (error) {
      this.failures += 1
      this.disabled = true
      if (process.env.GUARDIAN_WORKER_DEBUG === '1') {
        console.error('[worker-pool] prewarm failed; falling back to cold create:', error instanceof Error ? error.message.slice(0, 160) : String(error))
      }
    }
  }

  /** Ensure an idle session container exists; resolves to its name or null. */
  async warm(): Promise<string | null> {
    if (!this.enabled) return null
    if (this.idle.length) return this.idle[0]
    this.fill()
    while (this.inflight.size) {
      await Promise.all([...this.inflight])
      if (this.idle.length) break
    }
    return this.idle[0] ?? null
  }

  /** Take an idle container when it matches the caller's session shape; null means cold create. */
  async take(signal: AbortSignal, options?: WorkerSessionOptions): Promise<string | null> {
    if (!this.enabled) return null
    if (workerOptionsSignature(options) !== this.signature) return null
    if (!this.idle.length) await this.warm()
    signal.throwIfAborted()
    const name = this.idle.shift()
    if (!name) return null
    liveContainers.delete(name)
    this.outstanding.add(name)
    if (this.used.has(name)) this.reused += 1
    else this.used.add(name)
    return name
  }

  /** Remove one idle container (pool disabled, oversized, or failed reuse). */
  private async removeIdle(name: string): Promise<void> {
    liveContainers.delete(name)
    await this.docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
    this.removed += 1
  }

  /**
   * Return a cleanly stopped container to the pool. The caller has already reset `/tmp`; a
   * container that is not stopped, or a pool that is full/disabled, is removed instead.
   */
  async release(name: string): Promise<boolean> {
    this.outstanding.delete(name)
    if (!this.enabled) {
      this.discarded += 1
      await this.removeIdle(name)
      return false
    }
    let status = ''
    try {
      status = (await this.docker(['container', 'inspect', '-f', '{{.State.Status}}', name], AbortSignal.timeout(5_000))).trim()
    } catch {
      status = ''
    }
    if (status !== 'exited' && status !== 'created') {
      this.discarded += 1
      await this.removeIdle(name)
      return false
    }
    if (this.idle.length >= this.capacity) {
      this.discarded += 1
      await this.removeIdle(name)
      return false
    }
    this.idle.push(name)
    this.returned += 1
    trackLiveContainer(name)
    return true
  }

  async close(): Promise<void> {
    this.closed = true
    const idle = this.idle.splice(0)
    await Promise.all(idle.map(name => this.removeIdle(name)))
  }
}

export class LinuxWorkerBackend implements WorkerBackend {
  private readonly image: string
  private readonly owner?: string
  private readonly runId?: string
  private readonly cell?: string
  private readonly docker: DockerRunner
  private readonly staleCreatedMs: number
  private warmPool?: WarmWorkerPool
  /** Last pool policy installed by Execution (run id + credential generation). */
  private warmPoolPolicy?: string
  /** Cumulative stats of pools retired by a policy change (metrics stay run-wide). */
  private retiredPoolStats = { created: 0, reused: 0, failures: 0 }
  private readonly pooled = new Set<string>()
  private readonly activeContainers = new Set<string>()
  private readonly removals = new Map<string, Promise<void>>()
  private sessionsServed = 0
  private coldSessionCreates = 0
  private reclaiming?: Promise<void>

  constructor({ image = 'guardian-worker:v4', workspace, runId, dockerRunner, staleCreatedMs, cell }: {
    image?: string
    workspace?: { id: string; directory: string }
    runId?: string
    /** Test seam: replace the docker CLI executor (defaults to the real CLI). */
    dockerRunner?: DockerRunner
    /** Grace before an abandoned `created` container is reclaimed (default 2 min). */
    staleCreatedMs?: number
    /**
     * Matrix cell id (default: `GUARDIAN_CELL_ID`). Labels every container `dev.guardian.cell`
     * and enables the best-effort warm session pool unless `GUARDIAN_WARM_WORKERS=0`.
     */
    cell?: string
  } = {}) {
    this.image = image
    this.runId = runId
    this.docker = dockerRunner ?? docker
    this.staleCreatedMs = Math.max(0, staleCreatedMs ?? DEFAULT_STALE_CREATED_MS)
    const cellId = cell ?? process.env.GUARDIAN_CELL_ID
    this.cell = cellId && cellId.trim() ? cellId.trim() : undefined
    if (workspace) {
      this.owner = createHash('sha256').update(workspace.id).update('\0').update(realpathSync(workspace.directory)).digest('hex')
    }
    // The pool is installed lazily: Execution sets the run/credential policy before the first
    // assignment, so prewarming under the default label would only create a container to discard.
    this.installWarmPool(this.defaultWarmPolicy(), false)
  }

  /** Pool key: an explicit cell, else the workspace. A bare test backend never prewarms. */
  private poolCell(): string | undefined {
    return this.cell ?? (this.owner ? `ws-${this.owner.slice(0, 12)}` : undefined)
  }

  private defaultWarmPolicy(): string {
    return this.runId ?? (this.owner ? `workspace-${this.owner.slice(0, 12)}` : `adhoc-${processSessionId.slice(0, 8)}`)
  }

  private installWarmPool(policy: string, warmNow = true): void {
    const poolCell = this.poolCell()
    if (!poolCell || !warmWorkersEnabled()) return
    if (this.warmPool && this.warmPoolPolicy === policy) return
    const previous = this.warmPool
    if (previous) {
      const stats = previous.stats
      this.retiredPoolStats.created += stats.created
      this.retiredPoolStats.reused += stats.reused
      this.retiredPoolStats.failures += stats.failures
      // Close removes idle containers; a session still holding one releases into a closed pool,
      // which discards instead of reusing. Never carry an old-generation container forward.
      void previous.close().catch(() => undefined)
    }
    this.warmPoolPolicy = policy
    this.pooled.clear()
    this.warmPool = sharedWarmPool({
      cell: poolCell,
      image: this.image,
      dockerRunner: this.docker,
      runLabel: `${this.defaultWarmPolicy()}#${policy}`,
      ...(this.owner ? { owner: this.owner } : {}),
    })
    // Kick the first create early; failure only disables the pool (cold path remains).
    if (warmNow) void this.warmPool.warm()
  }

  /**
   * Install the run's warm-pool policy: run identity + credential generation. A policy change
   * (new run, tenant, secret rotation, scope/option change) retires the pool and rebuilds it, so
   * an idle container created under earlier credentials is never reused.
   */
  setWarmPoolPolicy(policy: string): void {
    const normalized = policy.trim()
    if (!normalized) return
    this.installWarmPool(normalized)
  }

  /** Shutdown seam: remove idle containers so a finished run leaves no warm pool behind. */
  async closeWarmPool(): Promise<void> {
    const pool = this.warmPool
    this.warmPool = undefined
    if (!pool) return
    const stats = pool.stats
    this.retiredPoolStats.created += stats.created
    this.retiredPoolStats.reused += stats.reused
    this.retiredPoolStats.failures += stats.failures
    await pool.close().catch(() => undefined)
  }

  /** Warm-pool state (test/diagnostic seam; never contains secrets). */
  get warmPoolStats(): WarmWorkerPool['stats'] | undefined {
    return this.warmPool?.stats
  }

  /** Container-reuse counters for the run's diagnostics event. */
  containerStats(): WorkerContainerStats {
    const pool = this.warmPool?.stats
    return {
      created: this.retiredPoolStats.created + (pool?.created ?? 0) + this.coldSessionCreates,
      reused: this.retiredPoolStats.reused + (pool?.reused ?? 0),
      sessions: this.sessionsServed,
      coldSessions: this.coldSessionCreates,
      idle: pool?.idle ?? 0,
      capacity: pool?.capacity ?? 0,
    }
  }

  /** One warm idle container per worker slot (called by Execution after slot planning). */
  setWarmCapacity(slots: number): void {
    this.warmPool?.setCapacity(slots)
  }

  /**
   * Reclaim leftovers from earlier workers. This runs on every operation and also from
   * Execution's 30 s sweep. Ownerless backends (preflight probes, benchmark clients) must
   * sweep too: they were the ones accumulating unattributed `created` containers.
   *
   * Housekeeping is strictly best-effort: a 404/409 from a concurrent removal must never
   * fail the worker operation that happened to trigger the sweep (that surfaced as a false
   * "Verification container failed" during inline replay verification).
   */
  reclaimInactive() {
    return this.reclaiming ??= (async () => {
      try {
        if (this.owner) await this.removeInactive(this.owner)
        await this.removeStaleCreated()
      } catch (error) {
        if (process.env.GUARDIAN_WORKER_DEBUG === '1') {
          console.error('[worker-docker] reclaim skipped:', error instanceof Error ? error.message.slice(0, 160) : String(error).slice(0, 160))
        }
      } finally {
        this.reclaiming = undefined
      }
    })()
  }

  private removeContainer(name: string) {
    // Coalesce concurrent removals: `finally` + the session close/error handlers can race,
    // and a second `docker rm` reports "removal ... already in progress" instead of a clean exit.
    if (this.warmPool?.owns(name)) return Promise.resolve()
    if (this.pooled.delete(name)) this.warmPool?.forget(name)
    const existing = this.removals.get(name)
    if (existing) return existing
    const removal = this.docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000))
      .then(() => undefined, () => undefined)
      .then(() => { this.pooled.delete(name) })
      .finally(() => { this.removals.delete(name) })
    this.removals.set(name, removal)
    return removal
  }

  /**
   * Remove guardian containers abandoned before use (`created`) or after they stopped
   * (`exited`/`dead`) — e.g. a SIGKILLed test process or a crashed CLI. Running (`Up`)
   * containers are left alone: they may belong to a concurrent stream. Only containers
   * older than the grace window are touched so an in-flight create is never killed.
   */
  private async removeStaleCreated() {
    const signal = AbortSignal.timeout(5_000)
    let rows: string
    try {
      rows = await this.docker([
        'container', 'ls', '--all', '--no-trunc',
        '--filter', 'status=created', '--filter', 'status=exited', '--filter', 'status=dead',
        '--format', '{{.ID}}\t{{.Names}}\t{{.Label "dev.guardian.created-at"}}\t{{.CreatedAt}}',
      ], signal)
    } catch {
      return
    }
    const now = Date.now()
    const stale: string[] = []
    for (const row of rows.trim().split('\n')) {
      if (!row) continue
      const [id, name, createdLabel, createdAt] = row.split('\t')
      if (!/^[a-f0-9]{64}$/.test(id) || !workerName.test(name)) continue
      // Never reap a container this process created: pool-parked idle containers sit in `created`
      // state between assignments and are removed by the pool, not by the stale sweep.
      if (this.activeContainers.has(name) || liveContainers.has(name)) continue
      const stamped = Number(createdLabel)
      const age = Number.isFinite(stamped) && stamped > 0 ? now - stamped : now - Date.parse(createdAt)
      if (!Number.isFinite(age) || age < this.staleCreatedMs) continue
      stale.push(id)
    }
    if (stale.length) {
      if (process.env.GUARDIAN_WORKER_DEBUG === '1') {
        console.error('[worker-docker] removeStaleCreated ids', stale.map(i => i.slice(0, 12)).join(','), 'rows', rows.trim().split('\n').length)
      }
      await this.docker(['container', 'rm', '--force', ...stale], signal).catch(() => undefined)
    }
  }

  private async removeInactive(owner: string) {
    const signal = AbortSignal.timeout(5_000)
    let inactive: string[] = []
    try {
      const rows = await this.docker([
        'container', 'ls', '--all', '--no-trunc', '--filter', `label=${workerNamespace}=${owner}`,
        '--format', '{{.ID}}\t{{.Names}}\t{{.Label "dev.guardian.created-at"}}\t{{.CreatedAt}}\t{{.Label "dev.guardian.session"}}',
      ], signal)
      inactive = rows.trim().split('\n').flatMap(row => {
        if (!row) return []
        const [id, name, _createdLabel, _createdAt, session] = row.split('\t')
        if (!/^[a-f0-9]{64}$/.test(id) || !workerName.test(name)) return []
        // Never touch this process's own containers: a concurrent run/session may be between
        // create and start. Cross-process leftovers are reclaimed regardless of age.
        if (this.activeContainers.has(name) || session === processSessionId) return []
        return [id]
      })
    } catch {
      return
    }
    if (!inactive.length) return
    if (process.env.GUARDIAN_WORKER_DEBUG === '1') {
      console.error('[worker-docker] removeInactive owner', owner.slice(0, 8), 'active', this.activeContainers.size, 'ids', inactive.map(i => i.slice(0, 12)).join(','))
    }
    await this.docker(['container', 'rm', '--force', ...inactive], signal).catch(() => undefined)
  }

  private containerCreateArgs(name: string, assignmentId: string, extraArgs: string[] = [], options?: WorkerSessionOptions, ipcDir?: string) {
    // Every container is attributable even when the caller did not supply a run id:
    // `run` falls back to the workspace hash or this process's ad-hoc session.
    const runLabelValue = this.runId ?? (this.owner ? `workspace-${this.owner.slice(0, 12)}` : `adhoc-${processSessionId.slice(0, 8)}`)
    return workerContainerCreateArgs({
      image: this.image,
      name,
      assignmentId,
      extraArgs,
      runLabel: runLabelValue,
      ...(this.owner ? { owner: this.owner } : {}),
      ...(this.cell ? { cell: this.cell } : {}),
      ...(options ? { options } : {}),
      ...(ipcDir ? { ipcDir } : {}),
    })
  }

  async run(rawJob: WorkerJob, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerResult> {
    signal.throwIfAborted()
    const job = jobSchema.parse(rawJob)
    const payload = JSON.stringify(job)
    if (Buffer.byteLength(payload) > 16 * 1024 * 1024) throw new Error('Worker inputs exceeded their limit.')
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'guardian-' + randomUUID()
    const timeoutMs = (job.timeoutMs ?? 60_000) + 10_000
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    // One-shot containers exit before a pointer can be read via `docker exec`, so bind a host
    // tmpfs and read the spilled payload directly (validated by size + sha256).
    const ipcDir = makeOneShotIpcDir()
    const preparedRepos = prepareReposMount(options?.reposDir)
    const effectiveOptions = preparedRepos ? { ...options, reposDir: preparedRepos.mountDir } : options
    this.activeContainers.add(name)
    trackLiveContainer(name)
    try {
      await this.docker(this.containerCreateArgs(name, job.assignmentId, [], effectiveOptions, ipcDir), deadline)
      const result = await this.docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      const parsed = JSON.parse(result) as Record<string, unknown>
      if (parsed.resultRef) {
        return resultSchema.parse(readOneShotRef(ipcDir, parsed.resultRef))
      }
      return resultSchema.parse(parsed)
    } finally {
      try { rmSync(ipcDir, { recursive: true, force: true }) } catch { /* ignore */ }
      await this.removeContainer(name)
      preparedRepos?.cleanup()
      this.activeContainers.delete(name)
      liveContainers.delete(name)
    }
  }

  async verifyStaticAst(
    assignmentId: string,
    rawReq: AstVerifyRequest,
    signal: AbortSignal,
    options?: WorkerSessionOptions,
  ): Promise<AstVerifyResult> {
    signal.throwIfAborted()
    const req = astVerifyRequestSchema.parse(rawReq)
    const payload = JSON.stringify({ op: 'ast_verify', ...req })
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'guardian-' + randomUUID()
    const timeoutMs = (req.timeoutMs ?? 30_000) + 15_000
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    const preparedRepos = prepareReposMount(options?.reposDir)
    const effectiveOptions = preparedRepos ? { ...options, reposDir: preparedRepos.mountDir } : options
    this.activeContainers.add(name)
    trackLiveContainer(name)
    try {
      await this.docker(this.containerCreateArgs(name, assignmentId, [], effectiveOptions), deadline)
      const result = await this.docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return astVerifyResultSchema.parse(JSON.parse(result))
    } finally {
      await this.removeContainer(name)
      preparedRepos?.cleanup()
      this.activeContainers.delete(name)
      liveContainers.delete(name)
    }
  }

  async openSession(assignmentId: string, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
    signal.throwIfAborted()
    await this.reclaimInactive()
    signal.throwIfAborted()
    // Warm pool first (best-effort): a pre-created session container skips the create
    // round-trip. Mismatched options or an unavailable pool fall back to the cold path.
    const warm = this.warmPool && !options?.rpcMountDir ? await this.warmPool.take(signal, options) : null
    const pooled = warm !== null
    const name = warm ?? 'guardian-' + randomUUID()
    this.sessionsServed += 1
    if (pooled) this.pooled.add(name)
    else this.coldSessionCreates += 1
    this.activeContainers.add(name)
    trackLiveContainer(name)
    let preparedRepos: PreparedReposMount | null = null
    const cleanupRepos = () => { preparedRepos?.cleanup() }
    if (!pooled) {
      try {
        preparedRepos = prepareReposMount(options?.reposDir)
        const effectiveOptions = preparedRepos ? { ...options, reposDir: preparedRepos.mountDir } : options
        await this.docker(this.containerCreateArgs(name, assignmentId, ['--session'], effectiveOptions), AbortSignal.any([signal, AbortSignal.timeout(15_000)]))
      } catch (error) {
        await this.removeContainer(name)
        cleanupRepos()
        this.activeContainers.delete(name)
        liveContainers.delete(name)
        throw error
      }
    }

    let cli: ChildProcess
    try {
      // A container that exists but never gets `start` must not outlive this call: spawn can
      // throw synchronously (bad DOCKER_HOST, CLI removed) or be aborted by a dead session.
      cli = spawn('docker', ['container', 'start', '--attach', '--interactive', name], {
        env: dockerEnv(),
        stdio: ['pipe', 'pipe', 'pipe'],
      })
    } catch (error) {
      await this.removeContainer(name)
      cleanupRepos()
      this.activeContainers.delete(name)
      liveContainers.delete(name)
      throw error
    }
    const sessionStderr: Buffer[] = []
    let sessionStderrBytes = 0
    cli.stderr?.on('data', (chunk: Buffer) => {
      if (sessionStderrBytes >= maxDockerStderrBytes) return
      const remaining = maxDockerStderrBytes - sessionStderrBytes
      const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk
      sessionStderr.push(slice)
      sessionStderrBytes += slice.length
    })
    const removeContainer = () => this.removeContainer(name)
    cli.stdin?.on('error', () => { /* Ignore EPIPE or write-after-end during shutdown. */ })
    const pending = new Map<string, { resolve: (value: Record<string, unknown>) => void; reject: (err: Error) => void }>()
    let closed = false
    let closing: Promise<void> | undefined
    let exited = false
    let resolveExit: (() => void) | undefined
    const exitPromise = new Promise<void>(resolve => { resolveExit = resolve })
    // Set while a pooled container is being handed back: the child `close` handler must not
    // remove a container the pool is about to reuse.
    let preserveOnExit = false

    const failAll = (err: Error) => {
      for (const [, waiter] of pending) waiter.reject(err)
      pending.clear()
    }

    const decoder = new BoundedLineDecoder()
    const settleLine = (msg: { id?: string; ok?: boolean; error?: string } & Record<string, unknown>, waiter: { resolve: (value: Record<string, unknown>) => void; reject: (err: Error) => void }) => {
      if (!msg.resultRef) {
        pending.delete(msg.id!)
        if (msg.ok) waiter.resolve(msg)
        else waiter.reject(new Error(msg.error ?? 'Worker session operation failed.'))
        return
      }
      // Oversized payload: fetch the tmpfs file pointer, validate size + sha256, then settle.
      void readResultRef(name, msg.resultRef, AbortSignal.timeout(30_000), this.docker).then(hydrated => {
        pending.delete(msg.id!)
        if (hydrated.ok === false) waiter.reject(new Error(typeof hydrated.error === 'string' ? hydrated.error : 'Worker session operation failed.'))
        else waiter.resolve({ ...hydrated, id: msg.id, ok: true })
      }, error => {
        pending.delete(msg.id!)
        waiter.reject(error instanceof Error ? error : new Error(String(error)))
        // A broken pointer indicates a tampered/truncated worker response: end the session.
        failAll(new Error('Worker result pointer could not be verified.'))
        void close()
      })
    }
    const handleLine = (line: string) => {
      const trimmed = line.trim()
      if (!trimmed) return
      try {
        const msg = JSON.parse(trimmed) as { id?: string; ok?: boolean; error?: string } & Record<string, unknown>
        const waiter = msg.id ? pending.get(msg.id) : undefined
        if (!waiter) return
        settleLine(msg, waiter)
      } catch {
        // Ignore malformed noise
      }
    }
    cli.stdout?.on('data', (chunk: Buffer) => {
      let lines: string[]
      try {
        lines = decoder.push(chunk)
      } catch (err) {
        // Flood / oversized line: terminate the session rather than buffering unbounded output.
        failAll(err instanceof Error ? err : new Error(String(err)))
        void close()
        return
      }
      for (const line of lines) handleLine(line)
    })
    cli.once('close', code => {
      closed = true
      exited = true
      resolveExit?.()
      failAll(new Error(formatWorkerFailure(Buffer.concat(sessionStderr).toString('utf8'), code).replace(/^The isolated worker failed/, 'Isolated worker session exited unexpectedly')))
      // A session that never reached `close()` (crash, image pull, OOM) could leave a container in
      // `created` state; always remove it here so abandoned workers do not accumulate. Pooled
      // containers taking the graceful stop path are released by `close()` instead and stay live.
      this.activeContainers.delete(name)
      if (!preserveOnExit) {
        liveContainers.delete(name)
        void removeContainer().finally(cleanupRepos)
      }
    })
    cli.once('error', error => {
      closed = true
      exited = true
      resolveExit?.()
      failAll(error)
      preserveOnExit = false
      this.activeContainers.delete(name)
      liveContainers.delete(name)
      void removeContainer().finally(cleanupRepos)
    })

    const close = () => {
      if (closing) return closing
      closing = (async () => {
        closed = true
        // Warm reuse: a clean session (no pending op, process still alive) resets `/tmp` first,
        // then asks the worker to shut down so the stopped container can serve the next
        // assignment without a cold `container create`.
        const reusable = pooled && this.warmPool?.enabled === true && pending.size === 0 && !exited
        let recycled = false
        if (reusable) {
          // 1) Reset the tmpfs scratch while the bridge is still running; 2) stop the container
          // (the session protocol's shutdown is advisory — the bridge can keep stdin open, so the
          // container is explicitly stopped and then verified by the pool before reuse).
          const reset = await this.docker(
            ['container', 'exec', name, 'sh', '-c', WARM_SCRATCH_RESET_COMMAND],
            AbortSignal.timeout(4_000),
          ).then(() => true, () => false)
          if (reset && !exited) {
            preserveOnExit = true
            try {
              if (cli.stdin && !cli.stdin.writableEnded && !cli.stdin.destroyed) {
                cli.stdin.write(JSON.stringify({ id: 'shutdown', op: 'shutdown' }) + '\n')
              }
            } catch { /* ignore */ }
            try {
              await this.docker(['container', 'stop', '--time', '1', name], AbortSignal.timeout(10_000))
            } catch { /* fall through: release() verifies the state and removes a live container */ }
            let timer: NodeJS.Timeout | undefined
            await Promise.race([
              exitPromise,
              new Promise<void>(resolve => { timer = setTimeout(resolve, 2_000); timer.unref?.() }),
            ])
            if (timer) clearTimeout(timer)
            recycled = true
          }
        }
        try {
          if (cli.stdin && !cli.stdin.writableEnded && !cli.stdin.destroyed) {
            cli.stdin.end(JSON.stringify({ id: 'shutdown', op: 'shutdown' }) + '\n')
          }
        } catch { /* ignore */ }
        try { cli.kill() } catch { /* ignore */ }
        failAll(new Error('Isolated worker session closed.'))
        cli.stdout?.removeAllListeners('data')
        if (recycled && this.warmPool) {
          const kept = await this.warmPool.release(name)
          if (kept) {
            this.pooled.delete(name)
            this.activeContainers.delete(name)
            // release() re-tracks the container as live: the pool (not this session) owns it now.
            return
          }
        }
        preserveOnExit = false
        await this.removeContainer(name)
        cleanupRepos()
        this.pooled.delete(name)
        this.activeContainers.delete(name)
        liveContainers.delete(name)
      })()
      return closing
    }

    const onAbort = () => { void close() }
    signal.addEventListener('abort', onAbort, { once: true })
    if (signal.aborted) void close()

    let chain: Promise<unknown> = Promise.resolve()
    const request = (payload: Record<string, unknown>, opSignal: AbortSignal, timeoutMs = 70_000) => {
      const run = () => new Promise<Record<string, unknown>>((resolve, reject) => {
        if (closed || !cli.stdin || cli.stdin.writableEnded || cli.stdin.destroyed) {
          return reject(new Error('Worker session is closed.'))
        }
        if (opSignal.aborted) return reject(opSignal.reason instanceof Error ? opSignal.reason : new Error('Aborted'))
        const id = randomUUID()
        const timer = setTimeout(() => {
          pending.delete(id)
          void close()
          reject(new Error('Worker session operation timed out.'))
        }, timeoutMs)
        const abortHandler = () => {
          clearTimeout(timer)
          pending.delete(id)
          void close()
          reject(opSignal.reason instanceof Error ? opSignal.reason : new Error('Aborted'))
        }
        opSignal.addEventListener('abort', abortHandler, { once: true })
        pending.set(id, {
          resolve: value => {
            clearTimeout(timer)
            opSignal.removeEventListener('abort', abortHandler)
            resolve(value)
          },
          reject: err => {
            clearTimeout(timer)
            opSignal.removeEventListener('abort', abortHandler)
            reject(err)
          },
        })
        cli.stdin.write(JSON.stringify({ ...payload, id }) + '\n')
      })
      const next = chain.then(run, run)
      chain = next.catch(() => undefined)
      return next
    }

    return {
      async stage(fileName, content, opSignal) {
        const clean = pathSchema.parse(fileName)
        const res = await request({ op: 'stage', name: clean, content }, opSignal, 15_000)
        return String(res.path ?? '/evidence/' + clean)
      },
      async exec(command, outputs, opSignal, timeoutMs = 60_000) {
        const validOutputs = z.array(outputNameSchema).max(16).parse(outputs)
        const res = await request({ op: 'exec', command: command.slice(0, 16 * 1024), outputs: validOutputs, timeoutMs }, opSignal, timeoutMs + 10_000)
        return resultSchema.parse(res.result)
      },
      async analyze(tool, args, opSignal) {
        const res = await request({ op: 'analyze', tool, args }, opSignal, 30_000)
        return (res.result as Record<string, unknown>) ?? {}
      },
      async sast(rawReq, opSignal) {
        const parsed = sastScanRequestSchema.parse(rawReq)
        const timeoutMs = (parsed.timeoutMs ?? 60_000) + 15_000
        const res = await request({ op: 'sast', ...parsed }, opSignal, timeoutMs)
        return sastScanResultSchema.parse(res.result)
      },
      async runScript(rawReq, opSignal) {
        const parsed = offlineScriptRequestSchema.parse(rawReq)
        const timeoutMs = (parsed.timeoutMs ?? 30_000) + 10_000
        const res = await request({ op: 'script', ...parsed }, opSignal, timeoutMs)
        return offlineScriptResultSchema.parse(res.result)
      },
      async verifyScript(rawReq, opSignal) {
        const parsed = verifyScriptRequestSchema.parse(rawReq)
        const preparedCode = prepareVerifyScript(parsed.code, parsed.runtime, parsed.title)
        const timeoutMs = (parsed.timeoutMs ?? 90_000) + 15_000
        const res = await request({
          op: 'verify',
          runtime: parsed.runtime,
          code: preparedCode,
          nonce: parsed.nonce,
          ...(parsed.timeoutMs !== undefined ? { timeoutMs: parsed.timeoutMs } : {}),
          sdkFiles: readVerifySdkFiles(),
        }, opSignal, timeoutMs)
        return verifyScriptResultSchema.parse(res.result)
      },
      async verifyStaticAst(rawReq, opSignal) {
        const parsed = astVerifyRequestSchema.parse(rawReq)
        const timeoutMs = (parsed.timeoutMs ?? 30_000) + 10_000
        const res = await request({ op: 'ast_verify', ...parsed }, opSignal, timeoutMs)
        return astVerifyResultSchema.parse(res.result)
      },
      async callGraph(rawReq, opSignal) {
        const parsed = callGraphRequestSchema.parse(rawReq)
        const timeoutMs = (parsed.timeoutMs ?? 45_000) + 15_000
        const res = await request({ op: 'call_graph', ...parsed }, opSignal, timeoutMs)
        return callGraphResultSchema.parse(res.result)
      },
      async close() {
        signal.removeEventListener('abort', onAbort)
        await close()
      },
    }
  }
}
