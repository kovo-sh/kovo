import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, realpathSync, statSync } from 'node:fs'
import { z } from 'zod'
import type { AnalyzerName } from '../../worker/analyzers.ts'

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
/** A container may legitimately sit in `created` only for the create→start instant. */
const DEFAULT_STALE_CREATED_MS = 120_000
const processSessionId = randomUUID()
const liveContainers = new Set<string>()
/** Process-scoped label value carried by every worker container (test/diagnostic seam). */
export function workerProcessSessionId() {
  return processSessionId
}
let liveExitHookInstalled = false
function removeLiveContainers(budgetMs = 4_000) {
  const deadline = Date.now() + budgetMs
  for (const container of [...liveContainers]) {
    const remaining = deadline - Date.now()
    if (remaining <= 0) break
    try { spawnSync('docker', ['container', 'rm', '--force', container], { stdio: 'ignore', timeout: Math.min(5_000, remaining) }) } catch { /* best-effort */ }
    liveContainers.delete(container)
  }
}
function trackLiveContainer(name: string) {
  liveContainers.add(name)
  if (liveExitHookInstalled) return
  liveExitHookInstalled = true
  // Remove any container this process created but did not get to start/close
  // (for example an aborted session between `docker create` and `docker start`,
  // or a Playwright-owned server terminated with SIGTERM). Shutdown cleanup is strictly bounded so
  // a slow/unreachable Docker daemon can never block process exit (and E2E teardown).
  process.once('exit', () => removeLiveContainers(1_500))
  process.once('SIGTERM', () => { removeLiveContainers(2_000); process.exit(143) })
  process.once('SIGINT', () => { removeLiveContainers(2_000); process.exit(130) })
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
}

export interface WorkerBackend {
  run(job: WorkerJob, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerResult>
  openSession(assignmentId: string, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession>
  verifyStaticAst(assignmentId: string, req: AstVerifyRequest, signal: AbortSignal, options?: WorkerSessionOptions): Promise<AstVerifyResult>
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

type DockerRunner = (args: string[], signal: AbortSignal, input?: string) => Promise<string>
/** The real CLI executor, exported so Docker-gated tests can wrap it (e.g. force a start failure). */
export const dockerCliRunner: DockerRunner = docker

export class LinuxWorkerBackend implements WorkerBackend {
  private readonly image: string
  private readonly owner?: string
  private readonly runId?: string
  private readonly docker: DockerRunner
  private readonly staleCreatedMs: number
  private readonly activeContainers = new Set<string>()
  private readonly removals = new Map<string, Promise<void>>()
  private reclaiming?: Promise<void>

  constructor({ image = 'guardian-worker:v4', workspace, runId, dockerRunner, staleCreatedMs }: {
    image?: string
    workspace?: { id: string; directory: string }
    runId?: string
    /** Test seam: replace the docker CLI executor (defaults to the real CLI). */
    dockerRunner?: DockerRunner
    /** Grace before an abandoned `created` container is reclaimed (default 2 min). */
    staleCreatedMs?: number
  } = {}) {
    this.image = image
    this.runId = runId
    this.docker = dockerRunner ?? docker
    this.staleCreatedMs = Math.max(0, staleCreatedMs ?? DEFAULT_STALE_CREATED_MS)
    if (workspace) {
      this.owner = createHash('sha256').update(workspace.id).update('\0').update(realpathSync(workspace.directory)).digest('hex')
    }
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
    const existing = this.removals.get(name)
    if (existing) return existing
    const removal = this.docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000))
      .then(() => undefined, () => undefined)
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
      if (this.activeContainers.has(name)) continue
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

  private resolveReposMountArgs(reposDir?: string): string[] {
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

  private containerCreateArgs(name: string, assignmentId: string, extraArgs: string[] = [], options?: WorkerSessionOptions) {
    // Every container is attributable even when the caller did not supply a run id:
    // `run` falls back to the workspace hash or this process's ad-hoc session.
    const runLabelValue = this.runId ?? (this.owner ? `workspace-${this.owner.slice(0, 12)}` : `adhoc-${processSessionId.slice(0, 8)}`)
    // Default 1536m RAM, 2.0 CPU, 256 PIDs (ceiling: 4096m / 4.0 / 384)
    const memoryMb = Math.round(clamp(options?.memoryMb, 1536, 512, 4096))
    const cpus = Number(clamp(options?.cpus, 2.0, 0.5, 4.0).toFixed(2))
    const pidsLimit = Math.round(clamp(options?.pidsLimit, 256, 64, 384))
    const tmpfsMb = Math.round(clamp(options?.tmpfsMb, 128, 64, 512))
    return [
      // No `--rm`: Docker's automatic removal races the explicit `rm --force` below and the
      // daemon answers "removal of container ... is already in progress", which previously
      // surfaced as a failed worker session. Explicit removal is the single mechanism.
      'container', 'create', '--name', name, '--interactive', '--pull', 'never',
      '--network', 'none', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--pids-limit', String(pidsLimit),
      '--cpus', String(cpus),
      '--memory', `${memoryMb}m`, '--memory-swap', `${memoryMb}m`,
      '--tmpfs', `/tmp:rw,nosuid,nodev,noexec,size=${tmpfsMb}m,mode=1777`,
      ...this.resolveReposMountArgs(options?.reposDir),
      '--label', `${assignmentNamespace}=` + assignmentId,
      '--label', `${runNamespace}=${runLabelValue}`,
      ...(this.owner ? ['--label', `${workerNamespace}=${this.owner}`] : []),
      '--label', `${sessionNamespace}=${processSessionId}`,
      '--label', `${createdAtNamespace}=` + Date.now(),
      this.image,
      ...extraArgs,
    ]
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
    this.activeContainers.add(name)
    trackLiveContainer(name)
    try {
      await this.docker(this.containerCreateArgs(name, job.assignmentId, [], options), deadline)
      const result = await this.docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return resultSchema.parse(JSON.parse(result))
    } finally {
      await this.removeContainer(name)
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
    this.activeContainers.add(name)
    trackLiveContainer(name)
    try {
      await this.docker(this.containerCreateArgs(name, assignmentId, [], options), deadline)
      const result = await this.docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return astVerifyResultSchema.parse(JSON.parse(result))
    } finally {
      await this.removeContainer(name)
      this.activeContainers.delete(name)
      liveContainers.delete(name)
    }
  }

  async openSession(assignmentId: string, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
    signal.throwIfAborted()
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'guardian-' + randomUUID()
    this.activeContainers.add(name)
    trackLiveContainer(name)
    try {
      await this.docker(this.containerCreateArgs(name, assignmentId, ['--session'], options), AbortSignal.any([signal, AbortSignal.timeout(15_000)]))
    } catch (error) {
      await this.removeContainer(name)
      this.activeContainers.delete(name)
      liveContainers.delete(name)
      throw error
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

    const failAll = (err: Error) => {
      for (const [, waiter] of pending) waiter.reject(err)
      pending.clear()
    }

    const decoder = new BoundedLineDecoder()
    const handleLine = (line: string) => {
      const trimmed = line.trim()
      if (!trimmed) return
      try {
        const msg = JSON.parse(trimmed) as { id?: string; ok?: boolean; error?: string } & Record<string, unknown>
        const waiter = msg.id ? pending.get(msg.id) : undefined
        if (!waiter) return
        pending.delete(msg.id!)
        if (msg.ok) waiter.resolve(msg)
        else waiter.reject(new Error(msg.error ?? 'Worker session operation failed.'))
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
      failAll(new Error(formatWorkerFailure(Buffer.concat(sessionStderr).toString('utf8'), code).replace(/^The isolated worker failed/, 'Isolated worker session exited unexpectedly')))
      // A session that never reached `close()` (crash, image pull, OOM) could leave a container in
      // `created` state; always remove it here so abandoned workers do not accumulate.
      this.activeContainers.delete(name)
      liveContainers.delete(name)
      void removeContainer()
    })
    cli.once('error', error => {
      closed = true
      failAll(error)
      this.activeContainers.delete(name)
      liveContainers.delete(name)
      void removeContainer()
    })

    const close = () => {
      if (closing) return closing
      closing = (async () => {
        closed = true
        try {
          if (cli.stdin && !cli.stdin.writableEnded && !cli.stdin.destroyed) {
            cli.stdin.end(JSON.stringify({ id: 'shutdown', op: 'shutdown' }) + '\n')
          }
        } catch { /* ignore */ }
        try { cli.kill() } catch { /* ignore */ }
        failAll(new Error('Isolated worker session closed.'))
        cli.stdout?.removeAllListeners('data')
        await this.removeContainer(name)
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
