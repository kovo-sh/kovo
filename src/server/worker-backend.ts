import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, realpathSync, statSync } from 'node:fs'
import { createInterface } from 'node:readline'
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
const liveContainers = new Set<string>()
let liveExitHookInstalled = false
function removeLiveContainers() {
  for (const container of liveContainers) {
    try { spawnSync('docker', ['container', 'rm', '--force', container], { stdio: 'ignore', timeout: 5_000 }) } catch { /* best-effort */ }
  }
}
function trackLiveContainer(name: string) {
  liveContainers.add(name)
  if (liveExitHookInstalled) return
  liveExitHookInstalled = true
  // Remove any container this process created but did not get to start/close
  // (for example an aborted session between `docker create` and `docker start`,
  // or a Playwright-owned server terminated with SIGTERM).
  process.once('exit', removeLiveContainers)
  process.once('SIGTERM', () => { removeLiveContainers(); process.exit(143) })
  process.once('SIGINT', () => { removeLiveContainers(); process.exit(130) })
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

function docker(args: string[], signal: AbortSignal, input?: string) {
  signal.throwIfAborted()
  return new Promise<string>((resolve, reject) => {
    const cli = spawn('docker', args, {
      signal,
      env: dockerEnv(),
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    const chunks: Buffer[] = []
    let size = 0
    const limit = 16 * 1024 * 1024
    cli.stdout.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > limit) {
        cli.kill()
        reject(new Error('Worker output exceeded its limit.'))
      } else chunks.push(chunk)
    })
    cli.stdin.on('error', () => { /* Early exit closes stdin. */ })
    cli.stdin.end(input)
    cli.once('error', error => reject(signal.aborted ? signal.reason : error))
    cli.once('close', code => {
      if (code === 0) resolve(Buffer.concat(chunks).toString('utf8'))
      else reject(new Error('The isolated worker failed. Build the local worker image and check Docker availability.'))
    })
  })
}

export class LinuxWorkerBackend implements WorkerBackend {
  private readonly image: string
  private readonly owner?: string
  private readonly activeContainers = new Set<string>()
  private reclaiming?: Promise<void>

  constructor({ image = 'guardian-worker:v4', workspace }: {
    image?: string
    workspace?: { id: string; directory: string }
  } = {}) {
    this.image = image
    if (workspace) {
      this.owner = createHash('sha256').update(workspace.id).update('\0').update(realpathSync(workspace.directory)).digest('hex')
    }
  }

  reclaimInactive() {
    if (!this.owner) return Promise.resolve()
    return this.reclaiming ??= this.removeInactive(this.owner).finally(() => {
      this.reclaiming = undefined
    })
  }

  private async removeInactive(owner: string) {
    const signal = AbortSignal.timeout(5_000)
    const list = async () => {
      const rows = await docker([
        'container', 'ls', '--all', '--no-trunc', '--filter', `label=${workerNamespace}=${owner}`,
        '--format', '{{.ID}}\t{{.Names}}',
      ], signal)
      return rows.trim().split('\n').flatMap(row => {
        const [id, name] = row.split('\t')
        return /^[a-f0-9]{64}$/.test(id) && workerName.test(name) && !this.activeContainers.has(name) ? [id] : []
      })
    }
    const inactive = await list()
    if (!inactive.length) return
    try {
      await docker(['container', 'rm', '--force', ...inactive], signal)
    } catch (error) {
      if ((await list()).length) throw error
    }
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
    // Default 1536m RAM, 2.0 CPU, 256 PIDs (ceiling: 4096m / 4.0 / 384)
    const memoryMb = Math.round(clamp(options?.memoryMb, 1536, 512, 4096))
    const cpus = Number(clamp(options?.cpus, 2.0, 0.5, 4.0).toFixed(2))
    const pidsLimit = Math.round(clamp(options?.pidsLimit, 256, 64, 384))
    const tmpfsMb = Math.round(clamp(options?.tmpfsMb, 128, 64, 512))
    return [
      'container', 'create', '--name', name, '--interactive', '--rm', '--pull', 'never',
      '--network', 'none', '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--pids-limit', String(pidsLimit),
      '--cpus', String(cpus),
      '--memory', `${memoryMb}m`, '--memory-swap', `${memoryMb}m`,
      '--tmpfs', `/tmp:rw,nosuid,nodev,noexec,size=${tmpfsMb}m,mode=1777`,
      ...this.resolveReposMountArgs(options?.reposDir),
      '--label', 'dev.guardian.assignment=' + assignmentId,
      ...(this.owner ? ['--label', `${workerNamespace}=${this.owner}`] : []),
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
      await docker(this.containerCreateArgs(name, job.assignmentId, [], options), deadline)
      const result = await docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return resultSchema.parse(JSON.parse(result))
    } finally {
      await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
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
      await docker(this.containerCreateArgs(name, assignmentId, [], options), deadline)
      const result = await docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return astVerifyResultSchema.parse(JSON.parse(result))
    } finally {
      await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
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
      await docker(this.containerCreateArgs(name, assignmentId, ['--session'], options), AbortSignal.any([signal, AbortSignal.timeout(15_000)]))
    } catch (error) {
      await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
      this.activeContainers.delete(name)
      liveContainers.delete(name)
      throw error
    }

    const cli: ChildProcess = spawn('docker', ['container', 'start', '--attach', '--interactive', name], {
      env: dockerEnv(),
      stdio: ['pipe', 'pipe', 'ignore'],
    })
    cli.stdin?.on('error', () => { /* Ignore EPIPE or write-after-end during shutdown. */ })
    const pending = new Map<string, { resolve: (value: Record<string, unknown>) => void; reject: (err: Error) => void }>()
    let closed = false
    let closing: Promise<void> | undefined

    const failAll = (err: Error) => {
      for (const [, waiter] of pending) waiter.reject(err)
      pending.clear()
    }

    const rl = createInterface({ input: cli.stdout!, crlfDelay: Infinity })
    rl.on('line', line => {
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
    })
    cli.once('close', () => {
      closed = true
      failAll(new Error('Isolated worker session exited unexpectedly.'))
    })
    cli.once('error', error => {
      closed = true
      failAll(error)
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
        rl.close()
        await docker(['container', 'rm', '--force', name], AbortSignal.timeout(5_000)).catch(() => undefined)
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
