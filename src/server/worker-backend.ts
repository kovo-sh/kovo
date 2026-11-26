import { spawn, spawnSync } from 'node:child_process'
import type { ChildProcess } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  chownSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs'
import { basename, dirname, isAbsolute, join, posix, relative, resolve as resolvePath, sep } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import ipaddr from 'ipaddr.js'
import { z } from 'zod'
import type { AnalyzerName } from '../../worker/analyzers.ts'
import { isSensitiveRepoEntry } from './safety-primitives.ts'
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
const workerNamespace = 'dev.kovo.workspace'
// Attribution labels: a leaked container must identify its run/assignment/session.
const runNamespace = 'dev.kovo.run'
const assignmentNamespace = 'dev.kovo.assignment'
const sessionNamespace = 'dev.kovo.session'
const createdAtNamespace = 'dev.kovo.created-at'
/** Matrix cells label every container so the cell reaper can remove exactly its own. */
const cellNamespace = 'dev.kovo.cell'
const warmNamespace = 'dev.kovo.warm'
/** Host PID that created/owns the container; stale sweep never reaps live-PID containers. */
export const WORKER_OWNER_PID_LABEL = 'kovo.owner_pid'
/** Linux PID namespace inode link (`pid:[...]`) of the owner process. */
export const WORKER_OWNER_PID_NS_LABEL = 'kovo.owner_pid_ns'
/** Process start time in clock ticks (`/proc/<pid>/stat` field 22) to defeat PID reuse. */
export const WORKER_OWNER_START_TIME_LABEL = 'kovo.owner_start_time'
/** Process session label stamped on every worker container. */
export const WORKER_SESSION_LABEL = sessionNamespace
/** Pool or backend instance id stamped on containers for ownership attribution. */
export const WORKER_POOL_INSTANCE_LABEL = 'kovo.pool_instance'
/** A container may legitimately sit in `created` only for the create→start instant. */
const DEFAULT_STALE_CREATED_MS = 120_000
/** Foreign-namespace containers (e.g. host CLI vs DooD server) cannot use local `kill(pid, 0)`; spare until TTL. */
export const DEFAULT_FOREIGN_OWNER_TTL_MS = 30 * 60_000

/** Read current process PID namespace (`pid:[...]`), or `null` when `/proc` is unavailable. */
export function currentPidNamespace(): string | null {
  try {
    const link = readlinkSync('/proc/self/ns/pid').trim()
    return link || null
  } catch {
    return null
  }
}

/** Read process start ticks (field 22 of `/proc/<pid>/stat`), or `null` when unavailable. */
export function readProcStartTicks(pid: number | 'self' = 'self'): string | null {
  try {
    const raw = readFileSync(`/proc/${pid}/stat`, 'utf8')
    const closeParen = raw.lastIndexOf(')')
    if (closeParen < 0) return null
    const rest = raw.slice(closeParen + 1).trim().split(/\s+/)
    const startTicks = rest[19]
    return startTicks && /^\d+$/.test(startTicks) ? startTicks : null
  } catch {
    return null
  }
}

function normalizeDockerLabel(raw: string | undefined): string | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed || trimmed === '<no value>') return null
  return trimmed
}

/**
 * Return `true` if host `pid` is still alive, `false` when definitely dead (`ESRCH`).
 * `EPERM` means the process exists under another UID, so we fail safe and treat it as alive.
 */
export function isOwnerPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code
    if (code === 'ESRCH') return false
    return true
  }
}

/**
 * Namespace-safe owner liveness check (H-31):
 * - Returns `true` when the owner is provably dead in the **same** PID namespace
 *   (`ESRCH` or recycled PID whose `/proc/<pid>/stat` start time changed).
 * - Returns `false` when the owner is alive in the **same** PID namespace.
 * - Returns `null` when the container belongs to a **foreign** PID namespace (e.g. host CLI vs
 *   DooD container) so callers fall back to a foreign TTL instead of misreading `ESRCH`.
 */
export function isOwnerProvablyDead(
  owner: { pid: number; pidNs?: string | null; startTime?: string | null },
  options: {
    currentPidNs?: string | null
    isPidAlive?: (pid: number) => boolean
    readPidStartTime?: (pid: number) => string | null
  } = {},
): boolean | null {
  const pidNs = normalizeDockerLabel(owner.pidNs ?? undefined)
  const currentNs = options.currentPidNs !== undefined ? options.currentPidNs : currentPidNamespace()
  if (pidNs !== null && (!currentNs || pidNs !== currentNs)) {
    return null
  }
  const checkAlive = options.isPidAlive ?? isOwnerPidAlive
  if (!checkAlive(owner.pid)) return true
  const expectedStart = normalizeDockerLabel(owner.startTime ?? undefined)
  if (expectedStart !== null) {
    const readStart = options.readPidStartTime ?? readProcStartTicks
    const liveStart = readStart(owner.pid)
    if (liveStart !== null && liveStart !== expectedStart) return true
  }
  return false
}

function parseOwnerPid(raw: string | undefined): number | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!/^\d+$/.test(trimmed)) return null
  const pid = Number(trimmed)
  return Number.isSafeInteger(pid) && pid > 0 ? pid : null
}
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
  let env: NodeJS.ProcessEnv | undefined
  try { env = dockerEnv() } catch { env = undefined }
  for (const container of [...liveContainers]) {
    const remaining = deadline - Date.now()
    if (remaining <= 0) break
    try { spawnSync('docker', ['container', 'rm', '--force', container], { stdio: 'ignore', ...(env ? { env } : {}), timeout: Math.min(5_000, remaining) }) } catch { /* best-effort */ }
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
const workerName = /^kovo-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/

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
  runtime: z.literal('ts'),
  code: z.string().min(1).max(256 * 1024),
  nonce: z.string().regex(/^[a-f0-9]{16,128}$/i),
  title: z.string().max(300).optional(),
  timeoutMs: z.number().int().min(1_000).max(120_000).optional(),
})

export const verifyScriptResultSchema = z.object({
  runtime: z.literal('ts'),
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
  /** Layer-3 `kovo_verify` script; claims are oracle-checked host-side. */
  verifyScript?(req: VerifyScriptRequest, signal: AbortSignal): Promise<VerifyScriptResult>
  verifyStaticAst(req: AstVerifyRequest, signal: AbortSignal): Promise<AstVerifyResult>
  callGraph?(req: CallGraphRequest, signal: AbortSignal): Promise<CallGraphResult>
  close(): Promise<void>
}

export interface WorkerSessionOptions {
  reposDir?: string
  /** Optional run identifier used to share a single immutable per-run `/repos` snapshot across workers. */
  runId?: string
  memoryMb?: number
  cpus?: number
  pidsLimit?: number
  tmpfsMb?: number
  /**
   * Host directory holding the Layer-1 verification RPC socket/token/context. Mounted read-only
   * at `/kovo-rpc`; the rest of the container filesystem stays read-only.
   */
  rpcMountDir?: string
  /**
   * Optional warm-pool policy key (`${runId}:${secretEpoch}`). When provided, `openSession`
   * acquires strictly from that policy's pool and never takes a container from another run's pool.
   */
  warmPoolPolicy?: string
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
  /** Container image tag used by this backend (container-visible isolation input for warm-pool keying). */
  readonly workerImage?: string
  /** Container-reuse counters (diagnostic seam; optional for test/fake backends). */
  containerStats?(): WorkerContainerStats | undefined
  /** Size the warm idle pool to the run's worker-slot count (one container per slot). */
  setWarmCapacity?(slots: number): void
  /**
   * Install the run's pool policy (run identity + container-visible mount/image policy, plus
   * optional read-only repo mount). A changed policy discards idle containers instead of reusing
   * them across runs, tenants, or repo mounts.
   */
  setWarmPoolPolicy?(policy: string, options?: { reposDir?: string }): void
  /** Evict and close all warm-pool containers/leases owned by `runId` on run disposal. */
  evictRunWarmPool?(runId: string): Promise<void>
  /** Remove idle warm containers on teardown instead of leaving them on the host. */
  closeWarmPool?(): Promise<void>
}

function clamp(val: number | undefined, fallback: number, min: number, max: number): number {
  if (val === undefined || !Number.isFinite(val)) return fallback
  return Math.max(min, Math.min(max, val))
}

function isContainerUid10001(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 10001
}

function isDoodScratchConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return Boolean(env.KOVO_HOST_SCRATCH_DIR?.trim() || env.KOVO_WORKER_SCRATCH_VOLUME?.trim())
}

function parseDockerTcpHost(host: string): { hostname: string; port: number } | null {
  if (/[\0\r\n\s]/.test(host)) return null
  const m = /^tcp:\/\/(\[[^\]]+\]|[^:/?#\r\n]+):(\d{1,5})$/.exec(host)
  if (!m) return null
  const port = Number(m[2])
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  return { hostname: m[1].toLowerCase(), port }
}

const COMPOSE_SERVICE_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i
const BLOCKED_COMPOSE_HOSTNAMES = new Set(['metadata', 'metadata.google.internal'])

function isAllowedDockerTcpHost(host: string, env: NodeJS.ProcessEnv): boolean {
  const parsed = parseDockerTcpHost(host)
  if (!parsed) return false
  if (env.KOVO_ALLOW_REMOTE_DOCKER_HOST === '1') return true
  const bare = parsed.hostname.startsWith('[') && parsed.hostname.endsWith(']')
    ? parsed.hostname.slice(1, -1)
    : parsed.hostname
  if (bare === 'docker-proxy' || bare === 'localhost') return true
  if (ipaddr.isValid(bare)) {
    const range = ipaddr.process(bare).range()
    if (range === 'loopback') return true
    if (isDoodScratchConfigured(env) && (range === 'private' || range === 'uniqueLocal')) return true
    return false
  }
  if (!isDoodScratchConfigured(env)) return false
  if (BLOCKED_COMPOSE_HOSTNAMES.has(bare)) return false
  // Allow single-label Docker Compose DNS proxy names (e.g. `docker-proxy`, `custom-socket-proxy`),
  // `host.docker.internal`, or explicit `.local` compose suffixes — never arbitrary public/metadata domains.
  if (COMPOSE_SERVICE_LABEL_RE.test(bare)) return true
  if (bare === 'host.docker.internal') return true
  if (bare.endsWith('.local') && /^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.local$/i.test(bare) && !bare.includes('metadata')) return true
  return false
}

export function dockerHost(env: NodeJS.ProcessEnv = process.env): string {
  const host = env.DOCKER_HOST?.trim() || 'unix:///var/run/docker.sock'
  if (/^unix:\/\/\/[^/?#\r\n][^?#\r\n]*$/.test(host)) {
    return host
  }
  if (isAllowedDockerTcpHost(host, env)) {
    return host
  }
  throw new Error('Kovo Hunter requires a local Docker Unix socket.')
}

export function dockerEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return {
    PATH: env.PATH,
    DOCKER_HOST: dockerHost(env),
    XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR,
  }
}

export type DoodScratchConfig =
  | {
      mode: 'host_bind'
      containerScratchDir: string
      hostScratchDir: string
    }
  | {
      mode: 'volume_subpath'
      containerScratchDir: string
      volumeName: string
    }

const DOCKER_VOLUME_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/
const SCRATCH_SESSION_ID_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/

function hasDotDotSegment(rawPath: string): boolean {
  return rawPath.split(/[\\/]+/).includes('..')
}

function resolveWithExistingAncestor(targetPath: string): string {
  const normalized = posix.resolve(targetPath)
  if (existsSync(normalized)) {
    return realpathSync(normalized)
  }
  const tail: string[] = []
  let cursor = normalized
  while (cursor !== '/' && !existsSync(cursor)) {
    tail.unshift(posix.basename(cursor))
    cursor = posix.dirname(cursor)
  }
  const base = existsSync(cursor) ? realpathSync(cursor) : cursor
  return posix.join(base, ...tail)
}

function normalizeHostScratchRoot(rawHostPath: string): string {
  if (/[\0,\r\n]/.test(rawHostPath) || hasDotDotSegment(rawHostPath)) {
    throw new Error('Invalid KOVO_HOST_SCRATCH_DIR path.')
  }
  if (!/^(?:\/|[A-Za-z]:[\\/])/.test(rawHostPath)) {
    throw new Error('KOVO_HOST_SCRATCH_DIR must be an absolute host path.')
  }
  if (/^[A-Za-z]:[\\/]/.test(rawHostPath)) {
    const trimmed = rawHostPath.replace(/[\\/]+$/, '')
    return trimmed.length === 2 ? `${trimmed}/` : trimmed.replace(/\\/g, '/')
  }
  const normalized = posix.resolve(rawHostPath)
  if (normalized === '/') {
    throw new Error('KOVO_HOST_SCRATCH_DIR must not be root "/".')
  }
  return normalized
}

export function resolveDoodScratchConfig(env: NodeJS.ProcessEnv = process.env): DoodScratchConfig | null {
  const hostScratchRaw = env.KOVO_HOST_SCRATCH_DIR?.trim() || ''
  const volumeRaw = env.KOVO_WORKER_SCRATCH_VOLUME?.trim() || ''
  if (!hostScratchRaw && !volumeRaw) {
    return null
  }
  const containerRaw = env.KOVO_CONTAINER_SCRATCH_DIR?.trim() || '/scratch'
  if (/[\0,\r\n]/.test(containerRaw) || !containerRaw.startsWith('/') || hasDotDotSegment(containerRaw)) {
    throw new Error('Invalid KOVO_CONTAINER_SCRATCH_DIR path.')
  }
  const containerScratchDir = posix.resolve(containerRaw)
  if (containerScratchDir === '/') {
    throw new Error('KOVO_CONTAINER_SCRATCH_DIR must not be root "/".')
  }
  if (hostScratchRaw) {
    return {
      mode: 'host_bind',
      containerScratchDir,
      hostScratchDir: normalizeHostScratchRoot(hostScratchRaw),
    }
  }
  if (!DOCKER_VOLUME_NAME_RE.test(volumeRaw)) {
    throw new Error('Invalid KOVO_WORKER_SCRATCH_VOLUME name.')
  }
  return {
    mode: 'volume_subpath',
    containerScratchDir,
    volumeName: volumeRaw,
  }
}

function assertValidScratchSessionId(sessionId: string): string {
  if (!SCRATCH_SESSION_ID_RE.test(sessionId) || sessionId === '.' || sessionId === '..') {
    throw new Error('Invalid worker scratch session identifier.')
  }
  return sessionId
}

function relativeScratchSubpath(containerBase: string, containerPath: string): string {
  if (/[\0,\r\n]/.test(containerPath) || !containerPath.startsWith('/') || hasDotDotSegment(containerPath)) {
    throw new Error('Invalid worker scratch mount path.')
  }
  const resolvedBase = resolveWithExistingAncestor(containerBase)
  const resolvedTarget = resolveWithExistingAncestor(containerPath)
  const rel = posix.relative(resolvedBase, resolvedTarget)
  if (!rel || rel === '.' || rel === '..' || rel.startsWith('../') || isAbsolute(rel) || hasDotDotSegment(rel)) {
    throw new Error('Worker scratch mount must target a per-session subdirectory within KOVO_CONTAINER_SCRATCH_DIR.')
  }
  return rel
}

export function prepareSessionScratchDir(
  sessionId: string,
  subdir?: string,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const config = resolveDoodScratchConfig(env)
  if (!config) {
    throw new Error('Sibling-container scratch mode is not configured.')
  }
  const safeSession = assertValidScratchSessionId(sessionId)
  const baseDir = config.containerScratchDir
  const dirMode = isContainerUid10001() ? 0o700 : 0o755
  mkdirSync(baseDir, { recursive: true, mode: dirMode })
  const sessionDir = join(baseDir, safeSession)
  mkdirSync(sessionDir, { recursive: true, mode: dirMode })
  chmodSync(sessionDir, dirMode)
  let targetDir = sessionDir
  if (subdir !== undefined) {
    if (/[\0,\r\n]/.test(subdir) || subdir.startsWith('/') || subdir.startsWith('\\') || hasDotDotSegment(subdir)) {
      throw new Error('Invalid worker scratch subdirectory.')
    }
    const parts = subdir.split(/[\\/]+/).filter(Boolean)
    if (parts.length === 0) {
      throw new Error('Invalid worker scratch subdirectory.')
    }
    targetDir = join(sessionDir, ...parts)
    mkdirSync(targetDir, { recursive: true, mode: dirMode })
    chmodSync(targetDir, dirMode)
  }
  relativeScratchSubpath(baseDir, targetDir)
  return targetDir
}

export function resolveDoodMountArg(
  containerPath: string,
  targetPath: string,
  options: { readonly?: boolean; env?: NodeJS.ProcessEnv } = {},
): string {
  if (/[\0,\r\n]/.test(targetPath) || !targetPath.startsWith('/')) {
    throw new Error('Invalid worker container mount target.')
  }
  const readonlySuffix = options.readonly ? ',readonly' : ''
  const config = resolveDoodScratchConfig(options.env)
  if (!config) {
    if (/[\0,\r\n]/.test(containerPath)) {
      throw new Error('Invalid host mount path.')
    }
    return `type=bind,source=${realpathSync(containerPath)},target=${targetPath}${readonlySuffix}`
  }
  const rel = relativeScratchSubpath(config.containerScratchDir, containerPath)
  if (config.mode === 'host_bind') {
    const hostPath = posix.join(config.hostScratchDir, rel)
    return `type=bind,source=${hostPath},target=${targetPath}${readonlySuffix}`
  }
  return `type=volume,source=${config.volumeName},target=${targetPath},volume-subpath=${rel}${readonlySuffix}`
}

export function workerAutoPullEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const raw = env.KOVO_WORKER_AUTO_PULL?.trim().toLowerCase()
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on'
}

const DEFAULT_WORKER_PULL_TIMEOUT_MS = 300_000
const inflightImagePulls = new WeakMap<DockerRunner, Map<string, Promise<void>>>()

function workerPullTimeoutMs(explicit?: number, env: NodeJS.ProcessEnv = process.env): number {
  if (explicit !== undefined && Number.isFinite(explicit)) {
    return clamp(explicit, DEFAULT_WORKER_PULL_TIMEOUT_MS, 1_000, 900_000)
  }
  const fromEnv = Number(env.KOVO_WORKER_PULL_TIMEOUT_MS)
  if (Number.isFinite(fromEnv) && fromEnv > 0) {
    return clamp(fromEnv, DEFAULT_WORKER_PULL_TIMEOUT_MS, 1_000, 900_000)
  }
  return DEFAULT_WORKER_PULL_TIMEOUT_MS
}

function raceWithAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    return Promise.reject(signal.reason instanceof Error ? signal.reason : new Error('Aborted'))
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      reject(signal.reason instanceof Error ? signal.reason : new Error('Aborted'))
    }
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      value => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      err => {
        signal.removeEventListener('abort', onAbort)
        reject(err)
      },
    )
  })
}

export async function ensureWorkerImageAvailable(
  image: string,
  dockerRunner: DockerRunner,
  signal: AbortSignal,
  options: { env?: NodeJS.ProcessEnv; pullTimeoutMs?: number } = {},
): Promise<void> {
  const env = options.env ?? process.env
  if (!workerAutoPullEnabled(env)) return
  signal.throwIfAborted()
  if (!image || /[\s\0\r\n]/.test(image) || image.startsWith('-')) {
    throw new Error('Invalid worker container image reference.')
  }
  let perRunner = inflightImagePulls.get(dockerRunner)
  if (!perRunner) {
    perRunner = new Map<string, Promise<void>>()
    inflightImagePulls.set(dockerRunner, perRunner)
  }
  const existing = perRunner.get(image)
  if (existing) {
    await raceWithAbort(existing, signal)
    return
  }
  const timeoutMs = workerPullTimeoutMs(options.pullTimeoutMs, env)
  const task = (async () => {
    try {
      await dockerRunner(['image', 'inspect', image], AbortSignal.timeout(10_000))
      return
    } catch {
      // Missing locally (or inspect failed): attempt bounded pull once.
    }
    try {
      await dockerRunner(['pull', image], AbortSignal.timeout(timeoutMs))
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      throw new Error(`Failed to pull worker image "${image}": ${detail}`)
    }
  })().finally(() => {
    perRunner?.delete(image)
  })
  perRunner.set(image, task)
  await raceWithAbort(task, signal)
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

const workerRefPath = /^\/tmp\/kovo-ipc\/[a-f0-9-]{36}\.json$/
const oneShotRefPath = /^\/kovo-ipc\/[a-f0-9-]{36}\.json$/
const resultRefSchema = z.object({
  path: z.string().regex(workerRefPath),
  bytes: z.number().int().positive().max(MAX_WORKER_REF_BYTES),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
})
const oneShotRefSchema = resultRefSchema.extend({ path: z.string().regex(oneShotRefPath) })

/**
 * Resolve the supplementary host GID passed to `--group-add` so non-root container UID `10001`
 * can access group-scoped (`0o750`/`0o770`/`0o640`/`0o660`) RPC/IPC mounts without world bits.
 * Returns `null` when host runs as UID `10001` (owner-only `0o700`/`0o600`), root (`uid=0`),
 * or when no positive non-root GID is available (never emits `--group-add 0`).
 */
export function resolveWorkerSharedGid(env: NodeJS.ProcessEnv = process.env): number | null {
  if (isContainerUid10001()) return null
  if (typeof process.getuid === 'function' && process.getuid() === 0) return null
  const override = env.KOVO_WORKER_SHARED_GID?.trim()
  if (override) {
    const parsed = Number(override)
    if (Number.isInteger(parsed) && parsed > 0) return parsed
  }
  if (typeof process.getgid === 'function') {
    const gid = process.getgid()
    if (Number.isInteger(gid) && gid > 0) return gid
  }
  return null
}

/** Per-one-shot tmpfs (or per-session DooD scratch) directory mounted at `/kovo-ipc`. */
function makeOneShotIpcDir(sessionId?: string, env: NodeJS.ProcessEnv = process.env): { ipcDir: string; cleanupDir: string } {
  const hostUid = typeof process.getuid === 'function' ? process.getuid() : -1
  const ownerOnly = isContainerUid10001() || hostUid === 0
  const ipcMode = ownerOnly ? 0o700 : 0o770
  const dood = resolveDoodScratchConfig(env)
  if (dood) {
    const sid = sessionId ?? `ipc-${randomUUID()}`
    const ipcDir = prepareSessionScratchDir(sid, 'ipc', env)
    chmodSync(ipcDir, ipcMode)
    if (hostUid === 0) { try { chownSync(ipcDir, 10001, 10001) } catch { /* non-fatal */ } }
    return { ipcDir, cleanupDir: ipcDir }
  }
  const base = existsSync('/dev/shm') ? '/dev/shm' : tmpdir()
  const dir = mkdtempSync(join(base, 'kovo-ipc-'))
  chmodSync(dir, ipcMode)
  if (hostUid === 0) { try { chownSync(dir, 10001, 10001) } catch { /* non-fatal */ } }
  return { ipcDir: dir, cleanupDir: dir }
}

function cleanupSessionSubdir(dir: string, env: NodeJS.ProcessEnv = process.env): void {
  try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  const dood = resolveDoodScratchConfig(env)
  if (!dood) return
  const parent = dirname(dir)
  try {
    if (parent !== dood.containerScratchDir && existsSync(parent) && readdirSync(parent).length === 0) {
      rmSync(parent, { recursive: true, force: true })
    }
  } catch { /* ignore */ }
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

const verifySdkFiles = ['kovo_verify.ts'] as const

export interface PreparedReadableMount {
  /** Host directory guaranteed readable/traversable by container UID 10001 (`0o755` dirs / `0o644` files). */
  mountDir: string
  /** True when Kovo Hunter staged a clean container-readable copy in `tmpdir()` instead of binding directly. */
  staged: boolean
  /** Remove any temporary staged directory (idempotent no-op when `staged === false`). */
  cleanup(): void
}

function resolveVerifySdkDir(sdkDir?: string): string {
  return sdkDir ?? process.env.KOVO_VERIFY_SDK_DIR ?? join(dirname(fileURLToPath(import.meta.url)), '../../worker/kovo_verify')
}

/**
 * Validate and prepare the `kovo_verify` SDK directory for container UID `10001` readability.
 * Under restrictive host `umask 0077` (e.g. `0o700` dir / `0o600` `kovo_verify.ts`), stages a
 * clean copy in `tmpdir()` with explicit `0o755` directory and `0o644` file permissions without
 * modifying host file modes, and tracks it for process-exit cleanup.
 */
export function prepareVerifySdkMount(sdkDir?: string): PreparedReadableMount {
  const dir = resolveVerifySdkDir(sdkDir)
  if (/[\0,\r\n]/.test(dir)) {
    throw new Error('Invalid kovo_verify SDK path.')
  }
  if (!existsSync(dir)) {
    throw new Error('kovo_verify SDK files are unavailable on this host.')
  }
  const rootStat = statSync(dir)
  if (!rootStat.isDirectory()) {
    throw new Error('kovo_verify SDK path must be a directory.')
  }
  const resolved = realpathSync(dir)
  if (/[\0,\r\n]/.test(resolved)) {
    throw new Error('Invalid resolved kovo_verify SDK path.')
  }

  const available: Array<{ name: string; fullPath: string; mode: number }> = []
  let needsStaging = (rootStat.mode & 0o005) !== 0o005
  for (const name of verifySdkFiles) {
    const fullPath = join(resolved, name)
    if (!existsSync(fullPath)) continue
    const st = statSync(fullPath)
    if (!st.isFile()) continue
    if (st.size > 256 * 1024) throw new Error('kovo_verify SDK file exceeds the size limit.')
    if ((st.mode & 0o004) !== 0o004) needsStaging = true
    available.push({ name, fullPath, mode: st.mode })
  }
  if (available.length === 0) {
    throw new Error('kovo_verify SDK files are unavailable on this host.')
  }
  if (!needsStaging) {
    return {
      mountDir: resolved,
      staged: false,
      cleanup() { /* direct host dir: never remove caller's directory */ },
    }
  }

  const sameContainerUid = isContainerUid10001()
  const stageDirMode = sameContainerUid ? 0o700 : 0o755
  const stageFileMode = sameContainerUid ? 0o600 : 0o644
  const rawStageDir = mkdtempSync(join(tmpdir(), 'kovo-sdk-'))
  chmodSync(rawStageDir, stageDirMode)
  const mountDir = realpathSync(rawStageDir)
  try {
    for (const file of available) {
      const dstPath = join(mountDir, file.name)
      copyFileSync(file.fullPath, dstPath)
      chmodSync(dstPath, stageFileMode)
    }
  } catch (error) {
    try { rmSync(mountDir, { recursive: true, force: true }) } catch { /* ignore */ }
    throw error
  }
  trackLiveStagedRepoDir(mountDir)
  let cleaned = false
  return {
    mountDir,
    staged: true,
    cleanup() {
      if (cleaned) return
      cleaned = true
      liveStagedRepoDirs.delete(mountDir)
      try { rmSync(mountDir, { recursive: true, force: true }) } catch { /* best-effort */ }
    },
  }
}

/**
 * The worker image predates the SDK, so the host stages it per call. This keeps the container
 * filesystem immutable and makes the SDK version auditable alongside the verifier that ran it.
 */
export function readVerifySdkFiles(sdkDir?: string): Array<{ name: string; content: string }> {
  const dir = resolveVerifySdkDir(sdkDir)
  const files: Array<{ name: string; content: string }> = []
  for (const name of verifySdkFiles) {
    const path = join(dir, name)
    if (!existsSync(path)) continue
    if (statSync(path).size > 256 * 1024) throw new Error('kovo_verify SDK file exceeds the size limit.')
    files.push({ name, content: readFileSync(path, 'utf8') })
  }
  if (files.length === 0) throw new Error('kovo_verify SDK files are unavailable on this host.')
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
        if (process.env.KOVO_WORKER_DEBUG === '1') {
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
  ownerPid?: number
  ownerPidNs?: string | null
  ownerStartTime?: string | null
  sessionId?: string
  poolInstanceId?: string
  options?: WorkerSessionOptions
  /** One-shot only: host tmpfs (or DooD scratch) dir mounted at /kovo-ipc for large-output pointers. */
  ipcDir?: string
  /** Optional environment override for sibling-container (DooD) mount resolution. */
  env?: NodeJS.ProcessEnv
}

export interface PreparedReposMount {
  /** Host directory bind-mounted read-only at `/repos`. */
  mountDir: string
  /** True when Kovo Hunter staged a clean container-readable copy instead of binding `reposDir` directly. */
  staged: boolean
  /** Number of secret/sensitive or unsafe entries excluded while staging. */
  excludedCount: number
  /** Remove any temporary staged directory (idempotent no-op when `staged === false`). */
  cleanup(): void
}

export const DEFAULT_MAX_STAGE_BYTES = 256 * 1024 * 1024
const MAX_STAGE_BYTES_ENV_CEILING = 1024 * 1024 * 1024
export const DEFAULT_MAX_STAGE_FILES = 50_000
export const DEFAULT_MAX_STAGE_DEPTH = 32

export class RepoStagingQuotaExceededError extends Error {
  readonly code: 'REPO_STAGING_BYTES_EXCEEDED' | 'REPO_STAGING_FILES_EXCEEDED' | 'REPO_STAGING_DEPTH_EXCEEDED'
  readonly status = 413
  readonly limitKind: 'bytes' | 'files' | 'depth'
  readonly actual: number
  readonly limit: number
  readonly offendingPath?: string

  constructor(limitKind: 'bytes' | 'files' | 'depth', actual: number, limit: number, offendingPath?: string) {
    const code = limitKind === 'bytes'
      ? 'REPO_STAGING_BYTES_EXCEEDED'
      : limitKind === 'files'
        ? 'REPO_STAGING_FILES_EXCEEDED'
        : 'REPO_STAGING_DEPTH_EXCEEDED'
    const label = limitKind === 'bytes'
      ? 'staging byte cap'
      : limitKind === 'files'
        ? 'staging file/inode cap'
        : 'staging directory depth cap'
    super(
      `Repository staging exceeded the ${label} (${actual} > ${limit} limit${offendingPath ? ` at "${offendingPath}"` : ''}).`,
    )
    this.name = 'RepoStagingQuotaExceededError'
    this.code = code
    this.limitKind = limitKind
    this.actual = actual
    this.limit = limit
    this.offendingPath = offendingPath
  }
}

export interface StageReposLimits {
  maxBytes?: number
  maxFiles?: number
  maxInodes?: number
  maxDepth?: number
}

function parsePositiveStageEnvInt(env: NodeJS.ProcessEnv, name: string): number | undefined {
  const raw = env[name]?.trim()
  if (!raw) return undefined
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined
  return Math.floor(parsed)
}

function resolveStageLimits(
  options?: StageReposLimits & { env?: NodeJS.ProcessEnv },
): { maxBytes: number; maxFiles: number; maxInodes: number; maxDepth: number } {
  const env = options?.env ?? process.env
  const envMaxBytes = parsePositiveStageEnvInt(env, 'KOVO_MAX_STAGE_REPO_BYTES')
  const cappedEnvMaxBytes = envMaxBytes !== undefined
    ? Math.min(envMaxBytes, MAX_STAGE_BYTES_ENV_CEILING)
    : undefined
  const maxBytes = Math.max(
    1,
    Math.floor(options?.maxBytes ?? cappedEnvMaxBytes ?? DEFAULT_MAX_STAGE_BYTES),
  )
  const maxFiles = Math.max(
    1,
    Math.floor(options?.maxFiles ?? parsePositiveStageEnvInt(env, 'KOVO_MAX_STAGE_REPO_FILES') ?? DEFAULT_MAX_STAGE_FILES),
  )
  const maxInodes = Math.max(
    maxFiles,
    Math.floor(options?.maxInodes ?? maxFiles * 2),
  )
  const maxDepth = Math.max(
    0,
    Math.floor(options?.maxDepth ?? parsePositiveStageEnvInt(env, 'KOVO_MAX_STAGE_REPO_DEPTH') ?? DEFAULT_MAX_STAGE_DEPTH),
  )
  return { maxBytes, maxFiles, maxInodes, maxDepth }
}

function resolveStageReposBaseDir(stageDirMode: number, env: NodeJS.ProcessEnv = process.env): string {
  const containerScratch = env.KOVO_CONTAINER_SCRATCH_DIR?.trim()
  if (containerScratch && isAbsolute(containerScratch) && !/[\0,\r\n]/.test(containerScratch) && posix.resolve(containerScratch) !== '/') {
    mkdirSync(containerScratch, { recursive: true, mode: stageDirMode })
    return containerScratch
  }
  const dataDir = env.KOVO_DATA_DIR?.trim()
  if (dataDir && !/[\0,\r\n]/.test(dataDir)) {
    const scratchBase = join(dataDir, 'scratch')
    mkdirSync(scratchBase, { recursive: true, mode: stageDirMode })
    return scratchBase
  }
  return tmpdir()
}

export function stageReadableReposTree(
  resolvedRoot: string,
  targetDir?: string,
  options?: StageReposLimits & { env?: NodeJS.ProcessEnv; onTargetResolved?: (mountDir: string) => void },
): { mountDir: string; excludedCount: number; stagedBytes: number; stagedFiles: number } {
  const sameContainerUid = isContainerUid10001()
  const stageDirMode = sameContainerUid ? 0o700 : 0o755
  const stageFileMode = sameContainerUid ? 0o600 : 0o644
  const { maxBytes, maxFiles, maxInodes, maxDepth } = resolveStageLimits(options)
  let mountDir: string
  let createdTargetDir = false
  if (targetDir) {
    if (existsSync(targetDir)) {
      const targetStat = lstatSync(targetDir)
      if (targetStat.isSymbolicLink() || !targetStat.isDirectory()) {
        throw new Error('Staging target path must be a directory.')
      }
      if (readdirSync(targetDir).length > 0) {
        throw new Error('Refusing to stage repository into non-empty target directory.')
      }
      mountDir = realpathSync(targetDir)
      createdTargetDir = false
    } else {
      mkdirSync(targetDir, { recursive: false, mode: stageDirMode })
      chmodSync(targetDir, stageDirMode)
      mountDir = realpathSync(targetDir)
      createdTargetDir = true
    }
  } else {
    const stageBase = resolveStageReposBaseDir(stageDirMode, options?.env)
    const rawStageDir = mkdtempSync(join(stageBase, 'kovo-repos-'))
    chmodSync(rawStageDir, stageDirMode)
    mountDir = realpathSync(rawStageDir)
    createdTargetDir = true
  }

  options?.onTargetResolved?.(mountDir)
  let excludedCount = 0
  let stagedBytes = 0
  let stagedFiles = 0
  let stagedInodes = 0
  const createdChildren: string[] = []

  const copyDir = (srcDir: string, dstDir: string, depth: number) => {
    if (depth > maxDepth) {
      throw new RepoStagingQuotaExceededError(
        'depth',
        depth,
        maxDepth,
        relative(resolvedRoot, srcDir).split(sep).join('/'),
      )
    }
    for (const entry of readdirSync(srcDir, { withFileTypes: true })) {
      const srcChild = join(srcDir, entry.name)
      const st = lstatSync(srcChild)
      if (st.isSymbolicLink()) {
        excludedCount += 1
        continue
      }
      const relPosix = relative(resolvedRoot, srcChild).split(sep).join('/')
      if (st.isDirectory()) {
        const nameLower = entry.name.toLowerCase()
        if (nameLower === 'node_modules') {
          excludedCount += 1
          continue
        }
        if (nameLower === '.git') {
          // Skip `.git` directories so multi-hundred-MB git object stores never exhaust scratch disk/inodes.
          let gitSensitiveCount = 0
          if (existsSync(join(srcChild, 'hooks'))) gitSensitiveCount += 1
          if (existsSync(join(srcChild, 'config'))) gitSensitiveCount += 1
          excludedCount += Math.max(1, gitSensitiveCount)
          continue
        }
        if (isSensitiveRepoEntry(relPosix, entry.name, true)) {
          excludedCount += 1
          continue
        }
        const nextDepth = depth + 1
        if (nextDepth > maxDepth) {
          throw new RepoStagingQuotaExceededError('depth', nextDepth, maxDepth, relPosix)
        }
        stagedInodes += 1
        if (stagedInodes > maxInodes) {
          throw new RepoStagingQuotaExceededError('files', stagedInodes, maxInodes, relPosix)
        }
        const dstChild = join(dstDir, entry.name)
        mkdirSync(dstChild)
        if (dstDir === mountDir) createdChildren.push(dstChild)
        chmodSync(dstChild, stageDirMode)
        copyDir(srcChild, dstChild, nextDepth)
      } else if (st.isFile()) {
        if (isSensitiveRepoEntry(relPosix, entry.name, false)) {
          excludedCount += 1
          continue
        }
        if (stagedFiles + 1 > maxFiles) {
          throw new RepoStagingQuotaExceededError('files', stagedFiles + 1, maxFiles, relPosix)
        }
        if (stagedInodes + 1 > maxInodes) {
          throw new RepoStagingQuotaExceededError('files', stagedInodes + 1, maxInodes, relPosix)
        }
        if (stagedBytes + st.size > maxBytes) {
          throw new RepoStagingQuotaExceededError('bytes', stagedBytes + st.size, maxBytes, relPosix)
        }
        const dstChild = join(dstDir, entry.name)
        if (dstDir === mountDir) createdChildren.push(dstChild)
        copyFileSync(srcChild, dstChild)
        chmodSync(dstChild, stageFileMode)
        const copiedStat = lstatSync(dstChild)
        stagedFiles += 1
        stagedInodes += 1
        stagedBytes += copiedStat.size
        if (stagedBytes > maxBytes) {
          throw new RepoStagingQuotaExceededError('bytes', stagedBytes, maxBytes, relPosix)
        }
      }
    }
  }

  try {
    copyDir(resolvedRoot, mountDir, 0)
  } catch (error) {
    if (createdTargetDir) {
      liveStagedRepoDirs.delete(mountDir)
      try { rmSync(mountDir, { recursive: true, force: true }) } catch { /* ignore */ }
    } else {
      // Never delete a pre-existing directory this call did not create; clean only our partial children.
      for (const child of createdChildren) {
        try { rmSync(child, { recursive: true, force: true }) } catch { /* ignore */ }
      }
    }
    throw error
  }
  return { mountDir, excludedCount, stagedBytes, stagedFiles }
}

/**
 * Validate and prepare a host `reposDir` for a read-only `/repos` bind mount into the non-root
 * Docker worker (`UID 10001`). Always stages an isolated immutable snapshot via
 * `stageReadableReposTree` — never direct-mounting the live mutable host checkout directory —
 * with explicit container-readable permissions (`0o755`/`0o644` on host, `0o700`/`0o600` when
 * running as UID 10001) while stripping `.git`, `node_modules`, symlinks, and sensitive files
 * (`.env`, keys, tokens) and leaving original host files completely unmodified.
 */
export function prepareReposMount(
  reposDir?: string,
  doodOptions?: StageReposLimits & { sessionId?: string; env?: NodeJS.ProcessEnv },
): PreparedReposMount | null {
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
  const env = doodOptions?.env ?? process.env
  const stageLimits = resolveStageLimits({ ...doodOptions, env })
  const dood = resolveDoodScratchConfig(env)
  const stageTarget = dood
    ? prepareSessionScratchDir(doodOptions?.sessionId ?? `repos-${randomUUID()}`, 'repos', env)
    : undefined
  let trackedMountDir: string | undefined
  let mountDir: string
  let excludedCount: number
  try {
    ({ mountDir, excludedCount } = stageReadableReposTree(resolved, stageTarget, {
      env,
      maxBytes: stageLimits.maxBytes,
      maxFiles: stageLimits.maxFiles,
      maxInodes: stageLimits.maxInodes,
      maxDepth: stageLimits.maxDepth,
      onTargetResolved: dir => {
        trackedMountDir = dir
        trackLiveStagedRepoDir(dir)
      },
    }))
  } catch (error) {
    if (trackedMountDir) liveStagedRepoDirs.delete(trackedMountDir)
    throw error
  }
  let cleaned = false
  return {
    mountDir,
    staged: true,
    excludedCount,
    cleanup() {
      if (cleaned) return
      cleaned = true
      liveStagedRepoDirs.delete(mountDir)
      cleanupSessionSubdir(mountDir, env)
    },
  }
}

function resolveReposMountArgs(reposDir?: string, env?: NodeJS.ProcessEnv): string[] {
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
  return ['--mount', resolveDoodMountArg(resolved, '/repos', { readonly: true, env })]
}

/**
 * Ensure a host verification RPC mount directory and its expected IPC artifacts (`token`,
 * `context.json`, `verify.sock`) are traversable/accessible by non-root container UID `10001`
 * even when created under a restrictive host `umask 0077`.
 */
export function ensureRpcMountReadable(rpcDir: string): string {
  if (/[\0,\r\n]/.test(rpcDir)) throw new Error('Invalid verification RPC mount path.')
  if (!existsSync(rpcDir)) throw new Error('Verification RPC mount path does not exist.')
  const st = statSync(rpcDir)
  if (!st.isDirectory()) throw new Error('Verification RPC mount path must be a directory.')
  const resolved = realpathSync(rpcDir)
  if (/[\0,\r\n]/.test(resolved)) throw new Error('Invalid resolved verification RPC mount path.')

  const hostUid = typeof process.getuid === 'function' ? process.getuid() : -1
  const ownerOnly = isContainerUid10001() || hostUid === 0
  const dirMode = ownerOnly ? 0o700 : 0o750
  const fileMode = ownerOnly ? 0o600 : 0o640
  const sockMode = ownerOnly ? 0o600 : 0o660
  chmodSync(resolved, dirMode)
  if (hostUid === 0) { try { chownSync(resolved, 10001, 10001) } catch { /* non-fatal */ } }
  for (const name of [VERIFY_RPC_TOKEN_NAME, VERIFY_RPC_CONTEXT_NAME]) {
    const filePath = join(resolved, name)
    if (!existsSync(filePath)) continue
    const fileStat = lstatSync(filePath)
    if (fileStat.isFile()) {
      chmodSync(filePath, fileMode)
      if (hostUid === 0) { try { chownSync(filePath, 10001, 10001) } catch { /* non-fatal */ } }
    }
  }
  const socketPath = join(resolved, VERIFY_RPC_SOCKET_NAME)
  if (existsSync(socketPath)) {
    const sockStat = lstatSync(socketPath)
    if (sockStat.isSocket() || sockStat.isFile()) {
      chmodSync(socketPath, sockMode)
      if (hostUid === 0) { try { chownSync(socketPath, 10001, 10001) } catch { /* non-fatal */ } }
    }
  }
  return resolved
}

/**
 * Mount the per-session verification RPC directory read-only at `/kovo-rpc`. The socket is
 * the only egress a `--network none` verification script needs; the rest of the container stays
 * read-only and the script never receives a persona credential (Layer 1 injects it).
 */
function resolveRpcMountArgs(rpcDir?: string, env?: NodeJS.ProcessEnv): string[] {
  if (!rpcDir) return []
  const resolved = ensureRpcMountReadable(rpcDir)
  return [
    '--mount', resolveDoodMountArg(resolved, VERIFY_RPC_CONTAINER_DIR, { readonly: true, env }),
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
  const ownerPidNs = input.ownerPidNs !== undefined ? input.ownerPidNs : currentPidNamespace()
  const ownerStartTime = input.ownerStartTime !== undefined ? input.ownerStartTime : readProcStartTicks('self')
  const sessionId = input.sessionId ?? processSessionId
  const sharedGid = resolveWorkerSharedGid(input.env)
  return [
    // No `--rm`: Docker's automatic removal races the explicit `rm --force` below and the
    // daemon answers "removal of container ... is already in progress", which previously
    // surfaced as a failed worker session. Explicit removal is the single mechanism.
    'container', 'create', '--name', input.name, '--interactive', '--pull', 'never',
    '--network', 'none', '--user', '10001:10001',
    ...(sharedGid !== null ? ['--group-add', String(sharedGid)] : []),
    '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', String(pidsLimit),
    '--cpus', String(cpus),
    '--memory', `${memoryMb}m`, '--memory-swap', `${memoryMb}m`,
    '--tmpfs', `/tmp:rw,nosuid,nodev,noexec,size=${tmpfsMb}m,mode=1777`,
    ...resolveReposMountArgs(options?.reposDir, input.env),
    ...resolveRpcMountArgs(options?.rpcMountDir, input.env),
    ...(input.ipcDir
      ? [
          '--mount', resolveDoodMountArg(realpathSync(input.ipcDir), '/kovo-ipc', { readonly: false, env: input.env }),
          '--env', 'KOVO_IPC_DIR=/kovo-ipc',
        ]
      : []),
    '--label', `${assignmentNamespace}=` + input.assignmentId,
    '--label', `${runNamespace}=${input.runLabel}`,
    ...(input.owner ? ['--label', `${workerNamespace}=${input.owner}`] : []),
    ...(input.cell ? ['--label', `${cellNamespace}=${input.cell}`] : []),
    ...(input.warm ? ['--label', `${warmNamespace}=1`] : []),
    '--label', `${WORKER_OWNER_PID_LABEL}=${input.ownerPid ?? process.pid}`,
    ...(ownerPidNs ? ['--label', `${WORKER_OWNER_PID_NS_LABEL}=${ownerPidNs}`] : []),
    ...(ownerStartTime ? ['--label', `${WORKER_OWNER_START_TIME_LABEL}=${ownerStartTime}`] : []),
    ...(input.poolInstanceId ? ['--label', `${WORKER_POOL_INSTANCE_LABEL}=${input.poolInstanceId}`] : []),
    '--label', `${sessionNamespace}=${sessionId}`,
    '--label', `${createdAtNamespace}=` + Date.now(),
    input.image,
    ...(input.extraArgs ?? []),
  ]
}

/** Warm-pool escape hatch: `KOVO_WARM_WORKERS=0` (or false/off) disables pooling. */
export function warmWorkersEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env.KOVO_WARM_WORKERS
  return value !== '0' && value !== 'false' && value !== 'off'
}

/** Hard upper bound on idle warm containers per cell (matches dynamic concurrency ceiling). */
export const MAX_WARM_POOL_CAPACITY = 12

/** Idle warm containers kept per cell (one per worker slot); bounded 1..12. */
export function warmPoolCapacity(env: NodeJS.ProcessEnv = process.env): number {
  const raw = Number(env.KOVO_WARM_SLOTS)
  if (!Number.isFinite(raw) || raw <= 0) return 1
  return Math.max(1, Math.min(MAX_WARM_POOL_CAPACITY, Math.floor(raw)))
}

/**
 * Scratch reset executed inside a pooled container before it is returned to the pool. `/tmp` is
 * the container tmpfs that backs `/evidence` and the scratch workspace, so clearing it gives the
 * next assignment a fresh filesystem without paying for a `container create` round-trip.
 */
export const WARM_SCRATCH_RESET_COMMAND = 'rm -rf /tmp/* /tmp/.[!.]* /tmp/..?* 2>/dev/null; true'

function normalizeReposDirKey(reposDir?: string): string | undefined {
  if (!reposDir) return undefined
  try {
    return realpathSync(reposDir)
  } catch {
    return resolvePath(reposDir)
  }
}

/**
 * Build a deterministic warm-pool isolation key strictly from container-visible state
 * (`runId`, normalized read-only `reposDir`, sorted `mountedRepos`, and container `image`).
 *
 * Host-only persona credential refresh generations MUST NEVER be hashed here: Docker worker
 * containers run `--network none` and never hold persona secrets, so credential auto-refresh
 * on the host must not tear down idle warm containers or re-stage `/repos`.
 */
export function buildWarmPoolPolicy(input: {
  runId: string
  reposDir?: string
  mountedRepos?: readonly string[]
  image?: string
}): string {
  const cleanRunId = input.runId.trim()
  const normalizedReposDir = normalizeReposDirKey(input.reposDir) ?? ''
  const normalizedRepos = [...new Set((input.mountedRepos ?? []).map(r => r.trim()).filter(Boolean))].sort()
  const normalizedImage = input.image?.trim() ?? ''
  const mountHash = createHash('sha256')
    .update(normalizedReposDir)
    .update('\0')
    .update(normalizedRepos.join('\n'))
    .update('\0')
    .update(normalizedImage)
    .digest('hex')
    .slice(0, 12)
  return `${cleanRunId}:${mountHash}`
}

interface RunRepoSnapshotLease {
  key: string
  runKey: string
  sourceDir: string
  prepared: PreparedReposMount
  /** Active borrowers: owning warm-pool slots + open sessions + in-flight run/verifyStaticAst calls. */
  activeLeases: number
  /** Marked true once retired by evictRunWarmPool / policy rotation / closeWarmPool; cleaned up when activeLeases hits 0. */
  retired: boolean
}

export const MAX_ACTIVE_WARM_POOLS = 16

function policyRunKey(policy: string): string {
  const idx = policy.lastIndexOf(':')
  return idx > 0 ? policy.slice(0, idx) : policy
}

interface WarmPoolSlot {
  policy: string
  runKey: string
  pool: WarmWorkerPool
  reposSource?: string
  preparedRepos?: RunRepoSnapshotLease
  warmed: boolean
  /** Concurrent in-flight `openSession` calls + active sessions referencing this slot. */
  activeSessions: number
  /** Marked true once replaced/evicted so containers don't recycle into a retired slot. */
  retired: boolean
}

/**
 * One pool per (cell, image, runLabel, owner, options) per process: Execution may construct more
 * than one backend, and a cell must not accumulate one idle container per backend.
 */
const warmPools = new Map<string, WarmWorkerPool>()
function sharedWarmPool(input: {
  cell: string
  image: string
  dockerRunner: DockerRunner
  runLabel: string
  owner?: string
  options?: WorkerSessionOptions
  reposDirPreStaged?: boolean
  capacity?: number
}): WarmWorkerPool {
  const sanitizedOptions = input.options ? { ...input.options } : undefined
  if (sanitizedOptions) {
    delete sanitizedOptions.rpcMountDir
    delete sanitizedOptions.warmPoolPolicy
    delete sanitizedOptions.runId
  }
  // Owner (tenant/workspace) and container options (including read-only reposDir) are part of the
  // key: two tenants or different repo mounts must never share an idle container.
  const key = `${input.cell}\0${input.image}\0${input.runLabel}\0${input.owner ?? ''}\0${workerOptionsSignature(sanitizedOptions)}`
  const existing = warmPools.get(key)
  if (existing && existing.state !== 'closed') {
    if (input.capacity !== undefined) existing.setCapacity(input.capacity)
    return existing
  }
  if (existing) warmPools.delete(key)
  const pool = new WarmWorkerPool({ ...input, options: sanitizedOptions, registryKey: key })
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
  readonly instanceId: string = randomUUID()
  private readonly image: string
  private readonly docker: DockerRunner
  private readonly runLabel: string
  private readonly owner?: string
  private readonly options: WorkerSessionOptions
  private readonly reposDirPreStaged: boolean
  private readonly signature: string
  private readonly registryKey?: string
  private preparedRepos?: PreparedReposMount | null
  private preparedReposRetired = false
  private capacity: number
  private readonly idle: string[] = []
  private readonly createdAtByName = new Map<string, number>()
  private readonly idleMaxAgeMs: number
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
    reposDirPreStaged?: boolean
    capacity?: number
    idleMaxAgeMs?: number
    registryKey?: string
  }) {
    this.cell = input.cell
    this.image = input.image
    this.docker = input.dockerRunner
    this.runLabel = input.runLabel
    this.owner = input.owner
    this.registryKey = input.registryKey
    this.reposDirPreStaged = Boolean(input.reposDirPreStaged)
    this.options = { ...(input.options ?? {}) }
    delete this.options.rpcMountDir
    delete this.options.warmPoolPolicy
    delete this.options.runId
    this.signature = workerOptionsSignature(this.options)
    this.capacity = Math.max(1, Math.min(MAX_WARM_POOL_CAPACITY, Math.floor(input.capacity ?? warmPoolCapacity())))
    this.idleMaxAgeMs = Math.max(1_000, input.idleMaxAgeMs ?? Math.floor(DEFAULT_FOREIGN_OWNER_TTL_MS / 2))
  }

  get enabled(): boolean { return !this.disabled && !this.closed }
  get outstandingCount(): number { return this.outstanding.size }
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
  setCapacity(slots: number, prefill = true): void {
    const next = Math.max(1, Math.min(MAX_WARM_POOL_CAPACITY, Math.floor(slots)))
    if (next === this.capacity) return
    this.capacity = next
    if (prefill) this.fill()
  }

  /** True when the pool currently owns an idle container with this name. */
  owns(name: string): boolean {
    return this.idle.includes(name)
  }

  private cleanupRetiredPreparedRepos(): void {
    if (!this.preparedReposRetired || this.outstanding.size > 0) return
    const staged = this.preparedRepos
    this.preparedRepos = undefined
    staged?.cleanup()
  }

  /** A pooled container died or was removed mid-session: stop accounting for it and refill. */
  forget(name: string): void {
    this.outstanding.delete(name)
    this.used.delete(name)
    this.cleanupRetiredPreparedRepos()
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

  private effectiveCreateOptions(): WorkerSessionOptions {
    if (!this.options.reposDir || this.reposDirPreStaged) return this.options
    if (this.preparedRepos === undefined) {
      this.preparedRepos = prepareReposMount(this.options.reposDir, { sessionId: `warm-${this.instanceId}-${randomUUID().slice(0, 8)}` })
    }
    return this.preparedRepos ? { ...this.options, reposDir: this.preparedRepos.mountDir } : this.options
  }

  private async create(): Promise<void> {
    const name = 'kovo-' + randomUUID()
    try {
      await ensureWorkerImageAvailable(this.image, this.docker, AbortSignal.timeout(DEFAULT_WORKER_PULL_TIMEOUT_MS))
      await this.docker(workerContainerCreateArgs({
        image: this.image,
        name,
        assignmentId: `warm-${randomUUID()}`,
        extraArgs: ['--session'],
        runLabel: this.runLabel,
        ...(this.owner ? { owner: this.owner } : {}),
        cell: this.cell,
        warm: true,
        ownerPid: process.pid,
        poolInstanceId: this.instanceId,
        options: this.effectiveCreateOptions(),
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
      this.createdAtByName.set(name, Date.now())
      trackLiveContainer(name)
    } catch (error) {
      this.failures += 1
      this.disabled = true
      if (this.idle.length === 0 && this.outstanding.size === 0) {
        const staged = this.preparedRepos
        this.preparedRepos = undefined
        staged?.cleanup()
      }
      if (process.env.KOVO_WORKER_DEBUG === '1') {
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

  private async inspectIdleContainer(name: string): Promise<boolean> {
    const createdAt = this.createdAtByName.get(name)
    if (createdAt !== undefined && Date.now() - createdAt >= this.idleMaxAgeMs) {
      return false
    }
    let raw: string
    try {
      raw = await this.docker([
        'container', 'inspect', '-f',
        `{{.State.Status}}\t{{index .Config.Labels "${WORKER_POOL_INSTANCE_LABEL}"}}`,
        name,
      ], AbortSignal.timeout(5_000))
    } catch {
      return false
    }
    const trimmed = raw.trim()
    if (!trimmed) return true
    const [status = '', instance = ''] = trimmed.split('\t')
    if (status !== 'created' && status !== 'exited') return false
    if (instance && instance !== '<no value>' && instance !== this.instanceId) return false
    return true
  }

  /** Take an idle container when it matches the caller's session shape; null means cold create. */
  async take(signal: AbortSignal, options?: WorkerSessionOptions): Promise<string | null> {
    if (!this.enabled) return null
    if (options?.rpcMountDir) return null
    if (workerOptionsSignature(options) !== this.signature) return null
    const startedEmpty = this.idle.length === 0
    if (startedEmpty) await this.warm()
    signal.throwIfAborted()
    while (this.idle.length > 0) {
      const name = this.idle.shift()!
      liveContainers.delete(name)
      const healthy = await this.inspectIdleContainer(name)
      signal.throwIfAborted()
      if (!healthy) {
        this.discarded += 1
        this.used.delete(name)
        await this.removeIdle(name)
        continue
      }
      this.outstanding.add(name)
      if (this.used.has(name)) this.reused += 1
      else this.used.add(name)
      return name
    }
    return null
  }

  /** Remove one idle container (pool disabled, oversized, or failed reuse). */
  private async removeIdle(name: string): Promise<void> {
    liveContainers.delete(name)
    this.createdAtByName.delete(name)
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
      this.cleanupRetiredPreparedRepos()
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
    this.createdAtByName.set(name, Date.now())
    this.returned += 1
    trackLiveContainer(name)
    return true
  }

  async close(): Promise<void> {
    this.closed = true
    if (this.registryKey && warmPools.get(this.registryKey) === this) {
      warmPools.delete(this.registryKey)
    }
    const idle = this.idle.splice(0)
    this.createdAtByName.clear()
    await Promise.all(idle.map(name => this.removeIdle(name)))
    this.preparedReposRetired = true
    this.cleanupRetiredPreparedRepos()
  }
}

export class LinuxWorkerBackend implements WorkerBackend {
  private readonly instanceId = randomUUID()
  private readonly image: string
  get workerImage(): string { return this.image }
  private readonly owner?: string
  private readonly runId?: string
  private readonly cell?: string
  private readonly docker: DockerRunner
  private readonly spawnSession: (name: string) => ChildProcess
  private readonly staleCreatedMs: number
  private readonly foreignOwnerTtlMs: number
  private readonly ownerPidNs: string | null
  private readonly isPidAlive: (pid: number) => boolean
  private readonly readPidStartTime: (pid: number) => string | null
  private readonly warmPools = new Map<string, WarmPoolSlot>()
  /** Immutable staged `/repos` snapshots shared across all workers in the same `(runKey, reposDir)`. */
  private readonly runRepoSnapshots = new Map<string, RunRepoSnapshotLease>()
  /** Most recently installed policy key (diagnostic `warmPoolStats` getter ONLY; NEVER used for run/snapshot/session resolution). */
  private activeWarmPoolPolicy?: string
  /** Hard bound on concurrent per-policy warm pools retained in `this.warmPools` (LRU evicted). */
  private readonly maxWarmPools: number
  /** Desired warm-pool slot capacity preserved across policy rotations. */
  private desiredWarmCapacity?: number
  /** Cumulative stats of pools retired by a policy change or eviction (metrics stay run-wide). */
  private retiredPoolStats = { created: 0, reused: 0, failures: 0 }
  private readonly pooled = new Map<string, WarmWorkerPool>()
  private readonly activeContainers = new Set<string>()
  private readonly removals = new Map<string, Promise<void>>()
  private sessionsServed = 0
  private coldSessionCreates = 0
  private reclaiming?: Promise<void>

  constructor(input: {
    image?: string
    workspace?: { id: string; directory: string }
    runId?: string
    /** Test seam: replace the docker CLI executor (defaults to the real CLI). */
    dockerRunner?: DockerRunner
    /** Test seam: replace `docker container start --attach --interactive` spawner. */
    sessionSpawner?: (name: string) => ChildProcess
    /** Grace before an abandoned `created` container is reclaimed (default 2 min). */
    staleCreatedMs?: number
    /** TTL before a foreign-namespace container is reclaimed (default 30 min). */
    foreignOwnerTtlMs?: number
    /** Test seam: override this process's PID namespace (`pid:[...]`). */
    ownerPidNs?: string | null
    /**
     * Matrix cell id (default: `KOVO_CELL_ID`). Labels every container `dev.kovo.cell`
     * and enables the best-effort warm session pool unless `KOVO_WARM_WORKERS=0`.
     */
    cell?: string
    /** Test seam: check whether a container owner PID is alive (defaults to `isOwnerPidAlive`). */
    isPidAlive?: (pid: number) => boolean
    /** Test seam: read `/proc/<pid>/stat` start ticks for PID-reuse detection. */
    readPidStartTime?: (pid: number) => string | null
    /** Optional max concurrent per-policy warm pools (bounded LRU; defaults to `MAX_ACTIVE_WARM_POOLS`). */
    maxWarmPools?: number
  } = {}) {
    const {
      image = 'kovo-worker:v4',
      workspace,
      runId,
      dockerRunner,
      sessionSpawner,
      staleCreatedMs,
      foreignOwnerTtlMs,
      ownerPidNs,
      cell,
      isPidAlive,
      readPidStartTime,
      maxWarmPools,
    } = input
    this.image = input.image ?? (process.env.KOVO_WORKER_IMAGE?.trim() || image)
    this.runId = runId
    this.docker = dockerRunner ?? docker
    this.spawnSession = sessionSpawner ?? (name => spawn('docker', ['container', 'start', '--attach', '--interactive', name], {
      env: dockerEnv(),
      stdio: ['pipe', 'pipe', 'pipe'],
    }))
    this.staleCreatedMs = Math.max(0, staleCreatedMs ?? DEFAULT_STALE_CREATED_MS)
    this.foreignOwnerTtlMs = Math.max(0, foreignOwnerTtlMs ?? DEFAULT_FOREIGN_OWNER_TTL_MS)
    this.ownerPidNs = ownerPidNs !== undefined ? ownerPidNs : currentPidNamespace()
    this.isPidAlive = isPidAlive ?? isOwnerPidAlive
    this.readPidStartTime = readPidStartTime ?? readProcStartTicks
    const envMaxPools = Number(process.env.KOVO_MAX_WARM_POOLS)
    this.maxWarmPools = Math.round(clamp(maxWarmPools ?? (Number.isFinite(envMaxPools) && envMaxPools > 0 ? envMaxPools : undefined), MAX_ACTIVE_WARM_POOLS, 1, 64))
    const cellId = cell ?? process.env.KOVO_CELL_ID
    this.cell = cellId && cellId.trim() ? cellId.trim() : undefined
    if (workspace) {
      this.owner = createHash('sha256').update(workspace.id).update('\0').update(realpathSync(workspace.directory)).digest('hex')
    }
    // The pool is installed lazily: Execution sets the run/credential policy before the first
    // assignment, so prewarming under the default label would only create a container to discard.
    this.installWarmPool(this.defaultWarmPolicy(), false)
  }

  private runSnapshotKey(runKey: string, sourceDir: string): string {
    return `${runKey}\0${sourceDir}`
  }

  private resolveRunKeyForOptions(options?: WorkerSessionOptions): string | undefined {
    const explicitRunId = options?.runId?.trim()
    if (explicitRunId) return explicitRunId
    const requestedPolicy = options?.warmPoolPolicy?.trim()
    if (requestedPolicy) return policyRunKey(requestedPolicy)
    // R4-H-8: NEVER infer run identity from mutable backend-global `activeWarmPoolPolicy`.
    // When callers omit both `runId` and `warmPoolPolicy` (and this backend is not scoped to a
    // single immutable `this.runId`), return undefined so `acquireReposForCall` fails closed by
    // staging a private single-call snapshot instead of attaching to another run's lease.
    const backendRunId = this.runId?.trim()
    return backendRunId || undefined
  }

  private evictExcessIdleRunSnapshots(): void {
    const maxCached = Math.max(this.maxWarmPools, MAX_ACTIVE_WARM_POOLS)
    if (this.runRepoSnapshots.size < maxCached) return
    for (const candidate of [...this.runRepoSnapshots.values()]) {
      if (this.runRepoSnapshots.size < maxCached) break
      if (candidate.activeLeases > 0) continue
      this.retireRunRepoSnapshot(candidate)
    }
  }

  private acquireRunRepoSnapshot(
    runKey: string,
    reposDir: string,
    sessionPrefix: string,
  ): RunRepoSnapshotLease | null {
    const sourceDir = normalizeReposDirKey(reposDir)
    if (!sourceDir) return null
    const key = this.runSnapshotKey(runKey, sourceDir)
    const existing = this.runRepoSnapshots.get(key)
    if (existing && !existing.retired && existsSync(existing.prepared.mountDir)) {
      this.runRepoSnapshots.delete(key)
      this.runRepoSnapshots.set(key, existing)
      existing.activeLeases += 1
      return existing
    }
    if (existing) {
      this.retireRunRepoSnapshot(existing)
    }
    this.evictExcessIdleRunSnapshots()
    const prepared = prepareReposMount(reposDir, {
      sessionId: `${sessionPrefix}-${this.instanceId.slice(0, 8)}-${randomUUID().slice(0, 8)}`,
    })
    if (!prepared) return null
    const lease: RunRepoSnapshotLease = {
      key,
      runKey,
      sourceDir,
      prepared,
      activeLeases: 1,
      retired: false,
    }
    this.runRepoSnapshots.set(key, lease)
    return lease
  }

  private retireRunRepoSnapshot(lease?: RunRepoSnapshotLease | null): void {
    if (!lease) return
    if (this.runRepoSnapshots.get(lease.key) === lease) {
      this.runRepoSnapshots.delete(lease.key)
    }
    lease.retired = true
    if (lease.activeLeases === 0) {
      lease.prepared.cleanup()
    }
  }

  private releaseRunRepoSnapshotLease(lease?: RunRepoSnapshotLease | null): void {
    if (!lease) return
    lease.activeLeases = Math.max(0, lease.activeLeases - 1)
    if (lease.retired && lease.activeLeases === 0) {
      lease.prepared.cleanup()
    } else if (lease.activeLeases === 0) {
      this.evictExcessIdleRunSnapshots()
    }
  }

  private acquireReposForCall(
    options: WorkerSessionOptions | undefined,
    fallbackSessionId: string,
  ): { mountDir: string; release: () => void } | null {
    if (!options?.reposDir) return null
    const runKey = this.resolveRunKeyForOptions(options)
    if (runKey) {
      const lease = this.acquireRunRepoSnapshot(runKey, options.reposDir, 'runsnap')
      if (!lease) return null
      let released = false
      return {
        mountDir: lease.prepared.mountDir,
        release: () => {
          if (released) return
          released = true
          this.releaseRunRepoSnapshotLease(lease)
        },
      }
    }
    const prepared = prepareReposMount(options.reposDir, { sessionId: fallbackSessionId })
    if (!prepared) return null
    let released = false
    return {
      mountDir: prepared.mountDir,
      release: () => {
        if (released) return
        released = true
        prepared.cleanup()
      },
    }
  }

  /** Pool key: an explicit cell, else the workspace. A bare test backend never prewarms. */
  private poolCell(): string | undefined {
    return this.cell ?? (this.owner ? `ws-${this.owner.slice(0, 12)}` : undefined)
  }

  private defaultWarmPolicy(): string {
    return this.runId ?? (this.owner ? `workspace-${this.owner.slice(0, 12)}` : `adhoc-${processSessionId.slice(0, 8)}`)
  }

  private currentWarmSlot(): WarmPoolSlot | undefined {
    if (!this.activeWarmPoolPolicy) return undefined
    return this.warmPools.get(this.activeWarmPoolPolicy)
  }

  private touchWarmSlot(slot: WarmPoolSlot): void {
    if (this.warmPools.get(slot.policy) !== slot) return
    this.warmPools.delete(slot.policy)
    this.warmPools.set(slot.policy, slot)
  }

  private acquireWarmSlot(slot: WarmPoolSlot): void {
    slot.activeSessions += 1
  }

  private releaseWarmSlot(slot: WarmPoolSlot): void {
    slot.activeSessions = Math.max(0, slot.activeSessions - 1)
    if (slot.activeSessions === 0) {
      this.evictExcessIdlePools()
    }
  }

  private evictExcessIdlePools(): void {
    if (this.warmPools.size <= this.maxWarmPools) return
    for (const candidate of [...this.warmPools.values()]) {
      if (this.warmPools.size <= this.maxWarmPools) break
      if (candidate.activeSessions > 0 || candidate.pool.outstandingCount > 0) continue
      void this.retireSlot(candidate)
    }
  }

  private retireSlot(slot: WarmPoolSlot, awaitClose = false): Promise<void> {
    slot.retired = true
    if (this.warmPools.get(slot.policy) === slot) {
      this.warmPools.delete(slot.policy)
    }
    if (this.activeWarmPoolPolicy === slot.policy) {
      let lastPolicy: string | undefined
      for (const key of this.warmPools.keys()) lastPolicy = key
      this.activeWarmPoolPolicy = lastPolicy
    }
    for (const [containerName, ownerPool] of this.pooled) {
      if (ownerPool === slot.pool) this.pooled.delete(containerName)
    }
    const stats = slot.pool.stats
    this.retiredPoolStats.created += stats.created
    this.retiredPoolStats.reused += stats.reused
    this.retiredPoolStats.failures += stats.failures
    // Close removes idle containers; a session still holding one releases into a closed pool,
    // which discards instead of reusing. Never carry an old-generation container forward.
    const closing = slot.pool.close().catch(() => undefined)
    const repoLease = slot.preparedRepos
    slot.preparedRepos = undefined
    if (repoLease) {
      this.retireRunRepoSnapshot(repoLease)
      this.releaseRunRepoSnapshotLease(repoLease)
    }
    return awaitClose ? closing : Promise.resolve()
  }

  private installWarmPool(policy: string, warmNow = true, options?: { reposDir?: string }): void {
    const poolCell = this.poolCell()
    if (!poolCell || !warmWorkersEnabled()) return
    const nextReposSource = normalizeReposDirKey(options?.reposDir)
    const existing = this.warmPools.get(policy)
    if (existing && !existing.retired && existing.reposSource === nextReposSource && existing.pool.state !== 'closed') {
      this.touchWarmSlot(existing)
      this.activeWarmPoolPolicy = policy
      if (warmNow && !existing.warmed) {
        existing.warmed = true
        void existing.pool.warm()
      }
      return
    }
    // Retire any unused lazy placeholder installed at construction time before the first run policy.
    const defaultPolicy = this.defaultWarmPolicy()
    const placeholder = this.warmPools.get(defaultPolicy)
    if (
      placeholder
      && !placeholder.warmed
      && placeholder.policy !== policy
      && placeholder.pool.stats.created === 0
      && placeholder.activeSessions === 0
    ) {
      void this.retireSlot(placeholder)
    }
    // Retire any existing pool for the SAME run (e.g. reposDir/mount policy change), while
    // leaving every other concurrent run's pool intact. Never clobber a matching-policy slot
    // that still has concurrent workers mid-`openSession`.
    const runKey = policyRunKey(policy)
    for (const slot of [...this.warmPools.values()]) {
      if (slot.policy === policy && slot.reposSource === nextReposSource && !slot.retired && slot.pool.state !== 'closed') {
        continue
      }
      if (slot.runKey === runKey || slot.policy === policy) {
        void this.retireSlot(slot)
      }
    }
    // Enforce bounded LRU across distinct runs so long-lived servers never leak idle pools,
    // NEVER evicting a slot that currently has concurrent workers mid-`openSession` or active
    // sessions; if all slots are active, excess pools are reclaimed as soon as sessions close.
    while (this.warmPools.size >= this.maxWarmPools) {
      let evictCandidate: WarmPoolSlot | undefined
      for (const candidate of this.warmPools.values()) {
        if (candidate.activeSessions === 0 && candidate.pool.outstandingCount === 0) {
          evictCandidate = candidate
          break
        }
      }
      if (!evictCandidate) break
      void this.retireSlot(evictCandidate)
    }
    let preparedRepos: RunRepoSnapshotLease | undefined
    let poolOptions: WorkerSessionOptions | undefined
    if (options?.reposDir) {
      const lease = this.acquireRunRepoSnapshot(runKey, options.reposDir, 'pool')
      if (lease) {
        preparedRepos = lease
        poolOptions = { reposDir: lease.prepared.mountDir }
      }
    }
    const pool = sharedWarmPool({
      cell: poolCell,
      image: this.image,
      dockerRunner: this.docker,
      runLabel: `${this.defaultWarmPolicy()}#${policy}`,
      ...(this.owner ? { owner: this.owner } : {}),
      ...(poolOptions ? { options: poolOptions, reposDirPreStaged: true } : {}),
      ...(this.desiredWarmCapacity !== undefined ? { capacity: this.desiredWarmCapacity } : {}),
    })
    const slot: WarmPoolSlot = {
      policy,
      runKey,
      pool,
      reposSource: nextReposSource,
      preparedRepos,
      warmed: warmNow,
      activeSessions: 0,
      retired: false,
    }
    this.warmPools.set(policy, slot)
    this.activeWarmPoolPolicy = policy
    // Kick the first create early; failure only disables the pool (cold path remains).
    if (warmNow) void pool.warm()
  }

  /**
   * Install a run's warm-pool policy: run identity + credential generation (`${runId}:${secretEpoch}`),
   * plus optional read-only `reposDir`. Concurrent runs retain isolated pools keyed by policy;
   * a rotation or repo-mount change within the same run retires only that run's prior pool.
   */
  setWarmPoolPolicy(policy: string, options?: { reposDir?: string }): void {
    const normalized = policy.trim()
    if (!normalized) return
    this.installWarmPool(normalized, true, options)
  }

  /** Evict and close all warm-pool containers and per-run repo snapshots owned by `runId` on run disposal. */
  async evictRunWarmPool(runId: string): Promise<void> {
    const normalized = runId.trim()
    if (!normalized) return
    const targets = [...this.warmPools.values()].filter(
      slot => slot.runKey === normalized || slot.policy === normalized,
    )
    await Promise.all(targets.map(slot => this.retireSlot(slot, true)))
    for (const lease of [...this.runRepoSnapshots.values()]) {
      if (lease.runKey === normalized) {
        this.retireRunRepoSnapshot(lease)
      }
    }
  }

  /** Shutdown seam: remove idle containers and staged per-run repo snapshots across all run pools. */
  async closeWarmPool(): Promise<void> {
    const slots = [...this.warmPools.values()]
    this.activeWarmPoolPolicy = undefined
    await Promise.all(slots.map(slot => this.retireSlot(slot, true)))
    for (const lease of [...this.runRepoSnapshots.values()]) {
      this.retireRunRepoSnapshot(lease)
    }
  }

  /** Close all warm pools and retire all cached per-run repo snapshots. */
  async close(): Promise<void> {
    await this.closeWarmPool()
  }

  /** Active warm-pool state (test/diagnostic seam; never contains secrets). */
  get warmPoolStats(): WarmWorkerPool['stats'] | undefined {
    return this.currentWarmSlot()?.pool.stats
  }

  /** Per-policy warm-pool stats (test/diagnostic seam; never contains secrets). */
  getWarmPoolStats(policy: string): WarmWorkerPool['stats'] | undefined {
    return this.warmPools.get(policy.trim())?.pool.stats
  }

  /** Number of per-policy warm pools currently retained in this backend. */
  get activeWarmPoolCount(): number {
    return this.warmPools.size
  }

  /** Container-reuse counters for the run's diagnostics event. */
  containerStats(): WorkerContainerStats {
    let created = this.retiredPoolStats.created + this.coldSessionCreates
    let reused = this.retiredPoolStats.reused
    let idle = 0
    let capacity = 0
    for (const slot of this.warmPools.values()) {
      const s = slot.pool.stats
      created += s.created
      reused += s.reused
      idle += s.idle
      capacity += s.capacity
    }
    return {
      created,
      reused,
      sessions: this.sessionsServed,
      coldSessions: this.coldSessionCreates,
      idle,
      capacity,
    }
  }

  /** One warm idle container per worker slot (called by Execution after slot planning). */
  setWarmCapacity(slots: number): void {
    this.desiredWarmCapacity = slots
    for (const slot of this.warmPools.values()) {
      slot.pool.setCapacity(slots, slot.warmed)
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
        if (process.env.KOVO_WORKER_DEBUG === '1') {
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
    for (const slot of this.warmPools.values()) {
      if (slot.pool.owns(name)) return Promise.resolve()
    }
    const ownerPool = this.pooled.get(name)
    if (ownerPool) {
      this.pooled.delete(name)
      ownerPool.forget(name)
    }
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
   * Remove kovo containers abandoned before use (`created`) or after they stopped
   * (`exited`/`dead`) — e.g. a SIGKILLed test process or a crashed CLI. Running (`Up`)
   * containers are left alone: they may belong to a concurrent stream.
   *
   * Ownership safety (H-31):
   * - Containers stamped with `kovo.owner_pid` in the **same** PID namespace are ONLY swept when
   *   that owner PID is provably dead (`ESRCH` or start-time mismatch).
   * - Containers from a **foreign** PID namespace (e.g. host CLI vs DooD container) are never
   *   probed against our local PID table and are spared until `foreignOwnerTtlMs` elapses.
   * - Legacy unlabelled containers are only swept past `staleCreatedMs`.
   */
  private async removeStaleCreated() {
    const signal = AbortSignal.timeout(5_000)
    let rows: string
    try {
      rows = await this.docker([
        'container', 'ls', '--all', '--no-trunc',
        '--filter', 'status=created', '--filter', 'status=exited', '--filter', 'status=dead',
        '--format',
        `{{.ID}}\t{{.Names}}\t{{.Label "${createdAtNamespace}"}}\t{{.CreatedAt}}\t{{.Label "${WORKER_OWNER_PID_LABEL}"}}\t{{.Label "${WORKER_POOL_INSTANCE_LABEL}"}}\t{{.Label "${WORKER_OWNER_PID_NS_LABEL}"}}\t{{.Label "${WORKER_OWNER_START_TIME_LABEL}"}}\t{{.Label "${sessionNamespace}"}}`,
      ], signal)
    } catch {
      return
    }
    const now = Date.now()
    const stale: string[] = []
    for (const row of rows.trim().split('\n')) {
      if (!row) continue
      const [id, name, createdLabel, createdAt, ownerPidLabel, _poolInst, ownerPidNs, ownerStartTime, session] = row.split('\t')
      if (!/^[a-f0-9]{64}$/.test(id) || !workerName.test(name)) continue
      // Never reap a container this process created: pool-parked idle containers sit in `created`
      // or `exited` state between assignments and are removed by the pool, not by the stale sweep.
      if (this.activeContainers.has(name) || liveContainers.has(name) || session === processSessionId) continue
      const stamped = Number(createdLabel)
      const age = Number.isFinite(stamped) && stamped > 0 ? now - stamped : now - Date.parse(createdAt)
      const ownerPid = parseOwnerPid(ownerPidLabel)
      if (ownerPid !== null) {
        const dead = isOwnerProvablyDead(
          { pid: ownerPid, pidNs: ownerPidNs, startTime: ownerStartTime },
          { currentPidNs: this.ownerPidNs, isPidAlive: this.isPidAlive, readPidStartTime: this.readPidStartTime },
        )
        if (dead === true) {
          stale.push(id)
        } else if (dead === null) {
          // Foreign PID namespace: fall back to foreign TTL instead of local kill(pid, 0).
          if (Number.isFinite(age) && age >= this.foreignOwnerTtlMs) stale.push(id)
        }
        continue
      }
      // Unlabelled legacy container: only sweep after the safe grace threshold.
      if (!Number.isFinite(age) || age < this.staleCreatedMs) continue
      stale.push(id)
    }
    if (stale.length) {
      if (process.env.KOVO_WORKER_DEBUG === '1') {
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
        '--format',
        `{{.ID}}\t{{.Names}}\t{{.Label "${createdAtNamespace}"}}\t{{.CreatedAt}}\t{{.Label "${sessionNamespace}"}}\t{{.Label "${WORKER_OWNER_PID_LABEL}"}}\t{{.Label "${WORKER_OWNER_PID_NS_LABEL}"}}\t{{.Label "${WORKER_OWNER_START_TIME_LABEL}"}}`,
      ], signal)
      const now = Date.now()
      inactive = rows.trim().split('\n').flatMap(row => {
        if (!row) return []
        const [id, name, createdLabel, createdAt, session, ownerPidLabel, ownerPidNs, ownerStartTime] = row.split('\t')
        if (!/^[a-f0-9]{64}$/.test(id) || !workerName.test(name)) return []
        // Never touch this process's own containers or any live sibling process's containers.
        if (this.activeContainers.has(name) || liveContainers.has(name) || session === processSessionId) return []
        const ownerPid = parseOwnerPid(ownerPidLabel)
        if (ownerPid !== null) {
          const dead = isOwnerProvablyDead(
            { pid: ownerPid, pidNs: ownerPidNs, startTime: ownerStartTime },
            { currentPidNs: this.ownerPidNs, isPidAlive: this.isPidAlive, readPidStartTime: this.readPidStartTime },
          )
          if (dead === false) return []
          if (dead === null) {
            const stamped = Number(createdLabel)
            const age = Number.isFinite(stamped) && stamped > 0 ? now - stamped : now - Date.parse(createdAt)
            return Number.isFinite(age) && age >= this.foreignOwnerTtlMs ? [id] : []
          }
          return [id]
        }
        return [id]
      })
    } catch {
      return
    }
    if (!inactive.length) return
    if (process.env.KOVO_WORKER_DEBUG === '1') {
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
      ownerPid: process.pid,
      poolInstanceId: this.instanceId,
      ...(options ? { options } : {}),
      ...(ipcDir ? { ipcDir } : {}),
    })
  }

  async run(rawJob: WorkerJob, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerResult> {
    signal.throwIfAborted()
    const job = jobSchema.parse(rawJob)
    const payload = JSON.stringify(job)
    if (Buffer.byteLength(payload) > 16 * 1024 * 1024) throw new Error('Worker inputs exceeded their limit.')
    await ensureWorkerImageAvailable(this.image, this.docker, signal)
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'kovo-' + randomUUID()
    const timeoutMs = (job.timeoutMs ?? 60_000) + 10_000
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    // One-shot containers exit before a pointer can be read via `docker exec`, so mount a host
    // tmpfs (or isolated DooD session subdir) and read the spilled payload directly (size + sha256).
    const scratchSessionId = `run-${randomUUID()}`
    let cleanupDir: string | undefined
    let repoAcquisition: { mountDir: string; release: () => void } | null = null
    this.activeContainers.add(name)
    trackLiveContainer(name)
    try {
      const ipc = makeOneShotIpcDir(scratchSessionId)
      cleanupDir = ipc.cleanupDir
      repoAcquisition = this.acquireReposForCall(options, scratchSessionId)
      const effectiveOptions = repoAcquisition ? { ...options, reposDir: repoAcquisition.mountDir } : options
      await this.docker(this.containerCreateArgs(name, job.assignmentId, [], effectiveOptions, ipc.ipcDir), deadline)
      const result = await this.docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      const parsed = JSON.parse(result) as Record<string, unknown>
      if (parsed.resultRef) {
        return resultSchema.parse(readOneShotRef(ipc.ipcDir, parsed.resultRef))
      }
      return resultSchema.parse(parsed)
    } finally {
      if (cleanupDir) cleanupSessionSubdir(cleanupDir)
      await this.removeContainer(name)
      repoAcquisition?.release()
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
    await ensureWorkerImageAvailable(this.image, this.docker, signal)
    await this.reclaimInactive()
    signal.throwIfAborted()
    const name = 'kovo-' + randomUUID()
    const timeoutMs = (req.timeoutMs ?? 30_000) + 15_000
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
    const repoAcquisition = this.acquireReposForCall(options, `ast-${randomUUID()}`)
    const effectiveOptions = repoAcquisition ? { ...options, reposDir: repoAcquisition.mountDir } : options
    this.activeContainers.add(name)
    trackLiveContainer(name)
    try {
      await this.docker(this.containerCreateArgs(name, assignmentId, [], effectiveOptions), deadline)
      const result = await this.docker(['container', 'start', '--attach', '--interactive', name], deadline, payload)
      return astVerifyResultSchema.parse(JSON.parse(result))
    } finally {
      await this.removeContainer(name)
      repoAcquisition?.release()
      this.activeContainers.delete(name)
      liveContainers.delete(name)
    }
  }

  async openSession(assignmentId: string, signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
    signal.throwIfAborted()
    await ensureWorkerImageAvailable(this.image, this.docker, signal)
    await this.reclaimInactive()
    signal.throwIfAborted()
    // Warm pool first (best-effort): resolve strictly from the caller's explicit `warmPoolPolicy`
    // or `runId` (NEVER from mutable backend-global `activeWarmPoolPolicy`) so concurrent runs
    // never take each other's warm containers or bind another run's stale `/repos` snapshot.
    // Per-call `rpcMountDir` sockets always bypass the pool for strict isolation.
    const requestedPolicy = options?.warmPoolPolicy?.trim()
    const effectiveRunKey = this.resolveRunKeyForOptions(options)
    let candidateSlot: WarmPoolSlot | undefined
    if (requestedPolicy) {
      const exactSlot = this.warmPools.get(requestedPolicy)
      if (exactSlot && !exactSlot.retired && Boolean(effectiveRunKey) && exactSlot.runKey === effectiveRunKey) {
        candidateSlot = exactSlot
      }
    } else if (effectiveRunKey) {
      const defaultPolicy = this.defaultWarmPolicy()
      for (const slot of this.warmPools.values()) {
        if (!slot.retired && slot.runKey === effectiveRunKey && slot.policy !== defaultPolicy) {
          candidateSlot = slot
          break
        }
      }
    }
    const activeSlot = candidateSlot && !candidateSlot.retired && Boolean(effectiveRunKey) && candidateSlot.runKey === effectiveRunKey
      ? candidateSlot
      : undefined
    let heldSlot: WarmPoolSlot | undefined
    let releasedSlot = false
    const releaseSlot = () => {
      if (releasedSlot) return
      releasedSlot = true
      const slot = heldSlot
      heldSlot = undefined
      if (slot) this.releaseWarmSlot(slot)
    }
    if (activeSlot) {
      this.touchWarmSlot(activeSlot)
      this.acquireWarmSlot(activeSlot)
      heldSlot = activeSlot
    }
    const activePool = activeSlot?.pool
    const warmRepos = activeSlot?.preparedRepos
    const matchesWarmRepos = Boolean(
      activeSlot
      && activePool
      && !options?.rpcMountDir
      && warmRepos
      && effectiveRunKey
      && activeSlot.runKey === effectiveRunKey
      && warmRepos.runKey === effectiveRunKey
      && options?.reposDir
      && normalizeReposDirKey(options.reposDir) === warmRepos.sourceDir,
    )
    let heldWarmRepos: RunRepoSnapshotLease | undefined
    let releasedWarmRepos = false
    const releaseWarmRepos = () => {
      if (releasedWarmRepos) return
      releasedWarmRepos = true
      const lease = heldWarmRepos
      heldWarmRepos = undefined
      this.releaseRunRepoSnapshotLease(lease)
    }
    const takeOptions = matchesWarmRepos && warmRepos
      ? { ...options, reposDir: warmRepos.prepared.mountDir }
      : options
    if (matchesWarmRepos && warmRepos) {
      warmRepos.activeLeases += 1
      heldWarmRepos = warmRepos
    }
    let warm: string | null = null
    try {
      warm = activePool && !options?.rpcMountDir ? await activePool.take(signal, takeOptions) : null
    } catch (error) {
      releaseWarmRepos()
      releaseSlot()
      throw error
    }
    if (warm === null) {
      releaseWarmRepos()
      releaseSlot()
    }
    let pooled = warm !== null
    let name = warm ?? 'kovo-' + randomUUID()
    this.sessionsServed += 1
    if (pooled && activePool) this.pooled.set(name, activePool)
    else this.coldSessionCreates += 1
    this.activeContainers.add(name)
    trackLiveContainer(name)
    let repoAcquisition: { mountDir: string; release: () => void } | null = null
    const cleanupRepos = () => {
      const current = repoAcquisition
      repoAcquisition = null
      current?.release()
    }
    const createColdSessionContainer = async (targetName: string) => {
      repoAcquisition = this.acquireReposForCall(options, `sess-${randomUUID()}`)
      const effectiveOptions = repoAcquisition ? { ...options, reposDir: repoAcquisition.mountDir } : options
      await this.docker(this.containerCreateArgs(targetName, assignmentId, ['--session'], effectiveOptions), AbortSignal.any([signal, AbortSignal.timeout(15_000)]))
    }
    if (!pooled) {
      try {
        await createColdSessionContainer(name)
      } catch (error) {
        await this.removeContainer(name)
        cleanupRepos()
        releaseWarmRepos()
        releaseSlot()
        this.activeContainers.delete(name)
        liveContainers.delete(name)
        throw error
      }
    }

    let cli: ChildProcess
    try {
      // A container that exists but never gets `start` must not outlive this call: spawn can
      // throw synchronously (bad DOCKER_HOST, CLI removed) or be aborted by a dead session.
      cli = this.spawnSession(name)
    } catch (error) {
      await this.removeContainer(name)
      cleanupRepos()
      releaseWarmRepos()
      releaseSlot()
      this.activeContainers.delete(name)
      liveContainers.delete(name)
      if (!pooled) throw error
      // Cold-start fallback on a stale pooled miss.
      pooled = false
      name = 'kovo-' + randomUUID()
      this.coldSessionCreates += 1
      this.activeContainers.add(name)
      trackLiveContainer(name)
      try {
        await createColdSessionContainer(name)
        cli = this.spawnSession(name)
      } catch (coldError) {
        await this.removeContainer(name)
        cleanupRepos()
        this.activeContainers.delete(name)
        liveContainers.delete(name)
        throw coldError
      }
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
        void removeContainer().finally(() => { cleanupRepos(); releaseWarmRepos(); releaseSlot() })
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
      void removeContainer().finally(() => { cleanupRepos(); releaseWarmRepos(); releaseSlot() })
    })

    const close = () => {
      if (closing) return closing
      closing = (async () => {
        closed = true
        // Warm reuse: a clean session (no pending op, process still alive) resets `/tmp` first,
        // then asks the worker to shut down so the stopped container can serve the next
        // assignment without a cold `container create`.
        const reusable = pooled
          && activePool?.enabled === true
          && activeSlot !== undefined
          && !activeSlot.retired
          && this.warmPools.get(activeSlot.policy) === activeSlot
          && pending.size === 0
          && !exited
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
        if (recycled && activePool) {
          const kept = await activePool.release(name)
          if (kept) {
            this.pooled.delete(name)
            this.activeContainers.delete(name)
            releaseWarmRepos()
            releaseSlot()
            // release() re-tracks the container as live: the pool (not this session) owns it now.
            return
          }
        }
        preserveOnExit = false
        await this.removeContainer(name)
        cleanupRepos()
        releaseWarmRepos()
        releaseSlot()
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
