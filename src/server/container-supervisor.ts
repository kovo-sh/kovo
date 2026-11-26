/**
 * Unified Docker lab container lifecycle supervisor (M-6, M-20).
 *
 * Single owner for:
 *   - Active lab run/container tracking across LabRunner instances in a process
 *   - Owner-PID labeling (`dev.kovo.owner-pid`) so live sibling processes are never disrupted
 *   - Durable crash-recovery state records and SQLite `LabContainerStore` row synchronization
 *   - Startup orphan Docker reaping (`recoverAll`) that removes live Docker containers, networks,
 *     volumes, and scratch directories *before* clearing SQLite registry rows
 *   - Synchronous signal/exit best-effort reaping (`reapSyncAll`)
 */
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import type { Server as TcpServer } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, isAbsolute, join } from 'node:path'
import {
  LAB_LABELS,
  LAB_PATHS,
  LAB_STATE_DIR_ENV,
  runDocker,
  safeRemoveLabTempDir,
  spawnDockerSync,
  validateLabRunId,
} from './lab-proxy.ts'
import type { DockerRunner, LabConfig, LabServiceSpec } from './lab-proxy.ts'

export const LAB_OWNER_PID_LABEL = 'dev.kovo.owner-pid'

const MAX_RECOVERED_RUNS = 32

export type LabContainerStatus = 'running' | 'orphaned' | 'reclaimed'

/**
 * Narrow structural view of the merged v6 Store lab-container registry.
 */
export interface LabContainerStore {
  recordLabContainer(input: {
    runId: string
    assignmentId?: string | null
    containerName: string
    imageName?: string | null
    status?: LabContainerStatus
  }): unknown
  markLabContainerOrphaned(runId: string, containerName: string): void
  listLabContainers(runId: string): Array<{ containerName: string; status?: string }>
  listOrphanedLabContainers?(): Array<{ runId: string; containerName: string; status?: string }>
}

export interface PersistedLabContainerRef {
  runId: string
  containerName: string
}

export interface LabReclaimResult {
  removed: number
  skipped: number
  mismatched: number
}

export interface LabRunRecord {
  version: 1
  runId: string
  networkName: string
  containerNames: string[]
  containerIds: string[]
  proxyContainerName?: string
  volumes: string[]
  sanitizedRepoDir?: string
  telemetryDir?: string
  ownsTelemetryDir?: boolean
  proxyDir?: string
  startedAt: number
  updatedAt: number
  pid: number
}

export interface LabRecoveryResult {
  runId: string
  containersRemoved: number
  networksRemoved: number
  volumesRemoved: number
  tempDirsRemoved: number
  recoveredFromRecord: boolean
}

export interface SupervisedTargetHandle {
  targetId: string
  runId: string
  networkName: string
  containerName: string
  containerNames: string[]
  containerIp: string
  imageName: string
  origin: string
  baseUrls: Record<string, string>
  hostPort: number
  internalPort: number
  healthPath: string
  sanitizedRepoDir: string
  seededPersonas: Array<{
    handle: string
    roleLabel: string
    authKind: 'cookie' | 'bearer' | 'header'
    headerName?: string
    personaId?: string
  }>
  telemetryDir?: string
  startedAt: number
  stop: () => Promise<void>
}

export interface SupervisedTargetState {
  handle: SupervisedTargetHandle
  labConfig: LabConfig
  primaryService: LabServiceSpec
  builtImages: string[]
  containerNames: string[]
  containerIds: string[]
  volumes: string[]
  forwarder: TcpServer
  proxyContainerName: string
  proxyDir: string
  ownsTelemetryDir: boolean
  storage?: LabContainerStore
}

// ===========================================================================
// Durable crash-recovery state records
// ===========================================================================

function labRunRecordFileName(runId: string): string {
  const slug = runId.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 96)
  const digest = createHash('sha256').update(runId).digest('hex').slice(0, 8)
  return `${slug}-${digest}.json`
}

/** Directory holding crash-recovery records; owner-only, never inside the repo. */
export function labStateDir(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env[LAB_STATE_DIR_ENV]?.trim()
  return configured && isAbsolute(configured) ? configured : join(tmpdir(), 'kovo-lab-state')
}

export function labRunRecordPath(stateDir: string, runId: string): string {
  validateLabRunId(runId)
  return join(stateDir, labRunRecordFileName(runId))
}

export function readLabRunRecord(stateDir: string, runId: string): LabRunRecord | null {
  const recordPath = labRunRecordPath(stateDir, runId)
  try {
    const raw = readFileSync(recordPath, 'utf8')
    const parsed = JSON.parse(raw) as Partial<LabRunRecord>
    if (!parsed || parsed.version !== 1 || parsed.runId !== runId) return null
    if (!Array.isArray(parsed.containerNames) || !Array.isArray(parsed.containerIds)) return null
    return {
      version: 1,
      runId,
      networkName: typeof parsed.networkName === 'string' ? parsed.networkName : '',
      containerNames: parsed.containerNames.filter((name): name is string => typeof name === 'string').slice(0, 32),
      containerIds: parsed.containerIds.filter((id): id is string => typeof id === 'string').slice(0, 32),
      ...(typeof parsed.proxyContainerName === 'string' ? { proxyContainerName: parsed.proxyContainerName } : {}),
      volumes: Array.isArray(parsed.volumes)
        ? parsed.volumes.filter((name): name is string => typeof name === 'string').slice(0, 32)
        : [],
      ...(typeof parsed.sanitizedRepoDir === 'string' ? { sanitizedRepoDir: parsed.sanitizedRepoDir } : {}),
      ...(typeof parsed.telemetryDir === 'string' ? { telemetryDir: parsed.telemetryDir } : {}),
      ...(parsed.ownsTelemetryDir === true ? { ownsTelemetryDir: true } : {}),
      ...(typeof parsed.proxyDir === 'string' ? { proxyDir: parsed.proxyDir } : {}),
      startedAt: typeof parsed.startedAt === 'number' ? parsed.startedAt : Date.now(),
      updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : Date.now(),
      pid: typeof parsed.pid === 'number' ? parsed.pid : 0,
    }
  } catch {
    return null
  }
}

export function writeLabRunRecord(stateDir: string, record: LabRunRecord): void {
  validateLabRunId(record.runId)
  mkdirSync(stateDir, { recursive: true, mode: 0o700 })
  chmodSync(stateDir, 0o700)
  const target = labRunRecordPath(stateDir, record.runId)
  const tmpPath = join(stateDir, `.${basename(target)}.${randomUUID()}.tmp`)
  writeFileSync(tmpPath, `${JSON.stringify({ ...record, version: 1, updatedAt: Date.now() }, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  })
  try {
    renameSync(tmpPath, target)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
}

export function removeLabRunRecord(stateDir: string, runId: string): void {
  try {
    unlinkSync(labRunRecordPath(stateDir, runId))
  } catch {
    // Idempotent: no record is a success.
  }
}

// ===========================================================================
// Signal / crash reaping
// ===========================================================================

const ACTIVE_SUPERVISORS = new Set<ContainerSupervisor>()
let supervisorSignalHooksInstalled = false

export interface LabSignalHookTarget {
  once(event: 'exit', listener: () => void): unknown
  prependOnceListener(event: 'SIGINT' | 'SIGTERM' | 'SIGHUP', listener: () => void): unknown
  listenerCount(event: 'SIGINT' | 'SIGTERM' | 'SIGHUP'): number
  removeListener(event: 'exit' | 'SIGINT' | 'SIGTERM' | 'SIGHUP', listener: () => void): unknown
}

export interface LabSignalHookOptions {
  reap?: () => void
  reraise?: (signal: 'SIGINT' | 'SIGTERM' | 'SIGHUP') => void
  target?: LabSignalHookTarget
}

export function bindLabSignalHooks(options: LabSignalHookOptions = {}): { dispose(): void } {
  const reap = options.reap ?? (() => {
    for (const supervisor of ACTIVE_SUPERVISORS) supervisor.reapSyncAll()
  })
  const reraise = options.reraise ?? ((signal: 'SIGINT' | 'SIGTERM' | 'SIGHUP') => {
    try {
      process.kill(process.pid, signal)
    } catch {
      // Ignore: the process is already exiting.
    }
  })
  const target = options.target ?? process
  const signalHandlers: Array<['SIGINT' | 'SIGTERM' | 'SIGHUP', () => void]> = []
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    const handler = () => {
      reap()
      // Only re-deliver the signal when no sibling graceful-shutdown listener remains registered
      // (so HTTP server, SQLite WAL, and worker-backend cleanup handlers are never preempted).
      if (target.listenerCount(signal) === 0) {
        reraise(signal)
      }
    }
    signalHandlers.push([signal, handler])
    target.prependOnceListener(signal, handler)
  }
  const onExit = () => reap()
  target.once('exit', onExit)
  return {
    dispose() {
      for (const [signal, handler] of signalHandlers) {
        target.removeListener(signal, handler)
      }
      target.removeListener('exit', onExit)
    },
  }
}

function installSupervisorSignalHooks(): void {
  if (supervisorSignalHooksInstalled) return
  supervisorSignalHooksInstalled = true
  bindLabSignalHooks()
}

function defaultIsPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | null)?.code
    return code === 'EPERM'
  }
}

function isMissingContainerError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err)
  return /no such container|no such object|not found/i.test(msg)
}

// ===========================================================================
// ContainerSupervisor
// ===========================================================================

export interface ContainerSupervisorOptions {
  /** Where crash-recovery records live. Defaults to KOVO_LAB_STATE_DIR or <tmp>/kovo-lab-state. */
  stateDir?: string
  /** Injectable Docker CLI runner (tests use a deterministic fake). */
  docker?: DockerRunner
  env?: NodeJS.ProcessEnv
  /** Owner process PID written to container labels and used to detect stale crash leftovers. */
  ownerPid?: number
  /** Optional PID liveness predicate for deterministic unit testing. */
  isPidAlive?: (pid: number) => boolean
}

export class ContainerSupervisor {
  readonly docker: DockerRunner
  readonly stateDir: string
  readonly env: NodeJS.ProcessEnv
  readonly ownerPid: number
  private readonly isPidAliveFn: (pid: number) => boolean
  private readonly active = new Map<string, SupervisedTargetState>()
  private readonly inFlightBootIds = new Set<string>()
  private startupRecoveryInFlight: Promise<LabRecoveryResult[]> | null = null

  constructor(options: ContainerSupervisorOptions = {}) {
    this.docker = options.docker ?? runDocker
    this.env = options.env ?? process.env
    this.stateDir = options.stateDir ?? labStateDir(this.env)
    this.ownerPid = options.ownerPid ?? process.pid
    this.isPidAliveFn = options.isPidAlive ?? defaultIsPidAlive
  }

  ownerExtraLabels(): Record<string, string> {
    return { [LAB_OWNER_PID_LABEL]: String(this.ownerPid) }
  }

  hasActiveRun(runId: string): boolean {
    return this.active.has(runId)
  }

  markBooting(runId: string): void {
    validateLabRunId(runId)
    this.inFlightBootIds.add(runId)
  }

  clearBooting(runId: string): void {
    this.inFlightBootIds.delete(runId)
  }

  isBooting(runId: string): boolean {
    return this.inFlightBootIds.has(runId)
  }

  getActiveRun(runId: string): SupervisedTargetState | undefined {
    return this.active.get(runId)
  }

  listActiveRuns(): SupervisedTargetState[] {
    return [...this.active.values()]
  }

  registerActiveRun(runId: string, state: SupervisedTargetState): void {
    installSupervisorSignalHooks()
    ACTIVE_SUPERVISORS.add(this)
    this.inFlightBootIds.delete(runId)
    this.active.set(runId, state)
    this.persistState(runId)
  }

  deleteActiveRun(runId: string): SupervisedTargetState | undefined {
    const state = this.active.get(runId)
    this.active.delete(runId)
    return state
  }

  async tryDocker(args: string[], signal?: AbortSignal): Promise<boolean> {
    try {
      await this.docker(args, signal ?? AbortSignal.timeout(10_000))
      return true
    } catch {
      return false
    }
  }

  async listByLabel(kind: 'container' | 'network' | 'volume', runId: string): Promise<string[]> {
    const args = kind === 'container'
      ? ['ps', '-aq', '--filter', `label=${LAB_LABELS.run}=${runId}`]
      : kind === 'network'
        ? ['network', 'ls', '-q', '--filter', `label=${LAB_LABELS.run}=${runId}`]
        : ['volume', 'ls', '-q', '--filter', `label=${LAB_LABELS.run}=${runId}`]
    try {
      const out = await this.docker(args, AbortSignal.timeout(10_000))
      return out.trim().split(/\s+/).filter(Boolean).slice(0, 64)
    } catch {
      return []
    }
  }

  private recordFor(runId: string, state: SupervisedTargetState): LabRunRecord {
    return {
      version: 1,
      runId,
      networkName: state.handle.networkName,
      containerNames: [...state.containerNames],
      containerIds: [...state.containerIds],
      proxyContainerName: state.proxyContainerName,
      volumes: [...state.volumes],
      sanitizedRepoDir: state.handle.sanitizedRepoDir,
      ...(state.handle.telemetryDir ? { telemetryDir: state.handle.telemetryDir } : {}),
      ownsTelemetryDir: state.ownsTelemetryDir,
      proxyDir: state.proxyDir,
      startedAt: state.handle.startedAt,
      updatedAt: Date.now(),
      pid: this.ownerPid,
    }
  }

  /**
   * Persist crash-recovery state. When a SQLite `LabContainerStore` is attached, `lab_containers`
   * rows plus Docker labels are the durable authority, so we avoid duplicating JSON files.
   */
  persistState(runId: string): void {
    const state = this.active.get(runId)
    if (!state || state.storage) return
    try {
      writeLabRunRecord(this.stateDir, this.recordFor(runId, state))
    } catch {
      // Persistence is best-effort: label-based reaping still covers a crash.
    }
  }

  recordContainerRow(
    storage: LabContainerStore | undefined,
    runId: string,
    containerName: string,
    imageName: string,
    status: LabContainerStatus,
  ): void {
    if (!storage) return
    try {
      storage.recordLabContainer({ runId, containerName, imageName, status })
    } catch {
      // Registry persistence is advisory: label-based reaping still covers a missing row.
    }
  }

  markContainerOrphaned(
    storage: LabContainerStore | undefined,
    runId: string,
    containerName: string,
  ): void {
    if (!storage) return
    try {
      storage.markLabContainerOrphaned(runId, containerName)
    } catch {
      // Best-effort: the durable label/recovery record remains the source of truth.
    }
  }

  deleteContainerRow(
    storage: LabContainerStore | undefined,
    runId: string,
    containerName: string,
  ): void {
    if (!storage) return
    try {
      const extended = storage as unknown as {
        deleteLabContainer?: (runId: string, containerName: string) => void
        client?: { prepare: (sql: string) => { run: (...params: unknown[]) => unknown } }
      }
      if (typeof extended.deleteLabContainer === 'function') {
        extended.deleteLabContainer(runId, containerName)
        return
      }
      if (extended.client) {
        extended.client
          .prepare('DELETE FROM lab_containers WHERE run_id = ? AND container_name = ?')
          .run(runId, containerName)
      }
    } catch {
      // Best-effort: a stale row is reclaimed on the next restart.
    }
  }

  /**
   * Remove a Docker container and delete its SQLite registry row ONLY when removal actually
   * succeeded (or `inspect` explicitly reports the container no longer exists). If removal fails
   * and Docker cannot confirm absence, keep the row marked `'orphaned'` for `recoverAll()`.
   */
  async removeContainerAndRow(
    storage: LabContainerStore | undefined,
    runId: string,
    containerName: string,
  ): Promise<boolean> {
    const removed = await this.tryDocker(['container', 'rm', '--force', containerName], AbortSignal.timeout(10_000))
    if (removed) {
      this.deleteContainerRow(storage, runId, containerName)
      return true
    }
    try {
      await this.docker(['inspect', '-f', '{{.Id}}', containerName], AbortSignal.timeout(5_000))
      // Container still exists in Docker: keep row marked orphaned so recoverAll() can reap it later.
      this.markContainerOrphaned(storage, runId, containerName)
      return false
    } catch (err) {
      if (isMissingContainerError(err)) {
        this.deleteContainerRow(storage, runId, containerName)
      } else {
        // Docker daemon unreachable or transient error: never drop the tracked row silently.
        this.markContainerOrphaned(storage, runId, containerName)
      }
      return false
    }
  }

  async cleanupDockerArtifacts(params: {
    volumes?: readonly string[]
    images?: readonly string[]
    networkName?: string
  }): Promise<void> {
    for (const vol of params.volumes ?? []) {
      await this.docker(['volume', 'rm', '--force', vol], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    for (const img of params.images ?? []) {
      await this.docker(['image', 'rm', '--force', img], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    if (params.networkName) {
      await this.docker(['network', 'rm', params.networkName], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
  }

  async sweepOrphanContainersForRun(runId: string): Promise<void> {
    const ids = await this.listByLabel('container', runId)
    if (ids.length === 0) return
    const batchRemoved = await this.tryDocker(['container', 'rm', '--force', ...ids], AbortSignal.timeout(10_000))
    if (!batchRemoved && ids.length > 1) {
      await Promise.all(ids.map(id => this.tryDocker(['container', 'rm', '--force', id], AbortSignal.timeout(5_000))))
    }
  }

  /**
   * Reclaim containers persisted in SQLite (`Store.recover()`). Each candidate is removed only
   * when its `dev.kovo.run` label matches the requested run.
   */
  async reclaimPersisted(
    containers: ReadonlyArray<PersistedLabContainerRef>,
    storage?: LabContainerStore,
  ): Promise<LabReclaimResult> {
    const result: LabReclaimResult = { removed: 0, skipped: 0, mismatched: 0 }
    const seen = new Set<string>()
    for (const ref of containers.slice(0, 64)) {
      if (
        typeof ref?.runId !== 'string' ||
        typeof ref?.containerName !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(ref.runId) ||
        !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(ref.containerName)
      ) {
        result.skipped += 1
        continue
      }
      const key = `${ref.runId}\u0000${ref.containerName}`
      if (seen.has(key)) continue
      seen.add(key)

      let label: string | null = null
      try {
        label = (await this.docker(
          ['inspect', '-f', `{{index .Config.Labels "${LAB_LABELS.run}"}}`, ref.containerName],
          AbortSignal.timeout(5_000),
        )).trim()
      } catch (err) {
        if (isMissingContainerError(err)) {
          this.deleteContainerRow(storage, ref.runId, ref.containerName)
        }
        result.skipped += 1
        continue
      }
      if (label !== ref.runId) {
        result.mismatched += 1
        continue
      }
      const removed = await this.tryDocker(['container', 'rm', '--force', ref.containerName], AbortSignal.timeout(10_000))
      if (removed) {
        result.removed += 1
        this.deleteContainerRow(storage, ref.runId, ref.containerName)
      } else {
        result.skipped += 1
      }
    }
    return result
  }

  /**
   * Reap every resource for a run: containers/networks/volumes by label, plus every path in the
   * persisted crash record and SQLite registry rows. Idempotent.
   */
  async recover(
    runId: string,
    storage?: LabContainerStore,
    extraContainerNames: readonly string[] = [],
  ): Promise<LabRecoveryResult> {
    validateLabRunId(runId)
    if (this.inFlightBootIds.has(runId)) {
      return {
        runId,
        containersRemoved: 0,
        networksRemoved: 0,
        volumesRemoved: 0,
        tempDirsRemoved: 0,
        recoveredFromRecord: false,
      }
    }
    if (this.active.has(runId)) {
      await this.stopRun(runId)
    }
    const record = readLabRunRecord(this.stateDir, runId)
    const result: LabRecoveryResult = {
      runId,
      containersRemoved: 0,
      networksRemoved: 0,
      volumesRemoved: 0,
      tempDirsRemoved: 0,
      recoveredFromRecord: record !== null,
    }

    const containerTargets = new Set<string>([
      ...(record?.containerNames ?? []),
      ...(record?.containerIds ?? []),
      ...(record?.proxyContainerName ? [record.proxyContainerName] : []),
      ...extraContainerNames,
      ...(await this.listByLabel('container', runId)),
    ])
    const processedContainers = new Set<string>()
    for (const target of containerTargets) {
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(target)) continue
      if (await this.removeContainerAndRow(storage, runId, target)) result.containersRemoved += 1
      processedContainers.add(target)
    }
    if (storage) {
      try {
        for (const row of storage.listLabContainers(runId)) {
          if (processedContainers.has(row.containerName)) continue
          if (await this.removeContainerAndRow(storage, runId, row.containerName)) result.containersRemoved += 1
        }
      } catch {
        // Registry cleanup is best-effort; the next recoverAll() retries.
      }
    }

    const networkTargets = new Set<string>([
      ...(record?.networkName ? [record.networkName] : []),
      ...(await this.listByLabel('network', runId)),
    ])
    for (const network of networkTargets) {
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(network)) continue
      if (await this.tryDocker(['network', 'rm', network])) result.networksRemoved += 1
    }

    const volumeTargets = new Set<string>([
      ...(record?.volumes ?? []),
      ...(await this.listByLabel('volume', runId)),
    ])
    for (const volume of volumeTargets) {
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(volume)) continue
      if (await this.tryDocker(['volume', 'rm', '--force', volume])) result.volumesRemoved += 1
    }

    if (safeRemoveLabTempDir(record?.sanitizedRepoDir, [LAB_PATHS.repoPrefix])) result.tempDirsRemoved += 1
    if (record?.ownsTelemetryDir && safeRemoveLabTempDir(record.telemetryDir)) result.tempDirsRemoved += 1
    if (safeRemoveLabTempDir(record?.proxyDir, [LAB_PATHS.proxyPrefix])) result.tempDirsRemoved += 1

    removeLabRunRecord(this.stateDir, runId)
    return result
  }

  private collectStoreOrphanRunIds(storage: LabContainerStore | undefined): string[] {
    if (!storage) return []
    const runIds = new Set<string>()
    const addValid = (raw: unknown) => {
      if (typeof raw === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(raw)) {
        runIds.add(raw)
      }
    }
    try {
      if (typeof storage.listOrphanedLabContainers === 'function') {
        for (const row of storage.listOrphanedLabContainers()) {
          addValid(row.runId)
        }
      }
      const extended = storage as unknown as {
        rows?: Map<string, { runId: string; status?: string }>
        client?: { prepare: (sql: string) => { all: (...params: unknown[]) => Array<{ run_id?: string }> } }
      }
      if (extended.client) {
        const rows = extended.client
          .prepare("SELECT DISTINCT run_id FROM lab_containers WHERE status IN ('orphaned', 'running')")
          .all()
        for (const row of rows) {
          addValid(row.run_id)
        }
      } else if (extended.rows instanceof Map) {
        for (const row of extended.rows.values()) {
          if (!row.status || row.status === 'orphaned' || row.status === 'running') {
            addValid(row.runId)
          }
        }
      }
    } catch {
      // Best-effort store scan.
    }
    return [...runIds]
  }

  /**
   * Idempotent startup recovery hook for server initialization. Coalesces concurrent boot calls
   * so Docker + SQLite orphan reaping runs cleanly without racing itself or mid-boot runs.
   */
  ensureStartupRecovery(
    storage?: LabContainerStore,
    options: { includeLiveOwners?: boolean; persistedContainers?: ReadonlyArray<PersistedLabContainerRef> } = {},
  ): Promise<LabRecoveryResult[]> {
    if (!this.startupRecoveryInFlight) {
      this.startupRecoveryInFlight = this.recoverAll(storage, options).finally(() => {
        this.startupRecoveryInFlight = null
      })
    }
    return this.startupRecoveryInFlight
  }

  /**
   * Recover every orphaned run found in persisted crash records, Docker `dev.kovo.lab=1` label
   * scans (skipping containers owned by a different still-alive PID or currently booting), and
   * optional `LabContainerStore` / pre-collected persisted rows.
   */
  async recoverAll(
    storage?: LabContainerStore,
    options: { includeLiveOwners?: boolean; persistedContainers?: ReadonlyArray<PersistedLabContainerRef> } = {},
  ): Promise<LabRecoveryResult[]> {
    const runIds = new Set<string>()
    const extraContainersByRun = new Map<string, string[]>()
    const liveOwnerRunIds = new Set<string>()
    const isProtectedRun = (runId: string) => this.active.has(runId) || this.inFlightBootIds.has(runId)

    // 0. Optional pre-collected persisted rows (e.g., returned by Store.recover() before row wipe)
    for (const ref of options.persistedContainers ?? []) {
      if (
        typeof ref?.runId !== 'string'
        || typeof ref?.containerName !== 'string'
        || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(ref.runId)
        || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(ref.containerName)
      ) {
        continue
      }
      if (isProtectedRun(ref.runId)) continue
      runIds.add(ref.runId)
      const list = extraContainersByRun.get(ref.runId) ?? []
      list.push(ref.containerName)
      extraContainersByRun.set(ref.runId, list)
    }

    // 1. Persisted JSON crash-recovery records
    try {
      for (const entry of readdirSync(this.stateDir)) {
        if (!entry.endsWith('.json')) continue
        try {
          const parsed = JSON.parse(readFileSync(join(this.stateDir, entry), 'utf8')) as {
            runId?: unknown
            pid?: unknown
          }
          const pid = typeof parsed.pid === 'number' ? parsed.pid : 0
          if (
            !options.includeLiveOwners
            && pid > 0
            && pid !== this.ownerPid
            && this.isPidAliveFn(pid)
          ) {
            if (typeof parsed.runId === 'string') liveOwnerRunIds.add(parsed.runId)
            continue
          }
          if (typeof parsed.runId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(parsed.runId)) {
            if (!isProtectedRun(parsed.runId)) runIds.add(parsed.runId)
          }
        } catch {
          // Ignore unreadable/corrupt records; the label scan below still finds live orphans.
        }
      }
    } catch {
      // No state dir yet.
    }

    // 2. Store orphaned / stale rows (M-6): inspect active/orphaned rows BEFORE deletion
    for (const storeRunId of this.collectStoreOrphanRunIds(storage)) {
      if (!isProtectedRun(storeRunId)) {
        runIds.add(storeRunId)
      }
    }

    // 3. Docker label scan (`dev.kovo.lab=1`), checking `dev.kovo.owner-pid` when present
    try {
      const ids = (await this.docker(['ps', '-aq', '--filter', `label=${LAB_LABELS.lab}=1`], AbortSignal.timeout(10_000)))
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 64)
      if (ids.length > 0) {
        const labels = await this.docker(
          [
            'inspect',
            '-f',
            `{{index .Config.Labels "${LAB_LABELS.run}"}}\t{{index .Config.Labels "${LAB_OWNER_PID_LABEL}"}}`,
            ...ids,
          ],
          AbortSignal.timeout(10_000),
        )
        const lines = labels.split('\n').map(l => l.trim()).filter(Boolean)
        for (let i = 0; i < lines.length; i += 1) {
          const line = lines[i]
          const tabIdx = line.indexOf('\t')
          const runId = (tabIdx >= 0 ? line.slice(0, tabIdx) : line).trim()
          const ownerPidRaw = (tabIdx >= 0 ? line.slice(tabIdx + 1) : '').trim()
          const ownerPidNum = /^\d+$/.test(ownerPidRaw) ? Number(ownerPidRaw) : 0
          const isOtherLiveOwner = !options.includeLiveOwners
            && ownerPidNum > 0
            && ownerPidNum !== this.ownerPid
            && this.isPidAliveFn(ownerPidNum)
          if (isOtherLiveOwner) {
            if (runId && runId !== '<no value>') liveOwnerRunIds.add(runId)
            continue
          }

          if (
            runId
            && runId !== '<no value>'
            && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(runId)
          ) {
            if (!isProtectedRun(runId)) {
              runIds.add(runId)
            }
          } else if (ids[i] && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(ids[i])) {
            // Unlabelled-run container carrying `dev.kovo.lab=1` with dead/no owner PID: reap directly.
            await this.tryDocker(['container', 'rm', '--force', ids[i]], AbortSignal.timeout(10_000))
          }
        }
      }
    } catch {
      // Docker unavailable: records still get cleaned up.
    }

    const results: LabRecoveryResult[] = []
    for (const runId of [...runIds].slice(0, MAX_RECOVERED_RUNS)) {
      if (runId === '<no value>' || isProtectedRun(runId) || liveOwnerRunIds.has(runId)) continue
      results.push(await this.recover(runId, storage, extraContainersByRun.get(runId)))
    }
    return results
  }

  /**
   * Synchronous best-effort reaping used from SIGINT/SIGTERM/exit handlers where async cleanup
   * cannot run.
   */
  reapSyncAll(): void {
    for (const [runId, state] of this.active.entries()) {
      for (const name of [state.proxyContainerName, ...state.containerNames]) {
        if (/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(name)) spawnDockerSync(['container', 'rm', '--force', name])
      }
      for (const id of state.containerIds) {
        if (/^[a-f0-9]{12,64}$/.test(id)) spawnDockerSync(['container', 'rm', '--force', id])
      }
      for (const listed of spawnDockerSync(['ps', '-aq', '--filter', `label=${LAB_LABELS.run}=${runId}`])
        .trim().split(/\s+/).filter(Boolean)) {
        spawnDockerSync(['container', 'rm', '--force', listed])
      }
      spawnDockerSync(['network', 'rm', state.handle.networkName])
      for (const volume of state.volumes) spawnDockerSync(['volume', 'rm', '--force', volume])
      safeRemoveLabTempDir(state.handle.sanitizedRepoDir, [LAB_PATHS.repoPrefix])
      safeRemoveLabTempDir(state.proxyDir, [LAB_PATHS.proxyPrefix])
      if (state.ownsTelemetryDir) safeRemoveLabTempDir(state.handle.telemetryDir)
      removeLabRunRecord(this.stateDir, runId)
    }
    this.active.clear()
  }

  async stopRun(runId: string): Promise<void> {
    const state = this.active.get(runId)
    if (!state) {
      removeLabRunRecord(this.stateDir, runId)
      return
    }
    this.active.delete(runId)

    await new Promise<void>(res => state.forwarder.close(() => res())).catch(() => undefined)
    await Promise.all([
      this.removeContainerAndRow(state.storage, runId, state.proxyContainerName),
      ...state.containerNames.map(cname => this.removeContainerAndRow(state.storage, runId, cname)),
    ])
    await this.sweepOrphanContainersForRun(runId)
    await this.cleanupDockerArtifacts({
      volumes: state.volumes,
      images: state.builtImages,
      networkName: state.handle.networkName,
    })
    safeRemoveLabTempDir(state.handle.sanitizedRepoDir, [LAB_PATHS.repoPrefix])
    safeRemoveLabTempDir(state.proxyDir, [LAB_PATHS.proxyPrefix])
    if (state.ownsTelemetryDir && state.handle.telemetryDir) {
      safeRemoveLabTempDir(state.handle.telemetryDir)
    }
    removeLabRunRecord(this.stateDir, runId)
  }

  async stopAll(): Promise<void> {
    const ids = [...this.active.keys()]
    await Promise.all(ids.map(id => this.stopRun(id)))
  }
}

let sharedSupervisor: ContainerSupervisor | undefined

export function getSharedContainerSupervisor(): ContainerSupervisor {
  if (!sharedSupervisor) {
    sharedSupervisor = new ContainerSupervisor()
  }
  return sharedSupervisor
}
