import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  copyFileSync,
  existsSync,
  fchmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import type { Stats } from 'node:fs'
import type { Server as TcpServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { parseUnifiedDiff } from './unified-diff.ts'
import {
  ContainerSupervisor,
  LAB_OWNER_PID_LABEL,
  bindLabSignalHooks,
  getSharedContainerSupervisor,
  labRunRecordPath,
  labStateDir,
  readLabRunRecord,
  removeLabRunRecord,
  writeLabRunRecord,
} from './container-supervisor.ts'
import type {
  ContainerSupervisorOptions,
  LabContainerStatus,
  LabContainerStore,
  LabReclaimResult,
  LabRecoveryResult,
  LabRunRecord,
  LabSignalHookOptions,
  LabSignalHookTarget,
  PersistedLabContainerRef,
} from './container-supervisor.ts'
import {
  LAB_DB_VOLUMES_ENV,
  LAB_LABELS,
  LAB_PATHS,
  LAB_PROXY_IMAGE_DEFAULT,
  LAB_PROXY_IMAGE_ENV,
  buildLabContainerRunArgs,
  buildLabNetworkCreateArgs,
  buildLabProxyRunArgs,
  buildWritableDataOverlay,
  createLabProxyDir,
  createLoopbackSocketForwarder,
  defaultLabDatabasePort,
  deriveHealthPathFromHealthcheck,
  detectLabDatabaseKind,
  labProxySocketMode,
  parseSeededPersonasFromStdout,
  resolveLabContainerUser,
  resolveLabStackServices,
  resolveStartCommand,
  rewriteSqliteDatabaseUrl,
  safeRemoveLabTempDir,
  validateLabRunId,
  waitForContainerPort,
  waitForHealthCheck,
  waitForLabProxySocket,
  writeLabProxyTarget,
} from './lab-proxy.ts'
import type { DockerRunner, LabConfig, LabServiceSpec, LabWritableOverlay } from './lab-proxy.ts'
import { buildIastContainerWiring, provisionRunTelemetryDir } from './lab-telemetry.ts'
import { createProjectPersona, listProjectPersonas } from './persona-vault.ts'
import type { Store } from './store.ts'
import { parseComposeInWorker } from './untrusted-compute-pool.ts'

// Re-export ContainerSupervisor and extracted proxy, network, compose, overlay, and IAST telemetry modules.
export {
  ContainerSupervisor,
  LAB_OWNER_PID_LABEL,
  bindLabSignalHooks,
  getSharedContainerSupervisor,
  labRunRecordPath,
  labStateDir,
  readLabRunRecord,
  removeLabRunRecord,
  writeLabRunRecord,
}
export type {
  ContainerSupervisorOptions,
  LabContainerStatus,
  LabContainerStore,
  LabReclaimResult,
  LabRecoveryResult,
  LabRunRecord,
  LabSignalHookOptions,
  LabSignalHookTarget,
  PersistedLabContainerRef,
}
export {
  LAB_CONTAINER_USER_ENV,
  LAB_DB_VOLUMES_ENV,
  LAB_LABELS,
  LAB_PATHS,
  LAB_PROXY_IMAGE_DEFAULT,
  LAB_PROXY_IMAGE_ENV,
  LAB_PROXY_SCRIPT,
  LAB_STATE_DIR_ENV,
  buildLabContainerRunArgs,
  buildLabNetworkCreateArgs,
  buildLabProxyRunArgs,
  buildWritableDataOverlay,
  createLabProxyDir,
  createLoopbackSocketForwarder,
  defaultLabDatabasePort,
  deriveHealthPathFromHealthcheck,
  detectLabDatabaseKind,
  labDataVolumeName,
  labProxySocketMode,
  normalizeImageRepository,
  parseAndSanitizeComposeYaml,
  resolveLabContainerUser,
  rewriteSqliteDatabaseUrl,
  safeRemoveLabTempDir,
  validateLabRunId,
  waitForLabProxySocket,
  writeLabProxyTarget,
} from './lab-proxy.ts'
export type {
  DockerRunner,
  LabConfig,
  LabContainerRunArgsInput,
  LabDatabaseKind,
  LabProxyRunArgsInput,
  LabServiceHealthcheck,
  LabServiceSpec,
  LabWritableOverlay,
  LabWritableOverlayInput,
} from './lab-proxy.ts'
export {
  MAX_IAST_TELEMETRY_RUN_DIRS,
  MAX_IAST_TELEMETRY_TOTAL_BYTES,
  assertIastTelemetryDirWritable,
  buildIastTelemetryMountArgs,
  createPerRunIastTelemetryDir,
  ingestLabTelemetry,
  prepareIastTelemetryDir,
  pruneLabTelemetryDirs,
} from './lab-telemetry.ts'
export type { IngestLabTelemetryInput, IngestLabTelemetryResult } from './lab-telemetry.ts'

export interface SeededPersonaSummary {
  handle: string
  roleLabel: string
  authKind: 'cookie' | 'bearer' | 'header'
  headerName?: string
  personaId?: string
}

export interface StartLabTargetParams {
  runId: string
  environment: 'public' | 'local-lab'
  repoDir: string
  labConfig?: LabConfig
  signal?: AbortSignal
  telemetryDir?: string
  storage?: Store
  projectId?: string
}

export interface LabTargetHandle {
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
  seededPersonas: SeededPersonaSummary[]
  telemetryDir?: string
  startedAt: number
  stop: () => Promise<void>
}

const EXCLUDED_DIR_NAMES = new Set(['.git', '.aws', '.ssh', '.gnupg', '.kube'])

const EXCLUDED_FILE_PATTERNS = [
  /^\.env(?:\..+)?$/i,
  /\.(?:pem|key|p12|pfx|jks|keystore)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
  /^\.(?:npmrc|netrc|pypirc|dockercfg)$/i,
  /^(?:secrets|credentials)\.(?:json|ya?ml|toml|env|txt)$/i,
]

/** Default and bounded resource limits for local-lab target containers so 12 concurrent worker containers fit comfortably in host RAM. */
export const DEFAULT_LAB_MEMORY_LIMIT = '512m'
export const MAX_LAB_MEMORY_LIMIT_MB = 2048
export const DEFAULT_LAB_CPUS = '1.0'
export const MAX_LAB_CPUS = 4.0
export const DEFAULT_LAB_PIDS_LIMIT = 128
export const MAX_LAB_PIDS_LIMIT = 512

function parseDockerMemoryLimitMb(raw: string | undefined): number | null {
  if (!raw) return null
  const match = /^(\d+(?:\.\d+)?)\s*([kmg])?b?$/i.exec(raw.trim())
  if (!match) return null
  const amount = Number(match[1])
  if (!Number.isFinite(amount) || amount <= 0) return null
  const unit = (match[2] ?? 'm').toLowerCase()
  if (unit === 'g') return Math.round(amount * 1024)
  if (unit === 'k') return Math.max(1, Math.round(amount / 1024))
  return Math.round(amount)
}

/** Resolve bounded memory, CPU, and PIDs limits for a local-lab service container. */
export function resolveLabServiceResourceLimits(
  service: Pick<LabServiceSpec, 'memoryLimit' | 'cpus' | 'pidsLimit'>,
  labConfig: Pick<LabConfig, 'memoryLimit' | 'cpus' | 'pidsLimit'>,
  env: NodeJS.ProcessEnv = process.env,
): { memoryLimit: string; cpus: string; pidsLimit: number } {
  const maxMemMbRaw = parseDockerMemoryLimitMb(env.KOVO_LAB_MAX_MEMORY_LIMIT)
  const maxMemMb = maxMemMbRaw ? Math.max(128, Math.min(8192, maxMemMbRaw)) : MAX_LAB_MEMORY_LIMIT_MB
  const rawMemory = (service.memoryLimit ?? labConfig.memoryLimit ?? '').trim()
  const parsedMemMb = parseDockerMemoryLimitMb(rawMemory)
  const memoryLimit = parsedMemMb !== null
    ? `${Math.max(64, Math.min(maxMemMb, parsedMemMb))}m`
    : DEFAULT_LAB_MEMORY_LIMIT

  const rawCpus = Number((service.cpus ?? labConfig.cpus ?? '').trim())
  const cpus = Number.isFinite(rawCpus) && rawCpus > 0
    ? Math.max(0.25, Math.min(MAX_LAB_CPUS, rawCpus)).toFixed(2).replace(/\.00$/, '.0')
    : DEFAULT_LAB_CPUS

  const rawPids = service.pidsLimit ?? labConfig.pidsLimit
  const pidsLimit = typeof rawPids === 'number' && Number.isFinite(rawPids) && rawPids > 0
    ? Math.max(32, Math.min(MAX_LAB_PIDS_LIMIT, Math.floor(rawPids)))
    : DEFAULT_LAB_PIDS_LIMIT

  return { memoryLimit, cpus, pidsLimit }
}

export function assertLocalLabAllowed(environment: string): void {
  if (environment !== 'local-lab') {
    throw new Error(
      `Local-lab app runner is forbidden on "${environment}" projects. Requires project.environment === 'local-lab'.`,
    )
  }
  if (process.env.KOVO_ALLOW_LOCAL_LAB !== '1') {
    throw new Error('Local-lab app runner requires KOVO_ALLOW_LOCAL_LAB=1.')
  }
}

// ===========================================================================
// Repository sanitization & confinement-checked unified diff patching
// ===========================================================================

function shouldSkipCopy(name: string, isDir: boolean): boolean {
  if (isDir) return EXCLUDED_DIR_NAMES.has(name)
  return EXCLUDED_FILE_PATTERNS.some(pattern => pattern.test(name))
}

function copySanitizedRepo(srcDir: string, destDir: string, rootReal: string): void {
  mkdirSync(destDir, { recursive: true, mode: 0o755 })
  // Ensure world-readable directory traversal so --cap-drop ALL (no CAP_DAC_OVERRIDE) containers can read /app.
  chmodSync(destDir, 0o755)
  for (const entry of readdirSync(srcDir)) {
    const srcPath = join(srcDir, entry)
    const dstPath = join(destDir, entry)
    const st = lstatSync(srcPath)
    if (st.isSymbolicLink()) {
      try {
        const targetReal = realpathSync(srcPath)
        const rel = relative(rootReal, targetReal)
        if (rel.startsWith('..') || rel.includes(`${sep}..${sep}`)) continue
      } catch {
        continue
      }
      continue
    }
    if (st.isDirectory()) {
      if (shouldSkipCopy(entry, true)) continue
      copySanitizedRepo(srcPath, dstPath, rootReal)
    } else if (st.isFile()) {
      if (shouldSkipCopy(entry, false)) continue
      copyFileSync(srcPath, dstPath)
      chmodSync(dstPath, (st.mode & 0o111) ? 0o755 : 0o644)
    }
  }
}

/** lstat that treats a missing entry as absent but surfaces every other failure as unsafe. */
function lstatOrNull(fullPath: string, relPath: string): Stats | null {
  try {
    return lstatSync(fullPath)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return null
    throw new Error(`Unsafe file path rejected: "${relPath}" (${code ?? 'lstat failed'})`)
  }
}

export function safeResolveUnderRoot(rootDir: string, relPath: string): string {
  const clean = relPath.replace(/^[ab]\//, '').replace(/\\/g, '/')
  if (!clean || clean.includes('\0') || clean.startsWith('/') || clean.split('/').some(seg => seg === '..')) {
    throw new Error(`Unsafe file path rejected: "${relPath}"`)
  }
  const rootReal = realpathSync(rootDir)
  const full = resolve(rootReal, clean)
  const rel = relative(rootReal, full)
  if (rel.startsWith('..') || rel === '' || isAbsolute(rel)) {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }

  // Walk every component with lstat (not existsSync) and reject any symlink unconditionally.
  let deepestExisting = rootReal
  let cursor = rootReal
  for (const segment of rel.split(sep)) {
    cursor = join(cursor, segment)
    const st = lstatOrNull(cursor, relPath)
    if (!st) break
    if (st.isSymbolicLink()) {
      throw new Error(`Symlinked path rejected inside repository: "${relPath}"`)
    }
    deepestExisting = cursor
  }

  let existingReal: string
  try {
    existingReal = realpathSync(deepestExisting)
  } catch {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }
  const existingRel = relative(rootReal, existingReal)
  if (existingRel.startsWith('..') || isAbsolute(existingRel)) {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }
  return full
}

function ensureSafeParentChain(rootDir: string, fullPath: string, relPath: string): void {
  const rootReal = realpathSync(rootDir)
  const rel = relative(rootReal, fullPath)
  const segments = rel.split(sep).slice(0, -1)
  let cursor = rootReal
  for (const segment of segments) {
    cursor = join(cursor, segment)
    let st = lstatOrNull(cursor, relPath)
    if (!st) {
      try {
        mkdirSync(cursor, { mode: 0o755 })
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
      }
      st = lstatOrNull(cursor, relPath)
      if (!st) throw new Error(`Failed to create patch directory for: "${relPath}"`)
    }
    if (st.isSymbolicLink()) {
      throw new Error(`Symlinked path rejected inside repository: "${relPath}"`)
    }
    if (!st.isDirectory()) {
      throw new Error(`Patch parent path is not a directory: "${relPath}"`)
    }
  }

  const parentReal = realpathSync(dirname(fullPath))
  const parentRel = relative(rootReal, parentReal)
  if (parentRel.startsWith('..') || isAbsolute(parentRel)) {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }
}

function readFileNoFollow(fullPath: string): string {
  const fd = openSync(fullPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
  try {
    return readFileSync(fd, 'utf8')
  } finally {
    closeSync(fd)
  }
}

function writeFileNoFollow(fullPath: string, content: string, createOnly: boolean): void {
  if (createOnly) {
    let fd: number | undefined
    try {
      fd = openSync(
        fullPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
        0o644,
      )
      writeSync(fd, content, null, 'utf8')
      fchmodSync(fd, 0o644)
    } finally {
      if (fd !== undefined) closeSync(fd)
    }
    return
  }

  const parent = dirname(fullPath)
  const tmpPath = join(parent, `.kovo-patch-${randomUUID()}.tmp`)
  let fd: number | undefined
  try {
    fd = openSync(
      tmpPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o644,
    )
    writeSync(fd, content, null, 'utf8')
    fchmodSync(fd, 0o644)
    closeSync(fd)
    fd = undefined

    const leaf = lstatOrNull(fullPath, fullPath)
    if (leaf?.isSymbolicLink()) {
      throw new Error(`Symlinked path rejected inside repository: "${fullPath}"`)
    }
    if (leaf && !leaf.isFile()) {
      throw new Error(`Patch target is not a regular file: "${fullPath}"`)
    }
    renameSync(tmpPath, fullPath)
  } catch (err) {
    if (fd !== undefined) {
      try { closeSync(fd) } catch { /* ignore */ }
    }
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
}

export function applyUnifiedDiffToDirectory(rootDir: string, diffText: string): { filesModified: string[] } {
  const patches = parseUnifiedDiff(diffText)
  if (!patches.length) {
    throw new Error('Unified diff contains no valid file hunks.')
  }

  const backups = new Map<string, string | null>()
  const filesModified: string[] = []

  try {
    for (const patch of patches) {
      const isDelete = patch.newPath === '/dev/null'
      const isCreate = patch.oldPath === '/dev/null'
      const relTarget = isDelete ? patch.oldPath : patch.newPath
      const fullPath = safeResolveUnderRoot(rootDir, relTarget)
      const normalizedRel = relTarget.replace(/^[ab]\//, '')

      const leaf = lstatOrNull(fullPath, relTarget)
      const existed = leaf !== null
      if (existed && !leaf.isFile()) {
        throw new Error(`Patch target is not a regular file: ${normalizedRel}`)
      }
      if (!backups.has(fullPath)) {
        backups.set(fullPath, existed ? readFileNoFollow(fullPath) : null)
      }

      if (!existed && !isCreate) {
        throw new Error(`Target file does not exist for patch: ${normalizedRel}`)
      }
      if (isCreate && existed) {
        throw new Error(`Create-file patch target already exists: ${normalizedRel}`)
      }

      const originalContent = existed ? readFileNoFollow(fullPath) : ''
      const hadTrailingNewline = originalContent.endsWith('\n')
      const lines = originalContent === ''
        ? []
        : (hadTrailingNewline ? originalContent.slice(0, -1).split('\n') : originalContent.split('\n'))

      let lineOffset = 0
      for (const hunk of patch.hunks) {
        const expectedOld = hunk.lines
          .filter(l => l.startsWith(' ') || l.startsWith('-'))
          .map(l => l.slice(1))
        const replacement = hunk.lines
          .filter(l => l.startsWith(' ') || l.startsWith('+'))
          .map(l => l.slice(1))

        const nominalIdx = Math.max(0, hunk.oldStart - 1 + lineOffset)
        const matchesAt = (idx: number) => {
          if (idx < 0 || idx + expectedOld.length > lines.length) return false
          for (let k = 0; k < expectedOld.length; k++) {
            if (lines[idx + k] !== expectedOld[k]) return false
          }
          return true
        }

        let matchIdx = -1
        if (expectedOld.length === 0) {
          matchIdx = Math.min(nominalIdx, lines.length)
        } else if (matchesAt(nominalIdx)) {
          matchIdx = nominalIdx
        } else {
          for (let delta = 1; delta <= 15; delta++) {
            if (matchesAt(nominalIdx + delta)) {
              matchIdx = nominalIdx + delta
              break
            }
            if (matchesAt(nominalIdx - delta)) {
              matchIdx = nominalIdx - delta
              break
            }
          }
        }

        if (matchIdx === -1) {
          throw new Error(`Patch hunk failed to apply cleanly to ${normalizedRel} near line ${hunk.oldStart}.`)
        }

        lines.splice(matchIdx, expectedOld.length, ...replacement)
        lineOffset += replacement.length - expectedOld.length
      }

      if (isDelete) {
        const current = lstatOrNull(fullPath, relTarget)
        if (current) {
          if (current.isSymbolicLink()) {
            throw new Error(`Symlinked path rejected inside repository: "${relTarget}"`)
          }
          unlinkSync(fullPath)
        }
      } else {
        ensureSafeParentChain(rootDir, fullPath, relTarget)
        const latestLeaf = lstatOrNull(fullPath, relTarget)
        if (latestLeaf?.isSymbolicLink()) {
          throw new Error(`Symlinked path rejected inside repository: "${relTarget}"`)
        }
        if (isCreate && latestLeaf) {
          throw new Error(`Create-file patch target already exists: ${normalizedRel}`)
        }
        if (!isCreate && !latestLeaf) {
          throw new Error(`Target file does not exist for patch: ${normalizedRel}`)
        }
        const out = lines.length > 0 ? lines.join('\n') + '\n' : ''
        writeFileNoFollow(fullPath, out, isCreate)
      }
      filesModified.push(normalizedRel)
    }

    return { filesModified }
  } catch (err) {
    for (const [filePath, prev] of backups.entries()) {
      try {
        const relRestore = relative(realpathSync(rootDir), filePath)
        if (prev === null) {
          const current = lstatOrNull(filePath, relRestore)
          if (current && !current.isSymbolicLink()) unlinkSync(filePath)
        } else {
          ensureSafeParentChain(rootDir, filePath, relRestore)
          writeFileNoFollow(filePath, prev, false)
        }
      } catch {
        // Best-effort rollback
      }
    }
    throw err
  }
}

// ===========================================================================
// LabRunner lifecycle orchestrator
// ===========================================================================

export interface LabRunnerOptions {
  /** Where crash-recovery records live. Defaults to KOVO_LAB_STATE_DIR or <tmp>/kovo-lab-state. */
  stateDir?: string
  /** Injectable Docker CLI runner (tests use a deterministic fake). */
  docker?: DockerRunner
  env?: NodeJS.ProcessEnv
  /** Shared ContainerSupervisor instance (defaults to process-wide singleton when no overrides are given). */
  supervisor?: ContainerSupervisor
  /** Owner process PID override for deterministic supervisor tests. */
  ownerPid?: number
}

export class LabRunner {
  readonly supervisor: ContainerSupervisor
  private readonly docker: DockerRunner
  private readonly stateDir: string
  private readonly env: NodeJS.ProcessEnv

  constructor(options: LabRunnerOptions = {}) {
    if (options.supervisor) {
      this.supervisor = options.supervisor
    } else if (options.docker || options.stateDir || options.env || options.ownerPid !== undefined) {
      this.supervisor = new ContainerSupervisor({
        docker: options.docker,
        stateDir: options.stateDir,
        env: options.env,
        ownerPid: options.ownerPid,
      })
    } else {
      this.supervisor = getSharedContainerSupervisor()
    }
    this.docker = options.docker ?? this.supervisor.docker
    this.env = options.env ?? this.supervisor.env
    this.stateDir = options.stateDir ?? this.supervisor.stateDir
  }

  getTarget(runId: string): LabTargetHandle | undefined {
    return this.supervisor.getActiveRun(runId)?.handle as LabTargetHandle | undefined
  }

  listTargets(): LabTargetHandle[] {
    return this.supervisor.listActiveRuns().map(s => s.handle as LabTargetHandle)
  }

  private async launchServiceContainer(params: {
    runId: string
    networkName: string
    sanitizedRepoDir: string
    service: LabServiceSpec
    labConfig: LabConfig
    isPrimary: boolean
    telemetryDir?: string
    storage?: LabContainerStore
    signal?: AbortSignal
  }): Promise<{
    containerName: string
    containerId: string
    containerIp: string
    imageName: string
    builtImage: boolean
    volumes: string[]
  }> {
    const { runId, networkName, sanitizedRepoDir, service, labConfig, isPrimary, telemetryDir, storage, signal } = params
    const containerUser = resolveLabContainerUser(this.env)
    const shortId = createHash('sha256').update(`${runId}:${service.name}:${randomUUID()}`).digest('hex').slice(0, 10)
    const safeSvc = service.name.replace(/[^a-z0-9_-]/g, '').slice(0, 20) || 'svc'
    const containerName = `kovo-lab-${safeSvc}-${shortId}`
    const { memoryLimit, cpus, pidsLimit } = resolveLabServiceResourceLimits(service, labConfig, this.env)

    let imageName: string
    let builtImage = false
    let cmd: string[] = []
    const mountArgs: string[] = []

    const dockerfileRel = service.dockerfile
      ?? (isPrimary
        ? (labConfig.dockerfile
          || (!service.image && !service.command && !service.startCommand && !labConfig.startCommand && !labConfig.image && existsSync(join(sanitizedRepoDir, 'Dockerfile'))
            ? 'Dockerfile'
            : undefined))
        : undefined)

    const rawCommand = service.command ?? service.startCommand ?? (isPrimary ? labConfig.startCommand : undefined)
    const rawEntrypoint = service.entrypoint
    let entrypointArg: string | undefined
    if (Array.isArray(rawEntrypoint) && rawEntrypoint.length > 0) {
      entrypointArg = rawEntrypoint[0]
    } else if (typeof rawEntrypoint === 'string' && rawEntrypoint.trim()) {
      entrypointArg = rawEntrypoint.trim()
    }

    if (dockerfileRel) {
      const dockerfileFull = safeResolveUnderRoot(sanitizedRepoDir, dockerfileRel)
      if (!existsSync(dockerfileFull)) {
        throw new Error(`Lab Dockerfile not found: ${dockerfileRel}`)
      }
      imageName = `kovo-lab-img-${safeSvc}-${shortId}:local`
      const buildSignal = AbortSignal.any([
        AbortSignal.timeout(labConfig.buildTimeoutMs ?? 120_000),
        ...(signal ? [signal] : []),
      ])
      await this.docker(
        ['build', '--pull=false', '--network', 'none', '-f', dockerfileFull, '-t', imageName, sanitizedRepoDir],
        buildSignal,
      )
      builtImage = true
      if (Array.isArray(rawCommand)) {
        cmd = rawCommand
      } else if (typeof rawCommand === 'string' && rawCommand.trim()) {
        cmd = ['sh', '-c', rawCommand.trim()]
      }
    } else if (service.image || service.command || service.startCommand) {
      imageName = service.image || labConfig.image || 'node:24-bookworm-slim'
      if (Array.isArray(rawCommand)) {
        cmd = rawCommand
      } else if (typeof rawCommand === 'string' && rawCommand.trim()) {
        cmd = ['sh', '-c', rawCommand.trim()]
      } else if (isPrimary) {
        const resolved = resolveStartCommand(sanitizedRepoDir, { ...labConfig, image: imageName })
        imageName = resolved.image
        cmd = resolved.cmd
      }
      mountArgs.push('--mount', `type=bind,source=${sanitizedRepoDir},target=/app,readonly`, '--workdir', '/app')
    } else {
      const resolved = resolveStartCommand(sanitizedRepoDir, labConfig)
      imageName = resolved.image
      cmd = resolved.cmd
      mountArgs.push('--mount', `type=bind,source=${sanitizedRepoDir},target=/app,readonly`, '--workdir', '/app')
    }

    if (Array.isArray(rawEntrypoint) && rawEntrypoint.length > 1) {
      cmd = [...rawEntrypoint.slice(1), ...cmd]
    }

    const mergedEnv: Record<string, string> = { ...(isPrimary ? labConfig.env : undefined), ...(service.env ?? {}) }
    const dbKind = detectLabDatabaseKind({ image: imageName, command: cmd, env: mergedEnv })
    if (dbKind === 'sqlite' && mergedEnv.DATABASE_URL) {
      mergedEnv.DATABASE_URL = rewriteSqliteDatabaseUrl(mergedEnv.DATABASE_URL)
    }

    const extraInternalEnv: Record<string, string> = {}
    const volumes: string[] = []
    let overlay: LabWritableOverlay | null = null
    if (dbKind) {
      overlay = buildWritableDataOverlay({
        kind: dbKind,
        serviceName: service.name,
        runId,
        containerUser,
        backing: this.env[LAB_DB_VOLUMES_ENV] === '1' ? 'volume' : 'tmpfs',
      })
      mountArgs.push(...overlay.mountArgs)
      Object.assign(extraInternalEnv, overlay.env)
      if (overlay.volumeName) {
        await this.docker([
          'volume', 'create',
          '--label', `${LAB_LABELS.lab}=1`,
          '--label', `${LAB_LABELS.run}=${runId}`,
          '--label', `${LAB_LABELS.service}=${service.name}`,
          overlay.volumeName,
        ], signal)
        volumes.push(overlay.volumeName)
      }
    }

    if (isPrimary && telemetryDir) {
      const iastWiring = buildIastContainerWiring(telemetryDir, labConfig)
      mountArgs.push(...iastWiring.mountArgs)
      Object.assign(extraInternalEnv, iastWiring.extraEnv)
    }

    const dbDefaultPort = dbKind ? defaultLabDatabasePort(dbKind) : undefined
    const internalPort = service.internalPort
      ?? dbDefaultPort
      ?? (isPrimary ? (labConfig.internalPort ?? 8080) : 8080)

    const runArgs = buildLabContainerRunArgs({
      containerName,
      networkName,
      runId,
      serviceName: service.name,
      imageName,
      cmd,
      internalPort,
      mountArgs,
      env: mergedEnv,
      extraEnv: extraInternalEnv,
      memoryLimit,
      cpus,
      pidsLimit,
      user: containerUser,
      readOnly: overlay ? overlay.readOnlyRootfs : true,
      writableTmpfs: overlay?.tmpfsArgs ?? [],
      networkAliases: service.networkAliases,
      extraLabels: this.supervisor.ownerExtraLabels(),
      ...(entrypointArg ? { entrypoint: entrypointArg } : {}),
    })

    try {
      await this.docker(runArgs, signal)
      this.supervisor.recordContainerRow(storage, runId, containerName, imageName, 'running')
      const containerId = (await this.docker(['inspect', '-f', '{{.Id}}', containerName], signal)).trim()
      const rawIp = (await this.docker(
        ['inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', containerName],
        signal,
      )).trim()
      if (!rawIp || !/^\d+\.\d+\.\d+\.\d+$/.test(rawIp)) {
        throw new Error(`Failed to resolve internal bridge IP for lab container ${containerName}.`)
      }
      if (!/^[a-f0-9]{12,64}$/.test(containerId)) {
        throw new Error(`Failed to resolve container id for lab container ${containerName}.`)
      }
      return { containerName, containerId, containerIp: rawIp, imageName, builtImage, volumes }
    } catch (err) {
      this.supervisor.markContainerOrphaned(storage, runId, containerName)
      await this.supervisor.removeContainerAndRow(storage, runId, containerName)
      await this.supervisor.cleanupDockerArtifacts({ volumes, images: builtImage ? [imageName] : [] })
      throw err
    }
  }

  async startLabTarget(params: StartLabTargetParams): Promise<LabTargetHandle> {
    assertLocalLabAllowed(params.environment)
    validateLabRunId(params.runId)
    params.signal?.throwIfAborted()

    if (!existsSync(params.repoDir) || !statSync(params.repoDir).isDirectory()) {
      throw new Error(`Lab repository directory does not exist: ${params.repoDir}`)
    }

    const labConfig: LabConfig = params.labConfig ?? {}
    const containerUser = resolveLabContainerUser(this.env)

    // Strict pre-launch validation BEFORE touching Docker or creating any networks/containers!
    let composeYaml: string | undefined
    if (labConfig.dockerComposeFile?.trim()) {
      const composePath = safeResolveUnderRoot(params.repoDir, labConfig.dockerComposeFile.trim())
      if (!existsSync(composePath)) {
        throw new Error(`Docker Compose file not found: ${labConfig.dockerComposeFile}`)
      }
      composeYaml = readFileSync(composePath, 'utf8')
      // Isolate untrusted compose YAML parsing inside bounded worker_threads pool (H-38).
      await parseComposeInWorker(composeYaml, { env: this.env, signal: params.signal })
    }
    const { primaryService, sidecarServices } = resolveLabStackServices({
      labConfig,
      composeYaml,
      env: this.env,
    })

    if (this.supervisor.hasActiveRun(params.runId)) {
      await this.stopLabTarget(params.runId)
    }

    const internalPort = primaryService.internalPort ?? labConfig.internalPort ?? 8080
    const healthPath = primaryService.healthPath
      ?? deriveHealthPathFromHealthcheck(primaryService.healthcheck)
      ?? labConfig.healthPath
      ?? '/health'
    const runSlug = params.runId.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase() || 'run'
    const shortRand = createHash('sha256').update(`${params.runId}:${randomUUID()}`).digest('hex').slice(0, 8)
    const networkName = `kovo-lab-${runSlug}-${shortRand}`

    const sanitizedRepoDir = mkdtempSync(join(tmpdir(), LAB_PATHS.repoPrefix))
    const repoReal = realpathSync(params.repoDir)
    copySanitizedRepo(repoReal, sanitizedRepoDir, repoReal)

    const { telemetryDir, ownsTelemetryDir, ephemeralTelemetryDir } = provisionRunTelemetryDir({
      iastEnabled: labConfig.iastEnabled,
      baseTelemetryDir: params.telemetryDir,
      runId: params.runId,
      containerUser,
    })

    const proxyDir = createLabProxyDir(params.runId, containerUser)
    const proxyContainerName = `kovo-lab-proxy-${shortRand}`
    const socketMode = labProxySocketMode(containerUser)

    let networkCreated = false
    let proxyStarted = false
    const containerNames: string[] = []
    const containerIds: string[] = []
    const builtImages: string[] = []
    const volumes: string[] = []
    let forwarder: TcpServer | undefined

    try {
      await this.docker(buildLabNetworkCreateArgs(params.runId, networkName), params.signal)
      networkCreated = true

      const baseUrls: Record<string, string> = {}

      for (const sidecar of sidecarServices) {
        const launched = await this.launchServiceContainer({
          runId: params.runId,
          networkName,
          sanitizedRepoDir,
          service: sidecar,
          labConfig,
          isPrimary: false,
          storage: params.storage,
          signal: params.signal,
        })
        containerNames.push(launched.containerName)
        containerIds.push(launched.containerId)
        volumes.push(...launched.volumes)
        if (launched.builtImage) builtImages.push(launched.imageName)
        const sidecarKind = detectLabDatabaseKind({ image: sidecar.image, command: sidecar.command, env: sidecar.env })
        const sidecarPort = sidecar.internalPort ?? defaultLabDatabasePort(sidecarKind ?? 'sqlite')
        if (sidecarPort) {
          if (!sidecarKind) baseUrls[sidecar.name] = `http://${sidecar.name}:${sidecarPort}`
          await waitForContainerPort(this.docker, launched.containerName, sidecarPort, {
            kind: sidecarKind,
            timeoutMs: 8_000,
            signal: params.signal,
          })
        }
      }

      const primaryLaunched = await this.launchServiceContainer({
        runId: params.runId,
        networkName,
        sanitizedRepoDir,
        service: primaryService,
        labConfig,
        isPrimary: true,
        telemetryDir,
        storage: params.storage,
        signal: params.signal,
      })
      containerNames.push(primaryLaunched.containerName)
      containerIds.push(primaryLaunched.containerId)
      volumes.push(...primaryLaunched.volumes)
      if (primaryLaunched.builtImage) builtImages.push(primaryLaunched.imageName)

      writeLabProxyTarget(proxyDir, primaryLaunched.containerName, internalPort)
      const proxyImage = this.env[LAB_PROXY_IMAGE_ENV]?.trim() || LAB_PROXY_IMAGE_DEFAULT
      await this.docker(buildLabProxyRunArgs({
        containerName: proxyContainerName,
        networkName,
        runId: params.runId,
        proxyDir,
        image: proxyImage,
        user: containerUser,
        targetHost: primaryLaunched.containerName,
        targetPort: internalPort,
        socketMode,
      }), params.signal)
      proxyStarted = true
      this.supervisor.recordContainerRow(params.storage, params.runId, proxyContainerName, proxyImage, 'running')
      let socketPath: string
      try {
        socketPath = await waitForLabProxySocket(proxyDir, 15_000, params.signal)
      } catch (err) {
        const status = await this.docker(
          ['inspect', '-f', '{{.State.Status}} exit={{.State.ExitCode}}', proxyContainerName],
          AbortSignal.timeout(5_000),
        ).catch(() => 'unavailable')
        throw new Error(`${err instanceof Error ? err.message : String(err)} (proxy container: ${status.trim()}).`)
      }
      const proxy = await createLoopbackSocketForwarder(socketPath)
      forwarder = proxy.server

      const origin = `http://127.0.0.1:${proxy.port}`
      baseUrls[primaryService.name] = origin
      baseUrls.primary = origin

      await waitForHealthCheck(origin, healthPath, labConfig.healthTimeoutMs ?? 30_000, params.signal)

      const seededPersonas = await this.runSeedCommand({
        seedCommand: labConfig.seedCommand,
        containerName: primaryLaunched.containerName,
        origin,
        storage: params.storage,
        projectId: params.projectId,
        signal: params.signal,
      })

      const handle: LabTargetHandle = {
        targetId: `${params.runId}:${primaryLaunched.containerName}`,
        runId: params.runId,
        networkName,
        containerName: primaryLaunched.containerName,
        containerNames: [...containerNames],
        containerIp: primaryLaunched.containerIp,
        imageName: primaryLaunched.imageName,
        origin,
        baseUrls,
        hostPort: proxy.port,
        internalPort,
        healthPath,
        sanitizedRepoDir,
        seededPersonas,
        ...(telemetryDir ? { telemetryDir } : {}),
        startedAt: Date.now(),
        stop: () => this.stopLabTarget(params.runId),
      }

      this.supervisor.registerActiveRun(params.runId, {
        handle,
        labConfig,
        primaryService,
        builtImages,
        containerNames,
        containerIds,
        volumes,
        forwarder: proxy.server,
        proxyContainerName,
        proxyDir,
        ownsTelemetryDir,
        ...(params.storage ? { storage: params.storage } : {}),
      })

      return handle
    } catch (err) {
      if (forwarder) {
        await new Promise<void>(res => forwarder!.close(() => res())).catch(() => undefined)
      }
      if (proxyStarted) {
        this.supervisor.markContainerOrphaned(params.storage, params.runId, proxyContainerName)
        await this.supervisor.removeContainerAndRow(params.storage, params.runId, proxyContainerName)
      }
      await Promise.all(containerNames.map(async cname => {
        this.supervisor.markContainerOrphaned(params.storage, params.runId, cname)
        await this.supervisor.removeContainerAndRow(params.storage, params.runId, cname)
      }))
      await this.supervisor.sweepOrphanContainersForRun(params.runId)
      await this.supervisor.cleanupDockerArtifacts({
        volumes,
        images: builtImages,
        networkName: networkCreated ? networkName : undefined,
      })
      safeRemoveLabTempDir(sanitizedRepoDir, [LAB_PATHS.repoPrefix])
      safeRemoveLabTempDir(proxyDir, [LAB_PATHS.proxyPrefix])
      if (ephemeralTelemetryDir && telemetryDir) safeRemoveLabTempDir(telemetryDir)
      removeLabRunRecord(this.stateDir, params.runId)
      throw err
    }
  }

  private async runSeedCommand(params: {
    seedCommand?: string
    containerName: string
    origin: string
    storage?: Store
    projectId?: string
    signal?: AbortSignal
  }): Promise<SeededPersonaSummary[]> {
    const seededPersonas: SeededPersonaSummary[] = []
    if (!params.seedCommand?.trim()) return seededPersonas
    const seedSignal = AbortSignal.any([
      AbortSignal.timeout(30_000),
      ...(params.signal ? [params.signal] : []),
    ])
    const seedStdout = await this.docker(
      ['exec', params.containerName, 'sh', '-c', params.seedCommand.trim()],
      seedSignal,
    )
    const parsedPersonas = parseSeededPersonasFromStdout(seedStdout)
    const existingHandles = params.storage && params.projectId
      ? new Set(listProjectPersonas(params.storage, params.projectId).map(p => p.handle))
      : new Set<string>()

    for (const p of parsedPersonas) {
      let personaId: string | undefined
      if (params.storage && params.projectId && !existingHandles.has(p.handle)) {
        const created = createProjectPersona(params.storage, {
          requestId: randomUUID(),
          projectId: params.projectId,
          handle: p.handle,
          roleLabel: p.roleLabel,
          originAllowlist: [params.origin],
          authKind: p.authKind,
          headerName: p.headerName,
          secret: p.secret,
          canaryMarkers: p.canaryMarkers,
        })
        personaId = created.id
        existingHandles.add(p.handle)
      }
      seededPersonas.push({
        handle: p.handle,
        roleLabel: p.roleLabel,
        authKind: p.authKind,
        ...(p.headerName ? { headerName: p.headerName } : {}),
        ...(personaId ? { personaId } : {}),
      })
    }
    return seededPersonas
  }

  async rebuildWithPatch(runId: string, patchDiff: string, signal?: AbortSignal): Promise<LabTargetHandle> {
    assertLocalLabAllowed('local-lab')
    validateLabRunId(runId)
    const state = this.supervisor.getActiveRun(runId)
    if (!state) {
      throw new Error(`No active local-lab target found for run ${runId}.`)
    }

    applyUnifiedDiffToDirectory(state.handle.sanitizedRepoDir, patchDiff)

    const prevContainer = state.handle.containerName
    const prevContainerId = state.containerIds[state.containerNames.indexOf(prevContainer)]
    const prevBuiltImage = state.builtImages.includes(state.handle.imageName) ? state.handle.imageName : undefined

    const launched = await this.launchServiceContainer({
      runId,
      networkName: state.handle.networkName,
      sanitizedRepoDir: state.handle.sanitizedRepoDir,
      service: state.primaryService,
      labConfig: state.labConfig,
      isPrimary: true,
      telemetryDir: state.handle.telemetryDir,
      storage: state.storage,
      signal,
    })

    writeLabProxyTarget(state.proxyDir, launched.containerName, state.handle.internalPort)

    try {
      await waitForHealthCheck(
        state.handle.origin,
        state.handle.healthPath,
        state.labConfig.healthTimeoutMs ?? 30_000,
        signal,
      )
    } catch (err) {
      writeLabProxyTarget(state.proxyDir, prevContainer, state.handle.internalPort)
      this.supervisor.markContainerOrphaned(state.storage, runId, launched.containerName)
      await this.supervisor.removeContainerAndRow(state.storage, runId, launched.containerName)
      await this.supervisor.cleanupDockerArtifacts({
        volumes: launched.volumes,
        images: launched.builtImage ? [launched.imageName] : [],
      })
      throw err
    }

    const prevIndex = state.containerNames.indexOf(prevContainer)
    state.containerNames = state.containerNames.filter(c => c !== prevContainer)
    state.containerNames.push(launched.containerName)
    if (prevIndex >= 0) state.containerIds.splice(prevIndex, 1)
    state.containerIds.push(launched.containerId)
    state.volumes.push(...launched.volumes)
    if (launched.builtImage) state.builtImages.push(launched.imageName)

    state.handle = {
      ...state.handle,
      targetId: `${runId}:${launched.containerName}`,
      containerName: launched.containerName,
      containerNames: [...state.containerNames],
      containerIp: launched.containerIp,
      imageName: launched.imageName,
      startedAt: Date.now(),
    }

    await this.supervisor.removeContainerAndRow(state.storage, runId, prevContainer)
    if (prevBuiltImage && prevBuiltImage !== launched.imageName) {
      state.builtImages = state.builtImages.filter(i => i !== prevBuiltImage)
      await this.docker(['image', 'rm', '--force', prevBuiltImage], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    state.containerIds = state.containerIds.filter(id => id !== prevContainerId)
    this.supervisor.persistState(runId)

    return state.handle as LabTargetHandle
  }

  reclaimPersisted(
    containers: ReadonlyArray<PersistedLabContainerRef>,
    storage?: LabContainerStore,
  ): Promise<LabReclaimResult> {
    return this.supervisor.reclaimPersisted(containers, storage)
  }

  recover(runId: string, storage?: LabContainerStore): Promise<LabRecoveryResult> {
    return this.supervisor.recover(runId, storage)
  }

  recoverAll(storage?: LabContainerStore): Promise<LabRecoveryResult[]> {
    return this.supervisor.recoverAll(storage)
  }

  reapSyncAll(): void {
    this.supervisor.reapSyncAll()
  }

  stopLabTarget(runId: string): Promise<void> {
    return this.supervisor.stopRun(runId)
  }

  stopAll(): Promise<void> {
    return this.supervisor.stopAll()
  }
}

let sharedLabRunner: LabRunner | undefined

/** Process-wide shared LabRunner backed by `getSharedContainerSupervisor()` (M-20). */
export function getSharedLabRunner(): LabRunner {
  if (!sharedLabRunner) {
    sharedLabRunner = new LabRunner({ supervisor: getSharedContainerSupervisor() })
  }
  return sharedLabRunner
}
