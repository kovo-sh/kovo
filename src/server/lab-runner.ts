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
  writeFileSync,
  writeSync,
} from 'node:fs'
import type { Stats } from 'node:fs'
import type { Server as TcpServer } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import {
  LAB_DB_VOLUMES_ENV,
  LAB_LABELS,
  LAB_PATHS,
  LAB_PROXY_IMAGE_DEFAULT,
  LAB_PROXY_IMAGE_ENV,
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
  labProxySocketMode,
  parseSeededPersonasFromStdout,
  resolveLabContainerUser,
  resolveLabStackServices,
  resolveStartCommand,
  rewriteSqliteDatabaseUrl,
  runDocker,
  safeRemoveLabTempDir,
  spawnDockerSync,
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

// Re-export extracted proxy, network, compose, overlay, and IAST telemetry modules for 100% facade compatibility.
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

export type LabContainerStatus = 'running' | 'orphaned' | 'reclaimed'

/**
 * Narrow structural view of the merged v6 Store lab-container registry. LabRunner accepts the full
 * `Store` (StartLabTargetParams.storage); this interface keeps lifecycle wiring testable with a
 * fake and decouples the runner from Store internals.
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

interface InternalTargetState {
  handle: LabTargetHandle
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

const EXCLUDED_DIR_NAMES = new Set(['.git', '.aws', '.ssh', '.gnupg', '.kube'])

const EXCLUDED_FILE_PATTERNS = [
  /^\.env(?:\..+)?$/i,
  /\.(?:pem|key|p12|pfx|jks|keystore)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
  /^\.(?:npmrc|netrc|pypirc|dockercfg)$/i,
  /^(?:secrets|credentials)\.(?:json|ya?ml|toml|env|txt)$/i,
]

const MAX_RECOVERED_RUNS = 32

export function assertLocalLabAllowed(environment: string): void {
  if (environment !== 'local-lab') {
    throw new Error(
      `Local-lab app runner is forbidden on "${environment}" projects. Requires project.environment === 'local-lab'.`,
    )
  }
  if (process.env.GUARDIAN_ALLOW_LOCAL_LAB !== '1') {
    throw new Error('Local-lab app runner requires GUARDIAN_ALLOW_LOCAL_LAB=1.')
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
  const tmpPath = join(parent, `.guardian-patch-${randomUUID()}.tmp`)
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

interface ParsedHunk {
  oldStart: number
  oldCount: number
  newStart: number
  newCount: number
  lines: string[]
}

interface ParsedFilePatch {
  oldPath: string
  newPath: string
  hunks: ParsedHunk[]
}

function parseUnifiedDiff(diffText: string): ParsedFilePatch[] {
  const rawLines = diffText.replace(/\r\n/g, '\n').split('\n')
  const patches: ParsedFilePatch[] = []
  let i = 0

  while (i < rawLines.length) {
    const line = rawLines[i]
    if (line.startsWith('--- ')) {
      const oldPath = line.slice(4).split('\t')[0].trim()
      const nextLine = rawLines[i + 1] ?? ''
      if (!nextLine.startsWith('+++ ')) {
        i++
        continue
      }
      const newPath = nextLine.slice(4).split('\t')[0].trim()
      i += 2
      const hunks: ParsedHunk[] = []

      while (i < rawLines.length) {
        const hLine = rawLines[i]
        if (hLine.startsWith('--- ') || hLine.startsWith('diff --git ')) break
        const match = hLine.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/)
        if (!match) {
          i++
          continue
        }
        const oldStart = Number(match[1])
        const oldCount = match[2] !== undefined ? Number(match[2]) : 1
        const newStart = Number(match[3])
        const newCount = match[4] !== undefined ? Number(match[4]) : 1
        i++
        const hunkLines: string[] = []
        let seenOld = 0
        let seenNew = 0
        while (i < rawLines.length) {
          const contentLine = rawLines[i]
          if (contentLine.startsWith('@@ ') || contentLine.startsWith('diff --git ') || contentLine.startsWith('--- ')) {
            break
          }
          if (contentLine.startsWith('\\ No newline at end of file')) {
            i++
            continue
          }
          if (seenOld >= oldCount && seenNew >= newCount && contentLine === '') {
            i++
            break
          }
          if (contentLine.startsWith(' ')) {
            hunkLines.push(contentLine)
            seenOld++
            seenNew++
            i++
          } else if (contentLine.startsWith('-')) {
            hunkLines.push(contentLine)
            seenOld++
            i++
          } else if (contentLine.startsWith('+')) {
            hunkLines.push(contentLine)
            seenNew++
            i++
          } else if (contentLine === '' && (seenOld < oldCount || seenNew < newCount)) {
            hunkLines.push(' ')
            seenOld++
            seenNew++
            i++
          } else {
            break
          }
        }
        hunks.push({ oldStart, oldCount, newStart, newCount, lines: hunkLines })
      }

      if (hunks.length > 0) {
        patches.push({ oldPath, newPath, hunks })
      }
      continue
    }
    i++
  }

  return patches
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
// Durable run state (crash recovery / orphan reaping)
// ===========================================================================

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

function labRunRecordFileName(runId: string): string {
  const slug = runId.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 96)
  const digest = createHash('sha256').update(runId).digest('hex').slice(0, 8)
  return `${slug}-${digest}.json`
}

/** Directory holding crash-recovery records; owner-only, never inside the repo. */
export function labStateDir(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env[LAB_STATE_DIR_ENV]?.trim()
  return configured && isAbsolute(configured) ? configured : join(tmpdir(), 'guardian-lab-state')
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

const ACTIVE_LAB_RUNNERS = new Set<LabRunner>()
let labSignalHooksInstalled = false

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
    for (const runner of ACTIVE_LAB_RUNNERS) runner.reapSyncAll()
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

function installLabSignalHooks(): void {
  if (labSignalHooksInstalled) return
  labSignalHooksInstalled = true
  bindLabSignalHooks()
}

// ===========================================================================
// LabRunner lifecycle orchestrator
// ===========================================================================

export interface LabRunnerOptions {
  /** Where crash-recovery records live. Defaults to GUARDIAN_LAB_STATE_DIR or <tmp>/guardian-lab-state. */
  stateDir?: string
  /** Injectable Docker CLI runner (tests use a deterministic fake). */
  docker?: DockerRunner
  env?: NodeJS.ProcessEnv
}

export class LabRunner {
  private readonly active = new Map<string, InternalTargetState>()
  private readonly docker: DockerRunner
  private readonly stateDir: string
  private readonly env: NodeJS.ProcessEnv

  constructor(options: LabRunnerOptions = {}) {
    this.docker = options.docker ?? runDocker
    this.env = options.env ?? process.env
    this.stateDir = options.stateDir ?? labStateDir(this.env)
  }

  getTarget(runId: string): LabTargetHandle | undefined {
    return this.active.get(runId)?.handle
  }

  listTargets(): LabTargetHandle[] {
    return [...this.active.values()].map(s => s.handle)
  }

  private async tryDocker(args: string[], signal?: AbortSignal): Promise<boolean> {
    try {
      await this.docker(args, signal ?? AbortSignal.timeout(10_000))
      return true
    } catch {
      return false
    }
  }

  private async listByLabel(kind: 'container' | 'network' | 'volume', runId: string): Promise<string[]> {
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

  private recordFor(runId: string, state: InternalTargetState): LabRunRecord {
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
      pid: process.pid,
    }
  }

  /**
   * Persist crash-recovery state. When a SQLite `LabContainerStore` is attached, `lab_containers`
   * rows plus Docker `dev.guardian.run` labels are the durable authority, so we avoid duplicating
   * JSON crash-recovery files in `stateDir`. Standalone callers without a Store fall back to the
   * JSON file record.
   */
  private persistState(runId: string): void {
    const state = this.active.get(runId)
    if (!state || state.storage) return
    try {
      writeLabRunRecord(this.stateDir, this.recordFor(runId, state))
    } catch {
      // Persistence is best-effort: label-based reaping still covers a crash.
    }
  }

  // --- Store lab-container registry -------------------------------------------------

  private recordContainerRow(
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

  private markContainerOrphaned(
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

  private deleteContainerRow(
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
      // Best-effort: a stale row is reclaimed by Store.recover() on the next restart.
    }
  }

  private async removeContainerAndRow(
    storage: LabContainerStore | undefined,
    runId: string,
    containerName: string,
  ): Promise<boolean> {
    const removed = await this.tryDocker(['container', 'rm', '--force', containerName], AbortSignal.timeout(10_000))
    if (removed) {
      this.deleteContainerRow(storage, runId, containerName)
      return true
    }
    const stillExists = await this.tryDocker(
      ['inspect', '-f', '{{.Id}}', containerName],
      AbortSignal.timeout(5_000),
    )
    if (!stillExists) this.deleteContainerRow(storage, runId, containerName)
    return false
  }

  private async cleanupDockerArtifacts(params: {
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

  /**
   * Reclaim containers returned by `Store.recover()`. Each candidate is removed only when its
   * `dev.guardian.run` label matches the requested run, so a stale/corrupt row can never delete a
   * container belonging to another run. Missing containers are treated as already reclaimed.
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
      } catch {
        this.deleteContainerRow(storage, ref.runId, ref.containerName)
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
    const containerName = `guardian-lab-${safeSvc}-${shortId}`
    const memoryLimit = service.memoryLimit ?? labConfig.memoryLimit ?? '512m'
    const cpus = service.cpus ?? labConfig.cpus ?? '1.0'
    const pidsLimit = service.pidsLimit ?? labConfig.pidsLimit ?? 128

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
      imageName = `guardian-lab-img-${safeSvc}-${shortId}:local`
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
      ...(entrypointArg ? { entrypoint: entrypointArg } : {}),
    })

    try {
      await this.docker(runArgs, signal)
      this.recordContainerRow(storage, runId, containerName, imageName, 'running')
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
      this.markContainerOrphaned(storage, runId, containerName)
      await this.docker(['container', 'rm', '--force', containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      await this.cleanupDockerArtifacts({ volumes, images: builtImage ? [imageName] : [] })
      throw err
    }
  }

  async startLabTarget(params: StartLabTargetParams): Promise<LabTargetHandle> {
    assertLocalLabAllowed(params.environment)
    validateLabRunId(params.runId)
    params.signal?.throwIfAborted()
    installLabSignalHooks()
    ACTIVE_LAB_RUNNERS.add(this)

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
    }
    const { primaryService, sidecarServices } = resolveLabStackServices({
      labConfig,
      composeYaml,
      env: this.env,
    })

    if (this.active.has(params.runId)) {
      await this.stopLabTarget(params.runId)
    }

    const internalPort = primaryService.internalPort ?? labConfig.internalPort ?? 8080
    const healthPath = primaryService.healthPath
      ?? deriveHealthPathFromHealthcheck(primaryService.healthcheck)
      ?? labConfig.healthPath
      ?? '/health'
    const runSlug = params.runId.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase() || 'run'
    const shortRand = createHash('sha256').update(`${params.runId}:${randomUUID()}`).digest('hex').slice(0, 8)
    const networkName = `guardian-lab-${runSlug}-${shortRand}`

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
    const proxyContainerName = `guardian-lab-proxy-${shortRand}`
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
      this.recordContainerRow(params.storage, params.runId, proxyContainerName, proxyImage, 'running')
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

      this.active.set(params.runId, {
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
      this.persistState(params.runId)

      return handle
    } catch (err) {
      if (forwarder) {
        await new Promise<void>(res => forwarder!.close(() => res())).catch(() => undefined)
      }
      if (proxyStarted) {
        this.markContainerOrphaned(params.storage, params.runId, proxyContainerName)
        await this.docker(['container', 'rm', '--force', proxyContainerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      for (const cname of containerNames) {
        this.markContainerOrphaned(params.storage, params.runId, cname)
        await this.docker(['container', 'rm', '--force', cname], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      await this.sweepOrphanContainersForRun(params.runId)
      await this.cleanupDockerArtifacts({
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
    const state = this.active.get(runId)
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
      this.markContainerOrphaned(state.storage, runId, launched.containerName)
      await this.docker(['container', 'rm', '--force', launched.containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      await this.cleanupDockerArtifacts({
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

    await this.removeContainerAndRow(state.storage, runId, prevContainer)
    if (prevBuiltImage && prevBuiltImage !== launched.imageName) {
      state.builtImages = state.builtImages.filter(i => i !== prevBuiltImage)
      await this.docker(['image', 'rm', '--force', prevBuiltImage], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    state.containerIds = state.containerIds.filter(id => id !== prevContainerId)
    this.persistState(runId)

    return state.handle
  }

  private async sweepOrphanContainersForRun(runId: string): Promise<void> {
    const ids = await this.listByLabel('container', runId)
    if (ids.length > 0) {
      await this.docker(['container', 'rm', '--force', ...ids], AbortSignal.timeout(10_000)).catch(() => undefined)
    }
  }

  /**
   * Reap every resource for a run: containers/networks/volumes by label, plus every path in the
   * persisted crash record. Idempotent — calling it twice is safe and returns zero removals.
   */
  async recover(runId: string, storage?: LabContainerStore): Promise<LabRecoveryResult> {
    validateLabRunId(runId)
    if (this.active.has(runId)) {
      await this.stopLabTarget(runId)
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
        // Registry cleanup is best-effort; the next Store.recover() retries.
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

  /**
   * Recover every run found in persisted records, the lab label scan and (optionally) the Store
   * registry rows.
   */
  async recoverAll(storage?: LabContainerStore): Promise<LabRecoveryResult[]> {
    const runIds = new Set<string>()
    try {
      for (const entry of readdirSync(this.stateDir)) {
        if (!entry.endsWith('.json')) continue
        try {
          const parsed = JSON.parse(readFileSync(join(this.stateDir, entry), 'utf8')) as { runId?: unknown }
          if (typeof parsed.runId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(parsed.runId)) {
            runIds.add(parsed.runId)
          }
        } catch {
          // Ignore unreadable/corrupt records; the label scan below still finds live orphans.
        }
      }
    } catch {
      // No state dir yet.
    }

    try {
      const ids = (await this.docker(['ps', '-aq', '--filter', `label=${LAB_LABELS.lab}=1`], AbortSignal.timeout(10_000)))
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 64)
      if (ids.length > 0) {
        const labels = await this.docker(
          ['inspect', '-f', `{{index .Config.Labels "${LAB_LABELS.run}"}}`, ...ids],
          AbortSignal.timeout(10_000),
        )
        for (const line of labels.split('\n')) {
          const runId = line.trim()
          if (/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(runId)) runIds.add(runId)
        }
      }
    } catch {
      // Docker unavailable: records still get cleaned up.
    }

    const results: LabRecoveryResult[] = []
    for (const runId of [...runIds].slice(0, MAX_RECOVERED_RUNS)) {
      if (runId === '<no value>') continue
      results.push(await this.recover(runId, storage))
    }
    return results
  }

  /**
   * Synchronous best-effort reaping used from SIGINT/SIGTERM/exit handlers where async cleanup
   * cannot run. Removes persisted ids/names, sweeps by label, then removes scratch dirs.
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

  async stopLabTarget(runId: string): Promise<void> {
    const state = this.active.get(runId)
    if (!state) {
      removeLabRunRecord(this.stateDir, runId)
      return
    }
    this.active.delete(runId)

    await new Promise<void>(res => state.forwarder.close(() => res())).catch(() => undefined)
    await this.removeContainerAndRow(state.storage, runId, state.proxyContainerName)
    for (const cname of state.containerNames) {
      await this.removeContainerAndRow(state.storage, runId, cname)
    }
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
    await Promise.all(ids.map(id => this.stopLabTarget(id)))
  }
}
