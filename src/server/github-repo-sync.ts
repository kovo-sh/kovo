import { execFileSync, spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  promises as fsp,
  readdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { DEFAULT_GITHUB_API_BASE_URL, resolveFreshGithubCredential } from './github-auth.ts'
import { mineSecurityRelevantCommitDiffs, type CommitDiffSignal } from './program-graph.ts'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

export interface RepoDependency {
  ecosystem: string
  package: string
  version: string
  sourceFile: string
}

export interface SyncedRepoFile {
  path: string
  category: 'manifest' | 'lockfile' | 'openapi' | 'graphql' | 'route' | 'config'
  size: number
  truncated: boolean
  content: string
}

export interface SyncedRepoSpec {
  name: string
  kind: 'openapi' | 'graphql' | 'routes' | 'notes'
  content: string
}

export interface SyncedGithubRepo {
  fullName: string
  defaultBranch: string
  private: boolean
  description: string | null
  language: string | null
  treeCount: number
  files: SyncedRepoFile[]
  dependencies: RepoDependency[]
  specs: SyncedRepoSpec[]
  warnings: string[]
  mountPath?: string
  localPath?: string
  commitSha?: string
  topLevelDirs?: string[]
  /** Bounded git history retained for code-first regression mining. */
  gitHistory?: {
    depth: number
    commitsScanned: number
    commitDiffs: CommitDiffSignal[]
    metadataPreserved: boolean
  }
}

export interface GithubSyncOptions {
  dataDir?: string
  patPath?: string
  apiBaseUrl?: string
  githubBaseUrl?: string
  gitBaseUrl?: string
  cloneDir?: string
  fetchImpl?: typeof fetch
  maxFilesPerRepo?: number
  maxFileBytes?: number
  maxRepoBytes?: number
  cloneTimeoutMs?: number
  /** Bounded clone history depth (default 1 for shallow clone). `.git` is preserved unless explicitly stripped. */
  historyDepth?: number
  /** Mine security-relevant diffs, then remove `.git` from the mounted checkout. */
  stripGitMetadata?: boolean
  /** Maximum commits inspected for diffs during sync (default 20). */
  maxCommitDiffs?: number
  /** Maximum on-disk size in bytes allowed for a single cloned repository (default 256 MiB). */
  maxRepoDiskBytes?: number
  /** Maximum combined on-disk size in bytes allowed across all mounted repos for one project (default 1 GiB). */
  maxProjectDiskBytes?: number
  /** Maximum file count (inode cap) allowed for a single cloned repository (default 50,000). */
  maxRepoFiles?: number
  /** Maximum directory nesting depth allowed inside a repository tree (default 32). */
  maxRepoDepth?: number
  /** Optional observability hook invoked after pre-checkout tree quota checks pass and immediately before `git checkout`. */
  onBeforeCheckout?: (info: {
    stagingDir: string
    blobBytes: number
    fileCount: number
    inodeCount: number
    maxDepth: number
  }) => void
  /** Explicitly allow or disallow `file://` git origins (disabled in production; allowed in test runtime unless false). */
  allowLocalFileProtocol?: boolean
  /** Whether to query GitHub `/repos/<owner>/<repo>` size metadata prior to cloning when using HTTP(S) origins. */
  preflightSizeCheck?: boolean
  /** Active-run guard invoked inside the per-repo lock before mutating or swapping checkouts. */
  assertNoActiveRuns?: (repoFullName: string) => void | Promise<void>
  /** When true on multi-repo batches, isolate individual repo failures instead of aborting remaining repos. */
  continueOnError?: boolean
  /** Optional callback invoked for each per-repo error when `continueOnError` is true. */
  onRepoError?: (repoFullName: string, error: Error) => void
}

export interface RepoCommitDiffMining {
  available: boolean
  reason?: string
  commitsScanned: number
  commitDiffs: CommitDiffSignal[]
}

export const DEFAULT_CLONE_DEPTH = 1
export const DEFAULT_MAX_REPO_DISK_BYTES = 256 * 1024 * 1024
export const DEFAULT_MAX_PROJECT_DISK_BYTES = 1024 * 1024 * 1024
export const DEFAULT_MAX_REPO_FILES = 50_000
export const DEFAULT_MAX_PROJECT_FILES = 200_000
export const DEFAULT_MAX_REPO_DEPTH = 32

export class RepoWorkspaceBusyError extends Error {
  readonly code: 'REPO_ACTIVE_RUN_LOCKED' | 'REPO_SYNC_IN_PROGRESS'
  readonly status = 409
  readonly activeRunIds: string[]

  constructor(
    code: 'REPO_ACTIVE_RUN_LOCKED' | 'REPO_SYNC_IN_PROGRESS',
    message: string,
    activeRunIds: readonly string[] = [],
  ) {
    super(message)
    this.name = 'RepoWorkspaceBusyError'
    this.code = code
    this.activeRunIds = [...activeRunIds]
  }
}

export class RepoDiskQuotaExceededError extends Error {
  readonly code = 'REPO_DISK_QUOTA_EXCEEDED'
  readonly status = 413
  readonly scope: 'repo' | 'project'
  readonly repoFullName: string
  readonly actualBytes: number
  readonly quotaBytes: number

  constructor(scope: 'repo' | 'project', repoFullName: string, actualBytes: number, quotaBytes: number) {
    const scopeLabel = scope === 'repo' ? `Repository "${repoFullName}"` : `Project repositories including "${repoFullName}"`
    super(
      `${scopeLabel} exceeded the ${scope} disk quota (${actualBytes} bytes > ${quotaBytes} bytes limit).`,
    )
    this.name = 'RepoDiskQuotaExceededError'
    this.scope = scope
    this.repoFullName = repoFullName
    this.actualBytes = actualBytes
    this.quotaBytes = quotaBytes
  }
}

export class RepoDepthLimitExceededError extends Error {
  readonly code = 'REPO_DEPTH_LIMIT_EXCEEDED'
  readonly status = 413
  readonly target: string
  readonly depth: number
  readonly maxDepth: number
  readonly offendingPath?: string

  constructor(target: string, depth: number, maxDepth: number, offendingPath?: string) {
    super(
      `Repository "${target}" exceeded the maximum directory depth (${depth} > ${maxDepth} limit${offendingPath ? ` at "${offendingPath}"` : ''}).`,
    )
    this.name = 'RepoDepthLimitExceededError'
    this.target = target
    this.depth = depth
    this.maxDepth = maxDepth
    this.offendingPath = offendingPath
  }
}

export class RepoFileLimitExceededError extends Error {
  readonly code = 'REPO_FILE_LIMIT_EXCEEDED'
  readonly status = 413
  readonly scope: 'repo' | 'project' | 'directory'
  readonly target: string
  readonly actualFiles: number
  readonly maxFiles: number

  constructor(
    scope: 'repo' | 'project' | 'directory',
    target: string,
    actualFiles: number,
    maxFiles: number,
  ) {
    super(
      `Repository "${target}" exceeded the ${scope} file/inode cap (${actualFiles} > ${maxFiles} limit).`,
    )
    this.name = 'RepoFileLimitExceededError'
    this.scope = scope
    this.target = target
    this.actualFiles = actualFiles
    this.maxFiles = maxFiles
  }
}

const repoFullNamePattern = /^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/
const safeSegmentPattern = /^[a-zA-Z0-9_.-]{1,128}$/
const defaultMaxFilesPerRepo = 40
const defaultMaxFileBytes = 512 * 1024
const defaultMaxRepoBytes = 2 * 1024 * 1024
const defaultMaxLockfileBytes = 8 * 1024 * 1024
const defaultCloneTimeoutMs = 120_000
const defaultHistoryDepth = DEFAULT_CLONE_DEPTH
const defaultMaxCommitDiffs = 20

const repoLockTails = new Map<string, Promise<void>>()
const activeRepoLockKeys = new Set<string>()
const activeStagingDirs = new Set<string>()

function isTestRuntime(): boolean {
  if (typeof process === 'undefined') return false
  return Boolean(process.env.NODE_TEST_CONTEXT)
    || process.env.NODE_ENV === 'test'
    || (Array.isArray(process.execArgv) && process.execArgv.includes('--test'))
}

function parsePositiveEnvBytes(name: string): number | undefined {
  if (typeof process === 'undefined' || !process.env) return undefined
  const raw = process.env[name]?.trim()
  if (!raw) return undefined
  const parsed = Number(raw)
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined
  return Math.floor(parsed)
}

function repoLockKey(targetRootDir: string, fullName: string): string {
  return `${resolve(targetRootDir)}::${fullName.toLowerCase()}`
}

export function isRepoOperationLocked(targetRootDir: string, repoSlug: string): boolean {
  const { fullName } = parseRepoFullName(repoSlug)
  return activeRepoLockKeys.has(repoLockKey(targetRootDir, fullName))
}

/**
 * Serialize concurrent clone/resync/unlink operations for the same `(cloneRoot, owner/repo)` key.
 * Waiters observe `options.signal` while queued without breaking serialization for subsequent callers.
 */
export async function withRepoOperationLock<T>(
  targetRootDir: string,
  repoSlug: string,
  fn: () => Promise<T> | T,
  options: { signal?: AbortSignal } = {},
): Promise<T> {
  options.signal?.throwIfAborted()
  const { fullName } = parseRepoFullName(repoSlug)
  const key = repoLockKey(targetRootDir, fullName)
  const previous = repoLockTails.get(key)

  let release!: () => void
  const current = new Promise<void>(resolvePromise => {
    release = resolvePromise
  })
  const tail = (previous ?? Promise.resolve()).then(() => current)
  repoLockTails.set(key, tail)

  const waitForTurn = async (): Promise<void> => {
    if (!previous) return
    const signal = options.signal
    if (!signal) {
      await previous
      return
    }
    if (signal.aborted) {
      throw signal.reason ?? new DOMException('The operation was aborted.', 'AbortError')
    }
    await new Promise<void>((resolveWait, rejectWait) => {
      const onAbort = () => {
        rejectWait(signal.reason ?? new DOMException('The operation was aborted.', 'AbortError'))
      }
      signal.addEventListener('abort', onAbort, { once: true })
      previous.then(
        () => {
          signal.removeEventListener('abort', onAbort)
          resolveWait()
        },
        () => {
          signal.removeEventListener('abort', onAbort)
          resolveWait()
        },
      )
    })
  }

  let acquired = false
  try {
    await waitForTurn()
    options.signal?.throwIfAborted()
    acquired = true
    activeRepoLockKeys.add(key)
    return await fn()
  } finally {
    if (acquired) {
      activeRepoLockKeys.delete(key)
    }
    release()
    if (repoLockTails.get(key) === tail) {
      repoLockTails.delete(key)
    }
  }
}

export interface OrphanCleanupResult {
  removed: string[]
  warnings: string[]
}

/**
 * Deterministically remove orphaned `.tmp-*` and `.old-*` checkout directories left behind
 * by interrupted clones/swaps under `repos/<projectId>/`, skipping any paths actively in flight.
 */
export function cleanupOrphanedRepoDirs(
  reposDir: string,
  options: { skipPaths?: ReadonlySet<string> } = {},
): OrphanCleanupResult {
  const removed: string[] = []
  const warnings: string[] = []
  if (!reposDir || /[\0,\r\n]/.test(reposDir) || !existsSync(reposDir)) {
    return { removed, warnings }
  }
  let rootStat
  try {
    rootStat = lstatSync(reposDir)
  } catch {
    return { removed, warnings }
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    return { removed, warnings }
  }
  const resolvedRoot = realpathSync(reposDir)

  const shouldSkip = (entryPath: string): boolean => {
    const resolved = resolve(entryPath)
    return activeStagingDirs.has(resolved) || Boolean(options.skipPaths?.has(resolved))
  }

  const removeIfOrphan = (entryPath: string, name: string): boolean => {
    if (!name.startsWith('.tmp-') && !name.startsWith('.old-')) return false
    if (shouldSkip(entryPath)) return false
    if (!resolve(entryPath).startsWith(resolvedRoot + sep)) return false
    try {
      const st = lstatSync(entryPath)
      if (st.isSymbolicLink()) {
        rmSync(entryPath, { force: true })
      } else {
        rmSync(entryPath, { recursive: true, force: true })
      }
      removed.push(relative(resolvedRoot, entryPath).split(sep).join('/'))
      return true
    } catch (err) {
      warnings.push(`Failed to clean orphaned checkout "${name}": ${err instanceof Error ? err.message : String(err)}`)
      return false
    }
  }

  let topEntries
  try {
    topEntries = readdirSync(resolvedRoot, { withFileTypes: true })
  } catch {
    return { removed, warnings }
  }

  for (const topEntry of topEntries) {
    const topPath = join(resolvedRoot, topEntry.name)
    if (removeIfOrphan(topPath, topEntry.name)) continue
    if (topEntry.name.startsWith('.') || !safeSegmentPattern.test(topEntry.name)) continue
    let topStat
    try {
      topStat = lstatSync(topPath)
    } catch {
      continue
    }
    if (!topStat.isDirectory() || topStat.isSymbolicLink()) continue

    let ownerEntries
    try {
      ownerEntries = readdirSync(topPath, { withFileTypes: true })
    } catch {
      continue
    }
    let removedInOwner = false
    for (const child of ownerEntries) {
      const childPath = join(topPath, child.name)
      if (removeIfOrphan(childPath, child.name)) {
        removedInOwner = true
      }
    }
    if (removedInOwner) {
      try {
        if (readdirSync(topPath).length === 0) {
          rmdirSync(topPath)
        }
      } catch {
        // Best-effort cleanup of empty owner dir.
      }
    }
  }

  return { removed: removed.sort(), warnings }
}

export function buildHardenedGitCloneArgs(input: {
  repoUrl: string
  stagingDir: string
  depth?: number
  allowLocalFileProtocol?: boolean
  noCheckout?: boolean
}): string[] {
  const depth = Math.max(1, Math.min(Math.floor(input.depth ?? DEFAULT_CLONE_DEPTH), 100))
  const fileProtocolPolicy = input.allowLocalFileProtocol ? 'user' : 'never'
  const args = [
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.symlinks=false',
    '-c', `protocol.file.allow=${fileProtocolPolicy}`,
    '-c', 'protocol.ext.allow=never',
    '-c', 'submodule.recurse=false',
    '-c', 'fetch.recurseSubmodules=false',
    'clone',
    '--depth', String(depth),
    '--single-branch',
    '--no-tags',
    '--no-recurse-submodules',
  ]
  if (input.noCheckout !== false) {
    args.push('--no-checkout')
  }
  args.push('--', input.repoUrl, input.stagingDir)
  return args
}

const skippedDirNames = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.next',
  '.nuxt',
  '.vercel',
  'coverage',
  'vendor',
  '__pycache__',
  '.venv',
  'target',
])

const lockfileNames = new Set([
  'package-lock.json',
  'pnpm-lock.yaml',
  'bun.lock',
  'yarn.lock',
  'requirements.txt',
  'pyproject.toml',
  'go.sum',
  'cargo.lock',
  'uv.lock',
])

export function projectReposDir(dataDir: string, projectId: string): string {
  if (!dataDir || /[\0,\r\n]/.test(dataDir)) {
    throw new Error('Invalid workspace data directory.')
  }
  if (!safeSegmentPattern.test(projectId) || projectId === '.' || projectId === '..' || projectId.includes('..')) {
    throw new Error(`Invalid project ID for repository directory: "${projectId}".`)
  }
  return join(dataDir, 'repos', projectId)
}

export function listMountedRepos(reposDir: string): string[] {
  if (!reposDir || /[\0,\r\n]/.test(reposDir) || !existsSync(reposDir)) return []
  let rootStat
  try {
    rootStat = lstatSync(reposDir)
  } catch {
    return []
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return []

  const mounted: string[] = []
  let owners
  try {
    owners = readdirSync(reposDir, { withFileTypes: true })
  } catch {
    return []
  }
  for (const ownerEntry of owners) {
    if (ownerEntry.name.startsWith('.') || !safeSegmentPattern.test(ownerEntry.name)) continue
    if (!ownerEntry.isDirectory() || ownerEntry.isSymbolicLink()) continue
    const ownerPath = join(reposDir, ownerEntry.name)
    let repos
    try {
      repos = readdirSync(ownerPath, { withFileTypes: true })
    } catch {
      continue
    }
    for (const repoEntry of repos) {
      if (repoEntry.name.startsWith('.') || !safeSegmentPattern.test(repoEntry.name)) continue
      if (!repoEntry.isDirectory() || repoEntry.isSymbolicLink()) continue
      mounted.push(`/repos/${ownerEntry.name}/${repoEntry.name}`)
    }
  }
  return mounted.sort()
}

export interface ProjectMountedRepo {
  fullName: string
  mountPath: string
  branch: string | null
  commitSha: string | null
  sizeBytes: number
  updatedAt: number
}

export interface UnlinkMountedRepoResult {
  unlinked: boolean
  fullName: string
}

export interface MeasureDirectoryOptions {
  /** Maximum allowed directory nesting depth below `dirPath` (default `DEFAULT_MAX_REPO_DEPTH` = 32). */
  maxDepth?: number
  /** Maximum allowed regular files (default `DEFAULT_MAX_REPO_FILES` = 50,000). */
  maxFiles?: number
  /** Maximum allowed total entries / inodes (files + directories + symlinks; default `maxFiles * 2`). */
  maxInodes?: number
  /** Optional early-abort byte ceiling; throws `RepoDiskQuotaExceededError` as soon as exceeded. */
  maxBytes?: number
  /** Scope label used in quota errors (default `'repo'`). */
  scope?: 'repo' | 'project'
  /** Target label (repo fullName or path) used in thrown errors. */
  targetLabel?: string
  /** Bounded async concurrency for filesystem stat operations (default 32). */
  concurrency?: number
  /** Optional abort signal. */
  signal?: AbortSignal
}

export interface DirectoryMeasurement {
  bytes: number
  fileCount: number
  inodeCount: number
  maxDepth: number
}

function resolveMeasureOptions(dirPath: string, options: MeasureDirectoryOptions = {}) {
  const maxDepth = Math.max(0, Math.floor(options.maxDepth ?? DEFAULT_MAX_REPO_DEPTH))
  const maxFiles = Math.max(1, Math.floor(options.maxFiles ?? DEFAULT_MAX_REPO_FILES))
  const maxInodes = Math.max(maxFiles, Math.floor(options.maxInodes ?? maxFiles * 2))
  const maxBytes = options.maxBytes !== undefined && Number.isFinite(options.maxBytes) && options.maxBytes >= 0
    ? Math.floor(options.maxBytes)
    : undefined
  const scope = options.scope ?? 'repo'
  const targetLabel = options.targetLabel ?? dirPath
  const concurrency = Math.max(1, Math.min(Math.floor(options.concurrency ?? 32), 64))
  return { maxDepth, maxFiles, maxInodes, maxBytes, scope, targetLabel, concurrency }
}

/**
 * Asynchronously measure directory disk usage, file/inode count, and nesting depth using
 * `fs.promises.readdir` / `lstat` with bounded concurrency and event-loop yields.
 * Always fails closed on over-depth directories (`> maxDepth`, default 32) and file/inode caps.
 */
export async function measureDirectoryUsage(
  dirPath: string,
  options: MeasureDirectoryOptions = {},
): Promise<DirectoryMeasurement> {
  options.signal?.throwIfAborted()
  const { maxDepth, maxFiles, maxInodes, maxBytes, scope, targetLabel, concurrency } = resolveMeasureOptions(dirPath, options)

  let rootStat
  try {
    rootStat = await fsp.lstat(dirPath)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      return { bytes: 0, fileCount: 0, inodeCount: 0, maxDepth: 0 }
    }
    throw err
  }
  if (rootStat.isSymbolicLink()) {
    return { bytes: 0, fileCount: 0, inodeCount: 1, maxDepth: 0 }
  }
  if (rootStat.isFile()) {
    if (maxBytes !== undefined && rootStat.size > maxBytes) {
      throw new RepoDiskQuotaExceededError(scope, targetLabel, rootStat.size, maxBytes)
    }
    return { bytes: rootStat.size, fileCount: 1, inodeCount: 1, maxDepth: 0 }
  }
  if (!rootStat.isDirectory()) {
    return { bytes: 0, fileCount: 0, inodeCount: 0, maxDepth: 0 }
  }

  let bytes = 0
  let fileCount = 0
  let inodeCount = 0
  let observedMaxDepth = 0
  let opsSinceYield = 0
  const queue: Array<{ path: string; depth: number }> = [{ path: dirPath, depth: 0 }]

  while (queue.length > 0) {
    options.signal?.throwIfAborted()
    const current = queue.shift()!
    if (current.depth > maxDepth) {
      throw new RepoDepthLimitExceededError(targetLabel, current.depth, maxDepth, current.path)
    }
    if (current.depth > observedMaxDepth) {
      observedMaxDepth = current.depth
    }

    let entries
    try {
      entries = await fsp.readdir(current.path, { withFileTypes: true })
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code
      if (code === 'ENOENT') continue
      throw err
    }

    for (let i = 0; i < entries.length; i += concurrency) {
      options.signal?.throwIfAborted()
      const batch = entries.slice(i, i + concurrency)
      const statResults = await Promise.all(
        batch.map(async entry => {
          const fullPath = join(current.path, entry.name)
          try {
            const st = await fsp.lstat(fullPath)
            return { fullPath, st }
          } catch (err) {
            const code = (err as NodeJS.ErrnoException | undefined)?.code
            if (code === 'ENOENT') return null
            throw err
          }
        }),
      )

      for (const item of statResults) {
        if (!item) continue
        const { fullPath, st } = item
        if (st.isSymbolicLink()) {
          inodeCount += 1
          if (inodeCount > maxInodes) {
            throw new RepoFileLimitExceededError(scope, targetLabel, inodeCount, maxInodes)
          }
          continue
        }
        if (st.isFile()) {
          fileCount += 1
          inodeCount += 1
          bytes += st.size
          if (fileCount > maxFiles) {
            throw new RepoFileLimitExceededError(scope, targetLabel, fileCount, maxFiles)
          }
          if (inodeCount > maxInodes) {
            throw new RepoFileLimitExceededError(scope, targetLabel, inodeCount, maxInodes)
          }
          if (maxBytes !== undefined && bytes > maxBytes) {
            throw new RepoDiskQuotaExceededError(scope, targetLabel, bytes, maxBytes)
          }
        } else if (st.isDirectory()) {
          inodeCount += 1
          if (inodeCount > maxInodes) {
            throw new RepoFileLimitExceededError(scope, targetLabel, inodeCount, maxInodes)
          }
          const nextDepth = current.depth + 1
          if (nextDepth > maxDepth) {
            throw new RepoDepthLimitExceededError(targetLabel, nextDepth, maxDepth, fullPath)
          }
          queue.push({ path: fullPath, depth: nextDepth })
        }
      }

      opsSinceYield += batch.length
      if (opsSinceYield >= 256) {
        opsSinceYield = 0
        await new Promise<void>(resolveImmediate => setImmediate(resolveImmediate))
      }
    }
  }

  return { bytes, fileCount, inodeCount, maxDepth: observedMaxDepth }
}

/**
 * Asynchronously measure directory disk usage in bytes, failing closed on over-depth
 * directories (`> 32` by default) and file/inode caps.
 */
export async function measureDirectoryBytes(
  dirPath: string,
  options: MeasureDirectoryOptions = {},
): Promise<number> {
  const usage = await measureDirectoryUsage(dirPath, options)
  return usage.bytes
}

/**
 * Fail-closed synchronous directory byte counter reserved for legacy synchronous metadata
 * listing (`listProjectMountedRepos`). Enforces the exact same over-depth and file/inode caps.
 */
function measureDirectoryBytesSyncFailClosed(
  dirPath: string,
  options: Omit<MeasureDirectoryOptions, 'concurrency' | 'signal'> = {},
): number {
  const { maxDepth, maxFiles, maxInodes, maxBytes, scope, targetLabel } = resolveMeasureOptions(dirPath, options)
  let rootStat
  try {
    rootStat = lstatSync(dirPath)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code
    if (code === 'ENOENT' || code === 'ENOTDIR') return 0
    throw err
  }
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    return rootStat.isFile() ? rootStat.size : 0
  }

  let bytes = 0
  let fileCount = 0
  let inodeCount = 0
  const stack: Array<{ path: string; depth: number }> = [{ path: dirPath, depth: 0 }]

  while (stack.length > 0) {
    const current = stack.pop()!
    if (current.depth > maxDepth) {
      throw new RepoDepthLimitExceededError(targetLabel, current.depth, maxDepth, current.path)
    }
    let entries
    try {
      entries = readdirSync(current.path, { withFileTypes: true })
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code
      if (code === 'ENOENT') continue
      throw err
    }
    for (const entry of entries) {
      const fullPath = join(current.path, entry.name)
      let st
      try {
        st = lstatSync(fullPath)
      } catch (err) {
        const code = (err as NodeJS.ErrnoException | undefined)?.code
        if (code === 'ENOENT') continue
        throw err
      }
      if (st.isSymbolicLink()) {
        inodeCount += 1
        if (inodeCount > maxInodes) {
          throw new RepoFileLimitExceededError(scope, targetLabel, inodeCount, maxInodes)
        }
        continue
      }
      if (st.isFile()) {
        fileCount += 1
        inodeCount += 1
        bytes += st.size
        if (fileCount > maxFiles) {
          throw new RepoFileLimitExceededError(scope, targetLabel, fileCount, maxFiles)
        }
        if (inodeCount > maxInodes) {
          throw new RepoFileLimitExceededError(scope, targetLabel, inodeCount, maxInodes)
        }
        if (maxBytes !== undefined && bytes > maxBytes) {
          throw new RepoDiskQuotaExceededError(scope, targetLabel, bytes, maxBytes)
        }
      } else if (st.isDirectory()) {
        inodeCount += 1
        if (inodeCount > maxInodes) {
          throw new RepoFileLimitExceededError(scope, targetLabel, inodeCount, maxInodes)
        }
        const nextDepth = current.depth + 1
        if (nextDepth > maxDepth) {
          throw new RepoDepthLimitExceededError(targetLabel, nextDepth, maxDepth, fullPath)
        }
        stack.push({ path: fullPath, depth: nextDepth })
      }
    }
  }
  return bytes
}

export interface UnlinkMountedRepoOptions {
  activeRunIds?: readonly string[]
  assertNoActiveRuns?: () => void
}

export async function measureProjectDiskBytes(
  reposDir: string,
  options: {
    excludeRepo?: string
    maxDepth?: number
    maxFiles?: number
    maxInodes?: number
    signal?: AbortSignal
  } = {},
): Promise<number> {
  options.signal?.throwIfAborted()
  const excluded = options.excludeRepo ? parseRepoFullName(options.excludeRepo).fullName.toLowerCase() : null
  const mounted = listMountedRepos(reposDir)
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_REPO_DEPTH
  const maxFiles = Math.max(1, Math.floor(options.maxFiles ?? DEFAULT_MAX_PROJECT_FILES))
  const maxInodes = Math.max(maxFiles, Math.floor(options.maxInodes ?? maxFiles * 2))
  let totalBytes = 0
  let totalFiles = 0
  let totalInodes = 0
  for (const mountPath of mounted) {
    options.signal?.throwIfAborted()
    const fullName = mountPath.slice('/repos/'.length)
    if (excluded && fullName.toLowerCase() === excluded) continue
    const { owner, repo } = parseRepoFullName(fullName)
    const remainingFiles = Math.max(1, maxFiles - totalFiles)
    const remainingInodes = Math.max(1, maxInodes - totalInodes)
    const usage = await measureDirectoryUsage(join(reposDir, owner, repo), {
      maxDepth,
      maxFiles: remainingFiles,
      maxInodes: remainingInodes,
      scope: 'project',
      targetLabel: fullName,
      signal: options.signal,
    })
    totalBytes += usage.bytes
    totalFiles += usage.fileCount
    totalInodes += usage.inodeCount
    if (totalFiles > maxFiles) {
      throw new RepoFileLimitExceededError('project', fullName, totalFiles, maxFiles)
    }
    if (totalInodes > maxInodes) {
      throw new RepoFileLimitExceededError('project', fullName, totalInodes, maxInodes)
    }
  }
  return totalBytes
}

function readRepoGitHeadInfo(repoDir: string): { branch: string | null; commitSha: string | null } {
  const gitPath = join(repoDir, '.git')
  if (!existsSync(gitPath)) return { branch: null, commitSha: null }
  try {
    if (lstatSync(gitPath).isSymbolicLink()) return { branch: null, commitSha: null }
  } catch {
    return { branch: null, commitSha: null }
  }
  const baseArgs = [
    '-C', repoDir,
    '-c', 'safe.directory=*',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.symlinks=false',
    '-c', 'protocol.file.allow=never',
    '-c', 'protocol.ext.allow=never',
  ]
  let branch: string | null = null
  let commitSha: string | null = null
  try {
    const rawBranch = execFileSync('git', [...baseArgs, 'rev-parse', '--abbrev-ref', 'HEAD'], {
      encoding: 'utf8',
      timeout: 3_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    if (rawBranch && rawBranch !== 'HEAD') branch = rawBranch
  } catch {
    // Best-effort git branch read.
  }
  try {
    const rawSha = execFileSync('git', [...baseArgs, 'rev-parse', '--short', 'HEAD'], {
      encoding: 'utf8',
      timeout: 3_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
    if (rawSha) commitSha = rawSha
  } catch {
    // Best-effort git SHA read.
  }
  return { branch, commitSha }
}

/** List mounted repositories for a project with git metadata, byte size, and mtime. */
export function listProjectMountedRepos(dataDir: string, projectId: string): ProjectMountedRepo[] {
  const reposDir = projectReposDir(dataDir, projectId)
  const mounted = listMountedRepos(reposDir)
  const out: ProjectMountedRepo[] = []
  for (const mountPath of mounted) {
    const fullName = mountPath.slice('/repos/'.length)
    const { owner, repo } = parseRepoFullName(fullName)
    const repoDir = join(reposDir, owner, repo)
    let updatedAt = 0
    try {
      updatedAt = Math.round(lstatSync(repoDir).mtimeMs)
    } catch {
      continue
    }
    const { branch, commitSha } = readRepoGitHeadInfo(repoDir)
    const sizeBytes = measureDirectoryBytesSyncFailClosed(repoDir, { targetLabel: fullName })
    out.push({
      fullName,
      mountPath,
      branch,
      commitSha,
      sizeBytes,
      updatedAt,
    })
  }
  return out
}

function unlinkProjectMountedRepoUnlocked(
  dataDir: string,
  projectId: string,
  repoSlug: string,
  _options: UnlinkMountedRepoOptions = {},
): UnlinkMountedRepoResult {
  const reposDir = projectReposDir(dataDir, projectId)
  const { fullName, owner, repo } = parseRepoFullName(repoSlug)

  if (!existsSync(reposDir)) {
    return { unlinked: false, fullName }
  }
  const rootStat = lstatSync(reposDir)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('Invalid project repository root directory.')
  }
  const resolvedRoot = realpathSync(reposDir)
  const ownerDir = join(resolvedRoot, owner)
  const targetDir = join(ownerDir, repo)

  if (
    !resolve(ownerDir).startsWith(resolvedRoot + sep) ||
    !resolve(targetDir).startsWith(resolvedRoot + sep) ||
    relative(resolvedRoot, targetDir) !== join(owner, repo)
  ) {
    throw new Error(`Repository path escapes project root: "${repoSlug}".`)
  }

  let ownerStat
  try {
    ownerStat = lstatSync(ownerDir)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { unlinked: false, fullName }
    }
    throw err
  }
  if (ownerStat.isSymbolicLink() || !ownerStat.isDirectory()) {
    throw new Error(`Refusing to unlink inside invalid owner path: "${owner}".`)
  }
  const realOwner = realpathSync(ownerDir)
  if (!realOwner.startsWith(resolvedRoot + sep)) {
    throw new Error(`Repository owner path escapes project root: "${owner}".`)
  }

  let targetStat
  try {
    targetStat = lstatSync(targetDir)
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { unlinked: false, fullName }
    }
    throw err
  }
  if (targetStat.isSymbolicLink() || !targetStat.isDirectory()) {
    throw new Error(`Refusing to unlink non-directory or symlinked repository path: "${fullName}".`)
  }
  const realTarget = realpathSync(targetDir)
  if (!realTarget.startsWith(resolvedRoot + sep) || relative(resolvedRoot, realTarget) !== join(owner, repo)) {
    throw new Error(`Resolved repository path escapes project root: "${fullName}".`)
  }

  rmSync(targetDir, { recursive: true, force: true })
  // Also sweep any orphaned staging/backup directories left for this repo.
  try {
    for (const entry of readdirSync(ownerDir, { withFileTypes: true })) {
      if (entry.name.startsWith(`.tmp-${repo}-`) || entry.name.startsWith(`.old-${repo}-`)) {
        const orphanPath = join(ownerDir, entry.name)
        if (!activeStagingDirs.has(resolve(orphanPath))) {
          rmSync(orphanPath, { recursive: true, force: true })
        }
      }
    }
    if (readdirSync(ownerDir).length === 0) {
      rmdirSync(ownerDir)
    }
  } catch {
    // Best-effort cleanup of orphaned staging dirs and empty owner directory.
  }
  return { unlinked: true, fullName }
}

/**
 * Unlink (delete) a single mounted repository checkout under `repos/<projectId>/<owner>/<repo>`.
 * Strictly enforces path containment and rejects unlink while a concurrent sync holds the per-repo lock.
 * Safe during active runs because worker containers mount immutable per-run snapshots.
 */
export function unlinkProjectMountedRepo(
  dataDir: string,
  projectId: string,
  repoSlug: string,
  options: UnlinkMountedRepoOptions = {},
): UnlinkMountedRepoResult {
  const reposDir = projectReposDir(dataDir, projectId)
  const { fullName } = parseRepoFullName(repoSlug)
  if (isRepoOperationLocked(reposDir, fullName)) {
    throw new RepoWorkspaceBusyError(
      'REPO_SYNC_IN_PROGRESS',
      `Repository "${fullName}" currently has a sync or unlink operation in progress. Wait for it to finish and try again.`,
    )
  }
  return unlinkProjectMountedRepoUnlocked(dataDir, projectId, repoSlug, options)
}

/**
 * Async locked variant of `unlinkProjectMountedRepo` that serializes cleanly against concurrent clones/resyncs.
 */
export async function unlinkProjectMountedRepoLocked(
  dataDir: string,
  projectId: string,
  repoSlug: string,
  options: UnlinkMountedRepoOptions & { signal?: AbortSignal } = {},
): Promise<UnlinkMountedRepoResult> {
  const reposDir = projectReposDir(dataDir, projectId)
  return await withRepoOperationLock(
    reposDir,
    repoSlug,
    () => unlinkProjectMountedRepoUnlocked(dataDir, projectId, repoSlug, options),
    { signal: options.signal },
  )
}

function parseRepoFullName(rawName: string): { fullName: string; owner: string; repo: string } {
  const fullName = rawName.trim()
  if (!repoFullNamePattern.test(fullName) || fullName.includes('..')) {
    throw new Error(`Invalid GitHub repository name: "${fullName}". Expected "owner/repo".`)
  }
  const [owner, repo] = fullName.split('/')
  if (
    !owner || !repo ||
    owner === '.' || owner === '..' || repo === '.' || repo === '..' ||
    owner.startsWith('-') || repo.startsWith('-')
  ) {
    throw new Error(`Invalid GitHub repository name: "${fullName}". Expected "owner/repo".`)
  }
  return { fullName, owner, repo }
}

function classifyRepoPath(filePath: string): { category: SyncedRepoFile['category']; priority: number } | null {
  const lower = filePath.toLowerCase()
  const base = lower.split('/').pop() ?? lower

  // Skip build output, vendored dependencies, minified assets, and tests
  if (/(?:^|\/)(?:node_modules|dist|build|\.next|\.nuxt|\.vercel|coverage|vendor|__tests__|__mocks__)\//.test(lower)) {
    return null
  }
  if (/\.(?:min\.js|map|png|jpg|jpeg|gif|webp|ico|woff2?|ttf|eot|pdf|zip|tar|gz|mp4|svg)$/i.test(lower)) {
    return null
  }
  if (/\.(?:test|spec)\.[a-z0-9]+$/i.test(lower)) {
    return null
  }

  // Manifests & lockfiles (highest priority for exact CVE correlation)
  if (base === 'package.json') return { category: 'manifest', priority: 100 }
  if (base === 'package-lock.json' || base === 'pnpm-lock.yaml' || base === 'bun.lock' || base === 'yarn.lock') {
    return { category: 'lockfile', priority: 95 }
  }
  if (base === 'go.sum' || base === 'requirements.txt' || base === 'pyproject.toml' || base === 'uv.lock' || base === 'cargo.lock') {
    return { category: 'lockfile', priority: 90 }
  }

  // OpenAPI & GraphQL specs
  if (/(?:openapi|swagger).*\.(?:json|ya?ml)$/i.test(base)) return { category: 'openapi', priority: 88 }
  if (/\.(?:graphql|gql)$/i.test(base)) return { category: 'graphql', priority: 85 }

  // Framework & security configs
  if (/^(?:next\.config|vercel\.json|netlify\.toml|wrangler\.toml|wrangler\.jsonc?|cors\.|security\.)/i.test(base)) {
    return { category: 'config', priority: 80 }
  }

  // High-signal server routes, middleware, auth, upload, webhook, billing, and API handlers
  if (/\.(?:ts|tsx|js|jsx|mts|mjs|cjs|py|go)$/i.test(base)) {
    if (/^middleware\./i.test(base) || /(?:^|\/)middleware\//i.test(lower)) return { category: 'route', priority: 84 }
    if (/(?:^|\/)(?:app\/api|pages\/api|src\/app\/api|src\/pages\/api|routes|api|handlers|controllers|endpoints)\//i.test(lower)) {
      return { category: 'route', priority: 78 }
    }
    if (/(?:auth|oauth|session|jwt|token|rbac|acl|permission|upload|presign|storage|webhook|billing|stripe|proxy|redirect|cors|graphql|trpc|admin|server)/i.test(base)) {
      return { category: 'route', priority: 72 }
    }
  }

  return null
}

function cleanSemver(raw: string): string | null {
  const trimmed = raw.trim().replace(/^[~^=<>!\s]+/, '').split(/[\s|,;]/, 1)[0]
  if (!trimmed || !/^\d+\.\d+/.test(trimmed)) return null
  return trimmed.slice(0, 64)
}

export function parseDependenciesFromFile(filePath: string, content: string): RepoDependency[] {
  const base = (filePath.split('/').pop() ?? filePath).toLowerCase()
  const out: RepoDependency[] = []
  const seen = new Set<string>()
  const add = (ecosystem: string, pkg: string, version: string | null) => {
    if (!pkg || !version) return
    const key = `${ecosystem}:${pkg}:${version}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ ecosystem, package: pkg, version, sourceFile: filePath })
  }

  if (base === 'package.json') {
    try {
      const parsed = JSON.parse(content) as {
        dependencies?: Record<string, string>
        devDependencies?: Record<string, string>
      }
      for (const [pkg, ver] of Object.entries({ ...parsed.dependencies, ...parsed.devDependencies })) {
        add('npm', pkg, cleanSemver(ver))
      }
    } catch { /* ignore malformed JSON */ }
    return out
  }

  if (base === 'package-lock.json') {
    try {
      const parsed = JSON.parse(content) as {
        packages?: Record<string, { version?: string }>
        dependencies?: Record<string, { version?: string }>
      }
      if (parsed.packages) {
        for (const [pkgPath, meta] of Object.entries(parsed.packages)) {
          if (!pkgPath || !meta?.version) continue
          const match = pkgPath.match(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)$/)
          if (match) add('npm', match[1], cleanSemver(meta.version))
        }
      }
      if (parsed.dependencies) {
        for (const [pkg, meta] of Object.entries(parsed.dependencies)) {
          if (meta?.version) add('npm', pkg, cleanSemver(meta.version))
        }
      }
    } catch { /* ignore */ }
    return out.slice(0, 500)
  }

  if (base === 'pnpm-lock.yaml') {
    // Matches both pnpm v9 (`'next@15.1.0':` / `@scope/pkg@1.2.3(...)`) and v6 (`/@scope/pkg@1.2.3:`)
    const lines = content.split('\n')
    let inPackages = false
    for (const line of lines) {
      if (/^packages:\s*$/.test(line)) {
        inPackages = true
        continue
      }
      if (inPackages && /^[a-zA-Z]/.test(line)) {
        inPackages = false
        continue
      }
      if (!inPackages) continue
      const match = line.match(/^\s{2}['"]?\/?((?:@[^/@'"\s]+\/)?[^/@'"\s(]+)[@/]([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)/)
      if (match) add('npm', match[1], cleanSemver(match[2]))
    }
    return out.slice(0, 500)
  }

  if (base === 'bun.lock') {
    // bun.lock is JSONC (JSON with trailing commas). Parse package tuples like `"next": ["next@15.1.0", ...]`.
    for (const match of content.matchAll(/"((?:@[^/"\s]+\/)?[a-zA-Z0-9_.-]+)@([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)"/g)) {
      add('npm', match[1], cleanSemver(match[2]))
    }
    return out.slice(0, 500)
  }

  if (base === 'yarn.lock') {
    let currentPkg: string | null = null
    for (const line of content.split('\n')) {
      if (!line.startsWith(' ') && !line.startsWith('\t') && line.trimEnd().endsWith(':')) {
        const header = line.trim().replace(/:$/, '').split(',')[0].trim().replace(/^["']|["']$/g, '')
        const atIdx = header.startsWith('@') ? header.indexOf('@', 1) : header.indexOf('@')
        currentPkg = atIdx > 0 ? header.slice(0, atIdx) : null
        continue
      }
      if (currentPkg) {
        const verMatch = line.match(/^\s+version(?::|\s+)\s*["']?([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)["']?/)
        if (verMatch) {
          add('npm', currentPkg, cleanSemver(verMatch[1]))
          currentPkg = null
        }
      }
    }
    return out.slice(0, 500)
  }

  if (base === 'requirements.txt') {
    for (const line of content.split('\n')) {
      const m = line.trim().match(/^([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=|<=)\s*([0-9][0-9a-zA-Z.*+-]*)/)
      if (m) add('PyPI', m[1], cleanSemver(m[2]))
    }
    return out.slice(0, 300)
  }

  if (base === 'pyproject.toml') {
    let section = ''
    let inDepsArray = false
    for (const rawLine of content.split('\n')) {
      const line = rawLine.replace(/#.*$/, '').trim()
      if (!line) continue
      const secMatch = line.match(/^\[([^\]]+)\]$/)
      if (secMatch) {
        section = secMatch[1].trim()
        inDepsArray = false
        continue
      }
      if (section === 'project' || section.startsWith('project.optional-dependencies')) {
        if (/^dependencies\s*=\s*\[/.test(line) || (section.startsWith('project.optional-dependencies') && /=\s*\[/.test(line))) {
          inDepsArray = !line.includes(']')
        }
        if (inDepsArray || /^dependencies\s*=/.test(line) || section.startsWith('project.optional-dependencies')) {
          for (const m of line.matchAll(/["']([a-zA-Z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|>=|~=|<=|!=)\s*([0-9][0-9a-zA-Z.*+-]*)/g)) {
            add('PyPI', m[1], cleanSemver(m[2]))
          }
          if (line.includes(']')) inDepsArray = false
        }
      } else if (section === 'tool.poetry.dependencies' || section === 'tool.poetry.dev-dependencies' || section.endsWith('.dependencies')) {
        const kv = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*(?:"([^"]+)"|'([^']+)'|\{[^}]*version\s*=\s*["']([^"']+)["'])/)
        if (kv && kv[1].toLowerCase() !== 'python') {
          add('PyPI', kv[1], cleanSemver(kv[2] ?? kv[3] ?? kv[4] ?? ''))
        }
      }
    }
    return out.slice(0, 300)
  }

  if (base === 'go.sum') {
    for (const line of content.split('\n')) {
      const m = line.trim().match(/^([^\s]+)\s+v([0-9]+\.[0-9]+\.[0-9A-Za-z.+-]*)/)
      if (m) add('Go', m[1], m[2].replace(/\/go\.mod$/, ''))
    }
    return out.slice(0, 300)
  }

  if (base === 'cargo.lock') {
    let inPkg = false
    let pkgName: string | null = null
    let pkgVer: string | null = null
    const flush = () => {
      if (pkgName && pkgVer) add('crates.io', pkgName, cleanSemver(pkgVer))
      pkgName = null
      pkgVer = null
    }
    for (const rawLine of content.split('\n')) {
      const line = rawLine.trim()
      if (line === '[[package]]') {
        flush()
        inPkg = true
        continue
      }
      if (!inPkg) continue
      const nameMatch = line.match(/^name\s*=\s*"([^"]+)"/)
      if (nameMatch) { pkgName = nameMatch[1]; continue }
      const verMatch = line.match(/^version\s*=\s*"([^"]+)"/)
      if (verMatch) { pkgVer = verMatch[1]; continue }
    }
    flush()
    return out.slice(0, 500)
  }

  return out
}

function deduplicateDependencies(allDependencies: readonly RepoDependency[]): RepoDependency[] {
  const depMap = new Map<string, RepoDependency>()
  for (const dep of allDependencies) {
    const key = `${dep.ecosystem}:${dep.package}`
    const existing = depMap.get(key)
    const isManifest = dep.sourceFile.endsWith('package.json') || dep.sourceFile.endsWith('pyproject.toml')
    const existingIsManifest = existing
      ? (existing.sourceFile.endsWith('package.json') || existing.sourceFile.endsWith('pyproject.toml'))
      : false
    if (!existing || (!isManifest && existingIsManifest)) {
      depMap.set(key, dep)
    }
  }
  return [...depMap.values()]
}

function buildDependenciesSpec(fullName: string, dependencies: readonly RepoDependency[]): SyncedRepoSpec | null {
  if (dependencies.length === 0) return null
  const depLines = dependencies
    .slice(0, 600)
    .map(d => `${d.ecosystem}:${d.package}@${d.version} (${d.sourceFile})`)
  return {
    name: `${fullName}:dependencies`.slice(0, 160),
    kind: 'notes',
    content: `# Extracted Dependencies for ${fullName} (${dependencies.length} total)\n\n${depLines.join('\n')}`,
  }
}

function buildRepoSpecs(fullName: string, files: readonly SyncedRepoFile[], dependencies: readonly RepoDependency[]): SyncedRepoSpec[] {
  const specs: SyncedRepoSpec[] = []

  for (const file of files) {
    if (file.category === 'openapi') {
      specs.push({
        name: `${fullName}:${file.path}`.slice(0, 160),
        kind: 'openapi',
        content: file.content.slice(0, 512 * 1024),
      })
    } else if (file.category === 'graphql') {
      specs.push({
        name: `${fullName}:${file.path}`.slice(0, 160),
        kind: 'graphql',
        content: file.content.slice(0, 512 * 1024),
      })
    }
  }

  const routeFiles = files.filter(f => f.category === 'route' || f.category === 'config')
  if (routeFiles.length > 0) {
    const sections: string[] = [`# Read-Only Server Route & Security Handler Context: ${fullName}\n`]
    let total = 0
    for (const f of routeFiles) {
      const chunk = `\n## ${f.path}\n\`\`\`\n${f.content.slice(0, 24 * 1024)}\n\`\`\`\n`
      if (total + chunk.length > 512 * 1024) break
      sections.push(chunk)
      total += chunk.length
    }
    specs.push({
      name: `${fullName}:routes-and-handlers`.slice(0, 160),
      kind: 'routes',
      content: sections.join(''),
    })
  }

  const depSpec = buildDependenciesSpec(fullName, dependencies)
  if (depSpec) specs.push(depSpec)

  return specs
}

function buildClonedRepoSpecs(input: {
  fullName: string
  defaultBranch: string
  commitSha?: string
  mountPath: string
  treeCount: number
  topLevelDirs: readonly string[]
  topLevelFiles: readonly string[]
  manifestPaths: readonly string[]
  schemaFiles: readonly SyncedRepoFile[]
  dependencies: readonly RepoDependency[]
}): SyncedRepoSpec[] {
  const specs: SyncedRepoSpec[] = []

  const inventoryLines = [
    `# Cloned Repository Inventory: ${input.fullName}`,
    '',
    `- Repository: ${input.fullName}`,
    `- Branch: ${input.defaultBranch}${input.commitSha ? ` (${input.commitSha})` : ''}`,
    `- Container Mount Path (read-only): ${input.mountPath}`,
    `- Total Files: ${input.treeCount}`,
    `- Top-Level Directories: ${input.topLevelDirs.length ? input.topLevelDirs.join(', ') : '(none)'}`,
    `- Top-Level Files: ${input.topLevelFiles.length ? input.topLevelFiles.slice(0, 40).join(', ') : '(none)'}`,
    `- Manifests & Lockfiles Scanned (${input.manifestPaths.length}): ${input.manifestPaths.length ? input.manifestPaths.slice(0, 40).join(', ') : '(none)'}`,
    `- Dependencies Extracted: ${input.dependencies.length}`,
    '',
    'Explore this full codebase inside `derive_evidence` using standard bash commands:',
    `- \`find ${input.mountPath} -maxdepth 3\``,
    `- \`grep -rn "pattern" ${input.mountPath}\` or \`rg -n "pattern" ${input.mountPath}\``,
    `- \`sed -n '1,120p' ${input.mountPath}/path/to/file\``,
  ]
  specs.push({
    name: `${input.fullName}:inventory`.slice(0, 160),
    kind: 'notes',
    content: inventoryLines.join('\n'),
  })

  for (const file of input.schemaFiles) {
    if (file.category === 'openapi') {
      specs.push({
        name: `${input.fullName}:${file.path}`.slice(0, 160),
        kind: 'openapi',
        content: file.content.slice(0, 512 * 1024),
      })
    } else if (file.category === 'graphql') {
      specs.push({
        name: `${input.fullName}:${file.path}`.slice(0, 160),
        kind: 'graphql',
        content: file.content.slice(0, 512 * 1024),
      })
    }
  }

  const depSpec = buildDependenciesSpec(input.fullName, input.dependencies)
  if (depSpec) specs.push(depSpec)

  return specs
}

function runGit(
  args: string[],
  env: NodeJS.ProcessEnv,
  secrets: readonly NamedSecret[],
  signal?: AbortSignal,
  timeoutMs = defaultCloneTimeoutMs,
): Promise<{ stdout: string; stderr: string }> {
  signal?.throwIfAborted()
  const deadline = signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs)
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn('git', args, {
      env,
      signal: deadline,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const outChunks: Buffer[] = []
    const errChunks: Buffer[] = []
    let outLen = 0
    let errLen = 0
    const cap = 256 * 1024
    child.stdout.on('data', (chunk: Buffer) => {
      if (outLen < cap) {
        outChunks.push(chunk.subarray(0, cap - outLen))
        outLen += chunk.length
      }
    })
    child.stderr.on('data', (chunk: Buffer) => {
      if (errLen < cap) {
        errChunks.push(chunk.subarray(0, cap - errLen))
        errLen += chunk.length
      }
    })
    child.once('error', err => {
      if (deadline.aborted) {
        rejectPromise(new Error(`git ${args[0] ?? ''} aborted or timed out.`))
      } else {
        rejectPromise(new Error(redact(err.message, secrets)))
      }
    })
    child.once('close', code => {
      const stdout = redact(Buffer.concat(outChunks).toString('utf8'), secrets)
      const stderr = redact(Buffer.concat(errChunks).toString('utf8'), secrets)
      if (code === 0) {
        resolvePromise({ stdout, stderr })
      } else {
        const detail = (stderr || stdout).trim().slice(0, 300)
        rejectPromise(new Error(`git ${args[0] ?? ''} failed (exit ${code}): ${detail}`))
      }
    })
  })
}

function chmodTreeReadable(dirPath: string): void {
  try {
    chmodSync(dirPath, 0o755)
    for (const entry of readdirSync(dirPath, { withFileTypes: true })) {
      const fullPath = join(dirPath, entry.name)
      const st = lstatSync(fullPath)
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) chmodTreeReadable(fullPath)
      else if (st.isFile()) chmodSync(fullPath, 0o644)
    }
  } catch { /* best-effort */ }
}

function stripGitSymlinks(dirPath: string): void {
  let entries
  try {
    entries = readdirSync(dirPath, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    const fullPath = join(dirPath, entry.name)
    try {
      if (lstatSync(fullPath).isSymbolicLink()) {
        rmSync(fullPath, { force: true })
      } else if (entry.isDirectory()) {
        stripGitSymlinks(fullPath)
      }
    } catch { /* best-effort */ }
  }
}

const NEUTRALIZED_GIT_ATTRIBUTES_CONTENT = '* -text -crlf -ident -working-tree-encoding -filter -eol\n'
const MAX_GITATTRIBUTES_BLOB_BYTES = 256 * 1024

/**
 * Write `.git/info/attributes` neutralizing every built-in and custom checkout transform
 * (`text`, `crlf`, `ident`, `working-tree-encoding`, `filter`, `eol`) so repo `.gitattributes`
 * cannot amplify checked-out bytes on disk (R4-H-18).
 */
function writeNeutralizedGitAttributes(gitDir: string): void {
  const infoDir = join(gitDir, 'info')
  try {
    if (existsSync(infoDir)) {
      const st = lstatSync(infoDir)
      if (st.isSymbolicLink() || !st.isDirectory()) {
        rmSync(infoDir, { recursive: true, force: true })
      }
    }
  } catch { /* best-effort */ }
  mkdirSync(infoDir, { recursive: true, mode: 0o755 })
  const attrsPath = join(infoDir, 'attributes')
  try {
    if (existsSync(attrsPath) && lstatSync(attrsPath).isSymbolicLink()) {
      rmSync(attrsPath, { force: true })
    }
  } catch { /* best-effort */ }
  writeFileSync(attrsPath, NEUTRALIZED_GIT_ATTRIBUTES_CONTENT, { mode: 0o644 })
  chmodSync(attrsPath, 0o644)
}

/** Strip credentials/headers/filters from `.git/config`, neutralize hooks & `.git/info/attributes` before mounting. */
function sanitizeGitMetadata(gitDir: string): void {
  stripGitSymlinks(gitDir)
  const configPath = join(gitDir, 'config')
  try {
    if (existsSync(configPath)) {
      const raw = readFileSync(configPath, 'utf8')
      const sections: string[] = []
      let skippingUnsafeSection = false
      for (const line of raw.split('\n')) {
        const section = /^\s*\[([^\]]+)\]\s*$/.exec(line)
        if (section) {
          skippingUnsafeSection = /^(?:credential|filter)(?:\s|$)/i.test(section[1]!)
          if (!skippingUnsafeSection) sections.push(line)
          continue
        }
        if (skippingUnsafeSection) continue
        if (
          /extraheader/i.test(line)
          || /^\s*(?:username|password|token|attributesfile|autocrlf|eol|safecrlf)\s*=/i.test(line)
        ) {
          continue
        }
        sections.push(line.replace(/(https?:\/\/)[^/@\s]+@/gi, '$1'))
      }
      writeFileSync(configPath, sections.join('\n'), { mode: 0o644 })
      chmodSync(configPath, 0o644)
    }
  } catch { /* best-effort: mount remains read-only */ }
  try {
    writeNeutralizedGitAttributes(gitDir)
  } catch { /* best-effort; re-enforced fail-closed before checkout */ }
  const hooksDir = join(gitDir, 'hooks')
  try {
    if (existsSync(hooksDir)) {
      for (const entry of readdirSync(hooksDir, { withFileTypes: true })) {
        if (entry.isFile()) chmodSync(join(hooksDir, entry.name), 0o644)
      }
    }
  } catch { /* best-effort */ }
}

function isSymlinkEscapingRoot(fullPath: string, resolvedRoot: string): boolean {
  try {
    const rawTarget = readlinkSync(fullPath)
    const logicalTarget = resolve(dirname(fullPath), rawTarget)
    if (!(logicalTarget === resolvedRoot || logicalTarget.startsWith(resolvedRoot + sep))) {
      return true
    }
  } catch {
    return true
  }
  try {
    const realTarget = realpathSync(fullPath)
    return !(realTarget === resolvedRoot || realTarget.startsWith(resolvedRoot + sep))
  } catch {
    // Dangling symlink: logicalTarget already checked above; reject dangling relative escapes
    // and treat any unreadable/broken target conservatively as escaping if outside root.
    return false
  }
}

/**
 * Inspect an entire cloned repository tree (including `.git` and dependency dirs):
 * - Unconditionally strips all OS symlinks so read-only mounts and patch tooling never traverse links.
 * - Also inspects git-tracked symlink blobs (index mode 120000 written as text files under `core.symlinks=false`).
 * - When `rejectEscaping` is true (default), throws if any OS or git-tracked symlink targets outside `rootDir`.
 */
export function verifyAndStripRepoSymlinks(
  rootDir: string,
  options: { rejectEscaping?: boolean } = {},
): { removedSymlinks: string[]; escapingSymlinks: string[] } {
  const resolvedRoot = realpathSync(rootDir)
  const removedSymlinks: string[] = []
  const escapingSymlinks: string[] = []
  const escapingSet = new Set<string>()

  const recordEscaping = (relPath: string) => {
    if (!escapingSet.has(relPath)) {
      escapingSet.add(relPath)
      escapingSymlinks.push(relPath)
    }
  }

  const visit = (currentDir: string, depth: number) => {
    if (depth > 64) {
      throw new RepoDepthLimitExceededError(rootDir, depth, 64, currentDir)
    }
    let entries
    try {
      entries = readdirSync(currentDir, { withFileTypes: true })
    } catch {
      return
    }
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name)
      let st
      try {
        st = lstatSync(fullPath)
      } catch {
        continue
      }
      if (st.isSymbolicLink()) {
        const relPath = relative(resolvedRoot, fullPath).split(sep).join('/')
        const escaped = isSymlinkEscapingRoot(fullPath, resolvedRoot)
        rmSync(fullPath, { force: true })
        removedSymlinks.push(relPath)
        if (escaped) recordEscaping(relPath)
        continue
      }
      if (st.isDirectory()) {
        visit(fullPath, depth + 1)
      }
    }
  }

  visit(resolvedRoot, 0)

  // Check git index for mode-120000 symlink entries (materialized as plain text under core.symlinks=false).
  const gitDir = join(resolvedRoot, '.git')
  if (existsSync(gitDir)) {
    try {
      if (!lstatSync(gitDir).isSymbolicLink()) {
        const lsOut = execFileSync(
          'git',
          [
            '-C', resolvedRoot,
            '-c', 'safe.directory=*',
            '-c', 'core.fsmonitor=false',
            '-c', 'core.hooksPath=/dev/null',
            '-c', 'core.symlinks=false',
            '-c', 'protocol.file.allow=never',
            '-c', 'protocol.ext.allow=never',
            'ls-files', '-s', '-z',
          ],
          { encoding: 'utf8', timeout: 5_000, maxBuffer: 4 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] },
        )
        for (const rec of lsOut.split('\0')) {
          if (!rec.startsWith('120000 ')) continue
          const tabIdx = rec.indexOf('\t')
          if (tabIdx < 0) continue
          const relPath = rec.slice(tabIdx + 1)
          if (!relPath || relPath.includes('\0')) continue
          const entryFullPath = resolve(resolvedRoot, relPath)
          if (!entryFullPath.startsWith(resolvedRoot + sep)) {
            recordEscaping(relPath)
            continue
          }
          try {
            const st = lstatSync(entryFullPath)
            if (st.isFile() && st.size <= 4096) {
              const targetSpec = readFileSync(entryFullPath, 'utf8').trim()
              const logicalTarget = resolve(dirname(entryFullPath), targetSpec)
              if (!(logicalTarget === resolvedRoot || logicalTarget.startsWith(resolvedRoot + sep))) {
                rmSync(entryFullPath, { force: true })
                removedSymlinks.push(relPath)
                recordEscaping(relPath)
              }
            }
          } catch {
            // Best-effort inspect of mode-120000 file.
          }
        }
      }
    } catch {
      // Non-git or unreadable index; OS symlink scan above still enforced.
    }
  }

  if (options.rejectEscaping !== false && escapingSymlinks.length > 0) {
    throw new Error(
      `Rejected repository containing symlink escaping checkout root: ${escapingSymlinks.slice(0, 5).join(', ')}`,
    )
  }

  return { removedSymlinks, escapingSymlinks }
}

function walkClonedRepo(
  rootDir: string,
  secrets: readonly NamedSecret[],
  maxFileBytes: number,
  warnings: string[],
): {
  treeCount: number
  topLevelDirs: string[]
  topLevelFiles: string[]
  manifestPaths: string[]
  files: SyncedRepoFile[]
  schemaFiles: SyncedRepoFile[]
  dependencies: RepoDependency[]
} {
  const resolvedRoot = realpathSync(rootDir)
  const topLevelDirs: string[] = []
  const topLevelFiles: string[] = []
  const manifestPaths: string[] = []
  const files: SyncedRepoFile[] = []
  const schemaFiles: SyncedRepoFile[] = []
  const allDependencies: RepoDependency[] = []
  let treeCount = 0

  const visit = (currentDir: string, depth: number) => {
    chmodSync(currentDir, 0o755)
    const entries = readdirSync(currentDir, { withFileTypes: true })
    entries.sort((a, b) => a.name.localeCompare(b.name))

    for (const entry of entries) {
      const fullPath = join(currentDir, entry.name)
      const lstat = lstatSync(fullPath)

      // Strip ALL symlinks unconditionally so mounts and patch tooling never traverse links.
      if (lstat.isSymbolicLink()) {
        const escaped = isSymlinkEscapingRoot(fullPath, resolvedRoot)
        rmSync(fullPath, { force: true })
        warnings.push(
          `${escaped ? 'Removed out-of-tree symlink' : 'Removed in-tree symlink'}: ${relative(rootDir, fullPath).split(sep).join('/')}`,
        )
        continue
      }

      if (lstat.isDirectory()) {
        if (entry.name === '.git') {
          // Preserve bounded history for Stage-3 regression mining; sanitize + make readable.
          sanitizeGitMetadata(fullPath)
          chmodTreeReadable(fullPath)
          continue
        }
        if (depth === 0) topLevelDirs.push(entry.name)
        if (skippedDirNames.has(entry.name)) {
          // Still ensure readable permissions if somehow present in repo, without scanning dependencies inside it
          chmodTreeReadable(fullPath)
          continue
        }
        visit(fullPath, depth + 1)
        continue
      }

      if (!lstat.isFile()) continue
      chmodSync(fullPath, 0o644)
      treeCount += 1
      if (depth === 0) topLevelFiles.push(entry.name)

      const relPath = relative(rootDir, fullPath).split(sep).join('/')
      const lowerBase = entry.name.toLowerCase()
      const isManifest = lowerBase === 'package.json'
      const isLockfile = lockfileNames.has(lowerBase)
      const isOpenApi = /(?:openapi|swagger).*\.(?:json|ya?ml)$/i.test(lowerBase)
      const isGraphql = /\.(?:graphql|gql)$/i.test(lowerBase)

      if (isManifest || isLockfile) {
        manifestPaths.push(relPath)
        if (lstat.size <= defaultMaxLockfileBytes) {
          try {
            const raw = readFileSync(fullPath, 'utf8')
            allDependencies.push(...parseDependenciesFromFile(relPath, raw))
            const truncated = raw.length > maxFileBytes
            files.push({
              path: relPath,
              category: isManifest ? 'manifest' : 'lockfile',
              size: lstat.size,
              truncated,
              content: redact(truncated ? raw.slice(0, maxFileBytes) : raw, secrets),
            })
          } catch (err) {
            warnings.push(`Failed to read ${relPath}: ${redact(err instanceof Error ? err.message : String(err), secrets)}`)
          }
        } else {
          warnings.push(`Skipped oversized lockfile ${relPath} (${lstat.size} bytes).`)
        }
      } else if ((isOpenApi || isGraphql) && schemaFiles.length < 16 && lstat.size <= maxFileBytes * 2) {
        try {
          const raw = readFileSync(fullPath, 'utf8')
          const truncated = raw.length > maxFileBytes
          const item: SyncedRepoFile = {
            path: relPath,
            category: isOpenApi ? 'openapi' : 'graphql',
            size: lstat.size,
            truncated,
            content: redact(truncated ? raw.slice(0, maxFileBytes) : raw, secrets),
          }
          schemaFiles.push(item)
          files.push(item)
        } catch { /* ignore unreadable schema */ }
      }
    }
  }

  visit(rootDir, 0)
  return {
    treeCount,
    topLevelDirs,
    topLevelFiles,
    manifestPaths,
    files,
    schemaFiles,
    dependencies: deduplicateDependencies(allDependencies),
  }
}

/**
 * Mine a bounded, credential-free git history for security-relevant commit diffs.
 * Pure server-side operation; never emits raw diffs or repository contents.
 */
export function readRepoCommitDiffs(
  repoDir: string,
  options: { maxCommits?: number; diffBase?: string; maxDiffBytes?: number } = {},
): RepoCommitDiffMining {
  const gitDir = join(repoDir, '.git')
  if (!existsSync(gitDir)) return { available: false, reason: 'No .git directory in mounted repository.', commitsScanned: 0, commitDiffs: [] }
  const maxCommits = Math.max(1, Math.min(options.maxCommits ?? defaultMaxCommitDiffs, 200))
  const maxDiffBytes = Math.max(16_384, Math.min(options.maxDiffBytes ?? 262_144, 1024 * 1024))
  const baseArgs = [
    '-C', repoDir,
    '-c', 'safe.directory=*',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.symlinks=false',
    '-c', 'protocol.file.allow=never',
    '-c', 'protocol.ext.allow=never',
  ]
  try {
    execFileSync('git', [...baseArgs, 'rev-parse', '--git-dir'], { encoding: 'utf8', timeout: 5_000, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch {
    return { available: false, reason: 'Invalid git repository.', commitsScanned: 0, commitDiffs: [] }
  }
  const safeBase = options.diffBase && /^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$/.test(options.diffBase) ? options.diffBase : undefined
  const range = safeBase ? `${safeBase}..HEAD` : undefined
  let logOut = ''
  try {
    const args = [...baseArgs, 'log', '-n', String(maxCommits), '--no-merges', '--pretty=format:===COMMIT===%H%x09%aI%x09%s', '--name-only']
    if (range) args.push(range)
    logOut = execFileSync('git', args, { encoding: 'utf8', timeout: 10_000, maxBuffer: 2 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] })
  } catch {
    return { available: false, reason: 'git log failed.', commitsScanned: 0, commitDiffs: [] }
  }
  const commits: Array<{ sha: string; subject: string; committedAt?: string; diff: string }> = []
  for (const block of logOut.split('===COMMIT===').slice(1)) {
    const lines = block.trim().split('\n')
    const [sha, committedAt, ...subjectParts] = (lines[0] ?? '').split('\t')
    if (!sha) continue
    commits.push({ sha, subject: subjectParts.join('\t'), ...(committedAt ? { committedAt } : {}), diff: '' })
  }
  for (const commit of commits) {
    try {
      commit.diff = execFileSync('git', [...baseArgs, 'show', '--no-ext-diff', '--unified=3', '--no-color', '--format=', commit.sha], {
        encoding: 'utf8', timeout: 8_000, maxBuffer: maxDiffBytes + 1024, stdio: ['ignore', 'pipe', 'ignore'],
      }).slice(0, maxDiffBytes)
    } catch { commit.diff = '' }
  }
  return {
    available: true,
    commitsScanned: commits.length,
    commitDiffs: mineSecurityRelevantCommitDiffs(commits, { maxSignals: 100, maxLinesPerFile: 12 }),
  }
}

async function checkGithubPreflightRepoSize(input: {
  fullName: string
  pat: string
  apiBase: string
  fetchFn: typeof fetch
  maxRepoDiskBytes: number
  signal?: AbortSignal
}): Promise<void> {
  const reqSignal = input.signal
    ? AbortSignal.any([input.signal, AbortSignal.timeout(10_000)])
    : AbortSignal.timeout(10_000)
  let res: Response
  try {
    res = await input.fetchFn(`${input.apiBase}/repos/${input.fullName}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${input.pat}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'KovoHunter/2 read-only repo connector',
      },
      signal: reqSignal,
    })
  } catch (err) {
    if (input.signal?.aborted) throw err
    return
  }
  if (!res.ok) return
  let meta: { size?: unknown }
  try {
    meta = await res.json() as { size?: unknown }
  } catch {
    return
  }
  if (typeof meta.size === 'number' && Number.isFinite(meta.size) && meta.size > 0) {
    const estimatedBytes = Math.round(meta.size * 1024)
    if (estimatedBytes > input.maxRepoDiskBytes) {
      throw new RepoDiskQuotaExceededError('repo', input.fullName, estimatedBytes, input.maxRepoDiskBytes)
    }
  }
}

interface GitTreeBlobEntry {
  mode: string
  oid: string
  size: number
  relPath: string
}

interface PreCheckoutTreeSummary {
  blobBytes: number
  fileCount: number
  inodeCount: number
  maxDepth: number
  blobs: GitTreeBlobEntry[]
  gitattributesBlobs: GitTreeBlobEntry[]
}

function buildHardenedGitCheckoutPrefix(stagingDir: string): string[] {
  return [
    '-C', stagingDir,
    '-c', 'safe.directory=*',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.symlinks=false',
    '-c', 'core.attributesFile=/dev/null',
    '-c', 'core.autocrlf=false',
    '-c', 'core.eol=lf',
    '-c', 'core.safecrlf=false',
    '-c', 'filter.lfs.smudge=',
    '-c', 'filter.lfs.process=',
    '-c', 'filter.lfs.required=false',
    '-c', 'protocol.file.allow=never',
    '-c', 'protocol.ext.allow=never',
    '-c', 'submodule.recurse=false',
  ]
}

function findAmplifyingGitAttributeToken(content: string): string | null {
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    let idx = 0
    if (line.startsWith('"')) {
      idx = 1
      while (idx < line.length) {
        if (line[idx] === '\\' && idx + 1 < line.length) { idx += 2; continue }
        if (line[idx] === '"') { idx += 1; break }
        idx += 1
      }
    } else {
      while (idx < line.length) {
        if (line[idx] === '\\' && idx + 1 < line.length) { idx += 2; continue }
        if (/\s/.test(line[idx]!)) break
        idx += 1
      }
    }
    const attrPart = line.slice(idx).trim()
    if (!attrPart) continue
    for (const token of attrPart.split(/\s+/)) {
      if (!token || token.startsWith('-') || token.startsWith('!')) continue
      if (/^(?:ident|working-tree-encoding(?:=.*)?)$/i.test(token)) {
        return token
      }
    }
  }
  return null
}

async function inspectGitAttributesBeforeCheckout(input: {
  stagingDir: string
  fullName: string
  gitEnv: NodeJS.ProcessEnv
  secrets: readonly NamedSecret[]
  gitattributesBlobs: readonly GitTreeBlobEntry[]
  signal?: AbortSignal
  timeoutMs: number
}): Promise<void> {
  if (input.gitattributesBlobs.length === 0) return
  const prefix = buildHardenedGitCheckoutPrefix(input.stagingDir)
  for (const entry of input.gitattributesBlobs) {
    input.signal?.throwIfAborted()
    if (entry.size > MAX_GITATTRIBUTES_BLOB_BYTES) {
      const err = new Error(
        `Rejected repository "${input.fullName}": .gitattributes file "${entry.relPath}" exceeds ${MAX_GITATTRIBUTES_BLOB_BYTES} bytes.`,
      ) as Error & { code: string; status: number }
      err.code = 'REPO_UNSAFE_GITATTRIBUTES'
      err.status = 400
      throw err
    }
    const res = await runGit(
      [...prefix, 'cat-file', 'blob', entry.oid],
      input.gitEnv,
      input.secrets,
      input.signal,
      Math.min(input.timeoutMs, 15_000),
    )
    const unsafeToken = findAmplifyingGitAttributeToken(res.stdout)
    if (unsafeToken) {
      const err = new Error(
        `Rejected repository "${input.fullName}": "${entry.relPath}" requests amplifying checkout attribute "${unsafeToken}".`,
      ) as Error & { code: string; status: number }
      err.code = 'REPO_UNSAFE_GITATTRIBUTES'
      err.status = 400
      throw err
    }
  }
}

/**
 * Materialize a `--no-checkout` staging repository via ONE attribute-neutralized, streaming
 * byte-accounted primitive (R4-H-18):
 *   1. Re-writes `.git/info/attributes` neutralizing `* -text -crlf -ident -working-tree-encoding -filter -eol`.
 *   2. Populates `.git/index` via `git read-tree HEAD` (with `-c core.attributesFile=/dev/null -c core.autocrlf=false -c core.eol=lf`)
 *      so downstream symlink/index inspection works identically without running checkout filters.
 *   3. Streams raw object bytes via `git cat-file --batch` directly to disk with hard per-chunk
 *      byte accounting against `maxRepoDiskBytes` and `maxProjectDiskBytes`, aborting immediately
 *      before disk writes can ever exceed quota.
 */
async function materializeGitTreeBounded(input: {
  stagingDir: string
  fullName: string
  gitEnv: NodeJS.ProcessEnv
  secrets: readonly NamedSecret[]
  blobs: readonly GitTreeBlobEntry[]
  maxRepoDiskBytes: number
  maxProjectDiskBytes: number
  existingProjectBytes: number
  baseGitBytes: number
  signal?: AbortSignal
  timeoutMs: number
}): Promise<{ bytesWritten: number; filesWritten: number }> {
  input.signal?.throwIfAborted()
  const gitDirPath = join(input.stagingDir, '.git')
  writeNeutralizedGitAttributes(gitDirPath)

  const prefix = buildHardenedGitCheckoutPrefix(input.stagingDir)
  // Populate `.git/index` from HEAD without touching the working tree so `git ls-files -s` works cleanly.
  await runGit([...prefix, 'read-tree', 'HEAD'], input.gitEnv, input.secrets, input.signal, input.timeoutMs)

  if (input.blobs.length === 0) {
    return { bytesWritten: 0, filesWritten: 0 }
  }

  const resolvedStaging = realpathSync(input.stagingDir)
  const deadline = input.signal
    ? AbortSignal.any([input.signal, AbortSignal.timeout(input.timeoutMs)])
    : AbortSignal.timeout(input.timeoutMs)

  return await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn('git', [...prefix, 'cat-file', '--batch'], {
      env: input.gitEnv,
      signal: deadline,
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    let entryIndex = 0
    let state: 'header' | 'body' | 'trailing_lf' = 'header'
    let headerBuf: Buffer = Buffer.alloc(0)
    let remaining = 0
    let currentFd: number | null = null
    let currentDestPath: string | null = null
    let currentFileMode = 0o644
    let totalBytesWritten = 0
    let abortError: Error | null = null
    const errChunks: Buffer[] = []
    let errLen = 0
    const errCap = 64 * 1024
    const maxHeaderBytes = 4096

    const closeCurrentFd = () => {
      if (currentFd !== null) {
        const fd = currentFd
        currentFd = null
        try { closeSync(fd) } catch { /* ignore */ }
      }
    }

    const failEarly = (err: Error) => {
      if (abortError) return
      abortError = err
      closeCurrentFd()
      try { child.stdin.destroy() } catch { /* ignore */ }
      try { child.stdout.destroy() } catch { /* ignore */ }
      try { child.kill('SIGKILL') } catch { /* ignore */ }
    }

    const checkBudget = (nextBytesWritten: number): boolean => {
      const projectedRepoBytes = input.baseGitBytes + nextBytesWritten
      if (projectedRepoBytes > input.maxRepoDiskBytes) {
        failEarly(new RepoDiskQuotaExceededError('repo', input.fullName, projectedRepoBytes, input.maxRepoDiskBytes))
        return false
      }
      const projectedProjectBytes = input.existingProjectBytes + projectedRepoBytes
      if (projectedProjectBytes > input.maxProjectDiskBytes) {
        failEarly(new RepoDiskQuotaExceededError('project', input.fullName, projectedProjectBytes, input.maxProjectDiskBytes))
        return false
      }
      return true
    }

    const ensureSafeParentDirs = (destPath: string) => {
      const relDir = relative(resolvedStaging, dirname(destPath))
      if (!relDir || relDir === '.') return
      const parts = relDir.split(sep).filter(Boolean)
      let cur = resolvedStaging
      for (const part of parts) {
        cur = join(cur, part)
        if (existsSync(cur)) {
          const st = lstatSync(cur)
          if (st.isSymbolicLink() || !st.isDirectory()) {
            throw new Error(`Unsafe non-directory or symlink component while checking out "${input.fullName}".`)
          }
        } else {
          mkdirSync(cur, { mode: 0o755 })
          chmodSync(cur, 0o755)
        }
      }
    }

    // Feed blob OIDs to `git cat-file --batch` stdin with stream backpressure.
    let feedIndex = 0
    const pumpStdin = () => {
      while (!abortError && feedIndex < input.blobs.length) {
        const line = `${input.blobs[feedIndex]!.oid}\n`
        feedIndex += 1
        if (!child.stdin.write(line)) {
          child.stdin.once('drain', pumpStdin)
          return
        }
      }
      if (!abortError) {
        child.stdin.end()
      }
    }
    child.stdin.on('error', () => { /* child exit/abort handler owns error reporting */ })
    pumpStdin()

    child.stdout.on('data', (chunk: Buffer) => {
      if (abortError) return
      let offset = 0
      while (offset < chunk.length && !abortError) {
        if (state === 'header') {
          const nlIdx = chunk.indexOf(0x0a, offset)
          if (nlIdx < 0) {
            const slice = chunk.subarray(offset)
            if (headerBuf.length + slice.length > maxHeaderBytes) {
              failEarly(new Error(`Malformed git cat-file header while checking out "${input.fullName}".`))
              return
            }
            headerBuf = headerBuf.length > 0 ? Buffer.concat([headerBuf, slice]) : Buffer.from(slice)
            offset = chunk.length
            break
          }
          const lineBuf = headerBuf.length > 0
            ? Buffer.concat([headerBuf, chunk.subarray(offset, nlIdx)])
            : chunk.subarray(offset, nlIdx)
          headerBuf = Buffer.alloc(0)
          offset = nlIdx + 1

          if (entryIndex >= input.blobs.length) {
            failEarly(new Error(`Unexpected extra git cat-file object while checking out "${input.fullName}".`))
            return
          }
          const expected = input.blobs[entryIndex]!
          const headerLine = lineBuf.toString('utf8').trim()
          const parts = headerLine.split(' ')
          if (parts.length !== 3 || parts[1] !== 'blob' || parts[0] !== expected.oid) {
            failEarly(new Error(`Unexpected git cat-file header "${headerLine.slice(0, 120)}" for "${input.fullName}".`))
            return
          }
          const actualSize = Number(parts[2])
          if (!Number.isFinite(actualSize) || actualSize < 0) {
            failEarly(new Error(`Invalid git blob byte count "${parts[2]}" for "${input.fullName}".`))
            return
          }
          if (!checkBudget(totalBytesWritten + actualSize)) return

          const destPath = resolve(resolvedStaging, expected.relPath)
          if (!destPath.startsWith(resolvedStaging + sep)) {
            failEarly(new Error(`Checkout path escapes staging directory in "${input.fullName}": ${expected.relPath}`))
            return
          }
          try {
            ensureSafeParentDirs(destPath)
            currentFileMode = expected.mode === '100755' ? 0o755 : 0o644
            currentDestPath = destPath
            const openFlags = fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | (fsConstants.O_NOFOLLOW ?? 0)
            currentFd = openSync(destPath, openFlags, currentFileMode)
          } catch (err) {
            failEarly(err instanceof Error ? err : new Error(String(err)))
            return
          }

          if (actualSize === 0) {
            closeCurrentFd()
            try { chmodSync(destPath, currentFileMode) } catch { /* best-effort */ }
            currentDestPath = null
            remaining = 0
            state = 'trailing_lf'
          } else {
            remaining = actualSize
            state = 'body'
          }
          continue
        }

        if (state === 'body') {
          const take = Math.min(remaining, chunk.length - offset)
          if (!checkBudget(totalBytesWritten + take)) return
          try {
            let written = 0
            while (written < take) {
              const n = writeSync(currentFd!, chunk, offset + written, take - written)
              if (n <= 0) throw new Error(`Short write while checking out "${input.fullName}".`)
              written += n
            }
          } catch (err) {
            failEarly(err instanceof Error ? err : new Error(String(err)))
            return
          }
          totalBytesWritten += take
          remaining -= take
          offset += take
          if (remaining === 0) {
            closeCurrentFd()
            if (currentDestPath) {
              try { chmodSync(currentDestPath, currentFileMode) } catch { /* best-effort */ }
              currentDestPath = null
            }
            state = 'trailing_lf'
          }
          continue
        }

        // state === 'trailing_lf'
        if (chunk[offset] !== 0x0a) {
          failEarly(new Error(`Malformed git cat-file framing while checking out "${input.fullName}".`))
          return
        }
        offset += 1
        entryIndex += 1
        state = 'header'
      }
    })

    child.stderr.on('data', (chunk: Buffer) => {
      if (errLen < errCap) {
        errChunks.push(chunk.subarray(0, errCap - errLen))
        errLen += chunk.length
      }
    })

    child.once('error', err => {
      closeCurrentFd()
      if (abortError) {
        rejectPromise(abortError)
        return
      }
      if (deadline.aborted) {
        rejectPromise(new Error(`git cat-file checkout aborted or timed out for "${input.fullName}".`))
      } else {
        rejectPromise(new Error(redact(err.message, input.secrets)))
      }
    })

    child.once('close', code => {
      closeCurrentFd()
      if (abortError) {
        rejectPromise(abortError)
        return
      }
      if (code !== 0) {
        const stderr = redact(Buffer.concat(errChunks).toString('utf8'), input.secrets).trim().slice(0, 300)
        rejectPromise(new Error(`git cat-file checkout failed for "${input.fullName}" (exit ${code}): ${stderr}`))
        return
      }
      if (entryIndex !== input.blobs.length || state !== 'header' || headerBuf.length > 0) {
        rejectPromise(new Error(`Truncated git cat-file checkout stream for "${input.fullName}" (${entryIndex}/${input.blobs.length} files).`))
        return
      }
      resolvePromise({ bytesWritten: totalBytesWritten, filesWritten: entryIndex })
    })
  })
}

/**
 * Stream `git ls-tree -r -t -l -z HEAD` on a `--no-checkout` staging repository and abort
 * immediately if uncompressed blob bytes, file/inode count, or directory depth exceed limits.
 * No working-tree files exist on disk until this check completes cleanly.
 */
function inspectGitTreeBeforeCheckout(input: {
  stagingDir: string
  fullName: string
  gitEnv: NodeJS.ProcessEnv
  secrets: readonly NamedSecret[]
  maxRepoDiskBytes: number
  maxProjectDiskBytes: number
  existingProjectBytes: number
  baseGitBytes: number
  maxRepoFiles: number
  maxRepoDepth: number
  signal?: AbortSignal
  timeoutMs: number
}): Promise<PreCheckoutTreeSummary> {
  input.signal?.throwIfAborted()
  const deadline = input.signal
    ? AbortSignal.any([input.signal, AbortSignal.timeout(input.timeoutMs)])
    : AbortSignal.timeout(input.timeoutMs)
  const maxInodes = Math.max(input.maxRepoFiles, input.maxRepoFiles * 2)
  const maxSingleRecordBytes = 256 * 1024

  return new Promise((resolvePromise, rejectPromise) => {
    const args = [
      '-C', input.stagingDir,
      '-c', 'safe.directory=*',
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'core.symlinks=false',
      '-c', 'core.attributesFile=/dev/null',
      '-c', 'core.autocrlf=false',
      '-c', 'core.eol=lf',
      '-c', 'protocol.file.allow=never',
      '-c', 'protocol.ext.allow=never',
      'ls-tree', '-r', '-t', '-l', '-z', 'HEAD',
    ]
    const child = spawn('git', args, {
      env: input.gitEnv,
      signal: deadline,
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    let blobBytes = 0
    let fileCount = 0
    let inodeCount = 0
    let maxDepth = 0
    const blobs: GitTreeBlobEntry[] = []
    const gitattributesBlobs: GitTreeBlobEntry[] = []
    let remainder: Buffer = Buffer.alloc(0)
    let abortError: Error | null = null
    const errChunks: Buffer[] = []
    let errLen = 0
    const errCap = 64 * 1024

    const failEarly = (err: Error) => {
      if (abortError) return
      abortError = err
      try { child.stdout.destroy() } catch { /* ignore */ }
      try { child.kill('SIGKILL') } catch { /* ignore */ }
    }

    const processRecord = (recBuf: Buffer) => {
      if (abortError || recBuf.length === 0) return
      const rec = recBuf.toString('utf8')
      const tabIdx = rec.indexOf('\t')
      if (tabIdx < 0) {
        failEarly(new Error(`Malformed git ls-tree record while inspecting "${input.fullName}".`))
        return
      }
      const header = rec.slice(0, tabIdx).trim()
      const relPath = rec.slice(tabIdx + 1)
      const parts = header.split(/\s+/)
      if (parts.length < 4) {
        failEarly(new Error(`Malformed git ls-tree header while inspecting "${input.fullName}".`))
        return
      }
      const mode = parts[0]!
      const type = parts[1]!
      const oid = parts[2]!
      const sizeToken = parts[3]!
      const segments = relPath.split('/').filter(Boolean)
      if (
        segments.length === 0
        || relPath.startsWith('/')
        || segments.some(seg => seg === '.' || seg === '..' || seg.toLowerCase() === '.git')
      ) {
        failEarly(new Error(`Unsafe git tree path "${relPath}" in "${input.fullName}".`))
        return
      }
      const dirDepth = type === 'tree'
        ? segments.length
        : Math.max(0, segments.length - 1)
      if (dirDepth > maxDepth) maxDepth = dirDepth
      if (dirDepth > input.maxRepoDepth) {
        failEarly(new RepoDepthLimitExceededError(input.fullName, dirDepth, input.maxRepoDepth, relPath))
        return
      }

      inodeCount += 1
      if (inodeCount > maxInodes) {
        failEarly(new RepoFileLimitExceededError('repo', input.fullName, inodeCount, maxInodes))
        return
      }

      if (type === 'tree') return

      fileCount += 1
      if (fileCount > input.maxRepoFiles) {
        failEarly(new RepoFileLimitExceededError('repo', input.fullName, fileCount, input.maxRepoFiles))
        return
      }

      if (type === 'blob') {
        const size = Number(sizeToken)
        if (!Number.isFinite(size) || size < 0) {
          failEarly(new Error(`Invalid blob size "${sizeToken}" in git ls-tree for "${input.fullName}".`))
          return
        }
        blobBytes += size
        const projectedRepoBytes = input.baseGitBytes + blobBytes
        if (projectedRepoBytes > input.maxRepoDiskBytes) {
          failEarly(new RepoDiskQuotaExceededError('repo', input.fullName, projectedRepoBytes, input.maxRepoDiskBytes))
          return
        }
        const projectedProjectBytes = input.existingProjectBytes + projectedRepoBytes
        if (projectedProjectBytes > input.maxProjectDiskBytes) {
          failEarly(new RepoDiskQuotaExceededError('project', input.fullName, projectedProjectBytes, input.maxProjectDiskBytes))
          return
        }
        const blobEntry: GitTreeBlobEntry = { mode, oid, size, relPath }
        blobs.push(blobEntry)
        if (segments[segments.length - 1]?.toLowerCase() === '.gitattributes') {
          gitattributesBlobs.push(blobEntry)
        }
      }
    }

    child.stdout.on('data', (chunk: Buffer) => {
      if (abortError) return
      const combined = remainder.length > 0 ? Buffer.concat([remainder, chunk]) : chunk
      let start = 0
      while (start < combined.length && !abortError) {
        const nulIdx = combined.indexOf(0, start)
        if (nulIdx < 0) break
        processRecord(combined.subarray(start, nulIdx))
        start = nulIdx + 1
      }
      if (abortError) {
        remainder = Buffer.alloc(0)
        return
      }
      const leftover = combined.subarray(start)
      if (leftover.length > maxSingleRecordBytes) {
        failEarly(new Error(`Oversized git ls-tree entry while inspecting "${input.fullName}".`))
        remainder = Buffer.alloc(0)
        return
      }
      remainder = Buffer.from(leftover)
    })

    child.stderr.on('data', (chunk: Buffer) => {
      if (errLen < errCap) {
        errChunks.push(chunk.subarray(0, errCap - errLen))
        errLen += chunk.length
      }
    })

    child.once('error', err => {
      if (abortError) {
        rejectPromise(abortError)
        return
      }
      if (deadline.aborted) {
        rejectPromise(new Error(`git ls-tree aborted or timed out for "${input.fullName}".`))
      } else {
        rejectPromise(new Error(redact(err.message, input.secrets)))
      }
    })

    child.once('close', code => {
      if (!abortError && remainder.length > 0) {
        processRecord(remainder)
      }
      if (abortError) {
        rejectPromise(abortError)
        return
      }
      if (code === 0) {
        resolvePromise({ blobBytes, fileCount, inodeCount, maxDepth, blobs, gitattributesBlobs })
        return
      }
      const stderr = redact(Buffer.concat(errChunks).toString('utf8'), input.secrets).trim().slice(0, 300)
      rejectPromise(new Error(`git ls-tree failed for "${input.fullName}" (exit ${code}): ${stderr}`))
    })
  })
}

export async function cloneGithubRepos(
  repoFullNames: readonly string[],
  targetRootDir: string,
  signal?: AbortSignal,
  options: GithubSyncOptions = {},
): Promise<SyncedGithubRepo[]> {
  signal?.throwIfAborted()
  if (!targetRootDir || /[\0,\r\n]/.test(targetRootDir)) {
    throw new Error('Invalid repository clone root directory.')
  }

  const gitBase = (options.gitBaseUrl ?? 'https://github.com').replace(/\/+$/, '')
  const gitBaseUrl = new URL(gitBase)
  if (!['https:', 'http:', 'file:'].includes(gitBaseUrl.protocol)) {
    throw new Error(`Unsupported Git base protocol: ${gitBaseUrl.protocol}`)
  }
  const allowLocalFileProtocol = gitBaseUrl.protocol === 'file:'
    && (options.allowLocalFileProtocol === true || (options.allowLocalFileProtocol !== false && isTestRuntime()))
  if (gitBaseUrl.protocol === 'file:' && !allowLocalFileProtocol) {
    throw new Error('Git file:// protocol is disabled outside explicit test mode.')
  }

  const maxFileBytes = Math.max(1024, Math.min(options.maxFileBytes ?? defaultMaxFileBytes, 2 * 1024 * 1024))
  const cloneTimeoutMs = Math.max(5_000, Math.min(options.cloneTimeoutMs ?? defaultCloneTimeoutMs, 600_000))
  const historyDepth = Math.max(1, Math.min(Math.floor(options.historyDepth ?? defaultHistoryDepth), 100))
  const stripGitMetadata = options.stripGitMetadata === true
  const maxCommitDiffs = Math.max(0, Math.min(Math.floor(options.maxCommitDiffs ?? defaultMaxCommitDiffs), 200))
  const maxRepoDiskBytes = Math.max(
    1024,
    Math.floor(options.maxRepoDiskBytes ?? parsePositiveEnvBytes('KOVO_MAX_REPO_DISK_BYTES') ?? DEFAULT_MAX_REPO_DISK_BYTES),
  )
  const maxProjectDiskBytes = Math.max(
    1024,
    Math.floor(options.maxProjectDiskBytes ?? parsePositiveEnvBytes('KOVO_MAX_PROJECT_DISK_BYTES') ?? DEFAULT_MAX_PROJECT_DISK_BYTES),
  )
  const maxRepoFiles = Math.max(
    1,
    Math.floor(options.maxRepoFiles ?? parsePositiveEnvBytes('KOVO_MAX_REPO_FILES') ?? DEFAULT_MAX_REPO_FILES),
  )
  const maxProjectFiles = Math.max(DEFAULT_MAX_PROJECT_FILES, maxRepoFiles)
  const maxRepoDepth = Math.max(
    0,
    Math.floor(options.maxRepoDepth ?? parsePositiveEnvBytes('KOVO_MAX_REPO_DEPTH') ?? DEFAULT_MAX_REPO_DEPTH),
  )

  mkdirSync(targetRootDir, { recursive: true, mode: 0o755 })
  chmodSync(targetRootDir, 0o755)
  const resolvedRoot = realpathSync(targetRootDir)

  // Sweep orphaned `.tmp-*` / `.old-*` directories left behind by crashed syncs.
  cleanupOrphanedRepoDirs(resolvedRoot)

  const shouldPreflightSize =
    gitBaseUrl.protocol !== 'file:'
    && options.preflightSizeCheck !== false
    && (Boolean(options.apiBaseUrl) || gitBaseUrl.hostname === 'github.com')
  const apiBase = (options.apiBaseUrl ?? DEFAULT_GITHUB_API_BASE_URL).replace(/\/+$/, '')
  const fetchFn = options.fetchImpl ?? fetch

  const results: SyncedGithubRepo[] = []
  let firstError: unknown = null

  for (const rawName of repoFullNames) {
    signal?.throwIfAborted()
    const { fullName, owner, repo } = parseRepoFullName(rawName)

    const runSingleRepo = async (): Promise<SyncedGithubRepo> => {
      return await withRepoOperationLock(
        resolvedRoot,
        fullName,
        async () => {
          signal?.throwIfAborted()

          // Resolve fresh credentials per repo so long multi-repo batches pick up rotated tokens.
          const cred = await resolveFreshGithubCredential({
            dataDir: options.dataDir,
            patPath: options.patPath,
            githubBaseUrl: options.githubBaseUrl,
            fetchImpl: options.fetchImpl,
            signal,
          })
          const pat = cred.accessToken
          const basicAuth = Buffer.from(`x-access-token:${pat}`, 'utf8').toString('base64')
          const secrets: NamedSecret[] = [
            { value: pat, placeholder: '[redacted]' },
            { value: basicAuth, placeholder: '[redacted]' },
            ...(cred.refreshToken ? [{ value: cred.refreshToken, placeholder: '[redacted]' }] : []),
          ]

          if (shouldPreflightSize) {
            await checkGithubPreflightRepoSize({
              fullName,
              pat,
              apiBase,
              fetchFn,
              maxRepoDiskBytes,
              signal,
            })
          }

          const gitEnv: NodeJS.ProcessEnv = {
            PATH: process.env.PATH,
            HOME: process.env.HOME,
            GIT_TERMINAL_PROMPT: '0',
            GIT_ASKPASS: 'echo',
            GIT_CONFIG_NOSYSTEM: '1',
            GIT_CONFIG_GLOBAL: '/dev/null',
          }
          if (gitBaseUrl.protocol === 'https:' || gitBaseUrl.protocol === 'http:') {
            gitEnv.GIT_CONFIG_COUNT = '2'
            gitEnv.GIT_CONFIG_KEY_0 = `http.${gitBaseUrl.origin}/.extraHeader`
            gitEnv.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${basicAuth}`
            gitEnv.GIT_CONFIG_KEY_1 = 'core.symlinks'
            gitEnv.GIT_CONFIG_VALUE_1 = 'false'
          } else {
            gitEnv.GIT_CONFIG_COUNT = '1'
            gitEnv.GIT_CONFIG_KEY_0 = 'core.symlinks'
            gitEnv.GIT_CONFIG_VALUE_0 = 'false'
          }

          const ownerDir = join(resolvedRoot, owner)
          const finalDir = join(ownerDir, repo)
          if (!resolve(finalDir).startsWith(resolvedRoot + sep)) {
            throw new Error(`Resolved clone path escapes root directory: ${fullName}`)
          }

          mkdirSync(ownerDir, { recursive: true, mode: 0o755 })
          chmodSync(ownerDir, 0o755)

          const stagingDir = join(ownerDir, `.tmp-${repo}-${randomUUID()}`)
          const backupDir = join(ownerDir, `.old-${repo}-${randomUUID()}`)
          const resolvedStaging = resolve(stagingDir)
          const resolvedBackup = resolve(backupDir)
          activeStagingDirs.add(resolvedStaging)
          activeStagingDirs.add(resolvedBackup)

          const repoUrl = `${gitBase}/${owner}/${repo}.git`
          const warnings: string[] = []

          try {
            // 1. Clone with `--no-checkout` so zero working-tree files hit disk before quota inspection.
            const cloneArgs = buildHardenedGitCloneArgs({
              repoUrl,
              stagingDir,
              depth: historyDepth,
              allowLocalFileProtocol,
              noCheckout: true,
            })
            await runGit(cloneArgs, gitEnv, secrets, signal, cloneTimeoutMs)

            let defaultBranch = 'main'
            let commitSha: string | undefined
            let hasHead = false
            const revParsePrefix = [
              '-C', stagingDir,
              '-c', 'core.hooksPath=/dev/null',
              '-c', 'core.fsmonitor=false',
              '-c', 'core.symlinks=false',
              '-c', 'protocol.file.allow=never',
              '-c', 'protocol.ext.allow=never',
              '-c', 'submodule.recurse=false',
            ]
            try {
              const br = await runGit([...revParsePrefix, 'rev-parse', '--abbrev-ref', 'HEAD'], gitEnv, secrets, signal, 10_000)
              if (br.stdout.trim() && br.stdout.trim() !== 'HEAD') defaultBranch = br.stdout.trim()
            } catch { /* fallback to main */ }
            try {
              const sha = await runGit([...revParsePrefix, 'rev-parse', '--short', 'HEAD'], gitEnv, secrets, signal, 10_000)
              if (sha.stdout.trim()) {
                commitSha = sha.stdout.trim()
                hasHead = true
              }
            } catch { /* empty repo / unborn HEAD */ }

            // 2. Sanitize `.git` metadata BEFORE inspecting or checking out anything.
            const gitDirPath = join(stagingDir, '.git')
            sanitizeGitMetadata(gitDirPath)

            // 3. Measure existing project disk usage and `.git` store asynchronously before checkout.
            const existingOtherBytesPre = await measureProjectDiskBytes(resolvedRoot, {
              excludeRepo: fullName,
              maxDepth: maxRepoDepth,
              maxFiles: maxProjectFiles,
              signal,
            })
            const gitDirUsage = await measureDirectoryUsage(gitDirPath, {
              maxDepth: Math.max(maxRepoDepth, 16),
              maxFiles: Math.max(maxRepoFiles, 1000),
              maxBytes: stripGitMetadata ? Math.max(maxRepoDiskBytes, 1024 * 1024) : maxRepoDiskBytes,
              scope: 'repo',
              targetLabel: fullName,
              signal,
            })
            const baseGitBytes = stripGitMetadata ? 0 : gitDirUsage.bytes
            if (baseGitBytes > maxRepoDiskBytes) {
              throw new RepoDiskQuotaExceededError('repo', fullName, baseGitBytes, maxRepoDiskBytes)
            }
            if (existingOtherBytesPre + baseGitBytes > maxProjectDiskBytes) {
              throw new RepoDiskQuotaExceededError('project', fullName, existingOtherBytesPre + baseGitBytes, maxProjectDiskBytes)
            }

            // 4. Stream `git ls-tree -r -t -l -z HEAD` to enforce uncompressed blob bytes, file/inode cap,
            //    and max directory depth, and inspect `.gitattributes` BEFORE writing any working-tree file to disk.
            const treeSummary: PreCheckoutTreeSummary = hasHead
              ? await inspectGitTreeBeforeCheckout({
                  stagingDir,
                  fullName,
                  gitEnv,
                  secrets,
                  maxRepoDiskBytes,
                  maxProjectDiskBytes,
                  existingProjectBytes: existingOtherBytesPre,
                  baseGitBytes,
                  maxRepoFiles,
                  maxRepoDepth,
                  signal,
                  timeoutMs: cloneTimeoutMs,
                })
              : { blobBytes: 0, fileCount: 0, inodeCount: 0, maxDepth: 0, blobs: [], gitattributesBlobs: [] }

            if (hasHead && treeSummary.gitattributesBlobs.length > 0) {
              await inspectGitAttributesBeforeCheckout({
                stagingDir,
                fullName,
                gitEnv,
                secrets,
                gitattributesBlobs: treeSummary.gitattributesBlobs,
                signal,
                timeoutMs: cloneTimeoutMs,
              })
            }

            options.onBeforeCheckout?.({
              stagingDir,
              blobBytes: treeSummary.blobBytes,
              fileCount: treeSummary.fileCount,
              inodeCount: treeSummary.inodeCount,
              maxDepth: treeSummary.maxDepth,
            })

            // 5. Materialize working tree via ONE attribute-neutralized, streaming byte-accounted primitive
            //    after pre-checkout tree quota, `.gitattributes`, file/inode, and depth checks pass.
            if (hasHead) {
              await materializeGitTreeBounded({
                stagingDir,
                fullName,
                gitEnv,
                secrets,
                blobs: treeSummary.blobs,
                maxRepoDiskBytes,
                maxProjectDiskBytes,
                existingProjectBytes: existingOtherBytesPre,
                baseGitBytes,
                signal,
                timeoutMs: cloneTimeoutMs,
              })
            }

            // Reject any OS or git-tracked symlink escaping the checkout root, and strip all symlinks.
            const symlinkCheck = verifyAndStripRepoSymlinks(stagingDir, { rejectEscaping: true })
            for (const removedLink of symlinkCheck.removedSymlinks) {
              warnings.push(`Removed symlink: ${removedLink}`)
            }

            // Walk full tree: enforce permissions for uid 10001:10001 and extract dependencies/schemas.
            const walked = walkClonedRepo(stagingDir, secrets, maxFileBytes, warnings)

            // Mine security-relevant diffs from the bounded history before any optional cleanup.
            const mined = maxCommitDiffs > 0
              ? readRepoCommitDiffs(stagingDir, { maxCommits: maxCommitDiffs })
              : { available: false, commitsScanned: 0, commitDiffs: [] as CommitDiffSignal[] }
            if (stripGitMetadata) {
              rmSync(gitDirPath, { recursive: true, force: true })
            }

            // Defense-in-depth async post-checkout enforcement (depth, file/inode cap, per-repo & per-project bytes).
            const postCheckoutMaxFiles = stripGitMetadata
              ? maxRepoFiles
              : maxRepoFiles + Math.min(gitDirUsage.fileCount, 1000)
            const stagedUsage = await measureDirectoryUsage(stagingDir, {
              maxDepth: maxRepoDepth,
              maxFiles: postCheckoutMaxFiles,
              maxBytes: maxRepoDiskBytes,
              scope: 'repo',
              targetLabel: fullName,
              signal,
            })
            if (stagedUsage.bytes > maxRepoDiskBytes) {
              throw new RepoDiskQuotaExceededError('repo', fullName, stagedUsage.bytes, maxRepoDiskBytes)
            }
            const existingOtherBytes = await measureProjectDiskBytes(resolvedRoot, {
              excludeRepo: fullName,
              maxDepth: maxRepoDepth,
              maxFiles: maxProjectFiles,
              signal,
            })
            if (existingOtherBytes + stagedUsage.bytes > maxProjectDiskBytes) {
              throw new RepoDiskQuotaExceededError('project', fullName, existingOtherBytes + stagedUsage.bytes, maxProjectDiskBytes)
            }

            // Atomically swap staged directory into final destination
            let movedOld = false
            try {
              if (existsSync(finalDir)) {
                renameSync(finalDir, backupDir)
                movedOld = true
              }
              renameSync(stagingDir, finalDir)
              if (movedOld) {
                rmSync(backupDir, { recursive: true, force: true })
              }
            } catch (swapErr) {
              if (movedOld && !existsSync(finalDir) && existsSync(backupDir)) {
                try { renameSync(backupDir, finalDir) } catch { /* ignore */ }
              }
              throw swapErr
            }

            const mountPath = `/repos/${owner}/${repo}`
            const specs = buildClonedRepoSpecs({
              fullName,
              defaultBranch,
              commitSha,
              mountPath,
              treeCount: walked.treeCount,
              topLevelDirs: walked.topLevelDirs,
              topLevelFiles: walked.topLevelFiles,
              manifestPaths: walked.manifestPaths,
              schemaFiles: walked.schemaFiles,
              dependencies: walked.dependencies,
            })

            return {
              fullName,
              defaultBranch,
              private: true,
              description: null,
              language: null,
              treeCount: walked.treeCount,
              files: walked.files,
              dependencies: walked.dependencies,
              specs,
              warnings,
              mountPath,
              localPath: finalDir,
              commitSha,
              topLevelDirs: walked.topLevelDirs,
              gitHistory: {
                depth: historyDepth,
                commitsScanned: mined.commitsScanned,
                commitDiffs: mined.commitDiffs,
                metadataPreserved: !stripGitMetadata,
              },
            }
          } finally {
            try { rmSync(stagingDir, { recursive: true, force: true }) } catch { /* best-effort */ }
            try { rmSync(backupDir, { recursive: true, force: true }) } catch { /* best-effort */ }
            activeStagingDirs.delete(resolvedStaging)
            activeStagingDirs.delete(resolvedBackup)
          }
        },
        { signal },
      )
    }

    try {
      results.push(await runSingleRepo())
    } catch (err) {
      if (!options.continueOnError || repoFullNames.length <= 1) {
        throw err
      }
      if (!firstError) firstError = err
      options.onRepoError?.(fullName, err instanceof Error ? err : new Error(String(err)))
    }
  }

  if (results.length === 0 && firstError) {
    throw firstError
  }

  return results
}

export interface RepoWorkspaceManagerOptions {
  maxRepoDiskBytes?: number
  maxProjectDiskBytes?: number
  maxRepoFiles?: number
  maxRepoDepth?: number
  shallowDepth?: number
  /** @deprecated No-op: worker containers mount immutable per-run snapshots, so active runs never block re-sync or unlink. */
  activeRunChecker?: (projectId: string) => readonly string[] | Promise<readonly string[]>
}

/**
 * Coordinates repository workspace lifecycle under `repos/<projectId>/<owner>/<repo>`:
 * per-repo operation locks, orphan `.tmp-*`/`.old-*` GC, shallow hardened clones,
 * and per-repo / per-project disk quotas.
 */
export class RepoWorkspaceManager {
  readonly maxRepoDiskBytes: number
  readonly maxProjectDiskBytes: number
  readonly maxRepoFiles: number
  readonly maxRepoDepth: number
  readonly shallowDepth: number

  constructor(options: RepoWorkspaceManagerOptions = {}) {
    this.maxRepoDiskBytes = options.maxRepoDiskBytes ?? DEFAULT_MAX_REPO_DISK_BYTES
    this.maxProjectDiskBytes = options.maxProjectDiskBytes ?? DEFAULT_MAX_PROJECT_DISK_BYTES
    this.maxRepoFiles = options.maxRepoFiles ?? DEFAULT_MAX_REPO_FILES
    this.maxRepoDepth = options.maxRepoDepth ?? DEFAULT_MAX_REPO_DEPTH
    this.shallowDepth = Math.max(1, Math.min(Math.floor(options.shallowDepth ?? DEFAULT_CLONE_DEPTH), 100))
  }

  async withLock<T>(
    dataDir: string,
    projectId: string,
    repoSlug: string,
    fn: () => Promise<T> | T,
    signal?: AbortSignal,
  ): Promise<T> {
    return await withRepoOperationLock(projectReposDir(dataDir, projectId), repoSlug, fn, { signal })
  }

  /**
   * @deprecated No-op: live Docker workers always mount immutable per-run snapshots via
   * `prepareReposMount`, so re-syncing or unlinking a repo never corrupts live worker mounts.
   */
  async assertNoActiveRuns(_projectId: string, _action: 're-sync' | 'unlink', _repoSlug: string): Promise<void> {
    // Intentionally a no-op: per-run immutable repo snapshots decouple host checkout mutations from live runs.
  }

  cleanupOrphans(dataDir: string, projectId: string): OrphanCleanupResult {
    return cleanupOrphanedRepoDirs(projectReposDir(dataDir, projectId))
  }

  listRepos(dataDir: string, projectId: string): ProjectMountedRepo[] {
    return listProjectMountedRepos(dataDir, projectId)
  }

  async measureProjectBytes(dataDir: string, projectId: string): Promise<number> {
    return await measureProjectDiskBytes(projectReposDir(dataDir, projectId), {
      maxDepth: this.maxRepoDepth,
      maxFiles: Math.max(DEFAULT_MAX_PROJECT_FILES, this.maxRepoFiles),
    })
  }

  async syncRepos(
    dataDir: string,
    projectId: string,
    repoFullNames: readonly string[],
    signal?: AbortSignal,
    options: GithubSyncOptions = {},
  ): Promise<SyncedGithubRepo[]> {
    const cloneDir = projectReposDir(dataDir, projectId)
    return await cloneGithubRepos(repoFullNames, cloneDir, signal, {
      dataDir,
      historyDepth: this.shallowDepth,
      maxRepoDiskBytes: this.maxRepoDiskBytes,
      maxProjectDiskBytes: this.maxProjectDiskBytes,
      maxRepoFiles: this.maxRepoFiles,
      maxRepoDepth: this.maxRepoDepth,
      ...options,
    })
  }

  async unlinkRepo(
    dataDir: string,
    projectId: string,
    repoSlug: string,
    options: UnlinkMountedRepoOptions & { signal?: AbortSignal } = {},
  ): Promise<UnlinkMountedRepoResult> {
    const { fullName } = parseRepoFullName(repoSlug)
    return await this.withLock(
      dataDir,
      projectId,
      fullName,
      () => unlinkProjectMountedRepoUnlocked(dataDir, projectId, fullName, options),
      options.signal,
    )
  }
}

let sharedRepoWorkspaceManager: RepoWorkspaceManager | null = null

export function getSharedRepoWorkspaceManager(): RepoWorkspaceManager {
  if (!sharedRepoWorkspaceManager) {
    sharedRepoWorkspaceManager = new RepoWorkspaceManager()
  }
  return sharedRepoWorkspaceManager
}

export async function syncGithubRepos(
  repoFullNames: readonly string[],
  signal?: AbortSignal,
  options: GithubSyncOptions = {},
): Promise<SyncedGithubRepo[]> {
  if (options.cloneDir) {
    return cloneGithubRepos(repoFullNames, options.cloneDir, signal, options)
  }

  signal?.throwIfAborted()
  const apiBase = (options.apiBaseUrl ?? DEFAULT_GITHUB_API_BASE_URL).replace(/\/+$/, '')
  const fetchFn = options.fetchImpl ?? fetch
  const maxFilesPerRepo = Math.max(1, Math.min(options.maxFilesPerRepo ?? defaultMaxFilesPerRepo, 80))
  const maxFileBytes = Math.max(1024, Math.min(options.maxFileBytes ?? defaultMaxFileBytes, 2 * 1024 * 1024))
  const maxRepoBytes = Math.max(4096, Math.min(options.maxRepoBytes ?? defaultMaxRepoBytes, 8 * 1024 * 1024))

  const results: SyncedGithubRepo[] = []

  for (const rawName of repoFullNames) {
    signal?.throwIfAborted()
    const { fullName } = parseRepoFullName(rawName)

    const cred = await resolveFreshGithubCredential({
      dataDir: options.dataDir,
      patPath: options.patPath,
      githubBaseUrl: options.githubBaseUrl,
      fetchImpl: options.fetchImpl,
      signal,
    })
    const pat = cred.accessToken
    const secrets: NamedSecret[] = [
      { value: pat, placeholder: '[redacted]' },
      ...(cred.refreshToken ? [{ value: cred.refreshToken, placeholder: '[redacted]' }] : []),
    ]
    const headers: Record<string, string> = {
      Authorization: `Bearer ${pat}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'KovoHunter/2 read-only repo connector',
    }

    const githubGetJson = async <T>(path: string): Promise<T> => {
      const reqSignal = signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000)
      const res = await fetchFn(`${apiBase}${path}`, { method: 'GET', headers, signal: reqSignal })
      if (!res.ok) {
        const body = redact(await res.text().catch(() => ''), secrets).slice(0, 240)
        throw new Error(`GitHub API GET ${path} failed (${res.status}): ${body}`)
      }
      return await res.json() as T
    }

    const warnings: string[] = []
    const repoMeta = await githubGetJson<{
      default_branch?: string
      private?: boolean
      description?: string | null
      language?: string | null
    }>(`/repos/${fullName}`)

    const defaultBranch = repoMeta.default_branch || 'main'
    const treeResp = await githubGetJson<{
      truncated?: boolean
      tree?: Array<{ path?: string; type?: string; sha?: string; size?: number }>
    }>(`/repos/${fullName}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`)

    if (treeResp.truncated) {
      warnings.push('GitHub git tree response was truncated due to repository size.')
    }

    const candidates: Array<{ path: string; sha: string; size: number; category: SyncedRepoFile['category']; priority: number }> = []
    for (const entry of treeResp.tree ?? []) {
      if (entry.type !== 'blob' || !entry.path || !entry.sha) continue
      const classified = classifyRepoPath(entry.path)
      if (!classified) continue
      candidates.push({
        path: entry.path,
        sha: entry.sha,
        size: entry.size ?? 0,
        category: classified.category,
        priority: classified.priority,
      })
    }

    // Prioritize manifests/lockfiles/schemas first, then shallower route/middleware files.
    candidates.sort((a, b) => {
      if (b.priority !== a.priority) return b.priority - a.priority
      const depthDiff = a.path.split('/').length - b.path.split('/').length
      if (depthDiff !== 0) return depthDiff
      return a.size - b.size
    })

    const files: SyncedRepoFile[] = []
    const allDependencies: RepoDependency[] = []
    let repoBytes = 0

    for (const candidate of candidates.slice(0, maxFilesPerRepo)) {
      signal?.throwIfAborted()
      if (repoBytes >= maxRepoBytes) {
        warnings.push(`Reached bounded repository byte cap (${maxRepoBytes} bytes).`)
        break
      }
      if (candidate.size > maxFileBytes * 4 && candidate.category !== 'lockfile') {
        warnings.push(`Skipped oversized file ${candidate.path} (${candidate.size} bytes).`)
        continue
      }

      try {
        const blob = await githubGetJson<{ content?: string; encoding?: string }>(`/repos/${fullName}/git/blobs/${encodeURIComponent(candidate.sha)}`)
        if (!blob.content) continue
        const decoded = blob.encoding === 'base64'
          ? Buffer.from(blob.content.replace(/\s+/g, ''), 'base64').toString('utf8')
          : blob.content

        // Extract dependencies before truncation/redaction of lockfile preview (lockfiles don't contain PATs, and we never return raw secrets).
        if (candidate.category === 'manifest' || candidate.category === 'lockfile') {
          allDependencies.push(...parseDependenciesFromFile(candidate.path, decoded))
        }

        const remaining = Math.max(0, maxRepoBytes - repoBytes)
        const limit = Math.min(maxFileBytes, remaining)
        const truncated = decoded.length > limit
        const safeContent = redact(truncated ? decoded.slice(0, limit) : decoded, secrets)
        repoBytes += Buffer.byteLength(safeContent)
        files.push({
          path: candidate.path,
          category: candidate.category,
          size: candidate.size,
          truncated,
          content: safeContent,
        })
      } catch (err) {
        warnings.push(`Failed to read ${candidate.path}: ${redact(err instanceof Error ? err.message : String(err), secrets)}`)
      }
    }

    const dependencies = deduplicateDependencies(allDependencies)

    results.push({
      fullName,
      defaultBranch,
      private: Boolean(repoMeta.private),
      description: repoMeta.description ? redact(repoMeta.description, secrets).slice(0, 300) : null,
      language: repoMeta.language ?? null,
      treeCount: treeResp.tree?.length ?? 0,
      files,
      dependencies,
      specs: buildRepoSpecs(fullName, files, dependencies),
      warnings,
    })
  }

  return results
}
