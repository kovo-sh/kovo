/**
 * Single Phase A StaticWorkspaceSnapshot (Architecture Wave 2 Proposal B1).
 *
 * Performs ONE bounded, permission-safe, symlink-safe filesystem walk of `reposDir`,
 * excluding dependency/build directories, binary files, and secret/credential files,
 * then builds `ProgramGraph` once and exposes an immutable snapshot shared across
 * `phase0-recon`, `program-graph`, `invariant-synthesizer`, and `semantic-audit`.
 */
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
} from 'node:fs'
import { basename, extname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { extractProgramGraph, type ProgramGraph } from './program-graph.ts'
import { extractProgramGraphInWorker } from './untrusted-compute-pool.ts'

// ============================================================================
// Bounds & Exclusion Rules
// ============================================================================

export const DEFAULT_SNAPSHOT_MAX_FILES = 2500
export const DEFAULT_SNAPSHOT_MAX_FILE_BYTES = 256 * 1024
export const DEFAULT_SNAPSHOT_MAX_TOTAL_BYTES = 24 * 1024 * 1024

export const SNAPSHOT_SKIP_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  '.next',
  '.nuxt',
  'dist',
  'build',
  'out',
  'coverage',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
  'target',
  '.gradle',
  '.idea',
  '.cache',
  '.turbo',
  'credentials',
  '.credentials',
  '.secrets',
])

export const SNAPSHOT_GRAPH_SOURCE_EXTS: ReadonlySet<string> = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.java', '.kt', '.go', '.rb',
])

export const SNAPSHOT_STATIC_ROUTE_EXTS: ReadonlySet<string> = new Set([
  ...SNAPSHOT_GRAPH_SOURCE_EXTS,
  '.graphql', '.gql',
])

export const SNAPSHOT_SEMANTIC_SOURCE_EXTS: ReadonlySet<string> = new Set([
  ...SNAPSHOT_GRAPH_SOURCE_EXTS,
  '.php', '.json',
])

const BINARY_EXTENSIONS: ReadonlySet<string> = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.tiff', '.svgz',
  '.pdf', '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
  '.wasm', '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
  '.db', '.sqlite', '.sqlite3',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.webm', '.wav', '.flac', '.ogg',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.class', '.jar', '.war', '.pyc', '.pyo', '.o', '.a', '.lib', '.node',
])

const SECRET_EXTENSIONS: ReadonlySet<string> = new Set([
  '.key', '.pem', '.pat', '.salt', '.p12', '.pfx', '.jks', '.keystore',
])

const SECRET_EXACT_BASENAMES: ReadonlySet<string> = new Set([
  '.env',
  '.envrc',
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.pgpass',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'htpasswd',
  '.htpasswd',
  'secrets.json',
  'secrets.yml',
  'secrets.yaml',
])

const SECRET_CREDENTIAL_FILE_RE = /(?:^|[._-])credentials(?:$|\.(?:json|ya?ml|toml|ini|cfg|conf|txt|xml|properties|env|bak)$)|\.(?:credentials|secret|secrets)$/i
const SECRET_DIR_SEGMENT_RE = /^(?:\.?credentials|\.secrets)$/i

const MANIFEST_BASENAMES: ReadonlySet<string> = new Set([
  'package.json',
  'requirements.txt',
  'pyproject.toml',
  'pipfile',
  'go.mod',
  'pom.xml',
  'build.gradle',
  'build.gradle.kts',
  'gemfile',
])

const COMPOSE_FILE_RE = /^(?:docker-)?compose(?:[._-][^/]*)?\.ya?ml$/i
const DOCKERFILE_RE = /^dockerfile(?:\.[^/]*)?$/i
const INGRESS_FILE_RE = /^ingress[^/]*\.ya?ml$/i
const SAFE_REPO_SEGMENT_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/
const NO_FOLLOW = (fsConstants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0

// ============================================================================
// Public Types
// ============================================================================

export interface StaticWorkspaceWalkStats {
  readonly walkCount: 1
  readonly filesScanned: number
  readonly bytesRead: number
}

export interface StaticWorkspaceManifest {
  readonly name: string
  readonly content: string
}

export interface StaticWorkspaceFileContent {
  readonly path: string
  readonly content: string
}

export interface StaticWorkspaceSnapshot {
  readonly reposDir: string
  readonly rootReal: string
  /** Sorted POSIX relative paths of non-excluded regular files scanned during the single walk. */
  readonly files: readonly string[]
  /** Immutable, size-bounded UTF-8 source cache keyed by POSIX relative path (never includes secrets/binaries). */
  readonly sourceByPath: ReadonlyMap<string, string>
  /** Pre-computed cross-framework ProgramGraph built once from snapshot source files. */
  readonly programGraph: ProgramGraph
  /** Mounted repo roots (`owner/repo`) inferred during the single walk without extra `readdir` calls. */
  readonly mountedRepos: readonly string[]
  /** Dependency manifests collected during the single walk. */
  readonly manifests: readonly StaticWorkspaceManifest[]
  /** Dockerfiles collected during the single walk. */
  readonly dockerfiles: readonly StaticWorkspaceFileContent[]
  /** First docker-compose file content collected during the single walk, if any. */
  readonly compose?: string
  /** First Kubernetes Ingress YAML collected during the single walk, if any. */
  readonly ingress?: string
  readonly createdAtMs: number
  readonly walkStats: StaticWorkspaceWalkStats
}

export interface BuildStaticWorkspaceSnapshotOptions {
  /** Max regular files visited during the walk (default 2500). */
  maxFiles?: number
  /** Max individual file size in bytes (default 256 KiB). */
  maxFileBytes?: number
  /** Max cumulative bytes stored in `sourceByPath` (default 24 MiB). */
  maxTotalBytes?: number
  /** Optional explicit repo identifier label forwarded to `extractProgramGraph`. */
  repo?: string
  /** Optional explicit mounted repo list (skips inferring from walk depth). */
  mountedRepos?: readonly string[]
  /** Optional timeout for worker-isolated ProgramGraph extraction. */
  workerTimeoutMs?: number
  /** Optional cancellation signal for worker-isolated ProgramGraph extraction. */
  signal?: AbortSignal
}

// ============================================================================
// Predicates & Safe File Helpers
// ============================================================================

/**
 * Returns true if a relative path or filename denotes a secret or credential file
 * that must never be read into `sourceByPath` (`.env*` except `.env.example`,
 * `*.key`, `*.pem`, `*.pat`, `*.salt`, and credential files/dirs).
 */
export function isSecretWorkspacePath(filePath: string): boolean {
  const normalized = filePath.replaceAll('\\', '/')
  const segments = normalized.split('/').filter(Boolean)
  if (segments.length === 0) return false

  // Check directory segments for credential/secret directories.
  for (let i = 0; i < segments.length - 1; i += 1) {
    if (SECRET_DIR_SEGMENT_RE.test(segments[i]!)) return true
  }

  const base = segments[segments.length - 1]!.toLowerCase()
  if (base === '.env.example') return false
  if (base.startsWith('.env.')) return true
  if (SECRET_EXACT_BASENAMES.has(base)) return true

  const ext = extname(base).toLowerCase()
  if (SECRET_EXTENSIONS.has(ext)) return true
  if (SECRET_CREDENTIAL_FILE_RE.test(base)) return true

  return false
}

export function isBinaryWorkspaceFilename(name: string): boolean {
  return BINARY_EXTENSIONS.has(extname(name).toLowerCase())
}

export function isManifestWorkspaceFilename(name: string): boolean {
  const base = name.toLowerCase()
  return MANIFEST_BASENAMES.has(base) || /^requirements[-.].*\.txt$/.test(base)
}

function isRealPathUnder(rootReal: string, candidate: string): boolean {
  try {
    const real = realpathSync(candidate)
    const rel = relative(rootReal, real)
    return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel))
  } catch {
    return false
  }
}

/**
 * Read a regular, non-symlink file safely using `O_NOFOLLOW` + `fstatSync` so symlinks,
 * permission errors, oversized files, and binary files (NUL bytes) are rejected cleanly.
 */
function readSafeUtf8RegularFile(fullPath: string, maxFileBytes: number): { content: string; bytes: number } | null {
  let fd: number | undefined
  try {
    fd = openSync(fullPath, fsConstants.O_RDONLY | NO_FOLLOW)
    const st = fstatSync(fd)
    if (!st.isFile() || st.size > maxFileBytes) return null
    const raw = readFileSync(fd)
    if (raw.byteLength > maxFileBytes) return null
    if (raw.includes(0)) return null
    return { content: raw.toString('utf8'), bytes: raw.byteLength }
  } catch {
    return null
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd) } catch { /* already closed */ }
    }
  }
}

function createImmutableMap<K, V>(entries: Iterable<readonly [K, V]>): ReadonlyMap<K, V> {
  const map = new Map<K, V>()
  for (const [k, v] of entries) map.set(k, v)
  const reject = () => {
    throw new TypeError('StaticWorkspaceSnapshot.sourceByPath is immutable')
  }
  Object.defineProperties(map, {
    set: { value: reject, enumerable: false, configurable: false, writable: false },
    delete: { value: reject, enumerable: false, configurable: false, writable: false },
    clear: { value: reject, enumerable: false, configurable: false, writable: false },
  })
  return Object.freeze(map)
}

function shouldReadIntoSourceCache(name: string, ext: string): boolean {
  const lower = name.toLowerCase()
  if (SNAPSHOT_STATIC_ROUTE_EXTS.has(ext) || SNAPSHOT_SEMANTIC_SOURCE_EXTS.has(ext)) return true
  if (isManifestWorkspaceFilename(name)) return true
  if (COMPOSE_FILE_RE.test(name) || DOCKERFILE_RE.test(name) || INGRESS_FILE_RE.test(name)) return true
  if (ext === '.yaml' || ext === '.yml' || ext === '.toml' || ext === '.tf' || ext === '.hcl' || ext === '.ini' || ext === '.conf') return true
  if (lower === '.env.example') return true
  return false
}

// ============================================================================
// Snapshot Builder & Accessors
// ============================================================================

interface CollectedSnapshotInputs {
  empty?: StaticWorkspaceSnapshot
  rootReal?: string
  files?: readonly string[]
  sourceByPath?: ReadonlyMap<string, string>
  graphSourceFiles?: Array<{ path: string; content: string }>
  mountedRepos?: readonly string[]
  manifests?: readonly StaticWorkspaceManifest[]
  dockerfiles?: readonly StaticWorkspaceFileContent[]
  compose?: string
  ingress?: string
  createdAtMs?: number
  walkStats?: StaticWorkspaceWalkStats
  repoLabel?: string
}

function collectWorkspaceSnapshotInputs(
  reposDir: string,
  options: BuildStaticWorkspaceSnapshotOptions = {},
): CollectedSnapshotInputs {
  const createdAtMs = Date.now()
  const maxFiles = Math.max(1, Math.min(options.maxFiles ?? DEFAULT_SNAPSHOT_MAX_FILES, 20_000))
  const maxFileBytes = Math.max(1024, Math.min(options.maxFileBytes ?? DEFAULT_SNAPSHOT_MAX_FILE_BYTES, 4 * 1024 * 1024))
  const maxTotalBytes = Math.max(maxFileBytes, Math.min(options.maxTotalBytes ?? DEFAULT_SNAPSHOT_MAX_TOTAL_BYTES, 128 * 1024 * 1024))

  const emptySnapshot = (rootReal: string): StaticWorkspaceSnapshot => {
    const emptyGraph = extractProgramGraph({ files: [], repo: options.repo })
    return Object.freeze({
      reposDir,
      rootReal,
      files: Object.freeze([]),
      sourceByPath: createImmutableMap<string, string>([]),
      programGraph: emptyGraph,
      mountedRepos: Object.freeze(options.mountedRepos ? [...options.mountedRepos] : []),
      manifests: Object.freeze([]),
      dockerfiles: Object.freeze([]),
      createdAtMs,
      walkStats: Object.freeze({ walkCount: 1 as const, filesScanned: 0, bytesRead: 0 }),
    })
  }

  if (!reposDir || /[\0\r\n]/.test(reposDir) || !existsSync(reposDir)) {
    return { empty: emptySnapshot('') }
  }

  let rootReal: string
  try {
    rootReal = realpathSync(reposDir)
    const rootSt = lstatSync(rootReal)
    if (!rootSt.isDirectory()) return { empty: emptySnapshot(rootReal) }
  } catch {
    return { empty: emptySnapshot('') }
  }

  const files: string[] = []
  const sourceEntries: Array<[string, string]> = []
  const graphSourceFiles: Array<{ path: string; content: string }> = []
  const manifests: StaticWorkspaceManifest[] = []
  const dockerfiles: StaticWorkspaceFileContent[] = []
  const inferredMountedRepos = new Set<string>()
  let compose: string | undefined
  let ingress: string | undefined
  let filesScanned = 0
  let bytesRead = 0

  const stack: Array<{ dir: string; depth: number; seg1?: string }> = [{ dir: rootReal, depth: 0 }]

  while (stack.length > 0 && filesScanned < maxFiles) {
    const current = stack.pop()!
    let entries: string[]
    try {
      entries = readdirSync(current.dir).sort()
    } catch {
      continue
    }

    // Push subdirectories in reverse sorted order so stack pop visits lexicographically.
    const subdirs: Array<{ dir: string; depth: number; seg1?: string }> = []

    for (const name of entries) {
      if (filesScanned >= maxFiles) break
      if (SNAPSHOT_SKIP_DIRS.has(name) || name === '.git') continue

      const full = join(current.dir, name)
      let st
      try {
        st = lstatSync(full)
      } catch {
        continue
      }

      // Never follow or read through symlinks.
      if (st.isSymbolicLink()) continue

      if (st.isDirectory()) {
        if (SECRET_DIR_SEGMENT_RE.test(name)) continue
        if (!isRealPathUnder(rootReal, full)) continue
        const nextDepth = current.depth + 1
        if (nextDepth === 1) {
          const validSeg1 = !name.startsWith('.') && SAFE_REPO_SEGMENT_RE.test(name) ? name : undefined
          subdirs.push({ dir: full, depth: nextDepth, seg1: validSeg1 })
        } else {
          if (nextDepth === 2 && current.seg1 && !name.startsWith('.') && SAFE_REPO_SEGMENT_RE.test(name)) {
            inferredMountedRepos.add(`${current.seg1}/${name}`)
          }
          subdirs.push({ dir: full, depth: nextDepth, seg1: current.seg1 })
        }
        continue
      }

      if (!st.isFile()) continue

      const rel = relative(rootReal, full).split(sep).join('/')
      if (isSecretWorkspacePath(rel)) continue
      if (isBinaryWorkspaceFilename(name)) continue
      if (st.size > maxFileBytes) continue

      filesScanned += 1

      const ext = extname(name).toLowerCase()
      if (!shouldReadIntoSourceCache(name, ext)) {
        files.push(rel)
        continue
      }

      if (bytesRead + st.size > maxTotalBytes) {
        files.push(rel)
        continue
      }

      const read = readSafeUtf8RegularFile(full, maxFileBytes)
      if (read === null) continue
      if (bytesRead + read.bytes > maxTotalBytes) {
        files.push(rel)
        continue
      }

      files.push(rel)
      bytesRead += read.bytes
      sourceEntries.push([rel, read.content])

      if (SNAPSHOT_GRAPH_SOURCE_EXTS.has(ext)) {
        graphSourceFiles.push({ path: rel, content: read.content })
      }
      if (isManifestWorkspaceFilename(name) && manifests.length < 120) {
        manifests.push(Object.freeze({ name: rel, content: read.content }))
      }
      if (DOCKERFILE_RE.test(name) && dockerfiles.length < 40) {
        dockerfiles.push(Object.freeze({ path: rel, content: read.content }))
      }
      if (COMPOSE_FILE_RE.test(name) && compose === undefined) {
        compose = read.content
      }
      if (
        ingress === undefined
        && (INGRESS_FILE_RE.test(name) || ((ext === '.yaml' || ext === '.yml') && read.content.slice(0, 4000).includes('kind: Ingress')))
      ) {
        ingress = read.content
      }
    }

    for (let i = subdirs.length - 1; i >= 0; i -= 1) {
      stack.push(subdirs[i]!)
    }
  }

  files.sort()
  sourceEntries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  graphSourceFiles.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))

  const mountedRepos = options.mountedRepos
    ? [...options.mountedRepos].sort()
    : [...inferredMountedRepos].sort()

  const repoLabel = options.repo ?? (mountedRepos.join(',') || undefined)

  return {
    rootReal,
    files: Object.freeze(files),
    sourceByPath: createImmutableMap(sourceEntries),
    graphSourceFiles,
    mountedRepos: Object.freeze(mountedRepos),
    manifests: Object.freeze(manifests),
    dockerfiles: Object.freeze(dockerfiles),
    ...(compose !== undefined ? { compose } : {}),
    ...(ingress !== undefined ? { ingress } : {}),
    createdAtMs,
    walkStats: Object.freeze({
      walkCount: 1 as const,
      filesScanned,
      bytesRead,
    }),
    repoLabel,
  }
}

function freezeSnapshot(reposDir: string, collected: CollectedSnapshotInputs, programGraph: ProgramGraph): StaticWorkspaceSnapshot {
  return Object.freeze({
    reposDir,
    rootReal: collected.rootReal!,
    files: collected.files!,
    sourceByPath: collected.sourceByPath!,
    programGraph,
    mountedRepos: collected.mountedRepos!,
    manifests: collected.manifests!,
    dockerfiles: collected.dockerfiles!,
    ...(collected.compose !== undefined ? { compose: collected.compose } : {}),
    ...(collected.ingress !== undefined ? { ingress: collected.ingress } : {}),
    createdAtMs: collected.createdAtMs!,
    walkStats: collected.walkStats!,
  })
}

function matchesExistingSnapshot(reposDir: string, existing?: StaticWorkspaceSnapshot | null): existing is StaticWorkspaceSnapshot {
  if (!existing) return false
  if (existing.reposDir === reposDir) return true
  if (reposDir && existing.rootReal) {
    if (resolve(reposDir) === existing.rootReal || resolve(reposDir) === resolve(existing.reposDir)) {
      return true
    }
    try {
      if (realpathSync(reposDir) === existing.rootReal) return true
    } catch {
      // Directory may have been removed or unresolvable; fall through to rebuild if needed.
    }
  }
  return false
}

/**
 * Perform ONE bounded, permission-safe walk of `reposDir`, cache bounded UTF-8 text
 * sources (excluding secrets & binaries), and build `ProgramGraph` once.
 */
export function buildStaticWorkspaceSnapshot(
  reposDir: string,
  options: BuildStaticWorkspaceSnapshotOptions = {},
): StaticWorkspaceSnapshot {
  const collected = collectWorkspaceSnapshotInputs(reposDir, options)
  if (collected.empty) return collected.empty
  const programGraph = extractProgramGraph({ files: collected.graphSourceFiles, repo: collected.repoLabel })
  return freezeSnapshot(reposDir, collected, programGraph)
}

/**
 * Async variant of `buildStaticWorkspaceSnapshot` that offloads `extractProgramGraph`
 * onto `UntrustedComputePool` so untrusted source parsing never stalls the main event loop.
 */
export async function buildStaticWorkspaceSnapshotInWorker(
  reposDir: string,
  options: BuildStaticWorkspaceSnapshotOptions = {},
): Promise<StaticWorkspaceSnapshot> {
  const collected = collectWorkspaceSnapshotInputs(reposDir, options)
  if (collected.empty) return collected.empty
  const files = collected.graphSourceFiles ?? []
  const programGraph = files.length === 0
    ? extractProgramGraph({ files: [], repo: collected.repoLabel })
    : await extractProgramGraphInWorker(
        { files, repo: collected.repoLabel },
        { timeoutMs: options.workerTimeoutMs, signal: options.signal },
      )
  return freezeSnapshot(reposDir, collected, programGraph)
}

/**
 * Reuse an existing `StaticWorkspaceSnapshot` when it already matches `reposDir`
 * (zero filesystem walks), otherwise build a fresh snapshot once.
 */
export function getOrBuildStaticWorkspaceSnapshot(
  reposDir: string,
  existing?: StaticWorkspaceSnapshot | null,
  options?: BuildStaticWorkspaceSnapshotOptions,
): StaticWorkspaceSnapshot {
  if (matchesExistingSnapshot(reposDir, existing)) return existing
  return buildStaticWorkspaceSnapshot(reposDir, options)
}

/**
 * Async variant of `getOrBuildStaticWorkspaceSnapshot` offloading `ProgramGraph` extraction
 * onto `UntrustedComputePool`.
 */
export async function getOrBuildStaticWorkspaceSnapshotInWorker(
  reposDir: string,
  existing?: StaticWorkspaceSnapshot | null,
  options?: BuildStaticWorkspaceSnapshotOptions,
): Promise<StaticWorkspaceSnapshot> {
  if (matchesExistingSnapshot(reposDir, existing)) return existing
  return buildStaticWorkspaceSnapshotInWorker(reposDir, options)
}

/**
 * Extract cached `{ path, content }` source file records from a `StaticWorkspaceSnapshot`
 * without touching disk. Defaults to ProgramGraph source extensions.
 */
export function snapshotSourceFiles(
  snapshot: StaticWorkspaceSnapshot,
  options: {
    extensions?: ReadonlySet<string>
    repoPrefix?: string
  } = {},
): Array<{ path: string; content: string }> {
  const exts = options.extensions ?? SNAPSHOT_GRAPH_SOURCE_EXTS
  const prefix = options.repoPrefix?.replace(/^\/+|\/+$/g, '')
  const matched: Array<{ path: string; content: string }> = []
  const fallbackAll: Array<{ path: string; content: string }> = []

  for (const [relPath, content] of snapshot.sourceByPath.entries()) {
    const ext = extname(relPath).toLowerCase()
    if (!exts.has(ext)) continue
    if (prefix) {
      if (relPath === prefix || relPath.startsWith(`${prefix}/`)) {
        matched.push({ path: relPath.slice(prefix.length + 1) || relPath, content })
      } else {
        fallbackAll.push({ path: relPath, content })
      }
    } else {
      matched.push({ path: relPath, content })
    }
  }

  if (!prefix || matched.length > 0) return matched

  // Single-repo root layout (reposDir itself is the repo directory, e.g. `/tmp/my-app/src/...`).
  const rootBase = snapshot.rootReal ? basename(snapshot.rootReal) : ''
  const isDirectRoot =
    (rootBase && (prefix === rootBase || prefix.endsWith(`/${rootBase}`)))
    || (!prefix.includes('/') && snapshot.mountedRepos.length === 0)
  return isDirectRoot ? fallbackAll : []
}
