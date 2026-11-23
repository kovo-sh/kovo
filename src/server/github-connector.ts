import { execFileSync, spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  accessSync,
  chmodSync,
  constants,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { join, relative, resolve, sep } from 'node:path'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import { mineSecurityRelevantCommitDiffs, type CommitDiffSignal } from './program-graph.ts'

export const DEFAULT_GITHUB_PAT_PATH = join(homedir(), '.config', 'guardian-fixtures', 'github.pat')

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
  patPath?: string
  apiBaseUrl?: string
  gitBaseUrl?: string
  cloneDir?: string
  fetchImpl?: typeof fetch
  maxFilesPerRepo?: number
  maxFileBytes?: number
  maxRepoBytes?: number
  cloneTimeoutMs?: number
  /** Bounded clone history depth (default 100). `.git` is preserved unless explicitly stripped. */
  historyDepth?: number
  /** Mine security-relevant diffs, then remove `.git` from the mounted checkout. */
  stripGitMetadata?: boolean
  /** Maximum commits inspected for diffs during sync (default 20). */
  maxCommitDiffs?: number
}

const repoFullNamePattern = /^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/
const safeSegmentPattern = /^[a-zA-Z0-9_.-]{1,128}$/
const defaultMaxFilesPerRepo = 40
const defaultMaxFileBytes = 512 * 1024
const defaultMaxRepoBytes = 2 * 1024 * 1024
const defaultMaxLockfileBytes = 8 * 1024 * 1024
const defaultCloneTimeoutMs = 120_000
const defaultHistoryDepth = 100
const defaultMaxCommitDiffs = 20

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

function readGithubPat(patPath = DEFAULT_GITHUB_PAT_PATH): string {
  const stat = statSync(patPath)
  if (!stat.isFile() || stat.size === 0) {
    throw new Error('GitHub PAT file is missing or empty.')
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error('GitHub PAT file must have owner-only 0600 permissions.')
  }
  accessSync(patPath, constants.R_OK)
  const pat = readFileSync(patPath, 'utf8').trim()
  if (!pat || pat.length < 10) {
    throw new Error('GitHub PAT file does not contain a valid token.')
  }
  return pat
}

export function hasGithubPat(patPath = DEFAULT_GITHUB_PAT_PATH): boolean {
  try {
    readGithubPat(patPath)
    return true
  } catch {
    return false
  }
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

      // Never allow symlinks escaping the clone root; strip all symlinks for safety.
      if (lstat.isSymbolicLink()) {
        let escaped = true
        try {
          const target = realpathSync(fullPath)
          escaped = !(target === resolvedRoot || target.startsWith(resolvedRoot + sep))
        } catch {
          escaped = true
        }
        if (escaped) {
          rmSync(fullPath, { force: true })
          warnings.push(`Removed out-of-tree symlink: ${relative(rootDir, fullPath).split(sep).join('/')}`)
        }
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

/** Strip credentials/headers from `.git/config` and neutralize hooks before mounting. */
function sanitizeGitMetadata(gitDir: string): void {
  stripGitSymlinks(gitDir)
  const configPath = join(gitDir, 'config')
  try {
    if (!existsSync(configPath)) return
    const raw = readFileSync(configPath, 'utf8')
    const sections: string[] = []
    let skippingCredentialSection = false
    for (const line of raw.split('\n')) {
      const section = /^\s*\[([^\]]+)\]\s*$/.exec(line)
      if (section) {
        skippingCredentialSection = /^credential(?:\s|$)/i.test(section[1])
        if (!skippingCredentialSection) sections.push(line)
        continue
      }
      if (skippingCredentialSection) continue
      if (/extraheader/i.test(line) || /^\s*(?:username|password|token)\s*=/i.test(line)) continue
      sections.push(line.replace(/(https?:\/\/)[^/@\s]+@/gi, '$1'))
    }
    writeFileSync(configPath, sections.join('\n'), { mode: 0o644 })
    chmodSync(configPath, 0o644)
  } catch { /* best-effort: mount remains read-only */ }
  const hooksDir = join(gitDir, 'hooks')
  try {
    if (existsSync(hooksDir)) {
      for (const entry of readdirSync(hooksDir, { withFileTypes: true })) {
        if (entry.isFile()) chmodSync(join(hooksDir, entry.name), 0o644)
      }
    }
  } catch { /* best-effort */ }
}

export interface RepoCommitDiffMining {
  available: boolean
  reason?: string
  commitsScanned: number
  commitDiffs: CommitDiffSignal[]
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
  const baseArgs = ['-C', repoDir, '-c', 'safe.directory=*', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null']
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
      commit.diff = execFileSync('git', [...baseArgs, 'show', '--unified=3', '--no-color', '--format=', commit.sha], {
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

  const pat = readGithubPat(options.patPath)
  const basicAuth = Buffer.from(`x-access-token:${pat}`, 'utf8').toString('base64')
  const secrets: NamedSecret[] = [
    { value: pat, placeholder: '[redacted]' },
    { value: basicAuth, placeholder: '[redacted]' },
  ]
  const gitBase = (options.gitBaseUrl ?? 'https://github.com').replace(/\/+$/, '')
  const gitBaseUrl = new URL(gitBase)
  if (!['https:', 'http:', 'file:'].includes(gitBaseUrl.protocol)) {
    throw new Error(`Unsupported Git base protocol: ${gitBaseUrl.protocol}`)
  }
  const maxFileBytes = Math.max(1024, Math.min(options.maxFileBytes ?? defaultMaxFileBytes, 2 * 1024 * 1024))
  const cloneTimeoutMs = Math.max(5_000, Math.min(options.cloneTimeoutMs ?? defaultCloneTimeoutMs, 600_000))
  const historyDepth = Math.max(1, Math.min(Math.floor(options.historyDepth ?? defaultHistoryDepth), 1000))
  const stripGitMetadata = options.stripGitMetadata === true
  const maxCommitDiffs = Math.max(0, Math.min(Math.floor(options.maxCommitDiffs ?? defaultMaxCommitDiffs), 200))

  mkdirSync(targetRootDir, { recursive: true, mode: 0o755 })
  chmodSync(targetRootDir, 0o755)
  const resolvedRoot = realpathSync(targetRootDir)

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

  const results: SyncedGithubRepo[] = []

  for (const rawName of repoFullNames) {
    signal?.throwIfAborted()
    const { fullName, owner, repo } = parseRepoFullName(rawName)
    const ownerDir = join(resolvedRoot, owner)
    const finalDir = join(ownerDir, repo)
    if (!resolve(finalDir).startsWith(resolvedRoot + sep)) {
      throw new Error(`Resolved clone path escapes root directory: ${fullName}`)
    }

    mkdirSync(ownerDir, { recursive: true, mode: 0o755 })
    chmodSync(ownerDir, 0o755)

    const stagingDir = join(ownerDir, `.tmp-${repo}-${randomUUID()}`)
    const backupDir = join(ownerDir, `.old-${repo}-${randomUUID()}`)
    const repoUrl = `${gitBase}/${owner}/${repo}.git`
    const warnings: string[] = []

    try {
      await runGit(
        ['clone', '--depth', String(historyDepth), '--single-branch', '--no-tags', '--', repoUrl, stagingDir],
        gitEnv,
        secrets,
        signal,
        cloneTimeoutMs,
      )

      let defaultBranch = 'main'
      let commitSha: string | undefined
      try {
        const br = await runGit(['-C', stagingDir, 'rev-parse', '--abbrev-ref', 'HEAD'], gitEnv, secrets, signal, 10_000)
        if (br.stdout.trim() && br.stdout.trim() !== 'HEAD') defaultBranch = br.stdout.trim()
      } catch { /* fallback to main */ }
      try {
        const sha = await runGit(['-C', stagingDir, 'rev-parse', '--short', 'HEAD'], gitEnv, secrets, signal, 10_000)
        if (sha.stdout.trim()) commitSha = sha.stdout.trim()
      } catch { /* optional */ }

      // Sanitize retained git metadata (strip credentials, symlinks, executable hooks).
      sanitizeGitMetadata(join(stagingDir, '.git'))

      // Walk full tree: strip escaping symlinks, set a+rX permissions for uid 10001:10001, extract all dependencies
      const walked = walkClonedRepo(stagingDir, secrets, maxFileBytes, warnings)

      // Mine security-relevant diffs from the bounded history before any optional cleanup.
      const mined = maxCommitDiffs > 0
        ? readRepoCommitDiffs(stagingDir, { maxCommits: maxCommitDiffs })
        : { available: false, commitsScanned: 0, commitDiffs: [] as CommitDiffSignal[] }
      if (stripGitMetadata) {
        rmSync(join(stagingDir, '.git'), { recursive: true, force: true })
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

      results.push({
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
      })
    } finally {
      rmSync(stagingDir, { recursive: true, force: true })
      rmSync(backupDir, { recursive: true, force: true })
    }
  }

  return results
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
  const pat = readGithubPat(options.patPath)
  const secrets: NamedSecret[] = [{ value: pat, placeholder: '[redacted]' }]
  const apiBase = (options.apiBaseUrl ?? 'https://api.github.com').replace(/\/+$/, '')
  const fetchFn = options.fetchImpl ?? fetch
  const maxFilesPerRepo = Math.max(1, Math.min(options.maxFilesPerRepo ?? defaultMaxFilesPerRepo, 80))
  const maxFileBytes = Math.max(1024, Math.min(options.maxFileBytes ?? defaultMaxFileBytes, 2 * 1024 * 1024))
  const maxRepoBytes = Math.max(4096, Math.min(options.maxRepoBytes ?? defaultMaxRepoBytes, 8 * 1024 * 1024))

  const headers: Record<string, string> = {
    Authorization: `Bearer ${pat}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'Guardian/2 read-only repo connector',
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

  const results: SyncedGithubRepo[] = []

  for (const rawName of repoFullNames) {
    signal?.throwIfAborted()
    const { fullName } = parseRepoFullName(rawName)

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
