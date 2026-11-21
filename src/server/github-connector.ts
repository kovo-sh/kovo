import { accessSync, constants, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { redact } from './redact.ts'
import type { NamedSecret } from './redact.ts'

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
}

export interface GithubSyncOptions {
  patPath?: string
  apiBaseUrl?: string
  fetchImpl?: typeof fetch
  maxFilesPerRepo?: number
  maxFileBytes?: number
  maxRepoBytes?: number
}

const repoFullNamePattern = /^[a-zA-Z0-9_.-]{1,100}\/[a-zA-Z0-9_.-]{1,100}$/
const defaultMaxFilesPerRepo = 40
const defaultMaxFileBytes = 512 * 1024
const defaultMaxRepoBytes = 2 * 1024 * 1024

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
  const trimmed = raw.trim().replace(/^[~^=<>!\s]+/, '').split(/[\s|,]/, 1)[0]
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

  if (base === 'requirements.txt') {
    for (const line of content.split('\n')) {
      const m = line.trim().match(/^([a-zA-Z0-9_.-]+)\s*==\s*([0-9][0-9a-zA-Z.*+-]*)/)
      if (m) add('PyPI', m[1], m[2])
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

  return out
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

  if (dependencies.length > 0) {
    const depLines = dependencies
      .slice(0, 400)
      .map(d => `${d.ecosystem}:${d.package}@${d.version} (${d.sourceFile})`)
    specs.push({
      name: `${fullName}:dependencies`.slice(0, 160),
      kind: 'notes',
      content: `# Extracted Dependencies for ${fullName} (${dependencies.length} total)\n\n${depLines.join('\n')}`,
    })
  }

  return specs
}

export async function syncGithubRepos(
  repoFullNames: readonly string[],
  signal?: AbortSignal,
  options: GithubSyncOptions = {},
): Promise<SyncedGithubRepo[]> {
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
    const fullName = rawName.trim()
    if (!repoFullNamePattern.test(fullName) || fullName.includes('..')) {
      throw new Error(`Invalid GitHub repository name: "${fullName}". Expected "owner/repo".`)
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

    // Deduplicate dependencies across files, preferring lockfiles over package.json ranges.
    const depMap = new Map<string, RepoDependency>()
    for (const dep of allDependencies) {
      const key = `${dep.ecosystem}:${dep.package}`
      const existing = depMap.get(key)
      const isLock = !dep.sourceFile.endsWith('package.json')
      if (!existing || (isLock && existing.sourceFile.endsWith('package.json'))) {
        depMap.set(key, dep)
      }
    }
    const dependencies = [...depMap.values()]

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
