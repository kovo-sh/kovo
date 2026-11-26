import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, extname, join, relative } from 'node:path'
import { createInterface } from 'node:readline'
import { Bash, InMemoryFs, MountableFs, OverlayFs } from 'just-bash'
import { buildCallGraphFromFiles, runAnalyzer } from './analyzers.ts'
import type { AnalyzerName, CallGraphBuildResult, CallGraphSinkKind } from './analyzers.ts'

export type SastEngine = 'opengrep' | 'ast-grep' | 'gitleaks' | 'trufflehog' | 'trivy-fs' | 'bandit'
export type SastSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface SastFinding {
  engine: SastEngine
  ruleId: string
  severity: SastSeverity
  file: string
  line: number
  endLine?: number
  message: string
  maskedPreview: string
  cwe?: string
}

export interface SastScanRequest {
  repo: string
  engines: SastEngine[]
  paths?: string[]
  ruleFilter?: string
  timeoutMs?: number
}

export interface SastScanResult {
  repo: string
  enginesRun: SastEngine[]
  engineStatus: Record<string, { ok: boolean; count: number; durationMs: number; toolVersion?: string; note?: string }>
  findings: SastFinding[]
  totalFindings: number
  truncated: boolean
  evidencePath?: string
  durationMs: number
}

export interface OfflineScriptRequest {
  runtime: 'python' | 'node'
  code: string
  timeoutMs?: number
}

export interface OfflineScriptResult {
  runtime: 'python' | 'node'
  exitCode: number
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
}

/** kovo_verify script execution (Layer-3 SDK staged into the sandbox at call time). */
export interface VerifyScriptRequest {
  runtime: 'ts'
  code: string
  nonce: string
  /** SDK source files (zero-dep TypeScript) written next to the script. */
  sdkFiles?: Array<{ name: string; content: string }>
  timeoutMs?: number
}

export interface VerifyScriptResult {
  runtime: 'ts'
  exitCode: number
  /** Parsed proof document (claims only; stdout is never evidence). */
  result: unknown
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
}

export interface AstVerifyRequest {
  repo: string
  file: string
  startLine: number
  endLine: number
  engine: 'opengrep' | 'ast-grep'
  ruleOrPattern: string
  timeoutMs?: number
}

export interface AstVerifyResult {
  verified: boolean
  engine: 'opengrep' | 'ast-grep'
  repo: string
  file: string
  startLine: number
  endLine: number
  matchedLines: number[]
  codeExcerpt: string
  matchCount: number
  durationMs: number
  reason?: string
}

type OneShotInput =
  | {
      op?: 'exec'
      files: Array<{ name: string; content: string }>
      command: string
      outputs: string[]
      timeoutMs?: number
    }
  | ({ op: 'ast_verify' } & AstVerifyRequest)

export interface CallGraphRequest {
  repo: string
  paths?: string[]
  maxDepth?: number
  customGuardPatterns?: string[]
  customSanitizerPatterns?: string[]
  customSinkPatterns?: Array<{ pattern: string; sinkKind: CallGraphSinkKind }>
}

export interface CallGraphResult extends CallGraphBuildResult {
  repo: string
  evidencePath?: string
  durationMs: number
}

type SessionMessage =
  | { id: string; op: 'stage'; name: string; content: string }
  | { id: string; op: 'exec'; command: string; outputs: string[]; timeoutMs?: number }
  | { id: string; op: 'analyze'; tool: AnalyzerName; args: Record<string, unknown> }
  | ({ id: string; op: 'sast' } & SastScanRequest)
  | ({ id: string; op: 'script' } & OfflineScriptRequest)
  | ({ id: string; op: 'verify' } & VerifyScriptRequest)
  | ({ id: string; op: 'ast_verify' } & AstVerifyRequest)
  | ({ id: string; op: 'call_graph' } & CallGraphRequest)
  | { id: string; op: 'shutdown' }

const maxInputBytes = 16 * 1024 * 1024
const maxOutputBytes = 256 * 1024
const maxFileBytes = 2 * 1024 * 1024
const maxScratchBytes = 16 * 1024 * 1024
const maxSastFindingsReturned = 400
const maxScriptCodeBytes = 256 * 1024
const maxToolCaptureBytes = 8 * 1024 * 1024
// Chunked IPC: an NDJSON response above this size is written to the container tmpfs and the
// host receives a file pointer instead. The host's BoundedLineDecoder kills sessions at 64 KiB,
// so the spill threshold must stay meaningfully below that.
const IPC_SPILL_THRESHOLD = 48 * 1024
const IPC_SPILL_DIR = process.env.KOVO_IPC_DIR || '/tmp/kovo-ipc'
const cleanSdkName = /^kovo_verify\.ts$/
const cleanPath = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}(?:\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}){0,3}$/
const cleanOutputName = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/
const cleanRepoName = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}(?:\/[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}){0,3}$/
const REPOS_ROOT = '/repos'
const RULES_ROOT = '/opt/kovo-rules'
const VENV_BIN = '/opt/kovo-venv/bin'
const EVIDENCE_SYMLINK_TARGET = '/tmp/kovo-evidence'

const SEVERITY_RANK: Record<SastSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

// ============================================================================
// Secret Masking (Non-Negotiable: NEVER leak raw secrets in NDJSON or evidence)
// ============================================================================

export function maskSecretValue(raw: string): string {
  const trimmed = raw.trim()
  if (!trimmed) return '[masked]'
  if (trimmed.length <= 10) return `[masked:${trimmed.length}]`
  return `${trimmed.slice(0, 4)}…[masked:${trimmed.length}]…${trimmed.slice(-4)}`
}

const SECRET_TOKEN_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[^\n]*/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[0-9a-zA-Z]{16,}\b/g,
  /\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g,
  /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
]

export function secretMask(input: string): string {
  if (!input) return input
  let out = input
  for (const re of SECRET_TOKEN_PATTERNS) {
    out = out.replace(re, match => {
      if (match.startsWith('-----BEGIN')) return '[masked:private-key]'
      return maskSecretValue(match)
    })
  }
  out = out.replace(
    /((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s/@]+:)([^@\s/]+)(@)/gi,
    (_m, pre: string, pw: string, at: string) => `${pre}${maskSecretValue(pw)}${at}`,
  )
  out = out.replace(
    /(\b(?:Authorization|Proxy-Authorization)\s*[:=]\s*(?:Bearer|Basic|Token)\s+)([A-Za-z0-9._~+/=-]{8,})/gi,
    (_m, pre: string, tok: string) => `${pre}${maskSecretValue(tok)}`,
  )
  out = out.replace(
    /(\b(?:SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL|POSTGRES_URL|JWT_SECRET|NEXTAUTH_SECRET|API_KEY|API_SECRET|SECRET_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|CLIENT_SECRET|SIGNING_SECRET|WEBHOOK_SECRET|STRIPE_SECRET|DB_PASSWORD|PASSWORD)\s*[:=]\s*["'`])([^"'`\r\n]{6,})(["'`])/gi,
    (_m, pre: string, val: string, quote: string) => `${pre}${maskSecretValue(val)}${quote}`,
  )
  return out
}

// ============================================================================
// Path Validation against /repos (blocks traversal and out-of-tree symlinks)
// ============================================================================

function resolveRepoRoot(repo: string): string {
  if (typeof repo !== 'string' || !repo.trim()) throw new Error('Invalid repo name.')
  if (repo.includes('\0') || repo.includes('\r') || repo.includes('\n')) {
    throw new Error('Invalid characters in repo name.')
  }
  if (!existsSync(REPOS_ROOT)) throw new Error('No repositories are mounted at /repos.')
  const reposReal = realpathSync(REPOS_ROOT)
  if (repo === '.') return reposReal
  if (repo.startsWith('/') || repo.split('/').includes('..') || !cleanRepoName.test(repo)) {
    throw new Error(`Invalid repo identifier: ${repo}`)
  }
  const candidate = join(reposReal, repo)
  if (!existsSync(candidate)) throw new Error(`Repository not found at /repos/${repo}`)
  const resolved = realpathSync(candidate)
  if (resolved !== reposReal && !resolved.startsWith(reposReal + '/')) {
    throw new Error('Repository path escapes /repos boundary.')
  }
  return resolved
}

function validateRelativeSubpath(rel: string): string {
  if (typeof rel !== 'string' || !rel.trim()) throw new Error('Empty path in request.')
  if (rel.includes('\0') || rel.includes('\r') || rel.includes('\n')) {
    throw new Error('Invalid characters in path.')
  }
  if (rel.startsWith('/') || rel.startsWith('\\')) {
    throw new Error(`Absolute paths are not allowed: ${rel}`)
  }
  const segments = rel.split(/[\\/]+/).filter(Boolean)
  if (!segments.length || segments.some(s => s === '..')) {
    throw new Error(`Path traversal rejected: ${rel}`)
  }
  return segments.join('/')
}

function resolveRepoSubpaths(repoRoot: string, paths?: string[]): string[] {
  if (!paths || paths.length === 0) return [repoRoot]
  const resolved: string[] = []
  for (const raw of paths.slice(0, 32)) {
    const clean = validateRelativeSubpath(raw)
    const full = join(repoRoot, clean)
    if (!existsSync(full)) continue
    const lst = lstatSync(full)
    if (lst.isSymbolicLink()) throw new Error(`Symlink target rejected: ${raw}`)
    const real = realpathSync(full)
    if (real !== repoRoot && !real.startsWith(repoRoot + '/')) {
      throw new Error(`Path escapes repository boundary: ${raw}`)
    }
    resolved.push(real)
  }
  if (resolved.length === 0) throw new Error('None of the requested paths exist inside the repository.')
  return resolved
}

function resolveRepoFile(repoRoot: string, relFile: string): string {
  const clean = validateRelativeSubpath(relFile)
  const full = join(repoRoot, clean)
  if (!existsSync(full)) throw new Error(`File not found in repository: ${clean}`)
  const lst = lstatSync(full)
  if (lst.isSymbolicLink() || !lst.isFile()) {
    throw new Error(`Target is not a regular file: ${clean}`)
  }
  const real = realpathSync(full)
  if (!real.startsWith(repoRoot + '/')) {
    throw new Error(`File escapes repository boundary: ${clean}`)
  }
  return real
}

function toRepoRelative(repoRoot: string, absOrRel: string): string {
  if (!absOrRel) return ''
  if (absOrRel.startsWith(repoRoot + '/')) return absOrRel.slice(repoRoot.length + 1)
  if (absOrRel.startsWith('/')) {
    const rel = relative(repoRoot, absOrRel)
    return rel.startsWith('..') ? absOrRel : rel
  }
  return absOrRel.replace(/^\.\//, '')
}

// ============================================================================
// Safe Subprocess Runner (no shell, hard timeout, bounded capture)
// ============================================================================

interface ToolExecResult {
  exitCode: number
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
}

function toolEnv(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH || `${VENV_BIN}:/opt/kovo-worker/node_modules/.bin:/usr/local/bin:/usr/bin:/bin`,
    HOME: '/tmp',
    XDG_CACHE_HOME: '/tmp/.cache',
    XDG_CONFIG_HOME: '/tmp/.config',
    TRIVY_CACHE_DIR: process.env.TRIVY_CACHE_DIR || '/opt/trivy-cache',
    TRIVY_DISABLE_TELEMETRY: 'true',
    SEMGREP_SEND_METRICS: 'off',
    OPENGREP_SEND_METRICS: 'off',
    PYTHONDONTWRITEBYTECODE: '1',
    LANG: 'C.UTF-8',
    ...extra,
  }
}

function ensureRuntimeDirs() {
  for (const dir of ['/tmp/.config', '/tmp/.cache', '/tmp/.trivy-cache']) {
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 })
    } catch { /* ignore */ }
  }
}

function execTool(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs: number; maxBytes?: number; env?: Record<string, string> },
): Promise<ToolExecResult> {
  ensureRuntimeDirs()
  const startedAt = Date.now()
  const maxBytes = opts.maxBytes ?? maxToolCaptureBytes
  return new Promise(resolve => {
    let stdoutLen = 0
    let stderrLen = 0
    const outChunks: Buffer[] = []
    const errChunks: Buffer[] = []
    let timedOut = false
    let settled = false

    const child = spawn(cmd, args, {
      cwd: opts.cwd ?? '/tmp',
      env: toolEnv(opts.env),
      stdio: ['ignore', 'pipe', 'pipe'],
    })

    const finish = (exitCode: number) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (killTimer) clearTimeout(killTimer)
      resolve({
        exitCode,
        stdout: Buffer.concat(outChunks).toString('utf8'),
        stderr: Buffer.concat(errChunks).toString('utf8'),
        durationMs: Date.now() - startedAt,
        timedOut,
      })
    }

    let killTimer: NodeJS.Timeout | undefined
    const timer = setTimeout(() => {
      timedOut = true
      try { child.kill('SIGTERM') } catch { /* ignore */ }
      killTimer = setTimeout(() => {
        try { child.kill('SIGKILL') } catch { /* ignore */ }
      }, 1500)
      killTimer.unref()
    }, opts.timeoutMs)
    timer.unref()

    child.stdout.on('data', (chunk: Buffer) => {
      if (stdoutLen >= maxBytes) return
      const remaining = maxBytes - stdoutLen
      const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk
      outChunks.push(slice)
      stdoutLen += slice.length
    })
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrLen >= maxBytes) return
      const remaining = maxBytes - stderrLen
      const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk
      errChunks.push(slice)
      stderrLen += slice.length
    })
    child.once('error', err => {
      errChunks.push(Buffer.from(err.message))
      finish(127)
    })
    child.once('close', code => {
      finish(timedOut ? 124 : (code ?? 1))
    })
  })
}

// ============================================================================
// File Walker (for Python presence, fallback secret scan, offline SCA)
// ============================================================================

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__', 'vendor', 'target'])

function walkFiles(roots: string[], maxFiles = 2000): string[] {
  const results: string[] = []
  const stack = [...roots]
  while (stack.length > 0 && results.length < maxFiles) {
    const cur = stack.pop()!
    let lst
    try {
      lst = lstatSync(cur)
    } catch {
      continue
    }
    if (lst.isSymbolicLink()) continue
    if (lst.isFile()) {
      results.push(cur)
      continue
    }
    if (!lst.isDirectory()) continue
    let entries: string[]
    try {
      entries = readdirSync(cur)
    } catch {
      continue
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry)) continue
      stack.push(join(cur, entry))
    }
  }
  return results
}

function normalizeSeverity(raw?: string): SastSeverity {
  const v = String(raw ?? '').toLowerCase()
  if (v === 'critical') return 'critical'
  if (v === 'error' || v === 'high') return 'high'
  if (v === 'warning' || v === 'warn' || v === 'medium') return 'medium'
  if (v === 'low') return 'low'
  return 'info'
}

function extractCwe(meta: unknown): string | undefined {
  if (!meta) return undefined
  if (typeof meta === 'string') {
    const m = meta.match(/CWE-\d+/i)
    return m ? m[0].toUpperCase() : undefined
  }
  if (typeof meta === 'number') return `CWE-${meta}`
  if (Array.isArray(meta)) {
    for (const item of meta) {
      const found = extractCwe(item)
      if (found) return found
    }
  }
  if (typeof meta === 'object') {
    const obj = meta as Record<string, unknown>
    return extractCwe(obj.cwe ?? obj.id)
  }
  return undefined
}

// ============================================================================
// Offline Semver Comparison + Built-in SCA & Fallback Secret Detectors
// ============================================================================

function parseSemver(raw: string): [number, number, number] | null {
  const cleaned = raw.trim().replace(/^[~^=v<> ]+/, '')
  const m = cleaned.match(/^(\d+)\.(\d+)(?:\.(\d+))?/)
  if (!m) return null
  return [Number(m[1]), Number(m[2]), Number(m[3] ?? '0')]
}

function cmpSemver(a: [number, number, number], b: [number, number, number]): number {
  if (a[0] !== b[0]) return a[0] - b[0]
  if (a[1] !== b[1]) return a[1] - b[1]
  return a[2] - b[2]
}

interface ScaAdvisory {
  id: string
  ecosystem: 'npm' | 'pypi' | 'go' | 'java' | 'rubygems'
  package: string
  affectedRanges: Array<{ min: string; maxExclusive: string }>
  severity: SastSeverity
  cwe?: string
  message: string
}

function versionAffected(version: string, ranges: Array<{ min: string; maxExclusive: string }>): boolean {
  const parsed = parseSemver(version)
  if (!parsed) return false
  for (const r of ranges) {
    const lo = parseSemver(r.min)
    const hi = parseSemver(r.maxExclusive)
    if (lo && hi && cmpSemver(parsed, lo) >= 0 && cmpSemver(parsed, hi) < 0) return true
  }
  return false
}

function runOfflineSca(repoRoot: string, targets: string[]): SastFinding[] {
  const advisoryPath = join(RULES_ROOT, 'sca-advisories.json')
  if (!existsSync(advisoryPath)) return []
  let advisories: ScaAdvisory[] = []
  try {
    const raw = JSON.parse(readFileSync(advisoryPath, 'utf8')) as { advisories?: ScaAdvisory[] }
    advisories = raw.advisories ?? []
  } catch {
    return []
  }
  const findings: SastFinding[] = []
  const files = walkFiles(targets, 1500)
  for (const file of files) {
    const base = (file.split('/').pop() ?? '').toLowerCase()
    if (!['package.json', 'package-lock.json', 'requirements.txt', 'pyproject.toml', 'pipfile', 'go.mod', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'gemfile', 'gemfile.lock'].includes(base.toLowerCase())) continue
    let text = ''
    try {
      const st = lstatSync(file)
      if (st.size > 1024 * 1024) continue
      text = readFileSync(file, 'utf8')
    } catch {
      continue
    }
    const rel = toRepoRelative(repoRoot, file)
    const lines = text.split('\n')
    const findLine = (needle: string) => {
      const idx = lines.findIndex(l => l.includes(needle))
      return idx >= 0 ? idx + 1 : 1
    }

    if (base === 'package.json') {
      try {
        const pkg = JSON.parse(text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
        const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) }
        for (const [name, ver] of Object.entries(deps)) {
          for (const adv of advisories) {
            if (adv.ecosystem !== 'npm' || adv.package !== name) continue
            if (versionAffected(ver, adv.affectedRanges)) {
              findings.push({
                engine: 'trivy-fs',
                ruleId: adv.id,
                severity: adv.severity,
                file: rel,
                line: findLine(`"${name}"`),
                message: `${adv.message} (detected ${name}@${ver})`,
                maskedPreview: `${name}: ${ver}`,
                cwe: adv.cwe,
              })
            }
          }
        }
      } catch { /* ignore malformed json */ }
    } else if (base === 'package-lock.json') {
      try {
        const lock = JSON.parse(text) as { packages?: Record<string, { version?: string }> }
        for (const [pkgPath, entry] of Object.entries(lock.packages ?? {})) {
          const name = pkgPath.replace(/^.*node_modules\//, '')
          const ver = entry?.version
          if (!name || !ver) continue
          for (const adv of advisories) {
            if (adv.ecosystem !== 'npm' || adv.package !== name) continue
            if (versionAffected(ver, adv.affectedRanges)) {
              findings.push({
                engine: 'trivy-fs',
                ruleId: adv.id,
                severity: adv.severity,
                file: rel,
                line: findLine(`"node_modules/${name}"`),
                message: `${adv.message} (locked ${name}@${ver})`,
                maskedPreview: `${name}@${ver}`,
                cwe: adv.cwe,
              })
            }
          }
        }
      } catch { /* ignore */ }
    } else if (base === 'requirements.txt') {
      lines.forEach((line, idx) => {
        const m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*==\s*([0-9][0-9A-Za-z._-]*)/)
        if (!m) return
        const name = m[1].toLowerCase()
        const ver = m[2]
        for (const adv of advisories) {
          if (adv.ecosystem !== 'pypi' || adv.package.toLowerCase() !== name) continue
          if (versionAffected(ver, adv.affectedRanges)) {
            findings.push({
              engine: 'trivy-fs',
              ruleId: adv.id,
              severity: adv.severity,
              file: rel,
              line: idx + 1,
              message: `${adv.message} (pinned ${name}==${ver})`,
              maskedPreview: `${name}==${ver}`,
              cwe: adv.cwe,
            })
          }
        }
      })
    } else if (base === 'go.mod') {
      lines.forEach((line, idx) => {
        const m = line.trim().match(/^(?:require\s+)?([A-Za-z0-9./_-]+)\s+v([0-9][0-9A-Za-z._-]*)/)
        if (!m) return
        const name = m[1]
        const ver = m[2]
        for (const adv of advisories) {
          if (adv.ecosystem !== 'go' || adv.package !== name) continue
          if (versionAffected(ver, adv.affectedRanges)) {
            findings.push({
              engine: 'trivy-fs',
              ruleId: adv.id,
              severity: adv.severity,
              file: rel,
              line: idx + 1,
              message: `${adv.message} (go.mod ${name} v${ver})`,
              maskedPreview: `${name} v${ver}`,
              cwe: adv.cwe,
            })
          }
        }
      })
    } else if (base === 'pyproject.toml' || base === 'pipfile') {
      lines.forEach((line, idx) => {
        for (const m of line.matchAll(/([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|\^)\s*["']?([0-9][0-9A-Za-z._-]*)/g)) {
          const name = m[1].toLowerCase()
          const ver = m[2]
          for (const adv of advisories) {
            if (adv.ecosystem !== 'pypi' || adv.package.toLowerCase() !== name) continue
            if (versionAffected(ver, adv.affectedRanges)) {
              findings.push({
                engine: 'trivy-fs', ruleId: adv.id, severity: adv.severity, file: rel, line: idx + 1,
                message: `${adv.message} (declared ${name}==${ver})`,
                maskedPreview: `${name}==${ver}`, cwe: adv.cwe,
              })
            }
          }
        }
      })
    } else if (base === 'pom.xml') {
      const artifactIds = [...text.matchAll(/<artifactId>\s*([A-Za-z0-9_.-]+)\s*<\/artifactId>/g)]
      const versions = [...text.matchAll(/<version>\s*([0-9][0-9A-Za-z._-]*)\s*<\/version>/g)]
      artifactIds.forEach((artifact, i) => {
        const name = artifact[1].toLowerCase()
        const ver = versions[i]?.[1]
        if (!ver) return
        for (const adv of advisories) {
          if (adv.ecosystem !== 'java' || adv.package.toLowerCase() !== name) continue
          if (versionAffected(ver, adv.affectedRanges)) {
            findings.push({
              engine: 'trivy-fs', ruleId: adv.id, severity: adv.severity, file: rel,
              line: findLine(`<artifactId>${artifact[1]}</artifactId>`),
              message: `${adv.message} (pom ${name}:${ver})`,
              maskedPreview: `${name}:${ver}`, cwe: adv.cwe,
            })
          }
        }
      })
    } else if (base === 'build.gradle' || base === 'build.gradle.kts') {
      lines.forEach((line, idx) => {
        for (const m of line.matchAll(/["']([a-zA-Z0-9_.-]+):([a-zA-Z0-9_.-]+):([0-9][0-9A-Za-z._-]*)["']/g)) {
          const name = m[2].toLowerCase()
          const ver = m[3]
          for (const adv of advisories) {
            if (adv.ecosystem !== 'java' || adv.package.toLowerCase() !== name) continue
            if (versionAffected(ver, adv.affectedRanges)) {
              findings.push({
                engine: 'trivy-fs', ruleId: adv.id, severity: adv.severity, file: rel, line: idx + 1,
                message: `${adv.message} (gradle ${name}:${ver})`,
                maskedPreview: `${name}:${ver}`, cwe: adv.cwe,
              })
            }
          }
        }
      })
    } else if (base === 'gemfile' || base === 'gemfile.lock') {
      lines.forEach((line, idx) => {
        const m = line.match(/^\s*gem\s+["']([A-Za-z0-9_.-]+)["']\s*,?\s*["']?([0-9][0-9A-Za-z._-]*)?/)
          ?? line.match(/^\s{4}([A-Za-z0-9_.-]+) \(([0-9][0-9A-Za-z._-]*)\)/)
        if (!m || !m[2]) return
        const name = m[1].toLowerCase()
        const ver = m[2]
        for (const adv of advisories) {
          if (adv.ecosystem !== 'rubygems' || adv.package.toLowerCase() !== name) continue
          if (versionAffected(ver, adv.affectedRanges)) {
            findings.push({
              engine: 'trivy-fs', ruleId: adv.id, severity: adv.severity, file: rel, line: idx + 1,
              message: `${adv.message} (bundler ${name} ${ver})`,
              maskedPreview: `${name} ${ver}`, cwe: adv.cwe,
            })
          }
        }
      })
    }
  }
  return findings
}

const FALLBACK_SECRET_RULES: Array<{ ruleId: string; severity: SastSeverity; cwe: string; message: string; regex: RegExp }> = [
  { ruleId: 'kovo.secret.aws-access-key', severity: 'critical', cwe: 'CWE-798', message: 'Hardcoded AWS access key ID detected.', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { ruleId: 'kovo.secret.github-token', severity: 'critical', cwe: 'CWE-798', message: 'Hardcoded GitHub personal access token detected.', regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g },
  { ruleId: 'kovo.secret.stripe-key', severity: 'critical', cwe: 'CWE-798', message: 'Hardcoded Stripe live secret key detected.', regex: /\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}\b/g },
  { ruleId: 'kovo.secret.private-key', severity: 'critical', cwe: 'CWE-798', message: 'Private cryptographic key material committed to repository.', regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g },
  { ruleId: 'kovo.secret.openai-anthropic', severity: 'high', cwe: 'CWE-798', message: 'Hardcoded LLM API key detected.', regex: /\bsk-(?:proj-|ant-)[A-Za-z0-9_-]{20,}\b/g },
  { ruleId: 'kovo.secret.google-api-key', severity: 'medium', cwe: 'CWE-798', message: 'Hardcoded Google API key detected.', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { ruleId: 'kovo.secret.slack-webhook', severity: 'high', cwe: 'CWE-798', message: 'Hardcoded Slack webhook URL detected.', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g },
  { ruleId: 'kovo.secret.generic-assignment', severity: 'high', cwe: 'CWE-798', message: 'Hardcoded secret or credential literal detected.', regex: /\b(?:SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE|JWT_SECRET|NEXTAUTH_SECRET|DATABASE_URL|POSTGRES_URL|STRIPE_SECRET|WEBHOOK_SECRET)\s*[:=]\s*["'`][^"'`\r\n]{8,160}["'`]/gi },
]

function runBuiltinSecretScan(repoRoot: string, targets: string[], engine: 'gitleaks' | 'trufflehog'): SastFinding[] {
  const findings: SastFinding[] = []
  const files = walkFiles(targets, 1500)
  for (const file of files) {
    let text = ''
    try {
      const st = lstatSync(file)
      if (st.size > 512 * 1024) continue
      const buf = readFileSync(file)
      if (buf.subarray(0, 512).includes(0)) continue // skip binary
      text = buf.toString('utf8')
    } catch {
      continue
    }
    const rel = toRepoRelative(repoRoot, file)
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i]
      for (const rule of FALLBACK_SECRET_RULES) {
        rule.regex.lastIndex = 0
        const match = rule.regex.exec(line)
        if (!match) continue
        findings.push({
          engine,
          ruleId: rule.ruleId,
          severity: rule.severity,
          file: rel,
          line: i + 1,
          message: rule.message,
          maskedPreview: secretMask(match[0].slice(0, 200)),
          cwe: rule.cwe,
        })
        if (findings.length >= 200) return findings
      }
    }
  }
  return findings
}

// ============================================================================
// Engine Runners for op: 'sast'
// ============================================================================

async function runOpengrepEngine(repoRoot: string, targets: string[], timeoutMs: number): Promise<{ findings: SastFinding[]; ok: boolean; note?: string }> {
  const configDir = join(RULES_ROOT, 'opengrep')
  if (!existsSync(configDir)) return { findings: [], ok: false, note: 'Missing /opt/kovo-rules/opengrep' }
  const interfileArgs = [
    'scan', '--config', configDir, '--enable-interfile', '--interfile-depth=3', '--interfile-timeout=30',
    '--max-memory=1024', '--json', '--no-git-ignore', '--quiet', ...targets,
  ]
  let res = await execTool('opengrep', interfileArgs, { cwd: repoRoot, timeoutMs })
  if (!res.stdout.trim() && res.exitCode !== 0) {
    // Fallback retry without --enable-interfile for huge/edge repositories
    res = await execTool('opengrep', [
      'scan', '--config', configDir, '--max-memory=1024', '--json', '--no-git-ignore', '--quiet', ...targets,
    ], { cwd: repoRoot, timeoutMs })
  }
  if (!res.stdout.trim()) {
    return { findings: [], ok: res.exitCode === 0, note: res.exitCode === 0 ? undefined : (res.stderr.trim().slice(0, 200) || `exit ${res.exitCode}`) }
  }
  try {
    const parsed = JSON.parse(res.stdout) as {
      errors?: Array<{ level?: string; message?: string }>
      results?: Array<{
        check_id?: string
        path?: string
        start?: { line?: number }
        end?: { line?: number }
        extra?: { severity?: string; message?: string; lines?: string; metadata?: Record<string, unknown> }
      }>
    }
    const findings: SastFinding[] = (parsed.results ?? []).map(r => {
      const ruleId = String(r.check_id ?? 'opengrep.rule').replace(/^opt\.kovo-rules\.opengrep\./, '')
      const cwe = extractCwe(r.extra?.metadata)
      return {
        engine: 'opengrep',
        ruleId,
        severity: normalizeSeverity(r.extra?.severity),
        file: toRepoRelative(repoRoot, r.path ?? ''),
        line: Number(r.start?.line ?? 1),
        endLine: r.end?.line ? Number(r.end.line) : undefined,
        message: secretMask(String(r.extra?.message ?? 'Opengrep finding')).slice(0, 400),
        maskedPreview: secretMask(String(r.extra?.lines ?? '').trim()).slice(0, 240),
        cwe,
      }
    })
    const fatalErr = (parsed.errors ?? []).find(e => e.level === 'error')
    if (fatalErr && findings.length === 0) {
      return { findings: [], ok: false, note: String(fatalErr.message ?? 'opengrep error').slice(0, 240) }
    }
    return { findings, ok: true }
  } catch (err) {
    return { findings: [], ok: false, note: `Failed to parse opengrep JSON: ${err instanceof Error ? err.message : 'parse error'}` }
  }
}

async function runAstGrepEngine(repoRoot: string, targets: string[], timeoutMs: number): Promise<{ findings: SastFinding[]; ok: boolean; note?: string }> {
  const configFile = join(RULES_ROOT, 'ast-grep', 'sgconfig.yml')
  if (!existsSync(configFile)) return { findings: [], ok: false, note: 'Missing /opt/kovo-rules/ast-grep/sgconfig.yml' }
  const res = await execTool('ast-grep', [
    'scan', '--config', configFile, '--include-metadata', '--json=compact', ...targets,
  ], { cwd: repoRoot, timeoutMs })
  const raw = res.stdout.trim()
  if (!raw) {
    return { findings: [], ok: res.exitCode === 0 || res.exitCode === 1, note: res.exitCode > 1 ? res.stderr.trim().slice(0, 200) : undefined }
  }
  try {
    const parsed = JSON.parse(raw) as Array<{
      ruleId?: string
      severity?: string
      message?: string
      file?: string
      text?: string
      metadata?: Record<string, unknown>
      range?: { start?: { line?: number }; end?: { line?: number } }
    }>
    const findings: SastFinding[] = (Array.isArray(parsed) ? parsed : []).map(m => ({
      engine: 'ast-grep',
      ruleId: String(m.ruleId ?? 'ast-grep.rule'),
      severity: normalizeSeverity(m.severity),
      file: toRepoRelative(repoRoot, m.file ?? ''),
      line: Number(m.range?.start?.line ?? 0) + 1,
      endLine: m.range?.end?.line !== undefined ? Number(m.range.end.line) + 1 : undefined,
      message: secretMask(String(m.message ?? 'ast-grep structural match')).slice(0, 400),
      maskedPreview: secretMask(String(m.text ?? '').trim().replace(/\s+/g, ' ')).slice(0, 240),
      cwe: extractCwe(m.metadata),
    }))
    return { findings, ok: true }
  } catch (err) {
    return { findings: [], ok: false, note: `Failed to parse ast-grep JSON: ${err instanceof Error ? err.message : 'parse error'}` }
  }
}

async function runGitleaksEngine(repoRoot: string, targets: string[], timeoutMs: number): Promise<{ findings: SastFinding[]; ok: boolean; note?: string }> {
  const findings: SastFinding[] = []
  let binaryOk = true
  let note: string | undefined
  for (const target of targets) {
    const reportPath = join(tmpdir(), `kovo-gitleaks-${randomUUID()}.json`)
    try {
      const res = await execTool('gitleaks', [
        'dir', '--no-banner', '--redact=100', '--exit-code', '0',
        '--report-format', 'json', '--report-path', reportPath, target,
      ], { cwd: repoRoot, timeoutMs })
      if (res.exitCode !== 0) {
        binaryOk = false
        note = res.stderr.trim().slice(0, 200) || `gitleaks exit ${res.exitCode}`
        break
      }
      if (existsSync(reportPath)) {
        const raw = await readFile(reportPath, 'utf8')
        const items = JSON.parse(raw || '[]') as Array<{
          RuleID?: string
          Description?: string
          File?: string
          StartLine?: number
          EndLine?: number
          Match?: string
          Secret?: string
        }>
        for (const item of Array.isArray(items) ? items : []) {
          const rawPreview = (item.Match || (item.Secret ? maskSecretValue(item.Secret) : '[masked]')).replace(/REDACTED/g, '[masked]')
          const masked = secretMask(String(rawPreview))
          const maskedPreview = (masked.includes('masked') ? masked : maskSecretValue(masked)).slice(0, 200)
          findings.push({
            engine: 'gitleaks',
            ruleId: String(item.RuleID ?? 'gitleaks.secret'),
            severity: 'high',
            file: toRepoRelative(repoRoot, item.File ?? ''),
            line: Number(item.StartLine ?? 1),
            endLine: item.EndLine ? Number(item.EndLine) : undefined,
            message: secretMask(String(item.Description ?? 'Hardcoded secret detected by gitleaks')).slice(0, 300),
            maskedPreview,
            cwe: 'CWE-798',
          })
        }
      }
    } catch (err) {
      binaryOk = false
      note = err instanceof Error ? err.message : 'gitleaks error'
      break
    } finally {
      await unlink(reportPath).catch(() => undefined)
    }
  }
  if (!binaryOk) {
    const fallback = runBuiltinSecretScan(repoRoot, targets, 'gitleaks')
    return { findings: fallback, ok: true, note: `Fallback offline secret detector used (${note ?? 'gitleaks unavailable'})` }
  }
  return { findings, ok: true }
}

async function runTrufflehogEngine(repoRoot: string, targets: string[], timeoutMs: number): Promise<{ findings: SastFinding[]; ok: boolean; note?: string }> {
  const res = await execTool('trufflehog', [
    'filesystem', '--no-verification', '--no-update', '--json', ...targets,
  ], { cwd: repoRoot, timeoutMs })
  if (res.exitCode !== 0 && !res.stdout.trim()) {
    const fallback = runBuiltinSecretScan(repoRoot, targets, 'trufflehog')
    return { findings: fallback, ok: true, note: `Fallback offline secret detector used (${res.stderr.trim().slice(0, 120) || 'exit ' + res.exitCode})` }
  }
  const findings: SastFinding[] = []
  for (const line of res.stdout.split('\n')) {
    const trimmed = line.trim()
    if (!trimmed.startsWith('{')) continue
    try {
      const obj = JSON.parse(trimmed) as {
        DetectorName?: string
        Raw?: string
        RawV2?: string
        Redacted?: string
        SourceMetadata?: { Data?: { Filesystem?: { file?: string; line?: number } } }
      }
      const fsMeta = obj.SourceMetadata?.Data?.Filesystem
      if (!obj.DetectorName || !fsMeta) continue
      const previewSource = obj.Raw || obj.RawV2 || obj.Redacted || ''
      findings.push({
        engine: 'trufflehog',
        ruleId: `trufflehog.${obj.DetectorName}`,
        severity: 'high',
        file: toRepoRelative(repoRoot, fsMeta.file ?? ''),
        line: Number(fsMeta.line ?? 1),
        message: `Potential ${obj.DetectorName} credential detected (unverified offline scan).`,
        maskedPreview: maskSecretValue(previewSource),
        cwe: 'CWE-798',
      })
    } catch { /* skip log lines */ }
  }
  return { findings, ok: true }
}

async function runTrivyFsEngine(repoRoot: string, targets: string[], timeoutMs: number): Promise<{ findings: SastFinding[]; ok: boolean; note?: string }> {
  const findings: SastFinding[] = []
  let trivyOk = true
  let note: string | undefined
  const cacheDir = process.env.TRIVY_CACHE_DIR || '/opt/trivy-cache'
  for (const target of targets) {
    const res = await execTool('trivy', [
      'fs', '--scanners', 'vuln,misconfig', '--offline-scan',
      '--skip-check-update', '--skip-db-update', '--skip-java-db-update',
      '--cache-dir', cacheDir, '--format', 'json', '--quiet', target,
    ], { cwd: repoRoot, timeoutMs })
    if (res.exitCode !== 0 && !res.stdout.trim()) {
      trivyOk = false
      note = res.stderr.trim().slice(0, 200) || `trivy exit ${res.exitCode}`
      continue
    }
    try {
      const parsed = JSON.parse(res.stdout || '{}') as {
        Results?: Array<{
          Target?: string
          Misconfigurations?: Array<{
            ID?: string
            Title?: string
            Description?: string
            Severity?: string
            CauseMetadata?: { StartLine?: number; EndLine?: number }
          }>
          Vulnerabilities?: Array<{
            VulnerabilityID?: string
            PkgName?: string
            InstalledVersion?: string
            FixedVersion?: string
            Title?: string
            Description?: string
            Severity?: string
            CweIDs?: string[]
          }>
        }>
      }
      for (const result of parsed.Results ?? []) {
        const relTarget = toRepoRelative(repoRoot, result.Target ?? '')
        for (const mis of result.Misconfigurations ?? []) {
          findings.push({
            engine: 'trivy-fs',
            ruleId: String(mis.ID ?? 'trivy.misconfig'),
            severity: normalizeSeverity(mis.Severity),
            file: relTarget,
            line: Number(mis.CauseMetadata?.StartLine ?? 1),
            endLine: mis.CauseMetadata?.EndLine ? Number(mis.CauseMetadata.EndLine) : undefined,
            message: secretMask(String(mis.Title || mis.Description || 'IaC misconfiguration')).slice(0, 400),
            maskedPreview: secretMask(String(mis.Title ?? mis.ID ?? '')).slice(0, 200),
          })
        }
        for (const vuln of result.Vulnerabilities ?? []) {
          const vulnId = String(vuln.VulnerabilityID ?? 'trivy.vuln')
          const pkg = String(vuln.PkgName ?? 'package')
          const inst = String(vuln.InstalledVersion ?? '')
          const fix = vuln.FixedVersion ? ` -> fix ${vuln.FixedVersion}` : ''
          const cwe = Array.isArray(vuln.CweIDs) && vuln.CweIDs[0] ? extractCwe(vuln.CweIDs[0]) : undefined
          findings.push({
            engine: 'trivy-fs',
            ruleId: vulnId,
            severity: normalizeSeverity(vuln.Severity),
            file: relTarget,
            line: 1,
            message: secretMask(`${vulnId}: ${pkg}@${inst}${fix} — ${vuln.Title || vuln.Description || 'Vulnerable dependency'}`).slice(0, 400),
            maskedPreview: secretMask(`${pkg}@${inst} (${vulnId})`).slice(0, 200),
            ...(cwe ? { cwe } : {}),
          })
        }
      }
    } catch {
      trivyOk = false
      note = 'Failed to parse trivy JSON output.'
    }
  }
  // Complement with deterministic offline SCA lockfile scanner (deduplicated against Trivy CVEs)
  const scaFindings = runOfflineSca(repoRoot, targets)
  const seenKeys = new Set(findings.map(f => `${f.ruleId}|${f.file}|${f.maskedPreview}`))
  for (const sf of scaFindings) {
    const key = `${sf.ruleId}|${sf.file}|${sf.maskedPreview}`
    if (!seenKeys.has(key)) {
      seenKeys.add(key)
      findings.push(sf)
    }
  }
  return { findings, ok: trivyOk || scaFindings.length > 0, note }
}

async function runBanditEngine(repoRoot: string, targets: string[], timeoutMs: number): Promise<{ findings: SastFinding[]; ok: boolean; note?: string }> {
  const pyFiles = walkFiles(targets, 2000).filter(f => f.endsWith('.py'))
  if (pyFiles.length === 0) {
    return { findings: [], ok: true, note: 'No Python files in target scope.' }
  }
  const banditBin = existsSync(join(VENV_BIN, 'bandit')) ? join(VENV_BIN, 'bandit') : 'bandit'
  const res = await execTool(banditBin, ['-r', '-f', 'json', '-q', ...targets], { cwd: repoRoot, timeoutMs })
  if (res.exitCode > 1 && !res.stdout.trim()) {
    return { findings: [], ok: false, note: res.stderr.trim().slice(0, 200) || `bandit exit ${res.exitCode}` }
  }
  try {
    const parsed = JSON.parse(res.stdout || '{}') as {
      results?: Array<{
        test_id?: string
        test_name?: string
        issue_severity?: string
        issue_text?: string
        filename?: string
        line_number?: number
        end_col_offset?: number
        code?: string
        issue_cwe?: { id?: number }
      }>
    }
    const findings: SastFinding[] = (parsed.results ?? []).map(item => ({
      engine: 'bandit',
      ruleId: `${item.test_id ?? 'B000'}${item.test_name ? '.' + item.test_name : ''}`,
      severity: normalizeSeverity(item.issue_severity),
      file: toRepoRelative(repoRoot, item.filename ?? ''),
      line: Number(item.line_number ?? 1),
      message: secretMask(String(item.issue_text ?? 'Bandit finding')).slice(0, 400),
      maskedPreview: secretMask(String(item.code ?? '').trim().replace(/\s+/g, ' ')).slice(0, 240),
      cwe: item.issue_cwe?.id ? `CWE-${item.issue_cwe.id}` : undefined,
    }))
    return { findings, ok: true }
  } catch (err) {
    return { findings: [], ok: false, note: `Failed to parse bandit JSON: ${err instanceof Error ? err.message : 'parse error'}` }
  }
}

async function runSastScan(
  req: SastScanRequest,
  id: string,
  inputDirectory: string,
  stagedContents: Map<string, string>,
): Promise<SastScanResult> {
  const startedAt = Date.now()
  const repoRoot = resolveRepoRoot(req.repo)
  const targets = resolveRepoSubpaths(repoRoot, req.paths)
  const validEngines: SastEngine[] = ['opengrep', 'ast-grep', 'gitleaks', 'trufflehog', 'trivy-fs', 'bandit']
  const engines = [...new Set((req.engines ?? []).filter((e): e is SastEngine => validEngines.includes(e)))]
  if (engines.length === 0) throw new Error('At least one valid SAST engine must be specified.')

  const totalBudgetMs = Math.max(5_000, Math.min(req.timeoutMs ?? 60_000, 120_000))
  // opengrep --enable-interfile is the highest-recall engine: give it a dedicated
  // weighted slice (>= 50% of the total budget, minimum 30s) instead of an equal share.
  const opengrepBudgetMs = engines.includes('opengrep')
    ? Math.max(30_000, Math.floor(totalBudgetMs * 0.5))
    : 0
  const otherEngines = engines.filter(e => e !== 'opengrep')
  const remainingBudgetMs = Math.max(5_000, totalBudgetMs - opengrepBudgetMs)
  const perEngineMs = Math.max(5_000, Math.floor(remainingBudgetMs / Math.max(1, otherEngines.length)))
  const engineStatus: SastScanResult['engineStatus'] = {}
  const allFindings: SastFinding[] = []

  for (const engine of engines) {
    const t0 = Date.now()
    let outcome: { findings: SastFinding[]; ok: boolean; note?: string }
    if (engine === 'opengrep') outcome = await runOpengrepEngine(repoRoot, targets, opengrepBudgetMs)
    else if (engine === 'ast-grep') outcome = await runAstGrepEngine(repoRoot, targets, perEngineMs)
    else if (engine === 'gitleaks') outcome = await runGitleaksEngine(repoRoot, targets, perEngineMs)
    else if (engine === 'trufflehog') outcome = await runTrufflehogEngine(repoRoot, targets, perEngineMs)
    else if (engine === 'trivy-fs') outcome = await runTrivyFsEngine(repoRoot, targets, perEngineMs)
    else outcome = await runBanditEngine(repoRoot, targets, perEngineMs)

    let filtered = outcome.findings
    if (req.ruleFilter) {
      const needle = req.ruleFilter.toLowerCase()
      filtered = filtered.filter(f =>
        f.ruleId.toLowerCase().includes(needle) ||
        f.message.toLowerCase().includes(needle) ||
        (f.cwe ?? '').toLowerCase().includes(needle))
    }
    // Enforce secretMask defense-in-depth on every finding
    const masked = filtered.map(f => ({
      ...f,
      message: secretMask(f.message),
      maskedPreview: secretMask(f.maskedPreview),
    }))
    engineStatus[engine] = {
      ok: outcome.ok,
      count: masked.length,
      durationMs: Date.now() - t0,
      ...(outcome.note ? { note: outcome.note } : {}),
    }
    allFindings.push(...masked)
  }

  // Deduplicate and sort by severity -> file -> line
  const seen = new Set<string>()
  const deduped: SastFinding[] = []
  for (const f of allFindings) {
    const key = `${f.engine}|${f.ruleId}|${f.file}|${f.line}`
    if (seen.has(key)) continue
    seen.add(key)
    deduped.push(f)
  }
  deduped.sort((a, b) =>
    (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) ||
    a.file.localeCompare(b.file) ||
    (a.line - b.line))

  const truncated = deduped.length > maxSastFindingsReturned
  const returnedFindings = deduped.slice(0, maxSastFindingsReturned)

  let evidencePath: string | undefined
  if (deduped.length > 0) {
    const safeId = id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 48) || randomUUID().slice(0, 12)
    const relEvidence = `sast/${safeId}.json`
    const fullJson = JSON.stringify({
      repo: req.repo,
      enginesRun: engines,
      engineStatus,
      totalFindings: deduped.length,
      findings: deduped,
    }, null, 2)
    if (Buffer.byteLength(fullJson) <= maxFileBytes) {
      await stageFile(inputDirectory, relEvidence, fullJson)
      stagedContents.set(relEvidence, fullJson)
      evidencePath = '/evidence/' + relEvidence
    }
  }

  return {
    repo: req.repo,
    enginesRun: engines,
    engineStatus,
    findings: returnedFindings,
    totalFindings: deduped.length,
    truncated,
    ...(evidencePath ? { evidencePath } : {}),
    durationMs: Date.now() - startedAt,
  }
}

// ============================================================================
// Offline Script Runner (op: 'script' — keeps /tmp noexec!)
// ============================================================================

async function runOfflineScript(req: OfflineScriptRequest, inputDirectory: string): Promise<OfflineScriptResult> {
  if (req.runtime !== 'python' && req.runtime !== 'node') {
    throw new Error(`Unsupported offline script runtime: ${String(req.runtime)}`)
  }
  if (typeof req.code !== 'string' || !req.code.trim()) {
    throw new Error('Offline script code must be non-empty.')
  }
  if (Buffer.byteLength(req.code) > maxScriptCodeBytes) {
    throw new Error('Offline script code exceeds 256 KiB limit.')
  }
  const timeoutMs = Math.max(1_000, Math.min(req.timeoutMs ?? 30_000, 60_000))
  const ext = req.runtime === 'python' ? '.py' : '.mjs'
  const scriptPath = join(tmpdir(), `kovo-script-${randomUUID()}${ext}`)
  await writeFile(scriptPath, req.code, { mode: 0o600 })
  try {
    const cmd = req.runtime === 'python'
      ? (existsSync(join(VENV_BIN, 'python3')) ? join(VENV_BIN, 'python3') : 'python3')
      : process.execPath
    const args = req.runtime === 'python'
      ? ['-s', scriptPath]
      : ['--max-old-space-size=256', scriptPath]
    const res = await execTool(cmd, args, {
      cwd: existsSync(REPOS_ROOT) ? REPOS_ROOT : tmpdir(),
      timeoutMs,
      maxBytes: maxOutputBytes,
      env: {
        KOVO_REPOS: REPOS_ROOT,
        KOVO_EVIDENCE: inputDirectory,
      },
    })
    return {
      runtime: req.runtime,
      exitCode: res.exitCode,
      stdout: secretMask(res.stdout).slice(0, maxOutputBytes),
      stderr: secretMask(res.stderr).slice(0, maxOutputBytes),
      durationMs: res.durationMs,
      timedOut: res.timedOut,
    }
  } finally {
    await unlink(scriptPath).catch(() => undefined)
  }
}

// ============================================================================
// Layer-3 kovo_verify script runner (3-hook SDK, transcript-backed claims)
// ============================================================================

async function runVerifyScript(req: VerifyScriptRequest): Promise<VerifyScriptResult> {
  if (req.runtime !== 'ts') {
    throw new Error(`Unsupported verification runtime: ${String(req.runtime)}. kovo_verify supports TypeScript only (runtime='ts').`)
  }
  if (typeof req.code !== 'string' || !req.code.trim()) throw new Error('Verification script code must be non-empty.')
  if (Buffer.byteLength(req.code) > maxScriptCodeBytes) throw new Error('Verification script exceeds 256 KiB limit.')
  if (typeof req.nonce !== 'string' || !/^[a-f0-9]{16,128}$/i.test(req.nonce)) throw new Error('Verification nonce is invalid.')
  const timeoutMs = Math.max(1_000, Math.min(req.timeoutMs ?? 90_000, 120_000))
  const dir = await mkdtemp(join(tmpdir(), 'kovo-verify-'))
  const resultPath = join(dir, 'result.json')
  const scriptPath = join(dir, 'candidate.ts')
  try {
    await writeFile(scriptPath, req.code, { mode: 0o600 })
    let sdkBytes = 0
    for (const file of req.sdkFiles ?? []) {
      if (!cleanSdkName.test(file.name)) throw new Error('Invalid verification SDK file name.')
      if (typeof file.content !== 'string') throw new Error('Verification SDK file content must be a string.')
      sdkBytes += Buffer.byteLength(file.content)
      if (sdkBytes > 512 * 1024) throw new Error('Verification SDK files exceed the size limit.')
      await writeFile(join(dir, file.name), file.content, { mode: 0o600 })
    }
    const res = await execTool(process.execPath, ['--max-old-space-size=256', scriptPath], {
      cwd: dir,
      timeoutMs,
      maxBytes: maxOutputBytes,
      env: {
        KOVO_RPC_SOCKET: process.env.KOVO_RPC_SOCKET ?? '/kovo-rpc/verify.sock',
        KOVO_RPC_TOKEN_FILE: process.env.KOVO_RPC_TOKEN_FILE ?? '/kovo-rpc/token',
        KOVO_RPC_CONTEXT_FILE: process.env.KOVO_RPC_CONTEXT_FILE ?? '/kovo-rpc/context.json',
        KOVO_VERIFY_NONCE: req.nonce,
        KOVO_PROOF_RESULT_FILE: resultPath,
      },
    })
    let result: unknown = null
    try {
      const raw = await readFile(resultPath, 'utf8')
      if (Buffer.byteLength(raw) <= 1024 * 1024) result = JSON.parse(raw)
    } catch {
      result = null
    }
    return {
      runtime: 'ts',
      exitCode: res.exitCode,
      result,
      stdout: secretMask(res.stdout).slice(0, maxOutputBytes),
      stderr: secretMask(res.stderr).slice(0, maxOutputBytes),
      durationMs: res.durationMs,
      timedOut: res.timedOut,
    }
  } finally {
    try { await unlink(scriptPath) } catch { /* ignore */ }
  }
}

// ============================================================================
// Deterministic Static AST Re-Verification (op: 'ast_verify')
// ============================================================================

function inferLanguageForFile(filePath: string, engine: 'opengrep' | 'ast-grep'): string | undefined {
  const ext = extname(filePath).toLowerCase()
  if (engine === 'ast-grep') {
    const map: Record<string, string> = {
      '.ts': 'ts', '.mts': 'ts', '.cts': 'ts',
      '.tsx': 'tsx',
      '.js': 'js', '.mjs': 'js', '.cjs': 'js', '.jsx': 'jsx',
      '.py': 'python', '.go': 'go', '.java': 'java',
      '.rb': 'ruby', '.rs': 'rust', '.php': 'php',
      '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
      '.html': 'html', '.css': 'css', '.c': 'c', '.cpp': 'cpp',
    }
    return map[ext]
  }
  const ogMap: Record<string, string> = {
    '.ts': 'typescript', '.mts': 'typescript', '.cts': 'typescript', '.tsx': 'typescript',
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
    '.py': 'python', '.go': 'go', '.java': 'java',
    '.rb': 'ruby', '.rs': 'rust', '.php': 'php',
    '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
    '.tf': 'hcl', '.html': 'html',
  }
  return ogMap[ext]
}

async function runAstVerify(req: AstVerifyRequest): Promise<AstVerifyResult> {
  const startedAt = Date.now()
  if (req.engine !== 'opengrep' && req.engine !== 'ast-grep') {
    throw new Error(`Unsupported AST verification engine: ${String(req.engine)}`)
  }
  if (!Number.isInteger(req.startLine) || !Number.isInteger(req.endLine) || req.startLine < 1 || req.endLine < req.startLine) {
    throw new Error('Invalid startLine/endLine range.')
  }
  if (typeof req.ruleOrPattern !== 'string' || !req.ruleOrPattern.trim() || req.ruleOrPattern.length > 32 * 1024) {
    throw new Error('ruleOrPattern must be a non-empty string under 32 KiB.')
  }

  const repoRoot = resolveRepoRoot(req.repo)
  const targetFile = resolveRepoFile(repoRoot, req.file)
  const content = await readFile(targetFile, 'utf8')
  const fileLines = content.split('\n')
  if (req.startLine > fileLines.length) {
    return {
      verified: false,
      engine: req.engine,
      repo: req.repo,
      file: req.file,
      startLine: req.startLine,
      endLine: req.endLine,
      matchedLines: [],
      codeExcerpt: '',
      matchCount: 0,
      durationMs: Date.now() - startedAt,
      reason: `startLine ${req.startLine} exceeds file length (${fileLines.length} lines).`,
    }
  }
  const clampedEnd = Math.min(req.endLine, fileLines.length)
  const codeExcerpt = secretMask(fileLines.slice(req.startLine - 1, clampedEnd).join('\n')).slice(0, 4096)
  const timeoutMs = Math.max(5_000, Math.min(req.timeoutMs ?? 30_000, 60_000))
  const trimmedRule = req.ruleOrPattern.trim()
  const matchedSpans: Array<{ start: number; end: number }> = []
  let engineError: string | undefined

  if (req.engine === 'ast-grep') {
    const isYamlRule = /(?:^|\n)id:\s*\S/.test(trimmedRule) && /(?:^|\n)rule:\s*/.test(trimmedRule)
    const isBuiltinRuleId = /^[a-z0-9][a-z0-9._-]{2,80}$/i.test(trimmedRule) && !trimmedRule.includes('$') && !trimmedRule.includes(' ')
    let tmpRulePath: string | undefined
    try {
      let args: string[]
      if (isYamlRule) {
        tmpRulePath = join(tmpdir(), `kovo-ast-rule-${randomUUID()}.yaml`)
        await writeFile(tmpRulePath, trimmedRule, { mode: 0o600 })
        args = ['scan', '--rule', tmpRulePath, '--json=compact', targetFile]
      } else if (isBuiltinRuleId && existsSync(join(RULES_ROOT, 'ast-grep', 'sgconfig.yml'))) {
        args = ['scan', '--config', join(RULES_ROOT, 'ast-grep', 'sgconfig.yml'), '--json=compact', targetFile]
      } else {
        const lang = inferLanguageForFile(targetFile, 'ast-grep')
        args = ['run', '--pattern', trimmedRule, ...(lang ? ['--lang', lang] : []), '--json=compact', targetFile]
      }
      const res = await execTool('ast-grep', args, { cwd: repoRoot, timeoutMs })
      if (res.stdout.trim()) {
        const parsed = JSON.parse(res.stdout.trim()) as Array<{ ruleId?: string; range?: { start?: { line?: number }; end?: { line?: number } } }>
        for (const m of Array.isArray(parsed) ? parsed : []) {
          if (isBuiltinRuleId && m.ruleId && m.ruleId !== trimmedRule) continue
          const s = Number(m.range?.start?.line ?? 0) + 1
          const e = m.range?.end?.line !== undefined ? Number(m.range.end.line) + 1 : s
          matchedSpans.push({ start: s, end: e })
        }
      } else if (res.exitCode > 1) {
        engineError = res.stderr.trim().slice(0, 240) || `ast-grep exited ${res.exitCode}`
      }
    } catch (err) {
      engineError = err instanceof Error ? err.message : 'ast-grep execution failed'
    } finally {
      if (tmpRulePath) await unlink(tmpRulePath).catch(() => undefined)
    }
  } else {
    const isYamlRule = /(?:^|\n)rules:\s*/.test(trimmedRule)
    const isBuiltinRuleId = /^[a-z0-9][a-z0-9._-]{2,120}$/i.test(trimmedRule) && !trimmedRule.includes('$') && !trimmedRule.includes(' ')
    let tmpRulePath: string | undefined
    try {
      let args: string[]
      if (isYamlRule) {
        tmpRulePath = join(tmpdir(), `kovo-og-rule-${randomUUID()}.yaml`)
        await writeFile(tmpRulePath, trimmedRule, { mode: 0o600 })
        args = ['scan', '--config', tmpRulePath, '--json', '--no-git-ignore', '--quiet', targetFile]
      } else if (isBuiltinRuleId && existsSync(join(RULES_ROOT, 'opengrep'))) {
        args = ['scan', '--config', join(RULES_ROOT, 'opengrep'), '--json', '--no-git-ignore', '--quiet', targetFile]
      } else {
        const lang = inferLanguageForFile(targetFile, 'opengrep') ?? 'generic'
        args = ['scan', '--pattern', trimmedRule, '--lang', lang, '--json', '--no-git-ignore', '--quiet', targetFile]
      }
      const res = await execTool('opengrep', args, { cwd: repoRoot, timeoutMs })
      if (res.stdout.trim()) {
        const parsed = JSON.parse(res.stdout.trim()) as {
          results?: Array<{ check_id?: string; start?: { line?: number }; end?: { line?: number } }>
        }
        for (const r of parsed.results ?? []) {
          if (isBuiltinRuleId) {
            const cid = String(r.check_id ?? '')
            if (cid !== trimmedRule && !cid.endsWith('.' + trimmedRule)) continue
          }
          const s = Number(r.start?.line ?? 1)
          const e = r.end?.line ? Number(r.end.line) : s
          matchedSpans.push({ start: s, end: e })
        }
      } else if (res.exitCode !== 0) {
        engineError = res.stderr.trim().slice(0, 240) || `opengrep exited ${res.exitCode}`
      }
    } catch (err) {
      engineError = err instanceof Error ? err.message : 'opengrep execution failed'
    } finally {
      if (tmpRulePath) await unlink(tmpRulePath).catch(() => undefined)
    }
  }

  const overlapping = matchedSpans.filter(span => span.start <= req.endLine && span.end >= req.startLine)
  const matchedLines = [...new Set((overlapping.length > 0 ? overlapping : matchedSpans).map(s => s.start))].sort((a, b) => a - b)
  const verified = overlapping.length > 0
  const reason = engineError
    ? `AST verification engine error: ${engineError}`
    : verified
      ? `Verified ${overlapping.length} deterministic ${req.engine} match(es) overlapping ${req.file}:${req.startLine}-${req.endLine}.`
      : matchedSpans.length > 0
        ? `Pattern matched lines [${matchedLines.join(', ')}] in ${req.file}, outside declared range ${req.startLine}-${req.endLine}.`
        : `Zero ${req.engine} matches for rule/pattern in ${req.file}.`

  return {
    verified,
    engine: req.engine,
    repo: req.repo,
    file: req.file,
    startLine: req.startLine,
    endLine: req.endLine,
    matchedLines,
    codeExcerpt,
    matchCount: overlapping.length,
    durationMs: Date.now() - startedAt,
    reason,
  }
}

const CALL_GRAPH_EXTS = new Set(['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.java', '.php', '.rb'])

async function runCallGraphIndex(
  req: CallGraphRequest,
  id: string,
  inputDirectory: string,
  stagedContents: Map<string, string>,
): Promise<CallGraphResult> {
  const startedAt = Date.now()
  const repoRoot = resolveRepoRoot(req.repo)
  const targets = resolveRepoSubpaths(repoRoot, req.paths)
  const allFiles = walkFiles(targets, 1200)
  const fileInputs: Array<{ file: string; content: string }> = []
  let totalBytes = 0
  for (const abs of allFiles) {
    if (!CALL_GRAPH_EXTS.has(extname(abs).toLowerCase())) continue
    try {
      const st = lstatSync(abs)
      if (!st.isFile() || st.isSymbolicLink() || st.size > 512 * 1024) continue
      if (totalBytes + st.size > 8 * 1024 * 1024) break
      const content = readFileSync(abs, 'utf8')
      totalBytes += st.size
      fileInputs.push({ file: toRepoRelative(repoRoot, abs), content })
    } catch {
      // skip unreadable files
    }
  }

  const built = buildCallGraphFromFiles(fileInputs, {
    maxDepth: req.maxDepth,
    customGuardPatterns: req.customGuardPatterns,
    customSanitizerPatterns: req.customSanitizerPatterns,
    customSinkPatterns: req.customSinkPatterns,
  })
  const maskedPaths = built.taintPaths.map(tp => ({
    ...tp,
    maskedSnippet: secretMask(tp.maskedSnippet),
  }))

  const result: CallGraphResult = {
    repo: req.repo,
    filesScanned: built.filesScanned,
    nodes: built.nodes.slice(0, 600),
    edges: built.edges.slice(0, 1200),
    taintPaths: maskedPaths.slice(0, 200),
    durationMs: Date.now() - startedAt,
  }

  const safeId = id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 48) || randomUUID().slice(0, 12)
  const relEvidence = `call-graph/${safeId}.json`
  const fullJson = JSON.stringify({ ...result, nodes: built.nodes, edges: built.edges, taintPaths: maskedPaths }, null, 2)
  if (Buffer.byteLength(fullJson) <= maxFileBytes) {
    await stageFile(inputDirectory, relEvidence, fullJson)
    stagedContents.set(relEvidence, fullJson)
    result.evidencePath = '/evidence/' + relEvidence
  }
  return result
}

// ============================================================================
// Core Sandbox & Backwards-Compatible Staging / Exec / Session Modes
// ============================================================================

async function stageFile(root: string, name: string, content: string) {
  if (!cleanPath.test(name) || name.includes('..')) throw new Error('Invalid input path.')
  if (Buffer.byteLength(content) > maxFileBytes) throw new Error('Staged file exceeds limit.')
  const full = join(root, name)
  await mkdir(dirname(full), { recursive: true, mode: 0o700 })
  await writeFile(full, content, { mode: 0o400 })
}

function spillPayload(payload: Record<string, unknown>): { path: string; bytes: number; sha256: string } {
  mkdirSync(IPC_SPILL_DIR, { recursive: true, mode: 0o700 })
  const path = join(IPC_SPILL_DIR, `${randomUUID()}.json`)
  const text = JSON.stringify(payload)
  // 0644: one-shot spills are read by the host through a tmpfs bind; sessions read via exec.
  writeFileSync(path, text, { mode: 0o644 })
  return { path, bytes: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex') }
}

/**
 * Emit one NDJSON response. Oversized payloads become a tmpfs file pointer so the host's
 * 64 KiB line guard never has to terminate the session (and the full output survives).
 */
function respondNdjson(payload: Record<string, unknown>) {
  const line = JSON.stringify(payload)
  if (Buffer.byteLength(line) <= IPC_SPILL_THRESHOLD) {
    process.stdout.write(line + '\n')
    return
  }
  const resultRef = spillPayload(payload)
  process.stdout.write(JSON.stringify({ id: payload.id, ok: payload.ok, resultRef }) + '\n')
}

/** One-shot responses keep their legacy shape unless they exceed the NDJSON line budget. */
function writeOneShot(result: unknown) {
  const line = JSON.stringify(result)
  if (Buffer.byteLength(line) <= IPC_SPILL_THRESHOLD) {
    process.stdout.write(line)
    return
  }
  process.stdout.write(JSON.stringify({ resultRef: spillPayload(result as Record<string, unknown>) }))
}

const DEFAULT_EXEC_TIMEOUT_MS = 60_000
const MIN_EXEC_TIMEOUT_MS = 1_000
const MAX_EXEC_TIMEOUT_MS = 120_000

function clampExecTimeoutMs(timeoutMs?: number): number {
  const numeric = typeof timeoutMs === 'number' && Number.isFinite(timeoutMs)
    ? Math.trunc(timeoutMs)
    : DEFAULT_EXEC_TIMEOUT_MS
  return Math.max(MIN_EXEC_TIMEOUT_MS, Math.min(numeric, MAX_EXEC_TIMEOUT_MS))
}

async function execCommand(
  shell: Bash,
  scratch: InMemoryFs,
  command: string,
  outputNames: string[],
  timeoutMs = DEFAULT_EXEC_TIMEOUT_MS,
) {
  const capped = clampExecTimeoutMs(timeoutMs)
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    // Cooperative cancellation only: the container and session stay alive. The previous
    // `process.exit(124)` killed the worker for a single slow command.
    controller.abort(new Error('Worker command exceeded its deadline.'))
  }, capped)
  timer.unref()
  try {
    const execPromise = shell.exec(command, { signal: controller.signal })
    let guard: ReturnType<typeof setTimeout> | undefined
    const timeoutPromise = new Promise<null>(resolve => {
      guard = setTimeout(() => resolve(null), capped)
      guard.unref()
    })
    execPromise.finally(() => { if (guard) clearTimeout(guard) }).catch(() => undefined)
    const result = await Promise.race([execPromise, timeoutPromise])
    if (result === null || timedOut) {
      return {
        exitCode: 124,
        stdout: '',
        stderr: 'Worker command exceeded its deadline and was cancelled.',
        outputs: {},
        timedOut: true,
      }
    }
    const outputs: Record<string, string> = {}
    for (const name of outputNames) {
      const path = '/work/' + name
      if (!cleanOutputName.test(name) || !(await scratch.exists(path))) continue
      const info = await scratch.lstat(path)
      if (info.isFile && !info.isSymbolicLink && info.size <= maxOutputBytes) {
        outputs[name] = await scratch.readFile(path)
      }
    }
    return {
      exitCode: result.exitCode,
      stdout: result.stdout.slice(0, maxOutputBytes),
      stderr: result.stderr.slice(0, maxOutputBytes),
      outputs,
      timedOut: false,
    }
  } catch (error) {
    if (timedOut || controller.signal.aborted) {
      return {
        exitCode: 124,
        stdout: '',
        stderr: 'Worker command exceeded its deadline and was cancelled.',
        outputs: {},
        timedOut: true,
      }
    }
    throw error
  } finally {
    clearTimeout(timer)
  }
}

async function createSandbox(maxExecutionTimeMs = MAX_EXEC_TIMEOUT_MS) {
  let inputDirectory: string
  try {
    const lst = lstatSync('/evidence')
    if (lst.isSymbolicLink()) {
      await mkdir(EVIDENCE_SYMLINK_TARGET, { recursive: true, mode: 0o700 })
      inputDirectory = EVIDENCE_SYMLINK_TARGET
    } else {
      inputDirectory = await mkdtemp(join(tmpdir(), 'kovo-inputs-'))
    }
  } catch {
    inputDirectory = await mkdtemp(join(tmpdir(), 'kovo-inputs-'))
  }

  const scratch = new InMemoryFs({}, { maxTotalBytes: maxScratchBytes })
  scratch.mkdirSync('/work')
  const mounts = [{
    mountPoint: '/evidence',
    filesystem: new OverlayFs({
      root: inputDirectory,
      mountPoint: '/',
      readOnly: true,
      allowSymlinks: false,
      maxFileReadSize: maxFileBytes,
    }),
  }]
  if (existsSync(REPOS_ROOT)) {
    mounts.push({
      mountPoint: '/repos',
      filesystem: new OverlayFs({
        root: REPOS_ROOT,
        mountPoint: '/',
        readOnly: true,
        allowSymlinks: false,
        maxFileReadSize: maxFileBytes,
      }),
    })
  }
  const fs = new MountableFs({
    base: scratch,
    mounts,
  })
  const boundedExecutionTimeMs = clampExecTimeoutMs(maxExecutionTimeMs)
  const shell = new Bash({
    cwd: '/work',
    fs,
    executionLimitProfile: 'hardened',
    executionLimits: {
      maxExecutionTimeMs: boundedExecutionTimeMs,
    },
    python: false,
    javascript: false,
  })
  return { inputDirectory, scratch, shell }
}

async function runOneShot() {
  const source = readFileSync(0, 'utf8')
  if (Buffer.byteLength(source) > maxInputBytes) throw new Error('Assignment inputs exceed the worker limit.')
  const job = JSON.parse(source) as OneShotInput
  if (job.op === 'ast_verify') {
    const result = await runAstVerify(job)
    process.stdout.write(JSON.stringify(result))
    return
  }
  const effectiveTimeoutMs = clampExecTimeoutMs(job.timeoutMs)
  const { inputDirectory, scratch, shell } = await createSandbox(effectiveTimeoutMs)
  for (const input of job.files) {
    await stageFile(inputDirectory, input.name, input.content)
  }
  const result = await execCommand(shell, scratch, job.command, job.outputs, effectiveTimeoutMs)
  writeOneShot(result)
}

async function runSession() {
  const { inputDirectory, scratch, shell } = await createSandbox(MAX_EXEC_TIMEOUT_MS)
  const stagedContents = new Map<string, string>()
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity })
  const respond = (payload: Record<string, unknown>) => {
    respondNdjson(payload)
  }
  for await (const line of rl) {
    const trimmed = line.trim()
    if (!trimmed) continue
    let msg: SessionMessage
    try {
      msg = JSON.parse(trimmed) as SessionMessage
    } catch {
      respond({ id: 'parse', ok: false, error: 'Invalid NDJSON command.' })
      continue
    }
    try {
      if (msg.op === 'shutdown') {
        respond({ id: msg.id, ok: true })
        break
      }
      if (msg.op === 'stage') {
        await stageFile(inputDirectory, msg.name, msg.content)
        stagedContents.set(msg.name, msg.content)
        respond({ id: msg.id, ok: true, path: '/evidence/' + msg.name })
      } else if (msg.op === 'exec') {
        const result = await execCommand(shell, scratch, msg.command, msg.outputs, clampExecTimeoutMs(msg.timeoutMs))
        respond({ id: msg.id, ok: true, result })
      } else if (msg.op === 'analyze') {
        if (msg.tool === 'call-graph' && typeof msg.args?.repo === 'string' && !Array.isArray(msg.args?.files)) {
          const cgResult = await runCallGraphIndex(msg.args as unknown as CallGraphRequest, msg.id, inputDirectory, stagedContents)
          respond({ id: msg.id, ok: true, result: cgResult })
        } else {
          const result = runAnalyzer(msg.tool, msg.args, (name: string) => {
            const clean = name.replace(/^\/evidence\//, '')
            const cached = stagedContents.get(clean)
            if (cached !== undefined) return cached
            throw new Error('Staged evidence file not found: ' + clean)
          })
          respond({ id: msg.id, ok: true, result })
        }
      } else if (msg.op === 'call_graph') {
        const result = await runCallGraphIndex(msg, msg.id, inputDirectory, stagedContents)
        respond({ id: msg.id, ok: true, result })
      } else if (msg.op === 'sast') {
        const result = await runSastScan(msg, msg.id, inputDirectory, stagedContents)
        respond({ id: msg.id, ok: true, result })
      } else if (msg.op === 'script') {
        const result = await runOfflineScript(msg, inputDirectory)
        respond({ id: msg.id, ok: true, result })
      } else if (msg.op === 'verify') {
        const result = await runVerifyScript(msg)
        respond({ id: msg.id, ok: true, result })
      } else if (msg.op === 'ast_verify') {
        const result = await runAstVerify(msg)
        respond({ id: msg.id, ok: true, result })
      } else {
        respond({ id: (msg as { id?: string }).id ?? 'unknown', ok: false, error: 'Unsupported worker operation.' })
      }
    } catch (error) {
      respond({ id: msg.id, ok: false, error: error instanceof Error ? error.message : 'Worker operation failed.' })
    }
  }
}

const sessionMode = process.argv.includes('--session')
;(sessionMode ? runSession() : runOneShot()).catch(() => {
  process.stderr.write('The evidence worker could not execute the operation.\n')
  process.exitCode = 1
})
