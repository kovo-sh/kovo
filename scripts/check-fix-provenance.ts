#!/usr/bin/env node
/**
 * Fix Provenance Guard (`R3-10`, Step 2).
 *
 * Inspects each commit in `--base <ref>..HEAD` (or `HEAD` when `--head` / default) and verifies
 * that every commit touching a confirmation-kernel file (loaded from `scripts/kernel-manifest.json`
 * when present, falling back to the canonical 20-file confirmation-kernel set) OR whose subject
 * references an audit finding / roadmap ID (`R[1-4]-[CHML]-`, `R[2-3]-\d+`) carries at least one
 * `Fixes: <ID>` trailer whose `<ID>` resolves in `plans/*.md`.
 *
 * Also validates that any `Fixes: <ID>` trailer present on any inspected commit resolves in
 * `plans/*.md` (catching dead/typo IDs immediately).
 *
 * Usage:
 *   node scripts/check-fix-provenance.ts --base HEAD~1
 *   node scripts/check-fix-provenance.ts --head
 *   node scripts/check-fix-provenance.ts --base origin/main --json
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  parseKernelCosmeticTrailer,
  verifyCosmeticKernelDiff,
} from './lib/kernel-cosmetic-ast.ts'

/** Canonical 20-file confirmation-kernel fallback set used when `scripts/kernel-manifest.json` is absent. */
export const FALLBACK_CONFIRMATION_KERNEL_FILES: readonly string[] = [
  'src/server/agent-script-proof.ts',
  'src/server/causal-proof-compiler.ts',
  'src/server/composite-autodag.ts',
  'src/server/composite-receipt.ts',
  'src/server/composite-terminal.ts',
  'src/server/exec-verify.ts',
  'src/server/floor-recipe-engine.ts',
  'src/server/floor-recipes.ts',
  'src/server/host-fact-log.ts',
  'src/server/oracle-invariants.ts',
  'src/server/proof-receipt.ts',
  'src/server/replay-verifier.ts',
  'src/server/retest-health.ts',
  'src/server/terminal-oracle-registry.ts',
  'src/server/v8-oracle-families.ts',
  'src/server/v8-oracle-hydrate.ts',
  'src/server/verify-claims.ts',
  'src/server/verify-prove-handlers.ts',
  'src/server/verify-rpc.ts',
  'src/server/verify-support.ts',
]

export const DEFAULT_KERNEL_MANIFEST_FILE = 'scripts/kernel-manifest.json'
export const DEFAULT_PLANS_DIR = 'plans'

/** Matches commit subjects referencing round 1-4 audit finding IDs or round 2-3 quality IDs. */
export const AUDIT_SUBJECT_ID_RE = /\b(?:R[1-4]-[CHML]-(?:\d+[a-z]?)?|R[2-3]-\d+[a-z]?)\b/gi

const FIXES_TRAILER_LINE_RE = /^\s*Fixes:\s*(.*)$/gim
const EXTRA_FIX_ID_TOKEN_RE = /^(?:R[1-4]-[CHML]-\d+[a-z]?|R[2-3]-\d+[a-z]?|CQ-\d+[a-z]?|[CHML]-\d+[a-z]?)$/i

export interface CommitProvenanceInput {
  sha: string
  subject: string
  message: string
  files: string[]
  parentSha?: string | null
  filePairs?: ReadonlyMap<string, { base: string | null; head: string | null }>
}

export interface CommitProvenanceResult {
  sha: string
  subject: string
  kernelFilesTouched: string[]
  subjectAuditIds: string[]
  requiresFixes: boolean
  cosmeticVerified?: boolean
  cosmeticReason?: string | null
  fixesIds: string[]
  resolvedIds: Record<string, string[]>
  unresolvedIds: string[]
  violations: string[]
  ok: boolean
}

export interface FixProvenanceReport {
  ok: boolean
  rootDir: string
  baseRef: string | null
  kernelSource: 'manifest' | 'fallback'
  kernelFileCount: number
  planFilesScanned: number
  commitsChecked: number
  failedCommits: number
  commits: CommitProvenanceResult[]
  error?: string
  durationMs: number
}

export interface FixProvenanceOptions {
  rootDir?: string
  baseRef?: string | null
  headOnly?: boolean
  manifestFile?: string
  plansDir?: string
  /** Optional programmatic commit list (bypasses git subprocess in unit tests). */
  commits?: CommitProvenanceInput[]
}

function normalizeRepoPath(p: string): string {
  return p.trim().replace(/\\/g, '/').replace(/^\.\//, '')
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/** Load confirmation-kernel files from `scripts/kernel-manifest.json` if present, else 20-file fallback. */
export function loadConfirmationKernelFiles(
  rootDir: string,
  manifestFile = DEFAULT_KERNEL_MANIFEST_FILE,
): { source: 'manifest' | 'fallback'; files: Set<string> } {
  const abs = resolve(rootDir, manifestFile)
  if (existsSync(abs)) {
    try {
      const raw = JSON.parse(readFileSync(abs, 'utf8')) as unknown
      const collected = new Set<string>()
      const addPath = (val: unknown) => {
        if (typeof val === 'string' && val.trim().endsWith('.ts')) {
          collected.add(normalizeRepoPath(val))
        }
      }
      if (Array.isArray(raw)) {
        for (const item of raw) {
          if (typeof item === 'string') addPath(item)
          else if (item && typeof item === 'object' && 'file' in item) addPath((item as { file?: unknown }).file)
        }
      } else if (raw && typeof raw === 'object') {
        const obj = raw as Record<string, unknown>
        for (const key of ['files', 'kernelFiles', 'modules']) {
          const arr = obj[key]
          if (Array.isArray(arr)) {
            for (const item of arr) {
              if (typeof item === 'string') addPath(item)
              else if (item && typeof item === 'object' && 'file' in item) addPath((item as { file?: unknown }).file)
            }
          }
        }
        for (const key of ['entries', 'functions', 'symbols']) {
          const arr = obj[key]
          if (Array.isArray(arr)) {
            for (const item of arr) {
              if (item && typeof item === 'object' && 'file' in item) addPath((item as { file?: unknown }).file)
            }
          }
        }
      }
      if (collected.size > 0) {
        return { source: 'manifest', files: collected }
      }
    } catch {
      // Fall through to canonical fallback if manifest is unreadable/malformed.
    }
  }
  return { source: 'fallback', files: new Set(FALLBACK_CONFIRMATION_KERNEL_FILES) }
}

/** Load all `plans/*.md` markdown documents for ID resolution. */
export function loadPlanDocuments(rootDir: string, plansDir = DEFAULT_PLANS_DIR): Array<{ file: string; content: string }> {
  const absDir = resolve(rootDir, plansDir)
  if (!existsSync(absDir)) return []
  const docs: Array<{ file: string; content: string }> = []
  for (const entry of readdirSync(absDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.md')) continue
    const rel = `${plansDir.replace(/\\/g, '/').replace(/\/+$/, '')}/${entry.name}`
    docs.push({ file: rel, content: readFileSync(join(absDir, entry.name), 'utf8') })
  }
  docs.sort((a, b) => a.file.localeCompare(b.file))
  return docs
}

/** Resolve an ID token against loaded `plans/*.md` documents with strict identifier boundaries. */
export function resolveIdInPlans(id: string, plans: ReadonlyArray<{ file: string; content: string }>): string[] {
  const cleaned = id.trim()
  if (!cleaned) return []
  const re = new RegExp(`(?<![A-Za-z0-9_-])${escapeRegExp(cleaned)}(?![A-Za-z0-9_-])`, 'i')
  const matches: string[] = []
  for (const doc of plans) {
    if (re.test(doc.content)) matches.push(doc.file)
  }
  return matches
}

/** Extract audit/quality IDs mentioned in a commit subject line. */
export function extractSubjectAuditIds(subject: string): string[] {
  const ids: string[] = []
  const seen = new Set<string>()
  AUDIT_SUBJECT_ID_RE.lastIndex = 0
  for (const m of subject.matchAll(AUDIT_SUBJECT_ID_RE)) {
    const raw = m[0]?.trim()
    if (!raw) continue
    const upper = raw.toUpperCase()
    if (!seen.has(upper)) {
      seen.add(upper)
      ids.push(raw)
    }
  }
  return ids
}

/** Extract all `<ID>` tokens from `Fixes: <ID>` trailer lines in a commit message. */
export function extractFixesTrailerIds(message: string): string[] {
  const ids: string[] = []
  const seen = new Set<string>()
  FIXES_TRAILER_LINE_RE.lastIndex = 0
  for (const match of message.matchAll(FIXES_TRAILER_LINE_RE)) {
    const value = (match[1] ?? '').trim()
    if (!value) continue
    for (const clause of value.split(',')) {
      const tokens = clause.trim().split(/\s+/).filter(Boolean)
      for (let i = 0; i < tokens.length; i += 1) {
        const cleaned = tokens[i]!.replace(/^[`([{"']+|[`)\]}"'.,;:]+$/g, '')
        if (!cleaned) continue
        if (i === 0 || EXTRA_FIX_ID_TOKEN_RE.test(cleaned)) {
          const upper = cleaned.toUpperCase()
          if (!seen.has(upper)) {
            seen.add(upper)
            ids.push(cleaned)
          }
        }
      }
    }
  }
  return ids
}

/** Evaluate fix provenance requirements for a single commit. */
export function evaluateCommitProvenance(
  commit: CommitProvenanceInput,
  kernelFiles: ReadonlySet<string>,
  plans: ReadonlyArray<{ file: string; content: string }>,
  rootDir?: string,
): CommitProvenanceResult {
  const kernelFilesTouched = commit.files
    .map(normalizeRepoPath)
    .filter(f => kernelFiles.has(f))
    .sort()
  const subjectAuditIds = extractSubjectAuditIds(commit.subject)
  const fixesIds = extractFixesTrailerIds(commit.message)

  const resolvedIds: Record<string, string[]> = {}
  const unresolvedIds: string[] = []
  for (const id of fixesIds) {
    const hits = resolveIdInPlans(id, plans)
    if (hits.length > 0) {
      resolvedIds[id] = hits
    } else {
      unresolvedIds.push(id)
    }
  }

  const violations: string[] = []
  let cosmeticVerified = false
  let cosmeticReason: string | null = null
  const cosmetic = parseKernelCosmeticTrailer(commit.message)
  if (kernelFilesTouched.length > 0 && cosmetic.present) {
    if (cosmetic.malformed) {
      violations.push(
        `malformed_kernel_cosmetic_trailer: commit ${commit.sha.slice(0, 8)} has malformed Kernel-cosmetic trailer ("${cosmetic.malformed}"); expected "Kernel-cosmetic: <reason (min 6 chars)>"`,
      )
    } else {
      const astRes = verifyCosmeticKernelDiff({
        rootDir: rootDir ?? resolve(join(fileURLToPath(import.meta.url), '../..')),
        baseRef: commit.parentSha ?? null,
        headRef: commit.sha,
        kernelFiles: kernelFilesTouched,
        filePairs: commit.filePairs,
      })
      if (astRes.ok) {
        cosmeticVerified = true
        cosmeticReason = cosmetic.reason
      } else {
        const detail = astRes.failedFiles.map(f => `${f.file}: ${f.reason}`).join('; ')
        violations.push(
          `invalid_kernel_cosmetic: commit ${commit.sha.slice(0, 8)} failed AST cosmetic verification: ${detail}`,
        )
      }
    }
  }

  const requiresFixes = (kernelFilesTouched.length > 0 && !cosmeticVerified) || subjectAuditIds.length > 0

  if (requiresFixes && fixesIds.length === 0) {
    const reasons: string[] = []
    if (kernelFilesTouched.length > 0 && !cosmeticVerified) {
      reasons.push(`touches ${kernelFilesTouched.length} confirmation-kernel file(s): ${kernelFilesTouched.join(', ')}`)
    }
    if (subjectAuditIds.length > 0) {
      reasons.push(`subject references audit ID(s): ${subjectAuditIds.join(', ')}`)
    }
    violations.push(`missing_fixes_trailer: commit ${commit.sha.slice(0, 8)} ${reasons.join(' and ')} — add a 'Fixes: <ID>' trailer resolving in plans/*.md`)
  }
  if (unresolvedIds.length > 0) {
    violations.push(
      `unresolvable_fixes_id: commit ${commit.sha.slice(0, 8)} has Fixes ID(s) not found in plans/*.md: ${unresolvedIds.join(', ')}`,
    )
  }

  return {
    sha: commit.sha,
    subject: commit.subject,
    kernelFilesTouched,
    subjectAuditIds,
    requiresFixes,
    ...(cosmeticVerified ? { cosmeticVerified: true, cosmeticReason } : {}),
    fixesIds,
    resolvedIds,
    unresolvedIds,
    violations,
    ok: violations.length === 0,
  }
}

function readGitCommits(rootDir: string, baseRef: string | null, headOnly: boolean): CommitProvenanceInput[] {
  const revArgs =
    baseRef && !headOnly
      ? ['-C', rootDir, 'rev-list', '--no-merges', '--reverse', `${baseRef}..HEAD`]
      : ['-C', rootDir, 'rev-list', '-n', '1', 'HEAD']
  const rawShas = execFileSync('git', revArgs, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
  if (!rawShas) return []
  const shas = rawShas.split(/\r?\n/).map(s => s.trim()).filter(Boolean)

  const commits: CommitProvenanceInput[] = []
  for (const sha of shas) {
    const rawMeta = execFileSync('git', ['-C', rootDir, 'show', '-s', '--format=%s%x00%B', sha], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const sepIdx = rawMeta.indexOf('\0')
    const subject = (sepIdx >= 0 ? rawMeta.slice(0, sepIdx) : rawMeta).trim()
    const message = (sepIdx >= 0 ? rawMeta.slice(sepIdx + 1) : rawMeta).trim()
    const rawFiles = execFileSync(
      'git',
      ['-C', rootDir, 'diff-tree', '--no-commit-id', '--name-only', '-r', '--root', sha],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    )
    const files = rawFiles
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean)
    let parentSha: string | null = null
    try {
      const p = execFileSync('git', ['-C', rootDir, 'rev-parse', '--verify', `${sha}^`], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim()
      if (p) parentSha = p
    } catch {
      parentSha = null
    }
    commits.push({ sha, subject, message, files, parentSha })
  }
  return commits
}

/** Run the fix-provenance check over a git range or supplied commits. */
export function runFixProvenanceCheck(options: FixProvenanceOptions = {}): FixProvenanceReport {
  const t0 = Date.now()
  const rootDir = resolve(options.rootDir ?? join(fileURLToPath(import.meta.url), '../..'))
  const baseRef = options.baseRef ?? null
  const headOnly = Boolean(options.headOnly)
  const kernel = loadConfirmationKernelFiles(rootDir, options.manifestFile ?? DEFAULT_KERNEL_MANIFEST_FILE)
  const plans = loadPlanDocuments(rootDir, options.plansDir ?? DEFAULT_PLANS_DIR)

  let commits: CommitProvenanceInput[]
  if (options.commits) {
    commits = options.commits
  } else {
    try {
      commits = readGitCommits(rootDir, baseRef, headOnly)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      return {
        ok: false,
        rootDir,
        baseRef,
        kernelSource: kernel.source,
        kernelFileCount: kernel.files.size,
        planFilesScanned: plans.length,
        commitsChecked: 0,
        failedCommits: 0,
        commits: [],
        error: `Failed to read git commits (${baseRef ? `${baseRef}..HEAD` : 'HEAD'}): ${msg}`,
        durationMs: Date.now() - t0,
      }
    }
  }

  const results = commits.map(c => evaluateCommitProvenance(c, kernel.files, plans, rootDir))
  const failedCommits = results.filter(r => !r.ok).length

  return {
    ok: failedCommits === 0,
    rootDir,
    baseRef,
    kernelSource: kernel.source,
    kernelFileCount: kernel.files.size,
    planFilesScanned: plans.length,
    commitsChecked: results.length,
    failedCommits,
    commits: results,
    durationMs: Date.now() - t0,
  }
}

function parseArgs(argv: string[]): FixProvenanceOptions & { json: boolean } {
  const opts: FixProvenanceOptions & { json: boolean } = { json: false }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--base' && argv[i + 1]) opts.baseRef = argv[++i]!
    else if (arg === '--head') opts.headOnly = true
    else if (arg === '--root' && argv[i + 1]) opts.rootDir = argv[++i]!
    else if (arg === '--manifest' && argv[i + 1]) opts.manifestFile = argv[++i]!
    else if (arg === '--plans-dir' && argv[i + 1]) opts.plansDir = argv[++i]!
    else if (arg === '--json') opts.json = true
  }
  return opts
}

function main(): void {
  const opts = parseArgs(process.argv.slice(2))
  const report = runFixProvenanceCheck(opts)
  if (opts.json) {
    console.log(JSON.stringify(report, null, 2))
  } else {
    const status = report.ok ? 'PASS' : 'FAIL'
    const rangeLabel = report.baseRef ? `${report.baseRef}..HEAD` : 'HEAD'
    console.log(
      `check-fix-provenance [${rangeLabel}] ${status} (${report.durationMs}ms): ` +
        `checked ${report.commitsChecked} commit(s), failed=${report.failedCommits}, ` +
        `kernelFiles=${report.kernelFileCount} (${report.kernelSource}), plans=${report.planFilesScanned}`,
    )
    if (report.error) console.error(`  ERROR: ${report.error}`)
    for (const c of report.commits) {
      if (!c.ok) {
        for (const v of c.violations) {
          console.error(`  FAIL  ${v}`)
        }
      } else if (c.cosmeticVerified) {
        console.log(
          `  OK    ${c.sha.slice(0, 8)} ${c.subject} (Kernel-cosmetic verified by AST: ${c.cosmeticReason})`,
        )
      } else if (c.requiresFixes) {
        const resolved = Object.entries(c.resolvedIds)
          .map(([id, files]) => `${id} -> ${files[0]}`)
          .join(', ')
        console.log(`  OK    ${c.sha.slice(0, 8)} ${c.subject} (Fixes: ${resolved})`)
      }
    }
  }
  if (!report.ok) process.exit(1)
}

const isMain = process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url
if (isMain) {
  main()
}
