#!/usr/bin/env node
/**
 * Contract-Change Diff Lint (`cq-3-merge-gate` / `R2-03`, plans/claude_quality_2.md §3).
 *
 * Inspects a git diff for edits to:
 *   1. Exported tunable/cap constants (`*_DEFAULT`, `*_BUDGET`, `*_MS`, `*_CAP`, `*_MAX_*`,
 *      `MAX_*`, `*_IN_FLIGHT`, `*_RPS`, `*_LIMIT`, plus camelCase `default*`/`max*` tunables)
 *      in `src/server/**`, `src/domain.ts`, or `scripts/benchmark-core.ts`, OR
 *   2. Numeric literals inside `assert.*` lines of gate, precision-kernel, `tests/r2-*`,
 *      `tests/r3-*`, or `tests/*security*` test suites.
 *
 * When any such contract edit is detected in committed changes, the commit range MUST carry
 * a `Contract-change:` trailer (one dedicated `Contract-change: <id> <reason>` trailer line per
 * changed tunable/gate ID; one generic trailer cannot cover multiple IDs).
 *
 * Uncommitted working-tree edits warn by default (`--allow-uncommitted`) so local iteration is
 * never blocked before commit; pass `--strict-uncommitted` or `--staged` to enforce strictly.
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
// Canonical KERNEL_TEST_RE imported from scripts/test-tiers.ts:
// ^tests\/.*(?:oracle|receipt|confirm-consistency|floor-recipe|verify-kernel|dispatch-funnel|contract-canary|path-parity|taxonomy-conformance).*\.test\.ts$
import {
  GATE_TEST_EXACT,
  KERNEL_TEST_RE,
  hasProtectedTestTag,
  parseTestFileTags,
  readTestFileTags,
} from './test-tiers.ts'
import {
  parseKernelCosmeticTrailer,
  verifyCosmeticKernelDiff,
} from './lib/kernel-cosmetic-ast.ts'

export type ContractChangeKind = 'tunable_constant_change' | 'gate_assert_literal_change'

export interface ContractChangeHit {
  kind: ContractChangeKind
  id: string
  file: string
  line: number
  symbol?: string
  before: string
  after: string
}

export interface ParsedDiffHunk {
  oldStart: number
  newStart: number
  removed: Array<{ lineNo: number; text: string }>
  added: Array<{ lineNo: number; text: string }>
}

export interface ParsedDiffFile {
  file: string
  hunks: ParsedDiffHunk[]
  deleted?: boolean
}

export interface ParityCorpusCovers {
  files: string[]
  classes: string[]
}

export interface ParityCorpusCaseMeta {
  id: string
  file: string
  side: 'tp' | 'fp' | 'retest' | null
  covers?: ParityCorpusCovers
}

export interface CommitParitySlice {
  sha: string
  diffText: string
  commitMessage: string
  baseRef?: string | null
  headRef?: string | null
  filePairs?: ReadonlyMap<string, { base: string | null; head: string | null }>
}

export interface MissingLooseningSide {
  file: string
  missing: Array<'tp' | 'fp'>
}

export interface CommitParityEvalResult {
  sha: string
  required: boolean
  ok: boolean
  warned: boolean
  kernelFilesTouched: string[]
  corpusFilesTouched: string[]
  parityCaseTrailers: string[]
  validParityCaseIds: string[]
  invalidParityCaseIds: string[]
  uncoveredKernelFiles: string[]
  loosening: boolean
  missingLooseningSides: MissingLooseningSide[]
  reviewedByTrailers: string[]
  overridden: boolean
  overrideTrailer: string | null
  cosmeticVerified?: boolean
  cosmeticReason?: string | null
  reason: string | null
}

export interface ParityGateEvalResult {
  required: boolean
  ok: boolean
  warned: boolean
  kernelFilesTouched: string[]
  corpusFilesTouched: string[]
  parityCaseTrailers: string[]
  validParityCaseIds: string[]
  invalidParityCaseIds: string[]
  uncoveredKernelFiles: string[]
  loosening: boolean
  missingLooseningSides: MissingLooseningSide[]
  reviewedByTrailers: string[]
  overridden: boolean
  overrideTrailer: string | null
  cosmeticVerified?: boolean
  cosmeticReason?: string | null
  commitResults?: CommitParityEvalResult[]
  reason: string | null
}

export interface ContractChangeEvalResult {
  ok: boolean
  mode: 'strict' | 'warn'
  sourceLabel: string
  hits: ContractChangeHit[]
  trailerPresent: boolean
  trailerValue: string | null
  trailers: string[]
  missingTrailerIds: string[]
  warned: boolean
  parity?: ParityGateEvalResult
}

export interface ContractChangeRepoResult {
  ok: boolean
  rootDir: string
  committed: ContractChangeEvalResult
  uncommitted: ContractChangeEvalResult | null
  durationMs: number
}

export interface CheckGitRepoOptions {
  rootDir?: string
  baseRef?: string | null
  stagedOnly?: boolean
  checkHead?: boolean
  strictUncommitted?: boolean
  strictPerId?: boolean
  commitMessageOverride?: string | null
}

export const EXTENDED_CONTRACT_TEST_RE = /^tests\/(?:r2-|r3-|.*security).*\.test\.ts$/

export const CONFIRMATION_KERNEL_FILE_RE =
  /^src\/server\/(?:(?:replay-verifier|verify-claims|proof-receipt|floor-recipe[^/]*|composite-receipt|composite-terminal|composite-autodag|oracle-invariants|exec-verify|v8-oracle-[^/]*|verify-support|terminal-oracle-registry|verify-prove-handlers|verify-rpc|agent-script-proof|host-fact-log|causal-proof-compiler|retest-health)|proof-kernel\/[^/]+)\.ts$/

const SCREAMING_TUNABLE_EXPORT_RE =
  /^\s*export\s+(?:const|let)\s+((?:[A-Z][A-Z0-9_]*_(?:DEFAULT|BUDGET|MS|CAP|IN_FLIGHT|RPS|LIMIT)|(?:[A-Z][A-Z0-9_]*_)?MAX_[A-Z0-9_]+))\b[^=]*=\s*(.+)$/
const CAMEL_TUNABLE_EXPORT_RE =
  /^\s*export\s+(?:const|let)\s+((?:(?:default|max)[A-Z][A-Za-z0-9]*|[a-z][A-Za-z0-9]*(?:Default|Budget|Ms|Cap|InFlight|Rps|Limit)))\b[^=]*=\s*(.+)$/
const FUNCTION_RHS_RE = /^(?:async\s+)?(?:\(|function\b|<[^>]+>\s*\()/
const ASSERT_CALL_RE = /\bassert\.[A-Za-z_]\w*\s*\(/
const NUMERIC_LITERAL_RE = /(?<![A-Za-z0-9_$])(?:\d[\d_]*(?:\.[\d_]+)?|\.\d[\d_]*)(?![A-Za-z0-9_$])/g
const CONTRACT_CHANGE_TRAILER_RE = /^\s*Contract-change:\s*(.+)$/im
const CONTRACT_CHANGE_TRAILER_ALL_RE = /^\s*Contract-change:\s*(.+)$/gim
const PARITY_CASE_TRAILER_ALL_RE = /^\s*Parity-case:\s*(.+)$/gim
const KERNEL_CHANGE_TRAILER_ALL_RE = /^\s*Kernel-change:\s*(.+)$/gim
const REVIEWED_BY_TRAILER_ALL_RE = /^\s*Reviewed-by:\s*(.+)$/gim
const KERNEL_GATE_OVERRIDE_TRAILER_ALL_RE = /^\s*Kernel-gate-override:\s*(.+)$/gim

const kernelManifestCache = new Map<string, { mtimeMs: number; files: ReadonlySet<string> }>()

function normalizeRel(relPath: string): string {
  return relPath.replace(/\\/g, '/').replace(/^\.\//, '')
}

/**
 * Load the generated confirmation-kernel file manifest (`scripts/kernel-manifest.json`).
 * Returns `null` if no manifest exists in `rootDir`.
 */
export function loadKernelManifestFiles(rootDir: string = REPO_ROOT): ReadonlySet<string> | null {
  const manifestPath = join(resolve(rootDir), 'scripts', 'kernel-manifest.json')
  if (!existsSync(manifestPath)) return null
  try {
    const mtimeMs = statSync(manifestPath).mtimeMs
    const cached = kernelManifestCache.get(manifestPath)
    if (cached && cached.mtimeMs === mtimeMs) return cached.files
    const parsed = JSON.parse(readFileSync(manifestPath, 'utf8')) as { files?: unknown }
    if (!Array.isArray(parsed.files)) return null
    const files = new Set(
      parsed.files
        .filter((f): f is string => typeof f === 'string' && f.trim().length > 0)
        .map(f => normalizeRel(f.trim())),
    )
    kernelManifestCache.set(manifestPath, { mtimeMs, files })
    return files
  } catch {
    return null
  }
}

export function isConfirmationKernelFile(relPath: string, rootDir: string = REPO_ROOT): boolean {
  const norm = normalizeRel(relPath)
  if (/(?:\.test|\.spec)\.[^./]+$/i.test(norm)) return false
  const localManifest = loadKernelManifestFiles(rootDir)
  if (localManifest) return localManifest.has(norm)
  const repoManifest = rootDir !== REPO_ROOT ? loadKernelManifestFiles(REPO_ROOT) : null
  if (repoManifest && repoManifest.has(norm)) return true
  return CONFIRMATION_KERNEL_FILE_RE.test(norm)
}

export function isParityCorpusFile(relPath: string): boolean {
  const norm = normalizeRel(relPath)
  return norm.startsWith('tests/parity/corpus/') && norm.endsWith('.json')
}

function parseCorpusCaseObject(raw: unknown, relFile: string): ParityCorpusCaseMeta | null {
  if (!raw || typeof raw !== 'object') return null
  const obj = raw as {
    id?: unknown
    side?: unknown
    covers?: { files?: unknown; classes?: unknown }
  }
  if (typeof obj.id !== 'string' || obj.id.trim().length === 0) return null
  const side =
    obj.side === 'tp' || obj.side === 'fp' || obj.side === 'retest' ? obj.side : null
  let covers: ParityCorpusCovers | undefined
  if (obj.covers && typeof obj.covers === 'object') {
    const files = Array.isArray(obj.covers.files)
      ? obj.covers.files
          .filter((f): f is string => typeof f === 'string' && f.trim().length > 0)
          .map(f => normalizeRel(f.trim()))
      : []
    const classes = Array.isArray(obj.covers.classes)
      ? obj.covers.classes
          .filter((c): c is string => typeof c === 'string' && c.trim().length > 0)
          .map(c => c.trim())
      : []
    covers = { files, classes }
  }
  return {
    id: obj.id.trim(),
    file: normalizeRel(relFile),
    side,
    ...(covers ? { covers } : {}),
  }
}

export function loadParityCorpusCases(rootDir: string = REPO_ROOT): Map<string, ParityCorpusCaseMeta> {
  const corpusDir = join(rootDir, 'tests', 'parity', 'corpus')
  const cases = new Map<string, ParityCorpusCaseMeta>()
  if (!existsSync(corpusDir)) return cases
  let files: string[]
  try {
    files = readdirSync(corpusDir).filter(f => f.endsWith('.json')).sort()
  } catch {
    return cases
  }
  for (const file of files) {
    try {
      const parsed = JSON.parse(readFileSync(join(corpusDir, file), 'utf8')) as unknown
      const meta = parseCorpusCaseObject(parsed, `tests/parity/corpus/${file}`)
      if (meta) cases.set(meta.id, meta)
    } catch {
      // Ignore unreadable/invalid JSON here; path-parity.test.ts validates corpus schema.
    }
  }
  return cases
}

export function loadParityCorpusIds(rootDir: string = REPO_ROOT): Set<string> {
  return new Set(loadParityCorpusCases(rootDir).keys())
}

export function parseParityCaseTrailers(commitMessages: string): string[] {
  const ids: string[] = []
  PARITY_CASE_TRAILER_ALL_RE.lastIndex = 0
  for (const m of commitMessages.matchAll(PARITY_CASE_TRAILER_ALL_RE)) {
    const raw = (m[1] ?? '').trim()
    if (!raw) continue
    const token = raw.split(/\s+/)[0]!.replace(/[,;:]+$/, '').trim()
    if (token.length > 0) ids.push(token)
  }
  return ids
}

export function parseKernelChangeTrailers(commitMessages: string): string[] {
  const vals: string[] = []
  KERNEL_CHANGE_TRAILER_ALL_RE.lastIndex = 0
  for (const m of commitMessages.matchAll(KERNEL_CHANGE_TRAILER_ALL_RE)) {
    const raw = (m[1] ?? '').trim()
    if (raw.length > 0) vals.push(raw)
  }
  return vals
}

export function isKernelLooseningChange(commitMessages: string): boolean {
  return parseKernelChangeTrailers(commitMessages).some(v => /^loosening\b/i.test(v))
}

export function parseReviewedByTrailers(commitMessages: string): string[] {
  const vals: string[] = []
  REVIEWED_BY_TRAILER_ALL_RE.lastIndex = 0
  for (const m of commitMessages.matchAll(REVIEWED_BY_TRAILER_ALL_RE)) {
    const raw = (m[1] ?? '').trim()
    if (raw.length > 0) vals.push(raw)
  }
  return vals
}

/**
 * Parse audited operator override trailers (`Kernel-gate-override: <ticket> <reason>`).
 * Requires at least 2 tokens and >= 12 chars so trivial/empty overrides are rejected.
 */
export function parseKernelGateOverrideTrailers(commitMessages: string): string[] {
  const valid: string[] = []
  KERNEL_GATE_OVERRIDE_TRAILER_ALL_RE.lastIndex = 0
  for (const m of commitMessages.matchAll(KERNEL_GATE_OVERRIDE_TRAILER_ALL_RE)) {
    const raw = (m[1] ?? '').trim()
    const tokens = raw.split(/\s+/).filter(Boolean)
    if (raw.length >= 12 && tokens.length >= 2) {
      valid.push(raw)
    }
  }
  return valid
}

export function isGateOrKernelTestFile(
  relPath: string,
  opts?: { rootDir?: string; sourceText?: string },
): boolean {
  const norm = normalizeRel(relPath)
  if (GATE_TEST_EXACT.has(norm) || KERNEL_TEST_RE.test(norm) || EXTENDED_CONTRACT_TEST_RE.test(norm)) {
    return true
  }
  if (!norm.startsWith('tests/') || !norm.endsWith('.test.ts')) return false
  const tags = opts?.sourceText !== undefined
    ? parseTestFileTags(opts.sourceText)
    : readTestFileTags(norm, opts?.rootDir ?? REPO_ROOT)
  return hasProtectedTestTag(tags)
}

export function isTunableSourceFile(relPath: string): boolean {
  const norm = relPath.replace(/\\/g, '/').replace(/^\.\//, '')
  if (norm === 'scripts/benchmark-core.ts' || norm === 'src/domain.ts') return true
  if (!norm.startsWith('src/server/')) return false
  if (/(?:\.test|\.spec)\.[^./]+$/i.test(norm)) return false
  return norm.endsWith('.ts')
}

function matchTunableExport(line: string): { symbol: string; rhs: string } | null {
  const m1 = SCREAMING_TUNABLE_EXPORT_RE.exec(line)
  if (m1) return { symbol: m1[1]!, rhs: m1[2]!.trim() }
  const m2 = CAMEL_TUNABLE_EXPORT_RE.exec(line)
  if (m2) {
    const rhs = m2[2]!.trim()
    if (FUNCTION_RHS_RE.test(rhs)) return null
    return { symbol: m2[1]!, rhs }
  }
  return null
}

/**
 * Strip comments and quoted string literals from a single TS line so numeric literal extraction
 * ignores assertion error messages and comments.
 */
export function stripStringsAndLineComment(line: string): string {
  let out = ''
  let quote: string | null = null
  let escaped = false
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]!
    const next = line[i + 1]
    if (quote) {
      if (escaped) {
        escaped = false
      } else if (ch === '\\') {
        escaped = true
      } else if (ch === quote) {
        quote = null
        out += '""'
      }
      continue
    }
    if (ch === '/' && next === '/') {
      break
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch
      continue
    }
    out += ch
  }
  return out
}

export function extractCodeNumericLiterals(line: string): string[] {
  const stripped = stripStringsAndLineComment(line)
  const matches = stripped.match(NUMERIC_LITERAL_RE)
  if (!matches) return []
  return matches.map(raw => String(Number(raw.replace(/_/g, ''))))
}

function normalizeRhs(rawRhs: string): string {
  const stripped = stripStringsAndLineComment(rawRhs).trim().replace(/;$/, '').trim()
  // Normalize numeric underscores so 6000 -> 6_000 is not flagged as a semantic change.
  return stripped.replace(NUMERIC_LITERAL_RE, m => String(Number(m.replace(/_/g, ''))))
}

export function parseUnifiedDiff(diffText: string): ParsedDiffFile[] {
  const files: ParsedDiffFile[] = []
  let currentFile: ParsedDiffFile | null = null
  let currentHunk: ParsedDiffHunk | null = null
  let oldLine = 0
  let newLine = 0

  for (const rawLine of diffText.split(/\r?\n/)) {
    if (rawLine.startsWith('diff --git ')) {
      currentHunk = null
      const match = /^diff --git [abciwo]\/(.+?) [abciwo]\/(.+)$/.exec(rawLine)
      currentFile = { file: match ? match[2]! : '', hunks: [] }
      files.push(currentFile)
      continue
    }
    if (/^\+\+\+ [abciwo]\//.test(rawLine)) {
      if (currentFile) currentFile.file = rawLine.slice(6).trim()
      continue
    }
    if (rawLine.startsWith('+++ /dev/null')) {
      // File deleted; keep old filename from header so deleted constants can still be observed.
      if (currentFile) currentFile.deleted = true
      continue
    }
    if (rawLine.startsWith('@@ ')) {
      const match = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(rawLine)
      if (match && currentFile) {
        oldLine = Number(match[1])
        newLine = Number(match[2])
        currentHunk = { oldStart: oldLine, newStart: newLine, removed: [], added: [] }
        currentFile.hunks.push(currentHunk)
      }
      continue
    }
    if (!currentHunk) continue
    if (rawLine.startsWith('-') && !rawLine.startsWith('---')) {
      currentHunk.removed.push({ lineNo: oldLine, text: rawLine.slice(1) })
      oldLine += 1
    } else if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
      currentHunk.added.push({ lineNo: newLine, text: rawLine.slice(1) })
      newLine += 1
    } else if (rawLine.startsWith(' ')) {
      oldLine += 1
      newLine += 1
    }
  }

  return files.filter(f => f.file.length > 0)
}

/** Returns true iff every value in `sub` appears with at least as high multiplicity in `sup`. */
function isSubMultiset(sub: readonly string[], sup: readonly string[]): boolean {
  const counts = new Map<string, number>()
  for (const v of sup) counts.set(v, (counts.get(v) ?? 0) + 1)
  for (const v of sub) {
    const n = counts.get(v) ?? 0
    if (n <= 0) return false
    counts.set(v, n - 1)
  }
  return true
}

export function detectContractChanges(
  diffText: string,
  opts?: { rootDir?: string },
): ContractChangeHit[] {
  const parsedFiles = parseUnifiedDiff(diffText)
  const hits: ContractChangeHit[] = []

  for (const fileEntry of parsedFiles) {
    const tunable = isTunableSourceFile(fileEntry.file)
    const gateTest = isGateOrKernelTestFile(fileEntry.file, { rootDir: opts?.rootDir })
    if (!tunable && !gateTest) continue

    for (const hunk of fileEntry.hunks) {
      if (tunable) {
        const removedConsts = new Map<string, { lineNo: number; rhs: string; norm: string }>()
        const addedConsts = new Map<string, { lineNo: number; rhs: string; norm: string }>()
        for (const rem of hunk.removed) {
          const m = matchTunableExport(rem.text)
          if (m) removedConsts.set(m.symbol, { lineNo: rem.lineNo, rhs: m.rhs, norm: normalizeRhs(m.rhs) })
        }
        for (const add of hunk.added) {
          const m = matchTunableExport(add.text)
          if (m) addedConsts.set(m.symbol, { lineNo: add.lineNo, rhs: m.rhs, norm: normalizeRhs(m.rhs) })
        }
        for (const [symbol, before] of removedConsts) {
          const after = addedConsts.get(symbol)
          if (!after) {
            hits.push({
              kind: 'tunable_constant_change',
              id: symbol,
              file: fileEntry.file,
              line: before.lineNo,
              symbol,
              before: before.rhs,
              after: '(removed)',
            })
          } else if (after.norm !== before.norm) {
            hits.push({
              kind: 'tunable_constant_change',
              id: symbol,
              file: fileEntry.file,
              line: after.lineNo,
              symbol,
              before: before.rhs,
              after: after.rhs,
            })
          }
        }
      }

      if (gateTest) {
        const remAsserts = hunk.removed
          .filter(r => ASSERT_CALL_RE.test(r.text))
          .map(r => ({ ...r, nums: extractCodeNumericLiterals(r.text) }))
          .filter(r => r.nums.length > 0)
        if (remAsserts.length === 0) continue

        const addAsserts = hunk.added
          .filter(a => ASSERT_CALL_RE.test(a.text))
          .map(a => ({ ...a, nums: extractCodeNumericLiterals(a.text) }))

        const remNums = remAsserts.flatMap(r => r.nums)
        const addNums = addAsserts.flatMap(a => a.nums)
        if (!isSubMultiset(remNums, addNums)) {
          const firstAdd = addAsserts[0]
          const firstRem = remAsserts[0]!
          hits.push({
            kind: 'gate_assert_literal_change',
            id: fileEntry.file,
            file: fileEntry.file,
            line: firstAdd ? firstAdd.lineNo : firstRem.lineNo,
            before: firstRem.text.trim(),
            after: firstAdd ? firstAdd.text.trim() : '(assertion removed)',
          })
        }
      }
    }
  }

  return hits
}

export function parseContractChangeTrailers(commitMessages: string): string[] {
  const trailers: string[] = []
  CONTRACT_CHANGE_TRAILER_ALL_RE.lastIndex = 0
  for (const m of commitMessages.matchAll(CONTRACT_CHANGE_TRAILER_ALL_RE)) {
    const val = (m[1] ?? '').trim()
    if (val.length >= 6) trailers.push(val)
  }
  return trailers
}

export function hasContractChangeTrailer(commitMessages: string): { present: boolean; trailer: string | null } {
  const m = CONTRACT_CHANGE_TRAILER_RE.exec(commitMessages)
  if (!m) return { present: false, trailer: null }
  const val = m[1]!.trim()
  if (val.length < 6) return { present: false, trailer: null }
  return { present: true, trailer: val }
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function trailerMatchesHitId(trailer: string, hit: ContractChangeHit): boolean {
  if (hit.kind === 'tunable_constant_change' && hit.symbol) {
    const symRe = new RegExp(`(?<![A-Za-z0-9_$])${escapeRegExp(hit.symbol)}(?![A-Za-z0-9_$])`)
    return symRe.test(trailer)
  }
  const fileNorm = hit.file.replace(/\\/g, '/')
  const base = basename(fileNorm)
  const fileRe = new RegExp(`(?<![A-Za-z0-9_./-])${escapeRegExp(fileNorm)}(?![A-Za-z0-9_./-])`)
  const baseRe = new RegExp(`(?<![A-Za-z0-9_./-])${escapeRegExp(base)}(?![A-Za-z0-9_./-])`)
  return fileRe.test(trailer) || baseRe.test(trailer)
}

const EXPLICIT_TRAILER_TARGET_RE =
  /^(?:(tests\/[A-Za-z0-9_./-]+\.test\.ts)|([A-Z][A-Z0-9_]{3,})|((?:default|max)[A-Z][A-Za-z0-9]+))(?:\s*[:—–-]|\s)/

function matchPerIdTrailers(
  hits: readonly ContractChangeHit[],
  trailers: readonly string[],
  mode: boolean | 'strict',
): { ok: boolean; missingIds: string[] } {
  // Deduplicate required IDs in encounter order.
  const hitById = new Map<string, ContractChangeHit>()
  for (const h of hits) {
    if (!hitById.has(h.id)) hitById.set(h.id, h)
  }
  const required = [...hitById.values()]
  if (required.length === 0) return { ok: true, missingIds: [] }
  if (trailers.length === 0) return { ok: false, missingIds: required.map(r => r.id) }

  // Backward-compatible single-ID allowance when `mode === true` (non-strict):
  // 1 changed ID + >=1 trailer passes UNLESS the trailer explicitly targets a DIFFERENT ID.
  if (mode === true && required.length === 1) {
    const onlyHit = required[0]!
    if (trailers.some(t => trailerMatchesHitId(t, onlyHit))) {
      return { ok: true, missingIds: [] }
    }
    const anyGeneric = trailers.some(t => !EXPLICIT_TRAILER_TARGET_RE.test(t.trim()))
    if (anyGeneric) return { ok: true, missingIds: [] }
    return { ok: false, missingIds: [onlyHit.id] }
  }

  // Strict per-ID matching (ALWAYS enforced when >1 distinct ID changed, or when mode === 'strict'):
  // Each distinct changed ID requires its own dedicated `Contract-change:` trailer line naming that ID.
  const usedTrailerIdx = new Set<number>()
  const missingIds: string[] = []
  for (const hit of required) {
    let matched = false
    for (let i = 0; i < trailers.length; i += 1) {
      if (usedTrailerIdx.has(i)) continue
      if (trailerMatchesHitId(trailers[i]!, hit)) {
        usedTrailerIdx.add(i)
        matched = true
        break
      }
    }
    if (!matched) missingIds.push(hit.id)
  }
  return { ok: missingIds.length === 0, missingIds }
}

function parseCorpusCaseFromDiffFile(fileEntry: ParsedDiffFile, rootDir: string): ParityCorpusCaseMeta | null {
  const fullPath = join(rootDir, fileEntry.file)
  if (existsSync(fullPath)) {
    try {
      const parsed = JSON.parse(readFileSync(fullPath, 'utf8')) as unknown
      const meta = parseCorpusCaseObject(parsed, fileEntry.file)
      if (meta) return meta
    } catch {
      // Fall through to diff reconstruction.
    }
  }
  const addedText = fileEntry.hunks.flatMap(h => h.added.map(a => a.text)).join('\n').trim()
  if (addedText.startsWith('{')) {
    try {
      const parsed = JSON.parse(addedText) as unknown
      const meta = parseCorpusCaseObject(parsed, fileEntry.file)
      if (meta) return meta
    } catch {
      // Partial diff hunk on an existing file not present on disk.
    }
  }
  return null
}

function evaluateSingleDiffParityGate(opts: {
  sha: string
  diffText: string
  commitMessages: string
  mode: 'strict' | 'warn'
  rootDir: string
  baseRef?: string | null
  headRef?: string | null
  filePairs?: ReadonlyMap<string, { base: string | null; head: string | null }>
  corpusById: ReadonlyMap<string, ParityCorpusCaseMeta>
  corpusByFile: ReadonlyMap<string, ParityCorpusCaseMeta>
  corpusUsesCovers: boolean
  requireReviewedByOnLoosening: boolean
}): CommitParityEvalResult {
  const parsedFiles = parseUnifiedDiff(opts.diffText)
  const kernelFilesTouched = [
    ...new Set(parsedFiles.map(f => normalizeRel(f.file)).filter(f => isConfirmationKernelFile(f, opts.rootDir))),
  ].sort()
  const nonDeletedCorpusEntries = parsedFiles.filter(f => !f.deleted && isParityCorpusFile(f.file))
  const corpusFilesTouched = [...new Set(nonDeletedCorpusEntries.map(f => normalizeRel(f.file)))].sort()
  const parityCaseTrailers = parseParityCaseTrailers(opts.commitMessages)
  const loosening = isKernelLooseningChange(opts.commitMessages)
  const reviewedByTrailers = parseReviewedByTrailers(opts.commitMessages)
  const overrideTrailers = parseKernelGateOverrideTrailers(opts.commitMessages)
  const rawOverrideLinePresent = /^\s*Kernel-gate-override:/im.test(opts.commitMessages)

  if (kernelFilesTouched.length === 0) {
    return {
      sha: opts.sha,
      required: false,
      ok: true,
      warned: false,
      kernelFilesTouched: [],
      corpusFilesTouched,
      parityCaseTrailers,
      validParityCaseIds: [],
      invalidParityCaseIds: [],
      uncoveredKernelFiles: [],
      loosening,
      missingLooseningSides: [],
      reviewedByTrailers,
      overridden: false,
      overrideTrailer: null,
      reason: null,
    }
  }

  if (overrideTrailers.length > 0) {
    return {
      sha: opts.sha,
      required: true,
      ok: true,
      warned: false,
      kernelFilesTouched,
      corpusFilesTouched,
      parityCaseTrailers,
      validParityCaseIds: [],
      invalidParityCaseIds: [],
      uncoveredKernelFiles: [],
      loosening,
      missingLooseningSides: [],
      reviewedByTrailers,
      overridden: true,
      overrideTrailer: overrideTrailers[0]!,
      reason: null,
    }
  }

  if (rawOverrideLinePresent) {
    const reason = 'Malformed Kernel-gate-override trailer (requires "<ticket> <justification>" with >= 2 tokens and >= 12 chars).'
    return {
      sha: opts.sha,
      required: true,
      ok: opts.mode === 'warn',
      warned: opts.mode === 'warn',
      kernelFilesTouched,
      corpusFilesTouched,
      parityCaseTrailers,
      validParityCaseIds: [],
      invalidParityCaseIds: [],
      uncoveredKernelFiles: kernelFilesTouched,
      loosening,
      missingLooseningSides: [],
      reviewedByTrailers,
      overridden: false,
      overrideTrailer: null,
      reason,
    }
  }

  const cosmetic = parseKernelCosmeticTrailer(opts.commitMessages)
  if (cosmetic.present) {
    if (cosmetic.malformed) {
      return {
        sha: opts.sha,
        required: true,
        ok: false,
        warned: false,
        kernelFilesTouched,
        corpusFilesTouched,
        parityCaseTrailers,
        validParityCaseIds: [],
        invalidParityCaseIds: [],
        uncoveredKernelFiles: kernelFilesTouched,
        loosening,
        missingLooseningSides: [],
        reviewedByTrailers,
        overridden: false,
        overrideTrailer: null,
        cosmeticVerified: false,
        cosmeticReason: null,
        reason: `Malformed Kernel-cosmetic trailer ("${cosmetic.malformed}"); expected "Kernel-cosmetic: <reason (min 6 chars)>".`,
      }
    }
    const astRes = verifyCosmeticKernelDiff({
      rootDir: opts.rootDir,
      baseRef: opts.baseRef ?? null,
      headRef: opts.headRef ?? 'HEAD',
      kernelFiles: kernelFilesTouched,
      filePairs: opts.filePairs,
    })
    if (astRes.ok) {
      return {
        sha: opts.sha,
        required: true,
        ok: true,
        warned: false,
        kernelFilesTouched,
        corpusFilesTouched,
        parityCaseTrailers,
        validParityCaseIds: [],
        invalidParityCaseIds: [],
        uncoveredKernelFiles: [],
        loosening,
        missingLooseningSides: [],
        reviewedByTrailers,
        overridden: false,
        overrideTrailer: null,
        cosmeticVerified: true,
        cosmeticReason: cosmetic.reason,
        reason: null,
      }
    }
    const detail = astRes.failedFiles.map(f => `${f.file}: ${f.reason}`).join('; ')
    return {
      sha: opts.sha,
      required: true,
      ok: false,
      warned: false,
      kernelFilesTouched,
      corpusFilesTouched,
      parityCaseTrailers,
      validParityCaseIds: [],
      invalidParityCaseIds: [],
      uncoveredKernelFiles: kernelFilesTouched,
      loosening,
      missingLooseningSides: [],
      reviewedByTrailers,
      overridden: false,
      overrideTrailer: null,
      cosmeticVerified: false,
      cosmeticReason: null,
      reason: `Kernel-cosmetic AST verification failed: ${detail}`,
    }
  }

  // Merge any corpus files added/edited in this commit into the lookup maps for this commit.
  const effectiveById = new Map<string, ParityCorpusCaseMeta>(opts.corpusById)
  const effectiveByFile = new Map<string, ParityCorpusCaseMeta>(opts.corpusByFile)
  let effectiveUsesCovers = opts.corpusUsesCovers
  const touchedCases: ParityCorpusCaseMeta[] = []
  for (const entry of nonDeletedCorpusEntries) {
    const rel = normalizeRel(entry.file)
    const fromDiff = parseCorpusCaseFromDiffFile(entry, opts.rootDir)
    const existing = effectiveByFile.get(rel)
    const resolved = fromDiff ?? existing
    if (resolved) {
      effectiveById.set(resolved.id, resolved)
      effectiveByFile.set(rel, resolved)
      if (resolved.covers) effectiveUsesCovers = true
      touchedCases.push(resolved)
    }
  }

  const validParityCaseIds = parityCaseTrailers.filter(id => effectiveById.has(id))
  const invalidParityCaseIds = parityCaseTrailers.filter(id => !effectiveById.has(id))

  if (invalidParityCaseIds.length > 0) {
    const reason = `Unknown Parity-case ID(s): ${invalidParityCaseIds.join(', ')} (must match an existing case "id" in tests/parity/corpus/*.json).`
    return {
      sha: opts.sha,
      required: true,
      ok: opts.mode === 'warn',
      warned: opts.mode === 'warn',
      kernelFilesTouched,
      corpusFilesTouched,
      parityCaseTrailers,
      validParityCaseIds,
      invalidParityCaseIds,
      uncoveredKernelFiles: kernelFilesTouched,
      loosening,
      missingLooseningSides: [],
      reviewedByTrailers,
      overridden: false,
      overrideTrailer: null,
      reason,
    }
  }

  // Candidate parity cases for THIS commit: cited valid IDs + non-deleted corpus files touched in this commit.
  const candidateByKey = new Map<string, ParityCorpusCaseMeta>()
  for (const id of validParityCaseIds) {
    const meta = effectiveById.get(id)
    if (meta) candidateByKey.set(meta.id, meta)
  }
  for (const meta of touchedCases) {
    candidateByKey.set(meta.id, meta)
  }
  const candidates = [...candidateByKey.values()]

  if (corpusFilesTouched.length === 0 && validParityCaseIds.length === 0) {
    const reason = `Confirmation-kernel diff (${kernelFilesTouched.join(', ')}) must touch tests/parity/corpus/*.json OR carry "Parity-case: <id>" naming a corpus case whose covers.files covers each changed kernel file.`
    return {
      sha: opts.sha,
      required: true,
      ok: opts.mode === 'warn',
      warned: opts.mode === 'warn',
      kernelFilesTouched,
      corpusFilesTouched,
      parityCaseTrailers,
      validParityCaseIds,
      invalidParityCaseIds: [],
      uncoveredKernelFiles: kernelFilesTouched,
      loosening,
      missingLooseningSides: [],
      reviewedByTrailers,
      overridden: false,
      overrideTrailer: null,
      reason,
    }
  }

  // Semantic covers.files binding: every changed kernel file in this commit must be covered
  // by at least one candidate case's covers.files when the corpus declares covers metadata.
  let uncoveredKernelFiles: string[] = []
  if (effectiveUsesCovers) {
    const coveredFiles = new Set<string>()
    for (const c of candidates) {
      for (const f of c.covers?.files ?? []) {
        coveredFiles.add(normalizeRel(f))
      }
    }
    uncoveredKernelFiles = kernelFilesTouched.filter(kf => !coveredFiles.has(kf))
  }

  if (uncoveredKernelFiles.length > 0) {
    const citedDesc = validParityCaseIds.length > 0 ? validParityCaseIds.join(', ') : 'none'
    const touchedDesc = corpusFilesTouched.length > 0 ? corpusFilesTouched.join(', ') : 'none'
    const reason =
      `Confirmation-kernel file(s) not covered by commit Parity-case/corpus covers.files: ${uncoveredKernelFiles.join(', ')} ` +
      `(cited Parity-case: ${citedDesc}; touched corpus: ${touchedDesc}).`
    return {
      sha: opts.sha,
      required: true,
      ok: opts.mode === 'warn',
      warned: opts.mode === 'warn',
      kernelFilesTouched,
      corpusFilesTouched,
      parityCaseTrailers,
      validParityCaseIds,
      invalidParityCaseIds: [],
      uncoveredKernelFiles,
      loosening,
      missingLooseningSides: [],
      reviewedByTrailers,
      overridden: false,
      overrideTrailer: null,
      reason,
    }
  }

  // Kernel-change: loosening requires BOTH a TP and an FP corpus case covering each changed kernel file.
  const missingLooseningSides: MissingLooseningSide[] = []
  if (loosening) {
    for (const kf of kernelFilesTouched) {
      const covering = effectiveUsesCovers
        ? candidates.filter(c => (c.covers?.files ?? []).includes(kf))
        : candidates
      const hasTp = covering.some(c => c.side === 'tp')
      const hasFp = covering.some(c => c.side === 'fp')
      const missing: Array<'tp' | 'fp'> = []
      if (!hasTp) missing.push('tp')
      if (!hasFp) missing.push('fp')
      if (missing.length > 0) {
        missingLooseningSides.push({ file: kf, missing })
      }
    }
    if (missingLooseningSides.length > 0) {
      const detail = missingLooseningSides.map(m => `${m.file} missing ${m.missing.join('+')}`).join('; ')
      const reason = `Kernel-change: loosening requires BOTH a TP and an FP corpus case covering each changed kernel file (${detail}).`
      return {
        sha: opts.sha,
        required: true,
        ok: opts.mode === 'warn',
        warned: opts.mode === 'warn',
        kernelFilesTouched,
        corpusFilesTouched,
        parityCaseTrailers,
        validParityCaseIds,
        invalidParityCaseIds: [],
        uncoveredKernelFiles: [],
        loosening,
        missingLooseningSides,
        reviewedByTrailers,
        overridden: false,
        overrideTrailer: null,
        reason,
      }
    }
    if (opts.requireReviewedByOnLoosening && reviewedByTrailers.length === 0) {
      const reason = 'Kernel-change: loosening requires a "Reviewed-by: <reviewer-id> <case-id>" trailer.'
      return {
        sha: opts.sha,
        required: true,
        ok: opts.mode === 'warn',
        warned: opts.mode === 'warn',
        kernelFilesTouched,
        corpusFilesTouched,
        parityCaseTrailers,
        validParityCaseIds,
        invalidParityCaseIds: [],
        uncoveredKernelFiles: [],
        loosening,
        missingLooseningSides: [],
        reviewedByTrailers,
        overridden: false,
        overrideTrailer: null,
        reason,
      }
    }
  }

  return {
    sha: opts.sha,
    required: true,
    ok: true,
    warned: false,
    kernelFilesTouched,
    corpusFilesTouched,
    parityCaseTrailers,
    validParityCaseIds,
    invalidParityCaseIds: [],
    uncoveredKernelFiles: [],
    loosening,
    missingLooseningSides: [],
    reviewedByTrailers,
    overridden: false,
    overrideTrailer: null,
    reason: null,
  }
}

export function evaluateParityGate(opts: {
  diffText: string
  commitMessages: string
  mode: 'strict' | 'warn'
  rootDir?: string
  baseRef?: string | null
  headRef?: string | null
  filePairs?: ReadonlyMap<string, { base: string | null; head: string | null }>
  knownParityCaseIds?: ReadonlySet<string>
  knownParityCases?: ReadonlyMap<string, ParityCorpusCaseMeta>
  commits?: ReadonlyArray<CommitParitySlice>
  enforceCovers?: boolean
  requireReviewedByOnLoosening?: boolean
}): ParityGateEvalResult {
  const rootDir = opts.rootDir ?? REPO_ROOT
  let corpusById: Map<string, ParityCorpusCaseMeta>
  if (opts.knownParityCases) {
    corpusById = new Map(opts.knownParityCases)
  } else if (opts.knownParityCaseIds) {
    corpusById = new Map()
    for (const id of opts.knownParityCaseIds) {
      corpusById.set(id, { id, file: '', side: null })
    }
  } else {
    corpusById = loadParityCorpusCases(rootDir)
  }
  const corpusByFile = new Map<string, ParityCorpusCaseMeta>()
  let corpusUsesCovers = opts.enforceCovers === true
  for (const meta of corpusById.values()) {
    if (meta.file) corpusByFile.set(normalizeRel(meta.file), meta)
    if (meta.covers) corpusUsesCovers = true
  }
  const requireReviewedByOnLoosening =
    opts.requireReviewedByOnLoosening ?? process.env.KOVO_KERNEL_REVIEW_REQUIRED === '1'

  const slices: ReadonlyArray<CommitParitySlice> =
    opts.commits && opts.commits.length > 0
      ? opts.commits
      : [{
          sha: 'diff',
          diffText: opts.diffText,
          commitMessage: opts.commitMessages,
          baseRef: opts.baseRef ?? null,
          headRef: opts.headRef ?? 'HEAD',
          filePairs: opts.filePairs,
        }]

  const commitResults = slices.map(slice =>
    evaluateSingleDiffParityGate({
      sha: slice.sha,
      diffText: slice.diffText,
      commitMessages: slice.commitMessage,
      mode: opts.mode,
      rootDir,
      baseRef: slice.baseRef ?? opts.baseRef ?? null,
      headRef: slice.headRef ?? opts.headRef ?? 'HEAD',
      filePairs: slice.filePairs ?? opts.filePairs,
      corpusById,
      corpusByFile,
      corpusUsesCovers,
      requireReviewedByOnLoosening,
    }),
  )

  const kernelFilesTouched = [...new Set(commitResults.flatMap(r => r.kernelFilesTouched))].sort()
  const corpusFilesTouched = [...new Set(commitResults.flatMap(r => r.corpusFilesTouched))].sort()
  const parityCaseTrailers = commitResults.flatMap(r => r.parityCaseTrailers)
  const validParityCaseIds = [...new Set(commitResults.flatMap(r => r.validParityCaseIds))]
  const invalidParityCaseIds = [...new Set(commitResults.flatMap(r => r.invalidParityCaseIds))]
  const uncoveredKernelFiles = [...new Set(commitResults.flatMap(r => r.uncoveredKernelFiles))].sort()
  const loosening = commitResults.some(r => r.loosening)
  const missingLooseningSides = commitResults.flatMap(r => r.missingLooseningSides)
  const reviewedByTrailers = commitResults.flatMap(r => r.reviewedByTrailers)
  const overriddenResult = commitResults.find(r => r.overridden) ?? null
  const requiredResults = commitResults.filter(r => r.required)
  const cosmeticVerified =
    requiredResults.length > 0 && requiredResults.every(r => r.cosmeticVerified === true)
  const cosmeticReason = cosmeticVerified
    ? (requiredResults.find(r => r.cosmeticReason)?.cosmeticReason ?? null)
    : null
  const required = requiredResults.length > 0
  const ok = commitResults.every(r => r.ok)
  const warned = commitResults.some(r => r.warned)
  const failures = commitResults.filter(r => r.reason !== null)
  const reason =
    failures.length === 0
      ? null
      : failures.length === 1 && slices.length === 1
        ? failures[0]!.reason
        : failures.map(f => `[${f.sha}] ${f.reason}`).join(' | ')

  return {
    required,
    ok,
    warned,
    kernelFilesTouched,
    corpusFilesTouched,
    parityCaseTrailers,
    validParityCaseIds,
    invalidParityCaseIds,
    uncoveredKernelFiles,
    loosening,
    missingLooseningSides,
    reviewedByTrailers,
    overridden: overriddenResult !== null && ok,
    overrideTrailer: overriddenResult?.overrideTrailer ?? null,
    ...(cosmeticVerified ? { cosmeticVerified: true, cosmeticReason } : {}),
    ...(opts.commits && opts.commits.length > 0 ? { commitResults } : {}),
    reason,
  }
}

export function evaluateContractChange(opts: {
  diffText: string
  commitMessages: string
  mode: 'strict' | 'warn'
  sourceLabel: string
  /**
   * Enforce one `Contract-change:` trailer line per changed tunable/gate ID.
   * - `false` (default for legacy direct callers): any valid trailer authorizes the diff.
   * - `true` (default in `checkGitRepo` / CLI): enforces 1 dedicated trailer per ID whenever
   *   >1 ID changed, and rejects mismatched explicit target IDs on single-ID changes.
   * - `'strict'`: requires explicit ID mention even on single-ID changes.
   */
  requirePerId?: boolean | 'strict'
  rootDir?: string
  baseRef?: string | null
  headRef?: string | null
  filePairs?: ReadonlyMap<string, { base: string | null; head: string | null }>
  knownParityCaseIds?: ReadonlySet<string>
  knownParityCases?: ReadonlyMap<string, ParityCorpusCaseMeta>
  commits?: ReadonlyArray<CommitParitySlice>
  enforceCovers?: boolean
  requireReviewedByOnLoosening?: boolean
}): ContractChangeEvalResult {
  const hits = detectContractChanges(opts.diffText, { rootDir: opts.rootDir })
  const trailers = parseContractChangeTrailers(opts.commitMessages)
  const parity = evaluateParityGate({
    diffText: opts.diffText,
    commitMessages: opts.commitMessages,
    mode: opts.mode,
    rootDir: opts.rootDir,
    baseRef: opts.baseRef,
    headRef: opts.headRef,
    filePairs: opts.filePairs,
    knownParityCaseIds: opts.knownParityCaseIds,
    knownParityCases: opts.knownParityCases,
    commits: opts.commits,
    enforceCovers: opts.enforceCovers,
    requireReviewedByOnLoosening: opts.requireReviewedByOnLoosening,
  })
  if (hits.length === 0) {
    return {
      ok: parity.ok,
      mode: opts.mode,
      sourceLabel: opts.sourceLabel,
      hits: [],
      trailerPresent: false,
      trailerValue: null,
      trailers,
      missingTrailerIds: [],
      warned: parity.warned,
      parity,
    }
  }
  const firstTrailer = trailers[0] ?? null
  const perIdMode = opts.requirePerId ?? false
  const authorized = perIdMode
    ? matchPerIdTrailers(hits, trailers, perIdMode)
    : { ok: trailers.length > 0, missingIds: trailers.length > 0 ? [] : [...new Set(hits.map(h => h.id))] }

  if (authorized.ok) {
    return {
      ok: parity.ok,
      mode: opts.mode,
      sourceLabel: opts.sourceLabel,
      hits,
      trailerPresent: true,
      trailerValue: firstTrailer,
      trailers,
      missingTrailerIds: [],
      warned: parity.warned,
      parity,
    }
  }
  if (opts.mode === 'warn') {
    return {
      ok: parity.ok,
      mode: opts.mode,
      sourceLabel: opts.sourceLabel,
      hits,
      trailerPresent: trailers.length > 0,
      trailerValue: firstTrailer,
      trailers,
      missingTrailerIds: authorized.missingIds,
      warned: true,
      parity,
    }
  }
  return {
    ok: false,
    mode: opts.mode,
    sourceLabel: opts.sourceLabel,
    hits,
    trailerPresent: trailers.length > 0,
    trailerValue: firstTrailer,
    trailers,
    missingTrailerIds: authorized.missingIds,
    warned: false,
    parity,
  }
}

function runGit(rootDir: string, args: string[]): { ok: boolean; stdout: string } {
  try {
    const stdout = execFileSync('git', args, {
      cwd: rootDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024,
    })
    return { ok: true, stdout }
  } catch {
    return { ok: false, stdout: '' }
  }
}

const ZERO_SHA_RE = /^0+$/

export function resolveCommitBaseRef(rootDir: string, explicitBase?: string | null, checkHead?: boolean): string | null {
  const headSha = runGit(rootDir, ['rev-parse', 'HEAD']).stdout.trim()
  if (!headSha) return null

  const candidateBase = (explicitBase ?? process.env.KOVO_CONTRACT_BASE ?? '').trim()
  if (candidateBase) {
    if (ZERO_SHA_RE.test(candidateBase)) {
      const parent = runGit(rootDir, ['rev-parse', '--verify', 'HEAD~1^{commit}'])
      if (parent.ok && parent.stdout.trim()) return parent.stdout.trim()
      return null
    }
    const verified = runGit(rootDir, ['rev-parse', '--verify', `${candidateBase}^{commit}`])
    if (verified.ok && verified.stdout.trim()) {
      const resolved = verified.stdout.trim()
      if (resolved === headSha) return null
      const mb = runGit(rootDir, ['merge-base', resolved, headSha])
      if (mb.ok && mb.stdout.trim()) {
        return mb.stdout.trim() === headSha ? null : mb.stdout.trim()
      }
      return resolved
    }
    // Unresolvable CI base (e.g. shallow clone / force-pushed before SHA): fall back cleanly to HEAD~1 if present.
    const parent = runGit(rootDir, ['rev-parse', '--verify', 'HEAD~1^{commit}'])
    if (parent.ok && parent.stdout.trim()) return parent.stdout.trim()
    return null
  }

  const branch = runGit(rootDir, ['rev-parse', '--abbrev-ref', 'HEAD']).stdout.trim()

  // On feature/worktree branches, compare strictly against local main's merge-base.
  // If 0 commits ahead of main, return null (unless --check-head was explicitly requested).
  if (branch && branch !== 'main') {
    const mb = runGit(rootDir, ['merge-base', 'main', 'HEAD'])
    if (mb.ok && mb.stdout.trim()) {
      if (mb.stdout.trim() !== headSha) return mb.stdout.trim()
      if (!checkHead) return null
    }
  }
  // On main (or detached HEAD without main ref), compare against origin/main or upstream when unpushed commits exist.
  for (const remoteRef of ['origin/main', '@{upstream}']) {
    const remoteMb = runGit(rootDir, ['merge-base', remoteRef, 'HEAD'])
    if (remoteMb.ok && remoteMb.stdout.trim() && remoteMb.stdout.trim() !== headSha) {
      return remoteMb.stdout.trim()
    }
  }
  if (checkHead) {
    const parent = runGit(rootDir, ['rev-parse', '--verify', 'HEAD~1^{commit}'])
    if (parent.ok && parent.stdout.trim()) return parent.stdout.trim()
  }
  return null
}

function readSingleCommitDiffAndMsg(
  rootDir: string,
  sha: string,
  commitMessageOverride?: string | null,
): CommitParitySlice {
  const shortSha = sha.slice(0, 7)
  const diffRes = runGit(rootDir, [
    '-c', 'diff.mnemonicPrefix=false',
    '-c', 'diff.noprefix=false',
    'diff-tree', '--no-commit-id', '-p', '-r', '--root', '--no-ext-diff', '--unified=3', sha,
  ])
  const msgRes = commitMessageOverride != null
    ? { ok: true, stdout: commitMessageOverride }
    : runGit(rootDir, ['log', '-1', '--format=%B', sha])
  const parentRes = runGit(rootDir, ['rev-parse', '--verify', `${sha}^`])
  return {
    sha: shortSha,
    diffText: diffRes.stdout,
    commitMessage: msgRes.stdout,
    baseRef: parentRes.ok && parentRes.stdout.trim() ? parentRes.stdout.trim() : null,
    headRef: sha,
  }
}

/**
 * Read per-commit `{ sha, diffText, commitMessage }` slices for every non-merge commit in
 * `range` (e.g. `baseRef..HEAD`). For a merge-only range, returns the range diff as a slice.
 */
export function readCommitRangeParitySlices(
  rootDir: string,
  range: string,
  commitMessageOverride?: string | null,
): CommitParitySlice[] {
  const revRes = runGit(rootDir, ['rev-list', '--no-merges', '--reverse', range])
  const shas = revRes.ok
    ? revRes.stdout.split(/\r?\n/).map(s => s.trim()).filter(Boolean)
    : []
  if (shas.length > 0) {
    return shas.map(sha =>
      readSingleCommitDiffAndMsg(
        rootDir,
        sha,
        shas.length === 1 ? commitMessageOverride : undefined,
      ),
    )
  }
  const diffRes = runGit(rootDir, [
    '-c', 'diff.mnemonicPrefix=false',
    '-c', 'diff.noprefix=false',
    'diff', '--no-ext-diff', '--unified=3', range,
  ])
  const logRes = commitMessageOverride != null
    ? { ok: true, stdout: commitMessageOverride }
    : runGit(rootDir, ['log', '--format=%B', range])
  const [rangeBase, rangeHead] = range.split('..')
  return [{
    sha: range,
    diffText: diffRes.stdout,
    commitMessage: logRes.stdout,
    baseRef: rangeBase || null,
    headRef: rangeHead || 'HEAD',
  }]
}

/**
 * Replay the per-commit parity gate directly against any historical git commit (regular OR
 * merge commit — for merge commits `M`, evaluates every non-merge commit in `M^1..M`).
 */
export function evaluateSingleCommitParityGate(
  rootDir: string,
  commitRef: string,
  opts?: {
    mode?: 'strict' | 'warn'
    knownParityCases?: ReadonlyMap<string, ParityCorpusCaseMeta>
    enforceCovers?: boolean
    requireReviewedByOnLoosening?: boolean
  },
): ParityGateEvalResult {
  const absRoot = resolve(rootDir)
  const parentsRes = runGit(absRoot, ['rev-list', '--parents', '-n', '1', commitRef])
  const tokens = parentsRes.ok ? parentsRes.stdout.trim().split(/\s+/).filter(Boolean) : []
  const sha = tokens[0] ?? commitRef
  const isMerge = tokens.length >= 3
  const commits: CommitParitySlice[] = isMerge
    ? readCommitRangeParitySlices(absRoot, `${sha}^1..${sha}`)
    : [readSingleCommitDiffAndMsg(absRoot, sha)]
  return evaluateParityGate({
    diffText: commits.map(c => c.diffText).join('\n'),
    commitMessages: commits.map(c => c.commitMessage).join('\n'),
    commits,
    mode: opts?.mode ?? 'strict',
    rootDir: absRoot,
    knownParityCases: opts?.knownParityCases,
    enforceCovers: opts?.enforceCovers,
    requireReviewedByOnLoosening: opts?.requireReviewedByOnLoosening,
  })
}

export function checkGitRepo(opts: CheckGitRepoOptions = {}): ContractChangeRepoResult {
  const startedAt = performance.now()
  const rootDir = resolve(opts.rootDir ?? REPO_ROOT)
  const perIdMode: boolean | 'strict' = opts.strictPerId ? 'strict' : true

  if (opts.stagedOnly) {
    const diffRes = runGit(rootDir, ['-c', 'diff.mnemonicPrefix=false', '-c', 'diff.noprefix=false', 'diff', '--no-ext-diff', '--cached', '--unified=3'])
    const commitMessages = opts.commitMessageOverride ?? ''
    const mode = opts.strictUncommitted === false ? 'warn' : 'strict'
    const committed = evaluateContractChange({
      diffText: diffRes.stdout,
      commitMessages,
      mode,
      sourceLabel: 'staged (--cached)',
      requirePerId: perIdMode,
      rootDir,
      baseRef: 'HEAD',
      headRef: 'STAGED',
    })
    return {
      ok: committed.ok,
      rootDir,
      committed,
      uncommitted: null,
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const baseRef = resolveCommitBaseRef(rootDir, opts.baseRef, opts.checkHead)
  let committed: ContractChangeEvalResult
  if (baseRef) {
    const range = `${baseRef}..HEAD`
    const diffRes = runGit(rootDir, ['-c', 'diff.mnemonicPrefix=false', '-c', 'diff.noprefix=false', 'diff', '--no-ext-diff', '--unified=3', range])
    const logRes = opts.commitMessageOverride != null
      ? { ok: true, stdout: opts.commitMessageOverride }
      : runGit(rootDir, ['log', '--format=%B', range])
    const commits = readCommitRangeParitySlices(rootDir, range, opts.commitMessageOverride)
    committed = evaluateContractChange({
      diffText: diffRes.stdout,
      commitMessages: logRes.stdout,
      commits,
      mode: 'strict',
      sourceLabel: `committed (${range})`,
      requirePerId: perIdMode,
      rootDir,
    })
  } else {
    committed = {
      ok: true,
      mode: 'strict',
      sourceLabel: 'committed (0 commits ahead of base)',
      hits: [],
      trailerPresent: false,
      trailerValue: null,
      trailers: [],
      missingTrailerIds: [],
      warned: false,
    }
  }

  const dirtyDiff = runGit(rootDir, ['-c', 'diff.mnemonicPrefix=false', '-c', 'diff.noprefix=false', 'diff', '--no-ext-diff', '--unified=3', 'HEAD'])
  const uncommitted = evaluateContractChange({
    diffText: dirtyDiff.stdout,
    commitMessages: opts.commitMessageOverride ?? '',
    mode: opts.strictUncommitted ? 'strict' : 'warn',
    sourceLabel: 'working tree (uncommitted)',
    requirePerId: perIdMode,
    rootDir,
    baseRef: 'HEAD',
    headRef: 'WORKTREE',
  })

  return {
    ok: committed.ok && uncommitted.ok,
    rootDir,
    committed,
    uncommitted,
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
  }
}

export function formatContractChangeReport(result: ContractChangeRepoResult): string {
  const lines: string[] = []
  const sections = [result.committed, ...(result.uncommitted ? [result.uncommitted] : [])]
  for (const sec of sections) {
    if (sec.hits.length > 0) {
      const contractOk = sec.missingTrailerIds.length === 0
      if (contractOk && !(sec.mode === 'warn' && !sec.trailerPresent)) {
        lines.push(
          `contract-change [${sec.sourceLabel}]: PASS (${sec.hits.length} edit(s) authorized by ${sec.trailers.length} trailer(s): Contract-change: ${sec.trailerValue})`,
        )
      } else if (sec.mode === 'warn') {
        lines.push(
          `contract-change [${sec.sourceLabel}]: WARN (${sec.hits.length} uncommitted contract edit(s) — add one "Contract-change: <id> <reason>" trailer per changed ID when committing):`,
        )
        for (const h of sec.hits) {
          const sym = h.symbol ? ` ${h.symbol}` : ''
          lines.push(`  ${h.file}:${h.line} [${h.kind}]${sym}: ${h.before} -> ${h.after}`)
        }
      } else {
        const missingNote = sec.missingTrailerIds.length > 0
          ? ` — missing per-ID trailers for: ${sec.missingTrailerIds.join(', ')}`
          : ''
        lines.push(
          `contract-change [${sec.sourceLabel}]: FAIL (${sec.hits.length} contract edit(s) require one "Contract-change: <id> <reason>" commit trailer per changed tunable/gate ID${missingNote}):`,
        )
        for (const h of sec.hits) {
          const sym = h.symbol ? ` ${h.symbol}` : ''
          lines.push(`  ${h.file}:${h.line} [${h.kind}]${sym}: ${h.before} -> ${h.after}`)
        }
      }
    }
    const p = sec.parity
    if (p?.required) {
      if (p.overridden && p.ok) {
        lines.push(`parity-gate [${sec.sourceLabel}]: OVERRIDE (${p.kernelFilesTouched.length} confirmation-kernel file(s) overridden via Kernel-gate-override: ${p.overrideTrailer})`)
      } else if (p.cosmeticVerified && p.ok) {
        lines.push(`parity-gate [${sec.sourceLabel}]: PASS (cosmetic/non-behavioral kernel diff verified by AST; ${p.kernelFilesTouched.length} file(s))`)
      } else if (p.ok && !p.warned) {
        const via = p.corpusFilesTouched.length > 0
          ? `corpus diff (${p.corpusFilesTouched.length} file(s))`
          : `Parity-case: ${p.validParityCaseIds.join(', ')}`
        lines.push(`parity-gate [${sec.sourceLabel}]: PASS (${p.kernelFilesTouched.length} confirmation-kernel file(s) covered by ${via})`)
      } else if (p.warned) {
        lines.push(`parity-gate [${sec.sourceLabel}]: WARN (${p.reason})`)
      } else {
        lines.push(`parity-gate [${sec.sourceLabel}]: FAIL (${p.reason})`)
      }
    }
  }
  if (lines.length === 0) {
    lines.push(
      `contract-change: PASS (${result.committed.sourceLabel}, 0 un-trailered tunable/assert edits in ${result.durationMs}ms)`,
    )
  }
  return lines.join('\n')
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const usage = `Kovo Contract-Change Diff Lint

Usage:
  node scripts/check-contract-change.ts [options]

Options:
  --base <ref>             Check committed diff merge-base(<ref>, HEAD)..HEAD strictly (default: auto merge-base)
  --check-head             Check HEAD~1..HEAD strictly when at base ref
  --staged                 Check staged diff (--cached) strictly
  --allow-uncommitted      Warn-only on uncommitted working tree edits (default)
  --strict-uncommitted     Fail on uncommitted working tree edits without --commit-msg
  --strict-per-id          Require explicit ID mention in Contract-change trailer even for a single changed ID
  --commit-msg <text>      Provide commit message text (for hooks / tests)
  --commit-msg-file <path> Read commit message text from file
  --root <dir>             Repository root directory (default: repo root)
  --json                   Emit structured JSON result
  -h, --help               Show this help
`

export function main(argv: string[] = process.argv.slice(2)): number {
  let rootDir = REPO_ROOT
  let baseRef: string | null = null
  let stagedOnly = false
  let checkHead = false
  let strictUncommitted = false
  let strictPerId = false
  let commitMessageOverride: string | null = null
  let json = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      process.stdout.write(usage)
      return 0
    }
    if (arg === '--json') { json = true; continue }
    if (arg === '--staged') { stagedOnly = true; continue }
    if (arg === '--check-head') { checkHead = true; continue }
    if (arg === '--allow-uncommitted') { strictUncommitted = false; continue }
    if (arg === '--strict-uncommitted') { strictUncommitted = true; continue }
    if (arg === '--strict-per-id') { strictPerId = true; continue }
    if (arg === '--base') {
      const next = argv[i + 1]
      if (next === undefined) { process.stderr.write('error: --base requires a git ref\n'); return 2 }
      baseRef = next; i += 1; continue
    }
    if (arg === '--root') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --root requires a directory\n'); return 2 }
      rootDir = resolve(next); i += 1; continue
    }
    if (arg === '--commit-msg') {
      const next = argv[i + 1]
      if (next === undefined) { process.stderr.write('error: --commit-msg requires text\n'); return 2 }
      commitMessageOverride = next; i += 1; continue
    }
    if (arg === '--commit-msg-file') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --commit-msg-file requires a file path\n'); return 2 }
      commitMessageOverride = readFileSync(resolve(next), 'utf8'); i += 1; continue
    }
    process.stderr.write(`error: unknown argument '${arg}'\n`)
    return 2
  }

  const result = checkGitRepo({
    rootDir,
    baseRef,
    stagedOnly,
    checkHead,
    strictUncommitted,
    strictPerId,
    commitMessageOverride,
  })
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else {
    const report = `${formatContractChangeReport(result)}\n`
    if (result.ok) process.stdout.write(report)
    else process.stderr.write(report)
  }
  return result.ok ? 0 : 1
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  process.exit(main())
}
