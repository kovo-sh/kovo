#!/usr/bin/env node
/**
 * Independent Different-Model Kernel Review Lane Gate (`R3-05`, plans/claude_quality_3.md §5).
 *
 * Inspects a commit range (`--base <ref>`, default `HEAD~1`) to determine whether any file in
 * the confirmation-kernel set is touched (loading `scripts/kernel-manifest.json` when present,
 * with fallback to the complete 20-file confirmation-kernel list + `CONFIRMATION_KERNEL_FILE_RE`).
 *
 * When a confirmation-kernel file IS touched (and no valid operator-signed
 * `Expedited-kernel-fix: <operator-id> <reason>` override trailer is present):
 *   1. Requires a `Reviewed-by: <reviewer-model-id> <bypass-case-id>` trailer.
 *   2. Verifies `<reviewer-model-id>` is a valid non-placeholder model identifier belonging to a
 *      DIFFERENT model family from any `Author-model: <author-model-id>` trailer (or `--author-model`).
 *   3. Verifies `<bypass-case-id>` resolves to a rejecting FP corpus case
 *      (`tests/parity/corpus/*.json` with `expected.confirmed === false` and `side !== "tp"`)
 *      added or updated in the diff (or explicitly allowed via `--allow-case-id` in unit tests).
 *
 * Non-kernel diffs pass cleanly in milliseconds.
 *
 * Usage:
 *   node scripts/check-kernel-review.ts [--base <ref>] [--root <dir>] [--author-model <id>]
 *                                       [--allow-case-id <id>] [--commit-msg <text>]
 *                                       [--json] [-h|--help]
 */
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  CONFIRMATION_KERNEL_FILE_RE,
  isParityCorpusFile,
  parseUnifiedDiff,
  resolveCommitBaseRef,
} from './check-contract-change.ts'

export const FALLBACK_CONFIRMATION_KERNEL_FILES: readonly string[] = Object.freeze([
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
  'src/server/terminal-oracle-registry.ts',
  'src/server/v8-oracle-families.ts',
  'src/server/v8-oracle-hydrate.ts',
  'src/server/verify-claims.ts',
  'src/server/verify-prove-handlers.ts',
  'src/server/verify-rpc.ts',
  'src/server/verify-runner.ts',
  'src/server/verify-support.ts',
])

const FALLBACK_CONFIRMATION_KERNEL_SET = new Set<string>(FALLBACK_CONFIRMATION_KERNEL_FILES)

export interface KernelManifestInfo {
  source: 'scripts/kernel-manifest.json' | 'fallback-20-file-set'
  files: ReadonlySet<string>
}

export interface ReviewedByTrailer {
  reviewerModelId: string
  reviewerFamily: string
  bypassCaseId: string
  raw: string
}

export interface ExpeditedOverrideTrailer {
  operatorId: string
  reason: string
  raw: string
}

export interface BypassCaseValidation {
  caseId: string
  ok: boolean
  viaAllowList: boolean
  corpusFile: string | null
  expectedConfirmed: boolean | null
  side: string | null
  reason: string | null
}

export interface KernelReviewEvalResult {
  ok: boolean
  required: boolean
  manifestSource: 'scripts/kernel-manifest.json' | 'fallback-20-file-set'
  sourceLabel: string
  kernelFilesTouched: string[]
  corpusFilesInDiff: string[]
  expeditedOverride: ExpeditedOverrideTrailer | null
  authorModels: Array<{ modelId: string; family: string }>
  reviewedByTrailers: ReviewedByTrailer[]
  acceptedReview: ReviewedByTrailer | null
  bypassCase: BypassCaseValidation | null
  violations: string[]
  durationMs: number
}

export interface EvaluateKernelReviewOptions {
  diffText?: string
  changedFiles?: readonly string[]
  addedOrModifiedCorpusFiles?: readonly string[]
  commitMessages: string
  rootDir?: string
  sourceLabel?: string
  authorModelOverride?: string | null
  allowCaseIds?: ReadonlySet<string>
  corpusFileContents?: ReadonlyMap<string, string>
  kernelFilesOverride?: ReadonlySet<string>
}

export interface CheckKernelReviewRepoOptions {
  rootDir?: string
  baseRef?: string | null
  authorModelOverride?: string | null
  allowCaseIds?: ReadonlySet<string>
  commitMessageOverride?: string | null
}

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const REVIEWED_BY_ALL_RE = /^\s*Reviewed-by:\s*(.+)$/gim
const AUTHOR_MODEL_ALL_RE = /^\s*Author-model:\s*(\S+)/gim
const EXPEDITED_FIX_RE = /^\s*Expedited-kernel-fix:\s*(.+)$/im

const PLACEHOLDER_MODEL_IDS = new Set([
  'self',
  'same',
  'none',
  'n/a',
  'na',
  'tbd',
  'todo',
  'unknown',
  'unassigned',
  'auto',
  'null',
  'undefined',
])

function normalizePath(relPath: string): string {
  return relPath.replace(/\\/g, '/').replace(/^\.\//, '')
}

/**
 * Load the confirmation-kernel file set from `scripts/kernel-manifest.json` if present,
 * falling back to the canonical 20-file confirmation-kernel list when the manifest is absent.
 */
export function loadConfirmationKernelManifest(rootDir: string = REPO_ROOT): KernelManifestInfo {
  const manifestPath = join(rootDir, 'scripts', 'kernel-manifest.json')
  if (existsSync(manifestPath)) {
    try {
      const raw = JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown
      const extracted: string[] = []
      const pushEntry = (entry: unknown) => {
        if (typeof entry === 'string' && entry.trim().length > 0) {
          extracted.push(normalizePath(entry.trim()))
        } else if (entry && typeof entry === 'object') {
          const rec = entry as { file?: unknown; path?: unknown }
          if (typeof rec.file === 'string' && rec.file.trim().length > 0) {
            extracted.push(normalizePath(rec.file.trim()))
          } else if (typeof rec.path === 'string' && rec.path.trim().length > 0) {
            extracted.push(normalizePath(rec.path.trim()))
          }
        }
      }
      if (Array.isArray(raw)) {
        for (const item of raw) pushEntry(item)
      } else if (raw && typeof raw === 'object') {
        const obj = raw as { files?: unknown; kernelFiles?: unknown }
        if (Array.isArray(obj.files)) {
          for (const item of obj.files) pushEntry(item)
        } else if (Array.isArray(obj.kernelFiles)) {
          for (const item of obj.kernelFiles) pushEntry(item)
        }
      }
      if (extracted.length > 0) {
        return { source: 'scripts/kernel-manifest.json', files: new Set(extracted) }
      }
    } catch {
      // Fall through to canonical 20-file fallback list on unreadable/malformed manifest.
    }
  }
  return {
    source: 'fallback-20-file-set',
    files: new Set(FALLBACK_CONFIRMATION_KERNEL_SET),
  }
}

export function isKernelReviewProtectedFile(relPath: string, manifestFiles: ReadonlySet<string>): boolean {
  const norm = normalizePath(relPath)
  if (/(?:\.test|\.spec)\.[^./]+$/i.test(norm)) return false
  if (manifestFiles.has(norm)) return true
  return CONFIRMATION_KERNEL_FILE_RE.test(norm)
}

/**
 * Normalize a model identifier (e.g. `claude-opus-4-6`, `google/gemini-2.5-pro`, `opencode-glm-5`)
 * to its model family so same-family self-review is rejected.
 */
export function extractModelFamily(modelId: string): string {
  const raw = modelId.trim().toLowerCase()
  if (!raw || PLACEHOLDER_MODEL_IDS.has(raw)) return 'invalid'

  if (/(?:^|[/_\-:.])(?:claude|anthropic|opus|sonnet|haiku)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'anthropic-claude'
  }
  if (/(?:^|[/_\-:.])(?:gemini|google|gemma|palm)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'google-gemini'
  }
  if (/(?:^|[/_\-:.])(?:gpt|openai|codex|chatgpt|o1|o3|o4)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'openai-gpt'
  }
  if (/(?:^|[/_\-:.])(?:glm|chatglm|zhipu|z-ai|zai)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'zhipu-glm'
  }
  if (/(?:^|[/_\-:.])deepseek(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'deepseek'
  }
  if (/(?:^|[/_\-:.])(?:qwen|qwq|alibaba)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'alibaba-qwen'
  }
  if (/(?:^|[/_\-:.])(?:llama|meta-llama)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'meta-llama'
  }
  if (/(?:^|[/_\-:.])(?:mistral|mixtral|codestral)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'mistral'
  }
  if (/(?:^|[/_\-:.])(?:grok|xai|x-ai)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'xai-grok'
  }
  if (/(?:^|[/_\-:.])(?:kimi|moonshot)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'moonshot-kimi'
  }
  if (/(?:^|[/_\-:.])minimax(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'minimax'
  }
  if (/(?:^|[/_\-:.])(?:human|operator)(?:$|[/_\-:.0-9])/.test(raw)) {
    return 'human'
  }

  // Fallback: strip routing prefix like `openrouter/` or `opencode/` and take leading alpha family token.
  const withoutRouter = raw.replace(/^(?:openrouter|opencode|local|api)[/:_-]+/, '')
  const seg = withoutRouter.split(/[/_\-:.]+/).find(s => /[a-z]/.test(s))
  return seg && !PLACEHOLDER_MODEL_IDS.has(seg) ? seg : 'invalid'
}

export function parseReviewedByTrailers(commitMessages: string): {
  parsed: ReviewedByTrailer[]
  malformed: string[]
} {
  const parsed: ReviewedByTrailer[] = []
  const malformed: string[] = []
  REVIEWED_BY_ALL_RE.lastIndex = 0
  for (const m of commitMessages.matchAll(REVIEWED_BY_ALL_RE)) {
    const raw = (m[1] ?? '').trim()
    if (!raw) continue
    const tokens = raw.split(/\s+/).filter(Boolean)
    if (tokens.length < 2) {
      malformed.push(raw)
      continue
    }
    const reviewerModelId = tokens[0]!.replace(/[,;:]+$/, '')
    const bypassCaseId = tokens[1]!.replace(/[,;:]+$/, '')
    if (reviewerModelId.length < 2 || bypassCaseId.length < 2) {
      malformed.push(raw)
      continue
    }
    parsed.push({
      reviewerModelId,
      reviewerFamily: extractModelFamily(reviewerModelId),
      bypassCaseId,
      raw,
    })
  }
  return { parsed, malformed }
}

export function parseAuthorModels(
  commitMessages: string,
  override?: string | null,
): Array<{ modelId: string; family: string }> {
  const seen = new Set<string>()
  const out: Array<{ modelId: string; family: string }> = []
  const add = (rawId: string) => {
    const modelId = rawId.trim().replace(/[,;:]+$/, '')
    if (!modelId || seen.has(modelId.toLowerCase())) return
    seen.add(modelId.toLowerCase())
    out.push({ modelId, family: extractModelFamily(modelId) })
  }
  if (override && override.trim()) add(override)
  AUTHOR_MODEL_ALL_RE.lastIndex = 0
  for (const m of commitMessages.matchAll(AUTHOR_MODEL_ALL_RE)) {
    if (m[1]) add(m[1])
  }
  return out
}

export function parseExpeditedOverrideTrailer(commitMessages: string): {
  valid: ExpeditedOverrideTrailer | null
  malformed: string | null
} {
  const m = EXPEDITED_FIX_RE.exec(commitMessages)
  if (!m) return { valid: null, malformed: null }
  const raw = (m[1] ?? '').trim()
  const parts = /^(\S+)\s+(.+)$/.exec(raw)
  if (!parts) return { valid: null, malformed: raw || '(empty)' }
  const operatorId = parts[1]!.trim()
  const reason = parts[2]!.trim()
  if (operatorId.length < 3 || reason.length < 6) {
    return { valid: null, malformed: raw }
  }
  return { valid: { operatorId, reason, raw }, malformed: null }
}

function validateBypassCaseId(opts: {
  caseId: string
  corpusFilesInDiff: readonly string[]
  allowCaseIds?: ReadonlySet<string>
  rootDir?: string
  corpusFileContents?: ReadonlyMap<string, string>
}): BypassCaseValidation {
  if (opts.allowCaseIds?.has(opts.caseId)) {
    return {
      caseId: opts.caseId,
      ok: true,
      viaAllowList: true,
      corpusFile: null,
      expectedConfirmed: false,
      side: 'fp',
      reason: null,
    }
  }

  for (const relPath of opts.corpusFilesInDiff) {
    const norm = normalizePath(relPath)
    let rawText: string | null = opts.corpusFileContents?.get(norm) ?? null
    if (rawText === null && opts.rootDir) {
      const abs = join(opts.rootDir, norm)
      if (existsSync(abs)) {
        try {
          rawText = readFileSync(abs, 'utf8')
        } catch {
          rawText = null
        }
      }
    }
    if (rawText === null) continue
    let parsed: { id?: unknown; side?: unknown; expected?: { confirmed?: unknown } }
    try {
      parsed = JSON.parse(rawText) as { id?: unknown; side?: unknown; expected?: { confirmed?: unknown } }
    } catch {
      continue
    }
    if (typeof parsed.id !== 'string' || parsed.id.trim() !== opts.caseId) continue

    const expectedConfirmed =
      typeof parsed.expected?.confirmed === 'boolean' ? parsed.expected.confirmed : null
    const side = typeof parsed.side === 'string' ? parsed.side.trim().toLowerCase() : null

    if (expectedConfirmed !== false) {
      return {
        caseId: opts.caseId,
        ok: false,
        viaAllowList: false,
        corpusFile: norm,
        expectedConfirmed,
        side,
        reason: `Bypass case "${opts.caseId}" (${norm}) must be a rejecting case ("expected.confirmed": false), got ${String(expectedConfirmed)}.`,
      }
    }
    if (side !== null && side !== 'fp') {
      return {
        caseId: opts.caseId,
        ok: false,
        viaAllowList: false,
        corpusFile: norm,
        expectedConfirmed,
        side,
        reason: `Bypass case "${opts.caseId}" (${norm}) must be an FP case ("side": "fp"), got "${side}".`,
      }
    }
    return {
      caseId: opts.caseId,
      ok: true,
      viaAllowList: false,
      corpusFile: norm,
      expectedConfirmed: false,
      side: side ?? 'fp',
      reason: null,
    }
  }

  return {
    caseId: opts.caseId,
    ok: false,
    viaAllowList: false,
    corpusFile: null,
    expectedConfirmed: null,
    side: null,
    reason: `Bypass case "${opts.caseId}" was not found among newly added/updated rejecting FP corpus cases in tests/parity/corpus/*.json in this diff.`,
  }
}

export function evaluateKernelReview(opts: EvaluateKernelReviewOptions): KernelReviewEvalResult {
  const startedAt = performance.now()
  const manifest = opts.kernelFilesOverride
    ? { source: 'scripts/kernel-manifest.json' as const, files: opts.kernelFilesOverride }
    : loadConfirmationKernelManifest(opts.rootDir ?? REPO_ROOT)

  const parsedFiles = opts.diffText ? parseUnifiedDiff(opts.diffText) : []
  const changedFiles = opts.changedFiles
    ? [...new Set(opts.changedFiles.map(normalizePath).filter(Boolean))]
    : [...new Set(parsedFiles.map(f => normalizePath(f.file)).filter(Boolean))]

  const corpusFilesInDiff = opts.addedOrModifiedCorpusFiles
    ? [...new Set(opts.addedOrModifiedCorpusFiles.map(normalizePath).filter(isParityCorpusFile))]
    : [...new Set(parsedFiles.filter(f => !f.deleted).map(f => normalizePath(f.file)).filter(isParityCorpusFile))]

  const kernelFilesTouched = changedFiles.filter(f => isKernelReviewProtectedFile(f, manifest.files))
  const sourceLabel = opts.sourceLabel ?? 'diff'

  if (kernelFilesTouched.length === 0) {
    return {
      ok: true,
      required: false,
      manifestSource: manifest.source,
      sourceLabel,
      kernelFilesTouched: [],
      corpusFilesInDiff,
      expeditedOverride: null,
      authorModels: [],
      reviewedByTrailers: [],
      acceptedReview: null,
      bypassCase: null,
      violations: [],
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const authorModels = parseAuthorModels(opts.commitMessages, opts.authorModelOverride)
  const expedited = parseExpeditedOverrideTrailer(opts.commitMessages)
  if (expedited.valid) {
    return {
      ok: true,
      required: true,
      manifestSource: manifest.source,
      sourceLabel,
      kernelFilesTouched,
      corpusFilesInDiff,
      expeditedOverride: expedited.valid,
      authorModels,
      reviewedByTrailers: [],
      acceptedReview: null,
      bypassCase: null,
      violations: [],
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const violations: string[] = []
  if (expedited.malformed) {
    violations.push(
      `Malformed "Expedited-kernel-fix:" trailer ("${expedited.malformed}"); expected "Expedited-kernel-fix: <operator-id> <reason (min 6 chars)>".`,
    )
  }

  const { parsed: reviewedByTrailers, malformed: malformedReviewedBy } = parseReviewedByTrailers(
    opts.commitMessages,
  )

  if (reviewedByTrailers.length === 0) {
    if (malformedReviewedBy.length > 0) {
      violations.push(
        `Malformed "Reviewed-by:" trailer (${malformedReviewedBy.join('; ')}); confirmation-kernel diff (${kernelFilesTouched.join(', ')}) requires "Reviewed-by: <reviewer-model-id> <bypass-case-id>".`,
      )
    } else {
      violations.push(
        `Confirmation-kernel diff (${kernelFilesTouched.join(', ')}) requires a different-model "Reviewed-by: <reviewer-model-id> <bypass-case-id>" trailer (or operator-signed "Expedited-kernel-fix: <operator-id> <reason>").`,
      )
    }
    return {
      ok: false,
      required: true,
      manifestSource: manifest.source,
      sourceLabel,
      kernelFilesTouched,
      corpusFilesInDiff,
      expeditedOverride: null,
      authorModels,
      reviewedByTrailers,
      acceptedReview: null,
      bypassCase: null,
      violations,
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const authorFamilies = new Set(authorModels.map(a => a.family).filter(f => f !== 'invalid'))
  let acceptedReview: ReviewedByTrailer | null = null
  let lastBypassValidation: BypassCaseValidation | null = null
  const candidateErrors: string[] = []

  for (const review of reviewedByTrailers) {
    if (review.reviewerFamily === 'invalid') {
      candidateErrors.push(
        `Reviewed-by reviewer model "${review.reviewerModelId}" is invalid or a placeholder; specify a concrete different-family model ID (e.g. claude-opus-4, opencode-glm-5).`,
      )
      continue
    }
    if (authorFamilies.has(review.reviewerFamily)) {
      const matchedAuthors = authorModels
        .filter(a => a.family === review.reviewerFamily)
        .map(a => a.modelId)
        .join(', ')
      candidateErrors.push(
        `Same-family review rejected: reviewer "${review.reviewerModelId}" (family: ${review.reviewerFamily}) matches author model (${matchedAuthors}). Kernel diffs require a different model family.`,
      )
      continue
    }
    const bypass = validateBypassCaseId({
      caseId: review.bypassCaseId,
      corpusFilesInDiff,
      allowCaseIds: opts.allowCaseIds,
      rootDir: opts.rootDir,
      corpusFileContents: opts.corpusFileContents,
    })
    lastBypassValidation = bypass
    if (!bypass.ok) {
      candidateErrors.push(bypass.reason ?? `Bypass case "${review.bypassCaseId}" validation failed.`)
      continue
    }
    acceptedReview = review
    break
  }

  if (!acceptedReview) {
    violations.push(...candidateErrors)
  }

  return {
    ok: violations.length === 0 && acceptedReview !== null,
    required: true,
    manifestSource: manifest.source,
    sourceLabel,
    kernelFilesTouched,
    corpusFilesInDiff,
    expeditedOverride: null,
    authorModels,
    reviewedByTrailers,
    acceptedReview,
    bypassCase: lastBypassValidation,
    violations,
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
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

export function checkKernelReviewRepo(opts: CheckKernelReviewRepoOptions = {}): KernelReviewEvalResult {
  const startedAt = performance.now()
  const rootDir = resolve(opts.rootDir ?? REPO_ROOT)
  const requestedBase = opts.baseRef ?? 'HEAD~1'
  const baseRef = resolveCommitBaseRef(rootDir, requestedBase, true)
  const manifest = loadConfirmationKernelManifest(rootDir)

  if (!baseRef) {
    return {
      ok: true,
      required: false,
      manifestSource: manifest.source,
      sourceLabel: `committed (0 commits ahead of ${requestedBase})`,
      kernelFilesTouched: [],
      corpusFilesInDiff: [],
      expeditedOverride: null,
      authorModels: [],
      reviewedByTrailers: [],
      acceptedReview: null,
      bypassCase: null,
      violations: [],
      durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
    }
  }

  const range = `${baseRef}..HEAD`
  const nameStatusRes = runGit(rootDir, ['diff', '--name-status', range])
  const changedFiles: string[] = []
  const addedOrModifiedCorpusFiles: string[] = []

  if (nameStatusRes.ok) {
    for (const line of nameStatusRes.stdout.split(/\r?\n/)) {
      const trimmed = line.trim()
      if (!trimmed) continue
      const parts = trimmed.split('\t')
      const status = parts[0] ?? ''
      const file = normalizePath(parts[parts.length - 1] ?? '')
      if (!file) continue
      changedFiles.push(file)
      if (!status.startsWith('D') && isParityCorpusFile(file)) {
        addedOrModifiedCorpusFiles.push(file)
      }
    }
  }

  const logRes =
    opts.commitMessageOverride != null
      ? { ok: true, stdout: opts.commitMessageOverride }
      : runGit(rootDir, ['log', '--format=%B', range])

  const corpusFileContents = new Map<string, string>()
  for (const corpusFile of addedOrModifiedCorpusFiles) {
    const abs = join(rootDir, corpusFile)
    if (existsSync(abs)) {
      try {
        corpusFileContents.set(corpusFile, readFileSync(abs, 'utf8'))
        continue
      } catch {
        // Fall back to git show HEAD:<file>
      }
    }
    const showRes = runGit(rootDir, ['show', `HEAD:${corpusFile}`])
    if (showRes.ok) corpusFileContents.set(corpusFile, showRes.stdout)
  }

  const evalRes = evaluateKernelReview({
    changedFiles,
    addedOrModifiedCorpusFiles,
    commitMessages: logRes.stdout,
    rootDir,
    sourceLabel: `committed (${range})`,
    authorModelOverride: opts.authorModelOverride ?? process.env.KOVO_AUTHOR_MODEL ?? null,
    allowCaseIds: opts.allowCaseIds,
    corpusFileContents,
    kernelFilesOverride: manifest.files,
  })
  return {
    ...evalRes,
    manifestSource: manifest.source,
    durationMs: Math.max(0, Math.round(performance.now() - startedAt)),
  }
}

export function formatKernelReviewReport(result: KernelReviewEvalResult): string {
  if (!result.required) {
    return `check-kernel-review [${result.sourceLabel}]: PASS (0 confirmation-kernel files touched; manifest=${result.manifestSource}; ${result.durationMs}ms)`
  }
  if (result.ok && result.expeditedOverride) {
    return `check-kernel-review [${result.sourceLabel}]: PASS — EXPEDITED OVERRIDE (${result.kernelFilesTouched.length} kernel file(s); operator=${result.expeditedOverride.operatorId}; post-merge independent review required within 24h)`
  }
  if (result.ok && result.acceptedReview) {
    const bypassNote = result.bypassCase?.viaAllowList
      ? `${result.acceptedReview.bypassCaseId} (via --allow-case-id)`
      : `${result.acceptedReview.bypassCaseId} (${result.bypassCase?.corpusFile ?? 'corpus'})`
    return `check-kernel-review [${result.sourceLabel}]: PASS (${result.kernelFilesTouched.length} kernel file(s) reviewed by ${result.acceptedReview.reviewerModelId} [${result.acceptedReview.reviewerFamily}], rejecting bypass case=${bypassNote}; ${result.durationMs}ms)`
  }
  const lines = [
    `check-kernel-review [${result.sourceLabel}]: FAIL (${result.kernelFilesTouched.length} confirmation-kernel file(s) touched: ${result.kernelFilesTouched.join(', ')}):`,
  ]
  for (const v of result.violations) {
    lines.push(`  - ${v}`)
  }
  return lines.join('\n')
}

const usage = `Kovo Hunter Independent Kernel Review Lane Gate (R3-05)

Usage:
  node scripts/check-kernel-review.ts [options]

Options:
  --base <ref>             Base git ref to diff against HEAD (default: HEAD~1)
  --root <dir>             Repository root directory (default: repo root)
  --author-model <id>      Author model ID for same-family comparison (also reads Author-model: trailers)
  --allow-case-id <id>     Allow a specific bypass case ID without corpus file lookup (repeatable; unit tests)
  --commit-msg <text>      Override commit message text (for hooks / tests)
  --commit-msg-file <path> Read commit message text from file
  --json                   Emit structured JSON result
  -h, --help               Show this help
`

export function main(argv: string[] = process.argv.slice(2)): number {
  let rootDir = REPO_ROOT
  let baseRef: string | null = 'HEAD~1'
  let authorModelOverride: string | null = null
  const allowCaseIds = new Set<string>()
  let commitMessageOverride: string | null = null
  let json = false

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!
    if (arg === '--help' || arg === '-h') {
      process.stdout.write(usage)
      return 0
    }
    if (arg === '--json') { json = true; continue }
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
    if (arg === '--author-model') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --author-model requires a model ID\n'); return 2 }
      authorModelOverride = next; i += 1; continue
    }
    if (arg === '--allow-case-id') {
      const next = argv[i + 1]
      if (!next) { process.stderr.write('error: --allow-case-id requires a case ID\n'); return 2 }
      allowCaseIds.add(next); i += 1; continue
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

  const result = checkKernelReviewRepo({
    rootDir,
    baseRef,
    authorModelOverride,
    allowCaseIds: allowCaseIds.size > 0 ? allowCaseIds : undefined,
    commitMessageOverride,
  })
  if (json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
  } else {
    const report = `${formatKernelReviewReport(result)}\n`
    if (result.ok) process.stdout.write(report)
    else process.stderr.write(report)
  }
  return result.ok ? 0 : 1
}

const isMain = process.argv[1] ? import.meta.url === pathToFileURL(resolve(process.argv[1])).href : false
if (isMain) {
  process.exit(main())
}
