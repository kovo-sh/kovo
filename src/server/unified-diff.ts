/**
 * Strict hunk-counted unified diff parser and validator (M-24).
 *
 * Parses unified diffs strictly by declared `@@ -a,b +c,d @@` hunk line counts so
 * removed lines starting with `-- ` (e.g. SQL comments, YAML separators, CLI flags)
 * or added lines starting with `++ ` never prematurely terminate a hunk.
 *
 * Security invariants enforced during parsing:
 * - Rejects path traversal (`..`, `.`, absolute paths, backslashes, NUL/control chars, drive letters).
 * - Rejects binary patch markers (`GIT binary patch`, `Binary files ... differ`).
 * - Rejects git symlink (`120000`) and submodule/gitlink (`160000`) mode changes.
 * - Rejects malformed hunk headers, missing `+++` pairings, empty file patches,
 *   truncated hunks, extra trailing hunk lines, and mismatched old/new line counts.
 */

export interface ParsedHunkLine {
  kind: 'context' | 'add' | 'remove'
  text: string
  raw: string
}

export interface ParsedHunk {
  oldStart: number
  oldCount: number
  newStart: number
  newCount: number
  headerContext?: string
  /** Raw prefixed lines (` `, `-`, `+`) matching exact oldCount/newCount. */
  lines: string[]
  /** Structured representation of each hunk line. */
  entries: ParsedHunkLine[]
}

export interface ParsedFilePatch {
  oldPath: string
  newPath: string
  /** Normalized repository-relative path (without leading `a/` or `b/`). */
  normalizedPath: string
  isCreate: boolean
  isDelete: boolean
  hunks: ParsedHunk[]
}

export class UnifiedDiffError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'UnifiedDiffError'
  }
}

export interface ParseUnifiedDiffOptions {
  /** When true, an empty diff returns `[]` instead of throwing. Default: false. */
  allowEmpty?: boolean
}

const HUNK_HEADER_RE = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: ?(.*))?$/
const GIT_DIFF_HEADER_RE = /^diff --git (\S+) (\S+)$/
const DISALLOWED_MODE_RE = /^(?:old mode|new mode|new file mode|deleted file mode) (120000|160000)\b/
const BINARY_PATCH_RE = /^(?:GIT binary patch|Binary files .+ differ)$/

function stripPrefixForRole(raw: string, role: 'old' | 'new'): string {
  if (role === 'old' && raw.startsWith('a/')) return raw.slice(2)
  if (role === 'new' && raw.startsWith('b/')) return raw.slice(2)
  // Also strip the other standard prefix if a tool emitted a/b consistently on one side
  if (raw.startsWith('a/') || raw.startsWith('b/')) return raw.slice(2)
  return raw
}

/**
 * Validate and normalize a unified-diff file path (`---` / `+++` / `diff --git`).
 * Returns `'/dev/null'` for create/delete sentinels, or a clean POSIX repo-relative path.
 * Throws `UnifiedDiffError` with an `Unsafe ... escapes ...` message on traversal or invalid paths.
 */
export function validateDiffPath(rawPath: string, role: 'old' | 'new'): string {
  if (/[\x00-\x08\x0a-\x1f\x7f]/.test(rawPath)) {
    throw new UnifiedDiffError(`Unsafe diff path contains control characters: "${rawPath}"`)
  }
  const trimmed = rawPath.split('\t')[0]?.trim() ?? ''
  if (!trimmed) {
    throw new UnifiedDiffError(`Unsafe diff path: empty ${role} file header path.`)
  }
  if (trimmed === '/dev/null') return '/dev/null'

  // Reject git C-quoted paths (often used for control chars/escapes or non-portable names)
  if (trimmed.startsWith('"') || trimmed.endsWith('"')) {
    throw new UnifiedDiffError(`Unsafe quoted diff path rejected: "${trimmed}"`)
  }
  if (/[\x00-\x1f\x7f]/.test(trimmed)) {
    throw new UnifiedDiffError(`Unsafe diff path contains control characters: "${trimmed}"`)
  }
  if (trimmed.startsWith('-')) {
    throw new UnifiedDiffError(`Unsafe diff path starts with "-" (option injection rejected): "${trimmed}"`)
  }
  if (trimmed.includes('\\') || /^[A-Za-z]:/.test(trimmed)) {
    throw new UnifiedDiffError(`Unsafe diff path escapes repository root (non-POSIX separator or drive): "${trimmed}"`)
  }

  const stripped = stripPrefixForRole(trimmed, role)
  if (!stripped || stripped.startsWith('/') || stripped.endsWith('/')) {
    throw new UnifiedDiffError(`Unsafe diff path escapes repository root: "${trimmed}"`)
  }
  if (stripped.startsWith('-')) {
    throw new UnifiedDiffError(`Unsafe diff path starts with "-" (option injection rejected): "${trimmed}"`)
  }

  const segments = stripped.split('/')
  for (const seg of segments) {
    if (!seg || seg === '.' || seg === '..') {
      throw new UnifiedDiffError(`Unsafe diff path escapes repository root: "${trimmed}"`)
    }
  }
  return stripped
}

/**
 * Parse and strictly validate a unified diff string using declared hunk line counts.
 */
export function parseUnifiedDiff(diffText: string, options: ParseUnifiedDiffOptions = {}): ParsedFilePatch[] {
  if (typeof diffText !== 'string') {
    throw new UnifiedDiffError('Unified diff must be a string.')
  }
  const normalized = diffText.replace(/\r\n/g, '\n')
  if (!normalized.trim()) {
    if (options.allowEmpty) return []
    throw new UnifiedDiffError('Unified diff contains no valid file hunks.')
  }

  // Drop a single trailing empty element produced by a final newline so EOF truncation is exact.
  const rawLines = normalized.endsWith('\n')
    ? normalized.slice(0, -1).split('\n')
    : normalized.split('\n')

  const patches: ParsedFilePatch[] = []
  let i = 0

  while (i < rawLines.length) {
    const line = rawLines[i]!

    if (BINARY_PATCH_RE.test(line)) {
      throw new UnifiedDiffError(`Binary patches are rejected: "${line}"`)
    }
    const badMode = DISALLOWED_MODE_RE.exec(line)
    if (badMode) {
      throw new UnifiedDiffError(`Unsafe git file mode (${badMode[1]}) rejected (symlinks/gitlinks not permitted).`)
    }
    if (line.startsWith('rename from ') || line.startsWith('rename to ')) {
      const role = line.startsWith('rename from ') ? 'old' : 'new'
      const rawRenamePath = line.slice(line.indexOf(' ', 7) + 1)
      validateDiffPath(rawRenamePath, role)
      throw new UnifiedDiffError(`File renames are unsupported in unified diff patches: "${line}"`)
    }
    if (line.startsWith('copy from ') || line.startsWith('copy to ')) {
      const role = line.startsWith('copy from ') ? 'old' : 'new'
      const rawCopyPath = line.slice(line.indexOf(' ', 5) + 1)
      validateDiffPath(rawCopyPath, role)
      throw new UnifiedDiffError(`File copies are unsupported in unified diff patches: "${line}"`)
    }
    if (line.startsWith('diff --git ')) {
      const m = GIT_DIFF_HEADER_RE.exec(line)
      if (!m) {
        throw new UnifiedDiffError(`Malformed diff --git header: "${line}"`)
      }
      const oldDiffPath = validateDiffPath(m[1]!, 'old')
      const newDiffPath = validateDiffPath(m[2]!, 'new')
      if (oldDiffPath !== newDiffPath) {
        throw new UnifiedDiffError(`File renames/copies are unsupported in diff --git header: ${oldDiffPath} -> ${newDiffPath}`)
      }
      i += 1
      continue
    }
    if (line.startsWith('@@')) {
      throw new UnifiedDiffError(`Malformed diff: hunk header appeared before ---/+++ file header: "${line}"`)
    }

    if (line.startsWith('--- ')) {
      const rawOldPath = line.slice(4).split('\t')[0]?.trim() ?? ''
      const nextLine = rawLines[i + 1]
      if (nextLine === undefined || !nextLine.startsWith('+++ ')) {
        throw new UnifiedDiffError(`Malformed diff: missing +++ header after "${line}"`)
      }
      const rawNewPath = nextLine.slice(4).split('\t')[0]?.trim() ?? ''

      const normOld = validateDiffPath(rawOldPath, 'old')
      const normNew = validateDiffPath(rawNewPath, 'new')
      const isCreate = normOld === '/dev/null'
      const isDelete = normNew === '/dev/null'
      if (isCreate && isDelete) {
        throw new UnifiedDiffError('Malformed diff: both old and new file paths cannot be /dev/null.')
      }
      if (!isCreate && !isDelete && normOld !== normNew) {
        throw new UnifiedDiffError(`File renames/copies across different paths (${normOld} -> ${normNew}) are unsupported in unified diff patches.`)
      }
      const normalizedPath = isDelete ? normOld : normNew
      i += 2

      const hunks: ParsedHunk[] = []
      while (i < rawLines.length) {
        const hLine = rawLines[i]!
        if (hLine === '') {
          i += 1
          continue
        }
        if (hLine.startsWith('diff --git ') || hLine.startsWith('--- ')) {
          break
        }
        if (BINARY_PATCH_RE.test(hLine)) {
          throw new UnifiedDiffError(`Binary patches are rejected: "${hLine}"`)
        }
        const hBadMode = DISALLOWED_MODE_RE.exec(hLine)
        if (hBadMode) {
          throw new UnifiedDiffError(`Unsafe git file mode (${hBadMode[1]}) rejected (symlinks/gitlinks not permitted).`)
        }
        if (!hLine.startsWith('@@')) {
          throw new UnifiedDiffError(`Unexpected line between hunks in ${normalizedPath}: "${hLine}"`)
        }

        const match = HUNK_HEADER_RE.exec(hLine)
        if (!match) {
          throw new UnifiedDiffError(`Malformed hunk header in ${normalizedPath}: "${hLine}"`)
        }
        const oldStart = Number(match[1])
        const oldCount = match[2] !== undefined ? Number(match[2]) : 1
        const newStart = Number(match[3])
        const newCount = match[4] !== undefined ? Number(match[4]) : 1
        const headerContext = match[5] ? match[5] : undefined

        if (!Number.isSafeInteger(oldStart) || !Number.isSafeInteger(oldCount) || !Number.isSafeInteger(newStart) || !Number.isSafeInteger(newCount)) {
          throw new UnifiedDiffError(`Invalid numeric range in hunk header: "${hLine}"`)
        }
        if (oldCount === 0 && newCount === 0) {
          throw new UnifiedDiffError(`Malformed hunk header with zero old and new line counts: "${hLine}"`)
        }
        if ((oldCount > 0 && oldStart < 1) || (newCount > 0 && newStart < 1)) {
          throw new UnifiedDiffError(`Invalid 0 start line for non-empty hunk: "${hLine}"`)
        }

        i += 1
        const hunkLines: string[] = []
        const entries: ParsedHunkLine[] = []
        let seenOld = 0
        let seenNew = 0

        // Strictly count old/new lines according to the @@ header.
        // Removed lines starting with `-- ` (prefixed as `--- `) or added lines starting with
        // `++ ` (prefixed as `+++ `) are consumed as hunk content while counts remain unsatisfied.
        while (seenOld < oldCount || seenNew < newCount) {
          if (i >= rawLines.length) {
            throw new UnifiedDiffError(
              `Truncated hunk in ${normalizedPath} at @@ -${oldStart},${oldCount} +${newStart},${newCount} @@: ` +
              `expected ${oldCount} old / ${newCount} new lines, got ${seenOld} old / ${seenNew} new.`,
            )
          }
          const contentLine = rawLines[i]!
          if (contentLine.startsWith('\\ No newline at end of file')) {
            i += 1
            continue
          }
          if (contentLine.startsWith(' ')) {
            seenOld += 1
            seenNew += 1
            if (seenOld > oldCount || seenNew > newCount) {
              throw new UnifiedDiffError(
                `Hunk line count mismatch in ${normalizedPath} at @@ -${oldStart},${oldCount} +${newStart},${newCount} @@: ` +
                `context line overflowed declared counts (${seenOld}/${oldCount} old, ${seenNew}/${newCount} new).`,
              )
            }
            hunkLines.push(contentLine)
            entries.push({ kind: 'context', text: contentLine.slice(1), raw: contentLine })
            i += 1
          } else if (contentLine.startsWith('-')) {
            seenOld += 1
            if (seenOld > oldCount) {
              throw new UnifiedDiffError(
                `Hunk line count mismatch in ${normalizedPath} at @@ -${oldStart},${oldCount} +${newStart},${newCount} @@: ` +
                `removed lines exceeded declared oldCount (${seenOld} > ${oldCount}).`,
              )
            }
            hunkLines.push(contentLine)
            entries.push({ kind: 'remove', text: contentLine.slice(1), raw: contentLine })
            i += 1
          } else if (contentLine.startsWith('+')) {
            seenNew += 1
            if (seenNew > newCount) {
              throw new UnifiedDiffError(
                `Hunk line count mismatch in ${normalizedPath} at @@ -${oldStart},${oldCount} +${newStart},${newCount} @@: ` +
                `added lines exceeded declared newCount (${seenNew} > ${newCount}).`,
              )
            }
            hunkLines.push(contentLine)
            entries.push({ kind: 'add', text: contentLine.slice(1), raw: contentLine })
            i += 1
          } else if (
            contentLine === ''
            && seenOld < oldCount
            && seenNew < newCount
          ) {
            // Blank context line whose trailing space was stripped by an editor (including at EOF or section boundary).
            seenOld += 1
            seenNew += 1
            hunkLines.push(' ')
            entries.push({ kind: 'context', text: '', raw: ' ' })
            i += 1
          } else {
            throw new UnifiedDiffError(
              `Malformed hunk body in ${normalizedPath} at @@ -${oldStart},${oldCount} +${newStart},${newCount} @@: ` +
              `unexpected line "${contentLine.slice(0, 80)}" after ${seenOld}/${oldCount} old and ${seenNew}/${newCount} new lines.`,
            )
          }
        }

        // Consume optional `\ No newline at end of file` marker immediately after the last hunk line.
        while (i < rawLines.length && rawLines[i]!.startsWith('\\ No newline at end of file')) {
          i += 1
        }

        // Reject extra uncounted hunk body lines after declared counts are already satisfied.
        if (i < rawLines.length) {
          const trailing = rawLines[i]!
          const isExtraContent =
            trailing.startsWith(' ')
            || (trailing.startsWith('+') && !trailing.startsWith('+++ '))
            || (trailing.startsWith('-') && !trailing.startsWith('--- '))
          if (isExtraContent) {
            throw new UnifiedDiffError(
              `Hunk line count mismatch in ${normalizedPath} at @@ -${oldStart},${oldCount} +${newStart},${newCount} @@: ` +
              `extra uncounted line after declared hunk end: "${trailing.slice(0, 80)}".`,
            )
          }
        }

        hunks.push({
          oldStart,
          oldCount,
          newStart,
          newCount,
          ...(headerContext !== undefined ? { headerContext } : {}),
          lines: hunkLines,
          entries,
        })
      }

      if (hunks.length === 0) {
        throw new UnifiedDiffError(`File patch for ${normalizedPath} contains no valid hunks.`)
      }

      patches.push({
        oldPath: rawOldPath,
        newPath: rawNewPath,
        normalizedPath,
        isCreate,
        isDelete,
        hunks,
      })
      continue
    }

    if (
      line === ''
      || line.startsWith('index ')
      || line.startsWith('old mode ')
      || line.startsWith('new mode ')
      || line.startsWith('new file mode ')
      || line.startsWith('deleted file mode ')
      || line.startsWith('similarity index ')
      || line.startsWith('dissimilarity index ')
    ) {
      i += 1
      continue
    }

    // Reject stray `+++ ` without a preceding `--- ` header.
    if (line.startsWith('+++ ')) {
      throw new UnifiedDiffError(`Malformed diff: unexpected +++ header without preceding ---: "${line}"`)
    }

    throw new UnifiedDiffError(`Unexpected line outside diff hunk: "${line.slice(0, 80)}"`)
  }

  if (patches.length === 0 && !options.allowEmpty) {
    throw new UnifiedDiffError('Unified diff contains no valid file hunks.')
  }

  return patches
}

/**
 * Non-throwing wrapper around `parseUnifiedDiff`.
 */
export function validateUnifiedDiff(
  diffText: string,
): { ok: true; patches: ParsedFilePatch[] } | { ok: false; error: string } {
  try {
    return { ok: true, patches: parseUnifiedDiff(diffText) }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

/**
 * Produce the exact inverse unified diff so a previously applied patch can be cleanly reverted.
 * File creations invert to deletions (`/dev/null` target) and file deletions invert to creations.
 */
export function invertUnifiedDiff(diffText: string): string {
  const patches = parseUnifiedDiff(diffText)
  const out: string[] = []
  for (const patch of patches) {
    const invOldHeader = patch.isDelete ? '/dev/null' : `a/${patch.normalizedPath}`
    const invNewHeader = patch.isCreate ? '/dev/null' : `b/${patch.normalizedPath}`
    out.push(`--- ${invOldHeader}`, `+++ ${invNewHeader}`)
    for (const hunk of patch.hunks) {
      const ctx = hunk.headerContext ? ` ${hunk.headerContext}` : ''
      out.push(`@@ -${hunk.newStart},${hunk.newCount} +${hunk.oldStart},${hunk.oldCount} @@${ctx}`)
      for (const entry of hunk.entries) {
        if (entry.kind === 'context') out.push(` ${entry.text}`)
        else if (entry.kind === 'add') out.push(`-${entry.text}`)
        else out.push(`+${entry.text}`)
      }
    }
  }
  return out.join('\n') + '\n'
}
