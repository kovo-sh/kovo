/**
 * Static ReDoS-safe regex compiler for worker/model-supplied claim patterns.
 */

const MAX_CLAIM_REGEX_LEN = 256
const MAX_CLAIM_REGEX_ALTERNATIONS = 16
const MAX_CLAIM_REGEX_DEPTH = 6
const MAX_CLAIM_REGEX_REPEAT = 100
export const MAX_CLAIM_REGEX_HAYSTACK = 4096

/**
 * Compile a worker/model-supplied claim regex with a fast static ReDoS validator.
 * Rejects overly long patterns, control chars, backreferences, lookarounds, stacked or nested
 * quantifiers, ambiguous quantified alternations, and excessive alternations/nesting before
 * `new RegExp` or `.test()` can touch the host event loop.
 */
export function compileSafeClaimRegex(pattern: string): { ok: true; regex: RegExp } | { ok: false; reason: string } {
  if (typeof pattern !== 'string' || pattern.length === 0) return { ok: false, reason: 'Regex pattern must be non-empty.' }
  if (pattern.length > MAX_CLAIM_REGEX_LEN) return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_LEN} character limit.` }
  if (/[\0\r\n]/.test(pattern)) return { ok: false, reason: 'Regex contains forbidden control characters.' }
  if (/\\[1-9]|\\k</.test(pattern)) return { ok: false, reason: 'Regex backreferences are not allowed.' }
  if (/\(\?[=!<]/.test(pattern)) return { ok: false, reason: 'Regex lookarounds are not allowed.' }

  type Frame = { hasQuantifier: boolean; hasAlt: boolean; branches: string[]; curBranch: string }
  const stack: Frame[] = [{ hasQuantifier: false, hasAlt: false, branches: [], curBranch: '' }]
  let inClass = false
  let totalAlts = 0
  let prevWasQuantifier = false
  let lastClosedGroup: Frame | null = null
  let curAtomWildcard: string | null = null
  let prevUnboundedWildcard: string | null = null

  const readQuantifier = (idx: number): { end: number; repeatsMoreThanOnce: boolean; unbounded: boolean; tooLarge: boolean } | null => {
    const ch = pattern[idx]
    if (ch === '+' || ch === '*') {
      const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
      return { end, repeatsMoreThanOnce: true, unbounded: true, tooLarge: false }
    }
    if (ch === '?') {
      const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
      return { end, repeatsMoreThanOnce: false, unbounded: false, tooLarge: false }
    }
    if (ch === '{') {
      const m = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(idx))
      if (!m) return null
      const min = Number(m[1]), hasComma = m[0].includes(','), max = hasComma ? (m[2] ? Number(m[2]) : Infinity) : min
      const rawEnd = idx + m[0].length
      const end = pattern[rawEnd] === '?' ? rawEnd + 1 : rawEnd
      const tooLarge = min > MAX_CLAIM_REGEX_REPEAT || (Number.isFinite(max) && max > MAX_CLAIM_REGEX_REPEAT)
      return { end, repeatsMoreThanOnce: max > 1, unbounded: !Number.isFinite(max), tooLarge }
    }
    return null
  }

  const branchesMayOverlap = (branches: readonly string[]): boolean => {
    const starts = new Set<string>()
    for (const raw of branches) {
      const b = raw.trim()
      if (!b) return true
      if (b[0] === '.' || b[0] === '[' || b[0] === '(' || b[0] === '\\') return true
      if (starts.has(b[0]!)) return true
      starts.add(b[0]!)
    }
    return false
  }

  for (let i = 0; i < pattern.length; ) {
    const ch = pattern[i]!
    const top = stack[stack.length - 1]!
    if (inClass) {
      if (ch === '\\') { top.curBranch += pattern.slice(i, i + 2); i += 2; continue }
      if (ch === ']') inClass = false
      top.curBranch += ch
      i += 1
      continue
    }
    if (ch === '\\') {
      prevWasQuantifier = false
      lastClosedGroup = null
      const esc = pattern.slice(i, i + 2)
      curAtomWildcard = (esc === '\\s' || esc === '\\S' || esc === '\\w' || esc === '\\W' || esc === '\\d' || esc === '\\D') ? esc : null
      if (!curAtomWildcard) prevUnboundedWildcard = null
      top.curBranch += esc
      i += 2
      continue
    }
    if (ch === '[') {
      inClass = true
      prevWasQuantifier = false
      lastClosedGroup = null
      const closeIdx = pattern.indexOf(']', i + 1)
      curAtomWildcard = closeIdx > i ? pattern.slice(i, closeIdx + 1) : '['
      top.curBranch += ch
      i += 1
      continue
    }
    if (ch === '(') {
      if (stack.length > MAX_CLAIM_REGEX_DEPTH) return { ok: false, reason: `Regex group nesting exceeds limit (${MAX_CLAIM_REGEX_DEPTH}).` }
      prevWasQuantifier = false
      lastClosedGroup = null
      curAtomWildcard = null
      prevUnboundedWildcard = null
      stack.push({ hasQuantifier: false, hasAlt: false, branches: [], curBranch: '' })
      if (pattern[i + 1] === '?' && pattern[i + 2] === ':') i += 3
      else i += 1
      continue
    }
    if (ch === ')') {
      if (stack.length <= 1) return { ok: false, reason: 'Unbalanced closing parenthesis.' }
      const frame = stack.pop()!
      frame.branches.push(frame.curBranch)
      const parent = stack[stack.length - 1]!
      if (frame.hasQuantifier) parent.hasQuantifier = true
      parent.curBranch += '()'
      lastClosedGroup = frame
      prevWasQuantifier = false
      curAtomWildcard = null
      prevUnboundedWildcard = null
      i += 1
      continue
    }
    if (ch === '|') {
      totalAlts += 1
      if (totalAlts > MAX_CLAIM_REGEX_ALTERNATIONS) return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_ALTERNATIONS} alternations.` }
      top.hasAlt = true
      top.branches.push(top.curBranch)
      top.curBranch = ''
      prevWasQuantifier = false
      lastClosedGroup = null
      curAtomWildcard = null
      prevUnboundedWildcard = null
      i += 1
      continue
    }
    const q = readQuantifier(i)
    if (q) {
      if (prevWasQuantifier) return { ok: false, reason: 'Stacked quantifiers risk catastrophic backtracking (ReDoS).' }
      if (q.tooLarge) return { ok: false, reason: `Quantifier repetition exceeds limit (${MAX_CLAIM_REGEX_REPEAT}).` }
      if (q.repeatsMoreThanOnce) {
        top.hasQuantifier = true
        if (lastClosedGroup?.hasQuantifier) return { ok: false, reason: 'Nested quantifiers risk catastrophic backtracking (ReDoS).' }
        if (lastClosedGroup?.hasAlt && branchesMayOverlap(lastClosedGroup.branches)) {
          return { ok: false, reason: 'Quantified overlapping alternation risks catastrophic backtracking (ReDoS).' }
        }
        if (q.unbounded && curAtomWildcard) {
          const overlapsPrev = prevUnboundedWildcard !== null && (
            prevUnboundedWildcard === '.' || curAtomWildcard === '.' || prevUnboundedWildcard === curAtomWildcard
          )
          if (overlapsPrev) return { ok: false, reason: 'Adjacent unbounded wildcards risk catastrophic backtracking (ReDoS).' }
          prevUnboundedWildcard = curAtomWildcard
        } else {
          prevUnboundedWildcard = null
        }
      }
      prevWasQuantifier = true
      lastClosedGroup = null
      curAtomWildcard = null
      top.curBranch += pattern.slice(i, q.end)
      i = q.end
      continue
    }
    prevWasQuantifier = false
    lastClosedGroup = null
    curAtomWildcard = ch === '.' ? '.' : null
    if (!curAtomWildcard) prevUnboundedWildcard = null
    top.curBranch += ch
    i += 1
  }
  if (inClass || stack.length !== 1) return { ok: false, reason: 'Unbalanced regex syntax.' }
  try {
    return { ok: true, regex: new RegExp(pattern) }
  } catch {
    return { ok: false, reason: 'Invalid regular expression syntax.' }
  }
}
