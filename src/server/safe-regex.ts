/**
 * Single untrusted-regex chokepoint for worker/model-supplied patterns (`H-32` / `R2-H-26`).
 *
 * Rejects backreferences, lookarounds, control characters, overly long patterns, stacked or
 * nested quantifiers, optional/variable atoms inside repeated groups, quantified overlapping
 * alternations, overlapping quantified chains, and caps haystack length before matching.
 */

const MAX_CLAIM_REGEX_LEN = 256
const MAX_CLAIM_REGEX_LEN_HARD_CAP = 512
const MAX_CLAIM_REGEX_ALTERNATIONS = 16
const MAX_CLAIM_REGEX_DEPTH = 6
const MAX_CLAIM_REGEX_REPEAT = 100
const MAX_CLAIM_REGEX_QUANTIFIERS = 16
const MAX_CLAIM_REGEX_UNBOUNDED = 4
const MAX_CLAIM_REGEX_OPTIONALS = 8
const MAX_CLAIM_REGEX_CONSECUTIVE_OPTIONALS = 4
export const MAX_CLAIM_REGEX_HAYSTACK = 4096
export const MAX_UNTRUSTED_REGEX_HAYSTACK_CAP = 32_768

const ALLOWED_FLAGS = new Set(['i', 'm', 's', 'u'])

export interface SafeRegexCompileOptions {
  flags?: string
  maxLength?: number
}

export interface UntrustedRegexOptions {
  flags?: string
  maxPatternLen?: number
  maxHaystackLen?: number
}

export type UntrustedRegexResult =
  | { ok: true; matched: boolean; match: RegExpExecArray | null; truncated: boolean }
  | { ok: false; matched: false; match: null; reason: string }

/**
 * Compact ASCII character-class bitset (128 bits as four 32-bit ints + nonAscii flag)
 * for O(1) overlap detection between adjacent/chained quantified regex atoms.
 */
interface CharSet {
  w0: number
  w1: number
  w2: number
  w3: number
  nonAscii: boolean
}

function emptySet(): CharSet {
  return { w0: 0, w1: 0, w2: 0, w3: 0, nonAscii: false }
}

function fullSet(): CharSet {
  return { w0: -1, w1: -1, w2: -1, w3: -1, nonAscii: true }
}

function addCode(set: CharSet, code: number): void {
  if (code < 0) return
  if (code >= 128) {
    set.nonAscii = true
    return
  }
  const bit = 1 << (code & 31)
  if (code < 32) set.w0 |= bit
  else if (code < 64) set.w1 |= bit
  else if (code < 96) set.w2 |= bit
  else set.w3 |= bit
}

function addRange(set: CharSet, start: number, end: number): void {
  const lo = Math.max(0, start)
  const hi = Math.min(127, end)
  for (let c = lo; c <= hi; c += 1) addCode(set, c)
  if (end >= 128) set.nonAscii = true
}

function invertSet(set: CharSet): CharSet {
  return {
    w0: ~set.w0,
    w1: ~set.w1,
    w2: ~set.w2,
    w3: ~set.w3,
    nonAscii: !set.nonAscii,
  }
}

function unionInto(target: CharSet, other: CharSet): void {
  target.w0 |= other.w0
  target.w1 |= other.w1
  target.w2 |= other.w2
  target.w3 |= other.w3
  target.nonAscii = target.nonAscii || other.nonAscii
}

function setContainsCode(set: CharSet, code: number): boolean {
  if (code < 0) return false
  if (code >= 128) return set.nonAscii
  const bit = 1 << (code & 31)
  if (code < 32) return (set.w0 & bit) !== 0
  if (code < 64) return (set.w1 & bit) !== 0
  if (code < 96) return (set.w2 & bit) !== 0
  return (set.w3 & bit) !== 0
}

function setsOverlap(a: CharSet, b: CharSet): boolean {
  return ((a.w0 & b.w0) !== 0) ||
    ((a.w1 & b.w1) !== 0) ||
    ((a.w2 & b.w2) !== 0) ||
    ((a.w3 & b.w3) !== 0) ||
    (a.nonAscii && b.nonAscii)
}

function escapeCharSet(codeChar: string): CharSet {
  const s = emptySet()
  switch (codeChar) {
    case 'd':
      addRange(s, 48, 57)
      return s
    case 'D':
      return invertSet(escapeCharSet('d'))
    case 'w':
      addRange(s, 48, 57)
      addRange(s, 65, 90)
      addRange(s, 97, 122)
      addCode(s, 95)
      return s
    case 'W':
      return invertSet(escapeCharSet('w'))
    case 's':
      addCode(s, 9)
      addCode(s, 10)
      addCode(s, 11)
      addCode(s, 12)
      addCode(s, 13)
      addCode(s, 32)
      s.nonAscii = true
      return s
    case 'S':
      return invertSet(escapeCharSet('s'))
    case 't':
      addCode(s, 9)
      return s
    case 'n':
      addCode(s, 10)
      return s
    case 'r':
      addCode(s, 13)
      return s
    case 'f':
      addCode(s, 12)
      return s
    case 'v':
      addCode(s, 11)
      return s
    default:
      addCode(s, codeChar.charCodeAt(0))
      return s
  }
}

function literalCharSet(ch: string, ignoreCase: boolean): CharSet {
  const s = emptySet()
  if (ignoreCase) {
    addCode(s, ch.toLowerCase().charCodeAt(0))
    addCode(s, ch.toUpperCase().charCodeAt(0))
  } else {
    addCode(s, ch.charCodeAt(0))
  }
  return s
}

function parseCharClassSet(pattern: string, openIdx: number, ignoreCase: boolean): { set: CharSet; closeIdx: number } | null {
  let i = openIdx + 1
  if (i >= pattern.length) return null
  const negated = pattern[i] === '^'
  if (negated) i += 1
  const set = emptySet()
  let prevCharCode: number | null = null
  const start = i
  while (i < pattern.length) {
    const ch = pattern[i]!
    if (ch === ']' && i > start) {
      return { set: negated ? invertSet(set) : set, closeIdx: i }
    }
    if (ch === '\\' && i + 1 < pattern.length) {
      const next = pattern[i + 1]!
      if (next === 'd' || next === 'D' || next === 'w' || next === 'W' || next === 's' || next === 'S') {
        unionInto(set, escapeCharSet(next))
        prevCharCode = null
      } else {
        const escSet = escapeCharSet(next)
        unionInto(set, escSet)
        prevCharCode = next.charCodeAt(0)
      }
      i += 2
      continue
    }
    if (ch === '-' && prevCharCode !== null && i + 1 < pattern.length && pattern[i + 1] !== ']') {
      let endCode: number
      if (pattern[i + 1] === '\\' && i + 2 < pattern.length) {
        endCode = pattern[i + 2]!.charCodeAt(0)
        i += 3
      } else {
        endCode = pattern[i + 1]!.charCodeAt(0)
        i += 2
      }
      if (prevCharCode <= endCode) {
        addRange(set, prevCharCode, endCode)
        if (ignoreCase) {
          for (let c = Math.max(65, prevCharCode); c <= Math.min(90, endCode); c += 1) addCode(set, c + 32)
          for (let c = Math.max(97, prevCharCode); c <= Math.min(122, endCode); c += 1) addCode(set, c - 32)
        }
      }
      prevCharCode = null
      continue
    }
    unionInto(set, literalCharSet(ch, ignoreCase))
    prevCharCode = ch.charCodeAt(0)
    i += 1
  }
  return null
}

function validateFlags(flags: string | undefined): { ok: true; flags: string } | { ok: false; reason: string } {
  if (!flags) return { ok: true, flags: '' }
  const seen = new Set<string>()
  for (const ch of flags) {
    if (!ALLOWED_FLAGS.has(ch) || seen.has(ch)) {
      return { ok: false, reason: `Disallowed or duplicate regex flag "${ch}".` }
    }
    seen.add(ch)
  }
  return { ok: true, flags }
}

/**
 * Compile a worker/model-supplied claim regex with a fast static ReDoS validator.
 * Rejects overly long patterns, control chars, backreferences, lookarounds, stacked or nested
 * quantifiers, optional/variable atoms inside repeated groups, ambiguous quantified alternations,
 * overlapping quantified chains, and excessive alternations/nesting before `new RegExp` or
 * `.exec()` can touch the host event loop.
 */
export function compileSafeClaimRegex(
  pattern: string,
  opts?: SafeRegexCompileOptions,
): { ok: true; regex: RegExp } | { ok: false; reason: string } {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    return { ok: false, reason: 'Regex pattern must be non-empty.' }
  }
  const maxLen = Math.max(1, Math.min(opts?.maxLength ?? MAX_CLAIM_REGEX_LEN, MAX_CLAIM_REGEX_LEN_HARD_CAP))
  if (pattern.length > maxLen) {
    return { ok: false, reason: `Regex exceeds ${maxLen} character limit.` }
  }
  if (/[\0\r\n]/.test(pattern)) {
    return { ok: false, reason: 'Regex contains forbidden control characters.' }
  }
  const flagCheck = validateFlags(opts?.flags)
  if (!flagCheck.ok) return flagCheck
  const ignoreCase = flagCheck.flags.includes('i')

  type Frame = {
    hasQuantifier: boolean
    hasVariableQuantifier: boolean
    hasAlt: boolean
    branches: string[]
    curBranch: string
    charUnion: CharSet
  }
  const stack: Frame[] = [{
    hasQuantifier: false,
    hasVariableQuantifier: false,
    hasAlt: false,
    branches: [],
    curBranch: '',
    charUnion: emptySet(),
  }]
  let totalAlts = 0
  let totalQuantifiers = 0
  let totalUnbounded = 0
  let totalOptionals = 0
  let consecutiveOptionals = 0
  let prevWasQuantifier = false
  let lastClosedGroup: Frame | null = null
  let curAtomSet: CharSet | null = null
  let prevUnboundedSet: CharSet | null = null

  const readQuantifier = (idx: number): {
    end: number
    min: number
    max: number
    repeatsMoreThanOnce: boolean
    unbounded: boolean
    variable: boolean
    tooLarge: boolean
  } | null => {
    const ch = pattern[idx]
    if (ch === '+' || ch === '*') {
      const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
      const min = ch === '+' ? 1 : 0
      return { end, min, max: Infinity, repeatsMoreThanOnce: true, unbounded: true, variable: true, tooLarge: false }
    }
    if (ch === '?') {
      const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
      return { end, min: 0, max: 1, repeatsMoreThanOnce: false, unbounded: false, variable: true, tooLarge: false }
    }
    if (ch === '{') {
      const m = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(idx))
      if (!m) return null
      const min = Number(m[1])
      const hasComma = m[0].includes(',')
      const max = hasComma ? (m[2] ? Number(m[2]) : Infinity) : min
      if (Number.isFinite(max) && max < min) return null
      const rawEnd = idx + m[0].length
      const end = pattern[rawEnd] === '?' ? rawEnd + 1 : rawEnd
      const tooLarge = min > MAX_CLAIM_REGEX_REPEAT || (Number.isFinite(max) && max > MAX_CLAIM_REGEX_REPEAT)
      return {
        end,
        min,
        max,
        repeatsMoreThanOnce: max > 1,
        unbounded: !Number.isFinite(max),
        variable: min !== max,
        tooLarge,
      }
    }
    return null
  }

  const branchesMayOverlap = (branches: readonly string[]): boolean => {
    const starts = new Set<string>()
    for (const raw of branches) {
      const b = raw.trim()
      if (!b) return true
      if (b[0] === '.' || b[0] === '[' || b[0] === '(' || b[0] === '\\') return true
      const lead = ignoreCase ? b[0]!.toLowerCase() : b[0]!
      if (starts.has(lead)) return true
      starts.add(lead)
    }
    return false
  }

  for (let i = 0; i < pattern.length; ) {
    const ch = pattern[i]!
    const top = stack[stack.length - 1]!

    if (ch === '\\') {
      if (i + 1 >= pattern.length) return { ok: false, reason: 'Trailing escape in regex.' }
      const next = pattern[i + 1]!
      if (/[1-9]/.test(next) || (next === 'k' && pattern[i + 2] === '<')) {
        return { ok: false, reason: 'Regex backreferences are not allowed.' }
      }
      prevWasQuantifier = false
      lastClosedGroup = null
      const atomSet = escapeCharSet(next)
      curAtomSet = atomSet
      unionInto(top.charUnion, atomSet)
      if (prevUnboundedSet && (next !== 'b' && next !== 'B')) {
        if (!setsOverlap(prevUnboundedSet, atomSet)) prevUnboundedSet = null
      }
      top.curBranch += pattern.slice(i, i + 2)
      i += 2
      continue
    }

    if (ch === '[') {
      const parsed = parseCharClassSet(pattern, i, ignoreCase)
      if (!parsed) return { ok: false, reason: 'Unbalanced character class in regex.' }
      prevWasQuantifier = false
      lastClosedGroup = null
      curAtomSet = parsed.set
      unionInto(top.charUnion, parsed.set)
      // If a character class is NOT followed by an unbounded quantifier, check if it breaks the chain
      if (prevUnboundedSet && !setsOverlap(prevUnboundedSet, parsed.set)) {
        prevUnboundedSet = null
      }
      top.curBranch += pattern.slice(i, parsed.closeIdx + 1)
      i = parsed.closeIdx + 1
      continue
    }

    if (ch === '(') {
      if (pattern[i + 1] === '?') {
        const marker = pattern[i + 2]
        if (marker === '=' || marker === '!' || (marker === '<' && (pattern[i + 3] === '=' || pattern[i + 3] === '!'))) {
          return { ok: false, reason: 'Regex lookarounds are not allowed.' }
        }
        if (marker !== ':') {
          if (marker === '<') {
            const nameMatch = /^\(\?<([A-Za-z_][A-Za-z0-9_]*)>/.exec(pattern.slice(i))
            if (!nameMatch) return { ok: false, reason: 'Unsupported regex group syntax.' }
            if (stack.length > MAX_CLAIM_REGEX_DEPTH) {
              return { ok: false, reason: `Regex group nesting exceeds limit (${MAX_CLAIM_REGEX_DEPTH}).` }
            }
            prevWasQuantifier = false
            lastClosedGroup = null
            curAtomSet = null
            prevUnboundedSet = null
            consecutiveOptionals = 0
            stack.push({ hasQuantifier: false, hasVariableQuantifier: false, hasAlt: false, branches: [], curBranch: '', charUnion: emptySet() })
            i += nameMatch[0].length
            continue
          }
          return { ok: false, reason: 'Unsupported regex group syntax.' }
        }
      }
      if (stack.length > MAX_CLAIM_REGEX_DEPTH) {
        return { ok: false, reason: `Regex group nesting exceeds limit (${MAX_CLAIM_REGEX_DEPTH}).` }
      }
      prevWasQuantifier = false
      lastClosedGroup = null
      curAtomSet = null
      prevUnboundedSet = null
      consecutiveOptionals = 0
      stack.push({ hasQuantifier: false, hasVariableQuantifier: false, hasAlt: false, branches: [], curBranch: '', charUnion: emptySet() })
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
      if (frame.hasVariableQuantifier) parent.hasVariableQuantifier = true
      unionInto(parent.charUnion, frame.charUnion)
      parent.curBranch += '()'
      lastClosedGroup = frame
      prevWasQuantifier = false
      curAtomSet = frame.charUnion
      prevUnboundedSet = null
      consecutiveOptionals = 0
      i += 1
      continue
    }

    if (ch === '|') {
      totalAlts += 1
      if (totalAlts > MAX_CLAIM_REGEX_ALTERNATIONS) {
        return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_ALTERNATIONS} alternations.` }
      }
      top.hasAlt = true
      top.branches.push(top.curBranch)
      top.curBranch = ''
      prevWasQuantifier = false
      lastClosedGroup = null
      curAtomSet = null
      prevUnboundedSet = null
      consecutiveOptionals = 0
      i += 1
      continue
    }

    const q = readQuantifier(i)
    if (q) {
      if (prevWasQuantifier) {
        return { ok: false, reason: 'Stacked quantifiers risk catastrophic backtracking (ReDoS).' }
      }
      if (q.tooLarge) {
        return { ok: false, reason: `Quantifier repetition exceeds limit (${MAX_CLAIM_REGEX_REPEAT}).` }
      }
      totalQuantifiers += 1
      if (totalQuantifiers > MAX_CLAIM_REGEX_QUANTIFIERS) {
        return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_QUANTIFIERS} quantifiers.` }
      }
      if (q.variable) {
        top.hasVariableQuantifier = true
      }
      if (q.min === 0 && q.max === 1) {
        totalOptionals += 1
        consecutiveOptionals += 1
        if (totalOptionals > MAX_CLAIM_REGEX_OPTIONALS || consecutiveOptionals > MAX_CLAIM_REGEX_CONSECUTIVE_OPTIONALS) {
          return { ok: false, reason: 'Excessive optional quantifiers risk exponential backtracking (ReDoS).' }
        }
      } else {
        consecutiveOptionals = 0
      }
      if (q.unbounded) {
        totalUnbounded += 1
        if (totalUnbounded > MAX_CLAIM_REGEX_UNBOUNDED) {
          return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_UNBOUNDED} unbounded quantifiers.` }
        }
      }
      if (q.repeatsMoreThanOnce) {
        top.hasQuantifier = true
        if (lastClosedGroup && (lastClosedGroup.hasQuantifier || lastClosedGroup.hasVariableQuantifier)) {
          return { ok: false, reason: 'Nested or variable quantifiers inside a repeated group risk catastrophic backtracking (ReDoS).' }
        }
        if (lastClosedGroup?.hasAlt && branchesMayOverlap(lastClosedGroup.branches)) {
          return { ok: false, reason: 'Quantified overlapping alternation risks catastrophic backtracking (ReDoS).' }
        }
        if (q.variable && curAtomSet) {
          if (prevUnboundedSet && setsOverlap(prevUnboundedSet, curAtomSet)) {
            return { ok: false, reason: 'Overlapping quantified chain risks polynomial backtracking (ReDoS).' }
          }
          if (q.unbounded) {
            prevUnboundedSet = curAtomSet
          }
        } else if (!q.unbounded) {
          prevUnboundedSet = null
        }
      }
      prevWasQuantifier = true
      lastClosedGroup = null
      curAtomSet = null
      top.curBranch += pattern.slice(i, q.end)
      i = q.end
      continue
    }

    prevWasQuantifier = false
    lastClosedGroup = null
    if (ch === '^' || ch === '$') {
      curAtomSet = null
      prevUnboundedSet = null
      consecutiveOptionals = 0
      top.curBranch += ch
      i += 1
      continue
    }

    const atomSet = ch === '.' ? fullSet() : literalCharSet(ch, ignoreCase)
    curAtomSet = atomSet
    unionInto(top.charUnion, atomSet)
    // A literal character that is NOT matched by the preceding unbounded atom breaks the
    // backtracking overlap chain (e.g. `[a-z0-9]+_[0-9a-f]{12}`). A character that IS matched
    // (e.g. `_` after `\w+`, or `a` after `.*`) keeps the overlap chain live so `\w+_\w+` and
    // `.*a.*` are rejected.
    if (prevUnboundedSet) {
      const breaksChain = ch !== '.' && !setContainsCode(prevUnboundedSet, ch.charCodeAt(0)) &&
        (!ignoreCase || (!setContainsCode(prevUnboundedSet, ch.toLowerCase().charCodeAt(0)) &&
          !setContainsCode(prevUnboundedSet, ch.toUpperCase().charCodeAt(0))))
      if (breaksChain) prevUnboundedSet = null
    }
    if (pattern[i + 1] !== '?') consecutiveOptionals = 0
    top.curBranch += ch
    i += 1
  }

  if (stack.length !== 1) return { ok: false, reason: 'Unbalanced regex syntax.' }
  try {
    return { ok: true, regex: new RegExp(pattern, flagCheck.flags) }
  } catch {
    return { ok: false, reason: 'Invalid regular expression syntax.' }
  }
}

/**
 * Single chokepoint for executing untrusted/worker/model-supplied regex patterns.
 * Rejects backreferences, lookarounds, overly long patterns, and ReDoS constructs via
 * `compileSafeClaimRegex`, then caps the haystack length before matching.
 */
export function runUntrustedRegex(
  pattern: string,
  text: string,
  opts?: UntrustedRegexOptions,
): UntrustedRegexResult {
  const compiled = compileSafeClaimRegex(pattern, {
    flags: opts?.flags,
    maxLength: opts?.maxPatternLen,
  })
  if (!compiled.ok) {
    return { ok: false, matched: false, match: null, reason: compiled.reason }
  }
  const cap = Math.max(0, Math.min(opts?.maxHaystackLen ?? MAX_CLAIM_REGEX_HAYSTACK, MAX_UNTRUSTED_REGEX_HAYSTACK_CAP))
  const source = typeof text === 'string' ? text : ''
  const truncated = source.length > cap
  const haystack = truncated ? source.slice(0, cap) : source
  const match = compiled.regex.exec(haystack)
  return { ok: true, matched: match !== null, match, truncated }
}
