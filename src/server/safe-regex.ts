/**
 * Single untrusted-regex chokepoint for worker/model-supplied patterns (`H-32` / `R2-H-26` / `R3-H-11`).
 *
 * Parses patterns into a bounded AST with exact JavaScript RegExp semantics and statically rejects:
 * - non-linear / unsupported flags (`i`, `u`, `v`, `g`, `y`, `d`; only `m` and `s` are permitted so
 *   V8's linear-time fallback engine always engages),
 * - backreferences, lookarounds, inline modifier groups (`(?i:...)`), control characters, overly
 *   long patterns, empty / negated-empty character classes (`[]` / `[^]`),
 * - stacked or nested quantifiers, nullable or variable atoms inside repeated groups, quantified
 *   overlapping alternations,
 * - overlapping variable-repetition chains across unquantified group boundaries, alternations,
 *   zero-width assertions, and optional/nullable bridging atoms (`?`, `{0,n}`, `*`, `(?:...)?`).
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

/**
 * Only `m` and `s` preserve V8's `--enable-experimental-regexp-engine-on-excessive-backtracks`
 * linear-time fallback. `i` and `u` disable the fallback and are therefore disallowed (`R3-H-11`).
 */
const ALLOWED_FLAGS = new Set(['m', 's'])

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

function cloneSet(set: CharSet): CharSet {
  return { w0: set.w0, w1: set.w1, w2: set.w2, w3: set.w3, nonAscii: set.nonAscii }
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

function singleCodeSet(code: number): CharSet {
  const s = emptySet()
  addCode(s, code)
  return s
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

function unionSets(a: CharSet, b: CharSet): CharSet {
  return {
    w0: a.w0 | b.w0,
    w1: a.w1 | b.w1,
    w2: a.w2 | b.w2,
    w3: a.w3 | b.w3,
    nonAscii: a.nonAscii || b.nonAscii,
  }
}

function unionNullableSets(a: CharSet | null, b: CharSet | null): CharSet | null {
  if (!a) return b ? cloneSet(b) : null
  if (!b) return cloneSet(a)
  return unionSets(a, b)
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

type ParsedEscape =
  | { ok: true; kind: 'anchor'; end: number }
  | { ok: true; kind: 'shorthand'; set: CharSet; end: number }
  | { ok: true; kind: 'char'; code: number; set: CharSet; end: number }
  | { ok: false; reason: string }

function parseEscape(pattern: string, idx: number, inCharClass: boolean): ParsedEscape {
  if (idx + 1 >= pattern.length) {
    return { ok: false, reason: 'Trailing escape in regex.' }
  }
  const next = pattern[idx + 1]!
  if (!inCharClass) {
    if (/[1-9]/.test(next) || (next === 'k' && pattern[idx + 2] === '<')) {
      return { ok: false, reason: 'Regex backreferences are not allowed.' }
    }
    if (next === 'b' || next === 'B') {
      return { ok: true, kind: 'anchor', end: idx + 2 }
    }
  } else if (next === 'b') {
    return { ok: true, kind: 'char', code: 8, set: singleCodeSet(8), end: idx + 2 }
  }
  if (next === 'd' || next === 'D' || next === 'w' || next === 'W' || next === 's' || next === 'S') {
    return { ok: true, kind: 'shorthand', set: escapeCharSet(next), end: idx + 2 }
  }
  if (next === 'x' && idx + 3 < pattern.length && /^[0-9a-fA-F]{2}$/.test(pattern.slice(idx + 2, idx + 4))) {
    const code = Number.parseInt(pattern.slice(idx + 2, idx + 4), 16)
    return { ok: true, kind: 'char', code, set: singleCodeSet(code), end: idx + 4 }
  }
  if (next === 'u' && idx + 5 < pattern.length && /^[0-9a-fA-F]{4}$/.test(pattern.slice(idx + 2, idx + 6))) {
    const code = Number.parseInt(pattern.slice(idx + 2, idx + 6), 16)
    return { ok: true, kind: 'char', code, set: singleCodeSet(code), end: idx + 6 }
  }
  if (next === 'c' && idx + 2 < pattern.length && /[A-Za-z]/.test(pattern[idx + 2]!)) {
    const code = pattern.charCodeAt(idx + 2) % 32
    return { ok: true, kind: 'char', code, set: singleCodeSet(code), end: idx + 3 }
  }
  if (next === '0' && (idx + 2 >= pattern.length || !/[0-7]/.test(pattern[idx + 2]!))) {
    return { ok: true, kind: 'char', code: 0, set: singleCodeSet(0), end: idx + 2 }
  }
  const controlCodes: Record<string, number> = { t: 9, n: 10, v: 11, f: 12, r: 13 }
  if (next in controlCodes) {
    const code = controlCodes[next]!
    return { ok: true, kind: 'char', code, set: singleCodeSet(code), end: idx + 2 }
  }
  const code = next.charCodeAt(0)
  return { ok: true, kind: 'char', code, set: singleCodeSet(code), end: idx + 2 }
}

/**
 * Parse a JS character class (`[...]`) using exact ECMAScript non-`u` semantics:
 * `]` closes immediately even at the first position (`[]` and `[^]`), never swallowing
 * subsequent tokens (`R3-H-11` Class 3). Empty `[]` and match-any `[^]` are explicitly rejected.
 */
function parseCharClassSet(
  pattern: string,
  openIdx: number,
): { ok: true; set: CharSet; closeIdx: number } | { ok: false; reason: string } {
  let i = openIdx + 1
  if (i >= pattern.length) return { ok: false, reason: 'Unbalanced character class in regex.' }
  const negated = pattern[i] === '^'
  if (negated) i += 1
  const set = emptySet()
  let prevCharCode: number | null = null
  const start = i
  while (i < pattern.length) {
    const ch = pattern[i]!
    if (ch === ']') {
      if (i === start) {
        return {
          ok: false,
          reason: negated
            ? 'Match-any negated empty character class "[^]" is not allowed.'
            : 'Empty character class "[]" is not allowed.',
        }
      }
      return { ok: true, set: negated ? invertSet(set) : set, closeIdx: i }
    }
    if (ch === '\\') {
      const esc = parseEscape(pattern, i, true)
      if (!esc.ok) return esc
      if (esc.kind === 'shorthand') {
        unionInto(set, esc.set)
        prevCharCode = null
      } else if (esc.kind === 'char') {
        unionInto(set, esc.set)
        prevCharCode = esc.code
      }
      i = esc.end
      continue
    }
    if (ch === '-' && prevCharCode !== null && i + 1 < pattern.length && pattern[i + 1] !== ']') {
      if (pattern[i + 1] === '\\') {
        const right = parseEscape(pattern, i + 1, true)
        if (!right.ok) return right
        if (right.kind === 'char') {
          if (prevCharCode > right.code) {
            return { ok: false, reason: 'Invalid character class range in regex.' }
          }
          addRange(set, prevCharCode, right.code)
        } else if (right.kind === 'shorthand') {
          addCode(set, 45)
          unionInto(set, right.set)
        }
        prevCharCode = null
        i = right.end
        continue
      }
      const endCode = pattern.charCodeAt(i + 1)
      if (prevCharCode > endCode) {
        return { ok: false, reason: 'Invalid character class range in regex.' }
      }
      addRange(set, prevCharCode, endCode)
      prevCharCode = null
      i += 2
      continue
    }
    const code = ch.charCodeAt(0)
    addCode(set, code)
    prevCharCode = code
    i += 1
  }
  return { ok: false, reason: 'Unbalanced character class in regex.' }
}

function validateFlags(flags: string | undefined): { ok: true; flags: string } | { ok: false; reason: string } {
  if (flags === undefined || flags === '') return { ok: true, flags: '' }
  if (typeof flags !== 'string') {
    return { ok: false, reason: 'Regex flags must be a string.' }
  }
  const seen = new Set<string>()
  for (const ch of flags) {
    if (!ALLOWED_FLAGS.has(ch) || seen.has(ch)) {
      return { ok: false, reason: `Disallowed or duplicate regex flag "${ch}".` }
    }
    seen.add(ch)
  }
  return { ok: true, flags }
}

interface QuantifierToken {
  end: number
  min: number
  max: number
  repeatsMoreThanOnce: boolean
  unbounded: boolean
  variable: boolean
  tooLarge: boolean
  invalidRange: boolean
}

function readQuantifier(pattern: string, idx: number): QuantifierToken | null {
  const ch = pattern[idx]
  if (ch === '+' || ch === '*') {
    const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
    const min = ch === '+' ? 1 : 0
    return {
      end,
      min,
      max: Infinity,
      repeatsMoreThanOnce: true,
      unbounded: true,
      variable: true,
      tooLarge: false,
      invalidRange: false,
    }
  }
  if (ch === '?') {
    const end = pattern[idx + 1] === '?' ? idx + 2 : idx + 1
    return {
      end,
      min: 0,
      max: 1,
      repeatsMoreThanOnce: false,
      unbounded: false,
      variable: true,
      tooLarge: false,
      invalidRange: false,
    }
  }
  if (ch === '{') {
    const m = /^\{(\d+)(?:,(\d*))?\}/.exec(pattern.slice(idx))
    if (!m) return null
    const min = Number(m[1])
    const hasComma = m[0].includes(',')
    const max = hasComma ? (m[2] ? Number(m[2]) : Infinity) : min
    const rawEnd = idx + m[0].length
    const end = pattern[rawEnd] === '?' ? rawEnd + 1 : rawEnd
    const invalidRange = Number.isFinite(max) && max < min
    const tooLarge = min > MAX_CLAIM_REGEX_REPEAT || (Number.isFinite(max) && max > MAX_CLAIM_REGEX_REPEAT)
    return {
      end,
      min,
      max,
      repeatsMoreThanOnce: max > 1,
      unbounded: !Number.isFinite(max),
      variable: min !== max,
      tooLarge,
      invalidRange,
    }
  }
  return null
}

type AstNode =
  | { kind: 'atom'; set: CharSet }
  | { kind: 'anchor' }
  | { kind: 'seq'; items: AstNode[] }
  | { kind: 'group'; branches: SeqNode[] }
  | {
      kind: 'quant'
      body: AstNode
      min: number
      max: number
      repeatsMoreThanOnce: boolean
      unbounded: boolean
      variable: boolean
    }

type SeqNode = Extract<AstNode, { kind: 'seq' }>

type Result<T> = { ok: true; value: T } | { ok: false; reason: string }

function parseRegexAst(pattern: string): Result<AstNode> {
  let pos = 0
  let depth = 0
  let totalAlts = 0
  let totalQuantifiers = 0
  let totalUnbounded = 0
  let totalOptionals = 0

  const parseAlternation = (): Result<SeqNode[]> => {
    const first = parseSequence()
    if (!first.ok) return first
    const branches: SeqNode[] = [first.value]
    while (pos < pattern.length && pattern[pos] === '|') {
      totalAlts += 1
      if (totalAlts > MAX_CLAIM_REGEX_ALTERNATIONS) {
        return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_ALTERNATIONS} alternations.` }
      }
      pos += 1
      const next = parseSequence()
      if (!next.ok) return next
      branches.push(next.value)
    }
    return { ok: true, value: branches }
  }

  const parseSequence = (): Result<SeqNode> => {
    const items: AstNode[] = []
    while (pos < pattern.length) {
      const ch = pattern[pos]!
      if (ch === ')' || ch === '|') break

      const bareQ = readQuantifier(pattern, pos)
      if (bareQ) {
        return { ok: false, reason: 'Quantifier has no preceding atom in regex.' }
      }

      let node: AstNode
      if (ch === '\\') {
        const esc = parseEscape(pattern, pos, false)
        if (!esc.ok) return esc
        node = esc.kind === 'anchor' ? { kind: 'anchor' } : { kind: 'atom', set: esc.set }
        pos = esc.end
      } else if (ch === '[') {
        const parsed = parseCharClassSet(pattern, pos)
        if (!parsed.ok) return parsed
        node = { kind: 'atom', set: parsed.set }
        pos = parsed.closeIdx + 1
      } else if (ch === '(') {
        if (pattern[pos + 1] === '?') {
          const marker = pattern[pos + 2]
          if (marker === '=' || marker === '!' || (marker === '<' && (pattern[pos + 3] === '=' || pattern[pos + 3] === '!'))) {
            return { ok: false, reason: 'Regex lookarounds are not allowed.' }
          }
          if (marker === ':') {
            pos += 3
          } else if (marker === '<') {
            const nameMatch = /^\(\?<([A-Za-z_][A-Za-z0-9_]*)>/.exec(pattern.slice(pos))
            if (!nameMatch) return { ok: false, reason: 'Unsupported regex group syntax.' }
            pos += nameMatch[0].length
          } else {
            return { ok: false, reason: 'Unsupported regex group syntax.' }
          }
        } else {
          pos += 1
        }
        if (depth >= MAX_CLAIM_REGEX_DEPTH) {
          return { ok: false, reason: `Regex group nesting exceeds limit (${MAX_CLAIM_REGEX_DEPTH}).` }
        }
        depth += 1
        const inner = parseAlternation()
        depth -= 1
        if (!inner.ok) return inner
        if (pos >= pattern.length || pattern[pos] !== ')') {
          return { ok: false, reason: 'Unbalanced regex syntax.' }
        }
        pos += 1
        node = { kind: 'group', branches: inner.value }
      } else if (ch === '^' || ch === '$') {
        node = { kind: 'anchor' }
        pos += 1
      } else if (ch === '.') {
        node = { kind: 'atom', set: fullSet() }
        pos += 1
      } else {
        node = { kind: 'atom', set: singleCodeSet(ch.charCodeAt(0)) }
        pos += 1
      }

      const q = readQuantifier(pattern, pos)
      if (q) {
        if (q.invalidRange) {
          return { ok: false, reason: 'Invalid quantifier range in regex.' }
        }
        if (node.kind === 'anchor') {
          return { ok: false, reason: 'Quantifiers on zero-width assertions are not allowed.' }
        }
        if (q.tooLarge) {
          return { ok: false, reason: `Quantifier repetition exceeds limit (${MAX_CLAIM_REGEX_REPEAT}).` }
        }
        totalQuantifiers += 1
        if (totalQuantifiers > MAX_CLAIM_REGEX_QUANTIFIERS) {
          return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_QUANTIFIERS} quantifiers.` }
        }
        if (q.min === 0 && q.max === 1) {
          totalOptionals += 1
          if (totalOptionals > MAX_CLAIM_REGEX_OPTIONALS) {
            return { ok: false, reason: 'Excessive optional quantifiers risk exponential backtracking (ReDoS).' }
          }
        }
        if (q.unbounded) {
          totalUnbounded += 1
          if (totalUnbounded > MAX_CLAIM_REGEX_UNBOUNDED) {
            return { ok: false, reason: `Regex exceeds ${MAX_CLAIM_REGEX_UNBOUNDED} unbounded quantifiers.` }
          }
        }
        pos = q.end
        if (pos < pattern.length && readQuantifier(pattern, pos)) {
          return { ok: false, reason: 'Stacked quantifiers risk catastrophic backtracking (ReDoS).' }
        }
        node = {
          kind: 'quant',
          body: node,
          min: q.min,
          max: q.max,
          repeatsMoreThanOnce: q.repeatsMoreThanOnce,
          unbounded: q.unbounded,
          variable: q.variable,
        }
      }

      items.push(node)
    }
    return { ok: true, value: { kind: 'seq', items } }
  }

  const top = parseAlternation()
  if (!top.ok) return top
  if (pos < pattern.length) {
    return { ok: false, reason: 'Unbalanced closing parenthesis.' }
  }
  return {
    ok: true,
    value: top.value.length === 1 ? top.value[0]! : { kind: 'group', branches: top.value },
  }
}

interface NodeSummary {
  nullable: boolean
  hasQuantifier: boolean
  hasVariableQuantifier: boolean
  hasOverlappingAlt: boolean
  firstChars: CharSet
  charUnion: CharSet
}

interface FlowState {
  /** Union of character sets of preceding variable-repetition runs not separated by a mandatory non-overlapping barrier. */
  activeSet: CharSet | null
  /** Count of consecutive optional (`?` / `{0,1}`) atoms across group boundaries. */
  consecutiveOptionals: number
}

function analyzeAstSafety(root: AstNode): Result<void> {
  const summaries = new Map<AstNode, NodeSummary>()

  const summarize = (node: AstNode): Result<NodeSummary> => {
    const cached = summaries.get(node)
    if (cached) return { ok: true, value: cached }

    let summary: NodeSummary
    switch (node.kind) {
      case 'atom':
        summary = {
          nullable: false,
          hasQuantifier: false,
          hasVariableQuantifier: false,
          hasOverlappingAlt: false,
          firstChars: cloneSet(node.set),
          charUnion: cloneSet(node.set),
        }
        break
      case 'anchor':
        summary = {
          nullable: true,
          hasQuantifier: false,
          hasVariableQuantifier: false,
          hasOverlappingAlt: false,
          firstChars: emptySet(),
          charUnion: emptySet(),
        }
        break
      case 'seq': {
        let nullable = true
        let hasQuantifier = false
        let hasVariableQuantifier = false
        let hasOverlappingAlt = false
        const firstChars = emptySet()
        const charUnion = emptySet()
        let prefixStillNullable = true
        for (const item of node.items) {
          const s = summarize(item)
          if (!s.ok) return s
          if (prefixStillNullable) {
            unionInto(firstChars, s.value.firstChars)
            if (!s.value.nullable) prefixStillNullable = false
          }
          if (!s.value.nullable) nullable = false
          if (s.value.hasQuantifier) hasQuantifier = true
          if (s.value.hasVariableQuantifier) hasVariableQuantifier = true
          if (s.value.hasOverlappingAlt) hasOverlappingAlt = true
          unionInto(charUnion, s.value.charUnion)
        }
        summary = { nullable, hasQuantifier, hasVariableQuantifier, hasOverlappingAlt, firstChars, charUnion }
        break
      }
      case 'group': {
        let nullable = false
        let hasQuantifier = false
        let hasVariableQuantifier = false
        let hasOverlappingAlt = false
        const firstChars = emptySet()
        const charUnion = emptySet()
        const branchFirsts: CharSet[] = []
        for (const branch of node.branches) {
          const s = summarize(branch)
          if (!s.ok) return s
          if (s.value.nullable) nullable = true
          if (s.value.hasQuantifier) hasQuantifier = true
          if (s.value.hasVariableQuantifier) hasVariableQuantifier = true
          if (s.value.hasOverlappingAlt) hasOverlappingAlt = true
          unionInto(firstChars, s.value.firstChars)
          unionInto(charUnion, s.value.charUnion)
          branchFirsts.push(s.value.firstChars)
        }
        if (node.branches.length > 1) {
          if (nullable) {
            hasOverlappingAlt = true
          } else {
            outer: for (let i = 0; i < branchFirsts.length; i += 1) {
              for (let j = i + 1; j < branchFirsts.length; j += 1) {
                if (setsOverlap(branchFirsts[i]!, branchFirsts[j]!)) {
                  hasOverlappingAlt = true
                  break outer
                }
              }
            }
          }
        }
        summary = { nullable, hasQuantifier, hasVariableQuantifier, hasOverlappingAlt, firstChars, charUnion }
        break
      }
      case 'quant': {
        const bodyRes = summarize(node.body)
        if (!bodyRes.ok) return bodyRes
        const b = bodyRes.value
        if (node.repeatsMoreThanOnce) {
          if (b.hasQuantifier || b.hasVariableQuantifier) {
            return {
              ok: false,
              reason: 'Nested or variable quantifiers inside a repeated group risk catastrophic backtracking (ReDoS).',
            }
          }
          if (b.nullable) {
            return {
              ok: false,
              reason: 'Repeated nullable group risks catastrophic backtracking (ReDoS).',
            }
          }
          if (b.hasOverlappingAlt) {
            return {
              ok: false,
              reason: 'Quantified overlapping alternation risks catastrophic backtracking (ReDoS).',
            }
          }
        }
        summary = {
          nullable: node.min === 0 || b.nullable,
          hasQuantifier: node.repeatsMoreThanOnce || b.hasQuantifier,
          hasVariableQuantifier: node.variable || b.hasVariableQuantifier,
          hasOverlappingAlt: b.hasOverlappingAlt,
          firstChars: node.max === 0 ? emptySet() : cloneSet(b.firstChars),
          charUnion: node.max === 0 ? emptySet() : cloneSet(b.charUnion),
        }
        break
      }
    }

    summaries.set(node, summary)
    return { ok: true, value: summary }
  }

  const rootSummary = summarize(root)
  if (!rootSummary.ok) return rootSummary

  /**
   * Forward dataflow pass tracking active overlapping variable-repetition runs across:
   * - unquantified groups and alternations (Class 1),
   * - optional/nullable bridging atoms `?`, `{0,n}`, `*`, `(?:...)?` (Class 2),
   * - zero-width assertions `^`, `$`, `\b`, `\B`.
   */
  const flow = (node: AstNode, state: FlowState): Result<FlowState> => {
    switch (node.kind) {
      case 'anchor':
        return { ok: true, value: state }

      case 'atom': {
        // A mandatory character that is NOT matched by the preceding active run breaks the
        // backtracking overlap chain (e.g. `[a-z0-9]+_[0-9a-f]{12}`). A character that IS
        // matched (e.g. `_` after `\w+`, or `a` after `.*`) preserves the overlap chain.
        const nextActive = state.activeSet && setsOverlap(state.activeSet, node.set)
          ? cloneSet(state.activeSet)
          : null
        return { ok: true, value: { activeSet: nextActive, consecutiveOptionals: 0 } }
      }

      case 'seq': {
        let cur = state
        for (const item of node.items) {
          const next = flow(item, cur)
          if (!next.ok) return next
          cur = next.value
        }
        return { ok: true, value: cur }
      }

      case 'group': {
        // Carry incoming state into every branch and propagate the conservative union out.
        let mergedActive: CharSet | null = null
        let maxConsec = 0
        for (const branch of node.branches) {
          const out = flow(branch, state)
          if (!out.ok) return out
          if (out.value.activeSet) {
            mergedActive = mergedActive ? unionSets(mergedActive, out.value.activeSet) : cloneSet(out.value.activeSet)
          }
          if (out.value.consecutiveOptionals > maxConsec) {
            maxConsec = out.value.consecutiveOptionals
          }
        }
        return { ok: true, value: { activeSet: mergedActive, consecutiveOptionals: maxConsec } }
      }

      case 'quant': {
        if (node.max === 0) {
          return { ok: true, value: state }
        }
        if (node.min === 1 && node.max === 1) {
          return flow(node.body, state)
        }
        if (node.min === 0 && node.max === 1) {
          // Optional atom/group (`?` / `{0,1}`): transparent on the 0-match path so a
          // non-overlapping optional atom between two overlapping runs never resets the chain.
          const nextConsec = state.consecutiveOptionals + 1
          if (nextConsec > MAX_CLAIM_REGEX_CONSECUTIVE_OPTIONALS) {
            return { ok: false, reason: 'Excessive optional quantifiers risk exponential backtracking (ReDoS).' }
          }
          const taken = flow(node.body, state)
          if (!taken.ok) return taken
          return {
            ok: true,
            value: {
              activeSet: unionNullableSets(state.activeSet, taken.value.activeSet),
              consecutiveOptionals: Math.max(nextConsec, taken.value.consecutiveOptionals),
            },
          }
        }
        if (!node.variable) {
          // Fixed repetition (`{k}` where k >= 2): mandatory non-variable body.
          const out = flow(node.body, state)
          if (!out.ok) return out
          return { ok: true, value: { activeSet: out.value.activeSet, consecutiveOptionals: 0 } }
        }
        // Variable repetition (`+`, `*`, `{m,}`, `{0,n}`, `{m,n}` with m < n and n > 1):
        const bodySummary = summaries.get(node.body)!
        if (state.activeSet && setsOverlap(state.activeSet, bodySummary.firstChars)) {
          return { ok: false, reason: 'Overlapping quantified chain risks polynomial backtracking (ReDoS).' }
        }
        // If `min === 0` (`*` or `{0,n}`), the 0-match path preserves `state.activeSet` transparently
        // while the >=1-match path activates `bodySummary.charUnion`.
        const nextActive = node.min === 0
          ? unionNullableSets(state.activeSet, bodySummary.charUnion)
          : cloneSet(bodySummary.charUnion)
        return { ok: true, value: { activeSet: nextActive, consecutiveOptionals: 0 } }
      }
    }
  }

  const finalFlow = flow(root, { activeSet: null, consecutiveOptionals: 0 })
  if (!finalFlow.ok) return finalFlow
  return { ok: true, value: undefined }
}

/**
 * Compile a worker/model-supplied claim regex with a fast static ReDoS validator.
 * Rejects disallowed flags (`i`, `u`, etc.), overly long patterns, control chars, backreferences,
 * lookarounds, inline modifier groups, empty/match-any classes (`[]`/`[^]`), stacked or nested
 * quantifiers, optional/variable/nullable atoms inside repeated groups, ambiguous quantified
 * alternations, overlapping quantified chains (including across group boundaries and optional
 * bridging atoms), and excessive alternations/nesting before `new RegExp` or `.exec()` can touch
 * the host event loop.
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

  const parsed = parseRegexAst(pattern)
  if (!parsed.ok) return parsed

  const safety = analyzeAstSafety(parsed.value)
  if (!safety.ok) return safety

  try {
    return { ok: true, regex: new RegExp(pattern, flagCheck.flags) }
  } catch {
    return { ok: false, reason: 'Invalid regular expression syntax.' }
  }
}

/**
 * Single chokepoint for executing untrusted/worker/model-supplied regex patterns.
 * Rejects backreferences, lookarounds, overly long patterns, non-linear flags, and ReDoS
 * constructs via `compileSafeClaimRegex`, then caps the haystack length before matching.
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
