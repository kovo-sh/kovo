// Minimal SQL tokenizer used only to decide whether a request-supplied value, when it appears inside
// a SQL string, stays within a single literal/identifier token or breaks out into SQL structure.
export type SqlTokenType = 'string' | 'ident' | 'number' | 'operator' | 'comment' | 'ws' | 'punct'

export interface SqlToken {
  type: SqlTokenType
  start: number
  end: number // exclusive
  value: string
}

const OPERATOR_CHARS = new Set('+-*/%<>=!|&^~'.split(''))
const PUNCT_CHARS = new Set('(),;.'.split(''))

export function tokenizeSql(sql: string): SqlToken[] {
  const tokens: SqlToken[] = []
  let i = 0
  const n = sql.length
  const push = (type: SqlTokenType, start: number, end: number) =>
    tokens.push({ type, start, end, value: sql.slice(start, end) })

  while (i < n) {
    const c = sql[i]!
    // whitespace
    if (/\s/.test(c)) {
      const s = i
      while (i < n && /\s/.test(sql[i]!)) i++
      push('ws', s, i)
      continue
    }
    // line comment
    if (c === '-' && sql[i + 1] === '-') {
      const s = i
      while (i < n && sql[i] !== '\n') i++
      push('comment', s, i)
      continue
    }
    // block comment
    if (c === '/' && sql[i + 1] === '*') {
      const s = i
      i += 2
      while (i < n && !(sql[i] === '*' && sql[i + 1] === '/')) i++
      i = Math.min(n, i + 2)
      push('comment', s, i)
      continue
    }
    // string literal ' ... '  ('' escape)
    if (c === "'") {
      const s = i
      i++
      while (i < n) {
        if (sql[i] === "'" && sql[i + 1] === "'") { i += 2; continue }
        if (sql[i] === "'") { i++; break }
        i++
      }
      push('string', s, i)
      continue
    }
    // quoted identifier " ... " or [ ... ] or ` ... `
    if (c === '"' || c === '`') {
      const s = i
      const q = c
      i++
      while (i < n && sql[i] !== q) i++
      i = Math.min(n, i + 1)
      push('ident', s, i)
      continue
    }
    if (c === '[') {
      const s = i
      while (i < n && sql[i] !== ']') i++
      i = Math.min(n, i + 1)
      push('ident', s, i)
      continue
    }
    // number
    if (/[0-9]/.test(c) || (c === '.' && /[0-9]/.test(sql[i + 1] ?? ''))) {
      const s = i
      while (i < n && /[0-9.eExXa-fA-F]/.test(sql[i]!)) i++
      push('number', s, i)
      continue
    }
    // identifier / keyword
    if (/[A-Za-z_@#$]/.test(c)) {
      const s = i
      while (i < n && /[A-Za-z0-9_@#$]/.test(sql[i]!)) i++
      push('ident', s, i)
      continue
    }
    // operators
    if (OPERATOR_CHARS.has(c)) {
      const s = i
      while (i < n && OPERATOR_CHARS.has(sql[i]!)) i++
      push('operator', s, i)
      continue
    }
    if (PUNCT_CHARS.has(c)) {
      push('punct', i, i + 1)
      i++
      continue
    }
    // anything else (e.g. ?) as punct
    push('punct', i, i + 1)
    i++
  }
  return tokens
}

/**
 * Does the substring [spanStart, spanEnd) fall entirely inside a single string literal,
 * a single number, or a single identifier token? If so, the injected value did not alter SQL
 * structure. Returns false when the span crosses token boundaries or includes operators / comments /
 * punctuation / keywords beyond one literal.
 */
export function spanIsContained(sql: string, spanStart: number, spanEnd: number): boolean {
  const tokens = tokenizeSql(sql)
  for (const t of tokens) {
    if (t.start <= spanStart && t.end >= spanEnd) {
      // fully inside one token: safe only if it's a literal or identifier (not operator/comment/punct)
      return t.type === 'string' || t.type === 'number' || t.type === 'ident'
    }
  }
  return false
}
