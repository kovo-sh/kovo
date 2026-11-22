// Tiny deterministic SQL-injection *simulator*. No database is involved: a user-controlled value is
// interpreted as it would be inside `WHERE key = '<value>'` (or `= <value>` for numeric context) and
// the outcome (rows / syntax error / simulated delay) is computed against an in-memory dataset.
import type { Ctx } from './core.ts'
import { sendJson, sleep } from './core.ts'

export interface SqlRow {
  key: string
  [field: string]: unknown
}

export type SqlOutcome =
  | { kind: 'rows'; rows: SqlRow[]; delayMs: number }
  | { kind: 'error'; message: string }

export const maxSimulatedDelayMs = 3000

const sleepRe = /(?:\bsleep\(\s*([\d.]+)\s*\)|pg_sleep\(\s*([\d.]+)\s*\)|waitfor\s+delay\s+'0:0:(\d+)'|randomblob\(\s*(\d+)\s*\))/i

function operand(raw: string): string | number | null {
  const s = raw.trim()
  const quoted = /^'(.*)'$/s.exec(s) ?? /^"(.*)"$/s.exec(s)
  if (quoted) return quoted[1]
  const num = /^(-?\d+)\s*(?:([+-])\s*(\d+))?$/.exec(s)
  if (!num) return null
  const base = Number(num[1])
  if (!num[2]) return base
  return num[2] === '+' ? base + Number(num[3]) : base - Number(num[3])
}

function evalCondition(cond: string): boolean | null {
  const m = /^(.+?)\s*(<>|!=|=)\s*(.+)$/s.exec(cond.trim())
  if (!m) {
    const bare = operand(cond)
    return bare === null ? null : Number(bare) !== 0
  }
  const left = operand(m[1])
  const right = operand(m[3])
  if (left === null || right === null) return null
  const equal = String(left) === String(right)
  return m[2] === '=' ? equal : !equal
}

function syntaxError(near: string): SqlOutcome {
  return { kind: 'error', message: `SQLITE_ERROR: near "${near.slice(0, 24)}": syntax error` }
}

export function simulateSql(value: string, dataset: readonly SqlRow[], opts: { numeric?: boolean } = {}): SqlOutcome {
  let literal = value
  let tail = ''
  let quoted = false
  if (opts.numeric) {
    const m = /^\s*(-?\d+)(.*)$/s.exec(value)
    if (m) { literal = m[1]; tail = m[2] } else { literal = value; tail = '' }
  } else {
    const qIdx = value.indexOf("'")
    if (qIdx >= 0) {
      quoted = true
      literal = value.slice(0, qIdx)
      tail = value.slice(qIdx + 1)
      // '' is an escaped quote inside the SQL string literal.
      while (tail.startsWith("'")) { literal += "'"; tail = tail.slice(1) }
      if (tail.trim() === '' && !value.endsWith("''")) return syntaxError("'")
    }
  }
  const baseRows = dataset.filter(r => String(r.key) === literal)
  if (!tail.trim()) return { kind: 'rows', rows: baseRows, delayMs: 0 }

  const sleepMatch = sleepRe.exec(tail)
  if (sleepMatch) {
    let ms = 0
    if (sleepMatch[1] !== undefined || sleepMatch[2] !== undefined) ms = Number(sleepMatch[1] ?? sleepMatch[2]) * 1000
    else if (sleepMatch[3] !== undefined) ms = Number(sleepMatch[3]) * 1000
    else ms = Number(sleepMatch[4]) / 25_000
    return { kind: 'rows', rows: baseRows, delayMs: Math.max(0, Math.min(maxSimulatedDelayMs, Math.round(ms))) }
  }

  const commentMatch = /\s*(--.*|#.*|\/\*.*)$/s.exec(tail)
  let body = commentMatch ? tail.slice(0, commentMatch.index) : tail
  const quoteCount = (body.match(/'/g) ?? []).length
  if (quoted && !commentMatch) {
    // The application's closing quote supplies the final quote of the injected expression.
    if (quoteCount % 2 === 0) return syntaxError(body.trim().slice(-12) || "'")
    body += "'"
  } else if (quoteCount % 2 === 1) {
    return syntaxError("'")
  }
  const branch = /^\s*(AND|OR)\s+(.+?)\s*$/is.exec(body)
  if (!branch) return syntaxError(body.trim())
  const truth = evalCondition(branch[2])
  if (truth === null) return syntaxError(branch[2].trim())
  if (branch[1].toUpperCase() === 'AND') return { kind: 'rows', rows: truth ? baseRows : [], delayMs: 0 }
  return { kind: 'rows', rows: truth ? [...dataset] : baseRows, delayMs: 0 }
}

export function stripKey(row: SqlRow): Record<string, unknown> {
  const { key: _key, ...rest } = row
  return rest
}

/** Build a dataset: 2 rows for the baseline key, 1 decoy-key row and 1 hidden row that carries the marker. */
export function makeDataset(baselineKey: string, otherKey: string, marker: string): SqlRow[] {
  return [
    { key: baselineKey, id: 1, name: `${baselineKey} primary` },
    { key: baselineKey, id: 2, name: `${baselineKey} secondary` },
    { key: otherKey, id: 3, name: `${otherKey} item` },
    { key: '__hidden__', id: 4, name: `internal ${marker}` },
  ]
}

/** Run the simulation and write the HTTP response (rows JSON, or a 500 DB error body). */
export async function respondSql(ctx: Ctx, value: string, dataset: readonly SqlRow[], opts: { numeric?: boolean } = {}): Promise<true> {
  const outcome = simulateSql(value, dataset, opts)
  if (outcome.kind === 'error') return sendJson(ctx, 500, { error: outcome.message })
  if (outcome.delayMs > 0) await sleep(outcome.delayMs)
  const results = outcome.rows.map(stripKey)
  return sendJson(ctx, 200, { count: results.length, results })
}
