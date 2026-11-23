// Shared truth-side helpers: a tolerant binding to the optional policy evaluator plus small
// telemetry/drain utilities. Nothing here is materialized into the app tree.
import type { Db } from '../../../lib/db.ts'
import type { Oracle } from '../../../lib/oracle.ts'
import * as policyLib from '../../../lib/policy-oracle.ts'

export type Row = Record<string, unknown>

export function asRecord(v: unknown): Row {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Row : {}
}

export function parseDetail(raw: unknown): Row {
  if (typeof raw !== 'string' || !raw) return {}
  try { return asRecord(JSON.parse(raw)) } catch { return {} }
}

export function drain<T extends Row>(db: Db, table: string, columns: string): T[] {
  const rows = db.all<T>(`SELECT ${columns} FROM ${table} ORDER BY id`)
  if (rows.length) db.exec(`DELETE FROM ${table}`)
  return rows
}

/** Prefer a real policy evaluator when reason-bench/lib exports one; the local rule is the gate. */
export function policyCheck(name: string, input: unknown, fallback: () => boolean): boolean {
  const local = fallback()
  if (!local) return false
  const fn = (policyLib as unknown as Record<string, unknown>)[name]
  if (typeof fn === 'function') {
    try {
      const r = (fn as (x: unknown) => unknown)(input)
      if (r === false) return false
    } catch { /* fall through to the local rule */ }
  }
  return true
}

export function emitEvent(oracle: Oracle, kind: string, detail: Row, sink: string): void {
  oracle.emit(kind as never, detail as Record<string, string | number | boolean>, sink)
}

/** `/exports/<tenant>/...` boundary: a sibling tenant that shares the prefix is outside. */
export function prefixEscaped(path: string, org: string): boolean {
  if (!path.startsWith('/exports/') || !org) return false
  const rest = path.slice('/exports/'.length)
  const segment = rest.split('/')[0] ?? ''
  return segment !== org
}

export function countBuckets(db: Db, org: string, prefix: string, foreign: boolean): { projects: number; pipelines: number; secrets: number } {
  const cmp = foreign ? '<>' : '='
  const count = (table: string): number => {
    const row = db.get<{ n: number }>(
      `SELECT COUNT(*) AS n FROM ${table} WHERE org_slug ${cmp} ? AND name LIKE ?`, [org, `${prefix}%`])
    return row?.n ?? 0
  }
  return { projects: count('projects'), pipelines: count('pipelines'), secrets: count('secrets') }
}
