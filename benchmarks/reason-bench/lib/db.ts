// SQLite wrapper over node:sqlite with a structural SQL-injection sink. Parameterized queries never
// trip the sink. A raw query trips it only when a request-supplied value, found verbatim in the SQL
// text, breaks out of a single literal/identifier token (quote break, comment, operator, keyword...).
import { DatabaseSync } from 'node:sqlite'
import type { Oracle } from './oracle.ts'
import { currentCtx } from './oracle.ts'
import { spanIsContained } from './sql-tokenize.ts'

export interface AuditSpec {
  table: string
  columns: string[]
}

export interface AuditRow {
  table: string
  op: 'INSERT' | 'UPDATE' | 'DELETE'
  rowid: number
  old: Record<string, unknown> | null
  neu: Record<string, unknown> | null
  seq: number
}

export interface Db {
  readonly handle: DatabaseSync
  exec(sql: string): void
  run(sql: string, params?: unknown[] | Record<string, unknown>): { changes: number; lastInsertRowid: number }
  get<T = Record<string, unknown>>(sql: string, params?: unknown[] | Record<string, unknown>): T | undefined
  all<T = Record<string, unknown>>(sql: string, params?: unknown[] | Record<string, unknown>): T[]
  // raw string SQL variants (apps that build SQL by concatenation use these; the sink watches them)
  rawRun(sql: string): { changes: number; lastInsertRowid: number }
  rawGet<T = Record<string, unknown>>(sql: string): T | undefined
  rawAll<T = Record<string, unknown>>(sql: string): T[]
  close(): void
}

// Allowlisted bare identifiers that apps legitimately concatenate (e.g. ORDER BY columns). A value
// equal to one of these never trips the sink even if concatenated.
const SAFE_IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,40}$/

function firstTable(sql: string): string {
  const m = sql.match(/\b(?:from|into|update|join)\s+["'`[]?([A-Za-z_][A-Za-z0-9_]*)/i)
  return m ? m[1]! : 'unknown'
}

export function createDb(oracle: Oracle, opts?: { safeIdents?: Set<string> }): Db {
  const handle = new DatabaseSync(':memory:')
  handle.exec('PRAGMA foreign_keys = ON;')
  const safe = opts?.safeIdents

  const checkRaw = (sql: string): void => {
    const ctx = currentCtx()
    if (!ctx || ctx.inputs.length === 0) return
    for (const raw of ctx.inputs) {
      if (raw.length < 2) continue
      if (SAFE_IDENT.test(raw) && (!safe || safe.has(raw))) {
        // a plain allowlisted identifier concatenated into e.g. ORDER BY — structurally benign
        if (safe && safe.has(raw)) continue
      }
      let from = 0
      for (;;) {
        const idx = sql.indexOf(raw, from)
        if (idx < 0) break
        if (!spanIsContained(sql, idx, idx + raw.length)) {
          oracle.emit(
            'sql_structure_change',
            { fragment: raw.slice(0, 80), table: firstTable(sql) },
            `db:${firstTable(sql)}`,
          )
          return
        }
        from = idx + raw.length
      }
    }
  }

  return {
    handle,
    exec: (sql) => handle.exec(sql),
    run(sql, params) {
      const stmt = handle.prepare(sql)
      const r = params === undefined ? stmt.run() : stmt.run(params as never)
      return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) }
    },
    get(sql, params) {
      const stmt = handle.prepare(sql)
      return (params === undefined ? stmt.get() : stmt.get(params as never)) as never
    },
    all(sql, params) {
      const stmt = handle.prepare(sql)
      return (params === undefined ? stmt.all() : stmt.all(params as never)) as never
    },
    rawRun(sql) {
      checkRaw(sql)
      const r = handle.prepare(sql).run()
      return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) }
    },
    rawGet(sql) {
      checkRaw(sql)
      return handle.prepare(sql).get() as never
    },
    rawAll(sql) {
      checkRaw(sql)
      return handle.prepare(sql).all() as never
    },
    close: () => handle.close(),
  }
}
