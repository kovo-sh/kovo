// Small adapter translating positional ? placeholders into the named-parameter form the database
// layer binds. Keeps feature code readable while using parameterised queries throughout.
import type { Db } from '../../../../lib/db.ts'

function toNamed(sql: string, params: readonly unknown[]): [string, Record<string, unknown>] {
  const obj: Record<string, unknown> = {}
  let i = 0
  const out = sql.replace(/\?/g, () => {
    const key = `p${i}`
    obj[key] = params[i]
    i += 1
    return `$${key}`
  })
  return [out, obj]
}

export function prun(db: Db, sql: string, params: readonly unknown[] = []): { changes: number; lastInsertRowid: number } {
  const [s, o] = toNamed(sql, params)
  return db.run(s, o)
}

export function pget<T = Record<string, unknown>>(db: Db, sql: string, params: readonly unknown[] = []): T | undefined {
  const [s, o] = toNamed(sql, params)
  return db.get<T>(s, o)
}

export function pall<T = Record<string, unknown>>(db: Db, sql: string, params: readonly unknown[] = []): T[] {
  const [s, o] = toNamed(sql, params)
  return db.all<T>(s, o)
}
