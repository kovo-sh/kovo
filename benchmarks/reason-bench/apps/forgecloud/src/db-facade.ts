// Thin database facade. Presents the same interface as the host handle but binds array parameters
// positionally (spreading them into the prepared statement) while delegating raw string queries
// unchanged so the structural query sink still observes them.
import type { Db } from '../../../lib/db.ts'

export function createDbFacade(db: Db): Db {
  const h = db.handle
  return {
    handle: h,
    exec: (sql) => db.exec(sql),
    run(sql, params) {
      const stmt = h.prepare(sql)
      const r = params === undefined ? stmt.run()
        : Array.isArray(params) ? stmt.run(...(params as never[])) : stmt.run(params as never)
      return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) }
    },
    get(sql, params) {
      const stmt = h.prepare(sql)
      return (params === undefined ? stmt.get()
        : Array.isArray(params) ? stmt.get(...(params as never[])) : stmt.get(params as never)) as never
    },
    all(sql, params) {
      const stmt = h.prepare(sql)
      return (params === undefined ? stmt.all()
        : Array.isArray(params) ? stmt.all(...(params as never[])) : stmt.all(params as never)) as never
    },
    rawRun: (sql) => db.rawRun(sql),
    rawGet: (sql) => db.rawGet(sql),
    rawAll: (sql) => db.rawAll(sql),
    close: () => db.close(),
  }
}
