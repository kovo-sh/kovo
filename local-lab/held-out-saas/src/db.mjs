// In-memory SQLite (node:sqlite) data layer. No disk access, no external services.
import { randomBytes } from 'node:crypto'
import { DatabaseSync } from 'node:sqlite'
import { marker } from './markers.mjs'

function blockingSleep(ms) {
  // Bounded synchronous delay used to model slow DB functions (lab only, hard cap 3.5s).
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(0, Math.min(ms, 3500)))
}

export function createDb() {
  const db = new DatabaseSync(':memory:')

  // Deterministic stand-ins for "heavy" SQL functions so time-based blind injection is reproducible:
  //  - SLEEP(n)                : MySQL-style delay
  //  - RANDOMBLOB(huge)        : the generic SQLite heavy-computation delay primitive (N / 25000 ms)
  db.function('sleep', { deterministic: false }, seconds => {
    blockingSleep(Number(seconds) * 1000)
    return 0
  })
  db.function('pg_sleep', { deterministic: false }, seconds => {
    blockingSleep(Number(seconds) * 1000)
    return 0
  })
  db.function('randomblob', { deterministic: false }, n => {
    const size = Math.floor(Number(n) || 0)
    if (size > 5_000_000) {
      blockingSleep(Math.round(size / 25_000))
      return Buffer.alloc(8)
    }
    return randomBytes(Math.max(1, Math.min(size, 1 << 20)))
  })

  db.exec(`
    CREATE TABLE members (id TEXT, tenant_id TEXT, name TEXT, email TEXT, note TEXT);
    CREATE TABLE sales_orders (ref TEXT, tenant_id TEXT, status TEXT, total REAL, memo TEXT);
    CREATE TABLE events (id INTEGER PRIMARY KEY, tenant_id TEXT, name TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT, name TEXT, price REAL, active INTEGER);
  `)

  const insertMember = db.prepare('INSERT INTO members VALUES (?, ?, ?, ?, ?)')
  insertMember.run('1', 'acme', 'Alice Anders', 'alice@acme.example', 'workspace owner')
  insertMember.run('2', 'acme', 'Ada Admin', 'ada@acme.example', 'billing admin')
  insertMember.run('3', 'acme', 'Vic Viewer', 'vic@acme.example', 'read only')
  insertMember.run('101', 'globex', 'Gus Globex', 'gus@globex.example', marker('hos-07'))

  const insertOrder = db.prepare('INSERT INTO sales_orders VALUES (?, ?, ?, ?, ?)')
  insertOrder.run('1', 'acme', 'shipped', 129.0, 'Rack kit')
  insertOrder.run('2', 'acme', 'pending', 49.5, 'Cable pack')
  insertOrder.run('3', 'acme', 'shipped', 980.0, 'Sensor array')
  insertOrder.run('9001', 'globex', 'shipped', 4200.0, marker('hos-06'))

  const insertEvent = db.prepare('INSERT INTO events (tenant_id, name) VALUES (?, ?)')
  insertEvent.run('acme', 'signup')
  insertEvent.run('acme', 'login')
  insertEvent.run('globex', `evt:${marker('hos-08')}`)

  const insertProduct = db.prepare('INSERT INTO products (sku, name, price, active) VALUES (?, ?, ?, ?)')
  insertProduct.run('1', 'Starter plan', 19.0, 1)
  insertProduct.run('2', 'Team plan', 99.0, 1)
  insertProduct.run('3', 'Enterprise plan', 499.0, 1)
  insertProduct.run('legacy-internal', marker('hos-09'), 0.0, 0)

  return db
}

/** Legacy ORM compat shim: rewrites Postgres-style `(SELECT 1 FROM pg_sleep(n)) IS NULL` into a scalar call. */
export function legacyCompat(sql) {
  return sql.replace(/\(\s*SELECT\s+1\s+FROM\s+pg_sleep\(([^)]*)\)\s*\)\s+IS\s+NULL/gi, 'pg_sleep($1) IS NULL')
}
