// Runtime audit triggers so monitors can judge database mutations against an authorization policy.
// Created at runtime (never present in the materialized app source), writing row-level diffs into an
// audit table that drainAudit() reads and clears per request.
import type { Db, AuditSpec, AuditRow } from './db.ts'

const AUDIT_TABLE = '__rb_audit'

export function installAuditTriggers(db: Db, specs: AuditSpec[]): void {
  db.exec(`CREATE TABLE IF NOT EXISTS ${AUDIT_TABLE} (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    tbl TEXT NOT NULL,
    op TEXT NOT NULL,
    rowid INTEGER,
    old_json TEXT,
    new_json TEXT
  );`)

  for (const spec of specs) {
    const cols = spec.columns
    const jsonObj = (prefix: 'OLD' | 'NEW') =>
      `json_object(${cols.map((c) => `'${c}', ${prefix}.${c}`).join(', ')})`
    const t = spec.table
    db.exec(`CREATE TRIGGER IF NOT EXISTS __rb_ai_${t} AFTER INSERT ON ${t} BEGIN
      INSERT INTO ${AUDIT_TABLE}(tbl, op, rowid, old_json, new_json)
      VALUES ('${t}', 'INSERT', NEW.rowid, NULL, ${jsonObj('NEW')});
    END;`)
    db.exec(`CREATE TRIGGER IF NOT EXISTS __rb_au_${t} AFTER UPDATE ON ${t} BEGIN
      INSERT INTO ${AUDIT_TABLE}(tbl, op, rowid, old_json, new_json)
      VALUES ('${t}', 'UPDATE', NEW.rowid, ${jsonObj('OLD')}, ${jsonObj('NEW')});
    END;`)
    db.exec(`CREATE TRIGGER IF NOT EXISTS __rb_ad_${t} AFTER DELETE ON ${t} BEGIN
      INSERT INTO ${AUDIT_TABLE}(tbl, op, rowid, old_json, new_json)
      VALUES ('${t}', 'DELETE', OLD.rowid, ${jsonObj('OLD')}, NULL);
    END;`)
  }
}

/** Return and clear audit rows accumulated since the last drain (i.e. during this request). */
export function drainAudit(db: Db): AuditRow[] {
  const rows = db.all<{ seq: number; tbl: string; op: string; rowid: number; old_json: string | null; new_json: string | null }>(
    `SELECT seq, tbl, op, rowid, old_json, new_json FROM ${AUDIT_TABLE} ORDER BY seq`,
  )
  if (rows.length) db.exec(`DELETE FROM ${AUDIT_TABLE}`)
  return rows.map((r) => ({
    seq: r.seq,
    table: r.tbl,
    op: r.op as AuditRow['op'],
    rowid: r.rowid,
    old: r.old_json ? JSON.parse(r.old_json) : null,
    neu: r.new_json ? JSON.parse(r.new_json) : null,
  }))
}

export function clearAudit(db: Db): void {
  db.exec(`DELETE FROM ${AUDIT_TABLE}`)
}
