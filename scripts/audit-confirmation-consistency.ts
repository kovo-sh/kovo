/**
 * Confirmation-consistency audit (precision integrity).
 *
 * Reads persisted Guardian store(s) read-only and asserts the product invariant:
 *   every finding persisted `runtime_confirmed` / `confirmed` must have persisted evidence that
 *   satisfies its oracle — its linked replay spec's `last_verification_diff.verdict === 'confirmed'`,
 *   an OOB ProofReceipt (`finding.verification` starts with `ProofReceipt` / an
 *   `oob.receipt_confirmed` event), a baseline review, or a legacy floor confirmation with no
 *   contradicting spec verdict.
 *
 * Prints structured rows only (ids, classes, verdicts, statuses) — never bodies or probe strings.
 *
 * Usage:
 *   node scripts/audit-confirmation-consistency.ts --data-dir /tmp/heldout-.../data
 *   node scripts/audit-confirmation-consistency.ts /tmp/cell/data/app-seed1-grey-box
 * Exit code 1 when any confirmed finding is contradicted by its persisted evidence.
 */
import { DatabaseSync } from 'node:sqlite'
import { existsSync, readdirSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'

interface AuditRow {
  db: string
  findingId: string
  checkId: string
  title: string
  verificationClass: string | null
  status: string | null
  linkedSpecId: string | null
  specVerdict: string | null
  evidenceKind: 'spec' | 'receipt' | 'baseline' | 'floor_artifact' | 'none'
  ok: boolean
  conflictEvent: boolean
}

function dbsUnder(root: string): string[] {
  const out: string[] = []
  const visit = (dir: string, depth: number) => {
    if (depth > 6) return
    let entries: string[] = []
    try { entries = readdirSync(dir) } catch { return }
    for (const name of entries) {
      const path = join(dir, name)
      let isDir = false
      try { isDir = statSync(path).isDirectory() } catch { continue }
      if (isDir) { if (name !== 'node_modules') visit(path, depth + 1) }
      else if (name === 'guardian.sqlite') out.push(path)
    }
  }
  if (!existsSync(root)) return out
  try { if (statSync(root).isFile()) return root.endsWith('guardian.sqlite') ? [root] : [] } catch { return out }
  visit(root, 0)
  return out
}

function auditDb(dbPath: string): AuditRow[] {
  const db = new DatabaseSync(dbPath, { readOnly: true })
  const rows: AuditRow[] = []
  try {
    const findings = db.prepare(
      `select id, check_id, finding_kind, verification_class, verification_tier, replay_spec_id, provenance, finding from findings`,
    ).all() as Array<Record<string, unknown>>
    const specs = new Map<string, Record<string, unknown>>()
    for (const spec of db.prepare(`select id, last_verification_diff from replay_specs`).all() as Array<Record<string, unknown>>) {
      specs.set(String(spec.id), spec)
    }
    const receiptFindings = new Set<string>()
    for (const event of db.prepare(`select detail from events where kind = 'oob.receipt_confirmed'`).all() as Array<{ detail: string }>) {
      try { receiptFindings.add(String(JSON.parse(event.detail).findingId)) } catch { /* ignore */ }
    }
    const conflictFindings = new Set<string>()
    for (const event of db.prepare(`select detail from events where kind = 'finding.confirmation_conflict'`).all() as Array<{ detail: string }>) {
      try { conflictFindings.add(String(JSON.parse(event.detail).findingId)) } catch { /* ignore */ }
    }
    const floorConfirmed = new Set<string>()
    for (const event of db.prepare(`select detail from events where kind = 'deterministic_engine.confirmed'`).all() as Array<{ detail: string }>) {
      try { floorConfirmed.add(String(JSON.parse(event.detail).findingId)) } catch { /* ignore */ }
    }

    for (const row of findings) {
      if (row.verification_class !== 'runtime_confirmed') continue
      let finding: Record<string, unknown> = {}
      try { finding = JSON.parse(String(row.finding)) } catch { /* ignore */ }
      if (finding.status !== 'confirmed') continue
      const specId = row.replay_spec_id ? String(row.replay_spec_id) : null
      const spec = specId ? specs.get(specId) : undefined
      let verdict: string | null = null
      if (spec?.last_verification_diff) {
        try {
          const parsed = JSON.parse(String(spec.last_verification_diff)) as { verdict?: string }
          verdict = parsed.verdict ?? null
        } catch { /* ignore */ }
      }
      const baseline = row.finding_kind === 'baseline_check' || row.verification_tier === 'baseline_confirmed'
      const receipt = receiptFindings.has(String(row.id))
        || (typeof finding.verification === 'string' && finding.verification.startsWith('ProofReceipt'))
      let evidenceKind: AuditRow['evidenceKind'] = 'none'
      let ok = false
      if (baseline) { evidenceKind = 'baseline'; ok = true }
      else if (verdict === 'confirmed') { evidenceKind = 'spec'; ok = true }
      else if (receipt) { evidenceKind = 'receipt'; ok = true }
      else if (verdict === null && floorConfirmed.has(String(row.id))) { evidenceKind = 'floor_artifact'; ok = true }
      rows.push({
        db: dbPath,
        findingId: String(row.id),
        checkId: String(row.check_id),
        title: String(finding.title ?? '').slice(0, 100),
        verificationClass: row.verification_class ? String(row.verification_class) : null,
        status: finding.status ? String(finding.status) : null,
        linkedSpecId: specId,
        specVerdict: verdict,
        evidenceKind,
        ok,
        conflictEvent: conflictFindings.has(String(row.id)),
      })
    }
  } finally {
    db.close()
  }
  return rows
}

const args = process.argv.slice(2)
const roots = args[0] === '--data-dir' ? [args[1] ?? ''] : args
if (roots.length === 0 || roots.some(root => !root)) {
  console.error('usage: node scripts/audit-confirmation-consistency.ts [--data-dir] <dir-or-db> [...]')
  process.exit(2)
}

const dbs = roots.flatMap(root => dbsUnder(resolve(root)))
let confirmed = 0
let conflicts = 0
const rows: AuditRow[] = []
for (const dbPath of dbs) {
  for (const row of auditDb(dbPath)) {
    rows.push(row)
    confirmed += 1
    if (!row.ok) conflicts += 1
  }
}
for (const row of rows.filter(r => !r.ok)) {
  console.log(JSON.stringify({
    conflict: true,
    db: row.db,
    findingId: row.findingId,
    checkId: row.checkId,
    title: row.title,
    verificationClass: row.verificationClass,
    status: row.status,
    linkedSpecId: row.linkedSpecId,
    specVerdict: row.specVerdict,
    evidenceKind: row.evidenceKind,
    conflictEvent: row.conflictEvent,
  }))
}
const byKind = rows.reduce<Record<string, number>>((acc, row) => {
  acc[row.evidenceKind] = (acc[row.evidenceKind] ?? 0) + 1
  return acc
}, {})
console.log(JSON.stringify({ dbs: dbs.length, confirmed, conflicts, evidenceKinds: byKind }))
process.exit(conflicts === 0 ? 0 : 1)
