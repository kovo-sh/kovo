/**
 * Single authoritative registry of every SQLite column that cites evidence or artifact IDs.
 *
 * Shared by:
 *  - `artifact-ttl.ts` (fail-closed TTL evidence protection — zero silent catches, covers all
 *    evidence/artifact citation tables including `sast_runs`, `messages`, and `lab_telemetry`)
 *  - `store-session.ts` (`collectRunCleanupFiles` & `filterUnreferencedFlatArtifacts`)
 *  - `store.ts` (`Store.verifySchema()` schema-walk drift check)
 *
 * Pure leaf module: zero imports from `store*.ts` or repositories.
 */
import type { DatabaseSync } from 'node:sqlite'

export type EvidenceCitationEncoding = 'scalar_id' | 'json_id_array' | 'json_nested'

export interface EvidenceCitingColumn {
  readonly table: string
  readonly column: string
  readonly encoding: EvidenceCitationEncoding
  /** Whether surviving rows citing an ID in this column protect it during TTL pruning. */
  readonly protectInTtl: boolean
  /** Whether this column holds a direct scalar artifact/evidence ID owned/referenced for disk GC. */
  readonly directArtifactColumn: boolean
  /** True for `broker_exchanges.body_artifact_id`, which TTL protects iff its exchange row is protected. */
  readonly scopedToProtectedExchanges?: boolean
}

/**
 * Exhaustive list of every column across `src/server/schema.ts` that references evidence or
 * artifact IDs. Adding a new `*_artifact_id` / `*evidence_ids*` / `*proof_receipt*` column to
 * `schema.ts` without registering it here fails `validateCitingColumnsAgainstTables()`.
 */
export const CITING_COLUMNS: readonly EvidenceCitingColumn[] = Object.freeze([
  {
    table: 'evidence',
    column: 'id',
    encoding: 'scalar_id',
    protectInTtl: false,
    directArtifactColumn: true,
  },
  {
    table: 'broker_exchanges',
    column: 'body_artifact_id',
    encoding: 'scalar_id',
    protectInTtl: true,
    directArtifactColumn: true,
    scopedToProtectedExchanges: true,
  },
  {
    table: 'replay_specs',
    column: 'proof_artifact_id',
    encoding: 'scalar_id',
    protectInTtl: true,
    directArtifactColumn: true,
  },
  {
    table: 'replay_specs',
    column: 'proof_receipt',
    encoding: 'json_nested',
    protectInTtl: true,
    directArtifactColumn: false,
  },
  {
    table: 'sast_runs',
    column: 'raw_artifact_id',
    encoding: 'scalar_id',
    protectInTtl: true,
    directArtifactColumn: true,
  },
  {
    table: 'lab_telemetry',
    column: 'artifact_id',
    encoding: 'scalar_id',
    protectInTtl: true,
    directArtifactColumn: true,
  },
  {
    table: 'retest_runs',
    column: 'evidence_ids',
    encoding: 'json_id_array',
    protectInTtl: true,
    directArtifactColumn: false,
  },
  {
    table: 'facts',
    column: 'evidence_ids',
    encoding: 'json_id_array',
    protectInTtl: true,
    directArtifactColumn: false,
  },
  {
    table: 'facts',
    column: 'data',
    encoding: 'json_nested',
    protectInTtl: true,
    directArtifactColumn: false,
  },
  {
    table: 'messages',
    column: 'evidence_ids',
    encoding: 'json_id_array',
    protectInTtl: true,
    directArtifactColumn: false,
  },
  {
    table: 'findings',
    column: 'finding',
    encoding: 'json_nested',
    protectInTtl: true,
    directArtifactColumn: false,
  },
])

const NESTED_EVIDENCE_KEY_RE = /^(?:evidence_?ids?|artifact_?id|proof_?artifact_?id|raw_?artifact_?id)$/i
const SCHEMA_CITING_COLUMN_RE = /(?:^|_)(?:evidence_ids?|artifact_id|proof_receipt)$/i

function addNonEmptyStrings(out: Set<string>, values: readonly unknown[]): void {
  for (const item of values) {
    if (typeof item === 'string') {
      const trimmed = item.trim()
      if (trimmed.length > 0) out.add(trimmed)
    }
  }
}

function collectNestedEvidenceIds(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 10 || value == null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const item of value) collectNestedEvidenceIds(item, out, depth + 1)
    return
  }
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (entry == null) continue
    if (NESTED_EVIDENCE_KEY_RE.test(key)) {
      if (typeof entry === 'string' && entry.trim().length > 0) {
        out.add(entry.trim())
        continue
      }
      if (Array.isArray(entry)) {
        addNonEmptyStrings(out, entry)
        continue
      }
    }
    if (typeof entry === 'object') {
      collectNestedEvidenceIds(entry, out, depth + 1)
    }
  }
}

function parseJsonColumnFailClosed(
  raw: unknown,
  entry: EvidenceCitingColumn,
  runId: string,
): unknown {
  if (raw == null) return null
  if (typeof raw !== 'string') return raw
  const trimmed = raw.trim()
  if (!trimmed) {
    throw new Error(
      `Evidence protection aborted: empty JSON in ${entry.table}.${entry.column} for run ${runId}.`,
    )
  }
  try {
    return JSON.parse(trimmed) as unknown
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    throw new Error(
      `Evidence protection aborted: corrupt JSON in ${entry.table}.${entry.column} for run ${runId}: ${detail}`,
    )
  }
}

/**
 * Fail-closed collection of every evidence/artifact ID protected from TTL pruning for `runId`.
 * Any SQL error or corrupt JSON in any citing column throws immediately so the caller aborts
 * the prune rather than silently shrinking the protected set.
 */
export function collectProtectedEvidenceIdsForRun(
  client: DatabaseSync,
  runId: string,
  protectedExchangeIds: ReadonlySet<string>,
): Set<string> {
  const protectedIds = new Set<string>()
  for (const entry of CITING_COLUMNS) {
    if (!entry.protectInTtl) continue
    if (entry.scopedToProtectedExchanges) {
      if (protectedExchangeIds.size === 0) continue
      const rows = client.prepare(
        `SELECT id, ${entry.column} AS val FROM ${entry.table} WHERE run_id = ? AND ${entry.column} IS NOT NULL`,
      ).all(runId) as Array<{ id: string; val: unknown }>
      for (const row of rows) {
        if (protectedExchangeIds.has(row.id) && typeof row.val === 'string') {
          const trimmed = row.val.trim()
          if (trimmed.length > 0) protectedIds.add(trimmed)
        }
      }
      continue
    }

    const rows = client.prepare(
      `SELECT ${entry.column} AS val FROM ${entry.table} WHERE run_id = ? AND ${entry.column} IS NOT NULL`,
    ).all(runId) as Array<{ val: unknown }>

    for (const row of rows) {
      if (row.val == null) continue
      if (entry.encoding === 'scalar_id') {
        if (typeof row.val === 'string') {
          const trimmed = row.val.trim()
          if (trimmed.length > 0) protectedIds.add(trimmed)
        }
        continue
      }
      const parsed = parseJsonColumnFailClosed(row.val, entry, runId)
      if (parsed == null) continue
      if (entry.encoding === 'json_id_array') {
        if (!Array.isArray(parsed)) {
          throw new Error(
            `Evidence protection aborted: expected JSON array in ${entry.table}.${entry.column} for run ${runId}.`,
          )
        }
        addNonEmptyStrings(protectedIds, parsed)
      } else {
        collectNestedEvidenceIds(parsed, protectedIds)
      }
    }
  }
  return protectedIds
}

/**
 * Collect direct scalar artifact/evidence IDs owned by `runId` for run-deletion cleanup.
 * Uses the same `CITING_COLUMNS` registry as TTL protection.
 */
export function collectDirectArtifactIdsForRun(
  client: DatabaseSync,
  runId: string,
): Set<string> {
  const artifactIds = new Set<string>()
  for (const entry of CITING_COLUMNS) {
    if (!entry.directArtifactColumn) continue
    const rows = client.prepare(
      `SELECT ${entry.column} AS aid FROM ${entry.table} WHERE run_id = ? AND ${entry.column} IS NOT NULL`,
    ).all(runId) as Array<{ aid: string | null }>
    for (const row of rows) {
      if (typeof row.aid === 'string' && row.aid.length > 0) {
        artifactIds.add(row.aid)
      }
    }
  }
  return artifactIds
}

/**
 * Return legacy flat artifact/blob IDs no longer referenced by any surviving table across runs.
 * Uses the same `CITING_COLUMNS` registry as TTL protection and run-deletion collection.
 */
export function filterUnreferencedDirectArtifactIds(
  client: DatabaseSync,
  artifactIds: ReadonlySet<string>,
  tableExists: (table: string) => boolean,
): string[] {
  if (artifactIds.size === 0) return []
  const checkers = CITING_COLUMNS
    .filter(entry => entry.directArtifactColumn && tableExists(entry.table))
    .map(entry => client.prepare(`SELECT 1 FROM ${entry.table} WHERE ${entry.column} = ? LIMIT 1`))

  const unreferenced: string[] = []
  for (const aid of artifactIds) {
    let referenced = false
    for (const stmt of checkers) {
      if (stmt.get(aid)) {
        referenced = true
        break
      }
    }
    if (!referenced) unreferenced.push(aid)
  }
  return unreferenced
}

/**
 * Schema-walk invariant check: verifies that
 *  1. Every `(table, column)` registered in `CITING_COLUMNS` exists in `tables`, and
 *  2. Every evidence/artifact-citing column in `tables` is registered in `CITING_COLUMNS`.
 * Returns an array of drift violation descriptions (empty array means 100% in sync).
 */
export function validateCitingColumnsAgainstTables(
  tables: ReadonlyArray<{ name: string; columns: ReadonlyArray<{ name: string }> }>,
): string[] {
  const tableColumns = new Map<string, Set<string>>()
  for (const table of tables) {
    tableColumns.set(table.name, new Set(table.columns.map(c => c.name)))
  }
  const registered = new Set<string>()
  const violations: string[] = []

  for (const entry of CITING_COLUMNS) {
    const key = `${entry.table}.${entry.column}`
    if (registered.has(key)) {
      violations.push(`Duplicate CITING_COLUMNS entry: ${key}`)
      continue
    }
    registered.add(key)
    const cols = tableColumns.get(entry.table)
    if (!cols) {
      violations.push(`CITING_COLUMNS references unknown table: ${entry.table}`)
    } else if (!cols.has(entry.column)) {
      violations.push(`CITING_COLUMNS references unknown column: ${key}`)
    }
  }

  for (const table of tables) {
    for (const col of table.columns) {
      if (SCHEMA_CITING_COLUMN_RE.test(col.name)) {
        const key = `${table.name}.${col.name}`
        if (!registered.has(key)) {
          violations.push(`Unregistered evidence/artifact citing column in schema.ts: ${key}`)
        }
      }
    }
  }

  return violations
}
