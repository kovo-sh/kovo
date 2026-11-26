/**
 * v7 M4 Production Operations — Deterministic Artifact TTL Purge.
 *
 * Purges expired broker exchanges (+ FTS rows + unreferenced blobs), aged evidence
 * artifact rows and their on-disk files (supporting both sharded and legacy flat
 * layouts), and expired temporary files under `<dataDir>/tmp` (never following
 * symlinks). Every purge appends a structured entry to the tenant audit log.
 */
import { createHash } from 'node:crypto'
import { lstatSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import type { Store } from './store.ts'

export interface ArtifactTtlPolicy {
  /** Delete broker exchanges older than this many ms (<= 0 disables exchange purge). */
  exchangeTtlMs?: number
  /** Delete evidence rows and artifact files older than this many ms (<= 0 disables). */
  artifactTtlMs?: number
  /** Delete temp files under `<dataDir>/tmp` (and `tempDirs`) older than this many ms (<= 0 disables). */
  tempFileTtlMs?: number
  /** Always preserve the newest N exchanges per run. Default 0. */
  keepLatestExchanges?: number
  /**
   * When true (default), preserve EVERY exchange (row, FTS entry, blob) and evidence artifact
   * referenced by findings, replay specs / proof receipts, retest runs, facts, or surfaced canaries.
   * Pass `false` explicitly only for hard-wipe / ZDR sweeps.
   */
  preserveConfirmedEvidence?: boolean
  /** Scope purge to a single run. */
  runId?: string
  /** Scope purge to a single tenant (projects/runs belonging to this tenant). */
  tenantId?: string
  /**
   * Skip all non-terminal runs (only prune strictly terminal runs: `complete`, `stopped`, `failed`)
   * and any run listed in `activeRunIds`. Default true.
   */
  skipActiveRuns?: boolean
  /** Optional set of in-memory active run IDs (e.g. from `AppRuntime`) that must be skipped. */
  activeRunIds?: ReadonlySet<string>
  /** Extra temporary directories to scan in addition to `<dataDir>/tmp`. */
  tempDirs?: string[]
  /** Actor recorded in the append-only tenant audit log. Default `'system'`. */
  actor?: string
  /** Injectable clock for deterministic tests. */
  now?: number
}

/**
 * Strictly terminal run statuses eligible for TTL retention pruning (R3-H-16).
 * Matches `RunStatus` terminal values in `src/domain.ts` (`'complete' | 'stopped' | 'failed'`)
 * plus legacy spelling aliases (`'completed'`, `'cancelled'`, `'canceled'`).
 * Non-terminal runs (`'running'`, `'waiting'`, `'paused'`, `'budget_paused'`, `'queued'`, etc.)
 * are NEVER eligible when `skipActiveRuns` is enabled (the default).
 */
const TERMINAL_RUN_STATUSES: ReadonlySet<string> = new Set([
  'complete',
  'completed',
  'stopped',
  'failed',
  'cancelled',
  'canceled',
])

export function isTerminalRunStatus(status: string | null | undefined): boolean {
  if (typeof status !== 'string') return false
  return TERMINAL_RUN_STATUSES.has(status.trim().toLowerCase())
}

export interface ArtifactTtlPurgeResult {
  purgedAt: string
  runsScanned: number
  exchangesDeleted: number
  ftsRowsDeleted: number
  blobsDeleted: number
  blobBytesFreed: number
  artifactsDeleted: number
  artifactFilesDeleted: number
  artifactBytesFreed: number
  tempFilesDeleted: number
  tempBytesFreed: number
  symlinksSkipped: number
}

export const DEFAULT_ZDR_TTL_POLICY: Required<
  Pick<ArtifactTtlPolicy, 'exchangeTtlMs' | 'artifactTtlMs' | 'tempFileTtlMs' | 'keepLatestExchanges' | 'preserveConfirmedEvidence' | 'skipActiveRuns'>
> = {
  exchangeTtlMs: 60 * 60_000,
  artifactTtlMs: 60 * 60_000,
  tempFileTtlMs: 15 * 60_000,
  keepLatestExchanges: 0,
  preserveConfirmedEvidence: false,
  skipActiveRuns: true,
}

function artifactBucket(id: string): string {
  return createHash('sha256').update(id).digest('hex').slice(0, 2)
}

function safeUnlinkRegularFile(path: string): { deleted: boolean; bytes: number; skippedSymlink: boolean } {
  try {
    const info = lstatSync(path)
    if (info.isSymbolicLink()) return { deleted: false, bytes: 0, skippedSymlink: true }
    if (!info.isFile()) return { deleted: false, bytes: 0, skippedSymlink: false }
    unlinkSync(path)
    return { deleted: true, bytes: info.size, skippedSymlink: false }
  } catch {
    return { deleted: false, bytes: 0, skippedSymlink: false }
  }
}

function candidateArtifactPaths(directory: string, runId: string, evidenceId: string): string[] {
  const bucket = artifactBucket(evidenceId)
  return [
    join(directory, 'artifacts', runId, bucket, `${evidenceId}.txt`),
    join(directory, 'artifacts', runId, `${evidenceId}.txt`),
    join(directory, 'artifacts', `${evidenceId}.txt`),
  ]
}

function addNonEmptyStrings(out: Set<string>, values: unknown): void {
  if (!Array.isArray(values)) return
  for (const item of values) {
    if (typeof item === 'string') {
      const trimmed = item.trim()
      if (trimmed.length > 0) out.add(trimmed)
    }
  }
}

const EVIDENCE_ID_KEY_RE = /^(?:evidence_?ids?|artifact_?id|proof_?artifact_?id)$/i

function collectEvidenceIdsFromJson(value: unknown, out: Set<string>, depth = 0): void {
  if (depth > 10 || value == null || typeof value !== 'object') return
  if (Array.isArray(value)) {
    for (const item of value) collectEvidenceIdsFromJson(item, out, depth + 1)
    return
  }
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (entry == null) continue
    if (EVIDENCE_ID_KEY_RE.test(key)) {
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
      collectEvidenceIdsFromJson(entry, out, depth + 1)
    }
  }
}

function parseJsonAndCollectEvidenceIds(raw: unknown, out: Set<string>, topLevelArray = false): void {
  if (raw == null) return
  let parsed: unknown = raw
  if (typeof raw === 'string') {
    const trimmed = raw.trim()
    if (!trimmed) return
    try {
      parsed = JSON.parse(trimmed)
    } catch {
      return
    }
  }
  if (topLevelArray && Array.isArray(parsed)) {
    addNonEmptyStrings(out, parsed)
    return
  }
  collectEvidenceIdsFromJson(parsed, out)
}

function collectProtectedEvidenceIds(
  storage: Store,
  runId: string,
  protectedExchangeIds?: ReadonlySet<string>,
): Set<string> {
  const protectedIds = new Set<string>()

  // 1. Findings (confirmed, static_verified, or any finding row citing evidenceIds).
  try {
    const findingRows = storage.client.prepare(
      'SELECT finding FROM findings WHERE run_id = ?',
    ).all(runId) as Array<{ finding: string | null }>
    for (const row of findingRows) {
      parseJsonAndCollectEvidenceIds(row.finding, protectedIds)
    }
  } catch {
    // Table unavailable on minimal schema.
  }

  // 2. Replay specs (proof_artifact_id + nested artifact/evidence refs inside proof_receipt).
  try {
    const specRows = storage.client.prepare(
      'SELECT proof_artifact_id, proof_receipt FROM replay_specs WHERE run_id = ?',
    ).all(runId) as Array<{ proof_artifact_id: string | null; proof_receipt: string | null }>
    for (const row of specRows) {
      if (typeof row.proof_artifact_id === 'string' && row.proof_artifact_id.trim().length > 0) {
        protectedIds.add(row.proof_artifact_id.trim())
      }
      parseJsonAndCollectEvidenceIds(row.proof_receipt, protectedIds)
    }
  } catch {
    // Fallback for legacy schemas without proof_receipt column.
    try {
      const specRows = storage.client.prepare(
        'SELECT proof_artifact_id FROM replay_specs WHERE run_id = ? AND proof_artifact_id IS NOT NULL',
      ).all(runId) as Array<{ proof_artifact_id: string }>
      for (const row of specRows) {
        if (row.proof_artifact_id) protectedIds.add(row.proof_artifact_id)
      }
    } catch {
      // Legacy schemas without proof_artifact_id.
    }
  }

  // 3. Retest runs (cited evidence_ids, e.g. composite_patch_retest structured artifacts).
  try {
    const retestRows = storage.client.prepare(
      'SELECT evidence_ids FROM retest_runs WHERE run_id = ?',
    ).all(runId) as Array<{ evidence_ids: string | null }>
    for (const row of retestRows) {
      parseJsonAndCollectEvidenceIds(row.evidence_ids, protectedIds, true)
    }
  } catch {
    // Table unavailable on minimal schema.
  }

  // 4. Facts (evidence_ids column + nested evidence/artifact refs in data JSON).
  try {
    const factRows = storage.client.prepare(
      'SELECT evidence_ids, data FROM facts WHERE run_id = ?',
    ).all(runId) as Array<{ evidence_ids: string | null; data: string | null }>
    for (const row of factRows) {
      parseJsonAndCollectEvidenceIds(row.evidence_ids, protectedIds, true)
      parseJsonAndCollectEvidenceIds(row.data, protectedIds)
    }
  } catch {
    // Table unavailable on minimal schema.
  }

  // 5. Blobs backing any protected broker exchange in this run.
  const citedExchanges = protectedExchangeIds ?? storage.findingsRepo.listProtectedExchangeIdsForRun(runId)
  if (citedExchanges.size > 0) {
    try {
      const exRows = storage.client.prepare(
        'SELECT id, body_artifact_id FROM broker_exchanges WHERE run_id = ? AND body_artifact_id IS NOT NULL',
      ).all(runId) as Array<{ id: string; body_artifact_id: string | null }>
      for (const row of exRows) {
        if (citedExchanges.has(row.id) && row.body_artifact_id) {
          protectedIds.add(row.body_artifact_id)
        }
      }
    } catch {
      // Table unavailable on minimal schema.
    }
  }

  return protectedIds
}

function purgeTempDirectory(
  root: string,
  cutoffMs: number,
): { filesDeleted: number; bytesFreed: number; symlinksSkipped: number } {
  let filesDeleted = 0
  let bytesFreed = 0
  let symlinksSkipped = 0
  const maxEntries = 25_000
  let seen = 0

  const walk = (dir: string, isRoot: boolean): boolean => {
    let entries
    try {
      const dirStat = lstatSync(dir)
      if (dirStat.isSymbolicLink()) {
        symlinksSkipped += 1
        return false
      }
      if (!dirStat.isDirectory()) return false
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return false
    }
    let remaining = 0
    for (const entry of entries) {
      seen += 1
      if (seen > maxEntries) {
        remaining += 1
        continue
      }
      const full = join(dir, entry.name)
      let info
      try {
        info = lstatSync(full)
      } catch {
        continue
      }
      if (info.isSymbolicLink()) {
        symlinksSkipped += 1
        remaining += 1
        continue
      }
      if (info.isDirectory()) {
        const emptied = walk(full, false)
        if (!emptied) remaining += 1
      } else if (info.isFile()) {
        if (info.mtimeMs <= cutoffMs) {
          try {
            unlinkSync(full)
            filesDeleted += 1
            bytesFreed += info.size
          } catch {
            remaining += 1
          }
        } else {
          remaining += 1
        }
      } else {
        remaining += 1
      }
    }
    if (!isRoot && remaining === 0) {
      try {
        rmdirSync(dir)
        return true
      } catch {
        return false
      }
    }
    return false
  }

  walk(root, true)
  return { filesDeleted, bytesFreed, symlinksSkipped }
}

/**
 * Deterministically purge expired exchanges, evidence artifacts (DB rows + disk files),
 * and temporary files according to `policy`, recording an append-only audit entry.
 */
export function purgeExpiredArtifacts(
  storage: Store,
  policy: ArtifactTtlPolicy,
): ArtifactTtlPurgeResult {
  storage.flushNow()
  const now = policy.now ?? Date.now()
  const skipNonTerminal = policy.skipActiveRuns ?? true
  const preserveEvidence = policy.preserveConfirmedEvidence ?? true
  const keepLatest = Math.max(0, Math.trunc(policy.keepLatestExchanges ?? 0))

  const result: ArtifactTtlPurgeResult = {
    purgedAt: new Date(now).toISOString(),
    runsScanned: 0,
    exchangesDeleted: 0,
    ftsRowsDeleted: 0,
    blobsDeleted: 0,
    blobBytesFreed: 0,
    artifactsDeleted: 0,
    artifactFilesDeleted: 0,
    artifactBytesFreed: 0,
    tempFilesDeleted: 0,
    tempBytesFreed: 0,
    symlinksSkipped: 0,
  }

  const isRunEligible = (row: { id: string; status: string }): boolean => {
    if (!skipNonTerminal) return true
    if (policy.activeRunIds?.has(row.id)) return false
    return isTerminalRunStatus(row.status)
  }

  // 1. Resolve candidate runs respecting optional runId, tenantId, and strict terminal-run safety.
  let candidateRunIds: string[] = []
  if (policy.runId) {
    if (policy.tenantId !== undefined) {
      storage.assertRunTenantAccess(policy.runId, policy.tenantId, policy.actor ?? 'system')
    }
    const row = storage.client.prepare('SELECT id, status FROM runs WHERE id = ?').get(policy.runId) as
      | { id: string; status: string }
      | undefined
    if (row && isRunEligible(row)) {
      candidateRunIds = [row.id]
    }
  } else if (policy.tenantId !== undefined) {
    const runs = storage.listRunsForTenant(policy.tenantId)
    candidateRunIds = runs
      .filter(r => isRunEligible(r))
      .map(r => r.id)
  } else {
    const rows = storage.client.prepare('SELECT id, status FROM runs').all() as Array<{ id: string; status: string }>
    candidateRunIds = rows
      .filter(r => isRunEligible(r))
      .map(r => r.id)
  }

  result.runsScanned = candidateRunIds.length

  const protectedExchangesByRun = new Map<string, Set<string>>()
  const getProtectedExchanges = (runId: string): Set<string> => {
    let existing = protectedExchangesByRun.get(runId)
    if (!existing) {
      existing = storage.findingsRepo.listProtectedExchangeIdsForRun(runId)
      protectedExchangesByRun.set(runId, existing)
    }
    return existing
  }

  // 2. Purge expired broker exchanges (+ FTS + unreferenced blobs), protecting every cited exchange.
  if (policy.exchangeTtlMs !== undefined && policy.exchangeTtlMs > 0) {
    for (const runId of candidateRunIds) {
      const protectedExchangeIds = preserveEvidence ? getProtectedExchanges(runId) : undefined
      const pruned = storage.pruneExchanges({
        runId,
        olderThanMs: policy.exchangeTtlMs,
        keepLatest,
        now,
        emitEvent: false,
        preserveProtectedExchanges: preserveEvidence,
        preserveConfirmedEvidence: preserveEvidence,
        ...(protectedExchangeIds ? { protectedExchangeIds } : {}),
      })
      result.exchangesDeleted += pruned.exchanges
      result.ftsRowsDeleted += pruned.ftsRows
      result.blobsDeleted += pruned.blobs
      result.blobBytesFreed += pruned.blobBytes
    }
  }

  // 3. Purge expired evidence artifact rows and schedule on-disk unlinks strictly post-COMMIT.
  if (policy.artifactTtlMs !== undefined && policy.artifactTtlMs > 0) {
    const cutoff = now - policy.artifactTtlMs
    const selectAged = storage.client.prepare(
      'SELECT id FROM evidence WHERE run_id = ? AND created_at <= ?',
    )
    const deleteEvidence = storage.client.prepare('DELETE FROM evidence WHERE id = ?')

    for (const runId of candidateRunIds) {
      const protectedIds = preserveEvidence
        ? collectProtectedEvidenceIds(storage, runId, getProtectedExchanges(runId))
        : new Set<string>()
      const agedRows = selectAged.all(runId, cutoff) as Array<{ id: string }>
      const eligibleIds = agedRows.map(row => row.id).filter(id => !protectedIds.has(id))
      if (eligibleIds.length === 0) continue

      storage.transaction(() => {
        const deletedIds: string[] = []
        for (const evidenceId of eligibleIds) {
          const changes = deleteEvidence.run(evidenceId)
          const count = Number(changes.changes)
          if (count > 0) {
            result.artifactsDeleted += count
            deletedIds.push(evidenceId)
          }
        }
        if (deletedIds.length > 0) {
          storage.session.afterCommit(() => {
            for (const evidenceId of deletedIds) {
              for (const candidatePath of candidateArtifactPaths(storage.directory, runId, evidenceId)) {
                const unlink = safeUnlinkRegularFile(candidatePath)
                if (unlink.skippedSymlink) result.symlinksSkipped += 1
                if (unlink.deleted) {
                  result.artifactFilesDeleted += 1
                  result.artifactBytesFreed += unlink.bytes
                }
              }
              // Best-effort cleanup of empty shard bucket directory.
              try {
                rmdirSync(join(storage.directory, 'artifacts', runId, artifactBucket(evidenceId)))
              } catch {
                // Non-empty or absent.
              }
            }
          })
        }
      }, { behavior: 'immediate' })
    }
  }

  // 4. Purge expired temporary files (never following symlinks).
  if (policy.tempFileTtlMs !== undefined && policy.tempFileTtlMs > 0) {
    const tempCutoff = now - policy.tempFileTtlMs
    const dirs = new Set<string>([join(storage.directory, 'tmp'), ...(policy.tempDirs ?? [])])
    for (const dir of dirs) {
      const swept = purgeTempDirectory(dir, tempCutoff)
      result.tempFilesDeleted += swept.filesDeleted
      result.tempBytesFreed += swept.bytesFreed
      result.symlinksSkipped += swept.symlinksSkipped
    }
  }

  // 5. Append structured audit entry to the append-only tenant audit log.
  const auditTenant = policy.tenantId ?? (policy.runId ? storage.getRunTenant(policy.runId) : 'default')
  storage.appendTenantAuditLog({
    tenantId: auditTenant,
    runId: policy.runId ?? null,
    actor: policy.actor ?? 'system',
    action: 'artifact.ttl_purge',
    resourceKind: 'artifacts',
    resourceId: policy.runId ?? null,
    outcome: 'purged',
    detail: {
      runsScanned: result.runsScanned,
      exchangesDeleted: result.exchangesDeleted,
      blobsDeleted: result.blobsDeleted,
      artifactsDeleted: result.artifactsDeleted,
      artifactFilesDeleted: result.artifactFilesDeleted,
      tempFilesDeleted: result.tempFilesDeleted,
      symlinksSkipped: result.symlinksSkipped,
    },
    now,
  })

  return result
}
