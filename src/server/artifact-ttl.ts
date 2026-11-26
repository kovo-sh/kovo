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
import { collectProtectedEvidenceIdsForRun } from './evidence-citations.ts'
import { isEligibleForArtifactTtlPurge, isTerminalRunStatus } from './run-status.ts'
import type { Store } from './store.ts'

export { isTerminalRunStatus }

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

function collectProtectedEvidenceIds(
  storage: Store,
  runId: string,
  protectedExchangeIds?: ReadonlySet<string>,
): Set<string> {
  const citedExchanges = protectedExchangeIds ?? storage.findingsRepo.listProtectedExchangeIdsForRun(runId)
  return collectProtectedEvidenceIdsForRun(storage.client, runId, citedExchanges)
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
    return isEligibleForArtifactTtlPurge(row.status)
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

  // Fail-closed pre-flight: resolve EVERY protected evidence set before deleting any row or file.
  // Any protection-query error or corrupt JSON aborts the entire prune cleanly with zero deletions.
  const protectedEvidenceByRun = new Map<string, Set<string>>()
  if (preserveEvidence && policy.artifactTtlMs !== undefined && policy.artifactTtlMs > 0) {
    for (const runId of candidateRunIds) {
      protectedEvidenceByRun.set(
        runId,
        collectProtectedEvidenceIds(storage, runId, getProtectedExchanges(runId)),
      )
    }
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
        ? (protectedEvidenceByRun.get(runId) ?? collectProtectedEvidenceIds(storage, runId, getProtectedExchanges(runId)))
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
