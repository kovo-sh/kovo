/**
 * Move S3 — `StorageMaintenanceController` (WAL Checkpointing, TTL/Operations Retention &
 * Safe Orphan Disk Sweeper).
 *
 * Owned by `AppRuntime` and started/stopped cleanly with `.unref()` timers:
 *  - Periodic non-blocking `PRAGMA wal_checkpoint(PASSIVE)` so WAL stays bounded during runs.
 *  - Idle-only (`activeRuns === 0`) `PRAGMA wal_checkpoint(TRUNCATE)` + `PRAGMA incremental_vacuum`.
 *  - Scheduled retention via `purgeExpiredArtifacts()` (exchanges, FTS, aged evidence, temp files).
 *  - Bounded `operations` table retention (default 7-day idempotency window).
 *  - DB-authoritative, symlink-safe orphan disk sweeper across `scratch/`, `artifacts/`, and
 *    `agent-sessions/` that never deletes active run dirs, live references, or in-flight files
 *    within the grace window.
 */
import { lstatSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { purgeExpiredArtifacts } from './artifact-ttl.ts'
import type { ArtifactTtlPolicy, ArtifactTtlPurgeResult } from './artifact-ttl.ts'
import { isSafePathSegment, tenantBlobSegment } from './store-session.ts'
import type { Store } from './store.ts'

export const DEFAULT_WAL_CHECKPOINT_INTERVAL_MS = 5 * 60_000
export const DEFAULT_MAINTENANCE_INTERVAL_MS = 30 * 60_000
export const DEFAULT_OPERATIONS_RETENTION_MS = 7 * 24 * 60 * 60_000
export const DEFAULT_ORPHAN_GRACE_MS = 30 * 60_000
export const DEFAULT_INCREMENTAL_VACUUM_PAGES = 200
export const DEFAULT_MAINTENANCE_TTL_POLICY: ArtifactTtlPolicy = {
  exchangeTtlMs: 14 * 24 * 60 * 60_000,
  artifactTtlMs: 14 * 24 * 60 * 60_000,
  tempFileTtlMs: 60 * 60_000,
  keepLatestExchanges: 0,
  preserveConfirmedEvidence: true,
  skipActiveRuns: true,
  actor: 'storage-maintenance',
}

export interface StorageMaintenanceOptions {
  store: Store
  /** Data directory root (defaults to `store.directory`). */
  dataDir?: string
  /** Callback returning active in-memory run IDs (e.g. `AppRuntime.activeRunIds()`). */
  getActiveRunIds?: () => readonly string[]
  /** Periodic WAL PASSIVE checkpoint interval in ms (`<= 0` disables timer). Default 5m. */
  walCheckpointIntervalMs?: number
  /** Periodic full maintenance sweep interval in ms (`<= 0` disables timer). Default 30m. */
  maintenanceIntervalMs?: number
  /** TTL policy passed to `purgeExpiredArtifacts`, or `false` to disable automatic TTL purge. */
  ttlPolicy?: ArtifactTtlPolicy | false
  /** Operations table idempotency retention window in ms (`<= 0` disables). Default 7d. */
  operationsRetentionMs?: number
  /** Grace window protecting recently created/in-flight files from orphan sweeping. Default 30m. */
  orphanGraceMs?: number
  /** Max freelist pages reclaimed per idle incremental vacuum (`<= 0` disables). Default 200. */
  incrementalVacuumPages?: number
  /** Optional extra scratch roots scanned in addition to `<dataDir>/scratch`. */
  scratchDirs?: readonly string[]
  /** Injectable clock for deterministic testing. */
  now?: () => number
  /** Optional structured error hook for background maintenance failures. */
  onError?: (stage: string, error: unknown) => void
}

export interface WalCheckpointReport {
  mode: 'passive' | 'truncate'
  busy: number
  log: number
  checkpointed: number
  activeRuns: number
  incrementalVacuumRan: boolean
  incrementalVacuumPages: number
}

export interface OperationsPruneReport {
  deleted: number
  cutoff: number
  retentionMs: number
}

export interface OrphanSweepReport {
  scratchFilesDeleted: number
  scratchDirsRemoved: number
  scratchBytesFreed: number
  artifactFilesDeleted: number
  artifactDirsRemoved: number
  artifactBytesFreed: number
  sessionFilesDeleted: number
  sessionDirsRemoved: number
  sessionBytesFreed: number
  symlinksSkipped: number
  skippedActiveRuns: number
}

export interface StorageMaintenanceReport {
  ranAt: string
  activeRuns: number
  checkpoint: WalCheckpointReport
  ttl: ArtifactTtlPurgeResult | null
  operations: OperationsPruneReport
  orphans: OrphanSweepReport
  errors: string[]
}

const MAX_WALK_ENTRIES = 50_000

function safeUnlinkFile(path: string): { deleted: boolean; bytes: number; skippedSymlink: boolean } {
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

function isProtectedByActiveRunName(name: string, activeRunIds: ReadonlySet<string>): boolean {
  if (activeRunIds.has(name)) return true
  for (const runId of activeRunIds) {
    if (runId.length >= 6 && name.includes(runId)) return true
  }
  return false
}

/**
 * Recursively sweep stale regular files (`mtimeMs <= cutoffMs`) and empty subdirectories inside
 * `root`, never following symlinks and skipping entries matching protected names.
 */
function sweepStaleTree(
  root: string,
  cutoffMs: number,
  options: {
    removeRootIfEmpty: boolean
    protectedNames?: ReadonlySet<string>
    activeRunIds?: ReadonlySet<string>
  },
): { filesDeleted: number; dirsRemoved: number; bytesFreed: number; symlinksSkipped: number; skippedActive: number } {
  let filesDeleted = 0
  let dirsRemoved = 0
  let bytesFreed = 0
  let symlinksSkipped = 0
  let skippedActive = 0
  let seen = 0

  const walk = (dir: string, isRoot: boolean): boolean => {
    let entries
    let initialDirMtimeMs = 0
    try {
      const stat = lstatSync(dir)
      if (stat.isSymbolicLink()) {
        symlinksSkipped += 1
        return false
      }
      if (!stat.isDirectory()) return false
      initialDirMtimeMs = stat.mtimeMs
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return false
    }

    let remaining = 0
    let removedAnyChild = false
    for (const entry of entries) {
      seen += 1
      if (seen > MAX_WALK_ENTRIES) {
        remaining += 1
        continue
      }
      if (options.protectedNames?.has(entry.name)) {
        remaining += 1
        continue
      }
      if (options.activeRunIds && isProtectedByActiveRunName(entry.name, options.activeRunIds)) {
        skippedActive += 1
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
        if (emptied) removedAnyChild = true
        else remaining += 1
      } else if (info.isFile()) {
        if (info.mtimeMs <= cutoffMs) {
          try {
            unlinkSync(full)
            filesDeleted += 1
            bytesFreed += info.size
            removedAnyChild = true
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

    const canRemove = isRoot ? options.removeRootIfEmpty : true
    // Note: unlinking a stale child updates the parent directory's mtime on POSIX, so check the
    // directory's pre-unlink mtime (or whether we just emptied it of stale children).
    if (canRemove && remaining === 0 && (removedAnyChild || initialDirMtimeMs <= cutoffMs)) {
      try {
        const dirStat = lstatSync(dir)
        if (!dirStat.isSymbolicLink()) {
          rmdirSync(dir)
          dirsRemoved += 1
          return true
        }
      } catch {
        return false
      }
    }
    return false
  }

  walk(root, true)
  return { filesDeleted, dirsRemoved, bytesFreed, symlinksSkipped, skippedActive }
}

function parseSessionIdFromFileName(name: string): string | null {
  for (const suffix of ['.sqlite-wal', '.sqlite-shm', '.sqlite']) {
    if (name.endsWith(suffix) && name.length > suffix.length) {
      return name.slice(0, -suffix.length)
    }
  }
  return null
}

function parseArtifactIdFromFileName(name: string): string | null {
  if (name.endsWith('.txt') && name.length > 4) {
    return name.slice(0, -4)
  }
  return null
}

export class StorageMaintenanceController {
  private readonly store: Store
  private readonly dataDir: string
  private readonly getActiveRunIdsFn?: () => readonly string[]
  private readonly walCheckpointIntervalMs: number
  private readonly maintenanceIntervalMs: number
  private readonly ttlPolicy: ArtifactTtlPolicy | false
  private readonly operationsRetentionMs: number
  private readonly orphanGraceMs: number
  private readonly incrementalVacuumPages: number
  private readonly scratchDirs: readonly string[]
  private readonly nowFn: () => number
  private readonly onError?: (stage: string, error: unknown) => void

  private walTimer: ReturnType<typeof setInterval> | null = null
  private maintenanceTimer: ReturnType<typeof setInterval> | null = null
  private stopped = false
  private inFlight = false
  private latestReport: StorageMaintenanceReport | null = null

  constructor(options: StorageMaintenanceOptions) {
    this.store = options.store
    this.dataDir = resolve(options.dataDir ?? options.store.directory)
    this.getActiveRunIdsFn = options.getActiveRunIds
    this.walCheckpointIntervalMs = options.walCheckpointIntervalMs ?? DEFAULT_WAL_CHECKPOINT_INTERVAL_MS
    this.maintenanceIntervalMs = options.maintenanceIntervalMs ?? DEFAULT_MAINTENANCE_INTERVAL_MS
    this.ttlPolicy = options.ttlPolicy === false
      ? false
      : { ...DEFAULT_MAINTENANCE_TTL_POLICY, ...(options.ttlPolicy ?? {}) }
    this.operationsRetentionMs = options.operationsRetentionMs ?? DEFAULT_OPERATIONS_RETENTION_MS
    this.orphanGraceMs = Math.max(0, options.orphanGraceMs ?? DEFAULT_ORPHAN_GRACE_MS)
    this.incrementalVacuumPages = Math.max(0, Math.trunc(options.incrementalVacuumPages ?? DEFAULT_INCREMENTAL_VACUUM_PAGES))
    this.scratchDirs = options.scratchDirs ?? []
    this.nowFn = options.now ?? (() => Date.now())
    this.onError = options.onError
  }

  /** Start periodic `.unref()` maintenance timers (idempotent). */
  start(): void {
    this.stopped = false
    if (!this.walTimer && this.walCheckpointIntervalMs > 0) {
      this.walTimer = setInterval(() => {
        if (this.stopped) return
        try {
          this.runCheckpoint({ allowTruncate: false })
        } catch (error) {
          this.onError?.('wal_checkpoint', error)
        }
      }, this.walCheckpointIntervalMs)
      this.walTimer.unref()
    }
    if (!this.maintenanceTimer && this.maintenanceIntervalMs > 0) {
      this.maintenanceTimer = setInterval(() => {
        if (this.stopped) return
        try {
          this.runMaintenanceCycle()
        } catch (error) {
          this.onError?.('maintenance_cycle', error)
        }
      }, this.maintenanceIntervalMs)
      this.maintenanceTimer.unref()
    }
  }

  /** Stop all maintenance timers cleanly (idempotent). */
  stop(): void {
    this.stopped = true
    if (this.walTimer) {
      clearInterval(this.walTimer)
      this.walTimer = null
    }
    if (this.maintenanceTimer) {
      clearInterval(this.maintenanceTimer)
      this.maintenanceTimer = null
    }
  }

  isRunning(): boolean {
    return !this.stopped && (this.walTimer !== null || this.maintenanceTimer !== null)
  }

  lastReport(): StorageMaintenanceReport | null {
    return this.latestReport
  }

  /** Resolve active runs from both in-memory `AppRuntime` and SQLite `runs.status = 'running'`. */
  activeRunIds(): Set<string> {
    const active = new Set<string>()
    for (const id of this.getActiveRunIdsFn?.() ?? []) {
      if (id) active.add(id)
    }
    try {
      const rows = this.store.client.prepare(
        "SELECT id FROM runs WHERE status = 'running'",
      ).all() as Array<{ id: string }>
      for (const row of rows) {
        if (row.id) active.add(row.id)
      }
    } catch {
      // Store may already be closing or uninitialized.
    }
    return active
  }

  /**
   * Run a SQLite WAL checkpoint. Always uses non-blocking `PASSIVE` while runs are active;
   * runs `TRUNCATE` + `PRAGMA incremental_vacuum` strictly when `allowTruncate` is true and
   * `activeRuns === 0`.
   */
  runCheckpoint(options: { allowTruncate?: boolean } = {}): WalCheckpointReport {
    this.store.flushNow()
    const activeRuns = this.activeRunIds().size
    const useTruncate = Boolean(options.allowTruncate) && activeRuns === 0
    const mode: 'passive' | 'truncate' = useTruncate ? 'truncate' : 'passive'
    const pragma = useTruncate ? 'PRAGMA wal_checkpoint(TRUNCATE)' : 'PRAGMA wal_checkpoint(PASSIVE)'
    const row = this.store.client.prepare(pragma).get() as
      | { busy?: number; log?: number; checkpointed?: number }
      | undefined

    let incrementalVacuumRan = false
    if (useTruncate && this.incrementalVacuumPages > 0) {
      this.store.client.exec(`PRAGMA incremental_vacuum(${this.incrementalVacuumPages});`)
      incrementalVacuumRan = true
    }

    return {
      mode,
      busy: Number(row?.busy ?? 0),
      log: Number(row?.log ?? 0),
      checkpointed: Number(row?.checkpointed ?? 0),
      activeRuns,
      incrementalVacuumRan,
      incrementalVacuumPages: incrementalVacuumRan ? this.incrementalVacuumPages : 0,
    }
  }

  /** Enforce bounded retention on the idempotency `operations` table (default 7-day window). */
  pruneOperations(options: { retentionMs?: number; now?: number } = {}): OperationsPruneReport {
    const retentionMs = options.retentionMs ?? this.operationsRetentionMs
    const now = options.now ?? this.nowFn()
    const cutoff = now - Math.max(0, retentionMs)
    if (!(retentionMs > 0)) {
      return { deleted: 0, cutoff, retentionMs }
    }
    const cols = this.store.client.prepare('PRAGMA table_info(operations)').all() as Array<{ name: string }>
    if (!cols.some(col => col.name === 'created_at')) {
      return { deleted: 0, cutoff, retentionMs }
    }
    const deleted = this.store.transaction(() => {
      const info = this.store.client.prepare(
        'DELETE FROM operations WHERE created_at < ?',
      ).run(cutoff)
      return Number(info.changes ?? 0)
    }, { behavior: 'immediate' })
    return { deleted, cutoff, retentionMs }
  }

  /**
   * Sweep stale orphaned disk files across `scratch/`, `artifacts/`, and `agent-sessions/`.
   * Never follows symlinks, never touches active run dirs, never removes DB-referenced files,
   * and respects `graceMs` so in-flight writes cannot be raced.
   */
  sweepOrphans(options: { graceMs?: number; now?: number } = {}): OrphanSweepReport {
    this.store.flushNow()
    const now = options.now ?? this.nowFn()
    const graceMs = Math.max(0, options.graceMs ?? this.orphanGraceMs)
    const cutoffMs = now - graceMs
    const activeRuns = this.activeRunIds()

    const report: OrphanSweepReport = {
      scratchFilesDeleted: 0,
      scratchDirsRemoved: 0,
      scratchBytesFreed: 0,
      artifactFilesDeleted: 0,
      artifactDirsRemoved: 0,
      artifactBytesFreed: 0,
      sessionFilesDeleted: 0,
      sessionDirsRemoved: 0,
      sessionBytesFreed: 0,
      symlinksSkipped: 0,
      skippedActiveRuns: 0,
    }

    // Snapshot authoritative DB references before inspecting the filesystem.
    const liveRunIds = new Set<string>(
      (this.store.client.prepare('SELECT id FROM runs').all() as Array<{ id: string }>).map(r => r.id),
    )
    const liveTenantSegments = new Set<string>(['default'])
    try {
      for (const row of this.store.client.prepare('SELECT DISTINCT tenant_id AS t FROM projects').all() as Array<{ t: string }>) {
        if (row.t) liveTenantSegments.add(tenantBlobSegment(row.t))
      }
      for (const row of this.store.client.prepare('SELECT DISTINCT tenant_id AS t FROM runs').all() as Array<{ t: string }>) {
        if (row.t) liveTenantSegments.add(tenantBlobSegment(row.t))
      }
    } catch { /* legacy schema without tenant_id */ }

    const liveSessionIds = new Set<string>()
    for (const row of this.store.client.prepare('SELECT DISTINCT session_id AS sid FROM assignments').all() as Array<{ sid: string | null }>) {
      if (row.sid) liveSessionIds.add(row.sid)
    }
    try {
      for (const row of this.store.client.prepare('SELECT DISTINCT session_id AS sid FROM board_members').all() as Array<{ sid: string | null }>) {
        if (row.sid) liveSessionIds.add(row.sid)
      }
    } catch { /* legacy schema without board_members */ }

    const activeSessionIds = new Set<string>()
    if (activeRuns.size > 0) {
      const placeholders = [...activeRuns].map(() => '?').join(', ')
      for (const row of this.store.client.prepare(
        `SELECT DISTINCT session_id AS sid FROM assignments WHERE run_id IN (${placeholders})`,
      ).all(...activeRuns) as Array<{ sid: string | null }>) {
        if (row.sid) activeSessionIds.add(row.sid)
      }
    }

    const referencedArtifacts = new Set<string>()
    const referencedBlobs = new Set<string>()
    for (const row of this.store.client.prepare('SELECT id FROM evidence').all() as Array<{ id: string }>) {
      if (row.id) referencedArtifacts.add(row.id)
    }
    for (const row of this.store.client.prepare(
      'SELECT DISTINCT body_artifact_id AS aid FROM broker_exchanges WHERE body_artifact_id IS NOT NULL',
    ).all() as Array<{ aid: string }>) {
      if (row.aid) {
        referencedArtifacts.add(row.aid)
        referencedBlobs.add(row.aid)
      }
    }
    for (const [table, col] of [
      ['replay_specs', 'proof_artifact_id'],
      ['sast_runs', 'raw_artifact_id'],
      ['lab_telemetry', 'artifact_id'],
    ] as const) {
      try {
        for (const row of this.store.client.prepare(
          `SELECT DISTINCT ${col} AS aid FROM ${table} WHERE ${col} IS NOT NULL`,
        ).all() as Array<{ aid: string }>) {
          if (row.aid) referencedArtifacts.add(row.aid)
        }
      } catch { /* optional table/column */ }
    }

    // 1. Sweep stale orphaned files & dirs under <dataDir>/scratch (and any extra scratchDirs).
    const scratchRoots = new Set<string>([join(this.dataDir, 'scratch'), ...this.scratchDirs.map(dir => resolve(dir))])
    const scratchProtected = new Set<string>([...activeRuns, ...activeSessionIds])
    for (const root of scratchRoots) {
      const swept = sweepStaleTree(root, cutoffMs, {
        removeRootIfEmpty: false,
        protectedNames: scratchProtected,
        activeRunIds: activeRuns,
      })
      report.scratchFilesDeleted += swept.filesDeleted
      report.scratchDirsRemoved += swept.dirsRemoved
      report.scratchBytesFreed += swept.bytesFreed
      report.symlinksSkipped += swept.symlinksSkipped
      report.skippedActiveRuns += swept.skippedActive
    }

    // 2. Sweep stale unreferenced artifacts under <dataDir>/artifacts/.
    this.sweepArtifactsDir(
      join(this.dataDir, 'artifacts'),
      cutoffMs,
      { activeRuns, liveRunIds, liveTenantSegments, referencedArtifacts, referencedBlobs },
      report,
    )

    // 3. Sweep orphaned agent session DBs / run directories under <dataDir>/agent-sessions/.
    this.sweepAgentSessionsDir(
      join(this.dataDir, 'agent-sessions'),
      cutoffMs,
      { activeRuns, liveRunIds, liveSessionIds },
      report,
    )

    return report
  }

  private sweepArtifactsDir(
    artifactsRoot: string,
    cutoffMs: number,
    refs: {
      activeRuns: ReadonlySet<string>
      liveRunIds: ReadonlySet<string>
      liveTenantSegments: ReadonlySet<string>
      referencedArtifacts: ReadonlySet<string>
      referencedBlobs: ReadonlySet<string>
    },
    report: OrphanSweepReport,
  ): void {
    let entries
    try {
      const stat = lstatSync(artifactsRoot)
      if (stat.isSymbolicLink() || !stat.isDirectory()) return
      entries = readdirSync(artifactsRoot, { withFileTypes: true })
    } catch {
      return
    }

    let seen = 0
    for (const entry of entries) {
      seen += 1
      if (seen > MAX_WALK_ENTRIES) break
      if (!isSafePathSegment(entry.name)) continue
      const full = join(artifactsRoot, entry.name)
      let info
      try {
        info = lstatSync(full)
      } catch {
        continue
      }
      if (info.isSymbolicLink()) {
        report.symlinksSkipped += 1
        continue
      }
      if (info.isFile()) {
        const artifactId = parseArtifactIdFromFileName(entry.name)
        if (!artifactId) continue
        if (refs.referencedArtifacts.has(artifactId)) continue
        if (info.mtimeMs > cutoffMs) continue
        const res = safeUnlinkFile(full)
        if (res.skippedSymlink) report.symlinksSkipped += 1
        if (res.deleted) {
          report.artifactFilesDeleted += 1
          report.artifactBytesFreed += res.bytes
        }
        continue
      }
      if (!info.isDirectory()) continue

      if (refs.activeRuns.has(entry.name)) {
        report.skippedActiveRuns += 1
        continue
      }

      if (refs.liveRunIds.has(entry.name)) {
        // Live inactive run directory: remove only unreferenced stale artifact/blob files.
        this.sweepUnreferencedArtifactSubtree(full, cutoffMs, refs.referencedArtifacts, report, false)
        continue
      }

      if (refs.liveTenantSegments.has(entry.name)) {
        // Tenant blob partition (`artifacts/<tenant>/blobs/<bucket>/<blobId>.txt`): sweep only unreferenced stale blobs.
        const blobsDir = join(full, 'blobs')
        this.sweepUnreferencedArtifactSubtree(blobsDir, cutoffMs, refs.referencedBlobs, report, false)
        continue
      }

      // Orphaned run directory (no longer in `runs` and not active): sweep stale files & empty dirs.
      const swept = sweepStaleTree(full, cutoffMs, {
        removeRootIfEmpty: true,
        activeRunIds: refs.activeRuns,
      })
      report.artifactFilesDeleted += swept.filesDeleted
      report.artifactDirsRemoved += swept.dirsRemoved
      report.artifactBytesFreed += swept.bytesFreed
      report.symlinksSkipped += swept.symlinksSkipped
      report.skippedActiveRuns += swept.skippedActive
    }
  }

  private sweepUnreferencedArtifactSubtree(
    dir: string,
    cutoffMs: number,
    referencedIds: ReadonlySet<string>,
    report: OrphanSweepReport,
    removeRootIfEmpty: boolean,
  ): boolean {
    let entries
    let initialDirMtimeMs = 0
    try {
      const stat = lstatSync(dir)
      if (stat.isSymbolicLink()) {
        report.symlinksSkipped += 1
        return false
      }
      if (!stat.isDirectory()) return false
      initialDirMtimeMs = stat.mtimeMs
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return false
    }

    let remaining = 0
    let removedAnyChild = false
    for (const entry of entries) {
      const full = join(dir, entry.name)
      let info
      try {
        info = lstatSync(full)
      } catch {
        continue
      }
      if (info.isSymbolicLink()) {
        report.symlinksSkipped += 1
        remaining += 1
        continue
      }
      if (info.isDirectory()) {
        const emptied = this.sweepUnreferencedArtifactSubtree(full, cutoffMs, referencedIds, report, true)
        if (emptied) removedAnyChild = true
        else remaining += 1
      } else if (info.isFile()) {
        const artifactId = parseArtifactIdFromFileName(entry.name)
        if (artifactId && !referencedIds.has(artifactId) && info.mtimeMs <= cutoffMs) {
          const res = safeUnlinkFile(full)
          if (res.skippedSymlink) {
            report.symlinksSkipped += 1
            remaining += 1
          } else if (res.deleted) {
            report.artifactFilesDeleted += 1
            report.artifactBytesFreed += res.bytes
            removedAnyChild = true
          } else {
            remaining += 1
          }
        } else {
          remaining += 1
        }
      } else {
        remaining += 1
      }
    }

    if (removeRootIfEmpty && remaining === 0 && (removedAnyChild || initialDirMtimeMs <= cutoffMs)) {
      try {
        const stat = lstatSync(dir)
        if (!stat.isSymbolicLink()) {
          rmdirSync(dir)
          report.artifactDirsRemoved += 1
          return true
        }
      } catch {
        return false
      }
    }
    return false
  }

  private sweepAgentSessionsDir(
    sessionsRoot: string,
    cutoffMs: number,
    refs: {
      activeRuns: ReadonlySet<string>
      liveRunIds: ReadonlySet<string>
      liveSessionIds: ReadonlySet<string>
    },
    report: OrphanSweepReport,
  ): void {
    let entries
    try {
      const stat = lstatSync(sessionsRoot)
      if (stat.isSymbolicLink() || !stat.isDirectory()) return
      entries = readdirSync(sessionsRoot, { withFileTypes: true })
    } catch {
      return
    }

    let seen = 0
    for (const entry of entries) {
      seen += 1
      if (seen > MAX_WALK_ENTRIES) break
      if (!isSafePathSegment(entry.name)) continue
      const full = join(sessionsRoot, entry.name)
      let info
      try {
        info = lstatSync(full)
      } catch {
        continue
      }
      if (info.isSymbolicLink()) {
        report.symlinksSkipped += 1
        continue
      }
      if (info.isDirectory()) {
        if (refs.activeRuns.has(entry.name)) {
          report.skippedActiveRuns += 1
          continue
        }
        if (refs.liveRunIds.has(entry.name)) continue
        const swept = sweepStaleTree(full, cutoffMs, {
          removeRootIfEmpty: true,
          activeRunIds: refs.activeRuns,
        })
        report.sessionFilesDeleted += swept.filesDeleted
        report.sessionDirsRemoved += swept.dirsRemoved
        report.sessionBytesFreed += swept.bytesFreed
        report.symlinksSkipped += swept.symlinksSkipped
        report.skippedActiveRuns += swept.skippedActive
        continue
      }
      if (!info.isFile()) continue
      const sessionId = parseSessionIdFromFileName(entry.name)
      if (!sessionId) continue
      if (refs.liveSessionIds.has(sessionId)) continue
      if (isProtectedByActiveRunName(sessionId, refs.activeRuns)) {
        report.skippedActiveRuns += 1
        continue
      }
      if (info.mtimeMs > cutoffMs) continue
      const res = safeUnlinkFile(full)
      if (res.skippedSymlink) report.symlinksSkipped += 1
      if (res.deleted) {
        report.sessionFilesDeleted += 1
        report.sessionBytesFreed += res.bytes
      }
    }
  }

  /**
   * Execute a full maintenance pass:
   *  1. Artifact/exchange/temp TTL purge (`artifact-ttl.ts`)
   *  2. Bounded `operations` table retention
   *  3. Orphan disk file sweep (`scratch/`, `artifacts/`, `agent-sessions/`)
   *  4. WAL checkpoint (`TRUNCATE` + `incremental_vacuum` when `activeRuns === 0`, else `PASSIVE`)
   */
  runMaintenanceCycle(options: { now?: number; graceMs?: number } = {}): StorageMaintenanceReport {
    if (this.inFlight && this.latestReport) {
      return this.latestReport
    }
    this.inFlight = true
    const now = options.now ?? this.nowFn()
    const errors: string[] = []
    let ttl: ArtifactTtlPurgeResult | null = null
    let operations: OperationsPruneReport = { deleted: 0, cutoff: now, retentionMs: this.operationsRetentionMs }
    let orphans: OrphanSweepReport = {
      scratchFilesDeleted: 0,
      scratchDirsRemoved: 0,
      scratchBytesFreed: 0,
      artifactFilesDeleted: 0,
      artifactDirsRemoved: 0,
      artifactBytesFreed: 0,
      sessionFilesDeleted: 0,
      sessionDirsRemoved: 0,
      sessionBytesFreed: 0,
      symlinksSkipped: 0,
      skippedActiveRuns: 0,
    }
    let checkpoint: WalCheckpointReport = {
      mode: 'passive',
      busy: 0,
      log: 0,
      checkpointed: 0,
      activeRuns: 0,
      incrementalVacuumRan: false,
      incrementalVacuumPages: 0,
    }

    try {
      if (this.ttlPolicy !== false) {
        try {
          ttl = purgeExpiredArtifacts(this.store, { ...this.ttlPolicy, now })
        } catch (error) {
          errors.push(`ttl: ${error instanceof Error ? error.message : String(error)}`)
          this.onError?.('ttl', error)
        }
      }

      try {
        operations = this.pruneOperations({ now })
      } catch (error) {
        errors.push(`operations: ${error instanceof Error ? error.message : String(error)}`)
        this.onError?.('operations', error)
      }

      try {
        orphans = this.sweepOrphans({ now, graceMs: options.graceMs })
      } catch (error) {
        errors.push(`orphans: ${error instanceof Error ? error.message : String(error)}`)
        this.onError?.('orphans', error)
      }

      try {
        checkpoint = this.runCheckpoint({ allowTruncate: true })
      } catch (error) {
        errors.push(`checkpoint: ${error instanceof Error ? error.message : String(error)}`)
        this.onError?.('checkpoint', error)
      }

      const report: StorageMaintenanceReport = {
        ranAt: new Date(now).toISOString(),
        activeRuns: checkpoint.activeRuns,
        checkpoint,
        ttl,
        operations,
        orphans,
        errors,
      }
      this.latestReport = report
      return report
    } finally {
      this.inFlight = false
    }
  }
}
