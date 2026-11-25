/**
 * v7 M4 Production Operations — Global < 2 s Kill Switch.
 *
 * Provides an immediate, fail-closed kill switch that:
 *  1. Trips process-wide in memory (< 1 ms) and aborts every registered in-flight
 *     AbortController (broker HTTP/DNS/TLS/WS requests, workers, etc.).
 *  2. Persists state atomically (0600 temp+rename JSON file and/or SQLite table) so
 *     external operators or sibling processes can trip it within < 50 ms.
 *  3. Supports either a global trip (`tenantId = null`) or a tenant-scoped trip.
 */
import { randomBytes } from 'node:crypto'
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { DatabaseSync } from 'node:sqlite'

export interface KillSwitchState {
  active: boolean
  reason: string | null
  trippedBy: string | null
  trippedAt: number | null
  /** `null` means global (all tenants halted); non-null halts only that tenant. */
  tenantId: string | null
  generation: number
}

export interface KillSwitchTripInput {
  reason: string
  trippedBy?: string
  tenantId?: string | null
  now?: number
}

export interface KillSwitchOptions {
  /** Optional path to an owner-only (0600) JSON backing file for cross-process trips. */
  filePath?: string
  /** Optional SQLite DatabaseSync handle for DB-backed persistence. */
  db?: DatabaseSync
  /** Minimum interval between external file/DB polls when in-memory state is inactive (ms). Default 25 ms. */
  pollIntervalMs?: number
  /** Optional injectable clock for deterministic tests. */
  now?: () => number
}

export class KillSwitchTrippedError extends Error {
  readonly code = 'KILL_SWITCH_TRIPPED'
  readonly trippedAt: number
  readonly reason: string
  readonly tenantId: string | null

  constructor(state: KillSwitchState) {
    const scope = state.tenantId ? `tenant "${state.tenantId}"` : 'global'
    const reason = state.reason || 'Operator triggered emergency kill switch.'
    super(`Kill switch active (${scope}): ${reason}`)
    this.name = 'KillSwitchTrippedError'
    this.trippedAt = state.trippedAt ?? Date.now()
    this.reason = reason
    this.tenantId = state.tenantId
  }
}

interface RegisteredController {
  controller: AbortController
  tenantId: string | null
}

function emptyState(generation = 0): KillSwitchState {
  return {
    active: false,
    reason: null,
    trippedBy: null,
    trippedAt: null,
    tenantId: null,
    generation,
  }
}

export class GlobalKillSwitch {
  private state: KillSwitchState = emptyState(0)
  private readonly controllers = new Set<RegisteredController>()
  private readonly listeners = new Set<(state: KillSwitchState) => void>()
  private filePath: string | null = null
  private db: DatabaseSync | null = null
  private pollIntervalMs = 25
  private lastExternalCheckMs = 0
  private lastFileMtimeMs = -1
  private nowFn: () => number = Date.now

  constructor(options: KillSwitchOptions = {}) {
    this.configure(options)
  }

  /** Attach or update file/DB backing and clock without dropping registered controllers. */
  configure(options: KillSwitchOptions): void {
    if ('filePath' in options) {
      this.filePath = options.filePath ?? null
      this.lastFileMtimeMs = -1
    }
    if ('db' in options) {
      this.db = options.db ?? null
      if (this.db) this.ensureDbTable(this.db)
    }
    if (options.pollIntervalMs !== undefined) {
      this.pollIntervalMs = Math.max(0, options.pollIntervalMs)
    }
    if (options.now) {
      this.nowFn = options.now
    }
    this.lastExternalCheckMs = 0
    this.syncFromExternal(true)
  }

  private ensureDbTable(db: DatabaseSync): void {
    db.exec(`
      CREATE TABLE IF NOT EXISTS kill_switch_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        active INTEGER NOT NULL DEFAULT 0,
        reason TEXT,
        tripped_by TEXT,
        tripped_at INTEGER,
        tenant_id TEXT,
        generation INTEGER NOT NULL DEFAULT 0
      );
    `)
  }

  private matchesScope(state: KillSwitchState, tenantId?: string | null): boolean {
    if (!state.active) return false
    if (state.tenantId === null) return true
    if (!tenantId) return false
    return state.tenantId === tenantId
  }

  private persistExternal(state: KillSwitchState): void {
    if (this.filePath) {
      mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 })
      const tmp = `${this.filePath}.${randomBytes(6).toString('hex')}.tmp`
      writeFileSync(tmp, JSON.stringify(state) + '\n', { flag: 'wx', mode: 0o600 })
      try {
        chmodSync(tmp, 0o600)
        renameSync(tmp, this.filePath)
        this.lastFileMtimeMs = statSync(this.filePath).mtimeMs
      } catch (err) {
        rmSync(tmp, { force: true })
        throw err
      }
    }
    if (this.db) {
      this.ensureDbTable(this.db)
      this.db.prepare(`
        INSERT INTO kill_switch_state (id, active, reason, tripped_by, tripped_at, tenant_id, generation)
        VALUES (1, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          active = excluded.active,
          reason = excluded.reason,
          tripped_by = excluded.tripped_by,
          tripped_at = excluded.tripped_at,
          tenant_id = excluded.tenant_id,
          generation = excluded.generation
      `).run(
        state.active ? 1 : 0,
        state.reason,
        state.trippedBy,
        state.trippedAt,
        state.tenantId,
        state.generation,
      )
    }
  }

  private readExternalState(): KillSwitchState | null {
    if (this.filePath) {
      try {
        const info = statSync(this.filePath)
        if (info.mtimeMs !== this.lastFileMtimeMs) {
          this.lastFileMtimeMs = info.mtimeMs
          const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as Partial<KillSwitchState>
          if (typeof parsed.active === 'boolean') {
            return {
              active: parsed.active,
              reason: typeof parsed.reason === 'string' ? parsed.reason : null,
              trippedBy: typeof parsed.trippedBy === 'string' ? parsed.trippedBy : null,
              trippedAt: typeof parsed.trippedAt === 'number' ? parsed.trippedAt : null,
              tenantId: typeof parsed.tenantId === 'string' ? parsed.tenantId : null,
              generation: typeof parsed.generation === 'number' ? parsed.generation : this.state.generation + 1,
            }
          }
        }
      } catch {
        // Absent file means no file-backed trip.
      }
    }
    if (this.db) {
      try {
        const row = this.db.prepare(
          'SELECT active, reason, tripped_by, tripped_at, tenant_id, generation FROM kill_switch_state WHERE id = 1',
        ).get() as {
          active: number
          reason: string | null
          tripped_by: string | null
          tripped_at: number | null
          tenant_id: string | null
          generation: number
        } | undefined
        if (row) {
          return {
            active: row.active === 1,
            reason: row.reason,
            trippedBy: row.tripped_by,
            trippedAt: row.tripped_at,
            tenantId: row.tenant_id,
            generation: row.generation,
          }
        }
      } catch {
        // Table not initialized yet or DB closed.
      }
    }
    return null
  }

  /** Sync state from file/DB backing when another process tripped or reset the switch. */
  syncFromExternal(force = false): void {
    if (!this.filePath && !this.db) return
    const now = this.nowFn()
    if (!force && now - this.lastExternalCheckMs < this.pollIntervalMs) return
    this.lastExternalCheckMs = now
    const external = this.readExternalState()
    if (!external) return
    const shouldAdopt =
      external.generation > this.state.generation ||
      (external.active && !this.state.active)
    if (!shouldAdopt) return
    const wasActive = this.state.active
    this.state = { ...external }
    if (this.state.active && !wasActive) {
      this.abortMatchingControllers(this.state)
      this.notifyListeners(this.state)
    }
  }

  private abortMatchingControllers(state: KillSwitchState): number {
    const error = new KillSwitchTrippedError(state)
    let aborted = 0
    for (const entry of [...this.controllers]) {
      if (state.tenantId === null || entry.tenantId === state.tenantId) {
        this.controllers.delete(entry)
        if (!entry.controller.signal.aborted) {
          entry.controller.abort(error)
          aborted += 1
        }
      }
    }
    return aborted
  }

  private notifyListeners(state: KillSwitchState): void {
    for (const listener of this.listeners) {
      try {
        listener({ ...state })
      } catch {
        // Listeners must never block emergency abort propagation.
      }
    }
  }

  /** Trip the kill switch immediately, persisting externally and aborting all matching in-flight work. */
  trip(input: KillSwitchTripInput): KillSwitchState {
    const now = input.now ?? this.nowFn()
    const next: KillSwitchState = {
      active: true,
      reason: (input.reason || 'Emergency kill switch tripped.').trim().slice(0, 500),
      trippedBy: (input.trippedBy || 'operator').trim().slice(0, 128),
      trippedAt: now,
      tenantId: input.tenantId ?? null,
      generation: this.state.generation + 1,
    }
    this.state = next
    this.lastExternalCheckMs = now
    this.abortMatchingControllers(next)
    this.persistExternal(next)
    this.notifyListeners(next)
    return { ...next }
  }

  /** Clear the kill switch so new runs/requests may proceed. */
  reset(options: { resetBy?: string; now?: number } = {}): KillSwitchState {
    const now = options.now ?? this.nowFn()
    const next = emptyState(this.state.generation + 1)
    this.state = next
    this.lastExternalCheckMs = now
    this.persistExternal(next)
    this.notifyListeners(next)
    return { ...next }
  }

  status(): KillSwitchState {
    this.syncFromExternal(false)
    return { ...this.state }
  }

  isActive(tenantId?: string | null): boolean {
    if (this.matchesScope(this.state, tenantId)) return true
    this.syncFromExternal(false)
    return this.matchesScope(this.state, tenantId)
  }

  /** Fail closed immediately if the kill switch is active globally or for `tenantId`. */
  assertAllowed(tenantId?: string | null): void {
    if (this.isActive(tenantId)) {
      throw new KillSwitchTrippedError(this.state)
    }
  }

  /**
   * Register an in-flight AbortController with the kill switch and return a combined AbortSignal.
   * Always call `release()` in a `finally` block so completed requests do not retain controllers.
   */
  bindSignal(
    callerSignal: AbortSignal,
    tenantId: string | null = null,
  ): { signal: AbortSignal; release: () => void } {
    this.assertAllowed(tenantId)
    const controller = new AbortController()
    const entry: RegisteredController = { controller, tenantId }
    this.controllers.add(entry)
    // Re-check after registration to close any race window.
    if (this.isActive(tenantId)) {
      this.controllers.delete(entry)
      const err = new KillSwitchTrippedError(this.state)
      controller.abort(err)
      throw err
    }
    const signal = AbortSignal.any([callerSignal, controller.signal])
    const release = () => {
      this.controllers.delete(entry)
    }
    return { signal, release }
  }

  /** Subscribe to kill-switch state transitions. Returns an unsubscribe function. */
  onChange(listener: (state: KillSwitchState) => void): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  /** Active registered in-flight controller count (diagnostics & chaos tests). */
  activeControllerCount(): number {
    return this.controllers.size
  }
}

export const globalKillSwitch = new GlobalKillSwitch()

export function configureGlobalKillSwitch(options: KillSwitchOptions): GlobalKillSwitch {
  globalKillSwitch.configure(options)
  return globalKillSwitch
}
