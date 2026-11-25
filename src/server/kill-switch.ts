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

function normalizeTenantId(tenantId?: string | null): string | null {
  if (typeof tenantId !== 'string') return null
  const trimmed = tenantId.trim()
  return trimmed.length > 0 ? trimmed : null
}

function emptyState(generation = 0, tenantId: string | null = null): KillSwitchState {
  return {
    active: false,
    reason: null,
    trippedBy: null,
    trippedAt: null,
    tenantId,
    generation,
  }
}

interface ExternalKillSwitchSnapshot {
  global: KillSwitchState
  tenants: Map<string, KillSwitchState>
  generation: number
}

function parseKillSwitchEntry(raw: unknown, fallbackTenantId: string | null, fallbackGeneration: number): KillSwitchState | null {
  if (!raw || typeof raw !== 'object') return null
  const parsed = raw as Partial<KillSwitchState>
  if (typeof parsed.active !== 'boolean') return null
  return {
    active: parsed.active,
    reason: typeof parsed.reason === 'string' ? parsed.reason : null,
    trippedBy: typeof parsed.trippedBy === 'string' ? parsed.trippedBy : null,
    trippedAt: typeof parsed.trippedAt === 'number' ? parsed.trippedAt : null,
    tenantId: fallbackTenantId ?? normalizeTenantId(parsed.tenantId),
    generation: typeof parsed.generation === 'number' ? parsed.generation : fallbackGeneration,
  }
}

export class GlobalKillSwitch {
  private globalState: KillSwitchState = emptyState(0)
  private readonly tenantStates = new Map<string, KillSwitchState>()
  private generation = 0
  private readonly controllers = new Set<RegisteredController>()
  private readonly listeners = new Set<(state: KillSwitchState) => void>()
  private readonly sseRevocationListeners = new Set<(state: KillSwitchState) => void>()
  private signalController: AbortController = new AbortController()
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
      CREATE TABLE IF NOT EXISTS kill_switch_tenants (
        tenant_id TEXT PRIMARY KEY,
        active INTEGER NOT NULL DEFAULT 0,
        reason TEXT,
        tripped_by TEXT,
        tripped_at INTEGER,
        generation INTEGER NOT NULL DEFAULT 0
      );
    `)
  }

  private matchesScope(state: KillSwitchState, tenantId?: string | null): boolean {
    if (!state.active) return false
    if (state.tenantId === null) return true
    const normalized = normalizeTenantId(tenantId)
    if (!normalized) return false
    return state.tenantId === normalized
  }

  private resolveActiveState(tenantId?: string | null): KillSwitchState | null {
    if (this.globalState.active) return this.globalState
    const normalized = normalizeTenantId(tenantId)
    if (!normalized) return null
    const tenantState = this.tenantStates.get(normalized)
    if (tenantState && this.matchesScope(tenantState, normalized)) return tenantState
    return null
  }

  private persistExternal(): void {
    if (this.filePath) {
      mkdirSync(dirname(this.filePath), { recursive: true, mode: 0o700 })
      const tmp = `${this.filePath}.${randomBytes(6).toString('hex')}.tmp`
      const payload = {
        ...this.globalState,
        generation: this.generation,
        tenants: Object.fromEntries(this.tenantStates),
      }
      writeFileSync(tmp, JSON.stringify(payload) + '\n', { flag: 'wx', mode: 0o600 })
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
        VALUES (1, ?, ?, ?, ?, NULL, ?)
        ON CONFLICT(id) DO UPDATE SET
          active = excluded.active,
          reason = excluded.reason,
          tripped_by = excluded.tripped_by,
          tripped_at = excluded.tripped_at,
          tenant_id = NULL,
          generation = excluded.generation
      `).run(
        this.globalState.active ? 1 : 0,
        this.globalState.reason,
        this.globalState.trippedBy,
        this.globalState.trippedAt,
        this.generation,
      )
      this.db.prepare('DELETE FROM kill_switch_tenants').run()
      const upsertTenant = this.db.prepare(`
        INSERT INTO kill_switch_tenants (tenant_id, active, reason, tripped_by, tripped_at, generation)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(tenant_id) DO UPDATE SET
          active = excluded.active,
          reason = excluded.reason,
          tripped_by = excluded.tripped_by,
          tripped_at = excluded.tripped_at,
          generation = excluded.generation
      `)
      for (const [tenantId, state] of this.tenantStates) {
        if (!state.active) continue
        upsertTenant.run(
          tenantId,
          1,
          state.reason,
          state.trippedBy,
          state.trippedAt,
          state.generation,
        )
      }
    }
  }

  private readExternalState(): ExternalKillSwitchSnapshot | null {
    if (this.filePath) {
      try {
        const info = statSync(this.filePath)
        if (info.mtimeMs !== this.lastFileMtimeMs) {
          this.lastFileMtimeMs = info.mtimeMs
          const parsed = JSON.parse(readFileSync(this.filePath, 'utf8')) as Partial<KillSwitchState> & {
            tenants?: Record<string, unknown>
          }
          const topGen = typeof parsed.generation === 'number' ? parsed.generation : this.generation + 1
          const tenants = new Map<string, KillSwitchState>()
          if (parsed.tenants && typeof parsed.tenants === 'object' && !Array.isArray(parsed.tenants)) {
            for (const [rawKey, rawVal] of Object.entries(parsed.tenants)) {
              const key = normalizeTenantId(rawKey)
              if (!key) continue
              const entry = parseKillSwitchEntry(rawVal, key, topGen)
              if (entry?.active) tenants.set(key, entry)
            }
          }
          if (typeof parsed.active === 'boolean') {
            const topTenant = normalizeTenantId(parsed.tenantId)
            // Backwards compatibility: legacy single-slot tenant file must not overwrite global state.
            if (topTenant && parsed.active) {
              if (!tenants.has(topTenant)) {
                tenants.set(topTenant, {
                  active: true,
                  reason: typeof parsed.reason === 'string' ? parsed.reason : null,
                  trippedBy: typeof parsed.trippedBy === 'string' ? parsed.trippedBy : null,
                  trippedAt: typeof parsed.trippedAt === 'number' ? parsed.trippedAt : null,
                  tenantId: topTenant,
                  generation: topGen,
                })
              }
              return { global: emptyState(0), tenants, generation: topGen }
            }
            return {
              global: {
                active: parsed.active,
                reason: typeof parsed.reason === 'string' ? parsed.reason : null,
                trippedBy: typeof parsed.trippedBy === 'string' ? parsed.trippedBy : null,
                trippedAt: typeof parsed.trippedAt === 'number' ? parsed.trippedAt : null,
                tenantId: null,
                generation: topGen,
              },
              tenants,
              generation: topGen,
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
        const tenantRows = (() => {
          try {
            return this.db!.prepare(
              'SELECT tenant_id, active, reason, tripped_by, tripped_at, generation FROM kill_switch_tenants WHERE active = 1',
            ).all() as Array<{
              tenant_id: string
              active: number
              reason: string | null
              tripped_by: string | null
              tripped_at: number | null
              generation: number
            }>
          } catch {
            return []
          }
        })()
        if (row || tenantRows.length > 0) {
          const tenants = new Map<string, KillSwitchState>()
          let maxGen = row?.generation ?? 0
          for (const tr of tenantRows) {
            const key = normalizeTenantId(tr.tenant_id)
            if (!key || tr.active !== 1) continue
            if (tr.generation > maxGen) maxGen = tr.generation
            tenants.set(key, {
              active: true,
              reason: tr.reason,
              trippedBy: tr.tripped_by,
              trippedAt: tr.tripped_at,
              tenantId: key,
              generation: tr.generation,
            })
          }
          const legacyTenant = normalizeTenantId(row?.tenant_id)
          if (row && legacyTenant && row.active === 1) {
            if (!tenants.has(legacyTenant)) {
              tenants.set(legacyTenant, {
                active: true,
                reason: row.reason,
                trippedBy: row.tripped_by,
                trippedAt: row.tripped_at,
                tenantId: legacyTenant,
                generation: row.generation,
              })
            }
            return { global: emptyState(0), tenants, generation: maxGen }
          }
          return {
            global: row
              ? {
                  active: row.active === 1,
                  reason: row.reason,
                  trippedBy: row.tripped_by,
                  trippedAt: row.tripped_at,
                  tenantId: null,
                  generation: row.generation,
                }
              : emptyState(0),
            tenants,
            generation: maxGen,
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
    const hasNewTenantTrip = [...external.tenants.keys()].some(tid => !this.tenantStates.get(tid)?.active)
    const shouldAdopt =
      external.generation > this.generation ||
      (external.global.active && !this.globalState.active) ||
      hasNewTenantTrip
    if (!shouldAdopt) return
    const wasGlobalActive = this.globalState.active
    const prevActiveTenants = new Set(
      [...this.tenantStates.entries()].filter(([, s]) => s.active).map(([tid]) => tid),
    )
    this.globalState = { ...external.global, tenantId: null }
    this.tenantStates.clear()
    for (const [tid, st] of external.tenants) {
      if (st.active) this.tenantStates.set(tid, { ...st, tenantId: tid })
    }
    this.generation = Math.max(this.generation, external.generation)
    if (this.globalState.active && !wasGlobalActive) {
      if (!this.signalController.signal.aborted) {
        this.signalController.abort(new KillSwitchTrippedError(this.globalState))
      }
      this.abortMatchingControllers(this.globalState)
      this.notifyListeners(this.globalState)
      this.notifySseRevocation(this.globalState)
    } else if (!this.globalState.active && wasGlobalActive && this.signalController.signal.aborted) {
      this.signalController = new AbortController()
    }
    for (const [tid, st] of this.tenantStates) {
      if (st.active && !prevActiveTenants.has(tid)) {
        this.abortMatchingControllers(st)
        this.notifyListeners(st)
        this.notifySseRevocation(st)
      }
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

  private notifySseRevocation(state: KillSwitchState): void {
    for (const listener of [...this.sseRevocationListeners]) {
      try {
        listener({ ...state })
      } catch {
        // SSE revocation failures must never block other subscribers or abort propagation.
      }
    }
  }

  /** Live global AbortSignal that aborts synchronously on a global trip and refreshes on global reset. */
  get signal(): AbortSignal {
    return this.signalController.signal
  }

  /** Convenience active trigger accepting either a plain reason string or full `KillSwitchTripInput`. */
  trigger(reasonOrInput: string | KillSwitchTripInput): KillSwitchState {
    if (typeof reasonOrInput === 'string') {
      return this.trip({ reason: reasonOrInput })
    }
    return this.trip(reasonOrInput)
  }

  /** Trip the kill switch immediately, persisting externally and aborting all matching in-flight work. */
  trip(input: KillSwitchTripInput): KillSwitchState {
    const now = input.now ?? this.nowFn()
    const tenantId = normalizeTenantId(input.tenantId)
    this.generation += 1
    const next: KillSwitchState = {
      active: true,
      reason: (input.reason || 'Emergency kill switch tripped.').trim().slice(0, 500),
      trippedBy: (input.trippedBy || 'operator').trim().slice(0, 128),
      trippedAt: now,
      tenantId,
      generation: this.generation,
    }
    if (tenantId === null) {
      this.globalState = next
      if (!this.signalController.signal.aborted) {
        this.signalController.abort(new KillSwitchTrippedError(next))
      }
    } else {
      // Tenant-scoped trip MUST NOT overwrite global state or other tenants' state.
      this.tenantStates.set(tenantId, next)
    }
    this.lastExternalCheckMs = now
    this.abortMatchingControllers(next)
    this.persistExternal()
    this.notifyListeners(next)
    this.notifySseRevocation(next)
    return { ...next }
  }

  /** Clear the kill switch (globally, or for a single tenant when `tenantId` is supplied). */
  reset(options: { resetBy?: string; tenantId?: string | null; now?: number } = {}): KillSwitchState {
    const now = options.now ?? this.nowFn()
    const tenantId = normalizeTenantId(options.tenantId)
    this.generation += 1
    if (tenantId !== null) {
      this.tenantStates.delete(tenantId)
      const next = emptyState(this.generation, tenantId)
      this.lastExternalCheckMs = now
      this.persistExternal()
      this.notifyListeners(next)
      return { ...next }
    }
    const next = emptyState(this.generation, null)
    this.globalState = next
    this.tenantStates.clear()
    if (this.signalController.signal.aborted) {
      this.signalController = new AbortController()
    }
    this.lastExternalCheckMs = now
    this.persistExternal()
    this.notifyListeners(next)
    return { ...next }
  }

  status(tenantId?: string | null): KillSwitchState {
    this.syncFromExternal(false)
    const normalized = normalizeTenantId(tenantId)
    if (normalized) {
      const active = this.resolveActiveState(normalized)
      return active ? { ...active } : emptyState(this.generation, normalized)
    }
    return { ...this.globalState }
  }

  activeTenants(): KillSwitchState[] {
    this.syncFromExternal(false)
    return [...this.tenantStates.values()].filter(s => s.active).map(s => ({ ...s }))
  }

  isActive(tenantId?: string | null): boolean {
    if (this.resolveActiveState(tenantId)) return true
    this.syncFromExternal(false)
    return this.resolveActiveState(tenantId) !== null
  }

  /** Fail closed immediately if the kill switch is active globally or for `tenantId`. */
  assertAllowed(tenantId?: string | null): void {
    let active = this.resolveActiveState(tenantId)
    if (!active) {
      this.syncFromExternal(false)
      active = this.resolveActiveState(tenantId)
    }
    if (active) {
      throw new KillSwitchTrippedError(active)
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
    const normalizedTenant = normalizeTenantId(tenantId)
    this.assertAllowed(normalizedTenant)
    const controller = new AbortController()
    const entry: RegisteredController = { controller, tenantId: normalizedTenant }
    this.controllers.add(entry)
    // Re-check after registration to close any race window.
    const active = this.resolveActiveState(normalizedTenant)
    if (active) {
      this.controllers.delete(entry)
      const err = new KillSwitchTrippedError(active)
      controller.abort(err)
      throw err
    }
    const signal = AbortSignal.any([callerSignal, controller.signal])
    const release = () => {
      this.controllers.delete(entry)
    }
    return { signal, release }
  }

  /**
   * Register an existing AbortController (e.g. a `RunContext.abortController`) directly with the
   * kill switch. If already active for `tenantId`, aborts the controller synchronously and returns
   * a no-op release callback.
   */
  registerAbortController(
    controller: AbortController,
    tenantId: string | null = null,
  ): () => void {
    const normalizedTenant = normalizeTenantId(tenantId)
    const active = this.resolveActiveState(normalizedTenant)
    if (active) {
      if (!controller.signal.aborted) {
        controller.abort(new KillSwitchTrippedError(active))
      }
      return () => {}
    }
    const entry: RegisteredController = { controller, tenantId: normalizedTenant }
    this.controllers.add(entry)
    // Re-check after registration to close any race window.
    const raced = this.resolveActiveState(normalizedTenant)
    if (raced) {
      this.controllers.delete(entry)
      if (!controller.signal.aborted) {
        controller.abort(new KillSwitchTrippedError(raced))
      }
      return () => {}
    }
    return () => {
      this.controllers.delete(entry)
    }
  }

  /** Subscribe to kill-switch state transitions. Returns an unsubscribe function. */
  onChange(listener: (state: KillSwitchState) => void): () => void {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  /** Subscribe to kill-switch state transitions (alias for `onChange`). */
  subscribe(listener: (state: KillSwitchState) => void): () => void {
    return this.onChange(listener)
  }

  /** Register an SSE revocation callback broadcast synchronously when the kill switch trips. */
  onSseRevocation(listener: (state: KillSwitchState) => void): () => void {
    this.sseRevocationListeners.add(listener)
    return () => {
      this.sseRevocationListeners.delete(listener)
    }
  }

  /** Active SSE revocation subscriber count (diagnostics & tests). */
  sseSubscriberCount(): number {
    return this.sseRevocationListeners.size
  }

  /** Active registered in-flight controller count (diagnostics & chaos tests). */
  activeControllerCount(): number {
    return this.controllers.size
  }
}

const GLOBAL_KILL_SWITCH_SYMBOL = Symbol.for('kovo.globalKillSwitch')

function getOrCreateGlobalKillSwitch(): GlobalKillSwitch {
  const g = globalThis as Record<symbol, GlobalKillSwitch | undefined>
  let existing = g[GLOBAL_KILL_SWITCH_SYMBOL]
  if (!existing) {
    existing = new GlobalKillSwitch()
    g[GLOBAL_KILL_SWITCH_SYMBOL] = existing
  }
  return existing
}

export const globalKillSwitch: GlobalKillSwitch = getOrCreateGlobalKillSwitch()

export function configureGlobalKillSwitch(options: KillSwitchOptions): GlobalKillSwitch {
  globalKillSwitch.configure(options)
  return globalKillSwitch
}
