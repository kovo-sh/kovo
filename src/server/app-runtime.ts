/**
 * Option 2 — Move 2: Single `AppRuntime` Composition Root.
 *
 * Consolidates process-wide runtime ownership across Vite SSR (`src/server.ts`) and the local
 * HTTP server (`scripts/serve.ts`) into one typed composition root:
 *  - `store`: lazily initialized once per data directory (zero dual SQLite locks)
 *  - `killSwitch`: active `GlobalKillSwitch` whose `trigger()`/`trip()` immediately aborts ALL
 *    active `RunContext` `AbortController`s and broadcasts SSE revocation callbacks
 *  - `runs`: mandatory per-run `RunContext` registry (`createRunContext`, `getRunContext`,
 *    `requireRunContext`, `disposeRunContext`)
 *  - `oob` / `canaryBroker`: optional/lazy OOB subsystem automatically unsubscribed per run and
 *    closed deterministically on `dispose()`
 *  - `dispose()`: deterministic graceful shutdown of all active runs, OOB relay/broker, and store.
 */
import { resolve } from 'node:path'
import { CanaryBroker } from './canary-broker.ts'
import {
  configureGlobalKillSwitch,
  GlobalKillSwitch,
  globalKillSwitch,
  KillSwitchTrippedError,
} from './kill-switch.ts'
import type { KillSwitchOptions, KillSwitchState } from './kill-switch.ts'
import { cancelOobDrainForRun } from './oob-drain.ts'
import { OobRelay } from './oob-relay.ts'
import { assertValidRunId, InvalidRunIdError, RunContext } from './run-context.ts'
import type { RunContextOptions, RunDrainReport } from './run-context.ts'
import { StorageMaintenanceController } from './storage-maintenance.ts'
import type { StorageMaintenanceOptions } from './storage-maintenance.ts'
import { dataDirectory, Store, store as legacyStore } from './store.ts'

export interface AppRuntimeOptions {
  /** Resolved data directory for SQLite store, OOB relay, and kill-switch backing file. */
  dataDir?: string
  /** Optional pre-built Store instance (DI / tests). */
  store?: Store
  /** Optional lazy Store factory override. */
  storeFactory?: (dataDir: string) => Store
  /** Optional pre-built GlobalKillSwitch instance. */
  killSwitch?: GlobalKillSwitch
  /** Optional KillSwitch configuration applied to `killSwitch`. */
  killSwitchOptions?: KillSwitchOptions
  /** Convenience shorthand for `killSwitchOptions.filePath`. */
  killSwitchFilePath?: string
  /** Optional pre-built OobRelay instance. */
  oobRelay?: OobRelay
  /** Optional pre-built CanaryBroker instance. */
  canaryBroker?: CanaryBroker
  /** When true (used by `getAppRuntime()`), shares the process-wide Store registry slot. */
  useSharedStoreRegistry?: boolean
  /** Default drain timeout (ms) used by `RunContext.drainAndDispose()`. */
  defaultDrainTimeoutMs?: number
  /** Move S3: StorageMaintenanceController configuration, or `false` to disable automatic background maintenance. */
  maintenance?: Omit<StorageMaintenanceOptions, 'store' | 'dataDir' | 'getActiveRunIds'> | false
  /** Whether to auto-start `.unref()` maintenance timers once `store` is materialized. Default true. */
  autoStartMaintenance?: boolean
}

export interface AppRuntimeDisposeReport {
  dataDir: string
  runsDisposed: number
  runReports: RunDrainReport[]
  oobClosed: boolean
  maintenanceStopped: boolean
  storeClosed: boolean
  errors: string[]
  alreadyDisposed: boolean
}

const APP_RUNTIME_SYMBOL = Symbol.for('kovo.appRuntime')
const STORE_SINGLETON_SYMBOL = Symbol.for('kovo.storeSingleton')

function getAppRuntimeRegistry(): Map<string, AppRuntime> {
  const g = globalThis as Record<symbol, Map<string, AppRuntime> | undefined>
  let registry = g[APP_RUNTIME_SYMBOL]
  if (!registry) {
    registry = new Map<string, AppRuntime>()
    g[APP_RUNTIME_SYMBOL] = registry
  }
  return registry
}

function getSharedStoreSlot(dir: string): Store {
  const resolvedDir = resolve(dir)
  if (resolvedDir === resolve(dataDirectory())) {
    return legacyStore()
  }
  const g = globalThis as Record<symbol, Map<string, Store> | undefined>
  let registry = g[STORE_SINGLETON_SYMBOL]
  if (!registry) {
    registry = new Map<string, Store>()
    g[STORE_SINGLETON_SYMBOL] = registry
  }
  let existing = registry.get(resolvedDir)
  if (!existing) {
    existing = new Store(resolvedDir)
    registry.set(resolvedDir, existing)
  }
  return existing
}

export class AppRuntime {
  readonly dataDir: string
  readonly killSwitch: GlobalKillSwitch
  readonly runs = new Map<string, RunContext>()

  private readonly useSharedStoreRegistry: boolean
  private readonly storeFactory?: (dataDir: string) => Store
  private readonly defaultDrainTimeoutMs?: number
  private readonly maintenanceEnabled: boolean
  private readonly autoStartMaintenance: boolean
  private readonly maintenanceOptions: Omit<StorageMaintenanceOptions, 'store' | 'dataDir' | 'getActiveRunIds'>
  private storeInstance: Store | null
  private oobRelayInstance: OobRelay | null
  private canaryBrokerInstance: CanaryBroker | null
  private maintenanceInstance: StorageMaintenanceController | null = null
  private readonly disposers = new Map<string, () => void | Promise<void>>()
  private disposed = false
  private disposePromise: Promise<AppRuntimeDisposeReport> | null = null

  constructor(options: AppRuntimeOptions = {}) {
    this.dataDir = resolve(options.dataDir ?? dataDirectory())
    this.useSharedStoreRegistry = options.useSharedStoreRegistry ?? false
    this.storeFactory = options.storeFactory
    this.defaultDrainTimeoutMs = options.defaultDrainTimeoutMs
    this.maintenanceEnabled = options.maintenance !== false
    this.autoStartMaintenance = options.autoStartMaintenance ?? true
    this.maintenanceOptions = options.maintenance && typeof options.maintenance === 'object' ? options.maintenance : {}
    this.storeInstance = options.store ?? null
    this.oobRelayInstance = options.oobRelay ?? options.canaryBroker?.oob ?? null
    this.canaryBrokerInstance = options.canaryBroker ?? null

    const ksOpts: KillSwitchOptions = {
      ...(options.killSwitchOptions ?? {}),
      ...(options.killSwitchFilePath !== undefined ? { filePath: options.killSwitchFilePath } : {}),
    }
    const hasKsConfig = Object.keys(ksOpts).length > 0
    if (options.killSwitch) {
      this.killSwitch = options.killSwitch
      if (hasKsConfig) this.killSwitch.configure(ksOpts)
    } else {
      this.killSwitch = new GlobalKillSwitch(ksOpts)
    }
    if (this.storeInstance && this.maintenanceEnabled && this.autoStartMaintenance) {
      this.ensureMaintenanceStarted()
    }
  }

  /** Lazily initialized Store instance owned by this runtime. */
  get store(): Store {
    this.assertNotDisposed()
    if (this.useSharedStoreRegistry && !this.storeFactory && !this.storeInstance) {
      const shared = getSharedStoreSlot(this.dataDir)
      this.storeInstance = shared
      if (this.maintenanceEnabled && this.autoStartMaintenance) {
        this.ensureMaintenanceStarted()
      }
      return shared
    }
    if (this.useSharedStoreRegistry && !this.storeFactory && this.storeInstance) {
      // If an external caller closed the shared Store directly, re-acquire cleanly.
      const g = globalThis as Record<symbol, Map<string, Store> | undefined>
      const registry = g[STORE_SINGLETON_SYMBOL]
      if (registry && registry.get(this.dataDir) !== this.storeInstance) {
        const shared = getSharedStoreSlot(this.dataDir)
        this.storeInstance = shared
        if (this.maintenanceInstance) {
          this.maintenanceInstance.stop()
          this.maintenanceInstance = null
        }
        if (this.maintenanceEnabled && this.autoStartMaintenance) {
          this.ensureMaintenanceStarted()
        }
        return shared
      }
      return this.storeInstance
    }
    if (!this.storeInstance) {
      this.storeInstance = this.storeFactory ? this.storeFactory(this.dataDir) : new Store(this.dataDir)
      if (this.maintenanceEnabled && this.autoStartMaintenance) {
        this.ensureMaintenanceStarted()
      }
    }
    return this.storeInstance
  }

  /** Lazily initialized StorageMaintenanceController owned by this runtime. */
  get maintenance(): StorageMaintenanceController {
    this.assertNotDisposed()
    if (!this.maintenanceInstance) {
      this.maintenanceInstance = new StorageMaintenanceController({
        ...this.maintenanceOptions,
        store: this.store,
        dataDir: this.dataDir,
        getActiveRunIds: () => this.activeRunIds(),
      })
    }
    return this.maintenanceInstance
  }

  /** Whether a StorageMaintenanceController has been materialized. */
  hasMaintenance(): boolean {
    return this.maintenanceInstance !== null
  }

  /** Start the runtime-owned StorageMaintenanceController with `.unref()` timers. */
  startMaintenance(): StorageMaintenanceController | null {
    this.assertNotDisposed()
    if (!this.maintenanceEnabled) return null
    const controller = this.maintenance
    controller.start()
    return controller
  }

  /** Stop the runtime-owned StorageMaintenanceController timers if initialized. */
  stopMaintenance(): boolean {
    if (!this.maintenanceInstance) return false
    this.maintenanceInstance.stop()
    return true
  }

  private ensureMaintenanceStarted(): void {
    if (!this.maintenanceEnabled || this.disposed || !this.storeInstance) return
    if (!this.maintenanceInstance) {
      this.maintenanceInstance = new StorageMaintenanceController({
        ...this.maintenanceOptions,
        store: this.storeInstance,
        dataDir: this.dataDir,
        getActiveRunIds: () => this.activeRunIds(),
      })
    }
    this.maintenanceInstance.start()
  }

  /** Whether `store` has been materialized yet (useful for lazy-init assertions). */
  hasStore(): boolean {
    return this.storeInstance !== null
  }

  /** Whether an OobRelay instance has been materialized or attached. */
  hasOobRelay(): boolean {
    return this.oobRelayInstance !== null
  }

  /** Whether a CanaryBroker instance has been materialized or attached. */
  hasCanaryBroker(): boolean {
    return this.canaryBrokerInstance !== null
  }

  /** Attach an externally constructed Store if none is attached yet. */
  attachStore(storeInstance: Store): void {
    this.assertNotDisposed()
    if (!this.storeInstance) {
      this.storeInstance = storeInstance
      if (this.maintenanceEnabled && this.autoStartMaintenance) {
        this.ensureMaintenanceStarted()
      }
    }
  }

  /**
   * Register a shutdown disposer (e.g. `Execution.stop()`) executed during `AppRuntime.dispose()`
   * BEFORE active RunContexts, OOB relay/broker, and Store are closed.
   */
  registerDisposer(name: string, disposeFn: () => void | Promise<void>): () => void {
    const key = name.trim() || `disposer-${this.disposers.size + 1}`
    if (this.disposed) {
      try { void Promise.resolve(disposeFn()).catch(() => undefined) } catch { /* ignore */ }
      return () => {}
    }
    this.disposers.set(key, disposeFn)
    return () => {
      if (this.disposers.get(key) === disposeFn) {
        this.disposers.delete(key)
      }
    }
  }

  /** Lazily initialized durable OOB relay owned by this runtime. */
  get oob(): OobRelay {
    this.assertNotDisposed()
    if (!this.oobRelayInstance) {
      this.oobRelayInstance = this.canaryBrokerInstance
        ? this.canaryBrokerInstance.oob
        : new OobRelay({ directory: this.dataDir })
    }
    return this.oobRelayInstance
  }

  /** Lazily initialized CanaryBroker owned by this runtime. */
  get canaryBroker(): CanaryBroker {
    this.assertNotDisposed()
    if (!this.canaryBrokerInstance) {
      this.canaryBrokerInstance = new CanaryBroker({
        ...(this.storeInstance ? { storage: this.storeInstance } : {}),
        ...(this.oobRelayInstance ? { oobRelay: this.oobRelayInstance } : { oobDirectory: this.dataDir }),
      })
      this.oobRelayInstance = this.canaryBrokerInstance.oob
    }
    return this.canaryBrokerInstance
  }

  /** Attach an externally constructed OobRelay so `RunContext` and `dispose()` manage its lifecycle. */
  attachOobRelay(relay: OobRelay): void {
    this.assertNotDisposed()
    this.oobRelayInstance = relay
  }

  /** Attach an externally constructed CanaryBroker so `RunContext` and `dispose()` manage its lifecycle. */
  attachCanaryBroker(broker: CanaryBroker): void {
    this.assertNotDisposed()
    this.canaryBrokerInstance = broker
    this.oobRelayInstance = broker.oob
  }

  /** Register an SSE revocation callback fired synchronously when `killSwitch` trips. */
  registerSseRevocation(listener: (state: KillSwitchState) => void): () => void {
    return this.killSwitch.onSseRevocation(listener)
  }

  /** Create and register a mandatory per-run `RunContext` chained to `this.killSwitch`. */
  createRunContext(
    runId: string,
    opts: Omit<RunContextOptions, 'runId' | 'killSwitch' | 'onDispose'> = {},
  ): RunContext {
    this.assertNotDisposed()
    const validRunId = assertValidRunId(runId, 'AppRuntime.createRunContext')
    if (this.runs.has(validRunId)) {
      throw new Error(`RunContext for runId "${validRunId}" already exists.`)
    }
    const ctx = new RunContext({
      ...opts,
      runId: validRunId,
      killSwitch: this.killSwitch,
      ...(opts.defaultDrainTimeoutMs === undefined && this.defaultDrainTimeoutMs !== undefined
        ? { defaultDrainTimeoutMs: this.defaultDrainTimeoutMs }
        : {}),
      onDispose: disposedRunId => {
        if (this.runs.get(disposedRunId) === ctx) {
          this.runs.delete(disposedRunId)
        }
      },
    })
    ctx.registerResource('oob:unsubscribe', () => {
      cancelOobDrainForRun(validRunId)
      if (this.canaryBrokerInstance) {
        this.canaryBrokerInstance.unsubscribeRun(validRunId)
      } else if (this.oobRelayInstance) {
        this.oobRelayInstance.unsubscribeRun(validRunId)
      }
    })
    this.runs.set(validRunId, ctx)
    return ctx
  }

  /** Look up an active `RunContext` by `runId`, returning `undefined` if not registered. */
  getRunContext(runId: string): RunContext | undefined {
    if (typeof runId !== 'string') return undefined
    const trimmed = runId.trim()
    if (!trimmed || trimmed.toLowerCase() === 'default') return undefined
    return this.runs.get(trimmed)
  }

  /** Require an active `RunContext` for `runId` (throws on invalid/default or unregistered `runId`). */
  requireRunContext(runId: string): RunContext {
    const validRunId = assertValidRunId(runId, 'AppRuntime.requireRunContext')
    const ctx = this.runs.get(validRunId)
    if (!ctx) {
      throw new Error(`RunContext not found for runId "${validRunId}".`)
    }
    return ctx
  }

  /** Drain and dispose a single `RunContext` by `runId`, removing it from `this.runs`. */
  async disposeRunContext(runId: string, timeoutMs?: number): Promise<RunDrainReport | null> {
    const ctx = this.getRunContext(runId)
    if (!ctx) return null
    return await ctx.drainAndDispose(timeoutMs)
  }

  activeRunIds(): string[] {
    return [...this.runs.keys()]
  }

  get isDisposed(): boolean {
    return this.disposed
  }

  /**
   * Deterministic graceful shutdown:
   *  1. Drain and dispose all active `RunContext`s via `Promise.allSettled`.
   *  2. Stop & close OOB listeners/relay if initialized.
   *  3. Close the owned `Store` if initialized.
   *  4. Remove this runtime from the process-wide registry if registered.
   */
  dispose(options: { timeoutMs?: number } = {}): Promise<AppRuntimeDisposeReport> {
    if (this.disposePromise) {
      return this.disposePromise.then(report => ({ ...report, alreadyDisposed: true }))
    }
    this.disposePromise = this.performDispose(options.timeoutMs)
    return this.disposePromise
  }

  private async performDispose(timeoutMs?: number): Promise<AppRuntimeDisposeReport> {
    const errors: string[] = []
    const registeredDisposers = [...this.disposers.entries()].reverse()
    this.disposers.clear()
    if (registeredDisposers.length > 0) {
      const disposerOutcomes = await Promise.allSettled(
        registeredDisposers.map(([, fn]) => Promise.resolve().then(() => fn())),
      )
      for (let i = 0; i < disposerOutcomes.length; i += 1) {
        const outcome = disposerOutcomes[i]!
        if (outcome.status === 'rejected') {
          const [name] = registeredDisposers[i]!
          errors.push(`disposer(${name}): ${outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason)}`)
        }
      }
    }

    const activeContexts = [...this.runs.values()]
    const runOutcomes = await Promise.allSettled(
      activeContexts.map(ctx => ctx.drainAndDispose(timeoutMs)),
    )
    const runReports: RunDrainReport[] = []
    for (const outcome of runOutcomes) {
      if (outcome.status === 'fulfilled') {
        runReports.push(outcome.value)
      } else {
        errors.push(`run-dispose: ${outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason)}`)
      }
    }
    this.runs.clear()

    let oobClosed = false
    const broker = this.canaryBrokerInstance
    const relay = this.oobRelayInstance
    this.canaryBrokerInstance = null
    this.oobRelayInstance = null
    if (broker || relay) {
      const oobTasks: Array<Promise<unknown>> = []
      if (broker) {
        oobTasks.push(Promise.resolve().then(() => broker.stop()))
        oobTasks.push(Promise.resolve().then(() => broker.closeOob()))
      } else if (relay) {
        oobTasks.push(Promise.resolve().then(() => relay.close()))
      }
      const oobOutcomes = await Promise.allSettled(oobTasks)
      for (const outcome of oobOutcomes) {
        if (outcome.status === 'rejected') {
          errors.push(`oob-close: ${outcome.reason instanceof Error ? outcome.reason.message : String(outcome.reason)}`)
        }
      }
      oobClosed = true
    }

    let maintenanceStopped = false
    const maint = this.maintenanceInstance
    this.maintenanceInstance = null
    if (maint) {
      try {
        maint.stop()
        maintenanceStopped = true
      } catch (err) {
        errors.push(`maintenance-stop: ${err instanceof Error ? err.message : String(err)}`)
      }
    }

    let storeClosed = false
    const st = this.storeInstance
    this.storeInstance = null
    if (st) {
      try {
        st.close()
        storeClosed = true
      } catch (err) {
        errors.push(`store-close: ${err instanceof Error ? err.message : String(err)}`)
      }
    }

    this.disposed = true
    const registry = getAppRuntimeRegistry()
    if (registry.get(this.dataDir) === this) {
      registry.delete(this.dataDir)
    }

    return {
      dataDir: this.dataDir,
      runsDisposed: runReports.length,
      runReports,
      oobClosed,
      maintenanceStopped,
      storeClosed,
      errors,
      alreadyDisposed: false,
    }
  }

  private assertNotDisposed(): void {
    if (this.disposed) {
      throw new Error('AppRuntime has been disposed.')
    }
  }
}

/**
 * Obtain the single shared `AppRuntime` composition root for `dataDir` (defaults to `dataDirectory()`).
 * Uses one process-wide registry (`Symbol.for('kovo.appRuntime')`) so Vite SSR (`src/server.ts`)
 * and Node ESM (`scripts/serve.ts`) share identical `AppRuntime`, `Store`, and `GlobalKillSwitch`.
 */
export function getAppRuntime(options: AppRuntimeOptions = {}): AppRuntime {
  const dir = resolve(options.dataDir ?? dataDirectory())
  const registry = getAppRuntimeRegistry()
  const existing = registry.get(dir)
  if (existing && !existing.isDisposed) {
    if (options.store && !existing.hasStore()) {
      existing.attachStore(options.store)
    }
    if (options.canaryBroker && !existing.hasCanaryBroker()) {
      existing.attachCanaryBroker(options.canaryBroker)
    } else if (options.oobRelay && !existing.hasOobRelay()) {
      existing.attachOobRelay(options.oobRelay)
    }
    const ksOpts: KillSwitchOptions = {
      ...(options.killSwitchOptions ?? {}),
      ...(options.killSwitchFilePath !== undefined ? { filePath: options.killSwitchFilePath } : {}),
    }
    if (Object.keys(ksOpts).length > 0) {
      existing.killSwitch.configure(ksOpts)
    }
    return existing
  }
  const created = new AppRuntime({
    ...options,
    dataDir: dir,
    killSwitch: options.killSwitch ?? globalKillSwitch,
    useSharedStoreRegistry: options.useSharedStoreRegistry ?? true,
  })
  registry.set(dir, created)
  return created
}

/**
 * Create a standalone, isolated `AppRuntime` instance (for tests, DI harnesses, or scoped workloads).
 * Does not register into or mutate the process-wide `getAppRuntime()` singleton.
 */
export function createAppRuntime(options: AppRuntimeOptions = {}): AppRuntime {
  return new AppRuntime({
    ...options,
    useSharedStoreRegistry: options.useSharedStoreRegistry ?? false,
  })
}

/** Dispose all registered process-wide `AppRuntime` instances (useful for graceful shutdown & tests). */
export async function disposeAllAppRuntimes(options?: { timeoutMs?: number }): Promise<AppRuntimeDisposeReport[]> {
  const registry = getAppRuntimeRegistry()
  const runtimes = [...registry.values()]
  const outcomes = await Promise.allSettled(runtimes.map(rt => rt.dispose(options)))
  return outcomes
    .filter((o): o is PromiseFulfilledResult<AppRuntimeDisposeReport> => o.status === 'fulfilled')
    .map(o => o.value)
}

/** Thin backward-compatible delegate returning the active `AppRuntime`'s `Store`. */
export function store(): Store {
  return getAppRuntime().store
}

export {
  assertValidRunId,
  configureGlobalKillSwitch,
  GlobalKillSwitch,
  globalKillSwitch,
  InvalidRunIdError,
  KillSwitchTrippedError,
  RunContext,
  StorageMaintenanceController,
  Store,
}
export type { KillSwitchOptions, KillSwitchState, RunContextOptions, RunDrainReport, StorageMaintenanceOptions }
