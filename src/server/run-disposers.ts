/**
 * Process-wide registry of per-run in-memory state disposers (R2-08).
 *
 * Any module under `src/server/**` that maintains module-level state keyed by
 * `runId` / `assignmentId` / `persona` registers its synchronous disposer here
 * at module load time. `Execution.cleanupRunState(runId)` drains every
 * registered disposer deterministically when a run finishes, cancels, or is
 * disposed — preventing silent memory growth and cross-run state bleed.
 */

export type RunDisposerFn = (runId: string) => void

export interface RunDisposerDrainResult {
  readonly runId: string
  readonly invoked: number
  readonly errors: ReadonlyArray<{ name: string; error: string }>
}

const runDisposers = new Map<string, RunDisposerFn>()

/**
 * Register (or replace by name) a synchronous per-run disposer invoked during
 * `Execution.cleanupRunState(runId)`. Returns an idempotent unregister handle.
 */
export function registerRunDisposer(name: string, fn: RunDisposerFn): () => void {
  const key = name.trim()
  if (!key) throw new Error('registerRunDisposer requires a non-empty disposer name.')
  runDisposers.set(key, fn)
  return () => {
    if (runDisposers.get(key) === fn) {
      runDisposers.delete(key)
    }
  }
}

/**
 * Drain every registered per-run disposer for `runId`.
 * Each disposer runs in isolation so a single throw never skips later disposers.
 */
export function runAllRunDisposers(runId: string): RunDisposerDrainResult {
  const normalized = typeof runId === 'string' ? runId.trim() : ''
  if (!normalized) {
    return { runId: '', invoked: 0, errors: [] }
  }
  let invoked = 0
  const errors: Array<{ name: string; error: string }> = []
  for (const [name, fn] of [...runDisposers.entries()]) {
    invoked += 1
    try {
      fn(normalized)
    } catch (err) {
      errors.push({
        name,
        error: err instanceof Error ? err.message : String(err),
      })
    }
  }
  return { runId: normalized, invoked, errors }
}
