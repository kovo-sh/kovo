/**
 * Canonical Run-Status Classification & Predicates (`src/server/run-status.ts`).
 *
 * Single source of truth for classifying `RunStatus` values from `src/domain.ts` so storage,
 * retention, maintenance, deletion, UI, and static drift audits never disagree on:
 *  - `'complete'` vs legacy `'completed'`
 *  - strictly actively executing (`'running'`) vs resumable non-terminal (`'paused'`,
 *    `'budget_paused'`, `'waiting'`, legacy `'queued'`)
 *  - strictly terminal (`'complete'`, `'stopped'`, `'failed'` + legacy aliases)
 */
import type { RunStatus } from '../domain.ts'

/** Canonical terminal `RunStatus` values in `src/domain.ts`. */
export type TerminalRunStatus = 'complete' | 'stopped' | 'failed'

/** Legacy terminal spelling aliases tolerated by read/retention helpers. */
export type LegacyTerminalRunStatusAlias = 'completed' | 'cancelled' | 'canceled'

/** Canonical status representing a run with actively executing workers / live bind-mounts. */
export type ActivelyExecutingRunStatus = 'running'

/** Canonical non-terminal statuses that are not actively executing and can resume/proceed. */
export type CanonicalResumableNonTerminalRunStatus = 'waiting' | 'paused' | 'budget_paused'

/** Legacy non-terminal queued spelling alias tolerated by classification helpers. */
export type LegacyResumableNonTerminalRunStatusAlias = 'queued'

/** Resumable non-terminal run statuses (canonical + legacy `'queued'`). */
export type ResumableNonTerminalRunStatus =
  | LegacyResumableNonTerminalRunStatusAlias
  | CanonicalResumableNonTerminalRunStatus

/** Exhaustive lifecycle category assigned to every canonical `RunStatus`. */
export type RunStatusCategory =
  | 'terminal'
  | 'actively_executing'
  | 'resumable_non_terminal'

/**
 * Canonical terminal `RunStatus` values (`'complete' | 'stopped' | 'failed'`).
 * Legacy spelling aliases (`'completed'`, `'cancelled'`, `'canceled'`) live in
 * `LEGACY_TERMINAL_RUN_STATUS_ALIASES` and are accepted by `isTerminalRunStatus()`.
 */
export const TERMINAL_RUN_STATUSES = [
  'complete',
  'stopped',
  'failed',
] as const satisfies readonly TerminalRunStatus[]

/** Legacy terminal aliases accepted by `isTerminalRunStatus()` for backward compatibility. */
export const LEGACY_TERMINAL_RUN_STATUS_ALIASES = [
  'completed',
  'cancelled',
  'canceled',
] as const satisfies readonly LegacyTerminalRunStatusAlias[]

/**
 * Strictly runs with live executing workers / bind-mounts (`'running'`).
 * Paused, budget-paused, waiting, and queued runs are non-terminal but NOT actively executing.
 */
export const ACTIVELY_EXECUTING_RUN_STATUSES = [
  'running',
] as const satisfies readonly ActivelyExecutingRunStatus[]

/** Non-terminal statuses that are paused/waiting/queued (resumable, no active worker loop). */
export const RESUMABLE_NON_TERMINAL_RUN_STATUSES = [
  'queued',
  'waiting',
  'paused',
  'budget_paused',
] as const satisfies readonly ResumableNonTerminalRunStatus[]

/** Canonical subset of `RESUMABLE_NON_TERMINAL_RUN_STATUSES` defined in `RunStatus`. */
export const CANONICAL_RESUMABLE_NON_TERMINAL_RUN_STATUSES = [
  'waiting',
  'paused',
  'budget_paused',
] as const satisfies readonly CanonicalResumableNonTerminalRunStatus[]

/** Every canonical `RunStatus` value defined by `src/domain.ts`, in lifecycle order. */
export const RUN_STATUSES = [
  'waiting',
  'running',
  'paused',
  'budget_paused',
  'stopped',
  'failed',
  'complete',
] as const satisfies readonly RunStatus[]

// ---------------------------------------------------------------------------
// Compile-time exhaustiveness & partition proofs over `RunStatus`
// ---------------------------------------------------------------------------

type AssertExact<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never
type AssertDisjoint<A, B> = [A & B] extends [never] ? true : never

type ClassifiedCanonicalUnion =
  | TerminalRunStatus
  | ActivelyExecutingRunStatus
  | CanonicalResumableNonTerminalRunStatus

/** Fails `tsc` if any `RunStatus` member is added to `src/domain.ts` without classification. */
const _assertRunStatusUnionExhaustive: AssertExact<ClassifiedCanonicalUnion, RunStatus> = true
const _assertRunStatusesArrayExhaustive: AssertExact<typeof RUN_STATUSES[number], RunStatus> = true
const _assertTerminalActiveDisjoint: AssertDisjoint<TerminalRunStatus, ActivelyExecutingRunStatus> = true
const _assertTerminalResumableDisjoint: AssertDisjoint<TerminalRunStatus, CanonicalResumableNonTerminalRunStatus> = true
const _assertActiveResumableDisjoint: AssertDisjoint<ActivelyExecutingRunStatus, CanonicalResumableNonTerminalRunStatus> = true
void _assertRunStatusUnionExhaustive
void _assertRunStatusesArrayExhaustive
void _assertTerminalActiveDisjoint
void _assertTerminalResumableDisjoint
void _assertActiveResumableDisjoint

/**
 * Exhaustive compile-time classification map over every `RunStatus`.
 * Adding a new member to `RunStatus` in `src/domain.ts` forces an explicit entry here.
 */
export const RUN_STATUS_CLASSIFICATION: Readonly<Record<RunStatus, RunStatusCategory>> = {
  waiting: 'resumable_non_terminal',
  running: 'actively_executing',
  paused: 'resumable_non_terminal',
  budget_paused: 'resumable_non_terminal',
  stopped: 'terminal',
  failed: 'terminal',
  complete: 'terminal',
}

/** Exhaustive classifier over canonical `RunStatus` values (compile-time checked via `never`). */
export function classifyRunStatus(status: RunStatus): RunStatusCategory {
  switch (status) {
    case 'complete':
    case 'stopped':
    case 'failed':
      return 'terminal'
    case 'running':
      return 'actively_executing'
    case 'waiting':
    case 'paused':
    case 'budget_paused':
      return 'resumable_non_terminal'
    default: {
      const _exhaustive: never = status
      return _exhaustive
    }
  }
}

// ---------------------------------------------------------------------------
// Runtime O(1) lookup sets & predicates
// ---------------------------------------------------------------------------

const CANONICAL_RUN_STATUS_SET: ReadonlySet<string> = new Set<string>(RUN_STATUSES)

const TERMINAL_RUN_STATUS_SET: ReadonlySet<string> = new Set<string>([
  ...TERMINAL_RUN_STATUSES,
  ...LEGACY_TERMINAL_RUN_STATUS_ALIASES,
])

const ACTIVELY_EXECUTING_RUN_STATUS_SET: ReadonlySet<string> = new Set<string>(
  ACTIVELY_EXECUTING_RUN_STATUSES,
)

const RESUMABLE_NON_TERMINAL_RUN_STATUS_SET: ReadonlySet<string> = new Set<string>(
  RESUMABLE_NON_TERMINAL_RUN_STATUSES,
)

const NON_TERMINAL_RUN_STATUS_SET: ReadonlySet<string> = new Set<string>([
  ...ACTIVELY_EXECUTING_RUN_STATUSES,
  ...RESUMABLE_NON_TERMINAL_RUN_STATUSES,
])

function normalizeStatus(status: string | null | undefined): string | null {
  if (typeof status !== 'string') return null
  const normalized = status.trim().toLowerCase()
  return normalized.length > 0 ? normalized : null
}

/** True when `status` is an exact canonical `RunStatus` value from `src/domain.ts`. */
export function isCanonicalRunStatus(status: string | null | undefined): status is RunStatus {
  return typeof status === 'string' && CANONICAL_RUN_STATUS_SET.has(status)
}

/**
 * True strictly for terminal run statuses (`'complete'`, `'stopped'`, `'failed'`) plus legacy
 * terminal aliases (`'completed'`, `'cancelled'`, `'canceled'`).
 * Fail-closed (`false`) for `null`, `undefined`, empty, or unrecognized strings.
 */
export function isTerminalRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && TERMINAL_RUN_STATUS_SET.has(normalized)
}

/**
 * True strictly for actively executing runs (`'running'`) with live workers / bind-mounts.
 * Returns `false` for `'paused'`, `'budget_paused'`, `'waiting'`, `'queued'`, terminal statuses,
 * and unrecognized values.
 */
export function isActivelyExecutingRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && ACTIVELY_EXECUTING_RUN_STATUS_SET.has(normalized)
}

/**
 * True for resumable non-terminal run statuses (`'queued'`, `'waiting'`, `'paused'`, `'budget_paused'`).
 */
export function isResumableNonTerminalRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && RESUMABLE_NON_TERMINAL_RUN_STATUS_SET.has(normalized)
}

/**
 * True for every non-terminal run status — both actively executing (`'running'`) and
 * resumable non-terminal (`'queued'`, `'waiting'`, `'paused'`, `'budget_paused'`).
 * Disjoint from `isTerminalRunStatus()` and collectively exhaustive over all `RUN_STATUSES`.
 */
export function isNonTerminalRunStatus(status: string | null | undefined): boolean {
  const normalized = normalizeStatus(status)
  return normalized !== null && NON_TERMINAL_RUN_STATUS_SET.has(normalized)
}
