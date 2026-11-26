/**
 * Exhaustive, browser-safe chain-step status specification (`R2-07`).
 *
 * Single source of truth for every `ChainStepStatus` across:
 * - Store readiness & dependent taint/blocking (`store-runs.ts` `refreshReadyChainSteps`)
 * - Dispatch funnel & deferral gating (`exec-dispatch.ts` `permanentlyBlockedStepIds`, `dispatchableReadySteps`)
 * - Planner retry & continuation handling (`exec-recon-planner.ts`)
 * - Orphaned-worker reconciliation (`run-actor.ts`)
 * - Snapshot dry-streak accounting (`run-snapshot.ts`)
 * - Browser/report UI badges & glyphs (zero Node/server imports)
 */

export type ChainStepStatus =
  | 'pending'
  | 'ready'
  | 'running'
  | 'complete'
  | 'blocked'
  | 'tainted'
  | 'canceled'
  | 'infra_failed'
  | 'turn_capped'
  | 'nudged_out'
  | 'rotated_partial'
  | 'model_failure'

export interface StepStatusMeta {
  /** Step has finished executing and will not run again. */
  readonly terminal: boolean
  /** Step is eligible for bounded single-retry requeue (`maybeRequeueRetryableStep`). */
  readonly retryable: boolean
  /** Step produced partial or complete state an explicit continuation/retry step may build on. */
  readonly continuable: boolean
  /** Step satisfies normal downstream `dependsOnStepIds` prerequisites. */
  readonly satisfiesDependency: boolean
  /**
   * Step unconditionally taints downstream pending dependents once reached.
   * Terminal non-satisfying statuses with `killsDependents: false` (`turn_capped`, `nudged_out`,
   * `rotated_partial`) still block any pending dependent that has not been re-pointed to an
   * active retry step (see {@link stepBlocksDependent}).
   */
  readonly killsDependents: boolean
  /** Step terminated without completing its planned verification work. */
  readonly lostWork: boolean
  /** Compact status glyph key for UI/report rendering. */
  readonly glyph: string
}

export const STEP_STATUS = {
  pending: {
    terminal: false,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: false,
    lostWork: false,
    glyph: 'pending',
  },
  ready: {
    terminal: false,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: false,
    lostWork: false,
    glyph: 'ready',
  },
  running: {
    terminal: false,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: false,
    lostWork: false,
    glyph: 'running',
  },
  complete: {
    terminal: true,
    retryable: false,
    continuable: true,
    satisfiesDependency: true,
    killsDependents: false,
    lostWork: false,
    glyph: 'complete',
  },
  blocked: {
    terminal: true,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: true,
    lostWork: true,
    glyph: 'blocked',
  },
  tainted: {
    terminal: true,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: true,
    lostWork: true,
    glyph: 'tainted',
  },
  canceled: {
    terminal: true,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: true,
    lostWork: true,
    glyph: 'canceled',
  },
  infra_failed: {
    terminal: true,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: true,
    lostWork: true,
    glyph: 'infra_failed',
  },
  turn_capped: {
    terminal: true,
    retryable: true,
    continuable: true,
    satisfiesDependency: false,
    killsDependents: false,
    lostWork: true,
    glyph: 'turn_capped',
  },
  nudged_out: {
    terminal: true,
    retryable: true,
    continuable: true,
    satisfiesDependency: false,
    killsDependents: false,
    lostWork: true,
    glyph: 'nudged_out',
  },
  rotated_partial: {
    terminal: true,
    retryable: false,
    continuable: true,
    satisfiesDependency: false,
    killsDependents: false,
    lostWork: true,
    glyph: 'rotated_partial',
  },
  model_failure: {
    terminal: true,
    retryable: false,
    continuable: false,
    satisfiesDependency: false,
    killsDependents: true,
    lostWork: true,
    glyph: 'model_failure',
  },
} as const satisfies Record<ChainStepStatus, StepStatusMeta>

export type ChainStepActiveStatus = {
  [K in ChainStepStatus]: typeof STEP_STATUS[K]['terminal'] extends false ? K : never
}[ChainStepStatus]

export type ChainStepTerminalStatus = {
  [K in ChainStepStatus]: typeof STEP_STATUS[K]['terminal'] extends true ? K : never
}[ChainStepStatus]

export type ChainStepRetryableStatus = {
  [K in ChainStepStatus]: typeof STEP_STATUS[K]['retryable'] extends true ? K : never
}[ChainStepStatus]

export type ChainStepContinuableStatus = {
  [K in ChainStepStatus]: typeof STEP_STATUS[K]['continuable'] extends true ? K : never
}[ChainStepStatus]

export type ChainStepLostWorkStatus = {
  [K in ChainStepStatus]: typeof STEP_STATUS[K]['lostWork'] extends true ? K : never
}[ChainStepStatus]

export const chainStepStatuses = Object.keys(STEP_STATUS) as readonly ChainStepStatus[]
export const chainStepActiveStatuses = chainStepStatuses.filter(
  (status): status is ChainStepActiveStatus => !STEP_STATUS[status].terminal,
)
export const chainStepTerminalStatuses = chainStepStatuses.filter(
  (status): status is ChainStepTerminalStatus => STEP_STATUS[status].terminal,
)
export const chainStepRetryableStatuses = chainStepStatuses.filter(
  (status): status is ChainStepRetryableStatus => STEP_STATUS[status].retryable,
)
export const chainStepContinuableStatuses = chainStepStatuses.filter(
  (status): status is ChainStepContinuableStatus => STEP_STATUS[status].continuable,
)
export const chainStepLostWorkStatuses = chainStepStatuses.filter(
  (status): status is ChainStepLostWorkStatus => STEP_STATUS[status].lostWork,
)

export function getStepStatusMeta(status: string | null | undefined): StepStatusMeta | undefined {
  if (!status) return undefined
  return (STEP_STATUS as Record<string, StepStatusMeta>)[status]
}

export function isTerminalStepStatus(status: string | null | undefined): status is ChainStepTerminalStatus {
  return getStepStatusMeta(status)?.terminal === true
}

export function isRetryableStepStatus(status: string | null | undefined): status is ChainStepRetryableStatus {
  return getStepStatusMeta(status)?.retryable === true
}

export function isContinuableStepStatus(status: string | null | undefined): status is ChainStepContinuableStatus {
  return getStepStatusMeta(status)?.continuable === true
}

export function stepSatisfiesDependency(status: string | null | undefined): boolean {
  return getStepStatusMeta(status)?.satisfiesDependency === true
}

export function stepKillsDependents(status: string | null | undefined): boolean {
  return getStepStatusMeta(status)?.killsDependents === true
}

export function isLostWorkStepStatus(status: string | null | undefined): status is ChainStepLostWorkStatus {
  return getStepStatusMeta(status)?.lostWork === true
}

/**
 * True when a parent step is terminal and does NOT satisfy downstream `dependsOnStepIds`.
 * Any pending child still depending on such a parent (i.e. not re-pointed to an active retry)
 * can never be promoted to `ready` and must be treated as permanently blocked / lost work.
 */
export function stepBlocksDependent(status: string | null | undefined): boolean {
  const meta = getStepStatusMeta(status)
  return Boolean(meta && meta.terminal && !meta.satisfiesDependency)
}
