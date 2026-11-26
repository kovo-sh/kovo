/**
 * Unified Run-Scale Safety Budgets (Systemic Stream B).
 *
 * Centralizes every finite DoS / OOM ceiling for multi-hop capability custody and
 * composite proof verification in a single typed policy module so runtime components
 * (`derived-custody.ts`, `verify-rpc.ts`, and callers) never drift onto hardcoded
 * micro-caps while still enforcing strict finite memory/CPU bounds.
 */

export const RUN_SAFETY_BUDGET_DEFAULTS = {
  maxCompositeVerifiesPerRun: 1_024,
  maxSealsPerRun: 4_096,
  maxSealsPerEndpoint: 256,
  maxVaultEntries: 4_096,
  maxSealAttempts: 8_192,
  /** R4-H-19: per-run active redaction registry capacity (lifecycle-aware; scales with run workload). */
  maxRedactedSecretsPerRun: 5_000,
  /** R4-H-11 (WS-10): per-origin quarantine thresholds replacing the global 240-row hair-trigger. */
  originQuarantineMin52xCount: 3,
  originQuarantineMin401Count: 3,
  originQuarantineMinDistinctPaths: 2,
  originQuarantineWindowMs: 300_000,
  /** R4-H-15 (WS-11): per-call host `search_repo` wall-clock deadline and byte budget. */
  searchRepoDeadlineMs: 2_500,
  searchRepoMaxBytes: 8 * 1024 * 1024,
  /** R4-H-20 (WS-14): OOB callback retention & ingest quotas. */
  oobMaxCallbacksPerToken: 64,
  oobMaxCallbacksPerRun: 2_048,
  oobMaxProtectedCallbacks: 1_024,
  oobMaxCallbacksPerIpWindow: 120,
  /** R3-07: Centralized assignment claim lease & orphan-reaper budgets. */
  assignmentLeaseMs: 10 * 60_000,
  investigationLeaseMs: 30 * 60_000,
  patchRetestLeaseMs: 15 * 60_000,
  assignmentReaperGraceMs: 5_000,
} as const

/** Hard finite OOM ceilings that neither run-scaling nor env/caller overrides may exceed. */
export const RUN_SAFETY_BUDGET_HARD_CEILINGS = {
  maxCompositeVerifiesPerRun: 10_000,
  maxSealsPerRun: 16_384,
  maxSealsPerEndpoint: 4_096,
  maxVaultEntries: 10_000,
  maxSealAttempts: 100_000,
  maxRedactedSecretsPerRun: 50_000,
  originQuarantineMin52xCount: 32,
  originQuarantineMin401Count: 32,
  originQuarantineMinDistinctPaths: 16,
  originQuarantineWindowMs: 3_600_000,
  searchRepoDeadlineMs: 15_000,
  searchRepoMaxBytes: 32 * 1024 * 1024,
  oobMaxCallbacksPerToken: 512,
  oobMaxCallbacksPerRun: 16_384,
  oobMaxProtectedCallbacks: 8_192,
  oobMaxCallbacksPerIpWindow: 2_048,
  assignmentLeaseMs: 60 * 60_000,
  investigationLeaseMs: 120 * 60_000,
  patchRetestLeaseMs: 60 * 60_000,
  assignmentReaperGraceMs: 5 * 60_000,
} as const

export const RUN_SAFETY_BUDGET_ENV_KEYS = {
  maxCompositeVerifiesPerRun: 'KOVO_MAX_COMPOSITE_VERIFIES_PER_RUN',
  maxSealsPerRun: 'KOVO_MAX_SEALS_PER_RUN',
  maxSealsPerEndpoint: 'KOVO_MAX_SEALS_PER_ENDPOINT',
  maxVaultEntries: 'KOVO_MAX_VAULT_ENTRIES',
  maxSealAttempts: 'KOVO_MAX_SEAL_ATTEMPTS',
  maxRedactedSecretsPerRun: 'KOVO_MAX_REDACTED_SECRETS_PER_RUN',
  originQuarantineMin52xCount: 'KOVO_ORIGIN_QUARANTINE_MIN_52X_COUNT',
  originQuarantineMin401Count: 'KOVO_ORIGIN_QUARANTINE_MIN_401_COUNT',
  originQuarantineMinDistinctPaths: 'KOVO_ORIGIN_QUARANTINE_MIN_DISTINCT_PATHS',
  originQuarantineWindowMs: 'KOVO_ORIGIN_QUARANTINE_WINDOW_MS',
  searchRepoDeadlineMs: 'KOVO_SEARCH_REPO_DEADLINE_MS',
  searchRepoMaxBytes: 'KOVO_SEARCH_REPO_MAX_BYTES',
  oobMaxCallbacksPerToken: 'KOVO_OOB_MAX_CALLBACKS_PER_TOKEN',
  oobMaxCallbacksPerRun: 'KOVO_OOB_MAX_CALLBACKS_PER_RUN',
  oobMaxProtectedCallbacks: 'KOVO_OOB_MAX_PROTECTED_CALLBACKS',
  oobMaxCallbacksPerIpWindow: 'KOVO_OOB_MAX_CALLBACKS_PER_IP_WINDOW',
  assignmentLeaseMs: 'KOVO_ASSIGNMENT_LEASE_MS',
  investigationLeaseMs: 'KOVO_INVESTIGATION_LEASE_MS',
  patchRetestLeaseMs: 'KOVO_PATCH_RETEST_LEASE_MS',
  assignmentReaperGraceMs: 'KOVO_ASSIGNMENT_REAPER_GRACE_MS',
} as const

export const DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN = RUN_SAFETY_BUDGET_DEFAULTS.maxCompositeVerifiesPerRun
export const DEFAULT_MAX_SEALS_PER_RUN = RUN_SAFETY_BUDGET_DEFAULTS.maxSealsPerRun
export const DEFAULT_MAX_SEALS_PER_ENDPOINT = RUN_SAFETY_BUDGET_DEFAULTS.maxSealsPerEndpoint
export const DEFAULT_MAX_VAULT_ENTRIES = RUN_SAFETY_BUDGET_DEFAULTS.maxVaultEntries
export const DEFAULT_MAX_SEAL_ATTEMPTS = RUN_SAFETY_BUDGET_DEFAULTS.maxSealAttempts

export const HARD_MAX_COMPOSITE_VERIFIES_PER_RUN = RUN_SAFETY_BUDGET_HARD_CEILINGS.maxCompositeVerifiesPerRun
export const HARD_MAX_SEALS_PER_RUN = RUN_SAFETY_BUDGET_HARD_CEILINGS.maxSealsPerRun
export const HARD_MAX_SEALS_PER_ENDPOINT = RUN_SAFETY_BUDGET_HARD_CEILINGS.maxSealsPerEndpoint
export const HARD_MAX_VAULT_ENTRIES = RUN_SAFETY_BUDGET_HARD_CEILINGS.maxVaultEntries
export const HARD_MAX_SEAL_ATTEMPTS = RUN_SAFETY_BUDGET_HARD_CEILINGS.maxSealAttempts

export interface RunSafetyBudgets {
  readonly maxCompositeVerifiesPerRun: number
  readonly maxSealsPerRun: number
  readonly maxSealsPerEndpoint: number
  readonly maxVaultEntries: number
  readonly maxSealAttempts: number
  readonly maxRedactedSecretsPerRun: number
  readonly originQuarantineMin52xCount: number
  readonly originQuarantineMin401Count: number
  readonly originQuarantineMinDistinctPaths: number
  readonly originQuarantineWindowMs: number
  readonly searchRepoDeadlineMs: number
  readonly searchRepoMaxBytes: number
  readonly oobMaxCallbacksPerToken: number
  readonly oobMaxCallbacksPerRun: number
  readonly oobMaxProtectedCallbacks: number
  readonly oobMaxCallbacksPerIpWindow: number
  readonly assignmentLeaseMs: number
  readonly investigationLeaseMs: number
  readonly patchRetestLeaseMs: number
  readonly assignmentReaperGraceMs: number
}

export interface RunSafetyBudgetOverrides {
  maxCompositeVerifiesPerRun?: number
  maxSealsPerRun?: number
  maxSealsPerEndpoint?: number
  maxVaultEntries?: number
  maxSealAttempts?: number
  maxRedactedSecretsPerRun?: number
  originQuarantineMin52xCount?: number
  originQuarantineMin401Count?: number
  originQuarantineMinDistinctPaths?: number
  originQuarantineWindowMs?: number
  searchRepoDeadlineMs?: number
  searchRepoMaxBytes?: number
  oobMaxCallbacksPerToken?: number
  oobMaxCallbacksPerRun?: number
  oobMaxProtectedCallbacks?: number
  oobMaxCallbacksPerIpWindow?: number
  assignmentLeaseMs?: number
  investigationLeaseMs?: number
  patchRetestLeaseMs?: number
  assignmentReaperGraceMs?: number
}

export interface RunSafetyBudgetOptions {
  /** Planned/configured assignment count for the run; scales above defaults for large runs while bounded by hard OOM ceilings. */
  maxAssignments?: number
  /** Whether dual-replay verification is active (default true; accounts for 2x fresh replay attempts per assignment). */
  dualReplay?: boolean
  /** Environment map to read `KOVO_MAX_*` overrides from (defaults to `process.env`). */
  env?: Readonly<Record<string, string | undefined>>
  /** Explicit caller overrides (take precedence over env vars, still strictly clamped to `[1, hardCeiling]`). */
  overrides?: RunSafetyBudgetOverrides
}

const POSITIVE_INT_RE = /^\d+$/

function clampBoundedInt(value: number, hardMax: number): number {
  const safeMax = Math.max(1, Math.floor(hardMax))
  return Math.max(1, Math.min(safeMax, Math.floor(value)))
}

/** Parse a positive integer env override (`KOVO_MAX_*`), ignoring empty, malformed, zero, or non-finite values. */
export function parseBoundedBudgetEnv(
  envKey: string,
  env: Readonly<Record<string, string | undefined>> = process.env,
): number | undefined {
  const raw = env[envKey]?.trim()
  if (!raw || !POSITIVE_INT_RE.test(raw)) return undefined
  const parsed = Number(raw)
  return Number.isSafeInteger(parsed) && parsed >= 1 ? parsed : undefined
}

/**
 * Resolve a single finite budget cap with precedence:
 *   explicit override > positive integer env var > fallback default
 * always strictly clamped to `[1, hardMax]`.
 */
export function resolveBoundedBudgetCap(
  explicit: number | undefined,
  envKey: string,
  fallback: number,
  hardMax: number,
  env: Readonly<Record<string, string | undefined>> = process.env,
): number {
  if (explicit !== undefined && Number.isFinite(explicit)) {
    return clampBoundedInt(explicit, hardMax)
  }
  const fromEnv = parseBoundedBudgetEnv(envKey, env)
  if (fromEnv !== undefined) {
    return clampBoundedInt(fromEnv, hardMax)
  }
  return clampBoundedInt(fallback, hardMax)
}

function resolveAssignmentLeaseBudgets(
  overrides: RunSafetyBudgetOverrides,
  env: Readonly<Record<string, string | undefined>>,
): Pick<RunSafetyBudgets, 'assignmentLeaseMs' | 'investigationLeaseMs' | 'patchRetestLeaseMs' | 'assignmentReaperGraceMs'> {
  return {
    assignmentLeaseMs: resolveBoundedBudgetCap(
      overrides.assignmentLeaseMs,
      RUN_SAFETY_BUDGET_ENV_KEYS.assignmentLeaseMs,
      RUN_SAFETY_BUDGET_DEFAULTS.assignmentLeaseMs,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.assignmentLeaseMs,
      env,
    ),
    investigationLeaseMs: resolveBoundedBudgetCap(
      overrides.investigationLeaseMs,
      RUN_SAFETY_BUDGET_ENV_KEYS.investigationLeaseMs,
      RUN_SAFETY_BUDGET_DEFAULTS.investigationLeaseMs,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.investigationLeaseMs,
      env,
    ),
    patchRetestLeaseMs: resolveBoundedBudgetCap(
      overrides.patchRetestLeaseMs,
      RUN_SAFETY_BUDGET_ENV_KEYS.patchRetestLeaseMs,
      RUN_SAFETY_BUDGET_DEFAULTS.patchRetestLeaseMs,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.patchRetestLeaseMs,
      env,
    ),
    assignmentReaperGraceMs: resolveBoundedBudgetCap(
      overrides.assignmentReaperGraceMs,
      RUN_SAFETY_BUDGET_ENV_KEYS.assignmentReaperGraceMs,
      RUN_SAFETY_BUDGET_DEFAULTS.assignmentReaperGraceMs,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.assignmentReaperGraceMs,
      env,
    ),
  }
}

/**
 * Compute unified run-scaled DoS safety budgets bounded by strict finite OOM ceilings.
 *
 * Baseline defaults (`1024` composite verifies / `4096` seals / `256` per-endpoint seals /
 * `4096` vault entries / `8192` seal attempts) easily accommodate 50+ dual-replay 4-hop
 * chains without starvation and scale smoothly if a larger `maxAssignments` budget is passed,
 * while clamping unconditionally at `RUN_SAFETY_BUDGET_HARD_CEILINGS`.
 */
export function resolveRunSafetyBudgets(options: RunSafetyBudgetOptions = {}): RunSafetyBudgets {
  const env = options.env ?? process.env
  const overrides = options.overrides ?? {}
  const replayFactor = options.dualReplay === false ? 1 : 2
  const scaledAssignments =
    options.maxAssignments !== undefined && Number.isFinite(options.maxAssignments) && options.maxAssignments > 0
      ? Math.max(1, Math.floor(options.maxAssignments))
      : undefined

  const baseComposite = scaledAssignments !== undefined
    ? Math.max(DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN, scaledAssignments * replayFactor * 4)
    : DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN
  const baseSealsPerRun = scaledAssignments !== undefined
    ? Math.max(DEFAULT_MAX_SEALS_PER_RUN, scaledAssignments * replayFactor * 16)
    : DEFAULT_MAX_SEALS_PER_RUN
  const baseSealsPerEndpoint = scaledAssignments !== undefined
    ? Math.max(DEFAULT_MAX_SEALS_PER_ENDPOINT, scaledAssignments * replayFactor * 2)
    : DEFAULT_MAX_SEALS_PER_ENDPOINT
  const baseVaultEntries = Math.max(DEFAULT_MAX_VAULT_ENTRIES, baseSealsPerRun)
  const baseSealAttempts = Math.max(DEFAULT_MAX_SEAL_ATTEMPTS, baseSealsPerRun * 2)
  const baseRedactedSecrets = scaledAssignments !== undefined
    ? Math.max(RUN_SAFETY_BUDGET_DEFAULTS.maxRedactedSecretsPerRun, scaledAssignments * replayFactor * 32)
    : RUN_SAFETY_BUDGET_DEFAULTS.maxRedactedSecretsPerRun
  const baseOobCallbacksPerRun = scaledAssignments !== undefined
    ? Math.max(RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerRun, scaledAssignments * replayFactor * 8)
    : RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerRun
  const baseOobProtectedCallbacks = scaledAssignments !== undefined
    ? Math.max(RUN_SAFETY_BUDGET_DEFAULTS.oobMaxProtectedCallbacks, scaledAssignments * replayFactor * 4)
    : RUN_SAFETY_BUDGET_DEFAULTS.oobMaxProtectedCallbacks

  return {
    maxCompositeVerifiesPerRun: resolveBoundedBudgetCap(
      overrides.maxCompositeVerifiesPerRun,
      RUN_SAFETY_BUDGET_ENV_KEYS.maxCompositeVerifiesPerRun,
      baseComposite,
      HARD_MAX_COMPOSITE_VERIFIES_PER_RUN,
      env,
    ),
    maxSealsPerRun: resolveBoundedBudgetCap(
      overrides.maxSealsPerRun,
      RUN_SAFETY_BUDGET_ENV_KEYS.maxSealsPerRun,
      baseSealsPerRun,
      HARD_MAX_SEALS_PER_RUN,
      env,
    ),
    maxSealsPerEndpoint: resolveBoundedBudgetCap(
      overrides.maxSealsPerEndpoint,
      RUN_SAFETY_BUDGET_ENV_KEYS.maxSealsPerEndpoint,
      baseSealsPerEndpoint,
      HARD_MAX_SEALS_PER_ENDPOINT,
      env,
    ),
    maxVaultEntries: resolveBoundedBudgetCap(
      overrides.maxVaultEntries,
      RUN_SAFETY_BUDGET_ENV_KEYS.maxVaultEntries,
      baseVaultEntries,
      HARD_MAX_VAULT_ENTRIES,
      env,
    ),
    maxSealAttempts: resolveBoundedBudgetCap(
      overrides.maxSealAttempts,
      RUN_SAFETY_BUDGET_ENV_KEYS.maxSealAttempts,
      baseSealAttempts,
      HARD_MAX_SEAL_ATTEMPTS,
      env,
    ),
    maxRedactedSecretsPerRun: resolveBoundedBudgetCap(
      overrides.maxRedactedSecretsPerRun,
      RUN_SAFETY_BUDGET_ENV_KEYS.maxRedactedSecretsPerRun,
      baseRedactedSecrets,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.maxRedactedSecretsPerRun,
      env,
    ),
    originQuarantineMin52xCount: resolveBoundedBudgetCap(
      overrides.originQuarantineMin52xCount,
      RUN_SAFETY_BUDGET_ENV_KEYS.originQuarantineMin52xCount,
      RUN_SAFETY_BUDGET_DEFAULTS.originQuarantineMin52xCount,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.originQuarantineMin52xCount,
      env,
    ),
    originQuarantineMin401Count: resolveBoundedBudgetCap(
      overrides.originQuarantineMin401Count,
      RUN_SAFETY_BUDGET_ENV_KEYS.originQuarantineMin401Count,
      RUN_SAFETY_BUDGET_DEFAULTS.originQuarantineMin401Count,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.originQuarantineMin401Count,
      env,
    ),
    originQuarantineMinDistinctPaths: resolveBoundedBudgetCap(
      overrides.originQuarantineMinDistinctPaths,
      RUN_SAFETY_BUDGET_ENV_KEYS.originQuarantineMinDistinctPaths,
      RUN_SAFETY_BUDGET_DEFAULTS.originQuarantineMinDistinctPaths,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.originQuarantineMinDistinctPaths,
      env,
    ),
    originQuarantineWindowMs: resolveBoundedBudgetCap(
      overrides.originQuarantineWindowMs,
      RUN_SAFETY_BUDGET_ENV_KEYS.originQuarantineWindowMs,
      RUN_SAFETY_BUDGET_DEFAULTS.originQuarantineWindowMs,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.originQuarantineWindowMs,
      env,
    ),
    searchRepoDeadlineMs: resolveBoundedBudgetCap(
      overrides.searchRepoDeadlineMs,
      RUN_SAFETY_BUDGET_ENV_KEYS.searchRepoDeadlineMs,
      RUN_SAFETY_BUDGET_DEFAULTS.searchRepoDeadlineMs,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.searchRepoDeadlineMs,
      env,
    ),
    searchRepoMaxBytes: resolveBoundedBudgetCap(
      overrides.searchRepoMaxBytes,
      RUN_SAFETY_BUDGET_ENV_KEYS.searchRepoMaxBytes,
      RUN_SAFETY_BUDGET_DEFAULTS.searchRepoMaxBytes,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.searchRepoMaxBytes,
      env,
    ),
    oobMaxCallbacksPerToken: resolveBoundedBudgetCap(
      overrides.oobMaxCallbacksPerToken,
      RUN_SAFETY_BUDGET_ENV_KEYS.oobMaxCallbacksPerToken,
      RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerToken,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.oobMaxCallbacksPerToken,
      env,
    ),
    oobMaxCallbacksPerRun: resolveBoundedBudgetCap(
      overrides.oobMaxCallbacksPerRun,
      RUN_SAFETY_BUDGET_ENV_KEYS.oobMaxCallbacksPerRun,
      baseOobCallbacksPerRun,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.oobMaxCallbacksPerRun,
      env,
    ),
    oobMaxProtectedCallbacks: resolveBoundedBudgetCap(
      overrides.oobMaxProtectedCallbacks,
      RUN_SAFETY_BUDGET_ENV_KEYS.oobMaxProtectedCallbacks,
      baseOobProtectedCallbacks,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.oobMaxProtectedCallbacks,
      env,
    ),
    oobMaxCallbacksPerIpWindow: resolveBoundedBudgetCap(
      overrides.oobMaxCallbacksPerIpWindow,
      RUN_SAFETY_BUDGET_ENV_KEYS.oobMaxCallbacksPerIpWindow,
      RUN_SAFETY_BUDGET_DEFAULTS.oobMaxCallbacksPerIpWindow,
      RUN_SAFETY_BUDGET_HARD_CEILINGS.oobMaxCallbacksPerIpWindow,
      env,
    ),
    ...resolveAssignmentLeaseBudgets(overrides, env),
  }
}

export type AssignmentLeaseKind =
  | 'default'
  | 'code_audit'
  | 'investigation'
  | 'verification'
  | 'retest'
  | 'patch_retest'
  | 'resume_parked'

export interface ResolvedAssignmentLeaseBudget {
  readonly kind: AssignmentLeaseKind
  readonly leaseMs: number
  readonly hardMaxMs: number
  readonly clamped: boolean
  readonly requestedMs?: number
}

/**
 * Resolve a bounded assignment claim lease duration from `RunSafetyBudgets` (`R3-07`),
 * returning clamping telemetry whenever a caller or env override exceeds `[1, hardMaxMs]`.
 */
export function resolveAssignmentLeaseBudget(
  kind: AssignmentLeaseKind = 'default',
  options: {
    requestedMs?: number
    env?: Readonly<Record<string, string | undefined>>
  } = {},
): ResolvedAssignmentLeaseBudget {
  const env = options.env ?? process.env
  const key: 'investigationLeaseMs' | 'patchRetestLeaseMs' | 'assignmentLeaseMs' =
    kind === 'investigation'
      ? 'investigationLeaseMs'
      : kind === 'patch_retest'
        ? 'patchRetestLeaseMs'
        : 'assignmentLeaseMs'
  const fallback = RUN_SAFETY_BUDGET_DEFAULTS[key]
  const hardMaxMs = RUN_SAFETY_BUDGET_HARD_CEILINGS[key]
  const envKey = RUN_SAFETY_BUDGET_ENV_KEYS[key]
  const rawRequested =
    options.requestedMs !== undefined && Number.isFinite(options.requestedMs)
      ? Math.floor(options.requestedMs)
      : parseBoundedBudgetEnv(envKey, env)
  const leaseMs = resolveBoundedBudgetCap(options.requestedMs, envKey, fallback, hardMaxMs, env)
  const clamped = rawRequested !== undefined && rawRequested !== leaseMs
  return {
    kind,
    leaseMs,
    hardMaxMs,
    clamped,
    ...(rawRequested !== undefined ? { requestedMs: rawRequested } : {}),
  }
}

// ---------------------------------------------------------------------------
// R2-08: Fail-closed per-run async-poll safety budget policy & ledger
// ---------------------------------------------------------------------------

export const DEFAULT_MAX_ASYNC_POLL_CALLS_PER_RUN = 128
export const HARD_MAX_ASYNC_POLL_CALLS_PER_RUN = 2_048
export const DEFAULT_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN = 512
export const HARD_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN = 8_192

const DEFAULT_MAX_TRACKED_ASYNC_POLL_RUNS = 2_048
const HARD_MAX_TRACKED_ASYNC_POLL_RUNS = 16_384
const ASYNC_POLL_CALLS_ENV_KEY = 'KOVO_MAX_ASYNC_POLL_CALLS_PER_RUN'
const ASYNC_POLL_ATTEMPTS_ENV_KEY = 'KOVO_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN'
const ASYNC_POLL_TRACKED_RUNS_ENV_KEY = 'KOVO_MAX_TRACKED_ASYNC_POLL_RUNS'

export interface AsyncPollBudgetUsage {
  calls: number
  attempts: number
  deniedCalls: number
  deniedAttempts: number
}

export interface AsyncPollBudgetLedgerOptions {
  defaultMaxCallsPerRun?: number
  hardMaxCallsPerRun?: number
  defaultMaxAttemptsPerRun?: number
  hardMaxAttemptsPerRun?: number
  maxTrackedRuns?: number
  env?: Readonly<Record<string, string | undefined>>
}

/**
 * Fail-closed per-run async-poll safety budget ledger (`RunSafetyBudgets`).
 *
 * Security & memory invariants:
 *  - Requires an explicit non-empty `runId` (never silently folds missing ids into `'__default__'`).
 *  - Never FIFO-evicts an active run at the tracked-runs capacity cap; denies fail-closed and
 *    increments `capacityDenials` until run disposal (`registerRunDisposer`) removes completed runs.
 *  - Denies fail-closed and increments per-run denial counters (`deniedCalls` / `deniedAttempts`)
 *    whenever per-run call or attempt caps are reached; counters never silently reset.
 */
export class RunAsyncPollBudgetLedger {
  private readonly runs = new Map<string, AsyncPollBudgetUsage>()
  private capacityDenials = 0
  private readonly defaultMaxCallsPerRun: number
  private readonly hardMaxCallsPerRun: number
  private readonly defaultMaxAttemptsPerRun: number
  private readonly hardMaxAttemptsPerRun: number
  private readonly defaultMaxTrackedRuns?: number
  private readonly env?: Readonly<Record<string, string | undefined>>

  constructor(options: AsyncPollBudgetLedgerOptions = {}) {
    this.defaultMaxCallsPerRun = options.defaultMaxCallsPerRun ?? DEFAULT_MAX_ASYNC_POLL_CALLS_PER_RUN
    this.hardMaxCallsPerRun = options.hardMaxCallsPerRun ?? HARD_MAX_ASYNC_POLL_CALLS_PER_RUN
    this.defaultMaxAttemptsPerRun = options.defaultMaxAttemptsPerRun ?? DEFAULT_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN
    this.hardMaxAttemptsPerRun = options.hardMaxAttemptsPerRun ?? HARD_MAX_ASYNC_POLL_ATTEMPTS_PER_RUN
    this.defaultMaxTrackedRuns = options.maxTrackedRuns
    this.env = options.env
  }

  private requireRunId(runId: string): string {
    const key = typeof runId === 'string' ? runId.trim() : ''
    if (!key) {
      throw new Error('async.awaitResult safety budget requires an explicit non-empty runId.')
    }
    return key
  }

  private resolveMaxTrackedRuns(override?: number): number {
    return resolveBoundedBudgetCap(
      override ?? this.defaultMaxTrackedRuns,
      ASYNC_POLL_TRACKED_RUNS_ENV_KEY,
      DEFAULT_MAX_TRACKED_ASYNC_POLL_RUNS,
      HARD_MAX_TRACKED_ASYNC_POLL_RUNS,
      this.env,
    )
  }

  private getOrCreate(runId: string, maxTrackedRunsOverride?: number): AsyncPollBudgetUsage {
    const key = this.requireRunId(runId)
    let state = this.runs.get(key)
    if (!state) {
      const cap = this.resolveMaxTrackedRuns(maxTrackedRunsOverride)
      if (this.runs.size >= cap) {
        this.capacityDenials += 1
        throw new Error(
          `async.awaitResult tracked-run safety budget capacity reached (max ${cap} active runs; denials=${this.capacityDenials}).`,
        )
      }
      state = { calls: 0, attempts: 0, deniedCalls: 0, deniedAttempts: 0 }
      this.runs.set(key, state)
    }
    return state
  }

  consumeCall(runId: string, maxPerRun?: number, maxTrackedRuns?: number): number {
    const cap = resolveBoundedBudgetCap(
      maxPerRun,
      ASYNC_POLL_CALLS_ENV_KEY,
      this.defaultMaxCallsPerRun,
      this.hardMaxCallsPerRun,
      this.env,
    )
    const state = this.getOrCreate(runId, maxTrackedRuns)
    if (state.calls >= cap) {
      state.deniedCalls += 1
      throw new Error(`async.awaitResult run call budget exceeded (max ${cap} per run; denied=${state.deniedCalls}).`)
    }
    state.calls += 1
    return state.calls
  }

  consumeAttempt(runId: string, maxPerRun?: number, maxTrackedRuns?: number): number {
    const cap = resolveBoundedBudgetCap(
      maxPerRun,
      ASYNC_POLL_ATTEMPTS_ENV_KEY,
      this.defaultMaxAttemptsPerRun,
      this.hardMaxAttemptsPerRun,
      this.env,
    )
    const state = this.getOrCreate(runId, maxTrackedRuns)
    if (state.attempts >= cap) {
      state.deniedAttempts += 1
      throw new Error(`async.awaitResult run poll-attempt budget exceeded (max ${cap} per run; denied=${state.deniedAttempts}).`)
    }
    state.attempts += 1
    return state.attempts
  }

  getUsage(runId: string): AsyncPollBudgetUsage {
    const key = typeof runId === 'string' ? runId.trim() : ''
    if (!key) return { calls: 0, attempts: 0, deniedCalls: 0, deniedAttempts: 0 }
    const state = this.runs.get(key)
    return state ? { ...state } : { calls: 0, attempts: 0, deniedCalls: 0, deniedAttempts: 0 }
  }

  getCapacityStats(): { trackedRuns: number; capacityDenials: number } {
    return { trackedRuns: this.runs.size, capacityDenials: this.capacityDenials }
  }

  has(runId: string): boolean {
    const key = typeof runId === 'string' ? runId.trim() : ''
    return key ? this.runs.has(key) : false
  }

  delete(runId?: string): void {
    if (runId === undefined) {
      this.runs.clear()
      this.capacityDenials = 0
      return
    }
    const key = typeof runId === 'string' ? runId.trim() : ''
    if (key) this.runs.delete(key)
  }
}

// ---------------------------------------------------------------------------
// R2-16: Single host-owned TargetLoadPolicy & unified HTTP status taxonomy
// ---------------------------------------------------------------------------
export {
  classifyTargetClass,
  classifyTargetLoadStatus,
  isLoopbackOrigin,
  normalizeIpBucketKey,
  ORIGIN_DOWN_HTTP_STATUSES,
  PROBE_INDUCED_EXEMPT_HTTP_STATUSES,
  resolveBrokerPerOriginConcurrencyCap,
  resolveBrokerPerOriginRpsCap,
  resolveExternalApexBucketKey,
  resolveExternalApexRpsCap,
  resolveExternalIpConcurrencyCap,
  resolveExternalIpRpsCap,
  resolveTargetLoadPolicy,
  TARGET_LOAD_POLICY_DEFAULTS,
  TARGET_LOAD_POLICY_ENV_KEYS,
  TARGET_LOAD_POLICY_HARD_CEILINGS,
  THROTTLED_HTTP_STATUSES,
} from './target-load-policy.ts'
export type {
  AggregateBucketKind,
  EffectiveOriginLoadPolicy,
  EffectiveTargetLoadPolicy,
  ResolveTargetClassOptions,
  ResolveTargetLoadPolicyOptions,
  TargetClass,
  TargetLoadStatusClass,
} from './target-load-policy.ts'
