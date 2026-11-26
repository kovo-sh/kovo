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
} as const

/** Hard finite OOM ceilings that neither run-scaling nor env/caller overrides may exceed. */
export const RUN_SAFETY_BUDGET_HARD_CEILINGS = {
  maxCompositeVerifiesPerRun: 10_000,
  maxSealsPerRun: 16_384,
  maxSealsPerEndpoint: 4_096,
  maxVaultEntries: 10_000,
  maxSealAttempts: 100_000,
} as const

export const RUN_SAFETY_BUDGET_ENV_KEYS = {
  maxCompositeVerifiesPerRun: 'KOVO_MAX_COMPOSITE_VERIFIES_PER_RUN',
  maxSealsPerRun: 'KOVO_MAX_SEALS_PER_RUN',
  maxSealsPerEndpoint: 'KOVO_MAX_SEALS_PER_ENDPOINT',
  maxVaultEntries: 'KOVO_MAX_VAULT_ENTRIES',
  maxSealAttempts: 'KOVO_MAX_SEAL_ATTEMPTS',
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
}

export interface RunSafetyBudgetOverrides {
  maxCompositeVerifiesPerRun?: number
  maxSealsPerRun?: number
  maxSealsPerEndpoint?: number
  maxVaultEntries?: number
  maxSealAttempts?: number
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
  }
}
