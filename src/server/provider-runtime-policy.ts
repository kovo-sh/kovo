import { DEFAULT_PROVIDER } from '../domain.ts'
import type { RoleAffinity, ThinkingLevel } from '../domain.ts'
import type {
  CallRecorder,
  ProviderConfig,
  ProviderOptions,
  TelemetryCallback,
  UsageCallback,
} from './provider.ts'
import type { SecretSource } from './provider-stream.ts'

/** Default no-token watchdog window for fast/non-reasoning profiles (ms). */
export const DEFAULT_NO_TOKEN_WATCHDOG_MS = 28_000
/** Medium-thinking profile no-token watchdog window before first/next SSE frame (ms). */
export const MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS = 45_000
/** High-thinking / reasoning-model no-token watchdog window (ms). */
export const REASONING_NO_TOKEN_WATCHDOG_MS = 60_000

/**
 * Conservatively high fallback pricing (USD per 1M tokens) applied whenever a non-default
 * (non-Flash) model profile omits explicit pricing. Prevents silent Flash price defaults from
 * under-counting spend against the hard USD cap, and NEVER disables the USD cap.
 */
export const CONSERVATIVE_FALLBACK_PRICING = {
  inputCostPerMtok: 15.0,
  cachedInputCostPerMtok: 3.75,
  outputCostPerMtok: 60.0,
} as const

export type ProviderTimeoutTier = 'fast' | 'medium' | 'reasoning'

export type ProviderCallPurpose =
  | 'worker'
  | 'semantic-audit'
  | 'dedupe-judge'
  | 'approval-safety-judge'
  | 'patch-author'
  | 'patch-reviewer'
  | 'connection'

export type PricingSource = 'explicit' | 'default_flash' | 'conservative_fallback'

export interface ProfilePricingInput {
  model?: string
  inputCostPerMtok?: number | null
  cachedInputCostPerMtok?: number | null
  outputCostPerMtok?: number | null
}

export interface ProfilePricingResolution {
  inputCostPerMtok: number
  cachedInputCostPerMtok: number
  outputCostPerMtok: number
  source: PricingSource
}

export interface RuntimePolicyProfileInput extends ProfilePricingInput {
  id?: string
  contextWindow?: number
  maxTokens?: number
  thinkingLevel?: ThinkingLevel
  roleAffinity?: RoleAffinity
}

export interface ResolveRuntimePolicyOptions {
  role?: RoleAffinity
  purpose?: ProviderCallPurpose
  thinkingLevel?: ThinkingLevel
  env?: NodeJS.ProcessEnv
}

export interface ProviderRuntimePolicy {
  profileId?: string
  model: string
  contextWindow: number
  maxTokens: number
  thinkingLevel: ThinkingLevel
  roleAffinity: RoleAffinity
  reasoningCapable: boolean
  timeoutTier: ProviderTimeoutTier
  noTokenWatchdogMs: number
  firstEventTimeoutMs: number
  idleTimeoutMs: number
  totalTimeoutMs: number
  slowTurnThresholdMs: number
  compactionReserveTokens: number
  pricing: ProfilePricingResolution
}

export interface ProviderOptionsForInput {
  runId?: string
  profile?: RuntimePolicyProfileInput
  signal?: AbortSignal
  secrets?: SecretSource
  onUsage?: UsageCallback
  onTelemetry?: TelemetryCallback
  onStreamActivity?: () => void
  onProfileSuccess?: (profileId: string) => void
  onProfileFailure?: (profileId: string, err: string, hard: boolean) => void
  onCandidatePolicy?: (policy: ProviderRuntimePolicy, candidate: ProviderConfig) => void
  beforeCall?: () => void
  record?: CallRecorder
  fetch?: typeof fetch
  resolveHost?: (hostname: string) => Promise<string[]>
  maxCalls?: number
  maxTransportRetries?: number
  transportRetryBaseMs?: number
  maxRequestBytes?: number
  responseLimit?: number
  thinkingLevel?: ThinkingLevel
  firstEventTimeoutMs?: number
  idleTimeoutMs?: number
  totalTimeoutMs?: number
  env?: NodeJS.ProcessEnv
}

const DEFAULT_FLASH_MODEL_NORMALIZED = DEFAULT_PROVIDER.model.trim().toLowerCase()

function isValidNonNegativeRate(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

/**
 * Returns true iff `model` matches the built-in default Flash model identifier.
 * Only the default Flash model may inherit `DEFAULT_PROVIDER` Flash pricing when prices are omitted.
 */
export function isDefaultFlashModel(model: string | undefined | null): boolean {
  if (typeof model !== 'string') return false
  return model.trim().toLowerCase() === DEFAULT_FLASH_MODEL_NORMALIZED
}

/**
 * Resolve effective per-million-token pricing for a profile without EVER returning null or
 * silently falling back to cheap Flash rates on non-Flash models:
 *  - Explicit finite non-negative `inputCostPerMtok` & `outputCostPerMtok` are honored
 *    (if `cachedInputCostPerMtok` is omitted on a non-Flash model, it defaults conservatively
 *    to `inputCostPerMtok`, never Flash's $0.003).
 *  - Omitted rates on the default Flash model use `DEFAULT_PROVIDER` Flash rates.
 *  - Omitted/invalid/null rates on any non-default model fall back to `CONSERVATIVE_FALLBACK_PRICING`.
 */
export function resolveProfilePricing(profile?: ProfilePricingInput): ProfilePricingResolution {
  const hasExplicitInput = isValidNonNegativeRate(profile?.inputCostPerMtok)
  const hasExplicitOutput = isValidNonNegativeRate(profile?.outputCostPerMtok)
  const hasExplicitCached = isValidNonNegativeRate(profile?.cachedInputCostPerMtok)
  const defaultFlash = isDefaultFlashModel(profile?.model)

  if (hasExplicitInput && hasExplicitOutput) {
    const inputRate = profile!.inputCostPerMtok!
    const outputRate = profile!.outputCostPerMtok!
    const cachedRate = hasExplicitCached
      ? profile!.cachedInputCostPerMtok!
      : (defaultFlash ? DEFAULT_PROVIDER.cachedInputCostPerMtok : inputRate)
    return {
      inputCostPerMtok: inputRate,
      cachedInputCostPerMtok: cachedRate,
      outputCostPerMtok: outputRate,
      source: 'explicit',
    }
  }

  if (defaultFlash) {
    return {
      inputCostPerMtok: hasExplicitInput ? profile!.inputCostPerMtok! : DEFAULT_PROVIDER.inputCostPerMtok,
      cachedInputCostPerMtok: hasExplicitCached ? profile!.cachedInputCostPerMtok! : DEFAULT_PROVIDER.cachedInputCostPerMtok,
      outputCostPerMtok: hasExplicitOutput ? profile!.outputCostPerMtok! : DEFAULT_PROVIDER.outputCostPerMtok,
      source: 'default_flash',
    }
  }

  const inputRate = hasExplicitInput ? profile!.inputCostPerMtok! : CONSERVATIVE_FALLBACK_PRICING.inputCostPerMtok
  const outputRate = hasExplicitOutput ? profile!.outputCostPerMtok! : CONSERVATIVE_FALLBACK_PRICING.outputCostPerMtok
  const cachedRate = hasExplicitCached
    ? profile!.cachedInputCostPerMtok!
    : Math.min(inputRate, CONSERVATIVE_FALLBACK_PRICING.cachedInputCostPerMtok)

  return {
    inputCostPerMtok: inputRate,
    cachedInputCostPerMtok: cachedRate,
    outputCostPerMtok: outputRate,
    source: 'conservative_fallback',
  }
}

function clampContextWindow(value?: number): number {
  const raw = typeof value === 'number' && Number.isFinite(value) && value > 0
    ? value
    : DEFAULT_PROVIDER.contextWindow
  return Math.max(32_000, Math.min(2_000_000, Math.floor(raw)))
}

function clampMaxTokens(value?: number): number {
  const raw = typeof value === 'number' && Number.isFinite(value) && value > 0
    ? value
    : DEFAULT_PROVIDER.maxTokens
  return Math.max(512, Math.min(393_216, Math.floor(raw)))
}

function computeCompactionReserveTokens(contextWindow: number, maxTokens: number): number {
  const scaled = Math.floor(contextWindow * 0.15)
  const desired = Math.max(maxTokens, Math.min(scaled, Math.max(8_192, maxTokens * 2)))
  return Math.max(2_048, Math.min(Math.floor(contextWindow * 0.35), desired))
}

function resolveTierTimeouts(
  tier: ProviderTimeoutTier,
  purpose: ProviderCallPurpose,
): { firstEventTimeoutMs: number; idleTimeoutMs: number; totalTimeoutMs: number; slowTurnThresholdMs: number } {
  const tierFloor = tier === 'reasoning'
    ? { firstEvent: REASONING_NO_TOKEN_WATCHDOG_MS, idle: 90_000, total: 240_000, slowTurn: 45_000 }
    : tier === 'medium'
      ? { firstEvent: MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS, idle: 60_000, total: 180_000, slowTurn: 30_000 }
      : { firstEvent: 30_000, idle: 30_000, total: 60_000, slowTurn: 20_000 }

  switch (purpose) {
    case 'worker':
      return {
        firstEventTimeoutMs: Math.max(120_000, tierFloor.firstEvent),
        idleTimeoutMs: Math.max(180_000, tierFloor.idle),
        totalTimeoutMs: 600_000,
        slowTurnThresholdMs: tierFloor.slowTurn,
      }
    case 'semantic-audit':
      // Reasoning affinity must never be capped below the reasoning tier (60s).
      return {
        firstEventTimeoutMs: Math.max(REASONING_NO_TOKEN_WATCHDOG_MS, tierFloor.firstEvent),
        idleTimeoutMs: Math.max(REASONING_NO_TOKEN_WATCHDOG_MS, tierFloor.idle),
        totalTimeoutMs: Math.max(180_000, tierFloor.total),
        slowTurnThresholdMs: tierFloor.slowTurn,
      }
    case 'patch-author':
    case 'patch-reviewer':
      return {
        firstEventTimeoutMs: Math.max(REASONING_NO_TOKEN_WATCHDOG_MS, tierFloor.firstEvent),
        idleTimeoutMs: Math.max(REASONING_NO_TOKEN_WATCHDOG_MS, tierFloor.idle),
        totalTimeoutMs: Math.max(120_000, tierFloor.total),
        slowTurnThresholdMs: tierFloor.slowTurn,
      }
    case 'dedupe-judge':
      return {
        firstEventTimeoutMs: tier === 'reasoning' ? tierFloor.firstEvent : 30_000,
        idleTimeoutMs: tier === 'reasoning' ? tierFloor.idle : 30_000,
        totalTimeoutMs: tier === 'reasoning' ? Math.max(90_000, tierFloor.total) : 45_000,
        slowTurnThresholdMs: tierFloor.slowTurn,
      }
    case 'approval-safety-judge':
      return {
        firstEventTimeoutMs: tier === 'reasoning' ? tierFloor.firstEvent : 20_000,
        idleTimeoutMs: tier === 'reasoning' ? tierFloor.idle : 20_000,
        totalTimeoutMs: tier === 'reasoning' ? Math.max(90_000, tierFloor.total) : 30_000,
        slowTurnThresholdMs: tierFloor.slowTurn,
      }
    case 'connection':
      return {
        firstEventTimeoutMs: 35_000,
        idleTimeoutMs: 35_000,
        totalTimeoutMs: 45_000,
        slowTurnThresholdMs: 20_000,
      }
  }
}

/**
 * Single authoritative `ProviderRuntimePolicy` resolver (R2-21).
 *
 * Computed strictly from the resolved profile's explicit fields (`contextWindow`, `maxTokens`,
 * `thinkingLevel`, `roleAffinity`, pricing fields) plus caller `role` / `purpose` — zero
 * model-name regexes. Recomputed per failover candidate inside `providerPool`.
 */
export function resolveProviderRuntimePolicy(
  profile?: RuntimePolicyProfileInput,
  opts: ResolveRuntimePolicyOptions = {},
): ProviderRuntimePolicy {
  const env = opts.env ?? process.env
  const purpose: ProviderCallPurpose = opts.purpose ?? 'worker'
  const contextWindow = clampContextWindow(profile?.contextWindow)
  const maxTokens = clampMaxTokens(profile?.maxTokens)
  const roleAffinity: RoleAffinity = opts.role ?? profile?.roleAffinity ?? DEFAULT_PROVIDER.roleAffinity
  const thinkingLevel: ThinkingLevel = purpose === 'connection'
    ? 'off'
    : (opts.thinkingLevel ?? profile?.thinkingLevel ?? (opts.role === 'fast' ? 'off' : 'off'))

  const reasoningCapable =
    purpose !== 'connection' &&
    (thinkingLevel === 'high' || roleAffinity === 'reasoning' || profile?.roleAffinity === 'reasoning')

  const timeoutTier: ProviderTimeoutTier = reasoningCapable
    ? 'reasoning'
    : thinkingLevel === 'medium'
      ? 'medium'
      : 'fast'

  const envNoTokenRaw = Number(env.KOVO_PROVIDER_NO_TOKEN_MS)
  const noTokenWatchdogMs = Number.isFinite(envNoTokenRaw) && envNoTokenRaw > 0
    ? Math.max(5_000, Math.min(180_000, Math.floor(envNoTokenRaw)))
    : timeoutTier === 'reasoning'
      ? REASONING_NO_TOKEN_WATCHDOG_MS
      : timeoutTier === 'medium'
        ? MEDIUM_THINKING_NO_TOKEN_WATCHDOG_MS
        : DEFAULT_NO_TOKEN_WATCHDOG_MS

  const timeouts = resolveTierTimeouts(timeoutTier, purpose)
  const compactionReserveTokens = computeCompactionReserveTokens(contextWindow, maxTokens)
  const pricing = resolveProfilePricing(profile)

  return {
    ...(profile?.id ? { profileId: profile.id } : {}),
    model: profile?.model ?? '',
    contextWindow,
    maxTokens,
    thinkingLevel,
    roleAffinity,
    reasoningCapable,
    timeoutTier,
    noTokenWatchdogMs,
    firstEventTimeoutMs: timeouts.firstEventTimeoutMs,
    idleTimeoutMs: timeouts.idleTimeoutMs,
    totalTimeoutMs: timeouts.totalTimeoutMs,
    slowTurnThresholdMs: timeouts.slowTurnThresholdMs,
    compactionReserveTokens,
    pricing,
  }
}

function extractRunId(run: { id?: string } | string | null | undefined, fallback?: string): string | undefined {
  if (typeof run === 'string') {
    const trimmed = run.trim()
    if (trimmed) return trimmed
  } else if (run && typeof run === 'object' && typeof run.id === 'string') {
    const trimmed = run.id.trim()
    if (trimmed) return trimmed
  }
  if (typeof fallback === 'string') {
    const trimmed = fallback.trim()
    if (trimmed) return trimmed
  }
  return undefined
}

/**
 * Single authoritative `ProviderOptions` builder used by all auxiliary and connection call sites
 * (`approval-judge`, `semantic-audit`, `dedupe`, `patch-workflow`, `testProvider`).
 *
 * Derives policy timeouts from `resolveProviderRuntimePolicy`, injects `runId` and telemetry hooks,
 * and marks `runtimePolicyManaged: true` (when timeouts are not explicitly overridden) so
 * `providerPool` recomputes per-candidate timeouts, compaction reserve, and pricing on failover.
 */
export function providerOptionsFor(
  run: { id?: string } | string | null | undefined,
  role: RoleAffinity,
  purpose: ProviderCallPurpose,
  overrides: ProviderOptionsForInput = {},
): ProviderOptions {
  const policy = resolveProviderRuntimePolicy(overrides.profile, {
    role,
    purpose,
    thinkingLevel: overrides.thinkingLevel,
    env: overrides.env,
  })
  const runId = extractRunId(run, overrides.runId)
  const hasExplicitTimeouts =
    overrides.firstEventTimeoutMs !== undefined ||
    overrides.idleTimeoutMs !== undefined ||
    overrides.totalTimeoutMs !== undefined

  return {
    ...(overrides.signal ? { signal: overrides.signal } : {}),
    ...(overrides.record ? { record: overrides.record } : {}),
    ...(overrides.secrets ? { secrets: overrides.secrets } : {}),
    ...(overrides.maxCalls !== undefined ? { maxCalls: overrides.maxCalls } : {}),
    ...(overrides.maxTransportRetries !== undefined ? { maxTransportRetries: overrides.maxTransportRetries } : {}),
    ...(overrides.transportRetryBaseMs !== undefined ? { transportRetryBaseMs: overrides.transportRetryBaseMs } : {}),
    ...(overrides.maxRequestBytes !== undefined ? { maxRequestBytes: overrides.maxRequestBytes } : {}),
    ...(overrides.responseLimit !== undefined ? { responseLimit: overrides.responseLimit } : {}),
    ...(overrides.beforeCall ? { beforeCall: overrides.beforeCall } : {}),
    ...(overrides.onUsage ? { onUsage: overrides.onUsage } : {}),
    ...(overrides.onTelemetry ? { onTelemetry: overrides.onTelemetry } : {}),
    ...(overrides.onStreamActivity ? { onStreamActivity: overrides.onStreamActivity } : {}),
    ...(overrides.onProfileSuccess ? { onProfileSuccess: overrides.onProfileSuccess } : {}),
    ...(overrides.onProfileFailure ? { onProfileFailure: overrides.onProfileFailure } : {}),
    ...(overrides.onCandidatePolicy ? { onCandidatePolicy: overrides.onCandidatePolicy } : {}),
    ...(overrides.fetch ? { fetch: overrides.fetch } : {}),
    ...(overrides.resolveHost ? { resolveHost: overrides.resolveHost } : {}),
    ...(runId ? { runId } : {}),
    roleAffinity: role,
    purpose,
    ...(overrides.thinkingLevel !== undefined ? { thinkingLevel: overrides.thinkingLevel } : {}),
    firstEventTimeoutMs: overrides.firstEventTimeoutMs ?? policy.firstEventTimeoutMs,
    idleTimeoutMs: overrides.idleTimeoutMs ?? policy.idleTimeoutMs,
    totalTimeoutMs: overrides.totalTimeoutMs ?? policy.totalTimeoutMs,
    runtimePolicyManaged: !hasExplicitTimeouts,
  }
}
