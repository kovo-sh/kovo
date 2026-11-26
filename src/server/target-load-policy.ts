/**
 * Single Host-Owned Target Load Policy & Unified HTTP Status Taxonomy (R2-16).
 *
 * Centralizes every target-load ceiling, per-target-class cap, aggregate apex/IP cap,
 * lane concurrency default, and the ONE authoritative HTTP target-load status taxonomy
 * (`origin_down` / `throttled` / `transient` / `client_error` / `healthy`) so broker,
 * recon, dispatch, and UI snapshots share one read-only contract without drifting.
 *
 * Stage 1 is strictly value-preserving against existing local-lab and external defaults.
 */
import ipaddr from 'ipaddr.js'
import { defaultMaxRpsPerOrigin, maxWorkerConcurrency } from '../domain.ts'
import { EgressGateway } from './egress-gateway.ts'
import { isIpLiteralHost, registrableApex } from './public-suffix.ts'

export type TargetClass = 'external' | 'loopback' | 'local_lab'

export type TargetLoadStatusClass =
  | 'origin_down'
  | 'throttled'
  | 'transient'
  | 'client_error'
  | 'healthy'

export type AggregateBucketKind = 'apex' | 'ip'

export interface ResolveTargetClassOptions {
  allowLocalLab?: boolean
  /**
   * Explicit caller/test forcing knob (e.g. force `'external'` caps on a loopback fixture
   * without toggling process-wide `KOVO_ALLOW_LOCAL_LAB` flags).
   */
  targetClassOverride?: TargetClass
}

/**
 * Authoritative default target-load policy values (Stage 1: strictly value-preserving).
 */
export const TARGET_LOAD_POLICY_DEFAULTS = {
  /** Per-origin concurrent in-flight HTTP cap for external/public hosts (polite bound). */
  externalOriginMaxInFlight: 4,
  /** Per-origin concurrent in-flight HTTP cap for loopback / authorized local-lab origins. */
  loopbackOriginMaxInFlight: 12,
  /** Per-origin RPS ceiling for external/public hosts. */
  externalOriginMaxRps: 20,
  /** Per-origin RPS ceiling for loopback / authorized local-lab origins. */
  loopbackOriginMaxRps: 100,
  /** Default per-origin RPS when a grant does not specify one. */
  defaultMaxRpsPerOrigin,
  /** Conservative default per-origin RPS for Tier-3 grants when unspecified. */
  tier3DefaultMaxRps: 3,
  /** Soft aggregate RPS ceiling shared across external subdomains of one PSL registrable apex. */
  externalApexMaxRps: 45,
  /** Soft aggregate RPS ceiling shared across all external origins resolving to one IP (incl. IP literals & multi-port/multi-vhost). */
  externalIpMaxRps: 45,
  /** Aggregate concurrent in-flight HTTP ceiling shared across all external origins resolving to one IP. */
  externalIpMaxInFlight: 8,
  /** Hard bound on active aggregate rate buckets kept in memory. */
  maxAggregateBuckets: 1_024,
  /** Idle TTL before an unreferenced aggregate bucket is eligible for eviction. */
  aggregateBucketIdleTtlMs: 60_000,
  /** Default broker circuit breaker thresholds & backoff bounds. */
  circuit5xxThreshold: 5,
  circuit429Threshold: 8,
  circuitWindowMs: 30_000,
  circuitBackoffBaseMs: 1_000,
  circuitBackoffMaxMs: 30_000,
  maxRetryAfterSeconds: 300,
  probeInduced5xxThresholdMultiplier: 3,
  minProbeInduced5xxThreshold: 6,
  /** Lane concurrency defaults (read-only snapshot in Stage 1; lane migration in Stage 2). */
  phase0OriginConcurrency: 6,
  phase0BrowserConcurrency: 3,
  baselineCaptureConcurrency: 6,
  phaseBAimdMinFloor: 2,
  phaseBAimdWarmStart: 6,
  phaseBAimdMaxCeiling: 12,
} as const

/** Hard finite ceilings that env or caller overrides may never exceed. */
export const TARGET_LOAD_POLICY_HARD_CEILINGS = {
  externalOriginMaxInFlight: 4,
  loopbackOriginMaxInFlight: 24,
  externalOriginMaxRps: 20,
  loopbackOriginMaxRps: 100,
  externalApexMaxRps: 200,
  externalIpMaxRps: 200,
  externalIpMaxInFlight: 32,
  phase0OriginConcurrency: 12,
  phase0BrowserConcurrency: 4,
  baselineCaptureConcurrency: 12,
  phaseBConcurrency: maxWorkerConcurrency,
} as const

export const TARGET_LOAD_POLICY_ENV_KEYS = {
  loopbackOriginMaxInFlight: 'KOVO_BROKER_LOOPBACK_IN_FLIGHT',
  externalApexMaxRps: 'KOVO_EXTERNAL_APEX_MAX_RPS',
  externalIpMaxRps: 'KOVO_EXTERNAL_IP_MAX_RPS',
  externalIpMaxInFlight: 'KOVO_EXTERNAL_IP_MAX_IN_FLIGHT',
  phase0OriginConcurrency: 'KOVO_PHASE0_ORIGIN_CONCURRENCY',
  phase0BrowserConcurrency: 'KOVO_PHASE0_BROWSER_CONCURRENCY',
  baselineCaptureConcurrency: 'KOVO_BASELINE_CAPTURE_CONCURRENCY',
  phaseBConcurrency: 'KOVO_PHASE_B_CONCURRENCY',
  workerConcurrency: 'KOVO_WORKER_CONCURRENCY',
} as const

/**
 * ONE authoritative HTTP target-load status taxonomy:
 *   - `origin_down`: gateway / availability / Cloudflare edge origin-down (502–504, 520–526)
 *   - `throttled`: explicit target rate-limiting (429) — strictly separate from LLM 429
 *   - `transient`: ordinary server 5xx (500, 501, 505–511, 527+, etc.)
 *   - `client_error`: non-429 4xx responses
 *   - `healthy`: <400 responses
 */
export const ORIGIN_DOWN_HTTP_STATUSES: ReadonlySet<number> = new Set([
  502, 503, 504, 520, 521, 522, 523, 524, 525, 526,
])

export const THROTTLED_HTTP_STATUSES: ReadonlySet<number> = new Set([429])

/** Plain 500/501 responses eligible for bounded probe-induced evidence (NEVER origin-down statuses). */
export const PROBE_INDUCED_EXEMPT_HTTP_STATUSES: ReadonlySet<number> = new Set([500, 501])

export function classifyTargetLoadStatus(status: number): TargetLoadStatusClass {
  if (ORIGIN_DOWN_HTTP_STATUSES.has(status)) return 'origin_down'
  if (THROTTLED_HTTP_STATUSES.has(status)) return 'throttled'
  if (status >= 500 && status <= 599) return 'transient'
  if (status >= 400 && status <= 499) return 'client_error'
  return 'healthy'
}

export const EXTERNAL_ORIGIN_MAX_IN_FLIGHT = TARGET_LOAD_POLICY_DEFAULTS.externalOriginMaxInFlight
export const LOOPBACK_ORIGIN_MAX_IN_FLIGHT = TARGET_LOAD_POLICY_DEFAULTS.loopbackOriginMaxInFlight
export const EXTERNAL_ORIGIN_MAX_RPS_CAP = TARGET_LOAD_POLICY_DEFAULTS.externalOriginMaxRps
export const LOOPBACK_ORIGIN_MAX_RPS_CAP = TARGET_LOAD_POLICY_DEFAULTS.loopbackOriginMaxRps
export const EXTERNAL_APEX_MAX_RPS_CAP = TARGET_LOAD_POLICY_DEFAULTS.externalApexMaxRps

/** True strictly for loopback origins (`localhost`, `127.0.0.0/8`, `::1`). */
export function isLoopbackOrigin(origin: string): boolean {
  try {
    return EgressGateway.isLoopbackLiteral(new URL(origin).hostname)
  } catch { /* invalid origin */ }
  return false
}

/**
 * Pure local-lab origin predicate matching `isLocalLabAutoApprovalOrigin` without introducing a
 * runtime import cycle through `approval-judge.ts` -> `provider.ts` -> `run-safety-budgets.ts`.
 * Matches loopback, RFC1918 private IPv4 (never 169.254.0.0/16 metadata/link-local), and
 * single-label Docker/LabRunner container hostnames.
 */
function isLocalLabOrigin(origin: string): boolean {
  let url: URL
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(origin) ? origin : `http://${origin}`)
  } catch {
    return false
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
  if (url.username || url.password) return false
  const host = url.hostname.toLowerCase()
  if (!host) return false
  if (host === 'localhost' || host === '::1' || host === '[::1]') return true
  if (ipaddr.IPv4.isValidFourPartDecimal(host)) {
    const [a, b] = ipaddr.IPv4.parse(host).octets
    if (a === 127 || a === 10) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    return false
  }
  if (host.includes(':')) return false
  return !host.includes('.') && /^[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/.test(host)
}

/**
 * Resolve the effective `TargetClass` for an origin.
 * When `targetClassOverride` is provided, it takes precedence so tests/callers can force
 * `'external'` politeness caps against loopback fixtures without toggling env-wide flags.
 */
export function classifyTargetClass(
  origin: string,
  options: ResolveTargetClassOptions = {},
): TargetClass {
  if (options.targetClassOverride) return options.targetClassOverride
  if (isLoopbackOrigin(origin)) return 'loopback'
  if (options.allowLocalLab && isLocalLabOrigin(origin)) return 'local_lab'
  return 'external'
}

function parseClampedIntEnv(
  envKey: string,
  fallback: number,
  min: number,
  max: number,
  env: Readonly<Record<string, string | undefined>> = process.env,
): number {
  const raw = env[envKey]
  if (raw === undefined || raw.trim() === '') return fallback
  const parsed = Number(raw.trim())
  if (!Number.isFinite(parsed) || parsed < min) return fallback
  return Math.max(min, Math.min(max, Math.floor(parsed)))
}

/**
 * Per-origin concurrent in-flight request ceiling. External origins stay bounded at 4;
 * loopback / authorized local-lab origins scale up to 12 (configurable up to 24).
 */
export function resolveBrokerPerOriginConcurrencyCap(
  origin: string,
  allowLocalLabOrigin = false,
  env: Readonly<Record<string, string | undefined>> = process.env,
  targetClassOverride?: TargetClass,
): number {
  const targetClass = classifyTargetClass(origin, {
    allowLocalLab: allowLocalLabOrigin,
    targetClassOverride,
  })
  if (targetClass === 'external') {
    return EXTERNAL_ORIGIN_MAX_IN_FLIGHT
  }
  return parseClampedIntEnv(
    TARGET_LOAD_POLICY_ENV_KEYS.loopbackOriginMaxInFlight,
    LOOPBACK_ORIGIN_MAX_IN_FLIGHT,
    2,
    TARGET_LOAD_POLICY_HARD_CEILINGS.loopbackOriginMaxInFlight,
    env,
  )
}

/** Per-origin RPS ceiling: polite cap (20) on external targets, higher ceiling (100) on loopback/local-lab. */
export function resolveBrokerPerOriginRpsCap(
  origin: string,
  requestedRps: number,
  allowLocalLabOrigin = false,
  targetClassOverride?: TargetClass,
): number {
  const targetClass = classifyTargetClass(origin, {
    allowLocalLab: allowLocalLabOrigin,
    targetClassOverride,
  })
  const ceiling = targetClass === 'external'
    ? EXTERNAL_ORIGIN_MAX_RPS_CAP
    : LOOPBACK_ORIGIN_MAX_RPS_CAP
  const safeRequested = Number.isFinite(requestedRps) ? requestedRps : TARGET_LOAD_POLICY_DEFAULTS.defaultMaxRpsPerOrigin
  return Math.max(1, Math.min(ceiling, safeRequested))
}

/**
 * Soft aggregate RPS cap shared across all external origins under one PSL registrable apex.
 * Configurable via `KOVO_EXTERNAL_APEX_MAX_RPS` (clamped to `[1, 200]`, default `45` req/s).
 */
export function resolveExternalApexRpsCap(
  env: Readonly<Record<string, string | undefined>> = process.env,
  overrideRps?: number,
): number {
  if (typeof overrideRps === 'number' && Number.isFinite(overrideRps) && overrideRps >= 1) {
    return Math.max(1, Math.min(TARGET_LOAD_POLICY_HARD_CEILINGS.externalApexMaxRps, Math.floor(overrideRps)))
  }
  return parseClampedIntEnv(
    TARGET_LOAD_POLICY_ENV_KEYS.externalApexMaxRps,
    EXTERNAL_APEX_MAX_RPS_CAP,
    1,
    TARGET_LOAD_POLICY_HARD_CEILINGS.externalApexMaxRps,
    env,
  )
}

/**
 * Soft aggregate RPS cap shared across all external origins resolving to the same IP address
 * (covers IP literals, multi-port targets on one IP, and multi-vhost domains sharing one IP).
 * Configurable via `KOVO_EXTERNAL_IP_MAX_RPS` (clamped to `[1, 200]`, default `45` req/s).
 */
export function resolveExternalIpRpsCap(
  env: Readonly<Record<string, string | undefined>> = process.env,
  overrideRps?: number,
): number {
  if (typeof overrideRps === 'number' && Number.isFinite(overrideRps) && overrideRps >= 1) {
    return Math.max(1, Math.min(TARGET_LOAD_POLICY_HARD_CEILINGS.externalIpMaxRps, Math.floor(overrideRps)))
  }
  return parseClampedIntEnv(
    TARGET_LOAD_POLICY_ENV_KEYS.externalIpMaxRps,
    TARGET_LOAD_POLICY_DEFAULTS.externalIpMaxRps,
    1,
    TARGET_LOAD_POLICY_HARD_CEILINGS.externalIpMaxRps,
    env,
  )
}

/**
 * Aggregate concurrent in-flight HTTP ceiling shared across all external origins resolving to one IP.
 * Configurable via `KOVO_EXTERNAL_IP_MAX_IN_FLIGHT` (clamped to `[1, 32]`, default `8`).
 */
export function resolveExternalIpConcurrencyCap(
  env: Readonly<Record<string, string | undefined>> = process.env,
  overrideInFlight?: number,
): number {
  if (typeof overrideInFlight === 'number' && Number.isFinite(overrideInFlight) && overrideInFlight >= 1) {
    return Math.max(1, Math.min(TARGET_LOAD_POLICY_HARD_CEILINGS.externalIpMaxInFlight, Math.floor(overrideInFlight)))
  }
  return parseClampedIntEnv(
    TARGET_LOAD_POLICY_ENV_KEYS.externalIpMaxInFlight,
    TARGET_LOAD_POLICY_DEFAULTS.externalIpMaxInFlight,
    1,
    TARGET_LOAD_POLICY_HARD_CEILINGS.externalIpMaxInFlight,
    env,
  )
}

/**
 * Shared PSL registrable apex key for external origins. Returns null for loopback, authorized
 * local-lab, private-lab, IP-literal, and bare-suffix origins unless `targetClassOverride === 'external'`
 * forces external evaluation (still returning null for IP literals / localhost so callers fall back
 * to the per-IP aggregate bucket).
 */
export function resolveExternalApexBucketKey(
  origin: string,
  allowLocalLabOrigin = false,
  targetClassOverride?: TargetClass,
): string | null {
  const forcedExternal = targetClassOverride === 'external'
  if (!forcedExternal) {
    if (allowLocalLabOrigin) return null
    if (isLoopbackOrigin(origin) || isLocalLabOrigin(origin)) return null
  } else if (classifyTargetClass(origin, { allowLocalLab: allowLocalLabOrigin, targetClassOverride }) !== 'external') {
    return null
  }
  try {
    const host = new URL(origin).hostname.toLowerCase()
    if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) {
      return null
    }
  } catch {
    return null
  }
  return registrableApex(origin)
}

/**
 * Normalize a resolved IP address (or IP-literal origin host) into a canonical per-IP
 * aggregate bucket key (unwrapping IPv4-mapped IPv6 addresses such as `::ffff:127.0.0.1`
 * to `127.0.0.1` so dual-stack vhosts share one bucket).
 */
export function normalizeIpBucketKey(rawIpOrHost: string | null | undefined): string | null {
  if (!rawIpOrHost) return null
  const stripped = rawIpOrHost.trim().replace(/^\[|\]$/g, '').split('%', 1)[0]?.trim() ?? ''
  if (!stripped || !ipaddr.isValid(stripped)) return null
  try {
    const parsed = ipaddr.parse(stripped)
    if (parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress()) {
      return (parsed as ipaddr.IPv6).toIPv4Address().toString().toLowerCase()
    }
    return parsed.toString().toLowerCase()
  } catch {
    return null
  }
}

export interface EffectiveOriginLoadPolicy {
  readonly origin: string
  readonly targetClass: TargetClass
  readonly maxInFlight: number
  readonly maxRps: number
  readonly apexBucketKey: string | null
  readonly ipBucketKey: string | null
  readonly aggregateMaxRps: number | null
  readonly aggregateMaxInFlight: number | null
}

export interface EffectiveTargetLoadPolicy {
  readonly targetClassOverride: TargetClass | null
  readonly broker: {
    readonly externalOriginMaxInFlight: number
    readonly loopbackOriginMaxInFlight: number
    readonly externalOriginMaxRps: number
    readonly loopbackOriginMaxRps: number
    readonly externalApexMaxRps: number
    readonly externalIpMaxRps: number
    readonly externalIpMaxInFlight: number
    readonly circuit5xxThreshold: number
    readonly circuit429Threshold: number
    readonly circuitWindowMs: number
    readonly circuitBackoffBaseMs: number
    readonly circuitBackoffMaxMs: number
    readonly maxRetryAfterSeconds: number
  }
  readonly lanes: {
    readonly phase0OriginConcurrency: number
    readonly phase0BrowserConcurrency: number
    readonly baselineCaptureConcurrency: number
    readonly phaseBConcurrencyOverride: number | null
    readonly phaseBAimdMinFloor: number
    readonly phaseBAimdWarmStart: number
    readonly phaseBAimdMaxCeiling: number
  }
  readonly origins: readonly EffectiveOriginLoadPolicy[]
}

export interface ResolveTargetLoadPolicyOptions {
  env?: Readonly<Record<string, string | undefined>>
  origins?: readonly string[]
  allowLocalLab?: boolean
  targetClassOverride?: TargetClass
  requestedMaxRpsPerOrigin?: number
  externalApexMaxRps?: number
  externalIpMaxRps?: number
  externalIpMaxInFlight?: number
  circuit5xxThreshold?: number
  circuit429Threshold?: number
  circuitWindowMs?: number
  circuitBackoffBaseMs?: number
  circuitBackoffMaxMs?: number
}

function parseOptionalPhaseBOverride(env: Readonly<Record<string, string | undefined>>): number | null {
  const raw = env[TARGET_LOAD_POLICY_ENV_KEYS.phaseBConcurrency] ?? env[TARGET_LOAD_POLICY_ENV_KEYS.workerConcurrency]
  if (raw === undefined || raw.trim() === '') return null
  const parsed = Number(raw.trim())
  if (!Number.isFinite(parsed) || parsed <= 0) return null
  return Math.max(1, Math.min(TARGET_LOAD_POLICY_HARD_CEILINGS.phaseBConcurrency, Math.floor(parsed)))
}

/**
 * Resolve a read-only `EffectiveTargetLoadPolicy` snapshot for a run/broker configuration.
 * Value-preserving against all existing local-lab and external defaults.
 */
export function resolveTargetLoadPolicy(
  options: ResolveTargetLoadPolicyOptions = {},
): EffectiveTargetLoadPolicy {
  const env = options.env ?? process.env
  const allowLocalLab = Boolean(options.allowLocalLab)
  const targetClassOverride = options.targetClassOverride
  const requestedRps = options.requestedMaxRpsPerOrigin ?? TARGET_LOAD_POLICY_DEFAULTS.defaultMaxRpsPerOrigin

  const loopbackOriginMaxInFlight = parseClampedIntEnv(
    TARGET_LOAD_POLICY_ENV_KEYS.loopbackOriginMaxInFlight,
    TARGET_LOAD_POLICY_DEFAULTS.loopbackOriginMaxInFlight,
    2,
    TARGET_LOAD_POLICY_HARD_CEILINGS.loopbackOriginMaxInFlight,
    env,
  )
  const externalApexMaxRps = resolveExternalApexRpsCap(env, options.externalApexMaxRps)
  const externalIpMaxRps = resolveExternalIpRpsCap(env, options.externalIpMaxRps)
  const externalIpMaxInFlight = resolveExternalIpConcurrencyCap(env, options.externalIpMaxInFlight)

  const origins: EffectiveOriginLoadPolicy[] = (options.origins ?? []).map(origin => {
    const targetClass = classifyTargetClass(origin, { allowLocalLab, targetClassOverride })
    const maxInFlight = resolveBrokerPerOriginConcurrencyCap(origin, allowLocalLab, env, targetClassOverride)
    const maxRps = resolveBrokerPerOriginRpsCap(origin, requestedRps, allowLocalLab, targetClassOverride)
    const apexBucketKey = resolveExternalApexBucketKey(origin, allowLocalLab, targetClassOverride)
    let ipBucketKey: string | null = null
    if (targetClass === 'external') {
      try {
        const host = new URL(origin).hostname
        if (isIpLiteralHost(host)) {
          ipBucketKey = normalizeIpBucketKey(host)
        }
      } catch { /* invalid origin */ }
    }
    const isExternal = targetClass === 'external'
    return {
      origin,
      targetClass,
      maxInFlight,
      maxRps,
      apexBucketKey,
      ipBucketKey,
      aggregateMaxRps: isExternal ? (apexBucketKey ? Math.min(externalApexMaxRps, externalIpMaxRps) : externalIpMaxRps) : null,
      aggregateMaxInFlight: isExternal ? externalIpMaxInFlight : null,
    }
  })

  return {
    targetClassOverride: targetClassOverride ?? null,
    broker: {
      externalOriginMaxInFlight: TARGET_LOAD_POLICY_DEFAULTS.externalOriginMaxInFlight,
      loopbackOriginMaxInFlight,
      externalOriginMaxRps: TARGET_LOAD_POLICY_DEFAULTS.externalOriginMaxRps,
      loopbackOriginMaxRps: TARGET_LOAD_POLICY_DEFAULTS.loopbackOriginMaxRps,
      externalApexMaxRps,
      externalIpMaxRps,
      externalIpMaxInFlight,
      circuit5xxThreshold: options.circuit5xxThreshold ?? TARGET_LOAD_POLICY_DEFAULTS.circuit5xxThreshold,
      circuit429Threshold: options.circuit429Threshold ?? TARGET_LOAD_POLICY_DEFAULTS.circuit429Threshold,
      circuitWindowMs: options.circuitWindowMs ?? TARGET_LOAD_POLICY_DEFAULTS.circuitWindowMs,
      circuitBackoffBaseMs: options.circuitBackoffBaseMs ?? TARGET_LOAD_POLICY_DEFAULTS.circuitBackoffBaseMs,
      circuitBackoffMaxMs: options.circuitBackoffMaxMs ?? TARGET_LOAD_POLICY_DEFAULTS.circuitBackoffMaxMs,
      maxRetryAfterSeconds: TARGET_LOAD_POLICY_DEFAULTS.maxRetryAfterSeconds,
    },
    lanes: {
      phase0OriginConcurrency: parseClampedIntEnv(
        TARGET_LOAD_POLICY_ENV_KEYS.phase0OriginConcurrency,
        TARGET_LOAD_POLICY_DEFAULTS.phase0OriginConcurrency,
        1,
        TARGET_LOAD_POLICY_HARD_CEILINGS.phase0OriginConcurrency,
        env,
      ),
      phase0BrowserConcurrency: parseClampedIntEnv(
        TARGET_LOAD_POLICY_ENV_KEYS.phase0BrowserConcurrency,
        TARGET_LOAD_POLICY_DEFAULTS.phase0BrowserConcurrency,
        1,
        TARGET_LOAD_POLICY_HARD_CEILINGS.phase0BrowserConcurrency,
        env,
      ),
      baselineCaptureConcurrency: parseClampedIntEnv(
        TARGET_LOAD_POLICY_ENV_KEYS.baselineCaptureConcurrency,
        TARGET_LOAD_POLICY_DEFAULTS.baselineCaptureConcurrency,
        1,
        TARGET_LOAD_POLICY_HARD_CEILINGS.baselineCaptureConcurrency,
        env,
      ),
      phaseBConcurrencyOverride: parseOptionalPhaseBOverride(env),
      phaseBAimdMinFloor: TARGET_LOAD_POLICY_DEFAULTS.phaseBAimdMinFloor,
      phaseBAimdWarmStart: TARGET_LOAD_POLICY_DEFAULTS.phaseBAimdWarmStart,
      phaseBAimdMaxCeiling: TARGET_LOAD_POLICY_DEFAULTS.phaseBAimdMaxCeiling,
    },
    origins,
  }
}
