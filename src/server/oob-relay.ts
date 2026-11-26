/**
 * Async out-of-band (OOB) relay: durable `pending_oob` correlation, callback integrity,
 * and deployable public relay profiles.
 *
 * Design goals (see plans/better-architecture.md §1.6 / Phase 3):
 *  - Two-stage correlation: a short immediate window (default 3 s) plus a durable
 *    `pending_oob` subscription (default 15 min, capped at 30 min) that promotes late
 *    callbacks (background jobs, PDF/email/webhook workers) into verified candidates.
 *  - Restart-safe: subscriptions, delivered callbacks, rejected callbacks and canary
 *    bindings live in an operator-owned SQLite file, so a new relay instance resumes
 *    exactly where the previous one stopped.
 *  - Idempotent: every callback is keyed by a stable callback id; re-delivery never
 *    double-counts and a promotion can only claim a callback once.
 *  - Fail-closed public profile: loopback is the default. A public HTTP/HTTPS/DNS(/SMTP)
 *    profile activates only from explicit operator configuration and refuses to open
 *    public listeners when any required piece (ACME hook or cert files, authoritative
 *    DNS provider, public base URL) is missing.
 *
 * This module never opens public listeners on its own. The listener wiring lives in
 * `canary-broker.ts` behind `startPublicProfile()`.
 */
import { createHash, randomUUID } from 'node:crypto'
import { join } from 'node:path'
import type { DatabaseSync } from 'node:sqlite'
import { cancelOobDrainForRun } from './oob-drain.ts'
import { assertValidRunId } from './run-context.ts'
import {
  RUN_SAFETY_BUDGET_HARD_CEILINGS,
  resolveRunSafetyBudgets,
} from './run-safety-budgets.ts'
import {
  SQLITE_DEFAULT_BUSY_TIMEOUT_MS,
  SQLITE_JOURNAL_SIZE_LIMIT_BYTES,
  openSqliteDatabase,
  withBusyRetry,
} from './store-session.ts'

export type OobProtocol = 'http' | 'dns' | 'smtp'

export type OobSubscriptionStatus = 'pending' | 'promoted' | 'expired'

export type OobRejectionReason =
  | 'invalid_token'
  | 'unknown_token'
  | 'token_mismatch'
  | 'source_not_allowlisted'
  | 'artifact_missing'
  | 'artifact_mismatch'
  | 'subscription_expired'
  | 'token_quota_exceeded'
  | 'run_quota_exceeded'
  | 'protected_quota_exceeded'
  | 'ip_rate_limited'

export interface OobDnsAnswer {
  type: 'A' | 'AAAA' | 'TXT' | 'CNAME' | 'NS'
  /** IPv4/IPv6 literal for A/AAAA, text for TXT, target name for CNAME/NS. */
  value: string
  ttl?: number
}

export interface OobDnsQuery {
  name: string
  type: number
  typeName: string
}

/**
 * Authoritative DNS hook. Operators either implement this directly (route 53, Cloudflare,
 * PowerDNS, Knot, ...) or wrap an existing provider. The relay's UDP/TCP listeners call it
 * for every query; returning `null` falls back to the built-in token answers.
 */
export interface OobDnsProvider {
  readonly name?: string
  resolve(query: OobDnsQuery): OobDnsAnswer | null | Promise<OobDnsAnswer | null>
}

export interface OobAcmeHttpChallenge {
  status?: number
  body: string
  contentType?: string
}

/**
 * ACME hook points. Kovo Hunter deliberately does not embed a CA: operators plug in
 * certbot/acme.sh/Caddy/their existing ACME client and provide a loader (plus an optional
 * renewal hook). Without one, the public HTTPS profile refuses to start.
 */
export interface OobAcmeHooks {
  loadCertificate(): Promise<{ cert: string; key: string }> | { cert: string; key: string }
  renew?(current: { cert: string; key: string }): Promise<{ cert: string; key: string }> | { cert: string; key: string }
  /** Path prefix the public HTTP listener answers ACME HTTP-01 challenges on. */
  httpChallengePath?: string
  /** Optional HTTP-01 responder; return null/undefined to fall through to the callback handler. */
  answerHttpChallenge?(pathAndQuery: string): OobAcmeHttpChallenge | null
}

export interface OobSmtpCallbackInput {
  token: string
  sourceIp?: string
  artifact?: string
  callbackId?: string
  detail?: Record<string, unknown>
}

/** SMTP is extensible: the relay delegates to an operator-provided provider. */
export interface OobSmtpProvider {
  start(context: { onCallback(input: OobSmtpCallbackInput): void }): Promise<void> | void
  stop?(): Promise<void> | void
}

export interface OobPublicRelayConfig {
  enabled?: boolean
  publicBaseUrl?: string
  http?: { host?: string; port?: number }
  https?: {
    host?: string
    port?: number
    certPath?: string
    keyPath?: string
    acme?: OobAcmeHooks
  }
  dns?: {
    domain?: string
    host?: string
    udpPort?: number
    tcpPort?: number
    provider?: OobDnsProvider
  }
  smtp?: { host?: string; port?: number; provider?: OobSmtpProvider }
  allowlist?: string[]
}

export interface OobRelayProfile {
  mode: 'loopback' | 'public'
  publicEnabled: boolean
  publicBaseUrl: string | null
  http: { host: string; port: number; enabled: boolean }
  https: {
    host: string
    port: number
    enabled: boolean
    certificate: 'acme-hook' | 'files' | 'missing'
    acme: OobAcmeHooks | null
    certPath: string | null
    keyPath: string | null
  }
  dns: {
    domain: string
    host: string
    udpPort: number
    tcpPort: number
    /** Authoritative DNS is required for a deployable public profile. */
    authoritative: boolean
    provider: OobDnsProvider | null
  }
  smtp: { host: string; port: number; enabled: boolean; provider: OobSmtpProvider | null }
  allowlist: string[]
  /** Human-readable reasons the public profile may not start (empty when startable). */
  problems: string[]
}

export interface OobBinding {
  runId: string
  assignmentId: string
  canaryId: string
  token: string
  /** Causal artifact (exchange id, proof-script step, injected parameter ref...). */
  artifact: string
}

export interface OobSubscriptionInput extends OobBinding {
  id?: string
  protocol?: OobProtocol
  /** Short synchronous window; defaults to 3 s. */
  immediateMs?: number
  /** Durable window; defaults to 15 min and is capped at 30 min. */
  windowMs?: number
  allowlist?: string[]
}

export interface OobSubscription extends OobBinding {
  id: string
  protocol: OobProtocol
  status: OobSubscriptionStatus
  createdAt: number
  immediateMs: number
  windowMs: number
  expiresAt: number
  promotedAt: number | null
  callbackId: string | null
  allowlist: string[]
}

export interface OobCallbackInput {
  token: string
  /** Stable id for idempotent re-delivery. Derived when omitted. */
  callbackId?: string
  protocol?: OobProtocol
  sourceIp?: string
  method?: string
  path?: string
  query?: string
  artifact?: string
  runId?: string
  assignmentId?: string
  canaryId?: string
  receivedAt?: number
  detail?: Record<string, unknown>
}

export interface OobCallback {
  callbackId: string
  token: string
  protocol: OobProtocol
  sourceIp: string
  method: string
  path: string
  query: string
  artifact: string | null
  runId: string | null
  assignmentId: string | null
  canaryId: string | null
  receivedAt: number
  claimedBy: string | null
  detail: Record<string, unknown> | null
}

export interface OobRejection {
  event: 'oob_rejected'
  callbackId: string
  token: string | null
  reason: OobRejectionReason
  detail: Record<string, unknown> | null
  at: number
}

export type OobRecordResult =
  | { accepted: true; duplicate: false; callback: OobCallback }
  | { accepted: false; duplicate: false; rejection: OobRejection }
  | { accepted: true; duplicate: true; callback: OobCallback }

export interface OobPromotion {
  stage: 'immediate' | 'late'
  subscription: OobSubscription
  callback: OobCallback
  latencyMs: number
}

export interface OobCorrelationResult {
  matched: boolean
  stage: 'immediate' | 'pending'
  subscription: OobSubscription
  callback: OobCallback | null
}

export interface OobCheckResult {
  matched: boolean
  callbacks: OobCallback[]
  subscriptions: OobSubscription[]
  detail: OobCallback | null
}

export interface OobAwaitOptions {
  timeoutMs?: number
  pollMs?: number
  signal?: AbortSignal
}

export interface OobCorrelateOptions {
  immediateMs?: number
  pollMs?: number
  sleep?: (ms: number) => Promise<void>
  signal?: AbortSignal
}

export interface OobIpRateLimitResult {
  allowed: boolean
  sourceIp: string
  count: number
  limit: number
  resetAt: number
}

export interface OobQuotaTelemetry {
  totalDropped: number
  droppedPerToken: number
  droppedPerRun: number
  droppedProtected: number
  droppedPerIp: number
  pruneRuns: number
  prunedRows: number
  trackedSourceIps: number
  budgets: {
    maxCallbacksPerToken: number
    maxCallbacksPerRun: number
    maxProtectedCallbacks: number
    maxCallbacksPerIpWindow: number
    ipRateLimitWindowMs: number
    maxTrackedSourceIps: number
  }
}

export interface OobRelayStatus {
  mode: 'loopback' | 'public'
  publicEnabled: boolean
  pending: number
  delivered: number
  promoted: number
  expired: number
  rejected: number
  bindings: number
  lastCallbackAt: number | null
  immediateMs: number
  windowMs: number
  problems: string[]
  quota: OobQuotaTelemetry
}

export interface OobUnsubscribeRunResult {
  runId: string
  expiredSubscriptions: number
  removedBindings: number
}

export class OobProfileError extends Error {
  readonly problems: string[]
  constructor(message: string, problems: string[] = []) {
    super(message)
    this.name = 'OobProfileError'
    this.problems = problems
  }
}

const defaultImmediateMs = 3_000
const maxWindowMs = 30 * 60_000
export const defaultOobWindowMs = 15 * 60_000
const defaultDnsDomain = 'canary.kovo.invalid'
const callbackTokenPattern = /^(kovo-canary-[a-f0-9]{24}|gn2o_[a-f0-9]{8,16})$/
/** Separate bounded retention cap for historical claimed callbacks (`claimed_by IS NOT NULL`). */
export const MAX_STORED_CLAIMED_OOB_CALLBACKS = 15_000
/** Separate bounded retention cap for unclaimed callbacks (`claimed_by IS NULL`); active `pending_oob` tokens are never evicted. */
export const MAX_STORED_UNCLAIMED_OOB_CALLBACKS = 5_000
/** Default TTL for historical claimed callbacks (7 days). */
export const DEFAULT_CLAIMED_CALLBACK_TTL_MS = 7 * 24 * 60 * 60_000
/** Default TTL for orphaned unclaimed callbacks without an active `pending_oob` subscription (24 hours). */
export const DEFAULT_UNCLAIMED_CALLBACK_TTL_MS = 24 * 60 * 60_000
/** Bounded ring-cap for `oob_rejections` so external OOB spam cannot fill host disk. */
export const MAX_STORED_OOB_REJECTIONS = 5_000
const DEFAULT_IP_RATE_LIMIT_WINDOW_MS = 60_000
const DEFAULT_MAX_TRACKED_SOURCE_IPS = 4_096
const HARD_MAX_TRACKED_SOURCE_IPS = 65_536
const DEFAULT_PRUNE_BATCH_SIZE = 64
const DEFAULT_PRUNE_INTERVAL_MS = 5_000
const MAX_CACHED_TOKEN_COUNTS = 16_384
const MAX_CACHED_RUN_COUNTS = 4_096
const LRU_EXPIRED_PROBE_LIMIT = 8

interface IpWindowEntry {
  windowStart: number
  count: number
}

/**
 * Bounded-memory (LRU) per-IP fixed-window rate limiter for OOB callback ingest.
 *
 * Guarantees O(1) memory and O(1) time per check even under spoofed-IP floods:
 *  - Active entries are refreshed to the MRU tail on every access.
 *  - When full, up to `LRU_EXPIRED_PROBE_LIMIT` oldest entries are checked for expiry before
 *    evicting the least-recently-used entry.
 */
class BoundedIpRateLimiter {
  private readonly entries = new Map<string, IpWindowEntry>()
  readonly maxPerWindow: number
  readonly windowMs: number
  readonly maxTrackedIps: number

  constructor(options: { maxPerWindow: number; windowMs: number; maxTrackedIps: number }) {
    this.maxPerWindow = Math.max(1, Math.trunc(options.maxPerWindow))
    this.windowMs = Math.max(100, Math.trunc(options.windowMs))
    this.maxTrackedIps = Math.max(1, Math.min(HARD_MAX_TRACKED_SOURCE_IPS, Math.trunc(options.maxTrackedIps)))
  }

  get size(): number {
    return this.entries.size
  }

  consume(rawIp: string | undefined, now: number): OobIpRateLimitResult {
    const key = normalizeIp(rawIp) || '(unknown)'
    let entry = this.entries.get(key)
    if (entry) {
      // Refresh LRU position.
      this.entries.delete(key)
      if (now - entry.windowStart >= this.windowMs) {
        entry = { windowStart: now, count: 0 }
      }
      this.entries.set(key, entry)
    } else {
      if (this.entries.size >= this.maxTrackedIps) {
        this.evictOne(now)
      }
      entry = { windowStart: now, count: 0 }
      this.entries.set(key, entry)
    }

    const resetAt = entry.windowStart + this.windowMs
    if (entry.count >= this.maxPerWindow) {
      return {
        allowed: false,
        sourceIp: key,
        count: entry.count,
        limit: this.maxPerWindow,
        resetAt,
      }
    }
    entry.count += 1
    return {
      allowed: true,
      sourceIp: key,
      count: entry.count,
      limit: this.maxPerWindow,
      resetAt,
    }
  }

  private evictOne(now: number): void {
    let checked = 0
    let oldestKey: string | undefined
    for (const [k, v] of this.entries) {
      if (oldestKey === undefined) oldestKey = k
      if (now - v.windowStart >= this.windowMs) {
        this.entries.delete(k)
        return
      }
      checked += 1
      if (checked >= LRU_EXPIRED_PROBE_LIMIT) break
    }
    if (oldestKey !== undefined) {
      this.entries.delete(oldestKey)
    }
  }
}

interface SubscriptionRow {
  id: string
  run_id: string
  assignment_id: string
  canary_id: string
  token: string
  artifact: string
  protocol: string
  created_at: number
  immediate_ms: number
  window_ms: number
  expires_at: number
  status: string
  callback_id: string | null
  promoted_at: number | null
  allowlist: string | null
}

interface CallbackRow {
  callback_id: string
  token: string
  protocol: string
  source_ip: string
  remote_ip: string
  method: string
  path: string
  query: string | null
  artifact: string | null
  run_id: string | null
  assignment_id: string | null
  canary_id: string | null
  received_at: number
  claimed_by: string | null
  detail: string | null
}

interface BindingRow {
  token: string
  canary_id: string
  run_id: string
  assignment_id: string
  created_at: number
}

interface RejectionRow {
  callback_id: string
  token: string | null
  reason: string
  detail: string | null
  created_at: number
}

function parsePort(value: string | undefined, fallback: number): number {
  if (!value) return fallback
  const parsed = Number(value)
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 65_535 ? parsed : fallback
}

function normalizeDomain(value: string | undefined): string | null {
  if (!value) return null
  const trimmed = value.trim().toLowerCase().replace(/^\.+|\.+$/g, '')
  return trimmed || null
}

function normalizePublicBaseUrl(raw: string | undefined): string | null {
  if (!raw) return null
  const trimmed = raw.trim().replace(/\/+$/, '')
  if (!trimmed) return null
  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
    return `${parsed.origin}${parsed.pathname}`.replace(/\/+$/, '')
  } catch {
    return null
  }
}

function normalizeIp(raw: string | undefined): string {
  const ip = (raw ?? '').trim().toLowerCase()
  if (ip.startsWith('::ffff:') && ip.includes('.')) return ip.slice('::ffff:'.length)
  return ip
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const part of parts) {
    const n = Number(part)
    if (!Number.isInteger(n) || n < 0 || n > 255) return null
    out = (out << 8) | n
  }
  return out >>> 0
}

/** Exact IP, IPv4 CIDR, or `*` wildcard. IPv6 is compared textually. */
export function ipInAllowlist(rawIp: string | undefined, allowlist: readonly string[]): boolean {
  if (allowlist.length === 0) return true
  const ip = normalizeIp(rawIp)
  if (!ip) return false
  for (const entryRaw of allowlist) {
    const entry = entryRaw.trim().toLowerCase()
    if (!entry) continue
    if (entry === '*') return true
    const [base, bitsRaw] = entry.split('/')
    const bits = bitsRaw === undefined ? null : Number(bitsRaw)
    if (bits === null) {
      if (normalizeIp(base) === ip) return true
      continue
    }
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) continue
    const baseInt = ipv4ToInt(normalizeIp(base))
    const ipInt = ipv4ToInt(ip)
    if (baseInt === null || ipInt === null) continue
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0
    if ((baseInt & mask) === (ipInt & mask)) return true
  }
  return false
}

export function resolveOobRelayProfile(
  config: OobPublicRelayConfig = {},
  env: Record<string, string | undefined> = process.env,
): OobRelayProfile {
  const envEnabled = env.KOVO_OOB_PUBLIC === '1' || env.KOVO_OOB_PUBLIC?.toLowerCase() === 'true'
  const hasExplicitConfig = Boolean(
    config.enabled ||
    config.publicBaseUrl ||
    config.http ||
    config.https ||
    config.dns ||
    config.smtp ||
    envEnabled ||
    env.KOVO_OOB_PUBLIC_URL ||
    env.KOVO_OOB_TLS_CERT ||
    env.KOVO_OOB_TLS_KEY ||
    env.KOVO_OOB_DNS_TCP_PORT,
  )

  const publicBaseUrl = normalizePublicBaseUrl(
    config.publicBaseUrl ?? env.KOVO_OOB_PUBLIC_URL ?? env.KOVO_CANARY_PUBLIC_URL,
  )
  const domain = normalizeDomain(config.dns?.domain ?? env.KOVO_OOB_DNS_DOMAIN ?? env.KOVO_CANARY_DNS_DOMAIN)
  const acme = config.https?.acme ?? null
  const certPath = config.https?.certPath ?? env.KOVO_OOB_TLS_CERT ?? null
  const keyPath = config.https?.keyPath ?? env.KOVO_OOB_TLS_KEY ?? null
  const dnsProvider = config.dns?.provider ?? null
  const smtpProvider = config.smtp?.provider ?? null
  const allowlist = [...(config.allowlist ?? [])].map(entry => entry.trim()).filter(Boolean)

  if (!hasExplicitConfig) {
    return {
      mode: 'loopback',
      publicEnabled: false,
      publicBaseUrl: null,
      http: { host: '127.0.0.1', port: 0, enabled: true },
      https: {
        host: '127.0.0.1', port: 443, enabled: false, certificate: 'missing',
        acme: null, certPath: null, keyPath: null,
      },
      dns: {
        domain: domain ?? normalizeDomain(env.KOVO_CANARY_DNS_DOMAIN) ?? defaultDnsDomain,
        host: '127.0.0.1',
        udpPort: parsePort(env.KOVO_CANARY_DNS_PORT, 0),
        tcpPort: 0,
        authoritative: false,
        provider: dnsProvider,
      },
      smtp: { host: '127.0.0.1', port: 0, enabled: false, provider: smtpProvider },
      allowlist,
      problems: [],
    }
  }

  const problems: string[] = []
  const certificate: OobRelayProfile['https']['certificate'] =
    acme ? 'acme-hook' : (certPath && keyPath ? 'files' : 'missing')

  if (!publicBaseUrl) problems.push('public base URL is not configured (KOVO_OOB_PUBLIC_URL)')
  else if (!publicBaseUrl.startsWith('https://')) problems.push('public base URL must be https for external OOB callbacks')
  if (certificate === 'missing') problems.push('HTTPS certificate source is missing: provide ACME hooks or cert/key files')
  if (!domain) problems.push('authoritative DNS domain is not configured (KOVO_OOB_DNS_DOMAIN)')
  if (!dnsProvider) problems.push('authoritative DNS provider hook is not configured')
  if (config.dns && config.dns.tcpPort === undefined && env.KOVO_OOB_DNS_TCP_PORT === undefined) {
    // TCP DNS is advertised by an authoritative profile; default to 53 when unset is acceptable.
  }

  return {
    mode: 'public',
    publicEnabled: problems.length === 0,
    publicBaseUrl,
    http: {
      host: config.http?.host ?? env.KOVO_OOB_HTTP_HOST ?? '0.0.0.0',
      port: config.http?.port ?? parsePort(env.KOVO_OOB_HTTP_PORT, 80),
      enabled: true,
    },
    https: {
      host: config.https?.host ?? env.KOVO_OOB_HTTPS_HOST ?? '0.0.0.0',
      port: config.https?.port ?? parsePort(env.KOVO_OOB_HTTPS_PORT, 443),
      enabled: true,
      certificate,
      acme,
      certPath: certPath ?? null,
      keyPath: keyPath ?? null,
    },
    dns: {
      domain: domain ?? defaultDnsDomain,
      host: config.dns?.host ?? env.KOVO_OOB_DNS_HOST ?? '0.0.0.0',
      udpPort: config.dns?.udpPort ?? parsePort(env.KOVO_OOB_DNS_UDP_PORT, 53),
      tcpPort: config.dns?.tcpPort ?? parsePort(env.KOVO_OOB_DNS_TCP_PORT, 53),
      authoritative: Boolean(domain && dnsProvider),
      provider: dnsProvider,
    },
    smtp: {
      host: config.smtp?.host ?? env.KOVO_OOB_SMTP_HOST ?? '0.0.0.0',
      port: config.smtp?.port ?? parsePort(env.KOVO_OOB_SMTP_PORT, 25),
      enabled: Boolean(smtpProvider),
      provider: smtpProvider,
    },
    allowlist,
    problems,
  }
}

export function assertPublicProfileStartable(profile: OobRelayProfile): OobRelayProfile {
  if (profile.mode !== 'public' || !profile.publicEnabled) {
    throw new OobProfileError(
      'Public OOB relay profile is not enabled; set explicit operator configuration before opening public listeners.',
      profile.problems,
    )
  }
  return profile
}

function deriveCallbackId(input: OobCallbackInput): string {
  if (input.callbackId && input.callbackId.trim()) return input.callbackId.trim().slice(0, 128)
  const digest = createHash('sha256')
    .update(input.token)
    .update('|').update(input.protocol ?? 'http')
    .update('|').update(input.method ?? 'GET')
    .update('|').update(input.path ?? '')
    .update('|').update(input.query ?? '')
    .update('|').update(input.sourceIp ?? '')
    .update('|').update(input.artifact ?? '')
    .digest('hex')
    .slice(0, 24)
  return `oobc_${digest}`
}

function subscriptionFromRow(row: SubscriptionRow): OobSubscription {
  let allowlist: string[] = []
  if (row.allowlist) {
    try {
      const parsed = JSON.parse(row.allowlist)
      if (Array.isArray(parsed)) allowlist = parsed.filter((entry): entry is string => typeof entry === 'string')
    } catch { /* ignore malformed allowlist */ }
  }
  return {
    id: row.id,
    runId: row.run_id,
    assignmentId: row.assignment_id,
    canaryId: row.canary_id,
    token: row.token,
    artifact: row.artifact,
    protocol: (row.protocol === 'dns' || row.protocol === 'smtp' ? row.protocol : 'http'),
    status: row.status === 'promoted' || row.status === 'expired' ? row.status : 'pending',
    createdAt: row.created_at,
    immediateMs: row.immediate_ms,
    windowMs: row.window_ms,
    expiresAt: row.expires_at,
    promotedAt: row.promoted_at,
    callbackId: row.callback_id,
    allowlist,
  }
}

function callbackFromRow(row: CallbackRow): OobCallback {
  let detail: Record<string, unknown> | null = null
  if (row.detail) {
    try {
      const parsed = JSON.parse(row.detail)
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) detail = parsed as Record<string, unknown>
    } catch { /* ignore malformed detail */ }
  }
  return {
    callbackId: row.callback_id,
    token: row.token,
    protocol: row.protocol === 'dns' || row.protocol === 'smtp' ? row.protocol : 'http',
    sourceIp: row.source_ip || row.remote_ip,
    method: row.method,
    path: row.path,
    query: row.query ?? '',
    artifact: row.artifact,
    runId: row.run_id,
    assignmentId: row.assignment_id,
    canaryId: row.canary_id,
    receivedAt: row.received_at,
    claimedBy: row.claimed_by,
    detail,
  }
}

export interface OobRelayOptions {
  /** Store directory; when provided, `oob-relay.sqlite` makes relay state restart-safe. */
  directory?: string
  profile?: OobPublicRelayConfig
  env?: Record<string, string | undefined>
  now?: () => number
  immediateMs?: number
  windowMs?: number
  allowlist?: string[]
  /** Bounded cap for persisted `oob_rejections` rows (defaults to `MAX_STORED_OOB_REJECTIONS = 5000`). */
  maxRejections?: number
  /** Bounded cap for historical claimed `oob_callbacks` rows (`claimed_by IS NOT NULL`). */
  maxClaimedCallbacks?: number
  /** Bounded cap for unclaimed `oob_callbacks` rows (`claimed_by IS NULL`, excluding active `pending_oob` tokens). */
  maxUnclaimedCallbacks?: number
  /** Retention TTL (ms) for historical claimed callbacks (0 disables TTL eviction). */
  claimedCallbackTtlMs?: number
  /** Retention TTL (ms) for orphaned unclaimed callbacks (0 disables TTL eviction). */
  unclaimedCallbackTtlMs?: number
  /** Per-token persisted callback quota (`run-safety-budgets.ts` `oobMaxCallbacksPerToken`). */
  maxCallbacksPerToken?: number
  /** Per-run persisted callback quota (`run-safety-budgets.ts` `oobMaxCallbacksPerRun`). */
  maxCallbacksPerRun?: number
  /** Separate hard cap on total protected unclaimed callbacks across active `pending_oob` subscriptions. */
  maxProtectedCallbacks?: number
  /** Per-IP callback rate limit per window (`run-safety-budgets.ts` `oobMaxCallbacksPerIpWindow`). */
  maxCallbacksPerIpWindow?: number
  /** Window duration in ms for per-IP ingest rate limiting (defaults to 60_000 ms). */
  ipRateLimitWindowMs?: number
  /** Bounded LRU capacity for tracked source IPs in the per-IP rate limiter (defaults to 4_096). */
  maxTrackedSourceIps?: number
  /** Optional assignment count for scaling run-level OOB safety budgets. */
  maxAssignments?: number
  /** Amortized pruning cadence: accepted inserts/claims between prune sweeps (defaults to 64 for production caps). */
  pruneBatchSize?: number
  /** Amortized pruning cadence: minimum ms between prune sweeps (defaults to 5_000 ms). */
  pruneIntervalMs?: number
  logger?: (rejection: OobRejection) => void
}

export class OobRelay {
  readonly directory: string | null
  private readonly client: DatabaseSync
  private readonly ownsClient: boolean
  private readonly now: () => number
  private readonly options: OobRelayOptions
  private readonly profile: OobRelayProfile
  private readonly defaultImmediateMs: number
  private readonly defaultWindowMs: number
  private readonly defaultAllowlist: string[]
  private readonly maxStoredRejections: number
  private readonly maxClaimedCallbacks: number
  private readonly maxUnclaimedCallbacks: number
  private readonly claimedCallbackTtlMs: number
  private readonly unclaimedCallbackTtlMs: number
  private readonly maxCallbacksPerToken: number
  private readonly maxCallbacksPerRun: number
  private readonly maxProtectedCallbacks: number
  private readonly ipRateLimiter: BoundedIpRateLimiter
  private readonly pruneBatchSize: number
  private readonly pruneIntervalMs: number
  private readonly tokenCallbackCounts = new Map<string, number>()
  private readonly runCallbackCounts = new Map<string, number>()
  private protectedCallbackCount: number | null = null
  private opsSinceLastPrune = 0
  private lastPruneAt: number | null = null
  private droppedPerToken = 0
  private droppedPerRun = 0
  private droppedProtected = 0
  private droppedPerIp = 0
  private pruneRuns = 0
  private prunedRows = 0
  private closed = false

  constructor(options: OobRelayOptions = {}) {
    this.options = options
    this.directory = options.directory ?? null
    this.now = options.now ?? (() => Date.now())
    const env = options.env ?? process.env
    this.profile = resolveOobRelayProfile(options.profile, env)
    this.defaultImmediateMs = Math.max(0, options.immediateMs ?? defaultImmediateMs)
    this.defaultWindowMs = Math.min(Math.max(1_000, options.windowMs ?? defaultOobWindowMs), maxWindowMs)
    this.defaultAllowlist = [...(options.allowlist ?? [])]
    this.maxStoredRejections = Math.max(1, Math.trunc(options.maxRejections ?? MAX_STORED_OOB_REJECTIONS))
    this.maxClaimedCallbacks = Math.max(0, Math.trunc(options.maxClaimedCallbacks ?? MAX_STORED_CLAIMED_OOB_CALLBACKS))
    this.maxUnclaimedCallbacks = Math.max(1, Math.trunc(options.maxUnclaimedCallbacks ?? MAX_STORED_UNCLAIMED_OOB_CALLBACKS))
    this.claimedCallbackTtlMs = Math.max(0, Math.trunc(options.claimedCallbackTtlMs ?? DEFAULT_CLAIMED_CALLBACK_TTL_MS))
    this.unclaimedCallbackTtlMs = Math.max(0, Math.trunc(options.unclaimedCallbackTtlMs ?? DEFAULT_UNCLAIMED_CALLBACK_TTL_MS))

    const budgets = resolveRunSafetyBudgets({
      maxAssignments: options.maxAssignments,
      env,
      overrides: {
        ...(options.maxCallbacksPerToken !== undefined ? { oobMaxCallbacksPerToken: options.maxCallbacksPerToken } : {}),
        ...(options.maxCallbacksPerRun !== undefined ? { oobMaxCallbacksPerRun: options.maxCallbacksPerRun } : {}),
        ...(options.maxProtectedCallbacks !== undefined ? { oobMaxProtectedCallbacks: options.maxProtectedCallbacks } : {}),
        ...(options.maxCallbacksPerIpWindow !== undefined ? { oobMaxCallbacksPerIpWindow: options.maxCallbacksPerIpWindow } : {}),
      },
    })
    this.maxCallbacksPerToken = budgets.oobMaxCallbacksPerToken
    this.maxCallbacksPerRun = budgets.oobMaxCallbacksPerRun
    this.maxProtectedCallbacks = budgets.oobMaxProtectedCallbacks
    this.ipRateLimiter = new BoundedIpRateLimiter({
      maxPerWindow: budgets.oobMaxCallbacksPerIpWindow,
      windowMs: options.ipRateLimitWindowMs ?? DEFAULT_IP_RATE_LIMIT_WINDOW_MS,
      maxTrackedIps: options.maxTrackedSourceIps ?? DEFAULT_MAX_TRACKED_SOURCE_IPS,
    })

    const smallestRetentionCap = Math.min(
      Math.max(1, this.maxClaimedCallbacks),
      this.maxUnclaimedCallbacks,
    )
    const defaultBatch = Math.min(
      DEFAULT_PRUNE_BATCH_SIZE,
      Math.max(1, Math.floor(smallestRetentionCap / 4)),
    )
    this.pruneBatchSize = Math.max(1, Math.trunc(options.pruneBatchSize ?? defaultBatch))
    const positiveTtls = [this.claimedCallbackTtlMs, this.unclaimedCallbackTtlMs].filter(ttl => ttl > 0)
    const minTtl = positiveTtls.length > 0 ? Math.min(...positiveTtls) : DEFAULT_PRUNE_INTERVAL_MS
    this.pruneIntervalMs = Math.max(
      1,
      Math.trunc(options.pruneIntervalMs ?? Math.min(DEFAULT_PRUNE_INTERVAL_MS, minTtl)),
    )

    const path = this.directory ? join(this.directory, 'oob-relay.sqlite') : ':memory:'
    this.client = openSqliteDatabase(path, {
      busyTimeoutMs: SQLITE_DEFAULT_BUSY_TIMEOUT_MS,
      journalSizeLimitBytes: SQLITE_JOURNAL_SIZE_LIMIT_BYTES,
      foreignKeys: true,
    })
    this.ownsClient = true
    this.client.exec(`
      CREATE TABLE IF NOT EXISTS pending_oob (
        id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL,
        assignment_id TEXT NOT NULL,
        canary_id TEXT NOT NULL,
        token TEXT NOT NULL,
        artifact TEXT NOT NULL DEFAULT '',
        protocol TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        immediate_ms INTEGER NOT NULL,
        window_ms INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        status TEXT NOT NULL,
        callback_id TEXT,
        promoted_at INTEGER,
        allowlist TEXT
      );
      CREATE INDEX IF NOT EXISTS pending_oob_run ON pending_oob(run_id, status);
      CREATE INDEX IF NOT EXISTS pending_oob_token ON pending_oob(token, status);
      CREATE UNIQUE INDEX IF NOT EXISTS pending_oob_binding
        ON pending_oob(run_id, canary_id, artifact);
      CREATE TABLE IF NOT EXISTS oob_callbacks (
        callback_id TEXT PRIMARY KEY,
        token TEXT NOT NULL,
        protocol TEXT NOT NULL,
        source_ip TEXT NOT NULL DEFAULT '',
        remote_ip TEXT NOT NULL DEFAULT '',
        method TEXT NOT NULL DEFAULT 'GET',
        path TEXT NOT NULL DEFAULT '',
        query TEXT,
        artifact TEXT,
        run_id TEXT,
        assignment_id TEXT,
        canary_id TEXT,
        received_at INTEGER NOT NULL,
        claimed_by TEXT,
        detail TEXT
      );
      CREATE INDEX IF NOT EXISTS oob_callbacks_token ON oob_callbacks(token);
      CREATE INDEX IF NOT EXISTS oob_callbacks_run ON oob_callbacks(run_id);
      CREATE INDEX IF NOT EXISTS oob_callbacks_claim ON oob_callbacks(token, claimed_by);
      CREATE INDEX IF NOT EXISTS oob_callbacks_claim_received ON oob_callbacks(claimed_by, received_at);
      CREATE TABLE IF NOT EXISTS oob_bindings (
        token TEXT PRIMARY KEY,
        canary_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        assignment_id TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oob_rejections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        callback_id TEXT NOT NULL,
        token TEXT,
        reason TEXT NOT NULL,
        detail TEXT,
        created_at INTEGER NOT NULL
      );
    `)
  }

  /** Resolved relay profile (loopback by default, public only from explicit config). */
  relayProfile(): OobRelayProfile {
    return this.profile
  }

  /** Register the token↔canary binding so callbacks validate even before a subscription. */
  registerCanary(binding: { token: string; canaryId: string; runId: string; assignmentId?: string }): void {
    const runId = assertValidRunId(binding.runId, 'OobRelay.registerCanary')
    const token = binding.token.trim().toLowerCase()
    if (!callbackTokenPattern.test(token)) return
    this.assertOpen()
    this.client.prepare(`
      INSERT INTO oob_bindings (token, canary_id, run_id, assignment_id, created_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(token) DO UPDATE SET
        canary_id = excluded.canary_id,
        run_id = excluded.run_id,
        assignment_id = excluded.assignment_id
    `).run(token, binding.canaryId, runId, binding.assignmentId ?? 'canary-broker', this.now())
  }

  subscribe(input: OobSubscriptionInput): OobSubscription {
    this.assertOpen()
    const runId = assertValidRunId(input.runId, 'OobRelay.subscribe')
    const token = input.token.trim().toLowerCase()
    if (!callbackTokenPattern.test(token)) throw new Error(`Invalid OOB canary token: ${token.slice(0, 32)}`)
    const now = this.now()
    const immediateMs = Math.max(0, input.immediateMs ?? this.defaultImmediateMs)
    const windowMs = Math.min(Math.max(immediateMs, input.windowMs ?? this.defaultWindowMs), maxWindowMs)
    const allowlist = input.allowlist ?? (this.defaultAllowlist.length ? this.defaultAllowlist : this.profile.allowlist)
    return this.inImmediateTx(() => {
      const existing = this.client.prepare(
        'SELECT * FROM pending_oob WHERE run_id = ? AND canary_id = ? AND artifact = ?',
      ).get(runId, input.canaryId, input.artifact) as unknown as SubscriptionRow | undefined
      if (existing) {
        if (existing.status === 'pending') {
          const expiresAt = now + windowMs
          this.client.prepare(
            'UPDATE pending_oob SET expires_at = ?, window_ms = ?, immediate_ms = ? WHERE id = ?',
          ).run(expiresAt, windowMs, immediateMs, existing.id)
          return this.subscription(existing.id)
        }
        return subscriptionFromRow(existing)
      }

      const id = input.id?.trim() || `oob_${randomUUID()}`
      this.client.prepare(`
        INSERT INTO pending_oob (
          id, run_id, assignment_id, canary_id, token, artifact, protocol,
          created_at, immediate_ms, window_ms, expires_at, status, allowlist
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
      `).run(
        id, runId, input.assignmentId, input.canaryId, token, input.artifact,
        input.protocol ?? 'http', now, immediateMs, windowMs, now + windowMs,
        allowlist.length ? JSON.stringify(allowlist) : null,
      )
      this.protectedCallbackCount = null
      return this.subscription(id)
    })
  }

  /**
   * Unsubscribe and clean up all active OOB subscriptions, bindings, and in-flight drains
   * owned by `runId` (called deterministically from `RunContext.dispose()`).
   */
  unsubscribeRun(runId: string): OobUnsubscribeRunResult {
    const validRunId = assertValidRunId(runId, 'OobRelay.unsubscribeRun')
    cancelOobDrainForRun(validRunId)
    if (this.closed) {
      return { runId: validRunId, expiredSubscriptions: 0, removedBindings: 0 }
    }
    return this.inImmediateTx(() => {
      const expired = this.client.prepare(
        "UPDATE pending_oob SET status = 'expired' WHERE run_id = ? AND status = 'pending'",
      ).run(validRunId) as { changes?: number | bigint }
      const removed = this.client.prepare(
        'DELETE FROM oob_bindings WHERE run_id = ?',
      ).run(validRunId) as { changes?: number | bigint }
      this.protectedCallbackCount = null
      this.runCallbackCounts.delete(validRunId)
      return {
        runId: validRunId,
        expiredSubscriptions: Number(expired?.changes ?? 0),
        removedBindings: Number(removed?.changes ?? 0),
      }
    })
  }

  subscription(id: string): OobSubscription {
    const row = this.client.prepare('SELECT * FROM pending_oob WHERE id = ?').get(id) as unknown as SubscriptionRow | undefined
    if (!row) throw new Error(`Unknown OOB subscription: ${id}`)
    return subscriptionFromRow(row)
  }

  /**
   * Enforce the bounded-memory (LRU) per-IP ingest rate limit.
   * Shared as the single authoritative gate for both `CanaryBroker` listeners and direct `recordCallback()`.
   */
  consumeIpRateLimit(sourceIp: string | undefined, now = this.now()): OobIpRateLimitResult {
    const result = this.ipRateLimiter.consume(sourceIp, now)
    if (!result.allowed) {
      this.droppedPerIp += 1
      this.notifyQuotaOverflow({
        event: 'oob_rejected',
        callbackId: `oob_ip_rl_${result.sourceIp}`,
        token: null,
        reason: 'ip_rate_limited',
        detail: {
          sourceIp: result.sourceIp,
          count: result.count,
          limit: result.limit,
          resetAt: result.resetAt,
        },
        at: now,
      }, this.droppedPerIp)
    }
    return result
  }

  /** Structured quota and pruning telemetry (overflow counts, prune sweeps, bounded IP tracker size). */
  quotaTelemetry(): OobQuotaTelemetry {
    const totalDropped =
      this.droppedPerToken + this.droppedPerRun + this.droppedProtected + this.droppedPerIp
    return {
      totalDropped,
      droppedPerToken: this.droppedPerToken,
      droppedPerRun: this.droppedPerRun,
      droppedProtected: this.droppedProtected,
      droppedPerIp: this.droppedPerIp,
      pruneRuns: this.pruneRuns,
      prunedRows: this.prunedRows,
      trackedSourceIps: this.ipRateLimiter.size,
      budgets: {
        maxCallbacksPerToken: this.maxCallbacksPerToken,
        maxCallbacksPerRun: this.maxCallbacksPerRun,
        maxProtectedCallbacks: this.maxProtectedCallbacks,
        maxCallbacksPerIpWindow: this.ipRateLimiter.maxPerWindow,
        ipRateLimitWindowMs: this.ipRateLimiter.windowMs,
        maxTrackedSourceIps: this.ipRateLimiter.maxTrackedIps,
      },
    }
  }

  /**
   * Ingest a callback. Validates token↔canary binding, source allowlist, causal artifact,
   * per-IP rate limit, and per-token/per-run/protected quotas BEFORE inserting into SQLite.
   * Validation rejections are persisted as `oob_rejected` events; quota/rate-limit overflows
   * are counted in structured telemetry without writing unbounded rows.
   */
  recordCallback(
    input: OobCallbackInput,
    options?: { ipRateLimitAlreadyConsumed?: boolean },
  ): OobRecordResult {
    this.assertOpen()
    const now = this.now()
    const token = input.token.trim().toLowerCase()
    const callbackId = deriveCallbackId({ ...input, token })
    const sourceIp = normalizeIp(input.sourceIp)
    const artifact = input.artifact?.trim() || null
    const reject = (reason: OobRejectionReason, detail?: Record<string, unknown>): OobRecordResult => {
      const rejection: OobRejection = {
        event: 'oob_rejected',
        callbackId,
        token: token || null,
        reason,
        detail: detail ?? null,
        at: now,
      }
      try {
        this.inImmediateTx(() => {
          this.client.prepare(
            'INSERT INTO oob_rejections (callback_id, token, reason, detail, created_at) VALUES (?, ?, ?, ?, ?)',
          ).run(callbackId, token || null, reason, detail ? JSON.stringify(detail) : null, now)
          this.pruneRejections()
        })
      } catch { /* rejection logging is best-effort */ }
      this.options.logger?.(rejection)
      return { accepted: false, duplicate: false, rejection }
    }

    const rejectQuota = (
      reason: 'token_quota_exceeded' | 'run_quota_exceeded' | 'protected_quota_exceeded' | 'ip_rate_limited',
      detail: Record<string, unknown>,
      counter: number,
    ): OobRecordResult => {
      const rejection: OobRejection = {
        event: 'oob_rejected',
        callbackId,
        token: token || null,
        reason,
        detail,
        at: now,
      }
      this.notifyQuotaOverflow(rejection, counter)
      return { accepted: false, duplicate: false, rejection }
    }

    if (!callbackTokenPattern.test(token)) {
      return reject('invalid_token')
    }

    if (!options?.ipRateLimitAlreadyConsumed) {
      const rate = this.ipRateLimiter.consume(sourceIp, now)
      if (!rate.allowed) {
        this.droppedPerIp += 1
        return rejectQuota(
          'ip_rate_limited',
          { sourceIp: rate.sourceIp, count: rate.count, limit: rate.limit, resetAt: rate.resetAt },
          this.droppedPerIp,
        )
      }
    }

    const binding = this.client.prepare('SELECT * FROM oob_bindings WHERE token = ?')
      .get(token) as unknown as BindingRow | undefined
    const declaredCanary = input.canaryId?.trim() || null
    if (declaredCanary && binding && binding.canary_id !== declaredCanary) {
      return reject('token_mismatch', { declaredCanaryId: declaredCanary, boundCanaryId: binding.canary_id })
    }
    if (declaredCanary) {
      const bound = this.client.prepare('SELECT * FROM oob_bindings WHERE canary_id = ?')
        .get(declaredCanary) as unknown as BindingRow | undefined
      if (bound && bound.token !== token) {
        return reject('token_mismatch', { declaredCanaryId: declaredCanary, boundToken: bound.token })
      }
    }

    const known = Boolean(binding) || this.client.prepare(
      "SELECT 1 AS ok FROM pending_oob WHERE token = ? AND status = 'pending' LIMIT 1",
    ).get(token)
    if (!known) return reject('unknown_token')

    const subscriptions = this.subscriptionsForToken(token).filter(sub => sub.status === 'pending')
    const allowlist = subscriptions.flatMap(sub => sub.allowlist)
    const effectiveAllowlist = allowlist.length > 0 ? allowlist : this.defaultAllowlist
    if (!ipInAllowlist(sourceIp, effectiveAllowlist)) {
      return reject('source_not_allowlisted', { sourceIp })
    }
    const artifactSubscriptions = subscriptions.filter(sub => sub.artifact)
    if (artifactSubscriptions.length > 0) {
      if (!artifact) return reject('artifact_missing', { subscriptionId: artifactSubscriptions[0].id })
      if (!artifactSubscriptions.some(sub => sub.artifact === artifact)) {
        return reject('artifact_mismatch', { expected: artifactSubscriptions.map(sub => sub.artifact) })
      }
    }

    // Idempotency check BEFORE storage quotas: redelivery of an already-persisted callback succeeds without consuming quota.
    const existing = this.callback(callbackId)
    if (existing) {
      return { accepted: true, duplicate: true, callback: existing }
    }

    const resolvedRunId = binding?.run_id ?? subscriptions[0]?.runId ?? input.runId ?? null
    const isProtected = subscriptions.length > 0

    // Quota-first ingest enforcement BEFORE writing to SQLite.
    const tokenCount = this.getTokenCallbackCount(token)
    if (tokenCount >= this.maxCallbacksPerToken) {
      this.droppedPerToken += 1
      return rejectQuota(
        'token_quota_exceeded',
        { count: tokenCount, limit: this.maxCallbacksPerToken },
        this.droppedPerToken,
      )
    }
    let runCount = 0
    if (resolvedRunId) {
      runCount = this.getRunCallbackCount(resolvedRunId)
      if (runCount >= this.maxCallbacksPerRun) {
        this.droppedPerRun += 1
        return rejectQuota(
          'run_quota_exceeded',
          { runId: resolvedRunId, count: runCount, limit: this.maxCallbacksPerRun },
          this.droppedPerRun,
        )
      }
    }
    let protectedCount = 0
    if (isProtected) {
      protectedCount = this.getProtectedCallbackCount()
      if (protectedCount >= this.maxProtectedCallbacks) {
        this.droppedProtected += 1
        return rejectQuota(
          'protected_quota_exceeded',
          { count: protectedCount, limit: this.maxProtectedCallbacks },
          this.droppedProtected,
        )
      }
    }

    const row: CallbackRow = {
      callback_id: callbackId,
      token,
      protocol: input.protocol ?? 'http',
      source_ip: sourceIp,
      remote_ip: sourceIp,
      method: (input.method ?? 'GET').toUpperCase().slice(0, 16),
      path: (input.path ?? '').slice(0, 512),
      query: input.query?.slice(0, 512) ?? null,
      artifact,
      run_id: resolvedRunId,
      assignment_id: binding?.assignment_id ?? subscriptions[0]?.assignmentId ?? input.assignmentId ?? null,
      canary_id: declaredCanary ?? binding?.canary_id ?? subscriptions[0]?.canaryId ?? null,
      received_at: input.receivedAt ?? now,
      claimed_by: null,
      detail: input.detail ? JSON.stringify(input.detail) : null,
    }

    const inserted = this.client.prepare(`
      INSERT OR IGNORE INTO oob_callbacks (
        callback_id, token, protocol, source_ip, remote_ip, method, path, query,
        artifact, run_id, assignment_id, canary_id, received_at, claimed_by, detail
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)
    `).run(
      row.callback_id, row.token, row.protocol, row.source_ip, row.remote_ip, row.method,
      row.path, row.query, row.artifact, row.run_id, row.assignment_id, row.canary_id,
      row.received_at, row.detail,
    ) as { changes?: number | bigint }
    const callback = this.callback(callbackId)
    if (!callback) return reject('unknown_token')
    if (!inserted || Number(inserted.changes ?? 0) === 0) {
      return { accepted: true, duplicate: true, callback }
    }
    this.setCachedCount(this.tokenCallbackCounts, token, tokenCount + 1, MAX_CACHED_TOKEN_COUNTS)
    if (resolvedRunId) {
      this.setCachedCount(this.runCallbackCounts, resolvedRunId, runCount + 1, MAX_CACHED_RUN_COUNTS)
    }
    if (isProtected) {
      this.protectedCallbackCount = protectedCount + 1
    }
    this.maybePruneCallbacks(now, callbackId)
    return { accepted: true, duplicate: false, callback }
  }

  callback(callbackId: string): OobCallback | null {
    const row = this.client.prepare('SELECT * FROM oob_callbacks WHERE callback_id = ?')
      .get(callbackId) as unknown as CallbackRow | undefined
    return row ? callbackFromRow(row) : null
  }

  callbacksForToken(token: string, limit?: number): OobCallback[] {
    const normalized = token.trim().toLowerCase()
    const effectiveLimit = Math.max(
      1,
      Math.min(
        Math.trunc(limit ?? this.maxCallbacksPerToken),
        RUN_SAFETY_BUDGET_HARD_CEILINGS.oobMaxCallbacksPerToken,
      ),
    )
    const rows = this.client.prepare(
      'SELECT * FROM oob_callbacks WHERE token = ? ORDER BY received_at ASC LIMIT ?',
    ).all(normalized, effectiveLimit) as unknown as CallbackRow[]
    return rows.map(callbackFromRow)
  }

  subscriptionsForToken(token: string): OobSubscription[] {
    const normalized = token.trim().toLowerCase()
    const rows = this.client.prepare(
      'SELECT * FROM pending_oob WHERE token = ? ORDER BY created_at ASC',
    ).all(normalized) as unknown as SubscriptionRow[]
    return rows.map(subscriptionFromRow)
  }

  hasSubscription(token: string): boolean {
    return Boolean(this.client.prepare(
      'SELECT 1 AS ok FROM pending_oob WHERE token = ? AND status = ? LIMIT 1',
    ).get(token.trim().toLowerCase(), 'pending'))
  }

  /** Active durable subscriptions (optionally scoped to a run). */
  pending(runId?: string): OobSubscription[] {
    const rows = runId
      ? this.client.prepare(
          'SELECT * FROM pending_oob WHERE status = ? AND run_id = ? ORDER BY created_at ASC',
        ).all('pending', runId) as unknown as SubscriptionRow[]
      : this.client.prepare(
          'SELECT * FROM pending_oob WHERE status = ? ORDER BY created_at ASC',
        ).all('pending') as unknown as SubscriptionRow[]
    return rows.map(subscriptionFromRow)
  }

  check(query: {
    token?: string
    callbackId?: string
    runId?: string
    canaryId?: string
    assignmentId?: string
  }): OobCheckResult {
    const callbacks: OobCallback[] = []
    if (query.callbackId) {
      const callback = this.callback(query.callbackId)
      if (callback) callbacks.push(callback)
    } else if (query.token) {
      callbacks.push(...this.callbacksForToken(query.token))
    } else if (query.canaryId) {
      const rows = this.client.prepare(
        'SELECT * FROM oob_callbacks WHERE canary_id = ? ORDER BY received_at ASC LIMIT ?',
      ).all(query.canaryId, this.maxCallbacksPerToken) as unknown as CallbackRow[]
      callbacks.push(...rows.map(callbackFromRow))
    } else if (query.runId) {
      const rows = this.client.prepare(
        'SELECT * FROM oob_callbacks WHERE run_id = ? ORDER BY received_at ASC LIMIT ?',
      ).all(query.runId, this.maxCallbacksPerRun) as unknown as CallbackRow[]
      callbacks.push(...rows.map(callbackFromRow))
    }
    const filtered = callbacks.filter(callback => {
      if (query.runId && callback.runId !== query.runId) return false
      if (query.assignmentId && callback.assignmentId !== query.assignmentId) return false
      if (query.canaryId && callback.canaryId !== query.canaryId) return false
      return true
    })
    const subscriptions = query.token ? this.subscriptionsForToken(query.token) : []
    return {
      matched: filtered.length > 0,
      callbacks: filtered,
      subscriptions,
      detail: filtered.length > 0 ? filtered[filtered.length - 1] : null,
    }
  }

  /**
   * Two-stage correlation: short immediate window, then a durable subscription.
   * The immediate poll is bounded (default 3 s) and the subscription covers the rest of the
   * configured window (default 15 min), promoting late callbacks on `promoteLate()`.
   */
  async correlate(input: OobSubscriptionInput, options: OobCorrelateOptions = {}): Promise<OobCorrelationResult> {
    const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => { setTimeout(resolve, ms) }))
    const pollMs = Math.max(15, options.pollMs ?? 150)
    const immediateMs = Math.max(0, options.immediateMs ?? input.immediateMs ?? this.defaultImmediateMs)
    const subscription = this.subscribe({ ...input, immediateMs })
    const deadline = this.now() + immediateMs
    const existing = this.callbacksForToken(subscription.token)
      .find(callback => callback.claimedBy === null && this.matchesSubscription(subscription, callback))
    if (existing) {
      const promotion = this.claim(subscription, existing, this.now())
      if (promotion.subscription.status === 'promoted' && promotion.subscription.callbackId === existing.callbackId) {
        return {
          matched: true,
          stage: 'immediate',
          subscription: promotion.subscription,
          callback: promotion.callback,
        }
      }
    }
    while (this.now() < deadline) {
      if (options.signal?.aborted) break
      await sleep(Math.min(pollMs, Math.max(0, deadline - this.now())))
      const late = this.callbacksForToken(subscription.token)
        .find(callback => callback.claimedBy === null && this.matchesSubscription(subscription, callback))
      if (late) {
        const promotion = this.claim(subscription, late, this.now())
        if (promotion.subscription.status === 'promoted' && promotion.subscription.callbackId === late.callbackId) {
          return {
            matched: true,
            stage: 'immediate',
            subscription: promotion.subscription,
            callback: promotion.callback,
          }
        }
      }
    }
    return { matched: false, stage: 'pending', subscription: this.subscription(subscription.id), callback: null }
  }

  /** Poll until a callback arrives or the timeout elapses. */
  async awaitAny(
    query: { token?: string; canaryId?: string; runId?: string; assignmentId?: string },
    options: OobAwaitOptions = {},
  ): Promise<{ matched: boolean; callback: OobCallback | null }> {
    const timeoutMs = Math.max(0, options.timeoutMs ?? this.defaultImmediateMs)
    const pollMs = Math.max(15, options.pollMs ?? 100)
    const started = Date.now()
    for (;;) {
      const result = this.check(query)
      if (result.matched) return { matched: true, callback: result.detail }
      if (options.signal?.aborted) return { matched: false, callback: null }
      if (Date.now() - started >= timeoutMs) return { matched: false, callback: null }
      await new Promise<void>(resolve => { setTimeout(resolve, Math.min(pollMs, timeoutMs)) })
    }
  }

  /**
   * Promote late callbacks into verified candidates. Idempotent: a subscription is promoted
   * once and a callback can be claimed by at most one subscription.
   */
  promoteLate(options: { runId?: string; now?: number; maxCallbacksPerToken?: number } = {}): OobPromotion[] {
    this.assertOpen()
    const now = options.now ?? this.now()
    const callbackLimit = Math.max(
      1,
      Math.min(
        Math.trunc(options.maxCallbacksPerToken ?? this.maxCallbacksPerToken),
        RUN_SAFETY_BUDGET_HARD_CEILINGS.oobMaxCallbacksPerToken,
      ),
    )
    const rows = options.runId
      ? this.client.prepare(
          'SELECT * FROM pending_oob WHERE status = ? AND run_id = ? ORDER BY created_at ASC',
        ).all('pending', options.runId) as unknown as SubscriptionRow[]
      : this.client.prepare(
          'SELECT * FROM pending_oob WHERE status = ? ORDER BY created_at ASC',
        ).all('pending') as unknown as SubscriptionRow[]

    const promotions: OobPromotion[] = []
    let expiredAny = false
    for (const row of rows) {
      const subscription = subscriptionFromRow(row)
      const callbacks = this.client.prepare(
        'SELECT * FROM oob_callbacks WHERE token = ? AND claimed_by IS NULL ORDER BY received_at ASC LIMIT ?',
      ).all(subscription.token, callbackLimit) as unknown as CallbackRow[]
      const candidate = callbacks
        .map(callbackFromRow)
        .find(callback => this.matchesSubscription(subscription, callback))
      if (candidate) {
        const promotion = this.claim(subscription, candidate, now)
        if (promotion.subscription.status === 'promoted' && promotion.subscription.callbackId === candidate.callbackId) {
          promotions.push(promotion)
        }
        continue
      }
      if (now > subscription.expiresAt) {
        const exp = this.client.prepare('UPDATE pending_oob SET status = ? WHERE id = ? AND status = ?')
          .run('expired', subscription.id, 'pending') as { changes?: number | bigint }
        if (Number(exp?.changes ?? 0) > 0) expiredAny = true
      }
    }
    if (expiredAny) {
      this.protectedCallbackCount = null
    }
    return promotions
  }

  private matchesSubscription(subscription: OobSubscription, callback: OobCallback): boolean {
    if (callback.runId && callback.runId !== subscription.runId) return false
    if (callback.receivedAt > subscription.expiresAt) return false
    if (subscription.artifact && callback.artifact !== subscription.artifact) return false
    if (subscription.allowlist.length > 0 && !ipInAllowlist(callback.sourceIp, subscription.allowlist)) return false
    return true
  }

  private claim(subscription: OobSubscription, callback: OobCallback, now: number): OobPromotion {
    let claimed = false
    withBusyRetry(() => this.client.exec('BEGIN IMMEDIATE'))
    try {
      const subUpdated = this.client.prepare(
        "UPDATE pending_oob SET status = 'promoted', callback_id = ?, promoted_at = ? WHERE id = ? AND status = 'pending'",
      ).run(callback.callbackId, now, subscription.id) as { changes?: number | bigint }
      if (Number(subUpdated?.changes ?? 0) > 0) {
        const cbUpdated = this.client.prepare(
          'UPDATE oob_callbacks SET claimed_by = ? WHERE callback_id = ? AND claimed_by IS NULL',
        ).run(subscription.id, callback.callbackId) as { changes?: number | bigint }
        if (Number(cbUpdated?.changes ?? 0) === 0) {
          this.client.exec('ROLLBACK')
          const current = this.subscription(subscription.id)
          const currentCb = this.callback(callback.callbackId) ?? callback
          return {
            stage: now - subscription.createdAt <= subscription.immediateMs ? 'immediate' : 'late',
            subscription: current,
            callback: currentCb,
            latencyMs: Math.max(0, callback.receivedAt - subscription.createdAt),
          }
        }
        claimed = true
      }
      withBusyRetry(() => this.client.exec('COMMIT'))
    } catch (err) {
      try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
      throw err
    }
    if (claimed) {
      this.protectedCallbackCount = null
      this.maybePruneCallbacks(now, callback.callbackId)
    }
    const updated = this.subscription(subscription.id)
    const updatedCb = this.callback(callback.callbackId) ?? callback
    return {
      stage: now - subscription.createdAt <= subscription.immediateMs ? 'immediate' : 'late',
      subscription: updated,
      callback: updatedCb,
      latencyMs: Math.max(0, callback.receivedAt - subscription.createdAt),
    }
  }

  rejections(limit = 50): OobRejection[] {
    const rows = this.client.prepare(
      'SELECT * FROM oob_rejections ORDER BY id DESC LIMIT ?',
    ).all(Math.max(1, Math.min(1_000, limit))) as unknown as RejectionRow[]
    return rows.map(row => ({
      event: 'oob_rejected',
      callbackId: row.callback_id,
      token: row.token,
      reason: row.reason as OobRejectionReason,
      detail: row.detail ? JSON.parse(row.detail) as Record<string, unknown> : null,
      at: row.created_at,
    }))
  }

  /** Compact status for the board / executor. */
  status(): OobRelayStatus {
    const count = (sql: string): number => {
      const row = this.client.prepare(sql).get() as unknown as { n: number | bigint } | undefined
      return Number(row?.n ?? 0)
    }
    const last = this.client.prepare('SELECT MAX(received_at) AS at FROM oob_callbacks')
      .get() as unknown as { at: number | null } | undefined
    return {
      mode: this.profile.mode,
      publicEnabled: this.profile.publicEnabled,
      pending: count("SELECT COUNT(*) AS n FROM pending_oob WHERE status = 'pending'"),
      delivered: count('SELECT COUNT(*) AS n FROM oob_callbacks'),
      promoted: count("SELECT COUNT(*) AS n FROM pending_oob WHERE status = 'promoted'"),
      expired: count("SELECT COUNT(*) AS n FROM pending_oob WHERE status = 'expired'"),
      rejected: count('SELECT COUNT(*) AS n FROM oob_rejections'),
      bindings: count('SELECT COUNT(*) AS n FROM oob_bindings'),
      lastCallbackAt: last?.at ?? null,
      immediateMs: this.defaultImmediateMs,
      windowMs: this.defaultWindowMs,
      problems: [...this.profile.problems],
      quota: this.quotaTelemetry(),
    }
  }

  /** Run a retention prune sweep immediately and return the number of rows evicted. */
  pruneNow(now = this.now()): number {
    this.assertOpen()
    this.opsSinceLastPrune = 0
    this.lastPruneAt = now
    return this.pruneCallbacks(now)
  }

  /** Resolve an authoritative DNS query through the configured provider hook. */
  async resolveDns(query: OobDnsQuery): Promise<OobDnsAnswer | null> {
    const provider = this.profile.dns.provider
    if (!provider) return null
    return await provider.resolve(query)
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    if (!this.ownsClient) return
    try {
      this.client.close()
    } catch { /* already closed */ }
  }

  private assertOpen(): void {
    if (this.closed) throw new Error('OOB relay is closed.')
  }

  private inImmediateTx<T>(fn: () => T): T {
    withBusyRetry(() => this.client.exec('BEGIN IMMEDIATE'))
    try {
      const result = fn()
      withBusyRetry(() => this.client.exec('COMMIT'))
      return result
    } catch (error) {
      try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
      throw error
    }
  }

  private pruneRejections(): void {
    this.client.prepare(`
      DELETE FROM oob_rejections
      WHERE id <= (
        SELECT id FROM oob_rejections ORDER BY id DESC LIMIT 1 OFFSET ?
      )
    `).run(this.maxStoredRejections)
  }

  private notifyQuotaOverflow(rejection: OobRejection, countForReason: number): void {
    // Emit structured logger notifications on powers of 10 (1, 10, 100, 1000, ...) so floods
    // never spam stderr while operators still see first-hit and order-of-magnitude escalation.
    if (
      this.options.logger &&
      (countForReason === 1 ||
        countForReason === 10 ||
        countForReason === 100 ||
        countForReason % 1_000 === 0)
    ) {
      this.options.logger(rejection)
    }
  }

  private setCachedCount(cache: Map<string, number>, key: string, value: number, maxEntries: number): void {
    if (cache.has(key)) {
      cache.delete(key)
    } else if (cache.size >= maxEntries) {
      const oldest = cache.keys().next().value
      if (oldest !== undefined) cache.delete(oldest)
    }
    cache.set(key, value)
  }

  private getTokenCallbackCount(token: string): number {
    const cached = this.tokenCallbackCounts.get(token)
    if (cached !== undefined) return cached
    const row = this.client.prepare(
      'SELECT COUNT(*) AS n FROM oob_callbacks WHERE token = ?',
    ).get(token) as unknown as { n: number | bigint } | undefined
    const count = Number(row?.n ?? 0)
    this.setCachedCount(this.tokenCallbackCounts, token, count, MAX_CACHED_TOKEN_COUNTS)
    return count
  }

  private getRunCallbackCount(runId: string): number {
    const cached = this.runCallbackCounts.get(runId)
    if (cached !== undefined) return cached
    const row = this.client.prepare(
      'SELECT COUNT(*) AS n FROM oob_callbacks WHERE run_id = ?',
    ).get(runId) as unknown as { n: number | bigint } | undefined
    const count = Number(row?.n ?? 0)
    this.setCachedCount(this.runCallbackCounts, runId, count, MAX_CACHED_RUN_COUNTS)
    return count
  }

  private getProtectedCallbackCount(): number {
    if (this.protectedCallbackCount !== null) return this.protectedCallbackCount
    const row = this.client.prepare(`
      SELECT COUNT(*) AS n FROM oob_callbacks c
      WHERE c.claimed_by IS NULL
        AND EXISTS (
          SELECT 1 FROM pending_oob p
          WHERE p.token = c.token AND p.status = 'pending'
        )
    `).get() as unknown as { n: number | bigint } | undefined
    const count = Number(row?.n ?? 0)
    this.protectedCallbackCount = count
    return count
  }

  private invalidateQuotaCaches(): void {
    this.tokenCallbackCounts.clear()
    this.runCallbackCounts.clear()
    this.protectedCallbackCount = null
  }

  /**
   * Amortized / interval-gated pruning trigger: avoids running synchronous SQLite retention
   * sweeps on every insert/claim while bounding excess rows to at most `pruneBatchSize`.
   */
  private maybePruneCallbacks(now: number, protectedCallbackId?: string): void {
    this.opsSinceLastPrune += 1
    const elapsed = this.lastPruneAt === null ? 0 : Math.max(0, now - this.lastPruneAt)
    if (this.lastPruneAt === null) {
      this.lastPruneAt = now
    }
    if (this.opsSinceLastPrune < this.pruneBatchSize && elapsed < this.pruneIntervalMs) {
      return
    }
    this.opsSinceLastPrune = 0
    this.lastPruneAt = now
    this.pruneCallbacks(now, protectedCallbackId)
  }

  /**
   * Enforce independent retention caps and TTLs for historical claimed rows (`claimed_by IS NOT NULL`)
   * vs. orphaned unprotected unclaimed rows (`claimed_by IS NULL` without an active `pending_oob`).
   *
   * Critical invariants:
   * - Historical claimed rows are pruned ONLY against `maxClaimedCallbacks` / `claimedCallbackTtlMs`
   *   (oldest first) and can NEVER trigger eviction of unclaimed rows.
   * - Protected unclaimed rows matching an active `pending_oob` subscription (`status = 'pending'`)
   *   are bounded separately at ingest by `maxProtectedCallbacks` and are excluded from the
   *   unprotected unclaimed count so they never trigger wasted O(n) anti-join prune scans.
   */
  private pruneCallbacks(now = this.now(), protectedCallbackId?: string): number {
    const protectedId = protectedCallbackId ?? null
    this.pruneRuns += 1
    const deleted = this.inImmediateTx(() => {
      let totalDeleted = 0

      // 1. Historical claimed rows (`claimed_by IS NOT NULL`): TTL first, then bounded oldest-first cap.
      if (this.claimedCallbackTtlMs > 0) {
        const cutoff = now - this.claimedCallbackTtlMs
        const res = this.client.prepare(`
          DELETE FROM oob_callbacks
          WHERE claimed_by IS NOT NULL
            AND received_at < ?
            AND (? IS NULL OR callback_id != ?)
        `).run(cutoff, protectedId, protectedId) as { changes?: number | bigint }
        totalDeleted += Number(res?.changes ?? 0)
      }
      const claimedRow = this.client.prepare(
        'SELECT COUNT(*) AS n FROM oob_callbacks WHERE claimed_by IS NOT NULL',
      ).get() as unknown as { n: number | bigint } | undefined
      const claimedTotal = Number(claimedRow?.n ?? 0)
      if (claimedTotal > this.maxClaimedCallbacks) {
        const res = this.client.prepare(`
          DELETE FROM oob_callbacks
          WHERE callback_id IN (
            SELECT callback_id FROM oob_callbacks
            WHERE claimed_by IS NOT NULL
              AND (? IS NULL OR callback_id != ?)
            ORDER BY received_at ASC, rowid ASC
            LIMIT ?
          )
        `).run(protectedId, protectedId, claimedTotal - this.maxClaimedCallbacks) as { changes?: number | bigint }
        totalDeleted += Number(res?.changes ?? 0)
      }

      // 2. Orphaned unclaimed rows (`claimed_by IS NULL` with NO active pending_oob subscription):
      //    protected pending rows are enforced by `maxProtectedCallbacks` at ingest and excluded here.
      if (this.unclaimedCallbackTtlMs > 0) {
        const unclaimedCutoff = now - this.unclaimedCallbackTtlMs
        const res = this.client.prepare(`
          DELETE FROM oob_callbacks
          WHERE claimed_by IS NULL
            AND received_at < ?
            AND (? IS NULL OR callback_id != ?)
            AND NOT EXISTS (
              SELECT 1 FROM pending_oob p
              WHERE p.token = oob_callbacks.token AND p.status = 'pending'
            )
        `).run(unclaimedCutoff, protectedId, protectedId) as { changes?: number | bigint }
        totalDeleted += Number(res?.changes ?? 0)
      }
      const unprotectedRow = this.client.prepare(`
        SELECT COUNT(*) AS n FROM oob_callbacks c
        WHERE c.claimed_by IS NULL
          AND NOT EXISTS (
            SELECT 1 FROM pending_oob p
            WHERE p.token = c.token AND p.status = 'pending'
          )
      `).get() as unknown as { n: number | bigint } | undefined
      const unprotectedTotal = Number(unprotectedRow?.n ?? 0)
      if (unprotectedTotal > this.maxUnclaimedCallbacks) {
        const res = this.client.prepare(`
          DELETE FROM oob_callbacks
          WHERE callback_id IN (
            SELECT c.callback_id FROM oob_callbacks c
            WHERE c.claimed_by IS NULL
              AND (? IS NULL OR c.callback_id != ?)
              AND NOT EXISTS (
                SELECT 1 FROM pending_oob p
                WHERE p.token = c.token AND p.status = 'pending'
              )
            ORDER BY c.received_at ASC, c.rowid ASC
            LIMIT ?
          )
        `).run(protectedId, protectedId, unprotectedTotal - this.maxUnclaimedCallbacks) as { changes?: number | bigint }
        totalDeleted += Number(res?.changes ?? 0)
      }

      return totalDeleted
    })

    if (deleted > 0) {
      this.prunedRows += deleted
      this.invalidateQuotaCaches()
    }
    return deleted
  }
}

/** Compact board-safe summary: no tokens, artifacts, or callback payloads. */
export function summarizeOobRelayStatus(status: OobRelayStatus): Record<string, unknown> {
  return {
    mode: status.mode,
    publicEnabled: status.publicEnabled,
    pending: status.pending,
    delivered: status.delivered,
    promoted: status.promoted,
    expired: status.expired,
    rejected: status.rejected,
    quotaDropped: status.quota.totalDropped,
    lastCallbackAt: status.lastCallbackAt,
    windowMs: status.windowMs,
    immediateMs: status.immediateMs,
    problems: status.problems.length,
  }
}
