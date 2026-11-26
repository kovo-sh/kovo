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
import { chmodSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { cancelOobDrainForRun } from './oob-drain.ts'
import { assertValidRunId } from './run-context.ts'

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
const maxStoredCallbacks = 20_000

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
  private closed = false

  constructor(options: OobRelayOptions = {}) {
    this.options = options
    this.directory = options.directory ?? null
    this.now = options.now ?? (() => Date.now())
    this.profile = resolveOobRelayProfile(options.profile, options.env ?? process.env)
    this.defaultImmediateMs = Math.max(0, options.immediateMs ?? defaultImmediateMs)
    this.defaultWindowMs = Math.min(Math.max(1_000, options.windowMs ?? defaultOobWindowMs), maxWindowMs)
    this.defaultAllowlist = [...(options.allowlist ?? [])]

    const path = this.directory ? join(this.directory, 'oob-relay.sqlite') : ':memory:'
    if (this.directory) mkdirSync(this.directory, { recursive: true, mode: 0o700 })
    this.client = new DatabaseSync(path, { timeout: 5_000 })
    this.ownsClient = true
    if (this.directory) {
      try {
        chmodSync(path, 0o600)
      } catch { /* best-effort owner-only permissions */ }
    }
    this.client.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
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
      CREATE INDEX IF NOT EXISTS oob_callbacks_claim ON oob_callbacks(token, claimed_by);
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
    return this.subscription(id)
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
    const expired = this.client.prepare(
      "UPDATE pending_oob SET status = 'expired' WHERE run_id = ? AND status = 'pending'",
    ).run(validRunId) as { changes?: number | bigint }
    const removed = this.client.prepare(
      'DELETE FROM oob_bindings WHERE run_id = ?',
    ).run(validRunId) as { changes?: number | bigint }
    return {
      runId: validRunId,
      expiredSubscriptions: Number(expired?.changes ?? 0),
      removedBindings: Number(removed?.changes ?? 0),
    }
  }

  subscription(id: string): OobSubscription {
    const row = this.client.prepare('SELECT * FROM pending_oob WHERE id = ?').get(id) as unknown as SubscriptionRow | undefined
    if (!row) throw new Error(`Unknown OOB subscription: ${id}`)
    return subscriptionFromRow(row)
  }

  /**
   * Ingest a callback. Validates token↔canary binding, source allowlist, and causal artifact
   * before persisting. Rejections are persisted as `oob_rejected` events and never promote.
   */
  recordCallback(input: OobCallbackInput): OobRecordResult {
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
        this.client.prepare(
          'INSERT INTO oob_rejections (callback_id, token, reason, detail, created_at) VALUES (?, ?, ?, ?, ?)',
        ).run(callbackId, token || null, reason, detail ? JSON.stringify(detail) : null, now)
      } catch { /* rejection logging is best-effort */ }
      this.options.logger?.(rejection)
      return { accepted: false, duplicate: false, rejection }
    }

    if (!callbackTokenPattern.test(token)) {
      return reject('invalid_token')
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
      run_id: binding?.run_id ?? subscriptions[0]?.runId ?? input.runId ?? null,
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
    this.pruneCallbacks()
    return { accepted: true, duplicate: false, callback }
  }

  callback(callbackId: string): OobCallback | null {
    const row = this.client.prepare('SELECT * FROM oob_callbacks WHERE callback_id = ?')
      .get(callbackId) as unknown as CallbackRow | undefined
    return row ? callbackFromRow(row) : null
  }

  callbacksForToken(token: string): OobCallback[] {
    const normalized = token.trim().toLowerCase()
    const rows = this.client.prepare(
      'SELECT * FROM oob_callbacks WHERE token = ? ORDER BY received_at ASC',
    ).all(normalized) as unknown as CallbackRow[]
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
        'SELECT * FROM oob_callbacks WHERE canary_id = ? ORDER BY received_at ASC',
      ).all(query.canaryId) as unknown as CallbackRow[]
      callbacks.push(...rows.map(callbackFromRow))
    } else if (query.runId) {
      const rows = this.client.prepare(
        'SELECT * FROM oob_callbacks WHERE run_id = ? ORDER BY received_at ASC',
      ).all(query.runId) as unknown as CallbackRow[]
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
  promoteLate(options: { runId?: string; now?: number } = {}): OobPromotion[] {
    this.assertOpen()
    const now = options.now ?? this.now()
    const rows = options.runId
      ? this.client.prepare(
          'SELECT * FROM pending_oob WHERE status = ? AND run_id = ? ORDER BY created_at ASC',
        ).all('pending', options.runId) as unknown as SubscriptionRow[]
      : this.client.prepare(
          'SELECT * FROM pending_oob WHERE status = ? ORDER BY created_at ASC',
        ).all('pending') as unknown as SubscriptionRow[]

    const promotions: OobPromotion[] = []
    for (const row of rows) {
      const subscription = subscriptionFromRow(row)
      const callbacks = this.client.prepare(
        'SELECT * FROM oob_callbacks WHERE token = ? AND claimed_by IS NULL ORDER BY received_at ASC',
      ).all(subscription.token) as unknown as CallbackRow[]
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
        this.client.prepare('UPDATE pending_oob SET status = ? WHERE id = ? AND status = ?')
          .run('expired', subscription.id, 'pending')
      }
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
    this.client.exec('BEGIN IMMEDIATE')
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
      }
      this.client.exec('COMMIT')
    } catch (err) {
      try { this.client.exec('ROLLBACK') } catch { /* ignore */ }
      throw err
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
    }
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

  private pruneCallbacks(): void {
    const row = this.client.prepare('SELECT COUNT(*) AS n FROM oob_callbacks')
      .get() as unknown as { n: number | bigint } | undefined
    const total = Number(row?.n ?? 0)
    if (total <= maxStoredCallbacks) return
    this.client.prepare(`
      DELETE FROM oob_callbacks
      WHERE claimed_by IS NULL AND callback_id IN (
        SELECT callback_id FROM oob_callbacks WHERE claimed_by IS NULL ORDER BY received_at ASC LIMIT ?
      )
    `).run(total - maxStoredCallbacks)
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
    lastCallbackAt: status.lastCallbackAt,
    windowMs: status.windowMs,
    immediateMs: status.immediateMs,
    problems: status.problems.length,
  }
}
