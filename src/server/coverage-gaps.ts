/**
 * v7 M4 Production Operations — Honest Coverage-Gap Reporting.
 *
 * Classifies real operational coverage gaps strictly from persisted run telemetry
 * (exchanges, events, endpoints, coverage entries, open proof gaps, OOB subscriptions).
 * Gaps are NEVER fabricated or hidden: if authentication failed, a WAF blocked requests,
 * prod_readonly refused mutations, OOB was unreachable, or discovered routes went untested,
 * the report states it plainly with exchange/event counts.
 */
import { eq } from 'drizzle-orm'
import { redact, redactZdr } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import {
  brokerExchanges,
  coverageEntries,
  endpoints,
  events,
  findings as findingsTable,
} from './schema.ts'
import { routePatternForPath } from './scope-policy.ts'
import type { Store } from './store.ts'

export const coverageGapKinds = [
  'auth_failed',
  'waf_blocked',
  'prod_readonly_skipped',
  'oob_unreachable',
  'uncovered_routes',
] as const
export type CoverageGapKind = typeof coverageGapKinds[number]

export interface CoverageGapEntry {
  kind: CoverageGapKind
  origin: string
  route?: string
  count: number
  summary: string
  exchangeIds: string[]
  eventIds: number[]
  sampleStatuses?: number[]
}

export interface CoverageGapReport {
  runId: string
  generatedAt: string
  totalGaps: number
  countsByKind: Record<CoverageGapKind, number>
  gaps: CoverageGapEntry[]
  honestSummary: string
}

export interface BuildCoverageGapOptions {
  approvedOrigins?: ReadonlySet<string>
  secrets?: readonly NamedSecret[]
  zdr?: boolean
  now?: number
}

const wafBodyOrHeaderPattern =
  /\b(?:cloudflare|cf-ray|akamai|incapsula|imperva|aws\s*waf|sucuri|mod_security|modsecurity|datadome|perimeterx|captcha|access\s+denied|request\s+blocked|bot\s+detected|rate\s+limit(?:ed)?)\b/i

const wafHeaderNames = new Set(['cf-mitigated', 'x-sucuri-id', 'x-akamai-transformed', 'x-amzn-waf-action', 'x-datadome'])

const authGapEventKinds = new Set([
  'auth.failed',
  'persona.auth_failed',
  'persona_auth_failed',
  'broker.persona_scope_mismatch',
])

const prodReadonlyEventPattern = /readonly_environment|prod_readonly|read-only\s+environment|tier\s+[01]\b.*(?:mutation|write|refused|disabled)/i
const oobUnreachableEventPattern = /oob[._-]?(?:unreachable|disabled|failed|relay_failed)|canary.*(?:unreachable|unavailable|disabled)/i
const authGapReasonPattern = /auth[._-]?failed|no_authenticated_persona|401\/401\/401|unauthenticated|session\s+expired|login\s+failed/i
const wafGapReasonPattern = /waf[._-]?blocked|rate[._-]?limit|circuit[._-]?open|429|captcha/i

function scrub(text: string, secrets: readonly NamedSecret[], zdr: boolean): string {
  return zdr ? redactZdr(text, secrets) : redact(text, secrets)
}

function isWafBlockedExchange(status: number, respHeaders: Record<string, string>, bodyPreview: string): boolean {
  if (status === 429) return true
  if (status !== 403 && status !== 406 && status !== 503) return false
  for (const [name, value] of Object.entries(respHeaders)) {
    const lower = name.toLowerCase()
    if (wafHeaderNames.has(lower)) return true
    if (lower === 'server' && wafBodyOrHeaderPattern.test(value)) return true
    if (lower === 'cf-ray' && (status === 403 || status === 503)) return true
  }
  return wafBodyOrHeaderPattern.test(bodyPreview)
}

/**
 * Derive an honest, structured `CoverageGapReport` from real persisted run telemetry.
 * Every reported gap cites actual exchange IDs, event IDs, or discovered endpoint records.
 */
export function buildCoverageGapReport(
  storage: Store,
  runId: string,
  options: BuildCoverageGapOptions = {},
): CoverageGapReport {
  const run = storage.run(runId)
  const secrets = options.secrets ?? []
  const zdr = options.zdr ?? false
  const approved = options.approvedOrigins

  const inScope = (origin: string | null | undefined): boolean => {
    if (!origin) return true
    if (!approved || approved.size === 0) return true
    return approved.has(origin)
  }

  const runExchanges = storage.db.select().from(brokerExchanges).where(eq(brokerExchanges.runId, run.id)).all()
    .filter(ex => inScope(ex.origin))
  const runEvents = storage.db.select().from(events).where(eq(events.runId, run.id)).all()
  const runEndpoints = storage.db.select().from(endpoints).where(eq(endpoints.runId, run.id)).all()
    .filter(ep => inScope(ep.origin))
  const runCoverage = storage.db.select().from(coverageEntries).where(eq(coverageEntries.runId, run.id)).all()
    .filter(c => inScope(c.origin))
  const runFindings = storage.db.select().from(findingsTable).where(eq(findingsTable.runId, run.id)).all()
  const defaultOrigin = run.approved[0] ?? 'run'

  const gaps: CoverageGapEntry[] = []

  // 1. auth_failed: persona-bound 401/403 exchanges, auth failure events, or auth proof gaps.
  const authByOrigin = new Map<string, { exchangeIds: string[]; eventIds: number[]; statuses: Set<number>; reasons: Set<string> }>()
  const noteAuth = (origin: string) => {
    let bucket = authByOrigin.get(origin)
    if (!bucket) {
      bucket = { exchangeIds: [], eventIds: [], statuses: new Set(), reasons: new Set() }
      authByOrigin.set(origin, bucket)
    }
    return bucket
  }
  for (const ex of runExchanges) {
    if (ex.personaHandle && (ex.status === 401 || (ex.status === 403 && !isWafBlockedExchange(ex.status, ex.respHeaders, ex.bodyPreview)))) {
      const b = noteAuth(ex.origin)
      b.exchangeIds.push(ex.id)
      b.statuses.add(ex.status)
    }
  }
  for (const ev of runEvents) {
    if (authGapEventKinds.has(ev.kind) || (ev.kind.includes('auth') && /fail|denied|mismatch|expired/i.test(ev.message))) {
      const origin = typeof ev.detail?.origin === 'string' ? ev.detail.origin : defaultOrigin
      if (!inScope(origin === 'run' ? null : origin)) continue
      const b = noteAuth(origin)
      b.eventIds.push(ev.id)
      b.reasons.add(scrub(ev.message, secrets, zdr).slice(0, 180))
    }
  }
  for (const cov of runCoverage) {
    if (cov.status === 'needs_follow_up' && authGapReasonPattern.test(`${cov.proofGapReason ?? ''} ${cov.summary}`)) {
      const b = noteAuth(cov.origin)
      b.reasons.add(scrub(cov.proofGapReason || cov.summary, secrets, zdr).slice(0, 180))
    }
  }
  for (const [origin, b] of authByOrigin) {
    const count = Math.max(b.exchangeIds.length + b.eventIds.length, b.reasons.size)
    if (count === 0) continue
    const extra = [...b.reasons].slice(0, 2).join('; ')
    gaps.push({
      kind: 'auth_failed',
      origin,
      count,
      summary: scrub(
        `Authentication failed or persona session rejected (${b.exchangeIds.length} exchange(s), ${b.eventIds.length} event(s))${extra ? `: ${extra}` : ''}.`,
        secrets,
        zdr,
      ),
      exchangeIds: b.exchangeIds.slice(0, 25),
      eventIds: b.eventIds.slice(0, 25),
      ...(b.statuses.size ? { sampleStatuses: [...b.statuses].sort((a, c) => a - c) } : {}),
    })
  }

  // 2. waf_blocked: 429 / WAF-signature 403/406/503 exchanges or circuit-open/WAF events.
  const wafByOrigin = new Map<string, { exchangeIds: string[]; eventIds: number[]; statuses: Set<number> }>()
  const noteWaf = (origin: string) => {
    let bucket = wafByOrigin.get(origin)
    if (!bucket) {
      bucket = { exchangeIds: [], eventIds: [], statuses: new Set() }
      wafByOrigin.set(origin, bucket)
    }
    return bucket
  }
  for (const ex of runExchanges) {
    if (isWafBlockedExchange(ex.status, ex.respHeaders, ex.bodyPreview)) {
      const b = noteWaf(ex.origin)
      b.exchangeIds.push(ex.id)
      b.statuses.add(ex.status)
    }
  }
  for (const ev of runEvents) {
    if (ev.kind === 'broker.circuit_open' || wafGapReasonPattern.test(`${ev.kind} ${ev.message}`)) {
      const origin = typeof ev.detail?.origin === 'string' ? ev.detail.origin : defaultOrigin
      if (!inScope(origin === 'run' ? null : origin)) continue
      noteWaf(origin).eventIds.push(ev.id)
    }
  }
  for (const [origin, b] of wafByOrigin) {
    const count = b.exchangeIds.length + b.eventIds.length
    if (count === 0) continue
    gaps.push({
      kind: 'waf_blocked',
      origin,
      count,
      summary: scrub(
        `WAF or rate limiting blocked ${b.exchangeIds.length} exchange(s) (${b.eventIds.length} circuit/throttle event(s)); affected routes could not be fully probed.`,
        secrets,
        zdr,
      ),
      exchangeIds: b.exchangeIds.slice(0, 25),
      eventIds: b.eventIds.slice(0, 25),
      ...(b.statuses.size ? { sampleStatuses: [...b.statuses].sort((a, c) => a - c) } : {}),
    })
  }

  // 3. prod_readonly_skipped: mutations refused by prod_readonly or read-only tier.
  const roByOrigin = new Map<string, { eventIds: number[]; reasons: Set<string> }>()
  const noteRo = (origin: string) => {
    let bucket = roByOrigin.get(origin)
    if (!bucket) {
      bucket = { eventIds: [], reasons: new Set() }
      roByOrigin.set(origin, bucket)
    }
    return bucket
  }
  for (const ev of runEvents) {
    if (prodReadonlyEventPattern.test(`${ev.kind} ${ev.message} ${JSON.stringify(ev.detail ?? {})}`)) {
      const origin = typeof ev.detail?.origin === 'string' ? ev.detail.origin : defaultOrigin
      if (!inScope(origin === 'run' ? null : origin)) continue
      const b = noteRo(origin)
      b.eventIds.push(ev.id)
      b.reasons.add(scrub(ev.message, secrets, zdr).slice(0, 180))
    }
  }
  for (const cov of runCoverage) {
    if ((cov.status === 'not_applicable' || cov.status === 'needs_follow_up') &&
        prodReadonlyEventPattern.test(`${cov.proofGapReason ?? ''} ${cov.summary}`)) {
      const b = noteRo(cov.origin)
      b.reasons.add(scrub(cov.proofGapReason || cov.summary, secrets, zdr).slice(0, 180))
    }
  }
  for (const [origin, b] of roByOrigin) {
    const count = Math.max(b.eventIds.length, b.reasons.size)
    if (count === 0) continue
    const extra = [...b.reasons].slice(0, 2).join('; ')
    gaps.push({
      kind: 'prod_readonly_skipped',
      origin,
      count,
      summary: scrub(
        `State-changing probes skipped due to read-only environment policy (${count} refusal/skip record(s))${extra ? `: ${extra}` : ''}.`,
        secrets,
        zdr,
      ),
      exchangeIds: [],
      eventIds: b.eventIds.slice(0, 25),
    })
  }

  // 4. oob_unreachable: OOB relay/canary unreachability events, proof gaps, or expired undelivered OOB subs.
  const oobByOrigin = new Map<string, { eventIds: number[]; expiredCount: number; reasons: Set<string> }>()
  const noteOob = (origin: string) => {
    let bucket = oobByOrigin.get(origin)
    if (!bucket) {
      bucket = { eventIds: [], expiredCount: 0, reasons: new Set() }
      oobByOrigin.set(origin, bucket)
    }
    return bucket
  }
  for (const ev of runEvents) {
    if (oobUnreachableEventPattern.test(`${ev.kind} ${ev.message}`)) {
      const origin = typeof ev.detail?.origin === 'string' ? ev.detail.origin : defaultOrigin
      if (!inScope(origin === 'run' ? null : origin)) continue
      const b = noteOob(origin)
      b.eventIds.push(ev.id)
      b.reasons.add(scrub(ev.message, secrets, zdr).slice(0, 180))
    }
  }
  for (const cov of runCoverage) {
    if (cov.status === 'needs_follow_up' && oobUnreachableEventPattern.test(`${cov.proofGapReason ?? ''} ${cov.summary}`)) {
      const b = noteOob(cov.origin)
      b.reasons.add(scrub(cov.proofGapReason || cov.summary, secrets, zdr).slice(0, 180))
    }
  }
  for (const row of runFindings) {
    if (row.verificationClass === 'pending_oob') {
      const origin = row.finding.origin || defaultOrigin
      if (!inScope(origin === 'run' ? null : origin)) continue
      const b = noteOob(origin)
      b.expiredCount += 1
      if (row.finding.runtimeProofGap) {
        b.reasons.add(scrub(row.finding.runtimeProofGap, secrets, zdr).slice(0, 180))
      }
    }
  }
  for (const [origin, b] of oobByOrigin) {
    const count = b.eventIds.length + b.expiredCount + (b.eventIds.length === 0 && b.expiredCount === 0 ? b.reasons.size : 0)
    if (count === 0) continue
    const extra = [...b.reasons].slice(0, 2).join('; ')
    gaps.push({
      kind: 'oob_unreachable',
      origin,
      count,
      summary: scrub(
        `Out-of-band verification could not confirm delivery (${b.expiredCount} pending OOB finding(s), ${b.eventIds.length} relay error event(s))${extra ? `: ${extra}` : ''}.`,
        secrets,
        zdr,
      ),
      exchangeIds: [],
      eventIds: b.eventIds.slice(0, 25),
    })
  }

  // 5. uncovered_routes: discovered endpoints with zero recorded broker exchanges.
  const testedRouteKeys = new Set<string>()
  for (const ex of runExchanges) {
    testedRouteKeys.add(`${ex.origin}\0${routePatternForPath(ex.pathAndQuery)}`)
  }
  const seenUncovered = new Set<string>()
  for (const ep of runEndpoints) {
    const normalized = routePatternForPath(ep.pathTemplate)
    const key = `${ep.origin}\0${normalized}`
    if (testedRouteKeys.has(key) || seenUncovered.has(key)) continue
    seenUncovered.add(key)
    gaps.push({
      kind: 'uncovered_routes',
      origin: ep.origin,
      route: `${ep.method.toUpperCase()} ${ep.pathTemplate}`,
      count: 1,
      summary: scrub(
        `Discovered route ${ep.method.toUpperCase()} ${ep.pathTemplate} (source: ${ep.source}) had no recorded live probe exchange.`,
        secrets,
        zdr,
      ),
      exchangeIds: [],
      eventIds: [],
    })
  }

  const countsByKind: Record<CoverageGapKind, number> = {
    auth_failed: 0,
    waf_blocked: 0,
    prod_readonly_skipped: 0,
    oob_unreachable: 0,
    uncovered_routes: 0,
  }
  for (const gap of gaps) {
    countsByKind[gap.kind] += 1
  }

  const totalGaps = gaps.length
  const activeKinds = coverageGapKinds.filter(k => countsByKind[k] > 0)
  const honestSummary = totalGaps === 0
    ? 'No operational coverage gaps (auth failures, WAF blocks, read-only skips, OOB unreachability, or untested discovered routes) were recorded in run telemetry.'
    : `Recorded ${totalGaps} operational coverage gap(s) across ${activeKinds.map(k => `${k}=${countsByKind[k]}`).join(', ')}. Absent findings in these areas must not be interpreted as clean passes.`

  return {
    runId: run.id,
    generatedAt: new Date(options.now ?? Date.now()).toISOString(),
    totalGaps,
    countsByKind,
    gaps,
    honestSummary,
  }
}

export function formatCoverageGapMarkdown(report: CoverageGapReport): string {
  const lines = [
    '## Operational coverage gaps',
    '',
    report.honestSummary,
    '',
  ]
  if (report.totalGaps === 0) return lines.join('\n')
  lines.push(
    '| Gap category | Origin | Route / Scope | Count | Details |',
    '| :--- | :--- | :--- | ---: | :--- |',
  )
  for (const gap of report.gaps) {
    const safeSummary = gap.summary.replace(/\|/g, '\\|').replace(/\s+/g, ' ')
    const routeCol = gap.route ? `\`${gap.route.replace(/\|/g, '\\|')}\`` : '—'
    lines.push(`| \`${gap.kind}\` | ${gap.origin} | ${routeCol} | ${gap.count} | ${safeSummary} |`)
  }
  lines.push('')
  return lines.join('\n')
}
