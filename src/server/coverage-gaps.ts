/**
 * v7 M4 Production Operations + R2-14 — Honest Coverage-Gap Reporting.
 *
 * Classifies real operational coverage gaps strictly from persisted run telemetry
 * (exchanges, events, endpoints, facts, coverage entries, open proof gaps, OOB subscriptions).
 * Gaps are NEVER fabricated or hidden: if authentication failed, a WAF blocked requests,
 * prod_readonly refused mutations, OOB was unreachable, preconditions emptied a class queue,
 * hypotheses were capped out, hosts were skipped/quarantined, or discovered `(method, route, class)`
 * tuples went untested, the report states it plainly with exchange/event counts.
 */
import { eq } from 'drizzle-orm'
import {
  categoryToOwaspCoverageCategory,
  extractCoverageEvidenceMetadata,
  normalizeOriginForCoverage,
} from './coverage-category.ts'
import { redact, redactZdr } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import {
  brokerExchanges,
  coverageEntries,
  endpoints,
  events,
  facts as factsTable,
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
  'precondition_unmet',
  'capped_out',
  'host_skipped',
] as const
export type CoverageGapKind = typeof coverageGapKinds[number]

export interface CoverageGapEntry {
  kind: CoverageGapKind
  origin: string
  method?: string
  route?: string
  vulnClass?: string
  precondition?: string
  stage?: string
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

function normalizeMethodAndRoute(rawMethod: unknown, rawRoute: unknown): { method: string; route: string; normalizedPath: string } {
  let method = typeof rawMethod === 'string' && rawMethod.trim() ? rawMethod.trim().toUpperCase() : 'ANY'
  let route = typeof rawRoute === 'string' && rawRoute.trim() ? rawRoute.trim() : '*'
  const embedded = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s+(.+)$/i.exec(route)
  if (embedded) {
    if (method === 'ANY') method = embedded[1]!.toUpperCase()
    route = embedded[2]!.trim()
  }
  const normalizedPath = route === '*' ? '*' : routePatternForPath(route)
  return { method, route, normalizedPath }
}

function formatRouteLabel(method: string, route: string): string {
  if (route === '*') return method === 'ANY' ? '*' : `${method} *`
  return `${method} ${route}`
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
  storage.flushNow()
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
  const runFacts = storage.db.select().from(factsTable).where(eq(factsTable.runId, run.id)).all()
    .filter(f => inScope(f.origin))
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
    if (ev.kind === 'coverage.precondition_unmet') continue
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
    if (ev.kind === 'coverage.precondition_unmet') continue
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

  // 5. precondition_unmet: structured observational events when tier, persona, browser, or canary guards skip a queue.
  const precondByKey = new Map<string, {
    origin: string
    method: string
    route: string
    vulnClass: string
    precondition: string
    count: number
    eventIds: number[]
    details: Set<string>
  }>()
  for (const ev of runEvents) {
    if (ev.kind !== 'coverage.precondition_unmet') continue
    const origin = typeof ev.detail?.origin === 'string' && ev.detail.origin.trim() ? ev.detail.origin.trim() : defaultOrigin
    if (!inScope(origin === 'run' ? null : origin)) continue
    const precondition = typeof ev.detail?.precondition === 'string' && ev.detail.precondition.trim()
      ? ev.detail.precondition.trim()
      : 'precondition'
    const classes: string[] = Array.isArray(ev.detail?.classes) && ev.detail.classes.length > 0
      ? ev.detail.classes.map(c => String(c).trim()).filter(Boolean)
      : [
          typeof ev.detail?.vulnClass === 'string' && ev.detail.vulnClass.trim()
            ? ev.detail.vulnClass.trim()
            : typeof ev.detail?.class === 'string' && ev.detail.class.trim()
              ? ev.detail.class.trim()
              : typeof ev.detail?.category === 'string' && ev.detail.category.trim()
                ? ev.detail.category.trim()
                : 'general',
        ]
    const routes: Array<{ method: string; route: string; normalizedPath: string }> =
      Array.isArray(ev.detail?.routes) && ev.detail.routes.length > 0
        ? ev.detail.routes.map(r => normalizeMethodAndRoute(ev.detail?.method, r))
        : [normalizeMethodAndRoute(ev.detail?.method, ev.detail?.route)]
    const skippedCount = typeof ev.detail?.skippedCount === 'number' && ev.detail.skippedCount > 0
      ? Math.floor(ev.detail.skippedCount)
      : 1
    const required = typeof ev.detail?.required === 'string' ? ev.detail.required : ''
    const observed = typeof ev.detail?.observed === 'string' ? ev.detail.observed : ''
    const detailLine = required || observed
      ? `${precondition} (need ${required || '?'}, got ${observed || '?'})`
      : scrub(ev.message, secrets, zdr).slice(0, 180)

    for (const r of routes) {
      for (const vulnClass of classes) {
        const key = `${origin}\0${r.method}\0${r.normalizedPath}\0${vulnClass}\0${precondition}`
        let bucket = precondByKey.get(key)
        if (!bucket) {
          bucket = {
            origin,
            method: r.method,
            route: formatRouteLabel(r.method, r.route),
            vulnClass,
            precondition,
            count: 0,
            eventIds: [],
            details: new Set(),
          }
          precondByKey.set(key, bucket)
        }
        bucket.count += skippedCount
        bucket.eventIds.push(ev.id)
        bucket.details.add(detailLine)
      }
    }
  }
  for (const b of precondByKey.values()) {
    const extra = [...b.details].slice(0, 2).join('; ')
    gaps.push({
      kind: 'precondition_unmet',
      origin: b.origin,
      method: b.method,
      route: b.route,
      vulnClass: b.vulnClass,
      precondition: b.precondition,
      count: b.count,
      summary: scrub(
        `Precondition unmet (${b.precondition}) skipped ${b.vulnClass} on ${b.route} (${b.count} item(s))${extra ? `: ${extra}` : ''}.`,
        secrets,
        zdr,
      ),
      exchangeIds: [],
      eventIds: [...new Set(b.eventIds)].slice(0, 25),
    })
  }

  // 6. capped_out: structured floor/planner cap events keyed per (origin, method, route, class).
  const unprobedTailFacts = runFacts.filter(f => f.data?.subkind === 'deterministic_engine_unprobed_tail')
  const cappedByKey = new Map<string, {
    origin: string
    method: string
    route: string
    vulnClass: string
    stage: string
    count: number
    eventIds: number[]
    reasons: Set<string>
  }>()
  const noteCapped = (entry: {
    origin: string
    method: string
    route: string
    normalizedPath: string
    vulnClass: string
    stage: string
    count: number
    eventId?: number
    reason?: string
  }) => {
    const key = `${entry.origin}\0${entry.method}\0${entry.normalizedPath}\0${entry.vulnClass}\0${entry.stage}`
    let bucket = cappedByKey.get(key)
    if (!bucket) {
      bucket = {
        origin: entry.origin,
        method: entry.method,
        route: formatRouteLabel(entry.method, entry.route),
        vulnClass: entry.vulnClass,
        stage: entry.stage,
        count: 0,
        eventIds: [],
        reasons: new Set(),
      }
      cappedByKey.set(key, bucket)
    }
    bucket.count += Math.max(1, entry.count)
    if (entry.eventId !== undefined) bucket.eventIds.push(entry.eventId)
    if (entry.reason) bucket.reasons.add(scrub(entry.reason, secrets, zdr).slice(0, 180))
  }

  for (const ev of runEvents) {
    if (ev.kind !== 'deterministic_engine.capped_out' && ev.kind !== 'coverage.capped_out' && !ev.kind.endsWith('.capped_out')) {
      continue
    }
    const detail = ev.detail ?? {}
    const eventOrigin = typeof detail.origin === 'string' && detail.origin.trim() ? detail.origin.trim() : defaultOrigin
    const rawRecords = Array.isArray(detail.cappedOut) ? detail.cappedOut : []
    const matchedTailIds = new Set<string>()

    for (const raw of rawRecords) {
      if (!raw || typeof raw !== 'object') continue
      const rec = raw as Record<string, unknown>
      const dropped = typeof rec.dropped === 'number' ? Math.floor(rec.dropped) : 0
      if (dropped <= 0) continue
      const vulnClass = typeof rec.class === 'string' && rec.class.trim()
        ? rec.class.trim()
        : typeof rec.vulnClass === 'string' && rec.vulnClass.trim()
          ? rec.vulnClass.trim()
          : 'general'
      const stage = typeof rec.stage === 'string' && rec.stage.trim() ? rec.stage.trim() : 'capped'
      const recOrigin = typeof rec.origin === 'string' && rec.origin.trim() ? rec.origin.trim() : eventOrigin

      if (typeof rec.route === 'string' && rec.route.trim()) {
        if (!inScope(recOrigin === 'run' ? null : recOrigin)) continue
        const norm = normalizeMethodAndRoute(rec.method, rec.route)
        noteCapped({
          origin: recOrigin,
          method: norm.method,
          route: norm.route,
          normalizedPath: norm.normalizedPath,
          vulnClass,
          stage,
          count: dropped,
          eventId: ev.id,
          reason: typeof rec.reason === 'string' ? rec.reason : `stage=${stage}, cap=${String(rec.cap ?? '?')}, dropped=${dropped}`,
        })
        continue
      }

      // Enrich class-level cappedOut records with persisted per-route unprobed tail facts when present.
      const matchingTail = unprobedTailFacts.filter(f => {
        const intent = typeof f.data?.intent === 'string' ? f.data.intent : ''
        const probeClass = typeof f.data?.probeClass === 'string' ? f.data.probeClass : ''
        const factStage = typeof f.data?.cappedOutStage === 'string' ? f.data.cappedOutStage : ''
        return (intent === vulnClass || probeClass === vulnClass) && (!factStage || factStage === stage)
      })
      if (matchingTail.length > 0) {
        for (const f of matchingTail) {
          matchedTailIds.add(f.id)
          if (!inScope(f.origin)) continue
          const norm = normalizeMethodAndRoute(f.data?.method, f.data?.endpoint)
          const factClass = typeof f.data?.probeClass === 'string' && f.data.probeClass.trim()
            ? f.data.probeClass.trim()
            : vulnClass
          noteCapped({
            origin: f.origin,
            method: norm.method,
            route: norm.route,
            normalizedPath: norm.normalizedPath,
            vulnClass: factClass,
            stage,
            count: 1,
            eventId: ev.id,
            reason: typeof f.data?.reason === 'string' ? f.data.reason : `stage=${stage}`,
          })
        }
      } else {
        if (!inScope(recOrigin === 'run' ? null : recOrigin)) continue
        const norm = normalizeMethodAndRoute(detail.method, detail.route)
        noteCapped({
          origin: recOrigin,
          method: norm.method,
          route: norm.route,
          normalizedPath: norm.normalizedPath,
          vulnClass,
          stage,
          count: dropped,
          eventId: ev.id,
          reason: `stage=${stage}, cap=${String(rec.cap ?? '?')}, kept=${String(rec.kept ?? 0)}, dropped=${dropped}`,
        })
      }
    }

    // Support direct single-record coverage.capped_out events without a `cappedOut` array.
    if (rawRecords.length === 0) {
      if (inScope(eventOrigin === 'run' ? null : eventOrigin)) {
        const vulnClass = typeof detail.vulnClass === 'string' && detail.vulnClass.trim()
          ? detail.vulnClass.trim()
          : typeof detail.class === 'string' && detail.class.trim()
            ? detail.class.trim()
            : 'general'
        const stage = typeof detail.stage === 'string' && detail.stage.trim() ? detail.stage.trim() : 'capped'
        const dropped = typeof detail.dropped === 'number' && detail.dropped > 0 ? Math.floor(detail.dropped) : 1
        const norm = normalizeMethodAndRoute(detail.method, detail.route)
        noteCapped({
          origin: eventOrigin,
          method: norm.method,
          route: norm.route,
          normalizedPath: norm.normalizedPath,
          vulnClass,
          stage,
          count: dropped,
          eventId: ev.id,
          reason: ev.message,
        })
      }
    }

    // Any remaining unprobed tail facts not yet matched by a class record are still surfaced.
    for (const f of unprobedTailFacts) {
      if (matchedTailIds.has(f.id) || !inScope(f.origin)) continue
      const norm = normalizeMethodAndRoute(f.data?.method, f.data?.endpoint)
      const factClass = typeof f.data?.probeClass === 'string' && f.data.probeClass.trim()
        ? f.data.probeClass.trim()
        : typeof f.data?.intent === 'string' && f.data.intent.trim()
          ? f.data.intent.trim()
          : 'general'
      const stage = typeof f.data?.cappedOutStage === 'string' && f.data.cappedOutStage.trim()
        ? f.data.cappedOutStage.trim()
        : 'capped'
      noteCapped({
        origin: f.origin,
        method: norm.method,
        route: norm.route,
        normalizedPath: norm.normalizedPath,
        vulnClass: factClass,
        stage,
        count: 1,
        eventId: ev.id,
        reason: typeof f.data?.reason === 'string' ? f.data.reason : f.summary,
      })
    }
  }
  for (const b of cappedByKey.values()) {
    const extra = [...b.reasons].slice(0, 2).join('; ')
    gaps.push({
      kind: 'capped_out',
      origin: b.origin,
      method: b.method,
      route: b.route,
      vulnClass: b.vulnClass,
      stage: b.stage,
      count: b.count,
      summary: scrub(
        `Capped out (${b.stage}) dropped ${b.count} ${b.vulnClass} hypothesis(es) on ${b.route}${extra ? `: ${extra}` : ''}.`,
        secrets,
        zdr,
      ),
      exchangeIds: [],
      eventIds: [...new Set(b.eventIds)].slice(0, 25),
    })
  }

  // 7. host_skipped: structured host skip / origin quarantine events keyed per (origin, method, route, class).
  const hostSkippedByKey = new Map<string, {
    origin: string
    method: string
    route: string
    vulnClass: string
    count: number
    eventIds: number[]
    reasons: Set<string>
  }>()
  for (const ev of runEvents) {
    if (
      ev.kind !== 'coverage.host_skipped'
      && ev.kind !== 'planner.origin_quarantined'
      && !ev.kind.endsWith('.host_skipped')
    ) {
      continue
    }
    const detail = ev.detail ?? {}
    const origin = typeof detail.origin === 'string' && detail.origin.trim() ? detail.origin.trim() : defaultOrigin
    if (!inScope(origin === 'run' ? null : origin)) continue
    const norm = normalizeMethodAndRoute(detail.method, detail.route)
    const vulnClass = typeof detail.vulnClass === 'string' && detail.vulnClass.trim()
      ? detail.vulnClass.trim()
      : typeof detail.class === 'string' && detail.class.trim()
        ? detail.class.trim()
        : 'all'
    const key = `${origin}\0${norm.method}\0${norm.normalizedPath}\0${vulnClass}`
    let bucket = hostSkippedByKey.get(key)
    if (!bucket) {
      bucket = {
        origin,
        method: norm.method,
        route: formatRouteLabel(norm.method, norm.route),
        vulnClass,
        count: 0,
        eventIds: [],
        reasons: new Set(),
      }
      hostSkippedByKey.set(key, bucket)
    }
    bucket.count += 1
    bucket.eventIds.push(ev.id)
    const reasonText = typeof detail.reason === 'string' && detail.reason.trim()
      ? `${detail.reason.trim()}: ${ev.message}`
      : ev.message
    bucket.reasons.add(scrub(reasonText, secrets, zdr).slice(0, 180))
  }
  for (const b of hostSkippedByKey.values()) {
    const extra = [...b.reasons].slice(0, 2).join('; ')
    gaps.push({
      kind: 'host_skipped',
      origin: b.origin,
      method: b.method,
      route: b.route,
      vulnClass: b.vulnClass,
      count: b.count,
      summary: scrub(
        `Host skipped/quarantined for ${b.vulnClass} on ${b.route} (${b.count} event(s))${extra ? `: ${extra}` : ''}.`,
        secrets,
        zdr,
      ),
      exchangeIds: [],
      eventIds: [...new Set(b.eventIds)].slice(0, 25),
    })
  }

  // 8. uncovered_routes: keyed per (origin, method, route, class) — never marks a route covered
  //    across HTTP methods or untested sink classes after a single unrelated exchange.
  const exchangeOriginById = new Map<string, string>()
  const testedMethodRouteKeys = new Set<string>()
  for (const ex of runExchanges) {
    const normOrigin = normalizeOriginForCoverage(ex.origin)
    exchangeOriginById.set(ex.id, normOrigin)
    testedMethodRouteKeys.add(`${normOrigin}\0${ex.method.toUpperCase()}\0${routePatternForPath(ex.pathAndQuery)}`)
  }

  // Index verified route-scoped coverage entries (origin + route + OWASP category).
  const verifiedRouteClassKeys = new Set<string>()
  for (const cov of runCoverage) {
    const normOrigin = normalizeOriginForCoverage(cov.origin)
    const meta = extractCoverageEvidenceMetadata(cov)
    const hasVerifiedEvidence = cov.status === 'reported'
      || ((cov.status === 'ruled_out' || cov.status === 'no_issue_found')
        && meta.exchangeIds.some(id => exchangeOriginById.get(id) === normOrigin))
    if (!hasVerifiedEvidence) continue
    for (const r of meta.routes) {
      const norm = normalizeMethodAndRoute(undefined, r)
      verifiedRouteClassKeys.add(`${normOrigin}\0${norm.method}\0${norm.normalizedPath}\0${cov.category}`)
      if (norm.method === 'ANY') {
        verifiedRouteClassKeys.add(`${normOrigin}\0ANY\0${norm.normalizedPath}\0${cov.category}`)
      }
    }
  }

  const seenUncovered = new Set<string>()
  for (const ep of runEndpoints) {
    const method = ep.method.toUpperCase()
    const normOrigin = normalizeOriginForCoverage(ep.origin)
    const normalized = routePatternForPath(ep.pathTemplate)
    const routeLabel = `${method} ${ep.pathTemplate}`
    const sinkClasses = Array.isArray(ep.sinkKinds)
      ? [...new Set(ep.sinkKinds.map(c => c.trim()).filter(Boolean))]
      : []

    if (sinkClasses.length > 0) {
      const testedSet = new Set(
        (Array.isArray(ep.testedClasses) ? ep.testedClasses : [])
          .flatMap(c => {
            const raw = c.trim().toLowerCase()
            const mapped = categoryToOwaspCoverageCategory(raw)
            return mapped ? [raw, mapped] : [raw]
          })
          .filter(Boolean),
      )
      for (const sinkClass of sinkClasses) {
        const lowerClass = sinkClass.toLowerCase()
        const mappedOwasp = categoryToOwaspCoverageCategory(sinkClass)
        const isTestedOnEndpoint = testedSet.has(lowerClass) || (mappedOwasp ? testedSet.has(mappedOwasp) : false)
        const isVerifiedInCoverage = mappedOwasp
          ? (verifiedRouteClassKeys.has(`${normOrigin}\0${method}\0${normalized}\0${mappedOwasp}`)
            || verifiedRouteClassKeys.has(`${normOrigin}\0ANY\0${normalized}\0${mappedOwasp}`))
          : false
        if (isTestedOnEndpoint || isVerifiedInCoverage) continue
        const dedupeKey = `${normOrigin}\0${method}\0${normalized}\0${lowerClass}`
        if (seenUncovered.has(dedupeKey)) continue
        seenUncovered.add(dedupeKey)
        gaps.push({
          kind: 'uncovered_routes',
          origin: ep.origin,
          method,
          route: routeLabel,
          vulnClass: sinkClass,
          count: 1,
          summary: scrub(
            `Discovered route ${routeLabel} (source: ${ep.source}) had no verified ${sinkClass} probe coverage.`,
            secrets,
            zdr,
          ),
          exchangeIds: [],
          eventIds: [],
        })
      }
      continue
    }

    const methodRouteKey = `${normOrigin}\0${method}\0${normalized}`
    if (testedMethodRouteKeys.has(methodRouteKey) || seenUncovered.has(methodRouteKey)) continue
    seenUncovered.add(methodRouteKey)
    gaps.push({
      kind: 'uncovered_routes',
      origin: ep.origin,
      method,
      route: routeLabel,
      vulnClass: 'all',
      count: 1,
      summary: scrub(
        `Discovered route ${routeLabel} (source: ${ep.source}) had no recorded live probe exchange.`,
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
    precondition_unmet: 0,
    capped_out: 0,
    host_skipped: 0,
  }
  for (const gap of gaps) {
    countsByKind[gap.kind] += 1
  }

  const totalGaps = gaps.length
  const activeKinds = coverageGapKinds.filter(k => countsByKind[k] > 0)
  const honestSummary = totalGaps === 0
    ? 'No operational coverage gaps (auth failures, WAF blocks, read-only skips, OOB unreachability, unmet preconditions, capped-out hypotheses, skipped hosts, or untested discovered routes) were recorded in run telemetry.'
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
    const classSuffix = gap.vulnClass && gap.vulnClass !== 'all' ? ` [${gap.vulnClass.replace(/\|/g, '\\|')}]` : ''
    const routeCol = gap.route
      ? `\`${gap.route.replace(/\|/g, '\\|')}\`${classSuffix}`
      : (classSuffix ? classSuffix.trim() : '—')
    lines.push(`| \`${gap.kind}\` | ${gap.origin} | ${routeCol} | ${gap.count} | ${safeSummary} |`)
  }
  lines.push('')
  return lines.join('\n')
}
