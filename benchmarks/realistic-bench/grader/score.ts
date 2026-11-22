// Core grader: gradeRun(input) -> Scorecard, plus aggregateScorecards. Pure. See CONTRACTS.md.
import type {
  FailureTaxonomyBucket, GradeInput, GroundTruthEntry, OracleEvent, RequestLogEntry,
  Scorecard, Severity, SubmittedFinding, VulnOutcome, VulnResult,
} from '../lib/types.ts'
import { failureTaxonomyBuckets } from '../lib/types.ts'
import { endpointMatches, matchFindingToEntries } from './match.ts'
import type { GradeEntry } from './match.ts'
import { attributeEvent, classifyFailure, computeFunnel } from './attribution.ts'
import type { FailureContext, FunnelStage } from './attribution.ts'
import { budgetCurve, findingCostUsd } from './budget.ts'

const severities: Severity[] = ['critical', 'high', 'medium', 'low']

function entryRouteKeys(entry: GroundTruthEntry): Set<string> {
  const s = new Set<string>()
  for (const e of entry.endpoints) if (e.routeKey) s.add(e.routeKey)
  for (const e of entry.triggerEndpoints) if (e.routeKey) s.add(e.routeKey)
  for (const rk of entry.oracle.routeKeys) s.add(rk)
  return s
}

function requestsOnEntry(entry: GroundTruthEntry, requests: RequestLogEntry[]): RequestLogEntry[] {
  const rk = entryRouteKeys(entry)
  const endpoints = [...entry.endpoints, ...entry.triggerEndpoints]
  return requests.filter((r) => {
    if (r.routeKey && rk.has(r.routeKey)) return true
    return endpoints.some((e) => endpointMatches({ method: r.method, path: r.path }, e))
  })
}

function rootCauseMatch(finding: SubmittedFinding, entry: GroundTruthEntry): boolean {
  if (!finding.codeLocations) return false
  const rcFile = entry.rootCause.file
  const rcSym = entry.rootCause.symbol
  return finding.codeLocations.some((loc) => {
    const fileHit = !!loc.file && (loc.file === rcFile || loc.file.endsWith(rcFile) || rcFile.endsWith(loc.file))
    const symHit = !!loc.symbol && loc.symbol === rcSym
    return fileHit || symHit
  })
}

interface VulnEval {
  entry: GroundTruthEntry
  matched: SubmittedFinding[]
  attributedEvents: OracleEvent[]
  outcome: VulnOutcome
  confirmingFinding?: SubmittedFinding
}

export function gradeRun(input: GradeInput): Scorecard {
  const { groundTruth: gt, findings, oracleEvents, requestLog, telemetry, mode } = input
  const active = findings.filter((f) => f.status !== 'ruled_out')

  const vulnEntries: GradeEntry[] = gt.vulns.map((e) => ({ entry: e, isDecoy: false }))
  const decoyEntries: GradeEntry[] = gt.decoys.map((e) => ({ entry: e, isDecoy: true }))
  const allEntries = [...vulnEntries, ...decoyEntries]

  // Match every active finding to its best entry.
  const matchOf = new Map<string, { entry: GroundTruthEntry; isDecoy: boolean } | null>()
  const vulnMatched = new Map<string, SubmittedFinding[]>()
  const decoyMatched = new Map<string, SubmittedFinding[]>()
  const unmatched: SubmittedFinding[] = []
  for (const f of active) {
    const m = matchFindingToEntries(f, allEntries)
    matchOf.set(f.id, m ? { entry: m.entry, isDecoy: m.isDecoy } : null)
    if (!m) { unmatched.push(f); continue }
    const bucket = m.isDecoy ? decoyMatched : vulnMatched
    const list = bucket.get(m.entry.siteId) ?? []
    list.push(f)
    bucket.set(m.entry.siteId, list)
  }

  // Evaluate each vuln.
  const evals: VulnEval[] = gt.vulns.map((entry) => {
    const matched = vulnMatched.get(entry.siteId) ?? []
    const attributedEvents = oracleEvents.filter((ev) => attributeEvent(ev, entry))
    let outcome: VulnOutcome = matched.length > 0 ? 'claimed_without_impact' : 'missed'
    let confirmingFinding: SubmittedFinding | undefined
    for (const f of matched) {
      if (f.status === 'runtime_confirmed' || f.status === 'confirmed') {
        const ev = attributedEvents.find((e) => e.ts <= f.submittedAtMs)
        if (ev) {
          outcome = 'confirmed'
          if (!confirmingFinding || f.submittedAtMs < confirmingFinding.submittedAtMs) confirmingFinding = f
        }
      }
    }
    if (outcome !== 'confirmed') {
      const anyStatic = matched.some((f) => f.status === 'static_verified' && rootCauseMatch(f, entry))
      if (anyStatic && matched.every((f) => f.status === 'static_verified')) outcome = 'static_only'
      else if (anyStatic && !matched.some((f) => f.status !== 'static_verified')) outcome = 'static_only'
    }
    return { entry, matched, attributedEvents, outcome, confirmingFinding }
  })

  // Telemetry-derived signals for failure classification.
  const tierBlockedOn = (entry: GroundTruthEntry): boolean => {
    const tb = telemetry.tierBlocked ?? []
    const eps = [...entry.endpoints, ...entry.triggerEndpoints]
    return tb.some((t) => eps.some((e) => endpointMatches(t, e)))
  }
  const assertionFailureOn = (matched: SubmittedFinding[], entry: GroundTruthEntry): boolean => {
    const af = telemetry.assertionFailures ?? []
    const ids = new Set(matched.map((f) => f.id))
    const eps = [...entry.endpoints, ...entry.triggerEndpoints]
    return af.some((a) => (a.findingId && ids.has(a.findingId)) ||
      (a.path != null && eps.some((e) => endpointMatches({ path: a.path as string }, e))))
  }
  const hypothesisFromTelemetry = (entry: GroundTruthEntry): boolean => {
    const hs = telemetry.hypotheses ?? []
    const eps = [...entry.endpoints, ...entry.triggerEndpoints]
    return hs.some((h) => eps.some((e) => endpointMatches({ method: h.method, path: h.path }, e)))
  }

  // Build funnel stages + failure buckets + VulnResults.
  const failureBuckets = {} as Record<FailureTaxonomyBucket, number>
  for (const b of failureTaxonomyBuckets) failureBuckets[b] = 0
  const funnelStages: FunnelStage[] = []
  const vulnResults: VulnResult[] = []

  for (const ev of evals) {
    const reqs = requestsOnEntry(ev.entry, requestLog)
    const surfaceDiscovered = reqs.length > 0
    const hypothesisFormed = reqs.some((r) => r.suspicious) || hypothesisFromTelemetry(ev.entry)
    const signalObserved = ev.attributedEvents.length > 0
    const specSubmitted = ev.matched.length > 0
    const confirmed = ev.outcome === 'confirmed'
    funnelStages.push({ surfaceDiscovered, hypothesisFormed, signalObserved, specSubmitted, confirmed })

    let failureBucket: FailureTaxonomyBucket | undefined
    if (!confirmed) {
      const triggerReqs = ev.entry.secondOrder
        ? requestLog.filter((r) => ev.entry.triggerEndpoints.some((e) => endpointMatches({ method: r.method, path: r.path }, e)))
        : []
      const storedReq = reqs.find((r) => r.suspicious)
      const triggerMiss = !!ev.entry.secondOrder && !!storedReq &&
        !triggerReqs.some((t) => t.ts >= (storedReq as RequestLogEntry).ts)
      const ctx: FailureContext = {
        surfaceDiscovered,
        hypothesisFormed,
        signalObserved,
        hasMatchingFinding: specSubmitted,
        confirmed,
        telemetryExhausted: !!telemetry.budgetExhausted,
        tierBlocked: tierBlockedOn(ev.entry),
        csrfBlocked: !!ev.entry.requiresCsrf && reqs.some((r) => r.csrfRejected),
        formEncodingMissing: !!ev.entry.formEncoding && reqs.some((r) => r.encodingMismatch),
        contextReset: reqs.some((r) => r.sessionLost),
        triggerMiss,
        assertionFailure: assertionFailureOn(ev.matched, ev.entry),
      }
      failureBucket = classifyFailure(ctx)
      failureBuckets[failureBucket]++
    }

    vulnResults.push({
      siteId: ev.entry.siteId,
      severity: ev.entry.severity,
      vulnClass: ev.entry.vulnClass,
      outcome: ev.outcome,
      matchedFindingIds: ev.matched.map((f) => f.id),
      oracleEventSeqs: ev.attributedEvents.map((e) => e.seq),
      failureBucket,
      confirmedAtUsd: ev.confirmingFinding ? findingCostUsd(ev.confirmingFinding, telemetry) : undefined,
    })
  }

  // spa_catchall_fp for unmatched FPs whose endpoints only ever hit SPA fallback.
  for (const f of unmatched) {
    const hits = requestLog.filter((r) => f.endpoints.some((e) => endpointMatches({ method: e.method, path: e.path }, { path: r.path })))
    if (hits.length > 0 && hits.every((r) => r.spaFallback || r.routeKey == null)) failureBuckets.spa_catchall_fp++
  }

  // Counts.
  const confirmed = evals.filter((e) => e.outcome === 'confirmed').length
  const staticOnly = evals.filter((e) => e.outcome === 'static_only').length
  const targets = gt.vulns.length
  const tp = confirmed
  const decoyFalsePositives = gt.decoys.filter((d) => (decoyMatched.get(d.siteId)?.length ?? 0) > 0).length
  const unmatchedFalsePositives = unmatched.length
  let duplicateFindings = 0
  for (const list of vulnMatched.values()) if (list.length > 1) duplicateFindings += list.length - 1

  const denom = tp + decoyFalsePositives + unmatchedFalsePositives
  const precision = findings.length === 0 ? 1 : denom === 0 ? 1 : tp / denom

  const recallBySeverity = {} as Scorecard['recallBySeverity']
  for (const sev of severities) {
    const t = evals.filter((e) => e.entry.severity === sev)
    const c = t.filter((e) => e.outcome === 'confirmed').length
    recallBySeverity[sev] = { targets: t.length, confirmed: c, recall: t.length > 0 ? c / t.length : 0 }
  }
  const recallByClass: Scorecard['recallByClass'] = {}
  for (const e of evals) {
    const k = e.entry.vulnClass
    const cur = recallByClass[k] ?? { targets: 0, confirmed: 0 }
    cur.targets++
    if (e.outcome === 'confirmed') cur.confirmed++
    recallByClass[k] = cur
  }

  const confirmingFindings = evals.map((e) => e.confirmingFinding).filter((f): f is SubmittedFinding => !!f)
  const chainsCompleted = gt.chains.filter((ch) =>
    ch.siteIds.every((sid) => evals.find((e) => e.entry.siteId === sid)?.outcome === 'confirmed')).length
  const egressBlocked = (input.egressLog ?? []).filter((e) => !e.allowed).length

  return {
    app: gt.app,
    seed: gt.seed,
    seedSet: gt.seedSet,
    mode,
    targets,
    confirmed,
    recall: targets > 0 ? confirmed / targets : 0,
    recallBySeverity,
    recallByClass,
    staticRecall: targets > 0 ? (confirmed + staticOnly) / targets : 0,
    precision,
    decoys: gt.decoys.length,
    decoyFalsePositives,
    unmatchedFalsePositives,
    duplicateFindings,
    chainsTotal: gt.chains.length,
    chainsCompleted,
    funnel: computeFunnel(funnelStages),
    failureBuckets,
    budgetCurve: budgetCurve(confirmingFindings, telemetry, targets),
    egressBlocked,
    totalCostUsd: telemetry.totalCostUsd,
    vulns: vulnResults,
    decoyResults: gt.decoys.map((d) => ({
      siteId: d.siteId,
      falsePositive: (decoyMatched.get(d.siteId)?.length ?? 0) > 0,
      findingIds: (decoyMatched.get(d.siteId) ?? []).map((f) => f.id),
    })),
    unmatchedFindingIds: unmatched.map((f) => f.id),
  }
}
