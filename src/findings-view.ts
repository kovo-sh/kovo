/**
 * Single pure, browser-safe, terminal findings projection for every operator surface:
 * headline, Report UI, Report summary, Markdown, SARIF, and signed receipt bundle.
 *
 * Includes canonical chain-finding deduplication and baseline HTTP security-header
 * collapse so no downstream consumer ever re-dedupes or re-filters after projection.
 */
import type { Finding, VerificationTier } from './domain.ts'
import { ORIGIN_WIDE_CWE_KEYS } from './finding-keys.ts'

export const STATIC_ANALYSIS_ORIGIN = 'https://static-analysis.invalid'

export type CanonicalSeverity = Finding['severity']
export type FindingBackingKind = 'receipt' | 'composite_receipt' | 'floor_spec' | 'oob' | 'static_only' | 'unbacked'
export type FindingDisposition = 'confirmed' | 'advisory' | 'unverified' | 'suppressed'
export type FindingBaseDisposition = Exclude<FindingDisposition, 'suppressed'>
export type FindingExclusionReason = 'superseded' | 'out_of_scope' | 'tainted_fact' | 'disallowed_provenance' | 'missing_evidence'

export const findingSeverityOrder: Record<Finding['severity'], number> = {
  critical: 0, high: 1, medium: 2, low: 3, informational: 4,
}

export const findingStatusOrder: Record<Finding['status'], number> = {
  confirmed: 0, static_verified: 1, pending: 2, inconclusive: 3, dismissed: 4,
}

export const HEADER_HYGIENE_CHECK_IDS = [
  'content-security-policy',
  'frame-protection',
  'nosniff',
  'referrer-policy',
  'server-disclosure',
] as const

const headerHygieneCheckIdSet = new Set<string>(HEADER_HYGIENE_CHECK_IDS)

const headerHygieneTitlePatterns: readonly RegExp[] = [
  /^content security policy is not enforced$/i,
  /^html response can be embedded without a recorded frame restriction$/i,
  /^mime sniffing protection missing$/i,
  /referrer[- ]policy/i,
  /^response discloses server technology details$/i,
]

export const HEADER_POSTURE_CATEGORY = 'HTTP Security Header Posture'

export function isConsolidatedHeaderPostureFinding(finding: Pick<Finding, 'category' | 'title'>): boolean {
  return finding.category === HEADER_POSTURE_CATEGORY || finding.title.startsWith(HEADER_POSTURE_CATEGORY)
}

export function isBaselineHeaderHygieneFinding(finding: Finding): boolean {
  if (finding.findingKind === 'multi_step_chain') return false
  if (isConsolidatedHeaderPostureFinding(finding)) return false
  if (finding.severity !== 'low' && finding.severity !== 'informational') return false
  if (finding.check?.id && headerHygieneCheckIdSet.has(finding.check.id)) return true
  return headerHygieneTitlePatterns.some(pattern => pattern.test(finding.title.trim()))
}

export interface HeaderPostureSummary {
  origin: string
  status: Finding['status']
  severity: 'low' | 'informational'
  count: number
  checks: Array<{
    id?: string
    title: string
    observed: string | null
    expected?: string
    cwe?: string
  }>
  evidenceIds: string[]
  finding: Finding
}

export function chainFindingDedupKey(finding: Pick<Finding, 'origin' | 'cwe' | 'category' | 'title' | 'fingerprintHash'>): string {
  const origin = finding.origin.trim().toLowerCase()
  const cwe = (finding.cwe ?? '').trim().toUpperCase()
  const title = finding.title.trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
  // A fingerprint already encodes (origin, endpoint, method, param/resolver, cwe), but origin-wide
  // classes (CORS/CSP/HSTS/TLS/cookies) share one host-level root cause and still collapse.
  if (cwe && ORIGIN_WIDE_CWE_KEYS.has(cwe)) return `${origin}::cwe::${cwe}`
  if (finding.fingerprintHash) return `${origin}::fp::${finding.fingerprintHash}`
  if (cwe) return `${origin}::cwe::${cwe}::title::${title}`
  const category = (finding.category ?? 'uncategorized').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-')
  return `${origin}::class::${category}::${title}`
}

export function mergeChainFindings(existing: Finding, incoming: Finding): Finding {
  const existingRank = findingStatusOrder[existing.status]
  const incomingRank = findingStatusOrder[incoming.status]
  const preferIncoming = incomingRank < existingRank ||
    (incomingRank === existingRank && existing.status !== 'confirmed' && existing.status !== 'static_verified')
  const primary = preferIncoming ? incoming : existing
  const secondary = preferIncoming ? existing : incoming
  const primaryVerified = primary.status === 'confirmed' || primary.status === 'static_verified'
  const secondaryVerified = secondary.status === 'confirmed' || secondary.status === 'static_verified'
  const bestSeverity: Finding['severity'] =
    primaryVerified && !secondaryVerified
      ? primary.severity
      : findingSeverityOrder[incoming.severity] < findingSeverityOrder[existing.severity]
        ? incoming.severity
        : existing.severity

  const evidenceIds = [...new Set([...existing.evidenceIds, ...incoming.evidenceIds])]
  const exchangeIds = [...new Set([...(existing.exchangeIds ?? []), ...(incoming.exchangeIds ?? [])])]
  const chainFactIds = [...new Set([...(existing.chainFactIds ?? []), ...(incoming.chainFactIds ?? [])])]
  const codeLocations = primary.codeLocations?.length ? primary.codeLocations : secondary.codeLocations

  const mergedTier: VerificationTier | undefined =
    primary.status === 'confirmed'
      ? (primary.verificationTier && primary.verificationTier !== 'static_verified'
          ? primary.verificationTier
          : (secondary.verificationTier && secondary.verificationTier !== 'static_verified'
              ? secondary.verificationTier
              : 'runtime_confirmed'))
      : (primary.verificationTier ?? secondary.verificationTier)
  const mergedRuntimeProofGap = primary.status === 'confirmed'
    ? (primary.runtimeProofGap ?? null)
    : (primary.runtimeProofGap ?? secondary.runtimeProofGap)

  const p = <K extends keyof Finding>(k: K) => primary[k] ?? secondary[k]
  return {
    ...secondary,
    ...primary,
    id: existing.id,
    severity: bestSeverity,
    findingKind: 'multi_step_chain',
    replaySpecId: p('replaySpecId'),
    verificationTier: mergedTier,
    fingerprintHash: p('fingerprintHash'),
    supersededByFindingId: p('supersededByFindingId'),
    counterevidence: p('counterevidence'),
    confidenceRationale: p('confidenceRationale'),
    severityChangeConditions: p('severityChangeConditions'),
    runtimeProofGap: mergedRuntimeProofGap,
    ...(codeLocations?.length ? { codeLocations } : {}),
    evidenceIds,
    ...(exchangeIds.length ? { exchangeIds } : {}),
    ...(chainFactIds.length ? { chainFactIds } : {}),
    scopeRevision: Math.max(existing.scopeRevision, incoming.scopeRevision),
  }
}

export function deduplicateChainFindings(findings: readonly Finding[]): Finding[] {
  const out: Finding[] = []
  const chainIndex = new Map<string, number>()
  for (const finding of findings) {
    if (finding.findingKind !== 'multi_step_chain') {
      out.push(finding)
      continue
    }
    const key = chainFindingDedupKey(finding)
    const idx = chainIndex.get(key)
    if (idx === undefined) {
      chainIndex.set(key, out.length)
      out.push(finding)
    } else {
      out[idx] = mergeChainFindings(out[idx], finding)
    }
  }
  return out
}

function safeHostname(origin: string): string {
  try { return new URL(origin).hostname } catch { return origin }
}

export function collapseBaselineHeaderFindings(findings: readonly Finding[]): {
  findings: Finding[]
  collapsedCount: number
  hygieneSummaries: HeaderPostureSummary[]
} {
  const kept: Finding[] = []
  const groups = new Map<string, Finding[]>()
  let collapsedCount = 0

  for (const finding of findings) {
    if (!isBaselineHeaderHygieneFinding(finding)) {
      kept.push(finding)
      continue
    }
    collapsedCount += 1
    const key = `${finding.origin}\0${finding.status}`
    const list = groups.get(key) ?? []
    list.push(finding)
    groups.set(key, list)
  }

  const hygieneSummaries: HeaderPostureSummary[] = []
  const consolidatedFindings: Finding[] = []

  for (const items of groups.values()) {
    const first = items[0]
    const origin = first.origin
    const status = first.status
    const severity: 'low' | 'informational' = items.some(item => item.severity === 'low') ? 'low' : 'informational'
    const evidenceIds = [...new Set(items.flatMap(item => item.evidenceIds))]
    const exchangeIds = [...new Set(items.flatMap(item => item.exchangeIds ?? []))]
    const cwes = [...new Set(items.map(item => item.cwe).filter((c): c is string => Boolean(c)))]
    const checks = items.map(item => ({
      id: item.check?.id,
      title: item.title,
      observed: item.check?.observed ?? null,
      expected: item.check?.expected,
      cwe: item.cwe,
    }))
    const host = safeHostname(origin)
    const checkSummary = checks
      .map(c => `${c.title}${c.observed ? ` (${c.observed})` : ''}`)
      .join('; ')
    const remediations = [...new Set(items.map(item => item.remediation.trim()).filter(Boolean))].join(' ')

    const pluralChecks = items.length === 1 ? 'check' : 'checks'
    const consolidated: Finding = {
      id: first.id,
      origin,
      title: `${HEADER_POSTURE_CATEGORY} (${items.length} ${items.length === 1 ? 'header gap' : 'header gaps'})`,
      status,
      severity,
      reason: `Consolidated ${items.length} baseline HTTP security header ${pluralChecks} on ${host}: ${checkSummary}.`,
      remediation: remediations || 'Configure CSP (frame-ancestors), X-Content-Type-Options: nosniff, Referrer-Policy, and minimize Server header disclosures.',
      impact: 'Missing browser security headers weaken defense-in-depth hardening without independently proving an exploitable vulnerability.',
      recheck: 'Re-fetch an authorized response and verify CSP, frame protection, nosniff, Referrer-Policy, and Server headers.',
      category: HEADER_POSTURE_CATEGORY,
      cwe: cwes.join(' / ') || 'CWE-693',
      confidence: status === 'confirmed' ? 'high' : status === 'inconclusive' ? 'low' : 'medium',
      verification: `Consolidated from ${items.length} baseline HTTP security header ${pluralChecks}.`,
      findingKind: 'baseline_check',
      evidenceIds,
      ...(exchangeIds.length ? { exchangeIds } : {}),
      scopeRevision: Math.max(...items.map(item => item.scopeRevision)),
    }

    consolidatedFindings.push(consolidated)
    hygieneSummaries.push({
      origin,
      status,
      severity,
      count: items.length,
      checks,
      evidenceIds,
      finding: consolidated,
    })
  }

  const combined = [...kept, ...consolidatedFindings].sort((a, b) =>
    findingStatusOrder[a.status] - findingStatusOrder[b.status] ||
    findingSeverityOrder[a.severity] - findingSeverityOrder[b.severity] ||
    Number(isConsolidatedHeaderPostureFinding(a)) - Number(isConsolidatedHeaderPostureFinding(b)) ||
    Number(a.findingKind !== 'multi_step_chain') - Number(b.findingKind !== 'multi_step_chain') ||
    a.origin.localeCompare(b.origin) ||
    a.title.localeCompare(b.title),
  )

  return { findings: combined, collapsedCount, hygieneSummaries }
}

export interface OperatorTriageOverlay {
  status?: string | null
  severityOverride?: string | null
  notes?: string | null
  updatedAt?: number
}

export interface FindingsViewInputRow {
  id: string
  origin: string
  status: string
  severity: string
  verificationTier?: VerificationTier | string | null
  verificationStatus?: string | null
  provenance?: string | null
  findingKind?: string | null
  replaySpecId?: string | null
  supersededByFindingId?: string | null
  evidenceIds?: readonly string[] | null
  exchangeIds?: readonly string[] | null
  chainFactIds?: readonly string[] | null
  sourceOrigins?: readonly string[] | null
  assetId?: string | null
  operatorTriage?: OperatorTriageOverlay | null
  hasReceipt?: boolean
  hasCompositeReceipt?: boolean
  hasOobBacking?: boolean
  replaySpecKind?: string | null
}

export interface FindingsScopeContext {
  approvedOrigins?: ReadonlySet<string> | readonly string[]
  approvedAssetIds?: ReadonlySet<string> | readonly string[]
  provenanceAllowedOrigins?: ReadonlySet<string> | readonly string[]
  taintedFactIds?: ReadonlySet<string> | readonly string[]
  requireEvidence?: boolean
}

export interface ProjectedFindingItem<T extends FindingsViewInputRow = FindingsViewInputRow> {
  finding: T
  backingKind: FindingBackingKind
  effectiveSeverity: CanonicalSeverity
  disposition: FindingDisposition
  preSuppressionDisposition: FindingBaseDisposition
  excludedReason?: FindingExclusionReason
  suppressedBy?: 'false_positive' | 'accepted_risk'
}

export interface FindingsViewCounts {
  total: number
  reportable: number
  confirmed: number
  advisories: number
  unverified: number
  suppressed: number
  excluded: number
  pending: number
  inconclusive: number
  dismissed: number
  bySeverity: Record<CanonicalSeverity, number>
  byConfirmedSeverity: Record<CanonicalSeverity, number>
  byExclusion: Partial<Record<FindingExclusionReason, number>>
}

export interface FindingsView<T extends FindingsViewInputRow = FindingsViewInputRow> {
  reportable: ProjectedFindingItem<T>[]
  confirmed: ProjectedFindingItem<T>[]
  advisories: ProjectedFindingItem<T>[]
  unverified: ProjectedFindingItem<T>[]
  suppressed: ProjectedFindingItem<T>[]
  /** Deduped suppressed items whose pre-suppression disposition was confirmed or advisory (for SARIF suppression emission). */
  suppressedReportable: ProjectedFindingItem<T>[]
  excluded: ProjectedFindingItem<T>[]
  items: ProjectedFindingItem<T>[]
  counts: FindingsViewCounts
}

const SEVS = new Set<string>(['critical', 'high', 'medium', 'low', 'informational'])

export function normalizeFindingSeverityOverride(v: unknown): CanonicalSeverity | null {
  if (typeof v !== 'string') return null
  const s = v.trim().toLowerCase()
  return s === 'info' ? 'informational' : SEVS.has(s) ? (s as CanonicalSeverity) : null
}

export function normalizeFindingSeverity(v: unknown, fallback: CanonicalSeverity = 'medium'): CanonicalSeverity {
  return normalizeFindingSeverityOverride(v) ?? fallback
}

const toSet = (x?: ReadonlySet<string> | readonly string[]) => (x === undefined ? undefined : x instanceof Set ? x : new Set(x))
const isStatic = (r: FindingsViewInputRow) =>
  r.status === 'static_verified' || r.verificationTier === 'static_verified' || r.verificationStatus === 'static_advisory'

export function classifyFindingBackingKind(r: FindingsViewInputRow): FindingBackingKind {
  if (r.hasCompositeReceipt) return 'composite_receipt'
  if (r.hasReceipt) return r.hasOobBacking && !r.exchangeIds?.length ? 'oob' : 'receipt'
  if (r.hasOobBacking || r.verificationStatus === 'pending_oob') return 'oob'
  if (isStatic(r) || r.replaySpecKind === 'static_ast_proof') return 'static_only'
  if (r.provenance === 'floor' || r.replaySpecId) return 'floor_spec'
  return 'unbacked'
}

const BASE_RANK: Record<FindingBaseDisposition, number> = { confirmed: 0, advisory: 1, unverified: 2 }

const isFullFinding = (r: FindingsViewInputRow): r is FindingsViewInputRow & Finding =>
  typeof (r as Partial<Finding>).title === 'string' && Array.isArray((r as Partial<Finding>).evidenceIds)

function dedupeProjected<T extends FindingsViewInputRow>(bucket: readonly ProjectedFindingItem<T>[]): ProjectedFindingItem<T>[] {
  const out: ProjectedFindingItem<T>[] = []
  const byKey = new Map<string, number>()
  for (const it of bucket) {
    const f = it.finding
    if (f.findingKind !== 'multi_step_chain' || !isFullFinding(f)) { out.push(it); continue }
    const idx = byKey.get(chainFindingDedupKey(f))
    if (idx === undefined) { byKey.set(chainFindingDedupKey(f), out.length); out.push(it); continue }
    const ex = out[idx]!
    const ef = ex.finding
    const [pri, sec] = BASE_RANK[it.preSuppressionDisposition] < BASE_RANK[ex.preSuppressionDisposition] ? [it, ex] : [ex, it]
    const finding = {
      ...sec.finding, ...pri.finding, ...mergeChainFindings(ef as T & Finding, f as T & Finding),
      hasCompositeReceipt: Boolean(ef.hasCompositeReceipt || f.hasCompositeReceipt),
      hasReceipt: Boolean(ef.hasReceipt || f.hasReceipt),
      hasOobBacking: Boolean(ef.hasOobBacking || f.hasOobBacking),
      operatorTriage: pri.finding.operatorTriage ?? sec.finding.operatorTriage,
    } as T
    const pre = pri.preSuppressionDisposition
    const suppressedBy = pri.suppressedBy ?? sec.suppressedBy
    out[idx] = {
      finding,
      backingKind: classifyFindingBackingKind(finding),
      effectiveSeverity: normalizeFindingSeverityOverride(finding.operatorTriage?.severityOverride)
        ?? (findingSeverityOrder[it.effectiveSeverity] < findingSeverityOrder[ex.effectiveSeverity] ? it.effectiveSeverity : ex.effectiveSeverity),
      disposition: ex.disposition === 'suppressed' || it.disposition === 'suppressed' ? 'suppressed' : pre,
      preSuppressionDisposition: pre,
      ...(suppressedBy ? { suppressedBy } : {}),
    }
  }
  return out
}

function collapseProjectedHeaders<T extends FindingsViewInputRow>(active: readonly ProjectedFindingItem<T>[]): ProjectedFindingItem<T>[] {
  const kept: ProjectedFindingItem<T>[] = []
  const groups = new Map<string, ProjectedFindingItem<T>[]>()
  for (const it of active) {
    const f = it.finding
    if (!isFullFinding(f) || typeof (f as Partial<Finding>).remediation !== 'string' || !isBaselineHeaderHygieneFinding(f)) {
      kept.push(it)
      continue
    }
    const k = `${f.origin}\0${it.disposition}\0${f.status}`
    const g = groups.get(k)
    if (g) g.push(it)
    else groups.set(k, [it])
  }
  for (const g of groups.values()) {
    const first = g[0]!
    const collapsed = collapseBaselineHeaderFindings(g.map(x => x.finding as unknown as Finding)).findings[0]!
    kept.push({
      ...first,
      finding: { ...first.finding, ...collapsed } as T,
      effectiveSeverity: g.reduce<CanonicalSeverity>(
        (b, x) => (findingSeverityOrder[x.effectiveSeverity] < findingSeverityOrder[b] ? x.effectiveSeverity : b),
        normalizeFindingSeverity(collapsed.severity),
      ),
    })
  }
  return kept
}

export function projectRunFindings<T extends FindingsViewInputRow>(
  rows: readonly T[],
  ctx: FindingsScopeContext = {},
): FindingsView<T> {
  const okOrigins = toSet(ctx.approvedOrigins)
  const okAssets = toSet(ctx.approvedAssetIds)
  const extraProv = toSet(ctx.provenanceAllowedOrigins)
  const tainted = toSet(ctx.taintedFactIds)
  const provOk = (o: string) => Boolean(okOrigins?.has(o) || extraProv?.has(o))

  const activeRaw: ProjectedFindingItem<T>[] = []
  const suppressedRaw: ProjectedFindingItem<T>[] = []
  const excluded: ProjectedFindingItem<T>[] = []
  const byExclusion: Partial<Record<FindingExclusionReason, number>> = {}

  for (const r of rows) {
    const st = isStatic(r)
    const rc = !st && r.status === 'confirmed' && (r.verificationStatus == null || r.verificationStatus === 'runtime_confirmed')
    const ts = r.operatorTriage?.status
    const suppressedBy = ts === 'false_positive' || ts === 'accepted_risk' ? ts : undefined
    const preSuppressionDisposition: FindingBaseDisposition = rc ? 'confirmed' : st ? 'advisory' : 'unverified'
    const disposition: FindingDisposition = suppressedBy ? 'suppressed' : preSuppressionDisposition
    const effectiveSeverity = normalizeFindingSeverityOverride(r.operatorTriage?.severityOverride) ?? normalizeFindingSeverity(r.severity)
    const backingKind = classifyFindingBackingKind(r)

    let excludedReason: FindingExclusionReason | undefined
    if (r.supersededByFindingId) {
      excludedReason = 'superseded'
    } else if (okOrigins !== undefined) {
      if (!st) {
        if ((okAssets && r.assetId && !okAssets.has(r.assetId)) || !okOrigins.has(r.origin)) excludedReason = 'out_of_scope'
        else if (r.sourceOrigins?.some(o => !provOk(o))) excludedReason = 'disallowed_provenance'
      } else {
        if (r.origin !== STATIC_ANALYSIS_ORIGIN && !okOrigins.has(r.origin)) excludedReason = 'out_of_scope'
        else if (r.sourceOrigins?.some(o => o !== STATIC_ANALYSIS_ORIGIN && !provOk(o))) excludedReason = 'disallowed_provenance'
      }
    }
    if (!excludedReason && tainted?.size && r.chainFactIds?.some(id => tainted.has(id))) excludedReason = 'tainted_fact'
    if (!excludedReason && ctx.requireEvidence && !r.evidenceIds?.length && !r.exchangeIds?.length) excludedReason = 'missing_evidence'

    const item: ProjectedFindingItem<T> = {
      finding: r,
      backingKind,
      effectiveSeverity,
      disposition,
      preSuppressionDisposition,
      ...(excludedReason ? { excludedReason } : {}),
      ...(suppressedBy ? { suppressedBy } : {}),
    }

    if (excludedReason) {
      excluded.push(item)
      byExclusion[excludedReason] = (byExclusion[excludedReason] ?? 0) + 1
    } else if (disposition === 'suppressed') {
      suppressedRaw.push(item)
    } else {
      activeRaw.push(item)
    }
  }

  const activeDeduped = collapseProjectedHeaders(dedupeProjected(activeRaw))
  const suppressed = dedupeProjected(suppressedRaw)
  const suppressedReportable = suppressed.filter(
    item => item.preSuppressionDisposition === 'confirmed' || item.preSuppressionDisposition === 'advisory',
  )

  const confirmed: ProjectedFindingItem<T>[] = []
  const advisories: ProjectedFindingItem<T>[] = []
  const unverified: ProjectedFindingItem<T>[] = []
  const bySeverity: Record<CanonicalSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  const byConfirmedSeverity: Record<CanonicalSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  let pending = 0
  let inconclusive = 0
  let dismissed = 0

  for (const item of activeDeduped) {
    if (item.disposition === 'confirmed') {
      confirmed.push(item)
      bySeverity[item.effectiveSeverity]++
      byConfirmedSeverity[item.effectiveSeverity]++
    } else if (item.disposition === 'advisory') {
      advisories.push(item)
      bySeverity[item.effectiveSeverity]++
    } else {
      unverified.push(item)
      if (item.finding.status === 'dismissed') dismissed++
      else {
        bySeverity[item.effectiveSeverity]++
        if (item.finding.status === 'pending' || item.finding.status === 'proposed') pending++
        else inconclusive++
      }
    }
  }

  const reportable = [...confirmed, ...advisories]
  const items = [...activeDeduped, ...suppressed, ...excluded]
  return {
    reportable,
    confirmed,
    advisories,
    unverified,
    suppressed,
    suppressedReportable,
    excluded,
    items,
    counts: {
      total: reportable.length + unverified.length,
      reportable: reportable.length,
      confirmed: confirmed.length,
      advisories: advisories.length,
      unverified: unverified.length,
      suppressed: suppressed.length,
      excluded: excluded.length,
      pending,
      inconclusive,
      dismissed,
      bySeverity,
      byConfirmedSeverity,
      byExclusion,
    },
  }
}
