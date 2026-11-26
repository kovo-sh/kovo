/**
 * Single pure, browser-safe findings projection for every operator surface:
 * headline, Report UI, Report summary, Markdown, SARIF, and signed receipt bundle.
 */
import type { Finding, VerificationTier } from './domain.ts'

export const STATIC_ANALYSIS_ORIGIN = 'https://static-analysis.invalid'

export type CanonicalSeverity = Finding['severity']
export type FindingBackingKind = 'receipt' | 'composite_receipt' | 'floor_spec' | 'oob' | 'static_only' | 'unbacked'
export type FindingDisposition = 'confirmed' | 'advisory' | 'unverified' | 'suppressed'
export type FindingExclusionReason = 'superseded' | 'out_of_scope' | 'tainted_fact' | 'disallowed_provenance' | 'missing_evidence'

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

export function projectRunFindings<T extends FindingsViewInputRow>(
  rows: readonly T[],
  ctx: FindingsScopeContext = {},
): FindingsView<T> {
  const okOrigins = toSet(ctx.approvedOrigins)
  const okAssets = toSet(ctx.approvedAssetIds)
  const extraProv = toSet(ctx.provenanceAllowedOrigins)
  const tainted = toSet(ctx.taintedFactIds)
  const provOk = (o: string) => Boolean(okOrigins?.has(o) || extraProv?.has(o))

  const confirmed: ProjectedFindingItem<T>[] = []
  const advisories: ProjectedFindingItem<T>[] = []
  const unverified: ProjectedFindingItem<T>[] = []
  const suppressed: ProjectedFindingItem<T>[] = []
  const excluded: ProjectedFindingItem<T>[] = []
  const items: ProjectedFindingItem<T>[] = []
  const bySeverity: Record<CanonicalSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  const byConfirmedSeverity: Record<CanonicalSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  const byExclusion: Partial<Record<FindingExclusionReason, number>> = {}
  let pending = 0
  let inconclusive = 0
  let dismissed = 0

  for (const r of rows) {
    const st = isStatic(r)
    const rc = !st && r.status === 'confirmed' && (r.verificationStatus == null || r.verificationStatus === 'runtime_confirmed')
    const ts = r.operatorTriage?.status
    const suppressedBy = ts === 'false_positive' || ts === 'accepted_risk' ? ts : undefined
    const disposition: FindingDisposition = suppressedBy ? 'suppressed' : rc ? 'confirmed' : st ? 'advisory' : 'unverified'
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
      ...(excludedReason ? { excludedReason } : {}),
      ...(suppressedBy ? { suppressedBy } : {}),
    }
    items.push(item)

    if (excludedReason) {
      excluded.push(item)
      byExclusion[excludedReason] = (byExclusion[excludedReason] ?? 0) + 1
    } else if (disposition === 'suppressed') {
      suppressed.push(item)
    } else if (disposition === 'confirmed') {
      confirmed.push(item)
      bySeverity[effectiveSeverity]++
      byConfirmedSeverity[effectiveSeverity]++
    } else if (disposition === 'advisory') {
      advisories.push(item)
      bySeverity[effectiveSeverity]++
    } else {
      unverified.push(item)
      if (r.status === 'dismissed') dismissed++
      else {
        bySeverity[effectiveSeverity]++
        if (r.status === 'pending' || r.status === 'proposed') pending++
        else inconclusive++
      }
    }
  }

  const reportable = [...confirmed, ...advisories]
  return {
    reportable,
    confirmed,
    advisories,
    unverified,
    suppressed,
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
