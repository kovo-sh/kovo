import { assessmentCheckTitles } from './domain.ts'
import type {
  CallerCompatibility,
  CapabilityTier,
  CheckCoverage,
  DynamicRetestVerdict,
  Finding,
  OwaspCategory,
  PatchProposalStatus,
  ReportBody,
  SelectedChecks,
  VerificationTier,
} from './domain.ts'

export const checkLabels: Record<CheckCoverage['status'], string> = {
  met: 'Meets baseline',
  gap: 'Gap found',
  inconclusive: 'Inconclusive',
  'not-applicable': 'Not applicable',
  untested: 'Untested',
}

export const owaspStatusLabels: Record<
  NonNullable<ReportBody['owaspCoverage']>[number]['status'],
  string
> = {
  reported: 'Finding reported',
  no_issue_found: 'No issue found',
  ruled_out: 'Ruled out',
  not_applicable: 'Not applicable',
  needs_follow_up: 'Needs follow-up',
}

export const retestVerdictLabels: Record<'reproduced' | 'fixed' | 'inconclusive', string> = {
  reproduced: 'Still reproducible',
  fixed: 'Verified fixed',
  inconclusive: 'Inconclusive',
}

export const findingSeverityOrder: Record<Finding['severity'], number> = {
  critical: 0, high: 1, medium: 2, low: 3, informational: 4,
}

export const findingStatusOrder: Record<Finding['status'], number> = {
  confirmed: 0, static_verified: 1, pending: 2, inconclusive: 3, dismissed: 4,
}

export const verificationTierLabels: Record<VerificationTier, string> = {
  runtime_confirmed: 'Runtime Confirmed',
  static_verified: 'Static Verified',
  baseline_confirmed: 'Baseline Confirmed',
}

export const patchStatusLabels: Record<PatchProposalStatus, string> = {
  draft: 'Draft',
  approved: 'Approved',
  rejected: 'Rejected',
  withheld: 'Withheld',
}

export const callerCompatibilityLabels: Record<CallerCompatibility, string> = {
  attacker_only: 'Refuses attacker only',
  needs_operator_step: 'Needs operator step',
  breaks_callers: 'Breaks legitimate callers',
}

export const dynamicRetestLabels: Record<DynamicRetestVerdict, string> = {
  fixed: 'Dynamic retest: Fixed',
  reproduced: 'Dynamic retest: Reproduced',
  skipped: 'Dynamic retest: Skipped',
}

export function findingVerificationTier(
  finding: Pick<Finding, 'status' | 'verificationTier' | 'findingKind'>,
): VerificationTier | undefined {
  if (finding.verificationTier) return finding.verificationTier
  if (finding.status === 'static_verified') return 'static_verified'
  if (finding.status === 'confirmed') {
    return finding.findingKind === 'baseline_check' ? 'baseline_confirmed' : 'runtime_confirmed'
  }
  return undefined
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

// Origin-wide classes where one root cause covers every route on the host. Keep in sync with
// ORIGIN_WIDE_CWES in src/server/dedupe.ts. Duplicated here so the report layer stays free of
// server/node imports (it also runs in the browser bundle).
const ORIGIN_WIDE_CWE_KEYS = new Set([
  'CWE-942', 'CWE-346', 'CWE-693', 'CWE-1021', 'CWE-319', 'CWE-295', 'CWE-327', 'CWE-614', 'CWE-1004', 'CWE-1275',
])

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

  return {
    ...secondary,
    ...primary,
    id: existing.id,
    severity: bestSeverity,
    findingKind: 'multi_step_chain',
    replaySpecId: primary.replaySpecId ?? secondary.replaySpecId,
    verificationTier: mergedTier,
    fingerprintHash: primary.fingerprintHash ?? secondary.fingerprintHash,
    supersededByFindingId: primary.supersededByFindingId ?? secondary.supersededByFindingId,
    counterevidence: primary.counterevidence ?? secondary.counterevidence,
    confidenceRationale: primary.confidenceRationale ?? secondary.confidenceRationale,
    severityChangeConditions: primary.severityChangeConditions ?? secondary.severityChangeConditions,
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

    const consolidated: Finding = {
      id: first.id,
      origin,
      title: `${HEADER_POSTURE_CATEGORY} (${items.length} ${items.length === 1 ? 'header gap' : 'header gaps'})`,
      status,
      severity,
      reason: `Consolidated ${items.length} baseline HTTP security header ${items.length === 1 ? 'check' : 'checks'} on ${host}: ${checkSummary}.`,
      remediation: remediations || 'Configure Content-Security-Policy (with frame-ancestors), X-Content-Type-Options: nosniff, a restrictive Referrer-Policy, and minimize Server/X-Powered-By disclosures.',
      impact: 'Missing or permissive browser security headers reduce defense-in-depth hardening against client-side attacks and reconnaissance, though they do not independently prove an exploitable vulnerability.',
      recheck: 'Re-fetch a fresh authorized response from this origin and verify CSP, frame protection, X-Content-Type-Options: nosniff, Referrer-Policy, and Server header hygiene.',
      category: HEADER_POSTURE_CATEGORY,
      cwe: cwes.join(' / ') || 'CWE-693',
      confidence: status === 'confirmed' ? 'high' : status === 'inconclusive' ? 'low' : 'medium',
      verification: `Consolidated from ${items.length} baseline HTTP security header ${items.length === 1 ? 'check' : 'checks'}.`,
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

// ---------------------------------------------------------------------------
// v6 provenance / confirmed-vs-advisory report contract
// ---------------------------------------------------------------------------

export const findingProvenances = ['floor', 'agent_only', 'chain_from_floor'] as const
export type FindingProvenance = typeof findingProvenances[number]

export const findingVerificationClasses = [
  'runtime_confirmed', 'pending_oob', 'static_advisory', 'open_proof_gap', 'dismissed',
] as const
export type FindingVerificationClass = typeof findingVerificationClasses[number]

/** Provenance/verification fields persisted beside a finding row (and embedded in its JSON). */
export interface FindingProvenanceFields {
  provenance?: FindingProvenance
  parentFindingIds?: string[] | null
  verificationStatus?: FindingVerificationClass
}

export type ProvenanceFinding = Finding & FindingProvenanceFields

export interface ProvenanceCounts {
  floor: number
  agent_only: number
  chain_from_floor: number
  /** `agent_only + chain_from_floor`: the additive agentic increment over the floor. */
  incremental: number
  /** camelCase aliases consumed by scripts/certify-phase1.ts. */
  agentOnly: number
  chainFromFloor: number
}

export interface ReportProvenanceSurface {
  provenanceCounts: ProvenanceCounts
  /** Static-only, pending-OOB, open-proof-gap and dismissed items; never recall/precision TP. */
  advisories: Finding[]
  /** Only runtime-confirmed findings (the grader's TP pool). */
  confirmedFindings: Finding[]
}

/**
 * Canonical non-superseded predicate shared across runtime confirmation, report saves,
 * Markdown exports, and SARIF exports so superseded upstream findings can never be double-counted.
 */
export function isActiveFinding(
  finding: Pick<Finding, 'supersededByFindingId'>,
): boolean {
  return finding.supersededByFindingId == null || finding.supersededByFindingId === ''
}

/** Project only non-superseded findings. */
export function filterActiveFindings<T extends Pick<Finding, 'supersededByFindingId'>>(
  findings: readonly T[],
): T[] {
  return findings.filter(isActiveFinding)
}

/** A finding is runtime-confirmed only when active (non-superseded) and status *and* verification class agree. */
export function isRuntimeConfirmedFinding(
  finding: Pick<Finding, 'status' | 'verificationTier' | 'supersededByFindingId'> & FindingProvenanceFields,
): boolean {
  if (!isActiveFinding(finding)) return false
  if (finding.status !== 'confirmed') return false
  const verification = finding.verificationStatus
  if (verification !== undefined && verification !== 'runtime_confirmed') return false
  return finding.verificationTier !== 'static_verified'
}

export function findingProvenanceOf(finding: FindingProvenanceFields): FindingProvenance {
  return finding.provenance ?? 'agent_only'
}

export function emptyProvenanceCounts(): ProvenanceCounts {
  return { floor: 0, agent_only: 0, chain_from_floor: 0, incremental: 0, agentOnly: 0, chainFromFloor: 0 }
}

/** Count provenance over the active confirmed set and split the remaining active items into a separate advisory bucket. */
export function buildProvenanceReport(findings: readonly (Finding & FindingProvenanceFields)[]): ReportProvenanceSurface {
  const counts = emptyProvenanceCounts()
  const advisories: Finding[] = []
  const confirmedFindings: Finding[] = []
  for (const finding of filterActiveFindings(findings)) {
    if (!isRuntimeConfirmedFinding(finding)) {
      advisories.push(finding)
      continue
    }
    confirmedFindings.push(finding)
    const provenance = findingProvenanceOf(finding)
    counts[provenance] += 1
  }
  counts.incremental = counts.agent_only + counts.chain_from_floor
  counts.agentOnly = counts.agent_only
  counts.chainFromFloor = counts.chain_from_floor
  return { provenanceCounts: counts, advisories, confirmedFindings }
}

export const suppliedResponseLabel = 'Supplied response metadata'

export function capabilityTierLabel(tier: CapabilityTier): string {
  switch (tier) {
    case 0: return 'Offline Review'
    case 1: return 'Read-Only Scan'
    case 2: return 'Authenticated Testing'
    case 3: return 'Active Testing (Approval-Gated)'
  }
}

export const owaspCategoryTitles: Record<OwaspCategory, string> = {
  'broken-access-control': 'Broken Access Control',
  'auth-identity': 'Auth & Identity',
  'injection-input': 'Injection & Input',
  'cors-client-side': 'CORS & Client-Side',
  'ssrf-redirects': 'SSRF & Redirects',
  'crypto-tls-transport': 'Crypto, TLS & Transport',
  'misconfig-exposure': 'Misconfiguration & Exposure',
  'upload-storage': 'Upload & Storage',
  'business-logic-race': 'Business Logic & Race',
  'dns-takeover-infra': 'DNS Takeover & Infra',
  'llm-ai-security': 'LLM & AI Security',
}

function checkCount(count: number) {
  return count + (count === 1 ? ' check' : ' checks')
}

export function reportHighlights(body: ReportBody) {
  const scope = new Set(body.scope.map(asset => asset.origin))
  const rows = new Map(body.coverage.map(row => [row.origin, row.checks]))
  const counts: Record<CheckCoverage['status'], number> = { met: 0, gap: 0, inconclusive: 0, 'not-applicable': 0, untested: 0 }
  let missingDetails = 0
  for (const origin of scope) {
    const checks = rows.get(origin)
    if (!checks?.length) missingDetails++
    for (const check of checks ?? []) counts[check.status]++
  }
  const coverageParts = [
    counts.met && checkCount(counts.met) + ' met baseline',
    counts.gap && counts.gap + (counts.gap === 1 ? ' verified gap' : ' verified gaps'),
    counts.inconclusive && checkCount(counts.inconclusive) + ' inconclusive',
    counts['not-applicable'] && checkCount(counts['not-applicable']) + ' not applicable',
    counts.untested && checkCount(counts.untested) + ' untested',
    missingDetails && 'Check details unavailable for ' + missingDetails + (missingDetails === 1 ? ' approved host' : ' approved hosts'),
  ].filter(Boolean)

  const owaspCount = body.owaspCoverage?.length ?? 0
  if (owaspCount > 0) {
    coverageParts.push(`${owaspCount} OWASP ${owaspCount === 1 ? 'category' : 'categories'} tracked`)
  }
  const coverage = coverageParts.join(' · ')

  const scopedFindings = collapseBaselineHeaderFindings(
    deduplicateChainFindings(filterActiveFindings(body.findings).filter(item =>
      scope.has(item.origin) || item.status === 'static_verified' || item.verificationTier === 'static_verified',
    )),
  ).findings
  const confirmed = scopedFindings.filter(item => item.status === 'confirmed')
  const staticVerified = scopedFindings.filter(item => item.status === 'static_verified')
  const chainConfirmed = confirmed.filter(item => item.findingKind === 'multi_step_chain').length
  const headerPostureCount = confirmed.filter(item => isConsolidatedHeaderPostureFinding(item)).length
  const prominentConfirmed = confirmed.filter(item => !isConsolidatedHeaderPostureFinding(item))
  const priorityPool = prominentConfirmed.length ? prominentConfirmed : (confirmed.length ? confirmed : staticVerified)
  const first = priorityPool.reduce<Finding | undefined>((highest, finding) => {
    if (!highest || findingSeverityOrder[finding.severity] < findingSeverityOrder[highest.severity]) return finding
    return highest
  }, undefined)
  const count = first ? priorityPool.filter(item => item.severity === first.severity).length : 0
  const priority = first && (count === 1
    ? { label: first.title, finding: first }
    : {
        label: count + (first.severity === 'informational' ? ' informational' : ' ' + first.severity + '-severity') +
          ' findings share top priority. Start with ' + first.title + '.',
        finding: first,
      })
  const openProofGapsCount = body.openProofGaps?.length ??
    (body.owaspCoverage?.filter(entry => entry.status === 'needs_follow_up').length ?? 0)
  const approvedPatchesCount = body.patchProposals?.filter(p => p.status === 'approved').length ?? 0
  return {
    coverage,
    confirmed: confirmed.length,
    staticVerified: staticVerified.length,
    chainConfirmed,
    headerPostureCount,
    openProofGapsCount,
    approvedPatchesCount,
    threatModelHosts: body.threatModel?.length ?? 0,
    owaspTracked: owaspCount,
    priority,
  }
}

export function reportEvidenceSource(sourceMode: 'prepared' | 'public', plan?: SelectedChecks, tier?: CapabilityTier) {
  const sources: string[] = []
  if (tier !== undefined) sources.push(capabilityTierLabel(tier))
  if (!plan || plan.checks.some(id => id !== 'access-policy')) {
    sources.push(sourceMode === 'prepared' ? suppliedResponseLabel : 'Approved HTTPS responses & brokered probes')
  }
  if (plan?.checks.includes('access-policy')) sources.push('Supplied access policy records')
  return sources.join(' · ')
}

export function reportPlanLabel(plan?: SelectedChecks) {
  if (!plan) return undefined
  const label = plan.source === 'standard' ? 'Standard checks' : 'Planned checks'
  return label + ' · ' + plan.checks.map(id => assessmentCheckTitles[id]).join(', ')
}
