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
import { ORIGIN_WIDE_CWE_KEYS } from './finding-keys.ts'
import {
  HEADER_HYGIENE_CHECK_IDS,
  HEADER_POSTURE_CATEGORY,
  chainFindingDedupKey,
  collapseBaselineHeaderFindings,
  deduplicateChainFindings,
  findingSeverityOrder,
  findingStatusOrder,
  isBaselineHeaderHygieneFinding,
  isConsolidatedHeaderPostureFinding,
  mergeChainFindings,
  projectRunFindings,
} from './findings-view.ts'
import type { FindingsScopeContext, FindingsViewInputRow, HeaderPostureSummary } from './findings-view.ts'

export {
  HEADER_HYGIENE_CHECK_IDS,
  HEADER_POSTURE_CATEGORY,
  ORIGIN_WIDE_CWE_KEYS,
  chainFindingDedupKey,
  collapseBaselineHeaderFindings,
  deduplicateChainFindings,
  findingSeverityOrder,
  findingStatusOrder,
  isBaselineHeaderHygieneFinding,
  isConsolidatedHeaderPostureFinding,
  mergeChainFindings,
}
export type { HeaderPostureSummary }

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

export function reportHighlights(body: ReportBody, scopeCtx?: Omit<FindingsScopeContext, 'approvedOrigins'>) {
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

  const projected = projectRunFindings(body.findings as readonly (Finding & FindingsViewInputRow)[], {
    ...scopeCtx,
    approvedOrigins: scope,
  })
  const withEffectiveSev = (item: typeof projected.confirmed[number]): Finding =>
    item.effectiveSeverity === item.finding.severity
      ? item.finding
      : { ...item.finding, severity: item.effectiveSeverity }
  const confirmed = projected.confirmed.map(withEffectiveSev)
  const staticVerified = projected.advisories.map(withEffectiveSev)
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
    reportable: confirmed.length + staticVerified.length,
    suppressed: projected.counts.suppressed,
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
