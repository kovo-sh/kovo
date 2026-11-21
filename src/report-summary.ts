import { assessmentCheckTitles } from './domain.ts'
import type { CapabilityTier, CheckCoverage, Finding, OwaspCategory, ReportBody, SelectedChecks } from './domain.ts'

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
  confirmed: 0, pending: 1, inconclusive: 2, dismissed: 3,
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

export function chainFindingDedupKey(finding: Pick<Finding, 'origin' | 'cwe' | 'category' | 'title'>): string {
  const origin = finding.origin.trim().toLowerCase()
  const cwe = (finding.cwe ?? '').trim().toUpperCase()
  if (cwe) return `${origin}::cwe::${cwe}`
  const category = (finding.category ?? 'uncategorized').trim().toLowerCase().replace(/[^a-z0-9]+/g, '-')
  const title = finding.title.trim().toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim()
  return `${origin}::class::${category}::${title}`
}

export function mergeChainFindings(existing: Finding, incoming: Finding): Finding {
  const existingRank = findingStatusOrder[existing.status]
  const incomingRank = findingStatusOrder[incoming.status]
  const preferIncoming = incomingRank < existingRank ||
    (incomingRank === existingRank && existing.status !== 'confirmed')
  const primary = preferIncoming ? incoming : existing
  const secondary = preferIncoming ? existing : incoming
  const bestSeverity: Finding['severity'] =
    primary.status === 'confirmed' && secondary.status !== 'confirmed'
      ? primary.severity
      : findingSeverityOrder[incoming.severity] < findingSeverityOrder[existing.severity]
        ? incoming.severity
        : existing.severity

  const evidenceIds = [...new Set([...existing.evidenceIds, ...incoming.evidenceIds])]
  const exchangeIds = [...new Set([...(existing.exchangeIds ?? []), ...(incoming.exchangeIds ?? [])])]
  const chainFactIds = [...new Set([...(existing.chainFactIds ?? []), ...(incoming.chainFactIds ?? [])])]

  return {
    ...secondary,
    ...primary,
    id: existing.id,
    severity: bestSeverity,
    findingKind: 'multi_step_chain',
    replaySpecId: primary.replaySpecId ?? secondary.replaySpecId,
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
      verification: `Consolidated from ${items.length} deterministic baseline header hygiene ${items.length === 1 ? 'check' : 'checks'}.`,
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

export const suppliedResponseLabel = 'Supplied response metadata'

export function capabilityTierLabel(tier: CapabilityTier): string {
  switch (tier) {
    case 0: return 'Tier 0 · Offline Prepared'
    case 1: return 'Tier 1 · Deep Read-Only + Safe Probes'
    case 2: return 'Tier 2 · Multi-Persona Safe Validation'
    case 3: return 'Tier 3 · Approval-Gated State & Execution'
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
    deduplicateChainFindings(body.findings.filter(item => scope.has(item.origin))),
  ).findings
  const confirmed = scopedFindings.filter(item => item.status === 'confirmed')
  const chainConfirmed = confirmed.filter(item => item.findingKind === 'multi_step_chain').length
  const headerPostureCount = confirmed.filter(item => isConsolidatedHeaderPostureFinding(item)).length
  const prominentConfirmed = confirmed.filter(item => !isConsolidatedHeaderPostureFinding(item))
  const priorityPool = prominentConfirmed.length ? prominentConfirmed : confirmed
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
  return {
    coverage,
    confirmed: confirmed.length,
    chainConfirmed,
    headerPostureCount,
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
