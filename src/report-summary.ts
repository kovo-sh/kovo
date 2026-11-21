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

  const confirmed = body.findings.filter(item => scope.has(item.origin) && item.status === 'confirmed')
  const chainConfirmed = confirmed.filter(item => item.findingKind === 'multi_step_chain').length
  const first = confirmed.reduce<Finding | undefined>((highest, finding) => {
    if (!highest || findingSeverityOrder[finding.severity] < findingSeverityOrder[highest.severity]) return finding
    return highest
  }, undefined)
  const count = first ? confirmed.filter(item => item.severity === first.severity).length : 0
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
