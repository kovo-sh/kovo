import { assessmentCheckTitles } from './domain.ts'
import type { CheckCoverage, Finding, ReportBody, SelectedChecks } from './domain.ts'

export const checkLabels: Record<CheckCoverage['status'], string> = {
  met: 'Meets baseline',
  gap: 'Gap found',
  inconclusive: 'Inconclusive',
  'not-applicable': 'Not applicable',
}

export const findingSeverityOrder: Record<Finding['severity'], number> = {
  critical: 0, high: 1, medium: 2, low: 3, informational: 4,
}
export const suppliedResponseLabel = 'Supplied response metadata'

function checkCount(count: number) {
  return count + (count === 1 ? ' check' : ' checks')
}

export function reportHighlights(body: ReportBody) {
  const scope = new Set(body.scope.map(asset => asset.origin))
  const rows = new Map(body.coverage.map(row => [row.origin, row.checks]))
  const counts: Record<CheckCoverage['status'], number> = { met: 0, gap: 0, inconclusive: 0, 'not-applicable': 0 }
  let missingDetails = 0
  for (const origin of scope) {
    const checks = rows.get(origin)
    if (!checks?.length) missingDetails++
    for (const check of checks ?? []) counts[check.status]++
  }
  const coverage = [
    counts.met && checkCount(counts.met) + ' met baseline',
    counts.gap && counts.gap + (counts.gap === 1 ? ' verified gap' : ' verified gaps'),
    counts.inconclusive && checkCount(counts.inconclusive) + ' inconclusive',
    counts['not-applicable'] && checkCount(counts['not-applicable']) + ' not applicable',
    missingDetails && 'Check details unavailable for ' + missingDetails + (missingDetails === 1 ? ' approved host' : ' approved hosts'),
  ].filter(Boolean).join(' · ')

  const confirmed = body.findings.filter(item => scope.has(item.origin) && item.status === 'confirmed')
  const first = confirmed.reduce<Finding | undefined>((highest, finding) => {
    if (!highest || findingSeverityOrder[finding.severity] < findingSeverityOrder[highest.severity]) return finding
    return highest
  }, undefined)
  const count = first ? confirmed.filter(item => item.severity === first.severity).length : 0
  const priority = first && (count === 1
    ? { label: first.title, finding: first }
    : {
        label: count + (first.severity === 'informational' ? ' informational' : ' ' + first.severity + '-severity') +
          ' findings share top priority.',
        finding: undefined,
      })
  return { coverage, confirmed: confirmed.length, priority }
}

export function reportEvidenceSource(sourceMode: 'prepared' | 'public', plan?: SelectedChecks) {
  const sources: string[] = []
  if (!plan || plan.checks.some(id => id !== 'access-policy')) {
    sources.push(sourceMode === 'prepared' ? suppliedResponseLabel : 'Approved HTTPS root responses')
  }
  if (plan?.checks.includes('access-policy')) sources.push('Supplied access policy records')
  return sources.join(' · ')
}

export function reportPlanLabel(plan?: SelectedChecks) {
  if (!plan) return undefined
  const label = plan.source === 'standard' ? 'Standard checks' : 'Planned checks'
  return label + ' · ' + plan.checks.map(id => assessmentCheckTitles[id]).join(', ')
}
