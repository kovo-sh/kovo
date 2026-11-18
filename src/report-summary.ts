import { assessmentCheckTitles } from './domain.ts'
import type { CheckCoverage, SelectedChecks } from './domain.ts'

export const checkLabels: Record<CheckCoverage['status'], string> = {
  met: 'Meets baseline',
  gap: 'Gap found',
  inconclusive: 'Inconclusive',
  'not-applicable': 'Not applicable',
}

export function reportEvidenceSource(sourceMode: 'prepared' | 'public', plan?: SelectedChecks) {
  const sources: string[] = []
  if (!plan || plan.checks.some(id => id !== 'access-policy')) {
    sources.push(sourceMode === 'prepared' ? 'Supplied response metadata' : 'Approved HTTPS root responses')
  }
  if (plan?.checks.includes('access-policy')) sources.push('Supplied access policy records')
  return sources.join(' · ')
}

export function reportPlanLabel(plan?: SelectedChecks) {
  if (!plan) return undefined
  const label = plan.source === 'standard' ? 'Standard checks' : 'Planned checks'
  return label + ' · ' + plan.checks.map(id => assessmentCheckTitles[id]).join(', ')
}
