import { z } from 'zod'
import { assessmentCheckIds, assessmentCheckTitles, responseCheckIds } from '../domain.ts'
import type { AssessmentCheckId, Candidate, SelectedChecks } from '../domain.ts'

const preferredChecks = z.strictObject({
  checks: z.array(z.enum(assessmentCheckIds)).min(1).max(assessmentCheckIds.length),
})

export function availableReviewChecks(assets: Candidate[], sourceMode: 'prepared' | 'public'): readonly AssessmentCheckId[] {
  if (!assets.some(asset => asset.accessPolicy)) return responseCheckIds
  return sourceMode === 'public' || assets.some(asset => asset.prepared) ? assessmentCheckIds : ['access-policy']
}

export function standardChecks(available: readonly AssessmentCheckId[] = responseCheckIds): SelectedChecks {
  return { source: 'standard', checks: [...available] }
}

export function reviewPlanPrompt(goal: string, sourceMode: 'prepared' | 'public',
  available: readonly AssessmentCheckId[] = responseCheckIds) {
  const evidence = [
    ...(available.some(id => id !== 'access-policy')
      ? [sourceMode === 'prepared' ? 'supplied response metadata' : 'approved HTTPS response metadata'] : []),
    ...(available.includes('access-policy') ? ['supplied access policy records'] : []),
  ]
  return JSON.stringify({
    goal,
    evidence: evidence.join(' and '),
    availableChecks: available.map(id => ({ id, title: assessmentCheckTitles[id] })),
  })
}

export function parseReviewPlan(answer: string, available: readonly AssessmentCheckId[] = responseCheckIds): SelectedChecks | null {
  try {
    const text = answer.trim().replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/i, '$1')
    const { checks } = preferredChecks.parse(JSON.parse(text))
    if (checks.some(id => !available.includes(id))) return null
    return { source: 'coordinator', checks: available.filter(id => checks.includes(id)) }
  } catch {
    return null
  }
}
