import { z } from 'zod'
import { responseCheckIds, responseCheckTitles } from '../domain.ts'
import type { SelectedChecks } from '../domain.ts'

const preferredChecks = z.strictObject({
  checks: z.array(z.enum(responseCheckIds)).min(1).max(responseCheckIds.length),
})

export const standardChecks: SelectedChecks = { source: 'standard', checks: [...responseCheckIds] }

export function reviewPlanPrompt(goal: string, sourceMode: 'prepared' | 'public') {
  return JSON.stringify({
    goal,
    evidence: sourceMode === 'prepared' ? 'supplied response metadata' : 'approved HTTPS response metadata',
    availableChecks: responseCheckIds.map(id => ({ id, title: responseCheckTitles[id] })),
  })
}

export function parseReviewPlan(answer: string): SelectedChecks | null {
  try {
    const text = answer.trim().replace(/^```(?:json)?\s*([\s\S]*?)\s*```$/i, '$1')
    const { checks } = preferredChecks.parse(JSON.parse(text))
    return { source: 'coordinator', checks: responseCheckIds.filter(id => checks.includes(id)) }
  } catch {
    return null
  }
}
