import type { runData } from '../actions.ts'
import type { Phase, WorkerPhase } from '../domain.ts'

export type RunDetail = Awaited<ReturnType<typeof runData>>
export type Worker = RunDetail['assignments'][number]
export const phaseNames: Record<Phase, string> = {
  consent: 'Discovery consent',
  discovery: 'Discovery',
  review: 'Awaiting scope approval',
  analysis: 'Analysis',
  verification: 'Verification',
  complete: 'Complete',
}

export const workerPhases: WorkerPhase[] = ['discovery', 'analysis', 'verification']
