import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { id } from './domain.ts'
import { store } from './server/store.ts'
import {
  operatorSeverityOverrides,
  operatorTriageStatuses,
  patchProposalReviewStatuses,
} from './server/store-findings.ts'

export type {
  OperatorSeverityOverride,
  OperatorTriage,
  OperatorTriageStatus,
  PatchProposalReviewStatus,
  TriagedFinding,
} from './server/store-findings.ts'

const findingOrProposalId = z.string().trim().min(1).max(200)

export const triageFindingAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    runId: id,
    findingId: findingOrProposalId,
    status: z.enum(operatorTriageStatuses).optional(),
    severityOverride: z.enum(operatorSeverityOverrides).nullable().optional(),
    notes: z.string().max(4000).optional(),
  }))
  .handler(({ data }) => {
    const db = store()
    return db.findingsRepo.triageFinding(
      data.findingId,
      {
        ...(data.status !== undefined ? { status: data.status } : {}),
        ...(data.severityOverride !== undefined ? { severityOverride: data.severityOverride } : {}),
        ...(data.notes !== undefined ? { notes: data.notes } : {}),
      },
      { runId: data.runId },
    )
  })

export const reviewPatchProposalAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    runId: id,
    proposalId: findingOrProposalId,
    status: z.enum(patchProposalReviewStatuses),
    reviewNotes: z.string().max(4000).optional(),
  }))
  .handler(({ data }) => {
    const db = store()
    return db.findingsRepo.updatePatchProposalReview(
      data.proposalId,
      {
        status: data.status,
        ...(data.reviewNotes !== undefined ? { reviewNotes: data.reviewNotes } : {}),
      },
      { runId: data.runId },
    )
  })
