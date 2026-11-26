import { randomUUID } from 'node:crypto'
import { createServerFn } from '@tanstack/react-start'
import { z } from 'zod'
import { approvalScopes, id, runLabelText } from './domain.ts'
import { execution } from './server/execution.ts'
import { store } from './server/store.ts'

export const decideApprovalAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    requestId: id.optional(),
    runId: id,
    approvalId: id,
    decision: z.enum(['approved', 'denied']),
    scope: z.enum(approvalScopes).optional(),
  }))
  .handler(({ data }) => {
    const result = store().command({
      requestId: data.requestId ?? randomUUID(),
      runId: data.runId,
      action: 'decide_approval',
      approvalId: data.approvalId,
      decision: data.decision,
      ...(data.scope ? { scope: data.scope } : {}),
    })
    execution().wake()
    return result
  })

export const revokeApprovalLeaseAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    requestId: id.optional(),
    runId: id,
    leaseId: id,
  }))
  .handler(({ data }) => {
    const result = store().command({
      requestId: data.requestId ?? randomUUID(),
      runId: data.runId,
      action: 'revoke_approval_lease',
      leaseId: data.leaseId,
    })
    execution().wake()
    return result
  })

export const removeApprovedPatternAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    requestId: id.optional(),
    runId: id,
    origin: z.string().trim().min(1).max(253),
    method: z.string().trim().min(1).max(16),
    pathPattern: z.string().trim().min(1).max(512),
    scopeRevision: z.number().int().nonnegative().optional(),
  }))
  .handler(({ data }) => {
    const result = store().command({
      requestId: data.requestId ?? randomUUID(),
      runId: data.runId,
      action: 'remove_approved_pattern',
      origin: data.origin,
      method: data.method,
      pathPattern: data.pathPattern,
      scopeRevision: data.scopeRevision,
    })
    execution().wake()
    return result
  })

export const renameRunAction = createServerFn({ method: 'POST' })
  .validator(z.object({
    requestId: id.optional(),
    runId: id,
    label: runLabelText,
  }))
  .handler(({ data }) => store().command({
    requestId: data.requestId ?? randomUUID(),
    runId: data.runId,
    action: 'rename_run',
    label: data.label,
  }))

export const listProjectRunLabelsAction = createServerFn({ method: 'GET' })
  .validator(z.object({ projectId: id }))
  .handler(({ data }) => store().runsRepo.listProjectRunLabels(data.projectId))

export const getRunRerunPresetAction = createServerFn({ method: 'GET' })
  .validator(z.object({ runId: id }))
  .handler(({ data }) => {
    const run = store().run(data.runId)
    return {
      projectId: run.projectId,
      goal: run.goal,
      sourceMode: (run.sourceMode === 'prepared' ? 'public' : run.sourceMode) as 'public',
      capabilityTier: run.capabilityTier,
      approvalPolicy: run.approvalPolicy,
      approvedPersonaIds: run.capabilityTier >= 2 ? run.approvedPersonaIds : [],
      budgetUsd: run.budgetUsd,
      budgetRequests: run.budgetRequests,
      maxRpsPerOrigin: run.maxRpsPerOrigin,
    }
  })
