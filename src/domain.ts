import { z } from 'zod'

export const id = z.uuid()
export const shortText = z.string().trim().min(1).max(120)
export const goalText = z.string().trim().min(1).max(1500)

export const assetOrigin = z.string().trim().min(1).max(253).transform((input, ctx) => {
  try {
    const url = new URL(input.includes('://') ? input : 'https://' + input)
    if (
      url.protocol !== 'https:' || url.username || url.password || url.port ||
      url.pathname !== '/' || url.search || url.hash ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(url.hostname) ||
      /^[\d.]+$/.test(url.hostname)
    ) throw new Error()
    return url.origin
  } catch {
    ctx.addIssue({ code: 'custom', message: 'Enter a hostname or HTTPS origin, such as example.com.' })
    return z.NEVER
  }
})

export const newProject = z.object({
  requestId: id,
  name: shortText,
  seeds: z.array(assetOrigin).min(1).max(24),
})
export const newRun = z.object({ requestId: id, projectId: id, goal: goalText })
export const addCandidate = z.object({
  origin: assetOrigin,
  source: shortText,
  thirdParty: z.boolean(),
})
export const projectAsset = addCandidate.extend({ requestId: id, projectId: id })
const commandBase = z.object({ requestId: id, runId: id })
export const runCommand = z.discriminatedUnion('action', [
  commandBase.extend({ action: z.literal('discover'), consent: z.literal(true) }),
  commandBase.extend({ action: z.literal('scope'), assetIds: z.array(id).max(48), consent: z.literal(true), saveProject: z.boolean().optional() }),
  commandBase.extend({ action: z.literal('candidate'), candidate: addCandidate }),
  commandBase.extend({ action: z.literal('revise'), goal: goalText }),
  commandBase.extend({ action: z.literal('message'), message: goalText }),
  ...(['pause', 'stop', 'resume'] as const).map(action => commandBase.extend({ action: z.literal(action) })),
])

export type RunCommand = z.output<typeof runCommand>
export type Phase = 'consent' | 'discovery' | 'review' | 'analysis' | 'verification' | 'complete'
export type RunStatus = 'waiting' | 'running' | 'paused' | 'stopped' | 'failed' | 'complete'
export type WorkerPhase = 'discovery' | 'analysis' | 'verification'
export type WorkerStatus = 'queued' | 'running' | 'paused' | 'complete' | 'canceled' | 'failed'

export interface Candidate {
  id: string
  origin: string
  source: string
  thirdParty: boolean
}

export interface EvidenceSummary {
  id: string
  assignmentId: string
  scopeRevision: number
  title: string
  kind: 'inventory' | 'observation' | 'verification'
  createdAt: number
}

export interface Finding {
  id: string
  origin: string
  title: string
  status: 'pending' | 'confirmed' | 'dismissed' | 'inconclusive'
  severity: 'low' | 'informational'
  reason: string
  remediation: string
  evidenceIds: string[]
  scopeRevision: number
}

export interface ReportBody {
  goal: string
  scope: Candidate[]
  scopeRevision: number
  goalRevision: number
  coverage: { origin: string; status: string; evidenceId: string | null }[]
  findings: Finding[]
  gaps: string[]
}

export const DEFAULT_PROVIDER = {
  endpoint: 'https://openrouter.ai/api/v1',
  model: 'deepseek/deepseek-v4.1-flash-1017',
  protocol: 'responses' as const,
}
