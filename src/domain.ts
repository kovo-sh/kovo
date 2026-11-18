import { z } from 'zod'
import type { AccessPolicySnapshot } from './access-policy.ts'

export const id = z.uuid()
export const shortText = z.string().trim().min(1).max(120)
export const goalText = z.string().trim().min(1).max(1500)
export const maxScopeHosts = 48
export const maxDnsExportBytes = 128 * 1024

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
export const newRun = z.object({
  requestId: id, projectId: id, goal: goalText,
  sourceMode: z.enum(['prepared', 'public']).default('prepared'),
})
export const referrerPolicies = [
  'no-referrer', 'no-referrer-when-downgrade', 'same-origin', 'origin', 'strict-origin',
  'origin-when-cross-origin', 'strict-origin-when-cross-origin', 'unsafe-url',
] as const

export const preparedObservation = z.object({
  status: z.number().int().min(100).max(599),
  mediaType: z.string().regex(/^[a-z0-9.+-]{1,40}\/[a-z0-9.+-]{1,60}$/),
  transportMaxAge: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).nullable(),
  includeSubDomains: z.boolean(),
  recordedAt: z.iso.datetime().optional(),
  contentTypeOptions: z.enum(['absent', 'nosniff', 'unrecognized']).optional(),
  referrerPolicy: z.enum(['absent', 'unrecognized', ...referrerPolicies]).optional(),
})
export const addCandidate = z.object({
  origin: assetOrigin,
  source: shortText,
  thirdParty: z.boolean(),
})
export const projectAsset = addCandidate.extend({ requestId: id, projectId: id, prepared: preparedObservation.optional() })
export const importDnsInventory = z.object({
  requestId: id, projectId: id, zone: assetOrigin, document: z.string().min(1).max(maxDnsExportBytes),
})
const commandBase = z.object({ requestId: id, runId: id })
export const runCommand = z.discriminatedUnion('action', [
  commandBase.extend({ action: z.literal('discover'), consent: z.literal(true) }),
  commandBase.extend({ action: z.literal('scope'), assetIds: z.array(id).max(maxScopeHosts), consent: z.literal(true), saveProject: z.boolean().optional() }),
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
  sourceEvidenceId?: string
  prepared?: PreparedObservation | null
  dnsSource?: DnsSource | null
  accessPolicy?: AccessPolicySnapshot | null
}

export interface DnsSource {
  zone: string
  recordTypes: ('A' | 'AAAA' | 'CNAME')[]
  externalAliases: string[]
}

export type PreparedObservation = z.output<typeof preparedObservation>

export interface EvidenceSummary {
  id: string
  assignmentId: string
  scopeRevision: number
  title: string
  kind: 'inventory' | 'observation' | 'access-policy' | 'analysis' | 'verification' | 'handoff'
  createdAt: number
}

export interface Finding {
  id: string
  origin: string
  title: string
  status: 'pending' | 'confirmed' | 'dismissed' | 'inconclusive'
  severity: 'medium' | 'low' | 'informational'
  reason: string
  remediation: string
  evidenceIds: string[]
  scopeRevision: number
  impact?: string
  recheck?: string
  check?: Pick<CheckCoverage, 'id' | 'caseId' | 'expected' | 'observed'>
}

export const responseCheckIds = ['hsts', 'nosniff', 'referrer-policy'] as const
export type ResponseCheckId = typeof responseCheckIds[number]
export const assessmentCheckIds = [...responseCheckIds, 'access-policy'] as const
export type AssessmentCheckId = typeof assessmentCheckIds[number]
export const assessmentCheckTitles: Record<AssessmentCheckId, string> = {
  hsts: 'HSTS policy',
  nosniff: 'MIME sniffing protection',
  'referrer-policy': 'Referrer policy',
  'access-policy': 'Access policy decisions',
}

export interface SelectedChecks {
  checks: AssessmentCheckId[]
  source: 'coordinator' | 'standard'
}

export type ReviewPlan =
  | { status: 'pending'; goalMessageId: string }
  | ({ status: 'ready'; goalMessageId: string } & SelectedChecks)

export interface CheckCoverage {
  id: AssessmentCheckId
  caseId?: string
  title: string
  status: 'met' | 'gap' | 'inconclusive' | 'not-applicable'
  expected: string
  observed: string | null
  reason: string
}

export interface ReportBody {
  goal: string
  scope: Candidate[]
  scopeRevision: number
  goalRevision: number
  selectedChecks?: SelectedChecks
  coverage: {
    origin: string
    status: string
    evidenceId: string | null
    analysisEvidenceId?: string
    accessEvidence?: { id: string; recordedAt?: string }
    checks?: CheckCoverage[]
  }[]
  findings: Finding[]
  gaps: string[]
}

export const DEFAULT_PROVIDER = {
  endpoint: 'https://openrouter.ai/api/v1',
  model: 'deepseek/deepseek-v4.1-flash-1017',
  protocol: 'responses' as const,
}

export const providerSettings = z.object({
  endpoint: z.string().trim().min(1).max(300).transform((input, ctx) => {
    try {
      const url = new URL(input)
      const local = url.protocol === 'http:' && url.hostname === '127.0.0.1' && Boolean(url.port)
      if ((!local && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash) throw new Error()
      return url.origin + url.pathname.replace(/\/+$/, '')
    } catch {
      ctx.addIssue({ code: 'custom', message: 'Enter an HTTPS provider base URL or a local model endpoint on 127.0.0.1.' })
      return z.NEVER
    }
  }),
  model: z.string().trim().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$/),
  protocol: z.enum(['responses', 'messages']),
  key: z.string().trim().min(8).max(512).regex(/^[\x21-\x7e]+$/),
})

export type ProviderSettings = z.output<typeof providerSettings>
