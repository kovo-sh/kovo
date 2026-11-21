import { z } from 'zod'
import type { AccessPolicySnapshot } from './access-policy.ts'

export const id = z.uuid()
export const shortText = z.string().trim().min(1).max(160)
export const goalText = z.string().trim().min(1).max(8000)
export const maxScopeHosts = 500
export const maxProjectSeeds = 100
export const maxDnsExportBytes = 4 * 1024 * 1024
export const maxSpecBytes = 2 * 1024 * 1024

export const defaultWorkerMaxTurns = 150
export const maxWorkerMaxTurns = 300
export const defaultRunMaxTurns = 2000
export const defaultBudgetUsd = 25
export const defaultBudgetRequests = 2500
export const defaultPublicBudgetRequests = 4000
export const defaultLabBudgetRequests = 10_000
export const maxBudgetRequests = 25_000
export const defaultMaxRpsPerOrigin = 5
export const maxRpsPerOriginCeiling = 20
export const defaultWorkerConcurrency = 6
export const maxWorkerConcurrency = 16

export const capabilityTiers = [0, 1, 2, 3] as const
export type CapabilityTier = typeof capabilityTiers[number]

export const thinkingLevels = ['off', 'low', 'medium', 'high'] as const
export type ThinkingLevel = typeof thinkingLevels[number]

export const httpMethods = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'] as const
export type HttpMethod = typeof httpMethods[number]

export const verificationTiers = ['runtime_confirmed', 'static_verified', 'baseline_confirmed'] as const
export type VerificationTier = typeof verificationTiers[number]

export const findingStatuses = ['pending', 'confirmed', 'static_verified', 'dismissed', 'inconclusive'] as const
export type FindingStatus = typeof findingStatuses[number]

export const coverageClosureStatuses = ['reported', 'no_issue_found', 'ruled_out', 'not_applicable', 'needs_follow_up'] as const
export type CoverageClosureStatus = typeof coverageClosureStatuses[number]

export const patchProposalStatuses = ['draft', 'approved', 'rejected', 'withheld'] as const
export type PatchProposalStatus = typeof patchProposalStatuses[number]

export const callerCompatibilities = ['attacker_only', 'needs_operator_step', 'breaks_callers'] as const
export type CallerCompatibility = typeof callerCompatibilities[number]

export const dynamicRetestVerdicts = ['fixed', 'reproduced', 'skipped'] as const
export type DynamicRetestVerdict = typeof dynamicRetestVerdicts[number]

export const codeLocationSchema = z.object({
  repo: z.string().trim().min(1).max(200),
  file: z.string().trim().min(1).max(500),
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  snippet: z.string().max(4000).optional(),
  label: z.string().max(200).optional(),
})
export type CodeLocation = z.output<typeof codeLocationSchema>

export const labConfigSchema = z.object({
  enabled: z.boolean().default(false),
  repo: z.string().trim().min(1).max(200).optional(),
  startCommand: z.string().trim().min(1).max(500).optional(),
  dockerfile: z.string().trim().min(1).max(300).optional(),
  dockerComposeFile: z.string().trim().min(1).max(300).optional(),
  healthPath: z.string().trim().startsWith('/').max(256).default('/'),
  internalPort: z.number().int().min(1).max(65_535).optional(),
})
export type LabConfig = z.output<typeof labConfigSchema>

export function isLocalLabEnvEnabled(): boolean {
  return typeof process !== 'undefined' && process.env?.GUARDIAN_ALLOW_LOCAL_LAB === '1'
}

function isAllowedLabIpv4(hostname: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname)
  if (!match) return false
  const octets = match.slice(1).map(Number)
  if (octets.some(o => !Number.isInteger(o) || o < 0 || o > 255)) return false
  const [a, b] = octets
  // Loopback (127.0.0.0/8) or RFC1918 private Docker lab subnets (10/8, 172.16/12, 192.168/16).
  // Explicitly excludes 169.254.0.0/16 cloud metadata link-local range.
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}

function parsePublicOrigin(input: string): string | null {
  try {
    const url = new URL(input.includes('://') ? input : 'https://' + input)
    if (
      url.protocol !== 'https:' || url.username || url.password || url.port ||
      url.pathname !== '/' || url.search || url.hash ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(url.hostname) ||
      /^[\d.]+$/.test(url.hostname)
    ) return null
    return url.origin
  } catch {
    return null
  }
}

function parseLabOrigin(input: string): string | null {
  try {
    const url = new URL(input.includes('://') ? input : 'http://' + input)
    if (
      (url.protocol !== 'http:' && url.protocol !== 'https:') ||
      url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash
    ) return null
    const host = url.hostname.toLowerCase()
    if (!host) return null
    if (host === 'localhost' || host === '[::1]' || host === '::1') {
      return url.origin
    }
    if (/^[\d.]+$/.test(host)) {
      return isAllowedLabIpv4(host) ? url.origin : null
    }
    // Reject metadata hostnames even in local-lab mode.
    if (host === 'metadata.google.internal' || host === 'metadata') return null
    if (/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/.test(host)) {
      return url.origin
    }
    return null
  } catch {
    return null
  }
}

export const publicAssetOrigin = z.string().trim().min(1).max(253).transform((input, ctx) => {
  const parsed = parsePublicOrigin(input)
  if (!parsed) {
    ctx.addIssue({ code: 'custom', message: 'Enter a hostname or HTTPS origin, such as example.com.' })
    return z.NEVER
  }
  return parsed
})

export const labAssetOrigin = z.string().trim().min(1).max(253).transform((input, ctx) => {
  if (!isLocalLabEnvEnabled()) {
    // Without GUARDIAN_ALLOW_LOCAL_LAB=1 only strict public HTTPS hostnames are accepted
    // (backwards compatible with v2 local-lab projects); http/port/IP origins stay rejected.
    const pub = parsePublicOrigin(input)
    if (pub) return pub
    ctx.addIssue({
      code: 'custom',
      message: 'Local-lab http/port/IP origins are blocked unless GUARDIAN_ALLOW_LOCAL_LAB=1.',
    })
    return z.NEVER
  }
  const parsed = parseLabOrigin(input)
  if (!parsed) {
    ctx.addIssue({
      code: 'custom',
      message: 'Enter an allowed local-lab HTTP/HTTPS origin (localhost, 127.0.0.1, private Docker subnet, or hostname with optional port).',
    })
    return z.NEVER
  }
  return parsed
})

/** Backwards-compatible public origin schema (strict HTTPS hostname, no port, no IP). */
export const assetOrigin = publicAssetOrigin

/** Accepts public HTTPS origins always, and lab HTTP/port origins ONLY when GUARDIAN_ALLOW_LOCAL_LAB=1. */
export const scopedAssetOrigin = z.string().trim().min(1).max(253).transform((input, ctx) => {
  const pub = parsePublicOrigin(input)
  if (pub) return pub
  if (isLocalLabEnvEnabled()) {
    const lab = parseLabOrigin(input)
    if (lab) return lab
  }
  ctx.addIssue({ code: 'custom', message: 'Enter a hostname or HTTPS origin, such as example.com.' })
  return z.NEVER
})

export function assetOriginForEnvironment(env: 'public' | 'local-lab') {
  return env === 'local-lab' ? labAssetOrigin : publicAssetOrigin
}

export const newProject = z.object({
  requestId: id,
  name: shortText,
  seeds: z.array(z.string().trim().min(1).max(253)).min(1).max(maxProjectSeeds),
  environment: z.enum(['public', 'local-lab']).default('public'),
  labConfig: labConfigSchema.optional(),
}).transform((data, ctx) => {
  const originSchema = assetOriginForEnvironment(data.environment)
  const normalizedSeeds: string[] = []
  for (let i = 0; i < data.seeds.length; i += 1) {
    const parsed = originSchema.safeParse(data.seeds[i])
    if (!parsed.success) {
      ctx.addIssue({
        code: 'custom',
        path: ['seeds', i],
        message: parsed.error.issues[0]?.message ?? 'Invalid project seed origin.',
      })
      return z.NEVER
    }
    normalizedSeeds.push(parsed.data)
  }
  return {
    ...data,
    seeds: normalizedSeeds,
  }
})

export const newRun = z.object({
  requestId: id,
  projectId: id,
  goal: goalText,
  sourceMode: z.enum(['prepared', 'public']).default('public'),
  capabilityTier: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).default(1),
  budgetUsd: z.number().min(0.1).max(500).default(defaultBudgetUsd),
  budgetRequests: z.number().int().min(0).max(maxBudgetRequests).default(defaultBudgetRequests),
  maxRpsPerOrigin: z.number().int().min(1).max(maxRpsPerOriginCeiling).default(defaultMaxRpsPerOrigin),
  workerConcurrency: z.number().int().min(1).max(maxWorkerConcurrency).default(defaultWorkerConcurrency),
  workerMaxTurns: z.number().int().min(1).max(maxWorkerMaxTurns).default(defaultWorkerMaxTurns),
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
  contentSecurityPolicy: z.enum(['absent', 'enforced', 'report-only', 'unrecognized']).optional(),
  frameProtection: z.enum(['absent', 'x-frame-options', 'csp-frame-ancestors', 'both', 'unrecognized']).optional(),
  serverDisclosure: z.enum(['absent', 'generic', 'technology']).optional(),
  corsPolicy: z.enum(['absent', 'restricted', 'wildcard', 'reflected-origin', 'reflected-origin-with-credentials']).optional(),
  errorExposure: z.enum(['none', 'internal-details', 'stack-trace']).optional(),
  sessionCookiePolicy: z.enum(['none', 'secure-httponly', 'secure-only', 'insecure']).optional(),
})

export const addCandidate = z.object({
  origin: assetOrigin,
  source: shortText,
  thirdParty: z.boolean(),
})

export const projectAsset = addCandidate.extend({
  requestId: id,
  projectId: id,
  prepared: preparedObservation.optional(),
})

export const importDnsInventory = z.object({
  requestId: id,
  projectId: id,
  zone: assetOrigin,
  document: z.string().min(1).max(maxDnsExportBytes),
})

export const importProjectSpec = z.object({
  requestId: id,
  projectId: id,
  name: shortText,
  kind: z.enum(['openapi', 'graphql', 'routes', 'notes']),
  origin: assetOrigin.optional(),
  content: z.string().min(1).max(maxSpecBytes),
})

export const personaHandle = z.string().trim().regex(/^[a-z0-9][a-z0-9_-]{0,47}$/)

export const createPersona = z.object({
  requestId: id,
  projectId: id,
  handle: personaHandle,
  roleLabel: shortText,
  originAllowlist: z.array(assetOrigin).min(1).max(64),
  authKind: z.enum(['cookie', 'bearer', 'header']),
  headerName: z.string().trim().regex(/^[A-Za-z0-9-]{1,64}$/).optional(),
  secret: z.string().trim().min(1).max(4096),
  canaryMarkers: z.array(shortText).max(16).default([]),
})

export const deletePersona = z.object({
  requestId: id,
  projectId: id,
  personaId: id,
})

const commandBase = z.object({ requestId: id, runId: id })
export const runCommand = z.discriminatedUnion('action', [
  commandBase.extend({ action: z.literal('discover'), consent: z.literal(true) }),
  commandBase.extend({
    action: z.literal('scope'),
    assetIds: z.array(id).max(maxScopeHosts),
    expectedScopeRevision: z.number().int().nonnegative(),
    consent: z.literal(true),
    saveProject: z.boolean().optional(),
    capabilityTier: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional(),
    approvedPersonaIds: z.array(id).max(32).optional(),
    budgetUsd: z.number().min(0.1).max(500).optional(),
    budgetRequests: z.number().int().min(0).max(maxBudgetRequests).optional(),
    maxRpsPerOrigin: z.number().int().min(1).max(maxRpsPerOriginCeiling).optional(),
  }),
  commandBase.extend({ action: z.literal('candidate'), candidate: addCandidate }),
  commandBase.extend({ action: z.literal('revise'), goal: goalText }),
  commandBase.extend({ action: z.literal('message'), message: goalText }),
  commandBase.extend({ action: z.literal('inject_hint'), hint: goalText, targetAssetId: id.optional() }),
  commandBase.extend({ action: z.literal('decide_approval'), approvalId: id, decision: z.enum(['approved', 'denied']) }),
  commandBase.extend({ action: z.literal('cancel_step'), stepId: id }),
  commandBase.extend({
    action: z.literal('raise_budget'),
    budgetUsd: z.number().min(0.1).max(500).optional(),
    budgetRequests: z.number().int().min(1).max(maxBudgetRequests).optional(),
    resume: z.boolean().default(true),
  }),
  commandBase.extend({ action: z.literal('retest_finding'), findingId: id }),
  ...(['pause', 'stop', 'resume'] as const).map(action => commandBase.extend({ action: z.literal(action) })),
])

export type RunCommand = z.output<typeof runCommand>
export type Phase = 'consent' | 'discovery' | 'review' | 'threat_model' | 'investigation' | 'verification' | 'complete'
export type RunStatus = 'waiting' | 'running' | 'paused' | 'budget_paused' | 'stopped' | 'failed' | 'complete'
export type WorkerPhase = 'discovery' | 'threat_model' | 'investigation' | 'verification' | 'retest'
export type WorkerStatus = 'queued' | 'running' | 'paused' | 'waiting_approval' | 'complete' | 'canceled' | 'failed'

export function workerHistory(
  run: { goalRevision: number; scopeRevision: number; approved: readonly string[] },
  workers: readonly { id: string; assetId: string | null; phase: WorkerPhase; goalRevision: number; scopeRevision: number }[],
) {
  const approved = new Set(run.approved)
  const history = new Map<string, string>()
  for (const worker of workers) {
    if (worker.phase === 'discovery') continue
    if (worker.goalRevision !== run.goalRevision) {
      history.set(worker.id, `Earlier goal · Revision ${worker.goalRevision}`)
    } else if (worker.assetId && run.scopeRevision > 0 && !approved.has(worker.assetId)) {
      history.set(worker.id, 'Host removed from scope')
    }
  }
  return history
}

export function canReviewScope(phase: Phase, status: RunStatus) {
  return phase === 'review' ? status === 'waiting'
    : ['threat_model', 'investigation', 'verification'].includes(phase) && status !== 'complete' && status !== 'failed'
}

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
  kind: 'inventory' | 'observation' | 'access-policy' | 'analysis' | 'verification' | 'handoff' | 'exchange' | 'replay' | 'dns' | 'tls' | 'browser' | 'threat-model' | 'digest' | 'sast' | 'surface' | 'patch' | 'ws'
  createdAt: number
}

export const findingSeverities = ['critical', 'high', 'medium', 'low', 'informational'] as const

export interface PatchProposalSummary {
  id: string
  findingId: string
  repo: string
  status: PatchProposalStatus
  callerCompatibility: CallerCompatibility
  diff: string
  codeLocations: CodeLocation[]
  reviewNotes: string
  dynamicRetestVerdict: DynamicRetestVerdict
  createdAt: number
  updatedAt: number
}

export interface Finding {
  id: string
  origin: string
  title: string
  status: FindingStatus
  severity: typeof findingSeverities[number]
  reason: string
  remediation: string
  evidenceIds: string[]
  scopeRevision: number
  impact?: string
  recheck?: string
  category?: string
  cwe?: string
  confidence?: 'high' | 'medium' | 'low'
  verification?: string
  verificationTier?: VerificationTier
  findingKind?: 'baseline_check' | 'multi_step_chain'
  replaySpecId?: string
  chainFactIds?: string[]
  exchangeIds?: string[]
  fingerprintHash?: string | null
  supersededByFindingId?: string | null
  counterevidence?: string | null
  confidenceRationale?: string | null
  severityChangeConditions?: string | null
  codeLocations?: CodeLocation[]
  runtimeProofGap?: string | null
  check?: Pick<CheckCoverage, 'id' | 'caseId' | 'expected' | 'observed'>
}

export const publicResponseCheckIds = [
  'hsts', 'nosniff', 'referrer-policy', 'content-security-policy', 'frame-protection', 'server-disclosure',
] as const
export const preparedOnlyCheckIds = ['cors-policy', 'error-exposure', 'session-cookie'] as const
export const responseCheckIds = [...publicResponseCheckIds, ...preparedOnlyCheckIds] as const
export type ResponseCheckId = typeof responseCheckIds[number]
export const assessmentCheckIds = [...responseCheckIds, 'access-policy'] as const
export type AssessmentCheckId = typeof assessmentCheckIds[number]
export const assessmentCheckTitles: Record<AssessmentCheckId, string> = {
  hsts: 'HSTS policy',
  nosniff: 'MIME sniffing protection',
  'referrer-policy': 'Referrer policy',
  'content-security-policy': 'Content Security Policy',
  'frame-protection': 'Frame embedding protection',
  'server-disclosure': 'Server technology disclosure',
  'cors-policy': 'Cross-origin access policy',
  'error-exposure': 'Error detail exposure',
  'session-cookie': 'Session cookie attributes',
  'access-policy': 'Access policy decisions',
}

export const owaspCategories = [
  'broken-access-control',
  'auth-identity',
  'injection-input',
  'cors-client-side',
  'ssrf-redirects',
  'crypto-tls-transport',
  'misconfig-exposure',
  'upload-storage',
  'business-logic-race',
  'dns-takeover-infra',
  'llm-ai-security',
] as const
export type OwaspCategory = typeof owaspCategories[number]

export interface SelectedChecks {
  checks: AssessmentCheckId[]
  source: 'coordinator' | 'standard'
}

export type ReviewPlan =
  | { status: 'pending'; goalMessageId: string; previous?: SelectedChecks }
  | ({ status: 'ready'; goalMessageId: string } & SelectedChecks)

export interface CheckCoverage {
  id: AssessmentCheckId
  caseId?: string
  title: string
  status: 'met' | 'gap' | 'inconclusive' | 'not-applicable' | 'untested'
  expected: string
  observed: string | null
  reason: string
}

export interface ChainTimelineStep {
  id: string
  role: string
  description: string
  origin: string
  method?: string
  path?: string
  status?: number
  exchangeId?: string
}

export interface ThreatModelSummary {
  origin: string
  riskTier: 'critical' | 'high' | 'medium' | 'low'
  surfaceTags: string[]
  rationale: string
}

export interface ReportBody {
  goal: string
  capabilityTier: CapabilityTier
  scope: Candidate[]
  scopeRevision: number
  goalRevision: number
  selectedChecks?: SelectedChecks
  threatModel?: ThreatModelSummary[]
  owaspCoverage?: {
    origin: string
    category: OwaspCategory
    status: CoverageClosureStatus
    summary: string
    enforcingControl?: string | null
    proofGapReason?: string | null
    linkedFindingId?: string | null
  }[]
  openProofGaps?: {
    origin: string
    category: string
    summary: string
    proofGapReason: string
  }[]
  patchProposals?: PatchProposalSummary[]
  metrics?: {
    turnsUsed: number
    requestsUsed: number
    factsRecorded: number
    chainStepsCompleted: number
    chainStepsUntested: number
    spentUsd: number
    spentTokens: number
  }
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
  name: 'OpenRouter DeepSeek V4.1 Flash',
  endpoint: 'https://openrouter.ai/api/v1',
  model: 'deepseek/deepseek-v4.1-flash-1017',
  protocol: 'responses' as const,
  contextWindow: 131_072,
  maxTokens: 16_384,
  thinkingLevel: 'medium' as ThinkingLevel,
  inputCostPerMtok: 0.25,
  outputCostPerMtok: 0.90,
}

const providerUrl = z.string().trim().min(1).max(300).transform((input, ctx) => {
  try {
    const url = new URL(input)
    const local = url.protocol === 'http:' && url.hostname === '127.0.0.1' && Boolean(url.port)
    if ((!local && url.protocol !== 'https:') || url.username || url.password || url.search || url.hash) throw new Error()
    return url.origin + url.pathname.replace(/\/+$/, '')
  } catch {
    ctx.addIssue({ code: 'custom', message: 'Enter an HTTPS provider base URL or a local model endpoint on 127.0.0.1.' })
    return z.NEVER
  }
})

export const providerSettings = z.object({
  id: id.optional(),
  name: shortText.default(DEFAULT_PROVIDER.name),
  endpoint: providerUrl,
  model: z.string().trim().regex(/^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$/),
  protocol: z.enum(['responses', 'messages']),
  key: z.string().trim().min(8).max(512).regex(/^[\x21-\x7e]+$/),
  priority: z.number().int().min(0).max(1000).default(100),
  enabled: z.boolean().default(true),
  contextWindow: z.number().int().min(32_000).max(1_000_000).default(DEFAULT_PROVIDER.contextWindow),
  maxTokens: z.number().int().min(512).max(65_536).default(DEFAULT_PROVIDER.maxTokens),
  thinkingLevel: z.enum(thinkingLevels).default(DEFAULT_PROVIDER.thinkingLevel),
  inputCostPerMtok: z.number().min(0).max(500).default(DEFAULT_PROVIDER.inputCostPerMtok),
  outputCostPerMtok: z.number().min(0).max(500).default(DEFAULT_PROVIDER.outputCostPerMtok),
})

export type ProviderSettings = z.output<typeof providerSettings>

export interface PublicModelProfile {
  id: string
  name: string
  endpoint: string
  model: string
  protocol: 'responses' | 'messages'
  priority: number
  enabled: boolean
  contextWindow: number
  maxTokens: number
  thinkingLevel: ThinkingLevel
  inputCostPerMtok: number
  outputCostPerMtok: number
  healthState: 'closed' | 'open' | 'half_open'
  cooldownUntil: number | null
  lastError: string | null
  updatedAt: number
}

export interface PublicPersona {
  id: string
  projectId: string
  handle: string
  roleLabel: string
  originAllowlist: string[]
  authKind: 'cookie' | 'bearer' | 'header'
  headerName: string | null
  canaryMarkers: string[]
  createdAt: number
}
