import { z } from 'zod'
import { assetOrigin, findingSeverities, owaspCategories, personaHandle } from './domain.ts'

const forbiddenHeaderNames = /^(?:authorization|proxy-authorization|cookie)$/i

const safeHeaders = z.record(z.string().min(1).max(64), z.string().max(1024)).refine(
  headers => Object.keys(headers).every(name => !forbiddenHeaderNames.test(name)),
  'Do not place Authorization or Cookie headers in a replay spec; reference an approved persona handle instead.',
)

const destructivePatterns = [
  /\b(?:rm\s+-[a-z]*[rf]|mkfs|dd\s+if=|shred|wipefs|shutdown|reboot|halt|poweroff|killall|iptables\s+-F|drop\s+table|truncate\s+table)\b/i,
  /(?:\/dev\/tcp\/|bash\s+-i|nc\s+-[a-z]*e|ncat\s+-[a-z]*e|python[23]?\s+-c\s+.*socket|php\s+-r\s+.*fsockopen|powershell\s+-enc)/i,
  /\/etc\/shadow|169\.254\.169\.254|metadata\.google\.internal/i,
]

export function containsDestructivePayload(text: string): boolean {
  return destructivePatterns.some(pattern => pattern.test(text))
}

export const replayExtractSchema = z.object({
  varName: z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]{0,31}$/),
  from: z.enum(['header', 'json', 'status', 'regex']),
  selector: z.string().min(1).max(256),
})

export const replayStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,32}$/),
  role: z.enum(['setup', 'control', 'probe', 'cleanup']),
  description: z.string().trim().min(1).max(400),
  request: z.object({
    origin: assetOrigin,
    method: z.enum(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH']),
    pathAndQuery: z.string().min(1).max(4096).refine(
      value => value.startsWith('/') && !value.startsWith('//'),
      'pathAndQuery must start with a single /.',
    ),
    headers: safeHeaders.optional(),
    persona: personaHandle.optional(),
    jsonBody: z.unknown().optional(),
    textBody: z.string().max(32_768).optional(),
    followRedirects: z.boolean().default(false),
    batchCount: z.number().int().min(2).max(10).optional(),
  }),
  extract: z.array(replayExtractSchema).max(8).optional(),
})

const replayBase = z.object({
  version: z.literal(1),
  origin: assetOrigin,
  title: z.string().trim().min(3).max(200),
  category: z.enum(owaspCategories).or(z.string().trim().min(1).max(64)),
  cwe: z.string().regex(/^CWE-\d{1,5}$/),
  severity: z.enum(findingSeverities),
  severityRationale: z.string().trim().min(5).max(800),
  impact: z.string().trim().min(5).max(1200),
  remediation: z.string().trim().min(5).max(1500),
  recheckInstructions: z.string().trim().min(5).max(1000),
  assertionsJq: z.string().trim().min(1).max(4096),
})

export const httpChainReplaySpecSchema = replayBase.extend({
  kind: z.literal('http_chain').default('http_chain'),
  spaCatchallControl: z.boolean().default(false),
  steps: z.array(replayStepSchema).min(2).max(12).refine(
    steps => steps.some(step => step.role === 'control') && steps.some(step => step.role === 'probe'),
    'HTTP chain replay specs require at least one control step and one probe step.',
  ),
})

export const dnsTakeoverReplaySpecSchema = replayBase.extend({
  kind: z.literal('dns_takeover'),
  targetOrigin: assetOrigin,
  probePath: z.string().startsWith('/').max(256).default('/'),
})

export const tlsAuditReplaySpecSchema = replayBase.extend({
  kind: z.literal('tls_audit'),
  targetOrigin: assetOrigin,
})

export const browserDomReplaySpecSchema = replayBase.extend({
  kind: z.literal('browser_dom'),
  targetOrigin: assetOrigin,
  controlPath: z.string().startsWith('/').max(2048),
  probePath: z.string().startsWith('/').max(2048),
  persona: personaHandle.optional(),
  checkKind: z.enum(['dom_xss', 'postmessage', 'client_storage', 'xhr_leak']),
})

export const browserChainFetchTargetSchema = z.object({
  origin: assetOrigin,
  pathAndQuery: z.string().min(1).max(2048).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'fetchTarget.pathAndQuery must start with a single /.',
  ),
  method: z.enum(['GET', 'HEAD', 'OPTIONS']).default('GET'),
  credentials: z.enum(['include', 'same-origin', 'omit']).default('include'),
})

export const browserChainStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,32}$/),
  role: z.enum(['setup', 'control', 'probe', 'cleanup']),
  description: z.string().trim().min(1).max(400),
  origin: assetOrigin,
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  persona: personaHandle.optional(),
  action: z.enum(['navigate', 'dom_check', 'postmessage_probe', 'same_site_fetch', 'redirect_observe']).default('navigate'),
  checkKind: z.enum(['dom_xss', 'postmessage', 'client_storage', 'xhr_leak']).optional(),
  selector: z.string().trim().min(1).max(256).refine(
    value => !/[<>{};`\\]|javascript:/i.test(value),
    'selector must be a safe read-only CSS selector.',
  ).optional(),
  fetchTarget: browserChainFetchTargetSchema.optional(),
  postMessageOrigin: z.string().trim().min(1).max(256).optional(),
  postMessagePayload: z.unknown().optional(),
  waitAfterLoadMs: z.number().int().min(0).max(5000).optional(),
}).refine(
  step => step.action !== 'same_site_fetch' || Boolean(step.fetchTarget),
  'browser_chain steps with action "same_site_fetch" require a fetchTarget.',
).refine(
  step => !containsDestructivePayload(JSON.stringify(step)),
  'browser_chain step rejected by destructive-payload denylist.',
)

export const browserChainReplaySpecSchema = replayBase.extend({
  kind: z.literal('browser_chain'),
  spaCatchallControl: z.boolean().default(false),
  steps: z.array(browserChainStepSchema).min(2).max(8).refine(
    steps => steps.some(step => step.role === 'control') && steps.some(step => step.role === 'probe'),
    'Browser chain replay specs require at least one control step and one probe step.',
  ),
})

export const raceBurstRequestSchema = z.object({
  origin: assetOrigin,
  method: z.enum(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH']),
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  headers: safeHeaders.optional(),
  persona: personaHandle.optional(),
  jsonBody: z.unknown().optional(),
  textBody: z.string().max(32_768).optional(),
  followRedirects: z.boolean().default(false),
})

export const raceBurstReplaySpecSchema = replayBase.extend({
  kind: z.literal('race_burst'),
  controlStep: replayStepSchema.optional(),
  burst: z.array(raceBurstRequestSchema).min(2).max(10),
  postCheckStep: replayStepSchema.optional(),
}).refine(
  spec => !containsDestructivePayload(JSON.stringify(spec)),
  'race_burst replay spec rejected by destructive-payload denylist.',
)

export const rceProofReplaySpecSchema = replayBase.extend({
  kind: z.literal('rce_proof'),
  proofMode: z.enum(['dynamic_math', 'split_echo', 'oob_canary']),
  requiresTier3Approval: z.literal(true).default(true),
  controlStep: replayStepSchema,
  probeStep: replayStepSchema,
}).refine(spec => {
  const serialized = JSON.stringify(spec.probeStep.request)
  if (containsDestructivePayload(serialized)) return false
  if (spec.proofMode === 'dynamic_math') return serialized.includes('{{nonce_a}}') && serialized.includes('{{nonce_b}}')
  if (spec.proofMode === 'split_echo') return serialized.includes('{{nonce_part1}}') && serialized.includes('{{nonce_part2}}')
  return serialized.includes('{{canary_token}}') || serialized.includes('{{canary_url}}')
}, 'RCE proof specs must use non-destructive dynamic replay nonces ({{nonce_a}}/{{nonce_b}}, {{nonce_part1}}/{{nonce_part2}}, or {{canary_token}}/{{canary_url}}) and must not contain destructive or reverse-shell payloads.')

export const declarativeReplaySpecSchema = z.discriminatedUnion('kind', [
  httpChainReplaySpecSchema,
  dnsTakeoverReplaySpecSchema,
  tlsAuditReplaySpecSchema,
  browserDomReplaySpecSchema,
  browserChainReplaySpecSchema,
  raceBurstReplaySpecSchema,
  rceProofReplaySpecSchema,
])

export const replaySpecSchema = declarativeReplaySpecSchema

export type ReplayStep = z.output<typeof replayStepSchema>
export type BrowserChainStep = z.output<typeof browserChainStepSchema>
export type BrowserChainReplaySpec = z.output<typeof browserChainReplaySpecSchema>
export type RaceBurstRequest = z.output<typeof raceBurstRequestSchema>
export type RaceBurstReplaySpec = z.output<typeof raceBurstReplaySpecSchema>
export type DeclarativeReplaySpec = z.output<typeof declarativeReplaySpecSchema>

export const replayAssertionOutcomeSchema = z.object({
  confirmed: z.boolean(),
  controlPassed: z.boolean(),
  observed: z.string().max(1200),
  expected: z.string().max(1200),
  reason: z.string().max(1200).optional(),
})

export type ReplayAssertionOutcome = z.output<typeof replayAssertionOutcomeSchema>

export function replaySpecOrigins(spec: DeclarativeReplaySpec): string[] {
  const origins = new Set<string>([spec.origin])
  if (spec.kind === 'http_chain') {
    for (const step of spec.steps) origins.add(step.request.origin)
  } else if (spec.kind === 'browser_chain') {
    for (const step of spec.steps) {
      origins.add(step.origin)
      if (step.fetchTarget) origins.add(step.fetchTarget.origin)
    }
  } else if (spec.kind === 'race_burst') {
    if (spec.controlStep) origins.add(spec.controlStep.request.origin)
    for (const req of spec.burst) origins.add(req.origin)
    if (spec.postCheckStep) origins.add(spec.postCheckStep.request.origin)
  } else if (spec.kind === 'rce_proof') {
    origins.add(spec.controlStep.request.origin)
    origins.add(spec.probeStep.request.origin)
  } else {
    origins.add(spec.targetOrigin)
  }
  return [...origins]
}
