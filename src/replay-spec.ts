import { z } from 'zod'
import { findingSeverities, httpMethods, owaspCategories, personaHandle, scopedAssetOrigin } from './domain.ts'

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

const webshellPatterns = [
  /<\?(?:php|=)/i,
  /<%[\s=@]/,
  /\beval\s*\(/i,
  /\bchild_process\b/i,
  /\bos\.system\s*\(/i,
  /\bsubprocess\.(?:Popen|run|call|check_output)\s*\(/i,
  /\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(/i,
  /\b(?:execSync|spawnSync)\s*\(/i,
  /\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
  /\b__import__\s*\(\s*['"]os['"]\s*\)/i,
]

export function containsDestructivePayload(text: string): boolean {
  return destructivePatterns.some(pattern => pattern.test(text))
}

export function containsWebshellSignature(text: string): boolean {
  return webshellPatterns.some(pattern => pattern.test(text))
}

export const expectedStatusSchema = z.union([
  z.number().int().min(100).max(599),
  z.array(z.number().int().min(100).max(599)).min(1).max(8),
])

export const replayExtractSchema = z.object({
  varName: z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]{0,31}$/),
  from: z.enum(['header', 'json', 'status', 'regex']),
  selector: z.string().min(1).max(256),
})

export const replayStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,32}$/),
  role: z.enum(['setup', 'control', 'probe', 'cleanup']),
  description: z.string().trim().min(1).max(400),
  expectedStatus: expectedStatusSchema.optional(),
  request: z.object({
    origin: scopedAssetOrigin,
    method: z.enum(httpMethods),
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
  origin: scopedAssetOrigin,
  title: z.string().trim().min(3).max(200),
  category: z.enum(owaspCategories).or(z.string().trim().min(1).max(64)),
  cwe: z.string().regex(/^CWE-\d{1,5}$/),
  severity: z.enum(findingSeverities),
  severityRationale: z.string().trim().min(5).max(800),
  impact: z.string().trim().min(5).max(1200),
  remediation: z.string().trim().min(5).max(1500),
  recheckInstructions: z.string().trim().min(5).max(1000),
  assertionsJq: z.string().trim().min(1).max(4096),
  requireControlNonError: z.boolean().optional(),
  expectedStatus: expectedStatusSchema.optional(),
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
  targetOrigin: scopedAssetOrigin,
  probePath: z.string().startsWith('/').max(256).default('/'),
})

export const tlsAuditReplaySpecSchema = replayBase.extend({
  kind: z.literal('tls_audit'),
  targetOrigin: scopedAssetOrigin,
})

export const browserDomReplaySpecSchema = replayBase.extend({
  kind: z.literal('browser_dom'),
  targetOrigin: scopedAssetOrigin,
  controlPath: z.string().startsWith('/').max(2048),
  probePath: z.string().startsWith('/').max(2048),
  persona: personaHandle.optional(),
  checkKind: z.enum(['dom_xss', 'postmessage', 'client_storage', 'xhr_leak']),
})

export const browserChainFetchTargetSchema = z.object({
  origin: scopedAssetOrigin,
  pathAndQuery: z.string().min(1).max(2048).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'fetchTarget.pathAndQuery must start with a single /.',
  ),
  method: z.enum(['GET', 'HEAD', 'OPTIONS']).default('GET'),
  credentials: z.enum(['include', 'same-origin', 'omit']).default('include'),
})

export const browserBuiltinCheckSchema = z.enum([
  'dom_sinks',
  'forms_inventory',
  'storage_keys',
  'postmessage_audit',
  'canary_presence',
  'page_metadata',
])
export type BrowserBuiltinCheck = z.output<typeof browserBuiltinCheckSchema>

export const browserChainActionTypes = [
  'navigate',
  'dom_check',
  'postmessage_probe',
  'same_site_fetch',
  'redirect_observe',
  'fill',
  'click',
  'select_option',
  'wait_for_selector',
  'wait_for_xhr',
  'evaluate_builtin',
  'dom_xss_sink_hook',
] as const

export const browserChainStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,32}$/),
  role: z.enum(['setup', 'control', 'probe', 'cleanup']),
  description: z.string().trim().min(1).max(400),
  origin: scopedAssetOrigin,
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  persona: personaHandle.optional(),
  action: z.enum(browserChainActionTypes).default('navigate'),
  checkKind: z.enum(['dom_xss', 'postmessage', 'client_storage', 'xhr_leak']).optional(),
  selector: z.string().trim().min(1).max(256).refine(
    value => !/[<>{};`\\]|javascript:/i.test(value),
    'selector must be a safe read-only CSS selector.',
  ).optional(),
  value: z.string().max(2048).optional(),
  builtinCheck: browserBuiltinCheckSchema.optional(),
  urlPattern: z.string().trim().min(1).max(256).optional(),
  enableSinkHook: z.boolean().optional(),
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
  origin: scopedAssetOrigin,
  method: z.enum(httpMethods),
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
  return serialized.includes('{{canary_token}}') || serialized.includes('{{canary_url}}') || serialized.includes('{{canary_dns_host}}')
}, 'RCE proof specs must use non-destructive dynamic replay nonces ({{nonce_a}}/{{nonce_b}}, {{nonce_part1}}/{{nonce_part2}}, or {{canary_token}}/{{canary_url}}/{{canary_dns_host}}) and must not contain destructive or reverse-shell payloads.')

// --- v3 Replay Spec Kinds ---

export const sqlBooleanDiffReplaySpecSchema = replayBase.extend({
  kind: z.literal('sql_boolean_diff'),
  targetOrigin: scopedAssetOrigin,
  method: z.enum(['GET', 'POST']).default('GET'),
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  headers: safeHeaders.optional(),
  persona: personaHandle.optional(),
  /** Optional JSON body object (POST); paramName may use dot-paths such as "filter.name". */
  jsonBody: z.unknown().optional(),
  paramName: z.string().trim().regex(/^[A-Za-z0-9_.\-\[\]]{1,128}$/),
  paramLocation: z.enum(['query', 'json']).default('query'),
  baselineValue: z.string().max(256).default('1'),
  quoteStyle: z.enum(['single', 'double', 'numeric']).default('single'),
  /** Optional custom value template; may use {{baseline}} and {{sql_expr}} (verifier-minted k=k / k=k+1). */
  valueTemplate: z.string().max(256).optional(),
  controlStep: replayStepSchema.optional(),
}).refine(spec => {
  const serialized = JSON.stringify({
    pathAndQuery: spec.pathAndQuery,
    jsonBody: spec.jsonBody,
    baselineValue: spec.baselineValue,
    valueTemplate: spec.valueTemplate,
  })
  return !containsDestructivePayload(serialized)
}, 'sql_boolean_diff spec rejected by destructive-payload denylist.').refine(
  spec => !spec.valueTemplate || spec.valueTemplate.includes('{{sql_expr}}'),
  'sql_boolean_diff valueTemplate must contain {{sql_expr}}.',
).refine(
  spec => spec.paramLocation !== 'json' || spec.method === 'POST',
  'sql_boolean_diff paramLocation "json" requires method POST.',
)

export const wsChainStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,32}$/),
  role: z.enum(['setup', 'control', 'probe', 'cleanup']),
  description: z.string().trim().min(1).max(400),
  origin: scopedAssetOrigin,
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  originHeader: z.string().trim().min(1).max(256).optional(),
  headers: safeHeaders.optional(),
  persona: personaHandle.optional(),
  subprotocols: z.array(z.string().trim().min(1).max(64)).max(4).optional(),
  sendMessages: z.array(z.string().max(8192)).max(10).optional(),
  maxFrames: z.number().int().min(1).max(25).default(10),
  waitMs: z.number().int().min(100).max(10_000).default(1500),
}).refine(
  step => !containsDestructivePayload(JSON.stringify(step)),
  'ws_chain step rejected by destructive-payload denylist.',
)

export const wsChainReplaySpecSchema = replayBase.extend({
  kind: z.literal('ws_chain'),
  steps: z.array(wsChainStepSchema).min(2).max(8).refine(
    steps => steps.some(step => step.role === 'control') && steps.some(step => step.role === 'probe'),
    'ws_chain replay specs require at least one control step and one probe step.',
  ),
})

export const uploadProbeStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9_-]{1,32}$/).default('upload'),
  role: z.enum(['setup', 'probe']).default('probe'),
  description: z.string().trim().min(1).max(400),
  origin: scopedAssetOrigin,
  method: z.enum(['POST', 'PUT']).default('POST'),
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  headers: safeHeaders.optional(),
  persona: personaHandle.optional(),
  fieldName: z.string().trim().min(1).max(128).default('file'),
  filename: z.string().trim().min(1).max(128),
  contentType: z.string().trim().min(1).max(128),
  contentTemplate: z.string().min(1).max(256 * 1024),
  extraFields: z.record(z.string().min(1).max(64), z.string().max(2048)).optional(),
  extract: z.array(replayExtractSchema).max(8).optional(),
})

export const uploadProbeReplaySpecSchema = replayBase.extend({
  kind: z.literal('upload_probe'),
  requiresTier3Approval: z.literal(true).default(true),
  controlStep: replayStepSchema.optional(),
  uploadStep: uploadProbeStepSchema,
  fetchStep: replayStepSchema,
  cleanupStep: replayStepSchema.optional(),
}).refine(spec => {
  const serialized = JSON.stringify(spec)
  if (containsDestructivePayload(serialized)) return false
  if (containsWebshellSignature(spec.uploadStep.contentTemplate) || containsWebshellSignature(spec.uploadStep.filename)) {
    return false
  }
  return spec.uploadStep.contentTemplate.includes('{{upload_nonce}}')
}, 'upload_probe specs must contain {{upload_nonce}} in uploadStep.contentTemplate and must not contain destructive payloads or webshell signatures.')

const safeRelativeRepoPath = z.string().trim().min(1).max(500).refine(
  val => !val.startsWith('/') && !val.includes('\\') && !val.split('/').includes('..') && !/[\r\n\0]/.test(val),
  'Path must be a clean relative path without traversal.',
)

export const staticAstProofReplaySpecSchema = replayBase.extend({
  kind: z.literal('static_ast_proof'),
  origin: scopedAssetOrigin.default('https://static-analysis.invalid'),
  repo: z.string().trim().min(1).max(200).refine(
    val => /^[a-zA-Z0-9._-]+(?:\/[a-zA-Z0-9._-]+)?$/.test(val) && !val.includes('..'),
    'repo must be a safe repository identifier.',
  ),
  file: safeRelativeRepoPath,
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  engine: z.enum(['opengrep', 'ast-grep']),
  ruleOrPattern: z.string().trim().min(1).max(4000),
  sourceToSinkTrace: z.string().trim().max(2000).optional(),
  runtimeProofGap: z.string().trim().min(5).max(1000),
}).refine(
  spec => spec.endLine >= spec.startLine,
  'static_ast_proof endLine must be >= startLine.',
)

export const declarativeReplaySpecSchema = z.discriminatedUnion('kind', [
  httpChainReplaySpecSchema,
  dnsTakeoverReplaySpecSchema,
  tlsAuditReplaySpecSchema,
  browserDomReplaySpecSchema,
  browserChainReplaySpecSchema,
  raceBurstReplaySpecSchema,
  rceProofReplaySpecSchema,
  sqlBooleanDiffReplaySpecSchema,
  wsChainReplaySpecSchema,
  uploadProbeReplaySpecSchema,
  staticAstProofReplaySpecSchema,
])

export const replaySpecSchema = declarativeReplaySpecSchema

export type ReplayStep = z.output<typeof replayStepSchema>
export type BrowserChainStep = z.output<typeof browserChainStepSchema>
export type BrowserChainReplaySpec = z.output<typeof browserChainReplaySpecSchema>
export type RaceBurstRequest = z.output<typeof raceBurstRequestSchema>
export type RaceBurstReplaySpec = z.output<typeof raceBurstReplaySpecSchema>
export type SqlBooleanDiffReplaySpec = z.output<typeof sqlBooleanDiffReplaySpecSchema>
export type WsChainStep = z.output<typeof wsChainStepSchema>
export type WsChainReplaySpec = z.output<typeof wsChainReplaySpecSchema>
export type UploadProbeReplaySpec = z.output<typeof uploadProbeReplaySpecSchema>
export type StaticAstProofReplaySpec = z.output<typeof staticAstProofReplaySpecSchema>
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
  if (spec.kind === 'static_ast_proof') {
    return []
  }
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
  } else if (spec.kind === 'sql_boolean_diff') {
    origins.add(spec.targetOrigin)
    if (spec.controlStep) origins.add(spec.controlStep.request.origin)
  } else if (spec.kind === 'ws_chain') {
    for (const step of spec.steps) origins.add(step.origin)
  } else if (spec.kind === 'upload_probe') {
    origins.add(spec.uploadStep.origin)
    origins.add(spec.fetchStep.request.origin)
    if (spec.controlStep) origins.add(spec.controlStep.request.origin)
    if (spec.cleanupStep) origins.add(spec.cleanupStep.request.origin)
  } else {
    origins.add(spec.targetOrigin)
  }
  return [...origins]
}
