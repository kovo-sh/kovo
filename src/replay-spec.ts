import { z } from 'zod'
import { findingSeverities, httpMethods, owaspCategories, personaHandle, scopedAssetOrigin } from './domain.ts'

const forbiddenHeaderNames = /^(?:authorization|proxy-authorization|cookie)$/i
/**
 * A verifier-minted token is referenced as `Bearer {{mint_name}}`; the mint itself is declared in
 * the spec's `tokenMints` and produced by the verifier. This is the only Authorization form a spec
 * may carry: a literal token (issued or forged) can never be embedded.
 */
const mintedBearerHeader = /^Bearer \{\{[a-zA-Z_][a-zA-Z0-9_]{0,31}\}\}$/

const safeHeaders = z.record(z.string().min(1).max(64), z.string().max(1024)).refine(
  headers => Object.keys(headers).every(name => {
    if (!forbiddenHeaderNames.test(name)) return true
    return /^authorization$/i.test(name) && typeof headers[name] === 'string' && mintedBearerHeader.test(headers[name]!)
  }),
  'Do not place Authorization or Cookie headers in a replay spec; reference an approved persona handle (or a verifier-minted tokenMints entry) instead.',
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

export const sessionHandleSchema = z.string().regex(/^[a-z0-9_-]{1,32}$/, 'session handle must match /^[a-z0-9_-]{1,32}$/.')

export const csrfBindObjectSchema = z.object({
  headerName: z.string().trim().min(1).max(64).refine(v => !/[\r\n\0]/.test(v), 'Invalid CSRF headerName.').optional(),
  fieldName: z.string().trim().min(1).max(64).refine(v => !/[\r\n\0]/.test(v), 'Invalid CSRF fieldName.').optional(),
  cookieName: z.string().trim().min(1).max(64).refine(v => !/[\r\n\0]/.test(v), 'Invalid CSRF cookieName.').optional(),
})

export const csrfBindSchema = z.union([z.boolean(), csrfBindObjectSchema])
export type CsrfBind = z.output<typeof csrfBindSchema>

export const authMutationSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('alg_none') }),
  z.object({ kind: z.literal('strip_signature') }),
  z.object({ kind: z.literal('expired_replay'), skewSeconds: z.number().int().min(1).max(31_536_000).optional() }),
  z.object({ kind: z.literal('rs256_to_hs256_jwks'), jwksUrl: z.string().url().max(512).optional() }),
  z.object({
    kind: z.literal('kid_inject'),
    value: z.string().min(1).max(256).refine(
      v => !/[\r\n\0]/.test(v) && !containsDestructivePayload(v),
      'kid_inject value rejected.',
    ),
  }),
  z.object({
    kind: z.literal('jku_x5u_canary'),
    header: z.enum(['jku', 'x5u']).default('jku'),
    url: z.string().max(512).refine(
      v => {
        if (/[\r\n\0]/.test(v) || containsDestructivePayload(v)) return false
        if (/\{\{canary_url\}\}/.test(v)) return true
        try {
          const parsed = new URL(v)
          if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
          const host = parsed.hostname.toLowerCase()
          if (host === '169.254.169.254' || host === 'metadata.google.internal' || host.startsWith('169.254.')) return false
          return /^\/c\/guardian-canary-[a-f0-9]{24}$/i.test(parsed.pathname) && !parsed.search && !parsed.hash
        } catch {
          return false
        }
      },
      'jku_x5u_canary url must be a safe http/https Guardian CanaryBroker URL.',
    ).optional(),
    value: z.string().max(512).refine(
      v => {
        if (/[\r\n\0]/.test(v) || containsDestructivePayload(v)) return false
        if (/\{\{canary_url\}\}/.test(v)) return true
        try {
          const parsed = new URL(v)
          if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
          const host = parsed.hostname.toLowerCase()
          if (host === '169.254.169.254' || host === 'metadata.google.internal' || host.startsWith('169.254.')) return false
          return /^\/c\/guardian-canary-[a-f0-9]{24}$/i.test(parsed.pathname) && !parsed.search && !parsed.hash
        } catch {
          return false
        }
      },
      'jku_x5u_canary value must be a safe http/https Guardian CanaryBroker URL.',
    ).optional(),
  }),
  z.object({
    kind: z.literal('claim_swap'),
    claims: z.record(
      z.string().min(1).max(64),
      z.union([z.string().max(256), z.number(), z.boolean()]),
    ),
    unsigned: z.boolean().optional(),
  }),
])
export type AuthMutation = z.output<typeof authMutationSchema>

export const universalParamLocations = ['query', 'json', 'form', 'path', 'header', 'xml', 'graphql_var'] as const
export type UniversalParamLocation = typeof universalParamLocations[number]
export const universalParamLocationSchema = z.enum(universalParamLocations)

export const cacheBusterValueRegex = /^[a-f0-9-]{16,36}$/i

export function extractCacheBusterParam(pathAndQuery: string): string | null {
  try {
    return new URL(pathAndQuery, 'http://guardian.invalid').searchParams.get('_gcb')
  } catch {
    return null
  }
}

const signedFieldName = z.string().trim().regex(/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/)

/**
 * Deterministic self-signed delivery. The verifier mints a throw-away key/timestamp at replay time
 * and recomputes the HMAC over one of the documented canonical forms, so an inline-key receiver can
 * be challenged with a freshly signature-valid (but application-issued-never) delivery rather than a
 * stale probe timestamp. The key is always generated, never supplied by a spec author.
 */
export const bodySignatureSchema = z.object({
  keyField: signedFieldName,
  signatureField: signedFieldName,
  timestampField: signedFieldName.optional(),
  eventField: signedFieldName.optional(),
  canonical: z.enum(['ts_event', 'ts_body', 'event', 'body']),
  algorithm: z.literal('hmac-sha256').default('hmac-sha256'),
  encoding: z.enum(['hex', 'base64']).default('hex'),
})
export type BodySignature = z.output<typeof bodySignatureSchema>

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
    session: sessionHandleSchema.optional(),
    csrfBind: csrfBindSchema.optional(),
    authMutation: authMutationSchema.optional(),
    traceId: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).optional(),
    jsonBody: z.unknown().optional(),
    textBody: z.string().max(32_768).optional(),
    followRedirects: z.boolean().default(false),
    batchCount: z.number().int().min(2).max(10).optional(),
    bodySignature: bodySignatureSchema.optional(),
  }).refine(
    req => !req.authMutation || Boolean(req.persona),
    'authMutation requires a persona handle.',
  ).refine(
    req => !req.bodySignature || req.textBody === undefined,
    'bodySignature requires a jsonBody object (not textBody).',
  ),
  extract: z.array(replayExtractSchema).max(8).optional(),
})

/**
 * Persisted floor-recipe envelope (Cut 3 retest receipts).
 *
 * A spec confirmed by a typed floor recipe records the exact `recipeId` + args that produced it, so
 * a retest re-runs the same recipe and validates a fresh `ProofReceipt` instead of re-interpreting
 * the legacy declarative shape. The legacy fields above stay on the spec for attribution, reporting
 * and the (still reachable) declarative re-verify path; they are not the retest contract.
 */
export const floorRecipeIds = [
  'access_boundary',
  'persisted_mutation',
  'boolean_or_timing',
  'oob_callback',
  'race_burst',
  'disclosure',
  'redirect',
  'browser_sink',
  'injection_fingerprint',
  'conserved_balance',
] as const

export const floorRecipeEnvelopeSchema = z.object({
  recipeId: z.enum(floorRecipeIds),
  /** Recipe arguments exactly as the planner produced them (typed by `FloorRecipeArgsMap`). */
  args: z.record(z.string(), z.unknown()),
})

export type FloorRecipeEnvelope = z.output<typeof floorRecipeEnvelopeSchema>

/**
 * Persisted agent-script proof envelope (v7 M5 script-proof migration).
 *
 * An agent proof is a Layer-3 `guardian_verify` script whose claims the independent transcript
 * oracle confirmed twice (fresh nonce, fresh session). The declarative fields on the row are only
 * attribution for reporting; they are never the confirmation or retest contract. This envelope
 * carries the bounded, redacted-at-rest script and the host-recorded confirmation so a retest can
 * re-run the same script and re-validate a fresh receipt.
 *
 * The full receipt, script artifact id and transcript digests live on the `replay_specs` proof
 * columns (queryable) and in the owner-only evidence artifact (purgeable).
 */
export const agentScriptProofEnvelopeSchema = z.object({
  kind: z.literal('agent_script'),
  runtime: z.enum(['ts', 'python']),
  /** Bounded script source. Redacted at rest; the artifact copy is the purgeable record. */
  script: z.string().min(1).max(64 * 1024),
  /** sha256 of the pre-redaction script, binding the row to the artifact copy. */
  scriptSha256: z.string().regex(/^[a-f0-9]{64}$/),
  /** Oracle verdict of the confirmation run. */
  verdict: z.enum(['confirmed', 'dismissed', 'inconclusive']),
  /** Machine-readable vulnerability class the receipt was built for (when mapped). */
  vulnClass: z.string().trim().min(1).max(64).optional(),
  /** Host-recorded exchange ids the confirmed claims cite (never script-supplied stdout). */
  exchangeIds: z.array(z.string().trim().min(1).max(128)).max(64).default([]),
  /** Transcript digests of the two fresh runs. */
  transcriptDigests: z.array(z.string().trim().min(1).max(128)).max(4).default([]),
  /** Evidence artifact holding the script source and receipt (owner-only, purgeable). */
  receiptArtifactId: z.string().trim().min(1).max(128).optional(),
  confirmedAt: z.number().int().nonnegative(),
})
export type AgentScriptProofEnvelope = z.output<typeof agentScriptProofEnvelopeSchema>

const replayBase = z.object({
  version: z.literal(1),
  /** Typed floor recipe that confirmed (and owns the retest of) this proof. */
  recipe: floorRecipeEnvelopeSchema.optional(),
  /** Layer-3 agent script that confirmed (and owns the retest of) this proof. */
  agentScript: agentScriptProofEnvelopeSchema.optional(),
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
  /**
   * Denied-control evidence path: a control that is *supposed* to be denied (cross-tenant 404/403)
   * is proof of the boundary, not a spec error. Declaring it stops the verifier from encouraging a
   * chain that drops its strongest control; the impact gate still requires a persisted side effect.
   */
  expectControlDenied: z.boolean().optional(),
  /** Minimum role the endpoint is supposed to require (viewer < member < admin < owner). */
  requiredRole: z.enum(['viewer', 'member', 'admin', 'owner']).optional(),
  /** Tenant that owns the acted-on resource; a probe actor from another tenant is a differential. */
  resourceTenant: z.string().trim().min(1).max(64).optional(),
  /** Effective app roles for persona handles (overrides a role label the verifier cannot parse). */
  actorRoles: z.record(personaHandle, z.enum(['viewer', 'member', 'admin', 'owner'])).optional(),
  /**
   * Impact-oracle events this endpoint is modelled to raise (e.g. `cross_tenant_write`,
   * `privilege_escalation`, `mass_assignment`, `invariant_violation`, `csrf_state_change`).
   * A declared event is a requirement, never evidence by itself: the verifier still demands the
   * persisted readback that the event would represent.
   */
  expectedImpactEvents: z.array(z.string().trim().min(1).max(48)).max(8).optional(),
  expectedStatus: expectedStatusSchema.optional(),
  /**
   * Non-secret regex shapes used for proof. The verifier reports which step bodies matched each
   * pattern in `proofMatches` (computed before redaction), so a tenant secret can be proven without
   * persisting the secret itself in the spec or in the evidence report.
   */
  proofPatterns: z.array(z.string().trim().min(4).max(200).refine(
    value => {
      if (/[\r\n\0]/.test(value)) return false
      try {
        new RegExp(value)
        return true
      } catch {
        return false
      }
    },
    'proofPatterns entries must be valid single-line regular expressions.',
  )).max(4).optional(),
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
  ).optional(),
  reusePage: z.boolean().optional(),
  resetContext: z.boolean().optional(),
  persona: personaHandle.optional(),
  session: sessionHandleSchema.optional(),
  csrfBind: csrfBindSchema.optional(),
  traceId: z.string().regex(/^[a-zA-Z0-9_-]{1,64}$/).optional(),
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
  steps: z.array(browserChainStepSchema).min(2).max(8).superRefine((steps, ctx) => {
    if (!steps.some(step => step.role === 'control') || !steps.some(step => step.role === 'probe')) {
      ctx.addIssue({
        code: 'custom',
        message: 'Browser chain replay specs require at least one control step and one probe step.',
      })
    }
    if (!steps[0]?.pathAndQuery) {
      ctx.addIssue({
        code: 'custom',
        path: [0, 'pathAndQuery'],
        message: 'First browser_chain step must specify pathAndQuery.',
      })
    }
    let activeRole: 'control' | 'probe' | null =
      steps[0]?.role === 'control' ? 'control' : steps[0]?.role === 'probe' ? 'probe' : null

    for (let i = 1; i < steps.length; i += 1) {
      const prev = steps[i - 1]
      const cur = steps[i]
      if (cur.resetContext === true) {
        activeRole = null
      }
      if (!cur.pathAndQuery) {
        if (cur.resetContext === true) {
          ctx.addIssue({
            code: 'custom',
            path: [i, 'pathAndQuery'],
            message: 'browser_chain step with resetContext: true must specify pathAndQuery.',
          })
        }
        if (cur.reusePage === false) {
          ctx.addIssue({
            code: 'custom',
            path: [i, 'pathAndQuery'],
            message: 'browser_chain step omitting pathAndQuery cannot set reusePage: false.',
          })
        }
        if (cur.origin !== prev.origin || (cur.persona ?? undefined) !== (prev.persona ?? undefined)) {
          ctx.addIssue({
            code: 'custom',
            path: [i, 'pathAndQuery'],
            message: 'browser_chain step omitting pathAndQuery must keep the same origin and persona as the previous step.',
          })
        }
        if ((cur.role === 'control' && activeRole === 'probe') || (cur.role === 'probe' && activeRole === 'control')) {
          ctx.addIssue({
            code: 'custom',
            path: [i, 'pathAndQuery'],
            message: 'browser_chain step omitting pathAndQuery cannot cross a control/probe context reset boundary.',
          })
        }
      }
      if (cur.role === 'control' || cur.role === 'probe') {
        activeRole = cur.role
      }
    }
  }),
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
  session: sessionHandleSchema.optional(),
  csrfBind: csrfBindSchema.optional(),
  jsonBody: z.unknown().optional(),
  textBody: z.string().max(32_768).optional(),
  followRedirects: z.boolean().default(false),
})

export const raceBurstReplaySpecSchema = replayBase.extend({
  kind: z.literal('race_burst'),
  /** Ordered prerequisite steps (create/mint/read) executed before controlStep; their extracts feed vars. */
  setupSteps: z.array(replayStepSchema).max(6).optional(),
  controlStep: replayStepSchema.optional(),
  burst: z.array(raceBurstRequestSchema).min(2).max(10),
  postCheckStep: replayStepSchema.optional(),
  /** Best-effort restoration steps executed after the burst/post-check (never in the burst itself). */
  cleanupSteps: z.array(replayStepSchema).max(4).optional(),
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
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH']).default('GET'),
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  headers: safeHeaders.optional(),
  persona: personaHandle.optional(),
  session: sessionHandleSchema.optional(),
  csrfBind: csrfBindSchema.optional(),
  /** Optional JSON body object (POST); paramName may use dot-paths such as "filter.name". */
  jsonBody: z.unknown().optional(),
  xmlTemplate: z.string().max(16_384).optional(),
  graphqlQuery: z.string().max(8_192).optional(),
  paramName: z.string().trim().regex(/^[A-Za-z0-9_.\-\[\]]{1,128}$/),
  paramLocation: universalParamLocationSchema.default('query'),
  baselineValue: z.string().max(256).default('1'),
  quoteStyle: z.enum(['single', 'double', 'numeric']).default('single'),
  /** Optional custom value template; may use {{baseline}} and {{sql_expr}} (verifier-minted k=k / k=k+1). */
  valueTemplate: z.string().max(256).optional(),
  controlStep: replayStepSchema.optional(),
}).refine(spec => {
  const serialized = JSON.stringify({
    pathAndQuery: spec.pathAndQuery,
    jsonBody: spec.jsonBody,
    xmlTemplate: spec.xmlTemplate,
    graphqlQuery: spec.graphqlQuery,
    baselineValue: spec.baselineValue,
    valueTemplate: spec.valueTemplate,
  })
  return !containsDestructivePayload(serialized)
}, 'sql_boolean_diff spec rejected by destructive-payload denylist.').refine(
  spec => !spec.valueTemplate || spec.valueTemplate.includes('{{sql_expr}}'),
  'sql_boolean_diff valueTemplate must contain {{sql_expr}}.',
).refine(
  spec => spec.paramLocation !== 'json' || spec.method !== 'GET',
  'sql_boolean_diff paramLocation "json" requires method POST.',
).refine(
  spec => !['form', 'xml', 'graphql_var'].includes(spec.paramLocation) || spec.method !== 'GET',
  'sql_boolean_diff body paramLocation requires POST/PUT/PATCH.',
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

const tokenClaimValue = z.union([z.string().max(256), z.number(), z.boolean()])

/**
 * Verifier-minted JWT for routes that read the token from a JSON/form body rather than a bearer
 * header. Claims are data-anchored placeholders (`{{now}}`, `{{now_plus_1h}}`, `{{subject}}`);
 * nothing here carries a real credential or a signing key.
 */
export const tokenMintSchema = z.object({
  name: z.string().regex(/^[a-zA-Z_][a-zA-Z0-9_]{0,31}$/),
  header: z.record(z.string().min(1).max(64), tokenClaimValue).optional(),
  payload: z.record(z.string().min(1).max(64), tokenClaimValue),
  signature: z.enum(['none', 'strip']).default('none'),
})

export const authProtocolProofReplaySpecSchema = replayBase.extend({
  kind: z.literal('auth_protocol_proof'),
  protocol: z.enum(['jwt', 'oauth', 'oidc', 'session', 'password_reset']).default('jwt'),
  spaCatchallControl: z.boolean().default(false),
  /** Unsigned token material minted into vars before the step loop (body-token routes). */
  tokenMints: z.array(tokenMintSchema).max(4).optional(),
  steps: z.array(replayStepSchema).min(2).max(12).superRefine((steps, ctx) => {
    if (!steps.some(s => s.role === 'control') || !steps.some(s => s.role === 'probe')) {
      ctx.addIssue({
        code: 'custom',
        message: 'auth_protocol_proof requires at least one control step and one probe step.',
      })
    }
  }),
}).refine(
  spec => spec.protocol !== 'jwt' || spec.steps.some(s => Boolean(s.request.authMutation)) || Boolean(spec.tokenMints?.length),
  'auth_protocol_proof with protocol "jwt" requires a step with authMutation or at least one tokenMints entry.',
)

const cachePathSchema = z.string().min(1).max(4096).refine(
  value => value.startsWith('/') && !value.startsWith('//'),
  'Path must start with a single /.',
)

function isValidGcbTokenOrPlaceholder(gcb: string | null, allowedPlaceholder: string): boolean {
  if (!gcb) return false
  if (gcb === allowedPlaceholder || gcb === '{{cache_buster}}') return true
  return cacheBusterValueRegex.test(gcb)
}

export const cacheDifferentialReplaySpecSchema = replayBase.extend({
  kind: z.literal('cache_differential'),
  targetOrigin: scopedAssetOrigin,
  mode: z.enum(['poison', 'deception']).default('poison'),
  method: z.enum(['GET', 'HEAD']).default('GET'),
  controlPath: cachePathSchema,
  probePath: cachePathSchema,
  verifyPath: cachePathSchema.optional(),
  /** Header-free caches: repeat the clean verify after a short delay and compare bodies/actors. */
  proofMode: z.enum(['header', 'body_repeat']).default('header'),
  repeatPath: cachePathSchema.optional(),
  /** An actor-specific marker (tenant canary / personalised value) observed in the warm response. */
  marker: z.string().min(4).max(256).refine(v => !/[\r\n\0]/.test(v), 'marker must be a single-line token.').optional(),
  poisonHeaders: safeHeaders.optional(),
  poisonPersona: personaHandle.optional(),
  controlPersona: personaHandle.optional(),
  verifyPersona: personaHandle.optional(),
  spaCatchallControl: z.boolean().default(false),
}).superRefine((spec, ctx) => {
  if (containsDestructivePayload(JSON.stringify({
    controlPath: spec.controlPath,
    probePath: spec.probePath,
    verifyPath: spec.verifyPath,
    repeatPath: spec.repeatPath,
    poisonHeaders: spec.poisonHeaders,
  }))) {
    ctx.addIssue({ code: 'custom', message: 'cache_differential spec rejected by destructive-payload denylist.' })
  }
  const ctrlGcb = extractCacheBusterParam(spec.controlPath)
  const probeGcb = extractCacheBusterParam(spec.probePath)
  if (!isValidGcbTokenOrPlaceholder(ctrlGcb, '{{control_gcb}}')) {
    ctx.addIssue({
      code: 'custom',
      path: ['controlPath'],
      message: 'cache_differential controlPath requires ?_gcb=<16-36 hex/uuid> (or {{control_gcb}}).',
    })
  }
  if (!isValidGcbTokenOrPlaceholder(probeGcb, '{{probe_gcb}}')) {
    ctx.addIssue({
      code: 'custom',
      path: ['probePath'],
      message: 'cache_differential probePath requires ?_gcb=<16-36 hex/uuid> (or {{probe_gcb}}).',
    })
  }
  if (ctrlGcb && probeGcb && !ctrlGcb.startsWith('{{') && ctrlGcb.toLowerCase() === probeGcb.toLowerCase()) {
    ctx.addIssue({
      code: 'custom',
      path: ['probePath'],
      message: 'cache_differential requires distinct _gcb cache-buster tokens for controlPath and probePath.',
    })
  }
  if (spec.verifyPath) {
    const verifyGcb = extractCacheBusterParam(spec.verifyPath)
    if (!isValidGcbTokenOrPlaceholder(verifyGcb, '{{probe_gcb}}')) {
      ctx.addIssue({
        code: 'custom',
        path: ['verifyPath'],
        message: 'cache_differential verifyPath requires ?_gcb=<16-36 hex/uuid>.',
      })
    }
  }
  if (spec.repeatPath) {
    const repeatGcb = extractCacheBusterParam(spec.repeatPath)
    if (!isValidGcbTokenOrPlaceholder(repeatGcb, '{{repeat_gcb}}')) {
      ctx.addIssue({
        code: 'custom',
        path: ['repeatPath'],
        message: 'cache_differential repeatPath requires ?_gcb=<16-36 hex/uuid>.',
      })
    }
  }
  if (spec.proofMode === 'body_repeat' && !spec.repeatPath) {
    ctx.addIssue({
      code: 'custom',
      path: ['repeatPath'],
      message: 'cache_differential proofMode "body_repeat" requires repeatPath.',
    })
  }
})

export const sqlTimeDiffReplaySpecSchema = replayBase.extend({
  kind: z.literal('sql_time_diff'),
  targetOrigin: scopedAssetOrigin,
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH']).default('GET'),
  pathAndQuery: z.string().min(1).max(4096).refine(
    value => value.startsWith('/') && !value.startsWith('//'),
    'pathAndQuery must start with a single /.',
  ),
  headers: safeHeaders.optional(),
  persona: personaHandle.optional(),
  session: sessionHandleSchema.optional(),
  csrfBind: csrfBindSchema.optional(),
  jsonBody: z.unknown().optional(),
  xmlTemplate: z.string().max(16_384).optional(),
  graphqlQuery: z.string().max(8_192).optional(),
  paramName: z.string().trim().regex(/^[A-Za-z0-9_.\-\[\]]{1,128}$/),
  paramLocation: universalParamLocationSchema.default('query'),
  baselineValue: z.string().max(256).default('1'),
  quoteStyle: z.enum(['single', 'double', 'numeric']).default('single'),
  dialect: z.enum(['postgres', 'mysql', 'sqlite', 'mssql']).default('postgres'),
  delayMs: z.number().int().min(1500).max(3000).optional(),
  valueTemplate: z.string().max(256).optional(),
  requiresTier3Approval: z.boolean().default(true),
  controlStep: replayStepSchema.optional(),
}).refine(spec => !containsDestructivePayload(JSON.stringify({
  pathAndQuery: spec.pathAndQuery,
  jsonBody: spec.jsonBody,
  xmlTemplate: spec.xmlTemplate,
  graphqlQuery: spec.graphqlQuery,
  baselineValue: spec.baselineValue,
  valueTemplate: spec.valueTemplate,
})), 'sql_time_diff spec rejected by destructive-payload denylist.')
  .refine(spec => !spec.valueTemplate || spec.valueTemplate.includes('{{delay_sec}}') || spec.valueTemplate.includes('{{delay_ms}}'),
    'sql_time_diff valueTemplate must contain {{delay_sec}} or {{delay_ms}}.')
  .refine(spec => !['json', 'form', 'xml', 'graphql_var'].includes(spec.paramLocation) || spec.method !== 'GET',
    'sql_time_diff body paramLocation requires POST/PUT/PATCH.')

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
  authProtocolProofReplaySpecSchema,
  cacheDifferentialReplaySpecSchema,
  sqlTimeDiffReplaySpecSchema,
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
export type AuthProtocolProofReplaySpec = z.output<typeof authProtocolProofReplaySpecSchema>
export type CacheDifferentialReplaySpec = z.output<typeof cacheDifferentialReplaySpecSchema>
export type SqlTimeDiffReplaySpec = z.output<typeof sqlTimeDiffReplaySpecSchema>
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
    for (const step of spec.setupSteps ?? []) origins.add(step.request.origin)
    if (spec.controlStep) origins.add(spec.controlStep.request.origin)
    for (const req of spec.burst) origins.add(req.origin)
    if (spec.postCheckStep) origins.add(spec.postCheckStep.request.origin)
    for (const step of spec.cleanupSteps ?? []) origins.add(step.request.origin)
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
  } else if (spec.kind === 'auth_protocol_proof') {
    for (const step of spec.steps) origins.add(step.request.origin)
  } else if (spec.kind === 'sql_time_diff') {
    origins.add(spec.targetOrigin)
    if (spec.controlStep) origins.add(spec.controlStep.request.origin)
  } else {
    origins.add(spec.targetOrigin)
  }
  return [...origins]
}
