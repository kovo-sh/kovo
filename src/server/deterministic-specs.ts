/**
 * Deterministic replay-spec synthesis for the in-product engine.
 *
 * The engine observes a differential probe signal (see surface-engine.ts) and builds the same
 * declarative replay shapes the benchmark pipeline proved out, but only from what the probe
 * actually observed: the endpoint, parameter location, identifiers and anomaly details. No
 * benchmark manifest or app-specific literal is consulted.
 *
 * Every builder is pure. Callers validate the returned record with
 * `declarativeReplaySpecSchema` and then let ReplayVerifier decide whether it is real, so a
 * builder mistake costs a bounded replay and can never persist an unverified finding.
 */
import { randomBytes } from 'node:crypto'
import {
  bogusIdFor,
  escalatePrivilegeBody,
  fillResourceId,
  isAuthzMatrixHitAdmissible,
  isSafeFieldName,
  isSafeIdentifier,
  isSafePersonaHandle,
  isSafeResourceId,
  pickBaselineWrite,
  PRIVILEGED_ACTION_RE,
  privilegeBaselineFor,
  resolveAuthzReadbackTemplate,
  SAFE_FIELD_NAME_RE,
  SAFE_PERSONA_HANDLE_RE,
  SAFE_RESOURCE_ID_RE,
  SENSITIVE_READ_ROUTE_RE,
} from './floor-heuristics.ts'
import type { AuthzMatrixRow } from './floor-heuristics.ts'
import { browserSinkEnvelopeFromSteps } from './floor-recipes.ts'
import { injectUniversalParam } from './probes/context.ts'
import type { DifferentialProbeClass, DifferentialResult, SurfaceParamLocation } from './surface-engine.ts'

export { bogusIdFor }

export interface EngineParam {
  name: string
  location: SurfaceParamLocation
  isObjectId?: boolean
  isCsrf?: boolean
  /** Schema-declared type from an OpenAPI/route map (string, integer, number, boolean, array, object). */
  declaredType?: string
  /** Runtime value shape observed in the target's own responses (url, path, xml, jwt, uuid, ...). */
  observedShape?: string
}

export interface EngineEndpoint {
  id: string
  origin: string
  method: string
  pathTemplate: string
  params: EngineParam[]
  riskScore?: number
  sinkKinds?: string[]
  source?: string
}

export type EngineIntent =
  | 'authz' | 'sqli' | 'ssti' | 'command_injection' | 'xxe' | 'ssrf' | 'traversal' | 'redirect' | 'xss' | 'graphql'
  | 'mass_assignment' | 'cache' | 'stored_xss' | 'csrf' | 'workflow' | 'race' | 'webhook' | 'auth_protocol' | 'secret_disclosure'

export interface EngineHypothesis {
  key: string
  endpoint: EngineEndpoint
  probeClass: DifferentialProbeClass
  intent: EngineIntent
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  /** Probe/replay path. Object-level authz hypotheses keep a `{{id}}` placeholder. */
  pathAndQuery: string
  param?: EngineParam
  location?: SurfaceParamLocation
  ownerPersona?: string
  otherPersona?: string
  resourceIds?: string[]
  jsonBody?: Record<string, unknown>
  formBody?: Record<string, string>
  xmlTemplate?: string
  graphqlQuery?: string
  baselineValue?: string
  candidateFields?: string[]
  candidateValues?: Record<string, string | boolean | number>
  ssrfParams?: string[]
  functionLevel?: boolean
  idParamName?: string
  /** Second-order SSRF: route that re-triggers the stored fetch, with `{{resource_id}}`. */
  triggerPath?: string
  /** Second-order XSS / CSRF: downstream read route. */
  readPath?: string
  /** workflow_invariant: collection list used to seed a transition target. */
  workflowListPath?: string
  /** workflow_invariant: readable detail route that exposes the object state. */
  workflowReadPath?: string
  /** workflow_invariant: the transition template with its original path placeholder. */
  workflowTargetTemplate?: string
  /** workflow_invariant: invoke the same terminal transition twice (step-skip proof). */
  repeatTransition?: boolean
  /** workflow_invariant: numeric quantity field for a conserved-value bound. */
  quantityField?: string
  /** Run-scoped headers (staging tenant/run tag) that every mutating replay step must carry. */
  headers?: Record<string, string>
  /** Multi-step client-price flow: producer route that mints the object the terminal route consumes. */
  flowCreatePath?: string
  /** Client-price-trust hypothesis: a terminal money route that trusts a caller-supplied price. */
  priceTrust?: boolean
  /** Synchronized state-changing burst hypothesis (TOCTOU / double-spend). */
  raceBurst?: boolean
  /** Bound session handle used for CSRF replay (no Authorization/Cookie headers). */
  session?: string
  graphqlRoots?: string[]
  graphqlSeedsByRoot?: Record<string, string[]>
  stateField?: string
  bodyField?: string
  createReadTemplate?: string
  secretScan?: boolean
  viewerPersona?: string
  csrfBind?: boolean
  /**
   * authz_matrix: a GET route that reads the mutated object (or the target actor's own identity)
   * so a mutating proof can carry a pre/post readback. The engine sets this when its harvest has
   * already observed the reading route; without it the synthesizer falls back to the endpoint's own
   * REST detail/function surface.
   */
  readbackPath?: string
  /** authz_matrix: actor for `readbackPath` when the read is the mutated user's own identity route. */
  readbackPersona?: string
  /**
   * authz_matrix (self-service function state): the identity field(s) the mutation body carried and
   * the value the post-mutation identity read must show. The readback is the actor's own observable
   * state, so the proof binds a named field instead of accepting an arbitrary body difference.
   */
  functionState?: {
    bindings: Array<{ field: string; value: string }>
    /** Identity values that restore the probe actor's own baseline before the mutation. */
    reset?: Array<{ field: string; value: string }>
    /** The replay mutation body (the probe matrix carries the non-mutating own-value body). */
    body?: Record<string, unknown>
  }
  /** authz_matrix: role the privileged control needed, when the probe outcome established it. */
  authzRequiredRole?: 'viewer' | 'member' | 'admin' | 'owner'
  /**
   * authz_matrix (destructive routes): an identifier held back from the probe matrix so the replay
   * has a live victim to act on. The probe still exercises the other identifiers; the reserved one
   * is only touched by the replay chain, where a real state change can be observed.
   */
  reservedVictimId?: string
  /** auth_protocol_audit: body/header fields that carry a token (body-token routes). */
  tokenFields?: string[]
  /** auth_protocol_audit: session-derived scalar claims for a forged token payload. */
  identityClaims?: Record<string, string>
  /** webhook_signature_bypass: delivery body and signature header name. */
  webhookBody?: Record<string, unknown>
  webhookHeader?: string
  risk: number
  notes?: string[]
}

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface SynthesizedEngineSpec {
  kind: string
  /** Canonical class label used for attribution/dedupe (benchmark-compatible spelling). */
  vulnClass: string
  endpoint: string
  spec: Record<string, unknown>
  /**
   * Runtime evidence the probe collected for this spec: the durable `pending_oob` subscription
   * ids and the callback stage (`immediate` / `late` / `pending`). It is deliberately outside the
   * persisted replay-spec schema; persistence and the run-level drain read it to correlate a late
   * callback with the finding it belongs to.
   */
  evidence?: Record<string, unknown>
}

interface RequestParts {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  pathAndQuery: string
  headers?: Record<string, string>
  jsonBody?: unknown
  textBody?: string
}

const jqStr = (v: string) => JSON.stringify(v)
const is2xx = (stepId: string) => `(.steps.${stepId}.status >= 200 and .steps.${stepId}.status < 300)`
const nonTrivial = (stepId: string, minBytes = 3) =>
  `(((${is2xx(stepId)})) and (((.steps.${stepId}.body | length) > ${minBytes}) or (((.steps.${stepId}.json | type) == "object") and (((.steps.${stepId}.json | keys | length) >= 2)))))`

interface FloorClassCopyTemplate {
  impact: string
  remediation: string
}

const FLOOR_COPY_BY_CLASS: Readonly<Record<string, FloorClassCopyTemplate>> = {
  bola: {
    impact: 'An authenticated actor can read or alter resources belonging to another user or tenant.',
    remediation: 'Enforce server-side object-level ownership and tenant authorization checks on every request naming a resource identifier.',
  },
  bfla: {
    impact: 'A lower-privileged actor can invoke a privileged administrative or role-gated function.',
    remediation: 'Enforce explicit server-side role and capability checks on every privileged endpoint rather than relying on client-side controls.',
  },
  sqli: {
    impact: 'Untrusted input alters server-side database query structure or evaluation.',
    remediation: 'Use parameterized queries or prepared statements and strict input validation; never concatenate untrusted input into queries.',
  },
  xxe: {
    impact: 'The XML parser resolves attacker-supplied external entities, enabling server-side file reads or out-of-band network callbacks.',
    remediation: 'Disable external entity resolution and DTD processing in the XML parser configuration.',
  },
  ssrf: {
    impact: 'The server issues outbound network requests to attacker-controlled destinations, exposing internal services or metadata endpoints.',
    remediation: 'Validate and allowlist outbound destination hosts and schemes; block private, loopback, and link-local IP ranges after DNS resolution.',
  },
  path_traversal: {
    impact: 'Attacker-supplied path input escapes the intended server root directory, allowing arbitrary file reads.',
    remediation: 'Canonicalize file paths server-side and verify the resolved path remains strictly inside the permitted base directory.',
  },
  open_redirect: {
    impact: 'Unvalidated redirect targets send users to attacker-controlled external origins.',
    remediation: 'Restrict redirect destinations to relative paths or an explicit allowlist of trusted origins.',
  },
  mass_assignment: {
    impact: 'Over-posted request fields persist privileged or protected attributes that the caller is not permitted to set.',
    remediation: 'Explicitly allowlist client-assignable fields and bind protected attributes server-side from trusted session context.',
  },
  csrf: {
    impact: 'A cross-site request can trigger state-changing actions using the victim’s ambient session credentials without an anti-CSRF token.',
    remediation: 'Require a validated per-session anti-CSRF token on state-changing routes and enforce SameSite cookie attributes.',
  },
  info_disclosure: {
    impact: 'Sensitive credentials, secrets, or audit records are exposed in responses returned to unentitled callers.',
    remediation: 'Remove credentials and internal secrets from response payloads and audit logs, and enforce server-side field filtering.',
  },
  xss: {
    impact: 'Untrusted input is rendered as executable script markup in a victim’s browser context.',
    remediation: 'Apply context-appropriate output encoding, sanitize rich HTML safely, and enforce a strict Content-Security-Policy.',
  },
  ssti: {
    impact: 'Untrusted input is evaluated as server-side template expressions, enabling server-side code execution.',
    remediation: 'Pass user input strictly as template data rather than template source, and use a sandboxed or logic-less template engine.',
  },
  cmdi: {
    impact: 'Untrusted input injects shell metacharacters into server-side operating system commands, enabling arbitrary command execution.',
    remediation: 'Execute commands with explicit argv arrays without invoking a shell, and strictly allowlist dynamic arguments.',
  },
  business_logic: {
    impact: 'Application workflow or state-machine invariants can be bypassed or replayed out of sequence.',
    remediation: 'Enforce state-transition and business-rule invariants atomically server-side before committing state changes.',
  },
  price_tampering: {
    impact: 'Client-supplied pricing or amount parameters override server-side authoritative totals during checkout or payment processing.',
    remediation: 'Compute prices, discounts, and totals strictly server-side from authoritative catalog records and ignore client-supplied amounts.',
  },
  race_double_spend: {
    impact: 'Concurrent requests race a non-atomic balance or quota check, allowing double-spend or duplicate state transitions.',
    remediation: 'Serialize balance and quota transitions using database transactions, row locks, unique constraints, or idempotency keys.',
  },
  jwt: {
    impact: 'Forged or unsigned authentication tokens bypass signature verification and grant authenticated session access.',
    remediation: 'Verify token signatures against an explicit algorithm allowlist and server-managed keys; reject unsigned (alg=none) and unverified tokens.',
  },
  webhook: {
    impact: 'Unsigned or forged webhook deliveries are accepted and processed without valid cryptographic signature verification.',
    remediation: 'Verify webhook HMAC signatures in constant time against the raw request body using a server-managed secret before processing events.',
  },
}

const DEFAULT_FLOOR_COPY: FloorClassCopyTemplate = {
  impact: 'A deterministic verification differential confirmed exploitable server-side behavior on the target endpoint.',
  remediation: 'Validate untrusted input and enforce strict server-side security controls on the affected endpoint.',
}

const FLOOR_COPY_BY_CWE: Readonly<Record<number, string>> = {
  639: 'bola',
  284: 'bola',
  566: 'bola',
  285: 'bfla',
  269: 'bfla',
  862: 'bfla',
  863: 'bfla',
  89: 'sqli',
  564: 'sqli',
  943: 'sqli',
  611: 'xxe',
  918: 'ssrf',
  22: 'path_traversal',
  23: 'path_traversal',
  73: 'path_traversal',
  601: 'open_redirect',
  915: 'mass_assignment',
  352: 'csrf',
  200: 'info_disclosure',
  359: 'info_disclosure',
  522: 'info_disclosure',
  532: 'info_disclosure',
  79: 'xss',
  80: 'xss',
  83: 'xss',
  1336: 'ssti',
  94: 'ssti',
  78: 'cmdi',
  77: 'cmdi',
  840: 'business_logic',
  841: 'business_logic',
  1284: 'business_logic',
  472: 'price_tampering',
  362: 'race_double_spend',
  367: 'race_double_spend',
  347: 'jwt',
  287: 'jwt',
  345: 'webhook',
}

function floorCopyTemplateFor(cwe: string, category: string): FloorClassCopyTemplate {
  const cweMatch = /^CWE-(\d+)$/i.exec(cwe.trim())
  if (cweMatch) {
    const key = FLOOR_COPY_BY_CWE[Number(cweMatch[1])]
    if (key && FLOOR_COPY_BY_CLASS[key]) return FLOOR_COPY_BY_CLASS[key]!
  }
  const normCat = category.trim().toLowerCase().replace(/[\s-]+/g, '_')
  if (normCat === 'broken_access_control' || normCat === 'idor' || normCat === 'cross_tenant_read' || normCat === 'cross_tenant_write') {
    return FLOOR_COPY_BY_CLASS.bola!
  }
  if (normCat === 'sensitive_data_exposure' || normCat === 'information_disclosure' || normCat === 'secret_disclosure') {
    return FLOOR_COPY_BY_CLASS.info_disclosure!
  }
  if (normCat === 'xss_reflected' || normCat === 'xss_stored' || normCat === 'dom_xss') {
    return FLOOR_COPY_BY_CLASS.xss!
  }
  if (normCat === 'workflow_bypass' || normCat === 'workflow_skip') {
    return FLOOR_COPY_BY_CLASS.business_logic!
  }
  if (normCat === 'webhook_forgery') {
    return FLOOR_COPY_BY_CLASS.webhook!
  }
  if (normCat === 'url_redirect') {
    return FLOOR_COPY_BY_CLASS.open_redirect!
  }
  return FLOOR_COPY_BY_CLASS[normCat] ?? DEFAULT_FLOOR_COPY
}

export function baseFields(
  origin: string,
  title: string,
  cwe: string,
  category: string,
  severity: Severity,
  jq: string,
) {
  const copy = floorCopyTemplateFor(cwe, category)
  return {
    version: 1 as const,
    origin,
    title: title.slice(0, 200),
    category,
    cwe,
    severity,
    severityRationale: 'Deterministic differential evidence was reproduced by the Zero-LLM verifier.',
    impact: copy.impact,
    remediation: copy.remediation,
    recheckInstructions: 'Replay the control and probe requests and compare the responses.',
    assertionsJq: jq,
  }
}

function stepOf(
  origin: string,
  id: string,
  role: 'setup' | 'control' | 'probe' | 'cleanup',
  description: string,
  parts: RequestParts,
  persona?: string | null,
  extra: Record<string, unknown> = {},
  expectedStatus?: number[],
) {
  return {
    id,
    role,
    description,
    ...(expectedStatus ? { expectedStatus } : {}),
    request: {
      origin,
      method: parts.method,
      pathAndQuery: parts.pathAndQuery,
      ...(parts.headers ? { headers: parts.headers } : {}),
      ...(parts.jsonBody !== undefined ? { jsonBody: parts.jsonBody } : {}),
      ...(parts.textBody !== undefined ? { textBody: parts.textBody } : {}),
      ...(persona ? { persona } : {}),
      followRedirects: false,
      ...extra,
    },
  }
}

function appendQuery(pathAndQuery: string, name: string, rawValue: string, encodeValue = true): string {
  const sep = pathAndQuery.includes('?') ? '&' : '?'
  const encodedValue = encodeValue && !rawValue.includes('{{') ? encodeURIComponent(rawValue) : rawValue
  return `${pathAndQuery}${sep}${encodeURIComponent(name)}=${encodedValue}`
}

/** Build one request for the hypothesis with `value` placed in its parameter. */
export function requestParts(hyp: EngineHypothesis, value: string): RequestParts | null {
  const param = hyp.param
  const location = hyp.location ?? param?.location
  if (!param || !location) return null
  const path = hyp.pathAndQuery
  const siblings = hyp.jsonBody && location !== 'json' ? { ...hyp.jsonBody } : (hyp.jsonBody ?? {})
  switch (location) {
    case 'query':
      return { method: 'GET', pathAndQuery: appendQuery(path, param.name, value) }
    case 'path':
      return { method: hyp.method === 'GET' ? 'GET' : hyp.method, pathAndQuery: path.replaceAll('{{val}}', encodeURIComponent(value)) }
    case 'header':
      return { method: hyp.method, pathAndQuery: path, headers: { [param.name]: value } }
    case 'json':
      return {
        method: hyp.method === 'GET' ? 'POST' : hyp.method,
        pathAndQuery: path,
        jsonBody: { ...siblings, [param.name]: value },
      }
    case 'form': {
      const all = { ...(hyp.formBody ?? {}), ...siblings, [param.name]: value }
      return {
        method: hyp.method === 'GET' ? 'POST' : hyp.method,
        pathAndQuery: path,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    case 'xml': {
      const template = hyp.xmlTemplate ?? `<request><${param.name}>{{val}}</${param.name}></request>`
      return {
        method: 'POST',
        pathAndQuery: path,
        headers: { 'Content-Type': 'application/xml' },
        textBody: template.replaceAll('{{val}}', value),
      }
    }
    case 'graphql_var': {
      if (!hyp.graphqlQuery) return null
      return {
        method: 'POST',
        pathAndQuery: path,
        jsonBody: { query: hyp.graphqlQuery, variables: { ...siblings, [param.name]: value } },
      }
    }
    default:
      return null
  }
}

// ---------------------------------------------------------------------------------------------
// Authorization matrix -> http_chain
// ---------------------------------------------------------------------------------------------

const NEGATIVE_CONTROL_STATUS = [400, 401, 403, 404, 405, 409, 410, 422]
/** A readback of a mutation's nonexistent identifier must be absent (never served). */
const BOGUS_READBACK_ABSENT_STATUS = [404, 410]

/**
 * Identity-scoped object read. A cross-actor read of the *same addressed object* is proven by the
 * victim object's own identifier appearing in the probe body: the response may echo unrelated
 * per-actor fields (`actor`, `viewer`, request ids), so a byte/key-identical body comparison
 * (`matchesOwnerJq`) rejects every real response whose body names the caller. This binds the proof
 * to the object identity instead, and stays a content assertion (never a status assertion).
 */
function objectIdentityJq(stepId: string, id: string): string {
  return `(.steps.${stepId}.body | contains(${jqStr(id)}))`
}

/** Same-object read where the served body is genuinely identical (byte or key/value equality). */
function matchesOwnerJq(): string {
  return `((.steps.p1.body == .steps.c1.body) or (.steps.c1.json as $c | .steps.p1.json as $p | ` +
    `(($c | type) == "object") and (([$c | keys[]] | length) > 0) and ` +
    `(([($c | to_entries[]) | select($p[.key] == .value)] | length) == ([$c | keys[]] | length))) or ` +
    `((.steps.c1.json as $c | .steps.p1.json as $p | ($c | type) == "array" and ($p | type) == "array") and ` +
    `((.steps.c1.body | length) > 3) and (.steps.p1.body == .steps.c1.body)))`
}

/**
 * Negative control for an object-level mutation. A route may acknowledge a mutation of an
 * id it does not have ("updated" response for an unknown record), so a 2xx is only admissible when
 * a separate readback of that same bogus identifier is absent — the mutation demonstrably addressed
 * nothing. A 4xx stays the primary shape (unchanged strength).
 */
function mutatingNegativeControlJq(bogusReadback: boolean): string {
  const denied = `((.steps.c2.status >= 400) and (.steps.c2.status < 500))`
  if (!bogusReadback) return denied
  return `(${denied} or ((${is2xx('c2')}) and ((.steps.c3.status == 404) or (.steps.c3.status == 410))))`
}

function negativeControlJq(mutating: boolean, bogusReadback = false): string {
  if (mutating) return mutatingNegativeControlJq(bogusReadback)
  return `(((.steps.c2.status >= 400) and (.steps.c2.status < 500)) or ((${is2xx('c2')}) and (.steps.c2.body != .steps.c1.body) and ((.steps.c2.body | length) > 2)))`
}

interface AuthzReadback {
  /** GET path (with the resource id already filled in) used before and after the mutation. */
  path: string
}

function synthAuthz(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const sensitiveRead = hyp.method === 'GET' && SENSITIVE_READ_ROUTE_RE.test(hyp.endpoint.pathTemplate)
  // A read of a credential/audit surface is a disclosure claim, not a body-equality claim. Delegate
  // it to the credential-proof shape (masked control or anonymous denial plus a pre-redaction
  // fingerprint / credential-shaped value); a listing read with no such evidence is not reported.
  if (sensitiveRead) {
    const sensitive = synthSensitiveRead(hyp, result)
    if (sensitive.length > 0) return sensitive
    if (hyp.method === 'GET') return []
  }
  const owner = hyp.ownerPersona
  const other = hyp.otherPersona
  if (!owner || !other) return []
  const cwe = 'CWE-639'
  const title = 'Cross-actor object or function access'
  let vulnClass = hyp.functionLevel ? 'bfla' : 'bola'
  const matrix = Array.isArray(result.details.matrix) ? result.details.matrix as AuthzMatrixRow[] : null
  const hits = result.anomalies
    .filter(a => a.type === 'unauthorized_access')
    .sort((a, b) => {
      const ga = String(a.method ?? 'GET') === 'GET' ? 0 : 1
      const gb = String(b.method ?? 'GET') === 'GET' ? 0 : 1
      if (ga !== gb) return ga - gb
      return Number(b.similarityToOwner ?? 0) - Number(a.similarityToOwner ?? 0)
    })
  if (hits.length === 0) return []
  const out: SynthesizedEngineSpec[] = []
  const seen = new Set<string>()

  for (const hit of hits) {
    const matrixId = String(hit.resourceId ?? '')
    const method = String(hit.method ?? 'GET')
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue
    const mutating = method !== 'GET'
    const functionLevel = hit.functionLevel === true || hyp.functionLevel === true
    const privilegedRoute = PRIVILEGED_ACTION_RE.test(hyp.endpoint.pathTemplate)
    // A privileged function route that declares the role it requires is a vertical (BFLA) claim even
    // when the route also addresses an object identifier; the replay proves a role escalation, so
    // the class follows the invariant rather than the URL shape.
    const verticalFunctionWrite = mutating && privilegedRoute && Boolean(hyp.authzRequiredRole)
    // Report the concrete cross-actor class (object read bolted to a real write impact) rather than
    // a generic category, so the finding's class matches the invariant the replay actually proved.
    const category = mutating
      ? (functionLevel || verticalFunctionWrite ? 'bfla' : 'cross_tenant_write')
      : (functionLevel ? 'bfla' : 'idor')
    if (verticalFunctionWrite) vulnClass = 'bfla'
    // A destructive matrix may have consumed the id it reported; the engine reserves one live
    // victim for privileged deletes so the replay can observe a real removal.
    const useReservedVictim = Boolean(hyp.reservedVictimId) && method === 'DELETE' && privilegedRoute && !functionLevel
    const id = useReservedVictim ? hyp.reservedVictimId! : matrixId
    const key = `${method}|${functionLevel ? 'fn' : id}`
    if (seen.has(key)) continue
    seen.add(key)
    if (!functionLevel && !isSafeResourceId(id)) continue

    if (!isAuthzMatrixHitAdmissible(matrix, hit, { mutating, functionLevel })) continue

    const observedBody = hyp.functionState?.body
      ?? (hit.bodyTemplate !== undefined && hit.bodyTemplate !== null
        ? hit.bodyTemplate
        : (hyp.jsonBody ?? {}))
    const escalatedBody = mutating && privilegedRoute ? escalatePrivilegeBody(observedBody, hyp.authzRequiredRole) : null
    const bodyTemplate = escalatedBody ?? observedBody
    const realPath = functionLevel ? hyp.pathAndQuery : fillResourceId(hyp.pathAndQuery, id)
    // A staging replay is still a mutation: every write step must carry the run-scoped tenant tag,
    // otherwise the scope contract refuses it and a real finding looks unverifiable.
    const writeHeaders = mutating ? hyp.headers : undefined
    const parts: RequestParts = {
      method: method as RequestParts['method'],
      pathAndQuery: realPath,
      ...(mutating ? { jsonBody: bodyTemplate } : {}),
      ...(writeHeaders ? { headers: writeHeaders } : {}),
    }
    const stepExtra = mutating && hyp.csrfBind ? { csrfBind: true } : {}
    const probePersona = hit.actor === 'anonymous' ? null : other
    // A self-service function-state proof reads the *probe actor's own* identity, so a control write
    // by the privileged actor would mutate the wrong record; the mutation itself is the only write.
    const selfState = Boolean(hyp.functionState?.bindings?.length)
    // The probe matrix already applied the body it reports. For a privileged entitlement grant the
    // control arm must first restore a non-privileged value of the *same* field, otherwise the replay
    // re-sends the already-persisted value and hides a real, non-idempotent escalation.
    const privilegeBaseline = mutating && !functionLevel && !selfState && method !== 'DELETE'
      ? privilegeBaselineFor(bodyTemplate, hyp.authzRequiredRole)
      : null
    const baselineWrite = privilegeBaseline ?? (mutating && !functionLevel && !selfState && method !== 'DELETE'
      ? pickBaselineWrite(bodyTemplate)
      : null)
    const withValue = (value: string | number | boolean): unknown => (
      bodyTemplate && typeof bodyTemplate === 'object' && !Array.isArray(bodyTemplate)
        ? { ...(bodyTemplate as Record<string, unknown>), [baselineWrite!.field]: value }
        : bodyTemplate
    )
    // A mutating proof must show the protected state changed in a *separate readback*, never the
    // mutation's own acknowledgement. Roles: the privileged actor reads before and after, the lower
    // role mutates in between; a function-level proof also lets the lower role re-read the function
    // state so the change is visible to the actor that caused it.
    const readbackTemplate = mutating ? resolveAuthzReadbackTemplate(hyp, functionLevel) : null
    const readback = readbackTemplate ? { path: fillResourceId(readbackTemplate.template, id) } : null
    // The bogus-id control is only observable through the same read route; a function-level proof
    // has no object read to bind it to, and a reserved delete victim owns its own control.
    const bogusReadbackTemplate = readbackTemplate && !functionLevel && !useReservedVictim && !selfState
      ? readbackTemplate
      : null
    const readbackPersona = readbackTemplate?.persona ?? hyp.readbackPersona ?? owner
    const neg = functionLevel || useReservedVictim || selfState
      ? null
      : negativeControlJq(mutating, Boolean(bogusReadbackTemplate))
    // For a privileged delete the bogus-id control may legitimately be a 200 no-op. Selectivity is
    // then proven by re-reading the reserved victim: it must still exist after the bogus delete.
    const deleteReservationJq = useReservedVictim
      ? `((( .steps.c2.status >= 400) and (.steps.c2.status < 500)) or ((${is2xx('c3')}) and (.steps.c3.body == .steps.c1.body)))`
      : null
    const steps: Array<Record<string, unknown>> = []
    const negativeId = matrix === null ? `kovo-none-${randomBytes(5).toString('hex')}` : bogusIdFor(id)
    const buildMutatingChain = (read: AuthzReadback) => {
      // The baseline write precedes the negative controls: `findPersistence` treats the first
      // successful control mutation as the comparison arm, and a 404 readback of a bogus object is
      // not a state baseline for it. Keeping the write first leaves the attribution arm with no
      // pre-read (nothing to compare), which is the honest reading.
      if (baselineWrite) {
        steps.push(stepOf(
          hyp.endpoint.origin, 'w1', 'control',
          `Authorized actor establishes the baseline "${baselineWrite.field}" value`,
          { method: method as RequestParts['method'], pathAndQuery: realPath, jsonBody: withValue(baselineWrite.baselineValue), ...(writeHeaders ? { headers: writeHeaders } : {}) },
          owner, stepExtra, [200, 201, 204],
        ))
      }
      if (!functionLevel) {
        steps.push(stepOf(
          hyp.endpoint.origin, 'c2', 'control',
          `Authorized actor addresses a nonexistent identifier (${negativeId})`,
          {
            method: method as RequestParts['method'],
            pathAndQuery: fillResourceId(hyp.pathAndQuery, negativeId),
            ...(mutating ? { jsonBody: bodyTemplate } : {}),
            ...(writeHeaders ? { headers: writeHeaders } : {}),
          },
          owner,
          stepExtra,
          useReservedVictim ? undefined : NEGATIVE_CONTROL_STATUS,
        ))
        // A route that acknowledges an unknown identifier still has to prove selectivity: the same
        // bogus identifier must be *absent* when read back (no object was mutated or created).
        if (bogusReadbackTemplate) {
          steps.push(stepOf(
            hyp.endpoint.origin, 'c3', 'control',
            `Authorized actor reads the same nonexistent identifier back (${negativeId})`,
            { method: 'GET', pathAndQuery: fillResourceId(bogusReadbackTemplate.template, negativeId) },
            readbackPersona,
            {},
            BOGUS_READBACK_ABSENT_STATUS,
          ))
        }
      }
      // Self-service function state: re-establish the probe actor's own identity baseline before the
      // pre-read, so a state change caused by the *probe matrix* earlier in the run cannot mask the
      // replay delta (and cannot make the replay look like a no-op).
      const resetBody = hyp.functionState?.reset?.length
        ? { ...(bodyTemplate as Record<string, unknown>), ...Object.fromEntries(hyp.functionState.reset.map(item => [item.field, item.value])) }
        : null
      if (resetBody && probePersona) {
        steps.push(stepOf(
          hyp.endpoint.origin, 'w0', 'control',
          'Authorized actor restores its own identity baseline',
          { method: method as RequestParts['method'], pathAndQuery: realPath, jsonBody: resetBody, ...(writeHeaders ? { headers: writeHeaders } : {}) },
          probePersona, stepExtra, [200, 201, 204],
        ))
      }
      steps.push(stepOf(
        hyp.endpoint.origin, 'c1', 'control',
        'Authorized actor reads the target state before the mutation',
        { method: 'GET', pathAndQuery: read.path }, readbackPersona,
      ))
      if (useReservedVictim) {
        steps.push(stepOf(
          hyp.endpoint.origin, 'c3', 'control',
          'Authorized actor confirms the reserved victim survived the bogus-id control',
          { method: 'GET', pathAndQuery: read.path }, readbackPersona,
        ))
      }
      steps.push(stepOf(hyp.endpoint.origin, 'p1', 'probe', `${probePersona ? 'Lower-privileged actor' : 'Unauthenticated caller'} performs the mutation`, parts, probePersona, stepExtra))
      steps.push(stepOf(
        hyp.endpoint.origin, 'p2', 'control',
        'Authorized actor re-reads the target state after the mutation',
        { method: 'GET', pathAndQuery: read.path }, readbackPersona, {},
        method === 'DELETE' ? [200, 204, 404, 410] : [200, 404],
      ))
      if (functionLevel && probePersona && readbackPersona !== probePersona) {
        steps.push(stepOf(
          hyp.endpoint.origin, 'p3', 'probe',
          'Lower-privileged actor observes the mutated function state',
          { method: 'GET', pathAndQuery: read.path }, probePersona, {}, [200, 403, 404],
        ))
      }
      // Identity-assumption routes persist the acting scope on the caller's own session, so the
      // proof would leave the instrument acting as the target tenant for every later read. Restore
      // the baseline after the observation; the assertion only reads c1/p2, so cleanup cannot
      // weaken it.
      if (resetBody && probePersona) {
        steps.push(stepOf(
          hyp.endpoint.origin, 'w3', 'control',
          'Authorized actor restores its own identity baseline after the proof',
          { method: method as RequestParts['method'], pathAndQuery: realPath, jsonBody: resetBody },
          probePersona, stepExtra, [200, 201, 204],
        ))
      }
      const jsonEquals = (stepId: string, field: string, value: unknown): string =>
        `((.steps.${stepId}.json | if type == "object" then .[${jqStr(field)}] else null end) == ${JSON.stringify(value)})`
      const jsonDiffers = (stepId: string, field: string, value: unknown): string =>
        `((.steps.${stepId}.json | if type == "object" then .[${jqStr(field)}] else null end) != ${JSON.stringify(value)})`
      // The actor's own identity read must show the bound field taking the value the mutation body
      // carried, and must not have shown it before. This is a field-bound state delta, not a
      // body-difference observation (a rotating nonce can never satisfy it).
      const stateChanged = selfState
        ? hyp.functionState!.bindings
          .map(binding => `((${jsonEquals('p2', binding.field, binding.value)}) and (${jsonDiffers('c1', binding.field, binding.value)}))`)
          .join(' or ')
        : null
      // Bind the post-read to the exact value this probe's mutation body carried. The baseline write
      // immediately before the pre-read guarantees it differs, so this proves a fresh
      // non-idempotent change and names the mutated field.
      const probeFieldValue = baselineWrite && bodyTemplate && typeof bodyTemplate === 'object' && !Array.isArray(bodyTemplate)
        ? (bodyTemplate as Record<string, unknown>)[baselineWrite.field]
        : undefined
      // Field-bound when the readback exposes the mutated field at the top level (the strong form,
      // which names the exact field). A collection/nested readback (e.g. a list of shipments) still
      // proves the same non-idempotent change by carrying the value this probe wrote in a body that
      // differs from the baseline; the value binding keeps a concurrent writer from being credited.
      const probeLiteral = JSON.stringify(probeFieldValue ?? null)
      const bodyBoundDelta = `((.steps.p2.body != .steps.c1.body) and (.steps.p2.body | contains(${probeLiteral})))`
      const fieldBoundDelta = baselineWrite && probeFieldValue !== undefined &&
        String(probeFieldValue) !== String(baselineWrite.baselineValue)
        ? `(((${jsonEquals('p2', baselineWrite.field, probeFieldValue)}) and (${jsonEquals('c1', baselineWrite.field, baselineWrite.baselineValue)})) or (${bodyBoundDelta}))`
        : null
      const persisted = method === 'DELETE'
        ? `(((.steps.p2.status >= 400) and (.steps.p2.status < 500)) or ((${is2xx('p2')}) and (.steps.p2.body != .steps.c1.body)))`
        : stateChanged
          ? `((${is2xx('p2')}) and (${stateChanged}))`
          : fieldBoundDelta
            ? `((${is2xx('p2')}) and (${fieldBoundDelta}))`
            : `((${is2xx('p2')}) and (.steps.p2.body != .steps.c1.body))`
      const extraControl = [
        baselineWrite ? is2xx('w1') : null,
        resetBody ? is2xx('w0') : null,
        deleteReservationJq,
      ].filter((expression): expression is string => Boolean(expression))
      return `{ controlPassed: ((${nonTrivial('c1', 2)})${extraControl.length ? ` and (${extraControl.join(') and (')})` : ''}${neg ? ` and (${neg})` : ''}), ` +
        `confirmed: ((${is2xx('p1')}) and (${persisted})${deleteReservationJq ? ` and (${deleteReservationJq})` : ''}${neg ? ` and (${neg})` : ''}), ` +
        `observed: ("probe status=" + (.steps.p1.status | tostring) + " after status=" + (.steps.p2.status | tostring)${neg ? ' + " bogus status=" + (.steps.c2.status | tostring)' : ''}), ` +
        'expected: "the mutation is denied and the protected state is unchanged" }'
    }
    if (readback) {
      const jq = buildMutatingChain(readback)
      out.push({
        kind: 'http_chain',
        vulnClass,
        endpoint: hyp.endpoint.pathTemplate,
        spec: {
          ...baseFields(hyp.endpoint.origin, title, cwe, category, 'high', jq),
          kind: 'http_chain',
          ...(mutating && hyp.authzRequiredRole ? { requiredRole: hyp.authzRequiredRole } : {}),
          // A role-exclusive mutation is an impact class of its own; the impact oracle still
          // requires a role differential AND a persisted state change on replay.
          ...(mutating && privilegedRoute && hyp.authzRequiredRole ? { expectedImpactEvents: ['privilege_escalation'] } : {}),
          // The post-delete 404 readback is persistence evidence, not a boundary denial. The access
          // boundary is the actor/role differential, which the impact gate still backs.
          ...(useReservedVictim ? { expectControlDenied: false } : {}),
          steps,
        },
      })
      continue
    }
    const ownerJq = nonTrivial('c1', 3)
    const probeJq = nonTrivial('p1', 3)
    // The non-owner arm is served the *same object*: the addressed identifier appears in the probe
    // body (an echo of unrelated per-actor fields is allowed), or the served payload is genuinely
    // identical. Publicness for this route was already vetoed from the matrix above.
    const sameObjectJq = functionLevel
      ? matchesOwnerJq()
      : `((${objectIdentityJq('p1', id)}) or (${matchesOwnerJq()}))`
    const jq = `{ controlPassed: ((${ownerJq})${neg ? ` and (${neg})` : ''}), ` +
      `confirmed: ((${probeJq})${neg ? ` and (${neg})` : ''} and (${sameObjectJq})), ` +
      `observed: ("probe status=" + (.steps.p1.status | tostring)${neg ? ' + " bogus status=" + (.steps.c2.status | tostring)' : ''}), ` +
      'expected: "non-owner denied" }'
    if (!functionLevel) {
      const negativeId = matrix === null ? `kovo-none-${randomBytes(5).toString('hex')}` : bogusIdFor(id)
      steps.push(stepOf(
        hyp.endpoint.origin, 'c2', 'control',
        `Authorized actor addresses a nonexistent identifier (${negativeId})`,
        {
          method: method as RequestParts['method'],
          pathAndQuery: fillResourceId(hyp.pathAndQuery, negativeId),
          ...(mutating ? { jsonBody: bodyTemplate } : {}),
        },
        owner, stepExtra, NEGATIVE_CONTROL_STATUS,
      ))
    }
    steps.push(stepOf(hyp.endpoint.origin, 'c1', 'control', 'Authorized actor performs the request', parts, owner, stepExtra))
    steps.push(stepOf(hyp.endpoint.origin, 'p1', 'probe', `${probePersona ? 'Lower-privileged actor' : 'Unauthenticated caller'} performs the same request`, parts, probePersona, stepExtra))
    out.push({
      kind: 'http_chain',
      vulnClass,
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, title, cwe, category, 'high', jq),
        kind: 'http_chain',
        steps,
      },
    })
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------------------------

function booleanStyle(style: string): { quoteStyle: 'single' | 'double' | 'numeric'; valueTemplate?: string } {
  switch (style) {
    case 'numeric': return { quoteStyle: 'numeric' }
    case 'double_quote': return { quoteStyle: 'double' }
    case 'single_quote': return { quoteStyle: 'single' }
    case 'or_branch': return { quoteStyle: 'single', valueTemplate: "{{baseline}}' OR {{sql_expr}}-- -" }
    case 'single_paren': return { quoteStyle: 'single', valueTemplate: "{{baseline}}') AND {{sql_expr}}-- -" }
    case 'single_double_paren': return { quoteStyle: 'single', valueTemplate: "{{baseline}}')) AND {{sql_expr}}-- -" }
    case 'like_breakout': return { quoteStyle: 'single', valueTemplate: "{{baseline}}%' AND {{sql_expr}}-- -" }
    case 'order_by': return { quoteStyle: 'single', valueTemplate: '{{baseline}} ORDER BY (CASE WHEN ({{sql_expr}}) THEN 1 ELSE 2 END)-- -' }
    default: return { quoteStyle: 'single' }
  }
}

const jqBoolean = '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }'

function synthSqlBoolean(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  if (!hyp.param || !hyp.location) return []
  const base = {
    ...baseFields(hyp.endpoint.origin, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high', jqBoolean),
    kind: 'sql_boolean_diff',
    targetOrigin: hyp.endpoint.origin,
    method: hyp.method,
    pathAndQuery: hyp.pathAndQuery,
    ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
    ...(hyp.location === 'json' || hyp.location === 'form' ? { jsonBody: (hyp.jsonBody ?? {}) } : {}),
    ...(hyp.location === 'xml' && hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate } : {}),
    ...(hyp.location === 'graphql_var' && hyp.graphqlQuery ? { graphqlQuery: hyp.graphqlQuery, jsonBody: { variables: (hyp.jsonBody ?? {}) } } : {}),
    paramName: hyp.param.name,
    paramLocation: hyp.location,
    baselineValue: hyp.baselineValue ?? '1',
  }
  const make = (styleName: string): SynthesizedEngineSpec => {
    const style = booleanStyle(styleName)
    return {
      kind: 'sql_boolean_diff',
      vulnClass: 'sqli',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...base,
        quoteStyle: style.quoteStyle,
        ...(style.valueTemplate ? { valueTemplate: style.valueTemplate } : {}),
      },
    }
  }
  const hit = result.anomalies.find(a => a.type === 'boolean_differential')
  if (hit) {
    const style = String(hit.style ?? 'single_quote')
    const out: SynthesizedEngineSpec[] = []
    const push = (candidate: SynthesizedEngineSpec) => {
      if (!out.some(existing => JSON.stringify(existing.spec) === JSON.stringify(candidate.spec))) out.push(candidate)
    }
    push(make(style))
    // A LIKE-wrapped search needs a baseline the true/false arms can actually separate. An empty or
    // very common term makes the `LIKE '%<term>'` prefix match the whole collection on its own, so
    // both arms look identical; a fresh non-matching term is tried first, then short discriminators.
    // This is a control-vs-variant choice, not a weaker assertion.
    const broadStyle = style === 'or_branch' || style === 'like_breakout'
    const broadBaselines = [`kovo-${randomBytes(4).toString('hex')}`, '1', 'zz', '', 'a', 'e']
    for (const baseline of (broadStyle ? broadBaselines : ['a', 'e', '1'])) {
      const candidate = make(style)
      candidate.spec.baselineValue = baseline
      push(candidate)
    }
    for (const fallback of ['single_quote', 'numeric', 'or_branch']) push(make(fallback))
    return out
  }
  if (!result.anomalies.some(a => a.type === 'db_error_fingerprint')) return []
  if (hyp.location === 'graphql_var') return []
  // A structural database error is real signal, but the boolean recipe (which treats every 5xx arm
  // as unstable) can never replay it. Render the canonical error-based chain instead: a benign
  // control arm and a quote-terminated probe arm that must return a 5xx carrying the *dialect
  // fingerprint* the probe observed. A bare 5xx is not admissible (the universal status-only ban
  // still owns that), so a signal without a known dialect yields no error proof.
  const errorChain = buildSqlErrorChain(hyp, result)
  const out: SynthesizedEngineSpec[] = errorChain ? [errorChain] : []
  out.push({
    kind: 'sql_boolean_diff',
    vulnClass: 'sqli',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...base,
      baselineValue: "x' OR 1=1-- -",
      quoteStyle: 'single',
      valueTemplate: "x' OR {{sql_expr}}-- -",
    },
  })
  for (const style of ['single_quote', 'numeric', 'double_quote', 'or_branch']) out.push(make(style))
  return out
}

/**
 * Engine/dialect error strings for the injected construct, lower-cased for a case-insensitive
 * `contains`. These are the *labels* the probe's own fingerprinting observed; the oracle re-tests
 * the recorded response against its own engine fingerprint table, so a body that merely mentions a
 * database name cannot pass both.
 */
const SQL_DIALECT_ERROR_TERMS: Record<string, readonly string[]> = {
  sqlite: ['sqlite_error', 'sqlite3.operationalerror', 'unrecognized token', 'sqlite/jdbcdriver'],
  postgresql: ['postgresql', 'psqlexception', 'org.postgresql', 'pg_query(', 'syntax error at or near', 'unterminated quoted string at or near'],
  mysql: ['you have an error in your sql syntax', 'mysqlsyntaxerrorexception', 'er_parse_error', 'sqlstate[42000]', 'mariadb', 'mysql server'],
  mssql: ['unclosed quotation mark after the character string', 'microsoft ole db provider for sql server', 'sqlserverexception', 'sqlclient.sqlexception', '[sql server]'],
  oracle: ['ora-', 'oracle error'],
}

/**
 * Gate an error-based SQL injection chain on a structural 5xx *and* the dialect fingerprint that
 * matches the construct the probe injected. Returns null when the signal has no known dialect, so
 * a bare 500 can never be rendered into a spec.
 */
export function buildSqlErrorChain(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec | null {
  if (!hyp.param || !hyp.location) return null
  const anomaly = result.anomalies.find(entry => entry.type === 'db_error_fingerprint')
  const dialect = typeof anomaly?.dialect === 'string' ? anomaly.dialect.toLowerCase() : ''
  const terms = SQL_DIALECT_ERROR_TERMS[dialect]
  if (!anomaly || !terms || terms.length === 0) return null
  const injected = (value: string) => injectUniversalParam({
    pathAndQuery: hyp.pathAndQuery,
    param: hyp.param!.name,
    paramLocation: hyp.location!,
    value,
    method: hyp.method === 'DELETE' ? 'POST' : hyp.method,
    ...(hyp.jsonBody ? { jsonBody: hyp.jsonBody } : {}),
    ...(hyp.formBody ? { formBody: hyp.formBody } : {}),
    ...(hyp.xmlTemplate ? { xmlTemplate: hyp.xmlTemplate } : {}),
    ...(hyp.graphqlQuery ? { graphqlQuery: hyp.graphqlQuery } : {}),
    ...(hyp.session ? { session: hyp.session } : {}),
  })
  const details = result.details as Record<string, unknown>
  // Use the probe's own grounded baseline (it may be empty for a LIKE/opaque sink); the same value
  // the probe sent is what makes the control arm and the quote arm differ by one construct only.
  const baseline = typeof details.baselineValue === 'string'
    ? details.baselineValue
    : (hyp.baselineValue ?? '1')
  const control = injected(baseline)
  const probe = injected(`${baseline}'`)
  const lowered = '(.steps.p1.body | ascii_downcase)'
  const fingerprintJq = `(${terms.map(term => `(${lowered} | contains(${jqStr(term)}))`).join(' or ')})`
  const stepRequest = (parts: ReturnType<typeof injected>, description: string, id: string, role: 'control' | 'probe') => ({
    id,
    role,
    description,
    request: {
      origin: hyp.endpoint.origin,
      method: parts.method,
      pathAndQuery: parts.pathAndQuery,
      ...(parts.body ? { textBody: parts.body } : {}),
      ...(parts.headers ? { headers: parts.headers } : {}),
      ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
      followRedirects: false,
    },
  })
  const assertionsJq = `{ controlPassed: ((${is2xx('c1')}) and ((.steps.c1.body | length) > 0)), ` +
    `confirmed: ((.steps.p1.status >= 500) and (.steps.p1.body != .steps.c1.body) and ${fingerprintJq}), ` +
    `observed: ("control status=" + (.steps.c1.status | tostring) + " probe status=" + (.steps.p1.status | tostring)), ` +
    `expected: "a ${dialect} engine error fingerprint on the injected parameter" }`
  return {
    kind: 'http_chain',
    vulnClass: 'sqli',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(
        hyp.endpoint.origin,
        `SQL structural error differential · ${hyp.method} ${hyp.endpoint.pathTemplate.slice(0, 80)} (${hyp.param.name})`,
        'CWE-89',
        'sqli',
        'high',
        assertionsJq,
      ),
      kind: 'http_chain',
      steps: [
        stepRequest(control, `Benign value for parameter "${hyp.param.name}"`, 'c1', 'control'),
        stepRequest(probe, `Quote-terminated value for parameter "${hyp.param.name}"`, 'p1', 'probe'),
      ],
    },
  }
}

// ---------------------------------------------------------------------------------------------
// XML external entity
// ---------------------------------------------------------------------------------------------

const xmlBenign = '<?xml version="1.0" encoding="UTF-8"?><kovo><ping>ok</ping></kovo>'
const xxeBodies: Record<string, string> = {
  general_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "{{canary_url}}">]><root>&gxxe;</root>',
  param_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % gxxep SYSTEM "{{canary_url}}"> %gxxep;]><root>ok</root>',
  svg_dtd: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY svgx SYSTEM "{{canary_url}}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&svgx;</text></svg>',
}
const canaryJq = (control: string) =>
  `{ controlPassed: (.steps.${control}.status < 500), confirmed: (.canary.triggered == true), observed: ("probeCallback=" + ((.canary.probeTriggered // false) | tostring)), expected: "no out-of-band callback" }`

/**
 * Durable-OOB correlation the floor canary probe recorded on its result (see
 * `trackFloorCanarySubscriptions`): subscription/canary ids and the callback stage. Absent for an
 * older caller or a relay that could not persist, in which case nothing is added.
 */
export function canaryOobEvidence(result: DifferentialResult): Record<string, unknown> | null {
  const stage = typeof result.details.canaryProbeStage === 'string' ? result.details.canaryProbeStage : null
  const subscriptionId = typeof result.details.oobSubscriptionId === 'string' ? result.details.oobSubscriptionId : null
  const canaryId = typeof result.details.oobCanaryId === 'string' ? result.details.oobCanaryId : null
  const promoted = result.details.promoted === true
  const subscriptions = Array.isArray(result.details.oob)
    ? (result.details.oob as Array<Record<string, unknown>>)
      .filter(item => item !== null && typeof item === 'object')
      .map(item => ({
        token: typeof item.token === 'string' ? item.token : null,
        canaryId: typeof item.canaryId === 'string' ? item.canaryId : null,
        subscriptionId: typeof item.subscriptionId === 'string' ? item.subscriptionId : null,
        stage: typeof item.stage === 'string' ? item.stage : null,
        promoted: item.promoted === true,
      }))
    : []
  if (!stage && !subscriptionId && subscriptions.length === 0) return null
  return {
    // Keys the ReplayVerifier already emits for its own two-stage canary wait (`canaryProbeStage`,
    // `canaryProbePromoted`, `canarySubscriptionId`) plus the durable ids this floor probe minted.
    ...(stage ? { canaryProbeStage: stage } : {}),
    canaryProbePromoted: promoted,
    ...(subscriptionId ? { oobSubscriptionId: subscriptionId, canarySubscriptionId: subscriptionId } : {}),
    ...(canaryId ? { oobCanaryId: canaryId } : {}),
    promoted,
    ...(subscriptions.length ? { subscriptions } : {}),
  }
}

/** Probe-step note that carries the OOB correlation into the persisted replay spec. */
export function canaryOobStepTag(result: DifferentialResult): string {
  const stage = typeof result.details.canaryProbeStage === 'string' ? result.details.canaryProbeStage : null
  const subscriptionId = typeof result.details.oobSubscriptionId === 'string' ? result.details.oobSubscriptionId : null
  const canaryId = typeof result.details.oobCanaryId === 'string' ? result.details.oobCanaryId : null
  if (!stage && !subscriptionId) return ''
  const parts: string[] = []
  if (stage) parts.push(`stage=${stage}`)
  if (result.details.promoted === true) parts.push('promoted')
  if (subscriptionId) parts.push(`sub=${subscriptionId}`)
  if (canaryId) parts.push(`canary=${canaryId}`)
  return ` [oob ${parts.join(' ')}]`
}

function synthXxe(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'xxe_canary_callback')
  if (!hit) return []
  const body = xxeBodies[String(hit.variant)] ?? xxeBodies.general_entity
  const headers = { 'Content-Type': 'application/xml' }
  const method = hyp.method === 'GET' ? 'POST' : hyp.method
  const evidence = canaryOobEvidence(result)
  return [{
    kind: 'http_chain',
    vulnClass: 'xxe',
    endpoint: hyp.endpoint.pathTemplate,
    ...(evidence ? { evidence } : {}),
    spec: {
      ...baseFields(hyp.endpoint.origin, 'XML external entity injection (out-of-band callback)', 'CWE-611', 'xxe', 'high', canaryJq('c1')),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign XML document', { method, pathAndQuery: hyp.pathAndQuery, headers, textBody: xmlBenign }, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', `XML document with external entity to Kovo Hunter canary${canaryOobStepTag(result)}`, { method, pathAndQuery: hyp.pathAndQuery, headers, textBody: body }, hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------------------------

function synthSsrf(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const direct = result.anomalies.find(a => a.type === 'canary_callback' && a.variant === 'http')
  if (!direct) return []
  const evidence = canaryOobEvidence(result)
  const tag = canaryOobStepTag(result)
  if (hyp.triggerPath) {
    const control = requestParts(hyp, 'http://kovo-control.invalid/')
    const probe = requestParts(hyp, '{{canary_url}}')
    if (!control || !probe) return []
    const trigger = hyp.triggerPath.replace('{{id}}', '{{resource_id}}')
    const steps = [
      stepOf(hyp.endpoint.origin, 'c1', 'control', 'Register a benign URL (no callback expected)', control, hyp.ownerPersona),
      {
        ...stepOf(hyp.endpoint.origin, 'p1', 'probe', `Register the canary URL through the write route${tag}`, probe, hyp.ownerPersona),
        extract: [{ varName: 'resource_id', from: 'json' as const, selector: 'id' }],
      },
      stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Trigger the stored URL fetch', { method: 'POST', pathAndQuery: trigger, jsonBody: {} }, hyp.ownerPersona),
    ]
    return [{
      kind: 'http_chain',
      vulnClass: 'ssrf',
      endpoint: hyp.endpoint.pathTemplate,
      ...(evidence ? { evidence } : {}),
      spec: {
        ...baseFields(hyp.endpoint.origin, 'Second-order server-side request forgery (stored URL fetched later)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
        kind: 'http_chain',
        steps,
      },
    }]
  }
  const control = requestParts(hyp, 'http://kovo-control.invalid/')
  const probe = requestParts(hyp, '{{canary_url}}')
  if (!control || !probe) return []
  return [{
    kind: 'http_chain',
    vulnClass: 'ssrf',
    endpoint: hyp.endpoint.pathTemplate,
    ...(evidence ? { evidence } : {}),
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Server-side request forgery (out-of-band callback)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign URL value (no callback expected)', control, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', `Kovo Hunter canary URL value${tag}`, probe, hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------------------------

function synthTraversal(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'path_traversal_escape')
  if (!hit || !hyp.param) return []
  const raw = String(hit.payload ?? '')
  if (!raw || raw.length > 200 || /[\r\n\0\\]/.test(raw)) return []
  const controlValue = `../kovo-none-${randomBytes(4).toString('hex')}.txt`
  const build = (value: string): RequestParts => {
    const parts = requestParts(hyp, value)
    if (parts) return parts
    return { method: hyp.method, pathAndQuery: hyp.pathAndQuery, jsonBody: { [hyp.param!.name]: value } }
  }
  const needle = typeof hit.contentNeedle === 'string' ? hit.contentNeedle.replace(/[\u0000-\u001f]/g, '').slice(0, 40) : ''
  const contentCheck = needle
    ? ` and (.steps.p1.body | contains(${jqStr(needle)}))`
    : ' and ((.steps.p1.body | length) > 0)'
  const jq = `{ controlPassed: ((.steps.c1.status < 200) or (.steps.c1.status >= 300)), ` +
    `confirmed: ((${is2xx('p1')})${contentCheck} and ((.steps.p1.body != .steps.c1.body) or (.steps.p1.status != .steps.c1.status))), ` +
    `observed: ("traversal status=" + (.steps.p1.status | tostring) + " bytes=" + (.steps.p1.body | length | tostring)), expected: "file names resolve inside the served root" }`
  return [{
    kind: 'http_chain',
    vulnClass: 'path_traversal',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Path traversal escapes the served root (jail-escape read)', 'CWE-22', 'path-traversal', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Nonexistent sibling traversal control', build(controlValue), hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Traversal payload that resolves outside the served root', build(raw), hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------------------------

function canaryHostOf(payload: string): string | null {
  // The probe may hand back an absolute, protocol-relative or backslash-prefixed payload.
  const match = /([A-Za-z0-9.-]*gxr[A-Za-z0-9._-]*\.invalid)/i.exec(payload)
  return match?.[1] ?? null
}

function synthRedirect(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'open_redirect_differential')
  if (!hit || !hyp.param) return []
  const payload = String(hit.payload ?? '')
  const host = canaryHostOf(payload)
  if (!host) return []
  const control = requestParts(hyp, `/kovo-return-${randomBytes(4).toString('hex')}`)
  const probe = requestParts(hyp, payload)
  if (!control || !probe) return []
  const jq = `{ controlPassed: (.steps.c1.status < 400), ` +
    `confirmed: ((.steps.p1.status >= 300 and .steps.p1.status < 400) and ((.steps.p1.headers.location // "") | contains(${jqStr(host)}))), ` +
    'observed: ("location=" + ((.steps.p1.headers.location // "") | tostring)), expected: "redirect target stays on the registered origin" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'open_redirect',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Unvalidated redirect target (off-origin navigation)', 'CWE-601', 'open-redirect', 'medium', jq),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign relative return target', control, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Off-origin canary return target', probe, hyp.ownerPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// GraphQL resolver authorization
// ---------------------------------------------------------------------------------------------

function synthGraphql(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const anomaly = result.anomalies.find(a =>
    a.type === 'graphql_cross_persona_access' || a.type === 'graphql_nested_bola' || a.type === 'graphql_bola_differential')
  if (!anomaly || !hyp.ownerPersona || !hyp.otherPersona) return []
  const field = typeof anomaly.field === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(anomaly.field) ? anomaly.field : null
  const nested = Array.isArray(anomaly.nestedPath)
    ? (anomaly.nestedPath as unknown[]).filter((x): x is string => typeof x === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(x))
    : []
  const recordedQueryRaw = typeof anomaly.query === 'string'
    ? anomaly.query
    : typeof anomaly.nestedQuery === 'string' ? anomaly.nestedQuery
      : typeof anomaly.operation === 'string' ? anomaly.operation : null
  const query = recordedQueryRaw && recordedQueryRaw.length <= 4000 &&
    /^\s*(?:[{(]|query\b|mutation\b|subscription\b|fragment\b)/.test(recordedQueryRaw) ? recordedQueryRaw : null
  if (!query) return []
  if (anomaly.sameRoot === false) return []
  const variables = anomaly.variables && typeof anomaly.variables === 'object' && !Array.isArray(anomaly.variables)
    ? anomaly.variables as Record<string, unknown> : {}
  const dataPath = field ? ['data', field, ...nested].map(p => `[${jqStr(p)}]`).join('') : '.data'
  const nestedLen = (id: string) => `((.steps.${id}.json${dataPath} // []) | length)`
  const errorsClean = (id: string) => `(((.steps.${id}.json.errors // []) | length) == 0)`
  const jq = `{ controlPassed: (${is2xx('c1')} and ${errorsClean('c1')} and (${nestedLen('c1')} >= 1)), ` +
    `confirmed: (${is2xx('p1')} and ${errorsClean('p1')} and (${nestedLen('p1')} >= 1) and (.steps.p1.json${dataPath} == .steps.c1.json${dataPath})), ` +
    `observed: ("nested records=" + (${nestedLen('p1')} | tostring)), expected: "nested owned data reaches only its owner" }`
  const step = (id: string, role: 'control' | 'probe', description: string, actor: string) =>
    stepOf(hyp.endpoint.origin, id, role, description, {
      method: 'POST',
      pathAndQuery: hyp.pathAndQuery,
      jsonBody: { query, ...(Object.keys(variables).length > 0 ? { variables } : {}) },
    }, actor)
  return [{
    kind: 'http_chain',
    vulnClass: 'graphql_bola',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'GraphQL resolver missing object authorization', 'CWE-639', 'broken-access-control', 'high', jq),
      kind: 'http_chain',
      steps: [
        step('c1', 'control', 'Owner queries the resolver', hyp.ownerPersona),
        step('p1', 'probe', 'Different actor queries the same resolver', hyp.otherPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Mass assignment (transition form)
// ---------------------------------------------------------------------------------------------

function massAssignmentValue(field: string, privileged: boolean, observed?: string | boolean | number): string | boolean | number | null {
  if (privileged && observed !== undefined && observed !== null) return observed
  if (/^(?:amount|total|price|cents|quantity|qty|count|balance|credit|limit)$/i.test(field)) {
    return privileged ? 987654321 : 0
  }
  if (/^(?:is|has|verified|admin|emailVerified|enabled|active|superuser|staff)/i.test(field)) return privileged
  if (privileged) {
    if (/role|admin|permission|privilege|scope/i.test(field)) return 'admin'
    if (/plan|tier/i.test(field)) return 'enterprise'
    if (/org|tenant|team|group|owner/i.test(field)) return '1'
    return 'kovo-privileged'
  }
  if (/role|permission|privilege|scope/i.test(field)) return 'user'
  if (/plan|tier/i.test(field)) return 'free'
  if (/org|tenant|team|group|owner/i.test(field)) return '0'
  return 'kovo-low'
}

function synthMassAssignment(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'mass_assignment')
  if (!hit || !hyp.ownerPersona) return []
  const hitField = String(hit.field ?? '')
  if (!SAFE_FIELD_NAME_RE.test(hitField)) return []
  // The probe reports the first field that persisted; a sibling privileged field (tenant_id vs
  // owner_id) may be the one with a clean read-back. Try the observed field first, then the
  // hypothesis's other candidate fields.
  const fields = [...new Set([hitField, ...(hyp.candidateFields ?? [])])]
    .filter(isSafeFieldName)
    .slice(0, 4)
  const method = (hyp.method === 'PUT' ? 'PUT' : hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const readPath = hyp.pathAndQuery.split('?')[0]
  const read: RequestParts = { method: 'GET', pathAndQuery: readPath }
  const out: SynthesizedEngineSpec[] = []
  // Create-shaped mass assignment with a tenant/owner field: the overposted record is scoped to the
  // other tenant, so the owner's list cannot show it. Prove impact with a second-tenant read-back of
  // a unique marker that the caller's control write never placed in that tenant.
  const hasIdPath = /\/:|\{\{id\}\}|\{[^}]+\}/.test(hyp.pathAndQuery)
  if (!hasIdPath && method === 'POST' && hyp.otherPersona) {
    const scopedField = ['tenant_id', 'tenantId', 'org_id', 'orgId', 'team_id', 'teamId', 'owner_id', 'ownerId']
      .find(field => hyp.candidateValues?.[field] !== undefined)
    const expected = scopedField ? hyp.candidateValues?.[scopedField] : undefined
    if (scopedField && expected !== undefined) {
      const marker = randomBytes(5).toString('hex')
      const controlName = `kovo-ma-control-${marker}`
      const probeName = `kovo-ma-probe-${marker}`
      const nameField = (hyp.candidateFields ?? []).find(field => /^(?:name|title|label|subject)$/i.test(field)) ?? 'name'
      const body = (name: string, value: unknown) => ({ ...(hyp.jsonBody ?? {}), [nameField]: name, [scopedField]: value })
      const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('b1')}) and (((.steps.b1.body | contains(${jqStr(probeName)})) | not))), ` +
        `confirmed: ((${is2xx('p1')}) and ((${is2xx('p2')}) and (.steps.p2.body | contains(${jqStr(probeName)})) and (((.steps.p2.body | contains(${jqStr(controlName)})) | not)))), ` +
        'observed: "cross-tenant created record visible to the other tenant", expected: "tenant-scoping fields must not be client-writable" }'
      out.push({
        kind: 'http_chain',
        vulnClass: 'mass_assignment',
        endpoint: hyp.endpoint.pathTemplate,
        spec: {
          ...baseFields(hyp.endpoint.origin, `Mass assignment of "${scopedField}" on create`, 'CWE-915', 'mass-assignment', 'high', jq),
          kind: 'http_chain',
          expectedImpactEvents: ['mass_assignment'],
          steps: [
            stepOf(hyp.endpoint.origin, 'c1', 'control', 'Create a record in the caller tenant', { method: 'POST', pathAndQuery: hyp.pathAndQuery, jsonBody: body(controlName, massAssignmentValue(scopedField, false)) }, hyp.ownerPersona),
            // A create has no pre-mutation object to read, but the persistence oracle compares a
            // read before the probe with the read after it. Baseline the other tenant's collection
            // first, so the probe-created row is a real delta rather than a first observation.
            stepOf(hyp.endpoint.origin, 'b1', 'control', 'Baseline read of the other tenant collection', read, hyp.otherPersona),
            stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Create the same record with the other tenant id', { method: 'POST', pathAndQuery: hyp.pathAndQuery, jsonBody: body(probeName, expected) }, hyp.ownerPersona),
            stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Read the collection as the other tenant', { method: 'GET', pathAndQuery: readPath }, hyp.otherPersona),
          ],
        },
      })
    }
  }
  for (const field of fields) {
    const lowValue = massAssignmentValue(field, false)
    const expected = massAssignmentValue(field, true, hyp.candidateValues?.[field])
    if (lowValue === null || expected === null || lowValue === expected) continue
    const write = (value: string | boolean | number): RequestParts => ({ method, pathAndQuery: hyp.pathAndQuery, jsonBody: { ...(hyp.jsonBody ?? {}), [field]: value } })
    const expectedLit = typeof expected === 'boolean' || typeof expected === 'number' ? String(expected) : jqStr(expected)
    const lowLit = typeof lowValue === 'boolean' || typeof lowValue === 'number' ? String(lowValue) : jqStr(lowValue)
    const jq = `{ controlPassed: (${is2xx('c1')} and ((.steps.c1.body | contains(${lowLit})))), ` +
      `confirmed: ((${is2xx('p2')}) and (.steps.p2.body | contains(${expectedLit})) and (((.steps.c1.body | contains(${expectedLit})) | not))), ` +
      `observed: (("${field} privileged value persisted")), expected: "privileged field must not be client-writable" }`
    out.push({
      kind: 'http_chain',
      vulnClass: 'mass_assignment',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, `Mass assignment of privileged field "${field}"`, 'CWE-915', 'mass-assignment', 'high', jq),
        kind: 'http_chain',
        // The hypothesis class is the endpoint's declared overpost impact: a persisted privileged
        // column must not be dismissed because the leaf name is not in the generic protected list.
        expectedImpactEvents: ['mass_assignment'],
        steps: [
          stepOf(hyp.endpoint.origin, 'w1', 'control', `Baseline write of a low-privilege "${field}" value`, write(lowValue), hyp.ownerPersona),
          stepOf(hyp.endpoint.origin, 'c1', 'control', 'Read the record to confirm the baseline value', read, hyp.ownerPersona),
          stepOf(hyp.endpoint.origin, 'p1', 'probe', `Overpost the privileged "${field}" field`, write(expected), hyp.ownerPersona),
          stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Re-read the record to observe persistence', read, hyp.ownerPersona),
        ],
      },
    })
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// CSRF: state change accepted without the anti-CSRF token
// ---------------------------------------------------------------------------------------------

function synthCsrf(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'csrf_state_change')
  if (!hit) return []
  const readPath = String(hit.readPath ?? hyp.readPath ?? '')
  const bodyField = String(hit.bodyField ?? hyp.bodyField ?? '')
  const stateField = String(hit.stateField ?? hyp.stateField ?? bodyField)
  if (!readPath.startsWith('/') || !SAFE_FIELD_NAME_RE.test(bodyField) || !SAFE_FIELD_NAME_RE.test(stateField)) return []
  const controlValue = hit.controlValue
  const expectedValue = hit.expectedValue
  if (controlValue === undefined || expectedValue === undefined || controlValue === expectedValue) return []
  const method = (hyp.method === 'PUT' || hyp.method === 'PATCH' ? hyp.method : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const stateLit = (value: unknown) => typeof value === 'boolean' || typeof value === 'number' ? String(value) : jqStr(String(value))
  const createTemplate = typeof hit.createReadTemplate === 'string' && hit.createReadTemplate.startsWith('/')
    ? hit.createReadTemplate
    : hit.create === true && typeof hyp.createReadTemplate === 'string' && hyp.createReadTemplate.startsWith('/')
      ? hyp.createReadTemplate
      : ''
  const sessionExtra = hyp.session ? { session: hyp.session } : {}
  if (createTemplate) {
    const readFor = (variable: string): RequestParts => ({
      method: 'GET',
      pathAndQuery: createTemplate.replace(/:([A-Za-z0-9_]+)/g, `{{${variable}}}`),
    })
    const aliases = /(?:amount|value|total|price|cents)/i.test(bodyField)
      ? ['amount', 'amount_cents', 'amountCents', 'value', 'cents', 'total', 'price', bodyField]
      : [bodyField]
    const body = (value: unknown, foreign: boolean): RequestParts => {
      const headers: Record<string, string> = foreign
        ? { Origin: 'https://untrusted.invalid', Referer: 'https://untrusted.invalid/' }
        : {}
      const payload: Record<string, unknown> = { ...(hyp.jsonBody ?? {}) }
      for (const alias of new Set(aliases)) payload[alias] = value
      if (hit.bodyEncoding === 'json') {
        return { method: 'POST', pathAndQuery: hyp.pathAndQuery, headers, jsonBody: payload }
      }
      return {
        method: 'POST',
        pathAndQuery: hyp.pathAndQuery,
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(payload).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('r1')}) and (.steps.r1.body | contains(${stateLit(controlValue)}))), ` +
      `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (.steps.p2.body | contains(${stateLit(expectedValue)}))), ` +
      'observed: "tokenless cross-origin create was persisted", expected: "state change must require the anti-CSRF token" }'
    return [{
      kind: 'http_chain',
      vulnClass: 'csrf',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, 'CSRF protection missing on a create request', 'CWE-352', 'csrf', 'high', jq),
        kind: 'http_chain',
        steps: [
          stepOf(hyp.endpoint.origin, 's2', 'setup', 'Load the state page so the jar binds its anti-CSRF token', { method: 'GET', pathAndQuery: '/' }, hyp.ownerPersona, sessionExtra),
          {
            ...stepOf(hyp.endpoint.origin, 'c1', 'control', 'Create with the anti-CSRF token bound', body(controlValue, false), hyp.ownerPersona, { ...sessionExtra, csrfBind: true }),
            extract: [{ varName: 'control_id', from: 'json' as const, selector: 'id' }],
          },
          stepOf(hyp.endpoint.origin, 'r1', 'control', 'Read the control-created object', readFor('control_id'), hyp.ownerPersona, sessionExtra),
          {
            ...stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Create without the anti-CSRF token (foreign Origin)', body(expectedValue, true), hyp.ownerPersona, sessionExtra),
            extract: [{ varName: 'probe_id', from: 'json' as const, selector: 'id' }],
          },
          stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Read the probe-created object', readFor('probe_id'), hyp.ownerPersona, sessionExtra),
        ],
      },
    }]
  }
  const read: RequestParts = { method: 'GET', pathAndQuery: readPath }
  const useForm = hit.bodyEncoding === 'form'
  const write = (value: unknown, foreign: boolean): RequestParts => {
    const headers: Record<string, string> = foreign
      ? { Origin: 'https://untrusted.invalid', Referer: 'https://untrusted.invalid/' }
      : {}
    const body = { ...(hyp.jsonBody ?? {}), [bodyField]: value }
    if (useForm) {
      return {
        method,
        pathAndQuery: hyp.pathAndQuery,
        headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
        textBody: Object.entries(body).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
      }
    }
    return { method, pathAndQuery: hyp.pathAndQuery, headers, jsonBody: body }
  }
  const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('r1')}) and (((.steps.r1.body | contains(${stateLit(controlValue)})) or (.steps.r1.json[${jqStr(stateField)}] == ${stateLit(controlValue)})))), ` +
    `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and ((.steps.p2.body | contains(${stateLit(expectedValue)})) or (.steps.p2.json[${jqStr(stateField)}] == ${stateLit(expectedValue)}))), ` +
    'observed: ("state=" + ((.steps.p2.json[' + jqStr(stateField) + '] // "collection") | tostring)), expected: "state change must require the anti-CSRF token" }'
  const steps: Array<Record<string, unknown>> = [
    stepOf(hyp.endpoint.origin, 's2', 'setup', 'Load the state page so the jar binds its anti-CSRF token', read, hyp.ownerPersona, sessionExtra),
    stepOf(hyp.endpoint.origin, 'c1', 'control', 'State change with the anti-CSRF token bound', write(controlValue, false), hyp.ownerPersona, { ...sessionExtra, csrfBind: true }),
    stepOf(hyp.endpoint.origin, 'r1', 'control', 'Read the restored baseline state', read, hyp.ownerPersona, sessionExtra),
    stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Same state change without the anti-CSRF token (foreign Origin)', write(expectedValue, true), hyp.ownerPersona, sessionExtra),
    stepOf(hyp.endpoint.origin, 'p2', 'probe', 'Read the mutated state', read, hyp.ownerPersona, sessionExtra),
  ]
  return [{
    kind: 'http_chain',
    vulnClass: 'csrf',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'CSRF protection missing on a state-changing request', 'CWE-352', 'csrf', 'high', jq),
      kind: 'http_chain',
      steps,
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Credential exposure on a read route
// ---------------------------------------------------------------------------------------------

/** Cross-actor read of a sensitive response (matrix `secret_disclosed` signal, redacted-safe). */
const GENERIC_CREDENTIAL_PATTERN = 'rb[s]_[A-Za-z0-9]+_[0-9a-f]{12}'

/**
 * Credential exposure on a read surface. Two evidence shapes are accepted, both content-bound:
 *  - a masked/compact control from the same actor (the probe view returns the raw secret, the
 *    compact view masks it) proven by a pre-redaction fingerprint;
 *  - an anonymous denial control (the route is auth-gated) plus a credential-shaped value or
 *    unmasked non-public field in the authenticated probe response. This form is deliberately
 *    text-tolerant: an audit log that embeds a secret reference in a free-text `detail` line has no
 *    owner-scoped JSON attribute, but the credential itself is still observable.
 */
function synthSensitiveRead(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const secretHit = result.anomalies.find(anomaly => anomaly.type === 'secret_disclosed')
  const unauthorizedHit = result.anomalies.find(anomaly =>
    anomaly.type === 'unauthorized_access' && String(anomaly.method ?? 'GET') === 'GET')
  const hit = secretHit ?? unauthorizedHit
  if (!hit || !hyp.ownerPersona) return []
  const path = typeof hit.path === 'string' && hit.path.startsWith('/') ? hit.path : hyp.pathAndQuery
  if (!path.startsWith('/')) return []
  const safePersona = (value: unknown): string | undefined =>
    isSafePersonaHandle(value) ? value : undefined
  const probePersona = safePersona(hit.persona) ?? safePersona(hyp.viewerPersona) ?? safePersona(hyp.otherPersona)
  if (!probePersona || probePersona === hyp.ownerPersona) return []
  const controlPath = typeof hit.controlPath === 'string' && hit.controlPath.startsWith('/') && hit.controlPath !== path
    ? hit.controlPath
    : null
  const maskedControl = controlPath !== null
  const controlPersona = maskedControl ? probePersona : null
  const knownControlStatus = typeof hit.controlStatus === 'number' ? hit.controlStatus : null
  const controlStatuses = knownControlStatus && knownControlStatus >= 400 && knownControlStatus < 500
    ? [knownControlStatus]
    : [401, 403]
  const field = isSafeFieldName(hit.field) ? hit.field : ''
  const pattern = typeof hit.secretPattern === 'string' && hit.secretPattern.length > 3 && hit.secretPattern.length < 200
    ? hit.secretPattern
    : GENERIC_CREDENTIAL_PATTERN
  const sensitiveSelector = field
    ? `select(.key == ${jqStr(field)})`
    : 'select(.key | test("secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|password|private[_-]?key"; "i"))'
  const rawSelector = `([.steps.%s.json | .. | objects | to_entries[] | ${sensitiveSelector} | select(.value | type == "string") | select((.value | length) > 8) | select((.value | test("[*…]|\\\\[redacted\\\\]"; "i")) | not)] | length)`
  const credentialEvidence = (id: string): string =>
    `((((.steps.${id}.secretMatches // []) | length) > 0) or ` +
    `((.steps.${id}.body // "") | test(${jqStr(pattern)})) or ` +
    `((${rawSelector.replaceAll('%s', id)}) >= 1))`
  const bodyPattern = (id: string): string => `((.steps.${id}.body // "") | test(${jqStr(pattern)}))`
  const fieldEvidence = (id: string): string => `((${rawSelector.replaceAll('%s', id)}) >= 1)`
  const fingerprintEvidence = (id: string): string => `(((.steps.${id}.secretMatches // []) | length) > 0)`
  // A compact control masks the value but the broker still fingerprints the redacted field, so the
  // masked and raw views share a field but not a pre-redaction fingerprint. Require a fingerprint
  // the control did not carry (or a credential-shaped/unmasked field the mask removed).
  const distinctFingerprint =
    `(.steps.p1.secretMatches[0].sha256Prefix as $fp | (([.steps.c1.secretMatches[]?.sha256Prefix] | index($fp)) == null))`
  const proof = maskedControl
    ? `((${bodyPattern('p1')}) or (${fieldEvidence('p1')}) or ((${fingerprintEvidence('p1')}) and ${distinctFingerprint}))`
    : credentialEvidence('p1')
  const control = maskedControl
    ? `(${is2xx('c1')})`
    : `((.steps.c1.status == ${controlStatuses.map(status => status.toString()).join(' or .steps.c1.status == ')}))`
  const jq = `{ controlPassed: ${control}, ` +
    `confirmed: ((${is2xx('p1')}) and ${proof}), ` +
    `observed: ("probe status=" + (.steps.p1.status | tostring) + " credential=" + ((${proof}) | tostring)), ` +
    'expected: "sensitive data is restricted to the authorized actor" }'
  const logSurface = /(?:audit|activity|logs?|events?)/i.test(hyp.endpoint.pathTemplate)
  return [{
    kind: 'http_chain',
    vulnClass: 'info_disclosure',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(
        hyp.endpoint.origin,
        logSurface ? 'Credential reference exposed in an audit/activity read' : 'Credential exposure on an unentitled read',
        logSurface ? 'CWE-532' : 'CWE-200',
        'sensitive-data-exposure',
        'high',
        jq,
      ),
      kind: 'http_chain',
      // The credential value shape the probe observed. The host re-tests it against the replayed
      // bodies (probe matches, no control matches); it is never accepted on the claim alone.
      ...(pattern ? { proofPatterns: [pattern] } : {}),
      steps: [
        stepOf(
          hyp.endpoint.origin, 'c1', 'control',
          maskedControl ? 'Lower-privileged actor reads the compact (masked) view' : 'Unauthenticated caller reads the sensitive route',
          { method: 'GET', pathAndQuery: controlPath ?? path },
          controlPersona,
          {},
          maskedControl ? [200] : controlStatuses,
        ),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Lower-privileged actor reads the sensitive response', { method: 'GET', pathAndQuery: path }, probePersona),
      ],
    },
  }]
}

function synthSecretDisclosure(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'secret_disclosed')
  if (!hit) return []
  const path = typeof hit.path === 'string' && hit.path.startsWith('/') ? hit.path : hyp.pathAndQuery
  // A same-endpoint compact toggle is not a trustworthy control (the app may ignore the query
  // name). A benign page proves the credential is not a site-wide constant while avoiding a 4xx
  // control that the replay verifier would treat as an unstable baseline.
  const controlPath = '/'
  const secretPersona = isSafePersonaHandle(hit.persona) ? hit.persona : hyp.ownerPersona
  const field = typeof hit.field === 'string' ? hit.field : ''
  const pattern = typeof hit.pattern === 'string' && hit.pattern.length > 3
    ? hit.pattern
    : typeof hit.secretPattern === 'string' && hit.secretPattern.length > 3 ? hit.secretPattern : ''
  if (!path.startsWith('/')) return []
  const sensitiveSelector = field && SAFE_FIELD_NAME_RE.test(field)
    ? `select(.key == ${jqStr(field)})`
    : 'select(.key | test("secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|password|private[_-]?key"; "i"))'
  const rawSelector = `([.steps.%s.json | .. | objects | to_entries[] | ${sensitiveSelector} | select(.value | type == "string") | select((.value | length) > 8) | select((.value | test("^[*…]|\\[redacted\\]"; "i")) | not)] | length)`
  const controlCheck = pattern
    ? `(((.steps.c1.body // "") | test(${jqStr(pattern)})) | not)`
    : `((${rawSelector.replaceAll('%s', 'c1')}) == 0)`
  const probeCheck = pattern
    ? `((.steps.p1.body // "") | test(${jqStr(pattern)}))`
    : `((${rawSelector.replaceAll('%s', 'p1')}) >= 1)`
  const jq = `{ controlPassed: ((.steps.c1.status < 500) and ${controlCheck}), ` +
    `confirmed: ((${is2xx('p1')}) and ${probeCheck}), ` +
    'observed: "unmasked credential returned to the client", expected: "secrets are never returned to clients" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'info_disclosure',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Credential exposure on a read response', 'CWE-200', 'information-disclosure', 'high', jq),
      kind: 'http_chain',
      ...(pattern ? { proofPatterns: [pattern] } : {}),
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Read the compact/preview (or a benign) control', { method: 'GET', pathAndQuery: controlPath }, hyp.ownerPersona),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Read the endpoint that returns the credential', { method: 'GET', pathAndQuery: path }, secretPersona),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Reflected XSS (browser chain)
// ---------------------------------------------------------------------------------------------

function synthReflectedXss(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'xss_context')
  if (!hit || !hyp.param || hyp.location !== 'query') return []
  const context = String(hit.context ?? 'html_body')
  const chars = Array.isArray(hit.unencodedChars) ? hit.unencodedChars.map(String) : []
  if (context !== 'html_body' || !chars.includes('<') || !chars.includes('"')) return []
  const controlPath = appendQuery(hyp.pathAndQuery, hyp.param.name, 'kovo')
  const payload = `<img src=x onerror="document.title='{{canary_token}}'">`
  const encodedPayload = payload.split('{{canary_token}}').map(encodeURIComponent).join('{{canary_token}}')
  const probePath = appendQuery(hyp.pathAndQuery, hyp.param.name, encodedPayload, false)
  const persona = hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}
  const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 400 and (.steps.c1.title != .canaryToken) and (([(.steps.c1.domSinkTraces // [])[] | select(.containsCanary)] | length) == 0)), ' +
    'confirmed: ((.steps.p1.status >= 200 and .steps.p1.status < 400) and ((.steps.p1.title == .canaryToken) or (([(.steps.p1.domSinkTraces // [])[] | select(.containsCanary)] | length) >= 1))), ' +
    'observed: ("probe title=" + (.steps.p1.title // "" | tostring)), expected: "reflected input is inert text" }'
  const steps = [
    { id: 'c1', role: 'control', description: 'Render the page with a benign parameter value', origin: hyp.endpoint.origin, ...persona, pathAndQuery: controlPath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 300 },
    { id: 'p1', role: 'probe', description: 'Render the page with an executable marker payload', origin: hyp.endpoint.origin, ...persona, pathAndQuery: probePath, action: 'navigate', checkKind: 'dom_xss', enableSinkHook: true, waitAfterLoadMs: 800 },
  ]
  // Cut 3d: the same steps carry the `browser_sink` envelope, so confirmation is the host-recorded
  // canary sink receipt rather than a declarative assertion over the legacy browser VM.
  const recipe = browserSinkEnvelopeFromSteps({ origin: hyp.endpoint.origin, vulnClass: 'dom_xss', steps })
  return [{
    kind: 'browser_chain',
    vulnClass: 'xss_reflected',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Reflected cross-site scripting (executed marker)', 'CWE-79', 'xss', 'high', jq),
      kind: 'browser_chain',
      steps,
      ...(recipe ? { recipe } : {}),
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Server-side template injection / command injection (verifier-minted nonce proofs)
// ---------------------------------------------------------------------------------------------

const sstiTemplates: Record<string, string> = {
  'jinja2/twig': '{{{{nonce_a}}*{{nonce_b}}}}',
  erb: '<%={{nonce_a}}*{{nonce_b}}%>',
  'freemarker/el': '${{{nonce_a}}*{{nonce_b}}}',
  'spel/pebble': '#{{{nonce_a}}*{{nonce_b}}}',
  thymeleaf: '[[${{{nonce_a}}*{{nonce_b}}}]]',
}

function synthSsti(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'expression_evaluated')
  if (!hit || !hyp.param) return []
  const template = sstiTemplates[String(hit.engine)]
  if (!template) return []
  const control = requestParts(hyp, 'kovo')
  const probe = requestParts(hyp, template)
  if (!control || !probe) return []
  const jq = '{ controlPassed: (.control.status < 500), confirmed: (.proof.mathVerified == true), ' +
    'observed: ("mathVerified=" + ((.proof.mathVerified // false) | tostring)), expected: "template input is not evaluated" }'
  return [{
    kind: 'rce_proof',
    vulnClass: 'ssti',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Server-side template injection (arithmetic evaluation)', 'CWE-1336', 'injection-input', 'high', jq),
      kind: 'rce_proof',
      proofMode: 'dynamic_math',
      requiresTier3Approval: true,
      controlStep: stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign template value', control, hyp.ownerPersona),
      probeStep: stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Verifier-minted arithmetic expression', probe, hyp.ownerPersona),
    },
  }]
}

/**
 * Split-echo payload builders, keyed by the probe variant that actually executed on this target.
 *
 * The two verifier-minted halves must be (a) separated in the outbound request and (b) joined by the
 * target's own evaluation, so plain reflection cannot satisfy the proof. For a command separator the
 * join is an empty command substitution, `$(echo '')`: the shell evaluates it to nothing, so the
 * halves become contiguous inside the `echo` argument, while the outbound request never contains the
 * assembled token and a sanitizer that only strips quoting cannot assemble it either. Substitution
 * output on its own line cannot be used to place the halves (several interpreters, including the
 * local shell model, emit it as a separate line), which is why the probe signal was real but the old
 * proof was dismissed. Substitution-shaped probe variants fall back to an empty quoted word inside
 * the substitution: a shell deletes it and joins the halves there.
 */
const splitEchoConnectors: Record<string, (base: string) => string> = {
  semicolon_echo: base => `${base}; echo {{nonce_part1}}$(echo ''){{nonce_part2}}`,
  subshell_echo: base => `${base}$(echo {{nonce_part1}}''{{nonce_part2}})`,
  quote_break: base => `${base}"; echo {{nonce_part1}}$(echo ''){{nonce_part2}}; "`,
  quote_break_id: base => `${base}"; id; echo {{nonce_part1}}$(echo ''){{nonce_part2}}; "`,
  pipe_echo: base => `${base} | echo {{nonce_part1}}$(echo ''){{nonce_part2}}`,
  backtick_echo: base => `${base}\`echo {{nonce_part1}}''{{nonce_part2}}\``,
}

function synthCommandInjection(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'command_executed')
  if (!hit || !hyp.param) return []
  const base = String(hit.baseValue ?? '127.0.0.1').slice(0, 64)
  const variant = String(hit.variant ?? 'semicolon_echo')
  const control = requestParts(hyp, base)
  if (!control) return []
  const jq = '{ controlPassed: (.control.status < 500), confirmed: (.proof.splitEchoVerified == true), ' +
    'observed: ("splitEcho=" + ((.proof.splitEchoVerified // false) | tostring)), expected: "shell metacharacters are inert data" }'
  const rceSpec = (template: string): SynthesizedEngineSpec | null => {
    const probe = requestParts(hyp, template)
    if (!probe) return null
    return {
      kind: 'rce_proof',
      vulnClass: 'command_injection',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, 'Command injection via shell metacharacters (nonce echo proof)', 'CWE-78', 'injection-input', 'critical', jq),
        kind: 'rce_proof',
        proofMode: 'split_echo',
        requiresTier3Approval: true,
        controlStep: stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign value', control, hyp.ownerPersona),
        probeStep: stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Verifier-minted split echo operands', probe, hyp.ownerPersona),
      },
    }
  }
  // Reuse the connector shape the probe already proved executes on *this* parameter and evidence.
  // One bounded proof shape; the observed-payload chain below is the only fallback.
  const out: SynthesizedEngineSpec[] = []
  const built = rceSpec((splitEchoConnectors[variant] ?? splitEchoConnectors.semicolon_echo!)(base))
  if (built) out.push(built)
  // Fallback for a target whose shell model joins the halves differently: replay the exact payload
  // the probe observed and assert the probe nonce is present while the sent payload is not
  // reflected (plain reflection cannot satisfy both halves). This is bounded to one extra candidate
  // and reuses recorded probe evidence — it never re-probes.
  const observedPayload = typeof hit.payload === 'string' ? hit.payload : ''
  const nonce = typeof hit.nonce === 'string' ? hit.nonce : ''
  if (observedPayload.length > 0 && observedPayload.length <= 200 && !/[\r\n\0]/.test(observedPayload) &&
      /^[A-Za-z0-9]{8,40}$/.test(nonce)) {
    const observedProbe = requestParts(hyp, observedPayload)
    if (observedProbe) {
      const chainJq = `{ controlPassed: ((.steps.c1.status < 500) and ((.steps.c1.body | contains(${jqStr(nonce)})) | not)), ` +
        `confirmed: ((${is2xx('p1')}) and (.steps.p1.body | contains(${jqStr(nonce)})) and ((.steps.p1.body | contains(${jqStr(observedPayload)})) | not)), ` +
        `observed: ("nonce=" + (${jqStr(nonce)}) + " reflected=" + ((.steps.p1.body | contains(${jqStr(observedPayload)})) | tostring)), expected: "shell metacharacters are inert data" }`
      out.push({
        kind: 'http_chain',
        vulnClass: 'command_injection',
        endpoint: hyp.endpoint.pathTemplate,
        spec: {
          ...baseFields(hyp.endpoint.origin, 'Command injection via shell metacharacters (observed nonce proof)', 'CWE-78', 'injection-input', 'critical', chainJq),
          kind: 'http_chain',
          steps: [
            stepOf(hyp.endpoint.origin, 'c1', 'control', 'Benign value', control, hyp.ownerPersona),
            stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Observed metacharacter payload', observedProbe, hyp.ownerPersona),
          ],
        },
      })
    }
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Workflow step-skip (repeat terminal transition)
// ---------------------------------------------------------------------------------------------

function synthWorkflowStepSkip(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'workflow_step_skip')
  if (!hit) return []
  const safeId = SAFE_RESOURCE_ID_RE
  const targetId = typeof hit.targetId === 'string' && safeId.test(hit.targetId) ? hit.targetId : null
  const template = typeof hit.targetTemplate === 'string' && hit.targetTemplate.startsWith('/')
    ? hit.targetTemplate
    : (hyp.workflowTargetTemplate ?? hyp.pathAndQuery)
  if (!template.startsWith('/')) return []
  const target = targetId ? template.replaceAll('{{id}}', encodeURIComponent(targetId)) : template
  if (!targetId && target.includes('{{id}}')) return []
  const method = (hyp.method === 'PUT' ? 'PUT' : hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const body = hit.targetBody && typeof hit.targetBody === 'object' && !Array.isArray(hit.targetBody)
    ? hit.targetBody as Record<string, unknown>
    : (hyp.jsonBody ?? {})
  const write = { method, pathAndQuery: target, jsonBody: body }
  const jq = `{ controlPassed: (${is2xx('c3')}), confirmed: (${is2xx('p1')}), ` +
    'observed: ("repeat transition status=" + (.steps.p1.status | tostring)), expected: "a terminal transition is rejected once the object left its prior state" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'workflow_bypass',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Workflow step skip: terminal transition accepted twice', 'CWE-840', 'business-logic', 'medium', jq),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c3', 'control', 'Perform the transition once (legal)', write, hyp.ownerPersona, {}, [200, 201, 204]),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Invoke the same terminal transition again', write, hyp.ownerPersona, {}, [200, 201, 204]),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Client-price tampering (multi-step checkout / commerce flow)
// ---------------------------------------------------------------------------------------------

function finiteNumber(value: unknown): number | null {
  const n = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(n) ? n : null
}

function safeFieldName(value: unknown): string | null {
  return isSafeIdentifier(value) ? value : null
}

/**
 * A terminal money route charged a caller-supplied price instead of the server-issued one. The
 * replay re-prices the *same server-created object* twice: once with the price the server itself
 * minted (control) and once with the tampered value (probe). Both steps address the vulnerable
 * endpoint, so the proof names exactly one target and cannot add unrelated routes to the report.
 */
function synthPriceTrust(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'price_tampering')
  if (!hit) return []
  const path = typeof hit.path === 'string' && hit.path.startsWith('/') ? hit.path.split('?')[0]! : hyp.pathAndQuery.split('?')[0]!
  const idField = safeFieldName(hit.idField)
  const resourceId = typeof hit.resourceId === 'string' && SAFE_RESOURCE_ID_RE.test(hit.resourceId) ? hit.resourceId : null
  const priceField = safeFieldName(hit.priceField)
  const serverPrice = finiteNumber(hit.serverPrice)
  const tamperedPrice = finiteNumber(hit.tamperedPrice)
  if (!idField || !resourceId || !priceField || serverPrice === null || tamperedPrice === null) return []
  if (!(tamperedPrice < serverPrice)) return []
  const chargedField = safeFieldName(hit.chargedField) ?? 'total'
  const bodyFor = (price: number): Record<string, unknown> => ({ [idField]: resourceId, [priceField]: price })
  const isCharged = (stepId: string, value: number): string =>
    `((.steps.${stepId}.json | if type == "object" then .[${jqStr(chargedField)}] else null end) == ${value})`
  const jq = `{ controlPassed: ((${is2xx('c1')}) and (${isCharged('c1', serverPrice)})), ` +
    `confirmed: ((${is2xx('c1')}) and (${isCharged('c1', serverPrice)}) and (${is2xx('p1')}) and (${isCharged('p1', tamperedPrice)}) and (${is2xx('p2')}) and (${isCharged('p2', tamperedPrice)}))` +
    `, observed: ("control " + ${jqStr(chargedField)} + "=" + (.steps.c1.json.${chargedField} | tostring) + " probe " + ${jqStr(chargedField)} + "=" + (.steps.p1.json.${chargedField} | tostring) + " repeat=" + (.steps.p2.status | tostring)), ` +
    'expected: "the server-issued price is charged regardless of the client value, and the terminal payment transition is not single-use" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'price_tampering',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Client-supplied price trusted by the payment step (control vs probe on the server-priced object)', 'CWE-472', 'price_tampering', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', `Pay the server-priced object (${chargedField}=${serverPrice})`, {
          method: 'POST', pathAndQuery: path, headers: hyp.headers, jsonBody: bodyFor(serverPrice),
        }, hyp.ownerPersona, {}, [200, 201]),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', `Pay the same object with a tampered ${priceField} (${tamperedPrice})`, {
          method: 'POST', pathAndQuery: path, headers: hyp.headers, jsonBody: bodyFor(tamperedPrice),
        }, hyp.ownerPersona, {}, [200, 201]),
        stepOf(hyp.endpoint.origin, 'p2', 'probe', `Replay the identical tampered payment on the already-paid object`, {
          method: 'POST', pathAndQuery: path, headers: hyp.headers, jsonBody: bodyFor(tamperedPrice),
        }, hyp.ownerPersona, {}, [200, 201]),
      ],
    },
  }]
}

// ---------------------------------------------------------------------------------------------
// Synchronized state-changing burst (TOCTOU / double-spend)
// ---------------------------------------------------------------------------------------------

/**
 * N same-packet requests are all acknowledged, but a separate pre/post read of the conserved value
 * shows a single debit. The replay rebuilds the over-count from scratch: a zero-value read of the
 * balance, the synchronized burst, then a second zero-value read. The assertion is arithmetic
 * (acknowledged transfers vs observed debit), never a status-only claim.
 */
function synthRaceBurst(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(a => a.type === 'race_double_spend')
  if (!hit) return []
  const origin = typeof hit.raceOrigin === 'string' && /^https?:\/\//.test(hit.raceOrigin) ? hit.raceOrigin : hyp.endpoint.origin
  const path = typeof hit.path === 'string' && hit.path.startsWith('/') ? hit.path.split('?')[0]! : hyp.pathAndQuery.split('?')[0]!
  const amountField = safeFieldName(hit.amountField)
  const balanceField = safeFieldName(hit.balanceField)
  const transferredField = safeFieldName(hit.transferredField)
  const amount = finiteNumber(hit.amount)
  const size = finiteNumber(hit.burstSize)
  if (!amountField || !balanceField || !transferredField || amount === null || amount <= 0) return []
  if (size === null || size < 2 || size > 10) return []
  const burstSize = Math.trunc(size)
  const key = typeof hit.idempotencyKey === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(hit.idempotencyKey)
    ? hit.idempotencyKey
    : null
  const bodyFor = (value: number): Record<string, unknown> => ({
    [amountField]: value,
    ...(key ? { idempotencyKey: key } : {}),
  })
  const readStep = (id: string, description: string) => ({
    ...stepOf(origin, id, 'setup', description, {
      method: 'POST', pathAndQuery: path, headers: hyp.headers, jsonBody: bodyFor(0),
    }, hyp.ownerPersona, {}, [200, 201]),
    extract: [{ varName: `${id}_balance`, from: 'json' as const, selector: balanceField }],
  })
  // race_burst evidence exposes ordered setup summaries under `.setup`, the burst under `.burst`
  // and the post-check under `.postCheck`; there is no `.steps` object for this kind.
  const preOk = `((.setup[0].status >= 200) and (.setup[0].status < 300))`
  const postOk = `((.postCheck.status >= 200) and (.postCheck.status < 300))`
  const transfersJq = `[.burst.results[] | select(.status == 200) | (.json.${transferredField} // 0)] | add`
  const acknowledgedJq = `([.burst.results[] | select(.status == 200)] | length)`
  const jq = `{ controlPassed: ((${preOk}) and (.setup[0].json.${balanceField} != null) and (${postOk}) and (.postCheck.json.${balanceField} != null)), ` +
    `confirmed: ((${preOk}) and (${postOk}) and (.setup[0].json.${balanceField} != null) and (.postCheck.json.${balanceField} != null) ` +
    `and ((.setup[0].json.${balanceField} - .postCheck.json.${balanceField}) == ${amount}) ` +
    `and (${acknowledgedJq} == ${burstSize}) and (${transfersJq} >= ${burstSize * amount})), ` +
    `observed: ("pre=" + (.setup[0].json.${balanceField} | tostring) + " post=" + (.postCheck.json.${balanceField} | tostring) + " acknowledged=" + (${acknowledgedJq} | tostring) + " transferred=" + (${transfersJq} | tostring)), ` +
    'expected: "a serial client can transfer the balance once; the synchronized burst acknowledges every request but debits the balance once" }'
  return [{
    kind: 'race_burst',
    vulnClass: 'race_double_spend',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(origin, 'Synchronized burst double-spend: multiple transfers acknowledged against one balance debit', 'CWE-362', 'race_double_spend', 'critical', jq),
      kind: 'race_burst',
      setupSteps: [readStep('pre', 'Read the conserved balance with a zero-value transfer')],
      burst: Array.from({ length: burstSize }, () => ({
        origin,
        method: 'POST' as const,
        pathAndQuery: path,
        ...(hyp.headers ? { headers: hyp.headers } : {}),
        ...(hyp.ownerPersona ? { persona: hyp.ownerPersona } : {}),
        jsonBody: bodyFor(amount),
        followRedirects: false,
      })),
      postCheckStep: stepOf(origin, 'post', 'cleanup', 'Re-read the conserved balance after the burst', {
        method: 'POST', pathAndQuery: path, headers: hyp.headers, jsonBody: bodyFor(0),
      }, hyp.ownerPersona, {}, [200, 201]),
      recipe: {
        recipeId: 'conserved_balance' as const,
        args: {
          origin,
          method: 'POST',
          pathAndQuery: path,
          vulnClass: 'race_double_spend',
          actor: { handle: hyp.ownerPersona ?? 'anonymous' },
          body: bodyFor(amount),
          burst: Math.min(8, burstSize),
          readback: {
            method: 'POST',
            pathAndQuery: path,
            jsonBody: bodyFor(0),
            ...(hyp.headers ? { headers: hyp.headers } : {}),
          },
          balanceField,
          unitDebit: amount,
          ...(hyp.headers ? { headers: hyp.headers } : {}),
        },
      },
    },
  }]
}

// ---------------------------------------------------------------------------------------------

const authMutationKinds = new Set(['alg_none', 'strip_signature', 'expired_replay', 'kid_inject', 'claim_swap', 'rs256_to_hs256_jwks'])

function synthAuthProtocol(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(anomaly =>
    anomaly.type === 'jwt_auth_mutation_bypass' || anomaly.type === 'jwt_authorization_forgery' ||
    anomaly.type === 'jwt_body_token_bypass')
  if (!hit || !hyp.ownerPersona) return []
  const mutation = typeof hit.mutation === 'string' && authMutationKinds.has(hit.mutation) ? hit.mutation : 'alg_none'
  const path = hyp.pathAndQuery.split('?')[0] || hyp.pathAndQuery
  // Forged-token transport: the probe minted the token itself from the caller's own claims and
  // presented it in a header/body field, so the replay mints the same pair deterministically. The
  // control keeps the declared HS256 header but carries a signature the target never issued; the
  // probe is the unsigned (`alg:none`) token with the identical payload.
  if (hit.type === 'jwt_authorization_forgery' || hit.type === 'jwt_body_token_bypass') {
    const rawPayload = hit.payload && typeof hit.payload === 'object' && !Array.isArray(hit.payload)
      ? hit.payload as Record<string, unknown>
      : (hyp.identityClaims ?? {})
    const payload: Record<string, string | number | boolean> = {}
    for (const [key, value] of Object.entries(rawPayload)) {
      if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(key)) continue
      if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
        payload[key] = typeof value === 'string' ? value.slice(0, 256) : value
      }
    }
    if (Object.keys(payload).length === 0) return []
    const declaredAlg = typeof hit.declaredAlg === 'string' && /^[A-Za-z0-9]{2,12}$/.test(hit.declaredAlg) ? hit.declaredAlg : 'HS256'
    const transport = hit.transport === 'body' ? 'body' : 'header'
    const field = typeof hit.tokenField === 'string' && SAFE_FIELD_NAME_RE.test(hit.tokenField) ? hit.tokenField : 'token'
    const body = hit.body && typeof hit.body === 'object' && !Array.isArray(hit.body) ? hit.body as Record<string, unknown> : {}
    // Header transport: the verifier mints both tokens from the same claims. The control keeps the
    // server's declared algorithm with an empty (never-issuable) signature; the probe is the unsigned
    // `alg:none` token. Nothing here carries a credential or a signing key.
    const headerMints = [
      { name: 'jwt_control', header: { alg: declaredAlg, typ: 'JWT' }, payload, signature: 'none' as const },
      { name: 'jwt_unsigned', header: { alg: 'none', typ: 'JWT' }, payload, signature: 'none' as const },
    ]
    const request = (token: string): RequestParts => transport === 'body'
      ? {
          method: hyp.method === 'GET' ? 'POST' : hyp.method,
          pathAndQuery: path,
          headers: { 'Content-Type': 'application/json' },
          jsonBody: { ...body, [field]: token },
        }
      : {
          method: hyp.method,
          pathAndQuery: path,
          headers: { Authorization: `Bearer ${token}` },
        }
    const controlRequest = request('{{jwt_control}}')
    const probeRequest = request('{{jwt_unsigned}}')
    // Acceptance is the authenticated read itself: a data-bearing JSON object on the unsigned
    // token, with the declared-algorithm/invalid-signature control denied. A bare status is never
    // the confirmation.
    const dataFieldCount = `([.steps.p1.json | to_entries[] | select((.key | test("^(?:ok|success|status|error|message|detail|reason|code)$"; "i")) | not)] | length)`
    const jq = `{ controlPassed: ((.steps.c1.status == 401) or (.steps.c1.status == 403) or (.steps.c1.status == 400)), ` +
      `confirmed: ((${is2xx('p1')}) and ((.steps.p1.json | type) == "object") and (${dataFieldCount} >= 1)), ` +
      'observed: (("control_status=" + (.steps.c1.status | tostring) + " accepted_status=" + (.steps.p1.status | tostring) + " fields=" + ((.steps.p1.json // {}) | keys | join(",")))), ' +
      'expected: "a token carrying the declared algorithm with an invalid signature is rejected; the unsigned alg=none token with the same claims is accepted and returns the authenticated data" }'
    return [{
      kind: 'auth_protocol_proof',
      vulnClass: 'jwt',
      endpoint: hyp.endpoint.pathTemplate,
      spec: {
        ...baseFields(hyp.endpoint.origin, 'JWT signature verification bypass (unsigned token accepted)', 'CWE-347', 'jwt', 'high', jq),
        kind: 'auth_protocol_proof',
        protocol: 'jwt',
        tokenMints: headerMints,
        steps: [
          stepOf(hyp.endpoint.origin, 'c1', 'control', `Same claims under ${declaredAlg} with an invalid signature are rejected`, controlRequest, null, {}, [400, 401, 403]),
          stepOf(hyp.endpoint.origin, 'p1', 'probe', `Unsigned alg=none token with the same claims is accepted`, probeRequest, null, {}, [200, 201, 204]),
        ],
      },
    }]
  }
  const jq = `{ controlPassed: ((.steps.c1.status >= 400) or (.steps.c1.status == 0)), ` +
    `confirmed: ${is2xx('p1')}, ` +
    'observed: (("probe_status=" + (.steps.p1.status | tostring))), ' +
    'expected: "random-signature token is rejected; mutated token is accepted" }'
  return [{
    kind: 'auth_protocol_proof',
    vulnClass: 'jwt',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'JWT signature verification bypass', 'CWE-347', 'jwt', 'high', jq),
      kind: 'auth_protocol_proof',
      protocol: 'jwt',
      steps: [
        stepOf(hyp.endpoint.origin, 'c1', 'control', 'Unauthenticated request is rejected', {
          method: hyp.method,
          pathAndQuery: path,
        }, null, {}, [400, 401, 403]),
        stepOf(hyp.endpoint.origin, 'p1', 'probe', `Mutated token (${mutation}) is accepted`, {
          method: hyp.method,
          pathAndQuery: path,
        }, hyp.ownerPersona, { authMutation: { kind: mutation } }, [200, 201, 204]),
      ],
    },
  }]
}

function synthWebhook(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(anomaly => anomaly.type === 'webhook_signature_bypass')
  if (!hit || !hyp.webhookBody || !hyp.ownerPersona) return []
  const body = hyp.webhookBody
  const header = typeof hit.headerName === 'string' && /^[A-Za-z0-9-]{1,64}$/.test(hit.headerName)
    ? hit.headerName
    : (hyp.webhookHeader ?? 'x-webhook-signature')
  const proof = typeof hit.proof === 'string' ? hit.proof : 'readback'
  const stateField = typeof hit.stateField === 'string' && SAFE_FIELD_NAME_RE.test(hit.stateField)
    ? hit.stateField : null
  const readPath = typeof hit.readPath === 'string' && hit.readPath.startsWith('/') && !hit.readPath.startsWith('//')
    ? hit.readPath : null
  const steps: unknown[] = [
    stepOf(hyp.endpoint.origin, 'c1', 'control', 'Tampered delivery signature', {
      method: 'POST',
      pathAndQuery: hyp.pathAndQuery,
      headers: { 'Content-Type': 'application/json', [header]: 'kovo_invalid_signature' },
      jsonBody: body,
    }, hyp.ownerPersona, {}, [200, 201, 202, 204, 400, 401, 403, 422]),
    stepOf(hyp.endpoint.origin, 'p1', 'probe', 'Unsigned delivery acceptance', {
      method: 'POST',
      pathAndQuery: hyp.pathAndQuery,
      headers: { 'Content-Type': 'application/json' },
      jsonBody: body,
    }, hyp.ownerPersona, {}, [200, 201, 202, 204]),
  ]
  let confirmedExpr = is2xx('p1')
  if (proof === 'readback' && readPath && stateField) {
    steps.push(stepOf(hyp.endpoint.origin, 'v1', 'probe', 'Read back the processed event', {
      method: 'GET',
      pathAndQuery: readPath,
    }, hyp.ownerPersona, {}, [200, 201, 204]))
    confirmedExpr = `(${is2xx('p1')} and (.steps.v1.json != null) and ((.steps.v1.json | tostring) | length > 2))`
  } else {
    confirmedExpr = `(${is2xx('p1')} and ((.steps.p1.body // "") | test("\\"(?:ok|received|processed|accepted|success)\\"\\s*:\\s*true"; "i")))`
  }
  const jq = `{ controlPassed: ((.steps.c1.status < 500) and (.steps.c1.status > 0)), ` +
    `confirmed: ${confirmedExpr}, ` +
    'observed: (("unsigned_status=" + (.steps.p1.status | tostring))), ' +
    'expected: "unsigned/tampered-key delivery is rejected and never processed" }'
  return [{
    kind: 'http_chain',
    vulnClass: 'webhook_forgery',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(hyp.endpoint.origin, 'Webhook signature verification bypass', 'CWE-345', 'webhook', 'high', jq),
      kind: 'http_chain',
      steps,
    },
  }]
}

// ---------------------------------------------------------------------------------------------

/** All schema-shaped candidate specs for a signal, most specific first. */
/**
 * Time-based blind SQLi: the engine only schedules this probe when the boolean arm produced no
 * signal (a response-identical sink), so the spec exists purely to reach the typed
 * `boolean_or_timing` timing recipe. Its declarative body is attribution; the recipe owns the proof.
 */
export function synthSqlTime(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  const hit = result.anomalies.find(anomaly => anomaly.type === 'sql_time_differential')
  if (!hit || !hyp.param) return []
  const dialectRaw = String(hit.dialect ?? '')
  const dialect = ['postgres', 'mysql', 'sqlite', 'mssql'].includes(dialectRaw)
    ? dialectRaw as 'postgres' | 'mysql' | 'sqlite' | 'mssql'
    : 'postgres'
  const delayMs = Math.max(1500, Math.min(3000, Number(hit.delayMs) || 2500))
  return [{
    kind: 'sql_time_diff',
    vulnClass: 'sqli',
    endpoint: hyp.endpoint.pathTemplate,
    spec: {
      ...baseFields(
        hyp.endpoint.origin,
        'Time-based blind SQL injection differential',
        'CWE-89',
        'injection-input',
        'high',
        '{ controlPassed: (.sqlTimeDiff.controlPassed == true), confirmed: (.sqlTimeDiff.passed == true) }',
      ),
      kind: 'sql_time_diff',
      targetOrigin: hyp.endpoint.origin,
      method: hyp.method === 'GET' ? 'GET' : hyp.method,
      pathAndQuery: hyp.pathAndQuery.split('?')[0] || '/',
      paramName: hyp.param.name,
      paramLocation: hyp.location ?? 'query',
      baselineValue: hyp.baselineValue ?? '1',
      quoteStyle: 'single',
      dialect,
      delayMs,
      ...(hyp.location === 'json' ? { jsonBody: hyp.jsonBody ?? {} } : {}),
      ...(hyp.location === 'form' ? { jsonBody: hyp.jsonBody ?? {} } : {}),
    },
  }]
}

export function synthesizeEngineSpecs(hyp: EngineHypothesis, result: DifferentialResult): SynthesizedEngineSpec[] {
  if (result.verdict !== 'signal') return []
  try {
    if (result.anomalies.some(anomaly => anomaly.type === 'secret_disclosed')) {
      const sensitiveRead = synthSensitiveRead(hyp, result)
      if (sensitiveRead.length > 0) return sensitiveRead
      return synthSecretDisclosure(hyp, result)
    }
    // Capability proofs are keyed by the invariant they established, not by the probe family that
    // happened to execute them (a workflow class owns both step-skip and price-trust evidence).
    if (result.anomalies.some(anomaly => anomaly.type === 'race_double_spend')) return synthRaceBurst(hyp, result)
    if (result.anomalies.some(anomaly => anomaly.type === 'price_tampering')) return synthPriceTrust(hyp, result)
    switch (hyp.probeClass) {
      case 'authz_matrix': return synthAuthz(hyp, result)
      case 'sqli_boolean': return synthSqlBoolean(hyp, result)
      case 'sqli_time_diff': return synthSqlTime(hyp, result)
      case 'ssti_math': return synthSsti(hyp, result)
      case 'command_injection': return synthCommandInjection(hyp, result)
      case 'workflow_invariant': return synthWorkflowStepSkip(hyp, result)
      case 'xxe_canary': return synthXxe(hyp, result)
      case 'ssrf_canary': return synthSsrf(hyp, result)
      case 'path_traversal_benign': return synthTraversal(hyp, result)
      case 'open_redirect_differential': return synthRedirect(hyp, result)
      case 'graphql_audit': return synthGraphql(hyp, result)
      case 'mass_assignment': return synthMassAssignment(hyp, result)
      case 'xss_context': return synthReflectedXss(hyp, result)
      case 'csrf_state_change': return synthCsrf(hyp, result)
      case 'auth_protocol_audit': return synthAuthProtocol(hyp, result)
      case 'webhook_signature_bypass': return synthWebhook(hyp, result)
      default: return []
    }
  } catch {
    return []
  }
}

/** Stable class label for a synthesized spec (used for attribution and hide-confirmed). */
export function vulnClassOfSpec(spec: Record<string, unknown>): string {
  const cwe = typeof spec.cwe === 'string' ? spec.cwe : ''
  const kind = typeof spec.kind === 'string' ? spec.kind : ''
  if (kind === 'browser_chain') return 'xss_reflected'
  if (kind === 'sql_boolean_diff' || kind === 'sql_time_diff') return 'sqli'
  if (kind === 'cache_differential') return 'cache_poisoning'
  if (kind === 'auth_protocol_proof') {
    const protocol = typeof spec.protocol === 'string' ? spec.protocol : 'jwt'
    return protocol === 'oauth' || protocol === 'oidc' ? 'oauth' : 'jwt'
  }
  switch (cwe) {
    case 'CWE-639': return 'bola'
    case 'CWE-89': return 'sqli'
    case 'CWE-611': return 'xxe'
    case 'CWE-918': return 'ssrf'
    case 'CWE-22': return 'path_traversal'
    case 'CWE-601': return 'open_redirect'
    case 'CWE-915': return 'mass_assignment'
    case 'CWE-79': return 'xss_reflected'
    case 'CWE-525': return 'cache_poisoning'
    case 'CWE-352': return 'csrf'
    case 'CWE-200': return 'info_disclosure'
    case 'CWE-1336': return 'ssti'
    case 'CWE-78': return 'command_injection'
    case 'CWE-840': return 'workflow_bypass'
    case 'CWE-472': return 'price_tampering'
    case 'CWE-362': return 'race_double_spend'
    case 'CWE-347': return 'jwt'
    case 'CWE-345': return 'webhook_forgery'
    default: return 'unknown'
  }
}
