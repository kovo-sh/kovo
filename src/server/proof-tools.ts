import { findingSeverities, httpMethods } from '../domain.ts'
import type { HttpMethod } from '../domain.ts'
import { containsDestructivePayload } from '../replay-spec.ts'
import type { DeclarativeReplaySpec, ReplayStep } from '../replay-spec.ts'

/**
 * Typed proof compilers.
 *
 * The agentic layer used to ask the model to hand-write a raw `DeclarativeReplaySpec` plus a jq
 * `assertionsJq` program. That is where most spec friction lived: Flash-class models emit plausible
 * JSON with status-only assertions, unbound bodies, or a declared endpoint that never ran. These
 * compilers take a small, typed, *verified* description of the proof and emit a deterministic
 * `http_chain` spec whose assertion is identifier-bound and proof-strength compliant.
 *
 * Design constraints:
 *  - Pure: no I/O, no clock, no randomness. Same input -> byte-identical spec (stable key order).
 *  - No app/route/seed literals: callers pass endpoints, field paths and identifiers.
 *  - No verifier changes: the emitted spec satisfies the existing schema and the v5.1 proof-strength
 *    gates (`classifyHttpChainAssertion`, `assessHttpChainProofStrength`,
 *    `assessHttpChainEndpointBinding`).
 *  - Repair-friendly: `validateProofInput` returns structured issues with a suggested fix so the
 *    model can repair in one turn; `ProofCompileError` carries the same shape.
 */

export const proofToolNames = [
  'prove_authz_read_diff',
  'prove_state_mutation_diff',
  'prove_business_invariant',
  'prove_canary_or_redirect',
] as const

export type ProofToolName = typeof proofToolNames[number]

export type ProofSurfaceKind = 'ssrf' | 'xxe' | 'stored_xss' | 'open_redirect'
export type BusinessInvariantOp = 'lt' | 'lte' | 'gt' | 'gte' | 'eq' | 'neq'
export type StateMutationOp = 'changed' | 'neq' | 'increment' | 'decrement' | 'set' | 'delete' | 'create' | 'skip'

export interface ProofExtract {
  varName: string
  from: 'header' | 'json' | 'status' | 'regex'
  selector: string
}

export interface ProofCsrfBind {
  headerName?: string
  fieldName?: string
  cookieName?: string
}

/** A typed replay step description. `id` is optional; compilers assign deterministic ids. */
export interface ProofStepInput {
  id?: string
  description?: string
  method?: HttpMethod
  pathAndQuery: string
  persona?: string
  session?: string
  headers?: Record<string, string>
  csrfBind?: boolean | ProofCsrfBind
  jsonBody?: unknown
  textBody?: string
  expectedStatus?: number | number[]
  followRedirects?: boolean
  extract?: ProofExtract[]
}

type Severity = typeof findingSeverities[number]

export interface ProofCommonInput {
  origin: string
  title?: string
  category?: string
  cwe?: string
  severity?: string
  severityRationale?: string
  impact?: string
  remediation?: string
  recheckInstructions?: string
}

export interface AuthzReadDiffInput extends ProofCommonInput {
  ownerPersona: string
  attackerPersona: string
  endpoint: string
  method?: HttpMethod
  resourceId: string
  identifierPath: string
}

export interface StateMutationDiffInput extends ProofCommonInput {
  setupSteps?: ProofStepInput[]
  beforeRead: ProofStepInput
  probeMutation: ProofStepInput
  afterRead: ProofStepInput
  changedFieldPath: string
  op?: StateMutationOp
  /** Optional benign control mutation; without it the control arm is the pre-mutation read. */
  controlMutation?: ProofStepInput
  controlAfterRead?: ProofStepInput
}

export interface BusinessInvariantInput extends ProofCommonInput {
  setupSteps?: ProofStepInput[]
  controlFlow: ProofStepInput | ProofStepInput[]
  probeFlow: ProofStepInput | ProofStepInput[]
  readback: ProofStepInput
  fieldPath: string
  op: BusinessInvariantOp
  /** Numeric/state baseline: a literal, `{{extractedVar}}`, or `stepId.field.path`. */
  baselineRef: string | number
  /** Optional explicit control readback (defaults to a clone of `readback` with role control). */
  controlReadback?: ProofStepInput
}

export interface CanaryOrRedirectInput extends ProofCommonInput {
  plantStep: ProofStepInput
  triggerStep: ProofStepInput
  canaryIdOrMarker: string
  surfaceKind: ProofSurfaceKind
}

export type CompiledReplaySpec = Extract<DeclarativeReplaySpec, { kind: 'http_chain' }>

export interface CompiledProof {
  spec: CompiledReplaySpec
  assertionsJq: string
  spaCatchallControl: boolean
  rationale: string
  warnings: string[]
}

export type ProofIssueCode =
  | 'missing'
  | 'invalid'
  | 'nonspecific_identifier'
  | 'ambiguous_scope'
  | 'conflicting_roles'
  | 'unsafe_payload'
  | 'unsupported'

export interface ProofIssue {
  field: string
  code: ProofIssueCode
  message: string
  fix: string
}

export type ProofValidationResult =
  | { ok: true; tool: ProofToolName; warnings: string[] }
  | { ok: false; tool: ProofToolName | null; errors: ProofIssue[] }

export class ProofCompileError extends Error {
  readonly tool: ProofToolName
  readonly issues: ProofIssue[]

  constructor(tool: ProofToolName, issues: ProofIssue[]) {
    const first = issues[0] ?? { field: 'input', message: 'Proof input is invalid.', fix: 'Provide the required identifiers.' }
    super(`${tool}: ${first.field}: ${first.message} ${first.fix}`)
    this.name = 'ProofCompileError'
    this.tool = tool
    this.issues = issues
  }

  toJSON(): { tool: ProofToolName; issues: ProofIssue[] } {
    return { tool: this.tool, issues: this.issues }
  }
}

// ---------------------------------------------------------------------------
// Small typed helpers
// ---------------------------------------------------------------------------

const STEP_ID_RE = /^[a-z0-9_-]{1,32}$/
const PERSONA_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/
const SESSION_RE = /^[a-z0-9_-]{1,32}$/
const JSON_PATH_RE = /^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$/
const RESOURCE_ID_RE = /^[A-Za-z0-9_.:@-]{1,128}$/
const CWE_RE = /^CWE-\d{1,5}$/
const CANARY_PLACEHOLDERS = new Set(['canary_token', 'canary_url', 'canary_dns_host', 'nonce_a', 'nonce_b', 'upload_nonce'])
const NON_IDENTIFIER_FIELDS = new Set(['status', 'body', 'bodypreview', 'headers', 'method', 'origin'])
const STATE_OPS = new Set<StateMutationOp>(['changed', 'neq', 'increment', 'decrement', 'set', 'delete', 'create', 'skip'])
const INVARIANT_OPS = new Set<BusinessInvariantOp>(['lt', 'lte', 'gt', 'gte', 'eq', 'neq'])
const SURFACES = new Set<ProofSurfaceKind>(['ssrf', 'xxe', 'stored_xss', 'open_redirect'])

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function readString(obj: Record<string, unknown>, key: string): string | undefined {
  const value = obj[key]
  return typeof value === 'string' ? value : undefined
}

function isCoveredByPlaceholder(value: string): boolean {
  const trimmed = value.trim()
  return /^\{\{.*\}\}$/.test(trimmed) || /^:[A-Za-z_][A-Za-z0-9_]*$/.test(trimmed) ||
    /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(trimmed) || /^<[^>]+>$/.test(trimmed)
}

function isSpecificValue(value: string): boolean {
  const trimmed = value.trim()
  if (trimmed.length < 2) return false
  if (/^(?:id|null|undefined|true|false|\*)$/i.test(trimmed)) return false
  return !isCoveredByPlaceholder(trimmed)
}

function markerPlaceholder(value: string): string | null {
  const match = /^\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$/.exec(value.trim())
  return match ? match[1]! : null
}

function isSingleLine(value: string): boolean {
  return !/[\r\n\0]/.test(value)
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value)
    return (url.protocol === 'http:' || url.protocol === 'https:') && url.host.length > 0
  } catch {
    return false
  }
}

function pathIssues(value: string | undefined, field: string): ProofIssue[] {
  if (!value) return [{ field, code: 'missing', message: 'A request path is required.', fix: 'Pass an absolute path such as /resource/{identifier}.' }]
  if (!value.startsWith('/') || value.startsWith('//')) {
    return [{ field, code: 'invalid', message: 'The path must start with a single /.', fix: 'Use a site-relative path beginning with exactly one slash.' }]
  }
  if (!isSingleLine(value) || value.length > 4096) {
    return [{ field, code: 'invalid', message: 'The path must be a single line of at most 4096 characters.', fix: 'Remove control characters and shorten the path.' }]
  }
  return []
}

function stepSerialized(step: unknown): string {
  try {
    return JSON.stringify(step) ?? ''
  } catch {
    return ''
  }
}

function stepIssues(value: unknown, field: string, opts: { mutating?: boolean; readOnly?: boolean } = {}): ProofIssue[] {
  const issues: ProofIssue[] = []
  if (!isRecord(value)) {
    return [{ field, code: 'missing', message: 'A step object is required.', fix: 'Pass { method, pathAndQuery, ... } with at least a path.' }]
  }
  const id = readString(value, 'id')
  if (id !== undefined && !STEP_ID_RE.test(id)) {
    issues.push({ field: `${field}.id`, code: 'invalid', message: 'Step id must match /^[a-z0-9_-]{1,32}$/.', fix: 'Use a short lower-case step id such as setup-1 or read-before.' })
  }
  const method = readString(value, 'method')
  if (method !== undefined && !(httpMethods as readonly string[]).includes(method)) {
    issues.push({ field: `${field}.method`, code: 'invalid', message: `Method ${method} is not supported.`, fix: `Use one of ${httpMethods.join(', ')}.` })
  }
  const pathAndQuery = readString(value, 'pathAndQuery')
  issues.push(...pathIssues(pathAndQuery, `${field}.pathAndQuery`))

  const persona = readString(value, 'persona')
  if (persona !== undefined && !PERSONA_RE.test(persona)) {
    issues.push({ field: `${field}.persona`, code: 'invalid', message: 'Persona handle is malformed.', fix: 'Use a lower-case persona handle from the assignment brief.' })
  }
  const session = readString(value, 'session')
  if (session !== undefined && !SESSION_RE.test(session)) {
    issues.push({ field: `${field}.session`, code: 'invalid', message: 'Session handle is malformed.', fix: 'Use a lower-case session handle such as owner-session.' })
  }
  const headers = value.headers
  if (headers !== undefined) {
    if (!isRecord(headers)) {
      issues.push({ field: `${field}.headers`, code: 'invalid', message: 'Headers must be an object of string values.', fix: 'Pass headers as a plain JSON object.' })
    } else {
      for (const [name, headerValue] of Object.entries(headers)) {
        if (/^(?:authorization|proxy-authorization|cookie)$/i.test(name)) {
          issues.push({ field: `${field}.headers.${name}`, code: 'invalid', message: 'Authorization and Cookie headers are not allowed in a replay step.', fix: 'Reference an approved persona handle instead of a raw credential.' })
        }
        if (typeof headerValue !== 'string' || !isSingleLine(headerValue)) {
          issues.push({ field: `${field}.headers.${name}`, code: 'invalid', message: 'Header values must be single-line strings.', fix: 'Remove newline characters from the header value.' })
        }
      }
    }
  }
  const description = readString(value, 'description')
  if (description !== undefined && (description.length === 0 || description.length > 400)) {
    issues.push({ field: `${field}.description`, code: 'invalid', message: 'Description must be 1-400 characters.', fix: 'Use a short description of what the step proves.' })
  }
  const effectiveMethod = method ?? 'GET'
  if (opts.mutating && !['POST', 'PUT', 'PATCH', 'DELETE'].includes(effectiveMethod)) {
    issues.push({ field: `${field}.method`, code: 'invalid', message: 'A mutation step must use POST, PUT, PATCH or DELETE.', fix: 'Use a mutating method for the probe mutation.' })
  }
  if (opts.readOnly && !['GET', 'HEAD', 'OPTIONS'].includes(effectiveMethod)) {
    issues.push({ field: `${field}.method`, code: 'invalid', message: 'A state read must use a read-only method.', fix: 'Use GET or HEAD for the before/after read.' })
  }
  if (containsDestructivePayload(stepSerialized(value))) {
    issues.push({ field, code: 'unsafe_payload', message: 'The step contains a destructive payload signature.', fix: 'Use a benign canary/nonce value instead of a destructive command.' })
  }
  return issues
}

function stepArrayIssues(value: unknown, field: string, max = 6): ProofIssue[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) {
    return [{ field, code: 'invalid', message: 'Expected an array of steps.', fix: 'Pass a JSON array of step objects.' }]
  }
  if (value.length > max) {
    return [{ field, code: 'invalid', message: `At most ${max} steps are supported.`, fix: `Reduce the flow to ${max} steps or fewer.` }]
  }
  const issues: ProofIssue[] = []
  value.forEach((step, index) => issues.push(...stepIssues(step, `${field}[${index}]`)))
  return issues
}

function flowSteps(value: unknown): ProofStepInput[] {
  return Array.isArray(value) ? value as ProofStepInput[] : [value as ProofStepInput]
}

function commonIssues(obj: Record<string, unknown>): ProofIssue[] {
  const issues: ProofIssue[] = []
  const origin = readString(obj, 'origin')
  if (!origin) {
    issues.push({ field: 'origin', code: 'missing', message: 'A target origin is required.', fix: 'Pass the approved asset origin from the assignment scope.' })
  } else if (!isHttpUrl(origin)) {
    issues.push({ field: 'origin', code: 'invalid', message: 'Origin must be an http(s) URL.', fix: 'Pass a scheme and host, for example https://app.example.' })
  }
  const title = readString(obj, 'title')
  if (title !== undefined && (title.length < 3 || title.length > 200)) {
    issues.push({ field: 'title', code: 'invalid', message: 'Title must be 3-200 characters.', fix: 'Use a short finding title.' })
  }
  const cwe = readString(obj, 'cwe')
  if (cwe !== undefined && !CWE_RE.test(cwe)) {
    issues.push({ field: 'cwe', code: 'invalid', message: 'CWE must look like CWE-639.', fix: 'Pass a CWE identifier.' })
  }
  const severity = readString(obj, 'severity')
  if (severity !== undefined && !(findingSeverities as readonly string[]).includes(severity)) {
    issues.push({ field: 'severity', code: 'invalid', message: `Severity ${severity} is not supported.`, fix: `Use one of ${findingSeverities.join(', ')}.` })
  }
  return issues
}

function endpointPlaceholder(endpoint: string, resourceId: string): string | null {
  const candidates = ['{resourceId}', '{{resourceId}}', ':resourceId', '{id}', ':id']
  for (const candidate of candidates) {
    if (endpoint.includes(candidate)) {
      return endpoint.split(candidate).join(encodeURIComponent(resourceId))
    }
  }
  if (endpoint.includes(resourceId) || endpoint.includes(encodeURIComponent(resourceId))) return endpoint
  return null
}

function resourceIdIssues(value: string | undefined): ProofIssue[] {
  if (!value) return [{ field: 'resourceId', code: 'missing', message: 'The victim resource identifier is required.', fix: 'Pass the concrete identifier harvested by recon (for example a UUID or tenant-scoped numeric id).' }]
  const trimmed = value.trim()
  if (!isSpecificValue(trimmed) || !RESOURCE_ID_RE.test(trimmed)) {
    return [{ field: 'resourceId', code: 'nonspecific_identifier', message: `Resource id ${JSON.stringify(value)} is a placeholder or too generic to bind a proof.`, fix: 'Pass the concrete value observed on the wire (not {id}, :id, id, *, or a single character).' }]
  }
  return []
}

function identifierPathIssues(value: string | undefined, field: string): ProofIssue[] {
  if (!value) return [{ field, code: 'missing', message: 'A response field path is required to bind the proof.', fix: 'Pass a JSON field path such as id or data.order_id.' }]
  if (!JSON_PATH_RE.test(value) || NON_IDENTIFIER_FIELDS.has(value.toLowerCase())) {
    return [{ field, code: 'nonspecific_identifier', message: `${JSON.stringify(value)} is not a specific response field path.`, fix: 'Use a dot path to a concrete object field (for example data.id); status/body/headers do not bind an identifier.' }]
  }
  return []
}

function markerIssues(value: string | undefined, surfaceKind: ProofSurfaceKind): ProofIssue[] {
  if (!value) return [{ field: 'canaryIdOrMarker', code: 'missing', message: 'A canary id or marker is required.', fix: 'Pass the planted canary token, marker, or an approved {{canary_*}} placeholder.' }]
  const placeholder = markerPlaceholder(value)
  if (placeholder) {
    if (!CANARY_PLACEHOLDERS.has(placeholder)) {
      return [{ field: 'canaryIdOrMarker', code: 'invalid', message: `Placeholder ${value} is not a verifier-minted canary.`, fix: `Use one of ${[...CANARY_PLACEHOLDERS].map(v => `{{${v}}}`).join(', ')}.` }]
    }
    if (surfaceKind === 'open_redirect') {
      return [{ field: 'canaryIdOrMarker', code: 'invalid', message: 'Open redirects need a concrete external host or marker, not an OOB canary.', fix: 'Pass the external redirect host or path marker that must appear in Location.' }]
    }
    if (surfaceKind === 'stored_xss') {
      return [{ field: 'canaryIdOrMarker', code: 'invalid', message: 'Stored XSS is proven by marker reflection, not an out-of-band callback.', fix: 'Pass a literal high-entropy marker that the stored sink returns.' }]
    }
    return []
  }
  if (value.trim().length < 4 || !isSingleLine(value) || value.length > 256) {
    return [{ field: 'canaryIdOrMarker', code: 'nonspecific_identifier', message: 'Marker must be a single-line value of 4-256 characters.', fix: 'Pass a unique high-entropy marker or the planted canary id.' }]
  }
  if (/^(?:test|canary|marker|foo|bar|baz|abc|example|value|id)$/i.test(value.trim())) {
    return [{ field: 'canaryIdOrMarker', code: 'nonspecific_identifier', message: `Marker ${JSON.stringify(value)} is too generic to attribute.`, fix: 'Use the exact high-entropy marker that was planted.' }]
  }
  if (containsDestructivePayload(value)) {
    return [{ field: 'canaryIdOrMarker', code: 'unsafe_payload', message: 'The marker matches a destructive-payload signature.', fix: 'Use a benign canary marker.' }]
  }
  return []
}

function authzIssues(obj: Record<string, unknown>): ProofIssue[] {
  const issues: ProofIssue[] = []
  const owner = readString(obj, 'ownerPersona')
  const attacker = readString(obj, 'attackerPersona')
  if (!owner) issues.push({ field: 'ownerPersona', code: 'missing', message: 'The owning persona is required.', fix: 'Pass the approved persona handle that owns the resource.' })
  else if (!PERSONA_RE.test(owner)) issues.push({ field: 'ownerPersona', code: 'invalid', message: 'Owner persona handle is malformed.', fix: 'Use a lower-case persona handle.' })
  if (!attacker) issues.push({ field: 'attackerPersona', code: 'missing', message: 'The attacker persona is required.', fix: 'Pass a different approved persona handle.' })
  else if (!PERSONA_RE.test(attacker)) issues.push({ field: 'attackerPersona', code: 'invalid', message: 'Attacker persona handle is malformed.', fix: 'Use a lower-case persona handle.' })
  if (owner && attacker && owner === attacker) {
    issues.push({ field: 'attackerPersona', code: 'conflicting_roles', message: 'Control and probe must be different actors.', fix: 'Use a second persona that is not entitled to the resource.' })
  }
  const endpoint = readString(obj, 'endpoint')
  issues.push(...pathIssues(endpoint, 'endpoint'))
  const method = readString(obj, 'method')
  if (method !== undefined && !(httpMethods as readonly string[]).includes(method)) {
    issues.push({ field: 'method', code: 'invalid', message: `Method ${method} is not supported.`, fix: `Use one of ${httpMethods.join(', ')}.` })
  }
  const resourceId = readString(obj, 'resourceId')
  issues.push(...resourceIdIssues(resourceId))
  issues.push(...identifierPathIssues(readString(obj, 'identifierPath'), 'identifierPath'))
  if (endpoint && resourceId && isSpecificValue(resourceId) && endpointPlaceholder(endpoint, resourceId) === null) {
    issues.push({
      field: 'endpoint',
      code: 'ambiguous_scope',
      message: 'The endpoint does not reference the victim resource identifier.',
      fix: 'Include {resourceId} (or the literal identifier) in the endpoint, for example /resource/{resourceId}.',
    })
  }
  if (endpoint && containsDestructivePayload(endpoint)) {
    issues.push({ field: 'endpoint', code: 'unsafe_payload', message: 'The endpoint contains a destructive-payload signature.', fix: 'Pass the plain resource path.' })
  }
  return issues
}

function stateIssues(obj: Record<string, unknown>): ProofIssue[] {
  const issues: ProofIssue[] = []
  issues.push(...stepArrayIssues(obj.setupSteps, 'setupSteps'))
  issues.push(...stepIssues(obj.beforeRead, 'beforeRead', { readOnly: true }))
  issues.push(...stepIssues(obj.probeMutation, 'probeMutation', { mutating: true }))
  issues.push(...stepIssues(obj.afterRead, 'afterRead', { readOnly: true }))
  if (obj.controlMutation !== undefined) {
    issues.push(...stepIssues(obj.controlMutation, 'controlMutation', { mutating: true }))
    if (obj.controlAfterRead === undefined) {
      issues.push({ field: 'controlAfterRead', code: 'missing', message: 'A control mutation needs a matching control readback.', fix: 'Pass controlAfterRead so the unchanged control field can be asserted.' })
    } else {
      issues.push(...stepIssues(obj.controlAfterRead, 'controlAfterRead', { readOnly: true }))
    }
  } else if (obj.controlAfterRead !== undefined) {
    issues.push({ field: 'controlMutation', code: 'missing', message: 'controlAfterRead was supplied without controlMutation.', fix: 'Pass controlMutation or remove controlAfterRead.' })
  }
  issues.push(...identifierPathIssues(readString(obj, 'changedFieldPath'), 'changedFieldPath'))
  const op = readString(obj, 'op')
  if (op !== undefined && !STATE_OPS.has(op as StateMutationOp)) {
    issues.push({ field: 'op', code: 'unsupported', message: `State mutation op ${op} is not supported.`, fix: `Use one of ${[...STATE_OPS].join(', ')}.` })
  }
  const beforePath = isRecord(obj.beforeRead) ? readString(obj.beforeRead, 'pathAndQuery') : undefined
  const afterPath = isRecord(obj.afterRead) ? readString(obj.afterRead, 'pathAndQuery') : undefined
  if (beforePath && afterPath && beforePath !== afterPath) {
    issues.push({ field: 'afterRead.pathAndQuery', code: 'ambiguous_scope', message: 'Before and after reads target different paths, so the field delta is not attributable.', fix: 'Read the same resource path before and after the mutation.' })
  }
  return issues
}

function numericBaseline(value: string | number): boolean {
  const text = typeof value === 'number' ? String(value) : value.trim()
  return text !== '' && Number.isFinite(Number(text))
}

function baselineRefIssues(value: unknown, op: BusinessInvariantOp, steps: unknown[]): ProofIssue[] {
  const numeric = op !== 'eq' && op !== 'neq'
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return [{ field: 'baselineRef', code: 'invalid', message: 'Baseline number is not finite.', fix: 'Pass a finite numeric baseline.' }]
    return []
  }
  if (typeof value !== 'string' || value.trim() === '') {
    return [{ field: 'baselineRef', code: 'missing', message: 'A baseline reference is required.', fix: 'Pass a numeric literal, {{extractedVar}}, or stepId.field.path.' }]
  }
  const text = value.trim()
  const placeholder = markerPlaceholder(text)
  if (placeholder) {
    const extracts = steps.flatMap(step => isRecord(step) && Array.isArray(step.extract) ? step.extract : [])
      .filter(isRecord)
      .map(extract => readString(extract, 'varName'))
    if (!extracts.includes(placeholder)) {
      return [{ field: 'baselineRef', code: 'ambiguous_scope', message: `No step extracts ${text}.`, fix: `Add an extract with varName ${placeholder} or pass a literal baseline.` }]
    }
    return []
  }
  const ref = /^([a-z0-9_-]{1,32})\.([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)$/.exec(text)
  if (ref) {
    const ids = steps.filter(isRecord).map(step => readString(step, 'id')).filter((id): id is string => Boolean(id))
    if (!ids.includes(ref[1]!)) {
      return [{ field: 'baselineRef', code: 'ambiguous_scope', message: `Baseline step ${ref[1]} has no explicit id in the supplied steps.`, fix: `Give the step an id of ${ref[1]} or pass a literal/numeric baseline.` }]
    }
    return []
  }
  if (numeric && !numericBaseline(text)) {
    return [{ field: 'baselineRef', code: 'invalid', message: `${JSON.stringify(value)} is not numeric.`, fix: `Op ${op} compares numbers; pass a numeric baseline or a step field reference.` }]
  }
  return []
}

function invariantIssues(obj: Record<string, unknown>): ProofIssue[] {
  const issues: ProofIssue[] = []
  issues.push(...stepArrayIssues(obj.setupSteps, 'setupSteps'))
  const control = obj.controlFlow
  const probe = obj.probeFlow
  if (control === undefined) issues.push({ field: 'controlFlow', code: 'missing', message: 'A control flow is required.', fix: 'Pass one or more steps that keep the invariant.' })
  else if (Array.isArray(control)) issues.push(...stepArrayIssues(control, 'controlFlow'))
  else issues.push(...stepIssues(control, 'controlFlow'))
  if (probe === undefined) issues.push({ field: 'probeFlow', code: 'missing', message: 'A probe flow is required.', fix: 'Pass one or more steps that try to violate the invariant.' })
  else if (Array.isArray(probe)) issues.push(...stepArrayIssues(probe, 'probeFlow'))
  else issues.push(...stepIssues(probe, 'probeFlow'))
  issues.push(...stepIssues(obj.readback, 'readback', { readOnly: true }))
  if (obj.controlReadback !== undefined) issues.push(...stepIssues(obj.controlReadback, 'controlReadback', { readOnly: true }))
  issues.push(...identifierPathIssues(readString(obj, 'fieldPath'), 'fieldPath'))
  const op = readString(obj, 'op')
  if (!op) issues.push({ field: 'op', code: 'missing', message: 'An invariant operator is required.', fix: `Use one of ${[...INVARIANT_OPS].join(', ')}.` })
  else if (!INVARIANT_OPS.has(op as BusinessInvariantOp)) issues.push({ field: 'op', code: 'unsupported', message: `Invariant op ${op} is not supported.`, fix: `Use one of ${[...INVARIANT_OPS].join(', ')}.` })
  const allSteps = [
    ...(Array.isArray(obj.setupSteps) ? obj.setupSteps : []),
    ...(control === undefined ? [] : Array.isArray(control) ? control : [control]),
    ...(probe === undefined ? [] : Array.isArray(probe) ? probe : [probe]),
    ...(obj.readback === undefined ? [] : [obj.readback]),
    ...(obj.controlReadback === undefined ? [] : [obj.controlReadback]),
  ]
  if (op && INVARIANT_OPS.has(op as BusinessInvariantOp)) {
    issues.push(...baselineRefIssues(obj.baselineRef, op as BusinessInvariantOp, allSteps))
  }
  if (control !== undefined && probe !== undefined) {
    const controlSteps = Array.isArray(control) ? control : [control]
    const probeSteps = Array.isArray(probe) ? probe : [probe]
    const serialize = (steps: unknown[]) => JSON.stringify(steps.map(step => isRecord(step) ? {
      method: step.method ?? 'GET',
      pathAndQuery: step.pathAndQuery,
      persona: step.persona,
      jsonBody: step.jsonBody,
      textBody: step.textBody,
    } : step))
    if (serialize(controlSteps) === serialize(probeSteps)) {
      issues.push({ field: 'probeFlow', code: 'ambiguous_scope', message: 'Control and probe flows are identical, so the invariant differential has no changed input.', fix: 'Change at least one request field (body, amount, persona, or step) in the probe flow.' })
    }
  }
  return issues
}

function canaryIssues(obj: Record<string, unknown>): ProofIssue[] {
  const issues: ProofIssue[] = []
  issues.push(...stepIssues(obj.plantStep, 'plantStep'))
  issues.push(...stepIssues(obj.triggerStep, 'triggerStep'))
  const surface = readString(obj, 'surfaceKind')
  if (!surface) issues.push({ field: 'surfaceKind', code: 'missing', message: 'A surface kind is required.', fix: `Use one of ${[...SURFACES].join(', ')}.` })
  else if (!SURFACES.has(surface as ProofSurfaceKind)) issues.push({ field: 'surfaceKind', code: 'unsupported', message: `Surface kind ${surface} is not supported.`, fix: `Use one of ${[...SURFACES].join(', ')}.` })
  const marker = readString(obj, 'canaryIdOrMarker')
  if (surface && SURFACES.has(surface as ProofSurfaceKind)) issues.push(...markerIssues(marker, surface as ProofSurfaceKind))
  if (!surface || !SURFACES.has(surface as ProofSurfaceKind) || !marker) return issues

  const plant = stepSerialized(obj.plantStep)
  const trigger = stepSerialized(obj.triggerStep)
  if (surface === 'open_redirect') {
    if (isRecord(obj.triggerStep) && obj.triggerStep.followRedirects === true) {
      issues.push({ field: 'triggerStep.followRedirects', code: 'invalid', message: 'Redirect proof must not follow the redirect.', fix: 'Set followRedirects: false so the Location header is observable.' })
    }
    if (!trigger.includes(marker)) {
      issues.push({ field: 'triggerStep', code: 'nonspecific_identifier', message: 'The trigger step does not contain the redirect marker.', fix: 'Put the external host or path marker in the trigger step query/body.' })
    }
    if (plant.includes(marker)) {
      issues.push({ field: 'plantStep', code: 'ambiguous_scope', message: 'The benign control request also contains the redirect marker.', fix: 'Keep the marker out of the control request so the two arms differ.' })
    }
    const plantPath = isRecord(obj.plantStep) ? readString(obj.plantStep, 'pathAndQuery') : undefined
    const triggerPath = isRecord(obj.triggerStep) ? readString(obj.triggerStep, 'pathAndQuery') : undefined
    if (plantPath && triggerPath && plantPath.split('?')[0] !== triggerPath.split('?')[0]) {
      issues.push({ field: 'plantStep.pathAndQuery', code: 'ambiguous_scope', message: 'The control request targets a different route than the redirect.', fix: 'Use the same redirect endpoint with a benign target for the control.' })
    }
    return issues
  }

  if (!plant.includes(marker)) {
    issues.push({ field: 'plantStep', code: 'nonspecific_identifier', message: 'The plant step does not contain the marker or canary.', fix: 'Put the marker/canary in the planted payload so the trigger step can observe propagation.' })
  }
  return issues
}

const toolIssueFns: Record<ProofToolName, (obj: Record<string, unknown>) => ProofIssue[]> = {
  prove_authz_read_diff: authzIssues,
  prove_state_mutation_diff: stateIssues,
  prove_business_invariant: invariantIssues,
  prove_canary_or_redirect: canaryIssues,
}

function validationWarnings(tool: ProofToolName, obj: Record<string, unknown>): string[] {
  const warnings: string[] = []
  if (tool === 'prove_authz_read_diff') {
    const method = readString(obj, 'method') ?? 'GET'
    if (!['GET', 'HEAD'].includes(method)) warnings.push(`Method ${method} mutates; a read differential is normally proven with GET/HEAD.`)
    const resourceId = readString(obj, 'resourceId') ?? ''
    if (/^\d{1,3}$/.test(resourceId)) warnings.push('Resource id is short/low-entropy; prefer a high-entropy victim identifier to avoid attributing an enumerable default object.')
  }
  if (tool === 'prove_state_mutation_diff' && obj.controlMutation === undefined) {
    warnings.push('No benign control mutation supplied; the control arm is the pre-mutation read, so only the before/after field delta is asserted.')
  }
  if (tool === 'prove_business_invariant' && typeof obj.baselineRef === 'string' && !markerPlaceholder(obj.baselineRef) && !obj.baselineRef.includes('.')) {
    warnings.push('Baseline was treated as a literal; prefer a control/readback field reference when the invariant is per-resource.')
  }
  if (tool === 'prove_canary_or_redirect') {
    const surface = readString(obj, 'surfaceKind')
    if (surface && surface !== 'open_redirect') {
      const marker = readString(obj, 'canaryIdOrMarker') ?? ''
      if (marker && stepSerialized(obj.triggerStep).includes(marker)) {
        warnings.push('The trigger step also contains the marker; ensure the control baseline still reflects the pre-plant state.')
      }
    }
  }
  return warnings
}

export function validateProofInput(toolName: string, input: unknown): ProofValidationResult {
  if (!(proofToolNames as readonly string[]).includes(toolName)) {
    return {
      ok: false,
      tool: null,
      errors: [{ field: 'toolName', code: 'unsupported', message: `Unknown proof tool ${JSON.stringify(toolName)}.`, fix: `Use one of ${proofToolNames.join(', ')}.` }],
    }
  }
  const tool = toolName as ProofToolName
  if (!isRecord(input)) {
    return {
      ok: false,
      tool,
      errors: [{ field: 'input', code: 'missing', message: 'Proof input must be an object.', fix: 'Pass the tool argument object described by describeProofTools().' }],
    }
  }
  const errors = [...commonIssues(input), ...toolIssueFns[tool](input)]
  if (errors.length > 0) return { ok: false, tool, errors }
  return { ok: true, tool, warnings: validationWarnings(tool, input) }
}

function ensureValid(tool: ProofToolName, input: unknown): string[] {
  const result = validateProofInput(tool, input)
  if (!result.ok) throw new ProofCompileError(tool, result.errors)
  return result.warnings
}

// ---------------------------------------------------------------------------
// Spec assembly
// ---------------------------------------------------------------------------

interface ToolDefaults {
  title: string
  category: string
  cwe: string
  severity: Severity
  severityRationale: string
  impact: string
  remediation: string
  recheckInstructions: string
}

interface CompiledBaseFields {
  version: 1
  origin: string
  title: string
  category: string
  cwe: string
  severity: Severity
  severityRationale: string
  impact: string
  remediation: string
  recheckInstructions: string
}

function baseFields(input: ProofCommonInput, defaults: ToolDefaults): CompiledBaseFields {
  return {
    version: 1,
    origin: input.origin,
    title: input.title ?? defaults.title,
    category: input.category ?? defaults.category,
    cwe: input.cwe ?? defaults.cwe,
    severity: (input.severity ?? defaults.severity) as Severity,
    severityRationale: input.severityRationale ?? defaults.severityRationale,
    impact: input.impact ?? defaults.impact,
    remediation: input.remediation ?? defaults.remediation,
    recheckInstructions: input.recheckInstructions ?? defaults.recheckInstructions,
  }
}

interface CompileStepOptions {
  tool: ProofToolName
  role: ReplayStep['role']
  id: string
  origin: string
  description: string
  usedIds: Set<string>
}

function compileStep(input: ProofStepInput, opts: CompileStepOptions): ReplayStep {
  const issues = stepIssues(input, `steps.${opts.id}`)
  if (issues.length > 0) throw new ProofCompileError(opts.tool, issues)
  const id = input.id ?? opts.id
  if (!STEP_ID_RE.test(id)) {
    throw new ProofCompileError(opts.tool, [{ field: `steps.${opts.id}.id`, code: 'invalid', message: 'Step id is malformed.', fix: 'Use /^[a-z0-9_-]{1,32}$/.' }])
  }
  if (opts.usedIds.has(id)) {
    throw new ProofCompileError(opts.tool, [{ field: `steps.${opts.id}.id`, code: 'ambiguous_scope', message: `Duplicate step id ${id}.`, fix: 'Give each step a unique id (or omit ids to let the compiler number them).' }])
  }
  opts.usedIds.add(id)
  const headers = input.headers
    ? Object.fromEntries(Object.keys(input.headers).sort().map(name => [name, input.headers![name]!]))
    : undefined
  const description = (input.description ?? opts.description).slice(0, 400)
  return {
    id,
    role: opts.role,
    description,
    ...(input.expectedStatus !== undefined ? { expectedStatus: input.expectedStatus } : {}),
    request: {
      origin: opts.origin,
      method: input.method ?? 'GET',
      pathAndQuery: input.pathAndQuery,
      ...(headers ? { headers } : {}),
      ...(input.persona ? { persona: input.persona } : {}),
      ...(input.session ? { session: input.session } : {}),
      ...(input.csrfBind !== undefined ? { csrfBind: input.csrfBind } : {}),
      ...(input.jsonBody !== undefined ? { jsonBody: structuredClone(input.jsonBody) } : {}),
      ...(input.textBody !== undefined ? { textBody: input.textBody } : {}),
      followRedirects: input.followRedirects ?? false,
    },
    ...(input.extract?.length ? { extract: input.extract.map(extract => ({ ...extract })) } : {}),
  }
}

function assembleSpec(input: ProofCommonInput, defaults: ToolDefaults, assertionsJq: string, spaCatchallControl: boolean, steps: ReplayStep[]): CompiledReplaySpec {
  const fields = baseFields(input, defaults)
  const spec = {
    version: fields.version,
    kind: 'http_chain' as const,
    origin: fields.origin,
    title: fields.title,
    category: fields.category,
    cwe: fields.cwe,
    severity: fields.severity,
    severityRationale: fields.severityRationale,
    impact: fields.impact,
    remediation: fields.remediation,
    recheckInstructions: fields.recheckInstructions,
    assertionsJq,
    requireControlNonError: true,
    spaCatchallControl,
    steps,
  }
  return spec
}

// ---------------------------------------------------------------------------
// jq generation
// ---------------------------------------------------------------------------

function jqString(value: string): string {
  return JSON.stringify(value)
}

function jqJson(stepId: string, path: string): string {
  return `.steps.${stepId}.json${path.split('.').map(segment => `.${segment}`).join('')}`
}

function jqBody(stepId: string): string {
  return `.steps.${stepId}.body`
}

function jqStatus(stepId: string): string {
  return `.steps.${stepId}.status`
}

function jqStringEq(expression: string, value: string): string {
  return `(((${expression}) | tostring) == ${jqString(value)})`
}

function jqSuccess(stepId: string): string {
  return `((${jqStatus(stepId)} >= 200) and (${jqStatus(stepId)} < 300))`
}

function jqPresent(expression: string): string {
  return `((${expression}) != null)`
}

function jqObserved(label: string, expression: string): string {
  return `${jqString(label)} + (((${expression}) // "missing") | tostring)`
}

// ---------------------------------------------------------------------------
// 1. Authorization read differential
// ---------------------------------------------------------------------------

const authzDefaults: ToolDefaults = {
  title: 'Cross-actor resource read',
  category: 'broken-access-control',
  cwe: 'CWE-639',
  severity: 'high',
  severityRationale: 'A different actor receives the same resource content as the owning actor.',
  impact: 'An authenticated attacker can read another actor or tenant resource.',
  remediation: 'Enforce an object-level ownership or tenant check on the handler before returning the object.',
  recheckInstructions: 'Replay the owner read and the attacker read; the attacker must receive 401/403/404 for the same identifier.',
}

export function proveAuthzReadDiff(input: AuthzReadDiffInput): CompiledProof {
  const warnings = ensureValid('prove_authz_read_diff', input)
  const method = input.method ?? 'GET'
  const pathAndQuery = endpointPlaceholder(input.endpoint, input.resourceId)!
  const identifierPath = input.identifierPath
  const usedIds = new Set<string>()
  const controlId = 'control'
  const probeId = 'probe'

  const control = compileStep({
    method,
    pathAndQuery,
    persona: input.ownerPersona,
    expectedStatus: 200,
  }, {
    tool: 'prove_authz_read_diff', role: 'control', id: controlId, origin: input.origin,
    description: 'Owner reads the target resource', usedIds,
  })
  const probe = compileStep({
    method,
    pathAndQuery,
    persona: input.attackerPersona,
    expectedStatus: [200, 401, 403, 404],
  }, {
    tool: 'prove_authz_read_diff', role: 'probe', id: probeId, origin: input.origin,
    description: 'Non-owner reads the same resource', usedIds,
  })

  const controlField = jqJson(control.id, identifierPath)
  const probeField = jqJson(probe.id, identifierPath)
  const assertionsJq = `{
  controlPassed: (${jqSuccess(control.id)} and ${jqPresent(controlField)} and ${jqStringEq(controlField, input.resourceId)}),
  confirmed: (${jqSuccess(probe.id)} and ${jqPresent(probeField)} and ${jqStringEq(probeField, input.resourceId)} and ((${jqBody(probe.id)} | contains(${jqString(input.resourceId)})))),
  observed: ("probe-status=" + (${jqStatus(probe.id)} | tostring) + " bound-" + ${jqString(identifierPath)} + "=" + (((${probeField}) // "missing") | tostring)),
  expected: "the attacker is denied for the same resource identifier"
}`

  const steps = [control, probe]
  const spec = assembleSpec(input, authzDefaults, assertionsJq, true, steps)
  return {
    spec,
    assertionsJq,
    spaCatchallControl: true,
    rationale: `Control reads ${method} ${pathAndQuery} as ${input.ownerPersona}; probe reads it as ${input.attackerPersona}. Confirmation requires the attacker response to echo the victim identifier ${JSON.stringify(input.resourceId)} at ${identifierPath}, not just a 2xx status.`,
    warnings,
  }
}

// ---------------------------------------------------------------------------
// 2. State mutation differential
// ---------------------------------------------------------------------------

const stateDefaults: ToolDefaults = {
  title: 'Unauthorized state mutation',
  category: 'broken-access-control',
  cwe: 'CWE-639',
  severity: 'high',
  severityRationale: 'A probe request changes a persisted field that the control path leaves unchanged.',
  impact: 'An unauthorized actor can alter another resource or skip a required workflow transition.',
  remediation: 'Authorize the mutation and re-read the persisted field after the request; bind the changed value to the acted-on resource.',
  recheckInstructions: 'Replay the before read, the mutation, and the after read; the field must remain at the control value for the attacker.',
}

function stateRelationJq(op: StateMutationOp, before: string, after: string): string {
  switch (op) {
    case 'increment':
      return `(try (((${after}) | tonumber) > ((${before}) | tonumber)) catch false)`
    case 'decrement':
      return `(try (((${after}) | tonumber) < ((${before}) | tonumber)) catch false)`
    case 'delete':
      return `((${after}) == null and (${before}) != null)`
    case 'create':
      return `((${before}) == null and (${after}) != null)`
    case 'changed':
    case 'neq':
    case 'set':
    case 'skip':
    default:
      return `(((${after}) | tostring) != ((${before}) | tostring))`
  }
}

export function proveStateMutationDiff(input: StateMutationDiffInput): CompiledProof {
  const warnings = ensureValid('prove_state_mutation_diff', input)
  const op = input.op ?? 'changed'
  const usedIds = new Set<string>()
  const steps: ReplayStep[] = []

  for (const [index, setup] of (input.setupSteps ?? []).entries()) {
    steps.push(compileStep(setup, {
      tool: 'prove_state_mutation_diff', role: 'setup', id: `setup_${index + 1}`, origin: input.origin,
      description: 'Prepare the resource state', usedIds,
    }))
  }

  let beforeReadStep: ReplayStep
  let controlAfterStep: ReplayStep | undefined
  if (input.controlMutation) {
    beforeReadStep = compileStep(input.beforeRead, {
      tool: 'prove_state_mutation_diff', role: 'control', id: 'control_before', origin: input.origin,
      description: 'Control read before the benign mutation', usedIds,
    })
    steps.push(beforeReadStep)
    steps.push(compileStep(input.controlMutation, {
      tool: 'prove_state_mutation_diff', role: 'control', id: 'control_mutate', origin: input.origin,
      description: 'Benign control mutation', usedIds,
    }))
    controlAfterStep = compileStep(input.controlAfterRead!, {
      tool: 'prove_state_mutation_diff', role: 'control', id: 'control_after', origin: input.origin,
      description: 'Control read after the benign mutation', usedIds,
    })
    steps.push(controlAfterStep)
  } else {
    beforeReadStep = compileStep(input.beforeRead, {
      tool: 'prove_state_mutation_diff', role: 'control', id: 'before_read', origin: input.origin,
      description: 'Read the field before the probe mutation', usedIds,
    })
    steps.push(beforeReadStep)
  }

  const mutationInput: ProofStepInput = op === 'delete'
    ? { ...input.probeMutation, expectedStatus: input.probeMutation.expectedStatus ?? [200, 201, 204, 401, 403, 409, 422] }
    : input.probeMutation
  const mutation = compileStep(mutationInput, {
    tool: 'prove_state_mutation_diff', role: 'probe', id: 'probe_mutate', origin: input.origin,
    description: 'Probe mutation of the target field', usedIds,
  })
  steps.push(mutation)

  const afterInput: ProofStepInput = op === 'delete'
    ? { ...input.afterRead, expectedStatus: input.afterRead.expectedStatus ?? [200, 204, 404] }
    : input.afterRead
  const after = compileStep(afterInput, {
    tool: 'prove_state_mutation_diff', role: 'control', id: 'after_read', origin: input.origin,
    description: 'Read the field after the probe mutation', usedIds,
  })
  steps.push(after)

  const fieldPath = input.changedFieldPath
  const beforeField = jqJson(beforeReadStep.id, fieldPath)
  const afterField = jqJson(after.id, fieldPath)
  const relation = stateRelationJq(op, beforeField, afterField)

  const controlUnchanged = controlAfterStep
    ? ` and (((${jqJson(controlAfterStep.id, fieldPath)} | tostring) == (${beforeField} | tostring)))`
    : ''
  const assertionsJq = `{
  controlPassed: (${jqSuccess(beforeReadStep.id)} and ${jqPresent(beforeField)}${controlUnchanged}),
  confirmed: (${jqSuccess(mutation.id)} and ${jqSuccess(after.id)} and ${relation}),
  observed: (${jqObserved('before=', beforeField)} + " " + ${jqObserved('after=', afterField)} + " mutation-status=" + (${jqStatus(mutation.id)} | tostring)),
  expected: "the mutation is rejected for the probe actor and ${fieldPath} stays at the control value"
}`

  const spec = assembleSpec(input, stateDefaults, assertionsJq, true, steps)
  return {
    spec,
    assertionsJq,
    spaCatchallControl: true,
    rationale: `Before/after reads of ${fieldPath} bracket a probe ${mutation.request.method} mutation. Confirmation requires the persisted field to satisfy "${op}" relative to the pre-mutation value; a 2xx without a state delta is not accepted.`,
    warnings,
  }
}

// ---------------------------------------------------------------------------
// 3. Business invariant
// ---------------------------------------------------------------------------

const invariantDefaults: ToolDefaults = {
  title: 'Business invariant bypass',
  category: 'business-logic-race',
  cwe: 'CWE-840',
  severity: 'high',
  severityRationale: 'The probe flow drives a numeric or state field outside the invariant that the control flow preserves.',
  impact: 'An attacker can move a balance, quota, counter or workflow state outside its allowed range.',
  remediation: 'Enforce the invariant server-side in the same transaction as the mutation, not only in the client flow.',
  recheckInstructions: 'Replay the control flow and the probe flow, then read the same field; the probe readback must violate the invariant while the control stays inside it.',
}

function invariantOpSymbol(op: BusinessInvariantOp): string {
  switch (op) {
    case 'lt': return '<'
    case 'lte': return '<='
    case 'gt': return '>'
    case 'gte': return '>='
    case 'eq': return '=='
    case 'neq': return '!='
  }
}

function baselineJq(baselineRef: string | number, op: BusinessInvariantOp, stepIds: readonly string[]): { expression: string; numeric: boolean } {
  const numeric = op !== 'eq' && op !== 'neq'
  if (typeof baselineRef === 'number') return { expression: String(baselineRef), numeric }
  const text = baselineRef.trim()
  const placeholder = markerPlaceholder(text)
  if (placeholder) return { expression: `.extractedVars.${placeholder}`, numeric }
  const ref = /^([a-z0-9_-]{1,32})\.(.+)$/.exec(text)
  if (ref && stepIds.includes(ref[1]!)) return { expression: jqJson(ref[1]!, ref[2]!), numeric }
  return { expression: jqString(text), numeric }
}

function invariantCompare(fieldExpression: string, baseline: { expression: string; numeric: boolean }, op: BusinessInvariantOp): string {
  if (baseline.numeric) {
    return `(try (((${fieldExpression}) | tonumber) ${invariantOpSymbol(op)} ((${baseline.expression}) | tonumber)) catch false)`
  }
  return `(((${fieldExpression}) | tostring) ${invariantOpSymbol(op)} ((${baseline.expression}) | tostring))`
}

export function proveBusinessInvariant(input: BusinessInvariantInput): CompiledProof {
  const warnings = ensureValid('prove_business_invariant', input)
  const usedIds = new Set<string>()
  const steps: ReplayStep[] = []

  for (const [index, setup] of (input.setupSteps ?? []).entries()) {
    steps.push(compileStep(setup, {
      tool: 'prove_business_invariant', role: 'setup', id: `setup_${index + 1}`, origin: input.origin,
      description: 'Prepare the invariant state', usedIds,
    }))
  }

  for (const [index, step] of flowSteps(input.controlFlow).entries()) {
    steps.push(compileStep(step, {
      tool: 'prove_business_invariant', role: 'control', id: `control_flow_${index + 1}`, origin: input.origin,
      description: 'Control flow stays within the invariant', usedIds,
    }))
  }
  const controlReadback = compileStep(input.controlReadback ?? { ...input.readback, id: undefined }, {
    tool: 'prove_business_invariant', role: 'control', id: 'control_readback', origin: input.origin,
    description: 'Read the invariant field after the control flow', usedIds,
  })
  steps.push(controlReadback)

  for (const [index, step] of flowSteps(input.probeFlow).entries()) {
    steps.push(compileStep(step, {
      tool: 'prove_business_invariant', role: 'probe', id: `probe_flow_${index + 1}`, origin: input.origin,
      description: 'Probe flow attempts to violate the invariant', usedIds,
    }))
  }
  const probeReadback = compileStep(input.readback, {
    tool: 'prove_business_invariant', role: 'probe', id: 'probe_readback', origin: input.origin,
    description: 'Read the invariant field after the probe flow', usedIds,
  })
  steps.push(probeReadback)

  const controlField = jqJson(controlReadback.id, input.fieldPath)
  const probeField = jqJson(probeReadback.id, input.fieldPath)
  const baseline = baselineJq(input.baselineRef, input.op, steps.map(step => step.id))
  const controlWithin = invariantCompare(controlField, baseline, input.op)
  const probeWithin = invariantCompare(probeField, baseline, input.op)

  const assertionsJq = `{
  controlPassed: (${jqSuccess(controlReadback.id)} and ${jqPresent(controlField)} and ${controlWithin}),
  confirmed: (${jqSuccess(probeReadback.id)} and ${jqPresent(probeField)} and ((${probeWithin}) | not)),
  observed: (${jqObserved('control=', controlField)} + " " + ${jqObserved('probe=', probeField)}),
  expected: "the control readback satisfies ${input.fieldPath} ${invariantOpSymbol(input.op)} baseline and the probe readback violates it"
}`

  const spec = assembleSpec(input, invariantDefaults, assertionsJq, true, steps)
  return {
    spec,
    assertionsJq,
    spaCatchallControl: true,
    rationale: `Control flow and probe flow are followed by the same ${input.fieldPath} readback. Confirmation requires the control readback to satisfy "${input.fieldPath} ${input.op} baseline" and the probe readback to violate it.`,
    warnings,
  }
}

// ---------------------------------------------------------------------------
// 4. Canary / marker propagation or external redirect
// ---------------------------------------------------------------------------

function surfaceDefaults(surfaceKind: ProofSurfaceKind): ToolDefaults {
  switch (surfaceKind) {
    case 'ssrf':
      return {
        title: 'Server-side request to an attacker-controlled destination',
        category: 'ssrf-redirects',
        cwe: 'CWE-918',
        severity: 'high',
        severityRationale: 'A planted destination is fetched by the server, proving server-side request forgery.',
        impact: 'The server can be induced to reach attacker-controlled or internal destinations.',
        remediation: 'Allowlist outbound destinations and resolve/validate the final host before connecting.',
        recheckInstructions: 'Replant the canary and trigger the fetch; the canary must no longer receive the request.',
      }
    case 'xxe':
      return {
        title: 'XML external entity expansion reaches an attacker destination',
        category: 'injection-input',
        cwe: 'CWE-611',
        severity: 'high',
        severityRationale: 'A planted external entity is expanded and reaches the attacker-controlled canary.',
        impact: 'The parser resolves attacker-controlled external entities, enabling file or network access.',
        remediation: 'Disable external entity and DTD resolution in the XML parser.',
        recheckInstructions: 'Replant the external entity and trigger parsing; the canary must not be contacted.',
      }
    case 'stored_xss':
      return {
        title: 'Stored markup is replayed to a later viewer',
        category: 'injection-input',
        cwe: 'CWE-79',
        severity: 'high',
        severityRationale: 'A marker planted through one actor is returned unsanitised to a later read.',
        impact: 'Attacker-controlled markup executes in another user\'s browser session.',
        remediation: 'Encode stored values on output and sanitise markup at the trust boundary.',
        recheckInstructions: 'Replant the marker and re-read the surface; the marker must be encoded or absent.',
      }
    case 'open_redirect':
      return {
        title: 'Open redirect to an external destination',
        category: 'ssrf-redirects',
        cwe: 'CWE-601',
        severity: 'medium',
        severityRationale: 'A benign request stays local while a marker-bearing request redirects to an external host.',
        impact: 'The application can be used as a trusted redirector for phishing or token leakage.',
        remediation: 'Resolve redirect targets against an allowlist and reject off-origin destinations.',
        recheckInstructions: 'Replay the benign and marker-bearing requests; the marker must no longer appear in Location.',
      }
  }
}

function redirectHost(origin: string): string {
  try {
    return new URL(origin).host.toLowerCase()
  } catch {
    return origin.toLowerCase()
  }
}

export function proveCanaryOrRedirect(input: CanaryOrRedirectInput): CompiledProof {
  const warnings = ensureValid('prove_canary_or_redirect', input)
  const usedIds = new Set<string>()
  const steps: ReplayStep[] = []
  const surface = input.surfaceKind
  const marker = input.canaryIdOrMarker
  const placeholder = markerPlaceholder(marker)

  const redirect = surface === 'open_redirect'
  const controlSource = redirect ? input.plantStep : { ...input.triggerStep, id: undefined }
  const controlStep = compileStep(controlSource, {
    tool: 'prove_canary_or_redirect', role: 'control', id: 'control', origin: input.origin,
    description: redirect ? 'Benign redirect baseline' : 'Baseline read before the marker is planted',
    usedIds,
  })
  steps.push(controlStep)

  if (!redirect) {
    steps.push(compileStep(input.plantStep, {
      tool: 'prove_canary_or_redirect', role: 'setup', id: 'plant', origin: input.origin,
      description: 'Plant the canary or marker', usedIds,
    }))
  }
  const probeStep = compileStep(input.triggerStep, {
    tool: 'prove_canary_or_redirect', role: 'probe', id: 'probe', origin: input.origin,
    description: redirect ? 'Marker-bearing redirect request' : 'Trigger the vulnerable sink', usedIds,
  })
  steps.push(probeStep)

  let assertionsJq: string
  if (redirect) {
    const host = redirectHost(input.origin)
    const controlLocation = `.steps.${controlStep.id}.headers.location`
    const probeLocation = `.steps.${probeStep.id}.headers.location`
    assertionsJq = `{
  controlPassed: (((${jqStatus(controlStep.id)} >= 200) and (${jqStatus(controlStep.id)} < 400)) and (((((${controlLocation}) // "") | tostring) | contains(${jqString(marker)})) | not)),
  confirmed: (((${jqStatus(probeStep.id)} >= 300) and (${jqStatus(probeStep.id)} < 400)) and (((((${probeLocation}) // "") | tostring) | contains(${jqString(marker)}))) and (((((${probeLocation}) // "") | tostring) | contains(${jqString(host)})) | not)),
  observed: ("status=" + (${jqStatus(probeStep.id)} | tostring) + " location=" + ((((${probeLocation}) // "") | tostring))),
  expected: "Location stays on ${host} and never contains the external marker"
}`
  } else if (placeholder) {
    assertionsJq = `{
  controlPassed: (${jqSuccess(controlStep.id)} and (.canary.controlTriggered == false)),
  confirmed: ((.canary.triggered == true) and (.canary.probeTriggered == true)),
  observed: ("probe-triggered=" + ((.canary.probeTriggered // false) | tostring) + " control-triggered=" + ((.canary.controlTriggered // false) | tostring)),
  expected: "the verifier canary fires only for the probe arm"
}`
  } else {
    const controlBody = jqBody(controlStep.id)
    const probeBody = jqBody(probeStep.id)
    assertionsJq = `{
  controlPassed: (${jqSuccess(controlStep.id)} and (((${controlBody}) | contains(${jqString(marker)})) | not)),
  confirmed: (${jqSuccess(probeStep.id)} and ((${probeBody}) | contains(${jqString(marker)}))),
  observed: ("probe-status=" + (${jqStatus(probeStep.id)} | tostring) + " marker-present=" + ((((${probeBody}) | contains(${jqString(marker)})) | tostring))),
  expected: "the marker is absent from the baseline and present only after the planted ${surface} trigger"
}`
  }

  const spaCatchallControl = surface === 'stored_xss'
  const spec = assembleSpec(input, surfaceDefaults(surface), assertionsJq, spaCatchallControl, steps)
  const sink = redirect ? 'the Location header' : `the ${surface} sink body`
  return {
    spec,
    assertionsJq,
    spaCatchallControl,
    rationale: `A control arm establishes the pre-plant/local baseline and the probe arm triggers ${sink}. Confirmation binds ${placeholder ? `the verifier-minted canary ${marker}` : `the planted marker ${JSON.stringify(marker)}`} to that sink; a status-only 2xx is never sufficient.`,
    warnings,
  }
}

// ---------------------------------------------------------------------------
// LLM tool descriptions
// ---------------------------------------------------------------------------

export interface ProofToolPropertySchema {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object'
  description: string
  enum?: readonly string[]
  items?: ProofToolPropertySchema
}

export interface ProofToolDescription {
  name: ProofToolName
  usage: string
  inputSchema: {
    type: 'object'
    required: readonly string[]
    properties: Record<string, ProofToolPropertySchema>
  }
}

const stepProperty: ProofToolPropertySchema = {
  type: 'object',
  description: 'Replay step: { id?, method?, pathAndQuery, persona?, session?, headers?, jsonBody?, textBody?, csrfBind?, expectedStatus?, followRedirects?, extract? }.',
}

const stepArrayProperty: ProofToolPropertySchema = {
  type: 'array',
  description: 'Ordered prerequisite steps executed before the differential.',
  items: stepProperty,
}

const commonProperties: Record<string, ProofToolPropertySchema> = {
  origin: { type: 'string', description: 'Approved asset origin, e.g. https://app.example.' },
  title: { type: 'string', description: 'Optional finding title override.' },
  category: { type: 'string', description: 'Optional OWASP category override.' },
  cwe: { type: 'string', description: 'Optional CWE override, e.g. CWE-639.' },
  severity: { type: 'string', description: 'Optional severity override.' },
}

/**
 * Compact, deterministic tool list for the agentic system prompt. Each compiler takes a typed proof
 * description and emits a replay spec with an identifier-bound jq assertion; the model never writes
 * raw spec JSON or jq.
 */
export function describeProofTools(): ProofToolDescription[] {
  return [
    {
      name: 'prove_authz_read_diff',
      usage: 'Compile a cross-actor read differential; the attacker read must echo the victim identifier, not just return 2xx.',
      inputSchema: {
        type: 'object',
        required: ['origin', 'ownerPersona', 'attackerPersona', 'endpoint', 'resourceId', 'identifierPath'],
        properties: {
          ...commonProperties,
          ownerPersona: { type: 'string', description: 'Persona that owns the resource.' },
          attackerPersona: { type: 'string', description: 'Different persona that should be denied.' },
          endpoint: { type: 'string', description: 'Resource path containing {resourceId} (or the literal id).' },
          method: { type: 'string', description: 'Read method, default GET.', enum: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'] },
          resourceId: { type: 'string', description: 'Concrete victim resource identifier observed on the wire.' },
          identifierPath: { type: 'string', description: 'Response JSON field that echoes the identifier, e.g. id or data.order_id.' },
        },
      },
    },
    {
      name: 'prove_state_mutation_diff',
      usage: 'Compile a before/after state delta proof for BFLA, CSRF, mass assignment, write-BOLA or workflow skip.',
      inputSchema: {
        type: 'object',
        required: ['origin', 'beforeRead', 'probeMutation', 'afterRead', 'changedFieldPath'],
        properties: {
          ...commonProperties,
          setupSteps: stepArrayProperty,
          beforeRead: stepProperty,
          probeMutation: stepProperty,
          afterRead: stepProperty,
          changedFieldPath: { type: 'string', description: 'Persisted JSON field that must change, e.g. role or subscription.plan.' },
          op: { type: 'string', description: 'Mutation semantics; default changed (after != before).', enum: [...STATE_OPS] },
          controlMutation: stepProperty,
          controlAfterRead: stepProperty,
        },
      },
    },
    {
      name: 'prove_business_invariant',
      usage: 'Compile a control-vs-probe invariant proof; the readback field must stay within the baseline for control and violate it for probe.',
      inputSchema: {
        type: 'object',
        required: ['origin', 'controlFlow', 'probeFlow', 'readback', 'fieldPath', 'op', 'baselineRef'],
        properties: {
          ...commonProperties,
          setupSteps: stepArrayProperty,
          controlFlow: { ...stepProperty, description: 'A step or ordered array of steps that keeps the invariant.' },
          probeFlow: { ...stepProperty, description: 'A step or ordered array of steps that attempts to violate the invariant.' },
          readback: stepProperty,
          controlReadback: stepProperty,
          fieldPath: { type: 'string', description: 'Numeric or state field read after each flow, e.g. balance.' },
          op: { type: 'string', description: 'Invariant direction the control must satisfy.', enum: [...INVARIANT_OPS] },
          baselineRef: { type: 'string', description: 'Numeric literal, {{extractedVar}}, or stepId.field.path.' },
        },
      },
    },
    {
      name: 'prove_canary_or_redirect',
      usage: 'Compile marker/canary propagation for SSRF, XXE or stored XSS, or an external Location assertion for open redirect.',
      inputSchema: {
        type: 'object',
        required: ['origin', 'plantStep', 'triggerStep', 'canaryIdOrMarker', 'surfaceKind'],
        properties: {
          ...commonProperties,
          plantStep: stepProperty,
          triggerStep: stepProperty,
          canaryIdOrMarker: { type: 'string', description: 'Planted marker, external host, or an approved {{canary_*}} placeholder.' },
          surfaceKind: { type: 'string', description: 'Vulnerable sink family.', enum: [...SURFACES] },
        },
      },
    },
  ]
}
