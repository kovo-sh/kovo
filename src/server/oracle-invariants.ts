/**
 * Semantic impact validators shared by every verification path.
 *
 * A differential probe can show that two arms *differ*; it cannot tell whether the difference is a
 * security impact or in-policy behaviour. These pure validators encode the authorization/impact
 * model once so the declarative replay path (`replay-verifier.ts`) and the transcript oracle
 * (`verify-rpc.ts`) reach the same verdict on the same evidence:
 *
 *  - vertical BFLA needs a role/tenant differential, not just a 2xx mutation;
 *  - roles are ordered owner > admin > member > viewer, scoped to a tenant;
 *  - a denied control is boundary evidence, never a spec error;
 *  - mass assignment needs a protected field persisted from the request body and read back by a
 *    clean control arm (a status + `ok:true` echo, or a catalog-authoritative price, is not impact);
 *  - CSRF needs an ambient cookie without SameSite=Strict plus a persisted state change and the
 *    route's `csrf_state_change` oracle;
 *  - a read disclosure needs an owner-scoped non-public attribute that the probe actor does not own.
 *
 * Defensive QA framing: everything here is a *falsifier* for over-claims. It never invents impact.
 */

export type ImpactClass = 'authorization' | 'bfla' | 'mass_assignment' | 'csrf' | 'other'
/** Orthogonal boundary class: what kind of gate must be demonstrated for a claim. */
export type BoundaryClass = 'auth' | 'mfa' | 'access' | 'other'
export type RoleName = 'viewer' | 'member' | 'admin' | 'owner'
export type AmbientAuth = 'cookie' | 'bearer' | 'header' | 'unknown'

/** Tenant-scoped role hierarchy. Keep this the single source of truth. */
export const ROLE_RANK: Readonly<Record<RoleName, number>> = { viewer: 0, member: 1, admin: 2, owner: 3 }
export const ROLE_NAMES: readonly RoleName[] = ['viewer', 'member', 'admin', 'owner']

const ROLE_WORD_RE = /\b(owner|admin(?:istrator)?|member|viewer|guest|user|editor)\b/i
const ROLE_ALIASES: Readonly<Record<string, RoleName>> = {
  owner: 'owner',
  admin: 'admin',
  administrator: 'admin',
  member: 'member',
  viewer: 'viewer',
  guest: 'viewer',
  user: 'member',
  editor: 'member',
}

export function normalizeRole(value: string | null | undefined): RoleName | null {
  if (!value) return null
  const word = ROLE_WORD_RE.exec(value)?.[1]?.toLowerCase()
  return word ? ROLE_ALIASES[word] ?? null : null
}

export function roleRank(role: string | null | undefined): number | null {
  const normalized = normalizeRole(role)
  return normalized === null ? null : ROLE_RANK[normalized]
}

/**
 * Persona labels carry the app role and tenant, e.g. `owner (acme)`, `viewer (acme)` or a bare
 * `admin`. The verifier never guesses a role from a path it has not seen a role label for.
 */
export function parseRoleLabel(label: string | null | undefined): { role: RoleName | null; tenant: string | null } {
  if (!label) return { role: null, tenant: null }
  const role = normalizeRole(label)
  const parenthetical = /\(([^)]{1,64})\)/.exec(label)?.[1]?.trim().toLowerCase() ?? null
  const tenant = parenthetical || (/^[a-z0-9_.:-]{1,64}$/i.test(label.trim()) && role === null ? label.trim().toLowerCase() : null)
  return { role, tenant }
}

export interface PersonaCredentialSource {
  handle: string
  roleLabel?: string | null
  authKind?: string | null
  headerType?: string | null
  cookies?: ReadonlyArray<{ name?: string | null; sameSite?: string | null }>
}

export interface ActorIdentity {
  handle: string | null
  role: RoleName | null
  tenant: string | null
  auth: AmbientAuth
  sameSite: string | null
}

const EMPTY_ACTOR: ActorIdentity = { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }

function ambientAuthOf(source: PersonaCredentialSource): AmbientAuth {
  const headerType = (source.headerType ?? '').toLowerCase()
  if (headerType === 'cookie' || headerType === 'bearer' || headerType === 'header') return headerType
  const kind = (source.authKind ?? '').toLowerCase()
  if (kind === 'cookie' || kind === 'login') return 'cookie'
  if (kind === 'bearer' || kind === 'jwt' || kind === 'token') return 'bearer'
  if (kind === 'header' || kind === 'api_key' || kind === 'apikey') return 'header'
  return 'unknown'
}

export function actorFromPersona(
  handle: string | null | undefined,
  personas: readonly PersonaCredentialSource[],
  declared?: { roles?: Record<string, string> | null; tenants?: Record<string, string> | null },
): ActorIdentity {
  if (!handle) return { ...EMPTY_ACTOR }
  const source = personas.find(persona => persona.handle === handle)
  const parsed = parseRoleLabel(source?.roleLabel ?? null)
  const role = normalizeRole(declared?.roles?.[handle] ?? null) ?? parsed.role ?? normalizeRole(handle)
  const tenant = declared?.tenants?.[handle]?.toLowerCase() ?? parsed.tenant
  const sameSite = source?.cookies?.find(cookie => cookie.sameSite)?.sameSite ?? null
  return {
    handle,
    role,
    tenant,
    auth: source ? ambientAuthOf(source) : 'unknown',
    sameSite,
  }
}

export interface ImpactStep {
  id: string
  /** Chain arm from the spec/claim (`control`, `probe`, `setup`, `cleanup`). */
  arm: 'control' | 'probe' | 'setup' | 'cleanup'
  method: string
  route?: string
  /** Exact request target, used for a parameter/body precondition differential. */
  pathAndQuery?: string
  status: number | null
  actor: ActorIdentity
  json?: unknown
  body?: string
  /** Request body actually sent by the probe (used to distinguish injected fields from echoes). */
  requestJson?: unknown
  requestHeaders?: Record<string, string> | null
  responseHeaders?: Record<string, string> | null
}

export interface ImpactInput {
  impactClass: ImpactClass
  steps: readonly ImpactStep[]
  requiredRole?: string | null
  resourceTenant?: string | null
  expectControlDenied?: boolean
  oracleEvents?: readonly string[]
  catalogPrices?: readonly number[]
  targetOrigin?: string | null
}

export interface ImpactAssessment {
  required: boolean
  satisfied: boolean
  reason: string
  evidence?: Record<string, unknown>
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export function isMutatingMethod(method: string | null | undefined): boolean {
  return MUTATING_METHODS.has((method ?? '').toUpperCase())
}

export function isReadMethod(method: string | null | undefined): boolean {
  return READ_METHODS.has((method ?? '').toUpperCase())
}

/**
 * A POST that carries only a read-only GraphQL *query* does not mutate the target. GraphQL clients
 * send queries over POST, so the verb alone cannot classify the exchange as state-changing; doing so
 * would demand a persisted readback that a read can never produce. Only an explicit `query`
 * operation (or the shorthand selection-set form `{ ... }`) counts, and an opaque/absent body is
 * never assumed read-only. Documents containing `mutation`/`subscription` stay mutating.
 */
export function isReadOnlyGraphqlRequest(step: Pick<ImpactStep, 'method' | 'requestJson'>): boolean {
  if ((step.method ?? '').toUpperCase() !== 'POST') return false
  const body = step.requestJson
  if (!body || typeof body !== 'object' || Array.isArray(body)) return false
  const query = (body as { query?: unknown }).query
  if (typeof query !== 'string') return false
  const text = query.trim()
  if (text.length === 0 || text.length > 16_384) return false
  if (!/^(?:query\b|\{)/.test(text)) return false
  return !/\b(?:mutation|subscription)\b/.test(text)
}

/** True when this step changes target state (method mutates and it is not a read-only GraphQL query). */
export function stepMutatesState(step: Pick<ImpactStep, 'method' | 'requestJson'>): boolean {
  return isMutatingMethod(step.method) && !isReadOnlyGraphqlRequest(step)
}

/** True when this step reads target state (an explicit read verb or a read-only GraphQL query). */
export function stepReadsState(step: Pick<ImpactStep, 'method' | 'requestJson'>): boolean {
  return isReadMethod(step.method) || isReadOnlyGraphqlRequest(step)
}

function isSuccess(status: number | null): boolean {
  return status !== null && status >= 200 && status < 300
}

function isDenied(status: number | null): boolean {
  return status === 401 || status === 403 || status === 404
}

function sameRoute(a: ImpactStep, b: ImpactStep): boolean {
  return (a.route ?? '') !== '' && a.route === b.route
}

// ---------------------------------------------------------------------------
// Impact classification (title / category / CWE descriptors only)
// ---------------------------------------------------------------------------

const CSRF_RE = /\bcsrf\b|cross[- ]site\s+request\s+forgery|CWE-352/i
const MASS_ASSIGN_RE = /mass[- ]?assign|over[- ]?post|CWE-915/i
const AUTHZ_RE = /\b(?:bola|bfla|idor|broken[- ]access[- ]control|access[- ]control|authori[sz]ation|privilege[- ]escalation|privilege[- ]escalation|tenant[- ]isolation|vertical[- ]access|cross[- ]tenant)\b/i
const AUTHZ_CWE_RE = /^CWE-(?:269|284|285|362|566|639|862|863|1021|1220)$/i

/** Classify a claim once, from machine-readable descriptors (never from a request path guess). */
export function classifyImpactDescriptor(parts: {
  cwe?: string | null
  category?: string | null
  title?: string | null
  impact?: string | null
}): ImpactClass {
  const text = `${parts.title ?? ''} ${parts.impact ?? ''}`
  if (CSRF_RE.test(text) || parts.cwe === 'CWE-352') return 'csrf'
  if (MASS_ASSIGN_RE.test(text) || parts.cwe === 'CWE-915') return 'mass_assignment'
  if (/\b(?:vertical|bfla|function[- ]level|privilege[- ]escalation)\b/i.test(text) ||
      /^CWE-(?:269|285|862|863)$/i.test(parts.cwe ?? '')) return 'bfla'
  if (AUTHZ_CWE_RE.test(parts.cwe ?? '') || AUTHZ_RE.test(parts.category ?? '') || AUTHZ_RE.test(text)) return 'authorization'
  return 'other'
}

// ---------------------------------------------------------------------------
// Field-level persistence
// ---------------------------------------------------------------------------

const PROTECTED_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:tenant(?:_?id)?|owner(?:_?id)?|role|roles|permissions?|privileges?|is_?admin|admin|is_?owner|price(?:_?cents)?|amount(?:_?cents)?|seat_?limit|seat_?count|seats?|seats_used|credits?|balance|plan(?:_?id)?|tier|visibility|private|shared|secret|api_?key|access_?token|email|password|hash)$/i
const PRICE_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:price(?:_?cents)?|amount(?:_?cents)?|cost(?:_?cents)?)$/i
const IDENTITY_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:owner(?:_?id)?|tenant(?:_?id)?|user(?:_?id)?|email|username|subject|created_?by|author)$/i
const SECRET_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:secret|api_?key|access_?token|token|password|hash|private_?note|note|internal|ssn)$/i

export function isProtectedField(path: string): boolean {
  const leaf = path.split('.').pop()?.toLowerCase() ?? ''
  return PROTECTED_FIELD_RE.test(leaf)
}

export function isPriceField(path: string): boolean {
  const leaf = path.split('.').pop()?.toLowerCase() ?? ''
  return PRICE_FIELD_RE.test(leaf)
}

/** Flatten a JSON object into `path -> primitive string` pairs (bounded; no arrays of objects). */
export function flattenJson(value: unknown, prefix = '', depth = 0, out = new Map<string, string>()): Map<string, string> {
  if (out.size >= 256 || depth > 6) return out
  if (value === null || value === undefined) return out
  if (Array.isArray(value)) {
    for (let i = 0; i < Math.min(value.length, 16); i += 1) flattenJson(value[i], `${prefix}[${i}]`, depth + 1, out)
    return out
  }
  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      flattenJson(child, prefix ? `${prefix}.${key}` : key, depth + 1, out)
    }
    return out
  }
  out.set(prefix, String(value))
  return out
}

export interface StateDelta {
  changed: string[]
  added: string[]
  removed: string[]
  /** True when the after-read failed/deleted, i.e. the resource disappeared. */
  deleted: boolean
}

export function stateDelta(before: unknown, after: unknown, afterStatus?: number | null): StateDelta {
  const beforeFields = before === undefined ? null : flattenJson(before)
  const afterFields = after === undefined ? null : flattenJson(after)
  const deleted = afterFields === null && (afterStatus === 404 || afterStatus === 204 || afterStatus === 410)
  const changed: string[] = []
  const added: string[] = []
  const removed: string[] = []
  if (beforeFields && afterFields) {
    for (const [path, value] of afterFields) {
      if (!beforeFields.has(path)) added.push(path)
      else if (beforeFields.get(path) !== value) changed.push(path)
    }
    for (const path of beforeFields.keys()) {
      if (!afterFields.has(path)) removed.push(path)
    }
  }
  return { changed, added, removed, deleted }
}

function collectNumericFieldValues(value: unknown, predicate: (path: string) => boolean, out: Set<number>, prefix = '', depth = 0): void {
  if (out.size >= 24 || depth > 5) return
  if (Array.isArray(value)) {
    for (const child of value.slice(0, 32)) collectNumericFieldValues(child, predicate, out, prefix, depth + 1)
    return
  }
  if (!value || typeof value !== 'object') return
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const path = prefix ? `${prefix}.${key}` : key
    collectNumericFieldValues(child, predicate, out, path, depth + 1)
    if (typeof child === 'number' && Number.isFinite(child) && predicate(path)) out.add(child)
  }
}

/** Catalog prices observed in a control read (a plan catalog / billing list), used to reject echoes. */
export function collectCatalogPrices(steps: readonly ImpactStep[]): number[] {
  const prices = new Set<number>()
  for (const step of steps) {
    if (step.arm === 'probe' || step.json === undefined || step.json === null) continue
    collectNumericFieldValues(step.json, path => isPriceField(path), prices)
  }
  return [...prices]
}

// ---------------------------------------------------------------------------
// Readback / persistence discovery
// ---------------------------------------------------------------------------

function step_isCleanRead(after: ImpactStep, probe: ImpactStep): boolean {
  return isReadMethod(after.method) && after.id !== probe.id && (after.arm === 'control' || after.actor.handle !== probe.actor.handle)
}

interface PersistenceProof {
  persisted: boolean
  reason: string
  before: ImpactStep | null
  after: ImpactStep | null
  delta: StateDelta | null
  clean: boolean
  controlDelta: StateDelta | null
}

function findPersistence(steps: readonly ImpactStep[], probe: ImpactStep): PersistenceProof {
  const reads = steps.filter(step => isReadMethod(step.method) && step.json !== undefined && step.json !== null)
  const before = [...reads].reverse().find(step => step.status !== null && isSuccess(step.status) && steps.indexOf(step) < steps.indexOf(probe)) ?? null
  // The readback must be a *separate GET* after the mutation (never the mutation response echo).
  // A different actor is preferred, but a same-actor self-service read is still a clean GET: the
  // mutation response itself is excluded because it is not a read method.
  const after = reads.find(step => steps.indexOf(step) > steps.indexOf(probe) &&
    (step.arm === 'control' || isSuccess(step.status) || step.status === 404 || step.status === 410)) ?? null
  const clean = Boolean(after && step_isCleanRead(after, probe))
  const delta = before && after ? stateDelta(before.json, after.json, after.status) : null
  // A control mutation must leave the field unchanged; if it changed, the delta is unattributable.
  const controlProbe = steps.find(step => step.arm === 'control' && isMutatingMethod(step.method) && isSuccess(step.status))
  let controlDelta: StateDelta | null = null
  let controlAfterJson: unknown
  if (controlProbe) {
    const controlBefore = [...reads].reverse().find(step => steps.indexOf(step) < steps.indexOf(controlProbe)) ?? null
    const controlAfter = reads.find(step => steps.indexOf(step) > steps.indexOf(controlProbe)) ?? null
    controlAfterJson = controlAfter?.json
    if (controlBefore && controlAfter) controlDelta = stateDelta(controlBefore.json, controlAfter.json, controlAfter.status)
  }
  if (!before) return { persisted: false, reason: 'no pre-mutation readback exists; a mutation response echo cannot prove persistence', before, after, delta, clean, controlDelta }
  if (!after) return { persisted: false, reason: 'no separate post-mutation GET readback exists; the mutation echo alone is not persistence', before, after, delta, clean, controlDelta }
  const changed = delta ? [...delta.changed, ...delta.added, ...delta.removed] : []
  if (delta?.deleted) return { persisted: true, reason: 'the readback resource was removed', before, after, delta, clean, controlDelta }
  if (changed.length === 0) return { persisted: false, reason: 'the post-mutation readback is identical to the baseline (idempotent no-op)', before, after, delta, clean, controlDelta }
  if (controlDelta && delta) {
    // A benign control mutation that lands the *same* value as the probe makes the delta
    // unattributable. A control that writes a different value (e.g. the CSRF control arm) is a
    // legitimate baseline, not a confounder.
    const probeAfter = after.json !== undefined && after.json !== null ? flattenJson(after.json) : new Map<string, string>()
    const controlAfterFields = controlAfterJson ? flattenJson(controlAfterJson) : new Map<string, string>()
    const conflicts = [...controlDelta.changed, ...controlDelta.added].some(path =>
      controlAfterFields.get(path) !== undefined && controlAfterFields.get(path) === probeAfter.get(path))
    if (conflicts) {
      return { persisted: false, reason: 'the control arm changed the same field to the same value, so the delta is not attributable to the probe', before, after, delta, clean, controlDelta }
    }
  }
  return { persisted: true, reason: `persisted field delta: ${changed.slice(0, 6).join(', ')}`, before, after, delta, clean, controlDelta }
}

function hasOracle(events: readonly string[] | undefined, kinds: readonly string[]): boolean {
  if (!events?.length) return false
  const wanted = new Set(kinds)
  return events.some(event => wanted.has(event))
}

// ---------------------------------------------------------------------------
// Authorization / BFLA
// ---------------------------------------------------------------------------

export interface AuthorizationAssessment extends ImpactAssessment {
  evidence: {
    probeRole?: RoleName | null
    requiredRole?: RoleName | null
    roleDifferential: boolean
    crossTenant: boolean
    boundaryControlDenied: boolean
    persisted: boolean
    changedFields: string[]
    disclosureFields: string[]
  }
}

function sameTenant(a: ActorIdentity, b: ActorIdentity): boolean {
  return Boolean(a.tenant && b.tenant && a.tenant === b.tenant)
}

export function assessAuthorizationImpact(input: ImpactInput): AuthorizationAssessment {
  const steps = input.steps
  const probes = steps.filter(step => step.arm === 'probe')
  const controls = steps.filter(step => step.arm === 'control')
  const probeSuccesses = probes.filter(step => isSuccess(step.status))
  const deniedControls = controls.filter(step => isDenied(step.status))
  // A boundary control is a *sibling* arm that was denied before the probe ran; a post-mutation
  // 404 readback is persistence evidence and must not be re-read as a boundary denial.
  const firstProbeIndex = probes.length ? steps.indexOf(probes[0]!) : -1
  const boundaryControlDenied = deniedControls.some(control =>
    (firstProbeIndex === -1 || steps.indexOf(control) < firstProbeIndex) &&
    probeSuccesses.some(probe => sameRoute(control, probe)))
  const requiredRole = normalizeRole(input.requiredRole)
  const requiredRank = roleRank(requiredRole)
  const mutatingProbe = probeSuccesses.find(step => stepMutatesState(step)) ?? null
  const probe = mutatingProbe ?? probeSuccesses.find(step => isReadMethod(step.method)) ?? probeSuccesses[0] ?? probes[0]

  const base = {
    probeRole: probe?.actor.role ?? null,
    requiredRole,
    roleDifferential: false,
    crossTenant: false,
    boundaryControlDenied,
    persisted: false,
    changedFields: [] as string[],
    disclosureFields: [] as string[],
  }
  if (!probe) {
    return { required: true, satisfied: false, reason: 'Authorization claim has no probe step to assess.', evidence: base }
  }
  const probeRank = roleRank(probe.actor.role)
  const resourceTenant = input.resourceTenant?.toLowerCase() ?? null
  // A successful same-route read by an actor in *another* tenant binds the resource to that tenant.
  const crossTenantControlRead = controls.some(control =>
    isReadMethod(control.method) &&
    isSuccess(control.status) &&
    control.json !== undefined &&
    Boolean(control.actor.tenant && probe.actor.tenant && control.actor.tenant !== probe.actor.tenant))
  const crossTenant = Boolean((resourceTenant && probe.actor.tenant && resourceTenant !== probe.actor.tenant) || crossTenantControlRead)
  const vertical = input.impactClass === 'bfla'

  let roleDifferential = false
  let escalationReason = ''
  if (requiredRank !== null && probeRank !== null) {
    roleDifferential = probeRank < requiredRank
    escalationReason = roleDifferential
      ? `probe role ${probe.actor.role} is below the required ${requiredRole}`
      : `probe role ${probe.actor.role} already satisfies the required ${requiredRole}`
  } else if (requiredRank === null) {
    // Infer the required role only from a same-tenant denied control (a cross-tenant denial is a
    // tenant boundary, not a role reference and must not be read as a vertical differential). When
    // neither arm carries tenant metadata, a strictly lower probe role is the only available reading.
    const sameTenantDenial = deniedControls.find(control => sameRoute(control, probe) &&
      (sameTenant(control.actor, probe.actor) || (!control.actor.tenant && !probe.actor.tenant)))
    const controlRank = sameTenantDenial ? roleRank(sameTenantDenial.actor.role) : null
    if (controlRank !== null && probeRank !== null) {
      roleDifferential = probeRank < controlRank
      escalationReason = roleDifferential
        ? `probe role ${probe.actor.role} is below the denied control role ${sameTenantDenial?.actor.role}`
        : `probe role ${probe.actor.role} is not below the control role ${sameTenantDenial?.actor.role}`
    }
  }
  base.roleDifferential = roleDifferential
  base.crossTenant = crossTenant

  if (mutatingProbe) {
    if (vertical && !roleDifferential && !crossTenant) {
      return {
        required: true,
        satisfied: false,
        reason: `Mutating probe ${mutatingProbe.id} succeeded, but there is no privilege/ownership differential: ${escalationReason || 'the actor is in the resource tenant and no required role is exceeded'}. A same-tenant content write by ${probe.actor.role ?? 'an authenticated actor'} is in policy.`,
        evidence: base,
      }
    }
    const persistence = findPersistence(steps, mutatingProbe)
    base.persisted = persistence.persisted
    base.changedFields = persistence.delta ? [...persistence.delta.changed, ...persistence.delta.added, ...persistence.delta.removed] : []
    if (!persistence.persisted) {
      return { required: true, satisfied: false, reason: `Mutating probe ${mutatingProbe.id} succeeded without persisted impact: ${persistence.reason}.`, evidence: base }
    }
    const protectedChanged = base.changedFields.filter(isProtectedField)
    // A cross-tenant write may persist any field; a same-tenant escalation must move a protected
    // field or carry the endpoint's declared impact event.
    const oracleDeclared = hasOracle(input.oracleEvents, ['privilege_escalation', 'mass_assignment', 'invariant_violation', 'cross_tenant_write', 'state_delta'])
    // A cross-tenant write may persist any field; a same-tenant escalation must move a protected
    // field or carry the endpoint's declared impact event.
    if (!crossTenant && protectedChanged.length === 0 && !oracleDeclared) {
      return { required: true, satisfied: false, reason: `The persisted change (${base.changedFields.slice(0, 6).join(', ') || 'none'}) is not a protected field and no impact-oracle event is declared; a state echo is not impact.`, evidence: base }
    }
    if (boundaryControlDenied && !oracleDeclared && !crossTenant) {
      return { required: true, satisfied: false, reason: 'The control arm was correctly denied and the probe mutated state, but no impact-oracle event is declared and the change is not cross-tenant; require the endpoint\'s impact event before confirming.', evidence: base }
    }
    return {
      required: true,
      satisfied: true,
      reason: `${vertical ? 'Vertical' : 'Object-level'} impact: ${escalationReason || (crossTenant ? 'cross-tenant resource access' : 'persisted protected-field change')}; ${persistence.reason}${protectedChanged.length ? `; protected fields: ${protectedChanged.slice(0, 6).join(', ')}` : ''}${oracleDeclared ? `; oracle ${input.oracleEvents!.join(',')}` : ''}.`,
      evidence: base,
    }
  }

  if (!probeSuccesses.length) {
    return { required: true, satisfied: false, reason: 'The probe actor was not served the resource, so no authorization differential exists.', evidence: base }
  }
  if (requiredRank !== null && probeRank !== null && !roleDifferential && !crossTenant) {
    return {
      required: true,
      satisfied: false,
      reason: `No vertical differential: the probe actor (${probe.actor.role}) already satisfies the declared required role (${requiredRole}); a read by a higher role is in policy.`,
      evidence: base,
    }
  }
  if (roleDifferential && boundaryControlDenied) {
    return {
      required: true,
      satisfied: true,
      reason: `Vertical read differential: ${escalationReason}; the sibling control on the same route was denied while the probe was served data.`,
      evidence: base,
    }
  }
  if (crossTenant) {
    return {
      required: true,
      satisfied: true,
      reason: `Cross-tenant read: the probe actor (tenant ${probe.actor.tenant ?? 'unknown'}) received a record served to a control actor in another tenant; the tenant boundary is the disclosure.`,
      evidence: base,
    }
  }
  const disclosure = assessReadDisclosure({ steps, probe })
  base.disclosureFields = disclosure.fields
  if (!disclosure.satisfied) {
    return { required: true, satisfied: false, reason: `Read-only proof lacks impact evidence: ${disclosure.reason}`, evidence: base }
  }
  return {
    required: true,
    satisfied: true,
    reason: `${escalationReason || (crossTenant ? 'cross-tenant read' : 'object-level read')}; ${disclosure.reason}`,
    evidence: base,
  }
}

export interface ReadDisclosureResult {
  satisfied: boolean
  fields: string[]
  reason: string
}

const OWNER_SCOPED_RE = /^(?:[a-z0-9]+[_-])*(?:owner(?:_?id)?|tenant(?:_?id)?|user(?:_?id)?|email|username|created_?by|author)$/i
const PRIVATE_DATA_RE = /^(?:[a-z0-9]+[_-])*(?:private(?:_?note)?|internal|secret|api_?key|access_?token|token|ssn|phone|address|note|text|body|content|message|title|email|subject|amount(?:_?cents)?|total|balance|credits?|number)$/i

/**
 * Response values are scrubbed before they leave the broker, so an identity that happened to equal
 * a credential becomes `[persona:<handle>:secret]`. The marker names the actor without exposing the
 * secret; treat it as that handle so field/identity binding survives redaction.
 */
function deRedactIdentity(value: string): string {
  return value.replace(/\[persona:([a-z0-9_.-]+):secret\]/gi, '$1').toLowerCase()
}

/**
 * A read only proves object-level disclosure when the probe response carries an owner-scoped,
 * non-public attribute that belongs to another actor (or is absent from the probe's own baseline).
 */
export function assessReadDisclosure(args: {
  steps: readonly ImpactStep[]
  probe: ImpactStep
}): ReadDisclosureResult {
  const { steps, probe } = args
  if (probe.json === undefined || typeof probe.json !== 'object' || probe.json === null) {
    return { satisfied: false, fields: [], reason: 'The probe response body is not a JSON record, so no object-scoped attribute can be bound to a victim.' }
  }
  const probeFields = flattenJson(probe.json)
  const controls = steps.filter(step => step.arm === 'control' && step.json !== undefined && step.json !== null)
  const probeBaseline = steps.find(step =>
    step !== probe &&
    isSuccess(step.status) &&
    step.actor.handle !== null &&
    step.actor.handle === probe.actor.handle &&
    step.json !== undefined)
  const baselineFields = probeBaseline?.json !== undefined ? flattenJson(probeBaseline.json) : null
  const probeIdentities = new Set(
    [probe.actor.handle, probe.actor.tenant, probe.actor.role].filter((value): value is string => Boolean(value)).map(value => value.toLowerCase()),
  )
  const controlIdentities = new Set<string>()
  for (const control of controls) {
    for (const value of [control.actor.handle, control.actor.tenant, control.actor.role]) {
      if (value) controlIdentities.add(value.toLowerCase())
    }
  }
  const matched: string[] = []
  for (const [path, rawValue] of probeFields) {
    const leaf = deRedactIdentity(path.split('.').pop() ?? '')
    const value = deRedactIdentity(rawValue.trim())
    if (!value || value === 'null' || value === 'undefined' || value === '0' || value === 'false' || value === 'true') continue
    if (probeIdentities.has(value)) continue
    if (OWNER_SCOPED_RE.test(leaf)) {
      const boundToControl = controlIdentities.has(value) ||
        controls.some(control => control.json != null && deRedactIdentity(flattenJson(control.json).get(path) ?? '') === value)
      const absentFromBaseline = baselineFields !== null && !baselineFields.has(path)
      const differsFromBaseline = baselineFields !== null && baselineFields.has(path) && deRedactIdentity(baselineFields.get(path) ?? '') !== value
      if (boundToControl || absentFromBaseline || differsFromBaseline) matched.push(path)
      continue
    }
    // Non-public payload (private note, secret material) with a substantive value is disclosure even
    // without a same-route control: it is not a public field the attacker could have read anyway.
    if (PRIVATE_DATA_RE.test(leaf) && value.length >= 4 && !/^\[?redacted/i.test(value)) matched.push(path)
  }
  if (matched.length === 0) {
    return {
      satisfied: false,
      fields: [],
      reason: 'The probe response exposes no owner-scoped, identifier-binding non-public attribute bound to another actor; a differing body without a victim-owned field is not object-level disclosure.',
    }
  }
  return {
    satisfied: true,
    fields: matched.slice(0, 8),
    reason: `Owner-scoped non-public field(s) disclosed: ${matched.slice(0, 6).join(', ')}.`,
  }
}

// ---------------------------------------------------------------------------
// Mass assignment
// ---------------------------------------------------------------------------

export interface MassAssignmentAssessment extends ImpactAssessment {
  evidence: { injected: string[]; persisted: string[]; protectedFields: string[]; catalogSuppressed: string[] }
}

export function assessMassAssignmentImpact(input: ImpactInput): MassAssignmentAssessment {
  const steps = input.steps
  const probes = steps.filter(step => step.arm === 'probe')
  const mutatingProbe = probes.find(step => isMutatingMethod(step.method) && isSuccess(step.status)) ?? null
  const empty = { injected: [] as string[], persisted: [] as string[], protectedFields: [] as string[], catalogSuppressed: [] as string[] }
  if (!mutatingProbe) {
    return { required: true, satisfied: false, reason: 'Mass-assignment claim has no successful mutating probe step.', evidence: empty }
  }
  if (mutatingProbe.requestJson === undefined) {
    return { required: true, satisfied: false, reason: 'Mass-assignment claim does not record the request body that carried the candidate fields.', evidence: empty }
  }
  const persistence = findPersistence(steps, mutatingProbe)
  if (!persistence.persisted || !persistence.delta) {
    return { required: true, satisfied: false, reason: `No persisted protected-field change was read back through a control arm: ${persistence.reason}. A 2xx plus an "ok:true" echo is insufficient.`, evidence: empty }
  }
  const bodyFields = flattenJson(mutatingProbe.requestJson)
  const afterFields = persistence.after?.json !== undefined ? flattenJson(persistence.after.json) : new Map<string, string>()
  const beforeFields = persistence.before?.json !== undefined ? flattenJson(persistence.before.json) : new Map<string, string>()
  const catalog = [...(input.catalogPrices ?? []), ...collectCatalogPrices(steps)]
  const injected: string[] = []
  const persisted: string[] = []
  const protectedFields: string[] = []
  const catalogSuppressed: string[] = []
  for (const [path, bodyValue] of bodyFields) {
    const afterValue = afterFields.get(path)
    if (afterValue === undefined) continue
    const beforeValue = beforeFields.get(path)
    if (beforeValue === afterValue) continue
    injected.push(path)
    if (afterValue !== bodyValue) {
      // The server wrote a different value than the caller supplied: not persisted from the body.
      continue
    }
    const numeric = Number(afterValue)
    if (isPriceField(path) && Number.isFinite(numeric) && catalog.includes(numeric)) {
      catalogSuppressed.push(path)
      continue
    }
    persisted.push(path)
    if (isProtectedField(path)) protectedFields.push(path)
  }
  const evidence = { injected, persisted, protectedFields, catalogSuppressed }
  if (persisted.length === 0) {
    // Create-shaped overposting: the created record is scoped to another actor/tenant, so the
    // caller's own readback cannot show it. The other actor reading the caller-supplied marker back
    // is persistence evidence for the protected field, provided the marker does not appear in a
    // control arm and a protected identity field was supplied.
    const requestFields = bodyFields
    const markerHits = [...requestFields.entries()]
      .filter(([path, value]) => !isProtectedField(path) && !isPriceField(path) && value.length >= 8 && !/^\d+$/.test(value))
    const scopedBodyFields = [...requestFields.keys()].filter(isProtectedField)
    const otherActorRead = steps.find(step =>
      isReadMethod(step.method) &&
      steps.indexOf(step) > steps.indexOf(mutatingProbe) &&
      step.actor.handle !== mutatingProbe.actor.handle &&
      typeof step.body === 'string' &&
      markerHits.some(([, value]) => step.body!.includes(value)))
    if (scopedBodyFields.length > 0 && otherActorRead) {
      return {
        required: true,
        satisfied: true,
        reason: `Create-time mass assignment: the caller-supplied protected field(s) ${scopedBodyFields.join(', ')} persisted into another actor's scope (${otherActorRead.actor.handle ?? 'other'}) with the probe marker, confirming tenant/owner mass assignment.`,
        evidence: { ...evidence, persisted: scopedBodyFields, protectedFields: scopedBodyFields },
      }
    }
    const why = catalogSuppressed.length
      ? `the only injected value(s) match the catalog price (${catalogSuppressed.join(', ')}); a catalog-authoritative price is not mass assignment`
      : 'no injected field was read back from the server; the response echo is not persistence'
    return { required: true, satisfied: false, reason: `Mass-assignment claim dismissed: ${why}.`, evidence }
  }
  const oracleDeclared = hasOracle(input.oracleEvents, ['mass_assignment', 'invariant_violation', 'privilege_escalation'])
  if (protectedFields.length === 0 && !oracleDeclared) {
    return {
      required: true,
      satisfied: false,
      reason: `Injected field(s) ${persisted.join(', ')} persisted but are not protected and no invariant/impact oracle event is declared.`,
      evidence,
    }
  }
  if (!oracleDeclared && protectedFields.length === 0) {
    return { required: true, satisfied: false, reason: 'Mass-assignment claim requires the endpoint\'s declared impact event or a persisted protected-field change.', evidence }
  }
  return {
    required: true,
    satisfied: true,
    reason: `Injected protected field(s) ${protectedFields.join(', ')} persisted and were read back by a clean control arm${oracleDeclared ? `; oracle ${input.oracleEvents!.join(',')}` : ''}.`,
    evidence,
  }
}

// ---------------------------------------------------------------------------
// CSRF
// ---------------------------------------------------------------------------

export interface CsrfAssessment extends ImpactAssessment {
  evidence: { ambient: AmbientAuth; sameSite: string | null; crossSite: boolean; persisted: boolean; oracleDeclared: boolean }
}

function headerValue(headers: Record<string, string> | null | undefined, name: string): string | null {
  if (!headers) return null
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) return value
  }
  return null
}

function originHost(value: string | null | undefined): string | null {
  if (!value) return null
  try { return new URL(value).host.toLowerCase() } catch { return null }
}

export function assessCsrfImpact(input: ImpactInput & { targetOrigin?: string | null }): CsrfAssessment {
  const steps = input.steps
  const probes = steps.filter(step => step.arm === 'probe')
  const mutatingProbe = probes.find(step => isMutatingMethod(step.method) && isSuccess(step.status)) ?? null
  const labels = {
    ambient: mutatingProbe?.actor.auth ?? 'unknown' as AmbientAuth,
    sameSite: mutatingProbe?.actor.sameSite ?? null,
    crossSite: false,
    persisted: false,
    oracleDeclared: hasOracle(input.oracleEvents, ['csrf_state_change']),
  }
  if (!mutatingProbe) {
    return { required: true, satisfied: false, reason: 'CSRF claim has no successful state-changing probe step.', evidence: labels }
  }
  const auth = mutatingProbe.actor.auth
  if (auth === 'bearer' || auth === 'header') {
    return { required: true, satisfied: false, reason: `CSRF claim dismissed: the probe authenticates with ${auth} credentials, which a cross-site form cannot attach (not CSRF-able).`, evidence: labels }
  }
  if (auth !== 'cookie') {
    return { required: true, satisfied: false, reason: 'CSRF claim dismissed: no ambient browser cookie is recorded for the probe actor, so the request is not browser-reachable as a CSRF.', evidence: labels }
  }
  const sameSite = (labels.sameSite ?? '').toLowerCase()
  if (sameSite === 'strict') {
    return { required: true, satisfied: false, reason: 'CSRF claim dismissed: the session cookie is SameSite=Strict, so a cross-site request cannot carry it.', evidence: labels }
  }
  if (sameSite === 'lax' && !isReadMethod(mutatingProbe.method)) {
    return { required: true, satisfied: false, reason: `CSRF claim dismissed: the session cookie is SameSite=Lax and ${mutatingProbe.method} is not a top-level GET/HEAD navigation, so the cookie is not attached.`, evidence: labels }
  }
  const originHeader = headerValue(mutatingProbe.requestHeaders, 'origin')
  const referer = headerValue(mutatingProbe.requestHeaders, 'referer')
  const targetHost = originHost(input.targetOrigin ?? null)
  const requestHost = originHost(originHeader ?? referer)
  const crossSite = Boolean(targetHost && requestHost && requestHost !== targetHost)
  labels.crossSite = crossSite
  if (!crossSite) {
    return { required: true, satisfied: false, reason: 'CSRF claim dismissed: the recorded request is same-origin (or carries no foreign Origin/Referer), so it is not a cross-site request.', evidence: labels }
  }
  if (!labels.oracleDeclared) {
    return { required: true, satisfied: false, reason: 'CSRF claim dismissed: the route does not carry a csrf_state_change impact oracle, so a token-less write on it has no modelled impact.', evidence: labels }
  }
  const persistence = findPersistence(steps, mutatingProbe)
  labels.persisted = persistence.persisted
  if (!persistence.persisted) {
    return { required: true, satisfied: false, reason: `CSRF claim accepted the request but no state change persisted: ${persistence.reason}.`, evidence: labels }
  }
  return { required: true, satisfied: true, reason: `Cross-site form POST carried the ambient SameSite=${labels.sameSite ?? 'unspecified'} cookie, the csrf_state_change oracle is declared, and ${persistence.reason}.`, evidence: labels }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

export function assessImpactEvidence(input: ImpactInput): ImpactAssessment {
  switch (input.impactClass) {
    case 'csrf':
      return assessCsrfImpact(input)
    case 'mass_assignment':
      return assessMassAssignmentImpact(input)
    case 'bfla':
    case 'authorization':
      return assessAuthorizationImpact(input)
    default:
      return { required: false, satisfied: true, reason: 'Not an authorization/impact claim.' }
  }
}

/** True when the declared oracle event names a class whose evidence the verifier can check. */
export function knownOracleEvent(event: string): boolean {
  return [
    'cross_tenant_read', 'cross_tenant_write', 'privilege_escalation', 'mass_assignment',
    'invariant_violation', 'csrf_state_change', 'state_delta', 'workflow_skip', 'secret_disclosed',
  ].includes(event)
}

// ---------------------------------------------------------------------------
// Universal boundary control (default-deny)
// ---------------------------------------------------------------------------

/**
 * Authentication/identity claims describe a gate being circumvented. A 2xx from a request that was
 * never gated is not a bypass (e.g. "2FA bypass" on an account that never enabled 2FA), so these
 * claims require a *challenged/denied control* and a variant that crosses that exact boundary.
 */
const MFA_CLAIM_RE = /\b(?:2fa|mfa|two[- ]?factor|multi[- ]?factor|one[- ]?time[- ]?pass(?:word|code)?|otp|totp|authenticator|step[- ]?up)\b/i
const AUTH_BOUNDARY_RE = /\b(?:authenticat(?:ion|or)[- ]?(?:bypass|confusion)|auth[- ]?bypass|login[- ]?bypass|session[- ]?fixation|token[- ]?forgery|jwt|sso|single[- ]?sign[- ]?on|oauth[- ]?confusion|confused[- ]?deputy|legacy[- ]?auth)\b/i
const AUTH_BOUNDARY_CWE_RE = /^CWE-(?:287|288|290|294|302|303|305|306|346|384|522|620|798)$/i
const ACCESS_BOUNDARY_RE = /\b(?:bola|bfla|idor|broken[- ]access[- ]control|access[- ]control|authori[sz]ation|privilege[- ]escalation|tenant[- ]isolation|vertical[- ]access|cross[- ]tenant|insecure[- ]direct[- ]object)\b/i
const ACCESS_BOUNDARY_CWE_RE = /^CWE-(?:269|284|285|566|639|862|863|1021|1220)$/i

export interface BoundaryDescriptor {
  cwe?: string | null
  category?: string | null
  title?: string | null
  impact?: string | null
}

/** Classify which boundary a claim must demonstrate. Auth outranks access (a bypass is a bypass). */
export function classifyBoundaryClaim(parts: BoundaryDescriptor): BoundaryClass {
  // Titles and categories are the claim's label; generic impact boilerplate ("outside their
  // authorization") must not turn an XXE/SSRF claim into an access-control claim.
  const text = `${parts.title ?? ''} ${parts.category ?? ''}`
  if (MFA_CLAIM_RE.test(text)) return 'mfa'
  if (AUTH_BOUNDARY_RE.test(text) || AUTH_BOUNDARY_CWE_RE.test(parts.cwe ?? '')) return 'auth'
  if (ACCESS_BOUNDARY_RE.test(text) || ACCESS_BOUNDARY_CWE_RE.test(parts.cwe ?? '')) return 'access'
  return 'other'
}

/** Collapse path identifiers so a negative/foreign-id control matches the real resource route. */
export function routeFamily(pathAndQuery: string | null | undefined): string {
  if (!pathAndQuery) return ''
  const path = pathAndQuery.split('?')[0].split('#')[0].replace(/\/{2,}/g, '/').replace(/\/+$/, '').toLowerCase() || '/'
  return path.split('/').map(segment => {
    if (!segment || /^(?:api|rest|v\d+|read|public|admin|me|settings|login|logout|auth|token|refresh|verify|mfa|2fa|otp|session)$/i.test(segment)) return segment
    const idShaped = /(?:^|[-_.])\d|^[0-9a-f]{8,}$|^[a-z]{2,10}_[A-Za-z0-9_-]{4,}$|^[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*$/.test(segment)
    if (idShaped && (segment.length >= 4 || /^[a-z]\d{1,3}$/i.test(segment))) return ':id'
    return segment
  }).join('/') || '/'
}

const MFA_CHALLENGE_RE = /\b(?:two[- ]?factor|2fa|mfa|otp|totp|one[- ]?time[- ]?(?:pass(?:word|code)?|code)|verification code|authenticator|challenge[- ]?required|mfa_required|step[- ]?up)\b/i
const LOGIN_REDIRECT_RE = /\/(?:login|signin|sign-in|sso|auth|session|mfa|2fa|verify)\b/i

export type BoundaryArm = 'control_denied' | 'actor_differential' | null

export interface BoundaryAssessment {
  required: boolean
  satisfied: boolean
  boundaryClass: BoundaryClass
  /** A control exchange that was denied or challenged (401/403, login redirect, MFA challenge, negative id). */
  controlDenied: boolean
  controlKind: 'denied' | 'challenge' | 'negative_id' | null
  /** A variant exchange that crossed the same route family with data/state proof. */
  crossed: boolean
  arm: BoundaryArm
  reason: string
  evidence: Record<string, unknown>
}

export interface BoundaryInput extends ImpactInput {
  /**
   * `true`  — the control arm is expected to be denied/challenged; a 2xx control is a spec error.
   * `false` — documented escape for `access` claims whose control is legitimately allowed
   *           (object differentials where both arms are served): the actor/precondition
   *           differential is the boundary. Ignored for `auth` claims, which always need a denial.
   * unset   — prefer control-denial evidence; fall back to the actor differential for `access`.
   */
  expectControlDenied?: boolean
}

function headerField(headers: Record<string, string> | null | undefined, pattern: RegExp): string | null {
  if (!headers) return null
  for (const [key, value] of Object.entries(headers)) {
    if (pattern.test(key) && typeof value === 'string' && value.length > 0) return value
  }
  return null
}

interface BoundarySignal {
  step: ImpactStep
  kind: 'denied' | 'challenge' | 'negative_id'
}

function boundarySignalOf(step: ImpactStep, successFamilies: ReadonlySet<string>): BoundarySignal | null {
  const status = step.status
  if (status === 401 || status === 403) return { step, kind: 'denied' }
  if (status !== null && status >= 300 && status < 400) {
    const location = headerField(step.responseHeaders, /^location$/i)
    if (location === null || LOGIN_REDIRECT_RE.test(location)) return { step, kind: 'challenge' }
  }
  if (status === 404 && successFamilies.has(routeFamily(step.route ?? ''))) return { step, kind: 'negative_id' }
  // A 200/4xx challenge page (MFA step-up) is a challenge, not a served resource.
  if (status !== null && (status < 300 || status === 428)) {
    const challengeHeader = headerField(step.responseHeaders, /^(?:www-authenticate|x-mfa|mfa|otp|challenge|location)$/i)
    const body = `${challengeHeader ?? ''} ${(step.body ?? '').slice(0, 2048)}`
    if (MFA_CHALLENGE_RE.test(body) && (step.json === undefined || step.json === null)) return { step, kind: 'challenge' }
  }
  return null
}

/**
 * MFA/2FA bypass gate. A 2xx from an OTP endpoint is not a bypass unless:
 *   1. a control read shows the account is enrolled (`twofa_enabled`/`mfa`/`totp` claim);
 *   2. a protected read is denied/challenged before the code check; and
 *   3. the same session/actor is granted the same protected resource after it.
 * A decorative endpoint that returns `{ok:true}` for any code but gates nothing is reported as an
 * advisory (not confirmed): there is no challenged control to cross.
 */
const MFA_ENROLL_FIELD_RE = /^(?:twofa|two_?fa|mfa|totp|otp|two_?factor|two_?factor_?enabled|twofa_?enabled|mfa_?enabled|totp_?enabled|authenticator(?:_?enabled)?|enrolled|mfa_?enrolled|two_?step)$/i
const MFA_ROUTE_RE = /\/(?:2fa|mfa|otp|totp|verify|challenge|step-?up)(?:\/|$|\?)/i

function truthyJsonLeaf(value: string): boolean {
  const lower = value.trim().toLowerCase()
  return lower === 'true' || lower === '1' || lower === 'yes' || lower === 'enabled' || lower === 'on' || lower === '"true"'
}

export interface MfaAssessment extends ImpactAssessment {
  evidence: {
    enrolled: boolean
    enrolledStep: string | null
    enrolledField: string | null
    preDenied: boolean
    preStep: string | null
    postGranted: boolean
    postStep: string | null
    challengeStep: string | null
    sameActor: boolean
    sameRoute: boolean
    decorative: boolean
  }
}

export function assessMfaBypass(input: ImpactInput): MfaAssessment {
  const steps = input.steps
  const evidence = {
    enrolled: false,
    enrolledStep: null as string | null,
    enrolledField: null as string | null,
    preDenied: false,
    preStep: null as string | null,
    postGranted: false,
    postStep: null as string | null,
    challengeStep: null as string | null,
    sameActor: false,
    sameRoute: false,
    decorative: false,
  }
  // 1. Enrollment must come from a control/setup read of the account state, not the probe echo.
  for (const step of steps) {
    if (step.arm === 'probe' || step.json === undefined || step.json === null) continue
    for (const [path, value] of flattenJson(step.json)) {
      const leaf = path.split('.').pop() ?? ''
      if (MFA_ENROLL_FIELD_RE.test(leaf) && truthyJsonLeaf(value)) {
        evidence.enrolled = true
        evidence.enrolledStep = step.id
        evidence.enrolledField = path
        break
      }
    }
    if (evidence.enrolled) break
  }
  // 2. Protected reads exclude the OTP/challenge endpoint itself.
  const protectedReads = steps.filter(step =>
    isReadMethod(step.method) &&
    !MFA_ROUTE_RE.test(step.pathAndQuery ?? '') &&
    !MFA_ROUTE_RE.test(step.route ?? ''))
  const challenge = steps.find(step =>
    isMutatingMethod(step.method) &&
    (MFA_ROUTE_RE.test(step.pathAndQuery ?? '') || MFA_ROUTE_RE.test(step.route ?? '') || MFA_CHALLENGE_RE.test(step.body ?? ''))) ??
    steps.find(step => step.arm === 'probe' && isMutatingMethod(step.method)) ??
    null
  evidence.challengeStep = challenge?.id ?? null
  const challengeIndex = challenge ? steps.indexOf(challenge) : steps.length
  const deniedRead = (step: ImpactStep): boolean =>
    step.status === 401 || step.status === 403 ||
    (step.status !== null && step.status >= 300 && step.status < 400) ||
    MFA_CHALLENGE_RE.test(`${headerField(step.responseHeaders, /^(?:www-authenticate|x-mfa|mfa|challenge)$/i) ?? ''} ${(step.body ?? '').slice(0, 1024)}`)
  const pre = [...protectedReads].reverse().find(step => steps.indexOf(step) < challengeIndex && deniedRead(step)) ?? null
  const post = protectedReads.find(step =>
    steps.indexOf(step) > (pre ? steps.indexOf(pre) : -1) &&
    isSuccess(step.status) &&
    ((step.json !== undefined && step.json !== null) || (step.body?.length ?? 0) >= 8)) ?? null
  evidence.preDenied = pre !== null
  evidence.preStep = pre?.id ?? null
  evidence.postGranted = post !== null
  evidence.postStep = post?.id ?? null
  evidence.sameActor = Boolean(pre && post && pre.actor.handle === post.actor.handle)
  evidence.sameRoute = Boolean(pre && post && routeFamily(pre.route ?? '') === routeFamily(post.route ?? ''))
  evidence.decorative = !pre

  if (!pre) {
    return {
      required: true,
      satisfied: false,
      reason: 'MFA/2FA claim dismissed: no protected read was denied/challenged before the code check, so the OTP endpoint gates nothing (decorative 2FA). Report this as an advisory, not a confirmed bypass.',
      evidence,
    }
  }
  if (!evidence.enrolled) {
    return {
      required: true,
      satisfied: false,
      reason: 'MFA/2FA claim dismissed: no control read shows the account is enrolled (twofa_enabled/mfa/totp claim). A 2xx from an OTP endpoint on an unenrolled account is not a bypass.',
      evidence,
    }
  }
  if (!post) {
    return {
      required: true,
      satisfied: false,
      reason: 'MFA/2FA claim dismissed: no post-challenge read of the same protected resource shows the boundary was crossed with data/state proof.',
      evidence,
    }
  }
  if (!evidence.sameActor) {
    return {
      required: true,
      satisfied: false,
      reason: 'MFA/2FA claim dismissed: the pre-challenge denial and post-challenge grant are not tied to the same session/actor.',
      evidence,
    }
  }
  if (!evidence.sameRoute) {
    return {
      required: true,
      satisfied: false,
      reason: 'MFA/2FA claim dismissed: the denied pre-challenge read and the granted post-challenge read are different resources, so no access differential is proven.',
      evidence,
    }
  }
  return {
    required: true,
    satisfied: true,
    reason: `MFA gate crossed: enrolled (${evidence.enrolledField}) control shows the boundary, "${pre.id}" was denied/challenged, and the same actor read ${post.route ?? 'the protected resource'} with data after the code check.`,
    evidence,
  }
}

/**
 * Universal default-deny boundary gate.
 *
 * `auth` claims confirm only with a denied/challenged control and a successful variant on the same
 * route family that exposes data or a state change. `access` claims confirm with either that denial
 * or an explicit actor/precondition differential (the documented control-legitimately-allowed
 * escape). A claim that merely gets a 2xx from an ungated request never confirms.
 */
export function assessBoundary(input: BoundaryInput & { boundaryClass: BoundaryClass }): BoundaryAssessment {
  return assessBoundaryForClass(input, input.boundaryClass)
}

function assessBoundaryForClass(input: BoundaryInput, boundaryClass: BoundaryClass): BoundaryAssessment {
  if (boundaryClass === 'other') {
    return {
      required: false, satisfied: true, boundaryClass, controlDenied: false, controlKind: null,
      crossed: false, arm: null, reason: 'Not an authentication/access-control claim.', evidence: {},
    }
  }
  const steps = input.steps
  const probeSteps = steps.filter(step => step.arm === 'probe')
  const controlSteps = steps.filter(step => step.arm === 'control')
  const successes = steps.filter(step => isSuccess(step.status))
  const successFamilies = new Set(successes.map(step => routeFamily(step.route ?? '')).filter(Boolean))
  const signals = steps
    .map(step => boundarySignalOf(step, successFamilies))
    .filter((signal): signal is BoundarySignal => signal !== null)
  const signal = signals.find(entry => entry.step.arm === 'control' || entry.step.arm === 'setup') ?? signals[0] ?? null
  const controlDenied = signal !== null
  // The variant must cross the same route family and expose data or a state change.
  const signalFamily = signal ? routeFamily(signal.step.route ?? '') : ''
  const crossed = Boolean(signal && successes.some(step =>
    step.id !== signal.step.id &&
    routeFamily(step.route ?? '') === signalFamily &&
    step.arm === 'probe' &&
    ((stepReadsState(step) && ((step.json !== undefined && step.json !== null) || (step.body?.length ?? 0) >= 8)) ||
      (stepMutatesState(step) && isSuccess(step.status)))))
  const distinctActors = new Set(steps.map(step => step.actor.handle).filter((handle): handle is string => Boolean(handle)))
  const roleOrTenantDifferential = steps.some(a => steps.some(b =>
    a !== b &&
    ((a.actor.role !== null && b.actor.role !== null && a.actor.role !== b.actor.role) ||
      (a.actor.tenant !== null && b.actor.tenant !== null && a.actor.tenant !== b.actor.tenant))))
  // A parameter/body precondition differential (e.g. ?id=pub vs ?id=priv) is the same kind of
  // "the variant changed the precondition" evidence as an actor differential.
  const requestDifferential = controlSteps.some(control => probeSteps.some(probe =>
    (control.pathAndQuery ?? control.route ?? '') !== (probe.pathAndQuery ?? probe.route ?? '') ||
    JSON.stringify(control.requestJson ?? null) !== JSON.stringify(probe.requestJson ?? null)))
  const actorDifferential = distinctActors.size >= 2 || roleOrTenantDifferential || requestDifferential
  const strict = input.expectControlDenied === true
  const escape = input.expectControlDenied === false
  const evidence = {
    boundaryClass,
    controlDenied,
    controlKind: signal?.kind ?? null,
    controlStep: signal?.step.id ?? null,
    crossed,
    arm: null as BoundaryArm,
    distinctActors: distinctActors.size,
    actorDifferential,
    expectControlDenied: input.expectControlDenied ?? null,
    probeSteps: probeSteps.length,
    controlSteps: controlSteps.length,
  }

  if (boundaryClass === 'auth') {
    if (!controlDenied) {
      return {
        required: true, satisfied: false, boundaryClass, controlDenied, controlKind: null, crossed,
        arm: null,
        reason: 'Authentication/bypass claim dismissed: the signed transcript has no denied/challenged control (401/403, login redirect or MFA challenge). A 2xx from a request that was never gated is not a bypass (e.g. 2FA bypass on an account without 2FA enabled). Add a challenged control and a variant that crosses it.',
        evidence,
      }
    }
    if (!crossed) {
      return {
        required: true, satisfied: false, boundaryClass, controlDenied, controlKind: signal?.kind ?? null, crossed,
        arm: null,
        reason: 'Authentication/bypass claim has a challenged control but no variant exchange on the same route family that crosses the boundary with data/state proof.',
        evidence,
      }
    }
    return {
      required: true, satisfied: true, boundaryClass, controlDenied, controlKind: signal?.kind ?? null, crossed,
      arm: 'control_denied',
      reason: `Boundary crossed: the ${signal?.kind === 'challenge' ? 'challenge' : 'denied control'} on "${signal?.step.id}" was bypassed by a successful variant with data/state evidence.`,
      evidence: { ...evidence, arm: 'control_denied' },
    }
  }

  // access
  if (controlDenied && (!escape || strict)) {
    if (!crossed) {
      return {
        required: true, satisfied: false, boundaryClass, controlDenied, controlKind: signal?.kind ?? null, crossed,
        arm: null,
        reason: 'Access-control claim has a denied/challenged control but no variant exchange on the same route family that crosses it with data/state proof.',
        evidence,
      }
    }
    return {
      required: true, satisfied: true, boundaryClass, controlDenied, controlKind: signal?.kind ?? null, crossed,
      arm: 'control_denied',
      reason: `Boundary crossed: the ${signal?.kind ?? 'denied'} control on "${signal?.step.id}" was crossed by a successful variant with data/state evidence.`,
      evidence: { ...evidence, arm: 'control_denied' },
    }
  }
  if (strict) {
    return {
      required: true, satisfied: false, boundaryClass, controlDenied, controlKind: null, crossed,
      arm: null,
      reason: 'expectControlDenied is true but no control exchange was denied/challenged on the same precondition; a spec that expects a gate must observe it.',
      evidence,
    }
  }
  if (!actorDifferential) {
    return {
      required: true, satisfied: false, boundaryClass, controlDenied, controlKind: null, crossed,
      arm: null,
      reason: 'Access-control claim has no denied/challenged control and no actor/precondition differential to stand in for the boundary; a 2xx from one actor is not a bypass.',
      evidence,
    }
  }
  return {
    required: true, satisfied: true, boundaryClass, controlDenied: false, controlKind: null, crossed,
    arm: 'actor_differential',
    reason: 'No denial is observable on this route (the control is legitimately served); the object boundary is demonstrated by the actor/precondition differential, which the impact gate must still back with data/state proof.',
    evidence: { ...evidence, arm: 'actor_differential' },
  }
}

