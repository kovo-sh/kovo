/**
 * Single-source field, route, role, and authorization heuristics for the deterministic floor.
 *
 * Shared by `deterministic-engine.ts`, `deterministic-specs.ts`, and `floor-recipe-engine.ts` so
 * live recipe planning, legacy spec synthesis, and hypothesis enumeration never silently drift.
 *
 * All regular expressions here are static literals (zero dynamic `RegExp` construction).
 */
import { randomBytes } from 'node:crypto'
import type { RoleName } from './oracle-invariants.ts'
import type { DifferentialResult } from './surface-engine.ts'

// ---------------------------------------------------------------------------------------------
// Route, action, and identity classification
// ---------------------------------------------------------------------------------------------

/** Routes whose name marks an elevated/privileged function (admin console, role grant, flags...). */
export const PRIVILEGED_ACTION_RE =
  /(?:^|[/_.-])(?:admin|administrator|administration|internal|manage|management|staff|superuser|privileged|backoffice|permissions?|roles?|grants?|scopes?|impersonate|feature[-_]?flags?)(?:$|[/_.-])/i

/** Read routes whose primary security property is credential/audit disclosure rather than body-equality BOLA. */
export const SENSITIVE_READ_ROUTE_RE =
  /(?:^|[/_.-])(?:tokens?|keys?|secrets?|audit|auditlog|activity|logs?|config|export|apikeys?|links?|integrations?)(?:$|[/_.-])/i

/**
 * Route shapes that hand the caller a new acting identity/scope (impersonation, act-as, tenant
 * switch). Mutating probes on these routes can change the instrument's own session, so their
 * bodies are restricted to benign content fields and mass-assignment is not run there.
 */
export const IDENTITY_ASSUMPTION_ROUTE_RE =
  /(?:^|[/_.-])(?:impersonat\w*|act[-_]?as|sudo|assume[-_]?role|switch[-_]?(?:tenant|org|store|user|account)|sts)(?:$|[/_.-])/i

/** Field names that select or change identity/scope rather than describing record content. */
export function isIdentityAssignmentField(field: string): boolean {
  const snake = field.replace(/[A-Z]/g, ch => '_' + ch.toLowerCase()).replace(/[-.]/g, '_')
  return /^(?:is_?_?admin|admin|role|roles|permission|permissions|privilege|privileges|grant|level|tenant|tenant_id|org|org_id|store|store_id|team|team_id|account|account_id|owner|owner_id|scope|acting|act_as|workspace|workspace_id|user|user_id|actor|subject|email)$/.test(snake)
}

/** Drop identity/scope selectors from a probe body (shallow and nested object levels). */
export function withoutIdentityFields(body: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [field, value] of Object.entries(body)) {
    if (isIdentityAssignmentField(field)) continue
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const nested = withoutIdentityFields(value as Record<string, unknown>)
      if (Object.keys(nested).length > 0) out[field] = nested
      continue
    }
    out[field] = value
  }
  return out
}

// ---------------------------------------------------------------------------------------------
// Baseline write & privilege-escalation field classification
// ---------------------------------------------------------------------------------------------

export const BASELINE_STRONG_NUMERIC_FIELD_RE =
  /(?:^|[_-])(?:amount|total|price|value|cents|balance|qty|quantity|count|seats?|credits?)(?:$|[_-])/i
export const BASELINE_TEXT_FIELD_RE =
  /^(?:name|title|label|description|note|notes|body|text|summary|message|subject|comment|company|address)$/i
export const BASELINE_WEAK_NUMERIC_FIELD_RE =
  /^(?:number|num|limit|score|rating|page|size|order)$/i
export const BASELINE_EXCLUDED_FIELD_RE =
  /(?:^|[_-])(?:id|uuid|owner|tenant|org|team|role|roles|permissions?|email|password|token|secret|key|status|state|created|updated)(?:$|[_-])/i
/** Scope/identity selectors: writing these changes which record is addressed, not its content. */
export const BASELINE_SELECTOR_FIELD_RE =
  /(?:^|[_-])(?:id|uuid|owner|tenant|org|team|role|roles|permissions?|email|password|token|secret|key|created|updated)(?:$|[_-])/i
export const BASELINE_STATE_FIELD_RE =
  /^(?:status|state|stage|phase|payment_state|fulfil?lment_state|lifecycle|visibility|priority|archived?|active)$/i
/** Columns a privileged-function mutation grants (role/plan/scope style escalation). */
export const PRIVILEGE_TARGET_FIELD_RE =
  /^(?:role|role_name|user_role|account_role|account_type|membership|plan|tier|level|scope|is_admin|is_owner|is_staff|admin|privilege|privileges|permissions|permission_level)$/i
/** Literal values that name an elevated entitlement (never a benign content value). */
export const PRIVILEGE_LITERAL_RE =
  /^(?:admin|administrator|owner|superuser|root|staff)$/i

export const CONSERVED_BALANCE_FIELD_RE = /balance|available|remaining|stock|on_?hand|quantity|credits?|points?/i
export const CONSERVED_ECHO_FIELD_RE = /transfer|debit|charge|amount|count|redeem|used|quantity|qty|reserved/i
export const CONSERVED_AMOUNT_FIELD_RE = /^(?:item_?|line_?|requested_?|reserved_?|redeem_?)?(?:amount|value|quantity|qty|count|units|seats|credits|points|total|redeem)$/i

// ---------------------------------------------------------------------------------------------
// Safe identifier / field / persona guards
// ---------------------------------------------------------------------------------------------

export const SAFE_RESOURCE_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/
export const SAFE_FIELD_NAME_RE = /^[A-Za-z0-9_.-]{1,64}$/
export const SAFE_PERSONA_HANDLE_RE = /^[a-z0-9_-]{1,32}$/
export const SAFE_IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/

export function isSafeResourceId(value: unknown): value is string {
  return typeof value === 'string' && SAFE_RESOURCE_ID_RE.test(value)
}

export function isSafeFieldName(value: unknown): value is string {
  return typeof value === 'string' && SAFE_FIELD_NAME_RE.test(value)
}

export function isSafePersonaHandle(value: unknown): value is string {
  return typeof value === 'string' && SAFE_PERSONA_HANDLE_RE.test(value)
}

export function isSafeIdentifier(value: unknown): value is string {
  return typeof value === 'string' && SAFE_IDENTIFIER_RE.test(value)
}

export function fillResourceId(pathAndQuery: string, id: string): string {
  return pathAndQuery.replaceAll('{{id}}', encodeURIComponent(id))
}

/**
 * A syntactically valid identifier that must not resolve to any real object. Used as a negative
 * control so a route that ignores its identifier (and serves the caller's own session object)
 * cannot be mistaken for an object-level authorization failure.
 */
export function bogusIdFor(id: string): string {
  if (/^\d{1,12}$/.test(id)) {
    const n = Number(id)
    if (Number.isSafeInteger(n)) {
      const bumped = n + 9_000_001
      if (String(bumped).length <= 12) return String(bumped)
    }
  }
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    const tail = id.slice(-1) === '0' ? '1' : '0'
    return `${id.slice(0, -1)}${tail}`
  }
  if (/^[A-Za-z]+[-_][A-Za-z0-9]+$/.test(id)) {
    const sep = id.includes('_') ? '_' : '-'
    return `${id.split(/[-_]/)[0]}${sep}gx9000001`
  }
  return `gx${randomBytes(8).toString('hex')}`
}

// ---------------------------------------------------------------------------------------------
// Posture / role privilege rankings
// ---------------------------------------------------------------------------------------------

export const ROLE_PRIVILEGE_RANK: Readonly<Record<string, number>> = {
  superadmin: 5,
  owner: 4,
  admin: 4,
  manager: 3,
  editor: 3,
  moderator: 3,
  member: 2,
  user: 2,
  viewer: 1,
  readonly: 1,
  guest: 0,
  anonymous: 0,
}

export function rolePrivilegeRank(role: RoleName | null | undefined): number | null {
  if (!role) return null
  return Object.prototype.hasOwnProperty.call(ROLE_PRIVILEGE_RANK, role) ? ROLE_PRIVILEGE_RANK[role]! : null
}

export const POSTURE_CWES: ReadonlySet<string> = new Set([
  'CWE-16', 'CWE-200', 'CWE-209', 'CWE-284', 'CWE-285', 'CWE-287', 'CWE-288', 'CWE-306', 'CWE-319', 'CWE-326',
  'CWE-346', 'CWE-523', 'CWE-538', 'CWE-540', 'CWE-614', 'CWE-639', 'CWE-693', 'CWE-862', 'CWE-863', 'CWE-942',
  'CWE-1004', 'CWE-1021',
])

export const POSTURE_CATEGORY_RE =
  /access|auth|bypass|cors|header|posture|misconfig|exposure|session|cookie|transport|tls|csp|policy|idor|bola|bfla/i

// ---------------------------------------------------------------------------------------------
// Shared authorization readback, baseline write, and matrix admissibility helpers
// ---------------------------------------------------------------------------------------------

export interface AuthzReadbackTemplate {
  /** Read route with its `{{id}}` placeholder still in place. */
  template: string
  /** Actor for the read when it is the mutated actor's own identity route. */
  persona?: string
}

/**
 * Resolve the readback route template for a mutating authorization proof:
 * explicit harvested readback route, the object's REST detail route (dropping a trailing
 * privileged action verb), or the function's own surface for an elevated action.
 */
export function resolveAuthzReadbackTemplate(
  input: { pathAndQuery: string; readbackPath?: string; readbackPersona?: string },
  functionLevel: boolean,
): AuthzReadbackTemplate | null {
  if (input.readbackPath) {
    return {
      template: input.readbackPath,
      ...(input.readbackPersona ? { persona: input.readbackPersona } : {}),
    }
  }
  const pathAndQuery = input.pathAndQuery
  const bare = pathAndQuery.split('?')[0]!
  if (functionLevel) return PRIVILEGED_ACTION_RE.test(bare) ? { template: pathAndQuery } : null
  const queryAt = pathAndQuery.indexOf('?')
  if (queryAt >= 0 && pathAndQuery.slice(queryAt).includes('{{id}}')) return { template: pathAndQuery }
  const segments = bare.split('/')
  const placeholder = segments.findIndex(seg =>
    seg === '{{id}}' || /^\{[^}]+\}$/.test(seg) || /^:[A-Za-z_][A-Za-z0-9_]*$/.test(seg))
  if (placeholder <= 0) return null
  if (placeholder === segments.length - 1) return { template: pathAndQuery }
  if (placeholder === segments.length - 2 && PRIVILEGED_ACTION_RE.test(bare)) {
    return { template: segments.slice(0, -1).join('/') }
  }
  return null
}

export interface BaselineWrite {
  field: string
  baselineValue: string | number | boolean
  probeValue: string | number | boolean
  baselineBody: Record<string, unknown>
}

/**
 * Restore a non-privileged baseline for a privileged-function entitlement grant so the probe's
 * value produces a fresh delta rather than an idempotent no-op.
 */
export function privilegeBaselineFor(bodyTemplate: unknown, requiredRole?: string | null): BaselineWrite | null {
  if (!bodyTemplate || typeof bodyTemplate !== 'object' || Array.isArray(bodyTemplate)) return null
  const record = bodyTemplate as Record<string, unknown>
  const entry = Object.entries(record).find(([field, value]) =>
    PRIVILEGE_TARGET_FIELD_RE.test(field) && typeof value === 'string' && PRIVILEGE_LITERAL_RE.test(value))
  if (!entry) return null
  const [field, value] = entry
  if (typeof value !== 'string') return null
  const demotion = requiredRole === 'admin' ? 'member' : 'viewer'
  if (value.toLowerCase() === demotion) return null
  return { field, baselineValue: demotion, probeValue: value, baselineBody: { ...record, [field]: demotion } }
}

/**
 * Escalate an existing privilege field on a privileged-function body to `requiredRole`.
 * Only a field the body already carries is escalated (never an invented field name).
 */
export function escalatePrivilegeBody(
  bodyTemplate: unknown,
  requiredRole?: string | null,
): Record<string, unknown> | null {
  if (!bodyTemplate || typeof bodyTemplate !== 'object' || Array.isArray(bodyTemplate) || !requiredRole) return null
  const record = bodyTemplate as Record<string, unknown>
  const field = Object.entries(record).find(([name, value]) =>
    PRIVILEGE_TARGET_FIELD_RE.test(name) &&
    (typeof value === 'string' || value === null || typeof value === 'number' || typeof value === 'boolean'))
  if (!field) return null
  return String(field[1]).toLowerCase() === requiredRole ? null : { ...record, [field[0]]: requiredRole }
}

/**
 * Choose a fresh baseline value for one mutable scalar field of a probe body so the probe write
 * creates a genuine non-idempotent delta against the pre-mutation readback.
 */
export function pickBaselineWrite(bodyTemplate: unknown): BaselineWrite | null {
  if (!bodyTemplate || typeof bodyTemplate !== 'object' || Array.isArray(bodyTemplate)) return null
  const record = bodyTemplate as Record<string, unknown>
  const scalarEntries = Object.entries(record).filter(([field, value]) =>
    SAFE_FIELD_NAME_RE.test(field) &&
    (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'))
  const entries = scalarEntries.filter(([field]) => !BASELINE_EXCLUDED_FIELD_RE.test(field))
  const chosen = entries.find(([field]) => BASELINE_STRONG_NUMERIC_FIELD_RE.test(field))
    ?? entries.find(([field]) => BASELINE_TEXT_FIELD_RE.test(field))
    ?? entries.find(([, value]) => typeof value === 'boolean')
    ?? entries.find(([field]) => BASELINE_WEAK_NUMERIC_FIELD_RE.test(field))
    ?? scalarEntries.find(([field]) => BASELINE_STATE_FIELD_RE.test(field))
    ?? scalarEntries.find(([field]) => !BASELINE_SELECTOR_FIELD_RE.test(field))
  if (!chosen) return null
  const [field, value] = chosen
  const nonce = randomBytes(4).toString('hex')
  if (typeof value === 'boolean') {
    const baselineValue = !value
    return { field, baselineValue, probeValue: value, baselineBody: { ...record, [field]: baselineValue } }
  }
  if (typeof value === 'number' || /^-?\d+(?:\.\d+)?$/.test(String(value))) {
    const base = 424_242 + (Number.parseInt(nonce.slice(0, 4), 16) % 1_000)
    return { field, baselineValue: base, probeValue: base + 1, baselineBody: { ...record, [field]: base } }
  }
  const baselineValue = `kovo-baseline-${nonce}`
  return { field, baselineValue, probeValue: `kovo-probe-${nonce}`, baselineBody: { ...record, [field]: baselineValue } }
}

export interface AuthzMatrixRow {
  resourceId?: unknown
  actor?: unknown
  status?: unknown
  bodyBytes?: unknown
  bodySha256?: unknown
  similarityToOwner?: unknown
  accessible?: unknown
}

/**
 * Evaluate owner/probe admissibility and publicness veto for one `unauthorized_access` hit
 * against the recorded authorization matrix. Shared between live recipe routing and spec synthesis.
 */
export function isAuthzMatrixHitAdmissible(
  matrix: readonly AuthzMatrixRow[] | null,
  hit: Record<string, unknown>,
  opts: { mutating: boolean; functionLevel: boolean },
): boolean {
  if (!matrix) return true
  const matrixId = String(hit.resourceId ?? '')
  const probeActor = hit.actor === 'anonymous' ? 'anonymous' : 'other_persona'
  const idRows = opts.functionLevel ? matrix : matrix.filter(r => String(r.resourceId ?? '') === matrixId)
  const ownerRow = idRows.find(r => r.actor === 'owner')
  const probeRow = idRows.find(r => r.actor === probeActor)
  if (!ownerRow || ownerRow.accessible !== true || typeof ownerRow.status !== 'number' ||
      ownerRow.status < 200 || ownerRow.status >= 300) return false
  if (typeof ownerRow.bodyBytes === 'number' && ownerRow.bodyBytes <= 2) return false
  if (!probeRow || probeRow.accessible !== true) return false
  if (!opts.mutating && Number(probeRow.similarityToOwner ?? hit.similarityToOwner ?? 0) < 0.7) return false
  const anonRow = idRows.find(r => r.actor === 'anonymous')
  if (!opts.mutating && anonRow?.accessible === true) {
    const sameBody = typeof anonRow.bodySha256 === 'string' && anonRow.bodySha256 === ownerRow.bodySha256
    const similar = Number(anonRow.similarityToOwner ?? 0) >= 0.7
    if (sameBody || similar) return false
  }
  return true
}

/** True when an `authz_matrix` differential result contains at least one admissible object/function hit. */
export function hasAdmissibleAuthzHit(
  hyp: { method: string; functionLevel?: boolean; ownerPersona?: string; otherPersona?: string; reservedVictimId?: string; endpoint: { pathTemplate: string } },
  result: DifferentialResult,
): boolean {
  if (!hyp.ownerPersona || !hyp.otherPersona) return false
  const matrix = Array.isArray(result.details.matrix) ? result.details.matrix as AuthzMatrixRow[] : null
  const privilegedRoute = PRIVILEGED_ACTION_RE.test(hyp.endpoint.pathTemplate)
  for (const hit of result.anomalies) {
    if (hit.type !== 'unauthorized_access') continue
    const method = String(hit.method ?? 'GET')
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue
    const mutating = method !== 'GET'
    const functionLevel = hit.functionLevel === true || hyp.functionLevel === true
    const useReservedVictim = Boolean(hyp.reservedVictimId) && method === 'DELETE' && privilegedRoute && !functionLevel
    const id = useReservedVictim ? hyp.reservedVictimId! : String(hit.resourceId ?? '')
    if (!functionLevel && !SAFE_RESOURCE_ID_RE.test(id)) continue
    if (isAuthzMatrixHitAdmissible(matrix, hit, { mutating, functionLevel })) return true
  }
  return false
}
