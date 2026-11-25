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

export type ImpactClass = 'authorization' | 'bfla' | 'mass_assignment' | 'csrf' | 'business_logic' | 'markup' | 'disclosure' | 'injection' | 'other'
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
  /** Pre-redaction credential fingerprints (sha256 prefixes only) observed in this exchange. */
  secretMatches?: readonly string[]
  /** Host-recorded wall-clock duration (timing-differential evidence). */
  durationMs?: number
  /**
   * Evidence role the recipe asked this exchange to fill (`benign_baseline`, `tautology`,
   * `contradiction`, `denied_control`, ...). Optional: the shared oracles infer what they can
   * from arm/status/shape, and use the role only to pair the status-differential triangle.
   */
  evidenceRole?: string
}

/**
 * Evidence models for the injection family. A status change alone is never evidence; these are the
 * only confirmation signals the shared oracle accepts for SQL/NoSQL/template/command/XXE/traversal.
 */
export interface InjectionEvidence {
  /** Restrict fingerprints to the construct family the proof claims. */
  family?: InjectionFamily
  /** Injected parameter name (required for the paired boolean-differential arm). */
  param?: string
  /** Paired control/probe rounds (>=2) with a stable structural delta. */
  rounds?: readonly BooleanDifferentialRound[]
  /** Host-recorded control/probe durations for a jitter-tolerant timing arm. */
  timing?: { controlMs: number; probeMs: number }
  /** A verified out-of-band callback delivered after the injected marker reached the target. */
  oobDelivered?: boolean
  /**
   * The narrow status-only boolean exception: a benign 2xx baseline, a 2xx tautology arm and a
   * failing contradiction arm that differs only by the boolean predicate. A single malformed
   * request that turns 200 into 500 is not this shape.
   */
  statusBoolean?: { benign: ImpactStep; tautology: ImpactStep; contradiction: ImpactStep }
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
  /**
   * Credential value shapes the proof itself asserts (the replay spec's `proofPatterns`). The host
   * re-tests each one against the recorded bodies: it must match the probe response and no control
   * response. This is evidence, not a declaration — an unmatched or control-echoing pattern does
   * nothing.
   */
  credentialPatterns?: readonly string[] | null
  /** Extra injection-arm evidence (boolean rounds, timing, OOB, status-boolean exception). */
  injection?: InjectionEvidence
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

/** Same resource tree: equal route family, or a collection readback above the mutated item. */
function relatedRoute(a: ImpactStep, b: ImpactStep): boolean {
  const left = routeFamily(a.route ?? a.pathAndQuery ?? '')
  const right = routeFamily(b.route ?? b.pathAndQuery ?? '')
  if (!left || !right) return false
  return left === right || left.startsWith(`${right}/`) || right.startsWith(`${left}/`)
}

export interface PublicnessAssessment {
  public: boolean
  reason: string
  referenceId?: string
}

/** Flattened, order-independent payload key for structural equality between two exchanges. */
function payloadKey(step: ImpactStep): string | null {
  if (step.json !== undefined && step.json !== null && typeof step.json === 'object') {
    const flat = flattenJson(step.json)
    if (flat.size === 0) return null
    return `json:${[...flat.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('\u0000')}`
  }
  if (typeof step.body === 'string' && step.body.length > 0) return `body:${step.body}`
  return null
}

/** Leaf names of every array-bearing listing response in the chain (a public collection shape). */
function listingLeaves(steps: readonly ImpactStep[]): Set<string> {
  const leaves = new Set<string>()
  const add = (path: string): void => {
    const leaf = (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase()
    if (leaf) leaves.add(leaf)
  }
  for (const step of steps) {
    if (!isReadMethod(step.method) || !isSuccess(step.status) || step.json === undefined) continue
    const flat = flattenJson(step.json)
    if (![...flat.keys()].some(path => path.includes('['))) continue
    for (const path of flat.keys()) add(path)
  }
  return leaves
}

/**
 * Publicness: a storefront/catalog surface readable without authentication, or one where a
 * non-owner caller receives a payload identical to the owner reference, is exposing the same
 * public object — not an object-level crossing. The claim survives when the shared payload still
 * binds an owner-scoped identity to another principal or carries a tenant/secret canary (a real
 * disclosure that a public surface would not have).
 */
export function assessPublicness(args: { steps: readonly ImpactStep[]; probe: ImpactStep }): PublicnessAssessment {
  const { steps, probe } = args
  if (!isReadMethod(probe.method) || !isSuccess(probe.status)) return { public: false, reason: '' }
  const probeTenant = probe.actor.tenant ?? null
  const sameRouteReads = steps.filter(step =>
    step !== probe &&
    isReadMethod(step.method) &&
    isSuccess(step.status) &&
    sameRoute(step, probe) &&
    step.json !== undefined &&
    step.json !== null)
  // (A) The surface is public when an anonymous caller is served a payload on the same route —
  // including the probe itself when the claim is an unauthenticated read.
  const anonymousRead = [probe, ...sameRouteReads].find(step =>
    step.actor.handle === null && (step.actor.tenant ?? null) === null && step.json !== undefined && step.json !== null)
  if (anonymousRead) {
    return {
      public: true,
      referenceId: anonymousRead.id,
      reason: `an unauthenticated caller was served a payload on the same route (${anonymousRead.id}), so the surface is publicly readable`,
    }
  }
  // (B) A non-owner payload identical to the owner reference (or differing only on fields the
  // public listing exposes) is the same public object. Local compare only; no anon arm needed.
  const probeKey = payloadKey(probe)
  if (!probeKey && probe.json === undefined) return { public: false, reason: '' }
  const references = sameRouteReads.filter(step =>
    step.arm === 'control' &&
    step.actor.handle !== probe.actor.handle &&
    (step.json !== undefined || typeof step.body === 'string') &&
    // Publicness compares the *same object request*: a negative/absent-id control (different path)
    // never establishes that the probe's payload is public.
    (step.pathAndQuery === undefined || probe.pathAndQuery === undefined || step.pathAndQuery === probe.pathAndQuery))
  if (references.length === 0) return { public: false, reason: '' }
  const controlFlats = sameRouteReads
    .filter(step => step.arm === 'control' && step.json !== undefined && step.json !== null && typeof step.json === 'object')
    .map(step => flattenJson(step.json))
  const listing = listingLeaves(steps)
  const probeFlat = probe.json !== undefined && probe.json !== null && typeof probe.json === 'object' ? flattenJson(probe.json) : null
  for (const reference of references) {
    const referenceTenant = reference.actor.tenant ?? null
    // Only an anonymous caller or a caller outside the reference tenant can be a "public" reader.
    if (probeTenant !== null && referenceTenant !== null && probeTenant === referenceTenant) continue
    if (!probeTenant && !referenceTenant) continue
    const same = payloadKey(reference) === probeKey
    let differingOnlyPublic = false
    if (!same) {
      if (!probeFlat) continue
      const referenceFlat = reference.json !== undefined && reference.json !== null && typeof reference.json === 'object'
        ? flattenJson(reference.json)
        : null
      if (!referenceFlat) continue
      const differing = new Set<string>()
      for (const [path, value] of probeFlat) if (referenceFlat.get(path) !== value) differing.add(path)
      for (const path of referenceFlat.keys()) if (!probeFlat.has(path)) differing.add(path)
      const leaves = [...differing].map(path => (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase())
      differingOnlyPublic = differing.size > 0 && leaves.every(leaf => listing.has(leaf)) && !leaves.some(leaf => PRINCIPAL_IDENTITY_FIELD_RE.test(leaf))
      if (!differingOnlyPublic) continue
    }
    // A genuine victim-owned attribute or canary in the shared payload defeats publicness.
    // Plain content-attribution labels (e.g. a display `author` on a public review or comment)
    // only bind an owner when the value actually carries an email, canary, or reference principal.
    const ownerBound = probeFlat
      ? [...probeFlat.entries()].some(([path, value]) => {
        if (!value || value === 'null') return false
        // Bound when the same value is served to a *control* actor (the owner reference read).
        if (!controlFlats.some(flat => flat.get(path) === value)) return false
        const leaf = (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase()
        return isOwnerBoundIdentity(leaf, value, reference)
      })
      : false
    if (ownerBound) continue
    return {
      public: true,
      referenceId: reference.id,
      reason: differingOnlyPublic
        ? `the ${probe.actor.tenant ? 'non-owner' : 'anonymous'} response matches the owner reference ${reference.id} on the same route except for fields the public listing already exposes, so the resource is publicly readable (publicness), not an access-control crossing`
        : `the ${probe.actor.tenant ? 'non-owner' : 'anonymous'} response is identical to the owner reference ${reference.id} on the same route, so the resource is publicly readable (publicness), not an access-control crossing`,
    }
  }
  return { public: false, reason: '' }

}

/** True when the probe creates a new collection member (POST with no id-like final segment). */
function isCreateShapedProbe(step: ImpactStep): boolean {
  if ((step.method ?? '').toUpperCase() !== 'POST') return false
  const path = (step.route ?? '').replace(/\/+$/, '')
  const last = path.split('/').filter(Boolean).pop() ?? ''
  return !/\d/.test(last)
}



// ---------------------------------------------------------------------------
// Impact classification (title / category / CWE descriptors only)
// ---------------------------------------------------------------------------

const CSRF_RE = /\bcsrf\b|cross[- ]site\s+request\s+forgery|CWE-352/i
const MASS_ASSIGN_RE = /mass[- ]?assign|over[- ]?post|CWE-915/i
const AUTHZ_RE = /\b(?:bola|bfla|idor|broken[- ]access[- ]control|access[- ]control|authori[sz]ation|privilege[- ]escalation|tenant[- ]isolation|vertical[- ]access|cross[- ]tenant|per[- ]object|object[- ]ownership|ownership[- ]check|same[- ]tenant|cross[- ]object|another user'?s)\b/i
const AUTHZ_CWE_RE = /^CWE-(?:269|284|285|362|566|639|862|863|1021|1220)$/i
const BUSINESS_LOGIC_RE = /\b(?:business[- ]logic|workflow|step[- ]skip|state[- ]transition|invariant|business[- ]rule|safe[- ]integer|range validation|sign validation|negative (?:amount|value|invoice)|client-supplied amount)\b/i
const BUSINESS_LOGIC_CWE_RE = /^CWE-(?:840|841|472|1284)$/i
const MARKUP_RE = /\b(?:xss|cross[- ]site\s+scripting|html[- ]injection|markup[- ]injection|script[- ]injection|scripting)\b/i
const MARKUP_CWE_RE = /^CWE-(?:79|80|83)$/i
// SQL injection has its own evidence model (control vs. boolean/error differentials), so it must not
// be collapsed into the "disclosure" bucket just because the impact narrative says the rows leak.
// Detection is by machine-readable label only: free-text "SQL injection" stays unmodelled ('other'),
// as it always has, so a narrative word cannot promote an unrelated claim into an ungated class.
const INJECTION_CWE_RE = /^CWE-(?:89|564|943)$/i
const INJECTION_CATEGORY_RE = /^(?:sqli|sql[-_ ]?injection|blind[-_ ]?sqli|injection[-_ ]input)$/i
const DISCLOSURE_RE = /\b(?:disclosure|data[- ]leak|information[- ]leak|leak(?:ed|s|age)?|exposure|expos(?:ed|ure)|sensitive[- ]data|unauthori[sz]ed[- ]read)\b/i
const DISCLOSURE_CWE_RE = /^CWE-(?:200|359|522|532)$/i
/**
 * Active markup only: a real tag carrying an event handler, or an executable scheme inside an
 * attribute. Escaped entities and inert presentation tags (`<b>`, `<h2>`) are not script execution.
 * Kept aligned with the benchmark impact oracle so "HTML injection" never equals "XSS".
 */
export const ACTIVE_MARKUP_RE = /<script\b|<[a-z][^>]*\son\w+\s*=|(?:href|src)\s*=\s*["']?\s*javascript:/i

/** Classify a claim once, from machine-readable descriptors (never from a request path guess). */
export function classifyImpactDescriptor(parts: {
  cwe?: string | null
  category?: string | null
  title?: string | null
  impact?: string | null
  description?: string | null
}): ImpactClass {
  const text = `${parts.title ?? ''} ${parts.impact ?? ''} ${parts.description ?? ''}`
  if (CSRF_RE.test(text) || parts.cwe === 'CWE-352') return 'csrf'
  if (MASS_ASSIGN_RE.test(text) || parts.cwe === 'CWE-915') return 'mass_assignment'
  // A markup claim is executable-content-only; classification is by CWE or explicit scripting words.
  if (MARKUP_CWE_RE.test(parts.cwe ?? '') || MARKUP_RE.test(text) ||
      MARKUP_RE.test(parts.category ?? '')) return 'markup'
  // Injection is classified from its own CWE family or SQL-specific category *before* the impact
  // narrative ("cross-store data disclosure") can rebrand it as information disclosure.
  if (INJECTION_CWE_RE.test(parts.cwe ?? '') ||
      INJECTION_CATEGORY_RE.test((parts.category ?? '').trim())) return 'injection'
  if (/\b(?:vertical|bfla|function[- ]level|privilege[- ]escalation)\b/i.test(text) ||
      /^CWE-(?:269|285|862|863)$/i.test(parts.cwe ?? '')) return 'bfla'
  // Business-logic/workflow claims carry their own impact model (invariant, repeat transition,
  // protected-field delta); they must never fall through to the ungated 'other' bucket.
  if (BUSINESS_LOGIC_CWE_RE.test(parts.cwe ?? '') || BUSINESS_LOGIC_RE.test(text) ||
      BUSINESS_LOGIC_RE.test(parts.category ?? '')) return 'business_logic'
  if (AUTHZ_CWE_RE.test(parts.cwe ?? '') || AUTHZ_RE.test(parts.category ?? '') || AUTHZ_RE.test(text)) return 'authorization'
  // Disclosure has no role/tenant differential of its own; it needs an entitled control or a
  // secret-shaped value. Classified last so authz-titled proof vocabulary keeps precedence.
  if (DISCLOSURE_CWE_RE.test(parts.cwe ?? '') || DISCLOSURE_RE.test(text) ||
      DISCLOSURE_RE.test(parts.category ?? '')) return 'disclosure'
  return 'other'
}

// ---------------------------------------------------------------------------
// Field-level persistence
// ---------------------------------------------------------------------------

const PROTECTED_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:tenant(?:_?id)?|owner(?:_?id)?|role|roles|permissions?|privileges?|is_?admin|admin|is_?owner|price(?:_?cents)?|amount(?:_?cents)?|seat_?limit|seat_?count|seats?|seats_used|credits?|balance|plan(?:_?id)?|tier|visibility|private|shared|secret|api_?key|access_?token|email|password|hash|store|scope|acting(?:_?as)?|account(?:_?id)?|org(?:anization)?(?:_?id)?|identity|impersonat\w*)$/i
/**
 * Role-exclusive function surfaces: a mutation here is the privileged action itself, so the
 * escalation impact is the function-level entitlement, not a protected content column.
 */
const FUNCTION_SURFACE_RE = /(?:^|\/)(?:admin(?:istrator)?|internal|manage|management|staff|superuser|privileged|backoffice|permissions?|roles?|grants?|scopes?|impersonate|feature[-_]?flags?)(?:\/|$)/i
const PRICE_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:price(?:_?cents)?|amount(?:_?cents)?|cost(?:_?cents)?)$/i
/**
 * Account/tenant ownership identifiers that bind an object to a specific principal. Kept distinct
 * from public content-attribution labels (`author`, `subject`) so a public review/comment naming
 * a display author does not defeat publicness unless its value carries an email, canary, or
 * reference principal identity.
 */
const PRINCIPAL_IDENTITY_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:owner(?:_?id)?|tenant(?:_?id)?|user(?:_?id)?|email|username|created_?by)$/i
const ATTRIBUTION_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:author|subject)$/i
const EMAIL_VALUE_RE = /^[^\s@]{1,64}@[^\s@]{1,128}\.[a-z]{2,24}$/i
const SECRET_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:secret|api_?key|access_?token|token|password|hash|private_?note|note|internal|ssn)$/i
/** Tenant/secret canary value shape emitted by the lab canary registry (`rbc_`/`rbs_`). */
const CANARY_VALUE_RE = /\brb[cs]_[a-z0-9]+_[0-9a-f]{6,}\b/i

function isOwnerBoundIdentity(leaf: string, value: string, reference?: ImpactStep | null): boolean {
  if (CANARY_VALUE_RE.test(value)) return true
  if (reference && reference.actor.handle === null) return false
  if (PRINCIPAL_IDENTITY_FIELD_RE.test(leaf)) return true
  if (ATTRIBUTION_FIELD_RE.test(leaf)) {
    const normalized = deRedactIdentity(value.trim())
    if (EMAIL_VALUE_RE.test(normalized)) return true
    if (reference) {
      const refHandle = reference.actor.handle?.toLowerCase() ?? null
      const refTenant = reference.actor.tenant?.toLowerCase() ?? null
      if ((refHandle !== null && normalized === refHandle) || (refTenant !== null && normalized === refTenant)) return true
    }
  }
  return false
}

/**
 * When a read-only chain marks both a collection listing and a child item read as `probe` steps
 * (e.g. actor B lists its own collection, then fetches actor A's item), pick the target item read
 * rather than the prerequisite listing so publicness and cross-tenant checks inspect the claimed
 * object.
 */
function selectPrimaryReadProbe(probeReads: readonly ImpactStep[], controls: readonly ImpactStep[]): ImpactStep | undefined {
  if (probeReads.length <= 1) return probeReads[0]
  let best = probeReads[0]!
  for (const candidate of probeReads.slice(1)) {
    const bestFamily = routeFamily(best.route ?? best.pathAndQuery ?? '')
    const candidateFamily = routeFamily(candidate.route ?? candidate.pathAndQuery ?? '')
    if (bestFamily && candidateFamily && candidateFamily.startsWith(`${bestFamily}/`)) {
      best = candidate
      continue
    }
    const bestHasExactControl = controls.some(control =>
      isReadMethod(control.method) &&
      isSuccess(control.status) &&
      control.actor.handle !== best.actor.handle &&
      sameRoute(control, best) &&
      (control.pathAndQuery === undefined || best.pathAndQuery === undefined || control.pathAndQuery === best.pathAndQuery))
    const candidateHasExactControl = controls.some(control =>
      isReadMethod(control.method) &&
      isSuccess(control.status) &&
      control.actor.handle !== candidate.actor.handle &&
      sameRoute(control, candidate) &&
      (control.pathAndQuery === undefined || candidate.pathAndQuery === undefined || control.pathAndQuery === candidate.pathAndQuery))
    if (!bestHasExactControl && candidateHasExactControl) {
      best = candidate
    }
  }
  return best
}

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

function isDeleteStep(step: Pick<ImpactStep, 'method' | 'requestJson'>): boolean {
  return isMutatingMethod(step.method) && (step.method ?? '').toUpperCase() === 'DELETE' && !isReadOnlyGraphqlRequest(step)
}

function findPersistence(steps: readonly ImpactStep[], probe: ImpactStep): PersistenceProof {
  const reads = steps.filter(step => isReadMethod(step.method) && step.json !== undefined && step.json !== null)
  const before = [...reads].reverse().find(step => step.status !== null && isSuccess(step.status) && steps.indexOf(step) < steps.indexOf(probe)) ?? null
  // The readback must be a *separate GET* after the mutation (never the mutation response echo).
  // A different actor is preferred, but a same-actor self-service read is still a clean GET: the
  // mutation response itself is excluded because it is not a read method.
  const after = reads.find(step => steps.indexOf(step) > steps.indexOf(probe) &&
    (step.arm === 'control' || isSuccess(step.status) || step.status === 404 || step.status === 410)) ?? null
  // A successful DELETE proves persistence when the separate readback reports the resource gone,
  // even if the tombstone response carries no JSON body. For any other verb a 404 readback is not a
  // state delta (the route may simply not be readable), so this exception is DELETE-only.
  const deletedRead = !after && isDeleteStep(probe)
    ? steps.find(step => steps.indexOf(step) > steps.indexOf(probe) && isReadMethod(step.method) &&
      (step.status === 404 || step.status === 410)) ?? null
    : null
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
  if (!after && !deletedRead) return { persisted: false, reason: 'no separate post-mutation GET readback exists; the mutation echo alone is not persistence', before, after, delta, clean, controlDelta }
  if (deletedRead) {
    return { persisted: true, reason: `the post-mutation readback reports the resource removed (HTTP ${deletedRead.status})`, before, after: deletedRead, delta, clean, controlDelta }
  }
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

/** Reject patterns that would match anything: the host must re-observe the value, not trust a claim. */
function isSpecificCredentialPattern(pattern: unknown): pattern is string {
  if (typeof pattern !== 'string') return false
  const value = pattern.trim()
  if (value.length < 8 || value.length > 200) return false
  if (/\.\*|\.\+|\\s\*|\\s\+|\(\?/.test(value)) return false
  try {
    // Must compile; a broken pattern is not evidence.
    new RegExp(value)
    return true
  } catch {
    return false
  }
}

/**
 * Credential-shaped values declared by the proof: a pattern that matches the probe response and no
 * control response. Returned patterns are the evidence; the caller still requires an authorization
 * boundary (a denied sibling arm or a role differential) before treating it as a disclosure.
 */
function credentialPatternEvidence(
  patterns: readonly string[] | null | undefined,
  probe: ImpactStep,
  controls: readonly ImpactStep[],
): string[] {
  if (!patterns?.length) return []
  const probeBody = typeof probe.body === 'string' ? probe.body : ''
  if (!probeBody) return []
  const controlBodies = controls.map(control => (typeof control.body === 'string' ? control.body : '')).join('\n')
  const matched: string[] = []
  for (const pattern of patterns) {
    if (!isSpecificCredentialPattern(pattern)) continue
    const expression = new RegExp(pattern)
    if (!expression.test(probeBody)) continue
    if (controlBodies && expression.test(controlBodies)) continue
    matched.push(pattern)
  }
  return matched.slice(0, 4)
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

const STRONG_OBJECT_ID_SEGMENT_RE = /^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{8,}|:[a-z0-9_]+|\{[a-z0-9_]+\}|[a-z]{1,12}[_-][a-z0-9_-]*\d[a-z0-9_-]*|[a-z]{1,6}\d+)$/i
const PREFIXED_SLUG_OBJECT_ID_RE = /^[a-z]{2,6}[_-][a-z0-9]{3,}$/i
const ROUTE_PREFIX_OR_VERSION_RE = /^(?:api|v\d+|api[-_]?v\d+|v\d+[-_](?:alpha|beta|rc)\d*)$/i
const NON_OBJECT_SEGMENT_RE = /^(?:api|v\d+|api[-_]?v\d+|v\d+[-_](?:alpha|beta|rc)\d*|oauth2?|http2|2fa|utf[-_]?8|sha[-_]?256|base[-_]?64|health[-_]?check|sign[-_]?(?:in|up|out)|log[-_]?(?:in|out)|reset[-_]?password|forgot[-_]?password|api[-_]?keys?|webhook[-_]?test|feature[-_]?flags?|user[-_]?profile|audit[-_]?logs?|credit[-_]?cards?|payment[-_]?methods?|rate[-_]?limits?)$/i
const OBJECT_QUERY_PARAM_RE = /(?:^|[?&])(?:[a-z0-9_]*_?id|tenant|org|organization|account|user|owner|customer|email|slug|key|number|token|code|handle)=[^&]+/i
const GRAPHQL_OBJECT_KEY_RE = /^(?:[a-z0-9_]*_?id|tenant|org|organization|account|user|owner|customer|email|slug|key|number|token|code|handle)$/i
const GRAPHQL_INLINE_OBJECT_ARG_RE = /\(\s*[^)]*\b(?:[a-z0-9_]*_?id|tenant|org|organization|account|user|owner|customer|email|slug|key|number|token|code|handle)\s*:\s*(?:"[^"\s][^"]*"|\d+)/i
const GRAPHQL_VAR_OBJECT_ARG_RE = /\(\s*[^)]*\b(?:[a-z0-9_]*_?id|tenant|org|organization|account|user|owner|customer|email|slug|key|number|token|code|handle)\s*:\s*\$([A-Za-z_][A-Za-z0-9_]*)/gi
const TENANT_SCOPE_FIELD_RE = /^(?:[a-z0-9]+[_-])*(?:tenant|org|organization|workspace)(?:_?id)?$/i

function hasNonEmptyScalar(val: unknown): boolean {
  return (typeof val === 'string' && val.trim().length > 0) || (typeof val === 'number' && Number.isFinite(val))
}

/**
 * True when a request targets a specific object (concrete ID segment in the path, an explicit
 * identifier query parameter, or a read-only GraphQL query carrying an object-identifier argument
 * or variable) rather than a bare collection listing like `GET /api/v1/charges`.
 */
export function isObjectScopedRequest(
  step: Pick<ImpactStep, 'route' | 'pathAndQuery'> & Partial<Pick<ImpactStep, 'method' | 'requestJson'>>,
): boolean {
  if (step.method && step.requestJson !== undefined && isReadOnlyGraphqlRequest({ method: step.method, requestJson: step.requestJson })) {
    const body = step.requestJson as { query?: unknown; variables?: unknown }
    const vars = body.variables && typeof body.variables === 'object' && !Array.isArray(body.variables)
      ? (body.variables as Record<string, unknown>)
      : null
    if (vars) {
      for (const [key, val] of Object.entries(vars)) {
        if (GRAPHQL_OBJECT_KEY_RE.test(key) && hasNonEmptyScalar(val)) return true
      }
    }
    if (typeof body.query === 'string') {
      if (GRAPHQL_INLINE_OBJECT_ARG_RE.test(body.query)) return true
      if (vars) {
        GRAPHQL_VAR_OBJECT_ARG_RE.lastIndex = 0
        let match: RegExpExecArray | null
        while ((match = GRAPHQL_VAR_OBJECT_ARG_RE.exec(body.query)) !== null) {
          if (hasNonEmptyScalar(vars[match[1]!])) return true
        }
      }
    }
  }
  const pathAndQuery = (step.pathAndQuery ?? step.route ?? '').trim()
  if (!pathAndQuery) return false
  const [pathname, query = ''] = pathAndQuery.split('?', 2)
  if (query && OBJECT_QUERY_PARAM_RE.test(`?${query}`)) return true
  const segments = pathname.split('/').filter(Boolean)
  for (let i = 0; i < segments.length; i += 1) {
    const seg = segments[i]!
    if (NON_OBJECT_SEGMENT_RE.test(seg)) continue
    if (STRONG_OBJECT_ID_SEGMENT_RE.test(seg)) return true
    if (i >= 1 && PREFIXED_SLUG_OBJECT_ID_RE.test(seg) && !ROUTE_PREFIX_OR_VERSION_RE.test(segments[i - 1]!)) {
      return true
    }
  }
  return false
}

/**
 * True when a probe response on a bare collection GET carries explicit cross-tenant or
 * foreign-owner disclosure evidence (not merely the caller's own tenant records):
 *  - a known foreign tenant/actor identity (from a foreign-tenant control or declared resourceTenant)
 *    appears in an owner/tenant field of the probe response, OR
 *  - the collection response spans >=2 distinct tenant/org/workspace IDs (unscoped multi-tenant dump).
 */
export function hasForeignTenantOrOwnerDisclosure(
  steps: readonly ImpactStep[],
  probe: ImpactStep,
  declaredResourceTenant?: string | null,
): boolean {
  if (probe.json === undefined || probe.json === null || typeof probe.json !== 'object') return false
  const flat = flattenJson(probe.json)
  if (flat.size === 0) return false
  const probeTenant = probe.actor.tenant?.toLowerCase() ?? null
  const probeHandle = probe.actor.handle?.toLowerCase() ?? null
  const foreignTenants = new Set<string>()
  const foreignHandles = new Set<string>()
  if (declaredResourceTenant) {
    const t = declaredResourceTenant.trim().toLowerCase()
    if (t && t !== probeTenant) foreignTenants.add(t)
  }
  for (const step of steps) {
    if (step === probe) continue
    const t = step.actor.tenant?.toLowerCase() ?? null
    const h = step.actor.handle?.toLowerCase() ?? null
    if (t && probeTenant && t !== probeTenant) {
      foreignTenants.add(t)
      if (h && h !== probeHandle) foreignHandles.add(h)
    }
  }
  const observedTenants = new Set<string>()
  for (const [path, rawValue] of flat) {
    const leaf = deRedactIdentity(path.replace(/\[\d+\]/g, '').split('.').pop() ?? '')
    const val = deRedactIdentity(rawValue.trim())
    if (!val || val === 'null' || val === 'undefined' || val === '0' || val === 'false' || val === 'true') continue
    if (TENANT_SCOPE_FIELD_RE.test(leaf)) {
      observedTenants.add(val)
      if (foreignTenants.has(val)) return true
    }
    if (OWNER_SCOPED_RE.test(leaf)) {
      if (foreignHandles.has(val) || foreignTenants.has(val)) return true
      for (const ft of foreignTenants) {
        if (ft.length >= 3 && val.includes(ft) && (!probeTenant || !val.includes(probeTenant))) return true
      }
      if (probeTenant && val.includes('@')) {
        const domain = val.split('@')[1] ?? ''
        for (const ft of foreignTenants) {
          if (ft.length >= 3 && domain.includes(ft) && !domain.includes(probeTenant)) return true
        }
      }
    }
    const canaryMatch = /\brbc_([a-z0-9-]+)_[0-9a-f]{8,}\b/i.exec(val)
    if (canaryMatch && probeTenant && canaryMatch[1]!.toLowerCase() !== probeTenant.replace(/[^a-z0-9-]/g, '')) {
      return true
    }
  }
  if (observedTenants.size >= 2) return true
  return false
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
  const requiredRole = normalizeRole(input.requiredRole)
  const requiredRank = roleRank(requiredRole)
  const mutatingProbe = probeSuccesses.find(step => stepMutatesState(step)) ?? null
  const primaryReadProbe = selectPrimaryReadProbe(probeSuccesses.filter(step => isReadMethod(step.method)), controls)
  const probe = mutatingProbe ?? primaryReadProbe ?? probeSuccesses[0] ?? probes[0]
  // A denial proves *this actor* is unentitled only when the denied control is a peer of the probe
  // (same tenant, or both unknown). A cross-tenant control that is denied shows tenant isolation,
  // which is the app working, not a boundary the probe crossed.
  const probeTenant = probe?.actor.tenant ?? null
  const declaredResourceTenant = input.resourceTenant?.toLowerCase() ?? null
  // A claim-declared resource tenant is untrusted: the mirror direction only counts when an actor
  // in that tenant actually read the same resource successfully (a control on the same object).
  const mirrorCorroborated = declaredResourceTenant !== null && probe !== undefined && steps.some(step =>
    step.actor.tenant === declaredResourceTenant &&
    isReadMethod(step.method) &&
    isSuccess(step.status) &&
    sameRoute(step, probe))
  // A cross-tenant mutation makes an *unauthenticated* denial meaningless as an authorization
  // control: a 401 for an anonymous caller proves the route requires authentication, not that the
  // probe crossed an ownership boundary (the probe already authenticated). This was the
  // `GET /api/me`-style misattribution where `anonAssign=401` was offered as the control for a
  // viewer writing another tenant's ticket.
  const crossTenantMutation = declaredResourceTenant !== null && probeTenant !== null && declaredResourceTenant !== probeTenant
  const peerDenial = (control: ImpactStep): boolean => {
    const tenant = control.actor.tenant ?? null
    const unauthenticated = control.actor.handle === null && tenant === null
    if (unauthenticated && crossTenantMutation && mutatingProbe !== undefined) return false
    if (tenant === null || probeTenant === null) return true
    return tenant === probeTenant ||
      (mirrorCorroborated && declaredResourceTenant !== null && tenant === declaredResourceTenant && declaredResourceTenant !== probeTenant)
  }
  const boundaryControlDenied = deniedControls.some(control =>
    peerDenial(control) &&
    (firstProbeIndex === -1 || steps.indexOf(control) < firstProbeIndex) &&
    probeSuccesses.some(success => sameRoute(control, success)))

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
  // The control read must be on the same resource tree as the probe (the item route or its parent
  // collection); a same-tenant `/api/me` read by two actors is not a victim readback for the object
  // the probe mutated.
  const crossTenantControlRead = controls.some(control =>
    isReadMethod(control.method) &&
    isSuccess(control.status) &&
    control.json !== undefined &&
    relatedRoute(control, probe) &&
    Boolean(control.actor.tenant && probe.actor.tenant && control.actor.tenant !== probe.actor.tenant))
  // A claim-declared `resourceTenant` is model-supplied; it only counts when a signed control arm
  // corroborates the boundary (a denial on the same route, or a read served to the other tenant).
  const crossTenant = crossTenantControlRead ||
    Boolean(resourceTenant && probe.actor.tenant && resourceTenant !== probe.actor.tenant && boundaryControlDenied)
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
    // A cross-tenant write needs a peer-entitlement control, not an anonymous 401: an unauthenticated
    // rejection only proves the login gate works, not that an authenticated tenant's object boundary
    // was crossed. A control read served to the resource tenant is the other legitimate baseline.
    if (crossTenant && !vertical && !crossTenantControlRead) {
      const authenticatedPeerDenial = deniedControls.some(control =>
        sameRoute(control, mutatingProbe) &&
        control.actor.handle !== null &&
        (roleRank(control.actor.role) === null ||
          roleRank(mutatingProbe.actor.role) === null ||
          roleRank(control.actor.role)! <= roleRank(mutatingProbe.actor.role)!))
      if (!authenticatedPeerDenial) {
        return {
          required: true,
          satisfied: false,
          reason: `Cross-tenant write ${mutatingProbe.id} is backed only by an anonymous/lower-evidence control; an unauthenticated 401 is not a tenant boundary. Add a denied control from an authenticated non-privileged actor in the same tenant as the probe, or a control read served to the resource tenant.`,
          evidence: base,
        }
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
    // field. A declared oracle event is a requirement the evidence must satisfy, never a substitute
    // for a missing differential (an LLM can declare anything).
    //
    // Function-level vertical escalation is its own impact model: a host-signed lower role performed
    // a mutating action on a role-exclusive function surface (admin/manage/role/grant/...) and the
    // change persisted. The privileged *function* is the asset, so demanding a content-column name
    // from the generic protected list would dismiss every flag/config action. A content write on a
    // non-function route (a viewer editing a workspace) still needs a protected field — the K=6 FP.
    const functionLevelEscalation = requiredRank !== null && roleDifferential &&
      probes.some(step => isMutatingMethod(step.method) && isSuccess(step.status) && FUNCTION_SURFACE_RE.test(step.route ?? ''))
    const oracleDeclared = hasOracle(input.oracleEvents, ['privilege_escalation', 'mass_assignment', 'invariant_violation', 'cross_tenant_write', 'state_delta'])
    if (!crossTenant && protectedChanged.length === 0 && !functionLevelEscalation) {
      return { required: true, satisfied: false, reason: `The persisted change (${base.changedFields.slice(0, 6).join(', ') || 'none'}) is not a protected field and no impact-oracle event is declared; a state echo is not impact.`, evidence: base }
    }
    if (boundaryControlDenied && !crossTenant && protectedChanged.length === 0 && !functionLevelEscalation) {
      return { required: true, satisfied: false, reason: 'The control arm was correctly denied and the probe mutated state, but the change is neither cross-tenant nor a protected field; a self-service write is not escalation.', evidence: base }
    }
    return {
      required: true,
      satisfied: true,
      reason: `${vertical || functionLevelEscalation ? 'Vertical' : 'Object-level'} impact: ${escalationReason || (crossTenant ? 'cross-tenant resource access' : 'persisted protected-field change')}; ${persistence.reason}${protectedChanged.length ? `; protected fields: ${protectedChanged.slice(0, 6).join(', ')}` : ''}${functionLevelEscalation ? '; role-gated function surface mutated by a lower role' : ''}${oracleDeclared ? `; oracle ${input.oracleEvents!.join(',')}` : ''}.`,
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
  const probeIsFunctionSurface = FUNCTION_SURFACE_RE.test(probe.route ?? '')
  const probeIsObjectScoped = isObjectScopedRequest(probe)
  // A read-only vertical differential with a denied control only confirms on a role-exclusive
  // privileged/function surface (`/admin`, `/audit`, `/manage`, ...) under BFLA. On a non-admin
  // bare collection GET (e.g. `GET /api/v1/charges`), a higher role receiving 401/403 while a
  // lower role reads its own collection is an inverted/role-partitioned control, NOT BOLA or BFLA.
  if (roleDifferential && boundaryControlDenied && vertical && probeIsFunctionSurface) {
    return {
      required: true,
      satisfied: true,
      reason: `Vertical read differential: ${escalationReason}; the sibling control on the same privileged route was denied while the probe was served data.`,
      evidence: base,
    }
  }
  if (crossTenant) {
    // A route that declares itself public (`/public`, `/share`, `/embed`, …) is readable by anyone
    // who holds the link; serving it to another tenant or anonymously is by design. Such a claim
    // needs owner-scoped private data, not merely a cross-tenant 200.
    const publicRoute = steps.some(step => PUBLIC_ROUTE_RE.test(step.route ?? ''))
    if (publicRoute) {
      const disclosure = assessReadDisclosure({ steps, probe })
      base.disclosureFields = disclosure.fields
      if (!disclosure.satisfied) {
        return {
          required: true,
          satisfied: false,
          reason: `Cross-tenant claim dismissed: the route declares itself public and ${disclosure.reason}`,
          evidence: base,
        }
      }
    }
    // Evidence-based publicness for routes whose path carries no public marker: a non-owner or
    // anonymous caller served the *same* payload the owner reference receives is reading the same
    // public object. Catalog/product surfaces (storefront browse, item detail, public store page)
    // are readable by design; a genuine crossing still differs, or binds owner-scoped data.
    const publicness = assessPublicness({ steps, probe })
    if (publicness.public && !roleDifferential) {
      return {
        required: true,
        satisfied: false,
        reason: `Cross-tenant claim dismissed (publicness): ${publicness.reason}.`,
        evidence: base,
      }
    }
    // A cross-tenant read backed ONLY by a parent-collection listing (no same-route owner
    // reference to compare for publicness and no denied control on the route) must expose an
    // owner-scoped principal identifier, tenant canary, or secret fingerprint; otherwise any
    // public item fetched after listing another tenant's collection would bypass publicness.
    const sameRouteControlRead = controls.some(control =>
      isReadMethod(control.method) &&
      isSuccess(control.status) &&
      control.json !== undefined &&
      sameRoute(control, probe) &&
      Boolean(control.actor.tenant && probe.actor.tenant && control.actor.tenant !== probe.actor.tenant))
    if (!sameRouteControlRead && !boundaryControlDenied && !roleDifferential) {
      const probeFlat = probe.json !== undefined && probe.json !== null && typeof probe.json === 'object'
        ? flattenJson(probe.json)
        : null
      const hasSecretMatch = (probe.secretMatches?.length ?? 0) > 0
      const hasPrincipalOrCanary = hasSecretMatch || (probeFlat
        ? [...probeFlat.entries()].some(([path, value]) => {
          if (!value || value === 'null') return false
          const leaf = (path.replace(/\[\d+\]/g, '').split('.').pop() ?? '').toLowerCase()
          return isOwnerBoundIdentity(leaf, value)
        })
        : false)
      if (!hasPrincipalOrCanary) {
        return {
          required: true,
          satisfied: false,
          reason: 'Cross-tenant claim dismissed (publicness): no same-route owner reference or denied control establishes non-publicness on this route, and the response exposes no owner-scoped principal identifier or tenant canary.',
          evidence: base,
        }
      }
    }
    return {
      required: true,
      satisfied: true,
      reason: `Cross-tenant read: the probe actor (tenant ${probe.actor.tenant ?? 'unknown'}) received a record served to a control actor in another tenant; the tenant boundary is the disclosure.`,
      evidence: base,
    }
  }
  const probeFingerprints = new Set<string>(probe.secretMatches ?? [])
  const controlFingerprints = new Set<string>(controls.flatMap(control => [...(control.secretMatches ?? [])]))
  const disclosedFingerprints = [...probeFingerprints].filter(fingerprint => !controlFingerprints.has(fingerprint))
  if (disclosedFingerprints.length > 0) {
    return {
      required: true,
      satisfied: true,
      reason: `Credential-shaped value(s) disclosed: ${disclosedFingerprints.length} pre-redaction secret fingerprint(s) appear in the probe response and not in any entitled control.`,
      evidence: base,
    }
  }
  // A credential-bearing response proves disclosure only when the caller was outside the route's
  // entitlement at the same time: a denied sibling arm on the same route, or a role differential.
  // The pattern is re-tested against the recorded bodies, so a declared-but-absent value (or one a
  // control also returns, i.e. a public constant) never confirms.
  const patternEvidence = credentialPatternEvidence(input.credentialPatterns, probe, controls)
  if (patternEvidence.length > 0 && probe.actor.handle !== null && (boundaryControlDenied || roleDifferential)) {
    return {
      required: true,
      satisfied: true,
      reason: `Credential-shaped value disclosed: the probe response matches ${patternEvidence.length} declared credential shape(s) absent from every control, under a ${boundaryControlDenied ? 'denied sibling control' : 'role differential'}.`,
      evidence: base,
    }
  }
  if (!probeIsObjectScoped && !(vertical && probeIsFunctionSurface)) {
    const foreignCollectionData = hasForeignTenantOrOwnerDisclosure(steps, probe, resourceTenant)
    if (!foreignCollectionData) {
      return {
        required: true,
        satisfied: false,
        reason: `Bare collection GET (${probe.route ?? probe.pathAndQuery ?? '/'}) lacks impact evidence: without an object identifier, ${vertical ? 'read-only BFLA' : 'object-level authorization (CWE-639)'} requires explicit cross-tenant or foreign-owner data disclosure; an inverted role denial while a caller reads its own collection is not an access-control crossing.`,
        evidence: base,
      }
    }
  }
  const disclosure = assessReadDisclosure({ steps, probe })
  base.disclosureFields = disclosure.fields
  // An anonymous (or non-owner) read that mirrors the owner reference on the same route exposes the
  // same public record — a catalog listing/item — not an owner-scoped disclosure. Genuine private
  // reads differ from the reference or bind an owner-scoped identity, so they are unaffected.
  const publicness = assessPublicness({ steps, probe })
  if (publicness.public && !roleDifferential) {
    return {
      required: true,
      satisfied: false,
      reason: `Read claim dismissed (publicness): ${publicness.reason}.`,
      evidence: base,
    }
  }
  if (disclosure.satisfied && !roleDifferential && !crossTenant && !boundaryControlDenied) {
    // Same-tenant, same-role read: the tenant is the object boundary, so an owner/identity field
    // alone is in policy (viewer reading a peer's space). Only private/secret data proves impact.
    const privateFields = disclosure.fields.filter(path => PRIVATE_DATA_RE.test(path.split('.').pop() ?? ''))
    if (privateFields.length === 0) {
      return {
        required: true,
        satisfied: false,
        reason: `Same-tenant read of owner-scoped field(s) (${disclosure.fields.slice(0, 6).join(', ')}) without a role/tenant differential: tenant content is readable by every member, so no private data was disclosed.`,
        evidence: base,
      }
    }
    base.disclosureFields = privateFields
  }
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
  // A public/anonymous read that returns the same body proves nothing about entitlement. Compare
  // against every anonymous control on the route: the variant body must differ from it.
  const anonymousBodies = steps
    .filter(step => step.arm === 'control' && step.actor.handle === null && typeof step.body === 'string' && step.body.length > 0)
    .map(step => step.body as string)
  const probeBodyText = typeof probe.body === 'string' ? probe.body : safeJson(probe.json)
  if (anonymousBodies.some(body => body === probeBodyText)) {
    return { satisfied: false, fields: [], reason: 'The probe body is byte-identical to an anonymous control read, so the response is public data rather than an entitlement crossing.' }
  }
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
    // A value an anonymous caller also receives is public, not a protected disclosure.
    if (anonymousBodies.some(body => body.includes(rawValue) || body.includes(value))) continue
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
  if (protectedFields.length > 0 && protectedFields.every(isPriceField) && !oracleDeclared) {
    return {
      required: true,
      satisfied: false,
      reason: `A caller-chosen money value (${protectedFields.slice(0, 6).join(', ')}) persisted, but no catalog or invariant event binds it: a caller-supplied amount is not mass assignment of an entitlement.`,
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
// Business logic / workflow integrity
// ---------------------------------------------------------------------------

export interface BusinessLogicAssessment extends ImpactAssessment {
  evidence: {
    persisted: boolean
    changedFields: string[]
    protectedFields: string[]
    repeatedTransition: boolean
    boundary: boolean
    oracleDeclared: boolean
  }
}

function sameMutatingRequest(a: ImpactStep, b: ImpactStep): boolean {
  if (!stepMutatesState(a) || !stepMutatesState(b)) return false
  if ((a.method ?? '').toUpperCase() !== (b.method ?? '').toUpperCase()) return false
  if ((a.route ?? '') === '' || a.route !== b.route) return false
  const aBody = a.requestJson === undefined ? null : JSON.stringify(a.requestJson)
  const bBody = b.requestJson === undefined ? null : JSON.stringify(b.requestJson)
  return aBody === bBody
}

/**
 * Business-logic/workflow claims assert an invariant the server never modelled in HTTP evidence.
 * A self-service owner mutation of a field the caller is entitled to edit is in policy; impact
 * requires one of: a boundary differential, the same terminal transition accepted twice, a
 * persisted *protected* field change, or a declared invariant/workflow oracle event.
 */
export function assessBusinessLogicImpact(input: ImpactInput): BusinessLogicAssessment {
  const steps = input.steps
  const probes = steps.filter(step => step.arm === 'probe')
  const mutatingProbe = probes.find(step => stepMutatesState(step) && isSuccess(step.status)) ?? null
  const labels = {
    persisted: false,
    changedFields: [] as string[],
    protectedFields: [] as string[],
    repeatedTransition: false,
    boundary: false,
    oracleDeclared: false,
  }
  if (!mutatingProbe) {
    return {
      required: true,
      satisfied: false,
      reason: 'Business-logic claim has no successful mutating probe step: an asserted invariant needs a state mutation that moved it.',
      evidence: labels,
    }
  }
  const probeTenant = mutatingProbe.actor.tenant ?? null
  const resourceTenant = input.resourceTenant?.toLowerCase() ?? null
  const mirrorCorroborated = resourceTenant !== null && steps.some(step =>
    step.actor.tenant === resourceTenant &&
    isReadMethod(step.method) &&
    isSuccess(step.status) &&
    sameRoute(step, mutatingProbe))
  const crossTenantWrite = resourceTenant !== null && probeTenant !== null && resourceTenant !== probeTenant
  const peerDenial = (control: ImpactStep): boolean => {
    const tenant = control.actor.tenant ?? null
    const unauthenticated = control.actor.handle === null && tenant === null
    // `anon=401` proves authentication, not authorization, for a cross-tenant write.
    if (unauthenticated && crossTenantWrite) return false
    if (tenant === null || probeTenant === null) return true
    return tenant === probeTenant ||
      (mirrorCorroborated && resourceTenant !== null && tenant === resourceTenant && resourceTenant !== probeTenant)
  }
  const boundaryControlDenied = steps.some(control =>
    control.arm === 'control' &&
    peerDenial(control) &&
    isDenied(control.status) &&
    sameRoute(control, mutatingProbe) &&
    steps.indexOf(control) < steps.indexOf(mutatingProbe))
  const crossTenant = Boolean(resourceTenant && mutatingProbe.actor.tenant && resourceTenant !== mutatingProbe.actor.tenant)
  const requiredRank = roleRank(normalizeRole(input.requiredRole) ?? null)
  const probeRank = roleRank(mutatingProbe.actor.role)
  const roleDifferential = requiredRank !== null && probeRank !== null && probeRank < requiredRank
  labels.boundary = boundaryControlDenied || crossTenant || roleDifferential
  if (labels.boundary) {
    return {
      required: true,
      satisfied: true,
      reason: 'Business-logic claim rides on a role/tenant boundary differential (the probe actor is outside the entitlement the control demonstrates).',
      evidence: labels,
    }
  }
  // The workflow step-skip shape: the identical terminal transition accepted a second time.
  labels.repeatedTransition = steps.some(other =>
    other !== mutatingProbe && isSuccess(other.status) && sameMutatingRequest(other, mutatingProbe))
  if (labels.repeatedTransition) {
    return {
      required: true,
      satisfied: true,
      reason: 'A terminal transition was accepted a second time for the same resource (the object did not leave its prior state).',
      evidence: labels,
    }
  }
  const reads = steps.filter(step => isReadMethod(step.method) && step.json !== undefined && step.json !== null)
  const beforeRead = [...reads].reverse().find(step => steps.indexOf(step) < steps.indexOf(mutatingProbe) && isSuccess(step.status)) ?? null
  const afterRead = reads.find(step => steps.indexOf(step) > steps.indexOf(mutatingProbe) &&
    (isSuccess(step.status) || step.status === 404 || step.status === 410)) ?? null
  const delta = beforeRead && afterRead ? stateDelta(beforeRead.json, afterRead.json, afterRead.status) : null
  labels.persisted = Boolean(delta && (delta.deleted || delta.changed.length + delta.added.length + delta.removed.length > 0))
  if (delta) {
    labels.changedFields = [...delta.changed, ...delta.added, ...delta.removed]
  }
  labels.protectedFields = labels.changedFields.filter(isProtectedField)
  // K=6 cross-talk guard: a delta caused by another worker's write is not this probe's impact.
  // The after-read must reflect a value this probe sent (or a marker it injected).
  const sent = new Set<string>()
  if (mutatingProbe.requestJson !== undefined) {
    for (const value of flattenJson(mutatingProbe.requestJson).values()) {
      sent.add(value)
      for (const token of value.slice(0, 256).match(/[A-Za-z0-9_-]{8,64}/g) ?? []) sent.add(token)
    }
  }
  const afterFields = afterRead?.json !== undefined ? flattenJson(afterRead.json) : new Map<string, string>()
  const attributable = labels.changedFields.some(path => sent.has(afterFields.get(path) ?? '')) ||
    (afterRead !== null && [...sent].some(token => String(afterRead.body ?? '').includes(token)))
  if (labels.persisted && !attributable && !labels.oracleDeclared) {
    return {
      required: true,
      satisfied: false,
      reason: `The state delta (${labels.changedFields.slice(0, 6).join(', ')}) does not reflect any value this probe sent; a concurrent writer cannot be excluded, so it is not this proof's impact.`,
      evidence: labels,
    }
  }
  labels.oracleDeclared = hasOracle(input.oracleEvents, ['invariant_violation', 'workflow_skip', 'race_double_spend', 'state_delta', 'privilege_escalation'])
  // A create-time caller-chosen *money* value (invoice amount, price) is not an invariant: the app
  // may legitimately accept it, and no control arm binds it. Require the endpoint's declared
  // invariant event for price/amount-only persistences on create-shaped probes.
  const priceOnly = labels.protectedFields.length > 0 && labels.protectedFields.every(isPriceField)
  if (labels.persisted && priceOnly && !labels.oracleDeclared) {
    return {
      required: true,
      satisfied: false,
      reason: `A caller-chosen money value (${labels.protectedFields.slice(0, 6).join(', ')}) persisted, but no invariant event is declared and no control arm binds the value: a caller-supplied amount is not an invariant violation.`,
      evidence: labels,
    }
  }
  if (labels.persisted && (labels.protectedFields.length > 0 || labels.oracleDeclared)) {
    return {
      required: true,
      satisfied: true,
      reason: `Persisted ${labels.protectedFields.length ? `protected field(s) ${labels.protectedFields.slice(0, 6).join(', ')}` : 'state change with a declared invariant event'}${labels.oracleDeclared ? `; oracle ${input.oracleEvents!.join(',')}` : ''}`,
      evidence: labels,
    }
  }
  return {
    required: true,
    satisfied: false,
    reason: labels.persisted
      ? `The mutation persisted only non-protected field(s) (${labels.changedFields.slice(0, 6).join(', ') || 'none'}) by an entitled actor in its own tenant: a self-service state change is not a business-invariant violation (no boundary, no repeated terminal transition, no protected field, no declared invariant event).`
      : 'No before/after readback proves the asserted invariant moved; the mutation response echo is not a state delta.',
    evidence: labels,
  }
}

// ---------------------------------------------------------------------------
// Boolean differential (boolean-only SQL injection and similar paired probes)
// ---------------------------------------------------------------------------

/**
 * One arm of a paired boolean-differential probe. The recipe sends the *same* request shape twice
 * per round; only the injected predicate value differs between the control and probe arms.
 */
export interface BooleanDifferentialArm {
  status: number | null
  method?: string
  pathAndQuery?: string
  requestJson?: unknown
  requestHeaders?: Record<string, string> | null
  json?: unknown
  body?: string
}

export interface BooleanDifferentialRound {
  control: BooleanDifferentialArm
  probe: BooleanDifferentialArm
}

export interface BooleanDifferentialAssessment extends ImpactAssessment {
  evidence: {
    rounds: number
    stable: boolean
    controlStable: boolean
    probeStable: boolean
    requestShapeMismatch: boolean
    serverErrors: boolean
    echoedOnly: boolean
    changedPaths: string[]
    echoPaths: string[]
  }
}

const booleanVolatileHeaders = new Set([
  'authorization', 'cookie', 'proxy-authorization', 'x-request-id', 'x-correlation-id',
  'x-trace-id', 'traceparent', 'tracestate', 'date', 'set-cookie',
])

const nonceLikeRun = /[A-Za-z0-9_-]{16,}/g
const uuidText = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

function leafClassOf(value: string, param?: string | null): string {
  if (value === '') return 'empty'
  if (uuidText.test(value)) return 'uuid'
  if (/^-?\d+$/.test(value)) {
    const n = Number(value)
    return n === 0 ? 'num:zero' : n === 1 ? 'num:one' : n > 0 ? 'num:many' : 'num:negative'
  }
  if (/^(?:true|false)$/i.test(value)) return `bool:${value.toLowerCase()}`
  if (param && value.toLowerCase().includes(param.toLowerCase())) return 'predicate'
  if (/^[A-Za-z0-9_+/=-]{16,}$/.test(value)) return 'token'
  return value.length <= 32 ? 'short' : 'long'
}

/**
 * Coarse structural signature: presence of keys, array length buckets, primitive *classes* and
 * status classes. Raw text is deliberately not compared, so a rotating nonce or timestamp cannot
 * masquerade as a differential.
 */
function structuralSignature(value: unknown, param?: string | null): Map<string, string> {
  const out = new Map<string, string>()
  const walk = (node: unknown, path: string, depth: number): void => {
    if (depth > 6 || out.size >= 256) return
    const key = path || '$'
    if (node === null || node === undefined) { out.set(key, 'null'); return }
    if (Array.isArray(node)) {
      out.set(`${key}[]`, node.length === 0 ? 'len:0' : node.length === 1 ? 'len:1' : node.length <= 3 ? 'len:few' : 'len:many')
      for (let i = 0; i < Math.min(node.length, 8); i += 1) walk(node[i], `${key}[${i}]`, depth + 1)
      return
    }
    if (typeof node === 'object') {
      const entries = Object.entries(node as Record<string, unknown>).slice(0, 64)
      for (const [childKey, child] of entries) walk(child, path ? `${path}.${childKey}` : childKey, depth + 1)
      return
    }
    out.set(key, leafClassOf(String(node), param))
  }
  walk(value, '', 0)
  if (out.size === 0) out.set('$', 'empty')
  return out
}

function bodySignature(arm: BooleanDifferentialArm, param?: string | null): Map<string, string> {
  const signature = arm.json !== undefined
    ? structuralSignature(arm.json, param)
    : (() => {
        const text = String(arm.body ?? '')
        const out = new Map<string, string>()
        out.set('body.length', text.length === 0 ? 'len:0' : text.length < 64 ? 'len:small' : text.length < 1024 ? 'len:medium' : 'len:large')
        out.set('body.lines', ((): string => {
          const lines = text.split('\n').length
          return lines <= 1 ? 'len:1' : lines <= 8 ? 'len:few' : 'len:many'
        })())
        // Non-JSON payloads (XML/HTML/text) still carry structure: the number of tags/elements is a
        // stable shape signal for a boolean differential (e.g. two `<item>` rows vs none).
        const tags = (text.match(/<\s*[A-Za-z][^>]*>/g) ?? []).length
        out.set('body.tags', tags === 0 ? 'tags:0' : tags <= 2 ? 'tags:few' : tags <= 8 ? 'tags:many' : 'tags:lots')
        return out
      })()
  signature.set('$status', arm.status === null ? 'none' : `${Math.floor(arm.status / 100)}xx`)
  return signature
}

function flattenedRaw(arm: BooleanDifferentialArm): Map<string, string> {
  if (arm.json !== undefined) return flattenJson(arm.json)
  return new Map([['body.text', String(arm.body ?? '')]])
}

function paramValueFromQuery(pathAndQuery: string | undefined, param: string): string | null {
  if (!pathAndQuery) return null
  try {
    return new URL(pathAndQuery, 'http://guardian.invalid').searchParams.get(param)
  } catch {
    return null
  }
}

function paramValueFromJson(value: unknown, param: string): string | null {
  if (!value || typeof value !== 'object') return null
  const wanted = param.split('.').pop() ?? param
  const walk = (node: unknown): string | null => {
    if (!node || typeof node !== 'object') return null
    if (Array.isArray(node)) {
      for (const item of node) {
        const hit = walk(item)
        if (hit !== null) return hit
      }
      return null
    }
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      if (key === param || key === wanted) return child === undefined || child === null ? null : String(child)
      const hit = walk(child)
      if (hit !== null) return hit
    }
    return null
  }
  return walk(value)
}

function maskJsonParam(value: unknown, param: string): unknown {
  const wanted = param.split('.').pop() ?? param
  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(walk)
    if (!node || typeof node !== 'object') return node
    const out: Record<string, unknown> = {}
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      out[key] = key === param || key === wanted ? '{{injected}}' : walk(child)
    }
    return out
  }
  return walk(value)
}

function maskedPath(pathAndQuery: string | undefined, param: string): string {
  if (!pathAndQuery) return ''
  try {
    const url = new URL(pathAndQuery, 'http://guardian.invalid')
    if (url.searchParams.has(param)) url.searchParams.set(param, '{{injected}}')
    let pathname = url.pathname
    // A path-carried parameter shows up as a segment carrying SQL syntax (quote/comment/operator).
    // Masking that segment is masking the injected value itself, not a different route.
    if (!url.searchParams.has(param) && /(?:%27|'|%20AND%20|%20OR%20|--|%2F\*)/i.test(pathname)) {
      pathname = pathname.replace(/\/[^/]+$/, '/{{injected}}')
    }
    return `${pathname}?${[...url.searchParams.entries()].map(([k, v]) => `${k}=${v}`).sort().join('&')}`
  } catch {
    return pathAndQuery
  }
}

function canonicalHeaders(headers: Record<string, string> | null | undefined, param?: string): Record<string, string> {
  const out: Record<string, string> = {}
  const injected = param ? param.toLowerCase() : null
  for (const [key, value] of Object.entries(headers ?? {})) {
    const lower = key.toLowerCase()
    if (booleanVolatileHeaders.has(lower)) continue
    // A header-carried parameter is the injected value; mask exactly that header, nothing else.
    out[lower] = injected && lower === injected ? '{{injected}}' : value
  }
  return out
}

function requestShape(arm: BooleanDifferentialArm, param: string): string {
  return JSON.stringify({
    method: (arm.method ?? '').toUpperCase(),
    path: maskedPath(arm.pathAndQuery, param),
    json: arm.requestJson === undefined ? null : maskJsonParam(arm.requestJson, param),
    headers: canonicalHeaders(arm.requestHeaders, param),
  })
}

/**
 * A rotating nonce/token: an alphanumeric run containing both letters and digits (or a long hex
 * run). Used only to *reject* a difference as volatile, never to confirm one.
 */
function looksVolatileValue(text: string): boolean {
  return /(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9_-]{8,}/.test(text) || /[0-9a-f]{12,}/i.test(text)
}

function normalizeEchoText(text: string, injected: readonly string[]): string {
  let out = text
  for (const value of injected) {
    if (value) out = out.split(value).join('')
  }
  return out.replace(nonceLikeRun, '').trim()
}

/** Paths whose raw values differ, plus whether each difference is only an echo/nonce artefact. */
function differentialPaths(control: BooleanDifferentialArm, probe: BooleanDifferentialArm, param: string): {
  changed: string[]
  echoed: string[]
} {
  const controlRaw = flattenedRaw(control)
  const probeRaw = flattenedRaw(probe)
  const controlSig = bodySignature(control, param)
  const probeSig = bodySignature(probe, param)
  // The signature map uses its own keys for non-JSON bodies (`body.length`, `body.tags`, `$status`),
  // so the union must include them; otherwise a signature-only difference is never compared.
  const paths = new Set([...controlRaw.keys(), ...probeRaw.keys(), ...controlSig.keys(), ...probeSig.keys()])
  const injected = [
    paramValueFromQuery(probe.pathAndQuery, param) ?? '',
    paramValueFromQuery(control.pathAndQuery, param) ?? '',
    paramValueFromJson(probe.requestJson, param) ?? '',
    paramValueFromJson(control.requestJson, param) ?? '',
  ].filter(Boolean)
  const changed: string[] = []
  const echoed: string[] = []
  for (const path of paths) {
    const cRaw = controlRaw.get(path) ?? ''
    const pRaw = probeRaw.get(path) ?? ''
    // Signature-level comparison first: only class/bucket changes count as structural.
    const cSig = controlSig.get(path) ?? ''
    const pSig = probeSig.get(path) ?? ''
    if (cSig === pSig) continue
    changed.push(path)
    const leaf = path.split('.').pop() ?? path
    const looksEcho = leaf.toLowerCase() === param.toLowerCase() ||
      leaf.toLowerCase().endsWith(param.toLowerCase()) ||
      (pRaw !== cRaw && normalizeEchoText(pRaw, injected) === normalizeEchoText(cRaw, injected)) ||
      (pRaw !== cRaw && looksVolatileValue(pRaw) && (cRaw === '' || looksVolatileValue(cRaw))) ||
      (pRaw.includes(param) && cRaw.includes(param))
    if (looksEcho) echoed.push(path)
  }
  return { changed, echoed }
}

function signatureMapKey(map: Map<string, string>): string {
  return [...map.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('|')
}

/**
 * Paired boolean-differential oracle. Confirms only when:
 *  - at least two control/probe rounds exist;
 *  - each pair sends the same request shape (method, route with the injected parameter masked,
 *    body and non-volatile headers) and the same route as its sibling arm;
 *  - no arm returned 5xx;
 *  - the control and probe structural signatures are each stable across rounds;
 *  - the control-vs-probe structural difference is non-empty and identical in every round;
 *  - the difference survives token stripping (echo/nonce-only changes are rejected).
 */
export function assessBooleanDifferential(input: {
  rounds: readonly BooleanDifferentialRound[]
  param?: string | null
}): BooleanDifferentialAssessment {
  const param = input.param?.trim() || ''
  const evidence = {
    rounds: input.rounds.length,
    stable: false,
    controlStable: false,
    probeStable: false,
    requestShapeMismatch: false,
    serverErrors: false,
    echoedOnly: false,
    changedPaths: [] as string[],
    echoPaths: [] as string[],
  }
  const reject = (reason: string): BooleanDifferentialAssessment => ({
    required: true,
    satisfied: false,
    reason,
    evidence,
  })

  if (!param) return reject('A boolean differential must name the injected parameter.')
  if (input.rounds.length < 2) return reject('A boolean differential needs at least two paired control/probe rounds.')
  for (const round of input.rounds) {
    if ((round.control.status ?? 0) >= 500 || (round.probe.status ?? 0) >= 500) {
      evidence.serverErrors = true
      return reject('A boolean differential arm returned a server error (5xx); error behaviour is not proof.'
      )
    }
  }
  for (const round of input.rounds) {
    if (requestShape(round.control, param) !== requestShape(round.probe, param)) {
      evidence.requestShapeMismatch = true
      return reject('The control and probe arms differ beyond the injected parameter (request shape mismatch).')
    }
  }

  const controlSignatures = input.rounds.map(round => signatureMapKey(bodySignature(round.control, param)))
  const probeSignatures = input.rounds.map(round => signatureMapKey(bodySignature(round.probe, param)))
  evidence.controlStable = new Set(controlSignatures).size === 1
  evidence.probeStable = new Set(probeSignatures).size === 1
  if (!evidence.controlStable || !evidence.probeStable) {
    return reject('The control or probe response structure was unstable across rounds; a moving baseline is not a differential.')
  }

  const roundDiffs = input.rounds.map(round => differentialPaths(round.control, round.probe, param))
  const structural = roundDiffs.map(diff => diff.echoed.length === diff.changed.length ? '' : [...diff.changed].filter(path => !diff.echoed.includes(path)).sort().join(','))
  const allEchoed = roundDiffs.every(diff => diff.changed.length > 0 && diff.echoed.length === diff.changed.length)
  evidence.echoPaths = [...new Set(roundDiffs.flatMap(diff => diff.echoed))]
  evidence.changedPaths = [...new Set(structural.flatMap(value => value ? value.split(',') : []))]
  if (allEchoed) {
    evidence.echoedOnly = true
    return reject('The only difference was the injected predicate echoed back (or a rotating nonce); no structural response change.')
  }
  if (structural.some(value => value === '')) {
    return reject('At least one round showed no structural response change; a boolean differential must reproduce every round.')
  }
  if (new Set(structural).size !== 1) {
    return reject('The structural response difference was unstable across rounds; the boolean differential must be identical each round.')
  }
  evidence.stable = true
  return {
    required: true,
    satisfied: true,
    reason: `A paired control/probe differential reproduced across ${input.rounds.length} rounds: structural change in ${evidence.changedPaths.slice(0, 6).join(', ')} after token stripping, with a stable control baseline and no 5xx.`,
    evidence,
  }
}

// ---------------------------------------------------------------------------
// Injection family (SQL/NoSQL/template/command/XXE/traversal)
// ---------------------------------------------------------------------------

export type InjectionFamily = 'sqli' | 'nosqli' | 'ssti' | 'cmdi' | 'xxe' | 'traversal' | 'injection'

export interface InjectionFingerprintMatch {
  family: InjectionFamily
  /** Engine/dialect label (sqlite, postgres, mysql, mssql, oracle, mongo, template, shell, xml, fs). */
  label: string
  /** The matched text, bounded to 120 characters. */
  text: string
}

/**
 * Engine/dialect-specific error strings. A generic HTTP 500 (`{"error":"Internal Server Error"}`) is
 * deliberately absent: only a fingerprint that names the injected construct's engine counts.
 */
const INJECTION_FINGERPRINTS: ReadonlyArray<{ family: InjectionFamily; label: string; re: RegExp }> = [
  { family: 'sqli', label: 'sqlite', re: /\bSQLITE_(?:ERROR|CONSTRAINT|MISUSE|NOTADB)\b|sqlite3\.(?:Operational|Programming|Database)Error/i },
  { family: 'sqli', label: 'postgres', re: /\b(?:PostgreSQL|pg_query|psycopg2|PG::\w+Error|syntax error at or near|unterminated quoted string|invalid input syntax for)\b/i },
  { family: 'sqli', label: 'mysql', re: /\b(?:MySqlException|MySQLSyntaxErrorException|ER_PARSE_ERROR|You have an error in your SQL syntax|check the manual that corresponds to your (?:MariaDB|MySQL) server)\b/i },
  { family: 'sqli', label: 'mssql', re: /\b(?:Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|Unclosed quotation mark after the character string|SQLServerException)\b/i },
  { family: 'sqli', label: 'oracle', re: /\bORA-\d{4,5}\b/i },
  { family: 'sqli', label: 'orm', re: /\b(?:SQLAlchemy|sqlalchemy\.exc|PrismaClient(?:KnownRequest)?Error|SequelizeDatabaseError|Knex(?:Timeout)?Error)\b/i },
  { family: 'nosqli', label: 'mongo', re: /\b(?:Mongo(?:Server|Parse|BulkWrite)Error|BSONTypeError|Cast to (?:ObjectId|number) failed|unknown top level operator|E11000 duplicate key)\b/i },
  { family: 'ssti', label: 'template', re: /\b(?:TemplateSyntaxError|TemplateNotFound|jinja2\.exceptions|UndefinedError|freemarker\.(?:core|template)|FreeMarker template error|VelocityException|SpelEvaluationException|EL100[0-9]E|ognl\.|OGNL expression|Handlebars|Mustache|SmartyCompilerException|Twig\\Error|Thymeleaf|ERB)\b/i },
  { family: 'cmdi', label: 'shell', re: /(?:\/bin\/(?:ba)?sh: |sh: \d+: |command not found|unexpected EOF while looking for matching|syntax error near unexpected token)/i },
  { family: 'xxe', label: 'xml', re: /\b(?:SAXParseException|XMLSyntaxError|lxml\.etree|org\.xml\.sax|XPathEvalError|DOCTYPE is disallowed|Entity .* not defined|external entity)\b/i },
  { family: 'traversal', label: 'fs', re: /\b(?:ENOENT|EACCES|ELOOP|No such file or directory|PathTraversalException|path traversal)\b/i },
]

/** First engine-specific fingerprint in `text`, optionally restricted to one construct family. */
export function matchInjectionFingerprint(
  text: string,
  family?: InjectionFamily | null,
): InjectionFingerprintMatch | null {
  if (!text) return null
  const bounded = text.slice(0, 32 * 1024)
  for (const entry of INJECTION_FINGERPRINTS) {
    if (family && family !== 'injection' && entry.family !== family) continue
    const match = entry.re.exec(bounded)
    if (!match) continue
    return { family: entry.family, label: entry.label, text: match[0].slice(0, 120) }
  }
  return null
}

/** Response-only text: a fingerprint must come from the server's error, never an echoed request. */
function responseText(step: ImpactStep): string {
  const json = step.json === undefined ? '' : safeJson(step.json)
  return `${step.body ?? ''}\n${json}`.slice(0, 32 * 1024)
}

function stepText(step: ImpactStep): string {
  const request = step.requestJson === undefined ? '' : safeJson(step.requestJson)
  return `${step.method ?? ''} ${step.pathAndQuery ?? ''}\n${responseText(step)}\n${request}`.slice(0, 32 * 1024)
}

function safeJson(value: unknown): string {
  try { return JSON.stringify(value) } catch { return '' }
}

export interface StatusOnlyDivergence {
  /** True when a probe arm failed (4xx/5xx) and its body carries no engine/parser fingerprint. */
  statusOnly: boolean
  reason: string
  controlId: string | null
  probeId: string | null
  controlStatus: number | null
  probeStatus: number | null
  fingerprint: InjectionFingerprintMatch | null
}

/**
 * Universal status-only guard. A failing probe (4xx/5xx) is never confirmation on its own: the
 * response must carry an engine/parser fingerprint for the injected construct, or another
 * evidence-bearing claim (structural differential, timing, OOB, state delta) must stand on its own.
 * This is class-independent so a bare `2xx -> 5xx` cannot confirm XSS, SSRF, traversal or injection.
 */
export function assessStatusOnlyDivergence(steps: readonly ImpactStep[]): StatusOnlyDivergence {
  const allProbes = steps.filter(step => step.arm === 'probe')
  const probes = allProbes.filter(step => step.status !== null && step.status >= 400)
  if (probes.length === 0) {
    return {
      statusOnly: false,
      reason: 'No failing probe arm is part of this evidence set.',
      controlId: null,
      probeId: null,
      controlStatus: null,
      probeStatus: null,
      fingerprint: null,
    }
  }
  // A successful probe that returns data or a state delta is independent positive evidence; the
  // failing sibling is then supporting context (e.g. a race burst's mixed outcomes), not the whole
  // proof. Only an evidence set whose probe arms *all* failed falls under the status-only ban.
  const substantive = (step: ImpactStep): boolean => {
    if (Array.isArray(step.json)) return step.json.length > 0
    if (step.json !== undefined && step.json !== null && typeof step.json === 'object') {
      return Object.keys(step.json as Record<string, unknown>).length > 0
    }
    const body = (step.body ?? '').trim()
    return body.length >= 16 && body !== '{}' && body !== '[]' && !/^"(?:ok|success|done)"$/i.test(body)
  }
  const hasPositiveProbe = allProbes.some(step =>
    step.status !== null && step.status >= 200 && step.status < 300 && substantive(step))
  if (hasPositiveProbe) {
    return {
      statusOnly: false,
      reason: 'A successful probe arm carries data/state evidence; the failing arm is supporting context.',
      controlId: null,
      probeId: probes[0]?.id ?? null,
      controlStatus: null,
      probeStatus: probes[0]?.status ?? null,
      fingerprint: null,
    }
  }
  const controls = steps.filter(step => step.arm === 'control' || step.arm === 'setup')
  for (const probe of probes) {
    const fingerprint = matchInjectionFingerprint(responseText(probe))
    if (fingerprint) continue
    const route = routeFamily(probe.route ?? probe.pathAndQuery ?? '')
    const control = [...controls].reverse().find(step =>
      step.status !== null && step.status >= 200 && step.status < 300 &&
      (!route || routeFamily(step.route ?? step.pathAndQuery ?? '') === route)) ?? null
    return {
      statusOnly: true,
      reason: `The probe returned HTTP ${probe.status} without an engine/parser fingerprint; a status divergence from the control (${control ? `HTTP ${control.status}` : 'no successful control'}) is not proof of injection or any other class.`,
      controlId: control?.id ?? null,
      probeId: probe.id,
      controlStatus: control?.status ?? null,
      probeStatus: probe.status,
      fingerprint: null,
    }
  }
  return {
    statusOnly: false,
    reason: 'The failing probe arm carries an engine/parser fingerprint.',
    controlId: null,
    probeId: probes[0]?.id ?? null,
    controlStatus: null,
    probeStatus: probes[0]?.status ?? null,
    fingerprint: matchInjectionFingerprint(responseText(probes[0]!)),
  }
}

function sameInjectionRoute(a: ImpactStep, b: ImpactStep): boolean {
  return routeFamily(a.route ?? a.pathAndQuery ?? '') === routeFamily(b.route ?? b.pathAndQuery ?? '')
}

/**
 * Injection confirmation requires a positive semantic oracle:
 *  - an engine/dialect error fingerprint present in the probe and absent from every control;
 *  - a paired boolean differential with a stable structural delta across >=2 rounds;
 *  - a timing arm outside the control envelope (>3x, control < 1s);
 *  - a verified out-of-band callback; or
 *  - the narrow status-only boolean exception (benign 2xx baseline + 2xx tautology + <500
 *    contradiction, same request shape apart from the predicate).
 * A single 200 -> 500 (or 200 -> 4xx) transition never confirms.
 */
export function assessInjectionImpact(input: ImpactInput): ImpactAssessment {
  const steps = input.steps
  const probes = steps.filter(step => step.arm === 'probe')
  const controls = steps.filter(step => step.arm === 'control')
  const evidence: Record<string, unknown> = {
    family: input.injection?.family ?? 'injection',
    fingerprint: null as InjectionFingerprintMatch | null,
    booleanRounds: input.injection?.rounds?.length ?? 0,
    timing: input.injection?.timing ?? null,
    oobDelivered: input.injection?.oobDelivered === true,
    statusBoolean: false,
  }
  if (probes.length === 0) {
    return { required: true, satisfied: false, reason: 'Injection claim has no probe arm to assess.', evidence }
  }
  const controlText = controls.map(responseText).join('\n')
  for (const probe of probes) {
    const text = responseText(probe)
    const fingerprint = matchInjectionFingerprint(text, input.injection?.family)
    if (!fingerprint) continue
    // A control that produces the same engine error is broken infrastructure, not injection.
    if (matchInjectionFingerprint(controlText, fingerprint.family)) continue
    evidence.fingerprint = fingerprint
    return {
      required: true,
      satisfied: true,
      reason: `The probe response carries a ${fingerprint.family}/${fingerprint.label} error fingerprint ("${fingerprint.text}") that no control arm produces; that is a semantic oracle, not a bare status change.`,
      evidence,
    }
  }
  if (input.injection?.rounds && input.injection.rounds.length >= 2) {
    const assessment = assessBooleanDifferential({
      rounds: input.injection.rounds,
      param: input.injection.param ?? null,
    })
    if (assessment.satisfied) {
      evidence.booleanRounds = input.injection.rounds.length
      return {
        required: true,
        satisfied: true,
        reason: `Injection boolean differential: ${assessment.reason}`,
        evidence: { ...evidence, boolean: assessment.evidence },
      }
    }
  }
  const timing = input.injection?.timing
  if (timing && timing.controlMs > 0 && timing.probeMs > 0) {
    if (timing.controlMs < 1_000 && timing.probeMs >= Math.max(1_000, timing.controlMs * 3)) {
      return {
        required: true,
        satisfied: true,
        reason: `The probe arm took ${timing.probeMs} ms against a ${timing.controlMs} ms control (>3x separation); a jitter-tolerant timing oracle.`,
        evidence,
      }
    }
  }
  if (input.injection?.oobDelivered) {
    return {
      required: true,
      satisfied: true,
      reason: 'A verified out-of-band callback was delivered after the injected marker reached the target.',
      evidence,
    }
  }
  const statusBoolean = input.injection?.statusBoolean
  if (statusBoolean) {
    const { benign, tautology, contradiction } = statusBoolean
    const benignOk = isSuccess(benign.status)
    const tautologyOk = isSuccess(tautology.status)
    const contradictionFails = contradiction.status !== null &&
      contradiction.status >= 400 && contradiction.status < 500
    const sameShape = sameInjectionRoute(tautology, contradiction) &&
      tautology.method.toUpperCase() === contradiction.method.toUpperCase()
    // The request target is percent-encoded on the wire, so `%20AND%20` would defeat a bare word
    // boundary. Decode before looking for the boolean operator (a failed decode leaves the raw text;
    // the check only ever accepts a stronger match, never a weaker one).
    const requestText = (step: ImpactStep): string => {
      const raw = `${step.pathAndQuery ?? ''}${safeJson(step.requestJson)}`
      try { return decodeURIComponent(raw) } catch { return raw }
    }
    const contrast = Boolean(
      stepText(tautology) !== stepText(contradiction) &&
      /\b(?:AND|OR)\b/i.test(requestText(tautology)) &&
      /\b(?:AND|OR)\b/i.test(requestText(contradiction)),
    )
    if (benignOk && tautologyOk && contradictionFails && sameShape && contrast) {
      evidence.statusBoolean = true
      return {
        required: true,
        satisfied: true,
        reason: `Status-only boolean exception: the benign baseline (${benign.status}) and tautology arm (${tautology.status}) are 2xx while the contradiction arm fails (${contradiction.status}) on the same request shape; this is a paired predicate contrast, not a single malformed request.`,
        evidence,
      }
    }
  }
  const divergence = assessStatusOnlyDivergence(steps)
  return {
    required: true,
    satisfied: false,
    reason: `Injection claim has no positive semantic oracle: ${divergence.reason} Add an engine/dialect error fingerprint, a paired boolean differential with a stable structural delta, a >3x timing arm, a verified OOB callback, or the paired status-boolean contrast (benign 2xx baseline + 2xx tautology + <500 contradiction).`,
    evidence: { ...evidence, statusOnly: divergence.statusOnly, statusReason: divergence.reason },
  }
}

// ---------------------------------------------------------------------------
// Markup / script execution
// ---------------------------------------------------------------------------

export interface MarkupAssessment extends ImpactAssessment {
  evidence: { activeMarkup: boolean; oracleDeclared: boolean; bodies: number; plantedMarker: boolean }
}

/**
 * Scripting claims need executable content. Unescaped presentation tags prove output-encoding debt,
 * not script execution; the payload must contain a script element, an inline event handler or a
 * javascript: URL in a probe response (or the endpoint's declared XSS impact event).
 */
export function assessMarkupImpact(input: ImpactInput): MarkupAssessment {
  const probes = input.steps.filter(step => step.arm === 'probe' && isSuccess(step.status))
  let activeMarkup = false
  for (const probe of probes) {
    if (typeof probe.body === 'string' && probe.body.length > 0 && ACTIVE_MARKUP_RE.test(probe.body)) {
      activeMarkup = true
      break
    }
  }
  // Second-order stored injection: a nonce marker injected by a mutating step inside *this* spec is
  // rendered back later and is absent from every control body. That is a stored-data flow the proof
  // itself created (the procedural stored-XSS shape), not a pre-existing tag an unrelated request
  // left behind (the K=6 over-claim shape).
  const planted = new Set<string>()
  for (const step of input.steps) {
    if (step.arm === 'control' || !stepMutatesState(step) || !isSuccess(step.status) || step.requestJson === undefined) continue
    for (const value of flattenJson(step.requestJson).values()) {
      // A marker may be embedded in a payload (`gxssab12<b>`): take its identifier-shaped run.
      for (const token of value.slice(0, 256).match(/[A-Za-z0-9_-]{8,64}/g) ?? []) planted.add(token)
    }
  }
  let plantedMarker = false
  if (planted.size > 0) {
    const controlBodies = input.steps.filter(step => step.arm === 'control').map(step => String(step.body ?? '')).join('\n')
    const candidates = [...planted].filter(marker => !controlBodies.includes(marker))
    plantedMarker = probes.some(probe => typeof probe.body === 'string' &&
      candidates.some(marker => probe.body!.includes(marker)))
  }
  const oracleDeclared = hasOracle(input.oracleEvents, ['stored_xss_rendered', 'reflected_xss_rendered'])
  const labels = { activeMarkup, oracleDeclared, bodies: probes.length, plantedMarker }
  if (activeMarkup || oracleDeclared || plantedMarker) {
    return {
      required: true,
      satisfied: true,
      reason: activeMarkup
        ? 'The probe response carries executable markup (script element, inline event handler or javascript: URL).'
        : plantedMarker
          ? 'A nonce marker injected by a mutating step inside this proof is rendered back on the stored read.'
          : `The claim declares the endpoint's XSS impact event (${input.oracleEvents!.join(',')}).`,
      evidence: labels,
    }
  }
  return {
    required: true,
    satisfied: false,
    reason: 'The rendered markup carries no executable content and no marker planted inside this proof: unescaped presentation tags are output-encoding debt, not script execution.',
    evidence: labels,
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
    case 'disclosure':
      return assessAuthorizationImpact(input)
    case 'business_logic':
      return assessBusinessLogicImpact(input)
    case 'markup':
      return assessMarkupImpact(input)
    case 'injection':
      return assessInjectionImpact(input)
    default:
      return { required: false, satisfied: true, reason: 'Not an authorization/impact claim.' }
  }
}

/** Canonical machine-readable labels for a *verified* impact class. */
export interface EvidenceClassLabel {
  vulnClass: string
  cwe: string
  category: string
}

const IMPACT_CLASS_LABELS: Record<string, EvidenceClassLabel> = {
  // Cross-tenant evidence is object-level authorization regardless of the model's business framing.
  bola: { vulnClass: 'bola', cwe: 'CWE-639', category: 'broken-access-control' },
  mass_assignment: { vulnClass: 'mass_assignment', cwe: 'CWE-915', category: 'mass-assignment' },
  csrf: { vulnClass: 'csrf', cwe: 'CWE-352', category: 'csrf' },
  markup: { vulnClass: 'xss_stored', cwe: 'CWE-79', category: 'xss' },
  disclosure: { vulnClass: 'info_disclosure', cwe: 'CWE-200', category: 'information-disclosure' },
  business_logic: { vulnClass: 'business_logic', cwe: 'CWE-840', category: 'business-logic' },
  injection: { vulnClass: 'sqli', cwe: 'CWE-89', category: 'injection' },
}

const IMPACT_CLASS_CWES: Record<string, number[]> = {
  bola: [639],
  mass_assignment: [915],
  csrf: [352],
  markup: [79, 80, 83],
  disclosure: [200, 359, 522, 532],
  business_logic: [840, 841, 472],
  injection: [89, 564, 943],
}

/** Label for a verified impact class, or null when the class has no single canonical label. */
export function evidenceClassLabel(impactClass: string | null | undefined): EvidenceClassLabel | null {
  return impactClass ? IMPACT_CLASS_LABELS[impactClass] ?? null : null
}

/**
 * Align a claim's machine-readable class with the *verified* evidence class. Only applied when the
 * evidence class is specific (mass assignment, csrf, markup, disclosure, business logic) and the
 * declared CWE is outside that class's family: e.g. a `tenant_id` overpost reported as BOLA
 * (CWE-639) is mass assignment (CWE-915). Authorization evidence never relabels a claim.
 */
export function alignClaimClass(
  claim: { cwe?: string | null; category?: string | null; vulnClass?: string | null },
  impactClass: string | null | undefined,
): EvidenceClassLabel | null {
  const label = evidenceClassLabel(impactClass)
  if (!label) return null
  const family = (impactClass ? IMPACT_CLASS_CWES[impactClass] : undefined) ?? []
  const declared = /(\d+)/.exec(claim.cwe ?? '')?.[1]
  if (declared !== undefined && family.includes(Number(declared))) return null
  return label
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
/** Share-style routes: readable by anyone holding the link, so cross-tenant reads are by design. */
const PUBLIC_ROUTE_RE = /\/(?:public|share|shared|embed|preview|open|link)(?:\/|$)/i

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
  // A denied arm only proves the caller was outside an entitlement *before* the crossing action.
  // A 404/403 readback recorded after the successful probe is persistence evidence (the object is
  // gone) or a consequence of the mutation, not a boundary the probe crossed — reading it as one
  // lets a legitimate post-delete readback mask a real actor differential.
  const firstProbeIndex = steps.findIndex(step => step.arm === 'probe')
  const signals = steps
    .map(step => boundarySignalOf(step, successFamilies))
    .filter((signal): signal is BoundarySignal => signal !== null)
    .filter(signal => firstProbeIndex < 0 || steps.indexOf(signal.step) < firstProbeIndex)
  const probeStep = steps.find(step => step.arm === 'probe') ?? null
  const probeActor = probeStep?.actor ?? null
  const resourceTenant = input.resourceTenant?.toLowerCase() ?? null
  const boundaryMirrorCorroborated = resourceTenant !== null && probeStep !== null && steps.some(step =>
    step.actor.tenant === resourceTenant && isReadMethod(step.method) && isSuccess(step.status) && sameRoute(step, probeStep))
  // A post-mutation 404 readback (e.g. the control deletes the object, then reads it) is
  // persistence evidence, not a boundary denial; drop signals that follow a control mutation on the
  // same route.
  const controlMutationIndexes = steps
    .map((step, index) => (step.arm === 'control' && stepMutatesState(step) ? index : -1))
    .filter(index => index >= 0)
  const boundarySignals = signals.filter(entry => {
    const at = steps.indexOf(entry.step)
    if (at < 0) return true
    return !controlMutationIndexes.some(mutatedAt => mutatedAt < at && sameRoute(steps[mutatedAt]!, entry.step))
  })
  const peerSignal = boundarySignals.find(entry => {
    const tenant = entry.step.actor.tenant ?? null
    if (tenant === null || probeActor?.tenant == null) return true
    return tenant === probeActor.tenant ||
      (boundaryMirrorCorroborated && resourceTenant !== null && tenant === resourceTenant && resourceTenant !== probeActor.tenant)
  }) ?? null
  const signal = peerSignal ?? null
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
  // `expectControlDenied: false` is model-supplied and must never *disable* the gate: an observed
  // denial always has to be crossed by the variant. The flag only documents intent.
  if (controlDenied) {
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

