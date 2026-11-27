/** http_chain / rce_proof spec synthesis: authz, mass assignment, SSRF, XXE, SSTI. */
import { randomBytes } from 'node:crypto'
import { appendQuery, baseFields, bogusIdFor, is2xx, jqStr, requestParts, sameAsControl, stepOf } from './benchmark-specs-common.ts'
import type { RequestParts, SynthesizedSpec } from './benchmark-specs-common.ts'
import { fillPlaceholders, hasPathPlaceholder, probePathFor, siblingValue } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

const canaryJq = (control: string) =>
  `{ controlPassed: (.steps.${control}.status < 500), confirmed: (.canary.triggered == true), observed: ("probeCallback=" + ((.canary.probeTriggered // false) | tostring)), expected: "no out-of-band callback" }`

const NEGATIVE_CONTROL_STATUS = [400, 401, 403, 404, 405, 409, 410, 422]

interface MatrixRow {
  resourceId?: unknown
  actor?: unknown
  status?: unknown
  bodyBytes?: unknown
  bodySha256?: unknown
  similarityToOwner?: unknown
  accessible?: unknown
}

/** A step must carry a non-trivial object, not an empty action acknowledgement. */
const nonTrivial = (id: string, minBytes = 3) =>
  `(((${is2xx(id)})) and (((.steps.${id}.body | length) > ${minBytes}) or (((.steps.${id}.json | type) == "object") and (((.steps.${id}.json | keys | length) >= 2)))))`

function matchesOwnerJq(): string {
  return `((.steps.p1.body == .steps.c1.body) or (.steps.c1.json as $c | .steps.p1.json as $p | ` +
    `(($c | type) == "object") and (([$c | keys[]] | length) > 0) and ` +
    `(([($c | to_entries[]) | select($p[.key] == .value)] | length) == ([$c | keys[]] | length))))`
}

/**
 * The negative control must prove the route is actually bound to the identifier. A handler that
 * ignores the id and operates on the session's own object returns the owner's response unchanged
 * for a bogus id, so the spec is not submitted. Mutating routes additionally never accept a
 * nonexistent object id.
 */
function negativeControlJq(mutating: boolean): string {
  if (mutating) return `((.steps.c2.status >= 400) and (.steps.c2.status < 500))`
  return `(((.steps.c2.status >= 400) and (.steps.c2.status < 500)) or ((${is2xx('c2')}) and (.steps.c2.body != .steps.c1.body) and ((.steps.c2.body | length) > 2)))`
}

function matrixRows(o: HypothesisOutcome): MatrixRow[] | null {
  const matrix = o.details.matrix
  if (!Array.isArray(matrix)) return null
  return matrix.filter((row): row is MatrixRow => Boolean(row) && typeof row === 'object')
}

interface ReadTarget {
  path: string
  /** A detail route returns one object; a list route is matched by identifier presence. */
  detail: boolean
  /** List route chosen by noun/synonym fallback rather than a harvested identifier pool. */
  reserved: boolean
}

const memberNoun = /(?:^|[/_-])(?:people|members?|users?|staff|accounts?|persons?|employees?)(?:$|[/_.-])/i

function listPathFor(env: ProbeEnv, id: string, endpointPath: string): { path: string; reserved: boolean } | null {
  const pools = [...(env.idCache ?? new Map<string, string[]>()).entries()]
  const matched = pools.filter(([, ids]) => ids.includes(id))
  const rank = (key: string) => (env.owner && key.startsWith(`${env.owner}|`) ? 0 : 1)
  matched.sort((a, b) => rank(a[0]) - rank(b[0]))
  for (const [key] of matched) {
    const candidate = key.slice(key.indexOf('|') + 1)
    if (candidate.startsWith('/') && !candidate.startsWith('//') && !hasPathPlaceholder(candidate)) {
      return { path: candidate, reserved: false }
    }
  }
  // The probe may already have consumed every identifier in the pool (a delete target list is
  // empty after the matrix). Fall back to a discovered collection of the same record family; the
  // replay re-reads it to reserve a live identifier before mutating.
  if (!memberNoun.test(endpointPath)) return null
  const candidate = (env.endpoints ?? [])
    .filter(e => e.method.toUpperCase() === 'GET' && !e.path.includes('?') && !hasPathPlaceholder(e.path) && memberNoun.test(e.path))
    .map(e => e.path)
    .sort((a, b) => Number(/admin|internal/i.test(a)) - Number(/admin|internal/i.test(b)) || a.length - b.length || a.localeCompare(b))[0]
  return candidate ? { path: candidate, reserved: true } : null
}

/**
 * Find a read route that can prove a mutation changed state: prefer a detail GET under a collection
 * that was already observed to contain the resource id, else the collection list itself. Derived
 * only from the run's own harvested identifier pools and discovered surface.
 */
function inferReadTarget(env: ProbeEnv, id: string, endpointPath: string): ReadTarget | null {
  const list = listPathFor(env, id, endpointPath)
  if (!list) return null
  if (list.reserved) return { path: list.path, detail: false, reserved: true }
  const depth = list.path.split('?')[0].split('/').filter(Boolean).length
  const detail = (env.endpoints ?? [])
    .filter(e => e.method.toUpperCase() === 'GET' && !e.path.includes('?') && hasPathPlaceholder(e.path))
    .map(e => e.path)
    .filter(p => p.startsWith(`${list.path}/`) && p.split('/').filter(Boolean).length === depth + 1)
    .sort((a, b) => a.length - b.length || a.localeCompare(b))[0]
  return detail
    ? { path: fillPlaceholders(detail, encodeURIComponent(id)), detail: true, reserved: false }
    : { path: list.path, detail: false, reserved: false }
}

/** Privileged literal asserted on the post-mutation read (never a raw secret; role/plan/boolean only). */
function privilegedLiteral(bodyTemplate: unknown): string | null {
  if (!bodyTemplate || typeof bodyTemplate !== 'object' || Array.isArray(bodyTemplate)) return null
  for (const [key, value] of Object.entries(bodyTemplate as Record<string, unknown>)) {
    if (!/role|admin|privilege|permission|scope|plan|tier|owner|staff|super/i.test(key)) continue
    if (typeof value === 'string' && /^[a-z][a-z0-9_-]{2,31}$/i.test(value)) return value
  }
  return null
}

/** A route whose name marks an elevated function (admin console, permission/role grant, ...). */
const privilegedRoute = /(?:^|[/_.-])(?:admin|administration|internal|manage|management|staff|superuser|privileged|backoffice|permissions?|roles?|grants?|scopes?)(?:$|[/_.-])/i

/**
 * The actor that can read the mutated record back. Identifier pools are harvested per persona and
 * route (see `idPool`), so a pool that contains this id names the credential that observed it.
 */
function readPersonaFor(env: ProbeEnv, id: string): string | null {
  const matched = [...(env.idCache ?? new Map<string, string[]>()).entries()]
    .filter(([key, ids]) => key.includes('|') && ids.includes(id))
    .sort((a, b) => Number(!a[0].startsWith(`${env.owner}|`)) - Number(!b[0].startsWith(`${env.owner}|`)))
  for (const [key] of matched) {
    const persona = key.slice(0, key.indexOf('|'))
    if (persona) return persona
  }
  return null
}

/**
 * Self-identity fallback: a user-administration route mutates an account whose role is visible on
 * that same account's own profile route. Only the personas whose user id the run already resolved
 * can read themselves, so the mutated id must equal one of those ids.
 */
function identityRoute(env: ProbeEnv): string | null {
  return (env.endpoints ?? [])
    .filter(e => e.method.toUpperCase() === 'GET' && !hasPathPlaceholder(e.path) && !e.path.includes('?'))
    .map(e => e.path)
    .filter(p => /(?:^|\/)(?:profile|me|whoami|session|account)(?:\/|$)/i.test(p))
    .sort((a, b) => a.length - b.length || a.localeCompare(b))[0] ?? null
}

function identityReadTarget(env: ProbeEnv, id: string): { path: string; persona: string } | null {
  const persona = id === env.ownerUserId ? env.owner : id === env.otherUserId ? env.other : id === env.viewerUserId ? env.viewer : null
  const path = identityRoute(env)
  return persona && path ? { path, persona } : null
}

function mutationPath(endpointPath: string, id: string): string {
  // `fillPlaceholders` understands every placeholder spelling discovery emits (`:id`, `{id}`,
  // `[id]`, `{{id}}`); a hand-rolled regex here silently left `{id}` in the wire path.
  const encoded = id.startsWith('{{') ? id : encodeURIComponent(id)
  return fillPlaceholders(endpointPath, encoded)
}

/**
 * Unauthorized mutation proven by state delta: the authorized actor reads the resource before the
 * probe write, the lower-privileged actor mutates it, and a post-write read shows the change (or the
 * object's disappearance for a delete). Identifier-bound, so a trivial `{ok:true}` acknowledgement
 * cannot pass on its own.
 */
function stateDeltaSpec(
  o: HypothesisOutcome, env: ProbeEnv, read: ReadTarget, id: string, method: string,
  bodyTemplate: unknown, probePersona: string | null, privileged: string | null,
  readback: { persona: string; vertical: boolean; requiredRole?: 'viewer' | 'member' | 'admin' | 'owner' } = { persona: env.owner ?? '', vertical: false },
): SynthesizedSpec[] {
  const stepExtra = env.caps.sessionAndCsrf ? { csrfBind: true } : {}
  const readPersona = readback.persona || env.owner
  // The reserved-victim proof must read and mutate as the same low-privileged actor: a reader in one
  // tenant and a writer in another cannot prove a same-tenant deletion.
  const writer = env.viewer ?? (probePersona && probePersona !== env.other ? probePersona : null)
  const title = readback.vertical
    ? 'Vertical BFLA: privileged function invocation (state delta)'
    : method === 'DELETE' ? 'Cross-actor object deletion (state delta)' : 'Cross-actor object mutation (state delta)'
  const common = (jq: string) => ({
    ...baseFields(env, title, readback.vertical ? 'CWE-285' : 'CWE-639', 'broken-access-control', 'high', jq),
    ...(readback.vertical && readback.requiredRole ? { requiredRole: readback.requiredRole } : {}),
    kind: 'http_chain' as const,
    steps: [] as Array<Record<string, unknown>>,
  })

  // A delete consumes the identifier the probe observed. Reserve a live member from the same
  // collection inside the replay instead of reusing a record that is already gone.
  if (method === 'DELETE' && !read.detail) {
    if (!writer) return []
    const specs: SynthesizedSpec[] = []
    for (const selector of ['items.1.id', '1.id', 'items[1].id']) {
      const hasVictim = (stepId: string) => `((.steps.${stepId}.body | index($v)) != null)`
      const controlPassed = `(${is2xx('c1')} and (($v | length) > 0) and ${hasVictim('c1')})`
      const goneByAbsence = `((${is2xx('p2')}) and ((${hasVictim('p2')}) | not) and ((.steps.p2.body | length) > 0))`
      const goneByError = `((.steps.p2.status >= 400) and (.steps.p2.status < 500))`
      const afterGone = `((($v | length) > 0) and (${goneByAbsence} or ${goneByError}))`
      const jq = `(.extractedVars.victim_id // "") as $v | ` +
        `{ controlPassed: ${controlPassed}, ` +
        `confirmed: (${is2xx('p1')} and ${afterGone}), ` +
        `observed: ("probe status=" + (.steps.p1.status | tostring) + " after status=" + (.steps.p2.status | tostring)), ` +
        `reason: ("c1=" + (.steps.c1.status | tostring) + " victim=" + ($v | tostring) + " p1=" + (.steps.p1.status | tostring) + " p2=" + (.steps.p2.status | tostring)), ` +
        'expected: "non-owner deletion must be denied" }'
      specs.push({
        kind: 'http_chain',
        spec: {
          ...common(jq),
          steps: [
            {
              ...stepOf(env, 'c1', 'control', 'Lower-privileged actor reads the member collection', { method: 'GET', pathAndQuery: read.path }, writer, {}, [200]),
              extract: [{ varName: 'victim_id', from: 'json' as const, selector }],
            },
            stepOf(env, 'p1', 'probe', 'Lower-privileged actor deletes a live member by identifier', { method: 'DELETE', pathAndQuery: mutationPath(o.hyp.endpoint.path, '{{victim_id}}'), ...(stepExtra) }, writer),
            stepOf(env, 'p2', 'probe', 'Lower-privileged actor re-reads the member collection', { method: 'GET', pathAndQuery: read.path }, writer),
          ],
        },
      })
    }
    return specs
  }

  const parts: RequestParts = {
    method: method as RequestParts['method'],
    pathAndQuery: mutationPath(o.hyp.endpoint.path, id),
    ...(method !== 'DELETE' ? { jsonBody: bodyTemplate } : {}),
  }
  const idLit = jqStr(id)
  const before = read.detail
    ? `(${is2xx('c1')} and ((.steps.c1.body | length) > 2))`
    : `(${is2xx('c1')} and ((.steps.c1.body | index(${idLit})) != null))`
  const after: string = method === 'DELETE'
    ? `(((.steps.p2.status >= 400) and (.steps.p2.status < 500)) or (${is2xx('p2')} and ((.steps.p2.body | index(${idLit})) == null) and (.steps.p2.body != .steps.c1.body)))`
    : `(${is2xx('p2')} and (.steps.p2.body != .steps.c1.body)${privileged ? ` and ((.steps.p2.body | ascii_downcase) | contains(${jqStr(privileged.toLowerCase())}))` : ''})`
  const jq = `{ controlPassed: ${before}, ` +
    `confirmed: ((${is2xx('p1')}) and ${after} and ${before}), ` +
    `observed: ("probe status=" + (.steps.p1.status | tostring) + " after status=" + (.steps.p2.status | tostring)), expected: "non-owner mutation must be denied" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...common(jq),
      steps: [
        stepOf(env, 'c1', 'control', 'Authorized actor reads the resource before the mutation', { method: 'GET', pathAndQuery: read.path }, readPersona),
        stepOf(env, 'p1', 'probe', 'Lower-privileged actor mutates the resource', parts, probePersona, stepExtra),
        stepOf(env, 'p2', 'probe', 'Authorized actor reads the resource after the mutation', { method: 'GET', pathAndQuery: read.path }, readPersona),
      ],
    },
  }]
}

/**
 * Function-level state delta: a privileged control actor sets a benign baseline, the lower-privileged
 * actor invokes the function, and a separate read of the function's own status route (or an inferred
 * sibling read) shows the state actually changed. Identifier binding is asserted when the read body
 * exposes the resource the function targeted. A mutation echo alone can never satisfy this proof.
 */
interface FunctionStateObservation {
  path: string
  controlBody: unknown
  probeBody: unknown
  fieldPath: string[]
  controlValue?: unknown
  probeValue: unknown
  bindingPath?: string[]
  bindingValue?: string
}

function jqAccessor(stepId: string, path: readonly string[]): string {
  return path.reduce((acc, segment) => (/^\d+$/.test(segment) ? `${acc}[${segment}]` : `${acc}[${jqStr(segment)}]`), `.steps.${stepId}.json`)
}

function jqLiteral(value: unknown): string {
  if (value === undefined || value === null) return 'null'
  return JSON.stringify(value)
}

function functionStateDeltaSpec(
  o: HypothesisOutcome,
  env: ProbeEnv,
  state: FunctionStateObservation,
  controlActor: string,
  probeActor: string | null,
  vertical: boolean,
): SynthesizedSpec[] {
  if (!state.fieldPath.length || !state.path.startsWith('/')) return []
  const stepExtra = env.caps.sessionAndCsrf ? { csrfBind: true } : {}
  const writeMethod: 'POST' | 'PUT' | 'PATCH' = o.hyp.method === 'PUT' || o.hyp.method === 'PATCH' ? o.hyp.method : 'POST'
  const actionPath = probePathFor(o.hyp)
  const readAccessor = jqAccessor('c1', state.fieldPath)
  const afterAccessor = jqAccessor('p2', state.fieldPath)
  const controlLit = jqLiteral(state.controlValue)
  const probeLit = jqLiteral(state.probeValue)
  const binding = state.bindingPath && state.bindingValue
    ? ` and (${jqAccessor('c1', state.bindingPath)} == ${jqStr(state.bindingValue)}) and (${jqAccessor('p2', state.bindingPath)} == ${jqStr(state.bindingValue)})`
    : ''
  const jq = `{ controlPassed: ((${is2xx('c1')}) and ((.steps.c1.body | length) > 2) and (${readAccessor} == ${controlLit})${binding}), ` +
    `confirmed: ((${is2xx('p1')}) and (${is2xx('p2')}) and (${afterAccessor} == ${probeLit}) and (${readAccessor} == ${controlLit}) and (.steps.p2.body != .steps.c1.body)${binding}), ` +
    `observed: ("probe status=" + (.steps.p1.status | tostring) + " state=" + (${afterAccessor} | tostring)), expected: "only the privileged role may change function state" }`
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env,
        vertical ? 'Vertical BFLA: privileged function invocation (state delta)' : 'Cross-actor function state change (state delta)',
        vertical ? 'CWE-285' : 'CWE-639', 'broken-access-control', 'high', jq),
      kind: 'http_chain',
      ...(vertical ? { requiredRole: 'admin' as const } : {}),
      ...(vertical ? { expectedImpactEvents: ['state_delta'] } : {}),
      steps: [
        stepOf(env, 'w1', 'control', 'Authorized actor sets the function state to a benign baseline', { method: writeMethod, pathAndQuery: actionPath, jsonBody: state.controlBody }, controlActor),
        stepOf(env, 'c1', 'control', 'Authorized actor reads the function state', { method: 'GET', pathAndQuery: state.path }, controlActor),
        stepOf(env, 'p1', 'probe', `${probeActor ? 'Lower-privileged actor' : 'Unauthenticated caller'} invokes the privileged function`, { method: writeMethod, pathAndQuery: actionPath, jsonBody: state.probeBody }, probeActor, stepExtra),
        stepOf(env, 'p2', 'control', 'Authorized actor re-reads the function state', { method: 'GET', pathAndQuery: state.path }, controlActor),
      ],
    },
  }]
}

export function synthAuthz(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const owner = o.pair?.owner ?? env.owner
  const other = o.pair?.other ?? env.other
  if (!owner || !other) return []
  const claimsId = o.hyp.endpoint.params.some(p => (p.isObjectId || /(^|[_-])id$/i.test(p.name)) && p.location === 'query')
  const hits = o.anomalies
    .filter(a => a.type === 'unauthorized_access')
    // Strongest evidence first: body-equivalent cross-actor reads, then mutations.
    .sort((a, b) => {
      const ga = String(a.method ?? 'GET') === 'GET' ? 0 : 1
      const gb = String(b.method ?? 'GET') === 'GET' ? 0 : 1
      if (ga !== gb) return ga - gb
      return (Number(b.similarityToOwner ?? 0)) - (Number(a.similarityToOwner ?? 0))
    })
  if (hits.length === 0) return []
  const rows = matrixRows(o)
  const rejects = { owner: 0, probe: 0, public: 0, trivial: 0 }
  const out: SynthesizedSpec[] = []
  const seen = new Set<string>()
  const selfReadbackEmitted = new Set<string>()

  for (const hit of hits) {
    const id = String(hit.resourceId ?? '')
    const method = String(hit.method ?? 'GET')
    if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) continue
    const mutating = method !== 'GET'
    const functionLevel = hit.functionLevel === true ||
      (!hasPathPlaceholder(o.hyp.endpoint.path) && !claimsId)
    const key = `${method}|${functionLevel ? 'fn' : id}`
    if (seen.has(key)) continue
    seen.add(key)
    if (!functionLevel && !/^[A-Za-z0-9_.:-]{1,128}$/.test(id)) continue

    const probeActor = hit.actor === 'anonymous' ? 'anonymous' : 'other_persona'
    let ownerOk = true
    let probeOk = true
    let ownerTrivial = false
    if (rows) {
      const idRows = functionLevel ? rows : rows.filter(r => String(r.resourceId ?? '') === id)
      const ownerRow = idRows.find(r => r.actor === 'owner')
      const probeRow = idRows.find(r => r.actor === probeActor)
      // (2) The owner must demonstrably address the resource, and the replay must carry body evidence.
      if (!ownerRow || ownerRow.accessible !== true || typeof ownerRow.status !== 'number' || ownerRow.status < 200 || ownerRow.status >= 300) { ownerOk = false; rejects.owner += 1 }
      else if (typeof ownerRow.bodyBytes === 'number' && ownerRow.bodyBytes <= (mutating ? 12 : 2)) { ownerOk = false; ownerTrivial = true; rejects.trivial += 1 }
      if (!probeRow || probeRow.accessible !== true) { probeOk = false; rejects.probe += 1 }
      else if (!mutating && Number(probeRow.similarityToOwner ?? hit.similarityToOwner ?? 0) < 0.7) { probeOk = false; rejects.probe += 1 }
      const anonRow = idRows.find(r => r.actor === 'anonymous')
      // Public data readable by anonymous callers with the same body is not an authorization failure.
      if (!mutating && anonRow?.accessible === true && ownerRow) {
        const sameBody = typeof anonRow.bodySha256 === 'string' && anonRow.bodySha256 === ownerRow.bodySha256
        const similar = Number(anonRow.similarityToOwner ?? 0) >= 0.7
        if (sameBody || similar) { ownerOk = false; rejects.public += 1 }
      }
    }
    const bodyTemplate: unknown = hit.bodyTemplate !== undefined && hit.bodyTemplate !== null ? hit.bodyTemplate : {}
    const elevated = privilegedRoute.test(o.hyp.endpoint.path)
    const mutatingActor = hit.actor === 'anonymous' ? null : other
    // A vertical function-level proof: the privileged control persona invokes an elevated route the
    // probe persona must not reach. The role differential is only declared when the run's own admin
    // credential is the control actor.
    const vertical = Boolean(env.admin && owner === env.admin && mutatingActor && mutatingActor !== env.admin)
    const requiredRole = vertical ? 'admin' as const : undefined
    // A function-level mutation proves persistence only through a separate read of the function's
    // observable state; the probe observed the exact delta (and its benign baseline) already.
    const functionState = o.details.functionState as FunctionStateObservation | undefined
    if (mutating && probeOk && functionLevel && functionState && !o.hyp.deleteMethod) {
      out.push(...functionStateDeltaSpec(o, env, functionState, owner, mutatingActor, vertical && method !== 'DELETE'))
      continue
    }
    // A mutating route that acknowledges with a trivial `{ok:true}` body, or an elevated action whose
    // response is only an echo, has real impact only when a separate read shows the state change.
    if (mutating && probeOk && elevated && (ownerTrivial || ownerOk)) {
      // Self-service is a fresh, unprobed victim for the same elevated function: the viewer invokes
      // it on its own account and re-reads its own profile. Never for a delete (it would remove the
      // reader) and never for a collection read.
      const selfRoute = !functionLevel && elevated && method !== 'DELETE' ? identityRoute(env) : null
      if (selfRoute && env.viewer && env.viewerUserId && !selfReadbackEmitted.has(method)) {
        selfReadbackEmitted.add(method)
        out.push(...stateDeltaSpec(o, env, { path: selfRoute, detail: false, reserved: false }, env.viewerUserId,
          method, bodyTemplate, mutatingActor, privilegedLiteral(bodyTemplate),
          { persona: env.viewer, vertical: vertical && method !== 'DELETE', ...(requiredRole ? { requiredRole } : {}) }))
      }
      let read: ReadTarget | null = null
      let persona: string | null = null
      let selfRead = false
      if (functionLevel) {
        // A trivial function response cannot be its own readback: a same-path read would just
        // re-observe the echo. Only a non-trivial state read (or a separate observable route)
        // can prove persistence.
        if (elevated && !ownerTrivial) {
          read = { path: o.hyp.endpoint.path, detail: true, reserved: false }
          persona = owner
        }
      } else {
        read = inferReadTarget(env, id, o.hyp.endpoint.path)
        if (read) persona = read.detail ? owner : readPersonaFor(env, id)
        if (!read || !persona) {
          const identity = identityReadTarget(env, id)
          if (identity) { read = { path: identity.path, detail: false, reserved: false }; persona = identity.persona; selfRead = true }
        }
      }
      if (read && persona) {
        // A vertical (BFLA) claim is only declared when the readback is the mutated object itself:
        // a collection sweep cannot prove the role differential and would over-claim.
        const directRead = read.detail || selfRead
        out.push(...stateDeltaSpec(o, env, read, id, method, bodyTemplate, mutatingActor, privilegedLiteral(bodyTemplate),
          { persona, vertical: vertical && method !== 'DELETE' && directRead, ...(requiredRole ? { requiredRole } : {}) }))
        continue
      }
      // The reserved-victim delete proof reads and mutates as the writer, so it does not need a
      // separately harvested reader for the identifier.
      if (read && !persona && method === 'DELETE' && !read.detail && (env.viewer ?? owner)) {
        out.push(...stateDeltaSpec(o, env, read, id, method, bodyTemplate, mutatingActor, privilegedLiteral(bodyTemplate),
          { persona: (env.viewer ?? owner)!, vertical: false }))
        continue
      }
    }
    if (!ownerOk || !probeOk) continue

    const path = functionLevel
      ? o.hyp.endpoint.path
      : hasPathPlaceholder(o.hyp.endpoint.path)
        ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(id))
        : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(id)}`
    const parts: RequestParts = { method: method as RequestParts['method'], pathAndQuery: path, ...(mutating ? { jsonBody: bodyTemplate } : {}) }
    const probePersona = hit.actor === 'anonymous' ? null : other
    // Object-level routes always get a negative control. Real probe outcomes use a format-aware
    // nonexistent id; hand-built fixtures fall back to a random sentinel identifier.
    const neg = functionLevel ? null : negativeControlJq(mutating)
    const ownerJq = nonTrivial('c1', mutating ? 12 : 3)
    const probeJq = nonTrivial('p1', mutating ? 12 : 3)
    const jq = `{ controlPassed: ((${ownerJq})${neg ? ` and (${neg})` : ''}), ` +
      `confirmed: ((${probeJq})${neg ? ` and (${neg})` : ''} and (${matchesOwnerJq()})), ` +
      `observed: ("probe status=" + (.steps.p1.status | tostring)${neg ? ' + " bogus status=" + (.steps.c2.status | tostring)' : ''}), ` +
      'expected: "non-owner denied" }'
    const steps: Array<Record<string, unknown>> = []
    if (!functionLevel) {
      const negativeId = rows === null ? `kovo-none-${randomBytes(5).toString('hex')}` : bogusIdFor(id)
      const negativePath = hasPathPlaceholder(o.hyp.endpoint.path)
        ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(negativeId))
        : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(negativeId)}`
      steps.push(stepOf(env, 'c2', 'control', `Authorized actor addresses a nonexistent identifier (${negativeId})`,
        { method: method as RequestParts['method'], pathAndQuery: negativePath, ...(mutating ? { jsonBody: bodyTemplate } : {}) },
        owner, {}, NEGATIVE_CONTROL_STATUS))
    }
    steps.push(stepOf(env, 'c1', 'control', 'Authorized actor performs the request', parts, owner))
    steps.push(stepOf(env, 'p1', 'probe', `${probePersona ? 'Lower-privileged actor' : 'Unauthenticated caller'} performs the same request`, parts, probePersona))
    out.push({
      kind: 'http_chain',
      spec: {
        ...baseFields(env, 'Cross-actor object or function access', 'CWE-639', 'broken-access-control', 'high', jq),
        kind: 'http_chain',
        steps,
      },
    })
  }
  if (out.length === 0 && process.env.KOVO_BENCH_DEBUG === '1') {
    process.stderr.write(`[spec-skip] authz_matrix ${o.hyp.endpoint.path}: owner=${rejects.owner} probe=${rejects.probe} public=${rejects.public} trivial=${rejects.trivial}\n`)
  }
  return out
}

function massAssignmentValue(field: string, privileged: boolean): string | boolean {
  if (/^(?:is|has|verified|admin|emailVerified|enabled|active|superuser|staff)/i.test(field)) return privileged
  if (privileged) {
    if (/role|admin|permission|privilege|scope/i.test(field)) return 'admin'
    if (/plan|tier/i.test(field)) return 'enterprise'
    if (/org|tenant|team|group/i.test(field)) return '1'
    return 'kovo-privileged'
  }
  if (/role|permission|privilege|scope/i.test(field)) return 'user'
  if (/plan|tier/i.test(field)) return 'free'
  if (/org|tenant|team|group/i.test(field)) return '0'
  return 'kovo-low'
}

/**
 * Mass assignment proven as a *transition*: write a low-privilege value (control), read it back,
 * then overpost the privileged value (probe) and read again. Valid even when the account already
 * holds the privileged value before the replay.
 */
function synthMassAssignmentTransition(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'mass_assignment')
  if (!hit || !env.owner) return []
  const field = String(hit.field ?? '')
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(field)) return []
  const lowValue = massAssignmentValue(field, false)
  const expected = massAssignmentValue(field, true)
  if (lowValue === expected) return []
  const method = (o.hyp.method === 'PUT' ? 'PUT' : o.hyp.method === 'PATCH' ? 'PATCH' : 'POST') as 'POST' | 'PUT' | 'PATCH'
  const path = hasPathPlaceholder(o.hyp.endpoint.path) ? fillPlaceholders(o.hyp.endpoint.path, '1') : o.hyp.endpoint.path
  const read: RequestParts = { method: 'GET', pathAndQuery: path }
  const write = (value: string | boolean): RequestParts => ({ method, pathAndQuery: path, jsonBody: { [field]: value } })
  const fieldLit = jqStr(field)
  const expectedLit = typeof expected === 'boolean' ? String(expected) : jqStr(expected)
  const lowLit = typeof lowValue === 'boolean' ? String(lowValue) : jqStr(lowValue)
  const jq = `{ controlPassed: (${is2xx('c1')} and ((.steps.c1.json | type) == "object") and (.steps.c1.json[${fieldLit}] == ${lowLit})), ` +
    `confirmed: ((${is2xx('p2')} and (.steps.p2.json[${fieldLit}] == ${expectedLit}))), ` +
    `observed: (("${field}=" + ((.steps.p2.json[${fieldLit}]) | tostring))), expected: "privileged field must not be writable" }`
  const spec = {
    ...baseFields(env, 'Mass assignment of a privileged profile field', 'CWE-915', 'mass-assignment', 'high', jq),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'w1', 'control', `Baseline write of a low-privilege "${field}" value`, write(lowValue), env.owner),
      stepOf(env, 'c1', 'control', 'Read the record to confirm the baseline value', read, env.owner),
      stepOf(env, 'p1', 'probe', `Overpost the privileged "${field}" field`, write(expected), env.owner),
      stepOf(env, 'p2', 'probe', 'Re-read the record to observe persistence', read, env.owner),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

export function synthMassAssignment(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'mass_assignment' && a.persisted === true)
  if (!hit || !env.owner) return []
  const field = String(hit.field ?? '')
  // Field names are replayed inside jq and JSON bodies; reject anything that is not a plain identifier.
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(field)) return []
  const out = synthMassAssignmentTransition(o, env)
  if (out.length > 0) return out
  const isBool = /^(?:is|has|verified|admin|emailVerified)/i.test(field)
  const value: string | boolean = isBool ? true : `kovo_ma_${randomBytes(3).toString('hex')}`
  const read: RequestParts = { method: 'GET', pathAndQuery: o.hyp.endpoint.path }
  const write: RequestParts = {
    method: o.hyp.endpoint.method === 'PUT' || o.hyp.endpoint.method === 'PATCH' ? o.hyp.endpoint.method as 'PUT' | 'PATCH' : (o.hyp.method === 'GET' ? 'PATCH' : o.hyp.method),
    pathAndQuery: o.hyp.endpoint.path, jsonBody: { [field]: value },
  }
  const has = isBool
    ? (id: string) => `((.steps.${id}.json | .[${jqStr(field)}]) == true)`
    : (id: string) => `(.steps.${id}.body | contains(${jqStr(String(value))}))`
  const spec = {
    ...baseFields(env, 'Mass assignment of privileged field', 'CWE-915', 'broken-access-control', 'high',
      `{ controlPassed: (${is2xx('c1')} and .steps.p1.status < 300), confirmed: (${has('p2')} and (${has('c1')} | not)), observed: ("p2.status=" + (.steps.p2.status | tostring)), expected: "privileged field is not client-writable" }`),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'c1', 'control', 'Read the record before overposting', read, env.owner),
      stepOf(env, 'p1', 'probe', 'Overpost a privileged field', write, env.owner),
      stepOf(env, 'p2', 'probe', 'Read the record back', read, env.owner),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

/**
 * Second-order SSRF: register a benign/canary URL through the write route, then trigger the app's
 * own fetch step. The verifier mints distinct control/probe canaries so a callback must come from
 * the probe registration, not from shared infrastructure.
 */
export function synthSecondOrderSsrf(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'second_order_ssrf_callback')
  if (!hit || !o.hyp.param) return []
  const param = o.hyp.param.name
  const location = o.hyp.location ?? 'json'
  const path = probePathFor(o.hyp)
  const pattern = typeof hit.triggerPattern === 'string' && hit.triggerPattern.startsWith('/') ? hit.triggerPattern : null
  if (!pattern) return []
  const siblings: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name === param || p.isCsrf || p.location !== location) continue
    siblings[p.name] = siblingValue(p.name, env)
  }
  const register = (value: string): RequestParts | null => {
    switch (location) {
      case 'query': return { method: o.hyp.method, pathAndQuery: appendQuery(path, param, value, false) }
      case 'form': {
        const all = { ...siblings, [param]: value }
        return {
          method: o.hyp.method, pathAndQuery: path,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          textBody: Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&'),
        }
      }
      case 'json': default: return { method: o.hyp.method, pathAndQuery: path, jsonBody: { ...siblings, [param]: value } }
    }
  }
  const control = register('http://kovo-control.invalid/')
  const probe = register('{{canary_url}}')
  if (!control || !probe) return []
  const registerStep = stepOf(env, 'p1', 'probe', 'Register the canary URL through the write route', probe)
  const steps = [
    stepOf(env, 'c1', 'control', 'Register a benign URL (no callback expected)', control),
    { ...registerStep, extract: [{ varName: 'resource_id', from: 'json' as const, selector: 'id' }] },
    stepOf(env, 'p2', 'probe', 'Trigger the stored URL fetch', { method: 'POST', pathAndQuery: pattern.replace('{{id}}', '{{resource_id}}'), jsonBody: {} }),
  ]
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'Second-order server-side request forgery (stored URL fetched later)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
      kind: 'http_chain',
      steps,
    },
  }]
}

export function synthSsrf(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const secondOrder = synthSecondOrderSsrf(o, env)
  if (secondOrder.length > 0) return secondOrder
  const hit = o.anomalies.find(a => a.type === 'canary_callback' && a.variant === 'http')
  if (!hit) return []
  const control = requestParts(o, env, 'http://kovo-control.invalid/')
  const probe = requestParts(o, env, '{{canary_url}}')
  if (!control || !probe) return []
  const spec = {
    ...baseFields(env, 'Server-side request forgery (out-of-band callback)', 'CWE-918', 'ssrf', 'high', canaryJq('c1')),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'c1', 'control', 'Benign URL value (no callback expected)', control),
      stepOf(env, 'p1', 'probe', 'Kovo canary URL value', probe),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

const xmlBenign = '<?xml version="1.0" encoding="UTF-8"?><kovo><ping>ok</ping></kovo>'
const xxeBodies: Record<string, string> = {
  general_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "{{canary_url}}">]><root>&gxxe;</root>',
  param_entity: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % gxxep SYSTEM "{{canary_url}}"> %gxxep;]><root>ok</root>',
  svg_dtd: '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE svg [<!ENTITY svgx SYSTEM "{{canary_url}}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&svgx;</text></svg>',
}

export function synthXxe(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'xxe_canary_callback')
  if (!hit) return []
  const body = xxeBodies[String(hit.variant)] ?? xxeBodies.general_entity
  const headers = { 'Content-Type': 'application/xml' }
  const path = o.hyp.endpoint.path
  const method = o.hyp.method === 'GET' ? 'POST' : o.hyp.method
  const spec = {
    ...baseFields(env, 'XML external entity injection (out-of-band callback)', 'CWE-611', 'xxe', 'high', canaryJq('c1')),
    kind: 'http_chain',
    steps: [
      stepOf(env, 'c1', 'control', 'Benign XML document', { method, pathAndQuery: path, headers, textBody: xmlBenign }),
      stepOf(env, 'p1', 'probe', 'XML document with external entity to Kovo canary', { method, pathAndQuery: path, headers, textBody: body }),
    ],
  }
  return [{ kind: 'http_chain', spec }]
}

const sstiTemplates: Record<string, string> = {
  'jinja2/twig': '{{{{nonce_a}}*{{nonce_b}}}}',
  erb: '<%={{nonce_a}}*{{nonce_b}}%>',
  'freemarker/el': '${{{nonce_a}}*{{nonce_b}}}',
  'spel/pebble': '#{{{nonce_a}}*{{nonce_b}}}',
  thymeleaf: '[[${{{nonce_a}}*{{nonce_b}}}]]',
}

/**
 * Command injection proven with a split-echo nonce: the assembled nonce only appears when the shell
 * executes two concatenated echo operands, so plain reflection cannot satisfy the proof.
 */
export function synthCommandInjection(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'command_executed')
  if (!hit || !o.hyp.param) return []
  const base = String(hit.baseValue ?? '127.0.0.1').slice(0, 64)
  const variant = String(hit.variant)
  // The two nonces must be joined by execution syntax, not literal adjacency: the verifier rejects
  // specs where the assembled token already appears in the outbound request.
  const templates: Record<string, string> = {
    semicolon_echo: `${base}; echo {{nonce_part1}}$(echo {{nonce_part2}})`,
    subshell_echo: `${base}$(echo {{nonce_part1}})$(echo {{nonce_part2}})`,
    quote_break: `${base}"; echo {{nonce_part1}}$(echo {{nonce_part2}}); "`,
    quote_break_id: `${base}"; id; echo {{nonce_part1}}$(echo {{nonce_part2}}); "`,
    pipe_echo: `${base} | echo {{nonce_part1}}$(echo {{nonce_part2}})`,
    backtick_echo: `${base}\`echo {{nonce_part1}}$(echo {{nonce_part2}})\``,
  }
  const template = templates[variant] ?? templates.semicolon_echo
  const control = requestParts(o, env, base)
  const probe = requestParts(o, env, template)
  if (!control || !probe) return []
  const out: SynthesizedSpec[] = [{
    kind: 'rce_proof',
    spec: {
      ...baseFields(env, 'Command injection via shell metacharacters (nonce echo proof)', 'CWE-78', 'injection-input', 'critical',
        '{ controlPassed: (.control.status < 500), confirmed: (.proof.splitEchoVerified == true), observed: ("splitEcho=" + ((.proof.splitEchoVerified // false) | tostring)), expected: "shell metacharacters are inert data" }'),
      kind: 'rce_proof',
      proofMode: 'split_echo',
      requiresTier3Approval: true,
      controlStep: stepOf(env, 'c1', 'control', 'Benign value', control),
      probeStep: stepOf(env, 'p1', 'probe', 'Verifier-minted split echo operands', probe),
    },
  }]
  // Second proof shape: the observed payload's nonce appears in the response while the payload
  // itself was not reflected. Rejected by the split-echo verifier when the simulator renders the
  // substitution on its own line, but an http_chain assertion can still prove execution.
  const observedPayload = typeof hit.payload === 'string' ? hit.payload : ''
  const nonce = typeof hit.nonce === 'string' ? hit.nonce : ''
  if (observedPayload.length > 0 && observedPayload.length <= 200 && !/[\r\n\0]/.test(observedPayload) &&
      /^[A-Za-z0-9]{8,40}$/.test(nonce)) {
    const observedProbe = requestParts(o, env, observedPayload)
    if (observedProbe) {
      const jq = `{ controlPassed: ((.steps.c1.status < 500) and ((.steps.c1.body | contains(${jqStr(nonce)})) | not)), ` +
        `confirmed: ((${is2xx('p1')}) and (.steps.p1.body | contains(${jqStr(nonce)})) and ((.steps.p1.body | contains(${jqStr(observedPayload)})) | not)), ` +
        `observed: ("nonce=" + (${jqStr(nonce)}) + " reflected=" + ((.steps.p1.body | contains(${jqStr(observedPayload)})) | tostring)), expected: "shell metacharacters are inert data" }`
      out.push({
        kind: 'http_chain',
        spec: {
          ...baseFields(env, 'Command injection via shell metacharacters (observed nonce proof)', 'CWE-78', 'injection-input', 'critical', jq),
          kind: 'http_chain',
          steps: [
            stepOf(env, 'c1', 'control', 'Benign value', control),
            stepOf(env, 'p1', 'probe', 'Observed metacharacter payload', observedProbe),
          ],
        },
      })
    }
  }
  return out
}

/**
 * Path traversal with a genuine out-of-jail oracle: the probe payload must return content that a
 * nonexistent sibling traversal cannot, or match a well-known file signature.
 */
export function synthTraversal(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'path_traversal_escape')
  if (!hit || !o.hyp.param) return []
  const param = o.hyp.param.name
  const location = o.hyp.location ?? 'query'
  const raw = String(hit.payload ?? '')
  if (!raw || raw.length > 200 || /[\r\n\0\\]/.test(raw)) return []
  const controlValue = `../kovo-none-${randomBytes(4).toString('hex')}.txt`
  const build = (value: string): RequestParts => {
    // Reuse the probe's injection encoding (query/form values are URL-encoded exactly once by the
    // broker), so the replay reproduces the payload the oracle actually accepted.
    if (location === 'query' || location === 'form') {
      const parts = requestParts(o, env, value)
      if (parts) return parts
    }
    return { method: o.hyp.method, pathAndQuery: o.hyp.endpoint.path, jsonBody: { [param]: value } }
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
    spec: {
      ...baseFields(env, 'Path traversal escapes the served root (jail-escape read)', 'CWE-22', 'path-traversal', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Nonexistent sibling traversal control', build(controlValue)),
        stepOf(env, 'p1', 'probe', 'Traversal payload that resolves outside the served root', build(raw)),
      ],
    },
  }]
}

export function synthSsti(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'expression_evaluated')
  if (!hit) return []
  const tpl = sstiTemplates[String(hit.engine)]
  const control = requestParts(o, env, 'kovo')
  const probe = tpl ? requestParts(o, env, tpl) : null
  if (!control || !probe) return []
  const spec = {
    ...baseFields(env, 'Server-side template injection (arithmetic evaluation)', 'CWE-1336', 'injection-input', 'high',
      '{ controlPassed: (.control.status < 500), confirmed: (.proof.mathVerified == true), observed: ("mathVerified=" + ((.proof.mathVerified // false) | tostring)), expected: "template input is not evaluated" }'),
    kind: 'rce_proof',
    proofMode: 'dynamic_math',
    requiresTier3Approval: true,
    controlStep: stepOf(env, 'c1', 'control', 'Benign value', control),
    probeStep: stepOf(env, 'p1', 'probe', 'Verifier-minted arithmetic expression', probe),
  }
  return [{ kind: 'rce_proof', spec }]
}
