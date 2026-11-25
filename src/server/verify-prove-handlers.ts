/**
 * Authoritative host proof RPC executors (`prove.*`) — single source of truth
 * for both thin worker SDKs (`kovo_verify.ts` and `kovo_verify.py`).
 *
 * Depends strictly downward on `verify-claims.ts` and `oracle-invariants.ts`;
 * receives host runtime capabilities via the narrow `ProveHandlerHost` seam.
 */
import type { BoundaryClass, ImpactClass } from './oracle-invariants.ts'
import {
  asRecord,
  describeMissingEvidence,
  evaluateClaim,
  TranscriptStore,
} from './verify-claims.ts'
import type { VerifyCanaryBroker, VerifyClaim } from './verify-claims.ts'

export type ProveHttpExchangeResult = {
  exchangeId: string
  status: number
  method: string
  pathAndQuery: string
  headers: Record<string, string>
  body: string
  bodyPreview: string
  bodyBytes: number
  bodySha256: string
  durationMs: number
  personaHandle: string | null
}

export interface ProveHandlerHost {
  readonly transcript: TranscriptStore
  readonly defaultOrigin: string | undefined
  readonly canaryBroker: VerifyCanaryBroker | undefined
  runHttpExchange(args: Record<string, unknown>, nonce: string): Promise<ProveHttpExchangeResult>
  runOob(args: Record<string, unknown>): Promise<unknown>
  runRace(args: Record<string, unknown>, nonce: string): Promise<unknown>
  scrubRecord<T>(value: T): T
}

function parseJsonSafe(raw: unknown): unknown {
  if (typeof raw !== 'string' || !raw) return undefined
  try { return JSON.parse(raw) } catch { return undefined }
}

function cleanPersona(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  if (!trimmed || /^(?:anonymous|anon|unauthenticated|none)$/i.test(trimmed)) return undefined
  return trimmed
}

function normalizeBodyAndHeaders(
  rawBody: unknown,
  rawHeaders?: Record<string, string>,
): { body?: string; headers?: Record<string, string> } {
  const headers = rawHeaders ? { ...rawHeaders } : undefined
  if (rawBody === undefined || rawBody === null) return { ...(headers ? { headers } : {}) }
  if (typeof rawBody === 'string') return { body: rawBody, ...(headers ? { headers } : {}) }
  const serialized = JSON.stringify(rawBody)
  const hasContentType = Object.keys(headers ?? {}).some(k => k.toLowerCase() === 'content-type')
  const nextHeaders = hasContentType ? headers : { 'content-type': 'application/json', ...(headers ?? {}) }
  return { body: serialized, ...(nextHeaders ? { headers: nextHeaders } : {}) }
}

function normalizeArmTarget(
  defaultOrigin: string | undefined,
  input: unknown,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const split = (rawTarget: unknown, fallbackOrigin?: string): { origin?: string; path: string } => {
    if (typeof rawTarget === 'string') {
      const trimmed = rawTarget.trim()
      if (!trimmed) throw new Error('HTTP target path/URL must be non-empty.')
      if (/^https?:\/\//i.test(trimmed)) {
        const url = new URL(trimmed)
        return { origin: url.origin, path: url.pathname + url.search }
      }
      const path = trimmed.startsWith('/') ? trimmed : `/${trimmed}`
      return { ...(fallbackOrigin ? { origin: fallbackOrigin } : {}), path }
    }
    const rec = asRecord(rawTarget)
    if (!rec) throw new Error('HTTP target requires a path/URL string or object.')
    const direct = rec.url ?? rec.path ?? rec.pathAndQuery ?? rec.endpoint ?? rec.route
    if (typeof direct === 'string' && direct.trim()) {
      const res = split(direct, typeof rec.origin === 'string' ? rec.origin : fallbackOrigin)
      return { ...(typeof rec.origin === 'string' ? { origin: rec.origin } : (res.origin ? { origin: res.origin } : {})), path: res.path }
    }
    if (rec.target !== undefined) {
      const nested = split(rec.target, typeof rec.origin === 'string' ? rec.origin : fallbackOrigin)
      return { ...(typeof rec.origin === 'string' ? { origin: rec.origin } : (nested.origin ? { origin: nested.origin } : {})), path: nested.path }
    }
    throw new Error('HTTP target requires a path/URL string or object.')
  }

  const rec = asRecord(input)
  const nestedOpts = rec && asRecord(rec.options) ? (rec.options as Record<string, unknown>) : {}
  const targetSrc = rec && rec.target !== undefined && (rec.options !== undefined || typeof rec.target !== 'string')
    ? rec.target
    : input
  const target = split(targetSrc, defaultOrigin)
  const merged: Record<string, unknown> = { ...(rec ?? {}), ...nestedOpts, ...overrides }
  const rawHeaders = asRecord(merged.headers) as Record<string, string> | null
  const { body, headers } = normalizeBodyAndHeaders(merged.body, rawHeaders ?? undefined)
  const rawPersona = merged.persona ?? merged.as_persona ?? merged.as
  const persona = cleanPersona(rawPersona)
  const role = typeof merged.sessionGroupRole === 'string'
    ? merged.sessionGroupRole
    : typeof merged.role === 'string' ? merged.role : undefined
  const followRedirects = typeof merged.followRedirects === 'boolean'
    ? merged.followRedirects
    : typeof merged.follow_redirects === 'boolean' ? merged.follow_redirects : undefined
  return {
    ...(target.origin ? { origin: target.origin } : {}),
    path: target.path,
    method: typeof merged.method === 'string' && merged.method.trim() ? merged.method.trim().toUpperCase() : 'GET',
    ...(headers ? { headers } : {}),
    ...(body !== undefined ? { body } : {}),
    ...(persona ? { persona } : {}),
    ...(typeof merged.session === 'string' && merged.session ? { session: merged.session } : {}),
    ...(role ? { sessionGroupRole: role } : {}),
    ...(followRedirects !== undefined ? { followRedirects } : {}),
    ...(merged.capability !== undefined ? { capability: merged.capability } : {}),
    ...(typeof merged.entityId === 'string' && merged.entityId.trim() ? { entityId: merged.entityId.trim() } : {}),
    ...(typeof merged.correlationId === 'string' && merged.correlationId.trim() ? { correlationId: merged.correlationId.trim() } : {}),
    ...(Array.isArray(merged.correlationIds) ? { correlationIds: merged.correlationIds } : {}),
    ...(typeof merged.evidenceRole === 'string' && merged.evidenceRole.trim() ? { evidenceRole: merged.evidenceRole.trim() } : {}),
    ...(typeof merged.replayAttempt === 'string' && merged.replayAttempt.trim() ? { replayAttempt: merged.replayAttempt.trim() } : {}),
  }
}

function proofEntry(
  role: string,
  ex: { exchangeId?: string; personaHandle?: string | null; method?: string | null; pathAndQuery?: string | null; status?: number | null; durationMs?: number } | null,
  note?: string,
): Record<string, unknown> {
  return {
    exchangeId: ex?.exchangeId ?? '',
    role,
    personaHandle: ex?.personaHandle ?? null,
    method: ex?.method ?? null,
    pathAndQuery: ex?.pathAndQuery ?? null,
    status: ex?.status ?? null,
    durationMs: ex?.durationMs ?? 0,
    ...(note ? { note } : {}),
  }
}

function readFieldValue(value: unknown, path: string): { found: boolean; value?: unknown } {
  const parts: Array<string | number> = []
  for (const raw of path.replace(/\[(\d+)\]/g, '.$1').split('.')) {
    if (!raw) continue
    parts.push(/^\d+$/.test(raw) ? Number(raw) : raw)
  }
  let current: unknown = value
  for (const part of parts) {
    if (current === null || typeof current !== 'object') return { found: false }
    if (Array.isArray(current)) {
      if (typeof part !== 'number' || part < 0 || part >= current.length) return { found: false }
      current = current[part]
      continue
    }
    if (!(part in (current as Record<string, unknown>))) return { found: false }
    current = (current as Record<string, unknown>)[String(part)]
  }
  return { found: true, value: current }
}

function computeFieldDelta(before: unknown, after: unknown): { changedFields: string[]; added: string[]; removed: string[] } {
  const flatten = (val: unknown, prefix = '', out = new Map<string, string>(), depth = 0): Map<string, string> => {
    if (out.size >= 512 || depth > 6) return out
    if (val === null || typeof val !== 'object') {
      if (prefix) out.set(prefix, JSON.stringify(val))
      return out
    }
    if (Array.isArray(val)) {
      val.slice(0, 64).forEach((child, idx) => flatten(child, `${prefix}[${idx}]`, out, depth + 1))
      return out
    }
    for (const [k, child] of Object.entries(val as Record<string, unknown>)) {
      flatten(child, prefix ? `${prefix}.${k}` : k, out, depth + 1)
    }
    return out
  }
  const bf = flatten(before)
  const af = flatten(after)
  const changedFields: string[] = []
  const added: string[] = []
  const removed: string[] = []
  for (const [p, v] of af) {
    if (!bf.has(p)) added.push(p)
    else if (bf.get(p) !== v) changedFields.push(p)
  }
  for (const p of bf.keys()) if (!af.has(p)) removed.push(p)
  return { changedFields, added, removed }
}

export async function handleProveAccessBoundary(host: ProveHandlerHost, args: Record<string, unknown>, nonce: string): Promise<unknown> {
  const route = args.route ?? args.url ?? args.path
  if (!route) throw new Error('prove_access_boundary requires `route`.')
  const probeRoute = args.probeRoute ?? args.probe_route ?? route
  const method = typeof args.method === 'string' && args.method.trim() ? args.method.trim().toUpperCase() : 'GET'
  const controlOpts = asRecord(args.controlOptions ?? args.control_options) ?? {}
  const probeOpts = asRecord(args.probeOptions ?? args.probe_options) ?? {}
  const controlPersona = cleanPersona(args.controlPersona ?? args.control_persona ?? controlOpts.as ?? controlOpts.as_persona ?? controlOpts.persona)
  const probePersona = cleanPersona(args.probePersona ?? args.probe_persona ?? probeOpts.as ?? probeOpts.as_persona ?? probeOpts.persona)
  const controlSession = String(args.controlSession ?? args.control_session ?? 'access-boundary-control')
  const probeSession = String(args.probeSession ?? args.probe_session ?? 'access-boundary-probe')

  const controlArgs = normalizeArmTarget(host.defaultOrigin, route, {
    ...controlOpts,
    method,
    persona: controlPersona,
    as: undefined,
    as_persona: undefined,
    sessionGroupRole: 'control',
    session: controlSession,
  })
  const probeArgs = normalizeArmTarget(host.defaultOrigin, probeRoute, {
    ...probeOpts,
    method,
    persona: probePersona,
    as: undefined,
    as_persona: undefined,
    sessionGroupRole: 'probe',
    session: probeSession,
  })
  const control = await host.runHttpExchange(controlArgs, nonce)
  const probe = await host.runHttpExchange(probeArgs, nonce)

  const expectControlDenied = (args.expectControlDenied ?? args.expect_control_denied) !== false
  const rawVuln = args.vulnClass ?? args.vuln_class
  const vulnClass = typeof rawVuln === 'string' && rawVuln.trim() ? rawVuln.trim() : undefined
  const isAuthVuln = Boolean(vulnClass && /^(?:auth_bypass|jwt_forgery|broken_auth|auth_protocol|token_forgery|authentication_bypass)$/i.test(vulnClass))
  const rawBoundary = args.boundaryClass ?? args.boundary_class
  const boundaryClass: BoundaryClass = (rawBoundary === 'auth' || rawBoundary === 'access')
    ? rawBoundary
    : (isAuthVuln ? 'auth' : 'access')
  const parseOptBody = (b: unknown): unknown => b === undefined || b === null ? undefined : (typeof b === 'string' ? (parseJsonSafe(b) ?? b) : b)
  const controlReqBody = parseOptBody(controlOpts.body)
  const probeReqBody = parseOptBody(probeOpts.body)
  const actorRoles = asRecord(args.actorRoles ?? args.actor_roles) as Record<string, string> | null
  const actorTenants = asRecord(args.actorTenants ?? args.actor_tenants) as Record<string, string> | null
  const message = typeof args.message === 'string' && args.message ? args.message : undefined

  const claim: Extract<VerifyClaim, { kind: 'boundary' }> = {
    kind: 'boundary',
    boundaryClass,
    ...(vulnClass ? { vulnClass } : {}),
    controlExchangeId: control.exchangeId,
    probeExchangeId: probe.exchangeId,
    expectControlDenied,
    ...(controlReqBody !== undefined ? { controlRequestBody: controlReqBody } : {}),
    ...(probeReqBody !== undefined ? { probeRequestBody: probeReqBody } : {}),
    ...(actorRoles ? { actorRoles } : {}),
    ...(actorTenants ? { actorTenants } : {}),
    ...(message ? { message } : {}),
  }
  const check = evaluateClaim(host.transcript, claim, {})
  const missingEvidence = check.passed ? [] : describeMissingEvidence(check)
  const obs = check.observed ?? {}
  return host.scrubRecord({
    ok: check.passed,
    confirmed: check.passed,
    claim,
    endpoint: probe.pathAndQuery,
    control,
    probe,
    transcript: { control_denied: control.exchangeId, variant_crossed: probe.exchangeId },
    evidence: {
      controlStatus: control.status,
      variantStatus: probe.status,
      controlDenied: typeof obs.controlDenied === 'boolean' ? obs.controlDenied : (control.status === 401 || control.status === 403 || (control.status >= 300 && control.status < 400)),
      crossed: typeof obs.crossed === 'boolean' ? obs.crossed : (probe.status >= 200 && probe.status < 300 && probe.body.length >= 8),
    },
    rejectedBy: check.passed ? null : (typeof obs.rejectedBy === 'string' ? obs.rejectedBy : 'boundary'),
    missingEvidence,
    transcriptSummary: [
      proofEntry('control_denied', control),
      proofEntry('variant_crossed', probe),
    ],
  })
}

export async function handleProvePersistedMutation(host: ProveHandlerHost, args: Record<string, unknown>, nonce: string): Promise<unknown> {
  const readRoute = args.readRoute ?? args.read_route
  const mutationSpec = args.mutation ?? args.write
  if (!readRoute || !mutationSpec) {
    throw new Error('prove_persisted_mutation requires `readRoute` and `mutation`.')
  }
  const fieldPath = String(args.fieldPath ?? args.field_path ?? '')
  const mutRec = asRecord(mutationSpec)
  const mutNested = mutRec && asRecord(mutRec.options) ? (mutRec.options as Record<string, unknown>) : {}
  const mutPersonaRaw = mutNested.as ?? mutNested.as_persona ?? mutNested.persona ?? mutRec?.as ?? mutRec?.as_persona ?? mutRec?.persona
  const readPersona = cleanPersona(args.readPersona ?? args.read_persona ?? mutPersonaRaw)
  const mutatePersona = cleanPersona(args.mutatePersona ?? args.mutate_persona ?? mutPersonaRaw)
  const readMethod = typeof (args.readMethod ?? args.read_method) === 'string' ? String(args.readMethod ?? args.read_method).toUpperCase() : 'GET'
  const readSession = String(args.readSession ?? args.read_session ?? 'persisted-read')

  const before = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
    method: readMethod,
    ...(readPersona ? { persona: readPersona } : {}),
    sessionGroupRole: 'control',
    session: readSession,
  }), nonce)

  const mutArgs = normalizeArmTarget(host.defaultOrigin, mutationSpec, {
    method: typeof (mutNested.method ?? mutRec?.method) === 'string' ? String(mutNested.method ?? mutRec?.method).toUpperCase() : 'POST',
    ...(mutatePersona ? { persona: mutatePersona } : {}),
    sessionGroupRole: 'probe',
    session: String(mutNested.session ?? mutRec?.session ?? readSession),
  })
  if (typeof mutArgs.body === 'string') {
    const h = asRecord(mutArgs.headers) as Record<string, string> | null
    if (!Object.keys(h ?? {}).some(k => k.toLowerCase() === 'content-type')) {
      mutArgs.headers = { 'content-type': 'application/json', ...(h ?? {}) }
    }
  }
  const mutation = await host.runHttpExchange(mutArgs, nonce)
  const after = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
    method: readMethod,
    ...(readPersona ? { persona: readPersona } : {}),
    sessionGroupRole: 'control',
    session: readSession,
  }), nonce)

  const beforeJson = parseJsonSafe(before.body)
  const afterJson = parseJsonSafe(after.body)
  const beforeField = readFieldValue(beforeJson, fieldPath)
  const afterField = readFieldValue(afterJson, fieldPath)
  const fields = computeFieldDelta(beforeJson, afterJson)
  const delta = {
    fieldPath,
    before: beforeField.found ? beforeField.value : undefined,
    after: afterField.found ? afterField.value : undefined,
    changed: beforeField.found && afterField.found && JSON.stringify(beforeField.value) !== JSON.stringify(afterField.value),
    ...fields,
  }
  const hasExpect = args.hasCustomExpectFn !== true && (('expectDelta' in args && args.expectDelta !== undefined) || ('expect_delta' in args && args.expect_delta !== undefined))
  const expectedVal = 'expectDelta' in args ? args.expectDelta : args.expect_delta
  const expectationMatched = hasExpect ? JSON.stringify(delta.after) === JSON.stringify(expectedVal) : true

  const rawImpact = args.impactClass ?? args.impact_class
  const impactClass: ImpactClass = (typeof rawImpact === 'string' && rawImpact.trim() ? rawImpact.trim() : 'mass_assignment') as ImpactClass
  const reqJson = typeof mutArgs.body === 'string' ? parseJsonSafe(mutArgs.body) : undefined
  const claim: Extract<VerifyClaim, { kind: 'impact' }> = {
    kind: 'impact',
    impactClass,
    probeExchangeId: mutation.exchangeId,
    beforeExchangeId: before.exchangeId,
    afterExchangeId: after.exchangeId,
    ...(typeof (args.requiredRole ?? args.required_role) === 'string' && String(args.requiredRole ?? args.required_role) ? { requiredRole: String(args.requiredRole ?? args.required_role) } : {}),
    ...(typeof (args.resourceTenant ?? args.resource_tenant) === 'string' && String(args.resourceTenant ?? args.resource_tenant) ? { resourceTenant: String(args.resourceTenant ?? args.resource_tenant) } : {}),
    ...(Array.isArray(args.oracleEvents ?? args.oracle_events) ? { oracleEvents: (args.oracleEvents ?? args.oracle_events) as string[] } : {}),
    ...(asRecord(args.actorRoles ?? args.actor_roles) ? { actorRoles: (args.actorRoles ?? args.actor_roles) as Record<string, string> } : {}),
    ...(asRecord(args.actorTenants ?? args.actor_tenants) ? { actorTenants: (args.actorTenants ?? args.actor_tenants) as Record<string, string> } : {}),
    ...(reqJson !== undefined ? { requestBody: reqJson } : {}),
    ...(typeof args.message === 'string' && args.message ? { message: args.message } : {}),
  }

  const check = evaluateClaim(host.transcript, claim, {})
  const missing = new Set<string>(check.passed ? [] : describeMissingEvidence(check))
  if (!(before.status >= 200 && before.status < 300)) missing.add('before_get')
  if (!(mutation.status >= 200 && mutation.status < 300)) missing.add('mutation_success')
  if (!(after.status >= 200 && after.status < 300)) missing.add('after_get')
  if (beforeJson === undefined || afterJson === undefined) missing.add('json_readback')
  if (fieldPath && !delta.changed) missing.add(`field_delta:${fieldPath}`)
  if (!expectationMatched) missing.add('expected_delta')
  const missingEvidence = [...missing]
  const ok = check.passed && missingEvidence.length === 0
  return host.scrubRecord({
    ok,
    confirmed: ok,
    claim,
    endpoint: mutation.pathAndQuery,
    before,
    mutation,
    after,
    delta,
    expectationMatched,
    rejectedBy: ok ? null : (typeof check.observed?.rejectedBy === 'string' ? check.observed.rejectedBy : 'impact'),
    missingEvidence,
    transcriptSummary: [
      proofEntry('before_get', before),
      proofEntry('mutation', mutation),
      proofEntry('after_get', after),
    ],
  })
}

export async function handleProveDifferential(host: ProveHandlerHost, args: Record<string, unknown>, nonce: string): Promise<unknown> {
  if (args.control === undefined || args.control === null || args.variant === undefined || args.variant === null) {
    throw new Error('prove_boolean_or_timing_diff requires `control` and `variant`.')
  }
  const mode: 'boolean' | 'timing' = args.mode === 'timing' ? 'timing' : 'boolean'
  const session = typeof args.session === 'string' && args.session ? args.session : `diff-${mode}`
  const message = typeof args.message === 'string' && args.message ? args.message : undefined
  const controlExchanges: Array<ProveHttpExchangeResult> = []
  const variantExchanges: Array<ProveHttpExchangeResult> = []
  const rounds = mode === 'timing'
    ? Math.max(5, Math.min(Math.round(Number(args.rounds ?? 6)), 7))
    : Math.max(2, Math.min(Math.round(Number(args.rounds ?? 3)), 6))

  for (let index = 0; index < rounds; index += 1) {
    const order: Array<'control' | 'variant'> = index % 2 === 0 ? ['control', 'variant'] : ['variant', 'control']
    for (const which of order) {
      const armArgs = normalizeArmTarget(host.defaultOrigin, which === 'control' ? args.control : args.variant, {
        sessionGroupRole: which === 'control' ? 'control' : 'probe',
        session,
      })
      const ex = await host.runHttpExchange(armArgs, nonce)
      if (which === 'control') controlExchanges.push(ex)
      else variantExchanges.push(ex)
    }
  }
  const controlIds = controlExchanges.map(ex => ex.exchangeId)
  const variantIds = variantExchanges.map(ex => ex.exchangeId)

  if (mode === 'timing') {
    const maxPValue = Number(args.maxPValue ?? args.max_p_value ?? 0.05)
    const claim: Extract<VerifyClaim, { kind: 'timing' }> = {
      kind: 'timing',
      controlIds,
      variantIds,
      minPairs: rounds,
      maxPValue,
      ...(message ? { message } : {}),
    }
    const check = evaluateClaim(host.transcript, claim, {})
    const missingEvidence = check.passed ? [] : describeMissingEvidence(check)
    return host.scrubRecord({
      ok: check.passed,
      confirmed: check.passed,
      mode: 'timing',
      endpoint: variantExchanges[0]?.pathAndQuery ?? null,
      controlIds,
      variantIds,
      claim,
      stats: check.observed ?? {},
      exchanges: { control: controlExchanges, variant: variantExchanges },
      rejectedBy: check.passed ? null : 'timing',
      missingEvidence,
      transcriptSummary: [
        ...controlExchanges.map(ex => proofEntry('control', ex, `timing ${ex.durationMs}ms`)),
        ...variantExchanges.map(ex => proofEntry('probe', ex, `timing ${ex.durationMs}ms`)),
      ],
    })
  }

  const minDeltaTokens = Number(args.minDeltaTokens ?? args.min_delta_tokens ?? args.minSimilarityDelta ?? args.min_similarity_delta ?? 1)
  const maxSimilarity = Number(args.maxSimilarity ?? args.max_similarity ?? 1)
  const claim: Extract<VerifyClaim, { kind: 'structural_diff' }> = {
    kind: 'structural_diff',
    controlIds,
    variantIds,
    minRounds: rounds,
    minDeltaTokens,
    maxSimilarity,
    ...(message ? { message } : {}),
  }
  const check = evaluateClaim(host.transcript, claim, {})
  const missingEvidence = check.passed ? [] : describeMissingEvidence(check)
  const obs = check.observed ?? {}
  return host.scrubRecord({
    ok: check.passed,
    confirmed: check.passed,
    mode: 'boolean',
    endpoint: variantExchanges[0]?.pathAndQuery ?? null,
    controlIds,
    variantIds,
    claim,
    stats: {
      stableDelta: obs.stableDelta ?? [],
      similarity: obs.similarity ?? 1,
      rounds,
      stableControl: obs.stableControl ?? false,
      stableVariant: obs.stableVariant ?? false,
    },
    exchanges: { control: controlExchanges, variant: variantExchanges },
    rejectedBy: check.passed ? null : (typeof obs.rejectedBy === 'string' ? obs.rejectedBy : 'structural_diff'),
    missingEvidence,
    transcriptSummary: [
      ...controlExchanges.map(ex => proofEntry('control', ex)),
      ...variantExchanges.map(ex => proofEntry('probe', ex)),
    ],
  })
}

export async function handleProveOob(host: ProveHandlerHost, args: Record<string, unknown>, nonce: string): Promise<unknown> {
  const phase = typeof args.phase === 'string' ? args.phase : 'full'
  const immediateMs = Number(args.immediateMs ?? args.immediate_ms ?? 3_000)
  const windowMsRaw = args.windowMs ?? args.window_ms
  const windowMs = windowMsRaw !== undefined && windowMsRaw !== null ? Number(windowMsRaw) : undefined
  const timeoutMs = Number(args.timeoutMs ?? args.timeout_ms ?? Math.max(immediateMs, 6_000))
  const message = typeof args.message === 'string' && args.message ? args.message : undefined

  const startOob = async () => {
    const handle = await host.runOob({ action: 'mint', label: typeof args.token === 'string' && args.token ? args.token : 'oob' }) as {
      exchangeId: string
      token: string
      url: string
      dnsHost: string
    }
    const subscription = await host.runOob({
      action: 'subscribe',
      token: handle.token,
      exchangeId: handle.exchangeId,
      immediateMs,
      ...(windowMs !== undefined ? { windowMs } : {}),
    }) as { subscriptionId?: string; createdAt?: number; status?: string }
    return { handle, subscription }
  }

  if (phase === 'start') {
    return await startOob()
  }

  let handle: { exchangeId: string; token: string; url: string; dnsHost: string }
  let subscription: { subscriptionId?: string; createdAt?: number; status?: string }
  let injection: ProveHttpExchangeResult | null = null
  let injectionError: string | null = null

  if (phase === 'finish') {
    const h = asRecord(args.handle)
    if (!h || typeof h.exchangeId !== 'string' || typeof h.token !== 'string') {
      throw new Error('prove.oob finish requires handle from prove.oob start.')
    }
    handle = {
      exchangeId: h.exchangeId,
      token: h.token,
      url: String(h.url ?? ''),
      dnsHost: String(h.dnsHost ?? ''),
    }
    subscription = (asRecord(args.subscription) ?? {}) as { subscriptionId?: string; createdAt?: number; status?: string }
    const injRec = asRecord(args.injection)
    if (injRec && typeof injRec.exchangeId === 'string') {
      injection = injRec as ProveHttpExchangeResult
    }
    if (typeof args.injectionError === 'string' && args.injectionError) {
      injectionError = args.injectionError
    }
  } else {
    const started = await startOob()
    handle = started.handle
    subscription = started.subscription
    const render = (tpl: string) => tpl
      .split('{{canaryUrl}}').join(handle.url)
      .split('{{canaryToken}}').join(handle.token)
      .split('{{canaryHost}}').join(handle.dnsHost)
    try {
      const injectSpec = args.inject
      if (injectSpec !== undefined && injectSpec !== null) {
        const specRec = asRecord(injectSpec)
        const rawBody = specRec?.body
        const renderedBody = rawBody !== undefined
          ? render(typeof rawBody === 'string' ? rawBody : JSON.stringify(rawBody))
          : undefined
        const targetSource = typeof injectSpec === 'string' ? render(injectSpec) : {
          ...specRec,
          ...(typeof specRec?.target === 'string' ? { target: render(specRec.target) } : {}),
          ...(typeof specRec?.url === 'string' ? { url: render(specRec.url) } : {}),
          ...(typeof specRec?.path === 'string' ? { path: render(specRec.path) } : {}),
        }
        const injectArgs = normalizeArmTarget(host.defaultOrigin, targetSource, {
          method: typeof specRec?.method === 'string' ? specRec.method.toUpperCase() : 'POST',
          ...(renderedBody !== undefined ? { body: renderedBody } : {}),
          sessionGroupRole: 'probe',
          session: 'oob-injection',
        })
        injection = await host.runHttpExchange(injectArgs, nonce)
      }
    } catch (error) {
      injectionError = error instanceof Error ? error.message : 'OOB injection failed.'
    }
  }

  const wait = await host.runOob({
    action: 'wait',
    token: handle.token,
    ...(subscription.subscriptionId ? { subscriptionId: subscription.subscriptionId } : {}),
    ...(typeof subscription.createdAt === 'number' ? { subscriptionCreatedAt: subscription.createdAt } : {}),
    immediateMs,
    timeoutMs,
  }) as {
    exchangeId?: string
    checkExchangeId?: string
    hit?: boolean
    stage?: 'immediate' | 'late' | 'pending' | 'none'
    promoted?: boolean
    subscriptionId?: string | null
  }
  const claim: Extract<VerifyClaim, { kind: 'oob' }> = {
    kind: 'oob',
    exchangeId: handle.exchangeId,
    expectHit: true,
    ...(message ? { message } : {}),
  }
  const canary = host.canaryBroker
  const check = evaluateClaim(host.transcript, claim, canary ? { canary } : {})
  const hit = wait.hit === true && check.passed
  const missing = new Set<string>(check.passed ? [] : describeMissingEvidence(check))
  if (!subscription.subscriptionId) missing.add('pending_oob_subscription')
  if (injectionError) missing.add('injection')
  if (!hit) missing.add('oob_callback_hit')
  const missingEvidence = [...missing]
  const ok = check.passed && missingEvidence.length === 0
  const mintEntry = {
    exchangeId: handle.exchangeId,
    role: 'oob_mint',
    personaHandle: null,
    method: 'MINT',
    pathAndQuery: '/',
    status: null,
    durationMs: 0,
  }
  return host.scrubRecord({
    ok,
    confirmed: ok,
    claim,
    endpoint: injection?.pathAndQuery ?? null,
    token: handle.token,
    url: handle.url,
    dnsHost: handle.dnsHost,
    hit,
    stage: wait.stage ?? (hit ? 'immediate' : subscription.subscriptionId ? 'pending' : 'none'),
    promoted: wait.promoted === true,
    subscriptionId: wait.subscriptionId ?? subscription.subscriptionId ?? null,
    exchanges: { mint: handle.exchangeId, injection: injection?.exchangeId ?? null, wait: wait.exchangeId ?? wait.checkExchangeId ?? null },
    rejectedBy: ok ? null : (injectionError ? 'injection' : 'oob'),
    missingEvidence,
    transcriptSummary: [
      mintEntry,
      ...(subscription.subscriptionId ? [{ ...mintEntry, exchangeId: subscription.subscriptionId, role: 'pending_oob', method: 'SUBSCRIBE', note: subscription.status ?? 'pending' }] : []),
      ...(injection ? [proofEntry('oob_injection', injection)] : []),
      ...(wait.exchangeId ? [{
        exchangeId: wait.exchangeId,
        role: 'oob_wait',
        personaHandle: null,
        method: 'WAIT',
        pathAndQuery: '/oob/wait',
        status: null,
        durationMs: 0,
        note: hit ? 'hit' : 'no callback',
      }] : []),
    ],
  })
}

export async function handleProveRace(host: ProveHandlerHost, args: Record<string, unknown>, nonce: string): Promise<unknown> {
  const rawRequests = args.requests
  const minDistinct = Number(args.minDistinctOutcomes ?? args.min_distinct_outcomes ?? 2)
  if (!Array.isArray(rawRequests) || rawRequests.length < 2 || rawRequests.length > 10) {
    const claim: Extract<VerifyClaim, { kind: 'race' }> = {
      kind: 'race',
      exchangeIds: [],
      mode: 'http1-fallback',
      minDistinctOutcomes: minDistinct,
    }
    return {
      ok: false,
      confirmed: false,
      claim,
      mode: 'http1-fallback',
      fallbackReason: 'race requires between 2 and 10 requests',
      summary: {},
      exchanges: [],
      rejectedBy: 'race',
      missingEvidence: ['race_requests'],
      transcriptSummary: [],
    }
  }

  const sessionBase = typeof args.session === 'string' && args.session ? args.session : undefined
  const topEntityId = typeof args.entityId === 'string' && args.entityId.trim() ? args.entityId.trim() : undefined
  const topCorrelationId = typeof args.correlationId === 'string' && args.correlationId.trim() ? args.correlationId.trim() : undefined
  const topCorrelationIds = Array.isArray(args.correlationIds) ? args.correlationIds : undefined
  let firstRequestBody: unknown = undefined
  const normalizedRequests = rawRequests.map((req, index) => {
    const normalized = normalizeArmTarget(host.defaultOrigin, req, {
      sessionGroupRole: 'probe',
      session: sessionBase ?? `race-${index}`,
    })
    if (topEntityId && normalized.entityId === undefined) normalized.entityId = topEntityId
    if (topCorrelationId && normalized.correlationId === undefined) normalized.correlationId = topCorrelationId
    if (topCorrelationIds && normalized.correlationIds === undefined) normalized.correlationIds = topCorrelationIds
    if (index === 0 && typeof normalized.body === 'string') {
      firstRequestBody = parseJsonSafe(normalized.body) ?? normalized.body
    }
    return normalized
  })
  const firstPersona = typeof normalizedRequests[0]?.persona === 'string' ? normalizedRequests[0].persona : undefined
  const readRoute = args.readRoute ?? args.read_route
  const readPersona = cleanPersona(args.readPersona ?? args.read_persona ?? firstPersona)
  const readMethod = typeof (args.readMethod ?? args.read_method) === 'string'
    ? String(args.readMethod ?? args.read_method).toUpperCase()
    : 'GET'

  let baseline: ProveHttpExchangeResult | null = null
  if (readRoute !== undefined && readRoute !== null) {
    baseline = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
      method: readMethod,
      ...(readPersona ? { persona: readPersona } : {}),
      sessionGroupRole: 'setup',
      session: sessionBase ? `${sessionBase}-baseline` : 'race-baseline',
    }), nonce)
  }

  const raceRes = await host.runRace({ requests: normalizedRequests }, nonce) as {
    mode?: 'h2-single-packet' | 'http1-fallback'
    fallbackReason?: string | null
    summary?: Record<string, unknown>
    results?: Array<{
      exchangeId: string; status: number; durationMs: number; bodySha256: string
      consumedCapabilityId?: string; consumedCapabilities?: string[]; derivedFromCapabilityIds?: string[]
    }>
  }
  const mode = raceRes.mode ?? 'http1-fallback'
  const exchanges = (raceRes.results ?? []).map(item => ({
    exchangeId: item.exchangeId,
    status: item.status,
    durationMs: item.durationMs,
    bodySha256: item.bodySha256,
    ...(item.consumedCapabilityId ? { consumedCapabilityId: item.consumedCapabilityId } : {}),
    ...(item.consumedCapabilities?.length ? { consumedCapabilities: item.consumedCapabilities } : {}),
    ...(item.derivedFromCapabilityIds?.length ? { derivedFromCapabilityIds: item.derivedFromCapabilityIds } : {}),
  }))

  let post: ProveHttpExchangeResult | null = null
  let serial: ProveHttpExchangeResult | null = null
  let serialPost: ProveHttpExchangeResult | null = null
  if (readRoute !== undefined && readRoute !== null) {
    post = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
      method: readMethod,
      ...(readPersona ? { persona: readPersona } : {}),
      sessionGroupRole: 'control',
      session: sessionBase ? `${sessionBase}-post` : 'race-post',
    }), nonce)
    const serialSpec = args.serialRequest ?? args.serial_request ?? rawRequests[0]
    const serialArgs = normalizeArmTarget(host.defaultOrigin, serialSpec, {
      sessionGroupRole: 'control',
      session: sessionBase ? `${sessionBase}-serial` : 'race-serial',
    })
    if (!serialArgs.method && normalizedRequests[0]?.method) serialArgs.method = normalizedRequests[0].method
    if (!serialArgs.persona && firstPersona) serialArgs.persona = firstPersona
    serial = await host.runHttpExchange(serialArgs, nonce)
    if (serial.status >= 200 && serial.status < 300) {
      serialPost = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
        method: readMethod,
        ...(readPersona ? { persona: readPersona } : {}),
        sessionGroupRole: 'control',
        session: sessionBase ? `${sessionBase}-serial-post` : 'race-serial-post',
      }), nonce)
    }
  }

  const ackedCount = exchanges.filter(item => item.status >= 200 && item.status < 300).length
  const baselineId = baseline?.exchangeId ?? (typeof (args.baselineExchangeId ?? args.baseline_exchange_id) === 'string' ? String(args.baselineExchangeId ?? args.baseline_exchange_id) : undefined)
  const postId = post?.exchangeId ?? (typeof (args.postExchangeId ?? args.post_exchange_id) === 'string' ? String(args.postExchangeId ?? args.post_exchange_id) : undefined)
  const rawSerialIds = args.serialExchangeIds ?? args.serial_exchange_ids
  const serialIds = serial ? [serial.exchangeId] : (Array.isArray(rawSerialIds) && rawSerialIds.length ? rawSerialIds.map(String) : undefined)
  const serialPreId = typeof (args.serialPreExchangeId ?? args.serial_pre_exchange_id) === 'string' ? String(args.serialPreExchangeId ?? args.serial_pre_exchange_id) : undefined
  const serialPostId = serialPost?.exchangeId ?? (typeof (args.serialPostExchangeId ?? args.serial_post_exchange_id) === 'string' ? String(args.serialPostExchangeId ?? args.serial_post_exchange_id) : undefined)
  const hasConservedContext = Boolean((readRoute !== undefined && readRoute !== null) || baselineId || postId || serialIds?.length)
  const explicitExpectAll = args.expectAllSuccess ?? args.expect_all_success
  const expectAllSuccess = explicitExpectAll !== undefined
    ? Boolean(explicitExpectAll)
    : !(hasConservedContext && ackedCount >= 2 && ackedCount < exchanges.length)
  const burstIds = exchanges.map(item => item.exchangeId)
  const balanceField = args.balanceField ?? args.balance_field
  const capField = args.capField ?? args.cap_field
  const unitDebit = args.unitDebit ?? args.unit_debit
  const vulnClass = args.vulnClass ?? args.vuln_class

  const claim: Extract<VerifyClaim, { kind: 'race' }> = {
    kind: 'race',
    exchangeIds: burstIds,
    ...(hasConservedContext ? { burstExchangeIds: burstIds } : {}),
    ...(baselineId ? { baselineExchangeId: baselineId } : {}),
    ...(postId ? { postExchangeId: postId } : {}),
    ...(serialPreId ? { serialPreExchangeId: serialPreId } : {}),
    ...(serialIds ? { serialExchangeIds: serialIds } : {}),
    ...(serialPostId ? { serialPostExchangeId: serialPostId } : {}),
    ...(typeof balanceField === 'string' && balanceField ? { balanceField } : {}),
    ...(typeof capField === 'string' && capField ? { capField } : {}),
    ...(unitDebit !== undefined && unitDebit !== null ? { unitDebit: Number(unitDebit) } : {}),
    ...(typeof vulnClass === 'string' && vulnClass ? { vulnClass } : hasConservedContext ? { vulnClass: 'race_double_spend' } : {}),
    ...(firstRequestBody !== undefined ? { requestBody: firstRequestBody } : {}),
    mode,
    minDistinctOutcomes: minDistinct,
    expectAllSuccess,
    ...(typeof args.message === 'string' && args.message ? { message: args.message } : {}),
  }

  const check = evaluateClaim(host.transcript, claim, {})
  const missing = new Set<string>(check.passed ? [] : describeMissingEvidence(check))
  if (args.barrier === 'h2' && mode !== 'h2-single-packet') missing.add('h2_single_packet_barrier')
  if (hasConservedContext && ackedCount < 2) missing.add('acked_burst_mutations')
  const missingEvidence = [...missing]
  const ok = check.passed && missingEvidence.length === 0

  return host.scrubRecord({
    ok,
    confirmed: ok,
    claim,
    endpoint: (normalizedRequests[0]?.path as string | undefined) ?? null,
    mode,
    fallbackReason: raceRes.fallbackReason ?? null,
    summary: raceRes.summary ?? {},
    exchanges,
    ...(baseline ? { baseline } : {}),
    ...(post ? { post } : {}),
    ...(serial ? { serial } : {}),
    ...(serialPost ? { serialPost } : {}),
    rejectedBy: ok ? null : 'race',
    missingEvidence,
    transcriptSummary: [
      ...(baseline ? [proofEntry('setup', baseline, 'baseline_read')] : []),
      ...exchanges.map((item, index) => ({
        exchangeId: item.exchangeId,
        role: 'race',
        personaHandle: (normalizedRequests[index]?.persona as string | undefined) ?? null,
        method: (normalizedRequests[index]?.method as string | undefined) ?? null,
        pathAndQuery: (normalizedRequests[index]?.path as string | undefined) ?? null,
        status: item.status,
        durationMs: item.durationMs,
        note: mode,
      })),
      ...(post ? [proofEntry('control', post, 'post_read')] : []),
      ...(serial ? [proofEntry('control', serial, 'serial_control')] : []),
      ...(serialPost ? [proofEntry('control', serialPost, 'serial_post_read')] : []),
    ],
  })
}

export async function handleProveInjection(host: ProveHandlerHost, args: Record<string, unknown>, nonce: string): Promise<unknown> {
  const baseRoute = args.url ?? args.path ?? args.pathAndQuery ?? args.endpoint ?? args.route
  const baseOpts: Record<string, unknown> = {
    ...(typeof args.method === 'string' ? { method: args.method } : {}),
    ...(asRecord(args.headers) ? { headers: args.headers } : {}),
    ...(typeof (args.as ?? args.as_persona ?? args.persona) === 'string' ? { persona: args.as ?? args.as_persona ?? args.persona } : {}),
  }
  const controlBodyArg = args.controlBody ?? args.control_body
  const probeBodyArg = args.probeBody ?? args.probe_body
  const rawControl = args.control ?? (baseRoute && controlBodyArg !== undefined ? { target: baseRoute, options: { ...baseOpts, body: controlBodyArg } } : undefined)
  const rawProbe = args.probe ?? args.variant ?? (baseRoute && probeBodyArg !== undefined ? { target: baseRoute, options: { ...baseOpts, body: probeBodyArg } } : undefined)
  if (!rawControl || !rawProbe) {
    throw new Error('prove_injection_differential requires `control` and `probe` (or base route with `controlBody` and `probeBody`).')
  }
  const session = typeof args.session === 'string' && args.session ? args.session : 'injection-diff'
  const expectedRaw = args.expectedOutput ?? args.expected_output
  const expected = typeof expectedRaw === 'string' ? expectedRaw.trim() : ''
  const vulnRaw = args.vulnClass ?? args.vuln_class
  const vulnClass = typeof vulnRaw === 'string' && vulnRaw.trim() ? vulnRaw.trim() : undefined
  const message = typeof args.message === 'string' && args.message ? args.message : undefined

  const controlArgs = normalizeArmTarget(host.defaultOrigin, rawControl, { sessionGroupRole: 'control', session })
  const probeArgs = normalizeArmTarget(host.defaultOrigin, rawProbe, { sessionGroupRole: 'probe', session })
  const controlReqBody = typeof controlArgs.body === 'string' ? (parseJsonSafe(controlArgs.body) ?? controlArgs.body) : undefined
  const probeReqBody = typeof probeArgs.body === 'string' ? (parseJsonSafe(probeArgs.body) ?? probeArgs.body) : undefined

  const control = await host.runHttpExchange(controlArgs, nonce)
  const probe = await host.runHttpExchange(probeArgs, nonce)
  const transcriptSummary = [
    proofEntry('control', control),
    proofEntry('probe', probe),
  ]

  if (expected.length >= 4) {
    const probe2 = await host.runHttpExchange(probeArgs, nonce)
    const control2 = await host.runHttpExchange(controlArgs, nonce)
    transcriptSummary.push(proofEntry('probe', probe2), proofEntry('control', control2))
    const probeReqText = `${String(probeArgs.path ?? '')}\n${String(probeArgs.body ?? '')}`
    const inProbe = probe.body.includes(expected) && probe2.body.includes(expected)
    const inControl = control.body.includes(expected) || control2.body.includes(expected)
    const reflected = probeReqText.includes(expected)
    const evaluated = inProbe && !inControl && !reflected

    const absentClaim: Extract<VerifyClaim, { kind: 'body_contains' }> = {
      kind: 'body_contains',
      exchangeId: control.exchangeId,
      text: expected,
      absent: true,
      ...(controlReqBody !== undefined ? { controlRequestBody: controlReqBody } : {}),
      message: `${vulnClass ?? 'ssti'} control lacks evaluated marker`,
    }
    const presentClaim: Extract<VerifyClaim, { kind: 'body_contains' }> = {
      kind: 'body_contains',
      exchangeId: probe.exchangeId,
      text: expected,
      absent: false,
      ...(vulnClass ? { vulnClass } : {}),
      ...(controlReqBody !== undefined ? { controlRequestBody: controlReqBody } : {}),
      ...(probeReqBody !== undefined ? { probeRequestBody: probeReqBody } : {}),
      message: message ?? `${vulnClass ?? 'ssti'} evaluated marker present in probe`,
    }
    const diffClaim: Extract<VerifyClaim, { kind: 'structural_diff' }> = {
      kind: 'structural_diff',
      controlIds: [control.exchangeId, control2.exchangeId],
      variantIds: [probe.exchangeId, probe2.exchangeId],
      minRounds: 2,
      minDeltaTokens: 1,
      message: message ?? `${vulnClass ?? 'ssti'} evaluated differential across 2 rounds`,
    }
    const claims: VerifyClaim[] = [absentClaim, presentClaim, diffClaim]
    const checks = claims.map(c => evaluateClaim(host.transcript, c, {}))
    const missing = new Set<string>()
    for (const c of checks) for (const item of describeMissingEvidence(c)) missing.add(item)
    if (!(control.status >= 200 && control.status < 300)) missing.add('control_2xx')
    if (!inProbe) missing.add('evaluated_marker_in_probe')
    if (inControl) missing.add('marker_absent_from_control')
    if (reflected) missing.add('non_reflected_expression')
    const missingEvidence = [...missing]
    const ok = checks.every(c => c.passed) && missingEvidence.length === 0
    return host.scrubRecord({
      ok,
      confirmed: ok,
      endpoint: probe.pathAndQuery,
      control,
      probe,
      claim: presentClaim,
      claims,
      evaluated,
      rejectedBy: ok ? null : 'injection_differential',
      missingEvidence,
      transcriptSummary,
    })
  }

  const impactClaim: Extract<VerifyClaim, { kind: 'impact' }> = {
    kind: 'impact',
    impactClass: 'injection',
    ...(vulnClass ? { vulnClass } : {}),
    controlExchangeIds: [control.exchangeId],
    probeExchangeId: probe.exchangeId,
    ...(probeReqBody !== undefined ? { requestBody: probeReqBody } : {}),
    ...(message ? { message } : {}),
  }
  const check = evaluateClaim(host.transcript, impactClaim, {})
  const missingEvidence = check.passed ? [] : describeMissingEvidence(check)
  return host.scrubRecord({
    ok: check.passed,
    confirmed: check.passed,
    endpoint: probe.pathAndQuery,
    control,
    probe,
    claim: impactClaim,
    claims: [impactClaim],
    evaluated: false,
    rejectedBy: check.passed ? null : 'impact',
    missingEvidence,
    transcriptSummary,
  })
}
