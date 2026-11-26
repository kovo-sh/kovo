/**
 * Authoritative host proof RPC executors (`prove.*`) — single source of truth
 * for both thin worker SDKs (`kovo_verify.ts` and `kovo_verify.py`).
 *
 * Depends strictly downward on `verify-claims.ts` and `oracle-invariants.ts`;
 * receives host runtime capabilities via the narrow `ProveHandlerHost` seam.
 */
import { randomBytes, randomUUID } from 'node:crypto'
import type { ArmProvenance } from './evidence-provenance.ts'
import type { NonceBinding } from './nonce-ledger.ts'
import type { BoundaryClass, ImpactClass } from './oracle-invariants.ts'
import { isReservedEvidenceRole } from './host-fact-log.ts'
import {
  defaultHostMintedOracle,
  derivedTimingVulnClassForFamily,
  exactPathnameOf,
  verifyHostExpressionProbe,
  verifySignedUrlMintPair,
  type ExpressionConstructFamily,
  type HostMintedBooleanPairChallenge,
  type HostMintedExpressionChallenge,
  type HostMintedTimingChallenge,
  type HostStampedBooleanPair,
  type TimingConstructFamily,
} from './proof-receipt.ts'
import {
  asRecord,
  describeMissingEvidence,
  evaluateClaim,
  TranscriptStore,
} from './verify-claims.ts'
import type { VerifyCanaryBroker, VerifyClaim } from './verify-claims.ts'
import {
  assessSignedUrlMintDifferential,
  computeWorkerVisibleBodyDigest,
  evaluateWorkerStructuralDiff,
  mintHostBooleanPair,
  normalizeStructuralTokens,
  structuralDiffNormalized,
  verifyBooleanArmBaseParity,
  type BooleanPairStyle,
  type SignedUrlMintExchange,
  type SignedUrlMintVariant,
} from './verify-support.ts'

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

export interface ProveHttpExchangeStamps {
  hostExpressionChallenge?: HostMintedExpressionChallenge
  hostBooleanPair?: HostStampedBooleanPair
  timingChallenge?: HostMintedTimingChallenge
  armProvenance?: ArmProvenance
  hostAssignedArm?: 'control' | 'probe' | 'setup' | 'cleanup'
}

export interface ProveHandlerHost {
  readonly runId?: string
  readonly transcript: TranscriptStore
  readonly defaultOrigin: string | undefined
  readonly canaryBroker: VerifyCanaryBroker | undefined
  readonly diffDigestKey?: string
  runHttpExchange(args: Record<string, unknown>, nonce: string, stamps?: ProveHttpExchangeStamps): Promise<ProveHttpExchangeResult>
  exchangeViewFromTranscript?(exchangeId: string): ProveHttpExchangeResult | null
  runOob(args: Record<string, unknown>): Promise<unknown>
  runRace(args: Record<string, unknown>, nonce: string): Promise<unknown>
  scrubRecord<T>(value: T): T
}

function proveMintBinding(host: ProveHandlerHost): { runId?: string; origin?: string } {
  return { ...(host.runId ? { runId: host.runId } : {}), ...(host.defaultOrigin ? { origin: host.defaultOrigin } : {}) }
}

function targetBindingFromArgs(
  host: ProveHandlerHost,
  armArgs: Record<string, unknown>,
  param?: string,
  armRole?: string,
): Partial<Omit<NonceBinding, 'oracleId'>> {
  const origin = typeof armArgs.origin === 'string' && armArgs.origin ? armArgs.origin : host.defaultOrigin
  const method = typeof armArgs.method === 'string' && armArgs.method ? armArgs.method.toUpperCase() : 'GET'
  const route = exactPathnameOf(typeof armArgs.path === 'string' ? armArgs.path : '/')
  return {
    ...(host.runId ? { runId: host.runId } : {}),
    ...(origin ? { origin } : {}),
    method,
    route,
    ...(param ? { param } : {}),
    ...(armRole ? { armRole } : {}),
  }
}

function hostAssignedStamp(
  arm: 'control' | 'probe' | 'setup' | 'cleanup',
  extra?: Omit<ProveHttpExchangeStamps, 'armProvenance' | 'hostAssignedArm'>,
): ProveHttpExchangeStamps {
  return { ...(extra ?? {}), armProvenance: 'host_assigned', hostAssignedArm: arm }
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
    ...(merged.authMutation !== undefined ? { authMutation: merged.authMutation } : {}),
    ...(typeof merged.entityId === 'string' && merged.entityId.trim() ? { entityId: merged.entityId.trim() } : {}),
    ...(typeof merged.correlationId === 'string' && merged.correlationId.trim() ? { correlationId: merged.correlationId.trim() } : {}),
    ...(Array.isArray(merged.correlationIds) ? { correlationIds: merged.correlationIds } : {}),
    ...(typeof merged.evidenceRole === 'string' && merged.evidenceRole.trim() && !isReservedEvidenceRole(merged.evidenceRole)
      ? { evidenceRole: merged.evidenceRole.trim() }
      : {}),
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
  const control = await host.runHttpExchange(controlArgs, nonce, hostAssignedStamp('control'))
  const probe = await host.runHttpExchange(probeArgs, nonce, hostAssignedStamp('probe'))

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
  }), nonce, hostAssignedStamp('control'))

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
  const mutation = await host.runHttpExchange(mutArgs, nonce, hostAssignedStamp('probe'))
  const after = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
    method: readMethod,
    ...(readPersona ? { persona: readPersona } : {}),
    sessionGroupRole: 'control',
    session: readSession,
  }), nonce, hostAssignedStamp('control'))

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

function rawEvidenceRoleOf(spec: unknown): string | null {
  const rec = asRecord(spec)
  if (!rec) return null
  const nested = asRecord(rec.options)
  const raw = nested?.evidenceRole ?? nested?.evidence_role ?? rec.evidenceRole ?? rec.evidence_role
  return typeof raw === 'string' && raw.trim() ? raw.trim() : null
}

function renderTemplateStrings(value: unknown, replacements: Readonly<Record<string, string>>): unknown {
  const apply = (text: string): string => {
    let out = text
    for (const [needle, replacement] of Object.entries(replacements)) {
      if (out.includes(needle)) out = out.split(needle).join(replacement)
    }
    return out
  }
  if (typeof value === 'string') return apply(value)
  if (Array.isArray(value)) return value.map(item => renderTemplateStrings(item, replacements))
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = renderTemplateStrings(v, replacements)
    }
    return out
  }
  return value
}

function hasAnyPlaceholder(value: unknown, placeholders: readonly string[]): boolean {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value ?? '')
  return placeholders.some(p => serialized.includes(p))
}

function paramMapFromArmArgs(armArgs: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {}
  const pathStr = String(armArgs.path ?? '/')
  const qIdx = pathStr.indexOf('?')
  if (qIdx >= 0) {
    for (const [k, v] of new URLSearchParams(pathStr.slice(qIdx + 1)).entries()) {
      out[k] = v
    }
  }
  if (typeof armArgs.body === 'string' && armArgs.body.trim()) {
    const parsed = parseJsonSafe(armArgs.body)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const flatten = (val: unknown, prefix = '', depth = 0): void => {
        if (depth > 4 || val === null || val === undefined) return
        if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') {
          out[`body:${prefix || '$'}`] = String(val)
          return
        }
        if (Array.isArray(val)) {
          val.slice(0, 16).forEach((item, idx) => flatten(item, `${prefix}[${idx}]`, depth + 1))
          return
        }
        if (typeof val === 'object') {
          for (const [k, child] of Object.entries(val as Record<string, unknown>)) {
            flatten(child, prefix ? `${prefix}.${k}` : k, depth + 1)
          }
        }
      }
      flatten(parsed)
    } else if (armArgs.body.includes('=')) {
      for (const [k, v] of new URLSearchParams(armArgs.body).entries()) {
        out[`body:${k}`] = v
      }
    } else {
      out['body:$'] = armArgs.body
    }
  }
  return out
}

function checkArmIdentityParity(
  defaultOrigin: string | undefined,
  controlArgs: Record<string, unknown>,
  probeArgs: Record<string, unknown>,
): { ok: true; differingParam: string } | { ok: false; reason: string } {
  const ctlOrigin = String(controlArgs.origin ?? defaultOrigin ?? '').trim().toLowerCase()
  const prbOrigin = String(probeArgs.origin ?? defaultOrigin ?? '').trim().toLowerCase()
  if (ctlOrigin !== prbOrigin) {
    return { ok: false, reason: `origin mismatch (${ctlOrigin || 'none'} vs ${prbOrigin || 'none'})` }
  }
  if (String(controlArgs.method ?? 'GET').toUpperCase() !== String(probeArgs.method ?? 'GET').toUpperCase()) {
    return { ok: false, reason: `method mismatch (${String(controlArgs.method)} vs ${String(probeArgs.method)})` }
  }
  const ctlPath = exactPathnameOf(String(controlArgs.path ?? '/'))
  const prbPath = exactPathnameOf(String(probeArgs.path ?? '/'))
  if (ctlPath !== prbPath) {
    return { ok: false, reason: `path mismatch (${ctlPath} vs ${prbPath})` }
  }
  if ((controlArgs.persona ?? null) !== (probeArgs.persona ?? null)) {
    return { ok: false, reason: `persona mismatch (${String(controlArgs.persona ?? 'anon')} vs ${String(probeArgs.persona ?? 'anon')})` }
  }
  if ((controlArgs.session ?? null) !== (probeArgs.session ?? null)) {
    return { ok: false, reason: `session mismatch (${String(controlArgs.session ?? 'none')} vs ${String(probeArgs.session ?? 'none')})` }
  }
  if (JSON.stringify(controlArgs.capability ?? null) !== JSON.stringify(probeArgs.capability ?? null)) {
    return { ok: false, reason: 'capability set mismatch across control and probe arms' }
  }
  const ctlParams = paramMapFromArmArgs(controlArgs)
  const prbParams = paramMapFromArmArgs(probeArgs)
  const allKeys = [...new Set([...Object.keys(ctlParams), ...Object.keys(prbParams)])].sort()
  const diffKeys = allKeys.filter(k => ctlParams[k] !== prbParams[k])
  if (diffKeys.length !== 1) {
    return {
      ok: false,
      reason: diffKeys.length === 0
        ? 'control and probe parameters are identical (need exactly 1 differing parameter)'
        : `control and probe differ in ${diffKeys.length} parameters (${diffKeys.join(', ')}); need exactly 1`,
    }
  }
  const soleKey = diffKeys[0]!
  // Check remaining query/body key shape parity
  for (const k of allKeys) {
    if (k === soleKey) continue
    if (ctlParams[k] !== prbParams[k]) {
      return { ok: false, reason: `request shape mismatch on parameter "${k}"` }
    }
  }
  return { ok: true, differingParam: soleKey }
}

export async function handleProveDifferential(host: ProveHandlerHost, args: Record<string, unknown>, nonce: string): Promise<unknown> {
  if (args.control === undefined || args.control === null || args.variant === undefined || args.variant === null) {
    throw new Error('prove_boolean_or_timing_diff requires `control` and `variant`.')
  }
  const mode: 'boolean' | 'timing' = args.mode === 'timing' ? 'timing' : 'boolean'
  const session = typeof args.session === 'string' && args.session ? args.session : `diff-${mode}`
  const message = typeof args.message === 'string' && args.message ? args.message : undefined
  const rounds = mode === 'timing'
    ? Math.max(5, Math.min(Math.round(Number(args.rounds ?? 6)), 7))
    : Math.max(2, Math.min(Math.round(Number(args.rounds ?? 3)), 6))

  let timingChallenge: HostMintedTimingChallenge | null = null
  let booleanPair: HostMintedBooleanPairChallenge | null = null
  let baselineTemplate: unknown = args.baseline
  let controlTemplate: unknown = args.control
  let variantTemplate: unknown = args.variant
  if (mode === 'boolean') {
    const boolPlaceholders = ['{{boolBase}}', '{{boolTrue}}', '{{boolFalse}}', '{{boolTrueSuffix}}', '{{boolFalseSuffix}}']
    const rawBoolBase = args.booleanBase ?? args.boolean_base ?? args.baseValue ?? args.base_value
    const usesHostBoolTemplate = Boolean(
      typeof rawBoolBase === 'string'
      || hasAnyPlaceholder(args.control, boolPlaceholders)
      || hasAnyPlaceholder(args.variant, boolPlaceholders)
      || (args.baseline !== undefined && hasAnyPlaceholder(args.baseline, boolPlaceholders)),
    )
    if (usesHostBoolTemplate) {
      const baseVal = typeof rawBoolBase === 'string' ? rawBoolBase : '1'
      if (baseVal.trim().length === 0) {
        return host.scrubRecord({
          ok: false,
          confirmed: false,
          mode: 'boolean',
          endpoint: null,
          controlIds: [],
          variantIds: [],
          stats: { reason: 'Boolean base value must be non-empty (empty-base standalone predicates are forbidden).' },
          exchanges: { control: [], variant: [] },
          rejectedBy: 'boolean_base_mismatch',
          missingEvidence: ['boolean_base_value_parity'],
          transcriptSummary: [],
        })
      }
      const rawStyle = String(args.booleanStyle ?? args.boolean_style ?? '').trim().toLowerCase()
      const style: BooleanPairStyle = rawStyle === 'single_quote' || rawStyle === 'single'
        ? 'single_quote'
        : rawStyle === 'double_quote' || rawStyle === 'double'
          ? 'double_quote'
          : 'numeric'
      const mintBinding = proveMintBinding(host)
      booleanPair = mintHostBooleanPair(baseVal, { style, oracle: { mintBooleanPair: (b, o) => defaultHostMintedOracle.mintBooleanPair(b, { ...o, binding: mintBinding }) } })
      const replacements: Record<string, string> = { '{{boolBase}}': booleanPair.baseValue, '{{boolTrue}}': booleanPair.trueValue, '{{boolFalse}}': booleanPair.falseValue, '{{boolTrueSuffix}}': booleanPair.trueSuffix, '{{boolFalseSuffix}}': booleanPair.falseSuffix }
      controlTemplate = renderTemplateStrings(args.control, replacements)
      variantTemplate = renderTemplateStrings(args.variant, replacements)
      if (baselineTemplate !== undefined && baselineTemplate !== null) baselineTemplate = renderTemplateStrings(baselineTemplate, replacements)
    }
  }
  if (mode === 'timing') {
    const rawFamily = String(args.timingFamily ?? args.timing_family ?? args.constructFamily ?? args.construct_family ?? '').trim().toLowerCase()
    const family: TimingConstructFamily = rawFamily === 'nosqli'
      ? 'nosqli'
      : rawFamily === 'cmdi' || rawFamily === 'command_injection'
        ? 'cmdi'
        : rawFamily === 'timing'
          ? 'timing'
          : 'sqli'
    const delayPlaceholders = ['{{delayToken}}', '{{delaySeconds}}', '{{delayMs}}', '{{delay}}']
    const usesHostDelayTemplate = Boolean(
      rawFamily ||
      hasAnyPlaceholder(args.variant, delayPlaceholders) ||
      hasAnyPlaceholder(args.control, delayPlaceholders),
    )
    if (!usesHostDelayTemplate) {
      const claim: Extract<VerifyClaim, { kind: 'timing' }> = {
        kind: 'timing',
        controlIds: [],
        variantIds: [],
        minPairs: rounds,
        maxPValue: Number(args.maxPValue ?? args.max_p_value ?? 0.05),
        ...(message ? { message } : {}),
      }
      return host.scrubRecord({
        ok: false,
        confirmed: false,
        mode: 'timing',
        endpoint: null,
        controlIds: [],
        variantIds: [],
        claim,
        stats: { reason: 'Timing differential requires a host-minted delay vs zero-delay control template ({{delayToken}}/{{delaySeconds}}/{{delayMs}} or timingFamily).' },
        exchanges: { control: [], variant: [] },
        rejectedBy: 'timing',
        missingEvidence: ['host_minted_timing_challenge'],
        transcriptSummary: [],
      })
    }
    const requestedDelayMs = Number(args.delayMs ?? args.delay_ms ?? 2_000)
    timingChallenge = defaultHostMintedOracle.mintTimingChallenge(family, Number.isFinite(requestedDelayMs) ? requestedDelayMs : 2_000, undefined, proveMintBinding(host))
    const delaySec = String(Math.max(1, Math.round(timingChallenge.delayMs / 1000)))
    controlTemplate = renderTemplateStrings(args.control, {
      '{{delayToken}}': timingChallenge.controlToken,
      '{{delaySeconds}}': '0',
      '{{delayMs}}': '0',
      '{{delay}}': timingChallenge.controlToken,
    })
    variantTemplate = renderTemplateStrings(args.variant, {
      '{{delayToken}}': timingChallenge.delayToken,
      '{{delaySeconds}}': delaySec,
      '{{delayMs}}': String(timingChallenge.delayMs),
      '{{delay}}': timingChallenge.delayToken,
    })
  }

  const baseControlArgs = normalizeArmTarget(host.defaultOrigin, controlTemplate, {
    sessionGroupRole: 'control',
    session,
  })
  const baseVariantArgs = normalizeArmTarget(host.defaultOrigin, variantTemplate, {
    sessionGroupRole: 'probe',
    session,
  })
  const baseBaselineArgs = baselineTemplate !== undefined && baselineTemplate !== null
    ? normalizeArmTarget(host.defaultOrigin, baselineTemplate, {
        sessionGroupRole: 'setup',
        session,
      })
    : null
  // H-15 / C-7: Enforce strict arm identity parity (origin, method, case-sensitive path,
  // persona, session, capability set, and single differing parameter) BEFORE issuing traffic.
  const parity = checkArmIdentityParity(host.defaultOrigin, baseControlArgs, baseVariantArgs)
  if (!parity.ok) {
    return host.scrubRecord({
      ok: false,
      confirmed: false,
      mode,
      endpoint: String(baseVariantArgs.path ?? ''),
      controlIds: [],
      variantIds: [],
      stats: { reason: `Differential arm identity rejected: ${parity.reason}` },
      exchanges: { control: [], variant: [] },
      rejectedBy: mode === 'timing' ? 'timing' : 'structural_diff',
      missingEvidence: ['arm_identity_parity'],
      transcriptSummary: [],
    })
  }
  if (baseBaselineArgs) {
    const baseParity = checkArmIdentityParity(host.defaultOrigin, baseBaselineArgs, baseVariantArgs)
    if (!baseParity.ok || baseParity.differingParam !== parity.differingParam) {
      const reason = !baseParity.ok
        ? baseParity.reason
        : `baseline differing parameter "${baseParity.differingParam}" != "${parity.differingParam}"`
      return host.scrubRecord({
        ok: false,
        confirmed: false,
        mode,
        endpoint: String(baseVariantArgs.path ?? ''),
        controlIds: [],
        variantIds: [],
        stats: { reason: `Differential baseline arm identity rejected: ${reason}` },
        exchanges: { control: [], variant: [] },
        rejectedBy: mode === 'timing' ? 'timing' : 'boolean_base_mismatch',
        missingEvidence: ['arm_identity_parity'],
        transcriptSummary: [],
      })
    }
  }

  // R3-C-4: Enforce base-value equality for boolean differential arms (and optional baseline / host pair).
  let boolParity: ReturnType<typeof verifyBooleanArmBaseParity> | null = null
  if (mode === 'boolean') {
    const ctlParams = paramMapFromArmArgs(baseControlArgs)
    const varParams = paramMapFromArmArgs(baseVariantArgs)
    const baseParams = baseBaselineArgs ? paramMapFromArmArgs(baseBaselineArgs) : null
    boolParity = verifyBooleanArmBaseParity({
      controlValue: ctlParams[parity.differingParam] ?? '',
      variantValue: varParams[parity.differingParam] ?? '',
      ...(baseParams ? { baselineValue: baseParams[parity.differingParam] ?? '' } : {}),
      ...(booleanPair ? { hostPair: booleanPair } : {}),
    })
    if (!boolParity.ok) {
      return host.scrubRecord({
        ok: false,
        confirmed: false,
        mode: 'boolean',
        endpoint: String(baseVariantArgs.path ?? ''),
        controlIds: [],
        variantIds: [],
        stats: { reason: `Boolean base-value parity rejected: ${boolParity.reason}`, differingParam: parity.differingParam },
        exchanges: { control: [], variant: [] },
        rejectedBy: 'boolean_base_mismatch',
        missingEvidence: ['boolean_base_value_parity'],
        transcriptSummary: [],
      })
    }
  }

  // R4-C-1 / R3-16: Stamp host-minted boolean/timing challenges with full target/arm binding & provenance.
  const targetBind = targetBindingFromArgs(host, baseVariantArgs, parity.differingParam)
  const baselineStamp = hostAssignedStamp('setup', booleanPair ? { hostBooleanPair: defaultHostMintedOracle.stampBooleanPairArm(booleanPair, 'baseline', targetBind) } : undefined)
  const controlBoolArm: 'true' | 'false' = boolParity?.ok && boolParity.controlTruth === false ? 'false' : 'true'
  const variantBoolArm: 'true' | 'false' = controlBoolArm === 'true' ? 'false' : 'true'
  const controlStamp = hostAssignedStamp('control', { ...(booleanPair ? { hostBooleanPair: defaultHostMintedOracle.stampBooleanPairArm(booleanPair, controlBoolArm, targetBind) } : {}), ...(timingChallenge ? { timingChallenge: defaultHostMintedOracle.stampTimingChallengeArm(timingChallenge, 'control', targetBind) } : {}) })
  const variantStamp = hostAssignedStamp('probe', { ...(booleanPair ? { hostBooleanPair: defaultHostMintedOracle.stampBooleanPairArm(booleanPair, variantBoolArm, targetBind) } : {}), ...(timingChallenge ? { timingChallenge: defaultHostMintedOracle.stampTimingChallengeArm(timingChallenge, 'probe', targetBind) } : {}) })

  const baselineExchanges: Array<ProveHttpExchangeResult> = []
  const controlExchanges: Array<ProveHttpExchangeResult> = []
  const variantExchanges: Array<ProveHttpExchangeResult> = []
  for (let index = 0; index < rounds; index += 1) {
    if (baseBaselineArgs) {
      baselineExchanges.push(await host.runHttpExchange({ ...baseBaselineArgs }, nonce, baselineStamp))
    }
    const order: Array<'control' | 'variant'> = index % 2 === 0 ? ['control', 'variant'] : ['variant', 'control']
    for (const which of order) {
      const armArgs = which === 'control' ? { ...baseControlArgs } : { ...baseVariantArgs }
      const armStamp = which === 'control' ? controlStamp : variantStamp
      const ex = await host.runHttpExchange(armArgs, nonce, armStamp)
      if (which === 'control') controlExchanges.push(ex)
      else variantExchanges.push(ex)
    }
  }
  const controlIds = controlExchanges.map(ex => ex.exchangeId)
  const variantIds = variantExchanges.map(ex => ex.exchangeId)

  if (mode === 'timing') {
    const maxPValue = Number(args.maxPValue ?? args.max_p_value ?? 0.05)
    const statusSet = new Set([...controlExchanges, ...variantExchanges].map(ex => ex.status))
    const statusParity = statusSet.size === 1
    const claim: Extract<VerifyClaim, { kind: 'timing' }> & {
      hostMintedTimingChallengeId?: string
      vulnClass?: string
    } = {
      kind: 'timing',
      controlIds,
      variantIds,
      minPairs: rounds,
      maxPValue,
      ...(timingChallenge ? {
        hostMintedTimingChallengeId: timingChallenge.challengeId,
        vulnClass: derivedTimingVulnClassForFamily(timingChallenge.family),
      } : {}),
      ...(message ? { message } : {}),
    }
    const check = evaluateClaim(host.transcript, claim, {})
    const missing = new Set<string>(check.passed ? [] : describeMissingEvidence(check))
    if (!statusParity) missing.add('timing_status_parity')
    if (!timingChallenge) missing.add('host_minted_timing_challenge')
    const missingEvidence = [...missing]
    const ok = check.passed && statusParity && Boolean(timingChallenge) && missingEvidence.length === 0
    return host.scrubRecord({
      ok,
      confirmed: ok,
      mode: 'timing',
      endpoint: variantExchanges[0]?.pathAndQuery ?? null,
      controlIds,
      variantIds,
      claim,
      ...(timingChallenge ? { hostTimingChallenge: timingChallenge, derivedVulnClass: derivedTimingVulnClassForFamily(timingChallenge.family) } : {}),
      stats: { ...(check.observed ?? {}), statusParity, differingParam: parity.differingParam },
      exchanges: { control: controlExchanges, variant: variantExchanges },
      rejectedBy: ok ? null : 'timing',
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
  // R3-H-2: Evaluate structural_diff strictly on worker-visible vault-scrubbed bodies and never
  // emit raw lowercased plaintext `stableDelta` fragments (emit count + keyed HMAC digests only).
  const digestKey = host.diffDigestKey ?? randomBytes(32).toString('hex')
  const workerDiff = evaluateWorkerStructuralDiff(
    controlExchanges.map(ex => ex.body),
    variantExchanges.map(ex => ex.body),
    { minDeltaTokens, maxSimilarity, digestKey },
  )
  let baselineOk = true
  if (baselineExchanges.length > 0 && boolParity?.ok && (boolParity.controlTruth === true || boolParity.variantTruth === true)) {
    const normBase = baselineExchanges.map(ex => normalizeStructuralTokens(ex.body))
    const trueBodies = (boolParity.controlTruth === true ? controlExchanges : variantExchanges).map(ex => normalizeStructuralTokens(ex.body))
    const stableBase = !normBase.some(b => !structuralDiffNormalized(normBase[0]!, b).normalizedEqual)
    const trueMatchesBase = stableBase && structuralDiffNormalized(normBase[0]!, trueBodies[0]!).normalizedEqual
    baselineOk = trueMatchesBase
  }
  const check = evaluateClaim(host.transcript, claim, {})
  const obs = check.observed ?? {}
  const ok = workerDiff.passed && check.passed && baselineOk
  const missing = new Set<string>(check.passed ? [] : describeMissingEvidence(check))
  if (!workerDiff.passed) missing.add(workerDiff.stableDeltaCount === 0 ? 'stable_variant_delta' : 'arm_differential')
  if (!baselineOk) missing.add('boolean_true_matches_baseline')
  const missingEvidence = ok ? [] : [...missing]
  return host.scrubRecord({
    ok,
    confirmed: ok,
    mode: 'boolean',
    endpoint: variantExchanges[0]?.pathAndQuery ?? null,
    controlIds,
    variantIds,
    ...(baselineExchanges.length > 0 ? { baselineIds: baselineExchanges.map(ex => ex.exchangeId) } : {}),
    ...(booleanPair ? { hostBooleanPair: booleanPair } : {}),
    claim,
    stats: {
      stableDeltaCount: workerDiff.stableDeltaCount,
      stableDeltaDigests: workerDiff.stableDeltaDigests,
      similarity: workerDiff.similarity,
      rounds,
      stableControl: workerDiff.stableControl,
      stableVariant: workerDiff.stableVariant,
      differingParam: parity.differingParam,
      ...(boolParity?.ok && boolParity.sharedBase !== null ? { sharedBase: boolParity.sharedBase } : {}),
      ...(baselineExchanges.length > 0 ? { baselineMatchesTrue: baselineOk } : {}),
    },
    exchanges: {
      ...(baselineExchanges.length > 0 ? { baseline: baselineExchanges } : {}),
      control: controlExchanges,
      variant: variantExchanges,
    },
    rejectedBy: ok ? null : (typeof obs.rejectedBy === 'string' ? obs.rejectedBy : (!baselineOk ? 'boolean_baseline_mismatch' : 'structural_diff')),
    missingEvidence,
    transcriptSummary: [
      ...baselineExchanges.map(ex => proofEntry('setup', ex, 'boolean_baseline')),
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
        injection = await host.runHttpExchange(injectArgs, nonce, hostAssignedStamp('probe'))
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

  // C-5: Reject any worker-supplied reserved evidenceRole on race requests.
  const badEvidenceRole = rawRequests.map(rawEvidenceRoleOf).find(r => r !== null && isReservedEvidenceRole(r))
  if (badEvidenceRole) {
    const claim: Extract<VerifyClaim, { kind: 'race' }> = {
      kind: 'race',
      exchangeIds: [],
      mode: 'http1-fallback',
      minDistinctOutcomes: minDistinct,
    }
    return host.scrubRecord({
      ok: false,
      confirmed: false,
      claim,
      mode: 'http1-fallback',
      fallbackReason: `Worker-supplied reserved evidenceRole "${badEvidenceRole}" is rejected; host assigns conservation roles.`,
      summary: {},
      exchanges: [],
      rejectedBy: 'reserved_evidence_role',
      missingEvidence: ['host_assigned_evidence_role'],
      transcriptSummary: [],
    })
  }

  // C-5: `readRoute` is mandatory to confirm `prove.race`; never fall back to worker-supplied
  // exchange IDs. When `readRoute` is absent, still execute the host-stamped burst so multi-hop
  // composite callers can consume burst `exchanges`, while failing closed (`ok: false`) on the
  // race claim itself.
  const readRoute = args.readRoute ?? args.read_route
  const hasReadRoute = readRoute !== undefined && readRoute !== null && (typeof readRoute !== 'string' || readRoute.trim().length > 0)

  const sessionBase = typeof args.session === 'string' && args.session ? args.session : undefined
  const topEntityId = typeof args.entityId === 'string' && args.entityId.trim() ? args.entityId.trim() : undefined
  const topCorrelationId = typeof args.correlationId === 'string' && args.correlationId.trim() ? args.correlationId.trim() : undefined
  const topCorrelationIds = Array.isArray(args.correlationIds) ? args.correlationIds : undefined
  const raceBatchId = `race_${randomUUID()}`
  let firstRequestBody: unknown = undefined
  const normalizedRequests = rawRequests.map((req, index) => {
    const normalized = normalizeArmTarget(host.defaultOrigin, req, {
      sessionGroupRole: 'probe',
      session: sessionBase ?? `race-${index}`,
    })
    normalized.raceBatchId = raceBatchId
    if (topEntityId && normalized.entityId === undefined) normalized.entityId = topEntityId
    if (topCorrelationId && normalized.correlationId === undefined) normalized.correlationId = topCorrelationId
    if (topCorrelationIds && normalized.correlationIds === undefined) normalized.correlationIds = topCorrelationIds
    if (index === 0 && typeof normalized.body === 'string') {
      firstRequestBody = parseJsonSafe(normalized.body) ?? normalized.body
    }
    return normalized
  })
  const firstPersona = typeof normalizedRequests[0]?.persona === 'string' ? normalizedRequests[0].persona : undefined
  const readPersona = cleanPersona(args.readPersona ?? args.read_persona ?? firstPersona)
  const readMethod = typeof (args.readMethod ?? args.read_method) === 'string'
    ? String(args.readMethod ?? args.read_method).toUpperCase()
    : 'GET'

  let baseline: ProveHttpExchangeResult | null = null
  if (hasReadRoute) {
    baseline = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
      method: readMethod,
      ...(readPersona ? { persona: readPersona } : {}),
      sessionGroupRole: 'setup',
      session: sessionBase ? `${sessionBase}-baseline` : 'race-baseline',
    }), nonce, hostAssignedStamp('setup'))
  }

  const raceRes = await host.runRace({ requests: normalizedRequests, raceBatchId }, nonce) as {
    mode?: 'h2-single-packet' | 'http1-fallback'
    fallbackReason?: string | null
    summary?: Record<string, unknown>
    raceBatchId?: string
    results?: Array<{
      exchangeId: string; status: number; durationMs: number; bodySha256: string
      consumedCapabilityId?: string; consumedCapabilities?: string[]; derivedFromCapabilityIds?: string[]
    }>
  }
  const effectiveBatchId = raceRes.raceBatchId ?? raceBatchId
  const mode = raceRes.mode ?? 'http1-fallback'
  const exchanges = (raceRes.results ?? []).map(item => ({
    exchangeId: item.exchangeId,
    status: item.status,
    durationMs: item.durationMs,
    bodySha256: item.bodySha256,
    raceBatchId: effectiveBatchId,
    ...(item.consumedCapabilityId ? { consumedCapabilityId: item.consumedCapabilityId } : {}),
    ...(item.consumedCapabilities?.length ? { consumedCapabilities: item.consumedCapabilities } : {}),
    ...(item.derivedFromCapabilityIds?.length ? { derivedFromCapabilityIds: item.derivedFromCapabilityIds } : {}),
  }))

  if (!hasReadRoute) {
    const burstIds = exchanges.map(item => item.exchangeId)
    const claim: Extract<VerifyClaim, { kind: 'race' }> & { raceBatchId?: string } = {
      kind: 'race',
      exchangeIds: burstIds,
      raceBatchId: effectiveBatchId,
      mode,
      minDistinctOutcomes: minDistinct,
    }
    return host.scrubRecord({
      ok: false,
      confirmed: false,
      claim,
      raceBatchId: effectiveBatchId,
      endpoint: (normalizedRequests[0]?.path as string | undefined) ?? null,
      mode,
      fallbackReason: 'prove.race requires `readRoute` for host-executed baseline/post/serial conservation verification (worker exchange ID fallbacks are forbidden).',
      summary: raceRes.summary ?? {},
      exchanges,
      rejectedBy: 'race',
      missingEvidence: ['read_route'],
      transcriptSummary: exchanges.map((item, index) => ({
        exchangeId: item.exchangeId,
        role: 'race',
        raceBatchId: effectiveBatchId,
        personaHandle: (normalizedRequests[index]?.persona as string | undefined) ?? null,
        method: (normalizedRequests[index]?.method as string | undefined) ?? null,
        pathAndQuery: (normalizedRequests[index]?.path as string | undefined) ?? null,
        status: item.status,
        durationMs: item.durationMs,
        note: mode,
      })),
    })
  }

  const post = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
    method: readMethod,
    ...(readPersona ? { persona: readPersona } : {}),
    sessionGroupRole: 'control',
    session: sessionBase ? `${sessionBase}-post` : 'race-post',
  }), nonce, hostAssignedStamp('control'))

  // C-5: Serial control arm MUST be the exact identical request as the concurrent burst arm
  // (`normalizedRequests[0]`), ignoring any worker `serialRequest` override.
  const { raceBatchId: _stripBatch, ...burstRequestTemplate } = normalizedRequests[0]!
  const serialArgs: Record<string, unknown> = {
    ...burstRequestTemplate,
    sessionGroupRole: 'control',
    session: sessionBase ? `${sessionBase}-serial` : 'race-serial',
  }
  const serial = await host.runHttpExchange(serialArgs, nonce, hostAssignedStamp('control'))
  let serialPost: ProveHttpExchangeResult | null = null
  if (serial.status >= 200 && serial.status < 300) {
    serialPost = await host.runHttpExchange(normalizeArmTarget(host.defaultOrigin, readRoute, {
      method: readMethod,
      ...(readPersona ? { persona: readPersona } : {}),
      sessionGroupRole: 'control',
      session: sessionBase ? `${sessionBase}-serial-post` : 'race-serial-post',
    }), nonce, hostAssignedStamp('control'))
  }

  const ackedCount = exchanges.filter(item => item.status >= 200 && item.status < 300).length
  // C-5: Host-only exchange IDs (never reading args.baselineExchangeId / postExchangeId / serialExchangeIds).
  const baselineId = baseline!.exchangeId
  const postId = post.exchangeId
  const serialIds = [serial.exchangeId]
  const serialPostId = serialPost?.exchangeId
  const hasConservedContext = true
  const explicitExpectAll = args.expectAllSuccess ?? args.expect_all_success
  const expectAllSuccess = explicitExpectAll !== undefined
    ? Boolean(explicitExpectAll)
    : !(hasConservedContext && ackedCount >= 2 && ackedCount < exchanges.length)
  const burstIds = exchanges.map(item => item.exchangeId)
  const balanceField = args.balanceField ?? args.balance_field
  const capField = args.capField ?? args.cap_field
  const vulnClass = args.vulnClass ?? args.vuln_class

  const claim: Extract<VerifyClaim, { kind: 'race' }> & { raceBatchId?: string } = {
    kind: 'race',
    exchangeIds: burstIds,
    burstExchangeIds: burstIds,
    raceBatchId: effectiveBatchId,
    baselineExchangeId: baselineId,
    postExchangeId: postId,
    serialExchangeIds: serialIds,
    ...(serialPostId ? { serialPostExchangeId: serialPostId } : {}),
    ...(typeof balanceField === 'string' && balanceField ? { balanceField } : {}),
    ...(typeof capField === 'string' && capField ? { capField } : {}),
    ...(typeof vulnClass === 'string' && vulnClass ? { vulnClass } : { vulnClass: 'race_double_spend' }),
    ...(firstRequestBody !== undefined ? { requestBody: firstRequestBody } : {}),
    mode,
    minDistinctOutcomes: minDistinct,
    expectAllSuccess,
    ...(typeof args.message === 'string' && args.message ? { message: args.message } : {}),
  }

  const check = evaluateClaim(host.transcript, claim, {})
  const missing = new Set<string>(check.passed ? [] : describeMissingEvidence(check))
  if (args.barrier === 'h2' && mode !== 'h2-single-packet') missing.add('h2_single_packet_barrier')
  if (ackedCount < 2) missing.add('acked_burst_mutations')
  const missingEvidence = [...missing]
  const ok = check.passed && missingEvidence.length === 0

  return host.scrubRecord({
    ok,
    confirmed: ok,
    claim,
    raceBatchId: effectiveBatchId,
    endpoint: (normalizedRequests[0]?.path as string | undefined) ?? null,
    mode,
    fallbackReason: raceRes.fallbackReason ?? null,
    summary: raceRes.summary ?? {},
    exchanges,
    baseline: baseline!,
    post,
    serial,
    ...(serialPost ? { serialPost } : {}),
    rejectedBy: ok ? null : 'race',
    missingEvidence,
    transcriptSummary: [
      proofEntry('setup', baseline!, 'baseline_read'),
      ...exchanges.map((item, index) => ({
        exchangeId: item.exchangeId,
        role: 'race',
        raceBatchId: effectiveBatchId,
        personaHandle: (normalizedRequests[index]?.persona as string | undefined) ?? null,
        method: (normalizedRequests[index]?.method as string | undefined) ?? null,
        pathAndQuery: (normalizedRequests[index]?.path as string | undefined) ?? null,
        status: item.status,
        durationMs: item.durationMs,
        note: mode,
      })),
      proofEntry('control', post, 'post_read'),
      proofEntry('control', serial, 'serial_control'),
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
  const workerExpected = typeof expectedRaw === 'string' ? expectedRaw.trim() : ''
  const rawFamily = String(args.expressionFamily ?? args.expression_family ?? '').trim().toLowerCase()
  const vulnRaw = args.vulnClass ?? args.vuln_class
  const vulnClass = typeof vulnRaw === 'string' && vulnRaw.trim() ? vulnRaw.trim() : undefined
  const message = typeof args.message === 'string' && args.message ? args.message : undefined

  const exprPlaceholders = ['{{expr}}', '{{operandA}}', '{{operandB}}']
  const usesHostMintedExpression = Boolean(
    rawFamily || hasAnyPlaceholder(rawProbe, exprPlaceholders),
  )

  // R2-C-6: Host-minted evaluated-expression differential oracle.
  // Mints two distinct randomized operand challenges per call and verifies each host-computed
  // output appears only in its own probe response, absent from controls and probe requests.
  if (usesHostMintedExpression) {
    const family: ExpressionConstructFamily = rawFamily === 'cmdi' || rawFamily === 'command_injection'
      ? 'cmdi'
      : rawFamily === 'sqli' || rawFamily === 'sqli_error'
        ? 'sqli'
        : rawFamily === 'expression'
          ? 'expression'
          : 'ssti'
    const exprBind = proveMintBinding(host)
    const ch1: HostMintedExpressionChallenge = defaultHostMintedOracle.mintExpressionChallenge(family, '*', exprBind)
    let ch2: HostMintedExpressionChallenge = defaultHostMintedOracle.mintExpressionChallenge(family, '*', exprBind)
    if (ch2.expectedOutput === ch1.expectedOutput) ch2 = defaultHostMintedOracle.mintExpressionChallenge(family, '*', exprBind)
    const renderChallenge = (spec: unknown, ch: HostMintedExpressionChallenge) =>
      renderTemplateStrings(spec, {
        '{{expr}}': ch.expressionSyntax,
        '{{operandA}}': String(ch.operandA),
        '{{operandB}}': String(ch.operandB),
      })
    const controlArgs = normalizeArmTarget(host.defaultOrigin, rawControl, { sessionGroupRole: 'control', session })
    const probeArgs1 = normalizeArmTarget(host.defaultOrigin, renderChallenge(rawProbe, ch1), { sessionGroupRole: 'probe', session })
    const probeArgs2 = normalizeArmTarget(host.defaultOrigin, renderChallenge(rawProbe, ch2), { sessionGroupRole: 'probe', session })
    const parity1 = checkArmIdentityParity(host.defaultOrigin, controlArgs, probeArgs1)
    const parity2 = checkArmIdentityParity(host.defaultOrigin, controlArgs, probeArgs2)
    if (!parity1.ok || !parity2.ok) {
      const reason = !parity1.ok ? parity1.reason : (!parity2.ok ? parity2.reason : 'arm identity mismatch')
      return host.scrubRecord({
        ok: false,
        confirmed: false,
        endpoint: String(probeArgs1.path ?? ''),
        evaluated: false,
        rejectedBy: 'injection_arm_identity',
        missingEvidence: ['arm_identity_parity'],
        reason,
        transcriptSummary: [],
      })
    }

    // R4-C-2 / R3-16: Bind full target/arm tuple and stamp per-exchange `hostExpressionChallenge` + provenance.
    const exprBind1 = targetBindingFromArgs(host, probeArgs1, parity1.differingParam, 'probe')
    const exprBind2 = targetBindingFromArgs(host, probeArgs2, parity2.differingParam, 'probe')
    const boundCh1 = defaultHostMintedOracle.bindExpressionChallenge(ch1, exprBind1, 'probe1')
    const boundCh2 = defaultHostMintedOracle.bindExpressionChallenge(ch2, exprBind2, 'probe2')
    const control = await host.runHttpExchange(controlArgs, nonce, hostAssignedStamp('control'))
    const probe1 = await host.runHttpExchange(probeArgs1, nonce, { hostExpressionChallenge: boundCh1, armProvenance: 'host_assigned', hostAssignedArm: 'probe' })
    const probe2 = await host.runHttpExchange(probeArgs2, nonce, { hostExpressionChallenge: boundCh2, armProvenance: 'host_assigned', hostAssignedArm: 'probe' })
    const control2 = await host.runHttpExchange(controlArgs, nonce, hostAssignedStamp('control'))
    const transcriptSummary = [
      proofEntry('control', control),
      proofEntry('probe', probe1),
      proofEntry('probe', probe2),
      proofEntry('control', control2),
    ]
    const derivedClass = family === 'cmdi' ? 'command_injection' : family === 'sqli' ? 'sqli_error' : family === 'ssti' ? 'ssti' : 'injection'
    const rawCtrl1 = host.transcript.body(control.exchangeId) ?? control.body
    const rawCtrl2 = host.transcript.body(control2.exchangeId) ?? control2.body
    const rawProbe1 = host.transcript.body(probe1.exchangeId) ?? probe1.body
    const rawProbe2 = host.transcript.body(probe2.exchangeId) ?? probe2.body
    const rec1 = host.transcript.get(probe1.exchangeId)
    const rec2 = host.transcript.get(probe2.exchangeId)
    const check1 = verifyHostExpressionProbe({
      probeRequest: {
        pathAndQuery: rec1?.request?.pathAndQuery ?? String(probeArgs1.path ?? ''),
        requestBody: host.transcript.requestBody(probe1.exchangeId) ?? (typeof probeArgs1.body === 'string' ? probeArgs1.body : null),
        requestHeaders: rec1?.request?.headers ?? (asRecord(probeArgs1.headers) as Record<string, string> | null),
      },
      probeBody: rawProbe1, probeStatus: probe1.status, controlBodies: [rawCtrl1, rawCtrl2],
      stampedChallenge: rec1?.hostExpressionChallenge ?? boundCh1, expectedChallengeId: boundCh1.challengeId, vulnClass: derivedClass, binding: exprBind1,
    })
    const check2 = verifyHostExpressionProbe({
      probeRequest: {
        pathAndQuery: rec2?.request?.pathAndQuery ?? String(probeArgs2.path ?? ''),
        requestBody: host.transcript.requestBody(probe2.exchangeId) ?? (typeof probeArgs2.body === 'string' ? probeArgs2.body : null),
        requestHeaders: rec2?.request?.headers ?? (asRecord(probeArgs2.headers) as Record<string, string> | null),
      },
      probeBody: rawProbe2, probeStatus: probe2.status, controlBodies: [rawCtrl1, rawCtrl2],
      stampedChallenge: rec2?.hostExpressionChallenge ?? boundCh2, expectedChallengeId: boundCh2.challengeId, vulnClass: derivedClass, binding: exprBind2,
    })
    const crossIsolated = !rawProbe1.includes(ch2.expectedOutput) && !rawProbe2.includes(ch1.expectedOutput)
    const varying = ch1.expectedOutput !== ch2.expectedOutput
    const all2xx = [control, control2, probe1, probe2].every(ex => ex.status >= 200 && ex.status < 300)
    const missing = new Set<string>()
    if (!all2xx) missing.add('control_and_probe_2xx')
    if (!varying) missing.add('varying_host_operands')
    if (!check1.ok || !check2.ok || !crossIsolated) {
      const reasons = `${check1.reason} ${check2.reason}`
      if (/malformed escape/i.test(reasons)) missing.add('clean_request_carrier')
      else if (/anti-reflection/i.test(reasons)) missing.add('non_reflected_expression')
      else if (/control leakage/i.test(reasons)) missing.add('output_absent_from_controls')
      else missing.add('host_computed_output_in_probes')
    }
    const missingEvidence = [...missing]
    const ok = missingEvidence.length === 0
    const hostClaim = {
      kind: 'host_evaluated_expression',
      vulnClass: derivedClass,
      controlIds: [control.exchangeId, control2.exchangeId],
      probeIds: [probe1.exchangeId, probe2.exchangeId],
      hostMintedChallengeIds: [ch1.challengeId, ch2.challengeId],
      message: message ?? `Host-minted ${family} evaluated-expression differential verified across 2 randomized challenges`,
    }
    // R4-C-2: NEVER return `expectedOutput` (or plaintext operands/expressionSyntax) to the worker.
    const publicChallenges = [
      { challengeId: ch1.challengeId, family: ch1.family, mintedAtMs: ch1.mintedAtMs },
      { challengeId: ch2.challengeId, family: ch2.family, mintedAtMs: ch2.mintedAtMs },
    ]
    return host.scrubRecord({
      ok,
      confirmed: ok,
      endpoint: probe1.pathAndQuery,
      control,
      probe: probe1,
      probe2,
      control2,
      hostMintedChallenges: publicChallenges,
      claim: hostClaim,
      claims: [hostClaim],
      evaluated: ok,
      rejectedBy: ok ? null : 'injection_differential',
      missingEvidence,
      transcriptSummary,
    })
  }

  // R2-C-6: Reject worker-chosen `expectedOutput` markers; downgrade plain `body_contains` pairs
  // to an unconfirmed lead rather than confirming injection on arbitrary page differences.
  if (workerExpected.length > 0) {
    const controlArgs = normalizeArmTarget(host.defaultOrigin, rawControl, { sessionGroupRole: 'control', session })
    const probeArgs = normalizeArmTarget(host.defaultOrigin, rawProbe, { sessionGroupRole: 'probe', session })
    const control = await host.runHttpExchange(controlArgs, nonce)
    const probe = await host.runHttpExchange(probeArgs, nonce)
    return host.scrubRecord({
      ok: false,
      confirmed: false,
      lead: true,
      endpoint: probe.pathAndQuery,
      control,
      probe,
      claims: [],
      evaluated: false,
      rejectedBy: 'worker_chosen_marker_rejected',
      missingEvidence: ['host_minted_expression_oracle'],
      transcriptSummary: [
        proofEntry('control', control),
        proofEntry('probe', probe),
      ],
    })
  }

  const controlArgs = normalizeArmTarget(host.defaultOrigin, rawControl, { sessionGroupRole: 'control', session })
  const probeArgs = normalizeArmTarget(host.defaultOrigin, rawProbe, { sessionGroupRole: 'probe', session })
  const probeReqBody = typeof probeArgs.body === 'string' ? (parseJsonSafe(probeArgs.body) ?? probeArgs.body) : undefined
  const control = await host.runHttpExchange(controlArgs, nonce, hostAssignedStamp('control'))
  const probe = await host.runHttpExchange(probeArgs, nonce, hostAssignedStamp('probe'))
  const transcriptSummary = [
    proofEntry('control', control),
    proofEntry('probe', probe),
  ]

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

function transcriptRecordToSignedUrlExchange(
  transcript: TranscriptStore,
  exchangeId: string,
  fallbackOrigin: string,
): SignedUrlMintExchange | null {
  const rec = transcript.get(exchangeId)
  if (!rec?.request) return null
  const rawBody = transcript.body(exchangeId) ?? ''
  const rawReqBody = transcript.requestBody(exchangeId) ?? null
  const parsedResp = parseJsonSafe(rawBody)
  const parsedReq = rawReqBody ? parseJsonSafe(rawReqBody) : undefined
  const reqExt = rec.request as typeof rec.request & { wireCredentialProvenance?: SignedUrlMintExchange['wireCredentialProvenance'] }
  return {
    exchangeId: rec.exchangeId,
    origin: rec.request.origin || fallbackOrigin,
    method: rec.request.method.toUpperCase(),
    pathAndQuery: rec.request.pathAndQuery,
    status: rec.response?.status ?? null,
    actorHandle: rec.request.personaHandle ?? null,
    requestHeaders: rec.request.headers ?? null,
    requestBody: rawReqBody,
    requestJson: parsedReq,
    responseHeaders: rec.response?.headers ?? null,
    responseBody: rawBody,
    responseJson: parsedResp,
    wireCredentialProvenance: reqExt.wireCredentialProvenance ?? null,
    consumedCapabilityId: rec.request.consumedCapabilityId ?? null,
  }
}

function exchangeSummaryFromTranscript(host: ProveHandlerHost, exchangeId: string): ProveHttpExchangeResult | null {
  if (host.exchangeViewFromTranscript) {
    return host.exchangeViewFromTranscript(exchangeId)
  }
  const rec = host.transcript.get(exchangeId)
  if (!rec?.request) return null
  const rawBody = host.transcript.body(exchangeId) ?? ''
  // R4-H-4: Compute response digests strictly from the worker-visible scrubbed body (NEVER raw response digests).
  const { scrubbedBody, bodyBytes, bodySha256 } = computeWorkerVisibleBodyDigest(rawBody, text => host.scrubRecord(text))
  return {
    exchangeId: rec.exchangeId,
    status: rec.response?.status ?? 0,
    method: rec.request.method,
    pathAndQuery: host.scrubRecord(rec.request.pathAndQuery),
    headers: host.scrubRecord(rec.response?.headers ?? {}),
    body: scrubbedBody.slice(0, 512 * 1024),
    bodyPreview: scrubbedBody.slice(0, 512),
    bodyBytes,
    bodySha256,
    durationMs: rec.durationMs,
    personaHandle: rec.request.personaHandle ?? null,
  }
}

function makeInPrefixAblationValue(controlValue: string, nonce: string): string {
  const tag = nonce.replace(/[^A-Za-z0-9]/g, '').slice(0, 6) || 'abl'
  const dotIdx = controlValue.lastIndexOf('.')
  if (dotIdx > 0 && dotIdx < controlValue.length - 1 && !controlValue.slice(dotIdx + 1).includes('/')) {
    return `${controlValue.slice(0, dotIdx)}_kovo_${tag}${controlValue.slice(dotIdx)}`
  }
  return `${controlValue || 'item'}_kovo_${tag}`
}

function buildSignedUrlAblationArgs(
  controlArgs: Record<string, unknown>,
  differingParam: string,
  nonce: string,
): Record<string, unknown> | null {
  const ctlParams = paramMapFromArmArgs(controlArgs)
  const ctlVal = ctlParams[differingParam]
  if (ctlVal === undefined) return null
  const ablVal = makeInPrefixAblationValue(ctlVal, nonce)
  if (differingParam.startsWith('body:')) {
    const fieldPath = differingParam.slice(5)
    const rawBody = typeof controlArgs.body === 'string' ? controlArgs.body : ''
    const parsed = parseJsonSafe(rawBody)
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const cloned = JSON.parse(JSON.stringify(parsed)) as Record<string, unknown>
      const parts = fieldPath.split('.')
      let cur: Record<string, unknown> = cloned
      for (let i = 0; i < parts.length - 1; i += 1) {
        const next = cur[parts[i]!]
        if (!next || typeof next !== 'object' || Array.isArray(next)) return null
        cur = next as Record<string, unknown>
      }
      const leaf = parts[parts.length - 1]!
      if (!(leaf in cur)) return null
      cur[leaf] = ablVal
      return { ...controlArgs, body: JSON.stringify(cloned), sessionGroupRole: 'control' }
    }
    if (rawBody.includes('=')) {
      const params = new URLSearchParams(rawBody)
      if (!params.has(fieldPath)) return null
      params.set(fieldPath, ablVal)
      return { ...controlArgs, body: params.toString(), sessionGroupRole: 'control' }
    }
    return { ...controlArgs, body: ablVal, sessionGroupRole: 'control' }
  }
  const pathStr = String(controlArgs.path ?? '/')
  const qIdx = pathStr.indexOf('?')
  if (qIdx < 0) return null
  const params = new URLSearchParams(pathStr.slice(qIdx + 1))
  if (!params.has(differingParam)) return null
  params.set(differingParam, ablVal)
  return { ...controlArgs, path: `${pathStr.slice(0, qIdx)}?${params.toString()}`, sessionGroupRole: 'control' }
}

export async function handleProveSignedUrlMint(
  host: ProveHandlerHost,
  args: Record<string, unknown>,
  nonce: string,
): Promise<unknown> {
  const session = typeof args.session === 'string' && args.session ? args.session : 'signed-url-mint'
  const rawVariant = String(args.variant ?? 'auto').trim().toLowerCase()
  const variant: SignedUrlMintVariant | 'auto' = rawVariant === 'key_traversal' || rawVariant === 'unauth_write_mint'
    ? rawVariant
    : 'auto'
  const baseRoute = args.route ?? args.url ?? args.path ?? args.pathAndQuery ?? args.endpoint
  const baseOpts: Record<string, unknown> = {
    ...(typeof args.method === 'string' ? { method: args.method } : { method: 'POST' }),
    ...(asRecord(args.headers) ? { headers: args.headers } : {}),
    ...(typeof (args.as ?? args.as_persona ?? args.persona) === 'string' ? { persona: args.as ?? args.as_persona ?? args.persona } : {}),
  }

  const existingControlId = typeof (args.controlExchangeId ?? args.control_exchange_id) === 'string'
    ? String(args.controlExchangeId ?? args.control_exchange_id).trim()
    : ''
  const existingProbeId = typeof (args.probeExchangeId ?? args.probe_exchange_id) === 'string'
    ? String(args.probeExchangeId ?? args.probe_exchange_id).trim()
    : ''
  const existingAblationId = typeof (args.ablationExchangeId ?? args.ablation_exchange_id) === 'string'
    ? String(args.ablationExchangeId ?? args.ablation_exchange_id).trim()
    : ''

  let control: ProveHttpExchangeResult | null = null
  let probe: ProveHttpExchangeResult | null = null
  let ablation: ProveHttpExchangeResult | null = null

  if (existingControlId && existingProbeId) {
    control = exchangeSummaryFromTranscript(host, existingControlId)
    probe = exchangeSummaryFromTranscript(host, existingProbeId)
    if (existingAblationId) {
      ablation = exchangeSummaryFromTranscript(host, existingAblationId)
    }
    if (!control || !probe) {
      throw new Error('prove.signedUrlMint references an unknown controlExchangeId or probeExchangeId.')
    }
  } else {
    const controlBodyArg = args.controlBody ?? args.control_body
    const probeBodyArg = args.probeBody ?? args.probe_body
    const ablationBodyArg = args.ablationBody ?? args.ablation_body
    const rawControl: unknown = args.control ?? (baseRoute && controlBodyArg !== undefined ? { target: baseRoute, options: { ...baseOpts, body: controlBodyArg } } : undefined)
    let rawProbe: unknown = args.probe ?? args.variantRequest ?? (baseRoute && probeBodyArg !== undefined ? { target: baseRoute, options: { ...baseOpts, body: probeBodyArg } } : undefined)
    const rawAblation: unknown = args.ablation ?? (baseRoute && ablationBodyArg !== undefined ? { target: baseRoute, options: { ...baseOpts, body: ablationBodyArg } } : undefined)
    if (!rawControl || !rawProbe) {
      throw new Error('prove_signed_url_mint requires `control` and `probe` (or `route` with `controlBody` and `probeBody`, or `controlExchangeId` and `probeExchangeId`).')
    }
    const traversalPlaceholders = ['{{signedUrlTraversal}}', '{{traversalKey}}']
    if (hasAnyPlaceholder(rawProbe, traversalPlaceholders)) {
      const mintedTrav = `../kovo-trav-${randomBytes(4).toString('hex')}.json`
      rawProbe = renderTemplateStrings(rawProbe, {
        '{{signedUrlTraversal}}': mintedTrav,
        '{{traversalKey}}': mintedTrav,
      })
    }
    const controlArgs = normalizeArmTarget(host.defaultOrigin, rawControl, {
      ...(typeof baseOpts.method === 'string' && !(asRecord(rawControl)?.method || asRecord(asRecord(rawControl)?.options)?.method) ? { method: baseOpts.method } : {}),
      sessionGroupRole: 'control',
      session,
    })
    const probeArgs = normalizeArmTarget(host.defaultOrigin, rawProbe, {
      ...(typeof baseOpts.method === 'string' && !(asRecord(rawProbe)?.method || asRecord(asRecord(rawProbe)?.options)?.method) ? { method: baseOpts.method } : {}),
      sessionGroupRole: 'probe',
      session,
    })
    control = await host.runHttpExchange(controlArgs, nonce, hostAssignedStamp('control'))
    probe = await host.runHttpExchange(probeArgs, nonce, hostAssignedStamp('probe'))
    if (rawAblation) {
      const ablationArgs = normalizeArmTarget(host.defaultOrigin, rawAblation, {
        ...(typeof baseOpts.method === 'string' && !(asRecord(rawAblation)?.method || asRecord(asRecord(rawAblation)?.options)?.method) ? { method: baseOpts.method } : {}),
        sessionGroupRole: 'control',
        session,
      })
      ablation = await host.runHttpExchange(ablationArgs, nonce, hostAssignedStamp('control'))
    } else if (control.status >= 200 && control.status < 300 && variant !== 'unauth_write_mint') {
      const armParity = checkArmIdentityParity(host.defaultOrigin, controlArgs, probeArgs)
      if (armParity.ok) {
        const autoAblArgs = buildSignedUrlAblationArgs(controlArgs, armParity.differingParam, nonce)
        if (autoAblArgs) {
          try { ablation = await host.runHttpExchange(autoAblArgs, nonce, hostAssignedStamp('control')) } catch { ablation = null }
        }
      }
    }
  }

  const hostControl = transcriptRecordToSignedUrlExchange(host.transcript, control.exchangeId, host.defaultOrigin ?? '')
  const hostProbe = transcriptRecordToSignedUrlExchange(host.transcript, probe.exchangeId, host.defaultOrigin ?? '')
  const hostAblation = ablation
    ? transcriptRecordToSignedUrlExchange(host.transcript, ablation.exchangeId, host.defaultOrigin ?? '')
    : null
  if (!hostControl || !hostProbe) {
    throw new Error('prove.signedUrlMint could not read host-signed control/probe records from the transcript.')
  }

  // R4-C-6: Delegate to the shared hardened kernel primitive (`verifySignedUrlMintPair`) and
  // enforce variant + in-prefix ablation arm checks via `assessSignedUrlMintDifferential`.
  const kernelCheck = verifySignedUrlMintPair({
    control: hostControl,
    probe: hostProbe,
  })
  const detailed = assessSignedUrlMintDifferential({
    control: hostControl,
    probe: hostProbe,
    ...(hostAblation ? { ablation: hostAblation } : {}),
    variant,
  })
  const confirmed = kernelCheck.confirmed && detailed.confirmed
  const rejectedBy = confirmed
    ? null
    : (!kernelCheck.confirmed ? (kernelCheck.rejectedBy ?? 'signed_url_mint') : (detailed.rejectedBy ?? 'signed_url_mint'))
  const missingEvidence = confirmed
    ? []
    : (!kernelCheck.confirmed ? kernelCheck.missingEvidence : detailed.missingEvidence)
  const reason = confirmed
    ? detailed.reason
    : (!kernelCheck.confirmed ? kernelCheck.reason : detailed.reason)
  const evidence: Record<string, unknown> = {
    ...(confirmed ? detailed.evidence : (!kernelCheck.confirmed ? kernelCheck.evidence : detailed.evidence)),
    ...(ablation ? { ablationExchangeId: ablation.exchangeId } : {}),
  }

  const chainId = `signed_url_mint:${detailed.variant ?? (variant === 'auto' ? 'unverified' : variant)}`
  const cwe = detailed.variant === 'unauth_write_mint' ? 'CWE-306' : 'CWE-22'
  const exchangeIds = [control.exchangeId, probe.exchangeId]
  // R4-C-6: NEVER stamp `replayMode: 'fresh_clean_replay'` without an actual fresh clean replay.
  const replayMode = 'one_shot_transcript' as const
  const recorded = host.transcript.recordCompositeVerification({
    chainId,
    terminalVulnClass: 'signed_url_mint',
    replayMode,
    hopCount: 1,
    confirmed,
    verifiedEdgeCount: confirmed ? 1 : 0,
    reason,
    rejectedBy,
    missingEvidence,
    exchangeIds,
    terminalExchangeId: probe.exchangeId,
    route: probe.pathAndQuery,
  })
  const claim: Extract<VerifyClaim, { kind: 'composite_receipt' }> = {
    kind: 'composite_receipt',
    verificationId: recorded.verificationId,
    chainId,
    terminalVulnClass: 'signed_url_mint',
    cwe,
    route: probe.pathAndQuery,
    exchangeIds,
    terminalExchangeId: probe.exchangeId,
    replayMode,
    hopCount: 1,
    ...(typeof args.message === 'string' && args.message ? { message: args.message } : {}),
    ...(!confirmed ? {
      rejectedBy: rejectedBy ?? 'signed_url_mint',
      missingEvidence,
      reason,
    } : {}),
  }

  return host.scrubRecord({
    ok: confirmed,
    confirmed,
    variant: confirmed ? detailed.variant : null,
    provider: confirmed ? detailed.provider : null,
    endpoint: probe.pathAndQuery,
    control,
    probe,
    ...(ablation ? { ablation } : {}),
    claim,
    claims: [claim],
    evidence,
    reason,
    rejectedBy,
    missingEvidence,
    transcriptSummary: [
      proofEntry('control', control),
      proofEntry('probe', probe),
      ...(ablation ? [proofEntry('control', ablation, 'in_prefix_ablation')] : []),
    ],
  })
}
