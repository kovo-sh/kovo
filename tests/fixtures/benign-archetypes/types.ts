/**
 * Parametric synthetic benign-archetype types and HostFactLog recording helpers (R3-12).
 *
 * Defensive QA framing:
 * Every archetype here is a pure, zero-network TypeScript simulator modeling a correct,
 * non-vulnerable web target (public route, input validator, deleting sanitizer, honest
 * accumulator, benign share link, integer coercion, honest RBAC, public cache/pagination).
 * Exchanges are recorded into an immutable, host-signed `HostFactLog` strictly from
 * simulated host-observed wire exchanges — never touching live targets.
 */
import { createHash } from 'node:crypto'
import { HostFactLog, type HostExchangeFactInput } from '../../../src/server/host-fact-log.ts'
import type { AmbientAuth, ImpactStep, RoleName } from '../../../src/server/oracle-invariants.ts'
import type {
  HostMintedExpressionChallenge,
  HostMintedTimingChallenge,
  HostStampedBooleanPair,
} from '../../../src/server/proof-receipt.ts'

export const MATRIX_SIGNING_KEY = 'r3-12-kernel-archetype-matrix-signing-key-2026'
export const MATRIX_ORIGIN = 'https://benign-qa.example.invalid'

export const BENIGN_ARCHETYPE_IDS = [
  'public_endpoint',
  'validator_4xx',
  'deleting_sanitizer',
  'honest_accumulator',
  'benign_share_link',
  'integer_coercion',
  'honest_rbac',
  'cache_hit_and_pagination',
] as const

export type BenignArchetypeId = (typeof BENIGN_ARCHETYPE_IDS)[number]

export interface SyntheticActor {
  readonly handle: string | null
  readonly role: RoleName | null
  readonly roleLabel?: string | null
  readonly tenant: string | null
  readonly auth: AmbientAuth
  readonly sameSite?: string | null
  readonly authHeader?: string | null
  readonly cookieHeader?: string | null
  readonly sessionId?: string | null
}

export const MATRIX_ACTORS = {
  anon: {
    handle: null,
    role: null,
    roleLabel: null,
    tenant: null,
    auth: 'unknown',
    sameSite: null,
  },
  ownerA: {
    handle: 'owner_a',
    role: 'owner',
    roleLabel: 'owner@tenant-a',
    tenant: 'tenant-a',
    auth: 'bearer',
    sameSite: null,
    authHeader: 'Bearer tok_owner_a_valid',
    sessionId: 'sess_owner_a',
  },
  memberA: {
    handle: 'member_a',
    role: 'member',
    roleLabel: 'member@tenant-a',
    tenant: 'tenant-a',
    auth: 'cookie',
    sameSite: 'Lax',
    cookieHeader: 'sid=sess_member_a_valid',
    sessionId: 'sess_member_a',
  },
  viewerA: {
    handle: 'viewer_a',
    role: 'viewer',
    roleLabel: 'viewer@tenant-a',
    tenant: 'tenant-a',
    auth: 'bearer',
    sameSite: null,
    authHeader: 'Bearer tok_viewer_a_valid',
    sessionId: 'sess_viewer_a',
  },
  ownerB: {
    handle: 'owner_b',
    role: 'owner',
    roleLabel: 'owner@tenant-b',
    tenant: 'tenant-b',
    auth: 'bearer',
    sameSite: null,
    authHeader: 'Bearer tok_owner_b_valid',
    sessionId: 'sess_owner_b',
  },
  memberB: {
    handle: 'member_b',
    role: 'member',
    roleLabel: 'member@tenant-b',
    tenant: 'tenant-b',
    auth: 'cookie',
    sameSite: 'Lax',
    cookieHeader: 'sid=sess_member_b_valid',
    sessionId: 'sess_member_b',
  },
  dualOrgActor: {
    handle: 'dual_user',
    role: 'admin',
    roleLabel: 'admin@tenant-a,viewer@tenant-b',
    tenant: 'tenant-a',
    auth: 'bearer',
    sameSite: null,
    authHeader: 'Bearer tok_dual_user_valid',
    sessionId: 'sess_dual_user',
  },
} as const satisfies Record<string, SyntheticActor>

export interface SyntheticTargetRequest {
  readonly method: string
  readonly pathAndQuery: string
  readonly actor: SyntheticActor
  readonly headers?: Readonly<Record<string, string>>
  readonly jsonBody?: unknown
  readonly rawBody?: string | null
  readonly arm?: ImpactStep['arm']
  readonly evidenceRole?: string
  readonly raceBatchId?: string | null
  readonly hostBooleanPair?: HostStampedBooleanPair
  readonly hostTimingChallenge?: HostMintedTimingChallenge
  readonly hostExpressionChallenge?: HostMintedExpressionChallenge
  readonly hostRedirectCanaryHost?: string | null
  readonly consumedCapabilities?: readonly string[]
  readonly correlationIds?: readonly string[]
  readonly op?: string
  readonly timestampMs?: number
  readonly durationMs?: number
}

export interface SyntheticTargetResponse {
  readonly status: number
  readonly headers?: Readonly<Record<string, string>>
  readonly json?: unknown
  readonly body?: string
  readonly durationMs?: number
  readonly emittedCapabilities?: readonly string[]
  readonly entityId?: string
}

export interface BenignTargetSession {
  readonly archetypeId: BenignArchetypeId
  readonly origin: string
  readonly primaryRoute: string
  readonly secondaryRoute: string
  readonly queryParam: string
  readonly baseParamValue: string
  readonly mutateRoute: string
  readonly balanceRoute: string
  readonly readEntityRoute: string
  readonly foreignEntityRoute: string
  readonly log: HostFactLog
  send(exchangeId: string, req: SyntheticTargetRequest): Readonly<{
    exchangeId: string
    status: number
    body: string
    json: unknown
    headers: Readonly<Record<string, string>>
    timestampMs: number
    durationMs: number
  }>
}

export interface BenignArchetypeDefinition {
  readonly id: BenignArchetypeId
  readonly title: string
  readonly description: string
  createSession(opts?: { signingKey?: string; origin?: string }): BenignTargetSession
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

export function parseQueryParams(pathAndQuery: string): URLSearchParams {
  const qIdx = pathAndQuery.indexOf('?')
  return new URLSearchParams(qIdx >= 0 ? pathAndQuery.slice(qIdx + 1) : '')
}

export function pathnameOf(pathAndQuery: string): string {
  const qIdx = pathAndQuery.indexOf('?')
  return (qIdx >= 0 ? pathAndQuery.slice(0, qIdx) : pathAndQuery) || '/'
}

export function headerCI(headers: Readonly<Record<string, string>> | undefined, name: string): string | null {
  if (!headers) return null
  const needle = name.toLowerCase()
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === needle) return v
  }
  return null
}

/**
 * Helper to construct a zero-network `BenignTargetSession` backed by a pure handler function.
 * Every exchange is recorded chronologically into a host-signed `HostFactLog`.
 */
export function createBenignSession(config: {
  archetypeId: BenignArchetypeId
  origin?: string
  signingKey?: string
  primaryRoute: string
  secondaryRoute: string
  queryParam: string
  baseParamValue: string
  mutateRoute: string
  balanceRoute: string
  readEntityRoute: string
  foreignEntityRoute: string
  handle: (req: SyntheticTargetRequest) => SyntheticTargetResponse
}): BenignTargetSession {
  const origin = config.origin ?? MATRIX_ORIGIN
  const signingKey = config.signingKey ?? MATRIX_SIGNING_KEY
  const log = new HostFactLog({ signingKey, assertCleanRequestPlane: true })
  let clockMs = 1_700_000_000_000

  return {
    archetypeId: config.archetypeId,
    origin,
    primaryRoute: config.primaryRoute,
    secondaryRoute: config.secondaryRoute,
    queryParam: config.queryParam,
    baseParamValue: config.baseParamValue,
    mutateRoute: config.mutateRoute,
    balanceRoute: config.balanceRoute,
    readEntityRoute: config.readEntityRoute,
    foreignEntityRoute: config.foreignEntityRoute,
    log,
    send(exchangeId: string, req: SyntheticTargetRequest) {
      const startedAt = req.timestampMs ?? (clockMs += 100)
      if (startedAt > clockMs) clockMs = startedAt
      const reqHeaders: Record<string, string> = {}
      if (req.actor.authHeader) reqHeaders.authorization = req.actor.authHeader
      if (req.actor.cookieHeader) reqHeaders.cookie = req.actor.cookieHeader
      if (req.jsonBody !== undefined) reqHeaders['content-type'] = 'application/json'
      if (req.headers) {
        for (const [k, v] of Object.entries(req.headers)) reqHeaders[k.toLowerCase()] = v
      }
      const rawRequestBody = req.rawBody !== undefined
        ? req.rawBody
        : req.jsonBody !== undefined
          ? JSON.stringify(req.jsonBody)
          : null

      const resp = config.handle({ ...req, headers: reqHeaders, rawBody: rawRequestBody })
      const durationMs = req.durationMs ?? resp.durationMs ?? 12
      const endedAt = startedAt + durationMs
      const body = resp.body !== undefined
        ? resp.body
        : resp.json !== undefined
          ? JSON.stringify(resp.json)
          : ''
      let parsedJson: unknown = resp.json
      if (parsedJson === undefined && body.startsWith('{')) {
        try { parsedJson = JSON.parse(body) } catch { parsedJson = undefined }
      }
      const responseHeaders: Record<string, string> = {
        'content-type': 'application/json; charset=utf-8',
        ...(resp.headers ?? {}),
      }

      const input: HostExchangeFactInput = {
        exchangeId,
        op: req.op ?? 'http',
        method: req.method.toUpperCase(),
        origin,
        pathAndQuery: req.pathAndQuery,
        status: resp.status,
        requestHeaders: reqHeaders,
        rawRequestBody,
        responseHeaders,
        rawResponseBody: body,
        actor: req.actor.handle,
        actorRole: req.actor.role,
        actorRoleLabel: req.actor.roleLabel ?? null,
        actorTenant: req.actor.tenant,
        ambientAuth: req.actor.auth,
        ...(req.actor.sameSite !== undefined ? { sameSite: req.actor.sameSite } : {}),
        ...(req.actor.sessionId ? { sessionId: req.actor.sessionId } : {}),
        durationMs,
        startedAt,
        endedAt,
        timestampMs: startedAt,
        arm: req.arm ?? 'probe',
        ...(req.evidenceRole ? { evidenceRole: req.evidenceRole } : {}),
        ...(req.raceBatchId !== undefined ? { raceBatchId: req.raceBatchId } : {}),
        ...(req.hostBooleanPair ? { hostBooleanPair: req.hostBooleanPair } : {}),
        ...(req.hostTimingChallenge ? { hostTimingChallenge: req.hostTimingChallenge } : {}),
        ...(req.hostExpressionChallenge ? { hostExpressionChallenge: req.hostExpressionChallenge } : {}),
        ...(req.hostRedirectCanaryHost !== undefined ? { hostRedirectCanaryHost: req.hostRedirectCanaryHost } : {}),
        ...(req.consumedCapabilities?.length ? { consumedCapabilities: req.consumedCapabilities } : {}),
        ...(resp.emittedCapabilities?.length ? { emittedCapabilities: resp.emittedCapabilities } : {}),
        ...(resp.entityId ? { entityId: resp.entityId } : {}),
        ...(req.correlationIds?.length ? { correlationIds: req.correlationIds } : {}),
        cleanSession: true,
      }
      log.recordExchange(input)
      return {
        exchangeId,
        status: resp.status,
        body,
        json: parsedJson,
        headers: responseHeaders,
        timestampMs: startedAt,
        durationMs,
      }
    },
  }
}
