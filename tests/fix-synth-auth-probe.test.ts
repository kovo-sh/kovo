/**
 * P0 #1 Regression Suite — Host-Minted Synthetic Invalid Auth Probes Without a Persona.
 *
 * Verifies:
 *  1. Unauthenticated runs (0 personas) can send host-minted `synthetic_invalid_bearer` and
 *     `synthetic_invalid_api_key` probes via `RequestBroker.executeHttp` without `personaHandle`,
 *     injecting deterministic non-secret tokens onto the wire and stamping
 *     `wireCredentialProvenance` with `source: 'caller_self_minted'` (never `persona_vault`).
 *  2. Custom allowlisted API-key header names (`X-Auth-Token`, `X-Access-Token`, `X-Session-Token`)
 *     are accepted while disallowed / sensitive headers (`Cookie`, `Authorization`, `Host`, arbitrary
 *     headers) fail closed (`invalid_header`).
 *  3. Even when `personaHandle` is supplied alongside a synthetic invalid auth mutation, ZERO
 *     persona vault credentials leak onto the wire and provenance stays `caller_self_minted`.
 *  4. H-8 / H-14 / R2-H-8 invariants remain 100% strict:
 *     - Arbitrary caller-supplied `Authorization` / `Cookie` headers are rejected with `forbidden_header`.
 *     - Persona-based `authMutation` kinds (`alg_none`, `strip_signature`, `tamper_sig`, etc.)
 *       without `personaHandle` still fail closed with `persona_required`.
 *     - Tier 1 (passive) still rejects synthetic `authMutation` with `tier_insufficient`.
 *  5. Broker `wireCredentialProvenance` from a synthetic invalid auth probe satisfies H-14
 *     `proof-receipt.ts` `auth_bypass` verification against an unauthenticated 401 control.
 *  6. Prompt guidance and Pi tool schema (`normalizePiAuthMutation`, `authMutationPiSchema`)
 *     expose both synthetic probe kinds cleanly.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  normalizePiAuthMutation,
  scenarioInstructions,
  SPECIALIST_PROFILES,
} from '../src/server/agent-prompts.ts'
import { BrokerDenied, RequestBroker } from '../src/server/broker.ts'
import type { Grant, PublicAddress } from '../src/server/broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { buildProofReceipt, verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ImpactStep } from '../src/server/proof-receipt.ts'
import {
  RequestAdmissionEngine,
  SYNTHETIC_INVALID_API_KEY_PREFIX,
  SYNTHETIC_INVALID_BEARER_PREFIX,
  validateCallerHeaders,
} from '../src/server/request-admission.ts'
import type { BrokerAuthMutation } from '../src/server/request-admission.ts'

const APP_ORIGIN = 'https://app.synth-auth-probe.example'
const PUBLIC_ADDR: PublicAddress = { address: '93.184.216.34', family: 4 }

function makeGrant(overrides: Partial<Grant> = {}): Grant {
  return {
    origin: APP_ORIGIN,
    tier: 2,
    allowLocalLab: false,
    maxRpsPerOrigin: 50,
    canRead: origin => origin === APP_ORIGIN,
    audit: () => {},
    ...overrides,
  }
}

function makePersona(
  handle: string,
  secret: string,
  authKind: 'bearer' | 'cookie' = 'bearer',
): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel: 'member:tenant-a',
    originAllowlist: [APP_ORIGIN],
    authKind,
    headerName: authKind === 'bearer' ? 'Authorization' : null,
    secret,
    canaryMarkers: [],
  }
}

function makeImpactStep(input: {
  id: string
  arm: 'control' | 'probe'
  method: string
  route: string
  status: number
  body: string
  requestHeaders?: Record<string, string>
  auth?: 'unknown' | 'bearer' | 'cookie' | 'header'
}): ImpactStep {
  return {
    id: input.id,
    arm: input.arm,
    actor: { handle: null, role: null, tenant: null, auth: input.auth ?? 'unknown', sameSite: null },
    method: input.method,
    route: input.route,
    status: input.status,
    body: input.body,
    requestHeaders: input.requestHeaders ?? {},
  }
}

test('synthetic_invalid_bearer on unauthenticated run (0 personas) injects deterministic probe and stamps caller_self_minted', async t => {
  const seenWireHeaders: Array<Record<string, string>> = []
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async (_url, _addr, _signal, req) => {
      seenWireHeaders.push({ ...(req?.headers ?? {}) })
      const auth = req?.headers?.Authorization ?? req?.headers?.authorization ?? ''
      const hasBearer = auth.startsWith('Bearer ')
      return {
        status: hasBearer ? 200 : 401,
        headers: { 'content-type': 'application/json' },
        body: hasBearer ? '{"accountId":"acct-42","plan":"pro"}' : '{"error":"missing bearer"}',
      }
    },
  })
  t.after(() => broker.closeTransport())

  const grant = makeGrant({ personas: new Map() })
  const first = await broker.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      runId: 'run-synth-bearer-001',
      authMutation: { kind: 'synthetic_invalid_bearer' },
    },
    grant,
    AbortSignal.timeout(5_000),
  )
  const second = await broker.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      runId: 'run-synth-bearer-001',
      authMutation: { kind: 'synthetic_invalid_bearer' },
    },
    grant,
    AbortSignal.timeout(5_000),
  )

  assert.equal(first.status, 200)
  assert.equal(first.personaHandle, null)
  const auth1 = seenWireHeaders[0]?.Authorization
  const auth2 = seenWireHeaders[1]?.Authorization
  assert.ok(auth1, 'Authorization header must be sent on the wire')
  assert.match(auth1, new RegExp(`^Bearer ${SYNTHETIC_INVALID_BEARER_PREFIX}[a-f0-9]{16}$`))
  assert.equal(auth1, auth2, 'synthetic invalid bearer must be deterministic within the same run')

  const prov = first.wireCredentialProvenance!
  assert.equal(prov.authenticated, true)
  assert.equal(prov.source, 'caller_self_minted')
  assert.deepEqual(prov.sources, ['caller_self_minted'])
  assert.equal(prov.personaHandle, null)
  assert.deepEqual(prov.vaultHeaderNames, [])
  assert.deepEqual(prov.vaultCookieNames, [])
  assert.deepEqual(prov.callerAuthHeaderNames, ['authorization'])
  assert.deepEqual(prov.headerNames, ['authorization'])
  assert.equal(prov.authMutated, true)

  // Verify H-14 proof-receipt treats broker provenance from synthetic_invalid_bearer as genuine auth_bypass.
  const controlRes = await broker.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      runId: 'run-synth-bearer-001',
    },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(controlRes.status, 401)
  assert.equal(controlRes.wireCredentialProvenance?.source, 'none')

  const receipt = buildProofReceipt({
    vulnClass: 'auth_bypass',
    target: { origin: APP_ORIGIN, method: 'GET', pathAndQuery: '/api/protected' },
    exchangeIds: ['ctl-1', 'prb-1'],
    claimedDelta: 'Presence-only Bearer middleware accepted host-minted invalid Bearer probe token.',
  })
  const verdict = verifyReceipt(receipt, {
    entries: [
      {
        exchangeId: 'ctl-1',
        origin: APP_ORIGIN,
        wireCredentialProvenance: controlRes.wireCredentialProvenance,
        step: makeImpactStep({
          id: 'ctl-1',
          arm: 'control',
          method: 'GET',
          route: '/api/protected',
          status: controlRes.status,
          body: controlRes.body,
        }),
      },
      {
        exchangeId: 'prb-1',
        origin: APP_ORIGIN,
        wireCredentialProvenance: first.wireCredentialProvenance,
        step: makeImpactStep({
          id: 'prb-1',
          arm: 'probe',
          method: 'GET',
          route: '/api/protected',
          status: first.status,
          body: first.body,
          auth: 'bearer',
          requestHeaders: { authorization: auth1 },
        }),
      },
    ],
  })
  assert.equal(verdict.confirmed, true, `synthetic_invalid_bearer auth_bypass must confirm under H-14: ${verdict.reason}`)
})

test('synthetic_invalid_api_key injects deterministic X-API-Key (or allowlisted headerName) and rejects unsafe headerName', async t => {
  const seenWireHeaders: Array<Record<string, string>> = []
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async (_url, _addr, _signal, req) => {
      seenWireHeaders.push({ ...(req?.headers ?? {}) })
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"ok":true}',
      }
    },
  })
  t.after(() => broker.closeTransport())

  const grant = makeGrant({ personas: new Map() })
  const resDefault = await broker.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/keys',
      runId: 'run-synth-apikey-001',
      authMutation: { kind: 'synthetic_invalid_api_key' },
    },
    grant,
    AbortSignal.timeout(5_000),
  )

  const apiKey = seenWireHeaders[0]?.['X-API-Key']
  assert.ok(apiKey, 'X-API-Key header must be sent on the wire')
  assert.match(apiKey, new RegExp(`^${SYNTHETIC_INVALID_API_KEY_PREFIX}[a-f0-9]{16}$`))
  assert.equal(resDefault.wireCredentialProvenance?.authenticated, true)
  assert.equal(resDefault.wireCredentialProvenance?.source, 'caller_self_minted')
  assert.deepEqual(resDefault.wireCredentialProvenance?.sources, ['caller_self_minted'])
  assert.deepEqual(resDefault.wireCredentialProvenance?.callerAuthHeaderNames, ['x-api-key'])
  assert.deepEqual(resDefault.wireCredentialProvenance?.vaultHeaderNames, [])
  assert.equal(resDefault.wireCredentialProvenance?.personaHandle, null)
  assert.equal(resDefault.wireCredentialProvenance?.authMutated, true)

  // Allowlisted alternate API-key header name succeeds.
  const resAlt = await broker.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/keys',
      runId: 'run-synth-apikey-001',
      authMutation: { kind: 'synthetic_invalid_api_key', headerName: 'X-Auth-Token' },
    },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(seenWireHeaders[1]?.['X-Auth-Token'], apiKey)
  assert.equal(resAlt.wireCredentialProvenance?.source, 'caller_self_minted')
  assert.deepEqual(resAlt.wireCredentialProvenance?.callerAuthHeaderNames, ['x-auth-token'])

  // Disallowed / dangerous header names must fail closed.
  for (const badHeader of ['Cookie', 'Authorization', 'Host', 'X-Forwarded-For', 'X-Custom-Arbitrary']) {
    await assert.rejects(
      () =>
        broker.executeHttp(
          {
            origin: APP_ORIGIN,
            method: 'GET',
            pathAndQuery: '/api/keys',
            runId: 'run-synth-apikey-001',
            authMutation: { kind: 'synthetic_invalid_api_key', headerName: badHeader },
          },
          grant,
          AbortSignal.timeout(5_000),
        ),
      err => err instanceof BrokerDenied && /allowlisted API-key header/i.test(err.message),
      `disallowed headerName "${badHeader}" must fail closed`,
    )
  }
})

test('synthetic invalid auth mutations never leak persona vault credentials even if personaHandle is supplied', async t => {
  const realBearerSecret = 'real-vault-secret-token-should-never-appear-on-wire'
  const realCookieSecret = 'sid=real-vault-cookie-secret-should-never-leak'
  const seenWireHeaders: Array<Record<string, string>> = []
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async (_url, _addr, _signal, req) => {
      seenWireHeaders.push({ ...(req?.headers ?? {}) })
      return {
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: '{"ok":true}',
      }
    },
  })
  t.after(() => broker.closeTransport())

  const personas = new Map<string, ResolvedPersona>([
    ['alice', makePersona('alice', realBearerSecret, 'bearer')],
    ['bob', makePersona('bob', realCookieSecret, 'cookie')],
  ])
  const grant = makeGrant({ personas })

  const bearerRes = await broker.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      runId: 'run-synth-no-leak',
      persona: 'alice',
      authMutation: { kind: 'synthetic_invalid_bearer' },
    },
    grant,
    AbortSignal.timeout(5_000),
  )

  const wire1 = seenWireHeaders[0]!
  assert.ok(!JSON.stringify(wire1).includes(realBearerSecret), 'real persona bearer secret must never leak onto wire')
  assert.match(wire1.Authorization ?? '', new RegExp(`^Bearer ${SYNTHETIC_INVALID_BEARER_PREFIX}[a-f0-9]{16}$`))
  assert.equal(bearerRes.personaHandle, null)
  assert.equal(bearerRes.wireCredentialProvenance?.source, 'caller_self_minted')
  assert.equal(bearerRes.wireCredentialProvenance?.personaHandle, null)
  assert.deepEqual(bearerRes.wireCredentialProvenance?.vaultHeaderNames, [])
  assert.deepEqual(bearerRes.wireCredentialProvenance?.vaultCookieNames, [])

  const cookieRes = await broker.executeHttp(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      runId: 'run-synth-no-leak',
      persona: 'bob',
      authMutation: { kind: 'synthetic_invalid_api_key' },
    },
    grant,
    AbortSignal.timeout(5_000),
  )

  const wire2 = seenWireHeaders[1]!
  assert.ok(!JSON.stringify(wire2).includes(realCookieSecret), 'real persona cookie secret must never leak onto wire')
  assert.equal(wire2.Cookie, undefined, 'real persona cookie header must never be sent')
  assert.equal(wire2.cookie, undefined, 'real persona cookie header must never be sent')
  assert.match(wire2['X-API-Key'] ?? '', new RegExp(`^${SYNTHETIC_INVALID_API_KEY_PREFIX}[a-f0-9]{16}$`))
  assert.equal(cookieRes.personaHandle, null)
  assert.equal(cookieRes.wireCredentialProvenance?.source, 'caller_self_minted')
  assert.equal(cookieRes.wireCredentialProvenance?.personaHandle, null)
  assert.deepEqual(cookieRes.wireCredentialProvenance?.vaultHeaderNames, [])
  assert.deepEqual(cookieRes.wireCredentialProvenance?.vaultCookieNames, [])
})

test('H-8/H-14 preservation: arbitrary Authorization/Cookie remain forbidden_header; persona authMutation without personaHandle still fails closed', async t => {
  const engine = new RequestAdmissionEngine({ env: {} })
  const grant = makeGrant()

  // 1. Arbitrary caller-supplied Authorization: Bearer real-secret-token without personaHandle -> forbidden_header
  const rawBearer = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      headers: { Authorization: 'Bearer real-secret-token' },
    },
    grant,
  )
  assert.equal(rawBearer.outcome, 'deny')
  assert.equal(rawBearer.reasonCode, 'forbidden_header')

  // 2. Arbitrary caller-supplied Cookie -> forbidden_header
  const rawCookie = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      headers: { Cookie: 'sid=real-session-cookie' },
    },
    grant,
  )
  assert.equal(rawCookie.outcome, 'deny')
  assert.equal(rawCookie.reasonCode, 'forbidden_header')

  // 3. Well-formed clearly tagged synthetic probe header passes validateCallerHeaders; malformed ones fail.
  const validProbeHdr = validateCallerHeaders({
    Authorization: `Bearer ${SYNTHETIC_INVALID_BEARER_PREFIX}0123456789abcdef`,
  })
  assert.equal(validProbeHdr.ok, true)

  for (const badVal of [
    `Bearer ${SYNTHETIC_INVALID_BEARER_PREFIX}short`,
    `Bearer ${SYNTHETIC_INVALID_BEARER_PREFIX}not-hex-zzzzzzzzzzzz`,
    `Bearer ${SYNTHETIC_INVALID_BEARER_PREFIX}0123456789abcdef extra`,
    'Bearer real-secret-token',
  ]) {
    const check = validateCallerHeaders({ Authorization: badVal })
    assert.equal(check.ok, false, `must reject "${badVal}"`)
    if (!check.ok) assert.equal(check.reasonCode, 'forbidden_header')
  }

  // 4. Persona-based authMutation kinds without personaHandle MUST still fail closed with persona_required.
  const personaMutations: BrokerAuthMutation[] = [
    { kind: 'alg_none' },
    { kind: 'strip_signature' },
    { kind: 'expired_replay' },
    { kind: 'tamper_sig' } as unknown as BrokerAuthMutation,
  ]
  for (const mutation of personaMutations) {
    const decision = engine.admit(
      {
        origin: APP_ORIGIN,
        method: 'GET',
        pathAndQuery: '/api/protected',
        authMutation: mutation,
      },
      grant,
    )
    assert.equal(decision.outcome, 'deny', `${mutation.kind} without personaHandle must deny`)
    assert.equal(decision.reasonCode, 'persona_required', `${mutation.kind} without personaHandle must return persona_required`)
  }

  // 5. Tier 1 (passive) still denies synthetic auth mutations.
  const tier1Decision = engine.admit(
    {
      origin: APP_ORIGIN,
      method: 'GET',
      pathAndQuery: '/api/protected',
      authMutation: { kind: 'synthetic_invalid_bearer' },
    },
    makeGrant({ tier: 1 }),
  )
  assert.equal(tier1Decision.outcome, 'deny')
  assert.equal(tier1Decision.reasonCode, 'tier_insufficient')

  // 6. Broker rejects arbitrary caller-supplied Authorization end-to-end.
  const broker = new RequestBroker({
    resolve: async () => [PUBLIC_ADDR],
    transport: async () => {
      throw new Error('transport must not be reached for forbidden_header')
    },
  })
  t.after(() => broker.closeTransport())
  await assert.rejects(
    () =>
      broker.executeHttp(
        {
          origin: APP_ORIGIN,
          method: 'GET',
          pathAndQuery: '/api/protected',
          headers: { Authorization: 'Bearer real-secret-token' },
        },
        grant,
        AbortSignal.timeout(5_000),
      ),
    err => err instanceof BrokerDenied && /cannot be set directly/i.test(err.message),
  )
})

test('agent-prompts exposes synthetic invalid auth probe normalization and unauthenticated prompt guidance', () => {
  assert.deepEqual(normalizePiAuthMutation({ kind: 'synthetic_invalid_bearer' }), {
    kind: 'synthetic_invalid_bearer',
  })
  assert.deepEqual(normalizePiAuthMutation({ kind: 'synthetic_invalid_api_key' }), {
    kind: 'synthetic_invalid_api_key',
  })
  assert.deepEqual(
    normalizePiAuthMutation({ kind: 'synthetic_invalid_api_key', headerName: ' X-Auth-Token ' }),
    { kind: 'synthetic_invalid_api_key', headerName: 'X-Auth-Token' },
  )
  assert.match(
    SPECIALIST_PROFILES['auth-session-oauth-specialist'].focusPrompt,
    /synthetic_invalid_bearer.*synthetic_invalid_api_key/,
  )
  assert.match(
    scenarioInstructions['worker-investigation'],
    /synthetic_invalid_bearer.*synthetic_invalid_api_key/,
  )
})
