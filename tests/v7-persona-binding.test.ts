// Persona binding: a request is always served under the declared actor's scope.
//
// The multi-tenant defect this pins: one persona's request was served another tenant's store, so a
// later credential-exposure probe read the wrong tenant's data (costing recall) and a cross-tenant
// claim could have been made from a scope the probe never declared (risking precision). Two
// independent guarantees are asserted here:
//
//  1. Transport isolation — a session jar belongs to exactly one persona. `RequestBroker.executeHttp`
//     receives `req.persona` on every call, so a Set-Cookie rotation is stored against that exact
//     (worker session, group role, persona) key and can never be replayed for another persona, even
//     when a caller hands both personas the same session label.
//  2. Evidence validity — when a persona presents a login-minted session cookie that a *different*
//     persona already used for the same origin, the exchange is flagged (`personaScopeMismatch`), a
//     `broker.persona_scope_mismatch` event is recorded, and differential probes refuse to stage it.
//     A mismatch can never confirm a target.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { RequestBroker, BrokerDenied } from '../src/server/broker.ts'
import type { Grant, PublicAddress, RawHttpResponse } from '../src/server/broker.ts'
import type { SecondOrderStore } from '../src/server/canary-broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { probeDifferential } from '../src/server/surface-engine.ts'
import { floorRecipe, runFloorRecipe } from '../src/server/floor-recipes.ts'

const origin = 'https://tenanta.example'
const publicAddr: PublicAddress = { address: '93.184.216.34', family: 4 }

function persona(handle: string, authKind: ResolvedPersona['authKind'], secret: string): ResolvedPersona {
  return {
    id: `id-${handle}`,
    handle,
    roleLabel: handle,
    originAllowlist: [origin],
    authKind,
    headerName: authKind === 'header' ? 'X-Api-Key' : null,
    secret,
    canaryMarkers: [],
  }
}

function makeGrant(personas: ReadonlyArray<ResolvedPersona>, storage?: SecondOrderStore): Grant {
  return {
    origin,
    tier: 2,
    maxRpsPerOrigin: 50,
    personas: new Map(personas.map(entry => [entry.handle, entry])),
    canRead: (value: string) => value === origin,
    audit: () => {},
    ...(storage ? { storage } : {}),
  }
}

/** A stub origin that records the exact request headers it received and replies with Set-Cookie. */
function recordingTransport() {
  const seen: Array<{ authorization: string | null; cookie: string | null; path: string }> = []
  const transport = async (
    _url: URL,
    _address: PublicAddress,
    _signal: AbortSignal,
    options?: { method?: string; headers?: Record<string, string> },
  ): Promise<RawHttpResponse> => {
    const headers = options?.headers ?? {}
    const authorization = headers.Authorization ?? headers.authorization ?? null
    const cookie = headers.Cookie ?? headers.cookie ?? null
    seen.push({ authorization, cookie, path: _url.pathname })
    // Each token gets its own server-side session handle, exactly like a real login.
    const sid = authorization?.split(' ')[1] ?? 'anon'
    return {
      status: 200,
      headers: { 'content-type': 'application/json', 'set-cookie': [`rb_sid=sess_for_${sid}; Path=/; HttpOnly`] },
      body: JSON.stringify({ store: sid }),
      bodyBytes: 32,
    }
  }
  return { transport, seen }
}

test('a Set-Cookie rotation is scoped to the persona that received it, even under one session label', async () => {
  const { transport, seen } = recordingTransport()
  const broker = new RequestBroker({ resolve: async () => [publicAddr], transport })
  const grant = makeGrant([persona('persona_a', 'bearer', 'token-a'), persona('viewer', 'bearer', 'token-v')])
  const signal = AbortSignal.timeout(30_000)
  // Both personas are handed the SAME session label: the jar key must still separate them.
  const request = (handle: string) => ({
    origin,
    method: 'GET' as const,
    pathAndQuery: '/api/v1/settings',
    persona: handle,
    session: 'shared-label',
  })

  await broker.executeHttp(request('persona_a'), grant, signal)
  await broker.executeHttp(request('persona_a'), grant, signal)
  await broker.executeHttp(request('viewer'), grant, signal)
  await broker.executeHttp(request('viewer'), grant, signal)

  const [a1, a2, v1, v2] = seen
  assert.equal(a1?.cookie, null, 'the first persona_a request has no session yet')
  assert.match(a2?.cookie ?? '', /rb_sid=sess_for_token-a/, 'persona_a reuses its own session cookie')
  assert.equal(v1?.cookie, null, "viewer must never inherit persona_a's rotated session cookie")
  assert.match(v2?.cookie ?? '', /rb_sid=sess_for_token-v/, 'viewer keeps its own session cookie')
  assert.equal(broker.getPersonaScopeMismatches().length, 0, 'isolated jars need no mismatch')
})

test('interleaved personas on one route never observe each other tenant (own store, own claim)', async () => {
  // A stateful origin: the store answered is the store pinned on the *session* the request carried.
  const TENANT_BY_COOKIE = new Map<string, string>([
    ['rb_sid=session_a', 'store-a'],
    ['rb_sid=session_b', 'store-b'],
  ])
  const seen: Array<{ persona: string | null; cookie: string | null; store: string }> = []
  const transport = async (
    _url: URL,
    _address: PublicAddress,
    _signal: AbortSignal,
    options?: { headers?: Record<string, string> },
  ): Promise<RawHttpResponse> => {
    const cookie = options?.headers?.Cookie ?? options?.headers?.cookie ?? null
    // Interleaved act-as: writes pin the *caller's own session* to the requested store.
    const store = (cookie ? TENANT_BY_COOKIE.get(cookie) : null) ?? 'anonymous'
    const body = JSON.stringify({ store })
    seen.push({ persona: null, cookie, store })
    return { status: 200, headers: { 'content-type': 'application/json' }, body, bodyBytes: body.length }
  }
  const broker = new RequestBroker({ resolve: async () => [publicAddr], transport })
  const grant = makeGrant([
    persona('persona_a', 'cookie', 'rb_sid=session_a'),
    persona('persona_b', 'cookie', 'rb_sid=session_b'),
  ])
  const signal = AbortSignal.timeout(30_000)
  const read = async (handle: string) => {
    const exchange = await broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: '/api/v1/settings', persona: handle },
      grant,
      signal,
    )
    return { store: (JSON.parse(exchange.body) as { store: string }).store }
  }

  // A/B/A/B interleaved on the same route in one run.
  const results = [await read('persona_a'), await read('persona_b'), await read('persona_a'), await read('persona_b')]
  assert.deepEqual(results.map(entry => entry.store), ['store-a', 'store-b', 'store-a', 'store-b'])
  // Each persona sent only its own session cookie.
  assert.deepEqual(seen.map(entry => entry.cookie), [
    'rb_sid=session_a', 'rb_sid=session_b', 'rb_sid=session_a', 'rb_sid=session_b',
  ])
  assert.equal(broker.getPersonaScopeMismatches().length, 0, 'no scope disagreement to report')
})

test('a claim from an exchange served another persona scope is evidence-invalid, never TP or FP', async () => {
  // The probe actor's declared tenant is store-a, but its credential is another persona's session
  // (store-b). The origin answers store-b; that answer must never become a finding.
  const TENANT_BY_COOKIE = new Map<string, string>([['rb_sid=session_b', 'store-b']])
  const transport = async (
    _url: URL,
    _address: PublicAddress,
    _signal: AbortSignal,
    options?: { headers?: Record<string, string> },
  ): Promise<RawHttpResponse> => {
    const cookie = options?.headers?.Cookie ?? options?.headers?.cookie ?? null
    const store = (cookie ? TENANT_BY_COOKIE.get(cookie) : null) ?? 'anonymous'
    const body = JSON.stringify({ store, providerKey: `rbs_${store}_96d3cc9d2620` })
    return { status: 200, headers: { 'content-type': 'application/json' }, body, bodyBytes: body.length }
  }
  const broker = new RequestBroker({ resolve: async () => [publicAddr], transport })
  const grant = makeGrant([
    // persona_a declares store-a but was minted persona_b's session (the bleed's signature).
    persona('persona_a', 'cookie', 'rb_sid=session_b'),
    persona('persona_b', 'cookie', 'rb_sid=session_b'),
  ])
  const signal = AbortSignal.timeout(30_000)

  // persona_b legitimately establishes ownership of session_b first.
  await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/api/v1/settings', persona: 'persona_b' }, grant, signal)

  // Now the same login session is presented for persona_a. The broker fails closed, so the wrong
  // tenant is never even fetched — not for a read, and not for a claim drawn from one.
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/api/v1/settings', persona: 'persona_a' }, grant, signal),
    /Persona scope mismatch/,
  )
  assert.equal(broker.getPersonaScopeMismatches().length, 1)

  // The differential path likewise stages nothing: no exchange id, no anomaly, no finding.
  const result = await probeDifferential(
    { origin, pathAndQuery: '/api/v1/settings/1', probeClass: 'path_traversal_benign', persona: 'persona_a' },
    broker, grant, undefined, signal,
  )
  assert.equal(result.verdict, 'inconclusive')
  assert.equal(result.exchangeIds.length, 0, 'evidence-invalid exchanges are never staged')
  assert.equal(result.anomalies.length, 0, 'a scope-mismatched response cannot become an anomaly')
})

test('two personas riding one server-side session raise broker.persona_scope_mismatch and are evidence-invalid', async () => {
  const { transport } = recordingTransport()
  const events: Array<{ kind: string; detail: Record<string, unknown> }> = []
  const storage = {
    event: (_runId: string | null, kind: string, _message: string, detail?: Record<string, unknown>) => {
      events.push({ kind, detail: detail ?? {} })
    },
  } as unknown as SecondOrderStore
  const broker = new RequestBroker({ resolve: async () => [publicAddr], transport })
  // Both personas were minted the same login session (the defect's signature).
  const grant = makeGrant([
    persona('persona_a', 'cookie', 'rb_sid=shared_login_session'),
    persona('viewer', 'cookie', 'rb_sid=shared_login_session'),
    persona('persona_b', 'cookie', 'rb_sid=other_login_session'),
  ], storage)
  const signal = AbortSignal.timeout(30_000)
  const request = (handle: string) => ({ origin, method: 'GET' as const, pathAndQuery: '/api/v1/settings', persona: handle })

  const first = await broker.executeHttp(request('persona_a'), grant, signal)
  assert.equal(first.status, 200, 'the first persona to use a session owns it')

  // The second persona must not be answered from the first persona's session at all.
  await assert.rejects(broker.executeHttp(request('viewer'), grant, signal), /Persona scope mismatch/)
  const mismatches = broker.getPersonaScopeMismatches()
  assert.equal(mismatches.length, 1)
  assert.deepEqual(
    { expected: mismatches[0]?.expected, observed: mismatches[0]?.observed, source: mismatches[0]?.source },
    { expected: 'viewer', observed: 'persona_a', source: 'vault_session:rb_sid' },
  )
  assert.equal(events.filter(event => event.kind === 'broker.persona_scope_mismatch').length, 1)
  assert.equal(events[0]?.detail.expected, 'viewer')
  assert.equal(events[0]?.detail.observed, 'persona_a')

  // A persona with its own session is unaffected, and the record is not sticky.
  const own = await broker.executeHttp(request('persona_b'), grant, signal)
  assert.equal(own.status, 200, 'distinct sessions keep their own scope')
  assert.equal(broker.getPersonaScopeMismatches().length, 1, 'mismatch records are reported once')
})

test('a differential probe refuses to stage a persona-scope-mismatched exchange', async () => {
  const { transport } = recordingTransport()
  const broker = new RequestBroker({ resolve: async () => [publicAddr], transport })
  const grant = makeGrant([
    persona('persona_a', 'cookie', 'rb_sid=shared_login_session'),
    persona('viewer', 'cookie', 'rb_sid=shared_login_session'),
  ])
  const signal = AbortSignal.timeout(30_000)

  // persona_a establishes ownership of the session first.
  await broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/api/v1/settings', persona: 'persona_a' }, grant, signal)

  const result = await probeDifferential({
    origin,
    pathAndQuery: '/api/v1/settings/1',
    probeClass: 'path_traversal_benign',
    persona: 'viewer',
  }, broker, grant, undefined, signal)

  assert.equal(result.verdict, 'inconclusive', 'a scope mismatch can never be a finding')
  assert.equal(result.exchangeIds.length, 0, 'no mismatched exchange is staged as evidence')
  assert.ok(result.notes.some(note => /scope mismatch/i.test(note)), 'the refusal is explained in the probe notes')
})

test('the broker rejects a persona it cannot resolve instead of falling back to ambient scope', async () => {
  const { transport } = recordingTransport()
  const broker = new RequestBroker({ resolve: async () => [publicAddr], transport })
  const grant = makeGrant([persona('persona_a', 'bearer', 'token-a')])
  await assert.rejects(
    broker.executeHttp({ origin, method: 'GET', pathAndQuery: '/api/v1/settings', persona: 'ghost' }, grant, AbortSignal.timeout(5_000)),
    BrokerDenied,
  )
})

test('an identity-assumption proof restores the actor baseline before the next persona probe', async () => {
  // A session-scoped store: an act-as write pins the caller's *session* to the target store, and
  // only a later write carrying the caller's own store puts it back (exactly the shape that made a
  // viewer read another tenant after an authz proof).
  const ACTOR_STORE = 'store-own'
  const TARGET_STORE = 'store-victim'
  const scopeByActor = new Map<string, string>()
  const handle = (req: { actor: { handle: string }; jsonBody?: unknown; role: string }) => {
    const actor = req.actor.handle
    const store = (req.jsonBody as { store?: string } | undefined)?.store
    if (store) {
      scopeByActor.set(actor, store)
      return { status: 200, json: { ok: true, actingAs: store }, body: JSON.stringify({ ok: true }), route: '/api/v1/admin/impersonate' }
    }
    const current = scopeByActor.get(actor) ?? ACTOR_STORE
    return { status: 200, json: { actor, store: current }, body: JSON.stringify({ actor, store: current }), route: '/api/v1/session' }
  }
  const execution = await runFloorRecipe(floorRecipe('persisted_mutation', {
    origin,
    method: 'POST',
    pathAndQuery: '/api/v1/admin/impersonate',
    vulnClass: 'bfla',
    actor: { handle: 'viewer', role: 'viewer', tenant: 'tenant-a', auth: 'cookie' },
    body: { store: TARGET_STORE },
    reset: { body: { store: ACTOR_STORE } },
    baselineMethod: 'GET',
    baselinePathAndQuery: '/api/v1/session',
    readbackMethod: 'GET',
    readbackPathAndQuery: '/api/v1/session',
  }), {
    runId: 'run-v7-persona-binding',
    request: req => handle(req),
    nextExchangeId: (() => { let n = 0; return () => `ex-${++n}` })(),
  })

  assert.equal(execution.result.verification.rule, 'impact')
  assert.equal(scopeByActor.get('viewer'), ACTOR_STORE,
    'the acting scope must be back to the actor own store after the proof')
  assert.ok(execution.result.transcript.entries?.some(entry => entry.evidenceRole === 'state_restore'),
    'the restore is recorded as its own cleanup exchange')
  // The next persona read (a later credential-exposure probe) is served the actor's own tenant.
  const nextRead = handle({ actor: { handle: 'viewer' }, role: 'control' }) as { json: { store: string } }
  assert.equal(nextRead.json.store, ACTOR_STORE, 'the next read by this persona is served its own tenant')
})
