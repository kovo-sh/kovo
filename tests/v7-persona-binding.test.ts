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
  assert.equal(first.personaScopeMismatch, undefined, 'the first persona to use a session owns it')

  const shared = await broker.executeHttp(request('viewer'), grant, signal)
  assert.equal(shared.personaScopeMismatch, true, 'a second persona on the same session is flagged')
  const mismatches = broker.getPersonaScopeMismatches()
  assert.equal(mismatches.length, 1)
  assert.deepEqual(
    { expected: mismatches[0]?.expected, observed: mismatches[0]?.observed, source: mismatches[0]?.source },
    { expected: 'viewer', observed: 'persona_a', source: 'vault_session:rb_sid' },
  )
  assert.equal(events.filter(event => event.kind === 'broker.persona_scope_mismatch').length, 1)
  assert.equal(events[0]?.detail.expected, 'viewer')
  assert.equal(events[0]?.detail.observed, 'persona_a')

  // A persona with its own session is unaffected, and the flag is not sticky.
  const own = await broker.executeHttp(request('persona_b'), grant, signal)
  assert.equal(own.personaScopeMismatch, undefined, 'distinct sessions keep their own scope')
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
