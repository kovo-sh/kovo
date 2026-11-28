/**
 * Track C1 — Unified Principal + Capability Custody Store behavioral tests.
 *
 * Covers:
 *   1. Multi-tenant principal registration & `listLowPrivFirst()` ordering without name regexes.
 *   2. Transparent `indexResponse()` -> `matchRequestValues()` / `lookupHandleByRawValue()` across
 *      raw, URL-encoded, JSON-escaped, and `Bearer `-stripped variants proving automatic cross-tenant
 *      lineage and deduplication against known values.
 *   3. `deriveMutatedCapability()` escape hatch preserving `derivedFromHandle` lineage.
 *   4. `WeakMap` non-serialization (`JSON.stringify` / `util.inspect` leak zero secrets), credential
 *      rotation scrubbing across configured personas, isolated broker sessions, and cloned worker
 *      cookie rotations, plus `runAllRunDisposers(runId)` complete disposal.
 *   5. Scale bound: hundreds of observations and O(1) reverse lookups complete in < 50ms.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { inspect } from 'node:util'
import { IsolatedSessionCache } from '../src/server/broker-session-isolation.ts'
import type { PersonaSessionClone } from '../src/server/persona-auth.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import {
  PrincipalCustodyStore,
  disposePrincipalCustodyStore,
  getOrCreatePrincipalCustodyStore,
  getPrincipalCustodyStore,
} from '../src/server/principal-custody.ts'
import { redact } from '../src/server/redact.ts'
import { runAllRunDisposers } from '../src/server/run-disposers.ts'
import { cloneWorkerPersona } from '../src/server/session-isolation.ts'

function makePersona(overrides: Partial<ResolvedPersona> & { handle: string }): ResolvedPersona {
  return {
    id: `p_${overrides.handle}`,
    roleLabel: overrides.roleLabel ?? 'Account',
    tenantRef: overrides.tenantRef ?? null,
    privilege: overrides.privilege ?? null,
    originAllowlist: overrides.originAllowlist ?? ['https://app.example.test'],
    authKind: overrides.authKind ?? 'bearer',
    headerName: overrides.headerName ?? null,
    secret: overrides.secret ?? `sec_${overrides.handle}_9f8e7d6c5b4a`,
    canaryMarkers: overrides.canaryMarkers ?? [],
    ...overrides,
  }
}

test('C1: multi-tenant principal registration & listLowPrivFirst() ordering without name regexes', () => {
  const store = new PrincipalCustodyStore({ runId: 'run-c1-ordering' })
  // Deliberately opaque handles and labels (no "admin"/"viewer" strings in names) to prove
  // ordering honors structured `privilege` + `configIndex` rather than name regexes.
  const personas = new Map<string, ResolvedPersona>([
    ['acct_01', makePersona({ handle: 'acct_01', roleLabel: 'Slot Alpha', tenantRef: 'tenant-a', privilege: 'owner' })],
    ['acct_02', makePersona({ handle: 'acct_02', roleLabel: 'Slot Beta', tenantRef: 'tenant-b', privilege: 'admin' })],
    ['acct_03', makePersona({ handle: 'acct_03', roleLabel: 'Slot Gamma', tenantRef: 'tenant-a', privilege: 'member' })],
    ['acct_04', makePersona({ handle: 'acct_04', roleLabel: 'Slot Delta', tenantRef: 'tenant-b', privilege: 'viewer' })],
    ['acct_05', makePersona({ handle: 'acct_05', roleLabel: 'Slot Epsilon', tenantRef: 'tenant-a', privilege: 'viewer' })],
  ])

  store.registerPersonas(personas)

  const ordered = store.listLowPrivFirst()
  assert.deepEqual(
    ordered.map(p => [p.handle, p.privilege, p.tenantRef]),
    [
      ['acct_04', 'viewer', 'tenant-b'],
      ['acct_05', 'viewer', 'tenant-a'],
      ['acct_03', 'member', 'tenant-a'],
      ['acct_02', 'admin', 'tenant-b'],
      ['acct_01', 'owner', 'tenant-a'],
    ],
  )

  const tenantAOnly = store.listLowPrivFirst({ tenantRef: 'tenant-a' })
  assert.deepEqual(tenantAOnly.map(p => p.handle), ['acct_05', 'acct_03', 'acct_01'])
  store.dispose()
})

test('C1: transparent indexResponse() -> matchRequestValues() / lookupHandleByRawValue() across variants & cross-tenant lineage', () => {
  const store = new PrincipalCustodyStore({ runId: 'run-c1-autolink' })
  const tenantAToken = 'tok_tenantA_static_778899aabbcc'
  const tenantBToken = 'tok_tenantB_static_112233ddeeff'

  store.registerPersonas(new Map([
    ['actor_a', makePersona({ handle: 'actor_a', roleLabel: 'Tenant A Member', tenantRef: 'tenant-a', privilege: 'member', secret: tenantAToken })],
    ['actor_b', makePersona({ handle: 'actor_b', roleLabel: 'Tenant B Admin', tenantRef: 'tenant-b', privilege: 'admin', secret: tenantBToken })],
  ]))

  const novelCookie = 'sid_b_live+99/88=776655aa'
  const novelBearer = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiX2FkbWluIiwidGVuYW50IjoidGVuYW50LWIifQ.sigB9876543210'
  const novelLocationCode = 'code_b_redirect+44/55=667788'
  const novelJsonTok = 'ext_b_tok/slash"quote_998877'

  const sealed = store.indexResponse({
    hopReceiptId: 'hop1_b',
    origin: 'https://app.example.test',
    ownerHandle: 'actor_b',
    sourceExchangeId: 'ex-101',
    headers: {
      Authorization: `Bearer ${novelBearer}`,
      'Set-Cookie': [
        `session_id=${novelCookie}; Path=/; HttpOnly; SameSite=Lax`,
        'theme=dark; Path=/',
      ],
      Location: `https://app.example.test/callback?access_token=${encodeURIComponent(novelLocationCode)}&page=1`,
    },
    extractions: [
      { slot: 'body_token', rawValue: novelJsonTok, carrier: 'body' },
      // Already-known configured persona token must deduplicate and NOT re-seal.
      { slot: 'dup_persona', rawValue: tenantBToken, carrier: 'body' },
    ],
  })

  assert.equal(sealed.length, 4)
  // Calling indexResponse again with identical novel values deduplicates cleanly.
  const sealedAgain = store.indexResponse({
    hopReceiptId: 'hop2_b',
    origin: 'https://app.example.test',
    ownerHandle: 'actor_b',
    headers: { Authorization: `Bearer ${novelBearer}` },
  })
  assert.equal(sealedAgain.length, 0)

  // 1. Raw cookie value echoed back
  const rawMatch = store.lookupHandleByRawValue(novelCookie)
  assert.equal(rawMatch?.matchType, 'capability')
  assert.equal(rawMatch?.matchedVariant, 'raw')
  assert.equal(rawMatch?.sourceProvenance?.sourceActorTenant, 'tenant-b')
  assert.equal(rawMatch?.sourceProvenance?.sourcePersonaHandle, 'actor_b')
  assert.equal(rawMatch?.capability?.defaultCookieName, 'session_id')

  // 2. Bearer-prefixed lookup strips "Bearer " cleanly
  const bearerMatch = store.lookupHandleByRawValue(`Bearer ${novelBearer}`)
  assert.equal(bearerMatch?.matchType, 'capability')
  assert.equal(bearerMatch?.matchedVariant, 'bearer_stripped')
  assert.equal(bearerMatch?.sourceProvenance?.sourceActorTenant, 'tenant-b')
  assert.ok(store.vault.hasActive(bearerMatch!.capabilityHandle!))

  // 3. URL-encoded variant lookup
  const urlMatch = store.lookupHandleByRawValue(encodeURIComponent(novelLocationCode))
  assert.equal(urlMatch?.matchType, 'capability')
  assert.equal(urlMatch?.matchedVariant, 'url_encoded')
  assert.equal(urlMatch?.sourceProvenance?.sourceActorTenant, 'tenant-b')

  // 4. JSON-escaped variant lookup
  const jsonEscaped = JSON.stringify(novelJsonTok).slice(1, -1)
  const jsonMatch = store.lookupHandleByRawValue(jsonEscaped)
  assert.equal(jsonMatch?.matchType, 'capability')
  assert.equal(jsonMatch?.matchedVariant, 'json_escaped')
  assert.equal(jsonMatch?.sourceProvenance?.sourceActorTenant, 'tenant-b')

  // 5. Full request matching across headers + URL query + JSON body + configured principal token
  const reqMatches = store.matchRequestValues({
    origin: 'https://app.example.test',
    headers: {
      Authorization: `Bearer ${novelBearer}`,
      Cookie: `other=1; session_id=${novelCookie}`,
      'X-Forwarded-Auth': tenantAToken,
    },
    url: `https://app.example.test/api/export?code=${encodeURIComponent(novelLocationCode)}`,
    body: JSON.stringify({ delegated: novelJsonTok }),
  })

  assert.equal(reqMatches.length, 5)
  const tenantsMatched = new Set(reqMatches.map(m => m.sourceProvenance?.sourceActorTenant))
  assert.deepEqual(tenantsMatched, new Set(['tenant-a', 'tenant-b']))

  // Cross-origin restriction on capability handles is respected when targetOrigin differs
  const wrongOriginMatches = store.matchRequestValues({
    origin: 'https://other.example.test',
    headers: { Authorization: `Bearer ${novelBearer}` },
  })
  assert.equal(wrongOriginMatches.length, 0)
  store.dispose()
})

test('C1: deriveMutatedCapability() preserves derivedFromHandle lineage and provenance', () => {
  const store = new PrincipalCustodyStore({ runId: 'run-c1-derive' })
  store.registerPersona(makePersona({
    handle: 'member_a',
    roleLabel: 'Org A Member',
    tenantRef: 'org-a',
    privilege: 'member',
  }), 0)

  const originalJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSIsInJvbGUiOiJtZW1iZXIifQ.origSig1234567890'
  const [baseCap] = store.indexResponse({
    hopReceiptId: 'h1',
    origin: 'https://app.example.test',
    ownerHandle: 'member_a',
    headers: { Authorization: `Bearer ${originalJwt}` },
  })
  assert.ok(baseCap)

  const tamperedJwt = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSIsInJvbGUiOiJhZG1pbiJ9.tamperedSig987654'
  const derived = store.deriveMutatedCapability(baseCap.handle, {
    hopReceiptId: 'h2',
    slot: 'jwt_alg_none',
    rawValue: tamperedJwt,
    kind: 'jwt',
    carrier: 'derived',
  })

  assert.equal(derived.derivedFromHandle, baseCap.handle)
  assert.equal(derived.principalId, baseCap.principalId)
  assert.equal(derived.sourceProvenance?.sourceActorTenant, 'org-a')
  assert.equal(store.vault.getMeta(derived.handle)?.derivedFromCapabilityId, baseCap.handle)

  // Mutated value auto-links back to the derived handle with lineage intact
  const matched = store.lookupHandleByRawValue(`Bearer ${tamperedJwt}`)
  assert.equal(matched?.capabilityHandle, derived.handle)
  assert.equal(matched?.capability?.derivedFromHandle, baseCap.handle)
  assert.equal(matched?.sourceProvenance?.sourcePersonaHandle, 'member_a')
  store.dispose()
})

test('C1: WeakMap non-serialization, rotation scrubbing (isolated + cloned sessions), and runAllRunDisposers() disposal', async () => {
  const runId = 'run-c1-lifecycle-test'
  const store = getOrCreatePrincipalCustodyStore(runId)

  const initialSecret = 'persona_initial_secret_8877665544'
  const rotatedSecret = 'persona_rotated_secret_1122334455'
  const isoSecret = 'isolated_ctrl_bearer_aabbccddeeff'
  const clonedRotatedCookie = 'rotated_clone_sid_99001122334455'
  const sealedRespToken = 'resp_sealed_token_ffeeddccbbaa99'

  const basePersona = makePersona({
    handle: 'member_rot',
    roleLabel: 'Member',
    tenantRef: 'tenant-rot',
    privilege: 'member',
    authKind: 'login',
    secret: initialSecret,
    session: {
      headerType: 'cookie',
      value: `sid=${initialSecret}`,
      adapterUsed: 'json',
      generation: 1,
    },
  })
  store.registerPersona(basePersona, 0)

  // Rotate configured persona credential
  store.registerPersona({
    ...basePersona,
    secret: rotatedSecret,
    secretHistory: [initialSecret],
    session: { headerType: 'cookie', value: `sid=${rotatedSecret}`, adapterUsed: 'json', generation: 2 },
  }, 0)

  // Register isolated broker session via IsolatedSessionCache
  const isoCache = new IsolatedSessionCache()
  await isoCache.getOrMint(
    { runId, sessionKey: 'control:a1:default', personaHandle: 'member_rot', origin: 'https://app.example.test' },
    async () => ({ headers: { Authorization: `Bearer ${isoSecret}` } }),
  )

  // Register cloned worker persona & rotate cookie via clone.applySetCookie
  const fakeClone: PersonaSessionClone = {
    id: 'clone-1',
    handle: 'member_rot',
    runId,
    generation: 2,
    servedGeneration: 2,
    poolGeneration: 2,
    syncServedGeneration: () => 2,
    isLoggedOut: () => false,
    headersFor: () => ({ Cookie: `sid=${rotatedSecret}` }),
    storageFor: () => null,
    cookiesFor: () => [{ name: 'sid', value: rotatedSecret, domain: 'app.example.test', path: '/' }],
    applySetCookie: () => { /* recorded in custody via wrapper */ },
    reportUnauthorized: async () => 'already-fresh',
    logout: () => {},
    dispose: () => {},
  }
  const cloned = cloneWorkerPersona(basePersona, 'assign-1', () => fakeClone, undefined, runId)
  assert.ok(cloned)
  cloned.clone.applySetCookie('https://app.example.test', [`sid=${clonedRotatedCookie}; Path=/; HttpOnly`])

  // Seal a novel response token
  store.indexResponse({
    hopReceiptId: 'hop_sec',
    origin: 'https://app.example.test',
    ownerHandle: 'member_rot',
    headers: { 'X-Auth-Token': sealedRespToken },
  })

  // WeakMap non-serialization invariant: zero raw secrets appear in JSON, inspect, or keys
  const serialized = [
    JSON.stringify(store),
    JSON.stringify(store.vault),
    inspect(store),
    inspect(store.vault),
    JSON.stringify(Object.keys(store)),
  ].join('\n')
  for (const secret of [initialSecret, rotatedSecret, isoSecret, clonedRotatedCookie, sealedRespToken]) {
    assert.equal(serialized.includes(secret), false, `secret leaked in serialized store: ${secret.slice(0, 12)}`)
  }

  // Rotation scrubbing: ALL historical, current, isolated, cloned-rotated, and sealed secrets are scrubbed
  const descriptors = store.scrubDescriptors()
  const sampleText = `init=${initialSecret} rot=${rotatedSecret} iso=${isoSecret} clone=${clonedRotatedCookie} cap=${sealedRespToken}`
  const redacted = redact(sampleText, descriptors)
  for (const secret of [initialSecret, rotatedSecret, isoSecret, clonedRotatedCookie, sealedRespToken]) {
    assert.equal(redacted.includes(secret), false, `secret was not scrubbed: ${secret.slice(0, 12)}`)
  }

  // Cloned & isolated tokens also resolve cleanly via lookupHandleByRawValue
  assert.equal(store.lookupHandleByRawValue(isoSecret)?.handle, 'member_rot')
  assert.equal(store.lookupHandleByRawValue(clonedRotatedCookie)?.handle, 'member_rot')

  // Complete disposal via runAllRunDisposers(runId)
  assert.equal(getPrincipalCustodyStore(runId), store)
  const drain = runAllRunDisposers(runId)
  assert.equal(drain.errors.length, 0)
  assert.equal(getPrincipalCustodyStore(runId), undefined)
  assert.equal(store.listLowPrivFirst({ includeClones: true, includeInactive: true }).length, 0)
  assert.equal(store.vault.list().length, 0)
  assert.equal(store.lookupHandleByRawValue(sealedRespToken), null)
  assert.equal(disposePrincipalCustodyStore(runId), false)
})

test('C1: scale bound — 300 response seals + 300 reverse lookups complete in < 50ms', () => {
  const store = new PrincipalCustodyStore({ runId: 'run-c1-scale' })
  store.registerPersona(makePersona({
    handle: 'scale_user',
    roleLabel: 'Member',
    tenantRef: 'tenant-scale',
    privilege: 'member',
  }), 0)

  const tokens: string[] = []
  const count = 300
  const t0 = performance.now()

  for (let i = 0; i < count; i += 1) {
    const raw = `tok_scale_${i.toString(36).padStart(4, '0')}+x${(i * 7919).toString(16)}/y${(i * 104729).toString(36)}`
    tokens.push(raw)
    store.indexResponse({
      hopReceiptId: `h_${i}`,
      origin: 'https://app.example.test',
      ownerHandle: 'scale_user',
      extractions: [{ slot: 'tok', rawValue: raw, carrier: 'body' }],
    })
  }

  let matchedCount = 0
  for (let i = 0; i < count; i += 1) {
    const tok = tokens[i]!
    const variant = i % 3 === 0 ? tok : i % 3 === 1 ? `Bearer ${tok}` : encodeURIComponent(tok)
    const hit = store.lookupHandleByRawValue(variant, 'https://app.example.test')
    if (hit?.matchType === 'capability') matchedCount += 1
  }

  const elapsedMs = performance.now() - t0
  assert.equal(matchedCount, count)
  assert.ok(elapsedMs < 50, `Expected 300 seals + 300 lookups in < 50ms, took ${elapsedMs.toFixed(2)}ms`)
  store.dispose()
})
