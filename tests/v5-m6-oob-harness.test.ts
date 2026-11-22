// v5 M6: OOB callback wiring for the graded realistic-bench harness.
// The app's contained egress only reaches loopback ports it was started with; the harness must
// create the Guardian canary listener first, pass that exact port to the app, and reuse the same
// broker for SSRF/XXE verification. Unregistered loopback ports must stay blocked.
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { resolveOobCallbackPorts, createEngineEnv } from '../scripts/benchmark-env.ts'
import { profileCaps } from '../scripts/benchmark-probes.ts'
import type { CanaryBroker } from '../src/server/canary-broker.ts'
import {
  runGuardianAgainstMaterialized, startOobCanaryBroker,
} from '../benchmarks/realistic-bench/guardian-adapter.ts'
import type { EngineModuleLike } from '../benchmarks/realistic-bench/guardian-adapter.ts'
import { briefingFor, startRealisticApp } from '../benchmarks/realistic-bench/run.ts'
import { loginPersonas } from '../benchmarks/realistic-bench/guardian-login.ts'
import type { Briefing, SiteMode, StartedApp } from '../benchmarks/realistic-bench/lib/types.ts'
import shopflow from '../benchmarks/realistic-bench/apps/shopflow/index.ts'
import { blueprint as shopflowBlueprint } from '../benchmarks/realistic-bench/apps/shopflow/truth/blueprint.ts'
import { generateVariant } from '../benchmarks/realistic-bench/generator/variant.ts'
import { buildGroundTruth } from '../benchmarks/realistic-bench/generator/groundtruth.ts'

function withLocalLab<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.env.GUARDIAN_ALLOW_LOCAL_LAB
  process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
  return fn().finally(() => {
    if (prev === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    else process.env.GUARDIAN_ALLOW_LOCAL_LAB = prev
  })
}

async function loginPersona(started: StartedApp, briefing: Briefing): Promise<{ cookie?: string; token?: string; headerName?: string }> {
  const loginPath = briefing.apiReference?.find(r => /login|signin|session/i.test(r.routeKey))?.path ?? '/login'
  const login = await loginPersonas(briefing.origin, loginPath, briefing.personas, fetch)
  const persona = login.personas.persona_a ?? Object.values(login.personas)[0]
  assert.ok(persona, `no persona logged in (notes: ${login.notes.join('; ')})`)
  return persona
}

function authHeaders(persona: { cookie?: string; token?: string; headerName?: string }): Record<string, string> {
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  if (persona.cookie) headers.cookie = persona.cookie
  else if (persona.headerName && persona.token) headers[persona.headerName] = persona.token
  else if (persona.token) headers.authorization = `Bearer ${persona.token}`
  return headers
}

test('OOB wiring: a running canary port must be exactly the port the app allows', () => {
  const fake = {
    listenerInfo: () => ({ running: true, host: '127.0.0.1', port: 41234 }),
    startLocalListener: async () => 'http://127.0.0.1:41234',
    stop: async () => undefined,
  } as unknown as CanaryBroker
  assert.deepEqual(resolveOobCallbackPorts(fake, [41234]), [41234])
  assert.deepEqual(resolveOobCallbackPorts(fake, [41234, 41234]), [41234])
  assert.throws(() => resolveOobCallbackPorts(fake, [41235]), /not in oobCallbackPorts/)
  assert.throws(() => resolveOobCallbackPorts(fake, [0]), /exact loopback ports/)
  assert.throws(() => resolveOobCallbackPorts(fake, [70_000]), /exact loopback ports/)
})

test('OOB wiring: registered canary port accepts an SSRF callback; an unregistered port stays blocked', async () => {
  await withLocalLab(async () => {
    const registered = await startOobCanaryBroker()
    const unregistered = await startOobCanaryBroker()
    let started: StartedApp | undefined
    try {
      // opsportal seed 2 has the direct integration SSRF twin vulnerable; the route fetches the
      // supplied URL through the contained egress guard with input taint.
      started = await startRealisticApp({ app: 'opsportal', seed: 2, oobCallbackPorts: [registered.port] })
      const briefing = briefingFor(started, 'grey-box')
      const persona = await loginPersona(started, briefing)
      const route = briefing.apiReference?.find(r => r.routeKey === 'integrationFetch')
      assert.ok(route, 'integration fetch route must be advertised in grey-box mode')
      const path = route.path.replace(/:[A-Za-z0-9_]+/, 'probe')
      const urlParam = started.plan.params.webhookUrl ?? 'url'

      const post = async (url: string) => fetch(`${started!.origin}${path}`, {
        method: 'POST', headers: authHeaders(persona), body: JSON.stringify({ [urlParam]: url }),
      })

      // 1. Registered port: the app's egress allowlist permits the exact loopback callback.
      const allowed = registered.broker as { mintCanary: (runId: string, label: string, origin?: string) => { token: string; httpUrl: string } }
      const mintedAllowed = allowed.mintCanary('oob-test', 'ssrf:registered')
      const allowedRes = await post(mintedAllowed.httpUrl)
      assert.equal(allowedRes.status, 200)
      await new Promise(resolve => setTimeout(resolve, 400))
      const allowedCheck = (registered.broker as { checkCanary: (t: string) => { hit: boolean } }).checkCanary(mintedAllowed.token)
      assert.equal(allowedCheck.hit, true, 'registered canary port must receive the callback')
      const ssrfEvents = started.oracle.events().filter(e => e.kind === 'ssrf_internal_fetch')
      assert.ok(ssrfEvents.some(e => e.routeKey === 'integrationFetch'), 'input-derived callback must emit ssrf_internal_fetch')

      // 2. A listener on a different loopback port is not in the app's allowlist.
      const other = unregistered.broker as { mintCanary: (runId: string, label: string, origin?: string) => { token: string; httpUrl: string } }
      const mintedBlocked = other.mintCanary('oob-test', 'ssrf:unregistered')
      const blockedRes = await post(mintedBlocked.httpUrl)
      assert.equal(blockedRes.status, 200)
      await new Promise(resolve => setTimeout(resolve, 400))
      assert.equal(
        (unregistered.broker as { checkCanary: (t: string) => { hit: boolean } }).checkCanary(mintedBlocked.token).hit,
        false,
        'unregistered loopback port must be blocked',
      )
      const egress = started.oracle.egress()
      assert.ok(egress.some(e => !e.allowed && e.reason === `port_blocked:${unregistered.port}`), 'blocked callback must be logged with the exact port')
      assert.equal(started.oracle.events().filter(e => e.kind === 'ssrf_internal_fetch').length, ssrfEvents.length)
    } finally {
      if (started) await started.stop()
      await registered.stop().catch(() => undefined)
      await unregistered.stop().catch(() => undefined)
    }
  })
})

test('OOB wiring: a simulated OOB callback correlates to its Guardian token', async () => {
  const oob = await startOobCanaryBroker()
  try {
    const broker = oob.broker as {
      mintCanary: (runId: string, label: string, origin?: string) => { token: string; httpUrl: string }
      checkCanary: (token: string) => { found: boolean; hit: boolean; hits: Array<{ protocol: string }> }
    }
    const minted = broker.mintCanary('oob-test', 'manual-correlation')
    assert.equal(broker.checkCanary(minted.token).hit, false)
    const res = await fetch(minted.httpUrl)
    assert.equal(res.status, 200)
    await new Promise(resolve => setTimeout(resolve, 100))
    const check = broker.checkCanary(minted.token)
    assert.equal(check.found, true)
    assert.equal(check.hit, true)
    assert.equal(check.hits[0]?.protocol, 'http')
  } finally {
    await oob.stop()
  }
})

test('OOB wiring: createEngineEnv reuses the caller broker and does not stop it', async () => {
  await withLocalLab(async () => {
    const oob = await startOobCanaryBroker()
    try {
      const env = await createEngineEnv(
        { origin: 'http://127.0.0.1:9', port: 9, personas: {}, close: async () => undefined },
        profileCaps('v4-full'),
        'oob-test',
        { canaryBroker: oob.broker as CanaryBroker, oobCallbackPorts: [oob.port] },
      )
      try {
        assert.equal(env.canaryBroker, oob.broker)
        assert.deepEqual(env.oobCallbackPorts, [oob.port])
        assert.equal(env.grant.canaryBroker, oob.broker, 'grant and probes must share the same broker')
      } finally {
        await env.cleanup()
      }
      const broker = oob.broker as { listenerInfo: () => { running: boolean; port: number | null } }
      assert.equal(broker.listenerInfo().running, true, 'caller-owned broker must survive env cleanup')
      assert.equal(broker.listenerInfo().port, oob.port)
    } finally {
      await oob.stop()
    }
  })
})

test('OOB wiring exposes no listener secret material', async () => {
  const oob = await startOobCanaryBroker()
  try {
    assert.deepEqual(Object.keys(oob).sort(), ['broker', 'port', 'stop'])
    const broker = oob.broker as {
      listenerInfo: () => Record<string, unknown>
      mintCanary: (runId: string, label: string) => { token: string; httpUrl: string }
    }
    const minted = broker.mintCanary('oob-test', 'leak-check')
    const surface = JSON.stringify({ port: oob.port, handleKeys: Object.keys(oob), base: broker.listenerInfo().localBaseUrl })
    assert.doesNotMatch(surface, /secret|guardian-canary-[a-f0-9]{24}/i, 'the wiring handle exposes neither the signing secret nor a minted token')
    assert.equal(typeof oob.port, 'number')
    assert.equal(new URL(minted.httpUrl).port, String(oob.port))
  } finally {
    await oob.stop()
  }
})

test('OOB wiring: adapter forwards the same broker and never serializes persona secrets', async () => {
  await withLocalLab(async () => {
    const sentinel = 'rb-persona-password-leak-sentinel'
    const treeDir = mkdtempSync(join(tmpdir(), 'oob-adapter-'))
    mkdirSync(treeDir, { recursive: true })
    writeFileSync(join(treeDir, 'variant.json'), JSON.stringify({
      app: 'acme-saas', apiPrefix: '/api', idFormat: 'int',
      routes: { login: { method: 'POST', path: '/api/auth/login' } }, params: {},
    }))
    let captured: unknown
    let cleaned = 0
    let oobStops = 0
    const env = { probeEnv: { origin: 'http://127.0.0.1:49160' }, requestsUsed: () => 0, cleanup: async () => { cleaned += 1 } }
    const engine: EngineModuleLike = {
      profileCaps: () => ({ mode: 'v4-full', tier: 3, inlineRetries: 0 }),
      createEngineEnv: async (_h, _c, _l, opts) => { captured = opts; return env },
      discoverEndpoints: async () => [],
      formHypotheses: () => ({ hypotheses: [], encodingSkips: [] }),
      runHypothesis: async () => ({ hyp: { key: 'none' } as never, verdict: 'no_signal', anomalies: [], csrfRejected: false, contextReset: false, tierBlocked: false }),
      synthesizeSpec: () => null,
      selectVerifierBackend: async () => ({ kind: 'local-jq', backend: {} }),
      verifyReplaySpec: async () => ({ verdict: 'confirmed' }),
    }
    const oob = { port: 45_551, broker: { tag: 'shared-broker' }, stop: async () => { oobStops += 1 } }
    const started = {
      app: 'acme-saas', origin: 'http://127.0.0.1:49160', sourceDir: treeDir,
      plan: {
        seed: 1, routes: { login: { method: 'POST', path: '/api/auth/login' } }, params: {},
        personas: { persona_a: { id: 'persona_a', email: 'a@example.test', password: sentinel, tenant: 't1', role: 'owner' } },
      },
      stop: async () => undefined,
    }
    try {
      const result = await runGuardianAgainstMaterialized({
        treeDir, seed: 1, app: 'acme-saas', profileMode: 'v4-full', verifierBackend: 'local-jq', started, oobCanary: oob,
      }, {
        loadEngine: async () => engine,
        briefing: () => ({ origin: started.origin, mode: 'grey-box', personas: [], apiReference: [] }),
        fetchImpl: (async () => new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })) as unknown as typeof fetch,
      })
      assert.deepEqual(captured, { canaryBroker: oob.broker, oobCallbackPorts: [oob.port] })
      assert.equal(cleaned, 1)
      assert.equal(oobStops, 0, 'caller keeps ownership of the OOB broker')
      const blob = JSON.stringify(result)
      assert.doesNotMatch(blob, new RegExp(sentinel), 'persona passwords must never reach result artefacts')
    } finally {
      rmSync(treeDir, { recursive: true, force: true })
    }
  })
})

async function startShopflowWithModes(seed: number, modes: Record<string, SiteMode>, oobPort: number): Promise<StartedApp> {
  const plan = generateVariant(shopflowBlueprint, seed)
  for (const [id, mode] of Object.entries(modes)) plan.sites[id] = mode
  return shopflow.start({
    plan,
    groundTruth: buildGroundTruth(shopflowBlueprint, plan),
    oobCallbackPorts: [oobPort],
  })
}

function canaryApi(broker: unknown) {
  return broker as {
    mintCanary: (runId: string, label: string, origin?: string) => { token: string; httpUrl: string }
    checkCanary: (token: string) => { hit: boolean }
  }
}

test('app OOB realism: vulnerable SSRF/XXE twins reach the registered loopback port and fire the oracle', async () => {
  await withLocalLab(async () => {
    const oob = await startOobCanaryBroker()
    let started: StartedApp | undefined
    try {
      started = await startShopflowWithModes(2, {
        'product-image-ssrf': 'vulnerable',
        'shipping-label-ssrf': 'vulnerable',
        'product-feed-xxe': 'vulnerable',
      }, oob.port)
      const briefing = briefingFor(started, 'grey-box')
      const persona = await loginPersona(started, briefing)
      const headers = authHeaders(persona)
      const broker = canaryApi(oob.broker)
      const post = (path: string, body: string, extra: Record<string, string> = {}) =>
        fetch(`${started!.origin}${path}`, { method: 'POST', headers: { ...headers, ...extra }, body })

      const image = broker.mintCanary('app-oob', 'product-image')
      const imagePath = started.plan.routes.importProductImage!.path.replace(/:[A-Za-z0-9_]+/, '1')
      assert.equal((await post(imagePath, JSON.stringify({ imageUrl: image.httpUrl }))).status, 202)

      const label = broker.mintCanary('app-oob', 'shipping-label')
      const labelPath = started.plan.routes.importShippingLabel!.path
      assert.equal((await post(labelPath, JSON.stringify({ templateUrl: label.httpUrl, raw: '' }))).status, 200)

      const xxe = broker.mintCanary('app-oob', 'product-feed-xxe')
      const xxePath = started.plan.routes.importProductFeed!.path
      const xml = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "${xxe.httpUrl}">]><root><note>&gxxe;</note></root>`
      assert.equal((await post(xxePath, xml, { 'content-type': 'application/xml' })).status, 200)

      await new Promise(resolve => setTimeout(resolve, 500))
      assert.equal(broker.checkCanary(image.token).hit, true, 'product-image SSRF must reach the registered OOB port')
      assert.equal(broker.checkCanary(label.token).hit, true, 'shipping-label SSRF must reach the registered OOB port')
      assert.equal(broker.checkCanary(xxe.token).hit, true, 'product-feed XXE must reach the registered OOB port')
      const events = started.oracle.events()
      assert.ok(events.some(e => e.kind === 'ssrf_internal_fetch' && e.routeKey === 'importProductImage'))
      assert.ok(events.some(e => e.kind === 'ssrf_internal_fetch' && e.routeKey === 'importShippingLabel'))
      assert.ok(events.some(e => e.kind === 'xxe_entity_resolved' && e.routeKey === 'importProductFeed'))
    } finally {
      if (started) await started.stop()
      await oob.stop().catch(() => undefined)
    }
  })
})

test('app OOB realism: opsportal saved webhook fetch fires from the ping trigger', async () => {
  await withLocalLab(async () => {
    const oob = await startOobCanaryBroker()
    let started: StartedApp | undefined
    try {
      started = await startRealisticApp({ app: 'opsportal', seed: 2, oobCallbackPorts: [oob.port] })
      const briefing = briefingFor(started, 'grey-box')
      const persona = await loginPersona(started, briefing)
      const headers = authHeaders(persona)
      const broker = canaryApi(oob.broker)
      const minted = broker.mintCanary('app-oob', 'webhook-ssrf')
      const urlField = started.plan.params['webhookUrl'] ?? 'url'
      const createPath = started.plan.routes['webhookCreate']!.path
      const created = await fetch(`${started.origin}${createPath}`, {
        method: 'POST', headers, body: JSON.stringify({ [urlField]: minted.httpUrl }),
      })
      assert.equal(created.status, 200)
      const createdBody = await created.json() as { id?: string }
      assert.ok(createdBody.id)
      const triggerPath = started.plan.routes['webhookTest']!.path.replace(/:[A-Za-z0-9_]+/, encodeURIComponent(createdBody.id!))
      assert.equal((await fetch(`${started.origin}${triggerPath}`, { method: 'POST', headers, body: '{}' })).status, 200)
      await new Promise(resolve => setTimeout(resolve, 400))
      assert.equal(broker.checkCanary(minted.token).hit, true)
      assert.ok(started.oracle.events().some(e => e.kind === 'ssrf_internal_fetch' && e.routeKey === 'webhookTest'))
    } finally {
      if (started) await started.stop()
      await oob.stop().catch(() => undefined)
    }
  })
})

test('app OOB realism: hardened SSRF/XXE twins stay silent on the same loopback callback', async () => {
  await withLocalLab(async () => {
    const oob = await startOobCanaryBroker()
    let started: StartedApp | undefined
    try {
      started = await startShopflowWithModes(2, {
        'product-image-ssrf': 'hardened',
        'shipping-label-ssrf': 'hardened',
        'product-feed-xxe': 'hardened',
      }, oob.port)
      const briefing = briefingFor(started, 'grey-box')
      const persona = await loginPersona(started, briefing)
      const headers = authHeaders(persona)
      const broker = canaryApi(oob.broker)
      const post = (path: string, body: string, extra: Record<string, string> = {}) =>
        fetch(`${started!.origin}${path}`, { method: 'POST', headers: { ...headers, ...extra }, body })

      const image = broker.mintCanary('app-oob', 'hardened-product-image')
      const imagePath = started.plan.routes.importProductImage!.path.replace(/:[A-Za-z0-9_]+/, '1')
      await post(imagePath, JSON.stringify({ imageUrl: image.httpUrl }))
      const label = broker.mintCanary('app-oob', 'hardened-shipping-label')
      await post(started.plan.routes.importShippingLabel!.path, JSON.stringify({ templateUrl: label.httpUrl, raw: '' }))
      const xxe = broker.mintCanary('app-oob', 'hardened-xxe')
      const xml = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY gxxe SYSTEM "${xxe.httpUrl}">]><root><note>&gxxe;</note></root>`
      await post(started.plan.routes.importProductFeed!.path, xml, { 'content-type': 'application/xml' })

      await new Promise(resolve => setTimeout(resolve, 400))
      assert.equal(broker.checkCanary(image.token).hit, false)
      assert.equal(broker.checkCanary(label.token).hit, false)
      assert.equal(broker.checkCanary(xxe.token).hit, false)
      const events = started.oracle.events()
      assert.equal(events.filter(e => e.kind === 'ssrf_internal_fetch' || e.kind === 'xxe_entity_resolved').length, 0)
      assert.equal(started.oracle.egress().filter(e => e.allowed).length, 0, 'hardened twins must not reach any egress target')
    } finally {
      if (started) await started.stop()
      await oob.stop().catch(() => undefined)
    }
  })
})
