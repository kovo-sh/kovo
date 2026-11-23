/**
 * v5.1 held-out gap: wordlist switch, lossless declared-surface ingestion, structural hints.
 *
 * The dev→held-out gap was traced to three causes: conventional noun/action wordlists inflating
 * dev, declared grey-box routes being dropped before the deterministic engine, and English
 * route-name triggers standing in for structural evidence. These tests pin the generic behaviour:
 * no app, fixture route, seed or benchmark literal is consulted.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'

import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { parseRealisticArgs } from '../scripts/benchmark-realistic.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  collapseRouteVariants,
  conventionalWordlistEnabled,
  engineWordlistSurface,
} from '../src/server/deterministic-engine.ts'
import type { EngineEndpoint } from '../src/server/deterministic-engine.ts'
import {
  harvestAllowMethods,
  harvestTolerantOpenApiOperations,
  harvestValidationFieldHints,
  ingestDeclaredApiSurface,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import type { Grant } from '../src/server/broker.ts'
import { synthesizeEngineSpecs } from '../src/server/deterministic-specs.ts'
import { makeLabGrant, makeStore, setupApprovedRun, startHttpFixture, withEnv } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const origin = 'http://127.0.0.1:4100'

function endpoint(over: Partial<EngineEndpoint> & Pick<EngineEndpoint, 'method' | 'pathTemplate'>): EngineEndpoint {
  return { id: `${over.method}:${over.pathTemplate}`, origin, params: [], riskScore: 40, ...over }
}

describe('conventional wordlist switch', () => {
  test('defaults ON for local-lab compatibility', () => {
    assert.equal(conventionalWordlistEnabled({}), true)
    assert.equal(conventionalWordlistEnabled({ GUARDIAN_CONVENTIONAL_WORDLIST: '' }), true)
    assert.equal(conventionalWordlistEnabled({ GUARDIAN_CONVENTIONAL_WORDLIST: 'on' }), true)
  })

  test('explicit OFF values disable only wordlist-only endpoints', () => {    for (const value of ['0', 'off', 'false', 'no', ' OFF ']) {
      assert.equal(conventionalWordlistEnabled({ GUARDIAN_CONVENTIONAL_WORDLIST: value }), false, value)
    }
    const surface = [
      endpoint({ method: 'GET', pathTemplate: '/api/declared', source: 'openapi' }),
      endpoint({ method: 'GET', pathTemplate: '/api/wordlist', source: 'conventional' }),
    ]
    assert.deepEqual(engineWordlistSurface(surface, true).map(e => e.pathTemplate), ['/api/declared', '/api/wordlist'])
    assert.deepEqual(engineWordlistSurface(surface, false).map(e => e.pathTemplate), ['/api/declared'])
  })

  test('the product harness flag records the effective switch', () => {
    const off = parseRealisticArgs(['--app', 'acme-saas', '--no-conventional-wordlist'], {})
    assert.equal(off.conventionalWordlist, false)
    const on = parseRealisticArgs(['--app', 'acme-saas'], {})
    assert.equal(on.conventionalWordlist, true)
  })

  test('renamed placeholders of one route collapse to a single triage endpoint', () => {
    const variants = [
      endpoint({ id: 'a', method: 'PATCH', pathTemplate: '/api/ledger/:entryId', params: [{ name: 'entryId', location: 'path' }], source: 'openapi' }),
      endpoint({ id: 'b', method: 'PATCH', pathTemplate: '/api/ledger/:id', params: [{ name: 'id', location: 'path' }], source: 'surface_probe' }),
      endpoint({ id: 'c', method: 'GET', pathTemplate: '/api/ledger/{entryId}', params: [] }),
      endpoint({ id: 'd', method: 'GET', pathTemplate: '/api/ledger', params: [{ name: 'q', location: 'query' }] }),
    ]
    const collapsed = collapseRouteVariants(variants)
    assert.equal(collapsed.length, 3, 'one PATCH detail, one GET detail, one collection')
    const patch = collapsed.find(item => item.method === 'PATCH')
    assert.equal(patch?.id, 'a')
    const getDetail = collapsed.find(item => item.method === 'GET' && /[:{]/.test(item.pathTemplate))
    assert.ok(getDetail, 'GET detail variant kept')
  })
})

describe('lossless declared API-reference ingestion', () => {
  test('keeps DELETE, PATCH and body-only POST with declared methods, deduped', (t: TestContext) => {
    const { storage } = makeStore(t, 'guardian-heldout-gap-')
    const project = storage.createProject({
      requestId: randomUUID(),
      name: 'declared surface',
      seeds: ['http://127.0.0.1:4100'],
      environment: 'local-lab',
    })
    const run = storage.createRun({
      requestId: randomUUID(),
      projectId: project.id,
      goal: 'declared surface ingestion',
      sourceMode: 'public',
      capabilityTier: 3,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [],
      budgetUsd: 5,
      budgetRequests: 200,
      maxRpsPerOrigin: 10,
      workerConcurrency: 1,
      workerMaxTurns: 4,
      multiTrialEnabled: false,
    })
    const doc = {
      openapi: '3.1.0',
      info: { title: 'ref', version: '1' },
      paths: {
        '/api/resources': {
          get: { parameters: [{ name: 'q', in: 'query', schema: { type: 'string' } }] },
          post: {
            requestBody: {
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { displayName: { type: 'string' } } },
                },
              },
            },
          },
        },
        '/api/resources/{resourceId}': {
          patch: {
            parameters: [{ name: 'resourceId', in: 'path', schema: { type: 'string' } }],
            requestBody: {
              content: { 'application/json': { schema: { type: 'object', properties: { role: { type: 'string' } } } } },
            },
          },
          delete: { parameters: [{ name: 'resourceId', in: 'path', schema: { type: 'string' } }] },
        },
        '/api/actions/settle': { post: {} },
      },
    }
    storage.importProjectSpec({
      requestId: randomUUID(),
      projectId: project.id,
      name: 'ref.json',
      kind: 'openapi',
      origin,
      content: JSON.stringify(doc),
    })

    const first = ingestDeclaredApiSurface({
      storage,
      runId: run.id,
      scopeRevision: storage.run(run.id).scopeRevision,
      origin,
    })
    assert.equal(first.specs, 1)
    assert.equal(first.endpoints, 5, `declared operations ingested (${JSON.stringify(first.methods)})`)
    assert.equal(first.methods.DELETE, 1)
    assert.equal(first.methods.PATCH, 1)
    assert.equal(first.methods.POST, 2)

    const endpoints = storage.listEndpoints(run.id, { origin })
    const keys = new Set(endpoints.map(e => `${e.method}:${e.pathTemplate}`))
    for (const key of [
      'GET:/api/resources', 'POST:/api/resources', 'PATCH:/api/resources/{resourceId}',
      'DELETE:/api/resources/{resourceId}', 'POST:/api/actions/settle',
    ]) assert.ok(keys.has(key), `declared route preserved: ${key}`)

    const params = storage.listEndpointParams(run.id)
    const bodyOnly = endpoints.find(e => e.method === 'POST' && e.pathTemplate === '/api/actions/settle')
    assert.ok(bodyOnly, 'body-only write route is not dropped for lack of a known field')
    assert.ok(
      params.some(p => p.name === 'displayName'),
      'request-body schema fields are recorded without an id segment',
    )

    const second = ingestDeclaredApiSurface({
      storage,
      runId: run.id,
      scopeRevision: storage.run(run.id).scopeRevision,
      origin,
    })
    assert.equal(second.endpoints, 0, 're-ingestion is deduped by (origin, METHOD, pathTemplate)')
    assert.equal(storage.listEndpoints(run.id, { origin }).length, endpoints.length)
  })

  test('tolerant scan keeps declared operations when the stored reference is unparseable', () => {
    const raw = JSON.stringify({
      openapi: '3.1.0',
      paths: {
        '/api/ledger': { get: { parameters: [{ name: 'q', in: 'query' }] }, post: {} },
        '/api/ledger/:entryId': { patch: {}, delete: {} },
      },
    }).replace('"openapi"', '"\u0001openapi"')
    assert.throws(() => JSON.parse(raw), 'fixture must be invalid JSON')
    const ops = harvestTolerantOpenApiOperations(raw)
    const keys = new Set(ops.map(op => `${op.method}:${op.pathTemplate}`))
    assert.ok(keys.has('GET:/api/ledger'))
    assert.ok(keys.has('POST:/api/ledger'))
    assert.ok(keys.has('PATCH:/api/ledger/:entryId'))
    assert.ok(keys.has('DELETE:/api/ledger/:entryId'))
    const get = ops.find(op => op.method === 'GET' && op.pathTemplate === '/api/ledger')
    assert.ok(get?.params.some(param => param.name === 'q' && param.location === 'query'))
    const patch = ops.find(op => op.method === 'PATCH')
    assert.ok(patch?.params.some(param => param.name === 'entryId' && param.location === 'path'))
  })

  test('Allow headers and validation bodies expose methods and field names passively', () => {
    assert.deepEqual(harvestAllowMethods({ allow: 'GET, POST, DELETE, OPTIONS' }), ['GET', 'POST', 'DELETE'])
    assert.deepEqual(harvestAllowMethods({ Allow: 'PATCH' }), ['PATCH'])
    assert.deepEqual(harvestAllowMethods({}), [])
    const hints = harvestValidationFieldHints(JSON.stringify({
      errors: [{ field: 'displayName' }, { path: 'settings.theme' }],
    }))
    assert.ok(hints.includes('displayName'))
    assert.ok(hints.includes('theme'))
    const textHints = harvestValidationFieldHints('accountEmail is required')
    assert.ok(textHints.includes('accountEmail'))
    assert.ok(!textHints.some(hint => /\/|`|\s/.test(hint)), 'only bare identifiers are learned')
  })

  test('structural intent selection is schema-valid for auth-protocol and webhook proofs', () => {
    const surface = endpoint({ method: 'GET', pathTemplate: '/api/session' })
    const authz = synthesizeEngineSpecs({
      key: 'auth', endpoint: surface, probeClass: 'auth_protocol_audit', intent: 'auth_protocol',
      method: 'GET', pathAndQuery: '/api/session', ownerPersona: 'persona-a', risk: 60,
    }, {
      probeClass: 'auth_protocol_audit', origin, pathAndQuery: '/api/session', verdict: 'signal',
      summary: 'jwt', anomalies: [{ type: 'jwt_auth_mutation_bypass', mutation: 'alg_none', status: 200 }],
      details: {}, requestsSent: 4, exchangeIds: [], stoppedReason: null, notes: [], durationMs: 1,
    })
    assert.equal(authz.length, 1)
    assert.equal(authz[0]!.vulnClass, 'jwt')
    assert.equal(authz[0]!.spec.kind, 'auth_protocol_proof')
    assert.doesNotThrow(() => declarativeReplaySpecSchema.parse(authz[0]!.spec))

    const receiver = endpoint({ method: 'POST', pathTemplate: '/api/events/receive' })
    const webhook = synthesizeEngineSpecs({
      key: 'wh', endpoint: receiver, probeClass: 'webhook_signature_bypass', intent: 'webhook',
      method: 'POST', pathAndQuery: '/api/events/receive', ownerPersona: 'persona-a',
      webhookBody: { event: 'guardian.verification' }, risk: 60,
    }, {
      probeClass: 'webhook_signature_bypass', origin, pathAndQuery: '/api/events/receive', verdict: 'signal',
      summary: 'accepted', anomalies: [{
        type: 'webhook_signature_bypass', headerName: 'x-signature', proof: 'acceptance',
        controlStatus: 401, acceptedStatus: 200,
      }],
      details: {}, requestsSent: 3, exchangeIds: [], stoppedReason: null, notes: [], durationMs: 1,
    })
    assert.equal(webhook.length, 1)
    assert.equal(webhook[0]!.vulnClass, 'webhook_forgery')
    assert.equal(webhook[0]!.spec.kind, 'http_chain')
    assert.doesNotThrow(() => declarativeReplaySpecSchema.parse(webhook[0]!.spec))
  })
})

describe('response-driven sibling derivation', () => {
  test('an observed collection yields GET/PATCH/DELETE <collection>/:id without noun assumptions', async (t: TestContext) => {
    const fx = await startHttpFixture(t, (req, _body, res) => {
      const url = req.url ?? '/'
      if ((req.method ?? 'GET').toUpperCase() === 'OPTIONS' && url.startsWith('/api/things/')) {
        res.statusCode = 204
        res.setHeader('Allow', 'GET, PATCH, DELETE, OPTIONS')
        res.end()
        return
      }
      if (url === '/') {
        res.setHeader('Content-Type', 'text/html')
        res.end('<html><body><a href="/api/things">things</a></body></html>')
        return
      }
      if (url === '/api/things') {
        res.setHeader('Content-Type', 'application/json')
        res.end(JSON.stringify({ items: [{ id: 'k-1', label: 'first' }, { id: 'k-2', label: 'second' }] }))
        return
      }
      res.statusCode = 404
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: 'not found' }))
    })

    const { storage } = makeStore(t, 'guardian-heldout-gap-sibling-')
    const setup = await setupApprovedRun(storage, { seeds: [fx.origin], budgetRequests: 900 })
    const grant: Grant = makeLabGrant(fx.origin, { tier: 1 })

    await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1', GUARDIAN_RECON_SIBLINGS: '1' }, () => runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 1,
      origins: [fx.origin],
      budgetRequests: 900,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant,
      signal: AbortSignal.timeout(30_000),
    }))

    const endpoints = storage.listEndpoints(setup.runId, { origin: fx.origin })
    const sibling = (method: string) => endpoints.find(e =>
      e.method === method && e.pathTemplate === '/api/things/:id')
    assert.ok(sibling('GET'), 'GET sibling derived from the observed collection')
    assert.ok(sibling('PATCH'), 'PATCH sibling derived for the same object template')
    assert.ok(sibling('DELETE'), 'DELETE sibling derived for the same object template')

    // Recon only records the sibling surface: it never issues a PATCH/DELETE from discovery.
    const writeRequests = fx.requests.filter(request =>
      ['PATCH', 'DELETE', 'PUT', 'POST'].includes((request.method ?? 'GET').toUpperCase()) &&
      (request.url ?? '').startsWith('/api/things'))
    assert.deepEqual(writeRequests, [], 'no write probe is issued from recon')
  })
})
