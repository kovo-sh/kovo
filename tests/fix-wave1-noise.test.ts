/**
 * Regression suite for P0 #3a, P0 #3b, P1 #4b, and P1 #5a:
 * - P0 #3a: Exclude static CDN asset extensions/prefixes & anonymous personas from `hyp_rt_cache` cache-bleed hypotheses
 * - P0 #3b: Stop minting fake `POST /_actions/<fn>` routes for Next.js `"use server"` functions; record metadata hints instead
 * - P1 #4b: Multi-repo mounted workspaces attach real bounded `phase0.code_slices` (`code_slices_attached > 0`)
 * - P1 #5a: Phase-0 uniform edge-protection wall fingerprinting (Vercel Deployment Protection 401, Cloudflare Access 302/403)
 *           fast-fails edge-walled hosts, records `edgeProtectedOrigins`, and emits `phase0.edge_protected` without hurting siblings
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import type { TestContext } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import type { BrokerExchangeResult, BrokerHttpRequest, Grant } from '../src/server/broker.ts'
import {
  inferRuntimeInvariantHypotheses,
} from '../src/server/invariant-synthesizer.ts'
import {
  extractStaticFrameworkRoutes,
  runPhase0Recon,
} from '../src/server/phase0-recon.ts'
import { makeLabGrant, makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

function makeTempDir(t: TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function writeTree(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const full = join(root, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content, 'utf8')
  }
}

function makeMultiOriginGrant(origins: readonly string[], tier: 0 | 1 | 2 = 2): Grant {
  const allowed = new Set(origins.map(o => new URL(o).origin))
  return {
    runId: 'test-wave1-noise',
    scopeRevision: 1,
    tier,
    allowLocalLab: true,
    canRead(origin: string) {
      try { return allowed.has(new URL(origin).origin) } catch { return false }
    },
    canWrite(origin: string) {
      try { return allowed.has(new URL(origin).origin) } catch { return false }
    },
    canUseAuth() { return true },
    audit() { /* noop */ },
  } as unknown as Grant
}

function makeExchange(
  req: BrokerHttpRequest,
  status: number,
  mediaType: string,
  body: string,
  seq: number,
  extra?: {
    respHeaders?: Record<string, string>
    finalOrigin?: string
    finalPathAndQuery?: string
    redirectOrigins?: string[]
    redirectPaths?: string[]
  },
): BrokerExchangeResult {
  return {
    id: `ex-${seq}`,
    origin: req.origin,
    method: req.method,
    pathAndQuery: req.pathAndQuery,
    status,
    mediaType,
    respHeaders: { 'content-type': mediaType, ...(extra?.respHeaders ?? {}) },
    reqHeaders: req.headers ?? {},
    body,
    bodyPreview: body.slice(0, 512),
    bodySha256: '0'.repeat(64),
    truncated: false,
    elapsedMs: 1,
    redirectPaths: extra?.redirectPaths ?? [],
    redirectOrigins: extra?.redirectOrigins ?? [req.origin],
    finalOrigin: extra?.finalOrigin ?? req.origin,
    finalPathAndQuery: extra?.finalPathAndQuery ?? req.pathAndQuery,
    personaHandle: req.persona ?? null,
    createdAt: Date.now(),
  } as unknown as BrokerExchangeResult
}

describe('P0 #3a: Eliminate Wave-1 CDN static-asset & anonymous cache-bleed spam', () => {
  test('all static asset extensions, static prefixes, and anonymous personas are excluded from hyp_rt_cache', () => {
    const cacheHeaders = { 'Cache-Control': 'public, max-age=31536000', 'X-Cache': 'HIT' }
    const staticPaths = [
      '/logo.png',
      '/icons/arrow.svg',
      '/hero.jpg',
      '/photo.jpeg',
      '/banner.webp',
      '/spinner.gif',
      '/favicon.ico',
      '/bundle.css',
      '/app.js',
      '/chunk.mjs',
      '/app.js.map',
      '/fonts/inter.woff',
      '/fonts/inter.woff2',
      '/fonts/mono.ttf',
      '/fonts/legacy.eot',
      '/pic.avif',
      '/intro.mp4',
      '/clip.webm',
      '/terms.pdf',
      '/robots.txt',
      '/sitemap.xml',
      '/_next/static/chunks/main-1234.js',
      '/_next/image?url=%2Fhero.png&w=640&q=75',
      '/static/logo',
      '/assets/brand/mark',
      '/images/cover',
      '/fonts/sans',
      '/favicon',
    ]

    const result = inferRuntimeInvariantHypotheses({
      mode: 'grey-box',
      personaObservations: [
        ...staticPaths.map(path => ({
          persona: 'user_a',
          surface: 'cdn' as const,
          serviceOrigin: 'https://cdn.app.test',
          method: 'GET',
          path,
          status: 200,
          responseHeaders: cacheHeaders,
        })),
        ...['anonymous', 'anon', 'ANONYMOUS', 'unauthenticated', '', '   '].map((persona, i) => ({
          persona,
          surface: 'http' as const,
          serviceOrigin: 'https://api.app.test',
          method: 'GET',
          path: `/api/public-${i}`,
          status: 200,
          responseHeaders: cacheHeaders,
        })),
        // Non-static API routes under /api/assets and /api/images with authenticated persona MUST still emit
        { persona: 'user_a', surface: 'http', serviceOrigin: 'https://api.app.test', method: 'GET', path: '/api/v1/assets/123', status: 200, responseHeaders: { 'Cache-Control': 'public, max-age=300' } },
      ],
    })

    const cacheHyps = result.hypotheses.filter(h => h.id.startsWith('hyp_rt_cache_'))
    assert.equal(cacheHyps.length, 1, `Expected only /api/v1/assets/123, got: ${cacheHyps.map(h => h.targetRoute).join(', ')}`)
    assert.equal(cacheHyps[0]!.targetRoute, 'GET /api/v1/assets/123')
  })

  test('static assets and anonymous personas NEVER generate hyp_rt_cache, while authenticated API endpoints STILL do', () => {
    const cacheHeaders = { 'Cache-Control': 'public, max-age=31536000', 'X-Cache': 'HIT' }
    const result = inferRuntimeInvariantHypotheses({
      mode: 'grey-box',
      personaObservations: [
        // Anonymous CDN static assets (the exact spam pattern from cdf8b04e)
        { persona: 'anonymous', surface: 'cdn', serviceOrigin: 'https://cdn.app.test', method: 'GET', path: '/logo.png', status: 200, responseHeaders: cacheHeaders },
        { persona: 'anonymous', surface: 'cdn', serviceOrigin: 'https://cdn.app.test', method: 'GET', path: '/icon.svg', status: 200, responseHeaders: cacheHeaders },
        { persona: 'anonymous', surface: 'cdn', serviceOrigin: 'https://cdn.app.test', method: 'GET', path: '/_next/static/chunks/framework.js', status: 200, responseHeaders: cacheHeaders },
        { persona: 'anonymous', surface: 'http', serviceOrigin: 'https://app.test', method: 'GET', path: '/_next/image?url=%2Fhero.png&w=384', status: 200, responseHeaders: cacheHeaders },
        // Authenticated persona fetching static assets -> still NOT cache-bleed spam
        { persona: 'user_a', surface: 'cdn', serviceOrigin: 'https://cdn.app.test', method: 'GET', path: '/banner.png', status: 200, responseHeaders: cacheHeaders },
        { persona: 'user_a', surface: 'http', serviceOrigin: 'https://app.test', method: 'GET', path: '/_next/static/chunks/app.js', status: 200, responseHeaders: cacheHeaders },
        { persona: 'user_a', surface: 'http', serviceOrigin: 'https://app.test', method: 'GET', path: '/static/theme.css', status: 200, responseHeaders: cacheHeaders },
        // Anonymous persona on an API endpoint -> MUST NOT emit cross-user cache-bleed
        { persona: 'anonymous', surface: 'http', serviceOrigin: 'https://api.app.test', method: 'GET', path: '/api/public-catalog', status: 200, responseHeaders: cacheHeaders },
        { persona: 'anon', surface: 'http', serviceOrigin: 'https://api.app.test', method: 'GET', path: '/api/pricing', status: 200, responseHeaders: cacheHeaders },
        // Genuine authenticated API endpoint with public cacheable response and no Vary: Authorization/Cookie -> MUST emit hyp_rt_cache!
        { persona: 'user_a', surface: 'http', serviceOrigin: 'https://api.app.test', method: 'GET', path: '/api/account', status: 200, responseHeaders: { 'Cache-Control': 'public, max-age=300' } },
      ],
    })

    const cacheHyps = result.hypotheses.filter(h => h.id.startsWith('hyp_rt_cache_'))
    assert.equal(cacheHyps.length, 1, `Expected exactly 1 hyp_rt_cache hypothesis, got ${cacheHyps.length}: ${cacheHyps.map(h => h.targetRoute).join(', ')}`)
    assert.equal(cacheHyps[0]!.targetRoute, 'GET /api/account')
    assert.equal(cacheHyps[0]!.serviceOrigin, 'https://api.app.test')
    assert.ok(cacheHyps[0]!.evidence.includes('persona=user_a'))
  })
})

describe('P0 #3b: Stop emitting fake POST /_actions/<fn> endpoints for Next.js "use server"', () => {
  test('"use server" functions record serverActions metadata without minting synthetic /_actions/* routes', async t => {
    const reposDir = makeTempDir(t, 'kovo-wave1-actions-')
    writeTree(reposDir, {
      'acme/web/src/app/settings/actions.ts': [
        '"use server"',
        'export async function redeemReferralAwardAction(code: string) {',
        '  return db.query("UPDATE referrals SET redeemed = true WHERE code = $1", [code])',
        '}',
        'export async function updateWorkspaceName(name: string) {',
        '  return { name }',
        '}',
      ].join('\n'),
      'acme/web/src/app/settings/page.tsx': [
        'import { redeemReferralAwardAction } from "./actions"',
        'export default function SettingsPage() {',
        '  return redeemReferralAwardAction',
        '}',
      ].join('\n'),
      'acme/web/src/app/api/orders/[id]/route.ts': [
        'export async function GET(req: Request) {',
        '  return Response.json({ ok: true })',
        '}',
      ].join('\n'),
    })

    const extracted = extractStaticFrameworkRoutes(reposDir)
    assert.ok(extracted.frameworks.includes('nextjs'))
    assert.equal(
      extracted.routes.some(r => r.pathTemplate.startsWith('/_actions/')),
      false,
      'Must NOT emit synthetic /_actions/<fn> routes',
    )
    assert.ok(extracted.routes.some(r => r.pathTemplate === '/api/orders/:id' && r.method === 'GET'))
    assert.equal(extracted.serverActions.length, 2)
    const redeemHint = extracted.serverActions.find(a => a.actionName === 'redeemReferralAwardAction')
    assert.ok(redeemHint, 'Expected metadata hint for redeemReferralAwardAction')
    assert.equal(redeemHint.headerHint, 'Next-Action')
    assert.equal(redeemHint.pageRoute, '/settings')
    assert.ok(redeemHint.sinkKinds.includes('server_action'))

    // End-to-end Tier-0 Phase-0 recon must NOT persist /_actions/* into SQLite endpoints
    const { storage } = makeStore(t, 'kovo-wave1-actions-db-')
    const origin = 'https://web.acme.test'
    const setup = await setupApprovedRun(storage, { seeds: [origin], tier: 0 })
    const res = await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 0,
      origins: [origin],
      reposDir,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: makeLabGrant(origin, { tier: 0 }),
      signal: AbortSignal.timeout(15_000),
    })

    const storedEndpoints = storage.listEndpoints(setup.runId, { limit: 200 })
    assert.equal(
      storedEndpoints.some(ep => ep.pathTemplate.startsWith('/_actions/')),
      false,
      'Phase-0 recon must NOT persist synthetic /_actions/* endpoints into store',
    )
    assert.ok(storedEndpoints.some(ep => ep.pathTemplate === '/api/orders/:id'))
    assert.equal(res.repoStaticExtraction?.serverActions?.length, 2)
  })
})

describe('P1 #4b: Multi-repo mounted workspaces attach real phase0.code_slices', () => {
  test('multi-repo mounted workspace with Next.js + Express services attaches bounded code slices (> 0)', async t => {
    const reposDir = makeTempDir(t, 'kovo-wave1-multirepo-')
    writeTree(reposDir, {
      'acme/uploader-svc/package.json': JSON.stringify({ name: 'uploader-svc' }),
      'acme/uploader-svc/index.js': [
        'const express = require("express")',
        'const app = express()',
        'app.post("/generate-upload-url", async (req, res) => {',
        '  const signed = await fetch("https://storage.example.test/" + req.body.extension)',
        '  res.json({ url: signed.url })',
        '})',
      ].join('\n'),
      'acme/engine-svc/package.json': JSON.stringify({ name: 'engine-svc' }),
      'acme/engine-svc/src/routes.ts': [
        'import express from "express"',
        'const app = express()',
        'app.post("/v1/tools/web-crawl", async (req, res) => {',
        '  const out = await fetch(req.body.url)',
        '  res.json({ ok: Boolean(out) })',
        '})',
      ].join('\n'),
      'acme/portal-app/package.json': JSON.stringify({ name: 'portal-app' }),
      'acme/portal-app/src/app/api/admin/usage/route.ts': [
        'export async function GET(req: Request) {',
        '  const rows = await db.query("SELECT * FROM usage")',
        '  return Response.json({ rows })',
        '}',
      ].join('\n'),
      'acme/billing-svc/package.json': JSON.stringify({ name: 'billing-svc' }),
      'acme/billing-svc/src/server.ts': [
        'import express from "express"',
        'const app = express()',
        'app.get("/api/invoices", async (req, res) => {',
        '  res.json({ invoices: [] })',
        '})',
      ].join('\n'),
    })

    const origins = ['https://portal.acme.test', 'https://engine.acme.test', 'https://upload.acme.test']
    const { storage } = makeStore(t, 'kovo-wave1-multirepo-db-')
    const setup = await setupApprovedRun(storage, { seeds: origins, tier: 0 })
    const res = await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 0,
      origins,
      reposDir,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: makeMultiOriginGrant(origins, 0),
      signal: AbortSignal.timeout(20_000),
    })

    assert.ok(res.codeSlices, 'Expected codeSlices summary')
    assert.equal(res.codeSlices.codeSlice, 'attached', `Expected codeSlice=attached, got ${JSON.stringify(res.codeSlices)}`)
    assert.ok(res.codeSlices.attached > 0, `Expected code_slices_attached > 0, got ${res.codeSlices.attached}`)
    assert.ok(res.codeSlices.routes > 0, `Expected code_slices_routes > 0, got ${res.codeSlices.routes}`)
    assert.ok(res.codeSlices.avgBytes > 0 && res.codeSlices.avgBytes <= 600, `Expected bounded avgBytes, got ${res.codeSlices.avgBytes}`)

    const attachedHypotheses = (res.codeToRuntimeHypotheses ?? []).filter(h => Boolean(h.codeSlice))
    assert.equal(attachedHypotheses.length, res.codeSlices.attached)
    for (const h of attachedHypotheses) {
      assert.ok(Buffer.byteLength(JSON.stringify(h.codeSlice), 'utf8') <= 600)
    }

    const sliceEvents = storage.eventsAfter(setup.runId, 0, 5000).filter(e => e.kind === 'phase0.code_slices')
    assert.equal(sliceEvents.length, 1)
    const detail = sliceEvents[0]!.detail as Record<string, unknown>
    assert.equal(detail.codeSlice, 'attached')
    assert.ok(Number(detail.code_slices_attached) > 0)
  })

  test('multi-repo workspace without /admin or intra-file sink rules STILL attaches real code slices to mounted routes', async t => {
    const reposDir = makeTempDir(t, 'kovo-wave1-multirepo-fallback-')
    writeTree(reposDir, {
      'org/svc-alpha/index.ts': [
        'import express from "express"',
        'const app = express()',
        'app.post("/generate-upload-url", (req, res) => { res.json({ ok: true }) })',
      ].join('\n'),
      'org/svc-beta/index.ts': [
        'import express from "express"',
        'const app = express()',
        'app.get("/v1/models", (req, res) => { res.json({ models: [] }) })',
      ].join('\n'),
    })

    const origins = ['https://alpha.org.test', 'https://beta.org.test']
    const { storage } = makeStore(t, 'kovo-wave1-multirepo-fb-db-')
    const setup = await setupApprovedRun(storage, { seeds: origins, tier: 0 })
    const res = await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 0,
      origins,
      reposDir,
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: makeMultiOriginGrant(origins, 0),
      signal: AbortSignal.timeout(20_000),
    })

    assert.equal(res.codeSlices?.codeSlice, 'attached')
    assert.ok((res.codeSlices?.attached ?? 0) >= 2, `Expected >= 2 slices across both repos, got ${res.codeSlices?.attached}`)
  })
})

describe('P1 #5a: Phase-0 uniform edge-protection wall fingerprinting', () => {
  test('uniform Vercel 401 wall & CF Access wall fast-fail and emit phase0.edge_protected while healthy sibling maps normally', async t => {
    const vercelOrigin = 'https://walled-vercel.edge.test'
    const cfOrigin = 'https://walled-cf.edge.test'
    const healthyOrigin = 'https://healthy-api.edge.test'
    const partialAuthOrigin = 'https://partial-auth.edge.test'
    const origins = [vercelOrigin, cfOrigin, healthyOrigin, partialAuthOrigin]

    let seq = 0
    const reqCountByOrigin = new Map<string, number>()
    const broker = {
      async executeHttp(req: BrokerHttpRequest) {
        seq += 1
        reqCountByOrigin.set(req.origin, (reqCountByOrigin.get(req.origin) ?? 0) + 1)
        if (req.origin === vercelOrigin) {
          return makeExchange(
            req,
            401,
            'text/html',
            '<html><head><title>Login – Vercel</title></head><body>Vercel Deployment Protection: Authentication Required</body></html>',
            seq,
            {
              respHeaders: {
                'x-vercel-id': 'iad1::987654321',
                'set-cookie': '_vercel_sso_nonce=nonce123; HttpOnly; Secure',
              },
            },
          )
        }
        if (req.origin === cfOrigin) {
          return makeExchange(
            req,
            302,
            'text/html',
            '',
            seq,
            {
              respHeaders: {
                location: 'https://corp.cloudflareaccess.com/cdn-cgi/access/login/walled-cf.edge.test',
                'cf-ray': '123456-LAX',
              },
            },
          )
        }
        if (req.origin === partialAuthOrigin) {
          // Root returns 401 with x-vercel-id, but unknown calibration paths return 404 -> NOT an edge wall!
          if (req.pathAndQuery === '/') {
            return makeExchange(req, 401, 'text/html', '<html><body>Unauthorized</body></html>', seq, {
              respHeaders: { 'x-vercel-id': 'iad1::app-route' },
            })
          }
          if (req.pathAndQuery === '/robots.txt') {
            return makeExchange(req, 200, 'text/plain', 'User-agent: *\nAllow: /api/status\n', seq)
          }
          return makeExchange(req, 404, 'application/json', '{"error":"not found"}', seq, {
            respHeaders: { 'x-vercel-id': 'iad1::app-route' },
          })
        }
        // Healthy sibling origin
        if (req.pathAndQuery === '/') {
          return makeExchange(req, 200, 'text/html', '<html><body><a href="/api/items">Items</a></body></html>', seq)
        }
        if (req.pathAndQuery === '/api/items') {
          return makeExchange(req, 200, 'application/json', JSON.stringify({ items: [{ id: 'itm_1' }] }), seq)
        }
        return makeExchange(req, 404, 'text/plain', 'Not Found', seq)
      },
    } as unknown as RequestBroker

    const { storage } = makeStore(t, 'kovo-wave1-edge-db-')
    const setup = await setupApprovedRun(storage, { seeds: origins, tier: 2 })
    const res = await runPhase0Recon({
      storage,
      runId: setup.runId,
      scopeRevision: setup.run.scopeRevision,
      tier: 2,
      origins,
      perOriginCap: 25,
      broker,
      grant: makeMultiOriginGrant(origins, 2),
      signal: AbortSignal.timeout(15_000),
    })

    // Both uniform edge-walled origins fast-failed at <= 4 requests
    assert.ok((reqCountByOrigin.get(vercelOrigin) ?? 99) <= 4, `Vercel walled host should fast-fail (got ${reqCountByOrigin.get(vercelOrigin)} reqs)`)
    assert.ok((reqCountByOrigin.get(cfOrigin) ?? 99) <= 4, `CF Access walled host should fast-fail (got ${reqCountByOrigin.get(cfOrigin)} reqs)`)

    // Recorded cleanly in result.edgeProtectedOrigins
    const edgeList = res.edgeProtectedOrigins ?? []
    assert.equal(edgeList.length, 2, `Expected 2 edgeProtectedOrigins, got ${JSON.stringify(edgeList)}`)
    const vercelRec = edgeList.find(e => e.origin === vercelOrigin)
    const cfRec = edgeList.find(e => e.origin === cfOrigin)
    assert.ok(vercelRec)
    assert.equal(vercelRec.vendor, 'vercel_deployment_protection')
    assert.equal(vercelRec.status, 401)
    assert.ok(vercelRec.probesObserved >= 3)
    assert.ok(cfRec)
    assert.equal(cfRec.vendor, 'cloudflare_access')
    assert.equal(cfRec.status, 302)

    // Partial auth origin (401 on /, 404 on unknown paths) MUST NOT be flagged as edge-protected
    assert.equal(edgeList.some(e => e.origin === partialAuthOrigin), false, 'Partial auth host must NOT be quarantined as uniform edge wall')

    // Structured phase0.edge_protected events emitted for both walled hosts
    const edgeEvents = storage.eventsAfter(setup.runId, 0, 5000).filter(e => e.kind === 'phase0.edge_protected')
    assert.equal(edgeEvents.length, 2)
    assert.ok(edgeEvents.some(e => (e.detail as Record<string, unknown>).origin === vercelOrigin))
    assert.ok(edgeEvents.some(e => (e.detail as Record<string, unknown>).origin === cfOrigin))

    // Healthy sibling mapped normally
    const healthyEndpoints = storage.listEndpoints(setup.runId, { origin: healthyOrigin, limit: 100 })
    assert.ok(healthyEndpoints.some(ep => ep.pathTemplate === '/api/items'), 'Healthy sibling origin must map /api/items normally')
  })
})
