/**
 * R2-20 fast guard suite:
 *   - PR-20a: Blueprint-derived fixture-contamination ratchet (`scripts/check-fixture-contamination.ts`)
 *   - PR-20b: `novelVocab` out-of-distribution mode (`benchmarks/realistic-bench/generator/variant.ts`)
 *   - PR-20c: `src/server/probes/cache.ts` owner-marker replacement (fail-closed without `actorMarkers.owner`)
 */
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  deriveFixtureRules,
  runFixtureContaminationCheck,
  updateFixtureBaselineMonotone,
} from '../scripts/check-fixture-contamination.ts'
import { generateVariant } from '../benchmarks/realistic-bench/generator/variant.ts'
import { buildGroundTruth } from '../benchmarks/realistic-bench/generator/groundtruth.ts'
import { blueprint as acmeBlueprint } from '../benchmarks/realistic-bench/apps/acme-saas/truth/blueprint.ts'
import { blueprint as opsportalBlueprint } from '../benchmarks/realistic-bench/apps/opsportal/truth/blueprint.ts'
import { blueprint as shopflowBlueprint } from '../benchmarks/realistic-bench/apps/shopflow/truth/blueprint.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { probeDifferential, type ProbeDifferentialRequest } from '../src/server/surface-engine.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

function makeTempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix))
}

async function startFixture(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ origin: string; close: () => Promise<void> }> {
  const srv = createServer(handler)
  await new Promise<void>(r => srv.listen(0, '127.0.0.1', r))
  const { port } = srv.address() as AddressInfo
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>(r => srv.close(() => r())),
  }
}

describe('PR-20a: blueprint-derived fixture-contamination ratchet', () => {
  test('derives canary grammars, VFS paths, and distinctive routes from all 3 benchmark suites without generic lexicon FPs', () => {
    const rules = deriveFixtureRules(REPO_ROOT)

    assert.ok(rules.canaryRegexes.length >= 2, 'derives canary grammar and synthetic secret prefix rules')
    assert.ok(rules.vfsPaths.includes('/app/config/secrets.env'), 'derives realistic-bench VFS secret path')
    assert.ok(rules.vfsPaths.includes('/app/.env'), 'derives realistic-bench VFS env path')
    assert.ok(rules.vfsPaths.includes('/var/log/system/audit.log'), 'derives opsportal VFS audit log path')
    assert.ok(rules.vfsPaths.includes('/etc/opsportal/secrets.env'), 'derives opsportal VFS secrets path')
    assert.ok(rules.vfsPaths.includes('/srv/ledger/internal-metadata.json'), 'derives reason-bench ledgerflow VFS path')
    assert.ok(!rules.vfsPaths.includes('/etc/passwd'), 'excludes generic OS /etc/passwd from VFS contamination list')

    assert.ok(rules.exactRoutes.has('/api/checkout/return'), 'derives realistic-bench shopflow route')
    assert.ok(rules.exactRoutes.has('/api/hooks/ledger'), 'derives reason-bench ledgerflow route')
    assert.ok(rules.exactRoutes.has('/api/rebates/apply'), 'derives multihop-saas connecthub route')
    assert.ok(rules.templateRoutes.has('/api/hooks/:param/ping'), 'derives expanded opsportal route template')
    assert.ok(rules.templateRoutes.has('/api/wares/:param/photos'), 'derives expanded shopflow route template')

    // Generic HTTP/API routes and generic single-noun pool routes must NOT appear
    assert.ok(!rules.exactRoutes.has('/api/users'), 'excludes generic /api/users')
    assert.ok(!rules.exactRoutes.has('/api/orders'), 'excludes generic /api/orders')
    assert.ok(!rules.exactRoutes.has('/api/invoices'), 'excludes generic /api/invoices')
    assert.ok(!rules.exactRoutes.has('/api/auth/login'), 'excludes generic /api/auth/login')
    assert.ok(!rules.exactRoutes.has('/api/health'), 'excludes generic /api/health')
    assert.ok(!rules.exactRoutes.has('/api/graphql'), 'excludes generic /api/graphql')
    assert.ok(!rules.templateRoutes.has('/api/users/:param'), 'excludes generic /api/users/:param')
  })

  test('passes on the real repository in <2s and confirms src/server/probes/cache.ts has 0 hits', () => {
    const res = runFixtureContaminationCheck({ rootDir: REPO_ROOT })
    assert.equal(res.ok, true, `expected PASS, got new=${JSON.stringify(res.newEntries)} resolved=${JSON.stringify(res.resolvedEntries)}`)
    assert.equal(res.newEntries.length, 0)
    assert.equal(res.resolvedEntries.length, 0)
    assert.ok(res.durationMs < 2000, `expected <2000ms, got ${res.durationMs}ms`)
    assert.ok(res.filesScanned > 50)
    const cacheHits = res.hits.filter(h => h.file === 'src/server/probes/cache.ts')
    assert.equal(cacheHits.length, 0, 'PR-20c must eliminate fixture canary grammar hits in src/server/probes/cache.ts')
  })

  test('detects synthetic canary, VFS, and route leaks while ignoring generic HTTP code and enforces monotone-shrinking baseline', () => {
    const tmp = makeTempDir('kovo-r2-20-lint-')
    try {
      const serverDir = join(tmp, 'src', 'server')
      mkdirSync(serverDir, { recursive: true })
      const baselinePath = join(tmp, 'fixture-baseline.json')

      // Clean generic code -> 0 hits
      writeFileSync(
        join(serverDir, 'clean.ts'),
        [
          'export const routes = ["/api/users", "/api/orders", "/api/auth/login", "/api/health"]',
          'export const osFile = "/etc/passwd"',
          'export const verbs_count = 3',
        ].join('\n'),
        'utf8',
      )
      writeFileSync(baselinePath, JSON.stringify({ version: 1, entries: [] }), 'utf8')
      const cleanRes = runFixtureContaminationCheck({ rootDir: tmp, benchmarksRoot: REPO_ROOT, baselinePath })
      assert.equal(cleanRes.ok, true)
      assert.equal(cleanRes.totalHits, 0)

      // Inject 3 distinct leak categories (using neutral synthetic markers, no exploit strings)
      const leakFile = join(serverDir, 'leak.ts')
      writeFileSync(
        leakFile,
        [
          'export const canaryRe = /rb[cs]_[a-z0-9]+_[0-9a-f]{12}/',
          'export const vfs = "/etc/opsportal/secrets.env"',
          'export const route = "/api/hooks/ledger"',
        ].join('\n'),
        'utf8',
      )
      const failRes = runFixtureContaminationCheck({ rootDir: tmp, benchmarksRoot: REPO_ROOT, baselinePath })
      assert.equal(failRes.ok, false)
      assert.equal(failRes.newEntries.length, 3)
      const categories = new Set(failRes.newEntries.map(e => e.category))
      assert.deepEqual(categories, new Set(['canary_grammar', 'vfs_path', 'blueprint_route']))

      // Monotone writer MUST refuse to add new entries to an existing baseline
      const refuseAdd = updateFixtureBaselineMonotone({ rootDir: tmp, benchmarksRoot: REPO_ROOT, baselinePath })
      assert.equal(refuseAdd.ok, false)
      assert.equal(refuseAdd.wrote, false)

      // Bootstrap a fresh baseline with the 3 entries, then remove 1 -> check MUST prune-fail
      const bootBaselinePath = join(tmp, 'boot-baseline.json')
      const booted = updateFixtureBaselineMonotone({
        rootDir: tmp,
        benchmarksRoot: REPO_ROOT,
        baselinePath: bootBaselinePath,
        allowBootstrap: true,
      })
      assert.equal(booted.ok, true)
      assert.equal(booted.nextTotal, 3)

      // Remove the canary hit without pruning baseline -> prune-fail
      writeFileSync(
        leakFile,
        [
          'export const vfs = "/etc/opsportal/secrets.env"',
          'export const route = "/api/hooks/ledger"',
        ].join('\n'),
        'utf8',
      )
      const pruneFailRes = runFixtureContaminationCheck({
        rootDir: tmp,
        benchmarksRoot: REPO_ROOT,
        baselinePath: bootBaselinePath,
      })
      assert.equal(pruneFailRes.ok, false)
      assert.equal(pruneFailRes.newEntries.length, 0)
      assert.equal(pruneFailRes.resolvedEntries.length, 1)
      assert.equal(pruneFailRes.resolvedEntries[0]!.category, 'canary_grammar')

      // Monotone prune succeeds and shrinks baseline from 3 -> 2
      const pruned = updateFixtureBaselineMonotone({
        rootDir: tmp,
        benchmarksRoot: REPO_ROOT,
        baselinePath: bootBaselinePath,
      })
      assert.equal(pruned.ok, true)
      assert.equal(pruned.wrote, true)
      assert.equal(pruned.previousTotal, 3)
      assert.equal(pruned.nextTotal, 2)

      const afterPrune = runFixtureContaminationCheck({
        rootDir: tmp,
        benchmarksRoot: REPO_ROOT,
        baselinePath: bootBaselinePath,
      })
      assert.equal(afterPrune.ok, true)
      assert.equal(afterPrune.totalHits, 2)
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  test('scripts/worker-gate.sh wires check-fixture-contamination.ts', () => {
    const gate = readFileSync(join(REPO_ROOT, 'scripts', 'worker-gate.sh'), 'utf8')
    assert.ok(
      gate.includes('node scripts/check-fixture-contamination.ts'),
      'worker-gate.sh must run node scripts/check-fixture-contamination.ts',
    )
  })
})

describe('PR-20b: realistic-bench variant.ts novelVocab mode', () => {
  const blueprints = [acmeBlueprint, opsportalBlueprint, shopflowBlueprint]

  test('default generation (novelVocab omitted or false) is 100% bit-for-bit preserved', () => {
    for (const bp of blueprints) {
      const base = generateVariant(bp, 42)
      const emptyOpts = generateVariant(bp, 42, {})
      const explicitFalse = generateVariant(bp, 42, { novelVocab: false })
      assert.deepStrictEqual(base, emptyOpts, `${bp.app}: omitted vs {}`)
      assert.deepStrictEqual(base, explicitFalse, `${bp.app}: omitted vs novelVocab:false`)
      assert.ok(bp.apiPrefixes.includes(base.apiPrefix), `${bp.app}: default apiPrefix from pool`)
    }
  })

  test('novelVocab:true deterministically substitutes non-pool prefix, route nouns, and params while preserving sites/personas/idFormat', () => {
    const SALT_A = 'r2-20-heldout-salt-aaaaaaaa'
    const SALT_B = 'r2-20-heldout-salt-bbbbbbbb'

    for (const bp of blueprints) {
      const defPlan = generateVariant(bp, 42)
      const nvA = generateVariant(bp, 42, { novelVocab: true })
      const nvB = generateVariant(bp, 42, { novelVocab: true })
      const nvOtherSeed = generateVariant(bp, 43, { novelVocab: true })

      // Deterministic for same seed, varies across seeds
      assert.deepStrictEqual(nvA, nvB, `${bp.app}: novelVocab deterministic`)
      assert.notDeepStrictEqual(nvA.routes, nvOtherSeed.routes, `${bp.app}: novelVocab varies by seed`)
      assert.notDeepStrictEqual(nvA.params, nvOtherSeed.params, `${bp.app}: novelVocab params vary by seed`)

      // Non-vocabulary dimensions stay apples-to-apples identical to default for the same seed
      assert.deepStrictEqual(nvA.sites, defPlan.sites, `${bp.app}: sites preserved`)
      assert.deepStrictEqual(nvA.personas, defPlan.personas, `${bp.app}: personas preserved`)
      assert.equal(nvA.idFormat, defPlan.idFormat, `${bp.app}: idFormat preserved`)
      assert.equal(nvA.canarySalt, defPlan.canarySalt, `${bp.app}: canarySalt preserved`)

      // Prefix is valid and out-of-distribution (not in blueprint pool)
      assert.ok(nvA.apiPrefix.startsWith('/'), `${bp.app}: apiPrefix starts with /`)
      assert.ok(!bp.apiPrefixes.includes(nvA.apiPrefix), `${bp.app}: novel apiPrefix not in pool`)

      // Every parameter name is a valid identifier, unique, and disjoint from blueprint paramVocab pool
      const paramPool = new Set(
        Object.entries(bp.paramVocab).flatMap(([k, vs]) => [k.toLowerCase(), ...vs.map(v => v.toLowerCase())]),
      )
      const seenParams = new Set<string>()
      for (const [k, v] of Object.entries(nvA.params)) {
        assert.match(v, /^[a-z][a-zA-Z0-9_]*$/, `${bp.app}: param ${k}=${v} valid identifier`)
        assert.ok(!seenParams.has(v), `${bp.app}: unique param ${v}`)
        seenParams.add(v)
        assert.ok(!paramPool.has(v.toLowerCase()), `${bp.app}: novel param ${v} disjoint from pool`)
      }

      // Route nouns are disjoint from blueprint vocab pool and collision-free
      const vocabPool = new Set(
        Object.entries(bp.vocab).flatMap(([k, vs]) => [k.toLowerCase(), ...vs.map(v => v.toLowerCase())]),
      )
      const seenSigs = new Set<string>()
      for (const [rk, tmpl] of Object.entries(bp.routes)) {
        const spec = nvA.routes[rk]!
        assert.ok(spec, `${bp.app}: route ${rk} present`)
        const sig = `${spec.method} ${spec.path}`
        assert.ok(!seenSigs.has(sig), `${bp.app}: collision-free route ${sig}`)
        seenSigs.add(sig)
        if (tmpl.path.includes('{noun:')) {
          const segs = spec.path.split('/').filter(Boolean)
          // At least one substituted segment is outside the blueprint vocab pool
          assert.ok(
            segs.some(s => !s.startsWith(':') && !vocabPool.has(s.toLowerCase()) && s !== nvA.apiPrefix.slice(1)),
            `${bp.app}: route ${rk} (${spec.path}) uses out-of-pool noun`,
          )
        }
      }

      // Ground truth builds cleanly from novelVocab plan
      const gt = buildGroundTruth(bp, nvA)
      assert.equal(gt.app, bp.app)
      assert.ok(gt.vulns.length > 0)
    }

    // Held-out seed + novelVocab respects salt isolation
    const hA = generateVariant(acmeBlueprint, 1_000_000, { salt: SALT_A, novelVocab: true })
    const hB = generateVariant(acmeBlueprint, 1_000_000, { salt: SALT_B, novelVocab: true })
    assert.equal(hA.seedSet, 'held-out')
    assert.notDeepStrictEqual(hA.routes, hB.routes)
    assert.notDeepStrictEqual(hA.params, hB.params)
  })
})

describe('PR-20c: probes/cache.ts cross-actor body_repeat uses actorMarkers.owner and fails closed', () => {
  const mkPersona = (handle: string, secret: string, origin: string): ResolvedPersona => ({
    id: handle,
    handle,
    roleLabel: handle,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret,
    canaryMarkers: [],
  })

  const runCacheProbe = (origin: string, req: Omit<ProbeDifferentialRequest, 'origin' | 'probeClass'>) => {
    const personas = new Map<string, ResolvedPersona>([
      ['owner_a', mkPersona('owner_a', 'tok-owner-a', origin)],
      ['other_b', mkPersona('other_b', 'tok-other-b', origin)],
    ])
    const grant: Grant = {
      origin,
      tier: 3,
      allowLocalLab: true,
      maxRpsPerOrigin: 200,
      personas,
      canRead: o => o === origin,
      isIdempotentPostAllowed: () => true,
      isStateChangeApproved: () => true,
      audit: () => undefined,
    }
    return probeDifferential(
      { origin, probeClass: 'cache_poison_deception', maxRequests: 40, ...req },
      new RequestBroker({ rejectUnauthorized: false }),
      grant,
      new CanaryBroker(),
      AbortSignal.timeout(20_000),
    )
  }

  test('signals on real customer owner marker without any fixture canary grammar, and fails closed without actorMarkers.owner', async () => {
    // Vulnerable cross-actor cache: caches by _gcb only (ignoring Authorization header).
    const cacheStore = new Map<string, string>()
    const fx = await startFixture((req, res) => {
      const u = new URL(req.url ?? '/', 'http://fixture')
      const gcb = u.searchParams.get('_gcb') ?? ''
      const auth = String(req.headers.authorization ?? '')
      if (u.pathname === '/reports/summary') {
        if (gcb && cacheStore.has(gcb)) {
          res.writeHead(200, { 'Content-Type': 'application/json' }).end(cacheStore.get(gcb)!)
          return
        }
        const body = auth.includes('tok-owner-a')
          ? JSON.stringify({
              org: 'tenant-alpha-99',
              // Deliberately includes a synthetic rbc-like token too so we prove the fail-closed test
              // does NOT fall back to fixture canary regexes when actorMarkers.owner is absent.
              audit: 'rbc_alpha_0123456789ab',
              summary: 'Q4 enterprise forecast for Alpha Holdings LLC (18 active workspaces)',
            })
          : JSON.stringify({
              org: 'tenant-beta-42',
              audit: 'rbc_beta_fedcba987654',
              summary: 'Q1 retail inventory ledger for Beta Commerce Inc (3 active stores)',
            })
        if (gcb) cacheStore.set(gcb, body)
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(body)
        return
      }
      res.writeHead(404).end('not found')
    })

    try {
      // 1. With real owner marker -> signals (body_repeat + web_cache_deception)
      const withMarker = await runCacheProbe(fx.origin, {
        pathAndQuery: '/reports/summary',
        ownerPersona: 'owner_a',
        otherPersona: 'other_b',
        actorMarkers: { owner: 'tenant-alpha-99', other: 'tenant-beta-42' },
      })

      assert.equal(withMarker.verdict, 'signal', withMarker.summary)
      assert.ok(
        withMarker.anomalies.some(a => a.type === 'cache_poisoning' && a.proof === 'body_repeat'),
        'emits cache_poisoning body_repeat anomaly with actorMarkers.owner',
      )
      assert.ok(
        withMarker.anomalies.some(a => a.type === 'web_cache_deception' && a.mode === 'cross_actor'),
        'emits cross_actor web_cache_deception anomaly',
      )

      // 2. Without actorMarkers.owner -> MUST FAIL CLOSED even though body has rbc_* token!
      cacheStore.clear()
      const withoutMarker = await runCacheProbe(fx.origin, {
        pathAndQuery: '/reports/summary',
        ownerPersona: 'owner_a',
        otherPersona: 'other_b',
      })

      assert.equal(withoutMarker.verdict, 'no_signal', 'must fail closed when actorMarkers.owner is absent')
      assert.equal(withoutMarker.anomalies.length, 0)
      const crossEntries = (withoutMarker.details.crossActor as Array<Record<string, unknown>>) ?? []
      assert.ok(crossEntries.length > 0)
      assert.equal(crossEntries[0]!.hasOwnerMarker, false)
      assert.equal(crossEntries[0]!.hit, false)

      // 3. When owner marker is shared (present in BOTH owner warm AND other fresh) -> fails closed
      cacheStore.clear()
      const sharedMarker = await runCacheProbe(fx.origin, {
        pathAndQuery: '/reports/summary',
        ownerPersona: 'owner_a',
        otherPersona: 'other_b',
        actorMarkers: { owner: 'active' },
      })

      assert.equal(sharedMarker.verdict, 'no_signal', 'must fail closed when owner marker also appears in fresh other response')
      assert.equal(sharedMarker.anomalies.length, 0)
    } finally {
      await fx.close()
    }
  })

  test('stays silent on hardened tenant-keyed cache even with valid actorMarkers.owner', async () => {
    const cacheStore = new Map<string, string>()
    const fx = await startFixture((req, res) => {
      const u = new URL(req.url ?? '/', 'http://fixture')
      const gcb = u.searchParams.get('_gcb') ?? ''
      const auth = String(req.headers.authorization ?? '')
      if (u.pathname === '/reports/summary') {
        const key = `${gcb}|${auth}`
        if (gcb && cacheStore.has(key)) {
          res.writeHead(200, { 'Content-Type': 'application/json' }).end(cacheStore.get(key)!)
          return
        }
        const body = auth.includes('tok-owner-a')
          ? JSON.stringify({ org: 'tenant-alpha-99', summary: 'Alpha private forecast' })
          : JSON.stringify({ org: 'tenant-beta-42', summary: 'Beta private ledger' })
        if (gcb) cacheStore.set(key, body)
        res.writeHead(200, { 'Content-Type': 'application/json' }).end(body)
        return
      }
      res.writeHead(404).end('not found')
    })

    try {
      const res = await runCacheProbe(fx.origin, {
        pathAndQuery: '/reports/summary',
        ownerPersona: 'owner_a',
        otherPersona: 'other_b',
        actorMarkers: { owner: 'tenant-alpha-99', other: 'tenant-beta-42' },
      })
      assert.equal(res.verdict, 'no_signal', res.summary)
      assert.equal(res.anomalies.length, 0)
    } finally {
      await fx.close()
    }
  })
})
