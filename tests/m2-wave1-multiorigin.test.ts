/**
 * Multi-Origin Wave-1 Planning & Source-Walk Unit Tests (`m2-wave1-multiorigin`):
 *
 * Verifies the 3 generic multi-origin Wave-1 fixes (zero app/route/persona hardcoding):
 *  1. Multi-origin Grey-Box & single-monorepo invariant hypothesis preservation:
 *     fuzzy path-prefix matching against all discovered endpoints across approved origins,
 *     and highest-risk + sibling-origin fallback instead of silently dropping unmapped GB hypotheses
 *     (while keeping explicitly unmapped sidecar repos in multi-repo WB mounts isolated).
 *  2. Service-balanced BFS + round-robin repo source walk (`collectBoundedRepoSourceFiles` /
 *     `selectBalancedRepoSourceCandidates`): prioritizes runtime dirs (`src/`, `server/`, `api/`,
 *     `routes/`, `handlers/`, `services/`, `controllers/`) ahead of `docs/`/`tests/`/`fixtures/`/
 *     `migrations/` and gives every service in a multi-service monorepo fair coverage within `maxFiles`.
 *  3. Per-origin Wave-1 coverage guarantee: every reachable approved origin with discovered endpoints
 *     gets a Wave-1 step (with sibling reachable origins and distinct `.host` titles for multi-port
 *     local origins) even when `codeAuditStepsCreated > 0` or LLM threat model only covered a subset.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'
import { RequestBroker } from '../src/server/broker.ts'
import { classifyHostTier } from '../src/server/agent-session.ts'
import {
  WHITEBOX_BLACKBOX_CAP_PRIORITY,
  applyCrownJewelStepBudget,
  computeHostTiers,
} from '../src/server/exec-dispatch.ts'
import {
  buildWave1UncoveredOriginFallbackSteps,
  classifyRepoDirTier,
  resolveWave1MultiOriginFallback,
  selectBalancedRepoSourceCandidates,
} from '../src/server/exec-recon-multiorigin.ts'
import { Execution } from '../src/server/execution.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import type { InvariantHypothesis, SynthesizeInvariantsResult } from '../src/server/invariant-synthesizer.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

function stubBackend(): WorkerBackend {
  return {
    name: 'stub-m2-multiorigin',
    async run() {
      return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} }
    },
  } as unknown as WorkerBackend
}

function makeBroker(): RequestBroker {
  return new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"ok":true}' }),
  })
}

function getPlanner(execution: Execution): ExecReconPlanner {
  return (execution as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

function makeHyp(overrides: Partial<InvariantHypothesis> & { id: string }): InvariantHypothesis {
  return {
    kind: 'policy_asymmetry',
    capabilityKind: 'policy_asymmetry',
    promotionStatus: 'capability_only',
    mode: 'grey-box',
    entity: 'order',
    surface: 'http',
    severity: 'high',
    score: 0.86,
    summary: `Differential guard asymmetry on ${overrides.targetRoute ?? '/api/orders'}`,
    preconditions: ['two tenants'],
    verificationHint: 'Compare control vs variant access',
    evidence: [],
    ...overrides,
  }
}

describe('1. Multi-origin Grey-Box & monorepo Wave-1 hypothesis preservation', () => {
  test('Grey-Box multi-origin hypotheses resolve via fuzzy path-prefix match and highest-risk multi-origin fallback without silent drops', async (t) => {
    const portalOrigin = 'https://portal.synth.example'
    const apiOrigin = 'https://api.synth.example'
    const idpOrigin = 'https://auth.synth.example'
    const origins = [portalOrigin, apiOrigin, idpOrigin]

    const { storage } = makeStore(t, 'kovo-m2-gb-wave1-')
    const { runId, run } = await setupApprovedRun(storage, { seeds: origins, tier: 2 })
    const exec = new Execution(storage, { broker: makeBroker(), backend: stubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())
    const planner = getPlanner(exec)

    // Seed discovered endpoints across all 3 origins; apiOrigin has highest risk score (96).
    storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: portalOrigin, method: 'GET',
      pathTemplate: '/console/settings', riskScore: 60, source: 'spa_crawl',
    })
    storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: apiOrigin, method: 'POST',
      pathTemplate: '/api/v1/ledger/transfers/:id/release', riskScore: 96, source: 'openapi',
    })
    storage.upsertEndpoint({
      runId, scopeRevision: run.scopeRevision, origin: idpOrigin, method: 'POST',
      pathTemplate: '/oauth2/federation/callback', riskScore: 84, source: 'spa_crawl',
    })

    const synthesis: SynthesizeInvariantsResult = {
      mode: 'grey-box',
      hypotheses: [
        // Fuzzy path-prefix match: `/ledger/transfers` matches `/api/v1/ledger/transfers/:id/release` on apiOrigin
        makeHyp({
          id: 'hyp_gb_prefix_api',
          entity: 'transfer',
          targetRoute: 'POST /ledger/transfers',
          summary: 'Batch release skips tenant ownership guard',
        }),
        // Fuzzy path-prefix match: `/oauth2/federation` matches `/oauth2/federation/callback` on idpOrigin
        makeHyp({
          id: 'hyp_gb_prefix_idp',
          entity: 'federation',
          targetRoute: 'POST /oauth2/federation',
          summary: 'Token exchange accepts unverified state parameter',
        }),
        // Completely ambiguous GB hypothesis (no serviceOrigin, no host mention, no matching route prefix)
        makeHyp({
          id: 'hyp_gb_ambiguous',
          kind: 'trust_boundary_mismatch',
          entity: 'boundary',
          summary: 'Downstream webhook consumer accepts unsigned replay across services',
          targetRoute: undefined,
        }),
      ],
      capabilitySeeds: [],
    }

    const createdIds = planner.promoteInvariantHypothesesToWave1ChainSteps(storage.run(runId), synthesis, {
      maxSteps: 6,
    })

    assert.equal(createdIds.length, 3, 'ALL 3 Grey-Box multi-origin hypotheses must be promoted (zero silent drops)')
    const steps = storage.listChainSteps(runId, storage.run(runId).goalRevision)
    const prefixApi = steps.find(s => s.hypothesis.includes('hyp_gb_prefix_api'))!
    const prefixIdp = steps.find(s => s.hypothesis.includes('hyp_gb_prefix_idp'))!
    const ambiguous = steps.find(s => s.hypothesis.includes('hyp_gb_ambiguous'))!

    assert.deepEqual(prefixApi.sourceOrigins, [apiOrigin], 'fuzzy prefix must bind transfer hypothesis to apiOrigin')
    assert.deepEqual(prefixIdp.sourceOrigins, [idpOrigin], 'fuzzy prefix must bind federation hypothesis to idpOrigin')
    assert.equal(ambiguous.sourceOrigins[0], apiOrigin, 'ambiguous GB hypothesis must pick highest-risk origin first')
    assert.deepEqual(
      new Set(ambiguous.sourceOrigins),
      new Set(origins),
      'ambiguous GB hypothesis must bind all active approved origins so publicOrigins covers every service',
    )

    const skippedEvents = storage.eventsAfter(runId, 0, 50).filter(e => e.kind === 'invariants.unmapped_origin_skipped')
    assert.equal(skippedEvents.length, 0, 'zero unmapped_origin_skipped telemetry should be emitted when all GB hypotheses are preserved')
  })

  test('resolveWave1MultiOriginFallback keeps empty approvedList unmapped and isolates explicitly unmapped multi-repo mounts', () => {
    const emptyRes = resolveWave1MultiOriginFallback({
      hypEntity: 'invoice',
      candidateRouteRefs: ['/api/invoices'],
      approvedList: [],
      activeOrigins: new Set(),
      storedEndpoints: [],
      staticOnlySources: new Set(['repo_ast']),
      explicitlyUnmappedMountedRepo: false,
      normalizeRoute: r => r,
      classifyTier: classifyHostTier,
    })
    assert.deepEqual(emptyRes, { origins: [], unmapped: true })

    const unmappedMultiRepo = resolveWave1MultiOriginFallback({
      hypEntity: 'cronjob',
      candidateRouteRefs: ['/internal/cron/sync'],
      approvedList: ['https://a.example', 'https://b.example'],
      activeOrigins: new Set(['https://a.example', 'https://b.example']),
      storedEndpoints: [],
      staticOnlySources: new Set(['repo_ast']),
      explicitlyUnmappedMountedRepo: true,
      normalizeRoute: r => r,
      classifyTier: classifyHostTier,
    })
    assert.deepEqual(unmappedMultiRepo, { origins: [], unmapped: true })

    // Single-monorepo (explicitlyUnmappedMountedRepo=false) with a quarantined origin excludes the quarantined host
    const monorepoRes = resolveWave1MultiOriginFallback({
      hypEntity: 'boundary',
      candidateRouteRefs: [],
      approvedList: ['https://gated.example', 'https://api.example', 'https://portal.example'],
      activeOrigins: new Set(['https://api.example', 'https://portal.example']),
      storedEndpoints: [
        { origin: 'https://portal.example', pathTemplate: '/home', riskScore: 40, source: 'spa_crawl' },
        { origin: 'https://api.example', pathTemplate: '/api/admin/roles', riskScore: 95, source: 'spa_crawl' },
      ],
      staticOnlySources: new Set(['repo_ast']),
      explicitlyUnmappedMountedRepo: false,
      normalizeRoute: r => r,
      classifyTier: classifyHostTier,
    })
    assert.equal(monorepoRes.unmapped, false)
    assert.deepEqual(monorepoRes.origins, ['https://api.example', 'https://portal.example'])
  })
})

describe('2. Service-balanced BFS & round-robin repo source walk', () => {
  test('selectBalancedRepoSourceCandidates prioritizes runtime source dirs over docs/tests/fixtures/migrations and balances across sibling services', () => {
    assert.equal(classifyRepoDirTier('src', 1), 0)
    assert.equal(classifyRepoDirTier('handlers', 1), 0)
    assert.equal(classifyRepoDirTier('docs', 0), 2)
    assert.equal(classifyRepoDirTier('__tests__', 0), 2)
    assert.equal(classifyRepoDirTier('fixtures', 0), 2)
    assert.equal(classifyRepoDirTier('migrations', 0), 2)
    assert.equal(classifyRepoDirTier('src', 2), 2, 'deprioritized subtree must stay deprioritized')

    const candidates: Array<{ full: string; relPath: string; depth: number }> = []
    // Pollute early directories with 60 docs/tests/fixtures/migrations files
    for (let i = 0; i < 20; i += 1) {
      candidates.push({ full: `/r/docs/doc_${i}.ts`, relPath: `docs/doc_${i}.ts`, depth: 1 })
      candidates.push({ full: `/r/__tests__/spec_${i}.ts`, relPath: `__tests__/spec_${i}.ts`, depth: 1 })
      candidates.push({ full: `/r/fixtures/fix_${i}.ts`, relPath: `fixtures/fix_${i}.ts`, depth: 1 })
      candidates.push({ full: `/r/migrations/mig_${i}.ts`, relPath: `migrations/mig_${i}.ts`, depth: 1 })
    }
    // Four sibling services where alpha alone has 60 files (would starve beta/gamma/delta under DFS)
    for (const svc of ['alpha', 'beta', 'gamma', 'delta']) {
      const count = svc === 'alpha' ? 60 : 12
      for (let i = 0; i < count; i += 1) {
        const relPath = `services/${svc}/src/routes/route_${String(i).padStart(2, '0')}.ts`
        candidates.push({ full: `/r/${relPath}`, relPath, depth: 4 })
      }
    }

    const picked = selectBalancedRepoSourceCandidates(candidates, 24)
    assert.equal(picked.length, 24)

    const counts = new Map<string, number>()
    for (const p of picked) {
      const top = p.relPath.startsWith('services/') ? p.relPath.split('/').slice(0, 2).join('/') : p.relPath.split('/')[0]!
      counts.set(top, (counts.get(top) ?? 0) + 1)
    }
    assert.equal(counts.get('docs') ?? 0, 0, 'docs must receive 0 slots while runtime services have files')
    assert.equal(counts.get('__tests__') ?? 0, 0, '__tests__ must receive 0 slots while runtime services have files')
    assert.equal(counts.get('fixtures') ?? 0, 0, 'fixtures must receive 0 slots while runtime services have files')
    assert.equal(counts.get('migrations') ?? 0, 0, 'migrations must receive 0 slots while runtime services have files')
    assert.equal(counts.get('services/alpha'), 6)
    assert.equal(counts.get('services/beta'), 6)
    assert.equal(counts.get('services/gamma'), 6)
    assert.equal(counts.get('services/delta'), 6)
  })

  test('end-to-end async collectBoundedRepoSourceFiles (via seedCapabilityLedgerInvariants) covers all services in an oversized monorepo', async (t) => {
    const tmpRepoBase = mkdtempSync(join(tmpdir(), 'kovo-m2-bfs-walk-'))
    t.after(() => rmSync(tmpRepoBase, { recursive: true, force: true }))

    const monoRoot = join(tmpRepoBase, 'monorepo')
    // Create 100 docs + 100 fixtures + 140 files in early services/a-first + 4 files in services/z-last (well over maxFiles=160)
    mkdirSync(join(monoRoot, 'docs'), { recursive: true })
    mkdirSync(join(monoRoot, 'fixtures'), { recursive: true })
    mkdirSync(join(monoRoot, 'services/a-first/src/routes'), { recursive: true })
    mkdirSync(join(monoRoot, 'services/m-middle/src/handlers'), { recursive: true })
    mkdirSync(join(monoRoot, 'services/z-last/src/routes'), { recursive: true })

    for (let i = 0; i < 90; i += 1) {
      writeFileSync(join(monoRoot, 'docs', `guide_${i}.ts`), `export const guide${i} = ${i}\n`)
      writeFileSync(join(monoRoot, 'fixtures', `seed_${i}.ts`), `export const seed${i} = ${i}\n`)
    }
    for (let i = 0; i < 140; i += 1) {
      writeFileSync(
        join(monoRoot, 'services/a-first/src/routes', `r_${String(i).padStart(3, '0')}.ts`),
        `import express from 'express'\nconst r = express.Router()\nr.get('/api/a/item_${i}', requireAuth, (_req, res) => res.json({ ok: true }))\n`,
      )
    }
    // Distinctive policy-asymmetry pair in m-middle (protected GET vs unguarded POST batch)
    writeFileSync(
      join(monoRoot, 'services/m-middle/src/handlers/shipments.ts'),
      [
        "import express from 'express'",
        'const router = express.Router()',
        "router.get('/api/shipments/:id', requireAuth, requireRole('admin'), (req, res) => res.json({ id: req.params.id }))",
        "router.post('/api/shipments/export', (req, res) => res.json({ exported: true }))",
        'export default router',
      ].join('\n'),
    )
    // Distinctive policy-asymmetry pair in z-last
    writeFileSync(
      join(monoRoot, 'services/z-last/src/routes/invoices.ts'),
      [
        "import express from 'express'",
        'const router = express.Router()',
        "router.get('/api/invoices/:id', requireAuth, requireRole('admin'), (req, res) => res.json({ id: req.params.id }))",
        "router.post('/api/invoices/export', (req, res) => res.json({ exported: true }))",
        'export default router',
      ].join('\n'),
    )

    const { storage } = makeStore(t, 'kovo-m2-mono-walk-')
    const origins = ['https://alpha.synth.example', 'https://middle.synth.example', 'https://last.synth.example']
    const { runId } = await setupApprovedRun(storage, { seeds: origins, tier: 2 })
    const exec = new Execution(storage, { broker: makeBroker(), backend: stubBackend(), deterministicSweep: false })
    t.after(() => exec.stop())
    const planner = getPlanner(exec)

    const seeded = await planner.seedCapabilityLedgerInvariants(storage.run(runId), {
      reposDir: tmpRepoBase,
      mountedRepos: ['/repos/monorepo'],
      approvedOrigins: new Set(origins),
      promoteWave1Chains: true,
    })

    const allLocations = seeded.synthesis.hypotheses.map(h => h.location?.file ?? '')
    const allText = seeded.synthesis.hypotheses.map(h => `${h.location?.file ?? ''} ${h.targetRoute ?? ''} ${h.summary}`).join('\n')
    assert.ok(
      allLocations.some(f => f.includes('m-middle')) || allText.includes('shipments'),
      `expected balanced BFS walk to reach services/m-middle despite 180 docs/fixtures + 140 a-first files; saw files: ${allLocations.join(', ')}`,
    )
    assert.ok(
      allLocations.some(f => f.includes('z-last')) || allText.includes('invoices'),
      `expected balanced BFS walk to reach services/z-last despite 180 docs/fixtures + 140 a-first files; saw files: ${allLocations.join(', ')}`,
    )
  })
})

describe('3. Per-origin Wave-1 coverage guarantee', () => {
  test('seeds fallback steps for uncovered approved origins with discovered endpoints even when codeAuditStepsCreated > 0, with sibling origins and unique multi-port titles', () => {
    const originA = 'http://127.0.0.1:4101'
    const originB = 'http://127.0.0.1:4102'
    const originC = 'http://127.0.0.1:4103'
    const originEmpty = 'http://127.0.0.1:4104'
    const entries = [
      { origin: originA, riskTier: 'high' as const, surfaceTags: ['api'], rationale: 'svc A' },
      { origin: originB, riskTier: 'high' as const, surfaceTags: ['auth'], rationale: 'svc B' },
      { origin: originC, riskTier: 'medium' as const, surfaceTags: ['upload'], rationale: 'svc C' },
      { origin: originEmpty, riskTier: 'low' as const, surfaceTags: ['static'], rationale: 'empty host' },
    ]
    const hostTiers = computeHostTiers([originA, originB, originC, originEmpty], entries)

    // White-box run where Source-First Code Audit created 3 steps ALL on originA, leaving B and C with 0 steps.
    const existingSteps = [
      { status: 'ready' as const, sourceOrigins: [originA], title: 'Source audit 1' },
      { status: 'ready' as const, sourceOrigins: [originA], title: 'Source audit 2' },
      { status: 'ready' as const, sourceOrigins: [originA], title: 'Source audit 3' },
    ]
    const discoveredEndpointOrigins = new Set([originA, originB, originC])

    const res = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: entries,
      seededSteps: [],
      existingSteps,
      discoveredEndpointOrigins,
      finalHostTiers: hostTiers,
      sourceMounted: true,
      codeAuditStepsCreated: 3,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
    })

    assert.equal(res.uncoveredAddedCount, 2, 'must seed fallback steps for uncovered origins B and C only')
    assert.equal(res.seededSteps.length, 2)
    const stepB = res.seededSteps.find(s => s.origins[0] === originB)!
    const stepC = res.seededSteps.find(s => s.origins[0] === originC)!
    assert.ok(stepB, 'originB must get a Wave-1 fallback step')
    assert.ok(stepC, 'originC must get a Wave-1 fallback step')
    assert.notEqual(stepB.title, stepC.title, 'multi-port origins on 127.0.0.1 must get distinct .host titles')
    assert.ok(stepB.title.includes('127.0.0.1:4102'))
    assert.ok(stepC.title.includes('127.0.0.1:4103'))
    assert.ok(stepB.origins.includes(originA) && stepB.origins.includes(originC), 'fallback step must include non-static sibling origins')
    assert.ok(stepC.origins.includes(originA) && stepC.origins.includes(originB), 'fallback step must include non-static sibling origins')
    assert.ok(stepB.priority <= WHITEBOX_BLACKBOX_CAP_PRIORITY - 5, 'white-box fallback step must stay below white-box code-audit leads')

    // Verify applyCrownJewelStepBudget admits BOTH B and C (no duplicate-title collapse!)
    const budgeted = applyCrownJewelStepBudget(res.seededSteps, hostTiers, existingSteps, Math.max(res.uncoveredAddedCount, 12 - existingSteps.length))
    assert.equal(budgeted.length, 2, 'applyCrownJewelStepBudget must admit both uncovered multi-port fallback steps')
    assert.deepEqual(new Set(budgeted.map(s => s.origins[0])), new Set([originB, originC]))
  })

  test('does NOT add redundant fallback steps when sole origin is already covered by white-box code audit, and never boosts low_value_static origins', () => {
    const soleOrigin = 'https://wb.synth.example'
    const entries = [{ origin: soleOrigin, riskTier: 'high' as const, surfaceTags: ['api'], rationale: 'sole' }]
    const hostTiers = computeHostTiers([soleOrigin], entries)
    const resSole = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: entries,
      seededSteps: [],
      existingSteps: [{ status: 'ready', sourceOrigins: [soleOrigin] }],
      discoveredEndpointOrigins: new Set([soleOrigin]),
      finalHostTiers: hostTiers,
      sourceMounted: true,
      codeAuditStepsCreated: 2,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
    })
    assert.equal(resSole.uncoveredAddedCount, 0)
    assert.equal(resSole.seededSteps.length, 0)

    const apiOrigin = 'https://api.synth.example'
    const docsOrigin = 'https://docs.synth.example'
    const mixedEntries = [
      { origin: apiOrigin, riskTier: 'high' as const, surfaceTags: ['api'], rationale: 'api' },
      { origin: docsOrigin, riskTier: 'low' as const, surfaceTags: ['static', 'low_value_static'], rationale: 'docs' },
    ]
    const mixedTiers = computeHostTiers([apiOrigin, docsOrigin], mixedEntries)
    const resMixed = buildWave1UncoveredOriginFallbackSteps({
      reachableFinalEntries: mixedEntries,
      seededSteps: [],
      existingSteps: [{ status: 'ready', sourceOrigins: [apiOrigin] }],
      discoveredEndpointOrigins: new Set([apiOrigin, docsOrigin]),
      finalHostTiers: mixedTiers,
      sourceMounted: false,
      codeAuditStepsCreated: 0,
      capabilityTier: 2,
      whiteBoxCapPriority: WHITEBOX_BLACKBOX_CAP_PRIORITY,
      classifyTier: classifyHostTier,
    })
    const docsStep = resMixed.seededSteps.find(s => s.origins[0] === docsOrigin)!
    assert.ok(docsStep, 'docs host still included in initial fallback')
    assert.deepEqual(docsStep.origins, [docsOrigin], 'low_value_static fallback must NOT attach crown-jewel sibling origins')
  })
})
