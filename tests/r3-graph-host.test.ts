// @kernel @fixes R3-H-12
/**
 * R3-H-12 regression tests:
 * 1. Static lint banning synchronous `extractProgramGraph(` calls in `src/server/` production host
 *    paths (outside the worker script & `program-graph.ts` definition), ensuring zero sync repo-walk
 *    fs calls in `collectBoundedRepoSourceFiles`, and zero dynamic `new RegExp(` in `program-graph.ts`.
 * 2. Linear O(N) scaling of `extractProgramGraph` on 32 KB / 64 KB / 128 KB files packed with
 *    unterminated Express & FastAPI call-site openers (plus nested closed openers) while preserving
 *    valid cross-framework route extraction.
 * 3. Bounded, non-backtracking Traefik `Host(` / `PathPrefix(` and compose/ingress extraction in
 *    `mapServicesToOrigins` (plus worker-isolated `extractProgramGraphInWorker` parity).
 * 4. Async, non-blocking `ExecReconPlanner.seedCapabilityLedgerInvariants` (offloading to
 *    `extractProgramGraphInWorker` + async `fs.promises` with yields, reusing `staticSnapshot`,
 *    and keeping `ensureWave1InvariantChainSteps` non-blocking when source is mounted).
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'
import { describe, test } from 'node:test'
import { Execution } from '../src/server/execution.ts'
import type { ExecReconPlanner } from '../src/server/exec-recon-planner.ts'
import { extractProgramGraph, mapServicesToOrigins } from '../src/server/program-graph.ts'
import { buildStaticWorkspaceSnapshotInWorker } from '../src/server/static-workspace-snapshot.ts'
import {
  closeSharedUntrustedComputePool,
  extractProgramGraphInWorker,
} from '../src/server/untrusted-compute-pool.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const SERVER_DIR = join(REPO_ROOT, 'src', 'server')

function measureMs(fn: () => void): number {
  const start = performance.now()
  fn()
  return performance.now() - start
}

function makeRepeatFile(header: string, chunk: string, targetBytes: number): string {
  const bodyBytes = Math.max(0, targetBytes - header.length)
  const count = Math.ceil(bodyBytes / chunk.length)
  return header + chunk.repeat(count).slice(0, bodyBytes)
}

function stubBackend(): WorkerBackend {
  return {
    name: 'stub-r3-graph-host',
    async run() {
      throw new Error('stub backend must not be invoked')
    },
  } as unknown as WorkerBackend
}

function getPlanner(execution: Execution): ExecReconPlanner {
  return (execution as unknown as { reconPlanner: ExecReconPlanner }).reconPlanner
}

describe('R3-H-12 static lint: no synchronous extractProgramGraph in server host paths', () => {
  test('bans synchronous extractProgramGraph( calls across src/server/*.ts production paths and dynamic new RegExp in program-graph.ts', () => {
    const serverFiles = readdirSync(SERVER_DIR)
      .filter(f => f.endsWith('.ts'))
      .sort()

    // Allowed occurrences:
    // - `program-graph.ts`: defines `export function extractProgramGraph(`
    // - `parser-worker-entry.ts`: dedicated worker-thread / child-process script
    // - `phase0-recon.ts` / `static-workspace-snapshot.ts`: ONLY inside legacy sync test-compat
    //   exports (`extractRepoProgramGraph`, `buildStaticWorkspaceSnapshot`) or `{ files: [] }` empty
    //   graph init — AND we assert below that ZERO `src/server/*.ts` production paths call those sync exports!
    const syncCallViolations: string[] = []
    const legacySyncWrapperCallers: string[] = []

    for (const file of serverFiles) {
      const fullPath = join(SERVER_DIR, file)
      const content = readFileSync(fullPath, 'utf8')
      const lines = content.split('\n')

      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i]!
        // Strip single-line comments to avoid flagging JSDoc/comments
        const codePart = line.replace(/\/\/.*$/, '').replace(/^\s*\*.*$/, '')

        if (/\bextractProgramGraph\s*\(/.test(codePart)) {
          if (file === 'program-graph.ts' || file === 'parser-worker-entry.ts') continue
          if (file === 'static-workspace-snapshot.ts' && /extractProgramGraph\s*\(\s*\{\s*files:\s*\[\]/.test(codePart)) {
            continue
          }
          // Check if inside the legacy sync-only test-compat helpers (verified uncalled in production below)
          const windowAbove = lines.slice(Math.max(0, i - 15), i + 1).join('\n')
          const isLegacySyncHelper =
            (file === 'phase0-recon.ts' && /export function extractRepoProgramGraph\b/.test(windowAbove))
            || (file === 'static-workspace-snapshot.ts' && /export function buildStaticWorkspaceSnapshot\b/.test(windowAbove))
          if (!isLegacySyncHelper) {
            syncCallViolations.push(`src/server/${file}:${i + 1}: ${line.trim()}`)
          }
        }

        // Ensure NO production server path calls the legacy synchronous wrappers
        if (
          /\b(?:extractRepoProgramGraph|buildStaticWorkspaceSnapshot|getOrBuildStaticWorkspaceSnapshot)\s*\(/.test(codePart)
          && !/export function (?:extractRepoProgramGraph|buildStaticWorkspaceSnapshot|getOrBuildStaticWorkspaceSnapshot)\b/.test(codePart)
        ) {
          // `getOrBuildStaticWorkspaceSnapshot` calling `buildStaticWorkspaceSnapshot` inside `static-workspace-snapshot.ts` is part of the same legacy sync export
          if (file === 'static-workspace-snapshot.ts') {
            const windowAbove = lines.slice(Math.max(0, i - 10), i + 1).join('\n')
            if (/export function getOrBuildStaticWorkspaceSnapshot\b/.test(windowAbove)) continue
          }
          legacySyncWrapperCallers.push(`src/server/${file}:${i + 1}: ${line.trim()}`)
        }
      }
    }

    assert.deepEqual(
      syncCallViolations,
      [],
      `Found forbidden synchronous extractProgramGraph( calls in server host paths:\n${syncCallViolations.join('\n')}`,
    )
    assert.deepEqual(
      legacySyncWrapperCallers,
      [],
      `Found forbidden production callers of synchronous ProgramGraph wrappers:\n${legacySyncWrapperCallers.join('\n')}`,
    )

    // Verify `exec-recon-planner.ts` routes through `extractProgramGraphInWorker` and uses async fs in `collectBoundedRepoSourceFiles`
    const plannerSrc = readFileSync(join(SERVER_DIR, 'exec-recon-planner.ts'), 'utf8')
    assert.equal(
      /\bextractProgramGraph\b(?!InWorker)/.test(plannerSrc),
      false,
      'exec-recon-planner.ts must not import or call synchronous extractProgramGraph',
    )
    assert.match(
      plannerSrc,
      /\bextractProgramGraphInWorker\s*\(/,
      'exec-recon-planner.ts must offload ProgramGraph extraction to extractProgramGraphInWorker',
    )
    assert.match(
      plannerSrc,
      /async\s+seedCapabilityLedgerInvariants\s*\(/,
      'seedCapabilityLedgerInvariants must be async',
    )
    const collectMatch = /async\s+function\s+collectBoundedRepoSourceFiles\b[\s\S]*?\n\}/.exec(plannerSrc)
    assert.ok(collectMatch, 'collectBoundedRepoSourceFiles must be an async function')
    assert.equal(
      /\b(?:existsSync|readdirSync|readFileSync|statSync|lstatSync)\b/.test(collectMatch[0]),
      false,
      'collectBoundedRepoSourceFiles must not use synchronous fs.*Sync APIs',
    )

    // Verify zero dynamic `new RegExp(` in `src/server/program-graph.ts`
    const graphSrc = readFileSync(join(SERVER_DIR, 'program-graph.ts'), 'utf8')
    assert.equal(
      /\bnew\s+RegExp\s*\(/.test(graphSrc),
      false,
      'program-graph.ts must contain zero dynamic new RegExp() calls',
    )
  })
})

describe('R3-H-12 linear scaling: unterminated call-site openers & nested calls in ProgramGraph', () => {
  test('32 KB vs 64 KB vs 128 KB unterminated Express & FastAPI openers complete in < 150ms with linear scaling', () => {
    // Warm up JIT + regex engine once
    extractProgramGraph({
      files: [
        { path: 'warmup.ts', content: "const app = express()\napp.get('/ok', okHandler)\n" },
        { path: 'warmup.py', content: "app = FastAPI()\n@app.get('/ok')\ndef ok(): pass\n" },
      ],
    })

    const sizes = [32 * 1024, 64 * 1024, 128 * 1024] as const

    // 1. Unterminated Express method-call openers
    const expressTimes: number[] = []
    for (const size of sizes) {
      const content = makeRepeatFile('const app = express()\n', "app.get('/api/item', ", size)
      let graph!: ReturnType<typeof extractProgramGraph>
      const elapsed = measureMs(() => {
        graph = extractProgramGraph({ files: [{ path: `src/unclosed_${size}.ts`, content }] })
      })
      expressTimes.push(elapsed)
      assert.ok(
        elapsed < 150,
        `Express unterminated ${size / 1024} KB took ${elapsed.toFixed(2)}ms (expected < 150ms)`,
      )
      assert.equal(graph.routes.length, 0)
    }
    const expressRatio = expressTimes[2]! / Math.max(1, expressTimes[0]!)
    assert.ok(
      expressRatio < 10,
      `Express scaling 128KB/32KB ratio=${expressRatio.toFixed(2)}x (${expressTimes.map(t => t.toFixed(1)).join(' / ')} ms) — expected linear (< 10x, not quadratic ~16x)`,
    )

    // 2. Unterminated FastAPI decorator openers
    const fastApiTimes: number[] = []
    for (const size of sizes) {
      const content = makeRepeatFile('app = FastAPI()\n', "@app.get('/api/item', ", size)
      let graph!: ReturnType<typeof extractProgramGraph>
      const elapsed = measureMs(() => {
        graph = extractProgramGraph({ files: [{ path: `app/unclosed_${size}.py`, content }] })
      })
      fastApiTimes.push(elapsed)
      assert.ok(
        elapsed < 150,
        `FastAPI unterminated ${size / 1024} KB took ${elapsed.toFixed(2)}ms (expected < 150ms)`,
      )
      assert.equal(graph.routes.length, 0)
    }
    const fastApiRatio = fastApiTimes[2]! / Math.max(1, fastApiTimes[0]!)
    assert.ok(
      fastApiRatio < 10,
      `FastAPI scaling 128KB/32KB ratio=${fastApiRatio.toFixed(2)}x (${fastApiTimes.map(t => t.toFixed(1)).join(' / ')} ms) — expected linear (< 10x, not quadratic ~16x)`,
    )

    // 3. Nested closed Express openers (`app.get(app.get(...)))`) also stay strictly linear
    const nestedCount = 6_000
    const nestedContent = `const app = express()\n${'app.get('.repeat(nestedCount)}${')'.repeat(nestedCount)}\n`
    const nestedElapsed = measureMs(() => {
      extractProgramGraph({ files: [{ path: 'src/nested_closed.ts', content: nestedContent }] })
    })
    assert.ok(nestedElapsed < 150, `Nested closed Express openers took ${nestedElapsed.toFixed(2)}ms (expected < 150ms)`)

    // 4. Unterminated Flask, Django, Nest, Gin, Chi openers all complete fast
    const otherCases = [
      { path: 'app/flask_evil.py', content: makeRepeatFile('app = Flask(__name__)\n', "@app.route('/x', ", 128 * 1024) },
      { path: 'app/django_evil.py', content: makeRepeatFile('urlpatterns = [\n', "path('items/', ", 128 * 1024) },
      { path: 'src/nest_evil.ts', content: makeRepeatFile('', "@Controller('/x')\n", 128 * 1024) },
      { path: 'cmd/gin_evil.go', content: makeRepeatFile('r := gin.Default()\n', 'r.GET("/x", ', 128 * 1024) },
      { path: 'cmd/chi_evil.go', content: makeRepeatFile('r := chi.NewRouter()\n', 'r.Get("/x", ', 128 * 1024) },
    ]
    for (const c of otherCases) {
      const elapsed = measureMs(() => {
        extractProgramGraph({ files: [c] })
      })
      assert.ok(elapsed < 150, `${c.path} took ${elapsed.toFixed(2)}ms (expected < 150ms)`)
    }

    // 5. Legitimate Express & FastAPI routes still extract cleanly
    const validGraph = extractProgramGraph({
      files: [
        {
          path: 'src/valid.ts',
          content: [
            'const app = express()',
            'app.use(requireAuth)',
            "app.get('/api/orders/:id', checkTenant, (req, res) => { return res.json(req.params.id) })",
            "app.route('/api/items').get(listItems).post(requireAdmin, createItem)",
          ].join('\n'),
        },
        {
          path: 'app/valid.py',
          content: [
            'app = FastAPI()',
            "@app.get('/api/users/{user_id}', dependencies=[Depends(require_auth)])",
            'async def get_user(user_id: str):',
            '    return {"id": user_id}',
          ].join('\n'),
        },
      ],
    })
    assert.ok(validGraph.routes.some(r => r.framework === 'express' && r.method === 'GET' && r.path === '/api/orders/:id'))
    assert.ok(validGraph.routes.some(r => r.framework === 'express' && r.method === 'POST' && r.path === '/api/items'))
    assert.ok(validGraph.routes.some(r => r.framework === 'fastapi' && r.method === 'GET' && r.path === '/api/users/:user_id'))
  })
})

describe('R3-H-12 bounded compose Host( / PathPrefix( extraction', () => {
  test('adversarial Traefik Host(/PathPrefix( compose labels do not backtrack or allocate unbounded captures while preserving valid mappings', async t => {
    t.after(() => closeSharedUntrustedComputePool())

    const evilSingleLine = [
      'services:',
      '  billing:',
      '    labels:',
      `      - "traefik.http.routers.evil1.rule=${'Host(   '.repeat(15_000)}"`,
      `      - "traefik.http.routers.evil2.rule=Host(\`${'a'.repeat(60_000)}\`)"`,
      `      - "traefik.http.routers.evil3.rule=${'PathPrefix(   '.repeat(15_000)}"`,
      '      - "traefik.http.routers.ok.rule=Host(`billing.shop.test`, `billing-alt.shop.test`) && PathPrefix(`/billing`)"',
    ].join('\n')

    const manyLines = [
      'services:',
      '  edge:',
      '    labels:',
      ...Array.from({ length: 12_000 }, (_, i) => `      - "traefik.http.routers.r${i}.rule=Host(\`h${i}.example.test\`) && PathPrefix(\`/p${i}\`)"`),
    ].join('\n')

    let mappings!: ReturnType<typeof mapServicesToOrigins>
    const elapsed = measureMs(() => {
      mappings = mapServicesToOrigins({
        services: [
          { name: 'billing', root: 'services/billing' },
          { name: 'edge', root: 'services/edge' },
        ],
        origins: ['https://billing.shop.test', 'https://billing-alt.shop.test', 'https://h0.example.test'],
        composeFiles: [
          { path: 'services/billing/docker-compose.yml', content: evilSingleLine },
          { path: 'services/edge/docker-compose.yml', content: manyLines },
        ],
      })
    })

    assert.ok(elapsed < 100, `Adversarial compose Host( parsing took ${elapsed.toFixed(2)}ms (expected < 100ms)`)
    const billing = mappings.find(m => m.service === 'billing')
    assert.equal(billing?.origin, 'https://billing.shop.test')
    assert.equal(billing?.pathPrefix, '/billing')
    assert.equal(billing?.confidence, 'exact')

    const edge = mappings.find(m => m.service === 'edge')
    assert.equal(edge?.origin, 'https://h0.example.test')
    assert.equal(edge?.pathPrefix, '/p0')

    // Worker-isolated extractProgramGraphInWorker also handles adversarial files safely off the host thread
    const workerGraph = await extractProgramGraphInWorker({
      files: [
        { path: 'src/evil.ts', content: makeRepeatFile('const app = express()\n', "app.get('/x', ", 128 * 1024) },
        { path: 'src/good.ts', content: "const app = express()\napp.get('/api/health', healthHandler)\n" },
      ],
      repo: 'adversarial-repo',
    })
    assert.ok(workerGraph.routes.some(r => r.path === '/api/health'))
  })
})

describe('R3-H-12 async seedCapabilityLedgerInvariants off the host event loop', () => {
  test('seeds white-box Layer-2 capability-ledger invariants asynchronously without blocking the event loop and supports staticSnapshot reuse', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-h12-seed-'))
    t.after(async () => {
      await closeSharedUntrustedComputePool()
      rmSync(dir, { recursive: true, force: true })
    })

    // Populate a mounted repo with valid multi-service source + 25 adversarial 64 KB unterminated-opener files
    mkdirSync(join(dir, 'app', 'services', 'api'), { recursive: true })
    mkdirSync(join(dir, 'app', 'services', 'noise'), { recursive: true })

    writeFileSync(
      join(dir, 'app', 'services', 'api', 'routes.ts'),
      [
        'const app = express()',
        "app.get('/api/v1/invoices/:id', requireAuth, requireTenant, getInvoice)",
        "app.post('/api/v1/invoices/export', exportInvoices)",
        "app.delete('/api/v1/invoices/:id', requireAuth, requireAdmin, deleteInvoice)",
      ].join('\n'),
      'utf8',
    )
    writeFileSync(
      join(dir, 'app', 'docker-compose.yml'),
      [
        'services:',
        '  api:',
        '    build: ./services/api',
        '    ports:',
        '      - "4000:4000"',
        '    labels:',
        '      - "traefik.http.routers.api.rule=Host(`api.synth.test`)"',
      ].join('\n'),
      'utf8',
    )
    const hostilePayload = makeRepeatFile('const app = express()\n', "app.get('/api/unclosed', ", 64 * 1024)
    for (let i = 0; i < 25; i += 1) {
      writeFileSync(join(dir, 'app', 'services', 'noise', `hostile_${i}.ts`), hostilePayload, 'utf8')
    }

    const ORIGIN_API = 'https://api.synth.test'
    const { storage } = makeStore(t, 'kovo-r3-h12-store-')
    const { runId } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
    const run = storage.run(runId)

    const execution = new Execution(storage, { backend: stubBackend(), maxDurationMs: 600_000 })
    t.after(() => execution.stop())
    const planner = getPlanner(execution)

    // Probe event-loop responsiveness while async seedCapabilityLedgerInvariants runs
    let ticks = 0
    let maxLagMs = 0
    let lastTick = performance.now()
    const timer = setInterval(() => {
      const now = performance.now()
      const lag = now - lastTick
      if (lag > maxLagMs) maxLagMs = lag
      lastTick = now
      ticks += 1
    }, 5)

    let result!: Awaited<ReturnType<ExecReconPlanner['seedCapabilityLedgerInvariants']>>
    try {
      const promise = planner.seedCapabilityLedgerInvariants(run, {
        reposDir: dir,
        mountedRepos: ['app'],
        approvedOrigins: new Set([ORIGIN_API]),
        promoteWave1Chains: true,
      })
      assert.ok(promise instanceof Promise, 'seedCapabilityLedgerInvariants must return a Promise')
      result = await promise
    } finally {
      clearInterval(timer)
    }

    assert.equal(result.mode, 'white-box')
    assert.ok(result.seededCount >= 1, `expected >= 1 white-box invariant seed, got ${result.seededCount}`)
    assert.ok(ticks >= 1, `expected event-loop timer ticks during async seeding, got ${ticks}`)
    assert.ok(maxLagMs < 250, `event-loop max lag during async seeding was ${maxLagMs.toFixed(1)}ms (expected < 250ms)`)

    const ledgerNodes = storage.capabilityLedger(runId).listCapabilities()
    assert.ok(ledgerNodes.length >= result.seededCount)
    assert.ok(
      ledgerNodes.every(n => n.promotionStatus === 'capability_only'),
      'all seeded capability ledger nodes must remain strictly quarantined as capability_only',
    )

    // Reusing an already-extracted StaticWorkspaceSnapshot works with zero disk re-walk / zero worker re-parse
    const snap = await buildStaticWorkspaceSnapshotInWorker(dir, { workerTimeoutMs: 10_000 })
    const { runId: runId2 } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
    const snapResult = await planner.seedCapabilityLedgerInvariants(storage.run(runId2), {
      staticSnapshot: snap,
      approvedOrigins: new Set([ORIGIN_API]),
      promoteWave1Chains: true,
    })
    assert.equal(snapResult.mode, 'white-box')
    assert.ok(snapResult.seededCount >= 1, 'staticSnapshot reuse must still seed Layer-2 invariants accurately')

    // ensureWave1InvariantChainSteps with a mounted repo never blocks the host event loop synchronously
    const { runId: runId3 } = await setupApprovedRun(storage, { seeds: [ORIGIN_API], tier: 2 })
    const run3 = storage.run(runId3)
    const origMount = (planner as unknown as { host: { projectReposMount: (id: string) => { reposDir?: string; mountedRepos: string[] } } }).host.projectReposMount
    ;(planner as unknown as { host: { projectReposMount: (id: string) => { reposDir?: string; mountedRepos: string[] } } }).host.projectReposMount = () => ({
      reposDir: dir,
      mountedRepos: ['app'],
    })
    try {
      let syncCount = -1
      const syncMs = measureMs(() => {
        syncCount = planner.ensureWave1InvariantChainSteps(run3, new Set([ORIGIN_API]))
      })
      assert.equal(syncCount, 0, 'mounted-repo ensureWave1InvariantChainSteps must offload asynchronously instead of running sync')
      assert.ok(syncMs < 25, `ensureWave1InvariantChainSteps blocked for ${syncMs.toFixed(2)}ms (expected < 25ms)`)
      // Wait for the scheduled background seed promise to settle cleanly before teardown
      const inFlight = (planner as unknown as { invariantsSeedingInFlight: Map<string, Promise<void>> }).invariantsSeedingInFlight.get(runId3)
      if (inFlight) await inFlight
      assert.ok(
        storage.capabilityLedger(runId3).listCapabilities().length >= 1,
        'background async seeding scheduled by ensureWave1InvariantChainSteps must populate CapabilityLedger',
      )
    } finally {
      ;(planner as unknown as { host: { projectReposMount: (id: string) => { reposDir?: string; mountedRepos: string[] } } }).host.projectReposMount = origMount
    }
  })
})
