/**
 * WS-11 (`R4-H-15` & `R4-H-16`) fast class-level stress & static-lint regression guards:
 * 1. R4-H-15: `search_repo` executes off the host event loop inside `UntrustedComputePool` with
 *    hard wall-clock `searchRepoDeadlineMs` worker termination, `searchRepoMaxBytes` budget
 *    enforcement, structured truncation/timeout telemetry, and responsive host event-loop ticks.
 * 2. R4-H-16: Shared O(n) `buildLineIndex` / `lineAtOffset` / `extractLineRange` helper; linear
 *    `< 250ms` adversarial scaling across `buildGuardAsymmetryMatrix`, `buildTrustBoundaryGraph`,
 *    `synthesizeInvariants`, Dockerfile `EXPOSE` (`mapServicesToOrigins`), and
 *    `inferServerActionPageRoute` (`extractStaticFrameworkRoutes`); plus off-host worker APIs
 *    (`synthesizeInvariantsInWorker`, `mapServicesToOriginsInWorker`, `extractStaticFrameworkRoutesInWorker`).
 * 3. Static lint extending R3-H-12: bans `.slice(0, ...).split('\n')` on repo content across
 *    `src/server/{invariant-synthesizer,program-graph,phase0-recon}.ts`, bans multiline `/^\s*EXPOSE/`,
 *    bans raw `.code.includes(` in `inferServerActionPageRoute`, and verifies `search_repo` routes
 *    through `searchRepoHostInWorker` + `resolveRunSafetyBudgets`.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'
import { describe, test } from 'node:test'
import { buildWorkerTools, searchRepoHostInWorker } from '../src/server/agent-session.ts'
import {
  buildGuardAsymmetryMatrix,
  buildTrustBoundaryGraph,
  synthesizeInvariants,
} from '../src/server/invariant-synthesizer.ts'
import { extractStaticFrameworkRoutes } from '../src/server/phase0-recon.ts'
import {
  buildLineIndex,
  extractLineRange,
  extractProgramGraph,
  lineAtOffset,
  mapServicesToOrigins,
} from '../src/server/program-graph.ts'
import { RUN_SAFETY_BUDGET_DEFAULTS, resolveRunSafetyBudgets } from '../src/server/run-safety-budgets.ts'
import {
  closeSharedUntrustedComputePool,
  extractStaticFrameworkRoutesInWorker,
  mapServicesToOriginsInWorker,
  synthesizeInvariantsInWorker,
} from '../src/server/untrusted-compute-pool.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const SERVER_DIR = join(REPO_ROOT, 'src', 'server')

function measureMs(fn: () => void): number {
  const start = performance.now()
  fn()
  return performance.now() - start
}

function makeRepeatChunk(header: string, chunk: string, targetBytes: number): string {
  const remaining = Math.max(0, targetBytes - header.length)
  const count = Math.ceil(remaining / chunk.length)
  return header + chunk.repeat(count).slice(0, remaining)
}

describe('WS-11 static lint (R4-H-15 & R4-H-16)', () => {
  test('bans per-match .slice(0, ...).split(\\n) in post-graph repo scanners and verifies worker/budget wiring', () => {
    const postGraphFiles = [
      'invariant-synthesizer.ts',
      'program-graph.ts',
      'phase0-recon.ts',
    ] as const

    const sliceSplitViolations: string[] = []
    const sliceSplitRe = /\.slice\s*\(\s*0\s*,[^)\n]{1,120}\)\s*\.split\s*\(\s*(?:['"`]\\n['"`]|\/\\r\?\\n\/)\s*\)/
    for (const file of postGraphFiles) {
      const src = readFileSync(join(SERVER_DIR, file), 'utf8')
      const lines = src.split('\n')
      for (let i = 0; i < lines.length; i += 1) {
        const codePart = lines[i]!.replace(/\/\/.*$/, '').replace(/^\s*\*.*$/, '')
        if (sliceSplitRe.test(codePart)) {
          sliceSplitViolations.push(`src/server/${file}:${i + 1}: ${lines[i]!.trim()}`)
        }
      }
    }
    assert.deepEqual(
      sliceSplitViolations,
      [],
      `Found forbidden quadratic per-match .slice(0, ...).split('\\n') patterns:\n${sliceSplitViolations.join('\n')}`,
    )

    // Verify `invariant-synthesizer.ts` imports and uses the shared `buildLineIndex` / `lineAtOffset` helper
    const synthSrc = readFileSync(join(SERVER_DIR, 'invariant-synthesizer.ts'), 'utf8')
    assert.match(synthSrc, /\bbuildLineIndex\b/, 'invariant-synthesizer.ts must use shared buildLineIndex')
    assert.match(synthSrc, /\blineAtOffset\b/, 'invariant-synthesizer.ts must use shared lineAtOffset')
    assert.match(synthSrc, /\bextractLineRange\b/, 'invariant-synthesizer.ts must use shared extractLineRange')

    // Verify `program-graph.ts` no longer uses multiline-anchored /^\s*EXPOSE/ regex
    const graphSrc = readFileSync(join(SERVER_DIR, 'program-graph.ts'), 'utf8')
    assert.equal(
      /\/\^\\s\*EXPOSE/.test(graphSrc),
      false,
      'program-graph.ts must not use multiline-anchored /^\\s*EXPOSE/ regex',
    )

    // Verify `phase0-recon.ts` inferServerActionPageRoute does not do per-action raw `.code.includes(` scans
    const phase0Src = readFileSync(join(SERVER_DIR, 'phase0-recon.ts'), 'utf8')
    const inferMatch = /const inferServerActionPageRoute\s*=\s*\([^)]*\)[^{]*\{[\s\S]*?\n  \}/.exec(phase0Src)
    assert.ok(inferMatch, 'phase0-recon.ts must define inferServerActionPageRoute')
    assert.equal(
      /\.code\.includes\s*\(/.test(inferMatch[0]),
      false,
      'inferServerActionPageRoute must use single-pass indexed page tokens instead of .code.includes()',
    )

    // Verify `agent-session.ts` routes live `search_repo` tool through `searchRepoHostInWorker` and `resolveRunSafetyBudgets`
    const sessionSrc = readFileSync(join(SERVER_DIR, 'agent-session.ts'), 'utf8')
    assert.match(sessionSrc, /\bresolveRunSafetyBudgets\s*\(/, 'agent-session.ts must consume resolveRunSafetyBudgets')
    assert.match(sessionSrc, /\bsearchRepoHostInWorker\s*\(/, 'agent-session.ts must route search_repo through searchRepoHostInWorker')
    const toolMatch = /name:\s*'search_repo'[\s\S]{0,1600}execute:\s*async[\s\S]{0,400}\}/.exec(sessionSrc)
    assert.ok(toolMatch, 'agent-session.ts must register search_repo tool')
    assert.match(
      toolMatch[0],
      /(?:searchRepoHostInWorker|HOST_REPO_SEARCH_RUNNERS\.worker)\s*\(/,
      'live search_repo tool handler must invoke searchRepoHostInWorker, not sync searchRepoHost',
    )
    assert.equal(
      /\bnew\s+RegExp\s*\(/.test(sessionSrc),
      false,
      'agent-session.ts must contain zero dynamic new RegExp() calls',
    )
  })
})

describe('R4-H-15: off-host search_repo worker thread with hard deadline and byte budgets', () => {
  test('long-line repo tree + single-quantifier regex runs off the host event loop under searchRepoDeadlineMs with structured telemetry', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r4-h15-search-'))
    t.after(async () => {
      await closeSharedUntrustedComputePool()
      rmSync(dir, { recursive: true, force: true })
    })

    const repoSrc = join(dir, 'acme', 'longlines', 'src')
    mkdirSync(repoSrc, { recursive: true })
    // 1. Moderately sized long-line repo + single-quantifier regex finds real matches cleanly
    const longLine = `${'a'.repeat(4_090)}\n`
    writeFileSync(join(repoSrc, 'blob_00.txt'), longLine.repeat(12), 'utf8')
    writeFileSync(join(repoSrc, 'z_target.ts'), `export const ok = 'aaaa_CANARY_HIT_42'\n`, 'utf8')

    // Default RunSafetyBudgets search with single-quantifier regex finishes well under deadlineMs
    // while keeping host event-loop timer responsive.
    const budgets = resolveRunSafetyBudgets()
    assert.equal(budgets.searchRepoDeadlineMs, RUN_SAFETY_BUDGET_DEFAULTS.searchRepoDeadlineMs)
    assert.equal(budgets.searchRepoMaxBytes, RUN_SAFETY_BUDGET_DEFAULTS.searchRepoMaxBytes)

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

    const start = performance.now()
    let res!: Awaited<ReturnType<typeof searchRepoHostInWorker>>
    try {
      res = await searchRepoHostInWorker(dir, {
        query: 'a+_CANARY_HIT_[0-9]+',
        regex: true,
      })
    } finally {
      clearInterval(timer)
    }
    const elapsed = performance.now() - start

    assert.ok(
      elapsed < budgets.searchRepoDeadlineMs,
      `Long-line single-quantifier search_repo took ${elapsed.toFixed(1)}ms (expected < ${budgets.searchRepoDeadlineMs}ms)`,
    )
    assert.ok(maxLagMs < 150, `Host event-loop lag spiked to ${maxLagMs.toFixed(1)}ms during worker search_repo`)
    assert.ok(ticks >= 1, `Expected host timer ticks during off-host search_repo, got ${ticks}`)
    assert.equal(res.mode, 'regex')
    assert.equal(res.deadlineMs, budgets.searchRepoDeadlineMs)
    assert.equal(res.maxBytes, budgets.searchRepoMaxBytes)
    assert.ok(res.bytesScanned > 0)
    assert.equal(res.matchCount, 1)
    assert.equal(res.matches[0]?.path, '/repos/acme/longlines/src/z_target.ts')

    // 2. Hard byte budget enforcement emits structured `max_bytes` truncation telemetry
    const byteDir = join(dir, 'acme', 'bytes')
    mkdirSync(byteDir, { recursive: true })
    const chunk256k = longLine.repeat(64)
    for (let i = 0; i < 4; i += 1) {
      writeFileSync(join(byteDir, `b_${i}.txt`), chunk256k, 'utf8')
    }
    const byteCapped = await searchRepoHostInWorker(
      dir,
      { query: 'CANARY_HIT', regex: false, pathPrefix: '/repos/acme/bytes' },
      { maxBytes: 300 * 1024 },
    )
    assert.equal(byteCapped.truncated, true)
    assert.equal(byteCapped.truncationReason, 'max_bytes')
    assert.ok(byteCapped.bytesScanned <= 300 * 1024 + 512 * 1024)

    // 3. Adversarial ~4 MiB long-line tree + single-quantifier regex hits hard wall-clock deadline
    //    and terminates cleanly off-host without stalling the host event loop or poisoning the pool.
    const heavyDir = join(dir, 'acme', 'heavy')
    mkdirSync(heavyDir, { recursive: true })
    const heavyChunk = longLine.repeat(120) // ~490 KiB per file
    for (let i = 0; i < 8; i += 1) {
      writeFileSync(join(heavyDir, `h_${String(i).padStart(2, '0')}.txt`), heavyChunk, 'utf8')
    }

    let timeoutTicks = 0
    let timeoutLagMs = 0
    let lastTimeoutTick = performance.now()
    const timeoutTimer = setInterval(() => {
      const now = performance.now()
      const lag = now - lastTimeoutTick
      if (lag > timeoutLagMs) timeoutLagMs = lag
      lastTimeoutTick = now
      timeoutTicks += 1
    }, 5)

    const timeoutStart = performance.now()
    let timedOutRes!: Awaited<ReturnType<typeof searchRepoHostInWorker>>
    try {
      timedOutRes = await searchRepoHostInWorker(
        dir,
        { query: 'a+_CANARY_NEVER_FOUND_[0-9]+', regex: true, pathPrefix: '/repos/acme/heavy' },
        { deadlineMs: 150, maxBytes: 16 * 1024 * 1024 },
      )
    } finally {
      clearInterval(timeoutTimer)
    }
    const timeoutElapsed = performance.now() - timeoutStart

    assert.ok(
      timeoutElapsed < budgets.searchRepoDeadlineMs && timeoutElapsed < 750,
      `Adversarial long-line search_repo took ${timeoutElapsed.toFixed(1)}ms (expected fast termination < 750ms)`,
    )
    assert.ok(timeoutTicks >= 5, `Expected responsive host timer ticks during worker termination, got ${timeoutTicks}`)
    assert.ok(timeoutLagMs < 150, `Host event-loop lag spiked to ${timeoutLagMs.toFixed(1)}ms during timed-out search_repo`)
    assert.equal(timedOutRes.deadlineMs, 150)
    assert.equal(timedOutRes.timedOut, true)
    assert.equal(timedOutRes.truncated, true)
    assert.equal(timedOutRes.truncationReason, 'deadline_exceeded')

    // Pool recovers cleanly after worker termination
    const followUp = await searchRepoHostInWorker(dir, {
      query: 'CANARY_HIT_42',
      pathPrefix: '/repos/acme/longlines/src/z_target.ts',
    })
    assert.equal(followUp.matchCount, 1)
    assert.equal(followUp.timedOut, undefined)

    // 4. Live `search_repo` tool built by `buildWorkerTools` works asynchronously off-host
    const rootAbort = new AbortController()
    const tools = buildWorkerTools({}, text => text, rootAbort.signal, 8_192, () => {}, { reposDir: dir })
    const searchTool = tools.find(tool => tool.name === 'search_repo')
    assert.ok(searchTool, 'buildWorkerTools must expose search_repo when reposDir is provided')
    const toolOut = await searchTool.execute(
      { query: 'CANARY_HIT_42', pathPrefix: '/repos/acme/longlines/src/z_target.ts' },
      {} as never,
      { abortSignal: rootAbort.signal } as never,
    )
    const serialized = typeof toolOut === 'string' ? toolOut : JSON.stringify(toolOut)
    assert.match(serialized, /z_target\.ts/)
  })
})

describe('R4-H-16: linear O(n) post-graph repo-content scanners & off-host worker pipeline', () => {
  test('shared buildLineIndex / lineAtOffset / extractLineRange matches exact line numbers and bounds single-line windows', () => {
    const sample = 'line1\nline2\nline3\r\nline4\n'
    const idx = buildLineIndex(sample)
    for (let offset = 0; offset <= sample.length; offset += 1) {
      const expected = sample.slice(0, offset).split('\n').length
      assert.equal(lineAtOffset(idx, offset), expected, `lineAtOffset mismatch at offset ${offset}`)
    }
    assert.equal(extractLineRange(sample, idx, 2, 4), 'line2\nline3\r')

    // Single-line 128 KB minified file extracts bounded window in O(1)
    const hugeOneLine = `${'x'.repeat(64_000)}MARKER_TARGET${'y'.repeat(64_000)}`
    const oneLineIdx = buildLineIndex(hugeOneLine)
    const win = extractLineRange(hugeOneLine, oneLineIdx, 1, 10, 1024, 64_000)
    assert.ok(win.length <= 1024)
    assert.ok(win.includes('MARKER_TARGET'))
  })

  test('128 KB adversarial file through buildGuardAsymmetryMatrix, buildTrustBoundaryGraph & synthesizeInvariants finishes < 250ms', async t => {
    t.after(() => closeSharedUntrustedComputePool())

    const validHeader = [
      "const app = express()",
      "app.get('/api/orders/:id', requireAuth, requireTenant, getOrder)",
      "app.post('/api/orders/bulk', bulkOrders)",
      "ws.on('orders:sync', (msg) => { db.query(msg) })",
      "fetch('http://billing.internal/charge', { headers: { 'x-user-id': req.user } })",
    ].join('\n') + '\n'

    // 128 KB packed with thousands of auxiliary WS/GraphQL/outbound matches (worst case for quadratic slice/split)
    const adversarialContent = makeRepeatChunk(
      validHeader,
      "ws.on('order_evt', () => { fetch('http://billing.internal/ping') })\n",
      128 * 1024,
    )
    const singleLineAdversarial = makeRepeatChunk(
      "ws.on('order_sync', () => { db.query(x) }); ",
      "ws.on('order_evt', () => { fetch('http://billing.internal/ping') }); ",
      128 * 1024,
    )

    const graph = extractProgramGraph({
      files: [{ path: 'services/api/routes.ts', content: validHeader }],
    })
    const sourceFiles = [
      { path: 'services/api/routes.ts', content: adversarialContent },
      { path: 'services/api/minified.ts', content: singleLineAdversarial },
    ]
    const services = [
      { name: 'api', root: 'services/api' },
      { name: 'billing', root: 'services/billing' },
    ]

    let matrixRes!: ReturnType<typeof buildGuardAsymmetryMatrix>
    const matrixMs = measureMs(() => {
      matrixRes = buildGuardAsymmetryMatrix(graph, { sourceFiles })
    })
    assert.ok(matrixMs < 250, `buildGuardAsymmetryMatrix on 2x128 KB adversarial files took ${matrixMs.toFixed(1)}ms (expected < 250ms)`)
    assert.ok(matrixRes.hypotheses.length >= 1, 'guard asymmetry hypotheses must still be detected')

    let boundaryRes!: ReturnType<typeof buildTrustBoundaryGraph>
    const boundaryMs = measureMs(() => {
      boundaryRes = buildTrustBoundaryGraph(graph, { sourceFiles, services })
    })
    assert.ok(boundaryMs < 250, `buildTrustBoundaryGraph on 2x128 KB adversarial files took ${boundaryMs.toFixed(1)}ms (expected < 250ms)`)
    assert.ok(boundaryRes.edges.length >= 1, 'trust boundary edges must still be detected')

    let synthRes!: ReturnType<typeof synthesizeInvariants>
    const synthMs = measureMs(() => {
      synthRes = synthesizeInvariants({ mode: 'white-box', graph, sourceFiles, services })
    })
    assert.ok(synthMs < 250, `synthesizeInvariants on 2x128 KB adversarial files took ${synthMs.toFixed(1)}ms (expected < 250ms)`)
    assert.ok(synthRes.hypotheses.length >= 1)

    // Worker-offloaded `synthesizeInvariantsInWorker` (WS-10 API) produces matching results off-host
    const workerSynth = await synthesizeInvariantsInWorker(
      { mode: 'white-box', graph, sourceFiles, services },
      { timeoutMs: 5_000 },
    )
    assert.equal(workerSynth.hypotheses.length, synthRes.hypotheses.length)
    assert.equal(workerSynth.capabilitySeeds.length, synthRes.capabilitySeeds.length)
  })

  test('256 KB adversarial Dockerfile EXPOSE scan finishes < 250ms synchronously and in worker', async t => {
    t.after(() => closeSharedUntrustedComputePool())

    // Classic multiline /^\s*EXPOSE/ ReDoS input: 256+ KB of alternating newlines and spaces + real EXPOSE at EOF
    const evilDockerfile = `${'\n   \t  '.repeat(40_000)}\n  EXPOSE   8080/tcp 8443\n`
    assert.ok(evilDockerfile.length >= 256 * 1024)

    const input = {
      services: [{ name: 'api', root: 'services/api' }],
      origins: ['http://127.0.0.1:8080', 'https://127.0.0.1:8443'],
      dockerfiles: [{ path: 'services/api/Dockerfile', content: evilDockerfile }],
    }

    let mappings!: ReturnType<typeof mapServicesToOrigins>
    const exposeMs = measureMs(() => {
      mappings = mapServicesToOrigins(input)
    })
    assert.ok(exposeMs < 250, `256 KB adversarial Dockerfile EXPOSE scan took ${exposeMs.toFixed(1)}ms (expected < 250ms)`)
    assert.equal(mappings[0]?.origin, 'http://127.0.0.1:8080')
    assert.equal(mappings[0]?.confidence, 'port')

    // Worker-offloaded `mapServicesToOriginsInWorker` produces identical mapping
    const workerMappings = await mapServicesToOriginsInWorker(input, { timeoutMs: 5_000 })
    assert.deepEqual(workerMappings, mappings)
  })

  test('many-action adversarial Next.js page through inferServerActionPageRoute finishes < 250ms synchronously and in worker', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-r4-h16-next-'))
    t.after(async () => {
      await closeSharedUntrustedComputePool()
      rmSync(dir, { recursive: true, force: true })
    })

    // Create 6 large 128 KB Next.js pages + a server-actions module with 1,200 exported actions
    const appBase = join(dir, 'acme', 'web', 'src', 'app')
    const pageNames = ['overview', 'reports', 'settings', 'invoices', 'members', 'payouts'] as const
    for (let p = 0; p < pageNames.length; p += 1) {
      const pageDir = join(appBase, pageNames[p]!)
      mkdirSync(pageDir, { recursive: true })
      const filler = 'export const noise = "lorem ipsum dolor sit amet consectetur adipiscing elit";\n'.repeat(1_700)
      const importLine = pageNames[p] === 'payouts'
        ? "import { approvePayoutAction } from '../billing/order-actions'\nexport default function Page() { return approvePayoutAction }\n"
        : `export default function Page${p}() { return null }\n`
      writeFileSync(join(pageDir, 'page.tsx'), `${filler}${importLine}`, 'utf8')
    }

    const actionsDir = join(appBase, 'billing')
    mkdirSync(actionsDir, { recursive: true })
    const actionDecls = [
      "'use server'",
      ...Array.from({ length: 1_200 }, (_, i) => `export async function generatedAction_${i}(formData: FormData) { return ${i} }`),
      'export async function approvePayoutAction(formData: FormData) { return formData }',
    ].join('\n')
    writeFileSync(join(actionsDir, 'order-actions.ts'), actionDecls, 'utf8')

    let extracted!: ReturnType<typeof extractStaticFrameworkRoutes>
    const elapsed = measureMs(() => {
      extracted = extractStaticFrameworkRoutes(dir)
    })
    assert.ok(elapsed < 250, `Adversarial many-action Next.js page route inference took ${elapsed.toFixed(1)}ms (expected < 250ms)`)
    const matchedAction = extracted.serverActions.find(a => a.actionName === 'approvePayoutAction')
    assert.ok(matchedAction, 'approvePayoutAction server action must be extracted')
    assert.equal(matchedAction.pageRoute, '/payouts', 'indexed token lookup must link action to importing /payouts page')
    const fallbackAction = extracted.serverActions.find(a => a.actionName === 'generatedAction_0')
    assert.equal(fallbackAction?.pageRoute, '/billing', 'unimported action must fall back to its /app directory route')

    // Worker-offloaded `extractStaticFrameworkRoutesInWorker` produces identical server action links
    const workerExtracted = await extractStaticFrameworkRoutesInWorker({ reposDir: dir }, { timeoutMs: 5_000 })
    const workerAction = workerExtracted.serverActions.find(a => a.actionName === 'approvePayoutAction')
    assert.equal(workerAction?.pageRoute, '/payouts')
    assert.equal(workerExtracted.serverActions.length, extracted.serverActions.length)
  })
})
