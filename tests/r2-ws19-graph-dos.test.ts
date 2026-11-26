/**
 * Adversarial DoS, ReDoS, deep-nesting, OOM amplification, subprocess crash isolation,
 * and prototype-pollution ingress regression tests (`WS-19` / Move D: R2-H-23, R2-H-24, R2-H-25, R2-C-2).
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { describe, test } from 'node:test'
import { pathToFileURL } from 'node:url'
import {
  extractJsonFieldNames,
  harvestConfigParamBindings,
  harvestJsRequestParams,
  harvestRouteMapParamHints,
  hasPrototypePollutionSegment,
  inferXhrRequestShape,
  isUsefulParamName,
} from '../src/server/phase0-recon.ts'
import { extractProgramGraph } from '../src/server/program-graph.ts'
import { buildStaticWorkspaceSnapshotInWorker } from '../src/server/static-workspace-snapshot.ts'
import {
  UntrustedComputeAbortedError,
  UntrustedComputePool,
  UntrustedComputeTimeoutError,
  UntrustedComputeWorkerError,
  closeSharedUntrustedComputePool,
  jsHarvestInWorker,
} from '../src/server/untrusted-compute-pool.ts'
import {
  exceedsJsAstNestingDepth,
  jsHarvest,
  secretScan,
} from '../worker/analyzers.ts'

function measureMs(fn: () => void): number {
  const start = performance.now()
  fn()
  return performance.now() - start
}

describe('R2-H-23: jsHarvest nesting guard, iterative walk, linear regexes & child_process crash isolation', () => {
  test('linear nesting-depth pre-scan rejects depth > 512 and deeply nested JS (2,000-5,000) returns cleanly in < 200ms', () => {
    assert.equal(exceedsJsAstNestingDepth('const x = (((1 + 2)));'), false)
    assert.equal(exceedsJsAstNestingDepth('('.repeat(600) + '1' + ')'.repeat(600)), true)
    assert.equal(exceedsJsAstNestingDepth("const r = /'/; " + '('.repeat(600) + '1' + ')'.repeat(600)), true)

    const payloads = [
      '('.repeat(2_500) + "fetch('/api/deep')" + ')'.repeat(2_500),
      '{'.repeat(3_500) + '}'.repeat(3_500),
      '['.repeat(5_000) + ']'.repeat(5_000),
      "const q = /'/; " + '('.repeat(2_500) + '1' + ')'.repeat(2_500),
    ]

    for (const [idx, code] of payloads.entries()) {
      let result!: Record<string, unknown>
      const elapsed = measureMs(() => {
        result = jsHarvest(code, `https://target.invalid/deep-${idx}.js`)
      })
      assert.ok(elapsed < 200, `Deep-nesting payload #${idx} took ${elapsed.toFixed(2)}ms (expected < 200ms)`)
      assert.equal(result.parserUsed, 'regex', `Deep-nesting payload #${idx} must fall back to regex mode`)
    }
  })

  test('quadratic jsHarvest and secretScan regex blobs complete in < 100ms while preserving real matches', () => {
    const graphqlEvil = 'query Ab '.repeat(110_000) // ~990 KB, no '{'
    const nextDataEvil = '<script '.repeat(120_000) // ~960 KB, no id="__NEXT_DATA__"
    const jwtEvil = '-eyJ'.repeat(100_000) // 400 KB repeated hyphen + eyJ
    const privKeyEvil = '-----BEGIN PRIVATE KEY----- '.repeat(25_000) // ~700 KB, no END

    // Warm up regex engine once
    jsHarvest('const a = 1;', 'warmup.js')

    for (const [name, blob] of [
      ['graphql-repeat', graphqlEvil],
      ['next-data-repeat', nextDataEvil],
      ['jwt-hyphen-repeat', jwtEvil],
      ['privkey-unterminated', privKeyEvil],
    ] as const) {
      const elapsed = measureMs(() => {
        jsHarvest(blob, `https://target.invalid/${name}.js`)
      })
      assert.ok(elapsed < 100, `jsHarvest ${name} took ${elapsed.toFixed(2)}ms (expected < 100ms)`)
    }

    const secretElapsed = measureMs(() => {
      const scan = secretScan(jwtEvil, 'jwt-evil.js')
      assert.equal(scan.matches.length, 0)
    })
    assert.ok(secretElapsed < 100, `secretScan jwt-hyphen-repeat took ${secretElapsed.toFixed(2)}ms (expected < 100ms)`)

    // Real matches still work cleanly.
    const validJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.signature_segment_ok'
    const validBlob = [
      'const q = "query GetOrders { orders { id total } }";',
      `<script id="__NEXT_DATA__" type="application/json">{"page":"/dash","buildId":"b123","props":{"ok":true}}</script>`,
      `const tok = "${validJwt}";`,
    ].join('\n')
    const parsed = jsHarvest(validBlob, 'https://target.invalid/good.js') as {
      graphqlDocs?: Array<{ name: string }>
      nextMeta?: { page?: string; buildId?: string }
      secretMatches?: Array<{ kind: string }>
    }
    assert.ok((parsed.graphqlDocs ?? []).some(d => d.name === 'GetOrders'))
    assert.equal(parsed.nextMeta?.page, '/dash')
    assert.equal(parsed.nextMeta?.buildId, 'b123')
    assert.ok((parsed.secretMatches ?? []).some(m => m.kind === 'jwt-literal'))
  })

  test('disposable child_process.fork pool isolates SIGSEGV crashes, strips env, enforces timeouts, and runs jsHarvestInWorker fast', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-ws19-proc-'))
    t.after(async () => {
      await closeSharedUntrustedComputePool()
      rmSync(dir, { recursive: true, force: true })
    })

    const workerPath = join(dir, 'crash-test-child.mjs')
    writeFileSync(
      workerPath,
      [
        "process.on('message', msg => {",
        "  if (msg.kind === 'fatal_signal') { process.kill(process.pid, 'SIGKILL'); return }",
        "  if (msg.kind === 'exit_139') { process.exit(139); return }",
        "  if (msg.kind === 'spin') { while (true) {} }",
        "  if (msg.kind === 'env') { process.send({ id: msg.id, ok: true, result: { keys: Object.keys(process.env), secret: process.env.KOVO_WS19_TEST_SECRET ?? null } }); return }",
        "  process.send({ id: msg.id, ok: true, result: { pid: process.pid, echoed: msg.payload } })",
        '})',
      ].join('\n'),
    )

    const prevSecret = process.env.KOVO_WS19_TEST_SECRET
    process.env.KOVO_WS19_TEST_SECRET = 'must-never-leak-to-child'
    const pool = new UntrustedComputePool({
      isolation: 'process',
      maxConcurrency: 1,
      defaultTimeoutMs: 1_000,
      workerEntry: pathToFileURL(workerPath),
    })
    t.after(() => pool.close())

    try {
      // 1. Env is stripped inside child process
      const envRes = await pool.run<{ keys: string[]; secret: string | null }>('env', {})
      assert.equal(envRes.secret, null)
      assert.equal(envRes.keys.includes('KOVO_WS19_TEST_SECRET'), false)

      // 2. Warm steady-state IPC round-trip is fast (< 25ms)
      const first = await pool.run<{ pid: number; echoed: string }>('echo', 'one')
      assert.notEqual(first.pid, process.pid, 'must execute in a separate child process')
      const ipcStart = performance.now()
      const second = await pool.run<{ pid: number; echoed: string }>('echo', 'two')
      const ipcMs = performance.now() - ipcStart
      assert.equal(second.pid, first.pid, 'pooled child process must be reused')
      assert.ok(ipcMs < 25, `warm IPC round-trip took ${ipcMs.toFixed(2)}ms`)

      // 3. Fatal signal / exit-139 kills only the child process; host survives and recycles cleanly
      await assert.rejects(
        () => pool.run('fatal_signal', {}),
        err => err instanceof UntrustedComputeWorkerError && /SIGKILL|exited|disconnected/i.test(err.message),
      )
      const afterCrash = await pool.run<{ pid: number; echoed: string }>('echo', 'recovered')
      assert.equal(afterCrash.echoed, 'recovered')
      assert.notEqual(afterCrash.pid, first.pid, 'crashed child must be replaced with a fresh PID')

      await assert.rejects(
        () => pool.run('exit_139', {}),
        err => err instanceof UntrustedComputeWorkerError && /139|exited|disconnected/i.test(err.message),
      )
      const afterExit139 = await pool.run<{ pid: number; echoed: string }>('echo', 'recovered-139')
      assert.equal(afterExit139.echoed, 'recovered-139')
      assert.notEqual(afterExit139.pid, afterCrash.pid, 'exit-139 child must be replaced with a fresh PID')

      // 4. Hard wall-clock SIGKILL timeout terminates infinite loop cleanly
      await assert.rejects(
        () => pool.run('spin', {}, { timeoutMs: 80 }),
        err => err instanceof UntrustedComputeTimeoutError,
      )
      const afterTimeout = await pool.run<{ echoed: string }>('echo', 'after-timeout')
      assert.equal(afterTimeout.echoed, 'after-timeout')
    } finally {
      if (prevSecret === undefined) delete process.env.KOVO_WS19_TEST_SECRET
      else process.env.KOVO_WS19_TEST_SECRET = prevSecret
    }

    // 5. Real jsHarvestInWorker runs in the shared disposable child process pool
    await jsHarvestInWorker("fetch('/api/warmup');", 'warmup.js')
    const deepStart = performance.now()
    const deepOut = await jsHarvestInWorker(
      '('.repeat(2_500) + "fetch('/api/nested')" + ')'.repeat(2_500),
      'https://target.invalid/deep.js',
    )
    const deepMs = performance.now() - deepStart
    assert.equal(deepOut.parserUsed, 'regex')
    assert.ok(deepMs < 200, `warm jsHarvestInWorker on deep nesting took ${deepMs.toFixed(2)}ms (expected < 200ms)`)
  })
})

describe('R2-H-24: ProgramGraph linear regexes & buildStaticWorkspaceSnapshotInWorker abort/timeout', () => {
  test('adversarial Rails, Express, $ calls/guards, Django, Spring, Gin, and Chi files each complete in < 200ms', () => {
    const cases: Array<{ path: string; content: string }> = [
      {
        path: 'config/routes.rb',
        content: [
          'Rails.application.routes.draw do',
          `  namespace :a, ${' '.repeat(80_000)}`,
          `  resources :users, ${'only: '.repeat(5_000)}`,
          '  namespace :api do',
          '    resources :orders, only: [:index, :show]',
          '  end',
          'end',
        ].join('\n'),
      },
      {
        path: 'src/express-evil.ts',
        content: [
          'const app = express()',
          'a'.repeat(80_000),
          "app.get('/api/ok', okHandler)",
        ].join('\n'),
      },
      {
        path: 'src/dollar-evil.ts',
        content: [
          'function checkAuth() {',
          '  const x = ' + '$a'.repeat(25_000) + ';',
          '  return verifyToken(x);',
          '}',
        ].join('\n'),
      },
      {
        path: 'app/urls.py',
        content: [
          'urlpatterns = []',
          '@login_required\n'.repeat(4_000),
          '@login_required',
          'def list_items(req): pass',
          "urlpatterns = [path('items/<int:id>', list_items)]",
        ].join('\n'),
      },
      {
        path: 'src/EvilController.java',
        content: [
          '@RestController',
          '@A\n'.repeat(4_000),
          '@RequestMapping("/api/v1")',
          'public class GoodController {',
          '  @GetMapping("/health")',
          '  public String health() { return "ok"; }',
          '}',
        ].join('\n'),
      },
      {
        path: 'cmd/gin_evil.go',
        content: [
          'r := gin.Default()',
          'a'.repeat(80_000),
          'r.GET("/ping", pingHandler)',
        ].join('\n'),
      },
      {
        path: 'cmd/chi_evil.go',
        content: [
          'r := chi.NewRouter()',
          '// ' + 'x'.repeat(80_000),
          'r.Get("/ready", readyHandler)',
        ].join('\n'),
      },
    ]

    for (const c of cases) {
      let graph!: ReturnType<typeof extractProgramGraph>
      const elapsed = measureMs(() => {
        graph = extractProgramGraph({ files: [c] })
      })
      assert.ok(elapsed < 200, `${c.path} took ${elapsed.toFixed(2)}ms (expected < 200ms)`)
      if (c.path === 'config/routes.rb') {
        assert.ok(graph.routes.some(r => r.path === '/api/orders' && r.method === 'GET'))
        assert.ok(graph.routes.some(r => r.path === '/api/orders/:id' && r.method === 'GET'))
      } else if (c.path === 'src/express-evil.ts') {
        assert.ok(graph.routes.some(r => r.path === '/api/ok'))
      } else if (c.path === 'app/urls.py') {
        assert.ok(graph.routes.some(r => r.framework === 'django' && r.path === '/items/:id'))
      } else if (c.path === 'src/EvilController.java') {
        assert.ok(graph.routes.some(r => r.framework === 'spring' && r.path === '/api/v1/health'))
      } else if (c.path === 'cmd/gin_evil.go') {
        assert.ok(graph.routes.some(r => r.framework === 'gin' && r.path === '/ping'))
      } else if (c.path === 'cmd/chi_evil.go') {
        assert.ok(graph.routes.some(r => r.framework === 'chi' && r.path === '/ready'))
      }
    }
  })

  test('buildStaticWorkspaceSnapshotInWorker propagates AbortSignal cleanly', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-ws19-snap-'))
    t.after(async () => {
      await closeSharedUntrustedComputePool()
      rmSync(dir, { recursive: true, force: true })
    })
    mkdirSync(join(dir, 'acme', 'svc'), { recursive: true })
    writeFileSync(
      join(dir, 'acme', 'svc', 'app.js'),
      "const app = express(); app.get('/api/ping', (req, res) => res.send('ok'));\n",
    )

    const aborted = new AbortController()
    aborted.abort()
    await assert.rejects(
      () => buildStaticWorkspaceSnapshotInWorker(dir, { signal: aborted.signal }),
      err => err instanceof UntrustedComputeAbortedError,
    )

    const snap = await buildStaticWorkspaceSnapshotInWorker(dir, { workerTimeoutMs: 5_000 })
    assert.ok(snap.programGraph.routes.some(r => r.path === '/api/ping'))
  })
})

describe('R2-H-25: ProgramGraph OOM amplification immunity (Gin, Rails, middleware fan-out, per-file budgets)', () => {
  test('Gin self-referential groups, cyclic groups, and deep nesting complete in < 200ms with bounded paths', () => {
    const lines = [
      'r := gin.Default()',
      'g := r.Group("/v1")',
      ...Array.from({ length: 300 }, () => 'g = g.Group("/aaaaaaaaaaaaaaaaaaaaaaaa")'),
      'a := r.Group("/a")',
      'b := a.Group("/b")',
      'a = b.Group("/cycle")',
      ...Array.from({ length: 30 }, (_, i) => `d${i + 1} := ${i === 0 ? 'r' : `d${i}`}.Group("/lvl${i}")`),
      'g.GET("/item", getItem)',
      'd30.GET("/deep", getDeep)',
    ]
    let graph!: ReturnType<typeof extractProgramGraph>
    const elapsed = measureMs(() => {
      graph = extractProgramGraph({ files: [{ path: 'cmd/gin_amp.go', content: lines.join('\n') }] })
    })
    assert.ok(elapsed < 200, `Gin amplification took ${elapsed.toFixed(2)}ms (expected < 200ms)`)
    assert.ok(graph.warnings.some(w => /self-referential Gin group/i.test(w)))
    assert.ok(graph.warnings.some(w => /depth capped/i.test(w)))
    for (const route of graph.routes) {
      assert.ok(route.path.length <= 2048, `route path exceeded 2048: ${route.path.length}`)
    }
    const item = graph.routes.find(r => r.handler === 'getItem')
    assert.equal(item?.path, '/v1/item', 'self-reassigned group must not amplify prefix')
  })

  test('unterminated Rails namespaces and deep nesting complete in < 200ms with bounded routes & paths', () => {
    const unclosed = [
      'Rails.application.routes.draw do',
      ...Array.from({ length: 1_000 }, (_, i) => `  namespace :ns_${i}_segment_padding do`),
      '  resources :items',
    ].join('\n')

    let graph!: ReturnType<typeof extractProgramGraph>
    const elapsed = measureMs(() => {
      graph = extractProgramGraph({ files: [{ path: 'config/routes.rb', content: unclosed }] })
    })
    assert.ok(elapsed < 200, `Unterminated Rails namespaces took ${elapsed.toFixed(2)}ms (expected < 200ms)`)
    assert.ok(graph.warnings.some(w => /unterminated Rails namespace/i.test(w)))
    for (const route of graph.routes) {
      assert.ok(route.path.length <= 2048)
    }
    // Deep properly closed namespaces must cap at 12
    const deepClosed = [
      'Rails.application.routes.draw do',
      ...Array.from({ length: 30 }, (_, i) => `${'  '.repeat(i + 1)}namespace :lvl${i} do`),
      `${'  '.repeat(32)}get '/leaf', to: 'leaf#show'`,
      ...Array.from({ length: 30 }, (_, i) => `${'  '.repeat(30 - i)}end`),
      'end',
    ].join('\n')
    let deepGraph!: ReturnType<typeof extractProgramGraph>
    const deepElapsed = measureMs(() => {
      deepGraph = extractProgramGraph({ files: [{ path: 'config/deep_routes.rb', content: deepClosed }] })
    })
    assert.ok(deepElapsed < 200)
    assert.ok(deepGraph.warnings.some(w => /depth capped/i.test(w)))
    for (const route of deepGraph.routes) {
      assert.ok(route.path.length <= 2048)
    }
  })

  test('Express middleware fan-out shares references, caps middleware <= 64, and enforces per-file route cap', () => {
    const mwLines = Array.from({ length: 400 }, (_, i) => `app.use(requireAuthMw_${i})`)
    const routeLines = Array.from({ length: 1_500 }, (_, i) => `app.get('/api/items/${i}', handler_${i})`)
    const code = ['const app = express()', ...mwLines, ...routeLines].join('\n')

    let graph!: ReturnType<typeof extractProgramGraph>
    const elapsed = measureMs(() => {
      graph = extractProgramGraph({ files: [{ path: 'src/mw-fanout.ts', content: code }] })
    })
    assert.ok(elapsed < 200, `Middleware fan-out took ${elapsed.toFixed(2)}ms (expected < 200ms)`)
    assert.ok(graph.routes.length > 0 && graph.routes.length <= 1_000, `expected per-file route cap <= 1000, got ${graph.routes.length}`)
    assert.ok(graph.warnings.some(w => /middleware capped/i.test(w)))
    assert.ok(graph.warnings.some(w => /Raw routes capped/i.test(w)))
    for (const route of graph.routes) {
      assert.ok(route.middleware.length <= 64, `middleware length ${route.middleware.length} > 64`)
    }
    // Reference sharing: routes without route-specific middleware share the exact same array reference.
    if (graph.routes.length >= 2) {
      assert.strictEqual(graph.routes[0].middleware, graph.routes[1].middleware)
      assert.strictEqual(graph.routes[0].guards, graph.routes[1].guards)
    }
  })
})

describe('R2-C-2: Prototype-pollution dotted-path ingress rejected in phase0-recon', () => {
  test('rejects __proto__, constructor, prototype in dotted/bracketed paths across recon extractors', () => {
    const evilNames = [
      '__proto__',
      'constructor',
      'prototype',
      '__proto__.allowLocalLab',
      'a.__proto__.polluted',
      'constructor.prototype.allowLocalLab',
      'user.constructor.prototype.isAdmin',
      'items[__proto__].x',
    ]
    for (const name of evilNames) {
      assert.equal(hasPrototypePollutionSegment(name), true, `expected rejection for ${name}`)
      assert.equal(isUsefulParamName(name), false, `isUsefulParamName must reject ${name}`)
    }
    assert.equal(hasPrototypePollutionSegment('filter.name'), false)
    assert.equal(isUsefulParamName('filter.name'), true)

    const jsonBody = JSON.stringify({
      safeField: 'ok',
      'a.__proto__.polluted': 'bad',
      'constructor.prototype.allowLocalLab': true,
      nested: { 'x.prototype.y': 1, validLeaf: 'yes' },
    })
    const fields = extractJsonFieldNames(jsonBody)
    assert.ok(fields.includes('safeField'))
    assert.ok(fields.includes('validLeaf'))
    for (const f of fields) {
      assert.equal(hasPrototypePollutionSegment(f), false, `extractJsonFieldNames leaked ${f}`)
    }

    const xhr = inferXhrRequestShape({
      url: 'https://target.invalid/api/save?__proto__.x=1&q=ok',
      method: 'POST',
      contentType: 'application/json',
      body: JSON.stringify({ user: { prototype: 'bad', name: 'alice' }, constructor: { prototype: 'bad' } }),
    })
    assert.ok(xhr)
    assert.ok(xhr.params.some(p => p.name === 'q'))
    assert.ok(xhr.params.some(p => p.name === 'user.name'))
    for (const p of xhr.params) {
      assert.equal(hasPrototypePollutionSegment(p.name), false, `inferXhrRequestShape leaked ${p.name}`)
    }

    const jsCode = [
      "fetch('/api/update', { method: 'POST', body: JSON.stringify({ constructor: { prototype: { isAdmin: true } }, safeKey: 1 }) });",
      "const p = cfg.params && cfg.params['__proto__.polluted']; payload[p] = 1; api('save', JSON.stringify(payload));",
    ].join('\n')
    for (const spec of harvestJsRequestParams(jsCode)) {
      for (const p of spec.params) {
        assert.equal(hasPrototypePollutionSegment(p.name), false, `harvestJsRequestParams leaked ${p.name}`)
      }
    }
    for (const b of harvestConfigParamBindings(jsCode)) {
      assert.equal(hasPrototypePollutionSegment(b.name), false, `harvestConfigParamBindings leaked ${b.name}`)
    }

    const hints = harvestRouteMapParamHints({
      paramNames: ['__proto__.allowLocalLab', 'constructor.prototype.x', 'orderId'],
      paramMap: { '__proto__.a': 'b', safeLogical: 'constructor.prototype.y', id: 'order_id' },
    })
    assert.ok(hints.paramHints.includes('orderId'))
    assert.ok(hints.paramHints.includes('order_id'))
    for (const h of hints.paramHints) {
      assert.equal(hasPrototypePollutionSegment(h), false)
    }
    assert.equal(({} as Record<string, unknown>).allowLocalLab, undefined)
    assert.equal(({} as Record<string, unknown>).polluted, undefined)
  })
})
