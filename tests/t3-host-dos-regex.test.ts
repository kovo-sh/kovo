/**
 * Host ReDoS, quadratic parsing & router cycle OOM hardening regression tests
 * (CLAUDE_AUDIT H-33, H-34, H-35, H-36).
 */
import assert from 'node:assert/strict'
import { performance } from 'node:perf_hooks'
import { describe, test } from 'node:test'
import {
  extractProgramGraph,
  extractStaticSecretsAndIacLeads,
} from '../src/server/program-graph.ts'
import {
  normalizeEphemeralNoise,
  responseSimilarity,
} from '../src/server/probes/context.ts'
import { jsHarvest } from '../worker/analyzers.ts'

const CI_MULT = process.env.CI ? 6 : 1
const MAX_50MS = 50 * CI_MULT
const MAX_100MS = 100 * CI_MULT

function measureMs(fn: () => void): number {
  const start = performance.now()
  fn()
  return performance.now() - start
}

describe('H-33: program-graph.ts linear-time parsing (anti-ReDoS)', () => {
  test('adversarial 80KB stringLiteralValue backslash/unclosed inputs complete in < 50ms', () => {
    const evilBackslashes = "'" + '\\'.repeat(60_000) + 'a'
    const evilEscaped = "'" + 'a\\'.repeat(30_000) + 'x'
    const code = [
      'const app = express()',
      `app.get(${evilBackslashes}, handlerA)`,
      `app.post(${evilEscaped}, handlerB)`,
      `app.get('/api/escaped\\'ok', handlerC)`,
      `app.get(\`/api/template\`, handlerD)`,
      `app.get(\`/api/\${dynamic}\`, handlerE)`,
    ].join('\n')

    let graph!: ReturnType<typeof extractProgramGraph>
    const elapsed = measureMs(() => {
      graph = extractProgramGraph({ files: [{ path: 'src/routes.ts', content: code }] })
    })
    assert.ok(elapsed < MAX_50MS, `Expected < ${MAX_50MS}ms on adversarial string literals, got ${elapsed.toFixed(2)}ms`)
    assert.ok(graph.routes.some(r => r.handler === 'handlerC' && r.path === "/api/escaped'ok"))
    assert.ok(graph.routes.some(r => r.handler === 'handlerD' && r.path === '/api/template'))
    assert.ok(!graph.routes.some(r => r.handler === 'handlerE'), 'interpolated template literal must not be treated as static path')
  })

  test('adversarial 80KB JS/TS method inputs complete in < 50ms while extracting real methods', () => {
    const payloads = [
      ' '.repeat(80_000) + '!',
      'public '.repeat(12_000) + '!',
      'async static readonly '.repeat(4_000) + 'notAMethod;',
      'foo(): ' + 'x'.repeat(80_000),
      'const a = ('.repeat(7_000),
      'function f(){'.repeat(6_000),
      [
        'class OrderController {',
        '  public async getOrder(id: string): Promise<Order> { return loadOrder(id) }',
        '  static helper(a: number) { return a + 1 }',
        '}',
      ].join('\n'),
    ]

    for (const [idx, content] of payloads.entries()) {
      let graph!: ReturnType<typeof extractProgramGraph>
      const elapsed = measureMs(() => {
        graph = extractProgramGraph({ files: [{ path: `src/evil-${idx}.ts`, content }] })
      })
      assert.ok(elapsed < MAX_50MS, `JS payload #${idx} took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
      if (idx === payloads.length - 1) {
        const fnNames = graph.nodes.filter(n => n.kind === 'function').map(n => n.symbol)
        assert.ok(fnNames.includes('getOrder'), 'must extract TS class method with return type')
        assert.ok(fnNames.includes('helper'), 'must extract static class method')
      }
    }
  })

  test('adversarial 80KB Java and Go inputs complete in < 50ms while extracting real methods', () => {
    const javaPayloads = [
      ' '.repeat(80_000) + '!',
      'public '.repeat(12_000) + '!',
      'public static final synchronized '.repeat(2_500) + '!',
      'public List<Map<String, Integer>> '.repeat(2_500) + '!',
      [
        '@RestController',
        '@RequestMapping("/api/v1")',
        'public class BillingController {',
        '  @GetMapping("/invoices/{id}")',
        '  public ResponseEntity<Invoice> getInvoice(@PathVariable Long id) {',
        '    return repo.findById(id);',
        '  }',
        '}',
      ].join('\n'),
    ]

    for (const [idx, content] of javaPayloads.entries()) {
      let graph!: ReturnType<typeof extractProgramGraph>
      const elapsed = measureMs(() => {
        graph = extractProgramGraph({ files: [{ path: `Billing${idx}.java`, content }] })
      })
      assert.ok(elapsed < MAX_50MS, `Java payload #${idx} took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
      if (idx === javaPayloads.length - 1) {
        const fnNames = graph.nodes.filter(n => n.kind === 'function').map(n => n.symbol)
        assert.ok(fnNames.includes('getInvoice'), 'must extract Java method')
        assert.ok(graph.routes.some(r => r.framework === 'spring' && r.path === '/api/v1/invoices/:id' && r.handler === 'getInvoice'))
      }
    }

    const goEvil = 'package main\n' + 'func ('.repeat(12_000)
    const goElapsed = measureMs(() => {
      extractProgramGraph({ files: [{ path: 'cmd/evil.go', content: goEvil }] })
    })
    assert.ok(goElapsed < MAX_50MS, `Go payload took ${goElapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
  })

  test('adversarial 80KB HINT_PREFILTER_RE / conn-string inputs complete in < 50ms', () => {
    const adversarialFiles = [
      { path: 'config/a.txt', content: '://' + ':'.repeat(80_000) },
      { path: 'config/b.env', content: 'postgres://' + ':'.repeat(80_000) },
      { path: 'config/c.ts', content: '://user:'.repeat(10_000) },
      { path: 'config/d.env', content: 'password' + ' '.repeat(80_000) + '!' },
      {
        path: 'config/real.env',
        content: [
          'DATABASE_URL=postgres://admin:s3cr3tpass@db.internal:5432/app',
          'REDIS_URL=redis://:redispass123@cache.internal:6379/0',
        ].join('\n'),
      },
    ]

    let leads!: ReturnType<typeof extractStaticSecretsAndIacLeads>
    const elapsed = measureMs(() => {
      leads = extractStaticSecretsAndIacLeads(adversarialFiles)
    })
    assert.ok(elapsed < MAX_50MS, `extractStaticSecretsAndIacLeads took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
    assert.equal(leads.filter(l => l.file === 'config/real.env').length, 2, 'must detect both real credentialed conn-strings')
    assert.equal(leads.filter(l => l.file !== 'config/real.env').length, 0, 'adversarial non-secret files must not produce false leads')
  })
})

describe('H-34: normalizeEphemeralNoise & responseSimilarity linear time', () => {
  test('adversarial 100KB payloads complete in < 50ms each', () => {
    const adversarialInputs = [
      'a'.repeat(100_000),
      'csrf'.repeat(25_000),
      'requestId'.repeat(11_000),
      'a:'.repeat(50_000),
      'requestId="' + 'x'.repeat(100_000),
      'requestId="a '.repeat(7_500),
      'x-nonce-token=' + '0'.repeat(100_000),
      ' '.repeat(100_000) + 'requestId: "abc"',
    ]

    for (const [idx, payload] of adversarialInputs.entries()) {
      const elapsed = measureMs(() => {
        normalizeEphemeralNoise(payload)
      })
      assert.ok(elapsed < MAX_50MS, `normalizeEphemeralNoise payload #${idx} took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
    }
  })

  test('responseSimilarity on 100KB bodies completes in < 50ms and preserves exact semantics', () => {
    const padding = 'item_stable_token '.repeat(5_500) // ~99KB
    const a = `{"id":"doc_42","requestId":"req-111","csrfToken":"tok-aaa","etag":"W/\\"1\\"","ts":1767225600000,"at":"2026-01-01T00:00:00Z","data":"${padding}"}`
    const b = `{"id":"doc_42","requestId":"req-999","csrfToken":"tok-zzz","etag":"W/\\"2\\"","ts":1767312000000,"at":"2026-05-05T12:34:56.789+02:00","data":"${padding}"}`

    let sim = 0
    const elapsed = measureMs(() => {
      sim = responseSimilarity(a, b)
    })
    assert.ok(elapsed < MAX_50MS, `responseSimilarity on 100KB bodies took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
    assert.equal(sim, 1, 'identical bodies differing only in ephemeral values must have similarity 1')

    const c = `{"id":"doc_999","other":"totally_different_body","requestId":"req-111"}`
    assert.ok(responseSimilarity(a, c) < 0.5)
  })

  test('preserves exact normalization behavior across JSON, headers, form params, and quotes', () => {
    const input = [
      '{"id":"usr_123","request_id":"r1","x-trace-id":"t1","correlationId":"c1","span-id":"s1",',
      '"_csrf":"abc","xsrfToken":"def","scriptNonce":"ghi","etag":"W/\\"v1\\"","server_time":"100","request-time":200}',
      "x-csrf-token=rawval&keep=yes single='val'",
      "traceId='single-quoted' requestId=\"esc\\\"quote\" bare_nonce=xyz;",
      'created=2026-03-14T15:09:26.535Z epoch=1700000000000 small=12345',
    ].join('\n')

    const out = normalizeEphemeralNoise(input)
    assert.ok(out.includes('"id":"usr_123"'), 'resource id must not be masked')
    assert.ok(out.includes('keep=yes'), 'non-ephemeral form param must not be masked')
    assert.ok(out.includes('small=12345'), 'non-epoch small numbers must not be masked')
    assert.ok(out.includes('"request_id":"<ephemeral>"'))
    assert.ok(out.includes('"x-trace-id":"<ephemeral>"'))
    assert.ok(out.includes('"correlationId":"<ephemeral>"'))
    assert.ok(out.includes('"span-id":"<ephemeral>"'))
    assert.ok(out.includes('"_csrf":"<ephemeral>"'))
    assert.ok(out.includes('"xsrfToken":"<ephemeral>"'))
    assert.ok(out.includes('"scriptNonce":"<ephemeral>"'))
    assert.ok(out.includes('"etag":"<ephemeral>"'))
    assert.ok(out.includes('"server_time":"<ephemeral>"'))
    assert.ok(out.includes('"request-time":"<ephemeral>"'))
    assert.ok(out.includes('x-csrf-token="<ephemeral>"&keep=yes'))
    assert.ok(out.includes('traceId="<ephemeral>"'))
    assert.ok(out.includes('requestId="<ephemeral>"'))
    assert.ok(out.includes('bare_nonce="<ephemeral>";'))
    assert.ok(out.includes('created=<ephemeral>'))
    assert.ok(out.includes('epoch=<ephemeral>'))
  })
})

describe('H-35: worker/analyzers.ts jsHarvest O(log n) nodeLine on 50K-line JS', () => {
  test('50,000-line JS file completes in < 100ms with accurate line numbers', () => {
    const lines: string[] = []
    lines.push("fetch('/api/first');")
    for (let i = 2; i < 25_000; i += 1) {
      if (i % 500 === 0) lines.push(`fetch('/api/step/${i}');`)
      else if (i % 50 === 0) lines.push(`const r${i} = { path: '/api/route/${i}' };`)
      else lines.push('// padding line')
    }
    lines.push("fetch('/api/middle');")
    for (let i = 25_001; i < 50_000; i += 1) {
      if (i % 500 === 0) lines.push(`fetch('/api/step/${i}');`)
      else if (i % 50 === 0) lines.push(`const r${i} = { path: '/api/route/${i}' };`)
      else lines.push('// padding line')
    }
    lines.push("fetch('/api/last');")
    const largeJs = lines.join('\n')
    assert.equal(lines.length, 50_000)

    // Warm up lazy parser module load once so measurement reflects jsHarvest runtime.
    jsHarvest("fetch('/api/warmup');", 'warmup.js')

    let out!: Record<string, unknown>
    const elapsed = measureMs(() => {
      out = jsHarvest(largeJs, 'https://app.invalid/large-50k.js')
    })
    assert.ok(elapsed < MAX_100MS, `jsHarvest on 50K-line JS took ${elapsed.toFixed(2)}ms (expected < ${MAX_100MS}ms)`)
    assert.ok(out.parserUsed === 'swc' || out.parserUsed === 'acorn', `expected AST parser, got ${String(out.parserUsed)}`)

    const calls = out.httpCalls as Array<{ url: string; line?: number }>
    assert.ok(Array.isArray(calls) && calls.length >= 100)
    const first = calls.find(c => c.url === '/api/first')
    const mid = calls.find(c => c.url === '/api/middle')
    const last = calls.find(c => c.url === '/api/last')
    assert.equal(first?.line, 1)
    assert.equal(mid?.line, 25_000)
    assert.equal(last?.line, 50_000)
  })
})

describe('H-36: program-graph.ts router cycle & diamond OOM hardening', () => {
  test('self-mounting router with repeated self-mounts terminates in < 50ms without path blowup', () => {
    const selfMounts = Array.from({ length: 200 }, (_, i) => `r.use('/loop${i}', r)`).join('\n')
    const code = [
      'const r = express.Router()',
      selfMounts,
      "r.get('/health', healthHandler)",
    ].join('\n')

    let graph!: ReturnType<typeof extractProgramGraph>
    const elapsed = measureMs(() => {
      graph = extractProgramGraph({ files: [{ path: 'src/self-loop.ts', content: code }] })
    })
    assert.ok(elapsed < MAX_50MS, `Self-mounting router took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
    const route = graph.routes.find(r => r.handler === 'healthHandler')
    assert.ok(route, 'non-cyclic route on self-mounting router should still be emitted')
    assert.equal(route.path, '/health', 'self-mount must not expand path repeatedly')
    assert.ok(graph.warnings.some(w => /self-mounting|cycle/i.test(w)), 'must record cycle warning')
  })

  test('mutual 2-cycle, 3-cycle, and lasso router graphs terminate in < 50ms', () => {
    const code = [
      'const app = express()',
      'const a = express.Router()',
      'const b = express.Router()',
      'const c = express.Router()',
      "app.use('/api', a)",
      "a.use('/b', b)",
      "b.use('/c', c)",
      "c.use('/a', a)",
      "a.get('/one', hOne)",
      "b.get('/two', hTwo)",
      "c.get('/three', hThree)",
      // Pure 2-cycle with no external root (Fastify-style router)
      'const x = fastify()',
      'const y = fastify()',
      "x.use('/x', y)",
      "y.use('/y', x)",
      "x.get('/ping', hPing)",
      "y.get('/pong', hPong)",
    ].join('\n')

    let graph!: ReturnType<typeof extractProgramGraph>
    const elapsed = measureMs(() => {
      graph = extractProgramGraph({ files: [{ path: 'src/cyclic.ts', content: code }] })
    })
    assert.ok(elapsed < MAX_50MS, `Cyclic router graph took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)

    assert.equal(graph.routes.find(r => r.handler === 'hOne')?.path, '/api/one')
    assert.equal(graph.routes.find(r => r.handler === 'hTwo')?.path, '/api/b/two')
    assert.equal(graph.routes.find(r => r.handler === 'hThree')?.path, '/api/b/c/three')
    assert.ok(graph.routes.find(r => r.handler === 'hPing'), 'pure cycle node route emitted')
    assert.ok(graph.routes.find(r => r.handler === 'hPong'), 'pure cycle peer route emitted')
    assert.ok(graph.warnings.some(w => /cyclic router mount/i.test(w)), 'must record cyclic router mount warning')
  })

  test('exponential diamond DAG (30 stages = 2^30 paths) and deep chain terminate in < 50ms', () => {
    const lines: string[] = ['const r0 = express.Router()']
    for (let i = 1; i <= 30; i += 1) {
      lines.push(`const r${i} = express.Router()`)
      lines.push(`r${i - 1}.use('/a', r${i})`)
      lines.push(`r${i - 1}.use('/b', r${i})`)
    }
    lines.push("r30.get('/leaf', leafHandler)")
    const code = lines.join('\n')

    let graph!: ReturnType<typeof extractProgramGraph>
    const elapsed = measureMs(() => {
      graph = extractProgramGraph({ files: [{ path: 'src/diamond.ts', content: code }] })
    })
    assert.ok(elapsed < MAX_50MS, `Diamond/deep router DAG took ${elapsed.toFixed(2)}ms (expected < ${MAX_50MS}ms)`)
    const leaf = graph.routes.find(r => r.handler === 'leafHandler')
    assert.ok(leaf, 'leaf route should still be present')
    assert.ok(leaf.path.length <= 2048, 'mounted path length must remain bounded')
    assert.ok(graph.warnings.some(w => /depth capped/i.test(w)), 'deep chain must trigger depth cap warning')
  })
})
