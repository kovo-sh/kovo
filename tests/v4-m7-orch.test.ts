/**
 * M7 orchestration speed: config knobs, budget maths, adaptive slow probes, class caps and the
 * bounded concurrency scheduler. Pure helpers run offline; CLI parsing covers the new flags.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import {
  BENCH_DEADLINE_MS_DEFAULT,
  BENCH_MAX_REQUESTS_DEFAULT,
  BENCH_PROBE_CONCURRENCY_DEFAULT,
  BENCH_VERIFY_CONCURRENCY_DEFAULT,
  applyBenchmarkClassCaps,
  classifyHypothesisConcurrency,
  computeSlowProbeAllowance,
  parseClassCapSpec,
  resolveBenchOrchestrationConfig,
  runBenchmarkSchedule,
  scoreSlowProbePlausibility,
  selectSlowProbeKeys,
  verificationBatches,
} from '../scripts/benchmark-core.ts'
import type { BenchmarkScheduledTask } from '../scripts/benchmark-core.ts'
import { benchmarkCliHelp, parseBenchmarkCliArgs } from '../scripts/benchmark-recall.ts'
import { parseArgs as parseMatrixArgs } from '../scripts/benchmark-realistic-matrix.ts'

const delay = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms))

describe('M7 orchestration: config knobs', () => {
  test('defaults preserve the pre-M7 request/deadline compatibility values', () => {
    const cfg = resolveBenchOrchestrationConfig({})
    assert.equal(cfg.maxRequests, BENCH_MAX_REQUESTS_DEFAULT)
    assert.equal(cfg.maxRequests, 3800)
    assert.equal(cfg.deadlineMs, BENCH_DEADLINE_MS_DEFAULT)
    assert.equal(cfg.deadlineMs, 8 * 60_000)
    assert.equal(cfg.probeConcurrency, BENCH_PROBE_CONCURRENCY_DEFAULT)
    assert.equal(cfg.probeConcurrency, 4)
    assert.equal(cfg.verifyConcurrency, BENCH_VERIFY_CONCURRENCY_DEFAULT)
    assert.equal(cfg.slowProbes, null)
    assert.equal(cfg.classCaps.perClass.path_traversal_benign, 8)
    assert.equal(cfg.classCaps.perEndpoint.path_traversal_benign, 1)
  })

  test('env values are read and concurrency is clamped; overrides win', () => {
    const env = {
      GUARDIAN_BENCH_MAX_REQUESTS: '1200',
      GUARDIAN_BENCH_DEADLINE_MS: '60000',
      GUARDIAN_BENCH_PROBE_CONCURRENCY: '99',
      GUARDIAN_BENCH_VERIFY_CONCURRENCY: '99',
      GUARDIAN_BENCH_SLOW_PROBES: '6',
      GUARDIAN_BENCH_CLASS_CAP: 'path_traversal_benign=2,sqli_boolean=9',
      GUARDIAN_BENCH_CLASS_ENDPOINT_CAP: 'cache_poison_deception=2',
    }
    const cfg = resolveBenchOrchestrationConfig(env, { maxRequests: 900, probeConcurrency: 3 })
    assert.equal(cfg.maxRequests, 900)
    assert.equal(cfg.deadlineMs, 60_000)
    assert.equal(cfg.probeConcurrency, 3)
    assert.equal(cfg.verifyConcurrency, 4)
    assert.equal(cfg.slowProbes, 6)
    assert.equal(cfg.classCaps.perClass.path_traversal_benign, 2)
    assert.equal(cfg.classCaps.perClass.sqli_boolean, 9)
    assert.equal(cfg.classCaps.perEndpoint.cache_poison_deception, 2)
  })

  test('invalid and out-of-range env values fall back to safe bounds, not crashes', () => {
    const cfg = resolveBenchOrchestrationConfig({
      GUARDIAN_BENCH_MAX_REQUESTS: 'nope',
      GUARDIAN_BENCH_DEADLINE_MS: '',
      GUARDIAN_BENCH_PROBE_CONCURRENCY: '0',
      GUARDIAN_BENCH_VERIFY_CONCURRENCY: '-3',
      GUARDIAN_BENCH_SLOW_PROBES: '900',
    })
    assert.equal(cfg.maxRequests, 3800)
    assert.equal(cfg.deadlineMs, 480_000)
    assert.equal(cfg.probeConcurrency, 1)
    assert.equal(cfg.verifyConcurrency, 1)
    assert.equal(cfg.slowProbes, 64)
  })

  test('parseClassCapSpec ignores malformed entries', () => {
    assert.deepEqual(parseClassCapSpec('a=1,b=2'), { a: 1, b: 2 })
    assert.deepEqual(parseClassCapSpec('a=x,b=,=3,c=-1,d=0'), { d: 0 })
    assert.deepEqual(parseClassCapSpec(undefined), {})
  })
})

describe('M7 orchestration: adaptive slow probes', () => {
  test('allowance is explicit when set, otherwise scaled and bounded 12..24', () => {
    assert.equal(computeSlowProbeAllowance(0), 12)
    assert.equal(computeSlowProbeAllowance(5), 12)
    assert.equal(computeSlowProbeAllowance(18), 18)
    assert.equal(computeSlowProbeAllowance(80), 24)
    assert.equal(computeSlowProbeAllowance(80, 7), 7)
    assert.equal(computeSlowProbeAllowance(80, 0), 0)
    assert.equal(computeSlowProbeAllowance(80, 900), 64)
  })

  test('plausibility ranks API data params above header/static routes', () => {
    const high = scoreSlowProbePlausibility({ key: 'k', path: '/api/orders/lookup', param: 'ref', location: 'query', method: 'GET' })
    const low = scoreSlowProbePlausibility({ key: 'k', path: '/static/logo.svg', param: 'X-Trace', location: 'header', method: 'GET' })
    assert.ok(high > low)
  })

  test('selection keeps the highest-plausibility candidates without reordering execution', () => {
    const candidates = [
      { key: 'early-low', path: '/static/a', param: 'x', location: 'header', method: 'GET' },
      { key: 'mid', path: '/api/products', param: 'category', location: 'query', method: 'GET' },
      { key: 'late-high', path: '/api/orders/lookup', param: 'ref', location: 'query', method: 'GET' },
    ]
    const selected = selectSlowProbeKeys(candidates, 2)
    assert.equal(selected.size, 2)
    assert.ok(selected.has('mid'))
    assert.ok(selected.has('late-high'))
    assert.ok(!selected.has('early-low'))
    // The returned value is a set; callers iterate the plan, so writes keep plan order.
    assert.deepEqual([...selected], ['mid', 'late-high'])
    assert.equal(selectSlowProbeKeys(candidates, 0).size, 0)
  })
})

describe('M7 orchestration: per-class caps', () => {
  const hyp = (key: string, probeClass: string, path: string, extra: Record<string, unknown> = {}) => ({
    key,
    probeClass,
    endpoint: { path },
    ...extra,
  })

  test('per-class cap keeps plausible hypotheses but emits survivors in plan order', () => {
    const hypotheses = [
      hyp('a', 'path_traversal_benign', '/static/a', { method: 'GET' }),
      hyp('b', 'path_traversal_benign', '/api/items/1', { method: 'GET' }),
      hyp('c', 'path_traversal_benign', '/api/orders/lookup', { method: 'GET' }),
    ]
    const result = applyBenchmarkClassCaps(hypotheses, { perClass: { path_traversal_benign: 2 }, perEndpoint: {} })
    assert.deepEqual(result.kept.map(h => h.key), ['b', 'c'])
    assert.equal(result.dropped.length, 1)
    assert.equal(result.dropped[0].reason, 'per_class_cap')
    assert.equal(result.dropped[0].key, 'a')
  })

  test('stateful writes retain their relative order when a cap applies', () => {
    const hypotheses = [
      hyp('w1', 'mass_assignment', '/api/profile', { method: 'PATCH' }),
      hyp('w2', 'mass_assignment', '/api/account/settings', { method: 'PATCH' }),
      hyp('w3', 'mass_assignment', '/api/org/members', { method: 'PATCH' }),
    ]
    const result = applyBenchmarkClassCaps(hypotheses, { perClass: { mass_assignment: 2 }, perEndpoint: {} })
    assert.deepEqual(result.kept.map(h => h.key), ['w1', 'w2'])
  })

  test('per-endpoint cap bounds repeated class probes on one route', () => {
    const hypotheses = [
      hyp('p1', 'ssti_math', '/greet', { method: 'GET' }),
      hyp('p2', 'ssti_math', '/greet', { method: 'GET' }),
      hyp('p3', 'ssti_math', '/other', { method: 'GET' }),
    ]
    const result = applyBenchmarkClassCaps(hypotheses, { perClass: {}, perEndpoint: { ssti_math: 1 } })
    assert.deepEqual(result.kept.map(h => h.key), ['p1', 'p3'])
    assert.equal(result.dropped[0].reason, 'per_endpoint_cap')
  })
})

describe('M7 orchestration: concurrency safety classification', () => {
  test('read-only GET hypotheses are parallel-safe', () => {
    for (const probeClass of ['sqli_boolean', 'sqli_time_diff', 'ssti_math', 'path_traversal_benign', 'authz_matrix', 'auth_protocol_audit']) {
      assert.equal(classifyHypothesisConcurrency({ probeClass, method: 'GET' }).parallelSafe, true, probeClass)
    }
    assert.equal(classifyHypothesisConcurrency({ probeClass: 'xss_context', method: 'GET' }).parallelSafe, true)
  })

  test('stateful writes, sessions, browser, cache and canary classes are serial', () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ probeClass: 'sqli_boolean', method: 'POST' }, 'stateful_write'],
      [{ probeClass: 'mass_assignment', method: 'PATCH' }, 'stateful_write'],
      [{ probeClass: 'sqli_boolean', method: 'GET', secondOrder: true }, 'second_order_write'],
      [{ probeClass: 'xss_context', method: 'GET', browserEligible: true }, 'shared_browser'],
      [{ probeClass: 'sqli_boolean', method: 'GET', csrfBound: true }, 'csrf_session_jar'],
      [{ probeClass: 'cache_poison_deception', method: 'GET' }, 'shared_cache_state'],
      [{ probeClass: 'ssrf_canary', method: 'GET' }, 'canary_callback'],
      [{ probeClass: 'xxe_canary', method: 'POST' }, 'stateful_write'],
      [{ probeClass: 'graphql_audit', method: 'POST' }, 'stateful_write'],
      [{ probeClass: 'workflow_invariant', method: 'GET' }, 'class:workflow_invariant'],
    ]
    for (const [input, reason] of cases) {
      const out = classifyHypothesisConcurrency(input as { probeClass: string; method: string })
      assert.equal(out.parallelSafe, false, JSON.stringify(input))
      assert.equal(out.reason, reason)
    }
  })
})

describe('M7 orchestration: bounded scheduler', () => {
  test('results are returned in task order even when parallel tasks finish out of order', async () => {
    const tasks: Array<BenchmarkScheduledTask<string>> = [
      { key: 'slow', parallelSafe: true, run: async () => { await delay(30); return 'slow' } },
      { key: 'fast', parallelSafe: true, run: async () => { await delay(1); return 'fast' } },
      { key: 'mid', parallelSafe: true, run: async () => { await delay(10); return 'mid' } },
    ]
    const results = await runBenchmarkSchedule(tasks, { concurrency: 3 })
    assert.deepEqual(results, ['slow', 'fast', 'mid'])
  })

  test('parallel-safe tasks overlap up to the configured bound', async () => {
    let active = 0
    let maxActive = 0
    const tasks: Array<BenchmarkScheduledTask<number>> = Array.from({ length: 7 }, (_v, i) => ({
      key: `p${i}`,
      parallelSafe: true,
      run: async () => {
        active += 1
        maxActive = Math.max(maxActive, active)
        await delay(15)
        active -= 1
        return i
      },
    }))
    const results = await runBenchmarkSchedule(tasks, { concurrency: 4 })
    assert.deepEqual(results, [0, 1, 2, 3, 4, 5, 6])
    assert.ok(maxActive > 1, `expected overlap, saw maxActive=${maxActive}`)
    assert.ok(maxActive <= 4, `exceeded concurrency: ${maxActive}`)
  })

  test('serial tasks drain in-flight work and run alone, preserving write order', async () => {
    const events: string[] = []
    let active = 0
    let serialSawActive = -1
    const parallel = (key: string): BenchmarkScheduledTask<string> => ({
      key,
      parallelSafe: true,
      run: async () => { active += 1; events.push(`start:${key}`); await delay(15); active -= 1; events.push(`end:${key}`); return key },
    })
    const serial = (key: string): BenchmarkScheduledTask<string> => ({
      key,
      parallelSafe: false,
      run: async () => { serialSawActive = Math.max(serialSawActive, active); events.push(`serial:${key}`); return key },
    })
    const results = await runBenchmarkSchedule([parallel('p1'), parallel('p2'), serial('w1'), serial('w2')], { concurrency: 4 })
    assert.deepEqual(results, ['p1', 'p2', 'w1', 'w2'])
    assert.equal(serialSawActive, 0)
    assert.ok(events.indexOf('end:p1') < events.indexOf('serial:w1'))
    assert.ok(events.indexOf('end:p2') < events.indexOf('serial:w1'))
    assert.ok(events.indexOf('serial:w1') < events.indexOf('serial:w2'))
  })

  test('concurrency 1 is fully serial, and dependencies wait for their producer', async () => {
    let active = 0
    let maxActive = 0
    const seen: string[] = []
    const tasks: Array<BenchmarkScheduledTask<string>> = [
      { key: 'a', parallelSafe: true, run: async () => { active += 1; maxActive = Math.max(maxActive, active); await delay(10); active -= 1; seen.push('a'); return 'a' } },
      { key: 'b', parallelSafe: true, dependsOn: ['a'], run: async () => { assert.ok(seen.includes('a')); seen.push('b'); return 'b' } },
      { key: 'c', parallelSafe: false, run: async () => { seen.push('c'); return 'c' } },
    ]
    assert.deepEqual(await runBenchmarkSchedule(tasks, { concurrency: 1 }), ['a', 'b', 'c'])
    assert.equal(maxActive, 1)
    assert.deepEqual(await runBenchmarkSchedule(tasks, { concurrency: 4 }), ['a', 'b', 'c'])
  })

  test('rejections surface after draining, and other tasks still complete', async () => {
    const done: string[] = []
    const tasks: Array<BenchmarkScheduledTask<string>> = [
      { key: 'ok', parallelSafe: true, run: async () => { await delay(5); done.push('ok'); return 'ok' } },
      { key: 'bad', parallelSafe: true, run: async () => { throw new Error('boom') } },
      { key: 'after', parallelSafe: false, run: async () => { done.push('after'); return 'after' } },
    ]
    await assert.rejects(() => runBenchmarkSchedule(tasks, { concurrency: 3 }), /boom/)
    assert.ok(done.includes('ok'))
    assert.ok(done.includes('after'))
  })

  test('verification batching preserves order and confirm-on-first batch boundaries', () => {
    assert.deepEqual(verificationBatches([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]])
    assert.deepEqual(verificationBatches([1], 4), [[1]])
    assert.deepEqual(verificationBatches([], 2), [])
  })
})

describe('M7 orchestration: CLI flags', () => {
  test('recall CLI parses the new orchestration flags', () => {
    const opts = parseBenchmarkCliArgs([
      '--suite', 'xben-25', '--max-requests', '1500', '--deadline-ms', '120000',
      '--probe-concurrency', '6', '--verify-concurrency', '3', '--slow-probes', '8',
    ])
    assert.deepEqual(opts.orchestration, {
      maxRequests: 1500, deadlineMs: 120000, probeConcurrency: 6, verifyConcurrency: 3, slowProbes: 8,
    })
    assert.match(benchmarkCliHelp(), /--probe-concurrency/)
    assert.match(benchmarkCliHelp(), /GUARDIAN_BENCH_MAX_REQUESTS/)
  })

  test('recall CLI rejects malformed counts and out-of-range concurrency', () => {
    assert.throws(() => parseBenchmarkCliArgs(['--max-requests', '0']), /max-requests/)
    assert.throws(() => parseBenchmarkCliArgs(['--deadline-ms', 'x']), /deadline-ms/)
    assert.throws(() => parseBenchmarkCliArgs(['--probe-concurrency', '9']), /probe-concurrency/)
    assert.throws(() => parseBenchmarkCliArgs(['--verify-concurrency', '0']), /verify-concurrency/)
    assert.throws(() => parseBenchmarkCliArgs(['--slow-probes', '-1']), /slow-probes/)
  })

  test('matrix runner accepts --suite and the orchestration knobs', () => {
    const realistic = parseMatrixArgs(['--apps', 'acme-saas', '--seeds', '42'])
    assert.equal(realistic.suite, 'realistic')
    const xben = parseMatrixArgs(['--suite', 'xben-25', '--probe-concurrency', '4', '--max-requests', '2000', '--verify-concurrency', '2'])
    assert.equal(xben.suite, 'xben-25')
    assert.equal(xben.probeConcurrency, 4)
    assert.equal(xben.maxRequests, 2000)
    assert.equal(xben.verifyConcurrency, 2)
    assert.equal(parseMatrixArgs(['--suite', 'held-out-saas']).suite, 'held-out-saas')
    assert.throws(() => parseMatrixArgs(['--suite', 'bogus']), /--suite/)
    assert.throws(() => parseMatrixArgs(['--probe-concurrency', '9']), /probe-concurrency/)
  })
})
