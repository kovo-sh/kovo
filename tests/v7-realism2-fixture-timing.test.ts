/**
 * Realism #2 — blind SQLi is a genuine timing oracle.
 *
 * The fixture's injected branch must take a real, attacker-chosen amount of time (bounded) while
 * returning a byte-identical body. Benign queries, boolean-only injections (including false ones),
 * and the parameterized decoy stay fast, so neither "injection noticed" nor WAN jitter can be
 * mistaken for a timing signal.
 *
 * No Docker: this starts the fixture in-process with zero jitter so the measurement is about the
 * server-side delay, not the edge proxy.
 */
import assert from 'node:assert/strict'
import { after, before, describe, test } from 'node:test'

import { MAX_SQLI_DELAY_MS, injectedTimeDelayMs, start, type WanOobFixture } from '../benchmarks/realism-suite/fixtures/wan-oob/index.ts'

describe('realism2 fixture: payload delay parsing', () => {
  test('reads each supported dialect family', () => {
    assert.equal(injectedTimeDelayMs("widgets' AND SLEEP(1.5)-- -"), 1500)
    assert.equal(injectedTimeDelayMs("widgets' AND (SELECT 1 FROM pg_sleep(2)) IS NULL-- -"), 2000)
    assert.equal(injectedTimeDelayMs("widgets'; WAITFOR DELAY '0:0:3'-- -"), 3000)
    // The engine's SQLite busy-loop: ~25 000 blob bytes per millisecond.
    assert.equal(injectedTimeDelayMs("widgets' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(37500000))))-- -"), 1500)
  })

  test('bounds the delay so a probe can never stall a scan', () => {
    assert.equal(injectedTimeDelayMs("x' AND SLEEP(30)-- -"), MAX_SQLI_DELAY_MS)
    assert.equal(injectedTimeDelayMs("x' AND SLEEP(0.001)-- -"), 150)
  })

  test('boolean-only and benign queries request no delay', () => {
    assert.equal(injectedTimeDelayMs('widgets'), null)
    assert.equal(injectedTimeDelayMs("widgets' OR 1=1 --"), null)
    assert.equal(injectedTimeDelayMs("widgets' AND 1=2 --"), null)
    assert.equal(injectedTimeDelayMs("widgets' UNION SELECT null --"), null)
  })
})

describe('realism2 fixture: blind-SQLi timing oracle', () => {
  let fixture: WanOobFixture
  before(async () => {
    process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
    // Zero edge jitter: the measurement is the server-side branch delay, not WAN noise.
    fixture = await start({ seed: 11, jitterMs: [0, 0], callbackDelayMs: [50, 80] })
  })
  after(async () => {
    await fixture?.stop?.()
  })

  const search = async (q: string): Promise<{ elapsedMs: number; body: string; status: number }> => {
    const started = Date.now()
    const response = await fetch(`${fixture.proxyOrigin}/v1/catalog/search?q=${encodeURIComponent(q)}`)
    const body = await response.text()
    return { elapsedMs: Date.now() - started, body, status: response.status }
  }

  test('a benign query is fast and returns the blind shape', async () => {
    const benign = await search('widgets')
    assert.equal(benign.status, 200)
    assert.ok(benign.elapsedMs < 600, `benign took ${benign.elapsedMs}ms`)
    assert.deepEqual(JSON.parse(benign.body), { results: [], tookMs: 12, cursor: null })
  })

  test('a sleep payload delays, keeps the body identical, and still schedules the callback', async () => {
    const before = fixture.collector.events().filter(event => event.kind === 'sqli').length
    const injected = await search("widgets' AND SLEEP(1.5)-- -")
    assert.equal(injected.status, 200)
    assert.ok(injected.elapsedMs >= 1200, `vulnerable branch took only ${injected.elapsedMs}ms`)
    assert.ok(injected.elapsedMs <= MAX_SQLI_DELAY_MS + 800, `delay exceeded the bound: ${injected.elapsedMs}ms`)
    // Blind: the body must not distinguish the branch.
    const benign = await search('widgets')
    assert.equal(injected.body, benign.body, 'injected and benign bodies must be byte-identical')
    // The async oracle is unchanged.
    const deadline = Date.now() + 4000
    while (Date.now() < deadline && fixture.collector.events().filter(event => event.kind === 'sqli').length === before) {
      await new Promise(resolve => setTimeout(resolve, 20))
    }
    assert.ok(fixture.collector.events().filter(event => event.kind === 'sqli').length > before, 'the sqli callback must still fire')
  })

  test('a bounded over-long sleep is clamped, not allowed to stall', async () => {
    const started = Date.now()
    await search("widgets' AND SLEEP(30)-- -")
    const elapsed = Date.now() - started
    assert.ok(elapsed >= MAX_SQLI_DELAY_MS - 400, `expected the clamped delay, got ${elapsed}ms`)
    assert.ok(elapsed <= MAX_SQLI_DELAY_MS + 1500, `clamped delay overshot: ${elapsed}ms`)
  })

  test('a boolean-only injection (false branch) stays fast', async () => {
    const falseArm = await search("widgets' AND 1=2 --")
    assert.ok(falseArm.elapsedMs < 600, `false arm took ${falseArm.elapsedMs}ms`)
  })

  test('the parameterized decoy route stays fast for the same payload', async () => {
    const started = Date.now()
    const response = await fetch(`${fixture.proxyOrigin}/v1/catalog/item/1?q=${encodeURIComponent("x' AND SLEEP(1.5)-- -")}`)
    assert.equal(response.status, 200)
    assert.ok(Date.now() - started < 600, 'the hardened/parameterized route must not delay')
  })
})
