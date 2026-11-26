import assert from 'node:assert/strict'
import { afterEach, beforeEach, describe, it } from 'node:test'
import {
  clearQaAnomalies,
  inspectRunPostCompletionAnomalies,
  isQaAnomaliesEnabled,
  listQaAnomalies,
  QA_ANOMALIES_MAX_ENTRIES,
  qaAnomalyKinds,
  recordQaAnomaly,
} from '../src/server/qa-anomalies.ts'

describe('Move 4 — Opt-In QA Anomaly Recorder (src/server/qa-anomalies.ts)', () => {
  const prevEnv = process.env.KOVO_QA_ANOMALIES

  beforeEach(() => {
    delete process.env.KOVO_QA_ANOMALIES
    clearQaAnomalies()
  })

  afterEach(() => {
    clearQaAnomalies()
    if (prevEnv === undefined) delete process.env.KOVO_QA_ANOMALIES
    else process.env.KOVO_QA_ANOMALIES = prevEnv
  })

  it('is disabled by default (zero-overhead no-op) unless KOVO_QA_ANOMALIES === "1"', () => {
    assert.equal(isQaAnomaliesEnabled(), false)
    assert.equal(isQaAnomaliesEnabled({ KOVO_QA_ANOMALIES: '0' }), false)
    assert.equal(isQaAnomaliesEnabled({ KOVO_QA_ANOMALIES: 'true' }), false)
    assert.equal(isQaAnomaliesEnabled({ KOVO_QA_ANOMALIES: '1' }), true)

    const dropped = recordQaAnomaly({
      kind: 'ui_console_error',
      routeOrOrigin: '/projects/123',
      summary: 'Should not be recorded when disabled',
    })
    assert.equal(dropped, null)
    assert.deepEqual(listQaAnomalies(), [])

    const postDropped = inspectRunPostCompletionAnomalies(
      { id: 'run-off', status: 'complete', phase: 'complete' },
      [{ id: 'asg-1', status: 'running' }],
      [{ id: 'f-1', status: 'static_verified', verificationTier: 'static_verified' }],
    )
    assert.deepEqual(postDropped, [])
    assert.deepEqual(listQaAnomalies(), [])
  })

  it('records all 7 structured anomaly kinds when KOVO_QA_ANOMALIES=1 and supports filtering/clearing', () => {
    process.env.KOVO_QA_ANOMALIES = '1'
    assert.equal(isQaAnomaliesEnabled(), true)

    for (let i = 0; i < qaAnomalyKinds.length; i += 1) {
      const kind = qaAnomalyKinds[i]!
      const rec = recordQaAnomaly({
        kind,
        routeOrOrigin: `https://app.example.test/step/${i}`,
        summary: `Observed ${kind} at step ${i}`,
        detail: { step: i, ok: false },
        ts: 1_700_000_000_000 + i * 1_000,
      })
      assert.ok(rec)
      assert.equal(rec.kind, kind)
      assert.equal(rec.routeOrOrigin, `https://app.example.test/step/${i}`)
      assert.equal(rec.detail?.step, i)
    }

    const all = listQaAnomalies()
    assert.equal(all.length, qaAnomalyKinds.length)
    assert.equal(listQaAnomalies({ kind: 'layout_violation' }).length, 1)
    assert.equal(listQaAnomalies({ limit: 3 }).length, 3)
    assert.equal(listQaAnomalies({ sinceTs: 1_700_000_004_000 }).length, qaAnomalyKinds.length - 4)

    // Returned records must be defensive copies so external mutation cannot corrupt ring buffer state.
    all[0]!.summary = 'mutated'
    if (all[0]!.detail) all[0]!.detail.step = 999
    const fresh = listQaAnomalies()
    assert.notEqual(fresh[0]!.summary, 'mutated')
    assert.equal(fresh[0]!.detail?.step, 0)

    clearQaAnomalies()
    assert.deepEqual(listQaAnomalies(), [])
  })

  it('enforces bounded ring buffer capacity (maxEntries = 200) via FIFO eviction', () => {
    assert.equal(QA_ANOMALIES_MAX_ENTRIES, 200)
    process.env.KOVO_QA_ANOMALIES = '1'

    for (let i = 0; i < 245; i += 1) {
      recordQaAnomaly({
        kind: 'unexpected_ui_rpc_error',
        routeOrOrigin: `/api/item/${i}`,
        summary: `Event #${i}`,
        detail: { index: i },
        ts: 1_000 + i,
      })
    }

    const items = listQaAnomalies()
    assert.equal(items.length, 200)
    assert.equal(items[0]!.detail?.index, 45, 'Oldest 45 entries must be evicted')
    assert.equal(items[199]!.detail?.index, 244, 'Newest entry must be retained')

    // Clearing and re-recording reuses the bounded ring cleanly.
    clearQaAnomalies()
    assert.equal(listQaAnomalies().length, 0)
    for (let i = 0; i < 5; i += 1) {
      recordQaAnomaly({ kind: 'ui_console_error', routeOrOrigin: `/p/${i}`, summary: `err ${i}` })
    }
    assert.equal(listQaAnomalies().length, 5)
    assert.deepEqual(listQaAnomalies({ limit: 3 }).map(e => e.routeOrOrigin), ['/p/2', '/p/3', '/p/4'])
  })

  it('strictly sanitizes cookies, auth headers, tokens, query secrets, and raw HTTP bodies', () => {
    process.env.KOVO_QA_ANOMALIES = '1'

    const syntheticJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyJ9.signature_secret_part'
    const syntheticApiKey = 'sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789'
    const bootstrapHex = 'a'.repeat(64)

    const circular: Record<string, unknown> = { safeStatus: 502, selector: '[role="dialog"]' }
    circular.self = circular

    const rec = recordQaAnomaly({
      kind: 'interactive_proxy_denied',
      routeOrOrigin: `https://user:pass@app.example.test/auth/cb?bootstrap=${bootstrapHex}&token=secret_tok_999#frag`,
      summary: `Denied with Authorization: Bearer secret_bearer_999999 and Cookie: kovo_local=supersecretvalue and ${syntheticJwt} and ${syntheticApiKey} <!doctype html><html><body>RAW_SECRET_HTML_BODY</body></html>`,
      detail: {
        statusCode: 403,
        method: 'POST',
        cookie: 'kovo_local=deadbeef',
        cookies: [{ name: 'sid', value: 'secret' }],
        authorization: 'Bearer top_secret_token_value',
        headers: { Authorization: 'Bearer nope', 'Set-Cookie': 'sid=123' },
        responseBody: '<html><body>sensitive response body</body></html>',
        rawBody: '{"secret":"value"}',
        html: '<div>secret</div>',
        accessToken: 'tok_live_123456',
        bootstrapSecret: bootstrapHex,
        note: `Got token=${syntheticApiKey} on /cb?code=oauth_code_123`,
        nested: circular,
      },
    })

    assert.ok(rec)
    const serialized = JSON.stringify(rec)

    // Route must strip userinfo, query params, and fragment.
    assert.equal(rec.routeOrOrigin, 'https://app.example.test/auth/cb')

    // Zero secret or raw HTTP body leakage anywhere in the stored record.
    for (const forbidden of [
      bootstrapHex,
      'secret_tok_999',
      'secret_bearer_999999',
      'supersecretvalue',
      'deadbeef',
      'top_secret_token_value',
      'RAW_SECRET_HTML_BODY',
      'sensitive response body',
      'tok_live_123456',
      'oauth_code_123',
      syntheticJwt,
      syntheticApiKey,
      'user:pass',
    ]) {
      assert.equal(serialized.includes(forbidden), false, `Sanitized anomaly must never contain "${forbidden}"`)
    }

    // Disallowed keys must be completely stripped while safe diagnostic fields remain intact.
    assert.equal(rec.detail?.statusCode, 403)
    assert.equal(rec.detail?.method, 'POST')
    assert.equal('cookie' in (rec.detail ?? {}), false)
    assert.equal('cookies' in (rec.detail ?? {}), false)
    assert.equal('authorization' in (rec.detail ?? {}), false)
    assert.equal('headers' in (rec.detail ?? {}), false)
    assert.equal('responseBody' in (rec.detail ?? {}), false)
    assert.equal('rawBody' in (rec.detail ?? {}), false)
    assert.equal('html' in (rec.detail ?? {}), false)
    assert.equal('accessToken' in (rec.detail ?? {}), false)
    assert.equal('bootstrapSecret' in (rec.detail ?? {}), false)
    assert.equal((rec.detail?.nested as Record<string, unknown>)?.safeStatus, 502)
    assert.equal((rec.detail?.nested as Record<string, unknown>)?.self, '[circular]')
  })

  it('inspectRunPostCompletionAnomalies detects orphaned running/queued assignments and zero_runtime_from_static on terminal runs', () => {
    process.env.KOVO_QA_ANOMALIES = '1'

    // 1. Non-terminal run should produce ZERO post-completion anomalies even with running assignments.
    const activeRunAnomalies = inspectRunPostCompletionAnomalies(
      { id: 'run-live', status: 'running', phase: 'investigation', candidates: [{ origin: 'http://127.0.0.1:4000' }] },
      [{ id: 'asg-live', status: 'running' }],
      [{ id: 'f-static', status: 'static_verified', verificationTier: 'static_verified' }],
    )
    assert.deepEqual(activeRunAnomalies, [])
    assert.equal(listQaAnomalies().length, 0)

    // 2. Terminal run with stuck running + queued assignments AND static_verified > 0, runtime_confirmed === 0.
    const detected = inspectRunPostCompletionAnomalies(
      { id: 'run-done-bad', status: 'complete', phase: 'complete', candidates: [{ origin: 'http://127.0.0.1:4000' }] },
      [
        { id: 'asg-ok', status: 'complete' },
        { id: 'asg-stuck-run', status: 'running' },
        { id: 'asg-stuck-q', status: 'queued' },
        { id: 'asg-canceled', status: 'canceled' },
      ],
      [
        { id: 'f-static-1', status: 'static_verified', verificationTier: 'static_verified' },
        { id: 'f-static-2', status: 'static_verified', verificationClass: 'static_verified' },
        { id: 'f-base', status: 'confirmed', findingKind: 'baseline_check', verificationTier: 'baseline_confirmed' },
        { id: 'f-superseded', status: 'confirmed', verificationTier: 'runtime_confirmed', supersededByFindingId: 'f-static-1' },
      ],
    )

    assert.equal(detected.length, 2)
    const orphan = detected.find(a => a.kind === 'orphaned_running_assignment')
    const zeroRuntime = detected.find(a => a.kind === 'zero_runtime_from_static')
    assert.ok(orphan, 'Expected orphaned_running_assignment anomaly')
    assert.equal(orphan.detail?.orphanedCount, 2)
    assert.equal(orphan.detail?.runningCount, 1)
    assert.equal(orphan.detail?.queuedCount, 1)
    assert.deepEqual(orphan.detail?.orphanedAssignmentIds, ['asg-stuck-run', 'asg-stuck-q'])

    assert.ok(zeroRuntime, 'Expected zero_runtime_from_static anomaly')
    assert.equal(zeroRuntime.detail?.staticVerifiedCount, 2)
    assert.equal(zeroRuntime.detail?.runtimeConfirmedCount, 0)

    // Both anomalies are also recorded in the ring buffer.
    assert.equal(listQaAnomalies().length, 2)
  })

  it('inspectRunPostCompletionAnomalies produces zero anomalies for healthy terminal runs', () => {
    process.env.KOVO_QA_ANOMALIES = '1'

    const healthyWithRuntime = inspectRunPostCompletionAnomalies(
      { id: 'run-good-1', status: 'complete', phase: 'complete' },
      [
        { id: 'asg-1', status: 'complete' },
        { id: 'asg-2', status: 'failed' },
      ],
      [
        { id: 'f-static', status: 'static_verified', verificationTier: 'static_verified' },
        { id: 'f-runtime', status: 'confirmed', verificationTier: 'runtime_confirmed' },
      ],
    )
    assert.deepEqual(healthyWithRuntime, [])

    const healthyNoStatic = inspectRunPostCompletionAnomalies(
      { id: 'run-good-2', status: 'stopped', phase: 'investigation' },
      [{ id: 'asg-3', status: 'canceled' }],
      [{ id: 'f-dismissed', status: 'dismissed' }],
    )
    assert.deepEqual(healthyNoStatic, [])
    assert.deepEqual(listQaAnomalies(), [])
  })
})
