/**
 * M7 held-out stream: patch-verification orchestration.
 *
 * These tests exercise `verifyPatchesLive` end to end at the orchestration layer with a fake
 * launcher and injected runtime seams, so they need no Docker, no jq and no real lab server.
 * Live recall numbers come from the separate validation run, not from unit tests.
 */
import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { parseBenchmarkCliArgs } from '../scripts/benchmark-recall.ts'
import { PatchTimeoutError, normalizePersonaMap, rebaseSpecOrigin, verifyPatchesLive } from '../scripts/benchmark-live.ts'
import type {
  ConfirmedFinding,
  PatchReplayResult,
  PatchVerificationHooks,
} from '../scripts/benchmark-live.ts'
import type { BenchmarkManifest, PatchVerificationSummary } from '../scripts/benchmark-core.ts'
import { withEnv } from './v4-tier-helpers.ts'

const finding = (id: string, isDecoy = false): ConfirmedFinding => ({
  id,
  isDecoy,
  path: `/api/${id}`,
  probeClass: 'sqli_boolean',
  spec: { kind: 'sql_boolean_diff', targetOrigin: 'http://127.0.0.1:1', pathAndQuery: `/api/${id}?q=1` },
})

function manifest(entries: Array<{ id: string; patchId?: string; isDecoy?: boolean }> = [
  { id: 'hos-01', patchId: 'hos-01' },
  { id: 'hos-02', patchId: 'hos-02' },
  { id: 'hos-03', patchId: 'hos-03' },
  { id: 'hos-d1', isDecoy: true },
]): BenchmarkManifest {
  return {
    challenges: entries.map(e => ({
      id: e.id,
      vulnClass: e.isDecoy ? 'decoy_sqli' : 'sqli_boolean',
      endpoint: `/api/${e.id}`,
      method: 'GET',
      param: 'q',
      ...(e.patchId ? { patchId: e.patchId } : {}),
      ...(e.isDecoy ? { isDecoy: true } : {}),
    })),
  }
}

interface FakeLauncherCall { patchedIds: string[] }

/**
 * Fake loopback launcher: records which patches each launch applied and rejects unknown ids the
 * same way the real lab server does. It never opens a socket; the injected runtime replaces the
 * network half of the retest.
 */
function fakeLauncher(knownPatchIds: string[], calls: FakeLauncherCall[]) {
  return async (opts?: { patchedIds?: string[] }) => {
    const patchedIds = opts?.patchedIds ?? []
    for (const id of patchedIds) {
      if (!knownPatchIds.includes(id)) throw new Error(`Unknown held-out SaaS patch id "${id}".`)
    }
    calls.push({ patchedIds: [...patchedIds] })
    return {
      origin: 'http://127.0.0.1:1',
      port: 1,
      personas: {},
      close: async () => undefined,
    }
  }
}

function runtimeHooks(input: {
  baselineFindings: ConfirmedFinding[]
  /** Findings that stop confirming when the given patch is applied. */
  fixedByPatch: (findingId: string, patchedIds: string[]) => boolean
  allPatchesFindings?: ConfirmedFinding[]
  onReplay?: (patchedIds: string[], findings: ConfirmedFinding[]) => void
  /** Optional launcher exercised by the replay seam (proves patchedIds propagation). */
  launch?: (opts: { patchedIds: string[] }) => Promise<{ close: () => Promise<void> }>
  /** Findings whose patched replay raises an exception (mapped to verdict "error"). */
  replayErrorsFor?: string[]
  replayHangsFor?: string[]
}): PatchVerificationHooks {
  return {
    runFull: async patchedIds => {
      if (patchedIds.length === 0) return { findings: input.baselineFindings, notes: ['baseline'] }
      return { findings: input.allPatchesFindings ?? [], notes: ['all-patches'] }
    },
    replayAll: async ({ findings, patchedIds }) => {
      input.onReplay?.(patchedIds, findings)
      if (input.launch) {
        const handle = await input.launch({ patchedIds })
        await handle.close()
      }
      if (input.replayHangsFor?.some(id => patchedIds.includes(id))) {
        return await new Promise<Map<string, PatchReplayResult>>(() => { /* deliberately never settles */ })
      }
      const out = new Map<string, PatchReplayResult>()
      for (const f of findings) {
        if (input.replayErrorsFor?.some(id => patchedIds.includes(id) && f.id === id)) {
          out.set(f.id, { verdict: 'error', verdicts: ['error'], note: 'simulated replay failure' })
          continue
        }
        const fixed = input.fixedByPatch(f.id, patchedIds)
        out.set(f.id, { verdict: fixed ? 'dismissed' : 'confirmed', verdicts: [fixed ? 'dismissed' : 'confirmed'] })
      }
      return out
    },
  }
}

describe('M7 held-out: verifyPatchesLive orchestration', () => {
  test('reproduces the baseline, retests each isolated patch and counts fixed targets', async () => {
    const calls: FakeLauncherCall[] = []
    const launcher = fakeLauncher(['hos-01', 'hos-02', 'hos-03'], calls)
    const replayCalls: string[][] = []
    const hooks = runtimeHooks({
      baselineFindings: [finding('hos-01'), finding('hos-02')],
      fixedByPatch: (id, patchedIds) => patchedIds.includes(id),
      onReplay: patchedIds => replayCalls.push(patchedIds),
      launch: launcher,
    })
    const summary: PatchVerificationSummary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest(),
      launcher,
      hooks,
      patchTimeoutMs: 2_000,
    }))

    assert.equal(summary.skippedReason, undefined)
    assert.equal(summary.attempted, 3)
    assert.equal(summary.reproducedBefore, 2)
    assert.equal(summary.fixed, 2)
    assert.equal(summary.decoyFalsePositivesBefore, 0)
    assert.deepEqual(summary.perPatch.map(p => p.patchId), ['hos-01', 'hos-02', 'hos-03'])

    const first = summary.perPatch[0]
    assert.equal(first.before, 'confirmed')
    assert.equal(first.after, 'dismissed')
    assert.equal(first.fixed, true)
    assert.equal(first.reproducedBefore, true)
    assert.equal(first.fixedAfter, true)
    assert.ok((first.verdicts ?? []).includes('dismissed'))

    const missing = summary.perPatch[2]
    assert.equal(missing.reproducedBefore, false)
    assert.equal(missing.fixed, false)
    assert.match((missing.notes ?? []).join(' '), /Not confirmed by the baseline/)

    // Baseline is injected above, so the launcher sees the two reproduced patches plus the
    // all-patches baseline-spec replay (the same id set, replayed against one server).
    assert.deepEqual(calls.map(c => c.patchedIds), [['hos-01'], ['hos-02'], ['hos-01', 'hos-02', 'hos-03']])
    assert.deepEqual(replayCalls.slice(0, 2), [['hos-01'], ['hos-02']])

    // Isolation: when hos-01 is patched, hos-02 (still unpatched in that launch) must confirm.
    const iso = first.isolationChecked ?? 0
    assert.equal(iso, 1)
    assert.equal(first.isolationPreserved, 1)
    assert.deepEqual(first.isolationLost, [])

    assert.ok(summary.allPatches)
    assert.equal(summary.allPatches?.attempted, true)
    assert.equal(summary.allPatches?.verdict, 'fixed')
    assert.deepEqual(summary.allPatches?.stillConfirming, [])
    assert.equal(summary.allPatches?.decoyFalsePositivesAfter, 0)
    assert.ok(typeof summary.durationMs === 'number')
  })

  test('flags isolation loss when a patch suppresses an unrelated finding', async () => {
    const calls: FakeLauncherCall[] = []
    const hooks = runtimeHooks({
      baselineFindings: [finding('hos-01'), finding('hos-02')],
      // Patch hos-01 also dismisses everything else: an isolation regression.
      fixedByPatch: (_id, patchedIds) => patchedIds.length > 0,
      allPatchesFindings: [],
    })
    const summary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest(),
      launcher: fakeLauncher(['hos-01', 'hos-02', 'hos-03'], calls),
      hooks,
      isolationSample: 2,
      patchTimeoutMs: 2_000,
    }))
    const first = summary.perPatch[0]
    assert.equal(first.fixed, true)
    assert.ok((first.isolationLost ?? []).includes('hos-02'))
    assert.match((first.notes ?? []).join(' '), /Isolation check/)
  })

  test('all-patches pass reports genuine baseline-spec regressions and decoy repeats honestly', async () => {
    const calls: FakeLauncherCall[] = []
    const hooks = runtimeHooks({
      baselineFindings: [finding('hos-01'), finding('hos-02'), finding('hos-d1', true)],
      // hos-01 is fixed by its patch; hos-02 still confirms under all patches (a genuine regression);
      // the decoy has no patch and keeps confirming.
      fixedByPatch: (id, patchedIds) => id === 'hos-d1' ? false : !(patchedIds.length > 1 && id === 'hos-02'),
    })
    const summary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest(),
      launcher: fakeLauncher(['hos-01', 'hos-02', 'hos-03'], calls),
      hooks,
      patchTimeoutMs: 2_000,
    }))
    assert.equal(summary.allPatches?.verdict, 'regressed')
    assert.deepEqual(summary.allPatches?.stillConfirming, ['hos-02'])
    assert.equal(summary.allPatches?.decoyFalsePositivesAfter, 1)
    assert.equal(summary.decoyFalsePositivesAfter, 1)
    assert.match((summary.allPatches?.notes ?? []).join(' '), /hos-d1/)
  })
})

describe('M7 held-out: verifyPatchesLive error paths', () => {
  test('launcher failure during the baseline yields a skipped summary instead of throwing', async () => {
    const launcher = async () => { throw new Error('lab server failed to boot') }
    const summary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest(),
      launcher,
    }))
    assert.equal(summary.attempted, 0)
    assert.equal(summary.fixed, 0)
    assert.deepEqual(summary.perPatch, [])
    assert.match(summary.skippedReason ?? '', /Baseline pipeline failed/)
    assert.match(summary.skippedReason ?? '', /lab server failed to boot/)
  })

  test('an unapproved patch id fails only that patch and leaves partial results', async () => {
    const calls: FakeLauncherCall[] = []
    const hooks = runtimeHooks({
      baselineFindings: [finding('hos-01'), finding('hos-99')],
      fixedByPatch: () => true,
      launch: fakeLauncher(['hos-01', 'hos-02', 'hos-03'], calls),
    })
    const summary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest([
        { id: 'hos-01', patchId: 'hos-01' },
        { id: 'hos-99', patchId: 'hos-99' },
      ]),
      launcher: fakeLauncher(['hos-01', 'hos-02', 'hos-03'], []),
      hooks,
      patchTimeoutMs: 2_000,
    }))
    assert.equal(summary.attempted, 2)
    assert.equal(summary.fixed, 1)
    assert.equal(summary.perPatch[1].after, 'error')
    assert.equal(summary.perPatch[1].fixed, false)
    assert.match((summary.perPatch[1].notes ?? []).join(' '), /Unknown held-out SaaS patch id/)
    // The first patch still ran; the all-patches launch is poisoned by the unknown id, so the pass
    // reports inconclusive rather than throwing.
    assert.equal(summary.perPatch[0].fixed, true)
    assert.equal(summary.allPatches?.attempted, false)
    assert.equal(summary.allPatches?.verdict, 'inconclusive')
    assert.match((summary.allPatches?.notes ?? []).join(' '), /did not complete/)
    assert.deepEqual(calls.map(c => c.patchedIds), [['hos-01']])
  })

  test('a patched-target replay error is not counted as fixed', async () => {
    const calls: FakeLauncherCall[] = []
    const hooks = runtimeHooks({
      baselineFindings: [finding('hos-01')],
      fixedByPatch: () => true,
      replayErrorsFor: ['hos-01'],
    })
    const summary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest([{ id: 'hos-01', patchId: 'hos-01' }]),
      launcher: fakeLauncher(['hos-01'], calls),
      hooks,
      patchTimeoutMs: 2_000,
    }))
    assert.equal(summary.reproducedBefore, 1)
    assert.equal(summary.fixed, 0)
    assert.equal(summary.perPatch[0].after, 'error')
    assert.equal(summary.perPatch[0].fixedAfter, false)
    assert.match((summary.perPatch[0].notes ?? []).join(' '), /simulated replay failure/)
  })

  test('a hung patch retest is bounded by the per-patch timeout', async () => {
    const calls: FakeLauncherCall[] = []
    const hooks = runtimeHooks({
      baselineFindings: [finding('hos-01'), finding('hos-02')],
      fixedByPatch: () => true,
      replayHangsFor: ['hos-02'],
    })
    const started = Date.now()
    const summary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest(),
      launcher: fakeLauncher(['hos-01', 'hos-02', 'hos-03'], calls),
      hooks,
      patchTimeoutMs: 40,
      allPatchesTimeoutMs: 80,
    }))
    const elapsed = Date.now() - started
    assert.equal(summary.perPatch[1].after, 'timeout')
    assert.match((summary.perPatch[1].notes ?? []).join(' '), /Timed out/)
    assert.equal(summary.perPatch[0].fixed, true)
    assert.ok(elapsed < 5_000, `timeout was not bounded (took ${elapsed}ms)`)
  })

  test('an all-patches timeout marks the pass inconclusive but keeps per-patch results', async () => {
    const calls: FakeLauncherCall[] = []
    const base = runtimeHooks({ baselineFindings: [finding('hos-01')], fixedByPatch: () => true })
    const hooks: PatchVerificationHooks = {
      ...base,
      replayAll: async ({ findings, patchedIds }) => {
        // Per-patch retests (one id) settle; the all-patches baseline replay (two ids) hangs.
        if (patchedIds.length > 1) return await new Promise(() => { /* hang the all-patches replay */ })
        return await base.replayAll!({ findings, patchedIds, timeoutMs: 2_000, signal: new AbortController().signal })
      },
    }
    const summary = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest(),
      launcher: fakeLauncher(['hos-01', 'hos-02', 'hos-03'], calls),
      hooks,
      patchTimeoutMs: 2_000,
      allPatchesTimeoutMs: 40,
    }))
    assert.equal(summary.perPatch[0].fixed, true)
    assert.equal(summary.allPatches?.attempted, false)
    assert.equal(summary.allPatches?.verdict, 'inconclusive')
    assert.match((summary.allPatches?.notes ?? []).join(' '), /did not complete/)
    assert.equal(summary.decoyFalsePositivesAfter, undefined)
  })

  test('refuses to run without the local-lab gate and skips manifests without patches', async () => {
    const gated = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: undefined }, () => verifyPatchesLive({
      manifest: manifest(),
      launcher: async () => { throw new Error('must not be called') },
    }))
    assert.match(gated.skippedReason ?? '', /GUARDIAN_ALLOW_LOCAL_LAB/)

    const noPatches = await withEnv({ GUARDIAN_ALLOW_LOCAL_LAB: '1' }, () => verifyPatchesLive({
      manifest: manifest([{ id: 'hos-01' }, { id: 'hos-d1', isDecoy: true }]),
      launcher: async () => { throw new Error('must not be called') },
    }))
    assert.equal(noPatches.attempted, 0)
    assert.match(noPatches.skippedReason ?? '', /no non-decoy challenge with a patchId/)
  })

  test('PatchTimeoutError identifies the bounded operation', () => {
    const err = new PatchTimeoutError('patch hos-01 retest', 25)
    assert.equal(err.name, 'PatchTimeoutError')
    assert.match(err.message, /patch hos-01 retest timed out after 25 ms/)
  })
})

describe('M7 held-out: replay rebasing + persona adapter', () => {
  test('normalizes the lab array persona shape into the engine map shape', () => {
    const map = normalizePersonaMap([
      { handle: 'persona_a', roleLabel: 'member', authKind: 'bearer', secret: 'a-token', userId: 'u_acme_1', tenantId: 'acme' },
      { handle: 'persona_b', roleLabel: 'member', secret: 'b-token', userId: 'u_globex_1' },
      { handle: 'admin', roleLabel: 'admin', token: 'admin-token', headerName: 'Authorization' },
    ])
    assert.deepEqual(map.persona_a, { token: 'a-token', role: 'member', userId: 'u_acme_1' })
    assert.equal(map.persona_b.token, 'b-token')
    assert.deepEqual(map.admin, { token: 'admin-token', headerName: 'Authorization', role: 'admin' })
    assert.deepEqual(normalizePersonaMap(undefined), {})
    const already = { persona_a: { token: 'x' } }
    assert.equal(normalizePersonaMap(already), already)
  })

  test('rebases structural origins for a fresh server but leaves payload URLs alone', () => {
    const spec = {
      version: 1,
      origin: 'http://127.0.0.1:3001',
      targetOrigin: 'http://127.0.0.1:3001',
      steps: [
        { id: 'c1', request: { origin: 'http://127.0.0.1:3001', pathAndQuery: '/api/v1/invoices/1001' } },
        { id: 'p1', request: { origin: 'http://127.0.0.1:3001', jsonBody: { url: 'http://127.0.0.1:9999/collect', origin: 'payload-value' } } },
      ],
      controlStep: { origin: 'http://127.0.0.1:3001', request: { origin: 'http://127.0.0.1:3001', pathAndQuery: '/api/v1/invoices/1001' } },
    }
    const rebased = rebaseSpecOrigin(spec, 'http://127.0.0.1:41234')
    assert.equal(rebased.origin, 'http://127.0.0.1:41234')
    assert.equal(rebased.targetOrigin, 'http://127.0.0.1:41234')
    assert.equal(rebased.steps[0]?.request.origin, 'http://127.0.0.1:41234')
    assert.equal(rebased.steps[1]?.request.origin, 'http://127.0.0.1:41234')
    // SSRF/webhook payloads must not be rewritten onto the new target origin.
    assert.equal(rebased.steps[1]?.request.jsonBody?.url, 'http://127.0.0.1:9999/collect')
    assert.equal(rebased.steps[1]?.request.jsonBody?.origin, 'payload-value')
    assert.equal(rebased.controlStep.request.origin, 'http://127.0.0.1:41234')
    // Input is not mutated.
    assert.equal(spec.origin, 'http://127.0.0.1:3001')
  })
})

describe('M7 held-out: CLI wiring', () => {
  test('--verify-patches accepts the held-out suite and preserves existing flags', () => {
    const opts = parseBenchmarkCliArgs([
      '--suite', 'held-out-saas', '--profile-mode', 'v4-full', '--verify-patches',
      '--verifier-backend', 'local-jq', '--git-sha', 'heldout-pre', '--out-md', '/tmp/pre.md',
    ])
    assert.equal(opts.suite, 'held-out-saas')
    assert.equal(opts.profileMode, 'v4-full')
    assert.equal(opts.verifyPatches, true)
    assert.equal(opts.verifierBackend, 'local-jq')
    assert.equal(opts.gitSha, 'heldout-pre')
    assert.equal(opts.outMd, '/tmp/pre.md')
  })

  test('--verify-patches=false is rejected rather than silently ignored', () => {
    assert.throws(() => parseBenchmarkCliArgs(['--verify-patches=false']), /does not take a value/)
  })
})
