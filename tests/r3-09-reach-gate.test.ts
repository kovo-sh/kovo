/**
 * R3-09 Fast Guard Suite (`tests/r3-09-reach-gate.test.ts`).
 *
 * Covers:
 *  1. `scripts/check-run-scoped-state.ts` detects undisposed class-field `Map`/`Set` keyed by
 *     `runId`/`assignmentId`, passes when backed by `runState.mapView(...)` or explicitly disposed,
 *     and passes on the live repo (with `ExecWorkerRunner.providerRetryCountsByRun` and
 *     `providerRetriesTotalByRun` migrated onto `runState.mapView`).
 *  2. `ExecWorkerRunner` disposes `providerRetryCountsByRun` & `providerRetriesTotalByRun`
 *     automatically via `runState.disposeRun(runId)` AND via `runAllRunDisposers(runId)` fallback.
 *  3. `scripts/check-direct-db-writes.ts` passes with 0 violations on the live repo, and
 *     `src/server/report-export.ts` has 0 direct `.db` writes.
 *  4. `scripts/check-unwired.ts` production-entrypoint reachability walker reports exact
 *     `reachable` / `testOnly` / `unreachable` counts on synthetic graphs (including dead-to-dead
 *     chains that syntactic checks miss) and passes on the live repo with
 *     `resolveProviderStallNoTokenMs` deleted.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { scanDirectDbWrites } from '../scripts/check-direct-db-writes.ts'
import { scanRunScopedState } from '../scripts/check-run-scoped-state.ts'
import { runUnwiredCheck } from '../scripts/check-unwired.ts'
import { RunOrchestrationStateStore } from '../src/server/exec-dispatch.ts'
import { ExecWorkerRunner, type ExecWorkerHost } from '../src/server/exec-worker-runner.ts'
import { runAllRunDisposers } from '../src/server/run-disposers.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

function makeTmpDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

describe('R3-09 #1: class-field run-scoped Map detection & ExecWorkerRunner disposal', () => {
  test('check-run-scoped-state flags undisposed class-field Maps keyed by runId/assignmentId and passes when disposed or mapView-backed', (t) => {
    const tmpRoot = makeTmpDir(t, 'r309-class-map-')
    mkdirSync(join(tmpRoot, 'src/server'), { recursive: true })

    // 1. Undisposed class-field Maps keyed by runId and assignmentId -> MUST FAIL
    writeFileSync(
      join(tmpRoot, 'src/server/leaky-runner.ts'),
      [
        'export class LeakyRunner {',
        '  private readonly retryCountsByRun = new Map<string, number>()',
        '  private readonly pendingByAssign = new Map<string, string>()',
        '  track(runId: string, assignmentId: string) {',
        '    this.retryCountsByRun.set(runId, 1)',
        '    this.pendingByAssign.set(assignmentId, "busy")',
        '  }',
        '}',
      ].join('\n') + '\n',
    )
    const failed = scanRunScopedState(tmpRoot, { baselinedKeys: [], baselineMax: 0 })
    assert.equal(failed.ok, false, 'undisposed class-field Maps MUST fail check-run-scoped-state')
    assert.deepEqual(
      failed.newViolations.map(v => v.key),
      [
        'src/server/leaky-runner.ts::LeakyRunner.pendingByAssign',
        'src/server/leaky-runner.ts::LeakyRunner.retryCountsByRun',
      ],
    )
    assert.ok(failed.newViolations.every(v => v.scope === 'class-field'))

    // 2. Same class migrated onto runState.mapView(...) + explicit delete -> MUST PASS
    writeFileSync(
      join(tmpRoot, 'src/server/leaky-runner.ts'),
      [
        'export class CleanRunner {',
        '  private readonly retryCountsByRun: Map<string, number>',
        '  private readonly pendingByAssign = new Map<string, string>()',
        '  constructor(runState: { mapView: (k: string) => Map<string, number> }) {',
        '    this.retryCountsByRun = runState.mapView("providerRetriesTotal")',
        '  }',
        '  track(runId: string, assignmentId: string) {',
        '    this.retryCountsByRun.set(runId, 1)',
        '    this.pendingByAssign.set(assignmentId, "busy")',
        '  }',
        '  cleanup(assignmentId: string) {',
        '    this.pendingByAssign.delete(assignmentId)',
        '  }',
        '}',
      ].join('\n') + '\n',
    )
    const passed = scanRunScopedState(tmpRoot, { baselinedKeys: [], baselineMax: 0 })
    assert.equal(passed.ok, true, `expected PASS after mapView + delete, got: ${JSON.stringify(passed.newViolations)}`)
    assert.equal(passed.newViolations.length, 0)
    assert.equal(passed.unregisteredCount, 0)
  })

  test('check-run-scoped-state passes on live repo and reports zero violations in exec-worker-runner.ts', () => {
    const res = scanRunScopedState(REPO_ROOT)
    assert.equal(res.ok, true, `live repo check-run-scoped-state failed: ${JSON.stringify(res.newViolations)}`)
    assert.equal(res.newViolations.length, 0)
    assert.equal(
      res.unregistered.some(f => f.file === 'src/server/exec-worker-runner.ts'),
      false,
      'exec-worker-runner.ts must have 0 unregistered per-run Maps',
    )
  })

  test('ExecWorkerRunner backs providerRetryCountsByRun & providerRetriesTotalByRun via runState.mapView and disposes cleanly', () => {
    // Path A: shared RunOrchestrationStateStore passed via host.runState
    const sharedRunState = new RunOrchestrationStateStore()
    const runnerWithShared = new ExecWorkerRunner({ runState: sharedRunState } as unknown as ExecWorkerHost)
    const internalA = runnerWithShared as unknown as {
      providerRetryCountsByRun: Map<string, Map<string, number>>
      providerRetriesTotalByRun: Map<string, number>
    }
    internalA.providerRetryCountsByRun.set('run-r309-a', new Map([['step-1', 2]]))
    internalA.providerRetriesTotalByRun.set('run-r309-a', 2)
    assert.equal(sharedRunState.get('run-r309-a')?.providerRetriesTotal, 2)
    assert.equal(sharedRunState.get('run-r309-a')?.providerRetryCounts?.get('step-1'), 2)

    sharedRunState.disposeRun('run-r309-a')
    assert.equal(internalA.providerRetryCountsByRun.has('run-r309-a'), false)
    assert.equal(internalA.providerRetriesTotalByRun.has('run-r309-a'), false)

    // Path B: host.runState omitted -> fallback own RunOrchestrationStateStore disposed by runAllRunDisposers
    const runnerFallback = new ExecWorkerRunner({} as unknown as ExecWorkerHost)
    const internalB = runnerFallback as unknown as {
      providerRetryCountsByRun: Map<string, Map<string, number>>
      providerRetriesTotalByRun: Map<string, number>
    }
    internalB.providerRetryCountsByRun.set('run-r309-b', new Map([['step-2', 3]]))
    internalB.providerRetriesTotalByRun.set('run-r309-b', 3)
    assert.equal(internalB.providerRetriesTotalByRun.get('run-r309-b'), 3)

    runAllRunDisposers('run-r309-b')
    assert.equal(internalB.providerRetryCountsByRun.has('run-r309-b'), false)
    assert.equal(internalB.providerRetriesTotalByRun.has('run-r309-b'), false)
  })
})

describe('R3-09 #2: direct DB writes ratchet passes cleanly', () => {
  test('check-direct-db-writes passes on live repo with 0 violations and 0 hits in report-export.ts', () => {
    const res = scanDirectDbWrites(REPO_ROOT)
    assert.equal(res.ok, true, `expected 0 direct-db regressions, got: ${res.regressions.join('; ')}`)
    assert.equal(res.regressions.length, 0)
    assert.equal(res.findingsWriteHits.length, 0)
    assert.equal(res.countsByFile['src/server/report-export.ts'] ?? 0, 0, 'report-export.ts must have 0 direct .db writes')
  })
})

describe('R3-09 #5: production-entrypoint reachability walker & dead export removal', () => {
  test('reachability walker classifies reachable, testOnly, and unreachable exports accurately (including dead-to-dead chains)', (t) => {
    const dir = makeTmpDir(t, 'r309-reach-')
    mkdirSync(join(dir, 'src/server'), { recursive: true })
    mkdirSync(join(dir, 'scripts'), { recursive: true })
    mkdirSync(join(dir, 'tests'), { recursive: true })

    // Production entrypoint reaches `liveRoot` -> `liveHelper`
    writeFileSync(join(dir, 'src/server.ts'), "import { liveRoot } from './server/core.ts'\nconsole.log(liveRoot())\n")
    writeFileSync(
      join(dir, 'src/server/core.ts'),
      [
        'export function liveHelper(): number { return 7 }',
        'export function liveRoot(): number { return liveHelper() }',
        'export function testOnlyFn(): number { return 9 }',
        'export function deadInternalHelper(): number { return 11 }',
        'export function deadCaller(): number { return deadInternalHelper() }',
      ].join('\n') + '\n',
    )
    // Dead module importing from another dead module: neither is reachable from any entrypoint!
    writeFileSync(
      join(dir, 'src/server/dead-leaf.ts'),
      'export function deadLeaf(): number { return 1 }\n',
    )
    writeFileSync(
      join(dir, 'src/server/dead-consumer.ts'),
      "import { deadLeaf } from './dead-leaf.ts'\nexport function deadConsumer(): number { return deadLeaf() }\n",
    )
    writeFileSync(
      join(dir, 'tests/core.test.ts'),
      "import { testOnlyFn } from '../src/server/core.ts'\nconsole.log(testOnlyFn())\n",
    )

    const baselinePath = join(dir, 'scripts/unwired-baseline.json')
    writeFileSync(
      baselinePath,
      JSON.stringify({
        version: 1,
        allowedCycles: [],
        keepUnwired: [],
        baselinedExports: [
          'src/server/core.ts::deadCaller',
          'src/server/core.ts::testOnlyFn',
          'src/server/dead-consumer.ts::deadConsumer',
        ],
      }),
    )

    const res = runUnwiredCheck({ rootDir: dir, baselinePath, now: '2026-11-26' })
    assert.equal(res.ok, true, `expected baseline PASS: ${JSON.stringify(res)}`)
    assert.equal(res.reachability.entrypoints, 1)
    assert.equal(res.reachability.reachable, 2, 'only liveRoot and liveHelper are reachable from src/server.ts')
    assert.deepEqual(res.reachability.testOnlyKeys, ['src/server/core.ts::testOnlyFn'])
    assert.deepEqual(res.reachability.unreachableKeys, [
      'src/server/core.ts::deadCaller',
      'src/server/core.ts::deadInternalHelper',
      'src/server/dead-consumer.ts::deadConsumer',
      'src/server/dead-leaf.ts::deadLeaf',
    ])
    assert.equal(
      res.reachability.reachable + res.reachability.testOnly + res.reachability.unreachable,
      res.totalServerValueExports,
      'reachability partition must sum exactly to totalServerValueExports',
    )
  })

  test('live repo check-unwired passes with resolveProviderStallNoTokenMs removed and valid reachability partition', () => {
    const dispatchSrc = readFileSync(join(REPO_ROOT, 'src/server/exec-dispatch.ts'), 'utf8')
    assert.equal(
      dispatchSrc.includes('resolveProviderStallNoTokenMs'),
      false,
      'resolveProviderStallNoTokenMs must be deleted from src/server/exec-dispatch.ts',
    )

    const res = runUnwiredCheck({ rootDir: REPO_ROOT })
    assert.equal(res.ok, true, `check-unwired failed on live repo: newUnwired=${res.newUnwiredExports.length}, resolved=${res.resolvedBaselineExports.length}`)
    assert.equal(res.newCycles.length, 0)
    assert.equal(res.newUnwiredExports.length, 0)
    assert.equal(res.resolvedBaselineExports.length, 0)
    assert.ok(res.reachability.entrypoints > 0)
    assert.ok(res.reachability.reachable > 0)
    assert.equal(
      res.reachability.reachable + res.reachability.testOnly + res.reachability.unreachable,
      res.totalServerValueExports,
    )
  })
})
