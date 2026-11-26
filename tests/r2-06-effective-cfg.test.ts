/**
 * R2-06 vertical slice tests:
 *  1. `conventionalWordlistEnabled()` defaults OFF (`false`) and requires explicit opt-in.
 *  2. `Execution` emits ONE structured `run.effective_config` event near run start (with R2-23
 *     floor duration & request cap policy), and `computeEffectiveConfig` reads it and FAILS
 *     closed (`EffectiveConfigMismatchError`) whenever a caller-declared literal disagrees.
 *  3. Store refuses harness-built `verifiedInline` / `runtime_confirmed` without a verifier-issued
 *     receipt or authorized host `backingKind` (and `benchmark-realism.ts` excludes `harness_assisted`).
 *  4. `certify-phase1` and `certify-v8` refuse `wordlistOn=true`, `reportable=false`, null config
 *     hash, mixed `benchmarkVersion`, and mismatched `sdkVersion` / `workerImageId`.
 *  5. `verify-rpc.ts` + `kovo_verify.ts` align on `kovo_verify/v8` and enforce the `hello` / header
 *     handshake (rejecting stale `v6-mvp` or mismatched versions, accepting matching `kovo_verify/v8`).
 *  6. `scripts/benchmark-backend.ts` resolves `KOVO_WORKER_IMAGE` identically to `LinuxWorkerBackend`
 *     and parses `kovo.worker.source_hash` / `kovo.worker.sdk_version` LABELs (matching `worker/Dockerfile`).
 *  7. `scripts/hillclimb-loop.sh` exits non-zero when the agentic leg is skipped (no Docker socket).
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'

import { conventionalWordlistEnabled } from '../src/server/deterministic-engine.ts'
import { Execution } from '../src/server/execution.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import type { Finding } from '../src/domain.ts'
import { InvariantError } from '../src/server/store-session.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SDK_VERSION,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VERIFY_SDK_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { KOVO_VERIFY_SDK_VERSION, VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'
import {
  EffectiveConfigMismatchError,
  computeEffectiveConfig,
  extractObservedEffectiveConfig,
} from '../scripts/bench-ledger.ts'
import {
  DEFAULT_WORKER_IMAGE,
  inspectDockerWorkerImage,
  resolveWorkerImageRef,
} from '../scripts/benchmark-backend.ts'
import { translateFindings } from '../scripts/benchmark-realism.ts'
import {
  CERTIFY_APPS,
  evaluateCertification,
  type RealismRun,
  type ReasonRun,
} from '../scripts/certify-phase1.ts'
import {
  evaluateV8Certification,
  type MultihopCellInput,
} from '../scripts/certify-v8.ts'
import { makeStore, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
const REPO_ROOT = resolve(import.meta.dirname, '..')

function makeSimpleSpec(origin: string, path = '/api/items/1'): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Synthetic differential verification fixture',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Synthetic test fixture.',
    impact: 'Cross-account data read.',
    remediation: 'Enforce ownership check.',
    recheckInstructions: 'Replay control and probe.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "200", expected: "403" }',
    spaCatchallControl: false,
    steps: [
      { id: 'c1', role: 'control', description: 'Control', request: { origin, method: 'GET', pathAndQuery: path, followRedirects: false }, expectedStatus: 403 },
      { id: 'p1', role: 'probe', description: 'Probe', request: { origin, method: 'GET', pathAndQuery: path, followRedirects: false }, expectedStatus: 200 },
    ],
  }
}

function makeConfirmedFinding(id: string, origin: string, scopeRevision: number, replaySpecId: string): Finding {
  return {
    id,
    origin,
    title: 'Synthetic access boundary finding',
    status: 'confirmed',
    severity: 'high',
    reason: 'Control denied; probe succeeded.',
    remediation: 'Check ownership.',
    evidenceIds: [],
    scopeRevision,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    confidence: 'high',
    verification: 'Synthetic verification fixture.',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
    replaySpecId,
  }
}

function sendRawRpc(
  socketPath: string,
  headers: Record<string, string>,
  payload: Record<string, unknown>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const data = JSON.stringify(payload)
  return new Promise((resolvePromise, reject) => {
    const req = httpRequest(
      {
        socketPath,
        path: '/rpc',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(data)),
          ...headers,
        },
      },
      res => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => chunks.push(c))
        res.on('end', () => {
          resolvePromise({
            status: res.statusCode ?? 0,
            body: JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>,
          })
        })
      },
    )
    req.on('error', reject)
    req.end(data)
  })
}

function makeValidPhase1Matrix(override?: (run: RealismRun, idx: number) => void): { runs: RealismRun[]; reason: ReasonRun[] } {
  const runs: RealismRun[] = []
  let seq = 0
  const mk = (app: string, seed: number, seedSet: 'dev' | 'held-out', llm: 'agentic' | 'deterministic-no-llm', confirmed: number, floorConfirmed?: number): RealismRun => {
    seq += 1
    const keys = Array.from({ length: confirmed }, (_, i) => `${app}|${app}-site-${i}`)
    const fc = floorConfirmed ?? confirmed
    const run: RealismRun = {
      id: `r-${seq}`,
      dir: '/synthetic',
      file: null,
      app,
      seed,
      seedSet,
      mode: 'grey-box',
      llm,
      targets: 22,
      confirmed,
      recall: confirmed / 22,
      precision: 1,
      cellConcurrency: 1,
      workerConcurrency: llm === 'agentic' ? 4 : 1,
      strictPrecision: 1,
      incompatibleClassCount: 0,
      misclassifiedFindingIds: [],
      decoyFalsePositives: 0,
      unmatchedFalsePositives: 0,
      confirmedKeys: keys,
      floor: {
        floorConfirmed: fc,
        floorLeadsConsumed: 4,
        floorLeadsEmitted: 4,
        floorLeadsQueued: 4,
        floorLeadsInvestigated: 4,
        source: 'synthetic',
      },
      provenance: llm === 'agentic' ? { floor: fc, agentOnly: Math.max(0, confirmed - fc), chainFromFloor: 0 } : null,
      provenanceComplete: true,
      provenanceSource: 'synthetic',
      advisories: 0,
      contractLeaks: 0,
      notes: [],
      benchmarkVersion: 'a'.repeat(64),
      effectiveConfigHash: 'b'.repeat(64),
      reportable: true,
      wordlistOn: false,
      workerImageId: 'sha256:1111111111111111',
      sdkVersion: VERIFY_RPC_SDK_VERSION,
    }
    return run
  }
  for (const app of CERTIFY_APPS) {
    for (const c of [10, 10, 10]) runs.push(mk(app, 1, 'dev', 'deterministic-no-llm', c))
    runs.push(mk(app, 1_000_043, 'held-out', 'deterministic-no-llm', 8))
    for (const c of [12, 14, 16]) runs.push(mk(app, 1, 'dev', 'agentic', c, 10))
    for (const c of [12, 14]) runs.push(mk(app, 1_000_043, 'held-out', 'agentic', c, 8))
  }
  if (override) runs.forEach(override)
  const reason: ReasonRun[] = [{
    source: 'synthetic',
    cells: [
      { app: 'ledgerflow', seed: 1, mode: 'grey-box', llm: 'deterministic-no-llm', targets: 14, confirmed: 0, recall: 0, precision: null, decoyFalsePositives: 0, unmatchedFalsePositives: 0, sites: Array.from({ length: 14 }, (_, i) => ({ siteId: `l-${i}`, confirmed: false })) },
      { app: 'forgecloud', seed: 1, mode: 'grey-box', llm: 'deterministic-no-llm', targets: 14, confirmed: 0, recall: 0, precision: null, decoyFalsePositives: 0, unmatchedFalsePositives: 0, sites: Array.from({ length: 14 }, (_, i) => ({ siteId: `f-${i}`, confirmed: false })) },
    ],
  }]
  return { runs, reason }
}

function makeValidV8M2Cells(override?: (cell: MultihopCellInput, idx: number) => void): MultihopCellInput[] {
  const apps = ['paygrid', 'shipforge', 'nexusiam'] as const
  const cells: MultihopCellInput[] = []
  for (const app of apps) {
    cells.push({
      schemaVersion: 1,
      app,
      sealed: false,
      seed: 1,
      seedSet: 'dev',
      mode: 'white-box',
      llm: 'deterministic-no-llm',
      budgetUsd: 0,
      maxDurationMs: 300_000,
      costUsd: 0,
      durationMs: 30_000,
      chainsTotal: 4,
      chainsConfirmed: 0,
      precision: null,
      hardenedTwinsTotal: 3,
      hardenedTwinDecoyFps: 0,
      unmatchedFalsePositives: 0,
      benchmarkVersion: 'a'.repeat(64),
      effectiveConfigHash: 'b'.repeat(64),
      reportable: true,
      wordlistOn: false,
      workerImageId: 'sha256:2222222222222222',
      sdkVersion: VERIFY_RPC_SDK_VERSION,
    })
  }
  for (const [mode, confirmed] of [['grey-box', 2], ['white-box', 3]] as const) {
    for (const app of apps) {
      cells.push({
        schemaVersion: 1,
        app,
        sealed: false,
        seed: 1,
        seedSet: 'dev',
        mode,
        llm: 'agentic',
        budgetUsd: 5,
        maxDurationMs: 1_800_000,
        costUsd: 3,
        durationMs: 600_000,
        chainsTotal: 4,
        chainsOracleObserved: confirmed,
        chainsCompositeConfirmed: confirmed,
        chainsConfirmed: confirmed,
        recall: confirmed / 4,
        precision: 1,
        hardenedTwinsTotal: 3,
        hardenedTwinDecoyFps: 0,
        unmatchedFalsePositives: 0,
        benchmarkVersion: 'a'.repeat(64),
        effectiveConfigHash: 'b'.repeat(64),
        reportable: true,
        wordlistOn: false,
        workerImageId: 'sha256:2222222222222222',
        sdkVersion: VERIFY_RPC_SDK_VERSION,
      })
    }
  }
  if (override) cells.forEach(override)
  return cells
}

describe('R2-06: wordlist default OFF, effective_config event, Store guard, certify refusals, worker identity & hillclimb', () => {
  test('1. conventionalWordlistEnabled() defaults OFF and requires explicit opt-in', () => {
    assert.equal(conventionalWordlistEnabled({}), false)
    assert.equal(conventionalWordlistEnabled({ KOVO_CONVENTIONAL_WORDLIST: '' }), false)
    assert.equal(conventionalWordlistEnabled({ KOVO_CONVENTIONAL_WORDLIST: '0' }), false)
    assert.equal(conventionalWordlistEnabled({ KOVO_CONVENTIONAL_WORDLIST: 'false' }), false)
    assert.equal(conventionalWordlistEnabled({ KOVO_CONVENTIONAL_WORDLIST: '1' }), true)
    assert.equal(conventionalWordlistEnabled({ KOVO_CONVENTIONAL_WORDLIST: 'true' }), true)
    assert.equal(conventionalWordlistEnabled({ KOVO_CONVENTIONAL_WORDLIST: 'on' }), true)
  })

  test('2. Execution emits run.effective_config once and computeEffectiveConfig fails closed on caller literal mismatch', async t => {
    const { storage } = makeStore(t, 'r2-06-effective-cfg-')
    const { runId } = await setupApprovedRun(storage, { budgetRequests: 400 })
    const engine = new Execution(storage, { deterministicOnly: true, maxDurationMs: 300_000 })
    t.after(async () => { await engine.stop() })
    // Invoke private tick/recorder by starting and waking once, then stopping cleanly.
    ;(engine as unknown as { ensureEffectiveConfigRecorded: (r: ReturnType<typeof storage.run>, p: unknown[]) => void })
      .ensureEffectiveConfigRecorded(storage.run(runId), [])
    // Calling a second time must be idempotent (only ONE event emitted).
    ;(engine as unknown as { ensureEffectiveConfigRecorded: (r: ReturnType<typeof storage.run>, p: unknown[]) => void })
      .ensureEffectiveConfigRecorded(storage.run(runId), [])

    const events = storage.eventsAfter(runId, 0, 200)
    const cfgEvents = events.filter(e => e.kind === 'run.effective_config')
    assert.equal(cfgEvents.length, 1, 'Execution must emit exactly one run.effective_config event per run')

    const observed = extractObservedEffectiveConfig(events)
    assert.ok(observed, 'extractObservedEffectiveConfig must parse the engine event')
    assert.equal(observed.deterministicOnly, true)
    assert.equal(observed.wordlistOn, false)
    assert.equal(observed.sdkVersion, VERIFY_RPC_SDK_VERSION)
    assert.equal(typeof observed.floorDurationMs, 'number')
    assert.equal(typeof observed.floorRequestCap, 'number')
    assert.equal(observed.floorPolicy, 'no_llm_240s')

    // Matching caller config succeeds and hashes observed fields.
    const ok = computeEffectiveConfig({
      observedEvents: events,
      deterministicOnly: true,
      wordlistOn: false,
      sdkVersion: VERIFY_RPC_SDK_VERSION,
      env: {},
    })
    assert.match(ok.effectiveConfigHash, /^[0-9a-f]{64}$/)
    assert.equal(ok.effectiveConfig.wordlistOn, false)
    assert.equal(ok.effectiveConfig.floorDurationMs, observed.floorDurationMs)

    // Caller literal disagreeing with observed event MUST throw EffectiveConfigMismatchError!
    assert.throws(
      () => computeEffectiveConfig({
        observedEvents: events,
        deterministicOnly: true,
        wordlistOn: true, // disagrees with observed wordlistOn=false!
        env: {},
      }),
      (err: unknown) => err instanceof EffectiveConfigMismatchError && err.mismatches.some(m => m.field === 'wordlistOn'),
    )
    assert.throws(
      () => computeEffectiveConfig({
        observedEvents: events,
        deterministicOnly: false, // disagrees with observed deterministicOnly=true!
        env: {},
      }),
      (err: unknown) => err instanceof EffectiveConfigMismatchError && err.mismatches.some(m => m.field === 'deterministicOnly'),
    )
    assert.throws(
      () => computeEffectiveConfig({
        observedEvents: events,
        sdkVersion: 'kovo_verify/v6-mvp', // disagrees with observed kovo_verify/v8!
        env: {},
      }),
      (err: unknown) => err instanceof EffectiveConfigMismatchError && err.mismatches.some(m => m.field === 'sdkVersion'),
    )
  })

  test('3. Store refuses harness-built verifiedInline & runtime_confirmed without receipt or authorized backingKind', async t => {
    const { storage } = makeStore(t, 'r2-06-store-guard-')
    const { runId } = await setupApprovedRun(storage, { budgetRequests: 300 })
    const run = storage.run(runId)
    const asset = run.candidates[0]!
    const origin = asset.origin
    const worker = storage.makeWorker(run, 'investigation', asset, 'Harness', 'Test harness guard')

    // (a) verifiedInline: true with no diff, no receipt, no backingKind -> MUST throw
    assert.throws(
      () => storage.createReplaySpec(run, worker, randomUUID(), makeSimpleSpec(origin), [origin], {
        verifiedInline: true,
      }),
      (err: unknown) => err instanceof InvariantError && err.code === 'invariant.unbacked_verified_inline',
    )

    // (b) verifiedInline: true tagged harness_assisted -> MUST throw
    assert.throws(
      () => storage.createReplaySpec(run, worker, randomUUID(), makeSimpleSpec(origin), [origin], {
        verifiedInline: true,
        backingKind: 'harness_assisted',
        lastVerificationDiff: { verdict: 'confirmed', controlPassed: true, stepStatuses: [], retriesRemaining: 0 },
      }),
      (err: unknown) => err instanceof InvariantError && err.code === 'invariant.harness_assisted_confirmation',
    )

    // (c) verifiedInline: true with requireReceiptOrBackingKind and bare self-built diff -> MUST throw
    assert.throws(
      () => storage.createReplaySpec(run, worker, randomUUID(), makeSimpleSpec(origin), [origin], {
        verifiedInline: true,
        requireReceiptOrBackingKind: true,
        lastVerificationDiff: { verdict: 'confirmed', controlPassed: true, stepStatuses: [], retriesRemaining: 0 },
      }),
      (err: unknown) => err instanceof InvariantError && err.code === 'invariant.unbacked_verified_inline',
    )

    // (d) upsertChainFinding with harness_assisted or requireReceiptOrBackingKind without receipt -> MUST throw
    const fid = randomUUID()
    const spec = storage.createReplaySpec(run, worker, fid, makeSimpleSpec(origin), [origin], {
      verifiedInline: true,
      backingKind: 'inline_verifier',
      lastVerificationDiff: { verdict: 'confirmed', controlPassed: true, stepStatuses: [], retriesRemaining: 0 },
    })
    assert.throws(
      () => storage.upsertChainFinding(run, asset.id, makeConfirmedFinding(fid, origin, run.scopeRevision, spec.id), spec.id, [origin], {
        backingKind: 'harness_assisted',
      }),
      (err: unknown) => err instanceof InvariantError && err.code === 'invariant.harness_assisted_confirmation',
    )
    assert.throws(
      () => storage.upsertChainFinding(run, asset.id, makeConfirmedFinding(fid, origin, run.scopeRevision, spec.id), spec.id, [origin], {
        requireReceiptOrBackingKind: true,
      }),
      (err: unknown) => err instanceof InvariantError && err.code === 'invariant.confirmation_evidence',
    )

    // (e) Verifier-issued confirmed ProofReceipt succeeds cleanly even under requireReceiptOrBackingKind
    const receiptFid = randomUUID()
    const receiptSpec = storage.createReplaySpec(run, worker, receiptFid, makeSimpleSpec(origin, '/api/items/9'), [origin], {
      verifiedInline: true,
      requireReceiptOrBackingKind: true,
      proof: {
        replaySpecId: '',
        findingId: receiptFid,
        verdict: 'confirmed',
        runtime: 'ts',
        scriptSha256: 'c'.repeat(64),
        artifactId: null,
        receipt: {
          receipt: {
            vulnClass: 'idor',
            target: { origin, method: 'GET', pathAndQuery: '/api/items/9' },
            exchangeIds: ['ex-1'],
            oobEventIds: [],
            browserTraceIds: [],
            claimedDelta: 'Cross-account read verified.',
          },
          verification: {
            confirmed: true,
            vulnClass: 'idor',
            rule: 'idor',
            reason: 'Verified.',
            observed: '200',
            expected: '403',
          },
        },
        createdAt: Date.now(),
      },
    })
    const saved = storage.upsertChainFinding(
      run, asset.id, makeConfirmedFinding(receiptFid, origin, run.scopeRevision, receiptSpec.id), receiptSpec.id, [origin],
      { requireReceiptOrBackingKind: true },
    )
    assert.equal(saved.status, 'confirmed')

    // (f) translateFindings excludes harness_assisted findings from product confirmed recall
    const translated = translateFindings({
      findings: [
        { ...makeConfirmedFinding('h-1', origin, run.scopeRevision, receiptSpec.id), provenance: 'harness_assisted' } as unknown as Finding,
      ],
      replaySpecs: [{ id: receiptSpec.id, findingId: 'h-1', spec: makeSimpleSpec(origin), createdAt: Date.now() }],
      exchanges: [],
      origins: { app: origin },
      secrets: [],
    })
    assert.equal(translated.findings.length, 0)
  })

  test('4. certify-phase1 and certify-v8 refuse wordlistOn=true, reportable=false, null config hash, mixed benchmarkVersion & mismatched sdk/image', () => {
    // Baseline clean matrices PASS
    const base1 = makeValidPhase1Matrix()
    const certOk = evaluateCertification(base1.runs, base1.reason, { mode: 'from-dir', gitSha: 'abc123' })
    assert.equal(certOk.verdict, 'PASS')
    assert.equal(certOk.status, 'VALID')

    const v8Ok = evaluateV8Certification({ gate: 'm2', cells: makeValidV8M2Cells() })
    assert.equal(v8Ok.verdict, 'PASS')
    assert.equal(v8Ok.status, 'VALID')

    const phase1BadCases: Array<[string, (r: RealismRun, i: number) => void]> = [
      ['wordlistOn=true', (r, i) => { if (i === 0) r.wordlistOn = true }],
      ['reportable=false', (r, i) => { if (i === 0) r.reportable = false }],
      ['null effectiveConfigHash', (r, i) => { if (i === 0) r.effectiveConfigHash = null }],
      ['mixed benchmarkVersion', (r, i) => { if (i === 1) r.benchmarkVersion = 'f'.repeat(64) }],
      ['mismatched sdkVersion', (r, i) => { if (i === 0) r.sdkVersion = 'kovo_verify/v6-mvp' }],
      ['mismatched workerImageId', (r, i) => { if (i === 1) r.workerImageId = 'sha256:9999999999999999' }],
    ]
    for (const [label, mutate] of phase1BadCases) {
      const m = makeValidPhase1Matrix(mutate)
      const cert = evaluateCertification(m.runs, m.reason, { mode: 'from-dir', gitSha: 'abc123' })
      assert.equal(cert.status, 'INVALID', `certify-phase1 must mark INVALID on ${label}`)
      assert.equal(cert.verdict, 'FAIL', `certify-phase1 must FAIL on ${label}`)
      assert.ok(cert.criteria.some(c => c.id === 'provenance_integrity' && c.status === 'FAIL'), `expected provenance_integrity FAIL for ${label}`)
      if (label === 'mixed benchmarkVersion') {
        assert.equal(cert.benchmarkVersion, 'MIXED', 'must never silently fall back to tree version on mixed benchmarkVersion')
      }
    }

    const v8BadCases: Array<[string, (c: MultihopCellInput, i: number) => void]> = [
      ['wordlistOn=true', (c, i) => { if (i === 0) c.wordlistOn = true }],
      ['reportable=false', (c, i) => { if (i === 0) c.reportable = false }],
      ['null effectiveConfigHash', (c, i) => { if (i === 0) c.effectiveConfigHash = null }],
      ['mixed benchmarkVersion', (c, i) => { if (i === 1) c.benchmarkVersion = 'f'.repeat(64) }],
      ['mismatched sdkVersion', (c, i) => { if (i === 0) c.sdkVersion = 'kovo_verify/v6-mvp' }],
      ['mismatched workerImageId', (c, i) => { if (i === 1) c.workerImageId = 'sha256:8888888888888888' }],
    ]
    for (const [label, mutate] of v8BadCases) {
      const rep = evaluateV8Certification({ gate: 'm2', cells: makeValidV8M2Cells(mutate) })
      assert.equal(rep.status, 'INVALID', `certify-v8 must mark INVALID on ${label}`)
      assert.equal(rep.verdict, 'FAIL', `certify-v8 must FAIL on ${label}`)
      assert.ok(rep.checks.some(c => c.id === 'provenance_integrity' && c.status === 'FAIL'), `expected provenance_integrity FAIL for ${label}`)
      if (label === 'mixed benchmarkVersion') {
        assert.equal(rep.benchmarkVersion, 'MIXED', 'certify-v8 must never fall back to tree version on mixed benchmarkVersion')
      }
    }
  })

  test('5. verify-rpc.ts & kovo_verify.ts align on kovo_verify/v8 and enforce hello/header handshake', async t => {
    assert.equal(VERIFY_RPC_SDK_VERSION, 'kovo_verify/v8')
    assert.equal(KOVO_VERIFY_SDK_VERSION, VERIFY_RPC_SDK_VERSION)

    const grant: Grant = {
      canRead: () => true,
      audit: () => undefined,
      allowLocalLab: true,
      tier: 3,
      personas: new Map(),
      secrets: [],
    }
    const rpc = new VerifyRpcServer({
      broker: new RequestBroker(),
      grant,
      runId: 'run-handshake',
      assignmentId: 'assign-handshake',
      targetOrigins: ['http://127.0.0.1:9999'],
    })
    await rpc.start()
    t.after(async () => { await rpc.close() })

    // Raw hello with stale sdkVersion MUST be rejected (both in hello payload and header).
    const badHeader = await sendRawRpc(
      rpc.socketPath,
      {
        [VERIFY_RPC_HEADER]: rpc.token,
        [VERIFY_NONCE_HEADER]: rpc.nonce,
        [VERIFY_SDK_HEADER]: 'kovo_verify/v6-mvp',
      },
      { op: 'hello', args: { sdkVersion: VERIFY_RPC_SDK_VERSION } },
    )
    assert.equal(badHeader.status, 403)
    assert.equal(badHeader.body.ok, false)

    const badPayload = await sendRawRpc(
      rpc.socketPath,
      {
        [VERIFY_RPC_HEADER]: rpc.token,
        [VERIFY_NONCE_HEADER]: rpc.nonce,
        [VERIFY_SDK_HEADER]: VERIFY_RPC_SDK_VERSION,
      },
      { op: 'hello', args: { sdkVersion: 'kovo_verify/v6-mvp' } },
    )
    assert.equal(badPayload.status, 200)
    assert.equal(badPayload.body.ok, false)
    assert.match(String(badPayload.body.error), /SDK version mismatch/i)

    // Matching VerifyContext.hello() MUST succeed and return kovo_verify/v8.
    const prev = {
      sock: process.env[VERIFY_RPC_SOCKET_ENV],
      tok: process.env[VERIFY_RPC_TOKEN_ENV],
      ctx: process.env[VERIFY_RPC_CONTEXT_ENV],
      nonce: process.env[VERIFY_NONCE_ENV],
    }
    process.env[VERIFY_RPC_SOCKET_ENV] = rpc.socketPath
    process.env[VERIFY_RPC_TOKEN_ENV] = join(rpc.hostDir, 'token')
    process.env[VERIFY_RPC_CONTEXT_ENV] = join(rpc.hostDir, 'context.json')
    process.env[VERIFY_NONCE_ENV] = rpc.nonce
    try {
      const ctx = new VerifyContext()
      assert.equal(ctx.sdkVersion, VERIFY_RPC_SDK_VERSION)
      const hello = await ctx.hello()
      assert.equal(hello.sdkVersion, VERIFY_RPC_SDK_VERSION)
      assert.equal(hello.runId, 'run-handshake')
      await assert.rejects(() => ctx.hello('kovo_verify/v6-mvp'), /SDK version mismatch/i)
    } finally {
      for (const [k, v] of [
        [VERIFY_RPC_SOCKET_ENV, prev.sock],
        [VERIFY_RPC_TOKEN_ENV, prev.tok],
        [VERIFY_RPC_CONTEXT_ENV, prev.ctx],
        [VERIFY_NONCE_ENV, prev.nonce],
      ] as const) {
        if (v === undefined) delete process.env[k]
        else process.env[k] = v
      }
    }
  })

  test('6. benchmark-backend resolves KOVO_WORKER_IMAGE and inspects LABELs matching worker/Dockerfile', async () => {
    assert.equal(resolveWorkerImageRef({}), DEFAULT_WORKER_IMAGE)
    assert.equal(resolveWorkerImageRef({ KOVO_WORKER_IMAGE: 'kovo-worker:custom-sha' }), 'kovo-worker:custom-sha')
    const inspected = await inspectDockerWorkerImage('kovo-worker:custom-sha', async (_file, args) => {
      if (args[0] === 'info') return { code: 0, stdout: '27.0.0\n', stderr: '' }
      assert.equal(args[args.length - 1], 'kovo-worker:custom-sha')
      return { code: 0, stdout: 'sha256:deadbeef0123\tabcdef123456\tkovo_verify/v8\n', stderr: '' }
    })
    assert.deepEqual(inspected, {
      imageRef: 'kovo-worker:custom-sha',
      imageId: 'sha256:deadbeef0123',
      sourceHash: 'abcdef123456',
      sdkVersion: 'kovo_verify/v8',
    })
    const dockerfile = readFileSync(join(REPO_ROOT, 'worker/Dockerfile'), 'utf8')
    assert.match(dockerfile, /ARG\s+KOVO_WORKER_SOURCE_HASH/)
    assert.match(dockerfile, /LABEL\s+[^\n]*kovo\.worker\.source_hash=/)
    assert.match(dockerfile, /kovo\.worker\.sdk_version=/)
  })

  test('7. hillclimb-loop.sh exits non-zero when agentic leg is skipped (docker unreachable)', t => {
    const tmp = mkdtempSync(join(tmpdir(), 'r2-06-hillclimb-'))
    t.after(() => rmSync(tmp, { recursive: true, force: true }))
    const fakeBin = join(tmp, 'bin')
    const outDir = join(tmp, 'out')
    writeFileSync(join(tmp, 'dummy'), '')
    // Create stub `docker` returning rc 1 and stub `npm` returning rc 0 so check leg is instant.
    spawnSync('mkdir', ['-p', fakeBin])
    const fakeDocker = join(fakeBin, 'docker')
    writeFileSync(fakeDocker, '#!/usr/bin/env bash\nexit 1\n')
    chmodSync(fakeDocker, 0o755)
    const fakeNpm = join(fakeBin, 'npm')
    writeFileSync(fakeNpm, '#!/usr/bin/env bash\necho ok\nexit 0\n')
    chmodSync(fakeNpm, 0o755)

    const res = spawnSync('bash', [join(REPO_ROOT, 'scripts/hillclimb-loop.sh'), '--smoke'], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH ?? ''}`,
        HILLCLIMB_SKIP_REALISTIC: '1',
        HILLCLIMB_OUT: outDir,
      },
      encoding: 'utf8',
    })
    assert.notEqual(res.status, 0, `expected non-zero exit when agentic leg is skipped; stdout=${res.stdout}`)
    const agenticRc = readFileSync(join(outDir, 'agentic.rc'), 'utf8').trim()
    assert.notEqual(agenticRc, '0')
    assert.match(readFileSync(join(outDir, 'agentic.log'), 'utf8'), /skipped/i)
  })
})
