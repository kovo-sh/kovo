// @kernel @fixes R4-H-8, R4-H-9, R4-H-10
/**
 * R4 WS-12 Class-Level Guards — Gate-6 Composite Retest Truthfulness (R4-H-9),
 * Proposal-Scoped Gate-6 Isolation & Newest-by-createdAt Export (R4-H-10),
 * and Explicit runId Threading in patch-workflow Syntax Checks (R4-H-8).
 */
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { desc, eq } from 'drizzle-orm'
import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { sha256Hex } from '../src/server/composite-receipt.ts'
import type { CompositeProofReceipt } from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import { applyUnifiedDiffToDirectory } from '../src/server/lab-runner.ts'
import type { LabRunner } from '../src/server/lab-runner.ts'
import {
  generateAndReviewPatch,
  retestCompositeChainPatch,
  runPatchAuthor,
  runPatchReviewer,
  verifyCompositePatchRetestProofIntegrity,
} from '../src/server/patch-workflow.ts'
import {
  exportRunReceiptBundle,
  verifyProofReceiptBundle,
} from '../src/server/receipt-export.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import { findings as findingsTable, replaySpecs, reports, retestRuns } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend, WorkerSessionOptions } from '../src/server/worker-backend.ts'

function makeTempDir(prefix: string, t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), `kovo-r4-g6-${prefix}-`))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function enableLocalLabEnv(t: { after: (fn: () => void) => void }): void {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  })
}

function makeGrant(origin: string): Grant {
  return {
    origin,
    tier: 2,
    allowLocalLab: true,
    canRead: o => o === origin,
    audit: () => {},
    personas: new Map([
      ['alice', { id: 'p-alice', handle: 'alice', roleLabel: 'member (org-a)', originAllowlist: [origin], authKind: 'bearer', headerName: 'Authorization', secret: 'Bearer tok-alice', canaryMarkers: [] }],
      ['bob', { id: 'p-bob', handle: 'bob', roleLabel: 'member (org-b)', originAllowlist: [origin], authKind: 'bearer', headerName: 'Authorization', secret: 'Bearer tok-bob', canaryMarkers: [] }],
    ]),
  }
}

function makeStoreWithRun(t: { after: (fn: () => void) => void }, origin: string) {
  enableLocalLabEnv(t)
  const dataDir = makeTempDir('store', t)
  const storage = new Store(dataDir)
  t.after(() => storage.close())
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'R4 Gate6 Retest Guard Project',
    seeds: [origin],
    environment: 'local-lab',
  })
  const run = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify R4-H-8/9/10 Gate-6 composite retest & export guards',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 50,
    maxRpsPerOrigin: 10,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })
  storage.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })
  const asset = storage.run(run.id).candidates[0]!
  storage.command({
    requestId: randomUUID(),
    runId: run.id,
    action: 'scope',
    expectedScopeRevision: 0,
    assetIds: [asset.id],
    consent: true,
    capabilityTier: 2,
  })
  const hydratedRun = storage.run(run.id)
  const worker = storage.makeWorker(hydratedRun, 'investigation', asset, 'Probe', 'R4 Gate6 worker')
  return { storage, project, run: hydratedRun, asset, worker }
}

function makeApproveReviewer(enforcingLocation: string) {
  return async () => JSON.stringify({
    approved: true,
    callerCompatibility: 'attacker_only',
    enforcingLocation,
    gates: {
      applicability: { passed: true, detail: 'Applies cleanly.' },
      security_closure: { passed: true, detail: 'Enforces tenant authorization.', enforcingLocation },
      sibling_coverage: { passed: true, detail: 'All sibling handlers covered.' },
      caller_compatibility: { passed: true, detail: 'Authorized callers preserved.' },
      repo_conventions: { passed: true, detail: 'Idiomatic.' },
    },
    reviewNotes: 'Statically approved.',
  })
}

function makeStubBackend(onRun?: (options?: WorkerSessionOptions) => void): WorkerBackend {
  return {
    async run(_job, _signal, options) {
      onRun?.(options)
      return { exitCode: 0, stdout: 'syntax-ok\n', stderr: '', outputs: {}, durationMs: 1, timedOut: false }
    },
    async openSession() { throw new Error('unused') },
    async verifyStaticAst() {
      return { verified: true, engine: 'ast-grep', repo: 'svc', file: 'src/export.ts', startLine: 1, endLine: 1, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
  }
}

function makeRepoAndLab(t: { after: (fn: () => void) => void }, origin: string) {
  const reposDir = makeTempDir('repos', t)
  const repoDir = join(reposDir, 'svc')
  const liveDir = makeTempDir('live', t)
  mkdirSync(join(repoDir, 'src'), { recursive: true })
  mkdirSync(join(liveDir, 'src'), { recursive: true })
  const vulnCode = 'export function downloadExport(ownerTenant: string, callerTenant: string) {\n  return { ok: true, ownerTenant }\n}\n'
  writeFileSync(join(repoDir, 'src/export.ts'), vulnCode)
  writeFileSync(join(liveDir, 'src/export.ts'), vulnCode)

  let rebuildCount = 0
  const labRunner = {
    rebuildWithPatch: async (_runId: string, diff: string) => {
      rebuildCount += 1
      applyUnifiedDiffToDirectory(liveDir, diff)
      return {
        targetId: 't-r4', origin, containerName: `c-r4-${rebuildCount}`, containerNames: [`c-r4-${rebuildCount}`],
        containerIp: '127.0.0.1', internalPort: 4490, healthPath: '/health', networkName: 'net', imageName: 'img',
        sanitizedRepoDir: liveDir, telemetryDir: liveDir, startedAt: Date.now(),
      }
    },
  } as unknown as LabRunner

  return { reposDir, liveDir, vulnCode, labRunner, getRebuildCount: () => rebuildCount }
}

function makeHttpReplaySpec(origin: string): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Multi-hop cross-tenant export disclosure',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Multi-hop directory + mint + download chain.',
    impact: 'Foreign tenant invoice export disclosed.',
    remediation: 'Verify caller tenant equals export owner tenant.',
    recheckInstructions: 'Replay composite DAG.',
    assertionsJq: '.steps | length > 0',
    spaCatchallControl: false,
    steps: [
      { id: 'c1', role: 'control', description: 'owner directory read', request: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory', persona: 'alice', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'foreign download', request: { origin, method: 'GET', pathAndQuery: '/api/v1/exports/exp-900/download', persona: 'bob', followRedirects: false } },
    ],
  }
}

function seedCompositeFinding(params: {
  storage: Store
  run: ReturnType<Store['run']>
  assetId: string
  worker: ReturnType<Store['makeWorker']>
  origin: string
  withFactLog?: boolean
  withValueDigests?: boolean
  ex2ReqHeaders?: Record<string, string>
  ex2RawBody?: string
  ex3Path?: string
  ex3ReqHeaders?: Record<string, string>
}) {
  const { storage, run, assetId, worker, origin } = params
  const findingId = `finding-r4-${randomUUID().slice(0, 8)}`
  const exBase = {
    runId: run.id,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [] as string[],
    mediaType: 'application/json',
    respHeaders: { 'content-type': 'application/json' },
    durationMs: 3,
  }
  const origDirTok = 'dir-nonce-orig-111'
  const origExpTok = 'exp-nonce-orig-222'
  const ex2RawBody = params.ex2RawBody ?? JSON.stringify({ directoryToken: origDirTok, exportId: 'exp-900' })
  const ex3Path = params.ex3Path ?? '/api/v1/exports/exp-900/download'
  const ex3Headers = params.ex3ReqHeaders ?? { 'x-export-token': origExpTok }

  const exCtrl = storage.recordExchange({
    ...exBase,
    method: 'GET',
    pathAndQuery: '/api/v1/exports/exp-900/download',
    personaHandle: 'bob',
    reqHeaders: {},
    status: 403,
    body: JSON.stringify({ error: 'forbidden' }),
  })
  const ex1 = storage.recordExchange({
    ...exBase,
    method: 'GET',
    pathAndQuery: '/api/v1/org/directory',
    personaHandle: 'bob',
    reqHeaders: {},
    status: 200,
    body: JSON.stringify({ tenant: 'org-b', directoryToken: origDirTok }),
  })
  const ex2 = storage.recordExchange({
    ...exBase,
    method: 'POST',
    pathAndQuery: '/api/v1/exports/mint',
    personaHandle: 'bob',
    reqHeaders: params.ex2ReqHeaders ?? { 'content-type': 'application/json', 'content-length': String(ex2RawBody.length) },
    status: 200,
    body: JSON.stringify({ exportToken: origExpTok }),
  })
  const ex3 = storage.recordExchange({
    ...exBase,
    method: 'GET',
    pathAndQuery: ex3Path,
    personaHandle: 'bob',
    reqHeaders: ex3Headers,
    status: 200,
    body: JSON.stringify({ tenantId: 'org-a', invoiceId: 'inv-100', amount: 9500 }),
  })

  let factLog: HostFactLog | undefined
  if (params.withFactLog) {
    factLog = new HostFactLog()
    factLog.recordExchange({
      exchangeId: exCtrl.id,
      origin,
      method: 'GET',
      pathAndQuery: '/api/v1/exports/exp-900/download',
      status: 403,
      actor: 'bob',
      requestHeaders: {},
      rawRequestBody: null,
      responseHeaders: { 'content-type': 'application/json' },
      rawResponseBody: JSON.stringify({ error: 'forbidden' }),
    })
    factLog.recordExchange({
      exchangeId: ex1.id,
      origin,
      method: 'GET',
      pathAndQuery: '/api/v1/org/directory',
      status: 200,
      actor: 'bob',
      requestHeaders: {},
      rawRequestBody: null,
      responseHeaders: { 'content-type': 'application/json' },
      rawResponseBody: JSON.stringify({ tenant: 'org-b', directoryToken: origDirTok }),
    })
    factLog.recordExchange({
      exchangeId: ex2.id,
      origin,
      method: 'POST',
      pathAndQuery: '/api/v1/exports/mint',
      status: 200,
      actor: 'bob',
      requestHeaders: params.ex2ReqHeaders ?? { 'content-type': 'application/json' },
      rawRequestBody: ex2RawBody,
      responseHeaders: { 'content-type': 'application/json' },
      rawResponseBody: JSON.stringify({ exportToken: origExpTok }),
    })
    factLog.recordExchange({
      exchangeId: ex3.id,
      origin,
      method: 'GET',
      pathAndQuery: ex3Path,
      status: 200,
      actor: 'bob',
      requestHeaders: ex3Headers,
      rawRequestBody: null,
      responseHeaders: { 'content-type': 'application/json' },
      rawResponseBody: JSON.stringify({ tenantId: 'org-a', invoiceId: 'inv-100', amount: 9500 }),
    })
  }

  const cap1 = 'cap:hop-1:directory_token'
  const cap2 = 'cap:hop-2:export_token'
  const compositeReceipt: CompositeProofReceipt = {
    chainId: `chain-r4-${randomUUID().slice(0, 8)}`,
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      {
        hopId: 'hop-1',
        surface: 'http',
        target: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory' },
        exchangeIds: [ex1.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Directory lookup returns dynamic token',
        producedCapabilities: [cap1],
        consumedCapabilities: [],
      },
      {
        hopId: 'hop-2',
        surface: 'http',
        target: { origin, method: 'POST', pathAndQuery: '/api/v1/exports/mint' },
        exchangeIds: [ex2.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Mint endpoint requires JSON body + fresh directory token',
        producedCapabilities: [cap2],
        consumedCapabilities: [cap1],
      },
      {
        hopId: 'hop-3',
        surface: 'http',
        target: { origin, method: 'GET', pathAndQuery: ex3Path },
        exchangeIds: [ex3.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Download endpoint leaks foreign tenant org-a invoice when given fresh export token',
        producedCapabilities: [],
        consumedCapabilities: [cap2],
      },
    ],
    causalEdges: [
      {
        kind: 'value_binding',
        fromHopId: 'hop-1',
        toHopId: 'hop-2',
        capabilityHandle: cap1,
        ...(params.withValueDigests ? { valueDigest: sha256Hex(origDirTok) } : {}),
        sourceExchangeId: ex1.id,
        targetExchangeId: ex2.id,
      },
      {
        kind: 'value_binding',
        fromHopId: 'hop-2',
        toHopId: 'hop-3',
        capabilityHandle: cap2,
        ...(params.withValueDigests ? { valueDigest: sha256Hex(origExpTok) } : {}),
        sourceExchangeId: ex2.id,
        targetExchangeId: ex3.id,
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop-3',
      summary: 'Foreign org-a invoice records exported across tenant boundary by org-b member',
      claimedImpact: 'Foreign org-a invoice records exported across tenant boundary by org-b member',
      preChainControlExchangeIds: [exCtrl.id],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  const spec = makeHttpReplaySpec(origin)
  const specRow = storage.createReplaySpec(run, worker, findingId, spec, [origin])
  const proofPayload = {
    receipt: {
      vulnClass: 'dual_tenant_abac',
      target: { origin, method: 'GET', pathAndQuery: ex3Path },
      exchangeIds: [ex1.id, ex2.id, ex3.id],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: 'Foreign org-a invoice records exported across tenant boundary',
    },
    verification: {
      confirmed: true,
      vulnClass: 'dual_tenant_abac',
      rule: 'composite:fresh_clean_replay',
      reason: '3-hop composite chain confirmed',
      observed: '3-hop CompositeProofReceipt',
      expected: 'tenant isolation enforced',
    },
    compositeReceipt,
    hopActors: { 'hop-1': 'bob', 'hop-2': 'bob', 'hop-3': 'bob' },
  }
  storage.db
    .update(replaySpecs)
    .set({ proofReceipt: proofPayload as unknown as typeof specRow.proofReceipt })
    .where(eq(replaySpecs.id, specRow.id))
    .run()

  const finding: Finding & { codeLocations?: Array<{ repo: string; file: string; startLine: number; endLine: number }> } = {
    id: findingId,
    origin,
    title: 'Multi-hop cross-tenant export disclosure',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    status: 'confirmed',
    reason: '3-hop chain leaks foreign org-a invoice data.',
    remediation: 'Verify caller tenant equals export owner tenant.',
    evidenceIds: [],
    exchangeIds: [ex1.id, ex2.id, ex3.id],
    scopeRevision: run.scopeRevision,
    replaySpecId: specRow.id,
    codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
  }

  storage.db.insert(findingsTable).values({
    id: findingId,
    runId: run.id,
    assetId,
    goalRevision: run.goalRevision,
    checkId: 'chain',
    caseId: `r4-g6-${findingId}`,
    findingKind: 'multi_step_chain',
    replaySpecId: specRow.id,
    provenance: 'agent_only',
    verificationClass: 'runtime_confirmed',
    sourceOrigins: [origin],
    verificationTier: 'runtime_confirmed',
    fingerprintHash: createHash('sha256').update(findingId).digest('hex'),
    status: 'confirmed',
    severity: 'high',
    cwe: 'CWE-639',
    origin,
    finding,
  }).run()

  return { finding, specRow, spec, compositeReceipt, factLog, ex1, ex2, ex3, exCtrl }
}

// ============================================================================
// Guard 1 (R4-H-9): Unpatched body-validating target + no-op patch NEVER yields 'fixed'
// ============================================================================

test('R4-H-9 Guard 1: Body-validating unpatched target with no-op patch NEVER yields fixed (inconclusive without factLog, reproduced with factLog)', async (t) => {
  const origin = 'http://127.0.0.1:4491'
  const { storage, run, asset, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, labRunner } = makeRepoAndLab(t, origin)

  // Target strictly validates JSON request body on POST /api/v1/exports/mint (returns 400 on empty body).
  let minted = false
  const origRebuild1 = labRunner.rebuildWithPatch.bind(labRunner)
  labRunner.rebuildWithPatch = async (runIdArg, diffArg, sigArg) => {
    minted = false
    return origRebuild1(runIdArg, diffArg, sigArg)
  }
  const makeBodyValidatingBroker = () => new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url, _addr, _sig, opts) => {
      const path = new URL(url).pathname
      if (path === '/api/v1/org/directory') {
        minted = false
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'org-b', directoryToken: 'dir-nonce-orig-111' }) }
      }
      if (path === '/api/v1/exports/mint') {
        const rawBody = typeof opts?.body === 'string' ? opts.body.trim() : ''
        if (!rawBody) {
          return { status: 400, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'body_required' }) }
        }
        const parsed = JSON.parse(rawBody) as { exportId?: string }
        if (parsed.exportId !== 'exp-900') {
          return { status: 422, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'invalid_export_id' }) }
        }
        minted = true
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ exportToken: 'exp-nonce-orig-222' }) }
      }
      if (path === '/api/v1/exports/exp-900/download') {
        if (!minted) return { status: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'forbidden_before_mint' }) }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenantId: 'org-a', invoiceId: 'inv-100', amount: 9500 }) }
      }
      return { status: 404, headers: { 'content-type': 'application/json' }, body: '{}' }
    },
  })

  // Case 1A: No factLog (request body missing from broker_exchanges) -> MUST fail closed as inconclusive/withheld, NEVER fixed/approved!
  const noFactSeed = seedCompositeFinding({ storage, run, assetId: asset.id, worker, origin, withFactLog: false })
  const noFactRes = await generateAndReviewPatch({
    runId: run.id,
    finding: noFactSeed.finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  // no-op comment\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'No-op patch.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: noFactSeed.spec,
      replaySpecId: noFactSeed.specRow.id,
      broker: makeBodyValidatingBroker(),
      backend: makeStubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
      baselineCaller: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory', persona: 'alice' },
      baselineExpectStatus: [200],
    },
  })
  assert.notEqual(noFactRes.status, 'approved', 'no-op patch on body-validating target must NEVER be approved')
  assert.notEqual(noFactRes.dynamicRetestVerdict, 'fixed')
  assert.equal(noFactRes.compositeVerdict, 'inconclusive')
  assert.equal(noFactRes.status, 'withheld')
  assert.equal(noFactRes.gates.find(g => g.gate === 6)?.passed, false)

  // Case 1B: With host factLog carrying sealed rawRequestBody -> faithfully replays body and reproduces no-op patch as still_vulnerable/rejected!
  const withFactSeed = seedCompositeFinding({ storage, run, assetId: asset.id, worker, origin, withFactLog: true })
  const withFactRes = await generateAndReviewPatch({
    runId: run.id,
    finding: withFactSeed.finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  // no-op comment\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'No-op patch.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: withFactSeed.spec,
      replaySpecId: withFactSeed.specRow.id,
      broker: makeBodyValidatingBroker(),
      factLog: withFactSeed.factLog,
      backend: makeStubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
      baselineCaller: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory', persona: 'alice' },
      baselineExpectStatus: [200],
    },
  })
  assert.equal(withFactRes.status, 'rejected', withFactRes.reviewNotes)
  assert.equal(withFactRes.dynamicRetestVerdict, 'reproduced')
  assert.equal(withFactRes.compositeVerdict, 'still_vulnerable')
  assert.equal(withFactRes.gates.find(g => g.gate === 6)?.passed, false)

  // Case 1C: Even if stateful target leaves pre-chain control returning 200 (missing denied control),
  // Gate 6 MUST fail closed as precondition_changed/withheld — NEVER 'fixed'!
  minted = true
  const driftedCtrlProof = await retestCompositeChainPatch({
    receipt: withFactSeed.compositeReceipt,
    brokerContext: {
      broker: makeBodyValidatingBroker(),
      grant: makeGrant(origin),
      storage,
      runId: run.id,
      factLog: withFactSeed.factLog,
      hopActors: { 'hop-1': 'bob', 'hop-2': 'bob', 'hop-3': 'bob' },
    },
  })
  assert.equal(driftedCtrlProof.verdict, 'precondition_changed')
  assert.equal(driftedCtrlProof.patchClosed, false)
})

// ============================================================================
// Guard 2 (R4-H-9): Token/nonce-validating target + redacted/browser/OOB/401 fail-closed
// ============================================================================

test('R4-H-9 Guard 2: Nonce-rotating target faithfully re-binds fresh tokens (reproduced on no-op, fixed on real fix) and fails closed when un-rebindable, redacted, browser/OOB unavailable, or 401 session-drifted', async (t) => {
  const origin = 'http://127.0.0.1:4492'
  const { storage, run, asset, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, labRunner } = makeRepoAndLab(t, origin)

  // Target mints a fresh nonce on EVERY call to hop-1 and hop-2, and strictly validates those fresh nonces
  // on hop-2 (JSON body) and hop-3 (query param) — rejecting stale nonces with HTTP 403!
  let nonceSeq = 0
  let activeDirNonce = ''
  let activeExpNonce = ''
  const isPatched = () => readFileSync(join(liveDir, 'src/export.ts'), 'utf8').includes('ownerTenant !== callerTenant')
  const makeNonceValidatingBroker = () => new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url, _addr, _sig, opts) => {
      const parsedUrl = new URL(url)
      if (parsedUrl.pathname === '/api/v1/org/directory') {
        nonceSeq += 1
        activeDirNonce = `dir-fresh-nonce-${nonceSeq}`
        activeExpNonce = ''
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'org-b', directoryToken: activeDirNonce }) }
      }
      if (parsedUrl.pathname === '/api/v1/exports/mint') {
        const body = typeof opts?.body === 'string' && opts.body.trim() ? JSON.parse(opts.body) as { directoryToken?: string } : {}
        if (!activeDirNonce || body.directoryToken !== activeDirNonce) {
          return { status: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'stale_directory_nonce' }) }
        }
        nonceSeq += 1
        activeExpNonce = `exp-fresh-nonce-${nonceSeq}`
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ exportToken: activeExpNonce }) }
      }
      if (parsedUrl.pathname === '/api/v1/exports/exp-900/download') {
        const suppliedTok = Object.entries(opts?.headers ?? {}).find(([k]) => k.toLowerCase() === 'x-export-token')?.[1] ?? ''
        if (!activeExpNonce || suppliedTok !== activeExpNonce || isPatched()) {
          return { status: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'forbidden_or_stale_export_token' }) }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenantId: 'org-a', invoiceId: 'inv-100', amount: 9500 }) }
      }
      return { status: 404, headers: { 'content-type': 'application/json' }, body: '{}' }
    },
  })

  // Case 2A: With factLog + valueDigest on edges + no-op patch -> MUST dynamically re-bind fresh nonces
  // (NOT fail on old valueDigest!) and reproduce as still_vulnerable/rejected!
  const seeded = seedCompositeFinding({ storage, run, assetId: asset.id, worker, origin, withFactLog: true, withValueDigests: true })
  const noopRes = await generateAndReviewPatch({
    runId: run.id,
    finding: seeded.finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  // ineffective patch\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Ineffective patch.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: seeded.spec,
      replaySpecId: seeded.specRow.id,
      broker: makeNonceValidatingBroker(),
      factLog: seeded.factLog,
      backend: makeStubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
      baselineCaller: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory', persona: 'alice' },
      baselineExpectStatus: [200],
    },
  })
  assert.equal(noopRes.status, 'rejected', noopRes.reviewNotes)
  assert.equal(noopRes.dynamicRetestVerdict, 'reproduced')
  assert.equal(noopRes.compositeVerdict, 'still_vulnerable')

  // Case 2B: Same nonce-rotating target with a GENUINE patch -> unpatched control reproduces via fresh re-binding,
  // then patched lab blocks at hop-3 -> approved & fixed!
  const fixedRes = await generateAndReviewPatch({
    runId: run.id,
    finding: seeded.finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  if (ownerTenant !== callerTenant) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce tenant isolation.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: seeded.spec,
      replaySpecId: seeded.specRow.id,
      broker: makeNonceValidatingBroker(),
      factLog: seeded.factLog,
      backend: makeStubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
      baselineCaller: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory', persona: 'alice' },
      baselineExpectStatus: [200],
    },
  })
  assert.equal(fixedRes.status, 'approved', fixedRes.reviewNotes)
  assert.equal(fixedRes.dynamicRetestVerdict, 'fixed')
  assert.equal(fixedRes.compositeVerdict, 'fixed')
  assert.equal(fixedRes.patchBrokeHopId, 'hop-3')
  assert.equal(verifyCompositePatchRetestProofIntegrity(fixedRes.compositeRetestProof!), true)

  // Case 2C: Redacted non-persona header unavailable in factLog -> fails closed as inconclusive (NEVER fixed)!
  const redactedSeed = seedCompositeFinding({
    storage, run, assetId: asset.id, worker, origin,
    withFactLog: false,
    ex2ReqHeaders: { 'x-custom-secret-hdr': '[redacted:cap:secret_hdr]' },
  })
  const redactedProof = await retestCompositeChainPatch({
    receipt: redactedSeed.compositeReceipt,
    brokerContext: {
      broker: makeNonceValidatingBroker(),
      grant: makeGrant(origin),
      storage,
      runId: run.id,
      assignmentId: worker.id,
      hopActors: { 'hop-1': 'bob', 'hop-2': 'bob', 'hop-3': 'bob' },
    },
  })
  assert.equal(redactedProof.verdict, 'inconclusive')
  assert.equal(redactedProof.patchClosed, false)

  // Case 2D: Browser or OOB terminal hop without ScopedBrowser / CanaryBroker -> fails closed as inconclusive!
  const browserReceipt: CompositeProofReceipt = {
    ...seeded.compositeReceipt,
    chainId: `chain-browser-${randomUUID().slice(0, 8)}`,
    hops: seeded.compositeReceipt.hops.map(h => h.hopId === 'hop-3' ? { ...h, surface: 'browser', browserTraceIds: ['tr-1'] } : h),
  }
  const browserProof = await retestCompositeChainPatch({
    receipt: browserReceipt,
    brokerContext: {
      broker: makeNonceValidatingBroker(),
      grant: makeGrant(origin),
      storage,
      runId: run.id,
      factLog: seeded.factLog,
      hopActors: { 'hop-1': 'bob', 'hop-2': 'bob', 'hop-3': 'bob' },
    },
  })
  assert.equal(browserProof.verdict, 'inconclusive')
  assert.match(browserProof.summary, /ScopedBrowser|inconclusive/i)

  const oobReceipt: CompositeProofReceipt = {
    ...seeded.compositeReceipt,
    chainId: `chain-oob-${randomUUID().slice(0, 8)}`,
    hops: seeded.compositeReceipt.hops.map(h => h.hopId === 'hop-3' ? { ...h, oobEventIds: ['oob-1'] } : h),
  }
  const oobProof = await retestCompositeChainPatch({
    receipt: oobReceipt,
    brokerContext: {
      broker: makeNonceValidatingBroker(),
      grant: makeGrant(origin),
      storage,
      runId: run.id,
      factLog: seeded.factLog,
      hopActors: { 'hop-1': 'bob', 'hop-2': 'bob', 'hop-3': 'bob' },
    },
  })
  assert.equal(oobProof.verdict, 'inconclusive')
  assert.match(oobProof.summary, /CanaryBroker|inconclusive/i)

  // Case 2E: Authenticated 401 session drift -> inconclusive per retest-health.ts (NEVER fixed)!
  const driftedBroker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async () => ({ status: 401, headers: { 'content-type': 'application/json' }, body: '{"error":"token_expired"}' }),
  })
  const driftProof = await retestCompositeChainPatch({
    receipt: seeded.compositeReceipt,
    brokerContext: {
      broker: driftedBroker,
      grant: makeGrant(origin),
      storage,
      runId: run.id,
      factLog: seeded.factLog,
      hopActors: { 'hop-1': 'bob', 'hop-2': 'bob', 'hop-3': 'bob' },
    },
  })
  assert.equal(driftProof.verdict, 'inconclusive')
  assert.equal(driftProof.patchClosed, false)
})

// ============================================================================
// Guard 3 (R4-H-10): Candidate Gate-6 never pollutes finding records + newest Verify Fix wins in exports
// ============================================================================

test('R4-H-10 Guard 3: Rejected/unmerged Gate-6 candidate patch never writes retest_runs or replay_specs.proof_receipt; newer reproduced retest wins in receipt-export and report-export', async (t) => {
  const origin = 'http://127.0.0.1:4493'
  const { storage, run, asset, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, labRunner } = makeRepoAndLab(t, origin)
  const seeded = seedCompositeFinding({ storage, run, assetId: asset.id, worker, origin, withFactLog: true })

  // Patched lab blocks hop-3 BUT ALSO breaks the authorized baseline caller (alice gets 500) -> Gate 6 REJECTS the patch!
  let minted = false
  const origRebuild3 = labRunner.rebuildWithPatch.bind(labRunner)
  labRunner.rebuildWithPatch = async (runIdArg, diffArg, sigArg) => {
    minted = false
    return origRebuild3(runIdArg, diffArg, sigArg)
  }
  const isPatched = () => readFileSync(join(liveDir, 'src/export.ts'), 'utf8').includes('ownerTenant !== callerTenant')
  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url, _addr, _sig, opts) => {
      const path = new URL(url).pathname
      const auth = Object.entries(opts?.headers ?? {}).find(([k]) => k.toLowerCase() === 'authorization')?.[1] ?? ''
      if (path === '/api/v1/org/directory') {
        if (isPatched() && auth.includes('tok-alice')) {
          return { status: 500, headers: { 'content-type': 'application/json' }, body: '{"error":"baseline_regression"}' }
        }
        minted = false
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'org-b', directoryToken: 'dir-nonce-orig-111' }) }
      }
      if (path === '/api/v1/exports/mint') {
        minted = true
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ exportToken: 'exp-nonce-orig-222' }) }
      }
      if (path === '/api/v1/exports/exp-900/download') {
        if (isPatched() || !minted) return { status: 403, headers: { 'content-type': 'application/json' }, body: '{"error":"forbidden"}' }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenantId: 'org-a', invoiceId: 'inv-100', amount: 9500 }) }
      }
      return { status: 404, headers: { 'content-type': 'application/json' }, body: '{}' }
    },
  })

  const rejectedPatch = await generateAndReviewPatch({
    runId: run.id,
    finding: seeded.finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  if (ownerTenant !== callerTenant) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Breaks baseline caller.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: seeded.spec,
      replaySpecId: seeded.specRow.id,
      broker,
      factLog: seeded.factLog,
      backend: makeStubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
      baselineCaller: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory', persona: 'alice' },
      baselineExpectStatus: [200],
    },
  })

  assert.equal(rejectedPatch.status, 'rejected')
  assert.equal(rejectedPatch.compositeVerdict, 'fixed')
  assert.equal(rejectedPatch.patchBrokeHopId, null)
  assert.ok(rejectedPatch.labRevision, 'proposal must carry labRevision')
  assert.equal(rejectedPatch.compositeRetestProof?.patchId, rejectedPatch.id)

  // Save the proposal with proposal-scoped Gate-6 metadata
  storage.savePatchProposal({
    id: rejectedPatch.id,
    runId: run.id,
    findingId: seeded.finding.id,
    repo: rejectedPatch.repo,
    status: rejectedPatch.status,
    callerCompatibility: rejectedPatch.callerCompatibility,
    diff: rejectedPatch.diff,
    codeLocations: rejectedPatch.codeLocations,
    reviewNotes: rejectedPatch.reviewNotes,
    dynamicRetestVerdict: rejectedPatch.dynamicRetestVerdict,
    labRevision: rejectedPatch.labRevision,
    compositeVerdict: rejectedPatch.compositeVerdict,
    patchBrokeHopId: rejectedPatch.patchBrokeHopId,
  })

  // 1) Finding-level retest_runs and replay_specs.proof_receipt MUST be untouched!
  const rtRowsBefore = storage.db.select().from(retestRuns).where(eq(retestRuns.findingId, seeded.finding.id)).all()
  assert.equal(rtRowsBefore.length, 0, 'rejected Gate-6 candidate patch must NEVER write to retest_runs')
  const specProofBefore = storage.getReplaySpec(run.id, seeded.specRow.id).proofReceipt as unknown as Record<string, unknown>
  assert.equal(specProofBefore.compositeVerdict, undefined, 'rejected Gate-6 candidate patch must NEVER mutate replay_specs.proof_receipt')
  assert.equal(specProofBefore.patchBrokeHopId, undefined)

  // 2) Even if a legacy DB had stale fixed metadata on replay_specs.proof_receipt, a subsequent authoritative
  //    finding-level "reproduced" Verify Fix retest MUST win in BOTH receipt-export.ts AND report-export.ts!
  storage.db.update(replaySpecs).set({
    proofReceipt: {
      ...specProofBefore,
      patchBrokeHopId: 'hop-3',
      compositeVerdict: 'fixed',
      compositeRetest: {
        retestId: 'legacy-stale-rt',
        verdict: 'fixed',
        compositeVerdict: 'fixed',
        patchBrokeHopId: 'hop-3',
        retestRunId: 'legacy-old-retest-row',
      },
    } as unknown as typeof seeded.specRow.proofReceipt,
  }).where(eq(replaySpecs.id, seeded.specRow.id)).run()

  // Insert an older fixed retest AND a newer reproduced retest to verify newest-by-createdAt ordering too!
  const tOld = Date.now() - 10_000
  const tNew = Date.now()
  storage.db.insert(retestRuns).values([
    {
      id: 'legacy-old-retest-row',
      projectId: run.projectId,
      runId: run.id,
      findingId: seeded.finding.id,
      replaySpecId: seeded.specRow.id,
      scopeRevision: run.scopeRevision,
      verdict: 'fixed',
      summary: 'Old retest: patchBrokeHopId=hop-3',
      evidenceIds: [],
      exchangeIds: [seeded.ex3.id],
      createdAt: tOld,
    },
    {
      id: 'newer-authoritative-reproduced-row',
      projectId: run.projectId,
      runId: run.id,
      findingId: seeded.finding.id,
      replaySpecId: seeded.specRow.id,
      scopeRevision: run.scopeRevision,
      verdict: 'reproduced',
      summary: 'Latest Verify Fix retest still reproduced foreign tenant export.',
      evidenceIds: [],
      exchangeIds: [seeded.ex1.id, seeded.ex2.id, seeded.ex3.id],
      createdAt: tNew,
    },
  ]).run()

  const secret = 'r4-h10-export-hmac-secret'
  const bundle = exportRunReceiptBundle(storage, run.id, { signing: { algorithm: 'hmac-sha256', secret } })
  assert.equal(verifyProofReceiptBundle(bundle, { secret }).valid, true)
  assert.equal(bundle.payload.compositeReceipts?.length, 1)
  const comp = bundle.payload.compositeReceipts![0]!
  assert.equal(comp.patchRetestVerdict, 'reproduced', 'receipt-export must prefer newer reproduced retest over stale spec fixed verdict')
  assert.equal(comp.patchBrokeHopId, null, 'reproduced verdict must clear patchBrokeHopId')
  assert.equal(comp.compositeVerdict, undefined, 'stale compositeVerdict=fixed must not leak onto reproduced export')
  const rec = bundle.payload.records.find(r => r.findingId === seeded.finding.id)!
  assert.equal(rec.patchRetests[0]?.verdict, 'reproduced')

  const reportId = randomUUID()
  storage.db.insert(reports).values({
    id: reportId,
    runId: run.id,
    version: 1,
    partial: false,
    body: {
      goal: 'Verify R4-H-10 report export',
      capabilityTier: 2,
      scope: [asset],
      scopeRevision: run.scopeRevision,
      goalRevision: run.goalRevision,
      findings: [seeded.finding],
      coverage: [],
      gaps: [],
      nextSteps: [],
    } as never,
    createdAt: Date.now() + 1000,
  }).run()

  const md = exportReportMarkdown(storage, run.id, reportId).content
  assert.match(md, /Latest Verify Fix retest\*\* Still reproducible/i, 'report-export must show newest reproduced Verify Fix retest')
  assert.ok(!md.includes('`patchBrokeHopId`: `hop-3`'), 'report-export must NOT show stale hop-3 fixed badge when latest retest is reproduced')
  assert.match(md, /- \*\*Patch retest\*\* reproduced/i)
})

// ============================================================================
// Guard 4 (R4-H-8): patch-workflow.ts passes explicit runId to repo-mounting syntax-check backend.run
// ============================================================================

test('R4-H-8 Guard 4: patch-workflow passes explicit runId to backend.run syntax checks across author, reviewer, and full workflow', async (t) => {
  const origin = 'http://127.0.0.1:4494'
  const { reposDir } = makeRepoAndLab(t, origin)
  const observedRunIds: Array<string | undefined> = []
  const backend = makeStubBackend(opts => { observedRunIds.push(opts?.runId) })

  const finding: Finding & { codeLocations?: Array<{ repo: string; file: string; startLine: number; endLine: number }> } = {
    id: 'finding-r4-h8',
    origin,
    title: 'Missing tenant check',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    status: 'confirmed',
    reason: 'Missing check.',
    remediation: 'Add check.',
    evidenceIds: [],
    scopeRevision: 1,
    codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
  }
  const candidatePatch = {
    fixBefore: '  return { ok: true, ownerTenant }',
    fixAfter: '  if (ownerTenant !== callerTenant) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerTenant }',
    codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
    rationale: 'Add tenant check.',
  }

  // 1) Direct runPatchAuthor
  const authorOut = await runPatchAuthor({
    runId: 'run-r4-h8-author',
    finding,
    repo: 'svc',
    reposDir,
    backend,
    candidatePatch,
  })
  assert.equal(observedRunIds.at(-1), 'run-r4-h8-author')

  // 2) Direct runPatchReviewer without precomputed applicability (triggers verifyPatchApplicability directly)
  await runPatchReviewer({
    runId: 'run-r4-h8-reviewer',
    finding,
    repo: 'svc',
    reposDir,
    authorOutput: { ...authorOut, applicability: undefined },
    backend,
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
  })
  assert.equal(observedRunIds.at(-1), 'run-r4-h8-reviewer')

  // 3) Full generateAndReviewPatch
  await generateAndReviewPatch({
    runId: 'run-r4-h8-full',
    finding,
    repo: 'svc',
    reposDir,
    backend,
    candidatePatch,
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
  })
  assert.equal(observedRunIds.at(-1), 'run-r4-h8-full')
  assert.deepEqual(observedRunIds, ['run-r4-h8-author', 'run-r4-h8-reviewer', 'run-r4-h8-full'])
})
