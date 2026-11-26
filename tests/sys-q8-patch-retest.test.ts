/**
 * Systemic Move Q8 — Production Multi-Hop Composite Patch Retesting (Gate-6 & Receipt Export).
 *
 * Verifies:
 *  1. Production Gate-6 composite retest via RequestBroker (no mock CompositePatchReplayRunner):
 *     - Genuine fix blocking intermediate/terminal hop -> approved, dynamicRetestVerdict='fixed',
 *       compositeVerdict='fixed', patchBrokeHopId populated, structured persistence in retest_runs,
 *       evidence artifact, and replay_specs.proof_receipt, and signed export round-trip.
 *     - Write-only multi-hop chain (no GET baseline caller) succeeds via benignPrefixHops.
 *     - 200-sanitized hop (capability redacted/stripped) -> fixed at the sanitized hop.
 *  2. Fail-closed precondition_changed invariant:
 *     - Upstream route/schema drift (HTTP 404/405/410) -> compositeVerdict='precondition_changed',
 *       Gate-6 withheld (NEVER 'fixed'/'approved'), retest_runs verdict='inconclusive',
 *       patchBrokeHopId=null (overwriting any stale hop ID).
 *  3. Still-vulnerable chain detection:
 *     - Unpatched multi-hop target reproduces full DAG -> Gate-6 rejected,
 *       dynamicRetestVerdict='reproduced', compositeVerdict='still_vulnerable', patchBrokeHopId=null.
 *  4. H-5 envelopeTrust & auth_setup_failed fail-closed invariants.
 *  5. receipt-export.ts reads structured patchBrokeHopId & compositeVerdict without regex scraping
 *     (ignoring misleading summary text when structured fields exist, enforcing fail-closed on
 *     non-fixed verdicts, and keeping clean legacy fallback for pre-Q8 fixed records).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { desc, eq } from 'drizzle-orm'
import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import type { CompositeProofReceipt } from '../src/server/composite-receipt.ts'
import { applyUnifiedDiffToDirectory } from '../src/server/lab-runner.ts'
import type { LabRunner } from '../src/server/lab-runner.ts'
import {
  generateAndReviewPatch,
  retestCompositeChainPatch,
  verifyCompositePatchRetestProofIntegrity,
} from '../src/server/patch-workflow.ts'
import {
  buildPortableCompositeReceiptRecord,
  exportRunReceiptBundle,
  extractStoreCompositeReceipts,
  verifyProofReceiptBundle,
} from '../src/server/receipt-export.ts'
import { replaySpecs, retestRuns } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

function makeTempDir(prefix: string, t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), `kovo-q8-${prefix}-`))
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

function makeGrant(origin: string, extraPersonas?: Map<string, Grant['personas'] extends Map<string, infer V> ? V : never>): Grant {
  const personas = new Map([
    ['alice', { id: 'p-alice', handle: 'alice', roleLabel: 'member (org-a)', originAllowlist: [origin], authKind: 'bearer' as const, headerName: 'Authorization', secret: 'Bearer tok-alice', canaryMarkers: [] }],
    ['bob', { id: 'p-bob', handle: 'bob', roleLabel: 'member (org-b)', originAllowlist: [origin], authKind: 'bearer' as const, headerName: 'Authorization', secret: 'Bearer tok-bob', canaryMarkers: [] }],
  ])
  if (extraPersonas) {
    for (const [k, v] of extraPersonas) personas.set(k, v)
  }
  return {
    origin,
    tier: 2,
    allowLocalLab: true,
    canRead: o => o === origin,
    audit: () => {},
    personas,
  }
}

function makeStoreWithRun(t: { after: (fn: () => void) => void }, origin: string) {
  enableLocalLabEnv(t)
  const dataDir = makeTempDir('store', t)
  const storage = new Store(dataDir)
  t.after(() => storage.close())
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'Sys Q8 Composite Retest Project',
    seeds: [origin],
    environment: 'local-lab',
  })
  const run = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify Q8 composite patch retest in Gate-6',
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
  const worker = storage.makeWorker(hydratedRun, 'investigation', asset, 'Probe', 'Q8 worker')
  return { storage, project, run: hydratedRun, worker }
}

function makeApproveReviewer(enforcingLocation: string) {
  return async () => JSON.stringify({
    approved: true,
    callerCompatibility: 'attacker_only',
    enforcingLocation,
    gates: {
      applicability: { passed: true, detail: 'Applies cleanly.' },
      security_closure: { passed: true, detail: 'Enforces tenant authorization on export hop.', enforcingLocation },
      sibling_coverage: { passed: true, detail: 'All sibling export handlers covered.' },
      caller_compatibility: { passed: true, detail: 'Benign upstream calls preserved.' },
      repo_conventions: { passed: true, detail: 'Idiomatic TypeScript.' },
    },
    reviewNotes: 'Statically approved.',
  })
}

function stubBackend(): WorkerBackend {
  return {
    async run() {
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

  const labRunner = {
    rebuildWithPatch: async (_runId: string, diff: string) => {
      applyUnifiedDiffToDirectory(liveDir, diff)
      return {
        targetId: 't-q8', origin, containerName: 'c-q8', containerNames: ['c-q8'], containerIp: '127.0.0.1',
        internalPort: 4480, healthPath: '/health', networkName: 'net', imageName: 'img',
        sanitizedRepoDir: liveDir, telemetryDir: liveDir, startedAt: Date.now(),
      }
    },
  } as unknown as LabRunner

  return { reposDir, liveDir, vulnCode, labRunner }
}

function makePlaceholderReplaySpec(origin: string, writeOnly = false): DeclarativeReplaySpec {
  if (writeOnly) {
    return {
      version: 1,
      kind: 'race_burst',
      origin,
      title: 'Multi-hop write-only approval bypass',
      category: 'business-logic',
      cwe: 'CWE-840',
      severity: 'high',
      severityRationale: 'Multi-hop state transition chain.',
      impact: 'Unauthorized approval.',
      remediation: 'Enforce creator != approver.',
      recheckInstructions: 'Replay composite DAG.',
      assertionsJq: 'true',
      burst: [
        { origin, method: 'POST', pathAndQuery: '/api/v1/drafts', persona: 'bob', followRedirects: false },
        { origin, method: 'POST', pathAndQuery: '/api/v1/drafts/draft-42/approve', persona: 'bob', followRedirects: false },
      ],
    }
  }
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Multi-hop cross-tenant export disclosure',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Chained directory + token mint + cross-tenant download.',
    impact: 'Foreign tenant invoice export disclosed to member of another org.',
    remediation: 'Verify tenant ownership before serving export download.',
    recheckInstructions: 'Replay 3-hop composite DAG.',
    assertionsJq: '.steps | length > 0',
    spaCatchallControl: false,
    steps: [
      { id: 'c1', role: 'control', description: 'owner directory read', request: { origin, method: 'GET', pathAndQuery: '/api/v1/org/directory', persona: 'alice', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'foreign download', request: { origin, method: 'GET', pathAndQuery: '/api/v1/exports/exp-900/download', persona: 'bob', followRedirects: false } },
    ],
  }
}

function seedThreeHopCompositeFinding(params: {
  storage: Store
  run: ReturnType<Store['run']>
  worker: ReturnType<Store['makeWorker']>
  origin: string
  writeOnly?: boolean
}) {
  const { storage, run, worker, origin, writeOnly = false } = params
  const findingId = `finding-${randomUUID().slice(0, 8)}`
  const exBase = {
    runId: run.id,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [] as string[],
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: { 'content-type': 'application/json' },
    durationMs: 4,
  }

  const exCtrl = storage.recordExchange({
    ...exBase,
    method: writeOnly ? 'POST' : 'GET',
    pathAndQuery: '/api/v1/exports/exp-900/download',
    personaHandle: 'bob',
    status: 403,
    body: JSON.stringify({ error: 'forbidden' }),
  })
  const ex1 = storage.recordExchange({
    ...exBase,
    method: writeOnly ? 'POST' : 'GET',
    pathAndQuery: '/api/v1/org/directory',
    personaHandle: 'bob',
    status: 200,
    body: JSON.stringify({ tenant: 'org-b', directoryToken: 'dir-tok-123' }),
  })
  const ex2 = storage.recordExchange({
    ...exBase,
    method: 'POST',
    pathAndQuery: '/api/v1/exports/mint',
    personaHandle: 'bob',
    status: 200,
    body: JSON.stringify({ exportToken: 'exp-tok-900' }),
  })
  const ex3 = storage.recordExchange({
    ...exBase,
    method: writeOnly ? 'POST' : 'GET',
    pathAndQuery: '/api/v1/exports/exp-900/download',
    personaHandle: 'bob',
    status: 200,
    body: JSON.stringify({ tenantId: 'org-a', invoiceId: 'inv-100', amount: 9500 }),
  })

  const cap1 = 'cap:hop-1:directory_token'
  const cap2 = 'cap:hop-2:export_token'
  const compositeReceipt: CompositeProofReceipt = {
    chainId: `chain-q8-${randomUUID().slice(0, 8)}`,
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      {
        hopId: 'hop-1',
        surface: 'http',
        target: { origin, method: writeOnly ? 'POST' : 'GET', pathAndQuery: '/api/v1/org/directory' },
        exchangeIds: [ex1.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Benign directory lookup returns org directory token',
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
        claimedDelta: 'Export mint endpoint issues download token',
        producedCapabilities: [cap2],
        consumedCapabilities: [cap1],
      },
      {
        hopId: 'hop-3',
        surface: 'http',
        target: { origin, method: writeOnly ? 'POST' : 'GET', pathAndQuery: '/api/v1/exports/exp-900/download' },
        exchangeIds: [ex3.id],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Download endpoint leaks foreign tenant org-a invoice data',
        producedCapabilities: [],
        consumedCapabilities: [cap2],
      },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop-1', toHopId: 'hop-2', capabilityHandle: cap1, sourceExchangeId: ex1.id, targetExchangeId: ex2.id },
      { kind: 'value_binding', fromHopId: 'hop-2', toHopId: 'hop-3', capabilityHandle: cap2, sourceExchangeId: ex2.id, targetExchangeId: ex3.id },
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

  const spec = makePlaceholderReplaySpec(origin, writeOnly)
  const specRow = storage.createReplaySpec(run, worker, findingId, spec, [origin])

  const proofPayload = {
    receipt: {
      vulnClass: 'dual_tenant_abac',
      target: { origin, method: 'GET', pathAndQuery: '/api/v1/exports/exp-900/download' },
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
    compositeVerification: {
      confirmed: true,
      chainId: compositeReceipt.chainId,
      terminalVulnClass: 'dual_tenant_abac',
      replayMode: 'fresh_clean_replay',
      modeBVerified: false,
      hopCount: 3,
      verifiedEdges: [
        { edgeIndex: 0, kind: 'value_binding', fromHopId: 'hop-1', toHopId: 'hop-2', verified: true, reason: 'ok' },
        { edgeIndex: 1, kind: 'value_binding', fromHopId: 'hop-2', toHopId: 'hop-3', verified: true, reason: 'ok' },
      ],
      reason: 'CompositeProofReceipt confirmed',
    },
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
    scopeRevision: run.scopeRevision,
    replaySpecId: specRow.id,
    codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
  }

  return { finding, specRow, spec, compositeReceipt, ex1, ex2, ex3, exCtrl }
}

// ============================================================================
// 1. Production Gate-6 Composite Retest — Genuine Fix (Fixed at Hop 3 + Export)
// ============================================================================

test('Q8-1: Production Gate-6 composite retest confirms genuine fix at hop-3, persists structured metadata, and exports without regex scraping', async (t) => {
  const origin = 'http://127.0.0.1:4480'
  const { storage, run, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, vulnCode, labRunner } = makeRepoAndLab(t, origin)
  const { finding, specRow, spec, compositeReceipt } = seedThreeHopCompositeFinding({ storage, run, worker, origin })

  // Live patched target:
  // - Hop 1 (directory) -> 200 OK (benign prefix preserved)
  // - Hop 2 (export mint) -> 200 OK (benign prefix preserved)
  // - Hop 3 (foreign download) -> 403 Forbidden (patch blocked the vulnerability!)
  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url) => {
      const path = new URL(url).pathname
      if (path === '/api/v1/org/directory') {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'org-b', directoryToken: 'dir-tok-fresh' }) }
      }
      if (path === '/api/v1/exports/mint') {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ exportToken: 'exp-tok-fresh' }) }
      }
      if (path === '/api/v1/exports/exp-900/download') {
        return { status: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'forbidden_tenant_mismatch' }) }
      }
      return { status: 404, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'not_found' }) }
    },
  })

  const res = await generateAndReviewPatch({
    runId: run.id,
    finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  if (ownerTenant !== callerTenant) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce tenant ownership check on export download.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: spec,
      replaySpecId: specRow.id,
      broker,
      backend: stubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
      // No compositeRunner supplied — must run the production RequestBroker composite runner!
    },
  })

  assert.equal(res.status, 'approved', res.reviewNotes)
  assert.equal(res.dynamicRetestVerdict, 'fixed')
  assert.equal(res.compositeVerdict, 'fixed')
  assert.equal(res.patchBrokeHopId, 'hop-3')
  assert.equal(res.gates.find(g => g.gate === 6)?.passed, true)
  assert.ok(res.compositeRetestProof, 'compositeRetestProof must be attached to PatchProposalResult')
  assert.equal(verifyCompositePatchRetestProofIntegrity(res.compositeRetestProof!), true)
  assert.deepEqual(res.compositeRetestProof!.benignPrefixHops, ['hop-1', 'hop-2'])
  assert.equal(readFileSync(join(liveDir, 'src/export.ts'), 'utf8'), vulnCode, 'clean Gate-6 rollback preserved')

  // Verify structured metadata persisted in SQLite (retest_runs + replay_specs.proof_receipt + artifact)
  const rtRows = storage.db.select().from(retestRuns).where(eq(retestRuns.findingId, finding.id)).orderBy(desc(retestRuns.createdAt)).all()
  assert.equal(rtRows.length, 1)
  assert.equal(rtRows[0]!.verdict, 'fixed')
  assert.equal(rtRows[0]!.evidenceIds.length, 1)
  const retestArt = JSON.parse(storage.artifact(run.id, rtRows[0]!.evidenceIds[0]!).content) as Record<string, unknown>
  assert.equal(retestArt.kind, 'composite_patch_retest')
  assert.equal(retestArt.compositeVerdict, 'fixed')
  assert.equal(retestArt.patchBrokeHopId, 'hop-3')

  const updatedSpec = storage.getReplaySpec(run.id, specRow.id)
  const storedProofObj = updatedSpec.proofReceipt as unknown as Record<string, unknown>
  assert.equal(storedProofObj.patchBrokeHopId, 'hop-3')
  assert.equal(storedProofObj.compositeVerdict, 'fixed')

  // Verify signed receipt bundle export reads structured patchBrokeHopId & compositeVerdict cleanly
  const secret = 'q8-export-hmac-secret-test'
  const bundle = exportRunReceiptBundle(storage, run.id, {
    signing: { algorithm: 'hmac-sha256', secret },
  })
  assert.equal(bundle.payload.compositeReceipts?.length, 1)
  const exported = bundle.payload.compositeReceipts![0]!
  assert.equal(exported.chainId, compositeReceipt.chainId)
  assert.equal(exported.patchBrokeHopId, 'hop-3')
  assert.equal(exported.patchRetestVerdict, 'fixed')
  assert.equal(exported.compositeVerdict, 'fixed')
  assert.equal(verifyProofReceiptBundle(bundle, { secret }).valid, true)
})

// ============================================================================
// 2. Write-Only Multi-Hop Chain (Benign Prefix Preserves Gate-6) & 200-Sanitized Hop
// ============================================================================

test('Q8-2: Write-only composite chain passes Gate-6 via benignPrefixHops and detects 200-sanitized intermediate hop fix', async (t) => {
  const origin = 'http://127.0.0.1:4481'
  const { storage, run, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, labRunner } = makeRepoAndLab(t, origin)
  const { finding, specRow, spec } = seedThreeHopCompositeFinding({ storage, run, worker, origin, writeOnly: true })

  // Patched target returns HTTP 200 on hop-1 (benign), and HTTP 200 with redacted/null exportToken on hop-2!
  const requestedPaths: string[] = []
  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url) => {
      const path = new URL(url).pathname
      requestedPaths.push(path)
      if (path === '/api/v1/org/directory') {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'org-b', directoryToken: 'dir-tok-2' }) }
      }
      if (path === '/api/v1/exports/mint') {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ status: 'ok', exportToken: '[redacted]' }) }
      }
      return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenantId: 'org-a' }) }
    },
  })

  const res = await generateAndReviewPatch({
    runId: run.id,
    finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  if (ownerTenant !== callerTenant) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Redact export token for non-owners.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: spec,
      replaySpecId: specRow.id,
      broker,
      backend: stubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
    },
  })

  assert.equal(res.status, 'approved', res.reviewNotes)
  assert.equal(res.dynamicRetestVerdict, 'fixed')
  assert.equal(res.compositeVerdict, 'fixed')
  assert.equal(res.patchBrokeHopId, 'hop-2')
  assert.deepEqual(res.compositeRetestProof?.benignPrefixHops, ['hop-1'])
  assert.equal(res.compositeRetestProof?.hopResults.find(h => h.hopId === 'hop-3')?.outcome, 'skipped_after_break')
  assert.equal(res.gates.find(g => g.gate === 6)?.passed, true)
  assert.match(res.dynamicRetestSummary ?? '', /benign prefix hops preserved/i)
  // Downstream hop-3 must NOT be replayed after hop-2 stops emitting capability!
  assert.equal(requestedPaths.filter(p => p === '/api/v1/exports/exp-900/download').length, 1, 'only pre-chain control should hit download endpoint, not probe hop-3')
})

// ============================================================================
// 3. Fail-Closed Precondition Invariant (`precondition_changed` -> NEVER 'fixed')
// ============================================================================

test('Q8-3: Production Gate-6 composite retest fails closed on precondition_changed (HTTP 404/410 drift -> withheld & inconclusive, NEVER fixed)', async (t) => {
  const origin = 'http://127.0.0.1:4482'
  const { storage, run, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, labRunner } = makeRepoAndLab(t, origin)
  const { finding, specRow, spec } = seedThreeHopCompositeFinding({ storage, run, worker, origin })

  // Pre-seed a stale patchBrokeHopId on proof_receipt to verify precondition_changed clears it!
  const beforeRow = storage.getReplaySpec(run.id, specRow.id)
  storage.db
    .update(replaySpecs)
    .set({
      proofReceipt: {
        ...(beforeRow.proofReceipt as unknown as Record<string, unknown>),
        patchBrokeHopId: 'stale-hop-from-earlier',
      } as unknown as typeof beforeRow.proofReceipt,
    })
    .where(eq(replaySpecs.id, specRow.id))
    .run()

  // Simulated environment drift: upstream setup hop-1 endpoint moved (HTTP 404 Cannot GET /api/v1/org/directory).
  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url) => {
      const path = new URL(url).pathname
      if (path === '/api/v1/org/directory') {
        return { status: 404, headers: { 'content-type': 'text/plain' }, body: 'Cannot GET /api/v1/org/directory' }
      }
      return { status: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'forbidden' }) }
    },
  })

  const res = await generateAndReviewPatch({
    runId: run.id,
    finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  if (ownerTenant !== callerTenant) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce tenant check.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: spec,
      replaySpecId: specRow.id,
      broker,
      backend: stubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
    },
  })

  // CRITICAL FAIL-CLOSED INVARIANT: precondition_changed MUST NEVER produce 'fixed' or 'approved'!
  assert.equal(res.status, 'withheld')
  assert.equal(res.dynamicRetestVerdict, 'skipped')
  assert.equal(res.compositeVerdict, 'precondition_changed')
  assert.equal(res.patchBrokeHopId, null)
  assert.equal(res.gates.find(g => g.gate === 6)?.passed, false)
  assert.match(res.dynamicRetestSummary ?? '', /precondition_changed/i)

  // Persisted retest_runs record MUST map precondition_changed -> 'inconclusive' (NEVER 'fixed')!
  const rtRows = storage.db.select().from(retestRuns).where(eq(retestRuns.findingId, finding.id)).orderBy(desc(retestRuns.createdAt)).all()
  assert.equal(rtRows.length, 1)
  assert.equal(rtRows[0]!.verdict, 'inconclusive')

  // Persisted proof_receipt must clear stale patchBrokeHopId and record compositeVerdict='precondition_changed'.
  const afterProof = storage.getReplaySpec(run.id, specRow.id).proofReceipt as unknown as Record<string, unknown>
  assert.equal(afterProof.patchBrokeHopId, null)
  assert.equal(afterProof.compositeVerdict, 'precondition_changed')

  // Exported bundle MUST reflect fail-closed inconclusive + compositeVerdict='precondition_changed' + patchBrokeHopId=null.
  const secret = 'q8-drift-hmac-secret'
  const bundle = exportRunReceiptBundle(storage, run.id, { signing: { algorithm: 'hmac-sha256', secret } })
  const exported = bundle.payload.compositeReceipts![0]!
  assert.equal(exported.patchRetestVerdict, 'inconclusive')
  assert.equal(exported.compositeVerdict, 'precondition_changed')
  assert.equal(exported.patchBrokeHopId, null)
  assert.equal(verifyProofReceiptBundle(bundle, { secret }).valid, true)
})

// ============================================================================
// 4. Unpatched Target Still Reproducing (`still_vulnerable` -> Gate-6 Rejected)
// ============================================================================

test('Q8-4: Production Gate-6 composite retest detects still-reproducing chain (still_vulnerable -> rejected & reproduced)', async (t) => {
  const origin = 'http://127.0.0.1:4483'
  const { storage, run, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, labRunner } = makeRepoAndLab(t, origin)
  const { finding, specRow, spec } = seedThreeHopCompositeFinding({ storage, run, worker, origin })

  // Unpatched target: pre-chain direct download is 403 (denied before minting), then hop-1 -> hop-2 -> hop-3
  // still discloses foreign tenant org-a data (200 OK)!
  let mintCalled = false
  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async (url) => {
      const path = new URL(url).pathname
      if (path === '/api/v1/org/directory') {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenant: 'org-b', directoryToken: 'dir-tok-live' }) }
      }
      if (path === '/api/v1/exports/mint') {
        mintCalled = true
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ exportToken: 'exp-tok-live' }) }
      }
      if (path === '/api/v1/exports/exp-900/download') {
        if (!mintCalled) {
          return { status: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'forbidden_before_mint' }) }
        }
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenantId: 'org-a', invoiceId: 'inv-100', amount: 9500 }) }
      }
      return { status: 404, headers: { 'content-type': 'application/json' }, body: '{}' }
    },
  })

  const res = await generateAndReviewPatch({
    runId: run.id,
    finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  // no-op ineffective change\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Ineffective patch.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: spec,
      replaySpecId: specRow.id,
      broker,
      backend: stubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
    },
  })

  assert.equal(res.status, 'rejected', res.reviewNotes)
  assert.equal(res.dynamicRetestVerdict, 'reproduced')
  assert.equal(res.compositeVerdict, 'still_vulnerable')
  assert.equal(res.patchBrokeHopId, null)
  assert.equal(res.gates.find(g => g.gate === 6)?.passed, false)

  const rtRows = storage.db.select().from(retestRuns).where(eq(retestRuns.findingId, finding.id)).orderBy(desc(retestRuns.createdAt)).all()
  assert.equal(rtRows.length, 1)
  assert.equal(rtRows[0]!.verdict, 'reproduced')
})

// ============================================================================
// 5. H-5 Untrusted Envelope & Missing Persona Auth Setup Fail-Closed
// ============================================================================

test('Q8-5: Composite retest fails closed on untrusted envelopeTrust (H-5) and missing persona auth setup', async (t) => {
  const origin = 'http://127.0.0.1:4484'
  const { storage, run, worker } = makeStoreWithRun(t, origin)
  const { reposDir, liveDir, labRunner } = makeRepoAndLab(t, origin)
  const { finding, spec, compositeReceipt } = seedThreeHopCompositeFinding({ storage, run, worker, origin })

  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async () => ({ status: 403, headers: { 'content-type': 'application/json' }, body: '{"error":"forbidden"}' }),
  })

  // H-5: untrusted envelopeTrust must withhold even if compositeReceipt is supplied!
  const untrustedRes = await generateAndReviewPatch({
    runId: run.id,
    finding: { ...finding, replaySpecId: 'forged-unpersisted-spec-id' },
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerTenant }',
      fixAfter: '  if (ownerTenant !== callerTenant) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerTenant }',
      codeLocations: [{ repo: 'svc', file: 'src/export.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce check.',
    },
    reviewerLlmCall: makeApproveReviewer('src/export.ts:2'),
    labRetest: {
      labRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: spec,
      compositeReceipt,
      broker,
      backend: stubBackend(),
      grant: makeGrant(origin),
      storage,
      assignmentId: worker.id,
    },
  })
  assert.equal(untrustedRes.status, 'withheld')
  assert.equal(untrustedRes.dynamicRetestVerdict, 'skipped')
  assert.equal(untrustedRes.compositeVerdict, 'inconclusive')
  assert.equal(untrustedRes.patchBrokeHopId, null)

  // Missing persona in grant -> auth_setup_failed -> inconclusive (NEVER 'fixed').
  const grantWithoutBob: Grant = {
    origin,
    tier: 2,
    allowLocalLab: true,
    canRead: o => o === origin,
    audit: () => {},
    personas: new Map([
      ['alice', { id: 'p-alice', handle: 'alice', roleLabel: 'member org-a', originAllowlist: [origin], authKind: 'bearer', headerName: 'Authorization', secret: 'Bearer tok-alice', canaryMarkers: [] }],
    ]),
  }
  const missingPersonaProof = await retestCompositeChainPatch({
    receipt: compositeReceipt,
    brokerContext: {
      broker,
      grant: grantWithoutBob,
      hopActors: { 'hop-1': 'bob', 'hop-2': 'bob', 'hop-3': 'bob' },
    },
  })
  assert.equal(missingPersonaProof.verdict, 'inconclusive')
  assert.equal(missingPersonaProof.patchClosed, false)
  assert.equal(missingPersonaProof.patchBrokeHopId, null)
  assert.match(missingPersonaProof.summary, /missing from grant/i)
})

// ============================================================================
// 6. receipt-export.ts Structured Extraction Without Regex Scraping
// ============================================================================

test('Q8-6: receipt-export.ts reads structured patchBrokeHopId/compositeVerdict directly, ignores misleading summary prose, and preserves legacy fallback', (t) => {
  const origin = 'http://127.0.0.1:4485'
  const { storage, run, worker } = makeStoreWithRun(t, origin)
  const { finding, specRow, compositeReceipt } = seedThreeHopCompositeFinding({ storage, run, worker, origin })
  const freshSpecRow = storage.getReplaySpec(run.id, specRow.id)

  // Case A: Retest record with structured patchBrokeHopId & compositeVerdict MUST override misleading summary text!
  const structuredFixedRetest = {
    id: randomUUID(),
    projectId: run.projectId,
    runId: run.id,
    findingId: finding.id,
    replaySpecId: specRow.id,
    scopeRevision: run.scopeRevision,
    verdict: 'fixed' as const,
    summary: 'Prose mentions patchBrokeHopId=wrong-hop-from-prose',
    evidenceIds: [] as string[],
    exchangeIds: [] as string[],
    createdAt: Date.now(),
    patchBrokeHopId: 'hop-2',
    compositeVerdict: 'fixed' as const,
  }
  const extractedFixed = extractStoreCompositeReceipts([freshSpecRow], [structuredFixedRetest])
  assert.equal(extractedFixed.length, 1)
  assert.equal(extractedFixed[0]!.patchBrokeHopId, 'hop-2', 'structured patchBrokeHopId must win over summary text')
  assert.equal(extractedFixed[0]!.compositeVerdict, 'fixed')
  assert.equal(extractedFixed[0]!.patchRetestVerdict, 'fixed')

  // Case B: Retest record with structured compositeVerdict='precondition_changed' MUST fail closed
  // (patchRetestVerdict='inconclusive', patchBrokeHopId=undefined) even if summary mentions a hop ID!
  const structuredDriftRetest = {
    ...structuredFixedRetest,
    id: randomUUID(),
    verdict: 'inconclusive' as const,
    summary: 'Route drifted: patchBrokeHopId=hop-3',
    patchBrokeHopId: 'hop-3',
    compositeVerdict: 'precondition_changed' as const,
  }
  const extractedDrift = extractStoreCompositeReceipts([freshSpecRow], [structuredDriftRetest])
  assert.equal(extractedDrift.length, 1)
  assert.equal(extractedDrift[0]!.compositeVerdict, 'precondition_changed')
  assert.equal(extractedDrift[0]!.patchRetestVerdict, 'inconclusive')
  assert.equal(extractedDrift[0]!.patchBrokeHopId, undefined)

  // buildPortableCompositeReceiptRecord also enforces fail-closed on non-fixed compositeVerdict
  const portableDrift = buildPortableCompositeReceiptRecord({
    receipt: compositeReceipt,
    patchBrokeHopId: 'hop-3',
    compositeVerdict: 'precondition_changed',
  })
  assert.equal(portableDrift.compositeVerdict, 'precondition_changed')
  assert.equal(portableDrift.patchRetestVerdict, 'inconclusive')
  assert.equal(portableDrift.patchBrokeHopId, null)

  // Case C: Legacy pre-Q8 record without structured fields falls back cleanly ONLY when verdict === 'fixed'
  const legacyFixedRetest = {
    id: randomUUID(),
    projectId: run.projectId,
    runId: run.id,
    findingId: finding.id,
    replaySpecId: specRow.id,
    scopeRevision: run.scopeRevision,
    verdict: 'fixed' as const,
    summary: 'Legacy summary: patchBrokeHopId=hop-3',
    evidenceIds: [] as string[],
    exchangeIds: [] as string[],
    createdAt: Date.now(),
  }
  const extractedLegacy = extractStoreCompositeReceipts([freshSpecRow], [legacyFixedRetest])
  assert.equal(extractedLegacy[0]!.patchBrokeHopId, 'hop-3')
  assert.equal(extractedLegacy[0]!.patchRetestVerdict, 'fixed')

  // Legacy record with verdict === 'inconclusive' MUST NOT extract patchBrokeHopId from summary!
  const legacyInconclusive = { ...legacyFixedRetest, id: randomUUID(), verdict: 'inconclusive' as const }
  const extractedLegacyInconclusive = extractStoreCompositeReceipts([freshSpecRow], [legacyInconclusive])
  assert.equal(extractedLegacyInconclusive[0]!.patchBrokeHopId, undefined)
  assert.equal(extractedLegacyInconclusive[0]!.patchRetestVerdict, 'inconclusive')

  // Static guard: PATCH_BROKE_HOP_RE regex scraping is eliminated from receipt-export.ts & zero new RegExp in receipt-export.ts
  const exportSrc = readFileSync(join(repoRoot, 'src/server/receipt-export.ts'), 'utf8')
  assert.equal(exportSrc.includes('PATCH_BROKE_HOP_RE'), false, 'PATCH_BROKE_HOP_RE regex scraping must be removed')
  assert.equal(/\bnew\s+RegExp\s*\(/.test(exportSrc), false, 'receipt-export.ts must have zero dynamic new RegExp()')
})
