import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import ts from 'typescript'
import type { Finding } from '../src/domain.ts'
import type { AgentScriptProofEnvelope, DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  buildCompositeVerifyOptionsFromGrant,
  PERSISTED_SCRIPT_INTEGRITY_ERROR,
  resolveVerifyRpcHostDir,
  retestPersistedAgentScript,
  verifyPersistedScriptIntegrity,
} from '../src/server/agent-script-proof.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import {
  bindConfirmedFindingIdentity,
  buildReplayFindingPatch,
  cweFamilyForReceiptClass,
  ExecVerifier,
  findOobMatchingReplaySpec,
  isCweConsistentWithReceiptClass,
  isSensitiveRepoEntry,
  isSensitiveRepoRelativePath,
  probeCanaryClass,
  type ExecVerifyHost,
} from '../src/server/exec-verify.ts'
import { assertSafeParamName, isSafeParamName } from '../src/server/exec-worker-runner.ts'
import type { ReplayVerificationResult } from '../src/server/replay-verifier.ts'
import { canaries, findings } from '../src/server/schema.ts'
import { Store, type ReplaySpecRow } from '../src/server/store.ts'
import { resolveDoodMountArg, type WorkerBackend } from '../src/server/worker-backend.ts'
import { normFStatus } from '../src/components/run/meta.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

/** Compile and load `extractReplayInfraFailure` + `ReplayFailureCallout` directly from `queue-read.tsx`. */
function loadReplayCalloutModule(): {
  extractReplayInfraFailure: (finding: { status?: string; verification?: string | null }, replayDiff?: unknown) => string | null
  ReplayFailureCallout: (props: { reason: string }) => React.ReactElement
} {
  const src = readFileSync(join(process.cwd(), 'src/components/run/views/queue-read.tsx'), 'utf8')
  const start = src.indexOf('const REPLAY_INFRA_ERROR_RE =')
  const end = src.indexOf('/** Code locations list shared by Queue and Finding inspectors. */')
  assert.ok(start >= 0 && end > start, 'Expected replay callout helpers in queue-read.tsx')
  const snippet = src.slice(start, end)
  const transpiled = ts.transpileModule(snippet, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      jsx: ts.JsxEmit.React,
    },
  }).outputText
  const exportsObj: Record<string, unknown> = {}
  const StubIcon = ({ name, className }: { name: string; className?: string }) =>
    React.createElement('span', { 'data-icon': name, className })
  const fn = new Function('exports', 'React', 'normFStatus', 'Icon', transpiled)
  fn(exportsObj, React, normFStatus, StubIcon)
  return exportsObj as {
    extractReplayInfraFailure: (finding: { status?: string; verification?: string | null }, replayDiff?: unknown) => string | null
    ReplayFailureCallout: (props: { reason: string }) => React.ReactElement
  }
}

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeTempDir(prefix: string, t: test.TestContext): string {
  const dir = mkdtempSync(join(tmpdir(), `kovo-ws15-${prefix}-`))
  t.after(() => {
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  })
  return dir
}

function makeStore(t: test.TestContext) {
  const dir = makeTempDir('store', t)
  const storage = new Store(dir)
  t.after(() => storage.close())
  return { dir, storage }
}

function makeAttemptReport(attempt: 1 | 2, digest: string) {
  return {
    attempt,
    nonce: `nonce-${digest}`,
    exitCode: 0,
    durationMs: 5,
    oraclePassed: true,
    failures: [],
    claimCount: 1,
    exchangeCount: 2,
    transcriptDigest: digest,
    signaturesValid: true,
    causal: [],
    title: null,
    nonceMismatch: false,
    rejectedBy: null,
    missingEvidence: [],
    transcriptSummary: [],
  }
}

function makeDummyBackend(onOpenSession?: () => void): WorkerBackend {
  return {
    async run() {
      return { exitCode: 0, stdout: '', stderr: '', outputs: {}, durationMs: 1, timedOut: false }
    },
    async verifyStaticAst() {
      return {
        verified: false,
        engine: 'ast-grep',
        repo: 'app',
        file: 'src/a.ts',
        startLine: 1,
        endLine: 1,
        matchedLines: [],
        codeExcerpt: '',
        matchCount: 0,
        durationMs: 1,
      }
    },
    async openSession() {
      onOpenSession?.()
      throw new Error('openSession should not have been called')
    },
  }
}

function makeExecVerifier(
  storage: Store,
  opts: {
    backend?: WorkerBackend
    canaryBroker?: CanaryBroker
    vault?: DerivedCapabilityVault
  } = {},
) {
  const broker = new RequestBroker()
  const canaryBroker = opts.canaryBroker ?? new CanaryBroker({ storage })
  const backend = opts.backend ?? makeDummyBackend()
  const host: ExecVerifyHost = {
    storage,
    broker,
    browser: null as unknown as ExecVerifyHost['browser'],
    canaryBroker,
    backend,
    approvedOriginsSet: run => new Set(run.candidates.filter(c => run.approved.includes(c.id)).map(c => c.origin)),
    permitted: (run, origin) => run.candidates.some(c => run.approved.includes(c.id) && c.origin === origin),
    check: job => storage.run(job.assignment.runId),
    buildGrant: (_job, run, permitted) => ({
      grant: makeLabGrant([...permitted][0] ?? run.candidates[0]!.origin),
      secrets: [],
      currentSecrets: () => [],
    }),
    projectReposMount: () => ({ reposDir: undefined, mountedRepos: [] }),
    isCanaryDnsConfigured: () => false,
    isCanaryListenerConfigured: () => false,
    markEndpointCoverage: () => undefined,
    markReplaySpecCoverage: () => undefined,
    waitForTier3Approval: async () => ({ approved: true }),
    postVerificationVerdict: () => null,
    cancelSiblingTrialsOnConfirmation: () => undefined,
    scheduleVariantSweepForFinding: () => undefined,
    completeWorker: () => undefined,
    recordSpecVerification: () => undefined,
    resolveInlineVerdictRow: (_runId, row) => row,
    ...(opts.vault ? { capabilityVaultFor: () => opts.vault! } : {}),
  }
  return new ExecVerifier(host)
}

function makeHttpChainSpec(origin: string, overrides: Partial<Extract<DeclarativeReplaySpec, { kind: 'http_chain' }>> = {}): Extract<DeclarativeReplaySpec, { kind: 'http_chain' }> {
  return {
    version: 1,
    kind: 'http_chain',
    spaCatchallControl: false,
    origin,
    title: 'Cross-tenant order read',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Unauthorized cross-tenant read',
    impact: 'Foreign tenant record disclosed',
    remediation: 'Enforce tenant check',
    recheckInstructions: 'Replay request',
    assertionsJq: 'true',
    steps: [
      {
        id: 'control',
        role: 'control',
        description: 'Control request',
        request: { origin, method: 'GET', pathAndQuery: '/api/orders/1', followRedirects: false },
      },
      {
        id: 'probe',
        role: 'probe',
        description: 'Probe request',
        request: { origin, method: 'GET', pathAndQuery: '/api/orders/2', followRedirects: false },
      },
    ],
    ...overrides,
  }
}

// ============================================================================
// 1. R2-H-16: Non-destructive script persistence & SHA-256 integrity check
// ============================================================================

test('R2-H-16: persistAgentScriptProof preserves executable script without heuristic redaction while scrubbing exact secrets and titles', async (t) => {
  const origin = 'http://127.0.0.1:4510'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Verifier', 'Persist script proof')
  const verifier = makeExecVerifier(storage)

  // Ordinary script containing synthetic forged JWT + password literal + Bearer header (NOT in allSecrets).
  const syntheticJwt = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiJ9.'
  const rawScript = [
    `const forged = "${syntheticJwt}";`,
    `const loginBody = { username: "demo", password: "synthetic-demo-password" };`,
    `const authHeader = "Bearer synthetic-bearer-value-12345";`,
    `export default async function run(ctx) { return ctx.result({ title: "JWT alg=none bypass" }); }`,
  ].join('\n')
  const expectedSha = createHash('sha256').update(rawScript).digest('hex')

  const secretInTitle = 'sk-real-secret-value-99999'
  const persisted = verifier.persistAgentScriptProof({
    run,
    assignment,
    script: rawScript,
    runtime: 'ts',
    title: `JWT bypass exposing ${secretInTitle}`,
    secrets: [{ value: secretInTitle, placeholder: '[redacted:api-key]' }],
    proof: {
      verdict: {
        confirmed: true,
        reason: 'confirmed',
        detail: 'Two fresh runs confirmed auth bypass.',
        attempts: [makeAttemptReport(1, 'a'.repeat(64)), makeAttemptReport(2, 'a'.repeat(64))],
        disagreements: [],
        claimTitle: null,
        rejectedBy: null,
        missingEvidence: [],
        transcriptSummary: [],
      },
      exchanges: [
        {
          exchangeId: 'ex-ctrl-1',
          method: 'GET',
          pathAndQuery: '/api/admin/me',
          origin,
          status: 401,
          sessionRole: 'control',
          requestHeaders: {},
          responseHeaders: {},
        },
        {
          exchangeId: 'ex-probe-1',
          method: 'GET',
          pathAndQuery: '/api/admin/me',
          origin,
          status: 200,
          sessionRole: 'probe',
          requestHeaders: {},
          responseHeaders: {},
        },
      ],
      receipt: {
        receipt: {
          vulnClass: 'jwt_forgery',
          target: { origin, method: 'GET', pathAndQuery: '/api/admin/me' },
          exchangeIds: ['ex-ctrl-1', 'ex-probe-1'],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'Forged token bypassed authentication',
        },
        verification: {
          confirmed: true,
          vulnClass: 'jwt_forgery',
          rule: 'auth_bypass',
          reason: 'Forged JWT accepted where baseline returned 401',
          observed: '200 vs 401',
          expected: '401',
        },
      },
      compositeReceipt: null,
      vulnClass: 'jwt_forgery',
      transcriptDigests: ['a'.repeat(64)],
      sealedCapabilities: [],
      transcriptRecords: [],
      hostTranscript: null,
      claimTitle: null,
      severity: 'high',
      description: null,
    },
  })

  const specRow = storage.getReplaySpec(run.id, persisted.replaySpecId)
  const envelope = (specRow.spec as { agentScript?: AgentScriptProofEnvelope }).agentScript
  assert.ok(envelope, 'persisted replay spec must carry agentScript envelope')
  assert.equal(envelope.scriptSha256, expectedSha)
  // Executable script MUST NOT have been heuristically mangled by `redact()`.
  assert.equal(envelope.script, rawScript)
  assert.ok(envelope.script.includes(syntheticJwt))
  assert.ok(envelope.script.includes('synthetic-demo-password'))
  assert.ok(envelope.script.includes('Bearer synthetic-bearer-value-12345'))
  assert.deepEqual(verifyPersistedScriptIntegrity(envelope, expectedSha), { ok: true, actualSha256: expectedSha })

  // Title MUST still have known secrets redacted (H-18 step 8).
  const findingRow = storage.db.select().from(findings).all().find(f => f.id === persisted.findingId)
  assert.ok(findingRow)
  assert.ok(!findingRow.finding.title.includes(secretInTitle), 'known secret must be redacted from title')
})

test('R2-H-16: retestPersistedAgentScript and reverifyAgentScriptProof return inconclusive (never fixed/dismissed) on SHA-256 mismatch', async (t) => {
  const origin = 'http://127.0.0.1:4511'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Verifier', 'Check SHA integrity')
  let openSessionCalled = false
  const backend = makeDummyBackend(() => { openSessionCalled = true })
  const verifier = makeExecVerifier(storage, { backend })
  const broker = new RequestBroker()

  const originalScript = 'const tok = "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."; export default async () => {};'
  const originalSha = createHash('sha256').update(originalScript).digest('hex')
  const redactedCorruptedScript = 'const tok = "[redacted]"; export default async () => {};'

  const tamperedEnvelope: AgentScriptProofEnvelope = {
    kind: 'agent_script',
    runtime: 'ts',
    script: redactedCorruptedScript,
    scriptSha256: originalSha,
    verdict: 'confirmed',
    vulnClass: 'jwt_forgery',
    exchangeIds: ['ex-1'],
    transcriptDigests: ['b'.repeat(64)],
    confirmedAt: Date.now(),
  }

  const check = verifyPersistedScriptIntegrity(tamperedEnvelope, originalSha)
  assert.equal(check.ok, false)
  if (!check.ok) assert.equal(check.reason, PERSISTED_SCRIPT_INTEGRITY_ERROR)

  // 1) Retest path MUST return `inconclusive`, NEVER `fixed` or `dismissed`, and never open a worker session.
  const retest = await retestPersistedAgentScript(tamperedEnvelope, {
    spec: makeHttpChainSpec(origin),
    broker,
    grant: makeLabGrant(origin),
    backend,
    signal: new AbortController().signal,
    origin,
  })
  assert.equal(retest.verdict, 'inconclusive')
  assert.equal(retest.replay.verdict, 'inconclusive')
  assert.equal(openSessionCalled, false)
  assert.match(retest.replay.outcome.reason ?? '', /SHA-256 mismatch/i)

  // 2) Reverify path MUST also return `inconclusive`, NEVER `dismissed`, and preserve existing finding reason.
  const findingId = randomUUID()
  const spec = { ...makeHttpChainSpec(origin, { cwe: 'CWE-347', category: 'auth-identity' }), agentScript: tamperedEnvelope }
  const specRow = storage.createReplaySpec(run, assignment, findingId, spec, [origin], {
    verifiedInline: true,
    lastVerificationDiff: {
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      controlPassed: true,
      assertionSummary: { observed: 'confirmed', expected: 'confirmed' },
      stepStatuses: [],
      retriesRemaining: 1,
    },
    proof: {
      replaySpecId: '',
      findingId,
      verdict: 'confirmed',
      runtime: 'ts',
      scriptSha256: originalSha,
      artifactId: null,
      receipt: null,
      createdAt: Date.now(),
    },
  })
  const originalReason = 'Forged alg=none JWT grants access to /api/admin/me.'
  storage.upsertChainFinding(run, asset.id, {
    id: findingId,
    origin,
    title: 'JWT alg=none authentication bypass',
    status: 'confirmed',
    severity: 'high',
    reason: originalReason,
    remediation: 'Pin JWT algorithm.',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    category: 'auth-identity',
    cwe: 'CWE-347',
    confidence: 'high',
    verification: 'ProofReceipt ex-1 · auth_bypass rule · confirmed',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
    replaySpecId: specRow.id,
  }, specRow.id, [origin])

  const proofRecord = storage.replaySpecProof(run.id, specRow.id)!
  const reverify = await verifier.reverifyAgentScriptProof(run, {
    job: { assignment, controller: new AbortController() } as unknown as Parameters<ExecVerifier['reverifyAgentScriptProof']>[1]['job'],
    grant: makeLabGrant(origin),
    currentSecrets: () => [],
    findingId,
    replaySpecId: specRow.id,
  }, proofRecord)
  assert.ok(reverify)
  assert.equal(reverify.status, 'inconclusive')
  assert.equal(openSessionCalled, false)
  const updatedRow = storage.db.select().from(findings).all().find(f => f.id === findingId)
  assert.equal(updatedRow?.finding.status, 'inconclusive')
  assert.equal(updatedRow?.finding.reason, originalReason, 'existing finding description must be preserved on integrity-mismatch inconclusive')
})

// ============================================================================
// 2. R2-H-14 / H-18: CWE receipt binding, class drift, OOB structured selection, store chokepoint
// ============================================================================

test('R2-H-14 / H-18: bindConfirmedFindingIdentity binds CWE/category strictly to verified receipt class and rejects class drift', () => {
  const origin = 'http://127.0.0.1:4512'
  assert.equal(cweFamilyForReceiptClass('ssrf').cwe, 'CWE-918')
  assert.equal(cweFamilyForReceiptClass('xxe').cwe, 'CWE-611')
  assert.equal(cweFamilyForReceiptClass('open_redirect').cwe, 'CWE-601')
  assert.equal(isCweConsistentWithReceiptClass('CWE-89', 'ssrf'), false)
  assert.equal(isCweConsistentWithReceiptClass('CWE-918', 'ssrf'), true)
  assert.equal(isCweConsistentWithReceiptClass('CWE-863', 'bola'), true)

  const existing: Finding = {
    id: randomUUID(),
    origin,
    title: 'Mislabeled SQLi claim',
    status: 'pending',
    severity: 'high',
    reason: 'Model claimed SQLi but receipt proved SSRF.',
    remediation: 'Fix it.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'injection-input',
    cwe: 'CWE-89',
  }
  const mislabelledSpec = makeHttpChainSpec(origin, {
    title: 'Mislabeled SQLi spec',
    cwe: 'CWE-89',
    category: 'injection-input',
  })
  const ssrfReplay: ReplayVerificationResult = {
    verdict: 'confirmed',
    verificationTier: 'runtime_confirmed',
    outcome: { confirmed: true, controlPassed: true, observed: 'OOB hit', expected: 'OOB hit' },
    exchangeIds: ['ex-1'],
    exchanges: [],
    evidencePayload: {},
    evidenceSha256: 'c'.repeat(64),
    receipt: {
      mode: 'strict',
      receipt: {
        vulnClass: 'ssrf',
        target: { origin, method: 'POST', pathAndQuery: '/api/fetch' },
        exchangeIds: ['ex-1'],
        oobEventIds: ['oob-1'],
        browserTraceIds: [],
        claimedDelta: 'Server fetched canary URL',
      },
      verification: {
        confirmed: true,
        vulnClass: 'ssrf',
        rule: 'oob',
        reason: 'OOB callback delivered',
        observed: 'delivered',
        expected: 'delivered',
      },
    },
  }

  // Mismatched spec.cwe (CWE-89) MUST be overridden by the confirmed receipt class (CWE-918 / ssrf-redirects).
  const bound = bindConfirmedFindingIdentity(existing, mislabelledSpec, ssrfReplay)
  assert.equal(bound.cwe, 'CWE-918')
  assert.equal(bound.category, 'ssrf-redirects')

  // In-family spec.cwe (CWE-863 within authorization family) is preserved.
  const authSpec = makeHttpChainSpec(origin, { cwe: 'CWE-863', category: 'broken-access-control' })
  const bolaReplay: ReplayVerificationResult = {
    ...ssrfReplay,
    receipt: {
      mode: 'strict',
      receipt: {
        vulnClass: 'bola',
        target: { origin, method: 'GET', pathAndQuery: '/api/orders/2' },
        exchangeIds: ['ex-1'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Foreign order returned',
      },
      verification: {
        confirmed: true,
        vulnClass: 'bola',
        rule: 'impact',
        reason: 'Cross-tenant read confirmed',
        observed: '200',
        expected: '403',
      },
    },
  }
  const boundInFamily = bindConfirmedFindingIdentity(existing, authSpec, bolaReplay)
  assert.equal(boundInFamily.cwe, 'CWE-863')
  assert.equal(boundInFamily.category, 'broken-access-control')
})

test('H-18: findOobMatchingReplaySpec uses structured fields only (never substring scan) and store chokepoint protects confirmed identity', async (t) => {
  const origin = 'http://127.0.0.1:4513'
  const otherOrigin = 'http://127.0.0.1:4599'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Verifier', 'Check OOB spec selection')

  const subId = 'sub-real-12345'
  const carrierId = 'ex-carrier-67890'
  // Spoofed spec embedding subId and carrierId inside its title/impact text (NOT structured fields).
  const spoofSpec = makeHttpChainSpec(origin, {
    title: `Spoofed finding mentioning ${subId} and ${carrierId}`,
    impact: `Contains ${subId}`,
  })
  const realSpec = {
    ...makeHttpChainSpec(origin, { title: 'Real SSRF spec', cwe: 'CWE-918', category: 'ssrf-redirects' }),
    agentScript: {
      kind: 'agent_script' as const,
      runtime: 'ts' as const,
      script: 'export default async () => {}',
      scriptSha256: createHash('sha256').update('export default async () => {}').digest('hex'),
      verdict: 'confirmed' as const,
      vulnClass: 'ssrf',
      exchangeIds: [carrierId],
      transcriptDigests: [],
      confirmedAt: Date.now(),
    },
  }
  const wrongOriginSpec = {
    ...makeHttpChainSpec(otherOrigin, { title: 'Other origin spec', cwe: 'CWE-918', category: 'ssrf-redirects' }),
    oobSubscriptionId: subId,
  } as unknown as DeclarativeReplaySpec

  const spoofRow: ReplaySpecRow = storage.createReplaySpec(run, assignment, randomUUID(), spoofSpec, [origin])
  const wrongOriginRow: ReplaySpecRow = storage.createReplaySpec(run, assignment, randomUUID(), wrongOriginSpec, [otherOrigin])
  const realRow: ReplaySpecRow = storage.createReplaySpec(run, assignment, randomUUID(), realSpec, [origin])

  // Substring spoof in title/impact MUST NOT match.
  assert.equal(
    findOobMatchingReplaySpec([spoofRow, wrongOriginRow], { subscriptionId: subId, carrierExchangeId: carrierId, origin }),
    undefined,
  )
  // Structured match on same origin MUST match the real row.
  assert.equal(
    findOobMatchingReplaySpec([spoofRow, wrongOriginRow, realRow], { subscriptionId: subId, carrierExchangeId: carrierId, origin })?.id,
    realRow.id,
  )

  // Store chokepoint: confirmed finding cannot have fingerprintHash/replaySpecId/identity mutated via updateProposedFinding or upsertChainFinding.
  const confirmedId = randomUUID()
  const confirmedSpec = storage.createReplaySpec(run, assignment, confirmedId, makeHttpChainSpec(origin), [origin], {
    verifiedInline: true,
    lastVerificationDiff: {
      verdict: 'confirmed',
      verificationTier: 'runtime_confirmed',
      controlPassed: true,
      assertionSummary: { observed: '200', expected: '403' },
      stepStatuses: [],
      retriesRemaining: 1,
    },
  })
  const swapSpec = storage.createReplaySpec(run, assignment, confirmedId, makeHttpChainSpec(origin, { cwe: 'CWE-78', title: 'Swapped RCE' }), [origin])
  const origFp = 'fp-immutable-001'
  storage.upsertChainFinding(run, asset.id, {
    id: confirmedId,
    origin,
    title: 'Confirmed BOLA',
    status: 'confirmed',
    severity: 'medium',
    reason: 'Cross-tenant disclosure.',
    remediation: 'Check ownership.',
    evidenceIds: [],
    scopeRevision: run.scopeRevision,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    fingerprintHash: origFp,
    confidence: 'high',
    verification: 'Zero-LLM confirmed',
    verificationTier: 'runtime_confirmed',
    findingKind: 'multi_step_chain',
    replaySpecId: confirmedSpec.id,
  }, confirmedSpec.id, [origin])

  const afterProposed = storage.updateProposedFinding(run, confirmedId, {
    replaySpecId: swapSpec.id,
    fingerprintHash: 'fp-mutated-999',
    finding: { cwe: 'CWE-78', title: 'Mutated', severity: 'critical', category: 'injection-input' },
  })
  assert.equal(afterProposed.cwe, 'CWE-639')
  assert.equal(afterProposed.replaySpecId, confirmedSpec.id)
  assert.equal(afterProposed.fingerprintHash, origFp)
  const dbRow = storage.db.select().from(findings).all().find(f => f.id === confirmedId)
  assert.equal(dbRow?.fingerprintHash, origFp)
  assert.equal(dbRow?.replaySpecId, confirmedSpec.id)
})

// ============================================================================
// 3. H-20: Run-scoped late OOB carrier map (request-side only, rejects echo-only)
// ============================================================================

test('H-20: ExecVerifier run-scoped OOB carrier map promotes late prove.oob callbacks and rejects echo-only carriers', async (t) => {
  const origin = 'http://127.0.0.1:4514'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'verification', asset, 'Verifier', 'OOB late promotion')
  const canaryBroker = new CanaryBroker({ storage })
  const verifier = makeExecVerifier(storage, { canaryBroker })

  assert.deepEqual(probeCanaryClass(`ssrf:prove_oob (${origin})`), { vulnClass: 'ssrf', origin, param: null })

  const token = 'oobtok1234567890abcdef'
  const canaryId = randomUUID()
  storage.db.insert(canaries).values({
    id: canaryId,
    runId: run.id,
    assignmentId: assignment.id,
    token,
    purpose: `ssrf:prove_oob (${origin})`,
    createdAt: Date.now(),
  }).run()

  // Echo-only carrier (token only in responseBody, not in path/headers/requestBody) MUST be rejected.
  verifier.recordOobCarrier(run.id, token, {
    exchangeId: 'ex-echo-only',
    origin,
    method: 'GET',
    pathAndQuery: '/api/echo',
    status: 200,
    personaHandle: null,
    assignmentId: assignment.id,
    reqHeaders: {},
    respHeaders: {},
    requestBody: '',
    responseBody: `reflected ${token}`,
  })
  assert.equal(verifier.getOobCarrier(run.id, token), undefined, 'echo-only carrier must not be stored')

  // Real request-side carrier (token in requestBody) IS recorded even without a SQLite broker_exchanges row.
  verifier.recordOobCarrier(run.id, token, {
    exchangeId: 'ex-prove-oob-1',
    origin,
    method: 'POST',
    pathAndQuery: '/api/webhooks/test',
    status: 202,
    personaHandle: 'member_a',
    assignmentId: assignment.id,
    reqHeaders: { 'content-type': 'application/json' },
    respHeaders: {},
    requestBody: JSON.stringify({ url: `http://127.0.0.1:9999/c/${token}` }),
    responseBody: '{"queued":true}',
  })
  assert.ok(verifier.getOobCarrier(run.id, token))

  const subId = `sub-${randomUUID()}`
  const converted = verifier.convertOobPromotions(run.id, [{
    stage: 'late',
    latencyMs: 12_500,
    subscription: {
      id: subId,
      runId: run.id,
      canaryId,
      token,
      artifact: 'ssrf:prove_oob',
      status: 'promoted',
      immediateMs: 3_000,
      windowMs: 60_000,
      createdAt: Date.now() - 15_000,
      expiresAt: Date.now() + 45_000,
      promotedAt: Date.now(),
      callbackId: 'cb-1',
    },
    callback: {
      callbackId: 'cb-1',
      token,
      canaryId,
      protocol: 'http',
      method: 'GET',
      path: `/c/${token}`,
      remoteAddress: '127.0.0.1',
      headers: {},
      receivedAt: Date.now(),
    },
  } as unknown as ReturnType<CanaryBroker['promoteLate']>[number]])

  assert.equal(converted, 1)
  const promoted = storage.db.select().from(findings).all().find(f => f.runId === run.id && f.finding.cwe === 'CWE-918')
  assert.ok(promoted, 'late OOB callback should promote into a confirmed CWE-918 finding')
  assert.equal(promoted.finding.status, 'confirmed')
  assert.equal(promoted.verificationTier, 'runtime_confirmed')
})

// ============================================================================
// 4. R2-H-22: DooD RPC scratch dir staging via prepareSessionScratchDir(sid, 'rpc')
// ============================================================================

test('R2-H-22: resolveVerifyRpcHostDir stages under per-session scratch rpc subdir so resolveDoodMountArg succeeds', (t) => {
  const scratchDir = makeTempDir('dood-scratch', t)
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    KOVO_CONTAINER_SCRATCH_DIR: scratchDir,
    KOVO_WORKER_SCRATCH_VOLUME: 'kovo_worker_scratch',
  }
  const rpcDir = resolveVerifyRpcHostDir('assign-42', 1, env)
  assert.ok(rpcDir, 'DooD mode must return a staged scratch directory')
  assert.ok(rpcDir.startsWith(scratchDir + '/'), `expected rpcDir under ${scratchDir}, got ${rpcDir}`)
  assert.ok(rpcDir.endsWith('/rpc'), `expected rpcDir to use per-session /rpc subdir, got ${rpcDir}`)
  assert.ok(!rpcDir.startsWith('/dev/shm'), 'DooD RPC dir must never use /dev/shm')

  const mountArg = resolveDoodMountArg(rpcDir, '/run/kovo-verify', { env })
  assert.match(mountArg, /^type=volume,source=kovo_worker_scratch,target=\/run\/kovo-verify,volume-subpath=[^,]+\/rpc$/)
})

// ============================================================================
// 5. H-39 sensitive scriptPath refusal, R2-C-2 param safety, warmPoolPolicy & H-11 options
// ============================================================================

test('H-39: readAgentProofScript refuses sensitive repo files, symlinks, and traversal while reading normal scripts', (t) => {
  const { storage } = makeStore(t)
  const verifier = makeExecVerifier(storage)
  const reposDir = makeTempDir('repos', t)
  const outsideDir = makeTempDir('outside', t)

  mkdirSync(join(reposDir, 'scripts'), { recursive: true })
  mkdirSync(join(reposDir, '.ssh'), { recursive: true })
  mkdirSync(join(reposDir, '.git'), { recursive: true })
  mkdirSync(join(reposDir, 'credentials'), { recursive: true })

  writeFileSync(join(reposDir, 'scripts/proof.ts'), 'export default async function () { return true }\n')
  writeFileSync(join(reposDir, '.env'), 'DB_PASS=secret\n')
  writeFileSync(join(reposDir, '.env.production.js'), 'module.exports = { secret: "x" }\n')
  writeFileSync(join(reposDir, '.ssh/id_rsa'), 'PRIVATE KEY\n')
  writeFileSync(join(reposDir, '.git/config'), '[remote "origin"]\nurl = https://u:p@example.com/r.git\n')
  writeFileSync(join(reposDir, 'secrets.json'), '{"apiKey":"123"}\n')
  writeFileSync(join(reposDir, 'server.pem'), 'PEM DATA\n')
  writeFileSync(join(reposDir, 'credentials/prod.txt'), 'token=abc\n')
  writeFileSync(join(outsideDir, 'escape.ts'), 'export default 1\n')
  symlinkSync(join(reposDir, '.env'), join(reposDir, 'scripts/link-to-env.ts'))
  symlinkSync(join(outsideDir, 'escape.ts'), join(reposDir, 'scripts/link-outside.ts'))

  assert.equal(isSensitiveRepoEntry('.ssh', '.ssh', true), true)
  assert.equal(isSensitiveRepoRelativePath('.env.production.js'), true)
  assert.equal(isSensitiveRepoRelativePath('scripts/proof.ts'), false)

  assert.match(verifier.readAgentProofScript(reposDir, 'scripts/proof.ts'), /return true/)

  for (const blocked of [
    '.env',
    '.env.production.js',
    '.ssh/id_rsa',
    '.git/config',
    'secrets.json',
    'server.pem',
    'credentials/prod.txt',
    'scripts/link-to-env.ts',
    'scripts/link-outside.ts',
    '../outside/escape.ts',
  ]) {
    assert.throws(
      () => verifier.readAgentProofScript(reposDir, blocked),
      /sensitive|workspace/i,
      `expected readAgentProofScript to refuse "${blocked}"`,
    )
  }
})

test('R2-C-2, warmPoolPolicy & H-11: assertSafeParamName blocks prototype segments, runner forwards warmPoolPolicy, and composite options derive from grant', () => {
  for (const bad of [
    '__proto__.allowLocalLab',
    'user.__proto__.polluted',
    'constructor.prototype.isAdmin',
    'a[__proto__].x',
    'prototype.allowedPorts',
    'a.constructor.b',
  ]) {
    assert.equal(isSafeParamName(bad), false, `expected "${bad}" to be rejected`)
    assert.throws(() => assertSafeParamName(bad), /prototype accessor/i)
  }
  for (const good of ['id', 'user.profile.email', 'filter.status', 'items[0].name']) {
    assert.equal(isSafeParamName(good), true, `expected "${good}" to be allowed`)
    assert.equal(assertSafeParamName(good), good)
  }

  // H-11: derive attackerPersonas & forbiddenShortcutPersonas from grant.personas
  const personas = new Map([
    ['member_a', { id: 'p1', handle: 'member_a', roleLabel: 'member (tenant-a)', originAllowlist: [], authKind: 'bearer' as const, headerName: null, secret: '', canaryMarkers: [] }],
    ['viewer_b', { id: 'p2', handle: 'viewer_b', roleLabel: 'viewer (tenant-b)', originAllowlist: [], authKind: 'bearer' as const, headerName: null, secret: '', canaryMarkers: [] }],
    ['org_admin', { id: 'p3', handle: 'org_admin', roleLabel: 'org_admin (tenant-a)', originAllowlist: [], authKind: 'bearer' as const, headerName: null, secret: '', canaryMarkers: [] }],
    ['owner_a', { id: 'p4', handle: 'owner_a', roleLabel: 'owner (tenant-a)', originAllowlist: [], authKind: 'bearer' as const, headerName: null, secret: '', canaryMarkers: [] }],
  ]) as unknown as NonNullable<Grant['personas']>
  const derived = buildCompositeVerifyOptionsFromGrant({ personas })
  assert.ok(derived)
  assert.deepEqual(new Set(derived.attackerPersonas), new Set(['member_a', 'viewer_b']))
  assert.deepEqual(new Set(derived.forbiddenShortcutPersonas), new Set(['org_admin', 'owner_a']))

  // Wiring verification in exec-worker-runner.ts: warmPoolPolicy forwarded to openSession + assertSafeParamName in probe_differential.
  const runnerSrc = readFileSync(join(process.cwd(), 'src/server/exec-worker-runner.ts'), 'utf8')
  assert.match(runnerSrc, /openSession\(\s*job\.assignment\.id,\s*job\.controller\.signal,\s*\{\s*warmPoolPolicy/)
  assert.ok(runnerSrc.includes("assertSafeParamName(args.paramName, 'paramName')"))
})

// ============================================================================
// 6. UX Bug: Preserve existingFinding.reason on inconclusive replay failure + amber UI callout
// ============================================================================

test('UX bug: buildReplayFindingPatch preserves existingFinding.reason on inconclusive replay failure and UI renders amber callout', () => {
  const origin = 'http://127.0.0.1:4515'
  const spec = makeHttpChainSpec(origin)
  const vulnerabilityDescription =
    'GET /api/orders/2 returned Tenant B invoice records when requested with Tenant A member credentials.'
  const existingFinding: Finding = {
    id: randomUUID(),
    origin,
    title: 'Cross-tenant BOLA on /api/orders/:id',
    status: 'pending',
    severity: 'high',
    reason: vulnerabilityDescription,
    remediation: 'Verify tenant ownership before returning order records.',
    evidenceIds: [],
    scopeRevision: 1,
    category: 'broken-access-control',
    cwe: 'CWE-639',
  }
  const replayCrash: ReplayVerificationResult = {
    verdict: 'inconclusive',
    outcome: {
      confirmed: false,
      controlPassed: false,
      observed: 'Replay execution failed: Worker session timed out (ECONNREFUSED)',
      expected: 'Clean replay execution passing control and deterministic assertions.',
      reason: 'Replay execution failed: Worker session timed out (ECONNREFUSED)',
    },
    exchangeIds: [],
    exchanges: [],
    evidencePayload: { error: 'Replay execution failed: Worker session timed out (ECONNREFUSED)' },
    evidenceSha256: 'd'.repeat(64),
  }

  const { patch } = buildReplayFindingPatch(spec, replayCrash, existingFinding, 'inconclusive', undefined, 'replay', [])
  assert.equal(patch.status, 'inconclusive')
  assert.equal(patch.reason, vulnerabilityDescription, 'existingFinding.reason MUST be preserved under "What happened"')
  assert.match(patch.verification ?? '', /Replay execution failed: Worker session timed out \(ECONNREFUSED\)/)

  // UI helper detects infra failure on inconclusive finding (from verification OR lastVerificationDiff).
  const { extractReplayInfraFailure, ReplayFailureCallout } = loadReplayCalloutModule()
  const extractedFromVerification = extractReplayInfraFailure(
    { status: 'inconclusive', verification: patch.verification },
    undefined,
  )
  assert.equal(extractedFromVerification, 'Replay execution failed: Worker session timed out (ECONNREFUSED)')

  const extractedFromDiff = extractReplayInfraFailure(
    { status: 'inconclusive', verification: undefined },
    {
      verdict: 'inconclusive',
      assertionSummary: {
        reason: 'Replay execution failed: socket hang up',
        observed: 'Replay execution failed: socket hang up',
      },
    },
  )
  assert.equal(extractedFromDiff, 'Replay execution failed: socket hang up')

  // Confirmed / static_verified / dismissed findings MUST NOT show the callout.
  assert.equal(
    extractReplayInfraFailure({ status: 'confirmed', verification: patch.verification }, undefined),
    null,
  )
  assert.equal(
    extractReplayInfraFailure({ status: 'static_verified', verification: patch.verification }, undefined),
    null,
  )
  assert.equal(
    extractReplayInfraFailure({ status: 'dismissed', verification: patch.verification }, undefined),
    null,
  )
  // Non-infra inconclusive verification text without an infra failure marker returns null.
  assert.equal(
    extractReplayInfraFailure({ status: 'inconclusive', verification: 'Zero-LLM http_chain replay verdict: inconclusive (controlPassed=false, observed: response body differed).' }, undefined),
    null,
  )

  // Amber inline callout renders cleanly with the heading and redacted error text.
  const html = renderToStaticMarkup(React.createElement(ReplayFailureCallout, { reason: extractedFromVerification! }))
  assert.ok(html.includes('data-testid="replay-failure-callout"'))
  assert.ok(html.includes('bg-warn-soft'))
  assert.ok(html.includes('text-warn'))
  assert.ok(html.includes("Live verification couldn&#x27;t run") || html.includes("Live verification couldn't run"))
  assert.ok(html.includes('Replay execution failed: Worker session timed out (ECONNREFUSED)'))

  // Verify both findings-inspector.tsx and queue-read.tsx wire ReplayFailureCallout directly after "What happened".
  const inspectorSrc = readFileSync(join(process.cwd(), 'src/components/run/views/findings-inspector.tsx'), 'utf8')
  const queueReadSrc = readFileSync(join(process.cwd(), 'src/components/run/views/queue-read.tsx'), 'utf8')
  assert.ok(inspectorSrc.includes('extractReplayInfraFailure(f, diff)'))
  assert.ok(inspectorSrc.includes('<ReplayFailureCallout reason={replayInfraFailure} />'))
  assert.ok(queueReadSrc.includes('extractReplayInfraFailure(F, replay?.lastVerificationDiff)'))
  assert.ok(queueReadSrc.includes('<ReplayFailureCallout reason={replayInfraFailure} />'))
})
