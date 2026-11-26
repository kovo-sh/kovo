/**
 * Regression suite for R3-H-13 and R3-H-15 (`src/server/exec-verify.ts`):
 *  - R3-H-13:
 *    1. Unrelated-class confirmed findings (e.g. SQLi CWE-89, XSS CWE-79) on the same route,
 *       method, and origin as a composite setup hop are NEVER superseded; same-class and
 *       explicitly declared precondition-class findings ARE superseded.
 *    2. Exact origin & explicit HTTP method matching: different loopback ports/hostnames
 *       (`127.0.0.1:3001` vs `127.0.0.1:3002` vs `localhost:3002`) and missing/`ANY` methods
 *       NEVER trigger supersession.
 *    3. Upstream supersession endpoints are derived strictly from non-terminal hops' cited
 *       host-signed transcript exchanges — unbound worker-declared `hop.target` strings alone
 *       NEVER supersede other findings.
 *    4. Every non-confirmed exit (SHA-256 integrity mismatch, legacy Python reverify demotion,
 *       and standard reverify failure) restores ALL previously superseded dependents through the
 *       single shared demotion/restore helper.
 *  - R3-H-15:
 *    5. Composite finding `origin`, asset association, fingerprint, dedupe key, and persisted
 *       receipt `target.origin` are derived strictly from the terminal exchange's host-signed
 *       `origin` in the transcript — never from worker-declared `hops[terminal].target.origin`.
 *       When declared hop origin disagrees with the host-signed terminal exchange origin,
 *       persistence and receipt serialization fail closed (never silently filing on origin B).
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eq } from 'drizzle-orm'

import type { AgentScriptProofResult, V8CompositeProofBundle } from '../src/server/agent-script-proof.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { CanaryBroker } from '../src/server/canary-broker.ts'
import type { CompositeProofReceipt, HostSignedTranscript } from '../src/server/composite-receipt.ts'
import {
  buildHostRecordedExchangeIndex,
  ExecVerifier,
  extractAgentProofTarget,
  extractCompositeUpstreamEndpoints,
  inspectCompositeHostOrigin,
  isEndpointSubsetOfUpstream,
  isFindingClassSupersessionCompatible,
  serializeCompositeProofReceiptRow,
  type ExecVerifyHost,
} from '../src/server/exec-verify.ts'
import { computeFindingFingerprint } from '../src/server/finding-fingerprint.ts'
import { findings, replaySpecs } from '../src/server/schema.ts'
import { InvariantError, Store } from '../src/server/store.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { makeLabGrant, setupApprovedRun } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

function makeStore(t: test.TestContext): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r3-exec-verify-id-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    try { rmSync(dir, { recursive: true, force: true }) } catch { /* ignore */ }
  })
  return { storage, dir }
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

function makeExecVerifier(storage: Store, backend?: WorkerBackend): ExecVerifier {
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const canaryBroker = new CanaryBroker({ storage })
  const host: ExecVerifyHost = {
    storage,
    broker,
    browser: null as unknown as ExecVerifyHost['browser'],
    canaryBroker,
    backend: backend ?? makeDummyBackend(),
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
  }
  return new ExecVerifier(host)
}

function makeAttemptReport(attempt: 1 | 2, digest: string) {
  return {
    attempt,
    nonce: `nonce-${digest}`,
    exitCode: 0,
    durationMs: 8,
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

function makeSingleHopProof(opts: {
  origin: string
  endpoint: string
  method: string
  vulnClass: string
  exchangePrefix: string
  claimTitle: string
}): AgentScriptProofResult {
  const ctrlId = `${opts.exchangePrefix}-ctrl`
  const probeId = `${opts.exchangePrefix}-probe`
  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Two fresh runs confirmed single-hop proof.',
      attempts: [
        makeAttemptReport(1, `s1-${opts.exchangePrefix}`),
        makeAttemptReport(2, `s2-${opts.exchangePrefix}`),
      ],
      disagreements: [],
      claimTitle: opts.claimTitle,
      rejectedBy: null,
      missingEvidence: [],
      transcriptSummary: [],
    },
    exchanges: [
      {
        exchangeId: ctrlId,
        op: 'http',
        method: opts.method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 403,
        durationMs: 3,
        personaHandle: 'member_a',
        sessionRole: 'control',
        actorRoleLabel: 'member',
        body: '{"error":"denied"}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
      {
        exchangeId: probeId,
        op: 'http',
        method: opts.method,
        pathAndQuery: opts.endpoint,
        origin: opts.origin,
        status: 200,
        durationMs: 5,
        personaHandle: 'member_a',
        sessionRole: 'probe',
        actorRoleLabel: 'member',
        body: '{"ok":true}',
        requestHeaders: {},
        responseHeaders: { 'content-type': 'application/json' },
      },
    ],
    receipt: {
      receipt: {
        vulnClass: opts.vulnClass,
        target: { origin: opts.origin, method: opts.method, pathAndQuery: opts.endpoint },
        exchangeIds: [ctrlId, probeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `${opts.vulnClass} delta confirmed`,
      },
      verification: {
        confirmed: true,
        vulnClass: opts.vulnClass,
        rule: 'impact',
        reason: `${opts.vulnClass} confirmed`,
        observed: '200 OK',
        expected: '403 Forbidden',
      },
    },
    compositeReceipt: null,
    vulnClass: opts.vulnClass,
    transcriptDigests: [`s1-${opts.exchangePrefix}`, `s2-${opts.exchangePrefix}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript: null,
    claimTitle: opts.claimTitle,
    severity: 'high',
    description: `${opts.vulnClass} proof.`,
  }
}

interface HopFixture {
  hopId: string
  /** Declared hop.target.origin (may intentionally differ from signed exchange origin in negative tests). */
  declaredOrigin: string
  declaredMethod: string
  declaredPathAndQuery: string
  /** Actual host-signed exchange origin/method/path in transcript. */
  signedOrigin?: string
  signedMethod?: string
  signedPathAndQuery?: string
  exchangeId: string
  /** Optional explicitly declared precondition receipt on this hop. */
  preconditionVulnClass?: string
}

function makeCompositeProof(opts: {
  chainId: string
  terminalVulnClass?: string
  hops: readonly HopFixture[]
  terminalHopId?: string
  claimTitle: string
  includeHostTranscript?: boolean
}): AgentScriptProofResult {
  const terminalVulnClass = opts.terminalVulnClass ?? 'dual_tenant_abac'
  const terminalHop = opts.hops.find(h => h.hopId === opts.terminalHopId) ?? opts.hops[opts.hops.length - 1]!
  const ctrlId = `${opts.chainId}-ctrl`
  const readbackId = `${opts.chainId}-rb`
  const termSignedOrigin = terminalHop.signedOrigin ?? terminalHop.declaredOrigin
  const termSignedMethod = terminalHop.signedMethod ?? terminalHop.declaredMethod
  const termSignedPath = terminalHop.signedPathAndQuery ?? terminalHop.declaredPathAndQuery

  const receipt: CompositeProofReceipt = {
    chainId: opts.chainId,
    terminalVulnClass,
    replayMode: 'fresh_clean_replay',
    hops: opts.hops.map(h => ({
      hopId: h.hopId,
      surface: 'http',
      target: {
        origin: h.declaredOrigin,
        method: h.declaredMethod,
        pathAndQuery: h.declaredPathAndQuery,
      },
      exchangeIds: [h.exchangeId],
      oobEventIds: [],
      browserTraceIds: [],
      claimedDelta: `Hop ${h.hopId} delta`,
      producedCapabilities: [],
      consumedCapabilities: [],
      ...(h.preconditionVulnClass ? {
        proofReceipt: {
          vulnClass: h.preconditionVulnClass,
          target: {
            origin: h.declaredOrigin,
            method: h.declaredMethod,
            pathAndQuery: h.declaredPathAndQuery,
          },
          exchangeIds: [h.exchangeId],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: `Precondition ${h.preconditionVulnClass}`,
        },
      } : {}),
    })),
    causalEdges: [],
    terminalImpact: {
      terminalHopId: terminalHop.hopId,
      claimedImpact: 'Confirmed multi-hop terminal impact.',
      summary: 'Confirmed multi-hop terminal impact.',
      terminalExchangeId: terminalHop.exchangeId,
      oracleFamily: terminalVulnClass as CompositeProofReceipt['terminalImpact']['oracleFamily'],
      preChainControlExchangeIds: [ctrlId],
      postChainReadbackExchangeIds: [readbackId],
    },
  }

  const compositeReceipt: V8CompositeProofBundle = {
    receipt,
    verification: {
      confirmed: true,
      chainId: opts.chainId,
      terminalVulnClass,
      replayMode: 'fresh_clean_replay',
      modeBVerified: false,
      hopCount: opts.hops.length,
      verifiedEdges: [],
      reason: 'Composite chain verified.',
      terminalOracleFamily: terminalVulnClass,
      terminalEndpoint: termSignedPath,
    },
    hopActors: Object.fromEntries(opts.hops.map(h => [h.hopId, 'member_a'])),
  }

  const exchanges: AgentScriptProofResult['exchanges'] = [
    {
      exchangeId: ctrlId,
      op: 'http',
      method: termSignedMethod,
      pathAndQuery: termSignedPath,
      origin: termSignedOrigin,
      status: 403,
      durationMs: 3,
      personaHandle: 'member_a',
      sessionRole: 'control',
      actorRoleLabel: 'member',
      body: '{"error":"forbidden"}',
      requestHeaders: {},
      responseHeaders: { 'content-type': 'application/json' },
    },
    ...opts.hops.map((h, idx) => ({
      exchangeId: h.exchangeId,
      op: 'http' as const,
      method: h.signedMethod ?? h.declaredMethod,
      pathAndQuery: h.signedPathAndQuery ?? h.declaredPathAndQuery,
      origin: h.signedOrigin ?? h.declaredOrigin,
      status: 200,
      durationMs: 5 + idx,
      personaHandle: 'member_a',
      sessionRole: h.hopId === terminalHop.hopId ? 'probe' as const : 'control' as const,
      actorRoleLabel: 'member',
      body: '{"ok":true}',
      requestHeaders: {},
      responseHeaders: { 'content-type': 'application/json' },
    })),
    {
      exchangeId: readbackId,
      op: 'http',
      method: 'GET',
      pathAndQuery: termSignedPath,
      origin: termSignedOrigin,
      status: 200,
      durationMs: 2,
      personaHandle: 'member_a',
      sessionRole: 'control',
      actorRoleLabel: 'member',
      body: '{"ok":true}',
      requestHeaders: {},
      responseHeaders: { 'content-type': 'application/json' },
    },
  ]

  const hostTranscript: HostSignedTranscript | null = opts.includeHostTranscript
    ? {
        entries: exchanges.map((ex, idx) => ({
          exchangeId: ex.exchangeId,
          origin: ex.origin,
          seq: idx + 1,
          timestampMs: 1_700_000_000_000 + idx * 10,
          step: {
            id: ex.exchangeId,
            arm: ex.sessionRole === 'probe' ? 'probe' : 'control',
            method: ex.method,
            pathAndQuery: ex.pathAndQuery,
            status: ex.status,
            actor: { handle: 'member_a', role: 'member', tenant: 'tenant_a', auth: 'bearer', sameSite: null },
          },
        })),
      }
    : null

  return {
    verdict: {
      confirmed: true,
      reason: 'confirmed',
      detail: 'Two fresh runs confirmed composite proof.',
      attempts: [
        makeAttemptReport(1, `c1-${opts.chainId}`),
        makeAttemptReport(2, `c2-${opts.chainId}`),
      ],
      disagreements: [],
      claimTitle: opts.claimTitle,
      rejectedBy: null,
      missingEvidence: [],
      transcriptSummary: [],
    },
    exchanges,
    receipt: null,
    compositeReceipt,
    vulnClass: terminalVulnClass,
    transcriptDigests: [`c1-${opts.chainId}`, `c2-${opts.chainId}`],
    sealedCapabilities: [],
    transcriptRecords: [],
    hostTranscript,
    claimTitle: opts.claimTitle,
    severity: 'high',
    description: 'Composite proof.',
  }
}

// ============================================================================
// 1. R3-H-13: Class / CWE bound supersession
// ============================================================================

test('R3-H-13: unrelated-class confirmed findings (SQLi/XSS/SSRF) on a composite setup hop route are NOT superseded, while matching class and explicit preconditions ARE', async (t) => {
  const origin = 'http://127.0.0.1:4611'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker', 'R3-H-13 class supersession')
  const verifier = makeExecVerifier(storage)

  // Confirmed SQLi (CWE-89) on the exact listing route used by BOLA setup hop
  const fSqli = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// sqli listing proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/orders/ord_10',
      method: 'GET',
      vulnClass: 'sqli',
      exchangePrefix: 'sqli-1',
      claimTitle: 'Boolean SQL injection on GET /v1/orders/:id',
    }),
    secrets: [],
  })

  // Confirmed XSS (CWE-79) on the exact same route
  const fXss = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// xss listing proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/orders/ord_11',
      method: 'GET',
      vulnClass: 'xss',
      exchangePrefix: 'xss-1',
      claimTitle: 'Reflected XSS on GET /v1/orders/:id',
    }),
    secrets: [],
  })

  // Confirmed SSRF (CWE-918) on a second setup route
  const fSsrf = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// ssrf webhook proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/webhooks/wh_5/fetch',
      method: 'POST',
      vulnClass: 'ssrf',
      exchangePrefix: 'ssrf-1',
      claimTitle: 'SSRF on webhook fetch route',
    }),
    secrets: [],
  })

  // Confirmed BOLA (CWE-639) on GET /v1/orders/:id (same class as dual_tenant_abac composite)
  const fBola = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// bola listing proof',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/orders/ord_12',
      method: 'GET',
      vulnClass: 'bola',
      exchangePrefix: 'bola-1',
      claimTitle: 'BOLA read on GET /v1/orders/:id',
    }),
    secrets: [],
  })

  // Persist 3-hop dual_tenant_abac composite whose setup hops touch GET /v1/orders/:id (no precondition class)
  // and POST /v1/webhooks/:id/fetch (with explicit precondition class 'ssrf')
  const fComp = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// composite abac chain',
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-r3h13-class',
      terminalVulnClass: 'dual_tenant_abac',
      includeHostTranscript: true,
      hops: [
        {
          hopId: 'h1',
          declaredOrigin: origin,
          declaredMethod: 'GET',
          declaredPathAndQuery: '/v1/orders/ord_99',
          exchangeId: 'c1-h1',
        },
        {
          hopId: 'h2',
          declaredOrigin: origin,
          declaredMethod: 'POST',
          declaredPathAndQuery: '/v1/webhooks/wh_99/fetch',
          exchangeId: 'c1-h2',
          preconditionVulnClass: 'ssrf',
        },
        {
          hopId: 'h3',
          declaredOrigin: origin,
          declaredMethod: 'POST',
          declaredPathAndQuery: '/v1/payouts/pay_99/approve',
          exchangeId: 'c1-h3',
        },
      ],
      claimTitle: 'Full 3-hop ABAC payout chain',
    }),
    secrets: [],
  })

  const rows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  const byId = new Map(rows.map(r => [r.id, r]))

  // Unrelated SQLi & XSS findings MUST NOT be superseded by BOLA setup hop!
  assert.equal(byId.get(fSqli.findingId)?.supersededByFindingId ?? null, null, 'SQLi finding must NOT be superseded by BOLA setup hop')
  assert.equal(byId.get(fXss.findingId)?.supersededByFindingId ?? null, null, 'XSS finding must NOT be superseded by BOLA setup hop')

  // Matching-class BOLA finding and explicitly declared SSRF precondition finding ARE superseded
  assert.equal(byId.get(fBola.findingId)?.supersededByFindingId, fComp.findingId)
  assert.equal(byId.get(fSsrf.findingId)?.supersededByFindingId, fComp.findingId)

  // Direct pure helper assertions
  assert.equal(isFindingClassSupersessionCompatible({ cwe: 'CWE-89', vulnClass: 'sqli' }, { terminalVulnClass: 'dual_tenant_abac' }), false)
  assert.equal(isFindingClassSupersessionCompatible({ cwe: 'CWE-79', vulnClass: 'xss' }, { terminalVulnClass: 'dual_tenant_abac' }), false)
  assert.equal(isFindingClassSupersessionCompatible({ cwe: null, vulnClass: null }, { terminalVulnClass: 'dual_tenant_abac' }), false)
  assert.equal(isFindingClassSupersessionCompatible({ cwe: 'CWE-639', vulnClass: 'bola' }, { terminalVulnClass: 'dual_tenant_abac' }), true)
  assert.equal(
    isFindingClassSupersessionCompatible(
      { cwe: 'CWE-918', vulnClass: 'ssrf' },
      { terminalVulnClass: 'dual_tenant_abac', preconditionVulnClasses: ['ssrf'] },
    ),
    true,
  )
})

// ============================================================================
// 2. R3-H-13: Exact origin, explicit method, and signed-exchange-only upstream extraction
// ============================================================================

test('R3-H-13: different loopback origins, missing/ANY methods, and unbound hop.target strings NEVER supersede findings', async (t) => {
  const origin1 = 'http://127.0.0.1:3001'
  const origin2 = 'http://127.0.0.1:3002'
  const localhostOrigin2 = 'http://localhost:3002'

  // Pure helper checks: exact origin and explicit HTTP method required
  assert.equal(
    isEndpointSubsetOfUpstream(
      [{ origin: origin1, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
      [{ origin: origin2, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
    ),
    false,
    '127.0.0.1:3001 must NEVER match 127.0.0.1:3002',
  )
  assert.equal(
    isEndpointSubsetOfUpstream(
      [{ origin: origin1, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
      [{ origin: localhostOrigin2, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
    ),
    false,
    '127.0.0.1:3001 must NEVER match localhost:3002',
  )
  assert.equal(
    isEndpointSubsetOfUpstream(
      [{ origin: origin2, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
      [{ origin: localhostOrigin2, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
    ),
    false,
    '127.0.0.1:3002 must NEVER match localhost:3002',
  )
  assert.equal(
    isEndpointSubsetOfUpstream(
      [{ origin: origin1, method: null, normalizedEndpoint: '/v1/tokens/exchange' }],
      [{ origin: origin1, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
    ),
    false,
    'missing method must NEVER match explicit method',
  )
  assert.equal(
    isEndpointSubsetOfUpstream(
      [{ origin: origin1, method: 'ANY', normalizedEndpoint: '/v1/tokens/exchange' }],
      [{ origin: origin1, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
    ),
    false,
    'ANY method must NEVER match explicit method',
  )
  assert.equal(
    isEndpointSubsetOfUpstream(
      [{ origin: origin1, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
      [{ origin: origin1, method: 'POST', normalizedEndpoint: '/v1/tokens/exchange' }],
    ),
    true,
  )

  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, {
    seeds: [origin1, origin2],
    environment: 'local-lab',
    tier: 3,
  })
  const run = storage.run(runId)
  const asset1 = run.candidates.find(c => c.origin === origin1)!
  const asset2 = run.candidates.find(c => c.origin === origin2)!
  const worker1 = storage.makeWorker(run, 'investigation', asset1, 'W1', 'Origin 1')
  const worker2 = storage.makeWorker(run, 'investigation', asset2, 'W2', 'Origin 2')
  const verifier = makeExecVerifier(storage)

  // Confirmed BOLA on 127.0.0.1:3001 POST /v1/tokens/exchange
  const fOrigin1 = verifier.persistAgentScriptProof({
    run,
    assignment: worker1,
    script: '// origin1 token exchange',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin: origin1,
      endpoint: '/v1/tokens/exchange',
      method: 'POST',
      vulnClass: 'authorization',
      exchangePrefix: 'o1-tok',
      claimTitle: 'Token exchange BOLA on 3001',
    }),
    secrets: [],
  })

  // Confirmed BOLA on 127.0.0.1:3002 POST /v1/secret/records (target of adversarial unbound hop.target)
  const fVictimOnOrigin2 = verifier.persistAgentScriptProof({
    run,
    assignment: worker2,
    script: '// origin2 victim secret records',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin: origin2,
      endpoint: '/v1/secret/records',
      method: 'POST',
      vulnClass: 'authorization',
      exchangePrefix: 'o2-victim',
      claimTitle: 'Secret records BOLA on 3002',
    }),
    secrets: [],
  })

  // Persist composite on 127.0.0.1:3002 whose:
  //  - hop 1 hits POST /v1/tokens/exchange on 127.0.0.1:3002 (different port from fOrigin1 on 3001!)
  //  - hop 2 declares unbound hop.target = POST /v1/secret/records on 3002, while its actual
  //    signed transcript exchange hit GET /v1/harmless/list on 3002!
  const adversarialProof = makeCompositeProof({
    chainId: 'chain-r3h13-origin-unbound',
    terminalVulnClass: 'dual_tenant_abac',
    includeHostTranscript: true,
    hops: [
      {
        hopId: 'h1',
        declaredOrigin: origin2,
        declaredMethod: 'POST',
        declaredPathAndQuery: '/v1/tokens/exchange',
        exchangeId: 'adv-h1',
      },
      {
        hopId: 'h2',
        declaredOrigin: origin2,
        declaredMethod: 'POST',
        declaredPathAndQuery: '/v1/secret/records',
        signedOrigin: origin2,
        signedMethod: 'GET',
        signedPathAndQuery: '/v1/harmless/list',
        exchangeId: 'adv-h2',
      },
      {
        hopId: 'h3',
        declaredOrigin: origin2,
        declaredMethod: 'POST',
        declaredPathAndQuery: '/v1/payouts/p1/approve',
        exchangeId: 'adv-h3',
      },
    ],
    claimTitle: 'Composite on 3002 with spoofed hop2 target',
  })

  // Verify extractCompositeUpstreamEndpoints NEVER uses unbound hop.target or empty transcript!
  assert.deepEqual(extractCompositeUpstreamEndpoints(adversarialProof.compositeReceipt!.receipt, []), [])
  const extractedUpstream = extractCompositeUpstreamEndpoints(
    adversarialProof.compositeReceipt!.receipt,
    buildHostRecordedExchangeIndex(adversarialProof),
  )
  assert.equal(
    extractedUpstream.some(u => u.normalizedEndpoint === '/v1/secret/records'),
    false,
    'unbound hop.target path must never appear in extracted upstream endpoints',
  )
  assert.equal(
    extractedUpstream.some(u => u.normalizedEndpoint === '/v1/harmless/list' && u.method === 'GET'),
    true,
    'actual host-signed exchange endpoint must be extracted',
  )

  verifier.persistAgentScriptProof({
    run,
    assignment: worker2,
    script: '// composite on 3002',
    runtime: 'ts',
    proof: adversarialProof,
    secrets: [],
  })

  const rows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  const byId = new Map(rows.map(r => [r.id, r]))
  assert.equal(
    byId.get(fOrigin1.findingId)?.supersededByFindingId ?? null,
    null,
    'finding on 127.0.0.1:3001 must NOT be superseded by composite on 127.0.0.1:3002',
  )
  assert.equal(
    byId.get(fVictimOnOrigin2.findingId)?.supersededByFindingId ?? null,
    null,
    'finding matching only unbound hop.target (not signed transcript exchange) must NOT be superseded',
  )
})

// ============================================================================
// 3. R3-H-13: Restore superseded dependents on EVERY non-confirmed exit
// ============================================================================

test('R3-H-13: demoting a superseding composite via integrity mismatch OR legacy reverify restores all superseded dependents', async (t) => {
  const origin = 'http://127.0.0.1:4621'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const worker = storage.makeWorker(run, 'investigation', asset, 'Worker', 'R3-H-13 restore tests')
  let openSessionCalls = 0
  const verifier = makeExecVerifier(storage, makeDummyBackend(() => { openSessionCalls += 1 }))

  // --- Branch A: SHA-256 integrity mismatch demotion ---
  const depA = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// dep A single-hop',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/tokens/mint',
      method: 'POST',
      vulnClass: 'authorization',
      exchangePrefix: 'dep-a',
      claimTitle: 'Upstream token mint BOLA',
    }),
    secrets: [],
  })

  const compAScript = 'export default async function run() { return { ok: "A" }; }'
  const compA = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: compAScript,
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-restore-integrity',
      terminalVulnClass: 'dual_tenant_abac',
      includeHostTranscript: true,
      hops: [
        { hopId: 'h1', declaredOrigin: origin, declaredMethod: 'POST', declaredPathAndQuery: '/v1/tokens/mint', exchangeId: 'ra-h1' },
        { hopId: 'h2', declaredOrigin: origin, declaredMethod: 'POST', declaredPathAndQuery: '/v1/transfers/t1/commit', exchangeId: 'ra-h2' },
      ],
      claimTitle: 'Composite A superseding dep A',
    }),
    secrets: [],
  })

  // Confirm depA is currently superseded by compA
  const depABefore = storage.db.select().from(findings).where(eq(findings.id, depA.findingId)).get()!
  assert.equal(depABefore.supersededByFindingId, compA.findingId)
  assert.equal(depABefore.finding.supersededByFindingId, compA.findingId)

  // Tamper the persisted script in replay_specs to trigger SHA-256 integrity mismatch
  const specRowA = storage.getReplaySpec(run.id, compA.replaySpecId)
  const tamperedSpecA = {
    ...specRowA.spec,
    agentScript: {
      ...(specRowA.spec as unknown as { agentScript: Record<string, unknown> }).agentScript,
      script: 'export default async function run() { return { ok: "[corrupted]" }; }',
    },
  }
  storage.db.update(replaySpecs)
    .set({ spec: tamperedSpecA as typeof specRowA.spec })
    .where(eq(replaySpecs.id, compA.replaySpecId))
    .run()

  const proofRecA = storage.replaySpecProof(run.id, compA.replaySpecId)!
  const reverifyA = await verifier.reverifyAgentScriptProof(run, {
    job: { assignment: worker, controller: new AbortController() } as unknown as Parameters<ExecVerifier['reverifyAgentScriptProof']>[1]['job'],
    grant: makeLabGrant(origin),
    currentSecrets: () => [],
    findingId: compA.findingId,
    replaySpecId: compA.replaySpecId,
  }, proofRecA)

  assert.ok(reverifyA)
  assert.equal(reverifyA.status, 'inconclusive')
  assert.equal(openSessionCalls, 0, 'integrity mismatch must fail closed before opening worker session')

  const compAAfter = storage.db.select().from(findings).where(eq(findings.id, compA.findingId)).get()!
  assert.equal(compAAfter.finding.status, 'inconclusive')
  const depAAfter = storage.db.select().from(findings).where(eq(findings.id, depA.findingId)).get()!
  assert.equal(depAAfter.supersededByFindingId ?? null, null, 'depA DB column must be restored on integrity mismatch demotion')
  assert.equal(depAAfter.finding.supersededByFindingId ?? null, null, 'depA JSON field must be restored on integrity mismatch demotion')

  // --- Branch B: Legacy Python reverify demotion ---
  const depB = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// dep B single-hop',
    runtime: 'ts',
    proof: makeSingleHopProof({
      origin,
      endpoint: '/v1/invites/claim',
      method: 'POST',
      vulnClass: 'authorization',
      exchangePrefix: 'dep-b',
      claimTitle: 'Upstream invite claim BOLA',
    }),
    secrets: [],
  })

  const compBScript = 'export default async function run() { return { ok: "B" }; }'
  const compB = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: compBScript,
    runtime: 'ts',
    proof: makeCompositeProof({
      chainId: 'chain-restore-legacy',
      terminalVulnClass: 'dual_tenant_abac',
      includeHostTranscript: true,
      hops: [
        { hopId: 'h1', declaredOrigin: origin, declaredMethod: 'POST', declaredPathAndQuery: '/v1/invites/claim', exchangeId: 'rb-h1' },
        { hopId: 'h2', declaredOrigin: origin, declaredMethod: 'POST', declaredPathAndQuery: '/v1/billing/export', exchangeId: 'rb-h2' },
      ],
      claimTitle: 'Composite B superseding dep B',
    }),
    secrets: [],
  })

  const depBBefore = storage.db.select().from(findings).where(eq(findings.id, depB.findingId)).get()!
  assert.equal(depBBefore.supersededByFindingId, compB.findingId)
  assert.equal(depBBefore.finding.supersededByFindingId, compB.findingId)

  // Trigger legacy runtime demotion branch (`proof.runtime !== 'ts'`)
  const proofRecB = storage.replaySpecProof(run.id, compB.replaySpecId)!
  const legacyProofRecB = { ...proofRecB, runtime: 'py' as unknown as 'ts' }
  const reverifyB = await verifier.reverifyAgentScriptProof(run, {
    job: { assignment: worker, controller: new AbortController() } as unknown as Parameters<ExecVerifier['reverifyAgentScriptProof']>[1]['job'],
    grant: makeLabGrant(origin),
    currentSecrets: () => [],
    findingId: compB.findingId,
    replaySpecId: compB.replaySpecId,
  }, legacyProofRecB)

  assert.ok(reverifyB)
  assert.equal(reverifyB.status, 'inconclusive')
  assert.equal(openSessionCalls, 0, 'legacy runtime rejection must fail closed before opening worker session')

  const compBAfter = storage.db.select().from(findings).where(eq(findings.id, compB.findingId)).get()!
  assert.equal(compBAfter.finding.status, 'inconclusive')
  const depBAfter = storage.db.select().from(findings).where(eq(findings.id, depB.findingId)).get()!
  assert.equal(depBAfter.supersededByFindingId ?? null, null, 'depB DB column must be restored on legacy reverify demotion')
  assert.equal(depBAfter.finding.supersededByFindingId ?? null, null, 'depB JSON field must be restored on legacy reverify demotion')
})

// ============================================================================
// 4. R3-H-15: Host-derived signed origin for composite proofs
// ============================================================================

test('R3-H-15: composite declaring terminal origin B while signed terminal exchange hit origin A is rejected (never filed on B), and valid composites bind strictly to signed transcript origin', async (t) => {
  const originA = 'http://127.0.0.1:4631'
  const originB = 'http://127.0.0.1:4632'
  const { storage } = makeStore(t)
  const { runId } = await setupApprovedRun(storage, {
    seeds: [originA, originB],
    environment: 'local-lab',
    tier: 3,
  })
  const run = storage.run(runId)
  const assetA = run.candidates.find(c => c.origin === originA)!
  const assetB = run.candidates.find(c => c.origin === originB)!
  const worker = storage.makeWorker(run, 'investigation', assetA, 'Worker', 'R3-H-15 origin binding')
  const verifier = makeExecVerifier(storage)

  // (a) Spoofed terminal hop: signed terminal exchange hit originA, but hops[terminal].target.origin declares originB!
  const spoofedTerminalProof = makeCompositeProof({
    chainId: 'chain-r3h15-spoofed-terminal',
    terminalVulnClass: 'dual_tenant_abac',
    includeHostTranscript: true,
    hops: [
      {
        hopId: 'h1',
        declaredOrigin: originA,
        declaredMethod: 'GET',
        declaredPathAndQuery: '/v1/tenants/t1/keys',
        signedOrigin: originA,
        exchangeId: 'sp-h1',
      },
      {
        hopId: 'h2',
        declaredOrigin: originB, // <-- spoofed declared origin B!
        declaredMethod: 'POST',
        declaredPathAndQuery: '/v1/payouts/p9/approve',
        signedOrigin: originA,   // <-- actual signed terminal exchange hit origin A!
        exchangeId: 'sp-h2',
      },
    ],
    claimTitle: 'Spoofed cross-origin terminal claim',
  })

  // inspectCompositeHostOrigin must fail closed
  const idx = buildHostRecordedExchangeIndex(spoofedTerminalProof)
  const originCheck = inspectCompositeHostOrigin(spoofedTerminalProof.compositeReceipt!.receipt, idx)
  assert.equal(originCheck.ok, false)
  if (!originCheck.ok) {
    assert.match(originCheck.reason, /disagrees with host-signed terminal exchange/i)
  }

  // extractAgentProofTarget must derive origin strictly from signed terminal exchange (originA), NEVER declared originB
  const dummySpec = verifier.agentProofAttributionSpec({
    origin: originA,
    title: 'Test',
    attribution: {
      label: 'cross-tenant ABAC',
      cwe: 'CWE-639',
      category: 'broken-access-control',
      impact: 'impact',
      remediation: 'remediation',
    },
    severity: 'high',
    envelope: {
      kind: 'agent_script',
      runtime: 'ts',
      script: '// s',
      scriptSha256: createHash('sha256').update('// s').digest('hex'),
      verdict: 'confirmed',
      exchangeIds: ['sp-h2'],
      transcriptDigests: ['d'.repeat(64)],
      confirmedAt: Date.now(),
    },
    proof: spoofedTerminalProof,
    receipt: null,
  })
  const extractedTarget = extractAgentProofTarget({
    cleanCompositeBundle: spoofedTerminalProof.compositeReceipt,
    receipt: null,
    baseSpec: dummySpec,
    proof: spoofedTerminalProof,
  })
  assert.equal(extractedTarget.origin, originA, 'extractAgentProofTarget must return signed terminal exchange origin A, never declared origin B')

  // serializeCompositeProofReceiptRow must fail closed when terminal exchange origin disagrees with declared origin
  assert.throws(
    () => serializeCompositeProofReceiptRow(
      spoofedTerminalProof.compositeReceipt!,
      null,
      idx.get('sp-h2')!,
    ),
    InvariantError,
  )

  // persistAgentScriptProof must fail closed and file ZERO findings on originB (or originA)
  assert.throws(
    () => verifier.persistAgentScriptProof({
      run,
      assignment: worker,
      script: '// spoofed origin script',
      runtime: 'ts',
      proof: spoofedTerminalProof,
      secrets: [],
    }),
    InvariantError,
  )
  assert.equal(
    storage.db.select().from(findings).where(eq(findings.runId, runId)).all().length,
    0,
    'rejected origin-mismatched composite must not persist any finding on origin B',
  )

  // (b) Non-terminal hop origin mismatch must also fail closed
  const spoofedUpstreamProof = makeCompositeProof({
    chainId: 'chain-r3h15-spoofed-upstream',
    terminalVulnClass: 'dual_tenant_abac',
    includeHostTranscript: true,
    hops: [
      {
        hopId: 'h1',
        declaredOrigin: originB, // <-- disagrees with signed originA!
        declaredMethod: 'GET',
        declaredPathAndQuery: '/v1/tenants/t1/keys',
        signedOrigin: originA,
        exchangeId: 'su-h1',
      },
      {
        hopId: 'h2',
        declaredOrigin: originA,
        declaredMethod: 'POST',
        declaredPathAndQuery: '/v1/payouts/p9/approve',
        signedOrigin: originA,
        exchangeId: 'su-h2',
      },
    ],
    claimTitle: 'Spoofed upstream hop origin',
  })
  assert.throws(
    () => verifier.persistAgentScriptProof({
      run,
      assignment: worker,
      script: '// spoofed upstream origin',
      runtime: 'ts',
      proof: spoofedUpstreamProof,
      secrets: [],
    }),
    InvariantError,
  )

  // (c) Valid composite where signed terminal exchange hits originA persists strictly on originA & assetA
  const validProof = makeCompositeProof({
    chainId: 'chain-r3h15-valid-origin-a',
    terminalVulnClass: 'dual_tenant_abac',
    includeHostTranscript: true,
    hops: [
      {
        hopId: 'h1',
        declaredOrigin: originA,
        declaredMethod: 'GET',
        declaredPathAndQuery: '/v1/tenants/t1/keys',
        signedOrigin: originA,
        exchangeId: 'va-h1',
      },
      {
        hopId: 'h2',
        declaredOrigin: originA,
        declaredMethod: 'POST',
        declaredPathAndQuery: '/v1/payouts/p9/approve',
        signedOrigin: originA,
        exchangeId: 'va-h2',
      },
    ],
    claimTitle: 'Valid composite on origin A',
  })
  const persisted = verifier.persistAgentScriptProof({
    run,
    assignment: worker,
    script: '// valid origin A proof',
    runtime: 'ts',
    proof: validProof,
    secrets: [],
  })

  const savedFinding = storage.db.select().from(findings).where(eq(findings.id, persisted.findingId)).get()!
  assert.equal(savedFinding.finding.origin, originA)
  assert.equal(savedFinding.assetId, assetA.id)
  assert.notEqual(savedFinding.assetId, assetB.id)
  assert.deepEqual(savedFinding.sourceOrigins, [originA])

  const expectedFpA = computeFindingFingerprint({
    origin: originA,
    cwe: 'CWE-639',
    category: 'broken-access-control',
    endpoint: '/v1/payouts/p9/approve',
    method: 'POST',
  })
  assert.equal(savedFinding.fingerprintHash, expectedFpA.hash)

  const savedSpec = storage.getReplaySpec(run.id, persisted.replaySpecId)
  const receiptTargetOrigin = (savedSpec.proofReceipt as { receipt?: { target?: { origin?: string } } } | null)?.receipt?.target?.origin
  assert.equal(receiptTargetOrigin, originA, 'persisted receipt target.origin must be signed terminal exchange origin A')
})
