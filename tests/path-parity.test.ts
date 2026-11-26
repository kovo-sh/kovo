/**
 * Wave 2 / Item #4 — Confirmation-Path Parity Corpus & Per-Path Guard Closure.
 *
 * Replays recorded TP/FP host-exchange + claim-envelope transcripts from
 * `tests/parity/corpus/*.json` through ALL live confirmation entry points:
 *   1. `verifyReplaySpec` (strict receipt default, real loopback HTTP + RequestBroker + LocalJqBackend)
 *   2. Floor recipe engine (`receiptCheckForResult` + `runCut3Recipe('injection_fingerprint')`)
 *   3. `evaluateClaims` (`TranscriptStore` + `HostFactLog.fromTranscriptStore`)
 *   4. `verifyCompositeReceipt` (multi-hop composite chains + decoy twins)
 *
 * Enforces label-permutation invariance (`canonical`, `'other'`, `CWE-20`, `CWE-only`,
 * `free-text title`) and pins all closed per-path fail-open seams.
 */
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { once } from 'node:events'
import { readdirSync, readFileSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker, type BrokerExchangeResult, type Grant } from '../src/server/broker.ts'
import { signHostRecord, verifyCompositeReceipt, type CompositeProofReceipt, type HostSignedTranscript, type HostTranscriptEntry } from '../src/server/composite-receipt.ts'
import {
  RECEIPT_EXEMPT_HOST_SPEC_KINDS,
  classifyRetestHealth,
  isReceiptExemptHostSpec,
  receiptCheckForResult,
  retestPersistedRecipe,
} from '../src/server/floor-recipe-engine.ts'
import { cut3FloorRecipe, runCut3Recipe, type FloorRecipeExecution } from '../src/server/floor-recipes.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import { classifyBoundaryClaim, classifyImpactDescriptor, type BoundaryClass, type ImpactClass, type ImpactStep, type InjectionFamily, type RoleName } from '../src/server/oracle-invariants.ts'
import { isPureJobOrHandleStubChain, proofReceiptMode } from '../src/server/proof-receipt.ts'
import { retestPersistedAgentScript, retestReplaySpec, verifyReplaySpec } from '../src/server/replay-verifier.ts'
import { assessDeclarativeRetestHealth, assessRetestHealth, type RetestFailureReason, type RetestHealthAssessment } from '../src/server/retest-health.ts'
import { TranscriptStore, evaluateClaims, type VerifyClaim } from '../src/server/verify-claims.ts'
import { VERIFY_NONCE_HEADER, VERIFY_RPC_CONTEXT_NAME, VERIFY_RPC_HEADER, VERIFY_RPC_SOCKET_NAME, VERIFY_RPC_TOKEN_NAME } from '../src/server/verify-rpc.ts'
import type { VerifyScriptRequest, VerifyScriptResult, WorkerBackend, WorkerSession, WorkerSessionOptions } from '../src/server/worker-backend.ts'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const CORPUS_DIR = join(REPO_ROOT, 'tests', 'parity', 'corpus')
const SIGNING_KEY = 'path-parity-corpus-signing-key-987654321'

interface ParityPersona {
  handle: string
  roleLabel: string
  role: RoleName
  tenant: string
  auth: 'bearer' | 'cookie' | 'header' | 'unknown'
  headerName: string
  headerValue: string
}

interface ParityExchange {
  id: string
  arm: 'control' | 'probe' | 'setup' | 'cleanup'
  role: 'control' | 'probe' | 'setup' | 'cleanup'
  method: string
  pathAndQuery: string
  persona: string | null
  requestJson?: unknown
  requestHeaders?: Record<string, string>
  status: number
  mediaType: string
  responseHeaders: Record<string, string>
  body: string
  executedSentinels?: string[]
}

interface ParityLabel {
  cwe?: string
  category?: string
  title?: string
  impact?: string
  claimedImpact?: ImpactClass
  claimedBoundary?: BoundaryClass
  vulnClass?: string
  injectionFamily?: InjectionFamily
}

interface ParityCase {
  id: string
  side: 'tp' | 'fp' | 'retest'
  archetype: string
  description: string
  canonicalLabel: ParityLabel
  freeTextLabel: { title: string; impact?: string }
  paths: {
    replay: boolean
    floorReceipt: boolean
    evaluateClaims: boolean
    composite: boolean
    floorInjectionRecipe: boolean
    retest?: boolean
  }
  expected: { confirmed: boolean }
  retest?: {
    scenario: 'drifted_session' | 'unbuildable_receipt' | 'composite_stage_rejected' | 'clean_fix'
    expectedVerdict: 'fixed' | 'inconclusive' | 'reproduced'
    expectedFailureReason: RetestFailureReason
    failedStage?: string
  }
  personas: ParityPersona[]
  exchanges: ParityExchange[]
  replaySpec?: {
    assertionsJq: string
    resourceTenant?: string
    requiredRole?: RoleName
    expectedImpactEvents?: string[]
  }
  injectionRecipe?: {
    param: string
    controlValue: string
    payload: string
    family?: InjectionFamily
  }
  claims?: VerifyClaim[]
  bareClaims?: VerifyClaim[]
  composite?: {
    chainId: string
    terminalVulnClass: string
    oracleFamily: string
    capabilityToken: string
    claimedDelta: string
  }
}

type PermutationKind = 'canonical' | 'other' | 'cwe_20' | 'cwe_only' | 'free_text'
const PERMUTATIONS: readonly PermutationKind[] = ['canonical', 'other', 'cwe_20', 'cwe_only', 'free_text']

function loadCorpus(): ParityCase[] {
  const files = readdirSync(CORPUS_DIR).filter(f => f.endsWith('.json')).sort()
  assert.ok(files.length >= 14, `expected >= 14 parity corpus files, found ${files.length}`)
  return files.map(f => JSON.parse(readFileSync(join(CORPUS_DIR, f), 'utf8')) as ParityCase)
}

function permuteLabel(c: ParityCase, perm: PermutationKind): ParityLabel {
  switch (perm) {
    case 'canonical':
      return { ...c.canonicalLabel }
    case 'other':
      return {
        category: 'other',
        title: 'Endpoint verification finding',
        impact: 'Observed response behavior on target route.',
        claimedImpact: 'other',
        claimedBoundary: 'other',
      }
    case 'cwe_20':
      return {
        cwe: 'CWE-20',
        category: 'input-validation',
        title: 'Improper input validation',
        impact: 'Unexpected behavior on supplied input.',
        claimedImpact: 'other',
        claimedBoundary: 'other',
      }
    case 'cwe_only': {
      const cwe = c.canonicalLabel.cwe
      const derivedImpact = classifyImpactDescriptor({ cwe })
      const derivedBoundary = classifyBoundaryClaim({ cwe })
      return {
        ...(cwe ? { cwe } : {}),
        category: 'other',
        title: 'Security finding',
        impact: 'Observed response difference.',
        claimedImpact: derivedImpact,
        claimedBoundary: derivedBoundary,
      }
    }
    case 'free_text': {
      const title = c.freeTextLabel.title
      const impact = c.freeTextLabel.impact ?? title
      return {
        title,
        impact,
        claimedImpact: classifyImpactDescriptor({ title, impact }),
        claimedBoundary: classifyBoundaryClaim({ title, impact }),
      }
    }
  }
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function parseJsonSafe(body: string): unknown {
  try { return JSON.parse(body) } catch { return undefined }
}

function buildGrant(origin: string, personas: readonly ParityPersona[]): Grant {
  return makeLabGrant(origin, {
    tier: 3,
    personas: new Map(personas.map((p, idx) => [p.handle, {
      id: `persona-${idx}-${p.handle}`,
      handle: p.handle,
      roleLabel: p.roleLabel,
      originAllowlist: [origin],
      authKind: p.auth === 'bearer' ? 'bearer' : p.auth === 'cookie' ? 'cookie' : 'header',
      headerName: p.headerName,
      secret: p.headerValue.replace(/^Bearer\s+/i, ''),
      canaryMarkers: [],
    }])),
  })
}

function buildReplaySpec(c: ParityCase, origin: string, label: ParityLabel): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: label.title ?? 'Security finding',
    category: label.category ?? 'other',
    cwe: label.cwe ?? 'CWE-0',
    severity: 'high',
    severityRationale: 'Parity corpus evaluation.',
    impact: label.impact ?? 'Observed behavior.',
    remediation: 'Enforce strict server-side verification.',
    recheckInstructions: 'Re-run parity transcript.',
    assertionsJq: c.replaySpec!.assertionsJq,
    ...(c.replaySpec!.resourceTenant ? { resourceTenant: c.replaySpec!.resourceTenant } : {}),
    ...(c.replaySpec!.requiredRole ? { requiredRole: c.replaySpec!.requiredRole } : {}),
    ...(c.replaySpec!.expectedImpactEvents ? { expectedImpactEvents: c.replaySpec!.expectedImpactEvents } : {}),
    steps: c.exchanges.map(ex => ({
      id: ex.id,
      role: ex.role,
      description: ex.id,
      request: {
        origin,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        ...(ex.persona ? { persona: ex.persona } : {}),
        ...(ex.requestJson !== undefined ? { jsonBody: ex.requestJson } : {}),
        ...(ex.requestHeaders ? { headers: ex.requestHeaders } : {}),
        followRedirects: false,
      },
    })),
  } as unknown as DeclarativeReplaySpec
}

function populateTranscriptStore(c: ParityCase, origin: string): { store: TranscriptStore; idMap: Map<string, string> } {
  const store = new TranscriptStore(Buffer.alloc(32, 7))
  const personaByHandle = new Map(c.personas.map(p => [p.handle, p]))
  const idMap = new Map<string, string>()
  let ts = 1_700_000_000_000
  for (const ex of c.exchanges) {
    ts += 100
    const persona = ex.persona ? personaByHandle.get(ex.persona) : undefined
    const reqHeaders: Record<string, string> = { ...(ex.requestHeaders ?? {}) }
    if (persona) reqHeaders[persona.headerName.toLowerCase()] = persona.headerValue
    const reqBody = ex.requestJson !== undefined ? JSON.stringify(ex.requestJson) : ''
    const rec = store.record({
      op: ex.executedSentinels?.length ? 'browser' : 'http',
      startedAt: ts,
      durationMs: 12,
      request: {
        origin,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        headers: reqHeaders,
        bodyBytes: Buffer.byteLength(reqBody, 'utf8'),
        bodySha256: sha256(reqBody),
        personaHandle: persona?.handle ?? null,
        sessionRole: ex.arm,
        actorRoleLabel: persona?.roleLabel ?? null,
        nonce: 'parity-nonce',
      },
      response: {
        status: ex.status,
        headers: ex.responseHeaders,
        bodyBytes: Buffer.byteLength(ex.body, 'utf8'),
        bodySha256: sha256(ex.body),
        mediaType: ex.mediaType,
      },
      ...(ex.executedSentinels?.length
        ? { artifact: { kind: 'browser', executedSentinels: ex.executedSentinels } }
        : {}),
      rawRequestBody: reqBody || undefined,
      body: ex.body,
    })
    idMap.set(ex.id, rec.exchangeId)
  }
  return { store, idMap }
}

function remapClaimIds(claims: readonly VerifyClaim[], idMap: ReadonlyMap<string, string>): VerifyClaim[] {
  const mapId = (id: string): string => idMap.get(id) ?? id
  return claims.map(claim => {
    switch (claim.kind) {
      case 'status':
      case 'header':
      case 'body_contains':
      case 'jsonpath':
      case 'css':
      case 'dom_sentinel':
      case 'oob':
        return { ...claim, exchangeId: mapId(claim.exchangeId) }
      case 'boundary':
        return { ...claim, controlExchangeId: mapId(claim.controlExchangeId), probeExchangeId: mapId(claim.probeExchangeId) }
      case 'impact':
        return {
          ...claim,
          probeExchangeId: mapId(claim.probeExchangeId),
          ...(claim.beforeExchangeId ? { beforeExchangeId: mapId(claim.beforeExchangeId) } : {}),
          ...(claim.afterExchangeId ? { afterExchangeId: mapId(claim.afterExchangeId) } : {}),
          ...(claim.controlExchangeIds ? { controlExchangeIds: claim.controlExchangeIds.map(mapId) } : {}),
        }
      case 'structural_diff':
        return { ...claim, controlIds: claim.controlIds.map(mapId), variantIds: claim.variantIds.map(mapId) }
      case 'timing':
        return { ...claim, controlIds: claim.controlIds.map(mapId), variantIds: claim.variantIds.map(mapId) }
      case 'race':
      case 'composite_receipt':
        return { ...claim, exchangeIds: claim.exchangeIds.map(mapId) }
      case 'host_evaluated_expression':
        return { ...claim, controlIds: claim.controlIds.map(mapId), probeIds: claim.probeIds.map(mapId) }
      case 'mfa':
        return {
          ...claim,
          enrolledExchangeId: mapId(claim.enrolledExchangeId),
          preChallengeExchangeId: mapId(claim.preChallengeExchangeId),
          postChallengeExchangeId: mapId(claim.postChallengeExchangeId),
          ...(claim.challengeExchangeId ? { challengeExchangeId: mapId(claim.challengeExchangeId) } : {}),
        }
    }
  })
}

function buildCompositeFixture(c: ParityCase, origin: string): {
  receipt: CompositeProofReceipt
  transcript: HostSignedTranscript
  store: TranscriptStore
  claim: VerifyClaim
} {
  const comp = c.composite!
  const personaByHandle = new Map(c.personas.map(p => [p.handle, p]))
  const capHandle = `cap:hop_1:${comp.capabilityToken}`
  const entries: HostTranscriptEntry[] = []
  let ts = 1_700_000_000_000
  for (const ex of c.exchanges) {
    ts += 250
    const p = ex.persona ? personaByHandle.get(ex.persona) : undefined
    const json = parseJsonSafe(ex.body)
    const step: ImpactStep = {
      id: ex.id,
      arm: ex.arm,
      method: ex.method,
      route: ex.pathAndQuery.split('?')[0] ?? '/',
      pathAndQuery: ex.pathAndQuery,
      status: ex.status,
      actor: {
        handle: p?.handle ?? null,
        role: p?.role ?? null,
        tenant: p?.tenant ?? null,
        auth: p?.auth ?? 'unknown',
        sameSite: null,
      },
      ...(json !== undefined ? { json } : {}),
      body: ex.body,
      ...(ex.requestJson !== undefined ? { requestJson: ex.requestJson } : {}),
      requestHeaders: p ? { [p.headerName]: p.headerValue } : null,
      responseHeaders: ex.responseHeaders,
    }
    const extra: Partial<HostTranscriptEntry> = {
      timestampMs: ts,
      actorPersona: p?.handle ?? null,
      cleanSession: true,
      ...(ex.id === 'hop1_ex' ? { emittedCapabilities: [capHandle] } : {}),
      ...(ex.id === 'hop2_prb' ? { consumedCapabilities: [capHandle] } : {}),
    }
    const base: HostTranscriptEntry = { exchangeId: ex.id, step, ...extra }
    entries.push({ ...base, hostSignature: signHostRecord(base, SIGNING_KEY) })
  }
  const hop1 = c.exchanges.find(e => e.id === 'hop1_ex')!
  const hop2 = c.exchanges.find(e => e.id === 'hop2_prb')!
  const receipt: CompositeProofReceipt = {
    chainId: comp.chainId,
    terminalVulnClass: comp.terminalVulnClass,
    hops: [
      {
        hopId: 'hop_1',
        surface: 'http',
        target: { origin, method: hop1.method, pathAndQuery: hop1.pathAndQuery },
        exchangeIds: ['hop1_ex'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Minted cross-tenant export token handle.',
        producedCapabilities: [capHandle],
        consumedCapabilities: [],
      },
      {
        hopId: 'hop_2',
        surface: 'http',
        target: { origin, method: hop2.method, pathAndQuery: hop2.pathAndQuery },
        exchangeIds: ['hop2_ctl', 'hop2_prb'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: comp.claimedDelta,
        producedCapabilities: [],
        consumedCapabilities: [capHandle],
      },
    ],
    causalEdges: [
      {
        fromHopId: 'hop_1',
        toHopId: 'hop_2',
        kind: 'value_binding',
        capabilityHandle: capHandle,
        sourceExchangeId: 'hop1_ex',
        targetExchangeId: 'hop2_prb',
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'hop2_prb',
      claimedImpact: comp.claimedDelta,
      summary: comp.claimedDelta,
      preChainControlExchangeIds: ['hop2_ctl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const transcript: HostSignedTranscript = { entries }
  const { store } = populateTranscriptStore(c, origin)
  const storeEntries = store.list()
  const storeExchangeIds = storeEntries.map(e => e.exchangeId)
  const claim: VerifyClaim = {
    kind: 'composite_receipt',
    chainId: comp.chainId,
    terminalVulnClass: comp.terminalVulnClass,
    exchangeIds: storeExchangeIds,
    terminalExchangeId: storeExchangeIds[2]!,
    compositeReceipt: {
      ...receipt,
      hops: receipt.hops.map((h, i) => ({
        ...h,
        exchangeIds: i === 0 ? [storeExchangeIds[0]!] : [storeExchangeIds[1]!, storeExchangeIds[2]!],
      })),
      causalEdges: receipt.causalEdges.map(edge => ({
        ...edge,
        sourceExchangeId: storeExchangeIds[0]!,
        targetExchangeId: storeExchangeIds[2]!,
      })),
      terminalImpact: {
        ...receipt.terminalImpact,
        terminalExchangeId: storeExchangeIds[2]!,
        preChainControlExchangeIds: [storeExchangeIds[1]!],
      },
    } as unknown as Record<string, unknown>,
  }
  return { receipt, transcript, store, claim }
}

// ============================================================================
// 1. Corpus completeness check
// ============================================================================

test('parity corpus: covers both TP and FP sides including anon-control authz and error-status-only injection', () => {
  const corpus = loadCorpus()
  const tps = corpus.filter(c => c.side === 'tp')
  const fps = corpus.filter(c => c.side === 'fp')
  assert.ok(tps.length >= 5, `expected >= 5 TP corpus cases, got ${tps.length}`)
  assert.ok(fps.length >= 8, `expected >= 8 FP corpus cases, got ${fps.length}`)
  const archetypes = new Set(corpus.map(c => c.archetype))
  assert.ok(archetypes.has('anon-control-authz'), 'missing anon-control-authz archetype')
  assert.ok(archetypes.has('error-status-only-injection'), 'missing error-status-only-injection archetype')
  assert.ok(archetypes.has('cross-tenant-bola'), 'missing cross-tenant-bola archetype')
  assert.ok(archetypes.has('bfla-vertical'), 'missing bfla-vertical archetype')
  assert.ok(archetypes.has('sqli-echoed-error'), 'missing sqli-echoed-error archetype')
  assert.ok(archetypes.has('xss-json-escaped-echo'), 'missing xss-json-escaped-echo archetype')
  assert.ok(archetypes.has('job-handle-stub'), 'missing job-handle-stub archetype')
  assert.ok(archetypes.has('composite-multihop-cross-tenant'), 'missing composite-multihop archetype')
  assert.ok(archetypes.has('composite-stub-decoy'), 'missing composite-stub-decoy archetype')
})

// ============================================================================
// 2. Entry point 1: verifyReplaySpec (strict receipt default) + label permutations
// ============================================================================

test('path parity [verifyReplaySpec]: enforces TP/FP verdicts and fail-closed label permutation invariance', async (t) => {
  const corpus = loadCorpus().filter(c => c.paths.replay)
  assert.ok(corpus.length >= 10)

  let activeCase: ParityCase | null = null
  let stepCursor = 0
  const server = createServer((req, res) => {
    req.resume()
    if (!activeCase) {
      res.statusCode = 500
      res.end('{}')
      return
    }
    const ex = activeCase.exchanges[stepCursor]
    stepCursor += 1
    if (!ex) {
      res.statusCode = 404
      res.end('{}')
      return
    }
    res.statusCode = ex.status
    for (const [k, v] of Object.entries(ex.responseHeaders)) res.setHeader(k, v)
    res.end(ex.body)
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const origin = `http://127.0.0.1:${port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })

  const backend = new LocalJqBackend()
  for (const c of corpus) {
    const grant = buildGrant(origin, c.personas)
    for (const perm of PERMUTATIONS) {
      activeCase = c
      stepCursor = 0
      const label = permuteLabel(c, perm)
      const spec = buildReplaySpec(c, origin, label)
      const res = await verifyReplaySpec({
        spec,
        broker: new RequestBroker({ rejectUnauthorized: false }),
        backend,
        grant,
        signal: AbortSignal.timeout(15_000),
      })
      if (c.side === 'fp') {
        assert.notEqual(
          res.verdict,
          'confirmed',
          `FP case ${c.id} MUST NOT confirm in verifyReplaySpec under permutation "${perm}" (reason=${res.outcome.reason ?? 'none'})`,
        )
        // Pin the closed replay-verifier.ts:508 gap: error-status-only-injection must fail proofStrength even under 'other'/'cwe_20'!
        if (c.id === 'error-status-only-injection-fp') {
          const ps = res.evidencePayload.proofStrength as { satisfied?: boolean } | undefined
          assert.equal(ps?.satisfied, false, `proofStrength must reject error-status-only under "${perm}"`)
        }
      } else if (perm === 'canonical') {
        assert.equal(
          res.verdict,
          'confirmed',
          `TP case ${c.id} must confirm in verifyReplaySpec under canonical label (got ${res.verdict}: ${res.outcome.reason ?? 'none'})`,
        )
        assert.equal(res.receipt?.mode, 'strict')
        assert.equal(res.receipt?.verification.confirmed, true)
      } else if (perm === 'other' || perm === 'cwe_20') {
        // R2-H-14: unmodelled 'other' / CWE-20 MUST fail closed in strict receipt mode, never silently confirm.
        assert.notEqual(
          res.verdict,
          'confirmed',
          `R2-H-14: unmodelled permutation "${perm}" on ${c.id} must fail closed in strict verifyReplaySpec`,
        )
      }
    }
  }
})

// ============================================================================
// 3. Entry point 2: Floor recipe engine (receiptCheckForResult + injection_fingerprint)
// ============================================================================

test('path parity [floor-recipe-engine]: receiptCheckForResult + injection_fingerprint enforce strict parity and echo stripping', async () => {
  const origin = 'http://127.0.0.1:4100'
  const corpus = loadCorpus()

  for (const c of corpus.filter(x => x.paths.floorReceipt)) {
    const personaByHandle = new Map(c.personas.map(p => [p.handle, p]))
    const stepsOut: Record<string, unknown> = {}
    const exchanges: BrokerExchangeResult[] = []
    const exchangeIds: string[] = []
    for (const [idx, ex] of c.exchanges.entries()) {
      const exId = `floor-ex-${idx}`
      const p = ex.persona ? personaByHandle.get(ex.persona) : undefined
      const json = parseJsonSafe(ex.body)
      stepsOut[ex.id] = {
        id: ex.id,
        role: ex.role,
        status: ex.status,
        body: ex.body,
        ...(json !== undefined ? { json } : {}),
        mediaType: ex.mediaType,
        responseHeaders: ex.responseHeaders,
        requestHeaders: p ? { [p.headerName]: p.headerValue } : {},
        ...(ex.requestJson !== undefined ? { requestBody: JSON.stringify(ex.requestJson) } : {}),
        ...(p ? { personaHandle: p.handle, actorRole: p.role, actorTenant: p.tenant, ambientAuth: p.auth } : {}),
        exchangeId: exId,
        durationMs: 10,
      }
      exchanges.push({
        exchangeId: exId,
        origin,
        method: ex.method,
        pathAndQuery: ex.pathAndQuery,
        status: ex.status,
        headers: ex.responseHeaders,
        body: ex.body,
        bodyBytes: Buffer.byteLength(ex.body, 'utf8'),
        bodySha256: sha256(ex.body),
        mediaType: ex.mediaType,
        durationMs: 10,
        redirectChain: [],
        secretMatches: [],
      } as unknown as BrokerExchangeResult)
      exchangeIds.push(exId)
    }

    for (const perm of PERMUTATIONS) {
      const label = permuteLabel(c, perm)
      const spec = buildReplaySpec(c, origin, label)
      const checked = receiptCheckForResult({
        mode: 'strict',
        verdict: 'confirmed',
        outcome: { confirmed: true, controlPassed: true, observed: 'ok', expected: 'blocked' },
        spec,
        evidencePayload: {
          steps: stepsOut,
          impactGate: { required: true, satisfied: true },
        },
        exchangeIds,
        exchanges,
      })
      if (c.side === 'fp') {
        assert.notEqual(
          checked.verdict,
          'confirmed',
          `FP case ${c.id} MUST NOT confirm in receiptCheckForResult under "${perm}"`,
        )
      } else if (perm === 'canonical') {
        assert.equal(
          checked.verdict,
          'confirmed',
          `TP case ${c.id} must confirm in receiptCheckForResult under canonical label (reason=${checked.outcome.reason ?? 'none'})`,
        )
      } else if (perm === 'other' || perm === 'cwe_20') {
        assert.notEqual(checked.verdict, 'confirmed', `unmodelled "${perm}" on ${c.id} must fail closed in receiptCheckForResult`)
      }
    }
  }

  // Floor `injection_fingerprint` recipe path: real fingerprint confirms; status-only, echoed-error, and cross-family mismatch reject!
  for (const c of corpus.filter(x => x.paths.floorInjectionRecipe && x.injectionRecipe)) {
    const ir = c.injectionRecipe!
    const ctlEx = c.exchanges.find(e => e.arm === 'control')!
    const prbEx = c.exchanges.find(e => e.arm === 'probe')!
    const exec = await runCut3Recipe(
      cut3FloorRecipe('injection_fingerprint', {
        origin,
        method: ctlEx.method,
        pathAndQuery: ctlEx.pathAndQuery,
        vulnClass: c.canonicalLabel.vulnClass ?? 'sqli',
        param: ir.param,
        controlValue: ir.controlValue,
        payload: ir.payload,
        ...(ir.family ? { family: ir.family } : {}),
        actor: { handle: 'anonymous' },
      }),
      {
        request: (req) => {
          const ex = req.arm === 'control' ? ctlEx : prbEx
          return {
            status: ex.status,
            body: ex.body,
            json: parseJsonSafe(ex.body),
            responseHeaders: ex.responseHeaders,
          }
        },
      },
    )
    assert.equal(
      exec.result.confirmed,
      c.expected.confirmed,
      `floor injection_fingerprint recipe mismatch for ${c.id}: expected ${c.expected.confirmed}, got ${exec.result.confirmed} (${exec.result.verification.reason})`,
    )
  }

  // Cross-family mismatch in floor injection_fingerprint recipe (declared sqli, response carries shell error)
  const crossFamily = await runCut3Recipe(
    cut3FloorRecipe('injection_fingerprint', {
      origin,
      method: 'GET',
      pathAndQuery: '/api/search?q=books',
      vulnClass: 'sqli',
      param: 'q',
      controlValue: 'books',
      payload: 'books;',
      actor: { handle: 'anonymous' },
    }),
    {
      request: (req) => req.arm === 'control'
        ? { status: 200, body: '{"items":[]}', json: { items: [] } }
        : { status: 500, body: '{"error":"sh: 1: kovo_cmd: not found"}', json: { error: 'sh: 1: kovo_cmd: not found' } },
    },
  )
  assert.equal(crossFamily.result.confirmed, false, 'sqli recipe must reject unrelated cmdi fingerprint via family binding')
})

// ============================================================================
// 4. Entry point 3: evaluateClaims + label permutation invariance
// ============================================================================

test('path parity [evaluateClaims]: enforces identical TP/FP verdicts across all 5 label permutations', () => {
  const origin = 'http://127.0.0.1:4200'
  const corpus = loadCorpus().filter(c => c.paths.evaluateClaims && !c.paths.composite)
  assert.ok(corpus.length >= 10)

  for (const c of corpus) {
    const { store, idMap } = populateTranscriptStore(c, origin)
    const factLog = HostFactLog.fromTranscriptStore(store)
    const allowedExchangeIds = new Set(store.list().map(r => r.exchangeId))
    const claimSets: Array<{ label: string; claims: VerifyClaim[] }> = []
    if (c.claims?.length) claimSets.push({ label: 'structured', claims: remapClaimIds(c.claims, idMap) })
    if (c.bareClaims?.length) claimSets.push({ label: 'bare', claims: remapClaimIds(c.bareClaims, idMap) })

    for (const { label: setName, claims } of claimSets) {
      const verdicts = new Map<PermutationKind, boolean>()
      for (const perm of PERMUTATIONS) {
        const lbl = permuteLabel(c, perm)
        const res = evaluateClaims(store, claims, {
          factLog,
          allowedExchangeIds,
          claimedImpact: lbl.claimedImpact,
          claimedBoundary: lbl.claimedBoundary,
          cwe: lbl.cwe ?? null,
          category: lbl.category ?? null,
          title: lbl.title ?? null,
          description: lbl.impact ?? null,
          ...(lbl.injectionFamily ? { injectionFamily: lbl.injectionFamily } : {}),
        })
        verdicts.set(perm, res.passed)
        if (c.side === 'fp') {
          assert.equal(
            res.passed,
            false,
            `FP case ${c.id} (${setName}) MUST FAIL evaluateClaims under permutation "${perm}"`,
          )
        } else if (setName === 'structured') {
          assert.equal(
            res.passed,
            true,
            `TP case ${c.id} (${setName}) MUST PASS evaluateClaims under permutation "${perm}" (failures: ${res.failures.join('; ')})`,
          )
        }
      }
      // Every permutation must agree on the verdict for FP cases and structured TP cases!
      if (c.side === 'fp' || setName === 'structured') {
        const distinct = new Set(verdicts.values())
        assert.equal(distinct.size, 1, `label permutation drift on ${c.id} (${setName}): ${JSON.stringify([...verdicts.entries()])}`)
      }
    }
  }
})

// ============================================================================
// 5. Entry point 4: verifyCompositeReceipt + evaluateClaims(composite_receipt)
// ============================================================================

test('path parity [verifyCompositeReceipt]: multi-hop TP confirms and stub decoy FP fails closed across permutations', () => {
  const origin = 'http://127.0.0.1:4300'
  const corpus = loadCorpus().filter(c => c.paths.composite)
  assert.ok(corpus.length >= 2)

  for (const c of corpus) {
    const { receipt, transcript, store, claim } = buildCompositeFixture(c, origin)
    const compRes = verifyCompositeReceipt(receipt, transcript, { signingKey: SIGNING_KEY })
    assert.equal(
      compRes.confirmed,
      c.expected.confirmed,
      `verifyCompositeReceipt mismatch for ${c.id}: expected ${c.expected.confirmed}, got ${compRes.confirmed} (${compRes.reason})`,
    )
    // Also verify label permutations on evaluateClaims(composite_receipt) reject decoy FP uniformly
    if (c.side === 'fp') {
      const factLog = HostFactLog.fromTranscriptStore(store)
      for (const perm of PERMUTATIONS) {
        const lbl = permuteLabel(c, perm)
        const ev = evaluateClaims(store, [claim], {
          factLog,
          claimedImpact: lbl.claimedImpact,
          claimedBoundary: lbl.claimedBoundary,
          cwe: lbl.cwe ?? null,
          title: lbl.title ?? null,
        })
        assert.equal(ev.passed, false, `composite decoy FP ${c.id} must fail evaluateClaims under "${perm}"`)
      }
    }
  }
})

// ============================================================================
// 6. Direct regression guards for closed per-path fail-open seams
// ============================================================================

test('proofReceiptMode: rejects off/shadow outside NODE_ENV=test and defaults strictly to strict', () => {
  assert.equal(proofReceiptMode({} as NodeJS.ProcessEnv), 'strict')
  assert.equal(proofReceiptMode({ KOVO_PROOF_RECEIPT: 'strict' } as NodeJS.ProcessEnv), 'strict')
  assert.equal(proofReceiptMode({ KOVO_PROOF_RECEIPT: '1' } as NodeJS.ProcessEnv), 'strict')
  assert.equal(proofReceiptMode({ NODE_ENV: 'production' } as NodeJS.ProcessEnv), 'strict')

  for (const badVal of ['off', '0', 'false', 'no', 'shadow', 'advisory']) {
    assert.throws(
      () => proofReceiptMode({ KOVO_PROOF_RECEIPT: badVal } as NodeJS.ProcessEnv),
      /rejected outside NODE_ENV=test/i,
      `KOVO_PROOF_RECEIPT=${badVal} must throw when NODE_ENV is unset`,
    )
    assert.throws(
      () => proofReceiptMode({ NODE_ENV: 'production', KOVO_PROOF_RECEIPT: badVal } as NodeJS.ProcessEnv),
      /rejected outside NODE_ENV=test/i,
      `KOVO_PROOF_RECEIPT=${badVal} must throw under NODE_ENV=production`,
    )
    assert.throws(
      () => proofReceiptMode({ NODE_ENV: 'development', KOVO_PROOF_RECEIPT: badVal } as NodeJS.ProcessEnv),
      /rejected outside NODE_ENV=test/i,
      `KOVO_PROOF_RECEIPT=${badVal} must throw under NODE_ENV=development`,
    )
  }

  // Allowed ONLY when NODE_ENV === 'test'
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'off' } as NodeJS.ProcessEnv), 'off')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: '0' } as NodeJS.ProcessEnv), 'off')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'shadow' } as NodeJS.ProcessEnv), 'shadow')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'advisory' } as NodeJS.ProcessEnv), 'shadow')
  assert.equal(proofReceiptMode({ NODE_ENV: 'test', KOVO_PROOF_RECEIPT: 'strict' } as NodeJS.ProcessEnv), 'strict')
})

test('receipt-exempt host spec kinds: explicit allowlist only for host_persisted envelopes, never untrusted', () => {
  assert.deepEqual(
    [...RECEIPT_EXEMPT_HOST_SPEC_KINDS].sort(),
    ['auth_protocol_proof', 'cache_differential', 'upload_probe', 'ws_chain'],
  )
  for (const kind of RECEIPT_EXEMPT_HOST_SPEC_KINDS) {
    assert.equal(isReceiptExemptHostSpec({ kind }, 'host_persisted'), true)
    assert.equal(isReceiptExemptHostSpec({ kind }, 'untrusted'), false)
    assert.equal(isReceiptExemptHostSpec({ kind }, undefined), false)
  }
  for (const nonExempt of ['http_chain', 'static_ast_proof', 'dns_takeover', 'sql_boolean_diff', 'sql_time_diff', 'browser_chain', 'race_burst', 'rce_proof'] as const) {
    assert.equal(isReceiptExemptHostSpec({ kind: nonExempt }, 'host_persisted'), false)
    assert.equal(isReceiptExemptHostSpec({ kind: nonExempt }, 'untrusted'), false)
  }
})

test('isPureJobOrHandleStubChain: rejects pure job/handle stubs while preserving persisted mutation + substantive readback', () => {
  const actor = { handle: 'member_a', role: 'member' as const, tenant: 'tenant-a', auth: 'bearer' as const, sameSite: null }
  const stubOnly: ImpactStep[] = [
    { id: 'c', arm: 'control', method: 'POST', route: '/v1/exports', status: 403, actor, json: { error: 'forbidden' }, body: '{"error":"forbidden"}' },
    { id: 'p', arm: 'probe', method: 'POST', route: '/v1/exports', status: 202, actor, json: { jobId: 'job_1', status: 'queued' }, body: '{"jobId":"job_1","status":"queued"}' },
    { id: 'poll', arm: 'control', method: 'GET', route: '/v1/exports/job_1', status: 200, actor, json: { job: { id: 'job_1', status: 'ready', artifactKey: 'org_b/a.csv' } }, body: '{"job":{"id":"job_1","status":"ready","artifactKey":"org_b/a.csv"}}' },
  ]
  assert.equal(isPureJobOrHandleStubChain(stubOnly), true)

  const persistedWithAck: ImpactStep[] = [
    { id: 'b', arm: 'control', method: 'GET', route: '/api/invoices/42', status: 200, actor, json: { id: '42', owner_id: 'u1', status: 'open', amount: 1500 }, body: '{"id":"42","owner_id":"u1","status":"open","amount":1500}' },
    { id: 'p', arm: 'probe', method: 'PATCH', route: '/api/invoices/42', status: 200, actor, json: { ok: true }, body: '{"ok":true}' },
    { id: 'a', arm: 'control', method: 'GET', route: '/api/invoices/42', status: 200, actor, json: { id: '42', owner_id: 'u2', status: 'open', amount: 1500 }, body: '{"id":"42","owner_id":"u2","status":"open","amount":1500}' },
  ]
  assert.equal(isPureJobOrHandleStubChain(persistedWithAck), false)
})

test('static hygiene guards: LOC caps, single impactGate veto, unconditional proofStrength, and zero unstripped matchInjectionFingerprint', () => {
  const replayVerifier = readFileSync(join(REPO_ROOT, 'src/server/replay-verifier.ts'), 'utf8')
  const verifyClaims = readFileSync(join(REPO_ROOT, 'src/server/verify-claims.ts'), 'utf8')
  const floorRecipes = readFileSync(join(REPO_ROOT, 'src/server/floor-recipes.ts'), 'utf8')

  const replayLines = replayVerifier.split('\n').length
  const verifyClaimsLines = verifyClaims.split('\n').length
  assert.ok(replayLines <= 1000, `replay-verifier.ts must stay <= 1000 LOC (got ${replayLines})`)
  assert.ok(verifyClaimsLines <= 2300, `verify-claims.ts must stay <= 2300 LOC (got ${verifyClaimsLines})`)

  assert.doesNotMatch(replayVerifier, /proofStrength\.claim\s*===\s*['"]authorization['"]/, 'proofStrength must be enforced for every claim class')
  const impactGateVetos = replayVerifier.match(/impactGate\?\.required\s*&&\s*!impactGate\.satisfied\s*&&\s*!proofGuardFailure/g) ?? []
  assert.equal(impactGateVetos.length, 1, `expected exactly 1 impactGate veto in replay-verifier.ts, found ${impactGateVetos.length}`)

  assert.doesNotMatch(verifyClaims, /\bmatchInjectionFingerprint\s*\(/, 'verify-claims.ts must route all fingerprint matches through matchStrippedInjectionFingerprint')
  assert.doesNotMatch(floorRecipes, /\bmatchInjectionFingerprint\s*\(/, 'floor-recipes.ts must route all fingerprint matches through matchStrippedInjectionFingerprint')
})

// ============================================================================
// 7. R2-04: Three-Engine Retest Parity Corpus (floor, declarative, agent-script)
// ============================================================================

async function parityRpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: Record<string, unknown>; error?: string }> {
  const body = JSON.stringify({ op, args })
  return await new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest(
      {
        socketPath,
        path: '/rpc',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          [VERIFY_RPC_HEADER]: token,
          [VERIFY_NONCE_HEADER]: nonce,
        },
      },
      res => {
        let data = ''
        res.setEncoding('utf8')
        res.on('data', chunk => { data += chunk })
        res.on('end', () => {
          try { resolvePromise(JSON.parse(data) as { ok: boolean; result?: Record<string, unknown>; error?: string }) }
          catch (err) { rejectPromise(err) }
        })
      },
    )
    req.on('error', rejectPromise)
    req.end(body)
  })
}

function makeRetestScriptBackend(
  c: ParityCase,
  origin: string,
): WorkerBackend {
  return {
    async run() { throw new Error('run() unsupported in parity fake backend') },
    async verifyStaticAst() { throw new Error('verifyStaticAst() unsupported in parity fake backend') },
    async openSession(_id: string, _signal: AbortSignal, opts?: WorkerSessionOptions): Promise<WorkerSession> {
      const rpcDir = opts?.rpcMountDir ?? ''
      return {
        async stage() { throw new Error('unused') },
        async exec() { throw new Error('unused') },
        async analyze() { throw new Error('unused') },
        async sast() { throw new Error('unused') },
        async runScript() { throw new Error('unused') },
        async verifyStaticAst() { throw new Error('unused') },
        async verifyScript(req: VerifyScriptRequest): Promise<VerifyScriptResult> {
          const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
          const token = readFileSync(join(rpcDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim()
          const context = JSON.parse(readFileSync(join(rpcDir, VERIFY_RPC_CONTEXT_NAME), 'utf8')) as { nonce: string }
          const rpc = (op: string, args: Record<string, unknown>) => parityRpcCall(socketPath, token, context.nonce, op, args)

          const exIdByStep = new Map<string, string>()
          for (const ex of c.exchanges) {
            const resp = await rpc('http', {
              origin,
              method: ex.method,
              path: ex.pathAndQuery,
              ...(ex.persona ? { persona: ex.persona } : {}),
              sessionGroupRole: ex.arm,
              ...(ex.requestJson !== undefined ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify(ex.requestJson) } : {}),
            })
            assert.equal(resp.ok, true, `RPC failed for ${c.id}/${ex.id}: ${resp.error ?? 'unknown'}`)
            exIdByStep.set(ex.id, String(resp.result!.exchangeId))
          }

          if (c.retest?.scenario === 'composite_stage_rejected' && c.composite) {
            const hop1Id = exIdByStep.get('hop1_ex')!
            const hop2CtlId = exIdByStep.get('hop2_ctl')!
            const hop2PrbId = exIdByStep.get('hop2_prb')!
            const sealed = await rpc('capability.seal', {
              exchangeId: hop1Id,
              hopReceiptId: 'hop_1',
              slot: 'downloadToken',
              jsonPath: 'downloadToken',
              kind: 'token',
              allowedOrigins: [origin],
            })
            const capHandle = String(sealed.result!.handle)
            // Deliberately fail edge_binding: hop_2 declares consumedCapabilities=[capHandle] while hop2_prb never used it.
            const compositeReceipt = {
              chainId: c.composite.chainId,
              terminalVulnClass: c.composite.terminalVulnClass,
              replayMode: 'fresh_clean_replay',
              hops: [
                { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/v1/exports/request' }, exchangeIds: [hop1Id], producedCapabilities: [capHandle], claimedDelta: 'Minted token.' },
                { hopId: 'hop_2', surface: 'http', target: { origin, method: 'GET', pathAndQuery: '/v1/exports/download?token=unrelated_tok' }, exchangeIds: [hop2CtlId, hop2PrbId], consumedCapabilities: [capHandle], claimedDelta: c.composite.claimedDelta },
              ],
              causalEdges: [
                { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: capHandle, sourceExchangeId: hop1Id, targetExchangeId: hop2PrbId },
              ],
              terminalImpact: {
                terminalHopId: 'hop_2',
                terminalExchangeId: hop2PrbId,
                summary: c.composite.claimedDelta,
                preChainControlExchangeIds: [hop2CtlId],
              },
            }
            const verified = await rpc('composite.verify', { receipt: compositeReceipt })
            const verObj = verified.result as { confirmed?: boolean; verificationId?: string }
            return {
              runtime: req.runtime,
              exitCode: 0,
              result: {
                sdk: 'kovo_verify.ts',
                nonce: context.nonce,
                title: c.canonicalLabel.title ?? c.id,
                claims: verObj.verificationId ? [{ kind: 'composite_receipt', verificationId: verObj.verificationId, chainId: c.composite.chainId, terminalVulnClass: c.composite.terminalVulnClass, exchangeIds: [hop1Id, hop2CtlId, hop2PrbId] }] : [],
              },
              stdout: '',
              stderr: '',
              durationMs: 10,
              timedOut: false,
            }
          }

          const mappedClaims = remapClaimIds(c.claims ?? [], exIdByStep)
          return {
            runtime: req.runtime,
            exitCode: 0,
            result: {
              nonce: context.nonce,
              title: c.canonicalLabel.title ?? c.id,
              severity: 'high',
              description: c.description,
              claims: mappedClaims,
            },
            stdout: '',
            stderr: '',
            durationMs: 10,
            timedOut: false,
          }
        },
        async close() {},
      }
    },
  }
}

test('R2-04 retest parity [floor + declarative + agent-script]: drifted session, unbuildable receipt, and composite stage rejection ALWAYS return inconclusive; genuine clean fix returns fixed', async (t) => {
  const retestCases = loadCorpus().filter(c => c.paths.retest && c.retest)
  assert.ok(retestCases.length >= 4, `expected >= 4 retest corpus cases, found ${retestCases.length}`)
  const scenarios = new Set(retestCases.map(c => c.retest!.scenario))
  assert.ok(scenarios.has('drifted_session'), 'missing drifted_session retest corpus case')
  assert.ok(scenarios.has('unbuildable_receipt'), 'missing unbuildable_receipt retest corpus case')
  assert.ok(scenarios.has('composite_stage_rejected'), 'missing composite_stage_rejected retest corpus case')
  assert.ok(scenarios.has('clean_fix'), 'missing clean_fix retest corpus case')

  let activeCase: ParityCase | null = null
  let stepCursor = 0
  const server = createServer((req, res) => {
    req.resume()
    if (!activeCase) {
      res.statusCode = 500
      res.end('{}')
      return
    }
    const ex = activeCase.exchanges[stepCursor % activeCase.exchanges.length]!
    stepCursor += 1
    res.statusCode = ex.status
    for (const [k, v] of Object.entries(ex.responseHeaders)) res.setHeader(k, v)
    res.end(ex.body)
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const origin = `http://127.0.0.1:${port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })

  const jqBackend = new LocalJqBackend()
  const broker = new RequestBroker({ rejectUnauthorized: false })

  for (const c of retestCases) {
    const rt = c.retest!
    const grant = buildGrant(origin, c.personas)

    // --- Engine 1: Floor recipe engine (retestPersistedRecipe / classifyRetestHealth) ---
    if (rt.scenario === 'drifted_session' || rt.scenario === 'clean_fix') {
      activeCase = c
      stepCursor = 0
      const floorRes = await retestPersistedRecipe({
        envelope: {
          recipeId: 'access_boundary',
          args: {
            origin,
            method: 'GET',
            pathAndQuery: '/api/invoices/inv_victim_9',
            vulnClass: 'bola',
            owner: { handle: 'owner_a', role: 'owner', tenant: 'tenant-a' },
            denied: { handle: 'viewer_b', role: 'viewer', tenant: 'tenant-b' },
            probe: { handle: 'member_b', role: 'member', tenant: 'tenant-b' },
          },
        },
        specKind: 'http_chain',
        vulnClass: 'bola',
        endpoint: '/api/invoices/inv_victim_9',
        origin,
        broker,
        grant,
        signal: AbortSignal.timeout(10_000),
      })
      assert.equal(floorRes.verdict, rt.expectedVerdict, `floor verdict mismatch on ${c.id}: ${floorRes.replay.outcome.reason ?? ''}`)
      const floorHealth = floorRes.replay.evidencePayload.retestHealth as RetestHealthAssessment
      assert.equal(floorHealth.failureReason, rt.expectedFailureReason, `floor failureReason mismatch on ${c.id}`)
      assert.equal(floorHealth.healthy, rt.expectedVerdict === 'fixed')
    } else if (rt.scenario === 'unbuildable_receipt') {
      const unbuildableExec = {
        result: {
          recipeId: 'persisted_mutation',
          confirmed: false,
          steps: c.exchanges.map((ex, i) => ({
            exchangeId: `floor-ex-${i}`,
            role: ex.role,
            arm: ex.arm,
            method: ex.method,
            pathAndQuery: ex.pathAndQuery,
            status: ex.status,
            durationMs: 5,
          })),
          exchangeIds: ['floor-ex-0', 'floor-ex-1'],
          oobEventIds: [],
          transcript: { entries: [] },
          verification: { confirmed: false, vulnClass: 'other', rule: 'none', reason: 'ProofReceipt could not be built.', observed: '', expected: '' },
        },
        receipt: { vulnClass: 'other', target: { origin, method: 'POST', pathAndQuery: '/api/inbox/alert-1/read' }, exchangeIds: [], oobEventIds: [], browserTraceIds: [], claimedDelta: '' },
        failure: { code: 'recipe_error', message: 'ProofReceipt could not be built from mutating boundary without readback.', missingRoles: ['verified_proof_receipt'] },
      } as unknown as FloorRecipeExecution
      const floorHealth = classifyRetestHealth(unbuildableExec)
      assert.equal(floorHealth.healthy, false, `floor must mark ${c.id} unhealthy`)
      assert.equal(floorHealth.failureReason, 'receipt_unbuildable')
    } else if (rt.scenario === 'composite_stage_rejected') {
      const compHealth = assessRetestHealth(
        { controlArms: [{ role: 'hop2_ctl', status: 403, authenticated: true, allowDenied: true }] },
        { arms: [{ role: 'hop2_prb', status: 403, authenticated: true }] },
        { compositeRejectedStage: rt.failedStage ?? 'edge_binding', failureDetail: 'Composite edge_binding stage rejected.' },
      )
      assert.equal(compHealth.healthy, false, `floor/shared assessor must mark ${c.id} unhealthy`)
      assert.equal(compHealth.failureReason, 'composite_stage_rejected')
    }

    // --- Engine 2: Declarative replay engine (retestReplaySpec) ---
    activeCase = c
    stepCursor = 0
    const declSpec = buildReplaySpec(c, origin, c.canonicalLabel)
    if (rt.scenario === 'composite_stage_rejected') {
      const declReplay = await verifyReplaySpec({ spec: declSpec, broker, backend: jqBackend, grant, signal: AbortSignal.timeout(10_000) })
      const declHealth = assessDeclarativeRetestHealth(declSpec, {
        ...declReplay,
        evidencePayload: {
          ...declReplay.evidencePayload,
          compositeVerification: { confirmed: false, failedStage: rt.failedStage ?? 'edge_binding', reason: 'Edge hop_1 -> hop_2 missing consumed capability attestation.' },
        },
      }, { receiptBuildable: true })
      assert.equal(declHealth.healthy, false, `declarative health must reject ${c.id}`)
      assert.equal(declHealth.failureReason, 'composite_stage_rejected')
    } else {
      const declRetest = await retestReplaySpec({
        spec: declSpec,
        broker,
        backend: jqBackend,
        grant,
        signal: AbortSignal.timeout(10_000),
      })
      assert.equal(declRetest.verdict, rt.expectedVerdict, `declarative verdict mismatch on ${c.id}: ${declRetest.replay.outcome.reason ?? ''}`)
      const declHealth = declRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment
      assert.equal(declHealth.failureReason, rt.expectedFailureReason, `declarative failureReason mismatch on ${c.id}`)
      assert.equal(declHealth.healthy, rt.expectedVerdict === 'fixed')
    }

    // --- Engine 3: Agent-script engine (retestPersistedAgentScript) ---
    activeCase = c
    stepCursor = 0
    const scriptText = `// parity retest script for ${c.id}\nexport default async () => ({ ok: true })\n`
    const envelope = {
      kind: 'agent_script' as const,
      runtime: 'ts' as const,
      script: scriptText,
      scriptSha256: sha256(scriptText),
      verdict: 'confirmed' as const,
      exchangeIds: ['ex-orig'],
      vulnClass: c.canonicalLabel.vulnClass ?? 'bola',
      transcriptDigests: [],
      confirmedAt: Date.now(),
    }
    const scriptBackend = makeRetestScriptBackend(c, origin)
    const agentRetest = await retestPersistedAgentScript(envelope, {
      spec: { origin, agentScript: envelope },
      origin,
      broker,
      grant,
      backend: scriptBackend,
      runId: `parity-${c.id}`,
      assignmentId: `assign-${c.id}`,
      signal: AbortSignal.timeout(15_000),
    })
    assert.equal(agentRetest.verdict, rt.expectedVerdict, `agent-script verdict mismatch on ${c.id}: ${agentRetest.replay.outcome.reason ?? ''}`)
    const agentHealth = agentRetest.replay.evidencePayload.retestHealth as RetestHealthAssessment
    assert.equal(agentHealth.failureReason, rt.expectedFailureReason, `agent-script failureReason mismatch on ${c.id}`)
    assert.equal(agentHealth.healthy, rt.expectedVerdict === 'fixed')
  }
})
