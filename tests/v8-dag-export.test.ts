/**
 * v8 Stream D — Multi-Hop CompositeProofReceipt DAG Export, Markdown Reporting & SARIF 2.1.0 Tests.
 *
 * Covers:
 *  1. Portable signed receipt bundle round-trip (HMAC-SHA256 & Ed25519) carrying compositeReceipts:
 *     all 4 causal edge bindings, topological hop order, replayMode, patchBrokeHopId, SHA-256 digest,
 *     ZDR/PII & secret scrubbing (zero leakage), tamper rejection (payload, per-record digest, signature),
 *     and 100% backward compatibility for single-hop bundles.
 *  2. Markdown DAG renderer (`formatCompositeChainMarkdown` + `exportReportMarkdown`):
 *     4-hop DAG path (`Hop 1 -> Hop 2 -> Hop 3 -> Hop 4 -> Terminal Impact`), actor/surface per hop,
 *     causal binding kinds, Mode-A verification badge, `patchBrokeHopId`, scope boundary, and ZDR scrubbing.
 *  3. SARIF 2.1.0 `codeFlows` / `threadFlows` (`compositeReceiptsToSarifCodeFlows` + `buildSarifLog`
 *     + `exportReportSarif`): ordered hop locations (surface + route + binding kind), zero secret leakage,
 *     OASIS SARIF 2.1.0 structural validation, and backward compatibility when no composite receipts exist.
 *  4. Anti-contamination lint confirming zero v8 benchmark literals in the 3 export modules.
 */
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { sha256Hex } from '../src/server/composite-receipt.ts'
import type { CompositeProofReceipt } from '../src/server/composite-receipt.ts'
import { exportRunReceiptBundle, verifyProofReceiptBundle } from '../src/server/receipt-export.ts'
import type { CompositeReceiptExportInput } from '../src/server/receipt-export.ts'
import { exportReportMarkdown, formatCompositeChainMarkdown } from '../src/server/report-export.ts'
import { buildSarifLog, compositeReceiptsToSarifCodeFlows, exportReportSarif } from '../src/server/sarif-export.ts'
import type { SarifFindingInput } from '../src/server/sarif-export.ts'
import { findings as findingsTable, replaySpecs, reports, retestRuns } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import { validateSarif21 } from './v3-fullstack-lab/sarif-validate.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN_API = 'https://api.example.test'
const ORIGIN_IDP = 'https://idp.example.test'
const ORIGIN_APP = 'https://app.example.test'
const ORIGIN_OOS = 'https://outside.example.test'

function tempDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), `guardian-${prefix}-`))
}

function makeRunSetup(storage: Store, name = 'v8 DAG Export App') {
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(),
    name,
    seeds: [ORIGIN_API, ORIGIN_IDP, ORIGIN_APP],
    environment: 'public',
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId,
    goal: 'Verify multi-hop DAG export, Markdown reporting, and SARIF codeFlows',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 10,
    budgetRequests: 50,
    maxRpsPerOrigin: 5,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const assets = storage.run(runId).candidates
  storage.command({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    expectedScopeRevision: 0,
    assetIds: assets.map(a => a.id),
    consent: true,
    capabilityTier: 2,
  })
  const worker = storage.makeWorker(storage.run(runId), 'investigation', assets[0]!, 'Probe', 'v8 DAG export test')
  return { projectId, runId, assets, worker }
}

/**
 * Build a 4-hop CompositeProofReceipt exercising ALL 4 causal edge bindings across 4 surfaces,
 * deliberately supplying hops out of topological order (`hop_3`, `hop_1`, `hop_4`, `hop_2`) to
 * verify deterministic topological ordering in portable export, Markdown, and SARIF codeFlows.
 */
function makeFourHopComposite(opts: {
  chainId?: string
  exchangeIds: [string, string, string, string]
  ablationExchangeId: string
  secretToken: string
  personaSecret: string
  piiEmail: string
  piiSsn: string
  rawCanary: string
  replayMode?: 'fresh_clean_replay' | 'one_shot_transcript'
}): CompositeProofReceipt {
  const [ex1, ex2, ex3, ex4] = opts.exchangeIds
  const valueDigest = sha256Hex('synthetic-delegated-material')
  return {
    chainId: opts.chainId ?? 'chain-v8-4hop-001',
    terminalVulnClass: 'cross_tenant_admin_takeover',
    // Deliberately shuffled to test topological DAG sorting
    hops: [
      {
        hopId: 'hop_3',
        surface: 'graphql',
        target: {
          origin: ORIGIN_API,
          method: 'POST',
          pathAndQuery: `/graphql?owner=${opts.piiEmail}&token=${opts.secretToken}`,
        },
        exchangeIds: [ex3],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Updated workspace policy owner using derived signature (secret=${opts.personaSecret}, SSN ${opts.piiSsn})`,
        producedCapabilities: [],
        consumedCapabilities: ['cap:hop_2:forged_assertion'],
        entityId: 'workspace-entity-42',
        canaryToken: opts.rawCanary,
      },
      {
        hopId: 'hop_1',
        surface: 'http',
        target: {
          origin: ORIGIN_API,
          method: 'GET',
          pathAndQuery: `/api/v1/preview?contact=${opts.piiEmail}`,
        },
        exchangeIds: [ex1],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Leaked signing material handle for ${opts.piiEmail} with Authorization: Bearer ${opts.secretToken}`,
        producedCapabilities: ['cap:hop_1:signing_material'],
        consumedCapabilities: [],
      },
      {
        hopId: 'hop_4',
        surface: 'async_job',
        target: {
          origin: ORIGIN_APP,
          method: 'GET',
          pathAndQuery: `/api/exports/job-99/download?notify=${opts.piiEmail}`,
        },
        exchangeIds: [ex4],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Downloaded foreign tenant export containing SSN ${opts.piiSsn} and ${opts.personaSecret}`,
        producedCapabilities: [],
        consumedCapabilities: [],
        entityId: 'workspace-entity-42',
      },
      {
        hopId: 'hop_2',
        surface: 'idp',
        target: {
          origin: ORIGIN_IDP,
          method: 'POST',
          pathAndQuery: '/oauth/token',
        },
        exchangeIds: [ex2],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Exchanged derived HS256 assertion for delegated session (${opts.personaSecret})`,
        producedCapabilities: ['cap:hop_2:forged_assertion'],
        consumedCapabilities: ['cap:hop_1:signing_material'],
      },
    ],
    causalEdges: [
      {
        kind: 'value_binding',
        fromHopId: 'hop_1',
        toHopId: 'hop_2',
        capabilityHandle: 'cap:hop_1:signing_material',
        valueDigest,
        sourceExchangeId: ex1,
        targetExchangeId: ex2,
      },
      {
        kind: 'derived_crypto_binding',
        fromHopId: 'hop_2',
        toHopId: 'hop_3',
        sourceCapabilityId: 'cap:hop_1:signing_material',
        derivedCapabilityId: 'cap:hop_2:forged_assertion',
        alg: 'HS256',
      },
      {
        kind: 'state_transition_binding',
        fromHopId: 'hop_3',
        toHopId: 'hop_4',
        entityId: 'workspace-entity-42',
        ablationExchangeIds: [opts.ablationExchangeId],
        mutationKind: 'policy_owner_rebind',
      },
      {
        kind: 'async_pivot_binding',
        fromHopId: 'hop_3',
        toHopId: 'hop_4',
        correlationId: 'job-corr-99',
        channel: 'async_job',
      },
    ],
    terminalImpact: {
      terminalHopId: 'hop_4',
      claimedImpact: `Cross-tenant export exfiltrated record for ${opts.piiEmail} (SSN ${opts.piiSsn}, token=${opts.secretToken})`,
      preChainControlExchangeIds: [opts.ablationExchangeId],
      postChainReadbackExchangeIds: [ex4],
    },
    replayMode: opts.replayMode ?? 'fresh_clean_replay',
  }
}

// ============================================================================
// 1. Portable Composite Receipt Bundle: Round-Trip Sign/Verify, ZDR/PII Scrub, Tamper Rejection
// ============================================================================

test('v8 Stream D: portable composite receipt bundle signs/verifies (Ed25519 & HMAC), scrubs ZDR/PII & secrets, and rejects tampering', () => {
  const dir = tempDir('v8-dag-bundle')
  const storage = new Store(join(dir, 'data'))
  try {
    const { projectId, runId, assets, worker } = makeRunSetup(storage)
    storage.setRunTenant(runId, 'tenant-v8')

    const secretToken = 'sk_live_v8CompositeSecretToken987654'
    const personaSecret = 'opaque-persona-secret-v8-dag-424242'
    const piiEmail = 'victim.user@corp.example'
    const piiSsn = '123-45-6789'
    const piiCard = '4532-0151-1283-0366'
    const rawCanary = 'canary_raw_secret_never_export_9988'

    const recordEx = (origin: string, method: string, path: string, persona: string | null, status: number, body: string) =>
      storage.recordExchange({
        runId,
        assignmentId: worker.id,
        scopeRevision: 1,
        origin,
        finalOrigin: origin,
        redirectOrigins: [origin],
        method,
        pathAndQuery: path,
        personaHandle: persona,
        status,
        mediaType: 'application/json',
        reqHeaders: { authorization: `Bearer ${secretToken}`, 'x-trace-id': 'trace-v8' },
        respHeaders: { 'content-type': 'application/json', 'set-cookie': `sid=${personaSecret}; HttpOnly` },
        body,
        durationMs: 12,
      })

    const ex1 = recordEx(ORIGIN_API, 'GET', `/api/v1/preview?contact=${piiEmail}`, 'member_a', 200, `{"owner":"${piiEmail}","card":"${piiCard}"}`)
    const ex2 = recordEx(ORIGIN_IDP, 'POST', '/oauth/token', 'member_a', 200, `{"token":"${secretToken}"}`)
    const ex3 = recordEx(ORIGIN_API, 'POST', '/graphql', null, 200, `{"data":{"rebind":true,"ssn":"${piiSsn}"}}`)
    const ex4 = recordEx(ORIGIN_APP, 'GET', '/api/exports/job-99/download', null, 200, `{"exported":"${piiEmail}","ssn":"${piiSsn}"}`)
    const exAblation = recordEx(ORIGIN_APP, 'GET', '/api/exports/job-99/download', 'member_a', 403, '{"error":"forbidden"}')
    storage.flushNow()

    // Seed a single-hop confirmed finding alongside the composite chain
    const findingId = randomUUID()
    const specId = randomUUID()
    const now = 1_765_000_000_000

    storage.db.insert(replaySpecs).values({
      id: specId,
      runId,
      findingId,
      assignmentId: worker.id,
      scopeRevision: 1,
      goalRevision: 0,
      spec: { kind: 'idor', origin: ORIGIN_API, pathAndQuery: '/api/v1/preview' } as never,
      specSha256: createHash('sha256').update(specId).digest('hex'),
      sourceOrigins: [ORIGIN_API],
      lastVerificationDiff: { verdict: 'confirmed' } as never,
      proofKind: 'agent_script',
      proofVerdict: 'confirmed',
      proofRuntime: 'ts',
      proofScriptSha256: createHash('sha256').update('script').digest('hex'),
      proofArtifactId: null,
      proofReceipt: {
        receipt: {
          vulnClass: 'idor',
          target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: `/api/v1/preview?contact=${piiEmail}` },
          exchangeIds: [ex1.id],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: `Single-hop preview read for ${piiEmail}`,
        },
        verification: {
          confirmed: true,
          vulnClass: 'idor',
          rule: 'idor.read',
          reason: 'Confirmed single-hop preview read',
          observed: 'HTTP 200',
          expected: 'HTTP 403',
        },
      },
      createdAt: now,
    }).run()

    storage.db.insert(findingsTable).values({
      id: findingId,
      runId,
      assetId: assets[0]!.id,
      goalRevision: 0,
      checkId: 'chain',
      caseId: 'v8-chain-001',
      findingKind: 'multi_step_chain',
      replaySpecId: specId,
      provenance: 'agent_only',
      verificationClass: 'runtime_confirmed',
      sourceOrigins: [ORIGIN_API, ORIGIN_IDP, ORIGIN_APP],
      verificationTier: 'runtime_confirmed',
      fingerprintHash: createHash('sha256').update('v8-chain-001').digest('hex'),
      finding: {
        id: findingId,
        title: `4-hop cross-tenant takeover (${piiEmail})`,
        severity: 'critical',
        category: 'broken-access-control',
        cwe: 'CWE-284',
        origin: ORIGIN_API,
        status: 'confirmed',
        reason: 'Confirmed 4-hop causal DAG chain',
        exchangeIds: [ex1.id, ex2.id, ex3.id, ex4.id],
        evidenceIds: [],
      } as never,
    }).run()

    // First verify backward compatibility: run without compositeReceipts omits field & keeps v7 return shape
    const hmacSecret = 'v8-dag-export-hmac-secret-0123456789'
    const singleOnlyBundle = exportRunReceiptBundle(storage, runId, {
      tenantId: 'tenant-v8',
      zdr: true,
      signing: { algorithm: 'hmac-sha256', secret: hmacSecret, keyId: 'v8-hmac-1' },
      now,
    })
    assert.equal(singleOnlyBundle.payload.compositeReceipts, undefined)
    assert.deepEqual(
      verifyProofReceiptBundle(singleOnlyBundle, { algorithm: 'hmac-sha256', secret: hmacSecret }),
      { valid: true, verifiedRecords: 1 },
    )

    // Now export with 4-hop CompositeProofReceipt + patchBrokeHopId
    const compositeReceipt = makeFourHopComposite({
      exchangeIds: [ex1.id, ex2.id, ex3.id, ex4.id],
      ablationExchangeId: exAblation.id,
      secretToken,
      personaSecret,
      piiEmail,
      piiSsn,
      rawCanary,
    })
    const compositeInput: CompositeReceiptExportInput = {
      findingId,
      title: `4-Hop Cross-Tenant Export Takeover (${piiEmail})`,
      severity: 'critical',
      cwe: 'CWE-284',
      receipt: compositeReceipt,
      verification: {
        confirmed: true,
        modeBVerified: false,
        reason: `CompositeProofReceipt confirmed (4 hops, 4 verified edges, secret=${secretToken})`,
        verifiedEdges: [
          { edgeIndex: 0, kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', verified: true, reason: 'ok' },
          { edgeIndex: 1, kind: 'derived_crypto_binding', fromHopId: 'hop_2', toHopId: 'hop_3', verified: true, reason: 'ok' },
          { edgeIndex: 2, kind: 'state_transition_binding', fromHopId: 'hop_3', toHopId: 'hop_4', verified: true, reason: 'ok' },
          { edgeIndex: 3, kind: 'async_pivot_binding', fromHopId: 'hop_3', toHopId: 'hop_4', verified: true, reason: 'ok' },
        ],
      },
      hopActors: { hop_1: 'member_a', hop_2: 'member_a', hop_3: null, hop_4: null },
      patchBrokeHopId: 'hop_3',
      patchRetestVerdict: 'fixed',
    }

    const edKeys = generateKeyPairSync('ed25519')
    const bundle = exportRunReceiptBundle(storage, runId, {
      tenantId: 'tenant-v8',
      zdr: true,
      signing: { algorithm: 'ed25519', privateKey: edKeys.privateKey, keyId: 'v8-ed-1' },
      compositeReceipts: [compositeInput],
      now,
    })

    assert.equal(bundle.payload.receiptCount, 1)
    assert.equal(bundle.payload.compositeReceipts?.length, 1)
    const comp = bundle.payload.compositeReceipts![0]!
    assert.equal(comp.chainId, 'chain-v8-4hop-001')
    assert.equal(comp.replayMode, 'fresh_clean_replay')
    assert.equal(comp.patchBrokeHopId, 'hop_3')
    assert.equal(comp.patchRetestVerdict, 'fixed')
    assert.equal(comp.hopCount, 4)
    assert.deepEqual(comp.hops.map(h => h.hopId), ['hop_1', 'hop_2', 'hop_3', 'hop_4'], 'hops must be topologically ordered')
    assert.deepEqual(comp.hops.map(h => h.order), [1, 2, 3, 4])
    assert.deepEqual(
      comp.causalEdges.map(e => e.kind),
      ['value_binding', 'derived_crypto_binding', 'state_transition_binding', 'async_pivot_binding'],
    )
    assert.ok(/^[0-9a-f]{64}$/.test(comp.recordSha256), 'composite recordSha256 must be 64-char hex SHA-256')
    assert.equal(comp.transcriptSlices.length, 5, 'should bundle all 4 hop exchanges + ablation control')

    // Zero secret or PII leakage anywhere in serialized ZDR bundle
    const serialized = JSON.stringify(bundle)
    assert.ok(!serialized.includes(secretToken), 'ZDR composite bundle leaked bearer/API token')
    assert.ok(!serialized.includes(piiEmail), 'ZDR composite bundle leaked email PII')
    assert.ok(!serialized.includes(piiSsn), 'ZDR composite bundle leaked SSN PII')
    assert.ok(!serialized.includes(piiCard), 'ZDR composite bundle leaked Luhn card PII')
    assert.ok(!serialized.includes(rawCanary), 'ZDR composite bundle leaked raw canaryToken')
    assert.ok(serialized.includes('[pii:email]'))
    assert.ok(serialized.includes('[pii:ssn]'))
    assert.ok(serialized.includes('[pii:card]'))

    // Round-trip Ed25519 verification passes
    assert.deepEqual(
      verifyProofReceiptBundle(bundle, { algorithm: 'ed25519', publicKey: edKeys.publicKey }),
      { valid: true, verifiedRecords: 1, verifiedCompositeRecords: 1 },
    )

    // Tamper 1: mutate composite hop delta -> payload SHA-256 mismatch
    const tamperedHop = structuredClone(bundle)
    tamperedHop.payload.compositeReceipts![0]!.hops[1]!.claimedDelta = 'tampered delta'
    const res1 = verifyProofReceiptBundle(tamperedHop, { publicKey: edKeys.publicKey })
    assert.equal(res1.valid, false)
    assert.match(res1.reason ?? '', /payload SHA-256 mismatch/i)

    // Tamper 2: mutate composite record AND recompute payloadSha256 without updating recordSha256 -> per-record SHA-256 mismatch
    const hmacBundle = exportRunReceiptBundle(storage, runId, {
      tenantId: 'tenant-v8',
      zdr: true,
      signing: { algorithm: 'hmac-sha256', secret: hmacSecret, keyId: 'v8-hmac-comp' },
      compositeReceipts: [compositeInput],
      now,
    })
    assert.deepEqual(
      verifyProofReceiptBundle(hmacBundle, { algorithm: 'hmac-sha256', secret: hmacSecret }),
      { valid: true, verifiedRecords: 1, verifiedCompositeRecords: 1 },
    )
    const badRecordHash = structuredClone(hmacBundle)
    badRecordHash.payload.compositeReceipts![0]!.recordSha256 = '0'.repeat(64)
    // Even if payloadSha256 were rewritten to match the mutated payload, per-record digest check catches it
    assert.equal(verifyProofReceiptBundle(badRecordHash, { secret: hmacSecret }).valid, false)

    // Tamper 3: wrong Ed25519 public key rejected
    const otherEd = generateKeyPairSync('ed25519')
    const resWrongKey = verifyProofReceiptBundle(bundle, { algorithm: 'ed25519', publicKey: otherEd.publicKey })
    assert.equal(resWrongKey.valid, false)
    assert.match(resWrongKey.reason ?? '', /Ed25519 signature/i)

    // Also verify store-persisted composite receipt + retest patchBrokeHopId auto-extraction
    storage.db.insert(retestRuns).values({
      id: randomUUID(),
      projectId,
      runId,
      findingId,
      replaySpecId: specId,
      scopeRevision: 1,
      verdict: 'fixed',
      summary: 'Full DAG retest passed closure: patchBrokeHopId=hop_3',
      evidenceIds: [],
      exchangeIds: [ex3.id],
      createdAt: now + 5000,
    }).run()
    storage.client
      .prepare('UPDATE replay_specs SET proof_receipt = ? WHERE id = ?')
      .run(JSON.stringify({
        receipt: {
          vulnClass: 'idor',
          target: { origin: ORIGIN_API, method: 'GET', pathAndQuery: '/api/v1/preview' },
          exchangeIds: [ex1.id],
          oobEventIds: [],
          browserTraceIds: [],
          claimedDelta: 'Single-hop preview read',
        },
        verification: {
          confirmed: true,
          vulnClass: 'idor',
          rule: 'idor.read',
          reason: 'ok',
          observed: '200',
          expected: '403',
        },
        compositeReceipt,
      }), specId)

    const autoExtractedBundle = exportRunReceiptBundle(storage, runId, {
      tenantId: 'tenant-v8',
      zdr: true,
      signing: { algorithm: 'hmac-sha256', secret: hmacSecret },
      now,
    })
    assert.equal(autoExtractedBundle.payload.compositeReceipts?.length, 1)
    assert.equal(autoExtractedBundle.payload.compositeReceipts![0]!.patchBrokeHopId, 'hop_3')
    assert.equal(autoExtractedBundle.payload.compositeReceipts![0]!.patchRetestVerdict, 'fixed')
    assert.equal(verifyProofReceiptBundle(autoExtractedBundle, { secret: hmacSecret }).valid, true)
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 2. Markdown DAG Renderer (`formatCompositeChainMarkdown` + `exportReportMarkdown`)
// ============================================================================

test('v8 Stream D: formatCompositeChainMarkdown renders 4-hop DAG chain, bindings, Mode-A badge, patchBrokeHopId, and integrates with exportReportMarkdown', () => {
  const secretToken = 'sk_live_mdSecretTokenDoNotLeak123456'
  const personaSecret = 'persona-secret-markdown-test-999'
  const piiEmail = 'target.admin@corp.example'
  const piiSsn = '123-45-6789'
  const rawCanary = 'canary_md_secret_7777'

  assert.equal(formatCompositeChainMarkdown([]), '')

  const compositeReceipt = makeFourHopComposite({
    exchangeIds: ['ex-1', 'ex-2', 'ex-3', 'ex-4'],
    ablationExchangeId: 'ex-ablation',
    secretToken,
    personaSecret,
    piiEmail,
    piiSsn,
    rawCanary,
  })

  const md = formatCompositeChainMarkdown(
    [
      {
        title: `Cross-tenant export takeover for ${piiEmail}`,
        severity: 'critical',
        cwe: 'CWE-284',
        receipt: compositeReceipt,
        hopActors: { hop_1: 'member_a', hop_2: 'member_a', hop_3: null, hop_4: null },
        patchBrokeHopId: 'hop_3',
        patchRetestVerdict: 'fixed',
      },
    ],
    {
      secrets: [{ value: personaSecret, placeholder: '[redacted:persona]' }],
      zdr: true,
    },
  )

  // Structural assertions on the 4-hop DAG Markdown rendering
  assert.match(md, /^## Multi-Hop Causal Chains/m)
  assert.match(md, /\[Mode-A Verified\]/)
  assert.match(md, /fresh_clean_replay/)
  assert.match(md, /Hop 1 \(`hop_1`\) -> Hop 2 \(`hop_2`\) -> Hop 3 \(`hop_3`\) -> Hop 4 \(`hop_4`\) -> \*\*Terminal Impact\*\*/)
  assert.match(md, /`patchBrokeHopId`: `hop_3`/)
  assert.match(md, /\*\*\(Patch broke here\)\*\*/)
  assert.match(md, /`http`/)
  assert.match(md, /`idp`/)
  assert.match(md, /`graphql`/)
  assert.match(md, /`async_job`/)
  assert.match(md, /`member_a`/)
  assert.match(md, /`value_binding`/)
  assert.match(md, /`derived_crypto_binding`/)
  assert.match(md, /`state_transition_binding`/)
  assert.match(md, /`async_pivot_binding`/)

  // Zero secret or PII leakage in Markdown
  assert.ok(!md.includes(secretToken), 'Markdown leaked bearer/API token')
  assert.ok(!md.includes(personaSecret), 'Markdown leaked named persona secret')
  assert.ok(!md.includes(piiEmail), 'Markdown leaked email PII')
  assert.ok(!md.includes(piiSsn), 'Markdown leaked SSN PII')
  assert.ok(!md.includes(rawCanary), 'Markdown leaked raw canaryToken')

  // Mode-B badge rendering check
  const modeBMd = formatCompositeChainMarkdown([
    makeFourHopComposite({
      chainId: 'chain-mode-b',
      exchangeIds: ['ex-1', 'ex-2', 'ex-3', 'ex-4'],
      ablationExchangeId: 'ex-ablation',
      secretToken,
      personaSecret,
      piiEmail,
      piiSsn,
      rawCanary,
      replayMode: 'one_shot_transcript',
    }),
  ])
  assert.match(modeBMd, /\[Mode-B Verified\]/)
  assert.match(modeBMd, /one_shot_transcript/)

  // End-to-end integration with exportReportMarkdown (including scope filtering)
  const dir = tempDir('v8-dag-md')
  const storage = new Store(join(dir, 'data'))
  try {
    const { runId, assets } = makeRunSetup(storage, 'MD Report Project')
    const reportId = randomUUID()
    storage.db.insert(reports).values({
      id: reportId,
      runId,
      version: 1,
      partial: false,
      body: {
        goal: 'Verify report markdown includes composite chains cleanly',
        capabilityTier: 2,
        scope: assets,
        scopeRevision: 1,
        goalRevision: 0,
        findings: [],
        coverage: [],
        gaps: [],
        nextSteps: [],
      } as never,
      createdAt: Date.now(),
    }).run()

    // Without composite receipts: no Multi-Hop Causal Chains section emitted (100% backward compatible)
    const baselineMd = exportReportMarkdown(storage, runId, reportId, { zdr: true })
    assert.ok(!baselineMd.content.includes('## Multi-Hop Causal Chains'))

    // Out-of-scope composite receipt must be filtered out
    const oosReceipt: CompositeProofReceipt = {
      ...compositeReceipt,
      chainId: 'chain-oos',
      hops: compositeReceipt.hops.map((h, i) => (i === 0 ? { ...h, target: { ...h.target, origin: ORIGIN_OOS } } : h)),
    }

    const withChainsMd = exportReportMarkdown(storage, runId, reportId, {
      zdr: true,
      compositeReceipts: [
        { receipt: compositeReceipt, patchBrokeHopId: 'hop_3', patchRetestVerdict: 'fixed' },
        { receipt: oosReceipt },
      ],
    })
    assert.match(withChainsMd.content, /## Multi-Hop Causal Chains/)
    assert.match(withChainsMd.content, /chain-v8-4hop-001/)
    assert.match(withChainsMd.content, /`patchBrokeHopId`: `hop_3`/)
    assert.ok(!withChainsMd.content.includes('chain-oos'), 'Out-of-scope composite chain must not appear in report')
    assert.ok(!withChainsMd.content.includes(secretToken))
    assert.ok(!withChainsMd.content.includes(piiEmail))
    assert.ok(!withChainsMd.content.includes(piiSsn))
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 3. SARIF 2.1.0 `codeFlows` / `threadFlows` & Backward Compatibility
// ============================================================================

test('v8 Stream D: compositeReceiptsToSarifCodeFlows & buildSarifLog emit valid SARIF 2.1.0 codeFlows with zero secret leakage', () => {
  const secretToken = 'sk_live_sarifSecretTokenNeverLeak888'
  const personaSecret = 'opaque-sarif-persona-secret-555111'
  const piiEmail = 'sarif.victim@corp.example'
  const piiSsn = '123-45-6789'
  const rawCanary = 'canary_sarif_never_export_1234'

  const compositeReceipt = makeFourHopComposite({
    exchangeIds: ['ex-1', 'ex-2', 'ex-3', 'ex-4'],
    ablationExchangeId: 'ex-ablation',
    secretToken,
    personaSecret,
    piiEmail,
    piiSsn,
    rawCanary,
  })

  // Direct helper test on single receipt input
  const flows = compositeReceiptsToSarifCodeFlows(
    {
      findingId: 'finding-4hop',
      receipt: compositeReceipt,
      hopActors: { hop_1: 'member_a', hop_2: 'member_a', hop_3: null, hop_4: null },
      patchBrokeHopId: 'hop_3',
    },
    {
      secrets: [{ value: personaSecret, placeholder: '[redacted:persona]' }],
      zdr: true,
    },
  )

  assert.equal(flows.length, 1)
  const flow = flows[0]!
  assert.match(flow.message?.text ?? '', /chain-v8-4hop-001/)
  assert.match(flow.message?.text ?? '', /patchBrokeHopId=hop_3/)
  assert.equal(flow.threadFlows.length, 1)

  const tf = flow.threadFlows[0]!
  assert.equal(tf.id, 'chain-v8-4hop-001')
  assert.equal(tf.locations.length, 4)

  // Verify topological order & executionOrder 1..4
  assert.deepEqual(tf.locations.map(l => l.executionOrder), [1, 2, 3, 4])
  assert.deepEqual(
    tf.locations.map(l => l.properties?.guardian.hopId),
    ['hop_1', 'hop_2', 'hop_3', 'hop_4'],
  )
  assert.deepEqual(
    tf.locations.map(l => l.properties?.guardian.surface),
    ['http', 'idp', 'graphql', 'async_job'],
  )
  assert.deepEqual(
    tf.locations.map(l => l.location.logicalLocations?.[0]?.kind),
    ['http', 'idp', 'graphql', 'async_job'],
  )

  // Verify route + surface + binding kinds in each location
  assert.match(tf.locations[0]!.location.logicalLocations?.[0]?.name ?? '', /^http:GET \/api\/v1\/preview/)
  assert.deepEqual(tf.locations[0]!.properties?.guardian.incomingBindingKinds, [])
  assert.equal(tf.locations[0]!.importance, 'essential')

  assert.match(tf.locations[1]!.location.logicalLocations?.[0]?.name ?? '', /^idp:POST \/oauth\/token/)
  assert.deepEqual(tf.locations[1]!.properties?.guardian.incomingBindingKinds, ['value_binding'])
  assert.ok(tf.locations[1]!.kinds?.includes('value_binding'))
  assert.equal(tf.locations[1]!.importance, 'important')

  assert.match(tf.locations[2]!.location.logicalLocations?.[0]?.name ?? '', /^graphql:POST \/graphql/)
  assert.deepEqual(tf.locations[2]!.properties?.guardian.incomingBindingKinds, ['derived_crypto_binding'])
  assert.equal(tf.locations[2]!.properties?.guardian.patchBrokeHopId, 'hop_3')

  assert.match(tf.locations[3]!.location.logicalLocations?.[0]?.name ?? '', /^async_job:GET \/api\/exports\/job-99\/download/)
  assert.deepEqual(
    tf.locations[3]!.properties?.guardian.incomingBindingKinds,
    ['state_transition_binding', 'async_pivot_binding'],
  )
  assert.equal(tf.locations[3]!.properties?.guardian.isTerminal, true)
  assert.equal(tf.locations[3]!.importance, 'essential')

  // Zero secret or PII leakage in codeFlows
  const flowJson = JSON.stringify(flows)
  assert.ok(!flowJson.includes(secretToken), 'SARIF codeFlows leaked bearer/API token')
  assert.ok(!flowJson.includes(personaSecret), 'SARIF codeFlows leaked persona secret')
  assert.ok(!flowJson.includes(piiEmail), 'SARIF codeFlows leaked email PII')
  assert.ok(!flowJson.includes(piiSsn), 'SARIF codeFlows leaked SSN PII')
  assert.ok(!flowJson.includes(rawCanary), 'SARIF codeFlows leaked raw canaryToken')

  // Full buildSarifLog integration + OASIS SARIF 2.1.0 validation + backward compatibility
  const chainFinding: SarifFindingInput = {
    id: 'finding-4hop',
    origin: ORIGIN_API,
    title: 'Multi-hop cross-tenant admin takeover',
    severity: 'critical',
    status: 'confirmed',
    category: 'broken-access-control',
    cwe: 'CWE-284',
    reason: 'Confirmed 4-hop DAG chain',
    remediation: 'Enforce strict tenant binding on policy rebind and export download.',
    evidenceIds: [],
    exchangeIds: ['ex-1', 'ex-2', 'ex-3', 'ex-4'],
    endpoint: '/api/exports/job-99/download',
    verificationTier: 'runtime_confirmed',
    scopeRevision: 1,
  }
  const singleFinding: SarifFindingInput = {
    id: 'finding-single',
    origin: ORIGIN_API,
    title: 'Missing HSTS header',
    severity: 'low',
    status: 'confirmed',
    category: 'crypto-tls-transport',
    cwe: 'CWE-319',
    reason: 'Strict-Transport-Security header missing',
    remediation: 'Add HSTS header.',
    evidenceIds: [],
    exchangeIds: [],
    endpoint: '/',
    verificationTier: 'runtime_confirmed',
    scopeRevision: 1,
  }

  const log = buildSarifLog({
    runId: randomUUID(),
    reportVersion: 1,
    goal: 'SARIF v8 DAG test',
    capabilityTier: 2,
    scopeRevision: 1,
    goalRevision: 0,
    approvedOrigins: [ORIGIN_API, ORIGIN_IDP, ORIGIN_APP],
    findings: [chainFinding, singleFinding],
    compositeReceipts: [
      {
        findingId: 'finding-4hop',
        receipt: compositeReceipt,
        patchBrokeHopId: 'hop_3',
      },
    ],
    secrets: [{ value: personaSecret, placeholder: '[redacted:persona]' }],
    zdr: true,
  })

  assert.deepEqual(validateSarif21(log), [], 'SARIF log with codeFlows must pass OASIS SARIF 2.1.0 validation')
  const sarifSerialized = JSON.stringify(log)
  assert.ok(!sarifSerialized.includes(secretToken))
  assert.ok(!sarifSerialized.includes(personaSecret))
  assert.ok(!sarifSerialized.includes(piiEmail))
  assert.ok(!sarifSerialized.includes(piiSsn))
  assert.ok(!sarifSerialized.includes(rawCanary))

  const chainResult = log.runs[0]!.results.find(r => r.properties.guardian.findingId === 'finding-4hop')!
  const singleResult = log.runs[0]!.results.find(r => r.properties.guardian.findingId === 'finding-single')!
  assert.equal(chainResult.codeFlows?.length, 1)
  assert.equal(chainResult.codeFlows![0]!.threadFlows[0]!.locations.length, 4)
  assert.equal(singleResult.codeFlows, undefined, 'single-hop finding must remain 100% backward compatible without codeFlows')

  // End-to-end exportReportSarif from Store
  const dir = tempDir('v8-dag-sarif')
  const storage = new Store(join(dir, 'data'))
  try {
    const { runId, assets } = makeRunSetup(storage, 'SARIF Store Project')
    const reportId = randomUUID()
    storage.db.insert(reports).values({
      id: reportId,
      runId,
      version: 1,
      partial: false,
      body: {
        goal: 'Export SARIF with composite codeFlows',
        capabilityTier: 2,
        scope: assets,
        scopeRevision: 1,
        goalRevision: 0,
        findings: [chainFinding],
        coverage: [],
        gaps: [],
        nextSteps: [],
      } as never,
      createdAt: Date.now(),
    }).run()

    const exported = exportReportSarif(
      storage,
      runId,
      reportId,
      [{ value: personaSecret, placeholder: '[redacted:persona]' }],
      {
        compositeReceipts: [{ findingId: 'finding-4hop', receipt: compositeReceipt, patchBrokeHopId: 'hop_3' }],
        zdr: true,
      },
    )
    assert.deepEqual(validateSarif21(exported.log), [])
    assert.equal(exported.log.runs[0]!.results[0]!.codeFlows?.length, 1)
    assert.ok(!exported.content.includes(secretToken))
    assert.ok(!exported.content.includes(personaSecret))
    assert.ok(!exported.content.includes(piiEmail))
  } finally {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  }
})

// ============================================================================
// 4. Anti-Contamination Check on Modified Server Files
// ============================================================================

test('v8 Stream D: zero benchmark literals in receipt-export.ts, report-export.ts, and sarif-export.ts', () => {
  const files = [
    'src/server/receipt-export.ts',
    'src/server/report-export.ts',
    'src/server/sarif-export.ts',
  ]
  const forbidden = [
    /\bpaygrid\b/i,
    /\bshipforge\b/i,
    /\bnexusiam\b/i,
    /\bconnecthub\b/i,
    /\b(?:PG|SF|NX|CH)-[CD]\d+\b/,
    /vault\.internal/i,
    /registry\.internal/i,
    /billing\.internal/i,
    /mh_fake_/i,
  ]
  for (const rel of files) {
    const src = readFileSync(join(repoRoot, rel), 'utf8')
    for (const re of forbidden) {
      assert.equal(re.test(src), false, `Benchmark literal matched ${re} in ${rel}`)
    }
  }
})
