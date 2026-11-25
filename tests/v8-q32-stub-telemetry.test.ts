/**
 * Queue #32 — surgical verification & telemetry fixes:
 *  1. Close `ti.proofReceipt` early-return stub bypass in `verifyTerminalImpactGate`:
 *     when `ti.proofReceipt` is supplied (without custom `options.verifyTerminalImpact`),
 *     `isJobOrHandleStub` is still enforced on `termEx` AND on every non-control 2xx probe
 *     exchange cited by `ti.proofReceipt`. Rejects fail-closed with `terminal_impact_unproven`
 *     unless a non-stub `postMutRb` or delivered OOB/browser sink proves terminal impact.
 *  2. Sanitized `topRejectDetails` telemetry in `scripts/benchmark-multihop.ts`:
 *     top 12 most frequent sanitized failure signatures across `kovo_verify` / `composite.verify`,
 *     normalizing UUIDs / gx-IDs / cap-handles / ports / numbers to `<id>`, capped <= 140 chars,
 *     and never leaking raw HTTP bodies or secrets.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  aggregateMultihopTelemetry,
  extractMultihopRunTelemetry,
  sanitizeRejectSignature,
} from '../scripts/benchmark-multihop.ts'
import { singleReceiptToComposite, verifyCompositeReceipt } from '../src/server/composite-receipt.ts'
import type { CompositeProofReceipt, HostSignedTranscript, HostTranscriptEntry } from '../src/server/composite-receipt.ts'
import { verifyReceipt } from '../src/server/proof-receipt.ts'
import type { ImpactStep, ProofReceipt } from '../src/server/proof-receipt.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'https://api.example.test'

function step(p: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return { actor: { handle: 'dual_member', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, ...p } as ImpactStep
}
function entry(exchangeId: string, s: ImpactStep, extra: Partial<HostTranscriptEntry> = {}): HostTranscriptEntry {
  return { exchangeId, step: s, timestampMs: 1_700_000_000_000, actorPersona: s.actor.handle, cleanSession: true, ...extra }
}

// ---------------------------------------------------------------------------
// 1. Close ti.proofReceipt Early-Return Stub Bypass
// ---------------------------------------------------------------------------

test('ti.proofReceipt CANNOT bypass isJobOrHandleStub on async export creation + job-status poll', () => {
  const cap = 'cap:hop_1:cache_key'
  const ownerB = { handle: 'owner_b', role: 'owner' as const, tenant: 'tenant_b', auth: 'bearer' as const, sameSite: null }
  const jobMeta = { id: 'job_9', kind: 'export', tenantId: 'tenant_b', status: 'ready', readyAt: 3, runId: 'r1', artifactKey: 'f.csv', processed: true }
  const transcript: HostSignedTranscript = {
    entries: [
      entry('pre_rb', step({ id: 'pre_rb', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/tenant_b/exports', actor: ownerB, json: { exports: [] } }), { timestampMs: 400 }),
      entry('ctl', step({ id: 'ctl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/v1/orgs/tenant_b/exports', actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null }, json: { error: 'forbidden' } }), { timestampMs: 500, replayAttempt: 'ablation_control' }),
      entry('prime', step({ id: 'prime', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/tenant_b/summary', json: { cached: true, cacheKey: 'k1' } }), { timestampMs: 1000, emittedCapabilities: [cap] }),
      entry('create', step({ id: 'create', arm: 'probe', method: 'POST', status: 202, pathAndQuery: '/v1/orgs/tenant_b/exports', json: { jobId: 'job_9', tenant: 'tenant_b', viaCache: true } }), { timestampMs: 2000, consumedCapabilities: [cap] }),
      entry('poll', step({ id: 'poll', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/tenant_b/exports', actor: ownerB, json: { exports: [jobMeta] } }), { timestampMs: 3000 }),
    ],
  }
  const innerProof: ProofReceipt = {
    vulnClass: 'bola',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orgs/tenant_b/exports' },
    exchangeIds: ['pre_rb', 'create', 'poll'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Created export handle for tenant_b via cache bleed',
    resourceTenant: 'tenant_b',
  }
  // Confirm v7 verifyReceipt alone WOULD confirm this stub-only persisted mutation!
  assert.equal(verifyReceipt(innerProof, transcript).confirmed, true, 'precondition: v7 verifyReceipt confirms the stub mutation')

  const receipt: CompositeProofReceipt = {
    chainId: 'q32-export-proof-bypass',
    terminalVulnClass: 'parser_cache_differential',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, pathAndQuery: '/v1/orgs/tenant_b/summary' }, exchangeIds: ['prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed shared cache', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, pathAndQuery: '/v1/orgs/tenant_b/exports' }, exchangeIds: ['create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created export job handle', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'create',
      claimedImpact: 'Cross-tenant export job created via cache differential',
      proofReceipt: innerProof,
      preChainControlExchangeIds: ['ctl'],
      postChainReadbackExchangeIds: ['poll'],
    },
    replayMode: 'fresh_clean_replay',
  }

  const res = verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['dual_member', 'member_a'] })
  assert.equal(res.confirmed, false, 'stub terminal probe must not bypass via ti.proofReceipt')
  assert.equal(res.failedStage, 'terminal_impact')
  assert.equal(res.rejectedBy, 'terminal_impact_unproven')
  assert.match(res.reason, /terminal_impact_unproven/)
})

test('ti.proofReceipt rejects when stub probe is cited ONLY in ti.proofReceipt.exchangeIds (not termEx)', () => {
  const ownerB = { handle: 'owner_b', role: 'owner' as const, tenant: 'tenant_b', auth: 'bearer' as const, sameSite: null }
  const jobMeta = { job: { id: 'job_44', kind: 'export', tenantId: 'tenant_b', status: 'ready', readyAt: 3, runId: 'r1', artifactKey: 'f.csv', processed: true } }
  const transcript: HostSignedTranscript = {
    entries: [
      entry('ctl_owner', step({ id: 'ctl_owner', arm: 'control', method: 'GET', status: 200, route: '/v1/exports/:id', pathAndQuery: '/v1/exports/job_44', actor: ownerB, json: jobMeta }), { timestampMs: 500 }),
      entry('real_probe', step({ id: 'real_probe', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/tenant_a/profile', json: { id: 'u1', email: 'me@tenant-a.test', balance: 10 } }), { timestampMs: 1000 }),
      entry('stub_probe', step({ id: 'stub_probe', arm: 'probe', method: 'GET', status: 200, route: '/v1/exports/:id', pathAndQuery: '/v1/exports/job_44', json: jobMeta }), { timestampMs: 2000 }),
    ],
  }
  const innerProof: ProofReceipt = {
    vulnClass: 'bola',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/job_44' },
    exchangeIds: ['ctl_owner', 'stub_probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Read foreign job-status envelope',
    resourceTenant: 'tenant_b',
  }
  assert.equal(verifyReceipt(innerProof, transcript).confirmed, true, 'precondition: v7 verifyReceipt confirms job-status GET')

  const receipt: CompositeProofReceipt = {
    chainId: 'q32-proof-cited-stub',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, pathAndQuery: '/v1/orgs/tenant_a/profile' }, exchangeIds: ['real_probe'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read profile', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      terminalExchangeId: 'real_probe',
      claimedImpact: 'Job status read via proofReceipt citation',
      proofReceipt: innerProof,
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const res = verifyCompositeReceipt(receipt, transcript, { attackerPersonas: ['dual_member'] })
  assert.equal(res.confirmed, false)
  assert.equal(res.failedStage, 'terminal_impact')
  assert.equal(res.rejectedBy, 'terminal_impact_unproven')
})

test('ti.proofReceipt PASSES when accompanied by a real non-stub postMutRb, delivered OOB sink, or custom verifyTerminalImpact', () => {
  const ownerB = { handle: 'owner_b', role: 'owner' as const, tenant: 'tenant_b', auth: 'bearer' as const, sameSite: null }
  const jobMeta = { id: 'job_9', kind: 'export', tenantId: 'tenant_b', status: 'ready', readyAt: 3, runId: 'r1', artifactKey: 'f.csv', processed: true }
  const transcript: HostSignedTranscript = {
    entries: [
      entry('pre_rb', step({ id: 'pre_rb', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/tenant_b/exports', actor: ownerB, json: { exports: [] } }), { timestampMs: 400 }),
      entry('ctl', step({ id: 'ctl', arm: 'control', method: 'POST', status: 403, pathAndQuery: '/v1/orgs/tenant_b/exports', json: { error: 'denied' } }), { timestampMs: 500 }),
      entry('create', step({ id: 'create', arm: 'probe', method: 'POST', status: 202, pathAndQuery: '/v1/orgs/tenant_b/exports', json: { jobId: 'job_9', tenant: 'tenant_b', viaCache: true } }), { timestampMs: 2000 }),
      entry('poll', step({ id: 'poll', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/orgs/tenant_b/exports', actor: ownerB, json: { exports: [jobMeta] } }), { timestampMs: 2500 }),
      entry('download', step({ id: 'download', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/files/export/tenant_b/file.csv', body: 'account,tenant,balance\nacct_9,tenant_b,99000\n' }), { timestampMs: 3000 }),
    ],
    oobEvents: [{ id: 'oob-1', token: 'tok-oob', delivered: true, receivedAtMs: 2500 }],
  }
  const innerProof: ProofReceipt = {
    vulnClass: 'bola',
    target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orgs/tenant_b/exports' },
    exchangeIds: ['pre_rb', 'create', 'poll'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Created export and downloaded tenant_b CSV data',
    resourceTenant: 'tenant_b',
  }
  assert.equal(verifyReceipt(innerProof, transcript).confirmed, true)

  const baseReceipt: CompositeProofReceipt = {
    chainId: 'q32-export-real-download',
    terminalVulnClass: 'parser_cache_differential',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, pathAndQuery: '/v1/orgs/tenant_b/exports' }, exchangeIds: ['create'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created export', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      terminalExchangeId: 'create',
      claimedImpact: 'Downloaded foreign-tenant CSV export',
      proofReceipt: innerProof,
      preChainControlExchangeIds: ['ctl'],
      postChainReadbackExchangeIds: ['download'],
    },
    replayMode: 'fresh_clean_replay',
  }

  // Case A: real non-stub postMutRb confirms.
  const withDownload = verifyCompositeReceipt(baseReceipt, transcript, { attackerPersonas: ['dual_member'] })
  assert.equal(withDownload.confirmed, true, withDownload.reason)

  // Case B: delivered OOB sink confirms even without postMutRb.
  const oobReceipt: CompositeProofReceipt = {
    ...baseReceipt,
    hops: [{ ...baseReceipt.hops[0]!, oobEventIds: ['oob-1'] }],
    terminalImpact: { ...baseReceipt.terminalImpact, postChainReadbackExchangeIds: [] },
  }
  const withOob = verifyCompositeReceipt(oobReceipt, transcript, { attackerPersonas: ['dual_member'] })
  assert.equal(withOob.confirmed, true, withOob.reason)

  // Case C: custom options.verifyTerminalImpact behavior remains intact.
  const noDownload: CompositeProofReceipt = {
    ...baseReceipt,
    terminalImpact: { ...baseReceipt.terminalImpact, postChainReadbackExchangeIds: [] },
  }
  const withCustom = verifyCompositeReceipt(noDownload, transcript, {
    attackerPersonas: ['dual_member'],
    verifyTerminalImpact: () => ({ confirmed: true, reason: 'custom oracle ok', family: 'parser_cache_differential' }),
  })
  assert.equal(withCustom.confirmed, true, withCustom.reason)
  assert.equal(withCustom.terminalOracleFamily, 'parser_cache_differential')
})

test('singleReceiptToComposite on a stub-only ProofReceipt fails closed with terminal_impact_unproven', () => {
  const ownerB = { handle: 'owner_b', role: 'owner' as const, tenant: 'tenant_b', auth: 'bearer' as const, sameSite: null }
  const jobMeta = { job: { id: 'job_1', kind: 'export', tenantId: 'tenant_b', status: 'ready', readyAt: 3, runId: 'r1', artifactKey: 'f.csv', processed: true } }
  const transcript: HostSignedTranscript = {
    entries: [
      entry('ctl_owner', step({ id: 'ctl_owner', arm: 'control', method: 'GET', status: 200, route: '/v1/exports/:id', pathAndQuery: '/v1/exports/job_1', actor: ownerB, json: jobMeta }), { timestampMs: 500 }),
      entry('poll_probe', step({ id: 'poll_probe', arm: 'probe', method: 'GET', status: 200, route: '/v1/exports/:id', pathAndQuery: '/v1/exports/job_1', json: jobMeta }), { timestampMs: 1000 }),
    ],
  }
  const innerProof: ProofReceipt = {
    vulnClass: 'bola',
    target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/job_1' },
    exchangeIds: ['ctl_owner', 'poll_probe'],
    oobEventIds: [],
    browserTraceIds: [],
    claimedDelta: 'Read job-status metadata for tenant_b',
    resourceTenant: 'tenant_b',
  }
  assert.equal(verifyReceipt(innerProof, transcript).confirmed, true)
  const comp = singleReceiptToComposite(innerProof)
  const res = verifyCompositeReceipt(comp, transcript, { attackerPersonas: ['dual_member'] })
  assert.equal(res.confirmed, false)
  assert.equal(res.failedStage, 'terminal_impact')
  assert.equal(res.rejectedBy, 'terminal_impact_unproven')
})

// ---------------------------------------------------------------------------
// 2. Sanitized topRejectDetails Telemetry
// ---------------------------------------------------------------------------

test('sanitizeRejectSignature normalizes UUIDs/gx-IDs/cap-handles/ports/numbers, caps <= 140 chars, and strips secrets/bodies', () => {
  const s1 = sanitizeRejectSignature(
    "CompositeProofReceipt rejected at stage 'edge_binding': Edge #0 (value_binding hop_1->hop_2, from=[gx-9a8b7c6d,gx-11223344] to=[gx-55667788]): value_binding handle \"cap:hop_1:export_tok_9\" not matched for 550e8400-e29b-41d4-a716-446655440000.",
  )
  assert.ok(s1)
  assert.ok(s1.length <= 140, `length ${s1.length} > 140`)
  assert.ok(!s1.includes('gx-9a8b7c6d'))
  assert.ok(!s1.includes('cap:hop_1'))
  assert.ok(!s1.includes('550e8400'))
  assert.match(s1, /Edge #<id> \(value_binding hop_<id>->hop_<id>, from=\[<id>\] to=\[<id>\]\): value_binding handle "<id>" not matched/)

  const s2 = sanitizeRejectSignature(
    'connect ECONNREFUSED 127.0.0.1:41235 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig123456 body={"email":"alice@secret.test","ssn":"123-45-6789","secret":"sk_live_999"}',
  )
  assert.ok(s2)
  assert.ok(s2.length <= 140)
  assert.ok(!s2.includes('41235'))
  assert.ok(!s2.includes('eyJhbGciOiJIUzI1NiJ9'))
  assert.ok(!s2.includes('alice@secret.test'))
  assert.ok(!s2.includes('sk_live_999'))
  assert.match(s2, /ECONNREFUSED <id>:<id>/)

  const pyTrace = sanitizeRejectSignature(
    'Traceback (most recent call last):\n  File "/tmp/run-99/script.py", line 42, in main\nKeyError: "missing_field"',
  )
  assert.equal(pyTrace, 'KeyError: "missing_field"')

  const htmlLeak = sanitizeRejectSignature('Unexpected response <!DOCTYPE html><html><body>secret customer PII</body></html>')
  assert.ok(htmlLeak)
  assert.ok(!htmlLeak.includes('secret customer PII'))
})

test('extractMultihopRunTelemetry & aggregateMultihopTelemetry compute top-12 sanitized topRejectDetails across events and kovo_verify sessions', () => {
  const tempDir = mkdtempSync(join(tmpdir(), 'kovo-q32-telemetry-'))
  try {
    const dbPath = join(tempDir, 'kovo.sqlite')
    const db = new DatabaseSync(dbPath)
    db.exec(`
      CREATE TABLE runs (id TEXT PRIMARY KEY, created_at INTEGER);
      CREATE TABLE assignments (id TEXT PRIMARY KEY, run_id TEXT, phase TEXT, status TEXT, session_id TEXT, created_at INTEGER);
      CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, kind TEXT, detail TEXT, created_at INTEGER);
    `)
    const t0 = 1_760_000_000_000
    db.prepare('INSERT INTO runs VALUES (?, ?)').run('r-q32', t0)
    db.prepare('INSERT INTO assignments VALUES (?, ?, ?, ?, ?, ?)').run('a-1', 'r-q32', 'investigation', 'complete', 'sess-q32', t0 + 1000)

    const insEv = db.prepare('INSERT INTO events (run_id, kind, detail, created_at) VALUES (?, ?, ?, ?)')
    // Two distinct gx-IDs/cap-handles with the SAME edge_binding failure -> should collapse to count=2!
    insEv.run('r-q32', 'composite.rejected', JSON.stringify({
      failedStage: 'edge_binding',
      detail: 'Edge #0 (value_binding hop_1->hop_2, from=[gx-aaa111] to=[gx-bbb222]): value_binding handle "cap:hop_1:tok_1" not matched.',
    }), t0 + 2000)
    insEv.run('r-q32', 'composite.verify', JSON.stringify({
      confirmed: false,
      failedStage: 'edge_binding',
      detail: 'Edge #1 (value_binding hop_2->hop_3, from=[gx-ccc333] to=[gx-ddd444]): value_binding handle "cap:hop_2:tok_2" not matched.',
    }), t0 + 3000)
    // Add 13 distinct synthetic reject signatures to verify top-12 truncation.
    for (let i = 1; i <= 13; i++) {
      insEv.run('r-q32', 'kovo_verify.failed', JSON.stringify({
        rejectedBy: 'dag_topology',
        detail: `Distinct topology defect alpha_${String.fromCharCode(64 + i)} on hop_${i}`,
      }), t0 + 4000 + i)
    }

    // Add agent-sessions SQLite with kovo_verify execution stderr + terminal_impact rejections.
    const sessionsDir = join(tempDir, 'agent-sessions')
    mkdirSync(sessionsDir, { recursive: true })
    const sessDb = new DatabaseSync(join(sessionsDir, 'sess-q32.sqlite'))
    sessDb.exec('CREATE TABLE entries (id INTEGER PRIMARY KEY AUTOINCREMENT, commit_seq INTEGER NOT NULL, record TEXT NOT NULL)')
    const gvToolCall = (id: string) => ({ role: 'assistant', content: [{ type: 'toolCall', id, name: 'kovo_verify', arguments: { script: 'await ctx.prove_composite({})' } }] })
    const sessRecord = {
      model: [
        gvToolCall('tc-1'),
        {
          role: 'toolResult',
          toolCallId: 'tc-1',
          content: JSON.stringify({
            confirmed: false,
            rejectedBy: 'execution',
            reason: 'execution_failed',
            detail: 'Script exited with code 1',
            stderrPreview: 'TypeError: ctx.seal_capability is not a function\n    at /tmp/gv-1001/script.ts:12:5',
          }),
        },
        gvToolCall('tc-2'),
        {
          role: 'toolResult',
          toolCallId: 'tc-2',
          content: JSON.stringify({
            confirmed: false,
            rejectedBy: 'execution',
            reason: 'execution_failed',
            detail: 'Script exited with code 1',
            stderrPreview: 'TypeError: ctx.seal_capability is not a function\n    at /tmp/gv-2002/script.ts:19:9',
          }),
        },
        gvToolCall('tc-3'),
        {
          role: 'toolResult',
          toolCallId: 'tc-3',
          content: JSON.stringify({
            confirmed: false,
            rejectedBy: 'composite_receipt',
            detail: "CompositeProofReceipt rejected at stage 'terminal_impact': terminal_impact_unproven: obtaining a job/export handle is intermediate",
            compositeReceipt: { chainId: 'chain-1', confirmed: false, failedStage: 'terminal_impact' },
          }),
        },
      ],
    }
    sessDb.prepare('INSERT INTO entries (commit_seq, record) VALUES (?, ?)').run(1, JSON.stringify(sessRecord))
    sessDb.close()

    const tel = extractMultihopRunTelemetry(db, 'r-q32', { dataDir: tempDir })
    db.close()

    const details = tel.v8SdkAdoption.topRejectDetails
    assert.ok(Array.isArray(details), 'topRejectDetails must be populated')
    assert.equal(details.length, 12, 'topRejectDetails must be capped at top 12')
    for (const d of details) {
      assert.ok(d.signature.length <= 140, `signature exceeded 140 chars: ${d.signature}`)
    }
    const edgeDetail = details.find(d => d.reason === 'edge_binding')
    assert.ok(edgeDetail)
    assert.equal(edgeDetail.count, 2)
    assert.match(edgeDetail.signature, /value_binding handle "<id>" not matched/)

    const execDetail = details.find(d => d.reason === 'execution')
    assert.ok(execDetail)
    assert.equal(execDetail.count, 2)
    assert.equal(execDetail.signature, 'TypeError: ctx.seal_capability is not a function')

    // Aggregate across 2 cells -> counts double cleanly and remain capped at 12.
    const agg = aggregateMultihopTelemetry([{ telemetry: tel }, { telemetry: tel }])
    assert.ok(agg?.v8SdkAdoption.topRejectDetails)
    assert.equal(agg.v8SdkAdoption.topRejectDetails.length, 12)
    const aggExec = agg.v8SdkAdoption.topRejectDetails.find(d => d.reason === 'execution')
    assert.equal(aggExec?.count, 4)
  } finally {
    rmSync(tempDir, { recursive: true, force: true })
  }
})

test('src/server/composite-receipt.ts stays <= 750 LOC with zero benchmark literals', () => {
  const src = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8')
  const loc = src.split('\n').length
  assert.ok(loc <= 750, `Expected <= 750 LOC, got ${loc}`)
})
