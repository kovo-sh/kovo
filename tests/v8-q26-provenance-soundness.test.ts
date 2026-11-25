/**
 * Queue #26 Attacker-Origin Provenance & Composite Verification Persistence Regression Suite.
 *
 * Verifies:
 *  1. Cross-tenant probe-arm collusion bypass is CLOSED in `verifyAttackerProvenance`:
 *     mixing pre-seeded authenticated personas from distinct tenants across probe-arm hops
 *     (e.g. Hop 1 as `member_a (tenant_a)` -> Hop 2-3 as `member_b (tenant_b)`) fails closed at
 *     stage `attacker_provenance` even when both personas are low-privilege / allowed.
 *  2. Legitimate single-tenant + anonymous + DAG-minted credential + cross-tenant control/readback
 *     chains continue to CONFIRM cleanly.
 *  3. `verifyTerminalImpactGate` builds `attackerTenants` across ALL pre-seeded probe-arm hops
 *     (not only `dag.roots`), so an anonymous Hop 1 followed by a `tenant_b` Hop 2 still catches
 *     own-tenant-only payloads.
 *  4. `terminalImpact.summary`, `terminalEndpoint`, `terminalOracleFamily`, `hopCount`, `confirmed`,
 *     and `reason` persist cleanly end-to-end through `verifyCompositeReceipt` -> `VerifyRpcServer`
 *     -> `runAgentScriptProof` -> `ExecVerifier.persistAgentScriptProof` -> SQLite `Store`
 *     (`findings`, `replay_specs.spec`, `replay_specs.proof_receipt`, and replay artifact) without
 *     ever dropping to `""`, `null`, or `{}`.
 *  5. LOC ceilings (`composite-receipt.ts <= 750`, `verify-rpc.ts <= 2300`) and zero contamination.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { eq } from 'drizzle-orm'

import { extractCompositeReceipts } from '../scripts/benchmark-multihop.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'
import type { Finding } from '../src/domain.ts'
import { runAgentScriptProof } from '../src/server/agent-script-proof.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type CompositeReceiptVerification,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { DerivedCapabilityVault } from '../src/server/derived-custody.ts'
import { Execution } from '../src/server/execution.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { extractStoreCompositeReceipts } from '../src/server/receipt-export.ts'
import { findings, replaySpecs } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import type {
  VerifyScriptRequest,
  VerifyScriptResult,
  WorkerBackend,
  WorkerSession,
  WorkerSessionOptions,
} from '../src/server/worker-backend.ts'
import { setupApprovedRun } from './v4-tier-helpers.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SIGNING_KEY = 'unit-test-q26-provenance-soundness-key-0123456789'

function makeSignedEntry(
  exchangeId: string,
  opts: {
    arm: 'control' | 'probe'
    method: string
    pathAndQuery?: string
    route?: string
    status: number
    timestampMs: number
    actorPersona?: string | null
    actorRole?: 'viewer' | 'member' | 'admin' | 'owner' | null
    actorTenant?: string | null
    actorRoleLabel?: string | null
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    cryptoAttestations?: HostTranscriptEntry['cryptoAttestations']
    json?: unknown
    body?: string
    evidenceRole?: string
  },
): HostTranscriptEntry {
  const actor = opts.actorPersona !== undefined ? opts.actorPersona : 'member_b'
  const role = opts.actorRole !== undefined ? opts.actorRole : (actor ? 'member' : null)
  const tenant = opts.actorTenant !== undefined ? opts.actorTenant : (actor ? 'tenant_b' : null)
  const roleLabel = opts.actorRoleLabel !== undefined
    ? opts.actorRoleLabel
    : (actor ? `${role ?? 'member'} (${tenant ?? 'tenant_b'})` : null)
  const route = opts.route !== undefined ? opts.route : (opts.pathAndQuery ? opts.pathAndQuery.split('?')[0]! : undefined)
  const entry: HostTranscriptEntry = {
    exchangeId,
    timestampMs: opts.timestampMs,
    actorPersona: actor,
    actorRoleLabel: roleLabel,
    cleanSession: true,
    ...(opts.emittedCapabilities ? { emittedCapabilities: opts.emittedCapabilities } : {}),
    ...(opts.consumedCapabilities ? { consumedCapabilities: opts.consumedCapabilities } : {}),
    ...(opts.cryptoAttestations ? { cryptoAttestations: opts.cryptoAttestations } : {}),
    ...(opts.evidenceRole ? { evidenceRole: opts.evidenceRole } : {}),
    step: {
      id: exchangeId,
      arm: opts.arm,
      method: opts.method,
      ...(route !== undefined ? { route } : {}),
      ...(opts.pathAndQuery !== undefined ? { pathAndQuery: opts.pathAndQuery } : {}),
      status: opts.status,
      actor: {
        handle: actor,
        role,
        tenant,
        auth: actor ? 'bearer' : 'unknown',
        sameSite: null,
      },
      ...(opts.json !== undefined ? { json: opts.json } : {}),
      ...(opts.body !== undefined ? { body: opts.body } : {}),
    },
  }
  return { ...entry, hostSignature: signHostRecord(entry, SIGNING_KEY) }
}

// ============================================================================
// 1. Cross-Tenant Probe-Arm Collusion Bypass is CLOSED
// ============================================================================

test('verifyAttackerProvenance rejects cross-tenant pre-seeded probe-arm collusion across hops and within a single hop', () => {
  const exportUrlCap = 'cap:hop_1:export_url'
  const downloadTokCap = 'cap:hop_2:download_tok'

  const collusionTranscript: HostSignedTranscript = {
    entries: [
      // Clean denied control as member_b (tenant_b) on terminal route
      makeSignedEntry('ex-ctrl-403', {
        arm: 'control', method: 'GET', pathAndQuery: '/api/exports/exp-a-1/download', status: 403, timestampMs: 800,
        actorPersona: 'member_b', actorTenant: 'tenant_b',
      }),
      // Hop 1: pre-seeded TARGET-TENANT persona member_a (tenant_a) legitimately creates export URL!
      makeSignedEntry('ex-hop1-member-a', {
        arm: 'probe', method: 'POST', pathAndQuery: '/api/exports', status: 200, timestampMs: 1000,
        actorPersona: 'member_a', actorTenant: 'tenant_a',
        emittedCapabilities: [exportUrlCap],
        json: { exportId: 'exp-a-1', signedUrl: '/api/exports/exp-a-1/download?sig=legit-a' },
      }),
      // Hop 2: DIFFERENT pre-seeded tenant persona member_b (tenant_b) receives the handle!
      makeSignedEntry('ex-hop2-member-b', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/exports/exp-a-1/meta', status: 200, timestampMs: 1100,
        actorPersona: 'member_b', actorTenant: 'tenant_b',
        consumedCapabilities: [exportUrlCap], emittedCapabilities: [downloadTokCap],
        json: { downloadToken: 'dl-tok-1' },
      }),
      // Hop 3: member_b downloads tenant_a data using the colluded handle
      makeSignedEntry('ex-hop3-member-b', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/exports/exp-a-1/download', status: 200, timestampMs: 1200,
        actorPersona: 'member_b', actorTenant: 'tenant_b',
        consumedCapabilities: [downloadTokCap],
        json: { tenantId: 'tenant_a', records: [{ id: 'tr-1', ownerEmail: 'cfo@tenant-a.test', balanceCents: 990000 }] },
      }),
    ],
  }

  const collusionReceipt = {
    chainId: 'chain-q26-collusion-3hop',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/exports' },
        exchangeIds: ['ex-hop1-member-a'], producedCapabilities: [exportUrlCap],
        claimedDelta: 'Target-tenant member created signed export URL.',
      },
      {
        hopId: 'hop_2', surface: 'http',
        target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/exports/exp-a-1/meta' },
        exchangeIds: ['ex-hop2-member-b'], consumedCapabilities: [exportUrlCap], producedCapabilities: [downloadTokCap],
        claimedDelta: 'Cross-tenant member resolved download token.',
      },
      {
        hopId: 'hop_3', surface: 'storage',
        target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/exports/exp-a-1/download' },
        exchangeIds: ['ex-hop3-member-b'], consumedCapabilities: [downloadTokCap],
        claimedDelta: 'Downloaded tenant_a confidential records.',
      },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: exportUrlCap },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: downloadTokCap },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      summary: 'Cross-tenant export download exposed tenant_a confidential treasury records.',
      terminalExchangeId: 'ex-hop3-member-b',
      preChainControlExchangeIds: ['ex-ctrl-403'],
    },
    replayMode: 'fresh_clean_replay',
  }

  // (a) Even when BOTH member_a and member_b are in attackerPersonas -> MUST REJECT at attacker_provenance!
  const resBothAllowed = verifyCompositeReceipt(collusionReceipt, collusionTranscript, {
    attackerPersonas: ['member_a', 'member_b'],
    signingKey: SIGNING_KEY,
  })
  assert.equal(resBothAllowed.confirmed, false)
  assert.equal(resBothAllowed.failedStage, 'attacker_provenance')
  assert.match(resBothAllowed.reason, /Cross-tenant probe-arm persona mismatch/i)
  assert.match(resBothAllowed.reason, /tenant_a, tenant_b/)
  assert.match(resBothAllowed.reason, /control or readback arms/i)

  // (b) Even when attackerPersonas is omitted (default non-owner policy) -> MUST REJECT at attacker_provenance!
  const resDefault = verifyCompositeReceipt(collusionReceipt, collusionTranscript, { signingKey: SIGNING_KEY })
  assert.equal(resDefault.confirmed, false)
  assert.equal(resDefault.failedStage, 'attacker_provenance')
  assert.match(resDefault.reason, /Cross-tenant probe-arm persona mismatch/i)

  // (c) Single hop mixing two pre-seeded probe exchanges from distinct tenants -> MUST REJECT!
  const singleHopMix = verifyCompositeReceipt({
    chainId: 'chain-q26-single-hop-mix',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      {
        hopId: 'hop_1', surface: 'http',
        target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/exports/exp-a-1/download' },
        exchangeIds: ['ex-hop1-member-a', 'ex-hop3-member-b'],
        claimedDelta: 'Mixed tenant_a and tenant_b probes in one hop.',
      },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      summary: 'Mixed-tenant probes read confidential tenant_a records.',
      terminalExchangeId: 'ex-hop3-member-b',
      preChainControlExchangeIds: ['ex-ctrl-403'],
    },
    replayMode: 'fresh_clean_replay',
  }, collusionTranscript, { attackerPersonas: ['member_a', 'member_b'], signingKey: SIGNING_KEY })
  assert.equal(singleHopMix.confirmed, false)
  assert.equal(singleHopMix.failedStage, 'attacker_provenance')
  assert.match(singleHopMix.reason, /Cross-tenant probe-arm persona mismatch/i)
})

// ============================================================================
// 2. Legitimate Single-Tenant, Anonymous, DAG-Minted, and Cross-Tenant Control Arms PASS
// ============================================================================

test('verifyAttackerProvenance allows anonymous + single-tenant, DAG-minted credentials, same-tenant peers, and target-tenant control/readback arms', () => {
  const keyCap = 'cap:hop_1:signing_key'
  const jwtCap = 'cap:hop_2:forged_tenant_a_jwt'
  const digest = sha256Hex('forged-tenant-a-jwt-bytes')

  const transcript: HostSignedTranscript = {
    entries: [
      // Control arm as member_b (tenant_b) denied on terminal endpoint
      makeSignedEntry('ex-ctrl-b-403', {
        arm: 'control', method: 'GET', pathAndQuery: '/api/vault/records', status: 403, timestampMs: 700,
        actorPersona: 'member_b', actorTenant: 'tenant_b',
      }),
      // Target-tenant owner control readback (arm: 'control') — MUST NOT trip probe-arm collusion!
      makeSignedEntry('ex-ctrl-owner-a-200', {
        arm: 'control', method: 'GET', pathAndQuery: '/api/vault/records', status: 200, timestampMs: 1400,
        actorPersona: 'owner_a', actorRole: 'owner', actorTenant: 'tenant_a',
        json: { tenantId: 'tenant_a', mutated: true, amountCents: 75000 },
      }),
      // Anonymous Hop 1 leaking public config key handle
      makeSignedEntry('ex-anon-hop1', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/public/runtime', status: 200, timestampMs: 900,
        actorPersona: null, actorRole: null, actorTenant: null, actorRoleLabel: null,
        emittedCapabilities: [keyCap],
        json: { ok: true, keyRef: 'k1' },
      }),
      // Authenticated Hop 1 as viewer_b (tenant_b)
      makeSignedEntry('ex-viewer-b-hop1', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/runtime/key', status: 200, timestampMs: 950,
        actorPersona: 'viewer_b', actorRole: 'viewer', actorTenant: 'tenant_b',
        emittedCapabilities: [keyCap],
        json: { ok: true, keyRef: 'k1' },
      }),
      // Hop 2 as member_b (same tenant_b!) deriving a tenant_a JWT via Layer 1
      makeSignedEntry('ex-member-b-hop2-derive', {
        arm: 'probe', method: 'POST', pathAndQuery: '/api/token/exchange', status: 200, timestampMs: 1100,
        actorPersona: 'member_b', actorTenant: 'tenant_b',
        consumedCapabilities: [keyCap], emittedCapabilities: [jwtCap],
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: jwtCap, alg: 'HS256', artifactDigest: digest, timestampMs: 1050 }],
        json: { ok: true },
      }),
      // Hop 3 using ONLY the freshly minted DAG-derived JWT (actorPersona: null, even if step.actor.tenant were tenant_a!)
      makeSignedEntry('ex-dag-minted-hop3', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/vault/records', status: 200, timestampMs: 1200,
        actorPersona: null, actorRole: null, actorTenant: 'tenant_a', actorRoleLabel: null,
        consumedCapabilities: [jwtCap],
        cryptoAttestations: [{ derivedFromCapabilityId: keyCap, derivedCapabilityId: jwtCap, alg: 'HS256', artifactDigest: digest, timestampMs: 1050 }],
        json: { tenantId: 'tenant_a', records: [{ id: 'v-1', ownerEmail: 'ceo@tenant-a.test', amountCents: 880000 }] },
      }),
    ],
  }

  // (a) Same-tenant peers (viewer_b + member_b, both tenant_b) + DAG-minted Hop 3 + owner_a control readback -> PASS!
  const sameTenantPlusDag = verifyCompositeReceipt({
    chainId: 'chain-q26-same-tenant-dag',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/runtime/key' }, exchangeIds: ['ex-viewer-b-hop1'], producedCapabilities: [keyCap], claimedDelta: 'Obtained signing key handle.' },
      { hopId: 'hop_2', surface: 'idp', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/token/exchange' }, exchangeIds: ['ex-member-b-hop2-derive'], consumedCapabilities: [keyCap], producedCapabilities: [jwtCap], claimedDelta: 'Derived forged scoped JWT.' },
      { hopId: 'hop_3', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET' }, exchangeIds: ['ex-dag-minted-hop3', 'ex-ctrl-owner-a-200'], consumedCapabilities: [jwtCap], claimedDelta: 'Accessed tenant_a vault records.' },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap, derivedCapabilityId: jwtCap, alg: 'HS256' },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: jwtCap },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      // Intentionally supply claimedImpact WITHOUT summary to verify backfill!
      claimedImpact: 'Forged HS256 token granted unauthorized access to tenant_a vault records.',
      terminalExchangeId: 'ex-dag-minted-hop3',
      preChainControlExchangeIds: ['ex-ctrl-b-403'],
      postChainReadbackExchangeIds: ['ex-ctrl-owner-a-200'],
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['viewer_b', 'member_b'], forbiddenShortcutPersonas: ['owner_a'], signingKey: SIGNING_KEY })

  assert.equal(sameTenantPlusDag.confirmed, true, sameTenantPlusDag.reason)
  assert.equal(sameTenantPlusDag.terminalOracleFamily, 'cryptographic_scope_replay')
  assert.equal(sameTenantPlusDag.terminalEndpoint, '/api/vault/records')
  assert.equal(sameTenantPlusDag.evidence?.terminalOracleFamily, 'cryptographic_scope_replay')
  assert.equal(sameTenantPlusDag.evidence?.terminalEndpoint, '/api/vault/records')

  // (b) Anonymous Hop 1 -> member_b (tenant_b) Hop 2 -> DAG-minted Hop 3 -> PASS!
  const anonRootChain = verifyCompositeReceipt({
    chainId: 'chain-q26-anon-root',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/public/runtime' }, exchangeIds: ['ex-anon-hop1'], producedCapabilities: [keyCap], claimedDelta: 'Anonymous leak of signing key handle.' },
      { hopId: 'hop_2', surface: 'idp', target: { origin: 'https://api.example.test', method: 'POST', pathAndQuery: '/api/token/exchange' }, exchangeIds: ['ex-member-b-hop2-derive'], consumedCapabilities: [keyCap], producedCapabilities: [jwtCap], claimedDelta: 'Derived forged scoped JWT as member_b.' },
      { hopId: 'hop_3', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/vault/records' }, exchangeIds: ['ex-dag-minted-hop3'], consumedCapabilities: [jwtCap], claimedDelta: 'Read tenant_a records.' },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'hop_1', toHopId: 'hop_2', sourceCapabilityId: keyCap, derivedCapabilityId: jwtCap, alg: 'HS256' },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: jwtCap },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      summary: 'Anonymous key disclosure chained with member_b exposed tenant_a vault records.',
      terminalExchangeId: 'ex-dag-minted-hop3',
      preChainControlExchangeIds: ['ex-ctrl-b-403'],
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { signingKey: SIGNING_KEY })
  assert.equal(anonRootChain.confirmed, true, anonRootChain.reason)
  assert.equal(anonRootChain.terminalOracleFamily, 'cryptographic_scope_replay')
  assert.equal(anonRootChain.terminalEndpoint, '/api/vault/records')
})

// ============================================================================
// 3. attackerTenants includes non-root pre-seeded probe hops (anonymous Hop 1 + tenant_b Hop 2)
// ============================================================================

test('verifyTerminalImpactGate tracks attackerTenants across ALL pre-seeded probe hops so anonymous Hop 1 + own-tenant Hop 2 still rejects', () => {
  const cap = 'cap:hop_1:anon_tok'
  const transcript: HostSignedTranscript = {
    entries: [
      makeSignedEntry('ex-ctrl-403', {
        arm: 'control', method: 'GET', pathAndQuery: '/api/exports/dl', status: 403, timestampMs: 800,
        actorPersona: 'member_b', actorTenant: 'tenant_b',
      }),
      makeSignedEntry('ex-anon-1', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/public/init', status: 200, timestampMs: 1000,
        actorPersona: null, actorRole: null, actorTenant: null, actorRoleLabel: null,
        emittedCapabilities: [cap], json: { token: 'pub-init-1' },
      }),
      // Hop 2 authenticates as member_b (tenant_b) and returns ONLY tenant_b's own records!
      makeSignedEntry('ex-own-2', {
        arm: 'probe', method: 'GET', pathAndQuery: '/api/exports/dl', status: 200, timestampMs: 1200,
        actorPersona: 'member_b', actorTenant: 'tenant_b',
        consumedCapabilities: [cap],
        json: { tenantId: 'tenant_b', records: [{ id: 'own-rec-1', amountCents: 100 }] },
      }),
    ],
  }

  const ownTenantAfterAnonRoot = verifyCompositeReceipt({
    chainId: 'chain-q26-anon-root-own-tenant',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/public/init' }, exchangeIds: ['ex-anon-1'], producedCapabilities: [cap], claimedDelta: 'Anon init.' },
      { hopId: 'hop_2', surface: 'http', target: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/api/exports/dl' }, exchangeIds: ['ex-own-2'], consumedCapabilities: [cap], claimedDelta: 'Fetched export.' },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Attempted cross-tenant export after anonymous hop 1.',
      terminalExchangeId: 'ex-own-2',
      preChainControlExchangeIds: ['ex-ctrl-403'],
    },
    replayMode: 'fresh_clean_replay',
  }, transcript, { signingKey: SIGNING_KEY })

  assert.equal(ownTenantAfterAnonRoot.confirmed, false)
  assert.equal(ownTenantAfterAnonRoot.failedStage, 'terminal_impact')
  assert.equal(ownTenantAfterAnonRoot.rejectedBy, 'terminal_impact_unproven')
})

// ============================================================================
// 4. End-to-End VerifyRpcServer -> runAgentScriptProof -> persistAgentScriptProof -> Store
// ============================================================================

function rpcCall(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        try {
          resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; result?: unknown; error?: string })
        } catch (err) {
          rejectPromise(err)
        }
      })
    })
    req.on('error', rejectPromise)
    req.end(payload)
  })
}

function makePersona(handle: string, roleLabel: string, token: string, origin: string): ResolvedPersona {
  return {
    id: `persona-${handle}`,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: null,
    secret: token,
    canaryMarkers: [],
  }
}

function makeGrant(origin: string, personas: ResolvedPersona[]): Grant {
  return {
    canRead: (candidate: string) => {
      try { return new URL(candidate).origin === origin } catch { return false }
    },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map(p => [p.handle, p])),
  }
}

function makeMockBackend(
  handler: (ctx: { socketPath: string; token: string; req: VerifyScriptRequest }) => Promise<VerifyScriptResult>,
): WorkerBackend {
  return {
    run: async () => { throw new Error('unused') },
    verifyStaticAst: async () => { throw new Error('unused') },
    async openSession(_assignmentId: string, _signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
      const dir = options?.rpcMountDir ?? ''
      return {
        stage: async () => { throw new Error('unused') },
        analyze: async () => { throw new Error('unused') },
        sast: async () => { throw new Error('unused') },
        runScript: async () => { throw new Error('unused') },
        verifyStaticAst: async () => { throw new Error('unused') },
        exec: async () => ({ stdout: '', stderr: '', exitCode: 0, outputs: {}, timedOut: false }),
        verifyScript: async (req) => handler({
          socketPath: join(dir, VERIFY_RPC_SOCKET_NAME),
          token: readFileSync(join(dir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim(),
          req,
        }),
        close: async () => undefined,
      }
    },
  }
}

test('end-to-end: VerifyRpcServer rejects cross-tenant collusion and persists non-empty compositeVerification, terminalOracleFamily, terminalEndpoint, and terminalImpact.summary', async (t) => {
  // Real local loopback HTTP server with two tenants: tenant_a and tenant_b.
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    res.setHeader('content-type', 'application/json')

    if (url.pathname === '/api/exports' && req.method === 'POST') {
      if (auth !== 'Bearer tok-member-a' && auth !== 'Bearer tok-member-b') {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      res.statusCode = 200
      res.end(JSON.stringify({
        exportId: 'exp-99',
        exportToken: auth === 'Bearer tok-member-a' ? 'tok_export_a_only_12345' : 'tok_export_b_pivot_98765',
      }))
      return
    }

    if (url.pathname === '/api/exports/exp-99/download' && req.method === 'GET') {
      const hdr = String(req.headers['x-export-token'] ?? '')
      if (hdr === 'tok_export_a_only_12345' || hdr === 'tok_export_b_pivot_98765') {
        res.statusCode = 200
        res.end(JSON.stringify({
          tenantId: 'tenant_a',
          records: [{ id: 'inv-a-1', ownerEmail: 'treasury@tenant-a.test', amountCents: 650000 }],
        }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden_cross_tenant_export' }))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not_found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as { port: number }).port
  const origin = `http://127.0.0.1:${port}`
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })

  const dir = mkdtempSync(join(tmpdir(), 'guardian-v8-q26-prov-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!
  const assignment = storage.makeWorker(run, 'investigation', asset, 'Multi-hop provenance test worker', 'Verify provenance and persistence')
  const broker = new RequestBroker({ rejectUnauthorized: false })
  const grant = makeGrant(origin, [
    makePersona('member_a', 'member (tenant_a)', 'tok-member-a', origin),
    makePersona('member_b', 'member (tenant_b)', 'tok-member-b', origin),
  ])

  // (a) Collusion script: Hop 1 as member_a (tenant_a) -> Hop 2 as member_b (tenant_b) MUST FAIL CLOSED!
  const collusionVault = new DerivedCapabilityVault({ runId: `${runId}-collusion` })
  const collusionBackend = makeMockBackend(async ({ socketPath, token, req }) => {
    const ctrl = await rpcCall(socketPath, token, req.nonce, 'http.send', {
      origin, method: 'GET', path: '/api/exports/exp-99/download', persona: 'member_b', sessionGroupRole: 'control',
    })
    const h1 = await rpcCall(socketPath, token, req.nonce, 'http.send', {
      origin, method: 'POST', path: '/api/exports', persona: 'member_a', sessionGroupRole: 'probe',
    })
    const h1ExId = (h1.result as { exchangeId: string }).exchangeId
    const seal = await rpcCall(socketPath, token, req.nonce, 'capability.seal', {
      exchangeId: h1ExId, hopReceiptId: 'hop_1', slot: 'export_tok', kind: 'header_secret',
      defaultHeaderName: 'x-export-token', jsonPath: 'exportToken', allowedOrigins: [origin],
    })
    const capHandle = (seal.result as { handle: string }).handle
    const h2 = await rpcCall(socketPath, token, req.nonce, 'http.send', {
      origin, method: 'GET', path: '/api/exports/exp-99/download', persona: 'member_b', sessionGroupRole: 'probe',
      capability: { handle: capHandle, target: 'header', headerName: 'x-export-token' },
    })
    const h2ExId = (h2.result as { exchangeId: string }).exchangeId
    const verified = await rpcCall(socketPath, token, req.nonce, 'composite.verify', {
      chainId: 'chain-q26-live-collusion',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: [h1ExId], producedCapabilities: [capHandle], claimedDelta: 'member_a minted export token.' },
        { hopId: 'hop_2', surface: 'storage', target: { origin, method: 'GET', pathAndQuery: '/api/exports/exp-99/download' }, exchangeIds: [h2ExId], consumedCapabilities: [capHandle], claimedDelta: 'member_b downloaded tenant_a export.' },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: capHandle }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        summary: 'Colluded cross-tenant export download exposed tenant_a records.',
        terminalExchangeId: h2ExId,
        preChainControlExchangeIds: [(ctrl.result as { exchangeId: string }).exchangeId],
      },
      replayMode: 'fresh_clean_replay',
    })
    const verObj = verified.result as { confirmed: boolean; failedStage?: string; rejectedBy?: string; claim: Record<string, unknown> }
    assert.equal(verObj.confirmed, false)
    assert.equal(verObj.failedStage, 'attacker_provenance')
    return {
      runtime: req.runtime,
      result: { sdk: 'guardian_verify.ts', nonce: req.nonce, claims: [verObj.claim] },
      stdout: '', stderr: '', exitCode: 0, durationMs: 5, timedOut: false,
    }
  })

  const collusionProof = await runAgentScriptProof({
    script: '// collusion test script',
    runtime: 'ts',
    broker,
    grant,
    backend: collusionBackend,
    runId,
    assignmentId: assignment.id,
    targetOrigins: [origin],
    signal: AbortSignal.timeout(15_000),
    capabilityVault: collusionVault,
  })
  assert.equal(collusionProof.verdict.confirmed, false)
  assert.equal(collusionProof.compositeReceipt?.verification.confirmed, false)
  assert.equal(collusionProof.compositeReceipt?.verification.failedStage, 'attacker_provenance')
  assert.match(collusionProof.verdict.detail ?? '', /Cross-tenant probe-arm persona mismatch/i)

  // (b) Legitimate single-tenant script (all probe hops as member_b, claimedImpact without summary,
  //     and terminal hop omitting target.pathAndQuery) -> CONFIRMS and persists EVERY field cleanly!
  const legitVault = new DerivedCapabilityVault({ runId: `${runId}-legit` })
  const legitBackend = makeMockBackend(async ({ socketPath, token, req }) => {
    const ctrl = await rpcCall(socketPath, token, req.nonce, 'http.send', {
      origin, method: 'GET', path: '/api/exports/exp-99/download', persona: 'member_b', sessionGroupRole: 'control',
    })
    const h1 = await rpcCall(socketPath, token, req.nonce, 'http.send', {
      origin, method: 'POST', path: '/api/exports', persona: 'member_b', sessionGroupRole: 'probe',
    })
    const h1ExId = (h1.result as { exchangeId: string }).exchangeId
    const seal = await rpcCall(socketPath, token, req.nonce, 'capability.seal', {
      exchangeId: h1ExId, hopReceiptId: 'hop_1', slot: 'export_tok', kind: 'header_secret',
      defaultHeaderName: 'x-export-token', jsonPath: 'exportToken', allowedOrigins: [origin],
    })
    const capHandle = (seal.result as { handle: string }).handle
    const h2 = await rpcCall(socketPath, token, req.nonce, 'http.send', {
      origin, method: 'GET', path: '/api/exports/exp-99/download', persona: 'member_b', sessionGroupRole: 'probe',
      capability: { handle: capHandle, target: 'header', headerName: 'x-export-token' },
    })
    const h2ExId = (h2.result as { exchangeId: string }).exchangeId
    const verified = await rpcCall(socketPath, token, req.nonce, 'composite.verify', {
      chainId: 'chain-q26-legit-persist',
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin, method: 'POST', pathAndQuery: '/api/exports' }, exchangeIds: [h1ExId], producedCapabilities: [capHandle], claimedDelta: 'member_b minted export token.' },
        // Deliberately omit pathAndQuery on terminal hop target to test terminalEndpoint backfill!
        { hopId: 'hop_2', surface: 'storage', target: { origin, method: 'GET' }, exchangeIds: [h2ExId], consumedCapabilities: [capHandle], claimedDelta: 'member_b downloaded tenant_a export.' },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: capHandle }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        // Deliberately supply claimedImpact without summary to test summary backfill!
        claimedImpact: 'Single-tenant member_b chain exposed tenant_a confidential export records.',
        terminalExchangeId: h2ExId,
        preChainControlExchangeIds: [(ctrl.result as { exchangeId: string }).exchangeId],
      },
      replayMode: 'fresh_clean_replay',
    })
    const verObj = verified.result as {
      confirmed: boolean
      terminalOracleFamily?: string
      terminalEndpoint?: string
      claim: Record<string, unknown>
    }
    assert.equal(verObj.confirmed, true, JSON.stringify(verObj))
    assert.equal(verObj.terminalOracleFamily, 'dual_tenant_abac')
    assert.equal(verObj.terminalEndpoint, '/api/exports/exp-99/download')
    return {
      runtime: req.runtime,
      result: {
        sdk: 'guardian_verify.ts',
        nonce: req.nonce,
        title: 'Cross-tenant export token bypass exposing tenant_a records',
        severity: 'high',
        claims: [verObj.claim],
      },
      stdout: '', stderr: '', exitCode: 0, durationMs: 6, timedOut: false,
    }
  })

  const legitProof = await runAgentScriptProof({
    script: '// legit composite proof script',
    runtime: 'ts',
    title: 'Cross-tenant export token bypass exposing tenant_a records',
    broker,
    grant,
    backend: legitBackend,
    runId,
    assignmentId: assignment.id,
    targetOrigins: [origin],
    signal: AbortSignal.timeout(15_000),
    capabilityVault: legitVault,
  })
  assert.equal(legitProof.verdict.confirmed, true, legitProof.verdict.detail)
  assert.equal(legitProof.compositeReceipt?.verification.confirmed, true)
  assert.equal(legitProof.compositeReceipt?.verification.terminalOracleFamily, 'dual_tenant_abac')
  assert.equal(legitProof.compositeReceipt?.verification.terminalEndpoint, '/api/exports/exp-99/download')
  assert.equal(
    legitProof.compositeReceipt?.receipt.terminalImpact.summary,
    'Single-tenant member_b chain exposed tenant_a confidential export records.',
  )
  assert.equal(legitProof.compositeReceipt?.receipt.hops[1]?.target.pathAndQuery, '/api/exports/exp-99/download')

  // Persist through Execution.persistAgentScriptProof -> SQLite Store and inspect ALL persisted views!
  const execution = new Execution(storage, { broker })
  t.after(() => { void execution.stop() })
  const persisted = (execution as unknown as {
    persistAgentScriptProof: (arg: Record<string, unknown>) => { findingId: string; replaySpecId: string; receiptId: string | null }
  }).persistAgentScriptProof({
    run,
    assignment,
    script: '// legit composite proof script',
    runtime: 'ts',
    title: 'Cross-tenant export token bypass exposing tenant_a records',
    proof: legitProof,
    secrets: [],
  })
  assert.equal(persisted.receiptId, 'chain-q26-legit-persist')

  // 1) findings table -> finding.evidence.compositeVerification & compositeReceipt
  const findingRows = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(findingRows.length, 1)
  const findingEv = (findingRows[0]!.finding as Finding & {
    evidence?: {
      compositeReceipt?: CompositeProofReceipt
      compositeVerification?: CompositeReceiptVerification
      terminalOracleFamily?: string
      terminalEndpoint?: string
    }
  }).evidence
  assert.ok(findingEv?.compositeVerification)
  assert.equal(findingEv.compositeVerification.confirmed, true)
  assert.equal(findingEv.compositeVerification.hopCount, 2)
  assert.equal(findingEv.compositeVerification.terminalOracleFamily, 'dual_tenant_abac')
  assert.equal(findingEv.compositeVerification.terminalEndpoint, '/api/exports/exp-99/download')
  assert.ok((findingEv.compositeVerification.reason ?? '').length > 10)
  assert.equal(findingEv.terminalOracleFamily, 'dual_tenant_abac')
  assert.equal(findingEv.terminalEndpoint, '/api/exports/exp-99/download')
  assert.equal(
    findingEv.compositeReceipt?.terminalImpact.summary,
    'Single-tenant member_b chain exposed tenant_a confidential export records.',
  )

  // 2) replay_specs.proof_receipt JSON column -> serializeCompositeProofReceiptRow output
  const specRows = storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, runId)).all()
  assert.equal(specRows.length, 1)
  const proofReceiptCol = specRows[0]!.proofReceipt as unknown as {
    receipt: { target: { pathAndQuery?: string } }
    compositeReceipt: CompositeProofReceipt
    compositeVerification: CompositeReceiptVerification
    hopActors: Record<string, string | null>
  }
  assert.equal(proofReceiptCol.receipt.target.pathAndQuery, '/api/exports/exp-99/download')
  assert.equal(proofReceiptCol.compositeVerification.confirmed, true)
  assert.equal(proofReceiptCol.compositeVerification.hopCount, 2)
  assert.equal(proofReceiptCol.compositeVerification.terminalOracleFamily, 'dual_tenant_abac')
  assert.equal(proofReceiptCol.compositeVerification.terminalEndpoint, '/api/exports/exp-99/download')
  assert.ok(proofReceiptCol.compositeVerification.reason.length > 10)
  assert.equal(
    proofReceiptCol.compositeReceipt.terminalImpact.summary,
    'Single-tenant member_b chain exposed tenant_a confidential export records.',
  )
  assert.deepEqual(proofReceiptCol.hopActors, { hop_1: 'member_b', hop_2: 'member_b' })

  // 3) Downstream extractors (`benchmark-multihop.ts` and `receipt-export.ts`) see non-empty verification!
  const detail = storage.runDetail(runId)
  const benchExtracted = extractCompositeReceipts({
    findings: detail.findings as Finding[],
    replaySpecs: detail.replaySpecs.map(r => ({ id: r.id, findingId: r.findingId, spec: r.spec })),
  })
  assert.equal(benchExtracted.length, 1)
  assert.equal(benchExtracted[0]!.confirmed, true)
  assert.equal(benchExtracted[0]!.verification?.terminalOracleFamily, 'dual_tenant_abac')
  assert.equal(benchExtracted[0]!.verification?.terminalEndpoint, '/api/exports/exp-99/download')

  const exportExtracted = extractStoreCompositeReceipts(specRows)
  assert.equal(exportExtracted.length, 1)
  const exportedVer = exportExtracted[0]!.verification as CompositeReceiptVerification | undefined
  assert.equal(exportedVer?.confirmed, true)
  assert.equal(exportedVer?.terminalOracleFamily, 'dual_tenant_abac')
  assert.equal(exportedVer?.terminalEndpoint, '/api/exports/exp-99/download')
})

// ============================================================================
// 5. LOC Ceilings & Anti-Contamination Gate
// ============================================================================

test('composite-receipt.ts <= 750 LOC, verify-rpc.ts <= 2300 LOC, and zero v8 benchmark contamination', () => {
  const compositeLoc = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8').trimEnd().split('\n').length
  const verifyRpcLoc = readFileSync(join(REPO_ROOT, 'src/server/verify-rpc.ts'), 'utf8').trimEnd().split('\n').length
  assert.ok(compositeLoc <= 750, `composite-receipt.ts is ${compositeLoc} LOC (ceiling <= 750)`)
  assert.ok(verifyRpcLoc <= 2300, `verify-rpc.ts is ${verifyRpcLoc} LOC (ceiling <= 2300)`)

  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `Unexpected benchmark contamination: ${JSON.stringify(scan.hits)}`)
  assert.deepEqual(scan.hits, [])
})
