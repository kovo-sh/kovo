/**
 * WS-5 (R4-C-5 Provenance, R4-H-5 Object-Bound Control & Auto-DAG, R4-H-6 Per-Exchange Tenant Privilege)
 * Fast Class-Level Guard Suite for `scripts/worker-gate.sh`.
 *
 * Verifies:
 *  1. R4-C-5: Every exchange ID named inside `terminalImpact.oracleInput` (including uncited
 *     `sourceValidIssuance` / `issuanceExchangeId` / `actions` / `replayedAcceptance`) flows through
 *     the shared cited-records collector into `verifyAttackerProvenance`; admin-issued uncited
 *     issuance is rejected at `attacker_provenance` (even if tagged `arm='control'`).
 *  2. R4-H-5: Honest per-object RBAC (list -> GET own object 200 + GET foreign sibling object 403)
 *     NEVER confirms `bola`, `idor`, `broken_access_control`, `bfla`, or `cross_tenant_read`,
 *     whether causal edges are explicit OR auto-inferred; cross-persona controls on DAG-cap hops
 *     are strictly rejected (`!termUsesDagCap` skip removed); auto-inferred edges never unlock
 *     sibling-ID controls even with same-owner metadata.
 *  3. R4-H-6: `buildCompositeVerifyOptionsFromGrant` keeps mixed-role dual-membership personas
 *     (`admin (org_a), member (org_b)`) in `forbiddenShortcutPersonas` by default; dual-membership
 *     personas acting on their own admin tenant (via route tenant, 0 markers, or 2+ markers, on
 *     terminal OR non-terminal hops) or with ambiguous acting tenant MUST reject across `bfla`,
 *     `privilege_escalation`, `bola`, `idor`, and `dual_tenant_abac`, while legitimate explicit
 *     `dual_tenant_abac` targeting a host-bound non-admin tenant confirms cleanly.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { buildCompositeVerifyOptionsFromGrant } from '../src/server/agent-script-proof.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'r4-ws5-composite-binding-signing-key-0123456789abcdef'

function makeStep(
  partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>,
): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? {
      handle: 'member_a',
      role: 'member',
      tenant: 'org_a',
      auth: 'bearer',
      sameSite: null,
    },
    ...(partial.route !== undefined
      ? { route: partial.route }
      : partial.pathAndQuery
        ? { route: partial.pathAndQuery.split('?')[0]! }
        : {}),
    ...(partial.pathAndQuery !== undefined ? { pathAndQuery: partial.pathAndQuery } : {}),
    ...(partial.json !== undefined ? { json: partial.json } : {}),
    ...(partial.body !== undefined ? { body: partial.body } : {}),
    ...(partial.requestJson !== undefined ? { requestJson: partial.requestJson } : {}),
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
    ...(partial.evidenceRole !== undefined ? { evidenceRole: partial.evidenceRole } : {}),
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    origin: extra.origin ?? ORIGIN,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    actorRoleLabel: extra.actorRoleLabel !== undefined
      ? extra.actorRoleLabel
      : (step.actor.role && step.actor.tenant ? `${step.actor.role} (${step.actor.tenant})` : null),
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

// ============================================================================
// 1. R4-C-5: Attacker provenance over EVERY exchange named in oracleInput
// ============================================================================

test('R4-C-5 guard: uncited admin-issued exchange named only in terminalImpact.oracleInput is rejected at attacker_provenance', () => {
  const ctrl = signedEntry('r4c5-ctrl', makeStep({
    id: 'r4c5-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/export-victim?sig=bad-sig',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)' })

  // Admin mints the signed link, and the worker intentionally omits this exchange from all hops!
  const adminIssuance = signedEntry('r4c5-admin-mint', makeStep({
    id: 'r4c5-admin-mint', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/admin/exports/share',
    actor: { handle: 'admin_a', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_a', signedUrl: 'https://api.example.test/api/v1/downloads/export-src?sig=valid-sig-r4c5' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'admin_a', actorRoleLabel: 'admin (org_a)' })

  // Even if the worker attempts to tag the admin issuance as arm='control', issuance roles MUST still be provenance-checked!
  const adminIssuanceLabeledCtrl = signedEntry('r4c5-admin-mint-ctl', makeStep({
    id: 'r4c5-admin-mint-ctl', arm: 'control', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/admin/exports/share',
    actor: { handle: 'admin_a', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_a', signedUrl: 'https://api.example.test/api/v1/downloads/export-src?sig=valid-sig-r4c5' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'admin_a', actorRoleLabel: 'admin (org_a)' })

  const memberReplay = signedEntry('r4c5-replay', makeStep({
    id: 'r4c5-replay', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-victim?sig=valid-sig-r4c5',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_a', fileId: 'export-victim', rows: [{ id: 'r1', amount: 9000 }] },
  }), { seq: 3, timestampMs: 1200, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)' })

  for (const [label, issEntry, keyName] of [
    ['sourceValidIssuance', adminIssuance, 'sourceValidIssuance'],
    ['sourceIssuanceExchangeId', adminIssuance, 'sourceIssuanceExchangeId'],
    ['issuanceExchangeId', adminIssuance, 'issuanceExchangeId'],
    ['control-labeled-issuance', adminIssuanceLabeledCtrl, 'sourceValidIssuance'],
  ] as const) {
    const receipt: CompositeProofReceipt = {
      chainId: `r4-c5-uncited-${label}`,
      terminalVulnClass: 'cryptographic_scope_replay',
      hops: [{
        hopId: 'hop_1', surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/downloads/export-victim?sig=valid-sig-r4c5' },
        exchangeIds: ['r4c5-replay'], // admin issuance deliberately uncited in hops!
        oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Redeemed export link with signature from uncited admin issuance.',
        producedCapabilities: [], consumedCapabilities: [],
      }],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'hop_1',
        terminalExchangeId: 'r4c5-replay',
        summary: 'Attempted cryptographic_scope_replay citing admin-issued link only inside oracleInput.',
        claimedImpact: 'Attempted cryptographic_scope_replay citing admin-issued link only inside oracleInput.',
        preChainControlExchangeIds: ['r4c5-ctrl'],
        postChainReadbackExchangeIds: [],
        oracleFamily: 'cryptographic_scope_replay',
        oracleInput: {
          tamperedSignatureControl: 'r4c5-ctrl',
          [keyName]: issEntry.exchangeId,
          replayedAcceptance: 'r4c5-replay',
        },
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(
      receipt,
      { entries: [ctrl, issEntry, memberReplay] },
      { attackerPersonas: ['member_b'], forbiddenShortcutPersonas: ['admin_a'], signingKey: SIGNING_KEY },
    )
    assert.equal(res.confirmed, false, `${label}: uncited admin issuance must be rejected`)
    assert.equal(res.failedStage, 'attacker_provenance', `${label}: expected attacker_provenance, got ${res.failedStage}: ${res.reason}`)
    assert.match(res.reason, /admin_a|forbidden/)
  }

  // Positive control: when member_b itself minted the link and replayed it onto a DIFFERENT signed resource, it confirms cleanly.
  const memberMint = signedEntry('r4c5-member-mint', makeStep({
    id: 'r4c5-member-mint', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/exports/share',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', signedUrl: 'https://api.example.test/api/v1/downloads/export-src?sig=valid-sig-r4c5' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)' })

  const validRes = verifyCompositeReceipt({
    chainId: 'r4-c5-member-mint-valid',
    terminalVulnClass: 'cryptographic_scope_replay',
    hops: [{
      hopId: 'hop_1', surface: 'http',
      target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/downloads/export-victim?sig=valid-sig-r4c5' },
      exchangeIds: ['r4c5-replay'],
      oobEventIds: [], browserTraceIds: [],
      claimedDelta: 'Replayed member-issued signature onto foreign tenant export.',
      producedCapabilities: [], consumedCapabilities: [],
    }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_1',
      terminalExchangeId: 'r4c5-replay',
      summary: 'Member-minted signature replayed across tenant and resource boundaries.',
      claimedImpact: 'Member-minted signature replayed across tenant and resource boundaries.',
      preChainControlExchangeIds: ['r4c5-ctrl'],
      postChainReadbackExchangeIds: [],
      oracleFamily: 'cryptographic_scope_replay',
      oracleInput: {
        tamperedSignatureControl: 'r4c5-ctrl',
        sourceValidIssuance: 'r4c5-member-mint',
        replayedAcceptance: 'r4c5-replay',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl, memberMint, memberReplay] }, {
    attackerPersonas: ['member_b'], forbiddenShortcutPersonas: ['admin_a'], signingKey: SIGNING_KEY,
  })
  assert.equal(validRes.confirmed, true, `member-minted cross-resource replay must confirm: ${validRes.reason}`)
})

// ============================================================================
// 2. R4-H-5: Honest RBAC, Actor-Check Enforcement & Auto-Edges Never Weaken
// ============================================================================

test('R4-H-5 guard: honest-RBAC stub (list -> GET own 200 + GET foreign sibling 403) MUST NOT confirm bola/idor/broken_access_control/bfla/cross_tenant_read', () => {
  const ownCap = 'cap:hop_1:own_item_id'
  const listOwn = signedEntry('rbac-list', makeStep({
    id: 'rbac-list', arm: 'setup', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/records',
    json: { records: [{ id: 'rec-8f7e6d5c', owner: 'member_a', tenantId: 'org_a' }] },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [ownCap] })

  const foreignCtrl = signedEntry('rbac-foreign-403', makeStep({
    id: 'rbac-foreign-403', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/records/rec-1a2b3c4d',
    json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050 })

  const readOwn = signedEntry('rbac-own-200', makeStep({
    id: 'rbac-own-200', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/records/rec-8f7e6d5c',
    json: { id: 'rec-8f7e6d5c', owner: 'member_a', tenantId: 'org_a', secretNote: 'own-private-record' },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [ownCap] })

  const transcript: HostSignedTranscript = { entries: [listOwn, foreignCtrl, readOwn] }

  for (const vulnClass of ['bola', 'idor', 'broken_access_control', 'bfla', 'cross_tenant_read'] as const) {
    for (const withExplicitEdge of [false, true]) {
      const receipt: CompositeProofReceipt = {
        chainId: `r4-h5-rbac-${vulnClass}-${withExplicitEdge ? 'explicit' : 'autodag'}`,
        terminalVulnClass: vulnClass,
        hops: [
          {
            hopId: 'hop_1', surface: 'http',
            target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/records' },
            exchangeIds: ['rbac-list'], oobEventIds: [], browserTraceIds: [],
            claimedDelta: 'Listed own records.', producedCapabilities: [ownCap], consumedCapabilities: [],
          },
          {
            hopId: 'hop_2', surface: 'http',
            target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/records/rec-8f7e6d5c' },
            exchangeIds: ['rbac-own-200'], oobEventIds: [], browserTraceIds: [],
            claimedDelta: 'Read own record.', producedCapabilities: [], consumedCapabilities: [ownCap],
          },
        ],
        causalEdges: withExplicitEdge
          ? [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: ownCap }]
          : [],
        terminalImpact: {
          terminalHopId: 'hop_2',
          terminalExchangeId: 'rbac-own-200',
          summary: `Honest RBAC check for ${vulnClass} comparing own object 200 against foreign sibling 403.`,
          claimedImpact: `Honest RBAC check for ${vulnClass} comparing own object 200 against foreign sibling 403.`,
          preChainControlExchangeIds: ['rbac-foreign-403'],
          postChainReadbackExchangeIds: [],
        },
        replayMode: 'fresh_clean_replay',
      }
      const res = verifyCompositeReceipt(receipt, transcript, {
        attackerPersonas: ['member_a'], signingKey: SIGNING_KEY,
      })
      assert.equal(res.confirmed, false, `${vulnClass} (${withExplicitEdge ? 'explicit' : 'auto-DAG'}) on honest RBAC MUST reject`)
      assert.equal(res.failedStage, 'terminal_impact')
    }
  }
})

test('R4-H-5 guard: cross-persona control on a DAG-cap terminal hop is rejected (!termUsesDagCap skip removed) and auto-edges never unlock sibling controls', () => {
  const cap = 'cap:hop_1:own_doc_ref'
  const h1 = signedEntry('xact-h1', makeStep({
    id: 'xact-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/docs',
    json: { docs: [{ id: 'doc-own-99' }] },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [cap] })

  // A DIFFERENT persona (member_b) is denied 403 on member_a's own document — honest RBAC!
  const otherPersonaCtrl = signedEntry('xact-ctrl-b', makeStep({
    id: 'xact-ctrl-b', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/docs/doc-own-99',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)' })

  // member_a reads its own document while consuming a DAG capability
  const h2 = signedEntry('xact-h2', makeStep({
    id: 'xact-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/docs/doc-own-99',
    json: { id: 'doc-own-99', balance: 5000, secret: 'member-a-own-secret' },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })

  const crossActorRes = verifyCompositeReceipt({
    chainId: 'r4-h5-cross-actor-ctrl',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/docs' }, exchangeIds: ['xact-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Listed docs', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/docs/doc-own-99' }, exchangeIds: ['xact-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read own doc', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'xact-h2',
      summary: 'Attempted to pair member_b 403 control with member_a 200 via DAG cap.',
      claimedImpact: 'Attempted to pair member_b 403 control with member_a 200 via DAG cap.',
      preChainControlExchangeIds: ['xact-ctrl-b'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [h1, otherPersonaCtrl, h2] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(crossActorRes.confirmed, false, 'cross-persona control on DAG-cap hop MUST be rejected')
  assert.equal(crossActorRes.failedStage, 'terminal_impact')

  // Auto-inferred edges (causalEdges: []) must NEVER unlock sibling dynamic-ID control matching even with same-owner metadata!
  const sibCtrl = signedEntry('auto-sib-ctrl', makeStep({
    id: 'auto-sib-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/0c9d8b7a/download',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })
  const sibOwnerRb = signedEntry('auto-sib-rb', makeStep({
    id: 'auto-sib-rb', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/0c9d8b7a/meta',
    actor: { handle: 'admin_b', role: 'admin', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { exportId: '0c9d8b7a', tenantId: 'org_b' },
  }), { seq: 2, timestampMs: 950, actorPersona: 'admin_b', actorRoleLabel: 'admin (org_b)' })
  const autoH1 = signedEntry('auto-sib-h1', makeStep({
    id: 'auto-sib-h1', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/v1/directory/items',
    json: { token: 'opaque-export-tok-987654' },
  }), { seq: 3, timestampMs: 1000, emittedCapabilities: [cap] })
  const autoH2 = signedEntry('auto-sib-h2', makeStep({
    id: 'auto-sib-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/e77f0a21/download',
    json: { tenantId: 'org_b', rows: [{ id: 'r1', balance: 7500 }] },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [cap] })

  const autoEdgeSibRes = verifyCompositeReceipt({
    chainId: 'r4-h5-auto-edge-sibling-denied',
    terminalVulnClass: 'cross_tenant_read',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/directory/items' }, exchangeIds: ['auto-sib-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained cap', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/e77f0a21/download' }, exchangeIds: ['auto-sib-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign export', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [], // auto-DAG infers value_binding, which must NOT unlock sibling-ID control!
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'auto-sib-h2',
      summary: 'Auto-inferred DAG edge must never unlock weaker sibling-ID control matching.',
      claimedImpact: 'Auto-inferred DAG edge must never unlock weaker sibling-ID control matching.',
      preChainControlExchangeIds: ['auto-sib-ctrl'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [sibCtrl, sibOwnerRb, autoH1, autoH2] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(autoEdgeSibRes.confirmed, false, 'auto-inferred edges must never unlock sibling-ID control rules')
  assert.equal(autoEdgeSibRes.failedStage, 'terminal_impact')
})

// ============================================================================
// 3. R4-H-6: Per-Exchange Tenant Privilege Enforcement on Every Hop
// ============================================================================

test('R4-H-6 guard: dual-membership persona (admin org_a, member org_b) on own tenant-A admin route MUST NOT confirm bfla/privilege_escalation/bola/idor', () => {
  const dualLabel = 'admin (org_a), member (org_b)'
  const mkPersona = (handle: string, roleLabel: string): ResolvedPersona => ({
    id: `p-${handle}`, handle, roleLabel, originAllowlist: [ORIGIN], authKind: 'header',
    headerName: 'X-User', secret: `secret-${handle}-99`, canaryMarkers: [],
  })
  const grant: Pick<Grant, 'personas'> = {
    personas: new Map([
      ['dual', mkPersona('dual', dualLabel)],
      ['member_b', mkPersona('member_b', 'member (org_b)')],
      ['admin_a', mkPersona('admin_a', 'admin (org_a)')],
    ]),
  }
  const grantOpts = buildCompositeVerifyOptionsFromGrant(grant)!
  assert.ok(grantOpts.forbiddenShortcutPersonas?.includes('dual'), 'dual persona must be in forbiddenShortcutPersonas by default')
  assert.ok(!grantOpts.attackerPersonas?.includes('dual'), 'dual persona must NOT be unconditionally in attackerPersonas')

  const cap = 'cap:dual:billing_ref'
  const dualActor = { handle: 'dual', role: 'admin' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const memberBActor = { handle: 'member_b', role: 'member' as const, tenant: 'org_b', auth: 'bearer' as const, sameSite: null }

  const ctrlMemberB = signedEntry('h6-ctrl-mb', makeStep({
    id: 'h6-ctrl-mb', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/orgs/org_a/billing',
    actor: memberBActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)' })

  // Hop 1: dual hits its own tenant-A admin settings
  const h1 = signedEntry('h6-h1', makeStep({
    id: 'h6-h1', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/orgs/org_a/settings',
    actor: dualActor, json: { billingKey: 'bk-12345678' },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'dual', actorRoleLabel: dualLabel, emittedCapabilities: [cap] })

  // Terminal variants on tenant-A admin route: (a) 0 body markers, (b) 2 body markers, (c) ambiguous route with 0 markers
  const h2NoMarkers = signedEntry('h6-h2-none', makeStep({
    id: 'h6-h2-none', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/orgs/org_a/billing',
    actor: dualActor, json: { balanceCents: 900000, invoices: [{ id: 'inv-1', amount: 5000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })

  const h2MultiMarkers = signedEntry('h6-h2-multi', makeStep({
    id: 'h6-h2-multi', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/orgs/org_a/billing',
    actor: dualActor, json: { tenantId: 'org_a', partnerTenant: 'org_b', balanceCents: 900000 },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })

  const h2Ambiguous = signedEntry('h6-h2-ambig', makeStep({
    id: 'h6-h2-ambig', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/billing/summary',
    actor: dualActor, json: { balanceCents: 900000, ledger: [{ id: 'l1', amount: 1000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })

  for (const vulnClass of ['bfla', 'privilege_escalation', 'bola', 'idor'] as const) {
    for (const [label, h2] of [['zero-body-markers', h2NoMarkers], ['multi-body-markers', h2MultiMarkers], ['ambiguous-route', h2Ambiguous]] as const) {
      const receipt: CompositeProofReceipt = {
        chainId: `r4-h6-${vulnClass}-${label}`,
        terminalVulnClass: vulnClass,
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_a/settings' }, exchangeIds: ['h6-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read org_a settings', producedCapabilities: [cap], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: h2.step.pathAndQuery! }, exchangeIds: [h2.exchangeId], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read billing', producedCapabilities: [], consumedCapabilities: [cap] },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
        terminalImpact: {
          terminalHopId: 'hop_2', terminalExchangeId: h2.exchangeId,
          summary: `Dual persona own-admin-tenant action claimed as ${vulnClass}.`,
          claimedImpact: `Dual persona own-admin-tenant action claimed as ${vulnClass}.`,
          preChainControlExchangeIds: ['h6-ctrl-mb'], postChainReadbackExchangeIds: [],
        },
        replayMode: 'fresh_clean_replay',
      }
      // Test BOTH with grant-derived options AND even when a caller explicitly allowlists `dual`!
      for (const [optLabel, opts] of [
        ['grant-options', { ...grantOpts, signingKey: SIGNING_KEY }],
        ['explicit-attacker', { attackerPersonas: ['dual'], personaRoleLabels: { dual: dualLabel }, signingKey: SIGNING_KEY }],
      ] as const) {
        const res = verifyCompositeReceipt(receipt, { entries: [ctrlMemberB, h1, h2] }, opts)
        assert.equal(res.confirmed, false, `${vulnClass}/${label}/${optLabel}: dual persona own-admin action MUST NOT confirm`)
        assert.equal(res.failedStage, 'attacker_provenance', `${vulnClass}/${label}/${optLabel}: expected attacker_provenance, got ${res.failedStage}: ${res.reason}`)
      }
    }
  }

  // Also verify non-terminal hop admin-tenant enforcement: even if Hop 2 targets org_b,
  // a non-dual_tenant_abac class (`bola`) using dual's admin org_a Hop 1 MUST fail at attacker_provenance!
  const h2OrgB = signedEntry('h6-h2-orgb', makeStep({
    id: 'h6-h2-orgb', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/orgs/org_b/billing',
    actor: { handle: 'dual', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', balanceCents: 12345 },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })
  const ctrlOrgB = signedEntry('h6-ctrl-orgb', makeStep({
    id: 'h6-ctrl-orgb', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/orgs/org_b/billing',
    actor: { handle: 'dual', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'dual', actorRoleLabel: dualLabel })

  const nonTermRes = verifyCompositeReceipt({
    chainId: 'r4-h6-nonterm-admin-hop',
    terminalVulnClass: 'bola',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_a/settings' }, exchangeIds: ['h6-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Admin action in org_a', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/billing' }, exchangeIds: ['h6-h2-orgb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read org_b billing', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'h6-h2-orgb',
      summary: 'Non-terminal org_a admin hop used inside bola chain.',
      claimedImpact: 'Non-terminal org_a admin hop used inside bola chain.',
      preChainControlExchangeIds: ['h6-ctrl-orgb'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrlOrgB, h1, h2OrgB] }, { attackerPersonas: ['dual'], personaRoleLabels: { dual: dualLabel }, signingKey: SIGNING_KEY })
  assert.equal(nonTermRes.confirmed, false, 'non-terminal admin-tenant hop on non-dual_tenant_abac class MUST reject')
  assert.equal(nonTermRes.failedStage, 'attacker_provenance')

  // Positive control: grant-derived options ALLOW dual ONLY under explicit dual_tenant_abac oracle targeting non-admin org_b!
  const primeEx = signedEntry('h6-dt-prime', makeStep({
    id: 'h6-dt-prime', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/orgs/org_a/permissions/prime',
    actor: dualActor, json: { tenantId: 'org_a', primed: true },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'dual', actorRoleLabel: dualLabel, emittedCapabilities: [cap] })
  const dtCtrlOrgB = signedEntry('h6-dt-ctrl-orgb', makeStep({
    id: 'h6-dt-ctrl-orgb', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/reports/billing',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'dual', actorRoleLabel: dualLabel })
  const dtBledOrgB = signedEntry('h6-dt-bled-orgb', makeStep({
    id: 'h6-dt-bled-orgb', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/reports/billing',
    actor: dualActor, json: { tenantId: 'org_b', balanceCents: 12345 },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })
  const dtRes = verifyCompositeReceipt({
    chainId: 'r4-h6-explicit-dual-abac-ok',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/permissions/prime' }, exchangeIds: ['h6-dt-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed permission cache', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/reports/billing' }, exchangeIds: ['h6-dt-bled-orgb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Bled org_a admin role into org_b', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'h6-dt-bled-orgb',
      summary: 'Explicit dual_tenant_abac cache bleed into non-admin tenant org_b.',
      claimedImpact: 'Explicit dual_tenant_abac cache bleed into non-admin tenant org_b.',
      preChainControlExchangeIds: ['h6-dt-ctrl-orgb'], postChainReadbackExchangeIds: [],
      oracleFamily: 'dual_tenant_abac',
      oracleInput: {
        mode: 'dual_org_cache_bleed',
        baselineDeniedControl: 'h6-dt-ctrl-orgb',
        primeAction: 'h6-dt-prime',
        bledAccess: 'h6-dt-bled-orgb',
      },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [dtCtrlOrgB, primeEx, dtBledOrgB] }, { ...grantOpts, signingKey: SIGNING_KEY })
  assert.equal(dtRes.confirmed, true, `explicit dual_tenant_abac targeting non-admin org_b with grant options must confirm: ${dtRes.reason}`)
})
