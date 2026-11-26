import assert from 'node:assert/strict'
import test from 'node:test'
import {
  deriveSignedTerminalOrigin,
  signHostRecord,
  verifyCompositeReceipt,
  verifyHopTargetsAgainstExchanges,
  type CompositeProofReceipt,
  type HostBrowserTrace,
  type HostOobEvent,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'

const SIGNING_KEY = 'r3-composite-actor-test-signing-key-0123456789abcdef'
const ORIGIN_A = 'https://api-a.example.test'
const ORIGIN_B = 'https://api-b.example.test'

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

function makeEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const rec: HostTranscriptEntry = {
    exchangeId,
    origin: extra.origin ?? ORIGIN_A,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    actorRoleLabel: extra.actorRoleLabel !== undefined ? extra.actorRoleLabel : 'member (org_a)',
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}

function signTrace(trace: HostBrowserTrace): HostBrowserTrace {
  return { ...trace, hostSignature: signHostRecord(trace, SIGNING_KEY) }
}

function signOob(oob: HostOobEvent): HostOobEvent {
  return { ...oob, hostSignature: signHostRecord(oob, SIGNING_KEY) }
}

// ============================================================================
// 1. R3-H-4(a/b): Forbidden cap-actor & base/wire persona laundering
// ============================================================================

test('R3-H-4: rejects forbidden admin-emitted cap, admin base persona + member cap, and admin wire persona in 2-hop chains', () => {
  const memberCap = 'cap:hop_1:member_cookie'
  const adminCap = 'cap:hop_1:admin_token'

  const ctrl = makeEntry('ex-ctrl', makeStep({
    id: 'ex-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/admin/vault',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)' })

  // Variant 1: Admin-emitted cap in hop 1 spent via actorPersona='cap:...' in hop 2
  const adminEmit = makeEntry('ex-h1-admin', makeStep({
    id: 'ex-h1-admin', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/session',
    actor: { handle: 'admin', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { token: 'adm-tok' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'admin', actorRoleLabel: 'admin (org_a)', emittedCapabilities: [adminCap] })

  const adminSpend = makeEntry('ex-h2-admin', makeStep({
    id: 'ex-h2-admin', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/vault',
    actor: { handle: adminCap, role: null, tenant: null, auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', vaultSecret: 'classified-record-99' },
  }), { seq: 3, timestampMs: 1200, actorPersona: adminCap, actorRoleLabel: null, consumedCapabilities: [adminCap] })

  const receiptAdminEmit: CompositeProofReceipt = {
    chainId: 'r3-h4-admin-cap',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/admin/session' }, exchangeIds: ['ex-h1-admin'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained admin token', producedCapabilities: [adminCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/admin/vault' }, exchangeIds: ['ex-h2-admin'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Accessed admin vault', producedCapabilities: [], consumedCapabilities: [adminCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: adminCap }],
    terminalImpact: { terminalHopId: 'h2', terminalExchangeId: 'ex-h2-admin', summary: 'Admin-emitted cap used to access vault.', claimedImpact: 'Admin-emitted cap used to access vault.', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  const r1 = verifyCompositeReceipt(receiptAdminEmit, { entries: [ctrl, adminEmit, adminSpend] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(r1.confirmed, false)
  assert.equal(r1.failedStage, 'attacker_provenance')

  // Variant 2: Member-emitted cookie cap in hop 1 + forbidden admin base persona on step.actor.handle in hop 2
  const memberEmit = makeEntry('ex-h1-mem', makeStep({
    id: 'ex-h1-mem', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/profile',
    json: { sessionHint: 'opaque-member-val' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', emittedCapabilities: [memberCap] })

  const adminBaseStep = makeEntry('ex-h2-base', makeStep({
    id: 'ex-h2-base', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/vault',
    actor: { handle: 'admin', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', vaultSecret: 'classified-record-99' },
  }), { seq: 3, timestampMs: 1200, actorPersona: memberCap, actorRoleLabel: 'member (org_a)', consumedCapabilities: [memberCap] })

  const receiptBaseAdmin: CompositeProofReceipt = {
    chainId: 'r3-h4-base-admin',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/profile' }, exchangeIds: ['ex-h1-mem'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Sealed member cookie', producedCapabilities: [memberCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/admin/vault' }, exchangeIds: ['ex-h2-base'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Accessed admin vault with merged admin header', producedCapabilities: [], consumedCapabilities: [memberCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: memberCap }],
    terminalImpact: { terminalHopId: 'h2', terminalExchangeId: 'ex-h2-base', summary: 'Admin base credential laundered under member cap.', claimedImpact: 'Admin base credential laundered under member cap.', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  const r2 = verifyCompositeReceipt(receiptBaseAdmin, { entries: [ctrl, memberEmit, adminBaseStep] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(r2.confirmed, false)
  assert.equal(r2.failedStage, 'attacker_provenance')

  // Variant 3: Admin wireCredentialProvenance.personaHandle + member cap (fromDag must NOT skip isForbidden!)
  const adminWireStep = makeEntry('ex-h2-wire', makeStep({
    id: 'ex-h2-wire', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/vault',
    actor: { handle: memberCap, role: 'member', tenant: 'org_a', auth: 'cookie', sameSite: null },
    json: { tenantId: 'org_b', vaultSecret: 'classified-record-99' },
  }), {
    seq: 3, timestampMs: 1200, actorPersona: memberCap, actorRoleLabel: 'member (org_a)', consumedCapabilities: [memberCap],
    wireCredentialProvenance: {
      authenticated: true, source: 'persona_vault', sources: ['persona_vault'], personaHandle: 'admin',
      session: null, headerNames: ['authorization'], cookieNames: ['sid'], vaultCookieNames: [],
      jarCookieNames: [], vaultHeaderNames: ['authorization'], callerAuthHeaderNames: [], authMutated: false,
    },
  })

  const r3 = verifyCompositeReceipt({
    ...receiptBaseAdmin,
    hops: [receiptBaseAdmin.hops[0]!, { ...receiptBaseAdmin.hops[1]!, exchangeIds: ['ex-h2-wire'] }],
    terminalImpact: { ...receiptBaseAdmin.terminalImpact, terminalExchangeId: 'ex-h2-wire' },
  }, { entries: [ctrl, memberEmit, adminWireStep] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(r3.confirmed, false)
  assert.equal(r3.failedStage, 'attacker_provenance')

  // Variant 4: Privileged roleLabel on a DAG cap hop (must NOT be skipped by fromDag!)
  const privRoleStep = makeEntry('ex-h2-privrole', makeStep({
    id: 'ex-h2-privrole', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/vault',
    actor: { handle: memberCap, role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', vaultSecret: 'classified-record-99' },
  }), { seq: 3, timestampMs: 1200, actorPersona: memberCap, actorRoleLabel: 'admin (org_a)', consumedCapabilities: [memberCap] })

  const r4 = verifyCompositeReceipt({
    ...receiptBaseAdmin,
    hops: [receiptBaseAdmin.hops[0]!, { ...receiptBaseAdmin.hops[1]!, exchangeIds: ['ex-h2-privrole'] }],
    terminalImpact: { ...receiptBaseAdmin.terminalImpact, terminalExchangeId: 'ex-h2-privrole' },
  }, { entries: [ctrl, memberEmit, privRoleStep] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(r4.confirmed, false)
  assert.equal(r4.failedStage, 'attacker_provenance')
})

// ============================================================================
// 2. R3-H-4(b): Junk-credential Bearer cap control must NOT confirm authz classes
// ============================================================================

test('R3-H-4(b): rejects junk-credential Bearer capability controls (401 and 403) across bola, broken_access_control, idor, and info_disclosure', () => {
  const junkCap = 'cap:hop_0:junk_value_from_member'
  const loginUserIdCap = 'cap:login:user_id_not_token'

  // Member reads own object (200) and seals an arbitrary high-entropy string from it
  const memberOwnRead = makeEntry('ex-own', makeStep({
    id: 'ex-own', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/items/item-own-1',
    json: { id: 'item-own-1', title: 'Own private note', opaqueRef: 'ref_9f8e7d6c5b4a' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', emittedCapabilities: [junkCap] })

  // Control sent with junkCap as Bearer -> gets 401 or 403
  const junkCtrl401 = makeEntry('ex-ctrl-401', makeStep({
    id: 'ex-ctrl-401', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/api/items/item-own-1',
    actor: { handle: junkCap, role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { error: 'invalid_token' },
  }), { seq: 2, timestampMs: 1050, actorPersona: junkCap, actorRoleLabel: 'member (org_a)', consumedCapabilities: [junkCap] })

  const junkCtrl403 = makeEntry('ex-ctrl-403', makeStep({
    id: 'ex-ctrl-403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/items/item-own-1',
    actor: { handle: junkCap, role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { error: 'token_rejected' },
  }), { seq: 3, timestampMs: 1060, actorPersona: junkCap, actorRoleLabel: 'member (org_a)', consumedCapabilities: [junkCap] })

  // Even a junk value sealed from POST /login getting 401 must be treated as anonymous for the 401 rule
  const loginEx = makeEntry('ex-login', makeStep({
    id: 'ex-login', arm: 'setup', method: 'POST', status: 200, pathAndQuery: '/login',
    json: { token: 'real-jwt', userId: 'usr_a1b2c3d4e5f6' },
  }), { seq: 0, timestampMs: 900, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', emittedCapabilities: [loginUserIdCap] })

  const loginJunkCtrl401 = makeEntry('ex-ctrl-login-401', makeStep({
    id: 'ex-ctrl-login-401', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/api/items/item-own-1',
    actor: { handle: loginUserIdCap, role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { error: 'unauthorized' },
  }), { seq: 4, timestampMs: 1070, actorPersona: loginUserIdCap, actorRoleLabel: 'member (org_a)', consumedCapabilities: [loginUserIdCap] })

  const transcript: HostSignedTranscript = {
    entries: [loginEx, memberOwnRead, junkCtrl401, junkCtrl403, loginJunkCtrl401],
  }

  for (const vulnClass of ['bola', 'broken_access_control', 'idor', 'info_disclosure']) {
    for (const ctrlId of ['ex-ctrl-401', 'ex-ctrl-403', 'ex-ctrl-login-401']) {
      const receipt: CompositeProofReceipt = {
        chainId: `r3-h4b-${vulnClass}-${ctrlId}`,
        terminalVulnClass: vulnClass,
        hops: [
          { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/items/item-own-1' }, exchangeIds: ['ex-own'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read member item', producedCapabilities: [], consumedCapabilities: [] },
        ],
        causalEdges: [],
        terminalImpact: {
          terminalHopId: 'h1',
          terminalExchangeId: 'ex-own',
          summary: `Attempted ${vulnClass} confirmation using junk cap control ${ctrlId}.`,
          claimedImpact: `Attempted ${vulnClass} confirmation using junk cap control ${ctrlId}.`,
          preChainControlExchangeIds: [ctrlId],
          postChainReadbackExchangeIds: [],
        },
        replayMode: 'fresh_clean_replay',
      }

      const res = verifyCompositeReceipt(receipt, transcript, {
        signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
      })
      assert.equal(res.confirmed, false, `${vulnClass} with ${ctrlId} must be rejected`)
      assert.equal(res.failedStage, 'terminal_impact')
    }
  }
})

// ============================================================================
// 3. R3-H-4(c): Browser-only / OOB-only root hops & forbidden trace caps
// ============================================================================

test('R3-H-4(c): rejects browser-only root hop, OOB-only root hop, and forbidden admin browser trace cap injection', () => {
  const domCap = 'cap:browser:admin_secret'
  const oobCap = 'cap:oob:unproven_token'

  const ctrl = makeEntry('ex-ctrl', makeStep({
    id: 'ex-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/vault/export',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'member_a' })

  const adminTrace = signTrace({
    id: 'tr-admin',
    origin: ORIGIN_A,
    timestampMs: 1050,
    actorPersona: 'admin',
    sinks: ['dom_read'],
    emittedCapabilities: [domCap],
  })

  const useDomCap = makeEntry('ex-use-dom', makeStep({
    id: 'ex-use-dom', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/vault/export',
    actor: { handle: domCap, role: null, tenant: null, auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', records: [{ id: 'r1', secret: 'val' }] },
  }), { seq: 2, timestampMs: 1200, actorPersona: domCap, actorRoleLabel: null, consumedCapabilities: [domCap] })

  // Case A: Browser-only root hop (no HTTP probe) from admin trace
  const browserRootReceipt: CompositeProofReceipt = {
    chainId: 'r3-h4c-browser-root',
    terminalVulnClass: 'bola',
    hops: [
      { hopId: 'h1', surface: 'browser', target: { origin: ORIGIN_A }, exchangeIds: [], oobEventIds: [], browserTraceIds: ['tr-admin'], claimedDelta: 'Admin browser rendered secret', producedCapabilities: [domCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/vault/export' }, exchangeIds: ['ex-use-dom'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Spent admin DOM secret', producedCapabilities: [], consumedCapabilities: [domCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: domCap }],
    terminalImpact: { terminalHopId: 'h2', terminalExchangeId: 'ex-use-dom', summary: 'Admin browser trace laundered into DAG cap.', claimedImpact: 'Admin browser trace laundered into DAG cap.', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  const rA = verifyCompositeReceipt(browserRootReceipt, { entries: [ctrl, useDomCap], browserTraces: [adminTrace] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(rA.confirmed, false)
  assert.equal(rA.failedStage, 'attacker_provenance')

  // Case B: Root hop with dummy member HTTP probe PLUS forbidden admin browser trace
  const dummyProbe = makeEntry('ex-dummy', makeStep({
    id: 'ex-dummy', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/health',
    json: { ok: true },
  }), { seq: 0, timestampMs: 1020, actorPersona: 'member_a' })

  const rB = verifyCompositeReceipt({
    ...browserRootReceipt,
    hops: [
      { ...browserRootReceipt.hops[0]!, target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/health' }, exchangeIds: ['ex-dummy'] },
      browserRootReceipt.hops[1]!,
    ],
  }, { entries: [ctrl, dummyProbe, useDomCap], browserTraces: [adminTrace] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(rB.confirmed, false)
  assert.equal(rB.failedStage, 'attacker_provenance')

  // Case C: OOB-only root hop (no HTTP probe)
  const oobEvt = signOob({
    id: 'oob-root',
    targetOrigin: ORIGIN_A,
    delivered: true,
    receivedAtMs: 1050,
    token: 'tok-oob-123456',
    emittedCapabilities: [oobCap],
  })
  const useOobCap = makeEntry('ex-use-oob', makeStep({
    id: 'ex-use-oob', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/vault/export',
    actor: { handle: oobCap, role: null, tenant: null, auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', records: [{ id: 'r1', secret: 'val' }] },
  }), { seq: 2, timestampMs: 1200, actorPersona: oobCap, actorRoleLabel: null, consumedCapabilities: [oobCap] })

  const oobRootReceipt: CompositeProofReceipt = {
    chainId: 'r3-h4c-oob-root',
    terminalVulnClass: 'bola',
    hops: [
      { hopId: 'h1', surface: 'webhook', target: { origin: ORIGIN_A }, exchangeIds: [], oobEventIds: ['oob-root'], browserTraceIds: [], claimedDelta: 'OOB event arrived', producedCapabilities: [oobCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/vault/export' }, exchangeIds: ['ex-use-oob'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Spent OOB cap', producedCapabilities: [], consumedCapabilities: [oobCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: oobCap }],
    terminalImpact: { terminalHopId: 'h2', terminalExchangeId: 'ex-use-oob', summary: 'OOB-only root hop injected capability.', claimedImpact: 'OOB-only root hop injected capability.', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  const rC = verifyCompositeReceipt(oobRootReceipt, { entries: [ctrl, useOobCap], oobEvents: [oobEvt] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(rC.confirmed, false)
  assert.equal(rC.failedStage, 'attacker_provenance')
})

// ============================================================================
// 4. R3-H-13 & R3-H-15: Hop-target binding & deriveSignedTerminalOrigin
// ============================================================================

test('R3-H-13 / R3-H-15: rejects hop targets whose origin, method, or route disagrees with cited signed exchanges and derives signed terminal origin', () => {
  const cap = 'cap:hop_1:delegated_tok'
  const ctrl = makeEntry('ex-ctrl', makeStep({
    id: 'ex-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/org-b/export',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, origin: ORIGIN_A, actorPersona: 'member_a' })

  const h1Ex = makeEntry('ex-1', makeStep({
    id: 'ex-1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/tokens/mint',
    json: { token: 'minted-tok' },
  }), { seq: 2, timestampMs: 1100, origin: ORIGIN_A, actorPersona: 'member_a', emittedCapabilities: [cap] })

  const h2Ex = makeEntry('ex-2', makeStep({
    id: 'ex-2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/org-b/export',
    actor: { handle: cap, role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', rows: [{ id: 'row-1', balance: 50000 }] },
  }), { seq: 3, timestampMs: 1200, origin: ORIGIN_A, actorPersona: cap, actorRoleLabel: 'member (org_a)', consumedCapabilities: [cap] })

  const transcript: HostSignedTranscript = { entries: [ctrl, h1Ex, h2Ex] }
  const baseReceipt: CompositeProofReceipt = {
    chainId: 'r3-hop-target-bind',
    terminalVulnClass: 'bola',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN_A, method: 'POST', pathAndQuery: '/api/tokens/mint' }, exchangeIds: ['ex-1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Minted token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN_A, method: 'GET', pathAndQuery: '/api/org-b/export' }, exchangeIds: ['ex-2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Exported foreign tenant data', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'h1', toHopId: 'h2', capabilityHandle: cap }],
    terminalImpact: { terminalHopId: 'h2', terminalExchangeId: 'ex-2', summary: 'Legitimate attacker-persona multi-hop cap chain.', claimedImpact: 'Legitimate attacker-persona multi-hop cap chain.', preChainControlExchangeIds: ['ex-ctrl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }

  // Positive control: matching origin, method, route, and attacker-persona cap chain -> CONFIRMED
  const ok = verifyCompositeReceipt(baseReceipt, transcript, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(ok.confirmed, true, `Expected legitimate chain to confirm, got: ${ok.reason}`)
  assert.equal(ok.terminalOrigin, ORIGIN_A)

  // Terminal origin mismatch (R3-H-15): declares ORIGIN_B while signed terminal exchange hit ORIGIN_A
  const wrongTermOrigin: CompositeProofReceipt = {
    ...baseReceipt,
    hops: [baseReceipt.hops[0]!, { ...baseReceipt.hops[1]!, target: { ...baseReceipt.hops[1]!.target, origin: ORIGIN_B } }],
  }
  assert.equal(deriveSignedTerminalOrigin(wrongTermOrigin, [ctrl, h1Ex, h2Ex]), ORIGIN_A)
  const rTermOrigin = verifyCompositeReceipt(wrongTermOrigin, transcript, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(rTermOrigin.confirmed, false)
  assert.equal(rTermOrigin.failedStage, 'transcript_integrity')

  // Upstream hop origin mismatch (R3-H-13)
  const wrongUpOrigin: CompositeProofReceipt = {
    ...baseReceipt,
    hops: [{ ...baseReceipt.hops[0]!, target: { ...baseReceipt.hops[0]!.target, origin: ORIGIN_B } }, baseReceipt.hops[1]!],
  }
  const rUpOrigin = verifyCompositeReceipt(wrongUpOrigin, transcript, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(rUpOrigin.confirmed, false)
  assert.equal(rUpOrigin.failedStage, 'transcript_integrity')

  // Upstream hop method mismatch (declared DELETE vs signed POST)
  const wrongMethod: CompositeProofReceipt = {
    ...baseReceipt,
    hops: [{ ...baseReceipt.hops[0]!, target: { ...baseReceipt.hops[0]!.target, method: 'DELETE' } }, baseReceipt.hops[1]!],
  }
  const rMethod = verifyCompositeReceipt(wrongMethod, transcript, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(rMethod.confirmed, false)
  assert.equal(rMethod.failedStage, 'transcript_integrity')

  // Upstream hop route mismatch (declared /api/unrelated/sqli vs signed /api/tokens/mint)
  const wrongRoute: CompositeProofReceipt = {
    ...baseReceipt,
    hops: [{ ...baseReceipt.hops[0]!, target: { ...baseReceipt.hops[0]!.target, pathAndQuery: '/api/unrelated/sqli' } }, baseReceipt.hops[1]!],
  }
  const rRoute = verifyCompositeReceipt(wrongRoute, transcript, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'], forbiddenShortcutPersonas: ['admin'],
  })
  assert.equal(rRoute.confirmed, false)
  assert.equal(rRoute.failedStage, 'transcript_integrity')

  // Helper allows cap-handle dynamic segment normalization while rejecting static route drift
  const dynEntry = makeEntry('ex-dyn', makeStep({
    id: 'ex-dyn', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: '/api/orders/ord_12345/rebind',
  }), { origin: ORIGIN_A })
  const dynReceipt: CompositeProofReceipt = {
    ...baseReceipt,
    hops: [{ ...baseReceipt.hops[0]!, target: { origin: ORIGIN_A, method: 'PATCH', pathAndQuery: '/api/orders/cap:h1:order_id/rebind' }, exchangeIds: ['ex-dyn'] }],
    causalEdges: [],
    terminalImpact: { ...baseReceipt.terminalImpact, terminalHopId: 'h1', terminalExchangeId: 'ex-dyn' },
  }
  assert.equal(verifyHopTargetsAgainstExchanges(dynReceipt, new Map([['ex-dyn', dynEntry]])).ok, true)
  const driftReceipt: CompositeProofReceipt = {
    ...dynReceipt,
    hops: [{ ...dynReceipt.hops[0]!, target: { origin: ORIGIN_A, method: 'PATCH', pathAndQuery: '/api/invoices/cap:h1:order_id/rebind' } }],
  }
  assert.equal(verifyHopTargetsAgainstExchanges(driftReceipt, new Map([['ex-dyn', dynEntry]])).ok, false)
})
