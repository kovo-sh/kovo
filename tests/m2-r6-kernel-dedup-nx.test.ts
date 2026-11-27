// @kernel @fixes R3-05
/**
 * M2 R6 Confirmation-Kernel Dedup, Entity-Less State-Transition & Signed-URL Provenance Suite.
 *
 * Covers all 3 systemic kernel fixes and negative bypass invariants:
 *  1. Host-completed `state_transition_binding` edge inference for entity-less privileged read
 *     terminals (`PATCH/POST/PUT -> GET` with verified pre-mutation denied control under same
 *     actor) + earliest clean pre-mutation denied control auto-selection when a post-mutation 2xx
 *     control was cited.
 *  2. Relaxed `winnerMut` for deeper `GET`-terminal causal-prefix supersession (both arrival
 *     orders) + exact-same-terminal multi-hop composite deduplication (`authz`/`privesc`/
 *     `economic`) with strict isolation across unrelated endpoints, origins, and injection/XSS/SSRF.
 *  3. 1-hop signed-URL/header `GET`/`HEAD` capability provenance guard rejecting smuggled
 *     signature queries/headers without in-DAG provenance while preserving 2+ hop signed-URL chains
 *     and plain non-signed `GET` proofs.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { canonicalNonAuthQuery } from '../src/server/v8-oracle-hydrate.ts'
import {
  isSameTerminalCompositeClassCompatible,
  matchCausalPrefixPartialChainSupersession,
  matchSameTerminalCompositeDedup,
  resolveCompositeSupersessionMatch,
  type UpstreamSupersessionEndpointLike,
} from '../src/server/composite-chain-dedup.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { resolveEntityLessReadStateTransition } from '../src/server/own-org-terminal-guard.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
void defaultTerminalOracleRegistry

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'test-m2-r6-kernel-dedup-nx-signing-key-9876543210'

function makeStep(overrides: Partial<ImpactStep> & { id: string; arm: 'control' | 'probe' }): ImpactStep {
  return {
    method: 'GET',
    pathAndQuery: '/v1/resource',
    status: 200,
    actor: { handle: 'user_a', role: 'member', tenant: 'org_alpha', auth: 'bearer', sameSite: null },
    ...overrides,
  }
}

function signedEntry(
  exchangeId: string,
  step: ImpactStep,
  extra: Partial<HostTranscriptEntry> = {},
): HostTranscriptEntry {
  const rec: HostTranscriptEntry = {
    exchangeId,
    origin: ORIGIN,
    timestampMs: extra.timestampMs ?? 1000,
    seq: extra.seq ?? 1,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : (step.actor.handle ?? 'user_a'),
    actorRoleLabel: extra.actorRoleLabel !== undefined ? extra.actorRoleLabel : `${step.actor.role ?? 'member'} (${step.actor.tenant ?? 'org_alpha'})`,
    cleanSession: extra.cleanSession ?? true,
    step: { route: step.pathAndQuery?.split('?')[0], ...step },
    ...extra,
  }
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}

// ============================================================================
// 1A. Host-Completed State-Transition Edge for Entity-Less Read Terminals
// ============================================================================

test('1A: infers state_transition_binding from privilege mutation to entity-less GET terminal with clean pre-mutation denied control', () => {
  const capSeed = 'cap:hop_seed:tok1'
  const capInbox = 'cap:hop_inbox:scim_tok'

  const ctrlVault403 = signedEntry('nx-ctrl-vault', makeStep({
    id: 'nx-ctrl-vault', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/v1/audit/vault',
    json: { error: 'owner_role_required' },
  }), { seq: 1, timestampMs: 1000 })

  const ctrlScim401 = signedEntry('nx-ctrl-scim', makeStep({
    id: 'nx-ctrl-scim', arm: 'control', method: 'PATCH', status: 401,
    pathAndQuery: '/v1/scim/users/usr_101',
    json: { error: 'scim_token_required' },
  }), { seq: 2, timestampMs: 1050 })

  const h1 = signedEntry('nx-h1', makeStep({
    id: 'nx-h1', arm: 'probe', method: 'POST', status: 201,
    pathAndQuery: '/v1/comments',
    json: { commentId: 'cmt_101' },
  }), { seq: 3, timestampMs: 1100, emittedCapabilities: [capSeed] })

  const h2 = signedEntry('nx-h2', makeStep({
    id: 'nx-h2', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/inbox/cmt_101',
    json: { scimToken: 'scim_tok_value_99' },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [capSeed], emittedCapabilities: [capInbox] })

  const h3 = signedEntry('nx-h3', makeStep({
    id: 'nx-h3', arm: 'probe', method: 'PATCH', status: 200,
    pathAndQuery: '/v1/scim/users/usr_101',
    requestJson: { role: 'owner' },
    json: { userId: 'usr_101', role: 'owner' },
  }), { seq: 5, timestampMs: 1300, actorPersona: capInbox, consumedCapabilities: [capInbox] })

  const h4 = signedEntry('nx-h4', makeStep({
    id: 'nx-h4', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/audit/vault',
    json: { tenant: 'org_alpha', events: [{ id: 'ev_1' }], artifact: 'vault_secret_data' },
  }), { seq: 6, timestampMs: 1400 })

  // Model omits the patch -> vault edge completely!
  const receipt: CompositeProofReceipt = {
    chainId: 'nx-entity-less-vault-omitted-edge',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'seed', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/comments' }, exchangeIds: ['nx-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Trigger worker notification', producedCapabilities: [capSeed], consumedCapabilities: [] },
      { hopId: 'inbox', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/inbox/cmt_101' }, exchangeIds: ['nx-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read leaked provisioning token', producedCapabilities: [capInbox], consumedCapabilities: [capSeed] },
      { hopId: 'patch', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/scim/users/usr_101' }, exchangeIds: ['nx-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Promote actor to owner role', producedCapabilities: [], consumedCapabilities: [capInbox] },
      { hopId: 'vault', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/audit/vault' }, exchangeIds: ['nx-h4'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read owner-only audit vault', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'seed', toHopId: 'inbox', capabilityHandle: capSeed },
      { kind: 'value_binding', fromHopId: 'inbox', toHopId: 'patch', capabilityHandle: capInbox },
    ],
    terminalImpact: {
      terminalHopId: 'vault',
      terminalExchangeId: 'nx-h4',
      summary: 'Provisioning token escalation unlocks owner-only audit vault for member account.',
      claimedImpact: 'Provisioning token escalation unlocks owner-only audit vault for member account.',
      preChainControlExchangeIds: ['nx-ctrl-vault', 'nx-ctrl-scim'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  const res = verifyCompositeReceipt(receipt, { entries: [ctrlVault403, ctrlScim401, h1, h2, h3, h4] }, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['user_a'],
  })
  assert.equal(res.confirmed, true, `Expected entity-less read terminal chain to confirm, got: ${res.reason}`)
  const stEdge = res.verifiedEdges.find(e => e.kind === 'state_transition_binding' && e.fromHopId === 'patch' && e.toHopId === 'vault')
  assert.ok(stEdge?.verified, 'Host must infer verified state_transition_binding edge patch -> vault')

  // Direct unit verification of resolveEntityLessReadStateTransition (v8-oracle-hydrate fallback)
  const direct = resolveEntityLessReadStateTransition({
    fromEx: h3, toEx: h4, isTerminalTo: true,
    allEntries: [ctrlVault403, ctrlScim401, h1, h2, h3, h4],
    pairExIds: new Set(['nx-h3', 'nx-h4']),
    allHopExIds: new Set(['nx-h1', 'nx-h2', 'nx-h3', 'nx-h4']),
    preCtrlIds: new Set(['nx-ctrl-vault', 'nx-ctrl-scim']),
    normRouteFam: p => (p ?? '').split('?')[0]!,
    sameCredIdentity: (a, b) => a.actorPersona === b.actorPersona,
    probeActorOf: e => (e.actorPersona === capInbox ? 'user_a' : (e.actorPersona ?? null)),
    isLoginCap: () => false, canonicalNonAuthQuery,
  })
  assert.deepEqual(direct, { entityId: 'usr_101', ablationExchangeId: 'nx-ctrl-vault' })
})

test('1A negative guards: rejects 200-only control, anon 401 control, post-mutation control, non-privilege POST, and actor mismatch', () => {
  const baseHops = (fromMethod: string, fromPath: string, fromReqJson?: Record<string, unknown>, fromActor = 'user_a'): {
    receipt: CompositeProofReceipt
    entries: (ctrl: HostTranscriptEntry) => HostSignedTranscript
  } => {
    const h1 = signedEntry('neg-h1', makeStep({
      id: 'neg-h1', arm: 'probe', method: fromMethod, status: 200, pathAndQuery: fromPath,
      actor: { handle: fromActor, role: 'member', tenant: 'org_alpha', auth: 'bearer', sameSite: null },
      ...(fromReqJson ? { requestJson: fromReqJson } : {}),
      json: { ok: true },
    }), { seq: 2, timestampMs: 1100, actorPersona: fromActor })
    const h2 = signedEntry('neg-h2', makeStep({
      id: 'neg-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/audit/vault',
      json: { secret: 'vault_data' },
    }), { seq: 3, timestampMs: 1200 })
    const receipt: CompositeProofReceipt = {
      chainId: 'nx-neg-test',
      terminalVulnClass: 'privilege_escalation',
      hops: [
        { hopId: 'mut', surface: 'http', target: { origin: ORIGIN, method: fromMethod, pathAndQuery: fromPath }, exchangeIds: ['neg-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Mutation step', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'vault', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/audit/vault' }, exchangeIds: ['neg-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read vault', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'vault', terminalExchangeId: 'neg-h2',
        summary: 'Entity-less read terminal negative test case.', claimedImpact: 'Entity-less read terminal negative test case.',
        preChainControlExchangeIds: ['neg-ctrl'], postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }
    return { receipt, entries: ctrl => ({ entries: [ctrl, h1, h2] }) }
  }

  // (1) Pre-chain control returned 200 (never denied!) -> MUST fail closed
  const c200 = signedEntry('neg-ctrl', makeStep({ id: 'neg-ctrl', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/audit/vault', json: { secret: 'already_accessible' } }), { seq: 1, timestampMs: 1000 })
  const t1 = baseHops('PATCH', '/v1/scim/users/usr_101', { role: 'owner' })
  assert.equal(verifyCompositeReceipt(t1.receipt, t1.entries(c200), { signingKey: SIGNING_KEY, attackerPersonas: ['user_a'] }).confirmed, false)

  // (2) Anonymous 401 control on authenticated terminal -> MUST fail closed
  const cAnon401 = signedEntry('neg-ctrl', makeStep({
    id: 'neg-ctrl', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/v1/audit/vault',
    actor: { handle: 'anon', role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { error: 'unauthorized' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'anon', actorRoleLabel: null })
  assert.equal(verifyCompositeReceipt(t1.receipt, t1.entries(cAnon401), { signingKey: SIGNING_KEY, attackerPersonas: ['user_a'] }).confirmed, false)

  // (3) Denied control timestamped AFTER mutation -> resolveEntityLessReadStateTransition MUST refuse
  const cPost403 = signedEntry('neg-ctrl', makeStep({ id: 'neg-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/v1/audit/vault', json: { error: 'forbidden' } }), { seq: 4, timestampMs: 1300 })
  const t1PostEntries = t1.entries(cPost403).entries!
  assert.equal(resolveEntityLessReadStateTransition({
    fromEx: t1PostEntries[1]!, toEx: t1PostEntries[2]!, isTerminalTo: true,
    allEntries: t1PostEntries, pairExIds: new Set(['neg-h1', 'neg-h2']), allHopExIds: new Set(['neg-h1', 'neg-h2']),
    preCtrlIds: new Set(['neg-ctrl']), normRouteFam: p => (p ?? '').split('?')[0]!,
    sameCredIdentity: (a, b) => a.actorPersona === b.actorPersona, probeActorOf: e => e.actorPersona ?? null, isLoginCap: () => false, canonicalNonAuthQuery,
  }), null)

  // (4) Non-privilege POST route (/v1/comments) without role/privilege fields -> resolveEntityLessReadStateTransition MUST refuse
  const cPre403 = signedEntry('neg-ctrl', makeStep({ id: 'neg-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/v1/audit/vault', json: { error: 'forbidden' } }), { seq: 1, timestampMs: 1000 })
  const t4 = baseHops('POST', '/v1/comments', { text: 'hello' })
  const t4Entries = t4.entries(cPre403).entries!
  assert.equal(resolveEntityLessReadStateTransition({
    fromEx: t4Entries[1]!, toEx: t4Entries[2]!, isTerminalTo: true,
    allEntries: t4Entries, pairExIds: new Set(['neg-h1', 'neg-h2']), allHopExIds: new Set(['neg-h1', 'neg-h2']),
    preCtrlIds: new Set(['neg-ctrl']), normRouteFam: p => (p ?? '').split('?')[0]!,
    sameCredIdentity: (a, b) => a.actorPersona === b.actorPersona, probeActorOf: e => e.actorPersona ?? null, isLoginCap: () => false, canonicalNonAuthQuery,
  }), null)

  // (5) Actor mismatch between mutation (user_b) and terminal (user_a) -> MUST fail closed
  const t5 = baseHops('PATCH', '/v1/scim/users/usr_101', { role: 'owner' }, 'user_b')
  assert.equal(verifyCompositeReceipt(t5.receipt, t5.entries(cPre403), { signingKey: SIGNING_KEY, attackerPersonas: ['user_a', 'user_b'] }).confirmed, false)
})

// ============================================================================
// 1B. Earliest Pre-Mutation Control Selection on state_transition_binding
// ============================================================================

test('1B: auto-selects earliest clean pre-mutation denied control when post-mutation 200 control is cited, and fails closed without one', () => {
  const pre403 = signedEntry('pm-pre403', makeStep({
    id: 'pm-pre403', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/v1/audit/vault', json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })

  const patchMut = signedEntry('pm-patch', makeStep({
    id: 'pm-patch', arm: 'probe', method: 'PATCH', status: 200,
    pathAndQuery: '/v1/scim/users/usr_202', requestJson: { role: 'owner' }, json: { id: 'usr_202', role: 'owner' },
  }), { seq: 2, timestampMs: 1100 })

  const postCtrl200 = signedEntry('pm-post200', makeStep({
    id: 'pm-post200', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/audit/vault', json: { events: [{ id: 'ev_1' }] },
  }), { seq: 3, timestampMs: 1200 })

  const termVault = signedEntry('pm-term', makeStep({
    id: 'pm-term', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/audit/vault', json: { events: [{ id: 'ev_1' }], artifact: 'secret_audit' },
  }), { seq: 4, timestampMs: 1300 })

  const receipt: CompositeProofReceipt = {
    chainId: 'pm-post-mut-ctrl-cited',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'patch', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/scim/users/usr_202' }, exchangeIds: ['pm-patch'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Elevate user role to owner', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'vault', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/audit/vault' }, exchangeIds: ['pm-term'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read owner audit vault', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [
      { kind: 'state_transition_binding', fromHopId: 'patch', toHopId: 'vault', entityId: 'usr_202', ablationExchangeIds: ['pm-post200'] },
    ],
    terminalImpact: {
      terminalHopId: 'vault', terminalExchangeId: 'pm-term',
      summary: 'Persistent role mutation unlocks audit vault despite post-mutation 200 control citation.',
      claimedImpact: 'Persistent role mutation unlocks audit vault despite post-mutation 200 control citation.',
      preChainControlExchangeIds: ['pm-post200'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  // Positive Scenario A: earlier clean pre-mutation 403 exists -> auto-selected and confirmed
  const resOk = verifyCompositeReceipt(receipt, { entries: [pre403, patchMut, postCtrl200, termVault] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['user_a'],
  })
  assert.equal(resOk.confirmed, true, `Expected earliest pre-mutation 403 auto-selection to confirm, got: ${resOk.reason}`)
  assert.equal((resOk.verifiedEdges[0]?.evidence as { ablationExchangeId?: string } | undefined)?.ablationExchangeId, 'pm-pre403')

  // Negative 1: NO pre-mutation denied control in transcript -> MUST fail closed on 200 control!
  const resNoPre = verifyCompositeReceipt(receipt, { entries: [patchMut, postCtrl200, termVault] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['user_a'],
  })
  assert.equal(resNoPre.confirmed, false)
  assert.equal(resNoPre.failedStage, 'edge_binding')

  // Negative 2: Anon 401 pre-mutation control on auth'd route -> MUST NOT be auto-selected!
  const anon401 = signedEntry('pm-anon401', makeStep({
    id: 'pm-anon401', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/v1/audit/vault',
    actor: { handle: 'anon', role: null, tenant: null, auth: 'unknown', sameSite: null }, json: { error: 'login' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'anon', actorRoleLabel: null })
  const resAnon = verifyCompositeReceipt(receipt, { entries: [anon401, patchMut, postCtrl200, termVault] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['user_a'],
  })
  assert.equal(resAnon.confirmed, false)

  // Negative 3: Flaky 403 -> 200 BEFORE mutation with NO intervening mutation -> MUST fail closed!
  const pre200NoMut = signedEntry('pm-post200', makeStep({
    id: 'pm-post200', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/audit/vault', json: { events: [] },
  }), { seq: 2, timestampMs: 1050 })
  const patchLater = signedEntry('pm-patch', makeStep({
    id: 'pm-patch', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: '/v1/scim/users/usr_202',
    requestJson: { role: 'owner' }, json: { id: 'usr_202', role: 'owner' },
  }), { seq: 3, timestampMs: 1150 })
  const resFlaky = verifyCompositeReceipt(receipt, { entries: [pre403, pre200NoMut, patchLater, termVault] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['user_a'],
  })
  assert.equal(resFlaky.confirmed, false)

  // Positive Scenario B: earlier mutation between seq=1 (403) and seq=3 (cited 200) before seq=4 (receipt PATCH) -> confirms!
  const earlierMut = signedEntry('pm-earlier-mut', makeStep({
    id: 'pm-earlier-mut', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: '/v1/scim/users/usr_202',
    requestJson: { role: 'owner' }, json: { id: 'usr_202', role: 'owner' },
  }), { seq: 2, timestampMs: 1020 })
  const mid200 = signedEntry('pm-post200', makeStep({
    id: 'pm-post200', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/audit/vault', json: { events: [] },
  }), { seq: 3, timestampMs: 1080 })
  const resScenarioB = verifyCompositeReceipt(receipt, { entries: [pre403, earlierMut, mid200, patchLater, termVault] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['user_a'],
  })
  assert.equal(resScenarioB.confirmed, true, `Expected Scenario B (earlier persistent mutation in transcript) to confirm, got: ${resScenarioB.reason}`)
})

// ============================================================================
// 2. GET-Terminal Causal-Prefix Supersession + Same-Terminal Multi-Hop Dedup
// ============================================================================

test('2A: deeper GET-terminal chain supersedes its shorter PATCH prefix in both arrival orders', () => {
  const matchExact = (a: UpstreamSupersessionEndpointLike, b: UpstreamSupersessionEndpointLike) =>
    a.origin === b.origin && a.method === b.method && a.normalizedEndpoint === b.normalizedEndpoint

  const fullChain = {
    chainId: 'full-vault-chain',
    hops: [
      { hopId: 'seed', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/comments' } },
      { hopId: 'inbox', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/inbox/cmt_1' } },
      { hopId: 'patch', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/scim/users/usr_1' } },
      { hopId: 'vault', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/audit/vault' } },
    ],
    terminalImpact: { terminalHopId: 'vault' },
  }
  const prefixChain = {
    chainId: 'prefix-patch-chain',
    hops: [
      { hopId: 'seed', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/comments' } },
      { hopId: 'inbox', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/inbox/cmt_1' } },
      { hopId: 'patch', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/scim/users/usr_1' } },
    ],
    terminalImpact: { terminalHopId: 'patch' },
  }
  const fullUp: UpstreamSupersessionEndpointLike[] = [
    { origin: ORIGIN, method: 'POST', normalizedEndpoint: '/v1/comments' },
    { origin: ORIGIN, method: 'GET', normalizedEndpoint: '/v1/inbox/:id' },
    { origin: ORIGIN, method: 'PATCH', normalizedEndpoint: '/v1/scim/users/:id' },
  ]
  const prefixUp: UpstreamSupersessionEndpointLike[] = [
    { origin: ORIGIN, method: 'POST', normalizedEndpoint: '/v1/comments' },
    { origin: ORIGIN, method: 'GET', normalizedEndpoint: '/v1/inbox/:id' },
  ]

  // Direct causal-prefix match with GET winner
  const direct = matchCausalPrefixPartialChainSupersession({
    winnerReceipt: fullChain, winnerOrigin: ORIGIN, winnerUpstreamNonGeneric: fullUp,
    partialReceipt: prefixChain, partialOrigin: ORIGIN, endpointsMatchExact: matchExact,
  })
  assert.ok(direct.length >= 1, 'Deeper GET-terminal chain must match its PATCH causal prefix')

  // Forward arrival: prefix persisted first, full GET chain arrives second -> incoming_supersedes_earlier
  const fwd = resolveCompositeSupersessionMatch({
    incomingReceipt: fullChain, incomingOrigin: ORIGIN, incomingTerminalEndpoint: 'GET /v1/audit/vault',
    incomingUpstreamNonGeneric: fullUp, earlierCompReceipt: prefixChain, earlierOrigin: ORIGIN,
    earlierEndpoints: [...prefixUp, { origin: ORIGIN, method: 'PATCH', normalizedEndpoint: '/v1/scim/users/:id' }],
    endpointsMatchExact: matchExact,
  })
  assert.equal(fwd.direction, 'incoming_supersedes_earlier')

  // Reverse arrival: full GET chain persisted first, prefix arrives second -> earlier_supersedes_incoming
  const rev = resolveCompositeSupersessionMatch({
    incomingReceipt: prefixChain, incomingOrigin: ORIGIN, incomingTerminalEndpoint: 'PATCH /v1/scim/users/:id',
    incomingUpstreamNonGeneric: prefixUp, earlierCompReceipt: fullChain, earlierOrigin: ORIGIN,
    earlierEndpoints: [...fullUp, { origin: ORIGIN, method: 'GET', normalizedEndpoint: '/v1/audit/vault' }],
    endpointsMatchExact: matchExact,
  })
  assert.equal(rev.direction, 'earlier_supersedes_incoming')
})

test('2B: exact-same-terminal multi-hop dedup supersedes shallower/weaker findings without merging distinct terminals or injection/XSS/SSRF', () => {
  const matchExact = (a: UpstreamSupersessionEndpointLike, b: UpstreamSupersessionEndpointLike) =>
    a.origin === b.origin && a.method === b.method && a.normalizedEndpoint === b.normalizedEndpoint

  const deepSync = {
    chainId: 'sync-4hop',
    hops: [
      { hopId: 'h1', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/search/projects' } },
      { hopId: 'h2', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/projects/p1/webhooks' } },
      { hopId: 'h3', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/projects/p1/webhooks/w1/deliveries' } },
      { hopId: 'h4', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/integrations/registry/sync' } },
    ],
    causalEdges: [{}, {}, {}],
    terminalImpact: { terminalHopId: 'h4' },
  }
  const shallowSync = {
    chainId: 'sync-2hop',
    hops: [
      { hopId: 'h1', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/repos/p1/webhooks' } },
      { hopId: 'h2', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/integrations/registry/sync' } },
    ],
    causalEdges: [{}],
    terminalImpact: { terminalHopId: 'h2' },
  }
  const resDeeper = matchSameTerminalCompositeDedup({
    incomingReceipt: deepSync, incomingOrigin: ORIGIN, earlierCompReceipt: shallowSync, earlierOrigin: ORIGIN, endpointsMatchExact: matchExact,
  })
  assert.equal(resDeeper.direction, 'incoming_supersedes_earlier')
  const resShallower = matchSameTerminalCompositeDedup({
    incomingReceipt: shallowSync, incomingOrigin: ORIGIN, earlierCompReceipt: deepSync, earlierOrigin: ORIGIN, endpointsMatchExact: matchExact,
  })
  assert.equal(resShallower.direction, 'earlier_supersedes_incoming')

  // Equal depth (3 vs 3): formal v8 oracle (economic_conservation) beats non-oracle (broken_access_control) on same settle-race terminal
  const settleAlt = {
    chainId: 'settle-alt',
    hops: [
      { hopId: 'h1', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' } },
      { hopId: 'h2', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' } },
      { hopId: 'h3', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_1/settle-race' } },
    ],
    causalEdges: [{}, {}],
    terminalImpact: { terminalHopId: 'h3' },
  }
  const settleEcon = {
    chainId: 'settle-econ',
    hops: [
      { hopId: 'h1', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders' } },
      { hopId: 'h2', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/orders/ord_2/rebind' } },
      { hopId: 'h3', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/orders/ord_2/settle-race' } },
    ],
    causalEdges: [{}, {}],
    terminalImpact: { terminalHopId: 'h3' },
  }
  const econWins = resolveCompositeSupersessionMatch({
    incomingReceipt: settleEcon, incomingOrigin: ORIGIN, incomingOracleFamily: 'economic_conservation',
    incomingUpstreamNonGeneric: [{ origin: ORIGIN, method: 'POST', normalizedEndpoint: '/v1/orders' }],
    earlierCompReceipt: settleAlt, earlierOrigin: ORIGIN, earlierOracleFamily: null, earlierEndpoints: [],
    endpointsMatchExact: matchExact,
  })
  assert.equal(econWins.direction, 'incoming_supersedes_earlier')
  assert.equal(econWins.sameTerminal, true)

  // Complete tie -> earlier wins (later-created duplicate is superseded)
  const tieRes = matchSameTerminalCompositeDedup({
    incomingReceipt: settleEcon, incomingOrigin: ORIGIN, incomingOracleFamily: 'economic_conservation',
    earlierCompReceipt: settleEcon, earlierOrigin: ORIGIN, earlierOracleFamily: 'economic_conservation',
    endpointsMatchExact: matchExact,
  })
  assert.equal(tieRes.direction, 'earlier_supersedes_incoming')

  // Distinct terminals (settle-race vs payouts/approve) -> NEVER merged
  const payoutApprove = {
    chainId: 'payout-approve',
    hops: [
      { hopId: 'h1', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' } },
      { hopId: 'h2', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/pay_1/approve' } },
    ],
    terminalImpact: { terminalHopId: 'h2' },
  }
  assert.equal(matchSameTerminalCompositeDedup({
    incomingReceipt: settleAlt, incomingOrigin: ORIGIN, earlierCompReceipt: payoutApprove, earlierOrigin: ORIGIN, endpointsMatchExact: matchExact,
  }).direction, 'none')

  // Distinct origins -> NEVER merged
  assert.equal(matchSameTerminalCompositeDedup({
    incomingReceipt: deepSync, incomingOrigin: ORIGIN, earlierCompReceipt: shallowSync, earlierOrigin: 'https://other.example.test', endpointsMatchExact: matchExact,
  }).direction, 'none')

  // Class compatibility: authz/privesc/economic compatible; SQLi/XSS/SSRF strictly excluded
  assert.equal(isSameTerminalCompositeClassCompatible({ cwe: 'CWE-863', vulnClass: 'broken_access_control' }, { vulnClass: 'economic_conservation', terminalOracleFamily: 'economic_conservation' }), true)
  assert.equal(isSameTerminalCompositeClassCompatible({ cwe: 'CWE-639', vulnClass: 'broken_access_control' }, { vulnClass: 'dual_tenant_abac', terminalOracleFamily: 'dual_tenant_abac' }), true)
  assert.equal(isSameTerminalCompositeClassCompatible({ cwe: 'CWE-89', vulnClass: 'sqli' }, { vulnClass: 'broken_access_control' }), false)
  assert.equal(isSameTerminalCompositeClassCompatible({ cwe: 'CWE-79', vulnClass: 'xss' }, { vulnClass: 'broken_access_control' }), false)
  assert.equal(isSameTerminalCompositeClassCompatible({ cwe: 'CWE-918', vulnClass: 'ssrf' }, { vulnClass: 'economic_conservation' }), false)
})

// ============================================================================
// 3. 1-Hop Signed-URL GET/HEAD Provenance Guard
// ============================================================================

test('3: rejects 1-hop signed-URL/header GET/HEAD without in-DAG provenance while preserving 2-hop signed-URL TPs and plain GET proofs', () => {
  const ctrl403 = signedEntry('su-ctrl', makeStep({
    id: 'su-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/files/export/org_beta/report.csv?tenant=org_beta&job=job_1',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })

  const probe1Hop = signedEntry('su-p1', makeStep({
    id: 'su-p1', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/files/export/org_beta/report.csv?tenant=org_beta&sig=deadbeef1234567890&job=job_1',
    body: 'tenant,account,balance\norg_beta,acc_9,50000\n',
  }), { seq: 2, timestampMs: 1100 })

  // (a) 1-hop smuggled ?sig=... GET -> MUST FAIL CLOSED
  const receipt1Hop: CompositeProofReceipt = {
    chainId: 'su-1hop-smuggled',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'dl', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/files/export/org_beta/report.csv?tenant=org_beta&sig=deadbeef1234567890&job=job_1' }, exchangeIds: ['su-p1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Download foreign export with smuggled signature', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'dl', terminalExchangeId: 'su-p1',
      summary: 'Smuggled 1-hop signed export download without in-DAG provenance.',
      claimedImpact: 'Smuggled 1-hop signed export download without in-DAG provenance.',
      preChainControlExchangeIds: ['su-ctrl'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const r1 = verifyCompositeReceipt(receipt1Hop, { entries: [ctrl403, probe1Hop] }, { signingKey: SIGNING_KEY, attackerPersonas: ['user_a'] })
  assert.equal(r1.confirmed, false)
  assert.match(r1.reason, /signed_url_unproven_capability_provenance/)

  // (b) 1-hop GET with X-Signature header + 401 control -> MUST FAIL CLOSED
  const ctrlHdr401 = signedEntry('su-hctrl', makeStep({
    id: 'su-hctrl', arm: 'control', method: 'GET', status: 401,
    pathAndQuery: '/files/export/org_beta/report.csv', json: { error: 'missing_sig' },
  }), { seq: 1, timestampMs: 1000 })
  const probeHdr = signedEntry('su-phdr', makeStep({
    id: 'su-phdr', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/files/export/org_beta/report.csv',
    requestHeaders: { 'x-amz-signature': 'smuggled_header_sig_999' },
    body: 'tenant,account,balance\norg_beta,acc_9,50000\n',
  }), { seq: 2, timestampMs: 1100 })
  const receiptHdr: CompositeProofReceipt = {
    ...receipt1Hop, chainId: 'su-1hop-hdr',
    hops: [{ ...receipt1Hop.hops[0]!, target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/files/export/org_beta/report.csv' }, exchangeIds: ['su-phdr'] }],
    terminalImpact: { ...receipt1Hop.terminalImpact, terminalExchangeId: 'su-phdr', preChainControlExchangeIds: ['su-hctrl'] },
  }
  const rHdr = verifyCompositeReceipt(receiptHdr, { entries: [ctrlHdr401, probeHdr] }, { signingKey: SIGNING_KEY, attackerPersonas: ['user_a'] })
  assert.equal(rHdr.confirmed, false)
  assert.match(rHdr.reason, /signed_url_unproven_capability_provenance/)

  // (c) 2-hop legitimate chain (mint signed URL -> download with cap edge) -> MUST CONFIRM!
  const urlCap = 'cap:hop_mint:signed_url_1'
  const mintHop = signedEntry('su-mint', makeStep({
    id: 'su-mint', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/exports/job_1/url',
    json: { signedUrl: '/files/export/org_beta/report.csv?tenant=org_beta&sig=deadbeef1234567890&job=job_1' },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [urlCap] })
  const dlHop = signedEntry('su-dl', makeStep({
    id: 'su-dl', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/files/export/org_beta/report.csv?tenant=org_beta&sig=deadbeef1234567890&job=job_1',
    body: 'tenant,account,balance\norg_beta,acc_9,50000\n',
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [urlCap] })
  const receipt2Hop: CompositeProofReceipt = {
    chainId: 'su-2hop-legit',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'mint', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/exports/job_1/url' }, exchangeIds: ['su-mint'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Mint signed export URL', producedCapabilities: [urlCap], consumedCapabilities: [] },
      { hopId: 'dl', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/files/export/org_beta/report.csv?tenant=org_beta&sig=deadbeef1234567890&job=job_1' }, exchangeIds: ['su-dl'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Download foreign export using minted signed URL', producedCapabilities: [], consumedCapabilities: [urlCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'mint', toHopId: 'dl', capabilityHandle: urlCap }],
    terminalImpact: {
      terminalHopId: 'dl', terminalExchangeId: 'su-dl',
      summary: 'Two-hop export URL mint and cross-tenant download with host-bound capability edge.',
      claimedImpact: 'Two-hop export URL mint and cross-tenant download with host-bound capability edge.',
      preChainControlExchangeIds: ['su-ctrl'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const r2 = verifyCompositeReceipt(receipt2Hop, { entries: [ctrl403, mintHop, dlHop] }, { signingKey: SIGNING_KEY, attackerPersonas: ['user_a'] })
  assert.equal(r2.confirmed, true, `Expected 2-hop signed-URL chain to confirm, got: ${r2.reason}`)

  // (d) Plain 1-hop non-signed cross-tenant GET BOLA (no sig query/header) -> MUST STILL CONFIRM!
  const plainCtrl = signedEntry('pl-ctrl', makeStep({
    id: 'pl-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/v1/docs/doc_beta_1/content?view=full', json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })
  const plainProbe = signedEntry('pl-probe', makeStep({
    id: 'pl-probe', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/docs/doc_beta_1/content?view=full',
    json: { tenantId: 'org_beta', content: 'private_foreign_document_text' },
  }), { seq: 2, timestampMs: 1100 })
  const receiptPlain: CompositeProofReceipt = {
    chainId: 'plain-1hop-bola',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'read', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/docs/doc_beta_1/content?view=full' }, exchangeIds: ['pl-probe'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign tenant document content', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'read', terminalExchangeId: 'pl-probe',
      summary: 'Cross-tenant document content read without signed-URL parameters.',
      claimedImpact: 'Cross-tenant document content read without signed-URL parameters.',
      preChainControlExchangeIds: ['pl-ctrl'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const rPlain = verifyCompositeReceipt(receiptPlain, { entries: [plainCtrl, plainProbe] }, { signingKey: SIGNING_KEY, attackerPersonas: ['user_a'] })
  assert.equal(rPlain.confirmed, true, `Expected plain 1-hop non-signed GET BOLA to still confirm, got: ${rPlain.reason}`)
})

// ============================================================================
// R3-05 independent-review hardening (claude-sonnet-5-5-high): entity-less inference must bind the
// denied control to the same non-auth query, and benign mutations (generic payload keys / benign
// user sub-resources) must never qualify as a privilege mutation.
// ============================================================================

test('R3-05 review: entity-less read inference rejects query-mismatched controls and benign mutation shapes', () => {
  const resolve = (fromPath: string, payload: Record<string, unknown>, ctrlPath: string, method = 'POST') => {
    const ctrl = signedEntry('rv-ctrl', makeStep({ id: 'rv-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: ctrlPath, json: { error: 'forbidden' } }), { seq: 1, timestampMs: 1000 })
    const h1 = signedEntry('neg-h1', makeStep({
      id: 'neg-h1', arm: 'probe', method, status: 200, pathAndQuery: fromPath,
      actor: { handle: 'user_a', role: 'member', tenant: 'org_alpha', auth: 'bearer', sameSite: null },
      requestJson: payload, json: { ok: true },
    }), { seq: 2, timestampMs: 1100, actorPersona: 'user_a' })
    const h2 = signedEntry('neg-h2', makeStep({ id: 'neg-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/audit/vault', json: { secret: 'vault_data' } }), { seq: 3, timestampMs: 1200 })
    const es = [ctrl, h1, h2]
    return resolveEntityLessReadStateTransition({
      fromEx: es[1]!, toEx: es[2]!, isTerminalTo: true,
      allEntries: es, pairExIds: new Set(['neg-h1', 'neg-h2']), allHopExIds: new Set(['neg-h1', 'neg-h2']),
      preCtrlIds: new Set(['rv-ctrl']), normRouteFam: p => (p ?? '').split('?')[0]!,
      sameCredIdentity: (a, b) => a.actorPersona === b.actorPersona, probeActorOf: e => e.actorPersona ?? null, isLoginCap: () => false, canonicalNonAuthQuery,
    })
  }
  // Control: denied under the SAME route and query -> binds (sanity).
  assert.ok(resolve('/v1/scim/users/usr_101', { role: 'owner' }, '/v1/audit/vault', 'PATCH'))
  // Control denied on a DIFFERENT query (other tenant/resource) must not bind to the unqualified terminal.
  assert.equal(resolve('/v1/scim/users/usr_101', { role: 'owner' }, '/v1/audit/vault?org=other', 'PATCH'), null)
  // Generic payload keys on a benign route are not privilege mutations.
  assert.equal(resolve('/v1/comments', { text: 'x', scope: 'public', level: 'info', group: 'g1' }, '/v1/audit/vault'), null)
  // Benign user sub-resources are not privilege mutations.
  assert.equal(resolve('/v1/users/usr_101/preferences', { theme: 'dark' }, '/v1/audit/vault', 'PATCH'), null)
})
