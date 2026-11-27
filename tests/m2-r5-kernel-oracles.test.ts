// @kernel @fixes R3-05
/**
 * M2 R5 Confirmation-Kernel & Oracle Soundness Regression Suite.
 *
 * Covers all 6 systemic kernel fixes and negative bypass invariants:
 *  - R1: Inbound `webhook_forgery` uses `auth_or_logic` (no false OOB demand) while outbound OOB
 *        webhook SSRF still enforces `'oob'`.
 *  - R2: `economic_conservation` filters intermediate read-only `GET` hops from `actions`,
 *        sums append-only ledger/transaction arrays (`entries`/`transactions`/`ledger`) with debit
 *        negation, and excludes control-denied unauthorized credit probes from `authorizedDeposits`
 *        (while preserving legitimate deposits and rejecting cross-actor 401 spoofing).
 *  - R3: `isJobOrHandleStub` accepts verified `POST`/`PUT` session-token grants carrying identity/
 *        authority claims when paired with a verified denied control on the same endpoint, while
 *        keeping unverified (`verified: false`), pending/queued, PAT, and async job stubs rejected.
 *  - R5: (a) Zero-delta `postMutRb` guard rejects post-mutation readbacks identical to an earlier
 *        same-route, same-actor baseline; (b) 1-hop forged-signature / webhook provenance guard
 *        rejects 1-hop `POST`/`PUT` receipts with 401 control + signature header without in-DAG
 *        secret provenance while leaving legitimate 1-hop race/double-spend proofs intact.
 *  - R6: Generic bidirectional causal-prefix partial-chain supersession (both arrival orders) with
 *        authz/privesc class compatibility and strict SQLi/XSS/cross-origin/generic-route exclusion.
 *  - R8: `dual_tenant_abac` `dual_org_cache_bleed` fails fast with `actor_not_dual_tenant` for
 *        single-tenant actors before `missing_tenant_scope`, and resolves opaque plain-text
 *        `bledAccess` `targetTenantId` for genuine dual-tenant actors without loosening JSON guards.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  isAuthzPrivescClassSupersessionCompatible,
  matchCausalPrefixPartialChainSupersession,
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
import { isFindingClassSupersessionCompatible } from '../src/server/exec-verify.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { resolveCompositeTerminalContract } from '../src/server/oracle-spec.ts'
import { extractLedgerBalanceMap, selectVerifiedPostMutationReadback } from '../src/server/own-org-terminal-guard.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import { evaluateDualTenantAbac, isJobOrHandleStub } from '../src/server/v8-oracle-families.ts'
import { hydrateV8OracleInput, type HydratableTranscriptIndex } from '../src/server/v8-oracle-hydrate.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'test-m2-r5-kernel-oracles-signing-key-0123456789'

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
    actorPersona: extra.actorPersona ?? step.actor.handle ?? 'user_a',
    actorRoleLabel: extra.actorRoleLabel ?? `${step.actor.role ?? 'member'} (${step.actor.tenant ?? 'org_alpha'})`,
    step: { route: step.pathAndQuery?.split('?')[0], ...step },
    ...extra,
  }
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}

// ============================================================================
// R1: Inbound webhook_forgery vs outbound OOB contract
// ============================================================================

test('R1: inbound webhook_forgery confirms 3-hop chain without OOB; outbound OOB still demands OOB', () => {
  assert.equal(resolveCompositeTerminalContract('webhook_forgery', false), 'auth_or_logic')
  assert.equal(resolveCompositeTerminalContract('webhook_forgery', true), 'oob')
  assert.equal(resolveCompositeTerminalContract('ssrf', false), 'oob')

  const jobCap = 'cap:hop_render:job_1'
  const secCap = 'cap:hop_trace:secret_1'

  const ctrl401 = signedEntry('r1-ctrl', makeStep({
    id: 'r1-ctrl', arm: 'control', method: 'POST', status: 401,
    pathAndQuery: '/v1/webhooks/billing',
    requestHeaders: { 'content-type': 'application/json', 'x-signature': 'bad_sig' },
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })

  const h1 = signedEntry('r1-h1', makeStep({
    id: 'r1-h1', arm: 'probe', method: 'POST', status: 202,
    pathAndQuery: '/v1/invoices/inv_101/render',
    json: { jobId: 'job_101', invoiceId: 'inv_101' },
  }), { seq: 2, timestampMs: 1100, emittedCapabilities: [jobCap] })

  const h2 = signedEntry('r1-h2', makeStep({
    id: 'r1-h2', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/jobs/job_101/trace',
    json: { jobId: 'job_101', status: 'done', leakedSecret: 'whsec_test_99' },
  }), { seq: 3, timestampMs: 1200, consumedCapabilities: [jobCap], emittedCapabilities: [secCap] })

  const h3 = signedEntry('r1-h3', makeStep({
    id: 'r1-h3', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/webhooks/billing',
    requestHeaders: { 'content-type': 'application/json', 'x-signature': 'valid_forged_sig' },
    json: { accepted: true, tenantId: 'org_beta', amountCents: 50000 },
  }), { seq: 4, timestampMs: 1300, consumedCapabilities: [secCap] })

  const rb = signedEntry('r1-rb', makeStep({
    id: 'r1-rb', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/ledger',
    actor: { handle: 'user_b', role: 'member', tenant: 'org_beta', auth: 'bearer', sameSite: null },
    json: { entries: [{ id: 'e1', tenantId: 'org_beta', amountCents: 50000 }] },
  }), { seq: 5, timestampMs: 1400, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)' })

  const receipt: CompositeProofReceipt = {
    chainId: 'r1-3hop-webhook-forgery',
    terminalVulnClass: 'webhook_forgery',
    hops: [
      { hopId: 'render', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/invoices/inv_101/render' }, exchangeIds: ['r1-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Start async render job', producedCapabilities: [jobCap], consumedCapabilities: [] },
      { hopId: 'trace', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/jobs/job_101/trace' }, exchangeIds: ['r1-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leak webhook signing secret from job trace', producedCapabilities: [secCap], consumedCapabilities: [jobCap] },
      { hopId: 'forge', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/billing' }, exchangeIds: ['r1-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Submit forged billing webhook with leaked secret', producedCapabilities: [], consumedCapabilities: [secCap] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'render', toHopId: 'trace', capabilityHandle: jobCap },
      { kind: 'value_binding', fromHopId: 'trace', toHopId: 'forge', capabilityHandle: secCap },
    ],
    terminalImpact: {
      terminalHopId: 'forge',
      terminalExchangeId: 'r1-h3',
      summary: 'Three-hop leaked secret enables forged inbound billing webhook crediting victim ledger.',
      claimedImpact: 'Three-hop leaked secret enables forged inbound billing webhook crediting victim ledger.',
      preChainControlExchangeIds: ['r1-ctrl'],
      postChainReadbackExchangeIds: ['r1-rb'],
    },
    replayMode: 'fresh_clean_replay',
  }

  const res = verifyCompositeReceipt(receipt, { entries: [ctrl401, h1, h2, h3, rb] }, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['user_a'],
  })
  assert.equal(res.confirmed, true, `Expected 3-hop inbound webhook_forgery to confirm, got: ${res.reason}`)
})

// ============================================================================
// R2: economic_conservation multi-hop actions filter + ledger summation + deposit guard
// ============================================================================

test('R2: extractLedgerBalanceMap sums large ledger arrays with debit negation and groups by tenant/account', () => {
  const entries = Array.from({ length: 132 }, (_, i) => ({
    id: `le_${i}`,
    tenantId: i % 2 === 0 ? 'org_alpha' : 'org_beta',
    amountCents: 1000,
    type: i === 1 ? 'debit' : 'credit',
  }))
  const map = extractLedgerBalanceMap({ entries })
  assert.deepEqual({ ...map }, { org_alpha: 66000, org_beta: 64000 })
  assert.deepEqual({ ...extractLedgerBalanceMap({ transactions: [{ delta: 500 }, { amount: 200, direction: 'withdrawal' }] }) }, { default: 300 })
  assert.equal(extractLedgerBalanceMap({ entries: [] }), undefined)
})

test('R2: 3-hop economic_conservation with GET trace in actionExchangeIds and ledger readback confirms while GET-only and legit deposits fail closed', () => {
  const jobCap = 'cap:r2:job_1'
  const secCap = 'cap:r2:sec_1'

  const baseLedger = signedEntry('r2-base', makeStep({
    id: 'r2-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/ledger',
    json: { entries: Array.from({ length: 40 }, (_, i) => ({ id: `e_${i}`, tenantId: 'org_alpha', amountCents: 1000 })) },
  }), { seq: 1, timestampMs: 1000 })

  const ctrl401 = signedEntry('r2-ctrl', makeStep({
    id: 'r2-ctrl', arm: 'control', method: 'POST', status: 401,
    pathAndQuery: '/v1/webhooks/billing',
    requestHeaders: { 'content-type': 'application/json', 'x-signature': 'bad_sig' },
    requestJson: { tenantId: 'org_alpha', amountCents: 99999 },
    json: { error: 'invalid_signature' },
  }), { seq: 2, timestampMs: 1050 })

  const h1 = signedEntry('r2-h1', makeStep({
    id: 'r2-h1', arm: 'probe', method: 'POST', status: 202,
    pathAndQuery: '/v1/invoices/inv_202/render',
    json: { jobId: 'job_202' },
  }), { seq: 3, timestampMs: 1100, emittedCapabilities: [jobCap] })

  const h2 = signedEntry('r2-h2', makeStep({
    id: 'r2-h2', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/jobs/job_202/trace',
    json: { jobId: 'job_202', status: 'done', leakedSecret: 'whsec_202' },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [jobCap], emittedCapabilities: [secCap] })

  const h3 = signedEntry('r2-h3', makeStep({
    id: 'r2-h3', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/webhooks/billing',
    requestHeaders: { 'content-type': 'application/json', 'x-signature': 'valid_forged_sig' },
    requestJson: { tenantId: 'org_alpha', amountCents: 25000 },
    json: { accepted: true, tenantId: 'org_alpha', amountCents: 25000 },
  }), { seq: 5, timestampMs: 1300, consumedCapabilities: [secCap] })

  const finLedger = signedEntry('r2-fin', makeStep({
    id: 'r2-fin', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/ledger',
    json: {
      entries: [
        ...Array.from({ length: 40 }, (_, i) => ({ id: `e_${i}`, tenantId: 'org_alpha', amountCents: 1000 })),
        { id: 'e_40', tenantId: 'org_alpha', amountCents: 25000 },
      ],
    },
  }), { seq: 6, timestampMs: 1400 })

  const receipt: CompositeProofReceipt = {
    chainId: 'r2-3hop-econ-ledger',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'render', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/invoices/inv_202/render' }, exchangeIds: ['r2-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Trigger render job', producedCapabilities: [jobCap], consumedCapabilities: [] },
      { hopId: 'trace', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/jobs/job_202/trace' }, exchangeIds: ['r2-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read secret from job trace', producedCapabilities: [secCap], consumedCapabilities: [jobCap] },
      { hopId: 'settle', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/billing' }, exchangeIds: ['r2-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Credit ledger with forged webhook', producedCapabilities: [], consumedCapabilities: [secCap] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'render', toHopId: 'trace', capabilityHandle: jobCap },
      { kind: 'value_binding', fromHopId: 'trace', toHopId: 'settle', capabilityHandle: secCap },
    ],
    terminalImpact: {
      terminalHopId: 'settle',
      terminalExchangeId: 'r2-h3',
      summary: 'Three-hop forged webhook mints 25000 cents in append-only ledger.',
      claimedImpact: 'Three-hop forged webhook mints 25000 cents in append-only ledger.',
      oracleFamily: 'economic_conservation',
      oracleInput: {
        baselineReadbackExchangeId: 'r2-base',
        finalReadbackExchangeId: 'r2-fin',
        actionExchangeIds: ['r2-h1', 'r2-h2', 'r2-h3'],
      },
      preChainControlExchangeIds: ['r2-ctrl', 'r2-base'],
      postChainReadbackExchangeIds: ['r2-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }

  const res = verifyCompositeReceipt(receipt, { entries: [baseLedger, ctrl401, h1, h2, h3, finLedger] }, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['user_a'],
  })
  assert.equal(res.confirmed, true, `Expected 3-hop ledger economic_conservation to confirm, got: ${res.reason}`)

  // Negative bypass 1: GET-only actionExchangeIds still fails with action_not_mutating
  const getOnlyRes = verifyCompositeReceipt({
    ...receipt,
    chainId: 'r2-get-only-actions',
    terminalImpact: {
      ...receipt.terminalImpact,
      oracleInput: {
        baselineReadbackExchangeId: 'r2-base',
        finalReadbackExchangeId: 'r2-fin',
        actionExchangeIds: ['r2-h2'],
      },
    },
  }, { entries: [baseLedger, ctrl401, h1, h2, h3, finLedger] }, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['user_a'],
  })
  assert.equal(getOnlyRes.confirmed, false)
  assert.match(getOnlyRes.reason, /action_not_mutating/i)

  // Negative bypass 2: Legitimate deposit (no denied control) OR cross-actor anon 401 still counts as authorizedDeposit -> balance_ledger_conserved
  const anon401 = signedEntry('r2-anon-401', makeStep({
    id: 'r2-anon-401', arm: 'control', method: 'POST', status: 401,
    pathAndQuery: '/v1/deposits',
    actor: { handle: 'anonymous', role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { error: 'login_required' },
  }), { seq: 2, timestampMs: 1050, actorPersona: 'anonymous', actorRoleLabel: 'anonymous' })
  const legitDeposit = signedEntry('r2-dep', makeStep({
    id: 'r2-dep', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/deposits',
    requestJson: { amountCents: 25000 },
    json: { deposited: true, amountCents: 25000 },
  }), { seq: 3, timestampMs: 1200 })
  const depRes = verifyCompositeReceipt({
    chainId: 'r2-legit-deposit-bypass',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'dep', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/deposits' }, exchangeIds: ['r2-dep'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Authorized deposit', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'dep',
      terminalExchangeId: 'r2-dep',
      summary: 'Attempt to treat legitimate deposit with anon 401 as value minting.',
      claimedImpact: 'Attempt to treat legitimate deposit with anon 401 as value minting.',
      oracleFamily: 'economic_conservation',
      oracleInput: {
        baselineReadbackExchangeId: 'r2-base',
        finalReadbackExchangeId: 'r2-fin',
        actionExchangeIds: ['r2-dep'],
      },
      preChainControlExchangeIds: ['r2-anon-401', 'r2-base'],
      postChainReadbackExchangeIds: ['r2-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [baseLedger, anon401, legitDeposit, finLedger] }, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['user_a'],
  })
  assert.equal(depRes.confirmed, false)
  assert.match(depRes.reason, /balance_ledger_conserved/i)
})

// ============================================================================
// R3: Session-token redemption with verified denied control vs stub bypasses
// ============================================================================

test('R3: isJobOrHandleStub accepts verified POST session grants with denied control while rejecting unverified/job/PAT stubs', () => {
  // Default 5-arg call stays strict (unexercised without denied control)
  assert.equal(isJobOrHandleStub({ token: 'sess_ok_99', tenant: 'org_alpha', role: 'admin' }, undefined, 200, 'POST', '/v1/invites/redeem'), true)
  // Paired with verified denied control -> concrete session/privilege grant!
  assert.equal(isJobOrHandleStub({ token: 'sess_ok_99', tenant: 'org_alpha', role: 'admin' }, undefined, 200, 'POST', '/v1/invites/redeem', undefined, true), false)

  // Bypass variants MUST stay rejected even with hasDeniedControl = true:
  assert.equal(isJobOrHandleStub({ token: 'sess_unv_1', tenant: 'org_alpha', role: 'finance', verified: false }, undefined, 200, 'POST', '/v1/invites/resolve', undefined, true), true)
  assert.equal(isJobOrHandleStub({ jobId: 'job_42', status: 'queued', downloadUrl: '/dl/42' }, undefined, 202, 'POST', '/v1/exports', undefined, true), true)
  assert.equal(isJobOrHandleStub({ patId: 'pat_1', token: 'pat_tok_1', scopes: ['repo:read'] }, undefined, 201, 'POST', '/v1/pats', undefined, true), true)
  assert.equal(isJobOrHandleStub({ token: 'sess_pend', tenant: 'org_alpha', role: 'admin', status: 'pending' }, undefined, 200, 'POST', '/v1/invites/redeem', undefined, true), true)
  assert.equal(isJobOrHandleStub({ signedUrl: 'https://storage.example.test/a.csv?sig=1' }, undefined, 200, 'POST', '/v1/exports/sign', undefined, true), true)

  // End-to-end 2-hop invite redemption with 403 denied control confirms cleanly
  const invCap = 'cap:r3:invite_tok'
  const userB = { handle: 'user_b', role: 'member' as const, tenant: 'org_beta', auth: 'bearer' as const, sameSite: null }
  const ctrl403 = signedEntry('r3-ctrl', makeStep({
    id: 'r3-ctrl', arm: 'control', method: 'POST', status: 403,
    pathAndQuery: '/v1/invites/redeem', actor: userB, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)' })
  const leak = signedEntry('r3-leak', makeStep({
    id: 'r3-leak', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/directory/invites', actor: userB,
    json: { pendingInvite: 'inv_tok_secret_1', tenant: 'org_alpha' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)', emittedCapabilities: [invCap] })
  const redeem = signedEntry('r3-redeem', makeStep({
    id: 'r3-redeem', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/invites/redeem', actor: userB,
    json: { token: 'admin_sess_tok_9988', tenant: 'org_alpha', role: 'admin' },
  }), { seq: 3, timestampMs: 1200, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)', consumedCapabilities: [invCap] })

  const res = verifyCompositeReceipt({
    chainId: 'r3-invite-redeem-2hop',
    terminalVulnClass: 'broken_access_control',
    hops: [
      { hopId: 'leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/directory/invites' }, exchangeIds: ['r3-leak'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leak foreign invite token', producedCapabilities: [invCap], consumedCapabilities: [] },
      { hopId: 'redeem', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/invites/redeem' }, exchangeIds: ['r3-redeem'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Redeem invite into foreign org admin session', producedCapabilities: [], consumedCapabilities: [invCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'leak', toHopId: 'redeem', capabilityHandle: invCap }],
    terminalImpact: {
      terminalHopId: 'redeem',
      terminalExchangeId: 'r3-redeem',
      summary: 'Foreign tenant invite redemption grants admin session token after 403 control.',
      claimedImpact: 'Foreign tenant invite redemption grants admin session token after 403 control.',
      preChainControlExchangeIds: ['r3-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl403, leak, redeem] }, { signingKey: SIGNING_KEY, attackerPersonas: ['user_b'] })
  assert.equal(res.confirmed, true, `Expected 2-hop invite redemption with 403 control to confirm, got: ${res.reason}`)
})

// ============================================================================
// R5: Zero-delta postMutRb guard + 1-hop forged-signature provenance guard
// ============================================================================

test('R5(a): zero-delta postMutRb (owner -> owner) fails closed while real delta (viewer -> owner) confirms', () => {
  const tokCap = 'cap:r5a:scim_tok'
  const viewerA = { handle: 'viewer_a', role: 'viewer' as const, tenant: 'org_alpha', auth: 'bearer' as const, sameSite: null }

  const makeChain = (preRole: string, postRole: string) => {
    const who = signedEntry(`r5a-who-${preRole}`, makeStep({
      id: `r5a-who-${preRole}`, arm: 'probe', method: 'GET', status: 200,
      pathAndQuery: '/v1/me', actor: viewerA,
      json: { userId: 'u_101', tenant: 'org_alpha', role: preRole, ts: 1000 },
    }), { seq: 1, timestampMs: 1000, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)' })
    const ctrl = signedEntry(`r5a-ctrl-${preRole}`, makeStep({
      id: `r5a-ctrl-${preRole}`, arm: 'control', method: 'PATCH', status: 401,
      pathAndQuery: '/v1/scim/users/u_101', actor: viewerA, json: { error: 'unauthorized' },
    }), { seq: 2, timestampMs: 1050, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)' })
    const leak = signedEntry(`r5a-leak-${preRole}`, makeStep({
      id: `r5a-leak-${preRole}`, arm: 'probe', method: 'GET', status: 200,
      pathAndQuery: '/v1/inbox/msg_1', actor: viewerA, json: { token: 'scim_secret_99' },
    }), { seq: 3, timestampMs: 1100, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)', emittedCapabilities: [tokCap] })
    const patch = signedEntry(`r5a-patch-${preRole}`, makeStep({
      id: `r5a-patch-${preRole}`, arm: 'probe', method: 'PATCH', status: 200,
      pathAndQuery: '/v1/scim/users/u_101', actor: viewerA,
      json: { id: 'u_101', tenant: 'org_alpha', role: postRole },
    }), { seq: 4, timestampMs: 1200, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)', consumedCapabilities: [tokCap] })
    const rb = signedEntry(`r5a-rb-${preRole}`, makeStep({
      id: `r5a-rb-${preRole}`, arm: 'control', method: 'GET', status: 200,
      pathAndQuery: '/v1/me', actor: viewerA,
      json: { userId: 'u_101', tenant: 'org_alpha', role: postRole, ts: 1300 },
    }), { seq: 5, timestampMs: 1300, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)' })

    const receipt: CompositeProofReceipt = {
      chainId: `r5a-${preRole}-to-${postRole}`,
      terminalVulnClass: 'privilege_escalation',
      hops: [
        { hopId: 'who', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/me' }, exchangeIds: [who.exchangeId], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read initial role', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/inbox/msg_1' }, exchangeIds: [leak.exchangeId], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leak SCIM token', producedCapabilities: [tokCap], consumedCapabilities: [] },
        { hopId: 'esc', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/scim/users/u_101' }, exchangeIds: [patch.exchangeId], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Escalate user role', producedCapabilities: [], consumedCapabilities: [tokCap] },
      ],
      causalEdges: [
        { kind: 'value_binding', fromHopId: 'who', toHopId: 'esc', valueDigest: 'a'.repeat(64) },
        { kind: 'value_binding', fromHopId: 'leak', toHopId: 'esc', capabilityHandle: tokCap },
      ],
      terminalImpact: {
        terminalHopId: 'esc',
        terminalExchangeId: patch.exchangeId,
        summary: 'SCIM PATCH promotes viewer_a role to owner verified via /v1/me readback.',
        claimedImpact: 'SCIM PATCH promotes viewer_a role to owner verified via /v1/me readback.',
        preChainControlExchangeIds: [ctrl.exchangeId],
        postChainReadbackExchangeIds: [rb.exchangeId],
      },
      replayMode: 'fresh_clean_replay',
    }
    // Use clean 2-hop + pre-chain baseline in transcript (same zero-delta condition)
    const cleanReceipt: CompositeProofReceipt = {
      ...receipt,
      hops: receipt.hops.slice(1),
      causalEdges: [{ kind: 'value_binding', fromHopId: 'leak', toHopId: 'esc', capabilityHandle: tokCap }],
    }
    return verifyCompositeReceipt(cleanReceipt, { entries: [who, ctrl, leak, patch, rb] }, {
      signingKey: SIGNING_KEY,
      attackerPersonas: ['viewer_a'],
    })
  }

  const zeroDelta = makeChain('owner', 'owner')
  assert.equal(zeroDelta.confirmed, false, 'Zero-delta owner->owner readback MUST fail closed')
  assert.match(zeroDelta.reason, /zero_delta_post_mutation_readback/i)

  const realDelta = makeChain('viewer', 'owner')
  assert.equal(realDelta.confirmed, true, `Real viewer->owner escalation must confirm, got: ${realDelta.reason}`)
})

test('R5(b): 1-hop forged-signature webhook receipts fail closed across classes while legitimate 1-hop race confirms', () => {
  const ctrl401 = signedEntry('r5b-ctrl', makeStep({
    id: 'r5b-ctrl', arm: 'control', method: 'POST', status: 401,
    pathAndQuery: '/v1/webhooks/billing',
    requestHeaders: { 'content-type': 'application/json', 'x-signature': 'invalid' },
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })
  const baseBal = signedEntry('r5b-base', makeStep({
    id: 'r5b-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_beta', balanceCents: 100000 },
  }), { seq: 2, timestampMs: 1050, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)' })
  const forgedPost = signedEntry('r5b-post', makeStep({
    id: 'r5b-post', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/webhooks/billing',
    requestHeaders: { 'content-type': 'application/json', 'x-signature': 'guessed_sig' },
    json: { accepted: true, tenantId: 'org_beta', amountCents: 50000 },
  }), { seq: 3, timestampMs: 1100 })
  const finBal = signedEntry('r5b-fin', makeStep({
    id: 'r5b-fin', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_beta', balanceCents: 150000 },
  }), { seq: 4, timestampMs: 1200, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)' })

  for (const cls of ['forged_settlement', 'webhook_forgery', 'cross_tenant_write', 'economic_conservation', 'broken_access_control'] as const) {
    const res = verifyCompositeReceipt({
      chainId: `r5b-1hop-${cls}`,
      terminalVulnClass: cls,
      hops: [
        { hopId: 'forge', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/webhooks/billing' }, exchangeIds: ['r5b-post'], oobEventIds: [], browserTraceIds: [], claimedDelta: '1-hop forged webhook', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'forge',
        terminalExchangeId: 'r5b-post',
        summary: `1-hop ${cls} without secret provenance must be rejected.`,
        claimedImpact: `1-hop ${cls} without secret provenance must be rejected.`,
        ...(cls === 'economic_conservation' ? {
          oracleFamily: 'economic_conservation' as const,
          oracleInput: {
            baselineReadbackExchangeId: 'r5b-base',
            finalReadbackExchangeId: 'r5b-fin',
            actionExchangeIds: ['r5b-post'],
          },
        } : {}),
        preChainControlExchangeIds: ['r5b-ctrl', 'r5b-base'],
        postChainReadbackExchangeIds: ['r5b-fin'],
      },
      replayMode: 'fresh_clean_replay',
    }, { entries: [ctrl401, baseBal, forgedPost, finBal] }, {
      signingKey: SIGNING_KEY,
      attackerPersonas: ['user_a'],
    })
    assert.equal(res.confirmed, false, `1-hop ${cls} forged webhook MUST reject`)
    assert.match(res.reason, /forged_signature_unproven_secret_provenance/i)
  }

  // Positive control: legitimate 1-hop economic_conservation race (no signature header, no 401) STILL confirms
  const raceBase = signedEntry('r5b-r-base', makeStep({
    id: 'r5b-r-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/wallet', json: { accountId: 'acc_1', balance: 100 },
  }), { seq: 1, timestampMs: 1000 })
  const raceA = signedEntry('r5b-r-a', makeStep({
    id: 'r5b-r-a', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/transfers', requestJson: { fromAccount: 'acc_1', toAccount: 'acc_2', amount: 100 },
    json: { ok: true },
  }), { seq: 2, timestampMs: 1100, raceBatchId: 'batch-1' })
  const raceB = signedEntry('r5b-r-b', makeStep({
    id: 'r5b-r-b', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/transfers', requestJson: { fromAccount: 'acc_1', toAccount: 'acc_2', amount: 100 },
    json: { ok: true },
  }), { seq: 3, timestampMs: 1101, raceBatchId: 'batch-1' })
  const raceFin = signedEntry('r5b-r-fin', makeStep({
    id: 'r5b-r-fin', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/wallet', json: { accountId: 'acc_1', balance: 200 },
  }), { seq: 4, timestampMs: 1200 })

  const raceRes = verifyCompositeReceipt({
    chainId: 'r5b-legit-1hop-race',
    terminalVulnClass: 'economic_conservation',
    hops: [
      { hopId: 'race', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/transfers' }, exchangeIds: ['r5b-r-a', 'r5b-r-b'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Concurrent internal transfer race mints value', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'race',
      terminalExchangeId: 'r5b-r-b',
      summary: 'Concurrent 1-hop race mints balance without authorized external deposits.',
      claimedImpact: 'Concurrent 1-hop race mints balance without authorized external deposits.',
      oracleFamily: 'economic_conservation',
      oracleInput: {
        baselineReadbackExchangeId: 'r5b-r-base',
        finalReadbackExchangeId: 'r5b-r-fin',
        actionExchangeIds: ['r5b-r-a', 'r5b-r-b'],
      },
      preChainControlExchangeIds: ['r5b-r-base'],
      postChainReadbackExchangeIds: ['r5b-r-fin'],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [raceBase, raceA, raceB, raceFin] }, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['user_a'],
  })
  assert.equal(raceRes.confirmed, true, `Legitimate 1-hop economic_conservation race must still confirm, got: ${raceRes.reason}`)
})

// ============================================================================
// R6: Causal-prefix partial-chain supersession (bidirectional + class safety)
// ============================================================================

test('R6: causal-prefix supersession marks earlier AND later partial-chain sub-findings superseded without touching unrelated classes/resources', () => {
  assert.equal(isAuthzPrivescClassSupersessionCompatible({ cwe: 'CWE-639', vulnClass: 'broken_access_control' }, { vulnClasses: ['privilege_escalation'] }), true)
  assert.equal(isFindingClassSupersessionCompatible({ cwe: 'CWE-639', vulnClass: 'broken_access_control' }, { terminalVulnClass: 'privilege_escalation' }), true)
  assert.equal(isFindingClassSupersessionCompatible({ cwe: 'CWE-89', vulnClass: 'sqli' }, { terminalVulnClass: 'privilege_escalation' }), false)
  assert.equal(isFindingClassSupersessionCompatible({ cwe: 'CWE-79', vulnClass: 'xss' }, { terminalVulnClass: 'privilege_escalation' }), false)

  const matchExact = (a: UpstreamSupersessionEndpointLike, b: UpstreamSupersessionEndpointLike) =>
    a.origin === b.origin && a.method === b.method && a.normalizedEndpoint === b.normalizedEndpoint

  const winnerApprove = {
    chainId: 'winner-approve',
    hops: [
      { hopId: 'resolve', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' } },
      { hopId: 'approve', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/pay_1/approve' } },
    ],
    terminalImpact: { terminalHopId: 'approve' },
  }
  const partialRebind = {
    chainId: 'partial-rebind',
    hops: [
      { hopId: 'leak', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/directory/orgs/alpha' } },
      { hopId: 'resolve', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' } },
      { hopId: 'list', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/payouts' } },
      { hopId: 'rebind', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/payouts/pay_1/rebind' } },
    ],
    terminalImpact: { terminalHopId: 'rebind' },
  }
  const partialRead = {
    chainId: 'partial-read',
    hops: [
      { hopId: 'leak', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/directory/orgs/alpha' } },
      { hopId: 'resolve', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' } },
      { hopId: 'read', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/payouts/pay_2' } },
    ],
    terminalImpact: { terminalHopId: 'read' },
  }
  const unrelatedWebhook = {
    chainId: 'unrelated-webhook',
    hops: [
      { hopId: 'resolve', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' } },
      { hopId: 'wh', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/webhooks/logs' } },
    ],
    terminalImpact: { terminalHopId: 'wh' },
  }

  const winnerUp: UpstreamSupersessionEndpointLike[] = [
    { origin: ORIGIN, method: 'POST', normalizedEndpoint: '/invites/resolve' },
  ]
  const partialReadUp: UpstreamSupersessionEndpointLike[] = [
    { origin: ORIGIN, method: 'GET', normalizedEndpoint: '/v1/directory/orgs/:id' },
    { origin: ORIGIN, method: 'POST', normalizedEndpoint: '/invites/resolve' },
  ]

  // Forward: partialRebind persisted FIRST, winnerApprove arrives SECOND -> incoming_supersedes_earlier
  const fwd = resolveCompositeSupersessionMatch({
    incomingReceipt: winnerApprove,
    incomingOrigin: ORIGIN,
    incomingTerminalEndpoint: 'POST /v1/payouts/pay_1/approve',
    incomingUpstreamNonGeneric: winnerUp,
    earlierCompReceipt: partialRebind,
    earlierOrigin: ORIGIN,
    earlierEndpoints: [],
    endpointsMatchExact: matchExact,
  })
  assert.equal(fwd.direction, 'incoming_supersedes_earlier')
  assert.ok(fwd.matched.length >= 1)

  // Reverse: winnerApprove persisted FIRST, partialRead arrives SECOND -> earlier_supersedes_incoming
  const rev = resolveCompositeSupersessionMatch({
    incomingReceipt: partialRead,
    incomingOrigin: ORIGIN,
    incomingTerminalEndpoint: 'GET /v1/payouts/pay_2',
    incomingUpstreamNonGeneric: partialReadUp,
    earlierCompReceipt: winnerApprove,
    earlierOrigin: ORIGIN,
    earlierEndpoints: [],
    endpointsMatchExact: matchExact,
  })
  assert.equal(rev.direction, 'earlier_supersedes_incoming')
  assert.ok(rev.matched.length >= 1)

  // Negative 1: unrelated resource family (/v1/webhooks/logs vs /v1/payouts/:id/approve) NEVER supersedes
  const diffRes = matchCausalPrefixPartialChainSupersession({
    winnerReceipt: winnerApprove,
    winnerOrigin: ORIGIN,
    winnerUpstreamNonGeneric: winnerUp,
    partialReceipt: unrelatedWebhook,
    partialOrigin: ORIGIN,
    endpointsMatchExact: matchExact,
  })
  assert.equal(diffRes.length, 0)

  // Negative 2: different origin NEVER supersedes
  const diffOrigin = matchCausalPrefixPartialChainSupersession({
    winnerReceipt: winnerApprove,
    winnerOrigin: ORIGIN,
    winnerUpstreamNonGeneric: winnerUp,
    partialReceipt: partialRead,
    partialOrigin: 'https://other.example.test',
    endpointsMatchExact: matchExact,
  })
  assert.equal(diffOrigin.length, 0)
})

// ============================================================================
// R8: dual_tenant_abac actor_not_dual_tenant + opaque plain-text fallback
// ============================================================================

test('R8: dual_org_cache_bleed fails fast with actor_not_dual_tenant for single-tenant actors and resolves opaque plain-text for genuine dual-tenant actors', () => {
  const singleRes = evaluateDualTenantAbac({
    mode: 'dual_org_cache_bleed',
    actor: { actorId: 'user_a', rolesByTenant: { org_alpha: 'member' } },
    primeTenantId: 'org_alpha',
    targetTenantId: '',
    baselineDeniedControl: { id: 'c1', hostSignature: 'hmac-sha256:c1:0123456789', timestampMs: 1000, status: 403 },
    primeAction: { id: 'p1', hostSignature: 'hmac-sha256:p1:0123456789', timestampMs: 1100, status: 200 },
    bledAccess: { id: 'b1', hostSignature: 'hmac-sha256:b1:0123456789', timestampMs: 1200, status: 200, body: 'col1,col2\n1,2' },
  })
  assert.equal(singleRes.satisfied, false)
  assert.match(singleRes.reason, /^actor_not_dual_tenant:/)

  // Genuine dual-tenant actor with opaque plain-text CSV bledAccess mentioning org_beta resolves targetTenantId via body token
  const dualActor = { handle: 'dual_user', role: 'admin' as const, tenant: 'org_alpha', auth: 'bearer' as const, sameSite: null }
  const dualLabel = 'admin (org_alpha), viewer (org_beta)'
  const ctrl = signedEntry('r8-ctrl', makeStep({
    id: 'r8-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/v1/exports/report.csv', actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'dual_user', actorRoleLabel: dualLabel })
  const prime = signedEntry('r8-prime', makeStep({
    id: 'r8-prime', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/cache/prime', actor: dualActor, json: { primed: true, tenantId: 'org_alpha' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'dual_user', actorRoleLabel: dualLabel })
  const bledCsvWithMarker = signedEntry('r8-bled-csv-marker', makeStep({
    id: 'r8-bled-csv-marker', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/exports/report.csv', actor: dualActor,
    body: 'tenant,account,amount\norg_beta,acc_99,500000\n',
  }), { seq: 3, timestampMs: 1200, actorPersona: 'dual_user', actorRoleLabel: dualLabel })
  const idxMarker: HydratableTranscriptIndex = {
    entriesById: new Map([[ctrl.exchangeId, ctrl], [prime.exchangeId, prime], [bledCsvWithMarker.exchangeId, bledCsvWithMarker]]),
  }
  const hyd = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'dual_org_cache_bleed',
    baselineDeniedControl: 'r8-ctrl',
    primeAction: 'r8-prime',
    bledAccess: 'r8-bled-csv-marker',
  }, idxMarker, 'sig-fallback')
  assert.equal(hyd.primeTenantId, 'org_alpha')
  assert.equal(hyd.targetTenantId, 'org_beta')

  // Item 4: opaque plain-text CSV with ZERO tenant marker in body or upstream MUST NOT fabricate targetTenantId and MUST stay confirmed: false end-to-end
  const bledCsvNoMarker = signedEntry('r8-bled-csv-empty', makeStep({
    id: 'r8-bled-csv-empty', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/v1/exports/report.csv', actor: dualActor,
    body: 'account,amount\nacc_99,500000\n',
  }), { seq: 3, timestampMs: 1200, actorPersona: 'dual_user', actorRoleLabel: dualLabel })
  const hydNoMarker = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'dual_org_cache_bleed',
    baselineDeniedControl: 'r8-ctrl',
    primeAction: 'r8-prime',
    bledAccess: 'r8-bled-csv-empty',
  }, { entriesById: new Map([[ctrl.exchangeId, ctrl], [prime.exchangeId, prime], [bledCsvNoMarker.exchangeId, bledCsvNoMarker]]) }, 'sig-fallback')
  assert.equal(hydNoMarker.targetTenantId, undefined)
  const opaqueNoMarkerEval = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrl, prime, bledCsvNoMarker] }),
    {
      kind: 'v8_family', family: 'dual_tenant_abac',
      rawInput: { mode: 'dual_org_cache_bleed', baselineDeniedControl: 'r8-ctrl', primeAction: 'r8-prime', bledAccess: 'r8-bled-csv-empty' },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(opaqueNoMarkerEval.confirmed, false)

  // Bypass guard preserved: structured JSON without tenant markers still does NOT trigger opaque plain-text fallback
  const ctrlJson = signedEntry('r8-ctrl-json', makeStep({
    id: 'r8-ctrl-json', arm: 'control', method: 'POST', status: 403,
    pathAndQuery: '/v1/exports/report', actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'dual_user', actorRoleLabel: dualLabel })
  const bledJson = signedEntry('r8-bled-json', makeStep({
    id: 'r8-bled-json', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/v1/exports/report', actor: dualActor,
    requestJson: { tenantId: 'org_beta' },
    json: { rows: [{ id: 'row_1', total: 500 }] },
  }), { seq: 4, timestampMs: 1300, actorPersona: 'dual_user', actorRoleLabel: dualLabel })
  const hydJson = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'dual_org_cache_bleed',
    targetTenantId: 'org_beta',
    baselineDeniedControl: 'r8-ctrl-json',
    primeAction: 'r8-prime',
    bledAccess: 'r8-bled-json',
  }, { entriesById: new Map([[ctrlJson.exchangeId, ctrlJson], [prime.exchangeId, prime], [bledJson.exchangeId, bledJson]]) }, 'sig-fallback')
  assert.equal(hydJson.targetTenantId, undefined)
  const jsonEval = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrlJson, prime, bledJson] }),
    {
      kind: 'v8_family', family: 'dual_tenant_abac',
      rawInput: { mode: 'dual_org_cache_bleed', targetTenantId: 'org_beta', baselineDeniedControl: 'r8-ctrl-json', primeAction: 'r8-prime', bledAccess: 'r8-bled-json' },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(jsonEval.confirmed, false)
  assert.equal(jsonEval.reason, 'missing_tenant_scope')
})

// ============================================================================
// R3-05 Independent Review Must-Fix Bypass Guards (MF1, MF2, MF3)
// ============================================================================

test('R3-05 MF1: 1-hop forged-webhook guard rejects 403/404 controls, alternate sig headers, query/body sigs, and webhook_forgery/forged_settlement classes', () => {
  const baseBal = signedEntry('mf1-base', makeStep({
    id: 'mf1-base', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_beta', balanceCents: 100000 },
  }), { seq: 1, timestampMs: 900, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)' })
  const finBal = signedEntry('mf1-fin', makeStep({
    id: 'mf1-fin', arm: 'control', method: 'GET', status: 200,
    pathAndQuery: '/v1/balance', json: { tenant: 'org_beta', balanceCents: 150000 },
  }), { seq: 4, timestampMs: 1300, actorPersona: 'user_b', actorRoleLabel: 'member (org_beta)' })

  const variants: Array<{
    name: string
    cls: string
    ctrlStatus: number
    probePath: string
    probeHeaders?: Record<string, string>
    probeReqJson?: Record<string, unknown>
    econ?: boolean
  }> = [
    { name: '403 control + x-signature', cls: 'cross_tenant_write', ctrlStatus: 403, probePath: '/v1/webhooks/billing', probeHeaders: { 'x-signature': 'abc' } },
    { name: '404 control + x-signature', cls: 'cross_tenant_write', ctrlStatus: 404, probePath: '/v1/webhooks/billing', probeHeaders: { 'x-signature': 'abc' } },
    { name: '403 control + economic_conservation', cls: 'economic_conservation', ctrlStatus: 403, probePath: '/v1/webhooks/billing', probeHeaders: { 'x-signature': 'abc' }, econ: true },
    { name: 'webhook-signature header', cls: 'cross_tenant_write', ctrlStatus: 401, probePath: '/v1/webhooks/billing', probeHeaders: { 'webhook-signature': 'v1=abc' } },
    { name: 'X-Shopify-Hmac-Sha256 header', cls: 'cross_tenant_write', ctrlStatus: 401, probePath: '/v1/webhooks/billing', probeHeaders: { 'X-Shopify-Hmac-Sha256': 'abc' } },
    { name: 'query-string signature', cls: 'cross_tenant_write', ctrlStatus: 401, probePath: '/v1/webhooks/billing?sig=abc123', probeHeaders: {} },
    { name: 'body JSON signature field', cls: 'cross_tenant_write', ctrlStatus: 401, probePath: '/v1/webhooks/billing', probeHeaders: {}, probeReqJson: { signature: 'abc123', amountCents: 50000 } },
    { name: 'webhook_forgery class without sig header', cls: 'webhook_forgery', ctrlStatus: 401, probePath: '/v1/webhooks/billing', probeHeaders: {} },
    { name: 'forged_settlement class with headers object', cls: 'forged_settlement', ctrlStatus: 403, probePath: '/v1/webhooks/billing', probeHeaders: { 'content-type': 'application/json' } },
  ]

  for (const v of variants) {
    const ctrl = signedEntry(`mf1-c-${v.name}`, makeStep({
      id: `mf1-c-${v.name}`, arm: 'control', method: 'POST', status: v.ctrlStatus,
      pathAndQuery: '/v1/webhooks/billing',
      ...(v.probeHeaders ? { requestHeaders: {} } : {}),
      json: { error: 'denied' },
    }), { seq: 2, timestampMs: 1000 })
    const probe = signedEntry(`mf1-p-${v.name}`, makeStep({
      id: `mf1-p-${v.name}`, arm: 'probe', method: 'POST', status: 200,
      pathAndQuery: v.probePath,
      ...(v.probeHeaders !== undefined ? { requestHeaders: v.probeHeaders } : {}),
      ...(v.probeReqJson !== undefined ? { requestJson: v.probeReqJson } : {}),
      json: { accepted: true, tenantId: 'org_beta', amountCents: 50000 },
    }), { seq: 3, timestampMs: 1100 })
    const res = verifyCompositeReceipt({
      chainId: `mf1-${v.name.replace(/[^a-z0-9]+/gi, '-')}`,
      terminalVulnClass: v.cls,
      hops: [{ hopId: 'forge', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: v.probePath }, exchangeIds: [probe.exchangeId], oobEventIds: [], browserTraceIds: [], claimedDelta: '1-hop forged webhook bypass attempt', producedCapabilities: [], consumedCapabilities: [] }],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'forge', terminalExchangeId: probe.exchangeId,
        summary: `Bypass attempt (${v.name}) must fail closed without secret provenance.`,
        claimedImpact: `Bypass attempt (${v.name}) must fail closed without secret provenance.`,
        ...(v.econ ? { oracleFamily: 'economic_conservation' as const, oracleInput: { baselineReadbackExchangeId: 'mf1-base', finalReadbackExchangeId: 'mf1-fin', actionExchangeIds: [probe.exchangeId] } } : {}),
        preChainControlExchangeIds: [ctrl.exchangeId, 'mf1-base'],
        postChainReadbackExchangeIds: ['mf1-fin'],
      },
      replayMode: 'fresh_clean_replay',
    }, { entries: [baseBal, ctrl, probe, finBal] }, { signingKey: SIGNING_KEY, attackerPersonas: ['user_a'] })
    assert.equal(res.confirmed, false, `MF1 variant "${v.name}" MUST fail closed, got confirmed=true`)
    assert.match(res.reason, /forged_signature_unproven_secret_provenance/i, `MF1 variant "${v.name}" unexpected reason: ${res.reason}`)
  }
})

test('R3-05 MF2: zero-delta readback strips rotating volatile keys (lastSeen/exp/iat/session_id/lastLoginAt), deep nested keys, and sorted query params while keeping real deltas', () => {
  const tokCap = 'cap:mf2:scim_tok'
  const viewerA = { handle: 'viewer_a', role: 'viewer' as const, tenant: 'org_alpha', auth: 'bearer' as const, sameSite: null }
  const deepWrap = (leaf: Record<string, unknown>, depth = 8): Record<string, unknown> => {
    let cur: Record<string, unknown> = leaf
    for (let i = 0; i < depth; i++) cur = { nested: cur }
    return cur
  }

  const runVariant = (preQuery: string, postQuery: string, preJson: Record<string, unknown>, postJson: Record<string, unknown>) => {
    const pre = signedEntry('mf2-pre', makeStep({
      id: 'mf2-pre', arm: 'probe', method: 'GET', status: 200,
      pathAndQuery: `/v1/me${preQuery}`, actor: viewerA, json: preJson,
    }), { seq: 1, timestampMs: 1000, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)' })
    const ctrl = signedEntry('mf2-ctrl', makeStep({
      id: 'mf2-ctrl', arm: 'control', method: 'PATCH', status: 401,
      pathAndQuery: '/v1/scim/users/u_202', actor: viewerA, json: { error: 'unauthorized' },
    }), { seq: 2, timestampMs: 1050, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)' })
    const leak = signedEntry('mf2-leak', makeStep({
      id: 'mf2-leak', arm: 'probe', method: 'GET', status: 200,
      pathAndQuery: '/v1/inbox/m2', actor: viewerA, json: { token: 'scim_tok_202' },
    }), { seq: 3, timestampMs: 1100, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)', emittedCapabilities: [tokCap] })
    const patch = signedEntry('mf2-patch', makeStep({
      id: 'mf2-patch', arm: 'probe', method: 'PATCH', status: 200,
      pathAndQuery: '/v1/scim/users/u_202', actor: viewerA, json: { id: 'u_202', tenant: 'org_alpha', role: 'owner' },
    }), { seq: 4, timestampMs: 1200, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)', consumedCapabilities: [tokCap] })
    const rb = signedEntry('mf2-rb', makeStep({
      id: 'mf2-rb', arm: 'control', method: 'GET', status: 200,
      pathAndQuery: `/v1/me${postQuery}`, actor: viewerA, json: postJson,
    }), { seq: 5, timestampMs: 1300, actorPersona: 'viewer_a', actorRoleLabel: 'viewer (org_alpha)' })

    return verifyCompositeReceipt({
      chainId: 'mf2-zero-delta-check',
      terminalVulnClass: 'privilege_escalation',
      hops: [
        { hopId: 'leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/inbox/m2' }, exchangeIds: ['mf2-leak'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leak SCIM token', producedCapabilities: [tokCap], consumedCapabilities: [] },
        { hopId: 'esc', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/scim/users/u_202' }, exchangeIds: ['mf2-patch'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Escalate role', producedCapabilities: [], consumedCapabilities: [tokCap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'leak', toHopId: 'esc', capabilityHandle: tokCap }],
      terminalImpact: {
        terminalHopId: 'esc', terminalExchangeId: 'mf2-patch',
        summary: 'SCIM PATCH promotes viewer_a to owner verified via /v1/me readback.',
        claimedImpact: 'SCIM PATCH promotes viewer_a to owner verified via /v1/me readback.',
        preChainControlExchangeIds: ['mf2-ctrl'], postChainReadbackExchangeIds: ['mf2-rb'],
      },
      replayMode: 'fresh_clean_replay',
    }, { entries: [pre, ctrl, leak, patch, rb] }, { signingKey: SIGNING_KEY, attackerPersonas: ['viewer_a'] })
  }

  // Rotating volatile fields + deep-nested volatile key (>6 depth) + reordered query params -> STILL zero-delta -> REJECT!
  const rotatingRes = runVariant(
    '?a=1&b=2',
    '?b=2&a=1',
    { userId: 'u_202', tenant: 'org_alpha', role: 'owner', lastSeen: 1000, exp: 9000, iat: 8000, session_id: 'sid_1', lastLoginAt: '2026-01-01T00:00:00Z', meta: deepWrap({ requestId: 'req_1', lastSeen: 1000 }) },
    { userId: 'u_202', tenant: 'org_alpha', role: 'owner', lastSeen: 1300, exp: 9999, iat: 8300, session_id: 'sid_2', lastLoginAt: '2026-01-01T00:05:00Z', meta: deepWrap({ requestId: 'req_2', lastSeen: 1300 }) },
  )
  assert.equal(rotatingRes.confirmed, false, 'Rotating volatile keys + deep nesting + reordered query MUST still reject as zero-delta')
  assert.match(rotatingRes.reason, /zero_delta_post_mutation_readback/i)

  // Real state delta (role viewer -> owner) alongside rotating volatile keys -> CONFIRMS!
  const realRes = runVariant(
    '?a=1&b=2',
    '?b=2&a=1',
    { userId: 'u_202', tenant: 'org_alpha', role: 'viewer', lastSeen: 1000, session_id: 'sid_1' },
    { userId: 'u_202', tenant: 'org_alpha', role: 'owner', lastSeen: 1300, session_id: 'sid_2' },
  )
  assert.equal(realRes.confirmed, true, `Real viewer->owner delta with rotating volatile keys must confirm, got: ${realRes.reason}`)
})

test('R3-05 MF3: extractLedgerBalanceMap negates spends/purchases, abstains on unrecognized directions, non-final statuses, mixed currencies, and handles Object.prototype group keys safely', () => {
  // Spend/purchase directions negate (never mint positive value)
  assert.deepEqual({ ...extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', type: 'purchase', amountCents: 2500 }] }) }, { org_a: -2500 })
  assert.deepEqual({ ...extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', type: 'fee', amountCents: 500 }, { tenantId: 'org_a', type: 'deposit', amountCents: 2000 }] }) }, { org_a: 1500 })

  // Unrecognized direction abstains
  assert.equal(extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', type: 'loyalty_points', amountCents: 2500 }] }), undefined)

  // Non-final status abstains
  for (const st of ['failed', 'pending', 'reversed', 'voided', 'declined', 'cancelled']) {
    assert.equal(extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', type: 'credit', status: st, amountCents: 2500 }] }), undefined, `status=${st} must abstain`)
  }

  // Mixed currencies abstain; single currency succeeds
  assert.equal(extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', currency: 'USD', amountCents: 100 }, { tenantId: 'org_a', currency: 'JPY', amountCents: 2500 }] }), undefined)
  assert.deepEqual({ ...extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', currency: 'USD', amountCents: 100 }, { tenantId: 'org_a', currency: 'usd', amountCents: 200 }] }) }, { org_a: 300 })

  // Non-numeric / NaN amount abstains
  assert.equal(extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', amountCents: '2500' }] }), undefined)
  assert.equal(extractLedgerBalanceMap({ entries: [{ tenantId: 'org_a', amountCents: Number.NaN }] }), undefined)

  // Prototype-chain group key (toString / valueOf) never produces string concatenation
  const protoMap = extractLedgerBalanceMap({ entries: [{ tenantId: 'toString', amountCents: 50 }, { tenantId: 'valueOf', amountCents: 75 }] })
  assert.ok(protoMap !== undefined)
  assert.equal(protoMap!['toString'], 50)
  assert.equal(protoMap!['valueOf'], 75)
  assert.equal(typeof protoMap!['toString'], 'number')
})

// ============================================================================
// R3-05 reviewer regression: zero-delta guard must run BEFORE the stub filter
// ============================================================================
test('R5(a) reviewer: stub-shaped zero-delta readback (exp/iat/session_id) still fails closed', () => {
  const viewer = { handle: 'v', role: 'viewer' as const, tenant: 'org_alpha', auth: 'bearer' as const, sameSite: null }
  const mk = (id: string, ts: number, t: number) => signedEntry(id, makeStep({
    id, arm: 'control', method: 'GET', status: 200, pathAndQuery: '/v1/me', actor: viewer,
    json: { userId: 'u_1', tenant: 'org_alpha', role: 'owner', exp: t + 3600, iat: t, session_id: `s${t}` },
  }), { seq: ts, timestampMs: ts, actorPersona: 'v', actorRoleLabel: 'viewer (org_alpha)' })
  const pre = mk('pre', 1000, 1000), term = mk('term', 1200, 1200), rb = mk('rb', 1300, 1300)
  const byId = new Map([[pre.exchangeId, pre], [term.exchangeId, term], [rb.exchangeId, rb]])
  const res = selectVerifiedPostMutationReadback(['rb'], term, byId, false, () => false, () => true, () => true)
  assert.equal(res.postMutRb, undefined)
  assert.equal(res.rejectedZeroDelta, true)
})
