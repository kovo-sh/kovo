/**
 * v8 M2 Kernel Soundness & Precision Regression Suite.
 *
 * Covers:
 *  1. `bf7eabc` `dual_member` regression fix: `isPrivilegedActorOrRole` allows multi-tenant personas
 *     holding a low-privilege role in at least one distinct tenant while forbidding `owner`,
 *     single-tenant `admin`, dual-admin, and `PRIV_HANDLE_RE` handles.
 *  2. `POST /login` -> `cap:*` tenant provenance propagation: `probeTenantOf` infers originating
 *     login tenant from actor/tenant or JSON tenant/email claims so mixed-tenant persona shortcuts
 *     fail closed at `attacker_provenance`, while legitimate single-tenant & DAG-minted creds pass.
 *  3. `selectStateTransitionPair` derived-cap & setup-login-cap lineage: omitting `as` on `toHop`
 *     with a `cap:hop_...` token traces actor lineage cleanly without false `actor_discontinuity`,
 *     while genuinely distinct personas or unlinked anon exchanges still fail closed.
 *  4. Composite terminal stub gate & expanded `isJobOrHandleStub`: rejects unexercised token-mint,
 *     session-mint, invite-list, webhook-create, delivery-log, and partial 2-3 hop chains without
 *     strict terminal impact, while confirming exercised sessions and cross-tenant terminal impact.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { isJobOrHandleStub } from '../src/server/v8-oracle-families.ts'
import {
  buildCapOriginIndex,
  hydrateV8OracleInput,
  isPrivilegedActorOrRole,
  selectStateTransitionPair,
  type HydratableTranscriptIndex,
} from '../src/server/v8-oracle-hydrate.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'm2-soundness-regression-signing-key-90123456'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
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
    ...(partial.route !== undefined ? { route: partial.route } : partial.pathAndQuery ? { route: partial.pathAndQuery.split('?')[0]! } : {}),
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
    step,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

// ============================================================================
// 1. Multi-tenant `dual_member` regression fix (isPrivilegedActorOrRole)
// ============================================================================

test('Req 1: isPrivilegedActorOrRole allows multi-tenant personas with a low-priv tenant role and forbids owner / single-tenant admin / privileged handles', () => {
  // Multi-tenant personas with admin in org_a and viewer/member/user in org_b -> ALLOWED (false)
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'admin [memberships=admin:org_a,viewer:org_b] (org_a)'), false)
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'admin@org_a, viewer@org_b'), false)
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'admin@org_a, user@org_b'), false)
  assert.equal(isPrivilegedActorOrRole('dual_member', null, 'admin [id=p1; memberships=admin:org_a,member:org_b] (org_a)'), false)
  assert.equal(isPrivilegedActorOrRole('member_a', 'member', 'member (org_a)'), false)

  // Strictly FORBIDDEN (true): owner (even multi-tenant), single-tenant admin, dual-admin, same-tenant admin+member, PRIV_HANDLE_RE
  assert.equal(isPrivilegedActorOrRole('dual_member', 'owner', 'owner [memberships=owner:org_a,viewer:org_b] (org_a)'), true)
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'owner@org_a, viewer@org_b'), true)
  assert.equal(isPrivilegedActorOrRole('svc_user', 'admin', 'admin (org_a)'), true)
  assert.equal(isPrivilegedActorOrRole('svc_user', 'admin', null), true)
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'admin@org_a, admin@org_b'), true)
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'admin@org_a, member@org_a'), true)
  assert.equal(isPrivilegedActorOrRole('admin_beta', 'admin', 'admin@org_a, viewer@org_b'), true)
  assert.equal(isPrivilegedActorOrRole('owner_a', 'member', 'member (org_a)'), true)
  assert.equal(isPrivilegedActorOrRole('root_svc', 'viewer', 'viewer (org_a)'), true)
})

test('Req 1: verifyCompositeReceipt and cross_surface_pivot confirm multi-tenant dual_member when attackerPersonas is omitted', () => {
  const dualLabel = 'admin [memberships=admin:org_a,viewer:org_b] (org_a)'
  const cap = 'cap:hop_1:export_sig'
  const ctrl = signedEntry('ex-dm-ctrl', makeStep({
    id: 'ex-dm-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/files/export/org_c/ledger.csv',
    actor: { handle: 'dual_member', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { timestampMs: 900, actorPersona: 'dual_member', actorRoleLabel: dualLabel })
  const h1 = signedEntry('ex-dm-h1', makeStep({
    id: 'ex-dm-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/exports/sign',
    actor: { handle: 'dual_member', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { signedUrl: '/files/export/org_b/ledger.csv?sig=s1' },
  }), { timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: dualLabel, emittedCapabilities: [cap] })
  const h2 = signedEntry('ex-dm-h2', makeStep({
    id: 'ex-dm-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/files/export/org_c/ledger.csv',
    actor: { handle: 'dual_member', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_c', rows: [{ account: 'acct-c', balanceCents: 88000 }] },
  }), { timestampMs: 1200, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })

  const receipt: CompositeProofReceipt = {
    chainId: 'm2-dual-member-omitted-personas',
    terminalVulnClass: 'cross_surface_pivot',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/exports/sign' }, exchangeIds: ['ex-dm-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Minted signed export URL', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'storage', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/files/export/org_c/ledger.csv' }, exchangeIds: ['ex-dm-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Downloaded sibling tenant ledger', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Dual-member persona exported sibling tenant treasury records.',
      summary: 'Dual-member persona exported sibling tenant treasury records.',
      terminalExchangeId: 'ex-dm-h2',
      preChainControlExchangeIds: ['ex-dm-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  // attackerPersonas intentionally omitted -> must CONFIRM for multi-tenant dual_member!
  const res = verifyCompositeReceipt(receipt, { entries: [ctrl, h1, h2] }, { signingKey: SIGNING_KEY })
  assert.equal(res.confirmed, true, res.reason)

  // Same receipt with explicit cross_surface_pivot hydration must set isPrivilegedPreSeeded=false
  const idx: HydratableTranscriptIndex = { entriesById: new Map([[ctrl.exchangeId, ctrl], [h1.exchangeId, h1], [h2.exchangeId, h2]]) }
  const hydrated = hydrateV8OracleInput('cross_surface_pivot', {
    preChainControlDenied: 'ex-dm-ctrl',
    hops: [{ surface: 'http', role: 'trigger_write', record: 'ex-dm-h1' }, { surface: 'storage', role: 'terminal_impact', record: 'ex-dm-h2', bindingKind: 'value_binding' }],
    terminalImpact: { kind: 'privileged_read' },
  }, idx, 'sig')
  assert.equal((hydrated.attackerOriginPersona as { isPrivilegedPreSeeded: boolean }).isPrivilegedPreSeeded, false)
})

// ============================================================================
// 2. POST /login -> cap:* tenant provenance bypass CLOSED
// ============================================================================

test('Req 2: POST /login -> cap:* propagates originating login tenant and blocks mixed-tenant persona shortcuts', () => {
  const dualLabel = 'admin [memberships=admin:org_a,viewer:org_b] (org_a)'
  const loginBCap = 'cap:hop_setup:member_b_session'
  const loginBEmailCap = 'cap:hop_setup:member_b_email_only'
  const hopCap = 'cap:hop_1:shared_handle'

  const loginB = signedEntry('ex-login-b', makeStep({
    id: 'ex-login-b', arm: 'setup', method: 'POST', status: 200, pathAndQuery: '/login',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    requestJson: { email: 'member_b@org-b.test', password: 'pw', tenant: 'org_b' },
    json: { token: 'sess-b', tenant: 'org_b', role: 'member' },
  }), { timestampMs: 800, actorPersona: null, actorRoleLabel: null, emittedCapabilities: [loginBCap] })

  const loginBEmailOnly = signedEntry('ex-login-b-email', makeStep({
    id: 'ex-login-b-email', arm: 'setup', method: 'POST', status: 200, pathAndQuery: '/api/v1/auth/login',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    requestJson: { email: 'member_b@org-b.test', password: 'pw' },
    json: { token: 'sess-b-2' },
  }), { timestampMs: 810, actorPersona: null, actorRoleLabel: null, emittedCapabilities: [loginBEmailCap] })

  const ctrl = signedEntry('ex-ctrl-mix', makeStep({
    id: 'ex-ctrl-mix', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/records/r-b',
    actor: { handle: 'dual_member', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { timestampMs: 900, actorPersona: 'dual_member', actorRoleLabel: dualLabel })

  const hop1Dual = signedEntry('ex-h1-dual', makeStep({
    id: 'ex-h1-dual', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/bootstrap',
    actor: { handle: 'dual_member', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { handle: 'h1' },
  }), { timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: dualLabel, emittedCapabilities: [hopCap] })

  const hop2CapB = signedEntry('ex-h2-cap-b', makeStep({
    id: 'ex-h2-cap-b', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/records/r-b',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { tenantId: 'org_b', records: [{ id: 'r-b', amountCents: 9000 }] },
  }), { timestampMs: 1200, actorPersona: null, actorRoleLabel: null, consumedCapabilities: [hopCap, loginBCap] })

  const hop2EmailCapB = signedEntry('ex-h2-email-b', makeStep({
    id: 'ex-h2-email-b', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/records/r-b',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { tenantId: 'org_b', records: [{ id: 'r-b', amountCents: 9000 }] },
  }), { timestampMs: 1200, actorPersona: null, actorRoleLabel: null, consumedCapabilities: [hopCap, loginBEmailCap] })

  const makeMixReceipt = (h2Id: string): CompositeProofReceipt => ({
    chainId: `m2-mix-${h2Id}`,
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/bootstrap' }, exchangeIds: ['ex-h1-dual'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained bootstrap handle', producedCapabilities: [hopCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/records/r-b' }, exchangeIds: [h2Id], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read org_b record with member_b login cap', producedCapabilities: [], consumedCapabilities: [hopCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: hopCap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      claimedImpact: 'Attempted cross-tenant shortcut by mixing dual_member with member_b login cap.',
      summary: 'Attempted cross-tenant shortcut by mixing dual_member with member_b login cap.',
      terminalExchangeId: h2Id,
      preChainControlExchangeIds: ['ex-ctrl-mix'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })

  // Case A: login cap carries JSON tenant: 'org_b' -> MUST reject at attacker_provenance
  const rTenant = verifyCompositeReceipt(makeMixReceipt('ex-h2-cap-b'), { entries: [loginB, ctrl, hop1Dual, hop2CapB] }, { signingKey: SIGNING_KEY })
  assert.equal(rTenant.confirmed, false, 'mixing dual_member (org_a) with member_b login cap (org_b) must fail')
  assert.equal(rTenant.failedStage, 'attacker_provenance')
  assert.match(rTenant.reason, /Cross-tenant probe-arm persona mismatch/i)

  // Case B: login cap carries ONLY email claim -> MUST reject at attacker_provenance
  const rEmail = verifyCompositeReceipt(makeMixReceipt('ex-h2-email-b'), { entries: [loginBEmailOnly, ctrl, hop1Dual, hop2EmailCapB] }, { signingKey: SIGNING_KEY })
  assert.equal(rEmail.confirmed, false, 'mixing dual_member (org_a) with member_b email-only login cap must fail')
  assert.equal(rEmail.failedStage, 'attacker_provenance')
  assert.match(rEmail.reason, /Cross-tenant probe-arm persona mismatch/i)

  // Case C: legitimate DAG-minted token (NOT from POST /login, e.g., POST /invites/resolve) MUST NOT trip probeTenants!
  const inviteCap = 'cap:hop_1:escalated_session'
  const h1Invite = signedEntry('ex-h1-inv', makeStep({
    id: 'ex-h1-inv', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/invites/resolve',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { token: 'esc-tok', tenant: 'org_a', role: 'admin' },
  }), { timestampMs: 1000, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)', emittedCapabilities: [inviteCap] })
  const h2Vault = signedEntry('ex-h2-vault', makeStep({
    id: 'ex-h2-vault', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/records/r-a',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { tenantId: 'org_a', records: [{ id: 'r-a', amountCents: 9900 }] },
  }), { timestampMs: 1200, actorPersona: null, actorRoleLabel: null, consumedCapabilities: [inviteCap] })
  const ctrlB = signedEntry('ex-ctrl-b', makeStep({
    id: 'ex-ctrl-b', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/records/r-a',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { error: 'forbidden' },
  }), { timestampMs: 900, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)' })
  const rLegit = verifyCompositeReceipt({
    chainId: 'm2-legit-dag-escalated-cap',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' }, exchangeIds: ['ex-h1-inv'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Resolved escalated session', producedCapabilities: [inviteCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/records/r-a' }, exchangeIds: ['ex-h2-vault'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read org_a record via DAG-minted session', producedCapabilities: [], consumedCapabilities: [inviteCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: inviteCap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      summary: 'Escalated session minted inside DAG read foreign tenant records.',
      terminalExchangeId: 'ex-h2-vault',
      preChainControlExchangeIds: ['ex-ctrl-b'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrlB, h1Invite, h2Vault] }, { attackerPersonas: ['member_b'], signingKey: SIGNING_KEY })
  assert.equal(rLegit.confirmed, true, rLegit.reason)
})

// ============================================================================
// 3. selectStateTransitionPair derived-cap & login-cap lineage
// ============================================================================

test('Req 3: selectStateTransitionPair resolves derived-cap and setup-login-cap lineage without false actor_discontinuity while rejecting mismatched personas', () => {
  const setupCapB = 'cap:hop_setup:member_b_session'
  const setupCapA = 'cap:hop_setup:member_a_session'
  const dagCap = 'cap:hop_1:delegated_session'

  const loginB = signedEntry('ex-l-b', makeStep({
    id: 'ex-l-b', arm: 'setup', method: 'POST', status: 200, pathAndQuery: '/login',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { token: 'tok-b', tenant: 'org_b' },
  }), { timestampMs: 500, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)', emittedCapabilities: [setupCapB] })

  const loginA = signedEntry('ex-l-a', makeStep({
    id: 'ex-l-a', arm: 'setup', method: 'POST', status: 200, pathAndQuery: '/login',
    actor: { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { token: 'tok-a', tenant: 'org_a' },
  }), { timestampMs: 510, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', emittedCapabilities: [setupCapA] })

  const fromB = signedEntry('ex-from-b', makeStep({
    id: 'ex-from-b', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/search/facets?q=private',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { count: 3 },
  }), { timestampMs: 1000, actorPersona: 'member_b', actorRoleLabel: 'member (org_b)', consumedCapabilities: [setupCapB] })

  // toHop omits `as` (`actorPersona: null`) and carries setupCapB (NOT in dagDerivedCaps!)
  const toCapB = signedEntry('ex-to-cap-b', makeStep({
    id: 'ex-to-cap-b', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/share/metadata',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { folder: 'private', exportHandle: 'h-1' },
  }), { timestampMs: 1200, actorPersona: null, actorRoleLabel: null, consumedCapabilities: [setupCapB] })

  // toHop uses actorPersona: 'cap:hop_1:delegated_session' (in dagDerivedCaps)
  const toActorCap = signedEntry('ex-to-actor-cap', makeStep({
    id: 'ex-to-actor-cap', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/action',
    actor: { handle: dagCap, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { ok: true, applied: true },
  }), { timestampMs: 1300, actorPersona: dagCap, actorRoleLabel: null })

  // Mismatched setup cap from member_a (NOT member_b, NOT in dagDerivedCaps)
  const toCapA = signedEntry('ex-to-cap-a', makeStep({
    id: 'ex-to-cap-a', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/share/metadata',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { folder: 'private' },
  }), { timestampMs: 1250, actorPersona: null, actorRoleLabel: null, consumedCapabilities: [setupCapA] })

  const toAnon = signedEntry('ex-to-anon', makeStep({
    id: 'ex-to-anon', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/share/metadata',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { folder: 'private' },
  }), { timestampMs: 1260, actorPersona: null, actorRoleLabel: null })

  const anonRe = /^(?:anon(?:ymous)?|unauth(?:enticated)?|guest)$/i
  const capIdx = buildCapOriginIndex([loginB, loginA, fromB, toCapB, toActorCap, toCapA, toAnon], anonRe)
  const helpers = {
    actorOf: (e: HostTranscriptEntry) => (e.actorPersona !== undefined ? e.actorPersona : (e.step.actor.handle ?? null)),
    probeTenantOf: () => null,
    entryMatchesEntity: () => false,
    anonActorRe: anonRe,
    resolveCapActor: (c: string) => capIdx.actorOf(c),
  }

  // Same-actor setup login cap (omitting `as` on toHop) -> PASSES!
  const okSetup = selectStateTransitionPair('state:folder_probe', [fromB], [toCapB], new Set(), helpers)
  assert.equal(okSetup.ok, true, 'setup login cap from same actor must not false-reject with actor_discontinuity')

  // DAG-derived cap in actorPersona -> PASSES!
  const okDagActor = selectStateTransitionPair('state:folder_probe', [fromB], [toActorCap], new Set([dagCap]), helpers)
  assert.equal(okDagActor.ok, true, 'DAG-derived cap in actorPersona must pass')

  // Different-actor setup login cap (member_b -> member_a cap) -> MUST REJECT with actor_discontinuity!
  const badMismatch = selectStateTransitionPair('state:folder_probe', [fromB], [toCapA], new Set(), helpers)
  assert.equal(badMismatch.ok, false)
  if (!badMismatch.ok) assert.equal(badMismatch.reason, 'actor_discontinuity')

  // Unlinked anonymous toHop -> MUST REJECT with actor_discontinuity!
  const badAnon = selectStateTransitionPair('state:folder_probe', [fromB], [toAnon], new Set(), helpers)
  assert.equal(badAnon.ok, false)
  if (!badAnon.ok) assert.equal(badAnon.reason, 'actor_discontinuity')
})

// ============================================================================
// 4. Tightened terminal stub gate & expanded isJobOrHandleStub
// ============================================================================

test('Req 4: isJobOrHandleStub rejects unexercised token-mint, session-mint, invite-list, and delivery-log stubs while accepting real payloads', () => {
  const stubs: Array<[unknown, number, string, string?]> = [
    [{ token: 'sess_1', tenant: 'org-a', role: 'finance', verified: false }, 200, 'POST', '/invites/resolve'],
    [{ token: 'sess_2', tenant: 'org-a', role: 'admin' }, 200, 'POST', '/invites/redeem'],
    [{ commentId: 'cmt_1', token: 'scim_tok_1' }, 200, 'GET', '/v1/inbox/cmt_1'],
    [{ patId: 'pat_1', token: 'pat_tok_1', scopes: ['repo:read'] }, 201, 'POST', '/pats'],
    [{ code: 'code_1', redirect: '/s/share-1', state: 'st' }, 200, 'GET', '/authorize'],
    [{ shareId: 'share-1', linked: true, state: 'st' }, 200, 'GET', '/s/share-1'],
    [{ invites: [{ id: 'inv_1', tenant: 'org-a', role: 'admin', email: 'a@org-a.test', revoked: false, verified: true, token: 'inv_tok_1' }] }, 200, 'GET', '/invites'],
    [{ invites: [] }, 200, 'GET', '/invites'],
    [{ webhookId: 'wh_1', deliveryId: 'dlv_1', status: 401 }, 201, 'POST', '/v1/projects/p1/webhooks'],
    [{ deliveries: [{ id: 'dlv_1', status: 401, log: 'delivery rejected: upstream 401 (body withheld)', ts: 1_700_000_000 }] }, 200, 'GET', '/v1/projects/p1/webhooks/wh_1/deliveries'],
    [{ deliveries: [{ id: 'dlv_2', status: 200, log: 'x-internal-token: tok_unexercised_123', ts: 1_700_000_000 }] }, 200, 'GET', '/v1/projects/p1/webhooks/wh_1/deliveries'],
  ]
  for (const [payload, status, method, route] of stubs) {
    assert.equal(isJobOrHandleStub(payload, undefined, status, method, route), true, `Expected stub=true for ${JSON.stringify(payload)}`)
  }

  const realPayloads: Array<[unknown, number, string, string?]> = [
    [{ userId: 'u_1', tenant: 'org_a', role: 'admin', origin: 'member_b' }, 200, 'GET', '/v1/me'],
    [{ tenant: 'org_b', secrets: [{ name: 'PROD_KEY', scope: 'prod', value: 'v-1' }] }, 200, 'POST', '/v1/integrations/registry/sync'],
    [{ role: 'owner' }, 200, 'GET', '/v1/me'],
    [{ token: 'eyJ...', user: { email: 'admin@victim.test', role: 'admin' } }, 200, 'GET', '/v1/session'],
    [{ payout: { id: 'po_1', status: 'approved', amountCents: 5000 } }, 200, 'POST', '/v1/payouts/po_1/approve'],
    [{ settled: true, amountCents: 50000, ledgerBalance: 150000 }, 200, 'POST', '/v1/webhooks/settlement'],
  ]
  for (const [payload, status, method, route] of realPayloads) {
    assert.equal(isJobOrHandleStub(payload, undefined, status, method, route), false, `Expected stub=false for ${JSON.stringify(payload)}`)
  }
})

test('Req 4: decoy partial chains with derived_crypto_binding ending on invite-resolve, rebind, invite-list, or delivery-log fail closed', () => {
  const emailCap = 'cap:hop_1:pending_email'
  const sessCap = 'cap:hop_2:unverified_sess'
  const tplCap = 'cap:hop_1:webhook_tpl'
  const whCap = 'cap:hop_2:webhook_id'
  const digest = sha256Hex('derived-payload')

  // Decoy 1: 2-hop partial chain with derived_crypto_binding ending on unexercised invite-resolve session mint
  const d1H1 = signedEntry('d1-h1', makeStep({
    id: 'd1-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/directory/orgs/org-a',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { pendingEmail: 'fin@org-a.test' },
  }), { timestampMs: 1000, actorPersona: 'member_b', emittedCapabilities: [emailCap] })
  const d1H2 = signedEntry('d1-h2', makeStep({
    id: 'd1-h2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/invites/resolve',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { token: 'tok_unverified', tenant: 'org-a', role: 'finance', verified: false },
  }), {
    timestampMs: 1200, actorPersona: 'member_b', emittedCapabilities: [sessCap],
    cryptoAttestations: [{ derivedFromCapabilityId: emailCap, alg: 'sha256', artifactDigest: digest, timestampMs: 1100 }],
  })
  const rD1 = verifyCompositeReceipt({
    chainId: 'decoy-invite-resolve-2hop',
    terminalVulnClass: 'self_approved_payout',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/directory/orgs/org-a' }, exchangeIds: ['d1-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Found pending email', producedCapabilities: [emailCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'idp', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' }, exchangeIds: ['d1-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Minted unverified finance session', producedCapabilities: [sessCap], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'derived_crypto_binding', fromHopId: 'h1', toHopId: 'h2', sourceCapabilityId: emailCap, alg: 'sha256' }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'Minted an unverified session token via invite collision without exercising it.',
      terminalExchangeId: 'd1-h2',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [d1H1, d1H2] }, { attackerPersonas: ['member_b'], signingKey: SIGNING_KEY })
  assert.equal(rD1.confirmed, false, '2-hop partial chain ending on invite-resolve must fail closed')
  assert.equal(rD1.failedStage, 'terminal_impact')
  assert.equal(rD1.rejectedBy, 'terminal_impact_unproven')

  // Decoy 2: 3-hop partial chain with derived_crypto_binding on h1->h2 and value_binding on h2->h3 ending on intermediate rebind (no denied control)
  const d1H3Rebind = signedEntry('d1-h3', makeStep({
    id: 'd1-h3', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: '/v1/payouts/po-1/rebind',
    actor: { handle: 'member_b', role: 'member', tenant: 'org_b', auth: 'bearer', sameSite: null },
    json: { payout: { id: 'po-1', status: 'draft', creator: 'member_b' } },
  }), { timestampMs: 1400, actorPersona: 'member_b', consumedCapabilities: [sessCap] })
  const rRebind = verifyCompositeReceipt({
    chainId: 'decoy-intermediate-rebind-3hop',
    terminalVulnClass: 'self_approved_payout',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/directory/orgs/org-a' }, exchangeIds: ['d1-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Found pending email', producedCapabilities: [emailCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'idp', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' }, exchangeIds: ['d1-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Minted session', producedCapabilities: [sessCap], consumedCapabilities: [] },
      { hopId: 'h3', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/payouts/po-1/rebind' }, exchangeIds: ['d1-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Rebound draft payout without approval', producedCapabilities: [], consumedCapabilities: [sessCap] },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'h1', toHopId: 'h2', sourceCapabilityId: emailCap, alg: 'sha256' },
      { kind: 'value_binding', fromHopId: 'h2', toHopId: 'h3', capabilityHandle: sessCap },
    ],
    terminalImpact: {
      terminalHopId: 'h3',
      summary: 'Partial chain ended at intermediate rebind without approval or denied control.',
      terminalExchangeId: 'd1-h3',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [d1H1, d1H2, d1H3Rebind] }, { attackerPersonas: ['member_b'], signingKey: SIGNING_KEY })
  assert.equal(rRebind.confirmed, false, '3-hop partial chain ending on intermediate rebind without denied control must fail closed')
  assert.equal(rRebind.failedStage, 'terminal_impact')
  assert.equal(rRebind.rejectedBy, 'terminal_impact_unproven')

  // Decoy 3: 3-hop partial chain with derived_crypto_binding on h1->h2 ending on delivery-log stub
  const d3H1 = signedEntry('d3-h1', makeStep({
    id: 'd3-h1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/search/projects',
    json: { webhookTemplates: [{ id: 'tpl-1' }] },
  }), { timestampMs: 1000, actorPersona: 'member_a', emittedCapabilities: [tplCap] })
  const d3H2 = signedEntry('d3-h2', makeStep({
    id: 'd3-h2', arm: 'probe', method: 'POST', status: 201, pathAndQuery: '/v1/projects/p1/webhooks',
    json: { webhookId: 'wh-1', deliveryId: 'dlv-1', status: 401 },
  }), {
    timestampMs: 1200, actorPersona: 'member_a', emittedCapabilities: [whCap],
    cryptoAttestations: [{ derivedFromCapabilityId: tplCap, alg: 'sha256', artifactDigest: digest, timestampMs: 1100 }],
  })
  const d3H3 = signedEntry('d3-h3', makeStep({
    id: 'd3-h3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/projects/p1/webhooks/wh-1/deliveries',
    json: { deliveries: [{ id: 'dlv-1', status: 401, log: 'delivery rejected: upstream 401 (body withheld)', ts: 1200 }] },
  }), { timestampMs: 1400, actorPersona: 'member_a', consumedCapabilities: [whCap] })
  const rD3 = verifyCompositeReceipt({
    chainId: 'decoy-delivery-log-3hop',
    terminalVulnClass: 'internal_token_exfiltration',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/search/projects' }, exchangeIds: ['d3-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Found webhook template', producedCapabilities: [tplCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/projects/p1/webhooks' }, exchangeIds: ['d3-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created webhook delivery', producedCapabilities: [whCap], consumedCapabilities: [] },
      { hopId: 'h3', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/projects/p1/webhooks/wh-1/deliveries' }, exchangeIds: ['d3-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read redacted delivery log', producedCapabilities: [], consumedCapabilities: [whCap] },
    ],
    causalEdges: [
      { kind: 'derived_crypto_binding', fromHopId: 'h1', toHopId: 'h2', sourceCapabilityId: tplCap, alg: 'sha256' },
      { kind: 'value_binding', fromHopId: 'h2', toHopId: 'h3', capabilityHandle: whCap },
    ],
    terminalImpact: {
      terminalHopId: 'h3',
      summary: 'Partial chain ended at redacted delivery log without exfiltrating data.',
      terminalExchangeId: 'd3-h3',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [d3H1, d3H2, d3H3] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(rD3.confirmed, false, '3-hop partial chain ending on delivery-log stub must fail closed')
  assert.equal(rD3.failedStage, 'terminal_impact')
  assert.equal(rD3.rejectedBy, 'terminal_impact_unproven')

  // Positive control: exercising the redeemed session in postChainReadbackExchangeIds CONFIRMS!
  const meReadback = signedEntry('d1-rb', makeStep({
    id: 'd1-rb', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/v1/me',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { userId: 'u-b', tenant: 'org-a', role: 'admin', origin: 'member_b' },
    evidenceRole: 'post_chain_readback',
  }), { timestampMs: 1500, actorPersona: null, consumedCapabilities: [sessCap], evidenceRole: 'post_chain_readback' })
  const rExercised = verifyCompositeReceipt({
    chainId: 'valid-exercised-session-readback',
    terminalVulnClass: 'stale_privilege_use',
    hops: [
      { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/directory/orgs/org-a' }, exchangeIds: ['d1-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Found stale invite handle', producedCapabilities: [emailCap], consumedCapabilities: [] },
      { hopId: 'h2', surface: 'idp', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' }, exchangeIds: ['d1-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Redeemed stale invite into admin session', producedCapabilities: [sessCap], consumedCapabilities: [] },
    ],
    causalEdges: [{ kind: 'derived_crypto_binding', fromHopId: 'h1', toHopId: 'h2', sourceCapabilityId: emailCap, alg: 'sha256' }],
    terminalImpact: {
      terminalHopId: 'h2',
      summary: 'Redeemed stale invite session and verified elevated admin role on /v1/me.',
      terminalExchangeId: 'd1-h2',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: ['d1-rb'],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [d1H1, d1H2, meReadback] }, { attackerPersonas: ['member_b'], signingKey: SIGNING_KEY })
  assert.equal(rExercised.confirmed, true, rExercised.reason)
})

test('LOC budgets: composite-receipt.ts <= 750 and v8-oracle-families.ts <= 750', () => {
  const crLines = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8').split('\n').length
  const ofLines = readFileSync(join(REPO_ROOT, 'src/server/v8-oracle-families.ts'), 'utf8').split('\n').length
  assert.ok(crLines <= 750, `composite-receipt.ts LOC ${crLines} > 750`)
  assert.ok(ofLines <= 750, `v8-oracle-families.ts LOC ${ofLines} > 750`)
})
