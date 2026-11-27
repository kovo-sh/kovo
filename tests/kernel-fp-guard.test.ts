/**
 * @kernel
 * R3-05 Confirmation-Kernel FP Guard Suite.
 *
 * Verifies:
 *  1. Consistent terminalVulnClass normalization (hyphens & whitespace -> `_`) across
 *     `composite-receipt.ts` and `v8-oracle-hydrate.ts` so hyphenated inputs like
 *     `broken-access-control`, `privilege-escalation`, `dual-tenant-abac`, and `business-logic`
 *     can never bypass class-specific oracle or precision guards.
 *  2. Rejection of own-org benign reads (directory, invites, collection listings like
 *     `GET /v1/payouts`, `GET /v1/directory/...`, `GET /v1/orgs/:own/invites`, and arbitrary
 *     custom-noun collections) and plain own-org POST resource creations (`POST /v1/orders`,
 *     `POST /v1/orgs/:own/exports`) across `broken_access_control`, `business_logic`, `bfla`,
 *     `privilege_escalation`, `bola`, and `idor`.
 *  3. Zero regression on legitimate cross-tenant, privilege-escalation, forged-settlement,
 *     state-transition, and economic-conservation TPs.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import '../src/server/terminal-oracle-registry.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/proof-receipt.ts'
import {
  normalizeTerminalVulnClass,
  resolveTerminalContract,
  resolveV8OracleFamilyOrDiagnostic,
} from '../src/server/v8-oracle-hydrate.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'kernel-fp-guard-test-signing-key-v1'

function makeEntry(
  exchangeId: string,
  opts: {
    arm: 'control' | 'probe'
    method: string
    pathAndQuery: string
    status: number
    timestampMs: number
    actorPersona?: string | null
    actorRole?: 'viewer' | 'member' | 'admin' | 'owner' | null
    actorTenant?: string | null
    actorRoleLabel?: string | null
    json?: unknown
    body?: string
    emittedCapabilities?: string[]
    consumedCapabilities?: string[]
    entityId?: string
    replayAttempt?: 'mode_a' | 'ablation_control' | 'primary'
  },
): HostTranscriptEntry {
  const actor = opts.actorPersona !== undefined ? opts.actorPersona : 'member_a'
  const tenant = opts.actorTenant !== undefined ? opts.actorTenant : (actor ? 'org_a' : null)
  const role = opts.actorRole !== undefined ? opts.actorRole : (actor ? 'member' : null)
  const step: ImpactStep = {
    id: exchangeId,
    arm: opts.arm,
    method: opts.method,
    status: opts.status,
    route: opts.pathAndQuery.split('?')[0]!,
    pathAndQuery: opts.pathAndQuery,
    actor: { handle: actor, role, tenant, auth: actor ? 'bearer' : 'unknown', sameSite: null },
    ...(opts.json !== undefined ? { json: opts.json } : {}),
    ...(opts.body !== undefined ? { body: opts.body } : {}),
  }
  const rec: HostTranscriptEntry = {
    exchangeId,
    origin: ORIGIN,
    step,
    timestampMs: opts.timestampMs,
    actorPersona: actor,
    ...(opts.actorRoleLabel !== undefined ? { actorRoleLabel: opts.actorRoleLabel } : {}),
    ...(tenant !== null ? { actorTenant: tenant } : {}),
    cleanSession: true,
    ...(opts.emittedCapabilities ? { emittedCapabilities: opts.emittedCapabilities } : {}),
    ...(opts.consumedCapabilities ? { consumedCapabilities: opts.consumedCapabilities } : {}),
    ...(opts.entityId ? { entityId: opts.entityId } : {}),
    ...(opts.replayAttempt ? { replayAttempt: opts.replayAttempt } : {}),
  }
  return { ...rec, hostSignature: signHostRecord(rec, SIGNING_KEY) }
}

function verifyWithFactLog(
  receipt: CompositeProofReceipt,
  entries: HostTranscriptEntry[],
  opts: { attackerPersonas?: string[]; personaRoleLabels?: Record<string, string> } = {},
) {
  const transcript: HostSignedTranscript = { entries }
  const factLog = HostFactLog.fromTranscript(transcript)
  return verifyCompositeReceipt(receipt, transcript, {
    signingKey: SIGNING_KEY,
    factLog,
    attackerPersonas: opts.attackerPersonas ?? ['member_a'],
    ...(opts.personaRoleLabels ? { personaRoleLabels: opts.personaRoleLabels } : {}),
  })
}

function singleHopReceipt(
  terminalVulnClass: string,
  method: string,
  pathAndQuery: string,
  probeId: string,
  ctrlId: string,
  postReadbackIds: string[] = [],
): CompositeProofReceipt {
  return {
    chainId: `fp-guard-${terminalVulnClass.replace(/[^a-z0-9]+/gi, '-')}`,
    terminalVulnClass,
    hops: [
      {
        hopId: 'hop_term',
        surface: 'http',
        target: { origin: ORIGIN, method, pathAndQuery },
        exchangeIds: [probeId],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: `Attempted ${method} ${pathAndQuery}`,
        producedCapabilities: [],
        consumedCapabilities: [],
      },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_term',
      terminalExchangeId: probeId,
      claimedImpact: `Claimed terminal impact on ${method} ${pathAndQuery}`,
      summary: `Claimed terminal impact on ${method} ${pathAndQuery}`,
      preChainControlExchangeIds: [ctrlId],
      postChainReadbackExchangeIds: postReadbackIds,
    },
    replayMode: 'fresh_clean_replay',
  }
}

// ============================================================================
// 1. Consistent class normalization (`-` & whitespace -> `_`)
// ============================================================================

test('normalizeTerminalVulnClass, resolveTerminalContract, and resolveV8OracleFamilyOrDiagnostic normalize hyphens & whitespace', () => {
  assert.equal(normalizeTerminalVulnClass('  broken-access-control  '), 'broken_access_control')
  assert.equal(normalizeTerminalVulnClass('Privilege-Escalation'), 'privilege_escalation')
  assert.equal(normalizeTerminalVulnClass('dual-tenant  abac'), 'dual_tenant_abac')
  assert.equal(normalizeTerminalVulnClass('business-logic'), 'business_logic')

  assert.equal(resolveTerminalContract('broken-access-control'), resolveTerminalContract('broken_access_control'))
  assert.ok(resolveTerminalContract('broken-access-control'))
  assert.equal(resolveTerminalContract('privilege-escalation'), resolveTerminalContract('privilege_escalation'))
  assert.ok(resolveTerminalContract('privilege-escalation'))
  assert.equal(resolveTerminalContract('dual-tenant-abac'), 'v8_dual_tenant')
  assert.equal(resolveTerminalContract('economic-conservation'), 'v8_economic')
  assert.equal(resolveTerminalContract('business-logic'), resolveTerminalContract('business_logic'))
  assert.ok(resolveTerminalContract('business-logic'))

  const dualFam = resolveV8OracleFamilyOrDiagnostic(undefined, 'dual-tenant-abac', undefined)
  assert.equal(dualFam.ok, true)
  if (dualFam.ok) assert.equal(dualFam.family, 'dual_tenant_abac')

  const econFam = resolveV8OracleFamilyOrDiagnostic(undefined, 'economic conservation', undefined)
  assert.equal(econFam.ok, true)
  if (econFam.ok) assert.equal(econFam.family, 'economic_conservation')
})

test('hyphenated v8 oracle class (dual-tenant-abac) cannot bypass dual_tenant_abac multi-hop oracle enforcement', () => {
  const entries = [
    makeEntry('ex-ctrl', { arm: 'control', method: 'GET', pathAndQuery: '/v1/records/rec-1', status: 403, timestampMs: 1000 }),
    makeEntry('ex-probe', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/records/rec-1', status: 200, timestampMs: 1100, json: { id: 'rec-1', tenant: 'org_b', amount: 500 } }),
  ]
  const res = verifyWithFactLog(
    singleHopReceipt('dual-tenant-abac', 'GET', '/v1/records/rec-1', 'ex-probe', 'ex-ctrl'),
    entries,
  )
  assert.equal(res.confirmed, false)
  assert.match(res.reason, /dual_tenant_abac|multi_hop_causal_chain_required/i)
})

test('hyphenated cross-tenant class (cross-tenant-read / cross-tenant-bola) rejects own-tenant-only reads', () => {
  const entries = [
    makeEntry('ex-ctrl', { arm: 'control', method: 'GET', pathAndQuery: '/v1/payouts/pay-1', status: 403, timestampMs: 1000 }),
    makeEntry('ex-probe', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/payouts/pay-1', status: 200, timestampMs: 1100, json: { id: 'pay-1', tenant: 'org_a', amountCents: 1000 } }),
  ]
  for (const cls of ['cross-tenant-read', 'cross-tenant-bola']) {
    const res = verifyWithFactLog(singleHopReceipt(cls, 'GET', '/v1/payouts/pay-1', 'ex-probe', 'ex-ctrl'), entries)
    assert.equal(res.confirmed, false, `${cls} should fail closed on own-tenant-only read`)
  }
})

// ============================================================================
// 2. Own-org benign-read rejection (directory / invites / collections)
// ============================================================================

test('rejects own-org directory, invite, and collection GET listings across broken_access_control, business_logic, bfla, and hyphenated classes', () => {
  const cases: Array<{ label: string; cls: string; path: string; json: unknown; personaRoleLabels?: Record<string, string> }> = [
    {
      label: 'business_logic -> GET /v1/payouts (own-org collection)',
      cls: 'business_logic',
      path: '/v1/payouts',
      json: { payouts: [{ id: 'pay-1', tenant: 'org_a', amountCents: 2500 }] },
    },
    {
      label: 'business-logic -> GET /v1/payouts (unattributed collection)',
      cls: 'business-logic',
      path: '/v1/payouts',
      json: { payouts: [{ id: 'pay-1', amountCents: 2500 }] },
    },
    {
      label: 'bfla -> GET /v1/directory/orgs/org_a',
      cls: 'bfla',
      path: '/v1/directory/orgs/org_a',
      json: { org: 'org_a', members: [{ email: 'fin@org-a.test', role: 'finance' }] },
    },
    {
      label: 'privilege-escalation -> GET /v1/directory/orgs/org_a',
      cls: 'privilege-escalation',
      path: '/v1/directory/orgs/org_a',
      json: { org: 'org_a', members: [{ email: 'fin@org-a.test', role: 'finance' }] },
    },
    {
      label: 'broken_access_control -> GET /v1/orgs/org_a/invites',
      cls: 'broken_access_control',
      path: '/v1/orgs/org_a/invites',
      json: { invites: [{ id: 'inv-1', tenant: 'org_a', email: 'fin@org-a.test' }] },
    },
    {
      label: 'broken-access-control -> GET /v1/orgs/acme/invites (own slug via personaRoleLabels, body omits tenant)',
      cls: 'broken-access-control',
      path: '/v1/orgs/acme/invites',
      json: { invites: [{ id: 'inv-1', email: 'fin@acme.test' }] },
      personaRoleLabels: { member_a: 'member [slug=acme] (org_a)' },
    },
    {
      label: 'broken_access_control -> GET /v1/widgets (custom-noun own-org collection)',
      cls: 'broken_access_control',
      path: '/v1/widgets',
      json: { tenant: 'org_a', widgets: [{ id: 'w-1', name: 'alpha' }] },
    },
  ]

  for (const tc of cases) {
    const entries = [
      makeEntry('ex-ctrl', { arm: 'control', method: 'GET', pathAndQuery: tc.path, status: 403, timestampMs: 1000 }),
      makeEntry('ex-probe', { arm: 'probe', method: 'GET', pathAndQuery: tc.path, status: 200, timestampMs: 1100, json: tc.json }),
    ]
    const res = verifyWithFactLog(
      singleHopReceipt(tc.cls, 'GET', tc.path, 'ex-probe', 'ex-ctrl'),
      entries,
      tc.personaRoleLabels ? { personaRoleLabels: tc.personaRoleLabels } : {},
    )
    assert.equal(res.confirmed, false, `Expected FAIL for ${tc.label}, got confirmed=true`)
    assert.equal(res.rejectedBy, 'terminal_impact_unproven', `Expected terminal_impact_unproven for ${tc.label}`)
  }
})

// ============================================================================
// 3. Own-org benign-create rejection (`POST /v1/orders`, `POST /v1/orgs/:own/exports`)
// ============================================================================

test('rejects plain own-org POST resource creation without post-mutation readback or v8 oracle', () => {
  const cases: Array<{ label: string; cls: string; path: string; json: unknown; personaRoleLabels?: Record<string, string> }> = [
    {
      label: 'business_logic -> POST /v1/orders',
      cls: 'business_logic',
      path: '/v1/orders',
      json: { order: { id: 'ord-1', tenant: 'org_a', totalCents: 1200, status: 'created' } },
    },
    {
      label: 'broken_access_control -> POST /v1/orgs/org_a/exports (non-stub body)',
      cls: 'broken_access_control',
      path: '/v1/orgs/org_a/exports',
      json: { tenant: 'org_a', rowsExported: 4, format: 'csv', created: true },
    },
    {
      label: 'broken-access-control -> POST /v1/orgs/acme/exports (own slug)',
      cls: 'broken-access-control',
      path: '/v1/orgs/acme/exports',
      json: { rowsExported: 4, format: 'csv', created: true },
      personaRoleLabels: { member_a: 'member [slug=acme] (org_a)' },
    },
    {
      label: 'bfla -> POST /v1/orders (same persona, no escalation)',
      cls: 'bfla',
      path: '/v1/orders',
      json: { order: { id: 'ord-1', tenant: 'org_a', totalCents: 1200 } },
    },
  ]

  for (const tc of cases) {
    const entries = [
      makeEntry('ex-ctrl', { arm: 'control', method: 'POST', pathAndQuery: tc.path, status: 403, timestampMs: 1000 }),
      makeEntry('ex-probe', { arm: 'probe', method: 'POST', pathAndQuery: tc.path, status: 201, timestampMs: 1100, json: tc.json }),
    ]
    const res = verifyWithFactLog(
      singleHopReceipt(tc.cls, 'POST', tc.path, 'ex-probe', 'ex-ctrl'),
      entries,
      tc.personaRoleLabels ? { personaRoleLabels: tc.personaRoleLabels } : {},
    )
    assert.equal(res.confirmed, false, `Expected FAIL for ${tc.label}, got confirmed=true`)
    assert.equal(res.rejectedBy, 'terminal_impact_unproven', `Expected terminal_impact_unproven for ${tc.label}`)
  }
})

// ============================================================================
// 4. Legitimate TP preservation (zero TP regressions)
// ============================================================================

test('preserves legitimate cross-tenant, priv-esc, forged-settlement, and business-logic TPs', () => {
  // (a) Cross-tenant secret exfiltration (broken_access_control -> POST /v1/integrations/registry/sync)
  const crossTenantRes = verifyWithFactLog(
    singleHopReceipt('broken_access_control', 'POST', '/v1/integrations/registry/sync', 'ex-sync-200', 'ex-sync-401'),
    [
      makeEntry('ex-sync-401', { arm: 'control', method: 'POST', pathAndQuery: '/v1/integrations/registry/sync', status: 401, timestampMs: 1000 }),
      makeEntry('ex-sync-200', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/integrations/registry/sync', status: 200, timestampMs: 1100, json: { tenant: 'org_b', secrets: [{ key: 'webhook_salt', value: 's3cr3t' }] } }),
    ],
  )
  assert.equal(crossTenantRes.confirmed, true, `cross-tenant secret sync regressed: ${crossTenantRes.reason}`)

  // (b) Own-org privilege escalation mutation via derived capability without readback (PATCH /v1/scim/users/:id)
  const scimCap = 'cap:hop_leak:scim_tok'
  const scimReceipt: CompositeProofReceipt = {
    chainId: 'tp-priv-esc-scim',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'hop_leak', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/inbox/msg-1' }, exchangeIds: ['ex-leak'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Leaked SCIM token', producedCapabilities: [scimCap], consumedCapabilities: [] },
      { hopId: 'hop_scim', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/v1/scim/users/usr-99' }, exchangeIds: ['ex-patch'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Escalated user role to owner', producedCapabilities: [], consumedCapabilities: [scimCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_leak', toHopId: 'hop_scim', capabilityHandle: scimCap }],
    terminalImpact: {
      terminalHopId: 'hop_scim',
      terminalExchangeId: 'ex-patch',
      claimedImpact: 'Escalated own-org member to owner via leaked SCIM token',
      summary: 'Escalated own-org member to owner via leaked SCIM token',
      preChainControlExchangeIds: ['ex-scim-401'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const scimRes = verifyWithFactLog(scimReceipt, [
    makeEntry('ex-scim-401', { arm: 'control', method: 'PATCH', pathAndQuery: '/v1/scim/users/usr-99', status: 401, timestampMs: 900 }),
    makeEntry('ex-leak', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/inbox/msg-1', status: 200, timestampMs: 1000, emittedCapabilities: [scimCap], json: { id: 'msg-1' } }),
    makeEntry('ex-patch', { arm: 'probe', method: 'PATCH', pathAndQuery: '/v1/scim/users/usr-99', status: 200, timestampMs: 1100, actorPersona: scimCap, actorTenant: 'org_a', consumedCapabilities: [scimCap], json: { id: 'usr-99', tenant: 'org_a', role: 'owner' } }),
  ])
  assert.equal(scimRes.confirmed, true, `own-org SCIM priv-esc regressed: ${scimRes.reason}`)

  // (c) Own-org business_logic WITH verified post-mutation readback (POST /v1/orders/:id/settle-race)
  const raceRes = verifyWithFactLog(
    singleHopReceipt('business_logic', 'POST', '/v1/orders/ord-42/settle-race', 'ex-race-200', 'ex-race-403', ['ex-race-rb']),
    [
      makeEntry('ex-race-403', { arm: 'control', method: 'POST', pathAndQuery: '/v1/orders/ord-42/settle-race', status: 403, timestampMs: 900 }),
      makeEntry('ex-race-200', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/ord-42/settle-race', status: 200, timestampMs: 1000, json: { order: { id: 'ord-42', tenant: 'org_a', captures: 2 } } }),
      makeEntry('ex-race-rb', { arm: 'control', method: 'GET', pathAndQuery: '/v1/orders/ord-42', status: 200, timestampMs: 1100, json: { order: { id: 'ord-42', tenant: 'org_a', captures: 2 } } }),
    ],
  )
  assert.equal(raceRes.confirmed, true, `business_logic with post-mutation readback regressed: ${raceRes.reason}`)

  // (d) Own-org business_logic WITHOUT readback BUT with escalated derived cap + 403 control on specific resource action
  const finCap = 'cap:hop_redeem:finance_session'
  const payoutApproveReceipt: CompositeProofReceipt = {
    chainId: 'tp-biz-logic-escalated-approve',
    terminalVulnClass: 'business_logic',
    hops: [
      { hopId: 'hop_redeem', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/invites/resolve' }, exchangeIds: ['ex-redeem'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Redeemed leaked finance invite', producedCapabilities: [finCap], consumedCapabilities: [] },
      { hopId: 'hop_approve', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/payouts/pay-88/approve' }, exchangeIds: ['ex-approve'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Self-approved payout with finance token', producedCapabilities: [], consumedCapabilities: [finCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_redeem', toHopId: 'hop_approve', capabilityHandle: finCap }],
    terminalImpact: {
      terminalHopId: 'hop_approve',
      terminalExchangeId: 'ex-approve',
      claimedImpact: 'Self-approved own-org payout using redeemed finance session',
      summary: 'Self-approved own-org payout using redeemed finance session',
      preChainControlExchangeIds: ['ex-app-403'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const payoutApproveRes = verifyWithFactLog(payoutApproveReceipt, [
    makeEntry('ex-app-403', { arm: 'control', method: 'POST', pathAndQuery: '/v1/payouts/pay-88/approve', status: 403, timestampMs: 900 }),
    makeEntry('ex-redeem', { arm: 'probe', method: 'POST', pathAndQuery: '/invites/resolve', status: 200, timestampMs: 1000, emittedCapabilities: [finCap], json: { role: 'finance' } }),
    makeEntry('ex-approve', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/payouts/pay-88/approve', status: 200, timestampMs: 1100, actorPersona: finCap, actorTenant: 'org_a', consumedCapabilities: [finCap], json: { payout: { id: 'pay-88', tenant: 'org_a', status: 'approved' } } }),
  ])
  assert.equal(payoutApproveRes.confirmed, true, `business_logic escalated payout approval regressed: ${payoutApproveRes.reason}`)

  // (e) Sensitive own-org privilege_escalation read (GET /v1/audit/vault with derived cap + 403 control)
  const vaultCap = 'cap:hop_escalate:audit_tok'
  const vaultReceipt: CompositeProofReceipt = {
    chainId: 'tp-priv-esc-audit-vault',
    terminalVulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'hop_esc', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/v1/tokens/exchange' }, exchangeIds: ['ex-esc'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained elevated audit token', producedCapabilities: [vaultCap], consumedCapabilities: [] },
      { hopId: 'hop_vault', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/v1/audit/vault' }, exchangeIds: ['ex-vault'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read restricted audit vault', producedCapabilities: [], consumedCapabilities: [vaultCap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_esc', toHopId: 'hop_vault', capabilityHandle: vaultCap }],
    terminalImpact: {
      terminalHopId: 'hop_vault',
      terminalExchangeId: 'ex-vault',
      claimedImpact: 'Read privileged audit vault records after privilege escalation',
      summary: 'Read privileged audit vault records after privilege escalation',
      preChainControlExchangeIds: ['ex-vault-403'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const vaultRes = verifyWithFactLog(vaultReceipt, [
    makeEntry('ex-vault-403', { arm: 'control', method: 'GET', pathAndQuery: '/v1/audit/vault', status: 403, timestampMs: 900 }),
    makeEntry('ex-esc', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/tokens/exchange', status: 200, timestampMs: 1000, emittedCapabilities: [vaultCap], json: { ok: true } }),
    makeEntry('ex-vault', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/audit/vault', status: 200, timestampMs: 1100, actorPersona: vaultCap, actorTenant: 'org_a', consumedCapabilities: [vaultCap], json: { tenant: 'org_a', events: [{ id: 'ev-1', secretHash: 'abc' }] } }),
  ])
  assert.equal(vaultRes.confirmed, true, `privileged audit vault read regressed: ${vaultRes.reason}`)

  // (f) Cross-tenant forged settlement (forged_settlement -> POST /v1/webhooks/settlement + readback)
  const settleRes = verifyWithFactLog(
    singleHopReceipt('forged_settlement', 'POST', '/v1/webhooks/settlement', 'ex-settle-200', 'ex-settle-401', ['ex-settle-rb']),
    [
      makeEntry('ex-settle-401', { arm: 'control', method: 'POST', pathAndQuery: '/v1/webhooks/settlement', status: 401, timestampMs: 900 }),
      makeEntry('ex-settle-200', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/webhooks/settlement', status: 200, timestampMs: 1000, json: { accepted: true, tenantId: 'org_b', amountCents: 99999 } }),
      makeEntry('ex-settle-rb', { arm: 'control', method: 'GET', pathAndQuery: '/v1/ledger', status: 200, timestampMs: 1100, actorPersona: 'member_b', actorTenant: 'org_b', json: { tenantId: 'org_b', balanceCents: 99999 } }),
    ],
  )
  assert.equal(settleRes.confirmed, true, `forged_settlement TP regressed: ${settleRes.reason}`)

  // (g) Foreign-org POST create (member_a targeting org_b) stays confirmed
  const foreignPostRes = verifyWithFactLog(
    singleHopReceipt('broken_access_control', 'POST', '/v1/orgs/org_b/orders', 'ex-fpost-201', 'ex-fpost-403'),
    [
      makeEntry('ex-fpost-403', { arm: 'control', method: 'POST', pathAndQuery: '/v1/orgs/org_b/orders', status: 403, timestampMs: 1000 }),
      makeEntry('ex-fpost-201', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orgs/org_b/orders', status: 201, timestampMs: 1100, json: { id: 'ord-b-1', totalCents: 2500, status: 'created' } }),
    ],
  )
  assert.equal(foreignPostRes.confirmed, true, `foreign-org POST TP regressed: ${foreignPostRes.reason}`)
})

// ============================================================================
// 5. R3-05 Independent Review Must-Fix Regression Guards
// ============================================================================

test('R3-05 Must-Fix #1: access_control contract aliases and auth_bypass family cannot bypass own-org read/create guards', () => {
  for (const cls of ['authz_bypass', 'authorization_bypass', 'auth_bypass', 'authentication_bypass', 'broken_auth', 'info_disclosure', 'information_disclosure', 'data_exposure']) {
    const getRes = verifyWithFactLog(
      singleHopReceipt(cls, 'GET', '/v1/payouts', 'ex-get-200', 'ex-get-403'),
      [
        makeEntry('ex-get-403', { arm: 'control', method: 'GET', pathAndQuery: '/v1/payouts', status: 403, timestampMs: 1000 }),
        makeEntry('ex-get-200', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/payouts', status: 200, timestampMs: 1100, json: { payouts: [{ id: 'p1', tenant: 'org_a', amount: 100 }] } }),
      ],
    )
    assert.equal(getRes.confirmed, false, `${cls} GET /v1/payouts must fail closed`)
    assert.equal(getRes.rejectedBy, 'terminal_impact_unproven')

    const postRes = verifyWithFactLog(
      singleHopReceipt(cls, 'POST', '/v1/orders', 'ex-post-201', 'ex-post-403'),
      [
        makeEntry('ex-post-403', { arm: 'control', method: 'POST', pathAndQuery: '/v1/orders', status: 403, timestampMs: 1000 }),
        makeEntry('ex-post-201', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders', status: 201, timestampMs: 1100, json: { order: { id: 'o1', tenant: 'org_a', total: 500 } } }),
      ],
    )
    assert.equal(postRes.confirmed, false, `${cls} POST /v1/orders must fail closed`)
    assert.equal(postRes.rejectedBy, 'terminal_impact_unproven')
  }
})

test('R3-05 Must-Fix #2: dot-segment traversal (/v1/payouts/vault/.., /v1/orders/admin/%2e%2e) cannot spoof sensitive-path exemption', () => {
  const dotGet = verifyWithFactLog(
    singleHopReceipt('broken_access_control', 'GET', '/v1/payouts/vault/..', 'ex-dot-get-200', 'ex-dot-get-403'),
    [
      makeEntry('ex-dot-get-403', { arm: 'control', method: 'GET', pathAndQuery: '/v1/payouts/vault/..', status: 403, timestampMs: 1000 }),
      makeEntry('ex-dot-get-200', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/payouts/vault/..', status: 200, timestampMs: 1100, json: { payouts: [{ id: 'p1', tenant: 'org_a', amount: 100 }] } }),
    ],
  )
  assert.equal(dotGet.confirmed, false, 'GET /v1/payouts/vault/.. must resolve dot-segments and fail closed')
  assert.equal(dotGet.rejectedBy, 'terminal_impact_unproven')

  const dotPost = verifyWithFactLog(
    singleHopReceipt('broken_access_control', 'POST', '/v1/orders/admin/%2e%2e', 'ex-dot-post-201', 'ex-dot-post-403'),
    [
      makeEntry('ex-dot-post-403', { arm: 'control', method: 'POST', pathAndQuery: '/v1/orders/admin/%2e%2e', status: 403, timestampMs: 1000 }),
      makeEntry('ex-dot-post-201', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders/admin/%2e%2e', status: 201, timestampMs: 1100, json: { id: 'o1', tenant: 'org_a', status: 'created' } }),
    ],
  )
  assert.equal(dotPost.confirmed, false, 'POST /v1/orders/admin/%2e%2e must resolve encoded dot-segments and fail closed')
  assert.equal(dotPost.rejectedBy, 'terminal_impact_unproven')
})

test('R3-05 Must-Fix #3: nested collection wrappers and pagination/non-boundary keys (next_page_token, discard_count) cannot evade collection guard', () => {
  const cases: Array<{ label: string; json: unknown }> = [
    {
      label: 'nested wrapper { data: { payouts: [...] } }',
      json: { data: { payouts: [{ id: 'p1', tenant: 'org_a', amount: 100 }] } },
    },
    {
      label: 'deeply nested wrapper with pagination token and discard_count',
      json: {
        meta: { next_page_token: 'cursor-xyz', pageToken: 'p2', discard_count: 3 },
        result: { page: { items: [{ id: 'i1', tenant: 'org_a' }] } },
      },
    },
  ]
  for (const tc of cases) {
    const res = verifyWithFactLog(
      singleHopReceipt('broken_access_control', 'GET', '/v1/payouts', 'ex-wrap-200', 'ex-wrap-403'),
      [
        makeEntry('ex-wrap-403', { arm: 'control', method: 'GET', pathAndQuery: '/v1/payouts', status: 403, timestampMs: 1000 }),
        makeEntry('ex-wrap-200', { arm: 'probe', method: 'GET', pathAndQuery: '/v1/payouts', status: 200, timestampMs: 1100, json: tc.json }),
      ],
    )
    assert.equal(res.confirmed, false, `${tc.label} must fail closed`)
    assert.equal(res.rejectedBy, 'terminal_impact_unproven')
  }
})

test('R3-05 Must-Fix #4: marker-less own-org POST /v1/orders (no tenant field in 200 body) fails closed', () => {
  for (const cls of ['broken_access_control', 'business_logic', 'authz_bypass', 'bfla']) {
    const res = verifyWithFactLog(
      singleHopReceipt(cls, 'POST', '/v1/orders', 'ex-nomark-201', 'ex-nomark-403'),
      [
        makeEntry('ex-nomark-403', { arm: 'control', method: 'POST', pathAndQuery: '/v1/orders', status: 403, timestampMs: 1000 }),
        makeEntry('ex-nomark-201', { arm: 'probe', method: 'POST', pathAndQuery: '/v1/orders', status: 201, timestampMs: 1100, json: { id: 'ord-99', totalCents: 1500, status: 'created' } }),
      ],
    )
    assert.equal(res.confirmed, false, `marker-less POST /v1/orders under ${cls} must fail closed`)
    assert.equal(res.rejectedBy, 'terminal_impact_unproven')
  }
})
