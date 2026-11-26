/**
 * M2 White-Box Composite-Proof & SDK Systemic Fixes Regression Suite.
 *
 * Covers the 4 generic, mechanism-level fixes:
 *  1. `dual_tenant_abac` host-transcript + persona-registry actor auto-hydration (with alias keys
 *     like `actorIdentity`/`actorUserId`), anti-spoof rejection, and free-form `oracleInput`
 *     fallthrough to `multiHopDualDag` when `terminalImpact.oracleFamily` is omitted.
 *  2. `composite-autodag` strictly chronological `value_binding` edge inference from host-signed
 *     `observedValueDigests` and high-entropy structured tokens (rejecting unrelated/trivial/echoed/
 *     reversed/cyclic hops).
 *  3. First-class `ch.raceBurst(hopId, opts)` inside `ctx.chain` calling host `race.burst`, stamping
 *     genuine host-signed `raceBatchId`, and auto-hydrating `economic_conservation`.
 *  4. Actionable SDK diagnostics for `capability.seal` (`status=...`, bounded redacted `topKeys=[...]`,
 *     never raw secrets), `dual_tenant_abac: missing_denied_control_on_terminal_route`, and
 *     `composite_schema` failures.
 */
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { join } from 'node:path'
import test from 'node:test'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import { augmentCompositeReceiptWithAutoDag } from '../src/server/composite-autodag.ts'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { resetRunCustodyBudgets } from '../src/server/derived-custody.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import { hydrateV8OracleInput, type HydratableTranscriptIndex } from '../src/server/v8-oracle-hydrate.ts'
import {
  VERIFY_NONCE_ENV,
  VERIFY_RPC_CONTEXT_ENV,
  VERIFY_RPC_SOCKET_ENV,
  VERIFY_RPC_TOKEN_ENV,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { VerifyContext } from '../worker/kovo_verify/kovo_verify.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'm2-wb-composite-fix-test-signing-key-0123456789abcdef'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null },
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
    origin: extra.origin ?? ORIGIN,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    actorRoleLabel: extra.actorRoleLabel !== undefined ? extra.actorRoleLabel : 'member (org_a)',
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

function makePersona(handle: string, roleLabel: string, secret: string, origin: string): ResolvedPersona {
  return {
    id: handle,
    handle,
    roleLabel,
    originAllowlist: [origin],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret,
    canaryMarkers: [],
    session: { headerType: 'bearer', value: secret, adapterUsed: 'static' },
  }
}

function makeGrant(origin: string, personas: ResolvedPersona[] = [], secrets: Array<{ value: string; placeholder: string }> = []): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(personas.map(p => [p.handle, p])),
    secrets,
  }
}

async function withSdkContext<T>(rpc: VerifyRpcServer, fn: (ctx: VerifyContext) => Promise<T>): Promise<T> {
  const prev = {
    sock: process.env[VERIFY_RPC_SOCKET_ENV],
    tok: process.env[VERIFY_RPC_TOKEN_ENV],
    ctx: process.env[VERIFY_RPC_CONTEXT_ENV],
    nonce: process.env[VERIFY_NONCE_ENV],
  }
  process.env[VERIFY_RPC_SOCKET_ENV] = rpc.socketPath
  process.env[VERIFY_RPC_TOKEN_ENV] = join(rpc.hostDir, 'token')
  process.env[VERIFY_RPC_CONTEXT_ENV] = join(rpc.hostDir, 'context.json')
  process.env[VERIFY_NONCE_ENV] = rpc.nonce
  try {
    return await fn(new VerifyContext())
  } finally {
    if (prev.sock === undefined) delete process.env[VERIFY_RPC_SOCKET_ENV]; else process.env[VERIFY_RPC_SOCKET_ENV] = prev.sock
    if (prev.tok === undefined) delete process.env[VERIFY_RPC_TOKEN_ENV]; else process.env[VERIFY_RPC_TOKEN_ENV] = prev.tok
    if (prev.ctx === undefined) delete process.env[VERIFY_RPC_CONTEXT_ENV]; else process.env[VERIFY_RPC_CONTEXT_ENV] = prev.ctx
    if (prev.nonce === undefined) delete process.env[VERIFY_NONCE_ENV]; else process.env[VERIFY_NONCE_ENV] = prev.nonce
  }
}

// ============================================================================
// 1. dual_tenant_abac actor auto-hydration + anti-spoof + free-form fallback
// ============================================================================

test('Fix 1: dual_tenant_abac auto-hydrates actor from host transcript & persona registry, ignores spoofed roles, and falls through on free-form oracleInput', () => {
  const dualActor = { handle: 'dual_member', role: 'admin' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const roleLabel = 'admin (org_a), viewer (org_b)'
  const sessionCap = 'cap:hop_1:session_tok'

  const loginEx = signedEntry('dt-login', makeStep({
    id: 'dt-login', arm: 'setup', method: 'POST', status: 200, pathAndQuery: '/api/v1/login',
    actor: dualActor, json: { token: 'session-tok-99887766' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: roleLabel, emittedCapabilities: [sessionCap] })

  const ctrl = signedEntry('dt-ctrl', makeStep({
    id: 'dt-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/reports/export',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050, actorPersona: 'dual_member', actorRoleLabel: roleLabel })

  const prime = signedEntry('dt-prime', makeStep({
    id: 'dt-prime', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/permissions/prime',
    actor: dualActor, json: { primed: true, tenantId: 'org_a', primeRef: 'prm_8f7e6d5c4b3a' },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: roleLabel })

  const bled = signedEntry('dt-bled', makeStep({
    id: 'dt-bled', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/reports/export',
    requestHeaders: { 'x-prime-ref': 'prm_8f7e6d5c4b3a' },
    actor: { handle: sessionCap, role: null, tenant: null, auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_b', rows: [{ id: 'r-99', total: 985000 }] },
  }), { seq: 4, timestampMs: 1200, actorPersona: sessionCap, actorRoleLabel: null, consumedCapabilities: [sessionCap] })

  const idx: HydratableTranscriptIndex = {
    entriesById: new Map([loginEx, ctrl, prime, bled].map(e => [e.exchangeId, e])),
    personaRoleLabels: { dual_member: roleLabel },
  }

  // (a) Omitted actor + cap-based terminal exchange -> derives dual_member + host rolesByTenant
  const hydOmitted = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'dual_org_cache_bleed',
    baselineDeniedControl: 'dt-ctrl',
    primeAction: 'dt-prime',
    bledAccess: 'dt-bled',
  }, idx, 'sig')
  assert.deepEqual(hydOmitted.actor, { actorId: 'dual_member', rolesByTenant: { org_a: 'admin', org_b: 'viewer' } })

  // (b) Alias key `actorIdentity: { persona: 'dual_member', rolesByTenant: { org_b: 'viewer', org_a: 'viewer' } }`
  //     -> accepts alias ID, IGNORES worker-claimed roles, populates host-verified roles!
  const hydAlias = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'dual_org_cache_bleed',
    actorIdentity: { persona: 'dual_member', rolesByTenant: { org_a: 'viewer', org_b: 'viewer' } },
    baselineDeniedControl: 'dt-ctrl',
    primeAction: 'dt-prime',
    bledAccess: 'dt-bled',
  }, idx, 'sig')
  assert.deepEqual(hydAlias.actor, { actorId: 'dual_member', rolesByTenant: { org_a: 'admin', org_b: 'viewer' } })

  // (c) Spoofed actor identity NOT in cited exchanges -> fails closed (actor omitted -> missing_actor_identity)
  const hydSpoof = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'dual_org_cache_bleed',
    actorUserId: 'some_other_actor',
    baselineDeniedControl: 'dt-ctrl',
    primeAction: 'dt-prime',
    bledAccess: 'dt-bled',
  }, idx, 'sig')
  assert.equal(hydSpoof.actor, undefined, 'spoofed actorUserId not in cited exchanges must fail closed')

  // (d) Privileged-in-target persona trying to spoof low-priv roles via `actorIdentity` MUST still be rejected!
  const dualAdminBoth = { handle: 'dual_admin', role: 'admin' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const bothLabel = 'admin (org_a), admin (org_b)'
  const ctrlBoth = signedEntry('dt-b-ctrl', makeStep({ id: 'dt-b-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/reports/export', actor: dualAdminBoth, json: { error: 'forbidden' } }), { seq: 1, timestampMs: 1000, actorPersona: 'dual_admin', actorRoleLabel: bothLabel })
  const primeBoth = signedEntry('dt-b-prime', makeStep({ id: 'dt-b-prime', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/permissions/prime', actor: dualAdminBoth, json: { primed: true } }), { seq: 2, timestampMs: 1100, actorPersona: 'dual_admin', actorRoleLabel: bothLabel })
  const bledBoth = signedEntry('dt-b-bled', makeStep({ id: 'dt-b-bled', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/reports/export', actor: dualAdminBoth, json: { tenantId: 'org_b', rows: [{ id: 'r1', amount: 100 }] } }), { seq: 3, timestampMs: 1200, actorPersona: 'dual_admin', actorRoleLabel: bothLabel })
  const spoofRoleRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrlBoth, primeBoth, bledBoth] }),
    {
      kind: 'v8_family',
      family: 'dual_tenant_abac',
      rawInput: {
        mode: 'dual_org_cache_bleed',
        actorIdentity: { persona: 'dual_admin', rolesByTenant: { org_a: 'admin', org_b: 'viewer' } },
        baselineDeniedControl: 'dt-b-ctrl',
        primeAction: 'dt-b-prime',
        bledAccess: 'dt-b-bled',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(spoofRoleRes.confirmed, false)
  assert.equal(spoofRoleRes.reason, 'actor_authorized_in_target_tenant')

  // (e) Free-form `oracleInput` without `mode` and WITHOUT explicit `oracleFamily` cleanly falls through
  //     to `multiHopDualDag` and confirms a valid 2-hop cross-tenant chain!
  const transcript: HostSignedTranscript = { entries: [loginEx, ctrl, prime, bled] }
  const freeFormReceipt: CompositeProofReceipt = {
    chainId: 'fix1-freeform-dual',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/permissions/prime' }, exchangeIds: ['dt-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed permission cache in org_a', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/reports/export' }, exchangeIds: ['dt-bled'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read org_b report data', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'dt-bled',
      summary: 'Cross-tenant export bleed confirmed via multi-hop chain.',
      claimedImpact: 'Cross-tenant export bleed confirmed via multi-hop chain.',
      preChainControlExchangeIds: ['dt-ctrl'],
      postChainReadbackExchangeIds: [],
      oracleInput: { foreignTenant: 'org_b', actorTenant: 'org_a', actorIdentity: { persona: 'dual_member' } },
    },
    replayMode: 'fresh_clean_replay',
  }
  const okFreeForm = verifyCompositeReceipt(freeFormReceipt, transcript, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['dual_member'],
    personaRoleLabels: { dual_member: roleLabel },
  })
  assert.equal(okFreeForm.confirmed, true, `Expected free-form dual_tenant_abac fallback to confirm, got: ${okFreeForm.reason}`)

  // (f) Explicit `oracleFamily: 'dual_tenant_abac'` with missing `mode` MUST STILL fail closed!
  const explicitMissingMode: CompositeProofReceipt = {
    ...freeFormReceipt,
    terminalImpact: { ...freeFormReceipt.terminalImpact, oracleFamily: 'dual_tenant_abac' },
  }
  const failExplicit = verifyCompositeReceipt(explicitMissingMode, transcript, {
    signingKey: SIGNING_KEY,
    attackerPersonas: ['dual_member'],
    personaRoleLabels: { dual_member: roleLabel },
  })
  assert.equal(failExplicit.confirmed, false, 'explicit oracleFamily without mode must still fail closed')
  assert.equal(failExplicit.failedStage, 'terminal_impact')
})

// ============================================================================
// 2. composite-autodag chronological value_binding inference from observedValueDigests
// ============================================================================

test('Fix 2: composite-autodag infers chronological value_binding edges from host-signed digests and rejects unrelated/trivial/echoed/reversed hops', () => {
  const ctrl = signedEntry('ad-ctrl', makeStep({
    id: 'ad-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/downloads/dl_9f8e7d6c5b4a',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })

  // 3-hop chain WITHOUT any `seal_capability` / `cap:` handles — connected solely via host-signed response->request IDs & URLs!
  const h1 = signedEntry('ad-h1', makeStep({
    id: 'ad-h1', arm: 'probe', method: 'POST', status: 201, pathAndQuery: '/api/v1/exports',
    requestJson: { scope: 'summary', clientTag: 'echoed_tag_123456' },
    json: { exportId: 'exp_8a7b6c5d4e3f', clientTag: 'echoed_tag_123456', status: 'queued' },
  }), { seq: 2, timestampMs: 1000 })

  const h2 = signedEntry('ad-h2', makeStep({
    id: 'ad-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/exp_8a7b6c5d4e3f',
    json: { status: 'ready', downloadUrl: '/api/v1/downloads/dl_9f8e7d6c5b4a?sig=a1b2c3d4e5f6' },
  }), { seq: 3, timestampMs: 1100 })

  const h3 = signedEntry('ad-h3', makeStep({
    id: 'ad-h3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/downloads/dl_9f8e7d6c5b4a?sig=a1b2c3d4e5f6',
    json: { tenantId: 'org_b', rows: [{ id: 'sec-1', balance: 50000 }] },
  }), { seq: 4, timestampMs: 1200 })

  const receipt3Hop: CompositeProofReceipt = {
    chainId: 'fix2-digest-autodag',
    terminalVulnClass: 'cross_tenant_exfiltration',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/exports' }, exchangeIds: ['ad-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created export job', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/exp_8a7b6c5d4e3f' }, exchangeIds: ['ad-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Polled export download URL', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_3', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/downloads/dl_9f8e7d6c5b4a?sig=a1b2c3d4e5f6' }, exchangeIds: ['ad-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Downloaded foreign tenant export', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_3',
      terminalExchangeId: 'ad-h3',
      summary: 'Multi-hop export chain confirmed via host-signed digest auto-DAG.',
      claimedImpact: 'Multi-hop export chain confirmed via host-signed digest auto-DAG.',
      preChainControlExchangeIds: ['ad-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  const resOk = verifyCompositeReceipt(receipt3Hop, { entries: [ctrl, h1, h2, h3] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(resOk.confirmed, true, `Expected digest-inferred 3-hop chain to confirm, got: ${resOk.reason}`)
  assert.equal(resOk.verifiedEdges.length, 2)
  assert.equal(resOk.evidence?.autoInferredEdgeCount, 2)

  // Negative A: Unrelated hops sharing only trivial/low-entropy values or static routes -> 0 edges!
  const triv1 = signedEntry('triv-1', makeStep({
    id: 'triv-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/users/profile',
    json: { status: 'completed', ok: true, tenant: 'org_a', endpoint: '/api/v1/users/profile', createdAt: '2026-11-26T00:00:00Z' },
  }), { seq: 1, timestampMs: 1000 })
  const triv2 = signedEntry('triv-2', makeStep({
    id: 'triv-2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/users/profile',
    requestJson: { status: 'completed', ok: true, tenant: 'org_a', createdAt: '2026-11-26T00:00:00Z' },
    json: { tenantId: 'org_b', secret: 'val' },
  }), { seq: 2, timestampMs: 1100 })
  const trivOut = augmentCompositeReceiptWithAutoDag({
    ...receipt3Hop,
    hops: [
      { ...receipt3Hop.hops[0]!, hopId: 'hop_1', exchangeIds: ['triv-1'] },
      { ...receipt3Hop.hops[1]!, hopId: 'hop_2', exchangeIds: ['triv-2'] },
    ],
    terminalImpact: { ...receipt3Hop.terminalImpact, terminalHopId: 'hop_2', terminalExchangeId: 'triv-2' },
  }, HostFactLog.fromTranscript({ entries: [triv1, triv2] }))
  assert.equal(trivOut.inferredEdges.length, 0, 'trivial/static/date values must never fabricate edges')

  // Negative B: Echoed request token (already sent in Hop 1's own request) -> 0 edges!
  const echo2 = signedEntry('echo-2', makeStep({
    id: 'echo-2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/items/echoed_tag_123456',
    json: { tenantId: 'org_b', rows: [{ id: '1', amount: 10 }] },
  }), { seq: 5, timestampMs: 1300 })
  const echoOut = augmentCompositeReceiptWithAutoDag({
    ...receipt3Hop,
    hops: [
      { ...receipt3Hop.hops[0]!, hopId: 'hop_1', exchangeIds: ['ad-h1'] },
      { ...receipt3Hop.hops[1]!, hopId: 'hop_2', exchangeIds: ['echo-2'] },
    ],
    terminalImpact: { ...receipt3Hop.terminalImpact, terminalHopId: 'hop_2', terminalExchangeId: 'echo-2' },
  }, HostFactLog.fromTranscript({ entries: [h1, echo2] }))
  assert.equal(echoOut.inferredEdges.length, 0, 'client-chosen value echoed by Hop 1 must not fabricate a value_binding edge')

  // Negative C: Reverse chronological timestamps (`h1.ts > h2.ts`) -> 0 edges!
  const rev1 = signedEntry('rev-1', h1.step, { seq: 10, timestampMs: 2000 })
  const rev2 = signedEntry('rev-2', h2.step, { seq: 9, timestampMs: 1500 })
  const revOut = augmentCompositeReceiptWithAutoDag({
    ...receipt3Hop,
    hops: [
      { ...receipt3Hop.hops[0]!, hopId: 'hop_1', exchangeIds: ['rev-1'] },
      { ...receipt3Hop.hops[1]!, hopId: 'hop_2', exchangeIds: ['rev-2'] },
    ],
    terminalImpact: { ...receipt3Hop.terminalImpact, terminalHopId: 'hop_2', terminalExchangeId: 'rev-2' },
  }, HostFactLog.fromTranscript({ entries: [rev1, rev2] }))
  assert.equal(revOut.inferredEdges.length, 0, 'reversed timestamps must never infer edges')

  // Positive D: Explicit host-signed `observedResponseDigests` -> `injectedRequestDigests`
  const customDig = sha256Hex('host-opaque-secret-token-445566')
  const d1 = signedEntry('dig-1', makeStep({ id: 'dig-1', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/step1', json: { ok: true } }), { seq: 1, timestampMs: 1000, observedResponseDigests: [customDig] })
  const d2 = signedEntry('dig-2', makeStep({ id: 'dig-2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/step2', json: { done: true } }), { seq: 2, timestampMs: 1100, injectedRequestDigests: [customDig] })
  const digOut = augmentCompositeReceiptWithAutoDag({
    ...receipt3Hop,
    hops: [
      { ...receipt3Hop.hops[0]!, hopId: 'hop_1', exchangeIds: ['dig-1'] },
      { ...receipt3Hop.hops[1]!, hopId: 'hop_2', exchangeIds: ['dig-2'] },
    ],
    terminalImpact: { ...receipt3Hop.terminalImpact, terminalHopId: 'hop_2', terminalExchangeId: 'dig-2' },
  }, HostFactLog.fromTranscript({ entries: [d1, d2] }))
  assert.equal(digOut.inferredEdges.length, 1)
  assert.equal(digOut.inferredEdges[0]!.kind, 'value_binding')
  assert.equal((digOut.inferredEdges[0]! as { valueDigest?: string }).valueDigest, customDig)
})

// ============================================================================
// 3. First-class ch.raceBurst(...) + real host raceBatchId + economic_conservation
// ============================================================================

test('Fix 3: ch.raceBurst stamps real host raceBatchId, auto-hydrates economic_conservation, confirms vulnerable burst, and rejects hardened twin', async (t) => {
  const runId = 'run-fix3-raceburst'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  let hardened = false
  let orderSeq = 0
  const orders = new Map<string, { paidAmount: number; refundedTotal: number; lock: boolean }>()

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(c as Buffer))
    req.on('end', () => {
      if (req.method === 'POST' && url.pathname === '/api/v1/orders') {
        orderSeq += 1
        const id = `ord_race_${String(orderSeq).padStart(4, '0')}_aa`
        orders.set(id, { paidAmount: 100, refundedTotal: 0, lock: false })
        res.writeHead(201, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ orderId: id, paidAmount: 100, refundedTotal: 0 }))
        return
      }
      const getM = /^\/api\/v1\/orders\/([^/]+)$/.exec(url.pathname)
      if (req.method === 'GET' && getM) {
        const ord = orders.get(getM[1]!)
        if (!ord) { res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' })); return }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ orderId: getM[1], paidAmount: ord.paidAmount, refundedTotal: ord.refundedTotal }))
        return
      }
      const refM = /^\/api\/v1\/orders\/([^/]+)\/refund$/.exec(url.pathname)
      if (req.method === 'POST' && refM) {
        const ord = orders.get(refM[1]!)
        if (!ord) { res.writeHead(404); res.end(JSON.stringify({ error: 'not_found' })); return }
        if (hardened && ord.refundedTotal >= ord.paidAmount) {
          res.writeHead(409, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: 'already_refunded' }))
          return
        }
        // Vulnerable twin allows concurrent/repeated refunds beyond paidAmount; hardened twin enforces conservation.
        if (hardened) {
          ord.refundedTotal = Math.min(ord.paidAmount, ord.refundedTotal + 100)
        } else {
          ord.refundedTotal += 100
        }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ orderId: refM[1], refundedAmount: 100, refundedTotal: ord.refundedTotal }))
        return
      }
      res.writeHead(404); res.end('not found')
    })
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const persona = makePersona('member_a', 'member (org_a)', 'secret_member_a_998877', origin)
  const runCase = async (isHardened: boolean) => {
    hardened = isHardened
    const rpc = new VerifyRpcServer({
      broker: new RequestBroker(),
      grant: makeGrant(origin, [persona]),
      runId,
      assignmentId: isHardened ? 'a-hardened' : 'a-vuln',
      targetOrigins: [origin],
    })
    await rpc.start()
    t.after(() => rpc.close())

    return await withSdkContext(rpc, async (ctx) => {
      const ch = ctx.chain(`race-over-refund-${isHardened ? 'hard' : 'vuln'}`, 'economic_conservation')
      const h1 = await ch.hop('hop_1', { claimedDelta: 'Created refundable order' }, () =>
        ctx.http_send('/api/v1/orders', { as: 'member_a', method: 'POST', body: { amount: 100 } }),
      )
      const orderId = (h1.json as { orderId: string }).orderId
      const burst = await ch.raceBurst('hop_2', {
        claimedDelta: 'Executed concurrent refund burst',
        readRoute: `/api/v1/orders/${orderId}`,
        readPersona: 'member_a',
        request: { path: `/api/v1/orders/${orderId}/refund`, method: 'POST', as: 'member_a', body: { amount: 100 } },
        count: 3,
      })
      assert.ok(burst.raceBatchId.startsWith('race_'), `expected host raceBatchId, got ${burst.raceBatchId}`)
      assert.equal(burst.results.length, 3)
      for (const r of burst.results) assert.equal(r.raceBatchId, burst.raceBatchId)

      // Verify host-signed transcript stamped identical raceBatchId on every burst exchange
      const signed = rpc.buildHostSignedTranscript()
      const burstEntries = (signed.entries ?? []).filter(e => burst.results.some(r => r.exchangeId === e.exchangeId))
      assert.equal(burstEntries.length, 3)
      assert.equal(new Set(burstEntries.map(e => e.raceBatchId)).size, 1)
      assert.equal(burstEntries[0]!.raceBatchId, burst.raceBatchId)

      const verdict = await ch.prove({
        claimedImpact: 'Concurrent refund burst exceeded paidAmount on order ledger.',
        oracleFamily: 'economic_conservation',
        oracleInput: { equation: 'over_refund' },
      })
      return { verdict, latest: rpc.transcript.latestCompositeVerification() }
    })
  }

  const vuln = await runCase(false)
  assert.equal(vuln.verdict.confirmed, true, `Vulnerable race burst must confirm, got: ${JSON.stringify(vuln.latest)}`)
  assert.ok((vuln.latest?.verifiedEdgeCount ?? 0) >= 1, 'Auto-DAG must link hop_1 -> hop_2 via host-signed orderId digest')

  const hard = await runCase(true)
  assert.equal(hard.verdict.confirmed, false, 'Hardened twin enforcing refund conservation must NOT confirm')
})

// ============================================================================
// 4. Actionable SDK Diagnostics (capability.seal topKeys, dual_tenant_abac, schema)
// ============================================================================

test('Fix 4: capability.seal reports bounded redacted status + topKeys without leaking secrets; dual_tenant_abac and schema errors echo route context', async (t) => {
  const runId = 'run-fix4-diagnostics'
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const RAW_SECRET = 'super_secret_token_value_99887766'
  const target = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({
      id: 'item_01',
      access_token: RAW_SECRET,
      expiresIn: 3600,
      extra1: 'a', extra2: 'b', extra3: 'c', extra4: 'd', extra5: 'e',
      extra6: 'f', extra7: 'g', extra8: 'h', extra9: 'i', extra10: 'j', extra11: 'k',
    }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => target.close(() => r())))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker(),
    grant: makeGrant(origin, [], [{ value: RAW_SECRET, placeholder: '[redacted:tok]' }]),
    runId,
    assignmentId: 'a-diag',
    targetOrigins: [origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  // 4a. SDK `ctx.seal_capability` miss includes `status=200, topKeys=[...]` bounded to 12 keys + '...' and NEVER raw secrets
  await withSdkContext(rpc, async (ctx) => {
    const ex = await ctx.http_send('/api/v1/token', { method: 'POST' })
    let errMsg = ''
    try {
      await ctx.seal_capability({ exchangeId: ex.exchangeId, slot: 'tok', jsonPath: '$.wrongField' })
    } catch (err) {
      errMsg = err instanceof Error ? err.message : String(err)
    }
    assert.match(errMsg, /structured field not found/i)
    assert.match(errMsg, /status=200/)
    assert.match(errMsg, /topKeys=\[id, access_token, expiresIn/)
    assert.match(errMsg, /\.\.\.\]/)
    assert.equal(errMsg.includes(RAW_SECRET), false, 'raw secret value must NEVER appear in seal diagnostic')
  })

  // 4b. `dual_tenant_abac: missing_denied_control_on_terminal_route` includes expected terminal route vs received control route/status
  const wrongCtrl = signedEntry('diag-ctrl', makeStep({
    id: 'diag-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/other/route',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 1000 })
  const h1 = signedEntry('diag-h1', makeStep({
    id: 'diag-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/jobs',
    json: { jobId: 'job_99887766aa' },
  }), { seq: 2, timestampMs: 1100 })
  const h2 = signedEntry('diag-h2', makeStep({
    id: 'diag-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/job_99887766aa',
    json: { tenantId: 'org_b', rows: [{ id: 'r1', balance: 400 }] },
  }), { seq: 3, timestampMs: 1200 })

  const ctrlMiss = verifyCompositeReceipt({
    chainId: 'fix4-ctrl-diag',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/jobs' }, exchangeIds: ['diag-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created export job', producedCapabilities: [], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/job_99887766aa' }, exchangeIds: ['diag-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Fetched foreign export', producedCapabilities: [], consumedCapabilities: [] },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'diag-h2',
      summary: 'Attempted dual-tenant confirmation with mismatched control route.',
      claimedImpact: 'Attempted dual-tenant confirmation with mismatched control route.',
      preChainControlExchangeIds: ['diag-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [wrongCtrl, h1, h2] }, { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] })

  assert.equal(ctrlMiss.confirmed, false)
  assert.match(ctrlMiss.reason, /missing_denied_control_on_terminal_route/)
  assert.match(ctrlMiss.reason, /expected=GET \/api\/v1\/exports\/:id/)
  assert.match(ctrlMiss.reason, /received=\[GET \/api\/v1\/other\/route \(403\)\]/)

  // 4c. `composite_schema` failure includes schema issue path + terminal route context
  const schemaFail = verifyCompositeReceipt({
    chainId: '',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [{ hopId: 'hop_1', target: { origin: ORIGIN, pathAndQuery: '/api/v1/exports/12345' }, claimedDelta: 'x' }],
    terminalImpact: { terminalHopId: 'hop_1' },
  }, { entries: [] })
  assert.equal(schemaFail.confirmed, false)
  assert.equal(schemaFail.failedStage, 'schema')
  assert.match(schemaFail.reason, /Schema validation failed:/)
  assert.match(schemaFail.reason, /terminalRoute=\/api\/v1\/exports\/:id/)
})
