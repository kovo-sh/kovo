// @kernel @fixes A2
/**
 * Track A2 — 5 Universal Tier-1 Deterministic Evidence Primitives (strictly 0-LLM).
 *
 * Pure behavioral suite (no source-text reads) covering:
 *  1. `resolveUniversalPrimitive()` for every legacy family / sub-mode / equation, canonical vuln classes,
 *     and the 5 primitive names (host resolver and the zero-dependency SDK mirror agree).
 *  2. All 5 primitives: TP confirmation + fail-closed FP rejection, incl. explicit JSONPath `$Q`
 *     conservation, non-fintech seat-quota conservation, victim cache digest WITHOUT `X-Cache: HIT`,
 *     own-tenant / masked-read rejection, and sequential legitimate wallet deposits rejection.
 *  3. Own-scope access invariants (self-minted session credentials, chain-induced boundary flips).
 *  4. SDK universal helpers and absence of positional hop mis-wiring (`synthOracleInput` removed).
 *  5. Track A1 follow-ups: (a) 5xx exemption scoped to cited exchanges, (b) no default
 *     `fresh_clean_replay` stamp on parse-failed verdicts, (c) `mac_address` is not a signature carrier.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import '../src/server/terminal-oracle-registry.ts'
import { RequestBroker } from '../src/server/broker.ts'
import { UNIVERSAL_EVIDENCE_PRIMITIVES as RE_EXPORTED_PRIMITIVES, resolveTranscriptReplayMode } from '../src/server/composite-receipt.ts'
import {
  UNIVERSAL_EVIDENCE_PRIMITIVES,
  evaluateEconomicConservation,
  evaluateJsonPathNumber,
  evaluateOwnScopeTerminalGuard,
  evaluateParserCacheDifferential,
  evaluateSignatureProvenanceGuard,
  evaluateUniversalPrimitive,
  evaluateV8OracleFamily,
  hasSignatureCarrier,
  isSignatureCarrierKey,
  resolveUniversalPrimitive,
  type HostSignedRecord,
  type OwnScopeGuardParams,
} from '../src/server/v8-oracle-families.ts'
import { hydrateV8OracleInput, type HydratableEntry } from '../src/server/v8-oracle-hydrate.ts'
import { evaluateOwnOrgTerminalGuard, hydrateBalanceMintingOperands } from '../src/server/own-org-terminal-guard.ts'
import { TranscriptStore } from '../src/server/verify-claims.ts'
import { findUnhandledServerError5xx } from '../src/server/verify-runner.ts'
import { VerifyRpcServer, VERIFY_NONCE_HEADER, VERIFY_RPC_HEADER } from '../src/server/verify-rpc.ts'
import * as sdk from '../worker/kovo_verify/kovo_verify.ts'
import { makeLabGrant } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'
const SIG = 'host-sig-0123456789abcdef'
const rec = (id: string, ts: number, o: Partial<HostSignedRecord> = {}): HostSignedRecord => ({ id, hostSignature: SIG, timestampMs: ts, status: 200, method: 'GET', route: '/v1/resource', actorId: 'member_a', ...o })
const entry = (id: string, seq: number, step: Partial<HydratableEntry['step']> & { method: string; pathAndQuery: string }, extra: Partial<HydratableEntry> = {}): HydratableEntry => ({
  exchangeId: id, seq, timestampMs: 1000 + seq * 100, actorPersona: 'member_a', hostSignature: SIG,
  step: { arm: 'probe', status: 200, actor: { handle: 'member_a', role: 'member', tenant: 'org_a' }, route: step.pathAndQuery.split('?')[0], ...step },
  ...extra,
})
const index = (...es: HydratableEntry[]) => ({ entriesById: new Map(es.map(e => [e.exchangeId, e])) })

/* ── 1. resolveUniversalPrimitive ─────────────────────────────────────────── */

const EXPECTED_PRIMITIVE: Readonly<Record<string, string>> = {
  causal_dag: 'causal_dag', access_differential: 'access_differential', state_delta_and_conservation: 'state_delta_and_conservation',
  wire_framing_and_cache_differential: 'wire_framing_and_cache_differential', oob_and_execution_witness: 'oob_and_execution_witness',
  // legacy families
  dual_tenant_abac: 'access_differential', temporal_revocation: 'access_differential', cryptographic_scope_replay: 'access_differential',
  economic_conservation: 'state_delta_and_conservation', parser_cache_differential: 'wire_framing_and_cache_differential', cross_surface_pivot: 'causal_dag',
  // legacy sub-modes / equations
  cross_org_transfer: 'access_differential', batch_partial_authz: 'access_differential', dual_org_cache_bleed: 'wire_framing_and_cache_differential',
  cache_primed: 'wire_framing_and_cache_differential', parser_differential: 'wire_framing_and_cache_differential', over_refund: 'state_delta_and_conservation',
  balance_minting: 'state_delta_and_conservation', underpaid_fulfillment: 'state_delta_and_conservation', ineligible_discount: 'state_delta_and_conservation',
  quantity_conservation: 'state_delta_and_conservation',
  // canonical vuln classes
  bola: 'access_differential', bfla: 'access_differential', broken_access_control: 'access_differential', cross_tenant_read: 'access_differential',
  privilege_escalation: 'access_differential', auth_bypass: 'access_differential', race_condition: 'state_delta_and_conservation',
  workflow_bypass: 'state_delta_and_conservation', business_logic: 'state_delta_and_conservation', mass_assignment: 'state_delta_and_conservation',
  cache_poisoning: 'wire_framing_and_cache_differential', request_smuggling: 'wire_framing_and_cache_differential',
  ssrf: 'oob_and_execution_witness', xss: 'oob_and_execution_witness', xxe: 'oob_and_execution_witness', ssti: 'oob_and_execution_witness',
  sqli: 'oob_and_execution_witness', rce: 'oob_and_execution_witness', webhook_forgery: 'causal_dag',
}

test('resolveUniversalPrimitive maps every legacy family, sub-mode, equation, canonical class, and primitive', () => {
  assert.deepEqual([...UNIVERSAL_EVIDENCE_PRIMITIVES], ['causal_dag', 'access_differential', 'state_delta_and_conservation', 'wire_framing_and_cache_differential', 'oob_and_execution_witness'])
  assert.deepEqual([...RE_EXPORTED_PRIMITIVES], [...UNIVERSAL_EVIDENCE_PRIMITIVES])
  for (const [label, primitive] of Object.entries(EXPECTED_PRIMITIVE)) assert.equal(resolveUniversalPrimitive(label), primitive, label)
  // Normalization + fail-safe fallback (never a weaker primitive, never prototype keys)
  assert.equal(resolveUniversalPrimitive('  Broken-Access Control '), 'access_differential')
  for (const odd of ['', 'totally_novel_policy_class', 'constructor', '__proto__', 'toString']) assert.equal(resolveUniversalPrimitive(odd), 'causal_dag', odd)
})

test('SDK resolveUniversalPrimitive mirror agrees with the host resolver; decisions carry their primitive', () => {
  assert.deepEqual([...sdk.UNIVERSAL_EVIDENCE_PRIMITIVES], [...UNIVERSAL_EVIDENCE_PRIMITIVES])
  for (const label of [...Object.keys(EXPECTED_PRIMITIVE), 'totally_novel_policy_class']) assert.equal(sdk.resolveUniversalPrimitive(label), resolveUniversalPrimitive(label), label)
  assert.equal(evaluateV8OracleFamily('economic_conservation', { equation: 'over_refund' } as never).primitive, 'state_delta_and_conservation')
  assert.equal(evaluateV8OracleFamily('dual_tenant_abac', { mode: 'dual_org_cache_bleed', actor: { actorId: 'a', rolesByTenant: {} } } as never).primitive, 'wire_framing_and_cache_differential')
  assert.equal(evaluateV8OracleFamily('cross_surface_pivot', { hops: [] } as never).primitive, 'causal_dag')
})

/* ── 2a. causal_dag ───────────────────────────────────────────────────────── */

test('causal_dag: verified value lineage across >= 2 surfaces confirms; unbound/orphan/stub/single-surface fail closed', () => {
  const token = 'tok_lineage_8c1f2a'
  const h1 = rec('ex-1', 100, { method: 'POST', route: '/v1/share', json: { shareToken: token } })
  const h2 = rec('ex-2', 200, { route: '/v1/report', requestHeaders: { authorization: `Bearer ${token}` }, json: { report: 'quarterly revenue summary', rows: 42 } })
  const hops = [{ hopId: 'mint', surface: 'http', record: h1 }, { hopId: 'read', surface: 'browser', record: h2 }]
  const edge = { kind: 'value_binding' as const, fromHopId: 'mint', toHopId: 'read', boundValue: token }
  const okRes = evaluateUniversalPrimitive('causal_dag', { hops, edges: [edge], terminalHopId: 'read', requireCrossSurface: true })
  assert.equal(okRes.satisfied, true, okRes.reason)
  assert.equal(okRes.evidence?.crossSurface, true)
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops, edges: [{ ...edge, boundValue: 'tok_never_seen_x9' }], terminalHopId: 'read' }).reason, 'unbound_causal_edge')
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops, edges: [], terminalHopId: 'read' }).reason, 'hop_does_not_reach_terminal')
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops: hops.map(h => ({ ...h, surface: 'http' })), edges: [edge], terminalHopId: 'read', requireCrossSurface: true }).reason, 'single_surface_not_cross_surface_pivot')
  const stubbed = [hops[0]!, { ...hops[1]!, record: { ...h2, status: 202, json: { jobId: 'job_9f2c11aa', status: 'queued' } } }]
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops: stubbed, edges: [edge], terminalHopId: 'read' }).reason, 'terminal_impact_unproven_intermediate_stub')
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops: [hops[0]!, { ...hops[1]!, record: { ...h2, timestampMs: 50 } }], edges: [edge], terminalHopId: 'read' }).reason, 'non_monotonic_causal_edge')
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops: [hops[0]!], edges: [], terminalHopId: 'mint' }).reason, 'invalid_hop_count')
})

/* ── 2b. access_differential ──────────────────────────────────────────────── */

test('access_differential: denied control vs succeeding variant exposing out-of-scope data confirms; own-tenant and masked reads fail closed', () => {
  const control = rec('ctl', 100, { status: 403, json: { error: 'forbidden' } })
  const variant = rec('var', 200, { json: { tenant: 'org_b', apiSecret: 'value held by tenant b', owner: 'alice b' } })
  const okRes = evaluateUniversalPrimitive('access_differential', { control, variant, ownTenants: ['org_a'] })
  assert.equal(okRes.satisfied, true, okRes.reason)
  assert.equal(okRes.subRule, 'read')
  assert.equal(evaluateUniversalPrimitive('access_differential', { control, variant: { ...variant, json: { tenant: 'org_a', apiSecret: 'own value here' } }, ownTenants: ['org_a'] }).reason, 'own_tenant_only_response')
  assert.equal(evaluateUniversalPrimitive('access_differential', { control, variant: { ...variant, json: { ssn: '***-**-1234', cardNumber: '•••• 4242' } } }).reason, 'masked_read_without_protected_data')
  assert.equal(evaluateUniversalPrimitive('access_differential', { control: { ...control, status: 200 }, variant }).reason, 'control_not_denied')
  assert.equal(evaluateUniversalPrimitive('access_differential', { control: { ...control, status: 401, actorId: 'anonymous' }, variant }).reason, 'unauthenticated_baseline_control')
  // Persisted out-of-scope mutation via host-derived readback delta
  const readback = rec('rb', 300, { json: { item: { id: 'it_7', owner: 'org_a', note: 'moved across tenants' } } })
  const mut = evaluateUniversalPrimitive('access_differential', { control, variant: { ...variant, method: 'POST' }, readback, requireReadback: true, persistedDelta: true })
  assert.equal(mut.satisfied, true, mut.reason)
  assert.equal(mut.subRule, 'mutation')
  assert.equal(evaluateUniversalPrimitive('access_differential', { control, variant: { ...variant, method: 'POST' }, readback, requireReadback: true, persistedDelta: false }).reason, 'mutation_not_persisted')
})

/* ── 2c. state_delta_and_conservation ─────────────────────────────────────── */

test('evaluateJsonPathNumber: deterministic host-side JSONPath subset; rejects recursive descent, prototype keys, and non-numbers', () => {
  const doc = { seatsUsed: 7, quota: { 'seats-used': 3 }, items: [{ qty: 1 }, { qty: 9 }], label: 'x' }
  assert.equal(evaluateJsonPathNumber(doc, '$.seatsUsed'), 7)
  assert.equal(evaluateJsonPathNumber(doc, "$.quota['seats-used']"), 3)
  assert.equal(evaluateJsonPathNumber(doc, '$.items[1].qty'), 9)
  for (const bad of ['seatsUsed', '$..qty', '$.__proto__.polluted', '$.label', '$.missing', '$.items[*].qty', '$.seatsUsed + 1']) assert.equal(evaluateJsonPathNumber(doc, bad), undefined, bad)
})

test('state_delta_and_conservation: explicit $Q seat-quota conservation vs benign serial control; structural delta; fail-closed operands', () => {
  const base = rec('base', 100, { route: '/v1/workspace', json: { plan: 'team', seatsUsed: 5, seatLimit: 5 } })
  const actions = [1, 2, 3].map(i => rec(`inv-${i}`, 200 + i, { method: 'POST', route: '/v1/workspace/invites', json: { invited: true } }))
  const fin = rec('fin', 300, { route: '/v1/workspace', json: { plan: 'team', seatsUsed: 8, seatLimit: 5 } })
  const ok = evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions, finalReadback: fin, quantitySelector: '$.seatsUsed', controlDelta: 0 })
  assert.equal(ok.satisfied, true, ok.reason)
  assert.equal(ok.evidence?.observedDelta, 3)
  assert.equal(evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions, finalReadback: fin, quantitySelector: '$.seatsUsed', controlDelta: 3 }).reason, 'quantity_conserved')
  assert.equal(evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions, finalReadback: fin, quantitySelector: '$.seatsUsed' }).reason, 'missing_authorized_delta_or_benign_control')
  assert.equal(evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions, finalReadback: fin, quantitySelector: '$.seats', controlDelta: 0 }).reason, 'missing_conservation_quantity')
  assert.equal(evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions: [], finalReadback: fin, quantitySelector: '$.seatsUsed', controlDelta: 0 }).reason, 'missing_action_records')
  assert.equal(evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions: actions.map(a => ({ ...a, method: 'GET' })), finalReadback: fin, quantitySelector: '$.seatsUsed', controlDelta: 0 }).reason, 'action_not_mutating')
  // Generic `before !== after` structural diff (volatile clock keys ignored)
  assert.equal(evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions, finalReadback: fin, structuralOnly: true }).satisfied, true)
  const sameState = { ...fin, json: { ...(base.json as object), updatedAt: '2026-11-28T10:00:00Z' } }
  assert.equal(evaluateUniversalPrimitive('state_delta_and_conservation', { baselineReadback: base, actions, finalReadback: sameState, structuralOnly: true }).reason, 'zero_state_delta')
})

test('state_delta_and_conservation (host-hydrated): $Q selector + serial-control calibration only from host-signed control readbacks', () => {
  const ctlBase = entry('c-base', 1, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspace', json: { seatsUsed: 5 } })
  const ctlInv = entry('c-inv', 2, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspace/invites', json: { invited: true } })
  const ctlInv2 = entry('c-inv2', 3, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspace/invites', status: 409, json: { error: 'seat_limit' } })
  const ctlFin = entry('c-fin', 4, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspace', json: { seatsUsed: 6 } })
  const base = entry('v-base', 5, { method: 'GET', pathAndQuery: '/v1/workspace', json: { seatsUsed: 6 } })
  const race = [6, 7].map(i => entry(`v-inv-${i}`, i, { method: 'POST', pathAndQuery: '/v1/workspace/invites', json: { invited: true } }, { raceBatchId: 'rb_seats' }))
  const fin = entry('v-fin', 8, { method: 'GET', pathAndQuery: '/v1/workspace', json: { seatsUsed: 8 } })
  const idx = index(ctlBase, ctlInv, ctlInv2, ctlFin, base, ...race, fin)
  const raw = { equation: 'quantity_conservation', quantitySelector: '$.seatsUsed', baselineReadback: 'v-base', finalReadback: 'v-fin', actions: race.map(r => r.exchangeId), controlBaselineReadback: 'c-base', controlFinalReadback: 'c-fin', authorizedDelta: 1000 }
  const hydrated = hydrateV8OracleInput('economic_conservation', raw, idx, SIG)
  assert.equal(hydrated.controlDelta, 1, 'benign serial control admitted exactly one seat')
  assert.equal(hydrated.authorizedDelta, undefined, 'worker-supplied authorizedDelta must never be hydrated')
  const verdict = evaluateEconomicConservation(hydrated as never)
  assert.equal(verdict.satisfied, true, verdict.reason)
  assert.equal(verdict.primitive, 'state_delta_and_conservation')
  // Without a host-signed control pair there is no ceiling -> fail closed (no worker ceiling accepted)
  const noCtl = evaluateEconomicConservation(hydrateV8OracleInput('economic_conservation', { ...raw, controlBaselineReadback: undefined, controlFinalReadback: undefined }, idx, SIG) as never)
  assert.equal(noCtl.satisfied, false)
  assert.equal(noCtl.reason, 'missing_authorized_delta_or_benign_control')
  // Probe-arm "control" readbacks cannot calibrate the ceiling
  const spoofIdx = index({ ...ctlBase, step: { ...ctlBase.step, arm: 'probe' } }, ctlInv, ctlInv2, ctlFin, base, ...race, fin)
  assert.equal(hydrateV8OracleInput('economic_conservation', raw, spoofIdx, SIG).controlDelta, undefined)
})

test('state_delta_and_conservation: sequential legitimate same-amount deposits to the own wallet are NOT collapsed or flagged; lineage-linked race overcredit confirms', () => {
  const base = entry('w-base', 1, { arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { tenant: 'org_a', balance: 100 } })
  const dep = (id: string, seq: number) => entry(id, seq, { method: 'POST', pathAndQuery: '/v1/wallets/wal_9f3a21c7/deposit', requestJson: { amount: 50 }, json: { id: 'wal_9f3a21c7', currency: 'USD', status: 'active' } })
  const fin = entry('w-fin', 4, { arm: 'control', method: 'GET', pathAndQuery: '/v1/balance', json: { tenant: 'org_a', balance: 200 } })
  const idx = index(base, dep('w-dep1', 2), dep('w-dep2', 3), fin)
  const hydrated = hydrateV8OracleInput('economic_conservation', { equation: 'balance_minting', baselineReadback: 'w-base', actions: ['w-dep1', 'w-dep2'], finalReadback: 'w-fin' }, idx, SIG)
  assert.equal(hydrated.authorizedDeposits, 100, 'each distinct deposit counts once (wallet id is never an entity collapse key)')
  const v = evaluateEconomicConservation(hydrated as never)
  assert.equal(v.satisfied, false)
  assert.equal(v.reason, 'balance_ledger_conserved')

  // Domain-free lineage: create (emits host capability, echoes amount) -> concurrent captures consuming it
  const cap = 'cap:hop_create:ent_77'
  const lBase = entry('l-base', 1, { arm: 'control', method: 'GET', pathAndQuery: '/v1/ledger', json: { balanceCents: 1000 } })
  const create = entry('l-create', 2, { method: 'POST', pathAndQuery: '/v1/things', status: 201, json: { thing: { amountCents: 500 } } }, { emittedCapabilities: [cap] })
  const capture = (id: string, seq: number) => entry(id, seq, { method: 'POST', pathAndQuery: '/v1/things/ent_77/capture', json: { thing: { amountCents: 500 } } }, { consumedCapabilities: [cap], raceBatchId: 'rb_cap', timestampMs: 1500 })
  const lFin = entry('l-fin', 5, { arm: 'control', method: 'GET', pathAndQuery: '/v1/ledger', json: { balanceCents: 2000 } })
  const lIdx = index(lBase, create, capture('l-c1', 3), capture('l-c2', 4), lFin)
  const mint = hydrateBalanceMintingOperands({ baseRec: { ...rec('l-base', 1100, { json: lBase.step.json }) }, finRec: rec('l-fin', 1500 + 100, { json: lFin.step.json }), actRecs: [rec('l-c1', 1500), rec('l-c2', 1500)], entriesById: lIdx.entriesById, tolerance: 1e-6, toRecord: e => rec(e.exchangeId, e.timestampMs ?? 1, { json: e.step.json }) })
  assert.equal(mint.ok, true, mint.reason)
  assert.equal(mint.authorizedDeposits, 500, 'echoed lifecycle amount dedupes to one authorized credit')
})

/* ── 2d. wire_framing_and_cache_differential ──────────────────────────────── */

test('wire_framing_and_cache_differential: victim-matched digest WITHOUT X-Cache: HIT confirms; mismatch/pre-exposed/ordering/same-principal fail closed', () => {
  const victim = 'digest-victim-statement-0042'
  const control = rec('c', 100, { actorId: 'member_a', tenantId: 'org_a', json: { statements: [] }, artifactDigest: 'digest-empty-0000' })
  const prime = rec('p', 200, { actorId: 'member_b', tenantId: 'org_b', artifactDigest: victim })
  const variant = rec('v', 300, { actorId: 'member_a', tenantId: 'org_a', responseHeaders: {}, json: { statement: 'tenant b revenue line', cents: 712000 }, artifactDigest: victim })
  const base = { property: 'cache_priming' as const, control, prime, variant, victimDigest: victim, requireDistinctPrincipals: true }
  const ok = evaluateUniversalPrimitive('wire_framing_and_cache_differential', base)
  assert.equal(ok.satisfied, true, ok.reason)
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { ...base, variant: { ...variant, artifactDigest: 'digest-own-0001' } }).reason, 'variant_did_not_receive_victim_artifact')
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { ...base, control: { ...control, artifactDigest: victim } }).reason, 'resource_already_exposed_in_clean_control')
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { ...base, variant: { ...variant, timestampMs: 150 } }).reason, 'variant_precedes_prime')
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { ...base, prime: { ...prime, actorId: 'member_a', tenantId: 'org_a' } }).reason, 'principals_not_distinct')
  // Legacy cache_primed adapter: no cache-hit evidence needed, but digest binding still required
  const legacy = { mode: 'cache_primed' as const, cacheKey: 'GET /v1/statements/latest', victimArtifactDigest: victim, cleanControl: control, victimOrPrimeRequest: prime, attackerProbe: variant, cacheHitObserved: false }
  assert.equal(evaluateParserCacheDifferential(legacy).satisfied, true)
  assert.equal(evaluateParserCacheDifferential({ ...legacy, attackerProbe: { ...variant, artifactDigest: 'digest-own-0001' } }).reason, 'attacker_did_not_receive_victim_artifact')
})

test('wire_framing_and_cache_differential: framing property must differ between denied control and succeeding variant', () => {
  const control = rec('c', 100, { method: 'POST', status: 403, json: { error: 'forbidden' } })
  const variant = rec('v', 200, { method: 'POST', json: { role: 'admin', granted: 'elevated scope applied' } })
  const okRes = evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'duplicate_json_key', control, variant, controlWireValue: '{"a":1}', variantWireValue: '{"a":1,"a":2}', bindActor: true })
  assert.equal(okRes.satisfied, true, okRes.reason)
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'duplicate_json_key', control, variant, controlWireValue: 'same', variantWireValue: 'same' }).reason, 'no_wire_differential_between_control_and_variant')
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'header_normalization', control: { ...control, status: 200 }, variant, controlWireValue: 'a', variantWireValue: 'b' }).reason, 'control_not_denied')
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'header_normalization', control, variant: { ...variant, route: '/v1/other' }, controlWireValue: 'a', variantWireValue: 'b' }).reason, 'control_and_variant_route_mismatch')
})

/* ── 2e. oob_and_execution_witness ────────────────────────────────────────── */

test('oob_and_execution_witness: host-minted canary on an independent witness confirms; weak/mismatched/early/control-present fail closed', () => {
  const canary = 'kovo-canary-7f3a9c21d4'
  const trigger = rec('t', 100, { method: 'POST', route: '/v1/import' })
  const witness = rec('w', 300, { route: '/oob/hit' })
  const base = { kind: 'oob_callback' as const, trigger, witness, hostCanary: canary, observedCanary: canary }
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', base).satisfied, true)
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...base, hostCanary: 'short' }).reason, 'weak_or_missing_host_canary')
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...base, observedCanary: 'kovo-canary-00000000' }).reason, 'canary_not_observed')
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...base, witness: { ...witness, timestampMs: 50 } }).reason, 'witness_precedes_trigger')
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...base, witness: { ...witness, id: 't' } }).reason, 'witness_reuses_trigger_exchange')
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...base, control: rec('c', 80), controlObservedCanary: canary }).reason, 'witness_present_in_control')
  const redirect = { kind: 'redirect_canary' as const, trigger, witness: rec('r', 200, { status: 302, responseHeaders: { Location: `https://${canary}.oob.example/landing` } }), hostCanary: canary }
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', redirect).satisfied, true)
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...redirect, witness: { ...redirect.witness, status: 200 } }).reason, 'redirect_canary_not_observed')
  const expr = { kind: 'host_evaluated_expression' as const, trigger: rec('e', 100, { route: '/v1/render', pathAndQuery: '/v1/render?expr=host-expr-ref-1' }), witness: rec('e', 100, { body: 'Total: 4913 units' }), hostCanary: canary, expectedValue: '4913' }
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', expr).satisfied, true)
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...expr, trigger: { ...expr.trigger, pathAndQuery: '/v1/render?echo=4913' } }).reason, 'expected_value_reflected_from_request')
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { ...expr, control: rec('ec', 50, { body: 'Total: 4913 units' }) }).reason, 'expected_value_present_in_control')
})

/* ── 3. own-scope access invariants (absorbed from the retired own-org guard) ── */

const guardBase = (term: HydratableEntry, extra: Partial<OwnScopeGuardParams> = {}): OwnScopeGuardParams => ({
  normCls: 'business_logic', contract: 'auth_or_logic', isPrivEscCls: false, isCrossTenantCls: false, termEx: term, terminalCtrl: undefined,
  attackerTenants: new Set(['quanta']), ownTenantOnly: true, hasForeignTenantData: false, hasPostMutation: false, hasV8Oracle: false, isReadOnlyDir: false,
  hasTermDerivedCrypto: false, hasVerifiedTermStateTransition: false, hasVerifiedTermValueBinding: false, hopCount: 2, ...extra,
})

test('own-scope guard: self-minted own-tenant session credentials never prove a boundary flip (any route spelling); a denied minting control does', () => {
  const mint = entry('mint', 1, { method: 'POST', pathAndQuery: '/api/v3/memberships/mbr_5521/activate', requestJson: { email: 'fin@quanta.example' }, json: { session: { token: 'sess_fin_5521abcd', role: 'finance' } } })
  const ctrl = entry('ctl', 0, { arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/v3/disbursements/dsb_77/approve', json: { error: 'finance_role_required' } })
  const term = entry('approve', 2, { method: 'POST', pathAndQuery: '/api/v3/disbursements/dsb_77/approve', json: { disbursement: { id: 'dsb_77', status: 'approved' } } }, { actorPersona: 'cap:mint:sess' })
  // Verified value binding of the minted capability into the terminal: the ONLY open question is the capability's provenance.
  const params = guardBase(term, { terminalCtrl: ctrl, upstreamEntries: [mint], preChainControlIds: ['ctl'], entriesById: index(ctrl, mint, term).entriesById, hasVerifiedTermValueBinding: true })
  assert.match(evaluateOwnScopeTerminalGuard(params) ?? '', /self-minted session credential/)
  assert.equal(evaluateOwnOrgTerminalGuard(params), evaluateOwnScopeTerminalGuard(params), 'legacy shim name delegates to the primitive guard')
  // Authentication (password-bearing) writes are logins, not capability grants
  const login = { ...mint, step: { ...mint.step, requestJson: { email: 'fin@quanta.example', password: 'not-a-real-secret' } } }
  assert.equal(evaluateOwnScopeTerminalGuard({ ...params, upstreamEntries: [login] }), null)
  // A clean denied control on the minting operation proves the mint itself was unauthorized
  const mintCtrl = entry('mint-ctl', 0, { arm: 'control', method: 'POST', status: 403, pathAndQuery: '/api/v3/memberships/mbr_5521/activate', json: { error: 'forbidden' } })
  assert.equal(evaluateOwnScopeTerminalGuard({ ...params, preChainControlIds: ['ctl', 'mint-ctl'], entriesById: index(ctrl, mintCtrl, mint, term).entriesById }), null)
})

test('own-scope guard: own-tenant collection listings fail closed unless a chain-induced boundary flip or sensitive payload proves protected data', () => {
  const listing = entry('list', 2, { method: 'GET', pathAndQuery: '/v1/orgs/quanta/members', json: { members: [{ id: 'u1', email: 'a@quanta.example', role: 'member' }] } })
  const params = guardBase(listing, { normCls: 'broken_access_control', contract: 'access_control' })
  assert.match(evaluateOwnScopeTerminalGuard(params) ?? '', /collection GET listing is non-terminal/)
  const deniedCtrl = entry('ctl', 1, { arm: 'control', method: 'GET', status: 403, pathAndQuery: '/v1/orgs/quanta/members' })
  assert.equal(evaluateOwnScopeTerminalGuard({ ...params, terminalCtrl: deniedCtrl, hasVerifiedTermValueBinding: true }), null, 'clean 403 + verified chain edge into the terminal is a boundary flip')
  assert.match(evaluateOwnScopeTerminalGuard({ ...params, terminalCtrl: deniedCtrl }) ?? '', /collection GET listing/, 'a denial without a verified chain edge proves nothing')
  const sensitive = { ...listing, step: { ...listing.step, json: { members: [{ id: 'u1', apiToken: 'tok_member_secret_1' }] } } }
  assert.equal(evaluateOwnScopeTerminalGuard({ ...params, termEx: sensitive }), null, 'sensitive keys inside array items are protected data, not a directory')
})

/* ── 4. SDK universal helpers (no positional hop guessing) ─────────────────── */

test('SDK: explicit primitive helpers name slots by role; synthOracleInput and positional hop guessing are gone', t => {
  const dir = mkdtempSync(join(tmpdir(), 'a2-sdk-'))
  const prev = { ctx: process.env.KOVO_RPC_CONTEXT_FILE, tok: process.env.KOVO_RPC_TOKEN_FILE }
  t.after(() => { process.env.KOVO_RPC_CONTEXT_FILE = prev.ctx; process.env.KOVO_RPC_TOKEN_FILE = prev.tok; rmSync(dir, { recursive: true, force: true }) })
  writeFileSync(join(dir, 'context.json'), JSON.stringify({ nonce: 'nonce-a2', runId: 'run-a2', targetOrigins: ['https://api.example.test'], sdkVersion: sdk.KOVO_VERIFY_SDK_VERSION }))
  writeFileSync(join(dir, 'token'), 'test-rpc-token')
  process.env.KOVO_RPC_CONTEXT_FILE = join(dir, 'context.json'); process.env.KOVO_RPC_TOKEN_FILE = join(dir, 'token')
  assert.equal('synthOracleInput' in sdk.ChainBuilder.prototype, false)

  const ch = new sdk.VerifyContext().chain('a2-crypto-extra-login-hop', 'cryptographic_scope_replay')
  ch.control('ex-tampered')
  ch.recordHop({ hopId: 'login', target: 'POST /api/session', exchangeIds: ['ex-login'], claimedDelta: 'Extra login hop shifts positions.' })
  ch.recordHop({ hopId: 'issue', target: 'POST /api/issue', exchangeIds: ['ex-issue'], claimedDelta: 'Issued signed token.' })
  ch.recordHop({ hopId: 'replay', target: 'GET /api/replay', exchangeIds: ['ex-replay'], claimedDelta: 'Replayed across scope.' })
  assert.equal(ch.build({ oracleFamily: 'cryptographic_scope_replay' }).terminalImpact.oracleInput, undefined, 'never wires hops[0] (the login) as the issuance')
  const spec = sdk.accessDifferential({ control: 'ex-tampered', issuance: { exchangeId: 'ex-issue' }, variant: 'ex-replay' })
  assert.equal(spec.primitive, 'access_differential')
  const built = ch.build({ ...spec })
  assert.equal(built.terminalImpact.oracleFamily, 'cryptographic_scope_replay')
  assert.deepEqual(built.terminalImpact.oracleInput, { tamperedSignatureControlExchangeId: 'ex-tampered', sourceValidIssuanceExchangeId: 'ex-issue', replayedAcceptanceExchangeId: 'ex-replay' })

  assert.deepEqual(sdk.stateDeltaAndConservation({ baseline: 'b', final: 'f', actions: ['a1', { exchangeId: 'a2' }], quantitySelector: '$.seatsUsed', controlBaseline: 'cb', controlFinal: 'cf' }), {
    primitive: 'state_delta_and_conservation', oracleFamily: 'economic_conservation',
    oracleInput: { equation: 'quantity_conservation', baselineReadbackExchangeId: 'b', finalReadbackExchangeId: 'f', actionExchangeIds: ['a1', 'a2'], quantitySelector: '$.seatsUsed', controlBaselineReadbackExchangeId: 'cb', controlFinalReadbackExchangeId: 'cf' },
  })
  assert.deepEqual(sdk.wireFramingAndCacheDifferential({ control: 'c', prime: 'p', variant: 'v' }).oracleInput, { mode: 'cache_primed', cleanControlExchangeId: 'c', victimOrPrimeRequestExchangeId: 'p', attackerProbeExchangeId: 'v' })
  assert.deepEqual(sdk.accessDifferential({ control: 'c', variant: 'v', foreignRecordId: 'f-2', ownRecordId: 'o-1', requestedIds: ['o-1', 'f-2'] }).oracleInput, { mode: 'batch_partial_authz', singleForeignControlDeniedExchangeId: 'c', batchRequestExchangeId: 'v', ownRecordId: 'o-1', foreignRecordId: 'f-2', requestedIds: ['o-1', 'f-2'] })
  assert.deepEqual(sdk.primitives.oob_and_execution_witness(), { primitive: 'oob_and_execution_witness', oracleInput: {} })
  assert.equal(sdk.primitives.resolveUniversalPrimitive('bola'), 'access_differential')
})

/* ── 5. Track A1 follow-ups ───────────────────────────────────────────────── */

test('A1(a): 5xx exemption is scoped to the exchanges an injection claim cites; uncited 5xx still fails closed', () => {
  const store = new TranscriptStore()
  const mk = (path: string, status: number) => store.record({
    op: 'http', startedAt: Date.now(), durationMs: 5,
    request: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: path, headers: {}, bodyBytes: 0, bodySha256: '0'.repeat(64), nonce: 'nonce-a2' },
    response: { status, headers: {}, bodyBytes: 0, bodySha256: '0'.repeat(64), mediaType: 'application/json' },
  })
  const probe = mk('/v1/search?q=probe-ref', 500), unrelated = mk('/v1/health', 503)
  const citingClaim = { kind: 'body_contains', exchangeId: probe.exchangeId, text: 'syntax error', vulnClass: 'sqli' } as never
  assert.equal(findUnhandledServerError5xx(store, [citingClaim])?.exchangeId, unrelated.exchangeId, 'uncited 5xx must fail closed even with an sql/inject claim')
  const onlyProbe = new TranscriptStore()
  const p2 = onlyProbe.record({ op: 'http', startedAt: Date.now(), durationMs: 5, request: { origin: 'https://api.example.test', method: 'GET', pathAndQuery: '/v1/search', headers: {}, bodyBytes: 0, bodySha256: '0'.repeat(64), nonce: 'nonce-a2' }, response: { status: 500, headers: {}, bodyBytes: 0, bodySha256: '0'.repeat(64), mediaType: 'text/plain' } })
  assert.equal(findUnhandledServerError5xx(onlyProbe, [{ kind: 'impact', impactClass: 'injection', probeExchangeId: p2.exchangeId } as never]), null, 'cited error-based injection 5xx is exempt')
  assert.equal(findUnhandledServerError5xx(onlyProbe, [{ kind: 'body_contains', exchangeId: 'gx-other', text: 'x', vulnClass: 'sql_injection' } as never])?.exchangeId, p2.exchangeId, 'a claim mentioning sql but citing another exchange exempts nothing')
  assert.equal(findUnhandledServerError5xx(onlyProbe, [{ kind: 'status', exchangeId: p2.exchangeId, expected: 500 } as never])?.exchangeId, p2.exchangeId, 'non-injection claims never exempt 5xx')
})

test('A1(b): parse-failed composite verdicts are never stamped fresh_clean_replay (transcript record, claim, and RPC result)', async t => {
  assert.equal(resolveTranscriptReplayMode({ replayMode: 'fresh_clean_replay', failedStage: 'schema' }), undefined)
  assert.equal(resolveTranscriptReplayMode({ replayMode: undefined as never }), undefined)
  assert.equal(resolveTranscriptReplayMode({ replayMode: 'one_shot_transcript', failedStage: 'edge_binding' }), 'one_shot_transcript')
  assert.equal(resolveTranscriptReplayMode({ replayMode: 'fresh_clean_replay' }), 'fresh_clean_replay')
  const origin = 'http://127.0.0.1:9'
  const rpc = new VerifyRpcServer({ broker: new RequestBroker({ rejectUnauthorized: false }), grant: makeLabGrant(origin, { tier: 3 }), runId: 'run-a2-replay-mode', assignmentId: 'asg-a2', targetOrigins: [origin] })
  t.after(() => rpc.close())
  const { socketPath, token, nonce } = await rpc.start()
  const http = await import('node:http')
  const payload = JSON.stringify({ op: 'composite.verify', args: { receipt: { chainId: 'a2-schema-fail', hops: [{ hopId: 'h1' }] } } })
  const res = await new Promise<{ ok: boolean; result?: Record<string, unknown> }>((resolve, reject) => {
    const req = http.request({ socketPath, path: '/rpc', method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), [VERIFY_RPC_HEADER]: token, [VERIFY_NONCE_HEADER]: nonce } }, r => { let body = ''; r.on('data', c => { body += c }); r.on('end', () => { try { resolve(JSON.parse(body)) } catch (e) { reject(e) } }) })
    req.on('error', reject); req.end(payload)
  })
  assert.equal(res.ok, true)
  assert.equal(res.result?.confirmed, false)
  assert.equal(res.result?.replayMode, undefined)
  assert.equal((res.result?.claim as { replayMode?: string } | undefined)?.replayMode, undefined)
  assert.equal(rpc.transcript.latestCompositeVerification()?.replayMode, undefined)
})

test('A1(c): hardware MAC-address fields are not signature carriers; cryptographic MAC/signature carriers still fail closed on 1-hop terminals', () => {
  for (const benign of ['mac_address', 'macAddress', 'device_mac', 'client_mac', 'hardware_mac', 'eth_mac', 'mac_addr']) assert.equal(isSignatureCarrierKey(benign), false, benign)
  for (const carrier of ['x-signature', 'x-hub-signature-256', 'stripe-signature', 'svix-signature', 'x-slack-signature', 'hmac', 'x-hmac', 'x-mac', 'request-mac', 'message-mac', 'auth-mac', 'signature', 'sig', 'digest', 'derivation']) assert.equal(isSignatureCarrierKey(carrier), true, carrier)
  const idor = (method: string, body: Record<string, unknown>, headers: Record<string, string> = {}) => entry('t', 2, { method, pathAndQuery: '/v1/devices/dev_9a8b7c6d', requestJson: body, requestHeaders: headers, json: { id: 'dev_9a8b7c6d', label: 'updated device' } })
  const guard = (term: HydratableEntry) => evaluateSignatureProvenanceGuard({ normCls: 'bola', hopCount: 1, verifiedEdgeCount: 0, singleHopProofOk: false, termEx: term, terminalCtrl: undefined, preChainControlIds: [], entriesById: new Map(), hasTermDerivedCrypto: false })
  for (const method of ['PATCH', 'DELETE']) {
    assert.equal(hasSignatureCarrier(idor(method, { mac_address: '00:1a:2b:3c:4d:5e', macAddress: '00:1a:2b:3c:4d:5f', device_mac: 'x' })), false)
    assert.equal(guard(idor(method, { mac_address: '00:1a:2b:3c:4d:5e', label: 'lab' })), null, `${method} IDOR with mac_address must not trip signature provenance`)
  }
  assert.match(guard(idor('PATCH', { hmac: 'forged', label: 'x' })) ?? '', /forged_signature_unproven_secret_provenance/)
  assert.match(guard(idor('PATCH', { label: 'x' }, { 'x-mac': 'forged' })) ?? '', /forged_signature_unproven_secret_provenance/)
  assert.match(guard(idor('DELETE', {}, { 'stripe-signature': 't=1,v1=forged' })) ?? '', /forged_signature_unproven_secret_provenance/)
  assert.match(guard(idor('PATCH', {}, { 'x-signature': 'forged' })) ?? '', /forged_signature_unproven_secret_provenance/)
})

/* ── 6. R3-05 Independent Review Hardening (gemini-4-neon-high) ────────────── */

test('R3-05 review: causal_dag rejects non-2xx terminals, duplicate hop exchange IDs, cycles, and case-spoofed surfaces', () => {
  const token = 'tok_dag_review_99ab'
  const h1 = rec('ex-1', 100, { method: 'POST', route: '/v1/mint', json: { token } })
  const h2 = rec('ex-2', 200, { route: '/v1/read', requestHeaders: { authorization: `Bearer ${token}` }, json: { secret: 'cross surface value' } })
  const edge = { kind: 'value_binding' as const, fromHopId: 'h1', toHopId: 'h2', boundValue: token }
  // Non-2xx terminal fails closed
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops: [{ hopId: 'h1', surface: 'http', record: h1 }, { hopId: 'h2', surface: 'browser', record: { ...h2, status: 403 } }], edges: [edge], terminalHopId: 'h2' }).reason, 'terminal_hop_not_accepted')
  // Duplicate exchange ID across hops fails closed
  const selfRec = rec('ex-same', 100, { requestHeaders: { authorization: `Bearer ${token}` }, json: { token, detail: 'self echoed record' } })
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops: [{ hopId: 'h1', surface: 'http', record: selfRec }, { hopId: 'h2', surface: 'browser', record: selfRec }], edges: [edge], terminalHopId: 'h2', requireCrossSurface: true }).reason, 'duplicate_hop_exchange_id')
  // Equal-timestamp cycle fails closed
  const c1 = rec('c1', 100, { requestHeaders: { 'x-t': token }, json: { token, data: 'row 1' } })
  const c2 = rec('c2', 100, { requestHeaders: { 'x-t': token }, json: { token, data: 'row 2' } })
  assert.equal(evaluateUniversalPrimitive('causal_dag', {
    hops: [{ hopId: 'a', surface: 'http', record: c1 }, { hopId: 'b', surface: 'browser', record: c2 }],
    edges: [{ kind: 'value_binding', fromHopId: 'a', toHopId: 'b', boundValue: token }, { kind: 'value_binding', fromHopId: 'b', toHopId: 'a', boundValue: token }],
    terminalHopId: 'b',
  }).reason, 'causal_dag_cycle_detected')
  // Case/whitespace surface spoofing ('http' vs ' HTTP ') is still 1 surface
  assert.equal(evaluateUniversalPrimitive('causal_dag', { hops: [{ hopId: 'h1', surface: 'http', record: h1 }, { hopId: 'h2', surface: ' HTTP ', record: h2 }], edges: [edge], terminalHopId: 'h2', requireCrossSurface: true }).reason, 'single_surface_not_cross_surface_pivot')
})

test('R3-05 review: wire_framing_and_cache_differential rejects cross-method DELETE-403 control, unauthenticated 401 control, exchange reuse, and unknown properties', () => {
  const sharedDigest = 'digest-shared-announcement-01'
  const prime = rec('p', 200, { method: 'GET', route: '/v1/announcements', actorId: 'member_b', tenantId: 'org_b', artifactDigest: sharedDigest, json: { announcement: 'Maintenance window Sunday' } })
  const probe = rec('v', 300, { method: 'GET', route: '/v1/announcements', actorId: 'member_a', tenantId: 'org_a', artifactDigest: sharedDigest, json: { announcement: 'Maintenance window Sunday' } })
  // Cross-method DELETE 403 cannot spoof cleanControl for GET 200 on a public/shared endpoint
  const deleteCtrl = rec('c-del', 100, { method: 'DELETE', route: '/v1/announcements', status: 403, actorId: 'member_a', tenantId: 'org_a', artifactDigest: 'digest-err' })
  assert.equal(evaluateParserCacheDifferential({ mode: 'cache_primed', cacheKey: 'GET /v1/announcements', victimArtifactDigest: sharedDigest, cleanControl: deleteCtrl, victimOrPrimeRequest: prime, attackerProbe: probe }).reason, 'control_and_variant_method_mismatch')
  // Unauthenticated 401 cannot spoof cleanControl for an authenticated probe
  const unauthCtrl = rec('c-401', 100, { method: 'GET', route: '/v1/announcements', status: 401, actorId: null, tenantId: null, artifactDigest: 'digest-401' })
  assert.equal(evaluateParserCacheDifferential({ mode: 'cache_primed', cacheKey: 'GET /v1/announcements', victimArtifactDigest: sharedDigest, cleanControl: unauthCtrl, victimOrPrimeRequest: prime, attackerProbe: probe }).satisfied, false)
  // Exchange reuse between prime and variant fails closed
  const okCtrl = rec('c-ok', 100, { method: 'GET', route: '/v1/announcements', status: 200, actorId: 'member_a', tenantId: 'org_a', artifactDigest: 'digest-empty' })
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'cache_priming', control: okCtrl, prime, variant: prime, victimDigest: sharedDigest }).reason, 'wire_differential_reuses_exchange_id')
  // Unknown wire property fails closed
  assert.equal(evaluateUniversalPrimitive('wire_framing_and_cache_differential', { property: 'invented_prop' as never, control: deleteCtrl, variant: probe, controlWireValue: 'a', variantWireValue: 'b' }).reason, 'missing_wire_property')
})

test('R3-05 review: quantity_conservation rejects malformed 400/unauth 401 control calibration, cross-resource control readbacks, and unrelated in-window DELETEs', () => {
  const base = entry('v-base', 10, { method: 'GET', pathAndQuery: '/v1/workspaces/ws_open', json: { seatsUsed: 2 } })
  const acts = [11, 12].map(i => entry(`v-inv-${i}`, i, { method: 'POST', pathAndQuery: '/v1/workspaces/ws_open/invites', json: { invited: true } }))
  const fin = entry('v-fin', 13, { method: 'GET', pathAndQuery: '/v1/workspaces/ws_open', json: { seatsUsed: 4 } })
  const raw = { equation: 'quantity_conservation', quantitySelector: '$.seatsUsed', baselineReadback: 'v-base', finalReadback: 'v-fin', actions: acts.map(a => a.exchangeId), controlBaselineReadback: 'c-base', controlFinalReadback: 'c-fin' }
  // 1) Malformed 400 Bad Request in control window cannot forge controlDelta=0
  const bad400Idx = index(
    entry('c-base', 1, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspaces/ws_open', json: { seatsUsed: 2 } }),
    entry('c-bad1', 2, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspaces/ws_open/invites', status: 400, json: { error: 'bad_request' } }),
    entry('c-bad2', 3, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspaces/ws_open/invites', status: 400, json: { error: 'bad_request' } }),
    entry('c-fin', 4, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspaces/ws_open', json: { seatsUsed: 2 } }),
    base, ...acts, fin,
  )
  assert.equal(hydrateV8OracleInput('economic_conservation', raw, bad400Idx, SIG).controlDelta, undefined)
  // 2) Different resource instance (ws_full vs ws_open) cannot calibrate ws_open
  const crossResIdx = index(
    entry('c-base', 1, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspaces/ws_full', json: { seatsUsed: 5 } }),
    entry('c-1', 2, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspaces/ws_full/invites', status: 409, json: { error: 'full' } }),
    entry('c-2', 3, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspaces/ws_full/invites', status: 409, json: { error: 'full' } }),
    entry('c-fin', 4, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspaces/ws_full', json: { seatsUsed: 5 } }),
    base, ...acts, fin,
  )
  assert.equal(hydrateV8OracleInput('economic_conservation', raw, crossResIdx, SIG).controlDelta, undefined)
  // 3) Unrelated DELETE inside control window cannot forge negative controlDelta
  const delIdx = index(
    entry('c-base', 1, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspaces/ws_open', json: { seatsUsed: 5 } }),
    entry('c-1', 2, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspaces/ws_open/invites', status: 200, json: { ok: true } }),
    entry('c-2', 3, { arm: 'control', method: 'POST', pathAndQuery: '/v1/workspaces/ws_open/invites', status: 200, json: { ok: true } }),
    entry('c-del', 4, { arm: 'control', method: 'DELETE', pathAndQuery: '/v1/workspaces/ws_open/members/m1', status: 200, json: { removed: true } }),
    entry('c-fin', 5, { arm: 'control', method: 'GET', pathAndQuery: '/v1/workspaces/ws_open', json: { seatsUsed: 1 } }),
    base, ...acts, fin,
  )
  assert.equal(hydrateV8OracleInput('economic_conservation', raw, delIdx, SIG).controlDelta, undefined)
})

test('R3-05 review: oob_and_execution_witness rejects relative redirect_canary, header-reflected expressions, unknown kinds; access_differential rejects readback reuse and request-tenant spoof in mintedSession', () => {
  const canary = 'kovo-canary-7f3a9c21d4'
  const trigger = rec('t', 100, { method: 'GET', route: '/v1/login', requestHeaders: { 'x-expr': '4913' } })
  // Relative Location carrying canary only in query param is NOT an open redirect
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { kind: 'redirect_canary', trigger, witness: rec('r', 200, { status: 302, responseHeaders: { Location: `/login?next=https://${canary}.oob.example` } }), hostCanary: canary }).reason, 'redirect_canary_not_observed')
  // Header-reflected expectedValue fails closed
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { kind: 'host_evaluated_expression', trigger, witness: rec('t', 100, { body: 'Echo: 4913' }), hostCanary: canary, expectedValue: '4913' }).reason, 'expected_value_reflected_from_request')
  // Unknown witness kind fails closed
  assert.equal(evaluateUniversalPrimitive('oob_and_execution_witness', { kind: 'bogus_witness' as never, trigger, witness: rec('w', 200), hostCanary: canary, observedCanary: canary }).reason, 'missing_witness_kind')
  // access_differential rejects readback reusing variant exchange even when requireReadback is false
  const ctl = rec('c', 100, { status: 403 }), vr = rec('v', 200, { json: { id: 'f-1', secret: 'val' } })
  assert.equal(evaluateUniversalPrimitive('access_differential', { control: ctl, variant: vr, readback: vr, persistedDelta: true }).reason, 'readback_reuses_probe_exchange')
  // Own-scope guard Case B: attacker-controlled requestJson.tenant cannot bypass self-minted terminal rejection when response omits tenant
  const spoofTerm = entry('mint-term', 2, { method: 'POST', pathAndQuery: '/api/v1/invites/accept', requestJson: { code: 'own_code', tenant: 'victim_org' }, json: { token: 'sess_own_1234', role: 'member' } })
  assert.match(evaluateOwnScopeTerminalGuard(guardBase(spoofTerm, { normCls: 'privilege_escalation', contract: 'access_control', isPrivEscCls: true, ownTenantOnly: false })) ?? '', /self-minted session terminal/)
})
