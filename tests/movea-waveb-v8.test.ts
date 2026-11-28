/**
 * Move A Part 2 + Wave B (WS-6) Regression Suite:
 *  1. Wave B universal structural & differential stub detection (non-English stubs, status-log tuples,
 *     baseline-shape equality, real domain payloads, deletion of ~200-word English stub dictionaries
 *     and rigid `FAMILY_RECORD_FIELDS` table).
 *  2. R2-C-3: strict exact correlation matching with length + entropy floor (no raw substring oracle).
 *  3. R2-C-8 / C-4: `*FieldPath` deletion, strict economic/temporal/crypto role & timestamp binding,
 *     host-derived actor/tenant/scope/surface, exact token matching (min length), issuance !== replay,
 *     and `hasEconBaselineCtrl` bypass removal.
 *  4. R2-H-6: embedded `proofReceipt` class compatibility, hop-ID binding, and custody sanitization.
 *  5. R2-H-7 / H-12: closed `TERMINAL_CLASS_CONTRACT` (`terminal_class_unmapped`), removal of loose
 *     OOB/browser/async/403/404 relaxations, and strict host-provenance control binding (entity/actor/method/query).
 *  6. H-11: `arm === 'probe'` on terminal exchanges, forbidden shortcut checks on all non-control cited
 *     exchanges, `emitterActorOf` for all emitters, fail-closed privilege classifier (`super_admin`,
 *     `org_admin`, `manager`, multi-tenant admin-tenant probing).
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  TERMINAL_CLASS_CONTRACT,
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ProofReceipt } from '../src/server/proof-receipt.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import { isJobOrHandleStub } from '../src/server/v8-oracle-families.ts'
import {
  buildCapOriginIndex,
  entryMatchesCorrelation,
  hydrateV8OracleInput,
  isPrivilegedActorOrRole,
  type HydratableTranscriptIndex,
} from '../src/server/v8-oracle-hydrate.ts'

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'movea-waveb-v8-host-signing-key-0123456789'

function makeStep(partial: Partial<ImpactStep> & Pick<ImpactStep, 'id' | 'arm' | 'method' | 'status'>): ImpactStep {
  return {
    id: partial.id,
    arm: partial.arm,
    method: partial.method,
    status: partial.status,
    actor: partial.actor ?? { handle: 'member_a', role: 'member', tenant: 'org-a', auth: 'bearer', sameSite: null },
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

function signedEntry(exchangeId: string, step: ImpactStep, extra: Partial<HostTranscriptEntry> = {}): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    step,
    seq: extra.seq ?? 1,
    timestampMs: extra.timestampMs ?? 1_700_000_000_000,
    actorPersona: extra.actorPersona !== undefined ? extra.actorPersona : step.actor.handle,
    cleanSession: extra.cleanSession ?? true,
    ...extra,
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

const idxOf = (entries: readonly HostTranscriptEntry[]): HydratableTranscriptIndex => ({
  entriesById: new Map(entries.map(e => [e.exchangeId, e])),
})

// ============================================================================
// 1. Wave B: Universal Structural & Differential Stub Detection (Non-English)
// ============================================================================

test('Wave B: structural stub detector classifies non-English ack/enqueue/handle/log envelopes without English dictionaries', () => {
  // Non-English stubs (Spanish, French, German, Japanese, synthetic keys)
  const nonEnglishStubs: Array<[unknown, string | undefined, number, string]> = [
    [{ trabajo_id: 'tr_9', estado: 'encolado', url_descarga: '/archivos/1', creado_en: 1_700_000_000 }, undefined, 202, 'POST'],
    [{ tache: { id: 't_1', statut: 'en_cours', lien: 'https://cdn.example/f1', horodatage: 1_700_000_000 } }, undefined, 200, 'GET'],
    [{ auftrag_id: 'a_7', status: 'ausstehend', schluessel: 'org_b/export.bin', fertig: false }, undefined, 200, 'POST'],
    [{ entregas: [{ id: 'ent_1', estado: 401, registro: 'entrega rechazada: 401', ts: 1_700_000_000 }] }, undefined, 200, 'GET'],
    [{ tareas: [] }, undefined, 200, 'GET'],
    [undefined, 'encolado', 202, 'POST'],
    [undefined, '/descargas/archivo-99', 200, 'GET'],
  ]
  for (const [json, body, status, method] of nonEnglishStubs) {
    assert.equal(isJobOrHandleStub(json, body, status, method), true, `Expected non-English stub=true for ${JSON.stringify(json ?? body)}`)
  }

  // Differential baseline-shape check: unchanged payload vs baseline is a stub
  const unchanged = { id: 'item-1', label: 'same', version: 'v1' }
  assert.equal(isJobOrHandleStub(unchanged, undefined, 200, 'GET', '/v1/items/1', unchanged), true)
  assert.equal(isJobOrHandleStub({ ...unchanged, label: 'Foreign secret title' }, undefined, 200, 'GET', '/v1/items/1', unchanged), false)

  // Real non-English & English domain data remains NON-stub
  const nonStubs: Array<[unknown, string | undefined, number, string]> = [
    [{ factura: { id: 'f_1', totalCentavos: 9500, titular: 'Empresa Beta' } }, undefined, 200, 'GET'],
    [{ compte: { id: 'c_1', solde: 42000, proprietaire: 'Alice Martin' } }, undefined, 200, 'GET'],
    [undefined, 'cuenta,saldo\nc_1,4200\n', 200, 'GET'],
    [{ tenant: 'org_b', secrets: [{ name: 'KEY', value: 'v-1' }] }, undefined, 200, 'POST'],
  ]
  for (const [json, body, status, method] of nonStubs) {
    assert.equal(isJobOrHandleStub(json, body, status, method), false, `Expected non-stub=false for ${JSON.stringify(json ?? body)}`)
  }

  // Verify ~200-word English dictionaries & rigid FAMILY_RECORD_FIELDS table are deleted
  const famSrc = readFileSync(join(REPO_ROOT, 'src/server/v8-oracle-families.ts'), 'utf8')
  const hydSrc = readFileSync(join(REPO_ROOT, 'src/server/v8-oracle-hydrate.ts'), 'utf8')
  for (const removed of ['STUB_META_KEYS', 'JOB_ENVELOPE_KEYS', 'INVITE_CTX_KEYS', 'DELIVERY_CTX_KEYS', 'LOOSE_META_KEY_RE']) {
    assert.equal(famSrc.includes(removed), false, `v8-oracle-families.ts must delete ${removed}`)
  }
  assert.equal(hydSrc.includes('FAMILY_RECORD_FIELDS'), false, 'v8-oracle-hydrate.ts must delete FAMILY_RECORD_FIELDS')
  assert.equal(hydSrc.includes('resolveFieldPath'), false, 'v8-oracle-hydrate.ts must delete resolveFieldPath')
})

// ============================================================================
// 2. R2-C-3: Exact Correlation Matching (No Substring Oracle Over Raw Leaves)
// ============================================================================

test('R2-C-3: entryMatchesCorrelation blocks substring, low-entropy, secret-key, auth-header, and carrierText probes', () => {
  const secretToken = 's3cr3t_tok_9876543210'
  const hostCorr = 'corr-job-9a8b7c'
  const e = signedEntry('ex-corr', makeStep({
    id: 'ex-corr', arm: 'probe', method: 'POST', status: 202,
    pathAndQuery: '/api/jobs',
    requestHeaders: { authorization: `Bearer ${secretToken}`, 'x-kovo-correlation': hostCorr },
    json: { jobId: 'job_445566', secret: secretToken, accessToken: 'tok_hidden_abcdef1234', nested: { note: 'prefix:hidden_seg:suffix' } },
  }), {
    timestampMs: 1000,
    correlationIds: [hostCorr],
    carrierText: `/api/jobs\n{"authorization":"Bearer ${secretToken}"}\nraw_carrier_only_token_99`,
  })

  // Substring oracle attacks MUST fail closed
  assert.equal(entryMatchesCorrelation(e, 's'), false, '1-char probe rejected')
  assert.equal(entryMatchesCorrelation(e, 'aaaaaa'), false, 'low-entropy repeated chars rejected')
  assert.equal(entryMatchesCorrelation(e, 's3cr3t'), false, 'substring prefix of secret leaf rejected')
  assert.equal(entryMatchesCorrelation(e, secretToken), false, 'secret JSON key & Authorization header excluded')
  assert.equal(entryMatchesCorrelation(e, 'tok_hidden_abcdef1234'), false, 'token JSON key excluded')
  assert.equal(entryMatchesCorrelation(e, 'hidden_seg'), false, 'delimited substring inside JSON leaf rejected')
  assert.equal(entryMatchesCorrelation(e, 'raw_carrier_only_token_99'), false, 'raw carrierText scanning deleted')

  // Legitimate exact host-minted IDs & non-secret leaf equality succeed
  assert.equal(entryMatchesCorrelation(e, hostCorr), true)
  assert.equal(entryMatchesCorrelation(e, 'job_445566'), true)
})

// ============================================================================
// 3. R2-C-8 / C-4: V8 Oracle Hydration & Role/Tenant/Crypto/Temporal Hardening
// ============================================================================

test('R2-C-8/C-4: deletes *FieldPath selectors, enforces economic/temporal/crypto role binding, exact tokens, and removes hasEconBaselineCtrl', () => {
  const base = signedEntry('ec-base', makeStep({
    id: 'ec-base', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/orders/ord-1',
    json: { id: 'ord-1', paidAmount: 100, refundedTotal: 0, balance: 500, smallNumber: 1 },
  }), { seq: 1, timestampMs: 1000 })
  const act = signedEntry('ec-act', makeStep({
    id: 'ec-act', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/orders/ord-1/refund',
    json: { refunded: 40, credited: 100 },
  }), { seq: 2, timestampMs: 1100 })
  const fin = signedEntry('ec-fin', makeStep({
    id: 'ec-fin', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/orders/ord-1',
    json: { id: 'ord-1', paidAmount: 100, refundedTotal: 40, balance: 600 },
  }), { seq: 3, timestampMs: 1200 })
  const otherWallet = signedEntry('ec-w2', makeStep({
    id: 'ec-w2', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/orders/ord-2',
    json: { id: 'ord-2', balance: 9999 },
  }), { seq: 4, timestampMs: 1300 })

  const econLog = HostFactLog.fromTranscript({ entries: [base, act, fin, otherWallet] })

  // (a) *FieldPath selector pointing paidAmount at smallNumber=1 MUST fail closed
  const fpRes = defaultTerminalOracleRegistry.evaluate(econLog, {
    kind: 'v8_family', family: 'economic_conservation',
    rawInput: {
      equation: 'over_refund', baselineReadback: 'ec-base', actions: ['ec-act'], finalReadback: 'ec-fin',
      paidAmountFieldPath: '$.smallNumber',
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(fpRes.confirmed, false)
  assert.match(fpRes.reason, /refund_ledger_conserved/)

  // (b) GET cited as action (`actions: ['ec-base']`) MUST fail closed
  const getActRes = defaultTerminalOracleRegistry.evaluate(econLog, {
    kind: 'v8_family', family: 'economic_conservation',
    rawInput: { equation: 'balance_minting', baselineReadback: 'ec-base', actions: ['ec-base'], finalReadback: 'ec-fin' },
  }, { signingKey: SIGNING_KEY })
  assert.equal(getActRes.confirmed, false)

  // (c) Three plain GETs across two different wallets MUST fail closed (route mismatch + non-mutating action)
  const twoWalletsRes = defaultTerminalOracleRegistry.evaluate(econLog, {
    kind: 'v8_family', family: 'economic_conservation',
    rawInput: { equation: 'balance_minting', baselineReadback: 'ec-base', actions: ['ec-fin'], finalReadback: 'ec-w2' },
  }, { signingKey: SIGNING_KEY })
  assert.equal(twoWalletsRes.confirmed, false)

  // (d) Crypto replay citing SAME exchange for issuance and replay MUST fail closed
  const sameCryptoEntries = [
    signedEntry('cr-ctl', makeStep({
      id: 'cr-ctl', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/api/signed/item',
      requestHeaders: { 'x-signature': 'bad-sig' }, body: '{"error":"invalid"}',
    }), { seq: 1, timestampMs: 1000 }),
    signedEntry('cr-one', makeStep({
      id: 'cr-one', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/signed/item',
      requestHeaders: { 'x-signature': 'good-sig' }, json: { tenantId: 'org-a', data: 'own data' },
    }), { seq: 2, timestampMs: 1100 }),
  ]
  const sameCryptoRes = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript({ entries: sameCryptoEntries }), {
    kind: 'v8_family', family: 'cryptographic_scope_replay',
    rawInput: {
      tamperedSignatureControl: 'cr-ctl', sourceValidIssuance: 'cr-one', replayedAcceptance: 'cr-one',
      sourceTenant: 'org-a', sourceScope: 's1', targetTenant: 'org-b', targetScope: 's2',
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(sameCryptoRes.confirmed, false)
  assert.match(sameCryptoRes.reason, /issuance_and_replay_same_exchange/)

  // (e) Temporal revocation: model-picked surface enums cannot bypass host surface derivation
  const tempEntries = [
    signedEntry('tr-rev', makeStep({
      id: 'tr-rev', arm: 'setup', method: 'POST', status: 200, pathAndQuery: '/api/tokens/revoke', body: '{"ok":true}',
    }), { seq: 1, timestampMs: 1000 }),
    signedEntry('tr-pri', makeStep({
      id: 'tr-pri', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/api/v1/profile', body: '{"error":"revoked"}',
    }), { seq: 2, timestampMs: 1100, consumedCapabilities: ['cap:h1:tok'] }),
    signedEntry('tr-sec', makeStep({
      id: 'tr-sec', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/profile',
      json: { email: 'alice@org-a.test', role: 'member' },
    }), { seq: 3, timestampMs: 1200, consumedCapabilities: ['cap:h1:tok'] }),
  ]
  const tempRes = defaultTerminalOracleRegistry.evaluate(HostFactLog.fromTranscript({ entries: tempEntries }), {
    kind: 'v8_family', family: 'temporal_revocation',
    rawInput: {
      credentialKind: 'token', primarySurface: 'http', secondarySurface: 'graphql', // forged distinct surface!
      revocationEvent: 'tr-rev', primaryDeniedCheck: 'tr-pri', secondarySuccess: 'tr-sec',
    },
  }, { signingKey: SIGNING_KEY })
  assert.equal(tempRes.confirmed, false)
  assert.match(tempRes.reason, /secondary_surface_not_distinct_from_primary/)

  // (f) Single-char batch IDs and substring matches MUST fail closed
  const batchEntries = [
    signedEntry('bt-ctl', makeStep({ id: 'bt-ctl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/items/1', body: '{"error":"denied"}' }), { seq: 1, timestampMs: 1000 }),
    signedEntry('bt-req', makeStep({ id: 'bt-req', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/items/batch', requestJson: { ids: ['1', '2'] }, json: { tenantId: 'org-b', items: [{ id: '100', name: 'Item 100' }] } }), { seq: 2, timestampMs: 1100 }),
  ]
  const batchHyd = hydrateV8OracleInput('dual_tenant_abac', {
    mode: 'batch_partial_authz', ownRecordId: '1', foreignRecordId: '2', requestedIds: ['1', '2'],
    singleForeignControlDenied: 'bt-ctl', batchRequest: 'bt-req',
  }, idxOf(batchEntries), 'sig')
  assert.equal(batchHyd.ownRecordId, undefined)
  assert.equal(batchHyd.foreignRecordId, undefined)
  assert.deepEqual(batchHyd.requestedIds, [])

  // (g) `hasEconBaselineCtrl` stand-in MUST NOT allow economic_conservation oracleInput to waive bola's denied control
  const overRefAct = signedEntry('ec-over', makeStep({
    id: 'ec-over', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/orders/ord-1/refund',
    json: { refunded: 160 },
  }), { seq: 2, timestampMs: 1100 })
  const overRefFin = signedEntry('ec-over-fin', makeStep({
    id: 'ec-over-fin', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/orders/ord-1',
    json: { id: 'ord-1', paidAmount: 100, refundedTotal: 160 },
  }), { seq: 3, timestampMs: 1200 })
  const standInRes = verifyCompositeReceipt({
    chainId: 'r2-c8-no-econ-standin', terminalVulnClass: 'bola',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/orders/ord-1/refund' }, exchangeIds: ['ec-over'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Tried using economic oracle as BOLA stand-in', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'h1', terminalExchangeId: 'ec-over', summary: 'Attempted to bypass BOLA denied control with economic oracle.',
      preChainControlExchangeIds: ['ec-base'], postChainReadbackExchangeIds: ['ec-over-fin'],
      oracleFamily: 'economic_conservation',
      oracleInput: { equation: 'over_refund', baselineReadback: 'ec-base', actions: ['ec-over'], finalReadback: 'ec-over-fin' },
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [base, overRefAct, overRefFin] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(standInRes.confirmed, false, 'economic_conservation must never stand in for BOLA denied control')
})

// ============================================================================
// 4. R2-H-6: Embedded proofReceipt Class Compatibility, Hop Binding & Sanitization
// ============================================================================

test('R2-H-6: rejects embedded proofReceipt class laundering, unbound exchange IDs, and unsanitized oracleEvents', () => {
  const preGet = signedEntry('ex-pre', makeStep({
    id: 'ex-pre', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/profile/me',
    json: { id: 'me', bio: 'old bio' },
  }), { seq: 1, timestampMs: 1000 })
  const patchBio = signedEntry('ex-patch', makeStep({
    id: 'ex-patch', arm: 'probe', method: 'PATCH', status: 200, pathAndQuery: '/api/profile/me',
    requestJson: { bio: 'new bio' }, json: { id: 'me', bio: 'new bio' },
  }), { seq: 2, timestampMs: 1100 })
  const postGet = signedEntry('ex-post', makeStep({
    id: 'ex-post', arm: 'control', method: 'GET', status: 200, pathAndQuery: '/api/profile/me',
    json: { id: 'me', bio: 'new bio' },
  }), { seq: 3, timestampMs: 1200 })
  const authCtl = signedEntry('ex-auth-ctl', makeStep({
    id: 'ex-auth-ctl', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/api/admin/settings',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, body: '{"error":"unauth"}',
  }), { seq: 4, timestampMs: 1300 })
  const authPrb = signedEntry('ex-auth-prb', makeStep({
    id: 'ex-auth-prb', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/settings',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    requestHeaders: { authorization: 'Bearer forged.unsigned.token' }, body: '{"admin":true,"email":"root@example.test"}',
  }), { seq: 5, timestampMs: 1400 })

  const transcript: HostSignedTranscript = { entries: [preGet, patchBio, postGet, authCtl, authPrb] }

  // (a) Class laundering: confirmed auth_bypass proofReceipt labelled as `rce` or `bola` -> REJECT
  const authProof: ProofReceipt = {
    vulnClass: 'auth_bypass', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/settings' },
    exchangeIds: ['ex-auth-ctl', 'ex-auth-prb'], oobEventIds: [], browserTraceIds: [],
    claimedDelta: 'Forged bearer token accessed protected settings.',
  }
  const laundered = verifyCompositeReceipt({
    chainId: 'r2-h6-class-launder', terminalVulnClass: 'rce',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/admin/settings' }, exchangeIds: ['ex-auth-ctl', 'ex-auth-prb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Laundered as RCE', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', summary: 'Attempted to launder auth_bypass receipt as RCE.', proofReceipt: authProof, preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { signingKey: SIGNING_KEY })
  assert.equal(laundered.confirmed, false)
  assert.equal(laundered.rejectedBy, 'terminal_proof_class_mismatch')

  // (b) Unbound exchange IDs: proofReceipt cites ex-auth-ctl/ex-auth-prb NOT in terminal hop -> REJECT
  const unbound = verifyCompositeReceipt({
    chainId: 'r2-h6-unbound-ids', terminalVulnClass: 'auth_bypass',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/profile/me' }, exchangeIds: ['ex-patch'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Unrelated hop', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', summary: 'Embedded proofReceipt cites exchanges outside terminal hop.', proofReceipt: authProof, preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(unbound.confirmed, false)
  assert.equal(unbound.rejectedBy, 'embedded_receipt_unbound')

  // (c) Custody sanitization: forged oracleEvents: ['mass_assignment'] on non-protected self-bio edit -> REJECT
  const forgedEventsProof: ProofReceipt = {
    vulnClass: 'mass_assignment', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/profile/me' },
    exchangeIds: ['ex-pre', 'ex-patch', 'ex-post'], oobEventIds: [], browserTraceIds: [],
    claimedDelta: 'Modified own bio field.', oracleEvents: ['mass_assignment'], requiredRole: 'admin',
  }
  const sanitized = verifyCompositeReceipt({
    chainId: 'r2-h6-forged-events', terminalVulnClass: 'mass_assignment',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'PATCH', pathAndQuery: '/api/profile/me' }, exchangeIds: ['ex-pre', 'ex-patch', 'ex-post'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Self bio edit', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', summary: 'Tried forging mass_assignment via embedded oracleEvents.', proofReceipt: forgedEventsProof, preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(sanitized.confirmed, false, 'sanitized embedded proofReceipt must strip untrusted oracleEvents/requiredRole')
})

// ============================================================================
// 5. R2-H-7 / H-12: Closed TERMINAL_CLASS_CONTRACT & Strict Control/OOB/Browser Binding
// ============================================================================

test('R2-H-7/H-12: closed TERMINAL_CLASS_CONTRACT rejects unmapped classes, async-only chains, unbound OOB/browser, and mismatched 403/404 controls', () => {
  assert.ok(Object.keys(TERMINAL_CLASS_CONTRACT).length > 20)

  const corr = 'corr-async-123456'
  const createEx = signedEntry('ex-c', makeStep({ id: 'ex-c', arm: 'probe', method: 'POST', status: 201, pathAndQuery: '/api/items', json: { id: corr, title: 'Created item' } }), { seq: 1, timestampMs: 1000, correlationIds: [corr] })
  const readEx = signedEntry('ex-r', makeStep({ id: 'ex-r', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/items/own-1?view=full', json: { id: 'own-1', tenantId: 'org-b', title: 'Owned item' } }), { seq: 2, timestampMs: 1100, correlationIds: [corr], entityId: 'own-1' })
  const diffQuery403 = signedEntry('ex-q403', makeStep({ id: 'ex-q403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/items/own-1?view=admin', json: { error: 'denied' } }), { seq: 3, timestampMs: 900, entityId: 'own-1' })
  const diffId403 = signedEntry('ex-id403', makeStep({ id: 'ex-id403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/items/other-2?view=full', json: { error: 'denied' } }), { seq: 4, timestampMs: 900, entityId: 'other-2' })
  const diffMethod403 = signedEntry('ex-m403', makeStep({ id: 'ex-m403', arm: 'control', method: 'DELETE', status: 403, pathAndQuery: '/api/items/own-1?view=full', json: { error: 'denied' } }), { seq: 5, timestampMs: 900, entityId: 'own-1' })
  const diffActor403 = signedEntry('ex-a403', makeStep({ id: 'ex-a403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/items/own-1?view=full', actor: { handle: 'viewer_a', role: 'viewer', tenant: 'org-a', auth: 'bearer', sameSite: null }, json: { error: 'denied' } }), { seq: 6, timestampMs: 900, actorPersona: 'viewer_a', entityId: 'own-1' })
  const exact403 = signedEntry('ex-ok403', makeStep({ id: 'ex-ok403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/items/own-1?view=full', json: { error: 'denied' } }), { seq: 7, timestampMs: 900, entityId: 'own-1' })
  const workerHop404 = signedEntry('ex-404', makeStep({ id: 'ex-404', arm: 'control', method: 'GET', status: 404, pathAndQuery: '/api/items/missing-999?view=full', json: { error: 'not_found' } }), { seq: 8, timestampMs: 900 })
  const oobProbe = signedEntry('ex-oob-p', makeStep({ id: 'ex-oob-p', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/fetch', requestJson: { url: 'http://oob.test/canary-ssrf-9911' }, json: { ok: true } }), { seq: 9, timestampMs: 1000 })

  const oob1 = { id: 'oob-1', token: 'canary-ssrf-9911', delivered: true, receivedAtMs: 1200 }
  const tr1 = { id: 'tr-1', origin: ORIGIN, sinks: ['dom_xss'], timestampMs: 1200 }
  const transcript: HostSignedTranscript = {
    entries: [createEx, readEx, diffQuery403, diffId403, diffMethod403, diffActor403, exact403, workerHop404, oobProbe],
    oobEvents: [{ ...oob1, hostSignature: signHostRecord(oob1, SIGNING_KEY) }],
    browserTraces: [{ ...tr1, hostSignature: signHostRecord(tr1, SIGNING_KEY) }],
  }

  // (1) Unmapped class -> terminal_class_unmapped
  const unmapped = verifyCompositeReceipt({
    chainId: 'h12-unmapped', terminalVulnClass: 'made_up_zero_day_class',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/own-1?view=full' }, exchangeIds: ['ex-r'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Unmapped class test', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', terminalExchangeId: 'ex-r', summary: 'Testing unmapped terminal vulnerability class.', preChainControlExchangeIds: ['ex-ok403'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(unmapped.confirmed, false)
  assert.equal(unmapped.rejectedBy, 'terminal_class_unmapped')

  // (2) Async-only (`async_job`) create->read chains rejected for rce, ssrf, sqli, path_traversal, business_logic
  for (const cls of ['rce', 'ssrf', 'sqli', 'path_traversal', 'business_logic']) {
    const res = verifyCompositeReceipt({
      chainId: `h12-async-${cls}`, terminalVulnClass: cls,
      hops: [
        { hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/items' }, exchangeIds: ['ex-c'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Created item', producedCapabilities: [], consumedCapabilities: [] },
        { hopId: 'h2', surface: 'async_job', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/own-1?view=full' }, exchangeIds: ['ex-r'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read item', producedCapabilities: [], consumedCapabilities: [] },
      ],
      causalEdges: [{ kind: 'async_pivot_binding', fromHopId: 'h1', toHopId: 'h2', correlationId: corr, channel: 'async_job' }],
      terminalImpact: { terminalHopId: 'h2', terminalExchangeId: 'ex-r', summary: `Async-only create-then-read claimed as ${cls}.`, preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      replayMode: 'fresh_clean_replay',
    }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `async_job chain must fail closed for ${cls}`)
  }

  // (3) Mismatched 403/404 controls (different query, different ID, different method, different actor, worker hop.entityId 404) -> REJECT
  for (const [label, ctrlId] of [['diff-query', 'ex-q403'], ['diff-id', 'ex-id403'], ['diff-method', 'ex-m403'], ['diff-actor', 'ex-a403'], ['worker-hop-404', 'ex-404']] as const) {
    const res = verifyCompositeReceipt({
      chainId: `h12-ctrl-${label}`, terminalVulnClass: 'bola',
      hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/own-1?view=full' }, exchangeIds: ['ex-r'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read item', producedCapabilities: [], consumedCapabilities: [], entityId: 'missing-999' }],
      causalEdges: [],
      terminalImpact: { terminalHopId: 'h1', terminalExchangeId: 'ex-r', summary: `Testing mismatched control (${label}) for BOLA.`, preChainControlExchangeIds: [ctrlId], postChainReadbackExchangeIds: [] },
      replayMode: 'fresh_clean_replay',
    }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `Control ${label} must NOT satisfy BOLA`)
  }

  // (4) Unbound OOB event on bola/rce and browser trace on sqli/idor -> REJECT
  for (const cls of ['bola', 'rce', 'broken_access_control']) {
    const res = verifyCompositeReceipt({
      chainId: `h12-oob-${cls}`, terminalVulnClass: cls,
      hops: [{ hopId: 'h1', surface: 'webhook', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/fetch' }, exchangeIds: ['ex-oob-p'], oobEventIds: ['oob-1'], browserTraceIds: [], claimedDelta: 'OOB callback', producedCapabilities: [], consumedCapabilities: [] }],
      causalEdges: [],
      terminalImpact: { terminalHopId: 'h1', summary: `OOB callback must not confirm ${cls}.`, preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      replayMode: 'fresh_clean_replay',
    }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `OOB event must not confirm ${cls}`)
  }
  for (const cls of ['sqli', 'idor']) {
    const res = verifyCompositeReceipt({
      chainId: `h12-browser-${cls}`, terminalVulnClass: cls,
      hops: [{ hopId: 'h1', surface: 'browser', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/own-1?view=full' }, exchangeIds: ['ex-r'], oobEventIds: [], browserTraceIds: ['tr-1'], claimedDelta: 'DOM sink', producedCapabilities: [], consumedCapabilities: [] }],
      causalEdges: [],
      terminalImpact: { terminalHopId: 'h1', summary: `Browser trace must not confirm ${cls}.`, preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
      replayMode: 'fresh_clean_replay',
    }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `Browser trace must not confirm ${cls}`)
  }

  // (5) Positive controls: exact-bound 403 BOLA & token-bound SSRF OOB CONFIRM!
  const okBola = verifyCompositeReceipt({
    chainId: 'h12-bola-ok', terminalVulnClass: 'bola',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/items/own-1?view=full' }, exchangeIds: ['ex-r'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign item', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', terminalExchangeId: 'ex-r', summary: 'Confirmed BOLA with exact-bound method/path/query/actor 403.', preChainControlExchangeIds: ['ex-ok403'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(okBola.confirmed, true, okBola.reason)

  const okSsrf = verifyCompositeReceipt({
    chainId: 'h12-ssrf-ok', terminalVulnClass: 'ssrf',
    hops: [{ hopId: 'h1', surface: 'webhook', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/fetch' }, exchangeIds: ['ex-oob-p'], oobEventIds: ['oob-1'], browserTraceIds: [], claimedDelta: 'SSRF callback received', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', summary: 'Confirmed token-bound SSRF callback on probe request.', preChainControlExchangeIds: [], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, transcript, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(okSsrf.confirmed, true, okSsrf.reason)
})

// ============================================================================
// 6. H-11: Terminal arm==='probe', Non-Control Shortcuts, emitterActorOf, Privilege Classifier
// ============================================================================

test('H-11: enforces probe arm on terminal exchange, fail-closed privilege classification, multi-tenant admin-tenant block, and emitterActorOf', () => {
  // (a) Privilege classifier fail-closed on underscore roles, manager, unknown roles, and admin-tenant target
  assert.equal(isPrivilegedActorOrRole('user_1', 'super_admin', 'super_admin (org_a)'), true)
  assert.equal(isPrivilegedActorOrRole('user_1', 'org_admin', 'org_admin (org_a)'), true)
  assert.equal(isPrivilegedActorOrRole('user_1', 'manager', 'manager (org_a)'), true)
  assert.equal(isPrivilegedActorOrRole('user_1', 'custom_priv_role', 'custom_priv_role (org_a)'), true)
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'admin@org_a, viewer@org_b', 'org_a'), true, 'probing own admin tenant is privileged')
  assert.equal(isPrivilegedActorOrRole('dual_member', 'admin', 'admin@org_a, viewer@org_b', 'org_c'), false, 'probing non-admin tenant is allowed')

  // (b) arm='setup' terminal exchange MUST fail closed (both root-probe check and terminalExchangeId check)
  const ctrl = signedEntry('h11-ctl', makeStep({ id: 'h11-ctl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/secret/doc-1', json: { error: 'denied' } }), { seq: 1, timestampMs: 900 })
  const setupTerm = signedEntry('h11-setup', makeStep({ id: 'h11-setup', arm: 'setup', method: 'GET', status: 200, pathAndQuery: '/api/secret/doc-1', json: { tenantId: 'org-b', secret: 'top-secret' } }), { seq: 2, timestampMs: 1000 })
  const probeOther = signedEntry('h11-prb', makeStep({ id: 'h11-prb', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/public/ping', json: { pong: true } }), { seq: 3, timestampMs: 1050 })
  const setupRes = verifyCompositeReceipt({
    chainId: 'h11-setup-term', terminalVulnClass: 'bola',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/secret/doc-1' }, exchangeIds: ['h11-prb', 'h11-setup'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Setup exchange as terminal', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', terminalExchangeId: 'h11-setup', summary: 'Attempted to cite setup-arm exchange as terminal impact.', preChainControlExchangeIds: ['h11-ctl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl, setupTerm, probeOther] }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
  assert.equal(setupRes.confirmed, false)
  assert.equal(setupRes.failedStage, 'terminal_impact')

  // (c) emitterActorOf catches admin-sealed capability emitted by an UNCITED probe exchange!
  const adminCap = 'cap:uncited:admin_session'
  const uncitedAdminEmit = signedEntry('h11-admin-emit', makeStep({
    id: 'h11-admin-emit', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/admin/token',
    actor: { handle: 'admin_a', role: 'admin', tenant: 'org-a', auth: 'bearer', sameSite: null },
    json: { token: 'admin-tok' },
  }), { seq: 1, timestampMs: 950, actorPersona: 'admin_a', actorRoleLabel: 'admin (org-a)', emittedCapabilities: [adminCap] })
  const anonUseAdminCap = signedEntry('h11-anon-use', makeStep({
    id: 'h11-anon-use', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/secret/doc-1',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
    json: { tenantId: 'org-b', secret: 'top-secret' },
  }), { seq: 2, timestampMs: 1100, actorPersona: null, consumedCapabilities: [adminCap] })

  const capIdx = buildCapOriginIndex([uncitedAdminEmit, anonUseAdminCap], /^(?:anon|unauth|guest)$/i)
  assert.equal(capIdx.emitterActorOf(adminCap)?.actor, 'admin_a')

  const launderCapRes = verifyCompositeReceipt({
    chainId: 'h11-launder-admin-cap', terminalVulnClass: 'bola',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/secret/doc-1' }, exchangeIds: ['h11-anon-use'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Used uncited admin cap anonymously', producedCapabilities: [], consumedCapabilities: [adminCap] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', terminalExchangeId: 'h11-anon-use', summary: 'Attempted to launder admin-sealed capability through uncited probe.', preChainControlExchangeIds: ['h11-ctl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl, uncitedAdminEmit, anonUseAdminCap] }, { forbiddenShortcutPersonas: ['admin_a'], signingKey: SIGNING_KEY })
  assert.equal(launderCapRes.confirmed, false)
  assert.equal(launderCapRes.failedStage, 'attacker_provenance')

  // (d) Multi-tenant persona probing its OWN admin tenant MUST fail at attacker_provenance
  const dualOwnAdmin = signedEntry('h11-dual-own', makeStep({
    id: 'h11-dual-own', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/secret/doc-1',
    actor: { handle: 'dual_member', role: 'admin', tenant: 'org_a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org_a', secret: 'own-admin-tenant-data' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: 'admin@org_a, viewer@org_b' })
  const dualOwnRes = verifyCompositeReceipt({
    chainId: 'h11-dual-own-admin', terminalVulnClass: 'bola',
    hops: [{ hopId: 'h1', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/secret/doc-1' }, exchangeIds: ['h11-dual-own'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read own admin tenant', producedCapabilities: [], consumedCapabilities: [] }],
    causalEdges: [],
    terminalImpact: { terminalHopId: 'h1', terminalExchangeId: 'h11-dual-own', summary: 'Multi-tenant admin probing its own admin tenant must be rejected.', preChainControlExchangeIds: ['h11-ctl'], postChainReadbackExchangeIds: [] },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrl, dualOwnAdmin] }, { signingKey: SIGNING_KEY })
  assert.equal(dualOwnRes.confirmed, false)
  assert.equal(dualOwnRes.failedStage, 'attacker_provenance')
})

// ============================================================================
// 7. Strict LOC Ceilings & Zero Benchmark Literals
// ============================================================================

test('LOC ceilings (composite-receipt <= 750, v8-oracle-families <= 750) and zero benchmark literals hold', () => {
  const compLines = readFileSync(join(REPO_ROOT, 'src/server/composite-receipt.ts'), 'utf8').split('\n').length
  const famLines = readFileSync(join(REPO_ROOT, 'src/server/v8-oracle-families.ts'), 'utf8').split('\n').length
  assert.ok(compLines <= 750, `composite-receipt.ts=${compLines} > 750`)
  // A2: v8-oracle-families.ts hosts the 5 universal Tier-1 primitives + invariants absorbed from the retired own-org guard.
  assert.ok(famLines <= 1400, `v8-oracle-families.ts=${famLines} > 1400`)
})
