// @kernel @fixes R4-C-5
/**
 * R4-C-5 Class-Level Guard — Signed-Resource Scope & Symmetric Tenant Derivation
 * for `cryptographic_scope_replay`.
 *
 * Verifies:
 *  1. Single-persona mint (/share, /url, or bare-signature /sign) -> tampered-sig 403
 *     -> valid download on the exact signed resource rejects (`same_principal_not_replay`).
 *  2. Two-persona fetch of a byte-identical signed bearer URL (same or different tenant,
 *     including reordered auth query parameters) rejects (`same_principal_not_replay`).
 *  3. Admin-issued -> member-fetched identical signed bearer link rejects (`same_principal_not_replay`).
 *  4. Direct `evaluateCryptographicScopeReplay` defense-in-depth rejects caller-only and
 *     route-only flows even when differing tenant/scope strings are passed directly.
 *  5. Symmetric tenant derivation resolves source and destination in the exact same order
 *     (response-attested markers first, then host persona/capability tenant).
 *  6. Genuine cross-tenant, cross-resource path, cross-resource non-auth query, and
 *     cross-tenant webhook HMAC signature replays confirm cleanly.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import {
  sha256Hex,
  signHostRecord,
  verifyCompositeReceipt,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { HostFactLog } from '../src/server/host-fact-log.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import { defaultTerminalOracleRegistry } from '../src/server/terminal-oracle-registry.ts'
import {
  evaluateCryptographicScopeReplay,
  type HostSignedRecord,
} from '../src/server/v8-oracle-families.ts'
import {
  hydrateV8OracleInput,
  type HydratableTranscriptIndex,
} from '../src/server/v8-oracle-hydrate.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'r4-c5-v8-scope-signing-key-0123456789abcdef'

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
      tenant: 'org-a',
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
    ...(partial.requestHeaders !== undefined ? { requestHeaders: partial.requestHeaders } : {}),
    ...(partial.responseHeaders !== undefined ? { responseHeaders: partial.responseHeaders } : {}),
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

test('R4-C-5 guard 1: single-persona mint -> tampered-sig 403 -> valid download MUST reject across /share, /url, and bare-sig /sign', () => {
  const ctrl = signedEntry('m-ctrl', makeStep({
    id: 'm-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/export-42?sig=tampered-sig',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })

  const download = signedEntry('m-dl', makeStep({
    id: 'm-dl', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-42?exp=1700000900&sig=valid-sig-001',
    json: { fileId: 'export-42', rows: [{ id: 'r1', amount: 500 }] },
  }), { seq: 3, timestampMs: 1200 })

  const mintVariants: Array<[string, HostTranscriptEntry]> = [
    ['share-signedUrl', signedEntry('m-share', makeStep({
      id: 'm-share', arm: 'probe', method: 'POST', status: 200,
      pathAndQuery: '/api/v1/exports/share',
      json: { signedUrl: 'https://api.example.test/api/v1/downloads/export-42?exp=1700000900&sig=valid-sig-001', scope: 'export:read' },
    }), { seq: 2, timestampMs: 1100 })],
    ['url-downloadUrl', signedEntry('m-url', makeStep({
      id: 'm-url', arm: 'probe', method: 'GET', status: 200,
      pathAndQuery: '/api/v1/exports/export-42/url',
      json: { downloadUrl: '/api/v1/downloads/export-42?sig=valid-sig-001&exp=1700000900' },
    }), { seq: 2, timestampMs: 1100 })],
    ['sign-bare-signature', signedEntry('m-sign', makeStep({
      id: 'm-sign', arm: 'probe', method: 'POST', status: 200,
      pathAndQuery: '/api/v1/exports/sign',
      json: { signature: 'valid-sig-001' },
    }), { seq: 2, timestampMs: 1100 })],
  ]

  for (const [label, mint] of mintVariants) {
    const entries = [ctrl, mint, download]
    const regRes = defaultTerminalOracleRegistry.evaluate(
      HostFactLog.fromTranscript({ entries }),
      {
        kind: 'v8_family',
        family: 'cryptographic_scope_replay',
        rawInput: {
          tamperedSignatureControl: ctrl.exchangeId,
          sourceValidIssuance: mint.exchangeId,
          replayedAcceptance: download.exchangeId,
        },
      },
      { signingKey: SIGNING_KEY },
    )
    assert.equal(regRes.confirmed, false, `${label}: mint->download must reject`)
    assert.equal(regRes.reason, 'same_principal_not_replay', `${label}: unexpected reason ${regRes.reason}`)

    const compRes = verifyCompositeReceipt({
      chainId: `r4-c5-mint-dl-${label}`,
      terminalVulnClass: 'cryptographic_scope_replay',
      hops: [{
        hopId: 'h1', surface: 'http',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/downloads/export-42?exp=1700000900&sig=valid-sig-001' },
        exchangeIds: [mint.exchangeId, download.exchangeId],
        oobEventIds: [], browserTraceIds: [],
        claimedDelta: 'Minted signed link and downloaded the exact same resource.',
        producedCapabilities: [], consumedCapabilities: [],
      }],
      causalEdges: [],
      terminalImpact: {
        terminalHopId: 'h1',
        terminalExchangeId: download.exchangeId,
        summary: 'Mint-to-download route difference verification control.',
        preChainControlExchangeIds: [ctrl.exchangeId],
        postChainReadbackExchangeIds: [],
        oracleFamily: 'cryptographic_scope_replay',
        oracleInput: {
          tamperedSignatureControl: ctrl.exchangeId,
          sourceValidIssuance: mint.exchangeId,
          replayedAcceptance: download.exchangeId,
        },
      },
      replayMode: 'fresh_clean_replay',
    }, { entries }, { attackerPersonas: ['member_a'], signingKey: SIGNING_KEY })
    assert.equal(compRes.confirmed, false, `${label}: composite receipt must reject`)
    assert.match(compRes.reason, /same_principal_not_replay/)
  }
})

test('R4-C-5 guard 2: two-persona byte-identical signed bearer URL fetch (same or different tenant) MUST reject', () => {
  for (const [label, bTenant] of [['same-tenant', 'org-a'], ['cross-tenant', 'org-b']] as const) {
    const ctrl = signedEntry(`p-ctrl-${label}`, makeStep({
      id: `p-ctrl-${label}`, arm: 'control', method: 'GET', status: 403,
      pathAndQuery: '/api/v1/downloads/shared?file=report.csv&sig=bad-sig',
      actor: { handle: 'member_b', role: 'member', tenant: bTenant, auth: 'bearer', sameSite: null },
      json: { error: 'invalid_signature' },
    }), { seq: 1, timestampMs: 1000, actorPersona: 'member_b' })

    const iss = signedEntry(`p-iss-${label}`, makeStep({
      id: `p-iss-${label}`, arm: 'probe', method: 'GET', status: 200,
      pathAndQuery: '/api/v1/downloads/shared?file=report.csv&exp=1700000900&sig=valid-sig-002',
      actor: { handle: 'member_a', role: 'member', tenant: 'org-a', auth: 'bearer', sameSite: null },
      json: { records: [{ id: 'doc-1', amount: 1200 }] },
    }), { seq: 2, timestampMs: 1100, actorPersona: 'member_a' })

    // Auth query params reordered, non-auth resource identical
    const rep = signedEntry(`p-rep-${label}`, makeStep({
      id: `p-rep-${label}`, arm: 'probe', method: 'GET', status: 200,
      pathAndQuery: '/api/v1/downloads/shared?sig=valid-sig-002&file=report.csv&exp=1700000900',
      actor: { handle: 'member_b', role: 'member', tenant: bTenant, auth: 'bearer', sameSite: null },
      json: { records: [{ id: 'doc-1', amount: 1200 }] },
    }), { seq: 3, timestampMs: 1200, actorPersona: 'member_b' })

    const res = defaultTerminalOracleRegistry.evaluate(
      HostFactLog.fromTranscript({ entries: [ctrl, iss, rep] }),
      {
        kind: 'v8_family',
        family: 'cryptographic_scope_replay',
        rawInput: {
          tamperedSignatureControl: ctrl.exchangeId,
          sourceValidIssuance: iss.exchangeId,
          replayedAcceptance: rep.exchangeId,
        },
      },
      { signingKey: SIGNING_KEY },
    )
    assert.equal(res.confirmed, false, `${label}: two-persona identical signed URL must reject`)
    assert.equal(res.reason, 'same_principal_not_replay', `${label}: unexpected reason ${res.reason}`)
  }
})

test('R4-C-5 guard 3: admin-issued -> member-fetched identical signed link MUST reject', () => {
  const ctrl = signedEntry('am-ctrl', makeStep({
    id: 'am-ctrl', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/export-99?sig=tampered-sig',
    actor: { handle: 'member_b', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000, actorPersona: 'member_b' })

  const adminMint = signedEntry('am-mint', makeStep({
    id: 'am-mint', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/admin/exports/share',
    actor: { handle: 'admin_a', role: 'admin', tenant: 'org-a', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org-a', signedUrl: 'https://api.example.test/api/v1/downloads/export-99?sig=valid-sig-003' },
  }), { seq: 2, timestampMs: 1100, actorPersona: 'admin_a' })

  const memberFetchWithTenant = signedEntry('am-fetch-t', makeStep({
    id: 'am-fetch-t', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-99?sig=valid-sig-003',
    actor: { handle: 'member_b', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org-a', fileId: 'export-99', rows: [{ id: 'r1', amount: 750 }] },
  }), { seq: 3, timestampMs: 1200, actorPersona: 'member_b' })

  const memberFetchNoTenant = signedEntry('am-fetch-nt', makeStep({
    id: 'am-fetch-nt', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-99?sig=valid-sig-003',
    actor: { handle: 'member_b', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
    json: { fileId: 'export-99', rows: [{ id: 'r1', amount: 750 }] },
  }), { seq: 4, timestampMs: 1300, actorPersona: 'member_b' })

  for (const [label, rep] of [['with-org-a-body', memberFetchWithTenant], ['without-body-tenant', memberFetchNoTenant]] as const) {
    const res = defaultTerminalOracleRegistry.evaluate(
      HostFactLog.fromTranscript({ entries: [ctrl, adminMint, rep] }),
      {
        kind: 'v8_family',
        family: 'cryptographic_scope_replay',
        rawInput: {
          tamperedSignatureControl: ctrl.exchangeId,
          sourceValidIssuance: adminMint.exchangeId,
          replayedAcceptance: rep.exchangeId,
        },
      },
      { signingKey: SIGNING_KEY },
    )
    assert.equal(res.confirmed, false, `${label}: admin-issued -> member-fetched identical link must reject`)
    assert.equal(res.reason, 'same_principal_not_replay', `${label}: unexpected reason ${res.reason}`)
  }
})

test('R4-C-5 guard 4: direct evaluateCryptographicScopeReplay defense-in-depth and symmetric tenant hydration', () => {
  const mkRec = (id: string, ts: number, status: number, extra: Partial<HostSignedRecord> = {}): HostSignedRecord => ({
    id, hostSignature: `hmac-sha256:${id}:deadbeef`, timestampMs: ts, status, method: 'GET',
    ...extra,
  })

  // Direct defense-in-depth: mint->download for identical signed resource rejects even with crafted tenant/scope strings
  const directMintDl = evaluateCryptographicScopeReplay({
    tamperedSignatureControl: mkRec('c1', 1000, 403, { route: '/api/v1/downloads/export-42', json: { error: 'bad_sig' } }),
    sourceValidIssuance: mkRec('s1', 1100, 200, {
      method: 'POST', route: '/api/v1/exports/share', actorId: 'member_a', tenantId: 'org-a',
      json: { signedUrl: 'https://api.example.test/api/v1/downloads/export-42?sig=valid-sig' },
    }),
    replayedAcceptance: mkRec('r1', 1200, 200, {
      route: '/api/v1/downloads/export-42', pathAndQuery: '/api/v1/downloads/export-42?sig=valid-sig',
      actorId: 'member_a', tenantId: 'org-a',
      json: { fileId: 'export-42', rows: [{ id: 'r1', amount: 500 }] },
    }),
    sourceTenant: 'org-a', sourceScope: 'org-a:/api/v1/exports/share',
    targetTenant: 'org-a', targetScope: 'org-a:/api/v1/downloads/export-42',
    tamperedSignatureDigest: sha256Hex('bad'),
    signatureDigest: sha256Hex('valid-sig'),
    replayedSignatureDigest: sha256Hex('valid-sig'),
  })
  assert.equal(directMintDl.satisfied, false)
  assert.equal(directMintDl.reason, 'same_principal_not_replay')

  // Direct defense-in-depth: two-persona byte-identical signed URL rejects even with differing tenant/scope strings
  const directCrossPersona = evaluateCryptographicScopeReplay({
    tamperedSignatureControl: mkRec('c2', 1000, 403, { route: '/api/v1/downloads/shared', json: { error: 'bad_sig' } }),
    sourceValidIssuance: mkRec('s2', 1100, 200, {
      route: '/api/v1/downloads/shared', pathAndQuery: '/api/v1/downloads/shared?sig=valid-sig',
      actorId: 'member_a', tenantId: 'org-a', json: { rows: [{ id: 'd1', amount: 100 }] },
    }),
    replayedAcceptance: mkRec('r2', 1200, 200, {
      route: '/api/v1/downloads/shared', pathAndQuery: '/api/v1/downloads/shared?sig=valid-sig',
      actorId: 'member_b', tenantId: 'org-b', json: { rows: [{ id: 'd1', amount: 100 }] },
    }),
    sourceTenant: 'org-a', sourceScope: 'org-a:member_a:/api/v1/downloads/shared',
    targetTenant: 'org-b', targetScope: 'org-b:member_b:/api/v1/downloads/shared',
    tamperedSignatureDigest: sha256Hex('bad'),
    signatureDigest: sha256Hex('valid-sig'),
    replayedSignatureDigest: sha256Hex('valid-sig'),
  })
  assert.equal(directCrossPersona.satisfied, false)
  assert.equal(directCrossPersona.reason, 'same_principal_not_replay')

  // Symmetric tenant derivation: response tenant beats persona tenant identically on both source and destination
  const symCtrl = signedEntry('sym-c', makeStep({
    id: 'sym-c', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/export-1?sig=bad',
    json: { error: 'bad_sig' },
  }), { seq: 1, timestampMs: 1000 })
  const symSrc = signedEntry('sym-s', makeStep({
    id: 'sym-s', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/exports/share',
    actor: { handle: 'member_a', role: 'member', tenant: 'org-persona', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org-resp', signedUrl: 'https://api.example.test/api/v1/downloads/export-1?sig=valid' },
  }), { seq: 2, timestampMs: 1100 })
  const symDst = signedEntry('sym-d', makeStep({
    id: 'sym-d', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-1?sig=valid',
    actor: { handle: 'member_a', role: 'member', tenant: 'org-persona', auth: 'bearer', sameSite: null },
    json: { tenantId: 'org-resp', rows: [{ id: 'r1', amount: 500 }] },
  }), { seq: 3, timestampMs: 1200 })

  const hyd = hydrateV8OracleInput('cryptographic_scope_replay', {
    tamperedSignatureControl: 'sym-c',
    sourceValidIssuance: 'sym-s',
    replayedAcceptance: 'sym-d',
  }, idxOf([symCtrl, symSrc, symDst]), 'sig')
  assert.equal(hyd.sourceTenant, 'org-resp', 'sourceTenant must follow response-before-persona symmetric order')
  assert.equal(hyd.targetTenant, 'org-resp', 'targetTenant must follow response-before-persona symmetric order')
  assert.equal(hyd.sourceScope, hyd.targetScope, 'same signed resource must produce identical scope')
})

test('R4-C-5 guard 5: genuine cross-tenant and cross-resource signature replays confirm cleanly', () => {
  // (a) Same-tenant, different signed resource path (export-1 signature replayed on export-2)
  const ctrlPath = signedEntry('tp-path-c', makeStep({
    id: 'tp-path-c', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads/export-2?sig=bad-sig',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })
  const issPath = signedEntry('tp-path-s', makeStep({
    id: 'tp-path-s', arm: 'probe', method: 'POST', status: 200,
    pathAndQuery: '/api/v1/exports/share',
    json: { signedUrl: 'https://api.example.test/api/v1/downloads/export-1?sig=valid-sig-path' },
  }), { seq: 2, timestampMs: 1100 })
  const repPath = signedEntry('tp-path-r', makeStep({
    id: 'tp-path-r', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads/export-2?sig=valid-sig-path',
    json: { fileId: 'export-2', rows: [{ id: 'secret-row', amount: 95000 }] },
  }), { seq: 3, timestampMs: 1200 })

  const pathRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrlPath, issPath, repPath] }),
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedSignatureControl: 'tp-path-c',
        sourceValidIssuance: 'tp-path-s',
        replayedAcceptance: 'tp-path-r',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(pathRes.confirmed, true, pathRes.reason)

  // (b) Same path, different non-auth query param (file=public.csv sig replayed on file=payroll.csv)
  const ctrlQ = signedEntry('tp-q-c', makeStep({
    id: 'tp-q-c', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/downloads?file=payroll.csv&sig=bad-sig',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })
  const issQ = signedEntry('tp-q-s', makeStep({
    id: 'tp-q-s', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads?file=public.csv&sig=valid-sig-q',
    json: { rows: [{ id: 'pub-1', amount: 10 }] },
  }), { seq: 2, timestampMs: 1100 })
  const repQ = signedEntry('tp-q-r', makeStep({
    id: 'tp-q-r', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/downloads?file=payroll.csv&sig=valid-sig-q',
    json: { rows: [{ id: 'pay-1', salary: 240000 }] },
  }), { seq: 3, timestampMs: 1200 })

  const queryRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrlQ, issQ, repQ] }),
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedSignatureControl: 'tp-q-c',
        sourceValidIssuance: 'tp-q-s',
        replayedAcceptance: 'tp-q-r',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(queryRes.confirmed, true, queryRes.reason)

  // (c) Cross-tenant signed resource replay (org-a/report sig replayed on org-b/treasury)
  const ctrlT = signedEntry('tp-t-c', makeStep({
    id: 'tp-t-c', arm: 'control', method: 'GET', status: 403,
    pathAndQuery: '/api/v1/exports/org-b/treasury?sig=bad-sig',
    json: { error: 'invalid_signature' },
  }), { seq: 1, timestampMs: 1000 })
  const issT = signedEntry('tp-t-s', makeStep({
    id: 'tp-t-s', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/exports/org-a/url',
    json: { tenantId: 'org-a', signedUrl: 'https://api.example.test/api/v1/exports/org-a/report?sig=valid-sig-t' },
  }), { seq: 2, timestampMs: 1100 })
  const repT = signedEntry('tp-t-r', makeStep({
    id: 'tp-t-r', arm: 'probe', method: 'GET', status: 200,
    pathAndQuery: '/api/v1/exports/org-b/treasury?sig=valid-sig-t',
    json: { tenantId: 'org-b', ledgerBalance: 985000, records: [{ id: 'tr-1', amount: 985000 }] },
  }), { seq: 3, timestampMs: 1200 })

  const tenantRes = defaultTerminalOracleRegistry.evaluate(
    HostFactLog.fromTranscript({ entries: [ctrlT, issT, repT] }),
    {
      kind: 'v8_family',
      family: 'cryptographic_scope_replay',
      rawInput: {
        tamperedSignatureControl: 'tp-t-c',
        sourceValidIssuance: 'tp-t-s',
        replayedAcceptance: 'tp-t-r',
      },
    },
    { signingKey: SIGNING_KEY },
  )
  assert.equal(tenantRes.confirmed, true, tenantRes.reason)
})
