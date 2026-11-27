// @kernel @fixes R3-12, R3-13
/**
 * Stream A (v8 M2 Kernel Fixes) Behavioral Regression Suite.
 *
 * Pure behavioral assertions (0 source-text regex assertions):
 *   1. Decoy FP guard: read-only metadata-only directory/document listings AND static web
 *      assets (`text/css`, `application/javascript`, `image/*`, `font/*`) MUST NOT satisfy
 *      cross-tenant confirmation, while genuine private document content & opaque non-asset
 *      plaintext exports still confirm cleanly.
 *   2. `dualAbacExempt` aligned with `allowDualCrossTenant`: mixed dual-tenant personas
 *      (`admin (org_a), member (org_b)`) succeed on legitimate cross-tenant target-tenant
 *      probes (`cross_tenant_export`, `cross_tenant_repo_theft`, `cross_tenant_partner_export`,
 *      `dual_tenant_abac`), while remaining strictly rejected on own `adminTenants`, ambiguous
 *      routes, and non-dual-tenant chains (`privilege_escalation`, `bfla`, `stale_privilege_use`,
 *      `bola`, `idor`).
 *   3. Host-observed `dual_tenant_abac` auto-hydration + clean 401/403 controls + Auto-DAG
 *      `async_pivot_binding` inference & Pass 1 non-stranding ancestor-cap rewiring (both TP
 *      confirm and FP reject invariants).
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { buildCompositeVerifyOptionsFromGrant } from '../src/server/agent-script-proof.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  analyzeCrossTenantTerminalEvidence,
  compileCausalChainFromTranscript,
  deriveHostDualTenantRawInput,
  isReadOnlyDirectoryOrMetadataImpact,
} from '../src/server/causal-proof-compiler.ts'
import {
  signHostRecord,
  verifyCompositeReceipt,
  type CompositeProofReceipt,
  type HostAsyncPollRecord,
  type HostSignedTranscript,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import type { ImpactStep } from '../src/server/oracle-invariants.ts'
import type { ResolvedPersona } from '../src/server/persona-vault.ts'

const ORIGIN = 'https://api.example.test'
const SIGNING_KEY = 'v8-m2-kernel-fixes-test-signing-key-0123456789abcdef'

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

function signedPoll(poll: Omit<HostAsyncPollRecord, 'hostSignature'>): HostAsyncPollRecord {
  return { ...poll, hostSignature: signHostRecord(poll, SIGNING_KEY) }
}

function makePersona(handle: string, roleLabel: string): ResolvedPersona {
  return {
    id: `p-${handle}`,
    handle,
    roleLabel,
    originAllowlist: [ORIGIN],
    authKind: 'bearer',
    headerName: 'Authorization',
    secret: `secret-${handle}-token`,
    canaryMarkers: [],
  }
}

// ============================================================================
// 1. Decoy FP Guard: Metadata-Only Listings & Static Web Assets (CSS/JS/Image/Font)
// ============================================================================

test('Fix 1a: rejects metadata-only directory/document listings on cross-tenant classes while confirming genuine private content', () => {
  const cap = 'cap:hop_1:ws_tok_1a'
  const h1 = signedEntry('m1-h1', makeStep({
    id: 'm1-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/workspaces/org_a/share-token',
    json: { token: 'share-tok-9988', workspace: 'org_a' },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [cap] })

  const ctrlDocs = signedEntry('m1-ctrl-docs', makeStep({
    id: 'm1-ctrl-docs', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/workspaces/org_b/docs',
    json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050 })

  const metaDocs = signedEntry('m1-meta-docs', makeStep({
    id: 'm1-meta-docs', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/workspaces/org_b/docs',
    json: { workspace: 'org_b', tenantId: 'org_b', docs: [{ id: 'doc-1', title: 'Q4 Plan', folder: 'finance' }, { id: 'doc-2', title: 'Handbook', folder: 'general' }] },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })

  const metaStub = signedEntry('m1-meta-stub', makeStep({
    id: 'm1-meta-stub', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/workspaces/org_b/docs',
    json: { workspace: 'org_b', tenantId: 'org_b', items: [{ id: 'it-1', name: 'Workspace Root', slug: 'org-b-root', mimeType: 'text/markdown', size: 2048, createdBy: 'alice', updatedAt: '2026-11-01T00:00:00Z' }] },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })

  assert.equal(isReadOnlyDirectoryOrMetadataImpact(metaDocs), true)
  assert.equal(isReadOnlyDirectoryOrMetadataImpact(metaStub), true)

  for (const [label, termEntry] of [['docs-listing', metaDocs], ['item-slug-stub', metaStub]] as const) {
    for (const vulnClass of ['cross_tenant_document_read', 'cross_tenant_read', 'dual_tenant_abac'] as const) {
      const receipt: CompositeProofReceipt = {
        chainId: `fix1a-${label}-${vulnClass}`,
        terminalVulnClass: vulnClass,
        hops: [
          { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/workspaces/org_a/share-token' }, exchangeIds: ['m1-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained share token', producedCapabilities: [cap], consumedCapabilities: [] },
          { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/workspaces/org_b/docs' }, exchangeIds: [termEntry.exchangeId], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Listed workspace document metadata', producedCapabilities: [], consumedCapabilities: [cap] },
        ],
        causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
        terminalImpact: {
          terminalHopId: 'hop_2',
          terminalExchangeId: termEntry.exchangeId,
          summary: 'Metadata-only workspace listing claimed as cross-tenant document read.',
          claimedImpact: 'Metadata-only workspace listing claimed as cross-tenant document read.',
          preChainControlExchangeIds: ['m1-ctrl-docs'],
          postChainReadbackExchangeIds: [],
        },
        replayMode: 'fresh_clean_replay',
      }
      const res = verifyCompositeReceipt(receipt, { entries: [h1, ctrlDocs, termEntry] }, {
        signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
      })
      assert.equal(res.confirmed, false, `${label}/${vulnClass} metadata-only listing MUST reject`)
      assert.equal(res.failedStage, 'terminal_impact')
    }
  }

  // Positive control: actual private document content confirms cleanly!
  const ctrlDocBody = signedEntry('m1-ctrl-body', makeStep({
    id: 'm1-ctrl-body', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/docs/doc-1',
    json: { error: 'forbidden' },
  }), { seq: 2, timestampMs: 1050 })
  const privateDoc = signedEntry('m1-private-doc', makeStep({
    id: 'm1-private-doc', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/docs/doc-1',
    json: { workspace: 'org_b', tenantId: 'org_b', id: 'doc-1', title: 'Q4 Plan', content: 'Confidential private org_b financial forecast.' },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })
  assert.equal(isReadOnlyDirectoryOrMetadataImpact(privateDoc), false)

  const okReceipt: CompositeProofReceipt = {
    chainId: 'fix1a-private-doc-ok',
    terminalVulnClass: 'cross_tenant_document_read',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/workspaces/org_a/share-token' }, exchangeIds: ['m1-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained share token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/docs/doc-1' }, exchangeIds: ['m1-private-doc'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read private foreign document body', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2',
      terminalExchangeId: 'm1-private-doc',
      summary: 'Read private org_b document content across tenant boundary.',
      claimedImpact: 'Read private org_b document content across tenant boundary.',
      preChainControlExchangeIds: ['m1-ctrl-body'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const okRes = verifyCompositeReceipt(okReceipt, { entries: [h1, ctrlDocBody, privateDoc] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(okRes.confirmed, true, `Genuine private document content must confirm, got: ${okRes.reason}`)
})

test('Fix 1b: excludes static web assets (CSS/JS/image/font) from opaquePlainTextMultiHop while keeping non-asset plaintext exports', () => {
  const cap = 'cap:hop_1:cache_key_1b'
  const h1 = signedEntry('m1b-h1', makeStep({
    id: 'm1b-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/cache/prime',
    json: { cacheKey: 'ck-99887766' },
  }), { seq: 1, timestampMs: 1000, emittedCapabilities: [cap] })

  for (const [label, pathAndQuery, contentType, body] of [
    ['css', '/static/theme.css', 'text/css; charset=utf-8', 'body { color: #222; background: #fff; }'],
    ['js', '/static/app.js', 'application/javascript', 'window.__THEME__ = "light";'],
    ['text-js', '/static/vendor.js', 'text/javascript; charset=utf-8', 'console.log("ok");'],
    ['font', '/static/ui.woff2', 'font/woff2', 'wOF2-binary-font-data'],
  ] as const) {
    const ctrl = signedEntry(`m1b-ctrl-${label}`, makeStep({
      id: `m1b-ctrl-${label}`, arm: 'control', method: 'GET', status: 403, pathAndQuery,
      json: { error: 'forbidden' },
    }), { seq: 2, timestampMs: 1050 })
    const assetEx = signedEntry(`m1b-ex-${label}`, makeStep({
      id: `m1b-ex-${label}`, arm: 'probe', method: 'GET', status: 200, pathAndQuery,
      responseHeaders: { 'content-type': contentType },
      body,
    }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })

    const analysis = analyzeCrossTenantTerminalEvidence(assetEx, new Set(['org_a']), false, true, [h1], false, true)
    assert.equal(analysis.crossTenantSatisfied, false, `${label} static asset must NOT satisfy crossTenantSatisfied`)

    const receipt: CompositeProofReceipt = {
      chainId: `fix1b-asset-${label}`,
      terminalVulnClass: 'cross_tenant_cache_bleed',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/cache/prime' }, exchangeIds: ['m1b-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed CDN cache', producedCapabilities: [cap], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'cdn', target: { origin: ORIGIN, method: 'GET', pathAndQuery }, exchangeIds: [assetEx.exchangeId], oobEventIds: [], browserTraceIds: [], claimedDelta: `Read cached ${label} asset`, producedCapabilities: [], consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        terminalExchangeId: assetEx.exchangeId,
        summary: `Cached ${label} static asset claimed as cross-tenant data bleed.`,
        claimedImpact: `Cached ${label} static asset claimed as cross-tenant data bleed.`,
        preChainControlExchangeIds: [ctrl.exchangeId],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(receipt, { entries: [h1, ctrl, assetEx] }, {
      signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
    })
    assert.equal(res.confirmed, false, `${label} static asset MUST reject cross_tenant_cache_bleed`)
    assert.equal(res.failedStage, 'terminal_impact')
  }

  // Positive control: genuine non-asset text/plain export body still satisfies opaquePlainTextMultiHop!
  const plainExport = signedEntry('m1b-plain-ok', makeStep({
    id: 'm1b-plain-ok', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/report-99.txt',
    responseHeaders: { 'content-type': 'text/plain; charset=utf-8' },
    body: 'PRIVATE LEDGER SUMMARY\nAccount 00419 balance 985000 USD\n',
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })
  const plainAnalysis = analyzeCrossTenantTerminalEvidence(plainExport, new Set(['org_a']), false, true, [h1], false, true)
  assert.equal(plainAnalysis.crossTenantSatisfied, true, 'non-asset text/plain multi-hop export must still satisfy crossTenantSatisfied')

  // Positive control: image/svg+xml export is NOT over-suppressed as static CSS/JS/font!
  const svgExport = signedEntry('m1b-svg-ok', makeStep({
    id: 'm1b-svg-ok', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/chart-99.svg',
    responseHeaders: { 'content-type': 'image/svg+xml' },
    body: '<svg xmlns="http://www.w3.org/2000/svg"><text>Q4 Revenue 985000</text></svg>',
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [cap] })
  const svgAnalysis = analyzeCrossTenantTerminalEvidence(svgExport, new Set(['org_a']), false, true, [h1], false, true)
  assert.equal(svgAnalysis.crossTenantSatisfied, true, 'SVG data export must not be over-suppressed')
})

// ============================================================================
// 2. dualAbacExempt Aligned With allowDualCrossTenant + Strict Fail-Closed Guards
// ============================================================================

test('Fix 2: dual_member succeeds on legitimate cross-tenant target-tenant probes and still fails closed on adminTenant, ambiguous routes, and non-dual classes', () => {
  const dualLabel = 'admin (org_a), member (org_b)'
  const grant: Pick<Grant, 'personas'> = {
    personas: new Map([
      ['dual_member', makePersona('dual_member', dualLabel)],
      ['member_a', makePersona('member_a', 'member (org_a)')],
      ['admin_a', makePersona('admin_a', 'admin (org_a)')],
    ]),
  }
  const grantOpts = buildCompositeVerifyOptionsFromGrant(grant)!
  assert.ok(grantOpts.dualTenantAbacPersonas?.includes('dual_member'))
  assert.ok(grantOpts.forbiddenShortcutPersonas?.includes('dual_member'))

  const cap = 'cap:hop_1:dual_prime_tok'
  const dualActor = { handle: 'dual_member', role: 'admin' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }

  const ctrlOrgB = signedEntry('f2-ctrl-orgb', makeStep({
    id: 'f2-ctrl-orgb', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/orgs/org_b/exports/full',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'dual_member', actorRoleLabel: dualLabel })

  const primeOrgA = signedEntry('f2-prime-orga', makeStep({
    id: 'f2-prime-orga', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/orgs/org_a/permissions/prime',
    actor: dualActor, json: { tenantId: 'org_a', primed: true },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: dualLabel, emittedCapabilities: [cap] })

  const readOrgB = signedEntry('f2-read-orgb', makeStep({
    id: 'f2-read-orgb', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/orgs/org_b/exports/full',
    actor: dualActor, json: { tenantId: 'org_b', rows: [{ id: 'rec-1', balanceCents: 440000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })

  // (a) Legitimate cross-tenant target-tenant probes succeed with grantOpts!
  for (const vulnClass of ['cross_tenant_export', 'cross_tenant_repo_theft', 'cross_tenant_partner_export', 'dual_tenant_abac'] as const) {
    const receipt: CompositeProofReceipt = {
      chainId: `fix2-allow-${vulnClass}`,
      terminalVulnClass: vulnClass,
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/permissions/prime' }, exchangeIds: ['f2-prime-orga'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed org_a permissions', producedCapabilities: [cap], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/exports/full' }, exchangeIds: ['f2-read-orgb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Exported org_b private records', producedCapabilities: [], consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        terminalExchangeId: 'f2-read-orgb',
        summary: `Dual-member cross-tenant probe confirmed for ${vulnClass} targeting org_b.`,
        claimedImpact: `Dual-member cross-tenant probe confirmed for ${vulnClass} targeting org_b.`,
        preChainControlExchangeIds: ['f2-ctrl-orgb'],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(receipt, { entries: [ctrlOrgB, primeOrgA, readOrgB] }, { ...grantOpts, signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, true, `dual_member on ${vulnClass} targeting non-admin org_b must confirm, got: ${res.reason}`)
  }

  // (b1) REJECT when dual_member hits its own adminTenant (org_a) on cross_tenant_export!
  const ctrlOrgA = signedEntry('f2-ctrl-orga', makeStep({
    id: 'f2-ctrl-orga', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/orgs/org_a/exports/full',
    actor: { handle: 'member_a', role: 'member', tenant: 'org_a', auth: 'bearer', sameSite: null }, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)' })
  const readOwnAdminOrgA = signedEntry('f2-read-orga', makeStep({
    id: 'f2-read-orga', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/orgs/org_a/exports/full',
    actor: dualActor, json: { tenantId: 'org_a', rows: [{ id: 'rec-a', balanceCents: 120000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })
  const adminRes = verifyCompositeReceipt({
    chainId: 'fix2-reject-own-admin',
    terminalVulnClass: 'cross_tenant_export',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/permissions/prime' }, exchangeIds: ['f2-prime-orga'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed org_a', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_a/exports/full' }, exchangeIds: ['f2-read-orga'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read own admin tenant', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'f2-read-orga',
      summary: 'Attempted to claim own admin tenant org_a export as cross-tenant.',
      claimedImpact: 'Attempted to claim own admin tenant org_a export as cross-tenant.',
      preChainControlExchangeIds: ['f2-ctrl-orga'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrlOrgA, primeOrgA, readOwnAdminOrgA] }, { ...grantOpts, signingKey: SIGNING_KEY })
  assert.equal(adminRes.confirmed, false, 'dual_member hitting own adminTenant MUST reject')
  assert.equal(adminRes.failedStage, 'attacker_provenance')

  // (b2) REJECT when dual_member hits an ambiguous route with zero host-bound tenant markers!
  const ctrlAmbig = signedEntry('f2-ctrl-ambig', makeStep({
    id: 'f2-ctrl-ambig', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/full',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'dual_member', actorRoleLabel: dualLabel })
  const readAmbig = signedEntry('f2-read-ambig', makeStep({
    id: 'f2-read-ambig', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/full',
    actor: dualActor, json: { rows: [{ id: 'rec-x', balanceCents: 99000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })
  const ambigRes = verifyCompositeReceipt({
    chainId: 'fix2-reject-ambig',
    terminalVulnClass: 'cross_tenant_export',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/permissions/prime' }, exchangeIds: ['f2-prime-orga'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/full' }, exchangeIds: ['f2-read-ambig'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read ambiguous export', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'f2-read-ambig',
      summary: 'Ambiguous route without host-bound tenant marker for dual_member.',
      claimedImpact: 'Ambiguous route without host-bound tenant marker for dual_member.',
      preChainControlExchangeIds: ['f2-ctrl-ambig'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrlAmbig, primeOrgA, readAmbig] }, { ...grantOpts, signingKey: SIGNING_KEY })
  assert.equal(ambigRes.confirmed, false, 'dual_member on ambiguous route MUST reject')
  assert.equal(ambigRes.failedStage, 'attacker_provenance')

  // (b3) REJECT when dual_member is used on non-dual-tenant classes!
  for (const forbiddenClass of ['privilege_escalation', 'bfla', 'stale_privilege_use', 'bola', 'idor'] as const) {
    const res = verifyCompositeReceipt({
      chainId: `fix2-reject-${forbiddenClass}`,
      terminalVulnClass: forbiddenClass,
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/permissions/prime' }, exchangeIds: ['f2-prime-orga'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed', producedCapabilities: [cap], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/orgs/org_b/exports/full' }, exchangeIds: ['f2-read-orgb'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read org_b', producedCapabilities: [], consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2', terminalExchangeId: 'f2-read-orgb',
        summary: `Non-dual class ${forbiddenClass} using dual_member shortcut.`,
        claimedImpact: `Non-dual class ${forbiddenClass} using dual_member shortcut.`,
        preChainControlExchangeIds: ['f2-ctrl-orgb'], postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }, { entries: [ctrlOrgB, primeOrgA, readOrgB] }, { ...grantOpts, signingKey: SIGNING_KEY })
    assert.equal(res.confirmed, false, `dual_member on ${forbiddenClass} MUST reject`)
    assert.equal(res.failedStage, 'attacker_provenance')
  }
})

// ============================================================================
// 3A. Host-Observed dual_tenant_abac Auto-Hydration & Clean 401/403 Controls
// ============================================================================

test('Fix 3a: dual_tenant_abac auto-hydrates from host-observed exchanges with omitted oracleInput and accepts clean 401/403 controls while rejecting FPs', () => {
  const dualLabel = 'admin (org_a), viewer (org_b)'
  const dualActor = { handle: 'dual_member', role: 'admin' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const cap = 'cap:hop_1:dual_auto_tok'

  const prime = signedEntry('d3-prime', makeStep({
    id: 'd3-prime', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/orgs/org_a/cache/prime',
    actor: dualActor, json: { tenantId: 'org_a', primed: true },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: dualLabel, emittedCapabilities: [cap] })

  const bled = signedEntry('d3-bled', makeStep({
    id: 'd3-bled', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/reports/billing',
    actor: dualActor, json: { tenantId: 'org_b', rows: [{ id: 'inv-9', amount: 88000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })

  // (a) Clean authenticated 401 AND 403 controls with explicit oracleFamily: 'dual_tenant_abac' AND omitted oracleInput -> auto-hydrates & CONFIRMS!
  for (const status of [401, 403] as const) {
    const ctrl = signedEntry(`d3-ctrl-${status}`, makeStep({
      id: `d3-ctrl-${status}`, arm: 'control', method: 'GET', status, pathAndQuery: '/api/v1/reports/billing',
      actor: dualActor, json: { error: status === 401 ? 'unauthorized' : 'forbidden' },
    }), { seq: 1, timestampMs: 900, actorPersona: 'dual_member', actorRoleLabel: dualLabel })

    const receipt: CompositeProofReceipt = {
      chainId: `fix3a-autohyd-${status}`,
      terminalVulnClass: 'dual_tenant_abac',
      hops: [
        { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/cache/prime' }, exchangeIds: ['d3-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed permission cache in org_a', producedCapabilities: [cap], consumedCapabilities: [] },
        { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/reports/billing' }, exchangeIds: ['d3-bled'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign org_b billing report', producedCapabilities: [], consumedCapabilities: [cap] },
      ],
      causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
      terminalImpact: {
        terminalHopId: 'hop_2',
        terminalExchangeId: 'd3-bled',
        summary: `Host-observed dual_tenant_abac auto-hydration with clean ${status} control.`,
        claimedImpact: `Host-observed dual_tenant_abac auto-hydration with clean ${status} control.`,
        oracleFamily: 'dual_tenant_abac',
        preChainControlExchangeIds: [ctrl.exchangeId],
        postChainReadbackExchangeIds: [],
      },
      replayMode: 'fresh_clean_replay',
    }
    const res = verifyCompositeReceipt(receipt, { entries: [ctrl, prime, bled] }, {
      signingKey: SIGNING_KEY,
      dualTenantAbacPersonas: ['dual_member'],
      forbiddenShortcutPersonas: ['dual_member'],
      attackerPersonas: ['member_a'],
      personaRoleLabels: { dual_member: dualLabel },
    })
    assert.equal(res.confirmed, true, `auto-hydrated dual_tenant_abac with clean ${status} control must confirm, got: ${res.reason}`)
    assert.equal(res.terminalOracleFamily, 'dual_tenant_abac')
  }

  // (b) Clean authenticated 401 control on non-cache-bleed 2-hop dual_tenant_abac chain (falls through to multiHopDualDag) -> CONFIRMS!
  const memberA = { handle: 'member_a', role: 'member' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const mCtrl401 = signedEntry('d3-m-ctrl401', makeStep({
    id: 'd3-m-ctrl401', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/api/v1/exports/data',
    actor: memberA, json: { error: 'token_scope_required' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)' })
  const mHop1 = signedEntry('d3-m-h1', makeStep({
    id: 'd3-m-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/exports/token',
    actor: memberA, json: { exportToken: 'tok-99887766' },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', emittedCapabilities: [cap] })
  const mHop2 = signedEntry('d3-m-h2', makeStep({
    id: 'd3-m-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/data',
    actor: memberA, json: { tenantId: 'org_b', rows: [{ id: 'r1', amount: 5000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', consumedCapabilities: [cap] })
  const res401 = verifyCompositeReceipt({
    chainId: 'fix3a-multihop-401',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/exports/token' }, exchangeIds: ['d3-m-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained export token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/data' }, exchangeIds: ['d3-m-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign tenant export', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'd3-m-h2',
      summary: 'Multi-hop dual_tenant_abac confirmed with clean authenticated 401 control.',
      claimedImpact: 'Multi-hop dual_tenant_abac confirmed with clean authenticated 401 control.',
      preChainControlExchangeIds: ['d3-m-ctrl401'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [mCtrl401, mHop1, mHop2] }, { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] })
  assert.equal(res401.confirmed, true, `multiHopDualDag with clean authenticated 401 must confirm, got: ${res401.reason}`)

  // (c) FP Rejects: missing denied control, unauthenticated bare 401, own-tenant-only data!
  const missingCtrlRes = verifyCompositeReceipt({
    chainId: 'fix3a-fp-no-ctrl',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/cache/prime' }, exchangeIds: ['d3-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/reports/billing' }, exchangeIds: ['d3-bled'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read billing', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'd3-bled',
      summary: 'Omitted denied control on dual_tenant_abac chain.',
      claimedImpact: 'Omitted denied control on dual_tenant_abac chain.',
      oracleFamily: 'dual_tenant_abac',
      preChainControlExchangeIds: [], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [prime, bled] }, {
    signingKey: SIGNING_KEY, dualTenantAbacPersonas: ['dual_member'], forbiddenShortcutPersonas: ['dual_member'],
    attackerPersonas: ['member_a'], personaRoleLabels: { dual_member: dualLabel },
  })
  assert.equal(missingCtrlRes.confirmed, false, 'missing denied control must reject')
  assert.equal(missingCtrlRes.failedStage, 'terminal_impact')

  const anon401 = signedEntry('d3-anon-401', makeStep({
    id: 'd3-anon-401', arm: 'control', method: 'GET', status: 401, pathAndQuery: '/api/v1/exports/data',
    actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null }, json: { error: 'unauthorized' },
  }), { seq: 1, timestampMs: 900, actorPersona: null, actorRoleLabel: null })
  const anon401Res = verifyCompositeReceipt({
    chainId: 'fix3a-fp-anon-401',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/exports/token' }, exchangeIds: ['d3-m-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/data' }, exchangeIds: ['d3-m-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read data', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'd3-m-h2',
      summary: 'Unauthenticated 401 control must not satisfy dual_tenant_abac.',
      claimedImpact: 'Unauthenticated 401 control must not satisfy dual_tenant_abac.',
      preChainControlExchangeIds: ['d3-anon-401'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [anon401, mHop1, mHop2] }, { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] })
  assert.equal(anon401Res.confirmed, false, 'unauthenticated bare 401 must still reject')
  assert.equal(anon401Res.failedStage, 'terminal_impact')

  const ownOnly = signedEntry('d3-own-only', makeStep({
    id: 'd3-own-only', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/data',
    actor: memberA, json: { tenantId: 'org_a', rows: [{ id: 'own-1', amount: 100 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', consumedCapabilities: [cap] })
  const ownOnlyRes = verifyCompositeReceipt({
    chainId: 'fix3a-fp-own-only',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/exports/token' }, exchangeIds: ['d3-m-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/data' }, exchangeIds: ['d3-own-only'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read own data', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'd3-own-only',
      summary: 'Own-tenant-only data must reject dual_tenant_abac.',
      claimedImpact: 'Own-tenant-only data must reject dual_tenant_abac.',
      preChainControlExchangeIds: ['d3-m-ctrl401'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [mCtrl401, mHop1, ownOnly] }, { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] })
  assert.equal(ownOnlyRes.confirmed, false, 'own-tenant-only response must reject')
  assert.equal(ownOnlyRes.failedStage, 'terminal_impact')
})

// ============================================================================
// 3B. Auto-DAG async_pivot_binding Inference & Pass 1 Orphan Prevention
// ============================================================================

test('Fix 3b: Auto-DAG infers async_pivot_binding (poll_convergence & async_job) and Pass 1 ancestor-cap rewire does not strand hop_2', () => {
  const sessionCap = 'cap:hop_1:session_auth_tok'
  const jobId = 'job_7f6e5d4c3b2a'

  // Case 1: 3-hop chain where hop_1 emits sessionCap, hop_2 triggers an async export job,
  // hop_3 awaits poll convergence via await_async, and worker mis-anchored hop_2 -> hop_3 on sessionCap!
  const ctrl = signedEntry('ap-ctrl', makeStep({
    id: 'ap-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: `/api/v1/jobs/${jobId}/result`,
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })
  const h1 = signedEntry('ap-h1', makeStep({
    id: 'ap-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/auth/session',
    json: { session: 'sess-a1b2c3d4' },
  }), { seq: 2, timestampMs: 1000, emittedCapabilities: [sessionCap] })
  const h2 = signedEntry('ap-h2', makeStep({
    id: 'ap-h2', arm: 'probe', method: 'POST', status: 202, pathAndQuery: '/api/v1/jobs/export',
    json: { jobId, status: 'queued' },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [sessionCap], entityId: jobId, correlationIds: [jobId] })
  const h3 = signedEntry('ap-h3', makeStep({
    id: 'ap-h3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: `/api/v1/jobs/${jobId}/result`,
    json: { jobId, tenantId: 'org_b', rows: [{ id: 'r1', balanceCents: 650000 }] },
  }), { seq: 4, timestampMs: 1300, consumedCapabilities: [sessionCap], entityId: jobId, correlationIds: [jobId] })
  const poll = signedPoll({
    id: 'poll-async-1',
    triggerExchangeId: 'ap-h2',
    tTriggerMs: 1100,
    tObservedMs: 1300,
    converged: true,
    correlationIds: [jobId],
    entityId: jobId,
  })

  const transcriptPoll: HostSignedTranscript = { entries: [ctrl, h1, h2, h3], asyncPollRecords: [poll] }
  const rewiredAsyncReceipt: CompositeProofReceipt = {
    chainId: 'fix3b-rewire-async-poll',
    terminalVulnClass: 'cross_tenant_export',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/auth/session' }, exchangeIds: ['ap-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained session token', producedCapabilities: [sessionCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'async_job', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/jobs/export' }, exchangeIds: ['ap-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Queued async export job', producedCapabilities: [], consumedCapabilities: [sessionCap], entityId: jobId },
      { hopId: 'hop_3', surface: 'async_job', target: { origin: ORIGIN, method: 'GET', pathAndQuery: `/api/v1/jobs/${jobId}/result` }, exchangeIds: ['ap-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Collected converged foreign export', producedCapabilities: [], consumedCapabilities: [sessionCap], entityId: jobId },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: sessionCap },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: sessionCap },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      terminalExchangeId: 'ap-h3',
      summary: 'Async export job rewired without stranding hop_2 via poll_convergence.',
      claimedImpact: 'Async export job rewired without stranding hop_2 via poll_convergence.',
      preChainControlExchangeIds: ['ap-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }

  const compiledPoll = compileCausalChainFromTranscript(rewiredAsyncReceipt, transcriptPoll)
  assert.equal(compiledPoll.rewiredEdges.length, 1)
  assert.ok(
    compiledPoll.inferredEdges.some(e => e.kind === 'async_pivot_binding' && e.fromHopId === 'hop_2' && e.toHopId === 'hop_3' && e.channel === 'poll_convergence' && e.pollRecordId === 'poll-async-1'),
    `Expected inferred async_pivot_binding (poll_convergence) hop_2->hop_3, got ${JSON.stringify(compiledPoll.inferredEdges)}`,
  )
  const verifiedPoll = verifyCompositeReceipt(rewiredAsyncReceipt, transcriptPoll, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(verifiedPoll.confirmed, true, `Async poll chain must confirm without stranding hop_2, got: ${verifiedPoll.reason}`)

  // Case 2: Pure async_job Auto-DAG inference (no HostAsyncPollRecord, no causalEdges declared!)
  const zeroEdgesReceipt: CompositeProofReceipt = {
    ...rewiredAsyncReceipt,
    chainId: 'fix3b-autodag-async-job',
    hops: [rewiredAsyncReceipt.hops[1]!, rewiredAsyncReceipt.hops[2]!],
    causalEdges: [],
  }
  const transcriptJobOnly: HostSignedTranscript = { entries: [ctrl, h1, h2, h3] }
  const compiledJob = compileCausalChainFromTranscript(zeroEdgesReceipt, transcriptJobOnly)
  assert.ok(
    compiledJob.inferredEdges.some(e => e.kind === 'async_pivot_binding' && e.fromHopId === 'hop_2' && e.toHopId === 'hop_3' && e.channel === 'async_job'),
    `Expected inferred async_pivot_binding (async_job) hop_2->hop_3, got ${JSON.stringify(compiledJob.inferredEdges)}`,
  )
  const verifiedJob = verifyCompositeReceipt(zeroEdgesReceipt, transcriptJobOnly, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(verifiedJob.confirmed, true, `Auto-DAG async_job chain must confirm, got: ${verifiedJob.reason}`)

  // Case 3: Pass 1 ancestor-cap rewiring where hop_2 is a state-mutating cache/role prime WITHOUT shared literal entityId
  // must NOT strand hop_2 when a clean pre-chain denied control exists on hop_3!
  const stCtrl = signedEntry('st-ctrl', makeStep({
    id: 'st-ctrl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/reports/treasury',
    json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900 })
  const stH1 = signedEntry('st-h1', makeStep({
    id: 'st-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/auth/session',
    json: { session: 'sess-state-1122' },
  }), { seq: 2, timestampMs: 1000, emittedCapabilities: [sessionCap] })
  const stH2 = signedEntry('st-h2', makeStep({
    id: 'st-h2', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/permissions/sync',
    json: { synced: true },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [sessionCap] })
  const stH3 = signedEntry('st-h3', makeStep({
    id: 'st-h3', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/reports/treasury',
    json: { tenantId: 'org_b', rows: [{ id: 'tr-1', balanceCents: 910000 }] },
  }), { seq: 4, timestampMs: 1200, consumedCapabilities: [sessionCap] })

  const rewiredStateReceipt: CompositeProofReceipt = {
    chainId: 'fix3b-rewire-logical-state',
    terminalVulnClass: 'cross_tenant_export',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/auth/session' }, exchangeIds: ['st-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained session', producedCapabilities: [sessionCap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/permissions/sync' }, exchangeIds: ['st-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Mutated permission sync state', producedCapabilities: [], consumedCapabilities: [sessionCap] },
      { hopId: 'hop_3', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/reports/treasury' }, exchangeIds: ['st-h3'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read foreign treasury report', producedCapabilities: [], consumedCapabilities: [sessionCap] },
    ],
    causalEdges: [
      { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: sessionCap },
      { kind: 'value_binding', fromHopId: 'hop_2', toHopId: 'hop_3', capabilityHandle: sessionCap },
    ],
    terminalImpact: {
      terminalHopId: 'hop_3',
      terminalExchangeId: 'st-h3',
      summary: 'Mutating hop_2 stays connected via state_transition_binding after ancestor-cap rewire.',
      claimedImpact: 'Mutating hop_2 stays connected via state_transition_binding after ancestor-cap rewire.',
      preChainControlExchangeIds: ['st-ctrl'],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }
  const verifiedState = verifyCompositeReceipt(rewiredStateReceipt, { entries: [stCtrl, stH1, stH2, stH3] }, {
    signingKey: SIGNING_KEY, attackerPersonas: ['member_a'],
  })
  assert.equal(verifiedState.confirmed, true, `Mutating hop_2 after Pass 1 rewire must confirm without stranding, got: ${verifiedState.reason}`)
  assert.ok(verifiedState.verifiedEdges.some(e => e.kind === 'state_transition_binding' && e.fromHopId === 'hop_2' && e.toHopId === 'hop_3' && e.verified))

  // Case 4 (negative): an unrelated read-only GET hop_2 with no causal link MUST STILL fail dag_topology!
  const roH2 = signedEntry('st-ro-h2', makeStep({
    id: 'st-ro-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/health',
    json: { status: 'ok' },
  }), { seq: 3, timestampMs: 1100, consumedCapabilities: [sessionCap] })
  const orphanRes = verifyCompositeReceipt({
    ...rewiredStateReceipt,
    chainId: 'fix3b-reject-unrelated-ro-hop2',
    hops: [
      rewiredStateReceipt.hops[0]!,
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/health' }, exchangeIds: ['st-ro-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Unrelated health check', producedCapabilities: [], consumedCapabilities: [sessionCap] },
      rewiredStateReceipt.hops[2]!,
    ],
  }, { entries: [stCtrl, stH1, roH2, stH3] }, { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] })
  assert.equal(orphanRes.confirmed, false, 'Unrelated read-only hop_2 must not receive a fabricated causal edge')
  assert.equal(orphanRes.failedStage, 'dag_topology')
})

// ============================================================================
// 4. R3-05 Independent Review Hardening Guards (Findings 1-4)
// ============================================================================

test('R3-05 review guards: pre-effInput listing guard, R4-C-5 URL stripping, strict deriveHostDualTenantRawInput control/transfer checks, and strict 401/single-tenant multiHopDualDag', () => {
  const dualLabel = 'admin (org_a), viewer (org_b)'
  const dualActor = { handle: 'dual_member', role: 'admin' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const otherActor = { handle: 'other_b', role: 'member' as const, tenant: 'org_b', auth: 'bearer' as const, sameSite: null }
  const cap = 'cap:hop_1:r305_tok'

  const prime = signedEntry('r5-prime', makeStep({
    id: 'r5-prime', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/orgs/org_a/cache/prime',
    actor: dualActor, json: { tenantId: 'org_a', primed: true },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: dualLabel, emittedCapabilities: [cap] })

  // Finding 1: Host-derived dual_org_cache_bleed on a metadata-only listing MUST reject BEFORE effInput!
  const ctrlList = signedEntry('r5-ctrl-list', makeStep({
    id: 'r5-ctrl-list', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/docs',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'dual_member', actorRoleLabel: dualLabel })
  const bledList = signedEntry('r5-bled-list', makeStep({
    id: 'r5-bled-list', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/docs',
    actor: dualActor, json: { workspace: 'org_b', tenantId: 'org_b', docs: [{ id: 'd1', title: 'Overview', folder: 'general', mimeType: 'text/plain', size: 120 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })
  const listRes = verifyCompositeReceipt({
    chainId: 'r305-f1-host-derived-metadata-listing',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/orgs/org_a/cache/prime' }, exchangeIds: ['r5-prime'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Primed org_a', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/docs' }, exchangeIds: ['r5-bled-list'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read metadata listing', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'r5-bled-list',
      summary: 'Host-derived dual_org_cache_bleed on metadata-only listing must reject.',
      claimedImpact: 'Host-derived dual_org_cache_bleed on metadata-only listing must reject.',
      oracleFamily: 'dual_tenant_abac',
      preChainControlExchangeIds: ['r5-ctrl-list'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [ctrlList, prime, bledList] }, {
    signingKey: SIGNING_KEY, dualTenantAbacPersonas: ['dual_member'], forbiddenShortcutPersonas: ['dual_member'],
    attackerPersonas: ['member_a'], personaRoleLabels: { dual_member: dualLabel },
  })
  assert.equal(listRes.confirmed, false, 'Finding 1: host-derived dual_org_cache_bleed on metadata listing must reject')
  assert.equal(listRes.failedStage, 'terminal_impact')

  // Finding 2: R4-C-5 URL-token stripping preserved in deriveHostDualTenantRawInput even with content/body keys!
  const ctrlRefl = signedEntry('r5-ctrl-refl', makeStep({
    id: 'r5-ctrl-refl', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/orgs/org_b/reports',
    actor: dualActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'dual_member', actorRoleLabel: dualLabel })
  const bledRefl = signedEntry('r5-bled-refl', makeStep({
    id: 'r5-bled-refl', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/orgs/org_b/reports',
    actor: dualActor, json: { tenantId: 'org_b', text: 'ok' },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })
  assert.equal(
    deriveHostDualTenantRawInput(
      { entriesById: new Map([ctrlRefl, prime, bledRefl].map(e => [e.exchangeId, e])), personaRoleLabels: { dual_member: dualLabel } },
      { preChainControlExchangeIds: ['r5-ctrl-refl'], termHopExchangeIds: ['r5-bled-refl'], postChainReadbackExchangeIds: [], citedExchangeIds: ['r5-prime', 'r5-bled-refl'], personaRoleLabels: { dual_member: dualLabel } },
    ),
    null,
    'Finding 2: URL-reflected tenant token must stay stripped in deriveHostDualTenantRawInput',
  )

  // Finding 3: Cross-actor 403, post-hoc 403 on cross_org_transfer, and empty-route control all return null!
  const otherCtrl403 = signedEntry('r5-other-403', makeStep({
    id: 'r5-other-403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/reports/billing',
    actor: otherActor, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'other_b', actorRoleLabel: 'member (org_b)' })
  const bledBill = signedEntry('r5-bled-bill', makeStep({
    id: 'r5-bled-bill', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/reports/billing',
    actor: dualActor, json: { tenantId: 'org_b', rows: [{ id: 'r1', amount: 500 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'dual_member', actorRoleLabel: dualLabel, consumedCapabilities: [cap] })
  assert.equal(
    deriveHostDualTenantRawInput(
      { entriesById: new Map([otherCtrl403, prime, bledBill].map(e => [e.exchangeId, e])), personaRoleLabels: { dual_member: dualLabel } },
      { preChainControlExchangeIds: ['r5-other-403'], termHopExchangeIds: ['r5-bled-bill'], postChainReadbackExchangeIds: [], citedExchangeIds: ['r5-prime', 'r5-bled-bill'], personaRoleLabels: { dual_member: dualLabel } },
    ),
    null,
    'Finding 3a: cross-actor 403 must never be accepted as baseline',
  )

  const postHocCtrl = signedEntry('r5-posthoc-403', makeStep({
    id: 'r5-posthoc-403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/assets/ent-7',
    actor: { handle: 'dual_member', role: 'viewer', tenant: 'org_b', auth: 'bearer', sameSite: null }, json: { error: 'forbidden' },
  }), { seq: 4, timestampMs: 1500, actorPersona: 'dual_member', actorRoleLabel: dualLabel, entityId: 'ent-7' })
  const xferEx = signedEntry('r5-xfer', makeStep({
    id: 'r5-xfer', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/assets/ent-7/transfer',
    actor: dualActor, json: { id: 'ent-7', transferred: true },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'dual_member', actorRoleLabel: dualLabel, entityId: 'ent-7' })
  const rbEx = signedEntry('r5-rb', makeStep({
    id: 'r5-rb', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/assets/ent-7',
    actor: dualActor, json: { id: 'ent-7', ownerTenantId: 'org_a', amount: 4200 },
  }), { seq: 3, timestampMs: 1200, actorPersona: 'dual_member', actorRoleLabel: dualLabel, entityId: 'ent-7' })
  assert.equal(
    deriveHostDualTenantRawInput(
      { entriesById: new Map([postHocCtrl, xferEx, rbEx].map(e => [e.exchangeId, e])), personaRoleLabels: { dual_member: dualLabel } },
      { preChainControlExchangeIds: ['r5-posthoc-403'], termHopExchangeIds: ['r5-xfer'], postChainReadbackExchangeIds: ['r5-rb'], citedExchangeIds: ['r5-xfer'], personaRoleLabels: { dual_member: dualLabel } },
    ),
    null,
    'Finding 3b: post-hoc 403 after transfer must never be accepted as baseline',
  )

  // Finding 4: (a) 401 control for persona that NEVER succeeded on another hop in chain MUST reject;
  //            (b) single-tenant persona stamping explicit oracleFamily: 'dual_tenant_abac' without oracleInput MUST reject!
  const memberA = { handle: 'member_a', role: 'member' as const, tenant: 'org_a', auth: 'bearer' as const, sameSite: null }
  const mCtrl403 = signedEntry('r5-m-403', makeStep({
    id: 'r5-m-403', arm: 'control', method: 'GET', status: 403, pathAndQuery: '/api/v1/exports/data',
    actor: memberA, json: { error: 'forbidden' },
  }), { seq: 1, timestampMs: 900, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)' })
  const mH1 = signedEntry('r5-m-h1', makeStep({
    id: 'r5-m-h1', arm: 'probe', method: 'POST', status: 200, pathAndQuery: '/api/v1/exports/token',
    actor: memberA, json: { exportToken: 'tok-r305-1122' },
  }), { seq: 2, timestampMs: 1000, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', emittedCapabilities: [cap] })
  const mH2 = signedEntry('r5-m-h2', makeStep({
    id: 'r5-m-h2', arm: 'probe', method: 'GET', status: 200, pathAndQuery: '/api/v1/exports/data',
    actor: memberA, json: { tenantId: 'org_b', rows: [{ id: 'r1', amount: 5000 }] },
  }), { seq: 3, timestampMs: 1100, actorPersona: 'member_a', actorRoleLabel: 'member (org_a)', consumedCapabilities: [cap] })

  const singleTenantExplicitRes = verifyCompositeReceipt({
    chainId: 'r305-f4-single-tenant-explicit-family',
    terminalVulnClass: 'dual_tenant_abac',
    hops: [
      { hopId: 'hop_1', surface: 'http', target: { origin: ORIGIN, method: 'POST', pathAndQuery: '/api/v1/exports/token' }, exchangeIds: ['r5-m-h1'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Obtained token', producedCapabilities: [cap], consumedCapabilities: [] },
      { hopId: 'hop_2', surface: 'http', target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/v1/exports/data' }, exchangeIds: ['r5-m-h2'], oobEventIds: [], browserTraceIds: [], claimedDelta: 'Read org_b data', producedCapabilities: [], consumedCapabilities: [cap] },
    ],
    causalEdges: [{ kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: cap }],
    terminalImpact: {
      terminalHopId: 'hop_2', terminalExchangeId: 'r5-m-h2',
      summary: 'Single-tenant persona claiming explicit oracleFamily dual_tenant_abac without oracleInput.',
      claimedImpact: 'Single-tenant persona claiming explicit oracleFamily dual_tenant_abac without oracleInput.',
      oracleFamily: 'dual_tenant_abac',
      preChainControlExchangeIds: ['r5-m-403'], postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  }, { entries: [mCtrl403, mH1, mH2] }, { signingKey: SIGNING_KEY, attackerPersonas: ['member_a'] })
  assert.equal(singleTenantExplicitRes.confirmed, false, 'Finding 4: single-tenant persona must not confirm explicit oracleFamily dual_tenant_abac without oracleInput/dual-tenant role')
  assert.equal(singleTenantExplicitRes.failedStage, 'terminal_impact')
})
