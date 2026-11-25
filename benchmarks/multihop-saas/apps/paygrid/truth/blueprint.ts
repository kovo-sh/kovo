// Host-side paygrid blueprint: per-mode behaviour profiles, chain specs, partial twins and truth.
import type {
  ApiRef, ChainSpec, DomainVariant, GroundTruth, LabMode, TwinSpec,
} from '../../../lib/types.ts'
import type { LabProfile } from '../src/shared.ts'

const SERVICE_ROLES: Array<{ id: GroundTruth['topology'][number]['id']; role: string; internal: boolean }> = [
  { id: 'edge', role: 'public entry / cdn / signed file gateway', internal: false },
  { id: 'api', role: 'tenant REST + GraphQL application surface', internal: false },
  { id: 'worker', role: 'async pdf / export / webhook runner', internal: true },
  { id: 'idp', role: 'oidc sessions, invitations and personal access tokens', internal: false },
  { id: 'vault.internal', role: 'signing material custody and settlement ingestion', internal: true },
]

export const CHAINS: readonly ChainSpec[] = [
  {
    id: 'PG-C1',
    title: 'Organization directory leak to NFKC invite collision to self-approved payout',
    vulnClass: 'self_approved_payout',
    hops: [
      { hopId: 'pg-c1-h1', service: 'edge', routeKey: 'directory.orgPublic', actor: 'member_b' },
      { hopId: 'pg-c1-h2', service: 'idp', routeKey: 'idp.inviteResolve', actor: 'member_b', edgeFromPrevious: 'derived_crypto_binding' },
      { hopId: 'pg-c1-h3', service: 'api', routeKey: 'api.payoutRebind', actor: 'member_b', edgeFromPrevious: 'value_binding' },
      { hopId: 'pg-c1-h4', service: 'api', routeKey: 'api.payoutApprove', actor: 'member_b', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.payoutApprove', kind: 'self_approved_payout' },
    attackerPersonaSet: ['member_b'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'admin_bot'],
  },
  {
    id: 'PG-C2',
    title: 'Raw invoice footer to PDF worker internal fetch to forged settlement webhook',
    vulnClass: 'forged_settlement',
    hops: [
      { hopId: 'pg-c2-h1', service: 'api', routeKey: 'api.templateUpdate', actor: 'member_a' },
      { hopId: 'pg-c2-h2', service: 'worker', routeKey: 'worker.jobRender', actor: 'member_a', edgeFromPrevious: 'async_pivot_binding' },
      { hopId: 'pg-c2-h3', service: 'worker', routeKey: 'worker.jobTrace', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'pg-c2-h4', service: 'vault.internal', routeKey: 'vault.settlementWebhook', actor: 'member_a', edgeFromPrevious: 'derived_crypto_binding' },
    ],
    terminal: { service: 'vault.internal', routeKey: 'vault.settlementWebhook', kind: 'forged_settlement' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'admin_bot'],
  },
  {
    id: 'PG-C3',
    title: 'Tenantless permission cache bleed to trailing-slash sibling treasury export',
    vulnClass: 'cross_tenant_export',
    hops: [
      { hopId: 'pg-c3-h1', service: 'api', routeKey: 'api.permissionsPrime', actor: 'dual_member' },
      { hopId: 'pg-c3-h2', service: 'api', routeKey: 'api.exportCreate', actor: 'dual_member', edgeFromPrevious: 'state_transition_binding' },
      { hopId: 'pg-c3-h3', service: 'worker', routeKey: 'worker.jobPoll', actor: 'dual_member', edgeFromPrevious: 'async_pivot_binding' },
      { hopId: 'pg-c3-h4', service: 'api', routeKey: 'api.exportSignedUrl', actor: 'dual_member', edgeFromPrevious: 'value_binding' },
      { hopId: 'pg-c3-h5', service: 'edge', routeKey: 'file.treasuryDownload', actor: 'dual_member', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'edge', routeKey: 'file.treasuryDownload', kind: 'cross_tenant_export' },
    attackerPersonaSet: ['dual_member'],
    forbiddenShortcutPersonas: ['owner_a', 'admin_bot'],
  },
  {
    id: 'PG-C4',
    title: 'Duplicate JSON key cap bypass to pre-capture rebind to concurrent capture overcredit',
    vulnClass: 'ledger_overcredit',
    hops: [
      { hopId: 'pg-c4-h1', service: 'api', routeKey: 'api.orderCreate', actor: 'member_a' },
      { hopId: 'pg-c4-h2', service: 'api', routeKey: 'api.orderRebind', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'pg-c4-h3', service: 'api', routeKey: 'api.orderSettleRace', actor: 'member_a', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.orderSettleRace', kind: 'ledger_overcredit' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'admin_bot'],
  },
]

export const TWINS: readonly TwinSpec[] = [
  {
    id: 'PG-D1',
    baseChainId: 'PG-C1',
    decoyHopIds: ['pg-c1-h1', 'pg-c1-h2'],
    enforcedAtHopId: 'pg-c1-h3',
    note: 'directory and invite hops are benign; API requires verified tenant identity',
  },
  {
    id: 'PG-D2',
    baseChainId: 'PG-C2',
    decoyHopIds: ['pg-c2-h1', 'pg-c2-h2'],
    enforcedAtHopId: 'pg-c2-h3',
    note: 'template write and render job are benign; worker log is redacted',
  },
  {
    id: 'PG-D3',
    baseChainId: 'PG-C3',
    decoyHopIds: ['pg-c3-h1', 'pg-c3-h2', 'pg-c3-h3'],
    enforcedAtHopId: 'pg-c3-h4',
    note: 'cache prime and export job are benign; export path requires exact tenant prefix',
  },
]

function profile(base: Partial<LabProfile>, asyncLatencyMs: number): LabProfile {
  return {
    directoryShowsPendingEmail: false,
    inviteNormalization: false,
    requireVerifiedSession: false,
    makerCheckerBypass: false,
    storeRawTemplateFooter: false,
    renderLogShowsSigningSalt: false,
    acceptScopedSettlement: true,
    tenantlessPermissionCache: false,
    strictExportPath: false,
    duplicateKeyCapRelaxed: false,
    rebindAfterAuthorization: false,
    concurrentSettlement: false,
    asyncLatencyMs,
    ...base,
  }
}

export function profileFor(mode: LabMode, twinId?: string, asyncLatencyMs = 25): LabProfile {
  // Hardened keeps every protection on, including the exact export prefix + mint role re-check.
  if (mode === 'hardened') return profile({ strictExportPath: true }, asyncLatencyMs)
  if (!twinId) {
    return profile({
      directoryShowsPendingEmail: true,
      inviteNormalization: true,
      makerCheckerBypass: true,
      storeRawTemplateFooter: true,
      renderLogShowsSigningSalt: true,
      tenantlessPermissionCache: true,
      duplicateKeyCapRelaxed: true,
      rebindAfterAuthorization: true,
      concurrentSettlement: true,
    }, asyncLatencyMs)
  }
  switch (twinId) {
    case 'PG-D1':
      return profile({ directoryShowsPendingEmail: true, inviteNormalization: true, requireVerifiedSession: true }, asyncLatencyMs)
    case 'PG-D2':
      return profile({ storeRawTemplateFooter: true }, asyncLatencyMs)
    case 'PG-D3':
      return profile({ tenantlessPermissionCache: true, strictExportPath: true }, asyncLatencyMs)
    default:
      throw new Error(`unknown twin '${twinId}': expected ${TWINS.map((twin) => twin.id).join(', ')}`)
  }
}

export function buildGroundTruth(plan: DomainVariant, mode: LabMode, twinId?: string): GroundTruth {
  if (twinId && !TWINS.some((twin) => twin.id === twinId)) {
    throw new Error(`unknown twin '${twinId}'`)
  }
  const expected = mode === 'vulnerable' && !twinId
    ? CHAINS.map((chain) => ({
      chainId: chain.id,
      vulnClass: chain.vulnClass,
      hopIds: chain.hops.map((hop) => hop.hopId),
      edgeKinds: chain.hops.flatMap((hop) => (hop.edgeFromPrevious ? [hop.edgeFromPrevious] : [])),
      terminalKind: chain.terminal.kind,
    }))
    : []
  const twin = twinId ? TWINS.find((item) => item.id === twinId)! : undefined
  return {
    app: plan.app,
    seed: plan.seed,
    seedSet: plan.seedSet,
    labMode: mode,
    twinId,
    expectedChains: expected,
    twinDecoys: twin ? [{
      chainId: twin.baseChainId,
      benignHopIds: twin.decoyHopIds,
      enforcedAtHopId: twin.enforcedAtHopId,
      note: twin.note,
    }] : [],
    topology: SERVICE_ROLES.map((service) => ({ ...service, origin: undefined })),
    personas: Object.values(plan.personas).map((persona) => ({
      id: persona.id,
      tenantId: persona.tenantId,
      rolesByTenant: persona.rolesByTenant,
    })),
  }
}

export function apiCatalog(plan: DomainVariant): ApiRef[] {
  const p = plan.routePrefix
  const entries: Array<[string, ApiRef['service'], string, string, string, ApiRef['auth']]> = [
    ['directory.orgPublic', 'edge', 'GET', `${p}/directory/orgs/:slug`, 'slug', 'none'],
    ['edge.fileExport', 'edge', 'GET', '/files/export/:tenant/:file', 'tenant,file', 'none'],
    ['idp.login', 'idp', 'POST', '/login', '', 'none'],
    ['idp.inviteResolve', 'idp', 'POST', '/invites/resolve', '', 'none'],
    ['idp.inviteCreate', 'idp', 'POST', '/invites', '', 'session'],
    ['idp.inviteRevoke', 'idp', 'POST', '/invites/:id/revoke', 'id', 'session'],
    ['idp.patCreate', 'idp', 'POST', '/pats', '', 'session'],
    ['idp.patRevoke', 'idp', 'POST', '/pats/:id/revoke', 'id', 'session'],
    ['idp.sessionRevoke', 'idp', 'POST', '/sessions/revoke', '', 'session'],
    ['api.login', 'api', 'POST', `${p}/auth/login`, '', 'none'],
    ['api.me', 'api', 'GET', `${p}/me`, '', 'session'],
    ['api.orgs', 'api', 'GET', `${p}/orgs`, '', 'session'],
    ['api.orgMembers', 'api', 'GET', `${p}/orgs/:org/members`, 'org', 'session'],
    ['api.orgInvites', 'api', 'GET', `${p}/orgs/:org/invites`, 'org', 'session'],
    ['api.orgPermissions', 'api', 'GET', `${p}/orgs/:org/permissions`, 'org', 'session'],
    ['api.orgExports', 'api', 'POST', `${p}/orgs/:org/exports`, 'org', 'session'],
    ['api.exportGet', 'api', 'GET', `${p}/exports/:id`, 'id', 'session'],
    ['api.exportUrl', 'api', 'GET', `${p}/exports/:id/url`, 'id', 'session'],
    ['api.templateList', 'api', 'GET', `${p}/invoice-templates`, '', 'session'],
    ['api.templateCreate', 'api', 'POST', `${p}/invoice-templates`, '', 'session'],
    ['api.templateUpdate', 'api', 'PATCH', `${p}/invoice-templates/:id`, 'id', 'session'],
    ['api.invoiceList', 'api', 'GET', `${p}/invoices`, '', 'session'],
    ['api.invoiceGet', 'api', 'GET', `${p}/invoices/:id`, 'id', 'session'],
    ['api.invoiceRender', 'api', 'POST', `${p}/invoices/:id/render`, 'id', 'session'],
    ['api.payoutList', 'api', 'GET', `${p}/payouts`, '', 'session'],
    ['api.payoutGet', 'api', 'GET', `${p}/payouts/:id`, 'id', 'session'],
    ['api.payoutRebind', 'api', 'PATCH', `${p}/payouts/:id/rebind`, 'id', 'session'],
    ['api.payoutApprove', 'api', 'POST', `${p}/payouts/:id/approve`, 'id', 'session'],
    ['api.orderCreate', 'api', 'POST', `${p}/orders`, '', 'session'],
    ['api.orderGet', 'api', 'GET', `${p}/orders/:id`, 'id', 'session'],
    ['api.orderRebind', 'api', 'PATCH', `${p}/orders/:id/rebind`, 'id', 'session'],
    ['api.orderSettleRace', 'api', 'POST', `${p}/orders/:id/settle-race`, 'id', 'session'],
    ['api.ledger', 'api', 'GET', `${p}/ledger`, '', 'session'],
    ['api.balance', 'api', 'GET', `${p}/balance`, '', 'session'],
    ['api.graphql', 'api', 'POST', `${p}/graphql`, '', 'session'],
    ['api.audit', 'api', 'GET', `${p}/audit`, '', 'session'],
    ['api.customers', 'api', 'GET', `${p}/customers`, '', 'session'],
    ['api.plans', 'api', 'GET', `${p}/plans`, '', 'session'],
    ['api.discounts', 'api', 'GET', `${p}/discounts`, '', 'session'],
    ['api.notifications', 'api', 'GET', `${p}/notifications`, '', 'session'],
    ['api.settings', 'api', 'GET', `${p}/settings`, '', 'session'],
    ['api.exchangeRates', 'api', 'GET', `${p}/exchange-rates`, '', 'session'],
    ['api.search', 'api', 'GET', `${p}/search`, '', 'session'],
    ['api.webhooks', 'api', 'GET', `${p}/webhooks`, '', 'session'],
    ['worker.jobExport', 'worker', 'POST', '/jobs/export', '', 'service'],
    ['worker.jobRender', 'worker', 'POST', '/jobs/render', '', 'service'],
    ['worker.jobPoll', 'worker', 'GET', '/jobs/:id', 'id', 'service'],
    ['worker.jobTrace', 'worker', 'GET', '/jobs/:id/trace', 'id', 'service'],
    ['worker.jobResult', 'worker', 'GET', '/jobs/:id/result', 'id', 'service'],
    ['worker.jobCancel', 'worker', 'POST', '/jobs/:id/cancel', 'id', 'service'],
    ['worker.queues', 'worker', 'GET', '/queues', '', 'service'],
    ['vault.signingKeys', 'vault.internal', 'GET', '/signing-keys', '', 'service'],
    ['vault.signHmac', 'vault.internal', 'POST', '/sign/hmac', '', 'service'],
    ['vault.settlementWebhook', 'vault.internal', 'POST', '/webhooks/settlement', '', 'service'],
    ['vault.treasury', 'vault.internal', 'GET', '/treasury/:tenant', 'tenant', 'service'],
    ['vault.keyRotate', 'vault.internal', 'POST', '/keys/rotate', '', 'service'],
  ]
  return entries.map(([routeKey, service, method, path, params, auth]) => ({
    routeKey, service, method, path,
    params: params ? params.split(',') : [],
    auth,
  }))
}
