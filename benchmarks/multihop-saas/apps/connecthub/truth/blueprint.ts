// Host-side connecthub blueprint: per-mode behaviour profiles, chain specs, partial twins and truth.
import type {
  ApiRef, ChainSpec, DomainVariant, GroundTruth, LabMode, TwinSpec,
} from '../../../lib/types.ts'
import type { LabProfile } from '../src/shared.ts'

export const ARCHETYPE = {
  id: 'connecthub',
  title: 'Marketplace, OAuth apps, delegated permissions and partner billing',
  sealed: true,
  split: 'sealed',
  services: 5,
} as const

const SERVICE_ROLES: Array<{ id: GroundTruth['topology'][number]['id']; role: string; internal: boolean }> = [
  { id: 'portal', role: 'partner portal and signed partner-file gateway', internal: false },
  { id: 'api', role: 'marketplace REST + GraphQL application surface', internal: false },
  { id: 'oauth', role: 'app consent, sessions and delegated token exchange', internal: false },
  { id: 'webhook-relay', role: 'asynchronous webhook delivery and callback runner', internal: true },
  { id: 'billing.internal', role: 'partner billing settlement and ledger readback', internal: true },
]

export const CHAINS: readonly ChainSpec[] = [
  {
    id: 'CH-C1',
    title: 'Consent scope widening to delegated rebate loop to billing conservation break',
    vulnClass: 'delegated_billing_rebate',
    hops: [
      { hopId: 'ch-c1-h1', service: 'oauth', routeKey: 'oauth.consentGrant', actor: 'member_a' },
      { hopId: 'ch-c1-h2', service: 'oauth', routeKey: 'oauth.tokenExchange', actor: 'member_a', edgeFromPrevious: 'derived_crypto_binding' },
      { hopId: 'ch-c1-h3', service: 'api', routeKey: 'api.rebateApply', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'ch-c1-h4', service: 'billing.internal', routeKey: 'billing.rebateSettle', actor: 'member_a', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: 'billing.internal', routeKey: 'billing.rebateSettle', kind: 'delegated_billing_rebate' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted', 'admin_bot'],
  },
  {
    id: 'CH-C2',
    title: 'Scope-omitting webhook replay to nested app secret resolver read',
    vulnClass: 'cross_tenant_secret_read',
    hops: [
      { hopId: 'ch-c2-h1', service: 'api', routeKey: 'api.webhookRegister', actor: 'member_b' },
      { hopId: 'ch-c2-h2', service: 'webhook-relay', routeKey: 'relay.deliveryPoll', actor: 'member_b', edgeFromPrevious: 'async_pivot_binding' },
      { hopId: 'ch-c2-h3', service: 'api', routeKey: 'api.webhookReplay', actor: 'member_b', edgeFromPrevious: 'derived_crypto_binding' },
      { hopId: 'ch-c2-h4', service: 'api', routeKey: 'api.graphqlAppSecret', actor: 'member_b', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.graphqlAppSecret', kind: 'cross_tenant_secret_read' },
    attackerPersonaSet: ['member_b'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'member_a', 'revoked_or_demoted', 'admin_bot'],
  },
  {
    id: 'CH-C3',
    title: 'Portal hop-by-hop internal actor smuggling to split-refund ledger break',
    vulnClass: 'split_refund_ledger_break',
    hops: [
      { hopId: 'ch-c3-h1', service: 'portal', routeKey: 'portal.caseCreate', actor: 'revoked_or_demoted' },
      { hopId: 'ch-c3-h2', service: 'portal', routeKey: 'portal.caseForward', actor: 'revoked_or_demoted', edgeFromPrevious: 'value_binding' },
      { hopId: 'ch-c3-h3', service: 'api', routeKey: 'api.refundSplit', actor: 'revoked_or_demoted', edgeFromPrevious: 'value_binding' },
      { hopId: 'ch-c3-h4', service: 'billing.internal', routeKey: 'billing.refundSettle', actor: 'revoked_or_demoted', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: 'billing.internal', routeKey: 'billing.refundSettle', kind: 'split_refund_ledger_break' },
    attackerPersonaSet: ['revoked_or_demoted'],
    forbiddenShortcutPersonas: ['owner_a', 'member_a', 'viewer_a', 'dual_member', 'member_b', 'admin_bot'],
  },
  {
    id: 'CH-C4',
    title: 'Stale callback token to signed partner prefix escape to cross-tenant export',
    vulnClass: 'cross_tenant_partner_export',
    hops: [
      { hopId: 'ch-c4-h1', service: 'api', routeKey: 'api.appUninstall', actor: 'dual_member' },
      { hopId: 'ch-c4-h2', service: 'webhook-relay', routeKey: 'relay.callbackReplay', actor: 'dual_member', edgeFromPrevious: 'value_binding' },
      { hopId: 'ch-c4-h3', service: 'api', routeKey: 'api.storageSign', actor: 'dual_member', edgeFromPrevious: 'async_pivot_binding' },
      { hopId: 'ch-c4-h4', service: 'api', routeKey: 'api.partnerExportIssue', actor: 'dual_member', edgeFromPrevious: 'value_binding' },
      { hopId: 'ch-c4-h5', service: 'portal', routeKey: 'portal.partnerExportDownload', actor: 'dual_member', edgeFromPrevious: 'value_binding' },
    ],
    terminal: { service: 'portal', routeKey: 'portal.partnerExportDownload', kind: 'cross_tenant_partner_export' },
    attackerPersonaSet: ['dual_member'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'member_a', 'member_b', 'revoked_or_demoted', 'admin_bot'],
  },
]

export const TWINS: readonly TwinSpec[] = [
  {
    id: 'CH-D1',
    baseChainId: 'CH-C1',
    decoyHopIds: ['ch-c1-h1', 'ch-c1-h2'],
    enforcedAtHopId: 'ch-c1-h3',
    note: 'consent and token hops are benign; rebate application intersects the displayed scopes and caps the amount',
  },
  {
    id: 'CH-D2',
    baseChainId: 'CH-C2',
    decoyHopIds: ['ch-c2-h1', 'ch-c2-h2'],
    enforcedAtHopId: 'ch-c2-h3',
    note: 'registration and delivery hops are benign; replay requires the canonical scope-bound HMAC and per-node GraphQL authz',
  },
  {
    id: 'CH-D3',
    baseChainId: 'CH-C3',
    decoyHopIds: ['ch-c3-h1', 'ch-c3-h2'],
    enforcedAtHopId: 'ch-c3-h3',
    note: 'case creation and forwarding are benign; casing-insensitive internal actor headers are stripped before forwarding',
  },
]

function profile(base: Partial<LabProfile>, asyncLatencyMs: number): LabProfile {
  return {
    consentScopeWidening: false,
    enforceConsentIntersection: true,
    rebateCapCents: 1,
    webhookSignatureScopeBound: true,
    webhookRequireVerifiedEndpoint: true,
    graphqlPerNodeAuthz: true,
    staleCallbackTokenRetained: false,
    acceptStaleCallback: false,
    stripInternalHeaders: true,
    trustInternalActorHeader: false,
    acceptCaseActorHint: false,
    signedPrefixTrailingSlash: true,
    asyncLatencyMs,
    ...base,
  }
}

export function profileFor(mode: LabMode, twinId?: string, asyncLatencyMs = 25): LabProfile {
  if (mode === 'hardened') return profile({}, asyncLatencyMs)
  if (!twinId) {
    return profile({
      consentScopeWidening: true,
      enforceConsentIntersection: false,
      rebateCapCents: 0,
      webhookSignatureScopeBound: false,
      webhookRequireVerifiedEndpoint: false,
      graphqlPerNodeAuthz: false,
      staleCallbackTokenRetained: true,
      acceptStaleCallback: true,
      stripInternalHeaders: false,
      trustInternalActorHeader: true,
      acceptCaseActorHint: true,
      signedPrefixTrailingSlash: false,
    }, asyncLatencyMs)
  }
  switch (twinId) {
    case 'CH-D1':
      return profile({ consentScopeWidening: true, enforceConsentIntersection: true, rebateCapCents: 1 }, asyncLatencyMs)
    case 'CH-D2':
      return profile({ webhookSignatureScopeBound: true, webhookRequireVerifiedEndpoint: false, graphqlPerNodeAuthz: true }, asyncLatencyMs)
    case 'CH-D3':
      return profile({ acceptCaseActorHint: true, stripInternalHeaders: true, trustInternalActorHeader: false }, asyncLatencyMs)
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
  const twin = twinId ? TWINS.find((item) => item.id === twinId) : undefined
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
    ['portal.directoryApps', 'portal', 'GET', `${p}/directory/apps`, '', 'none'],
    ['portal.login', 'portal', 'POST', `${p}/auth/login`, '', 'none'],
    ['portal.apps', 'portal', 'GET', `${p}/apps`, '', 'session'],
    ['portal.caseCreate', 'portal', 'POST', `${p}/cases`, '', 'session'],
    ['portal.caseForward', 'portal', 'POST', `${p}/cases/:id/forward`, 'id', 'session'],
    ['portal.caseList', 'portal', 'GET', `${p}/cases`, '', 'session'],
    ['portal.partnerExportDownload', 'portal', 'GET', '/files/partner/:tenant/:file', 'tenant,file', 'none'],
    ['portal.partners', 'portal', 'GET', '/partners', '', 'none'],
    ['portal.categories', 'portal', 'GET', '/categories', '', 'none'],
    ['portal.reviews', 'portal', 'GET', '/reviews', '', 'none'],
    ['portal.support', 'portal', 'GET', '/support', '', 'none'],
    ['portal.faq', 'portal', 'GET', '/faq', '', 'none'],
    ['portal.status', 'portal', 'GET', '/status', '', 'none'],
    ['portal.announcements', 'portal', 'GET', '/announcements', '', 'none'],
    ['portal.assetsCss', 'portal', 'GET', '/assets/app.css', '', 'none'],
    ['portal.assetsJs', 'portal', 'GET', '/assets/app.js', '', 'none'],
    ['portal.regions', 'portal', 'GET', '/regions', '', 'none'],
    ['portal.plans', 'portal', 'GET', '/plans', '', 'none'],

    ['api.login', 'api', 'POST', `${p}/auth/login`, '', 'none'],
    ['api.me', 'api', 'GET', `${p}/me`, '', 'session'],
    ['api.apps', 'api', 'GET', `${p}/apps`, '', 'session'],
    ['api.appCreate', 'api', 'POST', `${p}/apps`, '', 'session'],
    ['api.appInstall', 'api', 'POST', `${p}/apps/:id/install`, 'id', 'session'],
    ['api.appUninstall', 'api', 'POST', `${p}/apps/:id/uninstall`, 'id', 'session'],
    ['api.appSecrets', 'api', 'GET', `${p}/apps/:id/secrets`, 'id', 'session'],
    ['api.invoices', 'api', 'GET', `${p}/invoices`, '', 'session'],
    ['api.invoiceGet', 'api', 'GET', `${p}/invoices/:id`, 'id', 'session'],
    ['api.rebateApply', 'api', 'POST', `${p}/rebates/apply`, '', 'session'],
    ['api.webhookRegister', 'api', 'POST', `${p}/webhooks`, '', 'session'],
    ['api.webhookList', 'api', 'GET', `${p}/webhooks`, '', 'session'],
    ['api.webhookDelete', 'api', 'DELETE', `${p}/webhooks/:id`, 'id', 'session'],
    ['api.webhookReplay', 'api', 'POST', `${p}/webhooks/replay`, '', 'none'],
    ['api.graphqlAppSecret', 'api', 'POST', `${p}/graphql`, '', 'none'],
    ['api.storageSign', 'api', 'POST', `${p}/storage/sign`, '', 'service'],
    ['api.partnerExportIssue', 'api', 'POST', `${p}/partner/exports`, '', 'session'],
    ['api.partnerExportList', 'api', 'GET', `${p}/partner/exports`, '', 'session'],
    ['api.refundSplit', 'api', 'POST', `${p}/internal/cases/:id/refund-split`, 'id', 'service'],
    ['api.ledger', 'api', 'GET', `${p}/ledger`, '', 'session'],
    ['api.refunds', 'api', 'GET', `${p}/refunds`, '', 'session'],
    ['api.audit', 'api', 'GET', `${p}/audit`, '', 'session'],
    ['api.plans', 'api', 'GET', `${p}/plans`, '', 'session'],
    ['api.partners', 'api', 'GET', `${p}/partners`, '', 'session'],
    ['api.notifications', 'api', 'GET', `${p}/notifications`, '', 'session'],
    ['api.search', 'api', 'GET', `${p}/search`, '', 'session'],
    ['api.settings', 'api', 'GET', `${p}/settings`, '', 'session'],
    ['api.marketplace', 'api', 'GET', `${p}/marketplace`, '', 'session'],
    ['api.categories', 'api', 'GET', `${p}/categories`, '', 'session'],
    ['api.reviews', 'api', 'GET', `${p}/reviews`, '', 'session'],
    ['api.usage', 'api', 'GET', `${p}/usage`, '', 'session'],
    ['api.statements', 'api', 'GET', `${p}/statements`, '', 'session'],
    ['api.balances', 'api', 'GET', `${p}/balances`, '', 'session'],
    ['api.integrations', 'api', 'GET', `${p}/integrations`, '', 'session'],
    ['api.webhookEvents', 'api', 'GET', `${p}/webhook-events`, '', 'session'],
    ['api.regions', 'api', 'GET', `${p}/regions`, '', 'session'],
    ['api.currencies', 'api', 'GET', `${p}/currencies`, '', 'session'],
    ['api.taxes', 'api', 'GET', `${p}/taxes`, '', 'session'],
    ['api.coupons', 'api', 'GET', `${p}/coupons`, '', 'session'],
    ['api.entitlements', 'api', 'GET', `${p}/entitlements`, '', 'session'],
    ['api.scopes', 'api', 'GET', `${p}/scopes`, '', 'session'],
    ['api.installations', 'api', 'GET', `${p}/installations`, '', 'session'],
    ['api.pats', 'api', 'GET', `${p}/pats`, '', 'session'],

    ['oauth.login', 'oauth', 'POST', '/login', '', 'none'],
    ['oauth.consentGrant', 'oauth', 'POST', '/authorize', '', 'session'],
    ['oauth.tokenExchange', 'oauth', 'POST', '/token', '', 'none'],
    ['oauth.revoke', 'oauth', 'POST', '/revoke', '', 'none'],
    ['oauth.sessionRevoke', 'oauth', 'POST', '/sessions/revoke', '', 'none'],
    ['oauth.patCreate', 'oauth', 'POST', '/pats', '', 'session'],
    ['oauth.patRevoke', 'oauth', 'POST', '/pats/:id/revoke', 'id', 'session'],
    ['oauth.keyRotate', 'oauth', 'POST', '/keys/rotate', '', 'session'],
    ['oauth.scopes', 'oauth', 'GET', '/scopes', '', 'none'],
    ['oauth.userinfo', 'oauth', 'GET', '/userinfo', '', 'session'],
    ['oauth.consents', 'oauth', 'GET', '/consents', '', 'session'],
    ['oauth.clients', 'oauth', 'GET', '/clients', '', 'none'],
    ['oauth.grants', 'oauth', 'GET', '/grants', '', 'none'],
    ['oauth.jwks', 'oauth', 'GET', '/jwks', '', 'none'],
    ['oauth.discovery', 'oauth', 'GET', '/discovery', '', 'none'],
    ['oauth.introspect', 'oauth', 'POST', '/introspect', '', 'none'],

    ['relay.subscribe', 'webhook-relay', 'POST', '/subscriptions', '', 'service'],
    ['relay.deliveryPoll', 'webhook-relay', 'GET', '/deliveries/:id', 'id', 'service'],
    ['relay.deliveryList', 'webhook-relay', 'GET', '/deliveries', '', 'service'],
    ['relay.subscriptionList', 'webhook-relay', 'GET', '/subscriptions', '', 'service'],
    ['relay.webhookDelete', 'webhook-relay', 'DELETE', '/webhooks/:id', 'id', 'service'],
    ['relay.callbackReplay', 'webhook-relay', 'POST', '/callbacks/:tokenId/replay', 'tokenId', 'service'],
    ['relay.callbackPoll', 'webhook-relay', 'GET', '/callbacks/jobs/:id', 'id', 'service'],
    ['relay.jobCancel', 'webhook-relay', 'POST', '/jobs/:id/cancel', 'id', 'service'],
    ['relay.queues', 'webhook-relay', 'GET', '/queues', '', 'service'],
    ['relay.attempts', 'webhook-relay', 'GET', '/attempts', '', 'service'],

    ['billing.rebateSettle', 'billing.internal', 'POST', '/rebates/settle', '', 'service'],
    ['billing.refundSettle', 'billing.internal', 'POST', '/refunds/settle', '', 'service'],
    ['billing.ledger', 'billing.internal', 'GET', '/ledger', '', 'service'],
    ['billing.conservation', 'billing.internal', 'GET', '/conservation/:id', 'id', 'service'],
    ['billing.keyRotate', 'billing.internal', 'POST', '/keys/rotate', '', 'service'],
    ['billing.reset', 'billing.internal', 'POST', '/reset', '', 'service'],
    ['billing.partners', 'billing.internal', 'GET', '/partners', '', 'service'],
    ['billing.balances', 'billing.internal', 'GET', '/balances', '', 'service'],
    ['billing.statements', 'billing.internal', 'GET', '/statements', '', 'service'],
    ['billing.remittances', 'billing.internal', 'GET', '/remittances', '', 'service'],
    ['billing.taxes', 'billing.internal', 'GET', '/taxes', '', 'service'],
    ['billing.currencies', 'billing.internal', 'GET', '/currencies', '', 'service'],
    ['billing.reconciliation', 'billing.internal', 'GET', '/reconciliation', '', 'service'],
    ['billing.audit', 'billing.internal', 'GET', '/audit', '', 'service'],
    ['billing.digest', 'billing.internal', 'GET', '/digest', '', 'service'],
  ]
  return entries.map(([routeKey, service, method, path, params, auth]) => ({
    routeKey, service, method, path,
    params: params ? params.split(',') : [],
    auth,
  }))
}
