// Host-side nexusiam blueprint: per-mode behaviour profiles, chain specs, partial twins and truth.
import type {
  ApiRef, AppName, ChainSpec, DomainVariant, GroundTruth, LabMode, ServiceId, TerminalImpactKind, TwinSpec,
} from '../../../lib/types.ts'
import type { LabProfile, NexusPlan, ServiceName } from '../src/shared.ts'

const NEXUS_APP = 'nexusiam' as unknown as AppName

function sid(name: ServiceName): ServiceId {
  return name as unknown as ServiceId
}

function impact(name: string): TerminalImpactKind {
  return name as unknown as TerminalImpactKind
}

const SERVICE_ROLES: Array<{ id: ServiceName; role: string; internal: boolean }> = [
  { id: 'cdn', role: 'public static and profile cache edge', internal: false },
  { id: 'app', role: 'collaboration SPA and moderation worker', internal: false },
  { id: 'api', role: 'IAM, SCIM, documents, search and audit surfaces', internal: false },
  { id: 'idp', role: 'OIDC sessions, invitations and personal access tokens', internal: false },
  { id: 'docs-worker', role: 'async document export and artifact delivery', internal: true },
]

export const CHAINS: readonly ChainSpec[] = [
  {
    id: 'NX-C1',
    title: 'Moderation render to bot-origin SCIM token to role promotion to audit vault read',
    vulnClass: 'privilege_escalation',
    hops: [
      { hopId: 'nx-c1-h1', service: sid('api'), routeKey: 'api.commentCreate', actor: 'member_a' },
      { hopId: 'nx-c1-h2', service: sid('app'), routeKey: 'app.moderationRender', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c1-h3', service: sid('api'), routeKey: 'api.scimTokenMint', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c1-h4', service: sid('api'), routeKey: 'api.scimUserPatch', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c1-h5', service: sid('api'), routeKey: 'api.auditVaultRead', actor: 'member_a', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: sid('api'), routeKey: 'api.auditVaultRead', kind: impact('privilege_escalation') },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted', 'admin_bot'],
  },
  {
    id: 'NX-C2',
    title: 'Identity subpath redirect to delegated code to pending invite to stale invitation redemption',
    vulnClass: 'stale_privilege_use',
    hops: [
      { hopId: 'nx-c2-h1', service: sid('idp'), routeKey: 'idp.authorizeRedirect', actor: 'member_b' },
      { hopId: 'nx-c2-h2', service: sid('app'), routeKey: 'app.shareLinkCapture', actor: 'member_b', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c2-h3', service: sid('idp'), routeKey: 'idp.pendingInvites', actor: 'member_b', edgeFromPrevious: 'derived_crypto_binding' },
      { hopId: 'nx-c2-h4', service: sid('idp'), routeKey: 'idp.inviteRedeem', actor: 'member_b', edgeFromPrevious: 'derived_crypto_binding' },
    ],
    terminal: { service: sid('idp'), routeKey: 'idp.inviteRedeem', kind: impact('stale_privilege_use') },
    attackerPersonaSet: ['member_b'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'revoked_or_demoted', 'admin_bot'],
  },
  {
    id: 'NX-C3',
    title: 'Profile cache authorization omission to empty workspace fallback to private document read',
    vulnClass: 'cross_tenant_document_read',
    hops: [
      { hopId: 'nx-c3-h1', service: sid('cdn'), routeKey: 'cdn.profileCacheRead', actor: 'member_b' },
      { hopId: 'nx-c3-h2', service: sid('api'), routeKey: 'api.docsWorkspaceFallback', actor: 'member_b', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c3-h3', service: sid('api'), routeKey: 'api.docPrivateOpen', actor: 'member_b', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c3-h4', service: sid('api'), routeKey: 'api.docContentRead', actor: 'member_b', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: sid('api'), routeKey: 'api.docContentRead', kind: impact('cross_tenant_document_read') },
    attackerPersonaSet: ['member_b'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'revoked_or_demoted', 'admin_bot'],
  },
  {
    id: 'NX-C4',
    title: 'Facet count oracle to share metadata handle to stale export job to artifact exfiltration',
    vulnClass: 'cross_tenant_exfiltration',
    hops: [
      { hopId: 'nx-c4-h1', service: sid('api'), routeKey: 'api.searchFacets', actor: 'revoked_or_demoted' },
      { hopId: 'nx-c4-h2', service: sid('api'), routeKey: 'api.shareMetadata', actor: 'revoked_or_demoted', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c4-h3', service: sid('docs-worker'), routeKey: 'docsWorker.jobPoll', actor: 'revoked_or_demoted', edgeFromPrevious: 'value_binding' },
      { hopId: 'nx-c4-h4', service: sid('docs-worker'), routeKey: 'docsWorker.jobResult', actor: 'revoked_or_demoted', edgeFromPrevious: 'async_pivot_binding' },
    ],
    terminal: { service: sid('docs-worker'), routeKey: 'docsWorker.jobResult', kind: impact('cross_tenant_exfiltration') },
    attackerPersonaSet: ['revoked_or_demoted'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'member_a', 'dual_member', 'member_b', 'admin_bot'],
  },
]

export const TWINS: readonly TwinSpec[] = [
  {
    id: 'NX-D1',
    baseChainId: 'NX-C1',
    decoyHopIds: ['nx-c1-h1', 'nx-c1-h2'],
    enforcedAtHopId: 'nx-c1-h3',
    note: 'comment and moderation visit are benign; the admin view escapes content and rotates the script nonce',
  },
  {
    id: 'NX-D2',
    baseChainId: 'NX-C2',
    decoyHopIds: ['nx-c2-h1', 'nx-c2-h2'],
    enforcedAtHopId: 'nx-c2-h3',
    note: 'authorization and share preview are benign; invite listing requires a live tenant role and exact redirect origin',
  },
  {
    id: 'NX-D3',
    baseChainId: 'NX-C3',
    decoyHopIds: ['nx-c3-h1', 'nx-c3-h2'],
    enforcedAtHopId: 'nx-c3-h3',
    note: 'profile cache read and workspace listing are benign; private documents require an exact workspace binding',
  },
]

function profile(base: Partial<LabProfile>, asyncLatencyMs: number): LabProfile {
  return {
    moderationPipeline: false,
    moderationRendersRaw: false,
    botSameOriginMint: false,
    redirectSubpathAccepted: false,
    inviteListLeaksToken: false,
    staleInviteRedeem: false,
    cacheIgnoresAuth: false,
    emptyWorkspaceFallsBack: false,
    privateDocScopeCheck: false,
    facetsLeakCounts: false,
    shareMetadataLeaksHandle: false,
    exportJobExfiltrates: false,
    asyncLatencyMs,
    ...base,
  }
}

export function profileFor(mode: LabMode, twinId?: string, asyncLatencyMs = 25): LabProfile {
  if (mode === 'hardened') return profile({}, asyncLatencyMs)
  if (!twinId) {
    return profile({
      moderationPipeline: true,
      moderationRendersRaw: true,
      botSameOriginMint: true,
      redirectSubpathAccepted: true,
      inviteListLeaksToken: true,
      staleInviteRedeem: true,
      cacheIgnoresAuth: true,
      emptyWorkspaceFallsBack: true,
      privateDocScopeCheck: false,
      facetsLeakCounts: true,
      shareMetadataLeaksHandle: true,
      exportJobExfiltrates: true,
    }, asyncLatencyMs)
  }
  switch (twinId) {
    case 'NX-D1':
      return profile({ moderationPipeline: true, moderationRendersRaw: false }, asyncLatencyMs)
    case 'NX-D2':
      return profile({ redirectSubpathAccepted: true, inviteListLeaksToken: false, staleInviteRedeem: false }, asyncLatencyMs)
    case 'NX-D3':
      return profile({
        cacheIgnoresAuth: true, emptyWorkspaceFallsBack: true, privateDocScopeCheck: true,
      }, asyncLatencyMs)
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
    app: NEXUS_APP,
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
    topology: SERVICE_ROLES.map((service) => ({ id: sid(service.id), role: service.role, internal: service.internal })),
    personas: Object.values(plan.personas).map((persona) => ({
      id: persona.id,
      tenantId: persona.tenantId,
      rolesByTenant: persona.rolesByTenant,
    })),
  }
}

export function apiCatalog(plan: NexusPlan): ApiRef[] {
  const p = plan.routePrefix
  const entries: Array<[string, ServiceName, string, string, string, ApiRef['auth']]> = [
    ['cdn.profileCss', 'cdn', 'GET', '/public/profile/:slug.css', 'slug', 'none'],
    ['cdn.assets', 'cdn', 'GET', '/assets/:name', 'name', 'none'],
    ['app.index', 'app', 'GET', '/', '', 'none'],
    ['app.moderationQueue', 'app', 'GET', '/v1/moderation/queue', '', 'service'],
    ['app.sharePreview', 'app', 'GET', '/s/:id', 'id', 'none'],
    ['app.inbox', 'app', 'GET', `${p}/inbox/:commentId`, 'commentId', 'session'],
    ['idp.login', 'idp', 'POST', '/login', '', 'none'],
    ['idp.authorizeRedirect', 'idp', 'GET', '/authorize', 'client_id,redirect_uri,next', 'none'],
    ['idp.token', 'idp', 'POST', '/token', '', 'none'],
    ['idp.jwks', 'idp', 'GET', '/jwks', '', 'none'],
    ['idp.inviteCreate', 'idp', 'POST', '/invites', '', 'session'],
    ['idp.pendingInvites', 'idp', 'GET', '/invites', 'tenant', 'session'],
    ['idp.inviteRevoke', 'idp', 'POST', '/invites/:id/revoke', 'id', 'session'],
    ['idp.inviteRedeem', 'idp', 'POST', '/invites/redeem', '', 'session'],
    ['idp.patCreate', 'idp', 'POST', '/pats', '', 'session'],
    ['idp.patList', 'idp', 'GET', '/pats', '', 'session'],
    ['idp.patRevoke', 'idp', 'POST', '/pats/:id/revoke', 'id', 'session'],
    ['idp.sessionRevoke', 'idp', 'POST', '/sessions/revoke', '', 'session'],
    ['idp.users', 'idp', 'GET', '/users', '', 'none'],
    ['idp.scopes', 'idp', 'GET', '/scopes', '', 'none'],
    ['idp.keys', 'idp', 'GET', '/keys', '', 'none'],
    ['idp.tenants', 'idp', 'GET', '/tenants', '', 'none'],
    ['idp.audit', 'idp', 'GET', '/audit', '', 'none'],
    ['api.login', 'api', 'POST', `${p}/auth/login`, '', 'none'],
    ['api.me', 'api', 'GET', `${p}/me`, '', 'session'],
    ['api.orgs', 'api', 'GET', `${p}/orgs`, '', 'session'],
    ['api.orgMembers', 'api', 'GET', `${p}/orgs/:org/members`, 'org', 'session'],
    ['api.commentCreate', 'api', 'POST', `${p}/comments`, '', 'session'],
    ['api.commentList', 'api', 'GET', `${p}/comments`, '', 'session'],
    ['api.scimTokenCreate', 'api', 'POST', `${p}/scim/tokens`, '', 'session'],
    ['api.scimTokenList', 'api', 'GET', `${p}/scim/tokens`, '', 'session'],
    ['api.scimTokenRevoke', 'api', 'POST', `${p}/scim/tokens/:id/revoke`, 'id', 'session'],
    ['api.scimUserPatch', 'api', 'PATCH', `${p}/scim/users/:id`, 'id', 'service'],
    ['api.docsList', 'api', 'GET', `${p}/docs`, 'workspace', 'session'],
    ['api.docGet', 'api', 'GET', `${p}/docs/:id`, 'id', 'session'],
    ['api.docContent', 'api', 'GET', `${p}/docs/:id/content`, 'id', 'session'],
    ['api.shareMetadata', 'api', 'GET', `${p}/docs/share/:id/metadata`, 'id,folder', 'session'],
    ['api.searchFacets', 'api', 'GET', `${p}/search/facets`, 'q,tenant', 'session'],
    ['api.auditVault', 'api', 'GET', `${p}/audit/vault`, 'tenant', 'session'],
    ['api.graphql', 'api', 'POST', `${p}/graphql`, '', 'session'],
    ['api.audit', 'api', 'GET', `${p}/audit`, '', 'session'],
    ['api.customers', 'api', 'GET', `${p}/customers`, '', 'session'],
    ['api.plans', 'api', 'GET', `${p}/plans`, '', 'session'],
    ['api.notifications', 'api', 'GET', `${p}/notifications`, '', 'session'],
    ['api.settings', 'api', 'GET', `${p}/settings`, '', 'session'],
    ['api.folders', 'api', 'GET', `${p}/folders`, '', 'session'],
    ['api.groups', 'api', 'GET', `${p}/groups`, '', 'session'],
    ['api.webhooks', 'api', 'GET', `${p}/webhooks`, '', 'session'],
    ['api.integrations', 'api', 'GET', `${p}/integrations`, '', 'session'],
    ['api.pats', 'api', 'GET', `${p}/pats`, '', 'session'],
    ['docsWorker.jobCreate', 'docs-worker', 'POST', '/jobs/export', '', 'service'],
    ['docsWorker.jobPoll', 'docs-worker', 'GET', '/jobs/:id', 'id', 'service'],
    ['docsWorker.jobResult', 'docs-worker', 'GET', '/jobs/:id/result', 'id', 'service'],
    ['docsWorker.jobCancel', 'docs-worker', 'POST', '/jobs/:id/cancel', 'id', 'service'],
    ['docsWorker.queues', 'docs-worker', 'GET', '/queues', '', 'service'],
    ['docsWorker.runners', 'docs-worker', 'GET', '/runners', '', 'service'],
    ['docsWorker.audit', 'docs-worker', 'GET', '/audit', '', 'service'],
  ]
  return entries.map(([routeKey, service, method, path, params, auth]) => ({
    routeKey,
    service: sid(service),
    method,
    path,
    params: params ? params.split(',') : [],
    auth,
  }))
}
