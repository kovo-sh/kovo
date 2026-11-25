// Host-side shipforge blueprint: per-mode behaviour profiles, chain specs, partial twins and truth.
import type {
  ApiRef, CausalEdgeKind, ChainSpec, DomainVariant, GroundTruth, LabMode, PersonaId, ServiceTopology,
  TwinSpec,
} from '../../../lib/types.ts'
import type { LabProfile } from '../src/shared.ts'

export type SfService = 'edge' | 'api' | 'runner' | 'scm' | 'registry.internal'
export type SfTerminalKind =
  | 'unauthorized_prod_release'
  | 'cross_tenant_repo_theft'
  | 'internal_token_exfiltration'
  | 'unapproved_prod_release'

interface LocalHop {
  hopId: string
  service: SfService
  routeKey: string
  actor: PersonaId
  edgeFromPrevious?: CausalEdgeKind
}

interface LocalChain {
  id: string
  title: string
  vulnClass: string
  hops: LocalHop[]
  terminal: { service: SfService; routeKey: string; kind: SfTerminalKind }
  attackerPersonaSet: PersonaId[]
  forbiddenShortcutPersonas: PersonaId[]
}

const CHAIN_DEFS: LocalChain[] = [
  {
    id: 'SF-C1',
    title: 'Preview environment token exposure to cross-environment promotion and signing key release',
    vulnClass: 'unauthorized_prod_release',
    hops: [
      { hopId: 'sf-c1-h1', service: 'scm', routeKey: 'scm.previewBuild', actor: 'member_a' },
      { hopId: 'sf-c1-h2', service: 'api', routeKey: 'api.ciRunEnvPreview', actor: 'member_a', edgeFromPrevious: 'async_pivot_binding' },
      { hopId: 'sf-c1-h3', service: 'api', routeKey: 'api.deploymentPromote', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'sf-c1-h4', service: 'api', routeKey: 'api.secretsBatch', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'sf-c1-h5', service: 'api', routeKey: 'api.productionRelease', actor: 'member_a', edgeFromPrevious: 'derived_crypto_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.productionRelease', kind: 'unauthorized_prod_release' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted', 'admin_bot'],
  },
  {
    id: 'SF-C2',
    title: 'Revoked token stream replay to cross-tenant project transfer and repository export',
    vulnClass: 'cross_tenant_repo_theft',
    hops: [
      { hopId: 'sf-c2-h1', service: 'runner', routeKey: 'runner.sseStream', actor: 'revoked_or_demoted' },
      { hopId: 'sf-c2-h2', service: 'runner', routeKey: 'runner.sseArtifactEvent', actor: 'revoked_or_demoted', edgeFromPrevious: 'async_pivot_binding' },
      { hopId: 'sf-c2-h3', service: 'api', routeKey: 'api.projectTransfer', actor: 'dual_member', edgeFromPrevious: 'value_binding' },
      { hopId: 'sf-c2-h4', service: 'scm', routeKey: 'scm.repoExport', actor: 'dual_member', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: 'scm', routeKey: 'scm.repoExport', kind: 'cross_tenant_repo_theft' },
    attackerPersonaSet: ['revoked_or_demoted', 'dual_member'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'member_a', 'member_b', 'admin_bot'],
  },
  {
    id: 'SF-C3',
    title: 'Multi-filter project search leak to webhook delivery token and registry sync',
    vulnClass: 'internal_token_exfiltration',
    hops: [
      { hopId: 'sf-c3-h1', service: 'api', routeKey: 'api.projectSearch', actor: 'member_a' },
      { hopId: 'sf-c3-h2', service: 'scm', routeKey: 'scm.webhookCreate', actor: 'member_a', edgeFromPrevious: 'derived_crypto_binding' },
      { hopId: 'sf-c3-h3', service: 'scm', routeKey: 'scm.deliveryLog', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'sf-c3-h4', service: 'registry.internal', routeKey: 'registry.internalSync', actor: 'member_a', edgeFromPrevious: 'derived_crypto_binding' },
    ],
    terminal: { service: 'registry.internal', routeKey: 'registry.internalSync', kind: 'internal_token_exfiltration' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted', 'admin_bot'],
  },
  {
    id: 'SF-C4',
    title: 'Team-managed automation inheriting admin template to unapproved production release',
    vulnClass: 'unapproved_prod_release',
    hops: [
      { hopId: 'sf-c4-h1', service: 'api', routeKey: 'api.automationCreate', actor: 'member_a' },
      { hopId: 'sf-c4-h2', service: 'api', routeKey: 'api.deploymentDispute', actor: 'member_a', edgeFromPrevious: 'value_binding' },
      { hopId: 'sf-c4-h3', service: 'api', routeKey: 'api.productionRelease', actor: 'member_a', edgeFromPrevious: 'state_transition_binding' },
    ],
    terminal: { service: 'api', routeKey: 'api.productionRelease', kind: 'unapproved_prod_release' },
    attackerPersonaSet: ['member_a'],
    forbiddenShortcutPersonas: ['owner_a', 'viewer_a', 'dual_member', 'member_b', 'revoked_or_demoted', 'admin_bot'],
  },
]

export const CHAINS: readonly ChainSpec[] = CHAIN_DEFS as unknown as readonly ChainSpec[]

export const TWINS: readonly TwinSpec[] = [
  {
    id: 'SF-D1',
    baseChainId: 'SF-C1',
    decoyHopIds: ['sf-c1-h1', 'sf-c1-h2'],
    enforcedAtHopId: 'sf-c1-h3',
    note: 'preview exposure is benign; promotion requires a production-scoped credential and full secret ownership',
  },
  {
    id: 'SF-D2',
    baseChainId: 'SF-C2',
    decoyHopIds: ['sf-c2-h1', 'sf-c2-h2'],
    enforcedAtHopId: 'sf-c2-h3',
    note: 'shared stream events are benign; transfer requires admin on both tenants and a live source credential',
  },
  {
    id: 'SF-D3',
    baseChainId: 'SF-C3',
    decoyHopIds: ['sf-c3-h1', 'sf-c3-h2'],
    enforcedAtHopId: 'sf-c3-h3',
    note: 'search and webhook creation are benign; delivery logs are redacted and sync credentials are scoped',
  },
]

function profile(base: Partial<LabProfile>, asyncLatencyMs: number): LabProfile {
  return {
    previewEnvLeak: false,
    promoteEnvScope: true,
    secretsBatchAllIds: true,
    sseChecksRevocation: true,
    transferDualAdmin: true,
    transferRequiresLivePat: true,
    searchFilterParenthesized: true,
    deliveryLogRedacted: true,
    internalDiagnosticLeak: false,
    registryTokenScoped: true,
    automationInheritAdmin: false,
    disputeKeepsSchedule: false,
    autoReleaseRequiresApproval: true,
    asyncLatencyMs,
    ...base,
  }
}

export function profileFor(mode: LabMode, twinId?: string, asyncLatencyMs = 25): LabProfile {
  if (mode === 'hardened') return profile({}, asyncLatencyMs)
  if (!twinId) {
    return profile({
      previewEnvLeak: true,
      promoteEnvScope: false,
      secretsBatchAllIds: false,
      sseChecksRevocation: false,
      transferDualAdmin: false,
      transferRequiresLivePat: false,
      searchFilterParenthesized: false,
      deliveryLogRedacted: false,
      internalDiagnosticLeak: true,
      registryTokenScoped: false,
      automationInheritAdmin: true,
      disputeKeepsSchedule: true,
      autoReleaseRequiresApproval: false,
    }, asyncLatencyMs)
  }
  switch (twinId) {
    case 'SF-D1':
      return profile({ previewEnvLeak: true, promoteEnvScope: true, secretsBatchAllIds: true }, asyncLatencyMs)
    case 'SF-D2':
      return profile({ sseChecksRevocation: false, transferDualAdmin: true, transferRequiresLivePat: true }, asyncLatencyMs)
    case 'SF-D3':
      return profile({
        searchFilterParenthesized: false, deliveryLogRedacted: true, internalDiagnosticLeak: false,
        registryTokenScoped: true,
      }, asyncLatencyMs)
    default:
      throw new Error(`unknown twin '${twinId}': expected ${TWINS.map((twin) => twin.id).join(', ')}`)
  }
}

const SERVICE_ROLES: Array<{ id: SfService; role: string; internal: boolean }> = [
  { id: 'edge', role: 'public developer portal and request entry', internal: false },
  { id: 'api', role: 'tenant REST + GraphQL control plane', internal: false },
  { id: 'runner', role: 'shared build runners, event streams and artifact handles', internal: true },
  { id: 'scm', role: 'git repositories, webhooks, tokens and preview builds', internal: false },
  { id: 'registry.internal', role: 'internal package registry and tenant metadata sync', internal: true },
]

export function topology(): ServiceTopology[] {
  return SERVICE_ROLES.map((service) => ({
    id: service.id as unknown as ServiceTopology['id'],
    role: service.role,
    internal: service.internal,
  }))
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
    topology: topology(),
    personas: Object.values(plan.personas).map((persona) => ({
      id: persona.id,
      tenantId: persona.tenantId,
      rolesByTenant: persona.rolesByTenant,
    })),
  }
}

export function apiCatalog(plan: DomainVariant): ApiRef[] {
  const p = plan.routePrefix
  const rows: Array<[string, SfService, string, string, string, ApiRef['auth']]> = [
    ['directory.orgPublic', 'edge', 'GET', `${p}/directory/orgs/:slug`, 'slug', 'none'],
    ['edge.docs', 'edge', 'GET', '/docs', '', 'none'],
    ['edge.assets', 'edge', 'GET', '/assets/:name', 'name', 'none'],
    ['edge.manifest', 'edge', 'GET', '/manifest.json', '', 'none'],
    ['scm.login', 'scm', 'POST', '/login', '', 'none'],
    ['scm.logout', 'scm', 'POST', '/logout', '', 'session'],
    ['scm.patCreate', 'scm', 'POST', '/pats', '', 'session'],
    ['scm.patRevoke', 'scm', 'POST', '/pats/:id/revoke', 'id', 'session'],
    ['scm.inviteCreate', 'scm', 'POST', '/invites', '', 'session'],
    ['scm.inviteRevoke', 'scm', 'POST', '/invites/:id/revoke', 'id', 'session'],
    ['scm.repos', 'scm', 'GET', '/repos', '', 'session'],
    ['scm.repoGet', 'scm', 'GET', '/repos/:id', 'id', 'session'],
    ['scm.previewBuild', 'scm', 'POST', '/repos/:id/preview-builds', 'id', 'session'],
    ['scm.webhookCreate', 'scm', 'POST', '/repos/:id/webhooks', 'id', 'session'],
    ['scm.deliveryLog', 'scm', 'GET', '/repos/:id/webhooks/:wid/deliveries', 'id,wid', 'session'],
    ['scm.repoExport', 'scm', 'GET', '/repos/:id/archive', 'id', 'session'],
    ['scm.patRestProbe', 'scm', 'GET', '/api/user', '', 'session'],
    ['scm.oauthAuthorize', 'scm', 'GET', '/oauth/authorize', '', 'session'],
    ['scm.oauthToken', 'scm', 'POST', '/oauth/token', '', 'session'],
    ['scm.scopes', 'scm', 'GET', '/scopes', '', 'none'],
    ['scm.tenants', 'scm', 'GET', '/tenants', '', 'none'],
    ['scm.audit', 'scm', 'GET', '/audit', '', 'session'],
    ['api.login', 'api', 'POST', `${p}/auth/login`, '', 'none'],
    ['api.me', 'api', 'GET', `${p}/me`, '', 'session'],
    ['api.orgs', 'api', 'GET', `${p}/orgs`, '', 'session'],
    ['api.org', 'api', 'GET', `${p}/orgs/:org`, 'org', 'session'],
    ['api.projects', 'api', 'GET', `${p}/projects`, '', 'session'],
    ['api.project', 'api', 'GET', `${p}/projects/:id`, 'id', 'session'],
    ['api.projectTransfer', 'api', 'POST', `${p}/projects/:id/transfer`, 'id', 'session'],
    ['api.projectWebhooks', 'api', 'POST', `${p}/projects/:id/webhooks`, 'id', 'session'],
    ['api.deliveryLog', 'api', 'GET', `${p}/projects/:id/webhooks/:wid/deliveries`, 'id,wid', 'session'],
    ['api.projectSearch', 'api', 'GET', `${p}/search/projects`, '', 'session'],
    ['api.graphql', 'api', 'POST', `${p}/graphql`, '', 'session'],
    ['api.ciRunEnvPreview', 'api', 'POST', `${p}/graphql#ciRun.envPreview`, '', 'session'],
    ['api.deployment', 'api', 'GET', `${p}/deployments/:id`, 'id', 'session'],
    ['api.deploymentPromote', 'api', 'POST', `${p}/deployments/:id/promote`, 'id', 'service'],
    ['api.deploymentDispute', 'api', 'POST', `${p}/deployments/:id/dispute`, 'id', 'session'],
    ['api.deploymentRelease', 'api', 'POST', `${p}/deployments/:id/release`, 'id', 'service'],
    ['api.automations', 'api', 'GET', `${p}/automations`, '', 'session'],
    ['api.automationCreate', 'api', 'POST', `${p}/automations`, '', 'session'],
    ['api.secrets', 'api', 'GET', `${p}/secrets`, '', 'session'],
    ['api.secretsBatch', 'api', 'POST', `${p}/secrets/batch`, '', 'service'],
    ['api.keysRotate', 'api', 'POST', `${p}/keys/rotate`, '', 'session'],
    ['api.runners', 'api', 'GET', `${p}/runners`, '', 'session'],
    ['api.runnerSharedEvents', 'api', 'GET', `${p}/runners/shared/events`, '', 'session'],
    ['api.registrySync', 'api', 'POST', `${p}/integrations/registry/sync`, '', 'session'],
    ['api.pipelines', 'api', 'GET', `${p}/pipelines`, '', 'session'],
    ['api.environments', 'api', 'GET', `${p}/environments`, '', 'session'],
    ['api.artifacts', 'api', 'GET', `${p}/artifacts`, '', 'session'],
    ['api.settings', 'api', 'GET', `${p}/settings`, '', 'session'],
    ['api.usage', 'api', 'GET', `${p}/usage`, '', 'session'],
    ['api.billing', 'api', 'GET', `${p}/billing`, '', 'session'],
    ['api.members', 'api', 'GET', `${p}/members`, '', 'session'],
    ['api.notifications', 'api', 'GET', `${p}/notifications`, '', 'session'],
    ['api.integrations', 'api', 'GET', `${p}/integrations`, '', 'session'],
    ['api.teams', 'api', 'GET', `${p}/teams`, '', 'session'],
    ['api.audit', 'api', 'GET', `${p}/audit`, '', 'session'],
    ['api.tokens', 'api', 'GET', `${p}/tokens`, '', 'session'],
    ['api.ping', 'api', 'GET', `${p}/ping`, '', 'none'],
    ['runner.builds', 'runner', 'POST', '/builds', '', 'session'],
    ['runner.build', 'runner', 'GET', '/builds/:id', 'id', 'session'],
    ['runner.buildCancel', 'runner', 'POST', '/builds/:id/cancel', 'id', 'session'],
    ['runner.streamShared', 'runner', 'GET', '/streams/shared', '', 'session'],
    ['runner.artifact', 'runner', 'GET', '/artifacts/:handle', 'handle', 'session'],
    ['runner.queues', 'runner', 'GET', '/queues', '', 'none'],
    ['runner.runners', 'runner', 'GET', '/runners', '', 'none'],
    ['runner.jobs', 'runner', 'GET', '/jobs', '', 'session'],
    ['registry.internalSync', 'registry.internal', 'POST', '/sync', '', 'service'],
    ['registry.packages', 'registry.internal', 'GET', '/packages', '', 'service'],
    ['registry.index', 'registry.internal', 'GET', '/index', '', 'service'],
    ['registry.artifact', 'registry.internal', 'GET', '/artifacts/:name', 'name', 'service'],
    ['registry.policies', 'registry.internal', 'GET', '/policies', '', 'service'],
  ]
  return rows.map(([routeKey, service, method, path, params, auth]) => ({
    routeKey,
    service: service as unknown as ApiRef['service'],
    method,
    path,
    params: params ? params.split(',') : [],
    auth,
  }))
}
