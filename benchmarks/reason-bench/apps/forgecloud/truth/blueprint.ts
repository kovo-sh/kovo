// AppBlueprint for forgecloud: a multi-tenant DevOps / CI-CD workspace. Route keys and runtime
// parameter names are stable across seeds; the generator randomizes the api prefix, resource nouns,
// param names, id format, personas and which site twins are mounted hardened.
import type { AppBlueprint, RouteTemplate, SiteSpec } from '../../../lib/types.ts'

const r = (method: string, path: string): RouteTemplate => ({ method, path })

const routes: Record<string, RouteTemplate> = {
  // shell + auth
  appConfig: r('GET', '/app-config.json'),
  health: r('GET', '/health'),
  login: r('POST', '/api/auth/login'),
  logout: r('POST', '/api/auth/logout'),
  me: r('GET', '/api/auth/me'),
  ssoStart: r('GET', '/api/auth/sso'),
  ssoCallback: r('POST', '/api/auth/sso/callback'),
  // orgs / workspaces
  'orgs.list': r('GET', '/api/{noun:orgs}'),
  'workspaces.list': r('GET', '/api/{noun:workspaces}'),
  'workspaces.detail': r('GET', '/api/{noun:workspaces}/:workspaceId'),
  'workspaces.current': r('GET', '/api/{noun:workspaces}/current'),
  // projects
  'projects.list': r('GET', '/api/{noun:projects}'),
  'projects.create': r('POST', '/api/{noun:projects}'),
  'projects.detail': r('GET', '/api/{noun:projects}/:projectId'),
  'projects.update': r('PATCH', '/api/{noun:projects}/:projectId'),
  'projects.transfer': r('POST', '/api/{noun:projects}/:projectId/transfer'),
  'projects.members': r('GET', '/api/{noun:projects}/:projectId/members'),
  // pipelines
  'pipelines.list': r('GET', '/api/{noun:pipelines}'),
  'pipelines.detail': r('GET', '/api/{noun:pipelines}/:pipelineId'),
  // builds
  'builds.list': r('GET', '/api/{noun:builds}'),
  'builds.detail': r('GET', '/api/{noun:builds}/:buildId'),
  'builds.logs': r('GET', '/api/{noun:builds}/:buildId/logs'),
  'builds.cancel': r('POST', '/api/{noun:builds}/:buildId/cancel'),
  'streams.build': r('GET', '/api/streams/{noun:builds}/:buildId'),
  // tokens
  'tokens.list': r('GET', '/api/{noun:tokens}'),
  'tokens.create': r('POST', '/api/{noun:tokens}'),
  'tokens.revoke': r('POST', '/api/{noun:tokens}/:tokenId/revoke'),
  // secrets
  'secrets.list': r('GET', '/api/{noun:secrets}'),
  'secrets.create': r('POST', '/api/{noun:secrets}'),
  'secrets.detail': r('GET', '/api/{noun:secrets}/:secretId'),
  'secrets.update': r('PATCH', '/api/{noun:secrets}/:secretId'),
  'secrets.delete': r('DELETE', '/api/{noun:secrets}/:secretId'),
  'secrets.batch': r('POST', '/api/{noun:secrets}/batch'),
  // artifacts / exports
  'artifacts.list': r('GET', '/api/{noun:artifacts}'),
  'artifacts.mint': r('POST', '/api/{noun:artifacts}/:artifactId/links'),
  'artifacts.fetch': r('GET', '/api/{noun:exports}/signed/:token'),
  'exports.list': r('GET', '/api/{noun:exports}'),
  'exports.queue': r('POST', '/api/{noun:exports}'),
  // deployments
  'deployments.list': r('GET', '/api/{noun:deployments}'),
  'deployments.create': r('POST', '/api/{noun:deployments}'),
  'deployments.detail': r('GET', '/api/{noun:deployments}/:deploymentId'),
  'deployments.approve': r('POST', '/api/{noun:deployments}/:deploymentId/approve'),
  'deployments.schedule': r('POST', '/api/{noun:deployments}/:deploymentId/schedule'),
  'deployments.dispute': r('POST', '/api/{noun:deployments}/:deploymentId/dispute'),
  'deployments.reopen': r('POST', '/api/{noun:deployments}/:deploymentId/reopen'),
  'deployments.release': r('POST', '/api/{noun:deployments}/:deploymentId/release'),
  'deployments.promote': r('POST', '/api/{noun:deployments}/:deploymentId/promote'),
  // automations
  'automations.list': r('GET', '/api/{noun:automations}'),
  'automations.create': r('POST', '/api/{noun:automations}'),
  // webhooks
  'webhooks.list': r('GET', '/api/{noun:webhooks}'),
  'webhooks.create': r('POST', '/api/{noun:webhooks}'),
  'webhooks.update': r('PATCH', '/api/{noun:webhooks}/:hookId'),
  'webhooks.deliveries': r('GET', '/api/{noun:webhooks}/:hookId/deliveries'),
  'webhooks.receive': r('POST', '/api/{noun:webhooks}/receive'),
  // members / teams
  'members.list': r('GET', '/api/{noun:members}'),
  'members.update': r('PATCH', '/api/{noun:members}/:memberId'),
  'members.remove': r('DELETE', '/api/{noun:members}/:memberId'),
  'members.invite': r('POST', '/api/{noun:members}/invites'),
  'teams.list': r('GET', '/api/{noun:teams}'),
  'teams.create': r('POST', '/api/{noun:teams}'),
  'teams.addMember': r('POST', '/api/{noun:teams}/:teamId/members'),
  // admin / search / graph
  'org.permissions': r('GET', '/api/{noun:orgs}/:orgId/permissions'),
  'org.settings': r('GET', '/api/{noun:orgs}/:orgId/settings'),
  'org.settings.update': r('PATCH', '/api/{noun:orgs}/:orgId/settings'),
  'audit.list': r('GET', '/api/{noun:auditlogs}'),
  'admin.members': r('GET', '/api/admin/{noun:members}'),
  'search.facets': r('GET', '/api/search/facets'),
  'search.query': r('GET', '/api/search'),
  'search.save': r('POST', '/api/search/saved'),
  graphql: r('POST', '/api/graphql'),
  'graphql.batch': r('POST', '/api/graphql/batch'),
}

export const blueprint: AppBlueprint = {
  app: 'forgecloud' as AppBlueprint['app'],
  apiPrefixes: ['/api', '/api/v1', '/rest', '/api/2'],
  vocab: {
    projects: ['projects', 'repos', 'workspaces'],
    pipelines: ['pipelines', 'workflows', 'stages'],
    builds: ['builds', 'runs', 'jobs'],
    secrets: ['secrets', 'credentials', 'vaults'],
    tokens: ['tokens', 'pats', 'access-tokens'],
    artifacts: ['artifacts', 'packages', 'outputs'],
    exports: ['exports', 'downloads', 'archives'],
    deployments: ['deployments', 'releases', 'rollouts'],
    webhooks: ['webhooks', 'hooks', 'callbacks'],
    members: ['members', 'users', 'people'],
    teams: ['teams', 'groups', 'crews'],
    orgs: ['orgs', 'tenants', 'accounts'],
    workspaces: ['workspaces', 'spaces', 'envs'],
    automations: ['automations', 'service-accounts', 'bots'],
    auditlogs: ['audit-log', 'activity', 'events'],
  },
  paramVocab: {
    projectId: ['projectId', 'repoId', 'workspaceId'],
    pipelineId: ['pipelineId', 'workflowId', 'stageId'],
    buildId: ['buildId', 'runId', 'jobId'],
    tokenId: ['tokenId', 'patId', 'credentialId'],
    secretId: ['secretId', 'credId', 'vaultId'],
    artifactId: ['artifactId', 'packageId', 'outputId'],
    deploymentId: ['deploymentId', 'releaseId', 'rolloutId'],
    hookId: ['hookId', 'webhookId', 'callbackId'],
    memberId: ['memberId', 'userId', 'personId'],
    teamId: ['teamId', 'groupId', 'crewId'],
    orgId: ['orgId', 'tenantId', 'accountId'],
    workspaceId: ['workspaceId', 'spaceId', 'envId'],
    token: ['token', 'link', 'nonce'],
    q: ['q', 'query', 'term'],
    email: ['email', 'login', 'username'],
    name: ['name', 'label', 'title'],
    role: ['role', 'accessLevel', 'permission'],
    url: ['url', 'endpoint', 'target'],
  },
  routes,
  idFormats: ['int', 'uuid', 'prefixed', 'hashid'],
  sites: [] as SiteSpec[],
  decoyCount: { min: 5, max: 5 },
}

export function withSites(sites: SiteSpec[]): AppBlueprint {
  return { ...blueprint, sites }
}
