// Logical route templates, vocab synonyms and param synonyms for the opsportal app. Lives under
// truth/ (never materialized). Nouns in {noun:X} and :param segments are substituted per seed.
import type { RouteTemplate } from '../../../lib/types.ts'

export const vocab: Record<string, string[]> = {
  tickets: ['tickets', 'cases', 'issues'],
  accounts: ['accounts', 'customers', 'orgs'],
  users: ['users', 'members', 'staff'],
  teams: ['teams', 'squads', 'groups'],
  reports: ['reports', 'exports', 'docs'],
  searches: ['searches', 'queries', 'saved-views'],
  logs: ['logs', 'journals', 'streams'],
  jobs: ['jobs', 'tasks', 'runs'],
  backups: ['backups', 'snapshots', 'archives'],
  diagnostics: ['diagnostics', 'diag', 'probes'],
  integrations: ['integrations', 'connectors', 'links'],
  webhooks: ['webhooks', 'hooks', 'dispatchers'],
  flags: ['flags', 'toggles', 'switches'],
  audit: ['audit', 'auditlog', 'trail'],
  tokens: ['tokens', 'keys', 'credentials'],
}

export const paramVocab: Record<string, string[]> = {
  ticketId: ['ticketId', 'ticketRef', 'tid'],
  accountId: ['accountId', 'accountRef', 'aid'],
  userId: ['userId', 'memberId', 'uid'],
  teamId: ['teamId', 'squadId', 'grpId'],
  reportId: ['reportId', 'reportRef', 'rid'],
  jobId: ['jobId', 'taskId', 'jid'],
  integrationId: ['integrationId', 'connectorId', 'iid'],
  webhookId: ['webhookId', 'hookId', 'wid'],
  flagKey: ['flagKey', 'toggleKey', 'fkey'],
  auditId: ['auditId', 'eventId', 'evId'],
  templateSrc: ['template', 'source', 'layout'],
  host: ['host', 'target', 'endpointHost'],
  logName: ['file', 'logFile', 'name'],
  nextUrl: ['next', 'returnTo', 'continue'],
  searchQuery: ['q', 'term', 'keyword'],
  noteBody: ['note', 'content', 'message'],
  filterExpr: ['filter', 'expr', 'clause'],
  role: ['role', 'grant', 'level'],
  teamField: ['teamField', 'orgField', 'squadField'],
  webhookUrl: ['url', 'endpoint', 'callbackUrl'],
  accountField: ['field', 'attr', 'prop'],
  flagValue: ['value', 'state', 'setting'],
  xmlDoc: ['doc', 'xml', 'descriptor'],
  token: ['token', 'assertion', 'bearer'],
}

const r = (method: string, path: string): RouteTemplate => ({ method, path })

export const routes: Record<string, RouteTemplate> = {
  // auth + common
  login: r('POST', '/login'),
  logout: r('POST', '/logout'),
  me: r('GET', '/api/me'),
  csrf: r('GET', '/api/csrf'),
  health: r('GET', '/api/health'),
  appConfig: r('GET', '/app-config.json'),
  ssoStart: r('GET', '/sso/start'),
  ssoCallback: r('GET', '/sso/callback'),
  samlImport: r('POST', '/api/sso/import'),
  // dashboard + graphql
  graphql: r('POST', '/api/graphql'),
  dashboard: r('GET', '/api/dashboard'),
  dashboardSummary: r('GET', '/api/dashboard/summary'),
  // tickets
  ticketList: r('GET', '/api/{noun:tickets}'),
  ticketGet: r('GET', '/api/{noun:tickets}/:ticketId'),
  ticketView: r('GET', '/api/{noun:tickets}/:ticketId/view'),
  ticketCreate: r('POST', '/api/{noun:tickets}'),
  ticketUpdate: r('PATCH', '/api/{noun:tickets}/:ticketId'),
  ticketNoteCreate: r('POST', '/api/{noun:tickets}/:ticketId/notes'),
  ticketNotes: r('GET', '/api/{noun:tickets}/:ticketId/notes'),
  ticketAssign: r('POST', '/api/{noun:tickets}/:ticketId/assign'),
  // accounts
  accountList: r('GET', '/api/{noun:accounts}'),
  accountGet: r('GET', '/api/{noun:accounts}/:accountId'),
  accountUpdate: r('PATCH', '/api/{noun:accounts}/:accountId'),
  accountSearch: r('GET', '/api/{noun:accounts}/search'),
  accountCreate: r('POST', '/api/{noun:accounts}'),
  // users + teams
  userList: r('GET', '/api/{noun:users}'),
  userGet: r('GET', '/api/{noun:users}/:userId'),
  userUpdate: r('PATCH', '/api/{noun:users}/:userId'),
  roleChange: r('POST', '/api/{noun:users}/:userId/role'),
  teamList: r('GET', '/api/{noun:teams}'),
  teamGet: r('GET', '/api/{noun:teams}/:teamId'),
  // reports
  reportList: r('GET', '/api/{noun:reports}'),
  reportGet: r('GET', '/api/{noun:reports}/:reportId'),
  reportRender: r('POST', '/api/{noun:reports}/render'),
  reportCreate: r('POST', '/api/{noun:reports}'),
  // saved searches
  searchList: r('GET', '/api/{noun:searches}'),
  searchRun: r('POST', '/api/{noun:searches}/run'),
  searchCreate: r('POST', '/api/{noun:searches}'),
  // logs
  logList: r('GET', '/api/{noun:logs}'),
  logView: r('GET', '/api/{noun:logs}/view'),
  logFilter: r('POST', '/api/{noun:logs}/filter'),
  // jobs + diagnostics + backups
  jobList: r('GET', '/api/{noun:jobs}'),
  jobGet: r('GET', '/api/{noun:jobs}/:jobId'),
  jobTrigger: r('POST', '/api/{noun:jobs}/:jobId/trigger'),
  jobComplete: r('POST', '/api/{noun:jobs}/:jobId/complete'),
  backupRun: r('POST', '/api/{noun:backups}/run'),
  diagRun: r('POST', '/api/{noun:diagnostics}/run'),
  backupCallback: r('POST', '/api/{noun:backups}/callback'),
  // integrations + webhooks
  integrationList: r('GET', '/api/{noun:integrations}'),
  integrationGet: r('GET', '/api/{noun:integrations}/:integrationId'),
  integrationFetch: r('POST', '/api/{noun:integrations}/:integrationId/fetch'),
  webhookList: r('GET', '/api/{noun:webhooks}'),
  webhookCreate: r('POST', '/api/{noun:webhooks}'),
  // `ping` is the carrier's delivery-test verb; the probe's first trigger candidate is /ping.
  webhookTest: r('POST', '/api/{noun:webhooks}/:webhookId/ping'),
  // feature flags
  flagList: r('GET', '/api/{noun:flags}'),
  flagGet: r('GET', '/api/{noun:flags}/:flagKey'),
  flagSet: r('PATCH', '/api/{noun:flags}/:flagKey'),
  // audit
  auditList: r('GET', '/api/{noun:audit}'),
  auditGet: r('GET', '/api/{noun:audit}/:auditId'),
  // api tokens + legacy v1
  tokenList: r('GET', '/api/{noun:tokens}'),
  tokenIssue: r('POST', '/api/{noun:tokens}'),
  apiWhoami: r('GET', '/api/v1/whoami'),
  v1AccountGet: r('GET', '/api/v1/{noun:accounts}/:accountId'),
  adminUsers: r('GET', '/api/admin/users'),
  adminFlags: r('GET', '/api/admin/flags'),
}
