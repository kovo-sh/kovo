// AppBlueprint for acme-saas: a multi-tenant B2B SaaS lab. 67 routes across projects, invoices,
// files, members, invites, API keys, webhooks, reports, notifications, billing, SSO/OAuth, admin and
// legacy surfaces, plus 28 planted (vulnerable, hardened) twin sites. The generator randomizes the
// api prefix, resource nouns, param names, id format, personas and which sites are decoys per seed.
import type { AppBlueprint, RouteTemplate, SiteSpec } from '../../../lib/types.ts'

import { spec as invoiceBola } from '../sites/acme.invoice-bola/spec.ts'
import { spec as projectSearchSqli } from '../sites/acme.project-search-sqli/spec.ts'
import { spec as filePathTraversal } from '../sites/acme.file-path-traversal/spec.ts'
import { spec as avatarSsrf } from '../sites/acme.avatar-ssrf/spec.ts'
import { spec as memberRolePrivesc } from '../sites/acme.member-role-privesc/spec.ts'
import { spec as projectMassAssign } from '../sites/acme.project-mass-assign/spec.ts'
import { spec as invoiceWriteBola } from '../sites/acme.invoice-write-bola/spec.ts'
import { spec as reportSsti } from '../sites/acme.report-ssti/spec.ts'
import { spec as webhookForgery } from '../sites/acme.webhook-forgery/spec.ts'
import { spec as jwtNone } from '../sites/acme.jwt-none/spec.ts'
import { spec as ssoOpenRedirect } from '../sites/acme.sso-open-redirect/spec.ts'
import { spec as projectStoredXss } from '../sites/acme.project-stored-xss/spec.ts'
import { spec as reflectedSearchXss } from '../sites/acme.reflected-search-xss/spec.ts'
import { spec as importXxe } from '../sites/acme.import-xxe/spec.ts'
import { spec as exportCmdInjection } from '../sites/acme.export-cmd-injection/spec.ts'
import { spec as settingsCsrf } from '../sites/acme.settings-csrf/spec.ts'
import { spec as reportCachePoison } from '../sites/acme.report-cache-poison/spec.ts'
import { spec as apikeyDisclosure } from '../sites/acme.apikey-disclosure/spec.ts'
import { spec as seatInvariant } from '../sites/acme.seat-invariant/spec.ts'
import { spec as creditDoubleSpend } from '../sites/acme.credit-double-spend/spec.ts'
import { spec as inviteWorkflowSkip } from '../sites/acme.invite-workflow-skip/spec.ts'
import { spec as adminBfla } from '../sites/acme.admin-bfla/spec.ts'
import { spec as legacyAuthBypass } from '../sites/acme.legacy-auth-bypass/spec.ts'
import { spec as notificationIdor } from '../sites/acme.notification-idor/spec.ts'
import { spec as fileListBola } from '../sites/acme.file-list-bola/spec.ts'
import { spec as billingTamper } from '../sites/acme.billing-tamper/spec.ts'
import { spec as auditlogSecret } from '../sites/acme.auditlog-secret/spec.ts'
import { spec as exportOpenRedirect } from '../sites/acme.export-open-redirect/spec.ts'

const sites: SiteSpec[] = [
  invoiceBola, projectSearchSqli, filePathTraversal, avatarSsrf, memberRolePrivesc, projectMassAssign,
  invoiceWriteBola, reportSsti, webhookForgery, jwtNone, ssoOpenRedirect, projectStoredXss,
  reflectedSearchXss, importXxe, exportCmdInjection, settingsCsrf, reportCachePoison, apikeyDisclosure,
  seatInvariant, creditDoubleSpend, inviteWorkflowSkip, adminBfla, legacyAuthBypass, notificationIdor,
  fileListBola, billingTamper, auditlogSecret, exportOpenRedirect,
]

const r = (method: string, path: string): RouteTemplate => ({ method, path })

const routes: Record<string, RouteTemplate> = {
  // session + auth
  appConfig: r('GET', '/app-config.json'),
  health: r('GET', '/health'),
  login: r('POST', '/api/auth/login'),
  logout: r('POST', '/api/auth/logout'),
  me: r('GET', '/api/me'),
  twofaVerify: r('POST', '/api/auth/2fa'),
  ssoStart: r('GET', '/api/auth/sso'),
  ssoCallback: r('GET', '/api/auth/sso/callback'),
  legacyLogin: r('POST', '/api/v1/login'),
  refreshToken: r('POST', '/api/auth/token'),
  // projects
  listProjects: r('GET', '/api/{noun:projects}'),
  getProject: r('GET', '/api/{noun:projects}/:projectId'),
  createProject: r('POST', '/api/{noun:projects}'),
  updateProject: r('PATCH', '/api/{noun:projects}/:projectId'),
  deleteProject: r('DELETE', '/api/{noun:projects}/:projectId'),
  searchProjects: r('GET', '/api/search/{noun:projects}'),
  renderProjectCard: r('GET', '/api/{noun:projects}/:projectId/card'),
  // invoices
  listInvoices: r('GET', '/api/{noun:invoices}'),
  getInvoice: r('GET', '/api/{noun:invoices}/:invoiceId'),
  createInvoice: r('POST', '/api/{noun:invoices}'),
  updateInvoice: r('PATCH', '/api/{noun:invoices}/:invoiceId'),
  deleteInvoice: r('DELETE', '/api/{noun:invoices}/:invoiceId'),
  exportInvoices: r('GET', '/api/{noun:exports}/{noun:invoices}'),
  // files
  listFiles: r('GET', '/api/{noun:files}'),
  getFile: r('GET', '/api/{noun:files}/:fileId'),
  downloadFile: r('GET', '/api/download/{noun:files}'),
  uploadFile: r('POST', '/api/{noun:files}'),
  // members / invites / api keys
  listMembers: r('GET', '/api/{noun:members}'),
  getMember: r('GET', '/api/{noun:members}/:memberId'),
  updateMember: r('PATCH', '/api/{noun:members}/:memberId'),
  removeMember: r('DELETE', '/api/{noun:members}/:memberId'),
  updateAvatar: r('PUT', '/api/{noun:members}/:memberId/avatar'),
  inviteMember: r('POST', '/api/{noun:invites}'),
  acceptInvite: r('POST', '/api/{noun:invites}/accept'),
  listApiKeys: r('GET', '/api/{noun:apikeys}'),
  createApiKey: r('POST', '/api/{noun:apikeys}'),
  revokeApiKey: r('DELETE', '/api/{noun:apikeys}/:keyId'),
  // webhooks
  listWebhooks: r('GET', '/api/{noun:webhooks}'),
  createWebhook: r('POST', '/api/{noun:webhooks}'),
  deleteWebhook: r('DELETE', '/api/{noun:webhooks}/:hookId'),
  receiveWebhook: r('POST', '/api/{noun:webhooks}/receive'),
  // reports / exports
  listReports: r('GET', '/api/{noun:reports}'),
  getReport: r('GET', '/api/{noun:reports}/:reportId'),
  createReport: r('POST', '/api/{noun:reports}'),
  renderReport: r('GET', '/api/{noun:reports}/:reportId/render'),
  publicReport: r('GET', '/api/{noun:reports}/:reportId/public'),
  exportReport: r('POST', '/api/{noun:exports}/{noun:reports}'),
  // notifications
  listNotifications: r('GET', '/api/{noun:notifications}'),
  getNotification: r('GET', '/api/{noun:notifications}/:notifId'),
  markNotification: r('POST', '/api/{noun:notifications}/:notifId/read'),
  // billing / settings
  getBilling: r('GET', '/api/{noun:plans}/current'),
  updatePlan: r('PATCH', '/api/{noun:plans}/current'),
  addSeat: r('POST', '/api/{noun:seats}'),
  applyCredit: r('POST', '/api/{noun:credits}'),
  getSettings: r('GET', '/api/settings'),
  updateSettings: r('POST', '/api/settings'),
  // integrations
  getIntegrationConfig: r('GET', '/api/{noun:integrations}/config'),
  importProjects: r('POST', '/api/{noun:integrations}/import'),
  // admin (not referenced by the UI — must be discovered)
  adminListTenants: r('GET', '/api/admin/{noun:orgs}'),
  adminGetTenant: r('GET', '/api/admin/{noun:orgs}/:orgId'),
  adminDeleteUser: r('DELETE', '/api/admin/{noun:members}/:memberId'),
  adminAuditLog: r('GET', '/api/admin/{noun:auditlogs}'),
  adminImpersonate: r('POST', '/api/admin/impersonate'),
  // legacy v1 (not referenced by the UI — must be discovered)
  legacyListInvoices: r('GET', '/api/v1/{noun:invoices}'),
  legacyGetUser: r('GET', '/api/v1/{noun:members}/:memberId'),
  reflectedSearch: r('GET', '/api/v1/search'),
  exportRedirect: r('GET', '/api/v1/{noun:exports}/download'),
}

export const blueprint: AppBlueprint = {
  app: 'acme-saas',
  apiPrefixes: ['/api', '/api/v1', '/rest', '/api/2'],
  vocab: {
    projects: ['projects', 'workspaces', 'spaces'],
    invoices: ['invoices', 'billing-docs', 'statements'],
    files: ['files', 'documents', 'assets'],
    members: ['members', 'users', 'people'],
    invites: ['invites', 'invitations', 'enrollments'],
    apikeys: ['api-keys', 'tokens', 'credentials'],
    webhooks: ['webhooks', 'hooks', 'callbacks'],
    reports: ['reports', 'analytics', 'insights'],
    notifications: ['notifications', 'alerts', 'inbox'],
    orgs: ['orgs', 'tenants', 'accounts'],
    plans: ['plan', 'subscription', 'billing'],
    auditlogs: ['audit-log', 'activity', 'events'],
    integrations: ['integrations', 'connections', 'apps'],
    exports: ['exports', 'downloads', 'archives'],
    seats: ['seats', 'licenses', 'allocations'],
    credits: ['credits', 'wallet', 'balance'],
  },
  paramVocab: {
    projectId: ['projectId', 'projId', 'workspaceId'],
    invoiceId: ['invoiceId', 'invId', 'docId'],
    fileId: ['fileId', 'docId', 'assetId'],
    memberId: ['memberId', 'userId', 'personId'],
    notifId: ['notifId', 'alertId', 'msgId'],
    reportId: ['reportId', 'analyticId', 'insightId'],
    keyId: ['keyId', 'tokenId', 'credId'],
    hookId: ['hookId', 'webhookId', 'callbackId'],
    orgId: ['orgId', 'tenantId', 'accountId'],
    inviteId: ['inviteId', 'invitationId', 'enrollId'],
    planId: ['planId', 'tierId', 'subscriptionId'],
    q: ['q', 'query', 'term'],
    filePath: ['path', 'file', 'name'],
    avatarUrl: ['avatarUrl', 'imageUrl', 'pictureUrl'],
    url: ['url', 'returnTo', 'next'],
    role: ['role', 'accessLevel', 'permission'],
    amount: ['amount', 'value', 'cents'],
    name: ['name', 'label', 'title'],
    token: ['token', 'code', 'nonce'],
    email: ['email', 'login', 'username'],
  },
  routes,
  idFormats: ['int', 'uuid', 'prefixed', 'hashid'],
  sites,
  decoyCount: { min: 6, max: 8 },
}
