// AppBlueprint for ledgerflow: a multi-tenant B2B billing, wallets and approvals lab. Route keys are
// the stable contract shared by the shell, the site modules and the generator; vocab/param synonyms
// are randomized per seed. Site specs are discovered at runtime from sites/<id>/spec.ts so the shell
// starts with zero sites mounted.
import type { AppBlueprint, RouteTemplate, SiteSpec } from '../../../lib/types.ts'

const r = (method: string, path: string): RouteTemplate => ({ method, path })

export const ROUTES: Record<string, RouteTemplate> = {
  appConfig: r('GET', '/app-config.json'),
  apiReference: r('GET', '/api'),
  health: r('GET', '/api/health'),
  dashboard: r('GET', '/api/dashboard'),
  login: r('POST', '/api/auth/login'),
  logout: r('POST', '/api/auth/logout'),
  me: r('GET', '/api/me'),
  ssoStart: r('GET', '/api/auth/sso/start'),
  ssoCallback: r('GET', '/api/auth/sso/callback'),
  requestPasswordReset: r('POST', '/api/auth/password/reset'),
  changeEmail: r('POST', '/api/me/email'),

  listInvoices: r('GET', '/api/{noun:invoices}'),
  getInvoice: r('GET', '/api/{noun:invoices}/:invoiceId'),
  createInvoice: r('POST', '/api/{noun:invoices}'),
  updateInvoice: r('PATCH', '/api/{noun:invoices}/:invoiceId'),
  deleteInvoice: r('DELETE', '/api/{noun:invoices}/:invoiceId'),
  previewInvoice: r('GET', '/api/{noun:invoices}/:invoiceId/preview'),
  exportInvoicePdf: r('POST', '/api/{noun:invoices}/:invoiceId/pdf'),

  listOrders: r('GET', '/api/{noun:orders}'),
  getOrder: r('GET', '/api/{noun:orders}/:orderId'),
  updateOrder: r('PATCH', '/api/{noun:orders}/:orderId'),
  refundOrderItem: r('POST', '/api/{noun:orders}/:orderId/items/:itemId/refund'),

  getCart: r('GET', '/api/{noun:carts}/:cartId'),
  listCarts: r('GET', '/api/{noun:carts}'),
  addCartItem: r('POST', '/api/{noun:carts}/:cartId/items'),
  patchCartItem: r('PATCH', '/api/{noun:carts}/:cartId/items/:itemId'),
  deleteCartItem: r('DELETE', '/api/{noun:carts}/:cartId/items/:itemId'),
  applyCoupon: r('POST', '/api/{noun:carts}/:cartId/coupon'),
  checkoutCart: r('POST', '/api/{noun:carts}/:cartId/checkout'),
  listCoupons: r('GET', '/api/{noun:coupons}'),

  listWallets: r('GET', '/api/{noun:wallets}'),
  convertWallet: r('POST', '/api/{noun:wallets}/:walletId/convert'),
  listTransfers: r('GET', '/api/{noun:transfers}'),
  transferFunds: r('POST', '/api/{noun:transfers}'),
  createPayout: r('POST', '/api/{noun:payouts}'),
  listPayouts: r('GET', '/api/{noun:payouts}'),
  updatePayout: r('PATCH', '/api/{noun:payouts}/:payoutId'),
  approvePayout: r('POST', '/api/{noun:payouts}/:payoutId/approve'),
  listApprovals: r('GET', '/api/{noun:approvals}'),
  delegateApproval: r('POST', '/api/{noun:approvals}/:approvalId/delegate'),

  getSubscription: r('GET', '/api/{noun:subscriptions}'),
  upgradePlan: r('POST', '/api/{noun:subscriptions}/upgrade'),
  downgradePlan: r('POST', '/api/{noun:subscriptions}/downgrade'),

  listMembers: r('GET', '/api/{noun:members}'),
  updateRole: r('PATCH', '/api/{noun:members}/:memberId/role'),
  removeMember: r('DELETE', '/api/{noun:members}/:memberId'),
  listInvites: r('GET', '/api/{noun:invites}'),
  inviteMember: r('POST', '/api/{noun:invites}'),
  downgradeInvite: r('PATCH', '/api/{noun:invites}/:inviteId'),
  acceptInvite: r('POST', '/api/{noun:invites}/accept'),
  activityFeed: r('GET', '/api/{noun:activity}'),

  listExports: r('GET', '/api/{noun:exports}'),
  queueExport: r('POST', '/api/{noun:exports}'),
  downloadExport: r('GET', '/api/{noun:exports}/:exportId/download'),
  signedDownload: r('GET', '/api/downloads'),

  listFiles: r('GET', '/api/{noun:files}'),
  downloadFile: r('GET', '/api/{noun:files}/:fileId/download'),
  uploadFile: r('POST', '/api/{noun:files}'),

  createPaymentIntent: r('POST', '/api/{noun:payment-intents}'),
  getPaymentIntent: r('GET', '/api/{noun:payment-intents}/:intentId'),
  capturePaymentIntent: r('POST', '/api/{noun:payment-intents}/:intentId/capture'),

  receiveWebhook: r('POST', '/api/hooks/ledger'),
}

export const VOCAB: Record<string, string[]> = {
  invoices: ['invoices', 'billing-docs', 'statements'],
  orders: ['orders', 'purchases', 'sales'],
  carts: ['carts', 'baskets', 'checkouts'],
  coupons: ['coupons', 'promotions', 'discounts'],
  wallets: ['wallets', 'balances', 'funds'],
  transfers: ['transfers', 'movements', 'remittances'],
  payouts: ['payouts', 'disbursements', 'withdrawals'],
  approvals: ['approvals', 'signoffs', 'reviews'],
  subscriptions: ['subscriptions', 'plans', 'licences'],
  members: ['members', 'people', 'staff'],
  invites: ['invites', 'onboarding', 'invitations'],
  activity: ['activity', 'timeline', 'feed'],
  exports: ['exports', 'archives', 'reports'],
  files: ['files', 'documents', 'attachments'],
  'payment-intents': ['payment-intents', 'charges', 'captures'],
}

export const PARAM_VOCAB: Record<string, string[]> = {
  invoiceId: ['invoiceId', 'docId', 'billId'],
  orderId: ['orderId', 'purchaseId', 'saleId'],
  itemId: ['itemId', 'lineId', 'positionId'],
  cartId: ['cartId', 'basketId', 'checkoutId'],
  payoutId: ['payoutId', 'disbursementId', 'withdrawalId'],
  approvalId: ['approvalId', 'signoffId', 'reviewId'],
  inviteId: ['inviteId', 'onboardingId', 'invitationId'],
  memberId: ['memberId', 'personId', 'staffId'],
  exportId: ['exportId', 'archiveId', 'reportId'],
  fileId: ['fileId', 'documentId', 'attachmentId'],
  intentId: ['intentId', 'chargeId', 'captureId'],
  walletId: ['walletId', 'balanceId', 'fundId'],
  tenantId: ['tenantId', 'orgId', 'workspaceId'],
  token: ['token', 'ticket', 'credential'],
  email: ['email', 'address', 'mail'],
  amount: ['amount', 'value', 'total'],
  role: ['role', 'permission', 'level'],
  plan: ['plan', 'tier', 'package'],
  kind: ['kind', 'type', 'category'],
  sku: ['sku', 'product', 'code'],
}

const ID_FORMATS = ['int', 'uuid', 'prefixed', 'hashid'] as const

export function blueprintWith(sites: SiteSpec[]): AppBlueprint {
  const decoy = sites.length === 0 ? { min: 0, max: 0 } : { min: Math.min(5, sites.length), max: Math.min(5, sites.length) }
  return {
    app: 'ledgerflow',
    apiPrefixes: ['/api', '/rest', '/api/v1'],
    vocab: VOCAB,
    paramVocab: PARAM_VOCAB,
    routes: ROUTES,
    idFormats: [...ID_FORMATS],
    sites,
    decoyCount: decoy,
  }
}

export const blueprint = blueprintWith([])
