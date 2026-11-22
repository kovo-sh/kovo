// AppBlueprint for shopflow: a multi-tenant e-commerce / payments platform (storefront + merchant
// back-office). Routes cover storefront, back-office, admin-only (UI-unreferenced) and legacy v1
// surfaces. All 26 planted SiteSpecs are imported from their sites/<id>/spec.ts. Validated by
// generator/validate.ts (see tests/shopflow.test.ts).
import type { AppBlueprint, RouteTemplate } from '../../../lib/types.ts'
import { spec as orderBolaRead } from '../sites/order-bola-read/spec.ts'
import { spec as shipmentBolaWrite } from '../sites/shipment-bola-write/spec.ts'
import { spec as productSearchSqli } from '../sites/product-search-sqli/spec.ts'
import { spec as invoicePathTraversal } from '../sites/invoice-path-traversal/spec.ts'
import { spec as productImageSsrf } from '../sites/product-image-ssrf/spec.ts'
import { spec as checkoutOpenRedirect } from '../sites/checkout-open-redirect/spec.ts'
import { spec as reviewStoredXss } from '../sites/review-stored-xss/spec.ts'
import { spec as orderMassAssignment } from '../sites/order-mass-assignment/spec.ts'
import { spec as apiJwtAlgNone } from '../sites/api-jwt-alg-none/spec.ts'
import { spec as refundCsrf } from '../sites/refund-csrf/spec.ts'
import { spec as negativeQtyLogic } from '../sites/negative-qty-logic/spec.ts'
import { spec as storefrontCachePoison } from '../sites/storefront-cache-poison/spec.ts'
import { spec as giftcardRace } from '../sites/giftcard-race/spec.ts'
import { spec as paymentWebhookForgery } from '../sites/payment-webhook-forgery/spec.ts'
import { spec as productFeedXxe } from '../sites/product-feed-xxe/spec.ts'
import { spec as checkoutWorkflowSkip } from '../sites/checkout-workflow-skip/spec.ts'
import { spec as couponReuse } from '../sites/coupon-reuse/spec.ts'
import { spec as inventoryOversell } from '../sites/inventory-oversell/spec.ts'
import { spec as refundExceedsPayment } from '../sites/refund-exceeds-payment/spec.ts'
import { spec as tokenSecretDisclosure } from '../sites/token-secret-disclosure/spec.ts'
import { spec as customerBolaRead } from '../sites/customer-bola-read/spec.ts'
import { spec as adminImpersonatePrivesc } from '../sites/admin-impersonate-privesc/spec.ts'
import { spec as settingsSecretDisclosure } from '../sites/settings-secret-disclosure/spec.ts'
import { spec as shippingLabelSsrf } from '../sites/shipping-label-ssrf/spec.ts'
import { spec as couponAfterLock } from '../sites/coupon-after-lock/spec.ts'
import { spec as overRefundChain } from '../sites/over-refund-chain/spec.ts'

const r = (method: string, path: string): RouteTemplate => ({ method, path })

const routes: Record<string, RouteTemplate> = {
  // auth + common
  login: r('POST', '/login'),
  logout: r('POST', '/logout'),
  session: r('GET', '/api/session'),
  csrfToken: r('GET', '/api/csrf'),
  healthCheck: r('GET', '/api/health'),
  appConfig: r('GET', '/app-config.json'),
  // storefront: catalog + reviews
  listProducts: r('GET', '/api/{noun:products}'),
  getProduct: r('GET', '/api/{noun:products}/:productId'),
  searchProducts: r('GET', '/api/search'),
  productReviews: r('GET', '/api/{noun:products}/:productId/{noun:reviews}'),
  submitReview: r('POST', '/api/{noun:products}/:productId/{noun:reviews}'),
  listReviews: r('GET', '/api/{noun:reviews}'),
  getReview: r('GET', '/api/{noun:reviews}/:reviewId'),
  storeProductPage: r('GET', '/api/{noun:stores}/:storeId/{noun:products}/:productId'),
  // storefront: cart + checkout
  createCart: r('POST', '/api/{noun:carts}'),
  getCart: r('GET', '/api/{noun:carts}/:cartId'),
  addCartItem: r('POST', '/api/{noun:carts}/:cartId/items'),
  updateCartItem: r('PATCH', '/api/{noun:carts}/:cartId/items/:productId'),
  applyCoupon: r('POST', '/api/{noun:carts}/:cartId/{noun:coupons}'),
  applyPricedCoupon: r('POST', '/api/{noun:carts}/:cartId/{noun:coupons}/reapply'),
  checkout: r('POST', '/api/{noun:carts}/:cartId/checkout'),
  checkoutReturn: r('GET', '/api/checkout/return'),
  // storefront: gift cards
  listGiftCards: r('GET', '/api/{noun:giftcards}'),
  getGiftCard: r('GET', '/api/{noun:giftcards}/:giftCardId'),
  redeemGiftCard: r('POST', '/api/{noun:giftcards}/:giftCardId/redeem'),
  // orders
  listOrders: r('GET', '/api/{noun:orders}'),
  getOrder: r('GET', '/api/{noun:orders}/:orderId'),
  updateOrder: r('PATCH', '/api/{noun:orders}/:orderId'),
  cancelOrder: r('POST', '/api/{noun:orders}/:orderId/cancel'),
  confirmOrder: r('POST', '/api/{noun:orders}/:orderId/confirm'),
  capturePayment: r('POST', '/api/{noun:orders}/:orderId/{noun:payments}'),
  getInvoice: r('GET', '/api/{noun:orders}/:orderId/{noun:invoices}'),
  // fulfillment
  listShipments: r('GET', '/api/{noun:shipments}'),
  updateShipment: r('PATCH', '/api/{noun:shipments}/:shipmentId'),
  // payments + refunds + payouts
  listPayments: r('GET', '/api/{noun:payments}'),
  getPayment: r('GET', '/api/{noun:payments}/:paymentId'),
  createRefund: r('POST', '/api/{noun:refunds}'),
  createRefundLine: r('POST', '/api/{noun:refunds}/lines'),
  getRefund: r('GET', '/api/{noun:refunds}/:refundId'),
  approveRefund: r('POST', '/api/{noun:refunds}/:refundId/approve'),
  createPayout: r('POST', '/api/{noun:payouts}'),
  // customers (crm)
  listCustomers: r('GET', '/api/{noun:customers}'),
  getCustomer: r('GET', '/api/{noun:customers}/:customerId'),
  // moderation
  moderationQueue: r('GET', '/api/admin/{noun:reviews}'),
  moderateReview: r('PATCH', '/api/admin/{noun:reviews}/:reviewId'),
  // webhooks + imports
  listWebhooks: r('GET', '/api/{noun:webhooks}'),
  paymentWebhook: r('POST', '/api/{noun:webhooks}/{noun:payments}'),
  importProductFeed: r('POST', '/api/{noun:feeds}'),
  importShippingLabel: r('POST', '/api/{noun:labels}'),
  importProductImage: r('POST', '/api/{noun:products}/:productId/{noun:images}'),
  // tokens + settings + stores + reports
  listTokens: r('GET', '/api/{noun:tokens}'),
  getToken: r('GET', '/api/{noun:tokens}/:tokenId'),
  createToken: r('POST', '/api/{noun:tokens}'),
  getSettings: r('GET', '/api/settings'),
  updateSettings: r('PATCH', '/api/settings'),
  getStore: r('GET', '/api/{noun:stores}/:storeId'),
  salesReport: r('GET', '/api/reports/sales'),
  // admin-only (intentionally not referenced by the UI config)
  adminListStores: r('GET', '/api/admin/{noun:stores}'),
  adminImpersonate: r('POST', '/api/admin/impersonate'),
  adminConfig: r('GET', '/api/admin/config'),
  adminMetrics: r('GET', '/api/admin/metrics'),
  // legacy v1 compatibility surface
  legacyGetOrder: r('GET', '/api/legacy/{noun:orders}/:orderId'),
  legacyListProducts: r('GET', '/api/legacy/{noun:products}'),
  legacyGetCustomer: r('GET', '/api/legacy/{noun:customers}/:customerId'),
}

export const blueprint: AppBlueprint = {
  app: 'shopflow',
  apiPrefixes: ['/api/v1', '/rest', '/api'],
  vocab: {
    products: ['products', 'catalog', 'wares'],
    orders: ['orders', 'purchases', 'sales-orders'],
    carts: ['carts', 'baskets', 'bags'],
    coupons: ['coupons', 'promos', 'vouchers'],
    giftcards: ['gift-cards', 'credits', 'store-credit'],
    payments: ['payments', 'charges', 'transactions'],
    refunds: ['refunds', 'reversals', 'rmas'],
    shipments: ['shipments', 'fulfillments', 'deliveries'],
    reviews: ['reviews', 'ratings', 'testimonials'],
    customers: ['customers', 'shoppers', 'patrons'],
    invoices: ['invoices', 'receipts', 'billing-docs'],
    webhooks: ['webhooks', 'callbacks', 'event-hooks'],
    feeds: ['feeds', 'catalog-feed', 'product-import'],
    labels: ['labels', 'manifests', 'shipping-labels'],
    tokens: ['tokens', 'api-keys', 'credentials'],
    stores: ['stores', 'shops', 'storefronts'],
    images: ['images', 'media', 'photos'],
    payouts: ['payouts', 'settlements', 'disbursements'],
  },
  paramVocab: {
    productId: ['productId', 'product', 'sku'],
    cartId: ['cartId', 'basket', 'bag'],
    orderId: ['orderId', 'order', 'purchaseId'],
    giftCardId: ['giftCardId', 'cardId', 'creditId'],
    shipmentId: ['shipmentId', 'fulfillmentId', 'deliveryId'],
    paymentId: ['paymentId', 'chargeId', 'txnId'],
    refundId: ['refundId', 'reversalId', 'rmaId'],
    customerId: ['customerId', 'shopperId', 'patronId'],
    reviewId: ['reviewId', 'ratingId', 'feedbackId'],
    tokenId: ['tokenId', 'keyId', 'credId'],
    storeId: ['storeId', 'shopId', 'sellerId'],
    couponCode: ['couponCode', 'promoCode', 'voucher'],
    searchQuery: ['q', 'query', 'term'],
    invoiceFile: ['file', 'document', 'name'],
    imageUrl: ['src', 'imageUrl', 'source'],
    returnUrl: ['returnUrl', 'redirect', 'next'],
    itemQty: ['qty', 'quantity', 'count'],
    bodyAmount: ['amount', 'value', 'cents'],
  },
  routes,
  idFormats: ['int', 'uuid', 'prefixed', 'hashid'],
  sites: [
    orderBolaRead, shipmentBolaWrite, productSearchSqli, invoicePathTraversal, productImageSsrf,
    checkoutOpenRedirect, reviewStoredXss, orderMassAssignment, apiJwtAlgNone, refundCsrf,
    negativeQtyLogic, storefrontCachePoison, giftcardRace, paymentWebhookForgery, productFeedXxe,
    checkoutWorkflowSkip, couponReuse, inventoryOversell, refundExceedsPayment, tokenSecretDisclosure,
    customerBolaRead, adminImpersonatePrivesc, settingsSecretDisclosure, shippingLabelSsrf,
    couponAfterLock, overRefundChain,
  ],
  decoyCount: { min: 6, max: 8 },
}

export const implementedSiteIds = [
  'order-bola-read', 'shipment-bola-write', 'product-search-sqli', 'invoice-path-traversal',
  'product-image-ssrf', 'checkout-open-redirect', 'review-stored-xss', 'order-mass-assignment',
  'api-jwt-alg-none', 'refund-csrf', 'negative-qty-logic', 'storefront-cache-poison', 'giftcard-race',
  'payment-webhook-forgery', 'product-feed-xxe', 'checkout-workflow-skip', 'coupon-reuse',
  'inventory-oversell', 'refund-exceeds-payment', 'token-secret-disclosure', 'customer-bola-read',
  'admin-impersonate-privesc', 'settings-secret-disclosure', 'shipping-label-ssrf', 'coupon-after-lock',
  'over-refund-chain',
] as const
