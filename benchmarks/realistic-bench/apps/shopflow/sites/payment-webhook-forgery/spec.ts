import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'payment-webhook-forgery',
  title: 'Payment webhook signature forgery',
  vulnClass: 'webhook_forgery',
  cwe: 'CWE-345',
  severity: 'critical',
  routeKeys: ['paymentWebhook'],
  params: [],
  oracle: { kinds: ['webhook_forgery'], routeKeys: ['paymentWebhook'] },
  rootCause: { file: 'billing/webhooks.ts', symbol: 'handlePaymentWebhook' },
  formEncoding: 'json',
  canBeDecoy: false,
  lure: 'verifies an HMAC but against a shared test-mode secret anyone can compute',
}
