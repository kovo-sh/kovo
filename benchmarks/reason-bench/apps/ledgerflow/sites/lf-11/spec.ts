import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-11',
  title: 'Delivery signature does not cover the declared tenant and event scope',
  vulnClass: 'webhook_forgery',
  cwe: 'CWE-345',
  severity: 'high',
  family: 'D',
  routeKeys: ['receiveWebhook'],
  params: ['token', 'kind', 'tenantId'],
  oracle: { kinds: ['hmac_scope_replay'], routeKeys: ['receiveWebhook'] },
  rootCause: { file: 'hooks/delivery-scope.ts', symbol: 'register' },
  lure: 'rejects unsigned deliveries and accepts the digest a partner computed over timestamp and body',
  canBeDecoy: false,
}
