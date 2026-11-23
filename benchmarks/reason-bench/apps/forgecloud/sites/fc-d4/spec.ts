// Site spec for the canonical webhook signature look-alike.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-d4',
  title: 'Webhook update verifies a signature bound to tenant, event type and body',
  vulnClass: 'webhook_forgery',
  cwe: 'CWE-345',
  severity: 'high',
  family: 'D',
  routeKeys: ['webhooks.update'],
  triggerRouteKeys: ['webhooks.update'],
  params: ['hookId'],
  canBeDecoy: true,
  oracle: { kinds: ['hmac_scope_replay'], routeKeys: ['webhooks.update'] },
  rootCause: { file: 'webhooks/canonical-scope.ts', symbol: 'register' },
  lure: 'The update handler accepts a verification bundle with a tenant, event type and body, which looks like the receiver whose signature covers only timestamp and body.',
}

export default spec
