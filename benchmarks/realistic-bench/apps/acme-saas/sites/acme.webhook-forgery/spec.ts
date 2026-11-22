import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.webhook-forgery',
  title: "Inbound webhook signature forgery",
  vulnClass: 'webhook_forgery',
  cwe: 'CWE-345',
  severity: 'medium',
  routeKeys: ['receiveWebhook'],
  params: ['token'],
  oracle: { kinds: ['webhook_forgery'], routeKeys: ['receiveWebhook'] },
  rootCause: { file: 'webhooks/receive.ts', symbol: 'register' },
  formEncoding: 'json',
  lure: "compares a signature header but derives the expected signature from attacker-controllable fields, so any self-consistent signature passes",
}
