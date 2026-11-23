// Site spec for the webhook signing-salt chain.
import type { CausalChainSpec, SiteSpec } from '../../../../lib/types.ts'
import { blueprint as appBlueprint } from '../../truth/blueprint.ts'

const chain: CausalChainSpec = {
  id: 'fc-chain-webhook-salt',
  hops: [
    { hopId: 'read-delivery-detail', routeKey: 'webhooks.deliveries', kind: 'secret_disclosed' },
  ],
  finalImpactKind: 'webhook_forgery',
  finalRouteKey: 'webhooks.receive',
}

appBlueprint.chains = [...(appBlueprint.chains ?? []).filter((item) => item.id !== chain.id), chain]

const spec: SiteSpec = {
  id: 'fc-10',
  title: 'Delivery diagnostics expose the internal signing salt used to accept forged webhooks',
  vulnClass: 'chain',
  cwe: 'CWE-918',
  severity: 'critical',
  family: 'E',
  routeKeys: ['webhooks.deliveries', 'webhooks.receive'],
  triggerRouteKeys: ['webhooks.receive'],
  params: ['hookId'],
  canBeDecoy: false,
  causalChainId: chain.id,
  secondOrder: true,
  oracle: {
    kinds: ['secret_disclosed', 'webhook_forgery'],
    routeKeys: ['webhooks.deliveries', 'webhooks.receive'],
  },
  rootCause: { file: 'webhooks/delivery-ledger.ts', symbol: 'register' },
  lure: 'The delivery history is a routine diagnostics view and the receiver rejects every signature that does not verify, so both surfaces look clean in isolation.',
}

export default spec
