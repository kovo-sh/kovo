// Site spec for the runner-token environment chain.
import type { CausalChainSpec, SiteSpec } from '../../../../lib/types.ts'
import { blueprint as appBlueprint } from '../../truth/blueprint.ts'

const chain: CausalChainSpec = {
  id: 'fc-chain-runner-scope',
  hops: [
    { hopId: 'read-env-preview', routeKey: 'graphql', kind: 'secret_disclosed' },
  ],
  finalImpactKind: 'privilege_escalation',
  finalRouteKey: 'deployments.promote',
}

appBlueprint.chains = [...(appBlueprint.chains ?? []).filter((item) => item.id !== chain.id), chain]

const spec: SiteSpec = {
  id: 'fc-11',
  title: 'CI diagnostics expose a development runner credential that promotion accepts for production',
  vulnClass: 'chain',
  cwe: 'CWE-200',
  severity: 'critical',
  family: 'E',
  routeKeys: ['graphql', 'deployments.promote'],
  triggerRouteKeys: ['deployments.promote'],
  params: ['deploymentId'],
  canBeDecoy: false,
  causalChainId: chain.id,
  secondOrder: true,
  oracle: {
    kinds: ['secret_disclosed', 'privilege_escalation'],
    routeKeys: ['graphql', 'deployments.promote'],
  },
  rootCause: { file: 'deploy/runner-promotion.ts', symbol: 'register' },
  lure: 'The diagnostics field is read-only run metadata and promotion accepts a real runner credential, so neither request looks privileged on its own.',
}

export default spec
