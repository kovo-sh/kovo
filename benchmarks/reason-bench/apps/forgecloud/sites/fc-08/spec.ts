// Site spec for the federated sign-in tenant binding case.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-08',
  title: 'Federated sign-in issues a session from an assertion for another provider tenant',
  vulnClass: 'oauth',
  cwe: 'CWE-287',
  severity: 'critical',
  family: 'D',
  routeKeys: ['ssoCallback'],
  triggerRouteKeys: ['ssoCallback'],
  params: ['email'],
  oracle: { kinds: ['sso_tenant_confusion'], routeKeys: ['ssoCallback'] },
  rootCause: { file: 'auth/sso-federation.ts', symbol: 'register' },
  lure: 'The callback verifies the provider signature, the issuer, expiry and the account email before minting a session, so the hand-off looks fully validated.',
}

export default spec
