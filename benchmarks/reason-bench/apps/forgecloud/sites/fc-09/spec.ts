// Site spec for the duplicate-key role request case.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-09',
  title: 'Role change request is authorized on one duplicate field value and applied with another',
  vulnClass: 'mass_assignment',
  cwe: 'CWE-436',
  severity: 'high',
  family: 'D',
  routeKeys: ['members.update'],
  triggerRouteKeys: ['members.update'],
  params: ['role', 'memberId'],
  formEncoding: 'json',
  oracle: { kinds: ['parser_differential_bypass'], routeKeys: ['members.update'] },
  rootCause: { file: 'members/role-requests.ts', symbol: 'register' },
  lure: 'The request gate inspects the leading role field and only forwards read-only intents, while the member handler resolves the requested role again from the same document.',
}

export default spec
