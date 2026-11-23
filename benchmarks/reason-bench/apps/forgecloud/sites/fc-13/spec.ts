// Site spec for the permission cache key case.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-13',
  title: 'Permission cache reuses an administrative lookup from another organization',
  vulnClass: 'bfla',
  cwe: 'CWE-863',
  severity: 'high',
  family: 'F',
  routeKeys: ['org.permissions'],
  triggerRouteKeys: ['org.permissions'],
  params: ['orgId'],
  oracle: { kinds: ['cache_tenant_bleed'], routeKeys: ['org.permissions'] },
  rootCause: { file: 'admin/permission-cache.ts', symbol: 'register' },
  lure: 'The permissions endpoint resolves the requested organization and serves a cached capability list keyed by the caller, which looks like the tenant-scoped cache used elsewhere.',
}

export default spec
