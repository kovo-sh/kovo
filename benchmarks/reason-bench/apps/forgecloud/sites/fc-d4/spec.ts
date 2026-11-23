// Site spec for the tenant-scoped permission cache look-alike.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-d4',
  title: 'Permission cache entries are keyed by user and organization',
  vulnClass: 'bfla',
  cwe: 'CWE-863',
  severity: 'high',
  family: 'F',
  routeKeys: ['org.settings'],
  triggerRouteKeys: ['org.settings'],
  params: ['orgId'],
  canBeDecoy: true,
  oracle: { kinds: ['cache_tenant_bleed'], routeKeys: ['org.settings'] },
  rootCause: { file: 'admin/tenant-scoped-cache.ts', symbol: 'register' },
  lure: 'Settings reads reuse the process permission cache, which looks like the cache that is keyed by user alone and can serve an administrative entry to a viewer.',
}

export default spec
