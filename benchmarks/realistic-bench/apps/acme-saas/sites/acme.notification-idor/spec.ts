import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.notification-idor',
  title: "Notification cross-tenant read",
  vulnClass: 'idor',
  cwe: 'CWE-639',
  severity: 'medium',
  routeKeys: ['getNotification'],
  params: ['notifId'],
  oracle: { kinds: ['cross_tenant_read'], routeKeys: ['getNotification'] },
  rootCause: { file: 'notifications/read.ts', symbol: 'register' },
  lure: "filters notifications by id and marks them read for the session user, but the fetch itself is not tenant scoped",
}
