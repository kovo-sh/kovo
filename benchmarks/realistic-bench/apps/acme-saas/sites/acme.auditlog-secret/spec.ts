import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.auditlog-secret',
  title: "Admin audit log secret leakage",
  vulnClass: 'info_disclosure',
  cwe: 'CWE-532',
  severity: 'medium',
  routeKeys: ['adminAuditLog'],
  params: [],
  oracle: { kinds: ['secret_disclosed'], routeKeys: ['adminAuditLog'] },
  rootCause: { file: 'admin/audit.ts', symbol: 'register' },
  lure: "returns audit entries with a details blob that still contains the secret reference captured at event time",
}
