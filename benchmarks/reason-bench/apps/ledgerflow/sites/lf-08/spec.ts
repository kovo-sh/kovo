import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-08',
  title: 'Demoted administrator keeps a completed billing export download',
  vulnClass: 'bfla',
  cwe: 'CWE-863',
  severity: 'high',
  family: 'B',
  routeKeys: ['downloadExport'],
  params: ['exportId'],
  oracle: { kinds: ['stale_privilege_use'], routeKeys: ['downloadExport'] },
  rootCause: { file: 'exports/export-download.ts', symbol: 'register' },
  lure: 'checks that the caller queued the job and returns the finished artifact body',
  canBeDecoy: false,
}
