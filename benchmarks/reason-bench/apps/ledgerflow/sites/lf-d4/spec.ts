import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'lf-d4',
  title: 'Artifact delivery links keep reads inside the workspace export directory',
  vulnClass: 'path_traversal',
  cwe: 'CWE-22',
  severity: 'high',
  family: 'D',
  routeKeys: ['signedDownload'],
  params: ['token', 'tenantId'],
  oracle: { kinds: ['path_escape'], routeKeys: ['signedDownload'] },
  rootCause: { file: 'exports/signed-artifact.ts', symbol: 'register' },
  lure: 'mints and consumes short-lived links with a digest over the requested path',
  canBeDecoy: true,
}
