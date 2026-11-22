import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.file-path-traversal',
  title: "File download path traversal",
  vulnClass: 'path_traversal',
  cwe: 'CWE-22',
  severity: 'high',
  routeKeys: ['downloadFile'],
  params: ['filePath'],
  oracle: { kinds: ['path_escape'], routeKeys: ['downloadFile'] },
  rootCause: { file: 'files/download.ts', symbol: 'register' },
  lure: "strips a leading slash and rejects an absolute path, which looks protective but still joins the relative path onto the tenant jail before resolving",
}
