import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.avatar-ssrf',
  title: "Avatar fetch server-side request forgery",
  vulnClass: 'ssrf',
  cwe: 'CWE-918',
  severity: 'high',
  routeKeys: ['updateAvatar'],
  params: ['avatarUrl'],
  oracle: { kinds: ['ssrf_internal_fetch'], routeKeys: ['updateAvatar'] },
  rootCause: { file: 'members/avatar.ts', symbol: 'register' },
  lure: "checks that the URL is http(s) and has a hostname, which looks like validation but never blocks loopback or internal service hosts",
}
