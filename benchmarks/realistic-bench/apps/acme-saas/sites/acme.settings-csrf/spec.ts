import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.settings-csrf',
  title: "Account settings CSRF",
  vulnClass: 'csrf',
  cwe: 'CWE-352',
  severity: 'medium',
  routeKeys: ['updateSettings'],
  params: [],
  oracle: { kinds: ['csrf_state_change'], routeKeys: ['updateSettings'] },
  rootCause: { file: 'members/settings.ts', symbol: 'register' },
  formEncoding: 'form',
  requiresCsrf: true,
  lure: "checks for a session cookie and a same-site referer in one branch but applies the change before the token check on the form path",
}
