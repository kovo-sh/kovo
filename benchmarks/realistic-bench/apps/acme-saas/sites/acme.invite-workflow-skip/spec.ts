import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.invite-workflow-skip',
  title: "Invite acceptance workflow skip",
  vulnClass: 'workflow_bypass',
  cwe: 'CWE-841',
  severity: 'medium',
  routeKeys: ['acceptInvite'],
  params: ['token'],
  oracle: { kinds: ['workflow_skip'], routeKeys: ['acceptInvite'] },
  rootCause: { file: 'members/invites.ts', symbol: 'register' },
  lure: "looks the invite up by token and marks it accepted but never checks the invite is still in the pending state",
}
