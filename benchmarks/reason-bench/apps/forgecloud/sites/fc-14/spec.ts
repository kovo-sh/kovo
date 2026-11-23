// Site spec for the reopen scheduling case.
import type { SiteSpec } from '../../../../lib/types.ts'

const spec: SiteSpec = {
  id: 'fc-14',
  title: 'Reopening a scheduled deployment clears approval but leaves the automatic release armed',
  vulnClass: 'workflow_bypass',
  cwe: 'CWE-841',
  severity: 'high',
  family: 'F',
  routeKeys: ['deployments.reopen', 'deployments.release'],
  triggerRouteKeys: ['deployments.reopen', 'deployments.release'],
  params: ['deploymentId'],
  oracle: { kinds: ['workflow_skip'], routeKeys: ['deployments.reopen', 'deployments.release'] },
  rootCause: { file: 'deployments/reopen-window.ts', symbol: 'register' },
  lure: 'Reopening returns the request to review and the manual release trigger still checks for an approved deployment, so the review gate appears intact.',
}

export default spec
