import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'acme.seat-invariant',
  title: "Seat allocation invariant bypass",
  vulnClass: 'business_logic',
  cwe: 'CWE-840',
  severity: 'medium',
  routeKeys: ['addSeat'],
  params: [],
  oracle: { kinds: ['invariant_violation'], routeKeys: ['addSeat'] },
  rootCause: { file: 'billing/seats.ts', symbol: 'register' },
  lure: "checks the seat limit before incrementing but reads a stale count so a burst can exceed the plan limit",
}
