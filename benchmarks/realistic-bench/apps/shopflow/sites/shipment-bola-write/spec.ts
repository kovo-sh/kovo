import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'shipment-bola-write',
  title: 'Shipment status update across stores',
  vulnClass: 'bola',
  cwe: 'CWE-639',
  severity: 'high',
  routeKeys: ['updateShipment'],
  params: ['shipmentId'],
  oracle: { kinds: ['cross_tenant_write'], routeKeys: ['updateShipment'] },
  rootCause: { file: 'fulfillment/shipment-update.ts', symbol: 'updateShipment' },
  lure: 'checks that the shipment exists before writing but never rechecks ownership',
}
