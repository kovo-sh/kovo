# shipment-bola-write

- Class: bola (CWE-639), severity high
- Root cause (planted at): `src/fulfillment/shipment-update.ts`
- Entry routeKeys: updateShipment
- Trigger routeKeys: updateShipment
- Oracle attribution: kinds [cross_tenant_write] on [updateShipment]

## Approach (spec only; not yet implemented)

Shipment status update across stores — checks that the shipment exists before writing but never rechecks ownership.
The twin pair registers the `fulfillment/shipment-update.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
