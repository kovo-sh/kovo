// Loopback-only internal service descriptors for the contained outbound guard. The instance metadata
// endpoint models private-network infrastructure that is only reachable from server-side fetches; the
// guard flags it so an input-derived request that lands here is recorded. Clients never reach it
// directly. The origin is a fixed loopback address so server-side fetch targets stay deterministic.
import type { InternalServiceRef } from '../../../lib/egress.ts'

export const METADATA_PORT = 49201
export const METADATA_ORIGIN = `http://127.0.0.1:${METADATA_PORT}`

export const internalServices: InternalServiceRef[] = [
  { name: 'metadata', port: METADATA_PORT, internal: true },
]
