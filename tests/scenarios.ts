import type { PublicObservation } from '../src/server/broker.ts'

export const fixtureCredential = 'guardian-replay-fixture-key'
export const primaryOrigin = 'https://northstar.example'
export const unavailableOrigin = 'https://docs.northstar.example'
export const healthyOrigin = 'https://healthy.northstar.example'
export const excludedOrigin = 'https://help.vendor.example'
export const mainGoal = 'Review the public transport policy for our selected Northstar hosts.'
export const healthyGoal = 'Review the transport policy for the healthy Northstar fixture.'

export function observation(origin: string, status: number, transportMaxAge: number | null): PublicObservation {
  return {
    origin, finalOrigin: origin, status, mediaType: 'text/html',
    transportMaxAge, includeSubDomains: false, source: 'fixture response',
  }
}

export const primary = observation(primaryOrigin, 200, null)
export const unavailable = observation(unavailableOrigin, 503, null)
export const healthy = observation(healthyOrigin, 200, 31_536_000)
