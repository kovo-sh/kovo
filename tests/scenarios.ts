import type { PublicObservation } from '../src/server/broker.ts'

export const fixtureCredential = 'guardian-replay-fixture-key'
export const primaryOrigin = 'https://northstar.example'
export const unavailableOrigin = 'https://docs.northstar.example'
export const healthyOrigin = 'https://healthy.northstar.example'
export const excludedOrigin = 'https://help.vendor.example'
export const mainGoal = 'Review the public transport policy for our selected Northstar hosts.'
export const healthyGoal = 'Review the transport policy for the healthy Northstar fixture.'
export const allChecksGoal = 'Review all supported security headers on the approved responses.'
export const referrerGoal = 'Review only the Referrer-Policy header on the approved responses.'
export const statusQuestion = 'What is the current progress of this review?'

export function observation(origin: string, status: number, transportMaxAge: number | null): PublicObservation {
  return {
    origin, finalOrigin: origin, status, mediaType: 'text/html',
    transportMaxAge, includeSubDomains: false, source: 'fixture response',
  }
}

export const primary: PublicObservation = {
  ...observation(primaryOrigin, 200, null), contentTypeOptions: 'absent', referrerPolicy: 'unsafe-url',
}
export const unavailable: PublicObservation = {
  ...observation(unavailableOrigin, 503, null), contentTypeOptions: 'absent', referrerPolicy: 'absent',
}
export const healthy: PublicObservation = {
  ...observation(healthyOrigin, 200, 31_536_000), contentTypeOptions: 'nosniff', referrerPolicy: 'strict-origin-when-cross-origin',
}
