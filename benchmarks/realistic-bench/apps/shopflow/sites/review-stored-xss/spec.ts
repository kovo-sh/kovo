import type { SiteSpec } from '../../../../lib/types.ts'

export const spec: SiteSpec = {
  id: 'review-stored-xss',
  title: 'Stored review markup on dashboard',
  vulnClass: 'xss_stored',
  cwe: 'CWE-79',
  severity: 'high',
  routeKeys: ['submitReview'],
  triggerRouteKeys: ['moderationQueue'],
  params: ['productId'],
  oracle: { kinds: ['stored_xss_rendered'], routeKeys: ['moderationQueue'] },
  rootCause: { file: 'reviews/review-render.ts', symbol: 'renderReview' },
  secondOrder: true,
  lure: 'sanitizes on submit yet renders stored rich HTML verbatim in moderation',
}
