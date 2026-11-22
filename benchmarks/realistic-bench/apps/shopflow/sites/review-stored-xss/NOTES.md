# review-stored-xss

- Class: xss_stored (CWE-79), severity high
- Root cause (planted at): `src/reviews/review-render.ts`
- Entry routeKeys: submitReview
- Trigger routeKeys: moderationQueue
- Oracle attribution: kinds [stored_xss_rendered] on [moderationQueue]

## Approach (spec only; not yet implemented)

Stored review markup on dashboard — sanitizes on submit yet renders stored rich HTML verbatim in moderation.
The twin pair registers the `reviews/review-render.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
