# og.dashboard-cache-poison

- Title: Shared dashboard cache serves one tenant a cached foreign response
- Class: cache_poisoning (CWE-525), severity high
- Entry routes: dashboard
- Trigger routes: dashboard
- Oracle: cache_poisoned @ dashboard
- Root cause file: dashboard/cache.ts (symbol register)
- Lure: cache key includes a team query param that is not bound to the session tenant

Spec-only site: approach is to differentiate the twin at dashboard/cache.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
