# Benchmark fixture change log

Audit trail for every security-relevant change to a benchmark fixture or its ground truth. Rule: a fixture is hardened **only** when it had an unintended exploitable behavior on a non-planted route. Hardening must never be used to suppress a verifier over-claim on benign behavior, and no target may be added to `truth.json` to raise recall.

| Date | App / fixture | Change | Why | Effect on score |
| :--- | :--- | :--- | :--- | :--- |
| 2026-11-23 | `realism-suite/fixtures` (acme/shopflow/opsportal) | XSS output escaping fixed | Fixture escape defects produced over-claims (CWE-79 on already-escaped contexts) | Removed 2 unmatched FPs; no target lost |
| 2026-11-23 | `realism-suite/fixtures` (search leak) | Search result leak scoped to the requesting tenant | Leak was a fixture defect, not a planted target | Removed over-claim; recall unchanged |
| 2026-11-24 | `realistic-bench/apps/shopflow` | `PATCH /settings` and `PATCH /admin/reviews` require owner/admin role | A plain store member could mutate merchant settings; the fixture intended owner-only and this route is **not** a planted target | Removed 1 held-out unmatched FP (viewer→BFLA); recall unchanged at 8/19 held-out |
| 2026-11-24 | `realistic-bench/apps/shopflow` | `GET /cart`, `POST /cart/items` require `cart.owner === actor` (including the `negative-qty-logic` site override) | Carts were readable/mutable by any persona; unintended, not a planted target | Removed cross-persona over-claim risk; recall unchanged |
| 2026-11-24 | `realistic-bench/apps/opsportal` | GraphQL `parseSelections` replaced with a cursor-based recursive-descent parser (monotonic cursor, `MAX_GRAPH_QUERY_STEPS` 50k / `MAX_GRAPH_QUERY_DEPTH` 64, bounded `GraphQueryParseError`) | The old loop never advanced on argument values starting with `$`, `[` or `{`, hanging the app process and blocking whole benchmark cells | Parser robustness only; opsportal floor unchanged 10/18, precision 100% |
