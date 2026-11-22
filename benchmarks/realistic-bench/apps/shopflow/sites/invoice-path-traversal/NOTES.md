# invoice-path-traversal

- Class: path_traversal (CWE-22), severity high
- Root cause (planted at): `src/billing/invoice-export.ts`
- Entry routeKeys: getInvoice
- Trigger routeKeys: getInvoice
- Oracle attribution: kinds [path_escape] on [getInvoice]

## Approach (spec only; not yet implemented)

Invoice export path traversal — strips a leading slash from the filename, which does not stop ../ sequences.
The twin pair registers the `billing/invoice-export.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
