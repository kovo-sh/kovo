# product-search-sqli

- Class: sqli (CWE-89), severity high
- Root cause (planted at): `src/catalog/product-search.ts`
- Entry routeKeys: searchProducts
- Trigger routeKeys: searchProducts
- Oracle attribution: kinds [sql_structure_change] on [searchProducts]

## Approach (spec only; not yet implemented)

Product search raw SQL — escapes single quotes by doubling but still concatenates the LIKE clause.
The twin pair registers the `catalog/product-search.ts` module route(s); the solver drives the entry route(s) and impact is proven by the oracle event(s) above. The hardened twin applies the standard fix while keeping the same shape.
