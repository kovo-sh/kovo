# fc-06 author notes

- Mechanism: `search.facets` counts `name LIKE '<prefix>%'` across every tenant, so counts above the
  caller's own total confirm that another tenant has names sharing the prefix.
- Solver: member A lists own secrets (benign), asks facets for the own tenant prefix, then for that
  prefix plus `-` (shared only by the prefix-paired sibling tenant).
- Oracle wiring: the facet inspector recomputes own vs foreign buckets and emits
  `tenant_existence_oracle` at `search.facets` when the reported counts exceed the caller's baseline.
- Hardened twin: counts are scoped to `org_slug = caller`.
