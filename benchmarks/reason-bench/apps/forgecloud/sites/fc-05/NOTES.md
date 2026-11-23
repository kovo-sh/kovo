# fc-05 author notes

- Mechanism: `secrets.batch` validates the first id's tenant and then updates every id by external id
  without a tenant predicate. A batch of `[ownId, foreignId]` rotates the foreign secret.
- Solver: member A lists own secrets, member B lists B secrets (the operator knows both personas),
  then member A submits the mixed batch.
- Oracle wiring: the audit judge sees mutations spanning two tenants in one request and emits
  `batch_partial_authz_bypass` at `secrets.batch` (plus a per-row `cross_tenant_write`).
- Hardened twin: validates every id's tenant before mutating and scopes each UPDATE by org.
