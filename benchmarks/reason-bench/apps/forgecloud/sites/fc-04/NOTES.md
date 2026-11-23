# fc-04 author notes

- Mechanism: the pipeline list concatenates `AND state = ?` and `OR visibility = ?` without grouping
  the alternatives, so a two-filter request evaluates as
  `(tenant = ? AND state = ?) OR visibility = ?` and returns other tenants' rows.
- Solver: member reads own pipelines, applies one filter (control), then both filters; rows carry
  their project's short note so a leaked row is externally attributable.
- Oracle wiring: response canary scan emits `cross_tenant_read` at `pipelines.list`.
- Hardened twin: parenthesizes the combined predicate.
