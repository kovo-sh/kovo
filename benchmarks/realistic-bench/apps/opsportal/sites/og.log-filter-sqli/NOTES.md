# og.log-filter-sqli

- Title: Log filter compiles a raw WHERE clause from the filter expression
- Class: sqli (CWE-89), severity high
- Entry routes: logFilter
- Trigger routes: logFilter
- Oracle: sql_structure_change @ logFilter
- Root cause file: logs/filter.ts (symbol register)
- Lure: filter grammar looks structured but is spliced verbatim into the query

Spec-only site: approach is to differentiate the twin at logs/filter.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
