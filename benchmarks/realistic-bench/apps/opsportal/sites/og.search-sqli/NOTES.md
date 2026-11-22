# og.search-sqli

- Title: Saved search run builds raw SQL from the query string
- Class: sqli (CWE-89), severity high
- Entry routes: searchRun
- Trigger routes: searchRun
- Oracle: sql_structure_change @ searchRun
- Root cause file: search/run.ts (symbol register)
- Lure: input is quote-doubled, but the predicate is concatenated outside the quotes

Spec-only site: approach is to differentiate the twin at search/run.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
