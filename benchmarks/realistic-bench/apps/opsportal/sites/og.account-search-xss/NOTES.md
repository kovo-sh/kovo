# og.account-search-xss

- Title: Account search reflects the query term as rich HTML
- Class: xss_reflected (CWE-79), severity medium
- Entry routes: accountSearch
- Trigger routes: accountSearch
- Oracle: reflected_xss_rendered @ accountSearch
- Root cause file: accounts/search.ts (symbol register)
- Lure: the echoed term is escaped for attributes but emitted raw in the results banner

Spec-only site: approach is to differentiate the twin at accounts/search.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
