# fc-07 author notes

- Mechanism: the export-link minter accepts a caller-supplied storage path under `"/exports/" + org`
  (no trailing slash) and the fetch verifier applies the same slash-less prefix test. With the seed's
  prefix-paired tenants (`acme`, `acme-corp`), a path for the sibling tenant passes both checks.
- Solver: owner lists own artifacts, mints a link for `/exports/<sibling>/<ownArtifactName>`, fetches
  the link, re-lists artifacts.
- Oracle wiring: the signed-input inspector and the virtual-storage read monitor both emit
  `signed_url_prefix_escape` at `artifacts.fetch` (the fetched object also trips the tenant canary
  scan, which is expected secondary evidence).
- Hardened twin: the fetch boundary requires the trailing slash; minting is unchanged so the two
  files differ only in the boundary predicate.
