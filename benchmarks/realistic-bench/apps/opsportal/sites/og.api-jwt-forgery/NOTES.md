# og.api-jwt-forgery

- Title: Legacy API accepts an alg:none bearer token
- Class: jwt (CWE-347), severity high
- Entry routes: apiWhoami
- Trigger routes: apiWhoami
- Oracle: token_forgery @ apiWhoami
- Root cause file: tokens/verify.ts (symbol register)
- Lure: verifier keeps a none fallback for backwards compatibility with old agents

Spec-only site: approach is to differentiate the twin at tokens/verify.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
