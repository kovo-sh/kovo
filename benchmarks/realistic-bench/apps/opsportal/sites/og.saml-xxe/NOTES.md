# og.saml-xxe

- Title: SAML/config XML import resolves an external file entity
- Class: xxe (CWE-611), severity high
- Entry routes: samlImport
- Trigger routes: samlImport
- Oracle: xxe_entity_resolved @ samlImport
- Root cause file: sso/saml.ts (symbol register)
- Lure: parser enables entities to support signed metadata includes

Spec-only site: approach is to differentiate the twin at sso/saml.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
