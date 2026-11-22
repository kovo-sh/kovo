# og.sso-open-redirect

- Title: SSO callback redirects to an attacker-supplied next url
- Class: open_redirect (CWE-601), severity medium
- Entry routes: ssoCallback
- Trigger routes: ssoCallback
- Oracle: open_redirect @ ssoCallback
- Root cause file: sso/redirect.ts (symbol register)
- Lure: next is checked to start with a slash, which protocol-relative urls satisfy

Spec-only site: approach is to differentiate the twin at sso/redirect.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
