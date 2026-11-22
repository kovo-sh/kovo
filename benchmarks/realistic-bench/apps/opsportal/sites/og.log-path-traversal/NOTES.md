# og.log-path-traversal

- Title: Log file viewer resolves a user path outside the jailed log root
- Class: path_traversal (CWE-22), severity high
- Entry routes: logView
- Trigger routes: logView
- Oracle: path_escape @ logView
- Root cause file: logs/viewer.ts (symbol register)
- Lure: name is checked for a .log suffix which traversal sequences still satisfy

Spec-only site: approach is to differentiate the twin at logs/viewer.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
