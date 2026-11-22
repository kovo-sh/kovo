# og.user-mass-assignment

- Title: User profile update binds role and team from the request body
- Class: mass_assignment (CWE-915), severity high
- Entry routes: userUpdate
- Trigger routes: userUpdate
- Oracle: mass_assignment @ userUpdate
- Root cause file: users/profile.ts (symbol register)
- Lure: profile patch spreads the whole body over the record including privileged columns

Spec-only site: approach is to differentiate the twin at users/profile.ts so the
runtime boundary/encoding/validation check is present in one variant and absent in the other,
while both export the same register symbol and stay similar in shape and size.
