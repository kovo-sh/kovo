# Firebase Security Rules (Firestore, Realtime DB & Cloud Storage) Audit
Tags: firebase, firestore, rtdb, storage, rules, authz, multi-tenant, cloud
Summary: Audit firestore.rules, database.rules.json, storage.rules, and Cloud Functions for overly broad read/write rules, missing tenant ownership checks, custom-claim spoofing, and unauthenticated callable functions.

## 1. High-Risk Firebase Surfaces
Inspect `/repos` (`firestore.rules`, `database.rules.json`, `storage.rules`, `firebase.json`, `functions/**`) via `run_sast_scan` and `derive_evidence`:
1. **Wildcard or Expiration-Only Rules (`firestore.rules` / `storage.rules`):**
   - Flag `allow read, write: if true;`, `allow read, write: if request.time < timestamp.date(...);`, or `match /{document=**}` wildcards that shadow stricter subcollection rules.
   - Flag `allow read, write: if request.auth != null;` on user/tenant collections without checking `request.auth.uid == userId` or `resource.data.ownerId == request.auth.uid`.
2. **Broken `create` / `update` / `list` Separation:**
   - Distinguish `get` (single document by ID) vs `list` (collection query/enumeration) and `create` vs `update` vs `delete`.
   - Flag `update` rules that check `resource.data.ownerId == request.auth.uid` but forget to protect immutable fields (`request.resource.data.role == resource.data.role`, `request.resource.data.ownerId == resource.data.ownerId`, `diff().affectedKeys().hasOnly([...])`), enabling client-side privilege or ownership escalation.
3. **Realtime Database (`database.rules.json`) Rule Cascading:**
   - Remember RTDB `.read` and `.write` rules cascade downward: a parent `".read": true` or `".write": "auth != null"` overrides stricter child rules!
   - Verify `.validate` rules enforce schema types and prevent unauthorized field overwrites.
4. **Cloud Functions (`onRequest` vs `onCall`):**
   - Inspect HTTP `functions.https.onRequest` handlers for missing Firebase ID token verification (`admin.auth().verifyIdToken(...)`) — Admin SDK calls inside Cloud Functions bypass all Security Rules!
   - Inspect `onCall` functions for missing `context.auth` checks or trusting client-supplied `data.uid` instead of `context.auth.uid`.

## 2. Offline Static Analysis & Rule Trace
- Use `derive_evidence` and `run_offline_script` to parse `firestore.rules`, `database.rules.json`, and `storage.rules`, building a collection-by-collection permission matrix (`anonymous`, `other_authenticated_user`, `owner`, `admin`).
- Verify whether any client-writable user profile document stores `role`, `isAdmin`, or `plan` fields read by security rules (`get(/databases/.../users/$(request.auth.uid)).data.role`).

## 3. Closure & Verification
- For live approved Firebase/app endpoints, prove cross-tenant read leaks via `kovo_verify` (`ctx.prove_access_boundary` or `ctx.http` + `ctx.expect` comparing `owner` vs `other_persona` vs `anonymous`) and `return ctx.result({ title })`.
- For static rule defects in `/repos`, submit `static_ast_proof` (`static_verified` tier) citing the exact rules file line range and `counterevidence` (checking whether an outer rule or App Check requirement alters impact).
- Close properly scoped collections via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<rules-file:line>"`).
