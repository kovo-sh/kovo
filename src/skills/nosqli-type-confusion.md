# NoSQL Query Type-Confusion & Operator Filtering Audit
Tags: nosql, mongodb, mongoose, type-confusion, input-validation, query-builder, api
Summary: Audit MongoDB/Mongoose/document-store query handlers for missing primitive type validation on JSON bodies and bracket-encoded query strings using offline SAST and Guardian’s nosqli_type differential engine.

## 1. Root Cause & Source Audit (`/repos`)
Document-store query confusion occurs when an application passes raw parsed objects from `req.body` or Express/qs bracket-parsed `req.query` directly into a database filter (`collection.findOne({ email: req.body.email })`) without asserting that the value is a primitive string/number. If an attacker supplies an object containing query operators instead of a string, the driver interprets the object as a filter expression.

Inspect `/repos` via `run_sast_scan` (`opengrep`, `ast-grep`) and `derive_evidence`:
1. **Direct Request-to-Query Passing:** Search for `.find(`, `.findOne(`, `.findOneAndUpdate(`, `.deleteOne(`, `.aggregate(`, and `.where(` calls receiving unvalidated `req.body`, `req.query`, or `dto` fields.
2. **Schema & Sanitizer Check:** Check whether Zod (`z.string()`), Joi, Pydantic (`str`), class-validator (`@IsString()`), or Mongoose `sanitizeFilter: true` enforces primitive types before database queries execute.
3. **JavaScript Query Evaluation Sinks:** Flag any use of `$where`, `mapReduce`, or `$function` with interpolated user strings.
4. **Query Parser Settings:** Check Express `app.set('query parser', ...)` (`extended` / `qs` parses nested bracket notation into objects by default!).

## 2. Safe Non-Destructive Verification (`probe_differential`)
Use Guardian’s host-side `probe_differential` (`probeClass: "nosqli_type"`), which executes bounded, non-destructive type-comparison controls through `RequestBroker`:
- Compares a valid baseline primitive value against benign operator-typed controls on read-only filter/search/lookup endpoints.
- Checks for deterministic status, body-length, or record-count divergence while verifying negative controls and SPA-catchall exclusion.
- Keep Tier 1/2 checks strictly read-only; never probe mutating auth/account endpoints without Tier 3 HITL approval or `local-lab` isolation.

## 3. Closure, Replay Spec & Remediation
- **Remediation:** Enforce strict runtime schema validation requiring primitive types (`z.string()`, `typeof x === 'string'`), enable `mongoose.set('sanitizeFilter', true)`, reject keys starting with `$` or containing `.`, and avoid passing raw request objects into query builders.
- **Closure:** Confirm live read-only operator divergence via an `http_chain` Replay Spec (baseline control + invalid-type control + operator-object probe + strict `assertionsJq`) with non-empty `counterevidence`. For static-only code sinks, submit `static_ast_proof` (`static_verified`). Close validated handlers via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
