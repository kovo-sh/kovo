# SQL Parameterization Audit & Boolean Differential Verification
Tags: sqli, sql, database, orm, parameterization, boolean-diff, verification, code-audit
Summary: Audit database query builders and raw SQL sinks offline via SAST, then confirm unparameterized query handling strictly through Guardian’s non-destructive boolean differential engine and sql_boolean_diff Replay Specs.

## 1. Source-First Parameterization Audit (`/repos`)
Always audit `/repos` via `run_sast_scan` (`opengrep`, `ast-grep`, `bandit`) and `derive_evidence` before sending live probes:
1. **Raw String Interpolation Sinks:**
   - **Node.js / TypeScript:** Inspect `db.query`, `pool.query`, `knex.raw`, `prisma.$queryRawUnsafe`, `prisma.$executeRawUnsafe`, `sequelize.query`, and TypeORM `.where(...)` / `.orderBy(...)` for template literals or string concatenation involving request parameters.
   - **Python:** Inspect `cursor.execute`, SQLAlchemy `text(...)`, and Django `.raw()` / `.extra()` / `RawSQL` for f-strings, `%`, or `.format()` formatting instead of bound parameter tuples.
   - **Java / Go / Ruby:** Inspect JDBC `Statement` concatenation, Hibernate/JPA `createQuery` concatenation, MyBatis `${...}` interpolation (vs safe `#{...}`), Go `fmt.Sprintf` passed to `db.Query`, and Rails `.where("... #{...}")` / `.order(params[:sort])`.
2. **Dynamic Identifiers (`ORDER BY` / Column / Table Names):**
   - Parameter binding protects values, not SQL identifiers. Verify any user-controlled sort column, sort direction, or grouping field is validated against an explicit static allowlist map.

## 2. Non-Destructive Differential Verification (`probe_differential`)
Guardian strictly prohibits destructive database statements, data extraction loops, schema dumps, or sleep/DoS timing floods:
- Invoke Guardian’s host-side `probe_differential` (`probeClass: "sqli_boolean"`), which routes strictly through `RequestBroker` and compares a clean baseline response against randomized, side-effect-free boolean comparisons (`k=k` vs `k=k+1`) plus minimal syntax-boundary error fingerprinting.
- Verify baseline stability across repeated clean requests and ensure SPA-catchall exclusion before trusting any divergence.

## 3. Deterministic Zero-LLM Confirmation (`sql_boolean_diff`)
- To promote a live finding to `runtime_confirmed`, submit a `sql_boolean_diff` Declarative Replay Spec specifying `targetOrigin`, `method`, `pathAndQuery`, `paramName`, `paramLocation`, `baselineValue`, and `quoteStyle`.
- Guardian’s Replay Verifier independently mints **3 fresh unseen random integer pairs** and executes interleaved `(baseline, true, false)` triplets, confirming ONLY when `similarity(baseline, true) >= 0.90` AND `similarity(true, false) <= 0.75` (or deterministic non-5xx status divergence) holds across every round.
- For unreachable/Tier-0 source sinks, submit `static_ast_proof` (`static_verified` tier) citing the exact `file:line`.
- Always include non-empty `counterevidence` (checking whether an ORM cast, schema validator, or WAF alters behavior). Close properly parameterized queries via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
