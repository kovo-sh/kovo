# REST, GraphQL & tRPC API Security Testing
Tags: api, rest, graphql, trpc, openapi, introspection, mass-assignment
Summary: Enumerate and validate REST, GraphQL, and tRPC API attack surfaces using OpenAPI specs, introspection, method/content-type differentials, and non-destructive schema/auth controls.

## 1. Schema & Endpoint Discovery
1. Check uploaded `project_specs` staged in `/evidence/` first (`analyze_artifact` with `openapi-parse` or `graphql-parse`).
2. Probe standard documentation/schema endpoints at Tier 1 (`GET`, `followRedirects: false`, comparing against SPA catch-all):
   - OpenAPI/Swagger: `/openapi.json`, `/swagger.json`, `/api-docs`, `/v1/openapi.json`, `/api/openapi.json`, `/docs`
   - GraphQL: `/graphql`, `/api/graphql`, `/v1/graphql`
   - Health/debug/metrics: `/health`, `/healthz`, `/status`, `/version`, `/metrics`, `/api/health`, `/api/trpc`
3. For GraphQL endpoints, test read-only introspection (`GET /graphql?query={__schema{queryType{name}mutationType{name}types{name,kind}}}` at Tier 1, or allowlisted `POST` at Tier 2) and pass results to `analyze_artifact` (`tool: "graphql-parse"`).
   - If introspection is disabled, check whether GraphQL field suggestions ("Did you mean ...?") leak hidden query/mutation names.

## 2. High-Signal API Vulnerability Checks
- **Unauthenticated Admin / Internal Endpoints:** Test discovered `/api/admin/*`, `/api/internal/*`, `/api/debug/*`, `/api/metrics`, `/api/users`, `/api/export` routes without a persona. Compare against a valid control request and SPA catch-all.
- **HTTP Verb / Method Override Gaps:** Check if `OPTIONS` exposes unexpected methods or if `HEAD` / `GET` bypasses auth middleware applied only to `POST`, or if `X-HTTP-Method-Override` alters routing.
- **Excessive Data Exposure:** Inspect JSON responses for sensitive fields (`passwordHash`, `secret`, `apiKey`, `internalId`, `stripeCustomerId`, other tenants' PII, stack traces).
- **GraphQL Batching / Aliasing / Depth:** Note if query batching or unbounded aliases enable rate-limit bypass on sensitive queries (verify non-destructively with small alias count `2..3`, never DoS).
- **Verbose Errors & Stack Traces:** Send benign malformed types (e.g., `?limit=abc`, invalid UUID format) to check whether SQL errors, file paths, or internal upstream URLs leak.

## 3. `kovo_verify` Verification Guidelines
- Confirm runtime API/GraphQL exposure and authz flaws via `kovo_verify`: use `ctx.prove_access_boundary({ controlPersona, probePersona, route })` for authz differentials, or `ctx.http` + `ctx.expect.status` / `ctx.expect.header` / `ctx.expect.jsonPath` for schema/introspection leaks, verifying `content-type` is `application/json` (not an SPA HTML catch-all) and finishing with `return ctx.result({ title })`.
- Never claim "GraphQL introspection enabled" as High unless sensitive/admin mutations or internal PII types are exposed or combined with missing auth; rate pure public-schema introspection accurately (`low` or `informational`).
