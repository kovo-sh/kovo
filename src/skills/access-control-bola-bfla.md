# Access Control: BOLA, BFLA, IDOR & Multi-Tenant Isolation
Tags: access-control, bola, bfla, idor, rbac, multi-tenant, persona
Summary: Prove broken object-level authorization (BOLA/IDOR), broken function-level authorization (BFLA), and tenant isolation failures using Kovo’s opaque multi-persona Tier 2 differential controls.

## 1. Preconditions
- Requires **Tier 2** (or Tier 3 for state-changing mutations) with approved opaque personas (e.g., `tenant_a`, `tenant_b`, or `user_low` vs `admin`).
- At **Tier 1** (unauthenticated), focus on **missing authentication** on object/admin endpoints, predictable public object IDs/URLs (e.g., `/api/share/<id>`, `/api/invoices/<id>`), and Supabase/PostgREST public RLS exposure (`anon` key reading private tables).

## 2. Systematic BOLA / IDOR Methodology
1. **Harvest Object Identifiers:** Under `persona: "tenant_a"`, call list/profile/workspace/billing/project endpoints (`GET`) to extract `tenant_a`'s real resource IDs (UUIDs, integers, slugs, org IDs). Record as `kind: "object_ref"`.
2. **Cross-Tenant Differential Matrix (3-Way Proof):**
   - **Owner baseline (`setup`):** `GET /api/resources/<id_a>` with `persona: "tenant_a"` → `200` containing `tenant_a` data/canary.
   - **Negative control (`control`):** `GET /api/resources/<id_a>` unauthenticated (or `persona: "tenant_b"` requesting a known-inexistent ID) → `401`/`403`/`404`.
   - **Cross-tenant probe (`probe`):** `GET /api/resources/<id_a>` with `persona: "tenant_b"` → if `200` returning `tenant_a`'s private object/canary marker, you have a proven BOLA!
3. **BFLA (Privilege Escalation):**
   - Identify admin/staff/org-owner endpoints from OpenAPI specs, JS bundles, or `admin` persona responses.
   - Replay read-only admin routes with a low-privilege persona (`user_low`) vs unauthenticated control.
4. **Parameter & Header Manipulation:**
   - Test `orgId`, `workspaceId`, `userId`, `tenantId` query parameters and `X-Organization-Id` / `X-Tenant-Id` headers when authenticated as `tenant_b` referencing `tenant_a`'s ID.
   - Check Supabase PostgREST endpoints (`/rest/v1/<table>?select=*`) if a public `anon` key and Supabase URL were harvested—verify whether Row Level Security (RLS) restricts private user tables.
5. **Race Conditions / TOCTOU (Tier 2/3):**
   - On quota/credit/coupon/redemption endpoints, verify concurrency via `kovo_verify` using `ctx.prove_race_burst({ requests, readRoute, balanceField, unitDebit })` (`2..10` synchronized requests) only when non-destructive or Tier-3 approved.

## 3. `kovo_verify` Verification Requirements
- Use `kovo_verify` with `ctx.prove_access_boundary({ controlPersona, probePersona, route, method? })` for direct BOLA/BFLA checks, or `ctx.chain(...)` (or `ctx.http_send` + `ctx.seal_capability` + `ctx.prove_composite`) when the target ID must be harvested in a prerequisite setup hop (`replayMode: "fresh_clean_replay"`).
- Reference personas ONLY via opaque handles (`as` / `controlPersona` / `probePersona`, never raw `Authorization` or `Cookie`).
- Assert non-SPA content and concrete differential outcomes via `ctx.expect.status` / `ctx.expect.jsonPath` / `ctx.expect.bodyContains` and finish with `return ctx.result({ title })`.
