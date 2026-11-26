# Supabase Row-Level Security (RLS), PostgREST & Storage Policy Audit
Tags: supabase, rls, postgres, postgrest, storage, authz, multi-tenant, cloud
Summary: Audit Supabase migrations, RLS policies, Postgres RPC functions, Edge Functions, Storage buckets, and service-role usage for tenant isolation gaps and client-side bypasses.

## 1. High-Risk Supabase Surfaces
Inspect `/repos` (`supabase/migrations/*.sql`, `supabase/functions/**`, `app/**`, `src/**`) via `run_sast_scan` and `derive_evidence`:
1. **Missing or Disabled RLS on Public-Schema Tables:**
   - Check every `CREATE TABLE public.<name>` in SQL migrations for a matching `ALTER TABLE public.<name> ENABLE ROW LEVEL SECURITY;`. Any `public` table exposed via PostgREST without RLS is directly readable/writable using the public `anon` key.
2. **Overly Permissive RLS Policies:**
   - Audit `CREATE POLICY ... USING (...)` and `WITH CHECK (...)` clauses.
   - Flag `USING (true)` or `WITH CHECK (true)` on tenant/user tables, policies checking only `auth.role() = 'authenticated'` without `auth.uid() = user_id` (allows cross-tenant BOLA between any two signed-in users), or `UPDATE` policies missing `WITH CHECK` (allows reassigning `user_id`/`org_id` to another tenant).
   - Flag policies trusting mutable `auth.jwt() -> 'user_metadata'` instead of server-controlled `app_metadata` or database membership tables (`user_metadata` is writable by end users via `supabase.auth.updateUser()`).
3. **`SECURITY DEFINER` RPC Functions & Views:**
   - Audit every `CREATE FUNCTION ... SECURITY DEFINER` in `public`: verify it sets `SET search_path = public, pg_temp`, explicitly validates `auth.uid()` / caller membership inside the function body, and restricts `REVOKE ALL ON FUNCTION ... FROM anon, authenticated`.
   - Flag Postgres views without `security_invoker = true` (PG 15+) that accidentally bypass underlying table RLS.
4. **Service-Role Key Misuse & Edge Functions:**
   - Flag `SUPABASE_SERVICE_ROLE_KEY` imported in client bundles or used in server/Edge Functions without explicit session verification + `WHERE user_id = ...` filtering (service-role bypasses all RLS!).
5. **Storage Bucket Policies (`storage.objects`):**
   - Check public buckets vs private buckets and verify `storage.objects` RLS checks `bucket_id` and owner folder prefix (`(storage.foldername(name))[1] = auth.uid()::text`).

## 2. Safe Live Verification (`RequestBroker`)
- When a Supabase project origin is in approved scope, verify exposed PostgREST tables (`/rest/v1/<table>?select=*&limit=1`) using `probe_differential` (`authz_matrix`) comparing `owner`, `other_persona`, and `anonymous` (`apikey` header only) with strict 3-way controls.
- Never modify or delete production rows; keep Tier 1/2 checks read-only (`GET`/`HEAD`).

## 3. Closure & `kovo_verify` Discipline
- Confirm live cross-tenant PostgREST/RPC/Storage leaks via `kovo_verify` (`ctx.prove_access_boundary` or `ctx.http` + `ctx.expect` proving owner baseline `200` vs cross-persona/anonymous leak) + `return ctx.result({ title })`.
- Confirm source-only migration/policy defects with `static_ast_proof` (`static_verified`) citing exact SQL migration `file:line`.
- Rule out protected tables only by quoting the exact `ENABLE ROW LEVEL SECURITY` + `CREATE POLICY` `file:line` in `enforcingControl`.
