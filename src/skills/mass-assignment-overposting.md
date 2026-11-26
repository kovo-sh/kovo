# Mass Assignment, Over-Posting & Schema Binding Audit
Tags: mass-assignment, over-posting, dto, schema, validation, orm, privilege-escalation, api
Summary: Audit API request binding, ORM model updates, and DTO validation pipelines to detect unintended writes to privileged fields such as role, isAdmin, tenantId, plan, or verification flags.

## 1. Root Cause Pattern
Mass assignment occurs when an endpoint binds raw client JSON/form input directly into a database model, ORM entity, or state object without an explicit allowlist of user-editable fields. Common high-impact target properties include `role`, `roles`, `isAdmin`, `is_staff`, `permissions`, `orgId`, `tenantId`, `ownerId`, `userId`, `plan`, `credits`, `emailVerified`, and `status`.

## 2. Framework-Specific Audit Hotspots (`/repos`)
Run `run_sast_scan` (`opengrep`, `ast-grep`) and inspect request handlers via `derive_evidence`:
- **Node/Express/Next.js/Prisma/Mongoose:** `await prisma.user.update({ where: { id }, data: req.body })`, `Object.assign(user, req.body)`, `Model.findByIdAndUpdate(id, req.body)`, or Zod `.passthrough()` schemas passed straight into DB writes.
- **NestJS:** Missing `whitelist: true` in `ValidationPipe` combined with `repository.save(dto)`.
- **Django DRF:** `ModelSerializer` with `fields = "__all__"` or missing `read_only_fields` on privileged model columns.
- **FastAPI:** `payload.model_dump()` / `dict()` unpacked into SQLAlchemy model updates without field filtering.
- **Rails:** `params.permit!` or overly broad `params.require(:user).permit(...)`.
- **Spring Boot:** Binding `@RequestBody` or `@ModelAttribute` directly onto a JPA `@Entity` instead of a dedicated request DTO.

## 3. Safe Non-Destructive Verification
- **Static First:** Compare the schema/response fields returned by `GET /api/profile` or `GET /api/users/me` against the request validation layer in `/repos`.
- **Live Verification (Tier 3 / `local-lab` only):** On a disposable test persona (`user_a`), first capture baseline `GET` state (control), send a benign `PATCH`/`PUT` attempting to set a non-destructive extra marker or check whether an unauthorized field change is accepted vs rejected (`400`/`422`/ignored), then re-fetch `GET` state to verify persistence and restore/clean up state if changed. Never alter real user accounts or production privileges.

## 4. Closure & `kovo_verify` Discipline
- Confirm dynamic over-posting via `kovo_verify` using `ctx.prove_persisted_mutation({ readRoute, mutation: { path, method: "PATCH", body, as }, fieldPath, expectDelta })` (or `ctx.http` baseline `GET` / `PATCH` / readback `GET` + `ctx.expect.jsonPath`) + `return ctx.result({ title })`.
- Confirm source-only unsafe bindings via `static_ast_proof` (`static_verified`) citing exact handler `file:line`.
- Close properly allowlisted handlers via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line of DTO/schema pick/whitelist>"`).
