# Framework Audit: NestJS (Guards, Interceptors, Pipes & GraphQL/REST)
Tags: framework, nestjs, typescript, node, guards, pipes, dto, typeorm, prisma, authz
Summary: Audit NestJS controllers, global/route Guards, ValidationPipe settings, TypeORM/Prisma queries, GraphQL resolvers, and WebSocket gateways for missing auth, mass assignment, and injection.

## 1. High-Risk NestJS Surfaces
Inspect `/repos` via `run_sast_scan` (`engines: ["opengrep", "ast-grep"]`) before live probing:
1. **Guard Coverage & `@Public()` Bypass:**
   - Check `APP_GUARD` in `AppModule` vs per-controller `@UseGuards(JwtAuthGuard, RolesGuard)`.
   - Verify whether a custom `@Public()` decorator or `Reflector.getAllAndOverride` accidentally exempts sensitive child handlers, webhooks, or GraphQL mutations.
   - Verify `RolesGuard` checks both authentication AND resource ownership (guards alone often enforce only role, leaving cross-tenant BOLA open in services).
2. **`ValidationPipe` & DTO Mass Assignment:**
   - Inspect `app.useGlobalPipes(new ValidationPipe({ ... }))` in `main.ts`.
   - Flag missing `whitelist: true` and `forbidNonWhitelisted: true`: without `whitelist: true`, extra JSON properties (`role`, `isAdmin`, `orgId`) pass straight through DTOs into TypeORM `repository.save(dto)` or Prisma `create({ data: dto })`.
3. **ORM Query Builders (TypeORM / Prisma / Mongoose):**
   - Flag TypeORM `.where(\`... ${input}\`)`, `.orderBy(userInput)`, or `.query(\`...\`)` string interpolation.
   - Flag Prisma `$queryRawUnsafe` / `$executeRawUnsafe`.
   - Flag Mongoose `find(req.body)` / `findOne({ email: dto.email })` without string type validation (NoSQL operator injection).
4. **GraphQL Resolvers & WebSocket Gateways:**
   - Check `@Resolver()` queries/mutations and `@ResolveField()` field resolvers for missing `@UseGuards(...)` or missing tenant checks on nested relations.
   - Check `@WebSocketGateway({ cors: { origin: '*' } })` and `@SubscribeMessage()` handlers: HTTP `APP_GUARD` does NOT automatically protect WebSocket handshakes or message handlers!
5. **Swagger, CORS & File Serving:**
   - Check `SwaggerModule.setup(...)` exposure, `app.enableCors({ origin: true, credentials: true })` (reflects any origin with credentials!), and `@UploadedFile()` / `ServeStaticModule` path handling.

## 2. Offline Static & AST Triage
- Run `run_sast_scan` (`opengrep`, `ast-grep`) across `src/**/*.controller.ts`, `src/**/*.resolver.ts`, `src/**/*.gateway.ts`, and `src/main.ts`.
- Enumerate every `@Controller` / `@Get`/`@Post`/`@Patch`/`@Delete` and `@SubscribeMessage` handler via `derive_evidence` and verify guard + service-layer ownership checks.

## 3. Safe Live Verification
- Run `run_safe_templates` (`techTags: ["nestjs"]`) and `probe_surface` (`mode: "paths"`, `wordlist: "api-routes"`).
- Use `probe_differential` (`authz_matrix`, `graphql_audit`, `nosqli_type`, `sqli_boolean`) and `probe_websocket` (with spoofed `Origin: https://evil.invalid` vs same-origin control) via `RequestBroker`.

## 4. Closure & `kovo_verify` Discipline
- Confirm runtime flaws via `kovo_verify` (`ctx.prove_access_boundary`, `ctx.prove_boolean_or_timing_diff`, `ctx.http` + `ctx.expect`, or `ctx.seal_capability` + `ctx.prove_composite` for multi-hop chains) + `return ctx.result({ title })`.
- Record `ruled_out` only when quoting the exact `file:line` of the active `Guard` + ownership check or negative-control `exchangeId`.
