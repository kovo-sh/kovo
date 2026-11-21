# Framework Audit: FastAPI & Starlette
Tags: framework, fastapi, starlette, python, pydantic, depends, authz, openapi, cors
Summary: Audit FastAPI/Starlette routers, Depends() authentication chains, Pydantic models, OpenAPI exposure, CORS middleware, and async database/file handlers for authz, injection, and SSRF gaps.

## 1. High-Risk FastAPI / Starlette Surfaces
Inspect `/repos` via `run_sast_scan` (`engines: ["opengrep", "bandit", "ast-grep"]`) before live probing:
1. **Dependency Injection (`Depends`) Auth & Role Gaps:**
   - Map every `@app.<method>` and `@router.<method>` route and check both router-level `dependencies=[...]` and per-route `Depends(get_current_user)`.
   - Watch for optional auth dependencies (`auto_error=False`) that return `None` without a guard, or admin routes that check authentication (`get_current_user`) but omit role verification (`require_admin`).
2. **Pydantic Model Mass Assignment & Response Over-Exposure:**
   - Flag routes that call `model.model_dump()` / `payload.dict()` directly into ORM `.update(**data)` without restricting privileged fields (`role`, `is_admin`, `tenant_id`, `credits`).
   - Check routes missing `response_model=...` that return raw SQLAlchemy/Tortoise/Beanie ORM objects (leaking password hashes, internal tokens, or sibling fields).
3. **SQLAlchemy / Async DB & Outbound HTTP Sinks:**
   - Inspect `text(f"...")`, `session.execute(f"...")`, raw f-string queries, and user-controlled `httpx`/`aiohttp` URLs (SSRF).
   - Check `FileResponse` / `StaticFiles` / `UploadFile` paths for uncanonicalized `os.path.join(BASE_DIR, filename)` traversal (in Python, `os.path.join("/base", "/etc/...")` discards `/base` when the second arg starts with `/`).
4. **OpenAPI & Middleware Config:**
   - Check whether `/openapi.json`, `/docs`, and `/redoc` expose internal/admin endpoints in production.
   - Check `CORSMiddleware` for `allow_origins=["*"]` combined with `allow_credentials=True` or overly broad `allow_origin_regex`.
   - Inspect `Jinja2Templates` / `TemplateResponse` for `Template(user_input)` or `|safe` rendering.

## 2. Offline Static & AST Triage
- Run `run_sast_scan` (`opengrep`, `bandit`) and parse any OpenAPI schema with `analyze_artifact` (`tool: "openapi-parse"`).
- Build a route-to-`Depends` matrix via `derive_evidence` so every route lacking auth or tenant filtering is logged as a `code_audit_suspect`.

## 3. Safe Live Verification
- Run `run_safe_templates` (`techTags: ["fastapi"]`) and `probe_surface` (`mode: "paths"`, `wordlist: "swagger-openapi"`).
- Use `probe_differential` (`authz_matrix`, `sqli_boolean`, `path_traversal_benign`, `ssrf_canary`) through `RequestBroker`.
- For suspected mass assignment, verify at Tier 3 (or `local-lab`) with a benign non-destructive field control on a test persona record.

## 4. Closure & Replay Spec Discipline
- Prove runtime flaws via `http_chain`, `sql_boolean_diff`, or `upload_probe` Replay Specs with negative controls and explicit `counterevidence`.
- Close ruled-out routes by citing the exact `file:line` of the enforcing `Depends(...)` guard and tenant filter in `enforcingControl`.
