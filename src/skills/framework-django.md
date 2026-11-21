# Framework Audit: Django & Django REST Framework (DRF)
Tags: framework, django, drf, python, orm, authz, csrf, template, settings
Summary: Audit Django views, DRF ViewSets/Serializers, ORM queries, template rendering, CSRF exemptions, and settings.py misconfigurations using offline SAST/Bandit and safe differential controls.

## 1. High-Risk Django / DRF Surfaces
Audit `/repos` with `run_sast_scan` (`engines: ["opengrep", "bandit", "ast-grep"]`) before sending live requests:
1. **DRF `permission_classes` & `get_queryset()` Scoping:**
   - Check `DEFAULT_PERMISSION_CLASSES` in `settings.py` (defaults to `AllowAny` if unset).
   - Inspect every `ModelViewSet`, `APIView`, and `@api_view`: verify `permission_classes` AND object-level `check_object_permissions()` / `get_queryset()` filtering by `request.user` or `request.user.org`.
   - Watch for `lookup_field` IDOR where `queryset = Model.objects.all()` lacks tenant scoping.
2. **DRF Serializer Mass Assignment (`fields = "__all__"`):**
   - Flag serializers using `fields = "__all__"` or writable `is_staff`, `is_superuser`, `role`, `owner`, `balance`, or `plan` fields without `read_only_fields`.
3. **ORM Raw SQL & Unsafe Query Construction:**
   - Search for `.raw(`, `.extra(`, `RawSQL(`, and `cursor.execute(` using f-strings, `%`, or `.format()` instead of parameterized `%s` argument lists.
   - Check dynamic `**request.data` / `**request.GET.dict()` passed to `.filter(**params)` (enables relation traversal lookups such as `owner__password__startswith` or `user__api_key__icontains`).
4. **Template Injection & XSS:**
   - Flag `mark_safe()`, `format_html()` with unescaped user variables, `|safe` filter, `{% autoescape off %}`, or `Template(user_input).render(...)`.
5. **Security Middleware & Settings (`settings.py`):**
   - Check `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, `@csrf_exempt` on cookie-authenticated endpoints, `CORS_ALLOW_ALL_ORIGINS = True` with `CORS_ALLOW_CREDENTIALS = True`, `SESSION_COOKIE_SECURE`/`HTTPONLY`/`SAMESITE`, and exposed `/admin/` or `django-debug-toolbar`.

## 2. Offline Static & AST Triage
- Run `run_sast_scan` with `bandit` and `opengrep` across `**/views*.py`, `**/serializers*.py`, `**/urls.py`, and `**/settings*.py`.
- Use `derive_evidence` to list all `urlpatterns` and DRF router registrations, mapping each endpoint to its view class, `permission_classes`, and `get_queryset()` implementation.

## 3. Safe Live Verification
- Run `run_safe_templates` (`techTags: ["django"]`) to detect exposed debug traces, browsable DRF API endpoints, or misconfigured static/media roots.
- Use `probe_differential` (`authz_matrix` for BOLA/BFLA; `sqli_boolean` for suspected raw SQL; `ssti_math` for suspected dynamic `Template()` rendering).
- Test `DELETE`/`PATCH` BOLA only at Tier 3 (with HITL approval) or `local-lab` against disposable test resources.

## 4. Closure & Replay Spec Discipline
- Confirm dynamic BOLA/SQLi/SSTI with `http_chain` or `sql_boolean_diff` Replay Specs including negative controls.
- For static-only code findings (e.g., `DEBUG=True` or unreached raw SQL sink), submit `static_ast_proof` (`static_verified`) with exact `file:line`.
- Close clean views with `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
