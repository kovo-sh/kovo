# Framework Audit: Ruby on Rails
Tags: framework, rails, ruby, activerecord, strong-parameters, csrf, authz, erb
Summary: Audit Ruby on Rails controllers, before_action filters, Strong Parameters, ActiveRecord queries, ERB templates, ActionCable channels, and routes for authz, mass assignment, and injection flaws.

## 1. High-Risk Ruby on Rails Surfaces
Audit `/repos` via `run_sast_scan` (`engines: ["opengrep", "ast-grep"]`) and `derive_evidence`:
1. **`before_action` / `skip_before_action` Auth & CSRF Gaps:**
   - Map `config/routes.rb` and inspect every controller inheriting from `ApplicationController`.
   - Flag `skip_before_action :authenticate_user!` or `skip_before_action :verify_authenticity_token` without `only:` scoping or alternative signed-token/HMAC verification.
   - Check Pundit (`authorize @record`, `policy_scope(...)`) or CanCanCan (`load_and_authorize_resource`) coverage: watch for `Model.find(params[:id])` instead of `current_user.models.find(params[:id])`.
2. **Strong Parameters & Mass Assignment:**
   - Flag `params.permit!` or permitting sensitive columns (`:admin`, `:role`, `:user_id`, `:organization_id`, `:account_id`, `:verified`) inside `params.require(...).permit(...)`.
3. **ActiveRecord SQL Injection & Unsafe Dynamic Dispatch:**
   - Flag string interpolation inside `.where("name = '#{params[:q]}'")`, `.order(params[:sort])`, `.pluck(params[:col])`, `.joins(...)`, or `find_by_sql(...)`.
   - Flag `send(params[:action_name])`, `public_send(...)`, `constantize`, `safe_constantize`, `YAML.load` (vs `YAML.safe_load`), `Marshal.load`, or `open(user_url)` (`Kernel#open` / `URI.open`).
4. **Templates, Redirects & ActionCable:**
   - Flag `raw(...)`, `.html_safe`, `render inline: ...`, or `render file: params[:...]` (dynamic template/path rendering).
   - Flag `redirect_to params[:return_to]` without `allow_other_host: false` / safe relative-path validation.
   - Inspect `app/channels/application_cable/connection.rb` and `config.action_cable.disable_request_forgery_protection = true` (Cross-Site WebSocket Hijacking).

## 2. Offline Static & AST Triage
- Run `run_sast_scan` (`opengrep`, `ast-grep`) across `app/controllers/`, `app/models/`, `app/channels/`, `app/views/`, and `config/`.
- Check `Gemfile.lock` via `query_cves` (`ecosystem: "RubyGems"`) for known Rails/Rack/ActionPack CVEs (log as `cve_hypothesis` until verified).

## 3. Safe Live Verification
- Run `run_safe_templates` (`techTags: ["rails"]`) and `probe_surface` (`mode: "paths"`).
- Use `probe_differential` (`authz_matrix`, `sqli_boolean`, `ssti_math` with benign ERB prime-multiplication checks, `path_traversal_benign`) and `probe_websocket` (ActionCable `Origin` check) via `RequestBroker`.

## 4. Closure & Replay Spec Discipline
- Confirm dynamic flaws with `http_chain`, `sql_boolean_diff`, or `ws_chain` Replay Specs including negative controls and non-empty `counterevidence`.
- Close ruled-out controllers with `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
