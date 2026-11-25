# Server-Side Template Safety Audit & Non-Destructive Arithmetic Verification
Tags: ssti, templates, jinja2, twig, erb, freemarker, spel, handlebars, verification, code-audit
Summary: Audit server-side template rendering for untrusted template compilation via offline SAST and verify evaluation safely using Kovo Hunter’s non-destructive prime-arithmetic differential engine.

## 1. Root Cause & Source-First Audit (`/repos`)
Server-side template evaluation bugs happen when user-controlled text is compiled as template source code (rather than passed as a data variable to a static pre-authored template file).

Inspect `/repos` via `run_sast_scan` (`opengrep`, `ast-grep`, `bandit`) and `derive_evidence`:
1. **Python (Jinja2 / Mako / Django):** Flag `jinja2.Template(user_input).render(...)`, `render_template_string(user_input)`, `Environment().from_string(user_input)`, or `django.template.Template(user_input)` where untrusted strings are concatenated into the template body.
2. **Java / JVM (Spring / FreeMarker / Thymeleaf / Pebble):** Flag `SpelExpressionParser.parseExpression(user_input)` evaluated with `StandardEvaluationContext` (should use `SimpleEvaluationContext` or avoid expression parsing on untrusted input), dynamic FreeMarker `new Template(..., new StringReader(user_input))`, or unvalidated Thymeleaf dynamic view names.
3. **Node.js / Ruby / PHP:** Flag `Handlebars.compile(user_input)`, `ejs.render(user_input)`, `pug.render(user_input)`, `nunjucks.renderString(user_input)`, Rails `render inline: user_input` / `ERB.new(user_input)`, and PHP Twig `createTemplate(user_input)`.

## 2. Strictly Non-Destructive Verification
Kovo Hunter strictly prohibits shell execution, object-graph traversal gadgets, file reads, or environment dumps during template auditing:
1. **Tier 1–2 Discovery (`probe_differential`):** Call Kovo Hunter’s host-side `probe_differential` (`probeClass: "ssti_math"`), which sends fresh randomized prime-multiplication checks across common template syntaxes through `RequestBroker`. A genuine signal requires the computed numeric product to appear in the probe response while being absent from the baseline response and distinct from literal reflection.
2. **Tier 3 Confirmation (`rce_proof` with `proofMode: "dynamic_math"`):** If active confirmation is authorized (Tier 3 HITL approval card or `local-lab`), submit an `rce_proof` Replay Spec using Kovo Hunter’s verifier-minted `{{nonce_a}}` and `{{nonce_b}}` placeholders so the Replay Verifier proves deterministic server-side evaluation with zero reflection false positives and zero destructive impact.

## 3. Closure & Remediation
- **Remediation:** Never construct or compile template strings from user input; pass untrusted values strictly as context variables into static template files with auto-escaping enabled, or switch to logic-less templates / sandboxed contexts where user customization is required.
- **Closure:** Confirm live evaluation via `rce_proof` (`dynamic_math`) or static-only sinks via `static_ast_proof` (`static_verified`), always providing substantive `counterevidence` (e.g., distinguishing client-side Angular/Vue expression evaluation from server-side rendering). Close safe static templates via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
