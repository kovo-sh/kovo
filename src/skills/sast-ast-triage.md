# SAST & AST Triage: Reducing Noise with Deterministic Code Analysis
Tags: sast, ast, opengrep, ast-grep, bandit, gitleaks, trivy, triage, static-analysis
Summary: Combine offline SAST (Opengrep, Bandit), structural AST queries (ast-grep), secret scanning (Gitleaks/TruffleHog), and SCA (Trivy) inside Kovo Hunter’s air-gapped worker to separate real source-to-sink flaws from false positives.

## 1. Offline Toolchain Strategy
All static analysis executes strictly inside Kovo Hunter’s `--network none` container over the read-only `/repos/<owner>/<repo>` mount via `run_sast_scan` and `derive_evidence`:
1. **Run Targeted Scans First:** Invoke `run_sast_scan` with the engines matching the repo stack (`opengrep` + `ast-grep` for JS/TS/Python/Go/Java/Ruby; `bandit` for Python; `gitleaks`/`trufflehog` for secrets; `trivy-fs` for lockfiles & IaC).
2. **Focus on Crown-Jewel Paths:** Prioritize changed files (`--diff-base`), auth middleware, API routes, Server Actions, webhooks, database layers, upload handlers, and IaC manifests.
3. **Never Print Raw Secrets:** `worker/bridge.ts` automatically masks matched secret values. Report secret hits strictly by `file:line`, detector rule ID, and masked fingerprint.

## 2. Four-Step SAST Triage Discipline
A raw SAST hit is NEVER a confirmed finding. For every high/critical candidate:
1. **Reachability Check:** Trace backward from the sink (`file:line`) to an entry point (HTTP route, Server Action, GraphQL resolver, WebSocket handler, webhook, or CI trigger). Is the input actually caller-controlled, or is it hardcoded/config-derived?
2. **Sanitizer & Guard Check:** Trace every intermediate function and middleware on the path. Look for schema validation (Zod, Pydantic, class-validator), parameterized queries, explicit allowlists, authentication guards, or tenant `WHERE` filters.
3. **Runtime vs Static Path:**
   - If the target is reachable live (or in `local-lab`), convert the suspect into a `code_audit_suspect` fact and prove exploitability dynamically via `RequestBroker` + Zero-LLM `ReplayVerifier` (`runtime_confirmed` tier).
   - If runtime verification is genuinely unavailable (e.g., Tier 0 CI source-only review), construct a deterministic `static_ast_proof` Replay Spec referencing the exact `repo`, `file`, `startLine`, `endLine`, `engine`, and `ruleOrPattern` (`static_verified` tier — never conflated with `confirmed`).
4. **3-State Closure:**
   - Confirmed or static-verified → `record_coverage` (`status: "reported"`, `linkedFindingId`).
   - Mitigated on the exact path → `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
   - Unclear runtime behavior (e.g., hidden WAF/proxy or missing Tier 2 persona) → `record_coverage` (`status: "needs_follow_up"`, `proofGapReason: "<exact blocker>"`).
