# LLM Gateways, AI Proxy Endpoints & Quota/Auth Security
Tags: llm, ai, gateway, proxy, streaming, quota, prompt-injection, billing
Summary: Audit LLM proxy APIs, model-routing gateways, streaming SSE endpoints, key isolation, per-tenant rate/quota enforcement, and indirect prompt-injection trust boundaries.

## 1. AI Gateway Surface Discovery
1. Review `project_specs`, synced repositories, and JS bundles for AI/LLM gateway routes (`/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/api/chat`, `/api/ai/*`, `/api/llm/*`, `/api/completion`, `/api/stream`).
2. Record detected endpoints (`kind: "endpoint"`), model routing metadata, and auth mechanisms (`kind: "auth"`).

## 2. High-Signal Defensive Checks
- **Unauthenticated / Misconfigured Proxy Access:**
  - Verify AI proxy routes strictly reject unauthenticated requests (`401`/`403`) rather than forwarding calls using the server's upstream API key.
  - Check whether `OPTIONS` or `GET /v1/models` leaks internal upstream endpoints, provider keys, or model routing tables.
- **Provider Key & Header Isolation:**
  - Verify error responses (invalid model ID, malformed JSON, upstream 4xx/5xx) do not echo upstream `Authorization`, `x-api-key`, `openrouter` keys, or internal proxy stack traces.
  - Run `analyze_artifact` (`tool: "secret-scan"`) on client JS bundles and API error payloads to ensure upstream AI keys are never bundled client-side.
- **Cross-Tenant Context & Billing Isolation (Tier 2):**
  - With two personas (`tenant_a`, `tenant_b`), verify conversation history, thread IDs, uploaded prompt files, and usage/credit endpoints enforce strict tenant ownership (BOLA check).
  - Check whether arbitrary `model`, `base_url`, or `endpoint` override parameters in client requests are rejected (preventing SSRF or unauthorized costly model substitution).
- **Rate-Limit & Abuse Controls (Non-Destructive):**
  - Inspect rate-limit headers (`x-ratelimit-*`, `retry-after`) and quota enforcement responses without sending high-volume floods.
- **Indirect Prompt Injection & Tool Boundaries:**
  - If the application passes fetched web content, user uploads, or chat history into a backend agent/tool pipeline, document trust-boundary gaps (e.g., missing output sanitization when rendering LLM markdown/HTML into DOM → pair with `client-side-xss-postmessage`).

## 3. `kovo_verify` Verification Rules
- Use `kovo_verify` (`ctx.prove_access_boundary` or `ctx.http` + `ctx.expect` verifying non-SPA JSON API responses and cross-tenant isolation) + `return ctx.result({ title })`.
- Never send expensive long-generation prompts or abusive load; use minimal `max_tokens: 1` or read-only metadata/error-handling probes, and require Tier 3 approval for any state-changing or billable mutation.
