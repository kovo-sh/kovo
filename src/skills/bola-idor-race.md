# Multi-Persona BOLA/IDOR & Race Condition Testing
Tags: bola, idor, access-control, multi-persona, race-condition, toctou, rate-limit
Summary: Systematically track per-persona resource IDs across user_a, user_b, and anonymous contexts for cross-tenant BOLA/IDOR validation, and verify concurrency/TOCTOU flaws with bounded Tier 2/3 race bursts.

## 1. Preconditions & Safety Guardrails
- **Multi-persona BOLA/IDOR** requires **Tier 2** (read/non-destructive verification) or **Tier 3** (operator-approved state-changing checks) with at least two opaque approved personas (e.g. `user_a` / `tenant_a` and `user_b` / `tenant_b`).
- **Race bursts (`request_http_race`)** require **Tier 2 or Tier 3** and are strictly bounded to **2–10 synchronized concurrent requests** against approved origins. Never send destructive payloads, delete real accounts, or exceed the broker's concurrency and rate limits.
- Never place raw `Authorization` or `Cookie` headers in tool calls or Replay Specs—always reference opaque `persona` handles.

## 2. Automated Multi-Persona Resource Tracking (`persona_resource`)
1. **Harvest `user_a` Owned Resources:**
   - Call account, profile, project, workspace, document, invoice, API-key, or webhook list/detail endpoints under `persona: "user_a"` (or the first available non-admin persona).
   - Also inspect `bolaTestQueue` (if supplied in the prompt) for resources already harvested by earlier workers or source-code audit suspects.
2. **Record Every Owned Resource (`record_fact`):**
   - Persist each discovered object using `record_fact` with `kind: "object_ref"` and `data`:
     ```json
     {
       "subkind": "persona_resource",
       "ownerPersona": "user_a",
       "resourceId": "<id-or-slug>",
       "endpoint": "/api/projects/<id-or-slug>",
       "method": "GET",
       "resourceType": "project",
       "canaryMarker": "<unique-non-secret-field-owned-by-user_a>"
     }
     ```
3. **Systematic Cross-Persona Replay Matrix (3-Way Proof):**
   For every harvested `persona_resource`, test ALL three identities:
   - **Owner baseline (`setup`):** `persona: "user_a"` → confirms `200` with `user_a`'s unique marker/field.
   - **Anonymous control (`control`):** no `persona` (unauthenticated) → verifies whether auth is missing (`200` = unauthenticated IDOR!) or enforced (`401`/`403`).
   - **Cross-persona probe (`probe`):** `persona: "user_b"` → if `200` returning `user_a`'s private object/canary (and NOT an SPA `200 text/html` catch-all!), you have a confirmed cross-tenant BOLA/IDOR!
   - Also test alternate parameter carriers (`?orgId=`, `?workspaceId=`, `?userId=`, `X-Organization-Id`) and secondary endpoints (`export`, `download`, `members`, `settings`, `audit-log`) referencing the same `resourceId`.

## 3. Bounded Race Condition / TOCTOU Verification (`request_http_race`)
Target endpoints where concurrent execution can violate a single-use or quota invariant (e.g., coupon/invite redemption, credit/token consumption, trial/seat allocation, one-time webhook/callback confirmation, idempotency-key enforcement):
1. **Baseline Check First:** Inspect normal single-request behavior (or verify in mounted source code whether the handler uses a non-atomic `SELECT ... THEN UPDATE` pattern without transactions/row locks).
2. **Synchronized Burst (`request_http_race`):**
   - Pass `requests` (2–10 scoped requests, typically 4–6 identical or paired requests with the same approved `persona` and benign/test-account payload) plus a concise `rationale`.
   - Inspect returned `summary` (`total`, `statuses`, `statusCounts`, `distinctBodies`, `spreadMs`) and individual exchange bodies.
3. **Confirming a Real Race vs Benign Idempotency:**
   - **Real Race / TOCTOU:** Multiple concurrent requests succeed (`200`/`201`) with distinct created resource IDs or double-applied balance/quota changes where business logic permits at most one success.
   - **Not a Vulnerability:** Idempotent retries returning the exact same object/receipt (`distinctBodies === 1` with no duplicate side effect) or properly serialized `409 Conflict` / `429 Too Many Requests` rejections.

## 4. Zero-LLM Replay Spec Schemas
- **BOLA/IDOR (`kind: "http_chain"`):**
  - Include `spaCatchallControl: true`, a `setup` step extracting `user_a`'s resource ID, a negative `control` step (unauthenticated or non-existent ID), and a `probe` step as `user_b`.
- **Race / TOCTOU (`kind: "race_burst"`):**
  - Fields: `version: 1`, `kind: "race_burst"`, `origin`, standard metadata + `assertionsJq`, optional `controlStep` (`ReplayStep`), `burst` (array of 2–10 `{ origin, method, pathAndQuery, headers?, persona?, jsonBody?, textBody?, followRedirects? }`), and optional `postCheckStep` (`ReplayStep`).
  - `assertionsJq` evaluates `/evidence/replay-results.json`:
    `{ kind, origin, replayedAt, control, burst: { summary: { total, statuses, statusCounts, distinctBodies, minDurationMs, maxDurationMs, spreadMs }, results }, postCheck, extractedVars }`.
  - Assert that `control` behaved cleanly AND `([.burst.results[] | select(.status == 200 or .status == 201)] | length) > 1` (plus post-check state or distinct resource proof when applicable).
