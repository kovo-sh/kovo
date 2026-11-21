# Guardian v3 Verification Report

Verified on November 21, 2026 against [SPEC-v3.md](SPEC-v3.md) using the real compiled TanStack Start + React 19 production bundle, Playwright Chromium, Node.js 24 SQLite (`node:sqlite` + FTS5 trigram), real hardened Docker air-gapped worker image (`guardian-worker:local`, ID `47a031fc4573`, 1.42 GB), and real Docker `--internal` lab target containers.

---

## 1. Summary of Verification Gates (56 / 56 Automated Tests Passing)

Final combined verification command:
```bash
cd /home/exedev/guardian && npm run check && npm run build && npm run test:boundaries && node --test tests/v3-boundaries.test.ts tests/v3-protocol-browser.test.ts && npm run test:e2e
```

| Gate | Command | Pass Count | Duration | Result |
| :--- | :--- | :--- | :--- | :--- |
| **Hardened Worker Image** | `docker images guardian-worker:local` | Image `47a031fc4573` | — | **PASS** — `node:24-bookworm-slim` + pinned SHA-256 `opengrep v2.0.0`, `ast-grep`, `gitleaks v8.30.1`, `trufflehog v3.100.0`, `trivy v0.76.2`, `bandit 1.8.3`, offline Python/Node venv, UID `10001:10001`. |
| **TypeScript Typecheck** | `npm run check` (`tsc --noEmit`) | 0 errors | — | **PASS** — strict typecheck across `src/`, `scripts/`, `tests/`, `*.config.ts`. |
| **Production Build** | `npm run build` (`vite build`) | Client + SSR | 1.48s | **PASS** — Client bundle (1,052 modules, `949ms`) + TanStack Start SSR server bundle (128 modules, `527ms`). |
| **Core & v2 Boundary Suite** | `npm run test:boundaries` | **34 / 34** | 21.67s | **PASS** — `tests/boundaries.test.ts` (10), `tests/provider-stream.test.ts` (8), `tests/report-comparison.test.ts` (10), `tests/v2-upgrades.test.ts` (6). |
| **v3 Boundary & Subsystem Suite** | `node --test tests/v3-boundaries.test.ts` | **14 / 14** | ~30.6s | **PASS** — A1–A6 (real Docker worker v3, LabRunner `--internal` isolation, dedupe, air-gapped patch workflow, SARIF 2.1.0, headless CLI) + B1–B6 (surface/templates, DELETE/multipart, WS/interactive browser, dual HTTP+UDP DNS CanaryBroker, `static_ast_proof` + `requireControlNonError`, SQLite v2→v3 auto-migration). |
| **v3 Protocol & Interactive Browser Suite** | `node --test tests/v3-protocol-browser.test.ts` | **4 / 4** | ~12.5s | **PASS** — Self-contained loopback tests for `probeWebsocket` + `ws_chain`, Tier-3 `multipartParts` + `upload_probe`, interactive `ScopedBrowser` (`fill`/`click`/`wait_for_selector`/`dom_xss_sink_hook`) + `browser_chain`, and `ReplayVerifier` `requireControlNonError` (404/503 → `inconclusive`). |
| **Production Browser E2E Suite** | `npm run test:e2e` (`playwright test`) | **4 / 4** | 28.4s | **PASS** — `tests/guardian-v2.spec.ts` against real `scripts/serve.ts` + real Docker workers (`9.3s`, `5.2s`, `7.5s`, `5.5s`). |
| **Docker Hygiene Check** | `docker ps -aq` / `docker network ls` | **0 orphans** | — | **PASS** — Zero lingering Guardian worker containers, lab containers, or `--internal` networks. |

---

## 2. Detailed Verification of All 7 Non-Negotiable Defensive Invariants

| # | Defensive Invariant (SPEC-v3 §2) | Verified Evidence |
| :--- | :--- | :--- |
| **1** | **Zero-Network Workers** | `tests/v3-boundaries.test.ts` (A1) inspects live Docker `guardian-worker:local` `HostConfig`: `NetworkMode: "none"`, `ReadonlyRootfs: true`, `Privileged: false`, `CapDrop: ["ALL"]`, `no-new-privileges`, `User: "10001:10001"`, `Memory: 1 GiB`, `MemorySwap: 1 GiB`, `NanoCpus: 2.0`, `PidsLimit: 192`, `/tmp` `noexec,size=128m`, single read-only `/repos` bind mount; verified offline `gitleaks`/`trufflehog`/`opengrep`/`ast-grep` SAST with secret masking, offline Python & Node outbound socket blockage, `/repos` write denial, and script timeout enforcement. |
| **2** | **Opaque Credential Isolation** | `tests/boundaries.test.ts`, `tests/provider-stream.test.ts`, `tests/v3-boundaries.test.ts` (A1, A5, A6, B2, B3), `tests/v3-protocol-browser.test.ts` (#1), and `tests/guardian-v2.spec.ts` (#1): `0600` persona credential enforcement (CLI rejects `0644` persona files without leaking secret); cross-origin redirect auth stripping; bridge-level SAST/script secret masking; WebSocket frame secret redaction; cross-chunk OpenAI Responses & Anthropic Messages SSE redaction; zero secret leaks in SQLite, SARIF 2.1.0, and Markdown exports. |
| **3** | **Strict Non-Destructive Proof Standard** | `tests/boundaries.test.ts`, `tests/v3-boundaries.test.ts` (B1, B2), and `tests/v3-protocol-browser.test.ts` (#2): `DELETE` and `multipart/form-data` hard-blocked at Tiers 0–2 (`BrokerDenied`) and HITL-gated at Tier 3 (`BrokerApprovalRequired`); webshell signatures (`<?php`, `<%`, `child_process`) and `> 256 KiB` uploads rejected even at approved Tier 3; unsafe YAML templates (mutating without `requiresTier3`, third-party OAST callbacks) rejected at parse/load time (`TemplateValidationError`); `rce_proof` requires verifier-minted cryptographic nonces and rejects destructive payloads. |
| **4** | **Zero-LLM Finding Confirmation & Strict Tier Separation** | `tests/v3-boundaries.test.ts` (A5, B1, B5), `tests/v3-protocol-browser.test.ts` (#1–#4), and `tests/guardian-v2.spec.ts` (#1): templates emit only `cve_hypothesis`/`candidate_lead`; `static_ast_proof` runs deterministic offline `ast-grep`/`opengrep` re-verification and promotes strictly to `static_verified` (never `confirmed`/`runtime_confirmed`); `ws_chain`, `upload_probe`, `browser_chain`, and `http_chain` evaluate evidence inside `--network none` `jq` containers with `requireControlNonError` converting unexpected `404`/`503` posture responses to `inconclusive`; SARIF 2.1.0 preserves `runtime_confirmed` vs `static_verified` separation. |
| **5** | **Hard Technical Scope & Live Transitive Revocation** | `tests/boundaries.test.ts`, `tests/v3-boundaries.test.ts` (B1, B3), `tests/v3-protocol-browser.test.ts` (#1, #3), and `tests/guardian-v2.spec.ts` (#4): DNS public-IP enforcement (`ipaddr.js`), 8-hop redirect cap, `probeSurface` / `probeWebsocket` / `ScopedBrowser` out-of-scope rejection (`0` direct hits on unapproved third-party origins, recorded in `blockedOrigins`), sliding-window `5xx`/`429` defensive circuit breaker halting discovery early, and live mid-chain scope revocation omitting revoked hosts and transitively tainting downstream graph nodes. |
| **6** | **Crash-Safe Explicit Resumability** | `tests/guardian-v2.spec.ts` (#3) and `tests/v3-boundaries.test.ts` (B6): real `SIGKILL` crash during active investigation recovers cleanly into `paused` with zero requests sent before clicking **Resume** and zero duplicate baseline requests; SQLite v2→v3 auto-migration preserves existing v2 projects losslessly (tested on a `/tmp` copy of `.guardian/dyad-v2-smoke/data/guardian.sqlite` without touching the original) and persists v3 3-state closure (`openProofGaps`), `sast_runs`, `surface_probes`, and `patch_proposals`. |
| **7** | **Isolated White-Box Target Execution (`local-lab`)** | `tests/v3-boundaries.test.ts` (A2): `publicAssetOrigin` and `project.environment === 'public'` never permit loopback/HTTP/port origins even when `GUARDIAN_ALLOW_LOCAL_LAB=1`; `LabRunner.startLabTarget` hard-blocks unless **both** `environment === 'local-lab'` AND `GUARDIAN_ALLOW_LOCAL_LAB=1`; live lab targets run on a dedicated Docker `--internal` network (`Internal: true`), `--cap-drop ALL`, `no-new-privileges`, `Privileged: false`, bounded CPU/RAM/PIDs, zero published host ports, sanitized copy stripping `.env` and `*.pem` keys, zero internet egress (`1.1.1.1` blocked), zero access to host services/bridge gateways, safe non-mutating `rebuildWithPatch`, and clean teardown with zero orphans. |

---

## 3. Focused Loopback Protocol & Browser Tests (`tests/v3-protocol-browser.test.ts` — 4 / 4)

1. **WebSocket (`probeWebsocket` + `ws_chain`):** Verified Tier 0, out-of-scope, and Tier 1 persona denials (`BrokerDenied`); verified same-origin (`101`) vs untrusted-origin (`403`) on `/ws/strict`; verified persona header injection + secret redaction on received frames; verified `maxFrames` (`<= 2`) and `maxBytes` (`<= 1024`) bounds on `/ws/flood`; verified Zero-LLM `ws_chain` confirmation (`confirmed` / `runtime_confirmed`) on vulnerable `/ws/cswsh`, dismissal (`dismissed`) on `/ws/strict`, and `inconclusive` on unexpected `404` under `requireControlNonError`.
2. **Multipart Upload (`multipartParts` + `upload_probe`):** Verified Tier 1/2 rejection (`BrokerDenied`), Tier 3 HITL gating (`BrokerApprovalRequired`), webshell signature rejection (`<?php`, `<%`, `child_process`), and `256 KiB` cap (`262,145` bytes denied); verified Zero-LLM `upload_probe` mints `{{upload_nonce}}`, confirms inline `image/svg+xml` without `Content-Disposition: attachment` (`confirmed` / `runtime_confirmed`), dismisses hardened `Content-Disposition: attachment` responses (`dismissed`), and executes `cleanupStep` (`DELETE`) on every run.
3. **Interactive `ScopedBrowser` (`visitPage` + `browser_chain`):** Verified 100% `RequestBroker` proxying (`visit.exchanges.length === appHits`), out-of-scope third-party script abort (`0` hits on trap server, recorded in `blockedOrigins` and audited `denied`), sequential safe actions (`dom_xss_sink_hook`, `fill`, `click`, `wait_for_selector`), deterministic `innerHTML` canary trace capture on `/vuln` vs zero sink hits on `textContent` `/safe`, and end-to-end Zero-LLM `browser_chain` confirmation (`confirmed` / `runtime_confirmed`).
4. **`ReplayVerifier` `requireControlNonError` Guardrail:** Verified unexpected HTTP `404` and `503` on posture checks yield `inconclusive` with explicit error reasons even when `jq` returns `controlPassed: true, confirmed: true`, while explicitly declaring `expectedStatus: 404` allows intentional error-page checks to evaluate normally.

---

## 4. Defect Caught & Resolved During Gate Verification

- **Playwright E2E Fixture Contract Update (`tests/v2-fixture-server.ts:252-255`):** During `npm run test:e2e`, test #1 failed because `src/server/agent-session.ts:1631-1662` enforces SPEC-v3 §4.5C mandatory `counterevidence` (`>= 10` chars) and `confidenceRationale` (`>= 10` chars) on `propose_chain_finding`, whereas the legacy v2 mock fixture only passed `{ replaySpec: cveReplaySpec }`. Preserving SPEC-v3 §4.5C, updated `tests/v2-fixture-server.ts:252-255` to emit valid `counterevidence` and `confidenceRationale`, bringing `npm run test:e2e` to **4 / 4 passing**.

---

## 5. Inventory of Implemented Guardian v3 Modules & Playbooks

### Core Server, Sandbox, CLI & UI Modules
- **Air-Gapped Worker v3:** `worker/Dockerfile`, `worker/bridge.ts`, `worker/analyzers.ts`, `worker/rules/opengrep/{auth-access-control,iac-cloud,web-injection}.yaml`, `worker/rules/ast-grep/sgconfig.yml` (+ rules), `worker/rules/sca-advisories.json`, `src/server/worker-backend.ts`.
- **Broker, Discovery, Protocol & Browser v3:** `src/server/broker.ts` (Tier-3 `DELETE`, `multipartParts`, `probeWebsocket`, `local-lab` HTTP/port gate), `src/server/surface-engine.ts` (`probeSurface`, `probeDifferential`, `runSafeTemplates`), `src/templates/loader.ts`, `src/templates/yaml.ts`, `src/server/scoped-browser.ts` (interactive actions + `dom_xss_sink_hook`), `src/server/canary-broker.ts` (dual HTTP + authoritative UDP DNS).
- **Replay Verification, Dedupe & Closure Discipline:** `src/replay-spec.ts` (11 declarative replay spec kinds including `sql_boolean_diff`, `ws_chain`, `upload_probe`, `static_ast_proof`), `src/server/replay-verifier.ts` (`requireControlNonError`, strict `static_verified` tier separation), `src/server/dedupe.ts` (two-stage structural + semantic dedupe), `src/server/agent-session.ts`, `src/server/skills.ts`.
- **Isolated Lab Execution & Air-Gapped Patching:** `src/server/lab-runner.ts` (`--internal` Docker target runner + sanitized copy + `rebuildWithPatch`), `src/server/patch-workflow.ts` (air-gapped patch author + 6-gate independent reviewer withholding `breaks_callers`).
- **Persistence, Headless CLI, SARIF & UI:** `src/domain.ts`, `src/server/schema.ts`, `src/server/store.ts` (lossless v2→v3 auto-migration), `src/server/execution.ts`, `src/server/sarif-export.ts` (OASIS SARIF 2.1.0), `src/server/report-export.ts`, `src/report-summary.ts`, `src/actions.ts`, `scripts/cli.ts` (`guardian scan` headless CLI with exit codes `0/1/2`), `src/components/run-overview.tsx`, `src/components/run-report.tsx`.

### Curated Defensive Skills (`src/skills/` — 41 Playbooks)
1. `access-control-bola-bfla.md`
2. `api-rest-graphql.md`
3. `auth-oauth-oidc.md`
4. `bola-idor-race.md`
5. `business-logic-workflows.md`
6. `ci-github-actions-security.md`
7. `clerk-auth0-oidc.md`
8. `client-side-xss-postmessage.md`
9. `cors-csrf-cross-origin.md`
10. `cross-host-chaining.md`
11. `cve-runtime-correlation.md`
12. `deserialization-safe-fingerprint.md`
13. `dns-takeover-tls-infra.md`
14. `false-positive-elimination.md`
15. `firebase-rules-audit.md`
16. `framework-django.md`
17. `framework-fastapi.md`
18. `framework-nestjs.md`
19. `framework-nextjs.md`
20. `framework-rails.md`
21. `framework-springboot.md`
22. `iac-docker-k8s-terraform.md`
23. `injection-benign-proof.md`
24. `jwt-session-security.md`
25. `llm-gateway-ai-security.md`
26. `mass-assignment-overposting.md`
27. `nosqli-type-confusion.md`
28. `oob-ssrf-browser-chain.md`
29. `patch-verification.md`
30. `path-traversal-canonicalization.md`
31. `prototype-pollution-dom-server.md`
32. `recon-modern-spa.md`
33. `sast-ast-triage.md`
34. `source-first-audit.md`
35. `sqli-boolean-differential.md`
36. `ssrf-canary-redirects.md`
37. `ssti-non-destructive.md`
38. `supabase-rls-audit.md`
39. `upload-storage-security.md`
40. `websocket-cswsh.md`
41. `xxe-canary-proof.md`

### Vetted Non-Destructive YAML Templates (`src/templates/` — 37 Templates)
- **actuator (2):** `actuator-health-details-exposed.yaml`, `prometheus-metrics-exposed.yaml`
- **clerk (1):** `clerk-frontend-api-proxy-environment.yaml`
- **django (2):** `django-admin-login-exposed.yaml`, `django-debug-mode-enabled.yaml`
- **exposure (3):** `dotenv-file-exposed.yaml`, `git-config-exposed.yaml`, `phpinfo-exposed.yaml`
- **express (2):** `express-stack-trace-disclosure.yaml`, `express-x-powered-by-header.yaml`
- **fastapi (2):** `fastapi-docs-exposed.yaml`, `fastapi-openapi-json-exposed.yaml`
- **graphql (3):** `graphql-ide-exposed.yaml`, `graphql-introspection-enabled.yaml`, `graphql-introspection-post-tier3.yaml`
- **headers (2):** `cors-null-origin-allowed.yaml`, `cors-reflected-origin-credentials.yaml`
- **nestjs (1):** `nestjs-swagger-json-exposed.yaml`
- **nextjs (4):** `nextjs-dev-build-manifest.yaml`, `nextjs-image-optimizer-ssrf-canary.yaml`, `nextjs-middleware-subrequest-bypass.yaml`, `nextjs-source-map-exposed.yaml`
- **source-maps (2):** `bundle-js-source-map-exposed.yaml`, `cra-main-js-source-map-exposed.yaml`
- **springboot (3):** `springboot-actuator-env-exposed.yaml`, `springboot-actuator-index-exposed.yaml`, `springboot-actuator-mappings-exposed.yaml`
- **supabase (2):** `supabase-env-js-config.yaml`, `supabase-rest-openapi-exposed.yaml`
- **swagger (3):** `openapi-v3-docs-exposed.yaml`, `swagger-json-exposed.yaml`, `swagger-ui-exposed.yaml`
- **vite (2):** `vite-dev-server-exposed.yaml`, `vite-ping-endpoint.yaml`
- **wordpress (3):** `apache-server-status-exposed.yaml`, `nginx-status-exposed.yaml`, `wordpress-rest-user-enumeration.yaml`

---

## 6. Scope & Deferred Live Benchmarks

- **Protected Artifacts Untouched:** `.guardian/dyad-v2-smoke/` (read-only copy tested in `/tmp`), `site-prototypes/`, `ui-prototypes/`, and ports `8000`–`8004` were not modified.
- **Deferred Live Benchmarks:** External live smoke runs (`dyad.sh`) and full 104-challenge XBEN LLM recall benchmarking require live provider credentials/budget and are intentionally outside this deterministic offline CI verification pass.
