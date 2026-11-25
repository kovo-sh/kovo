# False-Positive Elimination & Zero-LLM Verification Discipline
Tags: verification, false-positives, controls, spa-catchall, kovo-verify, precision
Summary: Enforce Kovo Hunter's 100% precision bar by applying mandatory negative controls, SPA catch-all rejection, version-vs-reachability separation, and strict TypeScript `kovo_verify` assertions.

## 1. The Five Most Common Automated Pentester False Positives
1. **SPA `200 index.html` Catch-All Illusion:**
   - Modern React/Next.js/Vite frontends return `HTTP 200 text/html` for `/admin`, `/api/users`, `/.env`, and `/.kovo-nonexistent-999`.
   - **Rule:** Always compare probe responses against a random nonexistent path using `analyze_artifact` (`tool: "diff-response"`) and include a negative nonexistent-path control exchange in your TypeScript `kovo_verify` script. If `mediaType` is `text/html` and token similarity >= 0.85 with the catch-all control, it is a false positive—discard it immediately.
2. **Version-Only CVE Claims:**
   - Seeing `next@14.2.10` or `Server: nginx/1.x` in headers/lockfiles does NOT prove exploitability—edge WAFs, Vercel/Cloudflare header stripping, or unused features frequently neutralize the bug.
   - **Rule:** Record version matches only as `kind: "cve_hypothesis"` (`confidence: low`). Never propose a finding unless a live differential control-vs-probe test proves the vulnerable behavior is reachable. If blocked at the edge, record `record_coverage` with `status: "ruled_out"`.
3. **Input Reflection Mistaken for Execution:**
   - Seeing a query string echoed literally back inside JSON or an error message does NOT prove XSS, SSTI, or command execution.
   - **Rule:** For DOM/XSS, verify execution in a TypeScript `kovo_verify` script with `ctx.browser(...)` + `ctx.assert.domSentinel(...)`. For command/template/code execution proofs, use `ctx.proveInjectionDifferential(...)` (computed output absent from control and literal request) or `ctx.proveOobCallback(...)` with fresh verifier-minted canaries.
4. **Public Client Config Mistaken for Leaked Secrets:**
   - Publishable keys (`pk_live_*`, `pk_test_*`, Firebase web `apiKey`, Supabase `anon` JWT with working RLS, reCAPTCHA site keys) are intentionally public by design.
   - **Rule:** Distinguish publishable client identifiers from privileged secrets (`sk_live_*`, `service_role` JWT, `AKIA*`, private keys, DB connection strings). Only escalate public keys when chained with an actual server-side authorization bypass (e.g., missing RLS).
5. **Benign Public CORS / Generic Redirects:**
   - `ACAO: *` without `ACAC: true` on public unauthenticated assets is benign.
   - A redirect whose `Location` merely contains `example.invalid` inside a same-origin query parameter (e.g., `/login?next=https://example.invalid`) is NOT an open redirect—check that the parsed `Location` origin itself is external.

## 2. Pre-Submission Verification Checklist
Before submitting a TypeScript `kovo_verify` proof, verify every item:
- [ ] Does the script include both a clear control exchange and probe exchange (or call an authoritative `ctx.prove*` / `ctx.proveComposite` helper)?
- [ ] Do your transcript-backed claims (`ctx.assert.*` / `ctx.prove*`) verify BOTH that the control behaves as expected AND that the exact differential vulnerability condition holds?
- [ ] Are raw `Authorization` and `Cookie` headers completely absent (using opaque `as` / `persona` handles or sealed capability handles instead)?
- [ ] Is severity calibrated honestly to demonstrated impact (not hypothetical worst-case chains)?
- [ ] Did you record `record_coverage` accurately (`reported`, `no_issue_found`, or `ruled_out`)?
