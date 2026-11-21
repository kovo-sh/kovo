# False-Positive Elimination & Zero-LLM Verification Discipline
Tags: verification, false-positives, controls, spa-catchall, replay-spec, precision
Summary: Enforce Guardian v2’s 100% precision bar by applying mandatory negative controls, SPA catch-all rejection, version-vs-reachability separation, and strict Replay Spec assertions.

## 1. The Five Most Common Automated Pentester False Positives
1. **SPA `200 index.html` Catch-All Illusion:**
   - Modern React/Next.js/Vite frontends return `HTTP 200 text/html` for `/admin`, `/api/users`, `/.env`, and `/.guardian-nonexistent-999`.
   - **Rule:** Always compare probe responses against a random nonexistent path using `analyze_artifact` (`tool: "diff-response"`) and set `spaCatchallControl: true` in `http_chain` replay specs. If `mediaType` is `text/html` and token similarity >= 0.85 with the catch-all control, it is a false positive—discard it immediately.
2. **Version-Only CVE Claims:**
   - Seeing `next@14.2.10` or `Server: nginx/1.x` in headers/lockfiles does NOT prove exploitability—edge WAFs, Vercel/Cloudflare header stripping, or unused features frequently neutralize the bug.
   - **Rule:** Record version matches only as `kind: "cve_hypothesis"` (`confidence: low`). Never propose a finding unless a live differential control-vs-probe test proves the vulnerable behavior is reachable. If blocked at the edge, record `record_coverage` with `status: "ruled_out"`.
3. **Input Reflection Mistaken for Execution:**
   - Seeing a query string echoed literally back inside JSON or an error message does NOT prove XSS, SSTI, or command execution.
   - **Rule:** For DOM/XSS, verify execution in `browser_dom`. For `rce_proof`, rely exclusively on fresh verifier-minted `dynamic_math` (computed product absent from request), `split_echo` (assembled output absent from request), or dual `oob_canary` callbacks.
4. **Public Client Config Mistaken for Leaked Secrets:**
   - Publishable keys (`pk_live_*`, `pk_test_*`, Firebase web `apiKey`, Supabase `anon` JWT with working RLS, reCAPTCHA site keys) are intentionally public by design.
   - **Rule:** Distinguish publishable client identifiers from privileged secrets (`sk_live_*`, `service_role` JWT, `AKIA*`, private keys, DB connection strings). Only escalate public keys when chained with an actual server-side authorization bypass (e.g., missing RLS).
5. **Benign Public CORS / Generic Redirects:**
   - `ACAO: *` without `ACAC: true` on public unauthenticated assets is benign.
   - A redirect whose `Location` merely contains `example.invalid` inside a same-origin query parameter (e.g., `/login?next=https://example.invalid`) is NOT an open redirect—check that the parsed `Location` origin itself is external.

## 2. Pre-Submission Replay Spec Checklist
Before calling `propose_chain_finding`, verify every item:
- [ ] Does the spec include a clear `control` step and `probe` step?
- [ ] Does `assertionsJq` return `{ confirmed, controlPassed, observed, expected }` and verify BOTH `controlPassed == true` AND the exact differential condition?
- [ ] Are raw `Authorization` and `Cookie` headers completely absent (using opaque `persona` handles instead)?
- [ ] Is severity calibrated honestly to demonstrated impact (not hypothetical worst-case chains)?
- [ ] Did you record `record_coverage` accurately (`reported`, `no_issue_found`, or `ruled_out`)?
