# Kovo Hunter — Claude audit (2026-11-25)
> Round 2 (critical/high focus, snapshot 98881b4): see [CLAUDE_AUDIT_R2.md](CLAUDE_AUDIT_R2.md).
> Round 3 (new critical/high, snapshot 09a5126): see [CLAUDE_AUDIT_R3.md](CLAUDE_AUDIT_R3.md).
> Round 4 (new critical/high, snapshot 09f9eeb): see [CLAUDE_AUDIT_R4.md](CLAUDE_AUDIT_R4.md).

**Scope and method.** Multiple agents audited a read-only snapshot at commit `4f46973` (git worktree `agents/claude-audit`). Each area agent used ARCHITECTURE.md §2/§5/§6 as claims to test rather than truth, traced code by grep and targeted reads, and ran in-memory `node` probes where a regex or pure module was involved. Areas covered: broker/egress, approval, verify kernel, oracles/ledger, worker container, orchestration, agent/model, persistence, auth/secrets, HTTP/UI, engine/recon, replay/patch/report, invariants I1–I14, fail-open paths, concurrency, architecture, build health, prior-audit status, and eight gap areas: scoped browser, prove handlers, floor recipes, finding lifecycle, OOB/canary, untrusted repo analysis, among others. Each candidate then went through adversarial verification by one to three independent verifiers, who tried to refute it, corrected locations, and adjusted severity. Of **189 candidates, 185 were upheld and 4 refuted**. After merging findings with the same root cause, the 185 upheld findings collapse into **148 distinct findings**, plus one prior-audit re-report that is listed only in the prior-audit table. Severities are the verifier consensus. Where merged findings disagreed, the higher justified severity is used and the reason is given. Locations were spot-checked against the snapshot for every Critical item and a sample of High items. No benchmarks, Docker or network calls were run. No exploit payload strings appear anywhere in this document.

| Severity | security | correctness | reliability | data-integrity | performance | architecture | testing | maintainability | **Total** |
|---|---|---|---|---|---|---|---|---|---|
| Critical | 3 | 5 | 0 | 0 | 0 | 0 | 0 | 0 | **8** |
| High | 13 | 10 | 13 | 1 | 2 | 0 | 0 | 0 | **39** |
| Medium | 19 | 14 | 7 | 7 | 3 | 2 | 4 | 0 | **56** |
| Low | 14 | 3 | 12 | 6 | 1 | 4 | 1 | 4 | **45** |
| **Total** | 49 | 32 | 32 | 14 | 6 | 6 | 5 | 4 | **148** |

## Top risks

1. **The broker is not the only egress or approval gate.** The verify-RPC `http2` op uses its own HTTP/2 client and lets worker-supplied pseudo-headers override the method, path and authority after the approval check has run (C-1). A POST whose JSON body merely looks like a GraphQL query is approved on any path in `prod_readonly` (H-3). Batch and race approval evaluates only the first request but grants all of them (H-4). Subdomain auto-admission adds other tenants of shared platforms to the run's scope (C-2).
2. **The proof kernel confirms on inputs the model asserts.** Oracle operands, roles, tenants, ambient auth, request bodies, exchange ordering, oracle events and recipe envelopes all come from the worker without host corroboration. The result is forged or false `confirmed` verdicts in economic, business-logic, race, SQLi, DOM-XSS, CSRF, auth-bypass and access-control classes (C-3 to C-8, H-5, H-11 to H-18).
3. **Secrets reach the worker and the model.** `capability.seal` acts as a byte-level oracle over raw response bytes (C-3). The HTTP/2 path returns raw `Set-Cookie` headers (H-7). Browser pages hold raw jar cookies and persona tokens and return unredacted fields (H-8). Redaction misses common framework secrets and escaped encodings (M-13, M-14).
4. **The emergency stop does not stop anything in production.** The HTTP endpoint trips a different kill-switch instance from the one the broker reads (H-1). Tenant-scoped trips match nothing and can lift a global trip. No persistence is configured, and persona refreshers bypass the switch (H-2).
5. **Untrusted input can hang or crash the shared host process.** Worker regexes, target bodies and repo content reach catastrophic or quadratic regex and expansion paths on the main event loop (H-32 to H-38). Unhandled rejections after a run is deleted (H-30) and a poisoned batch writer (M-16) also crash or wedge the process.
6. **Runs wedge or spin with no terminal state.** A failed verification worker (H-27), a denied or expired Tier-3 approval (H-28), a provider outage hot-loop (H-29) and a cross-run scope-revision check (H-21) each leave runs `running` indefinitely or deny all egress.
7. **Cross-run and cross-project state bleeds.** Persona sessions are pooled by bare handle across projects (H-22). Worker clones freeze expiring credentials (H-23). Pooled browser contexts keep the grant of the first assignment that created them (H-24). The stale-container sweep deletes warm pools belonging to other processes (H-31).
8. **CI and gates do not reflect product health.** `test:boundaries` and the e2e step are red on `main` (M-32, M-33). `worker-gate` skips the trust-boundary suites (M-34). 187 of 264 test files are run by nothing, and 19 of them fail unseen (M-35).

## Findings

Ranked by severity, then by blast radius. "Verification" summarises what the adversarial verifiers confirmed.

### Critical

#### C-1 — Verify-RPC `http2` op bypasses the broker; caller pseudo-headers override the approved method, path and authority
- **Category:** security
- **Location:** [src/server/verify-rpc.ts:1296](../src/server/verify-rpc.ts#L1296), also [:1266-1279](../src/server/verify-rpc.ts#L1266) and [:625-632](../src/server/verify-rpc.ts#L625)
- **What's wrong:** `executeHttp2` decides on Tier, approval, scope and persona injection using `req.method`, `req.pathAndQuery` and `url.origin`. It then calls `client.request({':method':…, ':path':…, ...headers})`. Caller headers are spread last, and nothing strips names that begin with `:`. The path also bypasses every RequestBroker control: there is no kill-switch bind, no `evaluateScopeRequest`, no destructive denylist, no RPS slot, no audit, and no IP pin (`h2Connect` re-resolves the name).
- **Evidence:** `parseHttpArgs` rejects only CR/LF/NUL in header names. The forwarded-header blocklist at :1274 has no pseudo-headers. By contrast, `transport.ts:726` (`h2Headers`) does skip `:`-prefixed caller headers. A grep of verify-rpc.ts for killSwitch, evaluateScopeRequest, acquireSlot or audit finds nothing. The transcript records `prep.requestMeta`, which holds the declared method and path, not the ones sent.
- **Impact / failure scenario:** Worker code declares `GET`, which skips Tier and approval at any tier including Tier 1 and `prod_readonly`, then sends any state-changing verb to any path on a scoped origin. An `:authority` override sends persona credentials to another virtual host on a shared front end. Traffic continues after a kill-switch trip, and the signed evidence misstates what was sent.
- **Recommendation:** Route `http2` through `RequestBroker.executeHttp`, which already has an h2 transport. Until then, reject `:`-prefixed or non-token header names in `parseHttpArgs`, build pseudo-headers after the spread, pin the validated address, and add kill-switch, scope, denylist and audit checks. Add a regression test.
- **Verification:** Merged from two area findings. All five verifiers confirmed by code trace. Node's http2 client fills in pseudo-headers only when they are absent. ARCHITECTURE.md:275 incorrectly lists `http2` as brokered.

#### C-2 — Subdomain auto-admission computes the apex naively and admits other tenants of shared platforms as active scan targets
- **Category:** correctness (scope)
- **Location:** [src/server/subdomain-discovery.ts:117](../src/server/subdomain-discovery.ts#L117), also [:205-208](../src/server/subdomain-discovery.ts#L205), [:433-466](../src/server/subdomain-discovery.ts#L433), [exec-recon-planner.ts:1493-1513](../src/server/exec-recon-planner.ts#L1493)
- **What's wrong:** `apexDomainOfHost` takes the last two labels unless the pair is in a hardcoded list of ccTLD second-level suffixes. It never calls the PSL-backed `registrableDomain`. A seed such as a Vercel, GitHub Pages or Heroku tenant therefore gets the platform suffix as its apex. Every host under that apex that crt.sh lists and that resolves, plus `www.<apex>` which is always added, is auto-approved and receives Phase-0 recon and agentic probing in the same run.
- **Evidence:** `public-suffix.ts:10-12` names exactly this widening as the reason the PSL module exists, but this file never imports it. The SaaS CNAME filter excludes PaaS/CDN on purpose. `includeSubdomains` defaults to true for public projects (`routes/index.tsx:48`, `store-projects.ts:353`).
- **Impact / failure scenario:** An operator scanning their own app on a shared platform with default settings sends active probes to the platform vendor's `www` host and to up to 40 sibling tenants that were never authorized. This is egress outside scope.
- **Recommendation:** Admit only the asset host and its own subdomains. If apex discovery stays, use `registrableDomain()` and refuse when it returns a public suffix. Add a regression test with a shared-platform tenant seed.
- **Verification:** All three verifiers confirmed the code. Two kept critical and one argued high: the trigger is operator configuration, and crt.sh queries for large suffixes often time out, leaving only the `www` fallback. The sibling-host case for ordinary domains is intended behaviour. Severity stays critical because the `www.<platform>` admission happens on every such run under default settings.

#### C-3 — `capability.seal` acts as a byte-level oracle over raw, unredacted response bytes, so the worker can recover hidden secrets
- **Category:** security
- **Location:** [src/server/verify-rpc.ts:1650](../src/server/verify-rpc.ts#L1650) (regex at :1652-1656, value-membership test at :1658-1666, meta returned at :1733-1739), [src/server/derived-custody.ts:174-200](../src/server/derived-custody.ts#L174)
- **What's wrong:** `extractSecretFromExchange` runs worker-chosen selectors over `rawBodies` and `rawResponseHeaders`, which are captured before redaction. The regex selector accepts a capture of any length, including one character. `seal()` requires only `length > 0` and returns `sha256` and `sha256Prefix` of the raw value, and scrubbing leaves hex digests untouched. The `value` selector is a yes/no substring test over raw body plus headers, including Set-Cookie. Re-sealing the same handle skips the capacity check, so the number of queries is unbounded.
- **Evidence:** Raw capture happens at verify-rpc.ts:1079-1080 and broker.ts:3511. `MIN_SCRUB_LENGTH=4` means 1–3 character values are never scrubbed. No per-op budget exists in `dispatch`.
- **Impact / failure scenario:** A prompt-injected worker script learns one character per RPC by hashing it, or a prefix per call through membership tests. It can recover target-issued tokens, re-issued persona session cookies and JSON secret fields, then print them to stdout and into model context. This breaks I3, and ARCHITECTURE.md:312 says the opposite.
- **Recommendation:** Return only the handle, never a digest of a worker-selected substring. Enforce a minimum length and entropy before sealing. Replace free-form `value`/`regex` with host-defined extraction (jsonPath, header or cookie name). Rate-limit seals.
- **Verification:** Merged from two findings. Six verifiers confirmed the path and noted that ARCHITECTURE.md:312 is contradicted. Two rated it high because what leaks is the target's own bytes and there is no egress. Kept critical: this is secret exfiltration to the worker and model.

#### C-4 — v8 oracle hydration passes model-asserted operands and booleans through; `economic_conservation` returns early before every strict gate
- **Category:** correctness (proof kernel)
- **Location:** [src/server/v8-oracle-hydrate.ts:279](../src/server/v8-oracle-hydrate.ts#L279), [src/server/composite-receipt.ts:674](../src/server/composite-receipt.ts#L674), [src/server/v8-oracle-families.ts:395-440](../src/server/v8-oracle-families.ts#L395) and [:494-604](../src/server/v8-oracle-families.ts#L494)
- **What's wrong:** `hydrateV8OracleInput` begins with `{ ...rawInput }` and replaces only the fields that are record references. Every scalar and boolean reaches the evaluators exactly as the model wrote it. Affected inputs include `paidAmount`, `refundedAmounts`, `balancesBefore`/`balancesAfter`, `cacheHitObserved`, `victimArtifactDigest`, signature digests, `persistedImpact`, `elevatedRoleGranted`, `mutationPersisted`, `rolesByTenant` and `foreignDataObserved`. For `economic_conservation`, line 674 returns ok as soon as the explicit oracle passes, which skips the stub, own-tenant, needsStrict and denied-control gates.
- **Evidence:** The schema at composite-receipt.ts:64 is `oracleInput: z.record(z.unknown())`. No code compares these operands with the JSON of the hydrated readbacks. The prompts at agent-prompts.ts:1108 and :2825 tell the model to supply them. For `temporal_revocation` and `cryptographic_scope_replay`, a non-empty `oracleInput` also skips the two-hop requirement.
- **Impact / failure scenario:** A benign GET, POST and GET sequence, plus invented `paidAmount` and refund figures, is confirmed as over-refund or value-minting. Cache-bleed, signature-replay and revocation findings can likewise be confirmed on honest traffic. This is the "terminal impact claimed by assertion" that I7 says cannot happen.
- **Recommendation:** Derive every operand on the host from the hydrated readback JSON, using host- or receipt-declared paths evaluated over host records. Drop worker-facing booleans and digest overrides. Remove the early return at :674. Make `needsStrict` apply whenever an explicit family is used.
- **Verification:** Merged from two findings (C-4 critical, with the other families rated high). Six verifiers confirmed. The other families are partly bounded by the generic denied-control floor, but the shared root cause is the hydration spread.

#### C-5 — Conserved-balance/race receipt trusts worker-chosen exchange roles, array order, `unitDebit` and `requestBody`, and never checks concurrency
- **Category:** correctness (proof kernel)
- **Location:** [src/server/proof-receipt.ts:1676](../src/server/proof-receipt.ts#L1676), also [:728/:739](../src/server/proof-receipt.ts#L728), [:658-668](../src/server/proof-receipt.ts#L658), [:1684-1700](../src/server/proof-receipt.ts#L1684), [src/server/verify-prove-handlers.ts:757-763](../src/server/verify-prove-handlers.ts#L757)
- **What's wrong:** The race branch of `buildAgentScriptReceipt` builds the list `[baseline, …burst, post, serialPre, …serial, serialPost]` from IDs the worker cites, and never sorts it by transcript sequence. The other branches do sort, with `orderById`. `verifyConservedBalanceReceipt` then decides "before burst" and "after burst" by array position. The expected debit comes from the claim's `requestBody` or `unitDebit`, which overrides the host-recorded body. A 4xx serial control skips the serial-debit cross-check. Layer 3 needs only two 2xx responses with different bodies and does not require `op:'race'` or any overlap in time. `prove.race` copies baseline, post and serial IDs from args when `readRoute` is absent, and `serialPre` always comes from args.
- **Evidence:** Traced end to end by six verifiers. One corrected the exact scenario: reusing the same read for two roles fails because of role overwriting. A trivial variant with distinct pre-burst reads still confirms `under_debit`. A script can also return a hand-built race claim without calling `prove.race`.
- **Impact / failure scenario:** A target with correct concurrency control gets a `race_double_spend` (CWE-362) finding that is confirmed deterministically in both fresh runs.
- **Recommendation:** Never accept worker IDs for these roles. Require `readRoute` and record all reads on the host. Order cited entries by host seq and enforce baseline < burst < post < serial. Require burst records from one host race op. Compute debit only from host-recorded bodies.
- **Verification:** Merged from two findings (critical and high). Six verifiers confirmed. Critical stands because the false confirmation is accepted from untrusted input.

#### C-6 — `business_logic` impact passes on any successful write when the claim declares `requiredRole` or `resourceTenant`
- **Category:** correctness (proof kernel)
- **Location:** [src/server/oracle-invariants.ts:1640-1651](../src/server/oracle-invariants.ts#L1640)
- **What's wrong:** `assessBusinessLogicImpact` sets `labels.boundary = boundaryControlDenied || crossTenant || roleDifferential` and returns satisfied straight away. `crossTenant` compares the tenant the claim supplies with the probe actor, and `roleDifferential` compares the role the claim supplies. `mirrorCorroborated` is computed but never gates either value. The authorization assessor treats the same fields as untrusted and still requires persistence plus a protected field.
- **Evidence:** `isClaim` does not validate either field. They flow unchanged through verify-claims.ts:1137-1145 and proof-receipt.ts:1427-1430 and :508-517. The stub guard is skipped once roleDifferential or crossTenant is set. The impact-backed gate is satisfied when the title or CWE classifies as business_logic.
- **Impact / failure scenario:** A member persona's ordinary 2xx POST, plus `requiredRole: admin`, is confirmed as CWE-840 by both the claim oracle and the receipt. Even a hallucinated field is enough.
- **Recommendation:** Apply the same corroboration rules as `assessAuthorizationImpact`: a same-route denied control from a peer for the role claim, a mirrored tenant read for the tenant claim, and a persisted delta attributable to the probe.
- **Verification:** All three verifiers confirmed. The existing tests never exercise this shape.

#### C-7 — `prove.differential` in boolean mode confirms `sqli` for any parameter whose value changes the response
- **Category:** correctness (proof kernel)
- **Location:** [src/server/proof-receipt.ts:1583-1612](../src/server/proof-receipt.ts#L1583), [src/server/oracle-invariants.ts:1989-2058](../src/server/oracle-invariants.ts#L1989)
- **What's wrong:** Every `structural_diff` claim on which `deriveDifferingParam` finds one differing query parameter becomes `vulnClass: 'sqli'`, which the `boolean` rule then checks. `assessBooleanDifferential` checks only: no 5xx, the same masked request shape, stable signatures, and a non-echo structural delta. It never requires a predicate construct or a third arm that is true-equivalent to the control. The status_differential rule does require that triangle. `requestShape` drops Authorization/Cookie, so a difference in persona is invisible to it.
- **Evidence:** `handleProveDifferential` accepts two independent worker arms (verify-prove-handlers.ts:391-411). evaluateClaims counts any passing structural_diff as injection evidence (verify-claims.ts:1806-1812). `persistAgentScriptProof` stores the receipt class as the claim.
- **Impact / failure scenario:** A filter such as `category=books` returning a short list, compared with a category that does not exist returning an empty list, is persisted as runtime-confirmed SQL injection on ordinary list and search endpoints, and the false positives scale with the number of such endpoints. The prompts steer injection specialists to this helper.
- **Recommendation:** Require three arms on the same route, method and persona: a baseline, a true-equivalent predicate that matches the baseline, and a false predicate that differs, with predicate syntax the host recognises. Add the persona to `requestShape`. Stop hard-coding `sqli`.
- **Verification:** All three verifiers confirmed. One corrected the claim that a persona-only difference triggers it: a query parameter must also differ, which is trivial to arrange.

#### C-8 — DOM-XSS oracle treats a canary substring in any sink argument, or a surviving marker element, as code execution
- **Category:** correctness (proof kernel)
- **Location:** [src/server/scoped-browser.ts:578-589](../src/server/scoped-browser.ts#L578), also [:2447-2464](../src/server/scoped-browser.ts#L2447), [:3346-3362](../src/server/scoped-browser.ts#L3346), [floor-recipe-engine.ts:675-692](../src/server/floor-recipe-engine.ts#L675), [floor-recipes.ts:1419-1450](../src/server/floor-recipes.ts#L1419), [proof-receipt.ts:429-443](../src/server/proof-receipt.ts#L429)
- **What's wrong:** `recordSink` sets `containsCanary` on any value passed to the hooked innerHTML/outerHTML setters, document.write, eval/Function, location setters or postMessage when that value contains the canary token. The token is alphanumeric plus hyphens, so it survives escaping. The snapshot also counts any element whose id or data attribute holds the token. `browserSessionSeam` turns either signal into `sinkHit`. The `browser_sink` recipe has an optional control arm, and the kernel `browser` rule confirms when any trace has a sink. The recipe's jq replay check is hard-coded to `confirmed: true`.
- **Evidence:** Live through the strict-strangler path (deterministic-engine.ts:5273). One verifier noted that `args.canaryToken` can be chosen by the agent when the spec carries a recipe envelope (see H-5).
- **Impact / failure scenario:** Apps that write escaped input into innerHTML, sanitize with DOMPurify (which keeps id and data-* attributes), or postMessage the query string get a `dom_xss` finding confirmed deterministically. The agent can also steer toward these sinks on purpose.
- **Recommendation:** Count only execution evidence, such as a host-minted callback invoked from an isolated world with a nonce the page cannot read. Treat substring and marker hits as HTML-injection leads, not confirmations. Make the control arm mandatory.
- **Verification:** Three verifiers confirmed. One rated it high because framework text bindings are not hooked. Kept critical because the false "confirmed" is accepted by the kernel.

### High

#### H-1 — Kill-switch endpoint trips a different `GlobalKillSwitch` instance from the one the broker reads
- **Category:** reliability
- **Location:** [scripts/serve.ts:208](../scripts/serve.ts#L208) (import at :8, `main()` at :507-521), [src/server/broker.ts:1737](../src/server/broker.ts#L1737), [src/server/kill-switch.ts:354-358](../src/server/kill-switch.ts#L354)
- **What's wrong:** serve.ts imports `globalKillSwitch` from source. `main()` loads the Vite SSR bundle, which inlines its own copy of kill-switch.ts, and the bundle's broker uses that copy. `configureGlobalKillSwitch` has no callers, so neither instance has file or DB backing that could sync them.
- **Evidence:** `execution.ts:183-190` builds the broker without a `killSwitch`. The tests pass an explicit instance and a stub app, so they never see the split.
- **Impact / failure scenario:** POST /api/ops/kill-switch returns `active:true` and GET reports the switch as tripped, but brokered egress and in-flight requests continue. This breaks the "nothing after kill-switch" contract and the M4 gate of under 2 s.
- **Recommendation:** Export the bundle's instance and pass it to `createKovoLocalServer`, or configure shared DB/file backing in both module graphs. Add an end-to-end test against `build/server`.
- **Verification:** Three verifiers confirmed. Caveat: no `build/` directory exists in the worktree, so the duplicate-module conclusion rests on standard Vite SSR inlining of relative imports.

#### H-2 — Kill-switch scope model fails open: tenant trips match no grant, a tenant trip overwrites a global one, no persistence, and non-broker egress
- **Category:** reliability
- **Location:** [src/server/kill-switch.ts:126-131](../src/server/kill-switch.ts#L126) and [:265-293](../src/server/kill-switch.ts#L265), [src/server/execution.ts:1061](../src/server/execution.ts#L1061), [scripts/serve.ts:362-388](../scripts/serve.ts#L362), [src/server/persona-auth.ts:2962-2985](../src/server/persona-auth.ts#L2962), [src/server/verify-rpc.ts:1291](../src/server/verify-rpc.ts#L1291)
- **What's wrong:** (a) No production grant sets `tenantId`, so every broker check passes `null`, and `matchesScope` returns false for any tenant-scoped trip. (b) `trip()` replaces the single state slot, so a tenant trip lifts an active global trip, and `reset()` ignores tenantId while the audit row records a "tenant" scope. (c) `configureGlobalKillSwitch` is never called, so state lives only in memory. A restart clears it and `requeueInterruptedAssignments` resumes the work. (d) Persona refreshers (pinned fetch/Playwright), the HTTP/2 verify client and agent loops never consult the switch, and nothing subscribes to `onChange`. (e) When a global state is adopted over an active tenant trip in `syncFromExternal`, in-flight requests are not aborted.
- **Evidence:** `grep tenantId` finds nothing in execution.ts or exec-*.ts. Only broker.ts and serve.ts import kill-switch.
- **Impact / failure scenario:** An operator who trips the switch for one tenant halts nothing. An operator who adds a tenant trip after a global trip resumes all egress while the API reports active. Persona logins and refreshes keep reaching the IdP or target after any trip.
- **Recommendation:** Store a global flag plus a set of tripped tenants. Set `grant.tenantId` from `getRunTenant`, or reject tenant trips. Configure persistence at startup. Subscribe Execution to pause runs and stop refreshers. Bind persona-auth fetches and the http2 client to the switch.
- **Verification:** Merged from five findings (medium to high). Up to three verifiers each confirmed. Some downgraded to medium because only an operator can trigger it. Kept high because a documented emergency control silently fails open under realistic operator use.

#### H-3 — `prod_readonly`/staging contract treats any POST with a GraphQL-shaped JSON body as read-only, on any path and at Tier 1; escaped duplicate keys get past the parity guard
- **Category:** security
- **Location:** [src/server/scope-policy.ts:279-291](../src/server/scope-policy.ts#L279) and [:402](../src/server/scope-policy.ts#L402), [src/server/scope-policy.ts:205-214](../src/server/scope-policy.ts#L205), [src/server/broker.ts:2735-2765](../src/server/broker.ts#L2735)
- **What's wrong:** The JSON-envelope branch of `isVerifiedReadOnlyGraphqlQuery` never checks the path or content type. `evaluateScopeRequest` allows the request before the `prod_readonly` deny and before the staging denylist. The broker then sets `contractApproved`, skips the Tier<3 method gate through `verifiedGraphqlRead`, and skips the approval block entirely. Separately, `topLevelJsonKeys` (here and in approval-judge.ts:452-455) does not decode `\uXXXX` escapes. A duplicate `query` key written with an escape therefore escapes the duplicate check, and JSON.parse's last-wins result is classified as read-only.
- **Evidence:** In-memory probes reproduced both cases: an envelope POST to a cancel-style REST path returned allowed=true, and the escaped duplicate returned true while the plain duplicate returned false. Public projects default to `prod_readonly`, and method-override headers are not forbidden.
- **Impact / failure scenario:** On every default public project the agent can send unapproved state-changing POSTs to body-ignoring action routes (cancel, logout, purge), add a method-override header to turn them into another verb, or reach routes the operator denylisted in staging.
- **Recommendation:** Require an operator-declared or recon-confirmed GraphQL endpoint (path plus content type) for both branches. Decode key escapes before duplicate detection. Check the staging denylist first. Strip or escalate method-override headers.
- **Verification:** Merged from four findings: two from the fail-open area and two from prior-audit status (a new variant of prior item 8 and the idempotent-POST bypass). Every verifier confirmed. Stays high, not critical: egress stays in scope, and the harm depends on how the target endpoint treats the body.

#### H-4 — Batch/race approval evaluates only the first ("primary") request but grants single-use approval to every other distinct request
- **Category:** security
- **Location:** [src/server/execution.ts:1416-1435](../src/server/execution.ts#L1416) and [:1602/:1709](../src/server/execution.ts#L1602), [src/server/tier3-approval.ts:98-121, 211-258](../src/server/tier3-approval.ts#L98), [src/server/approval-judge.ts:340-375](../src/server/approval-judge.ts#L340)
- **What's wrong:** `planTier3ApprovalTargets` takes the first non-read-only request as primary, in the order the agent chose. Only the primary goes through structural escalation (DELETE/multipart/compressed/oversize), the benign fast path and the judge. On approve, `registerStateChangeGrant` writes ledger grants for every additional target. On retry, the ledger consume path is not gated on `hardEscalation`, so a granted DELETE or multipart request is sent. The race-burst card shows only `sample: requests[0]`.
- **Evidence:** `request_http_batch` accepts 2–10 arbitrary requests. An unauthenticated empty-body POST primary passes the zero-LLM fast path.
- **Impact / failure scenario:** In `ephemeral_lab` mode (the default for local-lab projects, and selectable by the operator for public projects) on non-auto-approved origins, a model-built batch sends DELETE or multipart requests without the documented human escalation.
- **Recommendation:** Evaluate every distinct fingerprint and escalate if any is escalated. Show every target to the judge and the human. Never grant targets the decision did not cover.
- **Verification:** Merged with the prior-audit status variant (rated medium). Four verifiers confirmed. One downgraded because the reach is limited to ephemeral_lab. Kept high because the untrusted agent can trigger it and it defeats a documented hard escalation.

#### H-5 — Model-supplied `recipe`/`agentScript` envelopes are executed by the kernel with model-chosen arguments; a `static_ast_proof` carrier skips scope, denylist and Tier-0 checks
- **Category:** security
- **Location:** [src/server/replay-verifier.ts:206](../src/server/replay-verifier.ts#L206) and [:930-941](../src/server/replay-verifier.ts#L930), [src/replay-spec.ts:256-260](../src/replay-spec.ts#L256), [src/server/agent-session.ts:2443/2571](../src/server/agent-session.ts#L2443), [src/server/floor-recipes.ts:607-611](../src/server/floor-recipes.ts#L607)
- **What's wrong:** `replayBase` declares optional `recipe` (with free `args`) and `agentScript`, and model intake keeps both fields. `verifyReplaySpecInner` dispatches `persistedRecipeOf(spec)` without checking that the host minted it. For `static_ast_proof` the origin list is empty, and the denylist and Tier-0 checks are skipped, but the recipe still runs live traffic. Recipe args set the actor role and tenant the oracle trusts, the receipt class, and independent control and probe paths. At retest time, `retestReplaySpec` prefers the envelope over the verified DSL, so a failing planted script maps to `dismissed`, then to `fixed`, and passes patch Gate 6. `update_proposed_finding` has no kovo_verify redirect at all.
- **Evidence:** No code strips these fields. The timing rule compares only max durations, so a fast control route paired with a slow probe route confirms `blind_sqli`.
- **Impact / failure scenario:** A prompt-injected agent gets `static_verified` or runtime-confirmed findings with forged actor metadata, or makes real findings retest as "Verified fixed" and pass Gate 6 with no code change.
- **Recommendation:** Treat `recipe`/`agentScript` as host-only. Strip them at every model-facing parse, and store host envelopes in a separate column. Re-derive actor role and tenant from the vault. Refuse recipe dispatch for static carriers. Have retest replay only the primitive the host recorded.
- **Verification:** Merged from two findings. Six verifiers confirmed. Bounded below critical because the broker still enforces scope and approvals, and in production the static path yields `static_verified`.

#### H-6 — OOB evidence is not bound to the mint, run or attempt: a stale or foreign canary token satisfies an OOB claim in both "fresh" runs
- **Category:** security
- **Location:** [src/server/verify-rpc.ts:1531-1573](../src/server/verify-rpc.ts#L1531), [src/server/verify-claims.ts:1356-1382](../src/server/verify-claims.ts#L1356), [src/server/canary-broker.ts:1570-1612](../src/server/canary-broker.ts#L1570), [src/server/oob-relay.ts:718-752, 1035-1050](../src/server/oob-relay.ts#L718)
- **What's wrong:** `oob wait`/`subscribe` accept any token and sign `{kind:'oob-mint', token, hit}`. `checkCanary` reads in-memory hits by token only (process-global, with no run filter). The `oob` claim accepts any `op:'oob'` record and re-checks liveness without a runId. The fingerprint is `{expectHit}` plus the token, so a fixed token agrees across both attempts. The relay `subscribe` and `matchesSubscription` do not check the run, so one run can claim another run's late callback.
- **Evidence:** Tokens from exploration are returned to the model (`mint_canary` tool). `appendHit` stores hits for tokens that were never minted. In the composite path, `buildHostSignedTranscript` turns the WAIT record into a delivered HostOobEvent, and the receipt `oob` rule accepts it when any cited exchange carries the token.
- **Impact / failure scenario:** A token that got a callback during exploration (possibly from a different endpoint) is hard-coded into the verify script. SSRF, XXE or webhook findings are then confirmed on the wrong endpoint without a fresh callback, which defeats I1 for OOB evidence.
- **Recommendation:** Accept only tokens minted in this transcript and nonce. Scope `checkCanary` by run and assignment, and drop unminted tokens. Require the hit time to be later than the mint. Check run binding in relay subscribe and match.
- **Verification:** Merged from two findings (high and medium). Six verifiers confirmed the mechanism. One showed that the single-hop receipt path does not persist an oob-only claim (see H-20), and the composite path was identified as the reachable route.

#### H-7 — HTTP/2 verify path returns target `Set-Cookie` values to the worker unredacted
- **Category:** security
- **Location:** [src/server/verify-rpc.ts:1222-1236](../src/server/verify-rpc.ts#L1222), source at [:1306-1313](../src/server/verify-rpc.ts#L1306)
- **What's wrong:** `executeHttp2` copies raw response headers, and `handleHttp2` returns them and records them through `scrubRecord`. That function scrubs only values matching known secrets or patterns, and never applies name-based `redactHeaders` the way the broker does (broker.ts:3536).
- **Evidence:** `redact()` leaves typical express-session and Rails cookie values unchanged because the header name is not part of the string.
- **Impact / failure scenario:** Rotated or newly issued persona session cookies reach the untrusted worker, the model context and the transcript, which breaks I3.
- **Recommendation:** Apply `redactHeaders` to HTTP/2 responses, or route the op through the broker (fixing C-1 fixes this too). Seal new session cookies.
- **Verification:** Three verifiers confirmed. Caveat: the worker cannot replay the cookie directly, because cookie and authorization headers are blocked.

#### H-8 — Raw secrets are live in browser pages (mirrored jar cookies, seeded persona storage), and several result fields skip `redact()`
- **Category:** security
- **Location:** [src/server/scoped-browser.ts:916-939](../src/server/scoped-browser.ts#L916), [:1879-1881, 2620-2622, 3497-3499](../src/server/scoped-browser.ts#L1879), [src/server/exec-worker-runner.ts:765-777](../src/server/exec-worker-runner.ts#L765)
- **What's wrong:** `mirrorJarCookies` adds raw, non-HttpOnly jar cookie values to the browser context. Pooled contexts seed persona storage. `forms[].action`, `inputNames`, `cookieNames` and the storage key lists are returned unredacted. The model-boundary scrub does not include broker-registered `jar:` secrets, and `stageJsonArtifact` stages the raw payload into the worker.
- **Evidence:** The docstring at :913 says the values never enter results, but page script can copy them into any of those fields. Re-encoding by page script also defeats literal redaction.
- **Impact / failure scenario:** A reflected or stored XSS on a lab target (present by construction) copies a session cookie or persona token into a storage key. The next browser visit hands the raw credential to the model.
- **Recommendation:** Redact every string field of browser results (`redactJsonValue`). Mirror opaque placeholders that the broker swaps back on the wire, not raw values. Add jar secrets to the session scrub.
- **Verification:** Three verifiers confirmed. One downgraded to medium because the persona-token case is caught by the final scrub; jar cookies are not.

#### H-9 — Values the worker seals become run-wide redaction needles that rewrite the transcript bodies the kernel judges
- **Category:** data-integrity
- **Location:** [src/server/derived-custody.ts:197](../src/server/derived-custody.ts#L197) and [:289-300](../src/server/derived-custody.ts#L289), [src/server/verify-rpc.ts:1703, 2115](../src/server/verify-rpc.ts#L1703)
- **What's wrong:** Every sealed value of 4+ characters joins `scrubHistory`, which never shrinks. `rescrubBodies` rewrites stored bodies, and the signed transcript parses JSON from the scrubbed text. Sealing a tenant id defeats `isOwnTenantOnly`, `bled_access_own_tenant_only` and `responseScopedToOwnTenant`. Sealing a key fragment breaks JSON parsing, which disables stub detection. The vault is per run, so one session corrupts evidence for every assignment and every reverify.
- **Evidence:** The skills tell workers to seal IDs (multihop-chains.md:41,47). `deRedactIdentity` restores persona placeholders only.
- **Impact / failure scenario:** An own-tenant read is confirmed as cross-tenant BOLA. Short IDs that are sealed in the normal course of a run corrupt JSON across the whole run.
- **Recommendation:** Build the kernel transcript from raw, host-only bodies and redact only at the worker boundary. Require high entropy and length before a value joins the scrub set. Scope scrub sets to the session.
- **Verification:** Three verifiers confirmed. Other kernel gates still apply, so this weakens defence in depth rather than forging a result alone.

#### H-10 — Re-sealing an existing handle (worker picks `hopReceiptId`/`slot`) forges `value_binding` causal edges
- **Category:** security
- **Location:** [src/server/derived-custody.ts:180-196](../src/server/derived-custody.ts#L180), [src/server/verify-rpc.ts:1680, 1697, 1820](../src/server/verify-rpc.ts#L1680), [src/server/composite-receipt.ts:321-335](../src/server/composite-receipt.ts#L321)
- **What's wrong:** `seal()` allows an existing handle to be overwritten with a new value taken from another exchange, and `jwtSign` does the same. The first exchange keeps the handle in its emitted capabilities. `verifyValueBinding` checks the handle only and never compares the consumed digest with the emitted one. `usesDag` then counts a non-root hop as attacker-derived.
- **Evidence:** `guardVaultAgainstPlaceholderReseal` blocks only placeholder-shaped values.
- **Impact / failure scenario:** Independent findings, or a capability lifted from a privileged exchange, are stitched into a chain the kernel reports as causally bound. This breaks I4/I5.
- **Recommendation:** Make handles immutable, or derive `hopReceiptId` from the host exchange. Require that the consumed digest equals the from-hop's emitted digest.
- **Verification:** Three verifiers confirmed. One rated medium because the worker can already place a control-arm exchange in a hop; re-sealing is a stealthier variant.

#### H-11 — I6 attacker provenance is unenforced in production: no caller sets `attackerPersonas`, `forbiddenShortcutPersonas`, `benchmarkMode` or `requireCleanSessionFlag`
- **Category:** security
- **Location:** [src/server/composite-receipt.ts:469-492](../src/server/composite-receipt.ts#L469), [src/server/exec-worker-runner.ts:1496](../src/server/exec-worker-runner.ts#L1496), [src/server/exec-verify.ts:2271](../src/server/exec-verify.ts#L2271), [composite-receipt.ts:604-606](../src/server/composite-receipt.ts#L604)
- **What's wrong:** `compositeVerifyOptions` is threaded through but never filled in. With no options, only the `owner` role is forbidden, so admin and unlabelled personas are accepted as the attacker at every probe hop. Only `arm==='probe'` exchanges are checked, and the worker chooses the arm, while capabilities from every arm feed `dagCaps`. The cross_surface_pivot oracle hard-codes `isPrivilegedPreSeeded:false`. Mode B's benchmark ban depends on a field the worker sets. `traceProvenanceToAttacker` has no caller, though ARCHITECTURE.md I6 cites it.
- **Evidence:** The tests always pass `attackerPersonas` explicitly. The terminal gate never compares the probe's role with the control's role.
- **Impact / failure scenario:** A 403 for a member control plus a 2xx for an admin probe on the same route is confirmed as broken access control.
- **Recommendation:** Build the options from the grant (lowest-privilege attacker set; admin/owner forbidden). Fail closed when they are empty. Check every exchange that feeds `dagCaps`. Set `isPrivilegedPreSeeded` from the role rank.
- **Verification:** Merged from two findings. Six verifiers confirmed. The single-hop kernel does reject this case; only the composite path is affected.

#### H-12 — I7 bypass: a composite receipt with no `oracleFamily` and a class outside the six families confirms on one 2xx response
- **Category:** security
- **Location:** [src/server/composite-receipt.ts:558-560](../src/server/composite-receipt.ts#L558) and [:672-686](../src/server/composite-receipt.ts#L672)
- **What's wrong:** When no family resolves, `dispatchDefaultV8Oracle` returns null and the heuristic gate applies. `ssrf` and `business_logic` are excluded from `needsStrict`, so a non-stub 2xx probe passes. For strict classes, any 404 on the same normalized route family counts as the denied control, including a 404 for an id that does not exist.
- **Evidence:** One-hop receipts need no edges. `runAgentScriptProof` overrides the verdict once both attempts confirm a composite.
- **Impact / failure scenario:** An `ssrf` finding is confirmed with no OOB event, and the single-hop path routes the same class through the `oob` rule. Broken access control is confirmed from the attacker's own record plus a 404 on a missing id.
- **Recommendation:** Make a resolved family or ProofReceipt rule mandatory for each terminal class. Remove the ssrf/business_logic exclusion. Accept a 404 control only for the same entity.
- **Verification:** Three verifiers confirmed. Two rated high because the transcripts are genuine.

#### H-13 — Impact oracles judge request body, ambient auth, SameSite and oracle events that the script declares, not what the host observed
- **Category:** security
- **Location:** [src/server/verify-claims.ts:932-950](../src/server/verify-claims.ts#L932), [src/server/proof-receipt.ts:1344-1348, 1408-1442](../src/server/proof-receipt.ts#L1344), [src/server/agent-script-proof.ts:137-160](../src/server/agent-script-proof.ts#L137), [src/server/oracle-invariants.ts:1469-1509, 2409-2455](../src/server/oracle-invariants.ts#L1469)
- **What's wrong:** `transcriptImpactStep` sets `actor.auth` from `claim.ambient.kind`. It lets `claim.ambient.sameSite` override the SameSite value the host observed. It sets `requestJson` from `claim.requestBody`, which is never compared with `bodySha256` or `rawRequestBody`. `transcriptToScriptExchanges` never fills `requestBody`, so receipts use the claim values too. `oracleEvents` comes from the claim and passes the `knownOracleEvent` filter.
- **Evidence:** `replay-verifier.ts:235-284` derives ambient auth from the vault, but the claim and receipt paths do not. The composite path does use `prov.rawRequestBody`. The missing-evidence hints tell the model exactly which fields to set.
- **Impact / failure scenario:** A persisted write by a bearer-token persona, plus a foreign Origin header and the declared fields, is confirmed as CSRF. A protected field that changed through a legitimate workflow is confirmed as mass assignment.
- **Recommendation:** Derive auth kind and SameSite from host credential placement and observed Set-Cookie. Use host-recorded request bodies. Treat claim `ambient` and `oracleEvents` as hints only.
- **Verification:** Merged from three findings. Nine verifiers confirmed. The stored-XSS sub-claim is redundant with the passthrough of declared oracle events. Tenant fallback through `actorTenants` is blocked on the receipt path.

#### H-14 — `auth_bypass` receipt guards only the anonymous-control-versus-persona-probe case; sealed capabilities, session jars and higher-privileged probes confirm
- **Category:** correctness
- **Location:** [src/server/proof-receipt.ts:1018-1027](../src/server/proof-receipt.ts#L1018), [:902-914](../src/server/proof-receipt.ts#L902), [:1464-1482](../src/server/proof-receipt.ts#L1464)
- **What's wrong:** The only actor check rejects a null-handle control paired with a persona probe. A token sealed from a normal login and injected through a capability keeps `personaHandle:null`, and so does an anonymous session-jar login. A member control paired with an admin probe also passes. `authBypassRequestDifferential` accepts any difference in headers or query (the query is stripped from the route). The `auth` boundary in the kernel ignores roles.
- **Evidence:** The broker blocks raw Authorization/Cookie from the caller, but the capability and jar paths work. The prompt tells the model to put the "bypass token" in probe options.
- **Impact / failure scenario:** Ordinary authenticated access to `/me`-style endpoints, or normal admin RBAC, is persisted as a CWE-287 authentication bypass.
- **Recommendation:** Reject the claim when the probe's credential came from a host-observed login or a sealed capability, or when the personas differ or the probe ranks at or above the control. Require that the only differential is the forged token.
- **Verification:** Merged from two findings. Six verifiers confirmed and corrected the raw-header path.

#### H-15 — `prove.differential` in timing mode confirms `blind_sqli` when the control and variant hit different routes or personas
- **Category:** correctness
- **Location:** [src/server/proof-receipt.ts:1614-1636](../src/server/proof-receipt.ts#L1614) and [:403-425](../src/server/proof-receipt.ts#L403), [src/server/verify-claims.ts:1384-1430](../src/server/verify-claims.ts#L1384)
- **What's wrong:** The timing branch hard-codes `blind_sqli` and never requires `deriveDifferingParam`, unlike the structural branch. The timing rule compares only maximum durations. The claim layer checks only interleaving and a Mann-Whitney test.
- **Evidence:** Each arm is normalized independently (verify-prove-handlers.ts:406-411).
- **Impact / failure scenario:** A fast endpoint used as control and a legitimately slow export endpoint used as variant (or a heavy page size) gives a confirmed CWE-89 finding.
- **Recommendation:** Require both arms to share route, method and persona and to differ in exactly one named parameter. Add a benign third arm. Derive the class from the declared family.
- **Verification:** Three verifiers confirmed.

#### H-16 — An injection error fingerprint that simply echoes the probe input still confirms
- **Category:** correctness
- **Location:** [src/server/oracle-invariants.ts:2237-2250](../src/server/oracle-invariants.ts#L2237), also [verify-claims.ts:1800-1811](../src/server/verify-claims.ts#L1800)
- **What's wrong:** `assessInjectionImpact` confirms on the first engine-error fingerprint in the probe response that the control lacks. Nothing compares the match with the probe's own path, headers or body, even though the `responseText` doc comment promises this. `verifyEvaluatedExpression` does include a reflection check. evaluateClaims counts any fingerprint as injection evidence.
- **Evidence:** The fingerprint table includes literal tokens that ordinary probe values contain.
- **Impact / failure scenario:** A search or 404 page that reflects its input confirms SQL, template, command, XXE or traversal injection, reproducibly in both runs.
- **Recommendation:** Discard any fingerprint whose matched text, or its decoded form, appears in the host-recorded request.
- **Verification:** One verifier upgraded this from medium to high: it is a realistic precision bypass of the kernel.

#### H-17 — `access_boundary` confirms BOLA/BFLA on any per-request or per-viewer token that differs from the controls; for BFLA the "denied" control is the owner re-reading the same route
- **Category:** correctness
- **Location:** [src/server/oracle-invariants.ts:1287-1296](../src/server/oracle-invariants.ts#L1287), [src/server/floor-recipe-engine.ts:524-535](../src/server/floor-recipe-engine.ts#L524), [src/server/floor-recipes.ts:831](../src/server/floor-recipes.ts#L831)
- **What's wrong:** The `disclosedFingerprints` branch returns satisfied with no denied control, no role differential and no cross-tenant check. It runs before the publicness check and the org-shared guard. Fingerprints include response headers, so a rotating XSRF cookie produces a new one on every response. The authz probe already filters out exactly this kind of noise (probes/authz.ts:333-342). For BFLA GET plans, the denied actor is the owner on the same path, and the control passes on any difference between two owner reads.
- **Evidence:** The only test covers anonymous access to a public route.
- **Impact / failure scenario:** Two members of the same workspace reading a shared object produce a confirmed BOLA. The BFLA receipt claims a denial that never happened.
- **Recommendation:** Require a boundary denial, role differential or cross-tenant relation before this branch. Ignore fingerprints whose field path also appears in a control with a different value. Never use the owner as the denied actor.
- **Verification:** Three verifiers confirmed. Two noted that header-based fingerprints make it worse than reported.

#### H-18 — A confirmed finding's CWE, origin, endpoint and title are never bound to the spec that confirmed it, and stay editable after confirmation
- **Category:** correctness
- **Location:** [src/server/exec-verify.ts:2578-2588](../src/server/exec-verify.ts#L2578), [src/server/exec-worker-runner.ts:1371-1426](../src/server/exec-worker-runner.ts#L1371)
- **What's wrong:** `update_proposed_finding` swaps in a new spec, checking only approved origins. The impact gate is chosen from the new spec's own labels, and unmodelled classes are ungated. The confirmation is written onto `{...findingRow.finding, ...patch}`, which keeps the old CWE, category, title, severity and origin. Title and summary can still be edited after verification.
- **Evidence:** `alignFindingForEvidence` relabels only for a handful of evidence classes. Report and SARIF headlines come from the finding row.
- **Impact / failure scenario:** A pending CWE-89 finding is confirmed by a trivially reproducing spec of a different class and is reported as a confirmed injection.
- **Recommendation:** Derive identity (origin, endpoint, method, CWE, fingerprint) from the verified spec on every confirming write, or reject the write on mismatch. Block edits on confirmed rows.
- **Verification:** Three verifiers confirmed. The portable receipt's vulnClass does reflect the spec.

#### H-19 — Verify Fix retest reports `fixed` when the recipe could not run its control arms (5xx, auth failure, missing trace)
- **Category:** correctness
- **Location:** [src/server/floor-recipe-engine.ts:1149-1153](../src/server/floor-recipe-engine.ts#L1149), [src/server/floor-recipes.ts:1765-1778](../src/server/floor-recipes.ts#L1765), [src/server/agent-script-proof.ts:662](../src/server/agent-script-proof.ts#L662)
- **What's wrong:** Every failure except `recipe_error` maps to `fixed`. `precondition_unsatisfied` is also produced when control arms fail: `entitled_read`, `benign_baseline`, `non_error_arm` on 5xx, `browser_trace` null.
- **Evidence:** A single 5xx or 401 is returned to the recipe as an ordinary exchange. The broker circuit opens only after 5+ errors, at which point the result correctly maps to inconclusive. Hard transport failures also map to inconclusive.
- **Impact / failure scenario:** When persona credentials expire or the target returns intermittent 5xx, findings are recorded as "Verified fixed" in reports, SARIF and the signed bundle.
- **Recommendation:** Map failures of control and harness arms to `inconclusive`, and allow `fixed` only when every control succeeded and the probe arm was refused. Do the same for `oracle_failed`.
- **Verification:** Three verifiers confirmed. One rated medium because the patch gate has its own baseline check and full outages trip the circuit.

#### H-20 — `prove.oob` proofs can never confirm: the receipt builder has no oob branch, and the subscription's artifact rejects every real callback
- **Category:** reliability
- **Location:** [src/server/proof-receipt.ts:1728](../src/server/proof-receipt.ts#L1728), [src/server/verify-rpc.ts:1505-1512](../src/server/verify-rpc.ts#L1505), [src/server/oob-relay.ts:817-823](../src/server/oob-relay.ts#L817), [src/server/canary-broker.ts:1465](../src/server/canary-broker.ts#L1465)
- **What's wrong:** `buildAgentScriptReceipt` returns null for oob claims, and the rejection message misleadingly refers to "mutating boundary readbacks". `prove.oob` subscribes with `artifact: exchangeId`, but the minted URL carries no artifact, so `recordCallback` rejects every callback as `artifact_missing`. Late promotion is also dead because `canaryId` is the token and the label has no origin suffix. Each affected run drains for the full 45 s.
- **Evidence:** Other call sites pass `artifact: ''` and explain why in a comment.
- **Impact / failure scenario:** Every agentic SSRF, XXE or webhook proof is rejected even when the canary was hit. These are false negatives across a whole class, and the repair feedback is wrong.
- **Recommendation:** Add an oob receipt branch using `buildOobReceipt` with host OOB events. Subscribe with `artifact: ''` and the real canary id. Add an end-to-end test.
- **Verification:** Merged from two findings. Six verifiers confirmed. It fails closed, with no false confirmations. The deterministic floor path is not affected.

#### H-21 — The broker-wide `latestScopeRevision` is compared with per-run revisions, so one run's scope re-approval denies egress for every other run
- **Category:** correctness
- **Location:** [src/server/broker.ts:2589-2597](../src/server/broker.ts#L2589) and [:1898-1907](../src/server/broker.ts#L1898)
- **What's wrong:** A single broker serves all runs. A request whose revision is below the global maximum is denied as stale. A higher revision purges every run's jars.
- **Evidence:** Revisions are per run and start at 1 on first approval. `canReviewScope` allows mid-run edits from the UI.
- **Impact / failure scenario:** One mid-run scope edit makes every other run in the process, including runs created later, fail all broker traffic until restart.
- **Recommendation:** Key revision tracking and jar revocation by runId.
- **Verification:** Three verifiers confirmed. It fails closed.

#### H-22 — Persona session pool is keyed by bare handle, so concurrent runs in different projects swap live credentials
- **Category:** security
- **Location:** [src/server/persona-auth.ts:1221-1241](../src/server/persona-auth.ts#L1221), [:2937, 2984](../src/server/persona-auth.ts#L2937), [src/server/execution.ts:1039](../src/server/execution.ts#L1039)
- **What's wrong:** Handles are unique only within a project. `register()` mutates the shared entry in place, and clones read that entry live. Refresh timers from each project rotate the same entry back and forth. Retest clones pick up stale entries from other projects. Nothing ever unregisters an entry.
- **Evidence:** In-memory check: a clone created from project A's bundle returned project B's cookie after B registered the same handle.
- **Impact / failure scenario:** Run A's requests carry project B's session cookies on shared origins, which corrupts authorization evidence (I6). On disjoint origins, A silently loses fresh sessions.
- **Recommendation:** Key entries by (run or project, personaId). Unregister them on run stop.
- **Verification:** Merged from two findings (high and medium). Six verifiers confirmed. The broker reauth path is unwired, so the 401-refresh part of the original claim is not reachable.

#### H-23 — Worker session clones freeze the credential at clone time, so refreshed sessions never reach workers; the 401 reauth path is unwired
- **Category:** reliability
- **Location:** [src/server/session-isolation.ts:27-78](../src/server/session-isolation.ts#L27), [src/server/execution.ts:180-205](../src/server/execution.ts#L180)
- **What's wrong:** For sessions without a bundle (written by the Clerk, Supabase and JSON adapters), `legacyCookie`/`value`/`bundle` come from the frozen `base`. `sessionPath` is dropped, so the file is never re-read. `createBroker` never sets `reauth`, so the broker never retries after a 401.
- **Evidence:** The Clerk session TTL is about 55 s, and assignments run at least 120 s. The file comment claims the opposite.
- **Impact / failure scenario:** Authenticated probes quietly turn unauthenticated during the assignment, giving large-scale false negatives on IDOR and tenant-isolation classes.
- **Recommendation:** Read the live entry lazily inside the clone, and wire `reauth`. Add a rotation test.
- **Verification:** Three verifiers confirmed.

#### H-24 — Pooled browser contexts keep the grant of the first assignment; later crawls are silently denied or run under the wrong grant
- **Category:** correctness
- **Location:** [src/server/scoped-browser.ts:1489-1494](../src/server/scoped-browser.ts#L1489), [:1522-1611](../src/server/scoped-browser.ts#L1522)
- **What's wrong:** The route handler and WebSocket guard capture `grant` when the context is created. Phase-0 recon creates the contexts, then its lease ends, and every later request fails `authorize()` and is aborted. `crawlStateGraph` swallows the error. There is no mutex on the shared `runtime.page`/`active`.
- **Evidence:** Contexts are pruned only on a runId change or LRU eviction.
- **Impact / failure scenario:** For the rest of every run at tier 2 or above, the agentic `crawl_state_graph` returns no pages, so SPA and browser coverage silently disappears.
- **Recommendation:** Read grant, persona and credentials from the per-visit state, and serialize visits per runtime.
- **Verification:** Three verifiers confirmed. One rated medium: the stale grant only ever denies, and assignmentId attribution comes from the per-visit state.

#### H-25 — The stream sanitizer rewrites the model's tool-call arguments, breaking `check_canary`, `kovo_verify` scripts and auth probes
- **Category:** correctness
- **Location:** [src/server/provider-stream.ts:94-104, 147-153](../src/server/provider-stream.ts#L94), [src/server/provider.ts:296-322](../src/server/provider.ts#L296)
- **What's wrong:** Function-call arguments are parsed and sanitized. Any key matching the credential pattern becomes the literal redaction marker, and `redact()` rewrites source-code assignments. pi-ai parses only the sanitized stream, so the host executes the altered arguments.
- **Evidence:** Reproduced: a `check_canary` token became the redaction marker, and a script with a CSRF-token assignment became a syntax error.
- **Impact / failure scenario:** Agentic blind OOB confirmation can never work. Proof scripts and auth probes that use names containing token, secret or password are corrupted, causing systematic false negatives and wasted turns.
- **Recommendation:** Do not apply credential heuristics to model-to-host tool arguments; replace only exact named secrets. Remove `scrub()` from executed code. Add a round-trip test.
- **Verification:** Three verifiers confirmed. It fails closed.

#### H-26 — `firstEventTimeoutMs` acts as a hard deadline on the whole response; the fetch signal aborts the body mid-stream
- **Category:** reliability
- **Location:** [src/server/provider.ts:254](../src/server/provider.ts#L254), also [:438-441](../src/server/provider.ts#L438), [patch-workflow.ts:273](../src/server/patch-workflow.ts#L273), [semantic-audit.ts:609](../src/server/semantic-audit.ts#L609)
- **What's wrong:** `connectSignal` includes `AbortSignal.timeout(firstEventTimeoutMs)` and is passed to fetch, which errors the response body when it fires. The idle reset never touches it. The error is classified as non-failover and is never retried, and usage is not recorded.
- **Evidence:** Empirically, a loopback SSE stream was aborted at the timeout while frames were still arriving (Node v26).
- **Impact / failure scenario:** Turns longer than 120 s are killed deterministically (60 s for patch, 45 s for semantic audit, 30 s for dedupe, 25 s for the judge).
- **Recommendation:** Pass only the total signal to fetch, and enforce the first-event bound with a separate timer that is cleared on the first frame.
- **Verification:** Three verifiers confirmed.

#### H-27 — A run never finalizes after any verification worker ends `failed`: no retry and no terminal path
- **Category:** reliability
- **Location:** [src/server/execution.ts:4247-4253](../src/server/execution.ts#L4247), [:4282-4288](../src/server/execution.ts#L4282), [src/server/exec-verify.ts:2664](../src/server/exec-verify.ts#L2664)
- **What's wrong:** Finalization requires every worker to be complete or canceled. A failed worker also blocks re-creation, because it counts as existing. Nothing requeues failed verification workers; only an operator pause followed by resume does.
- **Evidence:** `verifyBaselineJob`'s `backend.run` call is not wrapped and throws on Docker create or start failure, timeout or parse errors. Canary-listener and replay errors are caught (corrected by verifiers).
- **Impact / failure scenario:** One transient Docker error leaves the run `running`/`verification` indefinitely, with no report.
- **Recommendation:** Treat `failed` as terminal and finalize with a partial report, or requeue a bounded number of times and then mark the finding inconclusive.
- **Verification:** Three verifiers confirmed. One rated medium because the trigger list was too broad.

#### H-28 — An operator-denied or expired Tier-3 approval wedges the run in investigation and verification
- **Category:** correctness
- **Location:** [src/server/execution.ts:1708-1719](../src/server/execution.ts#L1708), [src/server/exec-verify.ts:1656-1668](../src/server/exec-verify.ts#L1656), [src/server/exec-worker-runner.ts:559](../src/server/exec-worker-runner.ts#L559)
- **What's wrong:** Parking clears the lease, and on a deny the worker is set to `failed` while the job still holds the old lease. Every later `check()` throws, so the "inconclusive" branch in verification is dead code. In investigation, the step stays `running` with no requeue. After a restart, parked workers are never resumed.
- **Evidence:** RCE and upload specs always escalate to a human on non-lab targets, and approvals expire after 15 minutes.
- **Impact / failure scenario:** The safety action the operator is meant to use (deny), or an unattended expiry, hangs the run. Recovery needs a manual stop or pause/resume.
- **Recommendation:** Finish the assignment through a lease-free path on denial, and expire parked workers during recovery.
- **Verification:** Three verifiers confirmed. One rated medium because the operator can always stop the run and get a partial report.

#### H-29 — Planner exceptions are swallowed and the planner is rescheduled every ~100 ms with no cap; a provider outage hot-loops forever
- **Category:** reliability
- **Location:** [src/server/execution.ts:3490-3493](../src/server/execution.ts#L3490), [:3328-3333](../src/server/execution.ts#L3328), [src/server/exec-recon-planner.ts:3562-3564, 3740-3752](../src/server/exec-recon-planner.ts#L3562)
- **What's wrong:** There is an empty `.catch`. `roundNo` is bumped before `agentTurn`. Every exit (the wall-clock check, dry rounds, `plannerDoneRound`) sits after the await. Profiles are never disabled, and failed calls cost nothing, so the budget never trips.
- **Impact / failure scenario:** A revoked key or exhausted credits means a real provider request about every 100 ms forever, with SQLite churn and no report.
- **Recommendation:** Count consecutive failures, back off exponentially, emit `planner.failed`, and advance or fail after N failures. Check the wall clock in `driveInvestigation`.
- **Verification:** Three verifiers confirmed.

#### H-30 — Promise chains with unguarded store reads in catch/finally crash the host process when a run is deleted mid-finalize
- **Category:** reliability
- **Location:** [src/server/oob-drain.ts:111-122](../src/server/oob-drain.ts#L111), [src/server/execution.ts:4155-4163](../src/server/execution.ts#L4155), [src/server/store.ts:1633-1662](../src/server/store.ts#L1633)
- **What's wrong:** `scheduleFinalReport`'s `.catch` calls the same throwing `commitFinalReport` again. `storage.run` throws "Run not found". No `unhandledRejection` handler exists, and Node ≥24 terminates on unhandled rejections. `stopRunsBeforeDelete` does not track in-memory drains.
- **Impact / failure scenario:** Stop & Delete during the up-to-45 s OOB drain kills the whole server and every concurrent run.
- **Recommendation:** Make finalizers tolerate a missing run, add a terminal `.catch` to every `void` chain, register a process-level handler, and wait for in-memory work before deleting.
- **Verification:** Three verifiers confirmed.

#### H-31 — Each process's stale-container sweep deletes other processes' idle warm-pool containers, and the pool then hands out a deleted container
- **Category:** reliability
- **Location:** [src/server/worker-backend.ts:1473-1505](../src/server/worker-backend.ts#L1473), [:1181-1194](../src/server/worker-backend.ts#L1181), [:1655-1683](../src/server/worker-backend.ts#L1655)
- **What's wrong:** The sweep filters only by name and by this process's own sets, with no owner, cell or session label. Age comes from the creation time, so recycled idle containers qualify. `take()` does not inspect the container, and `openSession` skips create for pooled names.
- **Impact / failure scenario:** Parallel matrix cells (the default concurrency of 3 with warm workers) lose sessions at random, which skews recall and reliability metrics.
- **Recommendation:** Scope the sweep by owner or session label. Use last-used time. Inspect in `take()` and fall back to a cold create.
- **Verification:** Three verifiers confirmed. One rated medium because each failure is bounded to one assignment.

#### H-32 — Worker- and model-supplied regexes run synchronously on the host event loop with no backtracking limit (ReDoS)
- **Category:** reliability
- **Location:** [src/server/verify-claims.ts:1281, 1314](../src/server/verify-claims.ts#L1281), [src/server/verify-rpc.ts:1650-1656](../src/server/verify-rpc.ts#L1650) and [:1889-1917](../src/server/verify-rpc.ts#L1889), [src/server/floor-recipe-engine.ts:1510-1512, 2575-2578](../src/server/floor-recipe-engine.ts#L2575), [src/replay-spec.ts:52-56](../src/replay-spec.ts#L52), [src/server/replay-verifier.ts:617](../src/server/replay-verifier.ts#L617)
- **What's wrong:** Header and jsonpath `matches` claims have no length limit. `capability.seal` regex and `async.awaitResult` predicates have a 256-character cap or none. Replay-spec `extract` selectors from `from:'regex'` (model-supplied through propose/update) run over bodies up to 2 MiB. The `proofPatterns` heuristic guard misses stacked ungrouped quantifiers. None of this runs in a worker thread or a linear-time engine, and `semantic-audit.ts:391` already has a guard that these paths do not use.
- **Evidence:** Measured: a nested-quantifier pattern took about 6 s on a 27-character subject, doubling with each character.
- **Impact / failure scenario:** One worker script or proposed spec freezes the whole host: every run, SSE, approvals and the kill switch.
- **Recommendation:** Replace free-form regex with structured selectors, or use RE2 / the V8 linear engine or a worker thread with a hard timeout. Cap both pattern and input length.
- **Verification:** Merged from three findings. Nine verifiers confirmed.

#### H-33 — ProgramGraph extraction runs catastrophic-backtracking regexes over untrusted repo content on the host thread
- **Category:** reliability
- **Location:** [src/server/program-graph.ts:485](../src/server/program-graph.ts#L485) (JS method, cubic), [:536](../src/server/program-graph.ts#L536) (Java/Kotlin, about n⁴), [:243](../src/server/program-graph.ts#L243) (`stringLiteralValue`, exponential on backslash runs), [:2370](../src/server/program-graph.ts#L2370) (`HINT_PREFILTER_RE` credential-URL branch, cubic, evaluated twice per build)
- **What's wrong:** Overlapping whitespace or escape alternatives in four regexes run with `matchAll`/`test` over whole files. `extractProgramGraph` is called synchronously from `buildStaticWorkspaceSnapshot` (execution.ts:2075), phase0-recon and exec-recon-planner, with only a size cap of 256 KB to 1 MB.
- **Evidence:** Measured: about 2,000 blank lines took 3.3 s, and 4,000 took 26 s (JS). A 500-whitespace Java file took 21 s, and 1,000 did not finish. About 38 backslashes took 3 s. An 8 KB prefilter line took 15.6 s.
- **Impact / failure scenario:** A small crafted file, or an unlucky generated one, in a scanned repo blocks the host for minutes to forever.
- **Recommendation:** Remove the overlapping quantifiers (details per regex in the source findings), scan line by line with a length cap, and move graph extraction to a bounded worker thread.
- **Verification:** Merged from four findings (three high, one medium). Every verifier reproduced the timings. The backslash case needs crafted content.

#### H-34 — Quadratic regex in `normalizeEphemeralNoise` lets a target block the host on every response comparison
- **Category:** performance
- **Location:** [src/server/probes/context.ts:55-58](../src/server/probes/context.ts#L55) (`responseSimilarity` at :69-71)
- **What's wrong:** An unanchored greedy word-character prefix sits before required keywords, and the regex is applied to the full body before the 4000-token slice. It is called from every probe comparison.
- **Evidence:** Measured: 40 k characters took 2.7 s and 128 KB took about 28 s per body. Several bodies are normalized per probe.
- **Impact / failure scenario:** A hostile in-scope target stalls the shared process for minutes per probe.
- **Recommendation:** Slice input to about 64 KB before normalizing, and anchor the key matcher on a key boundary.
- **Verification:** Three verifiers confirmed. A benign trigger needs long unbroken word runs.

#### H-35 — `jsHarvest` line-number computation is quadratic and runs synchronously on the host during phase-0 recon
- **Category:** performance
- **Location:** [worker/analyzers.ts:325-345](../worker/analyzers.ts#L325) (pass 1 at :444-445), [src/server/phase0-recon.ts:4174, 4299](../src/server/phase0-recon.ts#L4174)
- **What's wrong:** `nodeLine` rescans from offset 0 for every SWC node. The host imports `jsHarvest` directly, for up to 32 bundles per origin.
- **Evidence:** Measured: 475 KB took 47.7 s. Extrapolated, 1 MiB takes about 4 minutes per bundle. Ordinary SPA bundles trigger it with no malicious input.
- **Impact / failure scenario:** The event loop blocks for minutes during recon, which stalls every run.
- **Recommendation:** Build a newline offset table once and binary-search it. Compute line numbers lazily. Move harvesting off the main thread.
- **Verification:** Three verifiers confirmed. The claim about SWC offsets accumulating across calls was refuted.

#### H-36 — A router self-mount or mount cycle grows route paths until the host runs out of memory
- **Category:** reliability
- **Location:** [src/server/program-graph.ts:1394-1420](../src/server/program-graph.ts#L1394), mount recording at [:684-700](../src/server/program-graph.ts#L684)
- **What's wrong:** There are 12 fixpoint passes with no visited-set or ancestor check, and a self-mount always lengthens the base path. Every route copies the full path into `path` and `id`.
- **Evidence:** Measured: 100 self-mounts took 154 MB heap, growing quadratically. A 256 KB file projects to multiple GB.
- **Impact / failure scenario:** One crafted JS file crashes the host process.
- **Recommendation:** Reject self and ancestor mounts, and cap path length and chain depth.
- **Verification:** Three verifiers confirmed. One rated medium because it needs a hostile repo.

#### H-37 — Compose interpolation from a scanned repo resolves against the host's environment and injects the values into the lab container
- **Category:** security
- **Location:** [src/server/compose-parse.ts:810-814](../src/server/compose-parse.ts#L810), [src/server/lab-proxy.ts:445-452](../src/server/lab-proxy.ts#L445), [src/server/lab-runner.ts:857, 1259-1270](../src/server/lab-runner.ts#L857), [src/server/execution.ts:608](../src/server/execution.ts#L608)
- **What's wrong:** `interpolateTree(parsed, options.env ?? process.env)` runs, and `LabRunner` is constructed with no env, so production uses the full host env. Only keys are validated. The same module deliberately rejects `env_file`, so this is a gap in its own design.
- **Impact / failure scenario:** A hostile repo's app echoes host secrets that happen to be in the environment, such as the receipt signing key, the held-out salt or shell cloud tokens. They then flow into model context, evidence and reports.
- **Recommendation:** Interpolate against an empty or operator-allowlisted map, and fail closed on `${VAR}` that has no default.
- **Verification:** Three verifiers confirmed. Downgraded from critical because it needs local-lab mode, a configured compose file and a hostile repo.

#### H-38 — Compose YAML aliases expand exponentially with no size budget, so a ~1 KB document OOMs the host
- **Category:** reliability
- **Location:** [src/server/compose-parse.ts:280-283, 373-386, 595-622](../src/server/compose-parse.ts#L595)
- **What's wrong:** Every alias reference calls `structuredClone`. The limits cap bytes, lines, depth, anchor count and items per sequence, but not the expanded node count. `x-*` keys are parsed in full before they are skipped.
- **Evidence:** Measured: 977 bytes produced 16.7 M leaves in 4.35 s and 467 MB.
- **Impact / failure scenario:** One crafted compose file in a local-lab repo crashes or hangs the host.
- **Recommendation:** Keep a global budget of expanded nodes that counts every alias clone and merge.
- **Verification:** Three verifiers confirmed. One rated medium (opt-in local-lab).

#### H-39 — Post-confirmation variant sweep reads a code-location path the model controls on the host, with no containment, type or size check
- **Category:** security
- **Location:** [src/server/exec-recon-planner.ts:1944-1947](../src/server/exec-recon-planner.ts#L1944), [src/server/exec-worker-runner.ts:1232, 1278-1279](../src/server/exec-worker-runner.ts#L1232)
- **What's wrong:** It calls `readFileSync(join(reposDir, repo, file))` after only `existsSync`. `codeLocationSchema` limits only length, so parent-directory segments are accepted. Code locations survive runtime confirmation and can be attached afterwards through `update_proposed_finding` or the verified-merge path.
- **Impact / failure scenario:** A prompt-injected model points the read at a non-terminating character device or a FIFO, and the host OOMs or hangs. Content exposure is minimal: only a call-signature token is extracted.
- **Recommendation:** Validate code locations at ingest (the repo must be mounted; reject parent segments). Resolve the real path under the repo root, open with O_NOFOLLOW, and require a bounded regular file, or read from `staticSnapshot`.
- **Verification:** Three verifiers confirmed. `semantic-audit.ts` already has the containment check that this path lacks.

### Medium

#### M-1 — A plain operator Approve creates a durable, never-expiring lease that ignores persona and body
- **Category:** security
- **Location:** [src/server/store-runs.ts:1482-1492](../src/server/store-runs.ts#L1482), [:1383-1411](../src/server/store-runs.ts#L1383), [broker.ts:2737-2763](../src/server/broker.ts#L2737)
- **What's wrong:** `decideApproval` grants a lease on the route pattern with no expiry. `leaseAuthorizes` never checks the stored persona. A matching lease skips `isStateChangeApproved` and the DELETE/multipart/RCE escalation. The comment at execution.ts:1707 ("exactly this fingerprint once") is stale.
- **Impact / failure scenario:** Approving one `upload_probe` or `rce_proof` card in `prod_readonly` lets the worker send any body, upload or race burst to that route for any persona, for the rest of the run. No lease revocation command is wired.
- **Recommendation:** Make a plain approve single-use. Have approve-similar create a persona-bound, TTL lease that excludes destructive shapes. Refuse approval of expired cards.
- **Verification:** Three verifiers confirmed. Route-scoped leases are a documented design (better-architecture.md:73), so this was downgraded from high.

#### M-2 — Method-override headers and parameters evade the DELETE escalation, operator patterns and the judge
- **Category:** security
- **Location:** [src/server/approval-judge.ts:554](../src/server/approval-judge.ts#L554), [:346-358, 836-845](../src/server/approval-judge.ts#L346)
- **What's wrong:** Classification uses only `req.method`. Override headers are forwarded, patterns strip the query string, and the judge prompt omits headers.
- **Impact / failure scenario:** On frameworks that honour method override, a POST carrying an override header is approved as a POST and executed as a DELETE.
- **Recommendation:** Normalize the effective method before approval and fingerprinting, or refuse overrides on Tier-3 paths.
- **Verification:** Confirmed by one verifier.

#### M-3 — The safety judge sees only the first 1,200 characters of a body, but its approval grants the full body up to 64 KiB
- **Category:** security
- **Location:** [src/server/approval-judge.ts:836-846](../src/server/approval-judge.ts#L836), [execution.ts:3768-3772](../src/server/execution.ts#L3768)
- **What's wrong:** The preview is truncated without telling the judge. The grant is keyed on the hash of the full body.
- **Impact / failure scenario:** Under auto_review, state-changing fields placed after a benign prefix are never reviewed.
- **Recommendation:** Escalate when the body is longer than the judge window, or send the full body plus its length.
- **Verification:** Confirmed by one verifier. This is a new variant: the prior audit covered only the case above 64 KiB.

#### M-4 — Composite confirmation replaces `verifyScript`'s dual-replay agreement with a match on labels the worker chooses
- **Category:** correctness
- **Location:** [src/server/agent-script-proof.ts:337-418](../src/server/agent-script-proof.ts#L337)
- **What's wrong:** Agreement means only equal `chainId`, `terminalVulnClass` and hop count. The function overrides the verdict and `oraclePassed`, and takes the first confirmed composite from each attempt.
- **Impact / failure scenario:** Two attempts that each confirm different chains are reported as one reproducible finding, which breaks I1.
- **Recommendation:** Compare causal content derived by the host (route family, method, status, edge kinds, terminal oracle). Reject an attempt that confirms more than one composite.
- **Verification:** Merged from two findings. Two verifiers confirmed. Each composite still passes the host checks on its own.

#### M-5 — `syncVerifyArtifactsToLedger` links every sealed capability to the first capability consumed anywhere in the script
- **Category:** correctness
- **Location:** [src/server/exec-verify.ts:1072-1082](../src/server/exec-verify.ts#L1072)
- **What's wrong:** It uses a global `.find`, and never reads the `consumedByExchangeId` map it builds.
- **Impact / failure scenario:** The ledger DAG gets edges that never happened, which misdirects planning and briefs.
- **Recommendation:** Resolve the precondition from the source exchange of the seal.
- **Verification:** Confirmed by one verifier.

#### M-6 — Lab crash recovery is not wired up: `Store.recover` deletes container rows without reaping the containers
- **Category:** reliability
- **Location:** [src/server/store-runs.ts:194-213](../src/server/store-runs.ts#L194), [store.ts:260](../src/server/store.ts#L260), [lab-runner.ts:1021, 1670](../src/server/lab-runner.ts#L1021)
- **What's wrong:** `recover()` deletes `lab_containers` rows and logs "reclaimed". `reclaimPersisted` and `recoverAll` have no production caller. `persistState` skips the JSON record when storage is attached. Runs that fail partway through startup are not recorded in `active`.
- **Impact / failure scenario:** After a crash, lab stacks, networks, volumes and source copies in /tmp leak, and the event log is misleading.
- **Recommendation:** Call `recoverAll` before the rows are deleted, persist the record incrementally, and register partial state.
- **Verification:** Merged from two findings. Two verifiers confirmed. The lab network is internal, so the vulnerable services are not host-reachable.

#### M-7 — Patch Gate 6 permanently mutates the live lab source tree of an active run and never reverts it
- **Category:** data-integrity
- **Location:** [src/server/lab-runner.ts:1522-1585](../src/server/lab-runner.ts#L1522), [patch-workflow.ts:1097-1157](../src/server/patch-workflow.ts#L1097)
- **What's wrong:** The diff is applied in place to the bind-mounted `sanitizedRepoDir`. The proxy is swapped permanently on success. A failed health check reverts only the proxy. No verdict branch restores the tree.
- **Impact / failure scenario:** Later probes and retests in the same run hit an app running an unreviewed LLM patch, and a second patch for the same finding fails with a misleading "withheld".
- **Recommendation:** Build the patched variant from a fresh copy and always restore it in a `finally` block. Serialize patch workflows per run.
- **Verification:** Merged from two findings. Four verifiers confirmed. The temp copy means the user's repo is never touched.

#### M-8 — The verify-RPC socket, token and nonce in /dev/shm are reachable by any local user
- **Category:** security
- **Location:** [src/server/verify-rpc.ts:446-485](../src/server/verify-rpc.ts#L446)
- **What's wrong:** /dev/shm can be listed. The directory is 0711, but file names are fixed. The token and context are 0444 and the socket is 0666. There is no peer-credential check.
- **Impact / failure scenario:** On a multi-user host, a local process can drive scoped requests with persona injection, use the signing oracle, and inject transcript entries.
- **Recommendation:** Use a 0700 per-user runtime directory, chown it to the container uid, and check SO_PEERCRED.
- **Verification:** Confirmed by one verifier.

#### M-9 — Lab `docker build --network none` still lets BuildKit fetch URLs, frontends and base images from the host network
- **Category:** security
- **Location:** [src/server/lab-runner.ts:1124-1146](../src/server/lab-runner.ts#L1124), [lab-proxy.ts:684-726](../src/server/lab-proxy.ts#L684)
- **What's wrong:** Remote `ADD` sources, `# syntax=` frontends and missing `FROM` images are resolved by the daemon. `docker run` does not use `--pull never`. LLM-written patches can edit the Dockerfile and trigger a rebuild in Gate 6.
- **Impact / failure scenario:** A malicious repo or patch makes the daemon fetch arbitrary or internal URLs.
- **Recommendation:** Use an offline locked builder, strip remote sources, add `--pull never`, and allowlist images.
- **Verification:** Confirmed by one verifier, who also found the patch-workflow path. The BuildKit default was assumed, not checked.

#### M-10 — Pausing a run during Phase A permanently skips the rest of the deterministic floor
- **Category:** correctness
- **Location:** [src/server/execution.ts:2516-2519](../src/server/execution.ts#L2516), [:2444](../src/server/execution.ts#L2444)
- **What's wrong:** An aborted lane is still added to `agenticLaneCompleted`, and the key does not change across resume.
- **Impact / failure scenario:** After a budget, breaker or operator pause during Phase A, floor recall is lost with no error shown.
- **Recommendation:** Mark the lane complete only on a clean finish or a verification-driven abort.
- **Verification:** Confirmed by one verifier.

#### M-11 — The Phase-B scheduler ignores the operator's per-run `workerConcurrency` (AIMD goes up to 12)
- **Category:** correctness
- **Location:** [src/server/execution.ts:3205-3226, 3664-3672](../src/server/execution.ts#L3205), [exec-dispatch.ts:1508-1540](../src/server/exec-dispatch.ts#L1508)
- **What's wrong:** The configured value is a ceiling only when it is above the default of 6. AIMD warm-starts at 6. There is no cross-run cap.
- **Impact / failure scenario:** An operator who sets 1–2 workers to protect a fragile target gets 6–12 parallel specialists.
- **Recommendation:** Clamp AIMD to the configured value and share a process-wide token pool.
- **Verification:** Confirmed by one verifier. This is a new variant; the ledger row saying "Static concurrency" is outdated.

#### M-12 — Pending steps whose dependency was circuit-blocked are stranded forever and block completion
- **Category:** reliability
- **Location:** [src/server/store-runs.ts:1079-1102](../src/server/store-runs.ts#L1079), [execution.ts:3314-3315](../src/server/execution.ts#L3314)
- **What's wrong:** Nothing ever unblocks `blocked` steps. `refreshReadyChainSteps` treats only tainted and canceled dependencies as dead, and `anyActive` counts pending steps.
- **Impact / failure scenario:** A 429/5xx trip on one origin leaves dependent cross-origin steps pending, so the run never leaves investigation.
- **Recommendation:** Taint dependents of blocked steps, or unblock them when the circuit clears.
- **Verification:** One verifier confirmed and upgraded this from low.

#### M-13 — Redaction heuristics miss common framework secrets and JSON-quoted Authorization/Cookie headers
- **Category:** security
- **Location:** [src/server/redact.ts:9-15](../src/server/redact.ts#L9), [broker.ts:3518](../src/server/broker.ts#L3518)
- **What's wrong:** The key matcher is suffix-only. Vendor prefix rules are limited. The header rule needs the colon right after the name. Values disclosed by the target never become cap handles on the agent path.
- **Impact / failure scenario:** A .env or config disclosure puts the target's signing, cloud and payment keys in plaintext into the third-party model context and stored artifacts, which breaks I3.
- **Recommendation:** Use token-based key matching, the gitleaks vendor set, and JSON header forms.
- **Verification:** Three verifiers confirmed. All downgraded from high because the secrets belong to the target and Kovo's own secrets stay scrubbed.

#### M-14 — Named persona secrets survive redaction when the target returns them JSON-escaped, HTML-encoded, lowercase-percent-encoded or embedded in base64
- **Category:** security
- **Location:** [src/server/redact.ts:19-31](../src/server/redact.ts#L19), [persona-vault.ts:893-898](../src/server/persona-vault.ts#L893)
- **What's wrong:** Only the raw, uppercase-URI and aligned base64 variants are matched. Cookie values are registered only when they are at least 16 characters.
- **Impact / failure scenario:** A token containing an escaped slash, reflected by a PHP API, reaches the model.
- **Recommendation:** Generate escaped and entity variants, or decode JSON before redacting. Register short cookie values too.
- **Verification:** Confirmed by one verifier. JWT shapes are still caught.

#### M-15 — Editing a model profile's endpoint without re-entering the key sends the stored key to the new endpoint
- **Category:** security
- **Location:** [src/server/model-settings.ts:231-239, 241-255, 257-292](../src/server/model-settings.ts#L231), [src/domain.ts:881-886](../src/domain.ts#L881)
- **What's wrong:** `resolveEffectiveKey` reuses the stored key without comparing the endpoint or protocol. `testModel` exposes this directly.
- **Impact / failure scenario:** Any UI session can read out the "write-only" provider key through Test against a host it controls. An honest provider switch leaks the old key to the new vendor.
- **Recommendation:** Require the key to be re-entered when the endpoint or protocol changes.
- **Verification:** Merged from two findings. Two verifiers confirmed.

#### M-16 — A late exchange for a deleted run poisons the batched writer and stops every Store operation
- **Category:** reliability
- **Location:** [src/server/store-session.ts:1101-1125](../src/server/store-session.ts#L1101), [store.ts:199-209](../src/server/store.ts#L199), trigger [execution.ts:4059-4065](../src/server/execution.ts#L4059), [broker.ts:1211-1225](../src/server/broker.ts#L1211)
- **What's wrong:** On a constraint failure, `flushNow` puts the whole batch back on the queue and rethrows. The Store proxy flushes before every prepare or exec. Recorders bind to a cached run.
- **Evidence:** HTTP aborts are mostly cancelled before recording. Two reachable variants remain: the WebSocket transport resolves on abort and records against the cached run, and the browser timeout signal is not tied to the job.
- **Impact / failure scenario:** After one Stop & Delete during a WebSocket probe, every DB access fails until restart, other runs' exchanges are lost, and artifacts are recreated on disk.
- **Recommendation:** Isolate rows that fail and drop rows for deleted runs. Tombstone runs before deleting them.
- **Verification:** Three verifiers confirmed the poisoning. The trigger is narrower than claimed, so two downgraded from high.

#### M-17 — OOB receipt promotion overwrites an unrelated pending or dismissed finding matched only by (origin, CWE)
- **Category:** data-integrity
- **Location:** [src/server/exec-verify.ts:1561-1595](../src/server/exec-verify.ts#L1561)
- **What's wrong:** The `existing` lookup ignores endpoint, method and parameter. A raw DB update bypasses the repository. The stale `fingerprint_hash` and `replay_spec_id` columns are kept.
- **Impact / failure scenario:** One route's hypothesis is relabelled with another route's carrier, and a later genuine proof is merged into it.
- **Recommendation:** Match on structural fingerprint, route the write through FindingsRepository, or insert a new finding.
- **Verification:** Confirmed by one verifier. "Dismissed" here is a verifier status, not an operator action.

#### M-18 — The production server is built without a Store: receipt export always returns 503 and kill-switch actions are never audited
- **Category:** architecture
- **Location:** [scripts/serve.ts:518-523](../scripts/serve.ts#L518), [:373-397](../scripts/serve.ts#L373)
- **What's wrong:** `main()` omits `store`. Only the tests pass it.
- **Impact / failure scenario:** ProofReceipt export never works, and trips and resets leave no `tenant_audit_log` entry, which breaks I9.
- **Recommendation:** Pass the bundle's Store and add an end-to-end test against `build/server`.
- **Verification:** Confirmed by one verifier.

#### M-19 — "Sign out other devices" does not revoke open SSE streams or an unconsumed bootstrap secret
- **Category:** security
- **Location:** [scripts/serve.ts:442-449](../scripts/serve.ts#L442), [:309-325](../scripts/serve.ts#L309), [src/routes/api.runs.$runId.events.ts:46-71](../src/routes/api.runs.$runId.events.ts#L46)
- **What's wrong:** Rotation changes the token only. Existing streams keep running, and the bootstrap secret stays valid for the life of the process.
- **Impact / failure scenario:** A revoked device keeps receiving run events, and a leaked bootstrap URL still mints an owner session.
- **Recommendation:** Invalidate the bootstrap secret on rotation and close streams tracked per token.
- **Verification:** Confirmed by one verifier. This is a new variant of prior item 3.

#### M-20 — CLI `--local-lab` boots the lab twice through two LabRunners, breaking I11, and auto-approves the second origin
- **Category:** correctness
- **Location:** [scripts/cli.ts:510-543](../scripts/cli.ts#L510), [src/server/execution.ts:608](../src/server/execution.ts#L608), [exec-recon-planner.ts:1408-1470](../src/server/exec-recon-planner.ts#L1408)
- **What's wrong:** The CLI creates its own runner and boots under a throwaway id. `Execution` creates a second runner, and recon boots again under the real run id and adds that origin to scope.
- **Impact / failure scenario:** Two stacks run. Budget and findings are split between them. Stop and patch affect only one stack.
- **Recommendation:** Pass the CLI's runner into Execution, or let the engine own the boot.
- **Verification:** Merged from two findings. Two verifiers confirmed.

#### M-21 — The command-injection nonce oracle treats escaped or encoded reflection as command execution
- **Category:** correctness
- **Location:** [src/server/probes/injection.ts:713-718](../src/server/probes/injection.ts#L713), [deterministic-specs.ts:1783-1786](../src/server/deterministic-specs.ts#L1783)
- **What's wrong:** The rule is "nonce present and exact payload absent", so any transformed reflection passes.
- **Impact / failure scenario:** Pages that escape input produce false command-execution signals and Tier-3 RCE approval cards. No false confirmation, because the kernel gate holds.
- **Recommendation:** Use a split nonce (as rce_proof does) and drop the dead fallback.
- **Verification:** Confirmed by one verifier.

#### M-22 — When the patch reviewer LLM fails, the fallback offline review has a security-closure gate that does nothing
- **Category:** correctness
- **Location:** [src/server/patch-workflow.ts:842-843](../src/server/patch-workflow.ts#L842), [:1064-1067](../src/server/patch-workflow.ts#L1064)
- **What's wrong:** Any reviewer error leads to the deterministic review. Gate 2 checks `diff.includes('+')`, which is always true because of the header. Nothing ties the diff to the code location or to `fixBefore`/`fixAfter`.
- **Impact / failure scenario:** A 429 from the reviewer lets a patch to an unrelated file ship as "Approved" in the report and in SARIF `fixes`.
- **Recommendation:** Return "reviewer unavailable" or draft on error, and check that the diff touches the cited file and turns `fixBefore` into `fixAfter`.
- **Verification:** Confirmed by one verifier.

#### M-23 — The default HMAC key for signed receipt bundles is derived from the workspace UUID, which the UI returns
- **Category:** security
- **Location:** [src/server/receipt-export.ts:255-259, 788-795](../src/server/receipt-export.ts#L255), [store-projects.ts:53-59](../src/server/store-projects.ts#L53)
- **What's wrong:** Unless `KOVO_RECEIPT_SIGNING_KEY` is set (undocumented), the key is sha256 of a constant plus the workspace id.
- **Impact / failure scenario:** Anyone who sees the UI, the DB or a backup can forge bundles that verify, for example with fabricated confirmed findings or retest verdicts.
- **Recommendation:** Generate a random key stored 0600, or default to Ed25519. Mark bundles unsigned when no key exists.
- **Verification:** Confirmed by one verifier. A test locks in the derivable key.

#### M-24 — Unified-diff parsers end a hunk at a removed line that begins with `-- `, so the applied and exported patch differs from the diff
- **Category:** correctness
- **Location:** [src/server/lab-runner.ts:495](../src/server/lab-runner.ts#L495), [sarif-export.ts:316, 341-347](../src/server/sarif-export.ts#L316)
- **What's wrong:** A removed line that starts with `-- ` is read as a file header, and hunk counts are never checked. SARIF also deletes a line for insertion-only hunks.
- **Impact / failure scenario:** SQL-comment files are only partly patched while the report says "Approved", and SARIF fixes corrupt files.
- **Recommendation:** Parse hunks by count, share one tested parser, and emit zero-width inserts.
- **Verification:** Confirmed by one verifier.

#### M-25 — I4/I5 causal edges accept correlation: low-entropy echoed digests, ablations labelled as passing, anonymous ablations
- **Category:** security
- **Location:** [src/server/composite-receipt.ts:332-335, 388-399](../src/server/composite-receipt.ts#L332), [verify-rpc.ts:1096-1098](../src/server/verify-rpc.ts#L1096)
- **What's wrong:** `value_binding` matches any leaf, including booleans, header tokens and path segments. `evidenceRole:'invariant_preserved'`, which the worker sets, turns a 2xx ablation into a passing one. An actor-null ablation skips the actor check.
- **Impact / failure scenario:** Independent requests are stitched into a verified DAG. The two-hop requirement for strict families is satisfied by forged edges.
- **Recommendation:** Require sealed handles or high-entropy body values. Treat `evidenceRole` as a hint. Require that the ablation actor equals the to-hop actor.
- **Verification:** Confirmed by one verifier.

#### M-26 — The legacy single-run DeclarativeReplaySpec confirmation is still reachable through `update_proposed_finding` while kovo_verify is active
- **Category:** architecture
- **Location:** [src/server/agent-session.ts:2504-2519](../src/server/agent-session.ts#L2504), [exec-worker-runner.ts:1371-1446](../src/server/exec-worker-runner.ts#L1371)
- **What's wrong:** Only propose and verify have the kovo_verify redirect. `assertNotRecipeWiredLegacyCall` is called only from deterministic-engine.ts.
- **Impact / failure scenario:** A runtime-confirmed finding is produced without the dual clean replay, including for recipe-wired classes.
- **Recommendation:** Apply the redirect on the host in `executeInlineVerification`, and call the guard there.
- **Verification:** Confirmed by one verifier. This is a new variant of ledger row L432.

#### M-27 — The destructive-payload denylist stops decoding after one malformed escape and never decodes JSON unicode escapes
- **Category:** security
- **Location:** [src/server/broker.ts:855-866](../src/server/broker.ts#L855)
- **What's wrong:** It runs `decodeURIComponent` over the whole string, and the catch branch checks only the plus-decoded variant.
- **Impact / failure scenario:** Under local-lab auto-approval or a permissive policy, encoded destructive statements reach the target.
- **Recommendation:** Decode per component tolerantly, scan JSON string leaves, and escalate content that cannot be decoded.
- **Verification:** Confirmed by one verifier. This is a new variant of the prior audit's scan gaps.

#### M-28 — Raw secrets in the run-scoped capability vault are never released, on disk or in memory
- **Category:** data-integrity
- **Location:** [src/server/execution.ts:1256-1271](../src/server/execution.ts#L1256), [derived-custody.ts:131-148](../src/server/derived-custody.ts#L131)
- **What's wrong:** `capability-vaults/<runId>.json` stores raw values and is not part of `cleanupRunFilesOnDisk`. The in-memory map is never pruned. `revoke` keeps `scrubHistory`.
- **Impact / failure scenario:** Target tokens stay in plaintext after run or project deletion, and memory grows over time.
- **Recommendation:** Delete the vault file and map entry when a run ends or is deleted, and include them in the TTL sweep.
- **Verification:** Confirmed by one verifier.

#### M-29 — A configured egress proxy bypasses the broker's DNS pinning and private-address guard; WebSocket and TLS-inspection traffic skip the proxy
- **Category:** security
- **Location:** [src/server/transport.ts:575-584, 631-644, 1041-1058](../src/server/transport.ts#L575), [:1288-1301](../src/server/transport.ts#L1288), [broker.ts:1553-1566](../src/server/broker.ts#L1553)
- **What's wrong:** HTTP and socks5h proxies get the hostname, not the pinned address. WebSocket sessions, the default WS transport and the TLS inspector dial direct, breaking the module's own rule at transport.ts:646.
- **Impact / failure scenario:** With split-horizon or rebinding DNS, the proxy connects to internal or metadata addresses while carrying persona headers. WS traffic avoids the audited egress path.
- **Recommendation:** CONNECT to the pinned IP literal while keeping SNI. Never use socks5h. Route WS and TLS inspection through `openStream`.
- **Verification:** Merged from two findings (medium and low). Four verifiers confirmed. This requires the opt-in `KOVO_EGRESS_PROXY`.

#### M-30 — The ProofReceipt kernel runs in shadow mode by default, so DSL confirmations persist even when `verifyReceipt` rejects them
- **Category:** correctness
- **Location:** [src/server/floor-recipe-engine.ts:3567-3577](../src/server/floor-recipe-engine.ts#L3567), [replay-verifier.ts:812-820](../src/server/replay-verifier.ts#L812), [exec-verify.ts:1682-1726](../src/server/exec-verify.ts#L1682)
- **What's wrong:** Only `strict` vetoes. Agent-proposed `http_chain` specs for wired authorization classes reach the legacy DSL.
- **Impact / failure scenario:** A finding the kernel disagrees with is still reported as runtime_confirmed, and the only trace is an event row. This contradicts ARCHITECTURE §1.
- **Recommendation:** Make strict the default for agent-origin specs and stamp shadow rejections on the finding.
- **Verification:** Three verifiers confirmed. Downgraded from high because the DSL still runs host-side impact gates and shadow mode is a documented rollout state.

#### M-31 — ZDR mode is enforced inconsistently: UI Markdown and SARIF exports ignore it, and receipt export lets a query parameter turn it off
- **Category:** data-integrity
- **Location:** [src/server/receipt-export.ts:603](../src/server/receipt-export.ts#L603), [scripts/serve.ts:398-402](../scripts/serve.ts#L398), [src/actions.ts:401, 406](../src/actions.ts#L401), [sarif-export.ts:426](../src/server/sarif-export.ts#L426)
- **What's wrong:** `isZdrModeEnabled()` is read only by receipt export, and an explicit `false` overrides it.
- **Impact / failure scenario:** With `KOVO_ZDR_MODE=1`, the main exports still emit PII.
- **Recommendation:** Compute `zdr = env || option` in every exporter.
- **Verification:** Confirmed by one verifier.

#### M-32 — `test:boundaries`, a CI-gated suite, fails on main with 3–4 deterministic failures
- **Category:** testing
- **Location:** [tests/approval-judge.test.ts:103](../tests/approval-judge.test.ts#L103), [tests/boundaries.test.ts:395](../tests/boundaries.test.ts#L395), [tests/v2-upgrades.test.ts:982](../tests/v2-upgrades.test.ts#L982), [.github/workflows/verify.yml:27](../.github/workflows/verify.yml#L27)
- **What's wrong:** The tests drifted after keyword escalation was retired (8d77909) and the confirmation-evidence invariant was added (c673701). The key-name redactor now overwrites the persona placeholder.
- **Impact / failure scenario:** CI is permanently red, so real regressions are hidden, and the dedup and no-downgrade checks after line 982 never run.
- **Recommendation:** Update the tests to the v6 contract, seed confirming evidence, and skip the Docker-only cases when Docker is unavailable.
- **Verification:** Three verifiers confirmed. One verifier counted 4 deterministic failures, including a redirect-auth assertion. Downgraded from high because this is process, not runtime.

#### M-33 — The CI e2e step always fails: the report-benchmark reporter needs attachments that no spec produces
- **Category:** testing
- **Location:** [tests/report-benchmark-reporter.ts:67-74, 132](../tests/report-benchmark-reporter.ts#L132), [.github/workflows/verify.yml:28](../.github/workflows/verify.yml#L28)
- **What's wrong:** `collectReportBenchmark` has no caller since 403505a. `onEnd` returns `failed`, which overrides a green run. `benchmark:reports` greps for a tag no test has.
- **Impact / failure scenario:** UI regressions are hidden behind a step that is always red.
- **Recommendation:** Drop the reporter flag, or make it skip when no snapshots exist.
- **Verification:** Three verifiers confirmed by code trace (Playwright was not run).

#### M-34 — The mandatory worker-gate passes while the CI boundary and security suites fail
- **Category:** testing
- **Location:** [scripts/worker-gate.sh:41-88](../scripts/worker-gate.sh#L41)
- **What's wrong:** The gate omits `boundaries`, `approval-judge`, the `v5-security-*` suites and the kernel suites. The Docker-free subset exists only in `reverify-v5.sh --fast`.
- **Impact / failure scenario:** Trust-boundary regressions (already present at HEAD) merge through the documented gate.
- **Recommendation:** Run the Docker-free security and kernel subset in the gate, or call `reverify --fast`.
- **Verification:** Confirmed by one verifier.

#### M-35 — 187 of 264 test files are run by no script, gate or CI step; 19 Docker-free files fail unseen
- **Category:** testing
- **Location:** [docs/reverify-v5.sh:224](../docs/reverify-v5.sh#L224), [scripts/smoke-multihop.ts:43-48](../scripts/smoke-multihop.ts#L43); examples [tests/v6-scope.test.ts:368](../tests/v6-scope.test.ts#L368), [tests/v8-seam1-golden-e2e.test.ts:605](../tests/v8-seam1-golden-e2e.test.ts#L605), [tests/floor-regress.test.ts:397](../tests/floor-regress.test.ts#L397)
- **What's wrong:** Kernel and scope suites (`arch-c1-verify-kernel`, `v7-proofreceipt`, `v8-seam3-receipt-fuzz`, `v6-scope` and others) are orphaned. Of the 144 Docker-free orphans, 27 tests in 19 files fail, including an SF-C1 golden chain failing with `terminal_impact_unproven` (fixed after the snapshot, in 6190bbf).
- **Impact / failure scenario:** About 70% of the suite gives no signal.
- **Recommendation:** Add a `test:unit` glob to the gate and a CI check that fails on test files no runner references. Triage the 27 failures.
- **Verification:** Confirmed by one verifier, who counted 4 failures in the sampled files.

#### M-36 — Form and OIDC credential browsers pin Chromium to an unvalidated first DNS answer
- **Category:** security
- **Location:** [src/server/persona-auth.ts:2601-2614, 2316-2330](../src/server/persona-auth.ts#L2601), [:757-765](../src/server/persona-auth.ts#L757), [:2443-2446, 2752-2755](../src/server/persona-auth.ts#L2443)
- **What's wrong:** Addresses are pinned before launch without classification, and `MAP host addresses[0]` is used. At request time the check requires only a non-empty intersection with a fresh, classified resolution.
- **Impact / failure scenario:** A DNS answer that lists a private address first at pin time sends the typed persona password to a loopback, LAN or metadata address.
- **Recommendation:** Classify before pinning, pin only validated addresses, and require an exact match.
- **Verification:** Confirmed by one verifier. This is a new variant of prior item 5 / Then #4.

#### M-37 — Tier-3 dead ends: `sqli_time_diff` calls the approval hook without context, and a POST `rce_proof` uses up its only grant at the gate
- **Category:** reliability
- **Location:** [src/server/probes/injection.ts:513-519](../src/server/probes/injection.ts#L513), [floor-recipe-engine.ts:1645-1724](../src/server/floor-recipe-engine.ts#L1645), [broker.ts:2781-2788](../src/server/broker.ts#L2781)
- **What's wrong:** Without context the request is always hard-escalated, and nothing converts the resulting `BrokerApprovalRequired`. The rce_proof gate consumes the grant, and the control and probe fingerprints differ (no `isRceProof`, nonce bodies).
- **Impact / failure scenario:** The probe and floor time-based SQLi path and POST RCE proofs never confirm on public targets, and the operator approves for nothing. The agentic timing helper still works.
- **Recommendation:** Pass full context and route the error through `waitForTier3Approval`, or refuse up front. Register grants for the exact broker fingerprints.
- **Verification:** Confirmed by one verifier. The prior-audit item Then #6 is partially fixed, and the rce_proof part is a new variant.

#### M-38 — WebSockets opened from Web Workers, and all SharedWorker traffic, bypass both the route handler and the WebSocket scope guard
- **Category:** security
- **Location:** [src/server/scoped-browser.ts:441-484](../src/server/scoped-browser.ts#L441), [:395-430](../src/server/scoped-browser.ts#L395)
- **What's wrong:** `routeWebSocket` is a mock that applies to the main world only. Playwright detaches `shared_worker` targets. There is no deny on Worker or SharedWorker.
- **Impact / failure scenario:** A worker socket skips canRead, the wss-only rule, audit and the kill switch. The remaining barrier is the `MAP * ~NOTFOUND` resolver rule, which by Chromium semantics probably also blocks IP literals. That point is unverified.
- **Recommendation:** Deny worker constructors where they are not needed, or force all Chromium traffic through a broker-owned proxy.
- **Verification:** Three verifiers confirmed the bypass. All three downgraded from high because the egress destination is unproven.

#### M-39 — The persona storage seed has no origin guard, so pooled contexts write persona tokens into every origin and frame
- **Category:** security
- **Location:** [src/server/scoped-browser.ts:1527-1528](../src/server/scoped-browser.ts#L1527), [persona-vault.ts:469-482](../src/server/persona-vault.ts#L469)
- **What's wrong:** `storageHydrationScript` has no location check. It is installed once per (run, persona) context and runs in every frame.
- **Impact / failure scenario:** Origin A's storage token is exposed to the scripts of another in-scope origin or an asset iframe, which bypasses `originAllowlist`.
- **Recommendation:** Wrap the script in an origin check, or key pools by origin.
- **Verification:** Confirmed by one verifier.

#### M-40 — Browser redirects are collapsed: content from a broker-followed redirect is fulfilled under the original URL and origin
- **Category:** correctness
- **Location:** [src/server/scoped-browser.ts:1608, 1644-1649](../src/server/scoped-browser.ts#L1608)
- **What's wrong:** `followRedirects:true` is used, then the final hop is fulfilled for the original request. Chromium never sees the 3xx.
- **Impact / failure scenario:** An auth guard that redirects to login appears as a 200 at the protected path, which produces wrong visibility data and false BOLA/BFLA leads. Redirect-target scripts run in the wrong origin's context.
- **Recommendation:** Return 3xx hops to Chromium for navigation requests.
- **Verification:** Confirmed by one verifier.

#### M-41 — A run-wide, claim-once `promoteLate()` in `oob wait` and `awaitReplayCanary` throws away other subscriptions' late promotions
- **Category:** data-integrity
- **Location:** [src/server/verify-rpc.ts:1551-1554](../src/server/verify-rpc.ts#L1551), [verify-support.ts:158, 176](../src/server/verify-support.ts#L158), [oob-relay.ts:1003-1050](../src/server/oob-relay.ts#L1003)
- **What's wrong:** It promotes every pending subscription for the run, keeps only its own, and drops the rest. Promotion is claim-once.
- **Impact / failure scenario:** Late async SSRF and XXE findings are silently lost, depending on timing. This also happens in `--no-llm` Phase-3 replays.
- **Recommendation:** Scope `promoteLate` to the caller's token, or forward all promotions to `convertOobPromotions`.
- **Verification:** Confirmed by one verifier, who found the extra verify-support path.

#### M-42 — Verify Fix retest of `persisted_mutation` recipes is not idempotent, so it reports `fixed` for still-vulnerable deletes and excluded-field writes
- **Category:** correctness
- **Location:** [src/server/floor-recipe-engine.ts:510, 550](../src/server/floor-recipe-engine.ts#L510), [:1149](../src/server/floor-recipe-engine.ts#L1149)
- **What's wrong:** The confirmation consumed its own precondition (a DELETE victim, or no `baselineWrite`). The retest then sees no delta, or a 404, and maps that to `fixed`.
- **Impact / failure scenario:** A false "fixed" is deterministic for privileged object deletes. Other shapes are mitigated by volatile readback fields or by the authz matrix having pre-applied the body.
- **Recommendation:** Restore a known pre-state before retest, and map "pre-read equals probe body" to inconclusive.
- **Verification:** Three verifiers confirmed. Two narrowed it to DELETE and the patch-lab case.

#### M-43 — Cross-tenant `persisted_mutation` confirms on any readback field change, not only the fields the probe wrote
- **Category:** correctness
- **Location:** [src/server/oracle-invariants.ts:679-696, 744-797, 1161](../src/server/oracle-invariants.ts#L1161)
- **What's wrong:** `stateDelta` covers every field and there is no check that the probe actually sent the value. The business-logic assessor has such a check; this one does not.
- **Impact / failure scenario:** A 2xx no-op cross-tenant write, combined with a volatile field (view count, presigned URL), is confirmed as a critical cross-tenant write.
- **Recommendation:** Require that a changed path equals a field the probe wrote, with the written value.
- **Verification:** Confirmed by one verifier.

#### M-44 — The SQLi planner drops form, XML and header carriers and the probed timing style
- **Category:** correctness
- **Location:** [src/server/floor-recipe-engine.ts:257-313](../src/server/floor-recipe-engine.ts#L257), [floor-recipes.ts:962-984](../src/server/floor-recipes.ts#L962)
- **What's wrong:** Only `jsonBody` and `pathAndQuery` are forwarded, so for these locations the control and probe arms are identical requests. The style is ignored, and timing uses one sample per arm.
- **Impact / failure scenario:** Form and header SQLi can never be confirmed. A single latency outlier on identical requests can confirm `blind_sqli`.
- **Recommendation:** Carry `textBody` and headers through, use the probed style, and require several interleaved rounds.
- **Verification:** Confirmed by one verifier.

#### M-45 — Endpoint templating merges distinct static routes and drops the query string, so distinct findings are lost as duplicates
- **Category:** correctness
- **Location:** [src/server/finding-fingerprint.ts:78-85, 135-173](../src/server/finding-fingerprint.ts#L78)
- **What's wrong:** Static segments containing digits (MFA verify/disable, numbered checkout steps, versioned SSO handlers) become `:id`. The query string is stripped.
- **Impact / failure scenario:** A second real vulnerability on a sibling route is rejected or merged.
- **Recommendation:** Template only value positions observed in recon, and keep route-discriminating query keys.
- **Verification:** Confirmed by one verifier, who ran the module.

#### M-46 — `record_coverage` lets the model overwrite host-written `reported` coverage with an unchecked `ruled_out`
- **Category:** data-integrity
- **Location:** [src/server/store-findings.ts:1291-1321](../src/server/store-findings.ts#L1291), [exec-worker-runner.ts:416-442](../src/server/exec-worker-runner.ts#L416)
- **What's wrong:** It upserts unconditionally, and `linkedFindingId` is never validated.
- **Impact / failure scenario:** The coverage matrix and SARIF show a "pass" that contradicts confirmed findings, and proof gaps close.
- **Recommendation:** Never let a worker downgrade host rows, validate the link, and store worker assertions separately.
- **Verification:** Confirmed by one verifier.

#### M-47 — Fact reads are capped at the newest 200, so host `det_lead` facts and a step's own parent facts drop out
- **Category:** reliability
- **Location:** [src/server/exec-worker-runner.ts:689-692](../src/server/exec-worker-runner.ts#L689), [exec-recon-planner.ts:2211, 2437, 2545](../src/server/exec-recon-planner.ts#L2211), [exec-floor-lane.ts:863](../src/server/exec-floor-lane.ts#L863)
- **What's wrong:** Consumers filter an in-memory window of 200 rows. Multi-persona runs write a `persona_resource` fact per new ref.
- **Impact / failure scenario:** Parent facts, Tier-A coverage and older lead upgrades are silently lost as runs grow.
- **Recommendation:** Query by id or kind in SQL.
- **Verification:** Confirmed by one verifier.

#### M-48 — Worker `record_fact` can mint host-only markers (`det_lead`, `hop_checkpoint`, `chain_hop`) that the planner treats as host truth
- **Category:** security
- **Location:** [src/server/store-findings.ts:601-607](../src/server/store-findings.ts#L601), [exec-recon-planner.ts:2542-2600, 2730-2755](../src/server/exec-recon-planner.ts#L2542), [exec-dispatch.ts:488-494](../src/server/exec-dispatch.ts#L488)
- **What's wrong:** The `data` field is free-form, and subkinds are kept. Forged `det_lead` facts queue Tier-A steps at priority 90, change the stop guard and appear in every brief. Forged `hop_checkpoint` facts render as "verified hops" with `doNotRediscover`. Board handoffs can force the fact dependency.
- **Impact / failure scenario:** An untrusted specialist steers planning, wastes budget, and suppresses rediscovery for peers. No false confirmation.
- **Recommendation:** Reserve host-only subkinds and add a `producer` column set by the host.
- **Verification:** Merged from two findings (medium and low). Two verifiers confirmed. The `deterministic_engine_confirmed` suppression was refuted, because "already confirmed" is read from findings.

#### M-49 — The public OOB callback hit store is bounded by count, not bytes, and accepts tokens that were never minted
- **Category:** reliability
- **Location:** [src/server/canary-broker.ts:1336-1363](../src/server/canary-broker.ts#L1336), [:1072-1095](../src/server/canary-broker.ts#L1072), [oob-relay.ts:779-786, 1119-1131](../src/server/oob-relay.ts#L779)
- **What's wrong:** Up to 5,000 × 50 hits of about 20 KiB each are retained, and every request for a minted token rewrites about 200 KiB of JSON. Unminted tokens are stored too, and `oob_rejections` is never pruned.
- **Impact / failure scenario:** When the listener is exposed beyond loopback, a remote sender can OOM the host or grow SQLite without limit.
- **Recommendation:** Add a byte budget, retain minted tokens only, rate-limit per IP, and prune rejections.
- **Verification:** Merged from two findings. Four verifiers confirmed. Downgraded from high because the default bind is loopback.

#### M-50 — The global `oob_callbacks` prune lets one known token flush other runs' unclaimed callbacks
- **Category:** data-integrity
- **Location:** [src/server/oob-relay.ts:1119-1131](../src/server/oob-relay.ts#L1119), [:527-540](../src/server/oob-relay.ts#L527)
- **What's wrong:** The callback id includes the path. Pruning deletes the oldest unclaimed rows across the whole table.
- **Impact / failure scenario:** A hostile target sends about 20 k distinct-path callbacks and evicts other runs' pending late callbacks (false negatives).
- **Recommendation:** Add quotas per token and per run, and never prune tokens with pending subscriptions.
- **Verification:** Confirmed by one verifier.

#### M-51 — `resolveRouteSinkPaths` enumerates every simple path and blows up on cyclic call graphs
- **Category:** performance
- **Location:** [src/server/program-graph.ts:1702-1745](../src/server/program-graph.ts#L1702), [semantic-audit.ts:1619](../src/server/semantic-audit.ts#L1619)
- **What's wrong:** The DFS has no memoization, and `maxPaths` counts only successful paths. Depth is 16.
- **Impact / failure scenario:** A dense mutually recursive cluster hangs the semantic audit on the host thread.
- **Recommendation:** Add a global step budget, or use BFS with memoized best depth.
- **Verification:** Confirmed by one verifier.

#### M-52 — The snapshot call-graph builder has no node or edge cap
- **Category:** reliability
- **Location:** [src/server/semantic-audit.ts:1144-1210](../src/server/semantic-audit.ts#L1144)
- **What's wrong:** Every def or route line becomes a node, with up to about 90 edges per node.
- **Impact / failure scenario:** Dense generated or adversarial files reach GB-scale heap and an OOM crash.
- **Recommendation:** Cap nodes and edges as the ProgramGraph builder does, and warn on truncation.
- **Verification:** Three verifiers reproduced it. The graph is not persisted.

#### M-53 — Quadratic scans over repo content (delimiter matching, line numbers, sink and annotation regexes)
- **Category:** performance
- **Location:** [src/server/program-graph.ts:150-155, 172](../src/server/program-graph.ts#L172), [:430, 521-522, 1034, 1088](../src/server/program-graph.ts#L430), [phase0-recon.ts:357, 368](../src/server/phase0-recon.ts#L357)
- **What's wrong:** `findMatching` runs to end of file when a delimiter is unclosed. `lineNumberAt` rescans from offset 0. Python offsets are re-joined for every def.
- **Impact / failure scenario:** About 5–35 s per worst-case 256 KB file, so a repo of them stalls the host for minutes.
- **Recommendation:** Build a newline index, bound `findMatching`, and compute offsets incrementally.
- **Verification:** Confirmed by one verifier with timings. The Django decorator sub-claim was not reproduced.

#### M-54 — The anchor-harvest regex is quadratic on target HTML up to 2 MB, on every tracked exchange
- **Category:** performance
- **Location:** [src/server/resource-harvest.ts:200-201](../src/server/resource-harvest.ts#L200)
- **What's wrong:** It backtracks unbounded on unclosed anchor tags, and the HTML branch has no size cap.
- **Impact / failure scenario:** A target page stalls the host for minutes per fetch.
- **Recommendation:** Cap the scanned HTML and bound the attribute class.
- **Verification:** Confirmed by one verifier with timings.

#### M-55 — Operator approval patterns still treat verb-like segments as IDs and ignore the query string (prior residual)
- **Category:** security
- **Location:** [src/server/approval-pattern.ts:12-13, 22-32, 51-52](../src/server/approval-pattern.ts#L12)
- **What's wrong:** The prefixed-ID and opaque-token regexes match snake_case verbs and long tokens that contain a digit.
- **Impact / failure scenario:** Approving an item-ID route pre-approves sibling action routes at the same depth (legacy flow only).
- **Recommendation:** Treat only numeric, UUID, hex and placeholder segments as IDs, and include query keys in the pattern.
- **Verification:** Confirmed by one verifier. Prior item 1.3 / Then #7 is partially fixed.

#### M-56 — `isReadOnlySearchPost` still auto-approves state-changing POSTs based on words in the path (prior residual)
- **Category:** security
- **Location:** [src/server/approval-judge.ts:104-108, 512-522, 762-770](../src/server/approval-judge.ts#L512)
- **What's wrong:** A path word plus a body without mutation hint words gives a deterministic approve with no LLM.
- **Impact / failure scenario:** In the legacy flow, a state change on a path containing check or validate runs unapproved. It is also the cheapest primary for H-4.
- **Recommendation:** Remove the heuristic, or limit it to read-only routes the operator declares.
- **Verification:** Confirmed by one verifier. Prior item 8 is still open.

### Low

#### L-1 — The scope contract is evaluated on the raw `pathAndQuery`, while the wire request uses the normalized URL
- **Category:** security
- **Location:** [src/server/broker.ts:2729](../src/server/broker.ts#L2729), [scope-policy.ts:301-332](../src/server/scope-policy.ts#L301)
- **What's wrong:** Dot segments bypass the staging denylist. `authTokenPath` is unanchored and matches inside the query string.
- **Impact / failure scenario:** Latent: auth origins and denylists are populated only by a benchmark script.
- **Recommendation:** Evaluate on `url.pathname + url.search` and anchor the token path.
- **Verification:** Confirmed by one verifier.

#### L-2 — The `staging_isolated` tenant-tag contract is vacuous: the host adds the tag to every mutation, and a substring anywhere satisfies it
- **Category:** security
- **Location:** [src/server/scope-policy.ts:333-346, 415-427](../src/server/scope-policy.ts#L333), [execution.ts:3707-3719](../src/server/execution.ts#L3707)
- **What's wrong:** A tag found anywhere in the headers allows any non-denylisted mutation and skips Tier-3 approval.
- **Impact / failure scenario:** The mode is pre-authorized by design and only a benchmark can set it, so this is latent.
- **Recommendation:** Tie the tag to entities the host created, and keep DELETE and multipart on the approval path.
- **Verification:** Merged from two findings. Three verifiers confirmed.

#### L-3 — Approval retry re-sends a state change that was already sent (redirect target, partially sent batch)
- **Category:** reliability
- **Location:** [src/server/execution.ts:3756-3783](../src/server/execution.ts#L3756), [broker.ts:3478-3486, 3600](../src/server/broker.ts#L3478)
- **What's wrong:** Retry restarts from the original request. Batch items already in flight are re-sent. The first hop's exchange is never recorded.
- **Impact / failure scenario:** A duplicate mutation and an evidence gap. An operator-pattern first hop can be sent twice.
- **Recommendation:** Resume from the redirect hop, and authorize the whole batch before sending any of it.
- **Verification:** Merged from two findings, one of them prior-audit status. Two verifiers confirmed.

#### L-4 — Mode A/Mode B clean-session checks do nothing because every non-control request is recorded as clean
- **Category:** correctness
- **Location:** [src/server/verify-rpc.ts:1148-1151](../src/server/verify-rpc.ts#L1148), [composite-receipt.ts:502-515](../src/server/composite-receipt.ts#L502)
- **What's wrong:** Any 409 from a probe satisfies "Mode-A clean replay failed".
- **Impact / failure scenario:** The Mode-B label is misleading. Mode B is not weaker than Mode A, so no false confirmation results.
- **Recommendation:** Track real session cleanliness and have the host originate Mode-A replays.
- **Verification:** Merged from two findings. Two verifiers confirmed.

#### L-5 — Transcript eviction removes whole records while the raw-body and provenance maps grow without bound
- **Category:** reliability
- **Location:** [src/server/verify-claims.ts:236-243](../src/server/verify-claims.ts#L236), [verify-rpc.ts:1079-1088](../src/server/verify-rpc.ts#L1079)
- **What's wrong:** Records above 512 are evicted, but the raw maps have no cap. Bodies are 2–4 MiB each.
- **Impact / failure scenario:** Host memory grows within an attempt. The guard-bypass part of the original claim was refuted.
- **Recommendation:** Fail the attempt above 512 exchanges and bound the maps.
- **Verification:** Confirmed by one verifier.

#### L-6 — The ledger's I6/I8 enforcement points are never called in product code
- **Category:** architecture
- **Location:** [src/server/capability-ledger.ts:546-554](../src/server/capability-ledger.ts#L546)
- **What's wrong:** `assertPromotable` and `traceProvenanceToAttacker` have no non-test caller, and the composite shortcut uses a bare boolean.
- **Impact / failure scenario:** The documentation overstates enforcement (see H-11).
- **Recommendation:** Wire these functions in or correct the I6/I8 rows.
- **Verification:** Confirmed by one verifier.

#### L-7 — The one-shot IPC directory is world-writable, and the host reads the result pointer following symlinks
- **Category:** reliability
- **Location:** [src/server/worker-backend.ts:487-504](../src/server/worker-backend.ts#L487)
- **What's wrong:** The directory is 0777 with no sticky bit, and `readFileSync` runs before the size and type checks.
- **Impact / failure scenario:** A local user swaps the file for a FIFO or `/dev/zero` and hangs or OOMs the host.
- **Recommendation:** Use 0700 and chown, `O_NOFOLLOW|O_NONBLOCK`, and `fstat` before reading.
- **Verification:** Confirmed by one verifier.

#### L-8 — The M0/I13 fail-fast exists only in benchmark scripts
- **Category:** architecture
- **Location:** [src/server/execution.ts:604-606](../src/server/execution.ts#L604), [exec-recon-planner.ts:1786](../src/server/exec-recon-planner.ts#L1786)
- **What's wrong:** There is no Docker or image preflight in the product. Spawn failures turn into AIMD pressure.
- **Impact / failure scenario:** Model budget is wasted on hosts where Docker is unavailable. I13 is scoped to local-jq, so this is robustness only.
- **Recommendation:** Probe the backend at start, and stop the run after N spawn failures.
- **Verification:** Merged from two findings. Two verifiers confirmed and downgraded.

#### L-9 — LLM usage and cost are never recorded for streams that fail after generating tokens
- **Category:** reliability
- **Location:** [src/server/provider.ts:304-318](../src/server/provider.ts#L304)
- **What's wrong:** `onUsage` runs only on success.
- **Impact / failure scenario:** The USD budget under-counts, and this is systematic together with H-26.
- **Recommendation:** Track usage incrementally and report it in `finally`.
- **Verification:** Confirmed by one verifier.

#### L-10 — The `tenant_audit_log` hash chain is unkeyed and unanchored
- **Category:** security
- **Location:** [src/server/store-session.ts:537-569](../src/server/store-session.ts#L537), [store-runs.ts:2822-2851](../src/server/store-runs.ts#L2822)
- **What's wrong:** It is plain SHA-256 with no head anchor, and the verifier has no production caller.
- **Impact / failure scenario:** Anyone who can write the DB can rewrite or truncate the log undetected, so the I9 claim is overstated.
- **Recommendation:** Use an HMAC with a host key and an external checkpoint, or correct I9.
- **Verification:** Confirmed by one verifier.

#### L-11 — `listRunsForTenant('default')` returns runs that belong to other tenants
- **Category:** security
- **Location:** [src/server/store-runs.ts:2724-2734](../src/server/store-runs.ts#L2724)
- **What's wrong:** The filter is inconsistent with `getRunTenant`, and `createRun` never copies the project's tenant.
- **Impact / failure scenario:** Latent: there is no production caller.
- **Recommendation:** Filter on the effective tenant.
- **Verification:** Confirmed by one verifier.

#### L-12 — The TTL purge deletes evidence of resumable runs and confirmed findings by default
- **Category:** data-integrity
- **Location:** [src/server/artifact-ttl.ts:54-61, 229-246](../src/server/artifact-ttl.ts#L54)
- **What's wrong:** It skips only `running` runs, and `preserveConfirmedEvidence` defaults to false.
- **Impact / failure scenario:** Latent: there is no caller.
- **Recommendation:** Skip all non-terminal runs and preserve confirmed evidence by default.
- **Verification:** Confirmed by one verifier.

#### L-13 — The single-flight GitHub token refresh is bound to the first caller's AbortSignal
- **Category:** reliability
- **Location:** [src/server/github-auth.ts:605-626](../src/server/github-auth.ts#L605)
- **What's wrong:** An abort after GitHub has rotated the token loses the new refresh token.
- **Impact / failure scenario:** The operator has to re-authorize after a cancelled sync.
- **Recommendation:** Detach the refresh signal from callers.
- **Verification:** Confirmed by one verifier.

#### L-14 — The SSE flush drains the whole backlog synchronously and ignores backpressure
- **Category:** performance
- **Location:** [src/routes/api.runs.$runId.events.ts:28-37](../src/routes/api.runs.$runId.events.ts#L28)
- **What's wrong:** `desiredSize` is checked once, then all events are drained.
- **Impact / failure scenario:** A one-time stall and memory proportional to run history on each reconnect.
- **Recommendation:** Re-check `desiredSize` inside the loop, or yield per batch.
- **Verification:** Confirmed by one verifier.

#### L-15 — An unescaped parameter name in a dynamic RegExp can throw and abort the floor
- **Category:** reliability
- **Location:** [src/server/deterministic-engine.ts:2155-2179](../src/server/deterministic-engine.ts#L2155), [phase0-recon.ts:1743](../src/server/phase0-recon.ts#L1743)
- **What's wrong:** `PARAM_NAME_RE` allows an unbalanced `[`.
- **Impact / failure scenario:** A target can blank the floor for a run in staging or lab mode. The error is caught at the lane level.
- **Recommendation:** Escape the name and fix the regex.
- **Verification:** Confirmed by one verifier.

#### L-16 — Exports default `confirmed: true` for composite records with no verification, and include chains created after the report version
- **Category:** data-integrity
- **Location:** [src/server/receipt-export.ts:499](../src/server/receipt-export.ts#L499), [report-export.ts:270, 580](../src/server/report-export.ts#L270)
- **What's wrong:** The default is latent because writers always include the verification. Historical markdown versions show chains confirmed later.
- **Impact / failure scenario:** Report drift.
- **Recommendation:** Default to false, and filter by report `createdAt` and scope revision.
- **Verification:** Confirmed by one verifier, who refuted the reachability of the default.

#### L-17 — The CVE broker sends dependency names to OSV outside the broker, and caches failures for 10 minutes
- **Category:** security
- **Location:** [src/server/cve-broker.ts:409-445](../src/server/cve-broker.ts#L409)
- **What's wrong:** Egress is on by default and bypasses the kill switch. Failed lookups are cached. The cache map is unbounded.
- **Impact / failure scenario:** Private package names leak, and CVE hypotheses are missing after a transient failure.
- **Recommendation:** Make OSV opt-in, and do not cache failures.
- **Verification:** Confirmed by one verifier.

#### L-18 — The I12 contamination lint covers only v8 tokens in `src/server` and `src/skills`
- **Category:** maintainability
- **Location:** [scripts/check-v8-contamination.ts:62-110](../scripts/check-v8-contamination.ts#L62)
- **What's wrong:** It skips `worker/`, templates and `src/*.ts`, and other benchmark suites.
- **Impact / failure scenario:** Coverage gap only; there are no live hits.
- **Recommendation:** Generate the tokens from benchmark manifests and widen the roots.
- **Verification:** Confirmed by one verifier.

#### L-19 — `StateChangeApprovalLedger.prune` passes the new grant's expiry as "now", which wipes all grants
- **Category:** correctness
- **Location:** [src/server/approval-judge.ts:276-310](../src/server/approval-judge.ts#L276)
- **Impact / failure scenario:** At 2,049 outstanding grants, every one-shot approval is discarded. It fails closed and re-escalates.
- **Recommendation:** Pass `Date.now()`.
- **Verification:** Confirmed by one verifier.

#### L-20 — Per-assignment persona clones are disposed only on successful completion
- **Category:** reliability
- **Location:** [src/server/exec-worker-runner.ts:481-485](../src/server/exec-worker-runner.ts#L481)
- **What's wrong:** Failed, canceled, floor-lane and retest paths leak clones and their cookie jars.
- **Impact / failure scenario:** Memory grows over the life of the process.
- **Recommendation:** Dispose in the `finally` that removes the active job.
- **Verification:** Confirmed by one verifier, who found extra leaking paths.

#### L-21 — M4 safety primitives are reported as landed but are not wired into the product
- **Category:** architecture
- **Location:** [src/server/scope-policy.ts:508-615](../src/server/scope-policy.ts#L508), [store.ts:1616](../src/server/store.ts#L1616), [store-runs.ts:311-367](../src/server/store-runs.ts#L311)
- **What's wrong:** The signed scope manifest, TTL purge, origin roles, route denylist and environment mode have no product writer. Approval leases are wired (verifier correction).
- **Impact / failure scenario:** VERIFICATION and HANDOVER overstate M4, and evidence is retained forever.
- **Recommendation:** Wire the primitives, or label them experimental.
- **Verification:** Confirmed by one verifier, who refuted the leases sub-claim.

#### L-22 — Values from the authorized header profile are sent to every origin, never redacted, and missing from recorded exchanges
- **Category:** security
- **Location:** [src/server/transport.ts:78, 114-144, 833-840](../src/server/transport.ts#L833)
- **Impact / failure scenario:** A target that reflects request headers echoes the operator's scanner token. Receipts omit headers that were sent.
- **Recommendation:** Register the values as secrets, apply them to target-role origins only, and merge them before recording.
- **Verification:** Confirmed by one verifier.

#### L-23 — An undocumented second runtime import cycle exists: replay-verifier and replay-feedback
- **Category:** maintainability
- **Location:** [src/server/replay-feedback.ts:17](../src/server/replay-feedback.ts#L17), [replay-verifier.ts:89](../src/server/replay-verifier.ts#L89)
- **Impact / failure scenario:** A latent load-order (TDZ) hazard. ARCHITECTURE.md claims there is only one cycle.
- **Recommendation:** Drop the barrel re-export and add an SCC check to the gate.
- **Verification:** Confirmed by one verifier.

#### L-24 — The `hillclimb-loop` smoke tier exits 0 when the agentic leg was skipped
- **Category:** reliability
- **Location:** [scripts/hillclimb-loop.sh:47-89](../scripts/hillclimb-loop.sh#L47)
- **Impact / failure scenario:** Without Docker, the agentic section is empty but the loop still passes.
- **Recommendation:** Use a non-zero or explicit "skipped" status.
- **Verification:** Confirmed by one verifier.

#### L-25 — The `worker-gate --full` fallback reruns the full gate after a real failure
- **Category:** testing
- **Location:** [scripts/worker-gate.sh:82-88](../scripts/worker-gate.sh#L82)
- **Impact / failure scenario:** Flaky failures are hidden and runtime doubles.
- **Recommendation:** Fall back only on exit 2 or when `newgrp` is missing.
- **Verification:** Confirmed by one verifier.

#### L-26 — Typecheck scope excludes `worker/` and `benchmarks/`; realistic-bench has 4 unseen type errors
- **Category:** maintainability
- **Location:** [tsconfig.json:15](../tsconfig.json#L15), [benchmarks/realistic-bench/tests/grader-misclassified.test.ts:63](../benchmarks/realistic-bench/tests/grader-misclassified.test.ts#L63)
- **Recommendation:** Add `erasableSyntaxOnly` and `tsc -p` steps for the worker and benchmarks.
- **Verification:** Confirmed by one verifier.

#### L-27 — Pooled browser contexts never close popups, so their traffic is attributed to later visits
- **Category:** reliability
- **Location:** [src/server/scoped-browser.ts:1541-1547, 1277-1316](../src/server/scoped-browser.ts#L1541)
- **Impact / failure scenario:** Recon evidence is polluted. The persona cannot differ within a pool key.
- **Recommendation:** Close extra pages on every visit.
- **Verification:** Confirmed by one verifier and downgraded.

#### L-28 — visitPage and the pooled path redact with a secret snapshot taken before navigation
- **Category:** security
- **Location:** [src/server/scoped-browser.ts:1996](../src/server/scoped-browser.ts#L1996), [:1744, 1679](../src/server/scoped-browser.ts#L1744)
- **Impact / failure scenario:** Cookies first set during a visit and logged by the app reach the model. The pooled WS URLs are pattern-redacted only.
- **Recommendation:** Resolve secrets at the point of use and share one route-handler factory.
- **Verification:** Confirmed by one verifier.

#### L-29 — `runBrowserSession`'s handler skips `classifyBrowserHttpRequest`
- **Category:** maintainability
- **Location:** [src/server/scoped-browser.ts:2898-2922](../src/server/scoped-browser.ts#L2898)
- **Impact / failure scenario:** Behaviour drift (no asset hydration in sessions). The broker still enforces scope.
- **Recommendation:** Use one handler for all three paths.
- **Verification:** Confirmed by one verifier.

#### L-30 — Prove-handler gates are advisory: the SDK pushes the claim even when the handler returns `confirmed:false`
- **Category:** architecture
- **Location:** [worker/kovo_verify/kovo_verify.ts:698-787](../worker/kovo_verify/kovo_verify.ts#L698)
- **Impact / failure scenario:** A requested h2 barrier or expected delta is ignored, and the worker is told one thing while the host confirms another.
- **Recommendation:** Encode the requirements in the claim, or record prove verdicts on the host.
- **Verification:** Confirmed by one verifier.

#### L-31 — Confirmed floor findings cite only probe-phase exchanges; the receipt IDs are truncated away
- **Category:** data-integrity
- **Location:** [src/server/exec-floor-lane.ts:1216, 1252](../src/server/exec-floor-lane.ts#L1252), [deterministic-engine.ts:5333](../src/server/deterministic-engine.ts#L5333)
- **Recommendation:** Put the receipt exchange IDs first.
- **Verification:** Confirmed by one verifier.

#### L-32 — Real personas named "guest" or "public" are sent unauthenticated while the recorded step keeps their role and tenant
- **Category:** correctness
- **Location:** [src/server/floor-recipes.ts:1893, 1957](../src/server/floor-recipes.ts#L1893)
- **Recommendation:** Treat only the internal sentinel as anonymous.
- **Verification:** Confirmed by one verifier.

#### L-33 — `verify_replay_spec` accepts any `replaySpecId` in the run and can demote other confirmed findings
- **Category:** data-integrity
- **Location:** [src/server/exec-verify.ts:2448-2450, 2565](../src/server/exec-verify.ts#L2448)
- **Impact / failure scenario:** Latent: the tool is hidden whenever kovo_verify is present, which is always the case in production.
- **Recommendation:** Require that the spec owner equals the finding.
- **Verification:** Two verifiers confirmed the code and downgraded from high because it is not reachable.

#### L-34 — The LLM dedupe judge chooses the merge target, enabling overwrites of pending findings and evidence grafts
- **Category:** data-integrity
- **Location:** [src/server/exec-worker-runner.ts:1209-1320](../src/server/exec-worker-runner.ts#L1209), [dedupe.ts:731-741](../src/server/dedupe.ts#L731)
- **Impact / failure scenario:** Judge mistakes collapse distinct pending findings. There is little added threat beyond `update_proposed_finding`.
- **Recommendation:** Apply structural conflict checks to the judge's choice.
- **Verification:** Confirmed by one verifier and downgraded.

#### L-35 — The agent-proof corroborating dedupe ignores parameter and mutated input, and merges across loopback ports
- **Category:** data-integrity
- **Location:** [src/server/exec-verify.ts:1918-1926, 2080-2122](../src/server/exec-verify.ts#L2080)
- **What's wrong:** The primary fingerprint also omits param, mutated and handler (root cause, per verifier).
- **Recommendation:** Pass those fields to `computeFindingFingerprint`.
- **Verification:** Confirmed by one verifier.

#### L-36 — Relay allowlist and artifact rejections never gate the verdict; a profile allowlist never reaches the relay
- **Category:** security
- **Location:** [src/server/canary-broker.ts:1338-1414, 1179-1188](../src/server/canary-broker.ts#L1338)
- **Impact / failure scenario:** Latent: `startPublicProfile` has no production caller.
- **Recommendation:** Make the relay the only gate.
- **Verification:** Confirmed by one verifier.

#### L-37 — The public TCP DNS listener has no connection cap, idle timeout or backpressure handling
- **Category:** reliability
- **Location:** [src/server/canary-broker.ts:958-977](../src/server/canary-broker.ts#L958)
- **Impact / failure scenario:** Latent: test-only caller.
- **Recommendation:** Add a timeout, `maxConnections` and write backpressure, and allocate the frame once.
- **Verification:** Three verifiers confirmed and downgraded from high.

#### L-38 — The DNS provider is called once per spoofable packet with no limit; a throw in `.catch` becomes an unhandled rejection
- **Category:** reliability
- **Location:** [src/server/canary-broker.ts:929-941](../src/server/canary-broker.ts#L929)
- **Impact / failure scenario:** Latent: the provider is configured only from code.
- **Recommendation:** Restrict to the zone, add a semaphore and timeout, and guard `respond`.
- **Verification:** Confirmed by one verifier.

#### L-39 — The DNS responder answers any zone and opcode (open reflector)
- **Category:** security
- **Location:** [src/server/canary-broker.ts:308-399](../src/server/canary-broker.ts#L308)
- **Recommendation:** Validate opcode and zone, and rate-limit responses.
- **Verification:** Confirmed by one verifier.

#### L-40 — Second-order markers carry 32 bits of entropy and rebind silently across runs
- **Category:** security
- **Location:** [src/server/canary-broker.ts:1493-1508](../src/server/canary-broker.ts#L1493), [oob-relay.ts:704-716](../src/server/oob-relay.ts#L704)
- **Impact / failure scenario:** A brute-forced hit injects false high-priority lead facts. Auto-enqueueing was refuted because the origin is not approved.
- **Recommendation:** Use 96-bit markers and refuse conflicts on insert.
- **Verification:** Confirmed by one verifier.

#### L-41 — Two exec-recon-planner host walkers follow symlinks, and one has no file cap
- **Category:** security
- **Location:** [src/server/exec-recon-planner.ts:599-638, 1957-1985](../src/server/exec-recon-planner.ts#L621)
- **Impact / failure scenario:** Latent: current ingest paths strip symlinks. This is a new variant of prior item 2.
- **Recommendation:** Reuse the snapshot's safe walker.
- **Verification:** Confirmed by one verifier.

#### L-42 — Form and OIDC login browsers still forward with `route.continue()`, so redirects are not re-checked (prior residual)
- **Category:** security
- **Location:** [src/server/persona-auth.ts:2448, 2757](../src/server/persona-auth.ts#L2757)
- **What's wrong:** Playwright calls the handler only for the first URL in a chain.
- **Impact / failure scenario:** IP-literal escape is probably blocked by the resolver rule (verifier correction). A pinned-host http downgrade is still possible.
- **Recommendation:** Fulfil through a guarded fetch with `maxRedirects:0`.
- **Verification:** Confirmed by one verifier and downgraded.

#### L-43 — `isOriginInScope` accepts any port when the allowlist entry uses the default port (prior residual)
- **Category:** security
- **Location:** [src/server/persona-auth.ts:247-249](../src/server/persona-auth.ts#L248)
- **Recommendation:** Compare the effective port.
- **Verification:** Confirmed by one verifier.

#### L-44 — Bootstrap hygiene: the `bootstrap-url` file persists after use and the URL is printed (prior residual)
- **Category:** security
- **Location:** [scripts/serve.ts:111-113, 526-531](../scripts/serve.ts#L527)
- **Recommendation:** Remove the file on consumption and print the file path instead of the URL.
- **Verification:** Confirmed by one verifier.

#### L-45 — Scoped browser contexts still accept downloads (prior residual)
- **Category:** reliability
- **Location:** [src/server/scoped-browser.ts:1512, 2026, 2870](../src/server/scoped-browser.ts#L1512), [persona-auth.ts:2374, 2664](../src/server/persona-auth.ts#L2374)
- **Impact / failure scenario:** Bounded by the broker body cap. Temporary files are cleaned when the browser closes.
- **Recommendation:** Set `acceptDownloads:false` on every context.
- **Verification:** Confirmed by one verifier.

## Critical architectural gaps

These themes group the individual findings above by the structural weakness behind them.

1. **The broker is not the only egress choke point.** ARCHITECTURE §2 says the host owns all egress through RequestBroker. In practice there are at least seven egress paths that bypass some or all broker controls: the verify-RPC HTTP/2 client (C-1, H-7), persona-auth's pinned fetch and Playwright (H-2, M-36, L-42), browser WebSocket and TLS inspection that bypass the egress proxy (M-29), worker and SharedWorker sockets (M-38), the OSV lookup (L-17), and the Docker daemon during lab builds (M-9). Each one re-implements, or skips, scope checks, pinning, the kill switch, redaction and audit. **Direction:** keep one transport, route every outbound byte through `broker.prepare*`, and add a test that greps for `fetch(`, `connect(` and `h2Connect(` outside transport.ts.

2. **The proof kernel trusts fields the worker writes.** The kernel decides "confirmed", but many of its inputs come from the untrusted script rather than host records: oracle operands and booleans (C-4), exchange role and ordering (C-5), `requiredRole`/`resourceTenant` (C-6), request bodies, ambient auth and oracle events (H-13), recipe envelopes (H-5), causal-edge labels and digests (H-10, M-25), arm labels and attacker sets (H-11), composite agreement labels (M-4), and receipt classes hard-coded from claim kind (C-7, H-15). Several oracles also accept substring or fingerprint evidence that reflection can satisfy (C-8, H-16, H-17, M-21). **Direction:** a single rule that every value an oracle reads must come from a host-signed transcript field or a host-resolved persona or credential descriptor. Make claims carry IDs only, and add a test per oracle that mutates each claim field and expects no change in the verdict.

3. **Invariants are enforced in tests and benchmarks, not in the product path.** I6 attacker sets are passed only in tests (H-11, L-6). I13's preflight exists only in benchmark scripts (L-8). I11 is broken by the CLI (M-20). I7 has a heuristic bypass (H-12). I9 has neither a keyed chain nor a production verifier (L-10, M-18). The ProofReceipt kernel runs in shadow mode by default (M-30). Kill-switch persistence is never configured (H-1, H-2). Several M4 primitives are unwired (L-21). ZDR is applied to one exporter only (M-31). **Direction:** every invariant row in §5 should name a production call site, backed by a contract test that drives `Execution`, not hand-built grants or options.

4. **Process-global state is keyed without run, project or owner scope.** The broker's scope revision (H-21), the persona pool by handle (H-22), the canary hit map and relay prune (H-6, M-49, M-50), run-wide `promoteLate` (M-41), the approval ledger prune (L-19), pooled browser contexts that capture the first grant (H-24), the container sweep (H-31), and capability vaults that are never freed (M-28). **Direction:** state shared within a process should be keyed by (runId, owner) by construction. A `RunScoped<T>` helper would make an unkeyed lookup fail to compile.

5. **Untrusted input is processed synchronously on the single host event loop.** Regexes supplied by the worker, model or spec (H-32), repo content (H-33, H-36, M-51 to M-53), target bodies (H-34, H-35, M-54), compose YAML (H-38), and OOB listeners (M-49, L-37, L-38) can each block or OOM the process that also runs the kill switch, approvals and every other run. **Direction:** move parsing and analysis of untrusted bytes into worker_threads with `resourceLimits` and a wall-clock timeout, or into the Docker worker. Ban backtracking regexes on untrusted input (use RE2 or the linear engine).

6. **The orchestration lifecycle has no terminal paths for failure.** A failed verification worker (H-27), a denied approval (H-28), a provider outage (H-29), a deleted run (H-30, M-16), a pause in Phase A (M-10) and blocked dependencies (M-12) each leave runs non-terminal, spinning or wedged. Retest maps "could not run" to "fixed" (H-19, M-42). **Direction:** an explicit state machine where every worker and step state has a timeout and a terminal transition, plus a run-level watchdog that finalizes with a partial report.

7. **Model-writable state can override host-verified state.** Finding labels after confirmation (H-18), coverage rows (M-46), host-only fact markers (M-48), foreign replay specs (L-33), dedupe merge targets (L-34), sealed scrub needles that rewrite evidence (H-9), and code-location paths read on the host (H-39). **Direction:** add a `producer` column (`host` or `worker`) to findings, facts, coverage and specs. The host writes; workers propose.

8. **Gates do not measure what ships.** CI is red (M-32, M-33), the mandatory gate omits the trust-boundary suites (M-34), 70% of test files are orphaned (M-35), and the typecheck and smoke loops have blind spots (L-24 to L-26). **Direction:** one `test:unit` glob in both the gate and CI, plus a check that fails on unreferenced test files.

## Prior audit (2026-11-22) residual status

| Prior item | Status | Evidence (current code at 4f46973) |
|---|---|---|
| 1.1 Tier-3 grant reused across 307/308 redirect | **FIXED** | `authorizeRedirectTarget` broker.ts:3175-3223, called at :3480-3483. Redirect paths recorded. Side effect: the retry re-sends the first hop (L-3). |
| 1.2 Idempotent-POST path predicate | **FIXED** (new variant open) | The predicate is deprecated and no longer consulted (broker.ts:307-312). A new body-shape bypass through the GraphQL envelope check in the contract is H-3. |
| 1.3 Operator pattern over-match | **PARTIAL** | Literal segments must now match and a trailing `*` no longer matches any depth. ID regexes still match snake_case verbs and long tokens, and the query is ignored (M-55). |
| 1.4 Patterns covering RCE when context is omitted | **FIXED** | No context means hard escalation (approval-judge.ts:340-346). |
| 2 Symlink escape (repo/patch) | **FIXED** | `safeResolveUnderRoot` lstats every component, rejects dangling links, and writes with O_EXCL plus O_NOFOLLOW (lab-runner.ts:318-440). A new walker variant is L-41. |
| 3 Bootstrap session | **FIXED** | Pairing tokens are 256-bit, single-use and TTL-bound (serve.ts:223-249). Rotation does not invalidate the bootstrap secret or SSE streams (M-19). |
| 4 Provider host scope / PSL | **PARTIAL** | Vendored PSL, shared-suffix rejection, and form/OIDC now calling `assertCredentialTarget` are all FIXED. Port binding applies only to explicit non-default ports (L-43). The same PSL defect remains in subdomain discovery (C-2, new variant). |
| 5 Credential redirects / SSRF | **PARTIAL** | Node fetch pins validated IPs, empty resolution is refused, `unknown` is no longer treated as safe, and localhost maps to literals: FIXED. NODE_USE_ENV_PROXY now only warns. The CSRF prefetch still reads cookies from a 3xx (STILL OPEN, low; DUPLICATE re-report of #134). Browser pinning is unvalidated (M-36, new variant). |
| 6 Browser egress residuals | **PARTIAL** | The `routeWebSocket` fallback fails closed and WebTransport/QUIC is disabled: FIXED. Downloads are still accepted (L-45). Form-login `route.continue()` and unguarded redirects remain (L-42). Worker and SharedWorker sockets bypass the guard (M-38, new). |
| 7 Lab container | **FIXED** | Numeric uid with root rejected (lab-proxy.ts:162-173). Per-run 0700 telemetry with a byte cap. Residual: no in-run quota (DoS only, not reported). |
| 8 Approval fast paths | **PARTIAL** | Idempotent gate removed. Plain duplicate keys are caught, but escaped duplicates evade both scanners (folded into H-3). >64 KiB and compressed bodies now escalate: FIXED. The path-word heuristic in `isReadOnlySearchPost` is STILL OPEN (M-56). |
| 9 Worker output bounds | **FIXED** | Not re-verified in depth. |
| Top-3 #1 Idempotent-POST bypass | **FIXED** (new variant H-3) | See 1.2. |
| Top-3 #2 307/308 redirect | **FIXED** | See 1.1. |
| Top-3 #3 Registrable-domain widening plus form-login allowlist | **FIXED** | See 4. |
| Then #4 Pin credential connections | **PARTIAL** | Node is pinned. Chromium form/OIDC pins are unvalidated (M-36). |
| Then #5 Dangling-symlink containment | **FIXED** | See 2. |
| Then #6 Restore Tier-3 flows | **PARTIAL** | Race instances, the batch approval path, and the RCE gate context are fixed. Dead ends remain for `sqli_time_diff` and POST `rce_proof` (M-37). The batch fix introduced the primary-only bypass (H-4). |
| Then #7 Tighten patterns | **PARTIAL** | M-55. |
| Then #8 Lab hardening | **FIXED** | The userns-remap docs were not checked. |
| Then #9 Fast-path parity | **PARTIAL** | Size and compression are fixed. Escaped duplicate keys (H-3) and the search-path heuristic (M-56) remain. |
| Then #10 Bootstrap hygiene | **STILL OPEN** | `bootstrap-url` is not removed on consumption, and the URL is printed to stdout (L-44). |

Context: public projects always carry a scopePolicy that defaults to `prod_readonly`, so the legacy ledger, pattern and judge path is reached only in `ephemeral_lab` mode. That lowers the reach of the pattern and search-fast-path items and makes the contract-level checks (H-3) the decisive control.

## Build & test health

- **Typecheck:** `tsc --noEmit -p tsconfig.json` exits 0 with 0 errors (~22 s). Root with `--erasableSyntaxOnly`: 0 errors. `worker/` via an ad-hoc tsconfig: 0 errors. Of the five `benchmarks/*/tsconfig.json`, four are clean and realistic-bench has 4 errors (L-26). No script or CI step runs the benchmark or worker typechecks.
- **`npm run test:boundaries`** (gated in CI): 45 tests, 38 pass, 7 fail, exit 1. Four failures are Docker-socket permission errors in this environment. Three are deterministic drift: keyword escalation retired, the confirmation-evidence invariant, and the key-name redactor overwriting the persona placeholder (M-32). The redaction failure is not a leak, because the raw value is scrubbed.
- **worker-gate pieces:** all pass. v8 contamination rc=0, v7-dispatch-funnel 26/0, v7-confirm-consistency 7/0, v4-m7-orch 26/0, v5-m1-wiring-correctness 30/0, v5-m2-state 10/0. The gate is green while CI is red (M-34).
- **Orphaned tests:** 187 of 264 `tests/*.test.ts` are referenced by no runner (package.json, worker-gate, reverify-v5 including its glob, hillclimb, bench-slice, smoke-multihop tier0, CI). Running the 144 Docker-free orphans gives 125 pass and 19 files with 27 failing tests (M-35).
- **CI e2e:** the custom Playwright reporter fails the run when no spec emits benchmark attachments, and none do (M-33). Not executed; derived from the code.
- **Not run:** Docker, Playwright and network suites, benchmarks. `node_modules` in the audit worktree is a symlink to the primary checkout. The worktree was clean at the end; scratch files went to /tmp only.

## Suggested remediation order

1. **Quick wins, hours each, high leverage:**
   - C-1: strip `:`-prefixed headers in `executeHttp2` now, and route through the broker next.
   - C-3: return only the handle from seal, and enforce a minimum length.
   - C-2: use `registrableDomain()` and admit only the asset host's own subdomains.
   - H-3: require a GraphQL endpoint for the envelope branch, and decode key escapes.
   - H-1: pass the bundle's kill-switch instance to `createKovoLocalServer`.
   - H-26: give fetch only the total signal.
   - H-25: stop sanitizing tool-call arguments with heuristics.
   - H-37: interpolate compose against an empty env.
   - H-20: subscribe `prove.oob` with an empty artifact.
   - L-19: one-line prune fix.
2. **Proof-kernel provenance pass (theme 2):** C-4, C-5, C-6, C-7, C-8, H-5, H-6, H-11, H-12, H-13, H-14, H-15, H-16, H-17, H-18, H-9, H-10, M-25, M-4. Then flip M-30 (strict by default for agent specs).
3. **Kill switch and approvals:** H-2, H-4, M-1, M-2, M-3, M-37, M-55, M-56, L-3.
4. **Host availability (theme 5):** H-32, H-33, H-34, H-35, H-36, H-38, H-39, M-51 to M-54, M-49, M-16, H-30.
5. **Lifecycle and terminal paths (theme 6):** H-27, H-28, H-29, H-19, M-42, M-10, M-12.
6. **Isolation and credentials (theme 4):** H-21, H-22, H-23, H-24, H-31, H-7, H-8, M-13, M-14, M-15, M-28, M-41, M-50.
7. **CI and gate health, in parallel with the above:** M-32, M-33, M-34, M-35, L-24 to L-26. Fix these early so the work above is measured.
8. **Remaining mediums by theme**, then lows, starting with latent items that become live once wired (L-1, L-2, L-11, L-12, L-21, L-33, L-36 to L-38).
