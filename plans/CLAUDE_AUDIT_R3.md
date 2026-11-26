# Kovo Hunter — Claude audit round 3: new critical & high (2026-11-25)

**Method.** This round audited a read-only git worktree pinned at `09a5126` (branch `agents/claude-audit-r3`). Round 1 ([CLAUDE_AUDIT.md](CLAUDE_AUDIT.md)) audited `4f46973`, round 2 ([CLAUDE_AUDIT_R2.md](CLAUDE_AUDIT_R2.md)) audited `98881b4`, and the earlier review is [SECURITY-REAUDIT-2026-11-22.md](SECURITY-REAUDIT-2026-11-22.md). About 71 commits have landed since round 2, and many of them claim to fix R1/R2 IDs. The scope was **new issues only**: regressions introduced by fixes, bypasses of fixes, new code, and pre-existing issues no earlier round reported. Unchanged known issues were not re-reported. The work had three parts:

1. **Hunting.** 14 area hunters covered egress/admission, the proof kernel, custody RPC, auth/browser, the control-plane UI, persistence/migrations, orchestration, repo/patch/host compute, worker/provider, the floor engine, supply chain/CI/deploy, subsystem interactions, secrets in new paths, and a sweep of new modules.
2. **Gap hunting.** 12 critic-driven gap hunters ran over 3 gap rounds. They covered the repo workspace manager, subdomain auto-admission, host-fact credential placement, the WS-17 scoped browser, the provider-key stream scrub, approval/kill-switch admission, OOB relay attribution, composite-receipt cap-actor resolution, oracle-invariants/families/safe-regex, exec-verify identity/supersession, and admission path canonicalisation.
3. **Verification.** Every candidate went to three adversarial lenses: refute/reachability, duplicate/root cause, and severity. A candidate was kept only if a majority upheld it, it stayed critical or high, and it was not a duplicate of R1 or R2.

| Candidates | Kept (C/H) | Downgraded below high | Duplicates of R1/R2 | Refuted |
|---:|---:|---:|---:|---:|
| 35 | 26 | 7 | 1 | 1 |

After merging shared root causes, the 26 kept candidates become **5 critical (R3-C-1..5) and 17 high (R3-H-1..17)** findings. While writing this report, every critical location and 14 of the 17 high locations were spot-checked against `09a5126` with grep/sed. No benchmarks, Docker or network calls were run. In-memory experiments used only pure functions, regexes and fake in-memory sockets. No exploit payload strings appear in this document; probes are described by class.

## Executive summary

Ranked by risk:

1. **One response header can crash the whole host (R3-C-1, regression from `d95922b` r2-ws2-proto-pollute).** The R2-C-2 hardening made `--disable-proto=throw` mandatory in the Docker image and the CLI shebang. Under that flag, Node's lazy `IncomingMessage.headers` getter throws when an upstream HTTP/1.1 response carries a header named after the prototype accessor. Every egress path reads `res.headers` synchronously inside socket callbacks, and no `uncaughtException` guard exists. Any scanned target, recon host, login endpoint or provider can kill every run and the operator UI with one passive response. Resumed runs then re-contact the same host, which gives a crash loop.
2. **The proof kernel still accepts forged "confirmed" verdicts, and four of these bypass fixes that were claimed complete.**
   - **R3-C-2:** business_logic confirms any idempotent update or delete. Readback deltas count `updated_at`/`version` churn, and a stale 404 counts as a second delta. This bypasses the R2-C-7 fix in `b675448` movea-oracle-invar.
   - **R3-C-3:** the kernel request plane is still heuristically credential-redacted, so any reflected value in a secret-named parameter survives the echo strip and confirms injection. This bypasses R2-C-9 in `b46d801` r2-ws3-custody-rpc.
   - **R3-C-4:** the boolean-differential triangle never binds the base value, so endpoints that coerce IDs to integers confirm sqli. This bypasses C-7, also in `b675448`.
   - **R3-C-5:** "host-derived" V8 tenant and scope labels are read from the worker's own request headers and body. This bypasses R2-C-8 in `851327f` movea-waveb-v8 and `7ac5249` fix-audit-proof-a.
3. **The composite kernel's cap-actor resolution launders credentials (R3-H-4, regression from `ae87490` fix-golden-e2e).** A capability actor is mapped to its emitter, or skips the forbidden-persona check through `fromDag`. That lets three things through:
   - an admin bearer kept alongside a member cookie capability,
   - a junk-credential 401 counted as the actor's own denied control,
   - browser or OOB-only root hops.

   All three yield confirmed BFLA/BOLA/privilege escalation. Separately, **R3-H-5** shows the H-13 CSRF fix (`054344e`/`874424b`) ignores the signed wire provenance once any cookie is present.
4. **Approval controls on live targets can still be bypassed (R3-H-1, bypass of R2-H-1 in `fed18e5` movec-egress-admit).** On derived staging_isolated with auto_review, two things count as isolation proof: the host's own staging tag written into JSON bodies, and a method-override carrier placed past the 64 KiB scan window. Either one auto-approves writes with no judge and no operator. **R3-H-9** shows that a `**` glob segment written by the model turns one "Approve similar" click into an origin-wide prefix approval.
5. **Blind custody is still not blind (R3-H-2).** `async.awaitResult` predicates and `prove.differential` stableDelta run on bodies the vault never scrubbed. That gives an unbudgeted membership oracle over reflected sealed values, including the HMAC outputs that R2-C-4 sealed.
6. **New code has credential and isolation gaps.**
   - **R3-H-3:** the browser_session refresher from `f66dcba` opt4-universal-auth runs target JavaScript with raw persona storageState behind an "any public HTTPS" proxy.
   - **R3-H-6:** every Chromium Kovo launches runs with `--no-sandbox`, because Playwright adds it unless `chromiumSandbox: true` is passed. The control recorded as verified in SECURITY-REAUDIT does not exist.
   - **R3-H-7:** Copy-as-cURL and the receipt `commandHint` put worker-chosen paths into shell commands unquoted.
7. **Scope widening re-introduced (R3-H-8, regression from `1d11b32` arch-u1u4-ui-scale / `688cb93`).** Server-authoritative scope ranking pre-selects every discovered host under the seed's registrable apex, which undoes the R2-H-5 host anchor at the consent sheet.
8. **Run wedges and false results at scale.**
   - **R3-H-10:** the H-8 outbound scrub (`9c36ce9`) rewrites provider protocol fields when a 4-character cookie value collides with them, so every agentic call returns 400.
   - **R3-H-11:** the safe-regex chokepoint (`b675448`) misses three pattern classes, and the backstop flag is off under `npm start`.
   - **R3-H-12:** the R2-H-24 graph fix (`98edff7`) left a synchronous host caller in place.
   - **R3-H-14:** the latest merge `09a5126` stamps `provenance:'floor'` on pending proposals, so they are frozen forever.
9. **Evidence and identity integrity.**
   - **R3-H-16:** the default-on StorageMaintenanceController (`5352132`) purges the exchanges behind confirmed findings after 14 days.
   - **R3-H-13:** composite receipts can supersede, and so hide, unrelated confirmed findings.
   - **R3-H-15:** composite findings are filed on the origin the worker declared, not the one actually exercised.
   - **R3-H-17:** the new repo disk quotas (`2d530cc`) are checked only after a full checkout, and they skip anything nested more than 32 directories deep.

**Fix streams that introduced regressions or are bypassable:** d95922b, fed18e5, 851327f, 7ac5249, b46d801, b675448, 054344e, 874424b, ae87490, 9c36ce9, 98edff7, 1d11b32/688cb93, 5352132, 2d530cc, 01b9d4d, c5dd4cc and 09a5126. The scorecard below lists the merges reviewed without C/H findings.

## New critical & high findings

### R3-C-1 — `--disable-proto=throw` turns any upstream header named after the prototype accessor into an uncaught exception that kills the host process

- **Kind:** fix-regression
- **Category:** reliability
- **Location:** [../src/server/egress-gateway.ts#L1187](../src/server/egress-gateway.ts#L1187), [#L1193](../src/server/egress-gateway.ts#L1193). Other sites read `res.headers` the same way, unguarded: egressFetch at [#L738](../src/server/egress-gateway.ts#L738), egressFetchStream at [#L992](../src/server/egress-gateway.ts#L992) and [#L996](../src/server/egress-gateway.ts#L996), the forward proxy at [#L1856](../src/server/egress-gateway.ts#L1856) and [#L1877](../src/server/egress-gateway.ts#L1877), and [../src/server/transport.ts#L1192](../src/server/transport.ts#L1192). The flag is set at [../Dockerfile#L66](../Dockerfile#L66) and [#L28](../Dockerfile#L28), [../scripts/cli.ts#L1](../scripts/cli.ts#L1) and [../scripts/serve.ts#L1056](../scripts/serve.ts#L1056). The caller is [../src/server/broker.ts#L1365](../src/server/broker.ts#L1365).
- **Introduced by:** `d95922b` (Merge r2-ws2-proto-pollute: R2-C-2 prototype pollution defense + Node hardening flags).
- **What's wrong:** The Docker CMD and the CLI shebang now run Node with `--disable-proto=throw`, and `KOVO_REQUIRE_HARDENED_NODE=1` stops startup if the flag is missing. Node's lazy `IncomingMessage.headers` getter builds a plain object and assigns each raw header by name. When a header's name is the prototype accessor, that assignment throws `ERR_PROTO_ACCESS`. Every Kovo HTTP/1 client path reads `res.headers` synchronously inside a `'response'` or `'end'` listener with no try/catch. The exception goes out through the socket data handler and becomes an `uncaughtException`. No handler for it exists in `src/` or `scripts/` (grep). `run-actor.ts` installs only `unhandledRejection`.
- **Evidence:** egressRawHttp1's `onResponse` reads `res.headers` at L1187 on the no-body path, which is the default, and `res.headers['content-encoding']` at L1193. On node v26.12.0 with an in-memory Duplex as `createConnection`, a response carrying that header behaves as follows:
  - without the flag, it is handled normally;
  - with `--disable-proto=delete`, it is handled normally;
  - with `--disable-proto=throw`, the process exits with code 1.

  The stack runs `_addHeaderLine` → `get headers` → user listener → `parserOnIncomingClient` → `socketOnData`.
- **Attack path:** Any HTTP endpoint the host contacts can return that header line. That includes an in-scope target, a host found by recon or discovery, a persona login endpoint, a page loaded through the browser proxy, or a provider. No approval and no LLM cooperation are needed; one passive GET is enough. Node parses the headers, the Kovo listener throws, and the host process exits. On restart, resumed runs re-contact the same host, so the crash repeats.
- **Impact:** Untrusted input crashes the whole host. Every concurrent run across all tenants aborts, in-flight approvals and transcripts are lost, and the UI goes offline, possibly in a persistent crash loop. Secondary effect: untrusted-JSON copy loops of the form `out[k] = v` now throw instead of copying. These include the H-8 outbound scrubber, `redactJsonNode`/`redactHeaders` and egress-sanitizer `sanitizeNode`.
- **Recommendation:**
  - Switch to `--disable-proto=delete` in the Dockerfile, the CLI shebang and both hardening checks.
  - Never read `IncomingMessage.headers`. Build header maps from `rawHeaders` into `Object.create(null)` and skip the reserved names.
  - Wrap every response/end/data listener body in try/catch that routes to `fail()`.
  - Install a process-level guard that logs the error and fails the affected run.
  - Convert untrusted-JSON copy loops to null-prototype outputs.
- **Related IDs:** R2-C-2.
- **Verification:** 3/3 critical. This round's spot-check confirmed L1187/L1193, Dockerfile L28/L66, cli.ts L1, serve.ts L1056-1058, broker.ts L1365, and that no `uncaughtException` handler exists.

### R3-C-2 — business_logic "verified repeated terminal transition" confirms any idempotent update or delete

- **Kind:** fix-bypass
- **Category:** correctness
- **Location:** [../src/server/oracle-invariants.ts#L1918](../src/server/oracle-invariants.ts#L1918) (second-delta check inside `findVerifiedRepeatedTransition` at L1868); `stateDelta` at [#L784](../src/server/oracle-invariants.ts#L784); short-circuit at [#L2053](../src/server/oracle-invariants.ts#L2053)-2069; reached from [../src/server/proof-receipt.ts#L1256](../src/server/proof-receipt.ts#L1256).
- **Introduced by:** `3462b78` (merge `b675448` movea-oracle-invar).
- **What's wrong:** The R2-C-7 fix replaced the "repeated POST" shortcut with three requirements: two identical successful mutations, an intermediate readback that differs from an earlier one, and a later readback that differs from the intermediate one. `assessBusinessLogicImpact` then returns `satisfied:true` with no boundary, role, protected-field or attribution check. Both deltas use `stateDelta`, which diffs every flattened leaf, excludes no volatile metadata, and sets `deleted=true` for any 404/204/410 read. Two consequences follow:
  - The same PUT sent twice satisfies both deltas once the resource stamps `updated_at`.
  - The same DELETE sent twice, both answered 204 (standard idempotent behaviour), satisfies it because the item 404 after the second delete counts as a "second delta", even though the object was gone after the first.
- **Evidence:** In-memory runs, one member actor, one tenant:
  - PUT twice with readbacks that differ in title and then only in `updated_at`: `satisfied:true`, `boundary:false`, `protectedFields:[]`.
  - DELETE twice (204/204), with a collection read in between and an item 404 afterwards: `satisfied:true`.
  - Control: the same as the PUT case without the `updated_at` bump gives `false`.

  One verifier also noted that steps include only cited exchanges. An uncited intermediate write therefore manufactures the second delta on any editable resource.
- **Attack path:** A worker, or an ordinary double-submit recipe, sends the same PUT or DELETE twice with GET readbacks. It then cites the first mutation as a control and the second as the probe in an impact receipt with class business_logic. The kernel confirms CWE-840.
- **Impact:** False confirmed business_logic and race findings on correct CRUD endpoints of almost any modern API. This reopens R2-C-7, which was critical.
- **Recommendation:**
  - Compute deltas only over fields the request wrote, or over host-declared invariant fields. Exclude timestamp, version, etag and counter leaves.
  - Require a semantic double effect.
  - Never count a 404/410 as a second delta unless a successful read of the same object sits between the two mutations.
  - Keep requiring a boundary or invariant signal.
  - Add both reproductions as negative tests.
- **Related IDs:** R2-C-7, C-6.
- **Verification:** 3/3 critical. Spot-check confirmed `stateDelta` L784-801, the second-delta loop L1912-1922 and the short-circuit L2053-2069.

### R3-C-3 — The kernel request plane is still heuristically credential-redacted while the response plane is raw, which defeats the echo strip and forges injection confirms

- **Kind:** fix-bypass
- **Category:** security
- **Location:** [../src/server/verify-rpc.ts#L666](../src/server/verify-rpc.ts#L666) (`scrubKernel`), used at [#L1084](../src/server/verify-rpc.ts#L1084)-1093 and in transcript entries around L2076; channel heuristics at [../src/server/egress-sanitizer.ts#L535](../src/server/egress-sanitizer.ts#L535); guard at [../src/server/host-fact-log.ts#L47](../src/server/host-fact-log.ts#L47); consumers [../src/server/proof-receipt.ts#L1211](../src/server/proof-receipt.ts#L1211), [#L2584](../src/server/proof-receipt.ts#L2584) and [../src/server/oracle-invariants.ts#L2841](../src/server/oracle-invariants.ts#L2841)-2930.
- **Introduced by:** `d7ebbc9` (merge `b46d801` r2-ws3-custody-rpc; carried by `054344e`).
- **What's wrong:** The R2-C-9 fix moved the kernel request plane from the vault sanitizer to `kernelSanitizer`. However, `scrubKernel` redacts on the `storage_log` channel, which still applies the key-name heuristics in redact.ts. A query pair or JSON/form field whose key looks secret-like becomes a bare `[redacted]`. The response body stays raw. The only fail-closed guard (`VAULT_SCRUBBED_TOKEN_RE`) matches just the capability placeholder, so a bare `[redacted]` passes it. `requestEchoTokens`, `stripRequestEchoes` and `matchStrippedInjectionFingerprint` build their echo set from that redacted plane. The echoed value is therefore never stripped, and the shape check still passes because both arms carry the same `[redacted]` key.
- **Evidence:** In-memory runs with the real `redact()` and `assessInjectionImpact`:
  - Control and probe differ only in a secret-named query parameter. The probe carries a database-engine error-fingerprint string, and the 2xx body echoes it. Result: `satisfied:true` (family sqli).
  - The same test under a neutral key name: `satisfied:false`.

  `HostFactLog.fromTranscriptStore` takes `pathAndQuery` from the scrubbed requestMeta, so the agent-script path inherits the problem.
- **Attack path:**
  1. The untrusted worker picks a reflecting endpoint, such as a search or listing page.
  2. It sends a control arm and a probe arm that differ only in a secret-named parameter, with the probe carrying the fingerprint class.
  3. It returns an injection impact claim.
  4. Both fresh attempts reproduce deterministically.
- **Impact:** Forged confirmed SQLi or other injection findings on any target that reflects parameters. This is the R2-C-9 outcome through a different redactor. The expression and markup anti-reflection checks are weakened the same way.
- **Recommendation:**
  - Build the kernel request plane from the raw broker request with only exact host-secret placeholders (no heuristics), or keep a parallel raw token set for anti-reflection.
  - Broaden the guard to any `[redacted` placeholder in an injection or markup arm.
  - Add a regression test with a secret-named echo.
- **Related IDs:** R2-C-9, H-9, H-16, R2-H-10. R2 had dismissed this redaction path as "fails closed"; it fails open.
- **Verification:** 3/3 critical. Spot-check confirmed `scrubKernel` L666-668, provenance L1084-1093, egress-sanitizer L535-539 and host-fact-log L47.

### R3-C-4 — Boolean-differential and status-boolean triangles never bind the base value, so integer-coercing parameterised endpoints confirm sqli

- **Kind:** fix-bypass
- **Category:** correctness
- **Location:** [../src/server/oracle-invariants.ts#L2610](../src/server/oracle-invariants.ts#L2610) (triangle construction L2604-2620); `booleanPredicateTruth` [#L2388](../src/server/oracle-invariants.ts#L2388); `requestShape` masking [#L2485](../src/server/oracle-invariants.ts#L2485); statusBoolean [#L3241](../src/server/oracle-invariants.ts#L3241)-3249; rules [../src/server/proof-receipt.ts#L704](../src/server/proof-receipt.ts#L704)-768 and `statusDifferentialRounds` [#L2699](../src/server/proof-receipt.ts#L2699).
- **Introduced by:** `3462b78` (merge `b675448` movea-oracle-invar).
- **What's wrong:** The C-7 fix added a baseline/true/false triangle and rejects bare literals. It labels the arms only by running `booleanPredicateTruth` over each arm's injected value, which finds one embedded comparison anywhere in that value. Nothing requires the true and false arms to share a base value once the predicate is removed, or to equal the baseline value. `requestShape` masks the injected parameter, so differing base values are invisible to the shape check. The status-boolean branch only checks opposite truth over the concatenated raw request.
- **Evidence:** In memory, a stub returns 200 only when the parsed leading integer equals the existing ID and 404 otherwise. Two rounds were run:
  - baseline = existing ID;
  - true arm = existing ID followed by a true comparison;
  - false arm = a missing ID followed by a false comparison.

  `assessBooleanDifferential` returned `satisfied:true`, and statusBoolean (200/200/404) also returned `satisfied:true`. Giving both arms the same base value was correctly rejected.
- **Attack path:** The worker sends the triangle through the broker to any object-ID endpoint that coerces input to its leading integer (parseInt-style handlers, PHP intval, Rails to_i, a MySQL implicit cast to an INT column). It then submits a `sqli` boolean or status_differential receipt. Replay re-sends the same requests, so it reproduces.
- **Impact:** Forged confirmed CWE-89 on safe, parameterised endpoints. This is exactly the false-positive class C-7 was meant to close.
- **Recommendation:**
  - Use host-minted predicate pairs: the host generates a base value plus true/false suffixes.
  - Require the arms to be byte-identical once the recorded predicate is removed, and require the baseline to equal the shared base.
  - Parse predicates only from the named parameter.
  - Apply the same rules to statusBoolean and `statusDifferentialRounds`.
  - Add a regression test with an integer-coercion stub.
- **Related IDs:** C-7.
- **Verification:** 3/3 critical. Spot-check confirmed L2602-2620 (truth comes from the predicate only; no base-value comparison).

### R3-C-5 — V8 hydration takes tenant and scope from the worker's own request plane (cryptographic_scope_replay; dual_tenant_abac batch_partial_authz and dual_org_cache_bleed)

- **Kind:** fix-bypass
- **Category:** correctness
- **Location:** [../src/server/v8-oracle-hydrate.ts#L988](../src/server/v8-oracle-hydrate.ts#L988) (`hostScopeOf`) and [#L982](../src/server/v8-oracle-hydrate.ts#L982)-987 (`hostSrcTenant`/`hostDstTenant`); `markersOf` [#L873](../src/server/v8-oracle-hydrate.ts#L873)-877 used at L893-904 and L909-931; evaluators [../src/server/v8-oracle-families.ts#L517](../src/server/v8-oracle-families.ts#L517)-519 and L268-330; request JSON filled from raw request body at [../src/server/terminal-oracle-registry.ts#L341](../src/server/terminal-oracle-registry.ts#L341)-346; terminal control match [../src/server/composite-receipt.ts#L660](../src/server/composite-receipt.ts#L660)-668.
- **Introduced by:**
  - `hostScopeOf`: `fc7d8d6` (merge `851327f` movea-waveb-v8).
  - `markersOf`: `efb13b5` (merge `7ac5249` fix-audit-proof-a).
- **What's wrong:** The R2-C-8 fix says tenant and scope are derived "strictly from host transcript records". The derivation still reads the worker's request plane:
  - `hostScopeOf` returns an `x-scope` request header first, then a `scope` field from the response or request JSON, and only then falls back to `tenant:route`.
  - `hostDstTenant` prefers tenant markers found in the request JSON.
  - `markersOf` merges tenant markers from the response, the request JSON and the raw request body.

  verify-rpc forwards arbitrary worker header names and records them.
  - **(a) cryptographic_scope_replay (critical).** The worker fetches the same signed URL twice, adding a custom scope header the second time. That makes `srcS ≠ dstS`. The digests match, a tampered-signature 403 supplies the denied control (`canonicalNonAuthQuery` strips the signature), and the family confirms `valid_signature_replayed_across_scope_boundary`.
  - **(b) batch_partial_authz (high variant).** A worker-added tenant field in the batch body becomes `foreignTenantId`. A foreign ID echoed in a per-item "denied" list counts as `foreignDataObserved`, because `recordContainsToken` matches exact leaves anywhere.
  - **(c) dual_org_cache_bleed (high variant).** `targetTenantId` and `observedTenantId` come from the bled-access request body.
- **Evidence:** In-memory runs with `signHostRecord`, HostFactLog and `defaultTerminalOracleRegistry`:
  - (a) The transcript was a 403 with a bad signature, a 200 with a valid signature, and the same 200 with one extra header. `v8_family` gave `confirmed:true`, and a one-hop composite receipt gave "CompositeProofReceipt confirmed (1 hop(s))". Removing the header gave `same_tenant_and_scope_not_replay`.
  - (b) `batch_partial_authorization_bypass_confirmed`. Removing the worker-added tenant field gave `missing_tenant_scope`.

  `git log -L` shows the `x-scope` lookup did not exist at 98881b4.
- **Attack path:** The worker uses benign, correctly behaving traffic against any signed-URL endpoint (downloads, exports, share links) or any batch API that echoes refused IDs. It then calls `composite.verify` / `ctx.prove_composite` with `oracleFamily` set to the family and `oracleInput` naming the exchange IDs.
- **Impact:** Forged confirmed critical cross-scope or cross-tenant findings that reproduce deterministically in both fresh runs and on retest.
- **Recommendation:**
  - Derive tenant and scope only from host persona metadata, host-sealed capability metadata and response-side markers, never from the request plane of the exchange under test.
  - Require replay and issuance to differ in a host-attested dimension: persona or tenant, route or entity.
  - For batch reads, require a returned object whose identifier is the foreign ID and that carries non-error fields, and require that the foreign tenant is known to the host.
  - Add regression tests for an identical signed URL with and without an extra header, an echoed-denial batch, and a request-body tenant field.
- **Related IDs:** R2-C-8, C-4.
- **Verification:** (a) 3/3 critical; (b)/(c) 3/3 high, merged here by shared root cause. Spot-check confirmed `markersOf` L873-877, `hostScopeOf` L988-996 and the evaluator L517-519.

### R3-H-1 — Derived staging_isolated auto_review still auto-approves writes with no judge or operator (two R2-H-1 bypasses)

- **Kind:** fix-bypass
- **Category:** security
- **Location:** [../src/server/request-admission.ts#L1615](../src/server/request-admission.ts#L1615) (auto_review branch L1600-1619); [../src/server/scope-policy.ts#L321](../src/server/scope-policy.ts#L321) (`detectMethodOverride` truncation, cap at L253); `requestCarriesTenantTag` [../src/server/scope-policy.ts#L1177](../src/server/scope-policy.ts#L1177)-1196; host body tagging [../src/server/execution.ts#L3649](../src/server/execution.ts#L3649)-3672 and [../src/server/deterministic-engine.ts#L3072](../src/server/deterministic-engine.ts#L3072)-3098; `classifyRequestMutation` [../src/server/request-admission.ts#L769](../src/server/request-admission.ts#L769)-794; `checkLease` L1556-1560.
- **Introduced by:** `2bd81f0` (merge `fed18e5` movec-egress-admit).
- **What's wrong:** The R2-H-1 fix auto-approves a non-structural mutation on derived staging only when it carries a "target-visible" tenant tag (`ignoreHostInjectedHeaders:true`). It escalates method-override carriers as structural. Both conditions can be defeated:
  - **(a) Host tag in the body.** For every mutating agent `request_http`, the host itself prefixes the run tag onto benign JSON fields (name, title, description, email and similar) via `tagStagingEntityBody`. `requestCarriesTenantTag` filters only headers, so the host's own body tag satisfies it. Any PUT, PATCH, action POST or GraphQL mutation that includes one benign field is contract-approved as `approval_policy:auto_review`. `isStateChangeApproved`, the judge and the operator never run.
  - **(b) 64 KiB scan window.** `detectMethodOverride` parses only `rawBody.slice(0, 64 KiB)`. A form or JSON body with an `_method` override field placed after a filler larger than the window is classified as a plain non-structural POST. The same truncated result also defeats `checkLease`'s override exclusion under a durable POST route lease, in any policy. The judge's own large-body escalation is never reached.
- **Evidence:** In-memory `RequestAdmissionEngine.admit`, derived staging, auto_review, counting approval-hook calls:
  - (a) `PATCH` on a user object with a privilege field plus a name field built by `stagingProbeTag`: allow, 0 hook calls. The same request without a taggable field: `require_approval`. The fix's own test (`tests/movec-egress-admit.test.ts:258-266`) sends an untagged body.
  - (b) A small tagged form with an override field: `require_approval`. The same with about 70 KiB of filler first: allow via `approval_policy:auto_review`, 0 hook calls.

  verify-rpc allows bodies up to 2 MiB. `request_http`'s `jsonBody` has no size cap.
- **Attack path:** An untrusted or target-steered worker on a Supervised (Tier 3, auto_review) public run, which derives staging_isolated by default (store-runs.ts L123-131), sends a privilege change, an account disable, or a padded override-to-delete. The broker forwards it to the live target, and the audit trail shows an auto-reviewed environment-contract write.
- **Impact:** State-changing and destructive writes reach live in-scope targets with no judge or human approval, on the default Supervised preset. This breaks the UI promise that write requests go to an independent safety checker.
- **Recommendation:**
  - On derived (non-explicit) staging_isolated, drop the tag-based auto-approve and route every non-read-only request through `isStateChangeApproved`. Alternatively, evaluate the tag against the body as the worker submitted it, before host tagging.
  - Never truncate the override scan; treat over-cap bodies as structural.
  - Share one classification across admission, leases and the judge.
  - Add regression tests for a `stagingProbeTag`-built PUT and for an override field placed after 64 KiB, for both form and JSON bodies.
- **Related IDs:** R2-H-1, L-2, M-2, M-3, H-3.
- **Verification:** (a) 3/3 high; (b) 3/3 high. Spot-check confirmed L253, L321, request-admission L1600-1619 and execution L3649-3672.

### R3-H-2 — Sealed capability values recoverable through `async.awaitResult` predicates and `prove.differential` stableDelta over bodies the vault never scrubbed

- **Kind:** fix-bypass (custody goal of WS-3)
- **Category:** security
- **Location:** [../src/server/verify-rpc.ts#L1902](../src/server/verify-rpc.ts#L1902) (pollFn) → `matchAsyncPredicate` [#L1805](../src/server/verify-rpc.ts#L1805)-1851; [../src/server/verify-claims.ts#L1462](../src/server/verify-claims.ts#L1462); [../src/server/verify-support.ts#L128](../src/server/verify-support.ts#L128); [../src/server/verify-prove-handlers.ts#L709](../src/server/verify-prove-handlers.ts#L709); root cause [../src/server/broker.ts#L3703](../src/server/broker.ts#L3703).
- **Introduced by:** Pre-existing at 98881b4. Not addressed by `b46d801` r2-ws3-custody-rpc, which claimed blind handle custody.
- **What's wrong:** The broker builds `safeBody = redact(rawBody, effectiveSecrets)`. `effectiveSecrets` holds persona, grant, request and broker-registered secrets, but never capability-vault values. When a request carries a sealed value inline and an in-scope page reflects it, the host-side `result.body` and the TranscriptStore body hold the raw value. Two worker-reachable channels then expose it:
  - **`async.awaitResult`.** It runs worker-supplied `bodyContains`, a free `bodyMatches` regex, jsonPath `equals`/`in`/`matches` and header `matches` on that body. It returns `converged` and a per-attempt matched log, which is a membership oracle with no budget. Booleans pass straight through `scrubRecord`.
  - **`prove.differential`.** `structural_diff` returns up to 16 lowercased, punctuation-split stableDelta tokens. The exact, case-sensitive vault scrub misses them, and `bodySha256` of the raw body lets the worker restore case offline.

  `capability.seal` extracts with jsonPath, header or cookie selectors from the raw pre-redaction bytes. The worker can therefore seal fields it only ever saw redacted.
- **Evidence:** In-memory runs with a fake broker that mimics broker.ts redaction:
  - A hidden 16-character value was recovered via `async.awaitResult` with `maxAttempts:1` prefix extension. The naive per-character loop took 666 requests; a character-class binary search takes about 6 per character.
  - One `prove.differential` call returned the value lowercased in `stats.stableDelta`.
- **Attack path:**
  1. Seal a target-issued secret that the broker hid by heuristic, or a `crypto.hmacSign` derived handle.
  2. Inline the handle into a reflecting in-scope request.
  3. Binary-search with `bodyMatches`, or read stableDelta.
  4. Print the plaintext. It then reaches the model, the provider and the logs.
- **Impact:** This breaks I3 and blind custody. Target secrets hidden by heuristics and sealed HMAC/JWT outputs reach the untrusted worker and model, which reopens R2-C-4's offline key brute force. Persona, session, jar and CSRF values are registered with the broker and stay redacted, which is why this is high rather than critical. The vault is shared per run.
- **Recommendation:**
  - Evaluate worker predicates and `structural_diff` only on bodies passed through the vault-aware `this.egress`, or register vault descriptors as broker secrets for verify-rpc requests.
  - Drop stableDelta, or replace it with counts or keyed digests.
  - Return digests of the worker-visible body only.
  - Give `async.awaitResult` a run-scoped budget and route it through the linear regex chokepoint.
  - Add a regression test asserting that true and false predicates give identical results on a reflected sealed value.
- **Related IDs:** C-3, R2-C-3, R2-C-4, H-9, H-32.
- **Verification:** 2 high, 1 critical. Spot-check confirmed pollFn L1898-1905 passing the unscrubbed `result.body`, and `stableDelta` at verify-prove-handlers L709.

### R3-H-3 — The browser_session refresher runs untrusted target JavaScript with raw persona storageState behind an "any public HTTPS" proxy

- **Kind:** new-code
- **Category:** security
- **Location:** [../src/server/browser-session-auth.ts#L362](../src/server/browser-session-auth.ts#L362) (`createBrowserSessionProxy` `allowOrigin`, L325-373); `refreshBrowserSession` [#L1190](../src/server/browser-session-auth.ts#L1190)-1206; wired from [../src/server/persona-auth.ts#L2286](../src/server/persona-auth.ts#L2286), L2390-2427 and L4266-4285.
- **Introduced by:** `e7d0261` (merge `f66dcba` opt4-universal-auth) and `8c87b63` (merge `cb7c722`).
- **What's wrong:** The unattended refresher opens Chromium with the persona's full persisted storageState: raw cookies including IdP-domain and HttpOnly cookies, plus every origin's localStorage. It sets `javaScriptEnabled:true` and navigates to `targetOrigin + verifyPath`, then waits for networkidle. Its proxy allows every `https:` URL, with no ScopePolicy, grant, tier or approval check. Only private, loopback and metadata IPs are blocked. Unlike ScopedBrowser, it has no H-8 wire placeholders, no broker route mediation and no service-worker block. It runs every 30-240 s for the whole run and on on-demand reauth.
- **Attack path:** A worker at Tier 2/3, doing the stored-XSS or second-order probing the product supports, plants persistent content that renders at verifyPath (default `/`). Within one refresh interval, or immediately after the worker induces a 401, the host browser runs that content with the real tokens. It sends localStorage JWT/refresh blobs and non-HttpOnly cookies to any public HTTPS host.
- **Impact:** Host-held persona credentials are exfiltrated to a third party outside the grant, and state-changing requests run with the real session without tier gating. This is a dual path that bypasses H-8.
- **Recommendation:**
  - Run refreshes through ScopedBrowser machinery: broker-mediated routes scoped to `persona.originAllowlist` and the project ScopePolicy, service workers blocked, placeholders seeded.
  - Require an explicit, operator-approved IdP origin list.
  - Drop third-party cookies from the bundle unless the operator opts in.
  - Refuse to refresh pages modified by the run.
- **Related IDs:** H-8, C-8.
- **Verification:** 2 high, 1 critical lowered to high. Spot-check confirmed `allowOrigin` returning true for https at L362 and `newContext({storageState, javaScriptEnabled:true, proxy})` at L1190-1197.

### R3-H-4 — Composite cap-actor resolution (`resolveActor`/`resolvedActorOf`/`fromDag`) launders forbidden credentials into attacker-origin evidence

- **Kind:** fix-regression and fix-bypass
- **Category:** security / correctness
- **Location:** [../src/server/composite-receipt.ts#L479](../src/server/composite-receipt.ts#L479) (`fromDag` skips `isForbidden`; `resolveActor` L465-470; extraIds L493); [#L137](../src/server/composite-receipt.ts#L137) (`resolvedActorOf`); [#L656](../src/server/composite-receipt.ts#L656)-657 (terminal control binding); L374-375 (ablation); [#L239](../src/server/composite-receipt.ts#L239)-240 (browser/OOB caps into dagCaps); [#L474](../src/server/composite-receipt.ts#L474) (root-hop exemption); [../src/server/verify-rpc.ts#L976](../src/server/verify-rpc.ts#L976)-996 (base-persona credential merge); `actorOf(cap)` [../src/server/v8-oracle-hydrate.ts#L316](../src/server/v8-oracle-hydrate.ts#L316)-330.
- **Introduced by:**
  - `25d409c` (merge `ae87490` fix-golden-e2e), the `fromDag` skip and emitter mapping.
  - `d7ebbc9` (merge `b46d801`), the R2-H-8 relabel that keeps base-persona headers.
  - `fc7d8d6` (merge `851327f`), the root-hop exemption.
- **What's wrong:** Three variants share one root cause: a `cap:` actor is resolved to whichever persona emitted it, or is exempted when it is DAG-derived, with no check of whose credential actually went on the wire.
  - **(a) Admin credential under a member label.** A request sent as an admin persona plus a member-emitted cookie capability keeps the admin Authorization or API-key header in `mergedBundleHeaders`; only base Cookie is dropped, and only when the cap supplies a bearer. It is signed as `actor=cap`, label member, auth cookie. `resolveActor` then sets `fromDag`, or maps the cap to member, so the forbidden admin persona is never checked. Result: confirmed BFLA or privilege escalation against correct RBAC.
  - **(b) Junk-credential control.** The terminal control actor check now uses `resolvedActorOf`. A control sent with a junk Bearer capability sealed from the member's own response gets 401/403, resolves to `member_a`, matches the terminal actor and dodges the anonymous-401 rule. Honest own-object 200 reads then confirm broken_access_control and info_disclosure, plus bola and idor when the body has no tenant markers. This reopens R2-H-7(c).
  - **(c) Browser/OOB root hops.** A root hop that cites only a browser trace or OOB event needs no probe, and the trace's `actorPersona` is never checked. The trace's `emittedCapabilities` still join dagCaps. `capability.seal` accepts a browser record as its source. A value rendered in a forbidden admin's browser session therefore becomes a DAG cap, and `fromDag` skips the forbidden check on the probe that uses it. This contradicts the H-11 fix plan item "dagCaps only from probes that passed provenance".
- **Evidence:** In-memory runs (`/tmp/r3exp/a.mts`, `b.mts`, `c.mts`, `d.mts`) over signed entries shaped like verify-rpc output, with `attackerPersonas=[member_a]` and `forbidden=[admin]`:
  - (a) A 2-hop chain gave `confirmed:true` for privilege_escalation. One verifier could not reproduce the 1-hop variant.
  - (b) `confirmed:true` for bola, broken_access_control, idor and info_disclosure.
  - (c) `confirmed:true`.

  All three are rejected at `70717d6` or when the real base persona is recorded. Citing the seal record instead of the trace is rejected ("admin is forbidden").
- **Attack path:** Grants necessarily carry a privileged persona for controls. The worker seals any high-entropy member or admin-page value, injects it as a capability alongside or instead of the real credential, and submits a 1-2 hop `compositeReceipt` or calls `composite.verify`.
- **Impact:** False confirmed authorization-bypass findings at scale. The signed evidence misstates which credential was on the wire.
- **Recommendation:**
  - In verify-rpc, reject base-persona plus auth-capability requests, or drop every base credential header when a capability supplies any auth. Alternatively, record both and check the base persona.
  - In composite-receipt:
    - Never let `fromDag` skip the forbidden check.
    - Bind controls by credential identity: same cap, or the persona's own session cap. Treat cap-auth controls as anonymous for the 401 rule.
    - Require a probe in every root hop.
    - Admit caps into dagCaps only from records that passed provenance.
  - Add regression tests for each variant.
- **Related IDs:** R2-H-8, H-11, H-12, H-14, R2-H-7.
- **Verification:** (a) 3/3 high; (b) 3/3 high; (c) 3/3 high. Spot-check confirmed `resolveActor` L465-470, the L479 skip, `resolvedActorOf` L137, the L656 control check, L239-240, the L474 exemption, and the verify-rpc L985-988 merge that skips base Cookie only for bearer caps.

### R3-H-5 — H-13 fix bypass: a cookie capability on a bearer persona still records pure cookie auth, and the worker chooses the cookie name and its SameSite

- **Kind:** fix-bypass
- **Category:** security
- **Location:** [../src/server/host-fact-log.ts#L461](../src/server/host-fact-log.ts#L461) (`useWireFallback`); [../src/server/verify-rpc.ts#L929](../src/server/verify-rpc.ts#L929), [#L990](../src/server/verify-rpc.ts#L990), [#L2084](../src/server/verify-rpc.ts#L2084); `resolveSameSite` [../src/server/host-fact-log.ts#L880](../src/server/host-fact-log.ts#L880)-895; `sameSiteFromRecord` [../src/server/verify-claims.ts#L945](../src/server/verify-claims.ts#L945)-951; [../src/server/proof-receipt.ts#L2290](../src/server/proof-receipt.ts#L2290)-2300.
- **Introduced by:** `2d21fdb` (merge `054344e` movea-proof-receipt) and `aad8ad9` (merge `874424b` movec-c1-h14-wire).
- **What's wrong:** `buildHostSignedTranscript` derives placement from the kernel meta headers. For a cookie capability, those headers hold only `Cookie: <worker name>=[injected]`. The base persona's Authorization header goes only into the ephemeral bundle on the wire. `useWireFallback` is disabled as soon as any Cookie is present, so the broker's signed wire provenance, which lists `authorization`, is ignored. The result is placement `cookie` with `mixed:false`, and `authenticatingCookieName` is the worker's choice. `resolveSameSite` looks that name up in any same-origin Set-Cookie, including anonymous exchanges. Otherwise it falls back to the first SameSite token anywhere in the joined Set-Cookie header, which is not bound to any cookie.
- **Evidence:** In memory, with wire provenance whose vault headers include authorization: placement was `{personaAuthKind:'cookie', mixed:false}` and ambient auth `cookie`, and `isCrossSiteSendableCsrfRequest` returned sendable. The only test (`tests/movea-proof-receipt.test.ts:858-864`) passes an explicit placement.
- **Attack path:** A bearer persona on a JSON API, plus any SameSite=None cookie on the origin (a CDN or load-balancer cookie is enough). The worker seals any value, sends a form-encoded write with a foreign Origin and a junk cookie capability named after the SameSite=None cookie, and records readbacks. The host itself emits `csrf_state_change`, and CWE-352 is confirmed.
- **Impact:** False CSRF findings on bearer-authenticated APIs, which browsers cannot CSRF. This is exactly the H-13 scenario the fix claimed to close.
- **Recommendation:**
  - Derive placement from the wire provenance whenever it is present, and mark it mixed when an auth header accompanies any cookie.
  - Stamp an explicit host placement from the injection step.
  - Bind the cookie name to vault or jar names, not to capability-supplied names.
  - Drop the unbound SameSite fallback.
  - Add an end-to-end `VerifyRpcServer` test.
- **Related IDs:** H-13, H-14, R2-H-8.
- **Verification:** 3/3 high. Spot-check confirmed that L461 disables the wire fallback whenever cookie names are present.

### R3-H-6 — Chromium always launches with `--no-sandbox`

- **Kind:** pre-existing-unreported, repeated in new code
- **Category:** security
- **Location:** [../src/server/scoped-browser.ts#L612](../src/server/scoped-browser.ts#L612)-628 (`launchChromium`); `chromiumLaunchArgs` L448-462; [../src/server/persona-auth.ts#L816](../src/server/persona-auth.ts#L816), L822; [../src/server/browser-session-auth.ts#L308](../src/server/browser-session-auth.ts#L308), L314; tests `tests/v5-security-auth2.test.ts:430` and `tests/v5-security-authbrowser.test.ts:428`.
- **Introduced by:** Pre-98881b4. Repeated in `e7d0261` (merge `f66dcba`).
- **What's wrong:** All launch sites call `chromium.launch({ headless: true, args })`. They treat "no `--no-sandbox` in our args" as "sandbox on". In playwright-core 1.65.1, Chromium's default args push `--no-sandbox` whenever `options.chromiumSandbox !== true` (coreBundle.js L45187, L45392). No Kovo call passes that option (grep finds none). The tests inspect only Kovo's own args list. SECURITY-REAUDIT-2026-11-22 records "Sandbox on by default" as verified.
- **Attack path:** A hostile or compromised target serves a renderer n-day exploit; the Chromium build is pinned and baked into the image. The scoped browser, form login or session capture loads it. Renderer code execution is now code execution as the Kovo user. That user can read data-dir credentials (the model key, HMAC signing keys, persona secrets), write the store, and in compose deployments reach docker-proxy (the R2-C-1 class).
- **Impact:** A documented isolation control is silently absent in every deployment.
- **Recommendation:**
  - Pass `chromiumSandbox: true` explicitly, and `false` only with `KOVO_INSECURE_NO_SANDBOX=1`.
  - Fail closed with an actionable error if the sandbox cannot start; ship a seccomp profile and document userns requirements.
  - Make the tests assert the launch option or the final argv.
  - Run browsers in a container without docker-socket or data-dir access.
- **Related IDs:** SECURITY-REAUDIT §Browser sandbox and item 6; R2-C-1 (amplifier only).
- **Verification:** 3/3 high. Spot-check confirmed L612-628, zero `chromiumSandbox` hits in src/scripts, and coreBundle L45187/L45392.

### R3-H-7 — Copy-as-cURL and the receipt `commandHint` put worker-chosen paths and header names into shell commands unescaped

- **Kind:** pre-existing-unreported
- **Category:** security
- **Location:** [../src/components/curl-parser.ts#L483](../src/components/curl-parser.ts#L483) (header key raw at L487); callers [../src/components/run/views/exchanges.tsx#L387](../src/components/run/views/exchanges.tsx#L387), [../src/components/run/views/queue-read.tsx#L292](../src/components/run/views/queue-read.tsx#L292); [../src/server/receipt-export.ts#L368](../src/server/receipt-export.ts#L368) (`buildCommandHint` L362-368).
- **Introduced by:** Not attributable to a post-R2 merge; recent touches (`e9bd850`, `867c25c`) left the output path unchanged.
- **What's wrong:** `formatExchangeAsCurl` interpolates the method and origin+pathAndQuery raw inside single quotes, and escapes only header values. `buildCommandHint` interpolates the path inside double quotes, where command substitution is live. Admission (`hasUnsafeAdmissionPath`, `canonicalPathAndQuery`, scope-policy L114-115) rejects only dot segments, backslashes, encoded separators and control characters. WHATWG URL leaves quotes, `$`, parentheses, `;`, `|` and `&` unencoded in the path. The broker stores `redact(req.pathAndQuery)` unchanged.
- **Evidence:** A stubbed-curl shell experiment, with no network: a canonical path with a quote breakout ran an injected command from the UI copy, and a path with a command substitution ran from the receipt hint.
- **Attack path:** An untrusted or target-steered worker sends a scoped GET whose path breaks quoting. The operator clicks "Copy as cURL" and pastes it, or a developer pastes the signed receipt's reproducer hint.
- **Impact:** Command execution on the operator's or developer's machine, outside the worker sandbox, through the product's own features. The signed bundle makes the hint look authoritative.
- **Recommendation:**
  - Use one POSIX single-quote helper for the method, the URL, and each whole `-H` argument, in both builders. Stop using double quotes.
  - Restrict the method to the `HttpMethod` enum.
  - Add a regression test that runs the generated command under a stubbed curl and asserts each field is one argv element, with the payloads built from character classes.
- **Related IDs:** none.
- **Verification:** 3/3 high. Spot-check confirmed L483/L487, receipt-export L362-368 and both callers.

### R3-H-8 — Server-authoritative scope ranking pre-selects every discovered host under the seed's registrable apex, re-widening the R2-H-5 anchor

- **Kind:** fix-bypass (regression versus the R2-H-5 anchor)
- **Category:** security
- **Location:** [../src/actions.ts#L593](../src/actions.ts#L593) (L590-600), `matchesWildcardParent` [#L619](../src/actions.ts#L619)-628, pre-selection L641-660; [../src/components/run/views/consent.tsx#L161](../src/components/run/views/consent.tsx#L161)-163 and L88; [../src/server/subdomain-discovery.ts#L1574](../src/server/subdomain-discovery.ts#L1574).
- **Introduced by:** `c2560db` (merge `1d11b32` arch-u1u4-ui-scale) and `0caf353` (merge `688cb93` r2-ws18-dood-worker, consent PSL).
- **What's wrong:** The R2-H-5 fix anchors Phase-0 auto-admit at the seed host, via `autoAdmitAnchorForOrigin` / `matchesAutoAdmitAnchor`. `computeServerScopeRanking` instead adds `registrableApex(origin)` for every includeSubdomains seed. `matchesWildcardParent` returns true for any host sharing that PSL apex, so up to 30 discovered, non-third-party hosts are put in `recommendedScopeAssetIds`/`highSignalScopeAssetIds`. With a saved default scope, they go into `extraSubs` on top of it. consent.tsx uses these as the initially checked set, and `setScope` applies no anchor check. At 98881b4 the client default stripped only `www.`.
- **Evidence:** For a seed on an unlisted multi-tenant vendor with includeSubdomains, the server anchor correctly rejects the sibling tenant, but the ranking pre-selects the seed plus other tenants and admin hosts. The inventory badge tells the operator `*.{seedhost}`.
- **Attack path:** A public project on a tenant subdomain of an unlisted vendor (includeSubdomains defaults to true) runs discovery. Discovery enumerates the vendor apex, and the operator accepts the pre-checked default.
- **Impact:** Active probing of other customers' tenants and vendor infrastructure under the operator's authorization. The R2-H-5(a) outcome is moved to one-click consent.
- **Recommendation:**
  - Pre-select only hosts that `matchesAutoAdmitAnchor(host, autoAdmitAnchorForOrigin(seed))` accepts.
  - Show same-apex hosts unchecked, with a label.
  - Optionally require a per-host acknowledgement in `setScope`.
  - Add a regression test for an unlisted-vendor tenant, and a lint banning `registrableApex` in scope-selection code.
- **Related IDs:** R2-H-5, C-2, H-4.
- **Verification:** 2 high, 1 medium (the operator still clicks approve). Spot-check confirmed L590-600 and L619-628.

### R3-H-9 — A `**` path segment written by the model turns "Approve similar" into an unbounded prefix approval for every same-method request on the origin

- **Kind:** fix-bypass (SECURITY-REAUDIT 1.3 invariant)
- **Category:** security
- **Location:** [../src/server/approval-pattern.ts#L95](../src/server/approval-pattern.ts#L95); prefix match [#L142](../src/server/approval-pattern.ts#L142)-147; [../src/server/store-runs.ts#L1836](../src/server/store-runs.ts#L1836)-1870; [../src/server/approval-judge.ts#L460](../src/server/approval-judge.ts#L460)-464.
- **Introduced by:** Pre-existing `**` semantics from the re-audit 1.3 fix; not changed after R2.
- **What's wrong:** The comment says `**` is honoured "only when the operator actually wrote it", but nothing enforces that. `normalizeApprovalPathPattern` keeps literal `*` and `**` segments from the approval card's `pathAndQuery`, which is the worker's request path. `canonicalPathAndQuery` lets `*` through. `approveSimilarEndpoint` stores the result as a prefix pattern; a bare root glob gives `fixedLength 0`, which matches every path. The same call bulk-approves every matching pending card. `authorizeStateChange` returns `operator_pattern` before the judge or ledger runs. Only the non-overridable shapes still escalate: RCE, override, compression, oversize body, malformed multipart and race.
- **Evidence:** Node experiment: `/api/**` and the bare glob survive normalisation, and each matches an unrelated deep admin-style POST (true).
- **Attack path:** The worker sends a state-changing request to a glob path, which usually gets a harmless 404 and a card. The operator clicks "Approve similar", expecting ID-segment similarity. From then on, every request with that method under the prefix bypasses review for the scope revision.
- **Impact:** One click gives run-wide approval of that method on the origin or subtree, and auto-approves queued cards.
- **Recommendation:**
  - Reject or escape `*`/`**` segments taken from card paths; only an explicit operator-typed pattern field may carry `**`.
  - Flag cards whose paths contain glob characters.
  - Add a regression test.
- **Related IDs:** SECURITY-REAUDIT 1.3, M-55, M-1.
- **Verification:** 2 high, 1 medium. Spot-check confirmed L95 and L140-148 (the comment contradicts the data flow), and store-runs L1836.

### R3-H-10 — The H-8 outbound exact scrub rewrites model-request protocol fields; a short cookie value set by the target breaks every agentic call

- **Kind:** fix-regression
- **Category:** reliability
- **Location:** [../src/server/provider.ts#L367](../src/server/provider.ts#L367) (L363-368); [../src/server/provider-stream.ts#L126](../src/server/provider-stream.ts#L126)-153; needle sources [../src/server/persona-vault.ts#L810](../src/server/persona-vault.ts#L810)-814, L515-517, [#L1641](../src/server/persona-vault.ts#L1641)-1680; persona-auth L3348-3355; [../src/server/agent-session.ts#L2989](../src/server/agent-session.ts#L2989)-3037.
- **Introduced by:** `f2e4194` (merge `9c36ce9` r2-ws7-provider-keys). The needle set was widened by `e7d0261`.
- **What's wrong:** `scrubExactSecretsValue` runs over the entire parsed provider request, including every string leaf and object key (roles, enum values, `tool_choice`, `reasoning.summary`, tool names, schema properties). It does substring replacement with needles of 4 or more characters. The needles include every captured cookie value of 4+ characters, whatever the cookie name. That covers `extractBrowserBundleSecrets`, `bundleSecrets` and login Set-Cookie `scrubTokens`. A target cookie whose value equals a protocol word (a role cookie, a preference cookie) puts a persona placeholder into that protocol field. The provider returns 400 on every call. `classifyFailoverError` treats 400 as no-failover and no-retry, and every candidate profile gets the same scrub.
- **Evidence:** The real scrub rewrote `input[].role`, `tool_choice`, `reasoning.summary` and the `input_text` type key. pi-ai 1.5.2 always emits these fields.
- **Attack path:** A target sets a short cookie whose value equals a protocol word, either deliberately to evade agentic analysis or by chance. Every agentic session using that persona fails with an unexplained HTTP 400.
- **Impact:** A run-wide wedge of the agentic lane, causing false negatives at scale. The deterministic floor survives. The pre-existing tool-argument exact scrub also rewrites probe paths that contain the token.
- **Recommendation:**
  - Scrub only content-bearing leaves (message text, tool arguments and outputs, instructions); never keys, role/type/enum fields or tool definitions.
  - Raise the persona needle floor (for example 8 characters plus an entropy check), and keep only auth-relevant cookies.
  - Surface 400s caused by local mutation as a clear local error.
- **Related IDs:** H-8, H-9, H-25.
- **Verification:** 3/3 high. Spot-check confirmed provider.ts L363-368.

### R3-H-11 — The safe-regex chokepoint accepts polynomial and exponential patterns; worker claim regexes wedge the host when Node runs without the linear-fallback flag (`npm start` / `npm run scan`)

- **Kind:** fix-bypass
- **Category:** reliability
- **Location:** [../src/server/safe-regex.ts#L413](../src/server/safe-regex.ts#L413) and [#L432](../src/server/safe-regex.ts#L432) (group boundaries reset the overlap chain), [#L359](../src/server/safe-regex.ts#L359) (a non-overlapping optional atom resets the chain), [#L183](../src/server/safe-regex.ts#L183) (empty and match-any class misparse); sinks [../src/server/verify-claims.ts#L1278](../src/server/verify-claims.ts#L1278), [#L1311](../src/server/verify-claims.ts#L1311), [../src/server/oracle-invariants.ts#L935](../src/server/oracle-invariants.ts#L935), [../src/server/egress-sanitizer.ts#L314](../src/server/egress-sanitizer.ts#L314); backstop [../scripts/serve.ts#L1056](../scripts/serve.ts#L1056), [../scripts/cli.ts#L507](../scripts/cli.ts#L507), `package.json` `start`/`scan`.
- **Introduced by:** `3462b78` (merge `b675448` movea-oracle-invar).
- **What's wrong:** `compileSafeClaimRegex` misses three pattern classes:
  - **(1)** Overlapping unbounded atoms each wrapped in an unquantified group. The overlap state is reset at every `(` and `)`.
  - **(2)** Word runs joined by an optional non-overlapping atom. The optional atom resets the chain and is never re-armed.
  - **(3)** A JS empty or match-any class. The analyser treats `]` immediately after `[` or `[^` as a literal, so it swallows a following nested-quantifier group that V8 actually compiles.

  The linear-engine flag is enforced only when `KOVO_REQUIRE_HARDENED_NODE=1`, which only the Dockerfile sets. `npm start` and `npm run scan` run plain `node`, which also bypasses the cli.ts shebang flags. The fallback also does not engage for the `i`/`u` flags, though no current sink passes flags.
- **Evidence:** Without the flag, timings were roughly n⁴ for class 1 (about 7-12 s at 400 characters) and class 2 (about 7-20 s at 200-400 characters), and exponential for class 3 (several seconds at about 28 characters). With the flag, all three finish in milliseconds.
- **Attack path:** A worker verify-script header or jsonpath claim uses an accepted pattern against an exchange value of 30 or more word characters (a token or ETag). `evaluateClaims` runs synchronously on the host thread (verify-runner.ts L472).
- **Impact:** The host event loop wedges for minutes to hours, stalling every run, the UI and the broker, on non-Docker deployments, including the documented npm workflows.
- **Recommendation:**
  - Make the flag mandatory at startup and add it to the npm scripts.
  - Run untrusted regexes in the compute pool with a timeout.
  - Fix the analyser: carry state across group boundaries, treat optional atoms as transparent, and parse or reject `[]`/`[^]` with JS semantics.
  - Reject the `i`/`u` flags.
  - Add the three classes to the H-32 bypass corpus.
- **Related IDs:** H-32, R2-H-26.
- **Verification:** 3/3 high. Spot-check confirmed the resets at L413 and L432, verify-claims L1278/L1311, and that `package.json` `start` is `node scripts/serve.ts`.

### R3-H-12 — R2-H-24 residual: ProgramGraph extraction still runs on the host thread for every white-box run, and the extractors are quadratic

- **Kind:** fix-bypass (incomplete fix)
- **Category:** reliability
- **Location:** [../src/server/exec-recon-planner.ts#L1310](../src/server/exec-recon-planner.ts#L1310) (`seedCapabilityLedgerInvariants`; callers L2150, L1601, L4263; `collectBoundedRepoSourceFiles` L866-907); [../src/server/program-graph.ts#L252](../src/server/program-graph.ts#L252) (`findMatching`), [#L314](../src/server/program-graph.ts#L314) (`argsAtCall`), per-match uses L1101, L1191, L1437, L1564; compose `Host(` regex L3910 via [../src/server/phase0-recon.ts#L1001](../src/server/phase0-recon.ts#L1001).
- **Introduced by:** Merge `98edff7` (r2-ws19-graph-dos) left this caller on the main thread. The caller predates 98881b4.
- **What's wrong:** `98edff7` moved the snapshot and Phase-0 paths to `extractProgramGraphInWorker`, but `seedCapabilityLedgerInvariants` still synchronously reads up to 160 files of up to 128 KB each and calls `extractProgramGraph` on the event loop. `findMatching` scans to end of file on an unclosed delimiter, once per call-site match. Failed matches `continue` without consuming the route budget, which makes the work O(matches × size).
- **Evidence:** One 128 KB file of unterminated Express method-call openers took 1.7-2.7 s, with quadratic growth across 32/64/128 KB. 8 files took 20.5 s. FastAPI took about 2 s per 128 KB. At the 160-file cap that is roughly 6-7 minutes per seed.
- **Attack path:** A hostile repo is synced, a run starts, `runThreatModel` → `seedCapabilityLedgerInvariants` runs, and the main thread freezes.
- **Impact:** A host-wide stall (UI, broker, approvals, kill switch) for minutes on every run against the repo.
- **Recommendation:**
  - Make the seed async via `extractProgramGraphInWorker`, or reuse the snapshot graph.
  - Ban the synchronous exports in server paths.
  - Precompute a delimiter index, or cap each `findMatching` scan, and charge failed matches against the budget.
  - Bound the `Host(` capture and move compose finalisation into the worker.
- **Related IDs:** R2-H-24, H-33, M-53, R2-H-23.
- **Verification:** 3/3 high. Spot-check confirmed the synchronous `extractProgramGraph` call at L1310.

### R3-H-13 — One composite receipt supersedes, and so hides, unrelated confirmed findings through unbound, worker-declared upstream hop targets

- **Kind:** pre-existing-unreported (plus restore gaps in post-R2 fixes)
- **Category:** data-integrity
- **Location:** [../src/server/exec-verify.ts#L2801](../src/server/exec-verify.ts#L2801)-2843; `extractCompositeUpstreamEndpoints` L822-833; `isEndpointSubsetOfUpstream` L912-930; loopback equivalence L591-612; restore only at L3223-3236; missing restore at L2975-3030 and L3036-3093; [../src/server/composite-receipt.ts#L39](../src/server/composite-receipt.ts#L39), L199-229.
- **Introduced by:** Supersession dates from `9bdf36d`, before R2. The restore gaps remain after `867c25c` (merge `c5dd4cc`) and `ae1220d` (merge `01b9d4d`).
- **What's wrong:** After a confirmed composite (and after a confirming reverify), the code marks superseded every confirmed, non-floor finding whose endpoint is a subset of the composite's non-terminal hop targets. The match uses only the path template, a compatible method (missing or ANY matches anything) and an equivalent origin (any two loopback origins are equal). It checks no class, CWE, parameter or exchange citation. Non-terminal `hop.target` is free schema data and is never bound to the hop's cited exchanges. The integrity-mismatch and legacy reverify branches demote the composite without restoring its dependents.
- **Attack path:**
  - Benign: a BOLA chain whose setup hop lists objects from the same endpoint as an unrelated confirmed injection finding hides that finding.
  - Adversarial: a model lists extra upstream hop targets naming other workers' finding endpoints.
- **Impact:** Confirmed findings of any class disappear from the findings list and confirmed counts (model.ts L436, finding-codec L69/L656, store-projects). This can persist after the superseding finding is demoted.
- **Recommendation:**
  - Supersede only when an upstream hop cites the earlier finding's exchanges, the class or CWE matches or is a declared precondition, and origins match exactly.
  - Bind every `hop.target` to its cited exchanges.
  - Restore dependents on every non-confirmed exit.
- **Related IDs:** H-18, R2-H-16, L-35, H-12.
- **Verification:** 3/3 high. Spot-check confirmed L2801.

### R3-H-14 — Stamping provenance `floor` on pending deterministic proposals freezes them: replay verdicts are dropped and agent confirmations of the same fingerprint are suppressed

- **Kind:** fix-regression
- **Category:** correctness
- **Location:** [../src/server/exec-floor-lane.ts#L1371](../src/server/exec-floor-lane.ts#L1371)-1374; guards [../src/server/store-findings.ts#L1477](../src/server/store-findings.ts#L1477)-1484 and L1836-1844; `findDuplicateChainFinding` L1700-1752; verdict writes [../src/server/exec-verify.ts#L2416](../src/server/exec-verify.ts#L2416)-2421 and L1959; `envelopeTrust` L2370; `confirmationEvidenceFor` store-findings L944-946.
- **Introduced by:** `f15d20d` (merge `09a5126` fix-cred-followups).
- **What's wrong:** `recordDeterministicFinding` now upserts status `pending` authz_matrix (CWE-639) and sqli_boolean (CWE-89) proposals with `{provenance:'floor'}`. The store treats `floor` as "floor-confirmed and immutable":
  - `updateProposedFinding` refuses every update.
  - `upsertChainFinding` returns the existing row whenever the caller does not pass `floor`.

  The replay verifier it queues writes through exactly those methods without the option. A confirmed verdict (via `persistReplayConfirmation`) and a dismissed or inconclusive verdict are therefore both silently discarded, and the row stays `pending` forever. Later agent or kovo_verify confirmations with the same structural fingerprint dedupe onto the frozen row and are suppressed as `floor_preserved`. The pending rows also get `envelopeTrust` `host_persisted` and `backed:true`.
- **Attack path:** No attacker is needed. Every deterministic differential proposal reaches this path. One verifier noted that the caller (`runDeterministicInvestigation`) is reached in the no-model-profile fallback, not in `--no-llm`, which narrows the blast radius.
- **Impact:** IDOR and SQLi differential proposals can never be confirmed or dismissed, and agent confirmations of the same fingerprints are dropped. Real high-severity issues are under-reported. The "floor means host-confirmed" invariant breaks.
- **Recommendation:**
  - Use a distinct provenance (for example `floor_proposed`) for pending rows, or pass the row's provenance on the verifier's confirming write.
  - Scope the immutability guards, the `host_persisted` derivation and `backed:true` to confirmed floor rows.
  - Add a regression test: replay of a pending floor proposal confirms or dismisses it, and an agent confirmation is not suppressed.
- **Related IDs:** H-5.
- **Verification:** 2 high, 1 medium. A separate floor-engine candidate for the same issue was rated medium and is merged here. Spot-check confirmed L1369-1374 and store-findings L1477-1484.

### R3-H-15 — Composite proofs are filed on the terminal hop's worker-declared origin, not the origin the terminal exchange hit

- **Kind:** pre-existing-unreported
- **Category:** correctness
- **Location:** [../src/server/exec-verify.ts#L2534](../src/server/exec-verify.ts#L2534)-2545; fingerprint and dedupe L2629-2655; receipt row [#L1344](../src/server/exec-verify.ts#L1344); [../src/server/composite-receipt.ts#L39](../src/server/composite-receipt.ts#L39) and L597; [../src/server/terminal-oracle-registry.ts#L192](../src/server/terminal-oracle-registry.ts#L192)-270.
- **Introduced by:** Not attributable to a post-R2 merge. The R2-H-14/H-18 bind covers CWE only.
- **What's wrong:** `persistAgentScriptProof` takes the origin from `hops[terminal].target.origin` before any host-derived origin, and checks only that it is in the approved set. Nothing in the composite verifier, the sanitiser or the two-run agreement check compares a hop's declared origin with the signed transcript entry's `origin`. The endpoint is host-derived, but the asset, fingerprint, dedupe key and persisted receipt `target` use the declared origin.
- **Attack path:** In a multi-origin run, a script proves a real chain on origin A and declares origin B, either by mistake or because target content steered it. The finding is filed on B, possibly merged into B's existing finding. Retest then tracks A's state under B.
- **Impact:** A confirmed finding on an asset where nothing was verified, while the vulnerable origin goes unreported and remediation status attaches to the wrong asset.
- **Recommendation:**
  - Derive the origin from the terminal exchange's signed `origin`.
  - Reject hops whose declared origin, method or route disagrees with their cited exchanges.
  - Apply the same rule in `serializeCompositeProofReceiptRow` and `extractAgentProofTarget`.
- **Related IDs:** H-18, R2-H-14, R2-H-6.
- **Verification:** 2 high, 1 medium. Spot-check confirmed L2534-2545.

### R3-H-16 — The default-on StorageMaintenanceController purges, every 30 minutes, the exchanges cited by confirmed findings and receipts once they are older than 14 days

- **Kind:** fix-regression (makes L-12 live)
- **Category:** data-integrity
- **Location:** [../src/server/storage-maintenance.ts#L26](../src/server/storage-maintenance.ts#L26)-34, L277, L801; [../src/server/artifact-ttl.ts#L250](../src/server/artifact-ttl.ts#L250)-266 (candidate runs L249-252; protection L90-125); [../src/server/store-findings.ts#L516](../src/server/store-findings.ts#L516)-596; [../src/server/app-runtime.ts#L126](../src/server/app-runtime.ts#L126)-183; [../src/server/receipt-export.ts#L784](../src/server/receipt-export.ts#L784)-796.
- **Introduced by:** `5352132` (Merge arch-s3s4s5-maint).
- **What's wrong:** AppRuntime starts maintenance by default with a 14-day exchange TTL and `preserveConfirmedEvidence:true`. That flag protects only evidence IDs. Exchange pruning deletes every `broker_exchanges` row, its FTS rows and unreferenced blobs by `run_id` and `created_at`. It never checks `findings.exchangeIds` or receipt `exchangeIds`. Candidate runs skip only status `running`, so waiting and paused runs are swept too. Receipt and report export then skip the missing exchanges silently. The repo's own test (`tests/arch-s3s4s5-maint.test.ts:354`) asserts the deletion.
- **Attack path:** No attacker. Normal operation past 14 days loses the transcripts and reproducers of confirmed findings, irreversibly.
- **Impact:** Irreversible loss of the evidence behind confirmed findings in every default deployment, contradicting the flag's name.
- **Recommendation:**
  - Ship with exchange and artifact TTL off unless the operator configures retention.
  - Protect every exchange cited by findings, receipts, retests or facts, plus their blobs.
  - Skip all non-terminal runs.
  - Add a test that a receipt export is unchanged after a maintenance cycle past the TTL.
- **Related IDs:** L-12.
- **Verification:** 2 high, 1 medium. Spot-check confirmed the default policy L26-34 and the artifact-ttl L249-266 run filter and unconditional prune.

### R3-H-17 — Repo disk quotas are enforced only after a full checkout and skip anything nested deeper than 32 directories

- **Kind:** new-code (bypass of a newly added control)
- **Category:** reliability
- **Location:** [../src/server/github-repo-sync.ts#L1742](../src/server/github-repo-sync.ts#L1742)-1749; `measureDirectoryBytes` [#L471](../src/server/github-repo-sync.ts#L471)-472; clone at L1700; clone args L357-381; preflight L1520-1563; `stageReadableReposTree` [../src/server/worker-backend.ts#L1331](../src/server/worker-backend.ts#L1331)-1409.
- **Introduced by:** `26c5a34` (merge `2d530cc` arch-p4-repo-mgr).
- **What's wrong:** The 256 MiB per-repo and 1 GiB per-project quotas are checked only after a full `git clone` checkout into the data-dir filesystem (shared with kovo.sqlite, credentials and evidence). The only pre-clone guard is GitHub's compressed `size` field. It runs only for github.com and fails open on errors. A compression-amplified tree writes until ENOSPC or the 120 s timeout. `measureDirectoryBytes` returns 0 below depth 32, so deeply nested content passes both quotas and is persisted. There are no file or inode caps, and the walks are synchronous.
- **Attack path:** An attacker who controls the content of a repo the operator links or re-syncs (a third-party repo, or a contributor with push access) uses a high-fan-out or deeply nested tree. The operator syncs.
- **Impact:** The shared disk or inodes are exhausted, breaking DB and evidence writes for every run. The quota overrun persists in the nested variant and is copied again on each staged session.
- **Recommendation:**
  - Clone with `--no-checkout`, sum blob sizes and counts from `ls-tree`, and reject before checkout. Alternatively, clone into a size-limited filesystem.
  - Remove the depth cutoff and fail on over-depth.
  - Add file and inode caps.
  - Make the walks async.
  - Cap staging bytes.
- **Related IDs:** none. The R1 H-33/H-36 and M-51..53 items are CPU, not disk.
- **Verification:** 2 high, 1 medium (the repo is chosen by the operator). Spot-check confirmed `if (depth > 32) return 0` at L472 and the post-checkout check L1740-1749.

## Fix-stream scorecard

| Merge | IDs it claimed | R3 findings against it | Verdict |
|---|---|---|---|
| `d95922b` r2-ws2-proto-pollute | R2-C-2 | R3-C-1 | **regression** |
| `fed18e5` movec-egress-admit | R2-H-1, H-3/4, R2-H-19, C-1, H-14, H-2 | R3-H-1 (a, b) | **bypassable** |
| `874424b` movec-c1-h14-wire | C-1, H-14 | R3-H-5 (wire provenance ignored); H-14 dead code (duplicate, see below) | **bypassable** |
| `054344e` movea-proof-receipt | H-13 SameSite, H-15, clean kernel plane | R3-H-5, R3-C-3 (carried) | **bypassable** |
| `b46d801` r2-ws3-custody-rpc | C-3, R2-C-3/4/9, R2-H-4/8/22 | R3-C-3, R3-H-2, R3-H-4(a) | **bypassable** |
| `b675448` movea-oracle-invar | R2-C-5/7, C-7, R2-H-10/12/26 | R3-C-2, R3-C-4, R3-H-11 | **bypassable** |
| `851327f` movea-waveb-v8 | R2-C-3/8, R2-H-6/7, H-11 | R3-C-5(a), R3-H-4(c) | **bypassable** |
| `7ac5249` fix-audit-proof-a | proof-kernel and V8 soundness | R3-C-5(b, c) | **bypassable** |
| `ae87490` fix-golden-e2e | golden-chain restore (cap: provenance) | R3-H-4 (a, b, c) | **regression** |
| `9c36ce9` r2-ws7-provider-keys | R2-H-2, H-25, H-8 | R3-H-10 | **regression** |
| `98edff7` r2-ws19-graph-dos | R2-H-24, H-33 | R3-H-12 | **bypassable** (missed caller) |
| `1d11b32` arch-u1u4-ui-scale (+ `688cb93` consent PSL) | server PSL ranking | R3-H-8 | **regression** (vs. R2-H-5) |
| `e27cf42` movec-scope-lints | R2-H-5, H-39 | none (Phase-0 anchor holds; bypassed at consent by `1d11b32`) | clean |
| `5352132` arch-s3s4s5-maint | S3/S4/S5 maintenance, codec, migrations | R3-H-16 (migration reuse downgraded to medium) | **regression** |
| `2d530cc` arch-p4-repo-mgr | locking, disk quotas, git/symlink hardening | R3-H-17 | **bypassable** |
| `01b9d4d` r2-ws15-verify-ux | R2-H-16, H-18, R2-H-22 | R3-H-13 (no restore on integrity branch) | **bypassable** |
| `c5dd4cc` fix-audit-proof-b | finding lifecycle, export integrity | R3-H-13 (incomplete restore) | **bypassable** |
| `09a5126` fix-cred-followups | M-15 test, floor provenance | R3-H-14 | **regression** |
| `f66dcba` opt4-universal-auth (new feature) | — | R3-H-3, R3-H-6 (repeated) | new-code findings |
| `7a21793` r2-ws17-browser-v2 | C-8, H-8 placeholders | none at C/H (pool release downgraded to medium) | clean |
| `09a7d9b` r2-ws1-compose-rce | R2-C-1 | none | clean |
| `2b5378f` r2-ws11-redact-dos | R2-H-27/28 | none | clean |
| `dd452e1` fix-audit-admission | path canonicalisation, duplicate headers, redirect ScopePolicy | none (the R3-H-9 glob is pre-existing approval logic) | clean |
| `612f6cb` r2-ws14-actor-wedges / `622e81c` arch-o4-clock-stream / `9030dff` | R2-H-17/18, H-2, H-27, R2-H-24 snapshot | none at C/H (approval-wait clock downgraded to medium) | clean |
| `cb7c722` arch-u2-control-plane | escrow, strict CSRF guard | none | clean |
| `5192faf` arch-s1s2-store-db | tenant-scoped repo, partitioned blobs | none | clean |
| `cbae67f` movea-retest-norm | WS-12/13 | none | clean |
| `f6122a1` r2-ws9-auth-sessions | R2-H-3, H-23, H-2, R2-H-23 | none | clean |

## Duplicates of earlier rounds

- The H-14 fix is dead code: the signed `wireCredentialProvenance` is never read by the auth_bypass guard, and the session-jar identity is dropped from every verify-path fact ([../src/server/proof-receipt.ts#L2011](../src/server/proof-receipt.ts#L2011)) → **H-14** (still open; not re-reported).

## Downgraded candidates

- **Approval fingerprints use the raw path while admission consumes against the canonical path, so approved Tier-3 requests whose path normalises are never sent.** [../src/server/request-admission.ts#L1722](../src/server/request-admission.ts#L1722). **Medium.** It fails closed: a lost request and recall loss, with no bypass.
- **The browser_session refresher adopts Authorization headers and localStorage JWTs supplied by the page as the persona credential and persists them across runs.** [../src/server/browser-session-auth.ts#L1216](../src/server/browser-session-auth.ts#L1216). **Medium.** Poisoning needs content on the target origin and affects the target's own test persona. The exfiltration side is R3-H-3.
- **The transactional migration runner reuses `user_version` numbers that older binaries stamped with a different meaning.** [../src/server/store.ts#L242](../src/server/store.ts#L242). **Medium.** It affects only upgrades from specific old binaries, is operator-recoverable, and has no attacker.
- **Pausing the wall clock during approval waits lets parked sessions accumulate for up to 15 minutes each.** [../src/server/run-actor.ts#L2147](../src/server/run-actor.ts#L2147). **Medium.** The pile-up is bounded and the claimed impact was overstated.
- **Floor provenance on pending deterministic findings makes them immutable** (floor-engine variant). [../src/server/exec-floor-lane.ts#L1371](../src/server/exec-floor-lane.ts#L1371). **Medium** for this candidate, because it is limited to the no-profile fallback. The same root cause is kept at high as R3-H-14 by the majority on the subsystem-interactions candidate.
- **Pooled browser pages and their WebSocket tunnels outlive the lease, the run and kill-switch trips, and `releaseRun()` has no production caller.** [../src/server/scoped-browser.ts#L2974](../src/server/scoped-browser.ts#L2974). **Medium.** This is a resource and hygiene issue; no cross-run credential use was shown.
- **Late-OOB drain promotion bypasses the R2-H-11 guards (first-in-script or newest-stored carrier, fail-open time check).** [../src/server/exec-verify.ts#L2047](../src/server/exec-verify.ts#L2047). **Medium.** The callback is real; only the attribution to an endpoint is weak, and the window is narrow.

## Fix plan — ordered

One writer per file. Streams marked **∥** can run in parallel with every other ∥ stream once WS-1 has merged; WS-1 merges first because it stops a host-wide crash.

| # | Stream (branch) | File lease | Closes | Regression tests | Parallel |
|---|---|---|---|---|---|
| 1 | `agents/r3-node-hardening` | `Dockerfile`, `scripts/serve.ts`, `scripts/cli.ts`, `package.json`, `src/server/egress-gateway.ts`, `src/server/transport.ts`, `src/server/redact.ts` | R3-C-1; R3-H-11 (backstop: mandatory linear flag, npm scripts) | Broker under production flags against an in-memory socket returning the reserved header name: the request rejects and the process survives. Startup fails without the linear flag. | first, then ∥ |
| 2 | `agents/r3-oracle-invariants` | `src/server/oracle-invariants.ts` | R3-C-2, R3-C-4 (kernel-side base binding, volatile-field exclusion, stale-404 rule) | Idempotent PUT/DELETE double-submit rejected. Integer-coercion boolean triangle rejected in both boolean and statusBoolean modes. | ∥ |
| 3 | `agents/r3-v8-hydrate` | `src/server/v8-oracle-hydrate.ts`, `src/server/v8-oracle-families.ts` | R3-C-5 | Identical signed URL with and without an extra header rejected. Echoed-denial batch rejected. Request-body tenant field ignored. | ∥ |
| 4a | `agents/r3-verify-rpc-custody` | `src/server/verify-rpc.ts`, `src/server/verify-support.ts`, `src/server/verify-prove-handlers.ts` | R3-C-3 (raw kernel plane), R3-H-2, R3-H-4(a) (drop or record base-persona credentials), R3-H-5 (stamp explicit placement); host-minted boolean pairs for R3-C-4 | Secret-named echo does not confirm. True and false `awaitResult` predicates on a reflected sealed value give identical results. No case-folded fragment in stableDelta. Admin plus member-cap request rejected. | ∥ |
| 4b | `agents/r3-hostfact-placement` | `src/server/host-fact-log.ts`, `src/server/verify-claims.ts`, `src/server/proof-receipt.ts` | R3-C-3 (broadened placeholder guard), R3-H-5 (wire-provenance placement, bound SameSite) | End-to-end bearer persona plus cookie cap: CSRF not confirmed. | **serialised after 4a** (consumes the explicit-placement interface) |
| 5 | `agents/r3-composite-actor` | `src/server/composite-receipt.ts` | R3-H-4(b, c), hop-target binding for R3-H-13/R3-H-15 | Junk-credential control rejected. Browser-only root hop rejected. Hop target that disagrees with its cited exchange rejected. | ∥ |
| 6 | `agents/r3-exec-verify-identity` | `src/server/exec-verify.ts` | R3-H-13 (class-bound supersession, restore on all branches), R3-H-15 (host-derived origin) | Unrelated-class finding not superseded. Dependents restored on integrity mismatch. Composite filed on the transcript origin. | ∥ (merge after 5 for the binding helper) |
| 7 | `agents/r3-admission-staging` | `src/server/request-admission.ts`, `src/server/scope-policy.ts` | R3-H-1 (a, b) | Body built by `stagingProbeTag` on derived staging requires approval. Override field after 64 KiB requires approval and fails the lease. | ∥ |
| 8 | `agents/r3-approval-glob` | `src/server/approval-pattern.ts`, `src/server/store-runs.ts` | R3-H-9 | "Approve similar" on a glob-path card matches only the literal path. | ∥ |
| 9 | `agents/r3-provider-scrub` | `src/server/provider.ts`, `src/server/provider-stream.ts`, `src/server/persona-vault.ts` | R3-H-10 | A cookie whose value collides with a protocol word leaves role, enum and key fields byte-identical. | ∥ |
| 10a | `agents/r3-browser-session` | `src/server/browser-session-auth.ts` | R3-H-3, and the R3-H-6 launch site there | Refresher egress outside the persona allowlist is denied. The launch passes `chromiumSandbox:true`. | ∥ |
| 10b | `agents/r3-chromium-sandbox` | `src/server/scoped-browser.ts`, `src/server/persona-auth.ts`, `tests/v5-security-auth2.test.ts`, `tests/v5-security-authbrowser.test.ts` | R3-H-6 | Tests assert the launch option or final argv, not Kovo's args list. | ∥ |
| 11 | `agents/r3-safe-regex` | `src/server/safe-regex.ts` | R3-H-11 (analyser) | The three bypass classes are added to the H-32 corpus and rejected. | ∥ |
| 12 | `agents/r3-graph-host` | `src/server/exec-recon-planner.ts`, `src/server/program-graph.ts` | R3-H-12 | No synchronous `extractProgramGraph` in server paths (lint). Unterminated-opener file scales linearly. | ∥ |
| 13a | `agents/r3-ui-curl` | `src/components/curl-parser.ts`, `src/server/receipt-export.ts` | R3-H-7 | Stub-curl argv test with quote-breaking paths. | ∥ |
| 13b | `agents/r3-scope-ranking` | `src/actions.ts`, `src/components/run/views/consent.tsx` | R3-H-8 | Unlisted-vendor tenant seed pre-selects only `*.seedhost`. | ∥ |
| 14 | `agents/r3-floor-provenance` | `src/server/exec-floor-lane.ts`, `src/server/store-findings.ts` | R3-H-14; also the protected-exchange exclusion in `pruneExchangeRows` for R3-H-16 | Pending deterministic proposal is confirmed or dismissed by replay. Agent confirmation is not suppressed. | ∥ |
| 15 | `agents/r3-retention` | `src/server/storage-maintenance.ts`, `src/server/artifact-ttl.ts`, `src/server/app-runtime.ts`, `tests/arch-s3s4s5-maint.test.ts` | R3-H-16 | Receipt export unchanged after a maintenance cycle past the TTL. Paused runs skipped. | **serialised after 14** (store-findings.ts prune signature) |
| 16 | `agents/r3-repo-quota` | `src/server/github-repo-sync.ts`, `src/server/worker-backend.ts` | R3-H-17 | Fan-out or compressible tree rejected before checkout. Depth >32 counted or rejected. Staging byte cap. | ∥ |

**Serialization exceptions:**
- 4b follows 4a, because the placement interface lives in `verify-rpc.ts`.
- 15 follows 14, because they share `store-findings.ts`.
- 6 merges after 5, because the hop-binding helper lives in `composite-receipt.ts`.
- WS-1 goes first because it removes a remotely triggerable host crash.

Every other stream holds a disjoint lease and can start at once. Every code branch runs `scripts/worker-gate.sh` before merge.
