# Kovo Hunter — Claude audit round 4: new critical & high (2026-11-26)

**Method.** This round audited a read-only git worktree pinned at `09f9eeb` (branch `agents/claude-audit-r4`). Earlier rounds: round 1 ([CLAUDE_AUDIT.md](CLAUDE_AUDIT.md)) at `4f46973`, round 2 ([CLAUDE_AUDIT_R2.md](CLAUDE_AUDIT_R2.md)) at `98881b4`, round 3 ([CLAUDE_AUDIT_R3.md](CLAUDE_AUDIT_R3.md)) at `09a5126`, plus the earlier [SECURITY-REAUDIT-2026-11-22.md](SECURITY-REAUDIT-2026-11-22.md). About 77 commits have landed since round 3, and many `swarm-r3-*` merges claim to close R3 IDs. **Scope is new issues only.** A bypass of a fix for a known issue, or a new bug that a fix introduced, counts as new and names the known ID. Unchanged known issues are not re-reported.

1. **Hunting.** 14 area hunters covered the kernel class sweep, composite/V8 receipts, single receipts, R3 critical-fix bypasses, R3 high-fix bypasses, custody/verify-support, egress/admission, agent/model tools, recon/Phase 0, auth/browser, repo/patch/worker, orchestration/persistence, UI/control plane/scripts, and a sweep of new modules.
2. **Gap hunting.** 12 critic-driven gap hunters ran over 3 gap rounds. They covered the broker credential plane, finding persistence and dedupe, provider outbound telemetry, scoped browser/OOB, the host-fact-log kernel seam, warm-pool cross-run isolation, the patch Gate-6 composite retest, the finding status machine, report/SARIF export, finding monotonicity, planner dispatch/quarantine, and broker breaker/apex. **The search hit the gap-round cap while hunters were still finding issues. The tail is not exhausted.** Gap-round hunters produced 8 of the 35 kept candidates (R4-H-2, R4-H-8 to R4-H-12, R4-H-19 and R4-H-20). Treat this report as a lower bound.
3. **Verification.** Every candidate went to three adversarial lenses: refute/reachability, duplicate/root cause, and severity. A candidate was kept only if a majority upheld it, it stayed critical or high, and it was not a duplicate of R1, R2 or R3.

| Candidates | Kept (C/H) | Downgraded below high | Duplicates of R1–R3 | Refuted |
|---:|---:|---:|---:|---:|
| 42 | 35 | 7 | 0 | 0 |

After merging shared root causes, the 35 kept candidates become **6 critical (R4-C-1..6) and 20 high (R4-H-1..20)** findings. While writing this report I spot-checked every critical location and all 20 high locations against `09f9eeb` with grep/sed. All the anchors below were re-read at the snapshot. No benchmarks, Docker or network calls were run. Hunters' in-memory experiments used only pure functions, regexes, temp-dir stores and loopback stubs. No exploit or test payload strings appear in this document; probes are named by class.

## Executive summary

Ranked by risk:

1. **The proof kernel still accepts false "confirmed" verdicts, and three R3 critical fixes are bypassable or regressed.**
   - **R4-C-1:** sqli boolean and status-boolean triangles still accept worker-chosen predicate pairs. Any length or charset input validator, or an integer-coercing handler fed a negated or parenthesised standalone predicate, forges CWE-89. This bypasses **R3-C-4** (fix `0e8c6b0` in merge `9a15fcd`, status path `c9169d6` in `5b7b270`). The host-minted pair primitive exists but the kernel never requires it.
   - **R4-C-4:** business_logic accepts an invariant-*named* field as its own signal. Correct accumulator endpoints (add-to-cart, deposit, vote) and any receipt with an uncited intermediate write therefore confirm CWE-840. This is a **regression of R3-C-2** introduced by the fix's own new branch (`9a15fcd`).
   - **R4-C-5:** cryptographic_scope_replay derives "scope" from the route or the caller persona. Every ordinary mint-then-download or share-link flow confirms a cross-scope signature replay. This is a **regression of R3-C-5** (`520c0d2`), and the fix's own tests assert the false positive.
2. **The anti-reflection primitives are substring tests that the worker can steer (R4-C-2, R4-C-3).** The host-minted expression oracle hands the worker the operands and the expected output. It accepts the worker's own probes and fails open when a URL decode throws. Separately, the fingerprint echo strip is defeated by any target sanitizer that deletes characters. Together these reopen R2-C-6 and R2-H-10/H-16: SSTI, command injection and SQLi can be forged on any sanitize-and-reflect page.
3. **A new oracle ships with no binding at all (R4-C-6).** `signed_url_mint` (merge `d2e31d8`) confirms CWE-22 when two benign files sit in different folders or buckets. It confirms CWE-306 when the negative control is a 400 validation error. Its echo check fails open the same way as R4-C-2.
4. **Approval blast radius is misrepresented (R4-H-1).** The new Prefix and Host leases (merge `353d5ee`) are honoured at broker admission before the judge, with no high-risk path check on prefix leases. One click on a benign card pre-approves admin, billing and delete-path writes on a live target.
5. **Credential custody regressions.**
   - **R4-H-2:** the R3-H-10 needle quality gate (`a3debe9`) now drops weak operator persona passwords and short session cookies from every redaction path, including outbound model requests.
   - **R4-H-17:** the inbound stream sanitizer still rewrites protocol keys, which is the half of R3-H-10 the fix left untouched.
   - **R4-H-3:** the R3-H-3 refresher guards (`bdd280c`) are dead code because the only production caller never passes them.
   - **R4-H-4:** the R3-H-2 digest fix (`0ea460e`) missed the request plane and `prove.signedUrlMint`.
6. **Composite access-control kernel reopened by `d3dd1e5` sys-host-autodag (R4-H-5, R4-H-6).** Dynamic sibling-ID controls accept "denied on someone else's object, allowed on mine" as BOLA. Separately, dual-membership personas holding admin in one tenant are reclassified as low-privilege attackers.
7. **Run wedges and host-thread stalls.**
   - **R4-H-12, R4-H-13:** quarantined-origin steps and CQ-5 typed step outcomes strand steps in pending or ready, and the run never leaves investigation.
   - **R4-H-14:** the R3-H-1 fix (`cfa2215`) made the method-override scan quadratic over 4 MiB.
   - **R4-H-15, R4-H-16:** the new host-side `search_repo` and the post-graph scanners left behind by the R3-H-12 fix (`25df28d`) stall the event loop on untrusted repo content.
   - **R4-H-20:** OOB retention for pending tokens is now unbounded.
8. **False "fixed" and cross-run results.**
   - **R4-H-9, R4-H-10:** the new production Gate-6 composite retest (`19e3548`) replays hops without request bodies and maps any non-reproduction to "fixed". It also persists that verdict as the finding's latest Verify Fix even when the patch is rejected.
   - **R4-H-8:** the per-run repo snapshot is chosen from backend-global state (`f1aca6c`), so run B can confirm against run A's stale source.
9. **Resource controls bypassed.**
   - **R4-H-18:** `.gitattributes` checkout transforms amplify bytes on disk about 40x past the R3-H-17 pre-checkout quota (`8c5765c`).
   - **R4-H-19:** the cq-13a fail-closed redaction cap (`3098138`) is filled by ordinary rotating-cookie apps.

**R3 fix merges that are bypassable or regressed:** `9a15fcd` (R3-C-2, R3-C-4), `5b7b270` (status path of R3-C-4), `520c0d2` (R3-C-5), `0ea460e` (R3-H-2), `bdd280c` (R3-H-3), `a3debe9` (R3-H-10, both bypassed and regressed), `25df28d` (R3-H-12 residual), `8c5765c` (R3-H-17) and `cfa2215` (R3-H-1, DoS regression). **Other merges that introduced new C/H issues:** `d2e31d8`, `d3dd1e5`, `353d5ee`, `f37e2a9`, `f1aca6c`, `19e3548`, `af7c78d`, `011f9ce`, `3098138`, `4717aea`, `e517b6a` and `2662064`.

## New critical & high findings

### R4-C-1 — sqli boolean and status-boolean triangles still accept worker-chosen predicate pairs: input validators and negated/parenthesised empty-base predicates forge CWE-89

- **Kind:** fix-bypass (R3-C-4).
- **Category:** correctness.
- **Location:**
  - [../src/server/oracle-invariants.ts#L3050](../src/server/oracle-invariants.ts#L3050): `verifyBooleanTriangleBinding`, with its leading-operand check at [#L3167](../src/server/oracle-invariants.ts#L3167).
  - Parser: [#L2661](../src/server/oracle-invariants.ts#L2661) `TRAILING_NUMERIC_PRED_RE` and the empty-base branch at [#L2745](../src/server/oracle-invariants.ts#L2745).
  - The 4xx false arm is accepted at [#L3297](../src/server/oracle-invariants.ts#L3297) (`assessBooleanDifferential`, which rejects only 5xx) and [#L3908](../src/server/oracle-invariants.ts#L3908) (statusBoolean).
  - Kernel rules [../src/server/proof-receipt.ts#L717](../src/server/proof-receipt.ts#L717) (boolean) and [#L788](../src/server/proof-receipt.ts#L788) (status_differential) never require a host pair. `mintHostBooleanPair` is used only at [../src/server/verify-prove-handlers.ts#L574](../src/server/verify-prove-handlers.ts#L574).
- **Introduced by:** `0e8c6b0` (merge `9a15fcd` swarm-r3-oracle-invariants); status path `c9169d6` (merge `5b7b270`).
- **What's wrong:** The R3-C-4 fix binds the stripped base value across baseline, true and false arms, but the worker still writes both predicate clauses. Two independent shapes get through.
  - **(a) Validator asymmetry.** Nothing requires the true and false clauses to have equal length or the same character classes. `assessBooleanDifferential` accepts a 4xx false arm and counts its `$status` and error body as the structural difference. The status-only rule compares no bodies at all. On any endpoint with a length cap or a character allowlist, a false clause one character longer, or one using a comparison operator the allowlist rejects, gets a 400/422 while the true arm matches the baseline.
  - **(b) Empty-base negation/paren.** `TRAILING_NUMERIC_PRED_RE` captures an optional leading negation keyword or open paren outside the prefix. A standalone predicate therefore parses with base `''`, and `leadingOperand` records only the digits after that token. A negated false comparison (true) and the same comparison without negation (false) share base and operand, so the R3-C-4 empty-base rule passes. An integer-coercing handler maps the baseline and the keyword-led true arm to the same invalid ID, and maps the false arm to a real one. The operand check is also skipped entirely when either side is a string comparison.
- **Evidence:** Hunters ran in-memory tests with the real `assessBooleanDifferential`, `assessInjectionImpact` and `verifyReceipt`:
  - (a) A length-cap stub and a charset-validator stub each gave `satisfied:true` for both the boolean rule and the statusBoolean rule over two rounds.
  - (b) A parseInt stub gave `satisfied:true` with `trueMatchesBaseline:true` and changed paths that included `$status`.
  - Grep at the snapshot finds `hostBooleanPair` and `mintHostBooleanPair` only in verify-support.ts and verify-prove-handlers.ts (the opt-in placeholder path), never in the kernel.
- **Attack path:**
  1. The worker, or a target-steered model, picks any search, filter or ID parameter with a validator or integer coercion.
  2. Through the broker it sends baseline, true and false arms twice, labelling them with `evidenceRole` (copied from worker args at verify-rpc.ts L1136).
  3. It submits a boolean or status_differential receipt: a kovo_verify receipt, a `structural_diff` agent-script claim (proof-receipt.ts L3446), or a composite single_hop.
  4. The kernel confirms CWE-89, and replay reproduces it.
- **Impact:** Deterministic forged critical SQLi on safe parameterised endpoints, which covers almost every modern API. This is the class C-7 and R3-C-4 were meant to close.
- **Recommendation:** **Failure class:** the worker authors the evidence the oracle discriminates on ("worker-chosen differential pair"). **Systemic fix:**
  - Make the host-minted boolean pair mandatory in the kernel, the way `hostExpressionChallenges` and `hostTimingChallenge` are bound.
    - Stamp the pair `challengeId` on the exchanges the host sends.
    - Require the true and false values to equal the minted values byte for byte, with equal length and the same character multiset.
    - Reject unminted triangles for both the boolean and status_differential rules.
  - Reject empty-base standalone predicates outright.
  - Require a same-skeleton predicate prefix, implemented as one shared `canonicalPredicateSkeleton` used by the kernel and verify-support so the two parsers cannot drift.
  - Require the false arm to stay in the baseline status class. For the status-only rule, also require a swapped-length second pair to give the same verdict.
  - **worker-gate guard:** length-cap, charset-validator and integer-coercion stubs. Every triangle shape on those stubs must stay unconfirmed.
- **Related IDs:** R3-C-4, C-7.
- **Verification:** Two candidates, 3/3 critical each. Spot-check confirmed `TRAILING_NUMERIC_PRED_RE` at L2661, the empty-base return at L2745-2754, the operand-only check at L3167-3176, 5xx-only rejection at L3297, and statusBoolean at L3908.

### R4-C-2 — The host-minted evaluated-expression oracle is transferable: the worker receives operands and expected output, cites its own probes, and anti-reflection is a literal substring test that fails open on decode errors

- **Kind:** fix-bypass (R2-C-6).
- **Category:** correctness.
- **Location:**
  - [../src/server/proof-receipt.ts#L2779](../src/server/proof-receipt.ts#L2779): a transcript-wide challenge fallback whenever the entry has no `hostExpressionChallenge`.
  - [#L2748](../src/server/proof-receipt.ts#L2748): `requestTextOf` runs one whole-string decode and keeps the raw text on throw.
  - [#L2808](../src/server/proof-receipt.ts#L2808): the literal `includes` anti-reflection check.
  - [#L3404](../src/server/proof-receipt.ts#L3404): the worker-cited `host_evaluated_expression` receipt builder.
  - [../src/server/verify-claims.ts#L1592](../src/server/verify-claims.ts#L1592): a duplicate check over the raw path plus body, with no decoding.
  - [../src/server/verify-prove-handlers.ts#L1388](../src/server/verify-prove-handlers.ts#L1388): returns `hostMintedChallenges` with operands and `expectedOutput` to the worker.
- **Introduced by:** `2d21fdb` (Move A Part 3a, host-minted oracle). The claim kind came with `30e4978` / merge `d3dd1e5` (sys-host-autodag) and `c1e2b4e` (cq-4).
- **What's wrong:** The R2-C-6 guarantee depends on the worker being unable to produce the expected output without server-side evaluation. Four things break it.
  - The worker gets the operands and the output back from `prove.injection`.
  - No producer ever stamps `hostExpressionChallenge` on an exchange. Grep finds only host-fact-log copy-throughs, so every cited probe, including one the worker sent itself with `ctx.http`, is checked against every challenge in the transcript.
  - Anti-reflection is a contiguous-substring test. The worker can place the operand expression in plain text to satisfy `probeCarriesExpressionWithOperands`, and supply the product split by inert characters that a sanitizer deletes. Alternatively it can supply the product percent-encoded and add one malformed escape in a parameter both arms share. That makes the kernel's `decodeURIComponent` throw, so it keeps only the raw text, while the target decodes per parameter and reflects the digits contiguously.
  - The verify-claims copy of the check never decodes at all, so there are two divergent checks for one guarantee.
- **Evidence:** Two in-memory tests with the real `verifyReceipt` and `defaultHostMintedOracle`:
  - A tag-stripping echo stub gave `confirmed:true`, "Host-minted server-side expression evaluation confirmed (ssti)".
  - The malformed-escape variant was traced in node: the decode throws, `new URL` preserves the encoded form, and no contiguous output appears in the request text.
- **Attack path:**
  1. In each kovo_verify attempt, the script calls `ctx.prove_injection` only to mint two challenges, and reads their operands and outputs.
  2. It sends one benign control and two probes with `ctx.http` to any reflected parameter.
  3. It returns a `host_evaluated_expression` claim citing those IDs.
  4. The kernel confirms SSTI, command injection or sqli_error, and fresh operands are recomputed on each attempt.
- **Impact:** Forged critical injection findings on any app that reflects a parameter, including apps that only HTML-escape it. This defeats R2-C-6.
- **Recommendation:** **Failure class:** challenge-response proof whose challenge is transferable, combined with a raw-plane substring anti-reflection test. **Systemic fix:**
  - Make challenges non-transferable.
    - The host renders the expression into the probe itself and stamps `hostExpressionChallenge` on the fact at send time inside `handleProveInjection`.
    - The kernel requires `entry.hostExpressionChallenge === challenge` and deletes the transcript-wide fallback.
    - Never return `expectedOutput` to the worker.
  - Route anti-reflection through one shared carrier normalizer (see R4-C-3 and R4-C-6). It should decode per component, fail closed on decode errors, delete markup, zero-width and non-digit characters before the containment test, and reject when the output's digits appear in order in the request.
  - Make verify-claims call the kernel primitive instead of its own copy.
  - **worker-gate guard:** worker-sent probes citing a minted challenge must not confirm, and neither must sanitizing echo or malformed-escape stubs.
- **Related IDs:** R2-C-6, R2-C-9, R3-C-3.
- **Verification:** 2/2 critical, plus corroboration from the R4-C-3 candidate's expression half. Spot-check confirmed the fallback at L2779-2784, the decode catch at L2757, the includes check at L2808, the verify-claims check at L1605-1606, and the challenge return at L1388.

### R4-C-3 — The fingerprint echo strip is subtractive substring matching, so target-side deleting sanitizers (tag stripping, zero-width removal, NFKC) forge sqli/ssti/cmdi/xxe fingerprints

- **Kind:** fix-bypass (R2-H-10 / H-16).
- **Category:** correctness.
- **Location:**
  - [../src/server/oracle-invariants.ts#L3619](../src/server/oracle-invariants.ts#L3619): `matchStrippedInjectionFingerprint`, with its containment rule at [#L3643](../src/server/oracle-invariants.ts#L3643).
  - [#L3526](../src/server/oracle-invariants.ts#L3526): `requestEchoTokens`.
  - [#L3585](../src/server/oracle-invariants.ts#L3585): `stripRequestEchoes`.
  - [#L3450](../src/server/oracle-invariants.ts#L3450): `normalizeEchoComparable`, which has no deletion normalization.
  - Reached via the impact rule at [../src/server/proof-receipt.ts#L1289](../src/server/proof-receipt.ts#L1289).
- **Introduced by:** `3462b78` (Move A Part 1, WS-4 echo strip). Not closed by `9a15fcd` or `c9169d6`.
- **What's wrong:** Request tokens are built from raw and URL-decoded values only. Subtraction covers raw, URL, JSON, HTML-entity, case and whitespace variants. The containment rule refuses a fingerprint only if the matched text occurs inside a normalized request token. A worker that splits an engine-error fingerprint with characters the target deletes (an empty inline tag, a zero-width character, an NFKC-folding compatibility form) leaves no request token containing the contiguous text. The sanitized reflection then shows the contiguous fingerprint, and `assessInjectionImpact` treats it as an engine error.
- **Evidence:** In-memory runs with the real `assessInjectionImpact`/`verifyReceipt` against a strip_tags-style reflecting stub:
  - A split engine-error fingerprint with a benign same-route control gave `satisfied:true` and family sqli.
  - Zero-width and NFKC stubs also confirmed.
  - The same fingerprint sent verbatim was correctly rejected, so the guard works only for verbatim echoes.
- **Attack path:**
  1. The worker picks any page that sanitizes and reflects a parameter, such as a "no results for …" page or a display name.
  2. It sends a control and a single-parameter-different probe.
  3. It submits a sqli_error, ssti, command_injection or xxe impact receipt.
  4. The kernel confirms, and replay is deterministic.
- **Impact:** Forged runtime_confirmed injection findings on targets whose defensive posture is exactly "sanitize then reflect". The findings flow into SARIF, receipts and retests.
- **Recommendation:** **Failure class:** raw-plane anti-reflection by subtractive substring matching. **Systemic fix:**
  - Use one shared anti-reflection primitive, the same one as R4-C-2 and R4-C-6.
  - Before containment, deletion-normalize both planes: strip markup and zero-width characters, NFKC-fold, and remove non-alphanumerics. Refuse a fingerprint whose core token can be rebuilt from any request carrier.
  - Stronger: require absence of the fingerprint in a host-mutated second probe that keeps the injection construct but removes the fingerprint-class substring.
  - **worker-gate guard:** tag-strip, zero-width and NFKC reflecting stubs must not confirm.
- **Related IDs:** R2-H-10, H-16, R2-C-6, R3-C-3 (R3-C-3 was the redaction vector; this is a separate mechanism).
- **Verification:** 3/3 critical. Spot-check confirmed the token builders at L3526/L3585 and the containment rule at L3643.

### R4-C-4 — business_logic accepts an invariant-*named* field as its own signal: correct accumulator endpoints and receipts with an uncited intermediate write confirm CWE-840

- **Kind:** fix-regression (R3-C-2).
- **Category:** correctness.
- **Location:**
  - [../src/server/oracle-invariants.ts#L2126](../src/server/oracle-invariants.ts#L2126): the cumulative same-direction branch and the no-before-read branch at [#L2139](../src/server/oracle-invariants.ts#L2139), both in `findVerifiedRepeatedTransition`.
  - [#L2313](../src/server/oracle-invariants.ts#L2313): `repeatedHasSignal` is satisfied by `repeated.invariantFields` alone.
  - [#L773](../src/server/oracle-invariants.ts#L773): `BUSINESS_INVARIANT_FIELD_RE`.
  - Impact steps come from cited exchanges only, at [../src/server/proof-receipt.ts#L1229](../src/server/proof-receipt.ts#L1229).
- **Introduced by:** `0e8c6b0` (merge `9a15fcd` swarm-r3-oracle-invariants).
- **What's wrong:** The R3-C-2 fix added a "semantic double effect" requirement and kept the requirement for a boundary or invariant signal. Both are satisfied by the same thing: a leaf whose name matches the broad invariant regex (quantity, balance, points, votes, stock, total, credits and so on). The kernel's `ImpactInput` never passes host-declared `invariantFields`, so the regex is the only classifier, and the classifier doubles as the proof. Two shapes reach confirmed:
  - **(a) Accumulators.** Two identical, legitimately additive mutations (add item, deposit, top-up, upvote, restock) move the field the same direction twice. That is correct behaviour.
  - **(b) Uncited write.** The kernel never checks that the cited window is complete. An extra write between the second mutation and the final readback fabricates a same-direction shift on an idempotent PUT. With no pre-first readback, any change to an invariant-named field that differs from the request literal is enough. This is the residual R3 noted in passing, now carried by the fix's own branch.
- **Evidence:** Hunters ran in-memory with the real `assessBusinessLogicImpact` and `verifyReceipt`, one member actor and one tenant:
  - A cart add-item twice, a wallet deposit twice and a quantity increment twice all gave `satisfied:true`, `boundary:false`, `oracleDeclared:false`, and protectedFields equal to the invariant leaf. The receipt form gave `confirmed:true`.
  - A PUT with an uncited third write gave `satisfied:true`.
  - The same shapes with a non-invariant field name gave `false`.
- **Attack path:**
  1. An ordinary double-submit recipe, or a worker, sends the same additive request twice with readbacks before, between and after. For variant (b), it adds one uncited write.
  2. It cites the first mutation as control and the second as probe in a business_logic or invariant_violation impact receipt.
  3. The kernel confirms, and the result reproduces.
- **Impact:** False confirmed business-logic findings on correct e-commerce, wallet, quota and social APIs at scale. This reopens R3-C-2 and R2-C-7(c), both critical.
- **Recommendation:** **Failure class:** a heuristic classifier used as proof, combined with a worker-selected evidence window. **Systemic fix:**
  - Use one shared "repeated transition requires a refusal or bound control" primitive, used by `assessBusinessLogicImpact` and the race_burst floor recipe. A double effect counts only when one of these holds:
    - a host-recorded boundary (a peer denial, or a single-use or limit control that refused);
    - a host-declared invariant with an explicit bound (single-use, floor, cap) that the second effect crosses.
  - Field names may classify but never satisfy.
  - Enforce cited-window completeness from HostFactLog seq ordering: reject a receipt if an uncited mutating exchange on the same resource falls inside the cited window.
  - Drop the no-before-read rule, and require equal-magnitude deltas.
  - **worker-gate guard:** add-to-cart twice, deposit twice and the uncited-write PUT must all be rejected.
- **Related IDs:** R3-C-2, R2-C-7, C-6.
- **Verification:** Three candidates, all 3/3 critical. One verifier noted that variant (b) needs deliberate cherry-picking and could be argued high; variant (a) needs no intent. Spot-check confirmed L2126-2143, L2312-2328 and the regex at L773.

### R4-C-5 — cryptographic_scope_replay derives "scope" from the route or the caller persona, and never provenance-checks the issuance: every working signed-link feature confirms a cross-scope signature replay

- **Kind:** fix-regression (R3-C-5).
- **Category:** correctness.
- **Location:**
  - [../src/server/v8-oracle-hydrate.ts#L976](../src/server/v8-oracle-hydrate.ts#L976): `hostScopeOf`, with the route fallback and actor embedding at L980-983. The asymmetric `hostDstTenant` is at [#L974](../src/server/v8-oracle-hydrate.ts#L974).
  - [../src/server/v8-oracle-families.ts#L542](../src/server/v8-oracle-families.ts#L542): denies only when tenant and scope are both equal. The same-identity guard at [#L544](../src/server/v8-oracle-families.ts#L544) runs only when the routes are equal.
  - [../src/server/composite-receipt.ts#L476](../src/server/composite-receipt.ts#L476): `verifyAttackerProvenance` checks only hop exchanges and `extraIds`, never records named only by `oracleInput`.
  - [../tests/r3-v8-hydrate.test.ts#L213](../tests/r3-v8-hydrate.test.ts#L213): the cross-route and cross-persona positive cases that enshrine the false positive.
- **Introduced by:** `158b9d7` (merge `520c0d2` swarm-r3-v8-hydrate). The route fallback was carried over from `fc7d8d6` (`851327f`).
- **What's wrong:** After R3-C-5 removed request-plane scope, the scope falls back to `tenant:route`, or `tenant:actor:route` when the issuance and replay personas differ. Both dimensions differ by construction in benign traffic.
  - **(a) Different routes.** A mint or share route and the download route always differ. A single persona minting a link, sending a tampered-signature 403 and then the valid download confirms `cross_scope_replay`.
  - **(b) Different personas.** A byte-identical signed URL fetched by two personas confirms `cross_scope_replay`, or `cross_tenant_scope_replay` when the tenants differ. A signed URL is a bearer capability, so this is correct behaviour.
  - **(c) Uncited issuance.** `oracleInput` may name an issuance exchange that no hop cites. That exchange skips the forbidden-persona check, so "admin's own export link, opened by a member" confirms. This is an H-11 rule gap.
- **Evidence:** In-memory tests with `signHostRecord`, `HostFactLog` and `defaultTerminalOracleRegistry`, plus a full one-hop `verifyCompositeReceipt` (the `composite.verify` path, `strictHostDerivation:true`):
  - The single-persona mint-then-download flow gave `confirmed:true`, with a sourceScope on the share route and a targetScope on the download route.
  - The admin-issued, member-fetched flow gave `confirmed:true`.
  - At `09a5126` the uncited cross-persona case returned `same_tenant_and_scope_not_replay`.
- **Attack path:** The worker uses any share, export, invite or verify link as designed. It records the issuance, one tampered-signature 403 and the redemption. It then calls `ctx.prove_composite` / `composite.verify` with `oracleFamily` `cryptographic_scope_replay` naming the three IDs. The result reproduces on retest.
- **Impact:** Forged critical CWE-347 "signature replayed across scope/tenant" findings on essentially every app with signed links.
- **Recommendation:** **Failure class:** an authorization dimension inferred from a non-authorization attribute (route, caller identity). **Systemic fix:**
  - Use one shared host-attested authorization-dimension primitive for all V8 families. Scope is what the signature covers.
  - Confirm only when the replay applies the issued signature to a *different signed resource* (canonical non-auth path or query, or a host-attested entity or tenant) from the one it was minted for.
  - Deny caller-only differences and route-only differences as `same_principal_not_replay`.
  - Derive the source and destination tenant in the same order.
  - Run attacker provenance over every exchange that `oracleInput` names or `hydrateRole` hydrates, through one shared "cited records" collector.
  - Flip the two positive cases in `tests/r3-v8-hydrate.test.ts`.
  - **worker-gate guard:** single-persona mint→download, two-persona identical URL, and admin→member must all be rejected.
- **Related IDs:** R3-C-5, R2-C-8, C-4, H-11.
- **Verification:** Three candidates, all 3/3 critical. One verifier confirmed the route-fallback variant was already latent at `09a5126`. It is still reported as the remaining path to the same false confirm after the R3-C-5 fix. Spot-check confirmed `hostScopeOf` L976-983, the deny at L542, the route-gated guard at L544-548, and the provenance loop at L476-499.

### R4-C-6 — The new `signed_url_mint` oracle has no input binding: benign multi-folder presign endpoints confirm CWE-22, a 400 control confirms CWE-306, and the echo check fails open

- **Kind:** new-code.
- **Category:** correctness.
- **Location:**
  - [../src/server/verify-support.ts#L1459](../src/server/verify-support.ts#L1459): `assessSignedUrlMintDifferential` Variant A, with the escape decision at [#L1485](../src/server/verify-support.ts#L1485).
  - [#L1430](../src/server/verify-support.ts#L1430): any 4xx counts as the Variant B control.
  - [#L1305](../src/server/verify-support.ts#L1305): `isSignatureOrUrlEchoedFromRequest`, which decodes the whole string and keeps the raw text on throw.
  - [#L1449](../src/server/verify-support.ts#L1449): only the probe arm is echo-filtered.
  - [../src/server/verify-prove-handlers.ts#L1508](../src/server/verify-prove-handlers.ts#L1508): `handleProveSignedUrlMint`, which records `confirmed` with `replayMode:'fresh_clean_replay'` at L1580 even though nothing is replayed.
  - [../src/server/proof-receipt.ts#L635](../src/server/proof-receipt.ts#L635) and [#L3192](../src/server/proof-receipt.ts#L3192): the receipt route and builder re-run the same assessor.
  - [../src/server/verify-claims.ts#L1533](../src/server/verify-claims.ts#L1533): the `composite_receipt` claim acceptance.
- **Introduced by:** `712927d` (merge `d2e31d8` swarm-fix-signed-url-oracle).
- **What's wrong:**
  - **Variant A (key_traversal).** After 2xx on both arms, the same canonical route (query stripped), differing request text and differing signatures, a host, bucket or parent-prefix difference alone confirms. Signatures always differ for distinct keys. Nothing requires:
    - a traversal or separator construct in the probe (only the nested-dir sub-branch reads the request);
    - the same persona on both arms;
    - an entitlement boundary;
    - an ablation arm.
  - **Variant B (unauth_write_mint).** It accepts a 400 validation error as the negative control, so intentionally public presign endpoints confirm.
  - **The echo check fails open.** It runs one `decodeURIComponent` over the whole request text and keeps the raw text on throw. One malformed escape elsewhere, or a JSON unicode escape in a body, hides a worker-crafted URL that the target reflects. The control arm is never echo-checked at all. That lets the worker *forge* either variant on any reflecting parameter.
- **Evidence:** In-memory runs of the real assessor:
  - Same user: file 101 under one folder and file 102 under another gave `confirmed:true`, `parent_prefix_escape`. Different buckets gave `host_escape` or `bucket_escape`.
  - Anonymous presign with a 400 "filename required" control gave `unauth_write_mint`.
  - A loopback run with a real `RequestBroker` and `VerifyRpcServer` against an echo-only `/search` stub: `prove.signedUrlMint` returned `confirmed:true`, and `evaluateClaim` returned `passed:true`.
- **Attack path:** The worker calls `ctx.prove_signed_url_mint` (RPC `prove.signedUrlMint`, no feature gate, verify-rpc.ts L575), or emits a `composite_receipt`/`impact` claim with a signed_url class. It cites two ordinary download-link requests, or a validation-error control plus a public presign call, or two crafted reflections. Both attempts confirm.
- **Impact:** False and forgeable confirmed CWE-22 and CWE-306 at scale. Almost every app serving S3, GCS, Azure or R2 links uses more than one prefix.
- **Recommendation:** **Failure class:** an oracle that decides from response text with no binding to the probe's own input, plus fail-open decoding. **Systemic fix:**
  - Bind the escape to a host-minted traversal or separator construct in the probe's single differing parameter, with an ablation arm that stays in-prefix.
  - Require the same persona on both arms. Treat host and bucket differences as non-evidence.
  - Variant B needs an anonymous 401/403 on the same route and body.
  - Echo-check both arms through the shared per-component, fail-closed carrier normalizer (R4-C-2, R4-C-3).
  - Never stamp `fresh_clean_replay` without a replay.
  - **worker-gate guard:** two-folder download, 400-control presign, malformed-escape echo and JSON-unicode echo must all be rejected.
- **Related IDs:** R3-C-3, R2-C-9 (same fail-open decode class); no prior ID for this oracle.
- **Verification:** Two candidates. The benign-binding candidate went 2/3 critical and 1/3 high (that verifier argued "wrong inference from real traffic"). The echo/forgery candidate went 3/3 critical. Merged at critical. Spot-check confirmed L1305-1313, L1430, L1449, L1484-1498 and L635.

### R4-H-1 — Prefix and Host "scoped approval" leases are honoured at broker admission before the judge; prefix leases skip the high-risk exclusion the UI promises

- **Kind:** new-code.
- **Category:** security.
- **Location:**
  - [../src/server/store-runs.ts#L1764](../src/server/store-runs.ts#L1764): `leaseAuthorizes` step 2 (prefix), which has no `isHighRiskOrExternalMutationPath`. Step 3 (host) at [#L1779](../src/server/store-runs.ts#L1779) uses only the path-token list.
  - [../src/server/request-admission.ts#L1698](../src/server/request-admission.ts#L1698): `checkLease` sets `contractApproved` before `isStateChangeApproved` (~L1809).
  - The prefix pattern is stored without a `source` at [../src/server/store-runs.ts#L1893](../src/server/store-runs.ts#L1893). [../src/server/approval-pattern.ts#L251](../src/server/approval-pattern.ts#L251) defaults a missing source to `operator_explicit`, which feeds Stage 1B at [../src/server/approval-judge.ts#L924](../src/server/approval-judge.ts#L924).
  - [../src/domain.ts#L158](../src/domain.ts#L158) derives a one-segment prefix.
  - UI copy: [../src/components/run/views/queue.tsx#L165](../src/components/run/views/queue.tsx#L165) and L800-808.
  - The guard that exists but is bypassed: [../src/server/run-actor.ts#L2133](../src/server/run-actor.ts#L2133).
- **Introduced by:** `e9e5ffd` (merge `353d5ee` swarm-ux-approval-scopes).
- **What's wrong:** High-risk exclusions are applied when a lease is granted (to the clicked card and to pending cards) and when run-actor reuses a lease. They are not applied when broker admission matches a future request against the lease, and broker admission is the authoritative path.
  - **Prefix lease.** A two-segment card path derives a `/api/**`-style prefix, and step 2 matches any same-method request under it. That includes admin, role, billing and delete-verb routes that `isHighRiskOrExternalMutationPath` itself classifies as high-risk.
  - **Host lease.** It relies on a path-token denylist that misses many destructive verbs, and it never inspects GraphQL or JSON-RPC mutation bodies.
  - **Override.** A lease hit also overrides `readonly_environment` through the `approval_lease:override` branch.
  - This is a dual-path drift: a strict gate in run-actor and a weak gate in admission.
- **Evidence:** An in-memory temp-dir Store and `RequestAdmissionEngine`, Tier 3 auto_review, with a counter on `isStateChangeApproved` calls:
  - After one Prefix approval of a benign notes POST, admin-role, billing-refund and delete-action POSTs returned `allowed_approval_lease` with 0 judge calls.
  - After a Host approval, account-close, order-cancel and user PATCH requests behaved the same way.
  - Without the lease, the same requests required approval and called the judge.
- **Attack path:** The worker sends a benign write, the operator clicks Prefix or Host trusting the "non-high-risk" copy, and the worker then sends privilege, billing or destructive writes under the prefix or the origin. These go to the live target with no judge and no card.
- **Impact:** Destructive, financial and privilege-changing requests reach live targets without review, after one click whose blast radius the UI misstates. The bypass persists for the rest of the scope revision and applies across personas.
- **Recommendation:** **Failure class:** admission dual path, where enforcement and consent copy have drifted apart. **Systemic fix:**
  - Use one lease-eligibility predicate in approval-pattern.ts and evaluate it at match time in all three `leaseAuthorizes` steps and in judge Stage 1B. The same predicate should drive the UI buttons and copy.
    - Apply the high-risk path check to prefix leases.
    - Refuse GraphQL, JSON-RPC and body-level destructive mutations on prefix and host leases.
    - Send any deterministic high-risk classification to `isStateChangeApproved`.
    - Never override `readonly_environment`.
  - Persist an explicit `source` on stored patterns and default missing ones to `card_path`.
  - Require at least two fixed prefix segments.
  - Delete the duplicate gating in run-actor.
  - **worker-gate guard:** with a prefix or host lease active, a high-risk path and a GraphQL mutation must both call the judge.
- **Related IDs:** R3-H-9, R3-H-1, M-1, M-55. The persona-binding sub-point repeats M-1 and is not counted as new.
- **Verification:** Three candidates, all 3/3 high. Verifiers agreed the prefix half is the confirmed core and the host half is weaker. Spot-check confirmed L1764-1787 and the `checkLease` definition at L1698-1701.

### R4-H-2 — The R3-H-10 needle quality gate is applied to the persona's own primary credential: weak passwords and short non-auth-named session cookies are no longer redacted on any path

- **Kind:** fix-regression (R3-H-10).
- **Category:** security.
- **Location:**
  - [../src/server/persona-vault.ts#L1949](../src/server/persona-vault.ts#L1949): the `personaSecrets` push gate.
  - [#L681](../src/server/persona-vault.ts#L681): `isAcceptableSecretNeedle`, which rejects values under 8 characters, lowercase values under 12, dictionary words and low-entropy values.
  - [#L697](../src/server/persona-vault.ts#L697): the cookie-name and entropy rule; `addCookieHeaderSecrets` at L708-728 skips the full header when no pair qualifies.
  - The divergent policy: [../src/server/verify-rpc.ts#L386](../src/server/verify-rpc.ts#L386) `getKernelSecrets` still adds raw values of 4 or more characters.
- **Introduced by:** `2fea2dc` (merge `a3debe9` swarm-r3-provider-scrub).
- **What's wrong:** The gate was meant for heuristic needles. It now also filters `persona.secret`, `secretHistory` and the minted session value. `personaSecrets` is the single needle source for:
  - broker exchange redaction (`collectSecrets`, broker.ts L1846);
  - worker tool-result scrubbing and the outbound provider scrub (execution.ts L1322, which feeds agent-session `resolveLiveSecrets`);
  - artifact and event redaction;
  - receipt, SARIF and report exports.

  The protocol-collision problem this gate addressed is already solved on the provider path by the content-only scrub plus the integrity check.
- **Evidence:** In memory with the real module:
  - A login persona with a dictionary-class password yielded 0 needles.
  - A bearer persona with a 6-character token yielded 0.
  - A cookie persona with a generic name and a 12-hex-character value yielded 0.
  - At `2fea2dc^` all three were registered.
- **Attack path:** The operator configures a typical weak test persona. The target reflects the credential in an unkeyed form: an IDOR or union-style row dump, a CSV export, a non-standard field name, or a bare echoed cookie value. Keyed forms are still caught by redact.ts patterns. The raw value reaches the worker tool result, the OpenRouter request (on that call and on every history replay), persisted artifacts and exports.
- **Impact:** An operator-supplied credential crosses the model and provider trust boundary and lands in plaintext in the DB and exports, silently. It is conditional on a weak credential plus an unkeyed reflection, which is why it is high and not critical.
- **Recommendation:** **Failure class:** needle-policy drift between paths, with no provenance on needles. **Systemic fix:**
  - Use one needle builder with provenance tiers. Primary operator credentials (persona secret, history, session value, every value in the configured Cookie header) are always exact needles with a minimal floor. The quality gate applies only to heuristic or derived needles.
  - Make `getKernelSecrets` and `personaSecrets` share that builder.
  - **worker-gate guard:** short, lowercase and low-entropy primary credentials yield needles, and a broker exchange reflecting one is redacted before it reaches a tool result or a provider request.
- **Related IDs:** R3-H-10, H-8.
- **Verification:** 3/3 high (one verifier adjusted it down from critical). Two other hunters' versions of this issue were downgraded to medium by their verifiers, because redact.ts keyed backstops narrow the leak; see "Downgraded candidates". The majority across all lenses holds high. Spot-check confirmed the push gate at L1947-1949.

### R4-H-3 — The R3-H-3 fix is unwired: the production refresher never passes `modifiedPaths`, `verifyPathModifiedByRun` or `scopePolicy`, so run-planted script still runs with the real session and the project routeDenylist is not enforced

- **Kind:** fix-bypass (R3-H-3).
- **Category:** security.
- **Location:**
  - [../src/server/persona-auth.ts#L2574](../src/server/persona-auth.ts#L2574): the only production `refreshBrowserSession` call.
  - Dead guards in browser-session-auth.ts: [#L2394](../src/server/browser-session-auth.ts#L2394) (modified-path refusal), [#L571](../src/server/browser-session-auth.ts#L571) (scope intersection), [#L649](../src/server/browser-session-auth.ts#L649) (routeDenylist, applied only when `policy.scopePolicy` is set; no method gating).
- **Introduced by:** `819dc8d` (merge `bdd280c` swarm-r3-browser-session). The caller was not touched there or in `179137f`/`6438222`.
- **What's wrong:** The fix added three primitives as *optional* arguments. The only caller supplies none of them. Grep finds `modifiedPaths` and `verifyPathModifiedByRun` only inside browser-session-auth.ts, and `scripts/unwired-baseline.json` lists `isVerifyPathModifiedByRun` and `BrowserSessionRefreshBlockedError` as unwired.
  - Third-party exfiltration is now closed by the origin allowlist.
  - Still open: host Chromium loads the persona's storageState with JavaScript enabled on the auto-captured `verifyPath` every 30-240 s and on reauth. Content the run itself planted can then issue any-verb requests to denylisted routes with the real session, and can copy transformed tokens into target state the worker later reads.
- **Evidence:** The argument list at persona-auth.ts L2574-2585 has no such keys. `isVerifyPathModifiedByRun` returns false when `modifiedPaths` is undefined.
- **Attack path:** A Tier-2/3 worker performs the stored or second-order probing the product supports, so that content renders at `verifyPath`. Within one refresh interval, or after inducing a 401, the refresher runs that content. It makes unapproved, untiered writes, including to denylisted routes, and launders tokens past exact-needle scrubbing.
- **Impact:** Unattended execution of run-planted code under the operator's real session. Tier, approval and routeDenylist controls are bypassed, and credentials leak to the worker via target state.
- **Recommendation:** **Failure class:** a security primitive landed as an optional caller argument, which leaves it unwired. **Systemic fix:**
  - Make the refresher's inputs host-derived and mandatory. `authenticateBrowserSession` resolves the run's mutated paths from broker write exchanges and the project ScopePolicy, and `refreshBrowserSession` fails closed without them.
  - Block non-GET/HEAD requests to target origins in the refresher unless they go to an approved IdP token endpoint.
  - Validate browser_session `originAllowlist` against the project scope at persona creation.
  - **worker-gate guard:** a contract test drives `PersonaAuthenticator.authenticateBrowserSession` with a stub launcher and asserts that `scopePolicy` is passed, a denylisted route is aborted, and a run-mutated `verifyPath` raises `BrowserSessionRefreshBlockedError`. Also fail check-unwired when a security primitive appears in the baseline.
- **Related IDs:** R3-H-3, H-8, H-2.
- **Verification:** Two candidates, 3/3 high each. Spot-check confirmed the call at L2574-2585.

### R4-H-4 — The R3-H-2 digest fix is incomplete: request-plane `bodySha256`/`bodyBytes` cover raw injected sealed values, and `prove.signedUrlMint` returns raw response digests

- **Kind:** fix-bypass (R3-H-2).
- **Category:** security.
- **Location:**
  - [../src/server/verify-rpc.ts#L1050](../src/server/verify-rpc.ts#L1050): `applyCapabilityInjection` hashes `scrubKernel(nextBody)`, and the kernel sanitizer has no vault values (L399).
  - The digest is returned unchanged by `transcript.get` at [#L583](../src/server/verify-rpc.ts#L583).
  - [../src/server/verify-prove-handlers.ts#L1489](../src/server/verify-prove-handlers.ts#L1489): `exchangeSummaryFromTranscript`, via the existing-ID branch at L1532-1536.
- **Introduced by:** The request-plane line predates R3 and was missed by `303dc87` (merge `0ea460e`). `exchangeSummaryFromTranscript` is new in `712927d`.
- **What's wrong:** After inline handle injection, the request digest and byte length cover the plaintext sealed value. The worker wrote every other byte of the body, so the digest is an exact offline guess-check and the length narrows the search. `capability.seal` extracts from raw pre-redaction bytes, so the worker can seal a field it only ever saw as redacted. `toPublicCapabilityMeta` deliberately strips sealed-value digests, and this path undoes that intent. The signedUrlMint summary brings back the reflected-value response digest oracle that R3-H-2 removed.
- **Evidence:** A loopback run with a real `RequestBroker` and `VerifyRpcServer`: seal a heuristically redacted field, send the worker's own template with the handle inline, then `transcript get`. `record.request.bodySha256` equalled the hash of the template filled with the raw secret.
- **Attack path:** Seal an OTP, reset code or PIN-like value. Inject it into any request. Read the digest. Brute-force it offline in the container.
- **Impact:** Blind custody (I3) breaks for low-entropy target secrets. High-entropy tokens stay safe in practice, which is why this is high.
- **Recommendation:** **Failure class:** worker-facing digests computed over host-only plaintext. **Systemic fix:**
  - Use one "worker-visible digest" primitive, applied in `scrubRecord` to every `bodySha256`/`bodyBytes` field on both request and response sides, across `exchangeView`, transcript get/list, `prove.*` summaries and async results (`observedValueDigests`). Each digest is either computed over vault-scrubbed text or is a host-keyed HMAC.
  - Route `exchangeSummaryFromTranscript` through `exchangeView`.
  - **worker-gate guard:** no worker-facing digest equals the hash of any string containing a vault value.
- **Related IDs:** R3-H-2, R2-C-4, C-3.
- **Verification:** 3/3 high. Spot-check confirmed L1050-1053.

### R4-H-5 — Dynamic sibling-ID control matching (`allowDynCtrl`) accepts "denied on someone else's object, allowed on mine" as BOLA/IDOR/BFLA, and the auto-DAG supplies the required edge for free

- **Kind:** new-code (regression of the R2-H-7(c) closure).
- **Category:** correctness.
- **Location:**
  - [../src/server/composite-receipt.ts#L654](../src/server/composite-receipt.ts#L654): `allowDynCtrl` (two or more hops plus any verified edge into the terminal hop), and the non-exact fallthrough at [#L660](../src/server/composite-receipt.ts#L660).
  - The actor-check skip when the terminal consumes a DAG cap, at [#L668](../src/server/composite-receipt.ts#L668).
  - [../src/server/composite-autodag.ts#L301](../src/server/composite-autodag.ts#L301): `matchesNormalizedCtrlPath`, which checks route shape only. Edge inference from consumed caps is at [#L202](../src/server/composite-autodag.ts#L202).
  - The fix's own positive test: [../tests/sys-host-autodag.test.ts#L617](../tests/sys-host-autodag.test.ts#L617).
- **Introduced by:** `30e4978` (merge `d3dd1e5` sys-host-autodag).
- **What's wrong:** At `09a5126` the terminal control had to hit the exact same path. Now a denied control on any sibling dynamic ID of the same route shape counts. Nothing binds the control to the same object, owner or tenant as the terminal exchange. Correct per-object RBAC (own object 200, foreign object 403) therefore satisfies `hasCleanDeniedCtrl`. The edge can come from the auto-DAG's substring-matched consumed caps, with `causalEdges: []`. With a DAG cap, the control may even come from a different persona. Access-control classes outside the cross-tenant regex (`broken_access_control`, `bfla`) confirm even with the attacker's own tenant marker in the body.
- **Evidence:** In-memory `verifyCompositeReceipt` with honest data: a list, then a GET of the attacker's own object, plus a 403 on a foreign ID. bola, idor, broken_access_control, bfla and cross_tenant_read all gave `confirmed:true`. The same scenario at `09a5126` was rejected with "Missing clean denied control".
- **Attack path:** Read your own object from a list, try a foreign ID, get 403, and submit a two-hop composite. A model left alone produces exactly this sequence.
- **Impact:** False confirmed authorization bypasses at scale on correctly secured multi-object APIs.
- **Recommendation:** **Failure class:** control binding by path pattern instead of host-derived object identity. **Systemic fix:**
  - Use one authoritative control-binding primitive. The terminal control must target the same host-derived object (an exact path, or an entity the host derived from the exchanges) with the same credential identity.
  - Sibling-ID controls need a positive same-owner readback.
  - Remove the `!termUsesDagCap` actor skip.
  - Never let auto-inferred edges unlock weaker terminal rules, and do not create `value_binding` edges from substring auto-detection.
  - Flip the test at L617.
  - **worker-gate guard:** an honest-RBAC stub must not confirm bola, idor, broken_access_control or bfla.
- **Related IDs:** R3-H-4, R2-H-7, H-12.
- **Verification:** 3/3 high. One verifier ran the `09a5126` archive and confirmed the regression. Spot-check confirmed L654-660.

### R4-H-6 — Dual-membership personas holding admin in one tenant are reclassified as allowed attackers; the privilege check runs only on the terminal hop and only when the response has exactly one tenant marker

- **Kind:** fix-regression (H-11).
- **Category:** security.
- **Location:**
  - [../src/server/agent-script-proof.ts#L321](../src/server/agent-script-proof.ts#L321): `buildCompositeVerifyOptionsFromGrant` calls `isPrivilegedActorOrRole` with no target tenant.
  - [../src/server/v8-oracle-hydrate.ts#L151](../src/server/v8-oracle-hydrate.ts#L151): returns false for a mixed-role label.
  - [../src/server/composite-receipt.ts#L446](../src/server/composite-receipt.ts#L446): the privilege test runs only when `tt` is set, and `tt` is computed at [#L480](../src/server/composite-receipt.ts#L480) for the terminal hop only, from a single response marker.
- **Introduced by:** `30e4978` (merge `d3dd1e5`).
- **What's wrong:** At `09a5126`, any admin token in a role label put the persona in `forbiddenShortcutPersonas`. Now a consultant-style label (admin in A, member in B) lands in `attackerPersonas`. Its genuine tenant-A admin actions are credited as low-privilege attacker evidence on every non-terminal hop, and on terminal hops whose body has zero or several tenant markers. The route tenant is never consulted.
- **Evidence:** Scratch runs:
  - The grant builder returned attackers `[dual, member_b]` and forbidden `[admin_a]`.
  - A two-hop chain on the persona's own admin billing route, with a member_b 403 as the control, gave `confirmed:true` for bfla, privilege_escalation, bola and idor.
  - At `09a5126`: "pre-seeded persona … is forbidden".
- **Attack path:** The operator configures the dual-membership persona, a setup the UI encourages for dual_tenant_abac. Honest exploration then produces admin 200s plus another member's 403, and the kernel signs a BFLA.
- **Impact:** False confirmed privilege escalation and BFLA that attribute entitled admin activity to an attacker.
- **Recommendation:** **Failure class:** privilege resolved per persona label instead of per exchange. **Systemic fix:**
  - Resolve the acting tenant of every exec-arm exchange from host data: route tenant, response markers and the persona tenant map.
  - Forbid the persona wherever it is admin in that tenant, and fail closed when the tenant is ambiguous, on every hop.
  - Keep mixed-role personas forbidden by default, and allow them only for an explicit dual_tenant_abac family with a host-bound target tenant.
  - **worker-gate guard:** a dual persona's own-admin-tenant action never confirms an access-control class.
- **Related IDs:** H-11, R3-H-4.
- **Verification:** 3/3 high. Spot-check confirmed L318-323.

### R4-H-7 — auth_bypass confirms on public endpoints: a junk-credential control returns 401 and an anonymous probe with any allowlisted header returns 200, because the self-sabotage guard covers only authenticated probes

- **Kind:** fix-bypass (C-4 / H-14).
- **Category:** correctness.
- **Location:**
  - [../src/server/proof-receipt.ts#L2151](../src/server/proof-receipt.ts#L2151): the self-sabotage loops are inside `if (probeAuthenticated)`.
  - [#L2252](../src/server/proof-receipt.ts#L2252): `verifyAuthBypassReceipt` accepts any 401/403 control (~L2268).
  - [#L2006](../src/server/proof-receipt.ts#L2006): `authBypassRequestDifferential` returns `'header'` for any added allowlisted header.
  - Host-minted junk credentials: [../src/server/broker.ts#L3667](../src/server/broker.ts#L3667).
- **Introduced by:** The synthetic mutations came with `db81ff7` (merge `f37e2a9` swarm-fix-synth-auth-probe). The guard scope dates from the C-4/H-14 fixes; see also `5b7b270`.
- **What's wrong:** Several frameworks return 401 for an invalid bearer or API key even on permit-all routes. A control carrying a host-minted invalid credential is therefore 401 on a public route. An anonymous probe that only adds an ignored forwarding-class or API-key-class header gets 200. No ablation arm is required: there is no check that the same anonymous request without the added header is denied. The prompts at agent-prompts.ts L1200/L1456 steer persona-less runs toward exactly these mutations.
- **Evidence:** In-memory `verifyReceipt` with an invalid-bearer control (401) and an anonymous probe with an added header (200, public list) gave `confirmed:true` with "header bypass".
- **Attack path:** A persona-less run. The worker, or a messy model, assigns the synthetic mutations to the arms and submits an auth_bypass claim. The result is CWE-287, deterministic in both attempts.
- **Impact:** False confirmed authentication bypasses on common public endpoints, built from host-minted traffic.
- **Recommendation:** **Failure class:** a differential with no ablation arm. **Systemic fix:**
  - Use one shared differential primitive. Require an anonymous ablation request (the probe minus the bypass element) to be denied.
  - The control may carry no credential the probe lacks, which applies the self-sabotage rule to anonymous probes too.
  - Allow synthetic invalid credentials only on the probe arm.
  - **worker-gate guard:** the permit-all-returns-401-for-invalid-bearer stub must not confirm.
- **Related IDs:** H-14, C-4, R3-H-4(b).
- **Verification:** 3/3 high. Spot-check confirmed L2150-2153.

### R4-H-8 — The per-run `/repos` snapshot is chosen from mutable backend-global state, so run B's static-AST proofs, code-audit sessions and verify runs mount run A's stale snapshot

- **Kind:** fix-regression (R2-H-21 isolation premise).
- **Category:** data-integrity.
- **Location:**
  - [../src/server/worker-backend.ts#L2217](../src/server/worker-backend.ts#L2217): `resolveRunKeyForOptions` falls back to `activeWarmPoolPolicy`.
  - [#L2242](../src/server/worker-backend.ts#L2242): `acquireRunRepoSnapshot` reuses the `(runKey, sourceDir)` lease.
  - `installWarmPool` flips the active policy at L2406 and L2480.
  - The `openSession` slot fallback is at L2815-2852.
  - Callers that pass only `{reposDir}`: [../src/server/floor-recipe-engine.ts#L1709](../src/server/floor-recipe-engine.ts#L1709) (and `confirmed:true` at L1737-1742), execution.ts L2175, semantic-audit.ts L2402/L2681, exec-verify.ts L4013, patch-workflow.ts L631.
- **Introduced by:** `e0653b4` (merge `f1aca6c` swarm-fix-repo-snapshots). It also removed the active-run re-sync/unlink lock on the strength of this snapshot isolation.
- **What's wrong:** No caller passes `options.runId`. Only investigation workers pass a policy. Every other repo-mounting call resolves its run from whichever run most recently called `setWarmPoolPolicy`, and every investigation worker of every concurrent run calls it. There is one backend per workspace and warm workers are on by default. `matchesWarmRepos` compares only the source directory.
- **Evidence:** A stub-docker reproduction (no Docker): A stages, the project is re-synced, B stages, and A touches its policy again. B's `verifyStaticAst` then bind-mounted A's snapshot and read the pre-re-sync content.
- **Attack path:** No attacker is needed. Fix a vulnerability, re-sync during run A (now allowed), start run B to confirm the fix. B confirms static_verified against the old code. A's later calls can likewise bind to B's snapshot.
- **Impact:** Cross-run source bleed and false confirmed, or missed, results in the fix-then-reverify workflow, nondeterministic by scheduling.
- **Recommendation:** **Failure class:** run identity inferred from mutable global state. **Systemic fix:**
  - Make `runId` a required input of every repo-mounting backend call and thread it from all callers.
  - `resolveRunKeyForOptions` fails closed, staging a private per-call snapshot, and `activeWarmPoolPolicy` is never a resolution input.
  - `openSession` requires slot `runKey === runId`.
  - **worker-gate guard:** two concurrent policies, and B never mounts A's lease.
- **Related IDs:** R2-H-21.
- **Verification:** 3/3 high. Spot-check confirmed L2217-2230.

### R4-H-9 — The production Gate-6 composite retest replays hops without request bodies or fresh bound values and maps any non-reproduction to "fixed", so no-op patches are approved

- **Kind:** new-code.
- **Category:** correctness.
- **Location:**
  - [../src/server/patch-workflow.ts#L2236](../src/server/patch-workflow.ts#L2236): the body comes only from `override?.body`, which production never sets (L1360-1373).
  - `sanitizeStoredReplayHeaders` drops redacted headers (L1801).
  - Mapping to "fixed": a 4xx with no effect becomes `blocked`, then `fixed` (L2665-2693). Producer-edge, `edge_binding` and terminal failures also become `fixed` (L2694-2700, L2776-2791).
  - Gate 6 passes with no baseline when a benign prefix hop exists (L1406-1409).
  - `broker_exchanges` stores no request body: [../src/server/schema.ts#L269](../src/server/schema.ts#L269).
- **Introduced by:** `cf8dd79` (merge `19e3548` swarm-sys-q8-patch-retest).
- **What's wrong:** Each hop is rebuilt lossily from the stored exchange.
  - Body-bearing hops get 400/422.
  - Consumers resend stale tokens.
  - Producers mint fresh nonces that fail the stored `valueDigest`.
  - OOB and browser terminals can never be re-proven, because the broker context carries neither a browser nor a canary broker.

  Every one of these reads as "the patch broke the chain". The host does hold the raw body (`factLog.getExchange(id)?.rawRequestBody`), but it is unused. There is no unpatched-control replay showing that the runner can reproduce at all.
- **Evidence:** A /tmp test with a no-op patch on an unpatched target, where a hop handler rejects an empty body, gave `status=approved`, `dynamicRetestVerdict=fixed` and Gate 6 passed.
- **Attack path:** No attacker is needed. An ineffective diff passes reviewer gates 1-5, and Gate 6 attests it as fixed.
- **Impact:** A host-attested "fixed" for still-vulnerable multi-hop findings, which propagates to signed receipts and SARIF.
- **Recommendation:** **Failure class:** lossy replay mapped to a positive verdict, with no reproduction control. **Systemic fix:**
  - Replay a faithful host request: the sealed request body from the fact log, with each consumer re-bound from the replayed producer's fresh output. Route browser and OOB hops through ScopedBrowser and CanaryBroker.
  - Return `inconclusive` whenever a hop cannot be rebuilt faithfully.
  - Accept `blocked` as `fixed` only after the same runner reproduced the chain on the pre-patch lab.
  - **worker-gate guard:** an unpatched body-validating or token-validating target must never yield `fixed`.
- **Related IDs:** H-5, R2-H-16, H-19 (same class, different path).
- **Verification:** 3/3 high. Spot-check confirmed L2234-2237.

### R4-H-10 — The Gate-6 composite retest writes a "fixed" Verify Fix row and spec-level `compositeVerdict` for an unmerged or rejected candidate patch, and export prefers that stale verdict over newer retests

- **Kind:** new-code.
- **Category:** data-integrity.
- **Location:**
  - [../src/server/patch-workflow.ts#L2515](../src/server/patch-workflow.ts#L2515): `recordRetestRun` inside `persistCompositeRetestMetadata` (defined at L2482). It is called from `finalize` at L2570 with `persistRetest:true` (L1372), before Gate 6 decides (L1380-1431) and before rollback.
  - It overwrites `replay_specs.proof_receipt` at L2532-2543.
  - [../src/server/receipt-export.ts#L761](../src/server/receipt-export.ts#L761): `fromSpecProof` outranks a newer, unstructured retest row.
  - [../src/server/report-export.ts#L495](../src/server/report-export.ts#L495): "Latest Verify Fix retest".
- **Introduced by:** `cf8dd79` (merge `19e3548`).
- **What's wrong:** A finding-level `retest_runs` row and the spec-level verdict are written against a lab containing a candidate diff. They are written even when Gate 6 then rejects the patch (baseline regression) or withholds it, and even though the lab is reverted afterwards. A later ordinary Verify Fix ("reproduced") carries no structured composite fields, so `resolveStructuredCompositeRetestMeta` falls back to the stale spec value.
- **Evidence:** Traced end to end. The older non-composite Gate-6 path never wrote `retest_runs`, so this is new with the Q8 wiring.
- **Attack path:** None needed: generate a patch, Gate 6 composite returns "fixed", the patch is rejected or never merged, and the report shows Fixed. A newer "reproduced" is overridden in the signed bundle and SARIF.
- **Impact:** Still-exploitable findings are shown as remediated in reports, the UI and signed exports.
- **Recommendation:** **Failure class:** a candidate-patch lab result persisted into the authoritative finding record. **Systemic fix:**
  - Persist Gate-6 proofs only on the patch proposal (tagged with `patchId` and lab revision), never in `retest_runs` or `replay_specs.proof_receipt`.
  - The export picks the newest retest by `createdAt`.
  - **worker-gate guard:** a rejected Gate-6 patch followed by a "reproduced" retest must export "reproduced".
- **Related IDs:** H-5.
- **Verification:** 3/3 high. Two verifiers flagged it as borderline with medium, because the proposal row itself shows rejected or withheld. Spot-check confirmed L2515 and L2570.

### R4-H-11 — One 52x response, or three anonymous 401s, in a global 240-row window permanently quarantines a live approved origin mid-run

- **Kind:** new-code.
- **Category:** correctness.
- **Location:**
  - [../src/server/exec-dispatch.ts#L2098](../src/server/exec-dispatch.ts#L2098): `detectQuarantinedOrigins`. The dead-host rule `allDeadOrError && (hasDead52x || n >= 2)` is at L2103-2121, and the 401-wall rule at L2123-2141.
  - [../src/server/exec-recon-planner.ts#L2433](../src/server/exec-recon-planner.ts#L2433): `getQuarantinedOriginSet` re-detects on every dispatch tick over `ORDER BY created_at DESC LIMIT 240` across all origins.
  - `unreachable` is sticky at L2341.
- **Introduced by:** `d869308` (merge `af7c78d` swarm-fix-repo-origin-map).
- **What's wrong:** The window has no per-origin floor and no minimum sample. Worker traffic, whose paths the LLM chooses and whose statuses the target chooses, feeds it. Earlier live 2xx rows for the same origin can scroll out of the window. `unreachable` is never released, even with a persona.
- **Evidence:** 239×200 for origin A plus one 524 for origin B, with a persona present, quarantines B with source `telemetry_52x_dead`, `requestsObserved 1`.
- **Attack path:** In a multi-origin run where A dominates traffic, a heavy endpoint on B times out at the edge. Alternatively, in a persona-less run, B returns 401 on three probed routes. B then drops out of dispatch, Wave-1, coverage seeding and fairness for the rest of the run, and feeds R4-H-12.
- **Impact:** Silent whole-origin false negatives; a hostile target can steer which approved hosts get tested.
- **Recommendation:** **Failure class:** a quarantine verdict from an unbounded, unstratified heuristic sample. **Systemic fix:**
  - Use one evidence-based detector, with thresholds kept in run-safety-budgets.ts.
  - Sample per origin. Require at least 3 probes across at least 2 paths, with no live non-401 response ever recorded for the origin.
  - Use Phase-0 or host-originated probes rather than worker traffic.
  - Release `unreachable` on a later live response.
  - **worker-gate guard:** the single-52x case and the window-scroll case.
- **Related IDs:** none.
- **Verification:** 2/3 high, 1/3 medium (that verifier cited visible coverage-gap telemetry). Kept high by majority.

### R4-H-12 — Ready steps on a quarantined origin are skipped by dispatch but never made terminal, so the run hangs in investigation

- **Kind:** new-code.
- **Category:** reliability.
- **Location:**
  - [../src/server/exec-dispatch.ts#L2656](../src/server/exec-dispatch.ts#L2656): `isQuarantinedStep`, then `continue` with no status write.
  - Only circuit-open steps are blocked, at execution.ts L3045-3058.
  - `anyActive` gates `advanceToVerification` at [../src/server/execution.ts#L3184](../src/server/execution.ts#L3184).
  - `dispatchableReadySteps` counts the skipped steps (exec-dispatch.ts L1174), and `evaluateDispatchStop` defers (L1381).
- **Introduced by:** `d869308` (merge `af7c78d`).
- **What's wrong:** These steps stay ready or pending forever. That keeps `anyActive` true and inflates `remainingReady`, so the planner's stop decision is deferred while slots are free. Only worker completions reschedule the planner, so once live origins drain nothing ever runs again. Wall-clock exhaustion is evaluated only inside planner rounds.
- **Evidence:** `evaluateDispatchStop({decision:'stop', remainingReady:3, freeSlots:4, inFlight:0})` returns a deferred continue. Every `advanceToVerification` path sits inside `!anyActive`.
- **Attack path:** None needed: an origin is quarantined after its steps were seeded (R4-H-11, or the 401-wall on any persona-less API host), and the run then sits at running/investigation indefinitely.
- **Impact:** A run wedge: no verification phase, no final report, and pending findings are never replay-verified.
- **Recommendation:** **Failure class:** a dispatch filter that is not a terminal state transition (same class as M-12 and R4-H-13). **Systemic fix:**
  - Route quarantine through the same terminal-transition primitive as circuit-open. Non-running steps whose origins are all quarantined become a typed `blocked`/`quarantined` status with a gap code, then `refreshReadyChainSteps` runs. Unquarantine restores them.
  - One quarantine-aware predicate serves `anyActive`, `dispatchableReadySteps` and `passOneCoverage`.
  - **worker-gate guard:** one live origin plus one quarantined origin with a ready step must reach verification.
- **Related IDs:** M-12.
- **Verification:** 3/3 high.

### R4-H-13 — CQ-5 typed step outcomes reintroduce the M-12 stranded-pending wedge: dependents of turn_capped, nudged_out, rotated_partial, infra_failed or model_failure parents stay pending forever

- **Kind:** fix-regression (M-12 class, via CQ-5).
- **Category:** reliability.
- **Location:**
  - [../src/server/store-runs.ts#L1362](../src/server/store-runs.ts#L1362): `refreshReadyChainSteps` taints only on tainted/canceled/blocked parents and promotes only when every parent is `complete`. `addChainStep` at L1292 applies the same rule.
  - Deterministic trigger: `expandEligibleMultiTrialSteps` copies `dependsOnStepIds` at [../src/server/execution.ts#L2402](../src/server/execution.ts#L2402).
  - Planner path: exec-recon-planner.ts L6142-6151.
  - `permanentlyBlockedStepIds` omits three of the new statuses (exec-dispatch.ts L1153-1160).
- **Introduced by:** `f60b5a4` (merge `011f9ce` swarm-cq-5-typed-outcomes).
- **What's wrong:** Before CQ-5, every worker exit wrote `complete`. Now five typed statuses are neither "satisfies dependency" nor "dead". Only `persistDispatchPlan` consults `CONTINUABLE_CHAIN_STEP_STATUSES`, and only at creation time.
- **Evidence:**
  - The `f60b5a4` diff replaces four `complete` writes.
  - Multi-trial expansion is on by default. It creates pending siblings of a retry whose parent is turn_capped, and nothing promotes them.
  - `anyActive` includes pending.
- **Attack path:** None needed: a routine turn-capped assignment, then a retry or hop continuation expanded into trial siblings, or a planner `dependsOnStepIds`. The run never leaves investigation.
- **Impact:** A run wedge in normal agentic operation that grows with run scale.
- **Recommendation:** **Failure class:** a closed status enum consumed by predicates that are not exhaustive. **Systemic fix:**
  - Derive "satisfies dependency" and "dead" sets from `chainStepTerminalStatuses` with a compile-time exhaustiveness proof, and use them in `refreshReadyChainSteps`, `addChainStep` and `permanentlyBlockedStepIds`.
  - Add a run-level backstop: when no step is ready or running and no worker is active, a stop decision advances, with stranded steps reported as telemetry.
  - **worker-gate guard:** for each terminal status as the parent, a pending child ends up ready or tainted.
- **Related IDs:** M-12, H-27.
- **Verification:** 3/3 high. Spot-check confirmed L1362-1376.

### R4-H-14 — The R3-H-1(b) fix scans the whole worker request body with a quadratic multipart regex, stalling the host event loop for minutes per request

- **Kind:** fix-regression (R3-H-1).
- **Category:** reliability.
- **Location:**
  - [../src/server/scope-policy.ts#L463](../src/server/scope-policy.ts#L463): the `[^\r\n]*\bname` test, with the same shape in the loop at L465.
  - The ceiling is raised to 4 MiB at [#L264](../src/server/scope-policy.ts#L264).
  - Called from `classifyRequestMutation` at [../src/server/request-admission.ts#L861](../src/server/request-admission.ts#L861) (step 7, L1648), and again by approval-judge.ts (L274/L627/L667/L794) and tier3-approval.ts L194.
- **Introduced by:** `558fd78` (merge `cfa2215` swarm-r3-admission-staging).
- **What's wrong:** The 64 KiB slice and the `[^;\r\n]*` class were both removed. The scan runs whenever the body merely contains a content-disposition token, whatever the content-type. On one long line of repeated disposition prefixes with no name field, the cost is O(occurrences × line length). V8's linear fallback does not trigger, because each start position stays under the backtrack threshold.
- **Evidence:** Timings with the production flags: 80 KB in 116-163 ms, 300 KB in 1.5-2.4 s via the real `classifyRequestMutation`, and about 100 s extrapolated at the 2 MiB worker body cap (verify-rpc.ts L654). The scan runs several times per request.
- **Attack path:** A worker sends one in-scope request with a crafted text body. Admission runs before any approval, so no consent is needed. Repeating it, or sending batches, keeps the host wedged.
- **Impact:** A host-wide stall of all runs, approvals, SSE and the kill-switch UI.
- **Recommendation:** **Failure class:** untrusted input on the host thread (see the class table). **Systemic fix:**
  - Fail closed beyond the 64 KiB classification window instead of scanning.
  - Use a single-pass CRLF header tokenizer, or bounded classes.
  - Route every host-side regex over untrusted bodies through the safe-regex chokepoint with a static guard.
  - **worker-gate guard:** `classifyRequestMutation` on a 2 MiB adversarial body finishes in under 50 ms.
- **Related IDs:** R3-H-1, R3-H-11, H-32..H-38.
- **Verification:** 3/3 high. Spot-check confirmed L462-466 and L264.

### R4-H-15 — The new host-executed `search_repo` runs model-chosen regexes synchronously on the host event loop over up to 32 MiB with no time budget

- **Kind:** new-code.
- **Category:** reliability.
- **Location:**
  - [../src/server/agent-session.ts#L1413](../src/server/agent-session.ts#L1413): `searchRepoHost`, with the per-line `regex.test` at L1465-1471.
  - Caps at L1214-1218.
  - Registered at L2518-2541.
- **Introduced by:** `2cc665a` (merge `e517b6a` sys-q2-repo-tools).
- **What's wrong:** Search moved out of the `--network none` container onto the host main thread. `compileSafeClaimRegex` correctly accepts ordinary unanchored single-quantifier patterns, but those are quadratic per line, and line length is capped only at 4096 characters. There is no deadline or worker thread, and the abort signal cannot interrupt synchronous code. The tool is marked parallel read-only.
- **Evidence:** About 8-38 ms per 4 KiB non-matching line with the production flags. A real `searchRepoHost` call over about 2 MiB of long lines blocked for 4.9-11.8 s. That extrapolates to roughly 70-170 s per call at the cap.
- **Attack path:** A white-box repo contains, or is seeded with, many long data lines. The model issues secret-hunting regex searches, on its own or through prompt injection. The host stalls.
- **Impact:** A host-wide stall across runs and the operator UI.
- **Recommendation:** **Failure class:** untrusted compute on the host thread. **Systemic fix:**
  - Run `search_repo` in the container, or in `UntrustedComputePool` with a hard wall-clock limit enforced by terminating the thread. Alternatively, restrict it to literal or linear-engine search.
  - Keep per-call time and step budgets in run-safety-budgets.ts, with truncation telemetry.
  - **worker-gate guard:** a long-line tree plus a single-quantifier pattern finishes under N ms.
- **Related IDs:** R3-H-11, R3-H-12.
- **Verification:** 3/3 high. Spot-check confirmed L1465-1471.

### R4-H-16 — R3-H-12 residual: repo-content scanners that run after the ProgramGraph worker are still quadratic on the host event loop

- **Kind:** fix-bypass (R3-H-12).
- **Category:** reliability.
- **Location:**
  - [../src/server/invariant-synthesizer.ts#L261](../src/server/invariant-synthesizer.ts#L261): a per-match slice and split, plus a whole-file split in `extractFunctionBodyWindow` at L206. `buildTrustBoundaryGraph` does the same at L521.
  - Host caller: [../src/server/exec-recon-planner.ts#L2645](../src/server/exec-recon-planner.ts#L2645) `synthesizeInvariants`.
  - [../src/server/program-graph.ts#L4789](../src/server/program-graph.ts#L4789): the Dockerfile EXPOSE scan with a multiline-anchored leading `\s*`, reached from phase0-recon.ts L1204.
  - [../src/server/phase0-recon.ts#L545](../src/server/phase0-recon.ts#L545): `inferServerActionPageRoute`, with O(actions × page bytes) `includes`.
- **Introduced by:** Residual of `25df28d` (swarm-r3-graph-host). `inferServerActionPageRoute` is new in `21676cf` (merge `2662064`).
- **What's wrong:** Only `extractProgramGraph` moved to the worker. The synchronous finalizer and Phase-0 scanners that consume the same untrusted bytes still run on the main thread.
- **Evidence:**
  - The real `buildGuardAsymmetryMatrix` and `synthesizeInvariants` took about 3.4-8.5 s per 128 KB file with quadratic growth. At the 160-file cap that is minutes to tens of minutes.
  - The EXPOSE regex took about 22-41 s per 256 KB Dockerfile.
  - The production regexp flags do not help.
- **Attack path:** Hostile content in a third-party or PR repo under white-box audit. The operator starts a run, and the host stalls.
- **Impact:** A host-wide wedge from untrusted repo content.
- **Recommendation:** **Failure class:** untrusted compute on the host thread, with a missed caller. **Systemic fix:**
  - Run the whole post-graph pipeline (`synthesizeInvariants`, `mapServicesToOrigins`, `extractStaticFrameworkRoutes`) in `UntrustedComputePool` with deadlines.
  - Add one shared newline-offset line-index helper, and ban per-match slice/split patterns via a lint extending the R3-H-12 guard.
  - Use a line-wise `[ \t]*` EXPOSE scan, and index page tokens once.
  - **worker-gate guard:** a 128 KB adversarial file per scanner finishes under budget.
- **Related IDs:** R3-H-12, R2-H-24, H-33, M-53.
- **Verification:** 3/3 high. Verifiers' measurements were lower than the hunter's, but still minutes at the caps. Spot-check confirmed L259-262 and L4789.

### R4-H-17 — R3-H-10 fix bypass: the inbound provider stream sanitizer still rewrites SSE keys and protocol `type` values with target-derived cookie needles, wedging every agentic call

- **Kind:** fix-bypass (R3-H-10).
- **Category:** reliability.
- **Location:**
  - [../src/server/provider-stream.ts#L771](../src/server/provider-stream.ts#L771): key redaction in `sanitizeProviderValue` (L751), which also redacts every string leaf, `type` included (L758), and non-data SSE lines (~L906).
  - The needle source: [../src/server/persona-auth.ts#L3524](../src/server/persona-auth.ts#L3524) raw `scrubTokens`, then [../src/server/persona-vault.ts#L1337](../src/server/persona-vault.ts#L1337) `addToken`, which uses `isAcceptableSecretNeedle` only.
- **Introduced by:** Pre-existing inbound path, left untouched by `2fea2dc` (merge `a3debe9`).
- **What's wrong:** Only the outbound scrub became content-aware. Raw login Set-Cookie values skip the auth-relevant cookie-name rule. Protocol substrings of 8 or more characters that contain punctuation (a Responses event prefix, Anthropic event-name stems) pass the needle filter.
- **Evidence:** With such a needle, a 3-frame Responses stream came out with every `type` mangled into a persona placeholder. The stream still terminates, but yields no text or tool calls.
- **Attack path:** The target sets an extra login cookie whose value is a protocol substring. Every later model stream in the run is blinded.
- **Impact:** The agentic lane is wedged run-wide, giving false negatives at scale; the deterministic floor survives.
- **Recommendation:** **Failure class:** structural fields scrubbed as content (the mirror of R3-H-10). **Systemic fix:**
  - Use one structural scrubber shared by both directions: content leaves only, never keys, `type`, `event`, IDs, indexes or status.
  - Add an inbound integrity check that fails loudly.
  - Apply the cookie-name rule to raw `scrubTokens`.
  - **worker-gate guard:** a protocol-substring needle never changes an SSE `type`.
- **Related IDs:** R3-H-10, H-8, H-25.
- **Verification:** 3/3 high. Spot-check confirmed L769-772.

### R4-H-18 — `.gitattributes` checkout transforms (ident, eol=crlf, working-tree-encoding) bypass the R3-H-17 pre-checkout blob quota by about 40x

- **Kind:** fix-bypass (R3-H-17).
- **Category:** reliability.
- **Location:**
  - [../src/server/github-repo-sync.ts#L1999](../src/server/github-repo-sync.ts#L1999): raw `ls-tree` blob sizes are summed in `inspectGitTreeBeforeCheckout`.
  - `checkout -f` at L2302-2312 disables only the LFS filters.
  - The post-checkout measurement is at L2338.
- **Introduced by:** `49ac817` (merge `8c5765c` swarm-r3-repo-quota).
- **What's wrong:** The quota assumes on-disk bytes equal blob bytes. The repo's own attributes request built-in conversions that multiply bytes during checkout, and nothing neutralizes core or info attributes. Repetitive blobs compress well, so the GitHub size preflight also passes.
- **Evidence:** A local `file://` experiment with the same flow: a 100,000-byte blob became a 3,920,000-byte checked-out file (39.2x). A 20 MB tree wrote more than 580 MB in 1.6 s.
- **Attack path:** Whoever controls a synced repo commits amplifying attributes plus blobs just under the per-repo budget. A sync or re-sync, now allowed during runs, writes roughly 10 GB to the shared data disk.
- **Impact:** ENOSPC on the shared data dir, breaking DB, evidence and credential writes for all tenants. It repeats on every re-sync.
- **Recommendation:** **Failure class:** a quota checked against a proxy for bytes rather than bytes written. **Systemic fix:**
  - Use one checkout primitive. Pre-write `.git/info/attributes` neutralizing text, ident, working-tree-encoding and filter; point `core.attributesFile` at `/dev/null`; set `core.autocrlf=false`.
  - Better: materialize via streaming with byte accounting that aborts at the cap, or use a hard-quota filesystem.
  - **worker-gate guard:** an amplifying fixture is rejected with on-disk usage never exceeding the cap.
- **Related IDs:** R3-H-17.
- **Verification:** 3/3 high. Spot-check confirmed L1999 and L2302-2312.

### R4-H-19 — The cq-13a fail-closed per-run redaction cap is filled by normal rotating-cookie behaviour and permanently breaks every jar-bound exchange for the rest of the run

- **Kind:** fix-regression (R2-H-28).
- **Category:** reliability.
- **Location:**
  - [../src/server/broker.ts#L2239](../src/server/broker.ts#L2239): `registerSecret` throws `RedactionCapacityError` at a fixed 5000 entries.
  - Registration happens post-send at L2485, L2517 and L2529 (`storeJarCookiesAndCsrf`, called at L4347 and L4762) and pre-send at L4191.
  - Entries are removed only by `disposeRun`.
- **Introduced by:** `c74834f` (merge `3098138` cq-13a-redaction-restore).
- **What's wrong:** Every distinct rotating cookie or masked CSRF value is registered forever. Several mainstream frameworks re-encrypt or mask on every response, so the cap is reached after a few thousand jar-bound responses. After that, exchanges throw *after* the request is on the wire, discarding the evidence for mutations that were actually sent. The cap is an unscaled constant that is not in run-safety-budgets.ts.
- **Evidence:** Code trace. `maxRedactedSecretsPerRun` is referenced only in broker.ts.
- **Attack path:** None needed: scan a rotating-cookie app, or a target emits many Set-Cookie values. Session and CSRF-bound proofs fail for the remainder of the run.
- **Impact:** A partial run wedge with false negatives at scale for authenticated verification. State changes are sent while their results are dropped.
- **Recommendation:** **Failure class:** an unscaled micro-cap with a fail-after-send placement. **Systemic fix:**
  - Move the cap into run-safety-budgets.ts, scaled to workload, with telemetry.
  - Make the registry lifecycle-aware: unregister superseded, deleted or evicted values.
  - Fail closed only before sending.
  - **worker-gate guard:** 10k rotating-value responses through one jar keep succeeding.
- **Related IDs:** R2-H-28.
- **Verification:** 2/3 high, 1/3 medium (that verifier noted fail-closed confidentiality and a large-run precondition). Kept high by majority.

### R4-H-20 — The M-50 fix makes OOB callback retention unbounded for pending tokens, and each new callback then costs an O(n) synchronous SQLite prune

- **Kind:** fix-regression (M-50).
- **Category:** reliability.
- **Location:**
  - [../src/server/oob-relay.ts#L1297](../src/server/oob-relay.ts#L1297): `pruneCallbacks` counts protected rows but can never delete them.
  - Called per insert at L930 and per claim at L1151.
  - The ingest at [../src/server/canary-broker.ts#L1448](../src/server/canary-broker.ts#L1448) has no per-token or per-IP quota.
- **Introduced by:** `86fd357` (merge `4717aea` sys-q3-oob-browser).
- **What's wrong:** Rows for tokens with a pending subscription are exempt from eviction but still count toward the cap. Above 5000 such rows, every callback runs a full count plus an anti-join scan that deletes nothing. `callbackId` includes path and query, so each distinct path is a new row. `callbacksForToken` and `promoteLate` load all of a token's rows with no LIMIT.
- **Evidence:** In-memory `OobRelay`, one pending subscription: per-2,500-insert time rose from about 0.35 s to about 7 s at 20k rows, linear growth per insert, and `delivered` passed the cap fourfold.
- **Attack path:** A hostile in-scope target that received a canary floods distinct-path callbacks while the subscription is pending.
- **Impact:** A host event-loop stall and unbounded SQLite growth across all runs. It requires a target-reachable listener, as real OOB does.
- **Recommendation:** **Failure class:** half of a recommended fix shipped ("protect pending" without "per-token quota"). **Systemic fix:**
  - Per-token and per-run callback quotas in run-safety-budgets.ts, with overflow counted in telemetry rather than inserted.
  - A separate, hard-capped protected budget.
  - Amortized or timer-based pruning.
  - A per-IP rate limit, and LIMIT on token reads.
  - **worker-gate guard:** more than 10k callbacks for one pending token gives a bounded row count and flat insert time.
- **Related IDs:** M-50, M-49.
- **Verification:** 2/3 high, 1/3 medium (that verifier cited the loopback-default precedent from M-49). Kept high by majority. Spot-check confirmed L1297-1316.

## Recurring failure classes

| # | Failure class | Critical/high instances R1–R4 | The one systemic move |
|---|---|---|---|
| 1 | **Worker-asserted or worker-selected evidence trusted by the kernel**: arms, pairs, challenge values and the cited window all chosen by the worker | C-6, C-7, H-14; R2-C-6, R2-C-7; R3-C-2, R3-C-4, R3-H-4; **R4-C-1, R4-C-2, R4-C-4, R4-H-5, R4-H-7** | Every discriminating input is host-minted and stamped on the fact at send time, and the kernel requires the stamp. Cited-window completeness comes from HostFactLog seq. One shared ablation-arm primitive. |
| 2 | **Heuristic classifier used as proof**: field names, route or persona difference, path shape | R2-C-8; R3-C-5; **R4-C-4, R4-C-5, R4-C-6, R4-H-5, R4-H-6** | One host-attested authorization-dimension primitive (principal, tenant, entity, signed resource) used by every oracle. Heuristics may classify, never satisfy. |
| 3 | **Raw-plane and substring anti-reflection oracles**, with fail-open decoding | H-16; R2-C-9, R2-H-10; R3-C-3, R3-H-2; **R4-C-2, R4-C-3, R4-C-6, R4-H-4** | One carrier normalizer (per-component decode, fail closed, deletion- and NFKC-normalized) for all anti-reflection checks. One worker-visible digest primitive applied in `scrubRecord`. |
| 4 | **Untrusted input processed on the host thread** | H-32..H-38; R2-H-24, R2-H-27, R2-H-29; R3-C-1, R3-H-11, R3-H-12; **R4-H-14, R4-H-15, R4-H-16, R4-H-20** | Every scan over repo, body or regex input runs in `UntrustedComputePool` with deadlines. Shared linear helpers (line index, header tokenizer). A static lint, plus a run-scale stress tier in worker-gate. |
| 5 | **Admission and approval dual paths, canonicalization differentials** | C-1, H-3/4, M-1; R2-H-1; R3-H-1, R3-H-9; **R4-H-1** | One lease and approval eligibility predicate, evaluated at match time inside `leaseAuthorizes`/admission, also driving the UI copy. |
| 6 | **Fix landed as an optional or unwired primitive, or a missed caller** | H-14 (dead code, R3); R3-H-12; **R4-H-3, R4-H-16, R4-H-17** | Contract tests that drive the *production caller*. check-unwired fails on any security primitive in the baseline. |
| 7 | **Lifecycle and terminal-state drift** (steps or verdicts never reach the right terminal state) | M-12; R3-H-13, R3-H-14; **R4-H-9, R4-H-10, R4-H-12, R4-H-13** | Exhaustive canonical status sets. Terminal transitions through one primitive. A run-level backstop. Candidate-lab results never written to authoritative finding records. |
| 8 | **Credential-plane needle and redaction policy drift** | H-8, H-25; R2-H-28; R3-H-10; **R4-H-2, R4-H-17, R4-H-19** | One needle builder with provenance tiers, shared by kernel, broker and provider. One structural scrubber for both directions. Lifecycle-aware registry budgets. |
| 9 | **Cross-run state through mutable globals** | R2-H-21; **R4-H-8** | Run identity is a required argument and never inferred. |
| 10 | **Quota checked on a proxy, or after the write** | R3-H-17; **R4-H-18, R4-H-20** | Streaming byte accounting that aborts at the cap, hard-quota filesystems, and quota-first ingest. |

## R3 fix scorecard

| R3 ID | Fixing merge(s) | Verdict | R4 IDs |
|---|---|---|---|
| R3-C-1 | `3fb5b6f` node-hardening, `1fc934d` fix-proto-playwright, `e37850c` serve-flags | clean | — |
| R3-C-2 | `9a15fcd` oracle-invariants (`0e8c6b0`) | **regressed** | R4-C-4 |
| R3-C-3 | `0ea460e` verify-rpc-custody (`303dc87`), `5b7b270` hostfact-place (`c9169d6`) | clean for the redaction vector; the class is open via a different mechanism | (R4-C-3) |
| R3-C-4 | `9a15fcd` (`0e8c6b0`), `5b7b270` (`c9169d6` status path), host pair in `0ea460e` (opt-in only) | **bypassable** | R4-C-1 |
| R3-C-5 | `520c0d2` v8-hydrate (`158b9d7`) | **regressed** | R4-C-5 |
| R3-H-1 | `cfa2215` admission-staging (`558fd78`) | **regressed** (DoS); the (a, b) approval bypasses hold | R4-H-14 |
| R3-H-2 | `0ea460e` (`303dc87`) | **bypassable** (incomplete) | R4-H-4 |
| R3-H-3 | `bdd280c` browser-session (`819dc8d`), `6438222` | **bypassable** (unwired) | R4-H-3 |
| R3-H-4 | `cc31d8a` composite-actor; `0ea460e` for (a) | clean for actor resolution; the class was reopened by `d3dd1e5` | (R4-H-5, R4-H-6) |
| R3-H-5 | `0ea460e`, `5b7b270` | clean | — |
| R3-H-6 | `44119bd` chromium-sandbox, `819dc8d` | clean | — |
| R3-H-7 | `162224f` ui-curl | clean | — |
| R3-H-8 | `5beddcd` scope-ranking | clean | — |
| R3-H-9 | `83db1fb` approval-glob | clean (worker globs rejected); the same blast radius reappeared via new operator scopes in `353d5ee` | (R4-H-1) |
| R3-H-10 | `a3debe9` provider-scrub (`2fea2dc`) | **bypassable and regressed** | R4-H-17, R4-H-2 |
| R3-H-11 | `9b994e4` safe-regex | clean (analyser); a new host sink was added elsewhere | (R4-H-15) |
| R3-H-12 | `25df28d` graph-host | **bypassable** (post-graph scanners left on host) | R4-H-16 |
| R3-H-13 | `7a658ab` exec-verify-id (`4cb5a68`) | clean | — |
| R3-H-14 | `ef208dd` floor-provenance | clean | — |
| R3-H-15 | `7a658ab` (`4cb5a68`) | clean | — |
| R3-H-16 | `81e9e96` retention | clean | — |
| R3-H-17 | `8c5765c` repo-quota (`49ac817`) | **bypassable** | R4-H-18 |

## Duplicates of earlier rounds

None. No kept candidate was an unchanged R1–R3 issue. Sub-points that do repeat known issues were dropped from their findings and are not counted: the lease persona-binding point in R4-H-1 (M-1) and the `readonly_environment` lease override that predates `353d5ee`.

## Downgraded candidates

- **personaSecrets skips short or low-entropy operator credentials** ([../src/server/persona-vault.ts#L1949](../src/server/persona-vault.ts#L1949)): medium according to the agent-model-tools verifiers, because redact.ts keyed backstops still catch keyed reflections. The same root cause was **kept as R4-H-2** by a different hunter's 3/3 high verdicts.
- **The R3-H-10 needle gate drops short or dictionary passwords and non-auth-named cookies** ([../src/server/persona-vault.ts#L1949](../src/server/persona-vault.ts#L1949)): medium from the broker-credential gap hunter. Merged into R4-H-2.
- **Interactive sign-in auto-classifies third-party iframe and multi-tenant IdP origins as approved IdP origins** ([../src/server/browser-session-auth.ts#L1094](../src/server/browser-session-auth.ts#L1094)): medium. The mechanism is real, but receiving tokens there needs further preconditions.
- **Mandatory per-run `/repos` staging caps the project at 256 MiB / 50k files, below the sync quota** ([../src/server/worker-backend.ts#L1507](../src/server/worker-backend.ts#L1507)): medium. It fails closed with a diagnostic, so this is a capability gap rather than a wedge.
- **The R2-10 deterministic dedupe veto never compares vulnerability class** ([../src/server/dedupe.ts#L602](../src/server/dedupe.ts#L602)): medium. It needs an LLM duplicate verdict on the same surface.
- **Superseded rows are dropped before the scope filter, so a confirmed finding disappears when its cross-origin superseder is unreportable** ([../src/server/store-runs.ts#L3129](../src/server/store-runs.ts#L3129)): medium. The data is not lost; it is hidden in the export.
- **The timeout breaker charges a shared redirect-chain deadline to the current hop's origin** ([../src/server/broker.ts#L4301](../src/server/broker.ts#L4301)): medium. A cross-run breaker trip is possible but bounded by cooldown.

## Fix plan — ordered

One writer per file. Streams marked **∥** can run in parallel with every other ∥ stream. Critical streams WS-1 to WS-5 go first and can all start at once (WS-3 rebases on WS-2's type change). Each stream adds its class-level guard to `scripts/worker-gate.sh` (as a fast test under `tests/`) **before** any long benchmark is re-run.

| # | Stream (branch) | File lease | Closes | Class-level guards for `scripts/worker-gate.sh` | Parallel |
|---|---|---|---|---|---|
| 1 | `agents/r4-oracle-invariants` | `src/server/oracle-invariants.ts` | R4-C-1 (kernel: skeleton binding, reject empty-base, false arm in same status class), R4-C-3 (deletion-normalized anti-reflection), R4-C-4 (refusal/bound control primitive, cited-window completeness, drop no-before-read) | Length-cap, charset and integer-coercion stubs reject every triangle. Tag-strip, zero-width and NFKC echo stubs reject. Add-to-cart twice, deposit twice and uncited-write PUT reject. | ∥ |
| 2 | `agents/r4-proof-kernel` | `src/server/proof-receipt.ts`, `src/server/verify-claims.ts` | R4-C-1 (boolean and status rules require stamped minted pair), R4-C-2 (require per-exchange `hostExpressionChallenge`, delete transcript fallback, shared normalizer, verify-claims delegates to kernel), R4-C-6 (receipt path), R4-H-7 (ablation arm, anonymous self-sabotage) | Worker-sent probes citing a minted challenge reject. Malformed-escape echo rejects. The permit-all-401 auth_bypass stub rejects. | ∥ (defines new stamped-field types first) |
| 3 | `agents/r4-verify-handlers` | `src/server/verify-prove-handlers.ts`, `src/server/verify-support.ts`, `src/server/verify-rpc.ts` | R4-C-2 (host renders and stamps probes, stop returning expectedOutput), R4-C-1 (stamp the boolean pair), R4-C-6 (input binding, persona, 401/403 control, both-arm fail-closed echo, no fake replayMode), R4-H-4 (worker-visible digest primitive in `scrubRecord`) | Two-folder presign and 400-control presign reject. No worker-facing digest equals the hash of a vault-bearing string. | after WS-2 types land |
| 4 | `agents/r4-v8-scope` | `src/server/v8-oracle-hydrate.ts`, `src/server/v8-oracle-families.ts`, `tests/r3-v8-hydrate.test.ts` | R4-C-5 (signed-resource scope, symmetric tenant derivation, flip positive tests) | Single-persona mint→download, two-persona identical URL, and admin→member all reject. | ∥ |
| 5 | `agents/r4-composite-binding` | `src/server/composite-receipt.ts`, `src/server/composite-autodag.ts`, `src/server/agent-script-proof.ts`, `tests/sys-host-autodag.test.ts` | R4-C-5 (provenance over every `oracleInput` record), R4-H-5 (object-bound control, remove DAG actor skip, auto-edges never unlock weaker rules), R4-H-6 (per-exchange tenant privilege) | The honest-RBAC stub never confirms. A dual persona's own-admin-tenant action never confirms. | ∥ |
| 6 | `agents/r4-approval-leases` | `src/server/store-runs.ts` (lease section), `src/server/request-admission.ts`, `src/server/approval-pattern.ts`, `src/server/approval-judge.ts`, `src/domain.ts`, `src/server/run-actor.ts`, `src/components/run/views/queue.tsx` | R4-H-1 | With prefix or host leases active, high-risk paths and GraphQL mutations call the judge. UI copy is generated from the predicate. | ∥ (hands `store-runs.ts` to WS-10 on merge) |
| 7 | `agents/r4-override-scan` | `src/server/scope-policy.ts` | R4-H-14 | `classifyRequestMutation` on a 2 MiB adversarial body finishes in under 50 ms. | ∥ |
| 8 | `agents/r4-credential-plane` | `src/server/persona-vault.ts`, `src/server/provider-stream.ts`, `src/server/persona-auth.ts`, `src/server/browser-session-auth.ts` | R4-H-2 (provenance-tiered needle builder), R4-H-17 (structural inbound scrub plus integrity check), R4-H-3 (mandatory host-derived refresher inputs) | Weak primary credentials yield needles. A protocol-substring needle never alters an SSE `type`. A production-caller refresher contract test. | ∥ (WS-3 switches `getKernelSecrets` to the shared builder afterwards) |
| 9 | `agents/r4-budgets-broker` | `src/server/run-safety-budgets.ts`, `src/server/broker.ts` | R4-H-19; also lands budget keys for WS-10, WS-11 and WS-14 (quarantine thresholds, `search_repo` deadline, OOB per-token quota) as a first small commit | 10k rotating-value responses keep succeeding. | ∥ (first commit merges early) |
| 10 | `agents/r4-orchestration-lifecycle` | `src/server/exec-dispatch.ts`, `src/server/execution.ts`, `src/server/exec-recon-planner.ts`, `src/server/store-runs.ts` (`refreshReadyChainSteps` / `addChainStep`, after the WS-6 handoff) | R4-H-11, R4-H-12, R4-H-13; also threads `runId` at the execution.ts code-audit `openSession` call (R4-H-8) and switches the `synthesizeInvariants` caller to the WS-11 worker API (R4-H-16) | Every terminal parent status leads to a ready or tainted child. A quarantined origin's steps leave the run able to reach verification. The single-52x and window-scroll cases. | after WS-6 for `store-runs.ts` |
| 11 | `agents/r4-host-compute` | `src/server/invariant-synthesizer.ts`, `src/server/program-graph.ts`, `src/server/phase0-recon.ts`, `src/server/untrusted-compute-pool.ts`, `src/server/agent-session.ts` | R4-H-15, R4-H-16 | Long-line tree plus single-quantifier `search_repo` finishes under budget. A 128 KB adversarial file per scanner finishes under budget. Lint bans per-match slice/split on repo content. | ∥ |
| 12 | `agents/r4-gate6-retest` | `src/server/patch-workflow.ts`, `src/server/receipt-export.ts`, `src/server/report-export.ts`, `src/server/store-findings.ts`, `src/server/schema.ts` | R4-H-9 (faithful replay from fact-log bodies, unpatched reproduction control, inconclusive on infidelity), R4-H-10 (proposal-scoped persistence, newest-retest export); also threads `runId` at the patch-workflow syntax check (R4-H-8) | Unpatched body or token validator never yields "fixed". Rejected Gate-6 then "reproduced" exports "reproduced". | ∥ |
| 13 | `agents/r4-repo-isolation` | `src/server/worker-backend.ts`, `src/server/github-repo-sync.ts`, `src/server/floor-recipe-engine.ts`, `src/server/semantic-audit.ts`, `src/server/exec-verify.ts` | R4-H-8 (required `runId`, no global fallback), R4-H-18 (attribute-neutralized, byte-accounted checkout) | Two concurrent policies never cross-mount. An amplifying `.gitattributes` fixture is rejected under the cap. | ∥ |
| 14 | `agents/r4-oob-quota` | `src/server/oob-relay.ts`, `src/server/canary-broker.ts` | R4-H-20 | More than 10k callbacks for one pending token gives bounded rows and flat insert time. | after WS-9's first commit |

**Serialization exceptions:**
- WS-3 follows WS-2, because the stamped challenge and pair fields are typed in `proof-receipt.ts`.
- WS-10 follows WS-6, because they share `store-runs.ts` (split by section with an explicit handoff).
- WS-10, WS-11 and WS-14 consume budget keys from WS-9's first commit.
- WS-3's `getKernelSecrets` change follows WS-8's shared needle builder.

**Cross-cutting guard:** extend `tests/sys-contract-canary.test.ts` so that `scripts/unwired-baseline.json` may not list any symbol from a security fix (the R4-H-3 class), and so that every oracle claiming "host-minted" asserts a per-exchange stamp (the R4-C-1 and R4-C-2 class).

## Execution log

| WS | Stream | Closes | Status | Merge SHA | Gate / Guard Result |
|---|---|---|---|---|---|
| 1 | `r4-oracle-invariants` | `R4-C-1` (kernel), `R4-C-3`, `R4-C-4` | **MERGED** | `9cbe3f9` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 56/56 r4/r3/movea/parity/taxonomy) |
| 2 | `r4-proof-kernel` | `R4-C-1` (receipts), `R4-C-2`, `R4-C-6` (receipts), `R4-H-7` | **MERGED** | `ed26d6a` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 90/91 [1 pre-existing quarantined H-5]) |
| 3 | `r4-verify-handlers` | `R4-C-1/2/6` (handlers), `R4-H-4` | **MERGED** | `02def86` | **PASS** (`tsc` 0 err, `check-unwired` PASS, `verify-rpc.ts <= 2300` LOC, 31/31 handlers/receipts/signed-url) |
| 4 | `r4-v8-scope` | `R4-C-5` | **MERGED** | `4a49d16` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 27/27 + 12/12 golden chains / 0/9 twins) |
| 5 | `r4-composite-binding` | `R4-C-5` (prov), `R4-H-5`, `R4-H-6` | **MERGED** | `09da617` | **PASS** (`tsc` 0 err, `check-unwired` PASS, `composite-receipt.ts = 749 <= 750`, 62/62 incl. 12/12 golden chains / 0/9 twins) |
| 6 | `r4-approval-leases` | `R4-H-1` | **MERGED** | `c0658ed` | **PASS** (`tsc` 0 err, build `479.54 kB`, `check-unwired` PASS, 50/50 lease/admission/Playwright) |
| 7 | `r4-override-scan` | `R4-H-14` | **MERGED** | `1b1cc70` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 2 MiB `classifyRequestMutation` 1.13ms median `<50ms`, 21/21) |
| 8 | `r4-credential-plane` | `R4-H-2`, `R4-H-17`, `R4-H-3` | **MERGED** | `1193182` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 41/41 credential/scrub/browser-session) |
| 9 | `r4-budgets-broker` | `R4-H-19` + budget keys | **MERGED** | `0f50ea2` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 24/24 incl. 10k rotating cookies/CSRF flat registry) |
| 10 | `r4-orch-lifecycle` | `R4-H-11`, `R4-H-12`, `R4-H-13` backstop, `R4-H-8` (`execution.ts`), `R4-H-16` (`exec-recon-planner.ts`) | **MERGED** | `23c4c00` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 95/95 orchestration/dispatch/step-status/origin-map) |
| 11 | `r4-host-compute` | `R4-H-15`, `R4-H-16` | **MERGED** | `01c4a1f` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 42/42 host-compute/graph/regex/repo-tools; 128KB/273KB scanners <10ms) |
| 12 | `r4-gate6-retest` | `R4-H-9`, `R4-H-10`, `R4-H-8` (patch-workflow) | **MERGED** | `a1fb6bc` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 51/51 gate6/retest/export/cascade; proposal-scoped & faithful replay) |
| 13 | `r4-repo-isolation` | `R4-H-8`, `R4-H-18` | **MERGED** | `7181691` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 53/53 repo-isolation/snapshots/quota/warmpool) |
| 14 | `r4-oob-quota` | `R4-H-20` | **MERGED** | `1c13c21` | **PASS** (`tsc` 0 err, `check-unwired` PASS, 54/54 OOB/canary/quota; >10k flood flat & bounded) |
| X | `r4-cross-guards` | L800 (`getKernelSecrets`) + L802 (`sys-contract-canary`) | **MERGED** | `40f5a17` | **PASS** (`tsc` 0 err, `verify-rpc.ts = 2275 <= 2300`, `check-unwired` PASS, 28/28 incl. Checks 5 & 6) |
