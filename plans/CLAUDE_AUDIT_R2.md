# Kovo Hunter — Claude audit round 2: critical & high (2026-11-25)

**Method.** This round audited a read-only git worktree pinned at commit `98881b4` (branch `agents/claude-audit-r2`). Round 1 ([CLAUDE_AUDIT.md](CLAUDE_AUDIT.md)) audited `4f46973`, and the earlier audit is [SECURITY-REAUDIT-2026-11-22.md](SECURITY-REAUDIT-2026-11-22.md). The round was limited to critical and high severity and had three passes:

1. **Rechecks.** All 47 round-1 critical and high items (C-1..C-8, H-1..H-39) were rechecked against the new snapshot. Any status other than OPEN then went through an adversarial status check, in which a second agent tried to reopen the finding or show the guard misses a production path.
2. **Hunting.** 12 area hunters covered: the diff since round 1, chain composition, the worker RPC surface, target-to-host, repo-to-host, confirmation paths, the secrets lifecycle, multi-run isolation, signing/crypto, lifecycle DoS, worker container launch, and the patch workflow. 5 variant hunters then expanded every round-1 C/H root cause into sibling locations.
3. **Verification.** Every new candidate went to three independent verifiers (lenses: refute or reachability; duplicate or root cause; severity). A candidate was kept only when a majority upheld it at critical or high.

| New candidates | Kept (C/H) | Downgraded below high | Duplicates of round 1 | Refuted |
|---:|---:|---:|---:|---:|
| 198 | 69 | 83 | 29 | 17 |

The 69 kept candidates collapse into **9 critical (R2-C-1..9) and 29 high (R2-H-1..29)** findings after merging shared root causes. Many of them are residual locations of round-1 items that are still OPEN or PARTIAL. Those entries say so, and they point to the round-1 subsection for root cause and fix instead of repeating it.

Every critical location was spot-checked against `98881b4` while writing this report. No benchmarks, Docker or network calls were run. In-memory experiments used only pure functions and regexes. No exploit payload strings appear anywhere in this document; probes are described by class.

## Executive summary

Ranked by risk:

1. **Scanned repos and targets can compromise the host.**
   - **R2-C-1:** a compose `image:` value is passed to `docker run` as an unvalidated argument. A value that starts with `--` becomes a docker option, so a hostile repo can bind-mount host paths read/write or run privileged. That means host secret theft and persistent code execution, with no LLM and no approval involved.
   - **R2-C-2:** dotted JSON parameter names reach `setJsonPath`, which pollutes `Object.prototype` across the whole process. This can flip egress defaults (`allowLocalLab`, `allowedPorts`) or crash egress for every run and tenant. The untrusted worker (`probe_differential.paramName`) or target JSON can trigger it.
2. **The worker can still recover hidden secrets.**
   - C-3 is still **OPEN (critical)**: the regex selector of `capability.seal` acts as an oracle over raw bytes.
   - Two more oracles were found, both new and both critical:
     - **R2-C-3:** `composite.verify` gives a substring oracle over raw, unredacted JSON leaves, with no rate limit.
     - **R2-C-4:** `crypto.hmacSign` returns a raw HMAC keyed by a slice the worker sealed, which allows offline brute force.
   - **R2-H-4:** `scrubbedPreview` truncates before it redacts, which leaks secret prefixes.
3. **The proof kernel still accepts false "confirmed" verdicts on ordinary traffic.** All of these are untrusted-worker or model inputs that reproduce deterministically across both fresh runs, so I1 does not catch them.
   - New:
     - **R2-C-5:** any HTML page that contains a script element confirms XSS.
     - **R2-C-6:** any search or filter differential plus a marker the worker picks confirms SSTI, command or SQL injection.
   - Residual locations of round-1 items:
     - **R2-C-7 / C-6:** business_logic confirms from an anonymous 401, `resourceBound`, or a repeated POST.
     - **R2-C-8 / C-4:** V8 oracle operands and record roles are chosen by the model.
     - **R2-C-9 / H-9:** the request plane is scrubbed with the vault, which defeats the anti-reflection check.
   - Round-1 C-5, C-7, H-11 and H-12 are also still critical.
4. **Credentials are sent to third parties.**
   - **R2-H-2:** the provider pool sends the primary profile's API key to every other profile's endpoint, on round-robin and on failover, under default settings.
   - **R2-H-3:** Supabase auto-discovery lets target HTML pick the endpoint that receives persona email and password.
5. **Approval and scope controls are bypassed.**
   - **R2-H-1:** on default Tier-3 public runs, which now run in `staging_isolated`, a POST that carries a method override and that the target executes as DELETE is auto-approved, with no judge and no operator.
   - C-1 remains PARTIAL: HTTP/2 skips throttling, the circuit breaker, audit and the egress proxy.
   - C-2 / R2-H-5: subdomain auto-admit still widens to SaaS vendor apexes and overrides scope-review deselection.
6. **Remediation verdicts are unreliable.**
   - H-19 is OPEN and R2-H-15 adds to it: probe-arm 5xx or 429 responses and recipes with no control arm both report `fixed`.
   - **R2-H-16:** persisted proof scripts are heuristically redacted and then re-executed, which turns real findings into `fixed` or `dismissed`.
   - H-23: retests run with expired sessions.
7. **Runs wedge.**
   - **R2-H-17:** a kill-switch trip followed by a reset, or a dispatch during drain, leaves the run a permanently aborted zombie.
   - **R2-H-18:** an approval waiter bound to the wrong signal wedges investigation when the operator approves.
   - **R2-H-19:** a compressed HTTP/1.1 response that closes mid-body never settles, so per-origin slots leak across runs.
8. **Host event-loop availability.** Untrusted target or repo bytes still reach backtracking regexes and amplifying parsers on the main thread:
   - H-32 and H-33 OPEN.
   - H-35 and H-36 PARTIAL. The `@swc/core` native segfault (R2-H-23) kills the process on source deployments that have run `worker:install`.
   - New sites: R2-H-24..29.
9. **The containerized DooD deployment is broken.**
   - **R2-H-22:** every kovo_verify session fails to mount the RPC socket.
   - **R2-H-21:** concurrent runs share one warm-pool `/repos` staging directory.

**Round-1 tally.** Of the 47 round-1 C/H items:

| Status | Count | Items |
|---|---:|---|
| OPEN | 11 | 10 of them contested and upheld as OPEN |
| PARTIAL | 24 | |
| FIXED | 12 | H-1, H-7, H-10, H-21, H-22, H-26, H-29, H-30, H-34, H-37, H-38, H-39 |
| CHANGED | 0 | |
| NOT_REPRODUCIBLE | 0 | |

Nine round-1 items are rated critical at this snapshot: C-3, C-4, C-5, C-6, C-7, H-9, H-11, H-12 and H-35.

## New critical & high findings

Each entry lists its category, locations, what is wrong, evidence, attack path, impact, recommendation, related round-1 IDs, and how it was verified. Line numbers are at `98881b4`.

### Critical

#### R2-C-1 — Compose `image:` value becomes an injected `docker run` option (host bind mount → secret theft and host code execution)

- **Category:** security (repo → host)
- **Location:**
  - [lab-proxy.ts#L428](../src/server/lab-proxy.ts#L428) (`validateComposeServiceSource` returns `normalized.image` unchecked)
  - [lab-proxy.ts#L718](../src/server/lab-proxy.ts#L718) (`buildLabContainerRunArgs` appends `imageName` and `cmd` with no `--`)
  - [lab-runner.ts#L780](../src/server/lab-runner.ts#L780)
  - [compose-parse.ts#L1227](../src/server/compose-parse.ts#L1227)
- **What's wrong:**
  - The compose hardening rejects forbidden keys (privileged, network_mode, cap_add, devices, pid, security_opt), volumes, ports, build context and root user, but it never validates the image reference.
  - The image goes into argv as a bare positional after all of Kovo's options. Docker parses `run` options up to the first positional, so an image value that starts with `--` is read as another option that comes after the hardening flags. The first element of the compose `command` array then becomes the real image.
  - Later flags override earlier ones. An injected bind mount, `--user` or privilege flag therefore defeats the volume allow-list, the read-only repo-only `/app` mount and the internal network.
  - Only the proxy image is regex-checked ([lab-proxy.ts#L810](../src/server/lab-proxy.ts#L810)).
  - Sidecars ([lab-runner.ts#L961](../src/server/lab-runner.ts#L961)) and the Gate-6 rebuild ([lab-runner.ts#L1174](../src/server/lab-runner.ts#L1174)) use the same path.
- **Evidence:**
  - `parseAndSanitizeComposeYaml` accepted a service whose image was a quoted harmless double-dash label option, with an array command.
  - `buildLabContainerRunArgs` put that option string directly before the command's first element.
  - Confirmed by three verifiers.
- **Attack path:**
  1. A hostile repository is synced or mounted.
  2. The operator sets `labConfig.dockerComposeFile` to the repo's compose file, which is the documented local-lab flow.
  3. Run start calls `startLabTarget`, which parses and sanitizes the file, then calls `runDocker`.
  4. The container starts as the Kovo uid with a host path mounted read/write.
  5. It reads the model credential, the GitHub PAT and the held-out salt and serves them to the scanner, and/or writes to shell rc files or the Kovo source tree.
- **Impact:** host secret exfiltration and persistent host code execution. On a rootful daemon with injected privilege flags this reaches host root. No model and no approval is involved.
- **Recommendation:**
  - Validate every compose and LabConfig image against a strict reference grammar: no leading `-`, no whitespace, no `=`. Prefer an allow-list of local or pinned images.
  - Insert `--` before the image in every docker argv that carries repo-derived positionals, and add `--pull never`.
  - Run lab containers as a dedicated uid that owns no Kovo files.
  - Add a regression test that rejects a leading-dash image and asserts that `--` comes before the image in argv.
- **Related round-1 IDs:** H-37, H-38, M-9.
- **Verification:** 3/3 verifiers upheld it as critical. Spot-checked at `98881b4` (lab-proxy.ts:428 and :718-723).

#### R2-C-2 — Process-wide `Object.prototype` pollution through dotted JSON parameter paths

- **Category:** security (worker/target → host)
- **Location:**
  - [probes/context.ts#L272](../src/server/probes/context.ts#L272) (`setJsonPath`)
  - [probes/context.ts#L356](../src/server/probes/context.ts#L356) (json location) and [#L465](../src/server/probes/context.ts#L465) (graphql_var)
  - Worker ingress: [agent-session.ts#L1703](../src/server/agent-session.ts#L1703), [exec-worker-runner.ts#L953](../src/server/exec-worker-runner.ts#L953), [surface-engine.ts#L612](../src/server/surface-engine.ts#L612)
  - Target ingress: [phase0-recon.ts#L1758](../src/server/phase0-recon.ts#L1758) and [#L1919](../src/server/phase0-recon.ts#L1919)
- **What's wrong:**
  - `setJsonPath` splits the parameter name on `.` and walks `cur = cur[part]` whenever the existing value is an object. It never rejects prototype accessor keys (`__proto__`, `constructor`, `prototype`).
  - A segment equal to the accessor key therefore resolves to the shared prototype, and the final assignment writes onto it. This happens while the request is being built, before the broker admits or denies it.
  - Parameter names come from two untrusted sources:
    - the worker's `probe_differential.paramName`, a free 128-character string that the host passes through without validation;
    - target JSON keys and OpenAPI properties, for which recon filters only whole-key prototype names, not dotted segments.
  - Note: the verifiers found that `candidateFields` is not forwarded from the worker `probe_differential` handler. Only the deterministic engine fills it. `paramName` alone is enough to trigger the bug.
- **Evidence:**
  - In memory, `injectUniversalParam` (json and graphql_var locations) emitted an empty wire body and left a process-wide prototype property set. A segment starting with `is` gives a boolean `true` through the mass-assignment path.
  - Consumers whose behavior changes:
    - [egress-gateway.ts#L445](../src/server/egress-gateway.ts#L445): `Boolean(policy.allowLocalLab)` disables the private and loopback guard, and allows HTTP.
    - [egress-gateway.ts#L450](../src/server/egress-gateway.ts#L450): a polluted non-callable `allowOrigin` throws a TypeError on every egress check.
    - [request-admission.ts#L288](../src/server/request-admission.ts#L288): `allowedPorts?.includes` coerces a string.
- **Attack path:** the worker calls `probe_differential` against an in-scope path, with `paramName` whose first segment is the prototype accessor and `paramLocation=json`. Global state changes immediately, for all runs, until the process restarts.
- **Impact:** cross-tenant mutation of global host state. The private-address egress guard can be disabled, or egress crashes host-wide. There is no audit trail.
- **Recommendation:**
  - Reject prototype accessor keys in every path segment.
  - Walk only own properties (`Object.hasOwn`) and create intermediate containers with `Object.create(null)`.
  - Validate names at every ingress: the `probe_differential` schema, `PARAM_NAME_RE`, OpenAPI `addParam`, and each segment in `extractJsonFieldNames`.
  - Defense in depth: freeze `Object.prototype` at host start, or run with `--disable-proto=throw`.
  - Add a regression test that asserts `({}).x === undefined` after injecting through every location.
- **Related round-1 IDs:** none. This is a new root cause. Adjacent to M-48 and H-5.
- **Verification:** 3/3 verifiers upheld it as critical. Spot-checked at `98881b4` (context.ts:272-293).

#### R2-C-3 — `composite.verify` is an unthrottled substring oracle over raw, unredacted request and response JSON

- **Category:** security (worker secret exfiltration)
- **Location:**
  - [composite-receipt.ts#L179](../src/server/composite-receipt.ts#L179) (`entryMatchesCorrelation`)
  - [composite-receipt.ts#L414](../src/server/composite-receipt.ts#L414) and [#L420](../src/server/composite-receipt.ts#L420)
  - [composite-receipt.ts#L716](../src/server/composite-receipt.ts#L716)
  - [verify-rpc.ts#L2054](../src/server/verify-rpc.ts#L2054) (step.json taken from `rawBodies`)
  - [verify-rpc.ts#L2143](../src/server/verify-rpc.ts#L2143) (verdict returned to the worker)
  - [verify-rpc.ts#L504](../src/server/verify-rpc.ts#L504)
- **What's wrong:**
  - The H-9 fix made `buildHostSignedTranscript` parse step JSON from raw, pre-redaction response bodies and from request bodies after inline-capability substitution.
  - `verifyAsyncPivotBinding` tests a correlationId the worker chooses with `leaf.includes(...)` against every JSON leaf, up to 2048 characters per leaf. The schema allows a correlationId of length 1.
  - A miss returns a distinct reason, "fromHop … has no trigger matching". `handleCompositeVerify` returns the whole verdict, including the stage, the reason and `verifiedEdges`.
  - There is no budget, and no egress is needed.
  - A related path: [verify-rpc.ts#L1062](../src/server/verify-rpc.ts#L1062) tests worker `correlationIds` by substring against raw combined text, and feeds the same matcher.
- **Evidence:** in memory, with a hidden leaf, a correct prefix advanced to `terminal_impact` with the edge verified, and a wrong prefix stopped at `edge_binding`. Citations only need real exchange IDs from the session.
- **Attack path:**
  1. The worker calls an in-scope endpoint as a persona, and the response holds that persona's token. The worker sees it redacted, which tells it where to aim. Alternatively, it seals a cookie and inlines it into a JSON request body.
  2. It submits two-hop receipts with an `async_pivot_binding` edge whose correlationId extends a guess one character at a time, about 62 calls per character.
  3. It prints the recovered value, which reaches model context.
- **Impact:** persona tokens, rotated sessions, redacted target secrets and sealed capability values can all be recovered. This breaks I3 through an op that the C-3 fix does not cover.
- **Recommendation:**
  - Match correlation only against host-minted identifiers (poll entity IDs, OOB tokens), by equality, with a minimum length and entropy. Alternatively, match only against worker-visible scrubbed leaves.
  - Return only a coarse confirmed/rejected result to the worker.
  - Add a run-scoped `composite.verify` budget.
  - Apply the same rule to the value_binding `valueDigest`/`entityId` equality (downgraded to medium, listed below).
- **Related round-1 IDs:** C-3, H-9, M-25.
- **Verification:** two candidates (worker-rpc-surface and variant-of-C-3) merged. 6/6 verifier passes upheld it as critical. Spot-checked at `98881b4` (composite-receipt.ts:179).

#### R2-C-4 — `crypto.hmacSign` returns a raw HMAC keyed by a worker-sealed slice of a hidden secret (offline brute force)

- **Category:** security (worker secret exfiltration)
- **Location:**
  - [verify-rpc.ts#L1670](../src/server/verify-rpc.ts#L1670) (`handleCryptoHmacSign`)
  - [verify-rpc.ts#L1567](../src/server/verify-rpc.ts#L1567) (regex selector over raw body)
  - [derived-custody.ts#L424](../src/server/derived-custody.ts#L424) (`hostHmacSign`)
  - [egress-sanitizer.ts#L150](../src/server/egress-sanitizer.ts#L150)
- **What's wrong:**
  - The C-3 fix removed digests from the seal meta. However, the regex selector can still capture `(8−k)` characters the worker already knows plus `k` unknown secret characters, and validation checks only length and a single repeated character.
  - `hmacSign` accepts any sealed handle in the run, with no restriction on kind or how the value was selected. It returns `createHmac(alg, rawValue).update(workerPayload)` unchanged, and `scrubRecord` does not touch HMAC output.
  - `hmacSign` has no rate limit.
- **Evidence:** `EgressSanitizer.sanitizeValue(…, 'worker_rpc')` passed hex, base64 and base64url HMAC outputs through unchanged. At k=3, a 32-character token needs about 11 seals, within 12 per exchange and 128 per session. Re-fetching a resource resets the per-exchange count.
- **Attack path:**
  1. Seal a sliding window of known context plus k unknown characters.
  2. Call `hmacSign` with a constant payload.
  3. Enumerate 62^k candidates offline inside the worker.
  4. Shift the window and repeat.
  5. Print the recovered plaintext.
- **Impact:** target tokens, persona session tokens and API keys that the host hid from the worker reach the worker and the model. This breaks I3, the same class as C-3.
- **Recommendation:**
  - Do not return raw HMAC output to the worker. Seal it behind a derived handle, as `jwtSign` already does.
  - Allow raw signatures only for host-designated signing-key kinds that were extracted by whole-field selectors (jsonPath, header or cookie name), never by free regex captures.
  - Count `hmacSign` and `jwtSign` calls against the seal budget.
  - Require minimum entropy for regex-selected seals.
- **Related round-1 IDs:** C-3, H-9.
- **Verification:** 3/3 verifiers upheld it as critical. Spot-checked at `98881b4` (verify-rpc.ts:1670 and :1726 return the signature).

#### R2-C-5 — Markup/XSS impact oracle confirms on any script element in a 2xx body, or on any request token echoed back

- **Category:** correctness (forged confirmation)
- **Location:**
  - [oracle-invariants.ts#L536](../src/server/oracle-invariants.ts#L536) (`ACTIVE_MARKUP_RE`)
  - [oracle-invariants.ts#L2580](../src/server/oracle-invariants.ts#L2580) (`assessMarkupImpact`) and [#L2593](../src/server/oracle-invariants.ts#L2593) (planted marker)
  - [proof-receipt.ts#L169](../src/server/proof-receipt.ts#L169) and [#L734](../src/server/proof-receipt.ts#L734)
  - [verify-claims.ts#L1158](../src/server/verify-claims.ts#L1158) and [#L1185](../src/server/verify-claims.ts#L1185)
  - [floor-recipe-engine.ts#L3532](../src/server/floor-recipe-engine.ts#L3532)
- **What's wrong:** there are two independent branches, and either one returns satisfied on its own.
  - **activeMarkup:** `ACTIVE_MARKUP_RE` matches anywhere in any 2xx probe body. Nearly every HTML page matches, including SPA shells that load a bundle. Nothing compares the body to a control, binds the match to a payload, or checks the content type.
  - **plantedMarker:** collects every run of 8 to 64 identifier characters from any successful mutating step's request JSON. It confirms when one of those runs appears in a probe body and in no control body. An ordinary create-then-echo of a plain title satisfies it, with no HTML context, escaping check or execution check.
  - Receipt classes xss, xss_stored, xss_reflected, markup and html_injection all route to this assessor. The markup class is exempt from the stub guard.
- **Evidence:**
  - Identical benign HTML control and probe that load an app script gave `verifyReceipt` confirmed=true (rule impact) for markup, xss_reflected and xss_stored.
  - A JSON create POST that echoes a nine-letter title confirmed through plantedMarker, both alone and with an empty-list control.
- **Attack path:** a worker script cites a GET of any HTML page as the probe of an impact claim with impactClass markup (or vulnClass xss_*). Alternatively it cites a create plus its echo. `buildAgentScriptReceipt` → `TerminalOracleRegistry` → confirmed.
- **Impact:** confirmed XSS on almost any web app, with a signed receipt, from untrusted model input or an honest model's mistake.
- **Recommendation:**
  - Confirm XSS only with browser execution attestation (see C-8).
  - On the HTTP side, require all of: a host-minted nonce carried by the probe request, that nonce absent from every same-route control, an HTML media type, and an executable context.
  - Delete the generic identifier-run harvest.
- **Related round-1 IDs:** C-8 (same "presence treated as execution" pattern, new location), H-13.
- **Verification:** two candidates merged. 6/6 verifier passes upheld it as critical. Spot-checked at `98881b4` (oracle-invariants.ts:536, :2580-2612).

#### R2-C-6 — Evaluated-expression oracle confirms SSTI/command/SQL injection from any value-dependent page difference and a worker-chosen marker

- **Category:** correctness (forged confirmation)
- **Location:**
  - [proof-receipt.ts#L1532](../src/server/proof-receipt.ts#L1532) (`verifyEvaluatedExpression`)
  - [proof-receipt.ts#L738](../src/server/proof-receipt.ts#L738) (fallback)
  - [proof-receipt.ts#L1925](../src/server/proof-receipt.ts#L1925) (body_contains pair)
  - [verify-prove-handlers.ts#L834](../src/server/verify-prove-handlers.ts#L834) (`prove_injection_differential`)
  - [agent-prompts.ts#L1079](../src/server/agent-prompts.ts#L1079)
- **What's wrong:**
  - Confirmation requires only four things:
    - a marker of at least 4 characters is in the 2xx probe body;
    - the marker is absent from the 2xx control bodies;
    - the marker is absent from the probe request text;
    - control and probe share a route family but differ in path or body.
  - The marker comes from the worker (`expectedOutput`, body_contains text, or proofPatterns), and so does vulnClass.
  - Nothing checks that the probe carries an expression or that the marker was computed by the host. Origin and persona are never compared.
  - The helper also emits a structural_diff claim, so the claim-layer injection gate passes.
- **Evidence:**
  - Control `?category=books` vs probe `?category=music`, with a product name present only in the probe JSON as the marker. Result: confirmed=true for command_injection, ssti and sqli (built as sqli_error).
  - Reproduced end to end with `verifyScript` and the local attempt factory.
- **Attack path:** the model runs `ctx.prove_injection_differential` on any search, filter or list endpoint and picks a marker from the matching record. Both fresh runs reproduce it.
- **Impact:** runtime-confirmed CWE-78, CWE-89 or CWE-1336 findings on every parameterized read endpoint, at scale.
- **Recommendation:**
  - The host mints the expression operands per attempt, requires the probe to carry them in a recognized expression syntax, and checks for the host-computed result. That result must differ between attempts.
  - Reject worker markers.
  - Require the same origin, persona and request shape apart from the injected value.
  - Until this exists, downgrade body_contains pairs to a lead.
- **Related round-1 IDs:** C-7 (same root pattern, different oracle), H-16, H-13.
- **Verification:** two candidates merged. 6/6 verifier passes upheld it as critical. Spot-checked at `98881b4` (proof-receipt.ts:1532-1545).

#### R2-C-7 — business_logic assessor confirms on an anonymous or lower-role denial, an attribution-only resource binding, or a duplicated POST (residual of C-6)

- **Category:** correctness (forged confirmation)
- **Location:**
  - [oracle-invariants.ts#L1659](../src/server/oracle-invariants.ts#L1659) (`peerDenial`)
  - [oracle-invariants.ts#L1685](../src/server/oracle-invariants.ts#L1685) (boundary early return)
  - [oracle-invariants.ts#L1696](../src/server/oracle-invariants.ts#L1696) (repeatedTransition)
  - [oracle-invariants.ts#L1716](../src/server/oracle-invariants.ts#L1716) and [#L1764](../src/server/oracle-invariants.ts#L1764) (`resourceBound`, added in `ecc0cae`)
- **What's wrong:** three branches each return satisfied with no protected field and no attributable invariant break.
  - **(a) peerDenial:**
    - It accepts an unauthenticated control unless a cross-tenant write was declared. The agent-script path never sets `resourceTenant`, so that exception never applies.
    - It accepts any control when either actor lacks tenant metadata.
    - It accepts any same-tenant control with no role-rank comparison.
    - The boundary branch then returns before `findPersistence` is called.
  - **(b) resourceBound:** this proves only that the delta belongs to the probe (attribution), yet it is also accepted as impact. That contradicts the function's own docstring.
  - **(c) repeatedTransition:** this needs only two 2xx steps with the same method, route and body. Any non-idempotent create qualifies.
- **Evidence:** in-memory `verifyReceipt` and the production chain with strict host derivation. Each of these confirmed CWE-840:
  - an anonymous PATCH returning 401, then a member PATCH returning 200;
  - a viewer 403, then an admin 201 (correct RBAC);
  - create, read, complete, read on the caller's own todo;
  - two identical 201 creates.
  - `tests/t2-oracle-invariants.test.ts:70-79` and `tests/v7-shopflow-fp.test.ts:117` lock in the wrong behavior.
- **Attack path / root cause / fix:** see the C-6 subsection below.
- **Impact:** a false confirmed CWE-840 on any authenticated write endpoint.
- **Recommendation:** see C-6. Remove `resourceBound` from the impact gate. Reject anonymous controls and require an equal-or-higher-rank peer plus persistence. Require prior-state proof for repeated transitions.
- **Related round-1 IDs:** C-6.
- **Verification:** four candidates merged (diff-since-r1 plus three variant-of-C-6). 3/3 verifiers on each candidate. The `resourceBound` candidate was rated high or critical, and critical was taken for consistency with C-6. Spot-checked at `98881b4` (oracle-invariants.ts:1659-1666, :1696, :1764).

#### R2-C-8 — V8 oracle hydration: model-chosen field-path selectors, unbound record roles, single-exchange crypto replay, model-labelled surfaces and substring IDs (residual of C-4)

- **Category:** correctness (forged confirmation)
- **Location:**
  - [v8-oracle-hydrate.ts#L947](../src/server/v8-oracle-hydrate.ts#L947) and [#L469](../src/server/v8-oracle-hydrate.ts#L469) (field paths)
  - [v8-oracle-hydrate.ts#L371](../src/server/v8-oracle-hydrate.ts#L371) and [#L916](../src/server/v8-oracle-hydrate.ts#L916) (role records)
  - [v8-oracle-hydrate.ts#L742](../src/server/v8-oracle-hydrate.ts#L742) (crypto)
  - [v8-oracle-hydrate.ts#L725](../src/server/v8-oracle-hydrate.ts#L725) (temporal)
  - [v8-oracle-hydrate.ts#L594](../src/server/v8-oracle-hydrate.ts#L594) and [#L699](../src/server/v8-oracle-hydrate.ts#L699) (substring tokens)
  - [v8-oracle-families.ts#L333](../src/server/v8-oracle-families.ts#L333) and [#L472](../src/server/v8-oracle-families.ts#L472)
  - [composite-receipt.ts#L574](../src/server/composite-receipt.ts#L574) and [#L680](../src/server/composite-receipt.ts#L680)
- **What's wrong:** the C-4 fix replaced model-supplied operands with operand selectors that the model chooses. Each variant below confirmed against a conserved, honest transcript:
  - `*FieldPath` selectors can point at any numeric leaf.
  - Any transcript exchange can fill the baseline, action or final role, and that includes a GET used as the "action".
  - One 200 exchange can be cited as both issuance and replay, so the host-derived digests match each other trivially.
  - Tenant and scope labels are free strings.
  - Temporal surfaces are model-picked enums. Choosing different surfaces skips the distinctness check.
  - Batch IDs and record IDs are matched by substring.
- **Evidence:**
  - These came back confirmed=true:
    - the repo's own conserved-ledger fixture, confirmed as over_refund through `paidAmountFieldPath`;
    - balance_minting with `actions=[baseline GET]`;
    - three plain GETs across two wallets, confirmed as value minting;
    - a single own-tenant GET used as a cross-tenant crypto scope replay;
    - temporal_revocation and batch_partial_authz built from benign traffic.
  - The honest over_refund control without paths was rejected, as it should be.
- **Attack path / root cause / fix:** see the C-4 subsection below.
- **Impact:** false critical findings (value minting, over-refund, cross-tenant replay) from untrusted input.
- **Related round-1 IDs:** C-4, C-5.
- **Verification:** five candidates merged: three critical (field paths, record roles, crypto) and two high (temporal, batch). 3/3 verifiers on each. The verifiers noted that the temporal and batch variants are the same C-4 root cause. Spot-checked at `98881b4` (v8-oracle-hydrate.ts:947-955).

#### R2-C-9 — Capability-vault scrubbing of the kernel request plane defeats the anti-reflection checks: SSTI evaluated-expression and the H-16 echo strip (residual of H-9)

- **Category:** correctness (forged confirmation)
- **Location:**
  - [verify-rpc.ts#L1124](../src/server/verify-rpc.ts#L1124) (`prepareCapRequest` stores `this.scrub(pathAndQuery)` and `scrubRecord(headers)`)
  - [verify-rpc.ts#L339](../src/server/verify-rpc.ts#L339) (`egress` includes `capabilityVaults`)
  - [verify-rpc.ts#L977](../src/server/verify-rpc.ts#L977), [#L1039](../src/server/verify-rpc.ts#L1039) and [#L2073](../src/server/verify-rpc.ts#L2073)
  - [host-fact-log.ts#L796](../src/server/host-fact-log.ts#L796)
  - Consumers: [proof-receipt.ts#L1544](../src/server/proof-receipt.ts#L1544) and [oracle-invariants.ts#L2295](../src/server/oracle-invariants.ts#L2295)
- **What's wrong:**
  - The H-9 fix made the kernel response plane raw. The request plane (path, headers, carrierText) still goes through the vault-aware worker sanitizer.
  - A worker that seals a reflected marker therefore produces a request that shows a placeholder while the raw body still shows the marker.
  - `verifyEvaluatedExpression`'s check `!probeReqText.includes(marker)` and `requestEchoTokens` both then treat reflection as server-side evaluation.
- **Evidence:**
  - An SSTI receipt with a raw path gave confirmed=false. The same exchanges with the vault-placeholder path gave confirmed=true ("non-reflected").
  - `assessInjectionImpact` on an echoed engine-error fingerprint gave satisfied=false with the raw path and true with the scrubbed path (family sqli).
  - The vault is run-shared, so both attempts reproduce.
- **Attack path / root cause / fix:** see the H-9 subsection below.
- **Impact:** any page that reflects input confirms SQL, template, command, XXE or traversal injection.
- **Related round-1 IDs:** H-9, H-16.
- **Verification:** two candidates merged (one critical, one high). The echo-strip variant was upheld as critical by 2/3 verifiers. Spot-checked at `98881b4` (verify-rpc.ts:339 and :1124-1125).

### High

#### R2-H-1 — An HTTP method override defeats the auto_review "deletes ask first" gate on derived `staging_isolated` runs

- **Category:** security (egress outside approval, data loss)
- **Location:**
  - [request-admission.ts#L731](../src/server/request-admission.ts#L731) (`isStructuralMutation` looks only at the literal verb)
  - [request-admission.ts#L1433](../src/server/request-admission.ts#L1433) (auto_review auto-approve)
  - [store-runs.ts#L123](../src/server/store-runs.ts#L123) (`deriveDefaultEnvironmentMode`, added in `1668ffd`)
  - [execution.ts#L3429](../src/server/execution.ts#L3429) (host tags every mutation)
  - [scope-policy.ts#L931](../src/server/scope-policy.ts#L931)
  - UI promise at [consent.tsx#L714](../src/components/run/views/consent.tsx#L714)
- **What's wrong:**
  - Public projects at Tier 3 or above (or yolo) now default to `staging_isolated`.
  - The host adds the run tag header to every write, so `requestCarriesTenantTag` always allows the request. That makes L-2's no-op tag contract the default.
  - In the auto_review branch, only `isStructuralMutation` (DELETE, multipart or compressed) is held for review. Every other request is contract-approved without ever reaching `isStateChangeApproved`, so no judge and no operator sees it.
  - Nothing in `src/server` normalizes or strips method-override headers or body `_method` parameters. `FORBIDDEN_CALLER_HEADERS` lets them through.
- **Evidence:**
  - Traced at `98881b4` by 3 verifiers.
  - A derived mode emits no `scope.environment_mode` event, so `explicitEnvironmentMode` is false.
  - Correction: the default `capabilityTier` is 1. Tier 3 is an operator choice, and it is the Supervised preset.
- **Attack path:** on a Supervised public run, the worker (or a model steered by the target) sends `request_http` as a POST with a method-override header or form `_method`, targeting an in-scope object ID on a Rails, Laravel, Symfony or Express-override app. The request is tagged, allowed and auto-approved, and the framework executes it as DELETE.
- **Impact:** destructive writes reach live targets without the human approval the UI promises. The audit trail records them as "safe tagged write".
- **Recommendation:**
  - Compute the effective verb including overrides, or refuse override carriers on non-lab targets.
  - Treat override-bearing requests as structural.
  - Do not treat a tag the host added itself as proof of isolation. For a derived `staging_isolated` mode, require an operator-declared tenant contract, or send auto_review writes through the judge with headers and the full body.
- **Related round-1 IDs:** M-2, L-2, M-3, H-3 (override not handled anywhere).
- **Verification:** 3/3 upheld as high. Spot-checked at `98881b4` (request-admission.ts:731 and :1433-1437).

#### R2-H-2 — Model provider pool sends the primary profile's API key to every other profile's endpoint

- **Category:** security (credential disclosure)
- **Location:**
  - [provider.ts#L689](../src/server/provider.ts#L689) (pool auth resolver returns `primary.key`)
  - [provider.ts#L580](../src/server/provider.ts#L580) (candidate stream gets the caller's `sOpts`)
  - [provider.ts#L413](../src/server/provider.ts#L413) (`...sOpts` spread with no apiKey override)
  - [provider.ts#L244](../src/server/provider.ts#L244) (key rewritten for openrouter.ai only)
- **What's wrong:**
  - pi-ai's `applyAuth` sets `requestOptions.apiKey` from the pool's single resolver.
  - `wrapMethod` builds each candidate's implementation but passes that `sOpts` through unchanged, so the OpenAI and Anthropic clients sign with the primary profile's key.
  - Priority defaults to 100, so `orderProfiles` round-robins inside equal groups. With two enabled profiles at default settings, about every other call, plus every failover, sends key A to endpoint B.
- **Evidence:**
  - A stubbed-fetch run with two profiles at priority 100 captured KEY-A on every request to `b.example.test`. KEY-B was never sent.
  - Callers include agent sessions, the approval judge, dedupe, semantic audit and patch authoring.
- **Attack path:** an operator configures a fallback profile on another vendor or a self-hosted gateway, or another UI user adds a profile that points at an endpoint they control. The primary long-lived key arrives there.
- **Impact:**
  - The primary model credential is disclosed to a third-party or attacker-chosen endpoint. This bypasses the M-15 per-profile endpoint pinning.
  - Failover never works, because B always fails auth and gets marked hard-failed.
- **Recommendation:**
  - Override per candidate: pass `{ ...sOpts, apiKey: candidate.key }` and set `apiKey: settings.key` last in `streamOpts`.
  - Better, in `makeFetch` delete any incoming `authorization` / `x-api-key` header and set the protocol's header from `settings.key`.
  - Add a regression test with two profiles.
- **Related round-1 IDs:** M-15.
- **Verification:** 3/3 upheld as high. Spot-checked at `98881b4` (provider.ts:689-692 and :578-581).

#### R2-H-3 — Supabase auto-discovery lets target content choose where persona email and password are sent

- **Category:** security (credential routing)
- **Location:**
  - [persona-auth.ts#L963](../src/server/persona-auth.ts#L963) (first hosted Supabase URL in the text wins)
  - [persona-auth.ts#L1559](../src/server/persona-auth.ts#L1559)
  - [persona-auth.ts#L1846](../src/server/persona-auth.ts#L1846) (`auto` adapter switches to supabase)
  - [persona-auth.ts#L2381](../src/server/persona-auth.ts#L2381) and [#L2308](../src/server/persona-auth.ts#L2308) (self-authorizing `isSupabaseCredentialHost(discoveredOrigin, …, discoveredOrigin)`)
- **What's wrong:**
  - With the default `auto` adapter and no loginUrl, `inspectTargetOrigin` scrapes the homepage and up to 4 same-origin bundles. Any hosted-Supabase URL it finds switches the adapter.
  - The discovered origin is passed in as its own authorizer, then appended to the credential allowlist. `credentialFetch` POSTs JSON `{email, password}` there.
  - The Clerk path next to it was hardened against exactly this; the Supabase path was not. The code is new since round 1.
- **Evidence:** a node run showed HTML containing only another project's public storage URL produced `supabaseOrigin` set to that project, and the authorization check returned true.
- **Attack path:** a third party who can put content into the target homepage or first bundles (UGC, a CMS widget, a dependency) inserts their project URL. The next persona login sends the credentials to their project.
- **Impact:** operator persona credentials go to an origin outside the persona allowlist and run scope, with no approval.
  - Verifier disagreement: one verifier noted that hosted GoTrue does not expose password bodies to project owners. Email, custom headers and the attempt itself are exposed. Benign apps that reference two projects misroute logins.
- **Recommendation:**
  - Take the Supabase origin only from an operator loginUrl or an explicit `originAllowlist`.
  - Drop the self-authorizing argument.
  - At minimum, require an anon-key JWT `ref` that equals the host ref, plus operator confirmation.
- **Related round-1 IDs:** none (new code).
- **Verification:** verifiers rated it critical, high and medium. Settled at high. Spot-checked at `98881b4` (persona-auth.ts:2381-2386).

#### R2-H-4 — `capability.seal` returns a raw-body preview that is truncated before it is redacted, leaking secret prefixes

- **Category:** security (worker secret exfiltration)
- **Location:**
  - [verify-rpc.ts#L1660](../src/server/verify-rpc.ts#L1660)
  - The same order exists in `exchangeView` at [verify-rpc.ts#L1088](../src/server/verify-rpc.ts#L1088) (512 KiB slice, medium, listed below)
- **What's wrong:**
  - The code computes `redact(this.scrub(raw.slice(0, 1024)))`.
  - Exact-value and key/value redaction both need the whole token. A secret that crosses byte 1024 therefore comes back with up to length−1 characters exposed.
  - Line 1539 in the same function does it correctly: redact first, then slice.
- **Evidence:** with an 18-character named secret placed so it crossed byte 1024, `redact()` returned 9 to 14 unredacted characters depending on the offset. Redacting the full body leaked nothing.
- **Attack path:** the worker seals any benign field of an exchange. It moves the secret across byte 1024 using reflected input or pagination, and reads the prefix. No oracle is needed.
- **Impact:** partial disclosure of persona and named secrets and sealed values. Breaks I3.
- **Recommendation:** redact the full raw body, then slice. Better, drop the preview entirely, because the worker already has the exchange view.
- **Related round-1 IDs:** C-3 (listed in the C-3 recheck as item 4).
- **Verification:** 3/3 upheld as high. Spot-checked at `98881b4` (verify-rpc.ts:1660).

#### R2-H-5 — Subdomain auto-admission still widens to multi-tenant SaaS vendor apexes and overrides scope-review deselection (residual of C-2)

- **Category:** security (egress outside scope)
- **Location:**
  - [subdomain-discovery.ts#L204](../src/server/subdomain-discovery.ts#L204)
  - [subdomain-discovery.ts#L940](../src/server/subdomain-discovery.ts#L940)
  - [subdomain-discovery.ts#L952](../src/server/subdomain-discovery.ts#L952)
  - [exec-recon-planner.ts#L1857](../src/server/exec-recon-planner.ts#L1857)
  - [store-runs.ts#L2125](../src/server/store-runs.ts#L2125)
- **What's wrong:** two independent issues.
  - **(a) SaaS apex.** `apexDomainOfHost` blocks only the PSL and a 43-entry PaaS list. Tenants on help-desk, issue-tracker, SSO and CMS vendors collapse to the vendor apex, and siblings get auto-admitted. The file's own `THIRD_PARTY_SAAS_CNAME_SUFFIXES` is never applied to the seed.
  - **(b) Deselection override.** `setScope` stores no declined set. Phase-0 then rediscovers hosts the operator unchecked and appends them to `run.approved` through `updateRun`, with no `scopeRevision` bump and no approval event. This also bypasses the 30-host auto-select cap.
- **Evidence:** in memory, tenants on several unlisted SaaS vendors returned the vendor apex. The deselection path was traced end to end to the grant rebuild.
- **Attack path / root cause / fix:** see the C-2 subsection below.
- **Impact:** active probing of other tenants' and vendors' hosts, and of first-party hosts the operator excluded.
- **Related round-1 IDs:** C-2.
- **Verification:** two candidates merged, each 3/3 upheld as high.

#### R2-H-6 — Composite terminal `proofReceipt` early return: class laundering, and worker-declared receipt fields reach `verifyReceipt` unsanitized

- **Category:** correctness (forged confirmation)
- **Location:**
  - [composite-receipt.ts#L635](../src/server/composite-receipt.ts#L635) and [#L654](../src/server/composite-receipt.ts#L654)
  - Sanitizer it skips: [terminal-oracle-registry.ts#L142](../src/server/terminal-oracle-registry.ts#L142)
  - Entry points: [verify-rpc.ts#L2136](../src/server/verify-rpc.ts#L2136) and [agent-script-proof.ts#L349](../src/server/agent-script-proof.ts#L349)
  - Class persisted at [agent-script-proof.ts#L480](../src/server/agent-script-proof.ts#L480) and [exec-verify.ts#L2108](../src/server/exec-verify.ts#L2108)
- **What's wrong:** when `terminalImpact.proofReceipt` is present, the gate runs `verifyReceipt` on the worker's raw receipt and returns ok after only a stub check. As a result:
  - **(a)** `proofReceipt.vulnClass` is never compared with `terminalVulnClass`, and the receipt's exchanges are never bound to the terminal hop. A confirmed low-impact receipt is persisted under any strict class the worker names. Denied-control, own-tenant and v8-family gates are all skipped.
  - **(b)** `sanitizeSingleHopReceiptForHostCustody` never runs. Worker `oracleEvents` (for example mass_assignment, which waives the protected-field rule), `requiredRole` (which sets `roleDifferential` → bfla `functionLevelEscalation`) and `resourceTenant` all reach the impact assessors.
- **Evidence:**
  - A one-hop composite over a genuine pre-GET, a PATCH of a non-protected field, and a readback was rejected without `oracleEvents`. With `["mass_assignment"]` it returned confirmed=true.
  - Class laundering was traced to persistence.
  - Clarification: declared `unitDebit` is min-bounded, and `resourceTenant` now needs host corroboration. The live leverage is `requiredRole` and the declared events.
- **Attack path:** a worker returns `compositeReceipt`, or calls `composite.verify`, with a 1-hop chain and an embedded receipt. Both fresh runs agree and the result is persisted under the chosen class.
- **Impact:** a real low-impact proof is relabelled as bola, rce and similar. Declared events and roles flip impact verdicts.
- **Recommendation:**
  - Run the registry sanitizer on every embedded receipt, both terminal and per hop.
  - Require `normalize(proofReceipt.vulnClass)` to equal or be allowed for `terminalVulnClass`.
  - Require the receipt's exchange, OOB and trace IDs to belong to the terminal hop.
  - Then apply the class contract (see H-12).
- **Related round-1 IDs:** H-12, H-13, C-5, C-6.
- **Verification:** four candidates merged (variant-of-C-5 ×2, variant-of-H-12, variant-of-H-13). Each was upheld as high (one verifier rated medium).

#### R2-H-7 — Composite heuristic terminal gate: unbound OOB/browser evidence, async_job create-then-read edges, and unbound 403/404 controls satisfy every class (residual of H-12)

- **Category:** correctness (forged confirmation)
- **Location:**
  - [composite-receipt.ts#L652](../src/server/composite-receipt.ts#L652) (`hasOob` / `hasBrowser`)
  - [composite-receipt.ts#L618](../src/server/composite-receipt.ts#L618) (the same escape in the v8 dispatch)
  - [composite-receipt.ts#L455](../src/server/composite-receipt.ts#L455) (async_job fallback)
  - [composite-receipt.ts#L666](../src/server/composite-receipt.ts#L666) (`terminalCtrl`)
  - [composite-receipt.ts#L680](../src/server/composite-receipt.ts#L680) (`needsStrict`)
- **What's wrong:**
  - **(a)** A delivered OOB event or a browser trace with any sinks in the terminal hop skips the denied-control and endpoint checks. This applies to strict classes (bola, broken_access_control) and to the v8 families, even with zero exchanges in the hop.
  - **(b)** An `async_job` edge is verified by two 2xx records that mention the same ID, which is an ordinary create-then-read. That turns `needsStrict` off for every non-strict class.
  - **(c)** A 403 control only has to be in the same route family, because numeric segments collapse. There is no entity, actor or method binding.
  - **(d)** The 404 entity check falls back to `hop.entityId`, which the worker writes.
- **Evidence:** in-memory `verifyCompositeReceipt` with signed entries returned confirmed=true in every case below:
  - rce, bola and broken_access_control from one delivered OOB event and no control;
  - sqli and idor from a `dom_xss` sink trace;
  - ssrf, rce, sqli, business_logic and path_traversal from a create-then-read with an `async_job` edge;
  - bola from a 200 on the attacker's own record plus a 403 on another ID.
- **Attack path / root cause / fix:** see the H-12 subsection below.
- **Impact:** false confirmed findings across strict and non-strict classes, built from genuine transcripts.
- **Related round-1 IDs:** H-12, H-6, H-11.
- **Verification:** four candidates merged (variant-of-H-6 and variant-of-H-12 ×3). All were upheld as high.

#### R2-H-8 — Capability-injected credentials are recorded under the base persona's handle and role, so a sealed privileged session confirms vertical or cross-tenant escalation "as member"

- **Category:** correctness (evidence integrity)
- **Location:**
  - [verify-rpc.ts#L947](../src/server/verify-rpc.ts#L947) (ephemeral persona keeps `baseRoleLabel`)
  - [verify-rpc.ts#L974](../src/server/verify-rpc.ts#L974) (`nextMeta` keeps the base `personaHandle` and `actorRoleLabel`)
  - Consumers: [verify-claims.ts#L936](../src/server/verify-claims.ts#L936), [host-fact-log.ts#L802](../src/server/host-fact-log.ts#L802), [oracle-invariants.ts#L1117](../src/server/oracle-invariants.ts#L1117), [composite-receipt.ts#L132](../src/server/composite-receipt.ts#L132)
- **What's wrong:**
  - A request with `persona: member` plus `capability` (or an inline `cap:` handle in Authorization or Cookie) is sent with the sealed credential.
  - The signed transcript still names the member persona and role.
  - Only the auth_bypass helper looks at `consumedCapabilities`. The bfla and bola authorization, boundary and composite role checks use the label.
- **Evidence:** traced end to end by 3 verifiers. `prove.persistedMutation` forwards per-arm `capability` (verify-prove-handlers.ts:123), and `requiredRole` comes from the worker.
- **Attack path:**
  1. Seal a rolling session token from an admin exchange.
  2. Mutate an admin function route as member with that capability and `requiredRole: admin`.
  3. The kernel confirms CWE-285 against correct RBAC.
- **Impact:** false bfla or bola at scale. The signed evidence misstates which credential was sent.
- **Recommendation:**
  - When a capability supplies Authorization or Cookie, record the actor as the capability, with the role and tenant of the seal's source exchange.
  - Alternatively, reject base-persona plus auth-capability requests.
  - In the authorization and composite oracles, treat probes that consumed capabilities the control lacked like the H-14 rule.
- **Related round-1 IDs:** H-14, H-11, H-13.
- **Verification:** 3/3 upheld as high.

#### R2-H-9 — Replay-spec `expectedImpactEvents` (and `csrfBind`) written by the model are re-admitted as `trustedOracleEvents` under strict host derivation

- **Category:** correctness (forged confirmation)
- **Location:**
  - [floor-recipe-engine.ts#L3647](../src/server/floor-recipe-engine.ts#L3647) and [#L3722](../src/server/floor-recipe-engine.ts#L3722)
  - [terminal-oracle-registry.ts#L172](../src/server/terminal-oracle-registry.ts#L172)
  - [replay-verifier.ts#L526](../src/server/replay-verifier.ts#L526) and [#L558](../src/server/replay-verifier.ts#L558)
  - [oracle-invariants.ts#L1550](../src/server/oracle-invariants.ts#L1550) and [#L2608](../src/server/oracle-invariants.ts#L2608)
- **What's wrong:**
  - `buildReplayReceipt` copies the spec's declared events into `receipt.oracleEvents`. `receiptCheckForResult` then passes them back as trusted after strict mode strips them.
  - A declared `stored_xss_rendered` event alone satisfies the markup assessor.
  - A declared `mass_assignment` event waives the protected-field rule.
  - A declared event also disables the business_logic attribution guard.
- **Evidence:** a self-profile edit plus a declared event confirms mass assignment in both the replay gate and the strict receipt. The CSRF half is weak, because the host still derives auth and SameSite.
- **Attack path:** `propose_chain_finding` with a declared event. Reachable where non-static replay specs are verified, which means legacy or `allowLegacyReplaySpec` paths, plus deterministic specs.
- **Impact:** confirmed XSS, mass-assignment or business-logic findings with no impact evidence.
- **Recommendation:** never pass spec-declared events as trusted. Derive trusted events only from host observations, and treat declared events as requirements only.
- **Related round-1 IDs:** H-13, C-6 (fix step 7).
- **Verification:** 3/3 upheld as high.

#### R2-H-10 — Injection-fingerprint oracle residuals: fingerprints from working defenses, zero-control confirmation, opaque non-JSON request bodies, and no family binding (residual of H-16)

- **Category:** correctness (forged confirmation)
- **Location:**
  - [oracle-invariants.ts#L2258](../src/server/oracle-invariants.ts#L2258) (fingerprint table, especially the nosqli, xxe and traversal rows)
  - [oracle-invariants.ts#L2483](../src/server/oracle-invariants.ts#L2483)
  - [oracle-invariants.ts#L2295](../src/server/oracle-invariants.ts#L2295)
  - [host-fact-log.ts#L537](../src/server/host-fact-log.ts#L537) and [verify-claims.ts#L955](../src/server/verify-claims.ts#L955)
  - [proof-receipt.ts#L725](../src/server/proof-receipt.ts#L725) (no `injection.family` passed)
- **What's wrong:**
  - **(a) Defense strings count as evidence.** The table includes strings that a hardened or validating server emits when it refuses input: DOCTYPE and external-entity refusals, a "path traversal" block message, ENOENT, ObjectId/number cast failures, and duplicate-key errors.
  - **(b) Zero controls.** With no controls, the "absent from controls" check passes vacuously.
  - **(c) Non-JSON bodies.** Form, XML and multipart bodies become a single string token, so a reflected single field is never stripped.
  - **(d) No family binding.** The kernel passes no family, so any fingerprint confirms any injection class.
- **Evidence:**
  - Each of the four defensive bodies returned satisfied=true against a benign 200 control.
  - A probe-only step with a static page phrase returned satisfied=true.
  - A form-encoded reflected field returned satisfied=true, while the same value as JSON was rejected.
- **Attack path / root cause / fix:** see the H-16 subsection below.
- **Impact:** false confirmed injection findings on hardened apps and on any page that reflects form input.
- **Related round-1 IDs:** H-16.
- **Verification:** three candidates merged, each upheld as high (one verifier rated zero-control as medium).

#### R2-H-11 — OOB receipt carrier can be any exchange that only echoes the token in its response, chosen by the model, and the "callback after injection" check uses the WAIT time (residual of H-6)

- **Category:** correctness (misattribution)
- **Location:**
  - [proof-receipt.ts#L2211](../src/server/proof-receipt.ts#L2211) and [#L2218](../src/server/proof-receipt.ts#L2218)
  - [proof-receipt.ts#L385](../src/server/proof-receipt.ts#L385) and [#L1651](../src/server/proof-receipt.ts#L1651)
  - [verify-rpc.ts#L1494](../src/server/verify-rpc.ts#L1494) and [#L2027](../src/server/verify-rpc.ts#L2027)
  - Drain path: [exec-verify.ts#L1726](../src/server/exec-verify.ts#L1726)
- **What's wrong:**
  - `carriesToken`, `stepCarries` and `carrierText` all include the response body.
  - An explicit `injectionExchangeId` becomes the only carrier and sets the receipt target.
  - The WAIT artifact never records the relay's callback time, so the ordering check compares against the wait end and almost never fails.
- **Evidence:** with POST A carrying the token in its request and GET B only echoing it, citing B gave verifyReceipt and the strict registry confirmed=true with target GET B.
- **Attack path / root cause / fix:** see the H-6 subsection below.
- **Impact:** a genuine callback is reported as SSRF on an endpoint that never fetched anything.
- **Related round-1 IDs:** H-6, H-20.
- **Verification:** 2/3 upheld as high, 1 as medium.

#### R2-H-12 — The cross-tenant publicness guard is satisfied by any credential fingerprint, including a rotating cookie

- **Category:** correctness (forged confirmation)
- **Location:** [oracle-invariants.ts#L1274](../src/server/oracle-invariants.ts#L1274)
- **What's wrong:**
  - In the cross-tenant branch, a read backed only by a parent-collection listing should be dismissed as publicness unless an owner-scoped principal is exposed.
  - Instead, `hasSecretMatch = probe.secretMatches.length > 0` passes on any fingerprint. It does not compare against controls or filter by kind or field path.
  - The broker fingerprints `set-cookie`, so XSRF and session rotation is enough.
- **Evidence:**
  - Alice (tenant t1) gets 200 on a listing, then Bob (tenant t2) gets 200 on a public item. That is dismissed as publicness.
  - Add one real fingerprint from a rotating XSRF cookie, and the same steps confirm a cross-tenant read.
- **Attack path:** the model cites only the foreign listing as the control. That skips the publicness owner and anonymous checks.
- **Impact:** false cross-tenant BOLA on public catalog objects for frameworks that rotate cookies.
- **Recommendation:** filter fingerprints by kind and field path (no `headers.*`, no CSRF/session names) and require them to match a victim-held value, as in H-17 fix step 4.
- **Related round-1 IDs:** H-17 (a different branch).
- **Verification:** 2/3 upheld as high, 1 as medium.

#### R2-H-13 — The receipt `redirect` rule confirms open_redirect on any off-origin Location, with no control binding and no attacker-controlled destination

- **Category:** correctness
- **Location:**
  - [proof-receipt.ts#L613](../src/server/proof-receipt.ts#L613)
  - [floor-recipes.ts#L1333](../src/server/floor-recipes.ts#L1333)
  - [floor-recipe-engine.ts#L3512](../src/server/floor-recipe-engine.ts#L3512)
- **What's wrong:**
  - The rule confirms when the cited probe has an off-origin Location that no other cited exchange shares byte for byte.
  - A probe cited alone confirms.
  - Nothing requires the control to share the probe's method, route or actor, or requires the destination to derive from the controlled parameter (`proofPatterns` is optional).
  - SSO and IdP redirects carry fresh state, so even a correct control "differs".
- **Evidence:** a single `/login` 302 to an external IdP gave confirmed=true (rule redirect).
- **Attack path:** an http_chain spec titled or labelled open_redirect, hitting any SSO or logout endpoint.
  - Reachability caveat: one verifier showed that model-authored http_chain specs are redirected to kovo_verify when that tool is active. The deterministic `synthRedirect` producer binds a canary. The live path is legacy and `allowLegacyReplaySpec` replay plus host-persisted recipes, and the kernel is the last gate for them.
- **Impact:** false CWE-601 on any app with an external auth redirect.
- **Recommendation:**
  - Require a same method, route and actor control.
  - Require a host-minted canary host in the probe's controlled parameter.
  - Require a 3xx status.
  - Compare hosts rather than whole Location strings.
- **Related round-1 IDs:** H-15 (fix step 8).
- **Verification:** 2/3 upheld as high, 1 as medium (reachability).

#### R2-H-14 — The receipt class is chosen by keywords in model labels, ahead of the CWE, and SSRF/XXE replay receipts build their own delivered OOB event (residual of H-18)

- **Category:** correctness
- **Location:**
  - [floor-recipe-engine.ts#L3508](../src/server/floor-recipe-engine.ts#L3508) (`receiptVulnClassFor`)
  - [floor-recipe-engine.ts#L3600](../src/server/floor-recipe-engine.ts#L3600) (event build)
  - [oracle-invariants.ts#L546](../src/server/oracle-invariants.ts#L546)
  - [exec-verify.ts#L270](../src/server/exec-verify.ts#L270) (`bindConfirmedFindingIdentity` prefers `spec.cwe`)
- **What's wrong:**
  - SSRF, XXE, redirect and webhook keywords in the title or impact text select the oracle before the CWE is considered. Strict mode fails closed on unmodelled CWEs, so this lets a spec swap in a receiptable class.
  - The SSRF and XXE branch builds `delivered:true` from any canary-shaped request text without checking `canary.triggered`.
  - The declared CWE, not the proven class, is what gets persisted.
- **Evidence:**
  - A CWE-22 spec failed closed with a neutral title, but confirmed (rule oob) after the title was changed to SSRF wording and the request carried a canary-shaped token.
  - In memory, CWE-89 specs with SSRF or redirect wording mapped to ssrf or open_redirect.
- **Attack path / root cause / fix:** see the H-18 subsection below. Also check `canary.triggered` for ssrf and xxe in `buildReplayReceipt`.
- **Impact:** strict receipt veto bypassed, and confirmed findings mislabelled.
- **Related round-1 IDs:** H-18, H-6.
- **Verification:** 2/3 upheld as high, 1 as medium.

#### R2-H-15 — Retest reports `fixed` when probe-side arms fail or a recipe has no control arm (residual of H-19)

- **Category:** correctness (false remediation)
- **Location:**
  - [floor-recipe-engine.ts#L1158](../src/server/floor-recipe-engine.ts#L1158) and [#L1253](../src/server/floor-recipe-engine.ts#L1253)
  - [floor-recipes.ts#L1211](../src/server/floor-recipes.ts#L1211) (race_burst)
  - [floor-recipes.ts#L1017](../src/server/floor-recipes.ts#L1017), [#L1047](../src/server/floor-recipes.ts#L1047) and [#L834](../src/server/floor-recipes.ts#L834)
- **What's wrong:**
  - `retestControlFailureReason` skips every step whose arm is not `control`.
  - race_burst has no control arm, so a burst that is throttled to all 429 or all 5xx gives `fixed`.
  - The following also give `fixed`: a boolean-mode probe 5xx, a 429 on the status tautology arm, and an access_boundary probe that returns 5xx, 429 or 401.
  - Short bursts never trip the broker circuit breaker.
- **Evidence:** scratch harness: "RACE all 429 => fixed", "BOOL probe 5xx => fixed", "STATUS tautology 429 => fixed".
- **Attack path / root cause / fix:** see the H-19 subsection below.
- **Impact:** a "Verified fixed" result for a vulnerability that still exists.
- **Related round-1 IDs:** H-19.
- **Verification:** 2/3 upheld as high, 1 as medium.

#### R2-H-16 — The persisted agent proof script is heuristically redacted and then re-executed on retest and reverify, which turns live findings into `fixed` or `dismissed`

- **Category:** correctness (false remediation)
- **Location:**
  - [exec-verify.ts#L2127](../src/server/exec-verify.ts#L2127) (sha over the raw script, redacted copy stored)
  - [agent-script-proof.ts#L671](../src/server/agent-script-proof.ts#L671), [#L728](../src/server/agent-script-proof.ts#L728) and [#L762](../src/server/agent-script-proof.ts#L762)
  - [exec-verify.ts#L2601](../src/server/exec-verify.ts#L2601)
  - [replay-verifier.ts#L959](../src/server/replay-verifier.ts#L959) (stored sha compared only with itself)
- **What's wrong:**
  - The script is stored as `scrubDerivedSecrets(redact(script))`. The full keyword heuristics replace JWT literals, quoted password/token values and Bearer values with a marker, and the syntax stays valid.
  - Retest and reverify run `envelope.script`, and nothing compares sha256 of that script with `scriptSha256`.
  - The altered script sends the marker on the wire. The resulting `oracle_failed` maps to `dismissed` and then to `fixed`, and reverify demotes the confirmed row.
  - Variants that break syntax degrade to inconclusive.
- **Evidence:** in-memory `redact()` on sample scripts. Both re-execution paths were traced at `98881b4`.
- **Attack path:** none needed. This happens with ordinary proofs that contain forged-token or login literals.
- **Impact:**
  - Still-exploitable findings are reported as remediated, and Gate 6 passes.
  - Confirmed findings get dismissed during the run.
- **Recommendation:**
  - Store the executable script in host-only custody, with exact-value redaction at most.
  - Assert `sha256(script) === scriptSha256` before running it. On mismatch, return inconclusive.
  - Map `oracle_failed` to `fixed` only under the H-19 health rule.
- **Related round-1 IDs:** H-25, H-19, H-9 (fix step 6).
- **Verification:** 3/3 upheld as high.

#### R2-H-17 — A no-op spawn on an aborted or draining RunActor orphans claimed workers: kill-switch trip-then-reset leaves runs zombie, and Resume during the drain window wedges verification

- **Category:** reliability (run wedge)
- **Location:**
  - [run-context.ts#L100](../src/server/run-context.ts#L100) (one-shot kill-switch registration)
  - [kill-switch.ts#L420](../src/server/kill-switch.ts#L420)
  - [run-actor.ts#L232](../src/server/run-actor.ts#L232) (spawn returns a no-op)
  - [run-actor.ts#L422](../src/server/run-actor.ts#L422) (`isDisposed` ignores aborted or draining)
  - [execution.ts#L755](../src/server/execution.ts#L755) (`ensureRunActor` reuses the actor)
  - [execution.ts#L4029](../src/server/execution.ts#L4029) and [#L3315](../src/server/execution.ts#L3315) (`active.set` before spawn)
  - [execution.ts#L1611](../src/server/execution.ts#L1611) (revoke never deletes from `active`)
- **What's wrong:**
  - A trip aborts the RunContext controller and deletes its registration. `reset()` never re-arms it, and Execution has no `onChange` subscriber.
  - Separately, Stop followed by Resume within the drain window (about 5 s plus lab teardown) leaves the draining actor in `this.actors`.
  - In both cases `claimAndDispatchWorker` marks the worker `running`, sets `active`, and calls spawn, which returns without running `fn`. The `finally` block that cleans `active` never executes.
  - Pause and resume do not recover. Only a restart does.
- **Evidence:**
  - In memory: trip, then reset gave `ctx.signal.aborted` true, and spawn did not run `fn` or its `finally`.
  - The drain-window path was traced through `driveVerification`.
- **Attack path:** routine operator actions (trip then reset, or Stop then Resume).
- **Impact:**
  - Runs never progress or finalize.
  - Concurrency slots leak.
  - Lease rows stay `running`.
- **Recommendation:**
  - Make `RunActor.isDisposed` true when the actor is aborted or draining, and recreate the actor.
  - Return `started:false` from spawn, and roll back claims and `active` on a no-op.
  - On kill-switch trip, pause runs durably and dispose them.
- **Related round-1 IDs:** H-1 (residual), H-2, H-27.
- **Verification:** two candidates merged. 2/3 upheld as high, 1 as medium on each.

#### R2-H-18 — Approval waiters are bound to the wrong abort signal: a session wall-clock rotation orphans a pending card, and approving it wedges investigation

- **Category:** reliability (run wedge)
- **Location:**
  - [run-actor.ts#L1732](../src/server/run-actor.ts#L1732) (`onAbort` does no cleanup)
  - [run-actor.ts#L1762](../src/server/run-actor.ts#L1762) (resume and `active.set`)
  - [run-actor.ts#L1839](../src/server/run-actor.ts#L1839) (reconcile ignores `approved`)
  - [execution.ts#L3482](../src/server/execution.ts#L3482) (session signal)
  - [exec-verify.ts#L2845](../src/server/exec-verify.ts#L2845) (inline rce_proof uses the job signal)
  - [exec-worker-runner.ts#L563](../src/server/exec-worker-runner.ts#L563)
- **What's wrong:**
  - **(a)** The investigation HTTP escalation waits on `sessionController.signal`. The 120–300 s wall clock aborts it, the card stays pending and the worker stays parked. Approving the card then leaves the step `running` forever.
  - **(b)** The inline rce_proof waiter uses `job.controller.signal`, so it outlives its session. On Approve it re-adds the job to `active` permanently and runs the replay for a dead session.
- **Evidence:** both chains traced by 3 verifiers. Approval cards expire after 15 minutes, so ordinary human latency triggers this.
- **Attack path / root cause / fix:** see the H-28 subsection below.
- **Impact:** investigation never reaches verification, and the run needs a manual Stop.
- **Related round-1 IDs:** H-28.
- **Verification:** two candidates merged, both 3/3 upheld as high.

#### R2-H-19 — A compressed HTTP/1.1 response that closes mid-body never settles, permanently leaking the per-origin in-flight slot and burst lock across runs

- **Category:** reliability (cross-run wedge)
- **Location:**
  - [egress-gateway.ts#L836](../src/server/egress-gateway.ts#L836)
  - [transport.ts#L1100](../src/server/transport.ts#L1100)
  - [broker.ts#L3256](../src/server/broker.ts#L3256)
  - [broker.ts#L3472](../src/server/broker.ts#L3472) and [#L3568](../src/server/broker.ts#L3568)
  - [broker.ts#L2157](../src/server/broker.ts#L2157)
- **What's wrong:**
  - In the compressed branch, `res.pipe(zlib)` has listeners only on the zlib stream. A clean FIN mid-body destroys `res` without emitting an error, and `pipe` does not propagate it, so the promise never settles.
  - Deadline abort is a no-op on an already-destroyed request, and `executePreparedHttp` has no `withAbort` wrapper.
  - The `acquireSlot` release and the `batchActive` reset sit in `finally` blocks that are never reached.
  - One broker serves every run. The external-origin cap is 2.
- **Evidence:** a reproduction over an in-memory Duplex: gzip headers, partial body, EOF stayed pending even after abort. The same flow without gzip rejected with 'aborted'.
- **Attack path:** any in-scope target or proxy that sends a compressed response and closes early (crash, upstream timeout, or a hostile target). The default transport advertises gzip.
- **Impact:**
  - Requests to that origin are denied for every run.
  - Race and batch probes are refused for the life of the process.
  - The awaiting step hangs.
- **Recommendation:**
  - Use `stream.pipeline` (or add `res` close and aborted handlers).
  - Wrap every transport call in `withAbort(deadline)`.
  - Make `batchActive` an owner token with a TTL.
- **Related round-1 IDs:** none. Adjacent to H-26 and H-27.
- **Verification:** 3/3 upheld as high.

#### R2-H-20 — The pooled ScopedBrowser closes every other run's live contexts on each visit, so concurrent runs destroy each other's SPA crawls (residual of H-24)

- **Category:** reliability (cross-run bleed, silent false negatives)
- **Location:**
  - [scoped-browser.ts#L1866](../src/server/scoped-browser.ts#L1866) (cross-run prune)
  - [scoped-browser.ts#L1655](../src/server/scoped-browser.ts#L1655) (LRU ignores `active`)
  - [phase0-recon.ts#L6076](../src/server/phase0-recon.ts#L6076) (errors swallowed)
- **What's wrong:**
  - `visitPages` deletes and closes every pooled entry whose runId differs from the current request. It does not check `entry.active`.
  - A crawl failure is a bare `continue`, so nothing records that the page was skipped.
  - Note: this eviction existed at round 1 (commit `0d7364a`). It was cited there only as background.
- **Evidence:** in-memory fake browser: run-2's visit closed run-1's page mid-visit.
- **Attack path / root cause / fix:** see the H-24 subsection below.
- **Impact:** both runs silently lose browser coverage (XHR endpoints, BOLA seed IDs, DOM surfaces).
- **Related round-1 IDs:** H-24, H-22.
- **Verification:** 2/3 upheld as high, 1 as medium.

#### R2-H-21 — DooD warm-pool `/repos` staging reuses one fixed scratch directory for the backend's lifetime: concurrent runs merge each other's source, and rotation deletes a live mount

- **Category:** data-integrity (cross-run bleed)
- **Location:**
  - [worker-backend.ts#L1832](../src/server/worker-backend.ts#L1832) (`pool-${instanceId}`)
  - [worker-backend.ts#L1186](../src/server/worker-backend.ts#L1186) (merge, then remove on EEXIST)
  - [worker-backend.ts#L604](../src/server/worker-backend.ts#L604) and [#L799](../src/server/worker-backend.ts#L799)
  - [exec-worker-runner.ts#L597](../src/server/exec-worker-runner.ts#L597)
- **What's wrong:**
  - Every pool install stages into the same path.
  - Retire is deferred while sessions are active.
  - A different project's tree then merges into the same directory, and the old lease's cleanup later `rm -rf`s it.
  - The same project hits EEXIST, and the error handler removes the directory that in-flight sessions have mounted.
- **Evidence:** the real `prepareReposMount` returned the same `mountDir` with both repos inside. `A.cleanup()` removed B's directory. A second same-project prepare threw and removed the live directory.
- **Attack path:** none. It is triggered by concurrent runs in the default compose deployment, or by a persona credential-epoch rotation.
- **Impact:** one project's source reaches another run's model and SAST, findings are attributed to the wrong project, and mid-run deletion causes code-audit false negatives.
- **Recommendation:**
  - Use a unique staging ID per prepare.
  - Refuse a non-empty target.
  - Never remove a directory this call did not create.
- **Related round-1 IDs:** H-31 (different root cause).
- **Verification:** 3/3 upheld as high. Spot-checked at `98881b4` (worker-backend.ts:1832).

#### R2-H-22 — In DooD mode the verify-RPC mount always fails, so every kovo_verify session errors in the shipped compose deployment

- **Category:** reliability (systematic false negatives)
- **Location:**
  - [worker-backend.ts#L1357](../src/server/worker-backend.ts#L1357)
  - [worker-backend.ts#L636](../src/server/worker-backend.ts#L636)
  - [verify-rpc.ts#L391](../src/server/verify-rpc.ts#L391)
  - [agent-script-proof.ts#L306](../src/server/agent-script-proof.ts#L306)
  - [docker-compose.yml](../docker-compose.yml)
- **What's wrong:**
  - The VerifyRpcServer `hostDir` is created by mkdtemp under `/dev/shm`. `resolveDoodMountArg` requires a per-session subdirectory of the scratch directory, so it throws.
  - RPC sessions bypass the warm pool, so the cold path is always taken.
  - Even without the throw, a container-local `/dev/shm` is invisible to the sibling daemon.
- **Evidence:** `resolveDoodMountArg` on a `/dev/shm` directory with the volume env set throws the per-session-subdirectory error. `docker-compose.yml` sets `KOVO_CONTAINER_SCRATCH_DIR` and `KOVO_WORKER_SCRATCH_VOLUME` by default.
- **Impact:** the Layer-3 transcript proof path cannot confirm anything in the containerized deployment. It fails closed and silently.
- **Recommendation:**
  - In DooD mode create the RPC `hostDir` with `prepareSessionScratchDir`.
  - Add a DooD-env unit test for `workerContainerCreateArgs` with `rpcMountDir`.
- **Related round-1 IDs:** M-8 (different root cause).
- **Verification:** 3/3 upheld as high.

#### R2-H-23 — `jsHarvest` still runs on the host thread: an `@swc/core` native stack overflow segfaults the process, and three regexes are quadratic (residual of H-35)

- **Category:** reliability / host availability
- **Location:**
  - [worker/analyzers.ts#L109](../worker/analyzers.ts#L109) (`parseSync`, no depth guard)
  - [worker/analyzers.ts#L718](../worker/analyzers.ts#L718) (GraphQL fallback)
  - [worker/analyzers.ts#L724](../worker/analyzers.ts#L724) (`__NEXT_DATA__`)
  - [worker/analyzers.ts#L2469](../worker/analyzers.ts#L2469) (jwt-literal in `secretScan`)
  - Host call sites: [phase0-recon.ts#L4634](../src/server/phase0-recon.ts#L4634) and [#L4767](../src/server/phase0-recon.ts#L4767)
  - Sibling: [persona-auth.ts#L1016](../src/server/persona-auth.ts#L1016) (Supabase jwt regex over 250 KB HTML plus 4×512 KB bundles)
- **What's wrong:**
  - About 10 KB of nested brackets crashes the process with SIGSEGV (exit 139). Neither try/catch nor `worker_threads` can contain a native crash.
  - Repeated-token bodies with no terminator are quadratic in all three regexes.
  - Nothing moves the work off the main thread.
- **Evidence:** measured exit 139 at nesting depth 5000. jwt-literal scanning took 3.3, 13 and 52 s at 100, 200 and 400 KB. The persona-auth regex took 40 s at 250 KB.
- **Deployment caveat:** `@swc/core` resolves only from `worker/node_modules`, which exists after `npm run worker:install` on source deployments. The shipped Docker image falls back to acorn or regex. The quadratic regexes affect every deployment.
- **Attack path / root cause / fix:** see the H-35 subsection below.
- **Impact:**
  - On source deployments, the whole host dies (all runs, the API and the kill switch).
  - Elsewhere, the event loop stalls for minutes per bundle.
- **Related round-1 IDs:** H-35.
- **Verification:** five candidates merged.
  - SWC segfault: verifiers split critical / high / high.
  - The regex sites: each upheld as high.

#### R2-H-24 — Super-linear ProgramGraph regexes remain on repo content in the host thread: Rails cubic, Express/Fastify quadratic, collectCalls/guardIdentifiers quadratic (residual of H-33)

- **Category:** reliability / host availability
- **Location:**
  - [program-graph.ts#L1574](../src/server/program-graph.ts#L1574) (Rails namespace/scope)
  - [program-graph.ts#L937](../src/server/program-graph.ts#L937), [#L973](../src/server/program-graph.ts#L973), [#L1004](../src/server/program-graph.ts#L1004) and [#L1083](../src/server/program-graph.ts#L1083) (Express/Fastify)
  - [program-graph.ts#L506](../src/server/program-graph.ts#L506) and [#L770](../src/server/program-graph.ts#L770) (calls/guards)
  - Callers: [static-workspace-snapshot.ts#L442](../src/server/static-workspace-snapshot.ts#L442) via [execution.ts#L1977](../src/server/execution.ts#L1977)
- **What's wrong:**
  - The Rails regex has overlapping `[^d]+` and `\s+` quantifiers.
  - The identifier-led regexes have no left boundary. `$` is not a word character, so `\b` fires inside identifier runs that contain it.
  - The worker-pool `extract_program_graph` task exists, but nothing calls it.
- **Evidence:**
  - Rails line: 0.1 s, 0.9 s and 7.2 s at 0.8, 1.6 and 3.2 KB (cubic).
  - Express run: 1.2 s, 5 s and 19 s at 20, 40 and 80 KB.
  - `$`-interleaved run: 1.1 s and 4.3 s at 20 and 40 KB.
- **Attack path / root cause / fix:** see the H-33 subsection below.
- **Impact:** a crafted repo blocks the host for minutes to hours.
- **Related round-1 IDs:** H-33, M-53.
- **Verification:** three candidates merged, each 3/3 upheld as high.

#### R2-H-25 — ProgramGraph extractors amplify memory on the host: Gin self-group, unterminated Rails namespace nesting, and router-level middleware fan-out (residual of H-36)

- **Category:** reliability / host availability (OOM)
- **Location:**
  - [program-graph.ts#L1428](../src/server/program-graph.ts#L1428) (Gin)
  - [program-graph.ts#L1570](../src/server/program-graph.ts#L1570) (Rails walk)
  - [program-graph.ts#L999](../src/server/program-graph.ts#L999), [#L1026](../src/server/program-graph.ts#L1026), [#L1074](../src/server/program-graph.ts#L1074) and [#L1808](../src/server/program-graph.ts#L1808) (middleware)
- **What's wrong:** the H-36 caps (path length 2048, depth 12, cycle checks) exist only in `resolveMountedRoutes`.
  - Gin composes prefixes with no self or ancestor check, which allows `=` reassignment.
  - Rails `blockEnd` falls back to EOF, so N unclosed blocks nest N deep.
  - Router-level middleware is copied into every route twice.
  - The 5000-route cap applies only after every extraction has been retained.
- **Evidence:**
  - One 256 KB Go file: 3.5–4.5 s and about 0.5–0.7 GB of heap.
  - Ten such files: V8 OOM abort.
  - 30 Rails files (about 7.6 MB, under the 24 MB budget): fatal heap OOM.
  - One middleware file: 15–33 s and about 0.6–1 GB retained.
- **Attack path / root cause / fix:** see the H-36 subsection below.
- **Impact:** a hostile repo crashes the host process.
- **Related round-1 IDs:** H-36, H-33.
- **Verification:** three candidates merged, each upheld as high.

#### R2-H-26 — `credentialPatternEvidence` compiles proof patterns written by the worker or model with no ReDoS guard, over uncapped bodies

- **Category:** reliability / host availability
- **Location:**
  - [oracle-invariants.ts#L812](../src/server/oracle-invariants.ts#L812) and [#L843](../src/server/oracle-invariants.ts#L843)
  - [oracle-invariants.ts#L1313](../src/server/oracle-invariants.ts#L1313)
  - Inputs: [proof-receipt.ts#L53](../src/server/proof-receipt.ts#L53), [proof-receipt.ts#L732](../src/server/proof-receipt.ts#L732), [replay-verifier.ts#L578](../src/server/replay-verifier.ts#L578), [replay-spec.ts#L298](../src/replay-spec.ts#L298)
- **What's wrong:**
  - `isSpecificCredentialPattern` checks only length and four wildcard tokens. Nested quantifiers inside capturing groups pass.
  - `new RegExp(p).test(probeBody)` then runs with no haystack cap.
  - `safeRegexTest` is used on `proofMatches` but not on this sink, which receives the same patterns.
- **Evidence:** a 12-character pattern that passes the guard took 2.2 s on 36 characters and grows exponentially.
- **Attack path / root cause / fix:** see the H-32 subsection below.
- **Impact:** one receipt or spec freezes the whole host.
- **Related round-1 IDs:** H-32.
- **Verification:** 3/3 upheld as high.

#### R2-H-27 — The PEM private-key redaction regex is quadratic and runs on every broker response and on worker-controlled RPC error text

- **Category:** reliability / host availability
- **Location:**
  - [redact.ts#L15](../src/server/redact.ts#L15) and [#L102](../src/server/redact.ts#L102)
  - [broker.ts#L3376](../src/server/broker.ts#L3376)
  - [verify-rpc.ts#L486](../src/server/verify-rpc.ts#L486) and [#L511](../src/server/verify-rpc.ts#L511)
- **What's wrong:**
  - The lazy `[\s\S]*?` between the BEGIN and END markers scans to EOF for every BEGIN marker that has no END.
  - `redact()` and `scanSecrets()` run on full bodies.
  - The verify-RPC `dispatch` interpolates the worker's raw `op` value (up to 4 MiB) into an error message, then scrubs it before slicing.
- **Evidence:** 2.4 s at 512 KB, about 35 s at 2 MiB.
- **Attack path:** a worker script sends an RPC call with a large `op` built from repeated BEGIN markers, or a hostile target returns a 1–2 MiB body made of them.
- **Impact:** a host stall of tens of seconds to minutes per request, repeatable at will.
- **Recommendation:**
  - Pair markers with `indexOf` scans.
  - Cap `redact` and `scanSecrets` input.
  - Allow-list `op` before building the message.
  - Slice console text before redacting it.
- **Related round-1 IDs:** H-32, H-34, M-54 (different sites).
- **Verification:** 3/3 upheld as high.

#### R2-H-28 — `sanitizeBrowserResult` rebuilds every registered secret's encoding variants for each string leaf, and the registry is host-wide and fillable by the target

- **Category:** reliability / host availability
- **Location:**
  - [egress-sanitizer.ts#L266](../src/server/egress-sanitizer.ts#L266) and [#L86](../src/server/egress-sanitizer.ts#L86)
  - [redact.ts#L79](../src/server/redact.ts#L79)
  - [broker.ts#L1686](../src/server/broker.ts#L1686) and [#L1874](../src/server/broker.ts#L1874)
  - [scoped-browser.ts#L2007](../src/server/scoped-browser.ts#L2007)
  - [exec-worker-runner.ts#L786](../src/server/exec-worker-runner.ts#L786) and [#L878](../src/server/exec-worker-runner.ts#L878)
- **What's wrong:**
  - `redactExactValues` rebuilds and sorts the full needle list on every call. Cost is leaves × secrets × variants.
  - The broker registry holds up to 5000 entries, is never cleared per run, and registers every Set-Cookie value.
  - The pooled path spreads the registry twice.
  - The result is sanitized 2–3 times.
- **Evidence:** a typical result took 0.15 s with 100 secrets, 1.4 s with 1000, and 8–13 s with 5000, per call.
- **Attack path:** a target that rotates cookies fills the registry. After that, every browser visit in every run stalls the host.
- **Impact:** a host-wide stall that repeats and persists across runs.
- **Recommendation:**
  - Precompute the needle set (for example Aho-Corasick) per sanitizer and secret generation.
  - Scope the registry per run and dedupe it.
  - Sanitize once.
- **Related round-1 IDs:** H-8 (cost introduced by the H-8 fix).
- **Verification:** 3/3 upheld as high.

#### R2-H-29 — Verify-plane normalizer regexes are quadratic on target bodies and worker claim strings (`STRUCTURAL_TAG_NONCE_RE`, `COMPOUND_ID_RE`)

- **Category:** reliability / host availability
- **Location:**
  - [verify-support.ts#L29](../src/server/verify-support.ts#L29) (used by `structuralDiff`, [verify-claims.ts#L1472](../src/server/verify-claims.ts#L1472) and [floor-recipe-engine.ts#L2103](../src/server/floor-recipe-engine.ts#L2103))
  - [verify-claims.ts#L582](../src/server/verify-claims.ts#L582) (used by `causalFingerprints` via [verify-runner.ts#L480](../src/server/verify-runner.ts#L480))
- **What's wrong:**
  - Two unbounded `[^"']*` classes surround a keyword alternation, and the compound-ID branches have overlapping quantifiers.
  - Neither normalizer caps its input.
  - `structural_diff` renormalizes about 20–58 times per claim.
- **Evidence:**
  - The nonce regex: 0.5 s at 64 KB and 35 s at 512 KB. The TranscriptStore body cap is 512 KiB.
  - The compound-ID regex survives the hex pre-pass only on mixed alphanumeric runs: 7.8 s at 128 KB.
- **Attack path:** a hostile target returns a crafted HTML body on a compared endpoint. Alternatively, a worker claim's `text` field is up to 1 MiB of result.
- **Impact:** a host stall of minutes per claim.
- **Recommendation:**
  - Bound the character classes, or use a tag-scoped scanner.
  - Cap normalizer input (fingerprinting only needs a few KB).
  - Hash long observed values.
- **Related round-1 IDs:** H-34 (now FIXED; these are new sites).
- **Verification:** two candidates merged, each 3/3 upheld as high.

## Round-1 critical & high: status at 98881b4

The status for each item comes from the recheck. Every non-OPEN status was then challenged by an adversarial checker. A † marks a contested status: the checker argued a different status from the recheck, and the final status shown is the one the checker upheld. "Severity now" is the severity at this snapshot.

| ID | Title (short) | Status | Severity now | Current location | Evidence (one line) |
|---|---|---|---|---|---|
| C-1 | HTTP/2 verify op bypasses broker | PARTIAL | high | [verify-rpc.ts#L1212](../src/server/verify-rpc.ts#L1212), [egress-gateway.ts#L943](../src/server/egress-gateway.ts#L943) | Pseudo-header forgery fixed at 3 layers and admit() runs; no acquireSlot, circuit breaker, grant.audit or egress-proxy/UA config on h2 |
| C-2 | Subdomain auto-admit admits other tenants | PARTIAL | high | [subdomain-discovery.ts#L204](../src/server/subdomain-discovery.ts#L204), [#L940](../src/server/subdomain-discovery.ts#L940) | PSL and PaaS deny-list added; tenants of unlisted SaaS vendors still collapse to the vendor apex; deselection is overridden (R2-H-5) |
| C-3 | capability.seal byte oracle | OPEN † | critical | [verify-rpc.ts#L1567](../src/server/verify-rpc.ts#L1567) | Regex selector still runs over raw bytes; a lookahead-anchored capture recovered a 16-hex secret in 64 queries; rate limit is per instance |
| C-4 | V8 oracle hydration trusts model operands | OPEN † | critical | [v8-oracle-hydrate.ts#L650](../src/server/v8-oracle-hydrate.ts#L650), [composite-receipt.ts#L680](../src/server/composite-receipt.ts#L680) | Spread removed, but the model picks field paths and record roles; 9 honest-traffic cases confirmed (R2-C-8) |
| C-5 | Conserved-balance race receipt trusts worker roles | PARTIAL | critical | [proof-receipt.ts#L911](../src/server/proof-receipt.ts#L911), [verify-prove-handlers.ts#L731](../src/server/verify-prove-handlers.ts#L731) | Ordering, aliasing, overlap and unitDebit fixed; unrelated 404 serial control plus concurrent GETs still confirm over_credit |
| C-6 | business_logic passes on any write | OPEN † | critical | [oracle-invariants.ts#L1630](../src/server/oracle-invariants.ts#L1630) | Label path closed; an anonymous 401, resourceBound or a repeated POST still confirms (R2-C-7) |
| C-7 | Boolean differential confirms sqli on any parameter | PARTIAL | critical | [oracle-invariants.ts#L2006](../src/server/oracle-invariants.ts#L2006), [proof-receipt.ts#L1991](../src/server/proof-receipt.ts#L1991) | Arbitrary pairs rejected, but bare 1/0 and true/false pairs pass; no third arm, persona or origin; class hard-coded to sqli |
| C-8 | DOM-XSS oracle treats substring as execution | PARTIAL | medium | [floor-recipe-engine.ts#L741](../src/server/floor-recipe-engine.ts#L741), [proof-receipt.ts#L596](../src/server/proof-receipt.ts#L596) | Seam now requires window flag or title; kernel still confirms any sinks; title channel has gaps; HTTP markup sibling is R2-C-5 |
| H-1 | Kill-switch endpoint trips a different instance | FIXED | none | [kill-switch.ts#L649](../src/server/kill-switch.ts#L649) | globalThis Symbol.for singleton plus file backing; the follow-on wedge is R2-H-17 |
| H-2 | Kill-switch scope fails open | PARTIAL | high | [kill-switch.ts#L513](../src/server/kill-switch.ts#L513), [persona-auth.ts#L3402](../src/server/persona-auth.ts#L3402) | Tenant grants and persistence fixed; refresher egress not gated; a global reset clears tenant trips; last-writer-wins file |
| H-3 | GraphQL read-only exception on any path | PARTIAL | medium | [scope-policy.ts#L749](../src/server/scope-policy.ts#L749) | Endpoint must end in a graphql segment and use a strict validator; still inferred from the path, with no method-override handling and a substring content type |
| H-4 | Batch approval grants unevaluated targets | PARTIAL | high | [run-actor.ts#L1404](../src/server/run-actor.ts#L1404) | Per-target evaluation added; combined card built from target[0], UI hides items, group key ignores headers |
| H-5 | Model recipe/agentScript envelopes executed | PARTIAL | medium | [replay-verifier.ts#L203](../src/server/replay-verifier.ts#L203), [patch-workflow.ts#L1152](../src/server/patch-workflow.ts#L1152) | Model-writable rows are static-only and refused; trust fails open when undefined; Gate 6 omits envelopeTrust |
| H-6 | OOB evidence not bound | PARTIAL | high | [proof-receipt.ts#L2178](../src/server/proof-receipt.ts#L2178) | Session, run and attempt binding fixed; carrier may be a response echo and the timestamp is the WAIT time (R2-H-11) |
| H-7 | H2 returns Set-Cookie unredacted | FIXED | none | [verify-rpc.ts#L1185](../src/server/verify-rpc.ts#L1185) | sanitizeHttpHeaders on reply and transcript; regression test present |
| H-8 | Raw secrets live in browser pages | PARTIAL | high | [scoped-browser.ts#L924](../src/server/scoped-browser.ts#L924), [agent-session.ts#L2949](../src/server/agent-session.ts#L2949) | Verbatim exfil closed; raw cookies and storage still seeded; transformed copies (hex, reversed, offset base64) leak |
| H-9 | Sealed values rewrite kernel transcript | OPEN † | critical | [verify-rpc.ts#L1124](../src/server/verify-rpc.ts#L1124) | Response plane raw, request plane still vault-scrubbed, giving a forged non-reflected confirmation (R2-C-9) |
| H-10 | Re-seal forges value_binding | FIXED | low | [derived-custody.ts#L186](../src/server/derived-custody.ts#L186) | HANDLE_IMMUTABLE guard on every seal path |
| H-11 | I6 attacker provenance unenforced | OPEN † | critical | [composite-receipt.ts#L480](../src/server/composite-receipt.ts#L480) | Options never wired; setup or cleanup-arm admin 2xx used as terminal confirms even with all options set |
| H-12 | Composite class outside families confirms on one 2xx | OPEN † | critical | [composite-receipt.ts#L560](../src/server/composite-receipt.ts#L560), [#L680](../src/server/composite-receipt.ts#L680) | Bare 2xx rejected, but an async edge, OOB, browser trace, or an unbound 403/404 still confirms (R2-H-7) |
| H-13 | Oracles judge declared body, auth, SameSite and events | PARTIAL | high | [host-fact-log.ts#L217](../src/server/host-fact-log.ts#L217), [proof-receipt.ts#L1815](../src/server/proof-receipt.ts#L1815) | Declared fields stripped; bearer persona plus junk cookie cap gives auth=cookie and confirmed CSRF |
| H-14 | auth_bypass blind to jars, caps, privilege | OPEN † | high | [proof-receipt.ts#L1282](../src/server/proof-receipt.ts#L1282), [host-fact-log.ts#L790](../src/server/host-fact-log.ts#L790) | Jar and cookie checks read fields the product transcript never records; /me access confirmed as CWE-287 |
| H-15 | Timing differential across routes or personas | PARTIAL | high | [proof-receipt.ts#L519](../src/server/proof-receipt.ts#L519) | Same route and handle enforced; query, body, status, session and capability ignored; param optional |
| H-16 | Echoed fingerprint confirms injection | PARTIAL | high | [oracle-invariants.ts#L2295](../src/server/oracle-invariants.ts#L2295) | Query and JSON echo stripped; form, XML, path, cookie, case and escape variants still confirm (R2-H-10) |
| H-17 | access_boundary confirms on per-request tokens | OPEN | high | [oracle-invariants.ts#L1298](../src/server/oracle-invariants.ts#L1298), [floor-recipe-engine.ts#L583](../src/server/floor-recipe-engine.ts#L583) | Logic unchanged; rotating cookie fingerprint confirms BFLA; owner re-read is the "denied" control |
| H-18 | Confirmed identity unbound and editable | PARTIAL | high | [exec-verify.ts#L257](../src/server/exec-verify.ts#L257), [exec-worker-runner.ts#L1447](../src/server/exec-worker-runner.ts#L1447) | Identity bound on confirm; guard never called; title and reason editable; label not checked against receipt class |
| H-19 | Retest reports fixed when controls failed | OPEN † | high | [floor-recipe-engine.ts#L1158](../src/server/floor-recipe-engine.ts#L1158), [agent-script-proof.ts#L762](../src/server/agent-script-proof.ts#L762) | Control-arm denylist only; probe-arm 429, 5xx, 302 or 401, and receipt_rejected, give fixed (R2-H-15) |
| H-20 | prove.oob never confirms | PARTIAL | medium | [proof-receipt.ts#L2162](../src/server/proof-receipt.ts#L2162) | In-session path confirms; multi-origin injection rejected; late promotion still dead |
| H-21 | Broker-wide scope revision | FIXED | none | [broker.ts#L1527](../src/server/broker.ts#L1527) | Per-run map |
| H-22 | Persona pool keyed by bare handle | FIXED | low | [persona-auth.ts#L1086](../src/server/persona-auth.ts#L1086) | Run-scoped keys; unscoped fallback remains |
| H-23 | Frozen worker clones; reauth unwired | PARTIAL | high | [execution.ts#L1702](../src/server/execution.ts#L1702), [persona-auth.ts#L3439](../src/server/persona-auth.ts#L3439) | Live clones and reauth wired; retests on finished runs use expired sessions; no generation dedup |
| H-24 | Pooled browser context keeps first grant | PARTIAL | high | [scoped-browser.ts#L1939](../src/server/scoped-browser.ts#L1939) | Sequential case fixed; concurrent visits share page and slot; cross-run prune (R2-H-20) |
| H-25 | Stream sanitizer rewrites tool args | PARTIAL | medium | [agent-session.ts#L1648](../src/server/agent-session.ts#L1648), [#L1803](../src/server/agent-session.ts#L1803) | Stream path fixed; run_offline_script and derive_evidence still heuristically scrubbed |
| H-26 | firstEventTimeout is a hard deadline | FIXED | low | [provider.ts#L255](../src/server/provider.ts#L255) | Clearable timer disarmed on first chunk |
| H-27 | Run never finalizes after failed worker | PARTIAL | medium | [execution.ts#L3996](../src/server/execution.ts#L3996) | Finalizes now; no retry; report says complete; spawn-during-drain wedge (R2-H-17) |
| H-28 | Denied/expired approval wedges run | PARTIAL | high | [run-actor.ts#L1814](../src/server/run-actor.ts#L1814) | Deny and expiry reconciled; approve-after-rotation and restart wedges remain (R2-H-18) |
| H-29 | Planner hot loop | FIXED | low | [execution.ts#L3159](../src/server/execution.ts#L3159) | Backoff plus breaker |
| H-30 | Finalize crashes on deleted run | FIXED | low | [oob-drain.ts#L174](../src/server/oob-drain.ts#L174) | IIFE with guarded catch, drain cancel, active guard |
| H-31 | Cross-process warm-pool sweep | PARTIAL | medium | [worker-backend.ts#L1961](../src/server/worker-backend.ts#L1961) | owner_pid label; PID namespace blind under DooD; take() never inspects |
| H-32 | Worker/model regexes ReDoS | OPEN † | high | [verify-rpc.ts#L1566](../src/server/verify-rpc.ts#L1566), [safe-regex.ts#L17](../src/server/safe-regex.ts#L17) | Three sites unguarded; new guards accept exponential classes (R2-H-26) |
| H-33 | ProgramGraph regexes on host thread | OPEN † | high | [program-graph.ts#L1574](../src/server/program-graph.ts#L1574), [static-workspace-snapshot.ts#L442](../src/server/static-workspace-snapshot.ts#L442) | Four named regexes fixed; others cubic or quadratic; pool task unwired (R2-H-24) |
| H-34 | normalizeEphemeralNoise quadratic | FIXED | none | [probes/context.ts#L79](../src/server/probes/context.ts#L79) | Linear scanner; sibling sites in R2-H-29 |
| H-35 | jsHarvest quadratic line numbers | PARTIAL | critical | [worker/analyzers.ts#L440](../worker/analyzers.ts#L440) | Line table fixed; SWC segfault, walkAst overflow and quadratic regexes remain (R2-H-23; R2 verification rates SWC high because it depends on deployment) |
| H-36 | Router self-mount OOM | PARTIAL | high | [program-graph.ts#L1659](../src/server/program-graph.ts#L1659) | Resolver capped; Gin, Rails and middleware paths uncapped (R2-H-25) |
| H-37 | Compose interpolation uses host env | FIXED | low | [compose-parse.ts#L925](../src/server/compose-parse.ts#L925) | Identity guard; a copied env still resolves (debt) |
| H-38 | Compose alias bomb | FIXED | low | [compose-parse.ts#L282](../src/server/compose-parse.ts#L282) | Node budget plus worker isolate; byte budget missing (debt) |
| H-39 | Variant sweep path read | FIXED | low | [exec-recon-planner.ts#L256](../src/server/exec-recon-planner.ts#L256) | Realpath, isFile and size checks; sibling walker skips `isSensitiveRepoEntry` (new, unrated) |

### Detail for items still OPEN, PARTIAL or CHANGED

Each subsection below is condensed from the recheck data.

#### C-1 — HTTP/2 verify op (PARTIAL, high)

- **Root cause.** HTTP/2 is a separate egress pipeline. The stateless checks (admit, SSRF pinning) were moved into shared modules. The stateful broker controls stayed private to `RequestBroker`:
  - `acquireSlot` token bucket and in-flight cap
  - circuit breaker and AIMD
  - `grant.audit`
  - persona 401 re-auth
  - transport config (egress proxy, mTLS, authorized User-Agent and headers)

  The admission engine's `budgetCheck` and `rateLimitCheck` hooks are never wired.
- **Attack path.** A worker sends many concurrent `op:'http2'` GETs to an in-scope production origin. Each opens a new pinned TLS connection, with no RPS or concurrency cap, no Retry-After handling and no circuit breaker. With a persona this can cause account lockout or a WAF ban. Nothing is audited, and the traffic bypasses the operator's egress proxy and identifying UA.
- **Fix plan.**
  1. Add `RequestBroker.executeHttp2Exchange`, or an `executeHttp(..., {protocol:'h2'})` mode. It runs prepareRequest, withKillSwitch, acquireSlot, audit 'allowed', `egressHttp2` with the pinned addresses, audit 'observed', recordStatus, and redaction.
  2. Delete the private egress in `executeHttp2` (verify-rpc.ts:1212).
  3. Require the budget and rate hooks for any engine used outside the broker.
  4. In `egressHttp2`, drop hop-by-hop headers and use try/finally around `client.request`.
  5. Add a per-session RPC in-flight cap.
  6. Fix ARCHITECTURE.md:275/:302 and add a grep contract that bans direct `EgressGateway.egress*` calls in verify-rpc.
- **Regression test.** `tests/c1-h2-broker-controls.test.ts`, using an h2c server with about 200 ms per stream and `maxRpsPerOrigin=1`:
  - 6 concurrent `http2` calls keep peak streams at or below the per-origin cap, with a wall time of at least about 5 s.
  - The audit spy sees allowed and observed for each call.
  - Repeated 429s open the circuit, and later calls reject with `BrokerCircuitOpen`.
  - A caller `connection` header rejects cleanly with no leaked handles.
  - Pseudo-header overrides are still ignored.

#### C-2 — Subdomain auto-admission (PARTIAL, high; see R2-H-5)

- **Root cause.** The principal for auto-admission is inferred from DNS naming (registrable domain minus a deny-list), not from what the operator approved. Admission also happens server-side after scope review, through `updateRun({approved})`, so it skips `setScope`, `scopeRevision` and the declined candidates. Liveness is the only signal, and `wildcardApexes` is ignored.
- **Attack path.**
  1. The operator creates a public seed on an unlisted SaaS tenant. `includeSubdomains` is on by default.
  2. Discovery queries the vendor apex.
  3. Phase 0 `applyDiscoveredSubdomainsToRun` auto-admits siblings and vendor hosts, plus any first-party hosts the operator unchecked.
  4. The grant is rebuilt and Phase-0 and workers actively probe them.
- **Fix plan.**
  1. Anchor admission at the approved asset host, with a leading `www.` stripped, and admit only `*.anchor`. Use registrable-domain discovery only to create unapproved candidates.
  2. Make apex siblings an opt-in per-asset flag that shows the computed domain.
  3. Persist a set of reviewed and declined candidates in `setScope` (store-runs.ts:2125), and never auto-admit anything in it.
  4. Route every admission through one store method that bumps `scopeRevision` and emits `asset.auto_admitted`.
  5. Apply `THIRD_PARTY_SAAS_CNAME_SUFFIXES` and a multi-tenant SaaS list to the seed and the apex.
  6. Do not auto-admit hosts that only answer because of a wildcard.
- **Regression test.** Add C-2b to `tests/t1-safety-bounds.test.ts`:
  - Unit: the anchor for SaaS tenant hosts never resolves to the vendor domain.
  - Store flow: with a stub vendor not in the PSL and sibling candidates, approving only the seed leaves the siblings as candidates only.
  - A pre-review `api.<corp>` that the operator declined is not admitted.
  - A new `x.app.<corp>` is admitted and the admission is recorded in an event.

#### C-3 — capability.seal byte oracle (OPEN, critical; siblings R2-C-3, R2-C-4, R2-H-4)

- **Root cause.** The host evaluates predicates the worker chooses over host-private raw bytes, then reports the result. Length floors only constrain the captured group, not what a lookaround asserts. Rate limits are keyed by objects the worker can recreate (exchangeId, a VerifyRpcServer instance). The preview truncates before it redacts.
- **Attack path.**
  1. Send an exchange whose response contains a hidden field.
  2. Seal it with the regex selector, where the capture is a visible anchor of 8 or more characters and a zero-width assertion tests the hidden bytes.
  3. Success versus "did not match" leaks one bit.
  4. Rotate exchanges every 12 attempts. That is about 128 queries per 32-hex token, which resets per attempt.
  5. Print the recovered value.
- **Fix plan.**
  1. Remove the regex selector for hidden data, keeping only whole-field jsonPath, header and cookie selectors. If regex must stay, run it on scrubbed text using a linear engine, and reject lookaround and backreferences.
  2. Collapse all extraction failures into one constant error.
  3. Move the seal budget into run-scoped state keyed by (run, origin+path+persona), with a hard cap per run.
  4. Redact before slicing (see R2-H-4).
  5. Derive `kind` only from args.
  6. Make composite correlation match by exact equality to host-minted IDs, and return coarse reasons only (see R2-C-3).
  7. Never return raw HMAC output (see R2-C-4).
  8. Rewrite I3 as "no worker-chosen predicate over host-private bytes", and add a CI grep guard.
- **Regression test.** `tests/c3-seal-oracle-r2.test.ts`:
  - A true assertion and a false assertion produce byte-identical results.
  - 300 seals across two servers trip the run budget.
  - A secret placed across byte 1024 never appears in the seal or exchange view.
  - composite.verify verdicts for a correct and a wrong first character are identical.
  - `meta.kind` does not depend on the raw value.

#### C-4 — V8 oracle hydration (OPEN, critical; see R2-C-8)

- **Root cause.** The fix changed the model's role from supplying operands to supplying operand selectors. The model still controls four things:
  - which JSON leaf each operand reads (`*FieldPath`)
  - which transcript record fills each role (`idx` is the whole transcript)
  - the identity labels (`rolesByTenant`, tenant and scope strings, surfaces)
  - substring matching of tokens

  On top of that, `hasEconBaselineCtrl` substitutes for the denied-control floor.
- **Attack path.** Ordinary authorized traffic (read, act, read, plus any same-family 403) goes into a one-hop `prove_composite` with field paths that point at the wrong leaves, or with a GET cited as the "action". It confirms over-refund, balance minting, cross-tenant replay, temporal revocation or batch bypass.
- **Fix plan.**
  1. Remove every `*FieldPath` from oracleInput. Use a per-role keyword split, and fail closed on ambiguity.
  2. Bind roles. Baseline and final must be distinct reads of the same route, entity and actor. Actions must be probe-arm writes in the terminal hop. Timestamps must be strictly ordered. IDs must be cited in the receipt.
  3. Delete `hasEconBaselineCtrl` as a stand-in for the denied control, and require a host-observed expected delta.
  4. Apply the stub, own-tenant, denied-control and two-hop checks before any explicit family returns.
  5. Derive actor roles and tenants from host persona metadata.
  6. Match tokens by exact leaf equality, with a minimum length.
  7. Crypto: require issuance ≠ replay and a host signature link.
  8. Temporal: take surfaces from host records, require a host-classified revocation, and make the baseline mandatory.
  9. Remove the `authorizedDeposits` override in terminal-oracle-registry.ts:257.
  10. Update the prompts.
- **Regression test.** Add C-4r2 to `tests/t2-composite-hydrate.test.ts`, using the conserved fixture. Each of these must be rejected:
  - over_refund through `paidAmountFieldPath`
  - balance_minting with the baseline cited as the action
  - a balance path pointed at refunded-total
  - unrelated discount paths
  - crypto replay where issuance and replay are the same exchange
  - asserted `rolesByTenant`
  - a mislabelled temporal revocation
  - single-character batch IDs

  A genuine over-refund must still confirm.

#### C-5 — Conserved-balance race receipt (PARTIAL, critical)

- **Root cause.** Role semantics come from evidenceRole labels assigned from claim IDs or worker args, not from host-recorded causality. Nothing checks that the roles form one experiment: same resource read before and after, one concurrent batch, and an identical serial control. The predicates (over_credit, negative_balance, cap, under_debit via request-field names) fire on correct behavior. Any 4xx response counts as a serial rejection.
- **Attack path.**
  1. Read a count or balance.
  2. Send two concurrent legitimate creates, or even two GETs.
  3. Read it again.
  4. Send an unrelated GET that returns 404 and cite it as the serial control.
  5. The race claim confirms over_credit and persists CWE-362. Both runs reproduce.
  6. Variant: `prove.race` still copies baseline, post and serial IDs from args, and the Layer-3 race claim does not require `op:'race'`.
- **Fix plan.**
  1. Stamp a host `raceBatchId` on each burst. Reject worker evidenceRoles for reserved roles.
  2. Make `readRoute` mandatory in `prove.race`, drop the ID fallbacks, and make the serial control the identical request.
  3. Have `buildAgentScriptReceipt` derive roles from the host batch.
  4. In verify:
     - require the same batch, op, method, route and actor
     - require reads on the same route and actor
     - narrow serial_rejection to 409, 410 or 422 after a serial 2xx
     - set the expected delta to acked × Δ
     - require over_credit ≥ 2Δ
     - require a serial boundary for negative and cap cases
  5. The Layer-3 race claim requires a single `raceBatchId`.
  6. Bind the composite `proofReceipt` class and exchanges (see R2-H-6).
- **Regression test.** `tests/c5-r2-conserved-balance.test.ts`:
  - Must be rejected:
    - (A) creates with a 404 serial control
    - (B) unit mismatch
    - (C) GET burst with different wallets
    - (D) overdraft with an unrelated 409
    - (E) no timestamps
    - (F) burst outside one batch
  - Positive case: a same-batch redeem with a serial 2xx followed by a 409 confirms under_debit.
  - Handler test: `prove.race` ignores args IDs.

#### C-6 — business_logic impact (OPEN, critical; see R2-C-7)

- **Root cause.** `assessBusinessLogicImpact` treats any one of four weak signals as impact:
  - `peerDenial`: accepts an anonymous control, accepts when tenant data is missing, and never compares roles
  - `resourceBound`, which is really an attribution check
  - `repeatedTransition`, which needs only the same method, route and body
  - `crossTenantControlRead` with a collection prefix

  The boundary branch returns before persistence is checked, and the authz assessor refuses these same steps.
- **Attack path.** Anonymous 401 then member 2xx on the same route, or viewer 403 then admin 201, or create→read→transition→read, or a duplicate POST. Add impactClass business_logic and it confirms as CWE-840.
- **Fix plan.**
  1. In `peerDenial`, reject anonymous controls, drop the missing-tenant fallback, require a control role rank at least the probe's, and require the same request body.
  2. The boundary branch must require a persisted, attributable delta or a host-trusted event.
  3. Remove `resourceBound` from the impact disjunction.
  4. `repeatedTransition` must require an existing resource ID, a readback in the post-state between the two calls, and a further delta.
  5. `crossTenantControlRead` must bind to an object ID with a victim readback.
  6. `handleProvePersistedMutation` must stop forwarding worker fields.
  7. `receiptCheckForResult` must stop passing spec events as trusted (see R2-H-9).
  8. Add an ARCHITECTURE invariant: no impact without a persisted, attributable delta or a host event.
- **Regression test.** In `tests/t2-oracle-invariants.test.ts` (or c6-r2), with host actors only:
  - Must be unsatisfied: (a) anonymous 401 + member PATCH, (b) viewer 403 + admin 201, (c) todo complete, (d) duplicate collection create, (e) globex collection read + acme POST.
  - Must stay satisfied: (f) an admin denied, then a viewer write with a protected change, (g) a double terminal transition with an intermediate readback and a second delta.
  - Fix the existing test at :70-91.

#### C-7 — Boolean differential (PARTIAL, critical)

- **Root cause.** "SQL injection" is inferred from three things: the same masked shape, a stable structural difference, and values the parser maps to opposite truth values (bare 1/0 and true/false are accepted). There is no third arm equivalent to true. requestShape ignores origin, persona and credentials. The class is hard-coded. The request body is reconstructed from carrierText, which includes the response.
- **Attack path.** `prove.differential` in boolean mode on a filter flag, or id=1 vs id=0, optionally with a different persona or origin per arm. A multi-line response then confirms CWE-89.
- **Fix plan.**
  1. Remove the bare-literal branches. Better, have the host mint predicate pairs and record them.
  2. Require a triangle of baseline, true and false arms.
  3. Add origin, persona and an auth digest to requestShape.
  4. Pass origin and actor into `toArm`, and read the raw request body from the fact log.
  5. Add identity checks to the structural_diff receipt, derive the class from the host family, and require a named param.
  6. Make verify-claims:1831 stop counting a bare structural_diff.
  7. Make `handleProveDifferential` reject per-arm persona or origin changes.
  8. Fix the test at `v7-agent-script-proofs.test.ts:541`.
- **Regression test.** Must be rejected:
  - (a) in_stock 1/0, true/false, and id 1/0
  - (b) 1/0 with pretty-printed JSON
  - (c) a second origin
  - (d) admin vs guest

  Plus:
  - (e) host triangle positive
  - (f) a GET with no body has no reconstructed request body
  - (g) a body_contains category pair is rejected (see R2-C-6)

#### C-8 — DOM-XSS oracle (PARTIAL, medium)

- **Root cause.** The kernel browser rule treats any non-empty `trace.sinks` as execution. Soundness lives only in the seam heuristic, which still accepts a title change as execution. The window flag is read in the main world, so prototype pollution can satisfy it. The canary is deterministic.
- **Attack path.** Residual paths that need a future producer or unusual app behavior:
  - a same-page follow-up step launders a server-rendered title
  - an entity-encoded title
  - an SPA title binding fed by JSON
  - client-side prototype pollution of the flag

  The HTTP-side sibling, R2-C-5, is critical and live today.
- **Fix plan.**
  1. Require a host-minted isolated-world execution attestation in the kernel rule.
  2. Use an `exposeBinding` or CDP isolated-world callback with a host nonce.
  3. Stop treating marker and substring hits as canary hits.
  4. Interim: check for a server-rendered title over the whole session, compare against the decoded title, and include JSON bodies.
  5. Make the control arm mandatory.
  6. Do not map `executedSentinels` to sinks.
  7. Fix `assessMarkupImpact` (see R2-C-5).
- **Regression test.**
  - Seam: follow-up-step title, encoded title and JSON-bound title all give `sinkHit=false`.
  - Kernel: `dom_xss:*` sinks without an attestation are not confirmed.
  - Playwright: prototype pollution of the flag does not trigger.
  - A missing control arm fails.

#### H-2 — Kill-switch scope (PARTIAL, high)

- **Root cause.** The kill switch is a passive gate outside the run lifecycle. It aborts controllers but does not pause runs. Egress not bound to a registered controller (persona refreshers, testPersonaAuth) is never gated, and `EgressGateway` never consults the switch. A global reset clears everything. Persistence is last-writer-wins over whole snapshots.
- **Attack path.**
  - (A) After a trip, persona refresh timers keep POSTing credentials.
  - (B) Trip then reset wedges runs (R2-H-17).
  - (C) A global reset silently lifts a tenant containment.
  - (D) A sibling instance's tenant trip lifts a global trip.
- **Fix plan.**
  1. A global reset touches only global state. Add a separate `resetAll` and audit the released tenants.
  2. Sync before mutating, and merge state monotonically by generation.
  3. `EgressGateway.egress*` requires a kill-switch tenant and checks it.
  4. Thread an AbortSignal into refreshers, and stop them on trip.
  5. Execution subscribes to `onChange` and pauses and disposes runs.
  6. Claim paths roll back a no-op spawn.
  7. `testPersonaAuth` sets tenantId and asserts the switch is allowed.
  8. Wire or delete the `killSwitchCheck` hook.
- **Regression test.** `kill-switch-lifecycle.test.ts`:
  - a global reset preserves tenant trips
  - cross-instance merge
  - a persistence failure still notifies
  - run recovery: pause → resume works
  - refresher fetch count is zero after a trip
  - EgressGateway rejects for a tripped tenant
  - `testPersonaAuth` throws

#### H-3 — GraphQL read-only exception (PARTIAL, medium)

- **Root cause.** The exception depends on bytes the agent writes: the path suffix, the body shape and the headers. GraphQL-ness and the effective verb are facts about the target, and they are never established. Four separate copies implement the exception.
- **Attack path.** A POST to a REST route whose last segment is a parameter set to "graphql", carrying a read envelope, optionally with a method override, a loose content-type substring, or a duplicate content-type header. It is allowed at Tier 1 under `prod_readonly` without approval.
- **Fix plan.**
  1. Add a host-owned set of confirmed GraphQL endpoints and match exactly.
  2. Make the effective method include overrides; deny when one is present.
  3. Canonicalize headers and reject duplicates.
  4. Make the judge reuse the strict JSON validator and pass headers.
  5. Bind the oracle's read check to confirmed endpoints and the strict document.
  6. Remove the classifiers from scoped-browser.
  7. Optionally check the denylist first under staging.
- **Regression test.**
  - A path ending in `/graphql` with no declared endpoint is denied.
  - Override headers and parameters are denied.
  - A duplicate content-type gives `invalid_header`.
  - Judge parity on escaped hint words.
  - A JSON body with an extra `query` key is not classed as a read.
  - A browser POST with no policy is denied.

#### H-4 — Batch/race approval (PARTIAL, high)

- **Root cause.** One human decision is not bound one-to-one to what the operator saw. The homogeneous combine groups by method and risk only. The card payload is agent-ordered and the UI cannot render it. Group keys and ledger fingerprints ignore headers, and the broker-side `authorizeStateChange` runs without headers.
- **Attack path.** Two to ten same-method escalations (for example DELETEs on other users' objects, with item 0 harmless) produce one card showing item 0 with "(empty body)". Approval grants all of them.
- **Fix plan.**
  1. Remove or narrow `canCombineHomogeneousBatch`, or store a hashed `targets` list that the decision binds to.
  2. Build the card on the host with a "Batch of N" line.
  3. Render `items`, `sample` and `count` in ReadApproval.
  4. Add multipart kind and a headers digest to `groupKeyOf` and to the fingerprint.
  5. Pass headers into `StateChangeApprovalContext`.
  6. Bind grants to the assignment.
  7. Write audit rows per target.
- **Regression test.** `tests/h4-batch-approval-r2.test.ts`:
  - Two DELETEs produce two cards, or a card that lists both targets; approving one card never sends the other.
  - A plain body and a compressed body are separated under strict.
  - A malformed vs well-formed multipart gives 2 targets.
  - A pattern does not approve a malformed multipart.
  - ReadApproval renders the items.

#### H-5 — Recipe/agentScript envelopes (PARTIAL, medium)

- **Root cause.** Envelope trust is a per-call opt-in flag, not a property of the data. Model specs and host envelopes share one column. A missing trust value fails open, and Gate 6 never sets it. The agent-script retest contract is model-authored code.
- **Attack path.** This is latent. If any model-writable non-static row reaches confirmed, a planted `agentScript` (with the hash of an earlier confirmed script) can be run by Gate 6, and an oracle_failed result turns into fixed. A live variant: a confirmed proof's own script decides whether the retest says "fixed" (see R2-H-16).
- **Fix plan.**
  1. Strip recipe and agentScript from the public schema.
  2. Reject them at intake.
  3. Move host envelopes to a host-only column.
  4. Read envelopes only from that column, and delete `hasStoredMatch`.
  5. Validators allow only `host_persisted`.
  6. Gate 6 passes the derived trust.
  7. Retest loads the script from the proof record, asserts its sha, and never maps oracle_failed to fixed for Gate 6.
  8. Take actor role and tenant from the vault.
- **Regression test.** `tests/h5-envelope-provenance.test.ts`:
  - Schema strips the fields.
  - Undefined trust is denied.
  - Gate 6 with a planted envelope does not report fixed.
  - A script hash mismatch gives inconclusive with no backend call.
  - Self-sabotage gives inconclusive.

#### H-6 — OOB binding (PARTIAL, high; see R2-H-11)

- **Root cause.** The host signs a token hit (a boolean), not when it happened, which request carried it, or where it came from. Causality is then rebuilt from WAIT timestamps and a substring search over request and response, and the carrier can be chosen.
- **Attack path.** Mint and subscribe. Inject into a real fetcher A. Have B echo the token. Wait. Claim `injectionExchangeId=B`. SSRF is confirmed on B. The drain path makes the same mistake on promotion.
- **Fix plan.**
  1. Sign the callback's `receivedAt`, `callbackId` and `canaryId` in the WAIT/CHECK artifact.
  2. Emit a `HostOobEvent` only with the real callback time.
  3. Make the carrier check request-side only.
  4. Require a unique carrier with a start time at or before the callback.
  5. The verify-claims oob claim requires `injectionExchangeId`.
  6. `convertOobPromotions` promotes host-minted subscriptions only.
  7. Ignore model-supplied origin and label at mint.
  8. Composite `hasOob` counts only for OOB classes with a token in the hop (see R2-H-7).
  9. Optionally pin the source IP.
- **Regression test.** `tests/t2-h6r2-oob-carrier-binding.test.ts`:
  - Echo-only B is rejected and A confirms.
  - A callback before injection is rejected.
  - The WAIT artifact carries the relay time.
  - Drain refuses verify-session subscriptions.
  - A composite with an unbound OOB event under broken_access_control is rejected.

#### H-8 — Raw secrets in browser pages (PARTIAL, high)

- **Root cause.** Real credential bytes are given to an untrusted page, then caught on the way out with exact-match redaction over a fixed set of encodings. The model-boundary scrub is a snapshot taken at session start and lacks jar and vault secrets.
- **Attack path.** A lab target with XSS: injected script reads a jar cookie or storage token, applies a transform outside the encoding set, and writes it into the DOM or a form. It passes `sanitizeBrowserResult` and the exact-only scrub and reaches the model.
- **Fix plan.**
  1. Put opaque placeholders into the page. The broker swaps them for real values on the wire, only for allow-listed origins.
  2. Make the model scrub live, including broker and vault secrets.
  3. Return the sanitized payload inline.
  4. Precompute the needle set (fixes R2-H-28 too).
  5. Add an ARCHITECTURE invariant: no real credential in any browser context.
- **Regression test.** `tests/scoped-browser-no-raw-secrets.test.ts`:
  - `addCookies` and init scripts never contain raw values or their hex or base64 encodings.
  - The broker wire carries the real value.
  - A transformed exfil does not decode to the secret.
  - The inline RPC result is sanitized.
  - A secret registered after session start is scrubbed.

#### H-9 — Request-plane vault scrub (OPEN, critical; see R2-C-9)

- **Root cause.** One sanitizer (`this.egress`, which includes the run-wide vault) builds both the worker view and the kernel request plane. The H-9 fix split only the response plane, so the kernel now compares raw response text against vault-scrubbed request text. The worker controls what goes into the scrub set: any value of 8 or more characters, run-wide, and the set only grows.
- **Attack path.** Get a marker reflected, seal it, then send a control and a probe that carries the marker. The recorded request path shows a placeholder while the raw body shows the marker. SSTI (or an echoed engine fingerprint) is confirmed. The vault is shared, so both runs reproduce.
- **Fix plan.**
  1. Record kernel `pathAndQuery`, headers and `carrierText` with the kernel sanitizer only.
  2. Make `buildHostSignedTranscript` and `fromTranscriptStore` use the kernel fields, and assert that no `[redacted:cap:` appears in the kernel plane.
  3. Oracles treat any placeholder in request text as unknown, and reject a proofPattern equal to a sealed-value digest.
  4. Only secret kinds of 12 or more characters with entropy go into the scrub set, scoped per session.
  5. Store the executable script host-only and check its sha before reverify.
  6. Stop telling the skills to seal job IDs.
  7. Add the ARCHITECTURE invariant.
- **Regression test.** `tests/h9-request-plane-kernel-truth.test.ts`:
  - After sealing M, the kernel path contains M and the worker view masks it.
  - The SSTI receipt with a reflected M is rejected.
  - `assessInjectionImpact` with a placeholder path is unsatisfied.
  - Script sha integrity is enforced.
  - Scope: a generic job-ID seal is not scrubbed.

#### H-11 — I6 attacker provenance (OPEN, critical)

- **Root cause.** Attacker eligibility comes from arm labels the worker controls and a role classifier that fails open. Provenance checks only `arm==='probe'`, and the terminal exchange may be setup or cleanup. Capability lineage is tracked only for login emitters. Labels the classifier does not recognize (underscore-joined or manager) count as unprivileged. `CompositeVerifyOptions` is never built from the grant.
- **Attack path.** An admin persona 2xx labelled `arm=setup` is cited as the terminal exchange, plus a member 403 control. A one-hop composite confirms authz_bypass even with every option set. Variants: privileged labels the classifier misses, and laundering a sealed admin capability.
- **Fix plan.**
  1. The terminal exchange must be `arm=probe`, and root hops need a probe.
  2. Run the forbidden-persona check on every non-control cited exchange. dagCaps come only from probes that passed provenance.
  3. Add `emitterActorOf` for any emitter.
  4. Classify privilege fail-closed and fix `ROLE_WORD_RE`.
  5. Add `buildCompositeVerifyPolicy(grant)`.
  6. Make the options required and fail closed when empty.
  7. Wire all production callers.
  8. Document I6.
- **Regression test.** `tests/h11-r2-attacker-provenance.test.ts`. Must be rejected:
  - setup or cleanup admin or owner terminal
  - `super_admin`, `org_admin` or `manager` probe
  - multi-tenant label probing the admin tenant
  - an anonymous probe holding an admin-sealed capability
  - a one-hop receipt with no probe

  Plus a positive control, and a wiring spy asserting that the options are derived from the grant.

#### H-12 — Composite class/oracle contract (OPEN, critical; see R2-H-6, R2-H-7)

- **Root cause.** When no family resolves, the terminal gate uses one heuristic that ignores the class:
  - any same-family denied control, unbound to entity or actor, with a 404 entity taken from the worker's `hop.entityId`
  - any delivered OOB event or browser sink
  - any async edge, which removes the control requirement
  - a `proofReceipt` short-circuit with no class binding

  `verify-claims` then treats a passing composite as impact for any class.
- **Attack path.** Paths (A) through (D), all deterministic across both runs: a create→read async_job edge, an own-record 200 plus another ID's 403, any OOB or sentinel, or an embedded low-impact receipt relabelled.
- **Fix plan.**
  1. Add a closed `TERMINAL_CLASS_CONTRACT` and fail closed with `terminal_class_unmapped`.
  2. Bind `proofReceipt` class and IDs to the terminal hop.
  3. Remove the oob/browser/async relaxations unless the token or sentinel is bound to that hop.
  4. Bind controls to entity, actor and method using host provenance only.
  5. Composite evidence counts only for the matching claimed class.
  6. Wire the options (see H-11).
  7. Fix `t2-composite-hydrate.test.ts:568`.
- **Regression test.** `tests/h12-r2-terminal-class-contract.test.ts`. Must be rejected:
  - (1) async-only chains for rce, ssrf, sqli, path_traversal and business_logic
  - (2) same-path 403 with a different query
  - (3) a different-ID 403
  - (4) a 404 with `hop.entityId`
  - (5) an unbound OOB event
  - (6) a browser trace for sqli
  - (7) an unmapped class
  - (8) a `proofReceipt` class mismatch

  Positive cases for dual_tenant_abac and token-bound SSRF must still confirm.

#### H-13 — Declared auth, SameSite and events (PARTIAL, high)

- **Root cause.** Actor auth and SameSite are inferred from the request headers the caller asked for, not from where the broker actually placed the credential. Unknown values default to permissive, and the CSRF event is synthesized from the same predicates the oracle gates on. The oracle never checks that the request could be sent cross-site.
- **Attack path.** A bearer persona plus a junk cookie capability, a foreign Origin and a JSON body. The host records `auth=cookie` and `sameSite=null` and adds `csrf_state_change`, so CWE-352 is confirmed on a bearer API. Related: genuine cookie CSRF can never be confirmed, and composite and replay paths leak declared fields (R2-H-6, R2-H-9).
- **Fix plan.**
  1. Record a host-only `credentialPlacement` (persona auth kind, capability targets, jar), and mark mixed cases.
  2. Derive `ambientAuth` only from that record.
  3. Bind SameSite to the authenticating cookie name, defaulting to Lax.
  4. CSRF requires a cross-site-sendable request: simple content type, no custom headers, no token. Reject mixed.
  5. Stop synthesizing `csrf_state_change` from Origin.
  6. Drop declared fallbacks in verify-claims, and pass the factLog in verify-runner.
  7. Move the custody sanitizer into `verifyReceipt`.
- **Regression test.** `tests/h13-host-credential-placement.test.ts`:
  - A bearer persona plus a cookie capability gives auth not cookie, no CSRF event, and no confirmation.
  - A Lax cookie persona is not confirmed.
  - SameSite=None with JSON is not confirmed; form-encoded with no token is confirmed.
  - Field-mutation invariance.

#### H-14 — auth_bypass credential provenance (OPEN, high)

- **Root cause.** The guard reads credential provenance from fields the product transcript never records. `requestMeta` holds only the caller's headers, while the jar cookies and vault headers live only on the wire. Unknown provenance is treated as "no credential". The login-token check reads only `authorization`. Any allowlisted header or query difference counts as the bypass.
- **Attack path.** Log in during setup with session S. Send the control with no session and get 401. Send the probe with S plus a cosmetic spoofable header and get 200 for /me. That confirms CWE-287. Variants: a login token re-sent in an x-auth header or a query parameter.
- **Fix plan.**
  1. The broker returns `wireCredentialProvenance` (names only).
  2. Sign the session and wire credentials into the transcript record.
  3. Populate the fact log from those fields.
  4. Use `credentialSetOf` with a subset check, and fail closed when provenance is missing.
  5. Compare login-issued tokens against every request carrier.
  6. Require exactly one differing element and an ablation arm.
  7. Apply the same rule in auto-classification.
  8. Fix persona-plus-jar overlap (downgraded medium).
- **Regression test.** `tests/h14-auth-bypass-wire-provenance.test.ts` against a real broker and server. Must be rejected: jar + header, jar + query, token in x-auth, token in query, token in body, and boundary auto-classify. Unsigned self-minted bearer with ablation must confirm. Missing provenance fails closed. Mutation invariance.

#### H-15 — Timing differential (PARTIAL, high)

- **Root cause.** Arm identity is origin, method, lower-cased path and handle. The query, body, headers, session, capabilities, auth and status are all outside it. No single differing parameter is required, no host delay binding, and the class is hard-coded to blind_sqli. Sample and interleave rules exist only outside the kernel.
- **Attack path.** A page-size query parameter, an anonymous 401 vs a capability probe, different session jars, a 400 validation control, or identical requests. Each confirms blind_sqli.
- **Fix plan.**
  1. Add a strict `timingArmIdentity` tuple.
  2. Require exactly one differing key, equal to a mandatory param.
  3. Require status parity, 5 or more arms, and interleaving inside the kernel.
  4. Bind a host-minted delay token and add a zero-delay arm.
  5. Derive the class from the construct family.
  6. Mirror the checks in the claim layer.
  7. `handleProveDifferential` builds both arms from one template.
  8. Fix the redirect rule (see R2-H-13).
  9. Make the floor recipe interleave 5 rounds.
- **Regression test.** `tests/h15-r2-timing-identity.test.ts`. Must be rejected: (A) through (I), covering query, capability, session, POST body, status, identical, case, 1+1 arms, and non-interleaved. A host-delay positive case must confirm.

#### H-16 — Injection fingerprint echo (PARTIAL, high; see R2-H-10)

- **Root cause.** Any fingerprint string anywhere in the probe response counts as evaluation. The echo subtraction misses several request carriers (non-JSON bodies, path segments, cookie sub-values, multipart) and several transforms (case, whitespace, escapes, truncation). The table includes defensive strings. Zero controls are allowed, and kernel callers pass no family.
- **Attack path.** A form POST where one field holds Postgres-label text, against an error page that reflects it, confirms CWE-89. Variants: an XML refusal with no control, or a WAF block message.
- **Fix plan.**
  1. Tokenize every carrier (and parse form bodies in `toImpactStep`).
  2. Normalize before stripping, and apply a containment rule.
  3. Move defensive strings out of the table.
  4. Require a same-route, same-shape control and the claimed family.
  5. Pass the family in proof-receipt, replay-verifier and floor-recipe-engine.
  6. Use a shared stripped helper in verify-claims.
  7. The floor recipe drops carrierText.
  8. Add the invariant.
- **Regression test.** H-16 r2 cases (a) through (h) are unsatisfied: form, XML, path segment, cookie, upper-case, `&#039;`, raw-escape and truncated echoes. Defensive, zero-control and family-mismatch cases are unsatisfied. A real server error still confirms. End to end: a form reflection through the fact log is not confirmed.

#### H-17 — access_boundary fingerprints (OPEN, high; see R2-H-12)

- **Root cause.** Disclosure semantics are inverted: "a fingerprint the controls lack" stands in for "a victim's secret received across a boundary". Fingerprints are bare hashes with no kind or field path, and include headers and the viewer's own credentials. For BFLA, the planner's "denied" control is the owner re-reading the same route.
- **Attack path.** A function-level GET with the owner as both entitled and denied arm and a member probe, where a rotating XSRF cookie produces a unique fingerprint. That confirms BFLA. The same works for same-tenant BOLA, and for self-echo on /me.
- **Fix plan.**
  1. Carry structured fingerprints (kind, fieldPath, ownerPersona).
  2. Attribute named secrets to their owner.
  3. Gate disclosure on a boundary, and require a match to a victim-held value.
  4. Fix the publicness escape at :1274.
  5. The planner never sets denied = owner on the same path, and needs a lower-role peer.
  6. Add a recipe invariant.
  7. Fix detect step 5.
  8. Fix the deterministic jq filter.
  9. Document the invariant.
- **Regression test.** Unsatisfied: (a) BFLA owner re-read, (b) same-tenant BOLA token, (c) self-echo, (d) a header fingerprint for publicness. Satisfied: (e) an entitled fingerprint after a peer 403. (f) The planner never sets denied = owner. (g) The recipe aborts. (h) Fingerprints are generated through the real redact path.

#### H-18 — Confirmed finding identity (PARTIAL, high; see R2-H-14)

- **Root cause.** No host component owns finding identity. The receipt class is picked from model labels by keyword, identity is rebuilt from the same labels, and immutability is enforced only at one call site. `guardConfirmedFindingMutation` is never called.
- **Attack path.**
  - Class swap: a CWE-89 spec with SSRF wording passes an SSRF receipt, but is persisted as CWE-89.
  - Retitle: `update_proposed_finding` on a confirmed row rewrites its title, reason and specs.
- **Fix plan.**
  1. Add `cweFamilyForReceiptClass`.
  2. Classify by CWE first, and fail on a keyword conflict.
  3. Bind the CWE from the receipt class.
  4. Make the store chokepoint immutable for verified rows.
  5. Call the guard in the handler.
  6. Reverify checks for class drift.
  7. OOB promotion selects by a structured field.
  8. Redact the title with secrets.
- **Regression test.** `tests/h18-confirmed-identity.test.ts`:
  - (A) Keyword conflict gives null.
  - (B) Binding gives the receipt family or a mismatch flag.
  - (C) Store update on a confirmed row is preserved.
  - (D) Handler blocks title, summary and spec.
  - (E) A secret in the title is redacted.

#### H-19 — Retest `fixed` without health (OPEN, high; see R2-H-15, R2-H-16)

- **Root cause.** `fixed` is derived by negation, and failures are not tagged as control or probe side. The guard looks only at control arms, against a narrow status denylist. Recipes with no control arm, and the agent-script path (oracle_failed → dismissed → fixed, including split attempts), never reach the guard.
- **Attack path.** The owner's session expires (302 or 403 on the entitled read), or a WAF answers 429 to the probe, or a flaky second attempt. Verify Fix then records "Verified fixed" with no code change.
- **Fix plan.**
  1. Tag each require with its side.
  2. Add an allowlist-based `classifyRetestHealth`: controls get the expected class, probes get a definitive status, there are no harness misses, and access needs the probe denied and the entitled read served.
  3. Map `step_budget` and `oracle_disagreement` to inconclusive.
  4. No-control recipes need at least one non-throttled probe.
  5. Agent scripts report fixed only when both attempts were healthy and failed.
  6. Reverify demotes only on the same rule.
  7. Persist health in the artifact.
  8. Add the invariant.
- **Regression test.** Extend `t2-oracle-invariants` with an access_boundary status matrix that gives inconclusive, plus a property: a 2xx probe is never fixed.
  - Persisted mutation with an HTML readback gives inconclusive.
  - Boolean probe 500 gives inconclusive.
  - Race all-429 gives inconclusive.
  - Oracle downgrade gives inconclusive.
  - New `h19-agent-script-retest` covers split attempts and reverify that keeps the row confirmed.

#### H-20 — prove.oob (PARTIAL, medium)

- **Root cause.** OOB evidence is spread across three stores and nothing joins them. The receipt builder makes its event from the WAIT record. Late promotion depends on label conventions and on stored exchanges that prove.oob never produces.
- **Attack path.**
  - A false negative: an async SSRF that calls back after more than 6 s is dropped, and the drain consumes the callback.
  - Multi-origin injection, or function-form injection with no role, is rejected.
- **Fix plan.**
  1. `handleProveOob` takes a vulnClass, mints `${class}:prove_oob` with the target origin, and builds the claim on the host.
  2. Sign the callback fields.
  3. Keep the artifact fields in the fact log.
  4. Pass `oobEvents` into the builder.
  5. Delete the WAIT synthesis.
  6. Carriers are request-side only.
  7. Drain uses a run-scoped carrier map.
  8. Give a class-aware rejection message.
- **Regression test.** `tests/t3-h20-oob-e2e.test.ts`:
  - Immediate path gives ssrf confirmed with an empty rejection list.
  - Late path persists CWE-918 and the pending set is empty.
  - An echo-only carrier is rejected.
  - The message does not mention "mutating boundary".

#### H-23 — Session lifecycle (PARTIAL, high)

- **Root cause.** Credentials have three uncoordinated owners: the pool, the interval timer and the broker reauth. The broker never passes the observed generation. The lifecycle is tied to "run is running" while retests run on finished runs. The expiry signal is hard-coded to 401.
- **Attack path.**
  - (A) Verify Fix after the session TTL: the probe gets 401, no reauth runs, the result is dismissed, then fixed.
  - (B) Sequential 401s each run a full re-login, which storms the IdP or thrashes single-session apps.
  - (C) The timer and a 401 refresh replay the same rotating refresh token, so the token family is revoked.
- **Fix plan.**
  1. The pool is the only refresh owner, and doRefresh is re-entrancy safe.
  2. The reauth signature carries the observed generation.
  3. Forward it.
  4. Pace refreshes per entry and add a circuit.
  5. Retests get an ephemeral session, and fail inconclusive without one.
  6. Detect login-redirect and 403 expiry.
  7. A 401 or redirect on an auth-bound arm after reauth gives inconclusive.
  8. Remove the unscoped fallbacks.
- **Regression test.** `tests/h23-session-lifecycle.test.ts`:
  - 3 sequential 401s give 1 refresh.
  - Timer plus 401 give a single upstream POST.
  - A retest after completion gives reproduced or inconclusive, never fixed.
  - Live clone rotation.

#### H-24 — Pooled browser concurrency (PARTIAL, high; see R2-H-20)

- **Root cause.** The pool hands one mutable runtime (one page, one active and grant slot) to every caller with the same key. There is no lease or lock, and release is unconditional. LRU eviction and the cross-run prune ignore in-flight visits. The pool proxy authorizes by the union of grants. Pages and tunnels outlive their run.
- **Attack path.**
  - Two workers crawl the same persona. Requests from A are judged under B's grant and attributed to B, A loses its page, and B's later requests are aborted.
  - Run B's visit closes run A's context mid-visit, so crawl errors are silently swallowed.
- **Fix plan.**
  1. Add a per-runtime mutex (or a page per checkout).
  2. Dedupe creation with a promise map.
  3. Make release ownership-checked, and navigate to about:blank on release.
  4. Eviction skips active entries. Replace the prune with `releaseRun` on dispose.
  5. Give each runtime its own proxy identity.
  6. Close tunnels per identity.
  7. Add the invariant.
- **Regression test.** `tests/h24-pooled-browser-concurrency.test.ts`:
  - Concurrent same-key visits keep their own grant and assignment, with no blocked in-scope requests.
  - Concurrent first use creates 1 context.
  - A cross-run visit does not close the in-flight one.
  - LRU skips active entries.
  - The proxy policy is per runtime.
  - Dispose closes contexts.

#### H-25 — Executable args scrubbed (PARTIAL, medium)

- **Root cause.** Heuristic display redaction is applied to data that is later executed. The stream path was moved to exact-only matching; `run_offline_script.code` and `derive_evidence.command` were not.
- **Attack path.** A JWT audit script or a grep for a key assignment is rewritten into broken code or code that runs on the marker. This produces false negatives at scale. It fails closed.
- **Fix plan.**
  1. Use exact-only redaction, or none, at agent-session.ts:1648 and :1803.
  2. Split `scrubForDisplay` from `scrubExact`, and add a lint rule.
  3. Drop the cookie-key clobber in the `llm_tool_args` channel.
  4. Make the signature channel exact-only.
  5. Fix the persisted proof script (see R2-H-16).
- **Regression test.** `tests/t1-executable-args-roundtrip.test.ts`:
  - Code and command are byte-identical apart from exact vault values.
  - A `headers.Cookie` value is kept.
  - The signature is kept.
  - The persisted script hash matches.

#### H-27 — Verification worker failure (PARTIAL, medium; see R2-H-17)

- **Root cause.** `failed` is both the terminal state and the dedupe key. Failure never feeds back to the finding, the report or the scheduler. Lifecycle depends on in-memory maps that are not tied to whether a task actually started.
- **Attack path.**
  - A Docker hiccup marks verification workers failed. The run is then reported complete and non-partial, and findings stay pending, which is a silent false negative.
  - Stop and Resume inside the drain window orphan a worker (see R2-H-17).
- **Fix plan.**
  1. Roll back claims when spawn is a no-op.
  2. `isDisposed` includes draining.
  3. Apply the same rule to the planner and investigation spawns.
  4. Add an attempt counter with a bounded requeue.
  5. Mark exhausted attempts inconclusive.
  6. `partial` reflects worker failures.
  7. Add gap lines.
  8. Add a lease watchdog.
- **Regression test.**
  - H-27b: retried once and then inconclusive, with `partial=true` and a gap line.
  - H-27c: dispatch during drain leaves no orphan and the run completes.
  - Spawn returns `started=false` while draining.

#### H-28 — Approval wedges (PARTIAL, high; see R2-H-18)

- **Root cause.** The approval wait is an in-memory coroutine, and progress is decided by durable rows. Parking keeps a stale lease. Cleanup is driven only by the request's terminal state, so a dead waiter or an approved request with no resumer is never handled. Step settlement keys on `stepId`, not ownership.
- **Attack path.**
  - A Tier-3 escalation waits longer than the 120 s wall clock, then is approved, and the step is `running` forever.
  - After a restart an approved parked verification worker blocks finalization.
  - A late expire cancels a replacement worker's step.
- **Fix plan.**
  1. After parking, update `job.assignment`. On abort, cancel the pending request and terminate the worker.
  2. Bind waits to the session signal (inline included), or pause the wall clock while parked.
  3. Reconcile handles `approved` with no waiter: requeue verification, reset investigation.
  4. Add an ownership guard on step settlement.
  5. Write the denial outcome durably.
  6. `recover()` cancels pending parked requests.
  7. Reconcile orphans.
- **Regression test.**
  - H-28b: an abort cancels the card.
  - H-28c: an approved request with no waiter does not wedge.
  - H-28d: a denial marks the finding inconclusive.
  - H-28e: a late terminate keeps the replacement worker's step.
  - Inline: a session abort cancels the card.

#### H-31 — Warm-pool sweep (PARTIAL, medium)

- **Root cause.** Ownership of a resource shared across the daemon is decided by a bare PID, which is only unique within one namespace. ESRCH is read as "dead". `take()` trusts the in-memory idle list.
- **Attack path.** In the shipped DooD compose deployment, a containerized instance reaps a host CLI's idle warm containers. The pool then hands out a deleted name and the assignment fails. A shared owner label can also force-remove running sessions.
- **Fix plan.**
  1. Add namespace, start-time and session labels.
  2. Use `isOwnerProvablyDead` only in the same namespace, and fall back to a foreign TTL.
  3. Recycle idle containers at TTL/2.
  4. `take()` inspects status and instance.
  5. Retry cold on a pooled miss.
  6. Apply the same owner rule in ContainerSupervisor.
  7. Document it.
- **Regression test.** `tests/h31-foreign-namespace-sweep.test.ts`:
  - A foreign-namespace container is kept until its TTL; a local dead owner is reaped.
  - `take()` drops a stale name.
  - A cold retry happens on no-such-container.
  - Supervisor does not reap a foreign PID 1.

#### H-32 — Untrusted regexes (OPEN, high; see R2-H-26)

- **Root cause.** Attacker-chosen regex source runs on V8's backtracking engine on the main thread. The fix added two divergent static heuristics that accept exponential optional-in-repeated-group and polynomial overlapping chains, and wired them at only two of five sites.
- **Attack path.** Any of these can freeze the host:
  - `async.awaitResult` `jsonPath.matches` / `header.matches`, which have no cap
  - `capability.seal` regex
  - an auth_protocol_proof extract
  - `proofPatterns` reaching `credentialPatternEvidence`
- **Fix plan.**
  1. Start node with `--enable-experimental-regexp-engine-on-excessive-backtracks` plus a backtrack limit, and add a startup self-check.
  2. Add a single `runUntrustedRegex` chokepoint: reject backrefs and lookarounds, cap the haystack, use the linear engine or the pool with a timeout, and merge the guards.
  3. Route every site through it.
  4. Refine the schemas at ingestion.
  5. Add an AST lint on non-literal `new RegExp`.
- **Regression test.** `tests/h32-redos-chokepoint.test.ts`:
  - Corpus of bypass classes generated in the test, each under 300 ms.
  - Per-site tests under 500 ms.
  - Startup flag test.
  - AST contract.

#### H-33 — ProgramGraph regexes (OPEN, high; see R2-H-24)

- **Root cause.** Backtracking regexes run over whole repo files on the host thread: unanchored identifier-led patterns, and overlapping adjacent quantifiers. Only four instances were patched, and the worker-pool task has no callers.
- **Attack path.** A repo file containing a Rails routes-draw marker plus a long whitespace tail, or an express() file with a long identifier run, blocks the host for minutes to hours.
- **Fix plan.**
  1. Add `extractProgramGraphInWorker` per file, with a timeout and a warning on overrun.
  2. Make the snapshot builder async and pass the abort signal.
  3. Add an invariant and a lint.
  4. Add `(?<![\w$])` boundaries.
  5. Make Rails line-based with a length cap.
  6. Bound the `only:` parse.
  7. Rewrite the Django and Spring scanners.
  8. Cap line length.
  9. Add a regex budget harness.
- **Regression test.** Add "H-33 variants" to `t3-host-dos-regex`: each 80 KB adversarial generator finishes under 100 ms. Add a table-driven regex budget test, and a wiring test with an event-loop lag probe under 200 ms and a timeout warning.

#### H-35 — jsHarvest on host (PARTIAL, critical in recheck; see R2-H-23)

- **Root cause.** `jsHarvest` handles fully attacker-controlled bytes inline, with three unbounded work classes: a native parser with no depth limit, recursive AST walks with no exception boundary, and quadratic regexes. Only the line-number quadratic was removed.
- **Attack path.** A hostile in-scope target serves a nested-bracket bundle. On source deployments with `@swc/core` installed this is a segfault. Otherwise a deep nest causes a RangeError that aborts all of Phase-0, and repeated-token 1–2 MiB bodies cause minutes of CPU per bundle.
- **Fix plan.**
  1. Add a linear nesting pre-scan before parsing (>512 means use regex mode).
  2. Use an iterative walk with a node budget, and wrap `jsHarvest` in try.
  3. Make the regexes linear and cap inputs at 512 KB.
  4. Add a `js_harvest` task in a child process or the Docker worker, with a timeout.
  5. Move phase0 to the async runner with per-bundle catch and an origin budget.
  6. Add a lint on host imports from worker/analyzers.
  7. Fix the sibling JWT regexes.
- **Regression test.** `tests/t4-jsharvest-isolation.test.ts`:
  - A child process with deep nesting exits 0 in regex mode.
  - Depth 3500 does not throw.
  - Three 1 MiB generators each under 500 ms.
  - Phase-0 completes through the pool.
  - Sibling regexes under 200 ms.

#### H-36 — Route amplification (PARTIAL, high; see R2-H-25)

- **Root cause.** Route-path and middleware size grows with counts the attacker controls. Caps exist only in the shared resolver, and every route copies its prefix and middleware. Extraction runs on the host thread rather than the resource-limited worker.
- **Attack path.** A Go file with repeated self-groups, or a routes file with unclosed namespaces, or one use() with thousands of middleware plus thousands of routes. One file uses gigabytes and a handful crash the host.
- **Fix plan.**
  1. Bound `joinPaths` at the shared cap and skip with a warning.
  2. Reject Gin self-groups and cap depth.
  3. Cap Rails depth and treat unterminated blocks as invalid.
  4. Cap and dedupe middleware with a Set, and store it by reference.
  5. Add a per-file raw-route and byte budget.
  6. Route extraction through the pool.
  7. Add an invariant.
- **Regression test.** H-36 variants for Gin, Rails and Express each finish under 1 s, with max path ≤ 2048, middleware ≤ 64, and heap delta under 64 MB. A pool wiring test checks that overrun leads to an empty graph with a warning.

## Duplicate/variant notes

### Candidates judged duplicates of a round-1 item (29)

These were folded into the round-1 item's status and fix plan above.

| Candidate | Location | Duplicate of |
|---|---|---|
| "Approve similar" on a non-multipart POST auto-approves multipart uploads | [approval-judge.ts#L346](../src/server/approval-judge.ts#L346) | M-1 |
| One plain Approve grants a run-long lease covering sibling verbs and personas | [store-runs.ts#L1530](../src/server/store-runs.ts#L1530) | M-1 |
| Per-session verify-RPC state never evicted; composite.verify reparses it all | [verify-rpc.ts#L1031](../src/server/verify-rpc.ts#L1031) | L-5 |
| Gate 6 rollback restores source only; the lab keeps running the patch | [patch-workflow.ts#L1146](../src/server/patch-workflow.ts#L1146) | M-7 |
| Persona refresh timers and the Clerk minter bypass the kill switch | [persona-auth.ts#L1980](../src/server/persona-auth.ts#L1980) | H-2 |
| testPersonaAuth builds a tenant-less grant and ignores the switch | [worker-session-reader.ts#L354](../src/server/worker-session-reader.ts#L354) | H-2 |
| Judge fast path matches hint words on undecoded JSON | [approval-judge.ts#L511](../src/server/approval-judge.ts#L511) | H-3 |
| Method-override carriers ignored by every read-only classifier | [request-admission.ts#L33](../src/server/request-admission.ts#L33) | H-3 (the auto_review DELETE-gate consequence is new: R2-H-1) |
| Agent-script retest runs model code as the "fixed" oracle | [agent-script-proof.ts#L762](../src/server/agent-script-proof.ts#L762) | H-19 |
| agentScript envelope not bound to the proof record (sha, verdict) | [replay-verifier.ts#L966](../src/server/replay-verifier.ts#L966) | H-5 |
| HTTP/2 Set-Cookie values not registered as exact-value secrets | [verify-rpc.ts#L1183](../src/server/verify-rpc.ts#L1183) | H-7 (residual hardening) |
| HMAC/JWT sign records always signed as probe arm, null actor | [verify-rpc.ts#L1786](../src/server/verify-rpc.ts#L1786) | H-11 |
| verifyValueBinding takes emission from control-arm and seal records | [composite-receipt.ts#L281](../src/server/composite-receipt.ts#L281) | H-10 (residual) |
| Terminal exchange may be a setup/cleanup arm | [composite-receipt.ts#L661](../src/server/composite-receipt.ts#L661) | H-11 |
| Sealed-capability laundering (lineage only for login emitters) | [v8-oracle-hydrate.ts#L204](../src/server/v8-oracle-hydrate.ts#L204) | H-11 |
| Privilege classifier fails open on underscore-joined or unknown roles | [oracle-invariants.ts#L30](../src/server/oracle-invariants.ts#L30) | H-11 |
| Composite auth_bypass blind to session jars | [verify-rpc.ts#L2080](../src/server/verify-rpc.ts#L2080) | H-14 |
| Timing kernel accepts 1+1 non-interleaved arms | [proof-receipt.ts#L519](../src/server/proof-receipt.ts#L519) | M-44 |
| Claims layer and floor recipe match fingerprints on unstripped text | [floor-recipes.ts#L1577](../src/server/floor-recipes.ts#L1577) | H-16 |
| Legacy http_chain actor_differential plus fingerprint confirms self-echo | [replay-verifier.ts#L564](../src/server/replay-verifier.ts#L564) | H-17 |
| Storage chokepoint lets callers mutate confirmed non-floor identity | [store-findings.ts#L1205](../src/server/store-findings.ts#L1205) | H-18 |
| Split pass/fail agent-script retest gives fixed | [verify-runner.ts#L651](../src/server/verify-runner.ts#L651) | H-19 |
| Registry downgrade becomes receipt_rejected, then fixed | [floor-recipe-engine.ts#L94](../src/server/floor-recipe-engine.ts#L94) | H-19 |
| Control-arm denylist misses 3xx, 403/404 expiry, 429, HTML readbacks | [floor-recipe-engine.ts#L1158](../src/server/floor-recipe-engine.ts#L1158) | H-19 |
| Approved parked worker with no waiter blocks verification | [run-actor.ts#L1839](../src/server/run-actor.ts#L1839) | H-28 |
| Verification denial branches dead; finding left pending | [exec-verify.ts#L1944](../src/server/exec-verify.ts#L1944) | H-28 |
| New static ReDoS guards accept exponential and polynomial classes | [safe-regex.ts#L17](../src/server/safe-regex.ts#L17) | H-32 |
| auth_protocol_proof extract bypasses extractVariablesSafe | [floor-recipe-engine.ts#L1630](../src/server/floor-recipe-engine.ts#L1630) | H-32 |
| UntrustedComputePool extract_program_graph isolate unwired | [static-workspace-snapshot.ts#L442](../src/server/static-workspace-snapshot.ts#L442) | H-33 |

### Kept findings that add new locations to round-1 items

These were kept because the round-1 fix does not cover these locations. They are merged into the R2 entries shown.

- **C-2 → R2-H-5.** Two gaps the PSL fix does not reach:
  - SaaS vendor apex (subdomain-discovery.ts:204)
  - deselection override (subdomain-discovery.ts:952)
- **C-3 → R2-C-3, R2-C-4, R2-H-4.** Three ops that the per-instance seal rate limit does not cover:
  - `composite.verify` substring oracle
  - `crypto.hmacSign`
  - truncate-then-redact preview
- **C-4 → R2-C-8.** Five variants:
  - field-path selectors
  - unbound record roles
  - crypto replay that cites the same exchange twice
  - temporal surface labels
  - batch substring IDs
- **C-5 → R2-H-6.** The composite `proofReceipt` laundering and the unsanitized path.
- **C-6 → R2-C-7.** Three issues:
  - `peerDenial` accepts anonymous or lower-role denials
  - `resourceBound`, new in `ecc0cae`
  - `repeatedTransition`
- **C-7 → R2-C-6.** The evaluated-expression oracle (same root pattern, different oracle).
- **C-8 → R2-C-5.** HTTP markup `ACTIVE_MARKUP_RE` and `plantedMarker`.
- **H-1 / H-2 / H-27 → R2-H-17.**
  - The RunContext is never re-armed after a reset.
  - Spawn during drain is a no-op.
- **H-6 / H-12 → R2-H-7, R2-H-11.**
  - Response-echo carrier and the WAIT time.
  - OOB events are not bound to the class.
- **H-8 → R2-H-28.** A performance cost the fix introduced.
- **H-9 / H-16 → R2-C-9.** The request plane defeats both anti-reflection checks.
- **H-12 → R2-H-6, R2-H-7.**
  - async_job, OOB and browser relaxations.
  - 403 entity binding and the 404 `hop.entityId`.
  - `proofReceipt` early return.
- **H-13 → R2-H-6, R2-H-9.**
  - The composite terminal receipt is unsanitized.
  - Replay-spec events are re-admitted as trusted.
- **H-14 → R2-H-8.** Capability-injected credentials are labelled with the base persona.
- **H-15 → R2-H-13.** The redirect rule.
- **H-16 → R2-H-10.**
  - Defensive fingerprints.
  - Zero controls.
  - Opaque non-JSON bodies.
- **H-17 → R2-H-12.** Publicness guard at line 1274.
- **H-18 → R2-H-14.** Keyword class choice, plus the SSRF/XXE self-delivered event.
- **H-19 → R2-H-15.** Probe-side failures, and recipes with no control arm.
- **H-24 → R2-H-20.** The cross-run prune. It already existed at round 1.
- **H-25 → R2-H-16.** The persisted proof script.
- **H-28 → R2-H-18.**
  - Waiters bound to the session signal and the job signal.
- **H-32 → R2-H-26.** `credentialPatternEvidence`.
- **H-33 → R2-H-24.**
  - Rails cubic.
  - Express/Fastify.
  - collectCalls/guardIdentifiers.
- **H-34 → R2-H-29.** Verify-plane normalizers (H-34 itself is FIXED).
- **H-35 → R2-H-23.**
  - SWC segfault.
  - `secretScan`, GraphQL and `__NEXT_DATA__` regexes.
  - persona-auth JWT regex.
- **H-36 → R2-H-25.**
  - Gin.
  - Rails nesting.
  - Middleware fan-out.
- **H-39 sibling (unrated).** The variant-sweep sibling walker scans the raw host `reposDir` without `isSensitiveRepoEntry`. A model-chosen token can echo lines from worker-excluded files (`.env.*.js`, `.ssh/*`) into the chain-step hypotheses (exec-recon-planner.ts:2316-2406). The H-39 status checker raised this as a new possible high/critical item; it has not yet been through the three-lens pass.

## Downgraded candidates

Each candidate was rated below high after three-lens verification. Each entry gives the title, location, final severity and why.

### Medium

- **Single-hop kernel evaluates only the second attempt; I1 rests on the claim layer** — [agent-script-proof.ts#L518](../src/server/agent-script-proof.ts#L518)
  - Real, but the claim layer still requires both attempts. The weaker attempt-1 gate is defense in depth.
- **CSRF oracle ignores browser request constraints (JSON PUT/DELETE)** — [oracle-invariants.ts#L2651](../src/server/oracle-invariants.ts#L2651)
  - Needs a cookie-auth app with unknown SameSite. Overlaps H-13's fix.
- **Supabase login sends creds to any hosted project (unhardened sibling)** — [persona-auth.ts#L963](../src/server/persona-auth.ts#L963)
  - This duplicate candidate was rated medium. The kept candidate (R2-H-3) is high.
- **Broker-wide `personaSessionOwners` not run-scoped, so a cookie blocks other runs** — [broker.ts#L1637](../src/server/broker.ts#L1637)
  - Fails closed. Affects only reused credentials across runs.
- **v6 upgrade: the `verification_class` CHECK rejects legacy rows before the backfill** — [store.ts#L1082](../src/server/store.ts#L1082)
  - Startup wedge only on databases with a legacy `static_verified`+confirmed row. One-time.
- **Seal and preview vault scrubbing applied after truncation in exchange views** — [verify-rpc.ts#L1089](../src/server/verify-rpc.ts#L1089)
  - The vault leak needs a sealed value past the slice boundary. Merged guidance with R2-H-4.
- **value_binding `valueDigest`/`entityId` equality is a whole-value guess oracle** — [composite-receipt.ts#L335](../src/server/composite-receipt.ts#L335)
  - Whole-value guessing only, with no prefix extension.
- **Redirect rule confirms with no control or attacker-controlled destination (duplicate candidate)** — [proof-receipt.ts#L613](../src/server/proof-receipt.ts#L613)
  - Kept as R2-H-13. This copy was rated medium for reachability.
- **strictHostDerivation undone by passing receipt `oracleEvents` back as trusted** — [floor-recipe-engine.ts#L3727](../src/server/floor-recipe-engine.ts#L3727)
  - Duplicate lens of R2-H-9. Rated medium in this pass.
- **Boolean rule rebuilds the request body from `carrierText`, which includes the response** — [proof-receipt.ts#L422](../src/server/proof-receipt.ts#L422)
  - The production path passes a factLog with the raw body. Latent.
- **Execution keeps claiming during a trip, leaking `active` and `running` rows** — [execution.ts#L4028](../src/server/execution.ts#L4028)
  - Merged into R2-H-17 at the higher rating.
- **Trip permanently poisons live RunActors (zombie running)** — [execution.ts#L758](../src/server/execution.ts#L758)
  - Same as R2-H-17. This lens rated it medium (operator-only trigger).
- **Single-target race/batch card renders "(empty body)" and hides the count** — [run-actor.ts#L1510](../src/server/run-actor.ts#L1510)
  - The operator still approves the same target. Covered by H-4's UI fix.
- **Run-end OOB drain converts verify-session subscriptions with model labels into findings** — [exec-verify.ts#L1721](../src/server/exec-verify.ts#L1721)
  - Needs a label matching ssrf/xxe plus a run-bound callback. Covered by the H-6 fix plan.
- **Composite `HostOobEvent` timestamp is the WAIT start, so the oob_relay ordering never fails** — [verify-rpc.ts#L2027](../src/server/verify-rpc.ts#L2027)
  - Part of R2-H-11 / H-6.
- **Token-bearing headers outside the deny-list reach the worker raw** — [redact.ts#L8](../src/server/redact.ts#L8)
  - Needs custom token headers. Values are target-issued, not host secrets.
- **Leaked custom-header credential replayed with no persona and auto-classified as auth_bypass** — [request-admission.ts#L33](../src/server/request-admission.ts#L33)
  - Chained with the above. Covered by the H-14 fix.
- **Broker redaction registry FIFO-evicted at 5000** — [broker.ts#L1686](../src/server/broker.ts#L1686)
  - Needs more than 5000 distinct secrets in the process lifetime.
- **Persisted proof script vault-scrubbed then re-executed (vault variant)** — [exec-verify.ts#L2128](../src/server/exec-verify.ts#L2128)
  - Same root cause as R2-H-16. The vault-only trigger is narrower.
- **Multi-tenant exemption clears an admin persona whatever tenant it probes** — [v8-oracle-hydrate.ts#L117](../src/server/v8-oracle-hydrate.ts#L117)
  - Needs specific dual-role personas. Covered by the H-11 fix.
- **CSRF oracle never checks cross-site sendability** — [oracle-invariants.ts#L2651](../src/server/oracle-invariants.ts#L2651)
  - Covered by the H-13 fix plan.
- **SameSite resolution binds to an arbitrary cookie; unknown treated as None** — [host-fact-log.ts#L474](../src/server/host-fact-log.ts#L474)
  - Covered by H-13.
- **Persona and jar credentials absent from recorded headers** — [verify-rpc.ts#L757](../src/server/verify-rpc.ts#L757)
  - The H-13/H-14 data gap. Fails closed for genuine CSRF.
- **Persona plus session jar swaps the wire identity while the transcript names the persona** — [broker.ts#L3143](../src/server/broker.ts#L3143)
  - Needs both set deliberately. Covered by the H-14 fix step 8.
- **Agent-path `ambientAuth` derived from requested headers** — [host-fact-log.ts#L322](../src/server/host-fact-log.ts#L322)
  - Same as H-13.
- **Injection family restriction dead in every kernel caller** — [proof-receipt.ts#L725](../src/server/proof-receipt.ts#L725)
  - Folded into R2-H-10.
- **Proof-strength guard counts any `secretMatch` as identifier_proof** — [floor-recipe-engine.ts#L3064](../src/server/floor-recipe-engine.ts#L3064)
  - A guard weakness, not a confirmer. Covered by H-17 step 7.
- **Deterministic info_disclosure jq treats any fingerprint as credential evidence** — [deterministic-specs.ts#L1546](../src/server/deterministic-specs.ts#L1546)
  - Covered by H-17 step 8.
- **Late OOB promotion binds to a finding by substring of the spec JSON** — [exec-verify.ts#L1847](../src/server/exec-verify.ts#L1847)
  - Needs an ID collision. Covered by H-18 step 7.
- **Engine late-OOB promotion picks the latest response echo as carrier** — [exec-verify.ts#L1726](../src/server/exec-verify.ts#L1726)
  - Misattribution of a real callback. Part of the H-6 fix.
- **Broker-global persona ownership not keyed by run (cross-run block)** — [broker.ts#L1620](../src/server/broker.ts#L1620)
  - Fails closed. Same as the item above.
- **`personaSessionOwners` not namespaced: cross-run scope-mismatch denial** — [broker.ts#L1630](../src/server/broker.ts#L1630)
  - Fails closed.
- **Process-wide WarmSpecialistController and `boardHandleTokens` keyed by bare handle** — [board-tools.ts#L873](../src/server/board-tools.ts#L873)
  - Reliability bleed of counters and retirements. No credentials involved.
- **Broker 401 reauth ignores pool generation (login storm)** — [execution.ts#L530](../src/server/execution.ts#L530)
  - Part of the H-23 fix.
- **Verify Fix and patch-gate retests run with no credential refresh** — [execution.ts#L1702](../src/server/execution.ts#L1702)
  - Part of H-23. Floor access recipes already degrade to inconclusive.
- **Interval refresher bypasses pool single-flight** — [persona-auth.ts#L3402](../src/server/persona-auth.ts#L3402)
  - Race window only. Part of H-23.
- **Non-401 session expiry never triggers reauth; form personas have no refresher** — [broker.ts#L3301](../src/server/broker.ts#L3301)
  - False negatives. Part of H-23.
- **Shared pool proxy authorizes by the union of active grants** — [scoped-browser.ts#L1510](../src/server/scoped-browser.ts#L1510)
  - Only traffic outside `context.route`. Every grant is still a real run grant.
- **Pool eviction and prune close live contexts** — [scoped-browser.ts#L1866](../src/server/scoped-browser.ts#L1866)
  - Merged into R2-H-20.
- **Pooled pages, cookies and WebSockets outlive visit, run and kill switch** — [scoped-browser.ts#L2072](../src/server/scoped-browser.ts#L2072)
  - Covered by the H-24 fix.
- **Concurrent first use orphans a BrowserContext** — [scoped-browser.ts#L1649](../src/server/scoped-browser.ts#L1649)
  - Resource leak only.
- **Signed transcript path and `carrierText` heuristically redacted before kernel binding** — [verify-rpc.ts#L1039](../src/server/verify-rpc.ts#L1039)
  - Fails closed: lost recall. Folded into the H-9 fix step 1.
- **Run-end report labels failed verification complete; findings stay pending** — [oob-drain.ts#L230](../src/server/oob-drain.ts#L230)
  - Same as H-27. This lens rated it medium.
- **Chain planner and investigation spawn leak on a no-op spawn** — [execution.ts#L3164](../src/server/execution.ts#L3164)
  - Merged into R2-H-17.
- **terminateApprovalBlockedAssignment cancels a step owned by another assignment** — [run-actor.ts#L1800](../src/server/run-actor.ts#L1800)
  - Needs restart plus a late expiry. Part of the H-28 fix.
- **Investigation provider outage recorded as step complete** — [exec-worker-runner.ts#L563](../src/server/exec-worker-runner.ts#L563)
  - The breaker still advances. Coverage reporting gap.
- **Planner breaker trip reported as a normal "Investigation complete"** — [execution.ts#L3900](../src/server/execution.ts#L3900)
  - Reporting gap only.
- **Lab recoverAll treats an equal or foreign-namespace PID wrongly** — [container-supervisor.ts#L744](../src/server/container-supervisor.ts#L744)
  - Same class as H-31.
- **PID-only ownership leaks containers after a containerized restart** — [worker-backend.ts#L1985](../src/server/worker-backend.ts#L1985)
  - Leak, not reap.
- **FastAPI/Flask/gin extractors use an unbounded leading identifier capture** — [program-graph.ts#L1220](../src/server/program-graph.ts#L1220)
  - Smaller magnitude than R2-H-24.
- **Rails resources `only:` regex quadratic** — [program-graph.ts#L1590](../src/server/program-graph.ts#L1590)
  - Seconds per file. Covered by the H-33 plan.
- **walkAst recursion RangeError aborts Phase-0 recon** — [worker/analyzers.ts#L169](../worker/analyzers.ts#L169)
  - Recon loss only. Folded into the R2-H-23 fix.
- **kovo_verify `scriptPath` reads worker-excluded files on the host and stderr echoes them** — [exec-verify.ts#L2053](../src/server/exec-verify.ts#L2053)
  - Rated medium. Same sensitive-file policy gap as the H-39 sibling walker. Should be re-reviewed.
- **codeLocations steer patch author and reviewer to read sensitive repo files into LLM prompts** — [patch-workflow.ts#L696](../src/server/patch-workflow.ts#L696)
  - Rated medium: patch flow only, operator-initiated.

### Low

- **Tier-3 approval consumed before header validation** — [request-admission.ts#L1528](../src/server/request-admission.ts#L1528)
  - Burns one approval. No bypass.
- **async.awaitResult sends up to maxAttempts requests; only the last is in the transcript** — [verify-rpc.ts#L1926](../src/server/verify-rpc.ts#L1926)
  - Bounded by attempts and admission.
- **Scope-review UI and server auto-admit use different anchors** — [consent.tsx#L93](../src/components/run/views/consent.tsx#L93)
  - Root of R2-H-5. This lens rated it medium.
- **Wildcard-DNS apexes auto-admit names that resolve only by wildcard** — [subdomain-discovery.ts#L678](../src/server/subdomain-discovery.ts#L678)
  - Needs wildcard zones. Covered by C-2 step 6.
- **`cross_surface_pivot` correlationToken substring match** — [v8-oracle-hydrate.ts#L604](../src/server/v8-oracle-hydrate.ts#L604)
  - Covered by C-4 step 6.
- **`prove.persistedMutation` evaluates with worker requiredRole and events (no factLog)** — [verify-prove-handlers.ts#L347](../src/server/verify-prove-handlers.ts#L347)
  - Advisory only. The kernel decides.
- **Global reset clears tenant trips** — [kill-switch.ts#L513](../src/server/kill-switch.ts#L513)
  - Inside H-2. Operator-only.
- **Cross-instance persistence is last-writer-wins** — [kill-switch.ts#L385](../src/server/kill-switch.ts#L385)
  - Needs two servers on one data directory.
- **Broker-side authorizeStateChange checks non-overridable reasons without headers** — [request-admission.ts#L1517](../src/server/request-admission.ts#L1517)
  - Needs a matching operator pattern. Part of H-4.
- **Ledger fingerprint omits compression and headers** — [approval-judge.ts#L237](../src/server/approval-judge.ts#L237)
  - Same as above.
- **Model-boundary scrub copies persona secrets at session start** — [agent-session.ts#L2949](../src/server/agent-session.ts#L2949)
  - Exact secrets rotate rarely. Part of H-8.
- **Tool handlers return the raw result inline next to the sanitized artifact** — [exec-worker-runner.ts#L937](../src/server/exec-worker-runner.ts#L937)
  - The broker body is already redacted. Part of H-8.
- **Receipt builder uses worker-sanitized bodies** — [agent-script-proof.ts#L168](../src/server/agent-script-proof.ts#L168)
  - Mostly refuted: the factLog uses raw bodies. Small recall loss.
- **Same-value re-seal reattributes emission** — [verify-rpc.ts#L920](../src/server/verify-rpc.ts#L920)
  - Immutability holds. Attribution edge case.
- **Agent-script reverify confirms without a class-identity check** — [exec-verify.ts#L2663](../src/server/exec-verify.ts#L2663)
  - Covered by H-18 step 6.
- **Confirmation headline is free model text** — [exec-verify.ts#L2307](../src/server/exec-verify.ts#L2307)
  - Covered by H-18.
- **Confirmed origin bound to `spec.origin`** — [floor-recipe-engine.ts#L3637](../src/server/floor-recipe-engine.ts#L3637)
  - The endpoint-binding guard already rejects mismatches.
- **persistReplayConfirmation re-binds the title without secrets** — [exec-verify.ts#L1639](../src/server/exec-verify.ts#L1639)
  - A secret in the title is rare.
- **OOB carrier echo (duplicate candidate)** — [proof-receipt.ts#L2218](../src/server/proof-receipt.ts#L2218)
  - This lens rated it low. The kept candidate is R2-H-11.
- **Out-of-scope denial on a grant without runId purges every run's cookies** — [broker.ts#L2359](../src/server/broker.ts#L2359)
  - Every production grant has a runId. Lab-only.
- **Warm-pool epoch reads persona generation without runId** — [exec-worker-runner.ts#L588](../src/server/exec-worker-runner.ts#L588)
  - Perf/rotation only. No credentials.
- **Worker no-token watchdog cuts the first-event window and aborts the assignment** — [exec-worker-runner.ts#L646](../src/server/exec-worker-runner.ts#L646)
  - Reliability tuning.
- **Manual lab-start action caps build at 120 s** — [actions.ts#L644](../src/actions.ts#L644)
  - UX only.
- **Persona refresh failures swallowed indefinitely** — [persona-auth.ts#L3402](../src/server/persona-auth.ts#L3402)
  - Reporting gap.
- **wake() has no top-level guard; sync finalize rethrows storage errors** — [oob-drain.ts#L178](../src/server/oob-drain.ts#L178)
  - Needs a non-race SQLite fault.
- **Retest jobs run unsupervised; their catch writes to a deleted run** — [execution.ts#L4048](../src/server/execution.ts#L4048)
  - The process guard swallows it.
- **unhandledRejection guard drops non-abort rejections silently** — [run-actor.ts#L587](../src/server/run-actor.ts#L587)
  - Observability only.
- **Trace, telemetry and brief JWT regexes quadratic** — [agent-trace.ts#L68](../src/server/agent-trace.ts#L68)
  - Small inputs only.
- **Compose file read fully before the size check** — [lab-runner.ts#L909](../src/server/lab-runner.ts#L909)
  - Repo file read into memory, then rejected by the parser.

## Fix plan — ordered

Each workstream owns a disjoint set of files: one writer per file, as AGENTS.md requires. Workstreams are ordered by risk reduction per unit of effort. Every stream runs `scripts/worker-gate.sh` before handoff and commits a WIP checkpoint at least every 15 minutes.

**Parallelism.** Streams with no file overlap can run in parallel. The table marks the few handoffs that force serialization. The waves are:

- **Wave 1:** WS-1 through WS-6.
- **Wave 2:** WS-7 through WS-14.
- **Wave 3:** WS-15 through WS-20.

| # | Workstream | Closes | Files owned (exclusive) | Regression tests | Effort | Parallel? |
|---|---|---|---|---|---|---|
| WS-1 | Lab container argv and compose hardening | R2-C-1; H-37 and H-38 debt; M-9 (`--pull never`) | `src/server/lab-proxy.ts`, `src/server/lab-runner.ts`, `src/server/compose-parse.ts` | leading-dash image rejected; `--` before the image in every lab argv; copied host env never resolves; byte budget on interpolation | S | yes |
| WS-2 | Host object safety and process flags | R2-C-2; H-32 backstop (V8 linear-regexp fallback flag and startup self-check) | `src/server/probes/context.ts`, `src/server/probes/mass-assignment.ts`, `src/server/surface-engine.ts`, `scripts/serve.ts`, `scripts/cli.ts`, `Dockerfile` | prototype accessor segments in every location leave `({}).x` undefined; frozen prototype at boot; exponential probe under 50 ms with flags | S | yes |
| WS-3 | Verify-RPC custody (worker oracles) | C-3, R2-C-3 (RPC side: coarse verdict, budget), R2-C-4, R2-H-4, R2-C-9 / H-9 (kernel request plane), R2-H-8, C-1 (verify-rpc side), H-6/H-20 artifact signing, R2-H-27 (allow-list `op` before the message) | `src/server/verify-rpc.ts`, `src/server/derived-custody.ts` | `c3-seal-oracle-r2`, `h9-request-plane-kernel-truth`, hmacSign returns a handle not a signature, preview never exposes a secret prefix, capability actor labelling | L | yes (hands kernel-plane field names to WS-5) |
| WS-4 | Oracle invariants | R2-C-5, R2-C-7 / C-6, C-7 (truth parser, triangle), R2-H-10 / H-16, R2-H-12 / H-17, R2-H-26, H-14/H-15 shared helpers | `src/server/oracle-invariants.ts`, `src/server/safe-regex.ts` | markup needs a nonce plus control absence; C-6 r2 matrix; H-16 r2 echo matrix; H-17 fingerprints; credential pattern ReDoS corpus | L | yes |
| WS-5 | Receipt kernel and host fact log | R2-C-6, C-5, C-7 (receipt side), R2-H-11 / H-6, H-13, H-14, H-15, R2-H-13, C-8 (kernel attestation), H-20 builder | `src/server/proof-receipt.ts`, `src/server/terminal-oracle-registry.ts`, `src/server/host-fact-log.ts` | evaluated-expression rejects worker markers; c5-r2, h14 wire provenance, h15-r2 timing identity, redirect binding, oob carrier binding | L | after WS-3 field handoff for the fact log |
| WS-6 | Composite kernel | R2-C-8 / C-4, R2-C-3 (matcher), R2-H-6, R2-H-7 / H-12, H-11 (kernel side), H-10 residual | `src/server/composite-receipt.ts`, `src/server/v8-oracle-hydrate.ts`, `src/server/v8-oracle-families.ts` | C-4r2 role and selector cases, h12-r2 class contract, h11-r2 provenance, correlation equality only | L | yes |
| WS-7 | Provider pool key isolation | R2-H-2, H-25 (exact-only redaction for executable args), H-8 (live model scrub) | `src/server/provider.ts`, `src/server/provider-stream.ts`, `src/server/agent-session.ts` | two-profile key isolation; executable-args round-trip; live scrub picks up late secrets | S | yes |
| WS-8 | Admission and approval | R2-H-1, H-3, H-4 (classification, fingerprint, UI) | `src/server/request-admission.ts`, `src/server/scope-policy.ts`, `src/server/approval-judge.ts`, `src/server/tier3-approval.ts`, `src/components/run/views/queue-read.tsx` | override carriers structural; derived staging does not auto-approve; H-3 r2; h4-batch-approval-r2 | M | yes (run-actor changes for H-4 go to WS-14) |
| WS-9 | Persona credentials | R2-H-3, H-23, H-2 (refresher gating), R2-H-23 (persona JWT regex) | `src/server/persona-auth.ts`, `src/server/session-isolation.ts`, `src/server/persona-vault.ts`, `src/server/worker-session-reader.ts` | Supabase origin only from loginUrl or allowlist; h23-session-lifecycle; refresher silent after trip | M | yes |
| WS-10 | Broker and egress transport | C-1 (`executeHttp2Exchange`), R2-H-19, H-14 (wire credential provenance), H-2 (`EgressGateway` kill-switch tenant) | `src/server/broker.ts`, `src/server/egress-gateway.ts`, `src/server/transport.ts` | c1-h2-broker-controls; compressed truncated body settles and releases its slot; burst lock owner TTL | M | yes (exports provenance types consumed by WS-3 and WS-5) |
| WS-11 | Redaction primitives | R2-H-27, R2-H-28, H-8 needle cache | `src/server/redact.ts`, `src/server/egress-sanitizer.ts` | PEM linear on 4 MiB; sanitize at 5000 secrets under 50 ms; encoding-variant parity | S | yes |
| WS-12 | Claims layer and prove handlers | H-32 claim/async/seal callers, R2-H-29, C-5 (`prove.race`), C-7 (`handleProveDifferential`), H-16 (stripped helper), H-13 (drop declared fallbacks) | `src/server/verify-claims.ts`, `src/server/verify-runner.ts`, `src/server/verify-prove-handlers.ts`, `src/server/verify-support.ts` | normalizers linear on 512 KiB; prove.race ignores arg IDs; structural_diff not counted as injection | M | after WS-4 helper exports |
| WS-13 | Floor/replay engine | R2-H-15 / H-19 health classifier, R2-H-9, R2-H-14 / H-18 class selection, H-5, H-32 (runnerExtractVariables), H-17 planner | `src/server/floor-recipe-engine.ts`, `src/server/floor-recipes.ts`, `src/server/replay-verifier.ts`, `src/replay-spec.ts` | retest health matrix; spec events never trusted; keyword conflict fails closed; envelope default-deny | M | yes |
| WS-14 | Run lifecycle and approvals | R2-H-17, R2-H-18 / H-28, H-27, H-2 (onChange pause), H-4 (combine), H-23 (retest session bootstrap call site) | `src/server/run-actor.ts`, `src/server/run-context.ts`, `src/server/execution.ts`, `src/server/kill-switch.ts`, `src/server/oob-drain.ts` | trip then reset resumes; drain-window dispatch has no orphan; H-28b to H-28e; kill-switch lifecycle | L | yes (serialize with WS-19 on `store-runs.ts` `recover()`) |
| WS-15 | Exec persistence and finding identity | R2-H-16, H-18 (handler guard, binding), H-11 (wire compositeVerifyOptions), R2-H-22 (RPC hostDir in scratch), H-6/H-20 drain | `src/server/exec-verify.ts`, `src/server/exec-worker-runner.ts`, `src/server/agent-script-proof.ts`, `src/server/store-findings.ts` | script sha integrity; h18-confirmed-identity; DooD RPC mount; options wiring spy | M | yes |
| WS-16 | Subdomain scope | R2-H-5 / C-2 | `src/server/subdomain-discovery.ts`, `src/server/exec-recon-planner.ts`, `src/server/store-runs.ts`, `src/components/run/views/consent.tsx` | C-2b anchor and declined-set tests | M | yes (hands `recover()` edit slot to WS-14) |
| WS-17 | Browser pool | R2-H-20 / H-24, H-8 (placeholders), C-8 (producer and isolated-world callback) | `src/server/scoped-browser.ts` | h24 concurrency; no raw secrets in the page; DOM exec attestation | L | yes |
| WS-18 | Worker containers (DooD) | R2-H-21, H-31 | `src/server/worker-backend.ts`, `src/server/container-supervisor.ts` | unique staging per prepare; foreign-namespace sweep | S | yes |
| WS-19 | Host parsers off the main thread | R2-H-23 / H-35, R2-H-24 / H-33, R2-H-25 / H-36, R2-C-2 (recon name filter) | `src/server/program-graph.ts`, `worker/analyzers.ts`, `src/server/phase0-recon.ts`, `src/server/static-workspace-snapshot.ts`, `src/server/untrusted-compute-pool.ts`, `src/server/parser-worker-entry.ts` | t4-jsharvest-isolation; H-33 and H-36 variant budgets; lag probe under 200 ms | L | yes |
| WS-20 | Invariants and docs | ARCHITECTURE.md I3, I6, I7 and §5 statements; AST lints (no non-literal RegExp, no direct EgressGateway in verify-rpc) | `ARCHITECTURE.md`, `scripts/worker-gate.sh`, `tests/contracts/*` (new) | lint contracts | S | after streams land |

**Merge order and serialization exceptions:**

1. WS-1 and WS-2 merge first. They are small and close the two host-compromise criticals.
2. WS-3, WS-4 and WS-6 next. They close the worker oracles and forged-confirmation criticals.
3. WS-5 lands after WS-3, because WS-3 defines the kernel request-plane and credential-provenance fields that `host-fact-log.ts` consumes.
4. WS-12 consumes helpers exported by WS-4.
5. `store-runs.ts` has one writer, WS-16. WS-14's `recover()` change is handed off to it, or done in WS-16 with WS-14's spec.
6. Re-run the smoke tier after each merge.
7. Run `reverify-v5.sh --full` once after wave 2, because the kernel tightening will move precision and recall numbers.
