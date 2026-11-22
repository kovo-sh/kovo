# Guardian v4 / M7 — Release Verification

**Date:** 2026-11-22  
**Spec:** [SPEC-v4.md](SPEC-v4.md)  
**Code base:** Guardian `main` @ `0ab0589` (final M7: v4 engine + merged held-out2 climb + v5 roadmap). Final benchmark artifacts: `iter3-merged` (00:28) and `heldout-merged` (00:31).

**Purpose:** release evidence for Guardian v4 / M7. Every number below is either re-derived from a preserved structured artifact or explicitly marked as copied from the M7 gate run. Provenance is listed in [Appendix D](#appendix-d--number-provenance).

> **Final M7 result:** XBEN-25 **25/25 (100%)**, held-out SaaS **20/20 (100%)** with **0/6 decoy FPs** and **20/20 patches fixed**. The one open caveat is the batched `allPatches=regressed` phantom (§4.3); per-patch retest is the evidence-honest number. Realistic-bench recall is unchanged from the v4 baseline and remains low (**0/172 dev**, **3/171 held-out**); see §5 and §9.

---

## 1. Scope and what “v4” means

Guardian v4 is the M1–M7 line: a stateful broker, offline worker, Phase-0 recon, multi-container lab execution, benchmark harness, and a release gate. “v4” is not a new scanning model; it is the v4 schema, probe/spec surface, and verification pipeline stacked on the v3 Zero-LLM confirmation boundary.

| Milestone | Delivered capability | Primary commit |
| :--- | :--- | :--- |
| M1 | v4 SQLite schema and lossless v2/v3→v4 migration; inline `verify_replay_spec`; role-affinity routing | `c00c8c4` |
| M2 | Stateful broker session jars, CSRF binding, JWT mutation probes, persistent browser, 7 parameter encodings | `c00c8c4` |
| M3 | Offline `guardian-worker:v4`, semantic audit, 1,600 transpiled templates | `c00c8c4` |
| M4 | Phase-0 recon, state graph, specialists, multi-trial branching | `aefa0e2` |
| M5 | Multi-container `LabRunner`, opt-in IAST, v4 UI | `c00c8c4` |
| M6 | Recall harness, XBEN-25 dev suite, held-out SaaS lab + patch retest | `233826e`, `5ff4305`, `b07ea84` |
| M7 | Full gate, discovery/spec integration, recall hill-climbing, held-out climb, realistic-bench | `25e1e82`, `a61738e`, `ca992f6`, `55f701e`, `ef4e711`, `c345f46`, `ee0ae70`, `39cb0db`, `0ab0589` |

**“Confirmed” in this document** always means a Zero-LLM replay verification (`ReplayVerifier` under `local-jq` or the Docker worker) reached `confirmed` / `runtime_confirmed`. LLM output is a hypothesis only. No LLM vote is counted as a finding.

Three evaluation surfaces are reported separately and are **not** comparable to each other:

| Surface | Purpose | Size |
| :--- | :--- | :--- |
| `xben-25` dev suite | Recall hill-climbing on the fixed dev corpus | 25 targets, 0 decoys |
| `local-lab/held-out-saas` | Anti-overfitting + patch retest | 20 vulns + 6 hard decoys |
| `benchmarks/realistic-bench` | XBEN-style multi-tenant realism, dev and salted held-out seeds | 3 apps, 78 sites, 6–8 decoys per seed |

---

## 2. Build and test gate

### 2.1 Non-Docker gate — 519 / 519 measured, 532 on the final tree

| Gate | Command | Pass | Fail / skip | Source |
| :--- | :--- | ---: | ---: | :--- |
| TypeScript typecheck | `npm run check` | 0 errors | 0 / 0 | Re-run on final tree |
| Production build | `npm run build` | client + SSR built | 0 / 0 | Re-run on final tree |
| v2/v3 core boundary suite | `npm run test:boundaries` | **46 / 46** | 0 / 0 | Gate log `boundaries-merged.log` |
| v3 + v3-protocol + v4 boundary suites | `node --test tests/v3-boundaries.test.ts tests/v3-protocol-browser.test.ts tests/v4-boundaries.test.ts` | **26 / 26** | 0 / 0 | Gate log `v34-merged.log` |
| v4 milestone suites M1–M6 | `node --test tests/v4-m1-*.test.ts … tests/v4-m6-*.test.ts` | **71 / 71** | 0 / 0 | Gate log `m-all-merged.log` |
| v4 M7 suites at gate time | `node --test tests/v4-m7-discovery.test.ts tests/v4-m7-heldout.test.ts tests/v4-m7-specs.test.ts` | **46 / 46** | 0 / 0 | Gate log / re-run |
| v4 tiered E2E matrix | `node --test --test-concurrency=1 tests/v4-e2e-tiers.test.ts` | **322 / 322** | 0 / 0 | Gate log `v4-e2e-tiers-merged2.log` |
| Playwright UI E2E (v2 + v4) | `npx playwright test` | **8 / 8** | 0 / 0 | Gate log `playwright-merged3.log` |
| **Measured release gate** | | **519 / 519** | **0 / 0** | 46+26+71+46+322+8 |
| Post-gate M7 additions (heldout2, probes2) | `node --test tests/v4-m7-heldout2.test.ts tests/v4-m7-probes2.test.ts` | **13 / 13** | 0 / 0 | Re-run on final tree |
| **Current tree total** | | **532 / 532** | **0 / 0** | 519 + 13 |

Duration of the 322-case tier matrix: 254.7 s. Playwright: 12.6 s, 8 workers. The 519 gate is the measured sum above and is reproducible from the preserved logs. The final tree adds 13 M7 tests from the merged held-out2 stream; those passed 59/59 in a re-run (46 + 13). A full 532-case gate has not been re-run as one pass.

### 2.2 Docker gate — 108 / 108 (reported)

| Gate | Pass | Source |
| :--- | ---: | :--- |
| Docker-required suite run A | **72 / 72** | M7 gate report |
| Docker-required suite run B | **36 / 36** | M7 gate report |
| Worker image | `guardian-worker:v4` / `:local`, **6.08 GB** | M7 gate report |
| Orphan containers / networks after gate | **0 / 0** | M7 gate report |

The docs session could not re-run Docker-daemon checks (`/var/run/docker.sock` is root:docker; the docs user is not in `docker` and `sudo` requires a password). These four rows are **copied**, not re-derived. The Docker gate commit is `55f701e`.

### 2.3 Benchmark harness self-tests

| Gate | Command | Pass | Source |
| :--- | :--- | ---: | :--- |
| realistic-bench tests | `GUARDIAN_ALLOW_LOCAL_LAB=1 node --test --test-concurrency=1 benchmarks/realistic-bench/tests/` | **142 / 142** | Re-run on final tree |
| realistic-bench typecheck | `tsc -p benchmarks/realistic-bench/tsconfig.json` | 0 errors | Re-run 2026-11-22 |

The harness grew from 114 to 142 tests with the decoy-audit, grader-soundness, and held-out-integrity suites (`55d33ac` / merge `ef2b4cf`). All 142 pass.

---

## 3. Recall hill-climbing on `xben-25`

Five measured iterations, same 25-target dev suite. Funnel stages are monotonic per target: surface → hypothesis → signal → spec → Zero-LLM confirmed.

| Iteration | Code state | Profile | Surface | Hypothesis | Signal | Spec | Confirmed | Recall | FP | Requests | Runtime |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- | ---: |
| `iter0-v3` | v3 baseline | `v3-baseline` | 3 | 2 | 1 | 0 | **0** | **0%** | 0 | n/r | 12.4 s |
| `iter0-v4` | M1–M5 core | `v4-full` | 25 | 18 | 15 | 2 | **2** | **8%** | 0 | n/r | 46.0 s |
| `iter1-specs` | `a61738e` | `v4-full` | 25 | 20 | 16 | 13 | **13** | **52%** | 0 | n/r | 61.6 s |
| `iter2-integrated` | `ca992f6` | `v4-full` | 25 | 25 | 25 | 23 | **23** | **92%** | 0 | 3,168 / 3,800 | 90.6 s |
| `iter3-merged` | `39cb0db` (held-out2) | `v4-full` | 25 | 25 | 25 | 25 | **25** | **100%** | 0 | 3,170 / 3,800 | 118.5 s |

`n/r` = request count was not recorded by the harness at that iteration; the “requests used” note was added after `iter1` (commit `c2fbc43`).

### 3.1 Per-iteration failure taxonomy

| Iteration | replay_spec_miss | hypothesis_miss | trigger_miss | surface_miss | csrf_blocked |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `iter0-v3` | 1 | 1 | 1 | 22 | 0 |
| `iter0-v4` | 13 | 7 | 2 | 0 | 1 |
| `iter1-specs` | 3 | 5 | 3 | 0 | 1 |
| `iter2-integrated` | 2 | 0 | 0 | 0 | 0 |
| `iter3-merged` | 0 | 0 | 0 | 0 | 0 |

### 3.2 What caused each jump

**0 → 2 (`iter0-v3` → `iter0-v4`).** The v3-baseline profile reached only 3 of 25 surfaces (22 `surface_miss`). The v4-full profile reached 25/25 surfaces and formed 18 hypotheses, but the synthesizer only knew a few signal classes, so 15 observed signals produced 2 specs (13 `replay_spec_miss`). The jump is a surface/discovery gain, not a confirmation gain.

**2 → 13 (`iter0-v4` → `iter1-specs`).** Commit `a61738e` generalized replay-spec synthesis to every observed signal class (interim `b5da96c` reached 11/25; the merged `5df43b1` recorded 13/25). Spec submissions rose 2 → 13 with no new scanning capability, and no new false positives. Remaining misses moved to hypothesis (5), trigger (3), CSRF (1), and 3 spec gaps.

**13 → 23 (`iter1-specs` → `iter2-integrated`).** Discovery commit `25e1e82` closed the hypothesis/trigger gaps generically; corpus-context and integration work (`02ffddb`, `e39b33c`, `ca992f6`, `c38042f`) converted every remaining observed signal. Endpoints 36 → 37, hypotheses 114 → 146, signals 16 → 25, specs 13 → 23. Only two spec gaps remained.

**23 → 25 (`iter2-integrated` → `iter3-merged`).** The held-out2 climb (`ee0ae70`, merged in `39cb0db`) added the missing probe/spec classes rather than route-specific exceptions. `xben-22` (path traversal) now converts its existing normalization signal into a spec. `xben-25` (RCE) moves from the traversal probe to a `command_injection` probe and confirms through command execution evidence. Hypothesis count falls 146 → 114 because noisy, non-converting hypotheses were pruned; every remaining hypothesis produced a signal and a spec. Zero failure buckets remain.

### 3.3 Previously remaining misses, now confirmed

| Target | Class | Probe class at `iter2` | Probe class at `iter3` | Reading |
| :--- | :--- | :--- | :--- | :--- |
| `xben-22` | `path_traversal` | `path_traversal_benign` (spec miss) | `path_traversal_benign` (confirmed) | Same signal; the missing spec class was added. |
| `xben-25` | `rce` | `path_traversal_benign` (spec miss) | `command_injection` (confirmed) | A command-execution probe now covers the challenge; confirmation is via execution evidence, not a rename. |

No target-specific hardcoding was introduced: both changes are generic probe/spec classes and are exercised by the M7 unit suites.

---

## 4. Held-out anti-overfitting (`local-lab/held-out-saas`)

20 planted High/Critical vulns + 6 hard decoys, run with the same engine that scored 25/25 on the dev corpus. 46 endpoints, 133 hypotheses, 3,542 / 3,800 requests, 222.4 s.

| Metric | Result |
| :--- | ---: |
| Confirmed | **20 / 20 (100%)** |
| Decoy false positives | **0 / 6** |
| Surface discovered | 20 / 20 |
| Hypothesis formed | 20 / 20 |
| Signal observed | 20 / 20 |
| Spec submitted | 20 / 20 |
| Precision (submitted findings) | 1.00 |

### 4.1 Previously blocked targets, now confirmed

The ten misses in the earlier held-out run are all confirmed in `heldout-merged`. The probes are general classes, not per-target routes.

| Target | Class | Old blocker | Probe now used |
| :--- | :--- | :--- | :--- |
| `hos-01` | BOLA | `trigger_miss` | `authz_matrix` |
| `hos-03` | BFLA | `hypothesis_miss` | `authz_matrix` |
| `hos-05` | server-action authz | `surface_miss` | `authz_matrix` |
| `hos-08` | time-blind SQLi | `trigger_miss` | `sqli_time_diff` |
| `hos-13` | workflow skip | `trigger_miss` | `workflow_invariant` |
| `hos-14` | race condition | `hypothesis_miss` | `race_burst` |
| `hos-15` | second-order XSS | `trigger_miss` | `xss_context` |
| `hos-16` | second-order SSRF | `hypothesis_miss` | `ssrf_canary` |
| `hos-18` | DOM XSS | `trigger_miss` | `xss_context` |
| `hos-20` | path traversal | `trigger_miss` | `path_traversal_benign` |

The expansion is probe/spec coverage (`ee0ae70`: IDs, state, race, second-order, BFLA), not benchmark-specific payloads.

### 4.2 Patch retest — 20 attempted / 20 reproduced / 20 fixed

| Goal (`HANDOVER-v4.md` §3.3) | Actual |
| :--- | :--- |
| `>= 18/20` confirmed | **20/20** — met |
| `0/6` decoy FPs | **0/6** — met |
| `>= 14/20` verified patches | **20/20** — met |
| Per-patch isolation preserved | **20/20 at 4/4 checks** |

| Outcome after patch | Targets | Notes |
| :--- | :--- | :--- |
| `dismissed` (18) | `hos-01`, `hos-02`, `hos-03`, `hos-05`, `hos-06`, `hos-07`, `hos-08`, `hos-09`, `hos-10`, `hos-11`, `hos-12`, `hos-13`, `hos-14`, `hos-15`, `hos-16`, `hos-18`, `hos-19`, `hos-20` | Replay no longer confirms; isolation 4/4. |
| `inconclusive` (2) | `hos-04`, `hos-17` | Counted as fixed by the harness because the vuln no longer confirms; isolation 4/4. |

**“Fixed” semantics:** 20/20 is the harness count. It includes `hos-04` and `hos-17`, whose patched retest is `inconclusive` rather than a clean `dismissed`. If a release needs “clean dismissal only”, the number is **18/20**. No patch reintroduced a decoy false positive.

### 4.3 `allPatches=regressed` is a known phantom

The batched artifact still says `verdict: "regressed"`, with `stillConfirming: ["hos-02", "hos-09"]`, `newlyConfirming: []`, and decoy FPs `0/0`. This is not evidence that the fixes failed:

- Fresh synthesis during the all-patches pass re-confirms always-on GraphQL introspection and credits it to both GraphQL challenges. Both IDs share the `/graphql` surface, so the batched run attributes one always-on observation twice.
- Per-patch retest is the evidence-honest measure: each of the 20 patches was applied in isolation, and all 20 suppressed their own confirmation with 4/4 isolation.
- The orchestration owner is fixing the all-patches pass to replay baseline attributed specs instead of re-synthesizing, which should remove the phantom. Until that lands, do not use the batched verdict as a regression signal.

**Residual caveat kept:** per-patch fixed 20/20 and clean-dismissed 18/20 are both reported; the document does not collapse them.

---

## 5. Realistic-bench (XBEN-style)

> **Baseline status:** the numbers in this section are the **v4 engine baseline**, unchanged by the held-out2 climb, which targeted the XBEN/held-out lab suites. The v5 targets for this benchmark (M0 harness, M6 recall/gap) live in [`plans/ROADMAP-v5.md`](plans/ROADMAP-v5.md). They are goals, not results.

### 5.1 Design

`benchmarks/realistic-bench` is a loopback-only benchmark built to test recall and precision against multi-tenant applications rather than single-bug CTF apps.

| Property | Implementation |
| :--- | :--- |
| Apps | 3: `acme-saas` (28 sites), `shopflow` (26), `opsportal` (24) = **78 sites** |
| Planted sites | 24–28 per app; some vulnerable, some hardened per seed |
| Decoys | 6–8 hard decoys per seed, graded like bugs |
| Grading | Impact oracle: a finding counts only if an attributed side-channel event fired at or before submission; matching a decoy is always a false positive |
| Variants | Per-seed randomization of API prefix, route nouns, parameter names, id format, personas, canary salt, and vulnerable/decoy assignment |
| Held-out | Seeds `>= 1_000_000` keyed by HMAC over `GUARDIAN_RB_HELDOUT_SALT`; dev seeds `1..9999` |
| Modes | `black-box`, `grey-box`, `white-box` (source tree with no truth/solver markers) |
| Metrics | 6-stage funnel, 11-bucket failure taxonomy, recall by severity/class, decoy FP rate, `precision = TP / (TP + decoyFP + unmatchedFP)`, chain completion, budget curves |
| Safety | Pure simulators for shell/SQL/file sinks; sockets bind `127.0.0.1` only; egress through a loopback allowlist; no `child_process`/`eval`/`vm` |

### 5.2 Measured results

All 18 runs used `v4-full`, `grey-box`, `local-jq`, seed set `1,2,42` (dev) and `1000001,1000002,1000042` (held-out).

**Dev matrix**

| App | Seed | Targets | Decoys | Confirmed | Decoy FP | Unmatched FP | Precision |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1 | 22 | 6 | 0 | 0 | 1 | 0 |
| acme-saas | 2 | 20 | 8 | 0 | 0 | 1 | 0 |
| acme-saas | 42 | 22 | 6 | 0 | 0 | 1 | 0 |
| opsportal | 1 | 18 | 6 | 0 | 0 | 3 | 0 |
| opsportal | 2 | 17 | 7 | 0 | 0 | 3 | 0 |
| opsportal | 42 | 16 | 8 | 0 | 0 | 3 | 0 |
| shopflow | 1 | 19 | 7 | 0 | 0 | 0 | 1 |
| shopflow | 2 | 20 | 6 | 0 | 0 | 0 | 1 |
| shopflow | 42 | 18 | 8 | 0 | 0 | 0 | 1 |
| **Total** | | **172** | **62** | **0** | **0** | **12** | **0** |

**Held-out matrix**

| App | Seed | Targets | Decoys | Confirmed | Decoy FP | Unmatched FP | Precision |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1000001 | 22 | 6 | 0 | 0 | 1 | 0 |
| acme-saas | 1000002 | 21 | 7 | 0 | 0 | 1 | 0 |
| acme-saas | 1000042 | 22 | 6 | 0 | 0 | 1 | 0 |
| opsportal | 1000001 | 16 | 8 | 0 | 0 | 3 | 0 |
| opsportal | 1000002 | 16 | 8 | 0 | 0 | 3 | 0 |
| opsportal | 1000042 | 17 | 7 | **3** | 0 | 3 | 0.50 |
| shopflow | 1000001 | 18 | 8 | 0 | 0 | 0 | 1 |
| shopflow | 1000002 | 20 | 6 | 0 | 0 | 0 | 1 |
| shopflow | 1000042 | 19 | 7 | 0 | 0 | 0 | 1 |
| **Total** | | **171** | **63** | **3** | **0** | **12** | **0.20** |

Interpretation, without spin:

- **Engine recall on this benchmark is low:** 0/172 on dev, 3/171 held-out (1.8%). The single held-out hit set is `opsportal` seed `1000042` with 3/17 (17.6%); every other run confirmed 0.
- **Decoy precision is clean:** 0 false positives across 125 decoy sites.
- **Overall precision is not clean:** every emitted finding is CWE-639 cross-actor access; 12 per split are unmatched. Under the benchmark’s own rule they are false positives, so dev precision is 0 and held-out precision is 0.20. “0 decoy FPs” is true but is not the whole precision story.
- **Chain completion is 0/1 in all 18 runs.** No end-to-end chain was completed on this benchmark.

### 5.3 Diagnosed bottleneck

Aggregate 6-stage funnel:

| Stage | Dev (172) | Held-out (171) |
| :--- | ---: | ---: |
| Surface discovered | 131 (76%) | 130 (76%) |
| Hypothesis formed | 131 | 130 |
| Signal observed | **10 (5.8%)** | **14 (8.2%)** |
| Spec submitted | 0 | 3 |
| Zero-LLM confirmed | 0 | 3 |

Aggregate failure buckets:

| Bucket | Dev | Held-out |
| :--- | ---: | ---: |
| `replay_spec_miss` (hypothesis formed, no signal/spec) | 116 | 114 |
| `surface_miss` | 33 | 37 |
| `budget_exhausted` | 17 | 11 |
| `csrf_blocked` | 3 | 3 |
| `form_encoding_missing` | 2 | 2 |
| `jq_assertion_bug` | 1 | 1 |

Discovery is not the primary limiter: it reaches 76% of planted sites on both splits, and hypothesis formation loses nothing after that. The collapse is **signal generation** — 131 surfaced/hypothesized sites produce 10 dev signals and 14 held-out signals. The dominant `replay_spec_miss` bucket is the classifier’s default for “hypothesis formed, probe produced no signal,” so it is a probe-trigger quality problem, not a spec-format problem. Secondary: 17 dev sites exhausted the request budget before a signal, and 3 sites were blocked by CSRF handling.

These are the v4 baseline numbers carried into v5. The v5 M0–M6 plan (real Execution harness, wiring, recon/auth, probes/verifiers, templates/AST/patch, Board, hill-climb gate) is in [`plans/ROADMAP-v5.md`](plans/ROADMAP-v5.md); its `≥65%` / `≥80%` recall targets are aspirational and are not claimed here.

---

## 6. Zero-trust and safety-boundary verification

| Boundary | Evidence (test) | Result |
| :--- | :--- | :--- |
| Loopback-only targets | `tests/v3-boundaries.test.ts` A2 (local-lab origin gate), `V4-B5` (`inhibit_ipv4`); `benchmarks/realistic-bench/tests/safety.test.ts` (“only safety.ts binds a socket, and only to 127.0.0.1”); `lib-egress.test.ts` (blocks every non-loopback host form and unregistered port) | PASS |
| Tier gating / non-destructive | `tests/v3-boundaries.test.ts` B2 (DELETE and multipart denied at Tiers 0–2, HITL at Tier 3); `tests/v4-boundaries.test.ts` V4-B4 (Tier-2 write allowlist defaults to `[]` on public); webshell and 256 KiB caps | PASS |
| CSRF and session isolation | `V4-B1` (origin/jar scoping, control vs probe isolation, purge on scope revocation, zero raw cookie leaks); `V4-B2` (JWT mutation redaction); CSRF jar-sharing fix `02ffddb` | PASS |
| Worker / lab sandbox | `tests/v3-boundaries.test.ts` A1 (`--network none`, read-only rootfs, cap-drop ALL, UID 10001, memory/PID limits), A2 (`--internal`, zero host ports, egress blocked); `V4-B5` (multi-service `--internal`, unsafe-directive rejection, zero orphans) | PASS |
| Canary / OOB | `tests/v3-boundaries.test.ts` B4 (dual HTTP + authoritative UDP DNS broker); M7 spec tests for `ssrf_canary`, `xxe_canary`, `jku_x5u_canary`; second-order canary ledger M2.11/M2.12 | PASS |
| Zero-LLM confirmation | `V4-B8` (rejects hardcoded nonces/LLM claims, caps retries, keeps `static_ast_proof` at `static_verified`); v3 B5; all benchmark confirmations used `local-jq` | PASS |
| Secret handling | `tests/v3-boundaries.test.ts` A5 (SARIF/exports: zero secret leaks), A6 (0600 persona enforcement); `V4-B2`/`V4-B6` redaction and IAST masking. No credential files are tracked (only synthetic test fixtures and secret-detection rules); the benchmark salt lives at `~/.config/guardian-bench/heldout.salt` (mode 600) and is never committed | PASS |
| Lab-only execution | `tests/v4-m7-heldout.test.ts` (refuses to run without `GUARDIAN_ALLOW_LOCAL_LAB=1`); realistic-bench requires the same gate and uses pure simulators for shell/SQL/file sinks | PASS |

---

## 7. Reproduction

### 7.1 Re-verify in one command

```bash
bash docs/reverify-v4.sh              # 524 node tests + 8 Playwright if Docker is reachable
bash docs/reverify-v4.sh --fast       # typecheck + build + 59 M7 suite tests (smoke)
bash docs/reverify-v4.sh --with-bench # also the 142 realistic-bench tests + typecheck
```

The full gate requires the Docker daemon and the `guardian-worker:v4` image; the script exits 2 with a message otherwise. `--fast` runs typecheck, build, and the 59 M7 tests without Docker. The script does not mutate source. The full total is 524 node tests plus 8 Playwright tests = **532**; the measured release gate before the held-out2 additions was 519.

### 7.2 Build and gate

```bash
cd <checkout>
npm ci
npm run worker:install                 # host deps for AST suites (@swc/core, acorn)
npm run worker:build                   # Docker required

NODE_OPTIONS=--max-old-space-size=1536 npm run check
NODE_OPTIONS=--max-old-space-size=1536 npm run build

GUARDIAN_ALLOW_LOCAL_LAB=1 npm run test:boundaries
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test tests/v3-boundaries.test.ts tests/v3-protocol-browser.test.ts tests/v4-boundaries.test.ts
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test tests/v4-m1-schema-verify-routing.test.ts tests/v4-m2-broker-browser-probes.test.ts \
  tests/v4-m3-worker-sast-templates.test.ts tests/v4-m4-surface-orchestration.test.ts \
  tests/v4-m5-lab-iast-ui.test.ts tests/v4-m6-benchmarks.test.ts
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test tests/v4-m7-discovery.test.ts tests/v4-m7-heldout.test.ts \
  tests/v4-m7-heldout2.test.ts tests/v4-m7-probes2.test.ts tests/v4-m7-specs.test.ts
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test --test-concurrency=1 tests/v4-e2e-tiers.test.ts
NODE_OPTIONS=--max-old-space-size=1536 npm run test:e2e

docker ps -aq --filter label=dev.guardian.assignment     # expect empty
docker ps -aq --filter label=dev.guardian.run            # expect empty
docker network ls -q --filter name=guardian              # expect empty
```

### 7.3 XBEN-25 hill-climbing

```bash
mkdir -p /tmp/guardian-m7-bench
NODE_OPTIONS=--max-old-space-size=1536 GUARDIAN_ALLOW_LOCAL_LAB=1 \
  npm run benchmark:recall -- --suite xben-25 --profile-mode v4-full \
  --verifier-backend local-jq --db /tmp/guardian-m7-bench \
  --git-sha iter3-merged --out-json /tmp/guardian-m7-bench/iter3-merged.json \
  --out-md /tmp/guardian-m7-bench/iter3-merged.md
```

Add `--baseline-sha <label>` and `--diff` to produce the per-iteration delta table. The suite is loopback-only; no external target is contacted.

### 7.4 Held-out SaaS + patch retest

```bash
NODE_OPTIONS=--max-old-space-size=1536 GUARDIAN_ALLOW_LOCAL_LAB=1 \
  npm run benchmark:recall -- --suite held-out-saas --profile-mode v4-full \
  --verifier-backend local-jq --verify-patches --db /tmp/guardian-m7-bench \
  --out-json /tmp/guardian-m7-bench/heldout-merged.json \
  --out-md /tmp/guardian-m7-bench/heldout-merged.md
```

### 7.5 realistic-bench dev matrix

```bash
export GUARDIAN_ALLOW_LOCAL_LAB=1
for app in acme-saas shopflow opsportal; do
  for seed in 1 2 42; do
    node benchmarks/realistic-bench/benchmark-realistic.ts \
      --app "$app" --seed "$seed" --split dev --profile-mode v4-full --mode grey-box --verifier local-jq \
      --out-json "/tmp/rb-score/$app-$seed.json" \
      --out-findings "/tmp/rb-score/$app-$seed.findings.json"
  done
done
```

### 7.6 realistic-bench held-out matrix

The salt is **never committed**. It lives at `~/.config/guardian-bench/heldout.salt` (owner-only, mode 600):

```bash
export GUARDIAN_ALLOW_LOCAL_LAB=1
export GUARDIAN_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"
for app in acme-saas shopflow opsportal; do
  for seed in 1000001 1000002 1000042; do
    node benchmarks/realistic-bench/benchmark-realistic.ts \
      --app "$app" --seed "$seed" --split heldout --profile-mode v4-full --mode grey-box --verifier local-jq \
      --out-json "/tmp/rb-score-heldout/$app-$seed.json" \
      --out-findings "/tmp/rb-score-heldout/$app-$seed.findings.json"
  done
done
```

Held-out seeds are refused without a salt of at least 16 characters.

---

## 8. Known limitations and next work

| Limitation | Evidence | Next work |
| :--- | :--- | :--- |
| Realistic-bench recall is the open v4 gap | 0/172 dev, 3/171 held-out; unchanged by held-out2 | v5 M0–M6: real Execution harness, trigger quality, recon/auth, probes/verifiers |
| Unmatched CWE-639 findings | 12 per split; dev precision 0, held-out 0.20 | Tighten cross-actor evidence: require impact-oracle-compatible row-level proof, not role-response diffs |
| Signal stage collapses | 10/131 dev, 14/130 held-out hypotheses produce a signal | Probe trigger coverage per encoding/method; inspect top `replay_spec_miss` sites |
| Budget exhaustion | 17 dev sites; runs used 3,168–3,560 of 3,800 | Raise or rebalance the request budget |
| `allPatches=regressed` phantom | batched pass leaves `hos-02`/`hos-09` confirming; per-patch is 20/20 with 4/4 isolation | Orchestration owner replays baseline attributed specs in the all-patches pass |
| “Fixed” counts inconclusive | `hos-04`, `hos-17` (clean dismissals: 18/20) | Require `dismissed` for a clean fix count; report inconclusive separately |
| XBEN and held-out labs are saturated | 25/25 and 20/20; no headroom to measure further gains | v5 M6 needs harder dev seeds and a fresh held-out set |
| Playwright parallel flake | `55f701e` raised the fail-closed alert wait to 15 s under parallel workers | Keep the 8-worker run; on failure re-run serially before triage |
| Cost is unmeasured | all runs used `local-jq`; `totalCostUsd = 0` | Run a live-provider pass to measure $/vuln and budget curves |
| Docker gate not re-derived | docs session lacks socket access | Re-run on a host in the `docker` group; verify 72/72, 36/36, 6.08 GB, 0 orphans |
| Final 532-case gate is assembled, not one run | 519 measured gate + 13 post-gate tests | Run `docs/reverify-v4.sh` on a Docker host for a single-pass 532 |
| Artifacts live under `/tmp` | `/tmp/guardian-m7-bench`, `/tmp/rb-score*` | Copy structured JSON into release storage before `/tmp` cleanup |

### 8.1 Discrepancy status

**Resolved in this revision:** held-out confirmed 10/20 → **20/20**; patches 9/20 → **20/20**; XBEN 23/25 → **25/25**; the `hos-09` isolation leak is gone (all 20 patches 4/4); the docs base is now `main` @ `0ab0589`.

**Still open:** `allPatches=regressed` phantom (per-patch is authoritative); “fixed” includes 2 inconclusive retests (clean dismissals 18/20); realistic-bench remains 0/172 dev and 3/171 held-out with 24 unmatched CWE-639 findings; Docker gate counts and image size remain copied; the 532 total is assembled from a 519 gate plus 13 post-gate tests.

---

## 9. Post-v4 / v5

v4/M7 is closed for the XBEN and held-out SaaS suites; realistic-bench is explicitly carried forward as the v5 baseline. The active plan is [`plans/ROADMAP-v5.md`](plans/ROADMAP-v5.md), with per-stream ownership and file leases in [`plans/message-board.md`](plans/message-board.md).

| v5 milestone | Workstream |
| :--- | :--- |
| **M0** | True E2E realistic-bench harness: drive the real `Execution` loop, baseline scorecard, `benchmark:realistic` CLI |
| **M1** | P0 wiring and correctness: broker/browser args, second-order/OOB canaries, dedupe/route templates, specialist routing, inline verify + Phase-3, guard/sanitizer, CVE semver |
| **M2** | State graph, recon, auth/session: endpoint params/dependencies, soft-404/auth recon, crawl, jars/CSRF/subdomain/401/circuit |
| **M3** | Real-world probes and verifiers: CSRF state-change, webhook forgery, open redirect, write-BOLA, race setup, noise normalization |
| **M4** | Templates, AST, SAST→DAST, Patch Gate 6: 2021–2026 corpus, multi-framework AST, bridge, real patch retest |
| **M5** | Swarm Message Board + Board UI: schema/store/SSE/UI, deterministic posters, warm specialists/handoffs |
| **M6** | Hill-climb + anti-overfitting + v5 gate: dev seeds, salted held-out, `VERIFICATION-v5.md` |

v5 targets are goals, not results: realistic-bench H/C recall `≥65%` grey-box / `≥80%` white-box with `≥95%` precision, held-out within 10% of dev.

---

## Appendix A — Commit list

| Commit | Role |
| :--- | :--- |
| `c00c8c4` | M1–M5 core, 1,600 compiled templates, v4 boundary/E2E suites |
| `aefa0e2` | M4 verification: specialists, GraphQL, LabRunner, crash-resume |
| `233826e` | M6 recall harness core, CLI, reporting, tests |
| `5ff4305` | M6 held-out SaaS lab (20 vulns + 6 decoys, patches) |
| `b07ea84` | M6 live pipeline circuit-breaker tuning |
| `25e1e82` | M7 discovery: hypothesis/trigger gap closure |
| `b5da96c` | M7B modular synthesis (interim 11/25) |
| `a61738e` | M7 spec synthesis for every observed signal class (13/25) |
| `c38042f` | Port spec builders into modular replay-spec architecture |
| `e39b33c` | Synthesis iteration: XML SQLi, CSRF priming, IDOR IDs, OAuth, XSS, cache |
| `02ffddb` | CSRF jar sharing, authz superset jq, reflected payload interpolation |
| `c2fbc43` | Report request-budget usage in live run notes |
| `ca992f6` | Integration iteration (23/25) |
| `55f701e` | Release gate: Playwright fail-closed timing |
| `ef4e711` | realistic-bench: 3 apps, 78 sites, impact oracle, seeds |
| `c345f46` | realistic-bench Guardian adapter, login bridge, scoring CLI |
| `c0acd90` | Parallel benchmark runner |
| `ee0ae70` | Held-out climb: generalized probes, spec synthesis, attribution |
| `55d33ac` | realistic-bench: harder decoys, grader accounting, held-out integrity |
| `7479a68` | Held-out probes: server-action/race scoping, stricter id segments |
| `39cb0db` | Merge heldout2: 20/20 held-out, 20/20 patches, 25/25 XBEN |
| `75c7db0` | Add v5 roadmap and ownership board |
| `ef2b4cf` | Merge realistic-bench hardening (142/142) |
| `9793d2d` | Per-origin budget for JS chunk harvesting |
| `0ab0589` | Record final v4 gates and phantom all-patches caveat |

## Appendix B — Test inventory

| File(s) | Tests |
| :--- | ---: |
| `tests/boundaries.test.ts`, `persona-login`, `approval-judge`, `report-comparison`, `provider-stream`, `v2-upgrades` | 46 |
| `tests/v3-boundaries.test.ts` | 14 |
| `tests/v3-protocol-browser.test.ts` | 4 |
| `tests/v4-boundaries.test.ts` | 8 |
| `tests/v4-e2e-tiers.test.ts` | 322 |
| `tests/v4-m1-schema-verify-routing.test.ts` | 15 |
| `tests/v4-m2-broker-browser-probes.test.ts` | 9 |
| `tests/v4-m3-worker-sast-templates.test.ts` | 15 |
| `tests/v4-m4-surface-orchestration.test.ts` | 10 |
| `tests/v4-m5-lab-iast-ui.test.ts` | 6 |
| `tests/v4-m6-benchmarks.test.ts` | 16 |
| `tests/v4-m7-discovery.test.ts` | 11 |
| `tests/v4-m7-heldout.test.ts` | 14 |
| `tests/v4-m7-heldout2.test.ts` | 10 |
| `tests/v4-m7-probes2.test.ts` | 3 |
| `tests/v4-m7-specs.test.ts` | 21 |
| `tests/guardian-v2.spec.ts` + `tests/guardian-v4.spec.ts` | 8 |
| **Measured gate (before held-out2 additions)** | **519** |
| **Current tree total** | **532** |
| `benchmarks/realistic-bench/tests/*.test.ts` (separate harness) | 142 |

## Appendix C — Artifact paths

| Artifact | Path |
| :--- | :--- |
| XBEN iterations | `/tmp/guardian-m7-bench/iter0-v3.json`, `iter0-v4.json`, `iter1-specs.json`, `iter2-integrated.json`, `iter3-merged.json` |
| Held-out + patches | `/tmp/guardian-m7-bench/heldout-final.json`, `heldout-merged.json` (+ `.md`) |
| Benchmark SQLite | `/tmp/guardian-m7-bench/guardian.sqlite` (`benchmark_runs`, 7 rows) |
| realistic-bench dev | `/tmp/rb-score/<app>-<seed>.json` and `.findings.json` |
| realistic-bench held-out | `/tmp/rb-score-heldout/<app>-<seed>.json` and `.findings.json` |
| Gate logs | `/tmp/opencode/m7-gate/{boundaries,v34,m-all,v4-e2e-tiers}-merged*.log`, `playwright-merged3.log` |
| v5 roadmap | `plans/ROADMAP-v5.md`, `plans/message-board.md` |
| Held-out salt | `~/.config/guardian-bench/heldout.salt` (mode 600; never commit) |

## Appendix D — Number provenance

| Number | Verified directly? | Method |
| :--- | :--- | :--- |
| 519 / 519 measured gate | Partially | 46/46, 26/26, 71/71, 322/322, 8/8 read from preserved gate summaries; 46/46 M7 and check/build re-run. Sum = 519 |
| 532 / 532 current tree | Partially | 519 measured + 13 new M7 tests (59/59 M7 re-run on final tree). No single 532 pass was run |
| 72/72, 36/36 Docker | No — copied | M7 gate report; Docker socket unavailable to this session |
| 6.08 GB worker image | No — copied | M7 gate report; no image-size evidence in preserved logs |
| 0 orphans | No — copied | M7 gate-time report |
| 142/142 realistic-bench | **Yes** | Re-ran suite on final tree; 142 pass, 0 fail, 0 skip |
| realistic-bench typecheck | **Yes** | `tsc -p benchmarks/realistic-bench/tsconfig.json` exit 0 |
| XBEN 0/2/13/23/25 | **Yes** | Parsed `funnelCounts`, `confirmedCount`, `failureTaxonomy` from the five JSON artifacts |
| 3,168 / 3,170 / 3,800 requests | **Yes** | `iter2-integrated.json`, `iter3-merged.json` `notes` |
| Held-out 20/20, 0/6 | **Yes** | Parsed `confirmedCount`, `perTarget` (20 confirmed + 6 `decoy_clean`) |
| Funnel 20/20/20/20/20/20 | **Yes** | `heldout-merged.json` `funnelCounts` |
| Patch 20/20, 20/20 isolation | **Yes** | Parsed `patchVerification.perPatch`: all 20 reproduced and fixed, every isolation 4/4 |
| `allPatches=regressed` phantom | **Yes** | Parsed `patchVerification.allPatches`: still `hos-02`/`hos-09`, no new confirmations, 0/0 decoy FPs |
| realistic-bench 0/172, 3/171, 0 decoy FPs | **Yes** | Summed all 18 scorecards; recomputed precision from `precision = TP/(TP+decoyFP+unmatchedFP)` |
| 12 unmatched findings per split | **Yes** | Summed `unmatchedFalsePositives`; inspected `.findings.json` (all CWE-639) |
| 3 apps / 78 sites | **Yes** | Counted site directories: 28 + 26 + 24 |
| 20 vulns + 6 decoys in held-out lab | **Yes** | `local-lab/held-out-saas/manifest.json`: 26 challenges, 6 flagged decoys |
| Salt path / mode | **Yes** | `stat` only; contents not read into this document |
