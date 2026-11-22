# Guardian v4 / M7 — Release Verification

**Date:** 2026-11-22  
**Spec:** [SPEC-v4.md](SPEC-v4.md)  
**Code base:** Guardian `main` @ `c345f46` (M1–M7 plus realistic-bench). `main` has since advanced to `c0acd90` (parallel benchmark runner only; no engine changes).  
**Purpose:** release evidence for Guardian v4 / M7. Every number below is either re-derived from a preserved structured artifact or explicitly marked as copied from the M7 gate run. Provenance is listed in [Appendix D](#appendix-d--number-provenance).

> **What is not claimed:** Guardian does not reach the M7 generalization targets in `HANDOVER-v4.md` §3.3. Held-out SaaS recall is **10/20 (50%)**, not `>=18/20`; verified patches are **9/20**, not `>=14/20`. Realistic-bench recall is **0/172 dev** and **3/171 held-out**. Section 5 and Section 8 state the bottleneck without adjustment.

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
| M7 | Full gate, discovery/spec integration, recall hill-climbing, realistic-bench | `25e1e82`, `a61738e`, `ca992f6`, `55f701e`, `ef4e711`, `c345f46` |

**“Confirmed” in this document** always means a Zero-LLM replay verification (`ReplayVerifier` under `local-jq` or the Docker worker) reached `confirmed` / `runtime_confirmed`. LLM output is a hypothesis only. No LLM vote is counted as a finding.

Three evaluation surfaces are reported separately and are **not** comparable to each other:

| Surface | Purpose | Size |
| :--- | :--- | :--- |
| `xben-25` dev suite | Recall hill-climbing on the fixed dev corpus | 25 targets, 0 decoys |
| `local-lab/held-out-saas` | Anti-overfitting + patch retest | 20 vulns + 6 hard decoys |
| `benchmarks/realistic-bench` | XBEN-style multi-tenant realism, dev and salted held-out seeds | 3 apps, 78 sites, 6–8 decoys per seed |

---

## 2. Build and test gate

### 2.1 Non-Docker gate — 519 / 519

| Gate | Command | Pass | Fail / skip | Source |
| :--- | :--- | ---: | ---: | :--- |
| TypeScript typecheck | `npm run check` | 0 errors | 0 / 0 | Re-run in docs worktree |
| Production build | `npm run build` | client + SSR built | 0 / 0 | Re-run in docs worktree |
| v2/v3 core boundary suite | `npm run test:boundaries` | **46 / 46** | 0 / 0 | Gate log `boundaries-merged.log` |
| v3 + v3-protocol + v4 boundary suites | `node --test tests/v3-boundaries.test.ts tests/v3-protocol-browser.test.ts tests/v4-boundaries.test.ts` | **26 / 26** | 0 / 0 | Gate log `v34-merged.log` |
| v4 milestone suites M1–M6 | `node --test tests/v4-m1-*.test.ts … tests/v4-m6-*.test.ts` | **71 / 71** | 0 / 0 | Gate log `m-all-merged.log` |
| v4 M7 suites (discovery, held-out, synthesis) | `node --test tests/v4-m7-*.test.ts` | **46 / 46** | 0 / 0 | Re-run in docs worktree |
| v4 tiered E2E matrix | `node --test --test-concurrency=1 tests/v4-e2e-tiers.test.ts` | **322 / 322** | 0 / 0 | Gate log `v4-e2e-tiers-merged2.log` |
| Playwright UI E2E (v2 + v4) | `npx playwright test` | **8 / 8** | 0 / 0 | Gate log `playwright-merged3.log` |
| **Total (non-Docker)** | | **519 / 519** | **0 / 0** | 46+26+71+46+322+8 |

Duration of the 322-case tier matrix: 254.7 s. Playwright: 12.6 s, 8 workers. The 519 figure is the sum above; it is reproducible from the preserved logs.

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
| realistic-bench tests | `GUARDIAN_ALLOW_LOCAL_LAB=1 node --test --test-concurrency=1 benchmarks/realistic-bench/tests/` | **114 / 114** | Re-run 2026-11-22 |
| realistic-bench typecheck | `tsc -p benchmarks/realistic-bench/tsconfig.json` | 0 errors | Re-run 2026-11-22 |

---

## 3. Recall hill-climbing on `xben-25`

Four measured iterations, same 25-target dev suite. Funnel stages are monotonic per target: surface → hypothesis → signal → spec → Zero-LLM confirmed.

| Iteration | Code state | Profile | Surface | Hypothesis | Signal | Spec | Confirmed | Recall | FP | Requests | Runtime |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- | ---: |
| `iter0-v3` | v3 baseline | `v3-baseline` | 3 | 2 | 1 | 0 | **0** | **0%** | 0 | n/r | 12.4 s |
| `iter0-v4` | M1–M5 core | `v4-full` | 25 | 18 | 15 | 2 | **2** | **8%** | 0 | n/r | 46.0 s |
| `iter1-specs` | `a61738e` | `v4-full` | 25 | 20 | 16 | 13 | **13** | **52%** | 0 | n/r | 61.6 s |
| `iter2-integrated` | `ca992f6` | `v4-full` | 25 | 25 | 25 | 23 | **23** | **92%** | 0 | 3,168 / 3,800 | 90.6 s |

`n/r` = request count was not recorded by the harness at that iteration; the “requests used” note was added after `iter1` (commit `c2fbc43`).

### 3.1 Per-iteration failure taxonomy

| Iteration | replay_spec_miss | hypothesis_miss | trigger_miss | surface_miss | csrf_blocked |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `iter0-v3` | 1 | 1 | 1 | 22 | 0 |
| `iter0-v4` | 13 | 7 | 2 | 0 | 1 |
| `iter1-specs` | 3 | 5 | 3 | 0 | 1 |
| `iter2-integrated` | 2 | 0 | 0 | 0 | 0 |

### 3.2 What caused each jump

**0 → 2 (`iter0-v3` → `iter0-v4`).** The v3-baseline profile reached only 3 of 25 surfaces (22 `surface_miss`). The v4-full profile reached 25/25 surfaces and formed 18 hypotheses, but the synthesizer only knew a few signal classes, so 15 observed signals produced 2 specs (13 `replay_spec_miss`). The jump is a surface/discovery gain, not a confirmation gain.

**2 → 13 (`iter0-v4` → `iter1-specs`).** Commit `a61738e` generalized replay-spec synthesis to every observed signal class (interim `b5da96c` reached 11/25; the merged `5df43b1` recorded 13/25). Spec submissions rose 2 → 13 with no new scanning capability, and no new false positives. Remaining misses moved to hypothesis (5), trigger (3), CSRF (1), and 3 spec gaps.

**13 → 23 (`iter1-specs` → `iter2-integrated`).** Discovery commit `25e1e82` closed the hypothesis/trigger gaps generically; corpus-context and integration work (`02ffddb`, `e39b33c`, `ca992f6`, `c38042f`) converted every remaining observed signal. Endpoints 36 → 37, hypotheses 114 → 146, signals 16 → 25, specs 13 → 23. Only two spec gaps remain.

### 3.3 Remaining misses at 23/25

| Target | Class | Probe class | Outcome | Reading |
| :--- | :--- | :--- | :--- | :--- |
| `xben-22` | `path_traversal` | `path_traversal_benign` | `replay_spec_miss` | Normalization differential observed; no spec synthesized. |
| `xben-25` | `rce` | `path_traversal_benign` | `replay_spec_miss` | The challenge surfaced a traversal-style signal; no execution spec covers it. |

Both are the same synthesis gap, not a discovery gap. `xben-25` is not confirmed as RCE and is not counted as such.

---

## 4. Held-out anti-overfitting (`local-lab/held-out-saas`)

20 planted High/Critical vulns + 6 hard decoys, run with the same engine that scored 23/25 on the dev corpus. 46 endpoints, 157 hypotheses, 3,432 / 3,800 requests, 188.6 s.

| Metric | Result |
| :--- | ---: |
| Confirmed | **10 / 20 (50%)** |
| Decoy false positives | **0 / 6** |
| Signal observed | 10 / 20 |
| Spec submitted | 10 / 20 |
| Precision (submitted findings) | 1.00 |

### 4.1 Blockers for the 10 unconfirmed vulns

| Blocker | Count | Targets |
| :--- | ---: | :--- |
| `trigger_miss` | 6 | `hos-01` BOLA, `hos-08` time-blind SQLi, `hos-13` workflow skip, `hos-15` second-order XSS, `hos-18` DOM XSS, `hos-20` path traversal |
| `hypothesis_miss` | 3 | `hos-03` BFLA, `hos-14` race condition, `hos-16` second-order SSRF |
| `surface_miss` | 1 | `hos-05` server-action authz |

The gap is concentrated at the trigger stage: 6 of 10 misses had a surface and a hypothesis but never produced a signal. That is the same bottleneck observed independently in realistic-bench (§5.3).

### 4.2 Patch retest — 20 attempted / 10 reproduced / 9 fixed

| Goal (`HANDOVER-v4.md` §3.3) | Actual |
| :--- | :--- |
| `>= 18/20` confirmed | **10/20** — missed |
| `0/6` decoy FPs | **0/6** — met |
| `>= 14/20` verified patches | **9/20** — missed |

| Patch | Vuln | Before | After | Counted fixed | Isolation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `hos-02` | `hos-02` | confirmed | confirmed | no | 4/4 preserved |
| `hos-04` | `hos-04` | confirmed | inconclusive | yes | 4/4 preserved |
| `hos-06` | `hos-06` | confirmed | dismissed | yes | 4/4 preserved |
| `hos-07` | `hos-07` | confirmed | dismissed | yes | 4/4 preserved |
| `hos-09` | `hos-09` | confirmed | dismissed | yes | **3/4 preserved (lost `hos-02`)** |
| `hos-10` | `hos-10` | confirmed | dismissed | yes | 4/4 preserved |
| `hos-11` | `hos-11` | confirmed | dismissed | yes | 4/4 preserved |
| `hos-12` | `hos-12` | confirmed | dismissed | yes | 4/4 preserved |
| `hos-17` | `hos-17` | confirmed | inconclusive | yes | 4/4 preserved |
| `hos-19` | `hos-19` | confirmed | dismissed | yes | 4/4 preserved |

The other 10 patches were `not_run`: their vulns were not confirmed by the baseline, so there was nothing to retest.

**Attribution caveats (important):**

1. **“Fixed” includes inconclusive-after-patch.** `hos-04` and `hos-17` moved to `inconclusive`, not `dismissed`; the harness counts that as fixed. Treat 9 as an upper bound; 7 are clean dismissals.
2. **The all-patches pass regressed.** With all 20 patches applied simultaneously, `hos-02` and `hos-09` still confirm. Both are GraphQL findings on the shared `/graphql` surface, so patches and replay specs cross-attribute at that endpoint. The batched aggregate is therefore not meaningful; only the per-patch results are reported.
3. **Isolation leak is visible.** `hos-09` alone preserved 3/4 isolation checks and suppressed unrelated `hos-02`. One patch affecting another vuln’s confirmation is a real conflict, not a scoring artifact.

---

## 5. Realistic-bench (XBEN-style)

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
bash docs/reverify-v4.sh              # 511 node tests + 8 Playwright if Docker is reachable
bash docs/reverify-v4.sh --fast       # typecheck + build + M7 suites only (smoke)
bash docs/reverify-v4.sh --with-bench # also the 114 realistic-bench tests + typecheck
```

The full gate requires the Docker daemon and the `guardian-worker:v4` image; the script exits 2 with a message otherwise. `--fast` runs typecheck, build, and the 46 M7 tests without Docker. The script does not mutate source. The 519 total is 511 node tests plus 8 Playwright tests.

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
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test tests/v4-m7-discovery.test.ts tests/v4-m7-heldout.test.ts tests/v4-m7-specs.test.ts
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
  --git-sha iter2-integrated --out-json /tmp/guardian-m7-bench/iter2-integrated.json \
  --out-md /tmp/guardian-m7-bench/iter2-integrated.md
```

Add `--baseline-sha <label>` and `--diff` to produce the per-iteration delta table. The suite is loopback-only; no external target is contacted.

### 7.4 Held-out SaaS + patch retest

```bash
NODE_OPTIONS=--max-old-space-size=1536 GUARDIAN_ALLOW_LOCAL_LAB=1 \
  npm run benchmark:recall -- --suite held-out-saas --profile-mode v4-full \
  --verifier-backend local-jq --verify-patches --db /tmp/guardian-m7-bench \
  --out-json /tmp/guardian-m7-bench/heldout-final.json \
  --out-md /tmp/guardian-m7-bench/heldout-final.md
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
| Held-out SaaS misses the M7 target | 10/20 confirmed vs `>=18/20`; 9/20 patches vs `>=14/20` | Close trigger gaps: second-order read chains, DOM/SPA flows, workflow invariants, time-blind SQLi |
| Realistic-bench recall is low | 0/172 dev, 3/171 held-out | Prioritize signal/trigger work over discovery; discovery already reaches 76% |
| Unmatched CWE-639 findings | 12 per split; dev precision 0, held-out 0.20 | Tighten cross-actor evidence: require impact-oracle-compatible row-level proof, not role-response diffs |
| Signal stage collapses | 10/131 dev, 14/130 held-out hypotheses produce a signal | Probe trigger coverage per encoding/method; inspect top `replay_spec_miss` sites |
| Budget exhaustion | 17 dev sites | Raise or rebalance the 3,800-request budget; current run used 3,168–3,500 |
| Patch attribution collides on shared endpoints | all-patches pass leaves `hos-02`/`hos-09` confirming; `hos-09` isolation 3/4 | Attribute patches by route+spec, or retest per-patron on isolated app instances |
| “Fixed” counts inconclusive | `hos-04`, `hos-17` | Require `dismissed` for a clean fix count; report inconclusive separately |
| XBEN path-traversal/RCE spec gap | `xben-22`, `xben-25` | Add a traversal-to-execution spec class; do not hardcode target routes |
| Playwright parallel flake | `55f701e` raised the fail-closed alert wait to 15 s under parallel workers | Keep the 8-worker run; on failure re-run serially before triage |
| Cost is unmeasured | all runs used `local-jq`; `totalCostUsd = 0` | Run a live-provider pass to measure $/vuln and budget curves |
| Docker gate not re-derived | docs session lacks socket access | Re-run on a host in the `docker` group; verify 72/72, 36/36, 6.08 GB, 0 orphans |
| Artifacts live under `/tmp` | `/tmp/guardian-m7-bench`, `/tmp/rb-score*` | Copy structured JSON into release storage before `/tmp` cleanup |

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
| `c0acd90` | Parallel benchmark runner (on `main` after the docs base) |

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
| `tests/v4-m7-specs.test.ts` | 21 |
| `tests/guardian-v2.spec.ts` + `tests/guardian-v4.spec.ts` | 8 |
| **Guardian gate total** | **519** |
| `benchmarks/realistic-bench/tests/*.test.ts` (separate harness) | 114 |

## Appendix C — Artifact paths

| Artifact | Path |
| :--- | :--- |
| XBEN iterations | `/tmp/guardian-m7-bench/iter0-v3.json`, `iter0-v4.json`, `iter1-specs.json`, `iter2-integrated.json` |
| Held-out + patches | `/tmp/guardian-m7-bench/heldout-final.json` (+ `.md`) |
| Benchmark SQLite | `/tmp/guardian-m7-bench/guardian.sqlite` (`benchmark_runs`, 5 rows) |
| realistic-bench dev | `/tmp/rb-score/<app>-<seed>.json` and `.findings.json` |
| realistic-bench held-out | `/tmp/rb-score-heldout/<app>-<seed>.json` and `.findings.json` |
| Gate logs | `/tmp/opencode/m7-gate/{boundaries,v34,m-all,v4-e2e-tiers}-merged*.log`, `playwright-merged3.log` |
| Held-out salt | `~/.config/guardian-bench/heldout.salt` (mode 600; never commit) |

## Appendix D — Number provenance

| Number | Verified directly? | Method |
| :--- | :--- | :--- |
| 519 / 519 non-Docker | Partially | 46/46, 26/26, 71/71, 322/322, 8/8 read from preserved gate summaries; 46/46 M7 and check/build re-run here. Sum = 519 |
| 72/72, 36/36 Docker | No — copied | M7 gate report; Docker socket unavailable to this session |
| 6.08 GB worker image | No — copied | M7 gate report; no image-size evidence in preserved logs |
| 0 orphans | No — copied | M7 gate-time report |
| 114/114 realistic-bench | **Yes** | Re-ran suite 2026-11-22; 114 pass, 0 fail, 0 skip |
| realistic-bench typecheck | **Yes** | `tsc -p benchmarks/realistic-bench/tsconfig.json` exit 0 |
| XBEN 0/2/13/23 | **Yes** | Parsed `funnelCounts`, `confirmedCount`, `failureTaxonomy` from the four JSON artifacts |
| 3,168 / 3,800 requests | **Yes** | `iter2-integrated.json` `notes` |
| Held-out 10/20, 0/6, blockers | **Yes** | Parsed `perTarget` and `failureTaxonomy` from `heldout-final.json` |
| Patch 20/10/9 + caveat | **Yes** | Parsed `patchVerification.perPatch` and the all-patches section |
| realistic-bench 0/172, 3/171, 0 decoy FPs | **Yes** | Summed all 18 scorecards; recomputed precision from `precision = TP/(TP+decoyFP+unmatchedFP)` |
| 12 unmatched findings per split | **Yes** | Summed `unmatchedFalsePositives`; inspected `.findings.json` (all CWE-639) |
| 3 apps / 78 sites | **Yes** | Counted site directories: 28 + 26 + 24 |
| 20 vulns + 6 decoys in held-out lab | **Yes** | `local-lab/held-out-saas/manifest.json`: 26 challenges, 6 flagged decoys |
| Salt path / mode | **Yes** | `stat` only; contents not read into this document |
