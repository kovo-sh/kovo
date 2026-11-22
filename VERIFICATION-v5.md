# Guardian v5 — Living Verification (`VERIFICATION-v5.md`)

**Status:** **RELEASE GATE PASS — capability gates open.** The deterministic release gate is 876/876 with 0 failures, 0 skips and 0 orphans. This does **not** mean every capability gate is met: realistic H/C recall is still below target, white-box is unmeasured, and chain completion is low.

**Snapshot:** 2026-11-22, base `main` @ `a7ccb5f` (secret-meta merge; includes M2–M5 and the final realistic/gate work), docs branch `agents/docs-v5`.
**Plan:** [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md) · [plans/v5.md](plans/v5.md)
**Prior release:** [VERIFICATION-v4.md](VERIFICATION-v4.md)
**Handover:** [HANDOVER-v5.md](HANDOVER-v5.md)

> Every number below is re-derived from a structured artifact or the release-gate logs unless marked **copied**. Provenance and discrepancies are in [§9](#9-provenance-and-discrepancies). No raw benchmark logs, payloads, secrets, or salts are reproduced here.

---

## 1. What v5 is measuring

v5 activates the already-built v4 primitives in production paths and measures the result end-to-end on `realistic-bench`. The goal is not a new scanner architecture; it is:

1. close broken production wires (broker/browser args, coverage/param/dependency plumbing, routing, dedupe, canary surfaces);
2. raise real-application recall while holding decoy false positives at zero;
3. prove generalization on salted held-out seeds, not just the dev suite;
4. publish before/after evidence per milestone.

The surfaces below are reported separately and are **not comparable to each other**.

| Surface | Purpose | Size |
| :--- | :--- | :--- |
| `benchmarks/xben-25` | Fixed dev suite used for recall hill-climbing | 25 targets, 0 decoys |
| `local-lab/held-out-saas` | Anti-overfitting + patch retest | 20 vulns + 6 hard decoys |
| `benchmarks/realistic-bench` | Multi-tenant realism, paired dev + salted held-out seeds | 3 apps, 172/171 targets, 6–8 decoys per seed |
| Agentic `Execution` matrix | Real LLM worker loop on realistic apps | 6 cells, wall-clock capped |

“Confirmed” means a Zero-LLM `ReplayVerifier` reached `confirmed` / `runtime_confirmed`. LLM output is a hypothesis only.

---

## 2. Release gates (v5 target vs current)

Targets are from the roadmap. **Held-out/dev parity uses the absolute percentage-point definition: within 10 pp.** The release gate (G10/G11) can pass while capability gates fail.

| # | Gate | v5 target | Current v5 evidence | Status |
| :--- | :--- | :--- | :--- | :--- |
| G1 | XBEN-25 recall | ≥ 23/25 | **25/25 (100%)**, 0 FP | **MET** |
| G2 | Held-out SaaS recall | ≥ 18/20 | **20/20 (100%)**, 6/6 decoys clean | **MET** |
| G3 | Held-out patch retest | ≥ 14/20 fixed | **20/20 fixed** (18 clean dismissals, 2 inconclusive counted fixed), `allPatches=fixed` | **MET, with caveat** |
| G4 | Realistic H/C recall — grey-box | ≥ 65% | **H/C 64/117 = 54.7%**; all severities **86/172 = 50.0%** | **NOT MET** |
| G5 | Realistic H/C recall — white-box | ≥ 80% | not measured | **NOT MEASURED** |
| G6 | Precision | ≥ 95% | dev **100%** (86/86), held-out **100%** (87/87) | **MET** |
| G7 | Decoy FP rate | ≤ 5% | **0/62** dev, **0/63** held-out | **MET** |
| G8 | Chain completion | ≥ 50% | **0/6** dev, **0/6** held-out | **NOT MET** |
| G9 | Held-out within 10 pp of dev | ≤ 10 pp absolute | dev **50.0%** vs held-out **50.9%** = **+0.9 pp** | **MET** |
| G10 | Full release gate | 100% pass, 0 skips | **876/876 PASS**, 0 fail, 0 skip | **PASS** |
| G11 | Orphan containers/networks | 0 / 0 | orphan hygiene **PASS**; 0 stale `Created`, 0 networks | **PASS** |

**Scorecard:** 7 met, 1 met-with-caveat (G3), 2 not met (G4, G8), 1 not measured (G5). **Release gate is PASS; capability gates G4/G5/G8 remain open.**

---

## 3. Milestone status (M0–M6)

| # | Scope | Status | Owner / worktree | Primary commits | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **M0** | True E2E `realistic-bench` harness, baseline, CLI | **DONE** | `m5-m0` / `agents/m0` | `ac5cebd`, `795f7c6`, `36998da` | Real `Execution`, per-cell isolation, inert-run preflight |
| **M1** | P0 wiring: broker/browser args, canaries, dedupe, routing, guard/sanitizer, CVE semver | **DONE** | `m5-m1-core`, `m5-m1-static` | `5dae946`, `0fd8a9d`, `4ad4078` | Recon halt fix restored XBEN 20→24 en route to 25/25 |
| **M2** | State graph, recon, auth/session, coverage | **DONE** | `m7-spa`, `m5-m2-auth`, `agents/m2-state` | `198cdad`, `e111d29`, `476e03c` | Endpoint graph, coverage, ID harvest, BOLA queue (10/10) |
| **M3** | Probes/verifiers: CSRF, webhook, open redirect, write-BOLA, race, noise | **DONE** | `m5-m3-probes`, `specs2` | `5aa897c`, `769311c`, `253f6c6`, `09596ae` | Probes3 + contracts merged; SSRF/XXE realism wired |
| **M4** | Templates, multi-framework AST, SAST→DAST, Patch Gate 6 | **DONE** | `m5-m4` / `agents/m4` | `c19e98a`, `05f2e39`, `e3202d7`, `0797d70` | 1,724 templates, 492 modern CVE-named, Gate 6 |
| **M5** | Swarm Board, Board UI, board tools, posters/wakeups | **DONE** | `m5-board` / `agents/board-ui` | `4b41388`, `b0b3cce`, `c019295`, `93ff078`, `f0e9bb7` | Deterministic 0-LLM posters, warm specialists, board tools |
| **M6** | Hill-climb, anti-overfitting, final gate | **PARTIAL** | `m5-docs2` / `agents/docs-v5` | `d54b463`, `84eb476`, `974904c`, `23dde15`, `a7ccb5f` | Deterministic gate measured; post-race agentic matrix pending |

---

## 4. Measured evidence

### 4.1 Full release gate — 876/876 PASS

Command: `bash docs/reverify-v5.sh --full` (under the Docker group). Log directory: `/tmp/guardian-reverify-v5.SJqH6f`. `--full` fails closed on Docker/image/Playwright unavailability and requires 0 skips and 0 orphans.

| Check | Result | Notes |
| :--- | ---: | :--- |
| Typecheck | **PASS (0 errors)** | prerequisite, not counted in 876 |
| Build | **PASS** | client + SSR; prerequisite, not counted |
| v2 core boundaries | **46 / 46** | 0 fail / 0 skip |
| v3/v4/v5 boundaries | **32 / 32** | 0 fail / 0 skip |
| v4 M1–M7 milestone suites | **198 / 198** | 0 fail / 0 skip |
| v5 milestone suites (gate list) | **118 / 118** | 0 fail / 0 skip |
| v5 gate worker lifecycle | **9 / 9** | 0 fail / 0 skip |
| v4 tiered E2E matrix | **322 / 322** | 0 fail / 0 skip |
| realistic-bench harness | **142 / 142** | 0 fail / 0 skip |
| Playwright UI E2E | **9 / 9** | v2 + v4 + v5 Board, 8 workers |
| Orphan hygiene | **PASS** | 0 stale `Created`, 0 networks |
| **Total** | **876 / 876** | 46+32+198+118+9+322+142+9 |

Independent coverage check on the same tree: the current `tests/v5-*.test.ts` glob is **237/237, 0 skip** under the Docker group. The gate’s v5 row covers its milestone list (118); the glob additionally includes M2-state, board tools/execution, M3 signals/specs3, M6 OOB/agentic-matrix, and secret-meta tests (see §9.2).

### 4.2 XBEN-25 — 25/25 (G1 met)

Source: `/tmp/guardian-m7-bench/final-dev.json` (`xben-25`, `v4-full`, `local-jq`, not simulated).

| Metric | Value |
| :--- | ---: |
| Targets / decoys | 25 / 0 |
| Confirmed / FP | **25 / 0** |
| Recall / precision | **100% / 100%** |
| Duration / cost | 88.9 s / $0.00 |
| Funnel | 25 → 25 surface → 25 hypothesis → 25 signal → 25 spec → 25 confirmed |

This restores v4 parity. The previous `xben-16` browser-chain miss is resolved.

### 4.3 Held-out SaaS — 20/20, patches 20/20 (G2/G3 met)

Source: `/tmp/guardian-m7-bench/final-held.json` (`held-out-saas`, `local-jq`).

| Metric | Value |
| :--- | ---: |
| Targets / decoys | 20 / 6 |
| Confirmed / decoys clean | **20 / 6** |
| False positives | 0 |
| Recall / precision | 100% / 100% |
| Funnel | 20 → 20 → 20 → 20 → 20 → 20 |
| Scan / patch retest | 119.9 s / 16.6 s |
| Cost | $0.00 |

Patch retest:

| Metric | Value |
| :--- | ---: |
| Attempted / reproduced before | 20 / 20 |
| Fixed | **20** |
| Clean dismissals | 18 |
| Inconclusive-after counted fixed | 2 (`hos-04`, `hos-17`) |
| Isolation preserved | 20 × 4/4, 0 lost |
| Decoy FP before / after | 0 / 0 |
| All-patches verdict | **`fixed`**; 20 replayed, 20 dismissed |

**Attribution caveat:** all-patches replays baseline-attributed specs; it is not a fresh pipeline pass. Two fixes are inconclusive-after, not clean dismissals.

### 4.4 realistic-bench dev — 86/172 (50.0%)

Source: `/tmp/rb-v5-final-dev/*.json` (9 scorecards; deterministic replay, `$0`).

| App | Seed | Confirmed / targets | Recall | Precision | Decoy FP | Unmatched | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1 | 13 / 22 | 59.1% | 100% | 0 | 0 | 0/0 |
| acme-saas | 2 | 10 / 20 | 50.0% | 100% | 0 | 0 | 0/0 |
| acme-saas | 42 | 12 / 22 | 54.5% | 100% | 0 | 0 | 0/1 |
| opsportal | 1 | 8 / 18 | 44.4% | 100% | 0 | 0 | 0/1 |
| opsportal | 2 | 7 / 17 | 41.2% | 100% | 0 | 0 | 0/1 |
| opsportal | 42 | 6 / 16 | 37.5% | 100% | 0 | 0 | 0/1 |
| shopflow | 1 | 11 / 19 | 57.9% | 100% | 0 | 0 | 0/1 |
| shopflow | 2 | 10 / 20 | 50.0% | 100% | 0 | 0 | 0/1 |
| shopflow | 42 | 9 / 18 | 50.0% | 100% | 0 | 0 | 0/0 |
| **Total** | | **86 / 172** | **50.0%** | **100%** | **0 / 62** | **0** | **0 / 6** |

Severity: Critical **11/26 (42.3%)**, High **53/91 (58.2%)**, Medium 20/52, Low 2/3 → **H/C 64/117 = 54.7%** (G4 target 65%).

Funnel and loss buckets:

| Stage / bucket | Count |
| :--- | ---: |
| Target vulns | 172 |
| Surface discovered | 158 (91.9%) |
| Hypothesis formed | 153 |
| Signal observed | **118 (68.6%)** |
| Spec submitted / confirmed | 88 / **86** |
| `replay_spec_miss` | 53 |
| `budget_exhausted` | 13 |
| `form_encoding_missing` | 10 |
| `hypothesis_miss` | 6 |
| `csrf_blocked` | 3 |
| `surface_miss` | 1 |

Class highlights: **SSRF 12/12 after the realism merge** (`e06074b`; the final 86/172 scorecard sums 11/12 — see §9.2), **XXE 7/7**, **BOLA 17/19**, **SQLi 5/7**, **stored XSS 6/6**, **path traversal 6/6**, **mass assignment 6/11**. Remaining zero classes include reflected XSS (0/5), business logic (0/12), workflow bypass (0/10), command injection (0/5), JWT (0/6), and auth bypass (0/2).

**Precision definition:** `TP / (TP + decoyFP + unmatchedFP)`. The 100% value is over 86 emitted findings with zero decoy and zero unmatched FPs.

### 4.5 realistic-bench held-out — 87/171 (50.9%)

Source: `/tmp/rb-v5-final-held/*.json` (9 salted scorecards, seeds `1000042/1/2`; salt from environment only). Paired with §4.4.

| App | Seed | Confirmed / targets | Recall | Precision | Decoy FP | Unmatched | Chains |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| acme-saas | 1000001 | 12 / 22 | 54.5% | 100% | 0 | 0 | 0/0 |
| acme-saas | 1000002 | 12 / 21 | 57.1% | 100% | 0 | 0 | 0/1 |
| acme-saas | 1000042 | 12 / 22 | 54.5% | 100% | 0 | 0 | 0/1 |
| opsportal | 1000001 | 7 / 16 | 43.8% | 100% | 0 | 0 | 0/1 |
| opsportal | 1000002 | 6 / 16 | 37.5% | 100% | 0 | 0 | 0/1 |
| opsportal | 1000042 | 8 / 17 | 47.1% | 100% | 0 | 0 | 0/1 |
| shopflow | 1000001 | 10 / 18 | 55.6% | 100% | 0 | 0 | 0/0 |
| shopflow | 1000002 | 11 / 20 | 55.0% | 100% | 0 | 0 | 0/1 |
| shopflow | 1000042 | 9 / 19 | 47.4% | 100% | 0 | 0 | 0/0 |
| **Total** | | **87 / 171** | **50.9%** | **100%** | **0 / 63** | **0** | **0 / 6** |

Severity: Critical 10/26, High 55/98, Medium 20/44, Low 2/3 → **H/C 65/124 = 52.4%**. Funnel: 171 → 161 surface → 158 hypothesis → **125 signal** → 88 spec → 87 confirmed. Buckets: `replay_spec_miss` 57, `budget_exhausted` 8, `form_encoding_missing` 8, `hypothesis_miss` 6, `csrf_blocked` 3, `surface_miss` 2.

Class highlights: BOLA 17/18, path traversal 9/9, open redirect 6/8, SSRF 11/12, XXE 5/5, SQLi 5/10, stored XSS 4/6, mass assignment 5/9.

**Gap:** dev **50.0%** vs held-out **50.9%** = **+0.9 pp absolute**; G9 met. H/C parity is slightly negative (54.7% dev vs 52.4% held-out), so the overall gap is not uniform across severities.

### 4.6 Agentic Execution baseline — STALE / PENDING

The 6-cell agentic matrix in `/tmp/opencode/m6-agentic-baseline/matrix.json` measured **12/117 (10.3%)**, **66.7% precision**, 6 cells, 39 decoys, 1 decoy FP, 5 unmatched FPs, **$1.8477**, 5,607.5 s wall, and a **39.3% worker-failure rate** (24 failed assignments). It was measured **before** the worker-removal race fix (`974904c`), so it is a pre-fix baseline, not current reliability.

A post-fix agentic matrix is running and will be reported separately. **Status: PENDING — no post-fix numbers are claimed here.** Do not combine this stale baseline with the deterministic 86/172 and 87/171 matrices.

### 4.7 M4 corpus and Gate 6

| Metric | Value | Method |
| :--- | ---: | :--- |
| Compiled YAML templates | **1,724** | count of `src/templates/compiled/**/*.yaml` |
| CVE-named templates, all years | 915 | `cve-*.yaml` |
| CVE-named modern templates (2021–2026) | **492** | filename year filter |
| Unique CVE IDs across templates | 916 | unique `cve:` fields |
| Unique modern CVE IDs (year ≥ 2021) | **493** | year filter on `cve:` field |

Use **492** for “CVE-named modern templates” and **493** for “unique modern CVE IDs”; state the definition. Gate 6/AST tests pass 10/10, including “Gate 6 never passes when skipped” and trivy-fs advisories.

### 4.8 M5 Board and swarm wiring

| Item | Evidence |
| :--- | :--- |
| Board schema/store/SSE + migration | `4b41388`; board tests 8/8 |
| Boundary behavior (redaction, taint, injection delimiters, mentions) | 6/6 boundary tests |
| Mandatory `Board` tab replaces `Coordinator` | Playwright pass; roster, unread badge, evidence chips, Tier-3 approval cards, mention autocomplete |
| Board tools / warm-specialist lifecycle | `b0b3cce`, merge `c019295`; 15/15 |
| Deterministic 0-LLM posters + execution wiring | `93ff078`, merge `f0e9bb7`; 9/9 execution tests |
| Workspace redesign port | `ca197a2` (Board in right pane) |

Board counts: **14 node board tests + 15 board-tools tests + 9 execution tests + 1 Playwright check**. The earlier “19/19” was a stale pre-merge count.

### 4.9 New engine capability and integrity fixes

**Secret-disclosure fingerprints (`secretMatches`)** — merge `a7ccb5f`, implementation `e18a775`. The broker records pre-redaction structural evidence without keeping the secret:

| Field | Meaning |
| :--- | :--- |
| `kind` | Secret class (credential, JWT, private key, bearer, header, key/value) |
| `sha256Prefix` | First 12 hex chars of SHA-256 of the raw value; correlation only, not reversible |
| `fieldPath` | Optional bounded location (`headers.<name>` or a JSON path) |
| `count` | Bounded occurrence count |

The raw value never enters logs, the DB body artifact, or an LLM prompt. A verifier that already holds the secret can correlate the fingerprint to prove disclosure. Covered by `tests/v5-secret-meta.test.ts` (**9/9**).

| Fix | Commit | Effect |
| :--- | :--- | :--- |
| Recon halt bug | `4ad4078` | Off-origin redirect denial no longer revokes whole scope; XBEN recovered 20→24 |
| SSRF/XXE OOB realism | `fa10e8d`, `0e3ffc0` | Impact paths reach the registered loopback OOB guard; canary-first wiring |
| Project-name escaping in stored-XSS twins | `095ffda` | Removes a decoy exploitable through the project name |
| Strict HTML escaping + tag-aware XSS monitors | `56a8ecc` | Escaped entities are inert; monitors only fire on real tags |
| Worker lifecycle / stale-container reclaim | `974904c`, `23dde15` | Fixes worker-removal race and container leaks; enables 0-orphan gate |

---

## 5. Before / after

Cumulative main-line deltas; M1–M5 merged in close succession.

| Metric | v4 baseline | Current v5 | Delta | Source |
| :--- | ---: | ---: | ---: | :--- |
| XBEN-25 | 25/25 | **25/25** | 0 (parity restored) | `iter3-merged` → `final-dev` |
| Held-out SaaS | 20/20 | **20/20** | 0 | `heldout-merged` → `final-held` |
| Held-out patches fixed | 20/20 | **20/20** | 0 | same |
| realistic dev confirmed | 0/172 | **86/172** | **+86** | `rb-score` → `rb-v5-final-dev` |
| realistic dev recall | 0.0% | **50.0%** | +50.0 pp | recomputed |
| realistic dev H/C recall | 0.0% | **54.7%** | +54.7 pp | recomputed |
| realistic dev precision | 0.00 | **1.00** | +1.00 | recomputed |
| realistic dev unmatched FP | 12 | **0** | **−12** | recomputed |
| realistic held-out confirmed | 3/171 | **87/171** | **+84** | `rb-score-heldout` → `rb-v5-final-held` |
| realistic held-out recall | 1.75% | **50.9%** | +49.1 pp | recomputed |
| realistic held-out H/C recall | — | **52.4%** | — | recomputed |
| realistic held-out precision | 0.20 | **1.00** | +0.80 | recomputed |
| realistic held-out unmatched FP | 12 | **0** | **−12** | recomputed |
| dev → held-out gap | not comparable | **+0.9 pp** | within 10 pp | paired runs |
| realistic dev surface discovered | 131/172 | **158/172** | +27 | funnel |
| realistic dev signal observed | 10 | **118** | **+108** | funnel |
| realistic held-out signal observed | 14 | **125** | **+111** | funnel |
| realistic chains | 0/1 per run | **0/6** | none completed | scorecards |
| Templates / modern CVE templates | 1,600 / — | **1,724 / 492** | +124 / +492 | corpus |
| Full deterministic gate | 519 v4 / n/a | **876/876** | — | gate log |

Per-milestone headline:

| Milestone | Headline |
| :--- | :--- |
| M0 | Real E2E harness, per-cell isolation, inert-run fail-fast |
| M1 | Recon halt fix; XBEN 20→24 en route to 25/25; realistic unmatched FPs 12→0 |
| M2 | Endpoint graph/coverage/ID harvest/BOLA queue; dev surface 131→158 |
| M3 | SSRF/XXE + CSRF/webhook/open-redirect probes; held-out 3→87 |
| M4 | 1,724 templates; 492 modern CVE-named; AST/bridge/Gate 6 |
| M5 | Board UI + tools + deterministic posters/warm specialists; 0-orphan lifecycle |
| M6 | Paired dev/held-out gap +0.9 pp; deterministic gate PASS; agentic post-fix matrix PENDING |

---

## 6. Honest gap list

| Gap | Measured state | Why it matters | Next action |
| :--- | :--- | :--- | :--- |
| Realistic H/C recall | **54.7% dev**, **52.4% held-out**, vs 65% target | G4 remains NOT MET | Close `replay_spec_miss` 53/57 and the zero-class gaps (reflected XSS, business logic, workflow, command injection, JWT auth bypass) |
| White-box recall | not run | G5 NOT MEASURED | Run the 9-cell `--mode white-box` matrix |
| Chain completion | **0/6 dev, 0/6 held-out** | G8 NOT MET | Finish chain planning/browser-chain verification; add chain fixtures |
| Signal → spec conversion | 118→88 dev, 125→88 held-out | 30–37 signals do not reach a spec | Inspect `replay_spec_miss` per class; improve spec synthesis |
| Agentic reliability | pre-fix 39.3% worker failure; post-fix matrix PENDING | Production LLM path not yet characterized | Report the post-race-fix matrix separately; keep per-cell isolation |
| Precision at scale | 100% on 86 dev + 87 held-out | Larger denominator now, but no high-recall stress | Track precision per class as recall rises |
| Patch attribution | 20/20 fixed, 2 inconclusive; all-patches replay | Avoid overstating clean fixes | Report clean dismissals (18/20); run a fresh all-patches pass |
| H/C vs all-severity parity | overall +0.9 pp, H/C −2.3 pp | G9 is all-severity; H/C parity differs | Report both; do not conflate |
| Gate coverage | official v5 row 118; independent glob 237 | Some new suites are outside the gate script row | Expand the gate script list or document the split |
| Artifact durability | evidence under `/tmp` | `/tmp` is ephemeral | Copy structured JSON into release storage |
| Corpus definition | 1,724 total; 492 modern CVE-named; 493 unique modern IDs | Avoid unverifiable headline counts | State the definition in release notes |

---

## 7. Known limitations

- **Release gate PASS is not capability PASS.** The deterministic gate is green, but G4 (H/C recall), G5 (white-box), and G8 (chains) are open.
- **H/C vs all-severity.** The headline realism numbers are all-severity (50.0% dev / 50.9% held-out). The 65% gate is H/C, where dev is 54.7%.
- **Agentic baseline is stale.** The 12/117 matrix predates the worker-removal race fix; the post-fix matrix is PENDING.
- **Patch “fixed” includes inconclusive retests.** Two held-out patches were counted fixed without a clean dismissal.
- **All-patches is replay-based.**
- **Gate v5 row is a subset.** The official gate covers 118 v5 tests; the current v5 glob is 237/237. The 876 total follows the gate script.
- **Docker needs `newgrp docker`** on this host; a plain `docker info` gets permission denied despite group membership.
- **No external targets.** All benchmarks are loopback-only.
- **No credentials, salts, or raw secrets in this document.** Paths only.

---

## 8. Reproduction

All commands are loopback-only. Never print, copy, or commit the model key, held-out salt, or secret values.

### 8.1 Setup and full gate

```bash
cd /path/to/guardian
npm ci
npm run worker:install
npm run worker:build

# Official release gate (Docker + Playwright); logs under /tmp.
newgrp docker -c 'bash docs/reverify-v5.sh --full'

# Docker-free subset (not the release gate).
bash docs/reverify-v5.sh --fast
```

### 8.2 Independent v5 suites and secret fingerprints

```bash
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 NODE_OPTIONS=--max-old-space-size=2048 &&
  node --test --test-concurrency=1 tests/v5-*.test.ts
'

# secretMatches shape/redaction persistence (9 tests).
node --test tests/v5-secret-meta.test.ts
```

`secretMatches` evidence is `{kind, sha256Prefix, fieldPath?, count}` only. To prove disclosure, correlate `sha256Prefix` against a secret the verifier already holds; never log or transmit the raw value.

### 8.3 XBEN-25

```bash
mkdir -p /tmp/guardian-v5-bench
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:recall -- \
  --suite xben-25 --profile-mode v4-full --verifier-backend local-jq \
  --git-sha v5-xben --out-json /tmp/guardian-v5-bench/xben.json \
  --out-md /tmp/guardian-v5-bench/xben.md
```

### 8.4 Held-out SaaS + patch retest

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:recall -- \
  --suite held-out-saas --profile-mode v4-full --verifier-backend local-jq \
  --verify-patches --git-sha v5-heldout \
  --out-json /tmp/guardian-v5-bench/heldout.json \
  --out-md /tmp/guardian-v5-bench/heldout.md
```

### 8.5 realistic-bench dev and held-out matrices

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 npm run benchmark:realistic -- \
  --app all --seeds 1,2,42 --mode grey-box \
  --verifier local-jq --concurrency 9 --isolate-data-dir \
  --out-dir /tmp/rb-v5-dev

# Salt lives at ~/.config/guardian-bench/heldout.salt (mode 600).
# Read it into the environment; never echo it.
export GUARDIAN_ALLOW_LOCAL_LAB=1
export GUARDIAN_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"

npm run benchmark:realistic -- \
  --app all --seeds 1000001,1000002,1000042 --held-out --mode grey-box \
  --verifier local-jq --concurrency 9 --isolate-data-dir \
  --out-dir /tmp/rb-v5-heldout

unset GUARDIAN_RB_HELDOUT_SALT
```

### 8.6 OOB callback ports

The harness binds one loopback canary listener and passes that exact port to the app’s egress allowlist (`resolveOobCallbackPorts`); a mismatch fails closed. To pin the port, set loopback-only `GUARDIAN_CANARY_PORT` (HTTP) and `GUARDIAN_CANARY_DNS_PORT` (DNS) before the run. Do not bind the canary listener to a non-loopback interface.

### 8.7 Agentic matrix

Use the model profile plus Docker workers and per-cell isolation. The post-fix matrix is **PENDING**; do not reuse the stale 12/117 numbers as current.

```bash
newgrp docker -c '
  cd /path/to/guardian &&
  export GUARDIAN_ALLOW_LOCAL_LAB=1 \
         GUARDIAN_DATA_DIR=/home/omarchy/guardian-data \
         NODE_OPTIONS=--max-old-space-size=2048 &&
  node scripts/benchmark-realistic.ts \
    --app all --seeds 1 --mode grey-box \
    --verifier docker --isolate-data-dir --concurrency 3 \
    --budget-usd 5 --max-duration-ms 1200000 \
    --out-dir /tmp/rb-v5-agentic
'
```

### 8.8 Hygiene

```bash
docker ps -aq --filter label=dev.guardian.assignment --filter status=created  # expect empty
docker ps -aq --filter label=dev.guardian.run                                 # expect empty
docker network ls -q --filter name=guardian                                   # expect empty
```

The release gate treats `guardian-*` containers stuck in `created` for >2 minutes as failures; active `Up` containers from concurrent work are not gate failures.

---

## 9. Provenance and discrepancies

### 9.1 Number provenance

| Claim | Value | Provenance | Status |
| :--- | :--- | :--- | :--- |
| Release gate | 876/876, 0 fail/skip/orphans | `/tmp/guardian-reverify-v5.SJqH6f` suite logs; sum re-derived | re-derived |
| XBEN | 25/25 | `/tmp/guardian-m7-bench/final-dev.json` | re-derived |
| Held-out SaaS + patches | 20/20, 20/20 fixed | `/tmp/guardian-m7-bench/final-held.json` | re-derived |
| Realistic dev | 86/172, 0/62 decoys, 0 unmatched | sum of 9 `/tmp/rb-v5-final-dev` scorecards | re-derived |
| Realistic held-out | 87/171, 0/63 decoys, 0 unmatched | sum of 9 `/tmp/rb-v5-final-held` scorecards | re-derived |
| Class highlights | BOLA 17/19, SQLi 5/7, stored XSS 6/6, traversal 6/6, XXE 7/7, SSRF 11/12 | final dev scorecards | re-derived |
| SSRF 12/12 | realism-merge highlight | `e06074b`; final scorecard sums 11/12 | **copied / differs** |
| Agentic baseline | 12/117, 66.7%, 39.3% worker failure | `/tmp/opencode/m6-agentic-baseline/matrix.json` | re-derived |
| Post-fix agentic matrix | PENDING | not part of this gate | **pending** |
| Templates / modern CVEs | 1,724 / 492 / 493 | filesystem counts | re-derived |
| Board tests | 14 + 15 tools + 9 execution + 1 Playwright | test runs | re-derived |
| Independent v5 glob | 237/237, 0 skip | test run under Docker | re-derived |
| Worker lifecycle fix | `974904c` / `23dde15` | commit + gate run | re-derived artifact |

### 9.2 Discrepancies and retired claims

1. **Modern CVE count retired:** earlier “521 CVEs” was unverifiable. Use **492 CVE-named modern templates** or **493 unique modern CVE IDs**.
2. **Board “19/19” retired:** current totals are 14 board + 15 tools + 9 execution + 1 Playwright.
3. **XBEN regression resolved:** 24/25 → **25/25**; `xben-16` now passes.
4. **SSRF highlight differs from the final scorecard:** the realism merge reported **12/12**, but the preserved final 86/172 scorecard sums **11/12**. The document records both; do not silently use 12/12 without the artifact.
5. **Gate v5 row is a subset:** the official gate reports 118 v5 tests; the current v5 glob is **237/237**. The 876 total is the official gate count, not 237 + other suites.
6. **H/C vs all-severity:** 50.0% dev is all-severity; H/C is 54.7%. Held-out is 50.9% / 52.4%. G9 is met on all-severity, but H/C parity is −2.3 pp.
7. **Agentic baseline is pre-fix:** 12/117 predates `974904c`; the post-fix matrix is PENDING. No post-fix number is claimed.
8. **Patch caveat:** 20/20 fixed includes 2 inconclusive-after retests; all-patches evidence is replay-based.
9. **Chains remain 0/6** on both splits despite the overall recall lift; G8 is still NOT MET.

### 9.3 Next review trigger

Refresh when the post-fix agentic matrix lands, the white-box matrix is run, chains are wired, or H/C recall approaches 65%. The gate table in §2 separates release-gate status from capability status; keep that distinction.
