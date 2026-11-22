# Guardian v5 — Engineering Handover (`HANDOVER-v5.md`)

**Status:** IN PROGRESS (living document) · **Snapshot:** 2026-11-22, `main` @ `edcc7f1` (includes `5b4b625`, M2 complete, paired realism)
**Read first:** [VERIFICATION-v5.md](VERIFICATION-v5.md) (measured evidence) · [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md) (ownership/gates)
**Previous line:** [HANDOVER-v4.md](HANDOVER-v4.md) · [VERIFICATION-v4.md](VERIFICATION-v4.md) (historical, closed)

---

## 1. Where v5 stands

| Milestone | Status | One-line handover |
| :--- | :--- | :--- |
| M0 | DONE | `npm run benchmark:realistic` drives real `Execution`; per-cell data-dir isolation; inert-run preflight. Baseline artifacts are under `/tmp` and must be preserved. |
| M1 | DONE | Broker/browser args, multi-surface canaries, dedupe, routing/skills, inline verify feedback, guard/sanitizer split, CVE semver. Recon halt fix (`4ad4078`) recovered XBEN 20→24; v4 parity was 25/25. |
| M2 | DONE | State graph, recon, auth/session, endpoint graph, coverage tracking, cross-persona ID harvesting, BOLA consumer queue. M2.1 acceptance 10/10; merge `198cdad`. |
| M3 | IN PROGRESS | CSRF state change, webhook forgery, open redirect, write-BOLA, noise tolerance, and spec contracts merged. Race setup, business-logic invariants, and the decoy-negative acceptance suite remain. |
| M4 | DONE | 1,724 compiled templates, 492 modern CVE-named templates, 493 unique modern CVE IDs, multi-framework AST, SAST→DAST bridge, Gate 6. |
| M5 | PHASE 1 + TOOLS DONE | Board schema/store/SSE, mandatory Board tab, board_post/read, warm-specialist lifecycle. 14 node board tests + 15 board-tools tests + 1 Playwright. Posters/wakeups still in progress. |
| M6 | IN PROGRESS | G9 parity met (+1.25 pp), but realistic H/C recall is 13.7%, white-box is unmeasured, chains are 0/6, and the container-lifecycle fix is in progress. |

**Release gate:** 6 met, 1 met-with-caveat, 2 not met, 1 not measured, 1 fix in progress. Details and exact denominators are in [VERIFICATION-v5.md §2](VERIFICATION-v5.md#2-release-gates-v5-target-vs-current).

---

## 2. What changed since v4

- **Realism harness is real and paired:** dev and salted held-out runs on the same M2 line. Dev **24/172 (14.0%)**, held-out **26/171 (15.2%)**, both precision 100%, 0/62 and 0/63 decoy FPs, 0 unmatched.
- **Held-out parity:** dev→held-out gap is **+1.25 percentage points absolute**, within the roadmap’s 10-pp definition (G9 met).
- **Modern corpus:** 1,600 legacy-capped templates → 1,724, including 492 CVE-named templates from 2021–2026 (493 unique modern CVE IDs).
- **Board UI and tools:** `Coordinator` is replaced by `Board` + `Worker Inspector`; board_post/read, zero-polling deltas, and warm-specialist lifecycle are merged (15/15 board-tools tests).
- **XBEN trade-off:** 25/25 v4 parity → 24/25; only `xben-16` (`browser_chain`) is missing. The v5 ≥23 gate passes, but do not claim v4 parity.
- **Recon halt fixed:** a denied off-origin redirect no longer revokes the whole scope; Phase-0 keeps discovering. XBEN recovered 20→24 (`4ad4078`).

---

## 3. Operational notes for the next session

- **Worktree setup:** symlink `node_modules` (and `worker/node_modules`) from the base checkout; `npm ci` in every worktree is unnecessary and slow.
- **AST suites:** without host worker deps, `tests/v5-m4-*` falls back to regex parsing and fails. Run `npm run worker:install` or link `worker/node_modules`.
- **Docker:** this host needs `newgrp docker -c '<command>'`; a plain `docker info` gets `permission denied` despite group membership. Worker image `guardian-worker:v4` exists.
- **Agentic runs:** `Execution` needs a model profile **and** the Docker worker backend. Use `GUARDIAN_DATA_DIR=/home/omarchy/guardian-data`, `--verifier docker`, and `--isolate-data-dir`; `local-jq` + model profile is inert and should fail fast.
- **Credentials:** the model key lives under the Guardian data dir (`credentials/…`, mode 600); never print/copy/commit it.
- **Held-out salt:** `~/.config/guardian-bench/heldout.salt` (mode 600). Read it into `GUARDIAN_RB_HELDOUT_SALT` only; never echo or commit.
- **Loopback only:** all benchmarks are local-lab / `127.0.0.1`; no external target probing.
- **Container hygiene:** 51 leaked `Created` assignment containers were found; the gate stream removed 50. Re-check saw 0 `Created`, 2 running, 0 networks. The lifecycle fix is in progress; re-run the orphan gate before release.
- **Artifacts:** benchmark JSON under `/tmp` is ephemeral. Copy structured scorecards into durable release storage; do not rely on `/tmp` for the final gate.

---

## 4. Open work, in order

1. **M3 completion:** race `setupSteps[]`, workflow/business-logic invariants, decoy-negative acceptance suite.
2. **Realism recall:** raise H/C from 13.7% toward 65% (grey) / 80% (white). Start with `replay_spec_miss` (90 dev / 91 held-out), budget exhaustion (23/20), surface misses (16/14), and form encodings (8/6).
3. **Chains:** 0/6 on both splits and XBEN `browser_chain` missed; wire M5 chain planning and browser-chain verification.
4. **Hold parity:** G9 passes at ~14–15% recall; re-check the +1.25 pp gap after each recall lift. Do not treat parity at 14% as generalization at 65%.
5. **White-box mode:** run the 9-cell matrix with `--mode white-box` and record recall/decoy FPs.
6. **Agentic reliability:** finish the container-lifecycle fix; fix worker bootstrap and wall-clock exhaustion; keep per-cell data-dir isolation.
7. **Patch attribution:** report clean dismissals separately (18/20), run a fresh all-patches pass, resolve shared-GraphQL attribution.
8. **Full gate:** re-run the v4 519-case matrix plus v5 149 tests and Playwright on a Docker host after merges.
9. **M5 posters/wakeups:** deterministic posters, warm specialist wakeups/handoffs, lossless compaction.

---

## 5. Reproduction

Use [VERIFICATION-v5.md §8](VERIFICATION-v5.md#8-reproduction). It covers typecheck/build, 149 v5 tests, Board Playwright/tools, XBEN, held-out with patches, the paired dev/held-out realism matrices, the agentic matrix, and the orphan check.

```bash
# Fast orientation
NODE_OPTIONS=--max-old-space-size=1536 npm run check
NODE_OPTIONS=--max-old-space-size=1536 npm run build
newgrp docker -c \
  'cd /path/to/guardian && export GUARDIAN_ALLOW_LOCAL_LAB=1 && node --test --test-concurrency=1 tests/v5-*.test.ts'
npx playwright test tests/guardian-v5-board.spec.ts --workers=1
node --test tests/v5-m5-board-tools.test.ts
```

---

## 6. Commit anchors

| Milestone | Commit | Role |
| :--- | :--- | :--- |
| M0 | `ac5cebd` | true E2E realistic harness |
| M0 | `795f7c6` | per-cell data-dir isolation |
| M0 | `36998da` | inert-run preflight + assignment diagnostics |
| M1 | `5dae946` | merge M1-core wiring |
| M1 | `0fd8a9d` | static audit: guards vs sanitizers, CVE semver |
| M1 | `4ad4078` | recon halt fix; XBEN 20→24 |
| M2 | `51d3b5a` | merge recon2 XHR route maps |
| M2 | `476e03c` | session jars, rotating CSRF, 401 refresh, circuits |
| M2 | `e111d29`, `198cdad` | endpoint graph, coverage, ID harvest, BOLA queue (10/10) |
| M3 | `5aa897c` | merge M3 probes |
| M3 | `3e8e418`, `769311c` | contract encodings, collection state, webhook/list reads |
| M4 | `c19e98a` / `05f2e39` | modern corpus, AST, bridge, Gate 6 |
| M4 | `e3202d7`, `0797d70` | live CVE/discovered-path wiring |
| M5 | `4b41388` / `344d9b1` | Board Phase 1 |
| M5 | `b0b3cce`, `c019295` | board tools, warm specialist lifecycle (15/15) |
| M5 | `ca197a2` | Board in redesigned workspace |
| M6 | `73b11c2` | v5 goal/gates/leases |
| M6 | `d54b463` | agentic benchmark matrix |
| Docs | `agents/docs-v5` | this handover + `VERIFICATION-v5.md` |

---

## 7. Honest limitations

v5 is not release-ready. XBEN and held-out SaaS remain strong; `realistic-bench` is the real gap. All-severity realism is 14.0% dev / 15.2% held-out, but H/C recall is 13.7% / 11.3% against a 65% grey-box target. Precision is 100% on a small denominator (24 dev + 26 held-out findings), chain completion is zero, white-box is unmeasured, and the container-lifecycle fix is not closed. The paired gap meets the 10-pp definition, but that must be re-proven as recall rises.
