# Guardian v5 — Engineering Handover (`HANDOVER-v5.md`)

**Status:** IN PROGRESS (living document) · **Snapshot:** 2026-11-22, `main` @ `175a0a1`
**Read first:** [VERIFICATION-v5.md](VERIFICATION-v5.md) (measured evidence) · [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md) (ownership/gates)
**Previous line:** [HANDOVER-v4.md](HANDOVER-v4.md) · [VERIFICATION-v4.md](VERIFICATION-v4.md) (historical, closed)

---

## 1. Where v5 stands

| Milestone | Status | One-line handover |
| :--- | :--- | :--- |
| M0 | DONE | `npm run benchmark:realistic` drives real `Execution`; per-cell data-dir isolation; inert-run preflight. Baseline artifacts are under `/tmp` and must be preserved. |
| M1 | DONE | Broker/browser args, multi-surface canaries, dedupe, routing/skills, inline verify feedback, guard/sanitizer split, CVE semver. XBEN recovered to 24/25 after the recovery commit; v4 parity was 25/25. |
| M2 | PARTIAL | Recon/auth/state-graph pieces merged (2.2/2.3/2.4); 2.1 endpoint-param/dependency consumers and cross-persona ID budget still need acceptance. |
| M3 | RUNNING | CSRF state change, webhook forgery, open redirect, write-BOLA, noise tolerance merged. Race setup, business-logic invariants, and the dedicated acceptance suite remain. |
| M4 | DONE | 1,724 compiled templates, 492 modern CVE-named templates, multi-framework AST, SAST→DAST bridge, Gate 6. |
| M5 | PHASE 1 DONE | Board schema/store/SSE + mandatory Board tab; 14 node tests + 1 Playwright spec. Posters, warm specialists, chaining, compaction remain. |
| M6 | IN PROGRESS | Gate not closed: realistic H/C recall 13.7% vs 65%, white-box unmeasured, chains 0/6, held-out gap 24.6% relative, orphans present. |

**Release gate:** 5 met, 1 met-with-caveat, 4 not met, 1 not measured. Details and exact denominators are in [VERIFICATION-v5.md §2](VERIFICATION-v5.md#2-release-gates-v5-target-vs-current).

---

## 2. What changed since v4

- **Realism harness is real:** `scripts/benchmark-realistic.ts` runs the production `Execution` loop, supports dev/salted held-out seeds, per-cell isolation, and deterministic or agentic modes.
- **Discovery and signal generation improved:** dev realistic recall 0→20/172, held-out 3/171→15/171, unmatched FPs 12→0 per split, precision 100% on the current emitted sets.
- **Modern corpus:** 1,600 legacy-capped templates → 1,724, including 492 CVE-named templates from 2021–2026.
- **Board UI:** the `Coordinator` tab is replaced by `Board` + `Worker Inspector`, with roster, SSE, redaction/taint boundaries, approval cards, and mention routing.
- **XBEN trade-off:** 25/25 v4 parity → 24/25; only `xben-16` (`browser_chain`) is missing. The v5 ≥23 gate passes, but do not claim v4 parity.

---

## 3. Operational notes for the next session

- **Worktree setup:** symlink `node_modules` (and `worker/node_modules`) from the base checkout; `npm ci` in every worktree is unnecessary and slow.
- **AST suites:** without host worker deps, `tests/v5-m4-*` falls back to regex parsing and fails. Run `npm run worker:install` or link `worker/node_modules`.
- **Docker:** this host needs `newgrp docker -c '<command>'`; a plain `docker info` gets `permission denied` despite group membership. Worker image `guardian-worker:v4` exists.
- **Agentic runs:** `Execution` needs a model profile **and** the Docker worker backend. Use `GUARDIAN_DATA_DIR=/home/omarchy/guardian-data`, `--verifier docker`, and `--isolate-data-dir`; `local-jq` + model profile is inert and should fail fast.
- **Credentials:** the model key lives under the Guardian data dir (`credentials/…`, mode 600); never print/copy/commit it.
- **Held-out salt:** `~/.config/guardian-bench/heldout.salt` (mode 600). Read it into `GUARDIAN_RB_HELDOUT_SALT` only; never echo or commit.
- **Loopback only:** all benchmarks are local-lab / `127.0.0.1`; no external target probing.
- **Container hygiene:** 51 created/never-started assignment containers were observed. Confirm ownership/age before deleting; then re-check the 0-orphan gate.
- **Artifacts:** benchmark JSON under `/tmp` is ephemeral. Copy structured scorecards into durable release storage; do not rely on `/tmp` for the final gate.

---

## 4. Open work, in order

1. **M2.1 acceptance:** endpoint-param consumers exist (`execution.ts:3158`) and resource tracking call sites are wired; prove coverage/dependency updates end-to-end, complete cross-persona ID harvesting for unauthenticated responses, add the per-resource test budget, then mark M2 done.
2. **M3 completion:** race `setupSteps[]`, workflow/business-logic invariants, decoy-negative acceptance suite.
3. **Realism recall:** raise H/C from 13.7% toward 65% (grey) / 80% (white). Start with `replay_spec_miss` (92 dev / 81 held-out), budget exhaustion (23 dev), surface misses (16 dev / 64 held-out), and form encodings (10 dev).
4. **Chains:** 0/6 on both splits and XBEN `browser_chain` missed; wire M5 chain planning and browser-chain verification.
5. **Held-out discipline:** re-run the salted matrix on the post-M1 tree; define “within 10%” as relative or absolute before scoring G9.
6. **Agentic reliability:** fix worker bootstrap failure and wall-clock exhaustion; sweep stranded containers; keep per-cell data-dir isolation.
7. **Patch attribution:** report clean dismissals separately (18/20), run a fresh all-patches pass, resolve shared-GraphQL attribution.
8. **Full gate:** re-run the v4 519-case matrix plus v5 suites and Playwright on a Docker host after merges.
9. **M5 Phase 1b/2/3:** deterministic posters, warm specialists/handoffs, lossless compaction.

---

## 5. Reproduction

Use [VERIFICATION-v5.md §8](VERIFICATION-v5.md#8-reproduction). It covers typecheck/build, v5 suites, Board Playwright, XBEN, held-out with patches, the dev/held-out realism matrices, the agentic matrix, and the orphan check.

```bash
# Fast orientation
NODE_OPTIONS=--max-old-space-size=1536 npm run check
NODE_OPTIONS=--max-old-space-size=1536 npm run build
newgrp docker -c \
  'cd /path/to/guardian && export GUARDIAN_ALLOW_LOCAL_LAB=1 && node --test --test-concurrency=1 tests/v5-*.test.ts'
npx playwright test tests/guardian-v5-board.spec.ts --workers=1
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
| M1 | `4ad4078` | XBEN recovery 20→24 |
| M2 | `51d3b5a` | merge recon2 XHR route maps |
| M2 | `476e03c` | session jars, rotating CSRF, 401 refresh, circuits |
| M3 | `5aa897c` | merge M3 probes |
| M4 | `c19e98a` / `05f2e39` | modern corpus, AST, bridge, Gate 6 |
| M4 | `e3202d7`, `0797d70` | live CVE/discovered-path wiring |
| M5 | `4b41388` / `344d9b1` | Board Phase 1 |
| M5 | `ca197a2` | Board in redesigned workspace |
| M6 | `73b11c2` | v5 goal/gates/leases |
| Docs | `agents/docs-v5` | this handover + `VERIFICATION-v5.md` |

---

## 7. Honest limitations

v5 is not release-ready. The XBEN and held-out SaaS suites are saturated and strong; `realistic-bench` is the real gap. The current 100% precision is measured on a small denominator (20 dev + 15 held-out findings), chain completion is zero, white-box is unmeasured, and the held-out matrix predates the latest dev run. Treat all v5 numbers as directional until M6 runs a paired dev/held-out gate on one tree.
