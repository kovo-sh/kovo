# Guardian v5 — Engineering Handover (`HANDOVER-v5.md`)

**Status:** RELEASE GATE PASS / capability gates open · **Snapshot:** 2026-11-22, `main` @ `a7ccb5f`
**Read first:** [VERIFICATION-v5.md](VERIFICATION-v5.md) · [plans/ROADMAP-v5.md](plans/ROADMAP-v5.md)
**Previous line:** [HANDOVER-v4.md](HANDOVER-v4.md) · [VERIFICATION-v4.md](VERIFICATION-v4.md) (historical, closed)

---

## 1. Where v5 stands

| Milestone | Status | One-line handover |
| :--- | :--- | :--- |
| M0 | DONE | Real E2E `realistic-bench` harness, per-cell data-dir isolation, inert-run preflight. |
| M1 | DONE | Broker/browser args, canaries, dedupe, routing/skills, verify feedback, guard/sanitizer split, CVE semver. Recon halt fix (`4ad4078`) recovered XBEN 20→24 en route to 25/25. |
| M2 | DONE | State graph, recon, auth/session, endpoint graph, coverage tracking, cross-persona ID harvesting, BOLA consumer queue (10/10). |
| M3 | DONE | CSRF/webhook/open-redirect/write-BOLA/race/noise probes; SSRF/XXE realism; spec contracts and probes3 merged. |
| M4 | DONE | 1,724 templates, 492 modern CVE-named templates (493 unique modern CVE IDs), multi-framework AST, SAST→DAST bridge, Gate 6. |
| M5 | DONE | Board UI, board tools, deterministic 0-LLM posters, warm specialists/handoffs. Board 14 node + 15 tools + 9 execution + 1 Playwright. |
| M6 | PARTIAL | Deterministic gate and paired realism measured; post-race agentic matrix PENDING. |

**Release gate:** **876/876 PASS**, 0 fail, 0 skip, 0 orphans (`docs/reverify-v5.sh --full`). **This is not capability parity:** G4 (H/C recall) and G8 (chains) are still NOT MET; G5 (white-box) is unmeasured. Details: [VERIFICATION-v5.md §2](VERIFICATION-v5.md#2-release-gates-v5-target-vs-current).

---

## 2. What changed

- **Realism:** dev **86/172 (50.0%)**, held-out **87/171 (50.9%)**, both precision 100%, 0/62 and 0/63 decoy FPs, 0 unmatched. Gap **+0.9 pp** (G9 met).
- **H/C recall:** dev **64/117 = 54.7%**, held-out **65/124 = 52.4%**. G4 (≥65%) is still NOT MET.
- **Saturation suites:** XBEN **25/25** (parity restored), held-out SaaS **20/20** with **20/20 patches fixed**, `allPatches=fixed`.
- **Class highlights:** SSRF **12/12** after the realism merge (final scorecard 11/12), XXE **7/7**, BOLA **17/19**, SQLi **5/7**, stored XSS **6/6**, traversal **6/6**, mass assignment **6/11**.
- **Gate:** full deterministic gate **876/876**, 0 orphans; the current v5 glob independently runs **237/237**.
- **Secret evidence:** broker pre-redaction `secretMatches` fingerprints (`kind`, `sha256Prefix`, `fieldPath`, `count`) enable disclosure proofs without raw secrets.
- **Integrity fixes:** project-name escaping and tag-aware XSS monitors; SSRF/XXE app realism; decoy audit; worker-removal race/lifecycle fix.

---

## 3. Operational notes

- **Worktree setup:** symlink `node_modules` (and `worker/node_modules`) from the base checkout.
- **AST suites:** run `npm run worker:install` or link `worker/node_modules`.
- **Docker:** use `newgrp docker -c '<command>'`; plain `docker info` can return permission denied.
- **Agentic runs:** model profile + `--verifier docker` + `--isolate-data-dir`; `local-jq` + profile is inert and must fail fast.
- **Credentials:** model key under the Guardian data dir (`credentials/…`, mode 600); never print/copy/commit.
- **Salt:** `~/.config/guardian-bench/heldout.salt` (mode 600); env `GUARDIAN_RB_HELDOUT_SALT` only; never echo.
- **OOB:** harness binds one loopback canary port and passes it to the app allowlist; optional `GUARDIAN_CANARY_PORT` / `GUARDIAN_CANARY_DNS_PORT`; never bind off-loopback.
- **Loopback only:** no external target probing.
- **Artifacts:** copy structured scorecards out of `/tmp`; `/tmp` is ephemeral.

---

## 4. Open work, in order

1. **Realism recall:** raise H/C from 54.7% to ≥65% (grey) and measure ≥80% (white). Focus on `replay_spec_miss` and the zero classes (reflected XSS, business logic, workflow, command injection, JWT/auth bypass).
2. **White-box matrix:** run the 9 cells with `--mode white-box` and record recall/decoy FPs (G5).
3. **Chains:** 0/6 on both splits; finish chain planning/browser-chain verification and add chain fixtures (G8).
4. **Agentic post-fix matrix:** report separately when complete; do not reuse the stale pre-fix 12/117 baseline as current.
5. **Precision at scale:** keep the decoy audit as recall rises.
6. **Patch attribution:** report clean dismissals (18/20) separately; run a fresh all-patches pass.
7. **Gate coverage:** expand the gate script’s v5 row to include all 237 current v5 tests, or document the subset explicitly.
8. **Artifact durability:** move `/tmp` evidence into release storage.
9. **H/C parity:** overall gap is +0.9 pp, but H/C is −2.3 pp; track both.

---

## 5. Reproduction

Use [VERIFICATION-v5.md §8](VERIFICATION-v5.md#8-reproduction). Core commands:

```bash
# Official full gate (Docker + Playwright), 876/876 expected.
newgrp docker -c 'bash docs/reverify-v5.sh --full'

# Independent v5 suites (237/237 on this tree).
newgrp docker -c \
  'cd /path/to/guardian && export GUARDIAN_ALLOW_LOCAL_LAB=1 && node --test --test-concurrency=1 tests/v5-*.test.ts'

# Secret fingerprints (9/9).
node --test tests/v5-secret-meta.test.ts
```

---

## 6. Commit anchors

| Milestone | Commit | Role |
| :--- | :--- | :--- |
| M0 | `ac5cebd` / `795f7c6` / `36998da` | harness, isolation, preflight |
| M1 | `5dae946` / `0fd8a9d` / `4ad4078` | wiring, static audit, recon halt fix |
| M2 | `198cdad` / `e111d29` / `476e03c` | endpoint graph/coverage/ID harvest, auth |
| M3 | `5aa897c` / `769311c` / `253f6c6` / `09596ae` | probes, contracts, probes3/realism |
| M4 | `c19e98a` / `05f2e39` / `e3202d7` / `0797d70` | corpus, AST/bridge/Gate 6, wiring |
| M5 | `4b41388` / `b0b3cce` / `93ff078` / `f0e9bb7` | Board, tools, posters/warm specialists |
| M6 | `d54b463` / `84eb476` / `974904c` / `23dde15` | agentic matrix, gate/lifecycle, final gate |
| Secret meta | `e18a775` / `a7ccb5f` | fingerprints, merge |
| Docs | `agents/docs-v5` | this handover + `VERIFICATION-v5.md` |

---

## 7. Honest limitations

The release gate is green, but v5 is not capability-complete. Realistic all-severity recall is ~50%, H/C is 54.7% dev / 52.4% held-out against a 65% target, white-box is unmeasured, and chains are 0/6. The agentic baseline (12/117, 66.7% precision) predates the worker-removal race fix; the post-fix matrix is pending. Patch evidence includes two inconclusive retests and a replay-based all-patches pass. The official gate’s v5 row covers 118 tests; the full v5 glob is 237/237, so gate coverage should be expanded before the next release decision.
