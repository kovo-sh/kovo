# Stream backlog (parallel dispatch queue)

Rule: keep at least **3 active streams** while any `ready` task has a free lease.
One stage per stream; split tasks that touch >2 files or span >1 milestone.
Leases are exclusive: a task may start only if its files are not held by an active stream.

Format:
`- [ ] <task> | status: ready|active|blocked | lease: <files> | deps: <task ids or -> | stream: <branch or ->`

## Active (2026-11-24, `main` @ `eec6419`)

- [ ] `queue-13b-cert` — Final Unified Agentic Certification Matrices on `main` @ `eec6419` (Dev `>= 40/59`, Salted Held-Out `>= 32/58`, Tier-1 Smoke 8/8 warm agentic post-floor snapshots) | status: active | lease: Docker benchmark slot | deps: - | stream: `@bench-verifier`
- [ ] `v7-docs-update` — Record verified milestones through `eec6419` + Queue #13b pending section in `VERIFICATION-v5.md`, `plans/ROADMAP-v5.md`, `plans/STREAM-BACKLOG.md` | status: active | lease: `VERIFICATION-v5.md`, `plans/ROADMAP-v5.md`, `plans/STREAM-BACKLOG.md` | deps: - | stream: `swarm/v7-docs-update`

## Ready (dispatch when a lease frees)

- [ ] `hos-07-probe-miss` — Investigate & restore `held-out-saas` `hos-07` probe-stage signal miss (`19/20 -> 20/20 + 20/20 patches`) | status: ready | lease: `scripts/benchmark-probes.ts` / engine probe slice | deps: - | stream: -
- [ ] `tier1-calibration` — Tier-1 smoke calibration study (8 varied builds vs reference) | status: ready | lease: `scripts/smoke-agentic.ts`, traps | deps: `queue-13b-cert` | stream: -
- [ ] `legacy-tests-cleanup` — Pre-existing suite: `tests/v5-engine-coverage.test.ts` 2 failures (content vs template param pick; OR-branch baseline) & `tests/v4-m4-surface-orchestration.test.ts` teardown hang | status: ready | lease: `tests/` | deps: - | stream: -

## Blocked (needs a test-migration stream first)

- [ ] `browser-vm-delete` — delete the remaining `browser_chain` interaction half of the legacy VM. Blocked: five e2e suites drive navigate/fill/click/dom-sink proofs through `verifyReplaySpec` directly (v3-protocol-browser, v4-e2e T2-05e/T3-05/T3-20, v4-m2 M2.6); each must move onto a `browser_sink` envelope + real `runBrowserSession` before the branch can go. | status: blocked | lease: replay-verifier, tests | stream: agents/cut3d-browser-retire

## Sequence after Queue #13b

1. Populate `VERIFICATION-v5.md` §V7.7 with Queue #13b exact Dev / Salted Held-Out / Tier-1 Smoke numbers and issue M1 certificate if `>= 40/59` dev, `>= 32/58` held-out, and `100%` precision pass.
2. Restore `held-out-saas` `hos-07` (`19/20 -> 20/20`).
3. Run Tier-1 smoke calibration study & continue remaining Cut 3 legacy VM retirements behind parity gates.

## Completed (through `main` @ `eec6419`)

- [x] `receipt-strict-and-lift` (`eec6419`) — Strict fail-closed `ProofReceipt` gate (closes `#150` receiptless `CWE-200` FP), `guardian_verify` `code`/`source` aliases + 3-error loop breaker, `alreadyConfirmed` cap `10 -> 30` + floor-confirmed BOLA/high-risk dispatch exclusion | stream: `swarm/receipt-strict-and-lift`
- [x] `hos-parity` (`c3da71f`) — Dotted JSON param nested object carrier fix restoring `held-out-saas` `hos-08` (`18 -> 19/20 + 19/20 patches @ 100%`) | stream: `agents/hos-parity`
- [x] `rename-test-accounts` (`5e8b25e`) — User-facing UI copy sweep `Personas -> Test Accounts` | stream: `swarm/rename-test-accounts`
- [x] `gv-ergonomics-fix` (`d4e7d31`) — Allow `guardian_verify` on final settlement turn, normalize SDK `path`/`url`/`target` args, inline signatures | stream: `swarm/gv-ergonomics-fix`
- [x] `create-project-github` (`0d3ceea`) — Optional GitHub repo picker inside `Create project` modal + removed confusing `Public` tag from `/` rows | stream: `swarm/create-project-github`
- [x] `new-run-dialog-a` (`476d9ff`, `e43440f`, `107cc31`) — Prototype A 3-up SVG `New run` dialog, global `.pw-modal` scroll fix, Readiness SVG tiles, removed `Public HTTPS` project tags | stream: `swarm/new-run-dialog-a`
- [x] `cut3d-race-retire` & `xben-25` SQL recovery (`51819a8`, `fabbb89`, `4945f93`, `0004070`) — Retired `race_burst` VM (−118 LOC; `replay-verifier.ts` `4,268 -> 3,507 LOC`) and restored `xben-25` **25/25 @ 100%** on Docker | stream: `swarm/cut3d-race-retire`
- [x] `brand-kovo-hunter` (`0d7e6bc`) & `project-header-dedup` (`2abe746`) — Kovo Hunter SVG mark/favicon kit + clean 2-row project header | stream: `swarm/brand-kovo-hunter`, `swarm/project-header-dedup`
- [x] `gv-eacces-fix` (`b0767c5`) & `gv-claims-fix` (`d1e0192`) — Fixed Docker `umask 0077` `EACCES` on `/guardian-rpc` and inline TS/Python script wrappers; unlocked first live Docker `proof_kind='agent_script'` `ProofReceipt` (`9828e5d`) | stream: `swarm/gv-eacces-fix`, `swarm/gv-claims-fix`
- [x] `ui-option3` Parts 1–3 + polish (`7fead98`, `e468ce2`, `03e9cdf`, `5ab19a6`) — Unified `.rw` left-rail `AppShell`, global `⌘K`, `/` Projects Home, 5-tab `/projects/$projectId`, `/settings` workbench refresh, two-card model picker, collapsible right pane | stream: `swarm/ui-option3-shell`, `swarm/ui-option3-project`, `swarm/ui-option3-settings`, `swarm/ui-polish-pass`
- [x] `device-pairing` (`3e075f0`) — Multi-device single-use 5-min ephemeral pairing links + `rotate-session` sign-out-other-devices | stream: `swarm/device-pairing`
- [x] `phase0-subdomain-discovery` (`266c478`) & `github-pat-ux` (`4d70351`) — Passive CT-log + live DNS subdomain discovery (`*.domain` opt-in + unchecked third-party SaaS CNAMEs with explicit approval) and `0600` vault Fine-Grained GitHub PAT + repo auto-discovery | stream: `swarm/phase0-subdomain-discovery`, `swarm/github-pat-ux`
- [x] `capability-misses` (`aca8262`) — Realism #2 `wan-oob` blind SQLi timing (**4/4 CAPABILITY PASS**, `0.0%` OOB FNR), JWT `alg:none` (new floor highs: dev **37/59**, salted held-out **29/58 @ 100%**), conserved-balance race rule | stream: `agents/capability-misses`
- [x] `exec-cleanup` (`2e1b2ed`) — `execution.ts` decomposition (`13,960 -> 5,388 LOC`, `−61.4%`, `−468` net `src/` LOC, 4/4 parity PASS) + 2-wave planner pipeline & false-dry stop fix | stream: `swarm/exec-cleanup`
- [x] `persona-binding` (`222bc90`) — Per-request persona jar isolation + fail-closed `broker.persona_scope_mismatch` + `state_restore` (resolved 26-vs-28 held-out erratum) | stream: `swarm/persona-binding`
- [x] `spec-authz` (`fe578db`) & `retest-receipts` (`d3e043d`) — Realism #4 **3/3** canonical (fallbacks deleted) & receipt-first retest migration | stream: `agents/spec-authz`, `agents/retest-receipts`
- [x] Prior v7/v6 completed streams: budget decoupling, agentic precision triage, floor restores, XSS all-occurrence scan, injection class precedence, Phase-0 crawl paging, Realism #3 capability, floor recipe library, brief slices, Realism #2 OOB attribution, worker-gate lease guard.
