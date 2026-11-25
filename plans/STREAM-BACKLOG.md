# Stream backlog (parallel dispatch queue)

Rule: keep at least **3 active streams** while any `ready` task has a free lease.
One stage per stream; split tasks that touch >2 files or span >1 milestone.
Leases are exclusive: a task may start only if its files are not held by an active stream.

Format:
`- [ ] <task> | status: ready|active|blocked | lease: <files> | deps: <task ids or -> | stream: <branch or ->`

## Active (2026-11-24, `main` @ `fb93a8a`)

- [ ] `v7-smoke-fix` — Fix Tier-1 Smoke `--resume-snapshot` `conversion`/`floorPreserved` accounting bug (caught in Queue #14 Step 3) + update `VERIFICATION-v5.md` §V7.7 & `plans/STREAM-BACKLOG.md` | status: active | lease: `scripts/smoke-agentic.ts`, `tests/v7-tier1-throughput.test.ts`, `VERIFICATION-v5.md`, `plans/STREAM-BACKLOG.md` | deps: - | stream: `swarm/v7-smoke-fix`
- [ ] `v7-m1-spa` — SPA/client-side surface & agentic lift work on `swarm/v7-m1-spa` | status: active | lease: SPA recon / M1 lift slice | deps: - | stream: `swarm/v7-m1-spa`
- [ ] `queue-15-cert` — Next Unified Agentic Certification Matrices + Tier-1 Warm Smoke on `main` post-`fb93a8a` (+ `v7-smoke-fix`, `v7-m1-spa`) measuring recovered XSS floor (`f9dc5d4`) + M2/M1 lift | status: ready | lease: Docker benchmark slot | deps: `v7-smoke-fix` | stream: `@bench-verifier`

## Ready (dispatch when a lease frees)

- [ ] `v7-m0-cut3f` — Final Cut 3f `replay-verifier.ts` retirement (`2,657 LOC -> <1K LOC`) behind parity gates (hand off to OpenCode pane 3 after `swarm/v7-m1-spa` commits) | status: ready | lease: `src/server/replay-verifier.ts`, verifier tests | deps: - | stream: `swarm/v7-m0-cut3f`
- [ ] `tier1-precision-and-p50` — Triage Queue #14 Tier-1 warm `lift` `1 unmatchedFP` and `rotation/opsportal` `p50=268.2s` (>110s gate) | status: ready | lease: `src/server/oracle-invariants.ts`, `src/server/agent-session.ts` | deps: `v7-smoke-fix` | stream: -
- [ ] `tier1-calibration` — Tier-1 smoke calibration study (8 varied builds vs reference) | status: ready | lease: `scripts/smoke-agentic.ts`, traps | deps: `v7-smoke-fix`, `queue-15-cert` | stream: -

## Sequence after Queue #14 (`main` @ `fb93a8a`)

1. Merge `swarm/v7-smoke-fix` (resumed snapshot `conversion` fix + §V7.7 provenance) and `swarm/v7-m1-spa`.
2. Run Queue #15 on `main` post-`fb93a8a` to verify recovered XSS floor (`f9dc5d4`), M1 aggregate recall (`>= 40/59` dev / `>= 32/58` held-out @ 100%), and Tier-1 warm 8/8 gates.
3. Land `v7-m0-cut3f` (`replay-verifier.ts < 1K LOC`), triage remaining Tier-1 `lift` `unmatchedFP` / `opsportal` p50, then run Tier-1 calibration and begin v8 (`plans/v8.md`).

## Completed (through `main` @ `fb93a8a`)

- [x] `v7-hos07-fix` (`fb93a8a` / `5b77b1c`) — Bumped `BENCH_MAX_REQUESTS_DEFAULT 3800 -> 6000` (`4,228/6,000`, `0` budgetSkipped), added GraphQL object-scoped arg/variable recognition in `isObjectScopedRequest()` keeping bare collection GET fail-closed (`hos-02`), restored `held-out-saas --verify-patches` to **20/20 + 20/20 patches @ 100.0% precision**, and fixed stale assertions/teardown in `tests/v5-engine-coverage.test.ts` & `tests/v4-m4-surface-orchestration.test.ts` (36/36 PASS) | stream: `swarm/v7-hos07-fix`
- [x] `v7-m0-cut3e` (`f9dc5d4` / `e939298`) — Retired `browser_chain` & 4 legacy VMs from `src/server/replay-verifier.ts` (−806 LOC; now **2,657 LOC**, −1,611 LOC from 4,268) + fixed `4375eb8` auth reflected-XSS `browser_sink` regression (`acme.reflected-search-xss`, `og.account-search-xss`) | stream: `swarm/v7-m0-cut3e`
- [x] `v7-m2-chains` (`4f09411` / `78f6240`) — M2 white-box-first AST/RBAC diff analysis, typed multi-round 4-hop `ChainHops`, and `reason-bench` readiness | stream: `swarm/v7-m2-chains`
- [x] `v7-m4-ops` (`53ca9f2` / `d53e237`) — M4 production operations: signed scope, `<2s` kill switch, ZDR/TTL/audit, tenant isolation, coverage gaps, `ProofReceipt` export | stream: `swarm/v7-m4-ops`
- [x] `v8-plan` (`1a3cebc` / `4d4971d`) — Authored `plans/v8.md` multi-hop realistic SaaS architecture & benchmark plan | stream: `swarm/v8-plan`
- [x] `queue-14-cert` (`4010d05`) — Full 3-leg Unified Agentic Certification + Tier-1 Warm Smoke (`@bench-verifier`): **100.0% worst-run precision** across both Dev (**36/59**, `$1.716`) and Salted Held-Out (**29/58**, `shopflow` 100.0%, `$1.536`), **21/21** live `agent_script` `ProofReceipt` confirmations (`0` stalls, `0` crashes, `0` conflicts), net-new `acme.invoice-bola` (`CWE-639`) on both matrices, Tier-1 warm **5/8 PASS** (`throughput=12`, `trap-zero=0`, `paired-net-new` `+1`/`+1`, `crashes=0`, `cost` `$1.199`) | stream: `@bench-verifier`
- [x] `collection-bola-precision` (`4010d05`) — Fail closed on bare collection GET role-inversion BOLA/BFLA receipts without cross-tenant evidence (restored `shopflow` to 100.0% precision) | stream: `swarm/collection-bola-precision`
- [x] `v7-docs-update` (`643b142`) — Recorded verified v7 milestones and LOC reductions in `VERIFICATION-v5.md`, `plans/ROADMAP-v5.md`, `plans/STREAM-BACKLOG.md` | stream: `swarm/v7-docs-update`
- [x] `cut3d-browser-retire` (`13111e4`) — Routed `browser_chain` DOM proofs onto `browser_sink` floor recipe (unblocking Cut 3e VM deletion) | stream: `agents/cut3d-browser-retire`
- [x] `agentic-lift-oracles` (`56afe19`) — Wired `auth_bypass`, `conserved_balance` `race_burst`, POST SSTI, and concrete-ID floor dedupe | stream: `swarm/agentic-lift-oracles`

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
