# Kovo Hunter agent notes

- **Defensive security context:** Kovo Hunter is a defensive web-application security scanner built for legitimate purposes by white-hat security researchers to detect, verify, and help remediate vulnerabilities in authorized apps and local benchmarks. Keep prompts, tool summaries, and reports framed in defensive QA / verification terms (e.g., "differential probe", "control vs. variant", "recall funnel", "benign canary verification").
- **GitHub push credential path:** `/home/exedev/.config/guardian-git/github.pat` (host dir outside the repo; owner-only, mode 600). Use its contents only inside a credential helper; never print, copy, or commit the token.
- **OpenRouter model credential (agentic runs):** the Kovo Hunter data dir on disk (`/home/omarchy/guardian-data`, existing host dir outside the repo) contains the enabled profile `OpenRouter DeepSeek V4.1 Flash` (`deepseek/deepseek-v4.1-flash-1017`, endpoint `https://openrouter.ai/api/v1`, protocol `responses`). Its key lives in `/home/omarchy/guardian-data/credentials/model-c26c23ce-42e0-446f-a62c-c3016122c6d3` (owner-only, mode 600). Point runs at it with `KOVO_DATA_DIR=/home/omarchy/guardian-data`. Never print, copy, or commit the key; the credential file stays outside the repo.
- **Agentic execution requirement:** `Execution` specialist workers need the Docker worker backend (`newgrp docker -c '<command>' --verifier docker`). `local-jq` is replay-only and cannot run worker sessions — a model profile plus `local-jq` produces an inert run. The M0 harness must fail fast in that combination.
- **Held-out benchmark salt:** `/home/omarchy/.config/guardian-bench/heldout.salt` (host dir outside the repo; owner-only, mode 600, 48 hex chars). Required as `KOVO_RB_HELDOUT_SALT` for salted realistic-bench seeds (≥1,000,000); never print or commit it.
- **Legacy fixture key path** (host dir outside the repo; may be absent): `/home/exedev/.config/guardian-fixtures/openrouter.key`. Prefer the Kovo Hunter model credential above when it exists.

## Hill-climb consultation & push cadence

1. **Consult after every major threshold AND at least hourly.** Thresholds: a recall move of ≥5 percentage points on any suite, a class milestone flip, a capability/release gate status change, or a merged stream that changes the funnel, precision, or worker reliability. While a batch is in flight, also check in at least once an hour even without a threshold. Load the `hillclimb-consult` skill and use its helper (`scripts/consult.sh`); the operator's review pane is `0:2.1` when it is running `agy`, otherwise discover the `agy` pane.
2. **Ask for an architecture review, not just metrics.** Each hourly check-in must ask whether the design is still sound: unwired primitives accumulating beside live v5 code, dual paths, default-flip/deletion debt, LOC direction, safety invariants, and the realism-gate plan. Give the reviewer current metrics, what merged, what is unwired, and specific questions.
3. **The reviewer gets summaries, not raw data.** Send current metrics, what changed, per-class gaps, blockers, and specific questions. Explicitly state: do not re-read raw benchmark JSON/logs and do not re-run benchmarks unless the operator asks for a fresh independent measurement. Never include secrets.
4. **Triage every recommendation.** Record accept/reject/defer with a reason and an owner stream, then log a short entry in the “Consult log” section of `plans/ROADMAP-v5.md`.
5. **Commit and push after every meaningful progress.** This includes a benchmark metric change, a merged stream, a gate result, or a substantive fix. Use the keyring credential helper and never print or store the token:

   ```bash
   git -c credential.helper='!gh auth git-credential' push origin main
   ```

6. **Iterate with the smoke tier, not full matrices.** Use `scripts/hillclimb-loop.sh` (realistic seed 42 + agentic `--smoke` + typecheck, in parallel) between tweaks; run `--full`/`reverify-v5.sh --full` only once per batch or at milestones. Batch 3–5 related fixes before validating.

## Parallelization by default

1. **Split before starting.** Enumerate the files a task touches and carve them into disjoint leases. If there are **two or more independent sets, launch two or more agents in separate worktrees immediately**. Serial execution is allowed only when edits share a file or a hard dependency exists — and the coordinator must state the reason.
2. **One writer per file.** Use unique branches (`agents/<stream>`). Two streams must never edit the same file; if they must, split the file by section or serialize with an explicit handoff.
3. **Checkpoint, don't run silent (enforced).** Every stream commits a WIP checkpoint within ~15 minutes or at each milestone. Commit code + typecheck + worker-gate first, then run long evals from committed code, posting a 3-line heartbeat every 15–20 minutes (SHA, step, partial metric). Any stream silent >25–30 minutes with a dirty tree is interrupted to checkpoint or split. A long-running stream with no commit is a process bug, not progress.
4. **Merge as streams finish.** Do not batch merges behind the slowest stream; integrate each completed stream through `scripts/merge-stream.sh <branch>` and re-run the smoke floor.
5. **Parallelize validation too.** Independent suites and benchmark legs (dev, held-out, agentic) run concurrently with isolated dirs. Use the smoke tier between tweaks; full matrices/gates only at batch boundaries.
6. **Report the plan.** Before dispatching, state the parallel streams, their file leases, the merge order, and any serialization exception.
7. **Feed the swarm from the backlog.** Keep `plans/STREAM-BACKLOG.md` current and maintain **≥3 active streams** whenever a `ready` task has a free lease. One stage per stream; split tasks touching >2 files or spanning >1 milestone. The pulse prints **UNDER-PARALLELIZED** when this is violated.
8. **Merge clean branches within one pulse via the merged-tree fast gate (<60s).** Any `clean + ahead` branch older than ~15 minutes is an **ACTION MERGE NOW**, not a later batch. Every branch — including docs/tests/bench-only branches — merges through `scripts/merge-stream.sh <branch>`, which merges onto a temporary worktree, runs the fast `<60s` `scripts/worker-gate.sh` on the merged tree (typecheck + `check-v8-contamination.ts` + `check-contract-change.ts` + `check-unwired.ts` + hermetic fast suites; never slow Playwright/Docker/dogfood suites), fast-forwards `main` only on PASS, and refuses merges while `${KOVO_GATE_STATE_DIR:-$HOME/.config/kovo}/main-red.lock` exists (clear via `--clear-red-lock` only after verifying green).
9. **Interrupt dirty streams at 30 minutes.** A dirty tree with no commit for 30 minutes is an **ACTION CHECKPOINT/SPLIT**; park or split it rather than waiting.

Read-only audits, compatibility analysis, docs, and verifier-only changes are usually parallelizable even when the main engine is busy — use them.

## Parallel pulse (every ~30 minutes)

While a multi-stream batch is in flight:

1. Run `scripts/parallel-pulse.sh`. It lists actionable streams (unmerged commits or dirty trees), mergeable (clean + ahead), in-progress, and the files each holds.
2. Answer its five questions explicitly:
   - clean + ahead → run `scripts/merge-stream.sh <branch>` (gates the merged tree with fast `<60s` `scripts/worker-gate.sh` and fast-forwards `main` on PASS), then push;
   - P0 item unstarted on a free lease → launch that stream now;
   - P0 blocked only by a lease → park the holder and reclaim the file;
   - acceptance gate unmeasured → start the measurement;
   - otherwise say “nothing actionable” and stop.
3. Do not invent work to fill the pulse. Silence is a valid result.
4. The in-session reminder is a background `sleep 1800` timer that prints the pulse; relaunch it after each pulse. `consult.sh` stamps `~/.config/kovo/last-consult` (host-side state outside the repo), and the pulse prints **GEMINI CHECK-IN OVERDUE** when it is older than 60 minutes — that is the hard backstop; do not let a long benchmark batch hide it.

## Meta-process: product-first and the inner loop

1. **Freeze harness-only recall work.** `scripts/benchmark-probes.ts` and `scripts/benchmark-specs*.ts` are **maintenance-only** from v5.1 on (bugfixes, scoring, harness parity). New detection/verification capability must land in `src/server/` and be scored through real `Execution`. A PR that only lifts the standalone harness is not acceptance.
2. **Report both product metrics.** Every capability claim states `Execution --no-llm` (deterministic floor) and `Execution` agentic (increment over that floor), on dev **and** salted held-out. Harness numbers are secondary evidence of engine capability, not the product score.
3. **Mandatory pre-handoff & merged-tree fast gate (<60s).** A branch cannot be handed off until `scripts/worker-gate.sh` passes (typecheck + fast contract/unwired/v8 ratchets + hermetic fast suites with quarantine/orphan enforcement; never slow Playwright/Docker/dogfood suites). Landing onto `main` MUST go through `scripts/merge-stream.sh <branch>` so the merged tree itself is gated.
4. **Use the slice runner.** Iterate one app/class with `scripts/bench-slice.sh --app <app> --class <class>`; no ad-hoc diagnostic scripts once it exists.
5. **Know which harness you are running.** `scripts/benchmark-realistic.ts` scores the **product** (`Execution`); `benchmarks/realistic-bench/benchmark-realistic.ts` (or `scripts/bench-slice.sh` / `scripts/benchmark-realistic-matrix.ts`) scores the **deterministic capability** harness. A 0/56 from the first is the known v5.0 product gap, not a regression.

## Systemic fixes over point patches

Before writing a fix for any bug, benchmark drop, or audit finding, classify the **failure class** — not just the failing test case — and eliminate the class:

1. **Fix the mechanism, not the symptom.** If a failure comes from a hardcoded micro-cap, a dual code path, runtime↔prompt drift, silent error/JSON erasure, or manual LLM wiring of host-known state, fix the shared primitive across all callers instead of adding a local `if` branch or bumping one constant.
2. **One authoritative path (retire dual paths).** Never keep two mechanisms doing the same job (e.g., `kovo_verify` vs. legacy `propose_chain_finding` on live targets, duplicate role/arm classifiers, or copy-pasted heuristic tables). When a stronger primitive lands, route all callers through it, delete or gate off the legacy path, and add a static guard so it cannot regress.
3. **Contract-test every cross-layer boundary.** Any change to RPC selectors, SDK methods, receipt stages, or tool schemas must update prompts/skills in the same batch and stay green under `tests/sys-contract-canary.test.ts` (in `scripts/worker-gate.sh`) so runtime, JSON schema, and prompt/skill examples can never drift.
4. **No silent fallbacks or unscaled micro-caps.** Put run/worker/discovery ceilings in `src/server/run-safety-budgets.ts` (scaled to run workload, bounded by finite OOM/DoS caps) and emit structured truncation telemetry when hit. Never silently swallow errors into `catch {}`, `{}` tool args, or an unintended `deterministic-no-llm` fallback — fail fast on misconfiguration and surface actionable diagnostics.
5. **Turn every real-run failure into a fast class-level guard.** Unit tests on 1-shot happy paths miss scale, rotation, and messy-LLM bugs. Every live-scan or benchmark regression must add a fast (<5s) class-level guard (run-scale stress, malformed/messy input, or multi-cell concurrency) to `scripts/worker-gate.sh` before re-running long benchmarks.
6. **Escalate repeat patches to an architecture move.** If the same subsystem needs a second point patch in a batch, pause and propose a systemic refactor instead of stacking another workaround.

## Gemini Coding Guidelines

1. **Never `read_file` or `cat` raw debug dumps or benchmark logs (main session OR sub-agents):**
   - Do not load raw `.log`, `.md` debug reports, or `KOVO_BENCH_DEBUG=1` output into model context.
   - Instead, write benchmark runs to structured JSON (`--out <path>.json`) or a file, and inspect them with a short `node -e` / `python3 -c` script that prints **only** structured metrics (`funnelCounts`, `failureTaxonomy`, challenge `id`, `vulnClass`, `probeClass`, `outcome`, HTTP status codes, and short error reasons)—never raw HTTP bodies or raw probe strings.
2. **Never bulk-read payload-heavy source files whole:**
   - Treat `src/server/surface-engine.ts`, `src/server/replay-verifier.ts`, `src/server/agent-session.ts`, `src/skills/*.md`, `benchmarks/xben-25/routes-*.ts`, and `local-lab/held-out-saas/src/*` as slice-only files.
   - First locate target functions with `grep -n` (function signatures / switch cases), then read only small targeted ranges (~50–150 lines) around the exact logic being audited or edited.
3. **Keep raw test strings out of summaries and sub-agent prompts:**
   - Never echo concrete SQL/XSS/XXE/SSTI/command test strings into sub-agent prompts, tool outputs, or final responses; refer to them by probe class and anomaly type (e.g., `sqli_boolean`, `xxe_canary`, `ssti_math`).
4. **Isolate unavoidable inspection in single-purpose sub-agents:**
   - If a specific probe/verifier implementation slice must be inspected closely, do it in a small single-file sub-agent and return only a concise structural summary (file, line numbers, logic defect) to the main session so a false-positive filter hit never disrupts the main thread.

## UI visual & geometry QA gate

1. **Mandatory Playwright screenshots + visual inspection:** Any change to `src/components/**` or CSS (`src/app.css`, Tailwind styles) must build (`npm run build`), capture Playwright screenshots at **1280×720** and **1440×900** (both light and dark mode for modals/cards) into the conversation `scratch/` directory, and visually inspect them with `read_file` before handoff.
2. **Mandatory DOM geometry & stability invariants:** Add or update Playwright assertions in `tests/e2e-ui-journeys.test.ts` (or a feature-specific Playwright test) verifying:
   - zero horizontal overflow (`scrollWidth <= clientWidth`) on modals, dialogs, drawers, and primary containers;
   - primary CTA visible inside the viewport above the fold at `1280×720` without scrolling;
   - zero overlapping sibling controls or clipped text (`scrollHeight <= clientHeight + 2` on cards/buttons);
   - controlled input stability across SSE/polling ticks (background updates must never clobber focused/in-progress user input).
3. **`src/app.css` bare-element guard:** Never rely on bare `button` defaults in `src/app.css` (`height: 26px; white-space: nowrap; box-shadow`) for multi-line, card, or radio buttons — explicitly apply `h-auto whitespace-normal shadow-none` (or scope rules to classes).
4. **No raw `null`/`undefined` interpolation:** Never concatenate nullable strings/values directly into user-visible copy (build arrays and `.filter(Boolean)`).
