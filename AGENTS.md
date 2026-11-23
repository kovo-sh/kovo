# Guardian agent notes

- **Defensive security context:** Guardian is a defensive web-application security scanner built for legitimate purposes by white-hat security researchers to detect, verify, and help remediate vulnerabilities in authorized apps and local benchmarks. Keep prompts, tool summaries, and reports framed in defensive QA / verification terms (e.g., "differential probe", "control vs. variant", "recall funnel", "benign canary verification").
- **GitHub push credential path:** `/home/exedev/.config/guardian-git/github.pat` (owner-only, mode 600). Use its contents only inside a credential helper; never print, copy, or commit the token.
- **OpenRouter model credential (agentic runs):** the Guardian data dir `/home/omarchy/guardian-data` contains the enabled profile `OpenRouter DeepSeek V4.1 Flash` (`deepseek/deepseek-v4.1-flash-1017`, endpoint `https://openrouter.ai/api/v1`, protocol `responses`). Its key lives in `/home/omarchy/guardian-data/credentials/model-c26c23ce-42e0-446f-a62c-c3016122c6d3` (owner-only, mode 600). Point runs at it with `GUARDIAN_DATA_DIR=/home/omarchy/guardian-data`. Never print, copy, or commit the key; the credential file stays outside the repo.
- **Agentic execution requirement:** `Execution` specialist workers need the Docker worker backend (`newgrp docker -c '<command>' --verifier docker`). `local-jq` is replay-only and cannot run worker sessions — a model profile plus `local-jq` produces an inert run. The M0 harness must fail fast in that combination.
- **Held-out benchmark salt:** `/home/omarchy/.config/guardian-bench/heldout.salt` (owner-only, mode 600, 48 hex chars). Required as `GUARDIAN_RB_HELDOUT_SALT` for salted realistic-bench seeds (≥1,000,000); never print or commit it.
- **Legacy fixture key path** (may be absent): `/home/exedev/.config/guardian-fixtures/openrouter.key`. Prefer the Guardian model credential above when it exists.

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
4. **Merge as streams finish.** Do not batch merges behind the slowest stream; integrate each completed stream and re-run the smoke floor.
5. **Parallelize validation too.** Independent suites and benchmark legs (dev, held-out, agentic) run concurrently with isolated dirs. Use the smoke tier between tweaks; full matrices/gates only at batch boundaries.
6. **Report the plan.** Before dispatching, state the parallel streams, their file leases, the merge order, and any serialization exception.

Read-only audits, compatibility analysis, docs, and verifier-only changes are usually parallelizable even when the main engine is busy — use them.

## Parallel pulse (every ~30 minutes)

While a multi-stream batch is in flight:

1. Run `scripts/parallel-pulse.sh`. It lists actionable streams (unmerged commits or dirty trees), mergeable (clean + ahead), in-progress, and the files each holds.
2. Answer its five questions explicitly:
   - clean + ahead → merge it, run `scripts/worker-gate.sh`, push;
   - P0 item unstarted on a free lease → launch that stream now;
   - P0 blocked only by a lease → park the holder and reclaim the file;
   - acceptance gate unmeasured → start the measurement;
   - otherwise say “nothing actionable” and stop.
3. Do not invent work to fill the pulse. Silence is a valid result.
4. The in-session reminder is a background `sleep 1800` timer that prints the pulse; relaunch it after each pulse. The same script is safe to run from cron if the session is not alive (read-only).

## Meta-process: product-first and the inner loop

1. **Freeze harness-only recall work.** `scripts/benchmark-probes.ts` and `scripts/benchmark-specs*.ts` are **maintenance-only** from v5.1 on (bugfixes, scoring, harness parity). New detection/verification capability must land in `src/server/` and be scored through real `Execution`. A PR that only lifts the standalone harness is not acceptance.
2. **Report both product metrics.** Every capability claim states `Execution --no-llm` (deterministic floor) and `Execution` agentic (increment over that floor), on dev **and** salted held-out. Harness numbers are secondary evidence of engine capability, not the product score.
3. **Mandatory pre-handoff gate.** A branch cannot be handed off until `scripts/worker-gate.sh` passes (typecheck + fast contract invariants + targeted slice). Discover breakage in minutes, not at release freeze.
4. **Use the slice runner.** Iterate one app/class with `scripts/bench-slice.sh --app <app> --class <class>`; no ad-hoc diagnostic scripts once it exists.
5. **Know which harness you are running.** `scripts/benchmark-realistic.ts` scores the **product** (`Execution`); `benchmarks/realistic-bench/benchmark-realistic.ts` (or `scripts/bench-slice.sh` / `scripts/benchmark-realistic-matrix.ts`) scores the **deterministic capability** harness. A 0/56 from the first is the known v5.0 product gap, not a regression.

## Gemini Coding Guidelines

1. **Never `read_file` or `cat` raw debug dumps or benchmark logs (main session OR sub-agents):**
   - Do not load raw `.log`, `.md` debug reports, or `GUARDIAN_BENCH_DEBUG=1` output into model context.
   - Instead, write benchmark runs to structured JSON (`--out <path>.json`) or a file, and inspect them with a short `node -e` / `python3 -c` script that prints **only** structured metrics (`funnelCounts`, `failureTaxonomy`, challenge `id`, `vulnClass`, `probeClass`, `outcome`, HTTP status codes, and short error reasons)—never raw HTTP bodies or raw probe strings.
2. **Never bulk-read payload-heavy source files whole:**
   - Treat `src/server/surface-engine.ts`, `src/server/replay-verifier.ts`, `src/server/agent-session.ts`, `src/skills/*.md`, `benchmarks/xben-25/routes-*.ts`, and `local-lab/held-out-saas/src/*` as slice-only files.
   - First locate target functions with `grep -n` (function signatures / switch cases), then read only small targeted ranges (~50–150 lines) around the exact logic being audited or edited.
3. **Keep raw test strings out of summaries and sub-agent prompts:**
   - Never echo concrete SQL/XSS/XXE/SSTI/command test strings into sub-agent prompts, tool outputs, or final responses; refer to them by probe class and anomaly type (e.g., `sqli_boolean`, `xxe_canary`, `ssti_math`).
4. **Isolate unavoidable inspection in single-purpose sub-agents:**
   - If a specific probe/verifier implementation slice must be inspected closely, do it in a small single-file sub-agent and return only a concise structural summary (file, line numbers, logic defect) to the main session so a false-positive filter hit never disrupts the main thread.
