# Guardian agent notes

- **Defensive security context:** Guardian is a defensive web-application security scanner built for legitimate purposes by white-hat security researchers to detect, verify, and help remediate vulnerabilities in authorized apps and local benchmarks. Keep prompts, tool summaries, and reports framed in defensive QA / verification terms (e.g., "differential probe", "control vs. variant", "recall funnel", "benign canary verification").
- **GitHub push credential path:** `/home/exedev/.config/guardian-git/github.pat` (owner-only, mode 600). Use its contents only inside a credential helper; never print, copy, or commit the token.
- **OpenRouter model credential (agentic runs):** the Guardian data dir `/home/omarchy/guardian-data` contains the enabled profile `OpenRouter DeepSeek V4.1 Flash` (`deepseek/deepseek-v4.1-flash-1017`, endpoint `https://openrouter.ai/api/v1`, protocol `responses`). Its key lives in `/home/omarchy/guardian-data/credentials/model-c26c23ce-42e0-446f-a62c-c3016122c6d3` (owner-only, mode 600). Point runs at it with `GUARDIAN_DATA_DIR=/home/omarchy/guardian-data`. Never print, copy, or commit the key; the credential file stays outside the repo.
- **Agentic execution requirement:** `Execution` specialist workers need the Docker worker backend (`newgrp docker -c '<command>' --verifier docker`). `local-jq` is replay-only and cannot run worker sessions — a model profile plus `local-jq` produces an inert run. The M0 harness must fail fast in that combination.
- **Held-out benchmark salt:** `/home/omarchy/.config/guardian-bench/heldout.salt` (owner-only, mode 600, 48 hex chars). Required as `GUARDIAN_RB_HELDOUT_SALT` for salted realistic-bench seeds (≥1,000,000); never print or commit it.
- **Legacy fixture key path** (may be absent): `/home/exedev/.config/guardian-fixtures/openrouter.key`. Prefer the Guardian model credential above when it exists.

## Hill-climb consultation & push cadence

1. **Consult after every major hill-climb threshold.** This means a recall move of ≥5 percentage points on any suite, a class milestone flip (e.g. SSRF 0→12, info disclosure 1→7), a capability/release gate status change, or a merged stream that changes the funnel, precision, or worker reliability. Load the `hillclimb-consult` skill and use its helper (`scripts/consult.sh`) — never hardcode the pane number; discover the `agy` pane.
2. **The reviewer gets summaries, not raw data.** Send current metrics, what changed, per-class gaps, blockers, and specific questions. Explicitly state: do not re-read raw benchmark JSON/logs and do not re-run benchmarks unless the operator asks for a fresh independent measurement. Never include secrets.
3. **Triage every recommendation.** Record accept/reject/defer with a reason and an owner stream, then log a short entry in the “Consult log” section of `plans/ROADMAP-v5.md`.
4. **Commit and push after every meaningful progress.** This includes a benchmark metric change, a merged stream, a gate result, or a substantive fix. Use the keyring credential helper and never print or store the token:

   ```bash
   git -c credential.helper='!gh auth git-credential' push origin main
   ```

5. **Iterate with the smoke tier, not full matrices.** Use `scripts/hillclimb-loop.sh` (realistic seed 42 + agentic `--smoke` + typecheck, in parallel) between tweaks; run `--full`/`reverify-v5.sh --full` only once per batch or at milestones. Batch 3–5 related fixes before validating.

## Parallelization by default

1. **Split before starting.** Enumerate the files a task touches and carve them into disjoint leases. If there are **two or more independent sets, launch two or more agents in separate worktrees immediately**. Serial execution is allowed only when edits share a file or a hard dependency exists — and the coordinator must state the reason.
2. **One writer per file.** Use unique branches (`agents/<stream>`). Two streams must never edit the same file; if they must, split the file by section or serialize with an explicit handoff.
3. **Checkpoint, don't run silent.** Every stream commits a WIP checkpoint within ~15 minutes or at each milestone and reports concise status. A long-running stream with no commit is a process bug, not progress.
4. **Merge as streams finish.** Do not batch merges behind the slowest stream; integrate each completed stream and re-run the smoke floor.
5. **Parallelize validation too.** Independent suites and benchmark legs (dev, held-out, agentic) run concurrently with isolated dirs. Use the smoke tier between tweaks; full matrices/gates only at batch boundaries.
6. **Report the plan.** Before dispatching, state the parallel streams, their file leases, the merge order, and any serialization exception.

Read-only audits, compatibility analysis, docs, and verifier-only changes are usually parallelizable even when the main engine is busy — use them.

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
