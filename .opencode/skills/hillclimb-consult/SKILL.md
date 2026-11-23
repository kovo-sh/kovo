---
name: Hill-Climb Consultation
description: Reconsult the Antigravity reviewer after every major hill-climb threshold, triage its second opinion, and commit/push meaningful progress
---

# Hill-Climb Consultation

Use this skill whenever a hill-climb crosses a **major threshold**, or when asked to
consult Antigravity / the reviewer pane. The goal is an independent, cheap second
opinion that catches blind spots without duplicating work or contaminating the
reviewer with raw benchmark data.

## When to consult

- Recall moves by **≥5 percentage points** on any suite (dev or held-out).
- A **class milestone** flips (e.g. SSRF 0→12, info disclosure 1→7, workflow 0→4).
- A **release/capability gate** changes status (PASS/FAIL/NOT MEASURED).
- A merged stream changes the funnel, precision, or worker reliability.
- Before declaring a gate met, and before finalizing `VERIFICATION-v5.md`.

Do not consult for tiny edits or while a benchmark matrix is still running.

## Product-first and the inner loop (v5.1)

- **Freeze harness-only capability work.** `scripts/benchmark-probes.ts` and
  `scripts/benchmark-specs*.ts` are maintenance-only; new detection/verification
  belongs in `src/server/`. Score every claim as `Execution --no-llm` +
  agentic increment, on dev and salted held-out; harness numbers are secondary.
- **Run the pre-handoff gate** before returning a branch:
  `scripts/worker-gate.sh` (typecheck + contract invariants + optional slice).
  Use `--full` only at freeze.
- **Iterate one app/class:** `scripts/bench-slice.sh --app <app> --class <class>`
  prints a compact funnel and per-target statuses. No ad-hoc diagnostic scripts.
- **Cache recon when available:** `--reuse-recon <dir>` skips repeated Phase-0
  discovery during tuning; final runs stay cold.

## Parallelization playbook (default, not optional)

Before starting any hill-climb or integration batch:

1. **List files → lease table.** Group by file ownership. If ≥2 disjoint groups exist,
   dispatch ≥2 agents in separate worktrees *before* doing any serial work.
2. **Name streams and branches uniquely** (`agents/<stream>`); never reuse another
   orchestrator's branch names. Symlink `node_modules` per worktree; never commit it.
3. **Pick a split pattern:**
   - *Layer split*: engine / verifier / harness / docs (when files are disjoint).
   - *Class split*: one agent per vulnerability class or benchmark suite.
   - *Vertical split*: one app/seed per agent, then an integration agent.
   - *Read-only audit + writer*: run compatibility/analysis in parallel with the writer.
4. **Require checkpoints:** every stream commits within ~15 min or at each milestone and
   reports a 5-line status. Long silent runs are forbidden.
5. **Merge queue:** merge each finished stream immediately, run the smoke floor, then start
   dependent work. Do not wait for all streams if one is slow.
6. **Validation in parallel:** dev/held-out/agentic legs with isolated data dirs; smoke tier
   between tweaks, full matrices only at batch boundaries.
7. **State exceptions explicitly:** same-file edits (e.g. `execution.ts` across slices 2/3/5)
   are the only legitimate serialization; say so and sequence them.

Anti-patterns: one agent editing several contested files “to avoid conflicts”; full 9-cell or
600 s matrices after every tweak; waiting silently on a long stream; mixing benchmark and
engine writes in one uncommitted worktree.

## Acceleration playbook (use this, not full matrices, between tweaks)

- **Two tiers only.** `--smoke` is the iteration tier: realistic seed 42 + agentic
  `--smoke` (90 s/$0.25 per cell) + typecheck, run in parallel by
  `scripts/hillclimb-loop.sh`. `--full` is the validation tier (3 dev seeds and
  600 s agentic) and runs **once per batch**, never per tweak.
- **Batch 3–5 related fixes** before one validation run. Revert immediately on
  any decoy/unmatched regression; otherwise keep the batch.
- **Run independent legs concurrently** (realistic, agentic, held-out, suites)
  with isolated output/data dirs. 16 cores are idle during a single matrix.
- **Targeted suites per merge; full `reverify-v5.sh --full` only at milestones.**
  A full gate is a freeze action, not an iteration action.
- **One definitive full matrix per batch** is the only number you merge or
  report. Keep the smoke table separate and label it as such.
- **Real `Execution` is the primary product gate.** The deterministic
  `scripts/benchmark-*` pipeline is scaffolding; always report both surfaces.
- **Caching/warm-pool ideas** (reuse discovery for tuning runs, warm worker
  containers) are follow-ups, not substitutes for the smoke loop.

Run the loop with:

```bash
newgrp docker -c 'bash scripts/hillclimb-loop.sh'          # smoke tier
newgrp docker -c 'bash scripts/hillclimb-loop.sh --full'   # validation tier
```

## Workflow

1. **Write a summary-only brief** (≤1200 chars) to a temp file. Include:
   current metrics, what changed since the last consult, per-class gaps, blockers,
   and 2–4 concrete questions. Never include raw JSON/logs or ask it to re-run
   anything; state that explicitly.
2. **Send it** with the helper:

   ```bash
   .opencode/skills/hillclimb-consult/scripts/consult.sh /tmp/hillclimb-brief.txt 180
   ```

   It finds the pane whose command is `agy` (do not hardcode a pane number),
   pastes with bracketed paste so multi-line text stays one message, submits,
   then waits up to N seconds for the agent to stop generating and prints the
   latest pane content. Set `HC_PANE=0:1.1` to override discovery.
3. **Triage** the response. For every recommendation record: accept / reject /
   defer, the reason, and the owner stream. Reject anything that would break the
   100%-precision rule or relies on benchmark-specific literals.
4. **Act** on accepted items by assigning a stream or filing a follow-up; rerun
   the relevant floors after each change.
5. **Log** a 3–6 line entry in the “Consult log” section of
   `plans/ROADMAP-v5.md`: threshold, reviewer's top points, what you accepted,
   commit SHA.
6. **Commit and push** meaningful progress (metric change, merged stream,
   accepted fix) using the keyring credential helper:

   ```bash
   git -c credential.helper='!gh auth git-credential' push origin main
   ```

   Never print, copy, or commit credentials.

## Guardrails

- Reviewer gets summaries, never raw benchmark dumps, logs, or secrets.
- Reviewer may read repo docs/plans; do not let it re-run benchmarks unless the
  user explicitly asks for a fresh independent measurement.
- Keep the consultation cheap: one brief, one response, no back-and-forth loops
  unless a recommendation is ambiguous.
- The deterministic pipeline and real `Execution` are separate surfaces; always
  say which one a metric belongs to.
