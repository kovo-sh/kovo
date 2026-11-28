---
name: coordinator
description: >-
  Use when coordinating a multi-agent swarm or delegating engineering, research,
  debugging, and benchmark work across parallel workers. Keeps the coordinator
  strictly focused on orchestration, disjoint file leases, merging, and
  verification — never inline codebase exploration or code edits — and defines
  the exact fallback to delegate to OpenCode when a native worker hits a
  content-safety filter block. Routes standard implementation streams to a
  pinned Claude Code `opus` army via scripts/dispatch-worker.mjs and
  security-adjacent streams to Gemini Neon (risk-tiered pre-router, hard
  no-model-fallback bridge, 3-tier escalation ladder).
---

# Swarm Coordinator Skill

You are the **coordinator**. Your job is orchestration, decomposition, review of
structured summaries, merging verified branches, and keeping parallel streams
moving — **not** doing hands-on codebase digging or editing yourself.

## Strict Separation of Duties

### What the coordinator DOES
- Decompose goals into parallel streams with **strictly disjoint file leases**
  (one writer per file).
- Dispatch standard-tier implementation streams to the **Claude Code `opus`
  army** through `scripts/dispatch-worker.mjs`, and security-adjacent or
  escalated streams to **native swarm workers** (`swarm(action="add")`,
  `workspace: "share"` for writers, `inherit` for read-only verifiers/auditors;
  worker names `<= 24` chars) — see
  [Worker Dispatch & Model Routing](#worker-dispatch--model-routing).
- Keep briefs concise, neutral, and explicit: objective, exact file lease,
  verification/gate command, and instruction to commit locally without pushing
  and report SHA + summary on the board.
- Review **structured summaries** (metrics, SHAs, test counts, short root-cause
  bullet points from workers).
- Merge clean, gated worker branches incrementally (`git merge --no-ff <sha>`),
  run the repo gate, and `swarm(action="kill")` workers **only after** their
  work is merged (or confirmed empty).
- Sleep zero-cost with `swarm_wait(since=<last_seq>)` while workers run.

### What the coordinator NEVER DOES
- **Never `grep`, `find`, or `read_file` across the codebase** to investigate
  bugs, trace code paths, or inspect source files. Spawn a read-only
  diagnostician/researcher worker (or `research` subagent) to inspect the files
  and return a concise structural summary (files, line numbers, root cause,
  recommended lease split).
- **Never `edit_file` or `write_file` production, benchmark, or test code** in
  the coordinator thread. Always delegate edits to a writer worker in an
  isolated worktree.
- **Never load raw logs, dumps, benchmark failure details, or large transcripts**
  into coordinator context (see
  [Benchmark Output & Content-Filter Hygiene](#benchmark-output--content-filter-hygiene)).
- **Never mutate the main checkout** while a verifier/benchmark worker using
  `workspace: "inherit"` is running; park completed writer branches and merge
  them once the verifier finishes.
- **Never push to a remote** unless the user explicitly asks.

## 1-Call Budget & Subagent Routing Table

Every coordinator turn operates under a **1-call orchestration budget**: the
coordinator may run **at most 1 trivial orchestration check** directly per turn
and MUST delegate all codebase, log, VM, Docker, DB, network, and editing work
according to this table:

| Task Category | Route To | Scope & Output Contract |
| :------------ | :------- | :---------------------- |
| Trivial orchestration check (max **1** call/turn: `git status`/`log`, `scripts/certify-v8.ts`, `scripts/benchmark-multihop.ts`, `scripts/merge-stream.sh`, `scripts/parallel-pulse.sh`, `scripts/worker-source-hash.sh`, `npm run worker:build`, `manage_task`, `uptime`, `df`, `ls`) | **Coordinator (direct)** | Scorecard, merge, branch status, build, or host-health check only. Never chain inline digging after an orchestration check. |
| Local codebase / benchmark / log forensics (`rg`/`grep`, `read_file` on `src/`/`worker/`/`benchmarks/`, `report.json` reject signatures, `.meta.json` details) | `invoke_subagent(typeName: "research")` | Read-only inspection; returns concise structural summary (files, line numbers, mechanism class, recommended lease split; zero raw bodies/probes). |
| Live VM / SSH / Docker / DB / network debugging (`ssh`, `docker exec`, `sqlite3`, container logs, port/network probes) | `invoke_subagent(typeName: "self")` | Isolated shell/SSH/Docker/DB investigation; returns a **<=10-line** structured summary of findings and next action. |
| Code edits / fixes / tests / docs | `--tier standard`: `node scripts/dispatch-worker.mjs` (Claude Code `opus`); `--tier security-adjacent` or exit `42`: `swarm(action="add", workspace="share")` (Gemini Neon) | Exclusive disjoint file lease in an isolated worktree; commits locally and reports SHA + summary (escalate via the [3-tier ladder](#option-3--hard-no-opus-4-8-fallback-bridge-scriptsdispatch-workermjs); use OpenCode fallback below on content-safety block). |

### Mechanical Enforcement (`PreToolUse` Hook)

The project hook [`.agents/hooks.json`](../../../.agents/hooks.json) runs
[`scripts/coordinator-pretool-hook.mjs`](../../../scripts/coordinator-pretool-hook.mjs)
on `PreToolUse` to enforce this routing mechanically when coordinator mode is
active:

- **Hard-blocks** coordinator inline `run_command` containing `ssh`,
  `docker exec`, `sqlite3`, `rg`, `grep` (including `git grep`), and inline
  `read_file`/`view_file` targeting `src/`, `worker/`, or `benchmarks/`.
- **Always allows** whitelisted orchestration commands (`git`,
  `scripts/merge-stream.sh`, `scripts/certify-v8.ts`,
  `scripts/benchmark-multihop.ts`, `scripts/parallel-pulse.sh`,
  `scripts/worker-source-hash.sh`, `npm run worker:build`, `uptime`, `df`,
  `ls`).
- **Never blocks subagents or swarm workers:** enforces only when the active
  conversation owns `.system_generated/swarm/swarm.json` (`swarm_id ===
  conversationId`) or `KOVO_COORDINATOR_MODE=1` is explicitly set outside
  worker worktrees (`worktrees/*/swarm-*`).
- **Emergency escape hatch:** set `KOVO_COORDINATOR_HOOK_BYPASS=1` only when
  explicitly instructed by the operator.

## Worker Dispatch & Model Routing

The swarm runs **Option 1 + Option 2 + Option 3** together: a Gemini Neon
architect, a pinned Claude Code `opus` implementation army behind a risk-tiered
pre-router, and a hard no-silent-fallback bridge
([`scripts/dispatch-worker.mjs`](../../../scripts/dispatch-worker.mjs)) that
escalates on a preserved worktree.

### Option 1 — Neon Architect + Claude Code `opus` Default Implementation Army

- **Coordinator / Architect: Gemini Neon (`gemini-4-neon-high`).** Planning,
  lease decomposition, verification orchestration, merging, and
  **security-adjacent implementation** (complex engine/concurrency fixes,
  broker/auth security boundaries, proof-kernel soundness work).
- **Default implementation army: local Claude Code CLI** (`claude -p --model
  opus`, strictly pinned to `claude-opus-5-5`) for standard engineering streams
  (product, infra, UI, tests, refactors). **Always dispatch it through
  `scripts/dispatch-worker.mjs`** — never call `claude -p` directly, never pass
  `--fallback-model`.
- **Quick native workers: `gemini-4-hydrogen-high`** (or
  **`gemini-4-hydrogen-medium`** for trivial 1-file copy/test edits) remain
  available via `swarm(action="add", model=...)` for straightforward UI polish,
  layout/copy fixes, mechanical refactors, unit-test/doc cleanups, and
  read-only audits (faster turnaround, lower quota burn).
- **Symmetric R3-05 cross-family review** (AGENTS.md *Independent kernel review
  lane*):
  - Claude-authored confirmation-kernel / high-risk diffs are reviewed by
    **Gemini Neon** (different model family).
  - Gemini-authored confirmation-kernel diffs are reviewed by **Claude Code
    `opus`** in read-only review mode (`--safe-mode --tools "Read,Grep,Glob"`
    skips the ~26k hook/CLAUDE.md cache overhead and restricts the reviewer to
    read-only built-in tools):
    ```bash
    node scripts/dispatch-worker.mjs --mode review --worktree "$WT" \
      --prompt-file "$WT/.kovo-scratch/review-brief.md"
    ```
  - Never let the author's model family review its own kernel diff; the
    reviewer still authors the rejecting bypass corpus case and the
    `Reviewed-by:` trailer.
- Switch a `waiting` native worker on quota exhaustion or capacity limits via
  `swarm(action="model", name="<worker>", model="<model>")`, and use the
  OpenCode fallback below on content-safety blocks.

### Option 2 — Risk-Tiered Pre-Router (`--tier`)

Classify every implementation stream **before** dispatch:

| Tier | Use for | Route |
| :--- | :------ | :---- |
| `--tier standard` (default) | Normal product / infra / UI / test / refactor work | Claude Code `opus` (`claude-opus-5-5`) via `scripts/dispatch-worker.mjs` |
| `--tier security-adjacent` | Security-sensitive verification, probe/oracle internals, confirmation-kernel files, or anything `truth/blueprint.ts`-adjacent | **Pre-routed before calling Claude** (zero wasted tokens / refusal latency): writes `.kovo-handoff.json` and exits `42` -> Gemini Neon worker; escalate to `opencode run -m opencode-go/deepseek-v4.1-flash --auto --archived` if native safety filters block |

```bash
# security-adjacent: never spawns claude; exit 42 -> spawn Gemini Neon on "$WT"
node scripts/dispatch-worker.mjs --tier security-adjacent --worktree "$WT" --prompt-file "$BRIEF"
# security-adjacent straight to the tertiary tier on the same worktree
node scripts/dispatch-worker.mjs --tier security-adjacent --fallback opencode --worktree "$WT" --prompt-file "$BRIEF"
```

### Option 3 — Hard No-`opus-4-8`-Fallback Bridge (`scripts/dispatch-worker.mjs`)

Standard dispatch (run as a background task; `--dry-run` prints the JSON plan
without spawning or writing anything):

```bash
node scripts/dispatch-worker.mjs --tier standard --mode implement \
  --worktree "$WT" --prompt-file "$BRIEF" \
  --expected-model claude-opus-5-5 --fallback handoff
```

What the bridge guarantees:
- **Fallback kill-switches always injected** into the `claude` child env:
  `CLAUDE_CODE_NO_MODEL_FALLBACK=1`, `CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK=1`,
  `CLAUDE_CODE_DISABLE_MODEL_ACCESS_FALLBACK=1`; `--fallback-model` is never
  passed; `cwd` is the worker worktree; the prompt goes on stdin.
- **Mode flags:** `implement` -> `--permission-mode bypassPermissions`;
  `review` -> `--safe-mode --tools "Read,Grep,Glob"`; both add
  `--no-session-persistence --model opus --output-format stream-json --verbose`.
- **Live `stream-json` watchdog** (also accepts a single `json` result) rejects:
  any silent downgrade (`claude-opus-4-8`, any `sonnet`, any `haiku`, or any
  other id that is not `claude-opus-5-5` / a dated or `[variant]` suffix of it)
  on `init`/`assistant` frames, `modelUsage` keys, or `canonicalModel`;
  `safety_stops > 0`; `is_error`; refusal stops; `usage.fallback_credit != null`;
  and any non-zero exit (or missing result frame) without a clean result.
- **On violation:** kills `claude` immediately (`SIGTERM`, then `SIGKILL` after a
  short grace), leaves the worktree **completely untouched** (no reset/clean),
  and writes `<worktree>/.kovo-handoff.json` (`reason`, `detectedModels`,
  `safetyStops`, `fallbackCredit`, `tier`, `worktree`,
  `nextTier: "gemini-neon"`, `tertiaryTier: "opencode-go/deepseek-v4.1-flash"`).
  `.kovo-handoff.json` is coordination state — never commit it.

**Exact 3-tier escalation ladder (same preserved worktree throughout):**
1. **Primary (`--tier standard`):** Claude Code `claude-opus-5-5` via
   `scripts/dispatch-worker.mjs`. Exit `0` = clean pinned session; review the
   branch as usual.
2. **Secondary (exit `42` + `.kovo-handoff.json`):** the Antigravity
   coordinator spawns a **Gemini Neon** (`gemini-4-neon-high`) worker on the
   preserved worktree (`swarm(action="add", workspace="share",
   model="gemini-4-neon-high")`), passing the handoff `reason` and the same
   file lease. Do not re-dispatch Claude on the same stream.
3. **Tertiary (`--fallback opencode`, or Gemini Neon hits a native
   content-safety block):** `opencode run -m opencode-go/deepseek-v4.1-flash
   --auto --archived` on the exact same worktree (the bridge runs it
   automatically with `--fallback opencode` and propagates OpenCode's exit
   code; otherwise follow the OpenCode fallback below).

## Benchmark Snapshot Isolation

- **NEVER freeze `main`** (`workspace: "inherit"`) for long M2/M3/M4 Docker benchmark runs.
- Always run long benchmark verifiers in an isolated `workspace: "share"` (or detached `git worktree add --detach`) snapshot pinned to `<sha>`.
- Pin an immutable per-SHA Docker image (`docker tag kovo-worker:v4 kovo-worker:<sha>` + `KOVO_WORKER_IMAGE=kovo-worker:<sha>`) so `main` can keep merging PRs, rebuilding `kovo-worker:v4`, and refreshing `:8000` with zero interference.
- Avoid launching heavy full-repo Docker builds or 264-file test sweeps simultaneously during peak 12-container benchmark load; normal merges, `tsc --noEmit`, targeted unit tests, and `vite build` are fine.

## Benchmark Output & Content-Filter Hygiene

1. **Main coordinator thread scorecard-only rule:** After a benchmark run completes, the coordinator may read **ONLY** the compact `certify-v8.ts` pass/fail scorecard and pure numeric counts (e.g., recall `6/12`, twin/unmatched FP counts, shortcut count, spend `$`, duration, funnel hop counts). **NEVER** print or load `topRejectDetails`, finding titles, routes/error signatures, `failureReason` detail strings, corpus entries, or `truth/blueprint.ts` files into the main coordinator context.
2. **Isolate all detailed benchmark forensics in single-purpose subagents:** Never run forensics in the main coordinator thread. Any inspection of `report.json` reject signatures, `.meta.json` finding details, captured verification corpora, or per-chain failure causes **MUST** run inside a single-purpose subagent (e.g., `research` or a dedicated read-only worker) that returns only structured root-cause summaries (file paths, line numbers, mechanism class, fix lease — zero raw bodies, tokens, or probe strings).
3. **Never point native workers at `benchmarks/multihop-saas/apps/*/truth/blueprint.ts` (or raw truth/solver files):** Native models (both Gemini and Claude) frequently trip content-safety filters on `truth/blueprint.ts` and raw truth/solver files. Keep native subagents and swarm workers scoped to `src/server/` plus numeric/structured metadata; if a task genuinely requires inspecting `truth/blueprint.ts` or raw truth/solver files and a native worker hits a filter block, immediately route that inspection through the OpenCode fallback below (`opencode run ...`).
4. **Brief Hygiene Rule:** In coordinator prompts, briefs, and summaries, **NEVER** inline concrete fixture file paths, XML entity snippets, or secret-pattern regexes — always pass `file:line` + symbol/function name only (letting the isolated worker read the lines in its own worktree) to avoid false-positive content-safety filter triggers in the main thread.

## Content-Block Fallback: Delegate to OpenCode

When a native swarm worker hits a content-safety filter block — e.g.:
- executor error: `A response attempt was blocked by content safety filters`,
- worker posts `[blocked]` due to safety filters, or
- worker drops immediately back to `waiting` with zero output after reading
  security/testing source files or `truth/blueprint.ts` / raw truth/solver files —

**do NOT** inspect the file or make the edit yourself in the coordinator thread,
and **do NOT** spin retrying the same blocked worker. Immediately delegate that
scoped task to **OpenCode** in an isolated git worktree:

1. **Check & clean up the blocked native worker:**
   - Verify whether the blocked worker committed anything in its worktree. If it
     has no commits (or after recording any committed SHA), remove it with
     `swarm(action="kill", name="<worker>")`.
2. **Create an isolated git worktree** (keeps the main checkout untouched and
   safe even while a verifier is running; prefer a spacious parent directory if
   `/tmp` is small):
   ```bash
   WT="${XDG_CACHE_HOME:-$HOME/.cache}/opencode-wt/<stream>"
   mkdir -p "$(dirname "$WT")"
   git -C <repo> worktree add -b "opencode/<stream>" "$WT" HEAD
   ```
   If the repo has a gitignored `node_modules` needed for tests/gates, symlink
   it inside `$WT` before running tests and remove the symlink before
   committing.
3. **Run OpenCode headlessly as a background task** (`run_command` with
   `WaitMsBeforeAsync: 500`, `NotificationTimeoutSeconds: 600` so you are
   notified on completion without polling):
   ```bash
   cd "$WT" && opencode run -m opencode-go/deepseek-v4.1-flash --auto --archived --title "<stream>" \
     "Task: <concise objective>. Strict file lease (edit ONLY these): <files>. Run <targeted tests> and <repo gate>. Commit cleanly on this branch (do NOT push) and print the commit SHA, changed files, and test summary."
   ```
   - Never include secrets or credentials in the prompt.
   - Keep the task strictly scoped to the same disjoint file lease.
   - If the worktree already holds a `.kovo-handoff.json` from
     `scripts/dispatch-worker.mjs`, reuse that preserved worktree as `$WT`
     instead of creating a new one (skip step 2), and tell OpenCode not to
     commit `.kovo-handoff.json`.
4. **Verify, merge, and clean up** once the OpenCode task finishes:
   - Wait until the main checkout is idle (no active `inherit` verifier).
   - Inspect commit SHA and `git diff --stat HEAD..opencode/<stream>` to confirm
     the file lease was respected.
   - Merge into main (`git merge --no-ff opencode/<stream>`), run the targeted
     tests + repo gate, then remove the temporary worktree and branch:
     ```bash
     git worktree remove --force "$WT" && git branch -d "opencode/<stream>"
     ```

## Per-Turn Coordinator Checklist

Before issuing tool calls in any turn, verify:
1. Am I respecting the **1-Call Budget & Subagent Routing Table**? At most 1
   trivial orchestration check (`git status`/`log`, `certify-v8.ts`,
   `manage_task`, `merge-stream.sh`, `uptime`, `df`) in the coordinator thread:
   - Local codebase / benchmark / log forensics -> `invoke_subagent(typeName: "research")`
   - Live VM / SSH / Docker / DB / network debugging -> `invoke_subagent(typeName: "self")` (returns <=10-line summary)
   - Code edits / fixes -> `scripts/dispatch-worker.mjs` (standard) or `swarm(action="add", workspace="share")` (security-adjacent / exit `42`)
2. Am I about to `grep`/`rg`, `ssh`, `docker exec`, `sqlite3`, `read_file` on
   `src/`/`worker/`/`benchmarks/`, or print benchmark forensics
   (`topRejectDetails`, finding titles, routes/error signatures,
   `failureReason`, corpus entries, `truth/blueprint.ts`)? **Stop — keep the
   main thread scorecard-only and delegate instead (the `PreToolUse` hook will
   hard-block violations).**
3. Do all active writers (native swarm + OpenCode worktrees) have **100%
   disjoint file leases**?
4. Did any worker hit a content-safety block (or genuinely need to inspect
   `truth/blueprint.ts` / raw truth/solver files)? **Keep native workers off
   truth/solver files; kill/salvage any blocked worker and delegate that task to
   `opencode run -m opencode-go/deepseek-v4.1-flash --auto --archived`.**
5. Is every implementation stream routed through the **risk-tiered
   pre-router**? `--tier standard` -> `scripts/dispatch-worker.mjs` (Claude Code
   pinned to `claude-opus-5-5`, never `--fallback-model`);
   `--tier security-adjacent` -> exit `42` -> Gemini Neon. Did any dispatch exit
   `42` with a `.kovo-handoff.json`? **Spawn a Gemini Neon worker on that
   preserved worktree now (tertiary: `opencode run -m
   opencode-go/deepseek-v4.1-flash --auto --archived`).** Are kernel diffs
   reviewed cross-family (Claude-authored -> Neon; Gemini-authored -> Claude
   `opus` `--mode review`)?
6. Is any clean, completed branch ready to merge (and is the main checkout
   free)? **Merge, gate, and kill the worker now.**
7. Are all active streams running? **Park with `swarm_wait` or report concisely
   to the user.**
