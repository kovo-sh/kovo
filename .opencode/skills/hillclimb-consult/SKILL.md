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
