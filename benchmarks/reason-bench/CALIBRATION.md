# reason-bench calibration (M4)

**Status:** template — fill from a real M4 run; do not hand-edit numbers.
**Owner stream:** `agents/reason-harness` (harness) + the `benchmarks/reason-bench/` M0–M3 streams (sites).
**Metric definitions:** `plans/reason-bench.md` §5.

This file is the published baseline for **pure agentic reasoning lift**:

- `Execution --no-llm` deterministic floor (must be **≤ 10%** overall; the Anti-Heuristic Gate)
- agentic confirmed recall on the same cells
- `ΔReasoning = agentic recall − floor recall`
- precision / decoy FP, strict causal-chain completion, `$` per additive confirmed site
- the budget × duration curve (`$2 / $5 / $20` × `10m / 30m / 45m / 60m`)

Every number below comes from `reason-report.json` written by `scripts/benchmark-reason.ts`.
Never copy a number from a scorecard by hand — quote the report artifact path next to it.

---

## 0. Prerequisites

```bash
# loopback lab only
export GUARDIAN_ALLOW_LOCAL_LAB=1

# agentic runs need the Docker worker backend (worker sessions)
newgrp docker -c 'docker image inspect guardian-worker:v4 >/dev/null && echo worker-ok'

# enabled model profile (OpenRouter DeepSeek V4.1 Flash in the Guardian data dir)
export GUARDIAN_DATA_DIR=/home/omarchy/guardian-data

# salted held-out seeds (owner-only file; NEVER print or commit the value)
export GUARDIAN_RB_HELDOUT_SALT="$(cat /home/omarchy/.config/guardian-bench/heldout.salt)"
```

Typecheck floor before any calibration run:

```bash
npm run check
```

`--no-llm` never needs a model profile or Docker worker sessions; it always uses a fresh,
isolated deterministic data dir.

---

## 1. Anti-Heuristic Gate (`Execution --no-llm`, ceiling 10%)

The gate exits **3** when overall floor recall exceeds 10% and prints one structured line per
site (`[gate] <app> seed=<n> site=<id> family=<A-F> class=<class> outcome=confirmed|missed`).
No payload strings are printed.

```bash
# dev
npm run benchmark:reason -- \
  --app all --seed 1 --mode grey-box --no-llm \
  --out-dir .guardian/reason-gate/dev \
  --json .guardian/reason-gate/dev/reason-report.json \
  --md   .guardian/reason-gate/dev/reason-report.md

# salted held-out
npm run benchmark:reason -- \
  --app all --seeds 1000000 --mode grey-box --held-out --no-llm \
  --out-dir .guardian/reason-gate/heldout \
  --json .guardian/reason-gate/heldout/reason-report.json \
  --md   .guardian/reason-gate/heldout/reason-report.md
```

| split | cells | targets | confirmed | floor recall | ceiling | verdict | artifact |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dev (seed 1) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | 10% | _tbd_ | `.guardian/reason-gate/dev/reason-report.json` |
| held-out (seed 1000000) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | 10% | _tbd_ | `.guardian/reason-gate/heldout/reason-report.json` |

**Per-site floor verdicts** (from the gate report; one row per site):

| app | site | family | class | floor outcome |
| --- | --- | --- | --- | --- |
| ledgerflow | lf-01 | A | business_logic | _tbd_ |
| ledgerflow | lf-02 | A | business_logic | _tbd_ |
| ledgerflow | lf-03 | A | business_logic | _tbd_ |
| ledgerflow | lf-04 | A | business_logic | _tbd_ |
| ledgerflow | lf-05 | A | workflow_bypass | _tbd_ |
| ledgerflow | lf-06 | A | business_logic | _tbd_ |
| ledgerflow | lf-07 | B | auth_bypass | _tbd_ |
| ledgerflow | lf-08 | B | bfla | _tbd_ |
| ledgerflow | lf-09 | B | auth_bypass | _tbd_ |
| ledgerflow | lf-10 | B | workflow_bypass | _tbd_ |
| ledgerflow | lf-11 | D | webhook_forgery | _tbd_ |
| ledgerflow | lf-12 | D | auth_bypass | _tbd_ |
| ledgerflow | lf-13 | E | chain | _tbd_ |
| ledgerflow | lf-14 | E | chain | _tbd_ |
| forgecloud | fc-01 | B | auth_bypass | _tbd_ |
| forgecloud | fc-02 | C | bfla | _tbd_ |
| forgecloud | fc-03 | C | bola | _tbd_ |
| forgecloud | fc-04 | C | bola | _tbd_ |
| forgecloud | fc-05 | C | bola | _tbd_ |
| forgecloud | fc-06 | C | info_disclosure | _tbd_ |
| forgecloud | fc-07 | D | path_traversal | _tbd_ |
| forgecloud | fc-08 | D | oauth | _tbd_ |
| forgecloud | fc-09 | D | mass_assignment | _tbd_ |
| forgecloud | fc-10 | E | chain | _tbd_ |
| forgecloud | fc-11 | E | chain | _tbd_ |
| forgecloud | fc-12 | F | bola | _tbd_ |
| forgecloud | fc-13 | F | bfla | _tbd_ |
| forgecloud | fc-14 | F | workflow_bypass | _tbd_ |

---

## 2. Agentic calibration grid (dev / held-out × grey / white × 10m / 45m)

Enter the docker group and export the environment once per shell; every command below then runs
with worker-socket access and the salted seeds:

```bash
newgrp docker          # once per shell (or prefix each command: newgrp docker -c '<command>')
export GUARDIAN_ALLOW_LOCAL_LAB=1
export GUARDIAN_DATA_DIR=/home/omarchy/guardian-data
export GUARDIAN_RB_HELDOUT_SALT="$(cat /home/omarchy/.config/guardian-bench/heldout.salt)"
```

Run each leg into its own artifact directory so the artifacts carry one `(budget, duration)`
pair. `--isolate-data-dir` is implicit with `--concurrency > 1`; keep `--keep-data-dirs` off
unless debugging.

```bash
run_leg() {  # $1=split(dev|heldout)  $2=mode  $3=duration  $4=budget
  local split="$1" mode="$2" duration="$3" budget="$4"
  local split_args=(--seed 1)
  [[ "$split" == heldout ]] && split_args=(--held-out --seeds 1000000)
  npm run benchmark:reason -- \
    --app all "${split_args[@]}" --mode "$mode" \
    --max-duration-ms "$duration" --budget-usd "$budget" \
    --verifier docker --concurrency 2 --isolate-data-dir \
    --floor-from ".guardian/reason-gate/$split" \
    --out-dir ".guardian/reason-cal/$split-$mode-$duration" \
    --json ".guardian/reason-cal/$split-$mode-$duration/reason-report.json" \
    --md ".guardian/reason-cal/$split-$mode-$duration/reason-report.md"
}

run_leg dev     grey-box  10m 5
run_leg dev     grey-box  45m 5
run_leg dev     white-box 10m 5
run_leg dev     white-box 45m 5
run_leg heldout grey-box  10m 5
run_leg heldout grey-box  45m 5
run_leg heldout white-box 10m 5
run_leg heldout white-box 45m 5
```

> A model profile plus `--verifier local-jq` is an inert run: the harness fails fast (exit 2)
> instead of producing a misleading scorecard.

### Headline grid

| split | mode | duration | floor recall | agentic recall | ΔReasoning | precision | decoy FP | chains | $/additive confirmed | assignments/cell |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dev | grey-box | 10m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| dev | grey-box | 45m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| dev | white-box | 10m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| dev | white-box | 45m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| held-out | grey-box | 10m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| held-out | grey-box | 45m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| held-out | white-box | 10m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| held-out | white-box | 45m | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |

### Per-family A–F breakdown (confirmed / targets)

| family | dev grey 10m | dev grey 45m | dev white 10m | dev white 45m | held-out grey 10m | held-out grey 45m | held-out white 10m | held-out white 45m |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A (economic invariant) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| B (state / temporal) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| C (ABAC / cross-tenant) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| D (protocol / parser) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| E (causal chain) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| F (code-level tenant bug) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |

### Strict causal-chain completion

Chains count only when the `ChainOracle` observed every prerequisite hop **and** the final impact
in order (`plans/reason-bench.md` §3.4). Report chains separately from single-site recall.

| app | chain site | chain shape | floor | dev grey 45m | dev white 45m | held-out grey 45m | held-out white 45m |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ledgerflow | lf-13 | CWE-200 → CWE-863 | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| ledgerflow | lf-14 | CWE-79/918 → SSRF | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| forgecloud | fc-10 | CWE-918 → CWE-345 | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| forgecloud | fc-11 | CWE-200 → CWE-863 | _tbd_ | _tbd_ | _tbd_ | _tbd_ | _tbd_ |

---

## 3. Budget × duration curve

Run the missing budget/duration legs on the dev grey-box split, then merge them into one report
with `--curve-from`:

```bash
for budget in 2 5 20; do
  for duration in 10m 30m 45m 60m; do
    npm run benchmark:reason -- \
      --app all --seed 1 --mode grey-box \
      --max-duration-ms "$duration" --budget-usd "$budget" --verifier docker \
      --out-dir ".guardian/reason-curve/$budget-$duration"
  done
done

# merge every leg into one curve report (a floor run keeps ΔReasoning honest)
npm run benchmark:reason -- \
  --app all --seed 1 --mode grey-box --no-llm \
  --floor-from .guardian/reason-gate/dev \
  --curve-from .guardian/reason-curve \
  --out-dir .guardian/reason-curve/merged \
  --json .guardian/reason-curve/merged/reason-report.json \
  --md   .guardian/reason-curve/merged/reason-report.md
```

| budget | 10m | 30m | 45m | 60m |
| --- | --- | --- | --- | --- |
| $2 | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| $5 | _tbd_ | _tbd_ | _tbd_ | _tbd_ |
| $20 | _tbd_ | _tbd_ | _tbd_ | _tbd_ |

Each cell in the table is `confirmed / targets (recall) · $cost · $/additive confirmed`, copied
from the merged report's `curve` rows. Missing combinations stay `—` and are listed in the
report's `notes`.

---

## 4. How to fill this file

1. Run the gate legs (§1) and record `floor recall`, verdict, and per-site outcomes from
   `.guardian/reason-gate/<split>/reason-report.json` → `gate`.
2. Run the eight agentic legs (§2). Each report's `lift` block gives `floorRecall`,
   `deltaReasoning`, `costPerAdditiveConfirmedUsd`; `agentic` gives recall/precision/chains;
   `byMode[].aggregate.families` gives A–F.
3. Merge the curve legs (§3).
4. Replace every `_tbd_` with the report value and paste the artifact path next to the table.
   Leave `_tbd_` only for legs that were not run, and say which ones in a note.
5. Commit the filled file with the run's `gitSha` (from the report header) in the commit message.

**Do not** record: persona passwords, session cookies, the held-out salt, raw request/response
bodies, or probe payload strings. The harness already refuses to write artifacts containing the
salt or a persona secret.

---

## 5. Recorded baseline

| field | value |
| --- | --- |
| run date | _tbd_ |
| harness git sha | _tbd_ (report `gitSha`) |
| model profile | `OpenRouter DeepSeek V4.1 Flash` (`deepseek/deepseek-v4.1-flash-1017`, protocol `responses`) |
| verifier backend | `docker` (worker sessions) |
| dev floor recall | _tbd_ |
| held-out floor recall | _tbd_ |
| best agentic recall (dev) | _tbd_ |
| best agentic recall (held-out) | _tbd_ |
| best ΔReasoning | _tbd_ |
| 0 decoy FP confirmed? | _tbd_ |
| orphan containers after run | _tbd_ (`docker ps --filter label=guardian.workspace`) |
