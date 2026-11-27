# reason-bench calibration (M4)

**Status:** deterministic floor + twin/soundness matrix recorded (2026-11-23); agentic calibration
cells remain **TODO** until the M4 agentic run.
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
export KOVO_ALLOW_LOCAL_LAB=1

# agentic runs need the Docker worker backend (worker sessions)
newgrp docker -c 'docker image inspect kovo-worker:v4 >/dev/null && echo worker-ok'

# enabled model profile (OpenRouter DeepSeek V4.1 Flash in the Kovo data dir)
export KOVO_DATA_DIR="$HOME/guardian-data"

# salted held-out seeds (owner-only file; NEVER print or commit the value)
export KOVO_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"
```

Typecheck floor before any calibration run:

```bash
node_modules/.bin/tsc -p benchmarks/reason-bench/tsconfig.json
```

Twin matrix (`run.ts selftest`, real site twins) and the acceptance suite:

```bash
# every real site twin on dev seeds 1,2 (exit 2 on any twin mismatch)
KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/reason-bench/run.ts selftest --app ledgerflow --seeds 1,2 \
  --site lf-01,lf-02,lf-03,lf-04,lf-05,lf-06,lf-07,lf-08,lf-09,lf-10,lf-11,lf-12,lf-13,lf-14
KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/reason-bench/run.ts selftest --app forgecloud --seeds 1,2 \
  --site fc-01,fc-02,fc-03,fc-04,fc-05,fc-06,fc-07,fc-08,fc-09,fc-10,fc-11,fc-12,fc-13,fc-14

# matrix + benign-soundness tests (the 30-seed sweep is opt-in)
KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/reason-bench/tests/
REASON_SOUNDNESS_SEEDS=1 KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/reason-bench/tests/soundness.test.ts
```

The `--site` filter lists the 14 real sites. The generic runner assumes a `vulnerable` twin fires,
which is not the contract for the five `*-d*` decoy look-alikes (they must be **0/0**); the decoy
role is asserted by `tests/{ledgerflow,forgecloud}.test.ts` and the soundness sweep instead.

| app | real site twins (seeds 1,2) | decoy look-alikes | benign reads per seed | oracle events (benign) | orphan records |
| --- | --- | --- | --- | --- | --- |
| ledgerflow | 56/56 | 5/5 at 0/0 | 114 (6 personas) | 0 | 0 |
| forgecloud | 56/56 | 5/5 at 0/0 | 95 (6 personas; revoked login denied) | 0 | 0 |

The 30-seed sweep (`REASON_SOUNDNESS_SEEDS=1`, seeds 1–30 × both apps) recorded 0 oracle events
and 0 orphan `kovo-qa-` records; teardown removes the materialized tree and closes the listener.

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
  --app all --seed 1 --mode grey-box --no-llm --concurrency 2 \
  --out-dir .kovo/reason-gate/dev \
  --json .kovo/reason-gate/dev/reason-report.json \
  --md   .kovo/reason-gate/dev/reason-report.md

# salted held-out
npm run benchmark:reason -- \
  --app all --held-out --seeds 1000042 --mode grey-box --no-llm --concurrency 2 \
  --out-dir .kovo/reason-gate/heldout \
  --json .kovo/reason-gate/heldout/reason-report.json \
  --md   .kovo/reason-gate/heldout/reason-report.md
```

`tests/anti-heuristic.test.ts` runs these two commands through the real CLI process boundary and
asserts **exit 0**, `gate.passed === true`, and `gate.recall <= 0.10`. A floor above the ceiling
makes the CLI exit **3**.

| split | cells | targets | confirmed | floor recall | ceiling | verdict | artifact |
| --- | --- | --- | --- | --- | --- | --- | --- |
| dev (seed 1) | 2 | 28 | 0 | 0.0% | 10% | PASS (exit 0) | `.kovo/reason-gate/dev/reason-report.json` |
| held-out (seed 1000042) | 2 | 28 | 0 | 0.0% | 10% | PASS (exit 0) | `.kovo/reason-gate/heldout/reason-report.json` |

**Per-site floor verdicts** (from the gate reports; `decoy` = mounted hardened for that seed, so it is
not a floor target; `missed` = scored target, no confirmed finding):

| app | site | family | class | dev seed 1 | held-out 1000042 |
| --- | --- | --- | --- | --- | --- |
| ledgerflow | lf-01 | A | business_logic | missed | missed |
| ledgerflow | lf-02 | A | business_logic | decoy | decoy |
| ledgerflow | lf-03 | A | business_logic | missed | missed |
| ledgerflow | lf-04 | A | business_logic | decoy | decoy |
| ledgerflow | lf-05 | A | workflow_bypass | missed | missed |
| ledgerflow | lf-06 | A | business_logic | missed | decoy |
| ledgerflow | lf-07 | B | auth_bypass | missed | missed |
| ledgerflow | lf-08 | B | bfla | missed | missed |
| ledgerflow | lf-09 | B | auth_bypass | missed | missed |
| ledgerflow | lf-10 | B | workflow_bypass | missed | missed |
| ledgerflow | lf-11 | D | webhook_forgery | missed | missed |
| ledgerflow | lf-12 | D | auth_bypass | missed | missed |
| ledgerflow | lf-13 | E | chain | missed | missed |
| ledgerflow | lf-14 | E | chain | missed | missed |
| ledgerflow | lf-d1 | A | business_logic | decoy | decoy |
| ledgerflow | lf-d2 | A | business_logic | missed | missed |
| ledgerflow | lf-d3 | A | workflow_bypass | missed | missed |
| ledgerflow | lf-d4 | D | path_traversal | decoy | missed |
| ledgerflow | lf-d5 | D | ssti | decoy | decoy |
| forgecloud | fc-01 | B | auth_bypass | decoy | decoy |
| forgecloud | fc-02 | C | bfla | missed | missed |
| forgecloud | fc-03 | C | bola | decoy | decoy |
| forgecloud | fc-04 | C | bola | missed | missed |
| forgecloud | fc-05 | C | bola | missed | decoy |
| forgecloud | fc-06 | C | info_disclosure | decoy | decoy |
| forgecloud | fc-07 | D | path_traversal | missed | missed |
| forgecloud | fc-08 | D | oauth | decoy | missed |
| forgecloud | fc-09 | D | mass_assignment | missed | missed |
| forgecloud | fc-10 | E | chain | missed | missed |
| forgecloud | fc-11 | E | chain | missed | missed |
| forgecloud | fc-12 | F | bola | missed | missed |
| forgecloud | fc-13 | F | bfla | missed | missed |
| forgecloud | fc-14 | F | workflow_bypass | missed | missed |
| forgecloud | fc-d1 | C | bola | missed | missed |
| forgecloud | fc-d2 | D | path_traversal | missed | decoy |
| forgecloud | fc-d3 | B | auth_bypass | missed | missed |
| forgecloud | fc-d4 | F | bfla | decoy | missed |
| forgecloud | fc-d5 | C | bola | missed | missed |

The hardened set is drawn per seed (five decoy units out of the 19 discovered site dirs), so a
canonical site can be a target on one split and a decoy on the other. The 2026-11-23 floor numbers
were produced by the commands above in a scratch output dir; re-running §1 repopulates
`.kovo/reason-gate/{dev,heldout}/` with the same report schema. `tests/anti-heuristic.test.ts`
re-runs both legs and asserts exit 0 + `recall <= 0.10`.

---

## 2. Agentic calibration grid (dev / held-out × grey / white × 10m / 45m)

Enter the docker group and export the environment once per shell; every command below then runs
with worker-socket access and the salted seeds:

```bash
newgrp docker          # once per shell (or prefix each command: newgrp docker -c '<command>')
export KOVO_ALLOW_LOCAL_LAB=1
export KOVO_DATA_DIR="$HOME/guardian-data"
export KOVO_RB_HELDOUT_SALT="$(cat "$HOME/.config/guardian-bench/heldout.salt")"
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
    --floor-from ".kovo/reason-gate/$split" \
    --out-dir ".kovo/reason-cal/$split-$mode-$duration" \
    --json ".kovo/reason-cal/$split-$mode-$duration/reason-report.json" \
    --md ".kovo/reason-cal/$split-$mode-$duration/reason-report.md"
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
| dev | grey-box | 10m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| dev | grey-box | 45m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| dev | white-box | 10m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| dev | white-box | 45m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| held-out | grey-box | 10m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| held-out | grey-box | 45m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| held-out | white-box | 10m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| held-out | white-box | 45m | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |

### Per-family A–F breakdown (confirmed / targets)

| family | dev grey 10m | dev grey 45m | dev white 10m | dev white 45m | held-out grey 10m | held-out grey 45m | held-out white 10m | held-out white 45m |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A (economic invariant) | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| B (state / temporal) | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| C (ABAC / cross-tenant) | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| D (protocol / parser) | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| E (causal chain) | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| F (code-level tenant bug) | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |

### Strict causal-chain completion

Chains count only when the `ChainOracle` observed every prerequisite hop **and** the final impact
in order (`plans/reason-bench.md` §3.4). Report chains separately from single-site recall.

| app | chain site | chain shape | floor | dev grey 45m | dev white 45m | held-out grey 45m | held-out white 45m |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ledgerflow | lf-13 | CWE-200 → CWE-863 | 0/0 | TODO | TODO | TODO | TODO |
| ledgerflow | lf-14 | CWE-79/918 → SSRF | 0/0 | TODO | TODO | TODO | TODO |
| forgecloud | fc-10 | CWE-918 → CWE-345 | 0/2 combined | TODO | TODO | TODO | TODO |
| forgecloud | fc-11 | CWE-200 → CWE-863 | 0/2 combined | TODO | TODO | TODO | TODO |

On the recorded build the ledgerflow floor reports `0/0` chain targets (no causal-chain specs were
materialized for lf-13/lf-14 on these seeds) and forgecloud reports `0/2` completed chains across
fc-10/fc-11. Chain completion is reported separately from single-site recall.

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
      --out-dir ".kovo/reason-curve/$budget-$duration"
  done
done

# merge every leg into one curve report (a floor run keeps ΔReasoning honest)
npm run benchmark:reason -- \
  --app all --seed 1 --mode grey-box --no-llm \
  --floor-from .kovo/reason-gate/dev \
  --curve-from .kovo/reason-curve \
  --out-dir .kovo/reason-curve/merged \
  --json .kovo/reason-curve/merged/reason-report.json \
  --md   .kovo/reason-curve/merged/reason-report.md
```

| budget | 10m | 30m | 45m | 60m |
| --- | --- | --- | --- | --- |
| $2 | TODO | TODO | TODO | TODO |
| $5 | TODO | TODO | TODO | TODO |
| $20 | TODO | TODO | TODO | TODO |

Each cell in the table is `confirmed / targets (recall) · $cost · $/additive confirmed`, copied
from the merged report's `curve` rows. Missing combinations stay `—` and are listed in the
report's `notes`.

---

## 4. How to fill this file

1. Run the gate legs (§1) and record `floor recall`, verdict, and per-site outcomes from
   `.kovo/reason-gate/<split>/reason-report.json` → `gate`.
2. Run the eight agentic legs (§2). Each report's `lift` block gives `floorRecall`,
   `deltaReasoning`, `costPerAdditiveConfirmedUsd`; `agentic` gives recall/precision/chains;
   `byMode[].aggregate.families` gives A–F.
3. Merge the curve legs (§3).
4. Replace every `TODO` with the report value and paste the artifact path next to the table.
   Leave `TODO` only for legs that were not run, and say which ones in a note.
5. Commit the filled file with the run's `gitSha` (from the report header) in the commit message.

**Do not** record: persona passwords, session cookies, the held-out salt, raw request/response
bodies, or probe payload strings. The harness already refuses to write artifacts containing the
salt or a persona secret.

---

## 5. Recorded baseline

| field | value |
| --- | --- |
| run date | 2026-11-23 (floor/matrix); agentic pending |
| harness git sha | `85588d53843e` (report `gitSha`) |
| model profile | `OpenRouter DeepSeek V4.1 Flash` (`deepseek/deepseek-v4.1-flash-1017`, protocol `responses`) |
| verifier backend | `docker` (worker sessions) for agentic; `--no-llm` floor needs no worker |
| dev floor recall | 0/28 (0.0%) |
| held-out floor recall | 0/28 (0.0%) |
| best agentic recall (dev) | TODO (M4 agentic run) |
| best agentic recall (held-out) | TODO (M4 agentic run) |
| best ΔReasoning | TODO (M4 agentic run) |
| 0 decoy FP confirmed? | yes — floor precision 100%, decoyFP 0 on both splits |
| orphan containers after run | 0 (`docker ps --filter label=kovo.workspace`; floor run uses no workers) |
