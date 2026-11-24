# Smoke battery (three tiers)

`npm run smoke:agentic -- [flags]` is the fast product-first inner loop. It is
deliberately separate from full benchmark matrices: Tier 0 is free and deterministic,
Tier 1 is the ~6 minute / ~$1 pre-handoff signal, and Tier 2 is documentation-only.

Defensive QA context: every target is a synthetic loopback lab. The battery measures
whether a defensive scanner over-claims; it never attacks third-party systems.

## Tier 0 — under 90 s, $0

1. `scripts/worker-gate.sh` — typecheck + fast contract invariants.
2. `benchmarks/realism-suite/traps/fp-archetypes.json` — six past over-claim
   archetypes replayed through the shared Oracle invariants:
   - 2FA endpoint 2xx without enrollment
   - `amount:-1` mutation echo
   - BFLA 2xx-only with no impact
   - mass-assignment echo with no persistence
   - Bearer-authenticated "CSRF"
   - public-route tenant canary

Each archetype must be **dismissed**. If any confirms, Tier 0 exits non-zero. The
runner calls the exported validators in `src/server/oracle-invariants.ts`; it never
spawns a model or a worker.

```bash
npm run smoke:agentic -- --tier 0
```

## Tier 1 — ~6 min, ~$1, four parallel cells

| Cell | Target | Budget | Gate |
| --- | --- | --- | --- |
| `lift` | acme-saas post-floor snapshot | 300 s | paired net-new, floor preservation, precision 100% |
| `rotation` | shopflow **or** opsportal post-floor snapshot | 300 s | precision 100% |
| `trap` | hardened zero-vuln fixture with writable-looking decoys | 240 s | **0 confirmed** |
| `micro` | realism #2 async OOB, #3 staging race/write-BOLA (300 s grey-box); #4 4-hop Tier-A sink (white-box, 420 s cold fallback) | 300 s each | wiring and capability reported separately; `latePromotions` and snapshot state printed |

Cell 2 rotates by `--cell-index` (or day of year when omitted). If the post-floor
snapshot is missing, the cell falls back to a cold run and captures a snapshot for
next time. Every cell gets an isolated data dir, so the four cells run concurrently.

### Post-recon snapshot for the #4 micro-slice

The lift/rotation cells resume from a `benchmark-realistic.ts` post-floor
checkpoint. `monorepo-whitebox` is different: it runs through
`scripts/benchmark-realism.ts`, which boots the fixture and the full `Execution`
loop. **Exact blocker:** that harness has no `--resume-recon-snapshot` /
`--snapshot-after-recon` flag (only `benchmark-realistic.ts` exposes
`--resume-snapshot` / `--snapshot-after-floor`), so it cannot yet capture or
consume a resumable post-recon checkpoint. The micro-slice therefore:

1. probes `<snapshot-root>/realism/monorepo-whitebox-seed<n>-post-recon/snapshot.json`;
2. reports `snapshot` when a harness advertises resume support and the marker
   exists, otherwise `unsupported` (marker present, harness cannot resume) or
   `cold` (no marker);
3. falls back to a **bounded** cold slice of `--micro-recon-timeout-sec` (default
   420 s, white-box so AST 4-hop chains are visible) instead of timing out
   silently at 180 s;
4. records `snapshot=<state>`, the per-fixture timeout and `latePromotions` in the
   cell detail (and the `snap`/`late` compact-table columns). A timeout with no
   artifact becomes a cell `error`, never a silent zero.

Remove the fallback once `scripts/benchmark-realism.ts` learns
`--resume-recon-snapshot`; `resolveMicroSlice` already consumes it through the
`resumeSupported` branch.

```bash
npm run smoke:agentic -- --tier 1 --out-dir /tmp/smoke --micro-recon-timeout-sec 420
```

The lift cell compares the resumed run against
`<snapshot-root>/baseline/<app>-seed<n>-grey-box.json` (override with
`--floor-scorecard`). Produce that baseline once with the deterministic floor:

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 node scripts/benchmark-realistic.ts \
  --app acme-saas --seed 1 --no-llm --max-duration-ms 300000 \
  --out-dir <snapshot-root>/baseline
```

### Gates

- precision 100% on lift/rotation, 0 confirmed on the trap;
- paired net-new >= `--lift-baseline` (a single -1 is allowed with
  `--rerun-on-minus-one`, improved conversion, and one rerun);
- conversion drop <= 10pp vs the floor baseline;
- 0 RPC/sandbox crashes;
- p50 assignment <= 75 s;
- >= 12 completed assignments in the 300 s lift cell;
- <= $0.80 per cell.

Exit code is 0 only when Tier 0 passes and every Tier 1 gate passes. The compact
table is printed on stdout; it includes `late` (OOB conversions promoted into
findings) and `snap` (post-recon snapshot state, e.g. `cold+420s`) so a cold
micro-slice is never mistaken for a snapshot-backed one. The full shape is written
to `<out-dir>/smoke-report.json` (add `--json` to print it).

## Tier 2 — documented, not run by default

`--tier 2` prints the full 3-app agentic matrix, salted held-out command, endurance
run, and realism exit gate. Held-out requires `GUARDIAN_RB_HELDOUT_SALT` and seeds
>= 1,000,000; never commit the salt.

```bash
npm run smoke:agentic -- --tier 2
```

## Dry run and calibration

`--dry-run` evaluates the corpus and prints the planned cells without starting a
model, worker, CLI, or fixture. `--calibrate --variants <json>` runs Tier 1 against
worktrees/commits and writes `<out-dir>/calibration.csv` for the Spearman study:

```json
[
  { "label": "main", "dir": "/path/to/worktree" },
  { "label": "b99ba0a", "commit": "b99ba0a" }
]
```

## Safety

- Loopback only: `GUARDIAN_ALLOW_LOCAL_LAB=1` is required by fixtures/trap.
- Model credentials stay outside the repo; per-cell data dirs copy profile metadata
  and symlink credential files, never the key itself.
- Agentic cells run under `newgrp docker` when the Docker socket is not in the
  current group.
