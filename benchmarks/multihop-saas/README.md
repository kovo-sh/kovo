# `multihop-saas` — v8 M0 benchmark track

Standalone, offline benchmark runtime for **deep multi-hop causal vulnerability identification** on
realistic multi-service SaaS applications. M0 ships the core runtime plus **Pilot Archetype 1
(`paygrid`)**. It has **zero npm dependencies**, uses **Node 24+ native TypeScript**, and only ever
binds `127.0.0.1:0` through a single helper (`lib/safety.ts`).

This directory is deliberately self-contained. It does not import `src/`, does not modify existing
benchmarks, and does not feed any result back into the engine.

---

## Quick start

```bash
# Every command that starts a service requires the explicit lab gate.
export KOVO_ALLOW_LOCAL_LAB=1

node benchmarks/multihop-saas/run.ts list
node benchmarks/multihop-saas/run.ts seeds --set dev --n 5
node benchmarks/multihop-saas/run.ts selftest --seeds 42
node benchmarks/multihop-saas/run.ts serve --seed 42 --mode vulnerable --briefing white-box

# One-shot: boot, run the deterministic reference solvers, grade and exit.
node benchmarks/multihop-saas/run.ts serve --seed 42 --mode vulnerable --once --out-dir /tmp/mh-out
```

Validation:

```bash
node_modules/.bin/tsc -p benchmarks/multihop-saas/tsconfig.json
KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/multihop-saas/tests/
```

---

## Safety invariants (hard, grep-enforced)

| Invariant | Enforcement |
|---|---|
| Local lab gate | `assertLocalLabAllowed()` must pass (`KOVO_ALLOW_LOCAL_LAB=1`) before any server starts; checked in `run.ts`, `startPaygrid`, `startServices`, `listenLoopback`, `egress.fetch`. |
| Loopback only | Only `lib/safety.ts` may call `.listen(...)`; it binds `127.0.0.1` port `0` and rejects any other address. `tests/safety.test.ts` scans the whole tree. |
| Zero dependencies | Imports are only `node:*` or relative `.ts` files. No nested `package.json`. |
| No dynamic execution | No `child_process`, `eval`, `new Function`, `vm`, or `worker_threads` anywhere. |
| Bounded egress | Service-to-service calls flow through `lib/egress.ts`, which accepts registered loopback origins only, caps bodies, and never follows redirects. |
| Virtual filesystem | Export/treasury reads use `lib/vfs.ts`; no real host path is read or written by a service. |
| Synthetic secrets only | Sessions, PATs, invites, signing salts, canaries and passwords use `mh_fake_*` prefixes. No real keys or `FLAG{}` strings. |
| Leak-free white-box tree | Materialized snapshots copy only the application source plus three runtime helpers; `scanTreeForLeakage` rejects `truth/`, `solver`, `decoy`, `oracle`, chain IDs, and `CWE-` markers in paths or content. |

Victim bots (`admin_bot`) exist only as runtime actors. No briefing ever exposes their credentials;
they can only be triggered through normal application workflows.

---

## Layout

```text
benchmarks/multihop-saas/
  README.md  CONTRACTS.md  tsconfig.json  run.ts
  lib/
    types.ts             4 typed edge bindings, personas/tenants, briefings, scorecards
    chain-oracle.ts      ChainOracle v2: lineage DAG, provenance, receipts, hop funnel
    safety.ts            the only socket binder + local-lab gate
    domain-variant.ts    dev 1..9999 / salted held-out >= 1_000_000, semantic randomization
    grader.ts            two-side TP/FP, strict decoy accounting, JSON + Markdown scorecard
    materialize.ts       white-box snapshot + leakage scanner
    egress.ts  vfs.ts  prng.ts
  apps/paygrid/
    index.ts             boot 5 services, monitor wiring, briefings
    src/                 application source (white-box visible, marker-free)
      server.ts          five loopback listeners
      service-edge.ts    public entry, directory, signed downloads, proxy
      service-api.ts     REST + GraphQL, orgs, templates, invoices, exports
      service-api-billing.ts  payouts, orders, ledger, capture race
      service-worker.ts  PDF / export jobs, poll convergence
      service-idp.ts     OIDC-shaped sessions, invites, PATs
      service-vault.ts   signing custody, settlement webhook, treasury
      state.ts policy.ts http.ts shared.ts
    truth/               host-only profiles, chain specs, ground truth, monitor
    solvers/             deterministic reference solvers (one per chain)
  tests/
    safety.test.ts       static containment + gate + seed + leakage tests
    causal-dag.test.ts   ChainOracle v2 and grading contracts
    paygrid.test.ts      live loopback matrix
```

---

## Pilot archetype: `paygrid`

B2B fintech — billing, ledger and payouts.

- **Services (5, isolated loopback listeners):** `edge`, `api` (REST + GraphQL), `worker`
  (PDF/export/webhook jobs), `idp` (OIDC-shaped sessions, invites, PATs), `vault.internal`.
- **Actors (7 across 3 tenants):** `owner_a`, `member_a`, `viewer_a`, `dual_member`
  (admin Org A / viewer Org B), `member_b`, `revoked_or_demoted`, victim `admin_bot`.
  Tenant slugs always prefix-overlap (`acme`, `acme-systems`, `acme-systems-treasury`) so the
  signed-prefix defect is reachable.
- **Lifecycle hooks:** invite create/revoke, PAT create/revoke, session revoke, export job
  create/cancel, key rotation, and `X-Kovo-Run-Id` propagation onto every created entity.
- **Async latency:** `asyncLatencyMs` is configurable (`fast-lab` profiles are typically 5–50 ms;
  WAN/endurance profiles can set 15–30 s). Jobs converge through bounded polling.

### Chains

| Chain | Hops | Edge bindings | Terminal impact |
|---|---:|---|---|
| `PG-C1` | 4 | derived crypto → value → state transition | self-approved payout |
| `PG-C2` | 4 | async pivot → value → derived crypto | forged settlement webhook |
| `PG-C3` | 5 | state transition → async pivot → value → value | cross-tenant treasury export |
| `PG-C4` | 3 | value → state transition | ledger over-credit |

`PG-C1` directory leak → NFKC invite collision → finance session → draft rebind → self-approval.
`PG-C2` raw invoice footer → async PDF worker internal fetch → signing salt in worker trace → forged
settlement webhook.
`PG-C3` tenantless permission-cache prime → Org B export via cache bleed → job convergence →
signed URL without trailing slash → sibling-tenant treasury download.
`PG-C4` edge/backend duplicate JSON key cap bypass → pre-capture rebind → concurrent capture race.

### Partial-hop hardened twins

| Twin | Base | Hops that genuinely exist | Invariant enforced at |
|---|---|---|---|
| `PG-D1` | `PG-C1` | directory leak, invite resolution | API requires verified tenant identity (`tid` + verified email) |
| `PG-D2` | `PG-C2` | raw footer write, PDF job creation | worker trace is redacted |
| `PG-D3` | `PG-C3` | cache prime, export job, job convergence | export path requires exact tenant prefix + trailing slash |

All three twins must produce **zero terminal oracle events**. A finding on a benign early hop is a
**strict decoy false positive** and fails the precision gate.

`mode: hardened` applies all counterpart invariants at once: all four reference solvers emit zero
oracle events and zero confirmed chains.

---

## Evaluation modes

| Mode | Personas | Topology | API catalog | Source tree |
|---|---|---|---|---|
| `black-box` | 3 low-privilege attackers | public entry origin only | no | no |
| `grey-box` | all 6 non-bot actors | public services (internal services named, no origins) | yes | no |
| `white-box` | all 6 non-bot actors | grey-box topology | yes | materialized leak-scanned snapshot |

`lab.briefing(mode)` returns the exact JSON a scanner may see. The white-box `sourceDir` points at a
fresh temporary tree that `scanTreeForLeakage` has already cleared.

---

## Seeds

- **Dev:** integers `1..9999`. Reproducible from the repository.
- **Held-out:** integers `>= 1_000_000`, derived/reproduced with
  `KOVO_RB_HELDOUT_SALT` (>= 16 chars, owner-only, never committed). Never pass a salt on the
  command line; held-out variants are keyed by HMAC-SHA256.

Semantic variation changes tenant slugs, user ids, emails, invite material, resource ids, secrets,
economics and route prefix. Resource ids are deterministic per seed; session/PAT/job tokens are
synthetic per-run values under `mh_fake_*`.

---

## Grading

A chain counts as a **true positive** only when both sides agree:

1. **ChainOracle v2** observed the complete ordered hop DAG, with valid typed edge bindings, monotonic
   timestamps, attacker-eligible provenance, and the terminal impact; and
2. a host-signed **`CompositeProofReceipt`** verifies and matches the same chain spec.

The scorecard reports `tp/fp/fn`, precision, recall, strict decoy FPs, FP categories
(`hardened_counterpart`, `decoy_twin`, `unmatched`, `unconfirmed`), the
`H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed` funnel, and per-hop drop reasons.
JSON and Markdown renderers are both available.

Deterministic scanner floors are checked with:

```bash
node benchmarks/multihop-saas/run.ts anti-heuristic-check --scorecard <scorecard.json> --max-recall 0.05
```

The v8 anti-heuristic ceiling is **5%**. The reference solvers exist only to prove that the lab
paths are reachable and gradeable; they are not a scanner score and must never be reported as one.

---

## Adding the next archetype (M1)

1. Add `apps/<archetype>/src/` with the same five-service shape and only marker-free application
   vocabulary.
2. Add `truth/blueprint.ts` (profiles, chain specs, twins, ground truth, API catalog) and
   `truth/monitors.ts` (neutral audit event → causal observation mapping).
3. Add one deterministic solver per chain under `solvers/`.
4. Extend `lib/types.ts` `appNames` only when the app is ready; `lib/domain-variant.ts` owns its
   semantic vocabulary.
5. Prove: vulnerable N/N, hardened 0 events, twins 0 terminal events, leakage scan 0 hits, static
   safety scan clean, and `--no-llm <= 5%`.
