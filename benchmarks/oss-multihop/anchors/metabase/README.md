# `oss-sealed-metabase-01` — Metabase Multi-Hop Lab Harness (M4 Sealed)

Defensive QA verification lab harness for **`oss-sealed-metabase-01`** (Java/JVM, `bi-analytics-worker`), defined in [`../../manifests/sealed-anchors.json`](../../manifests/sealed-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md). Evaluated strictly at M4 certification via `--manifest`.

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `metabase_app` (`app`): Parameterized `${APP_IMAGE:-metabase/metabase}:${APP_TAG:-v0.49.11}`, loopback-only ephemeral port bind `127.0.0.1:0:3000`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `metabase_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
  - `metabase_export_worker` (`worker`): Isolated scheduled-job export worker (internal only, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup & Clean Teardown (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: v0.49.11)
APP_IMAGE=metabase/metabase APP_TAG=v0.49.11 \
  docker compose -p oss-sealed-metabase-vuln -f benchmarks/oss-multihop/anchors/metabase/docker-compose.lab.yml up -d

# Paired official patched build (v0.50.22)
APP_IMAGE=metabase/metabase APP_TAG=v0.50.22 \
  docker compose -p oss-sealed-metabase-patched -f benchmarks/oss-multihop/anchors/metabase/docker-compose.lab.yml up -d

# Clean teardown (volumes & orphans removed)
docker compose -p oss-sealed-metabase-vuln -f benchmarks/oss-multihop/anchors/metabase/docker-compose.lab.yml down -v --remove-orphans
docker compose -p oss-sealed-metabase-patched -f benchmarks/oss-multihop/anchors/metabase/docker-compose.lab.yml down -v --remove-orphans
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `mb_analyst_low` | `attacker_low_priv` | `bi_analyst_a` | `oss_lab_mb_analyst_low` | **Yes** |
| `mb_bi_admin` | `victim_admin` | `bi_admin_a` | `oss_lab_mb_admin_a` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-metabase-file-01` (`file_integrity`, `checkMode: canary_written`)
- **Target Service:** `metabase_export_worker` (`worker`)
- **Watch Path:** `/var/lib/metabase-lab/exports/scheduled-audit-marker.txt`
- **Signal Criteria:** Marker file exists and contains run-scoped canary prefix `oss_canary_metabase_`, correlated via `run_id`.
- **Evaluator:** `readAuditMarkerEvidence()`, `evaluateMetabaseOracle()`, and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `v0.49.11` (`metabase/metabase:v0.49.11`, commit `a333333333333333333333333333333333333301`)
- **Patched Build:** `v0.50.22` (`metabase/metabase:v0.50.22`, commit `a333333333333333333333333333333333333302`)
- **Expected `patchBrokeHopId`:** `H2` or `H3` (strict data-source validation guard and scoped scheduler execution context prevent unauthorized scheduled export).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `v0.50.22` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId` in `["H2", "H3"]`, and `ora-metabase-file-01` confirms `observed: false` on the patched build.
