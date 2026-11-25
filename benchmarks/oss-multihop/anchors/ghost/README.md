# `oss-dev-ghost-01` — Ghost Multi-Hop Lab Harness

Defensive QA verification lab harness for **`oss-dev-ghost-01`** (JavaScript, `publishing-and-membership-cms`), defined in [`../../manifests/dev-anchors.json`](../../manifests/dev-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md).

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `ghost_app` (`app`): Parameterized `${APP_IMAGE:-ghost}:${APP_TAG:-5.82.2-alpine}`, loopback-only ephemeral port bind `127.0.0.1:0:2368`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `ghost_db` (`db`): `mysql:8.0.39` (internal only, zero host ports).
  - `ghost_export_worker` (`worker`): Isolated admin preview/export worker stub (internal only, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: v5.82.2)
APP_IMAGE=ghost APP_TAG=5.82.2-alpine \
  docker compose -p oss-lab-ghost-vuln -f benchmarks/oss-multihop/anchors/ghost/docker-compose.lab.yml up -d

# Paired official patched build (v5.96.0)
APP_IMAGE=ghost APP_TAG=5.96.0-alpine \
  docker compose -p oss-lab-ghost-patched -f benchmarks/oss-multihop/anchors/ghost/docker-compose.lab.yml up -d
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `ghost_contributor` | `attacker_low_priv` | `contrib_author` | `oss_lab_ghost_contributor` | **Yes** |
| `ghost_site_owner` | `victim_admin` | `owner_admin` | `oss_lab_ghost_owner` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-ghost-file-01` (`file_integrity`, `checkMode: canary_written`)
- **Target Service:** `ghost_export_worker` (`worker`)
- **Watched Path:** `/var/lib/ghost-lab/exports/audit-marker.txt`
- **Signal Criteria:** Watched export audit marker file exists and contains a run-scoped canary token prefixed with `oss_canary_ghost_`, correlated via `run_id`.
- **Evaluator:** `readAuditMarkerEvidence()`, `evaluateGhostOracle()`, and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `v5.82.2` (`ghost:5.82.2-alpine`, commit `3333333333333333333333333333333333333301`)
- **Patched Build:** `v5.96.0` (`ghost:5.96.0-alpine`, commit `3333333333333333333333333333333333333302`)
- **Expected `patchBrokeHopId`:** `H2` (strict admin preview sanitization and session boundary enforcement prevents the privileged preview pivot).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `v5.96.0` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId: "H2"`, and `ora-ghost-file-01` confirms `observed: false` on the patched build.
