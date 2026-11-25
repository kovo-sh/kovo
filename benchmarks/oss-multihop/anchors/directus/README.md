# `oss-dev-directus-01` — Directus Multi-Hop Lab Harness

Defensive QA verification lab harness for **`oss-dev-directus-01`** (TypeScript, `headless-cms-and-data-platform`), defined in [`../../manifests/dev-anchors.json`](../../manifests/dev-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md).

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `directus_app` (`app`): Parameterized `${APP_IMAGE:-directus/directus}:${APP_TAG:-10.10.7}`, loopback-only ephemeral port bind `127.0.0.1:0:8055`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `directus_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
  - `directus_cache` (`cache`): `redis:7.2.5-alpine` (`read_only: true`, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: v10.10.7)
APP_IMAGE=directus/directus APP_TAG=10.10.7 \
  docker compose -p oss-lab-directus-vuln -f benchmarks/oss-multihop/anchors/directus/docker-compose.lab.yml up -d

# Paired official patched build (v10.13.1)
APP_IMAGE=directus/directus APP_TAG=10.13.1 \
  docker compose -p oss-lab-directus-patched -f benchmarks/oss-multihop/anchors/directus/docker-compose.lab.yml up -d
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `directus_tenant_b_member` | `attacker_member` | `editor_tenant_b` | `oss_lab_directus_member_b` | **Yes** |
| `directus_tenant_a_admin` | `victim_admin` | `admin_tenant_a` | `oss_lab_directus_admin_a` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-directus-db-01` (`db_query`, engine `postgres`)
- **Target Service:** `directus_db`
- **Read-Only Audit Query:**
  ```sql
  SELECT id, role_name, canary_marker FROM directus_lab_audit WHERE canary_marker LIKE 'oss_canary_directus_%'
  ```
- **Signal Criteria:** One or more returned rows whose `canary_marker` column contains `oss_canary_directus_`, correlated via `run_id`.
- **Evaluator:** `evaluateDirectusOracle()` and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `v10.10.7` (`directus/directus:10.10.7`, commit `2222222222222222222222222222222222222201`)
- **Patched Build:** `v10.13.1` (`directus/directus:10.13.1`, commit `2222222222222222222222222222222222222202`)
- **Expected `patchBrokeHopId`:** `H2` or `H3` (strict relational RBAC filter parity and flow-hook execution scope enforcement).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `v10.13.1` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId` in `["H2", "H3"]`, and `ora-directus-db-01` confirms `observed: false` (0 matching audit rows) on the patched build.
