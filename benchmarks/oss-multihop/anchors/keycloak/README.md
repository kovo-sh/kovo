# `oss-sealed-keycloak-01` — Keycloak Multi-Hop Lab Harness (M4 Sealed)

Defensive QA verification lab harness for **`oss-sealed-keycloak-01`** (Java, `iam-federation`), defined in [`../../manifests/sealed-anchors.json`](../../manifests/sealed-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md). Evaluated strictly at M4 certification via `--manifest`.

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `keycloak_app` (`app`): Parameterized `${APP_IMAGE:-quay.io/keycloak/keycloak}:${APP_TAG:-24.0.4}`, loopback-only ephemeral port bind `127.0.0.1:0:8080`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `keycloak_idp_broker` (`idp`): Isolated federated OIDC broker stub (`read_only: true`, zero host ports).
  - `keycloak_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup & Clean Teardown (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: 24.0.4)
APP_IMAGE=quay.io/keycloak/keycloak APP_TAG=24.0.4 \
  docker compose -p oss-sealed-keycloak-vuln -f benchmarks/oss-multihop/anchors/keycloak/docker-compose.lab.yml up -d

# Paired official patched build (24.0.5)
APP_IMAGE=quay.io/keycloak/keycloak APP_TAG=24.0.5 \
  docker compose -p oss-sealed-keycloak-patched -f benchmarks/oss-multihop/anchors/keycloak/docker-compose.lab.yml up -d

# Clean teardown (volumes & orphans removed)
docker compose -p oss-sealed-keycloak-vuln -f benchmarks/oss-multihop/anchors/keycloak/docker-compose.lab.yml down -v --remove-orphans
docker compose -p oss-sealed-keycloak-patched -f benchmarks/oss-multihop/anchors/keycloak/docker-compose.lab.yml down -v --remove-orphans
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `kc_federated_user` | `attacker_low_priv` | `fed_member_a` | `oss_lab_kc_fed_user` | **Yes** |
| `kc_realm_admin` | `victim_admin` | `realm_admin_a` | `oss_lab_kc_realm_admin` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-keycloak-db-01` (`db_query`, Postgres)
- **Target Service:** `keycloak_db` (`db`)
- **Read-Only Query:** `SELECT id, realm_id, role_name, canary_marker FROM keycloak_lab_audit WHERE canary_marker LIKE 'oss_canary_keycloak_%'`
- **Signal Criteria:** One or more rows whose `canary_marker` contains run-scoped prefix `oss_canary_keycloak_`, correlated via `run_id`.
- **Evaluator:** `evaluateKeycloakOracle()` and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `24.0.4` (`quay.io/keycloak/keycloak:24.0.4`, commit `a111111111111111111111111111111111111101`)
- **Patched Build:** `24.0.5` (`quay.io/keycloak/keycloak:24.0.5`, commit `a111111111111111111111111111111111111102`)
- **Expected `patchBrokeHopId`:** `H2` (strict OIDC client-scope protocol mapper and brokered claim binding blocks audience/role widening).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `24.0.5` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId: "H2"`, and `ora-keycloak-db-01` confirms `observed: false` on the patched build.
