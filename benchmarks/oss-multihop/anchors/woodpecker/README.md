# `oss-sealed-woodpecker-01` — Woodpecker CI Multi-Hop Lab Harness (M4 Sealed)

Defensive QA verification lab harness for **`oss-sealed-woodpecker-01`** (Go, `ci-runner-pipeline`), defined in [`../../manifests/sealed-anchors.json`](../../manifests/sealed-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md). Evaluated strictly at M4 certification via `--manifest`.

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `woodpecker_app` (`app`): Parameterized `${APP_IMAGE:-woodpeckerci/woodpecker-server}:${APP_TAG:-v2.6.0}`, loopback-only ephemeral port bind `127.0.0.1:0:8000`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `woodpecker_agent` (`worker`): Parameterized `${AGENT_IMAGE:-woodpeckerci/woodpecker-agent}:${APP_TAG:-v2.6.0}` (internal only, zero host ports).
  - `woodpecker_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
  - `woodpecker_secret_meta` (`internal_target`): Isolated internal artifact/secret metadata stub (`read_only: true`, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup & Clean Teardown (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: v2.6.0)
APP_IMAGE=woodpeckerci/woodpecker-server APP_TAG=v2.6.0 \
  docker compose -p oss-sealed-woodpecker-vuln -f benchmarks/oss-multihop/anchors/woodpecker/docker-compose.lab.yml up -d

# Paired official patched build (v2.7.1)
APP_IMAGE=woodpeckerci/woodpecker-server APP_TAG=v2.7.1 \
  docker compose -p oss-sealed-woodpecker-patched -f benchmarks/oss-multihop/anchors/woodpecker/docker-compose.lab.yml up -d

# Clean teardown (volumes & orphans removed)
docker compose -p oss-sealed-woodpecker-vuln -f benchmarks/oss-multihop/anchors/woodpecker/docker-compose.lab.yml down -v --remove-orphans
docker compose -p oss-sealed-woodpecker-patched -f benchmarks/oss-multihop/anchors/woodpecker/docker-compose.lab.yml down -v --remove-orphans
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `wp_repo_contrib` | `attacker_member` | `ci_contrib_a` | `oss_lab_wp_contrib_a` | **Yes** |
| `wp_org_maintainer` | `victim_admin` | `ci_maintainer_a` | `oss_lab_wp_maintainer_a` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-woodpecker-oob-01` (`loopback_oob_collector`)
- **Target Service:** `woodpecker_secret_meta` (`internal_target`)
- **Collector Endpoint:** `http://127.0.0.1:19402/oob/woodpecker` (strictly loopback)
- **Signal Criteria:** `POST` request with path prefix `/oob/woodpecker/`, run-scoped canary token prefixed with `oss_canary_woodpecker_`, correlated via `X-Guardian-Run-Id`.
- **Evaluator:** `evaluateWoodpeckerOracle()` and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `v2.6.0` (`woodpeckerci/woodpecker-server:v2.6.0`, commit `a222222222222222222222222222222222222201`)
- **Patched Build:** `v2.7.1` (`woodpeckerci/woodpecker-server:v2.7.1`, commit `a222222222222222222222222222222222222202`)
- **Expected `patchBrokeHopId`:** `H2` (strict pipeline event filtering and secret-scope gating prevents untrusted runner dispatch with protected secret bindings).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `v2.7.1` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId: "H2"`, and `ora-woodpecker-oob-01` confirms `observed: false` on the patched build.
