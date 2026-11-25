# `oss-sealed-saleor-01` — Saleor Multi-Hop Lab Harness (M4 Sealed)

Defensive QA verification lab harness for **`oss-sealed-saleor-01`** (Python, `commerce-order-workflow`), defined in [`../../manifests/sealed-anchors.json`](../../manifests/sealed-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md). Evaluated strictly at M4 certification via `--manifest`.

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with `labProxyMode: isolated_lab_proxy` and zero public egress.
- **Services:**
  - `saleor_lab_proxy` (`lab_proxy`): Isolated loopback proxy (`127.0.0.1:0:8000`, `read_only: true`, `cap_drop: [ALL]`) forwarding to `saleor_app:8000`.
  - `saleor_app` (`app`): Parameterized `${APP_IMAGE:-ghcr.io/saleor/saleor}:${APP_TAG:-3.19.24}` (no direct host ports; reachable only through `saleor_lab_proxy`).
  - `saleor_worker` (`worker`): Parameterized `${APP_IMAGE:-ghcr.io/saleor/saleor}:${APP_TAG:-3.19.24}` async Celery fulfillment/billing worker (internal only, zero host ports).
  - `saleor_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
  - `saleor_cache` (`cache`): `redis:7.2.5-alpine` (`read_only: true`, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup & Clean Teardown (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: 3.19.24)
APP_IMAGE=ghcr.io/saleor/saleor APP_TAG=3.19.24 \
  docker compose -p oss-sealed-saleor-vuln -f benchmarks/oss-multihop/anchors/saleor/docker-compose.lab.yml up -d

# Paired official patched build (3.20.28)
APP_IMAGE=ghcr.io/saleor/saleor APP_TAG=3.20.28 \
  docker compose -p oss-sealed-saleor-patched -f benchmarks/oss-multihop/anchors/saleor/docker-compose.lab.yml up -d

# Clean teardown (volumes & orphans removed)
docker compose -p oss-sealed-saleor-vuln -f benchmarks/oss-multihop/anchors/saleor/docker-compose.lab.yml down -v --remove-orphans
docker compose -p oss-sealed-saleor-patched -f benchmarks/oss-multihop/anchors/saleor/docker-compose.lab.yml down -v --remove-orphans
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `saleor_store_buyer` | `attacker_low_priv` | `buyer_store_a` | `oss_lab_saleor_buyer_a` | **Yes** |
| `saleor_channel_admin` | `victim_admin` | `channel_admin_a` | `oss_lab_saleor_admin_a` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-saleor-log-01` (`container_log`, stream `stdout`)
- **Target Service:** `saleor_app` (`app`)
- **Expected Pattern:** `audit_event=delegated_billing_settlement_complete.*oss_canary_saleor_[a-z0-9_-]+`
- **Forbid Pattern:** `audit_event=delegated_billing_settlement_denied` (clean denial events on hardened/patched builds stay suppressed)
- **Signal Criteria:** Structured `stdout` audit log line on `saleor_app` matching delegated billing settlement completion with run-scoped canary prefix `oss_canary_saleor_`, correlated via `run_id`.
- **Evaluator:** `evaluateSaleorOracle()` and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `3.19.24` (`ghcr.io/saleor/saleor:3.19.24`, commit `a444444444444444444444444444444444444401`)
- **Patched Build:** `3.20.28` (`ghcr.io/saleor/saleor:3.20.28`, commit `a444444444444444444444444444444444444402`)
- **Expected `patchBrokeHopId`:** `H2` (strict delegated-app webhook scope binding and channel billing authorization guard blocks unauthorized order transition).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `3.20.28` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId: "H2"`, and `ora-saleor-log-01` confirms `observed: false` on the patched build.
