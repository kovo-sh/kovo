# `oss-dev-gitea-01` — Gitea Multi-Hop Lab Harness

Defensive QA verification lab harness for **`oss-dev-gitea-01`** (Go, `devops-git-hosting`), defined in [`../../manifests/dev-anchors.json`](../../manifests/dev-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md).

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `gitea_app` (`app`): Parameterized `${APP_IMAGE:-gitea/gitea}:${APP_TAG:-1.21.11}`, loopback-only ephemeral port bind `127.0.0.1:0:3000`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `gitea_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
  - `internal_runner_meta` (`internal_target`): Isolated internal runner/metadata stub (`read_only: true`, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: v1.21.11)
APP_IMAGE=gitea/gitea APP_TAG=1.21.11 \
  docker compose -p oss-lab-gitea-vuln -f benchmarks/oss-multihop/anchors/gitea/docker-compose.lab.yml up -d

# Paired official patched build (v1.22.6)
APP_IMAGE=gitea/gitea APP_TAG=1.22.6 \
  docker compose -p oss-lab-gitea-patched -f benchmarks/oss-multihop/anchors/gitea/docker-compose.lab.yml up -d
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `gitea_collab_low` | `attacker_low_priv` | `collab_dev_a` | `oss_lab_gitea_collab_low` | **Yes** |
| `gitea_org_admin` | `victim_admin` | `org_owner_a` | `oss_lab_gitea_org_admin` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-gitea-oob-01` (`loopback_oob_collector`)
- **Target Service:** `internal_runner_meta`
- **Collector Endpoint:** `http://127.0.0.1:19401/oob/gitea` (strictly loopback)
- **Signal Criteria:** `POST` request with path prefix `/oob/gitea/`, run-scoped canary token prefixed with `oss_canary_gitea_`, correlated via `X-Kovo-Run-Id`.
- **Evaluator:** `evaluateGiteaOracle()` and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `v1.21.11` (`gitea/gitea:1.21.11`, commit `1111111111111111111111111111111111111101`)
- **Patched Build:** `v1.22.6` (`gitea/gitea:1.22.6`, commit `1111111111111111111111111111111111111102`)
- **Expected `patchBrokeHopId`:** `H2` (webhook egress allowlist canonicalization blocks the internal pivot across the trust boundary).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `v1.22.6` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId: "H2"`, and `ora-gitea-oob-01` confirms `observed: false` on the patched build.
