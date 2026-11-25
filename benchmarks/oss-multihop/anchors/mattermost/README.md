# `oss-dev-mattermost-01` — Mattermost Multi-Hop Lab Harness

Defensive QA verification lab harness for **`oss-dev-mattermost-01`** (Go, `enterprise-collaboration-and-iam`), defined in [`../../manifests/dev-anchors.json`](../../manifests/dev-anchors.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md).

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with `labProxyMode: isolated_lab_proxy` and zero public egress.
- **Services:**
  - `mm_lab_proxy` (`lab_proxy`): Isolated loopback proxy (`127.0.0.1:0:8065`, `read_only: true`, `cap_drop: [ALL]`) forwarding to `mattermost_app:8065`.
  - `mattermost_app` (`app`): Parameterized `${APP_IMAGE:-mattermost/mattermost-team-edition}:${APP_TAG:-9.5.8}` (no direct host ports; reachable only through `mm_lab_proxy`).
  - `mattermost_idp` (`idp`): Isolated OIDC identity provider stub (`read_only: true`, zero host ports).
  - `mattermost_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup (Vulnerable vs Paired Patched Build)

```bash
# Vulnerable build (default: v9.5.8)
APP_IMAGE=mattermost/mattermost-team-edition APP_TAG=9.5.8 \
  docker compose -p oss-lab-mattermost-vuln -f benchmarks/oss-multihop/anchors/mattermost/docker-compose.lab.yml up -d

# Paired official patched build (v9.11.4)
APP_IMAGE=mattermost/mattermost-team-edition APP_TAG=9.11.4 \
  docker compose -p oss-lab-mattermost-patched -f benchmarks/oss-multihop/anchors/mattermost/docker-compose.lab.yml up -d
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `mm_team_member` | `attacker_member` | `member_collab_a` | `oss_lab_mm_member_a` | **Yes** |
| `mm_sys_admin` | `victim_admin` | `sysadmin_lab` | `oss_lab_mm_sysadmin` | **No** (shortcut rejected) |

---

## External Impact Oracle (`oracle.ts`)

- **Oracle ID:** `ora-mattermost-log-01` (`container_log`, stream `stdout`)
- **Target Service:** `mattermost_app` (`app`)
- **Expected Pattern:** `audit_event=compliance_export_complete.*oss_canary_mm_[a-z0-9_-]+`
- **Forbid Pattern:** `audit_event=compliance_export_denied` (clean denial events on hardened/patched builds stay suppressed)
- **Signal Criteria:** Structured `stdout` audit log line on `mattermost_app` matching the completion event with run-scoped canary prefix `oss_canary_mm_`, correlated via `run_id`.
- **Evaluator:** `evaluateMattermostOracle()` and `evaluatePairedBuilds()` delegate to `evaluateOracleEvidence()` in `../../lib/oracle-runner.ts`.

---

## Paired Patch Verification (`patchBrokeHopId`)

- **Vulnerable Build:** `v9.5.8` (`mattermost/mattermost-team-edition:9.5.8`, commit `4444444444444444444444444444444444444401`)
- **Patched Build:** `v9.11.4` (`mattermost/mattermost-team-edition:9.11.4`, commit `4444444444444444444444444444444444444402`)
- **Expected `patchBrokeHopId`:** `H2` (strict SSO/OAuth assertion claim binding and webhook authorization checks block scope confusion).
- **Closure Criteria:** Full `CompositeProofReceipt` DAG replay against `v9.11.4` reports `replayedFullDag: true`, `terminalImpactEliminated: true`, `patchBrokeHopId: "H2"`, and `ora-mattermost-log-01` confirms `observed: false` on the patched build.
