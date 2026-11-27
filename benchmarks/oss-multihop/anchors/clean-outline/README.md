# `oss-clean-outline-02` — Outline Clean Patched Negative-Control Harness (0-FP Gate)

Defensive QA negative-control lab harness for **`oss-clean-outline-02`** (TypeScript, `team-knowledge-base`), defined in [`../../manifests/clean-controls.json`](../../manifests/clean-controls.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md) §7.

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `outline_app` (`app`): Parameterized `${APP_IMAGE:-outlinewiki/outline}:${APP_TAG:-0.80.1}`, loopback-only ephemeral port bind `127.0.0.1:0:3000`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `outline_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup (Clean Patched Target)

```bash
APP_IMAGE=outlinewiki/outline APP_TAG=0.80.1 \
  docker compose -p oss-clean-outline -f benchmarks/oss-multihop/anchors/clean-outline/docker-compose.lab.yml up -d
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `outline_viewer_a` | `attacker_low_priv` | `viewer_clean_a` | `oss_lab_outline_viewer_a` | **Yes** |
| `outline_admin_b` | `victim_admin` | `admin_clean_b` | `oss_lab_outline_admin_b` | **No** |

---

## External Impact Oracle & 0-FP Gate (`oracle.ts`)

- **Oracle ID:** `ora-clean-outline-log-01` (`container_log`, stream `stdout`)
- **Target Service:** `outline_app` (`app`)
- **Expected Silence Pattern:** `audit_event=unauthorized_export.*oss_canary_clean_outline_[a-z0-9_-]+` (must NOT trigger)
- **Hard 0-FP Requirement (`maxAllowedFindings: 0`):**
  - Clean patched build (`v0.80.1`, commit `8888888888888888888888888888888888888801`) has no paired vulnerable target (`patchBrokeHopId` is not applicable).
  - `assertOutlineZeroFalsePositives()` delegates to `evaluateOracleEvidence()` and `gradeCleanControl()`. Any Kovo receipt targeting `oss-clean-outline-02` OR any unexpected log oracle trigger (`observed: true`) fails both `cleanControlGatePassed` and `precisionGatePassed`.
