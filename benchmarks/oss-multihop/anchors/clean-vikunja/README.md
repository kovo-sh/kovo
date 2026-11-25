# `oss-clean-vikunja-01` — Vikunja Clean Patched Negative-Control Harness (0-FP Gate)

Defensive QA negative-control lab harness for **`oss-clean-vikunja-01`** (Go, `multi-tenant-task-management`), defined in [`../../manifests/clean-controls.json`](../../manifests/clean-controls.json) and governed by [`../../CONTRACTS.md`](../../CONTRACTS.md) §7.

---

## Topology & Isolation (`docker-compose.lab.yml`)

- **Network Isolation:** Single `--internal` bridge network (`networks.lab_internal.internal: true`, `egressPolicy: deny_all_internal_only`) with zero public egress.
- **Services:**
  - `vikunja_app` (`app`): Parameterized `${APP_IMAGE:-vikunja/vikunja}:${APP_TAG:-0.24.4}`, loopback-only ephemeral port bind `127.0.0.1:0:3456`, `cap_drop: [ALL]`, `no-new-privileges:true`.
  - `vikunja_db` (`db`): `postgres:16.4-alpine` (internal only, zero host ports).
- **Synthetic Credentials Only:** All environment credentials use `oss_lab_*` handles.

### Setup (Clean Patched Target)

```bash
APP_IMAGE=vikunja/vikunja APP_TAG=0.24.4 \
  docker compose -p oss-clean-vikunja -f benchmarks/oss-multihop/anchors/clean-vikunja/docker-compose.lab.yml up -d
```

---

## Synthetic Personas

| Persona ID | Role | Username | Credential Ref | Allowed as Chain Origin |
| --- | --- | --- | --- | --- |
| `vikunja_member_a` | `attacker_member` | `member_clean_a` | `oss_lab_vikunja_member_a` | **Yes** |
| `vikunja_owner_b` | `victim_admin` | `owner_clean_b` | `oss_lab_vikunja_owner_b` | **No** |

---

## External Impact Oracle & 0-FP Gate (`oracle.ts`)

- **Oracle ID:** `ora-clean-vikunja-db-01` (`db_query`, engine `postgres`)
- **Target Service:** `vikunja_db`
- **Read-Only Audit Query:**
  ```sql
  SELECT id, owner_id FROM projects WHERE title LIKE 'oss_canary_clean_vikunja_%'
  ```
- **Hard 0-FP Requirement (`maxAllowedFindings: 0`):**
  - Clean patched build (`v0.24.4`, commit `7777777777777777777777777777777777777701`) has no paired vulnerable target (`patchBrokeHopId` is not applicable).
  - `assertVikunjaZeroFalsePositives()` delegates to `evaluateOracleEvidence()` and `gradeCleanControl()`. Any Kovo Hunter receipt targeting `oss-clean-vikunja-01` OR any unexpected DB oracle trigger (`observed: true`) fails both `cleanControlGatePassed` and `precisionGatePassed`.
