# `oss-multihop` — Contracts & Verification Specification

This document defines the binding contracts for `benchmarks/oss-multihop/` per [`plans/v8.md`](../../plans/v8.md) §"Real-World OSS / CVE Multi-Hop Anchor Corpus", §M2, and §M4.

---

## 1. Runtime & Containment Contract

- **Scope:** Standalone directory `benchmarks/oss-multihop/**`. Zero edits to `src/` or other benchmark suites.
- **Runtime:** Node 24+ native TypeScript type-stripping, ESM, explicit `.ts` extensions, `import type` for types, `erasableSyntaxOnly: true`, **zero npm dependencies** (`node:*` built-ins only).
- **Local-Lab Gate:** Any lab self-test or runtime check calls `assertLocalLabAllowed()`, requiring `KOVO_ALLOW_LOCAL_LAB=1`.
- **No Shell Execution in Framework Code:** The framework modules (`lib/`, `run.ts`) perform pure validation, external oracle evaluation, and two-side grading without `node:child_process`, `eval`, `new Function`, or `vm`.
- **Zero Exploit Payloads Committed:** Manifests describe defensive QA anchor topology, synthetic personas (`oss_lab_*`), read-only external impact oracles, and paired patch-retest contracts only.

---

## 2. Dev vs Sealed Corpus Split

- **Dev Anchors (`manifests/dev-anchors.json`):** 4 real-world OSS multi-hop anchor specs (`gitea`, `directus`, `ghost`, `mattermost`) spanning Go, TypeScript, and JavaScript. Used during M2–M3 engine validation and verification harness bring-up.
- **Sealed Anchors (M4 Certification Only):** 4 additional multi-language OSS multi-hop anchors stored outside dev hill-climbing, conforming strictly to [`manifests/sealed-manifest.example.json`](./manifests/sealed-manifest.example.json). Sealed target names, specific advisories, and chain details MUST NEVER appear in `manifests/sealed-manifest.example.json` or `src/server/`.
- **Generalization Stop Rule:** Per `plans/v8.md`, sealed anchors run only at M4 certification. If blind sealed recall drops `> 20 pp` below dev recall, development pauses to remove overfitted heuristics.

---

## 3. `--internal` Docker Lab Network Isolation Contract

Every `IsolatedComposeSchema` in an anchor or clean negative-control manifest MUST pass `validateComposeTemplate()` before any container is ever launched:

1. **Internal Networks Only:** At least one Docker network MUST be defined, and **every** network MUST declare `"internal": true` (equivalent to `docker network create --internal`) and `"driver": "bridge"`. `egressPolicy` MUST equal `"deny_all_internal_only"`.
2. **No Host Networking or Privileged Containers:** `networkMode` MUST NOT be `"host"` or reference another namespace; `privileged` MUST NOT be `true`; `capAdd` MUST NOT grant dangerous capabilities (`NET_ADMIN`, `SYS_ADMIN`, `SYS_PTRACE`, `DAC_OVERRIDE`, `ALL`).
3. **Loopback-Only Port Publication:**
   - Only services with role `"app"` or `"lab_proxy"` may publish host ports.
   - Internal services (`db`, `cache`, `worker`, `idp`, `internal_target`) MUST publish **zero** host ports.
   - Every published port MUST match `127.0.0.1:<hostPort>:<containerPort>` (recommended `127.0.0.1:0:<containerPort>` for ephemeral loopback allocation, or isolated lab proxy). Bare `<port>:<port>`, `0.0.0.0:...`, and `[::]:...` are hard-rejected.
4. **Immutable Image Pins & Synthetic Env:**
   - Every service MUST pin an immutable `sha256:<64-hex>` `imageDigest` and a non-floating `imageRef` (never `:latest`).
   - Environment values MUST contain synthetic lab credentials only (`FORBIDDEN_SECRET_PATTERNS` check rejects real tokens/keys).

---

## 4. External Impact Oracle Contract (`ExternalImpactOracleSpec`)

To eliminate self-grading bias, security impact on an OSS container stack is confirmed externally outside the system under test via one of four typed oracle kinds:

| Oracle Kind | Mechanism | Safety Constraint |
| --- | --- | --- |
| `db_query` | Read-only SQL `SELECT` against the isolated lab database container verifying unauthorized state mutation or privilege escalation | Query MUST start with `SELECT` and contain zero mutating DDL/DML keywords (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `TRUNCATE`, `CREATE`) |
| `container_log` | Structured regex/substring check on target container `stdout`/`stderr` audit stream | Pattern matches defensive audit/canary signal; supports `forbidPattern` for clean suppression checks |
| `loopback_oob_collector` | Isolated loopback HTTP collector recording internal SSRF/webhook pivots | `collectorUrl` MUST resolve strictly to `127.0.0.1` or `[::1]`; requires run-scoped `oss_canary_*` token when enabled |
| `file_integrity` | Checksum / marker / canary verification on a specific container path | `watchPath` MUST be an absolute path without `..` traversal |

Every oracle carries a `runScopedCanaryPrefix` (`oss_canary_*`), `expectedCorrelationField`, and bounded `pollTimeoutMs` (`100..60000` ms).

---

## 5. Two-Side Confirmation Contract (`lib/grader.ts`)

An anchor counts as a **True Positive (TP)** if and only if **both** sides confirm:

1. **External Impact Oracle Side:** An `ExternalOracleObservation` for `anchorId` with `buildTarget === 'vulnerable'`, `oracleId === anchor.impactOracle.oracleId`, `runId === receipt.runId`, and `observed === true`.
2. **Kovo `CompositeProofReceipt` Side:** A host-verified `KovoCompositeProofReceipt` (`verified === true`) satisfying:
   - `replayMode === 'fresh_clean_replay'` (Mode A is mandatory on benchmark anchors; Mode B `one_shot_transcript` is rejected).
   - **Attacker-Origin Provenance:** `attackerOriginVerified === true` and `originPersona` is listed in `anchor.personas` with `allowedAsChainOrigin: true` (victim/admin shortcutting is rejected).
   - **Causal Chain Completeness:** At least `anchor.hopCount` monotonically ordered hops (`t_1 <= t_2 <= ...`), with all `causalEdges` verified (`verified === true`) and connecting valid hops.
   - **Correlation & Temporal Order:** `terminalImpact.observed === true`, matching `correlationId` when present, and earliest hop timestamp `<= oracleObservation.observedAtMs`.

- **Oracle-only (no verified Kovo receipt):** Graded as **False Negative (`unconfirmed_oracle_only`)** — Kovo did not prove the chain.
- **Receipt-only (no external oracle confirmation) or rejected shortcut/edge/replay claim:** Graded as a **Spurious FP** — fails the 100% precision gate.

---

## 6. Paired Vulnerable vs Patched Commit & `patchBrokeHopId` Contract

Every `OssAnchorManifest` MUST pair:
- `vulnerableBuild`: pinned vulnerable release tag + 40-hex `commitSha` + `sha256:<64-hex>` `imageDigest`.
- `patchedBuild`: pinned official patched release tag + distinct 40-hex `commitSha` + `sha256:<64-hex>` `imageDigest`.
- `expectedPatchBrokeHopIds`: non-empty list of hop IDs from `anchor.hops` where the official patch is expected to break the causal chain.

Per `plans/v8.md` Open Decision #3, patch retest replays the full `CompositeProofReceipt` DAG against `patchedBuild` and reports `patchBrokeHopId`:
- A confirmed TP achieves patch-retest **closure** (`status: 'closed'`) iff:
  1. `replayedFullDag === true`
  2. `patchedCommitSha === anchor.patchedBuild.commitSha`
  3. `terminalImpactEliminated === true`
  4. `patchedOracleObservation` is present for `buildTarget === 'patched'` with `observed === false`
  5. `patchBrokeHopId` is a non-null, valid `hopId` belonging to `anchor.hops`
- Gate: `patchRetestClosureRate = patchRetestClosed / tpCount >= 0.80` (80% minimum closure).

---

## 7. Clean Patched Negative-Control Gate (0-FP)

`manifests/clean-controls.json` defines 2 pinned clean patched OSS targets with `maxAllowedFindings: 0`.
- **Any** finding or receipt emitted against a clean control (`fpCount > 0`) OR any unexpected external oracle trigger (`unexpectedOracleTriggers > 0`) immediately fails both `cleanControlGatePassed` and `precisionGatePassed` (`gates.passed = false`).

---

## 8. Metrics

- `recall = tpCount / totalAnchors`
- `precision = tpCount / (tpCount + totalFpCount)` (1.0 when `totalFpCount === 0`)
- `patchRetestClosureRate = patchRetestClosed / tpCount` (1.0 when `tpCount === 0`)
- `tpPerUsd = costUsd > 0 ? tpCount / costUsd : 0`
- `tpPer10m = durationMs > 0 ? tpCount / (durationMs / 600_000) : 0`
- `hopDepthFunnel`: counts anchors reaching `H1`, `H2`, `H3`, `H4+`, `oracleObserved`, and `twoSideConfirmed`.
