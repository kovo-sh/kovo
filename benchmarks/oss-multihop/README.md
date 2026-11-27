# `oss-multihop` — Real-World OSS / CVE Multi-Hop Anchor Corpus

`benchmarks/oss-multihop/` defines the declarative anchor specifications, safety validators, external impact oracle evaluators, and two-side grading engine for Kovo v8's Real-World OSS Multi-Hop Anchor Corpus (see [`plans/v8.md`](../../plans/v8.md) §"Real-World OSS / CVE Multi-Hop Anchor Corpus", §M2, and §M4).

Binding specification: [`CONTRACTS.md`](./CONTRACTS.md).

---

## Corpus Structure

| Split | Targets | Purpose |
| --- | --- | --- |
| **Dev Anchors (M2)** | 4 pinned OSS multi-hop anchors (`gitea`, `directus`, `ghost`, `mattermost`) | Iterative M2–M3 validation across Go, TypeScript, and JavaScript multi-service stacks |
| **Sealed Anchors (M4)** | 4 sealed OSS multi-hop anchors (kept outside dev hill-climbing; schema in `manifests/sealed-manifest.example.json`) | Blind M4 generalization certification |
| **Clean Negative Controls (M4)** | 2 pinned clean patched OSS targets (`vikunja`, `outline`) | Hard 0-FP precision gate (`maxAllowedFindings: 0`) |

---

## Safety & Isolation Guarantees

1. **Zero npm dependencies:** Pure Node 24+ native TypeScript (`node:*` built-ins only), `erasableSyntaxOnly: true`.
2. **Local-Lab Gate:** Lab selftests require `KOVO_ALLOW_LOCAL_LAB=1`.
3. **Strict `--internal` Docker lab networks:** Every Compose network MUST set `internal: true` (`egressPolicy: "deny_all_internal_only"`). Host networking (`network_mode: host`), `privileged: true`, and dangerous Linux capabilities (`NET_ADMIN`, `SYS_ADMIN`, etc.) are rejected by the manifest validator.
4. **Loopback-only port publication:** Host port bindings are allowed only on entry `app` or `lab_proxy` services and MUST bind `127.0.0.1:<port>:<containerPort>` (default `127.0.0.1:0:<containerPort>`). Internal targets, databases, caches, and async workers may never publish host ports.
5. **Pinned vulnerable & patched commits:** Every anchor pins both `vulnerableBuild` and `patchedBuild` with non-floating version tags, 40-hex commit SHAs, and `sha256:<64-hex>` OCI image digests.
6. **Zero exploit payloads committed:** Manifests contain only defensive QA architecture metadata, synthetic credential handles (`oss_lab_*`), read-only external impact oracle specs, and patch-retest contracts.

---

## Usage

```bash
# List committed dev anchors and clean negative controls
node benchmarks/oss-multihop/run.ts list

# Validate all committed manifests (dev anchors, clean controls, sealed template)
node benchmarks/oss-multihop/run.ts validate --all

# Validate a custom manifest file
node benchmarks/oss-multihop/run.ts validate --manifest /path/to/manifest.json

# Grade a run from structured JSON inputs
node benchmarks/oss-multihop/run.ts grade \
  --manifest benchmarks/oss-multihop/manifests/dev-anchors.json \
  --controls benchmarks/oss-multihop/manifests/clean-controls.json \
  --input /path/to/run-observations.json \
  --json /path/to/scorecard.json \
  --md /path/to/scorecard.md

# Run the offline self-test suite (no Docker required)
KOVO_ALLOW_LOCAL_LAB=1 node benchmarks/oss-multihop/run.ts selftest

# Typecheck & run unit/safety tests
node_modules/.bin/tsc -p benchmarks/oss-multihop/tsconfig.json
KOVO_ALLOW_LOCAL_LAB=1 node --test benchmarks/oss-multihop/tests/
```

---

## Hard M4 Acceptance Gates (`plans/v8.md`)

| Metric | Gate |
| --- | --- |
| **Precision (worst-run)** | **100%** (`totalFpCount === 0`) |
| **Clean Patched OSS Controls** | **0 FPs** across both clean controls |
| **Sealed Anchor Recall** | **`>= 50%`** confirmed via two-side verification |
| **Patch-Retest Closure** | **`>= 80%`** of confirmed TPs closed on paired patched commit with verified `patchBrokeHopId` |
| **Efficiency Reporting** | Publishes `TP/$` (`tpPerUsd`), `TP/10m` (`tpPer10m`), and Hop-Depth Funnel |
