# Non-Destructive Input Validation & Safe Proof-of-Execution Standards
Tags: input-validation, injection, rce-proof, tier-3, dynamic-nonce, verification
Summary: Audit server-side input handling and verify execution or parser flaws strictly through Kovo v2’s Tier 3 HITL gate and mathematically unforgeable non-destructive proof modes.

## 1. Passive & Differential Discovery First (Tier 1–2)
Before proposing any active execution check, gather strong structural evidence using read-only inspection:
1. Review synced source/specs (`project_specs`) and error responses for unsafe parsing boundaries (template rendering of user input, dynamic query construction, unsafe deserialization endpoints, shell/subprocess wrappers).
2. Send strictly benign syntax-boundary probes (e.g., mismatched quote/type validation checks on read-only query filters) and compare responses against a valid control request using `analyze_artifact` (`tool: "diff-response"`).
3. Record observed parser errors, framework versions, or unescaped reflection contexts via `record_fact` (`kind: "note"` or `kind: "cve_hypothesis"`).

## 2. Kovo v2 Non-Destructive Proof Standard (Tier 3 Only)
Kovo strictly prohibits destructive operations, persistent changes, file writes, host-file reads, reverse shells, or denial-of-service probes. All active execution verification MUST obey three invariants:
1. **Hard Tier 3 HITL Gate:** Active execution probes are blocked at Tiers 0–2 on public targets and require explicit operator approval via an inline Approval Card showing the exact target, rationale, and benign verification approach.
2. **Destructive Denylist Compliance:** Both the TypeScript `kovo_verify` verifier and `RequestBroker` reject destructive commands, file-write redirects, network shell patterns, and sensitive host/metadata paths.
3. **Unforgeable Verifier-Minted Nonces (Zero Reflection False Positives):**
   When writing a TypeScript `kovo_verify` proof for injection or execution, never rely on hardcoded static echoes—use Kovo's host-backed proof helpers with fresh per-run nonces (`ctx.nonce` / `ctx.oob.mint`):
   - **Evaluated Differential (`ctx.proveInjectionDifferential`):** Compare a clean control request against a benign computed expression (e.g., arithmetic evaluation or split concatenation) so the expected output appears in the probe response, is absent from the control response, and is not merely literal input reflection.
   - **Boolean / Timing Differential (`ctx.proveBooleanOrTimingDiff`):** Verify blind predicate or timing differences across paired control-vs-variant rounds via the host oracle rather than single-shot heuristics.
   - **Out-of-Band Callback (`ctx.proveOobCallback` / `ctx.oob`):** For asynchronous/blind execution paths, mint fresh host-verified Kovo canaries and confirm only when the probe canary triggers while the control path stays silent.

## 3. Honest Fallback & Calibration
- If a target blocks outbound egress or only exhibits benign error-message disclosure without provable execution, report the verified error-exposure or input-validation weakness honestly (`medium`/`low`) rather than speculating about execution.
