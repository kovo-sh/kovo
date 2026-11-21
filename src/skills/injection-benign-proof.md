# Non-Destructive Input Validation & Safe Proof-of-Execution Standards
Tags: input-validation, injection, rce-proof, tier-3, dynamic-nonce, verification
Summary: Audit server-side input handling and verify execution or parser flaws strictly through Guardian v2’s Tier 3 HITL gate and mathematically unforgeable non-destructive proof modes.

## 1. Passive & Differential Discovery First (Tier 1–2)
Before proposing any active execution check, gather strong structural evidence using read-only inspection:
1. Review synced source/specs (`project_specs`) and error responses for unsafe parsing boundaries (template rendering of user input, dynamic query construction, unsafe deserialization endpoints, shell/subprocess wrappers).
2. Send strictly benign syntax-boundary probes (e.g., mismatched quote/type validation checks on read-only query filters) and compare responses against a valid control request using `analyze_artifact` (`tool: "diff-response"`).
3. Record observed parser errors, framework versions, or unescaped reflection contexts via `record_fact` (`kind: "note"` or `kind: "cve_hypothesis"`).

## 2. Guardian v2 Non-Destructive Proof Standard (Tier 3 Only)
Guardian strictly prohibits destructive operations, persistent changes, file writes, host-file reads, reverse shells, or denial-of-service probes. All active execution verification MUST obey three invariants:
1. **Hard Tier 3 HITL Gate:** Active `rce_proof` specs are blocked at Tiers 0–2 on public targets and require explicit operator approval via an inline Approval Card showing the exact target, rationale, and benign template.
2. **Destructive Denylist Compliance:** Both `declarativeReplaySpecSchema` and `RequestBroker` reject destructive commands, file-write redirects, network shell patterns, and sensitive host/metadata paths.
3. **Unforgeable Verifier-Minted Nonces (Zero Reflection False Positives):**
   When constructing `kind: "rce_proof"`, never hardcode static expected outputs—always use placeholders populated fresh by Guardian’s Zero-LLM Replay Verifier at replay time:
   - **`proofMode: "dynamic_math"`:** Use `{{nonce_a}}` and `{{nonce_b}}` (verifier selects two fresh 5-digit primes). Confirmation succeeds only when the computed product appears in the probe response, is absent from `controlStep`, and is not merely literal input reflection.
   - **`proofMode: "split_echo"`:** Use `{{nonce_part1}}` and `{{nonce_part2}}` in a split concatenation template so the assembled token never appears in the HTTP request, eliminating reflection false positives.
   - **`proofMode: "oob_canary"`:** Use `{{canary_url}}` or `{{canary_token}}` for asynchronous/blind execution paths; the verifier mints separate control and probe Guardian canaries and confirms only when the probe canary triggers while the control canary stays silent.

## 3. Honest Fallback & Calibration
- If a target blocks outbound egress or only exhibits benign error-message disclosure without provable execution, report the verified error-exposure or input-validation weakness honestly (`medium`/`low`) rather than speculating about execution.
