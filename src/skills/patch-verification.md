# Air-Gapped Patch Authoring & Independent 6-Gate Verification
Tags: patch, remediation, verification, code-review, diff, security-fix, offline
Summary: Author minimal, repository-native security patches inside an air-gapped container and validate every diff through Kovo Hunter’s independent 6-gate Patch Reviewer without breaking legitimate callers.

## 1. Patch Author Workflow (`patch-author`)
Work strictly inside the `--network none` container over a writable tmpfs copy of `/repos/<owner>/<repo>` (never modifying read-only `/repos` or contacting remote git hosts):
1. **Build a Coverage Inventory First:** Before editing a single line, search the entire repo for every sibling route, Server Action, resolver, service method, or writer touching the same broken security invariant (e.g., every endpoint querying the same table without `userId`, or every webhook missing signature verification).
2. **Author a Minimal, Idiomatic Fix:**
   - Match the repository’s existing auth helpers, ORM patterns, validation libraries, and error status codes (`401`/`403`/`404`).
   - Avoid unrelated formatting churn, broad refactors, or introducing new external dependencies (the container is air-gapped).
3. **Run Offline Checks:** Execute available local syntax checks, TypeScript/linter checks, or unit tests inside the offline container to verify the patch compiles cleanly.
4. **Produce Exact Artifacts:** Emit `fixBefore` (verbatim existing lines), `fixAfter` (replacement lines), unified `diff`, `codeLocations`, and the complete `coverageInventory`.

## 2. Independent 6-Gate Patch Review (`patch-reviewer`)
The reviewer operates in a fresh session with zero shared context from the author and evaluates six ordered gates strictly:
1. **Gate 1 — Applicability & Clean Diff:** Verify `fixBefore` matches `/repos` verbatim, the unified diff applies cleanly, and syntax/typechecks pass.
2. **Gate 2 — Security Closure:** Quote the exact enforcing `file:line` in the patched code that closes the vulnerability on the attacker’s exact execution path.
3. **Gate 3 — Sibling Coverage:** Verify the Coverage Inventory did not miss sibling routes, HTTP methods, GraphQL fields, or background writers sharing the same flaw.
4. **Gate 4 — Legitimate-Caller Compatibility:** Classify impact strictly into one of:
   - `attacker_only` — rejects only unauthorized/malicious inputs; safe to approve.
   - `needs_operator_step` — safe code change that requires an operator config step (e.g., setting a webhook secret env var or DB migration).
   - `breaks_callers` — breaks valid existing callers, UI clients, or API contracts. **MANDATORY: automatically withhold (`status: "withheld"`) any patch classified `breaks_callers`!**
5. **Gate 5 — Repo Conventions & Minimality:** Confirm the diff is minimal, readable, and idiomatic without introducing new regressions or leaking secrets.
6. **Gate 6 — Optional Dynamic Fix Retest (`local-lab`):** When running in opt-in `local-lab` mode, rebuild the isolated `--internal` target with the patch applied and re-run the persisted TypeScript `kovo_verify` proof (Zero-LLM dynamic fix retest) to verify `reproduced -> fixed`.
