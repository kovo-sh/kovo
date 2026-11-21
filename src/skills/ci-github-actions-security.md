# CI/CD Security: GitHub Actions & Supply-Chain Hardening
Tags: ci, github-actions, supply-chain, workflow, oidc, permissions, static-analysis
Summary: Audit .github/workflows/*.yml and composite actions offline for untrusted event triggers, expression interpolation risks, excessive GITHUB_TOKEN permissions, and unpinned third-party actions.

## 1. Objective & Scope (Offline Static Analysis)
Audit `.github/workflows/*.{yml,yaml}` and `.github/actions/**/action.{yml,yaml}` inside `/repos` using `run_sast_scan` (`engines: ["opengrep", "gitleaks"]`) and `derive_evidence`. Never trigger or modify live CI pipelines.

## 2. High-Signal GitHub Actions Audit Checklist
1. **Dangerous Trigger & Checkout Patterns (`pull_request_target` / `workflow_run`):**
   - Flag `on: pull_request_target` combined with `actions/checkout` checking out untrusted fork refs (e.g., `github.event.pull_request.head.sha` or `head.ref`) followed by running build scripts, `npm install`, tests, or linters with repository write permissions or secrets.
   - Flag `workflow_run` workflows that unpack and execute untrusted build artifacts from fork PRs without strict schema/integrity validation.
2. **Untrusted Expression Interpolation in `run:` Blocks:**
   - Flag direct template interpolation of attacker-controllable event fields (such as PR title, PR body, branch `head_ref`, commit message, issue title/body, or comment body) inside shell `run:` or `github-script` steps instead of passing values safely through intermediate `env:` variables with double-quoted shell references.
3. **Excessive `GITHUB_TOKEN` Permissions:**
   - Check top-level and job-level `permissions:` blocks. Flag missing explicit `permissions: contents: read` or overly broad `permissions: write-all` / `id-token: write` / `packages: write` on untrusted PR jobs.
4. **Action Pinning & Artifact Integrity:**
   - Flag third-party `uses: owner/action@main` or mutable major version tags (`@v1`, `@v3`) on sensitive release/deploy jobs; recommend full 40-character commit SHA pinning (`uses: owner/action@<sha>`).
   - Check `secrets: inherit` passed to external reusable workflows and verify deployment environments enforce required reviewers / branch protection rules.
5. **Artifact & Log Secret Leakage:**
   - Check whether workflows echo sensitive env vars, upload `.env` or debug dumps via `actions/upload-artifact`, or expose OIDC tokens in logs.

## 3. Closure & Verification
- Submit verified workflow vulnerabilities as `static_ast_proof` (`static_verified` tier) referencing the exact `.github/workflows/<file>.yml:line` and deterministic `opengrep`/`ast-grep` query.
- In `counterevidence`, evaluate whether repository branch protection, fork-approval gates, or read-only `permissions:` mitigate exploitability, and note this in `severityChangeConditions`.
- Close clean workflows with `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<workflow-file:line>"`).
