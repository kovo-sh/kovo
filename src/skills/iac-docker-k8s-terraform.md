# Cloud & IaC Audit: Docker, Kubernetes & Terraform Security
Tags: iac, docker, kubernetes, k8s, terraform, cloud, supply-chain, static-analysis
Summary: Audit Dockerfiles, docker-compose specs, Kubernetes manifests, Helm charts, and Terraform configurations offline using Trivy/Opengrep to detect privilege escalation, public exposure, and secret leakage.

## 1. Objective & Scope (Offline Static Analysis)
Audit infrastructure-as-code files mounted under `/repos/<owner>/<repo>` strictly offline via `run_sast_scan` (`engines: ["trivy-fs", "opengrep", "gitleaks"]`) and `derive_evidence`. Never attempt to query live cloud metadata endpoints or modify external infrastructure.

## 2. Docker & Container Hardening Checklist
Inspect `Dockerfile*` and `docker-compose*.yml`:
1. **Non-Root Execution:** Verify a non-root `USER` is set (`USER 10001` or dedicated app user). Flag containers running as `root` or with `privileged: true`.
2. **Capabilities & Filesystem:** Check for missing `cap_drop: [ALL]`, `read_only: true`, `no-new-privileges:true`, or unsafe host bind mounts (`/var/run/docker.sock`, `/etc`, `/proc`, `/`).
3. **Secrets & Base Images:** Flag secrets baked into `ENV`, `ARG`, or `COPY .env` layers (they persist in image history). Prefer pinned image digests (`@sha256:...`) over mutable `:latest` tags.
4. **Network Exposure:** Flag databases/caches (`5432`, `6379`, `27017`, `9200`) bound to `0.0.0.0` instead of internal networks or `127.0.0.1`.

## 3. Kubernetes & Helm Manifest Checklist
Inspect `*.yaml` / `*.yml` under `k8s/`, `deploy/`, `charts/`, `manifests/`:
1. **Pod Security Context:** Flag `runAsNonRoot: false`, `privileged: true`, `allowPrivilegeEscalation: true`, `hostNetwork: true`, `hostPID: true`, `hostIPC: true`, or `hostPath` mounts.
2. **RBAC Over-Privilege:** Audit `ClusterRole` / `Role` definitions for wildcard verbs (`["*"]`), wildcard resources, `secrets` read access across namespaces, `pods/exec`, or `impersonate` grants.
3. **Network & Secrets:** Check for missing `NetworkPolicy` isolation on sensitive workloads, `automountServiceAccountToken: true` on untrusted pods, or plaintext secrets committed in `ConfigMap`/`Secret` manifests.

## 4. Terraform & Cloud Config Checklist
Inspect `*.tf`, `*.tfvars`, and policy JSON files:
1. **Public Storage & Databases:** Flag S3/GCS/Azure storage buckets with public read/write ACLs, disabled public-access blocks, or databases with `publicly_accessible = true` and `0.0.0.0/0` ingress rules.
2. **IAM Least Privilege:** Flag `"Action": "*"` or `"Resource": "*"` policies, overly permissive `AssumeRole` trust policies, or missing encryption-at-rest (`kms_key_id` / `encrypted = true`).
3. **State & Variables:** Flag committed `terraform.tfstate` files or hardcoded credentials in `.tfvars`.

## 5. Closure & Verification
- For concrete IaC misconfigurations in `/repos`, submit a `static_ast_proof` (`static_verified` tier) citing the exact manifest `file:line`, rule pattern, and `counterevidence` (checking whether an outer policy controller like OPA/Kyverno or Terraform module override mitigates the risk).
- Close clean configurations via `record_coverage` (`status: "ruled_out"`, `enforcingControl: "<file:line>"`).
