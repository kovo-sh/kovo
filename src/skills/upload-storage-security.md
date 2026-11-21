# File Upload, Presigned URLs & Object Storage Security
Tags: upload, storage, s3, r2, presigned-url, content-type, svg, path-traversal
Summary: Audit upload endpoints, presigned object-storage URLs, MIME/content-disposition handling, bucket listing controls, and cross-tenant object isolation.

## 1. Upload & Storage Surface Mapping
1. Search harvested JS bundles, OpenAPI specs, and `project_specs` for upload handlers (`/upload`, `/presign`, `/signed-url`, `/attachments`, `/images`, `/files`, `S3`, `R2`, `GCS`, `blob.core.windows.net`).
2. Record discovered object-storage hosts via `suggest_candidate_host` if they are outside the currently approved scope (never send unapproved requests).

## 2. Defensive Checks (Tier 1 Read-Only & Tier 2 Multi-Persona)
- **Public Bucket / Directory Listing:** On approved storage origins, test `GET /` and parent path prefixes to verify XML bucket listings (`<ListBucketResult>`) or directory indexes are disabled.
- **Content-Type & Content-Disposition Enforcement:**
  - Inspect headers on existing user-uploaded asset endpoints: confirm `X-Content-Type-Options: nosniff` is set and untrusted user files (HTML, SVG, XML) are either served from an isolated sandbox domain or forced to download via `Content-Disposition: attachment`.
- **Presigned URL Scoping & Expiration (Code/Spec + Tier 2 Review):**
  - Inspect signed URL query parameters (`X-Amz-Expires`, `X-Amz-SignedHeaders`, `content-type`, `content-length-range`).
  - Verify whether upload-signing endpoints enforce authentication, per-tenant key prefixes (`users/<userId>/...`), strict allowed MIME types, and maximum file size bounds.
- **Cross-Tenant Attachment Access (Tier 2):**
  - Check whether private attachment URLs use guessable sequential keys or omit authorization checks between `tenant_a` and `tenant_b`.
- **Path Normalization Review:**
  - Verify upload/download filename parameters reject relative path segments and remain confined to the expected tenant prefix (observe validation errors safely without attempting sensitive host file reads).

## 3. Verification & Replay Spec Guidelines
- Use `kind: "http_chain"` with a `control` request (legitimate static asset or unauthorized control) and a `probe` request verifying exact response status, `Content-Type`, missing `Content-Disposition: attachment` or exposed XML `<ListBucketResult>`, or cross-tenant `persona` read.
- Never upload malicious executables or oversized files; state-changing upload probes require Tier 3 HITL approval.
