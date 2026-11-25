# File Path Canonicalization & Directory Containment Audit
Tags: path-traversal, canonicalization, filesystem, file-download, static-files, code-audit
Summary: Audit file-serving routes, archive extractors, and storage path resolvers for missing root-directory containment checks using offline SAST and Kovo Hunter’s non-destructive path normalization controls.

## 1. Root Cause & Defensive Code Review (`/repos`)
Directory boundary bugs happen when user-supplied filenames, template names, or asset paths are concatenated onto a base directory without canonicalizing the resolved path and asserting containment inside the intended root.

Inspect `/repos` with `run_sast_scan` (`opengrep`, `ast-grep`, `bandit`) and `derive_evidence`:
1. **Path Join & Resolution Sinks:**
   - **Node.js / TypeScript:** Inspect `fs.readFile`, `fs.createReadStream`, `res.sendFile`, and `path.join(BASE_DIR, userInput)`. Verify the code calls `path.resolve(BASE_DIR, userInput)` AND checks that the resolved real path (`fs.realpathSync`) starts with `BASE_DIR + path.sep` (never just `.startsWith(BASE_DIR)` without the trailing separator, which misses sibling prefix directories like `/app/uploads-private`).
   - **Python (FastAPI / Django / Flask):** Flag `os.path.join(BASE_DIR, filename)` where an absolute user string discards `BASE_DIR`; require `Path(BASE_DIR).resolve()` containment checks (`resolved.is_relative_to(base)`).
   - **Java / Go / Ruby:** Verify `Paths.get(...).normalize().startsWith(base)` (Java), `filepath.Clean` + prefix check after `EvalSymlinks` (Go), and `File.expand_path` containment (Ruby).
2. **Double Decoding & Proxy Normalization Mismatches:**
   - Check reverse proxies (Nginx/CDN) vs backend routers for URL-decoding discrepancies or path-parameter normalization mismatches between auth middleware and file handlers.
3. **Archive Extraction (Zip Slip):**
   - Inspect tar/zip extractors (`adm-zip`, `tar`, `zipfile`, `ZipInputStream`) to ensure every entry destination is canonicalized and verified to stay within the extraction directory before writing.

## 2. Strictly Non-Destructive Verification
- **Hard Guardrail:** Never request sensitive host files, system credentials, or private keys.
- Use Kovo Hunter’s host-side `probe_differential` (`probeClass: "path_traversal_benign"`), which sends strictly harmless self-reference and non-existent canonicalization controls through `RequestBroker` to detect normalization bypasses without reading sensitive host data.
- For source-only findings, verify the unguarded sink deterministically with `static_ast_proof` (`static_verified` tier).

## 3. Closure & Remediation
- **Remediation:** Prefer opaque database IDs mapped to server-controlled filenames. When filenames are required, validate against a strict basename allowlist, resolve symlinks, and enforce `resolvedPath.startsWith(canonicalBase + sep)`.
- **Closure:** Confirm live boundary flaws via `http_chain` Replay Specs with a benign control and non-empty `counterevidence`; rule out safe handlers by quoting the exact canonicalization check `file:line` in `enforcingControl`.
