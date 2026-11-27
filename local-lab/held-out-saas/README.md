# Held-Out Modern SaaS Lab ("Orbit Workspace")

Kovo v4 Suite C: 20 planted High/Critical vulnerabilities + 6 hard decoys in a multi-tenant SaaS.
Pure Node.js stdlib (`node:http`, `node:crypto`, `node:sqlite`), synthetic data only, no npm install, no disk writes.

| File | Purpose |
| --- | --- |
| `manifest.json` | Ground truth: `challenges[]` (`hos-01..hos-20`, decoys `hos-d1..hos-d6`), personas, markers |
| `server.mjs` / `server.ts` | `startHeldOutSaasServer({ host?, port?, patchedIds? })` and `node server.mjs` entrypoint |
| `src/*.mjs` | identity, billing, graphql, xml-import, webhooks, content, files, server actions, decoys, pages |
| `Dockerfile`, `docker-compose.yml` | `node:24-bookworm-slim`, port 3000, `/health`; passes LabRunner's `--internal` compose sanitizer |
| `patches/hos-XX.patch` | One unified diff per vuln (flips one switch in `src/config.mjs`); `patches/index.json` |
| `smoke.mjs` | `node smoke.mjs`: 20/20 reproduce, 0/6 decoys, 20/20 fixed + per-patch isolation |
| `tools/generate-manifest.mjs` | Regenerates `manifest.json` (keeps markers) and the patch files |

## Safety

- Loopback only: the in-process launcher refuses non-loopback hosts unless `KOVO_LAB=1` (set by LabRunner).
- The only outbound primitive (`fetchLoopback`) refuses everything except `127.0.0.1` / `localhost` / `::1`
  (SSRF, XXE-OOB and JWT `jku` sinks).
- XXE `file://` and path traversal resolve against an in-memory virtual file system, never the host.
- SSTI uses a closed arithmetic/string interpreter (no `eval`, no `Function`, no child processes).
- SQL runs in an in-memory SQLite database; the time-delay primitives are bounded (3.5 s).

## Patch retest

`startHeldOutSaasServer({ patchedIds: ['hos-01'] })` or `server.setPatchedIds([...])` hot-toggles fixes.
For the Docker path, `LabRunner.rebuildWithPatch(runId, readFileSync('patches/hos-01.patch', 'utf8'))`
flips the same switch in the container's copy of `src/config.mjs`.

## Personas

`persona_a` (acme member), `persona_b` (globex member), `admin` (acme admin), `viewer` (acme viewer) — bearer HS256 JWTs.
`node seed-personas.mjs` prints them in LabRunner `seedCommand` JSON format.
