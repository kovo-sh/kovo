# realism-suite — v6 north-star integration fixtures

A compact, deterministic integration suite encoding the real-world conditions that
loopback benchmarks hide. Four independent fixtures, each with a start/stop module,
offline ground truth (`truth.json`), a one-page README, and a raw-HTTP self-test.
Everything binds `127.0.0.1:0`, requires `GUARDIAN_ALLOW_LOCAL_LAB=1`, uses synthetic
secrets only, and runs with Node 24+ type stripping and **zero npm dependencies**.

> Defensive QA context: these fixtures exist so a scanner's discovery, auth, replay and
> evidence pipeline can be measured against realistic enterprise, WAN, staging and
> white-box conditions — not to attack any real system.

## Fixtures

| Fixture | Encodes | Truth highlights |
| ------- | ------- | ---------------- |
| [`enterprise-spa`](fixtures/enterprise-spa/README.md) | CDN `assets.local` → `app.local` → `api.local`, external OIDC `idp.local`, hybrid HttpOnly cookie + Bearer + `X-Tenant-Id`, introspection-disabled GraphQL, interactive tabs/modals | stored XSS in the authenticated admin view, GraphQL BOLA, admin-export BFLA, `alg:none` refresh, IdP open redirect |
| [`wan-oob`](fixtures/wan-oob/README.md) | Edge proxy with seeded 50–300 ms jitter and rotating CSP nonces; worker callbacks 15–30 s after the response | blind SQLi, async SSRF, async XXE, unsigned webhook |
| [`staging-concurrency`](fixtures/staging-concurrency/README.md) | `staging_isolated` run tagging (`guardian-qa-<runId>-`), shared stateful DB, h2c transport | write-BOLA, report IDOR, checkout price tampering, HTTP/2 double-spend race, zero orphans after cleanup |
| [`monorepo-whitebox`](fixtures/monorepo-whitebox/README.md) | materialized multi-service repo with real `.git` history, nested mounts, 2,560 generated routes | 4-hop billing BOLA, 4-hop report SQLi, admin BFLA from middleware ordering, git-history regression |

Each fixture returns `origins` (loopback URLs), `hosts` (hostname → `127.0.0.1:port`),
`personas` (synthetic credentials + per-run tokens), and an API reference. `truth.json`
is never served. White-box fixtures additionally expose `sourceDir`, `resolve(path)` and
a git log/file reader.

## CLI

```bash
export GUARDIAN_ALLOW_LOCAL_LAB=1

node benchmarks/realism-suite/run.ts list
node benchmarks/realism-suite/run.ts brief --fixture enterprise-spa
node benchmarks/realism-suite/run.ts serve --fixture wan-oob          # SIGINT to stop
node benchmarks/realism-suite/run.ts grade --fixture enterprise-spa --findings findings.json
node benchmarks/realism-suite/run.ts selftest --fixture all
```

`grade` accepts either a JSON array of findings or `{ "findings": [...] }`. A finding is
`{ method?, origin?, endpoint, vulnClass?, cwe?, status? }`. `ruled_out` / `false_positive`
claims are ignored; decoy claims and unmatched endpoints count as false positives;
precision = TP / (TP + FP); recall and chain completion are reported too.

Programmatic API: `startFixture(name, opts)`, `briefingFor(started)`,
`gradeFixture(name, findings)`, `gradeFixtureFile(name, path)`.

## Safety

- `assertLocalLabAllowed()` runs before any fixture starts; without
  `GUARDIAN_ALLOW_LOCAL_LAB=1` start throws.
- Only `lib/safety.ts` calls `.listen(0, '127.0.0.1', …)`. No `0.0.0.0`, no wildcard binds.
- OOB/egress targets are loopback collectors only; the WAN proxy forwards to its own backend.
- No `child_process`, `eval`, `new Function`, or `vm` anywhere (`tests/safety.test.ts`).
- Webhook/OIDC/client secrets, tokens and canaries are synthetic (`rb_fake_*`, `rbs_fake_*`,
  `*.invalid`) and generated per run.
- `stop()` is idempotent and asserts teardown: timers cleared, temp trees removed, zero
  `guardian-qa-` records left behind.

## Validation

```bash
GUARDIAN_ALLOW_LOCAL_LAB=1 node --test benchmarks/realism-suite/tests/
node_modules/.bin/tsc -p benchmarks/realism-suite/tsconfig.json
npm run test:realism
scripts/worker-gate.sh
```

The suite is not part of the root `tsconfig.json` include list, so it ships its own
`tsconfig.json` (`tsc -p`).
