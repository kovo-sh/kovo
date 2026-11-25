# `multihop-saas` — build contracts (v8 M0)

Binding design for every module in this directory. The types in `lib/types.ts` are the frozen
contract; every archetype, monitor, solver, grader and test builds against them. Nothing here may
weaken an inherited `realistic-bench` / `reason-bench` safety invariant.

---

## 1. Hard rules

- **Scope:** write only under `benchmarks/multihop-saas/`. Never modify `src/`, root tests,
  `scripts/`, `package.json`, or existing benchmarks.
- **Runtime:** Node 24+ native TypeScript type stripping, ESM, explicit `.ts` relative imports,
  `import type` for types, erasable syntax only (no `enum`, no `namespace`, no parameter
  properties). **Zero npm dependencies** — only `node:*` built-ins.
- **Local-Lab Gate:** `GUARDIAN_ALLOW_LOCAL_LAB=1` is required before any server or service call.
  `assertLocalLabAllowed()` is invoked by `run.ts` (server commands), `startPaygrid`,
  `startServices`, `listenLoopback`, and `egress.fetch`.
- **Loopback only:** servers bind `127.0.0.1:0` exclusively through `lib/safety.ts`.
  `listenLoopback` rejects a post-bind address other than `127.0.0.1`. No other module may call
  `.listen(...)`.
- **Bounded egress:** service-to-service calls go through `lib/egress.ts`. Only registered loopback
  origins are accepted; paths must be absolute; redirects are disabled; responses are capped at
  64 KiB; every attempt is logged.
- **No dynamic execution:** no `child_process`, `eval`, `new Function`, `vm`, or
  `worker_threads` anywhere in the tree.
- **Virtual filesystem:** export/treasury content is served from `lib/vfs.ts` / in-memory lab
  state. Services never read or write a real host path.
- **Synthetic secrets only:** sessions (`mh_fake_sess_*`), PATs (`mh_fake_pat_*`), invites
  (`mh_fake_invite_*`), signing salts (`mh_fake_salt_*`), canaries (`mh_fake_canary_*`), and
  passwords (`mh_fake_pw_*`). No real keys, no `FLAG{}` strings.

---

## 2. Persona and topology contract

Exactly **7 actors across 3 tenants** per archetype:

| Persona | Tenant | Roles | Notes |
|---|---|---|---|
| `owner_a` | Org A | owner | privileged setup/victim arm; never attacker-eligible |
| `member_a` | Org A | member | attacker-eligible |
| `viewer_a` | Org A | viewer | low privilege; forbidden for several chains |
| `dual_member` | Org A / Org B | admin A, viewer B | dual-tenant attacker for cache-bleed chains |
| `member_b` | Org B | member | cross-tenant attacker |
| `revoked_or_demoted` | Org A | viewer (demoted) | revoked/demoted lifecycle actor |
| `admin_bot` | Org C | bot admin | victim bot; never credentialed to a scanner |

Tenant slugs form a prefix chain: `A`, `A-<suffix>`, `A-<suffix>-treasury`. The overlap is required
to exercise signed-prefix and sibling-tenant boundaries.

Every service has an `id`, `role`, `internal` flag and (when public) an `origin`. Five services are
required: `edge`, `api`, `worker`, `idp`, `vault.internal`.

---

## 3. Chain spec contract

```ts
interface ChainSpec {
  id: string                       // e.g. PG-C1
  title: string
  vulnClass: string                // terminal impact class
  hops: ChainHopSpec[]             // ordered; hop[0] has no edge
  terminal: { service, routeKey, kind }
  attackerPersonaSet: PersonaId[]  // provenance allowlist
  forbiddenShortcutPersonas: PersonaId[]
}

interface ChainHopSpec {
  hopId: string
  service: ServiceId
  routeKey: string                 // logical route key, not a literal URL
  actor: PersonaId
  edgeFromPrevious?: CausalEdgeKind
}
```

A single-hop finding is a 1-node DAG; this runtime currently certifies 3–5 hop chains.

---

## 4. Observation contract

Monitors consume **neutral application audit events** (kinds such as `template.updated`,
`worker.job_created`, `file.downloaded`) and record:

- **HopObservation:** `{ chainId, hopId, service, routeKey, actor, artifactDigest, entityId?,
  effectiveRole?, ts }`.
- **EdgeObservation:** `{ chainId, fromHopId, toHopId, kind, fromArtifactDigest, toConsumedDigest,
  derivedFromDigest?, entityId?, runId?, pollObserved?, ts }`.
- **ControlObservation:** `{ chainId, fromHopId, toHopId, entityId, result:
  'failed_without_predecessor' | 'unexpected_success', ts }`.
- **TerminalObservation:** `{ chainId, service, routeKey, kind, actor, entityId?, ts }`.

Ordering is by `ts`, then insertion `seq`. Hop timestamps must be monotonic (`t_i <= t_j`).
Artifacts are always SHA-256 digests; raw secret material is never stored in an observation.

---

## 5. Typed edge bindings (verification semantics)

| Kind | Required evidence | Verification |
|---|---|---|
| `value_binding` | `fromArtifactDigest`, `toConsumedDigest` | Both non-empty and equal to the producer hop's artifact digest; the consumer hop demonstrably used the same opaque handle/value. |
| `derived_crypto_binding` | `derivedFromDigest` | Equals the producer hop's artifact digest; represents a host-attested derivation (session minted from invite material, HMAC signed with leaked salt). |
| `state_transition_binding` | `entityId`, matching entity on both hops, **plus** a `ControlObservation` with `result: failed_without_predecessor` | Same shared entity/cache key mutated across hops; the terminal action fails cleanly without the predecessor state (ablation control). |
| `async_pivot_binding` | `runId === oracle.runId`, `pollObserved === true` | Trigger and downstream artifact share the run scope and were observed through bounded poll convergence in order. |

A missing edge, mismatched digest, missing control, wrong run scope, or regressed timestamp rejects
the chain with drop reason `edge_binding_rejected`.

---

## 6. Attacker-origin provenance (anti-shortcut)

- The **first hop** actor must be in `attackerPersonaSet`.
- **No hop** actor may be in `forbiddenShortcutPersonas`.
- The **terminal** actor must be attacker-eligible (same attacker or a capability derived inside the
  DAG; represented by the originating attacker persona on the derived session).
- `owner_a` may appear only in control/setup/victim arms, never as the chain origin or terminal
  actor. `admin_bot` is never attacker-eligible.

Violations fail closed with `persona_shortcut_rejected`, even if all edges are otherwise complete.

---

## 7. `CompositeProofReceipt` (host side)

Schema:

```ts
{
  chainId, terminalVulnClass,
  hops: [{ hopId, service, routeKey, actor, ts, artifactDigest }],
  causalEdges: [{ fromHopId, toHopId, kind, evidenceDigest }],
  terminalImpact: { kind, service, routeKey, ts },
  replayMode: 'fresh_clean_replay' | 'one_shot_transcript',
  signer: 'mh_host_runtime',
  signature: HMAC-SHA256(canonical payload, per-run key)
}
```

`verifyReceipt()` recomputes the MAC over a canonical, key-sorted payload and enforces:

1. chain id exists in the active spec set;
2. hop ids, services and route keys match the spec in order;
3. timestamps are monotonic;
4. every hop actor is attacker-eligible and none is forbidden;
5. edge ids and kinds match the spec in order;
6. terminal kind/service/route match the spec and follow the last hop;
7. terminal class matches `vulnClass`;
8. `replayMode === 'fresh_clean_replay'` (Mode A is mandatory for this benchmark; Mode B is
   rejected with `replay_mode_not_allowed` so it cannot mask flaky proofs);
9. the signature matches in constant time.

A receipt minted before the lineage is complete is refused. Tampered hop ids, actors, terminal
classes, replay modes and signatures all fail verification.

---

## 8. Two-side grading

A chain is a **true positive** iff:

```
ChainOracleV2.completed == true
  && ChainOracleV2.confirmed == true          // receipt present + signature verified
  && receipt.terminalVulnClass == finding.terminalVulnClass
  && receipt matches the finding's chain
```

FP accounting (strict):

| Category | Condition |
|---|---|
| `hardened_counterpart` | Any finding on a `mode: hardened` lab. |
| `decoy_twin` | Any finding on a partial twin (base chain id or a benign early hop id). **Strict decoy FP**, fails the precision gate. |
| `unmatched` | Finding chain id not in ground truth. |
| `unconfirmed` | Chain id exists but the oracle/receipt sides do not both confirm. |

`precision = tp / (tp + fp)`, `recall = tp / expected`. A gate passes only when precision is 100%,
there are zero strict decoy FPs, and all expected chains are confirmed (or there are no expected
chains, as in hardened/twin labs).

### Hop-Depth Funnel

`hopFunnel(evaluations)` in `lib/chain-oracle.ts` reports:

`H1 -> H2 -> H3 -> H4+ -> FinalOracle -> CompositeReceiptConfirmed`

alongside per-hop drop reasons: `capability_not_extracted`, `pivot_not_discovered`,
`edge_binding_rejected`, `replay_failed`, `budget_exhausted`, `persona_shortcut_rejected`,
`terminal_not_observed`.

---

## 9. Application runtime contract

Every archetype must provide:

- **Five isolated loopback services** with distinct route surfaces and realistic benign workflows.
- **Renewable lifecycle hooks:** create/revoke invites and PATs, revoke sessions, create/cancel async
  jobs, rotate keys, and reset/clean-room semantics suitable for Mode-A replay.
- **`X-Guardian-Run-Id` tagging:** every created entity and async correlation carries the caller's
  run id; the worker only converges jobs for the same run scope.
- **Configurable async latency:** `asyncLatencyMs` is a first-class option; jobs expose `queued` /
  `ready` / `failed` / `cancelled` and are processed by bounded polling.
- **Synthetic secrets only**, as defined in §1.
- **No chain markers in `src/`:** application code uses domain vocabulary only. Statements such as
  “raw footer stored”, “cache primed without tenant”, “duplicate key relaxed” describe policy, not
  assessment outcomes.

---

## 10. Briefing contract

| Mode | Personas | Origins | API catalog | Source |
|---|---|---|---|---|
| `black-box` | `member_a`, `member_b`, `revoked_or_demoted` | edge entry only | no | no |
| `grey-box` | all 6 non-bot actors | public service origins; internal services named without origins | yes | no |
| `white-box` | all 6 non-bot actors | same as grey-box | yes | materialized snapshot |

`admin_bot` credentials are never present in any briefing.

---

## 11. Materialization and leakage

`materialize()` copies only:

- `apps/<app>/src/**` (application source), and
- `lib/safety.ts`, `lib/egress.ts`, `lib/vfs.ts` (runtime helpers).

It writes a neutral `variant.json` (seed, seed set, route prefix, tenants, service names) and no
mode/twin/chain/ground-truth data. `scanTreeForLeakage(root)` rejects:

- path segments `truth`, `solver(s)`, `decoy`, `oracle`, `chains`;
- content matching `/vulnerab\w*|\bhardened\b|\bdecoy\w*\b|\boracle\w*\b|\bsolver\w*\b|CWE-\d+|ground.?truth|PG-[CD]\d/i`.

`assertNoLeakage()` is called during every materialization; a leak aborts lab startup.

---

## 12. Seed contract

- Dev: integers `1..9999`; deterministic from the repository.
- Held-out: integers `>= 1_000_000`; reproduction requires `GUARDIAN_RB_HELDOUT_SALT` (>= 16 chars).
  The PRNG key is HMAC-SHA256(salt, seed/label); salts are never accepted on the command line and
  never written to artifacts.
- `listSeeds('dev', n)` returns `1..n`; `listSeeds('held-out', n)` returns unique HMAC-derived seeds.
- Domain variation randomizes tenants, personas, ids, emails, economics, route prefix and secrets
  without changing topology or chain semantics.

---

## 13. `paygrid` chain catalogue

### `PG-C1` — 4 hops — `self_approved_payout`

| Hop | Service / route key | Actor | Edge into hop |
|---|---|---|---|
| `pg-c1-h1` | edge / `directory.orgPublic` | `member_b` | — |
| `pg-c1-h2` | idp / `idp.inviteResolve` | `member_b` | `derived_crypto_binding` |
| `pg-c1-h3` | api / `api.payoutRebind` | `member_b` | `value_binding` |
| `pg-c1-h4` | api / `api.payoutApprove` | `member_b` | `state_transition_binding` |

Directory exposes a pending finance email containing an NFKC ligature. The attacker resolves an
invite with the NFKC-normalized address, receives an Org A finance session, rebinds a draft payout's
`createdBy`, then self-approves. The state edge requires a clean member-role denial on the same
payout.

### `PG-C2` — 4 hops — `forged_settlement`

| Hop | Service / route key | Actor | Edge into hop |
|---|---|---|---|
| `pg-c2-h1` | api / `api.templateUpdate` | `member_a` | — |
| `pg-c2-h2` | worker / `worker.jobRender` | `member_a` | `async_pivot_binding` |
| `pg-c2-h3` | worker / `worker.jobTrace` | `member_a` | `value_binding` |
| `pg-c2-h4` | vault.internal / `vault.settlementWebhook` | `member_a` | `derived_crypto_binding` |

A raw invoice footer is stored; the async PDF worker fetches an internal render hook and its trace
retains the settlement signing salt. The attacker signs a scoped settlement webhook with the leaked
salt.

### `PG-C3` — 5 hops — `cross_tenant_export`

| Hop | Service / route key | Actor | Edge into hop |
|---|---|---|---|
| `pg-c3-h1` | api / `api.permissionsPrime` | `dual_member` | — |
| `pg-c3-h2` | api / `api.exportCreate` | `dual_member` | `state_transition_binding` |
| `pg-c3-h3` | worker / `worker.jobPoll` | `dual_member` | `async_pivot_binding` |
| `pg-c3-h4` | api / `api.exportSignedUrl` | `dual_member` | `value_binding` |
| `pg-c3-h5` | edge / `file.treasuryDownload` | `dual_member` | `value_binding` |

Org A admin permissions are cached under a tenantless key. The same user's Org B viewer session
creates an export via the bleed, converges the job, receives a signed URL whose prefix omits the
trailing slash, and downloads the sibling treasury tenant (`acme-systems-treasury`).

### `PG-C4` — 3 hops — `ledger_overcredit`

| Hop | Service / route key | Actor | Edge into hop |
|---|---|---|---|
| `pg-c4-h1` | api / `api.orderCreate` | `member_a` | — |
| `pg-c4-h2` | api / `api.orderRebind` | `member_a` | `value_binding` |
| `pg-c4-h3` | api / `api.orderSettleRace` | `member_a` | `state_transition_binding` |

The edge parser reads the last duplicate `amountCents` (under cap) while the backend reads the first
(over cap). A draft order is rebound into an authorized beneficiary, then two concurrent capture
requests both credit the ledger. A pre-rebind capture denial supplies the ablation control.

---

## 14. Partial-twin contract

`TwinSpec` declares `{ id, baseChainId, decoyHopIds, enforcedAtHopId, note }`. Twins are lab
profiles, not separate ground-truth chains:

- Hops before the enforcement point genuinely execute and are observable (capability-only).
- The enforcement hop applies a real invariant and must prevent the terminal observation.
- Ground truth has **no expected chains**; every reported finding is a strict decoy FP.
- The selftest additionally requires `hopsObserved >= 2` to prove the twin is not simply a broken
  lab.

| Twin | Base | Enforced invariant |
|---|---|---|
| `PG-D1` | `PG-C1` | strict OIDC `tid` + verified email required on API sessions |
| `PG-D2` | `PG-C2` | worker trace redacted (no signing salt) |
| `PG-D3` | `PG-C3` | exact tenant prefix + trailing slash required on export paths |

`mode: hardened` applies every counterpart invariant: zero oracle events from any solver.

---

## 15. CLI contract

`run.ts` supports:

- `list` — apps, services, chains, twins.
- `seeds --set dev|held-out --n <n>` — held-out requires the env salt; `--salt` is refused.
- `serve --seed --mode vulnerable|hardened --twin --briefing black-box|grey-box|white-box
  --async-latency-ms --out-dir --once` — held-out salt on the command line is refused.
- `grade --truth --findings --oracle [--json --md]`.
- `selftest --seeds 1,2,3 --async-latency-ms` — vulnerable 4/4, hardened 0 events, three twins with
  ≥2 hops and 0 terminals.
- `anti-heuristic-check --scorecard <file> --max-recall 0.05` (or a full grade input).

Exit code `2` signals a failed gate; `1` is an operational error.

---

## 16. Test contract (minimum)

- **`safety.test.ts`:** static banned constructs, single `.listen` owner, no wildcard binds or
  external URL literals, zero dependencies, synthetic secrets, gate enforcement (including
  `startPaygrid` refusal), egress refusals, seed policy, persona/tenant topology, materialization
  leakage scan (positive and negative cases).
- **`causal-dag.test.ts`:** all four edge bindings, out-of-order rejection, persona-shortcut
  rejection at first/terminal hop, missing ablation control, wrong async run scope, receipt
  tampering, non-Mode-A rejection, two-side confirmation, strict twin/hardened FP grading, funnel
  and drop reasons.
- **`paygrid.test.ts`:** vulnerable 4/4 with both-side confirmation; hardened 0 events + fabricated
  finding classification; three twins with real early hops and 0 terminals + strict decoy grading;
  leak-free white-box snapshot; mode-scoped briefings; lifecycle hooks; run-id tagging; configurable
  async latency; salted held-out run; anti-heuristic floor.

---

## 17. Change policy

- Additive changes to `lib/types.ts` are allowed; do not fork the edge kinds, persona set, seed sets,
  or receipt schema.
- Any new archetype must prove the full test contract before it is listed in `appNames`.
- No benchmark literal (archetype names, chain ids, internal service hostnames, `mh_fake_*`) may
  enter `src/server/` or `src/skills/`; that boundary is enforced outside this directory.
- Never weaken the leakage scanner, the loopback guard, the gate, or the strict decoy FP rule to make
  a chain pass.
