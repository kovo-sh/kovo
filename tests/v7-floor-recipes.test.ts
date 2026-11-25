/**
 * v7 M0 Cut 3 — typed floor recipe runner tests.
 *
 * These run the recipes against fake Layer-1 deps (no HTTP server): each fixture is a transcript
 * shape, so a recipe is exercised exactly as the broker adapter will drive it in production.
 */
import assert from 'node:assert/strict'
import test from 'node:test'
import { buildProofReceipt } from '../src/server/proof-receipt.ts'
import {
  FLOOR_RECIPE_IDS,
  MAX_FLOOR_RECIPE_STEPS,
  SPEC_KIND_RECIPES,
  floorRecipe,
  recipeForSpecKind,
  runFloorRecipe,
} from '../src/server/floor-recipes.ts'
import type {
  AccessBoundaryArgs,
  BooleanOrTimingArgs,
  DisclosureArgs,
  FloorExchange,
  FloorRecipe,
  FloorRecipeDeps,
  FloorRequestSpec,
  OobCallbackArgs,
  PersistedMutationArgs,
  RaceBurstArgs,
} from '../src/server/floor-recipes.ts'

const ORIGIN = 'https://app.example.invalid'

function fixtureDeps(
  handler: (spec: FloorRequestSpec) => FloorExchange,
  oob?: FloorRecipeDeps['oob'],
): FloorRecipeDeps {
  let seq = 0
  return {
    request: spec => handler(spec),
    nextExchangeId: () => `fx-${++seq}`,
    ...(oob ? { oob } : {}),
  }
}

// ============================================================================
// Registry and migration table
// ============================================================================

test('registry exposes exactly the six Cut 3 recipes', () => {
  assert.deepEqual([...FLOOR_RECIPE_IDS].sort(), [
    'access_boundary',
    'boolean_or_timing',
    'disclosure',
    'oob_callback',
    'persisted_mutation',
    'race_burst',
  ])
  const recipe = floorRecipe('access_boundary', accessArgs())
  assert.equal(recipe.id, 'access_boundary')
  assert.equal(recipe.args.pathAndQuery, '/api/invoices/42')
})

test('spec-kind mapping is 1:1 for receipt-shaped kinds and explicit about the gaps', () => {
  for (const id of FLOOR_RECIPE_IDS) {
    assert.ok(SPEC_KIND_RECIPES.some(row => row.recipe === id), `no mapping row for ${id}`)
  }
  assert.equal(recipeForSpecKind('http_chain', 'bola'), 'access_boundary')
  assert.equal(recipeForSpecKind('http_chain', 'bfla'), 'access_boundary')
  assert.equal(recipeForSpecKind('http_chain', 'mass_assignment'), 'persisted_mutation')
  assert.equal(recipeForSpecKind('http_chain', 'workflow_bypass'), 'persisted_mutation')
  assert.equal(recipeForSpecKind('http_chain', 'csrf'), 'persisted_mutation')
  assert.equal(recipeForSpecKind('http_chain', 'info_disclosure'), 'disclosure')
  assert.equal(recipeForSpecKind('http_chain', 'xxe'), 'oob_callback')
  assert.equal(recipeForSpecKind('http_chain', 'ssrf'), 'oob_callback')
  assert.equal(recipeForSpecKind('sql_time_diff', 'sqli'), 'boolean_or_timing')
  assert.equal(recipeForSpecKind('sql_boolean_diff', 'sqli'), 'boolean_or_timing')
  const booleanMapping = SPEC_KIND_RECIPES.find(row => row.specKind === 'sql_boolean_diff')!
  assert.match(booleanMapping.note, /Boolean rule/)
  assert.doesNotMatch(booleanMapping.note, /EXCEPTION/)
  assert.equal(recipeForSpecKind('race_burst', 'race_double_spend'), 'race_burst')
  assert.equal(recipeForSpecKind('browser_chain', 'xss_stored'), null)
  assert.equal(recipeForSpecKind('rce_proof', 'ssti'), null)
  assert.equal(recipeForSpecKind('http_chain', 'path_traversal'), null)
  assert.equal(recipeForSpecKind('unknown_kind', 'bola'), null)
})

// ============================================================================
// access_boundary
// ============================================================================

function accessArgs(): AccessBoundaryArgs {
  return {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/invoices/42',
    vulnClass: 'bola',
    owner: { handle: 'owner', role: 'owner', tenant: 'acme' },
    probe: { handle: 'viewer', role: 'viewer', tenant: 'acme' },
    denied: { handle: 'peer', role: 'viewer', tenant: 'acme' },
    requiredRole: 'admin',
  }
}

function accessDeps(probeStatus = 200): FloorRecipeDeps {
  return fixtureDeps(spec => {
    if (spec.role === 'entitled_read') return { exchangeId: 'ex-owner', status: 200, json: { owner_id: 'u-owner' } }
    if (spec.role === 'denied_control') return { exchangeId: 'ex-peer', status: 403, json: { error: 'forbidden' } }
    return { exchangeId: 'ex-probe', status: probeStatus, json: { owner_id: 'u-owner' } }
  })
}

test('access_boundary confirms a served lower-privileged probe and names a denied probe', async () => {
  const confirmed = await runFloorRecipe(floorRecipe('access_boundary', accessArgs()), accessDeps())
  assert.equal(confirmed.failure, undefined, confirmed.failure?.message ?? "unexpected failure")
  assert.equal(confirmed.result.confirmed, true)
  assert.equal(confirmed.result.verification.confirmed, true, confirmed.result.verification.reason)
  assert.equal(confirmed.result.verification.rule, 'impact')
  assert.deepEqual(confirmed.result.exchangeIds, ['ex-owner', 'ex-peer', 'ex-probe'])

  const hardened = await runFloorRecipe(floorRecipe('access_boundary', accessArgs()), accessDeps(403))
  assert.equal(hardened.result.confirmed, false)
  assert.equal(hardened.result.verification.confirmed, false)
  assert.ok(hardened.failure)
  assert.ok(hardened.failure!.missingRoles.includes('probe_request'), hardened.failure!.missingRoles.join(','))
})

test('access_boundary rejects a control that was not denied, naming denied_control', async () => {
  const deps = fixtureDeps(spec => {
    if (spec.role === 'entitled_read') return { exchangeId: 'ex-owner', status: 200, json: { owner_id: 'u-owner' } }
    if (spec.role === 'denied_control') return { exchangeId: 'ex-peer', status: 200, json: { owner_id: 'u-owner' } }
    return { exchangeId: 'ex-probe', status: 200, json: { owner_id: 'u-owner' } }
  })
  const run = await runFloorRecipe(floorRecipe('access_boundary', accessArgs()), deps)
  assert.equal(run.result.confirmed, false)
  assert.ok(run.failure)
  assert.equal(run.failure!.code, 'precondition_unsatisfied')
  assert.ok(run.failure!.missingRoles.includes('denied_control'), run.failure!.missingRoles.join(','))
})

// ============================================================================
// persisted_mutation
// ============================================================================

function mutationArgs(vulnClass = 'mass_assignment'): PersistedMutationArgs {
  return {
    origin: ORIGIN,
    method: 'PATCH',
    pathAndQuery: '/api/invoices/42',
    vulnClass,
    actor: { handle: 'member', role: 'member', tenant: 'acme' },
    body: { owner_id: 'u2' },
  }
}

function mutationDeps(after: { owner_id: string }): FloorRecipeDeps {
  return fixtureDeps(spec => {
    if (spec.role === 'baseline_read') return { exchangeId: 'ex-before', status: 200, json: { owner_id: 'u1', status: 'open' } }
    if (spec.role === 'mutation_probe') return { exchangeId: 'ex-write', status: 200, json: after }
    return { exchangeId: 'ex-after', status: 200, json: { ...after, status: 'open' } }
  })
}

test('persisted_mutation confirms a body field read back by a separate GET', async () => {
  const run = await runFloorRecipe(floorRecipe('persisted_mutation', mutationArgs()), mutationDeps({ owner_id: 'u2' }))
  assert.equal(run.failure, undefined, run.failure?.message ?? "unexpected failure")
  assert.equal(run.result.confirmed, true)
  assert.equal(run.result.verification.rule, 'impact')
  assert.deepEqual(run.result.exchangeIds, ['ex-before', 'ex-write', 'ex-after'])
})

test('persisted_mutation rejects a mutation echo whose readback is unchanged', async () => {
  const run = await runFloorRecipe(floorRecipe('persisted_mutation', mutationArgs()), mutationDeps({ owner_id: 'u1' }))
  assert.equal(run.result.confirmed, false)
  assert.ok(run.failure)
  assert.equal(run.failure!.code, 'receipt_rejected')
  assert.ok(run.failure!.missingRoles.includes('persisted_delta'), run.failure!.missingRoles.join(','))
})

test('persisted_mutation rejects a baseline-less chain, naming baseline_read', async () => {
  const deps = fixtureDeps(spec => {
    if (spec.role === 'baseline_read') return { exchangeId: 'ex-before', status: 200 }
    if (spec.role === 'mutation_probe') return { exchangeId: 'ex-write', status: 200, json: { owner_id: 'u2' } }
    return { exchangeId: 'ex-after', status: 200, json: { owner_id: 'u2' } }
  })
  const run = await runFloorRecipe(floorRecipe('persisted_mutation', mutationArgs()), deps)
  assert.equal(run.result.confirmed, false)
  assert.ok(run.failure!.missingRoles.includes('baseline_read'), run.failure!.missingRoles.join(','))
})

// ============================================================================
// boolean_or_timing
// ============================================================================

function timingArgs(mode: 'boolean' | 'timing' = 'timing'): BooleanOrTimingArgs {
  return {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/search?q=kovo',
    vulnClass: 'blind_sqli',
    mode,
  }
}

function timingDeps(controlMs: number, probeMs: number): FloorRecipeDeps {
  return fixtureDeps(spec => spec.role === 'timing_control'
    ? { exchangeId: 'ex-control', status: 200, durationMs: controlMs, body: '3 results' }
    : { exchangeId: 'ex-probe', status: 200, durationMs: probeMs, body: '3 results' })
}

test('boolean_or_timing confirms a stable >3x timing separation and rejects a noisy one', async () => {
  const confirmed = await runFloorRecipe(floorRecipe('boolean_or_timing', timingArgs()), timingDeps(40, 2_400))
  assert.equal(confirmed.failure, undefined, confirmed.failure?.message ?? "unexpected failure")
  assert.equal(confirmed.result.verification.rule, 'timing')
  assert.equal(confirmed.result.confirmed, true)

  const hardened = await runFloorRecipe(floorRecipe('boolean_or_timing', timingArgs()), timingDeps(40, 500))
  assert.equal(hardened.result.confirmed, false)
  assert.ok(hardened.failure!.missingRoles.includes('probe_delay'), hardened.failure!.missingRoles.join(','))
})

function booleanArgs(overrides: Partial<BooleanOrTimingArgs> = {}): BooleanOrTimingArgs {
  return {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: "/search?q=kovo%27+AND+%271%27%3D%271",
    controlPathAndQuery: "/search?q=kovo%27+AND+%271%27%3D%271",
    probePathAndQuery: "/search?q=kovo%27+AND+%271%27%3D%272",
    vulnClass: 'sqli',
    param: 'q',
    mode: 'boolean',
    rounds: 2,
    ...overrides,
  }
}

type BooleanRound = { control: FloorExchange; probe: FloorExchange }

function booleanDeps(rounds: BooleanRound[]): FloorRecipeDeps {
  let controlIndex = 0
  let probeIndex = 0
  return fixtureDeps(spec => spec.role === 'boolean_control'
    ? rounds[controlIndex++]!.control
    : rounds[probeIndex++]!.probe)
}

function vulnRounds(rounds = 2): BooleanRound[] {
  return Array.from({ length: rounds }, () => ({
    control: { status: 200, json: { rows: [{ id: 1 }, { id: 2 }], message: 'ok' } },
    probe: { status: 200, json: { rows: [], message: 'ok' } },
  }))
}

test('boolean_or_timing confirms a stable paired boolean differential', async () => {
  const run = await runFloorRecipe(floorRecipe('boolean_or_timing', booleanArgs()), booleanDeps(vulnRounds()))
  assert.equal(run.failure, undefined, run.failure?.message ?? 'unexpected failure')
  assert.equal(run.result.confirmed, true, run.result.verification.reason)
  assert.equal(run.result.verification.rule, 'boolean')
  assert.equal(run.receipt.exchangeIds.length, 4)
})

test('boolean_or_timing rejects hardened, echo-only, nonce-only, unstable and 5xx evidence', async () => {
  const hardened = await runFloorRecipe(floorRecipe('boolean_or_timing', booleanArgs()), booleanDeps(
    Array.from({ length: 2 }, () => ({
      control: { status: 200, json: { rows: [{ id: 1 }] } },
      probe: { status: 200, json: { rows: [{ id: 1 }] } },
    })),
  ))
  assert.equal(hardened.result.confirmed, false)
  assert.ok(hardened.failure!.missingRoles.includes('structural_delta'), hardened.failure!.missingRoles.join(','))

  const echoed = await runFloorRecipe(floorRecipe('boolean_or_timing', booleanArgs()), booleanDeps(
    Array.from({ length: 2 }, () => ({
      control: { status: 200, json: { result: '' } },
      probe: { status: 200, json: { result: "kovo' AND '1'='2" } },
    })),
  ))
  assert.equal(echoed.result.confirmed, false)
  assert.match(echoed.result.verification.reason, /echoed|nonce/i)

  const nonce = await runFloorRecipe(floorRecipe('boolean_or_timing', booleanArgs()), booleanDeps(
    Array.from({ length: 2 }, () => ({
      control: { status: 200, json: { rows: [], nonce: 'abc12345' } },
      probe: { status: 200, json: { rows: [], nonce: 'abcdef0123456789abcdef01' } },
    })),
  ))
  assert.equal(nonce.result.confirmed, false)

  const unstable = await runFloorRecipe(floorRecipe('boolean_or_timing', booleanArgs()), booleanDeps([
    { control: { status: 200, json: { rows: [{ id: 1 }] } }, probe: { status: 200, json: { rows: [] } } },
    { control: { status: 200, json: { rows: [{ id: 1 }] } }, probe: { status: 200, json: { rows: [{ id: 1 }] } } },
  ]))
  assert.equal(unstable.result.confirmed, false)
  assert.equal(unstable.result.verification.confirmed, false)
  assert.ok(unstable.failure!.missingRoles.includes('stable_differential'), unstable.failure!.missingRoles.join(','))

  const serverError = await runFloorRecipe(floorRecipe('boolean_or_timing', booleanArgs()), booleanDeps([
    { control: { status: 200, json: { rows: [{ id: 1 }] } }, probe: { status: 500, json: { error: 'boom' } } },
    { control: { status: 200, json: { rows: [{ id: 1 }] } }, probe: { status: 200, json: { rows: [] } } },
  ]))
  assert.equal(serverError.result.confirmed, false)
  assert.ok(serverError.failure!.missingRoles.includes('non_error_arm'), serverError.failure!.missingRoles.join(','))
})

test('boolean_or_timing rejects a request shape that differs beyond the predicate', async () => {
  const run = await runFloorRecipe(
    floorRecipe('boolean_or_timing', booleanArgs({ probePathAndQuery: "/search?q=kovo%27+AND+%271%27%3D%272&extra=1" })),
    booleanDeps(vulnRounds()),
  )
  assert.equal(run.result.confirmed, false)
  assert.ok(run.failure!.missingRoles.includes('request_shape'), run.failure!.missingRoles.join(','))
})

test('boolean_or_timing names a missing host duration', async () => {
  const deps = fixtureDeps(spec => spec.role === 'timing_control'
    ? { exchangeId: 'ex-control', status: 200, body: '3 results' }
    : { exchangeId: 'ex-probe', status: 200, durationMs: 2_400, body: '3 results' })
  const run = await runFloorRecipe(floorRecipe('boolean_or_timing', timingArgs()), deps)
  assert.equal(run.result.confirmed, false)
  assert.ok(run.failure!.missingRoles.includes('control_duration'), run.failure!.missingRoles.join(','))
})

// ============================================================================
// oob_callback
// ============================================================================

const CANARY = 'kovo-canary-0123456789abcdef01234567'

function oobArgs(): OobCallbackArgs {
  return {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/integrations/webhook-test',
    vulnClass: 'ssrf',
    token: CANARY,
    injectJsonBody: { url: `https://relay.invalid/c/${CANARY}` },
  }
}

function oobDeps(event: FloorRecipeDeps['oob']): FloorRecipeDeps {
  return fixtureDeps(
    () => ({ exchangeId: 'ex-inject', status: 202, json: { accepted: true } }),
    event,
  )
}

test('oob_callback confirms only a delivered callback that post-dates the carried token', async () => {
  const confirmed = await runFloorRecipe(floorRecipe('oob_callback', oobArgs()), oobDeps(() => ({
    id: 'sub-1',
    canaryId: 'c-1',
    token: CANARY,
    targetOrigin: ORIGIN,
    delivered: true,
    stage: 'late',
    receivedAtMs: 30_000,
    injectedAtMs: 1_000,
    latencyMs: 29_000,
  })))
  assert.equal(confirmed.failure, undefined, confirmed.failure?.message ?? "unexpected failure")
  assert.equal(confirmed.result.verification.rule, 'oob')
  assert.equal(confirmed.result.confirmed, true)
  assert.deepEqual(confirmed.result.oobEventIds, ['sub-1'])

  const missing = await runFloorRecipe(floorRecipe('oob_callback', oobArgs()), oobDeps(() => null))
  assert.equal(missing.result.confirmed, false)
  assert.ok(missing.failure!.missingRoles.includes('delivered_callback'), missing.failure!.missingRoles.join(','))

  const undelivered = await runFloorRecipe(floorRecipe('oob_callback', oobArgs()), oobDeps(() => ({
    id: 'sub-2',
    token: CANARY,
    targetOrigin: ORIGIN,
    delivered: false,
    receivedAtMs: 30_000,
    injectedAtMs: 1_000,
  })))
  assert.equal(undelivered.result.confirmed, false)
  assert.ok(undelivered.failure!.missingRoles.includes('delivered_callback'), undelivered.failure!.missingRoles.join(','))
})

test('oob_callback rejects a callback that arrived before injection, naming callback_causality', async () => {
  const run = await runFloorRecipe(floorRecipe('oob_callback', oobArgs()), oobDeps(() => ({
    id: 'sub-3',
    token: CANARY,
    targetOrigin: ORIGIN,
    delivered: true,
    receivedAtMs: 500,
    injectedAtMs: 1_000,
  })))
  assert.equal(run.result.confirmed, false)
  assert.ok(run.failure!.missingRoles.includes('callback_causality'), run.failure!.missingRoles.join(','))
})

// ============================================================================
// race_burst
// ============================================================================

function raceArgs(): RaceBurstArgs {
  return {
    origin: ORIGIN,
    method: 'POST',
    pathAndQuery: '/api/checkout/redeem',
    vulnClass: 'business_logic',
    actor: { handle: 'member', role: 'member', tenant: 'acme' },
    body: { code: 'GIFT-1' },
    burst: 3,
  }
}

function raceDeps(outcomes: FloorExchange[]): FloorRecipeDeps {
  let index = 0
  return fixtureDeps(spec => {
    assert.match(spec.role, /^burst_\d+$/)
    const outcome = outcomes[Math.min(index, outcomes.length - 1)]!
    index += 1
    return outcome
  })
}

test('race_burst confirms a repeated terminal transition with divergent outcomes', async () => {
  const run = await runFloorRecipe(floorRecipe('race_burst', raceArgs()), raceDeps([
    { exchangeId: 'ex-b1', status: 200, json: { balance: 0 } },
    { exchangeId: 'ex-b2', status: 200, json: { balance: -100 } },
    { exchangeId: 'ex-b3', status: 409, json: { error: 'conflict' } },
  ]))
  assert.equal(run.failure, undefined, run.failure?.message ?? "unexpected failure")
  assert.equal(run.result.confirmed, true)
  assert.equal(run.result.verification.rule, 'impact')

  const single = await runFloorRecipe(floorRecipe('race_burst', raceArgs()), raceDeps([
    { exchangeId: 'ex-b1', status: 200, json: { balance: 0 } },
    { exchangeId: 'ex-b2', status: 409, json: { error: 'conflict' } },
    { exchangeId: 'ex-b3', status: 409, json: { error: 'conflict' } },
  ]))
  assert.equal(single.result.confirmed, false)
  assert.ok(single.failure!.missingRoles.includes('burst_repeat'), single.failure!.missingRoles.join(','))
})

test('race_burst rejects a uniform burst even when the receipt oracle would pass', async () => {
  const run = await runFloorRecipe(floorRecipe('race_burst', raceArgs()), raceDeps([
    { exchangeId: 'ex-b1', status: 200, json: { balance: 0 } },
    { exchangeId: 'ex-b2', status: 200, json: { balance: 0 } },
    { exchangeId: 'ex-b3', status: 200, json: { balance: 0 } },
  ]))
  assert.equal(run.result.confirmed, false)
  assert.equal(run.result.verification.confirmed, true, 'the repeated-transition rule alone accepts this')
  assert.equal(run.failure!.code, 'precondition_unsatisfied')
  assert.deepEqual(run.failure!.missingRoles, ['burst_divergence'])
})

// ============================================================================
// disclosure
// ============================================================================

function disclosureArgs(): DisclosureArgs {
  return {
    origin: ORIGIN,
    method: 'GET',
    pathAndQuery: '/api/documents/42',
    vulnClass: 'disclosure',
    owner: { handle: 'owner', role: 'owner', tenant: 'acme' },
    probe: { handle: 'member-a', role: 'member', tenant: 'acme' },
    denied: { handle: 'peer', role: 'member', tenant: 'acme' },
    baselinePathAndQuery: '/api/documents/self',
  }
}

function disclosureDeps(probeJson: Record<string, unknown>): FloorRecipeDeps {
  return fixtureDeps(spec => {
    if (spec.role === 'probe_baseline') return { exchangeId: 'ex-baseline', status: 200, json: { owner_id: 'u-member-a', status: 'active' } }
    if (spec.role === 'entitled_read') return { exchangeId: 'ex-owner', status: 200, json: { owner_id: 'u-victim', private_note: 'victim only' } }
    if (spec.role === 'denied_control') return { exchangeId: 'ex-peer', status: 403, json: { error: 'forbidden' } }
    return { exchangeId: 'ex-probe', status: 200, json: probeJson }
  })
}

test('disclosure confirms an owner-scoped field read while a peer is denied', async () => {
  const run = await runFloorRecipe(floorRecipe('disclosure', disclosureArgs()), disclosureDeps({
    owner_id: 'u-victim',
    private_note: 'victim only',
  }))
  assert.equal(run.failure, undefined, run.failure?.message ?? "unexpected failure")
  assert.equal(run.result.confirmed, true)
  assert.equal(run.result.verification.rule, 'impact')
  assert.equal(run.result.exchangeIds.length, 4)
})

test('disclosure rejects a response that only contains the probe actor\'s own data', async () => {
  const run = await runFloorRecipe(floorRecipe('disclosure', disclosureArgs()), disclosureDeps({
    status: 'active',
    result_count: 0,
  }))
  assert.equal(run.result.confirmed, false)
  assert.ok(run.failure)
  assert.equal(run.failure!.code, 'receipt_rejected')
  assert.ok(run.failure!.missingRoles.includes('disclosed_field'), run.failure!.missingRoles.join(','))
})

// ============================================================================
// Runner invariants
// ============================================================================

test('runs are byte-deterministic for identical fixtures', async () => {
  const first = await runFloorRecipe(floorRecipe('access_boundary', accessArgs()), accessDeps())
  const second = await runFloorRecipe(floorRecipe('access_boundary', accessArgs()), accessDeps())
  assert.equal(JSON.stringify(first), JSON.stringify(second))

  const rejectedFirst = await runFloorRecipe(floorRecipe('persisted_mutation', mutationArgs()), mutationDeps({ owner_id: 'u1' }))
  const rejectedSecond = await runFloorRecipe(floorRecipe('persisted_mutation', mutationArgs()), mutationDeps({ owner_id: 'u1' }))
  assert.equal(JSON.stringify(rejectedFirst), JSON.stringify(rejectedSecond))
})

test('runFloorRecipe validates the receipt against the transcript (no ghost exchanges)', async () => {
  const recipe: FloorRecipe = {
    id: 'access_boundary',
    args: accessArgs(),
    run: async ctx => {
      const step = await ctx.send({ arm: 'probe', role: 'probe_request', method: 'GET', pathAndQuery: '/api/invoices/42', actor: { handle: 'viewer' } })
      assert.equal(step.exchangeId, 'ex-ghost')
      return buildProofReceipt({
        vulnClass: 'bola',
        target: { origin: ORIGIN, method: 'GET', pathAndQuery: '/api/invoices/42' },
        exchangeIds: ['ex-ghost', 'ex-not-sent'],
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'A cited exchange must exist.',
      })
    },
  }
  const deps = fixtureDeps(() => ({ exchangeId: 'ex-ghost', status: 200, json: { owner_id: 'u-owner' } }))
  const run = await runFloorRecipe(recipe, deps)
  assert.equal(run.result.confirmed, false)
  assert.equal(run.result.verification.confirmed, false)
  assert.equal(run.failure!.code, 'receipt_rejected')
  assert.match(run.failure!.message, /ex-not-sent/)
})

test('a recipe that overruns the step budget fails with a named bound, never a partial proof', async () => {
  const recipe: FloorRecipe = {
    id: 'access_boundary',
    args: accessArgs(),
    run: async ctx => {
      for (let index = 0; index < MAX_FLOOR_RECIPE_STEPS + 1; index += 1) {
        await ctx.send({ arm: 'probe', role: `probe_${index}`, method: 'GET', pathAndQuery: '/api/invoices/42', actor: { handle: 'viewer' } })
      }
      throw new Error('unreachable')
    },
  }
  const deps = fixtureDeps(spec => ({ exchangeId: `ex-${spec.role}`, status: 200, json: { ok: true } }))
  const run = await runFloorRecipe(recipe, deps)
  assert.equal(run.result.confirmed, false)
  assert.equal(run.result.steps.length, MAX_FLOOR_RECIPE_STEPS)
  assert.equal(run.failure!.code, 'step_budget_exceeded')
  assert.ok(run.failure!.missingRoles.includes('step_budget'))
})
