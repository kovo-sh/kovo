/**
 * Wave 2 Item #6 (`agent-contract-single-source`) Static & Behavioral Contract Suite.
 *
 * Guarantees that every budget threshold, tool category, settlement message, proof-gap code,
 * and `kovo_verify` alias counter derives from ONE authoritative source of truth:
 *   1. Exhaustive AST extraction of every `defineTool` in `src/server/agent-session.ts`
 *      against `AGENT_TOOL_REGISTRY` in `src/server/agent-tool-registry.ts` (plus fail-closed
 *      settlement allowlist checks).
 *   2. Literal extraction of every `proofGapReason` code across prompts, session tools, and
 *      recon planner builders -> every advertised code parses via `parseProofGapCode`.
 *   3. Settlement rejection & wrap-up message lint -> every actionable tool named in a
 *      settlement message is in `SETTLEMENT_ALLOWED_TOOLS` (never tells the model to probe
 *      after probing tools are revoked).
 *   4. Single-source `AssignmentBudget` parity -> every rendered prompt number equals the
 *      enforced `AssignmentBudget` threshold for `single_step`, `multi_step`, and
 *      `multi_hop_chain`, and `runAgentSession` consumes `budget.settlementTurn` directly.
 *   5. Host-side `kovo_verify` tool-arg & script/SDK alias-usage telemetry counters.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

import {
  ALL_SPEC_PROOF_GAP_CODES,
  SPEC_PROOF_GAP_CODES,
  buildAgenticPromptContext,
  codeAuditPrompt,
  gapValidationRejectedMessage,
  parseProofGapCode,
  settlementBannerMessage,
  settlementNudgeMessage,
  settlementSpecDirective,
  specSubmissionRequiredMessage,
  wallClockSettlementMessage,
  wallClockSettlementMs,
  workerInvestigationPrompt,
} from '../src/server/agent-prompts.ts'
import {
  AGENT_TOOL_NAMES,
  AGENT_TOOL_REGISTRY,
  NETWORK_TOOLS,
  PARALLEL_READ_ONLY_TOOLS,
  ROUTE_EVIDENCE_TOOLS,
  SETTLEMENT_ALLOWED_TOOLS,
  SETTLEMENT_REVOKED_TOOLS,
  SETTLEMENT_SPEC_PAUSED_TOOLS,
  SETTLEMENT_WRAPUP_TOOLS,
  SPEC_SUBMISSION_TOOLS,
  buildWorkerTools,
  runAgentSession,
  settlementToolBlock,
} from '../src/server/agent-session.ts'
import {
  resolveAssignmentBudget,
  resolveWorkerSettlementMs,
  type AssignmentBudget,
} from '../src/server/exec-dispatch.ts'
import { computeWorkerWallClockPlan } from '../src/server/exec-worker-runner.ts'
import {
  KovoVerifyAliasCounter,
  detectKovoVerifyScriptAliases,
  getKovoVerifyAliasUsage,
  recordKovoVerifyAliasUsage,
  resetKovoVerifyAliasUsage,
  type KovoVerifyAliasKey,
} from '../src/server/verify-runner.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SESSION_SRC_PATH = join(REPO_ROOT, 'src/server/agent-session.ts')
const PROMPTS_SRC_PATH = join(REPO_ROOT, 'src/server/agent-prompts.ts')
const PLANNER_SRC_PATH = join(REPO_ROOT, 'src/server/exec-recon-planner.ts')

function extractDefineToolNames(sourcePath: string): string[] {
  const src = readFileSync(sourcePath, 'utf8')
  const sf = ts.createSourceFile(sourcePath, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const names: string[] = []
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node)
      && ts.isIdentifier(node.expression)
      && node.expression.text === 'defineTool'
      && node.arguments.length > 0
    ) {
      const arg0 = node.arguments[0]!
      if (ts.isObjectLiteralExpression(arg0)) {
        for (const prop of arg0.properties) {
          if (
            ts.isPropertyAssignment(prop)
            && ((ts.isIdentifier(prop.name) && prop.name.text === 'name')
              || (ts.isStringLiteral(prop.name) && prop.name.text === 'name'))
            && ts.isStringLiteral(prop.initializer)
          ) {
            names.push(prop.initializer.text)
          }
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)
  return names
}

function extractMentionedKnownToolNames(text: string): string[] {
  const tokens = text.match(/\b[a-z][a-z0-9_]{2,}\b/g) ?? []
  const known = new Set<string>(AGENT_TOOL_NAMES)
  return [...new Set(tokens.filter(token => known.has(token)))]
}

function extractProofGapReasonLiterals(sourceText: string): string[] {
  const found = new Set<string>()
  const re = /proofGapReason\s*=\s*(?:\\?["'])([^"'\\]+)(?:\\?["'])/g
  for (const match of sourceText.matchAll(re)) {
    const raw = (match[1] ?? '').trim()
    if (!raw || raw.includes('${')) continue
    // Split placeholder/union forms like `<status|cannot_build_spec>` and ignore generic `<...>` placeholders.
    const unwrapped = raw.replace(/^<|>$/g, '')
    for (const part of unwrapped.split('|')) {
      const token = part.trim()
      if (!token) continue
      if (token === 'code' || token === 'status' || token.startsWith('<')) continue
      if (/^[a-z][a-z0-9_]+$/.test(token)) found.add(token)
    }
  }
  return [...found]
}

// ============================================================================
// 1. Exhaustive Tool Registry & Fail-Closed Settlement Allowlist
// ============================================================================

test('every defineTool in agent-session.ts is categorized in AGENT_TOOL_REGISTRY with zero drift or typos', () => {
  const defined = extractDefineToolNames(SESSION_SRC_PATH)
  assert.ok(defined.length >= 40, `Expected >= 40 defineTool registrations, found ${defined.length}`)
  const definedSet = new Set(defined)
  const registrySet = new Set<string>(AGENT_TOOL_NAMES)

  const uncategorized = [...definedSet].filter(name => !registrySet.has(name))
  assert.deepEqual(uncategorized, [], `Uncategorized defineTool(s): ${uncategorized.join(', ')}`)

  const staleRegistryEntries = [...registrySet].filter(name => !definedSet.has(name))
  assert.deepEqual(staleRegistryEntries, [], `Stale AGENT_TOOL_REGISTRY entries not registered by defineTool: ${staleRegistryEntries.join(', ')}`)

  // Invalid handler-key typo must never reappear as a tool name in any derived set.
  for (const set of [
    SETTLEMENT_ALLOWED_TOOLS,
    SETTLEMENT_REVOKED_TOOLS,
    SETTLEMENT_WRAPUP_TOOLS,
    SETTLEMENT_SPEC_PAUSED_TOOLS,
    ROUTE_EVIDENCE_TOOLS,
    SPEC_SUBMISSION_TOOLS,
    PARALLEL_READ_ONLY_TOOLS,
    NETWORK_TOOLS,
  ]) {
    assert.equal(set.has('requestHttpRace'), false, 'handler-key typo requestHttpRace must not appear in tool sets')
  }

  // Previously uncategorized crawl_state_graph is now live-network, route-evidence, and revoked in settlement.
  assert.equal(AGENT_TOOL_REGISTRY.crawl_state_graph.network, true)
  assert.equal(AGENT_TOOL_REGISTRY.crawl_state_graph.routeEvidence, true)
  assert.equal(AGENT_TOOL_REGISTRY.crawl_state_graph.settlementAllowed, false)
  assert.equal(ROUTE_EVIDENCE_TOOLS.has('crawl_state_graph'), true)
  assert.equal(SETTLEMENT_REVOKED_TOOLS.has('crawl_state_graph'), true)
  assert.equal(SETTLEMENT_ALLOWED_TOOLS.has('crawl_state_graph'), false)
  assert.ok(
    settlementToolBlock({ name: 'crawl_state_graph', settling: true, turnsUsed: 16, maxTurns: 18 }),
    'crawl_state_graph must be blocked during settlement',
  )

  // Q2 repo & evidence tools are parallel read-only and allowed in settlement wrap-up.
  for (const q2Tool of ['read_repo_file', 'search_repo', 'read_evidence_slice'] as const) {
    assert.equal(AGENT_TOOL_REGISTRY[q2Tool].parallelReadOnly, true)
    assert.equal(AGENT_TOOL_REGISTRY[q2Tool].settlementAllowed, true)
    assert.equal(AGENT_TOOL_REGISTRY[q2Tool].settlementPhase, 'wrapup')
    assert.equal(PARALLEL_READ_ONLY_TOOLS.has(q2Tool), true)
    assert.equal(SETTLEMENT_WRAPUP_TOOLS.has(q2Tool), true)
  }

  // Registry internal invariants: every network tool is revoked in settlement, and no allowed tool has phase 'revoked'.
  for (const [name, meta] of Object.entries(AGENT_TOOL_REGISTRY)) {
    if (meta.network) {
      assert.equal(meta.settlementAllowed, false, `network tool ${name} must not be allowed in settlement`)
      assert.equal(meta.settlementPhase, 'revoked', `network tool ${name} must have settlementPhase='revoked'`)
    }
    if (meta.settlementAllowed) {
      assert.notEqual(meta.settlementPhase, 'revoked', `allowed tool ${name} cannot have settlementPhase='revoked'`)
    } else {
      assert.equal(meta.settlementPhase, 'revoked', `disallowed tool ${name} must have settlementPhase='revoked'`)
    }
  }
})

test('settlement gating uses a positive allowlist so unknown/new network tools fail closed', () => {
  const blockUnknown = settlementToolBlock({
    name: 'probe_unregistered_future_tool',
    settling: true,
    turnsUsed: 16,
    maxTurns: 18,
  })
  assert.ok(blockUnknown, 'unknown/new tool must fail closed during settlement')
  assert.match(blockUnknown!, /disabled during settlement/)

  // Not blocked before settlement begins.
  assert.equal(
    settlementToolBlock({
      name: 'probe_unregistered_future_tool',
      settling: false,
      turnsUsed: 2,
      maxTurns: 18,
    }),
    undefined,
  )
})

// ============================================================================
// 2. Proof-Gap Code Enum Extraction & Parser Parity
// ============================================================================

test('every proofGapReason literal advertised in prompts, session tools, and recon planner parses cleanly', () => {
  const sources = [
    { name: 'agent-prompts.ts', text: readFileSync(PROMPTS_SRC_PATH, 'utf8') },
    { name: 'agent-session.ts', text: readFileSync(SESSION_SRC_PATH, 'utf8') },
    { name: 'exec-recon-planner.ts', text: readFileSync(PLANNER_SRC_PATH, 'utf8') },
  ]
  const allExtracted: Array<{ file: string; code: string }> = []
  for (const source of sources) {
    for (const code of extractProofGapReasonLiterals(source.text)) {
      allExtracted.push({ file: source.name, code })
    }
  }
  assert.ok(allExtracted.length >= 2, `Expected >= 2 proofGapReason literals, found ${allExtracted.length}`)

  for (const { file, code } of allExtracted) {
    assert.equal(
      parseProofGapCode(code),
      code,
      `Advertised proofGapReason="${code}" in ${file} must parse via parseProofGapCode`,
    )
    assert.ok(
      (ALL_SPEC_PROOF_GAP_CODES as readonly string[]).includes(code),
      `Advertised proofGapReason="${code}" in ${file} must belong to ALL_SPEC_PROOF_GAP_CODES`,
    )
  }

  // Canonical list stays at 8 codes so renderSettlementSpecDirective never truncates any canonical code.
  assert.equal(SPEC_PROOF_GAP_CODES.length, 8)
  assert.equal(parseProofGapCode('cannot_build_spec'), 'cannot_build_spec')
  assert.equal(parseProofGapCode('cannot_build_spec: missing baseline'), 'cannot_build_spec')
})

test('kovo_verify repeated validation error advertises a canonical parseable proofGapReason', async () => {
  const tools = buildWorkerTools(
    { kovo_verify: async () => ({ confirmed: false }) },
    v => v,
    AbortSignal.timeout(5_000),
    16 * 1024,
    () => {},
  )
  const kv = tools.find(t => t.name === 'kovo_verify')
  assert.ok(kv)
  let lastText = ''
  for (let i = 0; i < 3; i += 1) {
    const res = await kv.execute({ runtime: 'ts' } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never)
    lastText = (res.output?.[0] as { text?: string })?.text ?? ''
  }
  const codes = extractProofGapReasonLiterals(lastText)
  assert.ok(codes.length >= 1, `Expected proofGapReason literal in repeated error: ${lastText}`)
  for (const code of codes) {
    assert.equal(parseProofGapCode(code), code)
    assert.ok((SPEC_PROOF_GAP_CODES as readonly string[]).includes(code))
  }
})

// ============================================================================
// 3. Truthful Settlement Rejection & Banner Messages
// ============================================================================

test('every tool recommended in settlement messages is in SETTLEMENT_ALLOWED_TOOLS and gap rejections never tell the model to probe during settlement', () => {
  const route = { method: 'POST', path: '/api/v1/orders/:id', params: ['amount'], origin: 'https://app.example.invalid' }
  const directive = settlementSpecDirective(route)
  const rejectedGaps = [{ key: 'POST /api/v1/orders/:id', code: 'auth_blocked' as const, missing: 'a 401/403 response' }]

  // Gap rejection during settlement (default settling=true) must NEVER tell the model to probe the route.
  for (const hasKovoVerify of [true, false]) {
    const msg = gapValidationRejectedMessage(rejectedGaps, route, { hasKovoVerify })
    assert.doesNotMatch(msg, /\bprobe the route\b/i, 'settlement gap rejection must not instruct probing')
    const mentioned = extractMentionedKnownToolNames(msg)
    assert.ok(mentioned.length >= 2, `Expected actionable settlement tools in gap rejection: ${msg}`)
    for (const tool of mentioned) {
      assert.equal(
        SETTLEMENT_ALLOWED_TOOLS.has(tool),
        true,
        `Tool "${tool}" named in settlement gapValidationRejectedMessage must be in SETTLEMENT_ALLOWED_TOOLS`,
      )
    }
  }

  // Other settlement-phase messages must only recommend tools in SETTLEMENT_ALLOWED_TOOLS.
  const settlementMessages = [
    specSubmissionRequiredMessage(route, { hasKovoVerify: true }),
    specSubmissionRequiredMessage(route, { hasKovoVerify: false }),
    settlementNudgeMessage({ turn: 16, maxTurns: 18, settlementTurn: 16, proofTools: ['kovo_verify'], specDirective: directive }),
    wallClockSettlementMessage({ elapsedMs: 75_000, wallClockMs: 90_000, proofTools: ['kovo_verify'], specDirective: directive }),
    settlementToolBlock({ name: 'request_http', settling: true, turnsUsed: 16, maxTurns: 18 })!,
    settlementToolBlock({ name: 'search_facts', settling: true, turnsUsed: 18, maxTurns: 18 })!,
    settlementToolBlock({ name: 'derive_evidence', settling: true, turnsUsed: 16, maxTurns: 18, specPending: true, specDirective: directive })!,
  ]

  for (const msg of settlementMessages) {
    // Exclude the blocked tool name itself when checking `settlementToolBlock` messages.
    const sanitized = msg.replace(/\b(request_http|search_facts|derive_evidence) is (?:disabled|paused)\b/g, '')
    for (const tool of extractMentionedKnownToolNames(sanitized)) {
      assert.equal(
        SETTLEMENT_ALLOWED_TOOLS.has(tool),
        true,
        `Tool "${tool}" named in settlement message must be in SETTLEMENT_ALLOWED_TOOLS:\n${msg}`,
      )
    }
  }

  // Settlement banner lists the exact SETTLEMENT_REVOKED_TOOLS set as revoked and only allowed tools as actions.
  const banner = settlementBannerMessage({ turnsUsed: 16, maxTurns: 18, settlementTurn: 16, proofTools: ['kovo_verify'], specDirective: directive })
  assert.doesNotMatch(banner, /\b85%\b/, 'settlement banner must not hardcode stale 85% claim')
  assert.ok(banner.includes('turn 16/18'), `banner must show authoritative settlementTurn: ${banner}`)
  for (const revoked of SETTLEMENT_REVOKED_TOOLS) {
    assert.ok(banner.includes(revoked), `banner revoked list must include ${revoked}`)
  }
  const actionClause = banner.slice(banner.indexOf('Use your remaining turns ONLY to:'))
  for (const tool of extractMentionedKnownToolNames(actionClause)) {
    assert.equal(
      SETTLEMENT_ALLOWED_TOOLS.has(tool),
      true,
      `Action tool "${tool}" in settlementBannerMessage must be in SETTLEMENT_ALLOWED_TOOLS`,
    )
  }
})

// ============================================================================
// 4. Single-Source AssignmentBudget Prompt Rendering & Enforcement
// ============================================================================

test('rendered prompt budgets match AssignmentBudget thresholds exactly across all budget classes', () => {
  const cases: Array<{ label: string; budget: AssignmentBudget }> = [
    {
      label: 'single_step',
      budget: resolveAssignmentBudget(
        { title: 'Check single route', routes: ['/api/v1/items'] },
        { baseMaxTurns: 24, baseWallClockMs: 120_000 },
      ),
    },
    {
      label: 'multi_step',
      budget: resolveAssignmentBudget(
        { title: 'BOLA cross-persona check', multiStep: true, routes: ['/api/v1/orders/:id'] },
        { baseMaxTurns: 24, baseWallClockMs: 150_000 },
      ),
    },
    {
      label: 'multi_hop_chain',
      budget: resolveAssignmentBudget(
        { title: 'Clean-session chain: key -> jwt -> export', multiHopChain: true, dependsOnFactIds: ['f1', 'f2'] },
        { baseMaxTurns: 30, baseWallClockMs: 240_000, runDurationMs: 900_000 },
      ),
    },
  ]

  for (const { label, budget } of cases) {
    const prompt = workerInvestigationPrompt({
      goal: 'defensive verification',
      step: {
        id: `step-${label}`,
        title: `Verify ${label}`,
        hypothesis: 'Control vs variant check',
        category: 'broken-access-control',
        skills: ['bola-idor-race'],
        specialistProfile: 'bola-bfla-specialist',
      },
      origins: ['https://app.example.invalid'],
      capabilityTier: 2,
      maxTurns: budget.maxTurns,
      budget,
    })
    const parsed = JSON.parse(prompt) as {
      maxTurns: number
      settlementStartsAtTurn: number
      settlementNudgeAtTurn: number
      wallClockMs: number
      wallClockSettlementMs: number
      budgetClass?: string
      agenticContext: { microTaskGuidance: { turnBudget: string; settlement: string } }
    }

    assert.equal(parsed.maxTurns, budget.maxTurns, `${label}: maxTurns`)
    assert.equal(parsed.settlementStartsAtTurn, budget.settlementTurn, `${label}: settlementStartsAtTurn`)
    assert.equal(parsed.settlementNudgeAtTurn, budget.settlementTurn, `${label}: settlementNudgeAtTurn`)
    assert.equal(parsed.wallClockMs, budget.wallClockMs, `${label}: wallClockMs`)
    assert.equal(parsed.wallClockSettlementMs, budget.wallClockSettlementMs, `${label}: wallClockSettlementMs`)
    assert.doesNotMatch(parsed.agenticContext.microTaskGuidance.turnBudget, /8-10 turns/, `${label}: no stale 8-10 turns literal`)
    assert.ok(
      parsed.agenticContext.microTaskGuidance.turnBudget.includes(`${budget.maxTurns} turns`),
      `${label}: turnBudget mentions ${budget.maxTurns} turns`,
    )
    assert.ok(
      parsed.agenticContext.microTaskGuidance.turnBudget.includes(`turn ${budget.settlementTurn}`),
      `${label}: turnBudget mentions turn ${budget.settlementTurn}`,
    )
    assert.ok(
      parsed.agenticContext.microTaskGuidance.settlement.includes(`At turn ${budget.settlementTurn}`),
      `${label}: settlement guidance mentions turn ${budget.settlementTurn}`,
    )

    // Wall-clock settlement formula parity across dispatch, prompts, and worker-runner plan.
    const isMultiHop = budget.budgetClass === 'multi_hop_chain'
    assert.equal(
      resolveWorkerSettlementMs(budget.wallClockMs, isMultiHop),
      wallClockSettlementMs(budget.wallClockMs, isMultiHop),
      `${label}: single wall-clock settlement formula`,
    )
    const wallPlan = computeWorkerWallClockPlan({
      wallClockMs: budget.wallClockMs,
      explicitSettlementMs: budget.wallClockSettlementMs,
      isMultiHop,
    })
    assert.equal(wallPlan.effectiveSettlementMs, budget.wallClockSettlementMs, `${label}: wallPlan honors budget.wallClockSettlementMs`)
  }

  // No-budget planner context and codeAuditPrompt never emit hardcoded 8-10 or 0.85 drift.
  const noBudgetCtx = buildAgenticPromptContext() as { microTaskGuidance: { turnBudget: string } }
  assert.doesNotMatch(noBudgetCtx.microTaskGuidance.turnBudget, /8-10 turns/)
  const audit = JSON.parse(codeAuditPrompt({
    goal: 'audit',
    capabilityTier: 2,
    approvedOrigins: ['https://app.example.invalid'],
    mountedRepos: ['demo/app'],
    maxTurns: 18,
  })) as { maxTurns: number; settlementStartsAtTurn: number }
  assert.equal(audit.settlementStartsAtTurn, 16)
})

test('runAgentSession enforces budget.settlementTurn directly rather than recomputing floor(0.85 * maxTurns)', async t => {
  const prevLocal = process.env.KOVO_ALLOW_LOCAL_MODEL
  process.env.KOVO_ALLOW_LOCAL_MODEL = '1'
  t.after(() => {
    if (prevLocal === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
    else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocal
  })

  const dir = mkdtempSync(join(tmpdir(), 'kovo-agent-contract-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))

  const bodies: string[] = []
  let reqCount = 0
  const server = createServer((req, res) => {
    let raw = ''
    req.setEncoding('utf8')
    req.on('data', chunk => { raw += chunk })
    req.on('end', () => {
      reqCount += 1
      bodies.push(raw)
      const callId = `call_${reqCount}`
      const toolName = reqCount >= 6 ? 'complete_intent' : 'record_fact'
      const toolArgs = reqCount >= 6
        ? JSON.stringify({ status: 'ruled_out', summary: 'done' })
        : JSON.stringify({ kind: 'note', origin: 'https://app.example.invalid', summary: `turn ${reqCount}` })
      const sse = [
        `event: response.output_item.added\ndata: ${JSON.stringify({ type: 'response.output_item.added', output_index: 0, item: { type: 'function_call', id: `fc_${reqCount}`, call_id: callId, name: toolName, arguments: '' } })}\n\n`,
        `event: response.function_call_arguments.delta\ndata: ${JSON.stringify({ type: 'response.function_call_arguments.delta', output_index: 0, delta: toolArgs })}\n\n`,
        `event: response.output_item.done\ndata: ${JSON.stringify({ type: 'response.output_item.done', output_index: 0, item: { type: 'function_call', id: `fc_${reqCount}`, call_id: callId, name: toolName, arguments: toolArgs } })}\n\n`,
        `event: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', response: { id: `resp_${reqCount}`, status: 'completed', output: [{ type: 'function_call', id: `fc_${reqCount}`, call_id: callId, name: toolName, arguments: toolArgs }], usage: { input_tokens: 10, output_tokens: 5, total_tokens: 15 } } })}\n\n`,
      ].join('')
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      res.end(sse)
    })
  }).listen(0, '127.0.0.1')
  await once(server, 'listening')
  t.after(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()) }))
  const port = (server.address() as AddressInfo).port

  // Custom budget.settlementTurn = 4 on maxTurns = 10 (floor(10 * 0.85) would have been 8!).
  const customBudget: AssignmentBudget = {
    kind: 'single_step',
    budgetClass: 'single_step',
    maxTurns: 10,
    wallClockMs: 120_000,
    wallClockSettlementMs: 105_000,
    settlementTurn: 4,
  }

  const res = await runAgentSession({
    directory: dir,
    sessionId: `contract-budget-${randomUUID().slice(0, 8)}`,
    requestId: randomUUID(),
    settings: { endpoint: `http://127.0.0.1:${port}`, model: 'fixture-1', protocol: 'responses', key: 'fixture-key-1234' },
    scenario: 'worker-investigation',
    prompt: 'check budget enforcement',
    signal: AbortSignal.timeout(15_000),
    budget: customBudget,
    handlers: {
      record_fact: async () => ({ ok: true }),
      kovo_verify: async () => ({ confirmed: true, reason: 'confirmed', detail: 'ok', attempts: [] }),
      complete_intent: async () => ({ ok: true }),
    },
  })

  assert.equal(res.status, 'completed')
  // Turn 4 (index 3) receives the NUDGE; Turn 5 (index 4) receives the SETTLEMENT NOTICE at turn 4/10.
  assert.ok(bodies[3]?.includes('SETTLEMENT NUDGE'), 'turn 4 must receive SETTLEMENT NUDGE from budget.settlementTurn=4')
  assert.ok(bodies[3]?.includes('Hard settlement starts at turn 4'), 'nudge must echo budget.settlementTurn=4')
  assert.ok(bodies[4]?.includes('SETTLEMENT NOTICE'), 'turn 5 must enter settlement banner right after budget.settlementTurn=4')
  assert.ok(bodies[4]?.includes('turn 4/10'), 'banner must echo budget.settlementTurn=4/10')
})

// ============================================================================
// 5. Host-Side kovo_verify Alias-Usage Telemetry Counters
// ============================================================================

test('host-side kovo_verify alias counters track tool-arg and script/SDK aliases cleanly', async t => {
  const runId = `run-alias-test-${randomUUID().slice(0, 8)}`
  t.after(() => resetKovoVerifyAliasUsage(runId))

  // Clean canonical script triggers zero script alias hits.
  const canonicalScript = `await ctx.prove_access_boundary({ controlPersona: 'user_b', probePersona: 'user_a', route: '/api/items/1' }); return ctx.result({ title: 'BOLA' })`
  assert.deepEqual(detectKovoVerifyScriptAliases(canonicalScript), [])

  // Script using multiple aliases is accurately classified.
  const aliasedScript = [
    '```ts',
    "import { defineVerification } from './kovo_verify'",
    'export default defineVerification(async (ctx) => {',
    "  const r = await ctx.http_send({ endpoint: '/api/items/1', persona: 'user_a' })",
    "  await ctx.prove_injection_differential({ control: '/api/a', variant: '/api/b' })",
    '  await ctx.prove_composite({ hops: [], edges: [{ ablationExchange: r }] })',
    '  return ctx.result({ title: "aliased" })',
    '})',
    '```',
  ].join('\n')
  const detected = detectKovoVerifyScriptAliases(aliasedScript)
  for (const expected of [
    'script:code_fence',
    'script:bare_sdk_import',
    'script:define_verification',
    'script:export_default',
    'sdk_arg:persona',
    'sdk_arg:variant',
    'sdk_arg:edges',
    'sdk_arg:ablationExchange',
    'sdk_arg:endpoint_target',
  ] as const) {
    assert.ok(detected.includes(expected), `expected alias hit ${expected}, got ${detected.join(', ')}`)
  }

  // Counter class and run-scoped store aggregate deterministically.
  const counter = new KovoVerifyAliasCounter()
  counter.recordScript(canonicalScript)
  counter.recordScript(aliasedScript, ['tool_arg:code'])
  const localSnap = counter.snapshot()
  assert.equal(localSnap.totalCalls, 2)
  assert.equal(localSnap.byAlias['tool_arg:code'], 1)
  assert.equal(localSnap.byAlias['sdk_arg:persona'], 1)

  recordKovoVerifyAliasUsage(runId, ['tool_arg:source', 'sdk_arg:variant'])
  recordKovoVerifyAliasUsage(runId, [])
  const runSnap = getKovoVerifyAliasUsage(runId)
  assert.equal(runSnap.totalCalls, 2)
  assert.equal(runSnap.totalAliasHits, 2)
  assert.deepEqual(runSnap.byAlias, { 'sdk_arg:variant': 1, 'tool_arg:source': 1 })

  // Tool layer detects `code` and `source` aliases and surfaces them via onVerifyAliasUsed + payload.aliasUsed.
  const observedCallback: KovoVerifyAliasKey[][] = []
  const observedPayloads: Array<{ aliasUsed?: 'code' | 'source' }> = []
  const tools = buildWorkerTools(
    {
      kovo_verify: async args => {
        observedPayloads.push({ aliasUsed: args.aliasUsed })
        return { confirmed: false, reason: 'claims_missing', detail: 'none', attempts: [] }
      },
    },
    v => v,
    AbortSignal.timeout(5_000),
    16 * 1024,
    () => {},
    { onVerifyAliasUsed: aliases => observedCallback.push([...aliases]) },
  )
  const kv = tools.find(tool => tool.name === 'kovo_verify')!
  await kv.execute({ script: canonicalScript } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never)
  await kv.execute({ code: canonicalScript } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never)
  await kv.execute({ source: canonicalScript } as never, {} as never, { abortSignal: AbortSignal.timeout(5_000) } as never)

  assert.deepEqual(observedCallback, [['tool_arg:code'], ['tool_arg:source']])
  assert.deepEqual(observedPayloads, [{ aliasUsed: undefined }, { aliasUsed: 'code' }, { aliasUsed: 'source' }])
})
