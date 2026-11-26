/**
 * Systemic Stream B — Fast CI Canary Stress & Contract Gate.
 *
 * Prevents runtime ↔ prompt/skill ↔ tool-schema drift and hardcoded micro-cap regressions:
 *   1. Prompt ↔ Skill ↔ Runtime Contract Lint:
 *      - Extracts every fenced ts/typescript/js snippet mentioning `kovo_verify`, `ctx.`, or
 *        `seal_capability` from `src/server/agent-prompts.ts` and `src/skills/*.md`.
 *      - Asserts zero retired selectors (`regex` in `seal_capability`/`seal`), zero metadata-only
 *        `kovo_verify` calls missing `script`/`scriptPath`, zero v8 benchmark literals, and
 *        clean strict TypeScript typecheck against `worker/kovo_verify/kovo_verify.ts` (including
 *        normalization through `prepareVerifyScript`).
 *   2. 50× Dual-Replay Multi-Hop Budget Stress Test:
 *      - Drives 50 simulated dual-replay 4-hop chains (100 attempts × 4 seals + 100 composite
 *        verifies + 100 repeated shared `/login` endpoint seals) through `VerifyRpcServer` and
 *        `DerivedCapabilityVault` under default `RunSafetyBudgets` with zero starvation, while
 *        verifying strict finite OOM ceiling enforcement when exceeded.
 *   3. Isolated Multi-Cell Credential Preflight Smoke:
 *      - Runs `prepareIsolatedDataDir` + `acquireCredentialsDirEnv` concurrently across 3 temp
 *        cells, asserting real `0700` dirs (never symlinks), zero copied keys, and strict M-15
 *        symlink refusal.
 *   4. "Messy LLM Script" Corpus Check:
 *      - Verifies `kovo_verify` tool-schema validation rejects `{ runtime, timeoutMs, title }`
 *        without `script` with an actionable error and accepts valid `script`, while
 *        `capability.seal` rejects `{ regex }` with `SEAL_REGEX_RETIRED_ERROR` without burning
 *        budget and accepts `$.access_token`, `access_token`, `setCookie`, and `locationQuery`.
 */
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, posix, relative, resolve, sep } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

import {
  KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN,
  KOVO_VERIFY_TOOL_DESCRIPTION,
  KOVO_VERIFY_TS_ONLY_ERROR,
  kovoVerifyHelperGuidance,
  workerSessionInstructions,
  type KovoVerifyArgs,
} from '../src/server/agent-prompts.ts'
import { buildWorkerTools } from '../src/server/agent-session.ts'
import {
  MULTIHOP_HARDENED_TWIN_RULE,
  RECORD_COVERAGE_BRIEF_GUIDANCE,
  buildAssignmentBrief,
  renderSettlementSpecDirective,
} from '../src/server/assignment-brief.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  RECORD_COVERAGE_BASE_FIELDS,
  RECORD_COVERAGE_CONTRACT,
  buildRecordCoverageBriefGuidance,
  coverageStatusRank,
  type RecordCoverageFieldName,
} from '../src/server/coverage-category.ts'
import { coverageClosureStatuses } from '../src/domain.ts'
import {
  DerivedCapabilityVault,
  DerivedCustodyError,
  SEAL_REGEX_RETIRED_ERROR,
  consumeRunCompositeVerifyBudget,
  consumeRunSealBudget,
  getRunCustodyBudgetUsage,
  resetRunCustodyBudgets,
} from '../src/server/derived-custody.ts'
import {
  CREDENTIALS_DIR_ENV,
  privateModelProfiles,
  resolveCredentialsDir,
} from '../src/server/model-settings.ts'
import {
  DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN,
  DEFAULT_MAX_SEAL_ATTEMPTS,
  DEFAULT_MAX_SEALS_PER_ENDPOINT,
  DEFAULT_MAX_SEALS_PER_RUN,
  DEFAULT_MAX_VAULT_ENTRIES,
  RUN_SAFETY_BUDGET_DEFAULTS,
  RUN_SAFETY_BUDGET_ENV_KEYS,
  RUN_SAFETY_BUDGET_HARD_CEILINGS,
  resolveRunSafetyBudgets,
} from '../src/server/run-safety-budgets.ts'
import { Store } from '../src/server/store.ts'
import {
  HostMintedOracle,
  buildProofReceipt,
  verifyHostExpressionProbe,
  verifyReceipt,
} from '../src/server/proof-receipt.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import { prepareVerifyScript } from '../src/server/verify-runner.ts'
import {
  acquireCredentialsDirEnv,
  openCellStore,
  prepareIsolatedDataDir,
} from '../scripts/benchmark-realistic.ts'
import {
  V8_CONTAMINATION_RULES,
  scanSourceTreeForContamination,
  scanTextForContamination,
} from '../scripts/check-v8-contamination.ts'
import { SECURITY_GUARD_ENTRY_REGISTRY } from '../scripts/check-security-optional.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

interface RpcResp {
  ok: boolean
  result?: unknown
  error?: string
}

function rpcCall(server: VerifyRpcServer, op: string, args: Record<string, unknown> = {}): Promise<RpcResp> {
  return new Promise((resolvePromise, reject) => {
    const body = JSON.stringify({ op, args })
    const req = httpRequest({
      socketPath: server.socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        [VERIFY_RPC_HEADER]: server.token,
        [VERIFY_NONCE_HEADER]: server.nonce,
      },
    }, res => {
      let data = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { data += chunk })
      res.on('end', () => {
        try { resolvePromise(JSON.parse(data) as RpcResp) } catch (err) { reject(err) }
      })
    })
    req.on('error', reject)
    req.end(body)
  })
}

function makeGrant(origin: string, secrets: Array<{ value: string; placeholder: string }> = []): Grant {
  return {
    canRead: o => { try { return new URL(o).origin === origin } catch { return o === origin } },
    audit: () => undefined,
    allowLocalLab: true,
    maxRpsPerOrigin: 100,
    tier: 3,
    isStateChangeApproved: () => true,
    personas: new Map(),
    secrets,
  }
}

function sha256(val: string): string {
  return createHash('sha256').update(val, 'utf8').digest('hex')
}

function walkRegularFiles(root: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const full = join(root, entry.name)
    if (entry.isSymbolicLink()) continue
    if (entry.isDirectory()) out.push(...walkRegularFiles(full))
    else if (entry.isFile()) out.push(full)
  }
  return out
}

function propertyNameText(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) {
    return name.text
  }
  return null
}

function calleeTailName(expr: ts.LeftHandSideExpression): string | null {
  if (ts.isIdentifier(expr)) return expr.text
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text
  return null
}

// ---------------------------------------------------------------------------
// Check 1 — Prompt ↔ Skill ↔ Runtime Contract Lint
// ---------------------------------------------------------------------------
test('Check 1: Prompt & skill fenced snippets obey SDK contract, strict TS types, and anti-contamination', () => {
  interface ExtractedSnippet {
    source: string
    lang: string
    code: string
  }

  const promptSurfaces: Array<{ source: string; text: string }> = [
    { source: 'src/server/agent-prompts.ts#KOVO_VERIFY_TOOL_DESCRIPTION', text: KOVO_VERIFY_TOOL_DESCRIPTION },
    { source: 'src/server/agent-prompts.ts#KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN', text: KOVO_VERIFY_MULTIHOP_CRYPTO_ASYNC_PATTERN },
    { source: 'src/server/agent-prompts.ts#kovoVerifyHelperGuidance', text: kovoVerifyHelperGuidance() },
    { source: 'src/server/agent-prompts.ts#workerSessionInstructions(investigation)', text: workerSessionInstructions('worker-investigation', { hasKovoVerify: true }) },
    { source: 'src/server/agent-prompts.ts#workerSessionInstructions(code-auditor)', text: workerSessionInstructions('code-auditor', { hasKovoVerify: true }) },
  ]

  const skillsDir = join(REPO_ROOT, 'src/skills')
  const skillFiles = readdirSync(skillsDir).filter(f => f.endsWith('.md')).sort()
  const skillSurfaces = skillFiles.map(file => ({
    source: `src/skills/${file}`,
    text: readFileSync(join(skillsDir, file), 'utf8'),
  }))

  // Also inspect raw agent-prompts.ts for any template-literal fenced blocks not yet rendered above.
  const rawPromptsSrc = readFileSync(join(REPO_ROOT, 'src/server/agent-prompts.ts'), 'utf8')
  const rawSurfaces = [
    ...promptSurfaces,
    ...skillSurfaces,
    { source: 'src/server/agent-prompts.ts#raw', text: rawPromptsSrc },
  ]

  const FENCE_RE = /```(ts|typescript|js|javascript)\r?\n([\s\S]*?)```/gi
  const RELEVANT_RE = /\b(?:kovo_verify|seal_capability)\b|\bctx\./
  const seenCode = new Set<string>()
  const snippets: ExtractedSnippet[] = []

  for (const surface of rawSurfaces) {
    for (const match of surface.text.matchAll(FENCE_RE)) {
      const lang = (match[1] ?? '').toLowerCase()
      const code = match[2] ?? ''
      if (!RELEVANT_RE.test(code)) continue
      // Skip JS string-array source lines (e.g., `'```ts',` from rawPromptsSrc) since rendered prompt surfaces cover them cleanly.
      if (surface.source.endsWith('#raw') && /^\s*'/.test(code.trimStart())) continue
      const dedupeKey = code.trim()
      if (seenCode.has(dedupeKey)) continue
      seenCode.add(dedupeKey)
      snippets.push({ source: surface.source, lang, code })
    }
  }

  assert.ok(snippets.length >= 5, `Expected >= 5 relevant fenced snippets across prompts/skills, found ${snippets.length}`)

  // 1a) AST + textual checks: zero retired `regex` selectors, zero metadata-only `kovo_verify` calls, zero benchmark literals.
  const BENCHMARK_ARCHETYPE_RE = /\b(?:paygrid|shipforge|nexusiam|connecthub)\b/i
  for (const sn of snippets) {
    assert.equal(
      BENCHMARK_ARCHETYPE_RE.test(sn.code),
      false,
      `Benchmark archetype literal leaked into ${sn.source}`,
    )
    assert.deepEqual(
      scanTextForContamination(sn.source, sn.code, V8_CONTAMINATION_RULES),
      [],
      `Contamination token found in snippet from ${sn.source}`,
    )
    assert.equal(
      /\b(?:seal_capability|seal)\s*\(\s*\{[^}]*\bregex\s*:/s.test(sn.code),
      false,
      `Retired regex selector found in ${sn.source}`,
    )

    const sf = ts.createSourceFile(`${sn.source}.ts`, sn.code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
    const walk = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        const tail = calleeTailName(node.expression)
        if ((tail === 'seal_capability' || tail === 'seal') && node.arguments.length > 0) {
          const arg0 = node.arguments[0]!
          if (ts.isObjectLiteralExpression(arg0)) {
            for (const prop of arg0.properties) {
              if ((ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) && propertyNameText(prop.name) === 'regex') {
                assert.fail(`Retired \`regex\` selector in ${tail}({...}) inside ${sn.source}`)
              }
            }
          }
        }
        if (tail === 'kovo_verify' && node.arguments.length > 0) {
          const arg0 = node.arguments[0]!
          if (ts.isObjectLiteralExpression(arg0)) {
            const keys = new Set<string>()
            for (const prop of arg0.properties) {
              if (ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) {
                const key = propertyNameText(prop.name)
                if (key) keys.add(key)
              }
            }
            assert.ok(
              keys.has('script') || keys.has('scriptPath'),
              `Metadata-only kovo_verify({...}) call missing script/scriptPath in ${sn.source} (keys: ${[...keys].join(', ')})`,
            )
          }
        }
      }
      ts.forEachChild(node, walk)
    }
    walk(sf)
  }

  // 1b) Full repo anti-contamination sweep across src/server/ and src/skills/.
  const contamination = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(contamination.ok, true, `v8 contamination detected: ${JSON.stringify(contamination.hits)}`)

  // 1c) Strict TypeScript typecheck of EVERY extracted snippet against `worker/kovo_verify/kovo_verify.ts`
  //     after normalizing through `prepareVerifyScript` (exact Layer-3 runtime contract).
  const compilerOptions: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    allowImportingTsExtensions: true,
    noEmit: true,
    strict: true,
    skipLibCheck: true,
  }
  const host = ts.createCompilerHost(compilerOptions)
  const virtualFiles = new Map<string, string>()
  const origGetSourceFile = host.getSourceFile.bind(host)
  host.getSourceFile = (fileName, languageVersion) => {
    const abs = resolve(fileName)
    const content = virtualFiles.get(abs)
    if (content !== undefined) return ts.createSourceFile(fileName, content, languageVersion, true)
    return origGetSourceFile(fileName, languageVersion)
  }
  const origFileExists = host.fileExists.bind(host)
  host.fileExists = fileName => virtualFiles.has(resolve(fileName)) || origFileExists(fileName)

  const sdkDir = join(REPO_ROOT, 'worker/kovo_verify')
  const entries = snippets.map((sn, idx) => {
    const prepared = prepareVerifyScript(sn.code, 'ts', `canary-snippet-${idx}`)
    const vPath = join(sdkDir, `__canary_snippet_${idx}.ts`)
    virtualFiles.set(resolve(vPath), prepared)
    return { vPath, source: sn.source }
  })

  const program = ts.createProgram(entries.map(e => e.vPath), compilerOptions, host)
  for (const entry of entries) {
    const sf = program.getSourceFile(entry.vPath)
    assert.ok(sf, `Missing virtual source file for ${entry.source}`)
    const diags = [...program.getSyntacticDiagnostics(sf), ...program.getSemanticDiagnostics(sf)]
    assert.deepEqual(
      diags.map(d => `TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, ' ')}`),
      [],
      `TypeScript contract drift in ${entry.source}`,
    )
  }
})

// ---------------------------------------------------------------------------
// Check 2 — 50× Dual-Replay Multi-Hop Budget Stress Test + RunSafetyBudgets Policy
// ---------------------------------------------------------------------------
test('Check 2: 50x dual-replay 4-hop chains complete with zero starvation under default RunSafetyBudgets and still enforce finite caps', async t => {
  // 2a) Verify RunSafetyBudgets defaults, scaling, env parsing, and strict finite OOM ceilings.
  const defaults = resolveRunSafetyBudgets({ env: {} })
  assert.deepEqual(defaults, RUN_SAFETY_BUDGET_DEFAULTS)
  assert.equal(defaults.maxCompositeVerifiesPerRun, 1024)
  assert.equal(defaults.maxSealsPerRun, 4096)
  assert.equal(defaults.maxSealsPerEndpoint, 256)
  assert.equal(defaults.maxVaultEntries, 4096)
  assert.equal(defaults.maxSealAttempts, 8192)

  // Run scaling rises cleanly for larger assignment counts while clamping strictly at finite OOM ceilings.
  const scaled = resolveRunSafetyBudgets({ maxAssignments: 300, dualReplay: true, env: {} })
  assert.ok(scaled.maxCompositeVerifiesPerRun > defaults.maxCompositeVerifiesPerRun)
  assert.ok(scaled.maxSealsPerRun > defaults.maxSealsPerRun)
  assert.ok(scaled.maxSealsPerEndpoint > defaults.maxSealsPerEndpoint)
  assert.ok(scaled.maxCompositeVerifiesPerRun <= RUN_SAFETY_BUDGET_HARD_CEILINGS.maxCompositeVerifiesPerRun)
  assert.ok(scaled.maxSealsPerRun <= RUN_SAFETY_BUDGET_HARD_CEILINGS.maxSealsPerRun)

  const clampedEnv: Record<string, string> = {}
  for (const envKey of Object.values(RUN_SAFETY_BUDGET_ENV_KEYS)) {
    clampedEnv[envKey] = '99999999'
  }
  const clamped = resolveRunSafetyBudgets({
    maxAssignments: 1_000_000,
    dualReplay: true,
    env: clampedEnv,
  })
  assert.deepEqual(clamped, RUN_SAFETY_BUDGET_HARD_CEILINGS)

  const envConfigured = resolveRunSafetyBudgets({
    env: {
      KOVO_MAX_COMPOSITE_VERIFIES_PER_RUN: '2048',
      KOVO_MAX_SEALS_PER_RUN: '6000',
      KOVO_MAX_SEALS_PER_ENDPOINT: '512',
    },
  })
  assert.equal(envConfigured.maxCompositeVerifiesPerRun, 2048)
  assert.equal(envConfigured.maxSealsPerRun, 6000)
  assert.equal(envConfigured.maxSealsPerEndpoint, 512)

  // 2b) Live 50× dual-replay 4-hop chain stress test (100 attempts × 4 seals = 400 seals,
  //     100 repeated shared `/login` seals, 100 composite verifies).
  const runId = `run-canary-50x-${randomUUID().slice(0, 8)}`
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  let seq = 0
  const target = createServer((req, res) => {
    seq += 1
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    res.writeHead(200, { 'content-type': 'application/json' })
    if (url.pathname === '/login') {
      res.end(JSON.stringify({ token: `login_tok_${String(seq).padStart(6, '0')}_alpha` }))
      return
    }
    res.end(JSON.stringify({ token: `hop_tok_${url.pathname.replace(/\W+/g, '_')}_${String(seq).padStart(6, '0')}` }))
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => { target.closeAllConnections(); target.close(() => r()) }))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const broker = new RequestBroker({ transportConfig: { http2: false } })
  const grant = makeGrant(origin)
  const sharedVault = new DerivedCapabilityVault({
    runId,
    maxEntries: defaults.maxVaultEntries,
    maxSealAttempts: defaults.maxSealAttempts,
  })

  // Drive 50 dual-replay 4-hop chains (100 attempts) across 5 concurrent workers to stay fast (<1.5s).
  const TOTAL_CHAINS = 50
  const ATTEMPTS_PER_CHAIN = 2
  const runAttempt = async (chainIdx: number, attemptIdx: number): Promise<void> => {
    const rpc = new VerifyRpcServer({
      broker: new RequestBroker({ transportConfig: { http2: false } }),
      grant,
      runId,
      assignmentId: `chain-${chainIdx}-att-${attemptIdx}`,
      targetOrigins: [origin],
      capabilityVault: sharedVault,
    })
    await rpc.start()
    try {
      const hopPaths = ['/login', `/api/c${chainIdx}/hop2`, `/api/c${chainIdx}/hop3`, `/api/c${chainIdx}/hop4`]
      const hops: Array<Record<string, unknown>> = []
      let prevHandle: string | undefined
      for (let h = 0; h < hopPaths.length; h += 1) {
        const sendRes = await rpcCall(rpc, 'http.send', { path: hopPaths[h]!, method: h === 0 ? 'POST' : 'GET' })
        assert.equal(sendRes.ok, true, `http.send failed at c${chainIdx}/a${attemptIdx}/h${h}: ${sendRes.error ?? ''}`)
        const exId = (sendRes.result as { exchangeId: string }).exchangeId
        const hopId = `c${chainIdx}_a${attemptIdx}_h${h + 1}`
        const sealRes = await rpcCall(rpc, 'capability.seal', {
          exchangeId: exId,
          hopReceiptId: hopId,
          slot: 'tok',
          jsonPath: '$.token',
          kind: 'bearer_token',
        })
        assert.equal(sealRes.ok, true, `capability.seal starved at ${hopId}: ${sealRes.error ?? ''}`)
        const handle = (sealRes.result as { handle: string }).handle
        hops.push({
          hopId,
          surface: 'http',
          exchangeIds: [exId],
          target: { origin, method: h === 0 ? 'POST' : 'GET', pathAndQuery: hopPaths[h]! },
          producedCapabilities: [handle],
          ...(prevHandle ? { consumedCapabilities: [prevHandle] } : {}),
          claimedDelta: `Hop ${h + 1} completed`,
        })
        prevHandle = handle
      }
      const compRes = await rpcCall(rpc, 'composite.verify', {
        receipt: {
          chainId: `canary-chain-${chainIdx}-a${attemptIdx}`,
          terminalVulnClass: 'dual_tenant_abac',
          replayMode: 'fresh_clean_replay',
          hops,
          terminalImpact: {
            terminalHopId: `c${chainIdx}_a${attemptIdx}_h4`,
            claimedImpact: '4-hop stress chain verification',
          },
        },
      })
      assert.equal(compRes.ok, true, `composite.verify starved at c${chainIdx}/a${attemptIdx}: ${compRes.error ?? ''}`)
    } finally {
      await rpc.close()
    }
  }

  const tasks: Array<() => Promise<void>> = []
  for (let c = 0; c < TOTAL_CHAINS; c += 1) {
    for (let a = 0; a < ATTEMPTS_PER_CHAIN; a += 1) {
      tasks.push(() => runAttempt(c, a))
    }
  }
  const CONCURRENCY = 5
  let cursor = 0
  await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
    while (cursor < tasks.length) {
      const idx = cursor
      cursor += 1
      await tasks[idx]!()
    }
  }))

  const usage = getRunCustodyBudgetUsage(runId)
  assert.equal(usage.sealTotal, 400, 'Expected 100 attempts x 4 seals = 400 seals')
  assert.equal(usage.compositeVerifyTotal, 100, 'Expected 50 dual-replay chains = 100 composite verifies')
  const loginEndpointKey = `${origin}|/login|`
  assert.equal(usage.sealByEndpoint[loginEndpointKey], 100, 'Expected 100 shared /login endpoint seals')
  assert.equal(sharedVault.list().length, 400, 'Expected 400 sealed entries in shared vault')

  // 2c) Verify finite ceilings STILL enforce CAPACITY_EXCEEDED once exceeded!
  for (let i = 100; i < DEFAULT_MAX_SEALS_PER_ENDPOINT; i += 1) {
    consumeRunSealBudget(runId, loginEndpointKey)
  }
  assert.throws(
    () => consumeRunSealBudget(runId, loginEndpointKey),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'CAPACITY_EXCEEDED' && /max 256 per endpoint per run/.test(err.message),
  )

  for (let i = 100; i < DEFAULT_MAX_COMPOSITE_VERIFIES_PER_RUN; i += 1) {
    consumeRunCompositeVerifyBudget(runId)
  }
  assert.throws(
    () => consumeRunCompositeVerifyBudget(runId),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'CAPACITY_EXCEEDED' && /max 1024 per run/.test(err.message),
  )

  // Verify live VerifyRpcServer rejects the 1025th composite.verify with CAPACITY_EXCEEDED error.
  const overflowRpc = new VerifyRpcServer({ broker, grant, runId, assignmentId: 'overflow', targetOrigins: [origin], capabilityVault: sharedVault })
  await overflowRpc.start()
  t.after(() => overflowRpc.close())
  const overflowResp = await rpcCall(overflowRpc, 'composite.verify', {
    receipt: { chainId: 'overflow', terminalVulnClass: 'dual_tenant_abac', hops: [{ hopId: 'h1' }] },
  })
  assert.equal(overflowResp.ok, false)
  assert.match(overflowResp.error ?? '', /composite\.verify run budget exceeded \(max 1024 per run\)/)

  // Verify finite vault capacity enforcement.
  const boundedVault = new DerivedCapabilityVault({ runId: `${runId}-bounded`, maxEntries: 2, maxSealAttempts: 3 })
  boundedVault.seal({ hopReceiptId: 'h1', slot: 'a', rawValue: 'canary_secret_value_0001' })
  boundedVault.seal({ hopReceiptId: 'h2', slot: 'b', rawValue: 'canary_secret_value_0002' })
  assert.throws(
    () => boundedVault.seal({ hopReceiptId: 'h3', slot: 'c', rawValue: 'canary_secret_value_0003' }),
    (err: unknown) => err instanceof DerivedCustodyError && err.code === 'CAPACITY_EXCEEDED',
  )
})

// ---------------------------------------------------------------------------
// Check 3 — Isolated Multi-Cell Credential Preflight Smoke
// ---------------------------------------------------------------------------
test('Check 3: Isolated multi-cell credentials create real 0700 dirs, copy zero keys, and enforce M-15 symlink refusal', async t => {
  const prevEnv = process.env[CREDENTIALS_DIR_ENV]
  t.after(() => {
    if (prevEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
    else process.env[CREDENTIALS_DIR_ENV] = prevEnv
  })
  delete process.env[CREDENTIALS_DIR_ENV]

  const CANARY_KEY = 'sk-canary-never-copied-isolated-cell-key-774411'
  const hostDir = mkdtempSync(join(tmpdir(), 'kovo-canary-cred-host-'))
  const outRoot = mkdtempSync(join(tmpdir(), 'kovo-canary-cred-cells-'))
  const credDir = join(hostDir, 'credentials')
  t.after(() => {
    try { chmodSync(credDir, 0o700) } catch { /* ignore */ }
    rmSync(hostDir, { recursive: true, force: true })
    rmSync(outRoot, { recursive: true, force: true })
  })

  const store = new Store(hostDir)
  const workspaceId = store.workspace.id
  mkdirSync(credDir, { recursive: true, mode: 0o700 })
  chmodSync(credDir, 0o700)
  const credentialId = `model-${randomUUID()}`
  const credPath = join(credDir, credentialId)
  writeFileSync(credPath, CANARY_KEY, { mode: 0o600 })
  chmodSync(credPath, 0o600)

  store.db.$client.prepare(
    'insert into model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, '
    + 'enabled, context_window, max_tokens, thinking_level, role_affinity, input_cost_per_mtok, '
    + 'cached_input_cost_per_mtok, output_cost_per_mtok, health_state, cooldown_until, last_error, updated_at) '
    + 'values (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, null, null, ?)',
  ).run(
    randomUUID(), workspaceId, 'Canary Model Profile', 'https://openrouter.ai/api/v1',
    'deepseek/deepseek-v4.1-flash-1017', 'responses', credentialId, 100,
    128_000, 4_096, 'off', 'any', 0, 0, 0, 'closed', Date.now(),
  )
  store.close()

  // 3a) Concurrent preparation across 3 isolated temp cells.
  const cellDirs = ['cell-alpha', 'cell-beta', 'cell-gamma'].map(name => join(outRoot, 'cells', name))
  const prepared = await Promise.all(
    cellDirs.map(targetDir => Promise.resolve().then(() => prepareIsolatedDataDir({
      sourceDataDir: hostDir,
      targetDir,
    }))),
  )

  chmodSync(credDir, 0o500)
  const releases: Array<() => void> = []
  const openedStores: Store[] = []
  try {
    for (const iso of prepared) {
      assert.equal(iso.credentialsDir, credDir)
      const cellCreds = join(iso.directory, 'credentials')
      const st = lstatSync(cellCreds)
      assert.equal(st.isSymbolicLink(), false, 'isolated cell credentials/ must never be a symlink')
      assert.equal(st.isDirectory(), true, 'isolated cell credentials/ must be a real directory')
      assert.equal(st.mode & 0o777, 0o700, 'isolated cell credentials/ must be mode 0700')
      releases.push(acquireCredentialsDirEnv(iso.credentialsDir))
      openedStores.push(openCellStore(iso.directory))
    }

    assert.equal(process.env[CREDENTIALS_DIR_ENV], credDir)
    for (const cellStore of openedStores) {
      const profiles = privateModelProfiles(cellStore)
      assert.equal(profiles.length, 1)
      assert.equal(profiles[0]!.key, CANARY_KEY)
    }

    // Ref-counted release keeps KOVO_CREDENTIALS_DIR live until the last cell exits.
    releases[0]!()
    releases[1]!()
    assert.equal(process.env[CREDENTIALS_DIR_ENV], credDir)
    releases[2]!()
    assert.equal(process.env[CREDENTIALS_DIR_ENV], undefined)
  } finally {
    for (const rel of releases) rel()
    for (const s of openedStores) { try { s.close() } catch { /* ignore */ } }
  }

  // Zero copied key bytes anywhere under outRoot.
  const copiedKeyFiles = walkRegularFiles(outRoot).filter(f => readFileSync(f, 'utf8').includes(CANARY_KEY))
  assert.deepEqual(copiedKeyFiles, [], 'Credential key material must NEVER be copied into isolated cell directories')

  // 3b) Strict M-15 symlink refusal (both symlinked dir and symlinked file).
  chmodSync(credDir, 0o700)
  const movedDir = join(outRoot, 'moved-real-creds')
  mkdirSync(movedDir, { mode: 0o700 })
  chmodSync(movedDir, 0o700)
  writeFileSync(join(movedDir, credentialId), CANARY_KEY, { mode: 0o600 })
  rmSync(credDir, { recursive: true, force: true })
  symlinkSync(movedDir, credDir, 'dir')

  assert.throws(
    () => prepareIsolatedDataDir({ sourceDataDir: hostDir, targetDir: join(outRoot, 'reject-dir-link') }),
    /symbolic link/i,
  )

  process.env[CREDENTIALS_DIR_ENV] = `${credDir}/`
  assert.throws(() => resolveCredentialsDir(hostDir), /symbolic link/i)
  delete process.env[CREDENTIALS_DIR_ENV]

  // Restore real dir, replace credential file with a symlink -> must still refuse.
  unlinkSync(credDir)
  mkdirSync(credDir, { mode: 0o700 })
  chmodSync(credDir, 0o700)
  symlinkSync(join(movedDir, credentialId), credPath)

  assert.throws(
    () => prepareIsolatedDataDir({ sourceDataDir: hostDir, targetDir: join(outRoot, 'reject-file-link') }),
    /symbolic link/i,
  )
})

// ---------------------------------------------------------------------------
// Check 4 — "Messy LLM Script" Corpus Check
// ---------------------------------------------------------------------------
test('Check 4: Messy LLM corpus — kovo_verify rejects metadata-only calls & capability.seal rejects retired regex without burning budget', async t => {
  // 4a) Tool-schema / execute validation on `kovo_verify`.
  const receivedArgs: KovoVerifyArgs[] = []
  const controller = new AbortController()
  const tools = buildWorkerTools(
    {
      kovo_verify: async (args: KovoVerifyArgs) => {
        receivedArgs.push(args)
        return {
          confirmed: true,
          reason: 'ok',
          detail: 'confirmed',
          title: args.title ?? null,
          transcriptDigest: 'digest-ok',
          transcriptDigests: ['digest-ok'],
          failures: [],
          disagreements: [],
          attempts: [],
          rejectedBy: null,
          missingEvidence: [],
          transcriptSummary: [],
        }
      },
    },
    text => text,
    controller.signal,
    12 * 1024,
    () => undefined,
  )
  const kovoVerifyTool = tools.find(tool => tool.name === 'kovo_verify')
  assert.ok(kovoVerifyTool, 'kovo_verify tool must be registered')

  const execTool = async (args: Record<string, unknown>) => {
    const res = await kovoVerifyTool.execute(
      args as never,
      {} as never,
      { abortSignal: controller.signal } as never,
    )
    const text = (res.output ?? []).map(o => ('text' in o ? o.text : '')).join('\n')
    return { isError: Boolean(res.isError), text }
  }

  // Metadata-only calls without `script` must be rejected with actionable guidance and zero handler calls.
  const messyMeta1 = await execTool({ runtime: 'ts', timeoutMs: 30_000, title: 'Proof attempt without code' })
  assert.equal(messyMeta1.isError, true)
  assert.match(messyMeta1.text, /`script` is REQUIRED/i)
  assert.match(messyMeta1.text, /Example call:/i)

  const messyMeta2 = await execTool({ runtime: 'ts', timeoutMs: 15_000, title: 'Whitespace script', script: '   \n\t  ' })
  assert.equal(messyMeta2.isError, true)
  assert.match(messyMeta2.text, /`script` is REQUIRED/i)

  const messyMeta3 = await execTool({})
  assert.equal(messyMeta3.isError, true)
  assert.match(messyMeta3.text, /Repeated kovo_verify validation errors/i)

  // Non-TS runtime is rejected with TS-only error.
  const messyPy = await execTool({ runtime: 'py', script: 'print(1)' })
  assert.equal(messyPy.isError, true)
  assert.equal(messyPy.text, KOVO_VERIFY_TS_ONLY_ERROR)

  assert.equal(receivedArgs.length, 0, 'Malformed kovo_verify calls must never reach the runner handler')

  // Valid call with `script` succeeds cleanly.
  const validScript = 'await ctx.prove_access_boundary({ controlPersona: "user_b", probePersona: "user_a", route: "/api/v1/items/1" }); return ctx.result({ title: "BOLA" })'
  const validRes = await execTool({ script: validScript, runtime: 'ts', timeoutMs: 30_000, title: 'Valid proof' })
  assert.equal(validRes.isError, false, `Valid kovo_verify call failed: ${validRes.text}`)
  assert.equal(receivedArgs.length, 1)
  assert.equal(receivedArgs[0]!.script, validScript)
  assert.equal(receivedArgs[0]!.runtime, 'ts')

  // 4b) `capability.seal`: reject `{ regex }` with SEAL_REGEX_RETIRED_ERROR & 0 budget burned;
  //     accept `$.access_token`, `access_token`, `setCookie`, and `locationQuery`.
  const runId = `run-canary-corpus-${randomUUID().slice(0, 8)}`
  resetRunCustodyBudgets(runId)
  t.after(() => resetRunCustodyBudgets(runId))

  const ACCESS_TOK = 'corpus_access_tok_alpha_44556677'
  const COOKIE_VAL = 'corpus_cookie_sid_88990011'
  const LOC_CODE = 'corpus_redirect_code_22334455'

  const target = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (url.pathname === '/oauth/token') {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': `canary_sid=${COOKIE_VAL}; Path=/; HttpOnly; SameSite=Lax`,
      })
      res.end(JSON.stringify({ access_token: ACCESS_TOK }))
      return
    }
    if (url.pathname === '/oauth/authorize') {
      res.writeHead(302, {
        location: `https://client.example.invalid/cb?code=${LOC_CODE}&state=ok`,
      })
      res.end('')
      return
    }
    res.writeHead(404)
    res.end('not found')
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => { target.closeAllConnections(); target.close(() => r()) }))
  await once(target, 'listening')
  const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`

  const rpc = new VerifyRpcServer({
    broker: new RequestBroker({ transportConfig: { http2: false } }),
    grant: makeGrant(origin),
    runId,
    assignmentId: 'a-corpus',
    targetOrigins: [origin],
  })
  await rpc.start()
  t.after(() => rpc.close())

  const exTok = await rpcCall(rpc, 'http.send', { path: '/oauth/token', method: 'POST' })
  assert.equal(exTok.ok, true)
  const tokExId = (exTok.result as { exchangeId: string }).exchangeId

  const exAuth = await rpcCall(rpc, 'http.send', { path: '/oauth/authorize', method: 'GET', followRedirects: false })
  assert.equal(exAuth.ok, true)
  const authExId = (exAuth.result as { exchangeId: string }).exchangeId

  // Retired `regex` selector (both standalone and mixed with jsonPath) rejected with SEAL_REGEX_RETIRED_ERROR & 0 budget burned.
  for (const args of [
    { exchangeId: tokExId, hopReceiptId: 'h1', slot: 'rx_only', regex: '"access_token":"([^"]+)"' },
    { exchangeId: tokExId, hopReceiptId: 'h1', slot: 'rx_mixed', jsonPath: '$.access_token', regex: '(.+)' },
  ]) {
    const r = await rpcCall(rpc, 'capability.seal', args)
    assert.equal(r.ok, false)
    assert.equal(r.error, SEAL_REGEX_RETIRED_ERROR)
  }
  assert.equal(getRunCustodyBudgetUsage(runId).sealTotal, 0, 'Retired regex rejections must burn ZERO seal budget')

  // Structured selectors succeed cleanly and seal exact raw bytes without echoing them.
  const structuredCases = [
    { exchangeId: tokExId, slot: 'dollar_path', args: { jsonPath: '$.access_token', kind: 'bearer_token' }, expectedRaw: ACCESS_TOK },
    { exchangeId: tokExId, slot: 'bare_path', args: { jsonPath: 'access_token', kind: 'bearer_token' }, expectedRaw: ACCESS_TOK },
    { exchangeId: tokExId, slot: 'set_cookie', args: { setCookie: 'canary_sid' }, expectedRaw: COOKIE_VAL },
    { exchangeId: authExId, slot: 'loc_query', args: { locationQuery: 'code' }, expectedRaw: LOC_CODE },
  ]
  for (const c of structuredCases) {
    const r = await rpcCall(rpc, 'capability.seal', { exchangeId: c.exchangeId, hopReceiptId: 'h2', slot: c.slot, ...c.args })
    assert.equal(r.ok, true, `Structured selector ${c.slot} failed: ${r.error ?? ''}`)
    const handle = (r.result as { handle: string }).handle
    assert.equal(rpc.capabilityVault.getMeta(handle)?.sha256, sha256(c.expectedRaw))
    assert.equal(JSON.stringify(r).includes(c.expectedRaw), false)
  }
  assert.equal(getRunCustodyBudgetUsage(runId).sealTotal, 4)
})

function toPosixPath(p: string): string {
  return sep === '/' ? p : p.split(sep).join(posix.sep)
}

function resolveProductionImport(rootDir: string, fromRel: string, spec: string): string | null {
  if (!spec.startsWith('.')) return null
  const baseAbs = resolve(rootDir, dirname(fromRel), spec)
  const candidates = [
    baseAbs,
    `${baseAbs}.ts`,
    `${baseAbs}.tsx`,
    `${baseAbs}.mts`,
    join(baseAbs, 'index.ts'),
    join(baseAbs, 'index.tsx'),
  ]
  if (spec.endsWith('.js') || spec.endsWith('.jsx')) {
    const stem = baseAbs.slice(0, -3)
    candidates.unshift(`${stem}.ts`, `${stem}.tsx`)
  }
  for (const cand of candidates) {
    if (existsSync(cand) && statSync(cand).isFile()) {
      return toPosixPath(relative(rootDir, cand))
    }
  }
  return null
}

function hasExportModifier(node: ts.Node): boolean {
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined
  return Boolean(mods?.some(m => m.kind === ts.SyntaxKind.ExportKeyword))
}

interface ModuleReachabilityInfo {
  relPath: string
  declaredValueExports: Set<string>
  runtimeDeps: Set<string>
  namedImports: Array<{ localName: string; from: string; importedName: string }>
  namespaceImports: Array<{ localName: string; from: string }>
  reexports: Map<string, { from: string; importedName: string }>
  starReexports: Set<string>
  usedIdentifiers: Set<string>
  sameFileRefByExport: Map<string, Set<string>>
  dynamicImportTargets: Set<string>
}

function parseModuleReachability(rootDir: string, relPath: string): ModuleReachabilityInfo {
  const abs = join(rootDir, relPath)
  const src = readFileSync(abs, 'utf8')
  const sf = ts.createSourceFile(abs, src, ts.ScriptTarget.Latest, true)

  const info: ModuleReachabilityInfo = {
    relPath,
    declaredValueExports: new Set(),
    runtimeDeps: new Set(),
    namedImports: [],
    namespaceImports: [],
    reexports: new Map(),
    starReexports: new Set(),
    usedIdentifiers: new Set(),
    sameFileRefByExport: new Map(),
    dynamicImportTargets: new Set(),
  }

  const collectBinding = (name: ts.BindingName, out: Set<string>) => {
    if (ts.isIdentifier(name)) out.add(name.text)
    else for (const el of name.elements) if (ts.isBindingElement(el)) collectBinding(el.name, out)
  }

  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const clause = stmt.importClause
      if (clause?.isTypeOnly) continue
      const target = resolveProductionImport(rootDir, relPath, stmt.moduleSpecifier.text)
      if (!target) continue
      let hasValueImport = !clause
      if (clause?.name) {
        hasValueImport = true
        info.namedImports.push({ localName: clause.name.text, from: target, importedName: 'default' })
      }
      if (clause?.namedBindings) {
        if (ts.isNamespaceImport(clause.namedBindings)) {
          hasValueImport = true
          info.namespaceImports.push({ localName: clause.namedBindings.name.text, from: target })
        } else {
          for (const el of clause.namedBindings.elements) {
            if (el.isTypeOnly) continue
            hasValueImport = true
            info.namedImports.push({
              localName: el.name.text,
              from: target,
              importedName: (el.propertyName ?? el.name).text,
            })
          }
        }
      }
      if (hasValueImport) info.runtimeDeps.add(target)
      continue
    }

    if (ts.isExportDeclaration(stmt)) {
      if (stmt.isTypeOnly) continue
      const target = stmt.moduleSpecifier && ts.isStringLiteral(stmt.moduleSpecifier)
        ? resolveProductionImport(rootDir, relPath, stmt.moduleSpecifier.text)
        : null
      if (target) info.runtimeDeps.add(target)
      if (!stmt.exportClause && target) {
        info.starReexports.add(target)
      } else if (stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
        for (const el of stmt.exportClause.elements) {
          if (el.isTypeOnly) continue
          const exported = el.name.text
          const orig = (el.propertyName ?? el.name).text
          if (target) info.reexports.set(exported, { from: target, importedName: orig })
          else info.declaredValueExports.add(exported)
        }
      }
      continue
    }

    const stmtExports = new Set<string>()
    if (hasExportModifier(stmt)) {
      if ((ts.isFunctionDeclaration(stmt) || ts.isClassDeclaration(stmt) || ts.isEnumDeclaration(stmt)) && stmt.name) {
        stmtExports.add(stmt.name.text)
        info.declaredValueExports.add(stmt.name.text)
      } else if (ts.isVariableStatement(stmt)) {
        for (const decl of stmt.declarationList.declarations) {
          collectBinding(decl.name, stmtExports)
        }
        for (const n of stmtExports) info.declaredValueExports.add(n)
      }
    }

    const stmtIdents = new Set<string>()
    const walkExpr = (node: ts.Node) => {
      if (ts.isTypeNode(node) || ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) return
      if (
        ts.isCallExpression(node)
        && node.expression.kind === ts.SyntaxKind.ImportKeyword
        && node.arguments.length > 0
        && ts.isStringLiteral(node.arguments[0]!)
      ) {
        const dynTarget = resolveProductionImport(rootDir, relPath, node.arguments[0]!.text)
        if (dynTarget) {
          info.runtimeDeps.add(dynTarget)
          info.dynamicImportTargets.add(dynTarget)
        }
      }
      if (ts.isIdentifier(node)) {
        const parent = node.parent
        if (parent && ts.isPropertyAccessExpression(parent) && parent.name === node) {
          // Record member name for dynamic-import / namespace member references too
          info.usedIdentifiers.add(node.text)
          stmtIdents.add(node.text)
        } else {
          info.usedIdentifiers.add(node.text)
          stmtIdents.add(node.text)
        }
      }
      ts.forEachChild(node, walkExpr)
    }
    walkExpr(stmt)
    for (const exp of stmtExports) {
      info.sameFileRefByExport.set(exp, stmtIdents)
    }
  }
  return info
}

/**
 * R3-08 AST Production-Entry Reachability Walker:
 * Traces real runtime module & symbol edges from production entrypoints (`src/server.ts`,
 * `src/actions.ts`, `src/routes/**`, `scripts/serve.ts`, `scripts/benchmark-*.ts`, `worker/**`)
 * without scanning `tests/**`, returning both reachable modules and reachable `file::symbol` keys.
 */
function collectReachableProductionSymbols(rootDir: string): {
  modules: Map<string, ModuleReachabilityInfo>
  reachableModules: Set<string>
  reachableSymbols: Set<string>
} {
  const entrySeeds: string[] = []
  for (const rel of ['src/server.ts', 'src/actions.ts', 'scripts/serve.ts', 'scripts/benchmark-realistic.ts', 'scripts/benchmark-multihop.ts']) {
    if (existsSync(join(rootDir, rel))) entrySeeds.push(rel)
  }
  for (const dir of ['src/routes', 'worker']) {
    const abs = join(rootDir, dir)
    if (!existsSync(abs)) continue
    for (const full of walkRegularFiles(abs)) {
      if (full.endsWith('.ts') || full.endsWith('.tsx')) {
        const rel = toPosixPath(relative(rootDir, full))
        if (!rel.endsWith('.test.ts') && !rel.endsWith('.d.ts')) entrySeeds.push(rel)
      }
    }
  }

  const modules = new Map<string, ModuleReachabilityInfo>()
  const reachableModules = new Set<string>()
  const modQueue = [...new Set(entrySeeds)]

  while (modQueue.length > 0) {
    const rel = modQueue.shift()!
    if (reachableModules.has(rel)) continue
    if (rel.startsWith('tests/') || /\.test\.|\.spec\./i.test(rel)) continue
    if (!existsSync(join(rootDir, rel))) continue
    reachableModules.add(rel)
    const info = parseModuleReachability(rootDir, rel)
    modules.set(rel, info)
    for (const dep of info.runtimeDeps) {
      if (!reachableModules.has(dep)) modQueue.push(dep)
    }
  }

  const reachableSymbols = new Set<string>()
  const symQueue: Array<{ file: string; symbol: string }> = []
  const markSymbol = (file: string, symbol: string) => {
    const key = `${file}::${symbol}`
    if (reachableSymbols.has(key)) return
    reachableSymbols.add(key)
    symQueue.push({ file, symbol })
  }

  for (const info of modules.values()) {
    for (const imp of info.namedImports) {
      if (info.usedIdentifiers.has(imp.localName)) {
        markSymbol(imp.from, imp.importedName)
      }
    }
    for (const ns of info.namespaceImports) {
      const target = modules.get(ns.from)
      if (!target) continue
      for (const exp of target.declaredValueExports) {
        if (info.usedIdentifiers.has(exp) || info.usedIdentifiers.has(ns.localName)) {
          markSymbol(ns.from, exp)
        }
      }
    }
    for (const dynTarget of info.dynamicImportTargets) {
      const target = modules.get(dynTarget)
      if (!target) continue
      for (const exp of target.declaredValueExports) {
        if (info.usedIdentifiers.has(exp)) markSymbol(dynTarget, exp)
      }
    }
  }

  // Propagate through re-exports and same-file call edges from already-reachable exports.
  while (symQueue.length > 0) {
    const { file, symbol } = symQueue.shift()!
    const info = modules.get(file)
    if (!info) continue
    const reexp = info.reexports.get(symbol)
    if (reexp) markSymbol(reexp.from, reexp.importedName)
    if (!info.declaredValueExports.has(symbol) && !reexp) {
      for (const starTarget of info.starReexports) markSymbol(starTarget, symbol)
    }
    const sameFileRefs = info.sameFileRefByExport.get(symbol)
    if (sameFileRefs) {
      for (const ref of sameFileRefs) {
        if (info.declaredValueExports.has(ref)) markSymbol(file, ref)
      }
    }
  }

  return { modules, reachableModules, reachableSymbols }
}

function collectAstCallsAndProps(node: ts.Node, sf: ts.SourceFile): {
  callees: Set<string>
  qualifiedCalls: Set<string>
  propAccesses: Set<string>
  qualifiedProps: Set<string>
} {
  const callees = new Set<string>()
  const qualifiedCalls = new Set<string>()
  const propAccesses = new Set<string>()
  const qualifiedProps = new Set<string>()
  const walk = (n: ts.Node) => {
    if (ts.isCallExpression(n)) {
      const tail = calleeTailName(n.expression)
      if (tail) callees.add(tail)
      if (ts.isPropertyAccessExpression(n.expression)) {
        qualifiedCalls.add(`${n.expression.expression.getText(sf)}.${n.expression.name.text}`)
      }
    }
    if (ts.isPropertyAccessExpression(n)) {
      propAccesses.add(n.name.text)
      qualifiedProps.add(`${n.expression.getText(sf)}.${n.name.text}`)
    }
    ts.forEachChild(n, walk)
  }
  walk(node)
  return { callees, qualifiedCalls, propAccesses, qualifiedProps }
}

// ---------------------------------------------------------------------------
// Check 5 — R4-H-3 / R3-08 Security-Primitive Production Reachability Guard
// ---------------------------------------------------------------------------
test('Check 5: R4-H-3 / R3-08 — security primitives are never unwired and are AST-reachable from production entrypoints', () => {
  const baselinePath = join(REPO_ROOT, 'scripts/unwired-baseline.json')
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8')) as {
    baselinedExports?: string[]
    keepUnwired?: Array<{ key: string }>
    ticketedAdditions?: Array<{ key: string }>
  }

  const allUnwiredKeys = [
    ...(baseline.baselinedExports ?? []),
    ...(baseline.keepUnwired ?? []).map(entry => entry.key),
    ...(baseline.ticketedAdditions ?? []).map(entry => entry.key),
  ]

  // 5a) Structural guard ensuring scripts/unwired-baseline.json never baselines security primitives.
  const FORBIDDEN_SECURITY_GUARD_PATTERNS: Array<{ label: string; re: RegExp }> = [
    { label: 'auth-refresher guard', re: /(?:SessionRefresher|refreshBrowserSession|BrowserSessionProxyOrigin|BrowserSessionEgressPolicy)/i },
    { label: 'provenance needle-builder guard', re: /(?:SecretNeedle|PersonaSecretNeedles|ScrubbableCookie|OriginsWithinProjectScope)/i },
    { label: 'provider inbound/outbound scrubber guard', re: /(?:sanitizeProvider(?:Stream|Value)|InboundProviderFrame|OutboundProviderRequest)/i },
    { label: 'approval-lease predicate guard', re: /(?:leaseAuthorizes|LeaseEligibility|HighRiskOrExternalMutation|ApprovalLease|authorizeStateChange)/i },
    { label: 'host-minted oracle / proof-kernel guard', re: /(?:HostMinted|HostExpression|HostBooleanPair|HostTimingChallenge|HostRedirectCanary|StampedBooleanPair|SignedUrlMint(?:Pair|Differential)|WorkerVisibleBodyDigest|normalizeRequestCarrier)/i },
    { label: 'composite binding / tenant provenance guard', re: /(?:BoundTerminalControl|ExchangeTenantPrivilege|CitedReceiptExchanges|OracleInputProvenance)/i },
    { label: 'worker sandbox / bounded checkout / OOB quota guard', re: /(?:InWorker$|materializeGitTreeBounded|Oob(?:Callback|Token)Quota)/i },
  ]

  // 5b) Authoritative security-guard live reachability set (merges R3-08 registry + R4 security primitives).
  const REQUIRED_PRODUCTION_REACHABLE: Array<{ file: string; symbol: string }> = [
    ...SECURITY_GUARD_ENTRY_REGISTRY.map(spec => ({ file: spec.file, symbol: spec.symbol })),
    { file: 'src/server/browser-session-auth.ts', symbol: 'evaluateBrowserSessionProxyOrigin' },
    { file: 'src/server/browser-session-auth.ts', symbol: 'resolveBrowserSessionEgressPolicy' },
    { file: 'src/server/approval-pattern.ts', symbol: 'isHighRiskOrExternalMutationPath' },
    { file: 'src/server/provider-stream.ts', symbol: 'scrubOutboundProviderRequest' },
    { file: 'src/server/provider-stream.ts', symbol: 'sanitizeProviderValue' },
    { file: 'src/server/provider-stream.ts', symbol: 'verifyInboundProviderFrameIntegrity' },
    { file: 'src/server/composite-autodag.ts', symbol: 'matchesBoundTerminalControl' },
    { file: 'src/server/causal-proof-compiler.ts', symbol: 'evaluateExchangeTenantPrivilege' },
    { file: 'src/server/causal-proof-compiler.ts', symbol: 'collectCitedReceiptExchanges' },
    { file: 'src/server/untrusted-compute-pool.ts', symbol: 'synthesizeInvariantsInWorker' },
    { file: 'src/server/untrusted-compute-pool.ts', symbol: 'searchRepoInWorker' },
    { file: 'src/server/proof-receipt.ts', symbol: 'verifyHostExpressionProbe' },
    { file: 'src/server/verify-support.ts', symbol: 'computeWorkerVisibleBodyDigest' },
    { file: 'src/server/verify-support.ts', symbol: 'assessSignedUrlMintDifferential' },
  ]
  const requiredSymbolNames = new Set(REQUIRED_PRODUCTION_REACHABLE.map(r => r.symbol))

  const violations: string[] = []
  for (const key of allUnwiredKeys) {
    const symbol = key.includes('::') ? key.slice(key.indexOf('::') + 2) : key
    if (requiredSymbolNames.has(symbol)) {
      violations.push(`Forbidden security primitive listed as unwired: ${key}`)
      continue
    }
    for (const pat of FORBIDDEN_SECURITY_GUARD_PATTERNS) {
      if (pat.re.test(symbol)) {
        violations.push(`Security-fix symbol (${pat.label}) listed as unwired: ${key}`)
      }
    }
  }
  assert.deepEqual(violations, [], `R4-H-3 / R3-08 unwired-security-primitive violations:\n${violations.join('\n')}`)

  // 5c) Real AST production-entry reachability check (replaces regex export scan):
  //     every registry security symbol must be AST-exported AND reachable via import/call edges
  //     from a production entrypoint (`src/server.ts`, `src/actions.ts`, `src/routes/**`, `scripts/serve.ts`, etc.).
  const graph = collectReachableProductionSymbols(REPO_ROOT)
  const unreachable: string[] = []
  const seenReq = new Set<string>()
  for (const { file, symbol } of REQUIRED_PRODUCTION_REACHABLE) {
    const key = `${file}::${symbol}`
    if (seenReq.has(key)) continue
    seenReq.add(key)
    const mod = graph.modules.get(file)
    if (!mod || !graph.reachableModules.has(file)) {
      unreachable.push(`${key} (module "${file}" not reachable from any production entrypoint)`)
      continue
    }
    if (!mod.declaredValueExports.has(symbol) && !mod.reexports.has(symbol)) {
      unreachable.push(`${key} (symbol "${symbol}" is not exported as a value from "${file}")`)
      continue
    }
    if (!graph.reachableSymbols.has(key)) {
      unreachable.push(`${key} (exported from "${file}" but no production import/call edge reaches it)`)
    }
  }
  assert.deepEqual(
    unreachable,
    [],
    `R3-08 production-entry reachability failures:\n${unreachable.join('\n')}`,
  )

  // 5d) AST call lock-in: verify-rpc.ts must call buildPersonaSecretNeedles and must not call duplicate personaSecrets.
  const verifyRpcPath = join(REPO_ROOT, 'src/server/verify-rpc.ts')
  const verifyRpcSf = ts.createSourceFile(verifyRpcPath, readFileSync(verifyRpcPath, 'utf8'), ts.ScriptTarget.Latest, true)
  const verifyRpcAst = collectAstCallsAndProps(verifyRpcSf, verifyRpcSf)
  assert.ok(verifyRpcAst.callees.has('buildPersonaSecretNeedles'), 'src/server/verify-rpc.ts must call buildPersonaSecretNeedles')
  assert.equal(verifyRpcAst.callees.has('personaSecrets'), false, 'src/server/verify-rpc.ts must not duplicate personaSecrets alongside buildPersonaSecretNeedles')
})

// ---------------------------------------------------------------------------
// Check 6 — R4-C-1 & R4-C-2 Host-Minted Per-Exchange Stamp Guard (AST-verified, zero fixed windows)
// ---------------------------------------------------------------------------
test('Check 6: R4-C-1 & R4-C-2 — every host-minted oracle enforces per-exchange host stamps and prove.injection never leaks expectedOutput/operands', () => {
  const proofReceiptPath = join(REPO_ROOT, 'src/server/proof-receipt.ts')
  const verifyClaimsPath = join(REPO_ROOT, 'src/server/verify-claims.ts')
  const proveHandlersPath = join(REPO_ROOT, 'src/server/verify-prove-handlers.ts')
  const oracleInvariantsPath = join(REPO_ROOT, 'src/server/oracle-invariants.ts')

  const proofReceiptSf = ts.createSourceFile(proofReceiptPath, readFileSync(proofReceiptPath, 'utf8'), ts.ScriptTarget.Latest, true)
  const verifyClaimsSf = ts.createSourceFile(verifyClaimsPath, readFileSync(verifyClaimsPath, 'utf8'), ts.ScriptTarget.Latest, true)
  const proveSf = ts.createSourceFile(proveHandlersPath, readFileSync(proveHandlersPath, 'utf8'), ts.ScriptTarget.Latest, true)
  const oracleInvariantsSf = ts.createSourceFile(oracleInvariantsPath, readFileSync(oracleInvariantsPath, 'utf8'), ts.ScriptTarget.Latest, true)

  // 6a) AST inspection: ReceiptTranscriptEntry interface declares every per-exchange host stamp field.
  let entryInterface: ts.InterfaceDeclaration | undefined
  let verifyEvalExprFn: ts.FunctionDeclaration | undefined
  const ruleIfBranches = new Map<string, ts.Statement>()
  const walkProofReceipt = (node: ts.Node) => {
    if (ts.isInterfaceDeclaration(node) && node.name.text === 'ReceiptTranscriptEntry') {
      entryInterface = node
    } else if (ts.isFunctionDeclaration(node) && node.name?.text === 'verifyEvaluatedExpression') {
      verifyEvalExprFn = node
    } else if (
      ts.isIfStatement(node)
      && ts.isBinaryExpression(node.expression)
      && node.expression.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
      && ts.isIdentifier(node.expression.left)
      && node.expression.left.text === 'rule'
      && ts.isStringLiteral(node.expression.right)
    ) {
      ruleIfBranches.set(node.expression.right.text, node.thenStatement)
    }
    ts.forEachChild(node, walkProofReceipt)
  }
  walkProofReceipt(proofReceiptSf)

  assert.ok(entryInterface, 'ReceiptTranscriptEntry interface must exist in proof-receipt.ts')
  const entryProps = new Map<string, string>()
  for (const member of entryInterface.members) {
    if (ts.isPropertySignature(member)) {
      const key = propertyNameText(member.name)
      if (key && member.type) entryProps.set(key, member.type.getText(proofReceiptSf).trim())
    }
  }
  assert.equal(entryProps.get('hostBooleanPair'), 'HostStampedBooleanPair')
  assert.equal(entryProps.get('hostExpressionChallenge'), 'HostMintedExpressionChallenge')
  assert.equal(entryProps.get('hostTimingChallenge'), 'HostMintedTimingChallenge')
  assert.equal(entryProps.get('hostRedirectCanaryHost'), 'string | null')

  // 6b) Full-AST branch inspection across all 5 host-minted oracle families (NO fixed char windows!):
  for (const requiredRule of ['oob', 'boolean', 'status_differential', 'timing', 'redirect']) {
    assert.ok(ruleIfBranches.has(requiredRule), `proof-receipt.ts must have an explicit AST branch for rule === '${requiredRule}'`)
  }
  const oobAst = collectAstCallsAndProps(ruleIfBranches.get('oob')!, proofReceiptSf)
  const booleanAst = collectAstCallsAndProps(ruleIfBranches.get('boolean')!, proofReceiptSf)
  const statusAst = collectAstCallsAndProps(ruleIfBranches.get('status_differential')!, proofReceiptSf)
  const timingAst = collectAstCallsAndProps(ruleIfBranches.get('timing')!, proofReceiptSf)
  const redirectAst = collectAstCallsAndProps(ruleIfBranches.get('redirect')!, proofReceiptSf)
  const oracleInvAst = collectAstCallsAndProps(oracleInvariantsSf, oracleInvariantsSf)

  //     (1) boolean & status_differential -> verifyStampedBooleanPairRound + canonicalPredicateSkeleton
  assert.ok(booleanAst.callees.has('verifyStampedBooleanPairRound'), 'boolean rule AST branch must call verifyStampedBooleanPairRound')
  assert.ok(statusAst.callees.has('verifyStampedBooleanPairRound'), 'status_differential rule AST branch must call verifyStampedBooleanPairRound')
  assert.ok(oracleInvAst.callees.has('canonicalPredicateSkeleton'), 'oracle-invariants.ts must call canonicalPredicateSkeleton')

  //     (2) evaluated-expression -> full AST of verifyEvaluatedExpression + evaluateClaim case 'host_evaluated_expression'
  assert.ok(verifyEvalExprFn, 'verifyEvaluatedExpression function declaration must exist in proof-receipt.ts')
  const evalExprAst = collectAstCallsAndProps(verifyEvalExprFn, proofReceiptSf)
  assert.ok(evalExprAst.qualifiedProps.has('probe.hostExpressionChallenge'), 'verifyEvaluatedExpression must require per-exchange probe.hostExpressionChallenge')
  assert.equal(evalExprAst.qualifiedProps.has('transcript.hostExpressionChallenges'), false, 'verifyEvaluatedExpression must NEVER fall back to transcript.hostExpressionChallenges')
  assert.ok(evalExprAst.callees.has('verifyHostExpressionProbe'), 'verifyEvaluatedExpression must delegate to verifyHostExpressionProbe')

  let evaluateClaimFn: ts.FunctionDeclaration | undefined
  let hostEvalExprCase: ts.CaseClause | undefined
  const walkVerifyClaims = (node: ts.Node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'evaluateClaim') {
      evaluateClaimFn = node
      const walkClaimBody = (inner: ts.Node) => {
        if (ts.isCaseClause(inner) && ts.isStringLiteral(inner.expression) && inner.expression.text === 'host_evaluated_expression') {
          hostEvalExprCase = inner
        }
        ts.forEachChild(inner, walkClaimBody)
      }
      walkClaimBody(node)
    }
    ts.forEachChild(node, walkVerifyClaims)
  }
  walkVerifyClaims(verifyClaimsSf)
  assert.ok(evaluateClaimFn, 'verify-claims.ts must export evaluateClaim')
  assert.ok(hostEvalExprCase, 'evaluateClaim in verify-claims.ts must handle case "host_evaluated_expression"')
  const claimsExprAst = collectAstCallsAndProps(hostEvalExprCase, verifyClaimsSf)
  assert.ok(claimsExprAst.callees.has('verifyHostExpressionProbe'), 'verify-claims.ts must delegate host_evaluated_expression to verifyHostExpressionProbe')
  assert.ok(claimsExprAst.propAccesses.has('hostExpressionChallenge'), 'verify-claims.ts must forward per-exchange hostExpressionChallenge stamp')

  //     (3) timing -> oracle.verifyTimingChallenge + delayToken/controlToken binding
  assert.ok(timingAst.qualifiedCalls.has('oracle.verifyTimingChallenge'), 'timing rule AST branch must call oracle.verifyTimingChallenge')
  assert.ok(timingAst.propAccesses.has('delayToken'), 'timing rule AST branch must bind host-minted delayToken')
  assert.ok(timingAst.propAccesses.has('controlToken'), 'timing rule AST branch must bind host-minted controlToken')

  //     (4) redirect -> oracle.isMintedRedirectHost + hostRedirectCanaryHost
  assert.ok(redirectAst.propAccesses.has('hostRedirectCanaryHost'), 'redirect rule AST branch must inspect hostRedirectCanaryHost')
  assert.ok(redirectAst.qualifiedCalls.has('oracle.isMintedRedirectHost'), 'redirect rule AST branch must call oracle.isMintedRedirectHost')

  //     (5) OOB -> host callback signature verification + unique request-side carrier token
  assert.ok(oobAst.callees.has('verifyOobCallbackSignature'), 'oob rule AST branch must call verifyOobCallbackSignature')
  assert.ok(oobAst.callees.has('entryCarriesTokenInRequest'), 'oob rule AST branch must call entryCarriesTokenInRequest')

  // 6c) AST inspection of verify-prove-handlers.ts: stamps per-exchange hostBooleanPair & hostExpressionChallenge,
  //     and handleProveInjection NEVER returns expectedOutput or operands to workers.
  let hasBaselineBooleanStamp = false
  let expressionExchangeStamps = 0
  const walkProveStamps = (node: ts.Node) => {
    if (ts.isCallExpression(node)) {
      const tail = calleeTailName(node.expression)
      if (tail === 'stampBooleanPairArm' && node.arguments.length >= 2) {
        const arg1 = node.arguments[1]!
        if (ts.isStringLiteral(arg1) && arg1.text === 'baseline') hasBaselineBooleanStamp = true
      }
      if (tail === 'runHttpExchange' && node.arguments.length >= 3) {
        const arg2 = node.arguments[2]!
        if (ts.isObjectLiteralExpression(arg2)) {
          for (const p of arg2.properties) {
            if ((ts.isPropertyAssignment(p) || ts.isShorthandPropertyAssignment(p)) && propertyNameText(p.name) === 'hostExpressionChallenge') {
              expressionExchangeStamps += 1
            }
          }
        }
      }
    }
    ts.forEachChild(node, walkProveStamps)
  }
  walkProveStamps(proveSf)
  assert.equal(hasBaselineBooleanStamp, true, 'verify-prove-handlers.ts must stamp baseline boolean pair arm via stampBooleanPairArm(..., "baseline")')
  assert.ok(expressionExchangeStamps >= 2, `verify-prove-handlers.ts must stamp >= 2 hostExpressionChallenge exchanges via runHttpExchange, found ${expressionExchangeStamps}`)

  const SECRET_CHALLENGE_PROPS = new Set(['expectedOutput', 'expected_output', 'operandA', 'operandB', 'expressionSyntax'])
  let foundHandleProveInjection = false
  let foundPublicChallenges = false
  const inspectProveAst = (node: ts.Node): void => {
    if (ts.isFunctionDeclaration(node) && node.name?.text === 'handleProveInjection') {
      foundHandleProveInjection = true
      const walkFn = (inner: ts.Node): void => {
        // Inspect publicChallenges array literals
        if (ts.isVariableDeclaration(inner) && ts.isIdentifier(inner.name) && inner.name.text === 'publicChallenges' && inner.initializer) {
          foundPublicChallenges = true
          const checkObj = (sub: ts.Node): void => {
            if (ts.isPropertyAssignment(sub) || ts.isShorthandPropertyAssignment(sub)) {
              const propName = propertyNameText(sub.name)
              if (propName && SECRET_CHALLENGE_PROPS.has(propName)) {
                assert.fail(`handleProveInjection publicChallenges must NEVER expose "${propName}" to workers`)
              }
            }
            if (ts.isSpreadAssignment(sub)) {
              assert.fail('handleProveInjection publicChallenges must NOT spread raw challenge objects to workers')
            }
            ts.forEachChild(sub, checkObj)
          }
          checkObj(inner.initializer)
        }
        // Inspect every host.scrubRecord({...}) return object in handleProveInjection
        if (
          ts.isCallExpression(inner) &&
          calleeTailName(inner.expression) === 'scrubRecord' &&
          inner.arguments.length > 0 &&
          ts.isObjectLiteralExpression(inner.arguments[0]!)
        ) {
          for (const prop of inner.arguments[0]!.properties) {
            if (ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop)) {
              const propName = propertyNameText(prop.name)
              if (propName && SECRET_CHALLENGE_PROPS.has(propName)) {
                assert.fail(`handleProveInjection return payload must NEVER expose "${propName}" to workers`)
              }
              if (propName === 'hostMintedChallenges' && ts.isPropertyAssignment(prop) && ts.isArrayLiteralExpression(prop.initializer)) {
                for (const elem of prop.initializer.elements) {
                  if (ts.isIdentifier(elem) && (elem.text === 'ch1' || elem.text === 'ch2')) {
                    assert.fail('handleProveInjection must NOT return raw ch1/ch2 objects in hostMintedChallenges')
                  }
                }
              }
            }
          }
        }
        ts.forEachChild(inner, walkFn)
      }
      walkFn(node)
    }
    ts.forEachChild(node, inspectProveAst)
  }
  inspectProveAst(proveSf)
  assert.equal(foundHandleProveInjection, true, 'handleProveInjection function must exist in verify-prove-handlers.ts')
  assert.equal(foundPublicChallenges, true, 'handleProveInjection must construct sanitized publicChallenges')

  // 6d) Fast runtime fail-closed checks on the verification kernel across all 5 host-minted oracle families.
  const oracle = new HostMintedOracle()
  const origin = 'https://canary-stamp-guard.example.invalid'
  const exprCh = oracle.mintExpressionChallenge('ssti')
  const noStampExpr = verifyHostExpressionProbe({
    probeRequest: { pathAndQuery: `/render?q=${encodeURIComponent(exprCh.expressionSyntax)}` },
    probeBody: `result=${exprCh.expectedOutput}`,
    probeStatus: 200,
    controlBodies: ['result=benign'],
    stampedChallenge: undefined,
    expectedChallengeId: exprCh.challengeId,
    vulnClass: 'ssti',
    oracle,
  })
  assert.equal(noStampExpr.ok, false, 'verifyHostExpressionProbe must reject missing per-exchange stamp')

  // Transcript-only expression challenge (missing per-exchange probe.hostExpressionChallenge) must fail closed.
  const sstiReceipt = buildProofReceipt({
    vulnClass: 'ssti',
    target: { origin, method: 'GET', pathAndQuery: '/render?q=benign', param: 'q' },
    exchangeIds: ['c1', 'p1'],
    claimedDelta: 'Unstamped probe citing transcript expression challenge must reject.',
  })
  const transcriptOnlyExpr = verifyReceipt(sstiReceipt, {
    hostExpressionChallenges: [exprCh],
    entries: [
      {
        exchangeId: 'c1',
        origin,
        step: {
          id: 'c1', arm: 'control', method: 'GET', route: '/render', pathAndQuery: '/render?q=benign',
          status: 200, body: 'result=benign', actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
        },
      },
      {
        exchangeId: 'p1',
        origin,
        step: {
          id: 'p1', arm: 'probe', method: 'GET', route: '/render',
          pathAndQuery: `/render?q=${encodeURIComponent(exprCh.expressionSyntax)}`,
          status: 200, body: `result=${exprCh.expectedOutput}`, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
        },
      },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(transcriptOnlyExpr.confirmed, false, 'ssti receipt without per-exchange hostExpressionChallenge must fail closed')

  // Unstamped boolean differential triangle (missing hostBooleanPair) must fail closed.
  const boolReceipt = buildProofReceipt({
    vulnClass: 'boolean_differential',
    target: { origin, method: 'GET', pathAndQuery: '/items?id=1', param: 'id' },
    exchangeIds: ['bc1', 'bp1', 'bc2', 'bp2'],
    claimedDelta: 'Unstamped boolean differential must reject.',
  })
  const unstampedBool = verifyReceipt(boolReceipt, {
    entries: [
      { exchangeId: 'bc1', origin, step: { id: 'bc1', arm: 'control', method: 'GET', route: '/items', pathAndQuery: '/items?id=1+AND+121%3D121', status: 200, json: { ok: 1 }, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null } } },
      { exchangeId: 'bp1', origin, step: { id: 'bp1', arm: 'probe', method: 'GET', route: '/items', pathAndQuery: '/items?id=1+AND+121%3D211', status: 200, json: { ok: 0 }, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null } } },
      { exchangeId: 'bc2', origin, step: { id: 'bc2', arm: 'control', method: 'GET', route: '/items', pathAndQuery: '/items?id=1+AND+121%3D121', status: 200, json: { ok: 1 }, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null } } },
      { exchangeId: 'bp2', origin, step: { id: 'bp2', arm: 'probe', method: 'GET', route: '/items', pathAndQuery: '/items?id=1+AND+121%3D211', status: 200, json: { ok: 0 }, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null } } },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(unstampedBool.confirmed, false, 'boolean_differential without hostBooleanPair stamp must fail closed')

  // Unstamped timing differential (missing hostTimingChallenge) must fail closed.
  const timingIds: string[] = []
  const timingEntries = []
  for (let i = 0; i < 5; i += 1) {
    const cid = `tc${i}`
    const pid = `tp${i}`
    timingIds.push(cid, pid)
    timingEntries.push(
      { exchangeId: cid, origin, seq: i * 2 + 1, durationMs: 25, step: { id: cid, arm: 'control' as const, method: 'GET', route: '/slow', pathAndQuery: '/slow?q=SLEEP(0)', status: 200, durationMs: 25, body: '{}', actor: { handle: null, role: null, tenant: null, auth: 'unknown' as const, sameSite: null } } },
      { exchangeId: pid, origin, seq: i * 2 + 2, durationMs: 2_500, step: { id: pid, arm: 'probe' as const, method: 'GET', route: '/slow', pathAndQuery: '/slow?q=SLEEP(2)', status: 200, durationMs: 2_500, body: '{}', actor: { handle: null, role: null, tenant: null, auth: 'unknown' as const, sameSite: null } } },
    )
  }
  const timingReceipt = buildProofReceipt({
    vulnClass: 'sqli_time',
    target: { origin, method: 'GET', pathAndQuery: '/slow?q=SLEEP(0)', param: 'q' },
    exchangeIds: timingIds,
    claimedDelta: 'Unstamped timing differential must reject.',
  })
  const unstampedTiming = verifyReceipt(timingReceipt, { entries: timingEntries }, { hostMintedOracle: oracle })
  assert.equal(unstampedTiming.confirmed, false, 'timing receipt without hostTimingChallenge must fail closed')

  // Unminted redirect destination host must fail closed.
  const redirReceipt = buildProofReceipt({
    vulnClass: 'open_redirect',
    target: { origin, method: 'GET', pathAndQuery: '/go?next=/home', param: 'next' },
    exchangeIds: ['rc1', 'rp1'],
    claimedDelta: 'Unminted redirect host must reject.',
  })
  const unmintedRedir = verifyReceipt(redirReceipt, {
    entries: [
      {
        exchangeId: 'rc1',
        origin,
        step: {
          id: 'rc1', arm: 'control', method: 'GET', route: '/go', pathAndQuery: '/go?next=%2Fhome',
          status: 302, responseHeaders: { location: '/home' }, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
        },
      },
      {
        exchangeId: 'rp1',
        origin,
        step: {
          id: 'rp1', arm: 'probe', method: 'GET', route: '/go', pathAndQuery: '/go?next=https%3A%2F%2Fevil.example.invalid%2Fx',
          status: 302, responseHeaders: { location: 'https://evil.example.invalid/x' }, actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
        },
      },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(unmintedRedir.confirmed, false, 'open_redirect with unminted destination host must fail closed')

  // OOB receipt with response-only token (not in request carrier) must fail closed.
  const oobReceipt = buildProofReceipt({
    vulnClass: 'ssrf',
    target: { origin, method: 'POST', pathAndQuery: '/fetch' },
    exchangeIds: ['ox1'],
    oobEventIds: ['ev1'],
    claimedDelta: 'Response-only OOB token must reject.',
  })
  const responseOnlyOob = verifyReceipt(oobReceipt, {
    entries: [
      {
        exchangeId: 'ox1',
        origin,
        startedAt: 1_000,
        step: {
          id: 'ox1', arm: 'probe', method: 'POST', route: '/fetch', pathAndQuery: '/fetch',
          status: 200, requestBody: '{"url":"https://benign.example"}', body: '{"echo":"canary_tok_9988"}',
          actor: { handle: null, role: null, tenant: null, auth: 'unknown', sameSite: null },
        },
      },
    ],
    oobEvents: [
      { id: 'ev1', token: 'canary_tok_9988', targetOrigin: origin, delivered: true, receivedAtMs: 2_000 },
    ],
  }, { hostMintedOracle: oracle })
  assert.equal(responseOnlyOob.confirmed, false, 'OOB receipt with response-only token must fail closed')
})

// ---------------------------------------------------------------------------
// Check 7 — R3-15 Single Authoritative RecordCoverageContract Parity Lock-In
// ---------------------------------------------------------------------------
test('Check 7: R3-15 — record_coverage tool schema, store-findings validation, and worker brief share ONE RECORD_COVERAGE_CONTRACT across all 5 statuses', () => {
  const tools = buildWorkerTools(
    { record_coverage: async () => ({ ok: true }) },
    v => v,
    AbortSignal.timeout(5_000),
    16_384,
    () => {},
  )
  const recordCoverageTool = tools.find(t => t.name === 'record_coverage')
  assert.ok(recordCoverageTool, 'record_coverage tool must be registered by buildWorkerTools')

  // 7a) JSON schema base required fields and status enum match RECORD_COVERAGE_CONTRACT verbatim.
  const schema = recordCoverageTool.parameters as {
    required?: string[]
    properties?: Record<string, { enum?: string[]; description?: string }>
  }
  assert.deepEqual(
    [...(schema.required ?? [])].sort(),
    [...RECORD_COVERAGE_BASE_FIELDS].sort(),
    'record_coverage JSON schema required base fields must match RECORD_COVERAGE_BASE_FIELDS',
  )
  const schemaStatuses = [...(schema.properties?.status?.enum ?? [])].sort()
  const contractStatuses = [...Object.keys(RECORD_COVERAGE_CONTRACT)].sort()
  assert.deepEqual(schemaStatuses, [...coverageClosureStatuses].sort(), 'tool status enum must cover all CoverageClosureStatus values')
  assert.deepEqual(schemaStatuses, contractStatuses, 'tool status enum must match RECORD_COVERAGE_CONTRACT keys')

  // 7b) Tool description & parameter descriptions match RECORD_COVERAGE_CONTRACT for every status.
  for (const status of coverageClosureStatuses) {
    const rule = RECORD_COVERAGE_CONTRACT[status]
    assert.ok(
      recordCoverageTool.description.includes(rule.ruleSummary),
      `record_coverage tool description must embed RECORD_COVERAGE_CONTRACT.${status}.ruleSummary`,
    )
    assert.equal(rule.acceptsUnverifiedRepoCitation, false, `RECORD_COVERAGE_CONTRACT.${status} must never accept unverified repo prose`)
    for (const reqField of rule.requiredFields) {
      const propDesc = schema.properties?.[reqField]?.description ?? ''
      assert.ok(
        propDesc.includes(`"${status}"`),
        `record_coverage schema property "${reqField}" description must document requirement for status="${status}"`,
      )
    }
    if (rule.requiresVerifiedExchange) {
      assert.ok(
        rule.requiredFields.includes('exchangeIds'),
        `status="${status}" requires verified exchange and must list exchangeIds in requiredFields`,
      )
    }
  }

  // Ensure every conditional field listed in the schema only claims statuses that actually require it in RECORD_COVERAGE_CONTRACT.
  for (const field of ['enforcingControl', 'proofGapReason', 'linkedFindingId', 'exchangeIds'] as const satisfies readonly RecordCoverageFieldName[]) {
    const propDesc = schema.properties?.[field]?.description ?? ''
    for (const status of coverageClosureStatuses) {
      const required = RECORD_COVERAGE_CONTRACT[status].requiredFields.includes(field)
      if (required) {
        assert.ok(propDesc.includes(`"${status}"`), `schema field "${field}" must mention required status "${status}"`)
      } else {
        assert.ok(
          !new RegExp(`REQUIRED when status=[^:]*?"${status}"`).test(propDesc),
          `schema field "${field}" must NOT claim status="${status}" requires it`,
        )
      }
    }
  }

  // 7c) Zero schema/store/brief drift: verify live wiring in store-findings.ts, agent-session.ts, and assignment-brief.ts.
  const storeFindingsSrc = readFileSync(join(REPO_ROOT, 'src/server/store-findings.ts'), 'utf8')
  const agentSessionSrc = readFileSync(join(REPO_ROOT, 'src/server/agent-session.ts'), 'utf8')
  const briefSrc = readFileSync(join(REPO_ROOT, 'src/server/assignment-brief.ts'), 'utf8')

  assert.match(storeFindingsSrc, /\bRECORD_COVERAGE_CONTRACT\b/, 'store-findings.ts must consume RECORD_COVERAGE_CONTRACT')
  assert.match(storeFindingsSrc, /\bvalidateRecordCoverageContractInput\s*\(/, 'store-findings.ts must validate via validateRecordCoverageContractInput')
  assert.match(storeFindingsSrc, /\bmergeRouteCoverageStatuses\s*\(/, 'store-findings.ts must aggregate per-route statuses via mergeRouteCoverageStatuses')
  assert.doesNotMatch(
    storeFindingsSrc,
    /input\.status === 'no_issue_found' \|\| input\.status === 'ruled_out'/,
    'store-findings.ts must derive exchange requirement from RECORD_COVERAGE_CONTRACT, not a hardcoded status check',
  )

  assert.match(agentSessionSrc, /\bbuildRecordCoverageToolDescription\s*\(/, 'agent-session.ts must generate tool description from RECORD_COVERAGE_CONTRACT')
  assert.match(agentSessionSrc, /\bbuildRecordCoverageFieldDescriptions\s*\(/, 'agent-session.ts must generate field descriptions from RECORD_COVERAGE_CONTRACT')
  assert.match(agentSessionSrc, /\bvalidateRecordCoverageContractInput\s*\(/, 'agent-session.ts must validate via validateRecordCoverageContractInput')

  assert.match(briefSrc, /\bbuildRecordCoverageBriefGuidance\s*\(/, 'assignment-brief.ts must derive coverage guidance from RECORD_COVERAGE_CONTRACT')
  const expectedGuidance = buildRecordCoverageBriefGuidance()
  assert.equal(RECORD_COVERAGE_BRIEF_GUIDANCE, expectedGuidance)
  assert.ok(MULTIHOP_HARDENED_TWIN_RULE.includes('enforcingControl+exchangeIds'))
  const briefJson = buildAssignmentBrief({
    missionKind: 'class_scan',
    origin: 'https://canary-coverage.example.invalid',
    routes: [{ method: 'GET', path: '/api/items' }],
  })
  assert.ok(briefJson.includes(expectedGuidance), 'rendered assignment brief must surface RECORD_COVERAGE_CONTRACT guidance')
  const directive = renderSettlementSpecDirective(
    { method: 'GET', path: '/api/items', origin: 'https://canary-coverage.example.invalid' },
    'kovo_verify({ script })',
    ['no_spec_shape'],
  )
  assert.ok(directive.includes(expectedGuidance), 'settlement directive must surface RECORD_COVERAGE_CONTRACT guidance')

  // 7d) Interim route-safe precedence invariant: reported > needs_follow_up > negative closures > unprobed.
  assert.ok(coverageStatusRank('reported') > coverageStatusRank('needs_follow_up'))
  assert.ok(coverageStatusRank('needs_follow_up') > coverageStatusRank('no_issue_found'))
  assert.ok(coverageStatusRank('needs_follow_up') > coverageStatusRank('ruled_out'))
  assert.ok(coverageStatusRank('needs_follow_up') > coverageStatusRank('not_applicable'))
  assert.ok(coverageStatusRank('no_issue_found') > coverageStatusRank('unprobed'))
})
