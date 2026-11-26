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
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { createServer, request as httpRequest } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
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
import { RequestBroker, type Grant } from '../src/server/broker.ts'
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
