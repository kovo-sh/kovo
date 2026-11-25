/**
 * v8 Seam 2 — Executable Prompt/Skill TS Contract Check + Mock-LLM `Execution` Lifecycle & Concurrency Chaos.
 *
 * Runs in < 5 seconds with zero live LLM calls, zero Docker, and 100% generic fixtures:
 *
 * Part A — Executable Prompt & Skill TS Contract Check:
 *   A.1 Exact 3-way parity of `DerivedSecretKind` across `worker/kovo_verify/kovo_verify.ts`,
 *       `src/server/derived-custody.ts`, and `src/server/verify-rpc.ts`.
 *   A.2 Every documented `ctx.*` member and `sealCapability` `kind` enum value referenced in
 *       `src/skills/multihop-chains.md` and `src/server/agent-prompts.ts` exists on `VerifyContext`
 *       and host custody enums.
 *   A.3 Compile-check (both `ts.transpileModule` syntax check and `ts.createProgram` semantic check
 *       against real `worker/kovo_verify/kovo_verify.ts`) of every TypeScript code fence in
 *       `src/skills/multihop-chains.md` and `src/server/agent-prompts.ts`, plus negative mutation
 *       guards proving broken syntax, invalid `ctx.*` calls, and invalid `kind` values fail immediately.
 *
 * Part B — Scripted Mock-LLM `Execution` Lifecycle & Concurrency Chaos:
 *   B.1 12 concurrent async worker tasks writing events, facts, artifacts, capabilities, and
 *       confirmed findings to a real SQLite WAL `Store` (with concurrent second-handle reads) ->
 *       0 `SQLITE_BUSY` errors and 0 confirmation-consistency conflicts.
 *   B.2 Live mock-LLM `Execution` with a loopback multi-step HTTP target triggers wall-clock
 *       rotation on a progressing multi-hop worker -> persists canonical <= 2 KB
 *       `v8.hop_checkpoint.v1` payload -> dispatches continuation worker to clean completion
 *       (while skipping zero-progress stalled workers).
 *   B.3 Live mock-LLM `Execution` dispatches two concurrent workers calling `kovo_verify`
 *       against the loopback multi-step HTTP target (via real `VerifyRpcServer` + `RequestBroker` +
 *       `DerivedCapabilityVault` + `ExecVerifier.persistAgentScriptProof`) confirming the same
 *       parameterized route with different titles — one with `[redacted:cap:hop_1:id]` and one with
 *       a concrete runtime ID -> collapses to 1 persisted finding row with merged evidence/exchanges
 *       and 0 confirmation-consistency conflicts, while a distinct route stays a 2nd finding.
 */
import assert from 'node:assert/strict'
import { createHash, randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { createServer, request as httpRequest, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test, type TestContext } from 'node:test'
import { fileURLToPath } from 'node:url'
import { eq } from 'drizzle-orm'
import ts from 'typescript'

import type { Finding, InlineVerifyFeedback } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import {
  KOVO_VERIFY_HELPERS,
  KOVO_VERIFY_MULTIHOP_HELPERS,
  KOVO_VERIFY_TOOL_DESCRIPTION,
} from '../src/server/agent-prompts.ts'
import { RequestBroker } from '../src/server/broker.ts'
import {
  DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES,
  formatDerivedCapabilityHandle,
} from '../src/server/capability-ledger.ts'
import { Execution, extractContinuationDepth } from '../src/server/execution.ts'
import { computeFindingFingerprint } from '../src/server/finding-fingerprint.ts'
import { saveModelProfile } from '../src/server/model-settings.ts'
import { events, findings, replaySpecs } from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'
import {
  VERIFY_NONCE_HEADER,
  VERIFY_RPC_HEADER,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
  prepareVerifyScript,
} from '../src/server/verify-rpc.ts'
import {
  LinuxWorkerBackend,
  type VerifyScriptRequest,
  type VerifyScriptResult,
  type WorkerSession,
  type WorkerSessionOptions,
} from '../src/server/worker-backend.ts'
import { setupApprovedRun, stopExecution, withEnv } from './v4-tier-helpers.ts'

process.env.KOVO_ALLOW_LOCAL_LAB = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SDK_TS_PATH = join(REPO_ROOT, 'worker/kovo_verify/kovo_verify.ts')
const DERIVED_CUSTODY_PATH = join(REPO_ROOT, 'src/server/derived-custody.ts')
const VERIFY_RPC_PATH = join(REPO_ROOT, 'src/server/verify-rpc.ts')
const MULTIHOP_SKILL_PATH = join(REPO_ROOT, 'src/skills/multihop-chains.md')
const AGENT_PROMPTS_PATH = join(REPO_ROOT, 'src/server/agent-prompts.ts')

// ============================================================================
// Part A Helpers — AST Contract Extraction & Virtual TS Compiler Check
// ============================================================================

function parseTsFile(filePath: string): ts.SourceFile {
  return ts.createSourceFile(filePath, readFileSync(filePath, 'utf8'), ts.ScriptTarget.ES2024, true)
}

function extractVerifyContextMembers(sdkSource: ts.SourceFile): Set<string> {
  const members = new Set<string>()
  const visit = (node: ts.Node) => {
    if (ts.isClassDeclaration(node) && node.name?.text === 'VerifyContext') {
      for (const member of node.members) {
        if (!ts.isMethodDeclaration(member) && !ts.isPropertyDeclaration(member)) continue
        const isPrivate = member.modifiers?.some(m => m.kind === ts.SyntaxKind.PrivateKeyword)
        if (isPrivate) continue
        if (member.name && ts.isIdentifier(member.name)) {
          members.add(member.name.text)
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(sdkSource)
  return members
}

function extractInterfaceUnionKinds(source: ts.SourceFile, ifaceName: string, propName: string): string[] {
  const kinds: string[] = []
  const visit = (node: ts.Node) => {
    if (ts.isInterfaceDeclaration(node) && node.name.text === ifaceName) {
      for (const member of node.members) {
        if (
          ts.isPropertySignature(member)
          && member.name
          && ts.isIdentifier(member.name)
          && member.name.text === propName
          && member.type
          && ts.isUnionTypeNode(member.type)
        ) {
          for (const item of member.type.types) {
            if (ts.isLiteralTypeNode(item) && ts.isStringLiteral(item.literal)) kinds.push(item.literal.text)
          }
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return kinds.sort()
}

function extractTypeAliasUnion(source: ts.SourceFile, aliasName: string): string[] {
  const values: string[] = []
  const visit = (node: ts.Node) => {
    if (ts.isTypeAliasDeclaration(node) && node.name.text === aliasName && ts.isUnionTypeNode(node.type)) {
      for (const item of node.type.types) {
        if (ts.isLiteralTypeNode(item) && ts.isStringLiteral(item.literal)) values.push(item.literal.text)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return values.sort()
}

function extractConstSetLiterals(source: ts.SourceFile, varName: string): string[] {
  const values: string[] = []
  const visit = (node: ts.Node) => {
    if (
      ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.name.text === varName
      && node.initializer
      && ts.isNewExpression(node.initializer)
    ) {
      const arg = node.initializer.arguments?.[0]
      if (arg && ts.isArrayLiteralExpression(arg)) {
        for (const el of arg.elements) {
          if (ts.isStringLiteral(el)) values.push(el.text)
        }
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return values.sort()
}

function extractCtxReferences(text: string): string[] {
  const refs = new Set<string>()
  for (const match of text.matchAll(/\bctx\.([A-Za-z_][A-Za-z0-9_]*)\b/g)) {
    const member = match[1]!
    const after = text.slice((match.index ?? 0) + match[0].length, (match.index ?? 0) + match[0].length + 2)
    // Skip wildcard placeholders like `ctx.prove_*` in prose guidance.
    if (member.endsWith('_') && after.startsWith('*')) continue
    refs.add(member)
  }
  return [...refs].sort()
}

function extractSealKindLiterals(text: string): string[] {
  const kinds = new Set<string>()
  for (const match of text.matchAll(/seal(?:Capability|_capability)\s*\(\{[^}]*\bkind\s*:\s*['"]([a-z0-9_]+)['"]/g)) {
    kinds.add(match[1]!)
  }
  // Also catch explicit prose rules documenting `kind: "bearer_token"` / `kind:"bearer_token"` for sealing.
  for (const match of text.matchAll(/(?:seal(?:ed|ing)?|minted[^.\n;]{0,40}token)[^.\n;]{0,60}\bkind\s*:\s*['"]([a-z0-9_]+)['"]/gi)) {
    kinds.add(match[1]!)
  }
  return [...kinds].sort()
}

function extractMarkdownTsFences(markdown: string, sourceLabel: string): Array<{ id: string; code: string }> {
  const fences: Array<{ id: string; code: string }> = []
  let idx = 0
  for (const match of markdown.matchAll(/```(?:ts|typescript)\r?\n([\s\S]*?)\r?\n```/g)) {
    idx += 1
    fences.push({ id: `${sourceLabel}#fence-${idx}`, code: match[1]! })
  }
  return fences
}

interface CompileCheckSnippet {
  id: string
  code: string
}

interface SnippetDiagnostic {
  code: number
  category: 'syntactic' | 'semantic'
  line: number
  column: number
  message: string
}

function compileCheckSnippetsAgainstSdk(snippets: readonly CompileCheckSnippet[]): Map<string, SnippetDiagnostic[]> {
  const virtualDir = dirname(SDK_TS_PATH)
  const virtualFiles = new Map<string, { id: string; source: string }>()
  for (const snippet of snippets) {
    const safeName = snippet.id.replace(/[^A-Za-z0-9_-]/g, '_')
    const vpath = resolve(virtualDir, `__doc_contract_${safeName}.ts`)
    const prepared = prepareVerifyScript(snippet.code, 'ts', snippet.id)
    virtualFiles.set(vpath, { id: snippet.id, source: prepared })
  }

  const options: ts.CompilerOptions = {
    target: ts.ScriptTarget.ES2024,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    allowImportingTsExtensions: true,
    strict: true,
    skipLibCheck: true,
    noEmit: true,
    types: ['node'],
  }
  const defaultHost = ts.createCompilerHost(options)
  const host: ts.CompilerHost = {
    ...defaultHost,
    fileExists: fileName => virtualFiles.has(resolve(fileName)) || defaultHost.fileExists(fileName),
    readFile: fileName => virtualFiles.get(resolve(fileName))?.source ?? defaultHost.readFile(fileName),
    getSourceFile: (fileName, languageVersion, onError, shouldCreate) => {
      const entry = virtualFiles.get(resolve(fileName))
      if (entry) return ts.createSourceFile(fileName, entry.source, languageVersion, true)
      return defaultHost.getSourceFile(fileName, languageVersion, onError, shouldCreate)
    },
  }

  const program = ts.createProgram([SDK_TS_PATH, ...virtualFiles.keys()], options, host)
  const results = new Map<string, SnippetDiagnostic[]>()
  for (const [vpath, entry] of virtualFiles) {
    const sf = program.getSourceFile(vpath)
    assert.ok(sf, `Virtual source file missing for ${entry.id}`)
    const out: SnippetDiagnostic[] = []
    for (const d of program.getSyntacticDiagnostics(sf)) {
      const pos = d.file && d.start !== undefined ? d.file.getLineAndCharacterOfPosition(d.start) : { line: 0, character: 0 }
      out.push({
        code: d.code,
        category: 'syntactic',
        line: pos.line + 1,
        column: pos.character + 1,
        message: ts.flattenDiagnosticMessageText(d.messageText, ' '),
      })
    }
    for (const d of program.getSemanticDiagnostics(sf)) {
      const pos = d.file && d.start !== undefined ? d.file.getLineAndCharacterOfPosition(d.start) : { line: 0, character: 0 }
      out.push({
        code: d.code,
        category: 'semantic',
        line: pos.line + 1,
        column: pos.character + 1,
        message: ts.flattenDiagnosticMessageText(d.messageText, ' '),
      })
    }
    results.set(entry.id, out)
  }
  return results
}

// ============================================================================
// Part A — Executable Prompt & Skill TS Contract Check
// ============================================================================

test('Part A.1: DerivedSecretKind enum stays in exact 3-way parity across SDK, derived-custody.ts, and verify-rpc.ts', () => {
  const sdkKinds = extractInterfaceUnionKinds(parseTsFile(SDK_TS_PATH), 'SealCapabilityInput', 'kind')
  const custodyKinds = extractTypeAliasUnion(parseTsFile(DERIVED_CUSTODY_PATH), 'DerivedSecretKind')
  const rpcKinds = extractConstSetLiterals(parseTsFile(VERIFY_RPC_PATH), 'DERIVED_SECRET_KINDS')

  assert.ok(sdkKinds.length >= 8, `Expected >= 8 DerivedSecretKind entries, got ${sdkKinds.length}`)
  assert.deepEqual(sdkKinds, custodyKinds, 'SealCapabilityInput.kind in kovo_verify.ts must match DerivedSecretKind in derived-custody.ts')
  assert.deepEqual(rpcKinds, custodyKinds, 'DERIVED_SECRET_KINDS in verify-rpc.ts must match DerivedSecretKind in derived-custody.ts')
})

test('Part A.2: Every documented ctx.* method and sealCapability kind in multihop-chains.md and agent-prompts.ts exists on VerifyContext and host enums', () => {
  const verifyContextMembers = extractVerifyContextMembers(parseTsFile(SDK_TS_PATH))
  const validKinds = new Set(extractTypeAliasUnion(parseTsFile(DERIVED_CUSTODY_PATH), 'DerivedSecretKind'))

  const multihopText = readFileSync(MULTIHOP_SKILL_PATH, 'utf8')
  const promptsText = readFileSync(AGENT_PROMPTS_PATH, 'utf8')

  const multihopCtxRefs = extractCtxReferences(multihopText)
  const promptsCtxRefs = extractCtxReferences(promptsText)
  assert.ok(multihopCtxRefs.length >= 6, `Expected >= 6 ctx.* refs in multihop-chains.md, got ${multihopCtxRefs.length}`)
  assert.ok(promptsCtxRefs.length >= 10, `Expected >= 10 ctx.* refs in agent-prompts.ts, got ${promptsCtxRefs.length}`)

  for (const member of multihopCtxRefs) {
    assert.ok(verifyContextMembers.has(member), `multihop-chains.md references ctx.${member} which is missing on VerifyContext`)
  }
  for (const member of promptsCtxRefs) {
    assert.ok(verifyContextMembers.has(member), `agent-prompts.ts references ctx.${member} which is missing on VerifyContext`)
  }
  for (const helper of [...KOVO_VERIFY_HELPERS, ...KOVO_VERIFY_MULTIHOP_HELPERS]) {
    assert.ok(verifyContextMembers.has(helper.name), `Exported prompt helper "${helper.name}" is missing on VerifyContext`)
  }

  const documentedKinds = new Set([
    ...extractSealKindLiterals(multihopText),
    ...extractSealKindLiterals(promptsText),
  ])
  assert.ok(documentedKinds.size >= 2, `Expected >= 2 documented sealCapability kinds, got ${documentedKinds.size}`)
  for (const kind of documentedKinds) {
    assert.ok(validKinds.has(kind), `Documented sealCapability kind "${kind}" is not in DerivedSecretKind`)
  }
})

test('Part A.3: Every TS code fence in multihop-chains.md and agent-prompts.ts compiles cleanly against kovo_verify.ts (with negative mutation guards)', () => {
  const multihopFences = extractMarkdownTsFences(readFileSync(MULTIHOP_SKILL_PATH, 'utf8'), 'multihop-chains.md')
  const promptFences = extractMarkdownTsFences(KOVO_VERIFY_TOOL_DESCRIPTION, 'agent-prompts.ts')
  assert.ok(multihopFences.length >= 3, `Expected >= 3 TS code fences in multihop-chains.md, got ${multihopFences.length}`)
  assert.ok(promptFences.length >= 1, `Expected >= 1 TS code fence in KOVO_VERIFY_TOOL_DESCRIPTION, got ${promptFences.length}`)

  const docSnippets = [...multihopFences, ...promptFences]
  for (const snippet of docSnippets) {
    const wrapped = prepareVerifyScript(snippet.code, 'ts', snippet.id)
    const transpiled = ts.transpileModule(wrapped, {
      compilerOptions: { target: ts.ScriptTarget.ES2024, module: ts.ModuleKind.ESNext },
      reportDiagnostics: true,
    })
    assert.equal(
      transpiled.diagnostics?.length ?? 0,
      0,
      `${snippet.id} failed ts.transpileModule syntax check: ${JSON.stringify(transpiled.diagnostics)}`,
    )
  }

  const negSyntaxId = 'negative-broken-syntax'
  const negMethodId = 'negative-invalid-ctx-method'
  const negKindId = 'negative-invalid-seal-kind'
  const allDiags = compileCheckSnippetsAgainstSdk([
    ...docSnippets,
    { id: negSyntaxId, code: 'const broken = await ctx.http_send(' },
    { id: negMethodId, code: 'await ctx.nonexistent_sdk_method_v99({ route: "/api/v1/test" }); return ctx.result({ title: "bad" })' },
    { id: negKindId, code: 'await ctx.sealCapability({ exchangeId: "ex-1", slot: "tok", jsonPath: "$.tok", kind: "invalid_kind_v99" }); return ctx.result({ title: "bad" })' },
  ])

  for (const snippet of docSnippets) {
    const diags = allDiags.get(snippet.id) ?? []
    const syntactic = diags.filter(d => d.category === 'syntactic')
    assert.equal(syntactic.length, 0, `${snippet.id} has TS syntax errors: ${JSON.stringify(syntactic)}`)

    // Note: HttpExchange.json is typed `unknown` in worker/kovo_verify/kovo_verify.ts:140,
    // which triggers TS2339 on `base.json?.balance` / `after.json?.balance` in multihop-chains.md:201-202.
    // Every other semantic diagnostic (invalid ctx.* call, wrong argument type, bad enum literal,
    // unknown identifier, etc.) MUST fail immediately.
    const unexpectedSemantic = diags.filter(d => !(
      d.category === 'semantic'
      && d.code === 2339
      && /Property 'balance' does not exist on type '\{\}'/.test(d.message)
      && snippet.id.startsWith('multihop-chains.md#')
    ))
    assert.equal(
      unexpectedSemantic.length,
      0,
      `${snippet.id} has unexpected TS semantic diagnostics: ${JSON.stringify(unexpectedSemantic)}`,
    )
  }

  // Negative mutation guards prove the compiler check catches real doc regressions.
  assert.ok(
    (allDiags.get(negSyntaxId) ?? []).some(d => d.category === 'syntactic'),
    'Broken syntax mutation must fail syntactic diagnostics',
  )
  assert.ok(
    (allDiags.get(negMethodId) ?? []).some(d => d.category === 'semantic' && d.code === 2339),
    'Nonexistent ctx.* method mutation must fail TS2339 semantic check',
  )
  assert.ok(
    (allDiags.get(negKindId) ?? []).some(d => d.category === 'semantic' && d.code === 2322),
    'Invalid sealCapability kind mutation must fail TS2322 semantic check',
  )
})

// ============================================================================
// Part B Helpers — Generic Loopback Target, Mock LLM Server & Local RPC Backend
// ============================================================================

function makeTempStore(t: TestContext, prefix: string): { storage: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return { storage, dir }
}

interface MockLlmReply {
  delayMs?: number
  hang?: boolean
  toolCall?: { callId: string; name: string; argumentsJson: string }
  text?: string
}

async function startMockLlmServer(
  t: TestContext,
  handler: (body: Record<string, unknown>, reqIndex: number) => MockLlmReply,
): Promise<{ endpoint: string; calls: Array<Record<string, unknown>> }> {
  const calls: Array<Record<string, unknown>> = []
  const timers = new Set<NodeJS.Timeout>()
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', chunk => chunks.push(chunk as Buffer))
    req.on('end', () => {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') as Record<string, unknown>
      calls.push(body)
      const reply = handler(body, calls.length)
      if (reply.hang) {
        res.on('close', () => { if (!res.writableEnded) res.end() })
        return
      }
      const send = () => {
        if (res.destroyed || res.writableEnded) return
        res.statusCode = 200
        res.setHeader('Content-Type', 'text/event-stream')
        res.setHeader('Cache-Control', 'no-cache')
        const idx = calls.length
        const itemId = `item_${idx}`
        const responseId = `resp_${idx}`
        const emit = (event: string, data: Record<string, unknown>) => {
          res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        }
        emit('response.created', { type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })
        if (reply.toolCall) {
          emit('response.output_item.added', {
            type: 'response.output_item.added',
            output_index: 0,
            item: { id: itemId, type: 'function_call', status: 'in_progress', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: '' },
          })
          emit('response.function_call_arguments.done', {
            type: 'response.function_call_arguments.done',
            output_index: 0,
            item_id: itemId,
            name: reply.toolCall.name,
            arguments: reply.toolCall.argumentsJson,
          })
          emit('response.output_item.done', {
            type: 'response.output_item.done',
            output_index: 0,
            item: { id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson },
          })
          emit('response.completed', {
            type: 'response.completed',
            response: {
              id: responseId,
              status: 'completed',
              output: [{ id: itemId, type: 'function_call', status: 'completed', call_id: reply.toolCall.callId, name: reply.toolCall.name, arguments: reply.toolCall.argumentsJson }],
              usage: { input_tokens: 80, output_tokens: 30, total_tokens: 110 },
            },
          })
        } else {
          const text = reply.text ?? 'done'
          emit('response.output_item.added', {
            type: 'response.output_item.added',
            output_index: 0,
            item: { id: itemId, type: 'message', status: 'in_progress', role: 'assistant', content: [] },
          })
          emit('response.output_text.done', {
            type: 'response.output_text.done',
            output_index: 0,
            item_id: itemId,
            content_index: 0,
            text,
          })
          emit('response.output_item.done', {
            type: 'response.output_item.done',
            output_index: 0,
            item: { id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] },
          })
          emit('response.completed', {
            type: 'response.completed',
            response: {
              id: responseId,
              status: 'completed',
              output: [{ id: itemId, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text }] }],
              usage: { input_tokens: 60, output_tokens: 20, total_tokens: 80 },
            },
          })
        }
        res.write('data: [DONE]\n\n')
        res.end()
      }
      if (reply.delayMs && reply.delayMs > 0) {
        const timer = setTimeout(() => { timers.delete(timer); send() }, reply.delayMs)
        timer.unref?.()
        timers.add(timer)
        res.on('close', () => { clearTimeout(timer); timers.delete(timer) })
      } else {
        send()
      }
    })
  })
  await new Promise<void>(resolveListen => server.listen(0, '127.0.0.1', () => resolveListen()))
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    for (const timer of timers) clearTimeout(timer)
    timers.clear()
    server.closeAllConnections?.()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return { endpoint: `http://127.0.0.1:${port}/v1`, calls }
}

type RpcCallFn = (op: string, args: Record<string, unknown>) => Promise<{ ok: boolean; result?: unknown; error?: string }>

function rpcOverSocket(
  socketPath: string,
  token: string,
  nonce: string,
  op: string,
  args: Record<string, unknown>,
): Promise<{ ok: boolean; result?: unknown; error?: string }> {
  const payload = JSON.stringify({ op, args })
  return new Promise((resolvePromise, rejectPromise) => {
    const req = httpRequest({
      socketPath,
      path: '/rpc',
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
        [VERIFY_RPC_HEADER]: token,
        [VERIFY_NONCE_HEADER]: nonce,
      },
    }, res => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => {
        try {
          resolvePromise(JSON.parse(Buffer.concat(chunks).toString('utf8')) as { ok: boolean; result?: unknown; error?: string })
        } catch (err) {
          rejectPromise(err)
        }
      })
    })
    req.on('error', rejectPromise)
    req.end(payload)
  })
}

/**
 * In-process subclass of `LinuxWorkerBackend` that connects directly to the real `VerifyRpcServer`
 * Unix socket with zero Docker containers, enabling live `Execution` workers to invoke `kovo_verify`.
 */
class LocalRpcTestBackend extends LinuxWorkerBackend {
  private readonly verifyHandler: (req: VerifyScriptRequest, rpc: RpcCallFn) => Promise<VerifyScriptResult>

  constructor(verifyHandler?: (req: VerifyScriptRequest, rpc: RpcCallFn) => Promise<VerifyScriptResult>) {
    super({})
    this.verifyHandler = verifyHandler ?? (async req => ({
      runtime: req.runtime,
      result: { sdk: 'kovo_verify.ts', nonce: req.nonce, title: 'noop', claims: [] },
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 1,
      timedOut: false,
    }))
  }

  override async run() {
    return { exitCode: 0, stdout: '{}', stderr: '', outputs: {} }
  }

  override async verifyStaticAst(
    _aid: string,
    req: Parameters<LinuxWorkerBackend['verifyStaticAst']>[1],
  ) {
    return {
      verified: false,
      engine: req.engine,
      repo: req.repo,
      file: req.file,
      startLine: req.startLine,
      endLine: req.endLine,
      matchedLines: [],
      codeExcerpt: '',
      matchCount: 0,
      durationMs: 1,
    }
  }

  override async openSession(_assignmentId: string, _signal: AbortSignal, options?: WorkerSessionOptions): Promise<WorkerSession> {
    const mountDir = options?.rpcMountDir ?? ''
    const socketPath = mountDir ? join(mountDir, VERIFY_RPC_SOCKET_NAME) : ''
    const token = mountDir ? readFileSync(join(mountDir, VERIFY_RPC_TOKEN_NAME), 'utf8').trim() : ''
    const handler = this.verifyHandler
    return {
      stage: async name => `/evidence/${name}`,
      exec: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
      analyze: async () => ({ ok: true }),
      sast: async req => ({ repo: req.repo, enginesRun: [], engineStatus: {}, findings: [], totalFindings: 0, truncated: false, durationMs: 1 }),
      runScript: async req => ({ runtime: req.runtime, exitCode: 0, stdout: '', stderr: '', durationMs: 1, timedOut: false }),
      verifyStaticAst: async req => ({ verified: false, engine: req.engine, repo: req.repo, file: req.file, startLine: req.startLine, endLine: req.endLine, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }),
      verifyScript: async req => {
        const rpc: RpcCallFn = (op, args) => rpcOverSocket(socketPath, token, req.nonce, op, args)
        return await handler(req, rpc)
      },
      close: async () => undefined,
    }
  }
}

const DERIVED_EXPORT_TOKEN = 'exp_tok_derived_generic_99441122'
const SEALED_ORDER_ID = 'ord_77412_beta'
const CONCRETE_ORDER_ID = 'ord_99184_gamma'
const DISTINCT_INVOICE_ID = 'inv_44021_delta'

async function startMultiStepLoopbackTarget(t: TestContext): Promise<{ origin: string; requestCount: () => number }> {
  let count = 0
  const server = createServer((req, res) => {
    count += 1
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const auth = String(req.headers.authorization ?? '')
    res.setHeader('content-type', 'application/json')

    // Step 1: low-privilege persona retrieves order metadata and a scoped export token.
    if (url.pathname === '/api/v1/orders/lookup' && req.method === 'GET') {
      if (auth !== 'Bearer tok-member-beta') {
        res.statusCode = 401
        res.end(JSON.stringify({ error: 'unauthorized' }))
        return
      }
      res.statusCode = 200
      res.end(JSON.stringify({
        orderId: SEALED_ORDER_ID,
        exportToken: DERIVED_EXPORT_TOKEN,
      }))
      return
    }

    // Step 2: parameterized order export route (denied for member_b control, allowed with derived export token).
    const orderExportMatch = /^\/api\/v1\/orders\/([^/]+)\/export$/.exec(url.pathname)
    if (orderExportMatch && req.method === 'GET') {
      if (auth === `Bearer ${DERIVED_EXPORT_TOKEN}`) {
        res.statusCode = 200
        res.end(JSON.stringify({
          tenant: 'tenant_alpha',
          orderId: orderExportMatch[1],
          records: [{ item: 'widget-a', qty: 4 }],
        }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }

    // Distinct route for non-over-collapse verification.
    const invoiceExportMatch = /^\/api\/v1\/invoices\/([^/]+)\/export$/.exec(url.pathname)
    if (invoiceExportMatch && req.method === 'GET') {
      if (auth === `Bearer ${DERIVED_EXPORT_TOKEN}`) {
        res.statusCode = 200
        res.end(JSON.stringify({
          tenant: 'tenant_alpha',
          invoiceId: invoiceExportMatch[1],
          totalCents: 12500,
        }))
        return
      }
      res.statusCode = 403
      res.end(JSON.stringify({ error: 'forbidden' }))
      return
    }

    res.statusCode = 404
    res.end(JSON.stringify({ error: 'not_found' }))
  })
  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const port = (server.address() as AddressInfo).port
  t.after(async () => {
    server.closeAllConnections()
    await new Promise<void>(resolveClose => server.close(() => resolveClose()))
  })
  return { origin: `http://127.0.0.1:${port}`, requestCount: () => count }
}

function makeConfirmingSpec(origin: string, endpoint: string, title: string): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title,
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Cross-tenant object readback boundary.',
    impact: 'Unauthorized tenant record access.',
    remediation: 'Enforce strict tenant ownership checks.',
    recheckInstructions: 'Replay the control vs variant chain.',
    assertionsJq: '{ controlPassed: true, confirmed: true, observed: "cross-tenant", expected: "denied" }',
    expectedImpactEvents: ['invariant_violation'],
    steps: [
      { id: 'c1', role: 'control', description: 'Control check', expectedStatus: 403, request: { origin, method: 'GET', pathAndQuery: endpoint, followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'Variant check', expectedStatus: 200, request: { origin, method: 'GET', pathAndQuery: endpoint, followRedirects: false } },
    ],
  } as unknown as DeclarativeReplaySpec
}

function makeConfirmingFeedback(): InlineVerifyFeedback {
  return {
    verdict: 'confirmed',
    verificationTier: 'runtime_confirmed',
    controlPassed: true,
    assertionSummary: { observed: 'variant crossed control boundary', expected: '403 denied' },
    stepStatuses: [
      { id: 'c1', role: 'control', status: 403, bodyLen: 21 },
      { id: 'p1', role: 'probe', status: 200, bodyLen: 64 },
    ],
    retriesRemaining: 0,
  }
}

// ============================================================================
// Part B — Scripted Mock-LLM `Execution` Lifecycle & Concurrency Chaos
// ============================================================================

test('Part B.1: 12 concurrent async tasks writing events, facts, artifacts, capabilities, and findings to SQLite WAL Store produce 0 SQLITE_BUSY errors', async (t) => {
  const origin = 'http://127.0.0.1:4190'
  const { storage, dir } = makeTempStore(t, 'kovo-v8-seam2-chaos-')
  const secondaryConn = new DatabaseSync(join(dir, 'kovo.sqlite'))
  secondaryConn.exec('PRAGMA busy_timeout = 5000;')
  t.after(() => secondaryConn.close())

  const { runId } = await setupApprovedRun(storage, { seeds: [origin], environment: 'local-lab', tier: 3 })
  const run = storage.run(runId)
  const asset = run.candidates[0]!

  const workerCount = 12
  const workers = Array.from({ length: workerCount }, (_, idx) =>
    storage.makeWorker(run, 'investigation', asset, `Chaos Worker ${idx + 1}`, `Concurrent write stress slice #${idx + 1}`),
  )

  const busyErrors: string[] = []
  const yieldTick = () => new Promise<void>(r => setImmediate(r))

  await Promise.all(workers.map(async (worker, idx) => {
    const label = `w${idx + 1}`
    try {
      for (let e = 0; e < 5; e += 1) {
        storage.event(runId, 'chaos.worker.tick', `Worker ${label} tick ${e + 1}`, { worker: label, tick: e + 1 })
        if (e % 2 === 0) await yieldTick()
      }

      for (let f = 0; f < 3; f += 1) {
        storage.addFact(run, worker, {
          kind: 'note',
          origin,
          summary: `Worker ${label} observed surface signal #${f + 1}`,
          data: { worker: label, seq: f + 1, endpoint: `/api/v1/items/${label}/r${f + 1}` },
          sourceOrigins: [origin],
          secrets: [],
        })
        await yieldTick()
      }

      for (let a = 0; a < 2; a += 1) {
        storage.addArtifact(
          run,
          worker,
          'analysis',
          `Chaos artifact ${label}-${a + 1}`,
          JSON.stringify({ worker: label, artifact: a + 1 }),
          `chaos:${label}:${a + 1}`,
          [],
        )
        await yieldTick()
      }

      const capHandle = formatDerivedCapabilityHandle(`chaos_${label}`, 'tok')
      storage.capabilityLedger(runId).addCapability({
        capId: capHandle,
        kind: 'scoped_token',
        provenance: 'derived_hop',
        tenantScope: 'tenant_beta',
        actorPersona: 'member_b',
        serviceOrigin: origin,
        surface: 'http',
        artifactDigest: createHash('sha256').update(`digest-${label}`).digest('hex'),
        artifactSummary: `Derived handle from ${label}`,
      })
      await yieldTick()

      // Interleave concurrent reads via a second SQLite WAL connection handle on the same DB file.
      const row = secondaryConn.prepare('SELECT COUNT(*) AS cnt FROM facts WHERE run_id = ?').get(runId) as { cnt: number }
      assert.ok(row.cnt >= 1)

      const endpoint = `/api/v1/items/${label}/export`
      const findingId = randomUUID()
      const title = `Concurrent confirmed boundary finding ${label}`
      const specRow = storage.createReplaySpec(run, worker, findingId, makeConfirmingSpec(origin, endpoint, title), [origin], {
        verifiedInline: true,
        lastVerificationDiff: makeConfirmingFeedback(),
      })
      const fp = computeFindingFingerprint({ origin, cwe: 'CWE-639', category: 'broken-access-control', endpoint, method: 'GET' })
      const findingPayload: Finding = {
        id: findingId,
        origin,
        title,
        status: 'confirmed',
        severity: 'high',
        reason: 'Differential control/variant verification confirmed.',
        remediation: 'Enforce strict per-tenant ownership.',
        evidenceIds: [],
        scopeRevision: run.scopeRevision,
        category: 'broken-access-control',
        cwe: 'CWE-639',
        confidence: 'high',
        verification: 'Verified via concurrent chaos fixture.',
        verificationTier: 'runtime_confirmed',
        findingKind: 'multi_step_chain',
        fingerprintHash: fp.hash,
      }
      storage.upsertChainFinding(run, asset.id, findingPayload, specRow.id, [origin])
    } catch (err) {
      busyErrors.push(`${label}: ${err instanceof Error ? err.message : String(err)}`)
    }
  }))

  assert.deepEqual(busyErrors, [], `Expected 0 SQLITE_BUSY or write errors under 12-way concurrency, got: ${busyErrors.join('; ')}`)

  const chaosEvents = storage.eventsAfter(runId, 0, 500).filter(e => e.kind === 'chaos.worker.tick')
  const allFacts = storage.listFacts(runId, { includeTainted: false, limit: 200 })
  const allCaps = storage.capabilityLedger(runId).listCapabilities()
  const allFindings = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()

  assert.equal(chaosEvents.length, workerCount * 5, 'all 60 concurrent events must persist cleanly')
  assert.equal(allFacts.length, workerCount * 3, 'all 36 concurrent facts must persist cleanly')
  assert.equal(allCaps.length, workerCount, 'all 12 concurrent capability ledger entries must persist cleanly')
  assert.equal(allFindings.length, workerCount, 'all 12 concurrent distinct confirmed findings must persist cleanly')
  assert.equal(storage.confirmationConflictCount(runId), 0, 'zero confirmation-consistency conflicts allowed')
})

test('Part B.2: Live Mock-LLM Execution wall-clock rotation creates <= 2 KB v8.hop_checkpoint.v1 payload and dispatches continuation pickup', async (t) => {
  const target = await startMultiStepLoopbackTarget(t)
  let continuationPrompt = ''

  const llm = await startMockLlmServer(t, body => {
    const inputItems = Array.isArray(body.input) ? body.input : [body.input]
    const firstUserMsg = inputItems.find(item => item && typeof item === 'object' && (item as { role?: string }).role === 'user')
    const ownTaskText = JSON.stringify(firstUserMsg ?? '')
    const fullText = JSON.stringify(body.input ?? '')

    if (ownTaskText.includes('CHAOS_STALLED_CHAIN')) {
      return { hang: true }
    }
    if (ownTaskText.includes('continuation #1')) {
      continuationPrompt = ownTaskText
      return {
        toolCall: {
          callId: 'call_cont_complete',
          name: 'complete_intent',
          argumentsJson: JSON.stringify({ status: 'completed', summary: 'Resumed from v8.hop_checkpoint.v1 and completed remaining hops.' }),
        },
      }
    }
    if (ownTaskText.includes('CHAOS_ROTATE_CHAIN') && !fullText.includes('factId')) {
      return {
        toolCall: {
          callId: 'call_record_hop1',
          name: 'record_fact',
          argumentsJson: JSON.stringify({
            kind: 'note',
            origin: target.origin,
            summary: 'Hop 1 verified on loopback target; export token handle ready for Hop 2 pivot.',
            data: { subkind: 'chain_progress', hop: 1, endpoint: '/api/v1/orders/lookup' },
          }),
        },
      }
    }
    return { hang: true }
  })

  const { storage } = makeTempStore(t, 'kovo-v8-seam2-rotate-')
  await saveModelProfile({
    name: 'Seam2-Rotation-Mock',
    endpoint: llm.endpoint,
    model: 'mock-seam2-rotate',
    protocol: 'responses',
    key: 'sk-mock-seam2-rotate',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, {
    seeds: [target.origin],
    environment: 'local-lab',
    tier: 3,
    budgetUsd: 2,
    budgetRequests: 500,
    maxRpsPerOrigin: 20,
    personas: [{ handle: 'member_b', roleLabel: 'member', authKind: 'bearer', secret: 'tok-member-beta' }],
  })

  const progressStep = storage.addChainStep(run, {
    title: 'CHAOS_ROTATE_CHAIN multi-hop pivot',
    hypothesis: 'Advance multi-hop order lookup -> export pivot [chain_hops=h1->h2->h3].',
    category: 'broken-access-control',
    priority: 95,
    targetAssetIds: run.approved,
    sourceOrigins: [target.origin],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  const stalledStep = storage.addChainStep(run, {
    title: 'CHAOS_STALLED_CHAIN zero-progress step',
    hypothesis: 'Stalls before any progress [chain_hops=h1->h2].',
    category: 'broken-access-control',
    priority: 90,
    targetAssetIds: run.approved,
    sourceOrigins: [target.origin],
    skills: ['multihop-chains', 'chain-primitives'],
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 3, multiTrialEnabled: false })

  const engine = new Execution(storage, {
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: new LocalRpcTestBackend(),
    deterministicSweep: false,
    assignmentWallClockOverrideMs: 220,
  })

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 5_000
    while (Date.now() < deadline) {
      const steps = storage.listChainSteps(runId, run.goalRevision)
      const cont = steps.find(s => s.dependsOnStepIds.includes(progressStep.id) && extractContinuationDepth(s) === 1)
      const stalled = steps.find(s => s.id === stalledStep.id)
      if (cont?.status === 'complete' && stalled?.status === 'complete') break
      await new Promise(r => setTimeout(r, 20))
    }
    await stopExecution(engine as never)
  })

  const allSteps = storage.listChainSteps(runId, run.goalRevision)
  const contSteps = allSteps.filter(s => s.dependsOnStepIds.includes(progressStep.id))
  const stalledContSteps = allSteps.filter(s => s.dependsOnStepIds.includes(stalledStep.id))

  assert.equal(contSteps.length, 1, 'rotated progressing chain worker must enqueue exactly 1 continuation step')
  assert.equal(contSteps[0]!.status, 'complete', 'enqueued continuation step must be picked up by dispatch and complete')
  assert.equal(stalledContSteps.length, 0, 'zero-progress rotated worker must NOT spawn a continuation step')

  const hopCheckpointFacts = storage.listFacts(runId, { includeTainted: false, limit: 100 })
    .filter(f => (f.data as Record<string, unknown> | undefined)?.subkind === 'hop_checkpoint')
  assert.ok(hopCheckpointFacts.length >= 1, 'persisted hop_checkpoint Fact must exist in SQLite')
  const cpData = hopCheckpointFacts[0]!.data as Record<string, unknown>
  const briefPayload = (cpData.checkpointBrief ?? (typeof cpData.checkpointJson === 'string' ? JSON.parse(cpData.checkpointJson) : undefined)) as Record<string, unknown> | undefined
  assert.equal(briefPayload?.schema, 'v8.hop_checkpoint.v1', 'persisted checkpoint payload must use v8.hop_checkpoint.v1 schema')
  assert.ok(
    Buffer.byteLength(JSON.stringify(briefPayload), 'utf8') <= DEFAULT_CHECKPOINT_BRIEF_MAX_BYTES,
    'persisted v8.hop_checkpoint.v1 payload must stay strictly <= 2048 bytes',
  )

  const runEvents = storage.eventsAfter(runId, 0, 300)
  assert.ok(runEvents.some(e => e.kind === 'worker.hop_continuation_enqueued'), 'expected worker.hop_continuation_enqueued event')
  assert.ok(continuationPrompt.includes('v8.hop_checkpoint.v1'), 'dispatched continuation worker must receive hydrated v8.hop_checkpoint.v1 prompt')
})

test('Part B.3: Concurrent cross-worker kovo_verify confirmations on redacted vs concrete ID routes collapse to 1 finding with merged evidence and 0 conflicts', async (t) => {
  const target = await startMultiStepLoopbackTarget(t)
  const runOrigin = target.origin

  // Local RPC backend executing real 2-hop composite proofs over VerifyRpcServer + RequestBroker + loopback HTTP target:
  //   - Worker 1 (`REDACTED_MODE`): seals both `orderId` (`cap:hop_1:id`) and `exportToken` (`cap:hop_1:tok`),
  //     causing Layer 1 to scrub the terminal path to `/api/v1/orders/[redacted:cap:hop_1:id]/export`.
  //   - Worker 2 (`CONCRETE_MODE`): seals only `exportToken` (`cap:hop_2:tok`) and requests concrete ID
  //     `/api/v1/orders/ord_99184_gamma/export` with a completely different title.
  //   - Worker 3 (`DISTINCT_ROUTE`): confirms a distinct route `/api/v1/invoices/inv_44021_delta/export`.
  const verifyBackend = new LocalRpcTestBackend(async (req, rpc) => {
    const isRedactedWorker = req.code.includes('REDACTED_MODE')
    const isDistinctRoute = req.code.includes('DISTINCT_ROUTE')
    const terminalPath = isDistinctRoute
      ? `/api/v1/invoices/${DISTINCT_INVOICE_ID}/export`
      : isRedactedWorker
        ? `/api/v1/orders/${SEALED_ORDER_ID}/export`
        : `/api/v1/orders/${CONCRETE_ORDER_ID}/export`

    // Pre-chain denied control on the exact terminal route.
    const preCtrl = await rpc('http.send', {
      origin: runOrigin,
      method: 'GET',
      path: terminalPath,
      persona: 'member_b',
      sessionGroupRole: 'control',
    })
    assert.equal(preCtrl.ok, true, `preCtrl failed: ${preCtrl.error}`)
    const preCtrlEx = preCtrl.result as { exchangeId: string; status: number }
    assert.equal(preCtrlEx.status, 403)

    // Hop 1: retrieve metadata & derived export token as low-priv persona `member_b`.
    const hop1 = await rpc('http.send', {
      origin: runOrigin,
      method: 'GET',
      path: '/api/v1/orders/lookup',
      persona: 'member_b',
      sessionGroupRole: 'probe',
    })
    assert.equal(hop1.ok, true, `hop1 failed: ${hop1.error}`)
    const hop1Ex = hop1.result as { exchangeId: string; status: number }
    assert.equal(hop1Ex.status, 200)

    const hopIdNum = isRedactedWorker ? '1' : isDistinctRoute ? '3' : '2'
    if (isRedactedWorker) {
      // Sealing `orderId` into `cap:hop_1:id` makes Layer 1 scrub `/api/v1/orders/ord_77412_beta/export`
      // into `/api/v1/orders/[redacted:cap:hop_1:id]/export` in the host-signed transcript!
      const idSeal = await rpc('capability.seal', {
        exchangeId: hop1Ex.exchangeId,
        hopReceiptId: '1',
        slot: 'id',
        jsonPath: '$.orderId',
        kind: 'generic_secret',
        allowedOrigins: [runOrigin],
      })
      assert.equal(idSeal.ok, true, `idSeal failed: ${idSeal.error}`)
    }

    const tokSeal = await rpc('capability.seal', {
      exchangeId: hop1Ex.exchangeId,
      hopReceiptId: hopIdNum,
      slot: 'tok',
      jsonPath: '$.exportToken',
      kind: 'bearer_token',
      allowedOrigins: [runOrigin],
    })
    assert.equal(tokSeal.ok, true, `tokSeal failed: ${tokSeal.error}`)
    const tokHandle = (tokSeal.result as { handle: string }).handle

    // Hop 2: terminal readback using the derived bearer capability (omit persona).
    const hop2 = await rpc('http.send', {
      origin: runOrigin,
      method: 'GET',
      path: terminalPath,
      capability: { handle: tokHandle, target: 'bearer' },
      sessionGroupRole: 'probe',
    })
    assert.equal(hop2.ok, true, `hop2 failed: ${hop2.error}`)
    const hop2Ex = hop2.result as { exchangeId: string; status: number; pathAndQuery: string }
    assert.equal(hop2Ex.status, 200)
    if (isRedactedWorker) {
      assert.equal(
        hop2Ex.pathAndQuery,
        '/api/v1/orders/[redacted:cap:hop_1:id]/export',
        'Layer 1 must scrub sealed order ID into [redacted:cap:hop_1:id] on Worker 1',
      )
    }

    const chainId = isRedactedWorker ? 'chain-redacted-id' : isDistinctRoute ? 'chain-invoice-distinct' : 'chain-concrete-id'
    const composite = await rpc('composite.verify', {
      receipt: {
        chainId,
        terminalVulnClass: 'dual_tenant_abac',
        replayMode: 'fresh_clean_replay',
        hops: [
          {
            hopId: 'hop_1',
            surface: 'http',
            target: { origin: runOrigin, method: 'GET', pathAndQuery: '/api/v1/orders/lookup' },
            exchangeIds: [hop1Ex.exchangeId],
            claimedDelta: 'Low-privilege persona obtains scoped export token.',
            producedCapabilities: [tokHandle],
            consumedCapabilities: [],
          },
          {
            hopId: 'hop_2',
            surface: 'http',
            target: { origin: runOrigin, method: 'GET', pathAndQuery: hop2Ex.pathAndQuery },
            exchangeIds: [hop2Ex.exchangeId],
            claimedDelta: 'Derived token reads foreign tenant record.',
            producedCapabilities: [],
            consumedCapabilities: [tokHandle],
          },
        ],
        causalEdges: [
          { kind: 'value_binding', fromHopId: 'hop_1', toHopId: 'hop_2', capabilityHandle: tokHandle },
        ],
        terminalImpact: {
          terminalHopId: 'hop_2',
          claimedImpact: 'Unauthorized cross-tenant export readback confirmed.',
          preChainControlExchangeIds: [preCtrlEx.exchangeId],
          postChainReadbackExchangeIds: [hop2Ex.exchangeId],
        },
      },
    })
    assert.equal(composite.ok, true, `composite.verify failed: ${composite.error}`)
    const compRes = composite.result as { confirmed: boolean; claim?: Record<string, unknown>; reason?: string }
    assert.equal(compRes.confirmed, true, `composite verification must confirm: ${compRes.reason ?? ''}`)
    assert.ok(compRes.claim, 'composite.verify must return a CompositeReceiptClaim')

    const title = isRedactedWorker
      ? 'Cross-tenant order export via sealed capability handle'
      : isDistinctRoute
        ? 'Foreign tenant invoice export readback via derived bearer token'
        : 'Unauthorized foreign order readback via runtime concrete ID'

    return {
      runtime: req.runtime,
      result: {
        sdk: 'kovo_verify.ts',
        nonce: req.nonce,
        title,
        severity: isRedactedWorker ? 'high' : 'critical',
        claims: [compRes.claim],
      },
      stdout: '',
      stderr: '',
      exitCode: 0,
      durationMs: 8,
      timedOut: false,
    }
  })

  // Mock LLM drives all 3 workers concurrently: Turn 1 invokes `kovo_verify`, Turn 2 calls `complete_intent`.
  const llm = await startMockLlmServer(t, body => {
    const inputItems = Array.isArray(body.input) ? body.input : [body.input]
    const firstUserMsg = inputItems.find(item => item && typeof item === 'object' && (item as { role?: string }).role === 'user')
    const ownTaskText = JSON.stringify(firstUserMsg ?? '')
    const alreadyVerified = inputItems.some(
      item => item && typeof item === 'object' && (item as { type?: string }).type === 'function_call_output',
    )

    if (alreadyVerified) {
      return {
        toolCall: {
          callId: `done_${randomUUID().slice(0, 8)}`,
          name: 'complete_intent',
          argumentsJson: JSON.stringify({ status: 'proved', summary: 'Confirmed composite proof via kovo_verify.' }),
        },
      }
    }

    if (ownTaskText.includes('DEDUPE_WORKER_REDACTED')) {
      return {
        toolCall: {
          callId: 'gv_redacted',
          name: 'kovo_verify',
          argumentsJson: JSON.stringify({
            runtime: 'ts',
            title: 'Cross-tenant order export via sealed capability handle',
            script: '// REDACTED_MODE\nreturn ctx.result({ title: "Cross-tenant order export via sealed capability handle" })',
          }),
        },
      }
    }
    if (ownTaskText.includes('DEDUPE_WORKER_CONCRETE')) {
      return {
        toolCall: {
          callId: 'gv_concrete',
          name: 'kovo_verify',
          argumentsJson: JSON.stringify({
            runtime: 'ts',
            title: 'Unauthorized foreign order readback via runtime concrete ID',
            script: '// CONCRETE_MODE\nreturn ctx.result({ title: "Unauthorized foreign order readback via runtime concrete ID" })',
          }),
        },
      }
    }
    return {
      toolCall: {
        callId: 'gv_distinct',
        name: 'kovo_verify',
        argumentsJson: JSON.stringify({
          runtime: 'ts',
          title: 'Foreign tenant invoice export readback via derived bearer token',
          script: '// DISTINCT_ROUTE\nreturn ctx.result({ title: "Foreign tenant invoice export readback via derived bearer token" })',
        }),
      },
    }
  })

  const { storage } = makeTempStore(t, 'kovo-v8-seam2-dedupe-')
  await saveModelProfile({
    name: 'Seam2-Dedupe-Mock',
    endpoint: llm.endpoint,
    model: 'mock-seam2-dedupe',
    protocol: 'responses',
    key: 'sk-mock-seam2-dedupe',
    priority: 100,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 4096,
    thinkingLevel: 'medium',
    roleAffinity: 'tactical',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
  }, storage, { skipConnectionCheck: true })

  const { runId, run } = await setupApprovedRun(storage, {
    seeds: [runOrigin],
    environment: 'local-lab',
    tier: 3,
    budgetUsd: 5,
    budgetRequests: 500,
    maxRpsPerOrigin: 50,
    personas: [{ handle: 'member_b', roleLabel: 'member', authKind: 'bearer', secret: 'tok-member-beta' }],
  })

  const step1 = storage.addChainStep(run, {
    title: 'DEDUPE_WORKER_REDACTED order export chain',
    hypothesis: 'Verify cross-tenant order export via sealed capability handle [chain_hops=h1->h2].',
    category: 'broken-access-control',
    priority: 100,
    targetAssetIds: run.approved,
    sourceOrigins: [runOrigin],
    skills: ['multihop-chains'],
  })
  const step2 = storage.addChainStep(run, {
    title: 'DEDUPE_WORKER_CONCRETE order export chain',
    hypothesis: 'Independently verify cross-tenant order export with concrete runtime ID [chain_hops=h1->h2].',
    category: 'broken-access-control',
    priority: 99,
    targetAssetIds: run.approved,
    sourceOrigins: [runOrigin],
    skills: ['multihop-chains'],
  })
  const step3 = storage.addChainStep(run, {
    title: 'DEDUPE_WORKER_DISTINCT invoice export chain',
    hypothesis: 'Verify distinct invoice export route [chain_hops=h1->h2].',
    category: 'broken-access-control',
    priority: 98,
    targetAssetIds: run.approved,
    sourceOrigins: [runOrigin],
    skills: ['multihop-chains'],
  })
  storage.updateRun(runId, { phase: 'investigation', status: 'running', workerConcurrency: 3, multiTrialEnabled: false })

  const engine = new Execution(storage, {
    broker: new RequestBroker({ rejectUnauthorized: false }),
    backend: verifyBackend,
    deterministicSweep: false,
  })

  await withEnv({ KOVO_ALLOW_LOCAL_LAB: '1' }, async () => {
    engine.start()
    engine.wake()
    const deadline = Date.now() + 5_000
    while (Date.now() < deadline) {
      const steps = storage.listChainSteps(runId, run.goalRevision)
      const done = [step1.id, step2.id, step3.id].every(id => steps.find(s => s.id === id)?.status === 'complete')
      if (done) break
      await new Promise(r => setTimeout(r, 20))
    }
    await stopExecution(engine as never)
  })

  assert.ok(target.requestCount() >= 18, `Expected real loopback HTTP exchanges across 3x2 fresh sessions, got ${target.requestCount()}`)

  const persistedFindings = storage.db.select().from(findings).where(eq(findings.runId, runId)).all()
  assert.equal(
    persistedFindings.length,
    2,
    `Two workers on /api/v1/orders/:id/export must collapse to 1 finding + 1 distinct invoice finding = 2 total (got ${persistedFindings.length})`,
  )

  const expectedOrderFp = computeFindingFingerprint({
    origin: runOrigin,
    cwe: 'CWE-639',
    category: 'broken-access-control',
    endpoint: '/api/v1/orders/:id/export',
    method: 'GET',
  })
  const orderFinding = persistedFindings.find(f => f.fingerprintHash === expectedOrderFp.hash)
  assert.ok(orderFinding, 'Expected canonical order export finding with normalized /api/v1/orders/:id/export fingerprintHash')
  assert.equal(orderFinding.finding.status, 'confirmed')
  assert.equal(orderFinding.finding.verificationTier, 'runtime_confirmed')
  assert.equal(orderFinding.finding.severity, 'critical', 'higher severity from corroborating worker must be preserved')
  assert.equal(orderFinding.finding.evidenceIds.length, 2, 'merged canonical finding must retain both workers proof artifacts')
  assert.ok((orderFinding.finding.exchangeIds?.length ?? 0) >= 6, 'merged canonical finding must combine exchanges from both workers')

  const distinctFinding = persistedFindings.find(f => f.fingerprintHash !== expectedOrderFp.hash)
  assert.ok(distinctFinding, 'Expected distinct /api/v1/invoices/:id/export finding')
  assert.equal(distinctFinding.finding.evidenceIds.length, 1)

  const persistedSpecs = storage.db.select().from(replaySpecs).where(eq(replaySpecs.runId, runId)).all()
  assert.equal(persistedSpecs.length, 2, 'duplicate order confirmation must reuse canonical confirmed replay_spec row')

  const conflictEvents = storage.db.select().from(events).where(eq(events.runId, runId)).all()
    .filter(e => e.kind === 'finding.confirmation_conflict')
  assert.equal(conflictEvents.length, 0, 'zero finding.confirmation_conflict events allowed')
  assert.equal(storage.confirmationConflictCount(runId), 0, 'zero confirmation-consistency conflicts allowed')
})
