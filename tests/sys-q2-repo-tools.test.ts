/**
 * Systemic Quality Move Q2 Regression Tests — Parallel Structured Repo/Evidence Tools,
 * `derive_evidence` Parallelism, Malformed Tool-Call Diagnostics, and `just-bash` Timeout Alignment.
 *
 * Verifies (Docker-free, loopback fixtures, zero benchmark contamination):
 *  1. `read_repo_file`: numbered bounded line slices, pagination, secret redaction, strict path-jail,
 *     component-level symlink refusal, traversal refusal, `.git/` & `node_modules/` & sensitive file refusal,
 *     and binary file refusal.
 *  2. `search_repo`: fast literal search (default), case-sensitive mode, `pathPrefix` scoping, `maxMatches`
 *     bounding, skipping `.git/` / `node_modules/` / symlinks / sensitive / binary files, and ReDoS-safe
 *     `regex: true` via `safe-regex.ts` (rejecting catastrophic patterns fail-closed).
 *  3. `read_evidence_slice`: parallel slicing of `formatToolOutput` spilled outputs by `artifactId` and
 *     `/evidence/tool-output/...` path (zero shell round-trips), plus host `evidenceDir` path-jail &
 *     symlink-escape refusal.
 *  4. `PARALLEL_READ_ONLY_TOOLS` & concurrent execution: `read_repo_file`, `search_repo`,
 *     `read_evidence_slice`, and `derive_evidence` execute with `executionMode === 'parallel'`;
 *     `resolveAutoReposDir` resolves uniquely and fails closed on ambiguity/symlinks; live
 *     `runAgentSession` executes parallel read-only calls concurrently in a single turn.
 *  5. Malformed/truncated tool-call marker diagnostics (Q1 integration): both direct `kovo_verify`
 *     execution and `runAgentSession` `ToolTask` (`beforeTool`/`afterTool`) replace schema errors
 *     with clear truncated/malformed JSON repair diagnostics.
 *  6. `worker/bridge.ts` `just-bash` timeout alignment: `executionLimits.maxExecutionTimeMs` aligns
 *     with bounded `timeoutMs` (clamped `[1_000, 120_000]`) instead of silently killing at 30s.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  PARALLEL_READ_ONLY_TOOLS,
  SPECIALIST_COMMON_TOOLS,
  buildWorkerTools,
  createSessionScrubbers,
  detectMalformedToolCallArgs,
  formatMalformedToolArgsError,
  readEvidenceSliceHost,
  readRepoFileHost,
  resolveAutoReposDir,
  runAgentSession,
  searchRepoHost,
} from '../src/server/agent-session.ts'
import { createAgentTrace } from '../src/server/agent-trace.ts'
import type { ResolvedModelProfile } from '../src/server/model-settings.ts'
import { scanSourceTreeForContamination } from '../scripts/check-v8-contamination.ts'

process.env.KOVO_ALLOW_LOCAL_MODEL = '1'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function makeTempWorkspace(t: test.TestContext): {
  root: string
  reposDir: string
  evidenceDir: string
  outsideFile: string
  outsideDir: string
} {
  const root = mkdtempSync(join(tmpdir(), 'kovo-sys-q2-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const reposDir = join(root, 'repos-root')
  const evidenceDir = join(root, 'evidence-root')
  const outsideDir = join(root, 'outside-secret')
  mkdirSync(join(reposDir, 'acme/webapp/src/routes'), { recursive: true })
  mkdirSync(join(reposDir, 'acme/webapp/.git'), { recursive: true })
  mkdirSync(join(reposDir, 'acme/webapp/node_modules/pkg'), { recursive: true })
  mkdirSync(join(reposDir, 'acme/webapp/credentials'), { recursive: true })
  mkdirSync(join(evidenceDir, 'tool-output'), { recursive: true })
  mkdirSync(outsideDir, { recursive: true })

  const outsideFile = join(outsideDir, 'host-secret.txt')
  writeFileSync(outsideFile, 'TOP_SECRET_OUTSIDE_FILE_DO_NOT_READ\n', 'utf8')
  writeFileSync(join(outsideDir, 'nested.ts'), 'export const leaked = "OUTSIDE_DIR_TOKEN"\n', 'utf8')

  const lines = Array.from({ length: 450 }, (_, i) => `export const line_${i + 1} = "val_${i + 1}"`)
  lines[41] = 'export function authorizeTenant(req: Req) { return req.headers["x-tenant-id"] } // AUTH_GUARD_NEEDLE'
  lines[199] = 'export const SECOND_NEEDLE = "route_handler_marker"'
  writeFileSync(join(reposDir, 'acme/webapp/src/routes/orders.ts'), lines.join('\n') + '\n', 'utf8')
  writeFileSync(
    join(reposDir, 'acme/webapp/src/app.ts'),
    [
      'import { authorizeTenant } from "./routes/orders.ts"',
      'export const API_SECRET = "live_secret_token_xyz_998877"',
      'export function boot() { return authorizeTenant } // AUTH_GUARD_NEEDLE',
    ].join('\n') + '\n',
    'utf8',
  )
  writeFileSync(join(reposDir, 'acme/webapp/.env'), 'DATABASE_URL=postgres://secret:pw@db/prod\nAUTH_GUARD_NEEDLE\n', 'utf8')
  writeFileSync(join(reposDir, 'acme/webapp/.env.example'), 'DATABASE_URL=postgres://example\n', 'utf8')
  writeFileSync(join(reposDir, 'acme/webapp/tls.pem'), '-----BEGIN PRIVATE KEY-----\nAUTH_GUARD_NEEDLE\n', 'utf8')
  writeFileSync(join(reposDir, 'acme/webapp/credentials/prod.json'), '{"secret":"AUTH_GUARD_NEEDLE"}\n', 'utf8')
  writeFileSync(join(reposDir, 'acme/webapp/credentials/loader.ts'), 'export const loader = () => "ok"\n', 'utf8')
  writeFileSync(join(reposDir, 'acme/webapp/.git/config'), '[core]\n  AUTH_GUARD_NEEDLE = true\n', 'utf8')
  writeFileSync(join(reposDir, 'acme/webapp/node_modules/pkg/index.js'), 'module.exports = "AUTH_GUARD_NEEDLE"\n', 'utf8')
  writeFileSync(join(reposDir, 'acme/webapp/src/blob.bin'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x41, 0x55, 0x54, 0x48]))

  // Symlink escape fixtures inside reposDir and evidenceDir.
  symlinkSync(outsideFile, join(reposDir, 'acme/webapp/src/escape-link.ts'))
  symlinkSync(outsideDir, join(reposDir, 'acme/webapp/src/escape-dir'))
  symlinkSync(join(reposDir, 'acme/webapp/src/app.ts'), join(reposDir, 'acme/webapp/src/internal-link.ts'))
  symlinkSync(outsideFile, join(evidenceDir, 'escape-evidence.txt'))
  writeFileSync(join(evidenceDir, 'tool-output/staged-demo.txt'), '0123456789'.repeat(200), 'utf8')

  return { root, reposDir, evidenceDir, outsideFile, outsideDir }
}

function responsesSseTurn(toolCalls: Array<{ id: string; name: string; rawArgs: string }>, text?: string): string {
  const events: unknown[] = []
  const output: unknown[] = []
  let idx = 0
  const respId = `resp_${randomUUID().slice(0, 8)}`
  if (text !== undefined) {
    const msgId = `msg_${randomUUID().slice(0, 8)}`
    events.push({ type: 'response.output_item.added', output_index: idx, item: { id: msgId, type: 'message', status: 'in_progress', content: [] } })
    events.push({ type: 'response.output_item.done', output_index: idx, item: { id: msgId, type: 'message', status: 'completed', content: [{ type: 'output_text', text }] } })
    output.push({ id: msgId, type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text }] })
    idx += 1
  }
  for (const call of toolCalls) {
    const fcId = `fc_${randomUUID().slice(0, 8)}`
    events.push(
      { type: 'response.output_item.added', output_index: idx, item: { id: fcId, type: 'function_call', status: 'in_progress', call_id: call.id, name: call.name, arguments: '' } },
      { type: 'response.function_call_arguments.delta', output_index: idx, item_id: fcId, delta: call.rawArgs },
      { type: 'response.function_call_arguments.done', output_index: idx, item_id: fcId, name: call.name, arguments: call.rawArgs },
      { type: 'response.output_item.done', output_index: idx, item: { id: fcId, type: 'function_call', status: 'completed', call_id: call.id, name: call.name, arguments: call.rawArgs } },
    )
    output.push({ id: fcId, type: 'function_call', status: 'completed', call_id: call.id, name: call.name, arguments: call.rawArgs })
    idx += 1
  }
  events.push({
    type: 'response.completed',
    response: { id: respId, status: 'completed', output, usage: { input_tokens: 40, output_tokens: 20, total_tokens: 60 } },
  })
  return events.map(e => `data: ${JSON.stringify(e)}\n\n`).join('') + 'data: [DONE]\n\n'
}

// ---------------------------------------------------------------------------
// 1. read_repo_file: bounded slices, path-jail, symlink & sensitive-file defense
// ---------------------------------------------------------------------------
test('Q2.1: read_repo_file returns bounded numbered slices and enforces strict path-jail + symlink refusal', async t => {
  const { reposDir } = makeTempWorkspace(t)

  // Reads numbered slice with /repos/ prefix and caps to 400 lines.
  const slice1 = readRepoFileHost(reposDir, { path: '/repos/acme/webapp/src/routes/orders.ts', startLine: 40, endLine: 45 })
  assert.equal(slice1.path, '/repos/acme/webapp/src/routes/orders.ts')
  assert.equal(slice1.startLine, 40)
  assert.equal(slice1.endLine, 45)
  assert.equal(slice1.totalLines, 450)
  assert.equal(slice1.truncated, true)
  assert.equal(slice1.nextStartLine, 46)
  assert.match(slice1.content, /^40: export const line_40/m)
  assert.match(slice1.content, /^42: export function authorizeTenant/m)

  // Requesting 1..500 is bounded cleanly by max lines / byte cap.
  const bounded = readRepoFileHost(reposDir, { path: 'acme/webapp/src/routes/orders.ts', startLine: 1, endLine: 500 })
  assert.ok(bounded.endLine <= 400, `Expected <= 400 lines, got ${bounded.endLine}`)
  assert.ok(Buffer.byteLength(bounded.content, 'utf8') <= 16 * 1024)
  assert.equal(bounded.truncated, true)
  assert.equal(bounded.nextStartLine, bounded.endLine + 1)

  // Safe templates (.env.example) and source files inside credentials/ remain readable.
  assert.match(readRepoFileHost(reposDir, { path: '/repos/acme/webapp/.env.example' }).content, /DATABASE_URL/)
  assert.match(readRepoFileHost(reposDir, { path: '/repos/acme/webapp/credentials/loader.ts' }).content, /loader/)

  // Path traversal, null bytes, backslashes, symlinks, .git, node_modules, secrets, and binaries are refused.
  const refusedPaths: Array<[string, RegExp]> = [
    ['../outside-secret/host-secret.txt', /traversal/i],
    ['/repos/acme/webapp/../../outside-secret/host-secret.txt', /traversal/i],
    ['acme\\webapp\\src\\app.ts', /backslash/i],
    ['acme/webapp/src/app.ts\0.txt', /control/i],
    ['/repos/acme/webapp/src/escape-link.ts', /symlink/i],
    ['/repos/acme/webapp/src/escape-dir/nested.ts', /symlink/i],
    ['/repos/acme/webapp/src/internal-link.ts', /symlink/i],
    ['/repos/acme/webapp/.git/config', /restricted/i],
    ['/repos/acme/webapp/node_modules/pkg/index.js', /restricted/i],
    ['/repos/acme/webapp/.env', /restricted/i],
    ['/repos/acme/webapp/tls.pem', /restricted/i],
    ['/repos/acme/webapp/credentials/prod.json', /restricted/i],
    ['/repos/acme/webapp/src/blob.bin', /binary/i],
    ['/repos/acme/webapp/src', /regular file/i],
  ]
  for (const [badPath, pattern] of refusedPaths) {
    assert.throws(() => readRepoFileHost(reposDir, { path: badPath }), pattern, `Expected refusal for ${badPath}`)
  }

  // Through buildWorkerTools, live registered secrets are scrubbed before reaching the model.
  const scrubbers = createSessionScrubbers([{ placeholder: '[REDACTED:api_secret]', value: 'live_secret_token_xyz_998877' }])
  const controller = new AbortController()
  const tools = buildWorkerTools({}, scrubbers, controller.signal, 12 * 1024, () => {}, { reposDir })
  const readTool = tools.find(tool => tool.name === 'read_repo_file')
  assert.ok(readTool, 'read_repo_file must be registered when reposDir is configured')
  const res = await readTool.execute({ path: '/repos/acme/webapp/src/app.ts' } as never, {} as never, { abortSignal: controller.signal } as never)
  const outText = (res.output ?? []).map(p => ('text' in p ? p.text : '')).join('\n')
  assert.equal(res.isError ?? false, false)
  assert.equal(outText.includes('live_secret_token_xyz_998877'), false, 'Live secret must be scrubbed from read_repo_file output')
})

// ---------------------------------------------------------------------------
// 2. search_repo: literal default, skip-list hygiene, and ReDoS-safe regex
// ---------------------------------------------------------------------------
test('Q2.2: search_repo skips .git/node_modules/symlinks/secrets and enforces ReDoS-safe regex', t => {
  const { reposDir } = makeTempWorkspace(t)

  // Literal search finds only legitimate source matches (never .git, node_modules, .env, .pem, credentials/*.json, symlinks, binaries).
  const lit = searchRepoHost(reposDir, { query: 'AUTH_GUARD_NEEDLE' })
  assert.equal(lit.mode, 'literal')
  assert.equal(lit.matchCount, 2)
  assert.deepEqual(
    lit.matches.map(m => `${m.path}:${m.line}`),
    ['/repos/acme/webapp/src/app.ts:3', '/repos/acme/webapp/src/routes/orders.ts:42'],
  )

  // Case-sensitive search distinguishes case; pathPrefix scopes cleanly.
  const csMiss = searchRepoHost(reposDir, { query: 'auth_guard_needle', caseSensitive: true })
  assert.equal(csMiss.matchCount, 0)
  const scoped = searchRepoHost(reposDir, { query: 'AUTH_GUARD_NEEDLE', pathPrefix: '/repos/acme/webapp/src/routes' })
  assert.equal(scoped.matchCount, 1)
  assert.equal(scoped.matches[0]!.path, '/repos/acme/webapp/src/routes/orders.ts')

  // maxMatches caps output and sets truncated: true.
  const capped = searchRepoHost(reposDir, { query: 'export const line_', maxMatches: 3 })
  assert.equal(capped.matchCount, 3)
  assert.equal(capped.truncated, true)

  // Safe linear regex works.
  const safeRx = searchRepoHost(reposDir, { query: 'authorize[A-Z][a-z]+\\(', regex: true })
  assert.equal(safeRx.mode, 'regex')
  assert.equal(safeRx.matchCount, 1)
  assert.equal(safeRx.matches[0]!.line, 42)

  // Catastrophic backtracking ReDoS regex is rejected fail-closed by safe-regex.ts.
  const start = Date.now()
  assert.throws(
    () => searchRepoHost(reposDir, { query: '(a+)+$', regex: true }),
    /Unsafe or invalid search_repo regex rejected/i,
  )
  assert.throws(
    () => searchRepoHost(reposDir, { query: '(.*a){10}', regex: true }),
    /Unsafe or invalid search_repo regex rejected/i,
  )
  assert.ok(Date.now() - start < 500, 'Unsafe regex rejection must be instantaneous')

  // Traversal / symlink pathPrefix is refused.
  assert.throws(() => searchRepoHost(reposDir, { query: 'x', pathPrefix: '../outside-secret' }), /traversal/i)
  assert.throws(() => searchRepoHost(reposDir, { query: 'x', pathPrefix: '/repos/acme/webapp/src/escape-dir' }), /symlink/i)
})

// ---------------------------------------------------------------------------
// 3. read_evidence_slice: automatic spill paging + evidenceDir path-jail
// ---------------------------------------------------------------------------
test('Q2.3: formatToolOutput spills into host store for zero-shell read_evidence_slice paging and jails evidenceDir', async t => {
  const { evidenceDir } = makeTempWorkspace(t)
  const controller = new AbortController()
  const stagedBySpillCallback: Array<{ id: string; len: number }> = []
  const bigBody = Array.from({ length: 1200 }, (_, i) => `RECORD_${String(i).padStart(4, '0')}:payload_chunk`).join('\n')

  const tools = buildWorkerTools(
    {
      spillOutput: async (id, content) => {
        stagedBySpillCallback.push({ id, len: content.length })
        return `/evidence/tool-output/${id}.txt`
      },
      search_facts: async () => bigBody,
    },
    text => text,
    controller.signal,
    1024, // small inline limit to force spill
    () => {},
    { evidenceDir },
  )

  const searchFactsTool = tools.find(tool => tool.name === 'search_facts')!
  const readSliceTool = tools.find(tool => tool.name === 'read_evidence_slice')!
  assert.ok(readSliceTool, 'read_evidence_slice must be registered when spillOutput/evidenceDir is present')

  const rawRes = await searchFactsTool.execute({} as never, {} as never, { abortSignal: controller.signal } as never)
  const rawText = (rawRes.output ?? []).map(p => ('text' in p ? p.text : '')).join('\n')
  assert.match(rawText, /read_evidence_slice\(\{ artifactId: "([^"]+)"/)
  const idMatch = /artifactId="([^"]+)"/.exec(rawText)
  assert.ok(idMatch, `Expected artifactId in spill notice, got: ${rawText}`)
  const artifactId = idMatch[1]!
  assert.equal(stagedBySpillCallback.length, 1)

  // Read slice 0 and slice 1 in parallel by artifactId and by /evidence/... path.
  const [p1, p2] = await Promise.all([
    readSliceTool.execute({ artifactId, offset: 0, limit: 500 } as never, {} as never, { abortSignal: controller.signal } as never),
    readSliceTool.execute({ path: `/evidence/tool-output/${artifactId}.txt`, offset: 500, limit: 500 } as never, {} as never, { abortSignal: controller.signal } as never),
  ])
  const parsed1 = JSON.parse((p1.output ?? []).map(p => ('text' in p ? p.text : '')).join('')) as {
    artifactId: string; offset: number; returnedChars: number; hasMore: boolean; nextOffset: number; content: string
  }
  const parsed2 = JSON.parse((p2.output ?? []).map(p => ('text' in p ? p.text : '')).join('')) as {
    artifactId: string; offset: number; returnedChars: number; hasMore: boolean; content: string
  }
  assert.equal(parsed1.artifactId, artifactId)
  assert.equal(parsed1.offset, 0)
  assert.equal(parsed1.returnedChars, 500)
  assert.equal(parsed1.hasMore, true)
  assert.equal(parsed1.nextOffset, 500)
  assert.equal(parsed1.content + parsed2.content, bigBody.slice(0, 1000))

  // Host evidenceDir reads work and strictly refuse symlink/traversal escapes.
  const diskSlice = readEvidenceSliceHost({ evidenceDir }, { artifactId: 'staged-demo', offset: 10, limit: 25 })
  assert.equal(diskSlice.returnedChars, 25)
  assert.equal(diskSlice.content, '0123456789012345678901234')

  assert.throws(() => readEvidenceSliceHost({ evidenceDir }, { path: '/evidence/escape-evidence.txt' }), /symlink/i)
  assert.throws(() => readEvidenceSliceHost({ evidenceDir }, { path: '../outside-secret/host-secret.txt' }), /traversal/i)
  assert.throws(() => readEvidenceSliceHost({ evidenceDir }, { artifactId: '../escape' }), /Invalid evidence artifactId/i)
})

// ---------------------------------------------------------------------------
// 4. PARALLEL_READ_ONLY_TOOLS, auto-discovery & concurrent execution in one turn
// ---------------------------------------------------------------------------
test('Q2.4: repo/evidence tools & derive_evidence are parallel and execute concurrently in runAgentSession', async t => {
  const { root, reposDir } = makeTempWorkspace(t)

  // Verify PARALLEL_READ_ONLY_TOOLS + SPECIALIST_COMMON_TOOLS registration.
  for (const name of ['read_repo_file', 'search_repo', 'read_evidence_slice', 'derive_evidence']) {
    assert.ok(PARALLEL_READ_ONLY_TOOLS.has(name), `${name} must be in PARALLEL_READ_ONLY_TOOLS`)
  }
  for (const name of ['read_repo_file', 'search_repo', 'read_evidence_slice'] as const) {
    assert.ok(SPECIALIST_COMMON_TOOLS.includes(name), `${name} must be in SPECIALIST_COMMON_TOOLS`)
  }

  const tools = buildWorkerTools(
    {
      derive_evidence: async () => ({ exitCode: 0, stdout: 'ok', stderr: '' }),
      request_http: async () => ({ status: 200 }),
      record_fact: async () => ({ id: 'f1' }),
    },
    text => text,
    AbortSignal.timeout(5_000),
    12 * 1024,
    () => {},
    { reposDir },
  )
  const modeOf = (name: string) => tools.find(tool => tool.name === name)?.executionMode
  assert.equal(modeOf('read_repo_file'), 'parallel')
  assert.equal(modeOf('search_repo'), 'parallel')
  assert.equal(modeOf('read_evidence_slice'), 'parallel')
  assert.equal(modeOf('derive_evidence'), 'parallel')
  assert.equal(modeOf('request_http'), 'sequential')
  assert.equal(modeOf('record_fact'), 'sequential')

  // Verify resolveAutoReposDir resolves uniquely and fails closed on ambiguity.
  const dataDir = join(root, 'data-dir')
  mkdirSync(join(dataDir, 'repos/proj-alpha/acme/webapp'), { recursive: true })
  const promptOne = JSON.stringify({ mountedRepos: ['/repos/acme/webapp'] })
  assert.equal(resolveAutoReposDir(dataDir, promptOne), join(dataDir, 'repos/proj-alpha'))
  mkdirSync(join(dataDir, 'repos/proj-beta/acme/webapp'), { recursive: true })
  assert.equal(resolveAutoReposDir(dataDir, promptOne), undefined, 'Ambiguous multi-project match must fail closed')

  // Live runAgentSession concurrency verification: 3 parallel read calls overlap in-flight in 1 turn.
  let inFlight = 0
  let maxInFlight = 0
  let releaseBarrier: (() => void) | undefined
  const barrier = new Promise<void>(resolveBarrier => { releaseBarrier = resolveBarrier })
  const trackConcurrency = async <T>(fn: () => T): Promise<T> => {
    inFlight += 1
    if (inFlight > maxInFlight) maxInFlight = inFlight
    if (inFlight >= 3) releaseBarrier?.()
    await Promise.race([barrier, new Promise(r => setTimeout(r, 400))])
    try {
      return fn()
    } finally {
      inFlight -= 1
    }
  }

  let turnNo = 0
  const server = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      turnNo += 1
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (turnNo === 1) {
        res.end(responsesSseTurn([
          { id: 'c1', name: 'search_repo', rawArgs: JSON.stringify({ query: 'AUTH_GUARD_NEEDLE' }) },
          { id: 'c2', name: 'read_repo_file', rawArgs: JSON.stringify({ path: '/repos/acme/webapp/src/app.ts', startLine: 1, endLine: 10 }) },
          { id: 'c3', name: 'read_repo_file', rawArgs: JSON.stringify({ path: '/repos/acme/webapp/src/routes/orders.ts', startLine: 40, endLine: 45 }) },
        ]))
      } else {
        res.end(responsesSseTurn([
          { id: 'c4', name: 'complete_intent', rawArgs: JSON.stringify({ status: 'ruled_out', summary: 'Checked source files in parallel.' }) },
        ]))
      }
    })
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()) }))
  await once(server, 'listening')
  const port = (server.address() as AddressInfo).port

  const profile: ResolvedModelProfile = {
    id: 'mock-q2',
    name: 'Mock Q2',
    endpoint: `http://127.0.0.1:${port}/v1`,
    model: 'mock-model',
    protocol: 'responses',
    key: 'test-key-q2',
    priority: 1,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 2048,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }

  const sessionDataDir = join(root, 'session-run')
  const result = await runAgentSession({
    directory: sessionDataDir,
    sessionId: `sess-q2-par-${randomUUID().slice(0, 6)}`,
    requestId: 'req-q2-par',
    profiles: [profile],
    scenario: 'worker-investigation',
    prompt: 'Inspect repo files concurrently.',
    signal: AbortSignal.timeout(10_000),
    maxTurns: 4,
    reposDir,
    handlers: {
      read_repo_file: async args => trackConcurrency(() => readRepoFileHost(reposDir, args)),
      search_repo: async args => trackConcurrency(() => searchRepoHost(reposDir, args)),
      complete_intent: async () => ({ recorded: true }),
    },
  })

  assert.equal(result.status, 'completed')
  assert.equal(maxInFlight, 3, `Expected all 3 read-only tools to execute concurrently, maxInFlight=${maxInFlight}`)
})

// ---------------------------------------------------------------------------
// 5. Q1 Malformed/Truncated Tool-Call Marker Diagnostics
// ---------------------------------------------------------------------------
test('Q2.5: agent-session surfaces clear diagnostics for malformed/truncated tool-call markers', async t => {
  const { root, reposDir } = makeTempWorkspace(t)

  // Unit checks across supported marker shapes.
  assert.equal(detectMalformedToolCallArgs({ path: '/repos/a/b.ts' }), null)
  const d1 = detectMalformedToolCallArgs({ __kovoToolArgsParseError: { message: 'Unexpected end of JSON input', truncated: true, rawLength: 14200 } })
  assert.ok(d1)
  assert.equal(d1.truncated, true)
  assert.equal(d1.rawLength, 14200)
  assert.match(formatMalformedToolArgsError('kovo_verify', d1), /truncated\/malformed JSON \(14200 chars\)/i)

  const d2 = detectMalformedToolCallArgs({ __parseError: 'Unterminated string in JSON' })
  assert.ok(d2)
  assert.equal(d2.truncated, true)

  // Direct kovo_verify execution surfaces malformed-JSON repair instead of blaming missing script.
  const controller = new AbortController()
  const tools = buildWorkerTools(
    { kovo_verify: async () => ({ confirmed: true, reason: 'ok', detail: '', attempts: [] }) },
    text => text,
    controller.signal,
    12 * 1024,
    () => {},
  )
  const kvTool = tools.find(tool => tool.name === 'kovo_verify')!
  const kvRes = await kvTool.execute(
    { __parseError: 'Unexpected end of JSON input' } as never,
    {} as never,
    { abortSignal: controller.signal } as never,
  )
  assert.equal(kvRes.isError, true)
  const kvText = (kvRes.output ?? []).map(p => ('text' in p ? p.text : '')).join('\n')
  assert.match(kvText, /truncated\/malformed JSON/i)
  assert.match(kvText, /keep the payload\/script concise/i)

  // Full runAgentSession Harness round: schema-rejected malformed marker in `afterTool` replaces noisy error.
  const seenModelInputs: string[] = []
  let turnNo = 0
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', c => chunks.push(Buffer.from(c)))
    req.on('end', () => {
      seenModelInputs.push(Buffer.concat(chunks).toString('utf8'))
      turnNo += 1
      res.writeHead(200, { 'content-type': 'text/event-stream' })
      if (turnNo === 1) {
        res.end(responsesSseTurn([
          {
            id: 'call_malformed',
            name: 'read_repo_file',
            rawArgs: JSON.stringify({
              __kovoToolArgsParseError: { message: 'Unexpected end of JSON input', truncated: true, rawLength: 9100 },
            }),
          },
        ]))
      } else {
        res.end(responsesSseTurn([
          { id: 'call_done', name: 'complete_intent', rawArgs: JSON.stringify({ status: 'ruled_out', summary: 'Recovered after malformed JSON diagnostic.' }) },
        ]))
      }
    })
  }).listen(0, '127.0.0.1')
  t.after(() => new Promise<void>(r => { server.closeAllConnections(); server.close(() => r()) }))
  await once(server, 'listening')
  const port = (server.address() as AddressInfo).port

  const profile: ResolvedModelProfile = {
    id: 'mock-q2-malformed',
    name: 'Mock Q2 Malformed',
    endpoint: `http://127.0.0.1:${port}/v1`,
    model: 'mock-model',
    protocol: 'responses',
    key: 'test-key-q2',
    priority: 1,
    enabled: true,
    contextWindow: 128_000,
    maxTokens: 2048,
    thinkingLevel: 'off',
    roleAffinity: 'any',
    inputCostPerMtok: 0,
    cachedInputCostPerMtok: 0,
    outputCostPerMtok: 0,
    healthState: 'closed',
    cooldownUntil: null,
    lastError: null,
  }

  const traceDir = join(root, 'trace-dir')
  const trace = createAgentTrace({ dir: traceDir, manifest: { app: 'q2-malformed-test', mode: 'unit' } })
  const res = await runAgentSession({
    directory: join(root, 'malformed-session'),
    sessionId: `sess-q2-mal-${randomUUID().slice(0, 6)}`,
    requestId: 'req-q2-mal',
    profiles: [profile],
    scenario: 'worker-investigation',
    prompt: 'Test malformed tool call recovery.',
    signal: AbortSignal.timeout(10_000),
    maxTurns: 4,
    reposDir,
    trace,
    handlers: {
      complete_intent: async () => ({ recorded: true }),
    },
  })

  assert.equal(res.status, 'completed')
  assert.ok(seenModelInputs.length >= 2)
  assert.match(seenModelInputs[1]!, /truncated\/malformed JSON \(9100 chars\)/i)
  const traceLines = readFileSync(join(traceDir, 'events.jsonl'), 'utf8').trim().split('\n').map(l => JSON.parse(l) as Record<string, unknown>)
  const malformedEvent = traceLines.find(e => e.type === 'tool_result' && e.name === 'read_repo_file')
  assert.ok(malformedEvent, 'Trace must record tool_result for malformed read_repo_file call')
  assert.equal(malformedEvent.errorCode, 'malformed_tool_args')
})

// ---------------------------------------------------------------------------
// 6. worker/bridge.ts just-bash timeout alignment + anti-contamination + zero raw dynamic RegExp
// ---------------------------------------------------------------------------
test('Q2.6: worker/bridge.ts aligns just-bash maxExecutionTimeMs with bounded timeoutMs and preserves safety invariants', () => {
  const bridgeSrc = readFileSync(join(REPO_ROOT, 'worker/bridge.ts'), 'utf8')
  assert.match(bridgeSrc, /MAX_EXEC_TIMEOUT_MS\s*=\s*120_000/)
  assert.match(bridgeSrc, /function clampExecTimeoutMs/)
  assert.match(bridgeSrc, /executionLimitProfile:\s*'hardened'/)
  assert.match(bridgeSrc, /executionLimits:\s*\{\s*maxExecutionTimeMs:\s*boundedExecutionTimeMs\s*,?\s*\}/)
  assert.match(bridgeSrc, /createSandbox\(effectiveTimeoutMs\)/)
  assert.match(bridgeSrc, /createSandbox\(MAX_EXEC_TIMEOUT_MS\)/)

  // Verify zero unguarded `new RegExp(` added in agent-session.ts (regex search goes strictly through safe-regex.ts).
  const sessionSrc = readFileSync(join(REPO_ROOT, 'src/server/agent-session.ts'), 'utf8')
  assert.equal(/\bnew\s+RegExp\s*\(/.test(sessionSrc), false, 'agent-session.ts must not use raw dynamic new RegExp()')
  assert.ok(sessionSrc.includes('compileSafeClaimRegex('), 'search_repo regex mode must route through compileSafeClaimRegex')

  // Zero benchmark contamination across src/server/ and worker/.
  const scan = scanSourceTreeForContamination(REPO_ROOT)
  assert.equal(scan.ok, true, `v8 contamination detected: ${JSON.stringify(scan.hits)}`)
})
