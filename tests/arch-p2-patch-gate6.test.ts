/**
 * Move P2 — Patch Gate-6 unblock, H-5 envelopeTrust, strict syntax/AST & context windowing,
 * braceless/Python caller-break FP fixes, live-container vs disk rollback consistency,
 * and H-39 sensitive repo entry enforcement.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import type { Finding } from '../src/domain.ts'
import type { DeclarativeReplaySpec } from '../src/replay-spec.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { applyUnifiedDiffToDirectory } from '../src/server/lab-runner.ts'
import type { LabRunner } from '../src/server/lab-runner.ts'
import {
  buildUnifiedDiffFromSnippet,
  copyRepoTreeWithoutSymlinks,
  deriveGate6EnvelopeTrust,
  detectUnconditionalCallerBreak,
  extractFocusedFileContext,
  generateAndReviewPatch,
  runPatchAuthor,
  runPatchReviewer,
  synthesizeGate6BaselineCaller,
  verifyPatchApplicability,
  verifyStaticAstPostPatch,
} from '../src/server/patch-workflow.ts'
import { Store } from '../src/server/store.ts'
import { invertUnifiedDiff, parseUnifiedDiff } from '../src/server/unified-diff.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

function makeTempDir(prefix: string, t: { after: (fn: () => void) => void }): string {
  const dir = mkdtempSync(join(tmpdir(), `kovo-p2-${prefix}-`))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function makeGrant(origin: string): Grant {
  return {
    origin,
    tier: 2,
    allowLocalLab: true,
    canRead: o => o === origin,
    audit: () => {},
    personas: new Map([
      ['alice', { id: 'p-alice', handle: 'alice', roleLabel: 'member org-a', originAllowlist: [origin], authKind: 'bearer', headerName: 'Authorization', secret: 'Bearer tok-alice', canaryMarkers: [] }],
      ['bob', { id: 'p-bob', handle: 'bob', roleLabel: 'member org-b', originAllowlist: [origin], authKind: 'bearer', headerName: 'Authorization', secret: 'Bearer tok-bob', canaryMarkers: [] }],
      ['guest', { id: 'p-guest', handle: 'guest', roleLabel: 'viewer org-c', originAllowlist: [origin], authKind: 'bearer', headerName: 'Authorization', secret: 'Bearer tok-guest', canaryMarkers: [] }],
    ]),
  }
}

function enableLocalLabEnv(t: { after: (fn: () => void) => void }): void {
  const prev = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prev === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prev
  })
}

function makeStoreWithRun(t: { after: (fn: () => void) => void }, origin: string) {
  enableLocalLabEnv(t)
  const dataDir = makeTempDir('store', t)
  const storage = new Store(dataDir)
  t.after(() => storage.close())
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'Arch P2 Test Project',
    seeds: [origin],
    environment: 'local-lab',
  })
  const run = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify Arch P2 Gate-6 patch workflow',
    sourceMode: 'public',
    capabilityTier: 2,
    budgetUsd: 5,
    budgetRequests: 50,
    maxRpsPerOrigin: 10,
    workerConcurrency: 1,
    workerMaxTurns: 5,
  })
  storage.command({ requestId: randomUUID(), runId: run.id, action: 'discover', consent: true })
  const asset = storage.run(run.id).candidates[0]!
  storage.command({
    requestId: randomUUID(),
    runId: run.id,
    action: 'scope',
    expectedScopeRevision: 0,
    assetIds: [asset.id],
    consent: true,
    capabilityTier: 2,
  })
  const hydratedRun = storage.run(run.id)
  const worker = storage.makeWorker(hydratedRun, 'investigation', asset, 'Probe', 'Arch P2 worker')
  return { storage, project, run: hydratedRun, worker }
}

function makeFinding(origin: string, repo: string, file: string, extra: Partial<Finding & { codeLocations?: Array<{ repo: string; file: string; startLine: number; endLine: number }> }> = {}): Finding & { codeLocations?: Array<{ repo: string; file: string; startLine: number; endLine: number }> } {
  return {
    id: `finding-${randomUUID().slice(0, 8)}`,
    origin,
    title: 'Missing authorization check on invoice endpoint',
    cwe: 'CWE-639',
    category: 'broken-access-control',
    severity: 'high',
    status: 'confirmed',
    reason: 'Foreign tenant can read owner invoice.',
    remediation: 'Verify invoice.ownerId === req.user.id.',
    evidenceIds: [],
    scopeRevision: 1,
    codeLocations: [{ repo, file, startLine: 2, endLine: 2 }],
    ...extra,
  }
}

function makeApproveReviewer(enforcingLocation: string) {
  return async () => JSON.stringify({
    approved: true,
    callerCompatibility: 'attacker_only',
    enforcingLocation,
    gates: {
      applicability: { passed: true, detail: 'Applies cleanly.' },
      security_closure: { passed: true, detail: 'Enforces tenant ownership.', enforcingLocation },
      sibling_coverage: { passed: true, detail: 'All siblings covered.' },
      caller_compatibility: { passed: true, detail: 'Authorized callers preserved.' },
      repo_conventions: { passed: true, detail: 'Idiomatic.' },
    },
    reviewNotes: 'Statically approved.',
  })
}

function stubBackend(onRun?: () => void): WorkerBackend {
  return {
    async run() {
      onRun?.()
      return { exitCode: 0, stdout: 'syntax-ok\n', stderr: '', outputs: {}, durationMs: 1, timedOut: false }
    },
    async openSession() { throw new Error('unused') },
    async verifyStaticAst() {
      return { verified: true, engine: 'ast-grep', repo: 'svc', file: 'src/app.ts', startLine: 1, endLine: 1, matchedLines: [], codeExcerpt: '', matchCount: 0, durationMs: 1 }
    },
  }
}

function makeAccessBoundaryRecipeSpec(origin: string): DeclarativeReplaySpec {
  return {
    version: 1,
    kind: 'http_chain',
    origin,
    title: 'Cross-tenant invoice read',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Reads another tenant record.',
    impact: 'Unauthorized disclosure of foreign invoice.',
    remediation: 'Enforce owner check.',
    recheckInstructions: 'Replay recipe.',
    assertionsJq: '.steps | length > 0',
    spaCatchallControl: false,
    recipe: {
      recipeId: 'access_boundary',
      args: {
        origin,
        method: 'GET',
        pathAndQuery: '/api/invoices/101',
        vulnClass: 'bola',
        owner: { handle: 'alice', role: 'member', tenant: 'org-a', auth: 'bearer', sameSite: null },
        probe: { handle: 'bob', role: 'member', tenant: 'org-b', auth: 'bearer', sameSite: null },
        denied: { handle: 'guest', role: 'viewer', tenant: 'org-c', auth: 'bearer', sameSite: null },
      },
    },
    steps: [
      { id: 'c1', role: 'control', description: 'owner read', request: { origin, method: 'GET', pathAndQuery: '/api/invoices/101', persona: 'alice', followRedirects: false } },
      { id: 'p1', role: 'probe', description: 'foreign read', request: { origin, method: 'GET', pathAndQuery: '/api/invoices/101', persona: 'bob', followRedirects: false } },
    ],
  }
}

// ============================================================================
// 1. Gate-6 Unblock for kovo_verify (agentScript) & FloorRecipeEnvelope Findings
// ============================================================================

test('P2-1a: synthesizeGate6BaselineCaller derives safe read-only baselines for kovo_verify, FloorRecipeEnvelope, sql_*, browser_chain, and Phase-0 exchanges', (t) => {
  const origin = 'http://127.0.0.1:4410'
  const grant = makeGrant(origin)
  const { storage, run, worker } = makeStoreWithRun(t, origin)

  // Record a mutating POST (must be skipped!), a probe-y GET with SQL metachars (must be skipped!),
  // and a clean benign 200 GET control exchange from kovo_verify receipt.
  const exBase = {
    runId: run.id,
    assignmentId: worker.id,
    scopeRevision: run.scopeRevision,
    origin,
    finalOrigin: origin,
    redirectOrigins: [] as string[],
    mediaType: 'application/json',
    reqHeaders: {},
    respHeaders: {},
    durationMs: 5,
  }
  const exMutate = storage.recordExchange({
    ...exBase,
    method: 'POST',
    pathAndQuery: '/api/invoices/101/approve',
    status: 200,
    personaHandle: 'alice',
    body: '{"ok":true}',
  })
  const exProbe = storage.recordExchange({
    ...exBase,
    method: 'GET',
    pathAndQuery: "/api/invoices/101?q=' OR 1=1 --",
    status: 200,
    personaHandle: 'bob',
    body: '{"rows":[]}',
  })
  const exBenign = storage.recordExchange({
    ...exBase,
    method: 'GET',
    pathAndQuery: '/api/invoices/101',
    status: 200,
    personaHandle: 'alice',
    body: '{"id":101,"owner":"alice"}',
  })

  const agentSpec: DeclarativeReplaySpec = {
    version: 1,
    kind: 'race_burst',
    origin,
    title: 'Agent-script verified bug',
    category: 'broken-access-control',
    cwe: 'CWE-639',
    severity: 'high',
    severityRationale: 'Confirmed by kovo_verify.',
    impact: 'Unauthorized access.',
    remediation: 'Enforce check.',
    recheckInstructions: 'Re-run kovo_verify.',
    assertionsJq: 'true',
    burst: [
      { origin, method: 'POST', pathAndQuery: '/api/invoices/101/approve', persona: 'bob', followRedirects: false },
      { origin, method: 'POST', pathAndQuery: '/api/invoices/101/approve', persona: 'bob', followRedirects: false },
    ],
    agentScript: {
      kind: 'agent_script',
      runtime: 'ts',
      script: 'console.log("ok")',
      scriptSha256: 'a'.repeat(64),
      verdict: 'confirmed',
      vulnClass: 'bola',
      exchangeIds: [exMutate.id, exProbe.id, exBenign.id],
      transcriptDigests: [],
      confirmedAt: Date.now(),
    },
  }

  const fromReceipt = synthesizeGate6BaselineCaller({
    replaySpec: agentSpec,
    finding: makeFinding(origin, 'svc', 'src/app.ts'),
    storage,
    runId: run.id,
    grant,
  })
  assert.ok(fromReceipt, 'kovo_verify finding must synthesize baseline from cited benign GET exchange')
  assert.equal(fromReceipt.source, 'receipt_exchange')
  assert.equal(fromReceipt.caller.method, 'GET')
  assert.equal(fromReceipt.caller.pathAndQuery, '/api/invoices/101')
  assert.equal(fromReceipt.caller.persona, 'alice')

  // Phase-0 fallback when agentScript only cited a mutating POST.
  const mutateOnlyAgentSpec: DeclarativeReplaySpec = {
    ...agentSpec,
    agentScript: { ...agentSpec.agentScript!, exchangeIds: [exMutate.id] },
  }
  const fromPhase0 = synthesizeGate6BaselineCaller({
    replaySpec: mutateOnlyAgentSpec,
    finding: makeFinding(origin, 'svc', 'src/app.ts'),
    storage,
    runId: run.id,
    grant,
  })
  assert.ok(fromPhase0, 'must fall back to Phase-0 benign 2xx GET exchange when cited exchanges are mutating')
  assert.equal(fromPhase0.source, 'phase0_exchange')
  assert.equal(fromPhase0.caller.method, 'GET')
  assert.equal(fromPhase0.caller.pathAndQuery, '/api/invoices/101')

  // FloorRecipeEnvelope persisted_mutation (POST mutation + GET readback -> picks GET readback, never POST!).
  const mutationRecipeSpec: DeclarativeReplaySpec = {
    ...makeAccessBoundaryRecipeSpec(origin),
    recipe: {
      recipeId: 'persisted_mutation',
      args: {
        origin,
        method: 'POST',
        pathAndQuery: '/api/profile/update',
        readbackMethod: 'GET',
        readbackPathAndQuery: '/api/profile',
        vulnClass: 'mass_assignment',
        actor: { handle: 'alice', role: 'member', tenant: 'org-a', auth: 'bearer', sameSite: null },
        body: { role: 'admin' },
      },
    },
  }
  const fromRecipe = synthesizeGate6BaselineCaller({ replaySpec: mutationRecipeSpec, grant })
  assert.ok(fromRecipe)
  assert.equal(fromRecipe.source, 'recipe_control')
  assert.equal(fromRecipe.caller.method, 'GET')
  assert.equal(fromRecipe.caller.pathAndQuery, '/api/profile')
  assert.equal(fromRecipe.caller.persona, 'alice')

  // sql_boolean_diff (non-http_chain declarative spec) -> synthesizes GET baseline cleanly.
  const sqlSpec: DeclarativeReplaySpec = {
    version: 1,
    kind: 'sql_boolean_diff',
    origin,
    targetOrigin: origin,
    method: 'GET',
    pathAndQuery: '/api/search?q=widget',
    paramName: 'q',
    paramLocation: 'query',
    baselineValue: 'widget',
    quoteStyle: 'single',
    persona: 'alice',
    title: 'SQL injection',
    category: 'injection-input',
    cwe: 'CWE-89',
    severity: 'high',
    severityRationale: 'Boolean differential confirmed.',
    impact: 'Data disclosure.',
    remediation: 'Use parameterized query.',
    recheckInstructions: 'Replay.',
    assertionsJq: 'true',
  }
  const fromSql = synthesizeGate6BaselineCaller({ replaySpec: sqlSpec, grant })
  assert.ok(fromSql)
  assert.equal(fromSql.source, 'spec_control')
  assert.equal(fromSql.caller.method, 'GET')
  assert.equal(fromSql.caller.pathAndQuery, '/api/search?q=widget')

  // Fail-closed when NO safe read-only baseline exists (POST-only race_burst with no storage).
  const postOnlyRace: DeclarativeReplaySpec = {
    version: 1,
    kind: 'race_burst',
    origin,
    title: 'Race condition',
    category: 'business-logic',
    cwe: 'CWE-362',
    severity: 'high',
    severityRationale: 'Double spend.',
    impact: 'Balance corruption.',
    remediation: 'Use row lock.',
    recheckInstructions: 'Replay.',
    assertionsJq: 'true',
    burst: [
      { origin, method: 'POST', pathAndQuery: '/api/redeem', persona: 'alice', followRedirects: false },
      { origin, method: 'POST', pathAndQuery: '/api/redeem', persona: 'alice', followRedirects: false },
    ],
  }
  assert.equal(synthesizeGate6BaselineCaller({ replaySpec: postOnlyRace, grant }), null)
})

test('P2-1b: Gate-6 unblocks recipe-backed finding without explicit baselineCaller AND enforces H-5 envelopeTrust', async (t) => {
  const origin = 'http://127.0.0.1:4411'
  const reposDir = makeTempDir('g6-repos', t)
  const repoDir = join(reposDir, 'svc')
  const liveDir = makeTempDir('g6-live', t)
  mkdirSync(join(repoDir, 'src'), { recursive: true })
  mkdirSync(join(liveDir, 'src'), { recursive: true })
  const vulnCode = 'export function getInvoice(ownerId: string, userId: string) {\n  return { ok: true, ownerId }\n}\n'
  writeFileSync(join(repoDir, 'src/invoices.ts'), vulnCode)
  writeFileSync(join(liveDir, 'src/invoices.ts'), vulnCode)

  const { storage, run, worker } = makeStoreWithRun(t, origin)
  const recipeSpec = makeAccessBoundaryRecipeSpec(origin)
  const findingId = `finding-${randomUUID().slice(0, 8)}`
  const persistedSpec = storage.createReplaySpec(run, worker, findingId, recipeSpec, [origin])

  // Patched server: owner (alice) gets 200, foreign probe (bob) & denied (guest) get 403!
  const broker = new RequestBroker({
    rejectUnauthorized: false,
    transport: async (_url, _addr, _sig, options) => {
      const auth = Object.entries(options?.headers ?? {}).find(([k]) => k.toLowerCase() === 'authorization')?.[1] ?? ''
      if (auth.includes('tok-alice')) {
        return { status: 200, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id: 101, owner: 'alice' }) }
      }
      return { status: 403, headers: { 'content-type': 'application/json' }, body: JSON.stringify({ error: 'forbidden' }) }
    },
  })

  const mockLabRunner = {
    rebuildWithPatch: async (_runId: string, diff: string) => {
      applyUnifiedDiffToDirectory(liveDir, diff)
      return {
        targetId: 't1', origin, containerName: 'c1', containerNames: ['c1'], containerIp: '127.0.0.1',
        internalPort: 4411, healthPath: '/health', networkName: 'net', imageName: 'img',
        sanitizedRepoDir: liveDir, telemetryDir: liveDir, startedAt: Date.now(),
      }
    },
  } as unknown as LabRunner

  // 1) NO explicit baselineCaller, persisted replaySpecId in storage -> derives envelopeTrust: 'host_persisted'
  //    and synthesizes GET /api/invoices/101 as alice -> Gate 6 PASSES!
  const finding = makeFinding(origin, 'svc', 'src/invoices.ts', { replaySpecId: persistedSpec.id })
  assert.equal(deriveGate6EnvelopeTrust({ storage, runId: run.id }, finding), 'host_persisted')
  assert.equal(deriveGate6EnvelopeTrust({ storage, runId: run.id, replaySpecId: 'nonexistent-spec-id' }), 'untrusted')
  assert.equal(deriveGate6EnvelopeTrust({ envelopeTrust: 'untrusted', storage, runId: run.id }, finding), 'untrusted')

  const okRes = await generateAndReviewPatch({
    runId: run.id,
    finding,
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerId }',
      fixAfter: '  if (ownerId !== userId) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerId }',
      codeLocations: [{ repo: 'svc', file: 'src/invoices.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce owner check.',
    },
    reviewerLlmCall: makeApproveReviewer('src/invoices.ts:2'),
    labRetest: {
      labRunner: mockLabRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: recipeSpec,
      broker,
      backend: stubBackend(),
      grant: makeGrant(origin),
      storage,
      // Explicitly omitted baselineCaller & envelopeTrust — both synthesized/derived!
    },
  })
  assert.equal(okRes.status, 'approved', okRes.reviewNotes)
  assert.equal(okRes.dynamicRetestVerdict, 'fixed')
  assert.equal(okRes.gates.find(g => g.gate === 6)?.passed, true)
  assert.match(okRes.dynamicRetestSummary ?? '', /recipe_control/)
  assert.equal(readFileSync(join(liveDir, 'src/invoices.ts'), 'utf8'), vulnCode, 'clean rollback verified')

  // 2) H-5: Untrusted envelopeTrust MUST cause Gate-6 to fail closed (withheld, never fixed).
  const untrustedRes = await generateAndReviewPatch({
    runId: run.id,
    finding: makeFinding(origin, 'svc', 'src/invoices.ts', { replaySpecId: 'forged-unpersisted-id' }),
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return { ok: true, ownerId }',
      fixAfter: '  if (ownerId !== userId) return { ok: false, error: "forbidden" }\n  return { ok: true, ownerId }',
      codeLocations: [{ repo: 'svc', file: 'src/invoices.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce owner check.',
    },
    reviewerLlmCall: makeApproveReviewer('src/invoices.ts:2'),
    labRetest: {
      labRunner: mockLabRunner,
      runId: run.id,
      sanitizedRepoDir: liveDir,
      replaySpec: recipeSpec,
      broker,
      backend: stubBackend(),
      grant: makeGrant(origin),
      storage,
    },
  })
  assert.equal(untrustedRes.status, 'withheld', 'unpersisted replaySpecId must derive untrusted and fail closed')
  assert.equal(untrustedRes.gates.find(g => g.gate === 6)?.passed, false)
})

// ============================================================================
// 2. Strict Syntax/AST Check (No False-Green), Context Windowing, Dedup & Caller-Break
// ============================================================================

test('P2-2a: syntax check rejects broken TS without tsconfig even with stub backend and refuses false-green on missing toolchain', async (t) => {
  const reposDir = makeTempDir('syntax-repos', t)
  const repoDir = join(reposDir, 'app')
  mkdirSync(join(repoDir, 'src'), { recursive: true })
  writeFileSync(join(repoDir, 'src/handler.ts'), 'export function ok(a: number) {\n  return a + 1\n}\n')
  writeFileSync(join(repoDir, 'src/main.go'), 'package main\nfunc main() {\n\tprintln("hi")\n}\n')

  // Broken TS syntax with NO tsconfig.json AND a stub backend returning exitCode 0 -> MUST FAIL!
  const brokenTsDiff = [
    '--- a/src/handler.ts',
    '+++ b/src/handler.ts',
    '@@ -1,3 +1,3 @@',
    ' export function ok(a: number) {',
    '-  return a + 1',
    '+  if (!a { return (((',
    ' }',
    '',
  ].join('\n')
  const brokenRes = await verifyPatchApplicability({
    repoRoot: repoDir,
    repo: 'app',
    reposDir,
    diff: brokenTsDiff,
    fixBefore: '  return a + 1',
    fixAfter: '  if (!a { return (((',
    codeLocations: [{ repo: 'app', file: 'src/handler.ts', startLine: 2, endLine: 2 }],
    backend: stubBackend(),
  })
  assert.equal(brokenRes.applicable, true)
  assert.equal(brokenRes.syntaxCheck.passed, false, 'broken TS without tsconfig must NEVER pass false-green')
  assert.match(brokenRes.syntaxCheck.output ?? '', /syntax error/i)

  // Missing external Go toolchain (`KOVO_SYNTAX_UNAVAILABLE:go:src/main.go`) with exitCode 0 -> MUST NOT pass false-green!
  const validGoDiff = [
    '--- a/src/main.go',
    '+++ b/src/main.go',
    '@@ -1,4 +1,4 @@',
    ' package main',
    ' func main() {',
    '-\tprintln("hi")',
    '+\tprintln("secured")',
    ' }',
    '',
  ].join('\n')
  const missingGoBackend: WorkerBackend = {
    async run() {
      return { exitCode: 0, stdout: 'KOVO_SYNTAX_UNAVAILABLE:go:src/main.go\n', stderr: '', outputs: {}, durationMs: 1, timedOut: false }
    },
    async openSession() { throw new Error('unused') },
    async verifyStaticAst() { throw new Error('unused') },
  }
  const goRes = await verifyPatchApplicability({
    repoRoot: repoDir,
    repo: 'app',
    reposDir,
    diff: validGoDiff,
    fixBefore: '\tprintln("hi")',
    fixAfter: '\tprintln("secured")',
    codeLocations: [{ repo: 'app', file: 'src/main.go', startLine: 3, endLine: 3 }],
    backend: missingGoBackend,
  })
  assert.equal(goRes.syntaxCheck.passed, false, 'missing go toolchain must NEVER report passed: true')
  assert.equal(goRes.syntaxCheck.toolchainUnavailable, true)
  assert.match(goRes.syntaxCheck.output ?? '', /toolchain_unavailable/i)

  // Unbalanced Python delimiters caught directly by verifyStaticAstPostPatch.
  const pyWork = makeTempDir('py-ast', t)
  writeFileSync(join(pyWork, 'broken.py'), 'def check(x):\n    return (x + 1\n')
  const pyAst = verifyStaticAstPostPatch(pyWork, ['broken.py'])
  assert.equal(pyAst.ok, false)
  assert.match(pyAst.issues[0] ?? '', /unclosed delimiter/i)
})

test('P2-2b: extractFocusedFileContext preserves deep function context beyond 16KB, deduplicates Stage 1->2 applicability, and handles hintStartLine/mid-line diffs', async (t) => {
  const reposDir = makeTempDir('ctx-repos', t)
  const repoDir = join(reposDir, 'svc')
  mkdirSync(join(repoDir, 'src'), { recursive: true })

  // Build a > 55 KB file (~1,100 lines) with the vulnerable handler around line 980.
  const filler = Array.from({ length: 970 }, (_, i) => `export const fillerConst_${i} = "${'x'.repeat(40)}_${i}"`).join('\n')
  const deepHandler = [
    'export function sensitiveBillingHandler(req: { userId: string }, record: { ownerId: string }) {',
    '  return record',
    '}',
  ].join('\n')
  const bigFile = `import { auth } from './auth'\n${filler}\n${deepHandler}\n`
  assert.ok(bigFile.length > 50_000)
  writeFileSync(join(repoDir, 'src/big.ts'), bigFile)
  writeFileSync(join(repoDir, 'src/sibling.ts'), 'export function siblingBillingHandler() { return sensitiveBillingHandler }\n')

  const excerpt = extractFocusedFileContext(repoDir, 'src/big.ts', [{ startLine: 972, endLine: 975 }])
  assert.equal(excerpt.truncated, true)
  assert.ok(excerpt.content?.includes('import { auth }'), 'header imports preserved')
  assert.ok(excerpt.content?.includes('sensitiveBillingHandler'), 'deep target function preserved instead of byte-0 truncation')

  // Verify Stage 1 -> Stage 2 deduplication (backend.run called ONCE, not twice) AND reviewer receives deep context + siblingHints.
  let backendCalls = 0
  let capturedReviewerPrompt = ''
  const res = await generateAndReviewPatch({
    runId: 'run-dedup',
    finding: makeFinding('http://127.0.0.1:4412', 'svc', 'src/big.ts', {
      codeLocations: [{ repo: 'svc', file: 'src/big.ts', startLine: 973, endLine: 973, label: 'sensitiveBillingHandler' }],
    }),
    repo: 'svc',
    reposDir,
    backend: stubBackend(() => { backendCalls += 1 }),
    candidatePatch: {
      fixBefore: '  return record',
      fixAfter: '  if (record.ownerId !== req.userId) return null\n  return record',
      codeLocations: [{ repo: 'svc', file: 'src/big.ts', startLine: 973, endLine: 973, label: 'sensitiveBillingHandler' }],
      rationale: 'Check ownerId.',
    },
    reviewerLlmCall: async ({ userPrompt }) => {
      capturedReviewerPrompt = userPrompt
      return makeApproveReviewer('src/big.ts:973')()
    },
  })
  assert.equal(res.status, 'approved', res.reviewNotes)
  assert.equal(backendCalls, 1, 'Stage 2 must reuse Stage 1 applicability instead of re-running backend syntax check')
  assert.ok(capturedReviewerPrompt.includes('sensitiveBillingHandler'), 'reviewer prompt must include deep target function')
  assert.ok(capturedReviewerPrompt.includes('src/sibling.ts'), 'reviewer prompt must include siblingHints')

  // buildUnifiedDiffFromSnippet: hintStartLine disambiguates repeated snippet + mid-line replacement parses cleanly!
  const repeated = 'const a = getVal()\nconst b = 1\nconst c = getVal()\n'
  const built = buildUnifiedDiffFromSnippet('src/rep.ts', repeated, 'getVal()', 'getSafeVal()', 3)
  assert.equal(built.startLine, 3)
  const parsed = parseUnifiedDiff(built.diff)
  assert.equal(parsed.length, 1)
  assert.match(built.diff, /^-const c = getVal\(\)$/m)
  assert.match(built.diff, /^\+const c = getSafeVal\(\)$/m)
})

test('P2-2c: detectUnconditionalCallerBreak avoids braceless/Python FPs while still catching unconditional blocks', () => {
  // Python indented guard -> NOT a caller break!
  const pyGuard = [
    '--- a/app/views.py',
    '+++ b/app/views.py',
    '@@ -1,3 +1,5 @@',
    ' def get_invoice(req, inv):',
    '+    if inv.owner_id != req.user.id:',
    '+        return Response("forbidden", status=403)',
    '     return inv.to_dict()',
    '',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(pyGuard), false, 'Python indented if guard must not FP')

  const pyRaiseGuard = [
    '--- a/app/views.py',
    '+++ b/app/views.py',
    '@@ -1,3 +1,5 @@',
    ' def get_invoice(req, inv):',
    '+    if not req.user.is_admin:',
    '+        raise HTTPException(status_code=403)',
    '     return inv.to_dict()',
    '',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(pyRaiseGuard), false, 'Python indented raise HTTPException guard must not FP')

  // Braceless 2-line JS/TS if guard -> NOT a caller break!
  const bracelessJs = [
    '--- a/src/routes.ts',
    '+++ b/src/routes.ts',
    '@@ -1,3 +1,5 @@',
    ' app.get("/orders", (req, res) => {',
    '+  if (!req.user)',
    '+    return res.status(403).end()',
    '   return res.json(orders)',
    ' })',
    '',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(bracelessJs), false, 'braceless 2-line if guard must not FP')

  // Multiline parenthesized braceless if guard -> NOT a caller break!
  const multilineBraceless = [
    '--- a/src/routes.ts',
    '+++ b/src/routes.ts',
    '@@ -1,3 +1,7 @@',
    ' app.get("/orders", (req, res) => {',
    '+  if (',
    '+    !req.user ||',
    '+    req.user.tenant !== order.tenant',
    '+  )',
    '+    return res.status(403).end()',
    '   return res.json(orders)',
    ' })',
    '',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(multilineBraceless), false, 'multiline braceless if guard must not FP')

  // True unconditional blocks MUST still be flagged!
  const pyUncond = [
    '--- a/app/views.py',
    '+++ b/app/views.py',
    '@@ -1,2 +1,3 @@',
    ' def get_invoice(req, inv):',
    '+    raise HTTPException(status_code=403)',
    '     return inv.to_dict()',
    '',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(pyUncond), true, 'Python top-level unconditional raise must be flagged')

  const alwaysTrueJs = [
    '--- a/src/routes.ts',
    '+++ b/src/routes.ts',
    '@@ -1,2 +1,3 @@',
    ' app.get("/orders", (req, res) => {',
    '+  if (true) return res.status(403).end()',
    '   return res.json(orders)',
    ' })',
    '',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(alwaysTrueJs), true, 'if (true) must be flagged')

  const alwaysTruePy = [
    '--- a/app/views.py',
    '+++ b/app/views.py',
    '@@ -1,2 +1,4 @@',
    ' def get_invoice(req, inv):',
    '+    if True:',
    '+        return Response("forbidden", status=403)',
    '     return inv.to_dict()',
    '',
  ].join('\n')
  assert.equal(detectUnconditionalCallerBreak(alwaysTruePy), true, 'Python if True: must be flagged')
})

// ============================================================================
// 3. Live-Container vs Disk Rollback Consistency (No Desync / Stale Patched Files)
// ============================================================================

test('P2-3: Gate-6 recovers from reverse-diff rollback failure by restoring snapshot + rebuilding clean container, and never swallows permanent rollback failure', async (t) => {
  enableLocalLabEnv(t)
  const origin = 'http://127.0.0.1:4413'
  const reposDir = makeTempDir('rb-repos', t)
  const repoDir = join(reposDir, 'svc')
  const liveDir = makeTempDir('rb-live', t)
  mkdirSync(join(repoDir, 'src'), { recursive: true })
  mkdirSync(join(liveDir, 'src'), { recursive: true })
  const cleanCode = 'export function handle(ok: boolean) {\n  return 200\n}\n'
  writeFileSync(join(repoDir, 'src/handler.ts'), cleanCode)
  writeFileSync(join(liveDir, 'src/handler.ts'), cleanCode)

  const recipeSpec = makeAccessBoundaryRecipeSpec(origin)
  const makeBroker = () => new RequestBroker({
    rejectUnauthorized: false,
    transport: async (_url, _addr, _sig, options) => {
      const auth = Object.entries(options?.headers ?? {}).find(([k]) => k.toLowerCase() === 'authorization')?.[1] ?? ''
      return auth.includes('tok-alice')
        ? { status: 200, headers: { 'content-type': 'application/json' }, body: '{"id":101,"owner":"alice"}' }
        : { status: 403, headers: { 'content-type': 'application/json' }, body: '{"error":"forbidden"}' }
    },
  })

  // Case A: First rollback (reverseDiff) fails because runtime dirtied liveDir; recovery restores
  // snapshot from backupDir and rebuilds live container with clean identity diff -> BOTH container & disk clean!
  let containerCode = cleanCode
  let rebuildCount = 0
  const recoveringRunner = {
    rebuildWithPatch: async (_runId: string, diff: string) => {
      rebuildCount += 1
      if (rebuildCount === 1) {
        applyUnifiedDiffToDirectory(liveDir, diff)
        containerCode = readFileSync(join(liveDir, 'src/handler.ts'), 'utf8')
        // Simulate runtime side-effect dirtying the file so reverseDiff won't apply cleanly!
        writeFileSync(join(liveDir, 'src/handler.ts'), '// drifted runtime state\n')
      } else if (rebuildCount === 2) {
        // Applying reverseDiff against drifted file throws!
        applyUnifiedDiffToDirectory(liveDir, diff)
      } else {
        // Recovery rebuild on restored clean snapshot with identity diff succeeds!
        applyUnifiedDiffToDirectory(liveDir, diff)
        containerCode = readFileSync(join(liveDir, 'src/handler.ts'), 'utf8')
      }
      return {
        targetId: 't1', origin, containerName: `c${rebuildCount}`, containerNames: [`c${rebuildCount}`],
        containerIp: '127.0.0.1', internalPort: 4413, healthPath: '/health', networkName: 'net', imageName: 'img',
        sanitizedRepoDir: liveDir, telemetryDir: liveDir, startedAt: Date.now(),
      }
    },
  } as unknown as LabRunner

  const recovered = await generateAndReviewPatch({
    runId: 'run-rb-recover',
    finding: makeFinding(origin, 'svc', 'src/handler.ts'),
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return 200',
      fixAfter: '  if (!ok) return 403\n  return 200',
      codeLocations: [{ repo: 'svc', file: 'src/handler.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce guard.',
    },
    reviewerLlmCall: makeApproveReviewer('src/handler.ts:2'),
    labRetest: {
      labRunner: recoveringRunner,
      runId: 'run-rb-recover',
      sanitizedRepoDir: liveDir,
      replaySpec: recipeSpec,
      broker: makeBroker(),
      backend: stubBackend(),
      grant: makeGrant(origin),
    },
  })
  assert.equal(rebuildCount, 3, 'candidate rebuild + failed reverseDiff + snapshot-restored clean identity rebuild')
  assert.equal(readFileSync(join(liveDir, 'src/handler.ts'), 'utf8'), cleanCode, 'disk must be clean')
  assert.equal(containerCode, cleanCode, 'live container must match clean disk (no desync)')
  assert.equal(recovered.status, 'approved')
  assert.equal(recovered.gates.find(g => g.gate === 6)?.passed, true)

  // Case B: Permanent container rollback failure (both reverseDiff AND recovery rebuild throw) ->
  // MUST NOT swallow silently; Gate-6 fails closed as withheld with explicit rollback desync note!
  let failCall = 0
  const stuckRunner = {
    rebuildWithPatch: async (_runId: string, diff: string) => {
      failCall += 1
      if (failCall === 1) {
        applyUnifiedDiffToDirectory(liveDir, diff)
        return {
          targetId: 't1', origin, containerName: 'c-patched', containerNames: ['c-patched'],
          containerIp: '127.0.0.1', internalPort: 4413, healthPath: '/health', networkName: 'net', imageName: 'img',
          sanitizedRepoDir: liveDir, telemetryDir: liveDir, startedAt: Date.now(),
        }
      }
      throw new Error('docker daemon unavailable during rollback')
    },
  } as unknown as LabRunner

  const desynced = await generateAndReviewPatch({
    runId: 'run-rb-stuck',
    finding: makeFinding(origin, 'svc', 'src/handler.ts'),
    repo: 'svc',
    reposDir,
    candidatePatch: {
      fixBefore: '  return 200',
      fixAfter: '  if (!ok) return 403\n  return 200',
      codeLocations: [{ repo: 'svc', file: 'src/handler.ts', startLine: 2, endLine: 2 }],
      rationale: 'Enforce guard.',
    },
    reviewerLlmCall: makeApproveReviewer('src/handler.ts:2'),
    labRetest: {
      labRunner: stuckRunner,
      runId: 'run-rb-stuck',
      sanitizedRepoDir: liveDir,
      replaySpec: recipeSpec,
      broker: makeBroker(),
      backend: stubBackend(),
      grant: makeGrant(origin),
    },
  })
  assert.equal(desynced.status, 'withheld', 'permanent rollback failure must never silently approve')
  assert.equal(desynced.dynamicRetestVerdict, 'skipped')
  assert.equal(desynced.gates.find(g => g.gate === 6)?.passed, false)
  assert.match(desynced.dynamicRetestSummary ?? '', /rollback desync/i)
})

// ============================================================================
// 4. H-39 Sibling: isSensitiveRepoEntry Enforcement on Author/Reviewer/Applicability
// ============================================================================

test('P2-4: isSensitiveRepoEntry blocks sensitive repo files from Author/Reviewer prompts, applicability diffs, and air-gapped copies', async (t) => {
  const reposDir = makeTempDir('sens-repos', t)
  const repoDir = join(reposDir, 'svc')
  mkdirSync(join(repoDir, 'src'), { recursive: true })
  mkdirSync(join(repoDir, '.ssh'), { recursive: true })
  mkdirSync(join(repoDir, 'credentials'), { recursive: true })

  const SECRET_ENV = 'TOP_SECRET_DATABASE_PASSWORD_XYZ'
  const SECRET_SSH = 'PRIVATE_SSH_KEY_MATERIAL_ABC'
  writeFileSync(join(repoDir, '.env'), `DB_PASS=${SECRET_ENV}\n`)
  writeFileSync(join(repoDir, '.env.example'), 'DB_PASS=changeme\n')
  writeFileSync(join(repoDir, '.ssh/id_rsa'), SECRET_SSH)
  writeFileSync(join(repoDir, 'credentials/api.json'), '{"key":"secret"}')
  writeFileSync(join(repoDir, 'src/app.ts'), 'export const x = 1\n')

  // extractFocusedFileContext refuses sensitive paths while permitting .env.example & normal code.
  assert.equal(extractFocusedFileContext(repoDir, '.env', [{ startLine: 1 }]).content, null)
  assert.equal(extractFocusedFileContext(repoDir, '.ssh/id_rsa', [{ startLine: 1 }]).content, null)
  assert.equal(extractFocusedFileContext(repoDir, 'credentials/api.json', [{ startLine: 1 }]).content, null)
  assert.ok(extractFocusedFileContext(repoDir, '.env.example', [{ startLine: 1 }]).content?.includes('changeme'))

  // runPatchAuthor & runPatchReviewer never leak .env contents into LLM prompts.
  let authorPrompt = ''
  await assert.rejects(() => runPatchAuthor({
    runId: 'run-sens-author',
    finding: makeFinding('http://127.0.0.1:4414', 'svc', '.env', {
      codeLocations: [{ repo: 'svc', file: '.env', startLine: 1, endLine: 1 }],
    }),
    repo: 'svc',
    reposDir,
    authorLlmCall: async ({ userPrompt }) => {
      authorPrompt = userPrompt
      throw new Error('stop after inspecting prompt')
    },
  }))
  assert.equal(authorPrompt.includes(SECRET_ENV), false, 'patch author prompt must never receive .env contents')

  let reviewerPrompt = ''
  await runPatchReviewer({
    finding: makeFinding('http://127.0.0.1:4414', 'svc', 'src/app.ts'),
    repo: 'svc',
    reposDir,
    authorOutput: {
      repo: 'svc',
      coverageInventory: [{ file: '.env', line: 1, symbol: 'DB_PASS', role: 'helper', coveredByPatch: true, notes: 'env' }],
      fixBefore: 'export const x = 1',
      fixAfter: 'export const x = 2',
      diff: '--- a/src/app.ts\n+++ b/src/app.ts\n@@ -1,1 +1,1 @@\n-export const x = 1\n+export const x = 2\n',
      codeLocations: [{ repo: 'svc', file: 'src/app.ts', startLine: 1, endLine: 1 }],
      rationale: 'Update constant.',
      syntaxCheck: { ran: true, passed: true },
    },
    reviewerLlmCall: async ({ userPrompt }) => {
      reviewerPrompt = userPrompt
      return makeApproveReviewer('src/app.ts:1')()
    },
  })
  assert.equal(reviewerPrompt.includes(SECRET_ENV), false, 'patch reviewer prompt must never leak .env contents')
  assert.equal(reviewerPrompt.includes(SECRET_SSH), false, 'patch reviewer prompt must never leak .ssh contents')

  // verifyPatchApplicability rejects diffs targeting sensitive repo paths.
  const envDiff = '--- a/.env\n+++ b/.env\n@@ -1,1 +1,1 @@\n-DB_PASS=TOP_SECRET_DATABASE_PASSWORD_XYZ\n+DB_PASS=patched\n'
  const sensApp = await verifyPatchApplicability({
    repoRoot: repoDir,
    repo: 'svc',
    reposDir,
    diff: envDiff,
    fixBefore: '',
    codeLocations: [],
  })
  assert.equal(sensApp.applicable, false)
  assert.match(sensApp.error ?? '', /sensitive repository path/i)

  // copyRepoTreeWithoutSymlinks with excludeSensitive strips .env/.ssh/credentials while keeping .env.example & src/app.ts.
  const dest = makeTempDir('sens-copy', t)
  copyRepoTreeWithoutSymlinks(repoDir, dest, { excludeSensitive: true })
  assert.equal(existsSync(join(dest, '.env')), false)
  assert.equal(existsSync(join(dest, '.ssh/id_rsa')), false)
  assert.equal(existsSync(join(dest, 'credentials/api.json')), false)
  assert.equal(existsSync(join(dest, '.env.example')), true)
  assert.equal(existsSync(join(dest, 'src/app.ts')), true)
})

// ============================================================================
// 5. invertUnifiedDiff Round-Trip & Anti-Contamination Check
// ============================================================================

test('P2-5: invertUnifiedDiff cleanly inverts modify/create/delete diffs and src/server patch files have zero benchmark literals', (t) => {
  const work = makeTempDir('invert', t)
  mkdirSync(join(work, 'src'), { recursive: true })
  const orig = 'line1\nline2\nline3\n'
  writeFileSync(join(work, 'src/f.ts'), orig)

  const diff = [
    '--- a/src/f.ts',
    '+++ b/src/f.ts',
    '@@ -1,3 +1,3 @@',
    ' line1',
    '-line2',
    '+line2_patched',
    ' line3',
    '--- /dev/null',
    '+++ b/src/new.ts',
    '@@ -0,0 +1,1 @@',
    '+export const added = true',
    '',
  ].join('\n')

  applyUnifiedDiffToDirectory(work, diff)
  assert.equal(existsSync(join(work, 'src/new.ts')), true)
  applyUnifiedDiffToDirectory(work, invertUnifiedDiff(diff))
  assert.equal(readFileSync(join(work, 'src/f.ts'), 'utf8'), orig)
  assert.equal(existsSync(join(work, 'src/new.ts')), false, 'inverted create diff deletes created file')

  const forbidden = [/\bpaygrid\b/i, /\bshipforge\b/i, /\bnexusiam\b/i, /\bconnecthub\b/i, /\b(?:PG|SF|NX|CH)-C\d+\b/, /vault\.internal/i, /registry\.internal/i, /billing\.internal/i, /mh_fake_/i]
  for (const rel of ['src/server/patch-workflow.ts', 'src/server/unified-diff.ts']) {
    const src = readFileSync(join(repoRoot, rel), 'utf8')
    for (const re of forbidden) {
      assert.equal(re.test(src), false, `Benchmark literal matched ${re} in ${rel}`)
    }
  }
})
