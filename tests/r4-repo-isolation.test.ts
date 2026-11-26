import assert from 'node:assert/strict'
import { execFileSync, type ChildProcess } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { EventEmitter } from 'node:events'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PassThrough } from 'node:stream'
import test from 'node:test'
import {
  cleanupOrphanedRepoDirs,
  cloneGithubRepos,
  measureDirectoryBytes,
  projectReposDir,
} from '../src/server/github-repo-sync.ts'
import { runStaticAstProofRecipe } from '../src/server/floor-recipe-engine.ts'
import { runThreeStageSemanticAudit, runVariantSweepForFinding } from '../src/server/semantic-audit.ts'
import {
  LinuxWorkerBackend,
  buildWarmPoolPolicy,
  type DockerRunner,
  type WorkerBackend,
  type WorkerSessionOptions,
} from '../src/server/worker-backend.ts'

function makeTempDir(t: test.TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function runGitSync(cwd: string, args: string[]): string {
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

function createBareOriginRepo(
  workDir: string,
  owner: string,
  repo: string,
  files: Record<string, string | Buffer | { content: string | Buffer; mode?: number }>,
): { originRoot: string; barePath: string } {
  const originRoot = join(workDir, 'git-origin')
  const sourcePath = join(workDir, `src-${owner}-${repo}-${randomUUID().slice(0, 6)}`)
  const barePath = join(originRoot, owner, `${repo}.git`)
  mkdirSync(sourcePath, { recursive: true })
  mkdirSync(join(originRoot, owner), { recursive: true })

  execFileSync('git', ['init', '-b', 'main', sourcePath], { stdio: 'ignore' })
  runGitSync(sourcePath, ['config', 'user.email', 'qa@example.test'])
  runGitSync(sourcePath, ['config', 'user.name', 'QA Bot'])

  for (const [relPath, spec] of Object.entries(files)) {
    const fullPath = join(sourcePath, relPath)
    mkdirSync(join(fullPath, '..'), { recursive: true })
    if (typeof spec === 'string' || Buffer.isBuffer(spec)) {
      writeFileSync(fullPath, spec)
    } else {
      writeFileSync(fullPath, spec.content)
      if (spec.mode !== undefined) chmodSync(fullPath, spec.mode)
    }
  }
  runGitSync(sourcePath, ['add', '-A'])
  runGitSync(sourcePath, ['commit', '-m', 'init'])

  rmSync(barePath, { recursive: true, force: true })
  execFileSync('git', ['clone', '--bare', sourcePath, barePath], { stdio: 'ignore' })
  return { originRoot, barePath }
}

function writeTestPat(dir: string): string {
  const patPath = join(dir, 'test-github.pat')
  writeFileSync(patPath, 'github_pat_11TEST_R4_REPO_ISO_0123456789\n', { mode: 0o600 })
  chmodSync(patPath, 0o600)
  return patPath
}

function makeFakeSessionSpawner(onStop?: Map<string, () => void>) {
  const started: string[] = []
  const spawner = (name: string): ChildProcess => {
    started.push(name)
    const emitter = new EventEmitter() as EventEmitter & {
      stdin: PassThrough
      stdout: PassThrough
      stderr: PassThrough
      kill: () => boolean
    }
    emitter.stdin = new PassThrough()
    emitter.stdout = new PassThrough()
    emitter.stderr = new PassThrough()
    let closed = false
    const finish = () => {
      if (closed) return
      closed = true
      emitter.emit('close', 0)
    }
    emitter.kill = () => { finish(); return true }
    onStop?.set(name, finish)
    return emitter as unknown as ChildProcess
  }
  return { spawner, started }
}

function makeDockerStub(onStop?: Map<string, () => void>) {
  const states = new Map<string, { status: string; instance: string; mountDir?: string }>()
  const created: Array<{ name: string; mountDir?: string; contentAtCreate?: string }> = []
  const startedSnapshots: Array<{ name: string; mountDir?: string; content?: string }> = []

  const runner: DockerRunner = async (args, _signal, input) => {
    const verb = args[0] === 'container' ? args[1] : args[0]
    if (verb === 'create') {
      const name = args[args.indexOf('--name') + 1]!
      const instArg = args.find(a => a.startsWith('dev.kovo.pool_instance=')) ?? ''
      const instance = instArg.slice('dev.kovo.pool_instance='.length)
      const mountArg = args.find(a => a.includes('target=/repos,readonly')) ?? ''
      const match = /^type=bind,source=([^,]+),target=\/repos,readonly$/.exec(mountArg)
      const mountDir = match?.[1]
      const markerPath = mountDir ? join(mountDir, 'acme', 'app', 'handler.ts') : ''
      const contentAtCreate = markerPath && existsSync(markerPath) ? readFileSync(markerPath, 'utf8') : undefined
      states.set(name, { status: 'created', instance, mountDir })
      created.push({ name, mountDir, contentAtCreate })
      return 'created'
    }
    if (verb === 'inspect') {
      const name = args[args.length - 1]!
      const entry = states.get(name)
      if (!entry) throw new Error(`No such container: ${name}`)
      const fmtIdx = args.indexOf('-f')
      const fmt = fmtIdx >= 0 ? args[fmtIdx + 1] ?? '' : ''
      if (fmt.includes('\\t')) return `${entry.status}\t${entry.instance}\n`
      return `${entry.status}\n`
    }
    if (verb === 'stop') {
      const name = args[args.length - 1]!
      const entry = states.get(name)
      if (entry) entry.status = 'exited'
      onStop?.get(name)?.()
      return ''
    }
    if (verb === 'start') {
      const name = args[args.length - 1]!
      const entry = states.get(name)
      const markerPath = entry?.mountDir ? join(entry.mountDir, 'acme', 'app', 'handler.ts') : ''
      const content = markerPath && existsSync(markerPath) ? readFileSync(markerPath, 'utf8') : undefined
      startedSnapshots.push({ name, mountDir: entry?.mountDir, content })
      if (input && input.includes('"ast_verify"')) {
        return JSON.stringify({
          verified: Boolean(content?.includes('VULNERABLE_V1')),
          engine: 'ast-grep',
          repo: 'acme/app',
          file: 'handler.ts',
          startLine: 1,
          endLine: 1,
          matchedLines: content?.includes('VULNERABLE_V1') ? [1] : [],
          codeExcerpt: content ?? '',
          matchCount: content?.includes('VULNERABLE_V1') ? 1 : 0,
          durationMs: 1,
        })
      }
      return JSON.stringify({ exitCode: 0, stdout: content ?? 'ok', stderr: '', outputs: {} })
    }
    if (verb === 'rm') {
      for (const arg of args.slice(args.indexOf('--force') + 1)) states.delete(arg)
      return ''
    }
    return ''
  }
  return { runner, created, startedSnapshots, states }
}

async function waitFor(predicate: () => boolean, label: string, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (predicate()) return
    await new Promise(resolve => setTimeout(resolve, 10))
  }
  assert.fail(`Timed out waiting for: ${label}`)
}

test('R4-H-8: overlapping concurrent policies and host re-sync never mount Run A stale snapshot for Run B', async t => {
  const work = makeTempDir(t, 'kovo-r4-h8-concurrent-')
  const reposDir = join(work, 'repos')
  const appFile = join(reposDir, 'acme', 'app', 'handler.ts')
  mkdirSync(join(reposDir, 'acme', 'app'), { recursive: true, mode: 0o755 })
  writeFileSync(appFile, 'export const state = "VULNERABLE_V1"\n', { mode: 0o644 })

  const stopHooks = new Map<string, () => void>()
  const docker = makeDockerStub(stopHooks)
  const { spawner, started } = makeFakeSessionSpawner(stopHooks)

  const backend = new LinuxWorkerBackend({
    workspace: { id: 'ws-r4-h8', directory: work },
    cell: 'cell-r4-h8',
    dockerRunner: docker.runner,
    sessionSpawner: spawner,
  })
  t.after(() => backend.close())

  const runA = `run-a-${randomUUID().slice(0, 8)}`
  const runB = `run-b-${randomUUID().slice(0, 8)}`
  const policyA = buildWarmPoolPolicy({ runId: runA, reposDir, mountedRepos: ['/repos/acme/app'], image: 'kovo-worker:v4' })
  const policyB = buildWarmPoolPolicy({ runId: runB, reposDir, mountedRepos: ['/repos/acme/app'], image: 'kovo-worker:v4' })

  // 1. Run A installs warm policy and stages VULNERABLE_V1 snapshot.
  backend.setWarmPoolPolicy(policyA, { reposDir })
  await waitFor(() => backend.getWarmPoolStats(policyA)?.idle === 1, 'Run A warm pool ready')
  const runAContainer = docker.created[0]!.name
  const runASnapDir = docker.created[0]!.mountDir!
  assert.equal(docker.created[0]!.contentAtCreate, 'export const state = "VULNERABLE_V1"\n')

  // 2. Host repo is re-synced with the fix (FIXED_V2) while Run A is active.
  writeFileSync(appFile, 'export const state = "FIXED_V2"\n', { mode: 0o644 })

  // 3. Run B installs its warm policy and stages FIXED_V2 snapshot.
  backend.setWarmPoolPolicy(policyB, { reposDir })
  await waitFor(() => backend.getWarmPoolStats(policyB)?.idle === 1, 'Run B warm pool ready')
  const runBContainer = docker.created[1]!.name
  const runBSnapDir = docker.created[1]!.mountDir!
  assert.notEqual(runBSnapDir, runASnapDir)
  assert.equal(docker.created[1]!.contentAtCreate, 'export const state = "FIXED_V2"\n')

  // 4. Run A touches setWarmPoolPolicy again so backend-global activeWarmPoolPolicy flips back to Run A.
  backend.setWarmPoolPolicy(policyA, { reposDir })

  // 5. Run B verifyStaticAst MUST mount Run B's FIXED_V2 snapshot (NEVER Run A's stale VULNERABLE_V1!).
  const astB = await backend.verifyStaticAst(
    'asgn-ast-b',
    {
      repo: 'acme/app',
      file: 'handler.ts',
      startLine: 1,
      endLine: 1,
      engine: 'ast-grep',
      ruleOrPattern: 'VULNERABLE_V1',
    },
    AbortSignal.timeout(5_000),
    { reposDir, runId: runB },
  )
  assert.equal(astB.verified, false, 'Run B verifyStaticAst must see FIXED_V2 and NOT confirm against Run A stale snapshot')
  assert.equal(docker.startedSnapshots.at(-1)?.mountDir, runBSnapDir)

  // 6. Run B backend.run() MUST mount Run B's FIXED_V2 snapshot.
  const runResB = await backend.run(
    { assignmentId: randomUUID(), files: [], command: 'true', outputs: [] },
    AbortSignal.timeout(5_000),
    { reposDir, runId: runB },
  )
  assert.equal(runResB.stdout, 'export const state = "FIXED_V2"\n')
  assert.equal(docker.startedSnapshots.at(-1)?.mountDir, runBSnapDir)

  // 7. Run B openSession with runId (without warmPoolPolicy) MUST take Run B's warm container, NOT Run A's!
  const sessB = await backend.openSession('asgn-sess-b', AbortSignal.timeout(5_000), { reposDir, runId: runB })
  assert.equal(started.at(-1), runBContainer, 'Run B openSession must use Run B warm container, never Run A')
  assert.notEqual(started.at(-1), runAContainer)
  await sessB.close()

  // 8. Mismatched { runId: runB, warmPoolPolicy: policyA } MUST NOT take Run A's container or snapshot!
  const sessMismatch = await backend.openSession('asgn-mismatch', AbortSignal.timeout(5_000), {
    reposDir,
    runId: runB,
    warmPoolPolicy: policyA,
  })
  assert.notEqual(started.at(-1), runAContainer, 'mismatched runId vs warmPoolPolicy must never acquire Run A container')
  assert.equal(docker.created.at(-1)?.mountDir, runBSnapDir, 'mismatched call resolves snapshot from explicit runId=runB')
  await sessMismatch.close()

  // 9. Run A verifyStaticAst STILL reads Run A's own immutable VULNERABLE_V1 snapshot.
  const astA = await backend.verifyStaticAst(
    'asgn-ast-a',
    {
      repo: 'acme/app',
      file: 'handler.ts',
      startLine: 1,
      endLine: 1,
      engine: 'ast-grep',
      ruleOrPattern: 'VULNERABLE_V1',
    },
    AbortSignal.timeout(5_000),
    { reposDir, runId: runA },
  )
  assert.equal(astA.verified, true, 'Run A retains its own immutable V1 snapshot')
  assert.equal(docker.startedSnapshots.at(-1)?.mountDir, runASnapDir)
})

test('R4-H-8: omitted runId and warmPoolPolicy fail closed by staging a private single-call snapshot instead of using activeWarmPoolPolicy', async t => {
  const work = makeTempDir(t, 'kovo-r4-h8-failclosed-')
  const reposDir = join(work, 'repos')
  const appFile = join(reposDir, 'acme', 'app', 'handler.ts')
  mkdirSync(join(reposDir, 'acme', 'app'), { recursive: true, mode: 0o755 })
  writeFileSync(appFile, 'export const state = "VULNERABLE_V1"\n', { mode: 0o644 })

  const stopHooks = new Map<string, () => void>()
  const docker = makeDockerStub(stopHooks)
  const { spawner, started } = makeFakeSessionSpawner(stopHooks)

  const backend = new LinuxWorkerBackend({
    workspace: { id: 'ws-r4-h8-fc', directory: work },
    cell: 'cell-r4-h8-fc',
    dockerRunner: docker.runner,
    sessionSpawner: spawner,
  })
  t.after(() => backend.close())

  const runA = `run-a-${randomUUID().slice(0, 8)}`
  const policyA = buildWarmPoolPolicy({ runId: runA, reposDir, mountedRepos: ['/repos/acme/app'], image: 'kovo-worker:v4' })
  backend.setWarmPoolPolicy(policyA, { reposDir })
  await waitFor(() => backend.getWarmPoolStats(policyA)?.idle === 1, 'Run A warm pool ready')
  const runAContainer = docker.created[0]!.name
  const runASnapDir = docker.created[0]!.mountDir!

  // Update host repo to V2 after Run A staged V1.
  writeFileSync(appFile, 'export const state = "FIXED_V2"\n', { mode: 0o644 })

  // 1. verifyStaticAst omitting runId MUST stage a private snapshot of V2 and delete it on exit.
  const astNoRun = await backend.verifyStaticAst(
    'asgn-norun-ast',
    {
      repo: 'acme/app',
      file: 'handler.ts',
      startLine: 1,
      endLine: 1,
      engine: 'ast-grep',
      ruleOrPattern: 'VULNERABLE_V1',
    },
    AbortSignal.timeout(5_000),
    { reposDir },
  )
  const astPrivateMount = docker.startedSnapshots.at(-1)?.mountDir!
  assert.equal(astNoRun.verified, false, 'omitted-runId verifyStaticAst must read fresh V2, never Run A global policy')
  assert.notEqual(astPrivateMount, runASnapDir)
  assert.equal(existsSync(astPrivateMount), false, 'private single-call snapshot cleaned up after verifyStaticAst')
  assert.equal(existsSync(runASnapDir), true, 'Run A snapshot remains intact')

  // 2. backend.run() omitting runId MUST stage a private snapshot of V2 and delete it on exit.
  const runNoRun = await backend.run(
    { assignmentId: randomUUID(), files: [], command: 'true', outputs: [] },
    AbortSignal.timeout(5_000),
    { reposDir },
  )
  const runPrivateMount = docker.startedSnapshots.at(-1)?.mountDir!
  assert.equal(runNoRun.stdout, 'export const state = "FIXED_V2"\n')
  assert.notEqual(runPrivateMount, runASnapDir)
  assert.equal(existsSync(runPrivateMount), false, 'private single-call snapshot cleaned up after run()')

  // 3. openSession() omitting runId & warmPoolPolicy MUST bypass Run A's warm pool and stage a private V2 snapshot.
  const sessNoRun = await backend.openSession('asgn-norun-sess', AbortSignal.timeout(5_000), { reposDir })
  const sessPrivateMount = docker.created.at(-1)?.mountDir!
  assert.notEqual(started.at(-1), runAContainer, 'omitted-runId openSession must never take Run A warm container')
  assert.notEqual(sessPrivateMount, runASnapDir, 'omitted-runId openSession must stage a private snapshot')
  assert.equal(docker.created.at(-1)?.contentAtCreate, 'export const state = "FIXED_V2"\n')
  assert.equal(existsSync(sessPrivateMount), true, 'private snapshot stays live while session is open')
  await sessNoRun.close()
  assert.equal(existsSync(sessPrivateMount), false, 'private snapshot cleaned up when session closes')
  assert.equal(existsSync(runASnapDir), true, 'Run A snapshot remains intact')
})

test('R4-H-8: production callers thread explicit runId into verifyStaticAst, openSession, and verifyBaselineJob', async () => {
  const observedAstOpts: Array<WorkerSessionOptions | undefined> = []
  const observedOpenOpts: Array<WorkerSessionOptions | undefined> = []

  const stubBackend: WorkerBackend = {
    run: async () => ({ exitCode: 0, stdout: '', stderr: '', outputs: {} }),
    verifyStaticAst: async (_id, req, _signal, opts) => {
      observedAstOpts.push(opts)
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
    },
    openSession: async (_id, _signal, opts) => {
      observedOpenOpts.push(opts)
      throw new Error('stop_after_open_session')
    },
  }

  // 1. floor-recipe-engine.ts: runStaticAstProofRecipe threads ctx.runId.
  await runStaticAstProofRecipe(
    {
      version: 1,
      kind: 'static_ast_proof',
      title: 'Static test',
      category: 'injection',
      cwe: 'CWE-94',
      severity: 'high',
      severityRationale: 'Code evaluation sink in internal job.',
      impact: 'Arbitrary code evaluation.',
      remediation: 'Avoid dynamic code evaluation.',
      description: 'Static AST verification fixture.',
      origin: 'https://app.test',
      repo: 'acme/app',
      file: 'handler.ts',
      startLine: 1,
      endLine: 2,
      engine: 'ast-grep',
      ruleOrPattern: 'eval($X)',
      runtimeProofGap: 'requires internal job',
    } as never,
    {
      broker: {} as never,
      backend: stubBackend,
      reposDir: '/tmp/fake-repos',
      grant: { secrets: [] } as never,
      signal: AbortSignal.timeout(5_000),
      runId: 'run-ast-threaded',
      assignmentId: 'asgn-1',
    },
  )
  assert.equal(observedAstOpts.length, 1)
  assert.equal(observedAstOpts[0]?.runId, 'run-ast-threaded')
  assert.equal(observedAstOpts[0]?.reposDir, '/tmp/fake-repos')

  // 2. semantic-audit.ts: runVariantSweepForFinding threads ctx.run.id into openSession.
  const baseAuditCtx = {
    run: {
      id: 'run-sweep-threaded',
      projectId: 'proj-1',
      goal: 'audit',
      goalRevision: 1,
      scopeRevision: 1,
      capabilityTier: 2 as const,
      budgetUsd: 5,
      spentUsd: 0,
      budgetRequests: 100,
      spentRequests: 0,
    },
    approvedOrigins: ['https://app.test'],
    reposDir: '/tmp/fake-repos',
    mountedRepos: ['acme/app'],
    backend: stubBackend,
    signal: AbortSignal.timeout(5_000),
  }
  await assert.rejects(
    () => runVariantSweepForFinding(baseAuditCtx, {
      finding: {
        id: 'f-1',
        origin: 'https://app.test',
        title: 'Test',
        cwe: 'CWE-89',
        category: 'injection',
        severity: 'high',
        status: 'confirmed',
        codeLocations: [{ repo: 'acme/app', file: 'handler.ts', startLine: 1, endLine: 2 }],
      },
    }),
    /stop_after_open_session/,
  )
  assert.equal(observedOpenOpts.at(-1)?.runId, 'run-sweep-threaded')

  // 3. semantic-audit.ts: runThreeStageSemanticAudit threads ctx.run.id into openSession.
  await assert.rejects(
    () => runThreeStageSemanticAudit({ ...baseAuditCtx, run: { ...baseAuditCtx.run, id: 'run-stage3-threaded' } }),
    /stop_after_open_session/,
  )
  assert.equal(observedOpenOpts.at(-1)?.runId, 'run-stage3-threaded')

  // 4. exec-verify.ts: verifyBaselineJob threads runId: run.id into backend.run().
  const execVerifySrc = readFileSync(join(process.cwd(), 'src/server/exec-verify.ts'), 'utf8')
  assert.match(
    execVerifySrc,
    /reposDir\s*\?\s*\{\s*reposDir,\s*runId:\s*run\.id\s*\}\s*:\s*\{\s*runId:\s*run\.id\s*\}/,
    'exec-verify.ts verifyBaselineJob must thread runId: run.id into backend.run()',
  )
})

test('R4-H-18: amplifying .gitattributes (ident, working-tree-encoding=UTF-16, macro) is rejected pre-checkout with zero working-tree bytes written', async t => {
  const work = makeTempDir(t, 'kovo-r4-h18-reject-')
  const patPath = writeTestPat(work)
  const reposDir = projectReposDir(work, 'proj-r4-h18')

  // 20 KiB of `$Id$\n` (4,000 occurrences): under `ident` + `working-tree-encoding=UTF-16LE` + `eol=crlf`
  // git checkout expands this ~38x (~760 KiB), blowing far past the 64 KiB cap!
  // Commit payload first, then `.gitattributes` (exact real-world amplification commit sequence).
  const idPayload = '$Id$\n'.repeat(4_000)
  const { originRoot, barePath } = createBareOriginRepo(work, 'acme', 'amp-combo', {
    'payload.txt': idPayload,
  })
  const ampStage = join(work, 'src-amp-commit2')
  execFileSync('git', ['clone', barePath, ampStage], { stdio: 'ignore' })
  runGitSync(ampStage, ['config', 'user.email', 'qa@example.test'])
  runGitSync(ampStage, ['config', 'user.name', 'QA Bot'])
  writeFileSync(join(ampStage, '.gitattributes'), '*.txt ident working-tree-encoding=UTF-16LE eol=crlf\n')
  runGitSync(ampStage, ['add', '.gitattributes'])
  runGitSync(ampStage, ['commit', '-m', 'add amplifying gitattributes'])
  runGitSync(ampStage, ['push', 'origin', 'main:main'])

  let checkoutReached = false
  await assert.rejects(
    () => cloneGithubRepos(['acme/amp-combo'], reposDir, undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      maxRepoDiskBytes: 64 * 1024,
      onBeforeCheckout: () => { checkoutReached = true },
    }),
    err => err instanceof Error && (err as Error & { code?: string }).code === 'REPO_UNSAFE_GITATTRIBUTES',
  )
  assert.equal(checkoutReached, false, 'amplifying .gitattributes must be rejected BEFORE checkout')
  assert.equal(existsSync(join(reposDir, 'acme', 'amp-combo')), false)
  assert.deepEqual(cleanupOrphanedRepoDirs(reposDir).removed, [])
  assert.equal(await measureDirectoryBytes(reposDir), 0, 'zero bytes left on disk after pre-checkout rejection')

  // Nested subdirectory `.gitattributes` with `working-tree-encoding=UTF-32LE` is also rejected pre-checkout.
  const nested = createBareOriginRepo(work, 'acme', 'amp-nested-enc', {
    'sub/data.txt': 'A'.repeat(20_000),
  })
  const nestedStage = join(work, 'src-nested-commit2')
  execFileSync('git', ['clone', nested.barePath, nestedStage], { stdio: 'ignore' })
  runGitSync(nestedStage, ['config', 'user.email', 'qa@example.test'])
  runGitSync(nestedStage, ['config', 'user.name', 'QA Bot'])
  writeFileSync(join(nestedStage, 'sub', '.gitattributes'), '*.txt working-tree-encoding=UTF-32LE\n')
  runGitSync(nestedStage, ['add', 'sub/.gitattributes'])
  runGitSync(nestedStage, ['commit', '-m', 'add nested utf32'])
  runGitSync(nestedStage, ['push', 'origin', 'main:main'])

  let nestedCheckoutReached = false
  await assert.rejects(
    () => cloneGithubRepos(['acme/amp-nested-enc'], reposDir, undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      maxRepoDiskBytes: 64 * 1024,
      onBeforeCheckout: () => { nestedCheckoutReached = true },
    }),
    err => err instanceof Error && (err as Error & { code?: string }).code === 'REPO_UNSAFE_GITATTRIBUTES',
  )
  assert.equal(nestedCheckoutReached, false, 'nested working-tree-encoding must be rejected BEFORE checkout')

  // Macro indirection `[attr]boom ident` is also rejected pre-checkout.
  createBareOriginRepo(work, 'acme', 'amp-macro', {
    '.gitattributes': '[attr]boom ident\n* boom\n',
    'doc.txt': '$Id$\n'.repeat(1_000),
  })
  await assert.rejects(
    () => cloneGithubRepos(['acme/amp-macro'], reposDir, undefined, {
      patPath,
      gitBaseUrl: `file://${originRoot}`,
      allowLocalFileProtocol: true,
      maxRepoDiskBytes: 64 * 1024,
    }),
    err => err instanceof Error && (err as Error & { code?: string }).code === 'REPO_UNSAFE_GITATTRIBUTES',
  )
})

test('R4-H-18: eol=crlf / text / filter .gitattributes is neutralized with zero byte amplification, .git/info/attributes written, and quota respected', async t => {
  const work = makeTempDir(t, 'kovo-r4-h18-neutralize-')
  const patPath = writeTestPat(work)
  const reposDir = projectReposDir(work, 'proj-r4-h18-ok')

  // 45,000 LF bytes: `eol=crlf` would double this to 90,000 bytes (plus ~28 KiB .git = ~118 KiB > 80 KiB cap).
  // Neutralized streaming checkout must write the exact 45,000 raw blob bytes with zero CR expansion.
  const rawNewlines = '\n'.repeat(45_000)
  const { originRoot } = createBareOriginRepo(work, 'acme', 'crlf-neutral', {
    '.gitattributes': '* text eol=crlf filter=customboom\n',
    'lines.txt': rawNewlines,
    'empty.txt': '',
    'scripts/run.sh': { content: '#!/bin/sh\necho ok\n', mode: 0o755 },
  })

  const synced = await cloneGithubRepos(['acme/crlf-neutral'], reposDir, undefined, {
    patPath,
    gitBaseUrl: `file://${originRoot}`,
    allowLocalFileProtocol: true,
    maxRepoDiskBytes: 80 * 1024,
    stripGitMetadata: false,
  })
  assert.equal(synced.length, 1)

  const repoDir = join(reposDir, 'acme', 'crlf-neutral')
  const checkedOut = readFileSync(join(repoDir, 'lines.txt'))
  assert.equal(checkedOut.length, 45_000, 'eol=crlf must NOT amplify LF bytes on checkout')
  assert.equal(checkedOut.includes(0x0d), false, 'zero CR bytes injected')

  assert.equal(statSync(join(repoDir, 'empty.txt')).size, 0, 'zero-byte blob materialized accurately')
  assert.equal(readFileSync(join(repoDir, 'scripts', 'run.sh'), 'utf8'), '#!/bin/sh\necho ok\n')
  assert.equal(statSync(join(repoDir, 'scripts', 'run.sh')).mode & 0o777, 0o644, 'walkClonedRepo normalizes mounted files to 0o644')

  const infoAttrs = readFileSync(join(repoDir, '.git', 'info', 'attributes'), 'utf8')
  assert.match(infoAttrs, /\* -text -crlf -ident -working-tree-encoding -filter -eol/)

  const measuredBytes = await measureDirectoryBytes(repoDir)
  assert.ok(measuredBytes <= 80 * 1024, `total repo bytes (${measuredBytes}) must remain <= 80 KiB cap`)
})
