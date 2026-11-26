/**
 * R3-02 batch-boundary real-run defect fixes:
 *  1. Model credential resolution across nested `prepareIsolatedDataDir` + `benchmark-agentic-matrix.ts`
 *     model-gate cell data dirs via read-only `KOVO_CREDENTIALS_DIR` (preserving M-15 anti-symlink hardening).
 *  2. `scripts/batch-boundary.sh` early argument validation (`--apps`, `--modes`, `--verifier`, seeds) and
 *     deferred `benchmarks/realistic-bench/EXPOSED_SEEDS.json` recording so certifying benchmark legs observe
 *     a clean working tree (`dirty: false`) and failed pre-held-out runs do not self-dirty the repo.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { pathToFileURL } from 'node:url'

import { CREDENTIALS_DIR_ENV, privateModelProfiles } from '../src/server/model-settings.ts'
import { runAgentSession } from '../src/server/agent-session.ts'
import { classifyProviderFailure, providerPool } from '../src/server/provider.ts'
import { Store } from '../src/server/store.ts'
import { ModelGate } from '../scripts/benchmark-parallel.ts'
import {
  PreflightError,
  acquireCredentialsDirEnv,
  assertAgenticPreflight,
  prepareIsolatedDataDir,
} from '../scripts/benchmark-realistic.ts'
import {
  cellEnv,
  parseMatrixArgs,
  prepareGatedCellDataDirs,
  type MatrixCell,
} from '../scripts/benchmark-agentic-matrix.ts'
import { EXPOSED_SEEDS_PATH, loadExposedSeedState, readLedgerRows } from '../scripts/bench-ledger.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')
const TEST_KEY_CANARY = 'sk-or-v1-r302-batch-boundary-synthetic-test-key'

function makeTmpDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function createHostSourceDataDir(t: { after: (fn: () => void) => void }): {
  dir: string
  credDir: string
  credentialId: string
  profileName: string
} {
  const dir = makeTmpDir(t, 'r302-host-data-')
  const store = new Store(dir)
  const workspaceId = store.workspace.id
  const credDir = join(dir, 'credentials')
  mkdirSync(credDir, { recursive: true, mode: 0o700 })
  chmodSync(credDir, 0o700)
  const credentialId = `model-${randomUUID()}`
  const credPath = join(credDir, credentialId)
  writeFileSync(credPath, TEST_KEY_CANARY, { mode: 0o600 })
  chmodSync(credPath, 0o600)

  const profileName = 'OpenRouter DeepSeek V4.1 Flash'
  store.db.$client.prepare(
    'insert into model_profiles (id, workspace_id, name, endpoint, model, protocol, credential_id, priority, '
    + 'enabled, context_window, max_tokens, thinking_level, role_affinity, input_cost_per_mtok, '
    + 'cached_input_cost_per_mtok, output_cost_per_mtok, health_state, cooldown_until, last_error, updated_at) '
    + 'values (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, null, null, ?)',
  ).run(
    randomUUID(),
    workspaceId,
    profileName,
    'https://openrouter.ai/api/v1',
    'deepseek/deepseek-v4.1-flash-1017',
    'responses',
    credentialId,
    100,
    128_000,
    4_096,
    'off',
    'any',
    0,
    0,
    0,
    'closed',
    Date.now(),
  )
  store.close()
  return { dir, credDir, credentialId, profileName }
}

function walkRegularFiles(root: string): string[] {
  const out: string[] = []
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      const st = lstatSync(full)
      if (st.isSymbolicLink()) continue
      if (st.isDirectory()) walk(full)
      else if (st.isFile()) out.push(full)
    }
  }
  walk(root)
  return out
}

function hasAnySymlink(root: string): boolean {
  let found = false
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      const st = lstatSync(full)
      if (st.isSymbolicLink()) {
        found = true
        return
      }
      if (st.isDirectory()) walk(full)
    }
  }
  walk(root)
  return found
}

// ============================================================================
// 1. Model credential lookup across gated nested isolation
// ============================================================================

describe('R3-02 batch-fix: gated matrix nested isolation resolves host credentials via KOVO_CREDENTIALS_DIR', () => {
  test('prepareGatedCellDataDirs + cellEnv + nested prepareIsolatedDataDir loads profile with zero key copies/symlinks', async (t) => {
    const host = createHostSourceDataDir(t)
    const outDir = makeTmpDir(t, 'r302-matrix-out-')
    const gate = new ModelGate({ maxInFlightStreams: 4 })
    await gate.start()
    t.after(async () => {
      await gate.close()
    })

    const args = parseMatrixArgs(
      ['--apps', 'acme-saas', '--seeds', '1', '--modes', 'grey-box', '--data-dir', host.dir, '--out-dir', outDir],
      {},
    )
    const overrides = prepareGatedCellDataDirs(args, gate)
    const cell: MatrixCell = {
      app: 'acme-saas',
      seed: 1,
      mode: 'grey-box',
      seedSet: 'dev',
      label: 'acme-saas-seed1-grey-box',
    }
    const gatedDir = overrides[cell.label]
    assert.ok(gatedDir && existsSync(join(gatedDir, 'kovo.sqlite')))
    assert.equal(existsSync(join(gatedDir, 'credentials', host.credentialId)), false, 'gated dir must not copy or symlink keys')

    const childEnvironment = cellEnv(
      cell,
      { ...args, dataDirOverrides: overrides, credentialsDirOverride: host.credDir },
      { PATH: process.env.PATH },
    )
    assert.equal(childEnvironment[CREDENTIALS_DIR_ENV], host.credDir)
    assert.equal(childEnvironment.KOVO_DATA_DIR, gatedDir)
    assert.equal(childEnvironment.KOVO_ALLOW_LOCAL_MODEL, '1', 'gated agentic cell must export KOVO_ALLOW_LOCAL_MODEL=1 for loopback ModelGate')

    // --no-llm and --no-model-gate must NOT widen egress with KOVO_ALLOW_LOCAL_MODEL
    const noLlmEnv = cellEnv(cell, { ...args, noLlm: true }, { PATH: process.env.PATH })
    assert.equal(noLlmEnv[CREDENTIALS_DIR_ENV], undefined)
    assert.equal(noLlmEnv.KOVO_ALLOW_LOCAL_MODEL, undefined)
    const noGateEnv = cellEnv(cell, { ...args, modelGate: false }, { PATH: process.env.PATH })
    assert.equal(noGateEnv.KOVO_ALLOW_LOCAL_MODEL, undefined)

    // Simulate child benchmark-realistic.ts running prepareIsolatedDataDir on the gated source dir
    const cellDataDir = join(outDir, 'cell-runtime-data')
    const prevCredEnv = process.env[CREDENTIALS_DIR_ENV]
    process.env[CREDENTIALS_DIR_ENV] = childEnvironment[CREDENTIALS_DIR_ENV]
    t.after(() => {
      if (prevCredEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
      else process.env[CREDENTIALS_DIR_ENV] = prevCredEnv
    })

    const nested = prepareIsolatedDataDir({ sourceDataDir: gatedDir, targetDir: cellDataDir })
    assert.equal(nested.credentialsDir, host.credDir)
    assert.deepEqual(nested.profileNames, [host.profileName])

    const release = acquireCredentialsDirEnv(nested.credentialsDir)
    t.after(() => release())
    const cellStore = new Store(cellDataDir)
    t.after(() => cellStore.close())
    const resolved = privateModelProfiles(cellStore)
    assert.equal(resolved.length, 1)
    assert.equal(resolved[0]!.name, host.profileName)
    assert.equal(resolved[0]!.key, TEST_KEY_CANARY)
    assert.match(resolved[0]!.endpoint, new RegExp(`^http://127\\.0\\.0\\.1:${gate.port}/`))

    // M-15 invariant: zero symlinks and zero key copies anywhere in outDir
    assert.equal(hasAnySymlink(outDir), false, 'isolated/gated dirs must never contain symlinks')
    const leaked = walkRegularFiles(outDir).filter(f => readFileSync(f, 'utf8').includes(TEST_KEY_CANARY))
    assert.deepEqual(leaked, [], 'API key must never be copied into gated or cell data dirs')
  })

  test('nested prepareIsolatedDataDir still fails closed when KOVO_CREDENTIALS_DIR is missing or symlinked', async (t) => {
    const host = createHostSourceDataDir(t)
    const outDir = makeTmpDir(t, 'r302-nested-fail-')
    const gatedDir = join(outDir, 'gated')
    prepareIsolatedDataDir({ sourceDataDir: host.dir, targetDir: gatedDir })

    const prevCredEnv = process.env[CREDENTIALS_DIR_ENV]
    delete process.env[CREDENTIALS_DIR_ENV]
    t.after(() => {
      if (prevCredEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
      else process.env[CREDENTIALS_DIR_ENV] = prevCredEnv
    })

    // 1. No KOVO_CREDENTIALS_DIR -> empty gated credentials dir fails closed
    assert.throws(
      () => prepareIsolatedDataDir({ sourceDataDir: gatedDir, targetDir: join(outDir, 'cell-1') }),
      (err: unknown) => err instanceof PreflightError && /has no readable credential file/i.test(err.message),
    )

    // 2. Symlinked KOVO_CREDENTIALS_DIR -> rejected by anti-symlink hardening
    const symlinkCredDir = join(outDir, 'cred-link')
    symlinkSync(host.credDir, symlinkCredDir, 'dir')
    process.env[CREDENTIALS_DIR_ENV] = symlinkCredDir
    assert.throws(
      () => prepareIsolatedDataDir({ sourceDataDir: gatedDir, targetDir: join(outDir, 'cell-2') }),
      (err: unknown) => err instanceof PreflightError && /symbolic link/i.test(err.message),
    )

    // 3. Real 0700 KOVO_CREDENTIALS_DIR containing a symlinked credential file -> rejected
    const fakeCredDir = join(outDir, 'real-dir-symlink-file')
    mkdirSync(fakeCredDir, { mode: 0o700 })
    chmodSync(fakeCredDir, 0o700)
    symlinkSync(join(host.credDir, host.credentialId), join(fakeCredDir, host.credentialId))
    process.env[CREDENTIALS_DIR_ENV] = fakeCredDir
    assert.throws(
      () => prepareIsolatedDataDir({ sourceDataDir: gatedDir, targetDir: join(outDir, 'cell-3') }),
      (err: unknown) => err instanceof PreflightError && /symbolic link/i.test(err.message),
    )
  })
})

// ============================================================================
// 2. batch-boundary.sh early arg validation & deferred EXPOSED_SEEDS.json write
// ============================================================================

function initBatchBoundaryTempRepo(t: { after: (fn: () => void) => void }): {
  repoDir: string
  gitSha: string
  git: (args: string[]) => string
} {
  const repoDir = makeTmpDir(t, 'r302-batch-boundary-repo-')
  const git = (args: string[]) =>
    execFileSync('git', args, {
      cwd: repoDir,
      encoding: 'utf8',
      env: {
        ...process.env,
        GIT_AUTHOR_NAME: 'Kovo Test',
        GIT_AUTHOR_EMAIL: 'test@kovo.local',
        GIT_COMMITTER_NAME: 'Kovo Test',
        GIT_COMMITTER_EMAIL: 'test@kovo.local',
      },
    }).trim()

  git(['init', '-b', 'main'])
  writeFileSync(join(repoDir, '.gitignore'), '/.kovo/\n')
  mkdirSync(join(repoDir, 'scripts'), { recursive: true })
  mkdirSync(join(repoDir, 'benchmarks/realistic-bench'), { recursive: true })
  writeFileSync(join(repoDir, 'benchmarks/realistic-bench/BURNED_SEEDS'), '# test\n')
  writeFileSync(
    join(repoDir, 'scripts/batch-boundary.sh'),
    readFileSync(join(REPO_ROOT, 'scripts/batch-boundary.sh'), 'utf8'),
  )
  // Re-export real bench-ledger functions from the workspace checkout so EXPOSED_SEEDS.json and
  // ledger promotion operate strictly inside `repoDir` (via `process.cwd()`).
  const ledgerModuleUrl = pathToFileURL(join(REPO_ROOT, 'scripts/bench-ledger.ts')).href
  writeFileSync(
    join(repoDir, 'scripts/bench-ledger.ts'),
    `export * from ${JSON.stringify(ledgerModuleUrl)}\n`,
  )

  // Stub matrix runner: verifies `git status --porcelain` during each leg, logs observed dirty state,
  // optionally fails a named leg, and writes valid per-run ledger rows into KOVO_LEDGER_ROOT.
  writeFileSync(
    join(repoDir, 'scripts/benchmark-agentic-matrix.ts'),
    `import { execFileSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs'
import { join } from 'node:path'
import { appendPerRunLedgerRow, LEDGER_SCHEMA_VERSION, resolveGitState } from './bench-ledger.ts'

const argv = process.argv.slice(2)
const flag = (k) => {
  const idx = argv.indexOf(k)
  return idx >= 0 ? argv[idx + 1] : undefined
}
const noLlm = argv.includes('--no-llm')
const certify = argv.includes('--certify')
const outDir = flag('--out-dir')
const seeds = (flag('--seeds') ?? '1').split(',').map(Number)
const apps = (flag('--apps') ?? 'acme-saas').split(',')
const mode = (flag('--modes') ?? 'grey-box').split(',')[0]
const legName = outDir.split('/').pop()

const gitState = resolveGitState(process.cwd())
const exposedExists = existsSync(join(process.cwd(), 'benchmarks/realistic-bench/EXPOSED_SEEDS.json'))
const traceFile = process.env.TEST_LEG_TRACE
if (traceFile) {
  appendFileSync(traceFile, JSON.stringify({ legName, dirty: gitState.dirty, exposedExists, seeds }) + '\\n')
}
if (process.env.TEST_FAIL_LEG && process.env.TEST_FAIL_LEG === legName) {
  process.stderr.write('simulated failure in ' + legName + '\\n')
  process.exit(1)
}

mkdirSync(outDir, { recursive: true })
const ledgerRoot = process.env.KOVO_LEDGER_ROOT
for (const app of apps) {
  for (const seed of seeds) {
    appendPerRunLedgerRow(
      {
        schemaVersion: LEDGER_SCHEMA_VERSION,
        recordedAt: new Date().toISOString(),
        suite: 'realistic-bench',
        gitSha: gitState.gitSha,
        dirty: gitState.dirty,
        benchmarkVersion: 'a'.repeat(64),
        effectiveConfigHash: 'b'.repeat(64),
        app,
        split: seed >= 1_000_000 ? 'held-out' : 'dev',
        mode,
        llm: noLlm ? 'deterministic-no-llm' : 'agentic',
        seed,
        repeat: 1,
        certifying: certify && !gitState.dirty,
        reportable: true,
        status: 'VALID',
        targets: 10,
        confirmed: 5,
        recall: 0.5,
        rawPrecision: 1,
        strictPrecision: 1,
        precision: 1,
        decoyFalsePositives: 0,
        unmatchedFalsePositives: 0,
        validUnplantedCount: 0,
        costUsd: noLlm ? 0 : 0.1,
        durationMs: 500,
      },
      { runsDir: ledgerRoot, runId: legName + '-' + app + '-' + seed, repoRoot: process.cwd() },
    )
  }
}
`,
  )

  git(['add', '.'])
  git(['commit', '-m', 'init batch-boundary test repo'])
  const gitSha = git(['rev-parse', '--short=12', 'HEAD'])
  return { repoDir, gitSha, git }
}

describe('R3-02 batch-fix: scripts/batch-boundary.sh arg validation & deferred EXPOSED_SEEDS.json write', () => {
  test('validates --apps, --modes, --verifier, and seeds before drawing or writing EXPOSED_SEEDS.json', (t) => {
    const { repoDir, git } = initBatchBoundaryTempRepo(t)
    const salt = 'test-heldout-salt-do-not-leak-0123456789abcdef'
    const exposedFile = join(repoDir, EXPOSED_SEEDS_PATH)

    const badCases: Array<{ args: string[]; pattern: RegExp }> = [
      { args: ['--apps', 'not-an-app', '--data-dir', '/tmp/fake'], pattern: /unknown --apps value/i },
      { args: ['--modes', 'ultra-box', '--data-dir', '/tmp/fake'], pattern: /unknown --modes value/i },
      { args: ['--verifier', 'bogus', '--data-dir', '/tmp/fake'], pattern: /unknown --verifier value/i },
      { args: ['--dev-seeds', 'abc', '--data-dir', '/tmp/fake'], pattern: /positive integer/i },
      { args: ['--apps', 'acme-saas', '--modes', 'grey-box'], pattern: /require --data-dir or KOVO_DATA_DIR/i },
    ]

    for (const tc of badCases) {
      const env: NodeJS.ProcessEnv = { ...process.env, KOVO_RB_HELDOUT_SALT: salt }
      delete env.KOVO_DATA_DIR
      const res = spawnSync('bash', ['scripts/batch-boundary.sh', ...tc.args], {
        cwd: repoDir,
        encoding: 'utf8',
        env,
      })
      assert.equal(res.status, 2, `expected exit 2 for ${tc.args.join(' ')}, got ${res.status}: ${res.stderr}`)
      assert.match(res.stderr, tc.pattern)
      assert.equal(existsSync(exposedFile), false, `EXPOSED_SEEDS.json must NOT be written on arg error (${tc.args.join(' ')})`)
      assert.equal(git(['status', '--porcelain']), '', 'working tree must remain clean after arg validation failure')
    }
  })

  test('does not write EXPOSED_SEEDS.json if a dev leg fails, and keeps git clean during all 4 certifying legs before recording exposure', (t) => {
    const { repoDir, gitSha, git } = initBatchBoundaryTempRepo(t)
    const salt = 'test-heldout-salt-do-not-leak-fedcba9876543210'
    const exposedFile = join(repoDir, EXPOSED_SEEDS_PATH)
    const traceFile = join(repoDir, '.kovo/leg-trace.jsonl')
    mkdirSync(join(repoDir, '.kovo'), { recursive: true })

    // 1. Failing dev leg leaves working tree completely clean (EXPOSED_SEEDS.json NOT written)
    const failRun = spawnSync(
      'bash',
      [
        'scripts/batch-boundary.sh',
        '--apps', 'acme-saas',
        '--modes', 'grey-box',
        '--data-dir', '/tmp/fake-data-dir',
        '--skip-regression-floor',
        '--skip-render',
      ],
      {
        cwd: repoDir,
        encoding: 'utf8',
        env: {
          ...process.env,
          KOVO_RB_HELDOUT_SALT: salt,
          TEST_LEG_TRACE: traceFile,
          TEST_FAIL_LEG: 'dev-agentic',
        },
      },
    )
    assert.notEqual(failRun.status, 0, 'simulated dev-agentic failure must exit non-zero')
    assert.equal(existsSync(exposedFile), false, 'EXPOSED_SEEDS.json must NOT be created when dev leg fails before held-out starts')
    assert.equal(git(['status', '--porcelain']), '', 'repo must stay clean for immediate retry after dev leg failure')

    // 2. Clean retry: all 4 legs run, observe dirty=false and no EXPOSED_SEEDS.json, then EXPOSED_SEEDS.json
    //    is written AFTER held-out legs complete and certifying rows promote into ledger.jsonl!
    rmSync(traceFile, { force: true })
    const passRun = spawnSync(
      'bash',
      [
        'scripts/batch-boundary.sh',
        '--apps', 'acme-saas',
        '--modes', 'grey-box',
        '--data-dir', '/tmp/fake-data-dir',
        '--skip-regression-floor',
        '--skip-render',
      ],
      {
        cwd: repoDir,
        encoding: 'utf8',
        env: {
          ...process.env,
          KOVO_RB_HELDOUT_SALT: salt,
          TEST_LEG_TRACE: traceFile,
        },
      },
    )
    assert.equal(passRun.status, 0, `expected clean batch-boundary PASS:\nSTDOUT:\n${passRun.stdout}\nSTDERR:\n${passRun.stderr}`)

    // Verify all 4 legs ran and EVERY leg saw dirty: false and EXPOSED_SEEDS.json absent
    const legTraces = readFileSync(traceFile, 'utf8')
      .trim()
      .split('\n')
      .map(line => JSON.parse(line) as { legName: string; dirty: boolean; exposedExists: boolean; seeds: number[] })
    assert.deepEqual(
      legTraces.map(x => x.legName),
      ['dev-no-llm', 'dev-agentic', 'heldout-no-llm', 'heldout-agentic'],
    )
    for (const trace of legTraces) {
      assert.equal(trace.dirty, false, `leg '${trace.legName}' must observe dirty: false`)
      assert.equal(trace.exposedExists, false, `leg '${trace.legName}' must run before EXPOSED_SEEDS.json is written`)
    }

    // Verify EXPOSED_SEEDS.json WAS written after held-out legs completed, with exact drawn seeds
    assert.equal(existsSync(exposedFile), true, 'EXPOSED_SEEDS.json must be written once held-out legs complete')
    const state = loadExposedSeedState(EXPOSED_SEEDS_PATH, repoDir)
    assert.equal(state.records.length, 1)
    assert.equal(state.records[0]!.domain, 'certify')
    assert.equal(state.records[0]!.gitSha, gitSha)
    assert.deepEqual(state.records[0]!.seeds, legTraces[2]!.seeds)
    assert.equal(state.records[0]!.seeds.length, 3)

    // Verify certifying held-out rows promoted cleanly into benchmarks/results/ledger.jsonl
    const promoted = readLedgerRows('benchmarks/results/ledger.jsonl', repoDir)
    const heldoutCertifying = promoted.filter(r => r.split === 'held-out' && r.certifying && !r.dirty)
    assert.equal(heldoutCertifying.length, 3, 'all 3 certifying held-out agentic rows must promote cleanly')

    // Held-out salt never leaked anywhere
    assert.equal(passRun.stdout.includes(salt), false, 'salt must never appear in stdout')
    assert.equal(passRun.stderr.includes(salt), false, 'salt must never appear in stderr')
    assert.equal(readFileSync(exposedFile, 'utf8').includes(salt), false, 'salt must never appear in EXPOSED_SEEDS.json')
  })
})

describe('R3-02 loopback ModelGate egress, preflight fail-fast, and model_error detail preservation', () => {
  test('gated cell profile streams through loopback ModelGate (peak>=1) with cellEnv, fails closed without KOVO_ALLOW_LOCAL_MODEL, and preserves EgressDenied detail without stream_drop misclassification', async (t) => {
    const host = createHostSourceDataDir(t)
    const outDir = makeTmpDir(t, 'r302-gate-e2e-')
    const responseId = 'resp_r302_gate_ok'
    const ssePayload = [
      `event: response.created\ndata: ${JSON.stringify({ type: 'response.created', response: { id: responseId, status: 'in_progress', output: [] } })}\n\n`,
      `event: response.output_item.added\ndata: ${JSON.stringify({ type: 'response.output_item.added', output_index: 0, item: { id: 'msg_1', type: 'message', status: 'in_progress', role: 'assistant', content: [] } })}\n\n`,
      `event: response.output_text.delta\ndata: ${JSON.stringify({ type: 'response.output_text.delta', output_index: 0, item_id: 'msg_1', content_index: 0, delta: 'gate-ok' })}\n\n`,
      `event: response.output_text.done\ndata: ${JSON.stringify({ type: 'response.output_text.done', output_index: 0, item_id: 'msg_1', content_index: 0, text: 'gate-ok' })}\n\n`,
      `event: response.output_item.done\ndata: ${JSON.stringify({ type: 'response.output_item.done', output_index: 0, item: { id: 'msg_1', type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: 'gate-ok' }] } })}\n\n`,
      `event: response.completed\ndata: ${JSON.stringify({ type: 'response.completed', response: { id: responseId, status: 'completed', output: [{ id: 'msg_1', type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: 'gate-ok' }] }], usage: { input_tokens: 10, output_tokens: 4, total_tokens: 14 } } })}\n\n`,
    ].join('')
    const gate = new ModelGate({
      maxInFlightStreams: 4,
      fetchImpl: (async () => new Response(ssePayload, {
        status: 200,
        headers: { 'content-type': 'text/event-stream' },
      })) as typeof fetch,
    })
    await gate.start()
    t.after(async () => { await gate.close() })

    const args = parseMatrixArgs(
      ['--apps', 'acme-saas', '--seeds', '1', '--modes', 'grey-box', '--data-dir', host.dir, '--out-dir', outDir],
      {},
    )
    const overrides = prepareGatedCellDataDirs(args, gate)
    const cell: MatrixCell = {
      app: 'acme-saas',
      seed: 1,
      mode: 'grey-box',
      seedSet: 'dev',
      label: 'acme-saas-seed1-grey-box',
    }
    const childEnvironment = cellEnv(
      cell,
      { ...args, dataDirOverrides: overrides, credentialsDirOverride: host.credDir },
      { PATH: process.env.PATH },
    )
    assert.equal(childEnvironment.KOVO_ALLOW_LOCAL_MODEL, '1')

    const prevCredEnv = process.env[CREDENTIALS_DIR_ENV]
    const prevLocalModel = process.env.KOVO_ALLOW_LOCAL_MODEL
    const prevOffline = process.env.KOVO_OFFLINE
    process.env[CREDENTIALS_DIR_ENV] = childEnvironment[CREDENTIALS_DIR_ENV]
    t.after(() => {
      if (prevCredEnv === undefined) delete process.env[CREDENTIALS_DIR_ENV]
      else process.env[CREDENTIALS_DIR_ENV] = prevCredEnv
      if (prevLocalModel === undefined) delete process.env.KOVO_ALLOW_LOCAL_MODEL
      else process.env.KOVO_ALLOW_LOCAL_MODEL = prevLocalModel
      if (prevOffline === undefined) delete process.env.KOVO_OFFLINE
      else process.env.KOVO_OFFLINE = prevOffline
    })

    const cellDataDir = join(outDir, 'cell-runtime')
    const nested = prepareIsolatedDataDir({ sourceDataDir: overrides[cell.label]!, targetDir: cellDataDir })
    const release = acquireCredentialsDirEnv(nested.credentialsDir)
    t.after(() => release())
    const cellStore = new Store(cellDataDir)
    t.after(() => cellStore.close())
    const resolved = privateModelProfiles(cellStore)
    assert.equal(resolved.length, 1)

    // 1. Without KOVO_ALLOW_LOCAL_MODEL: EgressGateway blocks before hitting gate (peak=0),
    //    runAgentSession preserves the redacted EgressDenied detail, and classifyProviderFailure
    //    MUST NOT misclassify it as retryable stream_drop.
    delete process.env.KOVO_ALLOW_LOCAL_MODEL
    delete process.env.KOVO_OFFLINE
    const sessionDir = makeTmpDir(t, 'r302-session-')
    let blockedErr: Error | null = null
    try {
      await runAgentSession({
        directory: sessionDir,
        sessionId: 'r302-blocked-check',
        requestId: randomUUID(),
        settings: resolved[0]!,
        profiles: resolved,
        scenario: 'worker-investigation',
        prompt: 'ping',
        signal: AbortSignal.timeout(10_000),
      })
    } catch (err) {
      blockedErr = err instanceof Error ? err : new Error(String(err))
    }
    assert.ok(blockedErr, 'loopback ModelGate call without KOVO_ALLOW_LOCAL_MODEL must fail closed')
    assert.match(blockedErr.message, /model_error.*Plaintext HTTP egress/i, 'runAgentSession must preserve redacted model_error detail')
    assert.equal(blockedErr.message.includes(TEST_KEY_CANARY), false, 'error detail must never leak API key')
    assert.equal(gate.stats().peak, 0, 'EgressGateway must block before reaching loopback gate when KOVO_ALLOW_LOCAL_MODEL is unset')
    assert.equal(
      classifyProviderFailure(blockedErr),
      null,
      'EgressDenied detail in model_error must never be misclassified as retryable stream_drop',
    )

    // 2. With childEnvironment.KOVO_ALLOW_LOCAL_MODEL applied: providerPool reaches the loopback
    //    ModelGate cleanly and streams the response (peak >= 1).
    process.env.KOVO_ALLOW_LOCAL_MODEL = childEnvironment.KOVO_ALLOW_LOCAL_MODEL
    const { models, model } = providerPool(resolved, 'worker-investigation', {
      signal: AbortSignal.timeout(10_000),
      maxCalls: 2,
      maxTransportRetries: 0,
    })
    const stream = models.stream(model, {
      systemPrompt: 'Reply concisely.',
      messages: [{ role: 'user', content: 'ping', timestamp: Date.now() }],
      tools: [],
    })
    for await (const _ev of stream) { /* consume */ }
    const res = await stream.result()
    assert.equal(res.stopReason, 'stop')
    assert.ok(gate.stats().peak >= 1, `expected loopback ModelGate peak >= 1, got ${gate.stats().peak}`)
  })

  test('assertAgenticPreflight fails fast (PreflightError exit 2) on loopback HTTP model profiles without KOVO_ALLOW_LOCAL_MODEL', () => {
    assert.throws(
      () => assertAgenticPreflight({
        hasProfiles: true,
        noLlm: false,
        allowInertWorkers: false,
        backendKind: 'docker',
        workerSessions: true,
        profileEndpoints: ['http://127.0.0.1:41234/kovo-gate/aHR0cHM6Ly9vcGVucm91dGVyLmFpL2FwaS92MQ'],
        localModelEnabled: false,
      }),
      (err: unknown) => err instanceof PreflightError && err.exitCode === 2 && /KOVO_ALLOW_LOCAL_MODEL=1/.test(err.message),
    )

    // Passes when KOVO_ALLOW_LOCAL_MODEL is enabled or when endpoint is public HTTPS
    assert.doesNotThrow(() => assertAgenticPreflight({
      hasProfiles: true,
      noLlm: false,
      allowInertWorkers: false,
      backendKind: 'docker',
      workerSessions: true,
      profileEndpoints: ['http://127.0.0.1:41234/kovo-gate/aHR0cHM6Ly9vcGVucm91dGVyLmFpL2FwaS92MQ'],
      localModelEnabled: true,
    }))
    assert.doesNotThrow(() => assertAgenticPreflight({
      hasProfiles: true,
      noLlm: false,
      allowInertWorkers: false,
      backendKind: 'docker',
      workerSessions: true,
      profileEndpoints: ['https://openrouter.ai/api/v1'],
      localModelEnabled: false,
    }))
  })
})
