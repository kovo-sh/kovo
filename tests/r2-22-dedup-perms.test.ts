/**
 * R2-22 regression & invariant guard suite:
 *   1. PR-22a — Single authoritative `src/server/chromium-launch.ts`, duplicate exported-name
 *      static guard, and Playwright loader non-MODULE_NOT_FOUND rethrow contract.
 *   2. PR-22b — Worker RPC & IPC mount permission hardening (M-8 / L-7): zero world-readable
 *      (`0o444`) or world-writable (`0o666`/`0o777`) worker token/context/socket/IPC modes,
 *      group-scoped `0o750`/`0o770`/`0o640`/`0o660` paired with `--group-add <hostGid>` (never 0),
 *      and strictly owner-only `0o700`/`0o600` under UID `10001`.
 *   3. PR-22c — Warn-only function-length & file-growth ratchet (`scripts/check-function-growth.ts`).
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { runFunctionGrowthCheck } from '../scripts/check-function-growth.ts'
import { RequestBroker, type Grant } from '../src/server/broker.ts'
import {
  browserSessionChromiumArgs,
  buildBrowserSessionChromiumLaunchOptions,
  formatChromiumSandboxLaunchError,
} from '../src/server/browser-session-auth.ts'
import {
  buildChromiumLaunchArgs,
  buildPlaywrightChromiumLaunchOptions,
  formatChromiumSandboxError,
  isInsecureNoSandboxEnabled,
  loadPlaywrightChromium,
} from '../src/server/chromium-launch.ts'
import {
  buildFormChromiumLaunchOptions,
  formChromiumLaunchArgs,
} from '../src/server/persona-auth.ts'
import {
  buildChromiumLaunchOptions,
  chromiumLaunchArgs,
} from '../src/server/scoped-browser.ts'
import {
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
  VerifyRpcServer,
} from '../src/server/verify-rpc.ts'
import {
  LinuxWorkerBackend,
  ensureRpcMountReadable,
  resolveWorkerSharedGid,
  workerContainerCreateArgs,
} from '../src/server/worker-backend.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SERVER_DIR = join(REPO_ROOT, 'src', 'server')

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')
}

// ---------------------------------------------------------------------------
// 1. PR-22a: Single Chromium launch module + duplicate exported-name guard
// ---------------------------------------------------------------------------

test('PR-22a static guard: single authoritative chromium-launch.ts with zero duplicate definitions across src/server', () => {
  const serverFiles = readdirSync(SERVER_DIR)
    .filter(name => name.endsWith('.ts') && !name.endsWith('.d.ts'))
    .sort()

  const insecureDefFiles: string[] = []
  const webrtcFlagFiles: string[] = []
  const chromiumLaunchCallFiles: string[] = []
  const dynamicPlaywrightLoaderFiles: string[] = []

  // Also enforce zero duplicate exported function declarations of shared chromium/sandbox primitives.
  const exportedFnLocations = new Map<string, string[]>()
  const WATCHED_SHARED_EXPORTS = new Set([
    'isInsecureNoSandboxEnabled',
    'isChromiumSandboxFailure',
    'formatChromiumSandboxError',
    'loadPlaywrightChromium',
    'launchPlaywrightChromium',
    'buildChromiumLaunchArgs',
    'buildChromiumResolverRules',
    'buildPlaywrightChromiumLaunchOptions',
  ])

  for (const name of serverFiles) {
    const src = stripComments(readFileSync(join(SERVER_DIR, name), 'utf8'))
    if (/export\s+(?:async\s+)?function\s+isInsecureNoSandboxEnabled\b/.test(src)) {
      insecureDefFiles.push(name)
    }
    if (src.includes('--force-webrtc-ip-handling-policy=disable_non_proxied_udp')) {
      webrtcFlagFiles.push(name)
    }
    if (/\bchromium\.launch\s*\(/.test(src)) {
      chromiumLaunchCallFiles.push(name)
    }
    if (src.includes("'playwright-core'") || src.includes('"playwright-core"')) {
      dynamicPlaywrightLoaderFiles.push(name)
    }
    for (const m of src.matchAll(/^\s*export\s+(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/gm)) {
      const fnName = m[1]!
      if (WATCHED_SHARED_EXPORTS.has(fnName)) {
        const list = exportedFnLocations.get(fnName) ?? []
        list.push(name)
        exportedFnLocations.set(fnName, list)
      }
    }
  }

  assert.deepEqual(insecureDefFiles, ['chromium-launch.ts'], 'isInsecureNoSandboxEnabled must be defined ONLY in chromium-launch.ts')
  assert.deepEqual(webrtcFlagFiles, ['chromium-launch.ts'], 'Chromium launch flags must be assembled ONLY in chromium-launch.ts')
  assert.deepEqual(chromiumLaunchCallFiles, ['chromium-launch.ts'], 'chromium.launch() must be called ONLY in chromium-launch.ts')
  assert.deepEqual(dynamicPlaywrightLoaderFiles, ['chromium-launch.ts'], 'Dynamic playwright-core loading must live ONLY in chromium-launch.ts')

  for (const [fnName, files] of exportedFnLocations) {
    assert.deepEqual(files, ['chromium-launch.ts'], `Exported function ${fnName} must not be duplicated (found in: ${files.join(', ')})`)
  }

  // Ensure the three browser entrypoints all import from ./chromium-launch.ts and have zero bare catch around Playwright.
  for (const caller of ['persona-auth.ts', 'browser-session-auth.ts', 'scoped-browser.ts']) {
    const src = readFileSync(join(SERVER_DIR, caller), 'utf8')
    assert.match(src, /from\s+['"]\.\/chromium-launch\.ts['"]/, `${caller} must import from ./chromium-launch.ts`)
  }

  const chromiumLaunchSrc = readFileSync(join(SERVER_DIR, 'chromium-launch.ts'), 'utf8')
  assert.equal(/catch\s*\{/.test(chromiumLaunchSrc), false, 'chromium-launch.ts must never use a bare catch {}')
  assert.match(chromiumLaunchSrc, /ERR_MODULE_NOT_FOUND/, 'loadPlaywrightChromium must filter strictly on MODULE_NOT_FOUND')
})

test('PR-22a: loadPlaywrightChromium falls back ONLY on MODULE_NOT_FOUND and rethrows real errors', async () => {
  const coreLauncher = { launch: async () => ({ id: 'core' }) }
  const testLauncher = { launch: async () => ({ id: 'test' }) }

  // 1. Prefers playwright-core when present.
  const calls1: string[] = []
  const res1 = await loadPlaywrightChromium({
    importModule: async specifier => {
      calls1.push(specifier)
      if (specifier === 'playwright-core') return { chromium: coreLauncher }
      return { chromium: testLauncher }
    },
  })
  assert.equal(res1, coreLauncher)
  assert.deepEqual(calls1, ['playwright-core'])

  // 2. Falls back to @playwright/test on ERR_MODULE_NOT_FOUND and MODULE_NOT_FOUND.
  for (const code of ['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND']) {
    const calls: string[] = []
    const res = await loadPlaywrightChromium({
      importModule: async specifier => {
        calls.push(specifier)
        if (specifier === 'playwright-core') {
          const err = Object.assign(new Error(`Cannot find package '${specifier}'`), { code })
          throw err
        }
        return { chromium: testLauncher }
      },
    })
    assert.equal(res, testLauncher)
    assert.deepEqual(calls, ['playwright-core', '@playwright/test'])
  }

  // 3. Rethrows real runtime / permission / syntax errors without falling back.
  for (const err of [
    Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' }),
    new SyntaxError('Unexpected token in playwright-core'),
    new Error('Native dependency failed to load'),
  ]) {
    const calls: string[] = []
    await assert.rejects(
      () =>
        loadPlaywrightChromium({
          importModule: async specifier => {
            calls.push(specifier)
            if (specifier === 'playwright-core') throw err
            return { chromium: testLauncher }
          },
        }),
      thrown => thrown === err,
    )
    assert.deepEqual(calls, ['playwright-core'], 'must NOT fall back to @playwright/test on non-MODULE_NOT_FOUND errors')
  }
})

test('PR-22a: all three browser entrypoints produce identical hardened Chromium args and options', () => {
  const baseArgs = buildChromiumLaunchArgs()
  assert.deepEqual(chromiumLaunchArgs(), baseArgs)
  assert.deepEqual(formChromiumLaunchArgs(), baseArgs)
  assert.deepEqual(browserSessionChromiumArgs({ env: {} }), baseArgs)
  assert.equal(baseArgs.includes('--no-sandbox'), false)

  const baseOpts = buildPlaywrightChromiumLaunchOptions({ env: {} })
  assert.deepEqual(buildChromiumLaunchOptions({ env: {} }), baseOpts)
  assert.deepEqual(buildFormChromiumLaunchOptions({ env: {} }), baseOpts)
  assert.deepEqual(buildBrowserSessionChromiumLaunchOptions({ env: {} }), baseOpts)
  assert.equal(baseOpts.chromiumSandbox, true)

  assert.equal(isInsecureNoSandboxEnabled({}), false)
  assert.equal(isInsecureNoSandboxEnabled({ KOVO_INSECURE_NO_SANDBOX: 'true' }), false)
  assert.equal(isInsecureNoSandboxEnabled({ KOVO_INSECURE_NO_SANDBOX: '1' }), true)

  const errA = formatChromiumSandboxError(new Error('No usable sandbox'))
  const errB = formatChromiumSandboxLaunchError(new Error('No usable sandbox'))
  assert.equal(errA.message, errB.message)
  assert.ok(errA.cause instanceof Error)
})

// ---------------------------------------------------------------------------
// 2. PR-22b: Worker mount & IPC permission hardening (M-8 / L-7)
// ---------------------------------------------------------------------------

test('PR-22b static guard: zero 0o777/0o666/0o444/0o711 worker RPC/IPC modes in verify-rpc.ts and worker-backend.ts', () => {
  const verifyRpcSrc = stripComments(readFileSync(join(SERVER_DIR, 'verify-rpc.ts'), 'utf8'))
  for (const forbidden of ['0o777', '0o666', '0o444', '0o711']) {
    assert.equal(
      verifyRpcSrc.includes(forbidden),
      false,
      `verify-rpc.ts must not contain world-accessible mode ${forbidden}`,
    )
  }

  const workerBackendSrc = stripComments(readFileSync(join(SERVER_DIR, 'worker-backend.ts'), 'utf8'))
  // Extract makeOneShotIpcDir and ensureRpcMountReadable bodies for precise mode verification.
  const makeIpcMatch = /function makeOneShotIpcDir[\s\S]*?\n\}/.exec(workerBackendSrc)
  assert.ok(makeIpcMatch, 'makeOneShotIpcDir must exist in worker-backend.ts')
  for (const forbidden of ['0o777', '0o666', '0o444']) {
    assert.equal(makeIpcMatch[0].includes(forbidden), false, `makeOneShotIpcDir must not use ${forbidden}`)
  }

  const ensureRpcMatch = /export function ensureRpcMountReadable[\s\S]*?\n\}/.exec(workerBackendSrc)
  assert.ok(ensureRpcMatch, 'ensureRpcMountReadable must exist in worker-backend.ts')
  for (const forbidden of ['0o777', '0o666', '0o444', '0o711', '0o011', '0o044', '0o066']) {
    assert.equal(ensureRpcMatch[0].includes(forbidden), false, `ensureRpcMountReadable must not use ${forbidden}`)
  }
})

test('PR-22b: VerifyRpcServer uses group-scoped 0o750/0o640/0o660 (non-10001) and 0o700/0o600 (UID 10001) with zero world bits', async t => {
  const dummyGrant: Grant = {
    canRead: () => false,
    audit: () => undefined,
  }
  const prevUmask = process.umask(0o077)
  t.after(() => { process.umask(prevUmask) })

  // 1. Standard non-10001 host UID -> group-scoped 0o750 / 0o640 / 0o660, zero world bits.
  const server = new VerifyRpcServer({
    broker: new RequestBroker({ rejectUnauthorized: false }),
    grant: dummyGrant,
    runId: 'run-r2-22-host',
    assignmentId: 'asgn-r2-22-host',
    targetOrigins: ['http://127.0.0.1:18080'],
  })
  t.after(() => server.close())
  await server.start()

  const dirMode = statSync(server.hostDir).mode & 0o777
  const tokenMode = statSync(join(server.hostDir, VERIFY_RPC_TOKEN_NAME)).mode & 0o777
  const contextMode = statSync(join(server.hostDir, VERIFY_RPC_CONTEXT_NAME)).mode & 0o777
  const sockMode = lstatSync(server.socketPath).mode & 0o777

  assert.equal(dirMode, 0o750)
  assert.equal(tokenMode, 0o640)
  assert.equal(contextMode, 0o640)
  assert.equal(sockMode, 0o660)
  assert.equal(dirMode & 0o007, 0)
  assert.equal(tokenMode & 0o007, 0)
  assert.equal(contextMode & 0o007, 0)
  assert.equal(sockMode & 0o007, 0)

  // 2. Host UID 10001 -> strictly owner-only 0o700 / 0o600, zero group or world bits.
  const origGetuid = process.getuid
  process.getuid = () => 10001
  try {
    const server10001 = new VerifyRpcServer({
      broker: new RequestBroker({ rejectUnauthorized: false }),
      grant: dummyGrant,
      runId: 'run-r2-22-10001',
      assignmentId: 'asgn-r2-22-10001',
      targetOrigins: ['http://127.0.0.1:18080'],
    })
    t.after(() => server10001.close())
    await server10001.start()

    assert.equal(statSync(server10001.hostDir).mode & 0o777, 0o700)
    assert.equal(statSync(join(server10001.hostDir, VERIFY_RPC_TOKEN_NAME)).mode & 0o777, 0o600)
    assert.equal(statSync(join(server10001.hostDir, VERIFY_RPC_CONTEXT_NAME)).mode & 0o777, 0o600)
    assert.equal(lstatSync(server10001.socketPath).mode & 0o777, 0o600)
  } finally {
    process.getuid = origGetuid
  }
})

test('PR-22b: ensureRpcMountReadable strips world bits, workerContainerCreateArgs emits --group-add (never 0), and one-shot IPC is 0o770/0o700', async t => {
  const scratch = mkdtempSync(join(tmpdir(), 'kovo-r2-22-ipc-'))
  t.after(() => rmSync(scratch, { recursive: true, force: true }))

  // 1. ensureRpcMountReadable strips world-readable/writable 0o755/0o444/0o666 down to 0o750/0o640/0o660.
  const rpcDir = join(scratch, 'rpc-world')
  mkdirSync(rpcDir, { mode: 0o755 })
  chmodSync(rpcDir, 0o755)
  const tokenPath = join(rpcDir, VERIFY_RPC_TOKEN_NAME)
  const contextPath = join(rpcDir, VERIFY_RPC_CONTEXT_NAME)
  const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
  writeFileSync(tokenPath, 'tok\n', { mode: 0o444 })
  chmodSync(tokenPath, 0o444)
  writeFileSync(contextPath, '{}\n', { mode: 0o444 })
  chmodSync(contextPath, 0o444)
  const sockServer = createServer()
  await new Promise<void>((resolveListen, rejectListen) => {
    sockServer.once('error', rejectListen)
    sockServer.listen(socketPath, () => {
      sockServer.off('error', rejectListen)
      resolveListen()
    })
  })
  t.after(() => new Promise<void>(resolveClose => sockServer.close(() => resolveClose())))
  chmodSync(socketPath, 0o666)

  ensureRpcMountReadable(rpcDir)
  assert.equal(statSync(rpcDir).mode & 0o777, 0o750)
  assert.equal(statSync(tokenPath).mode & 0o777, 0o640)
  assert.equal(statSync(contextPath).mode & 0o777, 0o640)
  assert.equal(lstatSync(socketPath).mode & 0o777, 0o660)

  // 2. resolveWorkerSharedGid + workerContainerCreateArgs --group-add contract.
  const origGetuid = process.getuid
  const origGetgid = process.getgid
  try {
    process.getuid = () => 1000
    process.getgid = () => 1042
    assert.equal(resolveWorkerSharedGid({}), 1042)
    assert.equal(resolveWorkerSharedGid({ KOVO_WORKER_SHARED_GID: '2050' }), 2050)
    assert.equal(resolveWorkerSharedGid({ KOVO_WORKER_SHARED_GID: '0' }), 1042, 'GID 0 override must be ignored')

    const nonRootArgs = workerContainerCreateArgs({
      image: 'kovo-worker:v4',
      name: 'kovo-00000000-0000-0000-0000-000000000010',
      assignmentId: 'asgn-gid',
      runLabel: 'run-gid',
      env: {},
    })
    const idx = nonRootArgs.indexOf('--group-add')
    assert.ok(idx >= 0 && nonRootArgs[idx + 1] === '1042')

    // Never emit --group-add 0 when host GID is 0.
    process.getgid = () => 0
    assert.equal(resolveWorkerSharedGid({}), null)
    const zeroGidArgs = workerContainerCreateArgs({
      image: 'kovo-worker:v4',
      name: 'kovo-00000000-0000-0000-0000-000000000011',
      assignmentId: 'asgn-gid0',
      runLabel: 'run-gid0',
      env: {},
    })
    assert.equal(zeroGidArgs.includes('--group-add'), false, 'must NEVER pass --group-add 0')

    // UID 10001 uses owner-only modes and omits --group-add.
    process.getuid = () => 10001
    process.getgid = () => 10001
    assert.equal(resolveWorkerSharedGid({}), null)
    const uid10001Args = workerContainerCreateArgs({
      image: 'kovo-worker:v4',
      name: 'kovo-00000000-0000-0000-0000-000000000012',
      assignmentId: 'asgn-10001',
      runLabel: 'run-10001',
      env: {},
    })
    assert.equal(uid10001Args.includes('--group-add'), false)
  } finally {
    process.getuid = origGetuid
    process.getgid = origGetgid
  }

  // 3. LinuxWorkerBackend.run() creates one-shot /kovo-ipc dir as 0o770 (non-10001) with zero world bits.
  const prevUmask = process.umask(0o077)
  t.after(() => { process.umask(prevUmask) })
  let observedIpcMode = -1
  let observedGroupAdd: string | undefined
  const backend = new LinuxWorkerBackend({
    dockerRunner: async args => {
      if (args[0] === 'container' && args[1] === 'create') {
        const ipcMount = args.find(a => a.includes('target=/kovo-ipc')) ?? ''
        const m = /^type=bind,source=([^,]+),target=\/kovo-ipc$/.exec(ipcMount)
        assert.ok(m && m[1], `expected /kovo-ipc mount, got: ${ipcMount}`)
        observedIpcMode = statSync(m[1]).mode & 0o777
        const gIdx = args.indexOf('--group-add')
        observedGroupAdd = gIdx >= 0 ? args[gIdx + 1] : undefined
        return 'created'
      }
      if (args[0] === 'container' && args[1] === 'start') {
        return JSON.stringify({ exitCode: 0, stdout: 'ok', stderr: '', outputs: {} })
      }
      return ''
    },
  })
  const runResult = await backend.run(
    { assignmentId: randomUUID(), files: [], command: 'true', outputs: [] },
    AbortSignal.timeout(5_000),
  )
  assert.equal(runResult.exitCode, 0)
  assert.equal(observedIpcMode, 0o770, 'one-shot /kovo-ipc must be group-writable 0o770 (never 0o777)')
  assert.equal(observedIpcMode & 0o007, 0, 'one-shot /kovo-ipc must have zero world bits')
  if (typeof process.getgid === 'function' && process.getgid() > 0) {
    assert.equal(observedGroupAdd, String(process.getgid()))
  }
})

// ---------------------------------------------------------------------------
// 3. PR-22c: Warn-only function-length & file-growth ratchet
// ---------------------------------------------------------------------------

test(
  'PR-22c: check-function-growth.ts runs fast (<2s) in warn-only mode and fails only under --strict',
  { timeout: process.env.CI ? 45_000 : 25_000 },
  t => {
    const CI_TIMING_MULT = process.env.CI ? 8 : 1
    const maxScanMs = 2_000 * CI_TIMING_MULT
    // 1. Live scan over src/server/ in warn-only mode.
    const live = runFunctionGrowthCheck({ rootDir: REPO_ROOT, dir: 'src/server' })
    assert.equal(live.ok, true, 'warn-only mode must always return ok=true')
    assert.equal(live.strict, false)
    assert.ok(live.durationMs < maxScanMs, `expected <${maxScanMs}ms scan, took ${live.durationMs}ms`)
  assert.ok(live.filesScanned >= 40, `expected >=40 src/server files, got ${live.filesScanned}`)
  assert.ok(live.functionsScanned >= 200, `expected >=200 functions, got ${live.functionsScanned}`)
  assert.ok(
    live.oversizedFunctions.some(fn => fn.name === 'decideApproval' && fn.file.endsWith('store-runs.ts')),
    'analyzer should detect known oversized function decideApproval in store-runs.ts',
  )

  // 2. Deterministic synthetic fixture: warn-only exits 0; --strict exits 1 on oversized and 0 on clean.
  const dir = mkdtempSync(join(tmpdir(), 'kovo-fn-growth-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const bodyLines = Array.from({ length: 25 }, (_, i) => `  const v${i} = ${i}`).join('\n')
  writeFileSync(
    join(dir, 'sample.ts'),
    `export function giantHelper(): number {\n${bodyLines}\n  return v0\n}\n`,
  )

  const warnReport = runFunctionGrowthCheck({ rootDir: dir, dir: '.', maxFnLines: 10, maxFileLines: 100, strict: false })
  assert.equal(warnReport.ok, true)
  assert.equal(warnReport.oversizedFunctions.length, 1)
  assert.equal(warnReport.oversizedFunctions[0]!.name, 'giantHelper')

  const strictFail = runFunctionGrowthCheck({ rootDir: dir, dir: '.', maxFnLines: 10, maxFileLines: 100, strict: true })
  assert.equal(strictFail.ok, false)

  const strictPass = runFunctionGrowthCheck({ rootDir: dir, dir: '.', maxFnLines: 50, maxFileLines: 100, strict: true })
  assert.equal(strictPass.ok, true)

  // 3. CLI smoke test (warn-only exit 0).
  const cliOut = execFileSync(
    process.execPath,
    [join(REPO_ROOT, 'scripts', 'check-function-growth.ts'), '--dir', 'src/server'],
    { cwd: REPO_ROOT, encoding: 'utf8' },
  )
  assert.match(cliOut, /check-function-growth \[WARN-ONLY\] PASS/)
})
