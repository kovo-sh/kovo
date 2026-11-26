// Regression tests for non-root Docker worker (UID 10001) permissions under host umask 0077.
// Covers:
//   1. kovo_verify SDK staging (`prepareVerifySdkMount` / `readVerifySdkFiles`) on 0700/0600 host paths
//   2. `/kovo-rpc` bind-mount permission hardening (`ensureRpcMountReadable` / `workerContainerCreateArgs`)
//   3. Direct `WarmWorkerPool` staging of 0700/0600 `reposDir`
//   4. `worker/Dockerfile` chmod + non-root UID 10001 build-time readability/boot invariants
import assert from 'node:assert/strict'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  VERIFY_RPC_CONTEXT_NAME,
  VERIFY_RPC_SOCKET_NAME,
  VERIFY_RPC_TOKEN_NAME,
} from '../src/server/verify-rpc.ts'
import {
  WarmWorkerPool,
  ensureRpcMountReadable,
  prepareVerifySdkMount,
  readVerifySdkFiles,
  workerContainerCreateArgs,
} from '../src/server/worker-backend.ts'

function withUmask077<T>(fn: () => T): T {
  const prev = process.umask(0o077)
  try {
    return fn()
  } finally {
    process.umask(prev)
  }
}

async function withUmask077Async<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.umask(0o077)
  try {
    return await fn()
  } finally {
    process.umask(prev)
  }
}

test('prepareVerifySdkMount stages 0o700/0o600 mock SDK into 0o755/0o644 container-readable copy under umask 0077', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'kovo-sdk-perms-'))
  try {
    withUmask077(() => {
      const mockSdkDir = join(scratch, 'kovo_verify')
      mkdirSync(mockSdkDir, { mode: 0o700 })
      chmodSync(mockSdkDir, 0o700)
      const mockSdkFile = join(mockSdkDir, 'kovo_verify.ts')
      const sdkBody = 'export const KOVO_VERIFY_TEST_SDK = "ok"\n'
      writeFileSync(mockSdkFile, sdkBody, { mode: 0o600 })
      chmodSync(mockSdkFile, 0o600)

      assert.equal(statSync(mockSdkDir).mode & 0o777, 0o700, 'precondition: host SDK dir is 0o700')
      assert.equal(statSync(mockSdkFile).mode & 0o777, 0o600, 'precondition: host SDK file is 0o600')

      const prepared = prepareVerifySdkMount(mockSdkDir)
      try {
        assert.equal(prepared.staged, true, '0o700/0o600 SDK dir must be staged for UID 10001 readability')
        assert.notEqual(prepared.mountDir, realpathSync(mockSdkDir))

        const stagedDirMode = statSync(prepared.mountDir).mode & 0o777
        const stagedFile = join(prepared.mountDir, 'kovo_verify.ts')
        const stagedFileMode = statSync(stagedFile).mode & 0o777
        assert.equal(stagedDirMode, 0o755, 'staged SDK dir must be 0o755')
        assert.equal(stagedDirMode & 0o005, 0o005, 'staged SDK dir must grant o+rx for container UID 10001')
        assert.equal(stagedFileMode, 0o644, 'staged kovo_verify.ts must be 0o644')
        assert.equal(stagedFileMode & 0o004, 0o004, 'staged kovo_verify.ts must grant o+r for container UID 10001')
        assert.equal(readFileSync(stagedFile, 'utf8'), sdkBody)

        // Original host files must remain untouched.
        assert.equal(statSync(mockSdkDir).mode & 0o777, 0o700)
        assert.equal(statSync(mockSdkFile).mode & 0o777, 0o600)

        // readVerifySdkFiles reads cleanly from both explicit 0700/0600 path and KOVO_VERIFY_SDK_DIR env.
        const loadedDirect = readVerifySdkFiles(mockSdkDir)
        assert.deepEqual(loadedDirect, [{ name: 'kovo_verify.ts', content: sdkBody }])

        const prevEnv = process.env.KOVO_VERIFY_SDK_DIR
        process.env.KOVO_VERIFY_SDK_DIR = mockSdkDir
        try {
          const loadedEnv = readVerifySdkFiles()
          assert.deepEqual(loadedEnv, [{ name: 'kovo_verify.ts', content: sdkBody }])
        } finally {
          if (prevEnv === undefined) delete process.env.KOVO_VERIFY_SDK_DIR
          else process.env.KOVO_VERIFY_SDK_DIR = prevEnv
        }
      } finally {
        const stagedDir = prepared.mountDir
        prepared.cleanup()
        prepared.cleanup() // idempotent
        assert.equal(existsSync(stagedDir), false, 'cleanup must remove staged SDK directory')
      }

      // Already world-readable 0o755/0o644 SDK directory binds directly without copying.
      chmodSync(mockSdkDir, 0o755)
      chmodSync(mockSdkFile, 0o644)
      const direct = prepareVerifySdkMount(mockSdkDir)
      assert.equal(direct.staged, false, '0o755/0o644 SDK dir should not be unnecessarily copied')
      assert.equal(direct.mountDir, realpathSync(mockSdkDir))
      direct.cleanup()
      assert.equal(existsSync(mockSdkFile), true, 'direct cleanup must never delete caller SDK dir')
    })
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('ensureRpcMountReadable & workerContainerCreateArgs make 0o700/0o600 rpcMountDir accessible to container UID 10001', async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'kovo-rpc-perms-'))
  const server = createServer()
  try {
    await withUmask077Async(async () => {
      const rpcDir = join(scratch, 'rpc-restricted')
      mkdirSync(rpcDir, { mode: 0o700 })
      chmodSync(rpcDir, 0o700)
      const tokenPath = join(rpcDir, VERIFY_RPC_TOKEN_NAME)
      const contextPath = join(rpcDir, VERIFY_RPC_CONTEXT_NAME)
      const socketPath = join(rpcDir, VERIFY_RPC_SOCKET_NAME)
      writeFileSync(tokenPath, 'test-token\n', { mode: 0o600 })
      chmodSync(tokenPath, 0o600)
      writeFileSync(contextPath, '{"nonce":"abc"}\n', { mode: 0o600 })
      chmodSync(contextPath, 0o600)
      await new Promise<void>((resolve, reject) => {
        server.once('error', reject)
        server.listen(socketPath, () => {
          server.off('error', reject)
          resolve()
        })
      })
      chmodSync(socketPath, 0o600)

      assert.equal(statSync(rpcDir).mode & 0o777, 0o700)
      assert.equal(statSync(tokenPath).mode & 0o777, 0o600)
      assert.equal(statSync(contextPath).mode & 0o777, 0o600)
      assert.equal(lstatSync(socketPath).mode & 0o777, 0o600)

      const resolved = ensureRpcMountReadable(rpcDir)
      assert.equal(resolved, realpathSync(rpcDir))
      assert.equal(statSync(rpcDir).mode & 0o001, 0o001, 'RPC dir must grant o+x traversal for UID 10001')
      assert.equal(statSync(rpcDir).mode & 0o004, 0, 'RPC dir should stay non-listable (0o711) when upgraded from 0o700')
      assert.equal(statSync(tokenPath).mode & 0o004, 0o004, 'RPC token must grant o+r for UID 10001')
      assert.equal(statSync(contextPath).mode & 0o004, 0o004, 'RPC context.json must grant o+r for UID 10001')
      assert.equal(lstatSync(socketPath).mode & 0o006, 0o006, 'RPC Unix socket must grant o+rw for UID 10001')

      // Re-restrict and confirm workerContainerCreateArgs enforces the same guarantee automatically.
      chmodSync(rpcDir, 0o700)
      chmodSync(tokenPath, 0o600)
      chmodSync(contextPath, 0o600)
      chmodSync(socketPath, 0o600)

      const args = workerContainerCreateArgs({
        image: 'kovo-worker:v4',
        name: 'kovo-00000000-0000-0000-0000-000000000001',
        assignmentId: 'asgn-rpc-perms',
        runLabel: 'run-rpc-perms',
        options: { rpcMountDir: rpcDir },
      })
      assert.ok(args.includes(`type=bind,source=${realpathSync(rpcDir)},target=/kovo-rpc,readonly`))
      assert.equal(statSync(rpcDir).mode & 0o001, 0o001)
      assert.equal(statSync(tokenPath).mode & 0o004, 0o004)
      assert.equal(statSync(contextPath).mode & 0o004, 0o004)
      assert.equal(lstatSync(socketPath).mode & 0o006, 0o006)
    })
  } finally {
    await new Promise<void>(resolve => server.close(() => resolve()))
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('WarmWorkerPool stages 0o700/0o600 reposDir into 0o755/0o644 readable mount and cleans up on close()', async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'kovo-warm-perms-'))
  try {
    await withUmask077Async(async () => {
      const reposDir = join(scratch, 'restricted-repo')
      mkdirSync(reposDir, { mode: 0o700 })
      chmodSync(reposDir, 0o700)
      const file = join(reposDir, 'index.ts')
      writeFileSync(file, 'export const ok = 1\n', { mode: 0o600 })
      chmodSync(file, 0o600)

      let observedMountDir = ''
      const runner = async (args: string[]) => {
        if (args[0] === 'container' && args[1] === 'create') {
          const mountArg = args.find(arg => arg.includes('target=/repos,readonly')) ?? ''
          observedMountDir = /^type=bind,source=([^,]+),target=\/repos,readonly$/.exec(mountArg)?.[1] ?? ''
          return 'created'
        }
        return ''
      }

      const pool = new WarmWorkerPool({
        cell: 'cell-perms-test',
        image: 'kovo-worker:v4',
        dockerRunner: runner,
        runLabel: 'run-perms-test',
        options: { reposDir },
        capacity: 1,
      })

      let taken: string | null = null
      try {
        const warmed = await pool.warm()
        assert.ok(warmed, 'warm pool must prewarm container')
        assert.ok(observedMountDir, 'container create must bind-mount /repos')
        assert.notEqual(observedMountDir, realpathSync(reposDir), '0o700 reposDir must be staged')
        assert.equal(statSync(observedMountDir).mode & 0o777, 0o755)
        assert.equal(statSync(join(observedMountDir, 'index.ts')).mode & 0o777, 0o644)

        // Caller passing original reposDir still matches the warm pool signature.
        taken = await pool.take(AbortSignal.timeout(5_000), { reposDir })
        assert.equal(taken, warmed, 'warm pool take() must match caller reposDir signature')
      } finally {
        await pool.close()
      }
      // Move Q1: close() defers staged /repos deletion while an active taken container is still
      // outstanding, and cleans it up as soon as the last outstanding container is released.
      assert.equal(existsSync(observedMountDir), true, 'WarmWorkerPool.close() must defer staged /repos cleanup while a container is still checked out')
      if (taken) await pool.release(taken)
      assert.equal(existsSync(observedMountDir), false, 'WarmWorkerPool must clean up staged /repos dir once outstanding containers are released')
    })
  } finally {
    rmSync(scratch, { recursive: true, force: true })
  }
})

test('worker/Dockerfile grants world-readable permissions across /opt/kovo-worker and /opt/kovo-rules and runs UID 10001 boot check', () => {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
  const dockerfile = readFileSync(join(repoRoot, 'worker', 'Dockerfile'), 'utf8')

  assert.match(
    dockerfile,
    /chmod 0644 \/opt\/kovo-worker\/package\.json \/opt\/kovo-worker\/package-lock\.json/,
    'Dockerfile must chmod 0644 package.json & package-lock.json after COPY (immune to host umask 0077)',
  )
  assert.match(
    dockerfile,
    /chmod -R a\+rX \/opt\/kovo-worker(?:\s|$)/,
    'Dockerfile must chmod -R a+rX /opt/kovo-worker',
  )
  assert.match(
    dockerfile,
    /chmod -R a\+rX \/opt\/kovo-worker \/opt\/kovo-rules/,
    'Dockerfile must apply chmod -R a+rX across /opt/kovo-worker and /opt/kovo-rules after final COPY',
  )
  assert.match(
    dockerfile,
    /USER 10001:10001[\s\S]*find \/opt\/kovo-worker \/opt\/kovo-rules ! -readable[\s\S]*bridge\.ts --session/,
    'Dockerfile must verify non-root UID 10001 readability and bridge.ts boot at build time',
  )
})
