import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import * as githubAuth from '../src/server/github-auth.ts'
import * as githubConnector from '../src/server/github-connector.ts'
import * as githubRepoSync from '../src/server/github-repo-sync.ts'
import * as labProxy from '../src/server/lab-proxy.ts'
import * as labRunner from '../src/server/lab-runner.ts'
import * as labTelemetry from '../src/server/lab-telemetry.ts'
import type { DockerRunner, LabContainerStore } from '../src/server/lab-runner.ts'
import type { Store } from '../src/server/store.ts'

const SERVER_DIR = resolve(import.meta.dirname, '../src/server')

function lineCount(fileName: string): number {
  const text = readFileSync(join(SERVER_DIR, fileName), 'utf8')
  return text.split('\n').length
}

function readSource(fileName: string): string {
  return readFileSync(join(SERVER_DIR, fileName), 'utf8')
}

test('arch-c3 line budgets: lab-runner <= 1,800 LOC and github-connector <= 150 LOC barrel', () => {
  const labRunnerLines = lineCount('lab-runner.ts')
  const labTelemetryLines = lineCount('lab-telemetry.ts')
  const labProxyLines = lineCount('lab-proxy.ts')
  const githubConnectorLines = lineCount('github-connector.ts')
  const githubAuthLines = lineCount('github-auth.ts')
  const githubRepoSyncLines = lineCount('github-repo-sync.ts')

  assert.ok(labRunnerLines <= 1800, `Expected lab-runner.ts <= 1800 LOC, got ${labRunnerLines}`)
  assert.ok(githubConnectorLines <= 150, `Expected github-connector.ts <= 150 LOC barrel, got ${githubConnectorLines}`)
  assert.ok(labTelemetryLines > 100, `Expected lab-telemetry.ts to hold extracted telemetry logic, got ${labTelemetryLines}`)
  assert.ok(labProxyLines > 300, `Expected lab-proxy.ts to hold extracted proxy/network logic, got ${labProxyLines}`)
  assert.ok(githubAuthLines > 400, `Expected github-auth.ts to hold extracted auth/discovery logic, got ${githubAuthLines}`)
  assert.ok(githubRepoSyncLines > 400, `Expected github-repo-sync.ts to hold extracted clone/sync logic, got ${githubRepoSyncLines}`)
})

test('arch-c3 module boundaries: strictly acyclic imports and pure github-connector barrel', () => {
  const labProxySrc = readSource('lab-proxy.ts')
  const labTelemetrySrc = readSource('lab-telemetry.ts')
  const githubAuthSrc = readSource('github-auth.ts')
  const githubRepoSyncSrc = readSource('github-repo-sync.ts')
  const githubConnectorSrc = readSource('github-connector.ts')

  assert.equal(/from\s+['"]\.\/lab-(?:runner|telemetry)\.ts['"]/.test(labProxySrc), false, 'lab-proxy.ts must not depend on lab-runner.ts or lab-telemetry.ts')
  assert.equal(/from\s+['"]\.\/lab-runner\.ts['"]/.test(labTelemetrySrc), false, 'lab-telemetry.ts must not depend on lab-runner.ts')
  assert.equal(/from\s+['"]\.\/github-(?:connector|repo-sync)\.ts['"]/.test(githubAuthSrc), false, 'github-auth.ts must not depend on github-connector.ts or github-repo-sync.ts')
  assert.equal(/from\s+['"]\.\/github-connector\.ts['"]/.test(githubRepoSyncSrc), false, 'github-repo-sync.ts must not depend on github-connector.ts')

  // github-connector.ts must remain a pure re-export facade with no local runtime declarations.
  assert.equal(/^\s*(?:export\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+/m.test(githubConnectorSrc), false, 'github-connector.ts must be a pure barrel facade')
  assert.match(githubConnectorSrc, /from\s+['"]\.\/github-auth\.ts['"]/)
  assert.match(githubConnectorSrc, /from\s+['"]\.\/github-repo-sync\.ts['"]/)
})

test('arch-c3 export parity: lab-runner facade preserves 100% of public runtime exports', () => {
  const expectedLabExports = [
    'LAB_CONTAINER_USER_ENV',
    'LAB_DB_VOLUMES_ENV',
    'LAB_LABELS',
    'LAB_PATHS',
    'LAB_PROXY_IMAGE_DEFAULT',
    'LAB_PROXY_IMAGE_ENV',
    'LAB_PROXY_SCRIPT',
    'LAB_STATE_DIR_ENV',
    'LabRunner',
    'MAX_IAST_TELEMETRY_RUN_DIRS',
    'MAX_IAST_TELEMETRY_TOTAL_BYTES',
    'applyUnifiedDiffToDirectory',
    'assertIastTelemetryDirWritable',
    'assertLocalLabAllowed',
    'bindLabSignalHooks',
    'buildIastTelemetryMountArgs',
    'buildLabContainerRunArgs',
    'buildLabNetworkCreateArgs',
    'buildLabProxyRunArgs',
    'buildWritableDataOverlay',
    'createLabProxyDir',
    'createLoopbackSocketForwarder',
    'createPerRunIastTelemetryDir',
    'defaultLabDatabasePort',
    'deriveHealthPathFromHealthcheck',
    'detectLabDatabaseKind',
    'ingestLabTelemetry',
    'labDataVolumeName',
    'labProxySocketMode',
    'labRunRecordPath',
    'labStateDir',
    'normalizeImageRepository',
    'parseAndSanitizeComposeYaml',
    'prepareIastTelemetryDir',
    'pruneLabTelemetryDirs',
    'readLabRunRecord',
    'removeLabRunRecord',
    'resolveLabContainerUser',
    'rewriteSqliteDatabaseUrl',
    'safeRemoveLabTempDir',
    'safeResolveUnderRoot',
    'validateLabRunId',
    'waitForLabProxySocket',
    'writeLabProxyTarget',
    'writeLabRunRecord',
  ].sort()

  const actualLabExports = Object.keys(labRunner).sort()
  assert.deepEqual(actualLabExports, expectedLabExports)

  // Verify identity parity between facade and extracted modules.
  const telemetrySymbols = [
    'MAX_IAST_TELEMETRY_RUN_DIRS',
    'MAX_IAST_TELEMETRY_TOTAL_BYTES',
    'assertIastTelemetryDirWritable',
    'buildIastTelemetryMountArgs',
    'createPerRunIastTelemetryDir',
    'ingestLabTelemetry',
    'prepareIastTelemetryDir',
    'pruneLabTelemetryDirs',
  ] as const
  for (const sym of telemetrySymbols) {
    assert.strictEqual(labRunner[sym], labTelemetry[sym], `lab-runner.${sym} must re-export lab-telemetry.${sym}`)
  }

  const proxySymbols = [
    'LAB_CONTAINER_USER_ENV',
    'LAB_DB_VOLUMES_ENV',
    'LAB_LABELS',
    'LAB_PATHS',
    'LAB_PROXY_IMAGE_DEFAULT',
    'LAB_PROXY_IMAGE_ENV',
    'LAB_PROXY_SCRIPT',
    'LAB_STATE_DIR_ENV',
    'buildLabContainerRunArgs',
    'buildLabNetworkCreateArgs',
    'buildLabProxyRunArgs',
    'buildWritableDataOverlay',
    'createLabProxyDir',
    'createLoopbackSocketForwarder',
    'defaultLabDatabasePort',
    'deriveHealthPathFromHealthcheck',
    'detectLabDatabaseKind',
    'labDataVolumeName',
    'labProxySocketMode',
    'normalizeImageRepository',
    'parseAndSanitizeComposeYaml',
    'resolveLabContainerUser',
    'rewriteSqliteDatabaseUrl',
    'safeRemoveLabTempDir',
    'validateLabRunId',
    'waitForLabProxySocket',
    'writeLabProxyTarget',
  ] as const
  for (const sym of proxySymbols) {
    assert.strictEqual(labRunner[sym], labProxy[sym], `lab-runner.${sym} must re-export lab-proxy.${sym}`)
  }
})

test('arch-c3 export parity: github-connector barrel preserves 100% of public runtime exports', () => {
  const expectedGithubExports = [
    'DEFAULT_GITHUB_API_BASE_URL',
    'DEFAULT_GITHUB_BASE_URL',
    'DEFAULT_GITHUB_MAX_AUTO_SELECT',
    'DEFAULT_GITHUB_PAT_PATH',
    'cancelGithubDeviceFlow',
    'classifyGithubPatKind',
    'clearGithubPat',
    'cloneGithubRepos',
    'defaultSelectedRepoNames',
    'getGithubAuthStatus',
    'getGithubPatStatus',
    'githubAppInstallUrl',
    'hasGithubPat',
    'listAccessibleGithubRepos',
    'listMountedRepos',
    'parseDependenciesFromFile',
    'pollGithubDeviceFlow',
    'projectReposDir',
    'readGithubVaultCredential',
    'readRepoCommitDiffs',
    'resolveGithubAppSlug',
    'resolveGithubClientId',
    'resolveGithubPatPath',
    'saveGithubClientId',
    'saveGithubPat',
    'saveGithubVaultCredential',
    'startGithubDeviceFlow',
    'syncGithubRepos',
  ].sort()

  const actualGithubExports = Object.keys(githubConnector).sort()
  assert.deepEqual(actualGithubExports, expectedGithubExports)

  const authSymbols = [
    'DEFAULT_GITHUB_API_BASE_URL',
    'DEFAULT_GITHUB_BASE_URL',
    'DEFAULT_GITHUB_MAX_AUTO_SELECT',
    'DEFAULT_GITHUB_PAT_PATH',
    'cancelGithubDeviceFlow',
    'classifyGithubPatKind',
    'clearGithubPat',
    'defaultSelectedRepoNames',
    'getGithubAuthStatus',
    'getGithubPatStatus',
    'githubAppInstallUrl',
    'hasGithubPat',
    'listAccessibleGithubRepos',
    'pollGithubDeviceFlow',
    'readGithubVaultCredential',
    'resolveGithubAppSlug',
    'resolveGithubClientId',
    'resolveGithubPatPath',
    'saveGithubClientId',
    'saveGithubPat',
    'saveGithubVaultCredential',
    'startGithubDeviceFlow',
  ] as const
  for (const sym of authSymbols) {
    assert.strictEqual(githubConnector[sym], githubAuth[sym], `github-connector.${sym} must re-export github-auth.${sym}`)
  }

  const syncSymbols = [
    'cloneGithubRepos',
    'listMountedRepos',
    'parseDependenciesFromFile',
    'projectReposDir',
    'readRepoCommitDiffs',
    'syncGithubRepos',
  ] as const
  for (const sym of syncSymbols) {
    assert.strictEqual(githubConnector[sym], githubRepoSync[sym], `github-connector.${sym} must re-export github-repo-sync.${sym}`)
  }
})

test('arch-c3 crash-recovery consolidation: skips duplicate tmpdir JSON record when SQLite store is attached', async t => {
  const workspace = mkdtempSync(join(tmpdir(), 'guardian-arch-c3-state-'))
  t.after(() => rmSync(workspace, { recursive: true, force: true }))
  const repoDir = join(workspace, 'repo')
  const stateDir = join(workspace, 'state')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.js'), "require('http').createServer((_q, r) => r.end('ok')).listen(8080)\n")

  const rows = new Map<string, { runId: string; containerName: string; status: string }>()
  const store: LabContainerStore = {
    recordLabContainer(input) {
      rows.set(`${input.runId}/${input.containerName}`, {
        runId: input.runId,
        containerName: input.containerName,
        status: input.status ?? 'running',
      })
    },
    markLabContainerOrphaned(runId, containerName) {
      const row = rows.get(`${runId}/${containerName}`)
      if (row) row.status = 'orphaned'
    },
    listLabContainers(runId) {
      return [...rows.values()].filter(r => r.runId === runId)
    },
  }

  const live = new Map<string, string>()
  const servers: Array<{ close: (cb: () => void) => void }> = []
  let seq = 0
  const docker: DockerRunner = async args => {
    if (args[0] === 'network' || args[0] === 'volume' || args[0] === 'build' || args[0] === 'exec' || args[0] === 'ps') return ''
    if (args[0] === 'run') {
      const name = args[args.indexOf('--name') + 1]
      if (name.includes('-proxy-')) {
        const mountArg = args.find(arg => arg.startsWith('type=bind,source=')) ?? ''
        const dir = mountArg.slice('type=bind,source='.length, mountArg.indexOf(',target='))
        const server = createServer(socket => {
          socket.once('data', () => socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'))
          socket.on('error', () => undefined)
        })
        await new Promise<void>(resolvePromise => server.listen(join(dir, 'proxy.sock'), resolvePromise))
        servers.push(server)
      }
      seq += 1
      live.set(name, `a${String(seq).padStart(11, '0')}`)
      return ''
    }
    if (args[0] === 'inspect') {
      const name = args[args.length - 1]
      const format = args[2] ?? ''
      if (!live.has(name)) throw new Error(`No such container: ${name}`)
      if (format === '{{.Id}}') return live.get(name)!
      if (format.includes('NetworkSettings')) return '172.18.0.5'
      return 'running exit=0'
    }
    if (args[0] === 'container' && args[1] === 'rm') {
      live.delete(args[args.length - 1])
      return ''
    }
    return ''
  }
  t.after(async () => {
    await Promise.all(servers.map(s => new Promise<void>(r => s.close(() => r()))))
  })

  const prevAllow = process.env.GUARDIAN_ALLOW_LOCAL_LAB
  process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'
  try {
    const runner = new labRunner.LabRunner({ docker, stateDir })
    await runner.startLabTarget({
      runId: 'run-store-backed',
      environment: 'local-lab',
      repoDir,
      storage: store as unknown as Store,
      labConfig: {
        enabled: true,
        image: 'node:24-bookworm-slim',
        startCommand: 'node /app/server.js',
        internalPort: 8080,
        healthPath: '/health',
        healthTimeoutMs: 5_000,
      },
      signal: AbortSignal.timeout(15_000),
    })

    assert.equal(store.listLabContainers('run-store-backed').length, 2, 'SQLite store holds both containers')
    assert.equal(existsSync(labRunner.labRunRecordPath(stateDir, 'run-store-backed')), false, 'no duplicate tmpdir JSON record written when SQLite store is attached')
    await runner.stopLabTarget('run-store-backed')

    // Standalone (without storage) still writes the JSON crash-recovery record.
    await runner.startLabTarget({
      runId: 'run-standalone',
      environment: 'local-lab',
      repoDir,
      labConfig: {
        enabled: true,
        image: 'node:24-bookworm-slim',
        startCommand: 'node /app/server.js',
        internalPort: 8080,
        healthPath: '/health',
        healthTimeoutMs: 5_000,
      },
      signal: AbortSignal.timeout(15_000),
    })
    assert.equal(existsSync(labRunner.labRunRecordPath(stateDir, 'run-standalone')), true, 'standalone caller writes JSON recovery record')
    await runner.stopLabTarget('run-standalone')
    assert.deepEqual(existsSync(stateDir) ? readdirSync(stateDir) : [], [], 'stopLabTarget cleans up standalone record')
  } finally {
    if (prevAllow === undefined) delete process.env.GUARDIAN_ALLOW_LOCAL_LAB
    else process.env.GUARDIAN_ALLOW_LOCAL_LAB = prevAllow
  }
})
