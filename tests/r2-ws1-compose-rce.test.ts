/**
 * Regression suite for R2-C-1 (Critical):
 *   Compose `image:` value becomes an injected `docker run` option (host bind mount / privilege escalation).
 *
 * Verifies:
 *   1. Strict OCI `[registry/]repo[:tag][@digest]` image validation rejects leading `-`, whitespace,
 *      control chars, `=`, traversal (`..`), and malformed refs at compose-parse, sanitizer,
 *      LabConfig, and `docker run` argv builder boundaries.
 *   2. `--` is placed strictly before the image positional (and `--pull=never` before `--`) in
 *      both `buildLabContainerRunArgs` and `buildLabProxyRunArgs`.
 *   3. Untrusted lab service containers (compose primary without IAST, all sidecars, and patch
 *      rebuilds) run as dedicated unprivileged uid:gid `65534:65534` (not Kovo's uid) while keeping
 *      non-root numeric validation enforced in every `docker run` argv builder.
 */
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  ComposeParseError,
  isValidOciImageReference,
  parseComposeDocument,
  validateOciImageReference,
} from '../src/server/compose-parse.ts'
import type { ParsedComposeDocument } from '../src/server/compose-parse.ts'
import {
  DEFAULT_UNPRIVILEGED_LAB_USER,
  LAB_LABELS,
  LAB_PROXY_IMAGE_ENV,
  assertSafeLabImageReference,
  buildLabContainerRunArgs,
  buildLabProxyRunArgs,
  parseAndSanitizeComposeYaml,
  resolveLabContainerUser,
  resolveLabServiceContainerUser,
  resolveLabStackServices,
  resolveStartCommand,
  sanitizeParsedComposeDocument,
  validateRawServiceObject,
} from '../src/server/lab-proxy.ts'
import { LabRunner } from '../src/server/lab-runner.ts'
import type { DockerRunner } from '../src/server/lab-runner.ts'
import { closeSharedUntrustedComputePool, parseComposeInWorker } from '../src/server/untrusted-compute-pool.ts'

const SHA256_SAMPLE = '0123456789abcdef'.repeat(4)
const SHA384_SAMPLE = 'a1b2c3d4'.repeat(12)
const SHA512_SAMPLE = 'fedcba9876543210'.repeat(8)

const MALICIOUS_IMAGE_STRINGS = [
  '--volume=/:/host:rw',
  '--volume=/etc:/host',
  '-v',
  '-v /:/host',
  '--privileged',
  '--user=0:0',
  '--network=host',
  '--cap-add=SYS_ADMIN',
  '--label=kovo.test=1',
  '-',
  'node:24 --privileged',
  ' node:24',
  'node:24 ',
  'node:24\t--privileged',
  'node:24\n--privileged',
  'node:24\r',
  'node:24\x00',
  'node:24\x1b',
  'node:24\x7f',
  'node:tag=val',
  'foo=bar/app:1',
  'volume=/:/host',
  '../etc/passwd',
  'foo..bar/app:1',
  '/etc/passwd',
  'node:24:extra',
  'Node:24',
  'node:-badtag',
  'node:.badtag',
  'node:24@sha256:deadbeef',
  `node:24@md5:${'a'.repeat(32)}`,
  `node:24@sha256:${'A'.repeat(64)}`,
  'registry.example.com:99999/app:1',
  'registry.example.com:0/app:1',
  'foo:bar/app:1',
  'ghcr.io/org:123/app:1',
  '',
  'a'.repeat(256),
] as const

const VALID_IMAGE_STRINGS = [
  'node:24-bookworm-slim',
  'postgres:16-alpine',
  'redis:7',
  'ubuntu',
  'kovo-worker:local',
  'kovo-lab-img-app-0123456789:local',
  'docker.io/library/postgres:16',
  'ghcr.io/org/sub_repo/my-app.v2:1.2.3-rc.1',
  'localhost:5000/my-app:latest',
  'registry.example.com:5000/team/svc:v1',
  `ubuntu@sha256:${SHA256_SAMPLE}`,
  `ghcr.io/org/app:v1.0@sha256:${SHA256_SAMPLE}`,
  `app@sha384:${SHA384_SAMPLE}`,
  `app@sha512:${SHA512_SAMPLE}`,
] as const

function createFakeLabDocker() {
  const calls: string[][] = []
  const runCalls: Array<{ name: string; args: string[] }> = []
  const live = new Map<string, { id: string; runId: string }>()
  const servers: Array<{ close: (cb: () => void) => void }> = []
  let seq = 0

  const docker: DockerRunner = async args => {
    calls.push(args)
    if (args[0] === 'network' || args[0] === 'volume' || args[0] === 'build' || args[0] === 'exec' || args[0] === 'image') {
      return ''
    }
    if (args[0] === 'run') {
      const name = args[args.indexOf('--name') + 1] ?? ''
      runCalls.push({ name, args })
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
      let runId = ''
      for (let i = 0; i < args.length; i += 1) {
        if (args[i] === '--label') {
          const val = args[i + 1] ?? ''
          if (val.startsWith(`${LAB_LABELS.run}=`)) runId = val.slice(LAB_LABELS.run.length + 1)
        }
      }
      live.set(name, { id: `c${String(seq).padStart(11, '0')}`, runId })
      return ''
    }
    if (args[0] === 'inspect') {
      const format = args[2] ?? ''
      const name = args[args.length - 1] ?? ''
      const entry = live.get(name)
      if (!entry) throw new Error(`Error: No such container: ${name}`)
      if (format === '{{.Id}}') return entry.id
      if (format.includes('NetworkSettings')) return '172.18.0.10'
      if (format.includes('Labels')) return entry.runId
      return 'running exit=0'
    }
    if (args[0] === 'container' && args[1] === 'rm') {
      for (const target of args.slice(3)) live.delete(target)
      return ''
    }
    return ''
  }

  return {
    docker,
    calls,
    runCalls,
    live,
    async close() {
      await Promise.all(servers.map(s => new Promise<void>(r => s.close(() => r()))))
    },
  }
}

// ============================================================================
// 1. Strict OCI image reference grammar
// ============================================================================

test('R2-C-1: strict OCI image validator accepts valid [registry/]repo[:tag][@digest] references', () => {
  for (const valid of VALID_IMAGE_STRINGS) {
    const res = validateOciImageReference(valid)
    assert.equal(res.ok, true, `expected valid OCI image "${valid}" to pass, got: ${!res.ok ? res.reason : ''}`)
    assert.equal(isValidOciImageReference(valid), true)
    assert.equal(assertSafeLabImageReference(valid), valid)
  }
})

test('R2-C-1: strict OCI image validator rejects leading dashes, whitespace, control chars, =, and malformed refs', () => {
  for (const bad of MALICIOUS_IMAGE_STRINGS) {
    const res = validateOciImageReference(bad)
    assert.equal(res.ok, false, `expected malicious/malformed image ${JSON.stringify(bad)} to be rejected`)
    assert.equal(isValidOciImageReference(bad), false)
    assert.throws(
      () => assertSafeLabImageReference(bad),
      /Unsafe .* image reference .* rejected/i,
      `assertSafeLabImageReference must reject ${JSON.stringify(bad)}`,
    )
  }
  for (const nonString of [123, true, {}, [], null, undefined]) {
    assert.equal(validateOciImageReference(nonString).ok, false)
    assert.throws(() => assertSafeLabImageReference(nonString), /Unsafe .* image reference/i)
  }
})

// ============================================================================
// 2. Compose parse & sanitizer boundary
// ============================================================================

test('R2-C-1: compose parser and sanitizer reject leading-dash, whitespace, control-char, and "=" image values', async t => {
  t.after(() => closeSharedUntrustedComputePool())

  // Exact R2-C-1 exploit shape: quoted flag in `image:` + array `command:` providing the real image
  const exploitCases = [
    {
      label: 'quoted --volume bind mount option',
      yaml: 'services:\n  app:\n    image: "--volume=/:/host:rw"\n    command: ["node:24-bookworm-slim", "node", "-e", "1"]\n',
    },
    {
      label: 'short -v option with whitespace',
      yaml: 'services:\n  app:\n    image: "-v /:/host"\n    command: ["node:24-bookworm-slim"]\n',
    },
    {
      label: 'leading-dash --privileged flag',
      yaml: 'services:\n  app:\n    image: "--privileged"\n    command: ["node:24-bookworm-slim"]\n',
    },
    {
      label: 'leading-dash --user override',
      yaml: 'services:\n  app:\n    image: "--user=0:0"\n    command: ["node:24-bookworm-slim"]\n',
    },
    {
      label: 'whitespace inside image string',
      yaml: 'services:\n  app:\n    image: "node:24 --privileged"\n',
    },
    {
      label: 'leading whitespace in quoted image string',
      yaml: 'services:\n  app:\n    image: " node:24"\n',
    },
    {
      label: 'equals sign in image string',
      yaml: 'services:\n  app:\n    image: "node:tag=evil"\n',
    },
    {
      label: 'control char in double-quoted image string',
      yaml: 'services:\n  app:\n    image: "node:24\\n--privileged"\n',
    },
    {
      label: 'anchor merge carrying flag-injected image',
      yaml: 'x-base: &base\n  image: "--volume=/etc:/host"\nservices:\n  app:\n    <<: *base\n    command: ["node:24-bookworm-slim"]\n',
    },
    {
      label: 'sidecar service carrying flag-injected image',
      yaml: 'services:\n  app:\n    image: node:24-bookworm-slim\n  db:\n    image: "--volume=/:/host:rw"\n    command: ["postgres:16"]\n',
    },
  ]

  for (const entry of exploitCases) {
    assert.throws(
      () => parseComposeDocument(entry.yaml, { env: {} }),
      err => err instanceof ComposeParseError && /invalid image reference/i.test(err.message),
      `parseComposeDocument must reject ${entry.label}`,
    )
    assert.throws(
      () => parseAndSanitizeComposeYaml(entry.yaml, { env: {} }),
      /invalid image reference/i,
      `parseAndSanitizeComposeYaml must reject ${entry.label}`,
    )
  }

  // Variable interpolation injecting a leading-dash option must also be rejected
  assert.throws(
    () => parseComposeDocument('services:\n  app:\n    image: "${EVIL_IMG}"\n', { env: { EVIL_IMG: '--volume=/:/host:rw' } }),
    err => err instanceof ComposeParseError && /invalid image reference/i.test(err.message),
  )

  // Worker-thread compose parser must reject the same exploit
  await assert.rejects(
    () => parseComposeInWorker(exploitCases[0].yaml, { env: {} }),
    err => err instanceof ComposeParseError && /invalid image reference/i.test(err.message),
  )

  // Defense-in-depth: even a forged ParsedComposeDocument bypassing parseComposeDocument is rejected by sanitizeParsedComposeDocument
  const forgedDoc: ParsedComposeDocument = {
    services: [{
      name: 'app',
      config: { image: '--volume=/:/host:rw' },
      normalized: {
        name: 'app',
        image: '--volume=/:/host:rw',
        command: ['node:24-bookworm-slim'],
        expose: [],
        ports: [],
        dependsOn: [],
        volumes: [],
        networks: [],
        networkAliases: [],
      },
    }],
  }
  assert.throws(
    () => sanitizeParsedComposeDocument(forgedDoc),
    /Unsafe compose service "app" image reference/i,
  )

  // Leading-zero root user forms in compose are also rejected
  for (const badUser of ['00:00', '1000:0', '1000:00', '1000:root', 'ROOT']) {
    assert.throws(
      () => parseAndSanitizeComposeYaml(`services:\n  app:\n    image: node:24-bookworm-slim\n    user: "${badUser}"\n`, { env: {} }),
      /root user/i,
      `compose user "${badUser}" must be rejected`,
    )
  }
})

test('R2-C-1: validateRawServiceObject, resolveLabStackServices, and resolveStartCommand reject unsafe image strings', t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r2c1-start-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  writeFileSync(join(dir, 'server.js'), 'console.log("ok")\n')

  for (const bad of ['--volume=/:/host', '-v /:/host', 'node:24 --privileged', 'node:tag=1', ' node:24', 'node:24\n']) {
    assert.throws(
      () => validateRawServiceObject({ name: 'app', image: bad }),
      /Unsafe .* image reference/i,
      `validateRawServiceObject must reject ${JSON.stringify(bad)}`,
    )
    assert.throws(
      () => resolveLabStackServices({ labConfig: { enabled: true, image: bad } }),
      /Unsafe .* image reference/i,
      `resolveLabStackServices(labConfig.image) must reject ${JSON.stringify(bad)}`,
    )
    assert.throws(
      () => resolveLabStackServices({ labConfig: { enabled: true, services: [{ name: 'app', image: bad }] } }),
      /Unsafe .* image reference/i,
      `resolveLabStackServices(services[].image) must reject ${JSON.stringify(bad)}`,
    )
    assert.throws(
      () => resolveStartCommand(dir, { image: bad }),
      /Unsafe .* image reference/i,
      `resolveStartCommand must reject ${JSON.stringify(bad)}`,
    )
  }
})

// ============================================================================
// 3. Docker argv construction (`--` separator, `--pull=never`, image & user guards)
// ============================================================================

test('R2-C-1: buildLabContainerRunArgs and buildLabProxyRunArgs place "--" before image, enforce "--pull=never", and reject injected images/users', () => {
  const baseRunInput = {
    containerName: 'kovo-lab-app-1234',
    networkName: 'kovo-lab-net-1234',
    runId: 'run-r2c1',
    serviceName: 'app',
    imageName: 'node:24-bookworm-slim',
    cmd: ['node', '/app/server.js'],
    internalPort: 8080,
    mountArgs: ['--mount', 'type=bind,source=/tmp/repo,target=/app,readonly', '--workdir', '/app'],
    env: {},
    extraEnv: {},
    memoryLimit: '512m',
    cpus: '1.0',
    pidsLimit: 128,
    user: DEFAULT_UNPRIVILEGED_LAB_USER,
  }

  const runArgs = buildLabContainerRunArgs(baseRunInput)
  const sepIdx = runArgs.indexOf('--')
  const pullIdx = runArgs.indexOf('--pull=never')
  assert.ok(pullIdx > 0, 'docker run argv must include --pull=never')
  assert.ok(sepIdx > pullIdx, '"--" must come after --pull=never and all docker run options')
  assert.equal(runArgs[sepIdx + 1], 'node:24-bookworm-slim', 'image must immediately follow "--"')
  assert.deepEqual(runArgs.slice(sepIdx + 2), ['node', '/app/server.js'], 'command must immediately follow image')
  assert.equal(runArgs[runArgs.indexOf('--user') + 1], '65534:65534')

  for (const bad of ['--volume=/:/host', '-v /:/host', '--privileged', 'node:24 --privileged', 'node:tag=1', 'node:24\n']) {
    assert.throws(
      () => buildLabContainerRunArgs({ ...baseRunInput, imageName: bad }),
      /Unsafe .* image reference/i,
      `buildLabContainerRunArgs must reject ${JSON.stringify(bad)}`,
    )
  }

  for (const badUser of ['0:0', '00:00', '1000:0', 'root:root', '--privileged']) {
    assert.throws(
      () => buildLabContainerRunArgs({ ...baseRunInput, user: badUser }),
      /non-root|numeric|rejected/i,
      `buildLabContainerRunArgs must reject user ${JSON.stringify(badUser)}`,
    )
  }

  const baseProxyInput = {
    containerName: 'kovo-lab-proxy-1234',
    networkName: 'kovo-lab-net-1234',
    runId: 'run-r2c1',
    proxyDir: '/tmp/kovo-lab-proxy-1234',
    image: 'node:24-bookworm-slim',
    user: '1000:1000',
    targetHost: 'kovo-lab-app-1234',
    targetPort: 8080,
    socketMode: '600' as const,
  }
  const proxyArgs = buildLabProxyRunArgs(baseProxyInput)
  const proxySepIdx = proxyArgs.indexOf('--')
  const proxyPullIdx = proxyArgs.indexOf('--pull=never')
  assert.ok(proxyPullIdx > 0, 'proxy docker run argv must include --pull=never')
  assert.ok(proxySepIdx > proxyPullIdx, 'proxy "--" must come after all docker run options')
  assert.equal(proxyArgs[proxySepIdx + 1], 'node:24-bookworm-slim', 'proxy image must immediately follow "--"')
  assert.equal(proxyArgs[proxySepIdx + 2], 'node')

  for (const bad of ['--volume=/:/host', '-v /:/host', 'node:24 --privileged', 'node:tag=1', ' node:24', 'node:24\n']) {
    assert.throws(
      () => buildLabProxyRunArgs({ ...baseProxyInput, image: bad }),
      /Unsafe lab proxy image reference/i,
      `buildLabProxyRunArgs must reject ${JSON.stringify(bad)}`,
    )
  }
  for (const badUser of ['0:0', '00:00', 'root']) {
    assert.throws(
      () => buildLabProxyRunArgs({ ...baseProxyInput, user: badUser }),
      /non-root|numeric|rejected/i,
      `buildLabProxyRunArgs must reject user ${JSON.stringify(badUser)}`,
    )
  }
})

// ============================================================================
// 4. End-to-end LabRunner isolation: zero Docker calls on attack, unprivileged uid + `--` on valid stack
// ============================================================================

test('R2-C-1: LabRunner blocks hostile compose image before Docker, runs valid services as 65534:65534 with -- and --pull=never', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-r2c1-runner-'))
  const stateDir = join(dir, 'state')
  const repoDir = join(dir, 'repo')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.js'), 'require("http").createServer((_, r) => r.end("ok")).listen(8080)\n')

  const fake = createFakeLabDocker()
  t.after(async () => {
    await fake.close()
    await closeSharedUntrustedComputePool()
    rmSync(dir, { recursive: true, force: true })
  })

  const prevAllow = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  try {
    // 1. Hostile compose file with injected `--volume=...` fails BEFORE any Docker CLI call
    writeFileSync(
      join(repoDir, 'docker-compose.attack.yml'),
      [
        'services:',
        '  app:',
        '    image: "--volume=/:/host:rw"',
        '    command: ["node:24-bookworm-slim", "node", "/app/server.js"]',
      ].join('\n') + '\n',
    )
    const runner = new LabRunner({ docker: fake.docker, stateDir, env: {} })
    await assert.rejects(
      () => runner.startLabTarget({
        runId: 'run-r2c1-attack',
        environment: 'local-lab',
        repoDir,
        labConfig: { enabled: true, dockerComposeFile: 'docker-compose.attack.yml' },
      }),
      /invalid image reference/i,
    )
    assert.equal(fake.calls.length, 0, 'hostile compose image must be rejected before invoking Docker')

    // 2. Hostile sidecar compose image also fails BEFORE any Docker CLI call
    writeFileSync(
      join(repoDir, 'docker-compose.sidecar-attack.yml'),
      [
        'services:',
        '  app:',
        '    image: node:24-bookworm-slim',
        '  sidecar:',
        '    image: "-v /:/host"',
        '    command: ["redis:7"]',
      ].join('\n') + '\n',
    )
    await assert.rejects(
      () => runner.startLabTarget({
        runId: 'run-r2c1-sidecar-attack',
        environment: 'local-lab',
        repoDir,
        labConfig: { enabled: true, dockerComposeFile: 'docker-compose.sidecar-attack.yml' },
      }),
      /invalid image reference/i,
    )
    assert.equal(fake.calls.length, 0, 'hostile sidecar image must be rejected before invoking Docker')

    // 3. Hostile KOVO_LAB_PROXY_IMAGE env override is rejected
    const badProxyRunner = new LabRunner({
      docker: fake.docker,
      stateDir,
      env: { [LAB_PROXY_IMAGE_ENV]: '--privileged' },
    })
    await assert.rejects(
      () => badProxyRunner.startLabTarget({
        runId: 'run-r2c1-bad-proxy',
        environment: 'local-lab',
        repoDir,
        labConfig: { enabled: true, image: 'node:24-bookworm-slim', startCommand: 'node /app/server.js' },
      }),
      /Unsafe lab proxy image reference/i,
    )

    // 4. Valid compose stack (primary + sidecar) launches with `--pull=never`, `--` before image,
    //    and dedicated non-Kovo user `65534:65534` on every untrusted service container (plus Gate-6 rebuild).
    fake.calls.length = 0
    fake.runCalls.length = 0
    writeFileSync(
      join(repoDir, 'docker-compose.valid.yml'),
      [
        'services:',
        '  app:',
        '    image: node:24-bookworm-slim',
        '    command: ["node", "/app/server.js"]',
        '    expose: ["8080"]',
        '  cache:',
        '    image: redis:7',
        '    expose: ["6379"]',
      ].join('\n') + '\n',
    )
    await runner.startLabTarget({
      runId: 'run-r2c1-valid',
      environment: 'local-lab',
      repoDir,
      labConfig: { enabled: true, dockerComposeFile: 'docker-compose.valid.yml', healthTimeoutMs: 5_000 },
      signal: AbortSignal.timeout(15_000),
    })

    const serviceRuns = fake.runCalls.filter(c => !c.name.includes('-proxy-'))
    const proxyRuns = fake.runCalls.filter(c => c.name.includes('-proxy-'))
    assert.equal(serviceRuns.length, 2, 'expected primary + sidecar docker run invocations')
    assert.equal(proxyRuns.length, 1, 'expected 1 proxy docker run invocation')

    for (const call of [...serviceRuns, ...proxyRuns]) {
      const sepIdx = call.args.indexOf('--')
      assert.ok(call.args.includes('--pull=never'), `${call.name} must pass --pull=never`)
      assert.ok(sepIdx > call.args.indexOf('--pull=never'), `${call.name} must place "--" before image`)
      assert.equal(isValidOciImageReference(call.args[sepIdx + 1]), true, `${call.name} image after "--" must be valid OCI ref`)
    }
    for (const call of serviceRuns) {
      assert.equal(
        call.args[call.args.indexOf('--user') + 1],
        DEFAULT_UNPRIVILEGED_LAB_USER,
        `${call.name} must run as dedicated unprivileged non-Kovo uid:gid (${DEFAULT_UNPRIVILEGED_LAB_USER})`,
      )
    }

    // Gate-6 rebuildWithPatch also keeps `--pull=never`, `--` before image, and `65534:65534`
    const patchDiff = [
      '--- a/server.js',
      '+++ b/server.js',
      '@@ -1 +1 @@',
      '-require("http").createServer((_, r) => r.end("ok")).listen(8080)',
      '+require("http").createServer((_, r) => r.end("patched")).listen(8080)',
      '',
    ].join('\n')
    const beforeRebuildCount = fake.runCalls.length
    await runner.rebuildWithPatch('run-r2c1-valid', patchDiff, AbortSignal.timeout(15_000))
    const rebuildRun = fake.runCalls[beforeRebuildCount]
    assert.ok(rebuildRun, 'rebuildWithPatch must launch a replacement service container')
    assert.ok(rebuildRun.args.includes('--pull=never'))
    const rebuildSep = rebuildRun.args.indexOf('--')
    assert.ok(rebuildSep > 0)
    assert.equal(rebuildRun.args[rebuildSep + 1], 'node:24-bookworm-slim')
    assert.equal(rebuildRun.args[rebuildRun.args.indexOf('--user') + 1], DEFAULT_UNPRIVILEGED_LAB_USER)

    await runner.stopLabTarget('run-r2c1-valid')
  } finally {
    if (prevAllow === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevAllow
  }
})

test('R2-C-1: resolveLabServiceContainerUser defaults to 65534:65534 and honors KOVO_LAB_USER / IAST mount needs', () => {
  assert.equal(resolveLabServiceContainerUser({}), DEFAULT_UNPRIVILEGED_LAB_USER)
  assert.equal(resolveLabServiceContainerUser({}, { needsHostWritableMount: false }), DEFAULT_UNPRIVILEGED_LAB_USER)
  assert.equal(resolveLabServiceContainerUser({}, { needsHostWritableMount: true }), resolveLabContainerUser({}))
  assert.equal(resolveLabServiceContainerUser({ KOVO_LAB_USER: '2001:2001' }), '2001:2001')
  assert.throws(() => resolveLabServiceContainerUser({ KOVO_LAB_USER: '0:0' }), /non-root|rejected/i)
  assert.throws(() => resolveLabServiceContainerUser({ KOVO_LAB_USER: '00:00' }), /non-root|rejected/i)
})
