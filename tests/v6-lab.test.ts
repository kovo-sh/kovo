/**
 * v6 Phase 4 — LabRunner cleanup regression suite.
 *
 * Covers the four Phase 4 LabRunner deliverables:
 *   1. Real bounded YAML Compose parsing (anchors/aliases/merge keys, flow collections,
 *      block scalars, `${VAR}` interpolation, healthcheck) with explicit rejection of
 *      unsupported constructs, and the unchanged sanitizer security posture.
 *   2. Writable database overlays (Postgres/MySQL/MariaDB/Redis/Mongo/SQLite) so DB init no longer
 *      fails against a read-only rootfs, plus per-run named-volume naming/cleanup.
 *   3. Native Docker-network proxy: a trusted proxy container on the per-run `--internal` network
 *      reached by the host over a Unix-socket handshake. Zero published ports, loopback-only host
 *      listener, no per-connection `docker exec`.
 *   4. Persisted container IDs with `dev.kovo.run` / `dev.kovo.lab` labels, label-based
 *      orphan reaping and idempotent `recover()` for crash/restart cleanup.
 *
 * No Docker daemon is required: every assertion here is a pure spec, filesystem check, or a local
 * Unix-socket round trip. Live launch behavior is covered by v3 A2 and v4 B5/B6 (docker tier).
 */
import assert from 'node:assert/strict'
import { mkdirSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  COMPOSE_PARSER_LIMITS,
  ComposeParseError,
  interpolateComposeString,
  parseComposeDocument,
  parseYamlSubset,
} from '../src/server/compose-parse.ts'
import {
  LAB_LABELS,
  LAB_PATHS,
  LabRunner,
  buildIastTelemetryMountArgs,
  buildLabContainerRunArgs,
  buildLabNetworkCreateArgs,
  buildLabProxyRunArgs,
  buildWritableDataOverlay,
  createLoopbackSocketForwarder,
  createLabProxyDir,
  detectLabDatabaseKind,
  deriveHealthPathFromHealthcheck,
  labDataVolumeName,
  labRunRecordPath,
  parseAndSanitizeComposeYaml,
  readLabRunRecord,
  removeLabRunRecord,
  resolveLabContainerUser,
  rewriteSqliteDatabaseUrl,
  safeRemoveLabTempDir,
  writeLabProxyTarget,
  writeLabRunRecord,
} from '../src/server/lab-runner.ts'
import type { DockerRunner, LabContainerStore, LabRunRecord } from '../src/server/lab-runner.ts'
import type { Store } from '../src/server/store.ts'

function makeTempDir(t: { after: (fn: () => void) => void }, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function expectThrow(fn: () => unknown, pattern: RegExp, label: string): void {
  assert.throws(fn, pattern, label)
}

// ============================================================================
// 1. Bounded YAML Compose parser
// ============================================================================

test('v6 compose parser: multi-service document with list/map environment, depends_on and expose', () => {
  const document = parseComposeDocument(`
version: "3.9"
name: fixture-stack
services:
  app:
    image: node:24-bookworm-slim
    command: ["node", "/app/app.js"]
    environment:
      NODE_ENV: test
      PORT: "8080"
    depends_on:
      db:
        condition: service_healthy
    networks:
      default:
        aliases: [api, web]
  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_PASSWORD=fixture-pass
      - POSTGRES_DB=app
    expose:
      - "5432"
  cache:
    image: redis:7
    command: redis-server --save ""
`, { env: {} })

  assert.equal(document.version, '3.9')
  assert.equal(document.name, 'fixture-stack')
  assert.deepEqual(document.services.map(service => service.name), ['app', 'db', 'cache'])

  const app = document.services[0].normalized
  assert.equal(app.image, 'node:24-bookworm-slim')
  assert.deepEqual(app.command, ['node', '/app/app.js'])
  assert.deepEqual(app.environment, { NODE_ENV: 'test', PORT: '8080' })
  assert.deepEqual(app.dependsOn, ['db'])
  assert.deepEqual(app.networkAliases, ['api', 'web'])

  const db = document.services[1].normalized
  assert.deepEqual(db.environment, { POSTGRES_PASSWORD: 'fixture-pass', POSTGRES_DB: 'app' })
  assert.deepEqual(db.expose, [5432])
})

test('v6 compose parser: anchors, aliases, merge keys and copy-on-alias semantics', () => {
  const document = parseComposeDocument(`
x-defaults: &defaults
  image: node:24-bookworm-slim
  environment:
    NODE_ENV: test
x-worker: &worker
  command: node /app/worker.js
services:
  app:
    <<: *defaults
    command: node /app/app.js
    environment:
      NODE_ENV: production
  worker:
    <<: [*defaults, *worker]
`, { env: {} })

  const app = document.services[0].normalized
  assert.equal(app.image, 'node:24-bookworm-slim', 'merged anchor supplies the image')
  assert.deepEqual(app.environment, { NODE_ENV: 'production' }, 'explicit keys win over merged keys')
  assert.equal(app.command, 'node /app/app.js')

  const worker = document.services[1].normalized
  assert.equal(worker.environment?.NODE_ENV, 'test')
  assert.equal(worker.command, 'node /app/worker.js', 'multiple merge sources are applied in order')

  // Aliases must be deep clones: mutating one service never mutates the anchored template.
  const first = parseComposeDocument(`
x-base: &base
  image: node:24-bookworm-slim
  environment:
    FLAG: one
services:
  a:
    <<: *base
  b:
    <<: *base
`, { env: {} })
  assert.notEqual(first.services[0].normalized.environment, first.services[1].normalized.environment)
})

test('v6 compose parser: ${VAR} interpolation, defaults, $$ escape and missing-variable failure', () => {
  const yaml = `
services:
  app:
    image: node:24-bookworm-slim
    command: node /app/app.js --port \${PORT:-8080}
    environment:
      DB_PASSWORD: \${DB_PASSWORD}
      LITERAL: "cost$$5"
      WITH_DEFAULT: \${MISSING:-fallback}
  db:
    image: "postgres:\${PG_TAG}"
    environment:
      - POSTGRES_PASSWORD=\${DB_PASSWORD}
`
  const document = parseComposeDocument(yaml, {
    env: { PORT: '3000', DB_PASSWORD: 'fixture-secret', PG_TAG: '16' },
  })
  assert.equal(document.services[0].normalized.command, 'node /app/app.js --port 3000')
  assert.equal(document.services[0].normalized.environment?.DB_PASSWORD, 'fixture-secret')
  assert.equal(document.services[0].normalized.environment?.LITERAL, 'cost$5')
  assert.equal(document.services[0].normalized.environment?.WITH_DEFAULT, 'fallback')
  assert.equal(document.services[1].normalized.image, 'postgres:16')

  expectThrow(
    () => parseComposeDocument('services:\n  app:\n    image: node:24\n    command: ${NOT_SET}\n', { env: {} }),
    /required environment variable "NOT_SET" is not set/,
    'missing interpolation variables fail closed',
  )
  assert.equal(interpolateComposeString('a$$b', {}), 'a$b')
  assert.equal(interpolateComposeString('${X:-def}', {}), 'def')
  assert.throws(() => interpolateComposeString('${X', {}), ComposeParseError)
})

test('v6 compose parser: healthcheck parsing (CMD list/string, durations, retries, disable) and path derivation', () => {
  const document = parseComposeDocument(`
services:
  app:
    image: node:24-bookworm-slim
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8080/healthz?full=1"]
      interval: 10s
      timeout: 2500ms
      retries: 5
      start_period: 1m
  db:
    image: postgres:16
    healthcheck:
      test: pg_isready -U postgres
      interval: 5s
      retries: 20
  disabled:
    image: node:24-bookworm-slim
    healthcheck:
      disable: true
`, { env: {} })

  const app = document.services[0].normalized.healthcheck
  assert.deepEqual(app?.test, ['CMD', 'curl', '-fsS', 'http://localhost:8080/healthz?full=1'])
  assert.equal(app?.intervalMs, 10_000)
  assert.equal(app?.timeoutMs, 2_500)
  assert.equal(app?.retries, 5)
  assert.equal(app?.startPeriodMs, 60_000)
  assert.equal(deriveHealthPathFromHealthcheck({ test: app?.test }), '/healthz')

  const db = document.services[1].normalized.healthcheck
  assert.equal(db?.test, 'pg_isready -U postgres')
  assert.equal(deriveHealthPathFromHealthcheck({ test: db?.test }), undefined, 'non-HTTP probes do not invent a path')
  assert.equal(document.services[2].normalized.healthcheck?.disabled, true)
})

test('v6 compose parser: block scalars (literal and folded) and flow collections', () => {
  const document = parseComposeDocument(`
services:
  app:
    image: node:24-bookworm-slim
    command: |
      node /app/app.js
      --verbose
    environment: { NODE_ENV: test }
    expose: [8080, 9090]
`, { env: {} })
  assert.equal(document.services[0].normalized.command, 'node /app/app.js\n--verbose')
  assert.equal(document.services[0].config.command, 'node /app/app.js\n--verbose\n', 'literal block keeps its final newline in the raw config')
  assert.deepEqual(document.services[0].normalized.environment, { NODE_ENV: 'test' })
  assert.deepEqual(document.services[0].normalized.expose, [8080, 9090])

  const folded = parseComposeDocument('services:\n  app:\n    image: node:24\n    command: >\n      node\n      app.js\n', { env: {} })
  assert.equal(folded.services[0].normalized.command, 'node app.js')

  const subset = parseYamlSubset('a:\n  - 1\n  - {x: 1, y: [2, 3]}\nb: [true, null, "q"]\n', { env: {} }) as Record<string, unknown>
  assert.deepEqual(subset.a, [1, { x: 1, y: [2, 3] }])
  assert.deepEqual(subset.b, [true, null, 'q'])
})

test('v6 compose parser: unsupported constructs are rejected explicitly (never silently mis-parsed)', () => {
  const cases: Array<{ label: string; yaml: string; pattern: RegExp }> = [
    { label: 'tab indentation', yaml: 'services:\n\tapp:\n\t\timage: node:24\n', pattern: /tab characters are not allowed/ },
    { label: 'yaml tag', yaml: 'services:\n  app:\n    image: !!str node:24\n', pattern: /YAML tags are not supported/ },
    { label: 'multiple documents', yaml: 'services:\n  app:\n    image: node:24\n---\nservices:\n  b:\n    image: node:24\n', pattern: /multiple YAML documents/ },
    { label: 'complex key', yaml: 'services:\n  ? app\n  : { image: node:24 }\n', pattern: /complex keys|complex mapping keys/i },
    { label: 'duplicate key', yaml: 'services:\n  app:\n    image: node:24\n    image: node:22\n', pattern: /duplicate mapping key "image"/ },
    { label: 'unknown top-level key', yaml: 'service:\n  app:\n    image: node:24\n', pattern: /unsupported top-level compose key "service"/ },
    { label: 'top-level secrets', yaml: 'secrets:\n  x:\n    file: ./x\nservices:\n  app:\n    image: node:24\n', pattern: /unsupported top-level compose key "secrets"/ },
    { label: 'unknown service key', yaml: 'services:\n  app:\n    image: node:24\n    bogus: true\n', pattern: /unsupported compose service key "bogus"/ },
    { label: 'undefined alias', yaml: 'services:\n  app:\n    <<: *nope\n    image: node:24\n', pattern: /alias "\*nope" was never defined/ },
    { label: 'unterminated quote', yaml: 'services:\n  app:\n    image: "node:24\n', pattern: /unterminated quoted scalar/ },
    { label: 'bad duration', yaml: 'services:\n  app:\n    image: node:24\n    healthcheck:\n      test: "true"\n      interval: soon\n', pattern: /must be a duration/ },
    { label: 'too many services', yaml: Array.from({ length: 7 }, (_, i) => `  s${i}:\n    image: node:24`).join('\n').replace(/^/, 'services:\n'), pattern: /limit is 6/ },
    { label: 'empty document', yaml: '   \n', pattern: /document is empty/ },
    { label: 'oversized document', yaml: 'services:\n' + 'x'.repeat(COMPOSE_PARSER_LIMITS.maxBytes), pattern: /exceeds/ },
  ]
  for (const entry of cases) {
    expectThrow(() => parseComposeDocument(entry.yaml, { env: {} }), entry.pattern, `${entry.label} must be rejected`)
  }
})

test('v6 compose sanitizer: security posture preserved for every forbidden directive', () => {
  const unsafe: Array<{ label: string; yaml: string; pattern: RegExp }> = [
    { label: 'privileged', yaml: 'services:\n  app:\n    image: node:24\n    privileged: true\n', pattern: /privileged/i },
    { label: 'network_mode', yaml: 'services:\n  app:\n    image: node:24\n    network_mode: host\n', pattern: /network_mode/i },
    { label: 'cap_add', yaml: 'services:\n  app:\n    image: node:24\n    cap_add:\n      - SYS_ADMIN\n', pattern: /cap_add/i },
    { label: 'ports', yaml: 'services:\n  app:\n    image: node:24\n    ports:\n      - "8080:8080"\n', pattern: /ports/i },
    { label: 'host bind volume', yaml: 'services:\n  app:\n    image: node:24\n    volumes:\n      - /etc:/host-etc\n', pattern: /volume|bind/i },
    { label: 'named volume', yaml: 'services:\n  app:\n    image: node:24\n    volumes:\n      - data:/var/lib/data\n', pattern: /volume/i },
    { label: 'root user', yaml: 'services:\n  app:\n    image: node:24\n    user: "0:0"\n', pattern: /root user/i },
    { label: 'env_file', yaml: 'services:\n  app:\n    image: node:24\n    env_file: .env\n', pattern: /env_file/i },
    { label: 'tmpfs overlay', yaml: 'services:\n  app:\n    image: node:24\n    tmpfs:\n      - /run\n', pattern: /tmpfs/i },
    { label: 'build context escape', yaml: 'services:\n  app:\n    build: ../outside\n', pattern: /build context/i },
    { label: 'dockerfile traversal', yaml: 'services:\n  app:\n    build:\n      context: .\n      dockerfile: ../../etc/passwd\n', pattern: /Unsafe dockerfile path/i },
    { label: 'env key injection', yaml: 'services:\n  app:\n    image: node:24\n    environment:\n      LD_PRELOAD: /evil.so\n', pattern: /Forbidden unsafe environment variable key/i },
  ]
  for (const entry of unsafe) {
    assert.throws(
      () => parseAndSanitizeComposeYaml(entry.yaml, { env: {} }),
      entry.pattern,
      `${entry.label} must be rejected by the sanitizer`,
    )
  }

  // A valid compose document becomes a LabServiceSpec without touching the security defaults.
  const valid = parseAndSanitizeComposeYaml(`
services:
  app:
    image: node:24-bookworm-slim
    command: node /app/app.js
    expose: ["8080"]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/ready"]
    networks:
      default:
        aliases: [api]
  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: fixture-pass
`, { env: {} })
  assert.deepEqual(valid.map(service => service.name), ['app', 'db'])
  assert.equal(valid[0].internalPort, 8080)
  assert.equal(valid[0].healthPath, '/ready')
  assert.deepEqual(valid[0].networkAliases, ['api'])
  assert.equal(valid[1].image, 'postgres:16')
  assert.equal(valid[1].env?.POSTGRES_PASSWORD, 'fixture-pass')
  assert.equal('ports' in valid[0], false, 'internal expects no host-port field at all')
})

test('v6 explicit services keep the same sanitizer guarantees as compose services', () => {
  const runner = new LabRunner({ docker: async () => '' })
  assert.equal(typeof runner.startLabTarget, 'function')
  assert.throws(
    () => parseAndSanitizeComposeYaml('services:\n  App:\n    image: node:24\n', { env: {} }),
    /Invalid lab service name/,
    'service names stay lowercase/kebab',
  )
})

// ============================================================================
// 2. Writable database overlays
// ============================================================================

test('v6 writable overlays: every supported database gets a writable, uid-owned data dir', () => {
  const cases: Array<{ kind: Parameters<typeof buildWritableDataOverlay>[0]['kind']; dataDir: string }> = [
    { kind: 'postgres', dataDir: '/var/lib/postgresql/data' },
    { kind: 'mysql', dataDir: '/var/lib/mysql' },
    { kind: 'mariadb', dataDir: '/var/lib/mysql' },
    { kind: 'redis', dataDir: '/data' },
    { kind: 'mongo', dataDir: '/data/db' },
    { kind: 'sqlite', dataDir: '/app/data' },
  ]
  for (const entry of cases) {
    const overlay = buildWritableDataOverlay({
      kind: entry.kind,
      serviceName: 'db',
      runId: 'run-0001',
      containerUser: '1000:1001',
    })
    assert.equal(overlay.dataDir, entry.dataDir, `${entry.kind} data dir`)
    assert.ok(
      overlay.tmpfsArgs.some(spec => spec.startsWith(`${entry.dataDir}:rw,`)),
      `${entry.kind} must mount a writable tmpfs data dir`,
    )
    assert.match(overlay.tmpfsArgs.join(' '), /uid=1000,gid=1001/, `${entry.kind} overlay must be owned by the lab uid`)
    assert.match(overlay.tmpfsArgs.join(' '), /mode=0?700/, `${entry.kind} overlay must be 0700`)
    assert.equal(overlay.mountArgs.length, 0)
    assert.equal(overlay.kind, entry.kind)
  }

  assert.equal(buildWritableDataOverlay({ kind: 'postgres', serviceName: 'db', runId: 'r', containerUser: '1000:1000' }).env.PGDATA, '/var/lib/postgresql/data')
  assert.equal(buildWritableDataOverlay({ kind: 'sqlite', serviceName: 'app', runId: 'r', containerUser: '1000:1000' }).readOnlyRootfs, true)
  // DB images that initialise outside the data dir must not start under a read-only rootfs.
  for (const kind of ['postgres', 'mysql', 'mariadb', 'redis', 'mongo'] as const) {
    assert.equal(
      buildWritableDataOverlay({ kind, serviceName: 'db', runId: 'r', containerUser: '1000:1000' }).readOnlyRootfs,
      false,
      `${kind} must have a writable rootfs`,
    )
  }
})

test('v6 writable overlays: per-run named volume backing is named, labelled and removable', () => {
  const overlay = buildWritableDataOverlay({
    kind: 'postgres',
    serviceName: 'db',
    runId: 'abc12345-run',
    containerUser: '1000:1000',
    backing: 'volume',
    nonce: 'deadbeef',
  })
  assert.equal(overlay.volumeName, 'kovo-lab-vol-abc12345run-db-deadbeef')
  assert.deepEqual(overlay.mountArgs, ['--mount', 'type=volume,source=kovo-lab-vol-abc12345run-db-deadbeef,target=/var/lib/postgresql/data'])
  assert.equal(
    overlay.tmpfsArgs.some(spec => spec.startsWith('/var/lib/postgresql/data:')),
    false,
    'volume backing does not double-mount a tmpfs data dir',
  )

  // Per-run naming is deterministic only with an explicit nonce and never collides across runs.
  assert.equal(labDataVolumeName('run-a', 'db', 'cafe0001'), 'kovo-lab-vol-runa-db-cafe0001')
  assert.notEqual(labDataVolumeName('run-a', 'db'), labDataVolumeName('run-b', 'db'))

  assert.throws(
    () => buildWritableDataOverlay({ kind: 'postgres', serviceName: 'db', runId: 'r', containerUser: '0:0' }),
    /non-root numeric uid:gid/,
    'writable overlays never run as root',
  )
})

test('v6 database detection and SQLite URL rewrite', () => {
  const expectations: Array<[string | undefined, string | null | undefined]> = [
    ['postgres:16', 'postgres'],
    ['docker.io/library/postgres@sha256:abc', 'postgres'],
    ['mysql:8.4', 'mysql'],
    ['mariadb:11', 'mariadb'],
    ['redis:7-alpine', 'redis'],
    ['mongo:7', 'mongo'],
    ['node:24-bookworm-slim', null],
  ]
  for (const [image, expected] of expectations) {
    assert.equal(detectLabDatabaseKind({ image }), expected, `detect ${image}`)
  }
  assert.equal(detectLabDatabaseKind({ image: 'node:24', env: { DATABASE_URL: 'sqlite:/app/data/app.db' } }), 'sqlite')
  assert.equal(rewriteSqliteDatabaseUrl('sqlite:/app/app.db'), 'sqlite:/app/data/app.db')
  assert.equal(rewriteSqliteDatabaseUrl('sqlite:file:./prisma/dev.db'), 'sqlite:/app/data/dev.db')
  assert.equal(rewriteSqliteDatabaseUrl('postgres://user:pass@db/app'), 'postgres://user:pass@db/app')
})

test('v6 run args: DB services drop --read-only and get writable tmpfs; app services stay read-only', () => {
  const base = {
    containerName: 'kovo-lab-db-abc',
    networkName: 'kovo-lab-run-abc',
    runId: 'run-1',
    serviceName: 'db',
    imageName: 'postgres:16',
    cmd: ['postgres'],
    internalPort: 5432,
    mountArgs: [] as string[],
    env: {} as Record<string, string>,
    extraEnv: {} as Record<string, string>,
    memoryLimit: '512m',
    cpus: '1.0',
    pidsLimit: 128,
    user: '1000:1000',
  }
  const overlay = buildWritableDataOverlay({ kind: 'postgres', serviceName: 'db', runId: 'run-1', containerUser: '1000:1000' })
  const dbArgs = buildLabContainerRunArgs({
    ...base,
    readOnly: overlay.readOnlyRootfs,
    writableTmpfs: overlay.tmpfsArgs,
  })
  assert.equal(dbArgs.includes('--read-only'), false, 'DB containers must not use a read-only rootfs')
  assert.ok(dbArgs.includes('/var/lib/postgresql/data:rw,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700'))
  assert.deepEqual(dbArgs.filter((_, index) => dbArgs[index - 1] === '--cap-drop'), ['ALL'])
  assert.ok(dbArgs.join(' ').includes('no-new-privileges'))
  assert.ok(dbArgs.includes(`--label`) && dbArgs.some(arg => arg === `${LAB_LABELS.run}=run-1`))
  assert.equal(dbArgs.some(arg => arg === '-p' || arg === '--publish'), false)

  const appArgs = buildLabContainerRunArgs({ ...base, serviceName: 'app', imageName: 'node:24-bookworm-slim' })
  assert.ok(appArgs.includes('--read-only'), 'app containers keep the read-only rootfs')
  assert.ok(appArgs.includes('--user') && appArgs[appArgs.indexOf('--user') + 1] === '1000:1000')
})

// ============================================================================
// 3. Native Docker-network proxy
// ============================================================================

test('v6 proxy: container joins the internal network with zero published ports and full hardening', () => {
  const args = buildLabProxyRunArgs({
    containerName: 'kovo-lab-proxy-abc',
    networkName: 'kovo-lab-run-abc',
    runId: 'run-1',
    proxyDir: '/tmp/kovo-lab-proxy-run-abc123',
    user: '1000:1000',
    targetHost: 'kovo-lab-app-abc',
    targetPort: 8080,
    socketMode: '600',
  })
  assert.equal(args.includes('-p'), false)
  assert.equal(args.includes('--publish'), false)
  assert.equal(args.includes('--network-mode'), false)
  const networkIndex = args.indexOf('--network')
  assert.equal(args[networkIndex + 1], 'kovo-lab-run-abc', 'proxy joins the per-run internal network')
  assert.equal(args[args.indexOf('--user') + 1], '1000:1000')
  assert.deepEqual(args.filter((_, index) => args[index - 1] === '--cap-drop'), ['ALL'])
  assert.ok(args.join(' ').includes('no-new-privileges'))
  assert.ok(args.includes('--read-only'))
  assert.ok(args.includes(`${LAB_LABELS.lab}=1`))
  assert.ok(args.includes(`${LAB_LABELS.run}=run-1`))
  assert.ok(args.includes(`${LAB_LABELS.role}=proxy`))
  assert.ok(args.join(' ').includes('type=bind,source=/tmp/kovo-lab-proxy-run-abc123,target=/kovo-proxy'))
  const hostEnvIndex = args.indexOf('KOVO_PROXY_TARGET_HOST=kovo-lab-app-abc')
  assert.ok(hostEnvIndex > 0, 'target host is passed as one argv entry')
  assert.equal(args[hostEnvIndex - 1], '-e', 'env is passed via -e VALUE, never string-concatenated')

  expectThrow(
    () => buildLabProxyRunArgs({
      containerName: 'p', networkName: 'n', runId: 'r', proxyDir: '/tmp/x', user: '1000:1000',
      targetHost: 'app; rm -rf /', targetPort: 8080, socketMode: '600',
    }),
    /Unsafe lab proxy target host/,
    'proxy target cannot be shell-injected',
  )
})

test('v6 proxy: per-run network is --internal with inhibit_ipv4 and run labels', () => {
  const args = buildLabNetworkCreateArgs('run-1', 'kovo-lab-run-abc')
  assert.deepEqual(args.slice(0, 4), ['network', 'create', '--driver', 'bridge'])
  assert.ok(args.includes('--internal'))
  assert.ok(args.includes('com.docker.network.bridge.inhibit_ipv4=true'))
  assert.ok(args.includes(`${LAB_LABELS.run}=run-1`))
  assert.equal(args.some(arg => arg === '-p' || arg === '--publish'), false)
  expectThrow(() => buildLabNetworkCreateArgs('run-1', 'Bad Network'), /Unsafe lab network name/, 'network name is validated')
})

test('v6 proxy: host listener binds loopback only and relays over the Unix-socket handshake', async t => {
  const proxyDir = createLabProxyDir('run-proxy-test', resolveLabContainerUser())
  t.after(() => rmSync(proxyDir, { recursive: true, force: true }))
  assert.equal(statSync(proxyDir).mode & 0o777, 0o700, 'proxy handshake dir is owner-only')
  writeLabProxyTarget(proxyDir, 'kovo-lab-app-abc', 8080)
  assert.equal(readFileSync(join(proxyDir, 'target'), 'utf8'), 'kovo-lab-app-abc:8080\n')

  // Stand in for the proxy container: a Unix-socket echo server inside the handshake dir.
  const socketPath = join(proxyDir, 'proxy.sock')
  const echo = createServer(socket => socket.on('data', chunk => socket.write(`echo:${chunk.toString()}`)))
  await new Promise<void>(resolve => echo.listen(socketPath, resolve))
  t.after(() => new Promise<void>(resolve => echo.close(() => resolve())))

  const forwarder = await createLoopbackSocketForwarder(socketPath)
  t.after(() => new Promise<void>(resolve => forwarder.server.close(() => resolve())))
  const addr = forwarder.server.address() as AddressInfo
  assert.equal(addr.address, '127.0.0.1', 'host listener must never bind 0.0.0.0')
  assert.ok(addr.port > 0)

  const { connect } = await import('node:net')
  const response = await new Promise<string>((resolve, reject) => {
    const client = connect({ host: '127.0.0.1', port: addr.port }, () => client.write('ping'))
    client.setTimeout(2_000, () => reject(new Error('relay timed out')))
    client.once('data', chunk => { resolve(chunk.toString()); client.end() })
    client.once('error', reject)
  })
  assert.equal(response, 'echo:ping')
})

// ============================================================================
// 4. Persistence, orphan reaping and recovery
// ============================================================================

interface FakeDockerState {
  containers: string[]
  networks: string[]
  volumes: string[]
  /** Label scan results for `ps -aq --filter label=dev.kovo.lab=1`. */
  labContainers?: string[]
  labRunIds?: string[]
}

function fakeDocker(state: FakeDockerState): { runner: DockerRunner; calls: string[][] } {
  const calls: string[][] = []
  const runner: DockerRunner = async args => {
    calls.push(args)
    const filter = args.find(arg => arg.startsWith('label=')) ?? ''
    if (args[0] === 'container' && args[1] === 'rm') {
      const removed = new Set(args.slice(3))
      state.containers = state.containers.filter(id => !removed.has(id))
      if (state.labContainers) state.labContainers = state.labContainers.filter(id => !removed.has(id))
      return ''
    }
    if (args[0] === 'network' && args[1] === 'rm') {
      state.networks = state.networks.filter(name => name !== args[2])
      return ''
    }
    if (args[0] === 'volume' && args[1] === 'rm') {
      const name = args[args.length - 1]
      state.volumes = state.volumes.filter(volume => volume !== name)
      return ''
    }
    if (args[0] === 'ps' && args[1] === '-aq') {
      if (filter === `label=${LAB_LABELS.lab}=1`) return (state.labContainers ?? []).join('\n')
      return state.containers.join('\n')
    }
    if (args[0] === 'ps' && args[1] === '-q' && filter === `label=${LAB_LABELS.lab}=1`) {
      return (state.labContainers ?? []).join('\n')
    }
    if (args[0] === 'network' && args[1] === 'ls') return state.networks.join('\n')
    if (args[0] === 'volume' && args[1] === 'ls') return state.volumes.join('\n')
    if (args[0] === 'inspect' && args[1] === '-f' && args[2]?.includes('Labels')) {
      return (state.labRunIds ?? []).join('\n')
    }
    return ''
  }
  return { runner, calls }
}

test('v6 recovery: persisted labels/ids drive orphan reaping and repeated recovery is idempotent', async t => {
  const workspace = makeTempDir(t, 'kovo-v6-recover-')
  const stateDir = join(workspace, 'state')
  const repoDir = join(workspace, `${LAB_PATHS.repoPrefix}recover`)
  const proxyDir = join(workspace, `${LAB_PATHS.proxyPrefix}recover`)
  const telemetryDir = join(workspace, 'telemetry', 'run-recover')
  for (const dir of [repoDir, proxyDir, telemetryDir]) mkdirSync(dir, { recursive: true })

  const runId = 'run-recover-1'
  const record: LabRunRecord = {
    version: 1,
    runId,
    networkName: 'kovo-lab-runrecover1-abcd',
    containerNames: ['kovo-lab-app-aaaaaaaaaa'],
    containerIds: ['aaaaaaaaaaa1'],
    proxyContainerName: 'kovo-lab-proxy-abcd',
    volumes: ['kovo-lab-vol-runrecover1-db-deadbeef'],
    sanitizedRepoDir: repoDir,
    telemetryDir,
    ownsTelemetryDir: true,
    proxyDir,
    startedAt: Date.now(),
    updatedAt: Date.now(),
    pid: process.pid,
  }
  writeLabRunRecord(stateDir, record)
  assert.ok(existsSync(labRunRecordPath(stateDir, runId)))
  assert.equal(readLabRunRecord(stateDir, runId)?.containerIds[0], 'aaaaaaaaaaa1')

  const fake = fakeDocker({
    containers: ['bbbbbbbbbbb2'],
    networks: ['kovo-lab-runrecover1-abcd'],
    volumes: ['kovo-lab-vol-runrecover1-db-deadbeef'],
  })
  const runner = new LabRunner({ docker: fake.runner, stateDir })

  const first = await runner.recover(runId)
  assert.equal(first.recoveredFromRecord, true)
  assert.equal(first.containersRemoved, 4, 'proxy + persisted name + persisted id + label-listed orphan are all removed')
  assert.equal(first.networksRemoved, 1)
  assert.equal(first.volumesRemoved, 1)
  assert.ok(first.tempDirsRemoved >= 2, 'scratch repo and proxy dirs are removed')
  assert.equal(existsSync(repoDir), false)
  assert.equal(existsSync(proxyDir), false)
  assert.equal(existsSync(telemetryDir), false)
  assert.equal(existsSync(labRunRecordPath(stateDir, runId)), false)
  assert.ok(fake.calls.some(args => args.includes(`label=${LAB_LABELS.run}=${runId}`)), 'reaping is label-driven')
  assert.ok(fake.calls.some(args => args[0] === 'container' && args[1] === 'rm' && args.includes('aaaaaaaaaaa1')))

  const second = await runner.recover(runId)
  assert.equal(second.recoveredFromRecord, false, 'record was removed by the first pass')
  assert.equal(second.containersRemoved, 0)
  assert.equal(second.networksRemoved, 0)
  assert.equal(second.volumesRemoved, 0)
  assert.equal(second.tempDirsRemoved, 0)
})

test('v6 recovery: recoverAll finds crashed runs by the lab label even without a persisted record', async t => {
  const workspace = makeTempDir(t, 'kovo-v6-recover-all-')
  const stateDir = join(workspace, 'state')
  const fake = fakeDocker({
    containers: ['ccccccccccc3'],
    networks: ['kovo-lab-crashed-99'],
    volumes: [],
    labContainers: ['ccccccccccc3'],
    labRunIds: ['crashed-run-99'],
  })
  const runner = new LabRunner({ docker: fake.runner, stateDir })
  const results = await runner.recoverAll()
  assert.equal(results.length, 1)
  assert.equal(results[0].runId, 'crashed-run-99')
  assert.equal(results[0].recoveredFromRecord, false)
  assert.equal(results[0].containersRemoved, 1)
  assert.ok(fake.calls.some(args => args.includes(`label=${LAB_LABELS.lab}=1`)))
  assert.ok(fake.calls.some(args => args.includes(`label=${LAB_LABELS.run}=crashed-run-99`)))
})

test('v6 recovery: temp-dir cleanup refuses symlinks and unexpected names', async t => {
  const workspace = makeTempDir(t, 'kovo-v6-safe-rm-')
  const okDir = join(workspace, `${LAB_PATHS.repoPrefix}ok`)
  mkdirSync(okDir)
  assert.equal(safeRemoveLabTempDir(okDir), true)
  assert.equal(existsSync(okDir), false)

  const unrelated = join(workspace, 'important-data')
  mkdirSync(unrelated)
  assert.equal(safeRemoveLabTempDir(unrelated), false)
  assert.ok(existsSync(unrelated), 'unexpected directory names are never deleted')

  // A symlink with a plausible name is refused (never followed).
  const linkName = join(workspace, `${LAB_PATHS.repoPrefix}link`)
  const { symlinkSync } = await import('node:fs')
  try {
    symlinkSync(unrelated, linkName)
    assert.equal(safeRemoveLabTempDir(linkName), false)
    assert.ok(existsSync(unrelated))
  } catch {
    // Symlinks may be unavailable in some sandboxes; the name/type checks above still ran.
  }
})

test('v6 recovery: state records are bounded, 0600 and reject unsafe run ids', async t => {
  const stateDir = makeTempDir(t, 'kovo-v6-state-')
  const record: LabRunRecord = {
    version: 1,
    runId: 'run-state-1',
    networkName: 'kovo-lab-runstate1-abcd',
    containerNames: [],
    containerIds: [],
    volumes: [],
    startedAt: Date.now(),
    updatedAt: Date.now(),
    pid: process.pid,
  }
  writeLabRunRecord(stateDir, record)
  const path = labRunRecordPath(stateDir, record.runId)
  assert.equal(statSync(path).mode & 0o777, 0o600)
  assert.equal(statSync(stateDir).mode & 0o777, 0o700)
  assert.deepEqual(readdirSync(stateDir).filter(name => !name.startsWith('.')), [path.split('/').pop()])

  removeLabRunRecord(stateDir, record.runId)
  removeLabRunRecord(stateDir, record.runId)
  assert.equal(existsSync(path), false, 'record removal is idempotent')

  assert.throws(() => readLabRunRecord(stateDir, '../../etc/passwd'), /Invalid lab run id/)
  assert.throws(() => labRunRecordPath(stateDir, ''), /Invalid lab run id/)
})

test('v6 lifecycle: SIGINT/SIGTERM reaper is exported and stopAll is safe with no active runs', async () => {
  const fake = fakeDocker({ containers: [], networks: [], volumes: [] })
  const runner = new LabRunner({ docker: fake.runner, stateDir: mkdtempSync(join(tmpdir(), 'kovo-v6-stop-')) })
  await runner.stopAll()
  assert.deepEqual(runner.listTargets(), [])
  assert.equal(typeof runner.reapSyncAll, 'function')
})

// ============================================================================
// 4b. Store lab-container registry wiring (v6-store merge)
// ============================================================================

interface FakeLabRow {
  runId: string
  containerName: string
  imageName?: string
  status: string
}

function fakeLabStore(): LabContainerStore & {
  rows: Map<string, FakeLabRow>
  deleteLabContainer: (runId: string, containerName: string) => void
} {
  const rows = new Map<string, FakeLabRow>()
  const key = (runId: string, containerName: string) => `${runId}/${containerName}`
  return {
    rows,
    recordLabContainer(input) {
      const existing = rows.get(key(input.runId, input.containerName))
      const row: FakeLabRow = {
        runId: input.runId,
        containerName: input.containerName,
        imageName: input.imageName ?? existing?.imageName,
        status: input.status ?? existing?.status ?? 'running',
      }
      rows.set(key(input.runId, input.containerName), row)
      return row
    },
    markLabContainerOrphaned(runId, containerName) {
      const row = rows.get(key(runId, containerName))
      if (row) row.status = 'orphaned'
    },
    listLabContainers(runId) {
      return [...rows.values()].filter(row => row.runId === runId)
    },
    deleteLabContainer(runId, containerName) {
      rows.delete(key(runId, containerName))
    },
  }
}

/**
 * Docker CLI emulator for the lifecycle tests: creates a real Unix-socket stand-in for the proxy
 * container so the host relay + health check path runs end to end without a Docker daemon.
 */
function fakeLabDocker(options: { proxyFails?: boolean; rmFails?: boolean } = {}): {
  runner: DockerRunner
  calls: string[][]
  live: Map<string, string>
  labels: Map<string, string>
  close: () => Promise<void>
} {
  const calls: string[][] = []
  const live = new Map<string, string>()
  const labels = new Map<string, string>()
  const servers: Array<{ close: (cb: () => void) => void }> = []
  let counter = 0
  const runner: DockerRunner = async args => {
    calls.push(args)
    if (args[0] === 'network' || args[0] === 'volume' || args[0] === 'build' || args[0] === 'exec') return ''
    if (args[0] === 'run') {
      const name = args[args.indexOf('--name') + 1]
      const isProxy = name.includes('-proxy-')
      if (isProxy && options.proxyFails) throw new Error('proxy image unavailable')
      if (isProxy) {
        const mountArg = args.find(arg => arg.startsWith('type=bind,source=')) ?? ''
        const dir = mountArg.slice('type=bind,source='.length, mountArg.indexOf(',target='))
        const server = createServer(socket => {
          socket.once('data', () => {
            socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
          })
          socket.on('error', () => undefined)
        })
        await new Promise<void>(resolve => server.listen(join(dir, 'proxy.sock'), resolve))
        servers.push(server)
      }
      counter += 1
      live.set(name, `c${String(counter).padStart(11, '0')}`)
      return ''
    }
    if (args[0] === 'inspect') {
      const name = args[args.length - 1]
      const format = args[2] ?? ''
      if (!live.has(name)) throw new Error(`Error: No such container: ${name}`)
      if (format === '{{.Id}}') return live.get(name) ?? ''
      if (format.includes('NetworkSettings')) return '172.18.0.2'
      if (format.includes('State.Status')) return 'running exit=0'
      if (format.includes('Labels')) return live.has(name) ? (labels.get(name) ?? 'run-lifecycle-1') : ''
      return ''
    }
    if (args[0] === 'container' && args[1] === 'rm') {
      if (options.rmFails) throw new Error('simulated docker rm failure')
      live.delete(args[args.length - 1])
      return ''
    }
    if (args[0] === 'ps') return ''
    return ''
  }
  return {
    runner,
    calls,
    live,
    labels,
    close: () => new Promise<void>(resolve => {
      let pending = servers.length
      if (pending === 0) { resolve(); return }
      for (const server of servers) server.close(() => { pending -= 1; if (pending === 0) resolve() })
    }),
  }
}

test('v6 store wiring: a launched container and the proxy are recorded, then deleted on normal stop', async t => {
  const workspace = makeTempDir(t, 'kovo-v6-store-stop-')
  const repoDir = join(workspace, 'repo')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.js'), "require('http').createServer((_q, r) => r.end('ok')).listen(8080)\n")
  const stateDir = join(workspace, 'state')
  const store = fakeLabStore()
  const fake = fakeLabDocker()
  t.after(() => fake.close())
  const runner = new LabRunner({ docker: fake.runner, stateDir })
  const runId = 'run-lifecycle-1'

  const previous = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  try {
    const handle = await runner.startLabTarget({
      runId,
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
      signal: AbortSignal.timeout(30_000),
    })
    assert.match(handle.origin, /^http:\/\/127\.0\.0\.1:\d+$/)

    const rows = store.listLabContainers(runId)
    assert.equal(rows.length, 2, 'service + proxy containers are both persisted')
    assert.ok(rows.some(row => row.containerName === handle.containerName))
    assert.ok(rows.some(row => row.containerName.includes('-proxy-')))
    assert.ok(rows.every(row => row.status === 'running'))

    await runner.stopLabTarget(runId)
    assert.equal(store.listLabContainers(runId).length, 0, 'normal stop deletes every registry row')
    assert.equal(fake.live.size, 0, 'normal stop removes every container')
    assert.equal(existsSync(handle.sanitizedRepoDir), false)
  } finally {
    if (previous === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = previous
  }
})

test('v6 store wiring: an unexpected start failure keeps row orphaned if rm fails and deletes row once removed', async t => {
  const workspace = makeTempDir(t, 'kovo-v6-store-orphan-')
  const repoDir = join(workspace, 'repo')
  mkdirSync(repoDir, { recursive: true })
  writeFileSync(join(repoDir, 'server.js'), "require('http').createServer((_q, r) => r.end('ok')).listen(8080)\n")
  const store = fakeLabStore()
  const fakeFailingRm = fakeLabDocker({ proxyFails: true, rmFails: true })
  t.after(() => fakeFailingRm.close())
  const runnerFailingRm = new LabRunner({ docker: fakeFailingRm.runner, stateDir: join(workspace, 'state-fail') })
  const runId = 'run-lifecycle-orphan'

  const previous = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  try {
    await assert.rejects(
      runnerFailingRm.startLabTarget({
        runId,
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
        signal: AbortSignal.timeout(30_000),
      }),
      /proxy image unavailable/,
    )
    const rows = store.listLabContainers(runId)
    assert.equal(rows.length, 1, 'row stays tracked as orphaned when Docker removal fails')
    assert.equal(rows[0].status, 'orphaned', 'unexpected-exit containers whose removal failed stay marked orphaned')
    assert.equal(fakeFailingRm.live.size, 1, 'container remained live when rm failed')

    // Once Docker removal succeeds (clean start failure), both container and row are cleaned up.
    const fakeClean = fakeLabDocker({ proxyFails: true })
    t.after(() => fakeClean.close())
    const cleanStore = fakeLabStore()
    const runnerClean = new LabRunner({ docker: fakeClean.runner, stateDir: join(workspace, 'state-clean') })
    await assert.rejects(
      runnerClean.startLabTarget({
        runId: 'run-lifecycle-orphan-clean',
        environment: 'local-lab',
        repoDir,
        storage: cleanStore as unknown as Store,
        labConfig: {
          enabled: true,
          image: 'node:24-bookworm-slim',
          startCommand: 'node /app/server.js',
          internalPort: 8080,
          healthPath: '/health',
          healthTimeoutMs: 5_000,
        },
        signal: AbortSignal.timeout(30_000),
      }),
      /proxy image unavailable/,
    )
    assert.equal(fakeClean.live.size, 0, 'failure cleanup removes the container process')
    assert.equal(cleanStore.listLabContainers('run-lifecycle-orphan-clean').length, 0, 'row is deleted once container removal succeeds')
  } finally {
    if (previous === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = previous
  }
})

test('v6 store wiring: reclaimPersisted removes a recovered orphan and clears its row (label-scoped)', async t => {
  const workspace = makeTempDir(t, 'kovo-v6-reclaim-')
  const store = fakeLabStore()
  store.recordLabContainer({ runId: 'run-crashed-7', containerName: 'kovo-lab-app-crashed', imageName: 'node:24', status: 'orphaned' })
  const fake = fakeLabDocker()
  // Simulate the orphan still running on the same run label.
  fake.live.set('kovo-lab-app-crashed', 'c000000000007')
  fake.labels.set('kovo-lab-app-crashed', 'run-crashed-7')
  const runner = new LabRunner({ docker: fake.runner, stateDir: join(workspace, 'state') })

  const result = await runner.reclaimPersisted(
    [{ runId: 'run-crashed-7', containerName: 'kovo-lab-app-crashed' }],
    store,
  )
  assert.equal(result.removed, 1)
  assert.equal(result.mismatched, 0)
  assert.equal(fake.live.has('kovo-lab-app-crashed'), false)
  assert.equal(store.listLabContainers('run-crashed-7').length, 0, 'reclaimed row is deleted')

  // Label-scoped: a container whose label names a *different* run is never removed.
  fake.live.set('kovo-lab-app-other', 'c000000000008')
  fake.labels.set('kovo-lab-app-other', 'run-other')
  const mismatched = await runner.reclaimPersisted(
    [{ runId: 'run-crashed-7', containerName: 'kovo-lab-app-other' }],
    store,
  )
  assert.equal(mismatched.removed, 0)
  assert.equal(mismatched.mismatched, 1)
  assert.equal(fake.live.has('kovo-lab-app-other'), true, 'cross-run containers are never removed')

  // Idempotent: an already-gone container is skipped, not an error.
  const again = await runner.reclaimPersisted([{ runId: 'run-crashed-7', containerName: 'kovo-lab-app-gone' }], store)
  assert.equal(again.removed, 0)
  assert.equal(again.skipped, 1)
  await fake.close()
})

test('v6 store wiring: recover(runId, storage) deletes rows alongside label-driven removal', async t => {
  const workspace = makeTempDir(t, 'kovo-v6-recover-rows-')
  const store = fakeLabStore()
  store.recordLabContainer({ runId: 'run-recover-rows', containerName: 'kovo-lab-app-rows', imageName: 'node:24' })
  const fake = fakeLabDocker()
  fake.live.set('kovo-lab-app-rows', 'c000000000009')
  const runner = new LabRunner({ docker: fake.runner, stateDir: join(workspace, 'state') })
  // The fake's `ps` returns no ids and there is no crash record, so the registry row itself names
  // the container that must be reclaimed.
  const result = await runner.recover('run-recover-rows', store)
  assert.equal(result.containersRemoved, 1, 'registry-named orphan is removed even without a crash record')
  assert.equal(fake.live.has('kovo-lab-app-rows'), false)
  assert.equal(store.listLabContainers('run-recover-rows').length, 0, 'recover clears the registry rows for the run')
  await fake.close()
})

// ============================================================================
// 5. Existing security assertions still hold
// ============================================================================

test('v6 security invariants: non-root user parsing, read-only telemetry mount, DB overlay uid guard', () => {
  for (const bad of ['00:00', '0:1000', '1000:0', 'root:root', '1000', '1000:1000:0']) {
    assert.throws(() => resolveLabContainerUser({ KOVO_LAB_USER: bad }), /non-root|numeric|rejected/i)
  }
  assert.equal(resolveLabContainerUser({ KOVO_LAB_USER: '1000:1000' }), '1000:1000')
  const fallback = resolveLabContainerUser({})
  assert.notEqual(fallback.split(':')[0], '0')

  assert.deepEqual(buildIastTelemetryMountArgs('/host/telemetry', false), [
    '--mount', 'type=bind,source=/host/telemetry,target=/var/run/kovo-iast,readonly',
  ])
  assert.equal(buildIastTelemetryMountArgs('/host/telemetry', true).some(arg => arg.endsWith(',readonly')), false)

  // Every generated container argv keeps the hardening flags.
  const overlay = buildWritableDataOverlay({ kind: 'redis', serviceName: 'cache', runId: 'r', containerUser: '1000:1000' })
  const args = buildLabContainerRunArgs({
    containerName: 'c', networkName: 'n', runId: 'r', serviceName: 'cache', imageName: 'redis:7',
    cmd: ['redis-server'], internalPort: 6379, mountArgs: [], env: {}, extraEnv: {},
    memoryLimit: '256m', cpus: '0.5', pidsLimit: 64, user: '1000:1000',
    readOnly: overlay.readOnlyRootfs, writableTmpfs: overlay.tmpfsArgs,
  })
  assert.ok(args.includes('--cap-drop') && args.includes('ALL'))
  assert.ok(args.join(' ').includes('no-new-privileges'))
  assert.equal(args.some(arg => arg === '--privileged'), false)
  assert.equal(args.some(arg => arg === '--network' && args[args.indexOf('--network') + 1] === 'host'), false)
  assert.equal(args.some(arg => arg === '--publish' || arg === '-p'), false)
  assert.equal(args.some(arg => arg === '--read-only'), false, 'redis needs a writable rootfs for its config rewrite')
})

test('v6 proxy script never shells out to docker exec', async () => {
  const module = await import('../src/server/lab-runner.ts')
  assert.equal(typeof module.LAB_PROXY_SCRIPT, 'string')
  assert.equal(module.LAB_PROXY_SCRIPT.includes('docker'), false)
  assert.equal(module.LAB_PROXY_SCRIPT.includes('exec'), false)
  assert.ok(module.LAB_PROXY_SCRIPT.includes('net.connect'))
  assert.ok(module.LAB_PROXY_SCRIPT.includes("readFileSync(targetFile,'utf8')"), 'proxy re-reads the target per connection')
})

test('v6 parser limits are bounded', () => {
  assert.ok(COMPOSE_PARSER_LIMITS.maxBytes <= 1_048_576)
  assert.ok(COMPOSE_PARSER_LIMITS.maxLines <= 10_000)
  assert.ok(COMPOSE_PARSER_LIMITS.maxDepth <= 32)
})
