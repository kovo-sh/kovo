import { spawn, spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { connect as connectTcp, createServer as createTcpServer } from 'node:net'
import type { AddressInfo, Server as TcpServer } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, isAbsolute, join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { parseComposeDocument } from './compose-parse.ts'
import type { ComposeHealthcheckSpec, ComposeServiceSource } from './compose-parse.ts'

export interface LabServiceHealthcheck {
  test?: string | string[]
  intervalMs?: number
  timeoutMs?: number
  retries?: number
  startPeriodMs?: number
  disabled?: boolean
}

export interface LabServiceSpec {
  name: string
  image?: string
  dockerfile?: string
  startCommand?: string
  command?: string | string[]
  entrypoint?: string | string[]
  internalPort?: number
  healthPath?: string
  healthcheck?: LabServiceHealthcheck
  env?: Record<string, string>
  memoryLimit?: string
  cpus?: string
  pidsLimit?: number
  dependsOn?: string[]
  networkAliases?: string[]
}

export interface LabConfig {
  enabled?: boolean
  repo?: string
  startCommand?: string
  dockerfile?: string
  dockerComposeFile?: string
  healthPath?: string
  internalPort?: number
  image?: string
  env?: Record<string, string>
  buildTimeoutMs?: number
  healthTimeoutMs?: number
  memoryLimit?: string
  cpus?: string
  pidsLimit?: number
  services?: LabServiceSpec[]
  seedCommand?: string
  iastEnabled?: boolean
  iastRuntime?: 'node' | 'python' | 'jvm' | 'generic'
}

export type DockerRunner = (args: string[], signal?: AbortSignal) => Promise<string>

export const SAFE_ENV_KEY = /^[A-Z_][A-Z0-9_]{0,63}$/
export const SAFE_SERVICE_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/
const SAFE_LABEL_VALUE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/
export const MAX_LAB_CONTAINERS = 6

/** Docker labels used to persist and reap every lab resource. */
export const LAB_LABELS = {
  lab: 'dev.guardian.lab',
  run: 'dev.guardian.run',
  service: 'dev.guardian.service',
  role: 'dev.guardian.role',
} as const

/** Proxy container image: a known-good Node runtime that runs only the trusted relay script. */
export const LAB_PROXY_IMAGE_DEFAULT = 'node:24-bookworm-slim'
export const LAB_PROXY_IMAGE_ENV = 'GUARDIAN_LAB_PROXY_IMAGE'
export const LAB_DB_VOLUMES_ENV = 'GUARDIAN_LAB_DB_VOLUMES'
export const LAB_STATE_DIR_ENV = 'GUARDIAN_LAB_STATE_DIR'
const LAB_PROXY_TARGET_FILE = 'target'
const LAB_PROXY_SOCKET_FILE = 'proxy.sock'
const LAB_PROXY_DIR_PREFIX = 'guardian-lab-proxy-'
const LAB_REPO_DIR_PREFIX = 'guardian-lab-repo-'
const LAB_TELEMETRY_DIR_PREFIX = 'guardian-lab-telemetry-'

/** Scratch-directory prefixes; exported so recovery/cleanup policies are unit-testable. */
export const LAB_PATHS = {
  repoPrefix: LAB_REPO_DIR_PREFIX,
  proxyPrefix: LAB_PROXY_DIR_PREFIX,
  telemetryPrefix: LAB_TELEMETRY_DIR_PREFIX,
} as const

const FORBIDDEN_ENV_KEYS = new Set([
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'LD_AUDIT',
  'LD_DEBUG',
  'PATH',
  'NODE_OPTIONS',
  'NODE_EXTRA_CA_CERTS',
  'PYTHONPATH',
  'PYTHONSTARTUP',
  'PYTHONHOME',
  'PERL5OPT',
  'RUBYOPT',
  'BASH_ENV',
  'ENV',
  'IFS',
  'GCONV_PATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'HOSTALIASES',
  'OPENSSL_CONF',
])

const FORBIDDEN_COMPOSE_KEYS = new Set([
  'privileged',
  'network_mode',
  'cap_add',
  'ports',
  'devices',
  'pid',
  'ipc',
  'uts',
  'userns_mode',
  'security_opt',
  'sysctls',
  'extra_hosts',
])

/** Operator override for the lab container uid:gid. Must be a non-root numeric user. */
export const LAB_CONTAINER_USER_ENV = 'GUARDIAN_LAB_USER'

/**
 * Choose the non-root user lab containers run as. Defaults to the invoking uid:gid so a bind
 * mounted, owner-only IAST telemetry dir stays writable without world permissions; when Guardian
 * itself runs as root the container falls back to nobody:nogroup.
 */
export function resolveLabContainerUser(env: NodeJS.ProcessEnv = process.env): string {
  const override = env[LAB_CONTAINER_USER_ENV]?.trim()
  const candidate = override && override.length > 0
    ? override
    : (() => {
      const uid = typeof process.getuid === 'function' ? process.getuid() : undefined
      if (uid === undefined || uid === 0) return '65534:65534'
      const gid = typeof process.getgid === 'function' ? process.getgid() : uid
      return `${uid}:${gid}`
    })()
  // Parse numerically: Docker accepts leading zeros (`00:00` is uid 0), so a textual check on the
  // first character is not enough. Reject any non-numeric form and any uid/gid that resolves to 0.
  const match = /^(\d{1,10}):(\d{1,10})$/.exec(candidate)
  if (!match) {
    throw new Error(`${LAB_CONTAINER_USER_ENV} must be numeric uid:gid.`)
  }
  const uid = Number(match[1])
  const gid = Number(match[2])
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid) || uid < 0 || gid < 0) {
    throw new Error(`${LAB_CONTAINER_USER_ENV} must be numeric uid:gid.`)
  }
  if (uid === 0 || gid === 0) {
    throw new Error(`Lab containers must run as a non-root user; ${LAB_CONTAINER_USER_ENV}=0:* or *:0 is rejected.`)
  }
  return `${uid}:${gid}`
}

// ===========================================================================
// Compose & service spec validation
// ===========================================================================

export function validateEnvMap(env: Record<string, string> | undefined, context: string): void {
  if (!env) return
  for (const key of Object.keys(env)) {
    if (!SAFE_ENV_KEY.test(key)) {
      throw new Error(`Unsafe environment variable key "${key}" rejected in ${context}: must match ${SAFE_ENV_KEY.source}.`)
    }
    if (FORBIDDEN_ENV_KEYS.has(key)) {
      throw new Error(`Forbidden unsafe environment variable key "${key}" rejected in ${context}.`)
    }
  }
}

function validateVolumeSpec(raw: unknown, serviceName: string): void {
  const value = typeof raw === 'string'
    ? raw.trim()
    : (raw && typeof raw === 'object' && 'source' in raw ? String((raw as Record<string, unknown>).source ?? '') : String(raw ?? ''))
  if (!value) return
  const hostSide = value.includes(':') ? value.split(':')[0] : value
  const normalized = hostSide.trim()
  // Allow only clean paths strictly inside sanitized /repos; reject all other host bind mounts or traversals.
  if (
    normalized.includes('..') ||
    normalized.startsWith('/') && !normalized.startsWith('/repos/') && normalized !== '/repos' ||
    normalized.startsWith('.') ||
    normalized.startsWith('~') ||
    normalized.includes('docker.sock')
  ) {
    throw new Error(`Forbidden unsafe volume bind mount "${value}" rejected on lab service "${serviceName}".`)
  }
}

function composeHealthcheckToSpec(healthcheck: ComposeHealthcheckSpec | undefined): LabServiceHealthcheck | undefined {
  if (!healthcheck) return undefined
  if (healthcheck.test === undefined) return undefined
  const spec: LabServiceHealthcheck = { test: healthcheck.test }
  if (healthcheck.intervalMs !== undefined) spec.intervalMs = healthcheck.intervalMs
  if (healthcheck.timeoutMs !== undefined) spec.timeoutMs = healthcheck.timeoutMs
  if (healthcheck.retries !== undefined) spec.retries = healthcheck.retries
  if (healthcheck.startPeriodMs !== undefined) spec.startPeriodMs = healthcheck.startPeriodMs
  if (healthcheck.disabled !== undefined) spec.disabled = healthcheck.disabled
  return spec
}

export function validateRawServiceObject(raw: Record<string, unknown>, fallbackName?: string): LabServiceSpec {
  const name = String(raw.name ?? fallbackName ?? '').trim()
  if (!SAFE_SERVICE_NAME.test(name)) {
    throw new Error(`Invalid lab service name "${name}": must match ${SAFE_SERVICE_NAME.source}.`)
  }

  for (const key of Object.keys(raw)) {
    const lower = key.toLowerCase()
    if (FORBIDDEN_COMPOSE_KEYS.has(lower)) {
      const val = raw[key]
      const isEmptyList = Array.isArray(val) && val.length === 0
      const isFalseFlag = lower === 'privileged' && (val === false || val === 'false')
      if (!isEmptyList && !isFalseFlag) {
        throw new Error(`Forbidden unsafe compose directive "${key}" rejected on lab service "${name}".`)
      }
    }
    if (lower === 'volumes') {
      const vols = Array.isArray(raw[key]) ? raw[key] as unknown[] : (raw[key] ? [raw[key]] : [])
      for (const vol of vols) validateVolumeSpec(vol, name)
    }
  }

  const envObj = (raw.env ?? raw.environment) as Record<string, string> | undefined
  if (envObj && typeof envObj === 'object' && !Array.isArray(envObj)) {
    validateEnvMap(envObj, `service "${name}"`)
  }

  const internalPort = raw.internalPort !== undefined ? Number(raw.internalPort) : undefined
  if (internalPort !== undefined && (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65_535)) {
    throw new Error(`Invalid internalPort "${raw.internalPort}" on lab service "${name}".`)
  }

  const dockerfile = typeof raw.dockerfile === 'string' && raw.dockerfile.trim()
    ? raw.dockerfile.trim()
    : undefined
  if (dockerfile && (dockerfile.startsWith('/') || dockerfile.includes('..') || dockerfile.includes('\0'))) {
    throw new Error(`Unsafe dockerfile path "${dockerfile}" rejected on lab service "${name}".`)
  }

  const rawCommand = raw.command ?? raw.startCommand
  let command: string | string[] | undefined
  if (Array.isArray(rawCommand)) {
    command = rawCommand.map(v => String(v))
  } else if (typeof rawCommand === 'string' && rawCommand.trim()) {
    command = rawCommand.trim()
  }

  const rawEntrypoint = raw.entrypoint
  let entrypoint: string | string[] | undefined
  if (Array.isArray(rawEntrypoint)) {
    entrypoint = rawEntrypoint.map(v => String(v))
  } else if (typeof rawEntrypoint === 'string' && rawEntrypoint.trim()) {
    entrypoint = rawEntrypoint.trim()
  }

  const rawDeps = raw.dependsOn ?? raw.depends_on
  const dependsOn = Array.isArray(rawDeps)
    ? rawDeps.map(d => String(d).trim()).filter(Boolean)
    : undefined

  const rawAliases = raw.networkAliases
  const networkAliases = Array.isArray(rawAliases)
    ? rawAliases.map(alias => String(alias).trim()).filter(alias => SAFE_SERVICE_NAME.test(alias)).slice(0, 8)
    : undefined

  const rawHealthcheck = raw.healthcheck
  const healthcheck = rawHealthcheck && typeof rawHealthcheck === 'object' && !Array.isArray(rawHealthcheck)
    ? composeHealthcheckToSpec(rawHealthcheck as ComposeHealthcheckSpec)
    : undefined

  return {
    name,
    image: typeof raw.image === 'string' && raw.image.trim() ? raw.image.trim() : undefined,
    dockerfile,
    startCommand: typeof raw.startCommand === 'string' && raw.startCommand.trim() ? raw.startCommand.trim() : undefined,
    command,
    entrypoint,
    internalPort,
    healthPath: typeof raw.healthPath === 'string' && raw.healthPath.trim() ? raw.healthPath.trim() : undefined,
    healthcheck,
    env: envObj && typeof envObj === 'object' && !Array.isArray(envObj) ? { ...envObj } : undefined,
    memoryLimit: typeof raw.memoryLimit === 'string' && raw.memoryLimit.trim() ? raw.memoryLimit.trim() : undefined,
    cpus: typeof raw.cpus === 'string' && raw.cpus.trim() ? raw.cpus.trim() : undefined,
    pidsLimit: typeof raw.pidsLimit === 'number' && Number.isInteger(raw.pidsLimit) ? raw.pidsLimit : undefined,
    dependsOn,
    networkAliases,
  }
}

/**
 * Derive a readiness path from a Compose healthcheck command. Only a bounded http(s) URL is
 * considered; everything else returns undefined and the caller falls back to the configured
 * healthPath + TCP readiness probe.
 */
export function deriveHealthPathFromHealthcheck(healthcheck: LabServiceHealthcheck | undefined): string | undefined {
  if (!healthcheck || healthcheck.disabled) return undefined
  const test = healthcheck.test
  const parts = Array.isArray(test) ? test : (typeof test === 'string' ? [test] : [])
  for (const part of parts) {
    const match = /https?:\/\/[^\s/'"`]+(\/[^\s'"`]*)?/.exec(part)
    if (match) {
      const path = (match[1] ?? '/').split('?')[0]
      if (path.startsWith('/') && path.length <= 256) return path
    }
  }
  return undefined
}

const COMPOSE_UNSUPPORTED_SERVICE_DIRECTIVES: ReadonlyMap<string, string> = new Map([
  ['env_file', 'env_file is not supported; pass environment values explicitly'],
  ['volumes_from', 'volumes_from is not supported'],
  ['extends', 'extends is not supported'],
  ['links', 'links is not supported'],
  ['tmpfs', 'tmpfs overlays are not supported; DB data dirs are provisioned automatically'],
  ['deploy', 'deploy is not supported; use memoryLimit/cpus/pidsLimit'],
  ['profiles', 'profiles are not supported'],
  ['secrets', 'secrets are not supported'],
  ['configs', 'configs are not supported'],
])

function validateComposeServiceSource(source: ComposeServiceSource): LabServiceSpec {
  const { name, config, normalized } = source
  if (!SAFE_SERVICE_NAME.test(name)) {
    throw new Error(`Invalid lab service name "${name}": must match ${SAFE_SERVICE_NAME.source}.`)
  }

  // Reject every forbidden/unsupported directive explicitly: never let an unrecognised Compose
  // key silently become no-op semantics.
  for (const key of Object.keys(config)) {
    if (key.startsWith('x-')) continue
    const lower = key.toLowerCase()
    if (COMPOSE_UNSUPPORTED_SERVICE_DIRECTIVES.has(lower)) {
      throw new Error(
        `Unsupported compose service directive "${key}" rejected on lab service "${name}": ` +
        `${COMPOSE_UNSUPPORTED_SERVICE_DIRECTIVES.get(lower)}.`,
      )
    }
    if (FORBIDDEN_COMPOSE_KEYS.has(lower)) {
      const value = config[key]
      const isEmptyList = Array.isArray(value) && value.length === 0
      const isFalseFlag = lower === 'privileged' && (value === false || value === 'false')
      if (!isEmptyList && !isFalseFlag) {
        throw new Error(`Forbidden unsafe compose directive "${key}" rejected on lab service "${name}".`)
      }
    }
  }

  if (normalized.ports.length > 0) {
    throw new Error(
      `Forbidden unsafe compose directive "ports" rejected on lab service "${name}": ` +
      'lab targets are reached through a loopback-only proxy and never publish host ports.',
    )
  }

  if (normalized.volumes.length > 0) {
    throw new Error(
      `Forbidden unsafe compose volume directive rejected on lab service "${name}": ` +
      'host bind mounts and pre-existing volumes are not supported; databases get a per-run writable overlay.',
    )
  }

  if (normalized.build) {
    const context = normalized.build.context
    if (context !== '.' && context !== './') {
      throw new Error(`Forbidden unsafe compose build context "${context}" on service "${name}".`)
    }
    if (normalized.build.args && Object.keys(normalized.build.args).length > 0) {
      throw new Error(`Unsupported compose build.args on service "${name}".`)
    }
    if (normalized.build.target !== undefined) {
      throw new Error(`Unsupported compose build.target on service "${name}".`)
    }
  }

  const dockerfile = normalized.build?.dockerfile
  if (dockerfile && (dockerfile.startsWith('/') || dockerfile.includes('..') || dockerfile.includes('\0'))) {
    throw new Error(`Unsafe dockerfile path "${dockerfile}" rejected on lab service "${name}".`)
  }

  if (normalized.user !== undefined) {
    const userValue = normalized.user.trim()
    const uidPart = userValue.includes(':') ? userValue.split(':')[0] : userValue
    if (uidPart === '0' || uidPart === 'root') {
      throw new Error(`Forbidden root user "${userValue}" rejected on lab service "${name}"; lab containers must run as non-root.`)
    }
  }

  const env = normalized.environment
  if (env) validateEnvMap(env, `service "${name}"`)

  const healthcheck = composeHealthcheckToSpec(normalized.healthcheck)
  const healthPath = deriveHealthPathFromHealthcheck(healthcheck)

  const internalPort = normalized.expose.length > 0 ? normalized.expose[0] : undefined
  if (internalPort !== undefined && (!Number.isInteger(internalPort) || internalPort < 1 || internalPort > 65_535)) {
    throw new Error(`Invalid expose port "${internalPort}" on lab service "${name}".`)
  }

  const command = normalized.command
  const dependsOn = normalized.dependsOn.length > 0 ? normalized.dependsOn : undefined
  const networkAliases = normalized.networkAliases.length > 0 ? normalized.networkAliases : undefined

  return {
    name,
    image: normalized.image,
    dockerfile,
    command,
    entrypoint: normalized.entrypoint,
    internalPort,
    healthPath,
    healthcheck,
    env,
    dependsOn,
    networkAliases,
  }
}

/**
 * Parse and sanitize a Docker Compose document. Replaces the v5 indentation-regex parser with the
 * bounded YAML parser in `compose-parse.ts`; every security decision stays in this module.
 */
export function parseAndSanitizeComposeYaml(
  yamlText: string,
  options: { env?: Record<string, string | undefined>; maxServices?: number } = {},
): LabServiceSpec[] {
  const document = parseComposeDocument(yamlText, {
    env: options.env ?? (process.env as Record<string, string | undefined>),
    maxServices: options.maxServices ?? MAX_LAB_CONTAINERS,
  })
  if (document.services.length > MAX_LAB_CONTAINERS) {
    throw new Error(`Lab stack exceeds maximum limit of ${MAX_LAB_CONTAINERS} containers per run (got ${document.services.length}).`)
  }
  return document.services.map(validateComposeServiceSource)
}

export function choosePrimaryService(services: readonly LabServiceSpec[], labConfig: LabConfig): LabServiceSpec {
  return (
    services.find(s => s.name === 'app') ??
    services.find(s => s.name === 'web' || s.name === 'api') ??
    (labConfig.internalPort ? services.find(s => s.internalPort === labConfig.internalPort) : undefined) ??
    services[0]
  )
}

// ===========================================================================
// Writable database overlays & container run argv
// ===========================================================================

export type LabDatabaseKind = 'postgres' | 'mysql' | 'mariadb' | 'redis' | 'mongo' | 'sqlite'

const DB_DEFAULT_PORTS: Record<Exclude<LabDatabaseKind, 'sqlite'>, number> = {
  postgres: 5432,
  mysql: 3306,
  mariadb: 3306,
  redis: 6379,
  mongo: 27017,
}

/** Strip registry, tag and digest from an image reference so `docker.io/library/postgres:16` -> `postgres`. */
export function normalizeImageRepository(image: string | undefined): string | undefined {
  if (!image) return undefined
  const withoutDigest = image.split('@')[0]
  const lastSegment = withoutDigest.slice(withoutDigest.lastIndexOf('/') + 1)
  const repo = lastSegment.split(':')[0].trim().toLowerCase()
  return repo || undefined
}

/**
 * Detect a database service from its image/command/env. Detection only decides where a writable
 * data dir is mounted; it never relaxes isolation (cap-drop ALL / no-new-privileges stay on).
 */
export function detectLabDatabaseKind(input: {
  image?: string
  command?: string | string[]
  env?: Record<string, string | undefined>
}): LabDatabaseKind | null {
  const repo = normalizeImageRepository(input.image)
  if (repo) {
    if (repo === 'postgres' || repo === 'postgresql') return 'postgres'
    if (repo === 'mysql') return 'mysql'
    if (repo === 'mariadb') return 'mariadb'
    if (repo === 'redis') return 'redis'
    if (repo === 'mongo' || repo === 'mongodb') return 'mongo'
    if (repo.includes('sqlite')) return 'sqlite'
  }
  const commandText = Array.isArray(input.command) ? input.command.join(' ') : (input.command ?? '')
  const envText = Object.entries(input.env ?? {})
    .map(([key, value]) => `${key}=${value ?? ''}`)
    .join(' ')
  const haystack = `${commandText} ${envText}`.toLowerCase()
  if (/\bpostgres(?:ql)?\b|\bpostmaster\b/.test(haystack)) return 'postgres'
  if (/\bmariadbd?\b/.test(haystack)) return 'mariadb'
  if (/\bmysqld\b/.test(haystack)) return 'mysql'
  if (/\bredis-server\b/.test(haystack)) return 'redis'
  if (/\bmongod\b/.test(haystack)) return 'mongo'
  if (/\bsqlite3?\b|sqlite:|\.(?:db|sqlite|sqlite3)\b/.test(haystack)) return 'sqlite'
  return null
}

/** Default container port for a detected database (used for readiness probes and base URLs). */
export function defaultLabDatabasePort(kind: LabDatabaseKind): number | undefined {
  return kind === 'sqlite' ? undefined : DB_DEFAULT_PORTS[kind]
}

export function labDataVolumeName(runId: string, serviceName: string, nonce?: string): string {
  const runSlug = runId.replace(/[^a-z0-9]/gi, '').slice(0, 12).toLowerCase() || 'run'
  const svcSlug = serviceName.replace(/[^a-z0-9]/gi, '').slice(0, 20).toLowerCase() || 'svc'
  const suffix = (nonce ?? createHash('sha256').update(`${runId}:${serviceName}:${randomUUID()}`).digest('hex')).slice(0, 8)
  return `guardian-lab-vol-${runSlug}-${svcSlug}-${suffix}`
}

export interface LabWritableOverlayInput {
  kind: LabDatabaseKind
  serviceName: string
  runId: string
  containerUser: string
  /** `tmpfs` (default) keeps DB state ephemeral; `volume` uses a labelled per-run named volume. */
  backing?: 'tmpfs' | 'volume'
  nonce?: string
  sizeMb?: number
}

export interface LabWritableOverlay {
  kind: LabDatabaseKind
  dataDir: string
  readOnlyRootfs: boolean
  tmpfsArgs: string[]
  mountArgs: string[]
  env: Record<string, string>
  volumeName?: string
}

function tmpfsSpec(
  target: string,
  options: { uid: number; gid: number; mode: number; sizeMb: number },
): string {
  return `${target}:rw,nosuid,nodev,size=${options.sizeMb}m,uid=${options.uid},gid=${options.gid},mode=0${options.mode.toString(8)}`
}

/**
 * Plan the writable data-dir overlay for a database service.
 */
export function buildWritableDataOverlay(input: LabWritableOverlayInput): LabWritableOverlay {
  const [uidRaw, gidRaw] = input.containerUser.split(':')
  const uid = Number(uidRaw)
  const gid = Number(gidRaw)
  if (!Number.isInteger(uid) || !Number.isInteger(gid) || uid <= 0 || gid <= 0) {
    throw new Error(`${LAB_CONTAINER_USER_ENV} must resolve to a non-root numeric uid:gid for writable overlays.`)
  }
  const backing = input.backing ?? 'tmpfs'
  const sizeMb = input.sizeMb ?? 256
  const dataTmpfs = tmpfsSpec('<data>', { uid, gid, mode: 0o700, sizeMb })
  const socketTmpfs = (target: string, mode: number): string =>
    tmpfsSpec(target, { uid, gid, mode, sizeMb: 16 })

  const plan = (dataDir: string, extraTmpfs: string[], env: Record<string, string> = {}): LabWritableOverlay => {
    const overlay: LabWritableOverlay = {
      kind: input.kind,
      dataDir,
      // DB init writes outside the data dir on some images; the data dir is still uid-scoped.
      readOnlyRootfs: false,
      tmpfsArgs: [],
      mountArgs: [],
      env,
    }
    if (backing === 'volume') {
      overlay.volumeName = labDataVolumeName(input.runId, input.serviceName, input.nonce)
      overlay.mountArgs.push('--mount', `type=volume,source=${overlay.volumeName},target=${dataDir}`)
    } else {
      overlay.tmpfsArgs.push(dataTmpfs.replace('<data>', dataDir))
    }
    overlay.tmpfsArgs.push(...extraTmpfs)
    return overlay
  }

  switch (input.kind) {
    case 'postgres': {
      const dataDir = '/var/lib/postgresql/data'
      return plan(dataDir, [socketTmpfs('/var/run/postgresql', 0o775)], { PGDATA: dataDir })
    }
    case 'mysql':
      return plan('/var/lib/mysql', [socketTmpfs('/var/run/mysqld', 0o775)])
    case 'mariadb':
      return plan('/var/lib/mysql', [socketTmpfs('/run/mysqld', 0o775)])
    case 'redis':
      return plan('/data', [])
    case 'mongo':
      return plan('/data/db', [socketTmpfs('/data/configdb', 0o700)])
    case 'sqlite':
      // SQLite runs inside the app container: keep the app rootfs read-only but give the DB file a
      // writable per-run data dir, and point DATABASE_URL at it when the URL names a repo file.
      return {
        ...plan('/app/data', [socketTmpfs('/data', 0o700)], { GUARDIAN_LAB_DATA_DIR: '/app/data' }),
        readOnlyRootfs: true,
      }
  }
}

/** Rewrite a repo-relative sqlite URL to the writable per-run data dir. Bounded, no host paths. */
export function rewriteSqliteDatabaseUrl(value: string): string {
  const match = /^sqlite:(?:\/\/)?(?:file:)?(?:\.\/)?\/?(?:[A-Za-z0-9._-]+\/)?([A-Za-z0-9._-]{1,128}\.(?:db|sqlite|sqlite3))$/i.exec(value.trim())
  if (!match) return value
  return `sqlite:/app/data/${match[1]}`
}

export function buildSyntheticEnvArgs(
  internalPort: number,
  env: Record<string, string> | undefined,
  extraInternalEnv: Record<string, string> = {},
): string[] {
  const synthetic: Record<string, string> = {
    PORT: String(internalPort),
    HOST: '0.0.0.0',
    NODE_ENV: 'test',
    GUARDIAN_LAB: '1',
  }
  for (const [k, v] of Object.entries(env ?? {})) {
    if (!SAFE_ENV_KEY.test(k) || FORBIDDEN_ENV_KEYS.has(k)) {
      throw new Error(`Forbidden unsafe environment variable key "${k}" rejected.`)
    }
    synthetic[k] = String(v).slice(0, 1024)
  }
  for (const [k, v] of Object.entries(extraInternalEnv)) {
    synthetic[k] = v
  }
  const args: string[] = []
  for (const [k, v] of Object.entries(synthetic)) {
    args.push('-e', `${k}=${v}`)
  }
  return args
}

export interface LabContainerRunArgsInput {
  containerName: string
  networkName: string
  runId: string
  serviceName: string
  imageName: string
  cmd: string[]
  internalPort: number
  mountArgs: string[]
  env: Record<string, string>
  extraEnv: Record<string, string>
  memoryLimit: string
  cpus: string
  pidsLimit: number
  user: string
  /** Defaults to true. Only database images that initialise outside their data dir opt out. */
  readOnly?: boolean
  /** Extra `--tmpfs <spec>` mounts (writable DB overlays). */
  writableTmpfs?: string[]
  /** Extra network aliases (Compose `networks.<name>.aliases`). */
  networkAliases?: string[]
  /** Docker `--entrypoint` override (Compose `entrypoint`). */
  entrypoint?: string
  /** Additional non-security labels (role markers). */
  extraLabels?: Record<string, string>
}

/** Pure builder for the `docker run` argv; exported so security invariants are unit-testable. */
export function buildLabContainerRunArgs(input: LabContainerRunArgsInput): string[] {
  const aliases = [...new Set([input.serviceName, ...(input.networkAliases ?? [])])]
    .filter(alias => SAFE_SERVICE_NAME.test(alias))
  const labels: string[] = [
    `${LAB_LABELS.lab}=1`,
    `${LAB_LABELS.run}=${input.runId}`,
    `${LAB_LABELS.service}=${input.serviceName}`,
  ]
  for (const [key, value] of Object.entries(input.extraLabels ?? {})) {
    if (!/^dev\.guardian\.[a-z-]{1,32}$/.test(key) || !SAFE_LABEL_VALUE.test(value)) continue
    labels.push(`${key}=${value}`)
  }
  const args: string[] = [
    'run', '-d',
    '--name', input.containerName,
    '--network', input.networkName,
  ]
  for (const alias of aliases) args.push('--network-alias', alias)
  args.push(
    '--user', input.user,
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
  )
  if (input.readOnly !== false) args.push('--read-only')
  args.push('--tmpfs', '/tmp:rw,nosuid,nodev,size=64m')
  for (const spec of input.writableTmpfs ?? []) args.push('--tmpfs', spec)
  args.push(
    '--memory', input.memoryLimit,
    '--memory-swap', input.memoryLimit,
    '--cpus', input.cpus,
    '--pids-limit', String(input.pidsLimit),
  )
  for (const label of labels) args.push('--label', label)
  if (input.entrypoint) args.push('--entrypoint', input.entrypoint)
  args.push(
    ...buildSyntheticEnvArgs(input.internalPort, input.env, input.extraEnv),
    ...input.mountArgs,
    input.imageName,
    ...input.cmd,
  )
  return args
}

// ===========================================================================
// Loopback -> proxy-container relay & --internal network helpers
// ===========================================================================

/**
 * Trusted relay script executed by the proxy container. It has no user input: it binds a Unix
 * socket inside the bind-mounted proxy dir, re-reads the target file for every connection (so a
 * patch rebuild can retarget it without restarting the proxy), and pipes bytes to the service by
 * container DNS name on the internal network. No host TCP port is ever published.
 */
export const LAB_PROXY_SCRIPT = [
  "const net=require('net'),fs=require('fs')",
  "const dir='/guardian-proxy'",
  "const sock=dir+'/proxy.sock'",
  "const targetFile=dir+'/target'",
  "function target(){",
  "  try{",
  "    const raw=fs.readFileSync(targetFile,'utf8').trim()",
  "    const idx=raw.lastIndexOf(':')",
  "    if(idx>0){",
  "      const host=raw.slice(0,idx)",
  "      const port=Number(raw.slice(idx+1))",
  "      if(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(host)&&Number.isInteger(port)&&port>0&&port<65536)return{host,port}",
  "    }",
  "  }catch{}",
  "  return{host:process.env.GUARDIAN_PROXY_TARGET_HOST||'127.0.0.1',port:Number(process.env.GUARDIAN_PROXY_TARGET_PORT||'8080')}",
  "}",
  "try{fs.unlinkSync(sock)}catch{}",
  "net.createServer(client=>{",
  "  const {host,port}=target()",
  "  const upstream=net.connect({host,port})",
  "  const teardown=()=>{try{client.destroy()}catch{};try{upstream.destroy()}catch{}}",
  "  client.pipe(upstream)",
  "  upstream.pipe(client)",
  "  client.on('error',teardown)",
  "  upstream.on('error',teardown)",
  "  client.on('close',()=>{try{upstream.destroy()}catch{}})",
  "  upstream.on('close',()=>{try{client.destroy()}catch{}})",
  "  upstream.setTimeout(120000,teardown)",
  "  client.setTimeout(120000,teardown)",
  "}).listen(sock,()=>{",
  "  try{fs.chmodSync(sock,process.env.GUARDIAN_PROXY_SOCKET_MODE==='666'?0o666:0o600)}catch{}",
  "  console.log('guardian-lab-proxy-ready')",
  "})",
].join('\n')

/** Pure builder for the per-run `--internal` bridge network argv. */
export function buildLabNetworkCreateArgs(runId: string, networkName: string): string[] {
  if (!SAFE_SERVICE_NAME.test(networkName)) {
    throw new Error(`Unsafe lab network name "${networkName}" rejected.`)
  }
  return [
    'network', 'create',
    '--driver', 'bridge',
    '--internal',
    '-o', 'com.docker.network.bridge.inhibit_ipv4=true',
    '--label', `${LAB_LABELS.lab}=1`,
    '--label', `${LAB_LABELS.run}=${runId}`,
    networkName,
  ]
}

export interface LabProxyRunArgsInput {
  containerName: string
  networkName: string
  runId: string
  proxyDir: string
  image?: string
  user: string
  targetHost: string
  targetPort: number
  socketMode: '600' | '666'
  memoryLimit?: string
  cpus?: string
  pidsLimit?: number
}

/**
 * Pure builder for the proxy container argv. The proxy is on the same `--internal` user-defined
 * network as the lab services (so it resolves them by container DNS), carries the run label for
 * reaping, runs non-root with all capabilities dropped, and publishes zero ports.
 */
export function buildLabProxyRunArgs(input: LabProxyRunArgsInput): string[] {
  const image = (input.image ?? LAB_PROXY_IMAGE_DEFAULT).trim()
  if (!/^[A-Za-z0-9][A-Za-z0-9_./:@-]{0,191}$/.test(image) || image.includes('..')) {
    throw new Error(`Unsafe lab proxy image reference "${image}" rejected.`)
  }
  if (!SAFE_SERVICE_NAME.test(input.targetHost) && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(input.targetHost)) {
    throw new Error(`Unsafe lab proxy target host "${input.targetHost}" rejected.`)
  }
  if (!Number.isInteger(input.targetPort) || input.targetPort < 1 || input.targetPort > 65_535) {
    throw new Error(`Unsafe lab proxy target port "${input.targetPort}" rejected.`)
  }
  if (!isAbsolute(input.proxyDir) || input.proxyDir.includes(',') || input.proxyDir.includes('\0')) {
    throw new Error('Lab proxy dir must be a clean absolute path.')
  }
  return [
    'run', '-d',
    '--name', input.containerName,
    '--network', input.networkName,
    '--user', input.user,
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--read-only',
    '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m',
    '--memory', input.memoryLimit ?? '128m',
    '--memory-swap', input.memoryLimit ?? '128m',
    '--cpus', input.cpus ?? '0.5',
    '--pids-limit', String(input.pidsLimit ?? 64),
    '--label', `${LAB_LABELS.lab}=1`,
    '--label', `${LAB_LABELS.run}=${input.runId}`,
    '--label', `${LAB_LABELS.role}=proxy`,
    '--mount', `type=bind,source=${input.proxyDir},target=/guardian-proxy`,
    '-e', 'GUARDIAN_PROXY_SOCKET_MODE=' + input.socketMode,
    '-e', 'GUARDIAN_PROXY_TARGET_HOST=' + input.targetHost,
    '-e', 'GUARDIAN_PROXY_TARGET_PORT=' + String(input.targetPort),
    image,
    'node', '-e', LAB_PROXY_SCRIPT,
  ]
}

/** Create the owner-only proxy handshake dir (socket + target file live here). */
export function createLabProxyDir(
  runId: string,
  containerUser = resolveLabContainerUser(),
  baseDir = tmpdir(),
): string {
  mkdirSync(baseDir, { recursive: true, mode: 0o755 })
  const hostUid = typeof process.getuid === 'function' ? process.getuid() : undefined
  const containerUid = Number(containerUser.split(':')[0])
  if (hostUid !== undefined && hostUid !== 0 && containerUid !== hostUid) {
    throw new Error(
      `Lab proxy handshake dir must be writable by the lab container user (uid ${containerUid}); ` +
      `Guardian runs as uid ${hostUid}. Set ${LAB_CONTAINER_USER_ENV}=${hostUid}:${containerUser.split(':')[1]} ` +
      'or run Guardian as root.',
    )
  }
  const slug = runId.replace(/[^a-z0-9]/gi, '').slice(0, 12).toLowerCase() || 'run'
  const dir = mkdtempSync(join(baseDir, `${LAB_PROXY_DIR_PREFIX}${slug}-`))
  chmodSync(dir, 0o700)
  if (hostUid === 0) {
    const [uidRaw, gidRaw] = containerUser.split(':')
    try { chownSync(dir, Number(uidRaw), Number(gidRaw)) } catch { /* perms stay 0700 */ }
  }
  return dir
}

/**
 * Decide the handshake socket mode. The handshake dir is 0700 and owned by the lab container uid
 * (createLabProxyDir rejects a non-root uid mismatch), so a 0600 socket is always connectable by
 * the host relay. The '666' branch is retained for operator-supplied dirs that intentionally widen
 * access.
 */
export function labProxySocketMode(_containerUser?: string): '600' | '666' {
  return '600'
}

/** Atomically retarget the proxy (used on start and after a patch rebuild). */
export function writeLabProxyTarget(dir: string, host: string, port: number): void {
  if (!SAFE_SERVICE_NAME.test(host) && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    throw new Error(`Unsafe lab proxy target host "${host}" rejected.`)
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`Unsafe lab proxy target port "${port}" rejected.`)
  }
  const targetPath = join(dir, LAB_PROXY_TARGET_FILE)
  const tmpPath = join(dir, `.target-${randomUUID()}.tmp`)
  writeFileSync(tmpPath, `${host}:${port}\n`, { encoding: 'utf8', mode: 0o644, flag: 'wx' })
  try {
    renameSync(tmpPath, targetPath)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
}

export async function waitForLabProxySocket(
  dir: string,
  timeoutMs = 15_000,
  signal?: AbortSignal,
): Promise<string> {
  const socketPath = join(dir, LAB_PROXY_SOCKET_FILE)
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    signal?.throwIfAborted()
    if (existsSync(socketPath)) return socketPath
    await delay(50, undefined, { signal }).catch(() => undefined)
  }
  throw new Error(`Lab proxy did not create its handshake socket within ${timeoutMs}ms.`)
}

/**
 * Host-side loopback listener. Each accepted TCP connection opens a Unix-socket connection to the
 * proxy container, so no `docker exec` process is spawned per connection and long-lived/streaming
 * protocols survive. Bound strictly to 127.0.0.1 (no 0.0.0.0, no published docker port).
 */
export function createLoopbackSocketForwarder(
  socketPath: string,
): Promise<{ server: TcpServer; port: number }> {
  return new Promise((resolvePromise, reject) => {
    const server = createTcpServer(clientSocket => {
      const upstream = connectTcp({ path: socketPath })
      clientSocket.pipe(upstream)
      upstream.pipe(clientSocket)
      const teardown = () => {
        try { clientSocket.destroy() } catch { /* ignore */ }
        try { upstream.destroy() } catch { /* ignore */ }
      }
      clientSocket.on('error', teardown)
      upstream.on('error', teardown)
      clientSocket.on('close', () => { try { upstream.destroy() } catch { /* ignore */ } })
      upstream.on('close', () => { try { clientSocket.destroy() } catch { /* ignore */ } })
    })
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo | null
      if (!addr || typeof addr.port !== 'number') {
        server.close()
        reject(new Error('Failed to allocate loopback ephemeral port for lab target.'))
        return
      }
      resolvePromise({ server, port: addr.port })
    })
  })
}

// ===========================================================================
// Readiness probes, start-command inference & seeded persona stdout parsing
// ===========================================================================

function readinessProbeCommand(kind: LabDatabaseKind | null, port: number): string[] | null {
  switch (kind) {
    case 'postgres':
      return ['pg_isready', '-h', '127.0.0.1', '-p', String(port)]
    case 'mysql':
    case 'mariadb':
      return ['mysqladmin', 'ping', '-h', '127.0.0.1', '--silent']
    case 'redis':
      return ['redis-cli', '-h', '127.0.0.1', '-p', String(port), 'ping']
    default:
      return null
  }
}

export async function waitForHealthCheck(
  origin: string,
  healthPath: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<void> {
  const path = healthPath.startsWith('/') ? healthPath : '/' + healthPath
  const url = `${origin}${path}`
  const deadline = Date.now() + timeoutMs
  let lastError = 'No response received'

  while (Date.now() < deadline) {
    signal?.throwIfAborted()
    try {
      const res = await fetch(url, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.any([
          AbortSignal.timeout(2_500),
          ...(signal ? [signal] : []),
        ]),
      })
      if (res.status < 500) {
        await res.body?.cancel().catch(() => undefined)
        return
      }
      lastError = `HTTP ${res.status}`
      await res.body?.cancel().catch(() => undefined)
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err)
    }
    await delay(250, undefined, { signal }).catch(() => undefined)
  }

  throw new Error(`Lab target health check timed out after ${timeoutMs}ms at ${url} (${lastError}).`)
}

export async function waitForContainerPort(
  docker: DockerRunner,
  containerName: string,
  port: number,
  options: { kind?: LabDatabaseKind | null; timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<void> {
  const timeoutMs = options.timeoutMs ?? 10_000
  const deadline = Date.now() + timeoutMs
  const probeJs = `const net=require('net');const s=net.connect(${port},'127.0.0.1',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),1000);`
  const nativeProbe = readinessProbeCommand(options.kind ?? null, port)
  while (Date.now() < deadline) {
    options.signal?.throwIfAborted()
    try {
      if (nativeProbe) {
        await docker(['exec', containerName, ...nativeProbe], AbortSignal.timeout(2_000))
        return
      }
      await docker(['exec', containerName, 'node', '-e', probeJs], AbortSignal.timeout(2_000))
      return
    } catch {
      await delay(200, undefined, { signal: options.signal }).catch(() => undefined)
    }
  }
  // Readiness of optional sidecars is advisory: the app health check is the authoritative gate.
}

export function resolveStartCommand(sanitizedRepoDir: string, labConfig: LabConfig): { image: string; cmd: string[] } {
  const image = labConfig.image || 'node:24-bookworm-slim'
  if (labConfig.startCommand?.trim()) {
    return { image, cmd: ['sh', '-c', labConfig.startCommand.trim()] }
  }
  if (existsSync(join(sanitizedRepoDir, 'server.ts'))) {
    return { image, cmd: ['node', '/app/server.ts'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'server.mjs'))) {
    return { image, cmd: ['node', '/app/server.mjs'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'server.js'))) {
    return { image, cmd: ['node', '/app/server.js'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'index.js'))) {
    return { image, cmd: ['node', '/app/index.js'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'package.json'))) {
    return { image, cmd: ['npm', 'start'] }
  }
  if (existsSync(join(sanitizedRepoDir, 'app.py'))) {
    return { image: labConfig.image || 'guardian-worker:local', cmd: ['python3', '/app/app.py'] }
  }
  throw new Error('Unable to infer lab start command. Specify labConfig.startCommand or labConfig.dockerfile.')
}

export function parseSeededPersonasFromStdout(stdout: string): Array<{
  handle: string
  roleLabel: string
  authKind: 'cookie' | 'bearer' | 'header'
  headerName?: string
  secret: string
  canaryMarkers: string[]
}> {
  const lines = stdout.trim().split('\n').map(l => l.trim()).filter(Boolean)
  let parsed: unknown = null
  try {
    parsed = JSON.parse(stdout.trim())
  } catch {
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        parsed = JSON.parse(lines[i])
        break
      } catch {
        // Keep searching upward for JSON line
      }
    }
  }
  if (!parsed || typeof parsed !== 'object') return []
  const rawList = Array.isArray(parsed)
    ? parsed
    : (Array.isArray((parsed as Record<string, unknown>).personas) ? (parsed as Record<string, unknown>).personas as unknown[] : [])
  const out: Array<{
    handle: string
    roleLabel: string
    authKind: 'cookie' | 'bearer' | 'header'
    headerName?: string
    secret: string
    canaryMarkers: string[]
  }> = []
  for (const item of rawList) {
    if (!item || typeof item !== 'object') continue
    const rec = item as Record<string, unknown>
    const handle = typeof rec.handle === 'string' ? rec.handle.trim() : ''
    const secret = typeof rec.secret === 'string' ? rec.secret.trim() : ''
    if (!handle || !/^[a-z0-9][a-z0-9_-]{0,47}$/.test(handle) || !secret) continue
    const authKind = rec.authKind === 'cookie' || rec.authKind === 'header' || rec.authKind === 'bearer'
      ? rec.authKind
      : 'bearer'
    const roleLabel = typeof rec.roleLabel === 'string' && rec.roleLabel.trim() ? rec.roleLabel.trim() : handle
    const headerName = typeof rec.headerName === 'string' && rec.headerName.trim() ? rec.headerName.trim() : undefined
    const canaryMarkers = Array.isArray(rec.canaryMarkers) ? rec.canaryMarkers.map(String).slice(0, 16) : []
    out.push({ handle, roleLabel, authKind, headerName, secret, canaryMarkers })
  }
  return out
}

// ===========================================================================
// Docker CLI execution & lab path/run-id guards
// ===========================================================================

export function validateLabRunId(runId: string): string {
  if (typeof runId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(runId)) {
    throw new Error(`Invalid lab run id "${String(runId).slice(0, 64)}": must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}.`)
  }
  return runId
}

/**
 * Remove a lab scratch directory only if it is a real directory named with one of our known
 * prefixes. Refuses symlinks and unexpected names so a corrupted/stale record can never delete an
 * arbitrary path.
 */
export function safeRemoveLabTempDir(
  dirPath: string | undefined,
  expectedPrefixes: readonly string[] = [LAB_PATHS.repoPrefix, LAB_PATHS.telemetryPrefix, LAB_PATHS.proxyPrefix, 'run-'],
): boolean {
  if (!dirPath || !isAbsolute(dirPath)) return false
  const name = basename(dirPath)
  if (!expectedPrefixes.some(prefix => name.startsWith(prefix))) return false
  try {
    const st = lstatSync(dirPath)
    if (st.isSymbolicLink() || !st.isDirectory()) return false
    rmSync(dirPath, { recursive: true, force: true })
    return true
  } catch {
    return false
  }
}

export function resolveLabStackServices(params: {
  labConfig: LabConfig
  composeYaml?: string
  env: NodeJS.ProcessEnv
}): { services: LabServiceSpec[]; primaryService: LabServiceSpec; sidecarServices: LabServiceSpec[] } {
  const { labConfig, composeYaml, env } = params
  validateEnvMap(labConfig.env, 'labConfig.env')

  const composeServices = composeYaml !== undefined
    ? parseAndSanitizeComposeYaml(composeYaml, { env })
    : undefined

  let explicitServices: LabServiceSpec[] | undefined
  if (Array.isArray(labConfig.services) && labConfig.services.length > 0) {
    if (labConfig.services.length > MAX_LAB_CONTAINERS) {
      throw new Error(`Lab stack exceeds maximum limit of ${MAX_LAB_CONTAINERS} containers per run (got ${labConfig.services.length}).`)
    }
    explicitServices = labConfig.services.map(raw =>
      validateRawServiceObject(raw as unknown as Record<string, unknown>),
    )
  }

  const services: LabServiceSpec[] = explicitServices
    ?? composeServices
    ?? [{
      name: 'app',
      image: labConfig.image,
      dockerfile: labConfig.dockerfile,
      startCommand: labConfig.startCommand,
      internalPort: labConfig.internalPort ?? 8080,
      healthPath: labConfig.healthPath ?? '/health',
      env: labConfig.env,
      memoryLimit: labConfig.memoryLimit,
      cpus: labConfig.cpus,
      pidsLimit: labConfig.pidsLimit,
    }]

  if (services.length > MAX_LAB_CONTAINERS) {
    throw new Error(`Lab stack exceeds maximum limit of ${MAX_LAB_CONTAINERS} containers per run (got ${services.length}).`)
  }

  const primaryService = choosePrimaryService(services, labConfig)
  const sidecarServices = services.filter(s => s !== primaryService)
  return { services, primaryService, sidecarServices }
}

function dockerHost(): string {
  const host = process.env.DOCKER_HOST || 'unix:///var/run/docker.sock'
  if (!/^unix:\/\/\/[^/?#\r\n][^?#\r\n]*$/.test(host)) {
    throw new Error('Guardian LabRunner requires a local Docker Unix socket.')
  }
  return host
}

function dockerEnv() {
  return {
    PATH: process.env.PATH,
    DOCKER_HOST: dockerHost(),
    XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
  }
}

export function runDocker(args: string[], signal?: AbortSignal): Promise<string> {
  signal?.throwIfAborted()
  return new Promise((resolvePromise, reject) => {
    const proc = spawn('docker', args, {
      signal,
      env: dockerEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []
    proc.stdout.on('data', (chunk: Buffer) => stdoutChunks.push(chunk))
    proc.stderr.on('data', (chunk: Buffer) => stderrChunks.push(chunk))
    proc.once('error', err => reject(signal?.aborted ? signal.reason : err))
    proc.once('close', code => {
      if (code === 0) {
        resolvePromise(Buffer.concat(stdoutChunks).toString('utf8'))
      } else {
        const stderr = Buffer.concat(stderrChunks).toString('utf8').trim()
        reject(new Error(`Docker command failed (${args.slice(0, 3).join(' ')}): ${stderr || `exit ${code}`}`))
      }
    })
  })
}

export function spawnDockerSync(args: string[], timeoutMs = 5_000): string {
  try {
    const result = spawnSync('docker', args, {
      env: dockerEnv(),
      timeout: timeoutMs,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    return typeof result.stdout === 'string' ? result.stdout : ''
  } catch {
    return ''
  }
}
