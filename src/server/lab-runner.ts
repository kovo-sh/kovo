import { spawn, spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  chownSync,
  closeSync,
  constants as fsConstants,
  copyFileSync,
  existsSync,
  fchmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import type { Stats } from 'node:fs'
import { connect as connectTcp, createServer as createTcpServer } from 'node:net'
import type { AddressInfo, Server as TcpServer } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { parseComposeDocument } from './compose-parse.ts'
import type { ComposeHealthcheckSpec, ComposeServiceSource } from './compose-parse.ts'
import { createProjectPersona, listProjectPersonas } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'

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

export interface SeededPersonaSummary {
  handle: string
  roleLabel: string
  authKind: 'cookie' | 'bearer' | 'header'
  headerName?: string
  personaId?: string
}

export interface StartLabTargetParams {
  runId: string
  environment: 'public' | 'local-lab'
  repoDir: string
  labConfig?: LabConfig
  signal?: AbortSignal
  telemetryDir?: string
  storage?: Store
  projectId?: string
}

export interface LabTargetHandle {
  targetId: string
  runId: string
  networkName: string
  containerName: string
  containerNames: string[]
  containerIp: string
  imageName: string
  origin: string
  baseUrls: Record<string, string>
  hostPort: number
  internalPort: number
  healthPath: string
  sanitizedRepoDir: string
  seededPersonas: SeededPersonaSummary[]
  telemetryDir?: string
  startedAt: number
  stop: () => Promise<void>
}

export interface IngestLabTelemetryInput {
  runId: string
  exchangeId: string
  traceId: string
  environment: string
  telemetryDir: string
  rawTelemetry: Record<string, unknown>
  secrets?: readonly NamedSecret[]
  storage?: Store
}

export interface IngestLabTelemetryResult {
  filePath: string
  bytesWritten: number
  artifactId: string
  routesHit: string[]
  newLinesCovered: number
  sinkEventsCount: number
  hasUnhandledException: boolean
}

interface InternalTargetState {
  handle: LabTargetHandle
  labConfig: LabConfig
  primaryService: LabServiceSpec
  builtImages: string[]
  containerNames: string[]
  containerIds: string[]
  volumes: string[]
  forwarder: TcpServer
  proxyContainerName: string
  proxyDir: string
  ownsTelemetryDir: boolean
}

const EXCLUDED_DIR_NAMES = new Set([
  '.git',
  '.aws',
  '.ssh',
  '.gnupg',
  '.kube',
])

const EXCLUDED_FILE_PATTERNS = [
  /^\.env(?:\..+)?$/i,
  /\.(?:pem|key|p12|pfx|jks|keystore)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
  /^\.(?:npmrc|netrc|pypirc|dockercfg)$/i,
  /^(?:secrets|credentials)\.(?:json|ya?ml|toml|env|txt)$/i,
]

const SAFE_ENV_KEY = /^[A-Z_][A-Z0-9_]{0,63}$/
const SAFE_SERVICE_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/
const SAFE_LABEL_VALUE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/
const MAX_LAB_CONTAINERS = 6
const MAX_TELEMETRY_BYTES = 65_536

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
const MAX_RECOVERED_RUNS = 32

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

const BUILTIN_IAST_SECRET_PATTERNS: readonly [RegExp, string][] = [
  [/\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g, '[redacted:aws]'],
  [/\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g, '[redacted:stripe]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g, '[redacted:jwt]'],
  [/\bBearer\s+[a-z0-9._~+/=-]{8,}/gi, 'Bearer [redacted]'],
  [/\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\n\r]+/gi, '[redacted:header]'],
]

const IAST_HOOKS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../local-lab/iast')

export function assertLocalLabAllowed(environment: string): void {
  if (environment !== 'local-lab') {
    throw new Error(
      `Local-lab app runner is forbidden on "${environment}" projects. Requires project.environment === 'local-lab'.`,
    )
  }
  if (process.env.GUARDIAN_ALLOW_LOCAL_LAB !== '1') {
    throw new Error('Local-lab app runner requires GUARDIAN_ALLOW_LOCAL_LAB=1.')
  }
}

function validateEnvMap(env: Record<string, string> | undefined, context: string): void {
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

function validateRawServiceObject(raw: Record<string, unknown>, fallbackName?: string): LabServiceSpec {
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

function scrubIastString(text: string, secrets: readonly NamedSecret[]): string {
  let out = redact(text, secrets)
  for (const [pattern, replacement] of BUILTIN_IAST_SECRET_PATTERNS) {
    out = out.replace(pattern, replacement)
  }
  return out
}

function scrubIastValue(value: unknown, secrets: readonly NamedSecret[], maxStringLen = 8192): unknown {
  if (typeof value === 'string') {
    const cleaned = scrubIastString(value, secrets)
    return cleaned.length > maxStringLen ? cleaned.slice(0, maxStringLen) + '…[truncated]' : cleaned
  }
  if (Array.isArray(value)) {
    return value.slice(0, 64).map(item => scrubIastValue(item, secrets, maxStringLen))
  }
  if (value && typeof value === 'object') {
    const redacted = redactJsonValue(value, secrets) as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(redacted)) {
      out[k] = scrubIastValue(v, secrets, maxStringLen)
    }
    return out
  }
  return value
}

function routeMatchesEndpoint(routePath: string, pathTemplate: string): boolean {
  const cleanRoute = routePath.split('?')[0].trim()
  const cleanTemplate = pathTemplate.split('?')[0].trim()
  if (!cleanRoute || !cleanTemplate) return false
  if (cleanRoute === cleanTemplate) return true
  const escaped = cleanTemplate
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\\\{[^}]+\\\}/g, '[^/]+')
  return new RegExp(`^${escaped}$`).test(cleanRoute)
}

export function ingestLabTelemetry(input: IngestLabTelemetryInput): IngestLabTelemetryResult {
  if (input.environment !== 'local-lab') {
    throw new Error(
      `IAST lab telemetry ingestion is forbidden on "${input.environment}" environments. Requires environment === 'local-lab'.`,
    )
  }

  const secrets = input.secrets ?? []
  const safeExchangeId = input.exchangeId.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 96) || randomUUID()
  const safeTraceId = scrubIastString(input.traceId || safeExchangeId, secrets).slice(0, 128)

  const raw = input.rawTelemetry ?? {}
  const rawRoutes = Array.isArray(raw.routesHit) ? raw.routesHit : []
  const routesHit = [...new Set(rawRoutes.map(r => scrubIastString(String(r), secrets).slice(0, 256)).filter(Boolean))]
  const newLinesCovered = typeof raw.newLinesCovered === 'number' && Number.isFinite(raw.newLinesCovered)
    ? Math.max(0, Math.round(raw.newLinesCovered))
    : 0
  const rawSinks = Array.isArray(raw.sinkEvents) ? raw.sinkEvents : []
  const rawExceptions = Array.isArray(raw.exceptions) ? raw.exceptions : []
  const sinkEventsCount = rawSinks.length
  const hasUnhandledException = rawExceptions.length > 0 || Boolean(raw.hasUnhandledException)

  // Progressively tighten string caps so serialized JSON is strictly <= 65536 UTF-8 bytes and always valid JSON.
  let finalJson = ''
  for (const strCap of [4096, 1024, 256, 64]) {
    const scrubbed = scrubIastValue(
      {
        runId: input.runId,
        exchangeId: safeExchangeId,
        traceId: safeTraceId,
        routesHit,
        newLinesCovered,
        sinkEventsCount,
        hasUnhandledException,
        sinkEvents: rawSinks,
        exceptions: rawExceptions,
        ...(strCap < 4096 ? { truncated: true } : {}),
        recordedAt: Date.now(),
      },
      secrets,
      strCap,
    )
    const candidate = scrubIastString(JSON.stringify(scrubbed), secrets)
    if (Buffer.byteLength(candidate, 'utf8') <= MAX_TELEMETRY_BYTES) {
      finalJson = candidate
      break
    }
  }

  if (!finalJson || Buffer.byteLength(finalJson, 'utf8') > MAX_TELEMETRY_BYTES) {
    const minimal = {
      runId: input.runId,
      exchangeId: safeExchangeId,
      traceId: safeTraceId,
      routesHit: routesHit.slice(0, 16),
      newLinesCovered,
      sinkEventsCount,
      hasUnhandledException,
      truncated: true,
      recordedAt: Date.now(),
    }
    finalJson = scrubIastString(JSON.stringify(minimal), secrets)
  }

  mkdirSync(input.telemetryDir, { recursive: true, mode: 0o700 })
  const filePath = join(input.telemetryDir, `${safeExchangeId}.json`)
  writeFileSync(filePath, finalJson, { encoding: 'utf8', mode: 0o600 })
  const bytesWritten = Buffer.byteLength(finalJson, 'utf8')

  if (input.storage) {
    input.storage.insertLabTelemetry({
      runId: input.runId,
      exchangeId: safeExchangeId,
      traceId: safeTraceId,
      routesHit,
      newLinesCovered,
      sinkEventsCount,
      hasUnhandledException,
      artifactId: safeExchangeId,
    })

    if (routesHit.length > 0) {
      const endpoints = input.storage.listEndpoints(input.runId)
      const deltaPct = Math.max(10, Math.min(100, newLinesCovered * 5))
      for (const ep of endpoints) {
        if (routesHit.some(route => routeMatchesEndpoint(route, ep.pathTemplate))) {
          const prevPct = ep.coveragePct ?? 0
          const nextPct = Math.min(100, Math.max(prevPct + deltaPct, deltaPct))
          input.storage.updateEndpointCoverage(ep.id, nextPct)
        }
      }
    }
  }

  return {
    filePath,
    bytesWritten,
    artifactId: safeExchangeId,
    routesHit,
    newLinesCovered,
    sinkEventsCount,
    hasUnhandledException,
  }
}

export type DockerRunner = (args: string[], signal?: AbortSignal) => Promise<string>

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

function runDocker(args: string[], signal?: AbortSignal): Promise<string> {
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

function shouldSkipCopy(name: string, isDir: boolean): boolean {
  if (isDir) return EXCLUDED_DIR_NAMES.has(name)
  return EXCLUDED_FILE_PATTERNS.some(pattern => pattern.test(name))
}

function copySanitizedRepo(srcDir: string, destDir: string, rootReal: string): void {
  mkdirSync(destDir, { recursive: true, mode: 0o755 })
  // Ensure world-readable directory traversal so --cap-drop ALL (no CAP_DAC_OVERRIDE) containers can read /app.
  chmodSync(destDir, 0o755)
  const entries = readdirSync(srcDir)
  for (const entry of entries) {
    const srcPath = join(srcDir, entry)
    const dstPath = join(destDir, entry)
    const st = lstatSync(srcPath)
    if (st.isSymbolicLink()) {
      try {
        const targetReal = realpathSync(srcPath)
        const rel = relative(rootReal, targetReal)
        if (rel.startsWith('..') || rel.includes(`${sep}..${sep}`)) continue
      } catch {
        continue
      }
      continue
    }
    if (st.isDirectory()) {
      if (shouldSkipCopy(entry, true)) continue
      copySanitizedRepo(srcPath, dstPath, rootReal)
    } else if (st.isFile()) {
      if (shouldSkipCopy(entry, false)) continue
      copyFileSync(srcPath, dstPath)
      chmodSync(dstPath, (st.mode & 0o111) ? 0o755 : 0o644)
    }
  }
}

/** lstat that treats a missing entry as absent but surfaces every other failure as unsafe. */
function lstatOrNull(fullPath: string, relPath: string): Stats | null {
  try {
    return lstatSync(fullPath)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return null
    throw new Error(`Unsafe file path rejected: "${relPath}" (${code ?? 'lstat failed'})`)
  }
}

export function safeResolveUnderRoot(rootDir: string, relPath: string): string {
  const clean = relPath.replace(/^[ab]\//, '').replace(/\\/g, '/')
  if (!clean || clean.includes('\0') || clean.startsWith('/') || clean.split('/').some(seg => seg === '..')) {
    throw new Error(`Unsafe file path rejected: "${relPath}"`)
  }
  const rootReal = realpathSync(rootDir)
  const full = resolve(rootReal, clean)
  const rel = relative(rootReal, full)
  if (rel.startsWith('..') || rel === '' || isAbsolute(rel)) {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }

  // Textual containment is not enough: a component below the root can be a symlink to /etc or to
  // an outside directory. Walk every component with lstat (NOT existsSync, which follows links and
  // therefore treats a dangling link as absent) and reject any link unconditionally.
  let deepestExisting = rootReal
  let cursor = rootReal
  for (const segment of rel.split(sep)) {
    cursor = join(cursor, segment)
    const st = lstatOrNull(cursor, relPath)
    if (!st) break
    if (st.isSymbolicLink()) {
      throw new Error(`Symlinked path rejected inside repository: "${relPath}"`)
    }
    deepestExisting = cursor
  }

  // The deepest existing parent's canonical path must stay under the canonical root. A dangling
  // link that survived the walk cannot (realpath throws), so this fails closed as well.
  let existingReal: string
  try {
    existingReal = realpathSync(deepestExisting)
  } catch {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }
  const existingRel = relative(rootReal, existingReal)
  if (existingRel.startsWith('..') || isAbsolute(existingRel)) {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }
  return full
}

/**
 * Create (or verify) every parent directory of `fullPath` one component at a time with lstat, so a
 * concurrently or previously planted symlink is never traversed by `mkdir -p`. Re-checks the
 * canonical parent immediately before returning, right before the caller writes.
 */
function ensureSafeParentChain(rootDir: string, fullPath: string, relPath: string): void {
  const rootReal = realpathSync(rootDir)
  const rel = relative(rootReal, fullPath)
  const segments = rel.split(sep).slice(0, -1)
  let cursor = rootReal
  for (const segment of segments) {
    cursor = join(cursor, segment)
    let st = lstatOrNull(cursor, relPath)
    if (!st) {
      try {
        mkdirSync(cursor, { mode: 0o755 })
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
      }
      st = lstatOrNull(cursor, relPath)
      if (!st) throw new Error(`Failed to create patch directory for: "${relPath}"`)
    }
    if (st.isSymbolicLink()) {
      throw new Error(`Symlinked path rejected inside repository: "${relPath}"`)
    }
    if (!st.isDirectory()) {
      throw new Error(`Patch parent path is not a directory: "${relPath}"`)
    }
  }

  const parentReal = realpathSync(dirname(fullPath))
  const parentRel = relative(rootReal, parentReal)
  if (parentRel.startsWith('..') || isAbsolute(parentRel)) {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }
}

function readFileNoFollow(fullPath: string): string {
  const fd = openSync(fullPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
  try {
    return readFileSync(fd, 'utf8')
  } finally {
    closeSync(fd)
  }
}

/**
 * Atomically place `content` at `fullPath` without ever following an existing path: either create
 * the file directly with O_CREAT|O_EXCL|O_NOFOLLOW (`createOnly`), or stage a temp file in the same
 * verified directory and rename it over the target (rename replaces the directory entry, it never
 * writes through a link). A final lstat refuses a target that became a link.
 */
function writeFileNoFollow(fullPath: string, content: string, createOnly: boolean): void {
  if (createOnly) {
    let fd: number | undefined
    try {
      fd = openSync(
        fullPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
        0o644,
      )
      writeSync(fd, content, null, 'utf8')
      fchmodSync(fd, 0o644)
    } finally {
      if (fd !== undefined) closeSync(fd)
    }
    return
  }

  const parent = dirname(fullPath)
  const tmpPath = join(parent, `.guardian-patch-${randomUUID()}.tmp`)
  let fd: number | undefined
  try {
    fd = openSync(
      tmpPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o644,
    )
    writeSync(fd, content, null, 'utf8')
    fchmodSync(fd, 0o644)
    closeSync(fd)
    fd = undefined

    const leaf = lstatOrNull(fullPath, fullPath)
    if (leaf?.isSymbolicLink()) {
      throw new Error(`Symlinked path rejected inside repository: "${fullPath}"`)
    }
    if (leaf && !leaf.isFile()) {
      throw new Error(`Patch target is not a regular file: "${fullPath}"`)
    }
    renameSync(tmpPath, fullPath)
  } catch (err) {
    if (fd !== undefined) {
      try { closeSync(fd) } catch { /* ignore */ }
    }
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
}


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

/**
 * Prepare the IAST telemetry dir: owner-only (0700) rather than world-writable, optionally handed
 * to the non-root container user when Guardian itself runs as root.
 */
export function prepareIastTelemetryDir(dir: string, containerUser = resolveLabContainerUser()): string {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  chmodSync(dir, 0o700)
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    const [uidRaw, gidRaw] = containerUser.split(':')
    try { chownSync(dir, Number(uidRaw), Number(gidRaw)) } catch { /* best effort; perms stay 0700 */ }
  }
  return dir
}

/**
 * Fail fast when the 0700 telemetry dir is not writable by the user the lab container runs as.
 * Non-root Guardian cannot chown, so a `GUARDIAN_LAB_USER` uid different from Guardian's own uid
 * would silently produce no IAST data; that combination is rejected explicitly instead.
 */
export function assertIastTelemetryDirWritable(
  dir: string,
  containerUser = resolveLabContainerUser(),
): void {
  const [uidRaw, gidRaw] = containerUser.split(':')
  const containerUid = Number(uidRaw)
  const containerGid = Number(gidRaw)
  const st = statSync(dir)
  const guardianUid = typeof process.getuid === 'function' ? process.getuid() : undefined

  if (guardianUid === 0) {
    if (st.uid !== containerUid || st.gid !== containerGid) {
      throw new Error(
        `IAST telemetry dir ${dir} could not be handed to lab container user ${containerUser} ` +
        `(still uid ${st.uid}:gid ${st.gid}); refusing to run without writable telemetry.`,
      )
    }
    return
  }
  if (guardianUid !== undefined && guardianUid !== containerUid) {
    throw new Error(
      `IAST telemetry dir ${dir} is owned by uid ${guardianUid}, but the lab container runs as ` +
      `${containerUser}. A 0700 telemetry dir cannot be written by a different uid, so IAST data ` +
      `would be silently lost. Set ${LAB_CONTAINER_USER_ENV}=${guardianUid}:${st.gid} or run Guardian as root.`,
    )
  }
}

/** Mount args for the IAST telemetry bind; read-only unless IAST telemetry is enabled. */
export function buildIastTelemetryMountArgs(dir: string, iastEnabled: boolean): string[] {
  return ['--mount', `type=bind,source=${dir},target=/var/run/guardian-iast${iastEnabled ? '' : ',readonly'}`]
}

/** Bounded retention for per-run telemetry dirs under a shared data-dir base. */
export const MAX_IAST_TELEMETRY_RUN_DIRS = 4
export const MAX_IAST_TELEMETRY_TOTAL_BYTES = 128 * 1024 * 1024
const MAX_IAST_TELEMETRY_WALK_ENTRIES = 20_000

function boundedDirectorySize(root: string): number {
  let total = 0
  let seen = 0
  const stack = [root]
  while (stack.length > 0 && seen < MAX_IAST_TELEMETRY_WALK_ENTRIES) {
    const current = stack.pop()!
    let entries
    try {
      entries = readdirSync(current, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      seen += 1
      if (seen >= MAX_IAST_TELEMETRY_WALK_ENTRIES) break
      const full = join(current, entry.name)
      try {
        const st = lstatSync(full)
        if (st.isSymbolicLink()) continue
        if (st.isDirectory()) stack.push(full)
        else if (st.isFile()) total += st.size
      } catch {
        // Best-effort accounting.
      }
    }
  }
  return total
}

/**
 * Best-effort bounded cleanup of previous per-run telemetry dirs. Keeps the newest `retain` dirs and
 * removes older ones (and any beyond the total size cap) so a long-lived data dir cannot grow
 * without bound. Only entries named `run-*` are touched; the base dir itself is never removed.
 */
export function pruneLabTelemetryDirs(
  baseDir: string,
  retain = MAX_IAST_TELEMETRY_RUN_DIRS,
  maxTotalBytes = MAX_IAST_TELEMETRY_TOTAL_BYTES,
): string[] {
  let names: string[]
  try {
    names = readdirSync(baseDir)
  } catch {
    return []
  }
  const runs: Array<{ path: string; mtimeMs: number }> = []
  for (const name of names) {
    if (!/^run-[a-z0-9-]{1,80}$/i.test(name)) continue
    const full = join(baseDir, name)
    try {
      const st = lstatSync(full)
      if (st.isSymbolicLink() || !st.isDirectory()) continue
      runs.push({ path: full, mtimeMs: st.mtimeMs })
    } catch {
      continue
    }
  }
  runs.sort((a, b) => b.mtimeMs - a.mtimeMs)
  const removed: string[] = []
  for (const stale of runs.slice(Math.max(0, retain))) {
    try {
      rmSync(stale.path, { recursive: true, force: true })
      removed.push(stale.path)
    } catch {
      // Best-effort cleanup.
    }
  }
  let kept = runs.slice(0, Math.max(0, retain))
  let total = kept.reduce((sum, r) => sum + boundedDirectorySize(r.path), 0)
  while (total > maxTotalBytes && kept.length > 0) {
    const oldest = kept.pop()!
    const size = boundedDirectorySize(oldest.path)
    try {
      rmSync(oldest.path, { recursive: true, force: true })
      total -= size
      removed.push(oldest.path)
    } catch {
      break
    }
  }
  return removed
}

/**
 * Create a unique, owner-only per-run telemetry dir under the shared base so two lab runs can never
 * read or overwrite each other's IAST artifacts. Returns the per-run directory to mount.
 */
export function createPerRunIastTelemetryDir(
  baseDir: string,
  runId: string,
  containerUser = resolveLabContainerUser(),
): string {
  mkdirSync(baseDir, { recursive: true, mode: 0o700 })
  chmodSync(baseDir, 0o700)
  pruneLabTelemetryDirs(baseDir)

  const slug = runId.replace(/[^a-z0-9]/gi, '').slice(0, 16).toLowerCase() || 'run'
  const rand = randomUUID().replace(/-/g, '').slice(0, 12)
  const dir = join(baseDir, `run-${slug}-${rand}`)
  mkdirSync(dir, { mode: 0o700 })
  prepareIastTelemetryDir(dir, containerUser)
  assertIastTelemetryDirWritable(dir, containerUser)
  return dir
}


// ===========================================================================
// Durable run state (crash recovery / orphan reaping)
// ===========================================================================

export interface LabRunRecord {
  version: 1
  runId: string
  networkName: string
  containerNames: string[]
  containerIds: string[]
  proxyContainerName?: string
  volumes: string[]
  sanitizedRepoDir?: string
  telemetryDir?: string
  ownsTelemetryDir?: boolean
  proxyDir?: string
  startedAt: number
  updatedAt: number
  pid: number
}

export interface LabRecoveryResult {
  runId: string
  containersRemoved: number
  networksRemoved: number
  volumesRemoved: number
  tempDirsRemoved: number
  recoveredFromRecord: boolean
}

export function validateLabRunId(runId: string): string {
  if (typeof runId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(runId)) {
    throw new Error(`Invalid lab run id "${String(runId).slice(0, 64)}": must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}.`)
  }
  return runId
}

function labRunRecordFileName(runId: string): string {
  const slug = runId.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 96)
  const digest = createHash('sha256').update(runId).digest('hex').slice(0, 8)
  return `${slug}-${digest}.json`
}

/** Directory holding crash-recovery records; owner-only, never inside the repo. */
export function labStateDir(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env[LAB_STATE_DIR_ENV]?.trim()
  const dir = configured && isAbsolute(configured) ? configured : join(tmpdir(), 'guardian-lab-state')
  return dir
}

export function labRunRecordPath(stateDir: string, runId: string): string {
  validateLabRunId(runId)
  return join(stateDir, labRunRecordFileName(runId))
}

export function readLabRunRecord(stateDir: string, runId: string): LabRunRecord | null {
  const recordPath = labRunRecordPath(stateDir, runId)
  try {
    const raw = readFileSync(recordPath, 'utf8')
    const parsed = JSON.parse(raw) as Partial<LabRunRecord>
    if (!parsed || parsed.version !== 1 || parsed.runId !== runId) return null
    if (!Array.isArray(parsed.containerNames) || !Array.isArray(parsed.containerIds)) return null
    return {
      version: 1,
      runId,
      networkName: typeof parsed.networkName === 'string' ? parsed.networkName : '',
      containerNames: parsed.containerNames.filter((name): name is string => typeof name === 'string').slice(0, 32),
      containerIds: parsed.containerIds.filter((id): id is string => typeof id === 'string').slice(0, 32),
      ...(typeof parsed.proxyContainerName === 'string' ? { proxyContainerName: parsed.proxyContainerName } : {}),
      volumes: Array.isArray(parsed.volumes)
        ? parsed.volumes.filter((name): name is string => typeof name === 'string').slice(0, 32)
        : [],
      ...(typeof parsed.sanitizedRepoDir === 'string' ? { sanitizedRepoDir: parsed.sanitizedRepoDir } : {}),
      ...(typeof parsed.telemetryDir === 'string' ? { telemetryDir: parsed.telemetryDir } : {}),
      ...(parsed.ownsTelemetryDir === true ? { ownsTelemetryDir: true } : {}),
      ...(typeof parsed.proxyDir === 'string' ? { proxyDir: parsed.proxyDir } : {}),
      startedAt: typeof parsed.startedAt === 'number' ? parsed.startedAt : Date.now(),
      updatedAt: typeof parsed.updatedAt === 'number' ? parsed.updatedAt : Date.now(),
      pid: typeof parsed.pid === 'number' ? parsed.pid : 0,
    }
  } catch {
    return null
  }
}

export function writeLabRunRecord(stateDir: string, record: LabRunRecord): void {
  validateLabRunId(record.runId)
  mkdirSync(stateDir, { recursive: true, mode: 0o700 })
  chmodSync(stateDir, 0o700)
  const target = labRunRecordPath(stateDir, record.runId)
  const tmpPath = join(stateDir, `.${basename(target)}.${randomUUID()}.tmp`)
  writeFileSync(tmpPath, `${JSON.stringify({ ...record, version: 1, updatedAt: Date.now() }, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  })
  try {
    renameSync(tmpPath, target)
  } catch (err) {
    try { unlinkSync(tmpPath) } catch { /* ignore */ }
    throw err
  }
}

export function removeLabRunRecord(stateDir: string, runId: string): void {
  try {
    unlinkSync(labRunRecordPath(stateDir, runId))
  } catch {
    // Idempotent: no record is a success.
  }
}

/**
 * Remove a lab scratch directory only if it is a real directory named with one of our known
 * prefixes. Refuses symlinks and unexpected names so a corrupted/stale record can never delete an
 * arbitrary path.
 */
export function safeRemoveLabTempDir(
  dirPath: string | undefined,
  expectedPrefixes: readonly string[] = [LAB_REPO_DIR_PREFIX, LAB_TELEMETRY_DIR_PREFIX, LAB_PROXY_DIR_PREFIX, 'run-'],
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

// ===========================================================================
// Writable database overlays
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
 *
 * v5 mounted the sanitized repo read-only and never gave Postgres/MySQL/Redis a writable data dir,
 * so `initdb`/`mysqld --initialize`/AOF writes aborted and the lab "health check timed out" with no
 * actionable signal. Every DB now gets:
 *   - a writable data dir owned by the non-root lab uid (tmpfs by default, labelled per-run volume
 *     on request),
 *   - the runtime socket dir as a writable tmpfs,
 *   - NO `--read-only` rootfs for DB images that write outside the data dir during init,
 *   - explicit PGDATA for Postgres and a rewritten `sqlite:` URL for SQLite app services.
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
// Loopback -> proxy-container relay
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
 * Decide the handshake socket mode. When the container uid differs from Guardian's uid (only
 * possible via GUARDIAN_LAB_USER) the proxy dir becomes traversable (0711) and the socket 0666 so
 * the host relay can connect; this matches the trust level of the existing loopback TCP listener
 * (any local user may reach the lab target) without exposing the target to the network at all.
 */
export function labProxySocketMode(_containerUser?: string): '600' | '666' {
  // The handshake dir is 0700 and owned by the lab container uid (createLabProxyDir rejects a
  // non-root uid mismatch), so a 0600 socket is always connectable by the host relay. The '666'
  // branch is retained for operator-supplied dirs that intentionally widen access.
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



interface ParsedHunk {
  oldStart: number
  oldCount: number
  newStart: number
  newCount: number
  lines: string[]
}

interface ParsedFilePatch {
  oldPath: string
  newPath: string
  hunks: ParsedHunk[]
}

function parseUnifiedDiff(diffText: string): ParsedFilePatch[] {
  const rawLines = diffText.replace(/\r\n/g, '\n').split('\n')
  const patches: ParsedFilePatch[] = []
  let i = 0

  while (i < rawLines.length) {
    const line = rawLines[i]
    if (line.startsWith('--- ')) {
      const oldPath = line.slice(4).split('\t')[0].trim()
      const nextLine = rawLines[i + 1] ?? ''
      if (!nextLine.startsWith('+++ ')) {
        i++
        continue
      }
      const newPath = nextLine.slice(4).split('\t')[0].trim()
      i += 2
      const hunks: ParsedHunk[] = []

      while (i < rawLines.length) {
        const hLine = rawLines[i]
        if (hLine.startsWith('--- ') || hLine.startsWith('diff --git ')) break
        const match = hLine.match(/^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/)
        if (!match) {
          i++
          continue
        }
        const oldStart = Number(match[1])
        const oldCount = match[2] !== undefined ? Number(match[2]) : 1
        const newStart = Number(match[3])
        const newCount = match[4] !== undefined ? Number(match[4]) : 1
        i++
        const hunkLines: string[] = []
        let seenOld = 0
        let seenNew = 0
        while (i < rawLines.length) {
          const contentLine = rawLines[i]
          if (contentLine.startsWith('@@ ') || contentLine.startsWith('diff --git ') || contentLine.startsWith('--- ')) {
            break
          }
          if (contentLine.startsWith('\\ No newline at end of file')) {
            i++
            continue
          }
          if (seenOld >= oldCount && seenNew >= newCount && contentLine === '') {
            i++
            break
          }
          if (contentLine.startsWith(' ')) {
            hunkLines.push(contentLine)
            seenOld++
            seenNew++
            i++
          } else if (contentLine.startsWith('-')) {
            hunkLines.push(contentLine)
            seenOld++
            i++
          } else if (contentLine.startsWith('+')) {
            hunkLines.push(contentLine)
            seenNew++
            i++
          } else if (contentLine === '' && (seenOld < oldCount || seenNew < newCount)) {
            hunkLines.push(' ')
            seenOld++
            seenNew++
            i++
          } else {
            break
          }
        }
        hunks.push({ oldStart, oldCount, newStart, newCount, lines: hunkLines })
      }

      if (hunks.length > 0) {
        patches.push({ oldPath, newPath, hunks })
      }
      continue
    }
    i++
  }

  return patches
}

export function applyUnifiedDiffToDirectory(rootDir: string, diffText: string): { filesModified: string[] } {
  const patches = parseUnifiedDiff(diffText)
  if (!patches.length) {
    throw new Error('Unified diff contains no valid file hunks.')
  }

  const backups = new Map<string, string | null>()
  const filesModified: string[] = []

  try {
    for (const patch of patches) {
      const isDelete = patch.newPath === '/dev/null'
      const isCreate = patch.oldPath === '/dev/null'
      const relTarget = isDelete ? patch.oldPath : patch.newPath
      const fullPath = safeResolveUnderRoot(rootDir, relTarget)
      const normalizedRel = relTarget.replace(/^[ab]\//, '')

      // lstat, not existsSync: a dangling link reports as absent to existsSync and would be written
      // through. safeResolveUnderRoot already rejects any link component, including the leaf.
      const leaf = lstatOrNull(fullPath, relTarget)
      const existed = leaf !== null
      if (existed && !leaf.isFile()) {
        throw new Error(`Patch target is not a regular file: ${normalizedRel}`)
      }
      if (!backups.has(fullPath)) {
        backups.set(fullPath, existed ? readFileNoFollow(fullPath) : null)
      }

      if (!existed && !isCreate) {
        throw new Error(`Target file does not exist for patch: ${normalizedRel}`)
      }
      if (isCreate && existed) {
        throw new Error(`Create-file patch target already exists: ${normalizedRel}`)
      }

      const originalContent = existed ? readFileNoFollow(fullPath) : ''
      const hadTrailingNewline = originalContent.endsWith('\n')
      const lines = originalContent === ''
        ? []
        : (hadTrailingNewline ? originalContent.slice(0, -1).split('\n') : originalContent.split('\n'))

      let lineOffset = 0
      for (const hunk of patch.hunks) {
        const expectedOld = hunk.lines
          .filter(l => l.startsWith(' ') || l.startsWith('-'))
          .map(l => l.slice(1))
        const replacement = hunk.lines
          .filter(l => l.startsWith(' ') || l.startsWith('+'))
          .map(l => l.slice(1))

        const nominalIdx = Math.max(0, hunk.oldStart - 1 + lineOffset)
        const matchesAt = (idx: number) => {
          if (idx < 0 || idx + expectedOld.length > lines.length) return false
          for (let k = 0; k < expectedOld.length; k++) {
            if (lines[idx + k] !== expectedOld[k]) return false
          }
          return true
        }

        let matchIdx = -1
        if (expectedOld.length === 0) {
          matchIdx = Math.min(nominalIdx, lines.length)
        } else if (matchesAt(nominalIdx)) {
          matchIdx = nominalIdx
        } else {
          for (let delta = 1; delta <= 15; delta++) {
            if (matchesAt(nominalIdx + delta)) {
              matchIdx = nominalIdx + delta
              break
            }
            if (matchesAt(nominalIdx - delta)) {
              matchIdx = nominalIdx - delta
              break
            }
          }
        }

        if (matchIdx === -1) {
          throw new Error(`Patch hunk failed to apply cleanly to ${normalizedRel} near line ${hunk.oldStart}.`)
        }

        lines.splice(matchIdx, expectedOld.length, ...replacement)
        lineOffset += replacement.length - expectedOld.length
      }

      if (isDelete) {
        // Re-check with lstat and only unlink a regular file; never unlink through a link.
        const current = lstatOrNull(fullPath, relTarget)
        if (current) {
          if (current.isSymbolicLink()) {
            throw new Error(`Symlinked path rejected inside repository: "${relTarget}"`)
          }
          unlinkSync(fullPath)
        }
      } else {
        ensureSafeParentChain(rootDir, fullPath, relTarget)
        // Re-verify the leaf immediately before writing: safeResolve + lstat above is not atomic.
        const latestLeaf = lstatOrNull(fullPath, relTarget)
        if (latestLeaf?.isSymbolicLink()) {
          throw new Error(`Symlinked path rejected inside repository: "${relTarget}"`)
        }
        if (isCreate && latestLeaf) {
          throw new Error(`Create-file patch target already exists: ${normalizedRel}`)
        }
        if (!isCreate && !latestLeaf) {
          throw new Error(`Target file does not exist for patch: ${normalizedRel}`)
        }
        const out = lines.length > 0 ? lines.join('\n') + '\n' : ''
        writeFileNoFollow(fullPath, out, isCreate)
      }
      filesModified.push(normalizedRel)
    }

    return { filesModified }
  } catch (err) {
    for (const [filePath, prev] of backups.entries()) {
      try {
        const relRestore = relative(realpathSync(rootDir), filePath)
        if (prev === null) {
          const current = lstatOrNull(filePath, relRestore)
          if (current && !current.isSymbolicLink()) unlinkSync(filePath)
        } else {
          ensureSafeParentChain(rootDir, filePath, relRestore)
          writeFileNoFollow(filePath, prev, false)
        }
      } catch {
        // Best-effort rollback
      }
    }
    throw err
  }
}


/** Readiness probe argv for known database images (falls back to a Node TCP probe). */
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

async function waitForHealthCheck(origin: string, healthPath: string, timeoutMs: number, signal?: AbortSignal): Promise<void> {
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

async function waitForContainerPort(
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

function buildSyntheticEnvArgs(
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

function resolveStartCommand(sanitizedRepoDir: string, labConfig: LabConfig): { image: string; cmd: string[] } {
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

function parseSeededPersonasFromStdout(stdout: string): Array<{
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

function choosePrimaryService(services: readonly LabServiceSpec[], labConfig: LabConfig): LabServiceSpec {
  return (
    services.find(s => s.name === 'app') ??
    services.find(s => s.name === 'web' || s.name === 'api') ??
    (labConfig.internalPort ? services.find(s => s.internalPort === labConfig.internalPort) : undefined) ??
    services[0]
  )
}

// ===========================================================================
// Signal / crash reaping
// ===========================================================================

const ACTIVE_LAB_RUNNERS = new Set<LabRunner>()
let labSignalHooksInstalled = false

function spawnDockerSync(args: string[], timeoutMs = 5_000): string {
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

function installLabSignalHooks(): void {
  if (labSignalHooksInstalled) return
  labSignalHooksInstalled = true
  const reapThenReraise = (signal: NodeJS.Signals) => {
    for (const runner of ACTIVE_LAB_RUNNERS) runner.reapSyncAll()
    // Re-deliver the signal with our listener removed so the default action/other handlers run.
    try {
      process.kill(process.pid, signal)
    } catch {
      // Ignore: the process is already exiting.
    }
  }
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.once(signal, () => reapThenReraise(signal))
  }
  process.once('exit', () => {
    for (const runner of ACTIVE_LAB_RUNNERS) runner.reapSyncAll()
  })
}

export interface LabRunnerOptions {
  /** Where crash-recovery records live. Defaults to GUARDIAN_LAB_STATE_DIR or <tmp>/guardian-lab-state. */
  stateDir?: string
  /** Injectable Docker CLI runner (tests use a deterministic fake). */
  docker?: DockerRunner
  env?: NodeJS.ProcessEnv
}

export class LabRunner {
  private readonly active = new Map<string, InternalTargetState>()
  private readonly docker: DockerRunner
  private readonly stateDir: string
  private readonly env: NodeJS.ProcessEnv

  constructor(options: LabRunnerOptions = {}) {
    this.docker = options.docker ?? runDocker
    this.env = options.env ?? process.env
    this.stateDir = options.stateDir ?? labStateDir(this.env)
  }

  getTarget(runId: string): LabTargetHandle | undefined {
    return this.active.get(runId)?.handle
  }

  listTargets(): LabTargetHandle[] {
    return [...this.active.values()].map(s => s.handle)
  }

  private async tryDocker(args: string[], signal?: AbortSignal): Promise<boolean> {
    try {
      await this.docker(args, signal ?? AbortSignal.timeout(10_000))
      return true
    } catch {
      return false
    }
  }

  private async listByLabel(kind: 'container' | 'network' | 'volume', runId: string): Promise<string[]> {
    const args = kind === 'container'
      ? ['ps', '-aq', '--filter', `label=${LAB_LABELS.run}=${runId}`]
      : kind === 'network'
        ? ['network', 'ls', '-q', '--filter', `label=${LAB_LABELS.run}=${runId}`]
        : ['volume', 'ls', '-q', '--filter', `label=${LAB_LABELS.run}=${runId}`]
    try {
      const out = await this.docker(args, AbortSignal.timeout(10_000))
      return out.trim().split(/\s+/).filter(Boolean).slice(0, 64)
    } catch {
      return []
    }
  }

  private recordFor(runId: string, state: InternalTargetState): LabRunRecord {
    return {
      version: 1,
      runId,
      networkName: state.handle.networkName,
      containerNames: [...state.containerNames],
      containerIds: [...state.containerIds],
      proxyContainerName: state.proxyContainerName,
      volumes: [...state.volumes],
      sanitizedRepoDir: state.handle.sanitizedRepoDir,
      ...(state.handle.telemetryDir ? { telemetryDir: state.handle.telemetryDir } : {}),
      ownsTelemetryDir: state.ownsTelemetryDir,
      proxyDir: state.proxyDir,
      startedAt: state.handle.startedAt,
      updatedAt: Date.now(),
      pid: process.pid,
    }
  }

  private persistState(runId: string): void {
    const state = this.active.get(runId)
    if (!state) return
    try {
      writeLabRunRecord(this.stateDir, this.recordFor(runId, state))
    } catch {
      // Persistence is best-effort: label-based reaping still covers a crash.
    }
  }

  private async launchServiceContainer(params: {
    runId: string
    networkName: string
    sanitizedRepoDir: string
    service: LabServiceSpec
    labConfig: LabConfig
    isPrimary: boolean
    telemetryDir?: string
    signal?: AbortSignal
  }): Promise<{
    containerName: string
    containerId: string
    containerIp: string
    imageName: string
    builtImage: boolean
    volumes: string[]
  }> {
    const { runId, networkName, sanitizedRepoDir, service, labConfig, isPrimary, telemetryDir, signal } = params
    const containerUser = resolveLabContainerUser(this.env)
    const shortId = createHash('sha256').update(`${runId}:${service.name}:${randomUUID()}`).digest('hex').slice(0, 10)
    const safeSvc = service.name.replace(/[^a-z0-9_-]/g, '').slice(0, 20) || 'svc'
    const containerName = `guardian-lab-${safeSvc}-${shortId}`
    const memoryLimit = service.memoryLimit ?? labConfig.memoryLimit ?? '512m'
    const cpus = service.cpus ?? labConfig.cpus ?? '1.0'
    const pidsLimit = service.pidsLimit ?? labConfig.pidsLimit ?? 128

    let imageName: string
    let builtImage = false
    let cmd: string[] = []
    const mountArgs: string[] = []

    const dockerfileRel = service.dockerfile
      ?? (isPrimary
        ? (labConfig.dockerfile
          || (!service.image && !service.command && !service.startCommand && !labConfig.startCommand && !labConfig.image && existsSync(join(sanitizedRepoDir, 'Dockerfile'))
            ? 'Dockerfile'
            : undefined))
        : undefined)

    const rawCommand = service.command ?? service.startCommand ?? (isPrimary ? labConfig.startCommand : undefined)
    const rawEntrypoint = service.entrypoint
    let entrypointArg: string | undefined
    if (Array.isArray(rawEntrypoint) && rawEntrypoint.length > 0) {
      entrypointArg = rawEntrypoint[0]
    } else if (typeof rawEntrypoint === 'string' && rawEntrypoint.trim()) {
      entrypointArg = rawEntrypoint.trim()
    }

    if (dockerfileRel) {
      const dockerfileFull = safeResolveUnderRoot(sanitizedRepoDir, dockerfileRel)
      if (!existsSync(dockerfileFull)) {
        throw new Error(`Lab Dockerfile not found: ${dockerfileRel}`)
      }
      imageName = `guardian-lab-img-${safeSvc}-${shortId}:local`
      const buildSignal = AbortSignal.any([
        AbortSignal.timeout(labConfig.buildTimeoutMs ?? 120_000),
        ...(signal ? [signal] : []),
      ])
      await this.docker(
        ['build', '--pull=false', '--network', 'none', '-f', dockerfileFull, '-t', imageName, sanitizedRepoDir],
        buildSignal,
      )
      builtImage = true
      if (Array.isArray(rawCommand)) {
        cmd = rawCommand
      } else if (typeof rawCommand === 'string' && rawCommand.trim()) {
        cmd = ['sh', '-c', rawCommand.trim()]
      }
    } else if (service.image || service.command || service.startCommand) {
      imageName = service.image || labConfig.image || 'node:24-bookworm-slim'
      if (Array.isArray(rawCommand)) {
        cmd = rawCommand
      } else if (typeof rawCommand === 'string' && rawCommand.trim()) {
        cmd = ['sh', '-c', rawCommand.trim()]
      } else if (isPrimary) {
        const resolved = resolveStartCommand(sanitizedRepoDir, { ...labConfig, image: imageName })
        imageName = resolved.image
        cmd = resolved.cmd
      }
      mountArgs.push('--mount', `type=bind,source=${sanitizedRepoDir},target=/app,readonly`, '--workdir', '/app')
    } else {
      const resolved = resolveStartCommand(sanitizedRepoDir, labConfig)
      imageName = resolved.image
      cmd = resolved.cmd
      mountArgs.push('--mount', `type=bind,source=${sanitizedRepoDir},target=/app,readonly`, '--workdir', '/app')
    }

    // Compose entrypoint arrays keep the image binary but prepend their arguments to the command.
    if (Array.isArray(rawEntrypoint) && rawEntrypoint.length > 1) {
      cmd = [...rawEntrypoint.slice(1), ...cmd]
    }

    const mergedEnv: Record<string, string> = { ...(isPrimary ? labConfig.env : undefined), ...(service.env ?? {}) }
    const dbKind = detectLabDatabaseKind({
      image: imageName,
      command: cmd,
      env: mergedEnv,
    })

    // SQLite files normally live under the read-only /app bind mount; point them at the overlay.
    if (dbKind === 'sqlite' && mergedEnv.DATABASE_URL) {
      mergedEnv.DATABASE_URL = rewriteSqliteDatabaseUrl(mergedEnv.DATABASE_URL)
    }

    const extraInternalEnv: Record<string, string> = {}
    const volumes: string[] = []
    let overlay: LabWritableOverlay | null = null
    if (dbKind) {
      overlay = buildWritableDataOverlay({
        kind: dbKind,
        serviceName: service.name,
        runId,
        containerUser,
        backing: this.env[LAB_DB_VOLUMES_ENV] === '1' ? 'volume' : 'tmpfs',
      })
      mountArgs.push(...overlay.mountArgs)
      Object.assign(extraInternalEnv, overlay.env)
      if (overlay.volumeName) {
        const sized = ['volume', 'create',
          '--label', `${LAB_LABELS.lab}=1`,
          '--label', `${LAB_LABELS.run}=${runId}`,
          '--label', `${LAB_LABELS.service}=${service.name}`,
          overlay.volumeName,
        ]
        await this.docker(sized, signal)
        volumes.push(overlay.volumeName)
      }
    }

    if (isPrimary && telemetryDir) {
      const iastActive = Boolean(labConfig.iastEnabled)
      mountArgs.push(...buildIastTelemetryMountArgs(telemetryDir, iastActive))
      if (iastActive) {
        extraInternalEnv.GUARDIAN_IAST_OUT_DIR = '/var/run/guardian-iast'
        if (existsSync(IAST_HOOKS_DIR)) {
          mountArgs.push('--mount', `type=bind,source=${IAST_HOOKS_DIR},target=/opt/guardian-iast,readonly`)
          const runtime = labConfig.iastRuntime ?? 'node'
          if (runtime === 'node' && existsSync(join(IAST_HOOKS_DIR, 'node-hook.mjs'))) {
            extraInternalEnv.NODE_OPTIONS = '--import=/opt/guardian-iast/node-hook.mjs'
          } else if (runtime === 'python' && existsSync(join(IAST_HOOKS_DIR, 'python', 'sitecustomize.py'))) {
            extraInternalEnv.PYTHONPATH = '/opt/guardian-iast/python'
          }
        }
      }
    }

    const dbDefaultPort = dbKind ? defaultLabDatabasePort(dbKind) : undefined
    const internalPort = service.internalPort
      ?? dbDefaultPort
      ?? (isPrimary ? (labConfig.internalPort ?? 8080) : 8080)

    const runArgs = buildLabContainerRunArgs({
      containerName,
      networkName,
      runId,
      serviceName: service.name,
      imageName,
      cmd,
      internalPort,
      mountArgs,
      env: mergedEnv,
      extraEnv: extraInternalEnv,
      memoryLimit,
      cpus,
      pidsLimit,
      user: containerUser,
      readOnly: overlay ? overlay.readOnlyRootfs : true,
      writableTmpfs: overlay?.tmpfsArgs ?? [],
      networkAliases: service.networkAliases,
      ...(entrypointArg ? { entrypoint: entrypointArg } : {}),
    })

    try {
      await this.docker(runArgs, signal)
      const containerId = (await this.docker(['inspect', '-f', '{{.Id}}', containerName], signal)).trim()
      const rawIp = (await this.docker(
        ['inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', containerName],
        signal,
      )).trim()
      if (!rawIp || !/^\d+\.\d+\.\d+\.\d+$/.test(rawIp)) {
        throw new Error(`Failed to resolve internal bridge IP for lab container ${containerName}.`)
      }
      if (!/^[a-f0-9]{12,64}$/.test(containerId)) {
        throw new Error(`Failed to resolve container id for lab container ${containerName}.`)
      }
      return { containerName, containerId, containerIp: rawIp, imageName, builtImage, volumes }
    } catch (err) {
      await this.docker(['container', 'rm', '--force', containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      if (builtImage) {
        await this.docker(['image', 'rm', '--force', imageName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      for (const volume of volumes) {
        await this.docker(['volume', 'rm', '--force', volume], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      throw err
    }
  }

  async startLabTarget(params: StartLabTargetParams): Promise<LabTargetHandle> {
    assertLocalLabAllowed(params.environment)
    validateLabRunId(params.runId)
    params.signal?.throwIfAborted()
    installLabSignalHooks()
    ACTIVE_LAB_RUNNERS.add(this)

    if (!existsSync(params.repoDir) || !statSync(params.repoDir).isDirectory()) {
      throw new Error(`Lab repository directory does not exist: ${params.repoDir}`)
    }

    const labConfig: LabConfig = params.labConfig ?? {}
    const containerUser = resolveLabContainerUser(this.env)

    // Strict pre-launch validation BEFORE touching Docker or creating any networks/containers!
    validateEnvMap(labConfig.env, 'labConfig.env')

    let composeServices: LabServiceSpec[] | undefined
    if (labConfig.dockerComposeFile?.trim()) {
      const composePath = safeResolveUnderRoot(params.repoDir, labConfig.dockerComposeFile.trim())
      if (!existsSync(composePath)) {
        throw new Error(`Docker Compose file not found: ${labConfig.dockerComposeFile}`)
      }
      const composeYaml = readFileSync(composePath, 'utf8')
      composeServices = parseAndSanitizeComposeYaml(composeYaml, { env: this.env })
    }

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

    // Stop any previous lab target for this run before creating a new one.
    if (this.active.has(params.runId)) {
      await this.stopLabTarget(params.runId)
    }

    const internalPort = primaryService.internalPort ?? labConfig.internalPort ?? 8080
    const healthPath = primaryService.healthPath
      ?? deriveHealthPathFromHealthcheck(primaryService.healthcheck)
      ?? labConfig.healthPath
      ?? '/health'
    const runSlug = params.runId.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase() || 'run'
    const shortRand = createHash('sha256').update(`${params.runId}:${randomUUID()}`).digest('hex').slice(0, 8)
    const networkName = `guardian-lab-${runSlug}-${shortRand}`

    const sanitizedRepoDir = mkdtempSync(join(tmpdir(), LAB_REPO_DIR_PREFIX))
    const repoReal = realpathSync(params.repoDir)
    copySanitizedRepo(repoReal, sanitizedRepoDir, repoReal)

    let telemetryDir: string | undefined
    let ownsTelemetryDir = false
    let ephemeralTelemetryDir = false
    if (labConfig.iastEnabled) {
      // IAST telemetry is mounted into the lab container. Keep each run's dir owner-only (0700),
      // unique per run (never shared across runs), and run the container as a non-root user.
      if (params.telemetryDir) {
        telemetryDir = createPerRunIastTelemetryDir(params.telemetryDir, params.runId, containerUser)
        ephemeralTelemetryDir = true
      } else {
        telemetryDir = prepareIastTelemetryDir(
          mkdtempSync(join(tmpdir(), LAB_TELEMETRY_DIR_PREFIX)),
          containerUser,
        )
        assertIastTelemetryDirWritable(telemetryDir, containerUser)
        ownsTelemetryDir = true
        ephemeralTelemetryDir = true
      }
    }

    const proxyDir = createLabProxyDir(params.runId, containerUser)
    const proxyContainerName = `guardian-lab-proxy-${shortRand}`
    const socketMode = labProxySocketMode(containerUser)

    let networkCreated = false
    let proxyStarted = false
    const containerNames: string[] = []
    const containerIds: string[] = []
    const builtImages: string[] = []
    const volumes: string[] = []
    let forwarder: TcpServer | undefined

    try {
      // Dedicated per-run Docker --internal bridge network with inhibit_ipv4=true:
      // zero internet egress AND zero host bridge gateway IP (blocks access to host 0.0.0.0 services!).
      await this.docker(
        buildLabNetworkCreateArgs(params.runId, networkName),
        params.signal,
      )
      networkCreated = true

      const baseUrls: Record<string, string> = {}

      // Launch sidecars first so primary app and seedCommand can reach them by service DNS alias.
      for (const sidecar of sidecarServices) {
        const launched = await this.launchServiceContainer({
          runId: params.runId,
          networkName,
          sanitizedRepoDir,
          service: sidecar,
          labConfig,
          isPrimary: false,
          signal: params.signal,
        })
        containerNames.push(launched.containerName)
        containerIds.push(launched.containerId)
        volumes.push(...launched.volumes)
        if (launched.builtImage) builtImages.push(launched.imageName)
        const sidecarKind = detectLabDatabaseKind({
          image: sidecar.image,
          command: sidecar.command,
          env: sidecar.env,
        })
        const sidecarPort = sidecar.internalPort ?? defaultLabDatabasePort(sidecarKind ?? 'sqlite')
        if (sidecarPort) {
          if (!sidecarKind) baseUrls[sidecar.name] = `http://${sidecar.name}:${sidecarPort}`
          await waitForContainerPort(this.docker, launched.containerName, sidecarPort, {
            kind: sidecarKind,
            timeoutMs: 8_000,
            signal: params.signal,
          })
        }
      }

      const primaryLaunched = await this.launchServiceContainer({
        runId: params.runId,
        networkName,
        sanitizedRepoDir,
        service: primaryService,
        labConfig,
        isPrimary: true,
        telemetryDir,
        signal: params.signal,
      })
      containerNames.push(primaryLaunched.containerName)
      containerIds.push(primaryLaunched.containerId)
      volumes.push(...primaryLaunched.volumes)
      if (primaryLaunched.builtImage) builtImages.push(primaryLaunched.imageName)

      // Point the in-network proxy at the primary container (container DNS name, unique per launch).
      writeLabProxyTarget(proxyDir, primaryLaunched.containerName, internalPort)
      await this.docker(buildLabProxyRunArgs({
        containerName: proxyContainerName,
        networkName,
        runId: params.runId,
        proxyDir,
        image: this.env[LAB_PROXY_IMAGE_ENV]?.trim() || LAB_PROXY_IMAGE_DEFAULT,
        user: containerUser,
        targetHost: primaryLaunched.containerName,
        targetPort: internalPort,
        socketMode,
      }), params.signal)
      proxyStarted = true
      let socketPath: string
      try {
        socketPath = await waitForLabProxySocket(proxyDir, 15_000, params.signal)
      } catch (err) {
        const status = await this.docker(
          ['inspect', '-f', '{{.State.Status}} exit={{.State.ExitCode}}', proxyContainerName],
          AbortSignal.timeout(5_000),
        ).catch(() => 'unavailable')
        throw new Error(`${err instanceof Error ? err.message : String(err)} (proxy container: ${status.trim()}).`)
      }
      const proxy = await createLoopbackSocketForwarder(socketPath)
      forwarder = proxy.server

      const origin = `http://127.0.0.1:${proxy.port}`
      baseUrls[primaryService.name] = origin
      baseUrls.primary = origin

      await waitForHealthCheck(origin, healthPath, labConfig.healthTimeoutMs ?? 30_000, params.signal)

      // Execute optional deterministic seedCommand inside the --internal network.
      const seededPersonas: SeededPersonaSummary[] = []
      if (labConfig.seedCommand?.trim()) {
        const seedSignal = AbortSignal.any([
          AbortSignal.timeout(30_000),
          ...(params.signal ? [params.signal] : []),
        ])
        const seedStdout = await this.docker(
          ['exec', primaryLaunched.containerName, 'sh', '-c', labConfig.seedCommand.trim()],
          seedSignal,
        )
        const parsedPersonas = parseSeededPersonasFromStdout(seedStdout)
        const existingHandles = params.storage && params.projectId
          ? new Set(listProjectPersonas(params.storage, params.projectId).map(p => p.handle))
          : new Set<string>()

        for (const p of parsedPersonas) {
          let personaId: string | undefined
          if (params.storage && params.projectId && !existingHandles.has(p.handle)) {
            const created = createProjectPersona(params.storage, {
              requestId: randomUUID(),
              projectId: params.projectId,
              handle: p.handle,
              roleLabel: p.roleLabel,
              originAllowlist: [origin],
              authKind: p.authKind,
              headerName: p.headerName,
              secret: p.secret,
              canaryMarkers: p.canaryMarkers,
            })
            personaId = created.id
            existingHandles.add(p.handle)
          }
          seededPersonas.push({
            handle: p.handle,
            roleLabel: p.roleLabel,
            authKind: p.authKind,
            ...(p.headerName ? { headerName: p.headerName } : {}),
            ...(personaId ? { personaId } : {}),
          })
        }
      }

      const handle: LabTargetHandle = {
        targetId: `${params.runId}:${primaryLaunched.containerName}`,
        runId: params.runId,
        networkName,
        containerName: primaryLaunched.containerName,
        containerNames: [...containerNames],
        containerIp: primaryLaunched.containerIp,
        imageName: primaryLaunched.imageName,
        origin,
        baseUrls,
        hostPort: proxy.port,
        internalPort,
        healthPath,
        sanitizedRepoDir,
        seededPersonas,
        ...(telemetryDir ? { telemetryDir } : {}),
        startedAt: Date.now(),
        stop: () => this.stopLabTarget(params.runId),
      }

      this.active.set(params.runId, {
        handle,
        labConfig,
        primaryService,
        builtImages,
        containerNames,
        containerIds,
        volumes,
        forwarder: proxy.server,
        proxyContainerName,
        proxyDir,
        ownsTelemetryDir,
      })
      this.persistState(params.runId)

      return handle
    } catch (err) {
      if (forwarder) {
        await new Promise<void>(res => forwarder!.close(() => res())).catch(() => undefined)
      }
      if (proxyStarted) {
        await this.docker(['container', 'rm', '--force', proxyContainerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      for (const cname of containerNames) {
        await this.docker(['container', 'rm', '--force', cname], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      await this.sweepOrphanContainersForRun(params.runId)
      for (const vol of volumes) {
        await this.docker(['volume', 'rm', '--force', vol], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      for (const img of builtImages) {
        await this.docker(['image', 'rm', '--force', img], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      if (networkCreated) {
        await this.docker(['network', 'rm', networkName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      safeRemoveLabTempDir(sanitizedRepoDir, [LAB_REPO_DIR_PREFIX])
      safeRemoveLabTempDir(proxyDir, [LAB_PROXY_DIR_PREFIX])
      if (ephemeralTelemetryDir && telemetryDir) {
        safeRemoveLabTempDir(telemetryDir)
      }
      removeLabRunRecord(this.stateDir, params.runId)
      throw err
    }
  }

  async rebuildWithPatch(runId: string, patchDiff: string, signal?: AbortSignal): Promise<LabTargetHandle> {
    assertLocalLabAllowed('local-lab')
    validateLabRunId(runId)
    const state = this.active.get(runId)
    if (!state) {
      throw new Error(`No active local-lab target found for run ${runId}.`)
    }

    applyUnifiedDiffToDirectory(state.handle.sanitizedRepoDir, patchDiff)

    const prevContainer = state.handle.containerName
    const prevContainerId = state.containerIds[state.containerNames.indexOf(prevContainer)]
    const prevBuiltImage = state.builtImages.includes(state.handle.imageName) ? state.handle.imageName : undefined

    const launched = await this.launchServiceContainer({
      runId,
      networkName: state.handle.networkName,
      sanitizedRepoDir: state.handle.sanitizedRepoDir,
      service: state.primaryService,
      labConfig: state.labConfig,
      isPrimary: true,
      telemetryDir: state.handle.telemetryDir,
      signal,
    })

    // Retarget the in-network proxy before the health check so the rebuilt container is the target.
    writeLabProxyTarget(state.proxyDir, launched.containerName, state.handle.internalPort)

    try {
      await waitForHealthCheck(
        state.handle.origin,
        state.handle.healthPath,
        state.labConfig.healthTimeoutMs ?? 30_000,
        signal,
      )
    } catch (err) {
      writeLabProxyTarget(state.proxyDir, prevContainer, state.handle.internalPort)
      await this.docker(['container', 'rm', '--force', launched.containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      if (launched.builtImage) {
        await this.docker(['image', 'rm', '--force', launched.imageName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      for (const volume of launched.volumes) {
        await this.docker(['volume', 'rm', '--force', volume], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      throw err
    }

    const prevIndex = state.containerNames.indexOf(prevContainer)
    state.containerNames = state.containerNames.filter(c => c !== prevContainer)
    state.containerNames.push(launched.containerName)
    if (prevIndex >= 0) state.containerIds.splice(prevIndex, 1)
    state.containerIds.push(launched.containerId)
    state.volumes.push(...launched.volumes)
    if (launched.builtImage) state.builtImages.push(launched.imageName)

    state.handle = {
      ...state.handle,
      targetId: `${runId}:${launched.containerName}`,
      containerName: launched.containerName,
      containerNames: [...state.containerNames],
      containerIp: launched.containerIp,
      imageName: launched.imageName,
      startedAt: Date.now(),
    }

    await this.docker(['container', 'rm', '--force', prevContainer], AbortSignal.timeout(5_000)).catch(() => undefined)
    if (prevBuiltImage && prevBuiltImage !== launched.imageName) {
      state.builtImages = state.builtImages.filter(i => i !== prevBuiltImage)
      await this.docker(['image', 'rm', '--force', prevBuiltImage], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    state.containerIds = state.containerIds.filter(id => id !== prevContainerId)
    this.persistState(runId)

    return state.handle
  }

  private async sweepOrphanContainersForRun(runId: string): Promise<void> {
    const ids = await this.listByLabel('container', runId)
    if (ids.length > 0) {
      await this.docker(['container', 'rm', '--force', ...ids], AbortSignal.timeout(10_000)).catch(() => undefined)
    }
  }

  /**
   * Reap every resource for a run: containers/networks/volumes by label, plus every path in the
   * persisted crash record. Idempotent — calling it twice is safe and returns zero removals.
   */
  async recover(runId: string): Promise<LabRecoveryResult> {
    validateLabRunId(runId)
    if (this.active.has(runId)) {
      await this.stopLabTarget(runId)
    }
    const record = readLabRunRecord(this.stateDir, runId)
    const result: LabRecoveryResult = {
      runId,
      containersRemoved: 0,
      networksRemoved: 0,
      volumesRemoved: 0,
      tempDirsRemoved: 0,
      recoveredFromRecord: record !== null,
    }

    const containerTargets = new Set<string>([
      ...(record?.containerNames ?? []),
      ...(record?.containerIds ?? []),
      ...(record?.proxyContainerName ? [record.proxyContainerName] : []),
      ...(await this.listByLabel('container', runId)),
    ])
    for (const target of containerTargets) {
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(target)) continue
      if (await this.tryDocker(['container', 'rm', '--force', target])) result.containersRemoved += 1
    }

    const networkTargets = new Set<string>([
      ...(record?.networkName ? [record.networkName] : []),
      ...(await this.listByLabel('network', runId)),
    ])
    for (const network of networkTargets) {
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(network)) continue
      if (await this.tryDocker(['network', 'rm', network])) result.networksRemoved += 1
    }

    const volumeTargets = new Set<string>([
      ...(record?.volumes ?? []),
      ...(await this.listByLabel('volume', runId)),
    ])
    for (const volume of volumeTargets) {
      if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(volume)) continue
      if (await this.tryDocker(['volume', 'rm', '--force', volume])) result.volumesRemoved += 1
    }

    if (safeRemoveLabTempDir(record?.sanitizedRepoDir, [LAB_REPO_DIR_PREFIX])) result.tempDirsRemoved += 1
    if (record?.ownsTelemetryDir && safeRemoveLabTempDir(record.telemetryDir)) result.tempDirsRemoved += 1
    if (safeRemoveLabTempDir(record?.proxyDir, [LAB_PROXY_DIR_PREFIX])) result.tempDirsRemoved += 1

    removeLabRunRecord(this.stateDir, runId)
    return result
  }

  /** Recover every run found in persisted records and by the lab label (crash/restart path). */
  async recoverAll(): Promise<LabRecoveryResult[]> {
    const runIds = new Set<string>()
    try {
      for (const entry of readdirSync(this.stateDir)) {
        if (!entry.endsWith('.json')) continue
        try {
          const parsed = JSON.parse(readFileSync(join(this.stateDir, entry), 'utf8')) as { runId?: unknown }
          if (typeof parsed.runId === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(parsed.runId)) {
            runIds.add(parsed.runId)
          }
        } catch {
          // Ignore unreadable/corrupt records; the label scan below still finds live orphans.
        }
      }
    } catch {
      // No state dir yet.
    }

    try {
      const ids = (await this.docker(['ps', '-aq', '--filter', `label=${LAB_LABELS.lab}=1`], AbortSignal.timeout(10_000)))
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 64)
      if (ids.length > 0) {
        const labels = await this.docker(
          ['inspect', '-f', `{{index .Config.Labels "${LAB_LABELS.run}"}}`, ...ids],
          AbortSignal.timeout(10_000),
        )
        for (const line of labels.split('\n')) {
          const runId = line.trim()
          if (/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(runId)) runIds.add(runId)
        }
      }
    } catch {
      // Docker unavailable: records still get cleaned up.
    }

    const results: LabRecoveryResult[] = []
    for (const runId of [...runIds].slice(0, MAX_RECOVERED_RUNS)) {
      if (runId === '<no value>') continue
      results.push(await this.recover(runId))
    }
    return results
  }

  /**
   * Synchronous best-effort reaping used from SIGINT/SIGTERM/exit handlers where async cleanup
   * cannot run. Removes persisted ids/names, sweeps by label, then removes scratch dirs.
   */
  reapSyncAll(): void {
    for (const [runId, state] of this.active.entries()) {
      const names = [state.proxyContainerName, ...state.containerNames]
      for (const name of names) {
        if (/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(name)) spawnDockerSync(['container', 'rm', '--force', name])
      }
      for (const id of state.containerIds) {
        if (/^[a-f0-9]{12,64}$/.test(id)) spawnDockerSync(['container', 'rm', '--force', id])
      }
      for (const listed of spawnDockerSync(['ps', '-aq', '--filter', `label=${LAB_LABELS.run}=${runId}`])
        .trim().split(/\s+/).filter(Boolean)) {
        spawnDockerSync(['container', 'rm', '--force', listed])
      }
      spawnDockerSync(['network', 'rm', state.handle.networkName])
      for (const volume of state.volumes) spawnDockerSync(['volume', 'rm', '--force', volume])
      safeRemoveLabTempDir(state.handle.sanitizedRepoDir, [LAB_REPO_DIR_PREFIX])
      safeRemoveLabTempDir(state.proxyDir, [LAB_PROXY_DIR_PREFIX])
      if (state.ownsTelemetryDir) safeRemoveLabTempDir(state.handle.telemetryDir)
      removeLabRunRecord(this.stateDir, runId)
    }
    this.active.clear()
  }

  async stopLabTarget(runId: string): Promise<void> {
    const state = this.active.get(runId)
    if (!state) {
      removeLabRunRecord(this.stateDir, runId)
      return
    }
    this.active.delete(runId)

    await new Promise<void>(res => state.forwarder.close(() => res())).catch(() => undefined)
    await this.docker(['container', 'rm', '--force', state.proxyContainerName], AbortSignal.timeout(5_000)).catch(() => undefined)
    for (const cname of state.containerNames) {
      await this.docker(['container', 'rm', '--force', cname], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    await this.sweepOrphanContainersForRun(runId)
    for (const volume of state.volumes) {
      await this.docker(['volume', 'rm', '--force', volume], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    for (const img of state.builtImages) {
      await this.docker(['image', 'rm', '--force', img], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    await this.docker(['network', 'rm', state.handle.networkName], AbortSignal.timeout(5_000)).catch(() => undefined)
    safeRemoveLabTempDir(state.handle.sanitizedRepoDir, [LAB_REPO_DIR_PREFIX])
    safeRemoveLabTempDir(state.proxyDir, [LAB_PROXY_DIR_PREFIX])
    if (state.ownsTelemetryDir && state.handle.telemetryDir) {
      safeRemoveLabTempDir(state.handle.telemetryDir)
    }
    removeLabRunRecord(this.stateDir, runId)
  }

  async stopAll(): Promise<void> {
    const ids = [...this.active.keys()]
    await Promise.all(ids.map(id => this.stopLabTarget(id)))
  }
}
