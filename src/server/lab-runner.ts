import { spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { createServer as createTcpServer } from 'node:net'
import type { AddressInfo, Server as TcpServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { createProjectPersona, listProjectPersonas } from './persona-vault.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'

export interface LabServiceSpec {
  name: string
  image?: string
  dockerfile?: string
  startCommand?: string
  command?: string | string[]
  internalPort?: number
  healthPath?: string
  env?: Record<string, string>
  memoryLimit?: string
  cpus?: string
  pidsLimit?: number
  dependsOn?: string[]
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
  forwarder: TcpServer
  forwardTarget: { containerName: string; port: number }
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
const MAX_LAB_CONTAINERS = 6
const MAX_TELEMETRY_BYTES = 65_536

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

  const rawDeps = raw.dependsOn ?? raw.depends_on
  const dependsOn = Array.isArray(rawDeps)
    ? rawDeps.map(d => String(d).trim()).filter(Boolean)
    : undefined

  return {
    name,
    image: typeof raw.image === 'string' && raw.image.trim() ? raw.image.trim() : undefined,
    dockerfile,
    startCommand: typeof raw.startCommand === 'string' && raw.startCommand.trim() ? raw.startCommand.trim() : undefined,
    command,
    internalPort,
    healthPath: typeof raw.healthPath === 'string' && raw.healthPath.trim() ? raw.healthPath.trim() : undefined,
    env: envObj && typeof envObj === 'object' && !Array.isArray(envObj) ? { ...envObj } : undefined,
    memoryLimit: typeof raw.memoryLimit === 'string' && raw.memoryLimit.trim() ? raw.memoryLimit.trim() : undefined,
    cpus: typeof raw.cpus === 'string' && raw.cpus.trim() ? raw.cpus.trim() : undefined,
    pidsLimit: typeof raw.pidsLimit === 'number' && Number.isInteger(raw.pidsLimit) ? raw.pidsLimit : undefined,
    dependsOn,
  }
}

function unquoteYamlScalar(raw: string): string {
  const s = raw.trim()
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1)
  }
  return s
}

export function parseAndSanitizeComposeYaml(yamlText: string): LabServiceSpec[] {
  const lines = yamlText.replace(/\r\n/g, '\n').split('\n')
  const rawServices = new Map<string, Record<string, unknown>>()

  let inServices = false
  let servicesIndent = -1
  let currentService: string | null = null
  let serviceIndent = -1
  let currentProp: string | null = null
  let propIndent = -1

  for (const rawLine of lines) {
    const trimmed = rawLine.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const indent = rawLine.length - rawLine.trimStart().length

    if (!inServices) {
      if (/^services\s*:\s*$/.test(trimmed)) {
        inServices = true
        servicesIndent = indent
      }
      continue
    }

    // Left top-level services block
    if (indent <= servicesIndent && !trimmed.startsWith('-')) {
      inServices = false
      currentService = null
      currentProp = null
      continue
    }

    // Service name declaration
    if (currentService === null || indent <= serviceIndent) {
      const svcMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*:\s*$/)
      if (!svcMatch) continue
      currentService = svcMatch[1]
      serviceIndent = indent
      currentProp = null
      propIndent = -1
      rawServices.set(currentService, { name: currentService })
      continue
    }

    const svcObj = rawServices.get(currentService)!

    // Property under current service (or nested under currentProp)
    if (currentProp !== null && indent > propIndent) {
      if (trimmed.startsWith('- ')) {
        const item = unquoteYamlScalar(trimmed.slice(2))
        if (currentProp === 'environment') {
          const envMap = (svcObj.env ?? {}) as Record<string, string>
          const eqIdx = item.indexOf('=')
          if (eqIdx > 0) {
            envMap[item.slice(0, eqIdx).trim()] = unquoteYamlScalar(item.slice(eqIdx + 1))
          }
          svcObj.env = envMap
        } else {
          const arr = Array.isArray(svcObj[currentProp]) ? (svcObj[currentProp] as unknown[]) : []
          arr.push(item)
          svcObj[currentProp] = arr
        }
        continue
      }
      const nestedKv = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*:\s*(.*)$/)
      if (nestedKv) {
        const [, nk, nvRaw] = nestedKv
        const nv = unquoteYamlScalar(nvRaw)
        if (currentProp === 'environment') {
          const envMap = (svcObj.env ?? {}) as Record<string, string>
          envMap[nk] = nv
          svcObj.env = envMap
        } else if (currentProp === 'build') {
          if (nk === 'dockerfile' && nv) svcObj.dockerfile = nv
          if (nk === 'context' && nv && nv !== '.' && nv !== './') {
            throw new Error(`Forbidden unsafe compose build context "${nv}" on service "${currentService}".`)
          }
        }
        continue
      }
    }

    const kvMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*:\s*(.*)$/)
    if (!kvMatch) continue
    const [, key, valRaw] = kvMatch
    const val = valRaw.trim()
    currentProp = key
    propIndent = indent

    if (val === '') {
      if (key === 'environment') svcObj.env = {}
      else if (key === 'build') svcObj.dockerfile = 'Dockerfile'
      else svcObj[key] = []
      continue
    }

    if (key === 'build') {
      const ctx = unquoteYamlScalar(val)
      if (ctx !== '.' && ctx !== './') {
        throw new Error(`Forbidden unsafe compose build context "${ctx}" on service "${currentService}".`)
      }
      svcObj.dockerfile = 'Dockerfile'
      continue
    }

    if (val.startsWith('[') && val.endsWith(']')) {
      try {
        svcObj[key] = JSON.parse(val)
      } catch {
        svcObj[key] = val.slice(1, -1).split(',').map(s => unquoteYamlScalar(s)).filter(Boolean)
      }
      continue
    }

    if (val === 'true' || val === 'false') {
      svcObj[key] = val === 'true'
    } else {
      svcObj[key] = unquoteYamlScalar(val)
    }
  }

  if (rawServices.size === 0) {
    throw new Error('Docker Compose file contains no valid services.')
  }
  if (rawServices.size > MAX_LAB_CONTAINERS) {
    throw new Error(`Lab stack exceeds maximum limit of ${MAX_LAB_CONTAINERS} containers per run (got ${rawServices.size}).`)
  }

  const sanitized: LabServiceSpec[] = []
  for (const [svcName, rawObj] of rawServices.entries()) {
    sanitized.push(validateRawServiceObject(rawObj, svcName))
  }
  return sanitized
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

function safeResolveUnderRoot(rootDir: string, relPath: string): string {
  const clean = relPath.replace(/^[ab]\//, '').replace(/\\/g, '/')
  if (!clean || clean.includes('\0') || clean.startsWith('/') || clean.split('/').some(seg => seg === '..')) {
    throw new Error(`Unsafe file path rejected: "${relPath}"`)
  }
  const rootReal = realpathSync(rootDir)
  const full = resolve(rootReal, clean)
  const rel = relative(rootReal, full)
  if (rel.startsWith('..') || rel === '') {
    throw new Error(`Path escapes repository root: "${relPath}"`)
  }
  return full
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

      const existed = existsSync(fullPath)
      if (!backups.has(fullPath)) {
        backups.set(fullPath, existed ? readFileSync(fullPath, 'utf8') : null)
      }

      if (!existed && !isCreate) {
        throw new Error(`Target file does not exist for patch: ${normalizedRel}`)
      }

      const originalContent = existed ? readFileSync(fullPath, 'utf8') : ''
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
        if (existsSync(fullPath)) unlinkSync(fullPath)
      } else {
        mkdirSync(dirname(fullPath), { recursive: true, mode: 0o755 })
        const out = lines.length > 0 ? lines.join('\n') + '\n' : ''
        writeFileSync(fullPath, out, { encoding: 'utf8', mode: 0o644 })
        chmodSync(fullPath, 0o644)
      }
      filesModified.push(normalizedRel)
    }

    return { filesModified }
  } catch (err) {
    for (const [filePath, prev] of backups.entries()) {
      try {
        if (prev === null) {
          if (existsSync(filePath)) unlinkSync(filePath)
        } else {
          writeFileSync(filePath, prev, 'utf8')
        }
      } catch {
        // Best-effort rollback
      }
    }
    throw err
  }
}

function createLoopbackForwarder(
  targetRef: { containerName: string; port: number },
): Promise<{ server: TcpServer; port: number }> {
  const bridgeScript = [
    `if command -v node >/dev/null 2>&1; then`,
    `  exec node -e "const net=require('net');const s=net.connect(Number(process.argv[1]),'127.0.0.1');process.stdin.pipe(s);s.pipe(process.stdout);s.on('error',()=>process.exit(1));s.on('close',()=>process.exit(0));process.stdin.on('end',()=>s.end());" "$1"`,
    `elif command -v python3 >/dev/null 2>&1; then`,
    `  exec python3 -u -c "import os,select,socket,sys; s=socket.create_connection(('127.0.0.1',int(sys.argv[1]))); fds=[0,s.fileno()]` +
      `; \nwhile True:\n r,_,_=select.select(fds,[],[])\n if 0 in r:\n  d=os.read(0,65536)\n  if not d: s.shutdown(socket.SHUT_WR); fds.remove(0)\n  else: s.sendall(d)\n if s.fileno() in r:\n  d=s.recv(65536)\n  if not d: break\n  os.write(1,d)" "$1"`,
    `else`,
    `  exit 127`,
    `fi`,
  ].join('\n')

  return new Promise((resolvePromise, reject) => {
    const server = createTcpServer(clientSocket => {
      const proc = spawn(
        'docker',
        ['exec', '-i', targetRef.containerName, 'sh', '-c', bridgeScript, '_', String(targetRef.port)],
        { env: dockerEnv(), stdio: ['pipe', 'pipe', 'ignore'] },
      )
      clientSocket.pipe(proc.stdin)
      proc.stdout.pipe(clientSocket)

      const teardown = () => {
        try { clientSocket.destroy() } catch { /* ignore */ }
        try { proc.kill() } catch { /* ignore */ }
      }
      clientSocket.on('error', teardown)
      clientSocket.on('close', () => {
        try { proc.kill() } catch { /* ignore */ }
      })
      proc.stdin.on('error', () => { /* ignore EPIPE */ })
      proc.stdout.on('error', teardown)
      proc.once('error', teardown)
      proc.once('close', () => {
        try { clientSocket.end() } catch { /* ignore */ }
      })
    })
    server.once('error', reject)
    // Strictly bind ONLY to 127.0.0.1 ephemeral port (never 0.0.0.0).
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

async function waitForContainerPort(containerName: string, port: number, timeoutMs = 10_000, signal?: AbortSignal): Promise<void> {
  const deadline = Date.now() + timeoutMs
  const probeJs = `const net=require('net');const s=net.connect(${port},'127.0.0.1',()=>{s.end();process.exit(0)});s.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),1000);`
  while (Date.now() < deadline) {
    signal?.throwIfAborted()
    try {
      await runDocker(['exec', containerName, 'node', '-e', probeJs], AbortSignal.timeout(2_000))
      return
    } catch {
      await delay(200, undefined, { signal }).catch(() => undefined)
    }
  }
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

export class LabRunner {
  private readonly active = new Map<string, InternalTargetState>()

  getTarget(runId: string): LabTargetHandle | undefined {
    return this.active.get(runId)?.handle
  }

  listTargets(): LabTargetHandle[] {
    return [...this.active.values()].map(s => s.handle)
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
  }): Promise<{ containerName: string; containerIp: string; imageName: string; builtImage: boolean }> {
    const { runId, networkName, sanitizedRepoDir, service, labConfig, isPrimary, telemetryDir, signal } = params
    const shortId = createHash('sha256').update(`${runId}:${service.name}:${randomUUID()}`).digest('hex').slice(0, 10)
    const safeSvc = service.name.replace(/[^a-z0-9_-]/g, '').slice(0, 20) || 'svc'
    const containerName = `guardian-lab-${safeSvc}-${shortId}`
    const internalPort = service.internalPort ?? (isPrimary ? (labConfig.internalPort ?? 8080) : 8080)
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
      await runDocker(
        ['build', '--pull=false', '--network', 'none', '-f', dockerfileFull, '-t', imageName, sanitizedRepoDir],
        buildSignal,
      )
      builtImage = true
      const overrideCmd = service.command ?? service.startCommand ?? (isPrimary ? labConfig.startCommand : undefined)
      if (Array.isArray(overrideCmd)) {
        cmd = overrideCmd
      } else if (typeof overrideCmd === 'string' && overrideCmd.trim()) {
        cmd = ['sh', '-c', overrideCmd.trim()]
      }
    } else if (service.image || service.command || service.startCommand) {
      imageName = service.image || labConfig.image || 'node:24-bookworm-slim'
      const rawCmd = service.command ?? service.startCommand ?? (isPrimary ? labConfig.startCommand : undefined)
      if (Array.isArray(rawCmd)) {
        cmd = rawCmd
      } else if (typeof rawCmd === 'string' && rawCmd.trim()) {
        cmd = ['sh', '-c', rawCmd.trim()]
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

    const extraInternalEnv: Record<string, string> = {}
    if (isPrimary && labConfig.iastEnabled && telemetryDir) {
      mountArgs.push('--mount', `type=bind,source=${telemetryDir},target=/var/run/guardian-iast`)
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

    const mergedEnv = { ...(isPrimary ? labConfig.env : undefined), ...(service.env ?? {}) }

    const runArgs = [
      'run', '-d',
      '--name', containerName,
      '--network', networkName,
      '--network-alias', service.name,
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--read-only',
      '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
      '--memory', memoryLimit,
      '--memory-swap', memoryLimit,
      '--cpus', cpus,
      '--pids-limit', String(pidsLimit),
      '--label', 'dev.guardian.lab=1',
      '--label', `dev.guardian.run=${runId}`,
      '--label', `dev.guardian.service=${service.name}`,
      ...buildSyntheticEnvArgs(internalPort, mergedEnv, extraInternalEnv),
      ...mountArgs,
      imageName,
      ...cmd,
    ]

    try {
      await runDocker(runArgs, signal)
      const rawIp = (await runDocker(
        ['inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', containerName],
        signal,
      )).trim()
      if (!rawIp || !/^\d+\.\d+\.\d+\.\d+$/.test(rawIp)) {
        throw new Error(`Failed to resolve internal bridge IP for lab container ${containerName}.`)
      }
      return { containerName, containerIp: rawIp, imageName, builtImage }
    } catch (err) {
      await runDocker(['container', 'rm', '--force', containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      if (builtImage) {
        await runDocker(['image', 'rm', '--force', imageName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      throw err
    }
  }

  async startLabTarget(params: StartLabTargetParams): Promise<LabTargetHandle> {
    assertLocalLabAllowed(params.environment)
    params.signal?.throwIfAborted()

    if (!existsSync(params.repoDir) || !statSync(params.repoDir).isDirectory()) {
      throw new Error(`Lab repository directory does not exist: ${params.repoDir}`)
    }

    const labConfig: LabConfig = params.labConfig ?? {}

    // Strict pre-launch validation BEFORE touching Docker or creating any networks/containers!
    validateEnvMap(labConfig.env, 'labConfig.env')

    let composeServices: LabServiceSpec[] | undefined
    if (labConfig.dockerComposeFile?.trim()) {
      const composePath = safeResolveUnderRoot(params.repoDir, labConfig.dockerComposeFile.trim())
      if (!existsSync(composePath)) {
        throw new Error(`Docker Compose file not found: ${labConfig.dockerComposeFile}`)
      }
      const composeYaml = readFileSync(composePath, 'utf8')
      composeServices = parseAndSanitizeComposeYaml(composeYaml)
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
    const healthPath = primaryService.healthPath ?? labConfig.healthPath ?? '/health'
    const runSlug = params.runId.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase() || 'run'
    const shortRand = createHash('sha256').update(`${params.runId}:${randomUUID()}`).digest('hex').slice(0, 8)
    const networkName = `guardian-lab-${runSlug}-${shortRand}`

    const sanitizedRepoDir = mkdtempSync(join(tmpdir(), 'guardian-lab-repo-'))
    const repoReal = realpathSync(params.repoDir)
    copySanitizedRepo(repoReal, sanitizedRepoDir, repoReal)

    let telemetryDir: string | undefined
    let ownsTelemetryDir = false
    if (labConfig.iastEnabled) {
      if (params.telemetryDir) {
        telemetryDir = params.telemetryDir
        mkdirSync(telemetryDir, { recursive: true, mode: 0o777 })
        chmodSync(telemetryDir, 0o777)
      } else {
        telemetryDir = mkdtempSync(join(tmpdir(), 'guardian-lab-telemetry-'))
        chmodSync(telemetryDir, 0o777)
        ownsTelemetryDir = true
      }
    }

    let networkCreated = false
    const containerNames: string[] = []
    const builtImages: string[] = []
    let forwarder: TcpServer | undefined

    try {
      // Dedicated per-run Docker --internal bridge network with inhibit_ipv4=true:
      // zero internet egress AND zero host bridge gateway IP (blocks access to host 0.0.0.0 services!).
      await runDocker(
        [
          'network', 'create',
          '--driver', 'bridge',
          '--internal',
          '-o', 'com.docker.network.bridge.inhibit_ipv4=true',
          '--label', 'dev.guardian.lab=1',
          '--label', `dev.guardian.run=${params.runId}`,
          networkName,
        ],
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
        if (launched.builtImage) builtImages.push(launched.imageName)
        if (sidecar.internalPort) {
          baseUrls[sidecar.name] = `http://${sidecar.name}:${sidecar.internalPort}`
          await waitForContainerPort(launched.containerName, sidecar.internalPort, 8_000, params.signal)
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
      if (primaryLaunched.builtImage) builtImages.push(primaryLaunched.imageName)

      const forwardTarget = { containerName: primaryLaunched.containerName, port: internalPort }
      const proxy = await createLoopbackForwarder(forwardTarget)
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
        const seedStdout = await runDocker(
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
        forwarder: proxy.server,
        forwardTarget,
        ownsTelemetryDir,
      })

      return handle
    } catch (err) {
      if (forwarder) {
        await new Promise<void>(res => forwarder!.close(() => res())).catch(() => undefined)
      }
      for (const cname of containerNames) {
        await runDocker(['container', 'rm', '--force', cname], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      await this.sweepOrphanContainersForRun(params.runId)
      for (const img of builtImages) {
        await runDocker(['image', 'rm', '--force', img], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      if (networkCreated) {
        await runDocker(['network', 'rm', networkName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      rmSync(sanitizedRepoDir, { recursive: true, force: true })
      if (ownsTelemetryDir && telemetryDir) {
        rmSync(telemetryDir, { recursive: true, force: true })
      }
      throw err
    }
  }

  async rebuildWithPatch(runId: string, patchDiff: string, signal?: AbortSignal): Promise<LabTargetHandle> {
    assertLocalLabAllowed('local-lab')
    const state = this.active.get(runId)
    if (!state) {
      throw new Error(`No active local-lab target found for run ${runId}.`)
    }

    applyUnifiedDiffToDirectory(state.handle.sanitizedRepoDir, patchDiff)

    const prevContainer = state.handle.containerName
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

    state.forwardTarget.containerName = launched.containerName
    state.forwardTarget.port = state.handle.internalPort

    try {
      await waitForHealthCheck(
        state.handle.origin,
        state.handle.healthPath,
        state.labConfig.healthTimeoutMs ?? 30_000,
        signal,
      )
    } catch (err) {
      state.forwardTarget.containerName = prevContainer
      await runDocker(['container', 'rm', '--force', launched.containerName], AbortSignal.timeout(5_000)).catch(() => undefined)
      if (launched.builtImage) {
        await runDocker(['image', 'rm', '--force', launched.imageName], AbortSignal.timeout(5_000)).catch(() => undefined)
      }
      throw err
    }

    state.containerNames = state.containerNames.filter(c => c !== prevContainer)
    state.containerNames.push(launched.containerName)
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

    await runDocker(['container', 'rm', '--force', prevContainer], AbortSignal.timeout(5_000)).catch(() => undefined)
    if (prevBuiltImage && prevBuiltImage !== launched.imageName) {
      state.builtImages = state.builtImages.filter(i => i !== prevBuiltImage)
      await runDocker(['image', 'rm', '--force', prevBuiltImage], AbortSignal.timeout(5_000)).catch(() => undefined)
    }

    return state.handle
  }

  private async sweepOrphanContainersForRun(runId: string): Promise<void> {
    try {
      const out = await runDocker(
        ['ps', '-aq', '--filter', `label=dev.guardian.run=${runId}`],
        AbortSignal.timeout(5_000),
      )
      const ids = out.trim().split(/\s+/).filter(Boolean)
      if (ids.length > 0) {
        await runDocker(['container', 'rm', '--force', ...ids], AbortSignal.timeout(10_000)).catch(() => undefined)
      }
    } catch {
      // Best-effort sweep
    }
  }

  async stopLabTarget(runId: string): Promise<void> {
    const state = this.active.get(runId)
    if (!state) return
    this.active.delete(runId)

    await new Promise<void>(res => state.forwarder.close(() => res())).catch(() => undefined)
    for (const cname of state.containerNames) {
      await runDocker(['container', 'rm', '--force', cname], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    await this.sweepOrphanContainersForRun(runId)
    for (const img of state.builtImages) {
      await runDocker(['image', 'rm', '--force', img], AbortSignal.timeout(5_000)).catch(() => undefined)
    }
    await runDocker(['network', 'rm', state.handle.networkName], AbortSignal.timeout(5_000)).catch(() => undefined)
    try {
      rmSync(state.handle.sanitizedRepoDir, { recursive: true, force: true })
    } catch {
      // Best-effort cleanup
    }
    if (state.ownsTelemetryDir && state.handle.telemetryDir) {
      try {
        rmSync(state.handle.telemetryDir, { recursive: true, force: true })
      } catch {
        // Best-effort cleanup
      }
    }
  }

  async stopAll(): Promise<void> {
    const ids = [...this.active.keys()]
    await Promise.all(ids.map(id => this.stopLabTarget(id)))
  }
}
