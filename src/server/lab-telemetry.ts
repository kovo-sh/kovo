import { randomUUID } from 'node:crypto'
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { LAB_CONTAINER_USER_ENV, LAB_PATHS, resolveLabContainerUser } from './lab-proxy.ts'
import type { LabConfig } from './lab-proxy.ts'
import { redact, redactJsonValue } from './redact.ts'
import type { NamedSecret } from './redact.ts'
import type { Store } from './store.ts'

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

const MAX_TELEMETRY_BYTES = 65_536

/** Bounded retention for per-run telemetry dirs under a shared data-dir base. */
export const MAX_IAST_TELEMETRY_RUN_DIRS = 4
export const MAX_IAST_TELEMETRY_TOTAL_BYTES = 128 * 1024 * 1024
const MAX_IAST_TELEMETRY_WALK_ENTRIES = 20_000

const BUILTIN_IAST_SECRET_PATTERNS: readonly [RegExp, string][] = [
  [/\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b/g, '[redacted:aws]'],
  [/\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}\b/g, '[redacted:stripe]'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g, '[redacted:jwt]'],
  [/\bBearer\s+[a-z0-9._~+/=-]{8,}/gi, 'Bearer [redacted]'],
  [/\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\n\r]+/gi, '[redacted:header]'],
]

const IAST_HOOKS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../../local-lab/iast')

// ===========================================================================
// IAST telemetry scrubbing & ingestion
// ===========================================================================

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

// ===========================================================================
// Per-run IAST telemetry directory lifecycle & container wiring
// ===========================================================================

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
  const kept = runs.slice(0, Math.max(0, retain))
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

/** Provision an owner-only per-run telemetry directory when IAST is enabled. */
export function provisionRunTelemetryDir(params: {
  iastEnabled?: boolean
  baseTelemetryDir?: string
  runId: string
  containerUser: string
}): { telemetryDir?: string; ownsTelemetryDir: boolean; ephemeralTelemetryDir: boolean } {
  if (!params.iastEnabled) {
    return { ownsTelemetryDir: false, ephemeralTelemetryDir: false }
  }
  if (params.baseTelemetryDir) {
    return {
      telemetryDir: createPerRunIastTelemetryDir(params.baseTelemetryDir, params.runId, params.containerUser),
      ownsTelemetryDir: false,
      ephemeralTelemetryDir: true,
    }
  }
  const telemetryDir = prepareIastTelemetryDir(
    mkdtempSync(join(tmpdir(), LAB_PATHS.telemetryPrefix)),
    params.containerUser,
  )
  assertIastTelemetryDirWritable(telemetryDir, params.containerUser)
  return { telemetryDir, ownsTelemetryDir: true, ephemeralTelemetryDir: true }
}

/** Build container mount args and hook environment variables for IAST instrumentation. */
export function buildIastContainerWiring(
  telemetryDir: string,
  labConfig: Pick<LabConfig, 'iastEnabled' | 'iastRuntime'>,
): { mountArgs: string[]; extraEnv: Record<string, string> } {
  const iastActive = Boolean(labConfig.iastEnabled)
  const mountArgs = [...buildIastTelemetryMountArgs(telemetryDir, iastActive)]
  const extraEnv: Record<string, string> = {}
  if (iastActive) {
    extraEnv.GUARDIAN_IAST_OUT_DIR = '/var/run/guardian-iast'
    if (existsSync(IAST_HOOKS_DIR)) {
      mountArgs.push('--mount', `type=bind,source=${IAST_HOOKS_DIR},target=/opt/guardian-iast,readonly`)
      const runtime = labConfig.iastRuntime ?? 'node'
      if (runtime === 'node' && existsSync(join(IAST_HOOKS_DIR, 'node-hook.mjs'))) {
        extraEnv.NODE_OPTIONS = '--import=/opt/guardian-iast/node-hook.mjs'
      } else if (runtime === 'python' && existsSync(join(IAST_HOOKS_DIR, 'python', 'sitecustomize.py'))) {
        extraEnv.PYTHONPATH = '/opt/guardian-iast/python'
      }
    }
  }
  return { mountArgs, extraEnv }
}
